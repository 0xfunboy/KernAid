#!/usr/bin/env python3
"""Native, credential-free Fleet Resident package lifecycle smoke."""

from __future__ import annotations

import argparse
import json
import os
import plistlib
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path


MAX_PACKAGE_BYTES = 128 * 1024 * 1024
MAX_PROCESS_OUTPUT_BYTES = 64 * 1024
WINDOWS_SERVICE_NAME = "KernAidFleetResidentWindows"
MACOS_LAUNCHD_LABEL = "io.kernaid.fleet-resident-macos"
CONTRACT_MARKERS = (
    b"/v1/work-order-claims",
    b"/v1/work-order-results",
    b"dev.kernaid.fleet.work-order-claim-request.v1",
    b"dev.kernaid.fleet.work-order-result.v1",
)
FORBIDDEN_CONFIG_KEYS = {
    "arguments",
    "collector",
    "command",
    "password",
    "privatekey",
    "script",
    "secret",
    "seed",
    "token",
}


class SmokeFailure(RuntimeError):
    pass


def regular_file(path: Path, label: str) -> int:
    try:
        metadata = path.lstat()
    except FileNotFoundError as error:
        raise SmokeFailure(f"missing {label}: {path}") from error
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise SmokeFailure(f"{label} must be a regular non-symlink file")
    if metadata.st_size <= 0 or metadata.st_size > MAX_PACKAGE_BYTES:
        raise SmokeFailure(f"{label} has an invalid byte count")
    return metadata.st_size


def safe_directory(path: Path, label: str) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError as error:
        raise SmokeFailure(f"missing {label}: {path}") from error
    if path.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
        raise SmokeFailure(f"{label} must be a real directory")


def run(command: list[str], *, timeout: float = 30.0) -> subprocess.CompletedProcess[bytes]:
    try:
        result = subprocess.run(
            command,
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise SmokeFailure(f"could not run fixed lifecycle command: {command[0]}") from error
    if len(result.stdout) + len(result.stderr) > MAX_PROCESS_OUTPUT_BYTES:
        raise SmokeFailure(f"fixed lifecycle command emitted excessive output: {command[0]}")
    return result


def require_success(result: subprocess.CompletedProcess[bytes], label: str) -> None:
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).decode("utf-8", "replace").strip()
        raise SmokeFailure(f"{label} failed: {detail[:500]}")


def verify_binary_contract(binary: Path) -> None:
    regular_file(binary, "Resident executable")
    payload = binary.read_bytes()
    missing = [marker.decode("ascii") for marker in CONTRACT_MARKERS if marker not in payload]
    if missing:
        raise SmokeFailure(f"Resident executable lacks claim/result contract: {missing}")


def verify_public_config(path: Path, expected_schema: str) -> None:
    regular_file(path, "public configuration template")
    try:
        value = json.loads(path.read_bytes())
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SmokeFailure("public configuration template is invalid JSON") from error
    if not isinstance(value, dict) or value.get("schema") != expected_schema:
        raise SmokeFailure("public configuration template schema is invalid")

    def walk(item: object) -> None:
        if isinstance(item, dict):
            for key, child in item.items():
                if not isinstance(key, str) or key.lower() in FORBIDDEN_CONFIG_KEYS:
                    raise SmokeFailure("public configuration contains a credential or command key")
                walk(child)
        elif isinstance(item, list):
            for child in item:
                walk(child)

    walk(value)


def write_smoke_config(platform: str, root: Path) -> tuple[Path, Path]:
    schemas = {
        "linux": "dev.kernaid.fleet.resident-work-order-service-config.v1",
        "macos": "dev.kernaid.fleet.resident-macos-service-config.v1",
        "windows": "dev.kernaid.fleet.resident-windows-service-config.v1",
    }
    state = root / "state"
    trust = root / "absent-public-anchors"
    config = {
        "schema": schemas[platform],
        "endpoint": "https://fleet.example.invalid/",
        "tenantId": "native-lifecycle-smoke",
        "stateDirectory": str(state),
        "runtimeStateFile": str(root / "absent-runtime.sqlite3"),
        "serviceReceiptAnchorFile": str(trust / "service.pub"),
        "entitlementAnchorFile": str(trust / "entitlement.pub"),
        "policyAnchorFile": str(trust / "policy.pub"),
        "intervalSeconds": 60,
        "minimumBackoffSeconds": 2,
        "maximumBackoffSeconds": 30,
        "connectTimeoutSeconds": 2,
        "requestTimeoutSeconds": 5,
        "leaseSeconds": 300,
    }
    path = root / "smoke-config.json"
    path.write_bytes(
        json.dumps(config, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode(
            "utf-8"
        )
    )
    if os.name != "nt":
        path.chmod(0o600)
    return path, state


def exercise_run_once(platform: str, binary: Path, root: Path) -> None:
    config, state = write_smoke_config(platform, root)
    if platform == "windows":
        command = [str(binary), "run-once", "--config", str(config)]
        marker = b"KERNAID_FLEET_RESIDENT_WINDOWS_V1 status=failed code=io-failed"
    elif platform == "macos":
        command = [str(binary), "--config", str(config), "--once"]
        marker = b"KERNAID_FLEET_RESIDENT_MACOS_V1 status=failed code=io-failed"
    else:
        command = [str(binary), "--config", str(config), "--once"]
        marker = b"KERNAID_FLEET_RESIDENT_WORK_ORDERS_V1 status=failed code=io-failed"
    result = run(command)
    if result.returncode == 0 or marker not in result.stderr:
        raise SmokeFailure("credential-free run-once did not fail closed at the public-anchor gate")
    if not state.is_dir():
        raise SmokeFailure("run-once did not reach its isolated state-directory boundary")


def new_staging_root(platform: str) -> Path:
    root = Path(tempfile.mkdtemp(prefix=f"kernaid-{platform}-resident-smoke-"))
    if os.name != "nt":
        root.chmod(0o700)
    return root


def remove_staging_root(root: Path) -> None:
    shutil.rmtree(root)
    if root.exists() or root.is_symlink():
        raise SmokeFailure("staging cleanup was incomplete")


def linux_smoke(package: Path) -> None:
    if sys.platform != "linux":
        raise SmokeFailure("Linux lifecycle smoke requires a native Linux runner")
    regular_file(package, "Debian package")
    root = new_staging_root("linux")
    try:
        staged = root / "root"
        control = root / "control"
        require_success(
            run(["dpkg-deb", "--extract", str(package), str(staged)]),
            "package extraction",
        )
        require_success(
            run(["dpkg-deb", "--control", str(package), str(control)]),
            "control extraction",
        )
        forbidden_scripts = {"preinst", "postinst", "prerm", "postrm", "config", "triggers"}
        if forbidden_scripts.intersection(item.name for item in control.iterdir()):
            raise SmokeFailure("Debian package contains an installation side-effect script")
        for item in staged.rglob("*"):
            if item.is_symlink():
                raise SmokeFailure("Debian package staging contains a symlink")
            if item.is_dir() and (item.name.endswith(".wants") or item.name.endswith(".requires")):
                raise SmokeFailure("Debian package pre-enables a systemd unit")
        binary = staged / "usr/libexec/kernaid-fleet-resident-work-orders"
        verify_binary_contract(binary)
        template = staged / "usr/share/kernaid-fleet-resident/examples/fleet-work-orders.json"
        verify_public_config(
            template, "dev.kernaid.fleet.resident-work-order-service-config.v1"
        )
        unit = (
            staged
            / "usr/share/kernaid-fleet-resident/systemd/user"
            / "kernaid-fleet-resident-work-orders.service"
        )
        unit_text = unit.read_text(encoding="utf-8")
        if "WantedBy=default.target" not in unit_text or "ExecStart=/usr/libexec/" not in unit_text:
            raise SmokeFailure("Linux user unit lost its explicit opt-in contract")
        exercise_run_once("linux", binary, root)
    finally:
        remove_staging_root(root)


def safe_extract_windows_bundle(package: Path, destination: Path) -> None:
    expected = {
        "AUTHENTICODE-REQUIRED.txt",
        "INSTALL.md",
        "KernAid-Fleet-Resident.exe",
        "KernAid-Fleet-Resident.package.json",
        "config.example.json",
    }
    try:
        with zipfile.ZipFile(package, mode="r") as archive:
            infos = archive.infolist()
            if {info.filename for info in infos} != expected or len(infos) != len(expected):
                raise SmokeFailure("Windows bundle inventory is not exact")
            destination.mkdir(mode=0o700)
            for info in infos:
                path = Path(info.filename)
                mode = (info.external_attr >> 16) & 0o170000
                if (
                    path.is_absolute()
                    or len(path.parts) != 1
                    or info.is_dir()
                    or stat.S_ISLNK(mode)
                    or info.file_size <= 0
                    or info.file_size > MAX_PACKAGE_BYTES
                ):
                    raise SmokeFailure("Windows bundle contains an unsafe member")
                target = destination / info.filename
                with archive.open(info, mode="r") as source, target.open("xb") as output:
                    shutil.copyfileobj(source, output, 1024 * 1024)
    except (OSError, zipfile.BadZipFile) as error:
        raise SmokeFailure("Windows bundle is not a valid ZIP") from error


def windows_service_exists() -> bool:
    return run(["sc.exe", "query", WINDOWS_SERVICE_NAME], timeout=10).returncode == 0


def wait_for_windows_service_removal() -> bool:
    for _ in range(40):
        if not windows_service_exists():
            return True
        time.sleep(0.25)
    return False


def windows_smoke(package: Path) -> None:
    if os.name != "nt":
        raise SmokeFailure("Windows lifecycle smoke requires a native Windows runner")
    regular_file(package, "Windows deployment bundle")
    if windows_service_exists():
        raise SmokeFailure("refusing to replace an existing KernAid Windows service")
    root = new_staging_root("windows")
    installed = False
    try:
        bundle = root / "bundle"
        safe_extract_windows_bundle(package, bundle)
        binary = bundle / "KernAid-Fleet-Resident.exe"
        verify_binary_contract(binary)
        verify_public_config(
            bundle / "config.example.json",
            "dev.kernaid.fleet.resident-windows-service-config.v1",
        )
        config, _ = write_smoke_config("windows", root)
        require_success(
            run([str(binary), "install", "--config", str(config)]),
            "SCM staging install",
        )
        installed = True
        query = run(["sc.exe", "qc", WINDOWS_SERVICE_NAME], timeout=10)
        require_success(query, "SCM configuration query")
        service_contract = query.stdout.decode("utf-8", "replace").lower()
        if "demand_start" not in service_contract or "localservice" not in service_contract:
            raise SmokeFailure("Windows service is not disabled-by-default LocalService")
        state = run(["sc.exe", "query", WINDOWS_SERVICE_NAME], timeout=10)
        require_success(state, "SCM state query")
        if "STOPPED" not in state.stdout.decode("utf-8", "replace"):
            raise SmokeFailure("Windows service started during installation")
        exercise_run_once("windows", binary, root)
        require_success(run([str(binary), "uninstall"]), "SCM uninstall")
        if not wait_for_windows_service_removal():
            raise SmokeFailure("Windows service remained registered after uninstall")
        installed = False
    finally:
        if installed and windows_service_exists():
            run(["sc.exe", "stop", WINDOWS_SERVICE_NAME], timeout=10)
            run(["sc.exe", "delete", WINDOWS_SERVICE_NAME], timeout=10)
            wait_for_windows_service_removal()
        remove_staging_root(root)
    if windows_service_exists():
        raise SmokeFailure("Windows service cleanup was incomplete")


def launchd_service_loaded() -> bool:
    target = f"gui/{os.getuid()}/{MACOS_LAUNCHD_LABEL}"
    return run(["launchctl", "print", target], timeout=10).returncode == 0


def macos_smoke(package: Path) -> None:
    if sys.platform != "darwin":
        raise SmokeFailure("macOS lifecycle smoke requires a native macOS runner")
    safe_directory(package, "macOS development bundle")
    if launchd_service_loaded():
        raise SmokeFailure("refusing to replace an existing KernAid LaunchAgent")
    expected = {
        "INSTALL.md",
        "SHA256SUMS",
        "UNSIGNED-UNNOTARIZED.txt",
        "config.example.json",
        "io.kernaid.fleet-resident-macos.plist",
        "kernaid-fleet-resident-macos",
    }
    if {item.name for item in package.iterdir()} != expected:
        raise SmokeFailure("macOS bundle inventory is not exact")
    for name in expected:
        regular_file(package / name, f"macOS bundle member {name}")
    root = new_staging_root("macos")
    try:
        bundle = root / "bundle"
        shutil.copytree(package, bundle, symlinks=False)
        binary = bundle / "kernaid-fleet-resident-macos"
        verify_binary_contract(binary)
        verify_public_config(
            bundle / "config.example.json",
            "dev.kernaid.fleet.resident-macos-service-config.v1",
        )
        with (bundle / "io.kernaid.fleet-resident-macos.plist").open("rb") as source:
            plist = plistlib.load(source)
        if (
            plist.get("Label") != MACOS_LAUNCHD_LABEL
            or plist.get("RunAtLoad") is not False
            or plist.get("KeepAlive") is not False
            or "--config" not in plist.get("ProgramArguments", [])
        ):
            raise SmokeFailure("macOS LaunchAgent is not disabled-by-default")
        exercise_run_once("macos", binary, root)
        if launchd_service_loaded():
            raise SmokeFailure("macOS staging unexpectedly loaded the LaunchAgent")
    finally:
        remove_staging_root(root)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--platform", choices=("linux", "windows", "macos"), required=True)
    parser.add_argument("--package", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    arguments = parse_args()
    try:
        if arguments.platform == "linux":
            linux_smoke(arguments.package)
        elif arguments.platform == "windows":
            windows_smoke(arguments.package)
        else:
            macos_smoke(arguments.package)
    except SmokeFailure as error:
        print(
            f"KERNAID_FLEET_RESIDENT_LIFECYCLE_V1 platform={arguments.platform} "
            f"status=failed code={str(error)}",
            file=sys.stderr,
        )
        return 1
    print(
        f"KERNAID_FLEET_RESIDENT_LIFECYCLE_V1 platform={arguments.platform} status=ok "
        "install=staged run_once=fail-closed startup=disabled "
        "claim_result=present cleanup=complete"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
