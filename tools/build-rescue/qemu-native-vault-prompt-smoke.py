#!/usr/bin/python3
"""Exercise the feature-gated Vault VT prompt through the real Rescue UI."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import textwrap
import time
from pathlib import Path
from types import ModuleType
from typing import Sequence


REPO_DIR = Path(__file__).resolve().parents[2]
LIFECYCLE_PATH = REPO_DIR / "tools/build-rescue/qemu-vault-lifecycle-pty.py"
UI_SMOKE_PATH = REPO_DIR / "tools/build-rescue/qemu-tauri-ui-smoke.py"
LAYOUT_MANIFEST = REPO_DIR / "rescue/image-layout/device-layout.v1.json"
LAYOUT_TOOL = REPO_DIR / "tools/build-rescue/finalize-device-layout.py"
FAILURE_PREFIX = "KERNAID_QEMU_NATIVE_VAULT_PROMPT_FAILURE_V1"
ATTESTATION_PREFIX = "KERNAID_QEMU_NATIVE_VAULT_PROMPT_ATTESTATION_V1"
NATIVE_PROMPT_FLAG = "kernaid.native-prompt=vt-v1"
MEDIA_BYTES = 32_000_000_000
P3_START_BYTES = 17_179_869_184
MAX_ISO_BYTES = P3_START_BYTES - 1
MIN_TOTAL_TIMEOUT_SECONDS = 3_600
MAX_TOTAL_TIMEOUT_SECONDS = 5_400
FRAME_ATTEMPTS = 120
FRAME_SETTLE_SECONDS = 0.25
MAX_CONFIG_BYTES = 64 * 1024
SECRET_BYTES = 64
HEX_ALPHABET = b"0123456789abcdef"
JOURNAL_MARKER_DIRECTORY = "/run/kernaid-qemu-native-prompt-journal-proof"
JOURNAL_PROOF_STAGES = ("boot1", "boot2")
JOURNAL_MARKER_PROOF_TIMEOUT_SECONDS = 45.0


def _load_module(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


LIFECYCLE = _load_module("kernaid_native_prompt_lifecycle", LIFECYCLE_PATH)
UI_SMOKE = _load_module("kernaid_native_prompt_ui_smoke", UI_SMOKE_PATH)
ClosedFailure = LIFECYCLE.ClosedFailure


PRE_PROOF = textwrap.dedent(
    f"""
    import os,re,stat,subprocess,time
    FLAG={NATIVE_PROMPT_FLAG!r}
    ENV={{"HOME":"/","LANG":"C","LC_ALL":"C","PATH":"/usr/sbin:/usr/bin:/sbin:/bin"}}
    def show(unit,names):
        result=subprocess.run(["/usr/bin/systemctl","show",unit,"--property="+",".join(names)],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,env=ENV,timeout=3,check=False)
        if result.returncode!=0 or len(result.stdout)>4096: return None
        values={{}}
        for line in result.stdout.decode("ascii").splitlines():
            if "=" not in line: return None
            key,value=line.split("=",1)
            if key not in names or key in values: return None
            values[key]=value
        return values if set(values)==set(names) else None
    def valid():
        command=os.read(os.open("/proc/cmdline",os.O_RDONLY|os.O_CLOEXEC),4097)
        if len(command)>4096: return False
        tokens=command.decode("ascii").split()
        if tokens.count("boot=live")!=1 or tokens.count(FLAG)!=1: return False
        socket=show("kernaid-rescue-native-prompt.socket",("ActiveState","SubState","Result"))
        broker=show("kernaid-rescue-native-prompt.service",("ActiveState","SubState","Result","MainPID"))
        prompt=show("kernaid-rescue-native-vault-unlock.service",("ActiveState","SubState","Result"))
        desk=show("kernaid-rescue-desk-shell.service",("ActiveState","SubState","Result","MainPID"))
        try:
            endpoint=os.lstat("/run/kernaid-rescue-native-prompt.sock")
            active=open("/sys/class/tty/tty0/active","rb",buffering=0).read(16)
        except OSError: return False
        return socket=={{"ActiveState":"active","SubState":"listening","Result":"success"}} and broker is not None and broker["ActiveState"]=="active" and broker["SubState"]=="running" and broker["Result"]=="success" and broker["MainPID"].isdecimal() and int(broker["MainPID"])>1 and prompt is not None and prompt["ActiveState"]=="inactive" and prompt["SubState"]=="dead" and prompt["Result"] in ("","success") and desk is not None and desk["ActiveState"]=="active" and desk["SubState"]=="running" and desk["Result"]=="success" and desk["MainPID"].isdecimal() and int(desk["MainPID"])>1 and stat.S_ISSOCK(endpoint.st_mode) and endpoint.st_uid==0 and endpoint.st_nlink==1 and stat.S_IMODE(endpoint.st_mode)==0o660 and re.fullmatch(rb"tty([1-9]|[1-5][0-9]|6[0-3])\\n",active) is not None and active!=b"tty8\\n"
    deadline=time.monotonic()+45
    while time.monotonic()<deadline:
        try:
            if valid(): break
        except (OSError,UnicodeError,ValueError,subprocess.SubprocessError): pass
        time.sleep(0.1)
    else: raise SystemExit(45)
    print("KERNAID_QEMU_PROVIDER_PROOF_V1 stage=native-pre result=true")
    """
).strip().encode("ascii")


READY_PROOF = textwrap.dedent(
    f"""
    import os,re,subprocess,time
    FLAG={NATIVE_PROMPT_FLAG!r}
    ENV={{"HOME":"/","LANG":"C","LC_ALL":"C","PATH":"/usr/sbin:/usr/bin:/sbin:/bin"}}
    def show(unit,names):
        result=subprocess.run(["/usr/bin/systemctl","show",unit,"--property="+",".join(names)],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,env=ENV,timeout=3,check=False)
        if result.returncode!=0 or len(result.stdout)>4096: return None
        values={{}}
        for line in result.stdout.decode("ascii").splitlines():
            if "=" not in line: return None
            key,value=line.split("=",1)
            if key not in names or key in values: return None
            values[key]=value
        return values if set(values)==set(names) else None
    def valid():
        command=open("/proc/cmdline","rb",buffering=0).read(4097)
        if len(command)>4096: return False
        tokens=command.decode("ascii").split()
        if tokens.count("boot=live")!=1 or tokens.count(FLAG)!=1: return False
        prompt=show("kernaid-rescue-native-vault-unlock.service",("ActiveState","SubState","Result","MainPID","Type","NotifyAccess","User","Group"))
        broker=show("kernaid-rescue-native-prompt.service",("ActiveState","SubState","Result"))
        try: active=open("/sys/class/tty/tty0/active","rb",buffering=0).read(16)
        except OSError: return False
        return prompt is not None and prompt["ActiveState"]=="active" and prompt["SubState"]=="running" and prompt["Result"]=="success" and prompt["Type"]=="notify" and prompt["NotifyAccess"]=="main" and prompt["User"]=="kernaid" and prompt["Group"]=="kernaid" and prompt["MainPID"].isdecimal() and int(prompt["MainPID"])>1 and broker=={{"ActiveState":"active","SubState":"running","Result":"success"}} and active==b"tty8\\n"
    deadline=time.monotonic()+60
    while time.monotonic()<deadline:
        try:
            if valid(): break
        except (OSError,UnicodeError,ValueError,subprocess.SubprocessError): pass
        time.sleep(0.05)
    else: raise SystemExit(45)
    print("KERNAID_QEMU_PROVIDER_PROOF_V1 stage=native-ready result=true")
    """
).strip().encode("ascii")


POST_PROOF = textwrap.dedent(
    """
    import re,subprocess,time
    ENV={"HOME":"/","LANG":"C","LC_ALL":"C","PATH":"/usr/sbin:/usr/bin:/sbin:/bin"}
    def show(unit,names):
        result=subprocess.run(["/usr/bin/systemctl","show",unit,"--property="+",".join(names)],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,env=ENV,timeout=3,check=False)
        if result.returncode!=0 or len(result.stdout)>4096: return None
        values={}
        for line in result.stdout.decode("ascii").splitlines():
            if "=" not in line: return None
            key,value=line.split("=",1)
            if key not in names or key in values: return None
            values[key]=value
        return values if set(values)==set(names) else None
    def valid():
        prompt=show("kernaid-rescue-native-vault-unlock.service",("ActiveState","SubState","Result"))
        socket=show("kernaid-rescue-native-prompt.socket",("ActiveState","SubState","Result"))
        broker=show("kernaid-rescue-native-prompt.service",("ActiveState","SubState","Result"))
        desk=show("kernaid-rescue-desk-shell.service",("ActiveState","SubState","Result"))
        try: active=open("/sys/class/tty/tty0/active","rb",buffering=0).read(16)
        except OSError: return False
        return prompt=={"ActiveState":"inactive","SubState":"dead","Result":"success"} and socket=={"ActiveState":"active","SubState":"listening","Result":"success"} and broker=={"ActiveState":"active","SubState":"running","Result":"success"} and desk=={"ActiveState":"active","SubState":"running","Result":"success"} and re.fullmatch(rb"tty([1-9]|[1-5][0-9]|6[0-3])\\n",active) is not None and active!=b"tty8\\n"
    deadline=time.monotonic()+630
    while time.monotonic()<deadline:
        try:
            if valid(): break
        except (OSError,UnicodeError,subprocess.SubprocessError): pass
        time.sleep(0.1)
    else: raise SystemExit(45)
    print("KERNAID_QEMU_PROVIDER_PROOF_V1 stage=native-post result=true")
    """
).strip().encode("ascii")


def _journal_marker_proof(stage: str) -> bytes:
    if stage not in JOURNAL_PROOF_STAGES:
        raise ClosedFailure("journal", "proof-invalid")
    marker = (
        f"KERNAID_QEMU_NATIVE_PROMPT_JOURNAL_PROOF_V1 stage={stage} "
        "euid=root scope=full-current-boot entries=true coverage=true secret-absent=true\n"
    )
    source = textwrap.dedent(
        f"""
        import os,stat,subprocess,time
        PATH={f"{JOURNAL_MARKER_DIRECTORY}/{stage}"!r}
        EXPECTED={marker.encode("ascii")!r}
        ENV={{"HOME":"/","LANG":"C","LC_ALL":"C","PATH":"/usr/sbin:/usr/bin:/sbin:/bin"}}
        UNIT="kernaid-qemu-native-prompt-journal-proof@{stage}.service"
        deadline=time.monotonic()+35
        while time.monotonic()<deadline:
            try:
                item=os.lstat(PATH)
                result=subprocess.run(["/usr/bin/systemctl","show",UNIT,"--property=ActiveState,SubState,Result,ExecMainStatus,User,Group"],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,env=ENV,timeout=3,check=False)
                values=dict(line.split("=",1) for line in result.stdout.decode("ascii").splitlines())
                with open(PATH,"rb",buffering=0) as stream: content=stream.read(len(EXPECTED)+1)
                if stat.S_ISREG(item.st_mode) and item.st_uid==0 and item.st_gid==0 and item.st_nlink==1 and stat.S_IMODE(item.st_mode)==0o444 and item.st_size==len(EXPECTED) and content==EXPECTED and result.returncode==0 and values=={{"ActiveState":"inactive","SubState":"dead","Result":"success","ExecMainStatus":"0","User":"root","Group":"root"}}: break
            except (OSError,UnicodeError,ValueError,subprocess.SubprocessError): pass
            time.sleep(0.1)
        else: raise SystemExit(45)
        print("KERNAID_QEMU_PROVIDER_PROOF_V1 stage=native-journal-{stage} result=true")
        """
    ).strip().encode("ascii")
    if len(source) > 16 * 1024:
        raise ClosedFailure("journal", "proof-invalid")
    return source


def _new_passphrase() -> bytearray:
    value = bytearray(SECRET_BYTES)
    try:
        for index in range(len(value)):
            value[index] = HEX_ALPHABET[secrets.randbelow(len(HEX_ALPHABET))]
    except BaseException as error:
        LIFECYCLE.wipe(value)
        raise ClosedFailure("secret", "generation-failed") from error
    return value


def _deadline(aggregate: float, seconds: float) -> float:
    return min(aggregate, time.monotonic() + seconds)


def _tool(name: str) -> str:
    value = shutil.which(name)
    if value is None:
        raise ClosedFailure("preflight", "tool-missing")
    path = Path(value).resolve()
    try:
        metadata = path.stat()
    except OSError as error:
        raise ClosedFailure("preflight", "tool-invalid") from error
    if not path.is_absolute() or not stat.S_ISREG(metadata.st_mode) or not os.access(path, os.X_OK):
        raise ClosedFailure("preflight", "tool-invalid")
    return os.fspath(path)


def _run_fixed_tool(arguments: Sequence[str], stage: str, timeout: float) -> None:
    try:
        result = subprocess.run(
            list(arguments),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=timeout,
            env={"HOME": "/", "LANG": "C", "LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise ClosedFailure(stage, "tool-failed") from error
    if result.returncode != 0:
        raise ClosedFailure(stage, "tool-failed")


def _validate_private_directory(path: Path) -> None:
    metadata = path.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or metadata.st_uid != os.geteuid()
        or metadata.st_gid != os.getegid()
    ):
        raise ClosedFailure("allocation", "directory-invalid")


def _validate_regular(path: Path, *, minimum: int, maximum: int) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ClosedFailure("image", "file-invalid") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or not minimum <= metadata.st_size <= maximum
    ):
        raise ClosedFailure("image", "file-invalid")
    return metadata


def _identity(metadata: os.stat_result) -> tuple[int, int, int, int]:
    return metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns


def _validate_media(
    media: Path,
    expected: tuple[int, int, int, int],
    *,
    mode: int | None = None,
) -> os.stat_result:
    metadata = media.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != os.geteuid()
        or metadata.st_gid != os.getegid()
        or _identity(metadata) != expected
        or (mode is not None and stat.S_IMODE(metadata.st_mode) != mode)
    ):
        raise ClosedFailure("media", "identity-changed")
    return metadata


def _refresh_media_identity(
    media: Path, previous: tuple[int, int, int, int]
) -> tuple[int, int, int, int]:
    metadata = media.lstat()
    current = _identity(metadata)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != os.geteuid()
        or metadata.st_gid != os.getegid()
        or current[:3] != previous[:3]
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise ClosedFailure("media", "identity-changed")
    return current


def _extract_iso_file(
    xorriso: str,
    media: Path,
    expected_media: tuple[int, int, int, int],
    source: str,
    destination: Path,
) -> None:
    if destination.exists() or destination.is_symlink():
        raise ClosedFailure("extract", "destination-exists")
    _validate_media(media, expected_media, mode=0o400)
    _run_fixed_tool(
        (
            xorriso,
            "-abort_on",
            "FAILURE",
            "-osirrox",
            "on",
            "-indev",
            os.fspath(media),
            "-extract",
            source,
            os.fspath(destination),
        ),
        "extract",
        180.0,
    )
    _validate_media(media, expected_media, mode=0o400)
    os.chmod(destination, 0o600, follow_symlinks=False)


def _boot_append(config: bytes) -> str:
    if not config or len(config) > MAX_CONFIG_BYTES or b"\0" in config:
        raise ClosedFailure("extract", "boot-config-invalid")
    try:
        lines = config.decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        raise ClosedFailure("extract", "boot-config-invalid") from error
    candidates: list[list[str]] = []
    for line in lines:
        stripped = line.strip()
        if not stripped.startswith("append "):
            continue
        tokens = stripped.removeprefix("append ").split()
        if "boot=live" in tokens and "nomodeset" not in tokens:
            candidates.append(tokens)
    if len(candidates) != 1:
        raise ClosedFailure("extract", "boot-config-invalid")
    tokens = [token for token in candidates[0] if not token.startswith("initrd=")]
    if (
        tokens.count("boot=live") != 1
        or any(token == "kernaid.native-prompt" or token.startswith("kernaid.native-prompt=") for token in tokens)
        or any(not token or any(ord(character) < 33 or ord(character) > 126 for character in token) for token in tokens)
    ):
        raise ClosedFailure("extract", "boot-config-invalid")
    value = " ".join(tokens)
    if len(value) > 4096:
        raise ClosedFailure("extract", "boot-config-invalid")
    return value


def _extract_payload(
    media: Path,
    expected_media: tuple[int, int, int, int],
    iso_size: int,
    iso_digest: str,
    work_directory: Path,
    secret_directory: Path,
) -> tuple[Path, Path, str, bytearray]:
    xorriso = _tool("xorriso")
    unsquashfs = _tool("unsquashfs")
    kernel = work_directory / "vmlinuz"
    initrd = work_directory / "initrd.img"
    squashfs = work_directory / "filesystem.squashfs"
    boot_config = work_directory / "live.cfg"
    if _sha256(media, iso_size, expected_media) != iso_digest:
        raise ClosedFailure("extract", "media-digest-changed")
    for source, destination in (
        ("/live/vmlinuz", kernel),
        ("/live/initrd.img", initrd),
        ("/live/filesystem.squashfs", squashfs),
        ("/isolinux/live.cfg", boot_config),
    ):
        _extract_iso_file(xorriso, media, expected_media, source, destination)
    if _sha256(media, iso_size, expected_media) != iso_digest:
        raise ClosedFailure("extract", "media-digest-changed")
    _validate_regular(kernel, minimum=1, maximum=512 * 1024 * 1024)
    _validate_regular(initrd, minimum=1, maximum=2 * 1024 * 1024 * 1024)
    _validate_regular(squashfs, minimum=1, maximum=8 * 1024 * 1024 * 1024)
    config_metadata = _validate_regular(boot_config, minimum=1, maximum=MAX_CONFIG_BYTES)
    with boot_config.open("rb", buffering=0) as stream:
        config = stream.read(config_metadata.st_size + 1)
    append = _boot_append(config)

    credential_path = secret_directory / "login"
    credential_fd = os.open(
        credential_path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
    )
    process: subprocess.Popen[bytes] | None = None
    try:
        process = subprocess.Popen(
            (
                unsquashfs,
                "-cat",
                os.fspath(squashfs),
                "usr/lib/live/config/0030-user-setup",
            ),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            env={"HOME": "/", "LANG": "C", "LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
        )
        assert process.stdout is not None
        source_fd = os.dup(process.stdout.fileno())
        LIFECYCLE.extract_live_credential(
            source_fd,
            credential_fd,
            expected_uid=os.geteuid(),
            expected_gid=os.getegid(),
        )
        credential_fd = -1
        process.stdout.close()
        if process.wait(timeout=30.0) != 0:
            raise ClosedFailure("credential", "extract-failed")
        process = None
        login = LIFECYCLE.read_login_credential_fd(
            os.open(credential_path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW),
            expected_uid=os.geteuid(),
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise ClosedFailure("credential", "extract-failed") from error
    finally:
        if credential_fd >= 0:
            try:
                os.close(credential_fd)
            except OSError:
                pass
        if process is not None:
            try:
                process.kill()
                process.wait(timeout=5.0)
            except (OSError, subprocess.SubprocessError):
                pass
            if process.stdout is not None:
                process.stdout.close()
        try:
            credential_path.unlink()
        except FileNotFoundError:
            pass
    return kernel, initrd, append, login


def _copy_iso_to_media(
    iso: Path, iso_metadata: os.stat_result, media: Path
) -> tuple[str, tuple[int, int, int, int]]:
    source = os.open(iso, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    descriptor = os.open(
        media,
        os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
    )
    buffer = bytearray(4 * 1024 * 1024)
    view = memoryview(buffer)
    digest = hashlib.sha256()
    try:
        source_before = os.fstat(source)
        if _identity(source_before) != _identity(iso_metadata):
            raise ClosedFailure("media", "source-identity-changed")
        os.ftruncate(descriptor, MEDIA_BYTES)
        remaining = iso_metadata.st_size
        while remaining:
            count = os.readv(source, [view[: min(len(buffer), remaining)]])
            if count <= 0:
                raise ClosedFailure("media", "source-short-read")
            digest.update(view[:count])
            written = 0
            while written < count:
                step = os.write(descriptor, view[written:count])
                if step <= 0:
                    raise ClosedFailure("media", "copy-failed")
                written += step
            remaining -= count
        if os.read(source, 1):
            raise ClosedFailure("media", "source-grew")
        os.fsync(descriptor)
        source_after = os.fstat(source)
        if _identity(source_after) != _identity(source_before):
            raise ClosedFailure("media", "source-identity-changed")
        media_metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(media_metadata.st_mode)
            or media_metadata.st_nlink != 1
            or media_metadata.st_size != MEDIA_BYTES
        ):
            raise ClosedFailure("media", "copy-failed")
        return digest.hexdigest(), _identity(media_metadata)
    except OSError as error:
        raise ClosedFailure("media", "copy-failed") from error
    finally:
        view.release()
        LIFECYCLE.wipe(buffer)
        os.close(source)
        os.close(descriptor)


def _sha256(
    path: Path,
    length: int | None = None,
    expected_identity: tuple[int, int, int, int] | None = None,
) -> str:
    digest = hashlib.sha256()
    remaining = length
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        before = os.fstat(descriptor)
        if expected_identity is not None and _identity(before) != expected_identity:
            raise ClosedFailure("digest", "identity-changed")
        while remaining is None or remaining > 0:
            maximum = 4 * 1024 * 1024 if remaining is None else min(4 * 1024 * 1024, remaining)
            block = os.read(descriptor, maximum)
            if not block:
                break
            digest.update(block)
            if remaining is not None:
                remaining -= len(block)
        after = os.fstat(descriptor)
        if _identity(after) != _identity(before):
            raise ClosedFailure("digest", "identity-changed")
    except OSError as error:
        raise ClosedFailure("digest", "read-failed") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if remaining not in (None, 0):
        raise ClosedFailure("digest", "short-read")
    return digest.hexdigest()


def _copy_iso_prefix(
    media: Path,
    expected_media: tuple[int, int, int, int],
    iso_size: int,
    destination: Path,
) -> None:
    _validate_media(media, expected_media, mode=0o400)
    source = os.open(media, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    output = os.open(
        destination,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o400,
    )
    try:
        remaining = iso_size
        while remaining:
            block = os.read(source, min(4 * 1024 * 1024, remaining))
            if not block:
                raise ClosedFailure("image", "prefix-short-read")
            view = memoryview(block)
            try:
                while view:
                    written = os.write(output, view)
                    if written <= 0:
                        raise ClosedFailure("image", "prefix-copy-failed")
                    view = view[written:]
            finally:
                view.release()
            remaining -= len(block)
        os.fsync(output)
    except OSError as error:
        raise ClosedFailure("image", "prefix-copy-failed") from error
    finally:
        os.close(source)
        os.close(output)
    _validate_media(media, expected_media, mode=0o400)


def _qemu_arguments(
    media: Path,
    kernel: Path | None,
    initrd: Path | None,
    append: str | None,
    secret_digest: str,
) -> list[str]:
    if "," in os.fspath(media) or re.fullmatch(r"[0-9a-f]{64}", secret_digest) is None:
        raise ClosedFailure("qemu", "path-invalid")
    arguments = [
        "-machine",
        "accel=tcg",
        "-m",
        "2048",
        "-smp",
        "2",
        "-nic",
        "none",
        "-boot",
        "strict=on,menu=off",
        "-vga",
        "std",
        "-device",
        "qemu-xhci,id=kernaid_xhci",
        "-drive",
        f"if=none,id=kernaid_rescue_usb,file={media},format=raw,cache=none,aio=threads",
        "-device",
        "usb-storage,bus=kernaid_xhci.0,drive=kernaid_rescue_usb,bootindex=1",
        "-fw_cfg",
        "name=opt/kernaid-tauri-sandbox-probe,string=v1",
        "-fw_cfg",
        f"name=opt/kernaid-native-vault-secret-digest,string={secret_digest}",
    ]
    direct = kernel is not None or initrd is not None or append is not None
    if direct:
        if kernel is None or initrd is None or append is None:
            raise ClosedFailure("qemu", "direct-kernel-invalid")
        arguments.extend(("-kernel", os.fspath(kernel), "-initrd", os.fspath(initrd), "-append", append))
    return arguments


def _capture_frame(qmp: object, path: Path, work_directory: Path) -> tuple[int, int, bytes]:
    try:
        if path.exists() or path.is_symlink():
            raise UI_SMOKE.SmokeError("frame exists")
        qmp.execute("screendump", {"filename": os.fspath(path)})
        payload = UI_SMOKE._read_exact_screenshot(path, work_directory)
        return UI_SMOKE.parse_ppm(payload)
    except (OSError, UI_SMOKE.SmokeError) as error:
        raise ClosedFailure("framebuffer", "capture-failed") from error
    finally:
        try:
            UI_SMOKE._remove_screenshot(path, work_directory)
        except (OSError, UI_SMOKE.SmokeError):
            pass


def _find_brand_frame(qmp: object, work_directory: Path, deadline: float) -> tuple[int, int, bytes]:
    path = work_directory / "before.ppm"
    for _ in range(FRAME_ATTEMPTS):
        width, height, pixels = _capture_frame(qmp, path, work_directory)
        if UI_SMOKE.is_kernaid_render(pixels):
            return width, height, pixels
        if time.monotonic() >= deadline:
            break
        time.sleep(FRAME_SETTLE_SECONDS)
    raise ClosedFailure("framebuffer", "brand-missing")


def _require_prompt_frame(
    qmp: object,
    work_directory: Path,
    baseline: tuple[int, int, bytes],
    deadline: float,
) -> None:
    path = work_directory / "after.ppm"
    width, height, before = baseline
    for _ in range(FRAME_ATTEMPTS):
        next_width, next_height, pixels = _capture_frame(qmp, path, work_directory)
        if (
            (next_width, next_height) == (width, height)
            and not UI_SMOKE.is_kernaid_render(pixels)
            and UI_SMOKE.changed_pixels(before, pixels) >= 500
        ):
            return
        if time.monotonic() >= deadline:
            break
        time.sleep(FRAME_SETTLE_SECONDS)
    raise ClosedFailure("framebuffer", "prompt-missing")


def _send_alt_u(qmp: object) -> None:
    events = [
        (True, "alt"),
        (True, "u"),
        (False, "u"),
        (False, "alt"),
    ]
    qmp.execute(
        "input-send-event",
        {
            "events": [
                {
                    "type": "key",
                    "data": {
                        "down": down,
                        "key": {"type": "qcode", "data": qcode},
                    },
                }
                for down, qcode in events
            ]
        },
    )


def _captures_exclude_secret(harness: object, secret: bytearray) -> None:
    if harness.serial_capture.snapshot().find(secret) >= 0 or harness.output_capture.snapshot().find(secret) >= 0:
        raise ClosedFailure("secret", "exposure")


def _run_firstboot(
    qemu: str,
    media: Path,
    work_directory: Path,
    secret: bytearray,
    login: bytearray,
    secret_digest: str,
    media_identity: tuple[int, int, int, int],
    iso_size: int,
    iso_digest: str,
    timeout: float,
) -> tuple[int, int, int, int]:
    _validate_media(media, media_identity, mode=0o600)
    if _sha256(media, iso_size, media_identity) != iso_digest:
        raise ClosedFailure("media", "prefix-changed")
    qmp_path = work_directory / "qmp.sock"
    harness = LIFECYCLE.QemuHarness(
        qemu,
        _qemu_arguments(media, None, None, None, secret_digest),
        qmp_path,
        [secret, login],
        [secret, login],
    )
    aggregate = time.monotonic() + timeout
    try:
        console, qmp = harness.start(_deadline(aggregate, LIFECYCLE.QEMU_START_TIMEOUT_SECONDS))
        prompt = console.wait_regex(
            re.compile(rb"KERNAID_RESCUE_FIRSTBOOT_PROMPT_READY_V1 step=passphrase"),
            start=0,
            deadline=_deadline(aggregate, LIFECYCLE.READINESS_TIMEOUT_SECONDS),
            stage="firstboot-start",
        )
        qmp.set_deadline(_deadline(aggregate, 10.0))
        qmp.send_hex_line(secret)
        confirmation = console.wait_regex(
            re.compile(rb"KERNAID_RESCUE_FIRSTBOOT_PROMPT_READY_V1 step=confirmation"),
            start=prompt.end(),
            deadline=_deadline(aggregate, LIFECYCLE.READINESS_TIMEOUT_SECONDS),
            stage="firstboot-confirmation",
        )
        qmp.set_deadline(_deadline(aggregate, 10.0))
        qmp.send_hex_line(secret)
        LIFECYCLE.wait_firstboot_attestation(
            console,
            confirmation.end(),
            _deadline(aggregate, LIFECYCLE.READINESS_TIMEOUT_SECONDS),
        )
        cursor = LIFECYCLE.establish_live_session(console, aggregate, login)
        status, cursor = LIFECYCLE.run_companion(
            console, "status", "native-boot1-status", cursor, aggregate
        )
        if status.return_code != 0 or status.vault_state != "locked" or status.device_id is not None:
            raise ClosedFailure("firstboot", "vault-not-locked")
        LIFECYCLE.run_guest_proof(
            console,
            "native-journal-boot1",
            _journal_marker_proof("boot1"),
            cursor,
            aggregate,
            timeout=JOURNAL_MARKER_PROOF_TIMEOUT_SECONDS,
        )
        qmp.set_deadline(_deadline(aggregate, 10.0))
        qmp.system_powerdown()
        harness.wait_for_shutdown(_deadline(aggregate, LIFECYCLE.ACPI_SHUTDOWN_SECONDS))
        _captures_exclude_secret(harness, secret)
    finally:
        harness.cleanup()
    current = _refresh_media_identity(media, media_identity)
    if _sha256(media, iso_size, current) != iso_digest:
        raise ClosedFailure("media", "prefix-changed")
    return current


def _run_prompt_boot(
    qemu: str,
    media: Path,
    kernel: Path,
    initrd: Path,
    boot_append: str,
    work_directory: Path,
    secret: bytearray,
    login: bytearray,
    secret_digest: str,
    media_identity: tuple[int, int, int, int],
    iso_size: int,
    iso_digest: str,
    timeout: float,
) -> tuple[str, int, int, tuple[int, int, int, int]]:
    _validate_media(media, media_identity, mode=0o600)
    if _sha256(media, iso_size, media_identity) != iso_digest:
        raise ClosedFailure("media", "prefix-changed")
    qmp_path = work_directory / "qmp.sock"
    append = f"{boot_append} {NATIVE_PROMPT_FLAG}"
    if append.split().count(NATIVE_PROMPT_FLAG) != 1:
        raise ClosedFailure("gate", "flag-invalid")
    harness = LIFECYCLE.QemuHarness(
        qemu,
        _qemu_arguments(media, kernel, initrd, append, secret_digest),
        qmp_path,
        [secret, login],
        # live-config's public default login is the literal "live", which is
        # necessarily a substring of the required direct-boot token
        # "boot=live". Keep it forbidden in both bounded output captures, but
        # metadata-gate the high-entropy Vault passphrase only; every QEMU
        # argument remains closed by _qemu_arguments() and _boot_append().
        [secret],
    )
    aggregate = time.monotonic() + timeout
    try:
        console, qmp = harness.start(_deadline(aggregate, LIFECYCLE.QEMU_START_TIMEOUT_SECONDS))
        cursor = LIFECYCLE.establish_live_session(console, aggregate, login)
        before_status, cursor = LIFECYCLE.run_companion(
            console, "status", "native-pre-status", cursor, aggregate
        )
        if (
            before_status.return_code != 0
            or before_status.vault_state != "locked"
            or before_status.device_id is not None
        ):
            raise ClosedFailure("prompt", "vault-not-locked")
        baseline = _find_brand_frame(qmp, work_directory, _deadline(aggregate, 30.0))
        cursor = LIFECYCLE.run_guest_proof(
            console, "native-pre", PRE_PROOF, cursor, aggregate, timeout=60.0
        )
        time.sleep(0.5)
        qmp.set_deadline(_deadline(aggregate, 10.0))
        _send_alt_u(qmp)
        cursor = LIFECYCLE.run_guest_proof(
            console, "native-ready", READY_PROOF, cursor, aggregate, timeout=75.0
        )
        _require_prompt_frame(qmp, work_directory, baseline, _deadline(aggregate, 15.0))
        qmp.set_deadline(_deadline(aggregate, 10.0))
        qmp.send_hex_line(secret)
        cursor = LIFECYCLE.run_guest_proof(
            console, "native-post", POST_PROOF, cursor, aggregate, timeout=650.0
        )
        after_status, cursor = LIFECYCLE.run_companion(
            console, "status", "native-post-status", cursor, aggregate
        )
        if (
            after_status.return_code != 0
            or after_status.vault_state != "unlocked"
            or after_status.state_version != before_status.state_version + 2
            or after_status.device_id is None
            or LIFECYCLE.DEVICE_ID_RE.fullmatch(after_status.device_id) is None
        ):
            raise ClosedFailure("prompt", "unlock-invalid")
        LIFECYCLE.run_guest_proof(
            console,
            "native-journal-boot2",
            _journal_marker_proof("boot2"),
            cursor,
            aggregate,
            timeout=JOURNAL_MARKER_PROOF_TIMEOUT_SECONDS,
        )
        returned = _find_brand_frame(qmp, work_directory, _deadline(aggregate, 30.0))
        if returned[:2] != baseline[:2]:
            raise ClosedFailure("framebuffer", "dimension-changed")
        qmp.set_deadline(_deadline(aggregate, 10.0))
        qmp.system_powerdown()
        harness.wait_for_shutdown(_deadline(aggregate, LIFECYCLE.ACPI_SHUTDOWN_SECONDS))
        _captures_exclude_secret(harness, secret)
    finally:
        harness.cleanup()
    current = _refresh_media_identity(media, media_identity)
    if _sha256(media, iso_size, current) != iso_digest:
        raise ClosedFailure("media", "prefix-changed")
    return after_status.device_id, returned[0], returned[1], current


def _parse_arguments(arguments: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iso", required=True, type=Path)
    parser.add_argument("--qemu", default="qemu-system-x86_64")
    parser.add_argument("--timeout", type=int, default=3_600)
    parsed = parser.parse_args(arguments)
    if not MIN_TOTAL_TIMEOUT_SECONDS <= parsed.timeout <= MAX_TOTAL_TIMEOUT_SECONDS:
        raise ClosedFailure("arguments", "timeout-invalid")
    if not parsed.iso.is_absolute():
        raise ClosedFailure("arguments", "iso-not-absolute")
    return parsed


def run(arguments: Sequence[str]) -> str:
    parsed = _parse_arguments(arguments)
    iso_metadata = _validate_regular(parsed.iso, minimum=512, maximum=MAX_ISO_BYTES)
    qemu = _tool(parsed.qemu)
    work_root = Path(tempfile.mkdtemp(prefix="kernaid-qemu-native-prompt.", dir="/tmp"))
    secret_root = Path(tempfile.mkdtemp(prefix="kernaid-qemu-native-prompt.", dir="/dev/shm"))
    os.chmod(work_root, 0o700)
    os.chmod(secret_root, 0o700)
    login = bytearray()
    passphrase = bytearray()
    try:
        _validate_private_directory(work_root)
        _validate_private_directory(secret_root)
        media = work_root / "KernAid-Rescue-usb.raw"
        iso_digest, media_identity = _copy_iso_to_media(
            parsed.iso, iso_metadata, media
        )
        os.chmod(media, 0o400, follow_symlinks=False)
        _validate_media(media, media_identity, mode=0o400)
        if _sha256(media, iso_metadata.st_size, media_identity) != iso_digest:
            raise ClosedFailure("media", "prefix-mismatch")
        private_iso = work_root / "KernAid-Rescue-amd64.iso"
        _copy_iso_prefix(media, media_identity, iso_metadata.st_size, private_iso)
        private_metadata = _validate_regular(
            private_iso, minimum=512, maximum=MAX_ISO_BYTES
        )
        private_identity = _identity(private_metadata)
        if private_metadata.st_size != iso_metadata.st_size or _sha256(private_iso) != iso_digest:
            raise ClosedFailure("image", "private-prefix-invalid")
        _run_fixed_tool(
            (
                sys.executable,
                "-I",
                "-B",
                os.fspath(LAYOUT_TOOL),
                "verify",
                "--manifest",
                os.fspath(LAYOUT_MANIFEST),
                "--image",
                os.fspath(private_iso),
            ),
            "image",
            60.0,
        )
        private_after = _validate_regular(
            private_iso, minimum=512, maximum=MAX_ISO_BYTES
        )
        if _identity(private_after) != private_identity or _sha256(private_iso) != iso_digest:
            raise ClosedFailure("image", "private-prefix-changed")
        kernel, initrd, boot_append, login = _extract_payload(
            media,
            media_identity,
            iso_metadata.st_size,
            iso_digest,
            work_root,
            secret_root,
        )
        passphrase = _new_passphrase()
        if passphrase == login:
            raise ClosedFailure("secret", "generation-failed")
        secret_digest = hashlib.sha256(passphrase).hexdigest()
        os.chmod(media, 0o600, follow_symlinks=False)
        _validate_media(media, media_identity, mode=0o600)

        boot_budget = parsed.timeout / 2
        boot1_directory = work_root / "boot1"
        boot2_directory = work_root / "boot2"
        boot1_directory.mkdir(mode=0o700)
        boot2_directory.mkdir(mode=0o700)
        media_identity = _run_firstboot(
            qemu,
            media,
            boot1_directory,
            passphrase,
            login,
            secret_digest,
            media_identity,
            iso_metadata.st_size,
            iso_digest,
            boot_budget,
        )
        device_id, width, height, media_identity = _run_prompt_boot(
            qemu,
            media,
            kernel,
            initrd,
            boot_append,
            boot2_directory,
            passphrase,
            login,
            secret_digest,
            media_identity,
            iso_metadata.st_size,
            iso_digest,
            boot_budget,
        )
        _validate_media(media, media_identity, mode=0o600)
        return (
            f"{ATTESTATION_PREFIX} firmware=bios image=exact-usb "
            "boot1=provisioned boot2=direct-kernel-same-iso gate=vt-v1 "
            "socket=available broker=tauri-authenticated "
            "request=webview-tauri-enum-nonce prompt=tty8-ready-notify "
            "qmp-secret-input=true captured-secret-exposure=false "
            "journald-secret-exposure=false journald-scope=root-full-current-boot "
            "vault=unlocked "
            f"device_id={device_id} iso_sha256={iso_digest} "
            f"return=graphical-ui width={width} height={height} "
            "iso-prefix-immutable=true acpi-shutdowns=2 ready=true"
        )
    finally:
        LIFECYCLE.wipe(passphrase)
        LIFECYCLE.wipe(login)
        for directory in (secret_root, work_root):
            try:
                shutil.rmtree(directory)
            except FileNotFoundError:
                pass


def main(arguments: Sequence[str]) -> int:
    previous_handlers: dict[object, object] = {}
    previous_mask: set[object] | None = None
    failure: ClosedFailure | None = None
    attestation: str | None = None
    try:
        previous_handlers, previous_mask = LIFECYCLE.install_signal_guard()
        attestation = run(arguments)
    except ClosedFailure as error:
        failure = error
    except (LIFECYCLE.ControllerSignal, KeyboardInterrupt, SystemExit):
        failure = ClosedFailure("controller", "interrupted")
    except BaseException:
        failure = ClosedFailure("controller", "unexpected")
    finally:
        LIFECYCLE.enter_signal_safe_cleanup(previous_handlers)
        LIFECYCLE.restore_signal_guard(previous_handlers, previous_mask)
    if failure is not None:
        print(
            f"{FAILURE_PREFIX} stage={failure.stage} code={failure.code}",
            file=sys.stderr,
            flush=True,
        )
        return 1
    if attestation is None:
        print(
            f"{FAILURE_PREFIX} stage=controller code=unexpected",
            file=sys.stderr,
            flush=True,
        )
        return 1
    print(attestation, flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
