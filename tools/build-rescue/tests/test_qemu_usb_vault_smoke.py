from __future__ import annotations

import hashlib
import importlib.util
import os
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


TOOLS_DIR = Path(__file__).resolve().parents[1]
REPO_DIR = Path(__file__).resolve().parents[3]
SCRIPT = TOOLS_DIR / "qemu-usb-smoke.sh"
LAYOUT_MANIFEST = REPO_DIR / "rescue/image-layout/device-layout.v1.json"
CATALOG_V2_PATH = REPO_DIR / "tools/make-device/catalog_v2.py"
ENTRY_V2_PATH = REPO_DIR / "tools/make-device/catalog-entry-v2.py"
PROFILE_VERIFIER_PATH = TOOLS_DIR / "verify-vault-profile.py"


def load_module(name: str, path: Path) -> object:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


catalog_v2 = load_module("kernaid_mock_catalog_v2", CATALOG_V2_PATH)
entry_v2 = load_module("kernaid_mock_entry_v2", ENTRY_V2_PATH)
profile_verifier = load_module("kernaid_mock_profile_verifier", PROFILE_VERIFIER_PATH)


def partition_entry(
    *, status: int, type_code: int, start_lba: int, sector_count: int
) -> bytes:
    return (
        bytes((status,))
        + b"\x00\x02\x00"
        + bytes((type_code,))
        + b"\xfe\xff\xff"
        + struct.pack("<II", start_lba, sector_count)
    )


def write_finalized_fixture(path: Path) -> None:
    image = bytearray(4 * 1024 * 1024)
    image[446:462] = partition_entry(
        status=0x80, type_code=0x00, start_lba=64, sector_count=8000
    )
    image[462:478] = partition_entry(
        status=0x00, type_code=0xEF, start_lba=512, sector_count=256
    )
    image[478:494] = (
        bytes.fromhex("00feffff83feffff")
        + struct.pack("<II", 33_554_432, 16_777_216)
    )
    image[510:512] = b"\x55\xaa"
    path.write_bytes(image)


def executable(path: Path, source: str) -> None:
    path.write_text(textwrap.dedent(source).lstrip(), encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def shell_function(source: str, name: str) -> str:
    match = re.search(
        rf"^{re.escape(name)}\(\) \{{\n(?P<body>.*?)^\}}$",
        source,
        re.MULTILINE | re.DOTALL,
    )
    if match is None:
        raise AssertionError(f"shell function is missing: {name}")
    return match.group("body")


class MockToolchain:
    def __init__(self, directory: Path) -> None:
        self.root = directory
        self.bin = directory / "bin"
        self.state = directory / "state"
        self.bin.mkdir()
        self.state.mkdir()
        self._install()

    def _tool(self, name: str, source: str) -> None:
        executable(self.bin / name, source)

    def _install(self) -> None:
        self._tool(
            "id",
            """
            #!/usr/bin/env bash
            if [[ "${1:-}" == "-u" ]]; then printf '0\n'; else /usr/bin/id "$@"; fi
            """,
        )
        self._tool(
            "findmnt",
            """
            #!/usr/bin/env bash
            printf 'tmpfs\n'
            """,
        )
        self._tool(
            "stat",
            """
            #!/usr/bin/env bash
            if [[ "$*" == *"%a:%u:%g"* ]]; then
              case "${@: -1}" in
                */.kernaid-codex-home-v1/config.toml) printf '600:973:973:36\n' ;;
                */.kernaid-codex-home-v1) printf '700:973:973\n' ;;
                */.kernaid-secure-state-v1) printf '700:0:0\n' ;;
                *) printf '600:0:0\n' ;;
              esac
            else
              /usr/bin/stat "$@"
            fi
            """,
        )
        self._tool(
            "chown",
            """
            #!/usr/bin/env bash
            exit 0
            """,
        )
        self._tool(
            "losetup",
            """
            #!/usr/bin/env bash
            set -euo pipefail
            state="$KERNAID_MOCK_STATE_DIR"
            if [[ " $* " == *" --find "* && " $* " == *" --show "* ]]; then
              printf '%s\n' "${@: -1}" >"$state/backing"
              : >"$state/loop-attached"
              printf '/dev/loop0\n'
            elif [[ "${1:-}" == "--noheadings" ]]; then
              case "$*" in
                *BACK-FILE*) cat "$state/backing" ;;
                *OFFSET*) printf '17179869184\n' ;;
                *SIZELIMIT*) printf '8589934592\n' ;;
                *) exit 2 ;;
              esac
            elif [[ "${1:-}" == "-d" ]]; then
              rm -f "$state/loop-attached"
            elif [[ "${1:-}" == "-j" ]]; then
              if [[ -e "$state/loop-attached" ]]; then
                printf '/dev/loop0: []: (%s)\n' "$2"
              fi
            else
              exit 2
            fi
            """,
        )
        self._tool(
            "udevadm",
            """
            #!/usr/bin/env bash
            exit 0
            """,
        )
        self._tool(
            "cryptsetup",
            """
            #!/usr/bin/env bash
            set -euo pipefail
            state="$KERNAID_MOCK_STATE_DIR"
            command="${1:-}"
            case "$command" in
              luksFormat|isLuks) exit 0 ;;
              luksDump)
                printf '{}\n'
                ;;
              luksUUID)
                printf '11111111-2222-4333-8444-555555555555\n'
                ;;
              open)
                mapper="${@: -1}"
                : >"$state/mapper.$mapper"
                ;;
              close)
                if [[ "${KERNAID_MOCK_CLOSE_FAIL:-0}" == "1" \
                  && "$2" == kernaid-vault-* ]]; then
                  : >"$state/manager-close-failed"
                  exit 1
                fi
                rm -f "$state/mapper.${2:?}"
                ;;
              status)
                [[ -e "$state/mapper.${2:?}" ]]
                ;;
              *) exit 2 ;;
            esac
            """,
        )
        self._tool(
            "blkid",
            """
            #!/usr/bin/env bash
            set -euo pipefail
            tag=""
            previous=""
            for argument in "$@"; do
              if [[ "$previous" == "--match-tag" ]]; then tag="$argument"; fi
              previous="$argument"
            done
            device="${@: -1}"
            if [[ "$device" == /dev/loop0 ]]; then
              case "$tag" in
                TYPE) printf 'crypto_LUKS\n' ;;
                VERSION) printf '2\n' ;;
                LABEL) printf 'KERNAID_VAULT\n' ;;
                *) exit 2 ;;
              esac
            else
              case "$tag" in
                TYPE) printf 'ext4\n' ;;
                LABEL) printf 'KERNAID_VAULT\n' ;;
                UUID) printf 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee\n' ;;
                *) exit 2 ;;
              esac
            fi
            """,
        )
        self._tool(
            "mkfs.ext4",
            """
            #!/usr/bin/env bash
            exit 0
            """,
        )
        self._tool(
            "tune2fs",
            """
            #!/usr/bin/env bash
            exit 0
            """,
        )
        self._tool(
            "readlink",
            """
            #!/usr/bin/env bash
            if [[ "${@: -1}" == /dev/mapper/* ]]; then
              printf '/dev/dm-0\n'
            else
              /usr/bin/readlink "$@"
            fi
            """,
        )
        self._tool(
            "python3",
            """
            #!/usr/bin/env bash
            set -euo pipefail
            if [[ " $* " == *"/verify-vault-profile.py "* ]]; then
              kind=""
              if [[ " $* " == *" luks-json "* ]]; then kind=luks-json; fi
              if [[ " $* " == *" ext4 "* ]]; then kind=ext4; fi
              [[ -n "$kind" ]]
              if [[ "$kind" == luks-json ]]; then /usr/bin/cat >/dev/null; fi
              if [[ "$kind" == ext4 ]]; then
                device=""; mapper=""; backing=""
                while [[ "$#" -gt 0 ]]; do
                  case "$1" in
                    --device) device="$2"; shift 2 ;;
                    --mapper-name) mapper="$2"; shift 2 ;;
                    --backing-device) backing="$2"; shift 2 ;;
                    *) shift ;;
                  esac
                done
                if [[ "$device" != /dev/dm-0 \
                  || ! "$mapper" =~ ^kernaid-inspect-[0-9a-f]{16}$ \
                  || "$backing" != /dev/loop0 ]]; then
                  printf 'mock ext4 dm binding arguments rejected\n' >&2
                  exit 3
                fi
              fi
              printf '%s\n' "$kind" >>"$KERNAID_MOCK_STATE_DIR/profile-checks"
              if [[ "${KERNAID_MOCK_PROFILE_FAILURE:-}" == "$kind" ]]; then
                printf 'mock profile tamper rejected\n' >&2
                exit 2
              fi
              printf '%s\n' \
                "KERNAID_VAULT_PROFILE_CHECK_V1 kind=$kind sha256=b4801359bd4f31ce67fbd3ec15b6c81c44aa6759ba43b2a4e099a7dfcc25a37c verified=true"
              exit 0
            fi
            exec /usr/bin/python3 "$@"
            """,
        )
        self._tool(
            "mount",
            """
            #!/usr/bin/env bash
            : >"$KERNAID_MOCK_STATE_DIR/provision-mounted"
            """,
        )
        self._tool(
            "umount",
            """
            #!/usr/bin/env bash
            case "$1" in
              */provision) rm -f "$KERNAID_MOCK_STATE_DIR/provision-mounted" ;;
              /run/kernaid/vault/*) rm -f "$KERNAID_MOCK_STATE_DIR/manager-mounted" ;;
              *) exit 2 ;;
            esac
            """,
        )
        self._tool(
            "mountpoint",
            """
            #!/usr/bin/env bash
            target="${@: -1}"
            case "$target" in
              */provision) [[ -e "$KERNAID_MOCK_STATE_DIR/provision-mounted" ]] ;;
              /run/kernaid/vault/*) [[ -e "$KERNAID_MOCK_STATE_DIR/manager-mounted" ]] ;;
              *) exit 1 ;;
            esac
            """,
        )
        self._tool(
            "dd",
            """
            #!/usr/bin/env bash
            set -euo pipefail
            output=false
            skip=0
            for argument in "$@"; do
              case "$argument" in
                of=*) output=true ;;
                skip=*) skip="${argument#skip=}" ;;
              esac
            done
            if [[ "$output" == true || "$skip" == "0" ]]; then
              /usr/bin/dd "$@"
            else
              printf 'mock-provisioned-p3-v1'
            fi
            """,
        )
        self._tool(
            "qemu-system-x86_64",
            r"""
            #!/usr/bin/env bash
            printf '%s\n' "$$" >"$KERNAID_MOCK_STATE_DIR/qemu-pid"
            if [[ "${KERNAID_MOCK_QEMU_IGNORE_TERM:-0}" == "1" \
              || "${KERNAID_MOCK_QEMU_NOT_READY:-0}" == "1" ]]; then
              exec /usr/bin/python3 -c '
import os
import signal
import time

state = os.environ["KERNAID_MOCK_STATE_DIR"]

def observe_term(_signal, _frame):
    open(os.path.join(state, "qemu-term-observed"), "ab").close()

signal.signal(signal.SIGTERM, observe_term)
if os.environ.get("KERNAID_MOCK_QEMU_NOT_READY") == "1":
    print("KERNAID_RESCUE_TAURI_GUEST_FAILURE_V1 stage=process-tree", flush=True)
    print("KERNAID_RESCUE_NOT_READY: private-reason=must-not-escape", flush=True)
print("KERNAID_RESCUE_READY", flush=True)
print("KERNAID_RESCUE_TARGET_SELECTION_READY", flush=True)
time.sleep(30)
'
            fi
            printf 'KERNAID_RESCUE_READY\n'
            printf 'KERNAID_RESCUE_TARGET_SELECTION_READY\n'
            exec /usr/bin/sleep 30
            """,
        )

    def probe(self, path: Path) -> None:
        executable(
            path,
            """
            #!/usr/bin/env bash
            set -euo pipefail
            state="$KERNAID_MOCK_STATE_DIR"
            mode=""
            mapper=""
            while [[ "$#" -gt 0 ]]; do
              case "$1" in
                --device) shift 2 ;;
                --mapper) mapper="$2"; shift 2 ;;
                --mode) mode="$2"; shift 2 ;;
                *) exit 2 ;;
              esac
            done
            # Consume the descriptor without retaining or printing its bytes.
            /usr/bin/sha256sum >/dev/null
            printf '%s\n' "$mode" >>"$state/probe-calls"
            if [[ "$mode" == "initialize" \
              && "${KERNAID_MOCK_INITIALIZE_FAILURE:-none}" != "none" ]]; then
              if [[ "$KERNAID_MOCK_INITIALIZE_FAILURE" == "typed" ]]; then
                printf '%s\n' \
                  'KERNAID_RESCUE_VAULT_PROBE_FAILURE_V1 stage=unlock code=mount-verification-failed' \
                  >&2
              else
                printf '%s\n' \
                  'unsafe raw diagnostic path=/private/vault key=do-not-copy' >&2
              fi
              exit 2
            fi
            if [[ "$mode" == "verify" && ! -e "$state/wrong-key-seen" ]]; then
              : >"$state/wrong-key-seen"
              if [[ "${KERNAID_MOCK_PROBE_LEAK:-0}" == "1" ]]; then
                : >"$state/mapper.$mapper"
              fi
              printf 'Rescue vault lifecycle probe failed\n' >&2
              exit 2
            fi
            printf '%s\n' \
              "KERNAID_RESCUE_VAULT_PROBE_ATTESTATION_V1 mode=$mode journal_binding=device-identity-bound-v1 identity_public_key=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef clean_shutdown=true"
            """,
        )


class QemuUsbVaultSmokeTests(unittest.TestCase):
    def test_qemu_cleanup_is_identity_bound_and_fully_bounded(self) -> None:
        shell = SCRIPT.read_text(encoding="utf-8")

        for name, expected in (
            ("qemu_term_grace_seconds", 5),
            ("qemu_kill_grace_seconds", 5),
        ):
            match = re.search(
                rf"^readonly {name}=([0-9]+)$", shell, re.MULTILINE
            )
            self.assertIsNotNone(match)
            assert match is not None
            self.assertEqual(int(match.group(1)), expected)

        identity = shell_function(shell, "read_qemu_process_state_and_identity")
        capture = shell_function(
            shell, "capture_qemu_process_identity_bounded"
        )
        abort_unidentified = shell_function(
            shell, "abort_unidentified_qemu_bounded"
        )
        signal_bound = shell_function(shell, "signal_qemu_identity_bound")
        status = shell_function(shell, "qemu_process_status")
        reap = shell_function(shell, "reap_stopped_qemu")
        terminate = shell_function(shell, "terminate_qemu_bounded")
        cleanup = shell_function(shell, "cleanup")
        stop = shell_function(shell, "stop_qemu")
        boot = shell_function(shell, "run_boot")

        self.assertIn('"/proc/$pid/stat"', identity)
        self.assertIn('process_fields[19]', identity)
        self.assertIn("capture_qemu_process_identity_bounded", boot)
        self.assertIn("coproc QEMU_PROCESS", boot)
        self.assertIn("abort_unidentified_qemu_bounded", boot)
        self.assertIn("close_qemu_start_gate", abort_unidentified)
        self.assertIn("qemu_identity_capture_seconds", capture)
        self.assertIn('identity-mismatch', status)
        self.assertIn('[[ "$process_status" != "live" ]]', terminate)
        self.assertIn("signal_qemu_identity_bound TERM", terminate)
        self.assertIn("signal_qemu_identity_bound KILL", terminate)
        self.assertIn("os.pidfd_open", signal_bound)
        self.assertIn("signal.pidfd_send_signal", signal_bound)
        self.assertNotIn('kill -TERM "$qemu_pid"', shell)
        self.assertNotIn('kill -KILL "$qemu_pid"', shell)
        self.assertIn("qemu_term_grace_seconds", terminate)
        self.assertIn("qemu_kill_grace_seconds", terminate)
        self.assertEqual(shell.count('wait "$qemu_pid"'), 2)
        self.assertEqual(reap.count('wait "$qemu_pid"'), 1)
        self.assertNotIn('kill "$qemu_pid"', shell)
        self.assertIn("terminate_qemu_bounded", stop)
        self.assertIn("terminate_qemu_bounded", cleanup)
        self.assertIn("recover_qemu_start_gate_tracking", cleanup)
        self.assertIn("termination was not confirmed", cleanup)
        self.assertIn("qemu_cleanup_safe", cleanup)
        self.assertIn("qemu_process_status", boot)
        self.assertEqual(
            boot.count(
                '-fw_cfg "name=opt/kernaid-tauri-sandbox-probe,string=v1"'
            ),
            1,
        )
        self.assertNotIn("opt/kernaid-offline-inspection", boot)

    def test_profile_helper_rejects_a_misbound_dm_slave(self) -> None:
        scan = mock.MagicMock()
        scan.__enter__.return_value = [SimpleNamespace(name="loop1")]
        scan.__exit__.return_value = False

        def resolve(path: str) -> str:
            if path == "/sys/dev/block/253:7":
                return "/sys/devices/virtual/block/dm-0"
            if path.endswith("/slaves/loop1"):
                return "/sys/devices/pci0000/block/loop1"
            return path

        def read(path: str) -> str:
            if path.endswith("/dm/name"):
                return "kernaid-inspect-0123456789abcdef"
            if path.endswith("/dev"):
                return "7:1"
            raise AssertionError(path)

        with (
            mock.patch.object(
                profile_verifier,
                "_block_identity",
                side_effect=(
                    (1, 2, os.makedev(253, 7), stat.S_IFBLK | 0o600),
                    (3, 4, os.makedev(7, 0), stat.S_IFBLK | 0o600),
                ),
            ),
            mock.patch.object(profile_verifier.os.path, "realpath", side_effect=resolve),
            mock.patch.object(profile_verifier, "_read_sysfs_text", side_effect=read),
            mock.patch.object(profile_verifier.os, "scandir", return_value=scan),
        ):
            with self.assertRaisesRegex(RuntimeError, "exact p3 loop"):
                profile_verifier._dm_snapshot(
                    8,
                    "/dev/dm-0",
                    "kernaid-inspect-0123456789abcdef",
                    9,
                    "/dev/loop0",
                )

    def run_smoke(
        self,
        *,
        leak_on_wrong_key: bool = False,
        cleanup_close_failure: bool = False,
        profile_failure: str = "",
        initialize_failure: str = "none",
        qemu_ignore_term: bool = False,
        qemu_not_ready: bool = False,
    ) -> tuple[
        subprocess.CompletedProcess[str],
        Path,
        Path,
        Path,
        tempfile.TemporaryDirectory[str],
    ]:
        temporary = tempfile.TemporaryDirectory()
        directory = Path(temporary.name)
        mocks = MockToolchain(directory)
        iso = directory / "KernAid-Rescue-amd64.iso"
        log = directory / "bios.log"
        probe = directory / "kernaid-rescue-vault-probe"
        write_finalized_fixture(iso)
        mocks.probe(probe)
        environment = os.environ.copy()
        environment.update(
            {
                "PATH": f"{mocks.bin}:{environment['PATH']}",
                "KERNAID_MOCK_STATE_DIR": str(mocks.state),
                "KERNAID_MOCK_PROBE_LEAK": "1" if leak_on_wrong_key else "0",
                "KERNAID_MOCK_CLOSE_FAIL": "1" if cleanup_close_failure else "0",
                "KERNAID_MOCK_PROFILE_FAILURE": profile_failure,
                "KERNAID_MOCK_INITIALIZE_FAILURE": initialize_failure,
                "KERNAID_MOCK_QEMU_IGNORE_TERM": (
                    "1" if qemu_ignore_term else "0"
                ),
                "KERNAID_MOCK_QEMU_NOT_READY": (
                    "1" if qemu_not_ready else "0"
                ),
                "KERNAID_USB_SMOKE_LOG": str(log),
            }
        )
        result = subprocess.run(
            [str(SCRIPT), "bios", str(iso), str(probe)],
            cwd=REPO_DIR,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        return result, iso, log, mocks.state, temporary

    def test_term_ignoring_qemu_is_pidfd_killed_and_reaped_boundedly(self) -> None:
        started = time.monotonic()
        result, _iso, _log, state, temporary = self.run_smoke(
            qemu_ignore_term=True
        )
        elapsed = time.monotonic() - started
        self.addCleanup(temporary.cleanup)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertLess(elapsed, 20)
        self.assertTrue((state / "qemu-term-observed").exists())
        qemu_pid = int((state / "qemu-pid").read_text(encoding="utf-8"))
        self.assertFalse(Path(f"/proc/{qemu_pid}").exists())

    def test_not_ready_precedes_ready_and_is_killed_reaped_without_reason_leak(
        self,
    ) -> None:
        started = time.monotonic()
        result, _iso, log, state, temporary = self.run_smoke(qemu_not_ready=True)
        elapsed = time.monotonic() - started
        self.addCleanup(temporary.cleanup)

        self.assertNotEqual(result.returncode, 0)
        self.assertLess(elapsed, 20)
        self.assertTrue((state / "qemu-term-observed").exists())
        qemu_pid = int((state / "qemu-pid").read_text(encoding="utf-8"))
        self.assertFalse(Path(f"/proc/{qemu_pid}").exists())
        combined_output = result.stdout + result.stderr
        self.assertIn(
            "KERNAID_RESCUE_TAURI_GUEST_FAILURE_V1 stage=process-tree",
            result.stderr,
        )
        self.assertIn("Rescue guest reported a not-ready marker", result.stderr)
        self.assertNotIn("KERNAID_RESCUE_NOT_READY:", combined_output)
        self.assertNotIn("private-reason=must-not-escape", combined_output)
        self.assertNotIn("KERNAID_QEMU_USB_BOOT_READY_V1", combined_output)
        self.assertNotIn(
            "private-reason=must-not-escape", log.read_text(encoding="utf-8")
        )

    def test_mocked_lifecycle_emits_catalog_v2_compatible_evidence(self) -> None:
        result, iso, log, state, temporary = self.run_smoke()
        self.addCleanup(temporary.cleanup)
        self.assertEqual(result.returncode, 0, result.stderr)
        contents = log.read_text(encoding="utf-8")
        self.assertEqual(contents.count("KERNAID_QEMU_USB_ATTESTATION_V1 "), 1)
        self.assertEqual(
            contents.count("KERNAID_QEMU_USB_VAULT_ATTESTATION_V1 "), 1
        )
        self.assertEqual(
            contents.count("KERNAID_QEMU_USB_VAULT_PROFILE_CHECK_V1 "), 4
        )
        self.assertEqual(
            contents.count("KERNAID_QEMU_USB_VAULT_RAW_SCOPE_V1 "), 1
        )
        self.assertEqual(contents.count("KERNAID_QEMU_USB_BOOT_READY_V1 "), 2)
        self.assertEqual(
            contents.count("KERNAID_RESCUE_VAULT_WRONG_KEY_V1 "), 1
        )
        self.assertEqual(
            contents.count("KERNAID_RESCUE_VAULT_PROBE_ATTESTATION_V1 "), 2
        )
        self.assertEqual(contents.count("mode=initialize journal_binding="), 1)
        self.assertEqual(contents.count("mode=verify journal_binding="), 1)
        self.assertIn("post_verify_mount_outside_raw_window=true", contents)
        self.assertEqual(
            (state / "probe-calls").read_text(encoding="utf-8").splitlines(),
            ["initialize", "verify", "verify"],
        )
        self.assertFalse((state / "loop-attached").exists())
        self.assertEqual(list(state.glob("mapper.*")), [])
        self.assertFalse((state / "provision-mounted").exists())
        self.assertEqual(
            (state / "profile-checks").read_text(encoding="utf-8").splitlines(),
            ["luks-json", "ext4", "luks-json", "ext4"],
        )

        layout = catalog_v2.load_device_layout(LAYOUT_MANIFEST)
        iso_digest = hashlib.sha256(iso.read_bytes()).hexdigest()
        log_digest = entry_v2.attested_log(
            log,
            firmware="bios",
            iso_size=iso.stat().st_size,
            iso_sha256=iso_digest,
            layout=layout,
        )
        self.assertRegex(log_digest, r"^[0-9a-f]{64}$")

        uefi_log = log.with_name("uefi.log")
        uefi_log.write_text(
            contents.replace("firmware=bios", "firmware=uefi").replace(
                "uefi_vars=not-applicable", "uefi_vars=fresh-per-boot"
            ),
            encoding="utf-8",
        )
        generated = subprocess.run(
            [
                sys.executable,
                "-I",
                "-B",
                str(ENTRY_V2_PATH),
                "--iso",
                str(iso),
                "--sha256",
                iso_digest,
                "--layout-manifest",
                str(LAYOUT_MANIFEST),
                "--artifact-version",
                "ci-4242-1",
                "--bios-run-id",
                "4242",
                "--bios-run-url",
                "https://github.com/0xfunboy/KernAid/actions/runs/4242",
                "--bios-log",
                str(log),
                "--uefi-run-id",
                "4242",
                "--uefi-run-url",
                "https://github.com/0xfunboy/KernAid/actions/runs/4242",
                "--uefi-log",
                str(uefi_log),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(generated.returncode, 0, generated.stderr)

    def test_wrong_key_residue_fails_and_cleanup_closes_owned_resources(self) -> None:
        result, _iso, _log, state, temporary = self.run_smoke(
            leak_on_wrong_key=True
        )
        self.addCleanup(temporary.cleanup)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("left a disposable vault mount or mapper active", result.stderr)
        self.assertFalse((state / "loop-attached").exists())
        self.assertEqual(list(state.glob("mapper.*")), [])
        self.assertFalse((state / "manager-mounted").exists())

    def test_cleanup_failure_is_loud_and_preserves_the_disposable_medium(self) -> None:
        result, _iso, _log, state, temporary = self.run_smoke(
            leak_on_wrong_key=True, cleanup_close_failure=True
        )
        self.addCleanup(temporary.cleanup)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Failed to close the disposable managed mapper", result.stderr)
        self.assertIn("Preserving disposable media after cleanup failure", result.stderr)
        self.assertTrue((state / "manager-close-failed").exists())
        self.assertFalse((state / "loop-attached").exists())

        backing = Path((state / "backing").read_text(encoding="utf-8").strip())
        preserved = backing.parent
        self.assertRegex(str(preserved), r"^/tmp/kernaid-qemu-usb-vault\.[A-Za-z0-9]+$")
        self.assertTrue(preserved.is_dir())
        shutil.rmtree(preserved)

    def test_luks_profile_tamper_cannot_emit_vault_attestation(self) -> None:
        result, _iso, log, _state, temporary = self.run_smoke(
            profile_failure="luks-json"
        )
        self.addCleanup(temporary.cleanup)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("mock profile tamper rejected", result.stderr)
        self.assertEqual(
            (_state / "profile-checks").read_text(encoding="utf-8").splitlines(),
            ["luks-json"],
        )
        self.assertNotIn(
            "KERNAID_QEMU_USB_VAULT_ATTESTATION_V1 ",
            log.read_text(encoding="utf-8"),
        )

    def test_ext4_profile_tamper_cannot_emit_vault_attestation(self) -> None:
        result, _iso, log, _state, temporary = self.run_smoke(
            profile_failure="ext4"
        )
        self.addCleanup(temporary.cleanup)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("mock profile tamper rejected", result.stderr)
        self.assertEqual(
            (_state / "profile-checks").read_text(encoding="utf-8").splitlines(),
            ["luks-json", "ext4"],
        )
        self.assertNotIn(
            "KERNAID_QEMU_USB_VAULT_ATTESTATION_V1 ",
            log.read_text(encoding="utf-8"),
        )

    def test_typed_probe_failure_is_preserved_without_success_evidence(self) -> None:
        result, _iso, log, _state, temporary = self.run_smoke(
            initialize_failure="typed"
        )
        self.addCleanup(temporary.cleanup)
        self.assertNotEqual(result.returncode, 0)
        diagnostic = (
            "KERNAID_RESCUE_VAULT_PROBE_FAILURE_V1 "
            "stage=unlock code=mount-verification-failed"
        )
        self.assertIn(diagnostic, result.stderr)
        self.assertEqual(log.read_text(encoding="utf-8").splitlines(), [diagnostic])

    def test_untyped_probe_stderr_is_never_copied_to_diagnostics(self) -> None:
        result, _iso, log, _state, temporary = self.run_smoke(
            initialize_failure="unsafe"
        )
        self.addCleanup(temporary.cleanup)
        self.assertNotEqual(result.returncode, 0)
        combined = result.stdout + result.stderr + log.read_text(encoding="utf-8")
        self.assertNotIn("/private/vault", combined)
        self.assertNotIn("do-not-copy", combined)
        diagnostic = (
            "KERNAID_RESCUE_VAULT_PROBE_FAILURE_V1 "
            "stage=wrapper code=invalid-diagnostic"
        )
        self.assertIn(diagnostic, result.stderr)
        self.assertEqual(log.read_text(encoding="utf-8").splitlines(), [diagnostic])


if __name__ == "__main__":
    unittest.main()
