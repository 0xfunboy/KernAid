from __future__ import annotations

import os
import re
import stat
import subprocess
import tempfile
import textwrap
import time
import unittest
from pathlib import Path


TOOLS_DIR = Path(__file__).resolve().parents[1]
REPO_DIR = Path(__file__).resolve().parents[3]
SCRIPT = TOOLS_DIR / "qemu-smoke.sh"
USB_SCRIPT = TOOLS_DIR / "qemu-usb-smoke.sh"
RESCUE_WORKFLOW = REPO_DIR / ".github/workflows/rescue.yml"
VAULT_SERVICE = (
    REPO_DIR
    / "rescue/live-build/config/includes.chroot/etc/systemd/system"
    / "kernaid-rescue-vaultd.service"
)
READY_CHECK = (
    REPO_DIR
    / "rescue/live-build/config/includes.chroot/usr/lib/kernaid/ready-check"
)
SNAPSHOT_DIGEST = (
    "5ddfda2212ab077621f2c2092a1b9400c0d83853d4df7056a185ac78cc243774"
)


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


class QemuProcessLifecycleTests(unittest.TestCase):
    @staticmethod
    def function_definition(source: str, name: str) -> str:
        return f"{name}() {{\n{shell_function(source, name)}}}\n"

    def test_trap_only_recovery_is_annotated_for_shellcheck_versions(self) -> None:
        annotation = (
            "# shellcheck disable=SC2317,SC2329  "
            "# Invoked indirectly by the EXIT cleanup trap.\n"
            "recover_qemu_start_gate_tracking() {"
        )
        for script in (SCRIPT, USB_SCRIPT):
            with self.subTest(script=script.name):
                self.assertIn(annotation, script.read_text(encoding="utf-8"))

    def test_ui_session_failure_is_detected_and_reported_as_a_fixed_marker(
        self,
    ) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        definitions = "\n".join(
            self.function_definition(source, name)
            for name in (
                "rescue_not_ready_observed",
                "report_tauri_sandbox_failure",
            )
        )
        with tempfile.TemporaryDirectory() as temporary:
            log = Path(temporary) / "qemu.log"
            log.write_text(
                "[   86.656583] python3[936]: "
                "KERNAID_RESCUE_UI_SESSION_FAILURE_V1 "
                "stage=process-environment\n"
                "untrusted diagnostic detail must not be reported\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                [
                    "bash",
                    "-c",
                    "set -euo pipefail\n"
                    'log="$1"\n'
                    f"{definitions}\n"
                    "rescue_not_ready_observed\n"
                    "report_tauri_sandbox_failure\n",
                    "bash",
                    str(log),
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=5,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertEqual(
            result.stderr,
            "KERNAID_RESCUE_UI_SESSION_FAILURE_V1 "
            "stage=process-environment\n",
        )

    def test_capture_failure_closes_start_gate_and_reaps_for_both_harnesses(
        self,
    ) -> None:
        for script in (SCRIPT, USB_SCRIPT):
            with self.subTest(script=script.name):
                source = script.read_text(encoding="utf-8")
                definitions = "\n".join(
                    self.function_definition(source, name)
                    for name in (
                        "capture_qemu_process_identity_bounded",
                        "close_qemu_start_gate",
                        "recover_qemu_start_gate_tracking",
                        "reap_unidentified_qemu",
                        "abort_unidentified_qemu_bounded",
                    )
                )
                harness = f"""
set -euo pipefail
readonly qemu_identity_capture_seconds=1
readonly qemu_stop_poll_seconds=0.01
qemu_pid=""
qemu_process_identity=""
qemu_start_fd=""
qemu_last_status=""
{definitions}
read_qemu_process_state_and_identity() {{ return 1; }}
coproc QEMU_PROCESS {{ IFS= read -r ignored; exit 125; }}
child_pid="$QEMU_PROCESS_PID"
recover_qemu_start_gate_tracking
[[ "$qemu_pid" == "$child_pid" ]]
if capture_qemu_process_identity_bounded; then exit 91; fi
abort_unidentified_qemu_bounded
[[ -z "$qemu_pid" ]]
[[ ! -e "/proc/$child_pid" ]]
"""
                result = subprocess.run(
                    ["bash", "-c", harness],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_pidfd_signal_is_atomic_allowlisted_and_rejects_stale_identity(
        self,
    ) -> None:
        for script in (SCRIPT, USB_SCRIPT):
            with self.subTest(script=script.name):
                source = script.read_text(encoding="utf-8")
                signal_definition = self.function_definition(
                    source, "signal_qemu_identity_bound"
                )
                signal_body = shell_function(source, "signal_qemu_identity_bound")
                terminate_body = shell_function(source, "terminate_qemu_bounded")
                self.assertIn("[[ -x /usr/bin/python3 ]]", source)
                self.assertIn("/usr/bin/python3 -I -", signal_body)
                self.assertLess(
                    signal_body.index("os.pidfd_open"),
                    signal_body.index('open(f"/proc/{pid}/stat"'),
                )
                self.assertLess(
                    signal_body.index('open(f"/proc/{pid}/stat"'),
                    signal_body.index("signal.pidfd_send_signal"),
                )
                self.assertEqual(
                    terminate_body.count(
                        '[[ "$signal_status" -eq 3 ]] && reap_stopped_qemu'
                    ),
                    2,
                )
                self.assertEqual(
                    terminate_body.count('elif [[ "$signal_status" -ne 0 ]]'),
                    2,
                )

                child = subprocess.Popen(["/usr/bin/sleep", "30"])
                self.addCleanup(
                    lambda process=child: (
                        (process.kill(), process.wait())
                        if process.poll() is None
                        else process.wait()
                    )
                )
                stat_fields = Path(f"/proc/{child.pid}/stat").read_text(
                    encoding="ascii"
                ).rsplit(") ", 1)[1].split()
                identity = int(stat_fields[19])

                for expected, signal_name in (
                    (identity + 1, "TERM"),
                    (identity, "USR1"),
                ):
                    harness = f"""
set -euo pipefail
qemu_pid={child.pid}
qemu_process_identity={expected}
{signal_definition}
if signal_qemu_identity_bound {signal_name}; then
  exit 91
else
  signal_status=$?
fi
[[ "$signal_status" -eq 4 ]]
"""
                    result = subprocess.run(
                        ["bash", "-c", harness],
                        check=False,
                        capture_output=True,
                        text=True,
                        timeout=5,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIsNone(child.poll())

                harness = f"""
set -euo pipefail
qemu_pid={child.pid}
qemu_process_identity={identity}
{signal_definition}
signal_qemu_identity_bound TERM
"""
                result = subprocess.run(
                    ["bash", "-c", harness],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                child.wait(timeout=5)
                self.assertFalse(Path(f"/proc/{child.pid}").exists())

                harness = f"""
set -euo pipefail
qemu_pid={child.pid}
qemu_process_identity={identity}
{signal_definition}
if signal_qemu_identity_bound TERM; then
  exit 91
else
  signal_status=$?
fi
[[ "$signal_status" -eq 3 ]]
"""
                result = subprocess.run(
                    ["bash", "-c", harness],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_pidfd_preflight_failure_never_releases_qemu_and_reaps_gate(
        self,
    ) -> None:
        for script in (SCRIPT, USB_SCRIPT):
            with self.subTest(script=script.name):
                source = script.read_text(encoding="utf-8")
                launch = source.index("coproc QEMU_PROCESS")
                preflight = source.index(
                    "if ! signal_qemu_identity_bound CHECK", launch
                )
                release = source.index("if ! release_qemu_start_gate", launch)
                self.assertLess(preflight, release)
                self.assertIn(
                    "abort_unidentified_qemu_bounded",
                    source[preflight:release],
                )

                definitions = "\n".join(
                    self.function_definition(source, name)
                    for name in (
                        "read_qemu_process_state_and_identity",
                        "close_qemu_start_gate",
                        "reap_unidentified_qemu",
                        "abort_unidentified_qemu_bounded",
                    )
                )
                unavailable_signal = self.function_definition(
                    source, "signal_qemu_identity_bound"
                ).replace("/usr/bin/python3 -I -", "/usr/bin/false")
                harness = f"""
set -euo pipefail
readonly qemu_identity_capture_seconds=1
readonly qemu_stop_poll_seconds=0.01
qemu_pid=""
qemu_process_identity=""
qemu_start_fd=""
qemu_last_status=""
{definitions}
{unavailable_signal}
coproc TEST_QEMU {{ IFS= read -r ignored; exit 125; }}
qemu_pid="$TEST_QEMU_PID"
qemu_start_fd="${{TEST_QEMU[1]}}"
child_pid="$qemu_pid"
observation="$(read_qemu_process_state_and_identity "$qemu_pid")"
qemu_process_identity="${{observation#*:}}"
if signal_qemu_identity_bound CHECK; then exit 91; fi
abort_unidentified_qemu_bounded
[[ -z "$qemu_pid" ]]
[[ ! -e "/proc/$child_pid" ]]
"""
                result = subprocess.run(
                    ["bash", "-c", harness],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                self.assertEqual(result.returncode, 0, result.stderr)


class MockToolchain:
    def __init__(self, directory: Path) -> None:
        self.bin = directory / "bin"
        self.state = directory / "state"
        self.ovmf = directory / "ovmf"
        self.qmp_helper = directory / "qemu-tauri-ui-smoke.py"
        self.bin.mkdir()
        self.state.mkdir()
        self.ovmf.mkdir()
        (self.ovmf / "OVMF_CODE_4M.fd").write_bytes(b"mock OVMF 4M code")
        (self.ovmf / "OVMF_VARS_4M.fd").write_bytes(b"mock OVMF 4M vars")
        executable(
            self.qmp_helper,
            """
            #!/usr/bin/python3
            import argparse

            parser = argparse.ArgumentParser()
            parser.add_argument("--socket", required=True)
            parser.add_argument("--work-dir", required=True)
            parser.add_argument("--firmware", required=True, choices=("bios", "uefi"))
            options = parser.parse_args()
            print(
                "KERNAID_QEMU_TAURI_UI_ATTESTATION_V1 "
                f"firmware={options.firmware} shell=shipping "
                "renderer=webkit2gtk-4.1 display=default rendered=true input=true "
                "width=1024 height=768 changed_pixels=128"
            )
            """,
        )
        self._install()

    def _tool(self, name: str, source: str) -> None:
        executable(self.bin / name, source)

    def _install(self) -> None:
        for name in (
            "dd",
            "debugfs",
            "mcopy",
            "mmd",
            "mkfs.ext4",
            "mkfs.ntfs",
            "mkfs.vfat",
            "ntfsfix",
            "sgdisk",
        ):
            self._tool(
                name,
                """
                #!/usr/bin/env bash
                exit 0
                """,
            )
        self._tool(
            "python3",
            """
            #!/usr/bin/env bash
            # The layout verifier is orthogonal to the fixture privilege test.
            exit 0
            """,
        )
        self._tool(
            "ntfs-3g",
            """
            #!/usr/bin/env bash
            : >"$KERNAID_MOCK_STATE_DIR/direct-ntfs-3g"
            exit 95
            """,
        )
        self._tool(
            "mktemp",
            """
            #!/usr/bin/env bash
            : >"$KERNAID_MOCK_STATE_DIR/direct-mktemp"
            exit 95
            """,
        )
        self._tool(
            "umount",
            """
            #!/usr/bin/env bash
            : >"$KERNAID_MOCK_STATE_DIR/direct-umount"
            exit 95
            """,
        )
        self._tool(
            "sudo",
            r"""
            #!/usr/bin/env bash
            set -euo pipefail
            state="$KERNAID_MOCK_STATE_DIR"
            printf '%s\n' "$*" >>"$state/sudo-calls"
            [[ "${1:-}" == "-n" && "${2:-}" == "--" ]]
            shift 2
            command_path="${1:?}"
            shift
            case "${command_path##*/}" in
              ntfs-3g)
                image="${1:?}"
                mountpoint="${2:?}"
                shift 2
                [[ "${1:-}" == "-o" ]]
                options="${2:?}"
                [[ -f "$image" && -d "$mountpoint" ]]
                printf '%s\n' "$image" >"$state/mount-source"
                printf '%s\n' "$mountpoint" >"$state/mount-target"
                printf '%s\n' "$options" >"$state/mount-options"
                printf '%s\n' "$options" >"$state/mount-options-observed"
                ;;
              umount)
                [[ "${1:-}" == "--" ]]
                target="${2:?}"
                [[ -e "$state/mount-target" ]]
                [[ "$(cat "$state/mount-target")" == "$target" ]]
                rm -f "$state/mount-source" "$state/mount-target" \
                  "$state/mount-options"
                ;;
              *)
                exit 96
                ;;
            esac
            """,
        )
        self._tool(
            "findmnt",
            r"""
            #!/usr/bin/env bash
            set -euo pipefail
            state="$KERNAID_MOCK_STATE_DIR"
            target="${@: -1}"
            [[ -e "$state/mount-target" ]]
            [[ "$(cat "$state/mount-target")" == "$target" ]]
            case " $* " in
              *" -o SOURCE,TARGET,FSTYPE,OPTIONS "*)
                record_count=0
                if [[ -e "$state/mount-record-count" ]]; then
                  record_count="$(cat "$state/mount-record-count")"
                fi
                record_count=$((record_count + 1))
                printf '%s\n' "$record_count" >"$state/mount-record-count"
                source="$(cat "$state/mount-source")"
                if [[ -n "${KERNAID_MOCK_SOURCE_MISMATCH_AFTER_RECORD:-}" \
                  && "$record_count" -ge "$KERNAID_MOCK_SOURCE_MISMATCH_AFTER_RECORD" ]]; then
                  source="$state/unexpected-source"
                fi
                printf '%s %s %s %s\n' \
                  "$source" \
                  "$(cat "$state/mount-target")" \
                  "${KERNAID_MOCK_FSTYPE:-fuse}" \
                  'rw,nosuid,nodev,noexec,relatime,user_id=0,group_id=0,allow_other'
                ;;
              *" -o SOURCE "*) cat "$state/mount-source" ;;
              *" -o FSTYPE "*) printf '%s\n' "${KERNAID_MOCK_FSTYPE:-fuse}" ;;
              *" -o OPTIONS "*)
                printf 'rw,nosuid,nodev,noexec,relatime,user_id=0,group_id=0,allow_other\n'
                ;;
            esac
            """,
        )
        self._tool(
            "stat",
            r"""
            #!/usr/bin/env bash
            set -euo pipefail
            target="${@: -1}"
            if [[ " $* " == *" %F:%u:%g:%a "* && -d "$target" ]]; then
              if [[ "$target" == "${KERNAID_MOCK_CHAIN_DIRECTORY:-}" ]]; then
                printf '%s:%s:%s:%s\n' \
                  "${KERNAID_MOCK_CHAIN_FILE_TYPE:-directory}" \
                  "${KERNAID_MOCK_CHAIN_UID:-0}" \
                  "${KERNAID_MOCK_CHAIN_GID:-0}" \
                  "${KERNAID_MOCK_CHAIN_MODE:-755}"
              else
                printf 'directory:0:0:755\n'
              fi
              exit 0
            fi
            case "${target##*/}" in
              ntfs-3g|sudo|umount)
                if [[ " $* " == *" %F:%u:%g:%a "* ]]; then
                  printf 'regular file:0:0:755\n'
                  exit 0
                fi
                ;;
              OVMF_CODE_4M.fd|OVMF_VARS_4M.fd|OVMF_CODE.fd|OVMF_VARS.fd)
                if [[ " $* " == *" %F:%u:%g:%a "* ]]; then
                  printf 'regular file:0:0:%s\n' "${KERNAID_MOCK_OVMF_MODE:-644}"
                  exit 0
                fi
                ;;
            esac
            exec /usr/bin/stat "$@"
            """,
        )
        self._tool(
            "sync",
            r"""
            #!/usr/bin/env bash
            set -euo pipefail
            if [[ "${KERNAID_MOCK_SYNC_FAILURE:-0}" == "1" \
              && -e "$KERNAID_MOCK_STATE_DIR/mount-target" \
              && "${@: -1}" == "$(cat "$KERNAID_MOCK_STATE_DIR/mount-target")" ]]; then
              exit 73
            fi
            exec /usr/bin/sync "$@"
            """,
        )
        self._tool(
            "qemu-system-x86_64",
            r"""
            #!/usr/bin/env bash
            printf '%s\n' "$EUID" >"$KERNAID_MOCK_STATE_DIR/qemu-euid"
            printf '%s\n' "$$" >"$KERNAID_MOCK_STATE_DIR/qemu-pid"
            printf '%s\n' "$*" >"$KERNAID_MOCK_STATE_DIR/qemu-args"
            for argument in "$@"; do
              case "$argument" in
                if=pflash,format=raw,unit=1,file=*)
                  vars_path="${argument##*,file=}"
                  printf '%s\n' "$vars_path" >"$KERNAID_MOCK_STATE_DIR/qemu-ovmf-vars-path"
                  /usr/bin/stat -c '%a' -- "$vars_path" \
                    >"$KERNAID_MOCK_STATE_DIR/qemu-ovmf-vars-mode"
                  if /usr/bin/cmp -s -- \
                    "$KERNAID_MOCK_OVMF_VARS_TEMPLATE" "$vars_path"; then
                    : >"$KERNAID_MOCK_STATE_DIR/qemu-ovmf-vars-match"
                  fi
                  ;;
              esac
            done
            if [[ "${KERNAID_MOCK_QEMU_IGNORE_TERM:-0}" == "1" \
              || "${KERNAID_MOCK_QEMU_NOT_READY:-0}" == "1" ]]; then
              exec /usr/bin/python3 -c '
import os
import signal
import sys
import time

state = os.environ["KERNAID_MOCK_STATE_DIR"]

def observe_term(_signal, _frame):
    open(os.path.join(state, "qemu-term-observed"), "wb").close()

signal.signal(signal.SIGTERM, observe_term)
if os.environ.get("KERNAID_MOCK_QEMU_NOT_READY") == "1":
    print("KERNAID_RESCUE_NOT_READY: private-reason=must-not-escape", flush=True)
print("KERNAID_RESCUE_READY", flush=True)
hardware_marker = "KERNAID_RESCUE_HARDWARE_INVENTORY_READY"
sys.stdout.write(hardware_marker + "\r\n")
if os.environ.get("KERNAID_MOCK_DUPLICATE_HARDWARE_MARKER") == "1":
    sys.stdout.write(hardware_marker + "\r\n")
sys.stdout.flush()
print("KERNAID_RESCUE_TARGET_SELECTION_READY", flush=True)
print("KERNAID_RESCUE_OFFLINE_INSPECTION_READY", flush=True)
print("KERNAID_RESCUE_TAURI_GUEST_V1 identity=isolated pidns=private shell-bus=mount-masked session-bus=env-disabled-polkit-denied fs-sockets=allowlisted abstract-unix=not-attested devices=private device-fds=no-privileged shell=shipping renderer=webkit2gtk-4.1 window=visible display=active-xorg http=loopback x11=connected privileged-fs-sockets=absent nonloopback=denied width=1024 height=768", flush=True)
snapshot_marker = "KERNAID_RESCUE_LINUX_SNAPSHOT_E2E_V1 semantic_sha256=" + os.environ["KERNAID_MOCK_SNAPSHOT_DIGEST"]
sys.stdout.write("serial-prefix-without-line-feed")
print("\n" + snapshot_marker, flush=True)
if os.environ.get("KERNAID_MOCK_DUPLICATE_SNAPSHOT_MARKER") == "1":
    print(snapshot_marker, flush=True)
time.sleep(30)
'
            fi
            printf 'KERNAID_RESCUE_READY\n'
            printf 'KERNAID_RESCUE_HARDWARE_INVENTORY_READY\r\n'
            if [[ "${KERNAID_MOCK_DUPLICATE_HARDWARE_MARKER:-0}" == "1" ]]; then
              printf 'KERNAID_RESCUE_HARDWARE_INVENTORY_READY\r\n'
            fi
            printf 'KERNAID_RESCUE_TARGET_SELECTION_READY\n'
            printf 'KERNAID_RESCUE_OFFLINE_INSPECTION_READY\n'
            printf 'KERNAID_RESCUE_TAURI_GUEST_V1 identity=isolated pidns=private shell-bus=mount-masked session-bus=env-disabled-polkit-denied fs-sockets=allowlisted abstract-unix=not-attested devices=private device-fds=no-privileged shell=shipping renderer=webkit2gtk-4.1 window=visible display=active-xorg http=loopback x11=connected privileged-fs-sockets=absent nonloopback=denied width=1024 height=768\n'
            printf 'serial-prefix-without-line-feed'
            printf '\nKERNAID_RESCUE_LINUX_SNAPSHOT_E2E_V1 semantic_sha256=%s\n' \
              "$KERNAID_MOCK_SNAPSHOT_DIGEST"
            if [[ "${KERNAID_MOCK_DUPLICATE_SNAPSHOT_MARKER:-0}" == "1" ]]; then
              printf 'KERNAID_RESCUE_LINUX_SNAPSHOT_E2E_V1 semantic_sha256=%s\n' \
                "$KERNAID_MOCK_SNAPSHOT_DIGEST"
            fi
            exec /usr/bin/sleep 30
            """,
        )


class QemuSmokeFixturePrivilegeTests(unittest.TestCase):
    def test_hardware_inventory_marker_is_framed_strict_and_unique(self) -> None:
        ready = READY_CHECK.read_text(encoding="utf-8")
        script = SCRIPT.read_text(encoding="utf-8")
        validation = 'data.get("cpu", {}).get("status") == "complete"'
        emission = (
            "printf '\\nKERNAID_RESCUE_HARDWARE_INVENTORY_READY\\n' "
            ">/dev/ttyS0"
        )
        self.assertEqual(ready.count(emission), 1)
        self.assertLess(ready.index(validation), ready.index(emission))
        self.assertIn(
            "hardware_inventory_ready_observed() {",
            script,
        )
        self.assertIn(
            "LC_ALL=C tr -d '\\r' <\"$log\" \\\n"
            "    | grep -aE '^KERNAID_RESCUE_HARDWARE_INVENTORY_READY$' "
            ">/dev/null",
            script,
        )
        self.assertIn("&& hardware_inventory_ready_observed \\", script)
        self.assertIn(
            "Rescue hardware inventory marker was not unique",
            script,
        )
        stream = "serial-prefix-without-line-feed\nKERNAID_RESCUE_HARDWARE_INVENTORY_READY\r\n"
        markers = re.findall(
            r"^KERNAID_RESCUE_HARDWARE_INVENTORY_READY$",
            stream.replace("\r", ""),
            re.MULTILINE,
        )
        self.assertEqual(markers, ["KERNAID_RESCUE_HARDWARE_INVENTORY_READY"])

        matcher = (
            "set -o pipefail; LC_ALL=C tr -d '\\r' | "
            "grep -aE '^KERNAID_RESCUE_HARDWARE_INVENTORY_READY$' >/dev/null"
        )
        accepted = subprocess.run(
            ["bash", "-c", matcher],
            input=(
                "KERNAID_RESCUE_HARDWARE_INVENTORY_READY\r\n"
                + ("bounded-noise\n" * 131_072)
            ),
            text=True,
            check=False,
        )
        self.assertEqual(accepted.returncode, 0)
        for rejected_stream in (
            "serial-prefixKERNAID_RESCUE_HARDWARE_INVENTORY_READY\r\n",
            "KERNAID_RESCUE_HARDWARE_INVENTORY_READY-suffix\r\n",
        ):
            with self.subTest(rejected_stream=rejected_stream):
                rejected = subprocess.run(
                    ["bash", "-c", matcher],
                    input=rejected_stream,
                    text=True,
                    check=False,
                )
                self.assertNotEqual(rejected.returncode, 0)

    def materialize_test_script(self, directory: Path, mocks: MockToolchain) -> Path:
        source = SCRIPT.read_text(encoding="utf-8")
        replacements = {
            'snapshot_fixture="$repo_dir/tests/fixtures/linux-normalized-snapshot/healthy/root"': (
                f'snapshot_fixture="{REPO_DIR / "tests/fixtures/linux-normalized-snapshot/healthy/root"}'
                '"'
            ),
            'snapshot_golden="$repo_dir/tests/fixtures/linux-normalized-snapshot/expected/snapshot.v1.json"': (
                f'snapshot_golden="{REPO_DIR / "tests/fixtures/linux-normalized-snapshot/expected/snapshot.v1.json"}'
                '"'
            ),
            'ntfs_3g_command="/usr/bin/ntfs-3g"': (
                f'ntfs_3g_command="{mocks.bin / "ntfs-3g"}"'
            ),
            'sudo_command="/usr/bin/sudo"': f'sudo_command="{mocks.bin / "sudo"}"',
            'umount_command="/usr/bin/umount"': (
                f'umount_command="{mocks.bin / "umount"}"'
            ),
            'findmnt_command="/usr/bin/findmnt"': (
                f'findmnt_command="{mocks.bin / "findmnt"}"'
            ),
            'stat_command="/usr/bin/stat"': f'stat_command="{mocks.bin / "stat"}"',
            'ovmf_directory="/usr/share/OVMF"': f'ovmf_directory="{mocks.ovmf}"',
            '"$repo_dir/tools/build-rescue/qemu-tauri-ui-smoke.py"': (
                f'"{mocks.qmp_helper}"'
            ),
        }
        for fixed, test_only in replacements.items():
            self.assertEqual(source.count(fixed), 1, fixed)
            source = source.replace(fixed, test_only)
        fixed_allowlist = "    /usr/bin/*|/usr/sbin/*|/usr/lib/*) ;;"
        test_allowlist = f"    /usr/bin/*|/usr/sbin/*|/usr/lib/*|{mocks.bin}/*) ;;"
        self.assertEqual(source.count(fixed_allowlist), 1)
        source = source.replace(fixed_allowlist, test_allowlist)
        script = directory / "qemu-smoke-test-only.sh"
        executable(script, source)
        return script

    def run_smoke(
        self,
        *,
        sync_failure: bool = False,
        mounted_fstype: str = "fuse",
        source_mismatch_after_record: int | None = None,
        firmware: str = "bios",
        ovmf_layout: str = "4m",
        ovmf_mode: str = "644",
        ovmf_directory_file_type: str = "directory",
        ovmf_directory_uid: int = 0,
        ovmf_directory_gid: int = 0,
        ovmf_directory_mode: str = "755",
        ovmf_directory_symlink: bool = False,
        qemu_ignore_term: bool = False,
        qemu_not_ready: bool = False,
        snapshot_digest: str = SNAPSHOT_DIGEST,
        duplicate_hardware_marker: bool = False,
        duplicate_snapshot_marker: bool = False,
        resident_snapshot_digest: str | None = SNAPSHOT_DIGEST,
    ) -> tuple[
        subprocess.CompletedProcess[str], Path, Path, tempfile.TemporaryDirectory[str]
    ]:
        temporary = tempfile.TemporaryDirectory()
        directory = Path(temporary.name)
        mocks = MockToolchain(directory)
        if ovmf_directory_symlink:
            real_ovmf = directory / "ovmf-real"
            mocks.ovmf.rename(real_ovmf)
            mocks.ovmf.symlink_to(real_ovmf, target_is_directory=True)
        code_4m = mocks.ovmf / "OVMF_CODE_4M.fd"
        vars_4m = mocks.ovmf / "OVMF_VARS_4M.fd"
        if ovmf_layout == "missing":
            code_4m.unlink()
            vars_4m.unlink()
        elif ovmf_layout == "mismatched":
            vars_4m.unlink()
            (mocks.ovmf / "OVMF_VARS.fd").write_bytes(b"mock legacy vars")
        elif ovmf_layout == "same-identity":
            vars_4m.unlink()
            os.link(code_4m, vars_4m)
        elif ovmf_layout == "legacy":
            code_4m.rename(mocks.ovmf / "OVMF_CODE.fd")
            vars_4m.rename(mocks.ovmf / "OVMF_VARS.fd")
        elif ovmf_layout != "4m":
            raise AssertionError(f"unsupported OVMF test layout: {ovmf_layout}")
        script = self.materialize_test_script(directory, mocks)
        iso = directory / "KernAid-Rescue-amd64.iso"
        log = directory / "bios.log"
        iso.write_bytes(b"mock finalized rescue iso")
        environment = os.environ.copy()
        environment.update(
            {
                "PATH": f"{mocks.bin}:{environment['PATH']}",
                "KERNAID_MOCK_STATE_DIR": str(mocks.state),
                "KERNAID_MOCK_SYNC_FAILURE": "1" if sync_failure else "0",
                "KERNAID_MOCK_FSTYPE": mounted_fstype,
                "KERNAID_MOCK_OVMF_MODE": ovmf_mode,
                "KERNAID_MOCK_CHAIN_DIRECTORY": str(mocks.ovmf),
                "KERNAID_MOCK_CHAIN_FILE_TYPE": ovmf_directory_file_type,
                "KERNAID_MOCK_CHAIN_UID": str(ovmf_directory_uid),
                "KERNAID_MOCK_CHAIN_GID": str(ovmf_directory_gid),
                "KERNAID_MOCK_CHAIN_MODE": ovmf_directory_mode,
                "KERNAID_MOCK_QEMU_IGNORE_TERM": (
                    "1" if qemu_ignore_term else "0"
                ),
                "KERNAID_MOCK_QEMU_NOT_READY": (
                    "1" if qemu_not_ready else "0"
                ),
                "KERNAID_MOCK_SNAPSHOT_DIGEST": snapshot_digest,
                "KERNAID_MOCK_DUPLICATE_HARDWARE_MARKER": (
                    "1" if duplicate_hardware_marker else "0"
                ),
                "KERNAID_MOCK_DUPLICATE_SNAPSHOT_MARKER": (
                    "1" if duplicate_snapshot_marker else "0"
                ),
                "KERNAID_MOCK_OVMF_VARS_TEMPLATE": str(
                    mocks.ovmf
                    / (
                        "OVMF_VARS.fd"
                        if ovmf_layout == "legacy"
                        else "OVMF_VARS_4M.fd"
                    )
                ),
                "KERNAID_SMOKE_LOG": str(log),
                "TMPDIR": str(directory),
            }
        )
        environment.pop("KERNAID_RESIDENT_SNAPSHOT_SEMANTIC_SHA256", None)
        if resident_snapshot_digest is not None:
            environment["KERNAID_RESIDENT_SNAPSHOT_SEMANTIC_SHA256"] = (
                resident_snapshot_digest
            )
        if source_mismatch_after_record is not None:
            environment["KERNAID_MOCK_SOURCE_MISMATCH_AFTER_RECORD"] = str(
                source_mismatch_after_record
            )
        result = subprocess.run(
            [str(script), firmware, str(iso)],
            cwd=REPO_DIR,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
        )
        return result, log, mocks.state, temporary

    def test_privileged_tools_are_fixed_and_path_hijack_is_not_selected(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('ntfs_3g_command="/usr/bin/ntfs-3g"', source)
        self.assertIn('sudo_command="/usr/bin/sudo"', source)
        self.assertIn('umount_command="/usr/bin/umount"', source)
        self.assertIn('mktemp_command="/usr/bin/mktemp"', source)
        self.assertNotIn("command -v ntfs-3g", source)
        self.assertNotIn("command -v sudo", source)
        self.assertNotIn("command -v umount", source)
        self.assertIn("trusted_privileged_tool", source)
        self.assertIn("trusted_root_directory_chain", source)
        self.assertIn('"$file_type" != "symbolic link"', source)
        self.assertIn("8#$permissions & 0022", source)

        with tempfile.TemporaryDirectory() as temporary_name:
            directory = Path(temporary_name)
            mocks = MockToolchain(directory)
            environment = os.environ.copy()
            environment.update(
                {
                    "PATH": f"{mocks.bin}:{environment['PATH']}",
                    "KERNAID_MOCK_STATE_DIR": str(mocks.state),
                }
            )
            result = subprocess.run(
                [str(SCRIPT), "bios", str(directory / "missing.iso")],
                cwd=REPO_DIR,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((mocks.state / "sudo-calls").exists())
            self.assertFalse((mocks.state / "direct-ntfs-3g").exists())
            self.assertFalse((mocks.state / "direct-umount").exists())
            self.assertFalse((mocks.state / "direct-mktemp").exists())

    def test_gpt_esp_fixture_uses_explicit_host_tools_and_no_user_mtools_config(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        workflow = RESCUE_WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("mkfs.vfat", source)
        self.assertIn("sgdisk", source)
        self.assertEqual(source.count("MTOOLSRC=/dev/null mmd"), 4)
        self.assertEqual(source.count("MTOOLSRC=/dev/null mcopy"), 3)
        self.assertIn("windows_gpt_target_hash_before", source)
        self.assertIn("windows_gpt_target_hash_after", source)
        for package in ("dosfstools", "gdisk", "mtools"):
            self.assertIn(package, workflow)

    def test_workflow_hardens_exactly_three_ovmf_directory_chains(self) -> None:
        workflow = RESCUE_WORKFLOW.read_text(encoding="utf-8")
        marker = "      - name: Harden OVMF firmware ancestry"
        self.assertEqual(workflow.count(marker), 3)

        main_install = (
            "          sudo apt-get install -y \\\n"
            "            build-essential cryptsetup dosfstools e2fsprogs gdisk mtools ntfs-3g \\\n"
            "            ovmf qemu-system-x86 shellcheck udev util-linux\n"
        )
        lifecycle_install = (
            "          sudo apt-get install -y \\\n"
            "            coreutils cryptsetup e2fsprogs gawk grep libcrypt1 mount ovmf procps \\\n"
            "            python3 qemu-system-x86 squashfs-tools udev util-linux\n"
        )
        self.assertEqual(workflow.count(main_install + marker), 1)
        self.assertEqual(workflow.count(lifecycle_install + marker), 2)

        hardeners = []
        for remainder in workflow.split(marker)[1:]:
            hardener, separator, _following_step = remainder.partition("\n      - ")
            self.assertTrue(separator)
            hardeners.append(hardener)
        self.assertEqual(len(hardeners), 3)
        self.assertTrue(all(item == hardeners[0] for item in hardeners))

        body = hardeners[0]
        for invariant in (
            "sudo /usr/bin/python3 -I -B - <<'PY'",
            "os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC",
            "os.fchown(descriptor, 0, 0)",
            "os.fchmod(descriptor, stat.S_IMODE(before.st_mode) & ~0o022)",
            "not stat.S_ISDIR(current.st_mode)",
            "current.st_uid != 0",
            "current.st_gid != 0",
            "stat.S_IMODE(current.st_mode) & 0o022",
            'root = os.open("/", directory_flags)',
            "validate_trusted(root)",
            'usr = open_child(root, "usr", required=True)',
            'share = open_child(usr, "share", required=True)',
            'open_child(share, "OVMF", required=True)',
            'open_child(share, "edk2", required=False)',
        ):
            self.assertEqual(body.count(invariant), 1, invariant)
        self.assertNotIn("harden(root)", body)

        python_start = "          sudo /usr/bin/python3 -I -B - <<'PY'\n"
        embedded = body.split(python_start, maxsplit=1)[1].split(
            "\n          PY", maxsplit=1
        )[0]
        compile(
            textwrap.dedent(embedded),
            ".github/workflows/rescue.yml:ovmf-hardener",
            "exec",
        )

    def test_uefi_uses_paired_code_and_disposable_vars_pflash(self) -> None:
        result, _log, state, temporary = self.run_smoke(firmware="uefi")
        self.addCleanup(temporary.cleanup)

        self.assertEqual(result.returncode, 0, result.stderr)
        arguments = (state / "qemu-args").read_text(encoding="utf-8").split()
        pflash_drives = [
            argument for argument in arguments if argument.startswith("if=pflash,")
        ]
        self.assertEqual(len(pflash_drives), 2)
        self.assertEqual(
            pflash_drives[0],
            "if=pflash,format=raw,readonly=on,unit=0,file="
            f"{state.parent / 'ovmf' / 'OVMF_CODE_4M.fd'}",
        )
        self.assertTrue(
            pflash_drives[1].startswith("if=pflash,format=raw,unit=1,file=")
        )
        self.assertNotIn("readonly=on", pflash_drives[1])
        vars_path = Path(
            (state / "qemu-ovmf-vars-path").read_text(encoding="utf-8").strip()
        )
        self.assertFalse(vars_path.is_relative_to(state.parent / "ovmf"))
        self.assertEqual(
            (state / "qemu-ovmf-vars-mode").read_text(encoding="utf-8").strip(),
            "600",
        )
        self.assertTrue((state / "qemu-ovmf-vars-match").exists())
        self.assertFalse(vars_path.exists())
        target_drives = [
            argument for argument in arguments if "if=virtio" in argument
        ]
        self.assertEqual(len(target_drives), 3)
        for target_drive in target_drives:
            self.assertNotIn("readonly=on", target_drive)
            self.assertNotIn("snapshot=", target_drive)

    def test_firmware_directory_chain_is_root_owned_and_not_writable(self) -> None:
        trusted, _log, state, temporary = self.run_smoke(
            firmware="uefi",
            ovmf_directory_file_type="directory",
            ovmf_directory_uid=0,
            ovmf_directory_gid=0,
            ovmf_directory_mode="755",
        )
        self.addCleanup(temporary.cleanup)
        self.assertEqual(trusted.returncode, 0, trusted.stderr)
        self.assertTrue((state / "qemu-euid").exists())

        rejected_cases = (
            {
                "name": "group-writable",
                "ovmf_directory_mode": "775",
                "message": "untrusted parent directory",
            },
            {
                "name": "sticky-world-writable",
                "ovmf_directory_mode": "1777",
                "message": "untrusted parent directory",
            },
            {
                "name": "non-directory-metadata",
                "ovmf_directory_file_type": "regular file",
                "message": "untrusted parent directory",
            },
            {
                "name": "non-root-owner",
                "ovmf_directory_uid": 1001,
                "message": "untrusted parent directory",
            },
            {
                "name": "symlink",
                "ovmf_directory_symlink": True,
                "message": "unsafe parent directory",
            },
        )
        for rejected in rejected_cases:
            with self.subTest(case=rejected["name"]):
                options = {
                    key: value
                    for key, value in rejected.items()
                    if key not in {"name", "message"}
                }
                result, _log, state, temporary = self.run_smoke(
                    firmware="uefi", **options
                )
                self.addCleanup(temporary.cleanup)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn(rejected["message"], result.stderr)
                self.assertFalse((state / "qemu-euid").exists())

    def test_term_ignoring_qemu_is_killed_reaped_and_cleaned_boundedly(self) -> None:
        started = time.monotonic()
        result, _log, state, temporary = self.run_smoke(
            firmware="uefi", qemu_ignore_term=True
        )
        elapsed = time.monotonic() - started
        self.addCleanup(temporary.cleanup)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertLess(elapsed, 15)
        self.assertTrue((state / "qemu-term-observed").exists())
        qemu_pid = int((state / "qemu-pid").read_text(encoding="utf-8").strip())
        self.assertFalse(Path(f"/proc/{qemu_pid}").exists())
        vars_path = Path(
            (state / "qemu-ovmf-vars-path").read_text(encoding="utf-8").strip()
        )
        self.assertFalse(vars_path.exists())
        self.assertIn("PASS: KernAid Rescue booted", result.stdout)

    def test_not_ready_precedes_ready_and_is_killed_reaped_without_reason_leak(
        self,
    ) -> None:
        started = time.monotonic()
        result, log, state, temporary = self.run_smoke(
            firmware="uefi", qemu_not_ready=True
        )
        elapsed = time.monotonic() - started
        self.addCleanup(temporary.cleanup)

        self.assertNotEqual(result.returncode, 0)
        self.assertLess(elapsed, 15)
        self.assertTrue((state / "qemu-term-observed").exists())
        qemu_pid = int((state / "qemu-pid").read_text(encoding="utf-8").strip())
        self.assertFalse(Path(f"/proc/{qemu_pid}").exists())
        combined_output = result.stdout + result.stderr
        self.assertIn("Rescue guest reported a not-ready marker", result.stderr)
        self.assertNotIn("KERNAID_RESCUE_NOT_READY:", combined_output)
        self.assertNotIn("private-reason=must-not-escape", combined_output)
        self.assertNotIn("KERNAID_QEMU_ATTESTATION_V1", combined_output)
        self.assertIn(
            "private-reason=must-not-escape", log.read_text(encoding="utf-8")
        )
        vars_path = Path(
            (state / "qemu-ovmf-vars-path").read_text(encoding="utf-8").strip()
        )
        self.assertFalse(vars_path.exists())

    def test_uefi_accepts_only_the_matching_legacy_code_vars_pair(self) -> None:
        result, _log, state, temporary = self.run_smoke(
            firmware="uefi", ovmf_layout="legacy"
        )
        self.addCleanup(temporary.cleanup)

        self.assertEqual(result.returncode, 0, result.stderr)
        arguments = (state / "qemu-args").read_text(encoding="utf-8").split()
        pflash_drives = [
            argument for argument in arguments if argument.startswith("if=pflash,")
        ]
        self.assertEqual(len(pflash_drives), 2)
        self.assertTrue(pflash_drives[0].endswith("/OVMF_CODE.fd"))
        self.assertTrue((state / "qemu-ovmf-vars-match").exists())

    def test_uefi_rejects_missing_or_mismatched_firmware_pairs(self) -> None:
        for layout, message in (
            ("missing", "OVMF CODE/VARS firmware pair not found"),
            ("mismatched", "OVMF 4M CODE/VARS firmware pair is incomplete"),
            (
                "same-identity",
                "OVMF CODE and VARS firmware files have the same identity",
            ),
        ):
            with self.subTest(layout=layout):
                result, _log, state, temporary = self.run_smoke(
                    firmware="uefi", ovmf_layout=layout
                )
                self.addCleanup(temporary.cleanup)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn(message, result.stderr)
                self.assertFalse((state / "qemu-euid").exists())

    def test_uefi_rejects_writable_system_firmware_template(self) -> None:
        result, _log, state, temporary = self.run_smoke(
            firmware="uefi", ovmf_mode="666"
        )
        self.addCleanup(temporary.cleanup)

        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn(
            "OVMF firmware failed root ownership and mode validation",
            result.stderr,
        )
        self.assertFalse((state / "qemu-euid").exists())

    def test_fixture_mount_is_the_only_sudo_scope_and_qemu_is_unprivileged(
        self,
    ) -> None:
        result, log, state, temporary = self.run_smoke()
        self.addCleanup(temporary.cleanup)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("PASS: KernAid Rescue booted", result.stdout)
        self.assertIn("KERNAID_QEMU_OFFLINE_INSPECTION_ATTESTATION_V1", log.read_text())
        self.assertFalse((state / "direct-ntfs-3g").exists())
        self.assertFalse((state / "direct-umount").exists())
        self.assertFalse((state / "direct-mktemp").exists())
        self.assertFalse((state / "mount-source").exists())
        calls = (state / "sudo-calls").read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(calls), 2)
        self.assertIn("-n --", calls[0])
        self.assertIn("ntfs-3g", calls[0])
        self.assertIn("umount --", calls[1])
        options = (state / "mount-options-observed").read_text().strip().split(",")
        self.assertEqual(
            set(options),
            {
                "rw",
                "nodev",
                "nosuid",
                "noexec",
                "allow_other",
                f"uid={os.geteuid()}",
                f"gid={os.getegid()}",
                "umask=0077",
            },
        )
        self.assertEqual(
            (state / "qemu-euid").read_text(encoding="utf-8").strip(),
            str(os.geteuid()),
        )
        self.assertNotEqual(os.geteuid(), 0)
        self.assertNotIn("sudo", (state / "qemu-args").read_text(encoding="utf-8"))
        self.assertNotIn(
            "if=pflash", (state / "qemu-args").read_text(encoding="utf-8")
        )
        self.assertFalse((state / "qemu-ovmf-vars-path").exists())

    def test_snapshot_gate_rejects_wrong_and_duplicate_guest_markers(self) -> None:
        for options in (
            {"snapshot_digest": "0" * 64},
            {"duplicate_snapshot_marker": True},
        ):
            with self.subTest(options=options):
                result, log, state, temporary = self.run_smoke(**options)
                self.addCleanup(temporary.cleanup)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertNotIn(
                    "KERNAID_QEMU_LINUX_SNAPSHOT_E2E_V1",
                    result.stdout + result.stderr,
                )
                self.assertNotIn(
                    "KERNAID_QEMU_ATTESTATION_V1", log.read_text(encoding="utf-8")
                )
                qemu_pid = int(
                    (state / "qemu-pid").read_text(encoding="utf-8").strip()
                )
                self.assertFalse(Path(f"/proc/{qemu_pid}").exists())

    def test_hardware_inventory_gate_rejects_duplicate_guest_markers(self) -> None:
        result, log, state, temporary = self.run_smoke(
            duplicate_hardware_marker=True
        )
        self.addCleanup(temporary.cleanup)

        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn(
            "Rescue hardware inventory marker was not unique", result.stderr
        )
        self.assertNotIn(
            "KERNAID_QEMU_ATTESTATION_V1", log.read_text(encoding="utf-8")
        )
        qemu_pid = int((state / "qemu-pid").read_text(encoding="utf-8").strip())
        self.assertFalse(Path(f"/proc/{qemu_pid}").exists())

    def test_snapshot_gate_requires_the_runtime_resident_digest(self) -> None:
        for resident_digest, expected_error in (
            (None, "Resident Linux snapshot digest is required"),
            ("0" * 64, "did not match the shared healthy fixture"),
        ):
            with self.subTest(resident_digest=resident_digest):
                result, log, state, temporary = self.run_smoke(
                    resident_snapshot_digest=resident_digest
                )
                self.addCleanup(temporary.cleanup)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn(expected_error, result.stderr)
                self.assertFalse(log.exists())
                self.assertFalse((state / "sudo-calls").exists())
                self.assertFalse((state / "qemu-euid").exists())

    def test_failure_after_mount_performs_verified_normal_unmount(self) -> None:
        result, _log, state, temporary = self.run_smoke(sync_failure=True)
        self.addCleanup(temporary.cleanup)

        self.assertEqual(result.returncode, 73, result.stderr)
        self.assertFalse((state / "mount-source").exists())
        self.assertFalse((state / "direct-umount").exists())
        calls = (state / "sudo-calls").read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(calls), 2)
        self.assertIn("ntfs-3g", calls[0])
        self.assertIn("umount --", calls[1])
        self.assertFalse((state / "qemu-euid").exists())

    def test_fuseblk_mount_type_is_an_exact_ntfs_3g_qualified_variant(self) -> None:
        result, _log, state, temporary = self.run_smoke(mounted_fstype="fuseblk")
        self.addCleanup(temporary.cleanup)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((state / "mount-source").exists())
        self.assertEqual(
            (state / "qemu-euid").read_text(encoding="utf-8").strip(),
            str(os.geteuid()),
        )

    def test_changed_source_is_never_passed_to_privileged_unmount(self) -> None:
        result, _log, state, temporary = self.run_smoke(
            source_mismatch_after_record=2
        )
        self.addCleanup(temporary.cleanup)

        self.assertEqual(result.returncode, 1)
        self.assertIn(
            "Disposable Windows fixture mount provenance was not exact",
            result.stderr,
        )
        calls = (state / "sudo-calls").read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(calls), 1)
        self.assertIn("ntfs-3g", calls[0])
        self.assertTrue((state / "mount-source").exists())
        self.assertFalse((state / "qemu-euid").exists())


class QemuTimeoutBudgetTests(unittest.TestCase):
    @staticmethod
    def readonly_integer(source: str, name: str) -> int:
        match = re.search(
            rf"^readonly {re.escape(name)}=([0-9]+)$", source, re.MULTILINE
        )
        if match is None:
            raise AssertionError(f"missing exact readonly integer: {name}")
        return int(match.group(1))

    def test_tcg_boot_budgets_fit_inside_the_workflow_timeout(self) -> None:
        classic = SCRIPT.read_text(encoding="utf-8")
        usb = USB_SCRIPT.read_text(encoding="utf-8")
        workflow = RESCUE_WORKFLOW.read_text(encoding="utf-8")
        vault_service = VAULT_SERVICE.read_text(encoding="utf-8")
        ready_check = READY_CHECK.read_text(encoding="utf-8")

        classic_timeout = self.readonly_integer(classic, "boot_timeout_seconds")
        usb_timeout = self.readonly_integer(usb, "boot_timeout_seconds")
        usb_boot_count = self.readonly_integer(usb, "boot_count")
        classic_cleanup = self.readonly_integer(
            classic, "qemu_term_grace_seconds"
        ) + self.readonly_integer(classic, "qemu_kill_grace_seconds")
        usb_cleanup = self.readonly_integer(
            usb, "qemu_term_grace_seconds"
        ) + self.readonly_integer(usb, "qemu_kill_grace_seconds")
        classic_capture = self.readonly_integer(
            classic, "qemu_identity_capture_seconds"
        )
        usb_capture = self.readonly_integer(
            usb, "qemu_identity_capture_seconds"
        )
        vault_timeout_match = re.search(
            r"^TimeoutStartSec=([0-9]+)s$", vault_service, re.MULTILINE
        )
        self.assertIsNotNone(vault_timeout_match)
        assert vault_timeout_match is not None
        vault_timeout = int(vault_timeout_match.group(1))

        # These are the declared blocking portions of the longest, offline
        # readiness branch. The remaining eight seconds of its 370-second
        # allowance cover fixed local validation and marker publication.
        self.assertIn('while [ "$attempt" -le 30 ]; do', ready_check)
        self.assertEqual(
            len(re.findall(r"--max-time 2(?:\s|$)", ready_check)), 1
        )
        self.assertEqual(ready_check.count("--max-time 10"), 1)
        self.assertEqual(ready_check.count("--max-time 5 --retry 12"), 2)
        self.assertEqual(ready_check.count("--retry-max-time 60"), 2)
        self.assertEqual(ready_check.count("--max-time 22"), 6)
        declared_ready_check_seconds = (
            30 * (2 + 1) + 10 + 2 * (60 + 5) + 6 * 22
        )
        ready_check_allowance_seconds = 370
        self.assertEqual(declared_ready_check_seconds, 362)
        self.assertLessEqual(
            declared_ready_check_seconds, ready_check_allowance_seconds
        )

        tcg_pre_service_seconds = 180
        scheduling_and_poll_seconds = 30
        minimum_boot_timeout = (
            tcg_pre_service_seconds
            + vault_timeout
            + ready_check_allowance_seconds
            + scheduling_and_poll_seconds
        )
        workflow_timeout_match = re.search(
            r"^  build-and-smoke-test:\n"
            r"(?:(?!^  [a-z0-9-]+:\n).)*?"
            r"^    timeout-minutes:\s*([0-9]+)\s*$",
            workflow,
            re.MULTILINE | re.DOTALL,
        )
        self.assertIsNotNone(workflow_timeout_match)
        assert workflow_timeout_match is not None
        workflow_timeout_seconds = int(workflow_timeout_match.group(1)) * 60
        classic_invocations = workflow.count("./tools/build-rescue/qemu-smoke.sh ")
        usb_invocations = workflow.count(
            '"$PWD/tools/build-rescue/qemu-usb-smoke.sh" '
        )

        self.assertEqual(vault_timeout, 620)
        self.assertEqual(minimum_boot_timeout, 1200)
        self.assertGreaterEqual(classic_timeout, minimum_boot_timeout)
        self.assertGreaterEqual(usb_timeout, minimum_boot_timeout)
        self.assertEqual(classic_cleanup, 10)
        self.assertEqual(usb_cleanup, 10)
        self.assertEqual(classic_invocations, 2)
        self.assertEqual(usb_invocations, 2)
        total_tcg_budget = (
            classic_invocations * classic_timeout
            + usb_invocations * usb_boot_count * usb_timeout
        )
        total_cleanup_budget = (
            classic_invocations * classic_cleanup
            + usb_invocations * usb_boot_count * usb_cleanup
        )
        total_capture_budget = (
            classic_invocations * classic_capture
            + usb_invocations * usb_boot_count * usb_capture
        )
        self.assertGreaterEqual(
            workflow_timeout_seconds
            - total_tcg_budget
            - total_cleanup_budget
            - total_capture_budget,
            30 * 60,
        )


if __name__ == "__main__":
    unittest.main()
