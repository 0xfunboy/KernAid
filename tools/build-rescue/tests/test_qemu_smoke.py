from __future__ import annotations

import os
import re
import stat
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


TOOLS_DIR = Path(__file__).resolve().parents[1]
REPO_DIR = Path(__file__).resolve().parents[3]
SCRIPT = TOOLS_DIR / "qemu-smoke.sh"
USB_SCRIPT = TOOLS_DIR / "qemu-usb-smoke.sh"
RESCUE_WORKFLOW = REPO_DIR / ".github/workflows/rescue.yml"


def executable(path: Path, source: str) -> None:
    path.write_text(textwrap.dedent(source).lstrip(), encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


class MockToolchain:
    def __init__(self, directory: Path) -> None:
        self.bin = directory / "bin"
        self.state = directory / "state"
        self.bin.mkdir()
        self.state.mkdir()
        self._install()

    def _tool(self, name: str, source: str) -> None:
        executable(self.bin / name, source)

    def _install(self) -> None:
        for name in ("debugfs", "mkfs.ext4", "mkfs.ntfs", "ntfsfix"):
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
              printf 'directory:0:0:755\n'
              exit 0
            fi
            case "${target##*/}" in
              ntfs-3g|sudo|umount)
                if [[ " $* " == *" %F:%u:%g:%a "* ]]; then
                  printf 'regular file:0:0:755\n'
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
            printf '%s\n' "$*" >"$KERNAID_MOCK_STATE_DIR/qemu-args"
            printf 'KERNAID_RESCUE_READY\n'
            printf 'KERNAID_RESCUE_TARGET_SELECTION_READY\n'
            printf 'KERNAID_RESCUE_OFFLINE_INSPECTION_READY\n'
            exec /usr/bin/sleep 30
            """,
        )


class QemuSmokeFixturePrivilegeTests(unittest.TestCase):
    def materialize_test_script(self, directory: Path, mocks: MockToolchain) -> Path:
        source = SCRIPT.read_text(encoding="utf-8")
        replacements = {
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
    ) -> tuple[
        subprocess.CompletedProcess[str], Path, Path, tempfile.TemporaryDirectory[str]
    ]:
        temporary = tempfile.TemporaryDirectory()
        directory = Path(temporary.name)
        mocks = MockToolchain(directory)
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
                "KERNAID_SMOKE_LOG": str(log),
                "TMPDIR": str(directory),
            }
        )
        if source_mismatch_after_record is not None:
            environment["KERNAID_MOCK_SOURCE_MISMATCH_AFTER_RECORD"] = str(
                source_mismatch_after_record
            )
        result = subprocess.run(
            [str(script), "bios", str(iso)],
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

        classic_timeout = self.readonly_integer(classic, "boot_timeout_seconds")
        usb_timeout = self.readonly_integer(usb, "boot_timeout_seconds")
        usb_boot_count = self.readonly_integer(usb, "boot_count")
        workflow_timeout_match = re.search(
            r"^\s*timeout-minutes:\s*([0-9]+)\s*$", workflow, re.MULTILINE
        )
        self.assertIsNotNone(workflow_timeout_match)
        assert workflow_timeout_match is not None
        workflow_timeout_seconds = int(workflow_timeout_match.group(1)) * 60
        classic_invocations = workflow.count("./tools/build-rescue/qemu-smoke.sh ")
        usb_invocations = workflow.count(
            '"$PWD/tools/build-rescue/qemu-usb-smoke.sh" '
        )

        self.assertEqual(classic_timeout, 600)
        self.assertEqual(usb_timeout, 600)
        self.assertEqual(classic_invocations, 2)
        self.assertEqual(usb_invocations, 2)
        total_tcg_budget = (
            classic_invocations * classic_timeout
            + usb_invocations * usb_boot_count * usb_timeout
        )
        self.assertLess(total_tcg_budget, workflow_timeout_seconds)
        self.assertGreaterEqual(workflow_timeout_seconds - total_tcg_budget, 30 * 60)


if __name__ == "__main__":
    unittest.main()
