from __future__ import annotations

import importlib.util
import hashlib
import os
import re
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
from pathlib import Path


TOOLS_DIR = Path(__file__).resolve().parents[1]
SCRIPT = TOOLS_DIR / "qemu-native-vault-prompt-smoke.py"
WORKFLOW = TOOLS_DIR.parents[1] / ".github/workflows/rescue.yml"
REPO_DIR = TOOLS_DIR.parents[1]
JOURNAL_HELPER = (
    REPO_DIR
    / "rescue/live-build/config/includes.chroot/usr/lib/kernaid/qemu_native_prompt_journal_probe.py"
)


def load_script():
    spec = importlib.util.spec_from_file_location(
        "kernaid_qemu_native_vault_prompt_smoke_test", SCRIPT
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("native prompt smoke module is unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


native_prompt_smoke = load_script()


def load_journal_helper():
    spec = importlib.util.spec_from_file_location(
        "kernaid_qemu_native_prompt_journal_probe_test", JOURNAL_HELPER
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("journal proof module is unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


journal_helper = load_journal_helper()


class FakeQmp:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, object]]] = []

    def execute(self, command: str, arguments: dict[str, object]) -> None:
        self.calls.append((command, arguments))


class NativeVaultPromptSmokeTests(unittest.TestCase):
    def test_native_prompt_proofs_require_the_activated_socket_state(self) -> None:
        for proof in (native_prompt_smoke.PRE_PROOF, native_prompt_smoke.POST_PROOF):
            with self.subTest(proof=proof[:32]):
                self.assertNotIn(b'"SubState":"listening"', proof)
                self.assertIn(
                    b'socket=={"ActiveState":"active","SubState":"running","Result":"success"}',
                    proof,
                )

    def test_frame_capture_refreshes_qmp_deadline_and_closes_with_safe_stage(self) -> None:
        class FrameQmp:
            def __init__(self, failure=None) -> None:
                self.failure = failure
                self.events: list[tuple[str, object]] = []

            def set_deadline(self, deadline: float) -> None:
                self.events.append(("deadline", deadline))

            def execute(self, command: str, arguments: dict[str, object]) -> None:
                self.events.append((command, arguments))
                if self.failure is not None:
                    raise self.failure

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for stage in native_prompt_smoke.FRAME_CAPTURE_STAGES:
                with self.subTest(stage=stage):
                    qmp = FrameQmp()
                    path = root / f"{stage}.ppm"
                    with (
                        mock.patch.object(
                            native_prompt_smoke.time, "monotonic", return_value=100.0
                        ),
                        mock.patch.object(
                            native_prompt_smoke.UI_SMOKE,
                            "_read_exact_screenshot",
                            return_value=b"ppm",
                        ),
                        mock.patch.object(
                            native_prompt_smoke.UI_SMOKE,
                            "parse_ppm",
                            return_value=(800, 600, b"pixels"),
                        ),
                        mock.patch.object(
                            native_prompt_smoke.UI_SMOKE, "_remove_screenshot"
                        ),
                    ):
                        observed = native_prompt_smoke._capture_frame(
                            qmp, path, root, 130.0, stage
                        )
                    self.assertEqual(observed, (800, 600, b"pixels"))
                    self.assertEqual(qmp.events[0], ("deadline", 130.0))
                    self.assertEqual(qmp.events[1][0], "screendump")

            qmp_failure = FrameQmp(
                native_prompt_smoke.ClosedFailure("qmp", "send-timeout")
            )
            with (
                mock.patch.object(
                    native_prompt_smoke.time, "monotonic", return_value=100.0
                ),
                mock.patch.object(native_prompt_smoke.UI_SMOKE, "_remove_screenshot"),
                self.assertRaises(native_prompt_smoke.ClosedFailure) as failure,
            ):
                native_prompt_smoke._capture_frame(
                    qmp_failure, root / "failed.ppm", root, 130.0, "baseline"
                )
            self.assertEqual(
                (failure.exception.stage, failure.exception.code),
                ("framebuffer-baseline", "qmp-send-timeout"),
            )

            expired = FrameQmp()
            with (
                mock.patch.object(
                    native_prompt_smoke.time, "monotonic", return_value=130.0
                ),
                self.assertRaises(native_prompt_smoke.ClosedFailure) as failure,
            ):
                native_prompt_smoke._capture_frame(
                    expired, root / "expired.ppm", root, 130.0, "return"
                )
            self.assertEqual(
                (failure.exception.stage, failure.exception.code),
                ("framebuffer-return", "deadline"),
            )
            self.assertEqual(expired.events, [])

    def test_each_boot_keeps_the_qualified_lifecycle_timeout(self) -> None:
        parsed = native_prompt_smoke._parse_arguments(
            ["--iso", "/tmp/KernAid.iso", "--timeout", "3600"]
        )
        self.assertEqual(parsed.timeout / 2, 1800)
        with self.assertRaises(native_prompt_smoke.ClosedFailure):
            native_prompt_smoke._parse_arguments(
                ["--iso", "/tmp/KernAid.iso", "--timeout", "3599"]
            )

    def test_direct_kernel_append_is_extracted_from_the_default_iso_entry(self) -> None:
        config = b"""
label live-amd64
  append initrd=/live/initrd.img boot=live components quiet console=ttyS0,115200n8
label live-amd64-failsafe
  append initrd=/live/initrd.img boot=live components quiet nomodeset
"""
        self.assertEqual(
            native_prompt_smoke._boot_append(config),
            "boot=live components quiet console=ttyS0,115200n8",
        )
        for invalid in (
            b"append boot=live kernaid.native-prompt=vt-v1\n",
            b"append boot=live\nappend boot=live quiet\n",
            b"append boot=live nomodeset\n",
        ):
            with self.subTest(invalid=invalid):
                with self.assertRaises(native_prompt_smoke.ClosedFailure):
                    native_prompt_smoke._boot_append(invalid)

    def test_alt_u_is_paced_and_releases_the_modifier(self) -> None:
        qmp = FakeQmp()
        with mock.patch.object(native_prompt_smoke.time, "sleep") as sleep:
            native_prompt_smoke._send_alt_u(qmp)
        self.assertEqual([command for command, _arguments in qmp.calls], [
            "input-send-event",
            "input-send-event",
            "input-send-event",
        ])
        self.assertEqual(
            [
                [(True, "alt")],
                [(True, "u"), (False, "u")],
                [(False, "alt")],
            ],
            [
                [
                    (event["data"]["down"], event["data"]["key"]["data"])
                    for event in arguments["events"]
                ]
                for _command, arguments in qmp.calls
            ],
        )
        self.assertEqual(sleep.call_count, 3)

    def test_qemu_receives_only_the_secret_digest_marker(self) -> None:
        digest = "d" * 64
        arguments = native_prompt_smoke._qemu_arguments(
            Path("/tmp/private.raw"), None, None, None, digest
        )
        self.assertIn(
            f"name=opt/kernaid-native-vault-secret-digest,string={digest}",
            arguments,
        )
        with self.assertRaises(native_prompt_smoke.ClosedFailure):
            native_prompt_smoke._qemu_arguments(
                Path("/tmp/private.raw"), None, None, None, "invalid"
            )

    def test_direct_boot_does_not_treat_public_boot_live_as_login_exposure(self) -> None:
        secret = bytearray(b"0123456789abcdef" * 4)
        login = bytearray(b"live")
        media_identity = (1, 2, 3, 4)
        stop = native_prompt_smoke.ClosedFailure("test", "stop")
        try:
            with (
                mock.patch.object(native_prompt_smoke, "_validate_media"),
                mock.patch.object(
                    native_prompt_smoke, "_sha256", return_value="a" * 64
                ),
                mock.patch.object(
                    native_prompt_smoke.LIFECYCLE,
                    "QemuHarness",
                    side_effect=stop,
                ) as harness,
                self.assertRaises(native_prompt_smoke.ClosedFailure) as failure,
            ):
                native_prompt_smoke._run_prompt_boot(
                    "/usr/bin/qemu-system-x86_64",
                    Path("/tmp/private.raw"),
                    Path("/tmp/vmlinuz"),
                    Path("/tmp/initrd.img"),
                    "boot=live quiet",
                    Path("/tmp/boot2"),
                    secret,
                    login,
                    "d" * 64,
                    media_identity,
                    4096,
                    "a" * 64,
                    1800.0,
                )
            self.assertIs(failure.exception, stop)
            self.assertEqual(harness.call_args.args[3], [secret])
            self.assertEqual(harness.call_args.args[4], [secret])
        finally:
            native_prompt_smoke.LIFECYCLE.wipe(secret)
            native_prompt_smoke.LIFECYCLE.wipe(login)

    def test_guest_proofs_are_fixed_bounded_and_wait_for_notify_ready(self) -> None:
        proofs = {
            "native-pre": native_prompt_smoke.PRE_PROOF,
            "native-ready": native_prompt_smoke.READY_PROOF,
            "native-post": native_prompt_smoke.POST_PROOF,
        }
        for stage, source in proofs.items():
            with self.subTest(stage=stage):
                compile(source, f"<{stage}-proof>", "exec")
                self.assertLess(len(source), 16 * 1024)
                self.assertEqual(source.count(b"result=true"), 1)
                self.assertIn(
                    f"stage={stage} result=true".encode("ascii"), source
                )
        self.assertIn(b'prompt["ActiveState"]=="active"', proofs["native-ready"])
        self.assertIn(b'prompt["SubState"]=="running"', proofs["native-ready"])
        self.assertIn(b'prompt["Type"]=="notify"', proofs["native-ready"])
        self.assertIn(b'prompt["NotifyAccess"]=="main"', proofs["native-ready"])
        self.assertIn(b'active==b"tty8\\n"', proofs["native-ready"])
        self.assertIn(
            b"stage=native-ready checkpoint=", proofs["native-ready"]
        )
        self.assertNotIn(b"passphrase", proofs["native-ready"].lower())

    def test_passphrase_has_no_immutable_full_value_and_root_proof_is_closed(self) -> None:
        secret = native_prompt_smoke._new_passphrase()
        try:
            self.assertEqual(len(secret), 64)
            self.assertTrue(all(value in b"0123456789abcdef" for value in secret))
            for stage in native_prompt_smoke.JOURNAL_PROOF_STAGES:
                with self.subTest(stage=stage):
                    source = native_prompt_smoke._journal_marker_proof(stage)
                    self.assertIn(
                        f"stage=native-journal-{stage} result=true".encode("ascii"),
                        source,
                    )
                    self.assertIn(b'"User":"root"', source)
                    self.assertIn(b"scope=full-current-boot", source)
        finally:
            native_prompt_smoke.LIFECYCLE.wipe(secret)
        self.assertNotIn("token_hex", SCRIPT.read_text(encoding="utf-8"))
        helper = (
            REPO_DIR
            / "rescue/live-build/config/includes.chroot/usr/lib/kernaid/qemu_native_prompt_journal_probe.py"
        ).read_text(encoding="utf-8")
        service = (
            REPO_DIR
            / "rescue/live-build/config/includes.chroot/etc/systemd/system/kernaid-qemu-native-prompt-journal-proof@.service"
        ).read_text(encoding="utf-8")
        self.assertIn("os.geteuid() != 0", helper)
        self.assertIn('"--boot=0"', helper)
        self.assertIn('"--output=export"', helper)
        self.assertIn("MAX_JOURNAL_BYTES", helper)
        self.assertIn("_secret_absent(journal, expected_digest)", helper)
        self.assertIn("StandardOutput=null", service)
        self.assertIn("StandardError=null", service)
        self.assertIn("CapabilityBoundingSet=", service)
        self.assertIn("ProtectProc=invisible", service)
        self.assertIn("ProcSubset=all", service)
        self.assertNotIn("ProcSubset=pid", service)
        firstboot_unit = (
            REPO_DIR
            / "rescue/live-build/config/includes.chroot/etc/systemd/system/kernaid-rescue-firstboot.service"
        ).read_text(encoding="utf-8")
        prompt_unit = (
            REPO_DIR
            / "rescue/live-build/config/includes.chroot/etc/systemd/system/kernaid-rescue-native-vault-unlock.service"
        ).read_text(encoding="utf-8")
        self.assertNotIn(
            "OnSuccess=kernaid-qemu-native-prompt-journal-proof@boot1.service",
            firstboot_unit,
        )
        self.assertEqual(
            firstboot_unit.count(
                "Wants=kernaid-qemu-native-prompt-journal-proof@boot1.service"
            ),
            1,
        )
        before_lines = [
            line for line in firstboot_unit.splitlines() if line.startswith("Before=")
        ]
        self.assertEqual(len(before_lines), 1)
        self.assertEqual(
            before_lines[0].removeprefix("Before=").split().count(
                "kernaid-qemu-native-prompt-journal-proof@boot1.service"
            ),
            1,
        )
        self.assertEqual(
            prompt_unit.count(
                "OnSuccess=kernaid-qemu-native-prompt-journal-proof@boot2.service"
            ),
            1,
        )
        self.assertIn("ConditionPathExists=/sys/firmware/qemu_fw_cfg/", service)

        guest_match = re.search(
            rb"deadline=time\.monotonic\(\)\+(\d+)",
            native_prompt_smoke._journal_marker_proof("boot1"),
        )
        self.assertIsNotNone(guest_match)
        assert guest_match is not None
        unit_match = re.search(r"^TimeoutStartSec=(\d+)s$", service, re.MULTILINE)
        self.assertIsNotNone(unit_match)
        assert unit_match is not None
        self.assertGreater(
            native_prompt_smoke.JOURNAL_MARKER_PROOF_TIMEOUT_SECONDS,
            max(float(guest_match.group(1)), float(unit_match.group(1))),
        )
        self.assertEqual(
            SCRIPT.read_text(encoding="utf-8").count(
                "timeout=JOURNAL_MARKER_PROOF_TIMEOUT_SECONDS"
            ),
            len(native_prompt_smoke.JOURNAL_PROOF_STAGES),
        )

    def test_private_raw_is_digest_and_identity_pinned_before_extraction(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            iso = root / "input.iso"
            iso.write_bytes(b"KernAid-private-prefix" * 64)
            media = root / "private.raw"
            with mock.patch.object(native_prompt_smoke, "MEDIA_BYTES", 8192):
                digest, identity = native_prompt_smoke._copy_iso_to_media(
                    iso, iso.lstat(), media
                )
            self.assertEqual(digest, hashlib.sha256(iso.read_bytes()).hexdigest())
            os.chmod(media, 0o400)
            native_prompt_smoke._validate_media(media, identity, mode=0o400)
            self.assertEqual(
                native_prompt_smoke._sha256(media, iso.stat().st_size, identity),
                digest,
            )
            os.utime(media, ns=(media.stat().st_atime_ns, media.stat().st_mtime_ns + 1))
            with self.assertRaises(native_prompt_smoke.ClosedFailure):
                native_prompt_smoke._validate_media(media, identity, mode=0o400)

    def test_root_marker_publication_handles_partial_write_and_checks_identity(self) -> None:
        writes = []

        def partial(_descriptor, payload):
            count = min(3, len(payload))
            writes.append(bytes(payload[:count]))
            return count

        with mock.patch.object(journal_helper.os, "write", side_effect=partial):
            journal_helper._write_all(9, b"fixed-marker")
        self.assertEqual(b"".join(writes), b"fixed-marker")
        metadata = SimpleNamespace(
            st_mode=stat.S_IFREG | 0o444,
            st_uid=0,
            st_gid=0,
            st_nlink=1,
            st_size=12,
        )
        self.assertTrue(journal_helper._marker_metadata_valid(metadata, 12, 0))
        metadata.st_nlink = 2
        self.assertFalse(journal_helper._marker_metadata_valid(metadata, 12, 0))
        with mock.patch.object(journal_helper.os, "write", return_value=0):
            with self.assertRaises(journal_helper.ProbeFailure):
                journal_helper._write_all(9, b"fixed-marker")

    def test_workflow_reuses_one_iso_and_always_publishes_closed_evidence(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        job_match = re.search(
            r"^  native-vault-prompt-bios:\n(?P<body>.*?)"
            r"(?=^  [a-z0-9-]+:\n|\Z)",
            workflow,
            re.MULTILINE | re.DOTALL,
        )
        self.assertIsNotNone(job_match)
        job = job_match.group(0)
        self.assertIn("needs: build-and-smoke-test", job)
        self.assertIn("name: KernAid-Rescue-amd64", job)
        self.assertIn("qemu-native-vault-prompt-smoke.py", job)
        self.assertIn("--timeout 3600", job)
        self.assertNotIn("matrix:", job)
        self.assertNotIn("strategy:", job)
        self.assertNotIn("lb build", job)
        self.assertIn("stage=output code=invalid", job)
        self.assertIn("metadata.st_size > 4096", job)
        self.assertIn("payload.count(b\"\\n\") != 1", job)
        self.assertIn("safe_path.write_bytes(payload)", job)
        self.assertIn("captured-secret-exposure=false", job)
        self.assertIn("journald-secret-exposure=false", job)
        self.assertIn("journald-scope=root-full-current-boot", job)
        self.assertIn("iso_sha256=[0-9a-f]{64}", job)
        self.assertIn("if: always()", job)
        self.assertIn("retention-days: 30", job)
        self.assertIn("kernaid-native-vault-prompt.sanitized.log", job)
        self.assertNotIn("path: ${{ runner.temp }}/kernaid-native-vault-prompt.raw.log", job)
        qualified = workflow.split("  qualified-release:\n", 1)[1]
        self.assertIn("      - native-vault-prompt-bios\n", qualified)
        self.assertIn("KernAid-Rescue-native-vault-prompt-bios-evidence", qualified)
        self.assertIn("--native-prompt-evidence", qualified)


if __name__ == "__main__":
    unittest.main()
