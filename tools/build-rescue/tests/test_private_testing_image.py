from __future__ import annotations

import hashlib
import io
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
import textwrap
import unittest


REPO = Path(__file__).resolve().parents[3]
ENCRYPT = REPO / "tools/build-rescue/encrypt-private-test-image.sh"
STAGE = REPO / "tools/build-rescue/stage-assistant.sh"
WORKFLOW = REPO / ".github/workflows/rescue.yml"


class PrivateTestingWorkflowTests(unittest.TestCase):
    def test_private_dispatch_is_main_only_and_unqualified(self) -> None:
        source = WORKFLOW.read_text()
        self.assertIn("private_testing:\n", source)
        self.assertIn("        type: boolean\n        default: false", source)
        self.assertIn(
            "!inputs.private_testing || (github.event_name == 'workflow_dispatch' "
            "&& github.ref == 'refs/heads/main')",
            source,
        )
        for job in ("native-vault-prompt-bios", "vault-lifecycle-bios", "vault-lifecycle-uefi"):
            self.assertIn(f"  {job}:\n    if: ${{{{ !inputs.private_testing }}}}", source)
        self.assertIn(
            "  qualified-release:\n    if: github.ref == 'refs/heads/main' && !inputs.private_testing",
            source,
        )

    def test_all_base_job_uploads_are_public_except_encrypted_bundle(self) -> None:
        source = WORKFLOW.read_text().split("  native-vault-prompt-bios:", 1)[0]
        encrypted = []
        for step in re.split(r"^      - ", source, flags=re.MULTILINE):
            if "uses: actions/upload-artifact@v4" not in step:
                continue
            if "!inputs.private_testing" in step:
                continue
            self.assertIn("always() && inputs.private_testing && steps.encrypt_private.outcome == 'success'", step)
            self.assertIn("KernAid-Rescue-amd64-PRIVATE-testing-encrypted", step)
            self.assertIn("path: ${{ runner.temp }}/KernAid-Rescue-amd64-PRIVATE-testing.tar.gpg", step)
            self.assertNotIn(".iso\n", step)
            encrypted.append(step)
        self.assertEqual(len(encrypted), 1)
        for name in (
            "Derive catalog entry from the tested ISO and attested QEMU logs",
            "Derive and validate the inactive catalog-v2 evidence artifact",
        ):
            self.assertIn(f"      - name: {name}\n        if: ${{{{ !inputs.private_testing }}}}", source)

    def test_private_image_still_runs_exact_base_boot_gates_before_encryption(self) -> None:
        source = WORKFLOW.read_text()
        encryption = source.index("      - name: Encrypt private testing image and bounded diagnostics")
        for name in (
            "QEMU BIOS smoke test", "QEMU UEFI Secure Boot smoke test",
            "QEMU BIOS USB-style two-boot smoke test", "QEMU UEFI USB-style two-boot smoke test",
        ):
            step = source.split(f"      - name: {name}\n", 1)[1].split("      - ", 1)[0]
            self.assertNotIn("if:", step)
            self.assertLess(source.index(f"      - name: {name}\n"), encryption)
        self.assertIn('unset KERNAID_TEST_GEMROUTER_KEY', source)
        self.assertIn('KERNAID_PRIVATE_TESTING=1 KERNAID_PRIVATE_GEMROUTER_KEY_FILE="$key_file"', source)

    def test_failed_smoke_keeps_encrypted_forensics_but_cannot_qualify(self) -> None:
        source = WORKFLOW.read_text()
        encryption = source.split("      - name: Encrypt private testing image and bounded diagnostics\n", 1)[1].split("      - name:", 1)[0]
        self.assertIn("id: encrypt_private", encryption)
        self.assertIn("always() && inputs.private_testing && steps.build_image.outcome == 'success'", encryption)
        self.assertIn("--diagnostics", encryption)
        for gate in ("build_image", "repair_surface", "smoke_bios", "smoke_uefi", "snapshot_evidence", "smoke_usb_bios", "smoke_usb_uefi"):
            self.assertIn(f"${{{{ steps.{gate}.outcome }}}}", encryption)
        self.assertNotIn("continue-on-error", source)

    def test_readiness_diagnostic_exposes_only_exact_source_owned_codes(self) -> None:
        source = WORKFLOW.read_text()
        step = source.split("      - name: Publish only closed private readiness failure markers\n", 1)[1].split("      - name:", 1)[0]
        code = textwrap.dedent(step.split("<<'PY'\n", 1)[1].rsplit("          PY", 1)[0])
        with tempfile.TemporaryDirectory(prefix="kernaid-private-markers-test-") as temporary:
            root = Path(temporary)
            ready_path = root / "rescue/live-build/config/includes.chroot/usr/lib/kernaid/ready-check"
            ready_path.parent.mkdir(parents=True)
            ready_path.write_bytes((REPO / ready_path.relative_to(root)).read_bytes())
            valid = b"KERNAID_RESCUE_READINESS_FAILURE_V1 code=assistant-service"
            (root / "rescue-smoke-bios.log").write_bytes(
                b"private free text\nKERNAID_RESCUE_NOT_READY: private reason\n"
                + valid + b" extra-private-text\n"
                + b"prefix " + valid + b"\n"
                + b"KERNAID_RESCUE_READINESS_FAILURE_V1 code=unknown-private-code\n"
                + valid + b"\r\n" + valid + b"\n"
            )
            (root / "rescue-smoke-uefi.log").symlink_to(root / "rescue-smoke-bios.log")
            result = subprocess.run(["python3", "-I", "-B", "-c", code], cwd=root, capture_output=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual(result.stdout, valid + b"\n")
            self.assertEqual(result.stderr, b"")


@unittest.skipUnless(shutil.which("gpg"), "GnuPG is required")
class PrivateImageEncryptionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="kernaid-private-image-test-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.iso = self.directory / "KernAid-Rescue-amd64.iso"
        self.payload = b"Disposable image fixture, not bootable and no provider credential.\n"
        self.iso.write_bytes(self.payload)
        self.checksum = Path(f"{self.iso}.sha256")
        self.checksum.write_text(f"{hashlib.sha256(self.payload).hexdigest()}  {self.iso.name}\n")
        self.output = self.directory / "KernAid-Rescue-amd64-PRIVATE-testing.tar.gpg"
        self.passphrase = "disposable-test-encryption-passphrase"
        self.environment = {**os.environ, "TMPDIR": str(self.directory), "KERNAID_TEST_ISO_PASSPHRASE": self.passphrase}

    def encrypt(self, *arguments: str) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            ["bash", str(ENCRYPT), str(self.iso), str(self.output), *arguments],
            env=self.environment, capture_output=True, check=False,
        )

    def decrypt(self) -> bytes:
        gpg_home = self.directory / "decrypt-home"
        gpg_home.mkdir(mode=0o700)
        decrypted = subprocess.run(
            ["gpg", "--no-options", "--homedir", str(gpg_home), "--batch",
             "--pinentry-mode", "loopback", "--passphrase-fd", "0", "--decrypt", str(self.output)],
            input=f"{self.passphrase}\n".encode(), capture_output=True, check=False,
        )
        self.assertEqual(decrypted.returncode, 0, decrypted.stderr.decode())
        return decrypted.stdout

    def test_round_trip_contains_only_image_and_checksum_without_leaking_passphrase(self) -> None:
        result = self.encrypt()
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertNotIn(self.passphrase.encode(), result.stdout + result.stderr)
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o600)
        self.assertNotIn(self.payload, self.output.read_bytes())
        self.assertFalse(list(self.directory.glob("kernaid-private-iso.*")))
        with tarfile.open(fileobj=io.BytesIO(self.decrypt())) as archive:
            self.assertEqual(archive.getnames(), [self.iso.name, self.checksum.name])
            self.assertEqual(archive.extractfile(self.iso.name).read(), self.payload)

    def test_diagnostics_keep_bounded_fixed_logs_and_failed_gate_status_encrypted(self) -> None:
        private_log = b"discarded-start" + b"x" * (8 * 1024 * 1024) + b"private diagnostic tail"
        (self.directory / "rescue-smoke-bios.log").write_bytes(private_log)
        (self.directory / "rescue-smoke-uefi.log").symlink_to(self.iso)
        (self.directory / "unrelated.log").write_bytes(b"never included")
        self.environment.update(KERNAID_PRIVATE_BUILD_OUTCOME="success", KERNAID_PRIVATE_BIOS_OUTCOME="failure", KERNAID_PRIVATE_UEFI_OUTCOME="skipped")
        result = self.encrypt("--diagnostics")
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertNotIn(b"private diagnostic tail", result.stdout + result.stderr)
        self.assertFalse(list(self.directory.glob("kernaid-private-iso.*")))
        with tarfile.open(fileobj=io.BytesIO(self.decrypt())) as archive:
            self.assertEqual(archive.getnames(), [self.iso.name, self.checksum.name, "private-test-status.txt", "rescue-smoke-bios.log"])
            self.assertEqual(archive.extractfile("rescue-smoke-bios.log").read(), private_log[-8 * 1024 * 1024:])
            status = archive.extractfile("private-test-status.txt").read()
            for expected in (b"qualified=false\n", b"BUILD=success\n", b"BIOS=failure\n", b"UEFI=skipped\n"):
                self.assertIn(expected, status)

    def test_invalid_diagnostic_outcome_cannot_escape_to_archive(self) -> None:
        self.environment["KERNAID_PRIVATE_BIOS_OUTCOME"] = "private invalid outcome"
        result = self.encrypt("--diagnostics")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(b"private invalid outcome", result.stdout + result.stderr)
        self.assertFalse(self.output.exists())
        self.assertFalse(list(self.directory.glob("kernaid-private-iso.*")))

    def test_checksum_mismatch_fails_without_output(self) -> None:
        self.iso.write_bytes(b"changed disposable image")
        self.assertNotEqual(self.encrypt().returncode, 0)
        self.assertFalse(self.output.exists())

    def test_existing_output_is_not_overwritten(self) -> None:
        self.output.write_bytes(b"preserve existing file")
        self.assertNotEqual(self.encrypt().returncode, 0)
        self.assertEqual(self.output.read_bytes(), b"preserve existing file")

    def test_missing_passphrase_fails_without_output(self) -> None:
        self.environment.pop("KERNAID_TEST_ISO_PASSPHRASE")
        self.assertNotEqual(self.encrypt().returncode, 0)
        self.assertFalse(self.output.exists())


class PrivateStagingGuardTests(unittest.TestCase):
    def test_public_ci_rejects_credential_before_dependency_staging(self) -> None:
        result = subprocess.run(
            ["bash", str(STAGE)],
            env={**os.environ, "GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "push",
                 "GITHUB_REF": "refs/heads/main", "KERNAID_PRIVATE_TESTING": "0",
                 "KERNAID_PRIVATE_GEMROUTER_KEY_FILE": "/does-not-exist"},
            capture_output=True, check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"CI credentials are restricted", result.stderr)

    def test_staging_refuses_prior_credential_before_node_or_network(self) -> None:
        source = STAGE.read_text()
        guard = source.index("Refusing to reuse a pre-existing private assistant credential")
        self.assertLess(guard, source.index("node --version"))
        self.assertLess(guard, source.index("git clone"))
        self.assertIn('[[ -e "$private_destination" || -L "$private_destination" ]]', source)


if __name__ == "__main__":
    unittest.main()
