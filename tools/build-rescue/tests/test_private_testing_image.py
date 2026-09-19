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
            self.assertIn("if: inputs.private_testing", step)
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
        encryption = source.index("      - name: Encrypt the smoke-tested private testing image")
        for name in (
            "QEMU BIOS smoke test", "QEMU UEFI Secure Boot smoke test",
            "QEMU BIOS USB-style two-boot smoke test", "QEMU UEFI USB-style two-boot smoke test",
        ):
            step = source.split(f"      - name: {name}\n", 1)[1].split("      - ", 1)[0]
            self.assertNotIn("if:", step)
            self.assertLess(source.index(f"      - name: {name}\n"), encryption)
        self.assertIn('unset KERNAID_TEST_GEMROUTER_KEY', source)
        self.assertIn('KERNAID_PRIVATE_TESTING=1 KERNAID_PRIVATE_GEMROUTER_KEY_FILE="$key_file"', source)


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

    def encrypt(self) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            ["bash", str(ENCRYPT), str(self.iso), str(self.output)],
            env=self.environment, capture_output=True, check=False,
        )

    def test_round_trip_contains_only_image_and_checksum_without_leaking_passphrase(self) -> None:
        result = self.encrypt()
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertNotIn(self.passphrase.encode(), result.stdout + result.stderr)
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o600)
        self.assertNotIn(self.payload, self.output.read_bytes())
        self.assertFalse(list(self.directory.glob("kernaid-private-iso.*")))
        gpg_home = self.directory / "decrypt-home"
        gpg_home.mkdir(mode=0o700)
        decrypted = subprocess.run(
            ["gpg", "--no-options", "--homedir", str(gpg_home), "--batch",
             "--pinentry-mode", "loopback", "--passphrase-fd", "0", "--decrypt", str(self.output)],
            input=f"{self.passphrase}\n".encode(), capture_output=True, check=False,
        )
        self.assertEqual(decrypted.returncode, 0, decrypted.stderr.decode())
        with tarfile.open(fileobj=io.BytesIO(decrypted.stdout)) as archive:
            self.assertEqual(archive.getnames(), [self.iso.name, self.checksum.name])
            self.assertEqual(archive.extractfile(self.iso.name).read(), self.payload)

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
