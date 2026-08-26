from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


REPO_DIR = Path(__file__).resolve().parents[3]
SCRIPT = REPO_DIR / "tools/build-rescue/qualification-manifest.py"
RUN_ID = 32950000001
RUN_ATTEMPT = 2
RUN_URL = f"https://github.com/0xfunboy/KernAid/actions/runs/{RUN_ID}"
VERSION = f"ci-{RUN_ID}-{RUN_ATTEMPT}"
COMMIT = "0123456789abcdef0123456789abcdef01234567"


class RescueQualificationManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.iso = self.root / "KernAid-Rescue-amd64.iso"
        self.iso.write_bytes(b"qualified-rescue-image\0" * 257)
        self.iso_digest = hashlib.sha256(self.iso.read_bytes()).hexdigest()
        self.checksum = self.root / "KernAid-Rescue-amd64.iso.sha256"
        self.checksum.write_text(
            f"{self.iso_digest}  KernAid-Rescue-amd64.iso\n",
            encoding="ascii",
        )

        self.usb: dict[str, Path] = {}
        self.usb_digests: dict[str, str] = {}
        for firmware in ("bios", "uefi"):
            path = self.root / f"rescue-usb-smoke-{firmware}.log"
            path.write_text(f"usb evidence for {firmware}\n", encoding="ascii")
            self.usb[firmware] = path
            self.usb_digests[firmware] = hashlib.sha256(path.read_bytes()).hexdigest()

        attestations = {
            firmware: {
                "passed": True,
                "workflowRunId": RUN_ID,
                "workflowRunUrl": RUN_URL,
                "logSha256": self.usb_digests[firmware],
            }
            for firmware in ("bios", "uefi")
        }
        self.catalog = self.root / "KernAid-Rescue-amd64.catalog-entry-v2.json"
        self.catalog.write_text(
            json.dumps(
                {
                    "artifactName": self.iso.name,
                    "artifactVersion": VERSION,
                    "sha256": self.iso_digest,
                    "bytes": self.iso.stat().st_size,
                    "deviceLayout": {},
                    "qemuUsbBootAttestations": attestations,
                    "qemuVaultAttestations": attestations,
                }
            ),
            encoding="utf-8",
        )
        self.sbom = self.root / "KernAid-Rescue-amd64.codex.cdx.json"
        self.sbom.write_text(
            json.dumps(
                {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.6",
                    "version": 1,
                    "metadata": {},
                    "components": [{"type": "application", "name": "Codex CLI"}],
                }
            ),
            encoding="utf-8",
        )
        digest = "a" * 64
        self.snapshot = self.root / "kernaid-linux-snapshot-e2e.sanitized.log"
        self.snapshot.write_text(
            "".join(
                (
                    f"KERNAID_LINUX_SNAPSHOT_E2E_V1 source=resident semantic_sha256={digest}\n",
                    f"KERNAID_LINUX_SNAPSHOT_E2E_V1 source=rescue-bios semantic_sha256={digest}\n",
                    f"KERNAID_LINUX_SNAPSHOT_E2E_V1 source=rescue-uefi semantic_sha256={digest}\n",
                    f"KERNAID_LINUX_SNAPSHOT_PARITY_V1 semantic_sha256={digest} equal=true\n",
                )
            ),
            encoding="ascii",
        )
        self.lifecycle: dict[str, Path] = {}
        for firmware in ("bios", "uefi"):
            path = self.root / f"kernaid-vault-lifecycle-{firmware}.sanitized.log"
            path.write_text(
                "".join(
                    (
                        f"KERNAID_QEMU_VAULT_LIFECYCLE_BOOT_V1 firmware={firmware} boot=1 passing=true\n",
                        f"KERNAID_QEMU_VAULT_LIFECYCLE_BOOT_V1 firmware={firmware} boot=2 passing=true\n",
                        f"KERNAID_QEMU_VAULT_LIFECYCLE_RAW_V1 firmware={firmware} passing=true\n",
                        f"KERNAID_QEMU_VAULT_LIFECYCLE_ATTESTATION_V1 firmware={firmware} ready=true\n",
                    )
                ),
                encoding="ascii",
            )
            self.lifecycle[firmware] = path

    def command(self, operation: str, destination: Path) -> list[str]:
        result = [
            sys.executable,
            "-I",
            str(SCRIPT),
            operation,
            "--repository",
            "0xfunboy/KernAid",
            "--commit",
            COMMIT,
            "--run-id",
            str(RUN_ID),
            "--run-attempt",
            str(RUN_ATTEMPT),
            "--run-url",
            RUN_URL,
            "--artifact-version",
            VERSION,
            "--iso",
            str(self.iso),
            "--checksum",
            str(self.checksum),
            "--catalog",
            str(self.catalog),
            "--sbom",
            str(self.sbom),
            "--snapshot-evidence",
            str(self.snapshot),
            "--usb-bios-evidence",
            str(self.usb["bios"]),
            "--usb-uefi-evidence",
            str(self.usb["uefi"]),
            "--lifecycle-bios-evidence",
            str(self.lifecycle["bios"]),
            "--lifecycle-uefi-evidence",
            str(self.lifecycle["uefi"]),
        ]
        result.extend(("--output" if operation == "create" else "--manifest", str(destination)))
        return result

    def run_command(self, operation: str, destination: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            self.command(operation, destination),
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )

    def test_create_is_canonical_and_verify_recomputes_every_input(self) -> None:
        manifest = self.root / "KernAid-Rescue-amd64.qualified.json"
        created = self.run_command("create", manifest)
        self.assertEqual(created.returncode, 0, created.stderr)
        payload = manifest.read_bytes()
        document = json.loads(payload)
        self.assertEqual(
            payload,
            (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode(
                "ascii"
            ),
        )
        self.assertEqual(document["source"]["commit"], COMMIT)
        self.assertEqual(document["artifacts"]["iso"]["sha256"], self.iso_digest)
        self.assertEqual(
            document["evidence"]["qemuUsbBoot"]["uefi"]["sha256"],
            self.usb_digests["uefi"],
        )
        verified = self.run_command("verify", manifest)
        self.assertEqual(verified.returncode, 0, verified.stderr)
        self.assertEqual(created.stdout, verified.stdout)

    def test_verify_refuses_an_input_changed_after_manifest_creation(self) -> None:
        manifest = self.root / "KernAid-Rescue-amd64.qualified.json"
        self.assertEqual(self.run_command("create", manifest).returncode, 0)
        sbom = json.loads(self.sbom.read_text(encoding="utf-8"))
        sbom["components"].append({"type": "library", "name": "unexpected"})
        self.sbom.write_text(json.dumps(sbom), encoding="utf-8")
        result = self.run_command("verify", manifest)
        self.assertEqual(result.returncode, 3)
        self.assertIn("manifest is not exact and canonical", result.stderr)

    def test_create_refuses_catalog_not_bound_to_downloaded_evidence(self) -> None:
        catalog = json.loads(self.catalog.read_text(encoding="utf-8"))
        catalog["qemuUsbBootAttestations"]["bios"]["logSha256"] = "b" * 64
        self.catalog.write_text(json.dumps(catalog), encoding="utf-8")
        result = self.run_command(
            "create", self.root / "KernAid-Rescue-amd64.qualified.json"
        )
        self.assertEqual(result.returncode, 3)
        self.assertIn("not bound to this run and evidence", result.stderr)

    def test_create_refuses_a_version_from_another_run_attempt(self) -> None:
        command = self.command(
            "create", self.root / "KernAid-Rescue-amd64.qualified.json"
        )
        command[command.index("--artifact-version") + 1] = f"ci-{RUN_ID}-99"
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 3)
        self.assertIn("not bound to this run attempt", result.stderr)


if __name__ == "__main__":
    unittest.main()
