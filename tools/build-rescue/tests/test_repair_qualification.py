from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "repair-qualification.py"
COMMIT = "0123456789abcdef0123456789abcdef01234567"
RUN_ID = 33400000001
P3_SHA256 = "ebfb4ef19ae410f190327b5ebd312711263bc7579970e87d9c1e2d84e06b3c25"
SCENARIOS = (
    "bios-apply,uefi-apply,uefi-rollback,uefi-interrupt-reconcile,"
    "uefi-stale-target,uefi-cancel,uefi-backup-tamper,"
    "uefi-repaird-termination,uefi-auto-restore"
)


class RepairQualificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.iso = self.root / "KernAid-Rescue-Repair-amd64.iso"
        self.checksum = self.root / "KernAid-Rescue-Repair-amd64.iso.sha256"
        self.retail = self.root / "KernAid-Rescue-Repair-amd64-retail.img.xz"
        self.retail_checksum = self.root / (
            "KernAid-Rescue-Repair-amd64-retail.img.xz.sha256"
        )
        self.retail_metadata = self.root / (
            "KernAid-Rescue-Repair-amd64-retail.json"
        )
        self.bios = self.root / "kernaid-rescue-repair-bios.sanitized.log"
        self.uefi = self.root / "kernaid-rescue-repair-uefi.sanitized.log"
        self.batch = self.root / (
            "kernaid-rescue-repair-qualification-batch.sanitized.log"
        )
        self.catalog = self.root / (
            "KernAid-Rescue-Repair-amd64.catalog-entry.json"
        )
        self.manifest = self.root / "KernAid-Rescue-Repair-amd64.qualified.json"

        self.iso.write_bytes(b"repair-iso-fixture\0" * 47)
        self.retail.write_bytes(b"repair-retail-fixture\0" * 53)
        iso_sha = hashlib.sha256(self.iso.read_bytes()).hexdigest()
        retail_sha = hashlib.sha256(self.retail.read_bytes()).hexdigest()
        self.checksum.write_text(f"{iso_sha}  {self.iso.name}\n", encoding="ascii")
        self.retail_checksum.write_text(
            f"{retail_sha}  {self.retail.name}\n", encoding="ascii"
        )
        retail_document = {
            "compressed": {
                "bytes": self.retail.stat().st_size,
                "name": self.retail.name,
                "sha256": retail_sha,
            },
            "isoPrefix": {"bytes": self.iso.stat().st_size, "sha256": iso_sha},
            "p3": {
                "bytes": 8_589_934_592,
                "sha256": P3_SHA256,
                "startBytes": 17_179_869_184,
                "zero": True,
            },
            "raw": {
                "bytes": 32_000_000_000,
                "name": "KernAid-Rescue-Repair-amd64-retail.img",
                "sha256": "a" * 64,
            },
            "schema": "dev.kernaid.rescue-repair-retail-image.v1",
            "tailZero": True,
        }
        self.retail_metadata.write_text(
            json.dumps(retail_document, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="ascii",
        )
        unchanged = "b" * 64
        self.bios.write_text(
            "KERNAID_QEMU_ATTESTATION_V1 firmware=bios "
            f"iso_sha256={iso_sha} target_before_sha256={unchanged} "
            f"target_after_sha256={unchanged} ready=true\n",
            encoding="ascii",
        )
        self.uefi.write_text(
            "KERNAID_QEMU_ATTESTATION_V1 firmware=uefi "
            f"iso_sha256={iso_sha} target_before_sha256={unchanged} "
            f"target_after_sha256={unchanged} ready=true\n"
            "KERNAID_QEMU_SECURE_BOOT_ATTESTATION_V1 firmware=uefi machine=q35 "
            "ovmf_profile=ms-enrolled secure_boot=enabled setup_mode=disabled "
            f"shim_validation=enabled iso_sha256={iso_sha} ready=true\n",
            encoding="ascii",
        )
        self.batch.write_text(
            "KERNAID_QEMU_REPAIR_QUALIFICATION_BATCH_ATTESTATION_V1 "
            f"provisioning=shared scenarios={SCENARIOS} isolated_sparse_copies=true "
            f"iso_sha256={iso_sha} iso_prefix_immutable=true "
            "host_physical_devices=false ready=true\n",
            encoding="ascii",
        )

    def command(self, action: str) -> list[str]:
        result = [
            sys.executable,
            "-I",
            "-B",
            str(SCRIPT),
            action,
            "--repository",
            "0xfunboy/KernAid",
            "--commit",
            COMMIT,
            "--run-id",
            str(RUN_ID),
            "--run-attempt",
            "1",
            "--run-url",
            f"https://github.com/0xfunboy/KernAid/actions/runs/{RUN_ID}",
            "--artifact-version",
            f"repair-ci-{RUN_ID}-1",
            "--iso",
            str(self.iso),
            "--checksum",
            str(self.checksum),
            "--retail-image",
            str(self.retail),
            "--retail-checksum",
            str(self.retail_checksum),
            "--retail-metadata",
            str(self.retail_metadata),
            "--bios-evidence",
            str(self.bios),
            "--uefi-evidence",
            str(self.uefi),
            "--batch-evidence",
            str(self.batch),
            "--catalog",
            str(self.catalog),
        ]
        result.extend(
            ["--output", str(self.manifest)]
            if action == "create"
            else ["--manifest", str(self.manifest)]
        )
        return result

    def run_cli(self, action: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            self.command(action),
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )

    def create(self) -> None:
        result = self.run_cli("create")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_create_and_verify_keep_compiled_and_qualified_actions_distinct(self) -> None:
        self.create()
        manifest = json.loads(self.manifest.read_text(encoding="ascii"))
        catalog = json.loads(self.catalog.read_text(encoding="ascii"))
        self.assertFalse(manifest["diagnosisOnly"])
        self.assertTrue(manifest["repairEnabled"])
        self.assertFalse(manifest["physicalQualification"])
        self.assertEqual(manifest["channel"], "repair")
        self.assertEqual(
            manifest["capabilities"]["qualifiedRepairActions"],
            ["linux.fstab.disable-missing-uuid.v1"],
        )
        self.assertGreater(
            len(manifest["capabilities"]["compiledRepairActions"]),
            len(manifest["capabilities"]["qualifiedRepairActions"]),
        )
        self.assertEqual(catalog["schema"], "dev.kernaid.rescue-repair-catalog-entry.v1")
        self.assertEqual(self.run_cli("verify").returncode, 0)

    def test_verify_rejects_evidence_tampering(self) -> None:
        self.create()
        self.batch.write_text("ready=true\n", encoding="ascii")
        result = self.run_cli("verify")
        self.assertEqual(result.returncode, 3)
        self.assertIn("exact scenario set", result.stderr)

    def test_create_rejects_diagnosis_only_names(self) -> None:
        stable = self.root / "KernAid-Rescue-amd64.iso"
        stable.write_bytes(self.iso.read_bytes())
        command = self.command("create")
        command[command.index(str(self.iso))] = str(stable)
        result = subprocess.run(
            command, check=False, capture_output=True, text=True, timeout=10
        )
        self.assertEqual(result.returncode, 3)
        self.assertIn("filename is not exact", result.stderr)

    def test_verify_rejects_catalog_mutation(self) -> None:
        self.create()
        document = json.loads(self.catalog.read_text(encoding="ascii"))
        document["diagnosisOnly"] = True
        self.catalog.write_text(
            json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="ascii",
        )
        result = self.run_cli("verify")
        self.assertEqual(result.returncode, 3)
        self.assertIn("catalog is not exact", result.stderr)


if __name__ == "__main__":
    unittest.main()
