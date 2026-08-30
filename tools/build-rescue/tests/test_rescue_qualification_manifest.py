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
        self.retail = self.root / "KernAid-Rescue-amd64-retail.img.xz"
        self.retail.write_bytes(b"fixture-compressed-retail")
        self.retail_digest = hashlib.sha256(self.retail.read_bytes()).hexdigest()
        self.retail_checksum = self.root / "KernAid-Rescue-amd64-retail.img.xz.sha256"
        self.retail_checksum.write_text(
            f"{self.retail_digest}  {self.retail.name}\n", encoding="ascii"
        )
        self.retail_metadata = self.root / "KernAid-Rescue-amd64-retail.json"
        self.retail_metadata.write_text(
            json.dumps({
                "compressed": {"bytes": self.retail.stat().st_size, "name": self.retail.name, "sha256": self.retail_digest},
                "isoPrefix": {"bytes": self.iso.stat().st_size, "sha256": self.iso_digest},
                "p3": {"bytes": 8_589_934_592, "sha256": "ebfb4ef19ae410f190327b5ebd312711263bc7579970e87d9c1e2d84e06b3c25", "startBytes": 17_179_869_184, "zero": True},
                "raw": {"bytes": 32_000_000_000, "name": "KernAid-Rescue-amd64-retail.img", "sha256": "1" * 64},
                "schema": "dev.kernaid.rescue-retail-image.v1", "tailZero": True,
            }), encoding="ascii"
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
        self.native_prompt = self.root / "kernaid-native-vault-prompt.sanitized.log"
        self.native_prompt.write_text(
            "KERNAID_QEMU_NATIVE_VAULT_PROMPT_ATTESTATION_V1 "
            "firmware=bios image=exact-usb boot1=provisioned "
            "boot2=direct-kernel-same-iso gate=vt-v1 socket=available "
            "broker=tauri-authenticated request=webview-tauri-enum-nonce "
            "prompt=tty8-ready-notify qmp-secret-input=true "
            "captured-secret-exposure=false journald-secret-exposure=false "
            "journald-scope=root-full-current-boot "
            "vault=unlocked device_id=KA-0123456789abcdef01234567 "
            f"iso_sha256={self.iso_digest} return=graphical-ui "
            "width=1024 height=768 iso-prefix-immutable=true "
            "acpi-shutdowns=2 ready=true\n",
            encoding="ascii",
        )

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
            "--retail-image",
            str(self.retail),
            "--retail-checksum",
            str(self.retail_checksum),
            "--retail-metadata",
            str(self.retail_metadata),
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
            "--native-prompt-evidence",
            str(self.native_prompt),
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
        self.assertEqual(
            document["evidence"]["nativeVaultPrompt"]["subjectIsoSha256"],
            self.iso_digest,
        )
        self.assertEqual(
            document["requiredJobs"],
            [
                "build-and-smoke-test",
                "native-vault-prompt-bios",
                "vault-lifecycle-bios",
                "vault-lifecycle-uefi",
            ],
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

    def test_create_refuses_native_prompt_evidence_for_another_iso(self) -> None:
        payload = self.native_prompt.read_text(encoding="ascii").replace(
            self.iso_digest, "f" * 64
        )
        self.native_prompt.write_text(payload, encoding="ascii")
        result = self.run_command(
            "create", self.root / "KernAid-Rescue-amd64.qualified.json"
        )
        self.assertEqual(result.returncode, 3)
        self.assertIn("does not bind the exact Rescue ISO", result.stderr)

    def test_create_refuses_claimed_zero_p3_with_wrong_digest(self) -> None:
        metadata = json.loads(self.retail_metadata.read_text(encoding="ascii"))
        metadata["p3"]["sha256"] = "0" * 64
        self.retail_metadata.write_text(json.dumps(metadata), encoding="ascii")
        result = self.run_command(
            "create", self.root / "KernAid-Rescue-amd64.qualified.json"
        )
        self.assertEqual(result.returncode, 3)
        self.assertIn("fixed image layout", result.stderr)


if __name__ == "__main__":
    unittest.main()
