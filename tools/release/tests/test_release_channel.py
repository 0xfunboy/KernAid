from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


REPO_DIR = Path(__file__).resolve().parents[3]
SCRIPT = REPO_DIR / "tools/release/release_channel.py"
SCHEMA = REPO_DIR / "tools/release/release-channel.v1.schema.json"
WORKFLOW = REPO_DIR / ".github/workflows/release-channel.yml"
COMMIT = "0123456789abcdef0123456789abcdef01234567"


class ReleaseChannelTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.desk = self.root / "KernAid-Desk-linux-x86_64.AppImage"
        self.rescue = self.root / "KernAid-Rescue-amd64-qualified.zip"
        self.qualification = self.root / "KernAid-Rescue-amd64.qualified.json"
        self.retail = self.root / "KernAid-Rescue-amd64-retail.img.xz"
        self.desk.write_bytes(b"desk-package-v1\0" * 31)
        self.rescue.write_bytes(b"rescue-image-v1\0" * 37)
        self.qualification.write_bytes(b'{"qualified":true}\n')
        self.retail.write_bytes(b"compressed-retail-image-v1\0" * 29)
        self.descriptor = self.root / "descriptor.json"
        self.manifest = self.root / "channel.json"

    def artifact(
        self,
        *,
        component: str,
        platform: str,
        kind: str,
        path: Path,
        media_type: str,
        variant: str,
        version: str = "1.0.0",
    ) -> dict[str, object]:
        return {
            "architecture": "x86_64",
            "component": component,
            "kind": kind,
            "mediaType": media_type,
            "path": str(path),
            "platform": platform,
            "provenance": {
                "runAttempt": 1,
                "runId": 33000000001 if component == "desk" else 33000000002,
                "workflow": (
                    ".github/workflows/desktop.yml"
                    if component == "desk"
                    else ".github/workflows/rescue.yml"
                ),
            },
            "url": f"https://downloads.kernaid.dev/internal/{path.name}",
            "variant": variant,
            "version": version,
        }

    def descriptor_document(self) -> dict[str, object]:
        return {
            "artifacts": [
                self.artifact(
                    component="rescue",
                    platform="rescue",
                    kind="qualification",
                    path=self.qualification,
                    media_type="application/json",
                    variant="qualified-zip",
                ),
                self.artifact(
                    component="rescue",
                    platform="rescue",
                    kind="image",
                    path=self.retail,
                    media_type="application/x-xz",
                    variant="retail-img-xz",
                ),
                self.artifact(
                    component="desk",
                    platform="linux",
                    kind="package",
                    path=self.desk,
                    media_type="application/octet-stream",
                    variant="appimage",
                ),
                self.artifact(
                    component="rescue",
                    platform="rescue",
                    kind="image",
                    path=self.rescue,
                    media_type="application/zip",
                    variant="qualified-zip",
                ),
            ],
            "channel": "internal",
            "previous": None,
            "publishedAt": "2026-08-28T12:00:00Z",
            "schema": "dev.kernaid.release-channel-input.v1",
            "sequence": 1,
            "source": {"commit": COMMIT, "repository": "0xfunboy/KernAid"},
        }

    def write_descriptor(self, document: dict[str, object] | None = None) -> None:
        self.descriptor.write_text(
            json.dumps(document or self.descriptor_document()), encoding="utf-8"
        )

    def run_create(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                "-I",
                "-B",
                str(SCRIPT),
                "create",
                "--descriptor",
                str(self.descriptor),
                "--output",
                str(self.manifest),
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )

    def run_verify(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                "-I",
                "-B",
                str(SCRIPT),
                "verify",
                "--manifest",
                str(self.manifest),
                "--artifact-root",
                str(self.root),
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )

    def test_create_is_canonical_and_verify_rehashes_every_artifact(self) -> None:
        self.write_descriptor()
        created = self.run_create()
        self.assertEqual(created.returncode, 0, created.stderr)
        payload = self.manifest.read_bytes()
        document = json.loads(payload)
        self.assertEqual(
            payload,
            (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode(
                "ascii"
            ),
        )
        self.assertEqual(
            [artifact["component"] for artifact in document["artifacts"]],
            ["desk", "rescue", "rescue", "rescue"],
        )
        rescue = next(
            artifact
            for artifact in document["artifacts"]
            if artifact["kind"] == "image"
        )
        self.assertEqual(
            rescue["sha256"], hashlib.sha256(self.rescue.read_bytes()).hexdigest()
        )
        self.assertEqual(rescue["provenance"]["runId"], 33000000002)
        retail = next(
            artifact
            for artifact in document["artifacts"]
            if artifact["variant"] == "retail-img-xz"
        )
        self.assertEqual(retail["filename"], self.retail.name)
        verified = self.run_verify()
        self.assertEqual(verified.returncode, 0, verified.stderr)
        self.assertEqual(created.stdout, verified.stdout)

    def test_verify_refuses_noncanonical_json(self) -> None:
        self.write_descriptor()
        self.assertEqual(self.run_create().returncode, 0)
        document = json.loads(self.manifest.read_text(encoding="ascii"))
        self.manifest.write_text(json.dumps(document, indent=2) + "\n", encoding="ascii")
        result = self.run_verify()
        self.assertEqual(result.returncode, 3)
        self.assertIn("not exact and canonical", result.stderr)

    def test_verify_refuses_artifact_changed_after_publication(self) -> None:
        self.write_descriptor()
        self.assertEqual(self.run_create().returncode, 0)
        self.rescue.write_bytes(b"tampered-image-with-different-content")
        result = self.run_verify()
        self.assertEqual(result.returncode, 3)
        self.assertIn("does not match the manifest", result.stderr)

    def test_create_refuses_release_group_without_one_primary(self) -> None:
        document = self.descriptor_document()
        document["artifacts"] = [document["artifacts"][0]]  # type: ignore[index]
        self.write_descriptor(document)
        result = self.run_create()
        self.assertEqual(result.returncode, 3)
        self.assertIn("exactly one image", result.stderr)

    def test_create_refuses_gap_in_manifest_chain(self) -> None:
        document = self.descriptor_document()
        document["sequence"] = 3
        document["previous"] = {"sequence": 1, "sha256": "a" * 64}
        self.write_descriptor(document)
        result = self.run_create()
        self.assertEqual(result.returncode, 3)
        self.assertIn("immediately precede", result.stderr)

    def test_create_refuses_mixed_provenance_inside_release_group(self) -> None:
        document = self.descriptor_document()
        qualification = document["artifacts"][0]  # type: ignore[index]
        qualification["provenance"]["runAttempt"] = 2  # type: ignore[index]
        self.write_descriptor(document)
        result = self.run_create()
        self.assertEqual(result.returncode, 3)
        self.assertIn("one exact workflow run provenance", result.stderr)

    def test_same_desk_target_accepts_multiple_package_variants(self) -> None:
        deb = self.root / "kernaid-desk_1.0.0_amd64.deb"
        deb.write_bytes(b"desk-deb-v1\0" * 23)
        document = self.descriptor_document()
        document["artifacts"].append(  # type: ignore[union-attr]
            self.artifact(
                component="desk",
                platform="linux",
                kind="package",
                path=deb,
                media_type="application/vnd.debian.binary-package",
                variant="deb",
            )
        )
        self.write_descriptor(document)
        result = self.run_create()
        self.assertEqual(result.returncode, 0, result.stderr)
        manifest = json.loads(self.manifest.read_text(encoding="ascii"))
        self.assertEqual(
            [
                artifact["variant"]
                for artifact in manifest["artifacts"]
                if artifact["component"] == "desk"
            ],
            ["appimage", "deb"],
        )
        self.assertEqual(self.run_verify().returncode, 0)

    def test_create_refuses_wrong_json_type_without_traceback(self) -> None:
        document = self.descriptor_document()
        document["artifacts"][0]["component"] = []  # type: ignore[index]
        self.write_descriptor(document)
        result = self.run_create()
        self.assertEqual(result.returncode, 3)
        self.assertIn("component is unsupported", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_schema_is_strict_and_names_the_runtime_contract(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(
            schema["properties"]["schema"]["const"],
            "dev.kernaid.release-channel.v1",
        )
        self.assertFalse(schema["$defs"]["artifact"]["additionalProperties"])
        self.assertEqual(schema["$defs"]["artifact"]["properties"]["bytes"]["maximum"], 1_999_999_998)
        self.assertIn(
            "retail-img-xz", schema["$defs"]["artifact"]["properties"]["variant"]["enum"]
        )

    def test_publisher_splits_and_reverifies_the_retail_asset(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("KernAid-Rescue-amd64-qualified-retail", workflow)
        self.assertIn("KernAid-Rescue-amd64-retail.qualification.sigstore.json", workflow)
        self.assertIn('"variant": "retail-img-xz"', workflow)
        self.assertIn('"kind": "checksum"', workflow)
        self.assertIn('"variant": "qualified-iso"', workflow)
        self.assertIn("versioned ISO does not match its qualified checksum", workflow)
        self.assertIn("retail.img.xz.sha256", workflow)
        self.assertIn("versioned retail image does not match its qualified checksum", workflow)
        self.assertGreaterEqual(workflow.count("1_999_999_999"), 3)
        rename = workflow.index("os.rename(source, destination)")
        attest = workflow.index('gh attestation verify "$qualified/KernAid-Rescue-amd64-retail.img.xz"')
        manifest = workflow.index("qualification-manifest.py verify")
        self.assertLess(manifest, attest)
        self.assertLess(attest, rename)
        self.assertNotIn("os.link(qualified_output, release_output)", workflow)
        self.assertIn("moved.st_nlink != 1", workflow)

    def test_publisher_reverifies_native_prompt_evidence(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        archive_allowlist = workflow[
            workflow.index("          expected = {") : workflow.index(
                "          with zipfile.ZipFile(archive) as bundle:"
            )
        ]
        manifest_args = workflow[
            workflow.index("          manifest_args=(") : workflow.index(
                "          python3 -I -B tools/build-rescue/qualification-manifest.py verify"
            )
        ]
        evidence = "kernaid-native-vault-prompt.sanitized.log"
        self.assertIn(f'              "{evidence}",', archive_allowlist)
        self.assertIn(
            f'            --native-prompt-evidence "$qualified/{evidence}"',
            manifest_args,
        )


if __name__ == "__main__":
    unittest.main()
