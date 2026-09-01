from __future__ import annotations

import ast
from pathlib import Path
import unittest


REPO = Path(__file__).resolve().parents[3]
CANDIDATE = REPO / ".github/workflows/rescue-repair-candidate.yml"
PUBLISHER = REPO / ".github/workflows/release-channel-repair.yml"
QUALIFIER = REPO / "tools/build-rescue/repair-qualification.py"


class RepairPromotionStaticTests(unittest.TestCase):
    def test_candidate_qualifies_only_after_the_consolidated_repair_batch(self) -> None:
        workflow = CANDIDATE.read_text(encoding="utf-8")
        batch = workflow.index("QEMU consolidated repair candidate qualification")
        qualified = workflow.index("qualified-repair-release:")
        self.assertLess(batch, qualified)
        self.assertIn("needs: build-and-smoke-test", workflow[qualified:])
        self.assertIn("if: github.ref == 'refs/heads/main'", workflow[qualified:])
        self.assertIn("repair-qualification.py create", workflow[qualified:])
        self.assertIn("repair-qualification.py verify", workflow[qualified:])
        self.assertIn("--variant repair", workflow[qualified:])

    def test_candidate_emits_distinct_repair_artifacts_and_attestations(self) -> None:
        workflow = CANDIDATE.read_text(encoding="utf-8")
        qualified = workflow[workflow.index("qualified-repair-release:") :]
        self.assertIn("name: KernAid-Rescue-Repair-amd64-qualified", qualified)
        self.assertIn(
            "name: KernAid-Rescue-Repair-amd64-qualified-retail", qualified
        )
        self.assertIn(
            "https://kernaid.dev/attestations/rescue-repair-qualified-release/v1",
            qualified,
        )
        self.assertNotIn("KernAid-Rescue-amd64-qualified", qualified)
        self.assertNotIn("qualification-manifest.py", qualified)

    def test_qualifier_never_overclaims_compiled_actions(self) -> None:
        source = QUALIFIER.read_text(encoding="utf-8")
        assignments = {
            node.target.id: node.value
            for node in ast.parse(source).body
            if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name)
        }
        compiled = assignments.get("COMPILED_ACTIONS")
        self.assertIsInstance(compiled, ast.Tuple)
        self.assertEqual(
            ast.literal_eval(compiled),
            (
                "linux.crypttab.disable-missing-uuid.v1",
                "linux.ext4.fsck-preen-with-undo.v1",
                "linux.fstab.disable-missing-uuid.v1",
                "linux.network.restore-resolver-link.v1",
            ),
        )
        qualified = assignments.get("QUALIFIED_ACTIONS")
        self.assertIsInstance(qualified, ast.Name)
        self.assertEqual(qualified.id, "COMPILED_ACTIONS")
        self.assertIn('"physicalQualification": False', source)
        self.assertIn('"releaseClass": "engineering-candidate"', source)
        self.assertIn('"diagnosisOnly": False', source)
        self.assertIn('"repairEnabled": True', source)

    def test_publisher_is_an_isolated_anti_rollback_channel(self) -> None:
        workflow = PUBLISHER.read_text(encoding="utf-8")
        required = (
            "group: kernaid-repair-internal-release-channel",
            "CHANNEL: repair-internal",
            "kernaid-repair-internal-v",
            "previous Repair manifest digest does not match",
            "previous Repair manifest sequence is not contiguous",
            "previous tag is not the published Repair channel head",
            'release.get("immutable") is not True',
            '"variant": variant',
            '"workflow": ".github/workflows/rescue-repair-candidate.yml"',
            "repair-qualified-iso",
            "repair-qualified-zip",
            "repair-retail-img-xz",
        )
        for marker in required:
            self.assertIn(marker, workflow)
        self.assertNotIn("kernaid-internal-v", workflow)
        self.assertNotIn(".github/workflows/rescue.yml", workflow)
        self.assertNotIn("KernAid-Rescue-amd64-qualified", workflow)

    def test_publisher_reverifies_before_staging_or_manifest_creation(self) -> None:
        workflow = PUBLISHER.read_text(encoding="utf-8")
        verify = workflow.index("repair-qualification.py verify")
        attest = workflow.index("gh attestation verify", verify)
        stage = workflow.index('iso_release="$staging/', attest)
        channel = workflow.index("release_channel.py create", stage)
        publish = workflow.index('gh release create "$tag"', channel)
        self.assertLess(verify, attest)
        self.assertLess(attest, stage)
        self.assertLess(stage, channel)
        self.assertLess(channel, publish)


if __name__ == "__main__":
    unittest.main()
