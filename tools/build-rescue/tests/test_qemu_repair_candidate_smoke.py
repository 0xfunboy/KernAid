import importlib.util
import sys
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[3]
SCRIPT = REPO / "tools/build-rescue/qemu-repair-candidate-smoke.sh"
CONTROLLER = REPO / "tools/build-rescue/qemu-repair-candidate-pty.py"
WORKFLOW = REPO / ".github/workflows/rescue-repair-candidate.yml"

SPEC = importlib.util.spec_from_file_location("qemu_repair_candidate", CONTROLLER)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("unable to load repair candidate controller")
controller = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = controller
SPEC.loader.exec_module(controller)


class QemuRepairCandidateSmokeTests(unittest.TestCase):
    def test_gate_uses_only_two_explicit_disposable_qemu_backing_files(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('rescue_media="$work_dir/rescue-usb.raw"', source)
        self.assertIn('target_image="$work_dir/repair-target.raw"', source)
        self.assertIn("id=kernaid_rescue_usb,file=$rescue_media", source)
        self.assertIn("id=kernaid_repair_target,file=$target_image", source)
        self.assertIn(
            "virtio-blk-pci,drive=kernaid_repair_target,"
            "serial=KERNAID-REPAIR-V1",
            source,
        )
        self.assertEqual(source.count("serial=KERNAID-REPAIR-V1"), 1)
        self.assertIn("mkfs.ext4", source)
        self.assertIn('"$seed/usr"', source)
        self.assertIn("-return_with FAILURE 32", source)
        self.assertIn('[[ -f "$squashfs" && ! -L "$squashfs" ]]', source)
        for required in (
            'set_inode_field /etc uid 0',
            'set_inode_field /etc gid 0',
            'set_inode_field /etc mode 040755',
            'set_inode_field /etc/fstab uid 0',
            'set_inode_field /etc/fstab gid 0',
            'set_inode_field /etc/fstab mode 0100644',
        ):
            self.assertIn(required, source)
        self.assertIn("physical_parents=distinct", source)
        self.assertIn("host_physical_devices=false", source)
        self.assertNotIn("/dev/sd", source)
        self.assertNotIn("/dev/nvme", source)
        self.assertNotIn("losetup", source)

    def test_controller_drives_real_candidate_and_exact_typed_approval(self) -> None:
        source = CONTROLLER.read_text(encoding="utf-8")
        for required in (
            '"operation":"repair.fstab.prepare"',
            '"operation":"repair.fstab.approve"',
            "linux.fstab.disable-missing-uuid.v1",
            "DISABILITA VOCE FSTAB",
            'detail.get("beforeSha256")!=BEFORE',
            'detail.get("afterSha256")!=AFTER',
            '"vaultDistinct":True',
            'terminal_detail.get("terminalOutcome")!="committed"',
            '"target-capability-timed-out":"prepare-target-capability-timed-out"',
            '"target-capability-identity-changed":"prepare-target-capability-identity-changed"',
            '"target-capability-unavailable":"prepare-target-capability-unavailable"',
            '"prepare-target-capability-unavailable-unit-runtime-max"',
            '"prepare-target-capability-unavailable-unit-failed"',
            '"prepare-target-capability-unavailable-unit-collected"',
            '"prepare-target-capability-unavailable-unit-other"',
            '"observation-preview":"prepare-observation-preview"',
            '"vault-reserve":"prepare-vault-reserve"',
            '"admission-internal":"prepare-admission-internal"',
            '"--property=StatusText"',
            '"approval-proof","approval-binding","approval-admission",'
            '"approval-authorize","approval-cancel"',
        ):
            self.assertIn(required, source)
        self.assertTrue(
            {
                "execute-error-approval-proof",
                "execute-error-approval-binding",
                "execute-error-approval-admission",
                "execute-error-approval-authorize",
                "execute-error-approval-cancel",
                "execute-error-authority",
                "execute-error-target",
                "execute-error-lock",
                "execute-error-timeout",
                "execute-error-vault",
                "execute-error-write",
                "execute-error-mutation",
                "execute-error-recovery",
            }.issubset(controller.LIFECYCLE.PROVIDER_PROOF_REPAIR_CHECKPOINTS)
        )
        generated = controller.repair_source(
            "sha256:" + "a" * 64, "sha256:" + "b" * 64
        )
        self.assertLessEqual(len(generated), 16 * 1024)
        self.assertNotIn("mock", source.lower())

    def test_execute_failure_classifier_is_closed(self) -> None:
        namespace: dict[str, object] = {}
        exec(controller.EXECUTE_STATE_CLASSIFIER_SOURCE, namespace)
        classify = namespace["execute_state_checkpoint"]

        def terminal(state: str, outcome: str) -> dict[str, object]:
            return {
                "state": state,
                "detail": {
                    "kind": "terminal",
                    "terminalOutcome": outcome,
                    "reservationId": "B-" + "a" * 32,
                    "transactionBindingSha256": "sha256:" + "b" * 64,
                    "rebootRequired": state == "manual-reconciliation-required",
                    "prepareFailureStage": None,
                },
            }

        expected = {
            ("restored", "closed-before-unchanged"): "execute-state-closed-before-unchanged",
            ("restored", "closed-before-restored"): "execute-state-closed-before-restored",
            (
                "manual-reconciliation-required",
                "manual-reconciliation-required",
            ): "execute-state-manual-reconciliation-required",
        }
        for (state, outcome), checkpoint in expected.items():
            with self.subTest(checkpoint=checkpoint):
                self.assertEqual(classify(terminal(state, outcome)), checkpoint)

        failed = terminal("failed", "failed")
        failed["detail"]["reservationId"] = None
        failed["detail"]["transactionBindingSha256"] = None
        failed["detail"]["rebootRequired"] = False
        self.assertEqual(classify(failed), "execute-state-failed")

        invalid = terminal("restored", "closed-before-restored")
        invalid["detail"]["reservationId"] = "/dev/sda\nfuture-checkpoint"
        self.assertEqual(classify(invalid), "execute-state")
        self.assertNotIn("/dev/sda", classify(invalid))

        for checkpoint in set(expected.values()) | {"execute-state-failed"}:
            self.assertIn(checkpoint, controller.LIFECYCLE.PROVIDER_PROOF_REPAIR_CHECKPOINTS)

    def test_manual_candidate_workflow_runs_one_mutating_gate(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertEqual(
            workflow.count("./tools/build-rescue/qemu-repair-candidate-smoke.sh"),
            1,
        )
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('readonly qemu_smp="${KERNAID_QEMU_SMP:-2}"', source)
        self.assertIn('1|2|4|8)', source)
        self.assertIn('-smp "$qemu_smp"', source)
        self.assertIn("KERNAID_QEMU_SMP=4", workflow)

    def test_workflow_always_retains_private_forensics_without_promoting_failure(
        self,
    ) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        gate = workflow.index(
            "      - name: QEMU BIOS repair candidate apply qualification\n"
        )
        forensic_start = workflow.index(
            "      - name: Upload private repair candidate forensics\n"
        )
        promotable_start = workflow.index("      - name: Upload repair candidate ISO\n")
        self.assertLess(gate, forensic_start)
        self.assertLess(forensic_start, promotable_start)

        forensic = workflow[forensic_start:promotable_start]
        promotable = workflow[promotable_start:]
        expected_paths = (
            "            KernAid-Rescue-amd64-repair-candidate.iso\n"
            "            KernAid-Rescue-amd64-repair-candidate.iso.sha256\n"
        )
        self.assertIn("        if: ${{ always() }}\n", forensic)
        self.assertIn("          name: repair-candidate-forensics\n", forensic)
        self.assertIn(expected_paths, forensic)
        self.assertIn("          retention-days: 1\n", forensic)

        self.assertNotIn("        if: ${{ always() }}\n", promotable)
        self.assertIn(
            "          name: KernAid-Rescue-amd64-repair-candidate\n", promotable
        )
        self.assertIn(expected_paths, promotable)
        self.assertIn("          retention-days: 7\n", promotable)


if __name__ == "__main__":
    unittest.main()
