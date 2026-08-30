import importlib.util
import signal
import sys
import tempfile
import time
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
        self.assertIn(
            "driver=file,node-name=kernaid_repair_target_file,"
            "filename=$target_image",
            source,
        )
        self.assertIn(
            "driver=raw,node-name=kernaid_repair_target,"
            "file=kernaid_repair_target_file",
            source,
        )
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
        self.assertIn("LIFECYCLE.ResponseShapeFailure", source)
        self.assertIn("sha256={failure.block_sha256}", source)
        self.assertNotIn("failure.block=", source)
        self.assertIn('console, "repair-initial", cursor, aggregate', source)
        self.assertIn('"status", "repair-initial-status", cursor, aggregate', source)
        self.assertIn(
            'initial.vault_state != "locked" or initial.device_id is not None',
            source,
        )
        self.assertIn(
            'console, "repair-recovery-initial", cursor, aggregate', source
        )
        self.assertIn('"repair-recovery-initial-status"', source)
        self.assertIn("recovery_initial.device_id is not None", source)
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
        self.assertIn(b'"execute-state-closed-before-unchanged",', generated)
        self.assertIn(b'"execute-state-closed-before-restored",', generated)
        self.assertIn(b'diagnostic.startswith("execute-error-")', generated)
        armed = controller.repair_source(
            "sha256:" + "a" * 64,
            "sha256:" + "b" * 64,
            interrupt_arm=True,
        )
        self.assertLessEqual(len(armed), 16 * 1024)
        self.assertIn(b"child=os.fork()", armed)
        self.assertIn(
            b"KERNAID_QEMU_PROVIDER_PROOF_V1 stage=\"+STAGE+\" result=true",
            armed,
        )
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

    def test_manual_candidate_workflow_runs_closed_firmware_matrix(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertEqual(
            workflow.count("./tools/build-rescue/qemu-repair-candidate-smoke.sh"),
            4,
        )
        self.assertIn("qemu-repair-candidate-smoke.sh bios apply", workflow)
        self.assertIn("qemu-repair-candidate-smoke.sh uefi apply", workflow)
        self.assertIn("qemu-repair-candidate-smoke.sh uefi rollback", workflow)
        self.assertIn("uefi interrupt-reconcile", workflow)
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('firmware="${1:-bios}"', source)
        self.assertIn('scenario="${2:-apply}"', source)
        self.assertIn("controller_timeout=1500", source)
        self.assertIn("controller_timeout=1800", source)
        self.assertIn('readonly qemu_smp="${KERNAID_QEMU_SMP:-2}"', source)
        self.assertIn('1|2|4|8)', source)
        self.assertIn('-smp "$qemu_smp"', source)
        self.assertIn("KERNAID_QEMU_SMP=4", workflow)

    def test_uefi_post_commit_rollback_uses_public_v2_and_restores_before(
        self,
    ) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        shell = SCRIPT.read_text(encoding="utf-8")
        source = CONTROLLER.read_text(encoding="utf-8")
        generated = controller.rollback_source(
            "sha256:" + "a" * 64, "sha256:" + "b" * 64
        )
        self.assertLessEqual(len(generated), 16 * 1024)
        compile(generated, "<rollback-source>", "exec")
        self.assertIn(b"deadline=time.monotonic()+840", generated)
        self.assertIn(
            b"KERNAID_QEMU_PROVIDER_PROOF_FAILURE_V1 stage=repair-rollback checkpoint=",
            generated,
        )
        for checkpoint in controller.LIFECYCLE.PROVIDER_PROOF_ROLLBACK_CHECKPOINTS:
            self.assertIn(checkpoint.encode("ascii"), generated)
        self.assertIn("timeout=900.0", CONTROLLER.read_text(encoding="utf-8"))

        for required in (
            'ROLLBACK_API="kernaid.dev/rescue-repair-service/v1alpha2"',
            'repair(ROLLBACK_API,"repair.fstab.rollback.status")',
            'repair(ROLLBACK_API,"repair.fstab.rollback.prepare",',
            'repair(ROLLBACK_API,"repair.fstab.rollback.approve",',
            'rollback.get("source")!=source_receipt',
            'rollback.get("resourceId")!=RESOURCE',
            'rollback.get("backupLocator")!="vault://repair/"+source_receipt',
            'rollback.get("risk")!="R2"',
            'rollback.get("confirmationRequired")!=ROLLBACK_CONFIRMATION',
            'rollback.get("nextApprovalSequence")!=apply_sequence+1',
            'while rollback_approval_id==apply_approval_id:',
            '"rollbackId":rollback["rollbackId"]',
            'result.get("terminalOutcome")!="rolled-back-original"',
            'rolled_back.get("state")!="restored"',
        ):
            self.assertIn(required.encode("ascii"), generated)

        self.assertIn(
            'parsed.scenario in {"rollback", "interrupt-reconcile"} '
            'and parsed.firmware != "uefi"',
            source,
        )
        self.assertIn('expected_fstab="$seed/etc/fstab"', shell)
        self.assertIn('cmp -s -- "$expected_fstab" "$observed_fstab"', shell)
        self.assertIn("KERNAID_REPAIR_TARGET_SENTINEL", shell)
        self.assertIn('[[ "$prefix_after_sha256" == "$iso_sha256" ]]', shell)
        self.assertEqual(workflow.count("uefi rollback"), 1)

    def test_interruption_witness_and_reconciliation_are_fail_closed(self) -> None:
        source = CONTROLLER.read_text(encoding="utf-8")
        for required in (
            '"query-blockstats", {"query-nodes": True}',
            "process.kill()",
            "process.poll() != -signal.SIGKILL",
            '"execute-state-closed-before-unchanged"',
            '"execute-state-closed-before-restored"',
            '"manual-reconciliation-required"',
            'parsed.scenario in {"rollback", "interrupt-reconcile"} '
            'and parsed.firmware != "uefi"',
            "OVMF_VARS.repair-boot-{boot}.fd",
        ):
            self.assertIn(required, source)
        self.assertNotIn('qmp.execute("stop")', source)
        self.assertNotIn('qmp.execute("cont")', source)
        self.assertNotIn("qmp.quit()", source)
        recovery = controller.reconcile_source()
        self.assertLessEqual(len(recovery), 16 * 1024)
        self.assertIn(b'candidate.get("state") in ("restored","succeeded"', recovery)
        self.assertIn(b"execute-state-closed-before-unchanged", recovery)
        self.assertIn(b"execute-state-closed-before-restored", recovery)

        class Qmp:
            def __init__(self, result: object) -> None:
                self.result = result

            def execute_result(self, command: str, arguments: object) -> object:
                self.command = command
                self.arguments = arguments
                return self.result

        qmp = Qmp(
            [
                {
                    "node-name": controller.TARGET_NODE,
                    "stats": {"wr_bytes": 4096},
                }
            ]
        )
        self.assertEqual(controller.target_write_bytes(qmp), 4096)
        self.assertEqual(qmp.command, "query-blockstats")
        self.assertEqual(qmp.arguments, {"query-nodes": True})

        for invalid in (
            [],
            [
                {
                    "node-name": controller.TARGET_NODE,
                    "stats": {"wr_bytes": True},
                }
            ],
            [
                {
                    "node-name": controller.TARGET_NODE,
                    "stats": {"wr_bytes": 1},
                },
                {
                    "node-name": controller.TARGET_NODE,
                    "stats": {"wr_bytes": 2},
                },
            ],
        ):
            with self.subTest(invalid=invalid):
                with self.assertRaises(controller.LIFECYCLE.ClosedFailure):
                    controller.target_write_bytes(Qmp(invalid))

        class Process:
            returncode: int | None = None

            def poll(self) -> int | None:
                return self.returncode

            def kill(self) -> None:
                self.returncode = -signal.SIGKILL

        process = Process()
        harness = type("Harness", (), {"process": process})()
        controller.hard_power_cut(harness, time.monotonic() + 1.0)
        self.assertEqual(process.returncode, -signal.SIGKILL)

    def test_uefi_uses_a_fresh_private_vars_store_per_boot(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            template = root / "template.fd"
            template.write_bytes(b"OVMF-VARS")
            qmp_socket = root / "qmp.sock"
            first = controller.qemu_args_for_boot(
                ("-machine", "accel=tcg"),
                "uefi",
                1,
                qmp_socket,
                Path("/firmware/code.fd"),
                template,
            )
            second = controller.qemu_args_for_boot(
                ("-machine", "accel=tcg"),
                "uefi",
                2,
                qmp_socket,
                Path("/firmware/code.fd"),
                template,
            )
            first_vars = root / "OVMF_VARS.repair-boot-1.fd"
            second_vars = root / "OVMF_VARS.repair-boot-2.fd"
            self.assertEqual(first_vars.read_bytes(), b"OVMF-VARS")
            self.assertEqual(second_vars.read_bytes(), b"OVMF-VARS")
            self.assertTrue(any(f"file={first_vars}" in item for item in first))
            self.assertTrue(any(f"file={second_vars}" in item for item in second))
            self.assertNotEqual(first_vars, second_vars)

    def test_workflow_always_retains_private_forensics_without_promoting_failure(
        self,
    ) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        gate = workflow.index(
            "      - name: QEMU UEFI repair candidate restart reconciliation "
            "qualification\n"
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
