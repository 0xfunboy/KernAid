import importlib.util
import os
import signal
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock


REPO = Path(__file__).resolve().parents[3]
SCRIPT = REPO / "tools/build-rescue/qemu-repair-candidate-smoke.sh"
CONTROLLER = REPO / "tools/build-rescue/qemu-repair-candidate-pty.py"
TAMPER = REPO / "tools/build-rescue/qemu-repair-vault-tamper.py"
WORKFLOW = REPO / ".github/workflows/rescue-repair-candidate.yml"

SPEC = importlib.util.spec_from_file_location("qemu_repair_candidate", CONTROLLER)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("unable to load repair candidate controller")
controller = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = controller
SPEC.loader.exec_module(controller)

TAMPER_SPEC = importlib.util.spec_from_file_location(
    "qemu_repair_vault_tamper", TAMPER
)
if TAMPER_SPEC is None or TAMPER_SPEC.loader is None:
    raise RuntimeError("unable to load repair Vault tamper helper")
tamper = importlib.util.module_from_spec(TAMPER_SPEC)
sys.modules[TAMPER_SPEC.name] = tamper
TAMPER_SPEC.loader.exec_module(tamper)


class QemuRepairCandidateSmokeTests(unittest.TestCase):
    def test_firstboot_confirmation_advances_past_passphrase_prompt(self) -> None:
        console = mock.Mock()
        qmp = mock.Mock()
        key = bytearray(b"0" * 64)
        passphrase_prompt = mock.Mock()
        passphrase_prompt.end.return_value = 37
        confirmation_prompt = mock.Mock()
        confirmation_prompt.end.return_value = 91

        with (
            mock.patch.object(
                controller.LIFECYCLE,
                "wait_firstboot_prompt",
                side_effect=[passphrase_prompt, confirmation_prompt],
            ) as firstboot_prompt,
            mock.patch.object(
                controller.LIFECYCLE, "wait_firstboot_attestation"
            ) as firstboot_attestation,
        ):
            controller.provision_firstboot(
                console,
                qmp,
                key,
                time.monotonic() + 1800.0,
            )

        self.assertEqual(
            firstboot_prompt.call_args_list[0].args[1:3],
            ("passphrase", 0),
        )
        self.assertEqual(
            firstboot_prompt.call_args_list[1].args[1:3],
            ("confirmation", 37),
        )
        self.assertEqual(firstboot_attestation.call_args.args[1], 91)
        self.assertEqual(
            qmp.send_hex_line.call_args_list,
            [mock.call(key), mock.call(key)],
        )

    @staticmethod
    def _receipt_transcript_console(return_code: int) -> object:
        begin = b"KERNAID_PROVIDER_PROOF_BEGIN_V1_repair-backup-tamper-apply"
        receipt = (
            b"KERNAID_QEMU_REPAIR_RECEIPT_V1 "
            b"reservation_id=B-" + b"a" * 32 + b" "
            b"binding=sha256:" + b"b" * 64
        )
        end = b"KERNAID_PROVIDER_PROOF_END_V1_repair-backup-tamper-apply"
        capture = controller.LIFECYCLE.BoundedCapture(4096, [])
        capture.append(
            begin
            + b"\r\n"
            + receipt
            + b"\r\n"
            + end
            + b" rc="
            + str(return_code).encode("ascii")
            + b"\r\n"
        )

        class TranscriptConsole:
            def __init__(self) -> None:
                self.capture = capture

            def send(self, value: bytes, *, deadline: float) -> None:
                del value, deadline

            def wait_regex(
                self,
                pattern: object,
                *,
                start: int,
                deadline: float,
                stage: str,
            ) -> object:
                del deadline
                match = pattern.search(self.capture.snapshot(), start)
                if match is None:
                    raise controller.LIFECYCLE.ClosedFailure(stage, "timeout")
                return match

        return TranscriptConsole()

    def test_receipt_end_marker_is_adjacent_and_exact(self) -> None:
        console = self._receipt_transcript_console(0)

        reservation_id, binding, cursor = controller.run_receipt_guest_proof(
            console,
            b"print('unused')",
            0,
            time.monotonic() + 456.0,
        )

        self.assertEqual(reservation_id, "B-" + "a" * 32)
        self.assertEqual(binding, "sha256:" + "b" * 64)
        self.assertEqual(cursor, len(console.capture.snapshot()))

    def test_receipt_end_marker_nonzero_return_code_fails_closed(self) -> None:
        console = self._receipt_transcript_console(1)

        with self.assertRaises(controller.LIFECYCLE.ClosedFailure) as observed:
            controller.run_receipt_guest_proof(
                console,
                b"print('unused')",
                0,
                time.monotonic() + 456.0,
            )

        self.assertEqual(observed.exception.stage, "receipt")
        self.assertEqual(observed.exception.code, "command-failed")

    def test_repair_unlock_recovers_only_via_fresh_exact_status(self) -> None:
        key = bytearray(b"0" * 64)
        capture = controller.LIFECYCLE.BoundedCapture(4096, [])
        capture.append(b"contaminated unlock transaction")
        console = mock.Mock(capture=capture)
        noise = controller.LIFECYCLE.ResponseShapeFailure(
            "version-invalid",
            b"[  12.000000] kernel notice\n"
            b"stateVersion: 12\n"
            b"vaultState: unlocked\n"
            b"deviceId: KA-0123456789abcdef01234567",
            0,
        )
        noise.stage = "repair-unlock"
        noise.code = "response-version-invalid"
        recovered = controller.LIFECYCLE.CompanionResponse(
            state_version=12,
            vault_state="unlocked",
            device_id="KA-0123456789abcdef01234567",
            error=None,
            return_code=0,
        )

        with mock.patch.object(
            controller.LIFECYCLE,
            "run_companion",
            side_effect=[noise, (recovered, 91)],
        ) as run:
            observed, cursor = controller.run_repair_unlock_companion(
                console, "repair", 7, time.monotonic() + 10, key
            )

        self.assertEqual(observed, recovered)
        self.assertEqual(cursor, 91)
        self.assertEqual(run.call_count, 2)
        self.assertEqual(
            run.call_args_list[0].args[1:4],
            ("unlock", "repair-unlock", 7),
        )
        self.assertEqual(
            run.call_args_list[1].args[1:4],
            ("status", "repair-unlock-recovery-status", len(capture)),
        )

    def test_repair_unlock_noise_recovery_remains_fail_closed(self) -> None:
        key = bytearray(b"0" * 64)
        capture = controller.LIFECYCLE.BoundedCapture(4096, [])
        capture.append(b"contaminated unlock transaction")
        console = mock.Mock(capture=capture)
        noise = controller.LIFECYCLE.ResponseShapeFailure(
            "version-invalid",
            b"[  12.000000] kernel notice\n"
            b"stateVersion: 12\n"
            b"vaultState: unlocked\n"
            b"deviceId: KA-0123456789abcdef01234567",
            0,
        )
        noise.stage = "repair-unlock"
        noise.code = "response-version-invalid"
        still_locked = controller.LIFECYCLE.CompanionResponse(
            state_version=10,
            vault_state="locked",
            device_id=None,
            error=None,
            return_code=0,
        )

        with mock.patch.object(
            controller.LIFECYCLE,
            "run_companion",
            side_effect=[noise, (still_locked, 91)],
        ):
            with self.assertRaises(controller.LIFECYCLE.ClosedFailure) as observed:
                controller.run_repair_unlock_companion(
                    console, "repair", 7, time.monotonic() + 10, key
                )

        self.assertEqual(observed.exception.stage, "repair-unlock")
        self.assertEqual(observed.exception.code, "noise-recovery-invalid")

        noise.return_code = 1
        with mock.patch.object(
            controller.LIFECYCLE,
            "run_companion",
            side_effect=noise,
        ) as run:
            with self.assertRaises(controller.LIFECYCLE.ResponseShapeFailure):
                controller.run_repair_unlock_companion(
                    console, "repair", 7, time.monotonic() + 10, key
                )
        self.assertEqual(run.call_count, 1)

    def test_repair_unlock_requires_exact_state_transition(self) -> None:
        key = bytearray(b"0" * 64)
        console = mock.Mock()
        initial = controller.LIFECYCLE.CompanionResponse(
            state_version=10,
            vault_state="locked",
            device_id=None,
            error=None,
            return_code=0,
        )

        for version, succeeds in ((12, True), (11, False)):
            unlocked = controller.LIFECYCLE.CompanionResponse(
                state_version=version,
                vault_state="unlocked",
                device_id="KA-0123456789abcdef01234567",
                error=None,
                return_code=0,
            )
            with self.subTest(version=version), mock.patch.object(
                controller.LIFECYCLE,
                "establish_live_session",
                return_value=3,
            ), mock.patch.object(
                controller.LIFECYCLE,
                "collect_runtime",
                return_value=(mock.Mock(), 5),
            ), mock.patch.object(
                controller.LIFECYCLE,
                "run_companion",
                return_value=(initial, 7),
            ), mock.patch.object(
                controller,
                "run_repair_unlock_companion",
                return_value=(unlocked, 9),
            ):
                if succeeds:
                    self.assertEqual(
                        controller.unlock_repair_vault(
                            console,
                            time.monotonic() + 10,
                            bytearray(b"login"),
                            key,
                            stage="repair",
                        ),
                        9,
                    )
                else:
                    with self.assertRaises(
                        controller.LIFECYCLE.ClosedFailure
                    ) as observed:
                        controller.unlock_repair_vault(
                            console,
                            time.monotonic() + 10,
                            bytearray(b"login"),
                            key,
                            stage="repair",
                        )
                    self.assertEqual(observed.exception.stage, "vault")
                    self.assertEqual(observed.exception.code, "unlock-invalid")

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
            "virtio-blk-pci,id=kernaid_repair_target_device,"
            "drive=kernaid_repair_target,"
            "serial=KERNAID-REPAIR-V1",
            source,
        )
        self.assertEqual(source.count("id=kernaid_repair_target_device"), 1)
        self.assertEqual(source.count("serial=KERNAID-REPAIR-V1"), 1)
        self.assertIn("mkfs.ext4", source)
        self.assertIn('"$seed/usr/lib/systemd/system"', source)
        self.assertIn("-return_with FAILURE 32", source)
        self.assertIn('[[ -f "$squashfs" && ! -L "$squashfs" ]]', source)
        for required in (
            'set_inode_field /etc uid 0',
            'set_inode_field /etc gid 0',
            'set_inode_field /etc mode 040755',
            'set_inode_field /etc/fstab uid 0',
            'set_inode_field /etc/fstab gid 0',
            'set_inode_field /etc/fstab mode 0100644',
            "for regular in /etc/crypttab "
            "/usr/lib/systemd/system/systemd-resolved.service",
            'set_inode_field $regular uid 0',
            'set_inode_field $regular gid 0',
            'set_inode_field $regular mode 0100644',
            "/etc/systemd/system/multi-user.target.wants",
        ):
            self.assertIn(required, source)
        self.assertIn("physical_parents=distinct", source)
        self.assertIn("host_physical_devices=false", source)
        self.assertNotIn("/dev/sd", source)
        self.assertNotIn("/dev/nvme", source)
        self.assertNotIn("losetup --", source)

    def test_controller_drives_real_candidate_and_exact_typed_approval(self) -> None:
        source = CONTROLLER.read_text(encoding="utf-8")
        self.assertIn("LIFECYCLE.ResponseShapeFailure", source)
        self.assertIn("sha256={failure.block_sha256}", source)
        self.assertNotIn("failure.block=", source)
        self.assertIn('console, f"{stage}-initial", cursor, aggregate', source)
        self.assertIn('"status", f"{stage}-initial-status", cursor, aggregate', source)
        self.assertIn(
            'initial.vault_state != "locked" or initial.device_id is not None',
            source,
        )
        self.assertIn('stage="repair-recovery"', source)
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
            1,
        )
        self.assertIn("uefi qualification-batch", workflow)
        source = SCRIPT.read_text(encoding="utf-8")
        controller_source = CONTROLLER.read_text(encoding="utf-8")
        self.assertIn('firmware="${1:-bios}"', source)
        self.assertIn('scenario="${2:-apply}"', source)
        for scenario in (
            "bios:apply",
            "uefi:apply",
            "uefi:rollback",
            "uefi:interrupt-reconcile",
            "uefi:stale-target",
            "uefi:cancel",
            "uefi:backup-tamper",
            "uefi:repaird-termination",
            "uefi:auto-restore",
            "uefi:crypttab-lifecycle",
            "uefi:ext4-apply",
            "uefi:resolver-link-apply",
        ):
            self.assertIn(scenario, source)
        self.assertIn("controller_timeout=1500", source)
        self.assertIn("controller_timeout=1800", source)
        self.assertIn("controller_timeout=1200", source)
        self.assertIn("controller_timeout=2100", source)
        self.assertIn('parsed.scenario == "provision-base"', controller_source)
        self.assertIn("timeout_maximum = 2100", controller_source)
        self.assertIn('readonly qemu_smp="${KERNAID_QEMU_SMP:-2}"', source)
        self.assertIn('1|2|4|8)', source)
        self.assertIn('-smp "$qemu_smp"', source)
        self.assertNotIn("KERNAID_QEMU_SMP=4", workflow)
        self.assertEqual(workflow.count("KERNAID_QEMU_SMP=2"), 1)
        self.assertIn(
            "KERNAID_QEMU_REPAIR_QUALIFICATION_BATCH_ATTESTATION_V1",
            source,
        )
        self.assertIn(
            "actions=linux.fstab.disable-missing-uuid.v1,"
            "linux.crypttab.disable-missing-uuid.v1,"
            "linux.ext4.fsck-preen-with-undo.v1,"
            "linux.network.restore-resolver-link.v1",
            source,
        )

    def test_repair_shutdown_keeps_a_bounded_tcg_safe_budget(self) -> None:
        source = CONTROLLER.read_text(encoding="utf-8")
        self.assertEqual(controller.REPAIR_ACPI_SHUTDOWN_SECONDS, 300.0)
        self.assertEqual(
            controller.REPAIR_FIRSTBOOT_RESULT_TIMEOUT_SECONDS,
            1800.0,
        )
        self.assertEqual(source.count("REPAIR_ACPI_SHUTDOWN_SECONDS)"), 8)
        self.assertNotIn(
            "wait_for_shutdown(LIFECYCLE._deadline(aggregate, 180.0))", source
        )

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
        self.assertNotIn(b"def http(", generated)
        self.assertNotIn(b"=http(", generated)
        self.assertIn(b"def call(path,body=None,timeout=25):", generated)
        self.assertIn(
            b'selected_code,selected=call("/api/rescue/select-installed-target",selection)',
            generated,
        )
        self.assertIn(
            b'inspected_code,inspected=call("/api/rescue/inspect-installed-target",selection)',
            generated,
        )
        self.assertIn(b"deadline=time.monotonic()+840", generated)
        self.assertIn(
            b"KERNAID_QEMU_PROVIDER_PROOF_FAILURE_V1 stage=repair-rollback checkpoint=",
            generated,
        )
        service_ready_checkpoints = {
            "service-ready-internal",
            "service-ready-transport",
            "service-ready-http",
            "service-ready-response-invalid",
            "service-ready-non-idle",
        }
        self.assertTrue(
            service_ready_checkpoints.issubset(
                controller.LIFECYCLE.PROVIDER_PROOF_ROLLBACK_CHECKPOINTS
            )
        )
        for checkpoint in controller.LIFECYCLE.PROVIDER_PROOF_ROLLBACK_CHECKPOINTS:
            self.assertIn(checkpoint.encode("ascii"), generated)
        self.assertIn(
            b'except BaseException:\n        return "service-ready-internal"',
            generated,
        )
        self.assertIn(
            b'except (OSError,http.client.HTTPException):\n        return "service-ready-transport"',
            generated,
        )
        self.assertIn(b'if status!=200:\n        return "service-ready-http"', generated)
        self.assertIn(
            b'if not valid_response(value,APPLY_API,"repair.status",request):\n        return "service-ready-response-invalid"',
            generated,
        )
        self.assertIn(
            b'if value["state"]=="idle":\n        return None\n    return "service-ready-non-idle"',
            generated,
        )
        self.assertIn(
            b'checkpoint="service-ready-internal"\n        service_ready_checkpoint=service_ready()',
            generated,
        )
        self.assertIn(
            b"checkpoint=service_ready_checkpoint\n        if time.monotonic()>=deadline:",
            generated,
        )
        self.assertIn("timeout=900.0", CONTROLLER.read_text(encoding="utf-8"))

        for required in (
            'ROLLBACK_API="kernaid.dev/rescue-repair-service/v1alpha2"',
            'repair(ROLLBACK_API,"repair.fstab.rollback.status")',
            'repair(ROLLBACK_API,"repair.fstab.rollback.prepare",',
            '{"prepared","succeeded","failed","restored","manual-reconciliation-required"}',
            'if rollback_prepared.get("state")=="succeeded":',
            'checkpoint=rollback_prepare_failure_checkpoint()',
            'KERNAID_RESCUE_REPAIR_EXECUTION_FAILURE_V1 stage=',
            'ROLLBACK_FAILURE_STAGES=("authority","target","lock","timeout","vault","recovery")',
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

        self.assertIn('"interrupt-reconcile",', source)
        self.assertIn("*PACK_QUALIFICATION_SCENARIOS", source)
        self.assertIn('"scenario-firmware-invalid"', source)
        self.assertIn('expected_fstab="$seed/etc/fstab"', shell)
        self.assertIn('cmp -s -- "$expected_fstab" "$observed_fstab"', shell)
        self.assertIn("KERNAID_REPAIR_TARGET_SENTINEL", shell)
        self.assertIn('[[ "$prefix_after_sha256" == "$iso_sha256" ]]', shell)
        self.assertEqual(shell.count("uefi:rollback"), 1)

    def test_interruption_witness_and_reconciliation_are_fail_closed(self) -> None:
        source = CONTROLLER.read_text(encoding="utf-8")
        for required in (
            'qmp.execute_result("query-blockstats")',
            'TARGET_NODE = "kernaid_repair_target"',
            'TARGET_QDEV = "/machine/peripheral/kernaid_repair_target_device/virtio-backend"',
            "process.kill()",
            "process.poll() != -signal.SIGKILL",
            '"execute-state-closed-before-unchanged"',
            '"execute-state-closed-before-restored"',
            '"manual-reconciliation-required"',
            '"interrupt-reconcile",',
            "*PACK_QUALIFICATION_SCENARIOS",
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
                self.deadlines: list[float] = []

            def set_deadline(self, deadline: float) -> None:
                self.deadlines.append(deadline)

            def execute_result(
                self, command: str, arguments: object = None
            ) -> object:
                self.command = command
                self.arguments = arguments
                return self.result

        qmp = Qmp(
            [
                {
                    "device": "",
                    "node-name": controller.TARGET_NODE,
                    "qdev": controller.TARGET_QDEV,
                    "stats": {
                        "wr_bytes": 4096,
                        "wr_operations": 1,
                        "failed_wr_operations": 0,
                        "invalid_wr_operations": 0,
                    },
                    "parent": {
                        "node-name": "kernaid_repair_target_file",
                        "stats": {"wr_bytes": 0, "wr_operations": 0},
                    },
                },
            ]
        )
        self.assertEqual(controller.target_write_bytes(qmp), 4096)
        self.assertEqual(qmp.command, "query-blockstats")
        self.assertIsNone(qmp.arguments)

        for invalid in (
            [],
            [
                {
                    "device": "",
                    "node-name": controller.TARGET_NODE,
                    "qdev": "wrong",
                    "stats": {
                        "wr_bytes": 1,
                        "wr_operations": 1,
                        "failed_wr_operations": 0,
                        "invalid_wr_operations": 0,
                    },
                },
            ],
            [
                {
                    "device": "",
                    "node-name": controller.TARGET_NODE,
                    "qdev": controller.TARGET_QDEV,
                    "stats": {
                        "wr_bytes": True,
                        "wr_operations": 1,
                        "failed_wr_operations": 0,
                        "invalid_wr_operations": 0,
                    },
                },
            ],
            [
                {
                    "device": "",
                    "node-name": controller.TARGET_NODE,
                    "qdev": controller.TARGET_QDEV,
                    "stats": {
                        "wr_bytes": 1,
                        "wr_operations": 0,
                        "failed_wr_operations": 0,
                        "invalid_wr_operations": 0,
                    },
                },
            ],
            [
                {
                    "device": "",
                    "node-name": controller.TARGET_NODE,
                    "qdev": controller.TARGET_QDEV,
                    "stats": {
                        "wr_bytes": 1,
                        "wr_operations": 1,
                        "failed_wr_operations": 1,
                        "invalid_wr_operations": 0,
                    },
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

        clock = [0.0]
        sleeps: list[float] = []
        zero = Qmp(
            [
                {
                    "device": "",
                    "node-name": controller.TARGET_NODE,
                    "qdev": controller.TARGET_QDEV,
                    "stats": {
                        "wr_bytes": 0,
                        "wr_operations": 0,
                        "failed_wr_operations": 0,
                        "invalid_wr_operations": 0,
                    },
                },
            ]
        )

        def cross_witness_deadline(seconds: float) -> None:
            sleeps.append(seconds)
            clock[0] = 180.0

        with mock.patch.object(
            controller.time, "monotonic", side_effect=lambda: clock[0]
        ), mock.patch.object(
            controller.time, "sleep", side_effect=cross_witness_deadline
        ):
            with self.assertRaises(controller.LIFECYCLE.ClosedFailure) as observed:
                controller.interrupt_after_first_target_write(
                    mock.Mock(), zero, 1000.0
                )
        self.assertEqual(observed.exception.stage, "interruption")
        self.assertEqual(observed.exception.code, "target-write-timeout")
        self.assertEqual(sleeps, [0.1])
        self.assertEqual(zero.deadlines, [10.0])

    def test_failure_path_suite_reuses_one_provisioned_base_and_is_closed(self) -> None:
        shell = SCRIPT.read_text(encoding="utf-8")
        source = CONTROLLER.read_text(encoding="utf-8")
        workflow = WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("scenario=provision-base", shell)
        self.assertIn("cp --reflink=auto --sparse=always", shell)
        self.assertIn('controller_args+=(--already-provisioned)', shell)
        self.assertEqual(workflow.count("uefi qualification-batch"), 1)
        self.assertEqual(shell.count("uefi:stale-target"), 1)
        for scenario in controller.FAILURE_SCENARIOS:
            self.assertIn(scenario, shell)
        self.assertIn(
            "KERNAID_QEMU_REPAIR_FAILURE_PATHS_ATTESTATION_V1", shell
        )
        self.assertIn(
            "KERNAID_QEMU_REPAIR_FAILURE_CASE_V1 scenario=%s", shell
        )
        self.assertIn("isolated_sparse_copies=true", shell)
        self.assertIn("iso_sha256=$iso_sha256", shell)
        self.assertIn("target_raw_immutable=true", shell)
        self.assertIn("metadata=mode-uid-gid-no-xattrs", shell)
        self.assertIn(
            "kernaid-(fstab|crypttab|resolv\\.conf)-(stage|restore)-v1",
            shell,
        )
        self.assertIn("realpath -e --", shell)
        self.assertIn("stat -c '%h'", shell)
        self.assertIn('if target_write_bytes(qmp) != 0:', source)
        self.assertIn('elif writes != 0:', source)

    def test_all_compiled_repair_packs_have_closed_exact_image_proofs(self) -> None:
        shell = SCRIPT.read_text(encoding="utf-8")
        self.assertEqual(
            controller.PACK_QUALIFICATION_SCENARIOS,
            ("crypttab-lifecycle", "ext4-apply", "resolver-link-apply"),
        )
        expected = {
            "crypttab-lifecycle": (
                b"repair.crypttab.prepare",
                b"repair.crypttab.approve",
                b"linux.crypttab.disable-missing-uuid.v1",
                b"rescue:selected-linux-root:etc/crypttab",
                b"DISABILITA VOCE CRYPTTAB",
            ),
            "ext4-apply": (
                b"repair.ext4.prepare",
                b"repair.ext4.approve",
                b"linux.ext4.fsck-preen-with-undo.v1",
                b"rescue:selected-linux-filesystem:ext4",
                b"REPAIR EXT4 OFFLINE",
            ),
            "resolver-link-apply": (
                b"repair.resolver-link.prepare",
                b"repair.resolver-link.approve",
                b"linux.network.restore-resolver-link.v1",
                b"rescue:selected-linux-root:etc/resolver-link",
                b"RESTORE RESOLVER LINK",
            ),
        }
        for scenario, tokens in expected.items():
            with self.subTest(scenario=scenario):
                generated = controller.pack_qualification_source(
                    scenario,
                    "sha256:" + "a" * 64,
                    "sha256:" + "b" * 64,
                )
                self.assertLessEqual(len(generated), 16 * 1024)
                compile(generated, f"<{scenario}>", "exec")
                for token in tokens:
                    self.assertIn(token, generated)
                self.assertIn(b"prepared_keys={", generated)
                self.assertIn(b"deadline=time.monotonic()+600", generated)
                self.assertIn(b'"approvalSequence":detail["nextApprovalSequence"]', generated)
                self.assertIn(b'"typedConfirmation":CONFIRMATION', generated)
                self.assertNotIn(b"/dev/", generated)
                self.assertNotIn(b"subprocess", generated)

        crypttab = controller.pack_qualification_source(
            "crypttab-lifecycle",
            "sha256:" + "a" * 64,
            "sha256:" + "b" * 64,
        )
        self.assertIn(b"repair.crypttab.rollback.prepare", crypttab)
        self.assertIn(b"repair.crypttab.rollback.approve", crypttab)
        self.assertIn(b"RIPRISTINA CRYPTTAB ORIGINALE", crypttab)
        self.assertIn(b"while rollback_approval==apply_approval", crypttab)

        for required in (
            "KERNAID_EXT4_REPAIR_MARKER",
            'debugfs -w -R "clri <$ext4_marker_inode>"',
            'e2fsck -f -n "$target_image"',
            "ext4_preflight_status\" -eq 4",
            "ext4_postcheck_status\" -eq 0",
            "resolver-link-state:v1:missing",
            "resolver-link-state:v1:resolved-stub-relative",
            'Fast link dest: \"../run/systemd/resolve/stub-resolv.conf\"',
            "kernaid-(fstab|crypttab|resolv\\.conf)-(stage|restore)-v1",
        ):
            self.assertIn(required, shell)

    def test_candidate_only_fault_credentials_are_fixed_and_scenario_bound(self) -> None:
        shell = SCRIPT.read_text(encoding="utf-8")
        source = CONTROLLER.read_text(encoding="utf-8")
        self.assertEqual(
            controller.FAULT_CREDENTIAL, "kernaid-repair-fault"
        )
        fw_cfg_name = f"opt/io.systemd.credentials/{controller.FAULT_CREDENTIAL}"
        self.assertLessEqual(len(fw_cfg_name.encode("ascii")) + 1, 56)
        self.assertEqual(
            controller.FAULT_TERMINATE_AFTER_PENDING,
            "terminate-after-pending-v1",
        )
        self.assertEqual(
            controller.FAULT_FAIL_AFTER_INSTALLED, "fail-after-installed-v1"
        )
        self.assertIn('fault != expected_fault', source)
        self.assertIn("fault-credential-mismatch", source)
        self.assertIn("os.O_NOFOLLOW", source)
        self.assertIn("identity(before) != identity(after)", source)
        self.assertEqual(
            shell.count(
                "name=opt/io.systemd.credentials/"
                "kernaid-repair-fault,file="
            ),
            1,
        )

        with tempfile.TemporaryDirectory() as temporary:
            work_directory = Path(temporary)
            credential = work_directory / "qualification-fault"
            credential.write_bytes(
                controller.FAULT_TERMINATE_AFTER_PENDING.encode("ascii")
            )
            credential.chmod(0o600)
            specification = (
                "name=opt/io.systemd.credentials/"
                f"{controller.FAULT_CREDENTIAL},file={credential}"
            )
            self.assertEqual(
                controller.qualification_fault(
                    ("-fw_cfg", specification), work_directory
                ),
                controller.FAULT_TERMINATE_AFTER_PENDING,
            )
            for rejected in (
                ("-fw_cfg", specification, "-fw_cfg", specification),
                (
                    "-fw_cfg",
                    "name=opt/io.systemd.credentials/"
                    f"{controller.FAULT_CREDENTIAL},string=none-v1",
                ),
            ):
                with self.assertRaises(controller.LIFECYCLE.ClosedFailure):
                    controller.qualification_fault(rejected, work_directory)

        for scenario in (
            "stale-target",
            "cancel",
            "repaird-termination",
            "auto-restore",
        ):
            generated = controller.failure_path_source(
                scenario, "sha256:" + "a" * 64, "sha256:" + "b" * 64
            )
            self.assertLessEqual(len(generated), 16 * 1024)
            compile(generated, f"<{scenario}>", "exec")
        self.assertIn(
            b'new_pid==old_pid or not terminal(approved,"restored","closed-before-unchanged",True)',
            controller.failure_path_source(
                "repaird-termination",
                "sha256:" + "a" * 64,
                "sha256:" + "b" * 64,
            ),
        )
        termination = controller.failure_path_source(
            "repaird-termination",
            "sha256:" + "a" * 64,
            "sha256:" + "b" * 64,
        )
        self.assertIn(b"old_pid=repaird_pid()", termination)
        self.assertIn(b"new_pid=repaird_pid()", termination)
        self.assertIn(
            b'not terminal(approved,"restored","closed-before-restored",True)',
            controller.failure_path_source(
                "auto-restore",
                "sha256:" + "a" * 64,
                "sha256:" + "b" * 64,
            ),
        )

    def test_backup_tamper_handoff_is_bounded_and_never_mounted(self) -> None:
        source = CONTROLLER.read_text(encoding="utf-8")
        helper = TAMPER.read_text(encoding="utf-8")
        receipt = controller.repair_source(
            "sha256:" + "a" * 64,
            "sha256:" + "b" * 64,
            emit_receipt=True,
        )
        self.assertLessEqual(len(receipt), 16 * 1024)
        self.assertIn(b"KERNAID_QEMU_REPAIR_RECEIPT_V1", receipt)
        tampered = controller.tampered_backup_source(
            "B-" + "c" * 32, "sha256:" + "d" * 64
        )
        self.assertLessEqual(len(tampered), 16 * 1024)
        compile(tampered, "<backup-tamper>", "exec")
        self.assertIn(b'"error":"relay-unavailable"', tampered)
        self.assertIn(b"allow_recovery_closed=True", tampered)
        self.assertIn(b'initial.get("state")!="idle"', tampered)
        self.assertIn(b'result.get("state")!="idle"', tampered)
        self.assertIn('"/usr/bin/sudo",', source)
        self.assertIn('"-n",', source)
        self.assertIn("if remaining < 185.0:", source)
        self.assertIn("timeout = min(180.0, remaining - 5.0)", source)
        self.assertNotIn("key_file_bytes", source)
        self.assertNotIn("vault_key_path.read_bytes", source)
        self.assertIn("set_inode_field {backup} size 1", helper)
        self.assertIn("names != [expected]", helper)
        self.assertIn('command("blockdev")', helper)
        self.assertIn("os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW", helper)
        self.assertIn("dir_fd=parent_fd", helper)
        self.assertIn('MEDIA_NAME = "rescue-usb.raw"', helper)
        self.assertIn('KEY_NAME = "vault-key"', helper)
        self.assertIn("pass_fds=(media_fd,)", helper)
        self.assertIn("pass_fds=(key_fd,)", helper)
        self.assertIn('return f"/proc/self/fd/{descriptor}"', helper)
        self.assertIn("value[:] = b\"\\x00\" * len(value)", helper)
        self.assertIn("LOOP_GET_STATUS64", helper)
        self.assertIn("--nooverlap", helper)
        self.assertIn("baseline_loops = correlated_loop_devices", helper)
        self.assertIn("observed_loops - baseline_loops", helper)
        self.assertIn("correlated_loop_devices(media_metadata) - baseline_loops", helper)
        self.assertIn("mapper in kernel_mapper_names()", helper)
        self.assertIn("TOTAL_CLEANUP_SECONDS", helper)
        self.assertIn("if len(buffer) > OUTPUT_LIMIT_BYTES", helper)
        self.assertIn("mapper_owned = not mapper_baseline", helper)
        self.assertIn("if mapper_owned and mapper_still_open", helper)
        self.assertLess(
            helper.rindex("close_mapper_bounded("),
            helper.rindex("for loop in sorted(owned_loops)"),
        )
        self.assertNotIn('command("sync")', helper)
        self.assertNotIn('command("mount")', helper)
        self.assertNotIn('command("umount")', helper)

    def test_backup_tamper_failure_diagnostics_are_closed(self) -> None:
        expected = {
            "arguments-invalid",
            "backup-invalid",
            "caller-invalid",
            "cleanup-failed",
            "input-invalid",
            "key-invalid",
            "loop-collision",
            "loop-discovery-failed",
            "loop-invalid",
            "mapper-collision",
            "mapper-discovery-failed",
            "mapper-open-failed",
            "tamper-unverified",
            "tool-failed",
            "tool-missing",
            "unexpected",
        }
        self.assertEqual(tamper.PUBLIC_FAILURE_CODES, expected)
        self.assertEqual(controller.TAMPER_HELPER_FAILURE_CODES, expected)
        for code in sorted(expected):
            with self.subTest(code=code):
                stderr = (
                    "KERNAID_QEMU_REPAIR_VAULT_TAMPER_FAILURE_V1 "
                    f"code={code}\n"
                ).encode("ascii")
                self.assertEqual(
                    controller.tamper_helper_failure_code(1, b"", stderr),
                    f"helper-failed-{code}",
                )

        primary = tamper.ClosedFailure("backup-invalid")
        self.assertEqual(
            tamper.public_failure_code(primary, cleanup_failed=False),
            "backup-invalid",
        )
        self.assertEqual(
            tamper.public_failure_code(primary, cleanup_failed=True),
            "cleanup-failed",
        )
        self.assertEqual(
            tamper.public_failure_code(RuntimeError("secret"), cleanup_failed=False),
            "unexpected",
        )

    def test_backup_tamper_failure_diagnostics_reject_untrusted_bytes(self) -> None:
        generic = "helper-failed"
        valid = (
            b"KERNAID_QEMU_REPAIR_VAULT_TAMPER_FAILURE_V1 "
            b"code=backup-invalid\n"
        )
        rejected = (
            (2, b"", valid),
            (0, b"", valid),
            (1, b"unexpected", valid),
            (1, b"", valid.rstrip(b"\n")),
            (1, b"", valid.replace(b"\n", b"\r\n")),
            (1, b"", valid + b"secret\n"),
            (
                1,
                b"",
                b"KERNAID_QEMU_REPAIR_VAULT_TAMPER_FAILURE_V1 "
                b"code=/tmp/secret\n",
            ),
        )
        for returncode, stdout, stderr in rejected:
            with self.subTest(returncode=returncode, stdout=stdout, stderr=stderr):
                self.assertEqual(
                    controller.tamper_helper_failure_code(
                        returncode, stdout, stderr
                    ),
                    generic,
                )

    def test_backup_tamper_inputs_are_descriptor_pinned(self) -> None:
        suffix = (os.getpid() ^ time.time_ns()) & 0xFFFFFFFF
        root = Path("/tmp") / f"kernaid-qemu-repair-candidate.{suffix:08x}"
        root.mkdir(mode=0o700)
        media = root / tamper.MEDIA_NAME
        key = root / tamper.KEY_NAME
        replacement = root / "replacement"
        media_fd = key_fd = -1
        try:
            media.touch(mode=0o600)
            media.chmod(0o600)
            os.truncate(media, tamper.MEDIA_BYTES)
            key.write_bytes(b"a" * 64)
            key.chmod(0o600)
            media_fd, key_fd = tamper.open_qualification_inputs(
                media, key, owner=os.geteuid()
            )
            tamper.validate_key(key_fd)
            pinned = os.fstat(media_fd)

            replacement.touch(mode=0o600)
            replacement.chmod(0o600)
            os.truncate(replacement, tamper.MEDIA_BYTES)
            os.replace(replacement, media)
            named = media.stat()
            self.assertNotEqual(
                (pinned.st_dev, pinned.st_ino), (named.st_dev, named.st_ino)
            )
            self.assertEqual(
                os.stat(tamper.proc_fd(media_fd)).st_ino, pinned.st_ino
            )

            wrong_key = root / "not-vault-key"
            wrong_key.write_bytes(b"a" * 64)
            wrong_key.chmod(0o600)
            with self.assertRaises(tamper.ClosedFailure):
                tamper.open_qualification_inputs(
                    media, wrong_key, owner=os.geteuid()
                )
        finally:
            for descriptor in (key_fd, media_fd):
                if descriptor >= 0:
                    os.close(descriptor)
            shutil.rmtree(root)

    def test_backup_tamper_decodes_kernel_loop_device_numbers(self) -> None:
        device = os.makedev(252, 0x12345)
        huge_encoded = 0x45 | (252 << 8) | (0x12300 << 12)
        self.assertTrue(tamper.huge_device_matches(huge_encoded, device))
        self.assertFalse(tamper.huge_device_matches(huge_encoded + 1, device))
        self.assertEqual(tamper.LOOP_INFO64.size, 232)

    def test_backup_tamper_targets_the_isolated_vault_root_namespace(self) -> None:
        self.assertEqual(
            tamper.BACKUP_DIRECTORY,
            "/.kernaid-repair-store-v1/backups",
        )
        self.assertNotIn(".kernaid-secure-state-v1", tamper.BACKUP_DIRECTORY)

    def test_backup_tamper_parses_canonical_debugfs_inode_sizes(self) -> None:
        ubuntu_2404 = (
            b"Inode: 15   Type: regular    Mode:  0644\n"
            b"User:     0   Group:     0   Project:     0   Size: 4096\n"
            b"Fragment:  Address: 0    Number: 0    Size: 0\n"
        )
        legacy = b"Inode: 15   Type: regular\nSize: 1\nFile ACL: 0\n"
        self.assertEqual(tamper.parse_debugfs_inode_size(ubuntu_2404), 4096)
        self.assertEqual(tamper.parse_debugfs_inode_size(legacy), 1)

    def test_backup_tamper_rejects_ambiguous_debugfs_inode_sizes(self) -> None:
        fragment_only = b"Fragment: Address: 0 Number: 0 Size: 4096\n"
        conflicting = b"Size: 4096\nSize: 1\n"
        for output in (fragment_only, conflicting, b"Size: 1 trailing\n"):
            with self.subTest(output=output):
                with self.assertRaises(tamper.ClosedFailure):
                    tamper.parse_debugfs_inode_size(output)

    def test_backup_tamper_waits_past_loop_autoclear(self) -> None:
        loop = "/dev/loop7"
        with (
            mock.patch.object(
                tamper,
                "correlated_loop_devices",
                side_effect=({loop}, {loop}, set()),
            ),
            mock.patch.object(tamper, "command", return_value="/usr/sbin/losetup"),
            mock.patch.object(tamper, "run", return_value=b"") as invoked,
        ):
            self.assertTrue(
                tamper.detach_loop_bounded(loop, object(), time.monotonic() + 1.0)
            )
        invoked.assert_called_once_with(
            ["/usr/sbin/losetup", "--detach", loop],
            timeout=mock.ANY,
        )

    def test_backup_tamper_detects_mapper_without_udev_node(self) -> None:
        mapper = "kernaid-repair-tamper-123"
        with (
            mock.patch.object(tamper.os.path, "lexists", return_value=False),
            mock.patch.object(
                tamper, "kernel_mapper_names", return_value={mapper}
            ),
        ):
            self.assertTrue(
                tamper.mapper_exists(mapper, f"/dev/mapper/{mapper}")
            )

    def test_backup_tamper_caps_child_output_while_running(self) -> None:
        source = (
            "import sys;"
            "sys.stdout.buffer.write(b'x'*70000);"
            "sys.stdout.buffer.flush()"
        )
        started = time.monotonic()
        with self.assertRaises(tamper.ClosedFailure):
            tamper.run([sys.executable, "-I", "-B", "-c", source], timeout=2.0)
        self.assertLess(time.monotonic() - started, 2.5)

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
            "      - name: QEMU consolidated repair candidate qualification\n"
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
