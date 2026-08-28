from pathlib import Path
import unittest


REPO = Path(__file__).resolve().parents[3]
SCRIPT = REPO / "tools/build-rescue/qemu-repair-candidate-smoke.sh"
CONTROLLER = REPO / "tools/build-rescue/qemu-repair-candidate-pty.py"
WORKFLOW = REPO / ".github/workflows/rescue-repair-candidate.yml"


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
        ):
            self.assertIn(required, source)
        self.assertNotIn("mock", source.lower())

    def test_manual_candidate_workflow_runs_one_mutating_gate(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertEqual(
            workflow.count("./tools/build-rescue/qemu-repair-candidate-smoke.sh"),
            1,
        )


if __name__ == "__main__":
    unittest.main()
