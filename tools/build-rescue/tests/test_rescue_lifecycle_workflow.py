from __future__ import annotations

import hashlib
import re
import unittest
from pathlib import Path


REPO_DIR = Path(__file__).resolve().parents[3]
WORKFLOW = REPO_DIR / ".github/workflows/rescue.yml"
LIFECYCLE_HARNESS = REPO_DIR / "tools/build-rescue/qemu-vault-lifecycle-smoke.sh"
PROVIDER_PROBE = REPO_DIR / "tools/build-rescue/provider-lease-probe.py"


def job_block(source: str, name: str) -> str:
    match = re.search(
        rf"^  {re.escape(name)}:\n(?P<body>.*?)(?=^  [a-z0-9-]+:\n|\Z)",
        source,
        re.MULTILINE | re.DOTALL,
    )
    if match is None:
        raise AssertionError(f"workflow job is missing: {name}")
    return match.group(0)


def named_step(job: str, name: str) -> str:
    match = re.search(
        rf"^      - name: {re.escape(name)}\n(?P<body>.*?)(?=^      - |\Z)",
        job,
        re.MULTILINE | re.DOTALL,
    )
    if match is None:
        raise AssertionError(f"workflow step is missing: {name}")
    return match.group(0)


class RescueLifecycleWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")
        cls.legacy = job_block(cls.workflow, "build-and-smoke-test")

    def test_trigger_covers_report_schema_and_every_desk_workspace_dependency(self) -> None:
        required_paths = {
            '      - "crates/report-schema/**"',
            '      - "services/agent-gateway/**"',
            '      - "packages/provider-types/**"',
            '      - "packages/schemas/**"',
            '      - "packages/session-driver/**"',
            '      - "package.json"',
            '      - "pnpm-workspace.yaml"',
            '      - "rust-toolchain.toml"',
        }
        for path in required_paths:
            self.assertIn(path, self.workflow)

    def test_legacy_job_lints_both_harness_files_and_publishes_probe_input(self) -> None:
        validation = named_step(
            self.legacy, "Validate Rescue image-layout tooling"
        )
        self.assertIn("qemu-vault-lifecycle-smoke.sh", validation)
        self.assertIn("qemu-vault-lifecycle-pty.py", validation)
        self.assertIn("provider-lease-probe.py", validation)
        self.assertIn("bash -n", validation)
        self.assertIn("shellcheck", validation)
        self.assertIn('compile(path.read_bytes(), str(path), "exec"', validation)

        probe = named_step(
            self.legacy, "Publish the host-only lifecycle probe input"
        )
        self.assertIn("uses: actions/upload-artifact@v4", probe)
        self.assertIn("name: KernAid-Rescue-vault-lifecycle-probe-input", probe)
        self.assertIn("path: target/release/kernaid-rescue-vault-probe", probe)
        self.assertIn("if-no-files-found: error", probe)
        self.assertIn("retention-days: 1", probe)

    def test_lifecycle_evidence_cannot_become_a_catalog_input(self) -> None:
        catalog_v1 = named_step(
            self.legacy,
            "Derive catalog entry from the tested ISO and attested QEMU logs",
        )
        catalog_v2 = named_step(
            self.legacy,
            "Derive and validate the inactive catalog-v2 evidence artifact",
        )
        smoke_upload = named_step(self.legacy, "Publish smoke diagnostics")
        image_upload = named_step(self.legacy, "Publish checksums and image")
        for catalog_body in (catalog_v1, catalog_v2, smoke_upload, image_upload):
            self.assertNotIn("vault-lifecycle", catalog_body.lower())
            self.assertNotIn("lifecycle-*.log", catalog_body.lower())

        self.assertEqual(self.legacy.count("./tools/build-rescue/qemu-smoke.sh "), 2)
        self.assertEqual(
            self.legacy.count('"$PWD/tools/build-rescue/qemu-usb-smoke.sh" '), 2
        )
        self.assertEqual(catalog_v1.count("--bios-log"), 1)
        self.assertEqual(catalog_v1.count("--uefi-log"), 1)
        self.assertEqual(catalog_v2.count("--bios-log"), 1)
        self.assertEqual(catalog_v2.count("--uefi-log"), 1)

    def test_bios_and_uefi_are_explicit_isolated_downstream_jobs(self) -> None:
        for firmware in ("bios", "uefi"):
            with self.subTest(firmware=firmware):
                job = job_block(self.workflow, f"vault-lifecycle-{firmware}")
                self.assertIn("needs: build-and-smoke-test", job)
                self.assertIn("runs-on: ubuntu-24.04", job)
                self.assertRegex(
                    job, re.compile(r"^    timeout-minutes: 90$", re.MULTILINE)
                )
                self.assertNotIn("matrix:", job)
                self.assertNotIn("strategy:", job)

                run_step = named_step(
                    job, f"QEMU {firmware.upper()} two-boot vault lifecycle test"
                )
                self.assertRegex(
                    run_step,
                    re.compile(r"^        timeout-minutes: 80$", re.MULTILINE),
                )
                self.assertEqual(
                    run_step.count("qemu-vault-lifecycle-smoke.sh"), 1
                )
                self.assertIn(
                    f'{firmware} "$iso" "$probe" >"$raw_output" 2>&1', run_step
                )
                self.assertIn("sudo -n --", run_step)
                self.assertIn("boot_count=2", run_step)
                self.assertIn(
                    'kinds != ["boot", "boot", "raw", "attestation"]', run_step
                )
                self.assertIn('boots != ["1", "2"]', run_step)

                image_input = named_step(
                    job, "Download the tested Rescue image input"
                )
                probe_input = named_step(
                    job, "Download the host-only lifecycle probe input"
                )
                self.assertIn("uses: actions/download-artifact@v4", image_input)
                self.assertIn("name: KernAid-Rescue-amd64", image_input)
                self.assertIn("uses: actions/download-artifact@v4", probe_input)
                self.assertIn(
                    "name: KernAid-Rescue-vault-lifecycle-probe-input",
                    probe_input,
                )
                self.assertIn(f"lifecycle-{firmware}/image", image_input)
                self.assertIn(f"lifecycle-{firmware}/probe", probe_input)
                self.assertNotEqual(
                    re.search(r"^          path: (.+)$", image_input, re.MULTILINE).group(1),
                    re.search(r"^          path: (.+)$", probe_input, re.MULTILINE).group(1),
                )

    def test_each_job_installs_exact_lifecycle_tools_and_verifies_inputs(self) -> None:
        required_packages = {
            "coreutils",
            "cryptsetup",
            "e2fsprogs",
            "gawk",
            "grep",
            "libcrypt1",
            "mount",
            "ovmf",
            "procps",
            "python3",
            "qemu-system-x86",
            "squashfs-tools",
            "udev",
            "util-linux",
        }
        for firmware in ("bios", "uefi"):
            with self.subTest(firmware=firmware):
                job = job_block(self.workflow, f"vault-lifecycle-{firmware}")
                tooling = named_step(job, "Install isolated lifecycle VM tooling")
                package_body = tooling.split("apt-get install -y", maxsplit=1)[1]
                installed = set(
                    re.findall(r"[a-z0-9][a-z0-9+.-]+", package_body)
                )
                self.assertEqual(installed, required_packages)

                run_step = named_step(
                    job, f"QEMU {firmware.upper()} two-boot vault lifecycle test"
                )
                self.assertEqual(run_step.count('test ! -L "$input"'), 1)
                self.assertIn('= "regular file:1"', run_step)
                self.assertIn('chmod 0755 -- "$probe"', run_step)
                self.assertIn('= 755', run_step)
                self.assertIn("sha256sum --check --strict", run_step)

    def test_only_allowlisted_sanitized_lifecycle_output_is_uploaded(self) -> None:
        for firmware in ("bios", "uefi"):
            with self.subTest(firmware=firmware):
                job = job_block(self.workflow, f"vault-lifecycle-{firmware}")
                run_step = named_step(
                    job, f"QEMU {firmware.upper()} two-boot vault lifecycle test"
                )
                self.assertIn(
                    f'raw_output="$RUNNER_TEMP/kernaid-vault-lifecycle-{firmware}.raw.log"',
                    run_step,
                )
                self.assertIn("pattern.fullmatch(line)", run_step)
                self.assertIn("outside the allowlist", run_step)
                self.assertIn("os.O_NOFOLLOW", run_step)
                self.assertIn('stream.write(payload)', run_step)
                self.assertIn("stream.flush()", run_step)
                self.assertIn("os.fsync(stream.fileno())", run_step)
                self.assertIn(
                    "os.link(temporary_path, safe_path, follow_symlinks=False)",
                    run_step,
                )
                self.assertIn("final.st_nlink != 1", run_step)
                self.assertIn("final.st_size != len(payload)", run_step)
                self.assertIn("os.fsync(directory)", run_step)
                self.assertIn("published = True", run_step)
                self.assertIn("if not published:", run_step)
                self.assertNotIn("$GITHUB_WORKSPACE/kernaid-vault-lifecycle", run_step)

                upload = named_step(
                    job,
                    f"Publish sanitized {firmware.upper()} lifecycle evidence",
                )
                self.assertIn("if: always()", upload)
                self.assertIn("uses: actions/upload-artifact@v4", upload)
                self.assertIn(
                    f"name: KernAid-Rescue-vault-lifecycle-{firmware}-evidence",
                    upload,
                )
                self.assertIn(
                    f"path: ${{{{ runner.temp }}}}/kernaid-vault-lifecycle-{firmware}.sanitized.log",
                    upload,
                )
                self.assertNotIn(".raw.log", upload)
                self.assertNotIn("catalog", upload.lower())
                self.assertIn("if-no-files-found: error", upload)

    def test_workflow_and_harness_freeze_the_two_boot_contract(self) -> None:
        harness = LIFECYCLE_HARNESS.read_text(encoding="utf-8")
        self.assertEqual(harness.count("readonly boot_count=2"), 1)
        self.assertEqual(self.workflow.count("boot_count=2"), 2)
        self.assertEqual(self.workflow.count("qmp_acpi_shutdowns=2"), 2)
        self.assertEqual(self.workflow.count("expected_contracts = ["), 2)
        self.assertEqual(self.workflow.count('("1", "clean-lock"'), 2)
        self.assertEqual(self.workflow.count('("2", "persistent-fault"'), 2)
        self.assertEqual(self.workflow.count("boot_contracts != expected_contracts"), 2)
        self.assertEqual(self.workflow.count("acpi_shutdowns_clean=true"), 2)
        self.assertEqual(
            self.workflow.count("pre_terminal_daemon_processes_stable=true"), 2
        )
        self.assertEqual(
            self.workflow.count("pre_terminal_capabilities_exact=true"), 2
        )
        self.assertEqual(
            self.workflow.count("production_ui_provider_relay_path=true"), 4
        )
        self.assertEqual(
            harness.count("production_ui_provider_relay_path=true"), 2
        )
        self.assertEqual(harness.count("    -nic none\n"), 1)
        self.assertNotIn(" daemon_processes_stable=true", self.workflow)
        self.assertNotIn(" capabilities_exact=true", self.workflow)
        self.assertNotIn("persistent_fault_after_each_boot", self.workflow)
        self.assertIn("--provider-key-fd 7", harness)
        self.assertIn('7<"$provider_key"', harness)
        self.assertIn(
            "name=opt/io.systemd.credentials/provider-lease-probe,"
            "file=$provider_probe_helper",
            harness,
        )
        self.assertIn("== 15508", harness)
        digest = "23470d54d04fd4d025988e9fabf7401b12c9157c6d58162295c01817c103a08f"
        self.assertIn(digest, harness)
        self.assertEqual(PROVIDER_PROBE.stat().st_size, 15508)
        self.assertEqual(hashlib.sha256(PROVIDER_PROBE.read_bytes()).hexdigest(), digest)


if __name__ == "__main__":
    unittest.main()
