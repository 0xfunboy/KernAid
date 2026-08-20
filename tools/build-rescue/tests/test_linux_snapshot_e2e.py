from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import unittest


REPO_DIR = Path(__file__).resolve().parents[3]
SANITIZER_PATH = REPO_DIR / "tools/test-linux-snapshot/sanitize_e2e.py"
TREE_FINGERPRINT_PATH = (
    REPO_DIR / "tools/test-linux-snapshot/tree_fingerprint.py"
)
READY_CHECK = (
    REPO_DIR
    / "rescue/live-build/config/includes.chroot/usr/lib/kernaid/ready-check"
)
QEMU_SMOKE = REPO_DIR / "tools/build-rescue/qemu-smoke.sh"
QEMU_WITH_RESIDENT = (
    REPO_DIR / "tools/build-rescue/qemu-with-resident-snapshot.sh"
)
JUSTFILE = REPO_DIR / "justfile"
TAURI_MAIN = REPO_DIR / "apps/desk/src-tauri/src/main.rs"
RESIDENT_HARNESS = REPO_DIR / "tests/integration/linux-snapshot-resident-ipc.sh"
CI_RESIDENT_RUNNER = (
    REPO_DIR / "tests/integration/run-linux-snapshot-resident-ipc-ci.sh"
)
CI_WORKFLOW = REPO_DIR / ".github/workflows/ci.yml"
DESKTOP_WORKFLOW = REPO_DIR / ".github/workflows/desktop.yml"
RESCUE_WORKFLOW = REPO_DIR / ".github/workflows/rescue.yml"
DIGEST = "5ddfda2212ab077621f2c2092a1b9400c0d83853d4df7056a185ac78cc243774"


def load_sanitizer():
    specification = importlib.util.spec_from_file_location(
        "kernaid_linux_snapshot_e2e_sanitizer", SANITIZER_PATH
    )
    if specification is None or specification.loader is None:
        raise RuntimeError("snapshot E2E sanitizer could not be loaded")
    module = importlib.util.module_from_spec(specification)
    sys.modules[module.__name__] = module
    specification.loader.exec_module(module)
    return module


SANITIZER = load_sanitizer()


def load_tree_fingerprint():
    specification = importlib.util.spec_from_file_location(
        "kernaid_linux_snapshot_tree_fingerprint", TREE_FINGERPRINT_PATH
    )
    if specification is None or specification.loader is None:
        raise RuntimeError("snapshot tree fingerprint helper could not be loaded")
    module = importlib.util.module_from_spec(specification)
    sys.modules[module.__name__] = module
    specification.loader.exec_module(module)
    return module


TREE_FINGERPRINT = load_tree_fingerprint()


class LinuxSnapshotEndToEndTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)

    def write(self, name: str, payload: bytes) -> Path:
        path = self.directory / name
        path.write_bytes(payload)
        return path

    def inputs(self) -> tuple[Path, Path, Path]:
        resident = self.write(
            "resident.log",
            (
                "KERNAID_RESIDENT_LINUX_SNAPSHOT_E2E_V1 "
                f"semantic_sha256={DIGEST}\n"
            ).encode("ascii"),
        )
        logs = []
        for firmware in ("bios", "uefi"):
            logs.append(
                self.write(
                    f"{firmware}.log",
                    (
                        "untrusted boot diagnostic that must not be published\r\n"
                        "KERNAID_RESCUE_LINUX_SNAPSHOT_E2E_V1 "
                        f"semantic_sha256={DIGEST}\r\n"
                        "KERNAID_QEMU_LINUX_SNAPSHOT_E2E_V1 "
                        f"firmware={firmware} semantic_sha256={DIGEST} "
                        "semantic_equal=true\n"
                    ).encode("ascii"),
                )
            )
        return resident, logs[0], logs[1]

    def test_sanitizer_publishes_only_the_equal_allowlisted_digest(self) -> None:
        resident, bios, uefi = self.inputs()
        output = self.directory / "sanitized.log"
        payload = SANITIZER.sanitize(resident, bios, uefi)
        SANITIZER._publish(output, payload)
        self.assertEqual(
            output.read_text(encoding="ascii").splitlines(),
            [
                "KERNAID_LINUX_SNAPSHOT_E2E_V1 "
                f"source=resident semantic_sha256={DIGEST}",
                "KERNAID_LINUX_SNAPSHOT_E2E_V1 "
                f"source=rescue-bios semantic_sha256={DIGEST}",
                "KERNAID_LINUX_SNAPSHOT_E2E_V1 "
                f"source=rescue-uefi semantic_sha256={DIGEST}",
                "KERNAID_LINUX_SNAPSHOT_PARITY_V1 "
                f"semantic_sha256={DIGEST} equal=true",
            ],
        )
        self.assertNotIn(b"untrusted boot diagnostic", output.read_bytes())
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)

    def test_sanitizer_rejects_mismatch_duplicate_and_marker_payloads(self) -> None:
        resident, bios, uefi = self.inputs()
        mismatched = "0" * 64
        uefi.write_bytes(uefi.read_bytes().replace(DIGEST.encode(), mismatched.encode()))
        with self.assertRaisesRegex(SANITIZER.EvidenceError, "digests differed"):
            SANITIZER.sanitize(resident, bios, uefi)

        resident, bios, uefi = self.inputs()
        with bios.open("ab") as stream:
            stream.write(
                b"KERNAID_QEMU_LINUX_SNAPSHOT_E2E_V1 firmware=bios "
                + f"semantic_sha256={DIGEST} semantic_equal=true\n".encode("ascii")
            )
        with self.assertRaisesRegex(SANITIZER.EvidenceError, "not unique"):
            SANITIZER.sanitize(resident, bios, uefi)

        resident, bios, uefi = self.inputs()
        with bios.open("ab") as stream:
            stream.write(b"fixture-secret-package-name\n")
        with self.assertRaisesRegex(SANITIZER.EvidenceError, "raw marker"):
            SANITIZER.sanitize(resident, bios, uefi)

    def test_production_ipc_has_no_root_or_fixture_parameter(self) -> None:
        source = TAURI_MAIN.read_text(encoding="utf-8")
        start = source.index(
            "#[tauri::command]\nasync fn collect_linux_normalized_snapshot()"
        )
        end = source.index("\n#[tauri::command]", start + 1)
        command = source[start:end]
        self.assertIn("collect_current_root_snapshot()", command)
        self.assertNotIn("fixture", command.lower())
        self.assertNotIn("Path", command)
        handler_start = source.index("macro_rules! production_invoke_handler")
        handler_end = source.index("\nfn main()", handler_start)
        production_handler = source[handler_start:handler_end]
        self.assertEqual(
            production_handler.count("collect_linux_normalized_snapshot"),
            1,
        )
        self.assertEqual(
            source.count(".invoke_handler(production_invoke_handler!())"),
            2,
        )
        self.assertEqual(source.count("tauri::generate_handler!["), 1)
        harness = RESIDENT_HARNESS.read_text(encoding="utf-8")
        for token in (
            "unshare --user --map-root-user --mount --pid --fork",
            "--exact \"$probe_name\" --ignored",
            "tree_fingerprint",
        ):
            self.assertIn(token, harness)
        self.assertIn("rustix::process::chroot(&fixture_path)", source)
        self.assertIn(
            '"\\nKERNAID_RESIDENT_LINUX_SNAPSHOT_E2E_V1 '
            'semantic_sha256={semantic_digest:x}"',
            source,
        )
        self.assertIn('rb"^" + re.escape(prefix.encode("ascii"))', harness)
        marker = (
            "KERNAID_RESIDENT_LINUX_SNAPSHOT_E2E_V1 "
            f"semantic_sha256={DIGEST}"
        ).encode("ascii")
        libtest_output = b"test tests::resident_probe ... \n" + marker + b"\nok\n"
        marker_pattern = re.compile(
            rb"^KERNAID_RESIDENT_LINUX_SNAPSHOT_E2E_V1 "
            rb"semantic_sha256=([0-9a-f]{64})$",
            re.MULTILINE,
        )
        self.assertEqual(marker_pattern.findall(libtest_output), [DIGEST.encode("ascii")])

    def test_hosted_ci_policy_runner_is_closed_and_restores(self) -> None:
        source = CI_RESIDENT_RUNNER.read_text(encoding="utf-8")
        for token in (
            '${RUNNER_ENVIRONMENT:-}" != github-hosted',
            "/usr/bin/sudo -n /usr/sbin/sysctl",
            "trap finish_userns_policy EXIT",
            '"kernel.apparmor_restrict_unprivileged_userns='
            '$apparmor_userns_before"',
            '"kernel.unprivileged_userns_clone=$unprivileged_clone_before"',
            "/usr/bin/unshare --user --map-root-user /usr/bin/true",
            'resident_marker="$($resident_harness)"',
        ):
            self.assertIn(token, source)
        self.assertLess(
            source.index("restore_userns_policy || exit 1"),
            source.index(
                "printf 'KERNAID_RESIDENT_LINUX_SNAPSHOT_E2E_V1 "
                "semantic_sha256=%s"
            ),
        )
        self.assertTrue(CI_RESIDENT_RUNNER.stat().st_mode & stat.S_IXUSR)

        environment = os.environ.copy()
        for name in ("GITHUB_ACTIONS", "RUNNER_OS", "RUNNER_ENVIRONMENT"):
            environment.pop(name, None)
        rejected = subprocess.run(
            [str(CI_RESIDENT_RUNNER)],
            cwd=REPO_DIR,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(rejected.returncode, 2)
        self.assertIn("hosted-CI only", rejected.stderr)

    def test_tree_fingerprint_binds_mode_and_mtime_to_each_path(self) -> None:
        Record = TREE_FINGERPRINT.FingerprintRecord
        content_a = b"a" * 32
        content_b = b"b" * 32
        before = [
            Record(b"a", b"file", 0o600, 1, 100, 300, content_a),
            Record(b"b", b"file", 0o644, 1, 200, 300, content_b),
        ]
        swapped = [
            Record(b"a", b"file", 0o644, 1, 200, 300, content_a),
            Record(b"b", b"file", 0o600, 1, 100, 300, content_b),
        ]
        self.assertEqual(
            sorted((item.mode, item.mtime_ns) for item in before),
            sorted((item.mode, item.mtime_ns) for item in swapped),
        )
        self.assertNotEqual(
            TREE_FINGERPRINT.fingerprint_records(before),
            TREE_FINGERPRINT.fingerprint_records(swapped),
        )
        for harness_path in (
            RESIDENT_HARNESS,
            REPO_DIR / "tests/integration/linux-snapshot-parity.sh",
        ):
            harness = harness_path.read_text(encoding="utf-8")
            self.assertIn("tools/test-linux-snapshot/tree_fingerprint.py", harness)
            self.assertNotIn("sort -z", harness)

    def test_qemu_route_uses_the_same_fixture_and_emits_only_a_digest(self) -> None:
        qemu = QEMU_SMOKE.read_text(encoding="utf-8")
        self.assertIn(
            'snapshot_fixture="$repo_dir/tests/fixtures/linux-normalized-snapshot/healthy/root"',
            qemu,
        )
        self.assertIn('cp -a -- "$snapshot_fixture/." "$target_seed_dir/"', qemu)
        self.assertNotIn("ID=kernaid-qemu-fixture", qemu)
        self.assertIn("KERNAID_RESIDENT_SNAPSHOT_SEMANTIC_SHA256", qemu)
        self.assertIn(
            'resident_snapshot_semantic_sha256="${KERNAID_RESIDENT_SNAPSHOT_SEMANTIC_SHA256:-}"',
            qemu,
        )
        self.assertNotIn(
            "KERNAID_RESIDENT_SNAPSHOT_SEMANTIC_SHA256:-$snapshot_golden",
            qemu,
        )
        self.assertIn("KERNAID_QEMU_LINUX_SNAPSHOT_E2E_V1", qemu)

        ready = READY_CHECK.read_text(encoding="utf-8")
        scan = ready.index(
            'targets="$(curl --fail --silent --show-error --max-time 5'
        )
        select = ready.index(
            'selection="$(curl --fail --silent --show-error --max-time 22', scan
        )
        inspect = ready.index(
            'inspection="$(curl --fail --silent --show-error --max-time 22',
            select,
        )
        digest = ready.index("snapshot_semantic_sha256=", inspect)
        marker = ready.index("KERNAID_RESCUE_LINUX_SNAPSHOT_E2E_V1", digest)
        self.assertLess(scan, select)
        self.assertLess(select, inspect)
        self.assertLess(inspect, digest)
        self.assertLess(digest, marker)
        for raw_marker in (
            "fixture-machine-id-must-never-be-projected",
            "fixture-secret-package-name",
            "UUID=fixture-root",
            "server:/fixture",
        ):
            self.assertIn(raw_marker, ready[digest:marker])
        marker_line = next(
            line for line in ready.splitlines() if "echo \"KERNAID_RESCUE_LINUX" in line
        )
        self.assertNotIn("$inspection", marker_line)

    def test_qemu_recipe_requires_one_exact_runtime_resident_marker(self) -> None:
        source = QEMU_WITH_RESIDENT.read_text(encoding="utf-8")
        resident = self.write(
            "resident",
            b'#!/usr/bin/env bash\nprintf \'%s\\n\' "$MOCK_RESIDENT_MARKER"\n',
        )
        qemu = self.write(
            "qemu",
            (
                b"#!/usr/bin/env bash\n"
                b"printf '%s\\n' \"$KERNAID_RESIDENT_SNAPSHOT_SEMANTIC_SHA256\" "
                b">\"$MOCK_STATE/digest\"\n"
                b"printf '%s\\n' \"$*\" >\"$MOCK_STATE/args\"\n"
            ),
        )
        resident.chmod(0o700)
        qemu.chmod(0o700)
        source = source.replace(
            'resident_harness="$repo_dir/tests/integration/linux-snapshot-resident-ipc.sh"',
            f'resident_harness="{resident}"',
        ).replace(
            'qemu_smoke="$repo_dir/tools/build-rescue/qemu-smoke.sh"',
            f'qemu_smoke="{qemu}"',
        )
        wrapper = self.write("wrapper", source.encode("utf-8"))
        wrapper.chmod(0o700)

        environment = os.environ.copy()
        environment.update(
            {
                "MOCK_STATE": str(self.directory),
                "MOCK_RESIDENT_MARKER": (
                    "KERNAID_RESIDENT_LINUX_SNAPSHOT_E2E_V1 "
                    f"semantic_sha256={DIGEST}"
                ),
            }
        )
        result = subprocess.run(
            [str(wrapper), "bios", "/fixed/test.iso"],
            cwd=REPO_DIR,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.directory / "digest").read_text().strip(), DIGEST)
        self.assertEqual(
            (self.directory / "args").read_text().strip(),
            "bios /fixed/test.iso",
        )

        for marker in (
            f"KERNAID_RESIDENT_LINUX_SNAPSHOT_E2E_V1 semantic_sha256={DIGEST}\n"
            f"KERNAID_RESIDENT_LINUX_SNAPSHOT_E2E_V1 semantic_sha256={DIGEST}",
            "fixture-secret-package-name",
            "KERNAID_RESIDENT_LINUX_SNAPSHOT_E2E_V1 semantic_sha256=wrong",
        ):
            with self.subTest(marker=marker):
                (self.directory / "digest").unlink(missing_ok=True)
                environment["MOCK_RESIDENT_MARKER"] = marker
                rejected = subprocess.run(
                    [str(wrapper), "uefi"],
                    cwd=REPO_DIR,
                    env=environment,
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(rejected.returncode, 1)
                self.assertFalse((self.directory / "digest").exists())

        recipes = JUSTFILE.read_text(encoding="utf-8")
        self.assertIn(
            "./tools/build-rescue/qemu-with-resident-snapshot.sh bios",
            recipes,
        )
        self.assertIn(
            "./tools/build-rescue/qemu-with-resident-snapshot.sh uefi",
            recipes,
        )
        self.assertNotIn("./tools/build-rescue/qemu-smoke.sh bios", recipes)
        self.assertNotIn("./tools/build-rescue/qemu-smoke.sh uefi", recipes)

    def test_workflows_run_and_route_all_shared_snapshot_changes(self) -> None:
        ci = CI_WORKFLOW.read_text(encoding="utf-8")
        desktop = DESKTOP_WORKFLOW.read_text(encoding="utf-8")
        rescue = RESCUE_WORKFLOW.read_text(encoding="utf-8")
        for workflow in (ci, desktop, rescue):
            self.assertIn(
                "./tests/integration/run-linux-snapshot-resident-ipc-ci.sh",
                workflow,
            )
            self.assertNotIn("apparmor_restrict_unprivileged_userns", workflow)
            self.assertNotIn("unprivileged_userns_clone", workflow)
        for path_filter in (
            '"tests/fixtures/linux-normalized-snapshot/**"',
            '"tests/integration/linux-snapshot-resident-ipc.sh"',
            '"tests/integration/run-linux-snapshot-resident-ipc-ci.sh"',
            '"tools/test-linux-snapshot/**"',
        ):
            self.assertIn(path_filter, desktop)
            self.assertIn(path_filter, rescue)
        self.assertIn('"justfile"', rescue)
        self.assertIn("KERNAID_RESIDENT_SNAPSHOT_SEMANTIC_SHA256", rescue)
        self.assertEqual(
            rescue.count("tools/build-rescue/qemu-with-resident-snapshot.sh"),
            2,
        )
        self.assertIn("tools/test-linux-snapshot/sanitize_e2e.py", rescue)
        self.assertIn("KernAid-Linux-snapshot-e2e-evidence", rescue)
        self.assertIn(
            "${{ runner.temp }}/kernaid-linux-snapshot-e2e.sanitized.log",
            rescue,
        )
        smoke_upload = rescue.index("      - name: Publish smoke diagnostics")
        next_step = rescue.index("\n      - name:", smoke_upload + 1)
        self.assertNotIn("rescue-smoke-*.log", rescue[smoke_upload:next_step])


if __name__ == "__main__":
    unittest.main()
