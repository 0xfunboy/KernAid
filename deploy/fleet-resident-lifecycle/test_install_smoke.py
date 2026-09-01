from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "deploy/fleet-resident-lifecycle/install-smoke.py"


def load_smoke() -> object:
    spec = importlib.util.spec_from_file_location("kernaid_fleet_lifecycle_smoke", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


smoke = load_smoke()


class LifecycleSmokeStaticTests(unittest.TestCase):
    def test_binary_contract_requires_both_fixed_routes_and_envelopes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "resident"
            binary.write_bytes(b"\0".join(smoke.CONTRACT_MARKERS))
            smoke.verify_binary_contract(binary)
            binary.write_bytes(b"\0".join(smoke.CONTRACT_MARKERS[:-1]))
            with self.assertRaises(smoke.SmokeFailure):
                smoke.verify_binary_contract(binary)

    def test_native_enrollment_contract_is_packaged_without_a_credential(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "resident"
            binary.write_bytes(b"\0".join(smoke.ENROLLMENT_CONTRACT_MARKERS))
            smoke.verify_enrollment_contract(binary)
            binary.write_bytes(b"\0".join(smoke.ENROLLMENT_CONTRACT_MARKERS[:-1]))
            with self.assertRaises(smoke.SmokeFailure):
                smoke.verify_enrollment_contract(binary)

    def test_generated_configs_are_public_and_credential_free(self) -> None:
        schemas = {
            "linux": "dev.kernaid.fleet.resident-work-order-service-config.v1",
            "macos": "dev.kernaid.fleet.resident-macos-service-config.v1",
            "windows": "dev.kernaid.fleet.resident-windows-service-config.v1",
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for platform, schema in schemas.items():
                platform_root = root / platform
                platform_root.mkdir()
                config, _ = smoke.write_smoke_config(platform, platform_root)
                smoke.verify_public_config(config, schema)
                value = json.loads(config.read_bytes())
                self.assertEqual(value["endpoint"], "https://fleet.example.invalid/")
                self.assertFalse((platform_root / "absent-public-anchors").exists())
                if platform == "linux":
                    self.assertNotIn("enrollmentTokenFile", value)
                else:
                    self.assertEqual(
                        value["enrollmentTokenFile"],
                        str(platform_root / "absent-enrollment-token"),
                    )

    def test_platform_defaults_remain_off(self) -> None:
        linux_unit = (
            REPO
            / "deploy/fleet-resident-work-orders/kernaid-fleet-resident-work-orders.service"
        ).read_text(encoding="utf-8")
        macos_plist = (
            REPO
            / "deploy/fleet-resident-macos/io.kernaid.fleet-resident-macos.plist"
        ).read_text(encoding="utf-8")
        windows_source = (
            REPO / "crates/fleet-resident-work-orders/src/windows.rs"
        ).read_text(encoding="utf-8")
        self.assertIn("WantedBy=default.target", linux_unit)
        self.assertNotIn(".wants/", linux_unit)
        self.assertIn("<key>RunAtLoad</key>\n  <false/>", macos_plist)
        self.assertIn("<key>KeepAlive</key>\n  <false/>", macos_plist)
        self.assertIn("start_type: ServiceStartType::OnDemand", windows_source)
        self.assertIn("account_password: None", windows_source)

    def test_existing_workflows_run_native_lifecycle_without_duplicate_matrix(self) -> None:
        linux = (REPO / ".github/workflows/fleet-resident-linux.yml").read_text(
            encoding="utf-8"
        )
        windows = (REPO / ".github/workflows/fleet-resident-windows.yml").read_text(
            encoding="utf-8"
        )
        macos = (REPO / ".github/workflows/fleet-resident-macos.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("install-smoke.py --platform linux", linux)
        self.assertIn("runs-on: windows-2025", windows)
        self.assertIn("needs: cross-build-windows-x86-64", windows)
        self.assertIn("install-smoke.py --platform windows", windows)
        self.assertNotIn("matrix:", windows)
        self.assertIn("install-smoke.py --platform macos", macos)
        self.assertEqual(macos.count("target: aarch64-apple-darwin"), 1)
        self.assertEqual(macos.count("target: x86_64-apple-darwin"), 1)

    def test_linux_setup_bootstraps_identity_only_for_explicit_enable(self) -> None:
        setup = (
            REPO / "deploy/fleet-resident-linux/kernaid-fleet-resident-setup"
        ).read_text(encoding="utf-8")
        bootstrap = (
            "/usr/libexec/kernaid-fleet-resident-sync \\\n"
            '    --config "$config_dir/fleet-resident.json" \\\n'
            "    --initialize-identity \\\n"
            "    --once"
        )
        self.assertEqual(setup.count(bootstrap), 1)
        self.assertLess(setup.index("if ((enable_services)); then"), setup.index(bootstrap))
        self.assertLess(setup.index(bootstrap), setup.index("systemctl --user enable --now"))

    def test_windows_and_macos_bootstrap_remain_explicit_and_pre_start(self) -> None:
        windows = (REPO / "deploy/fleet-resident-windows/README.md").read_text(
            encoding="utf-8"
        )
        macos = (REPO / "deploy/fleet-resident-macos/README.md").read_text(
            encoding="utf-8"
        )
        self.assertLess(
            windows.index("kernaid-fleet-resident-windows.exe enroll"),
            windows.index("kernaid-fleet-resident-windows.exe start"),
        )
        self.assertIn("--initialize-identity --once", macos)
        plist = (
            REPO / "deploy/fleet-resident-macos/io.kernaid.fleet-resident-macos.plist"
        ).read_text(encoding="utf-8")
        self.assertIn("<key>RunAtLoad</key>\n  <false/>", plist)


if __name__ == "__main__":
    unittest.main()
