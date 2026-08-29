from __future__ import annotations

from collections import defaultdict
from pathlib import Path
import unittest


REPO = Path(__file__).resolve().parents[3]
LIVE = REPO / "rescue/live-build/config/includes.chroot"
CANDIDATE = REPO / "rescue/live-build/candidate"
BUILD = REPO / "tools/build-rescue/build.sh"
HOOK = REPO / "rescue/live-build/config/hooks/live/0100-kernaid-safety.hook.chroot"
WORKFLOW = REPO / ".github/workflows/rescue-repair-candidate.yml"
PHYSICAL_PARENT = REPO / "crates/broker/src/target_physical_parent.rs"


def unit_directives(path: Path) -> dict[str, dict[str, list[str]]]:
    sections: dict[str, dict[str, list[str]]] = {}
    current: dict[str, list[str]] | None = None
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            current = sections.setdefault(line[1:-1], defaultdict(list))
            continue
        if current is None or "=" not in line:
            raise AssertionError(f"invalid unit line in {path}: {raw_line!r}")
        key, value = line.split("=", maxsplit=1)
        current[key].append(value)
    return sections


class RepairCandidatePackagingTests(unittest.TestCase):
    def test_candidate_workflow_is_manual_isolated_and_publishes_only_iso(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("on:\n  workflow_dispatch:\n", workflow)
        self.assertNotIn("\n  push:", workflow)
        self.assertIn("node-version: 24.18.0", workflow)
        self.assertIn("KERNAID_REPAIR_CANDIDATE=1", workflow)
        self.assertIn("--features rescue-fstab-production-candidate", workflow)
        self.assertIn("-p kernaid-linux-blockfd", workflow)
        self.assertIn("KERNAID_BLOCKFD_PROBE_BINARY=", workflow)
        self.assertEqual(workflow.count("./tools/build-rescue/qemu-smoke.sh"), 2)
        self.assertIn("name: KernAid-Rescue-amd64-repair-candidate", workflow)
        for forbidden in ("catalog-entry", "qualified-release", "deploy-pages"):
            self.assertNotIn(forbidden, workflow)

    def test_default_profile_contains_no_candidate_artifact_or_client_group(self) -> None:
        absent = (
            LIVE / "usr/lib/kernaid/kernaid-rescue-repaird",
            LIVE / "usr/lib/kernaid/kernaid-blockfd-probe",
            LIVE / "usr/lib/kernaid/repair-candidate-image-v1",
            LIVE / "etc/systemd/system/kernaid-rescue-repaird.service",
            LIVE / "etc/systemd/system/kernaid-rescue-repaird.socket",
            LIVE / "etc/sysusers.d/kernaid-repair-candidate.conf",
            LIVE / "usr/lib/tmpfiles.d/kernaid-repair-candidate.conf",
            LIVE
            / "etc/systemd/system/kernaid-ui.service.d"
            / "50-kernaid-repair-candidate.conf",
            LIVE
            / "etc/systemd/system/kernaid-ready.service.d"
            / "50-kernaid-repair-candidate.conf",
        )
        for path in absent:
            self.assertFalse(path.exists(), path)
            self.assertFalse(path.is_symlink(), path)

        base_sysusers = (
            LIVE / "etc/sysusers.d/kernaid.conf"
        ).read_text(encoding="utf-8")
        base_ui = (
            LIVE / "etc/systemd/system/kernaid-ui.service"
        ).read_text(encoding="utf-8")
        self.assertIn("u kernaid-repair - ", base_sysusers)
        self.assertNotIn("kernaid-repair-client", base_sysusers)
        self.assertNotIn("kernaid-repair-client", base_ui)

    def test_build_toggle_stages_only_the_exact_candidate_binary_and_name(self) -> None:
        source = BUILD.read_text(encoding="utf-8")
        self.assertIn('repair_candidate="${KERNAID_REPAIR_CANDIDATE-0}"', source)
        self.assertIn(
            'repaird_binary="${KERNAID_RESCUE_REPAIRD_BINARY:-'
            '$repo_dir/target/release/kernaid-rescue-repaird}"',
            source,
        )
        self.assertIn(
            'blockfd_probe_binary="${KERNAID_BLOCKFD_PROBE_BINARY:-'
            '$repo_dir/target/release/kernaid-blockfd-probe}"',
            source,
        )
        self.assertIn(
            'KERNAID_REPAIR_CANDIDATE must be exactly 0 or 1', source
        )
        self.assertIn(
            'validate_amd64_elf "$repaird_binary" '
            '"Rescue fstab repair candidate broker"',
            source,
        )
        self.assertIn(
            'install -o root -g root -m 0755 '
            '"$repaird_binary" "$repaird_destination"',
            source,
        )
        self.assertIn(
            '"$blockfd_probe_binary" "$blockfd_probe_destination"', source
        )
        self.assertIn(
            'python3 -I "$repo_dir/tools/build-rescue/verify-shipping-binary.py" '
            '\\\n'
            '    "$repaird_destination"',
            source,
        )
        self.assertIn(
            'repair_bootappend_suffix=" kernaid.repair=fstab-v1"', source
        )
        self.assertIn('iso_basename="KernAid-Rescue-amd64.iso"', source)
        self.assertIn(
            'iso_basename="KernAid-Rescue-amd64-repair-candidate.iso"', source
        )
        self.assertIn('mv "$iso" "$repo_dir/$iso_basename"', source)
        self.assertIn(
            'sha256sum "$iso_basename" > "$iso_basename.sha256"', source
        )
        self.assertLess(
            source.index('if [[ "$repair_candidate" = "1" ]]; then\n'
                         '  repair_bootappend_suffix='),
            source.index('lb config \\\n'),
        )
        self.assertIn(
            'console=ttyS0,115200n8${repair_bootappend_suffix}"', source
        )
        self.assertIn('"$repaird_destination" \\', source)
        self.assertIn('"$repair_candidate_marker_destination" \\', source)

    def test_persistent_seqpacket_daemon_is_exactly_candidate_gated(self) -> None:
        socket = unit_directives(CANDIDATE / "kernaid-rescue-repaird.socket")
        service = unit_directives(CANDIDATE / "kernaid-rescue-repaird.service")
        socket_unit = socket["Unit"]
        socket_config = socket["Socket"]
        service_unit = service["Unit"]
        service_config = service["Service"]

        conditions = [
            "boot=live",
            "kernaid.repair=fstab-v1",
        ]
        self.assertEqual(socket_unit["ConditionKernelCommandLine"], conditions)
        self.assertEqual(service_unit["ConditionKernelCommandLine"], conditions)
        self.assertEqual(
            socket_unit["ConditionPathExists"],
            ["/usr/lib/kernaid/repair-candidate-image-v1"],
        )
        self.assertEqual(
            service_unit["ConditionPathExists"],
            ["/usr/lib/kernaid/repair-candidate-image-v1"],
        )
        self.assertEqual(
            service_unit["ConditionFileIsExecutable"],
            [
                "/usr/lib/kernaid/kernaid-rescue-repaird",
                "/usr/lib/kernaid/kernaid-blockfd-probe",
            ],
        )
        self.assertEqual(
            service_unit["ConditionPathIsDirectory"],
            ["/run/lock/kernaid-repair"],
        )
        self.assertEqual(
            socket_config["ListenSequentialPacket"],
            ["/run/kernaid-rescue-repair.sock"],
        )
        self.assertEqual(socket_config["Accept"], ["no"])
        self.assertEqual(socket_config["FileDescriptorName"], ["repair-api"])
        self.assertEqual(socket_config["SocketMode"], ["0660"])
        self.assertEqual(socket_config["SocketUser"], ["root"])
        self.assertEqual(socket_config["SocketGroup"], ["kernaid-repair-client"])
        self.assertEqual(service_config["Type"], ["notify"])
        self.assertEqual(service_config["NotifyAccess"], ["main"])
        self.assertEqual(
            service_config["Sockets"], ["kernaid-rescue-repaird.socket"]
        )
        self.assertEqual(
            service_config["ExecStart"],
            ["/usr/lib/kernaid/kernaid-rescue-repaird"],
        )
        self.assertEqual(service_config["Restart"], ["no"])
        self.assertNotIn("Install", service)
        self.assertEqual(service_config["StandardInput"], ["null"])
        self.assertNotIn("socket", service_config["StandardInput"])
        self.assertEqual(service_config["User"], ["kernaid-repair"])
        self.assertEqual(service_config["Group"], ["kernaid-repair"])
        self.assertEqual(
            service_config["SupplementaryGroups"], ["kernaid-vault"]
        )
        required = set(service_unit["Requires"][0].split())
        self.assertEqual(
            service_unit["BindsTo"], ["kernaid-rescue-vaultd.service"]
        )
        self.assertIn("kernaid-ready.service", service_unit["Before"][0].split())
        self.assertTrue(
            {
                "kernaid-rescue-repaird.socket",
                "kernaid-rescue-vaultd.socket",
                "kernaid-rescue-vaultd.service",
                "kernaid-rescue-target-capability.socket",
                "kernaid-rescue-target-write-capability.socket",
                "systemd-sysusers.service",
                "systemd-tmpfiles-setup.service",
            }
            <= required
        )
        after = set(service_unit["After"][0].split())
        self.assertIn("kernaid-rescue-target-write-capability.socket", after)

    def test_candidate_caps_mount_and_device_surface_are_minimal_and_private(self) -> None:
        service = unit_directives(
            CANDIDATE / "kernaid-rescue-repaird.service"
        )["Service"]
        caps = "CAP_DAC_OVERRIDE CAP_FOWNER CAP_CHOWN"
        self.assertEqual(service["CapabilityBoundingSet"], [caps])
        self.assertEqual(service["AmbientCapabilities"], [caps])
        for directive in (
            "NoNewPrivileges",
            "PrivateMounts",
            "PrivateNetwork",
            "PrivateIPC",
            "ProtectSystem",
            "ProtectHome",
            "ProtectControlGroups",
            "ProtectKernelLogs",
            "ProtectKernelModules",
            "ProtectKernelTunables",
        ):
            self.assertIn(service[directive][0], ("yes", "strict"), directive)
        self.assertEqual(service["RestrictAddressFamilies"], ["AF_UNIX"])
        self.assertEqual(service["PrivateDevices"], ["yes"])
        self.assertEqual(service["DevicePolicy"], ["closed"])
        self.assertNotIn("DeviceAllow", service)
        self.assertEqual(
            service["ReadWritePaths"], ["/run/lock/kernaid-repair"]
        )
        self.assertNotIn("DynamicUser", service)
        self.assertNotIn("CAP_DAC_READ_SEARCH", caps)
        self.assertNotIn("CAP_MKNOD", caps)
        self.assertNotIn("CAP_SYS_ADMIN", caps)
        physical_parent = PHYSICAL_PARENT.read_text(encoding="utf-8")
        self.assertIn("/usr/lib/kernaid/kernaid-blockfd-probe", physical_parent)
        self.assertNotIn("/usr/sbin/blockdev", physical_parent)
        self.assertNotIn("/proc/self/fd/0", physical_parent)
        unit_source = (
            CANDIDATE / "kernaid-rescue-repaird.service"
        ).read_text(encoding="utf-8")
        self.assertIn("authenticated", unit_source)
        self.assertIn("no host /dev access", unit_source)

    def test_only_loopback_server_gets_candidate_client_group(self) -> None:
        self.assertEqual(
            (CANDIDATE / "kernaid-repair-candidate.conf").read_text(
                encoding="utf-8"
            ).splitlines()[-1],
            "g kernaid-repair-client - -",
        )
        self.assertEqual(
            (CANDIDATE / "kernaid-repair-candidate.tmpfiles.conf").read_text(
                encoding="utf-8"
            ),
            "d /run/lock/kernaid-repair 2770 root kernaid-repair -\n",
        )
        dropin = unit_directives(
            CANDIDATE / "50-kernaid-repair-candidate.conf"
        )
        self.assertNotIn("Requires", dropin["Unit"])
        self.assertEqual(
            dropin["Unit"]["Wants"], ["kernaid-rescue-repaird.socket"]
        )
        self.assertEqual(
            dropin["Unit"]["After"], ["kernaid-rescue-repaird.socket"]
        )
        self.assertEqual(dropin["Service"]["Group"], ["kernaid-repair-client"])
        self.assertNotIn("SupplementaryGroups", dropin["Service"])
        ready_dropin = unit_directives(
            CANDIDATE / "50-kernaid-repair-candidate-ready.conf"
        )["Unit"]
        self.assertNotIn("Requires", ready_dropin)
        self.assertEqual(
            ready_dropin["Wants"], ["kernaid-rescue-repaird.socket"]
        )
        self.assertEqual(
            ready_dropin["After"], ["kernaid-rescue-repaird.socket"]
        )
        tauri = (
            LIVE / "etc/systemd/system/kernaid-rescue-desk-shell.service"
        ).read_text(encoding="utf-8")
        self.assertNotIn("kernaid-repair-client", tauri)
        self.assertIn("PrivatePIDs=yes", tauri)
        self.assertIn("TemporaryFileSystem=/run:ro", tauri)

        build = BUILD.read_text(encoding="utf-8")
        default_groups = build.split(
            "live-config.user-default-groups=", maxsplit=1
        )[1].split(" ", maxsplit=1)[0]
        self.assertNotIn("kernaid-repair-client", default_groups.split(","))

    def test_safety_hook_validates_and_enables_candidate_units_conditionally(self) -> None:
        hook = HOOK.read_text(encoding="utf-8")
        candidate_gate = (
            'if [ -e "$repair_candidate_marker" ] || '
            '[ -L "$repair_candidate_marker" ]; then'
        )
        self.assertIn(candidate_gate, hook)
        self.assertIn("grep -Fxq 'kernaid.repair=fstab-v1'", hook)
        self.assertEqual(
            hook.count("systemctl enable kernaid-rescue-repaird.socket"), 1
        )
        self.assertEqual(
            hook.count("systemctl enable kernaid-rescue-repaird.service"), 0
        )
        self.assertLess(
            hook.index('if [ "$repair_candidate_enabled" = "1" ]; then'),
            hook.index("systemctl enable kernaid-rescue-repaird.socket"),
        )
        for token in (
            '"$repair_candidate_binary"',
            '"$repair_candidate_blockfd_probe"',
            '"$repair_candidate_service"',
            '"$repair_candidate_socket"',
            '"$repair_candidate_sysusers"',
            '"$repair_candidate_tmpfiles"',
            '"$repair_candidate_ui_dropin"',
            '"$repair_candidate_ready_dropin"',
        ):
            self.assertGreaterEqual(hook.count(token), 3, token)


if __name__ == "__main__":
    unittest.main()
