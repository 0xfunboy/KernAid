from __future__ import annotations

from collections import defaultdict
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch


REPO = Path(__file__).resolve().parents[3]
LIVE = REPO / "rescue/live-build/config/includes.chroot"
CANDIDATE = REPO / "rescue/live-build/candidate"
BUILD = REPO / "tools/build-rescue/build.sh"
HOOK = REPO / "rescue/live-build/config/hooks/live/0100-kernaid-safety.hook.chroot"
WORKFLOW = REPO / ".github/workflows/rescue-repair-candidate.yml"
REPAIR_SMOKE = REPO / "tools/build-rescue/qemu-repair-candidate-smoke.sh"
REPAIR_CONTROLLER = REPO / "tools/build-rescue/qemu-repair-candidate-pty.py"
READY_CHECK = LIVE / "usr/lib/kernaid/ready-check"
PHYSICAL_PARENT = REPO / "crates/broker/src/target_physical_parent.rs"
REPAIR_ENGINE = REPO / "crates/broker/src/rescue_repair_service_engine.rs"
RESCUE_SERVER = (
    LIVE / "usr/lib/kernaid/rescue_server.py"
)


def load_module(name: str, path: Path):
    specification = importlib.util.spec_from_file_location(name, path)
    if specification is None or specification.loader is None:
        raise AssertionError(f"cannot load {path}")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


rescue_server = load_module("kernaid_repair_candidate_packaging", RESCUE_SERVER)


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
    def test_batch_only_repair_readiness_is_pinned_and_socket_bound(self) -> None:
        shell = REPAIR_SMOKE.read_text(encoding="utf-8")
        controller = REPAIR_CONTROLLER.read_text(encoding="utf-8")
        ready = READY_CHECK.read_text(encoding="utf-8")

        self.assertIn(
            'readonly qualification_batch_child="${KERNAID_REPAIR_QUALIFICATION_BATCH_CHILD:-}"',
            shell,
        )
        self.assertIn("KERNAID_REPAIR_QUALIFICATION_BATCH_CHILD=v1", shell)
        self.assertIn(
            '[[ "$qualification_batch_child" == v1',
            shell,
        )
        self.assertEqual(
            shell.count(
                "name=opt/kernaid-repair-qualification-probe,string=v1"
            ),
            1,
        )
        for contract in (
            "--qualification-batch-child",
            "guest_readiness=repair-service-v1 guest_readiness_marker=",
            'case_without_readiness_marker="${case_output/',
            "guest_readiness_marker=$repair_readiness_marker ready=true",
        ):
            self.assertIn(contract, shell)
        for contract in (
            "REPAIR_QUALIFICATION_READY_PATTERN",
            "REPAIR_QUALIFICATION_GLOBAL_READY_PATTERN",
            "REPAIR_QUALIFICATION_READY_THEN_GLOBAL_PATTERN",
            'ClosedFailure("readiness", "repair-marker-invalid")',
            "guest_readiness_marker={REPAIR_QUALIFICATION_READY_MARKER}",
        ):
            self.assertIn(contract, controller)
        marker_gate = ready[
            ready.index("repair_qualification_smoke=0") :
            ready.index("fail_vaultd_startup()")
        ]
        self.assertIn(
            "/sys/firmware/qemu_fw_cfg/by_name/opt/"
            "kernaid-repair-qualification-probe/raw",
            marker_gate,
        )
        for contract in (
            "os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW",
            "stat.S_ISREG(metadata.st_mode)",
            "metadata.st_uid != 0",
            "metadata.st_gid != 0",
            "metadata.st_nlink != 1",
            "stat.S_IMODE(metadata.st_mode) & 0o222",
            "metadata.st_size not in (0, 2, 3)",
            'payload not in (b"v1", b"v1\\0")',
        ):
            self.assertIn(contract, marker_gate)

        repair_gate_start = ready.index(
            'if [ "$repair_qualification_smoke" = "1" ]; then'
        )
        repair_gate_end = ready.index('script_path="', repair_gate_start)
        repair_gate = ready[repair_gate_start:repair_gate_end]
        self.assertLess(
            ready.index("KERNAID_RESCUE_APPLICATION_RELAY_READY"),
            repair_gate_start,
        )
        for contract in (
            "kernaid-repair-client",
            "kernaid-rescue-repaird.socket",
            "ActiveState",
            "SubState",
            "listening) ;;",
            "/run/kernaid-rescue-repair.sock",
            '0:${repair_client_group_id}:660:1',
            "KERNAID_RESCUE_REPAIR_QUALIFICATION_READY_V1",
            "full_readiness=separate",
            "echo KERNAID_RESCUE_READY",
            "exit 0",
        ):
            self.assertIn(contract, repair_gate)
        self.assertNotIn("listening|running", repair_gate)
        self.assertGreater(
            ready.rindex("echo KERNAID_RESCUE_READY"),
            ready.index("tauri_guest_attestation"),
        )

    def test_fleet_repair_local_relay_preserves_exact_action_binding(self) -> None:
        intent = {
            "schema": rescue_server.FLEET_REPAIR_INTENT_SCHEMA,
            "deviceId": "KA-" + "1" * 24,
            "workOrderId": "wo-rescue-1",
            "leaseId": "lease-rescue-1",
            "executionId": "exec_rescue_1",
            "actionId": "linux.ext4.fsck-preen-with-undo.v1",
            "actionVersion": 1,
            "risk": "R3",
            "state": "awaiting-approval",
            "leaseExpiresAt": "2026-09-01T01:05:00Z",
            "evidence": {
                "preparedId": "Q-" + "2" * 32,
                "sessionId": "S-" + "3" * 32,
                "planId": "P-" + "4" * 32,
                "planSha256": "5" * 64,
                "targetSha256": "6" * 64,
                "beforeSha256": "7" * 64,
                "afterSha256": "8" * 64,
                "diffSha256": "9" * 64,
                "backupLocator": "vault://repair/B-" + "a" * 32,
                "approvalSequence": 1,
                "evidenceSha256": "b" * 64,
            },
            "confirmationRequired": "REPAIR EXT4 OFFLINE",
        }
        response = {
            "apiVersion": rescue_server.FLEET_REPAIR_LOCAL_API_VERSION,
            "operation": "status",
            "outcome": "ok",
            "intent": intent,
        }
        rescue_server._validate_fleet_repair_response(response, "status")
        for changed in (
            {**intent, "risk": "R2"},
            {**intent, "confirmationRequired": "DISABILITA VOCE FSTAB"},
            {**intent, "evidence": None},
            {**intent, "leaseId": "lease forbidden"},
        ):
            with self.subTest(changed=changed):
                with self.assertRaises(rescue_server.FleetRepairRelayError):
                    rescue_server._validate_fleet_repair_response(
                        {**response, "intent": changed}, "status"
                    )

        with self.assertRaises(rescue_server.FleetRepairRelayError):
            rescue_server._validate_fleet_repair_response(
                {**response, "operation": "submit"}, "status"
            )

    def test_resolver_link_relay_is_path_free_and_exact(self) -> None:
        target = {
            "scanFingerprint": "scan:" + "1" * 64,
            "targetFingerprint": "sha256:" + "2" * 64,
            "targetId": "target:" + "3" * 64,
        }
        prepare = {
            "apiVersion": rescue_server.REPAIR_API_VERSION,
            "requestId": "R-10000000-0000-0000-0000-000000000001",
            "operation": "repair.resolver-link.prepare",
            "target": target,
        }
        rescue_server._validate_repair_request(prepare)
        approve = {
            "apiVersion": rescue_server.REPAIR_API_VERSION,
            "requestId": "R-10000000-0000-0000-0000-000000000002",
            "operation": "repair.resolver-link.approve",
            "preparedId": "Q-" + "4" * 32,
            "sessionId": "S-" + "5" * 32,
            "planId": "P-" + "6" * 32,
            "planHash": "sha256:" + "7" * 64,
            "approvalId": "A-" + "8" * 32,
            "approvalSequence": 1,
            "typedConfirmation": "RESTORE RESOLVER LINK",
        }
        rescue_server._validate_repair_request(approve)
        with self.assertRaises(rescue_server.RepairRelayError):
            rescue_server._validate_repair_request(
                {**prepare, "path": "/etc/resolv.conf"}
            )

        detail = {
            "kind": "resolver-link-prepared",
            "preparedId": approve["preparedId"],
            "sessionId": approve["sessionId"],
            "planId": approve["planId"],
            "planHash": approve["planHash"],
            "targetFingerprint": target["targetFingerprint"],
            "beforeSha256": "sha256:" + "9" * 64,
            "afterSha256": "sha256:" + "a" * 64,
            "diffSha256": "sha256:" + "b" * 64,
            "resourceId": "rescue:selected-linux-root:etc/resolver-link",
            "backupLocator": "vault://repair/B-" + "c" * 32,
            "actionId": "linux.network.restore-resolver-link.v1",
            "risk": "R2",
            "backup": {"state": "reserved", "vaultDistinct": True},
            "nextApprovalSequence": 1,
            "confirmationRequired": "RESTORE RESOLVER LINK",
        }
        self.assertTrue(rescue_server._validate_repair_prepared_detail(detail))
        self.assertFalse(
            rescue_server._validate_repair_prepared_detail(
                {**detail, "resourceId": "rescue:selected-linux-root:etc/fstab"}
            )
        )

    def test_crypttab_rollback_relay_is_exact_and_cross_binding_fails(self) -> None:
        source = {
            "reservationId": "B-0123456789abcdef0123456789abcdef",
            "transactionBindingSha256": "sha256:" + "5" * 64,
        }
        prepare = {
            "apiVersion": rescue_server.ROLLBACK_API_VERSION,
            "requestId": "R-10000000-0000-0000-0000-000000000001",
            "operation": "repair.crypttab.rollback.prepare",
            "source": source,
        }
        rescue_server._validate_repair_request(prepare)
        approve = {
            **prepare,
            "requestId": "R-10000000-0000-0000-0000-000000000002",
            "operation": "repair.crypttab.rollback.approve",
            "preparedId": "Q-" + "1" * 32,
            "rollbackId": "RB-" + "2" * 32,
            "sessionId": "S-" + "3" * 32,
            "planId": "P-" + "4" * 32,
            "planHash": "sha256:" + "6" * 64,
            "approvalId": "A-" + "7" * 32,
            "approvalSequence": 2,
            "typedConfirmation": "RIPRISTINA CRYPTTAB ORIGINALE",
        }
        rescue_server._validate_repair_request(approve)
        crossed = {**approve, "typedConfirmation": "RIPRISTINA FSTAB ORIGINALE"}
        with self.assertRaises(rescue_server.RepairRelayError):
            rescue_server._validate_repair_request(crossed)

        detail = {
            "kind": "crypttab-rollback-prepared",
            "preparedId": approve["preparedId"],
            "rollbackId": approve["rollbackId"],
            "sessionId": approve["sessionId"],
            "planId": approve["planId"],
            "planHash": approve["planHash"],
            "targetFingerprint": "sha256:" + "8" * 64,
            "source": source,
            "resourceId": "rescue:selected-linux-root:etc/crypttab",
            "backupLocator": "vault://repair/" + source["reservationId"],
            "actionId": "linux.crypttab.disable-missing-source.v1",
            "risk": "R2",
            "nextApprovalSequence": 2,
            "confirmationRequired": "RIPRISTINA CRYPTTAB ORIGINALE",
        }
        self.assertTrue(rescue_server._validate_rollback_prepared_detail(detail))
        self.assertFalse(
            rescue_server._validate_rollback_prepared_detail(
                {**detail, "kind": "fstab-rollback-prepared"}
            )
        )

    def test_vault_gate_preserves_timeout_and_closes_other_failures(self) -> None:
        cases = (
            ("TIMEOUT", 504, "timeout", 504),
            ("UNAVAILABLE", 503, "relay-unavailable", 503),
        )
        for source_code, source_status, expected_code, expected_status in cases:
            with self.subTest(source_code=source_code):
                failure = rescue_server.ApplicationRelayError(
                    source_code, source_status
                )
                with patch.object(
                    rescue_server, "_application_status", side_effect=failure
                ):
                    with self.assertRaises(
                        rescue_server.RepairRelayError
                    ) as raised:
                        rescue_server.require_unlocked_repair_vault(1.0)
                self.assertEqual(raised.exception.code, expected_code)
                self.assertEqual(raised.exception.status, expected_status)

    def test_locked_vault_cannot_activate_the_repair_recovery_barrier(self) -> None:
        source = RESCUE_SERVER.read_text(encoding="utf-8")
        gate = source.index("def require_unlocked_repair_vault(")
        handler = source.index("def _handle_repair_post(")
        status_call = source.index("status = _application_status(deadline)", gate)
        locked_check = source.index(
            'status["payload"]["vaultState"] != "unlocked"', gate
        )
        require = source.index("require_unlocked_repair_vault(deadline)", handler)
        relay = source.index("response = relay_repair_request(", handler)
        self.assertLess(gate, handler)
        self.assertLess(status_call, locked_check)
        self.assertLess(require, relay)
        self.assertIn(
            'raise RepairRelayError("relay-unavailable", 503)',
            source[gate:handler],
        )

    def test_candidate_workflow_is_manual_and_promotes_only_after_the_gate(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        build, qualification = workflow.split("  qualified-repair-release:\n", 1)
        self.assertIn("on:\n  workflow_dispatch:\n", workflow)
        self.assertNotIn("\n  push:", workflow)
        self.assertIn("node-version: 24.18.0", workflow)
        self.assertIn("KERNAID_REPAIR_CANDIDATE=1", workflow)
        self.assertIn("--features rescue-fstab-production-candidate", workflow)
        self.assertIn(
            "rescue-fstab-production-candidate,rescue-crypttab-production-candidate",
            workflow,
        )
        self.assertEqual(
            workflow.count(
                "rescue-fstab-production-candidate,"
                "rescue-crypttab-production-candidate,"
                "rescue-ext4-fsck-production-candidate"
            ),
            2,
        )
        self.assertEqual(workflow.count("--features custom-protocol"), 1)
        self.assertIn("-p kernaid-linux-blockfd", workflow)
        self.assertIn("KERNAID_BLOCKFD_PROBE_BINARY=", workflow)
        self.assertIn("experimental-fleet-signing", workflow)
        self.assertIn("-p kernaid-fleet-resident-work-orders", workflow)
        self.assertIn("--features rescue-fleet-service", workflow)
        self.assertIn("--bin kernaid-fleet-rescue-repair-bridge", workflow)
        self.assertIn("KERNAID_FLEET_RESCUE_REPAIR_BINARY=", workflow)
        self.assertEqual(workflow.count("./tools/build-rescue/qemu-smoke.sh"), 2)
        self.assertIn("QEMU UEFI Secure Boot candidate smoke test", workflow)
        self.assertIn("./tools/build-rescue/qemu-smoke.sh secureboot", workflow)
        self.assertNotIn("./tools/build-rescue/qemu-smoke.sh uefi", workflow)
        self.assertIn("name: KernAid-Rescue-amd64-repair-candidate", build)
        for forbidden in ("catalog-entry", "qualified-release", "deploy-pages"):
            self.assertNotIn(forbidden, build)
        self.assertIn("needs: build-and-smoke-test", qualification)
        self.assertIn("repair-qualification.py verify", qualification)
        self.assertIn("name: KernAid-Rescue-Repair-amd64-qualified", qualification)

    def test_default_profile_contains_no_candidate_artifact_or_client_group(self) -> None:
        absent = (
            LIVE / "usr/lib/kernaid/kernaid-rescue-repaird",
            LIVE / "usr/lib/kernaid/kernaid-fleet-rescue-repair-bridge",
            LIVE / "usr/lib/kernaid/kernaid-blockfd-probe",
            LIVE / "usr/lib/kernaid/repair-candidate-image-v1",
            LIVE / "etc/systemd/system/kernaid-rescue-repaird.service",
            LIVE / "etc/systemd/system/kernaid-rescue-repaird.socket",
            LIVE / "etc/systemd/system/kernaid-fleet-rescue-repair.service",
            LIVE / "etc/systemd/system/kernaid-fleet-rescue-repair.socket",
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
        self.assertNotIn("kernaid-fleet", base_sysusers)
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
            'fleet_rescue_binary="${KERNAID_FLEET_RESCUE_REPAIR_BINARY:-'
            '$repo_dir/target/release/kernaid-fleet-rescue-repair-bridge}"',
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
            'validate_amd64_elf "$fleet_rescue_binary" '
            '"Rescue Fleet repair bridge"',
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
        self.assertIn(
            'bootappend_compat="$bootappend_live nomodeset kernaid.graphics=compat"',
            source,
        )
        self.assertIn('--bootappend-live-failsafe "$bootappend_compat"', source)
        self.assertIn('"$repaird_destination" \\', source)
        self.assertIn('"$fleet_rescue_destination" \\', source)
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
                "/usr/sbin/e2fsck",
                "/usr/sbin/e2undo",
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
        self.assertEqual(
            service_config["LoadCredential"],
            [
                "kernaid-repair-fault:"
                "/sys/firmware/qemu_fw_cfg/by_name/opt/io.systemd.credentials/"
                "kernaid-repair-fault/raw"
            ],
        )
        self.assertEqual(
            service_config["SetCredential"],
            ["kernaid-repair-fault:none-v1"],
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

    def test_fault_credential_surface_is_candidate_only(self) -> None:
        stable_text = "\n".join(
            path.read_text(encoding="utf-8", errors="ignore")
            for path in LIVE.rglob("*")
            if path.is_file() and not path.is_symlink()
        )
        for forbidden in (
            "kernaid-repair-fault",
            "terminate-after-pending-v1",
            "fail-after-installed-v1",
        ):
            self.assertNotIn(forbidden, stable_text)

        candidate_service = (
            CANDIDATE / "kernaid-rescue-repaird.service"
        ).read_text(encoding="utf-8")
        engine = REPAIR_ENGINE.read_text(encoding="utf-8")
        self.assertIn(
            "LoadCredential wins only when that exact sysfs file exists",
            candidate_service,
        )
        self.assertIn("OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW", engine)
        self.assertNotIn("File::open(&path)", engine)

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

    def test_only_closed_local_services_get_candidate_client_group(self) -> None:
        sysusers = (CANDIDATE / "kernaid-repair-candidate.conf").read_text(
            encoding="utf-8"
        ).splitlines()
        self.assertIn("g kernaid-repair-client - -", sysusers)
        self.assertIn(
            'u kernaid-fleet - "KernAid Rescue Fleet work-order bridge" '
            "/nonexistent /usr/sbin/nologin",
            sysusers,
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

    def test_fleet_bridge_is_repair_only_and_has_narrow_process_authority(self) -> None:
        socket = unit_directives(
            CANDIDATE / "kernaid-fleet-rescue-repair.socket"
        )
        service = unit_directives(
            CANDIDATE / "kernaid-fleet-rescue-repair.service"
        )
        conditions = ["boot=live", "kernaid.repair=fstab-v1"]
        self.assertEqual(socket["Unit"]["ConditionKernelCommandLine"], conditions)
        self.assertEqual(service["Unit"]["ConditionKernelCommandLine"], conditions)
        self.assertEqual(
            socket["Socket"]["ListenSequentialPacket"],
            ["/run/kernaid-fleet-rescue-repair.sock"],
        )
        self.assertEqual(socket["Socket"]["FileDescriptorName"], ["fleet-rescue-api"])
        self.assertEqual(socket["Socket"]["SocketGroup"], ["kernaid-repair-client"])
        self.assertEqual(service["Service"]["User"], ["kernaid-fleet"])
        self.assertEqual(service["Service"]["Group"], ["kernaid-repair-client"])
        self.assertEqual(service["Service"]["SupplementaryGroups"], ["kernaid-vault"])
        self.assertEqual(service["Service"]["CapabilityBoundingSet"], [""])
        self.assertEqual(service["Service"]["AmbientCapabilities"], [""])
        self.assertEqual(
            service["Service"]["RestrictAddressFamilies"],
            ["AF_UNIX AF_INET AF_INET6"],
        )
        self.assertIn(
            "/etc/kernaid/fleet-rescue-repair.json",
            service["Unit"]["ConditionPathExists"],
        )
        self.assertNotIn("LoadCredential", service["Service"])
        self.assertNotIn("Environment", service["Service"])

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
        self.assertEqual(
            hook.count("systemctl enable kernaid-fleet-rescue-repair.socket"), 1
        )
        self.assertEqual(
            hook.count("systemctl enable kernaid-fleet-rescue-repair.service"), 1
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
            '"$fleet_repair_binary"',
            '"$fleet_repair_service"',
            '"$fleet_repair_socket"',
            '"$repair_candidate_sysusers"',
            '"$repair_candidate_tmpfiles"',
            '"$repair_candidate_ui_dropin"',
            '"$repair_candidate_ready_dropin"',
        ):
            self.assertGreaterEqual(hook.count(token), 3, token)


if __name__ == "__main__":
    unittest.main()
