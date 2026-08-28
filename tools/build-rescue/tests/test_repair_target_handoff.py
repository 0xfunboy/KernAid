from __future__ import annotations

import array
import fcntl
from importlib.util import module_from_spec, spec_from_file_location
import hashlib
import json
import os
from pathlib import Path
import socket
import threading
import unittest
from unittest.mock import patch


REPO_DIR = Path(__file__).resolve().parents[3]
LIVE_LIB = REPO_DIR / "rescue/live-build/config/includes.chroot/usr/lib/kernaid"
HANDOFF_PATH = LIVE_LIB / "repair_target_handoff.py"
SERVER_PATH = LIVE_LIB / "rescue_server.py"


def load_module(name: str, path: Path) -> object:
    spec = spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


handoff = load_module("kernaid_repair_target_handoff_tests", HANDOFF_PATH)
rescue_server = load_module("kernaid_rescue_server_handoff_tests", SERVER_PATH)

REQUEST = {
    "apiVersion": "kernaid.dev/rescue-target-capability/v1alpha2",
    "scanFingerprint": "scan:" + "1" * 64,
    "targetId": "target:" + "2" * 64,
    "requestId": "R-12345678-1234-1234-1234-123456789abc",
    "operation": "target.readonly.acquire",
}
RECOVERY_FINGERPRINT = "recovery:" + "4" * 64
RECOVERY_REQUEST = {
    "apiVersion": REQUEST["apiVersion"],
    "requestId": REQUEST["requestId"],
    "operation": "target.recovery.readonly.acquire",
    "recoveryFingerprint": RECOVERY_FINGERPRINT,
}

BLOCK_INVENTORY = json.dumps(
    {
        "blockdevices": [
            {
                "name": "sda",
                "uuid": "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE",
                "children": [
                    {
                        "name": "sda2",
                        "uuid": "11111111-2222-3333-4444-555555555555",
                    },
                    {
                        "name": "sda3",
                        "uuid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                    },
                ],
            }
        ]
    },
    sort_keys=True,
    separators=(",", ":"),
)

IDENTITY_OBSERVATIONS: list[dict[str, object]] = [
    {
        "collector": "system.hostname",
        "trust": "observed-untrusted",
        "output": "kernaid-fixture\n",
        "success": True,
        "truncated": False,
    },
    {
        "collector": "linux.block.inventory",
        "trust": "observed-untrusted",
        "output": BLOCK_INVENTORY,
        "success": True,
        "truncated": False,
    },
]


def _candidate(family: str = "linux") -> dict[str, object]:
    return {
        "targetId": REQUEST["targetId"],
        "sourceRef": "disk-1/volume-1",
        "diskId": "disk:" + "3" * 64,
        "osFamilyHint": family,
        "confidence": "low",
        "status": "unverified-installation-candidate",
        "detectionBasis": [f"{family}-filesystem-signature"],
        "requiresUnlock": False,
        "inspectionMode": "metadata-only-no-mount",
        "selectionEligible": True,
    }


def _selection(candidate: dict[str, object]) -> dict[str, object]:
    return {
        "apiVersion": "kernaid.dev/rescue-target-scan/v1alpha1",
        "status": "observe-target-validated",
        "scanFingerprint": REQUEST["scanFingerprint"],
        "target": candidate,
        "claims": {
            "installedOsConfirmed": False,
            "filesystemContentInspected": False,
            "mountOperationPerformed": False,
            "mutationPerformed": False,
        },
    }


REQUEST["targetFingerprint"] = rescue_server.rescue_target_fingerprint(
    rescue_server.inventory_fingerprint(IDENTITY_OBSERVATIONS),
    str(REQUEST["scanFingerprint"]),
    _candidate(),
)


def _resolution(candidate: dict[str, object], filesystem: str = "ext4") -> dict[str, object]:
    parent_identity = {
        "name": "sda",
        "maj:min": "8:0",
        "type": "disk",
        "size": 2 * 1024 * 1024,
        "ro": False,
        "rm": False,
        "tran": "sata",
        "fstype": None,
        "fsver": None,
        "mountpoints": [None],
        "uuid": None,
        "partuuid": None,
        "ptuuid": "fixture-table",
        "pttype": "gpt",
        "parttype": None,
        "serial": "fixture-serial",
        "wwn": None,
    }
    return {
        "candidate": candidate,
        "deviceIdentity": {
            "name": "sda2",
            "maj:min": "8:2",
            "type": "part",
            "size": 1024 * 1024,
            "ro": False,
            "rm": False,
            "tran": "sata",
            "fstype": filesystem,
            "fsver": "1.0",
            "mountpoints": [None],
            "uuid": "11111111-2222-3333-4444-555555555555",
            "partuuid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "ptuuid": "fixture-table",
            "pttype": "gpt",
            "parttype": None,
            "serial": None,
            "wwn": None,
        },
        "majorMinor": "8:2",
        "physicalParent": {
            "deviceIdentity": parent_identity,
            "majorMinor": "8:0",
            "kernelKind": "disk",
        },
        "filesystem": filesystem,
        "kernelKind": "part",
        "leaf": True,
        "directOnDisk": True,
        "recoveryFingerprint": RECOVERY_FINGERPRINT,
        "recoveryUnique": True,
        "topologyKinds": ["disk", "part"],
        "topologyFilesystems": [filesystem],
        "associatedEfiSystemPartition": {"state": "not-present"},
    }


class FakeTargets:
    InventoryBusy = type("InventoryBusy", (Exception,), {})
    TargetScanBusy = type("TargetScanBusy", (Exception,), {})
    TargetScanError = type("TargetScanError", (Exception,), {})
    TargetSelectionError = type("TargetSelectionError", (Exception,), {})

    def __init__(self, *, family: str = "linux", filesystem: str = "ext4") -> None:
        candidate = _candidate(family)
        self.selection = _selection(candidate)
        self.resolution = _resolution(candidate, filesystem)
        self.calls = 0
        self.events: list[str] = []
        self.observations = [dict(item) for item in IDENTITY_OBSERVATIONS]

    def canonical_target_selection(self, value: object) -> str:
        return json.dumps(value, sort_keys=True, separators=(",", ":"))

    def validate_target_selection(
        self, value: object, request: dict[str, str]
    ) -> dict[str, object]:
        if not isinstance(value, dict) or request != {
            "scanFingerprint": REQUEST["scanFingerprint"],
            "targetId": REQUEST["targetId"],
        }:
            raise ValueError("invalid fixture selection")
        target = value.get("target")
        if not isinstance(target, dict):
            raise ValueError("invalid fixture target")
        return target

    def resolve_installed_target(
        self, request: dict[str, object], *, deadline: float
    ) -> tuple[dict[str, object], dict[str, object]]:
        self.calls += 1
        self.events.append("resolve")
        if request != {
            "scanFingerprint": REQUEST["scanFingerprint"],
            "targetId": REQUEST["targetId"],
        } or deadline <= 0:
            raise AssertionError("unexpected canonical resolver request")
        return self.selection, self.resolution

    def resolve_recovery_target(
        self, request: dict[str, object], *, deadline: float
    ) -> tuple[dict[str, object], dict[str, object]]:
        self.calls += 1
        self.events.append("recover")
        if request != {"recoveryFingerprint": RECOVERY_FINGERPRINT} or deadline <= 0:
            raise AssertionError("unexpected recovery resolver request")
        return self.selection, self.resolution

    def inventory(self, *, deadline: float) -> list[dict[str, object]]:
        if deadline <= 0:
            raise AssertionError("unexpected inventory deadline")
        self.events.append("inventory")
        return [dict(item) for item in self.observations]

    def is_identity_observation(self, collector: str) -> bool:
        return rescue_server.is_identity_observation(collector)

    def inventory_fingerprint(self, observations: list[dict[str, object]]) -> str:
        return rescue_server.inventory_fingerprint(observations)

    def rescue_target_fingerprint(
        self,
        runtime_inventory_fingerprint: str,
        scan_fingerprint: str,
        candidate: dict[str, object],
    ) -> str:
        return rescue_server.rescue_target_fingerprint(
            runtime_inventory_fingerprint, scan_fingerprint, candidate
        )


def _receive(connection: socket.socket) -> tuple[dict[str, object], list[int]]:
    item_size = array.array("i").itemsize
    payload, ancillary, flags, _address = connection.recvmsg(
        4096,
        socket.CMSG_SPACE(5 * item_size),
        socket.MSG_CMSG_CLOEXEC,
    )
    if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
        raise AssertionError("response was truncated")
    descriptors: list[int] = []
    for level, kind, data in ancillary:
        if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
            rights = array.array("i")
            rights.frombytes(data[: len(data) - len(data) % item_size])
            descriptors.extend(rights)
    if any(
        fcntl.fcntl(descriptor, fcntl.F_GETFD) & fcntl.FD_CLOEXEC == 0
        for descriptor in descriptors
    ):
        raise AssertionError("received descriptor is inheritable")
    return json.loads(payload.decode("utf-8")), descriptors


def _pipe_capability(payload: bytes) -> int:
    read_descriptor, write_descriptor = os.pipe()
    try:
        written = os.write(write_descriptor, payload)
        if written != len(payload):
            raise RuntimeError("short fixture pipe write")
    finally:
        os.close(write_descriptor)
    return read_descriptor


class RepairTargetHandoffTests(unittest.TestCase):
    def test_candidate_is_packaged_but_not_activated(self) -> None:
        systemd = (
            REPO_DIR
            / "rescue/live-build/config/includes.chroot/etc/systemd/system"
        )
        safety_hook = (
            REPO_DIR
            / "rescue/live-build/config/hooks/live/0100-kernaid-safety.hook.chroot"
        ).read_text(encoding="utf-8")
        helper = "/usr/lib/kernaid/repair_target_handoff.py"
        self.assertEqual(safety_hook.count(helper), 2)
        socket_path = systemd / "kernaid-rescue-target-capability.socket"
        service_path = systemd / "kernaid-rescue-target-capability@.service"
        self.assertTrue(socket_path.is_file())
        self.assertTrue(service_path.is_file())
        self.assertEqual(
            safety_hook.count(
                "/etc/systemd/system/kernaid-rescue-target-capability.socket"
            ),
            2,
        )
        self.assertEqual(
            safety_hook.count(
                "/etc/systemd/system/kernaid-rescue-target-capability@.service"
            ),
            2,
        )
        self.assertNotIn("systemctl enable kernaid-rescue-target", safety_hook)

        socket_unit = socket_path.read_text(encoding="utf-8")
        service_unit = service_path.read_text(encoding="utf-8")
        self.assertNotIn("[Install]", socket_unit)
        self.assertIn(
            "ListenSequentialPacket=/run/kernaid-rescue-target-capability.sock",
            socket_unit,
        )
        self.assertIn("Accept=yes", socket_unit)
        self.assertIn("FileDescriptorName=target-capability", socket_unit)
        self.assertIn("SocketMode=0660", socket_unit)
        self.assertIn("SocketUser=root", socket_unit)
        self.assertIn("SocketGroup=kernaid-repair", socket_unit)
        self.assertIn("kernaid-offline-inspector-key.service", socket_unit)
        self.assertIn("systemd-sysusers.service", socket_unit)

        self.assertIn(
            "ExecStart=/usr/bin/python3 -I -B "
            "/usr/lib/kernaid/repair_target_handoff.py",
            service_unit,
        )
        self.assertIn(
            "Environment=KERNAID_TARGET_ID_KEY_FILE="
            "/run/kernaid-offline-inspector/target-id.key",
            service_unit,
        )
        self.assertNotIn("KERNAID_REPAIR_BROKER_UID", service_unit)
        self.assertIn("User=root", service_unit)
        self.assertIn("Group=root", service_unit)
        self.assertIn("NoNewPrivileges=yes", service_unit)
        self.assertIn("PrivateMounts=yes", service_unit)
        self.assertIn("PrivateNetwork=yes", service_unit)
        self.assertIn("ProtectSystem=strict", service_unit)
        self.assertIn("ReadOnlyPaths=/run /dev", service_unit)
        self.assertIn("DevicePolicy=closed", service_unit)
        self.assertIn("DeviceAllow=block-* r", service_unit)
        self.assertIn("CapabilityBoundingSet=CAP_SYS_ADMIN", service_unit)
        self.assertIn("AmbientCapabilities=\n", service_unit)
        self.assertIn(
            "SystemCallFilter=@system-service fsopen fsconfig fsmount", service_unit
        )
        self.assertIn("SystemCallErrorNumber=EPERM", service_unit)
        self.assertIn("RestrictAddressFamilies=AF_UNIX", service_unit)
        self.assertIn("RestrictNamespaces=yes", service_unit)
        self.assertIn("kernaid-offline-inspector-key.service", service_unit)
        self.assertIn("systemd-sysusers.service", service_unit)

        accounts = (
            REPO_DIR
            / "rescue/live-build/config/includes.chroot/etc/sysusers.d/kernaid.conf"
        ).read_text(encoding="utf-8")
        self.assertIn(
            'u kernaid-repair - "KernAid Rescue repair broker" '
            "/nonexistent /usr/sbin/nologin",
            accounts,
        )
        self.assertNotIn("m kernaid-repair ", accounts)
        self.assertNotRegex(accounts, r"(?m)^m\s+\S+\s+kernaid-repair$")

        ready = (LIVE_LIB / "ready-check").read_text(encoding="utf-8")
        self.assertIn('$1 == "kernaid-repair"', ready)
        self.assertIn('$3 == $4 && $3 != 0 && $3 != 1000', ready)
        self.assertIn('$5 == "KernAid Rescue repair broker"', ready)
        self.assertIn('$6 == "/nonexistent"', ready)
        self.assertIn('$7 == "/usr/sbin/nologin"', ready)
        self.assertIn("count == 1", ready)
        self.assertIn('$4 != ""', ready)
        self.assertIn(
            'test "$repair_groups" = "kernaid-repair"',
            ready,
        )
        self.assertIn(
            "for repair_forbidden_member in \\",
            ready,
        )
        for identity in (
            "kernaid",
            "kernaid-rescue-ui",
            "kernaid-openai",
            "kernaid-openai-egress",
            "kernaid-application",
            "kernaid-codex",
        ):
            self.assertIn(f"    {identity}", ready)
        self.assertNotIn("systemctl start kernaid-rescue-target-capability", ready)
        self.assertNotIn(
            "systemctl show --property=ActiveState --value "
            "kernaid-rescue-target-capability.socket",
            ready,
        )

    def test_repair_broker_account_parser_is_closed(self) -> None:
        valid = (
            b"root:x:0:0:root:/root:/bin/bash\n"
            b"kernaid:x:1000:1000:KernAid live user:/home/kernaid:/bin/bash\n"
            b"kernaid-repair:!:992:992:KernAid Rescue repair broker:"
            b"/nonexistent:/usr/sbin/nologin\n"
        )
        self.assertEqual(handoff._repair_broker_uid_from_passwd(valid), 992)
        invalid = (
            valid.replace(b"992:992", b"992:991", 1),
            valid.replace(b"KernAid Rescue repair broker", b"repair", 1),
            valid.replace(b"/nonexistent", b"/home/repair", 1),
            valid.replace(b"/usr/sbin/nologin", b"/bin/sh", 1),
            valid.replace(b"992:992", b"0:0", 1),
            valid.replace(b"992:992", b"1000:1000", 1),
            valid.replace(b":992:992:", b":0992:992:", 1),
            valid + b"duplicate:x:992:991::/nonexistent:/usr/sbin/nologin\n",
            valid + b"duplicate:x:991:992::/nonexistent:/usr/sbin/nologin\n",
            valid
            + b"kernaid-repair:!:991:991:KernAid Rescue repair broker:"
            b"/nonexistent:/usr/sbin/nologin\n",
            valid.rstrip(b"\n"),
            valid + b"\n",
        )
        for payload in invalid:
            with self.subTest(payload=payload[-96:]):
                with self.assertRaises(RuntimeError):
                    handoff._repair_broker_uid_from_passwd(payload)
        with self.assertRaises(RuntimeError):
            handoff._read_root_owned_passwd("/tmp/passwd")

    def _exchange(
        self,
        service: object,
        request: dict[str, object],
        *,
        expected_uid: int | None = None,
        profile: str = "readonly",
    ) -> tuple[dict[str, object], list[int]]:
        client, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)

        def run() -> None:
            with server:
                handoff.serve_connection(
                    server,
                    os.getuid() if expected_uid is None else expected_uid,
                    service,
                    expected_local=None,
                    profile=profile,
                )

        thread = threading.Thread(target=run)
        thread.start()
        try:
            client.send(json.dumps(request, separators=(",", ":")).encode("utf-8"))
            response = _receive(client)
        finally:
            client.close()
            thread.join(timeout=2)
        self.assertFalse(thread.is_alive())
        return response

    def test_write_profile_is_separate_and_candidate_gated(self) -> None:
        systemd = REPO_DIR / "rescue/live-build/config/includes.chroot/etc/systemd/system"
        readonly = (systemd / "kernaid-rescue-target-capability@.service").read_text()
        write_socket = (systemd / "kernaid-rescue-target-write-capability.socket").read_text()
        write_service = (systemd / "kernaid-rescue-target-write-capability@.service").read_text()
        self.assertIn("KERNAID_TARGET_HANDOFF_PROFILE=readonly", readonly)
        self.assertIn("ListenSequentialPacket=/run/kernaid-rescue-target-write-capability.sock", write_socket)
        self.assertIn("SocketMode=0660", write_socket)
        self.assertIn("SocketGroup=kernaid-repair", write_socket)
        for unit in (write_socket, write_service):
            self.assertIn("ConditionKernelCommandLine=kernaid.repair=fstab-v1", unit)
            self.assertIn("ConditionPathExists=/usr/lib/kernaid/repair-candidate-image-v1", unit)
        self.assertIn("KERNAID_TARGET_HANDOFF_PROFILE=write", write_service)
        self.assertIn("DeviceAllow=block-* rw", write_service)
        self.assertIn("CapabilityBoundingSet=CAP_SYS_ADMIN", write_service)
        self.assertIn("SystemCallFilter=@system-service fsopen fsconfig fsmount", write_service)
        write_request = {"apiVersion": handoff.API_VERSION, "requestId": REQUEST["requestId"],
                         "operation": handoff.WRITE_OPERATION,
                         "reservationId": "B-" + "a" * 32,
                         "transactionBindingSha256": "b" * 64}
        self.assertEqual(handoff._decode_request(handoff._canonical(write_request), "write"), write_request)
        with self.assertRaises(handoff.HandoffFailure):
            handoff._decode_request(handoff._canonical(write_request), "readonly")
        with self.assertRaises(handoff.HandoffFailure):
            handoff._decode_request(handoff._canonical(REQUEST), "write")

    def test_write_acquire_consumes_lease_then_sends_only_detached_mount(self) -> None:
        targets = FakeTargets()
        service = handoff.RepairTargetHandoff(targets)
        request = {"apiVersion": handoff.API_VERSION, "requestId": REQUEST["requestId"],
                   "operation": handoff.WRITE_OPERATION, "reservationId": "B-" + "a" * 32,
                   "transactionBindingSha256": "b" * 64}
        claims = {"parentMajor": 8, "parentMinor": 0, "diskSequence": 77,
                  "mediaSectorCount": 4096, "logicalSectorBytes": 512,
                  "leafSectorCount": 2048}
        lease = {"recoveryFingerprint": RECOVERY_FINGERPRINT,
                 "leaseBindingSha256": "c" * 64}
        leaf, parent, mount = (_pipe_capability(b"L"), _pipe_capability(b"P"),
                               _pipe_capability(b"M"))
        with (patch.object(handoff, "_consume_write_lease", return_value=lease),
              patch.object(handoff, "_mountinfo_has_device", return_value=False),
              patch.object(handoff, "_open_bound_block_device", side_effect=[leaf, parent]),
              patch.object(handoff, "_probe_physical_parent_claims",
                           return_value=claims) as probe,
              patch.object(handoff, "_revalidate_block_pair", return_value=None),
              patch.object(handoff, "_create_detached_ext4_write_mount", return_value=mount),
              patch.object(handoff, "_assert_detached_ext4_write_mount_fd", return_value=None)):
            response, descriptors = self._exchange(service, request, profile="write")
        try:
            self.assertEqual(targets.calls, 3)
            self.assertEqual(response["capability"], handoff.WRITE_CAPABILITY)
            self.assertEqual(response["descriptor"], {"type": handoff.WRITE_DESCRIPTOR_TYPE, "count": 1})
            self.assertEqual(len(descriptors), 1)
            self.assertEqual(os.read(descriptors[0], 1), b"M")
            self.assertEqual(probe.call_count, 2)
            for call in probe.call_args_list:
                self.assertEqual(call.args[2:], (1024 * 1024, 2 * 1024 * 1024, 8, 0))
        finally:
            for descriptor in descriptors:
                os.close(descriptor)

    def test_vault_consume_retries_only_one_authenticated_stale_state(self) -> None:
        reservation, binding = "B-" + "a" * 32, "b" * 64
        replies = [
            {"apiVersion": handoff.VAULT_API_VERSION, "requestId": "placeholder",
             "stateVersion": 9, "operation": handoff.VAULT_WRITE_OPERATION,
             "outcome": "error", "error": "STALE_STATE"},
            {"apiVersion": handoff.VAULT_API_VERSION, "requestId": "placeholder",
             "stateVersion": 10, "operation": handoff.VAULT_WRITE_OPERATION,
             "outcome": "ok", "payload": {"receipt": True}},
        ]
        requests = []

        def exchange(request, _deadline):
            requests.append(request)
            reply = replies.pop(0)
            reply["requestId"] = request["requestId"]
            return reply

        with (patch.object(handoff, "_vault_exchange", side_effect=exchange),
              patch.object(handoff, "_validate_write_lease", return_value={"ok": "yes"})):
            self.assertEqual(handoff._consume_write_lease(reservation, binding,
                                                          handoff.time.monotonic() + 1),
                             {"ok": "yes"})
        self.assertEqual([item["expectedStateVersion"] for item in requests], [0, 9])
        self.assertNotEqual(requests[0]["requestId"], requests[1]["requestId"])

        bad = {"apiVersion": handoff.VAULT_API_VERSION,
               "requestId": "placeholder", "stateVersion": 1,
               "operation": handoff.VAULT_WRITE_OPERATION,
               "outcome": "error", "error": "IO_FAILED"}
        with patch.object(handoff, "_vault_exchange",
                          side_effect=lambda request, _deadline: dict(bad, requestId=request["requestId"])) as mocked:
            with self.assertRaises(handoff.HandoffFailure):
                handoff._consume_write_lease(reservation, binding, handoff.time.monotonic() + 1)
        self.assertEqual(mocked.call_count, 1)

    def test_success_transfers_the_exact_ordered_read_only_bundle_v2(
        self,
    ) -> None:
        targets = FakeTargets()
        service = handoff.RepairTargetHandoff(targets)
        leaf_descriptor = _pipe_capability(b"L")
        parent_descriptor = _pipe_capability(b"P")
        parent_identity_descriptor = os.open(
            "/dev/null", os.O_PATH | os.O_CLOEXEC | os.O_NOFOLLOW
        )
        mount_descriptor = _pipe_capability(b"M")
        with (
            patch.object(handoff, "_mountinfo_has_device", return_value=False),
            patch.object(
                handoff,
                "_open_bound_block_device",
                side_effect=[leaf_descriptor, parent_descriptor],
            ),
            patch.object(handoff, "_assert_block_fd", return_value=None),
            patch.object(
                handoff, "_assert_readonly_block_capability", return_value=None
            ),
            patch.object(
                handoff,
                "_probe_physical_parent_claims",
                return_value={
                    "parentMajor": 8,
                    "parentMinor": 0,
                    "diskSequence": 77,
                    "mediaSectorCount": 4096,
                    "logicalSectorBytes": 512,
                    "leafSectorCount": 2048,
                },
            ),
            patch.object(
                handoff,
                "_open_bound_block_identity",
                return_value=parent_identity_descriptor,
            ),
            patch.object(handoff, "_assert_block_identity_fd", return_value=None),
            patch.object(handoff, "_revalidate_final_bundle", return_value=None),
            patch.object(
                handoff,
                "_create_detached_ext4_mount",
                return_value=mount_descriptor,
            ),
            patch.object(
                handoff, "_assert_detached_ext4_mount_fd", return_value=None
            ),
        ):
            response, descriptors = self._exchange(service, REQUEST)
        try:
            self.assertEqual(targets.calls, 3)
            self.assertEqual(
                targets.events, ["resolve", "inventory", "resolve", "resolve"]
            )
            self.assertEqual(
                handoff.SOCKET_PATH,
                "/run/kernaid-rescue-target-capability.sock",
            )
            self.assertEqual(
                response["apiVersion"],
                "kernaid.dev/rescue-target-capability/v1alpha2",
            )
            self.assertEqual(response["outcome"], "ok")
            self.assertEqual(response["requestId"], REQUEST["requestId"])
            self.assertEqual(response["operation"], REQUEST["operation"])
            self.assertEqual(
                response["scanFingerprint"], REQUEST["scanFingerprint"]
            )
            self.assertEqual(response["targetId"], REQUEST["targetId"])
            self.assertEqual(
                response["targetFingerprint"], REQUEST["targetFingerprint"]
            )
            self.assertEqual(
                response["recoveryFingerprint"], RECOVERY_FINGERPRINT
            )
            self.assertEqual(
                response["capability"],
                "linux-ext4-direct-leaf-readonly-bundle-v2",
            )
            self.assertEqual(
                response["descriptors"],
                [
                    {"index": 0, "type": "selected-target-block-readonly"},
                    {"index": 1, "type": "physical-parent-block-identity-path"},
                    {"index": 2, "type": "uuid-inventory-memfd-sealed"},
                    {
                        "index": 3,
                        "type": "selected-target-ext4-mount-readonly-detached",
                    },
                ],
            )
            self.assertEqual(
                response["physicalParentClaims"],
                {
                    "parentMajor": 8,
                    "parentMinor": 0,
                    "diskSequence": 77,
                    "mediaSectorCount": 4096,
                    "logicalSectorBytes": 512,
                    "leafSectorCount": 2048,
                },
            )
            self.assertEqual(
                set(response),
                {
                    "apiVersion",
                    "requestId",
                    "operation",
                    "outcome",
                    "scanFingerprint",
                    "targetFingerprint",
                    "targetId",
                    "recoveryFingerprint",
                    "capability",
                    "descriptors",
                    "physicalParentClaims",
                    "uuidInventory",
                },
            )
            self.assertLess(
                len(json.dumps(response, sort_keys=True, separators=(",", ":"))),
                2048,
            )
            self.assertEqual(len(descriptors), 4)
            self.assertEqual(os.read(descriptors[0], 1), b"L")
            with self.assertRaises(OSError):
                os.read(descriptors[1], 1)
            self.assertEqual(
                fcntl.fcntl(descriptors[1], fcntl.F_GETFL) & os.O_PATH,
                os.O_PATH,
            )
            with self.assertRaises(handoff.HandoffFailure):
                handoff._probe_u64(descriptors[1], handoff.BLKGETDISKSEQ)
            uuid_payload = os.pread(descriptors[2], 1024, 0)
            self.assertEqual(
                json.loads(uuid_payload.decode("ascii")),
                {
                    "schema": "kernaid.dev/rescue-uuid-inventory/v1",
                    "uuids": [
                        "11111111-2222-3333-4444-555555555555",
                        "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                    ],
                },
            )
            self.assertEqual(
                response["uuidInventory"],
                {
                    "schema": "kernaid.dev/rescue-uuid-inventory/v1",
                    "entryCount": 2,
                    "byteLength": len(uuid_payload),
                    "sha256": hashlib.sha256(uuid_payload).hexdigest(),
                },
            )
            self.assertEqual(
                handoff.fcntl.fcntl(descriptors[2], handoff.F_GET_SEALS),
                handoff.UUID_INVENTORY_SEALS,
            )
            with self.assertRaises(OSError):
                os.pwrite(descriptors[2], b"x", 0)
            with self.assertRaises(OSError):
                os.ftruncate(descriptors[2], 0)
            self.assertEqual(os.read(descriptors[3], 1), b"M")
            serialized = json.dumps(response, separators=(",", ":"))
            for forbidden in (
                "/dev/",
                "sda2",
                "8:2",
                "11111111-2222-3333-4444-555555555555",
                "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            ):
                self.assertNotIn(forbidden, serialized)
        finally:
            for descriptor in descriptors:
                os.close(descriptor)

    def test_uuid_inventory_bounds_and_canonical_maximum_are_exact(self) -> None:
        self.assertEqual(
            handoff._normalize_uuid_inventory(
                [
                    "BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB",
                    "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                    "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
                ]
            ),
            (
                "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
            ),
        )
        for values in (
            [],
            ["-a"],
            ["a-"],
            ["g"],
            ["a" * 129],
            ["a"] * 4097,
        ):
            with self.subTest(values=(len(values), values[:1])):
                with self.assertRaises(handoff.HandoffFailure):
                    handoff._normalize_uuid_inventory(values)
        maximum = tuple(f"{index:04x}" + "a" * 124 for index in range(4096))
        self.assertEqual(
            len(handoff._uuid_inventory_payload(maximum)),
            handoff.MAX_UUID_INVENTORY_BYTES,
        )
        maximum_response = {
            "apiVersion": handoff.API_VERSION,
            "requestId": REQUEST["requestId"],
            "operation": handoff.RECOVERY_OPERATION,
            "scanFingerprint": REQUEST["scanFingerprint"],
            "targetFingerprint": REQUEST["targetFingerprint"],
            "targetId": REQUEST["targetId"],
            "recoveryFingerprint": RECOVERY_FINGERPRINT,
            "outcome": "ok",
            "capability": handoff.BUNDLE_CAPABILITY,
            "descriptors": handoff._descriptor_manifest(),
            "physicalParentClaims": {
                "parentMajor": 4_294_967_295,
                "parentMinor": 4_294_967_295,
                "diskSequence": 18_446_744_073_709_551_615,
                "mediaSectorCount": 36_028_797_018_963_967,
                "logicalSectorBytes": 65_536,
                "leafSectorCount": 36_028_797_018_963_967,
            },
            "uuidInventory": {
                "schema": handoff.UUID_INVENTORY_SCHEMA,
                "entryCount": handoff.MAX_UUID_INVENTORY_ENTRIES,
                "byteLength": handoff.MAX_UUID_INVENTORY_BYTES,
                "sha256": "f" * 64,
            },
        }
        self.assertLess(
            len(handoff._canonical(maximum_response)), handoff.MAX_RESPONSE_BYTES
        )

    def test_parent_claims_are_derived_from_both_readable_block_fds(self) -> None:
        with (
            patch.object(
                handoff,
                "_probe_u64",
                side_effect=[77, 77, 1024 * 1024, 2 * 1024 * 1024],
            ),
            patch.object(handoff, "_probe_u32", side_effect=[512, 512]),
        ):
            self.assertEqual(
                handoff._probe_physical_parent_claims(
                    10, 11, 1024 * 1024, 2 * 1024 * 1024, 8, 0
                ),
                {
                    "parentMajor": 8,
                    "parentMinor": 0,
                    "diskSequence": 77,
                    "mediaSectorCount": 4096,
                    "logicalSectorBytes": 512,
                    "leafSectorCount": 2048,
                },
            )
        with (
            patch.object(
                handoff,
                "_probe_u64",
                side_effect=[77, 78, 1024 * 1024, 2 * 1024 * 1024],
            ),
            patch.object(handoff, "_probe_u32", side_effect=[512, 512]),
        ):
            with self.assertRaises(handoff.HandoffFailure):
                handoff._probe_physical_parent_claims(
                    10, 11, 1024 * 1024, 2 * 1024 * 1024, 8, 0
                )

    def test_mount_builder_uses_only_leaf_fd_ro_noload_and_create_excl(self) -> None:
        class FakeMountApi:
            def __init__(self) -> None:
                self.context = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
                self.mount = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
                self.calls: list[tuple[object, ...]] = []

            def fsopen(self, filesystem: bytes, flags: int) -> int:
                self.calls.append(("fsopen", filesystem, flags))
                return self.context

            def fsconfig(
                self,
                context: int,
                command: int,
                key: bytes | None,
                value: bytes | None,
                auxiliary: int,
            ) -> int:
                self.calls.append(
                    ("fsconfig", context, command, key, value, auxiliary)
                )
                return 0

            def fsmount(self, context: int, flags: int, attributes: int) -> int:
                self.calls.append(("fsmount", context, flags, attributes))
                return self.mount

            def fstatfs(self, _descriptor: int, _buffer: object) -> int:
                raise AssertionError("validation is patched in this fixture")

        leaf = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
        api = FakeMountApi()
        try:
            with (
                patch.object(handoff, "_GlibcMountApi", return_value=api),
                patch.object(
                    handoff, "_assert_detached_ext4_mount_fd", return_value=None
                ),
            ):
                mount = handoff._create_detached_ext4_mount(leaf, 8, 2)
            self.assertEqual(mount, api.mount)
            self.assertEqual(
                api.calls,
                [
                    ("fsopen", b"ext4", handoff.FSOPEN_CLOEXEC),
                    (
                        "fsconfig",
                        api.context,
                        handoff.FSCONFIG_SET_STRING,
                        b"source",
                        f"/proc/self/fd/{leaf}".encode("ascii"),
                        0,
                    ),
                    (
                        "fsconfig",
                        api.context,
                        handoff.FSCONFIG_SET_FLAG,
                        b"ro",
                        None,
                        0,
                    ),
                    (
                        "fsconfig",
                        api.context,
                        handoff.FSCONFIG_SET_FLAG,
                        b"noload",
                        None,
                        0,
                    ),
                    (
                        "fsconfig",
                        api.context,
                        handoff.FSCONFIG_CMD_CREATE_EXCL,
                        None,
                        None,
                        0,
                    ),
                    (
                        "fsmount",
                        api.context,
                        handoff.FSMOUNT_CLOEXEC,
                        handoff.REQUIRED_MOUNT_ATTRIBUTES,
                    ),
                ],
            )
            with self.assertRaises(OSError):
                os.fstat(api.context)
        finally:
            os.close(leaf)
            os.close(api.mount)

    def test_mount_builder_fails_closed_when_create_excl_is_unavailable(self) -> None:
        class UnsupportedExclusiveMountApi:
            def __init__(self) -> None:
                self.context = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
                self.commands: list[int] = []
                self.fsopen_calls = 0

            def fsopen(self, _filesystem: bytes, _flags: int) -> int:
                self.fsopen_calls += 1
                return self.context

            def fsconfig(
                self,
                _context: int,
                command: int,
                _key: bytes | None,
                _value: bytes | None,
                _auxiliary: int,
            ) -> int:
                self.commands.append(command)
                if command == handoff.FSCONFIG_CMD_CREATE_EXCL:
                    handoff.ctypes.set_errno(handoff.errno.EOPNOTSUPP)
                    return -1
                return 0

            def fsmount(
                self, _context: int, _flags: int, _attributes: int
            ) -> int:
                raise AssertionError("an unsupported exclusive create must not mount")

            def fstatfs(self, _descriptor: int, _buffer: object) -> int:
                raise AssertionError("an unsupported exclusive create must not validate")

        leaf = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
        api = UnsupportedExclusiveMountApi()
        try:
            with patch.object(handoff, "_GlibcMountApi", return_value=api):
                with self.assertRaises(handoff.HandoffFailure) as raised:
                    handoff._create_detached_ext4_mount(leaf, 8, 2)
            self.assertEqual(raised.exception.token, "DEVICE_UNAVAILABLE")
            self.assertEqual(api.fsopen_calls, 1)
            self.assertEqual(
                api.commands,
                [
                    handoff.FSCONFIG_SET_STRING,
                    handoff.FSCONFIG_SET_FLAG,
                    handoff.FSCONFIG_SET_FLAG,
                    handoff.FSCONFIG_CMD_CREATE_EXCL,
                ],
            )
            with self.assertRaises(OSError):
                os.fstat(api.context)
        finally:
            os.close(leaf)

    def test_recovery_rescans_twice_and_returns_only_fresh_opaque_claims(
        self,
    ) -> None:
        targets = FakeTargets()
        service = handoff.RepairTargetHandoff(targets)
        leaf_descriptor = _pipe_capability(b"L")
        parent_descriptor = _pipe_capability(b"P")
        parent_identity_descriptor = os.open(
            "/dev/null", os.O_PATH | os.O_CLOEXEC | os.O_NOFOLLOW
        )
        mount_descriptor = _pipe_capability(b"M")
        with (
            patch.object(handoff, "_mountinfo_has_device", return_value=False),
            patch.object(
                handoff,
                "_open_bound_block_device",
                side_effect=[leaf_descriptor, parent_descriptor],
            ),
            patch.object(handoff, "_assert_block_fd", return_value=None),
            patch.object(
                handoff, "_assert_readonly_block_capability", return_value=None
            ),
            patch.object(
                handoff,
                "_probe_physical_parent_claims",
                return_value={
                    "parentMajor": 8,
                    "parentMinor": 0,
                    "diskSequence": 77,
                    "mediaSectorCount": 4096,
                    "logicalSectorBytes": 512,
                    "leafSectorCount": 2048,
                },
            ),
            patch.object(
                handoff,
                "_open_bound_block_identity",
                return_value=parent_identity_descriptor,
            ),
            patch.object(handoff, "_assert_block_identity_fd", return_value=None),
            patch.object(handoff, "_revalidate_final_bundle", return_value=None),
            patch.object(
                handoff,
                "_create_detached_ext4_mount",
                return_value=mount_descriptor,
            ),
            patch.object(
                handoff, "_assert_detached_ext4_mount_fd", return_value=None
            ),
        ):
            response, descriptors = self._exchange(service, RECOVERY_REQUEST)
        try:
            self.assertEqual(
                targets.events, ["recover", "inventory", "recover", "recover"]
            )
            self.assertEqual(response["outcome"], "ok")
            self.assertEqual(response["operation"], RECOVERY_REQUEST["operation"])
            self.assertEqual(
                response["recoveryFingerprint"], RECOVERY_FINGERPRINT
            )
            self.assertEqual(response["scanFingerprint"], REQUEST["scanFingerprint"])
            self.assertEqual(response["targetId"], REQUEST["targetId"])
            self.assertEqual(
                response["targetFingerprint"], REQUEST["targetFingerprint"]
            )
            self.assertEqual(len(descriptors), 4)
            serialized = json.dumps(response, separators=(",", ":"))
            for forbidden in (
                "/dev/",
                "sda2",
                "8:2",
                "11111111-2222-3333-4444-555555555555",
                "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            ):
                self.assertNotIn(forbidden, serialized)
        finally:
            for descriptor in descriptors:
                os.close(descriptor)

    def test_recovery_rejects_identity_drift_or_ambiguity_without_rights(self) -> None:
        class DriftTargets(FakeTargets):
            def resolve_recovery_target(
                self, request: dict[str, object], *, deadline: float
            ) -> tuple[dict[str, object], dict[str, object]]:
                selection, resolution = super().resolve_recovery_target(
                    request, deadline=deadline
                )
                if self.calls == 2:
                    changed = dict(resolution)
                    changed["recoveryUnique"] = False
                    return selection, changed
                return selection, resolution

        targets = DriftTargets()
        service = handoff.RepairTargetHandoff(targets)
        leaf_descriptor = _pipe_capability(b"")
        parent_descriptor = _pipe_capability(b"")
        with (
            patch.object(handoff, "_mountinfo_has_device", return_value=False),
            patch.object(
                handoff,
                "_open_bound_block_device",
                side_effect=[leaf_descriptor, parent_descriptor],
            ),
            patch.object(handoff, "_assert_block_fd", return_value=None),
        ):
            response, descriptors = self._exchange(service, RECOVERY_REQUEST)
        self.assertEqual(response["outcome"], "error")
        self.assertEqual(response["operation"], RECOVERY_REQUEST["operation"])
        self.assertEqual(response["error"], "TARGET_CHANGED")
        self.assertEqual(descriptors, [])
        for descriptor in (leaf_descriptor, parent_descriptor):
            with self.assertRaises(OSError):
                os.fstat(descriptor)

    def test_parent_drift_between_root_owned_scans_closes_both_block_fds(
        self,
    ) -> None:
        class ParentDriftTargets(FakeTargets):
            def resolve_installed_target(
                self, request: dict[str, object], *, deadline: float
            ) -> tuple[dict[str, object], dict[str, object]]:
                selection, resolution = super().resolve_installed_target(
                    request, deadline=deadline
                )
                if self.calls == 2:
                    changed = dict(resolution)
                    parent = dict(changed["physicalParent"])
                    identity = dict(parent["deviceIdentity"])
                    identity["maj:min"] = "8:16"
                    parent["deviceIdentity"] = identity
                    parent["majorMinor"] = "8:16"
                    changed["physicalParent"] = parent
                    return selection, changed
                return selection, resolution

        targets = ParentDriftTargets()
        service = handoff.RepairTargetHandoff(targets)
        leaf_descriptor = _pipe_capability(b"")
        parent_descriptor = _pipe_capability(b"")
        with (
            patch.object(handoff, "_mountinfo_has_device", return_value=False),
            patch.object(
                handoff,
                "_open_bound_block_device",
                side_effect=[leaf_descriptor, parent_descriptor],
            ),
            patch.object(handoff, "_assert_block_fd", return_value=None),
        ):
            response, descriptors = self._exchange(service, REQUEST)
        self.assertEqual(response["outcome"], "error")
        self.assertEqual(response["error"], "TARGET_CHANGED")
        self.assertEqual(descriptors, [])
        for descriptor in (leaf_descriptor, parent_descriptor):
            with self.assertRaises(OSError):
                os.fstat(descriptor)

    def test_third_fresh_resolution_rejects_last_moment_parent_drift(self) -> None:
        class ThirdScanDriftTargets(FakeTargets):
            def resolve_installed_target(
                self, request: dict[str, object], *, deadline: float
            ) -> tuple[dict[str, object], dict[str, object]]:
                selection, resolution = super().resolve_installed_target(
                    request, deadline=deadline
                )
                if self.calls == 3:
                    changed = dict(resolution)
                    parent = dict(changed["physicalParent"])
                    identity = dict(parent["deviceIdentity"])
                    identity["maj:min"] = "8:16"
                    parent["deviceIdentity"] = identity
                    parent["majorMinor"] = "8:16"
                    changed["physicalParent"] = parent
                    return selection, changed
                return selection, resolution

        targets = ThirdScanDriftTargets()
        service = handoff.RepairTargetHandoff(targets)
        leaf_descriptor = _pipe_capability(b"")
        parent_descriptor = _pipe_capability(b"")
        claims = {
            "parentMajor": 8,
            "parentMinor": 0,
            "diskSequence": 77,
            "mediaSectorCount": 4096,
            "logicalSectorBytes": 512,
            "leafSectorCount": 2048,
        }
        with (
            patch.object(handoff, "_mountinfo_has_device", return_value=False),
            patch.object(
                handoff,
                "_open_bound_block_device",
                side_effect=[leaf_descriptor, parent_descriptor],
            ),
            patch.object(handoff, "_assert_block_fd", return_value=None),
            patch.object(
                handoff,
                "_complete_read_only_bundle",
                return_value=({"schema": handoff.UUID_INVENTORY_SCHEMA}, claims),
            ),
        ):
            response, descriptors = self._exchange(service, REQUEST)
        self.assertEqual(targets.calls, 3)
        self.assertEqual(response["outcome"], "error")
        self.assertEqual(response["error"], "TARGET_CHANGED")
        self.assertEqual(descriptors, [])

    def test_target_fingerprint_is_recomputed_and_mismatch_sends_no_rights(
        self,
    ) -> None:
        targets = FakeTargets()
        service = handoff.RepairTargetHandoff(targets)
        request = dict(REQUEST)
        request["targetFingerprint"] = "sha256:" + "f" * 64
        leaf_descriptor = _pipe_capability(b"")
        parent_descriptor = _pipe_capability(b"")
        with (
            patch.object(handoff, "_mountinfo_has_device", return_value=False),
            patch.object(
                handoff,
                "_open_bound_block_device",
                side_effect=[leaf_descriptor, parent_descriptor],
            ),
            patch.object(handoff, "_assert_block_fd", return_value=None),
        ):
            response, descriptors = self._exchange(service, request)
        self.assertEqual(targets.events, ["resolve", "inventory", "resolve"])
        self.assertEqual(response["outcome"], "error")
        self.assertEqual(response["error"], "TARGET_CHANGED")
        self.assertEqual(descriptors, [])
        for descriptor in (leaf_descriptor, parent_descriptor):
            with self.assertRaises(OSError):
                os.fstat(descriptor)

    def test_incomplete_identity_inventory_fails_closed(self) -> None:
        targets = FakeTargets()
        targets.observations[0]["success"] = False
        service = handoff.RepairTargetHandoff(targets)
        leaf_descriptor = _pipe_capability(b"")
        parent_descriptor = _pipe_capability(b"")
        with (
            patch.object(handoff, "_mountinfo_has_device", return_value=False),
            patch.object(
                handoff,
                "_open_bound_block_device",
                side_effect=[leaf_descriptor, parent_descriptor],
            ),
            patch.object(handoff, "_assert_block_fd", return_value=None),
        ):
            response, descriptors = self._exchange(service, REQUEST)
        self.assertEqual(targets.events, ["resolve", "inventory"])
        self.assertEqual(response["outcome"], "error")
        self.assertEqual(response["error"], "TARGET_UNAVAILABLE")
        self.assertEqual(descriptors, [])
        for descriptor in (leaf_descriptor, parent_descriptor):
            with self.assertRaises(OSError):
                os.fstat(descriptor)

    def test_closed_request_unsupported_target_and_wrong_peer_never_send_rights(
        self,
    ) -> None:
        unsupported = handoff.RepairTargetHandoff(
            FakeTargets(family="windows", filesystem="ntfs")
        )
        response, descriptors = self._exchange(unsupported, REQUEST)
        self.assertEqual(response["outcome"], "error")
        self.assertEqual(response["error"], "TARGET_UNSUPPORTED")
        self.assertEqual(
            set(response),
            {"apiVersion", "requestId", "operation", "outcome", "error"},
        )
        self.assertEqual(response["requestId"], REQUEST["requestId"])
        self.assertEqual(response["operation"], REQUEST["operation"])
        self.assertEqual(descriptors, [])

        malformed = dict(REQUEST)
        malformed["devicePath"] = "/dev/sda2"
        response, descriptors = self._exchange(unsupported, malformed)
        self.assertEqual(response["error"], "INVALID_REQUEST")
        self.assertEqual(
            set(response),
            {"apiVersion", "requestId", "operation", "outcome", "error"},
        )
        self.assertNotIn("/dev", json.dumps(response))
        self.assertEqual(descriptors, [])

        malformed_fingerprint = dict(REQUEST)
        malformed_fingerprint["targetFingerprint"] = "sha256:" + "A" * 64
        response, descriptors = self._exchange(unsupported, malformed_fingerprint)
        self.assertEqual(response["error"], "INVALID_REQUEST")
        self.assertEqual(descriptors, [])

        if os.getuid() != 0:
            client, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            with server:
                handoff.serve_connection(
                    server,
                    os.getuid() + 1,
                    unsupported,
                    expected_local=None,
                )
            client.settimeout(0.2)
            self.assertEqual(client.recv(1), b"")
            client.close()

    def test_root_resolver_retains_the_selected_leaf_physical_parent(self) -> None:
        def device(
            name: str,
            major_minor: str,
            kind: str,
            *,
            filesystem: str | None = None,
            filesystem_uuid: str | None = None,
            partition_uuid: str | None = None,
            children: list[dict[str, object]] | None = None,
        ) -> dict[str, object]:
            value: dict[str, object] = {
                "name": name,
                "maj:min": major_minor,
                "type": kind,
                "size": 2 * 1024 * 1024 if kind == "disk" else 1024 * 1024,
                "ro": False,
                "rm": False,
                "tran": "sata",
                "fstype": filesystem,
                "fsver": "1.0" if filesystem else None,
                "mountpoints": [None],
                "uuid": filesystem_uuid,
                "partuuid": partition_uuid,
                "ptuuid": "fixture-table" if kind == "disk" else None,
                "pttype": "gpt" if kind == "disk" else None,
                "parttype": None,
                "serial": "fixture-serial" if kind == "disk" else None,
                "wwn": None,
            }
            if children is not None:
                value["children"] = children
            return value

        snapshot, resolutions = rescue_server._normalize_installed_targets_with_resolutions(
            json.dumps(
                {
                    "blockdevices": [
                        device(
                            "sda",
                            "8:0",
                            "disk",
                            children=[
                                device(
                                    "sda2",
                                    "8:2",
                                    "part",
                                    filesystem="ext4",
                                    filesystem_uuid=(
                                        "11111111-2222-3333-4444-555555555555"
                                    ),
                                    partition_uuid=(
                                        "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
                                    ),
                                )
                            ],
                        )
                    ]
                }
            )
        )
        target_id = snapshot["candidates"][0]["targetId"]
        parent = resolutions[target_id]["physicalParent"]
        self.assertEqual(
            parent,
            {
                "deviceIdentity": {
                    key: value
                    for key, value in device("sda", "8:0", "disk").items()
                    if key != "children"
                },
                "majorMinor": "8:0",
                "kernelKind": "disk",
            },
        )

    def test_duplicate_target_identifier_fails_the_canonical_scan_closed(self) -> None:
        def device(
            name: str,
            kind: str,
            *,
            filesystem: str | None = None,
            children: list[dict[str, object]] | None = None,
        ) -> dict[str, object]:
            value: dict[str, object] = {
                "name": name,
                "maj:min": f"8:{sum(name.encode('ascii'))}",
                "type": kind,
                "size": 1024 * 1024,
                "ro": False,
                "rm": False,
                "tran": "sata",
                "fstype": filesystem,
                "fsver": None,
                "mountpoints": [],
                "uuid": None,
                "partuuid": None,
                "ptuuid": None,
                "pttype": "gpt" if kind == "disk" else None,
                "parttype": None,
                "serial": None,
                "wwn": None,
            }
            if children is not None:
                value["children"] = children
            return value

        fixture = {
            "blockdevices": [
                device(
                    "sda",
                    "disk",
                    children=[
                        device("sda1", "part", filesystem="ext4"),
                        device("sda2", "part", filesystem="ext4"),
                    ],
                )
            ]
        }
        original = rescue_server._ephemeral_target_id

        def collide(prefix: str, payload: object) -> str:
            if prefix == "target":
                return "target:" + "f" * 64
            return original(prefix, payload)

        with (
            patch.object(rescue_server, "_ephemeral_target_id", side_effect=collide),
            self.assertRaises(rescue_server.TargetScanError),
        ):
            rescue_server.normalize_installed_targets(json.dumps(fixture))


if __name__ == "__main__":
    unittest.main()
