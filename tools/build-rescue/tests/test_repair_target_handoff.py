from __future__ import annotations

import array
from importlib.util import module_from_spec, spec_from_file_location
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
    "apiVersion": "kernaid.dev/rescue-target-capability/v1alpha1",
    "scanFingerprint": "scan:" + "1" * 64,
    "targetId": "target:" + "2" * 64,
    "requestId": "R-12345678-1234-1234-1234-123456789abc",
    "operation": "target.readonly.acquire",
}

IDENTITY_OBSERVATIONS: list[dict[str, object]] = [
    {
        "collector": "system.hostname",
        "trust": "observed-untrusted",
        "output": "kernaid-fixture\n",
        "success": True,
        "truncated": False,
    }
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
            "uuid": "fixture",
            "partuuid": "fixture-part",
            "ptuuid": "fixture-table",
            "pttype": "gpt",
            "parttype": None,
            "serial": None,
            "wwn": None,
        },
        "majorMinor": "8:2",
        "filesystem": filesystem,
        "kernelKind": "part",
        "leaf": True,
        "directOnDisk": True,
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
        2048, socket.CMSG_SPACE(4 * item_size)
    )
    if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
        raise AssertionError("response was truncated")
    descriptors: list[int] = []
    for level, kind, data in ancillary:
        if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
            rights = array.array("i")
            rights.frombytes(data[: len(data) - len(data) % item_size])
            descriptors.extend(rights)
    return json.loads(payload.decode("utf-8")), descriptors


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
        self.assertIn("ReadOnlyPaths=/run", service_unit)
        self.assertIn("DevicePolicy=closed", service_unit)
        self.assertIn("DeviceAllow=block-* r", service_unit)
        self.assertIn("CapabilityBoundingSet=\n", service_unit)
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
    ) -> tuple[dict[str, object], list[int]]:
        client, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)

        def run() -> None:
            with server:
                handoff.serve_connection(
                    server,
                    os.getuid() if expected_uid is None else expected_uid,
                    service,
                    expected_local=None,
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

    def test_success_resolves_twice_and_transfers_exactly_one_read_only_capability(
        self,
    ) -> None:
        targets = FakeTargets()
        service = handoff.RepairTargetHandoff(targets)
        read_descriptor, write_descriptor = os.pipe()
        os.close(write_descriptor)
        with (
            patch.object(handoff, "_mountinfo_has_device", return_value=False),
            patch.object(
                handoff, "_open_bound_block_device", return_value=read_descriptor
            ),
            patch.object(handoff, "_assert_block_fd", return_value=None),
        ):
            response, descriptors = self._exchange(service, REQUEST)
        try:
            self.assertEqual(targets.calls, 2)
            self.assertEqual(targets.events, ["resolve", "inventory", "resolve"])
            self.assertEqual(
                handoff.SOCKET_PATH,
                "/run/kernaid-rescue-target-capability.sock",
            )
            self.assertEqual(
                response["apiVersion"],
                "kernaid.dev/rescue-target-capability/v1alpha1",
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
                response["capability"],
                "linux-ext4-direct-leaf-readonly-block-v1",
            )
            self.assertEqual(
                response["descriptor"],
                {"type": "selected-target-block-readonly", "count": 1},
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
                    "capability",
                    "descriptor",
                },
            )
            self.assertEqual(len(descriptors), 1)
            serialized = json.dumps(response, separators=(",", ":"))
            for forbidden in (
                "/dev/",
                "sda2",
                "8:2",
                "majorMinor",
                "physicalParent",
            ):
                self.assertNotIn(forbidden, serialized)
        finally:
            for descriptor in descriptors:
                os.close(descriptor)

    def test_target_fingerprint_is_recomputed_and_mismatch_sends_no_rights(
        self,
    ) -> None:
        targets = FakeTargets()
        service = handoff.RepairTargetHandoff(targets)
        request = dict(REQUEST)
        request["targetFingerprint"] = "sha256:" + "f" * 64
        read_descriptor, write_descriptor = os.pipe()
        os.close(write_descriptor)
        with (
            patch.object(handoff, "_mountinfo_has_device", return_value=False),
            patch.object(
                handoff, "_open_bound_block_device", return_value=read_descriptor
            ),
            patch.object(handoff, "_assert_block_fd", return_value=None),
        ):
            response, descriptors = self._exchange(service, request)
        self.assertEqual(targets.events, ["resolve", "inventory", "resolve"])
        self.assertEqual(response["outcome"], "error")
        self.assertEqual(response["error"], "TARGET_CHANGED")
        self.assertEqual(descriptors, [])
        with self.assertRaises(OSError):
            os.fstat(read_descriptor)

    def test_incomplete_identity_inventory_fails_closed(self) -> None:
        targets = FakeTargets()
        targets.observations[0]["success"] = False
        service = handoff.RepairTargetHandoff(targets)
        read_descriptor, write_descriptor = os.pipe()
        os.close(write_descriptor)
        with (
            patch.object(handoff, "_mountinfo_has_device", return_value=False),
            patch.object(
                handoff, "_open_bound_block_device", return_value=read_descriptor
            ),
            patch.object(handoff, "_assert_block_fd", return_value=None),
        ):
            response, descriptors = self._exchange(service, REQUEST)
        self.assertEqual(targets.events, ["resolve", "inventory"])
        self.assertEqual(response["outcome"], "error")
        self.assertEqual(response["error"], "TARGET_UNAVAILABLE")
        self.assertEqual(descriptors, [])
        with self.assertRaises(OSError):
            os.fstat(read_descriptor)

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
