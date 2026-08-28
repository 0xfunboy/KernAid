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
    TargetScanBusy = type("TargetScanBusy", (Exception,), {})
    TargetScanError = type("TargetScanError", (Exception,), {})
    TargetSelectionError = type("TargetSelectionError", (Exception,), {})

    def __init__(self, *, family: str = "linux", filesystem: str = "ext4") -> None:
        candidate = _candidate(family)
        self.selection = _selection(candidate)
        self.resolution = _resolution(candidate, filesystem)
        self.calls = 0

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
        if request != {
            "scanFingerprint": REQUEST["scanFingerprint"],
            "targetId": REQUEST["targetId"],
        } or deadline <= 0:
            raise AssertionError("unexpected canonical resolver request")
        return self.selection, self.resolution


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
        safety_hook = (
            REPO_DIR
            / "rescue/live-build/config/hooks/live/0100-kernaid-safety.hook.chroot"
        ).read_text(encoding="utf-8")
        helper = "/usr/lib/kernaid/repair_target_handoff.py"
        self.assertEqual(safety_hook.count(helper), 2)
        self.assertNotIn("systemctl enable kernaid-rescue-target", safety_hook)
        self.assertFalse(
            list(
                (
                    REPO_DIR
                    / "rescue/live-build/config/includes.chroot/etc/systemd/system"
                ).glob("*target-capability*")
            )
        )
        accounts = (
            REPO_DIR
            / "rescue/live-build/config/includes.chroot/etc/sysusers.d/kernaid.conf"
        ).read_text(encoding="utf-8")
        self.assertNotIn("kernaid-repair", accounts)

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
