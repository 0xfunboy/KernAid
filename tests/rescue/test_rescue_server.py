#!/usr/bin/python3
"""Unit tests for the Rescue R0 authorization boundary."""

from importlib.util import module_from_spec, spec_from_file_location
from http.client import HTTPConnection, RemoteDisconnected
import hashlib
import json
from pathlib import Path
import socket
import sys
import threading
import time
import unittest
from unittest.mock import patch

SERVER = (
    Path(__file__).parents[2]
    / "rescue/live-build/config/includes.chroot/usr/lib/kernaid/rescue_server.py"
)
READY_CHECK = (
    Path(__file__).parents[2]
    / "rescue/live-build/config/includes.chroot/usr/lib/kernaid/ready-check"
)
QEMU_SMOKE = Path(__file__).parents[2] / "tools/build-rescue/qemu-smoke.sh"
SPEC = spec_from_file_location("kernaid_rescue_server", SERVER)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load Rescue server")
rescue_server = module_from_spec(SPEC)
SPEC.loader.exec_module(rescue_server)

FINGERPRINT = "sha256:" + "1" * 64
SCAN_FINGERPRINT = "scan:" + "2" * 64
TARGET_ID = "target:" + "3" * 64
RESCUE_TARGET = {
    "scanFingerprint": SCAN_FINGERPRINT,
    "targetId": TARGET_ID,
}


def block_device(
    name: str,
    kind: str,
    *,
    major_minor: str | None = None,
    size: int = 1024,
    read_only: bool = False,
    removable: bool = False,
    transport: str | None = None,
    filesystem: str | None = None,
    mountpoints: list[str | None] | None = None,
    uuid: str | None = None,
    partuuid: str | None = None,
    ptuuid: str | None = None,
    pttype: str | None = None,
    parttype: str | None = None,
    serial: str | None = None,
    wwn: str | None = None,
    children: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    if major_minor is None:
        derived_minor = int.from_bytes(hashlib.sha256(name.encode()).digest()[:4], "big")
        major_minor = f"240:{derived_minor}"
    device: dict[str, object] = {
        "name": name,
        "maj:min": major_minor,
        "type": kind,
        "size": size,
        "ro": read_only,
        "rm": removable,
        "tran": transport,
        "fstype": filesystem,
        "fsver": None,
        "mountpoints": [] if mountpoints is None else mountpoints,
        "uuid": uuid,
        "partuuid": partuuid,
        "ptuuid": ptuuid,
        "pttype": pttype,
        "parttype": parttype,
        "serial": serial,
        "wwn": wwn,
    }
    if children is not None:
        device["children"] = children
    return device


def target_scan_fixture() -> str:
    linux_root_type = "4f68bce3-e8cd-4db1-96e7-fbcaf984b709"
    apple_apfs_type = "7c3457ef-0000-11aa-aa11-00306543ecac"
    return json.dumps(
        {
            "blockdevices": [
                block_device(
                    "sda",
                    "disk",
                    size=8_000_000_000,
                    removable=True,
                    transport="usb",
                    filesystem="iso9660",
                    mountpoints=["/run/live/medium"],
                    serial="RESCUE-DEVICE-SECRET",
                    pttype="dos",
                ),
                block_device(
                    "nvme0n1",
                    "disk",
                    size=1_000_000_000_000,
                    transport="nvme",
                    serial="CUSTOMER-SERIAL-SECRET",
                    wwn="CUSTOMER-WWN-SECRET",
                    ptuuid="CUSTOMER-PTUUID-SECRET",
                    pttype="gpt",
                    children=[
                        block_device(
                            "nvme0n1p1",
                            "part",
                            filesystem="vfat",
                            parttype=rescue_server.EFI_SYSTEM_PARTITION_TYPE,
                            uuid="CUSTOMER-EFI-UUID-SECRET",
                        ),
                        block_device(
                            "nvme0n1p2",
                            "part",
                            filesystem="ntfs",
                            uuid="CUSTOMER-NTFS-UUID-SECRET",
                        ),
                        block_device(
                            "nvme0n1p3",
                            "part",
                            filesystem="ext4",
                            parttype=linux_root_type,
                            uuid="CUSTOMER-LINUX-UUID-SECRET",
                        ),
                        block_device(
                            "nvme0n1p4",
                            "part",
                            filesystem="crypto_LUKS",
                            uuid="CUSTOMER-LUKS-UUID-SECRET",
                        ),
                        block_device(
                            "nvme0n1p5",
                            "part",
                            filesystem="apfs",
                            parttype=apple_apfs_type,
                            uuid="CUSTOMER-APFS-UUID-SECRET",
                        ),
                    ],
                ),
                block_device(
                    "sdb",
                    "disk",
                    size=500_000_000_000,
                    transport="sata",
                    children=[
                        block_device(
                            "sdb1",
                            "part",
                            filesystem="ext4",
                            mountpoints=["/customer/private/path"],
                        )
                    ],
                ),
            ]
        }
    )


def multi_pv_lvm_fixture(*, incoherent_copy: bool = False) -> str:
    def shared_logical_volume(size: int) -> dict[str, object]:
        return block_device(
            "vg-system",
            "lvm",
            major_minor="253:0",
            size=size,
            filesystem="ext4",
            uuid="SHARED-LV-FILESYSTEM-UUID",
        )

    return json.dumps(
        {
            "blockdevices": [
                block_device(
                    "vda",
                    "disk",
                    children=[
                        block_device(
                            "vda1",
                            "part",
                            filesystem="LVM2_member",
                            uuid="PV-ONE",
                            children=[shared_logical_volume(20_000)],
                        )
                    ],
                ),
                block_device(
                    "vdb",
                    "disk",
                    children=[
                        block_device(
                            "vdb1",
                            "part",
                            filesystem="LVM2_member",
                            uuid="PV-TWO",
                            children=[
                                shared_logical_volume(
                                    21_000 if incoherent_copy else 20_000
                                )
                            ],
                        )
                    ],
                ),
                block_device(
                    "vdc",
                    "disk",
                    filesystem="ntfs",
                    uuid="INDEPENDENT-FILESYSTEM-UUID",
                ),
            ]
        }
    )


def shared_btrfs_fixture() -> str:
    return json.dumps(
        {
            "blockdevices": [
                block_device(
                    "sdc",
                    "disk",
                    children=[
                        block_device(
                            "sdc1",
                            "part",
                            major_minor="8:33",
                            filesystem="btrfs",
                            uuid="SHARED-BTRFS-FILESYSTEM-UUID",
                        )
                    ],
                ),
                block_device(
                    "sdd",
                    "disk",
                    children=[
                        block_device(
                            "sdd1",
                            "part",
                            major_minor="8:49",
                            filesystem="btrfs",
                            uuid="SHARED-BTRFS-FILESYSTEM-UUID",
                        )
                    ],
                ),
            ]
        }
    )


class ObserveBrokerTests(unittest.TestCase):
    def request(self, **changes: object) -> dict[str, object]:
        request: dict[str, object] = {
            "sessionId": "S-test",
            "planId": "P-test",
            "targetFingerprint": FINGERPRINT,
            "sequence": 1,
            "action": "system.observe.noop",
            "rescueTarget": dict(RESCUE_TARGET),
        }
        request.update(changes)
        return request

    def authorization_case(
        self, *, inventory_output: str = "host\n", session_id: str = "S-boundary"
    ) -> tuple[
        list[dict[str, object]],
        dict[str, object],
        dict[str, object],
        dict[str, object],
    ]:
        observations: list[dict[str, object]] = [
            {
                "collector": "system.hostname",
                "trust": "observed-untrusted",
                "output": inventory_output,
                "success": True,
                "truncated": False,
            }
        ]
        snapshot = rescue_server.normalize_installed_targets(target_scan_fixture())
        candidate = snapshot["candidates"][0]
        rescue_target = {
            "scanFingerprint": snapshot["scanFingerprint"],
            "targetId": candidate["targetId"],
        }
        selection: dict[str, object] = {
            "apiVersion": rescue_server.TARGET_SCAN_API_VERSION,
            "status": "observe-target-validated",
            "scanFingerprint": snapshot["scanFingerprint"],
            "target": candidate,
            "claims": {
                "installedOsConfirmed": False,
                "filesystemContentInspected": False,
                "mountOperationPerformed": False,
                "mutationPerformed": False,
            },
        }
        inventory_fingerprint = rescue_server.inventory_fingerprint(observations)
        composite = rescue_server.rescue_target_fingerprint(
            inventory_fingerprint, snapshot["scanFingerprint"], candidate
        )
        request = self.request(
            sessionId=session_id,
            targetFingerprint=composite,
            rescueTarget=rescue_target,
        )
        return observations, selection, request, candidate

    def test_accepts_only_the_allowlisted_action_once(self) -> None:
        broker = rescue_server.ObserveBroker(FINGERPRINT, RESCUE_TARGET)
        broker.authorize(self.request())
        with self.assertRaisesRegex(rescue_server.BrokerError, "fuori sequenza"):
            broker.authorize(self.request())
        with self.assertRaisesRegex(rescue_server.BrokerError, "non consentita"):
            broker.authorize(self.request(action="shell.exec", sequence=2))

    def test_collector_bounds_stdout_and_marks_overflow_failed(self) -> None:
        observation = rescue_server.observe(
            "test.output-limit",
            (sys.executable, "-c", "print('x' * 100000)"),
        )
        self.assertFalse(observation["success"])
        self.assertTrue(observation["truncated"])
        self.assertLessEqual(
            len(str(observation["output"]).encode()), rescue_server.MAX_OUTPUT_BYTES
        )

    def test_collector_never_returns_untrusted_stderr(self) -> None:
        observation = rescue_server.observe(
            "test.stderr-separation",
            (
                sys.executable,
                "-c",
                "import sys; print('safe-stdout'); print('private-marker', file=sys.stderr)",
            ),
        )
        self.assertTrue(observation["success"])
        self.assertFalse(observation["truncated"])
        self.assertEqual(observation["output"], "safe-stdout\n")
        self.assertNotIn("private-marker", json.dumps(observation))

    def test_collector_rejects_non_utf8_output_without_expansion(self) -> None:
        observation = rescue_server.observe(
            "test.invalid-utf8",
            (sys.executable, "-c", "import os; os.write(1, bytes([255]) * 40000)"),
        )
        self.assertFalse(observation["success"])
        self.assertFalse(observation["truncated"])
        self.assertEqual(observation["output"], "")

    def test_collector_marks_stderr_overflow_without_exposing_it(self) -> None:
        observation = rescue_server.observe(
            "test.stderr-limit",
            (
                sys.executable,
                "-c",
                "import sys; print('safe'); sys.stderr.write('private-marker' * 10000)",
            ),
        )
        self.assertFalse(observation["success"])
        self.assertTrue(observation["truncated"])
        self.assertEqual(observation["output"], "safe\n")
        self.assertNotIn("private-marker", json.dumps(observation))

    def test_collector_kills_descendants_that_keep_pipes_open(self) -> None:
        program = (
            "import subprocess,sys; "
            "subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)']); "
            "print('parent-finished')"
        )
        started = time.monotonic()
        with (
            patch.object(rescue_server, "COLLECTOR_TIMEOUT_SECONDS", 0.2),
            patch.object(rescue_server, "COLLECTOR_KILL_GRACE_SECONDS", 0.1),
        ):
            observation = rescue_server.observe(
                "test.inherited-pipe", (sys.executable, "-c", program)
            )
        self.assertLess(time.monotonic() - started, 1)
        self.assertFalse(observation["success"])
        self.assertTrue(observation["truncated"])
        self.assertEqual(observation["output"], "parent-finished\n")

    def test_collector_uses_remaining_authorization_budget(self) -> None:
        started = time.monotonic()
        with (
            patch.object(rescue_server, "COLLECTOR_TIMEOUT_SECONDS", 5),
            patch.object(rescue_server, "COLLECTOR_KILL_GRACE_SECONDS", 0.05),
            self.assertRaises(TimeoutError),
        ):
            rescue_server.observe(
                "test.shared-deadline",
                (sys.executable, "-c", "import time; time.sleep(5)"),
                deadline=started + 0.12,
            )
        self.assertLess(time.monotonic() - started, 0.75)

    def test_inventory_uses_minimized_fixed_collectors(self) -> None:
        commands = dict(rescue_server.COMMANDS)
        self.assertNotIn("linux.fstab", commands)
        self.assertEqual(
            commands["linux.hardware.inventory"],
            ("/usr/lib/kernaid/kernaid-linux-hardware-inventory",),
        )
        lsblk = commands["linux.block.inventory"]
        fields = lsblk[lsblk.index("--output") + 1].split(",")
        self.assertEqual(
            fields,
            [
                "NAME",
                "TYPE",
                "SIZE",
                "RO",
                "FSTYPE",
                "MOUNTPOINTS",
                "SERIAL",
                "WWN",
                "UUID",
                "PARTUUID",
                "PTUUID",
            ],
        )
        self.assertNotIn("MODEL", fields)
        self.assertNotIn("KNAME", fields)
        self.assertNotIn("MAJ:MIN", fields)

    def test_inventory_collectors_run_concurrently(self) -> None:
        barrier = threading.Barrier(len(rescue_server.COMMANDS), timeout=3)
        active = 0
        maximum_active = 0
        counter_lock = threading.Lock()

        def concurrent_observe(
            collector: str, _command: tuple[str, ...]
        ) -> dict[str, object]:
            nonlocal active, maximum_active
            with counter_lock:
                active += 1
                maximum_active = max(maximum_active, active)
            try:
                barrier.wait()
            finally:
                with counter_lock:
                    active -= 1
            return {
                "collector": collector,
                "trust": "observed-untrusted",
                "output": "",
                "success": True,
                "truncated": False,
            }

        with patch.object(rescue_server, "observe", side_effect=concurrent_observe):
            observations = rescue_server.inventory()
        self.assertEqual(len(observations), len(rescue_server.COMMANDS))
        self.assertEqual(maximum_active, len(rescue_server.COMMANDS))

    def test_shared_deadline_reaches_target_scan_and_inventory_commands(self) -> None:
        deadline = time.monotonic() + 2
        observed_deadlines: list[float] = []
        observed_lock = threading.Lock()

        def bounded_observe(
            collector: str, _command: tuple[str, ...], received: float
        ) -> dict[str, object]:
            with observed_lock:
                observed_deadlines.append(received)
            return {
                "collector": collector,
                "trust": "observed-untrusted",
                "output": (
                    target_scan_fixture()
                    if collector == "rescue.installed-targets.metadata"
                    else ""
                ),
                "success": True,
                "truncated": False,
            }

        with patch.object(rescue_server, "observe", side_effect=bounded_observe):
            rescue_server.installed_targets(deadline)
            rescue_server.inventory(deadline)
        self.assertEqual(
            len(observed_deadlines), len(rescue_server.COMMANDS) + 1
        )
        self.assertEqual(set(observed_deadlines), {deadline})

    def test_overlapping_inventory_fails_immediately(self) -> None:
        entered = threading.Event()
        release = threading.Event()
        completed: list[list[dict[str, object]]] = []

        def blocked_observe(
            collector: str, _command: tuple[str, ...]
        ) -> dict[str, object]:
            entered.set()
            release.wait(timeout=3)
            return {
                "collector": collector,
                "trust": "observed-untrusted",
                "output": "",
                "success": True,
                "truncated": False,
            }

        with patch.object(rescue_server, "observe", side_effect=blocked_observe):
            worker = threading.Thread(
                target=lambda: completed.append(rescue_server.inventory()), daemon=True
            )
            worker.start()
            try:
                self.assertTrue(entered.wait(timeout=1))
                with self.assertRaises(rescue_server.InventoryBusy):
                    rescue_server.inventory()
            finally:
                release.set()
                worker.join(timeout=3)
        self.assertFalse(worker.is_alive())
        self.assertEqual(len(completed), 1)

    def test_rejects_stale_or_malformed_targets(self) -> None:
        broker = rescue_server.ObserveBroker(FINGERPRINT, RESCUE_TARGET)
        with self.assertRaisesRegex(rescue_server.BrokerError, "target è cambiato"):
            broker.authorize(self.request(targetFingerprint="sha256:" + "2" * 64))
        with self.assertRaisesRegex(rescue_server.BrokerError, "non valida"):
            broker.authorize(self.request(targetFingerprint="invalid"))
        with self.assertRaisesRegex(rescue_server.BrokerError, "Rescue è cambiato"):
            broker.authorize(
                self.request(
                    rescueTarget={
                        "scanFingerprint": SCAN_FINGERPRINT,
                        "targetId": "target:" + "4" * 64,
                    }
                )
            )

    def test_authorization_requires_exact_rescue_target_fields(self) -> None:
        observations, selection, request, _candidate = self.authorization_case()
        malformed_requests = [
            {key: value for key, value in request.items() if key != "rescueTarget"},
            {**request, "unexpected": True},
            {
                **request,
                "rescueTarget": {
                    **request["rescueTarget"],
                    "unexpected": "field",
                },
            },
            {
                **request,
                "rescueTarget": {
                    "scanFingerprint": request["rescueTarget"]["scanFingerprint"]
                },
            },
        ]
        for malformed in malformed_requests:
            with self.subTest(request=malformed):
                with (
                    patch.object(
                        rescue_server,
                        "select_installed_target",
                        return_value=selection,
                    ) as select,
                    patch.object(
                        rescue_server, "inventory", return_value=observations
                    ) as collect,
                    self.assertRaises(rescue_server.BrokerError),
                ):
                    rescue_server.authorize_observe(malformed)
                select.assert_not_called()
                collect.assert_not_called()

    def test_authorization_recollects_inventory_at_the_boundary(self) -> None:
        observations, selection, request, _candidate = self.authorization_case()
        events: list[str] = []
        deadlines: list[float] = []

        def select(
            _rescue_target: dict[str, object], *, deadline: float
        ) -> dict[str, object]:
            self.assertGreater(deadline, time.monotonic())
            deadlines.append(deadline)
            events.append("selection")
            return selection

        def collect(*, deadline: float) -> list[dict[str, object]]:
            self.assertGreater(deadline, time.monotonic())
            deadlines.append(deadline)
            events.append("inventory")
            return observations

        rescue_server.BROKERS.clear()
        with (
            patch.object(rescue_server, "select_installed_target", side_effect=select),
            patch.object(rescue_server, "inventory", side_effect=collect),
        ):
            rescue_server.authorize_observe(request)
        self.assertEqual(events, ["selection", "inventory", "selection"])
        self.assertEqual(len(set(deadlines)), 1)

    def test_composite_fingerprint_uses_the_documented_full_candidate_binding(self) -> None:
        observations, _selection, request, candidate = self.authorization_case()
        rescue_target = request["rescueTarget"]
        inventory_fingerprint = rescue_server.inventory_fingerprint(observations)
        candidate_json = json.dumps(
            candidate, ensure_ascii=True, sort_keys=True, separators=(",", ":")
        )
        material = "\0".join(
            (
                "kernaid-rescue-observe-target-v1",
                inventory_fingerprint,
                rescue_target["scanFingerprint"],
                rescue_target["targetId"],
                candidate_json,
            )
        )
        expected = f"sha256:{hashlib.sha256(material.encode('utf-8')).hexdigest()}"
        self.assertEqual(request["targetFingerprint"], expected)

        changed = dict(candidate)
        changed["requiresUnlock"] = not changed["requiresUnlock"]
        self.assertNotEqual(
            rescue_server.rescue_target_fingerprint(
                inventory_fingerprint,
                rescue_target["scanFingerprint"],
                changed,
            ),
            expected,
        )

    def test_composite_fingerprint_cross_language_vector(self) -> None:
        candidate: dict[str, object] = {
            "targetId": "target:" + "3" * 64,
            "sourceRef": "disk-1/volume-2",
            "diskId": "disk:" + "4" * 64,
            "osFamilyHint": "windows",
            "confidence": "low",
            "status": "unverified-installation-candidate",
            "detectionBasis": ["ntfs-filesystem-signature"],
            "requiresUnlock": False,
            "inspectionMode": "metadata-only-no-mount",
            "selectionEligible": True,
        }
        self.assertEqual(
            rescue_server.rescue_target_fingerprint(
                "sha256:" + "1" * 64,
                "scan:" + "2" * 64,
                candidate,
            ),
            "sha256:846c16507e5938abfaff4a2111a24adfe2d7aab353260887f74fbca249e20a36",
        )

    def test_authorization_rejects_incomplete_identity_inventory(self) -> None:
        _observations, selection, request, _candidate = self.authorization_case()
        observations = [
            {
                "collector": "linux.block.inventory",
                "trust": "observed-untrusted",
                "output": "partial",
                "success": False,
                "truncated": True,
            }
        ]
        with (
            patch.object(
                rescue_server, "select_installed_target", return_value=selection
            ),
            patch.object(rescue_server, "inventory", return_value=observations),
        ):
            with self.assertRaisesRegex(rescue_server.BrokerError, "incompleto"):
                rescue_server.authorize_observe(request)

    def test_changed_inventory_invalidates_an_existing_session(self) -> None:
        before, selection, request, _candidate = self.authorization_case(
            inventory_output="before\n", session_id="S-changing"
        )
        after = [{**before[0], "output": "after\n"}]
        rescue_server.BROKERS.clear()
        with (
            patch.object(
                rescue_server, "select_installed_target", return_value=selection
            ),
            patch.object(rescue_server, "inventory", side_effect=[before, after]),
        ):
            rescue_server.authorize_observe(request)
            with self.assertRaisesRegex(rescue_server.BrokerError, "target è cambiato"):
                rescue_server.authorize_observe(
                    {**request, "sequence": 2}
                )

    def test_existing_session_cannot_switch_to_another_valid_rescue_target(self) -> None:
        observations, selection_one, request_one, _candidate = self.authorization_case(
            session_id="S-retarget"
        )
        snapshot = rescue_server.normalize_installed_targets(target_scan_fixture())
        candidate_two = snapshot["candidates"][1]
        selection_two = {
            **selection_one,
            "target": candidate_two,
        }
        rescue_target_two = {
            "scanFingerprint": snapshot["scanFingerprint"],
            "targetId": candidate_two["targetId"],
        }
        request_two = self.request(
            sessionId="S-retarget",
            sequence=2,
            rescueTarget=rescue_target_two,
            targetFingerprint=rescue_server.rescue_target_fingerprint(
                rescue_server.inventory_fingerprint(observations),
                snapshot["scanFingerprint"],
                candidate_two,
            ),
        )
        rescue_server.BROKERS.clear()
        with (
            patch.object(
                rescue_server,
                "select_installed_target",
                side_effect=[
                    selection_one,
                    selection_one,
                    selection_two,
                    selection_two,
                ],
            ),
            patch.object(rescue_server, "inventory", return_value=observations),
        ):
            rescue_server.authorize_observe(request_one)
            with self.assertRaisesRegex(rescue_server.BrokerError, "Rescue è cambiato"):
                rescue_server.authorize_observe(request_two)

    def test_authorization_rejects_changed_a_b_selection(self) -> None:
        observations, selection_before, request, _candidate = self.authorization_case()
        selection_after = json.loads(json.dumps(selection_before))
        selection_after["target"]["requiresUnlock"] = not selection_after["target"][
            "requiresUnlock"
        ]
        rescue_server.BROKERS.clear()
        with (
            patch.object(
                rescue_server,
                "select_installed_target",
                side_effect=[selection_before, selection_after],
            ),
            patch.object(rescue_server, "inventory", return_value=observations),
            self.assertRaisesRegex(rescue_server.BrokerError, "durante"),
        ):
            rescue_server.authorize_observe(request)

    def test_extra_candidate_fields_fail_before_inventory(self) -> None:
        _observations, selection, request, _candidate = self.authorization_case()
        extra_selection = json.loads(json.dumps(selection))
        extra_selection["target"]["unexpected"] = "field"
        with (
            patch.object(
                rescue_server,
                "select_installed_target",
                return_value=extra_selection,
            ),
            patch.object(rescue_server, "inventory") as collect,
            self.assertRaisesRegex(rescue_server.BrokerError, "Candidato"),
        ):
            rescue_server.authorize_observe(request)
        collect.assert_not_called()

    def test_inventory_swap_between_equal_selections_breaks_composite_binding(self) -> None:
        _observations, selection, request, _candidate = self.authorization_case(
            inventory_output="target-a\n", session_id="S-aba"
        )
        swapped_inventory = [
            {
                "collector": "system.hostname",
                "trust": "observed-untrusted",
                "output": "target-b\n",
                "success": True,
                "truncated": False,
            }
        ]
        rescue_server.BROKERS.clear()
        with (
            patch.object(
                rescue_server, "select_installed_target", return_value=selection
            ) as select,
            patch.object(
                rescue_server, "inventory", return_value=swapped_inventory
            ),
            self.assertRaisesRegex(rescue_server.BrokerError, "target è cambiato"),
        ):
            rescue_server.authorize_observe(request)
        self.assertEqual(select.call_count, 2)

    def test_stale_selection_stops_before_runtime_inventory(self) -> None:
        _observations, _selection, request, _candidate = self.authorization_case()
        with (
            patch.object(
                rescue_server,
                "select_installed_target",
                side_effect=rescue_server.TargetSelectionError("stale"),
            ),
            patch.object(rescue_server, "inventory") as collect,
            self.assertRaises(rescue_server.TargetSelectionError),
        ):
            rescue_server.authorize_observe(request)
        collect.assert_not_called()

    def test_selection_becoming_stale_after_inventory_cannot_authorize(self) -> None:
        observations, selection, request, _candidate = self.authorization_case()
        with (
            patch.object(
                rescue_server,
                "select_installed_target",
                side_effect=[
                    selection,
                    rescue_server.TargetSelectionError("stale-after-inventory"),
                ],
            ),
            patch.object(
                rescue_server, "inventory", return_value=observations
            ) as collect,
            self.assertRaises(rescue_server.TargetSelectionError),
        ):
            rescue_server.authorize_observe(request)
        self.assertEqual(collect.call_count, 1)
        self.assertIn("deadline", collect.call_args.kwargs)

    def test_http_boundary_rejects_host_and_origin_attacks(self) -> None:
        observations, selection, request_value, _candidate = self.authorization_case(
            session_id="S-http"
        )
        request_value["planId"] = "P-http"
        request = json.dumps(request_value)
        server = rescue_server.BoundedThreadingHTTPServer(
            ("127.0.0.1", 0), rescue_server.RescueHandler
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 2)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        port = server.server_address[1]
        with (
            patch.object(
                rescue_server, "select_installed_target", return_value=selection
            ),
            patch.object(rescue_server, "inventory", return_value=observations),
        ):
            connection = HTTPConnection("127.0.0.1", port)
            connection.request("GET", "/api/inventory", headers={"Host": "attacker.invalid"})
            self.assertEqual(connection.getresponse().status, 421)
            connection.close()

            connection = HTTPConnection("127.0.0.1", port)
            connection.request(
                "GET",
                "/api/inventory",
                headers={
                    "Host": "127.0.0.1:4173",
                    "Sec-Fetch-Site": "cross-site",
                },
            )
            self.assertEqual(connection.getresponse().status, 403)
            connection.close()

            connection = HTTPConnection("127.0.0.1", port)
            connection.request(
                "POST",
                "/api/diagnose-linux-p0",
                body="{}",
                headers={
                    "Host": "127.0.0.1:4173",
                    "Origin": "http://127.0.0.1:4173",
                    "Content-Type": "application/json",
                },
            )
            self.assertEqual(connection.getresponse().status, 405)
            connection.close()

            connection = HTTPConnection("127.0.0.1", port)
            connection.request(
                "POST",
                "/api/authorize-observe",
                body=request,
                headers={
                    "Host": "127.0.0.1:4173",
                    "Origin": "https://attacker.invalid",
                    "Content-Type": "application/json",
                },
            )
            self.assertEqual(connection.getresponse().status, 403)
            connection.close()

            connection = HTTPConnection("127.0.0.1", port)
            connection.request(
                "POST",
                "/api/authorize-observe",
                body=request,
                headers={
                    "Host": "127.0.0.1:4173",
                    "Origin": "http://127.0.0.1:4173",
                    "Content-Type": "application/json",
                },
            )
            self.assertEqual(connection.getresponse().status, 200)
            connection.close()

    def test_inventory_http_returns_429_while_collection_is_busy(self) -> None:
        server = rescue_server.BoundedThreadingHTTPServer(
            ("127.0.0.1", 0), rescue_server.RescueHandler
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 2)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        port = server.server_address[1]
        with patch.object(
            rescue_server,
            "inventory",
            side_effect=rescue_server.InventoryBusy("busy"),
        ):
            connection = HTTPConnection("127.0.0.1", port)
            connection.request(
                "GET",
                "/api/inventory",
                headers={"Host": "127.0.0.1:4173"},
            )
            response = connection.getresponse()
            self.assertEqual(response.status, 429)
            self.assertEqual(response.getheader("Retry-After"), "1")
            self.assertEqual(
                response.getheader("Content-Security-Policy"),
                rescue_server.CONTENT_SECURITY_POLICY,
            )
            self.assertEqual(response.getheader("X-Frame-Options"), "DENY")
            self.assertEqual(response.getheader("Referrer-Policy"), "no-referrer")
            self.assertEqual(
                response.getheader("Cross-Origin-Opener-Policy"), "same-origin"
            )
            self.assertEqual(
                response.getheader("Cross-Origin-Resource-Policy"), "same-origin"
            )
            connection.close()

    def test_slow_request_body_is_timed_out(self) -> None:
        with patch.object(rescue_server, "SOCKET_TIMEOUT_SECONDS", 0.1):
            server = rescue_server.BoundedThreadingHTTPServer(
                ("127.0.0.1", 0), rescue_server.RescueHandler
            )
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                client = socket.create_connection(server.server_address, timeout=2)
                client.settimeout(2)
                client.sendall(
                    b"POST /api/authorize-observe HTTP/1.1\r\n"
                    b"Host: 127.0.0.1:4173\r\n"
                    b"Origin: http://127.0.0.1:4173\r\n"
                    b"Content-Type: application/json\r\n"
                    b"Content-Length: 100\r\n\r\n{"
                )
                response = bytearray()
                while chunk := client.recv(4096):
                    response.extend(chunk)
                self.assertIn(b" 408 ", response)
                client.close()
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

    def test_request_has_an_absolute_deadline(self) -> None:
        with (
            patch.object(rescue_server, "SOCKET_TIMEOUT_SECONDS", 2),
            patch.object(rescue_server, "REQUEST_DEADLINE_SECONDS", 0.1),
        ):
            server = rescue_server.BoundedThreadingHTTPServer(
                ("127.0.0.1", 0), rescue_server.RescueHandler
            )
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                client = socket.create_connection(server.server_address, timeout=2)
                client.settimeout(2)
                client.sendall(
                    b"POST /api/authorize-observe HTTP/1.1\r\n"
                    b"Host: 127.0.0.1:4173\r\n"
                    b"Origin: http://127.0.0.1:4173\r\n"
                    b"Content-Type: application/json\r\n"
                    b"Content-Length: 100\r\n\r\n{"
                )
                started = time.monotonic()
                try:
                    while client.recv(4096):
                        pass
                except ConnectionResetError:
                    pass
                self.assertLess(time.monotonic() - started, 1)
                client.close()
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

    def test_internal_authorize_deadline_prevents_ghost_session_and_sequence(self) -> None:
        _items, _selection, new_request, _candidate = self.authorization_case(
            session_id="S-deadline-new"
        )
        _items, _selection, existing_request, _candidate = self.authorization_case(
            session_id="S-deadline-existing"
        )
        existing_broker = rescue_server.ObserveBroker(
            existing_request["targetFingerprint"], existing_request["rescueTarget"]
        )
        existing_broker.authorize(existing_request)
        existing_retry = {**existing_request, "sequence": 2}
        rescue_server.BROKERS.clear()
        rescue_server.BROKERS["S-deadline-existing"] = existing_broker
        slow_scan = (sys.executable, "-c", "import time; time.sleep(5)")

        with (
            patch.object(rescue_server, "AUTHORIZE_DEADLINE_SECONDS", 0.12),
            patch.object(rescue_server, "REQUEST_DEADLINE_SECONDS", 1),
            patch.object(rescue_server, "COLLECTOR_TIMEOUT_SECONDS", 5),
            patch.object(rescue_server, "COLLECTOR_KILL_GRACE_SECONDS", 0.05),
            patch.object(rescue_server, "MAX_SERVER_THREADS", 1),
            patch.object(rescue_server, "TARGET_SCAN_COMMAND", slow_scan),
        ):
            server = rescue_server.BoundedThreadingHTTPServer(
                ("127.0.0.1", 0), rescue_server.RescueHandler
            )
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            port = server.server_address[1]

            def wait_for_worker_release() -> None:
                release_deadline = time.monotonic() + 1
                while not server.slots.acquire(blocking=False):
                    if time.monotonic() >= release_deadline:
                        self.fail("authorization worker remained occupied")
                    time.sleep(0.005)
                server.slots.release()

            def post(value: dict[str, object]) -> tuple[int | None, float]:
                connection = HTTPConnection("127.0.0.1", port, timeout=1)
                started = time.monotonic()
                try:
                    connection.request(
                        "POST",
                        "/api/authorize-observe",
                        body=json.dumps(value),
                        headers={
                            "Host": "127.0.0.1:4173",
                            "Origin": "http://127.0.0.1:4173",
                            "Content-Type": "application/json",
                        },
                    )
                    response = connection.getresponse()
                    status = response.status
                    response.read()
                    return status, time.monotonic() - started
                except (
                    BrokenPipeError,
                    ConnectionAbortedError,
                    ConnectionResetError,
                    RemoteDisconnected,
                    socket.timeout,
                ):
                    return None, time.monotonic() - started
                finally:
                    connection.close()

            try:
                for value in (new_request, existing_retry):
                    wait_for_worker_release()
                    started = time.monotonic()
                    status, elapsed = post(value)
                    self.assertIn(status, {None, 408})
                    self.assertLess(elapsed, 0.75)
                    wait_for_worker_release()
                    self.assertLess(time.monotonic() - started, 0.75)
                self.assertNotIn("S-deadline-new", rescue_server.BROKERS)
                self.assertIs(
                    rescue_server.BROKERS["S-deadline-existing"], existing_broker
                )
                self.assertEqual(existing_broker.last_sequence, 1)

                # MAX_SERVER_THREADS=1 makes this a worker-leak check: the next
                # request only receives a response if the timed-out worker left.
                connection = HTTPConnection("127.0.0.1", port, timeout=1)
                try:
                    connection.request(
                        "GET",
                        "/deadline-worker-released",
                        headers={"Host": "127.0.0.1:4173"},
                    )
                    response = connection.getresponse()
                    self.assertEqual(response.status, 404)
                    response.read()
                finally:
                    connection.close()
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)
                rescue_server.BROKERS.clear()

    def test_socket_expiry_cannot_advance_an_authorization_later(self) -> None:
        observations, selection, request, _candidate = self.authorization_case(
            session_id="S-socket-expired"
        )
        broker = rescue_server.ObserveBroker(
            request["targetFingerprint"], request["rescueTarget"]
        )
        broker.authorize(request)
        retry = {**request, "sequence": 2}
        rescue_server.BROKERS.clear()
        rescue_server.BROKERS["S-socket-expired"] = broker
        phase_finished = threading.Event()

        def delayed_selection(
            _rescue_target: dict[str, object], *, deadline: float
        ) -> dict[str, object]:
            self.assertGreater(deadline, time.monotonic())
            time.sleep(0.15)
            phase_finished.set()
            return selection

        with (
            patch.object(rescue_server, "AUTHORIZE_DEADLINE_SECONDS", 0.08),
            patch.object(rescue_server, "REQUEST_DEADLINE_SECONDS", 0.04),
            patch.object(rescue_server, "MAX_SERVER_THREADS", 1),
            patch.object(
                rescue_server,
                "select_installed_target",
                side_effect=delayed_selection,
            ),
            patch.object(
                rescue_server, "inventory", return_value=observations
            ) as collect,
        ):
            server = rescue_server.BoundedThreadingHTTPServer(
                ("127.0.0.1", 0), rescue_server.RescueHandler
            )
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            port = server.server_address[1]
            connection = HTTPConnection("127.0.0.1", port, timeout=1)
            try:
                connection.request(
                    "POST",
                    "/api/authorize-observe",
                    body=json.dumps(retry),
                    headers={
                        "Host": "127.0.0.1:4173",
                        "Origin": "http://127.0.0.1:4173",
                        "Content-Type": "application/json",
                    },
                )
                try:
                    response = connection.getresponse()
                    self.assertEqual(response.status, 408)
                    response.read()
                except (RemoteDisconnected, ConnectionResetError, socket.timeout):
                    pass
                self.assertTrue(phase_finished.wait(timeout=1))
                self.assertEqual(broker.last_sequence, 1)
                collect.assert_not_called()

                deadline = time.monotonic() + 1
                while True:
                    probe = HTTPConnection("127.0.0.1", port, timeout=0.25)
                    try:
                        probe.request(
                            "GET",
                            "/expired-worker-released",
                            headers={"Host": "127.0.0.1:4173"},
                        )
                        probe_response = probe.getresponse()
                        self.assertEqual(probe_response.status, 404)
                        probe_response.read()
                        break
                    except (RemoteDisconnected, ConnectionResetError, socket.timeout):
                        if time.monotonic() >= deadline:
                            self.fail("authorization worker remained occupied")
                        time.sleep(0.01)
                    finally:
                        probe.close()
            finally:
                connection.close()
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)
                rescue_server.BROKERS.clear()


class RepairRelayTests(unittest.TestCase):
    REQUEST_ID = "R-11111111-1111-1111-1111-111111111111"
    STATUS = {
        "apiVersion": rescue_server.REPAIR_API_VERSION,
        "requestId": REQUEST_ID,
        "operation": "repair.status",
    }
    IDLE = {
        **STATUS,
        "outcome": "ok",
        "stateVersion": 1,
        "state": "idle",
        "detail": None,
    }

    class FakeRepairSocket:
        family = socket.AF_UNIX

        def __init__(self, response: dict[str, object]) -> None:
            self.response = json.dumps(
                response, ensure_ascii=True, sort_keys=True, separators=(",", ":")
            ).encode("ascii")
            self.connected: list[str] = []
            self.sent: list[bytes] = []
            self.timeouts: list[float] = []
            self.closed = False

        def settimeout(self, value: float) -> None:
            self.timeouts.append(value)

        def connect(self, path: str) -> None:
            self.connected.append(path)

        def send(self, value: bytes) -> int:
            self.sent.append(value)
            return len(value)

        def recvmsg(
            self, _maximum: int, _ancillary_size: int
        ) -> tuple[bytes, list[tuple[int, int, bytes]], int, None]:
            return self.response, [], 0, None

        def getpeername(self) -> str:
            return rescue_server.REPAIR_SOCKET

        def getsockopt(
            self, level: int, option: int, _size: int | None = None
        ) -> int | bytes:
            if level != socket.SOL_SOCKET:
                raise OSError
            if option == socket.SO_TYPE:
                return socket.SOCK_SEQPACKET
            if option == socket.SO_PEERCRED:
                return rescue_server.struct.pack("3i", 1, 0, 0)
            raise OSError

        def close(self) -> None:
            self.closed = True

    def test_closed_request_contract_rejects_client_selected_material(self) -> None:
        target = {
            "scanFingerprint": "scan:" + "1" * 64,
            "targetFingerprint": "sha256:" + "2" * 64,
            "targetId": "target:" + "3" * 64,
        }
        prepare = {
            **self.STATUS,
            "operation": "repair.fstab.prepare",
            "target": target,
        }
        approve = {
            **self.STATUS,
            "operation": "repair.fstab.approve",
            "preparedId": "Q-" + "4" * 32,
            "sessionId": "S-" + "5" * 32,
            "planId": "P-" + "6" * 32,
            "planHash": "sha256:" + "7" * 64,
            "approvalId": "A-" + "8" * 32,
            "approvalSequence": 1,
            "typedConfirmation": "DISABILITA VOCE FSTAB",
        }
        cancel = {
            **self.STATUS,
            "operation": "repair.fstab.cancel",
            "preparedId": approve["preparedId"],
            "planHash": approve["planHash"],
        }
        for request in (self.STATUS, prepare, approve, cancel):
            rescue_server._validate_repair_request(request)

        source = {
            "reservationId": "B-" + "9" * 32,
            "transactionBindingSha256": "sha256:" + "8" * 64,
        }
        rollback_status = {
            "apiVersion": rescue_server.ROLLBACK_API_VERSION,
            "requestId": self.STATUS["requestId"],
            "operation": "repair.fstab.rollback.status",
        }
        rollback_prepare = {
            **rollback_status,
            "operation": "repair.fstab.rollback.prepare",
            "source": source,
        }
        rollback_approve = {
            **rollback_status,
            "operation": "repair.fstab.rollback.approve",
            "preparedId": "Q-" + "1" * 32,
            "rollbackId": "RB-" + "2" * 32,
            "sessionId": "S-" + "3" * 32,
            "planId": "P-" + "4" * 32,
            "planHash": "sha256:" + "5" * 64,
            "source": source,
            "approvalId": "A-" + "6" * 32,
            "approvalSequence": 2,
            "typedConfirmation": "RIPRISTINA FSTAB ORIGINALE",
        }
        rollback_cancel = {
            **rollback_status,
            "operation": "repair.fstab.rollback.cancel",
            "preparedId": rollback_approve["preparedId"],
            "rollbackId": rollback_approve["rollbackId"],
            "planHash": rollback_approve["planHash"],
            "source": source,
        }
        for request in (
            rollback_status,
            rollback_prepare,
            rollback_approve,
            rollback_cancel,
        ):
            rescue_server._validate_repair_request(request)

        for cross_version in (
            {**rollback_prepare, "apiVersion": rescue_server.REPAIR_API_VERSION},
            {**prepare, "apiVersion": rescue_server.ROLLBACK_API_VERSION},
        ):
            with self.assertRaisesRegex(
                rescue_server.RepairRelayError, "invalid-request"
            ):
                rescue_server._validate_repair_request(cross_version)

        for malformed in (
            {**prepare, "path": "/etc/fstab"},
            {**prepare, "bytes": "replacement"},
            {**approve, "typedConfirmation": "disabilita voce fstab"},
            {**approve, "approvalSequence": True},
        ):
            with self.assertRaisesRegex(
                rescue_server.RepairRelayError, "invalid-request"
            ):
                rescue_server._validate_repair_request(malformed)

    def test_response_contract_accepts_only_bounded_prepared_and_terminal_data(
        self,
    ) -> None:
        rescue_server._validate_repair_response(self.IDLE, self.STATUS)
        prepared = {
            **self.STATUS,
            "outcome": "ok",
            "stateVersion": 2,
            "state": "prepared",
            "detail": {
                "kind": "fstab-prepared",
                "preparedId": "Q-" + "1" * 32,
                "sessionId": "S-" + "2" * 32,
                "planId": "P-" + "3" * 32,
                "planHash": "sha256:" + "4" * 64,
                "targetFingerprint": "sha256:" + "5" * 64,
                "beforeSha256": "sha256:" + "6" * 64,
                "afterSha256": "sha256:" + "7" * 64,
                "diffSha256": "sha256:" + "8" * 64,
                "resourceId": "rescue:selected-linux-root:etc/fstab",
                "backupLocator": "vault://repair/B-" + "9" * 32,
                "actionId": "linux.fstab.disable-missing-uuid.v1",
                "risk": "R2",
                "backup": {"state": "reserved", "vaultDistinct": True},
                "nextApprovalSequence": 1,
                "confirmationRequired": "DISABILITA VOCE FSTAB",
            },
        }
        rescue_server._validate_repair_response(prepared, self.STATUS)
        for invalid in (
            {"resourceId": "rescue:selected-linux-root:etc/shadow"},
            {"backupLocator": "/run/kernaid-vault/backups/original"},
            {"backupLocator": "vault://repair/B-../../host-path"},
        ):
            with self.assertRaisesRegex(
                rescue_server.RepairRelayError, "invalid-response"
            ):
                rescue_server._validate_repair_response(
                    {**prepared, "detail": {**prepared["detail"], **invalid}},
                    self.STATUS,
                )
        rollback_request = {
            "apiVersion": rescue_server.ROLLBACK_API_VERSION,
            "requestId": self.STATUS["requestId"],
            "operation": "repair.fstab.rollback.prepare",
            "source": {
                "reservationId": "B-" + "9" * 32,
                "transactionBindingSha256": "sha256:" + "8" * 64,
            },
        }
        rollback_prepared = {
            **prepared,
            "apiVersion": rescue_server.ROLLBACK_API_VERSION,
            "operation": rollback_request["operation"],
            "detail": {
                "kind": "fstab-rollback-prepared",
                "preparedId": "Q-" + "1" * 32,
                "rollbackId": "RB-" + "2" * 32,
                "sessionId": "S-" + "3" * 32,
                "planId": "P-" + "4" * 32,
                "planHash": "sha256:" + "5" * 64,
                "targetFingerprint": "sha256:" + "6" * 64,
                "source": rollback_request["source"],
                "resourceId": "rescue:selected-linux-root:etc/fstab",
                "backupLocator": "vault://repair/B-" + "9" * 32,
                "actionId": "linux.fstab.restore",
                "risk": "R2",
                "nextApprovalSequence": 2,
                "confirmationRequired": "RIPRISTINA FSTAB ORIGINALE",
            },
        }
        rescue_server._validate_repair_response(
            rollback_prepared, rollback_request
        )
        with self.assertRaisesRegex(
            rescue_server.RepairRelayError, "invalid-response"
        ):
            rescue_server._validate_repair_response(
                {
                    **rollback_prepared,
                    "detail": {
                        **rollback_prepared["detail"],
                        "backupLocator": "/run/kernaid-vault/original",
                    },
                },
                rollback_request,
            )
        terminal = {
            **self.STATUS,
            "outcome": "ok",
            "stateVersion": 3,
            "state": "restored",
            "detail": {
                "kind": "terminal",
                "terminalOutcome": "closed-before-restored",
                "reservationId": "B-exact-backup",
                "transactionBindingSha256": "sha256:" + "9" * 64,
                "rebootRequired": False,
                "prepareFailureStage": None,
            },
        }
        rescue_server._validate_repair_response(terminal, self.STATUS)
        rollback_terminal = {
            **terminal,
            "apiVersion": rescue_server.ROLLBACK_API_VERSION,
            "operation": "repair.fstab.rollback.status",
            "detail": {
                **terminal["detail"],
                "terminalOutcome": "rolled-back-original",
                "reservationId": "B-" + "9" * 32,
            },
        }
        rescue_server._validate_repair_response(
            rollback_terminal,
            {
                **self.STATUS,
                "apiVersion": rescue_server.ROLLBACK_API_VERSION,
                "operation": "repair.fstab.rollback.status",
            },
        )
        with self.assertRaisesRegex(
            rescue_server.RepairRelayError, "invalid-response"
        ):
            rescue_server._validate_repair_response(
                {**terminal, "detail": rollback_terminal["detail"]},
                self.STATUS,
            )
        failed_prepare = {
            **terminal,
            "state": "failed",
            "detail": {
                "kind": "terminal",
                "terminalOutcome": "failed",
                "reservationId": None,
                "transactionBindingSha256": None,
                "rebootRequired": False,
                "prepareFailureStage": "target-capability-unavailable",
            },
        }
        rescue_server._validate_repair_response(failed_prepare, self.STATUS)
        with self.assertRaisesRegex(
            rescue_server.RepairRelayError, "invalid-response"
        ):
            rescue_server._validate_repair_response(
                {
                    **failed_prepare,
                    "detail": {
                        **failed_prepare["detail"],
                        "prepareFailureStage": "/dev/sda",
                    },
                },
                self.STATUS,
            )
        with self.assertRaisesRegex(
            rescue_server.RepairRelayError, "invalid-response"
        ):
            rescue_server._validate_repair_response(
                {**prepared, "detail": {**prepared["detail"], "path": "/dev/sda"}},
                self.STATUS,
            )

    def test_relay_authenticates_systemd_socket_and_releases_its_lock(self) -> None:
        repair_socket = self.FakeRepairSocket(self.IDLE)
        with (
            patch.object(rescue_server.socket, "socket", return_value=repair_socket),
            patch.object(rescue_server.time, "monotonic", return_value=100.0),
        ):
            response = rescue_server.relay_repair_request(self.STATUS, 108.0)
        self.assertEqual(response, self.IDLE)
        self.assertEqual(repair_socket.connected, [rescue_server.REPAIR_SOCKET])
        self.assertEqual(
            repair_socket.sent,
            [
                json.dumps(
                    self.STATUS,
                    ensure_ascii=True,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("ascii")
            ],
        )
        self.assertTrue(repair_socket.closed)
        self.assertTrue(rescue_server.REPAIR_RELAY_LOCK.acquire(blocking=False))
        rescue_server.REPAIR_RELAY_LOCK.release()


class ProviderRelayTests(unittest.TestCase):
    REQUEST = (
        b'{"apiVersion":"kernaid.dev/rescue-openai/v1alpha1",'
        b'"requestId":"O-11111111-1111-1111-1111-111111111111",'
        b'"operation":"provider.status","payload":{}}\n'
    )
    RESPONSE = (
        b'{"apiVersion":"kernaid.dev/rescue-openai/v1alpha1",'
        b'"requestId":"O-11111111-1111-1111-1111-111111111111",'
        b'"operation":"provider.status","ok":true,"payload":{'
        b'"provider":"openai","profile":"rescue-default",'
        b'"vault":"locked","credential":"unavailable"}}\n'
    )

    class FakeProviderSocket:
        family = socket.AF_UNIX

        def __init__(
            self,
            response: bytes,
            *,
            ancillary: list[tuple[int, int, bytes]] | None = None,
            flags: int = 0,
        ) -> None:
            self.response = response
            self.ancillary = [] if ancillary is None else ancillary
            self.flags = flags
            self.timeouts: list[float] = []
            self.connected: list[str] = []
            self.sent: list[bytes] = []
            self.recvmsg_calls: list[tuple[int, int]] = []
            self.closed = False
            self.peer = rescue_server.PROVIDER_SOCKET
            self.socket_type = socket.SOCK_SEQPACKET
            self.credentials = (123, 0, 0)

        def settimeout(self, value: float) -> None:
            self.timeouts.append(value)

        def connect(self, path: str) -> None:
            self.connected.append(path)

        def send(self, value: bytes) -> int:
            self.sent.append(value)
            return len(value)

        def recvmsg(
            self, maximum: int, ancillary_size: int
        ) -> tuple[bytes, list[tuple[int, int, bytes]], int, None]:
            self.recvmsg_calls.append((maximum, ancillary_size))
            return self.response, self.ancillary, self.flags, None

        def getpeername(self) -> str:
            return self.peer

        def getsockopt(
            self, level: int, option: int, _size: int | None = None
        ) -> int | bytes:
            if level != socket.SOL_SOCKET:
                raise OSError
            if option == socket.SO_TYPE:
                return self.socket_type
            if option == socket.SO_PEERCRED:
                return rescue_server.struct.pack("3i", *self.credentials)
            raise OSError

        def close(self) -> None:
            self.closed = True

    def start_server(
        self,
    ) -> tuple[rescue_server.BoundedThreadingHTTPServer, int]:
        server = rescue_server.BoundedThreadingHTTPServer(
            ("127.0.0.1", 0), rescue_server.RescueHandler
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 2)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server, server.server_address[1]

    def test_relay_uses_one_send_one_ancillary_free_recvmsg_and_absolute_deadline(
        self,
    ) -> None:
        provider_socket = self.FakeProviderSocket(self.RESPONSE)
        with (
            patch.object(rescue_server.socket, "socket", return_value=provider_socket),
            patch.object(rescue_server, "_validate_root_provider_peer"),
            patch.object(rescue_server.time, "monotonic", return_value=100.0),
        ):
            response = rescue_server.relay_openai_provider(self.REQUEST, 240.0)
        self.assertEqual(response, self.RESPONSE)
        self.assertEqual(provider_socket.connected, [rescue_server.PROVIDER_SOCKET])
        self.assertEqual(provider_socket.sent, [self.REQUEST])
        self.assertEqual(
            provider_socket.recvmsg_calls,
            [(rescue_server.MAX_PROVIDER_RESPONSE_FRAME_BYTES + 1, 0)],
        )
        self.assertEqual(provider_socket.timeouts, [140.0, 140.0, 140.0])
        self.assertTrue(provider_socket.closed)

    def test_provider_peer_must_be_the_fixed_root_seqpacket_listener(self) -> None:
        valid = self.FakeProviderSocket(self.RESPONSE)
        rescue_server._validate_root_provider_peer(valid)

        invalid = []
        wrong_path = self.FakeProviderSocket(self.RESPONSE)
        wrong_path.peer = "/run/not-kernaid.sock"
        invalid.append(wrong_path)
        wrong_family = self.FakeProviderSocket(self.RESPONSE)
        wrong_family.family = socket.AF_INET
        invalid.append(wrong_family)
        wrong_type = self.FakeProviderSocket(self.RESPONSE)
        wrong_type.socket_type = socket.SOCK_STREAM
        invalid.append(wrong_type)
        for credentials in ((0, 0, 0), (123, 1000, 0), (123, 0, 1000)):
            wrong_credentials = self.FakeProviderSocket(self.RESPONSE)
            wrong_credentials.credentials = credentials
            invalid.append(wrong_credentials)
        for provider_socket in invalid:
            with self.assertRaisesRegex(
                rescue_server.ProviderRelayError, "transport"
            ):
                rescue_server._validate_root_provider_peer(provider_socket)

    def test_constructor_failure_and_absolute_timeout_always_release_lock(self) -> None:
        with patch.object(
            rescue_server.socket, "socket", side_effect=OSError("closed")
        ):
            with self.assertRaisesRegex(rescue_server.ProviderRelayError, "transport"):
                rescue_server.relay_openai_provider(
                    self.REQUEST, time.monotonic() + 140
                )
        self.assertTrue(rescue_server.PROVIDER_RELAY_LOCK.acquire(blocking=False))
        rescue_server.PROVIDER_RELAY_LOCK.release()

        close_failure = self.FakeProviderSocket(self.RESPONSE)

        def fail_close() -> None:
            raise OSError

        close_failure.close = fail_close  # type: ignore[method-assign]
        with (
            patch.object(rescue_server.socket, "socket", return_value=close_failure),
            patch.object(rescue_server, "_validate_root_provider_peer"),
            patch.object(rescue_server.time, "monotonic", return_value=100.0),
        ):
            response = rescue_server.relay_openai_provider(self.REQUEST, 240.0)
        self.assertEqual(response, self.RESPONSE)
        self.assertTrue(rescue_server.PROVIDER_RELAY_LOCK.acquire(blocking=False))
        rescue_server.PROVIDER_RELAY_LOCK.release()

        provider_socket = self.FakeProviderSocket(self.RESPONSE)
        with (
            patch.object(rescue_server.socket, "socket", return_value=provider_socket),
            patch.object(rescue_server, "_validate_root_provider_peer"),
            patch.object(
                rescue_server.time, "monotonic", side_effect=[100.0, 241.0]
            ),
            self.assertRaisesRegex(rescue_server.ProviderRelayError, "timeout"),
        ):
            rescue_server.relay_openai_provider(self.REQUEST, 240.0)
        self.assertEqual(provider_socket.sent, [])
        self.assertTrue(provider_socket.closed)
        self.assertTrue(rescue_server.PROVIDER_RELAY_LOCK.acquire(blocking=False))
        rescue_server.PROVIDER_RELAY_LOCK.release()

    def test_busy_ancillary_truncation_and_multirecord_frames_fail_closed(self) -> None:
        self.assertTrue(rescue_server.PROVIDER_RELAY_LOCK.acquire(blocking=False))
        try:
            with self.assertRaisesRegex(rescue_server.ProviderRelayError, "busy"):
                rescue_server.relay_openai_provider(
                    self.REQUEST, time.monotonic() + 140
                )
        finally:
            rescue_server.PROVIDER_RELAY_LOCK.release()

        for ancillary, flags in (
            ([(socket.SOL_SOCKET, 1, b"x")], 0),
            ([], socket.MSG_TRUNC),
            ([], socket.MSG_CTRUNC),
        ):
            provider_socket = self.FakeProviderSocket(
                self.RESPONSE, ancillary=ancillary, flags=flags
            )
            with (
                patch.object(
                    rescue_server.socket, "socket", return_value=provider_socket
                ),
                patch.object(rescue_server, "_validate_root_provider_peer"),
                patch.object(rescue_server.time, "monotonic", return_value=100.0),
                self.assertRaisesRegex(
                    rescue_server.ProviderRelayError, "invalid_response"
                ),
            ):
                rescue_server.relay_openai_provider(self.REQUEST, 240.0)

        for invalid in (b"{}", b"{}\n{}\n", b"{}\r\n"):
            with self.assertRaises(rescue_server.ProviderRelayError):
                rescue_server.relay_openai_provider(invalid, 240.0)

    def test_http_endpoint_forwards_the_complete_frame_without_reencoding(self) -> None:
        _server, port = self.start_server()
        with patch.object(
            rescue_server, "relay_openai_provider", return_value=self.RESPONSE
        ) as relay:
            connection = HTTPConnection("127.0.0.1", port, timeout=2)
            try:
                connection.request(
                    "POST",
                    "/api/rescue/provider/openai",
                    body=self.REQUEST,
                    headers={
                        "Host": "127.0.0.1:4173",
                        "Origin": "http://127.0.0.1:4173",
                        "Sec-Fetch-Site": "same-origin",
                        "Content-Type": "application/json",
                    },
                )
                response = connection.getresponse()
                self.assertEqual(response.status, 200)
                self.assertEqual(response.getheader("Content-Type"), "application/json")
                self.assertEqual(response.getheader("Cache-Control"), "no-store")
                self.assertEqual(response.read(), self.RESPONSE)
            finally:
                connection.close()
        relay.assert_called_once()
        relayed_frame, deadline = relay.call_args.args
        self.assertEqual(relayed_frame, self.REQUEST)
        self.assertGreater(deadline, time.monotonic())
        self.assertLessEqual(deadline - time.monotonic(), 140)

    def test_http_endpoint_rejects_ambiguous_or_encoded_framing(self) -> None:
        _server, port = self.start_server()

        def raw_status(headers: bytes, body: bytes | None = None) -> int:
            request_body = self.REQUEST if body is None else body
            client = socket.create_connection(("127.0.0.1", port), timeout=2)
            try:
                client.sendall(
                    b"POST /api/rescue/provider/openai HTTP/1.1\r\n"
                    + headers
                    + b"Connection: close\r\n\r\n"
                    + request_body
                )
                response = bytearray()
                while chunk := client.recv(4096):
                    response.extend(chunk)
                return int(response.split(b" ", maxsplit=2)[1])
            finally:
                client.close()

        base = (
            b"Host: 127.0.0.1:4173\r\n"
            b"Origin: http://127.0.0.1:4173\r\n"
            b"Content-Type: application/json\r\n"
        )
        length = str(len(self.REQUEST)).encode("ascii")
        self.assertEqual(
            raw_status(
                b"Host: 127.0.0.1:4173\r\n"
                b"Origin: http://localhost:4173\r\n"
                b"Content-Type: application/json\r\nContent-Length: "
                + length
                + b"\r\n"
            ),
            403,
        )
        self.assertEqual(
            raw_status(
                base
                + b"Host: 127.0.0.1:4173\r\nContent-Length: "
                + length
                + b"\r\n"
            ),
            421,
        )
        self.assertEqual(
            raw_status(
                base
                + b"Origin: http://127.0.0.1:4173\r\nContent-Length: "
                + length
                + b"\r\n"
            ),
            403,
        )
        self.assertEqual(
            raw_status(
                base
                + b"Content-Type: application/json\r\nContent-Length: "
                + length
                + b"\r\n"
            ),
            415,
        )
        self.assertEqual(
            raw_status(
                base
                + b"Content-Length: "
                + length
                + b"\r\nContent-Length: "
                + length
                + b"\r\n"
            ),
            400,
        )
        self.assertEqual(
            raw_status(base + b"Content-Length: +3\r\n", b"{}\n"), 400
        )
        self.assertEqual(
            raw_status(
                base
                + b"Content-Encoding: identity\r\nContent-Length: "
                + length
                + b"\r\n"
            ),
            400,
        )
        self.assertEqual(
            raw_status(
                base
                + b"Transfer-Encoding: chunked\r\nContent-Length: "
                + length
                + b"\r\n"
            ),
            400,
        )
        self.assertEqual(
            raw_status(
                base
                + b"Sec-Fetch-Site: same-origin\r\n"
                + b"Sec-Fetch-Site: same-origin\r\nContent-Length: "
                + length
                + b"\r\n"
            ),
            403,
        )

    def test_http_relay_error_contains_only_a_closed_code(self) -> None:
        _server, port = self.start_server()
        with patch.object(
            rescue_server,
            "relay_openai_provider",
            side_effect=rescue_server.ProviderRelayError("transport", 503),
        ):
            connection = HTTPConnection("127.0.0.1", port, timeout=2)
            try:
                connection.request(
                    "POST",
                    "/api/rescue/provider/openai",
                    body=self.REQUEST,
                    headers={
                        "Host": "127.0.0.1:4173",
                        "Origin": "http://127.0.0.1:4173",
                        "Content-Type": "application/json",
                    },
                )
                response = connection.getresponse()
                self.assertEqual(response.status, 503)
                self.assertEqual(
                    json.loads(response.read()), {"error": {"code": "transport"}}
                )
            finally:
                connection.close()

    def test_http_relay_busy_response_is_canonical_and_retryable(self) -> None:
        _server, port = self.start_server()
        with patch.object(
            rescue_server,
            "relay_openai_provider",
            side_effect=rescue_server.ProviderRelayError("busy", 429),
        ):
            connection = HTTPConnection("127.0.0.1", port, timeout=2)
            try:
                connection.request(
                    "POST",
                    "/api/rescue/provider/openai",
                    body=self.REQUEST,
                    headers={
                        "Host": "127.0.0.1:4173",
                        "Origin": "http://127.0.0.1:4173",
                        "Sec-Fetch-Site": "same-origin",
                        "Content-Type": "application/json",
                    },
                )
                response = connection.getresponse()
                self.assertEqual(response.status, 429)
                self.assertEqual(
                    response.headers.get_all("Content-Type"), ["application/json"]
                )
                self.assertEqual(response.headers.get_all("Cache-Control"), ["no-store"])
                self.assertEqual(
                    response.headers.get_all("X-Content-Type-Options"), ["nosniff"]
                )
                self.assertEqual(response.headers.get_all("Retry-After"), ["1"])
                self.assertEqual(response.headers.get_all("Content-Length"), ["25"])
                self.assertEqual(response.headers.get_all("Transfer-Encoding", []), [])
                self.assertEqual(response.headers.get_all("Content-Encoding", []), [])
                self.assertEqual(response.read(), b'{"error":{"code":"busy"}}')
            finally:
                connection.close()


class InstalledTargetTests(unittest.TestCase):
    def test_qemu_requires_a_bound_fixture_selection_marker(self) -> None:
        ready_check = READY_CHECK.read_text()
        self.assertLess(rescue_server.AUTHORIZE_DEADLINE_SECONDS, 20)
        self.assertEqual(rescue_server.OFFLINE_HELPER_TIMEOUT_SECONDS, 20)
        self.assertLess(rescue_server.OFFLINE_HELPER_TIMEOUT_SECONDS, 22)
        self.assertLess(22, rescue_server.REQUEST_DEADLINE_SECONDS)
        self.assertIn("--max-time 22", ready_check)
        selection_requests = [
            line
            for line in ready_check.splitlines()
            if "/api/rescue/select-installed-target" in line
        ]
        self.assertEqual(len(selection_requests), 2)
        self.assertTrue(
            all("--max-time 22" in request for request in selection_requests)
        )
        self.assertTrue(
            all("--max-time 5" not in request for request in selection_requests)
        )
        post_position = ready_check.index("/api/rescue/select-installed-target")
        fingerprint_binding = ready_check.index("selection fingerprint binding failed")
        target_binding = ready_check.index("selection target binding failed")
        composite_binding = ready_check.index("kernaid-rescue-observe-target-v1")
        authorization_position = ready_check.index("/api/authorize-observe")
        target_marker = ready_check.index("KERNAID_RESCUE_TARGET_SELECTION_READY")
        selection_branch = ready_check.index('if [ -n "$selection_request" ]; then')
        selection_branch_end = ready_check.index("\nfi\n", selection_branch)
        general_marker = ready_check.index("echo KERNAID_RESCUE_READY")
        self.assertLess(post_position, fingerprint_binding)
        self.assertLess(fingerprint_binding, target_marker)
        self.assertLess(target_binding, composite_binding)
        self.assertLess(composite_binding, authorization_position)
        self.assertLess(authorization_position, target_marker)
        self.assertLess(selection_branch, authorization_position)
        self.assertLess(target_marker, selection_branch_end)
        self.assertLess(selection_branch_end, general_marker)
        self.assertLess(target_marker, general_marker)
        for required_contract in (
            'target.get("selectionEligible") is True',
            'target.get("confidence") == "low"',
            'target.get("status") == "unverified-installation-candidate"',
            'target.get("inspectionMode") == "metadata-only-no-mount"',
            'claims.get(key) is False',
            '"rescueTarget":rescue_target',
        ):
            self.assertIn(required_contract, ready_check)

        qemu_smoke = QEMU_SMOKE.read_text()
        self.assertIn("mkfs.ext4", qemu_smoke)
        self.assertIn(
            'grep -q "KERNAID_RESCUE_READY" "$log" \\\n'
            "    && hardware_inventory_ready_observed \\\n"
            "    && secure_boot_ready_observed \\\n"
            '    && grep -q "KERNAID_RESCUE_TARGET_SELECTION_READY" "$log"',
            qemu_smoke,
        )
        marker_condition = qemu_smoke.index(
            'grep -q "KERNAID_RESCUE_TARGET_SELECTION_READY"'
        )
        post_boot_hash = qemu_smoke.index("target_hash_after=", marker_condition)
        zero_write_comparison = qemu_smoke.index(
            '"$target_hash_after" != "$target_hash_before"', post_boot_hash
        )
        self.assertLess(marker_condition, post_boot_hash)
        self.assertLess(post_boot_hash, zero_write_comparison)

    def test_target_scan_uses_one_fixed_metadata_only_command(self) -> None:
        command = rescue_server.TARGET_SCAN_COMMAND
        self.assertEqual(
            command[:5],
            ("/usr/bin/lsblk", "--json", "--bytes", "--tree", "--output"),
        )
        fields = command[5].split(",")
        self.assertEqual(
            fields,
            [
                "NAME",
                "MAJ:MIN",
                "TYPE",
                "SIZE",
                "RO",
                "RM",
                "TRAN",
                "FSTYPE",
                "FSVER",
                "MOUNTPOINTS",
                "UUID",
                "PARTUUID",
                "PTUUID",
                "PTTYPE",
                "PARTTYPE",
                "SERIAL",
                "WWN",
            ],
        )
        self.assertNotIn("LABEL", fields)
        self.assertNotIn("MODEL", fields)
        self.assertNotIn("PATH", fields)
        self.assertNotIn("/usr/bin/mount", command)
        self.assertNotIn("/usr/bin/blkid", command)

    def test_normalizes_candidates_without_exposing_customer_identifiers(self) -> None:
        snapshot = rescue_server.normalize_installed_targets(target_scan_fixture())
        self.assertEqual(snapshot["apiVersion"], rescue_server.TARGET_SCAN_API_VERSION)
        self.assertEqual(snapshot["mode"], "observe-r0")
        self.assertTrue(str(snapshot["scanFingerprint"]).startswith("scan:"))
        self.assertEqual(len(snapshot["disks"]), 3)
        self.assertEqual(len(snapshot["candidates"]), 4)
        self.assertEqual(
            {candidate["osFamilyHint"] for candidate in snapshot["candidates"]},
            {"linux", "macos", "unknown-encrypted", "windows"},
        )
        self.assertTrue(
            all(
                candidate["confidence"] == "low"
                and candidate["status"] == "unverified-installation-candidate"
                and candidate["inspectionMode"] == "metadata-only-no-mount"
                for candidate in snapshot["candidates"]
            )
        )
        encrypted = next(
            candidate
            for candidate in snapshot["candidates"]
            if candidate["osFamilyHint"] == "unknown-encrypted"
        )
        self.assertTrue(encrypted["requiresUnlock"])

        mounted_disks = [disk for disk in snapshot["disks"] if disk["mounted"]]
        self.assertEqual(len(mounted_disks), 2)
        self.assertTrue(all(not disk["selectionEligible"] for disk in mounted_disks))
        self.assertTrue(
            any(
                "live-or-optical-filesystem-signature" in disk["exclusionReasons"]
                for disk in snapshot["disks"]
            )
        )
        self.assertEqual(
            snapshot["claims"],
            {
                "installedOsConfirmed": False,
                "filesystemContentInspected": False,
                "mountOperationPerformed": False,
                "mutationPerformed": False,
                "rawDeviceIdentifiersReturned": False,
            },
        )

        serialized = json.dumps(snapshot)
        for private_key in (
            "mountpoints",
            "maj:min",
            "name",
            "parttype",
            "partuuid",
            "ptuuid",
            "serial",
            "uuid",
            "wwn",
        ):
            self.assertNotIn(f'"{private_key}"', serialized)
        for private_value in (
            "CUSTOMER-",
            "RESCUE-DEVICE-SECRET",
            "/run/live/medium",
            "/customer/private/path",
            "nvme0n1",
            "sda",
            "sdb",
        ):
            self.assertNotIn(private_value, serialized)

    def test_internal_resolution_binds_only_one_direct_gpt_esp_sibling(self) -> None:
        snapshot, resolutions = rescue_server._normalize_installed_targets_with_resolutions(
            target_scan_fixture()
        )
        windows = next(
            candidate
            for candidate in snapshot["candidates"]
            if candidate["osFamilyHint"] == "windows"
        )
        resolved = resolutions[windows["targetId"]]
        esp = resolved["associatedEfiSystemPartition"]
        self.assertEqual(esp["state"], "eligible")
        self.assertEqual(esp["filesystem"], "vfat")
        self.assertEqual(esp["kernelKind"], "part")
        self.assertTrue(esp["leaf"])
        self.assertTrue(esp["directOnDisk"])
        self.assertNotIn("associatedEfiSystemPartition", json.dumps(snapshot))

        duplicate = json.loads(target_scan_fixture())
        disk = duplicate["blockdevices"][1]
        disk["children"].insert(
            1,
            block_device(
                "nvme0n1p9",
                "part",
                filesystem="vfat",
                parttype=rescue_server.EFI_SYSTEM_PARTITION_TYPE,
            ),
        )
        duplicate_snapshot, duplicate_resolutions = (
            rescue_server._normalize_installed_targets_with_resolutions(
                json.dumps(duplicate)
            )
        )
        duplicate_windows = next(
            candidate
            for candidate in duplicate_snapshot["candidates"]
            if candidate["osFamilyHint"] == "windows"
        )
        self.assertEqual(
            duplicate_resolutions[duplicate_windows["targetId"]][
                "associatedEfiSystemPartition"
            ],
            {"state": "ambiguous"},
        )

        unsupported = json.loads(target_scan_fixture())
        unsupported["blockdevices"][1]["children"][0]["fstype"] = "ext4"
        unsupported_snapshot, unsupported_resolutions = (
            rescue_server._normalize_installed_targets_with_resolutions(
                json.dumps(unsupported)
            )
        )
        unsupported_windows = next(
            candidate
            for candidate in unsupported_snapshot["candidates"]
            if candidate["osFamilyHint"] == "windows"
        )
        self.assertEqual(
            unsupported_resolutions[unsupported_windows["targetId"]][
                "associatedEfiSystemPartition"
            ],
            {"state": "unsupported"},
        )

    def test_recovery_target_digest_is_strong_unique_and_never_public(self) -> None:
        filesystem_uuid = "11111111-2222-3333-4444-555555555555"
        partition_uuid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

        def fixture(*, duplicate: bool = False, serial: str = "SERIAL-001") -> str:
            disks = [
                block_device(
                    "sda",
                    "disk",
                    size=8_000_000_000,
                    serial=serial,
                    wwn="0x5000c500aabbccdd",
                    pttype="gpt",
                    children=[
                        block_device(
                            "sda1",
                            "part",
                            size=7_000_000_000,
                            filesystem="ext4",
                            uuid=filesystem_uuid,
                            partuuid=partition_uuid,
                        )
                    ],
                )
            ]
            if duplicate:
                clone = json.loads(json.dumps(disks[0]))
                clone["name"] = "sdb"
                clone["maj:min"] = "8:16"
                clone["children"][0]["name"] = "sdb1"
                clone["children"][0]["maj:min"] = "8:17"
                disks.append(clone)
            return json.dumps({"blockdevices": disks})

        snapshot, resolutions = rescue_server._normalize_installed_targets_with_resolutions(
            fixture()
        )
        candidate = snapshot["candidates"][0]
        resolution = resolutions[candidate["targetId"]]
        recovery = resolution["recoveryFingerprint"]
        self.assertRegex(recovery, r"^recovery:[0-9a-f]{64}$")
        self.assertTrue(resolution["recoveryUnique"])
        serialized = json.dumps(snapshot, separators=(",", ":"))
        self.assertNotIn("recoveryFingerprint", serialized)
        self.assertNotIn(filesystem_uuid, serialized)
        self.assertNotIn(partition_uuid, serialized)
        self.assertNotIn("0x5000c500aabbccdd", serialized)

        with patch.object(rescue_server, "_target_scan_output", return_value=fixture()):
            selection, recovered = rescue_server.resolve_recovery_target(
                {"recoveryFingerprint": recovery}, deadline=time.monotonic() + 1
            )
        self.assertEqual(selection["target"]["targetId"], candidate["targetId"])
        self.assertEqual(recovered["recoveryFingerprint"], recovery)

        duplicate_snapshot, duplicate_resolutions = (
            rescue_server._normalize_installed_targets_with_resolutions(
                fixture(duplicate=True)
            )
        )
        self.assertEqual(len(duplicate_snapshot["candidates"]), 2)
        self.assertTrue(
            all(
                value["recoveryFingerprint"] == recovery
                and value["recoveryUnique"] is False
                for value in duplicate_resolutions.values()
            )
        )
        with patch.object(
            rescue_server,
            "_target_scan_output",
            return_value=fixture(duplicate=True),
        ), self.assertRaises(rescue_server.TargetSelectionError):
            rescue_server.resolve_recovery_target(
                {"recoveryFingerprint": recovery}, deadline=time.monotonic() + 1
            )

        malformed_snapshot, malformed_resolutions = (
            rescue_server._normalize_installed_targets_with_resolutions(
                fixture(serial="serial with spaces")
            )
        )
        malformed_candidate = malformed_snapshot["candidates"][0]
        # WWN remains the preferred strong anchor, so a weak serial cannot
        # weaken an otherwise qualified identity.
        self.assertIsNotNone(
            malformed_resolutions[malformed_candidate["targetId"]][
                "recoveryFingerprint"
            ]
        )

    def test_nested_candidate_does_not_abort_efi_sibling_resolution(self) -> None:
        fixture = json.dumps(
            {
                "blockdevices": [
                    block_device(
                        "sda",
                        "disk",
                        pttype="gpt",
                        children=[
                            block_device(
                                "sda1",
                                "part",
                                filesystem="vfat",
                                parttype=rescue_server.EFI_SYSTEM_PARTITION_TYPE,
                            ),
                            block_device(
                                "sda2",
                                "part",
                                filesystem="LVM2_member",
                                children=[
                                    block_device(
                                        "vg-root",
                                        "lvm",
                                        filesystem="ext4",
                                    )
                                ],
                            ),
                        ],
                    )
                ]
            }
        )
        snapshot, resolutions = rescue_server._normalize_installed_targets_with_resolutions(
            fixture
        )
        self.assertEqual(len(snapshot["candidates"]), 1)
        candidate = snapshot["candidates"][0]
        self.assertEqual(
            resolutions[candidate["targetId"]]["associatedEfiSystemPartition"],
            {"state": "unsupported"},
        )

    def test_multi_pv_lvm_disables_only_the_involved_disks(self) -> None:
        snapshot = rescue_server.normalize_installed_targets(multi_pv_lvm_fixture())
        complex_disks = [
            disk
            for disk in snapshot["disks"]
            if "complex-multi-parent-topology" in disk["exclusionReasons"]
        ]
        self.assertEqual(len(complex_disks), 2)
        self.assertTrue(all(not disk["selectionEligible"] for disk in complex_disks))
        self.assertEqual(len(snapshot["candidates"]), 1)
        self.assertEqual(snapshot["candidates"][0]["osFamilyHint"], "windows")
        serialized = json.dumps(snapshot)
        self.assertNotIn("253:0", serialized)
        self.assertNotIn("SHARED-LV-FILESYSTEM-UUID", serialized)

    def test_incoherent_duplicate_identity_is_not_selectable(self) -> None:
        snapshot = rescue_server.normalize_installed_targets(
            multi_pv_lvm_fixture(incoherent_copy=True)
        )
        complex_disks = [
            disk
            for disk in snapshot["disks"]
            if "complex-multi-parent-topology" in disk["exclusionReasons"]
        ]
        self.assertEqual(len(complex_disks), 2)
        self.assertTrue(all(not disk["selectionEligible"] for disk in complex_disks))
        self.assertEqual(len(snapshot["candidates"]), 1)

    def test_shared_btrfs_members_are_not_installation_candidates(self) -> None:
        snapshot = rescue_server.normalize_installed_targets(shared_btrfs_fixture())
        self.assertEqual(len(snapshot["disks"]), 2)
        self.assertEqual(snapshot["candidates"], [])
        self.assertTrue(
            all(
                disk["selectionEligible"] is False
                and "complex-multi-parent-topology" in disk["exclusionReasons"]
                for disk in snapshot["disks"]
            )
        )
        serialized = json.dumps(snapshot)
        self.assertNotIn("8:33", serialized)
        self.assertNotIn("8:49", serialized)
        self.assertNotIn("SHARED-BTRFS-FILESYSTEM-UUID", serialized)

    def test_target_parser_fails_closed_on_schema_and_response_limits(self) -> None:
        malformed = json.loads(target_scan_fixture())
        malformed["blockdevices"][0]["label"] = "private-label"
        with self.assertRaises(rescue_server.TargetScanError):
            rescue_server.normalize_installed_targets(json.dumps(malformed))
        malformed_identity = json.loads(target_scan_fixture())
        malformed_identity["blockdevices"][0]["maj:min"] = "not-a-kernel-id"
        with self.assertRaises(rescue_server.TargetScanError):
            rescue_server.normalize_installed_targets(json.dumps(malformed_identity))
        with self.assertRaises(rescue_server.TargetScanError):
            rescue_server.normalize_installed_targets("{}")
        with (
            patch.object(rescue_server, "MAX_TARGET_RESPONSE_BYTES", 64),
            self.assertRaises(rescue_server.TargetScanError),
        ):
            rescue_server.normalize_installed_targets(target_scan_fixture())

    def test_target_scan_rejects_incomplete_bounded_observation(self) -> None:
        with patch.object(
            rescue_server,
            "observe",
            return_value={
                "collector": "rescue.installed-targets.metadata",
                "trust": "observed-untrusted",
                "output": "private-partial-output",
                "success": False,
                "truncated": True,
            },
        ):
            with self.assertRaisesRegex(rescue_server.TargetScanError, "incompleta"):
                rescue_server.installed_targets()

    def test_overlapping_target_scans_fail_immediately(self) -> None:
        entered = threading.Event()
        release = threading.Event()
        completed: list[dict[str, object]] = []

        def blocked_observe(
            _collector: str, _command: tuple[str, ...]
        ) -> dict[str, object]:
            entered.set()
            release.wait(timeout=3)
            return {
                "collector": "rescue.installed-targets.metadata",
                "trust": "observed-untrusted",
                "output": target_scan_fixture(),
                "success": True,
                "truncated": False,
            }

        with patch.object(rescue_server, "observe", side_effect=blocked_observe):
            worker = threading.Thread(
                target=lambda: completed.append(rescue_server.installed_targets()),
                daemon=True,
            )
            worker.start()
            try:
                self.assertTrue(entered.wait(timeout=1))
                with self.assertRaises(rescue_server.TargetScanBusy):
                    rescue_server.installed_targets()
            finally:
                release.set()
                worker.join(timeout=3)
        self.assertFalse(worker.is_alive())
        self.assertEqual(len(completed), 1)

    def test_selection_recollects_and_rejects_stale_or_unknown_targets(self) -> None:
        snapshot = rescue_server.normalize_installed_targets(target_scan_fixture())
        candidate = snapshot["candidates"][0]
        request = {
            "scanFingerprint": snapshot["scanFingerprint"],
            "targetId": candidate["targetId"],
        }
        with patch.object(
            rescue_server, "installed_targets", return_value=snapshot
        ) as recollect:
            selection = rescue_server.select_installed_target(request)
        recollect.assert_called_once_with()
        self.assertEqual(selection["status"], "observe-target-validated")
        self.assertEqual(selection["target"], candidate)
        self.assertFalse(selection["claims"]["mountOperationPerformed"])
        self.assertFalse(selection["claims"]["mutationPerformed"])

        with patch.object(rescue_server, "installed_targets", return_value=snapshot):
            with self.assertRaisesRegex(
                rescue_server.TargetSelectionError, "topologia"
            ):
                rescue_server.select_installed_target(
                    {**request, "scanFingerprint": "scan:" + "0" * 64}
                )
            with self.assertRaisesRegex(
                rescue_server.TargetSelectionError, "non è più disponibile"
            ):
                rescue_server.select_installed_target(
                    {**request, "targetId": "target:" + "0" * 64}
                )
        with self.assertRaises(rescue_server.TargetSelectionError) as malformed:
            rescue_server.select_installed_target({"targetId": "shell.exec"})
        self.assertEqual(malformed.exception.status, 400)

    def test_http_scan_and_selection_return_only_normalized_observe_data(self) -> None:
        snapshot = rescue_server.normalize_installed_targets(target_scan_fixture())
        candidate = snapshot["candidates"][0]
        server = rescue_server.BoundedThreadingHTTPServer(
            ("127.0.0.1", 0), rescue_server.RescueHandler
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = server.server_address[1]
        try:
            with patch.object(rescue_server, "installed_targets", return_value=snapshot):
                connection = HTTPConnection("127.0.0.1", port)
                connection.request(
                    "GET",
                    "/api/rescue/installed-targets",
                    headers={"Host": "127.0.0.1:4173"},
                )
                response = connection.getresponse()
                self.assertEqual(response.status, 200)
                returned_scan = json.loads(response.read())
                self.assertEqual(returned_scan, snapshot)
                self.assertEqual(response.getheader("Cache-Control"), "no-store")
                connection.close()

                connection = HTTPConnection("127.0.0.1", port)
                connection.request(
                    "POST",
                    "/api/rescue/select-installed-target",
                    body=json.dumps(
                        {
                            "scanFingerprint": snapshot["scanFingerprint"],
                            "targetId": candidate["targetId"],
                        }
                    ),
                    headers={
                        "Host": "127.0.0.1:4173",
                        "Origin": "http://127.0.0.1:4173",
                        "Content-Type": "application/json",
                    },
                )
                response = connection.getresponse()
                self.assertEqual(response.status, 200)
                selection = json.loads(response.read())
                self.assertEqual(selection["status"], "observe-target-validated")
                self.assertFalse(selection["claims"]["filesystemContentInspected"])
                connection.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
