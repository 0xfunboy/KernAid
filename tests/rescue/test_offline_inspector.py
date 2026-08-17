#!/usr/bin/python3
"""Contracts for the isolated, read-only Rescue filesystem inspector."""

from importlib.util import module_from_spec, spec_from_file_location
from http.client import HTTPConnection
import hashlib
import json
import os
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest
from unittest.mock import patch


ROOT = Path(__file__).parents[2]
SERVER_PATH = ROOT / "rescue/live-build/config/includes.chroot/usr/lib/kernaid/rescue_server.py"
INSPECTOR_PATH = ROOT / "rescue/live-build/config/includes.chroot/usr/lib/kernaid/offline_inspector.py"
READY_CHECK = ROOT / "rescue/live-build/config/includes.chroot/usr/lib/kernaid/ready-check"
QEMU_SMOKE = ROOT / "tools/build-rescue/qemu-smoke.sh"
UI_SERVICE = ROOT / "rescue/live-build/config/includes.chroot/etc/systemd/system/kernaid-ui.service"
HELPER_SERVICE = ROOT / "rescue/live-build/config/includes.chroot/etc/systemd/system/kernaid-offline-inspector@.service"
HELPER_KEY_SERVICE = ROOT / "rescue/live-build/config/includes.chroot/etc/systemd/system/kernaid-offline-inspector-key.service"
HELPER_SOCKET = ROOT / "rescue/live-build/config/includes.chroot/etc/systemd/system/kernaid-offline-inspector.socket"
SAFETY_HOOK = ROOT / "rescue/live-build/config/hooks/live/0100-kernaid-safety.hook.chroot"


def load_module(name: str, path: Path) -> object:
    spec = spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


rescue_server = load_module("kernaid_rescue_server_offline_tests", SERVER_PATH)
offline_inspector = load_module("kernaid_offline_inspector_tests", INSPECTOR_PATH)

SCAN_ID = "scan:" + "1" * 64
TARGET_ID = "target:" + "2" * 64
DISK_ID = "disk:" + "3" * 64
REQUEST = {"scanFingerprint": SCAN_ID, "targetId": TARGET_ID}


def candidate(family: str = "linux", *, unlock: bool = False) -> dict[str, object]:
    return {
        "targetId": TARGET_ID,
        "sourceRef": "disk-1/volume-1",
        "diskId": DISK_ID,
        "osFamilyHint": family,
        "confidence": "low",
        "status": "unverified-installation-candidate",
        "detectionBasis": [f"{family}-filesystem-signature"],
        "requiresUnlock": unlock,
        "inspectionMode": "metadata-only-no-mount",
        "selectionEligible": True,
    }


def selection(value: dict[str, object] | None = None) -> dict[str, object]:
    return {
        "apiVersion": rescue_server.TARGET_SCAN_API_VERSION,
        "status": "observe-target-validated",
        "scanFingerprint": SCAN_ID,
        "target": candidate() if value is None else value,
        "claims": {
            "installedOsConfirmed": False,
            "filesystemContentInspected": False,
            "mountOperationPerformed": False,
            "mutationPerformed": False,
        },
    }


def resolution(
    filesystem: str = "ext4",
    *,
    family: str = "linux",
    kind: str = "part",
    topology_kinds: list[str] | None = None,
    topology_filesystems: list[str] | None = None,
    unlock: bool = False,
) -> dict[str, object]:
    return {
        "candidate": candidate(family, unlock=unlock),
        "deviceIdentity": {"maj:min": "8:2", "type": kind},
        "majorMinor": "8:2",
        "filesystem": filesystem,
        "kernelKind": kind,
        "leaf": True,
        "directOnDisk": True,
        "topologyKinds": ["disk", kind] if topology_kinds is None else topology_kinds,
        "topologyFilesystems": [filesystem]
        if topology_filesystems is None
        else topology_filesystems,
    }


class FakeTargets:
    TargetScanBusy = rescue_server.TargetScanBusy
    TargetScanError = rescue_server.TargetScanError
    TargetSelectionError = rescue_server.TargetSelectionError

    def __init__(self, resolved: dict[str, object] | None = None) -> None:
        self.resolved = resolution() if resolved is None else resolved
        self.resolve_count = 0

    def resolve_installed_target(
        self, request: dict[str, object], *, deadline: float
    ) -> tuple[dict[str, object], dict[str, object]]:
        if request != REQUEST or deadline <= time.monotonic():
            raise self.TargetSelectionError("stale")
        self.resolve_count += 1
        selected = self.resolved["candidate"]
        if not isinstance(selected, dict):
            raise RuntimeError("bad fake candidate")
        return selection(selected), json.loads(json.dumps(self.resolved))

    @staticmethod
    def canonical_target_selection(value: object) -> str:
        return json.dumps(value, sort_keys=True, separators=(",", ":"))

    def installed_targets(self, *, deadline: float) -> dict[str, object]:
        return {"apiVersion": "test", "deadlineActive": deadline > time.monotonic()}

    def select_installed_target(
        self, request: dict[str, object], *, deadline: float
    ) -> dict[str, object]:
        selected, _resolved = self.resolve_installed_target(request, deadline=deadline)
        return selected


class CorpusTests(unittest.TestCase):
    def test_linux_corpus_is_normalized_bounded_and_does_not_return_identifiers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "etc").mkdir()
            (root / "usr/lib").mkdir(parents=True)
            (root / "boot/grub").mkdir(parents=True)
            (root / "var/lib/dpkg").mkdir(parents=True)
            (root / "etc/os-release").write_text(
                'ID=debian\nNAME="Debian GNU/Linux"\nPRETTY_NAME="Customer Lab Secret OS"\nVERSION_ID="13"\n',
                encoding="utf-8",
            )
            (root / "etc/fstab").write_text(
                "UUID=customer-secret / ext4 defaults 0 1\nserver:/private /mnt nfs ro 0 0\n",
                encoding="utf-8",
            )
            (root / "etc/machine-id").write_text("customer-machine-secret\n", encoding="ascii")
            (root / "boot/vmlinuz-6.12-test").write_bytes(b"kernel")
            (root / "boot/initrd.img-6.12-test").write_bytes(b"initramfs")
            (root / "var/lib/dpkg/status").write_text("Package: secret\n", encoding="utf-8")
            root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                result = offline_inspector.collect_linux(
                    root_fd, time.monotonic() + 2
                )
            finally:
                os.close(root_fd)
        self.assertTrue(result["installationConfirmed"])
        self.assertEqual(result["family"], "linux")
        self.assertEqual(result["release"]["id"], "debian")
        self.assertEqual(result["boot"]["kernelArtifactCount"], 1)
        self.assertTrue(result["configuration"]["machineIdPresent"])
        self.assertEqual(result["configuration"]["fstab"]["networkEntryCount"], 1)
        encoded = json.dumps(result, sort_keys=True)
        self.assertNotIn("customer-machine-secret", encoded)
        self.assertNotIn("UUID=customer-secret", encoded)
        self.assertNotIn("server:/private", encoded)
        self.assertNotIn("Package: secret", encoded)

    def test_os_release_symlink_is_never_followed_and_uses_fixed_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "etc").mkdir()
            (root / "usr/lib").mkdir(parents=True)
            (root / "etc/os-release").symlink_to("../outside-secret")
            (root / "usr/lib/os-release").write_text("ID=fallback\n", encoding="ascii")
            root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                result = offline_inspector.collect_linux(
                    root_fd, time.monotonic() + 2
                )
            finally:
                os.close(root_fd)
        self.assertEqual(result["release"]["id"], "fallback")
        self.assertEqual(result["release"]["source"], "usr-lib-os-release")

    def test_windows_corpus_uses_only_static_presence_markers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Windows/System32/config").mkdir(parents=True)
            (root / "Windows/WinSxS").mkdir(parents=True)
            (root / "Users/Customer Name").mkdir(parents=True)
            for relative in (
                "Windows/System32/ntoskrnl.exe",
                "Windows/System32/config/SYSTEM",
                "Windows/System32/config/SOFTWARE",
                "Windows/WinSxS/pending.xml",
            ):
                (root / relative).write_bytes(b"customer-secret-registry-content")
            root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                result = offline_inspector.collect_windows(
                    root_fd, time.monotonic() + 2
                )
            finally:
                os.close(root_fd)
        self.assertTrue(result["installationConfirmed"])
        self.assertTrue(result["installationMarkers"]["usersDirectoryPresent"])
        self.assertTrue(result["servicing"]["pendingXmlPresent"])
        encoded = json.dumps(result, sort_keys=True)
        self.assertNotIn("Customer Name", encoded)
        self.assertNotIn("customer-secret", encoded)

    def test_symlink_fifo_and_oversize_allowed_files_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "etc").mkdir()
            (root / "etc/os-release").write_text("ID=test\n", encoding="ascii")
            (root / "etc/fstab").symlink_to("/etc/passwd")
            root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with self.assertRaisesRegex(
                    offline_inspector.InspectionError, "non è sicuro"
                ):
                    offline_inspector.collect_linux(root_fd, time.monotonic() + 2)
            finally:
                os.close(root_fd)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "etc").mkdir()
            os.mkfifo(root / "etc/fstab")
            root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with self.assertRaises(offline_inspector.InspectionError):
                    offline_inspector.collect_linux(root_fd, time.monotonic() + 2)
            finally:
                os.close(root_fd)

    def test_boot_directory_iteration_stops_at_the_entry_cap(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "etc").mkdir()
            (root / "usr").mkdir()
            (root / "etc/os-release").write_text("ID=test\n", encoding="ascii")
            (root / "boot").mkdir()
            for index in range(offline_inspector.MAX_DIRECTORY_ENTRIES + 1):
                (root / "boot" / f"artifact-{index:04d}").write_bytes(b"")
            root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with self.assertRaisesRegex(
                    offline_inspector.InspectionError, "directory boot"
                ):
                    offline_inspector.collect_linux(
                        root_fd, time.monotonic() + 2
                    )
            finally:
                os.close(root_fd)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "etc").mkdir()
            (root / "etc/os-release").write_bytes(
                b"ID=" + b"a" * offline_inspector.MAX_OS_RELEASE_BYTES
            )
            root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with self.assertRaises(offline_inspector.InspectionError):
                    offline_inspector.collect_linux(root_fd, time.monotonic() + 2)
            finally:
                os.close(root_fd)


class QualificationTests(unittest.TestCase):
    def assert_code(self, value: dict[str, object], code: str) -> None:
        with self.assertRaises(offline_inspector.InspectionError) as context:
            offline_inspector._qualify_resolution(value)
        self.assertEqual(context.exception.code, code)

    def test_allows_only_direct_leaf_ext4_and_ntfs(self) -> None:
        self.assertEqual(
            offline_inspector._qualify_resolution(resolution()),
            ("ext4", "noload", "linux", "journal-replay-disabled"),
        )
        self.assertEqual(
            offline_inspector._qualify_resolution(
                resolution("ntfs", family="windows")
            ),
            (
                "ntfs3",
                None,
                "windows",
                "read-only-no-force-driver-replay-not-applied",
            ),
        )

    def test_encrypted_apple_stacked_unsupported_and_ambiguous_fail_typed(self) -> None:
        self.assert_code(
            resolution("crypto_luks", family="unknown-encrypted", unlock=True),
            "unsupported-encrypted-storage",
        )
        self.assert_code(
            resolution("bitlocker", family="windows", unlock=True),
            "unsupported-encrypted-storage",
        )
        self.assert_code(
            resolution("apfs", family="macos"), "unsupported-apple-filesystem"
        )
        self.assert_code(
            resolution(
                "ext4",
                kind="lvm",
                topology_kinds=["disk", "lvm"],
                topology_filesystems=["lvm2_member", "ext4"],
            ),
            "unsupported-complex-storage",
        )
        self.assert_code(
            resolution(
                "ext4",
                topology_kinds=["disk", "part", "md"],
                topology_filesystems=["linux_raid_member", "ext4"],
            ),
            "unsupported-complex-storage",
        )
        self.assert_code(resolution("btrfs"), "unsupported-filesystem")
        self.assert_code(
            resolution("ext4", family="windows"), "ambiguous-os-family"
        )


class EngineTests(unittest.TestCase):
    def run_engine(
        self,
        targets: FakeTargets | None = None,
        *,
        umount_error: OSError | None = None,
    ) -> tuple[dict[str, object], list[tuple[object, ...]]]:
        fake_targets = FakeTargets() if targets is None else targets
        engine = offline_inspector.OfflineInspectionEngine(fake_targets)
        calls: list[tuple[object, ...]] = []
        descriptor = os.open("/dev/null", os.O_RDONLY)

        def mount_call(*args: object) -> None:
            calls.append(("mount", *args))

        def umount_call(*args: object) -> None:
            calls.append(("umount", *args))
            if umount_error is not None:
                raise umount_error

        normalized_linux = {
            "family": "linux",
            "installationConfirmed": True,
            "release": {
                "id": "debian",
                "name": "Debian",
                "prettyName": "Debian",
                "versionId": "13",
                "source": "etc-os-release",
            },
            "boot": {
                "directoryPresent": True,
                "kernelArtifactCount": 1,
                "initramfsArtifactCount": 1,
                "bootloaderDirectoryCount": 1,
                "symlinkArtifactCount": 0,
            },
            "configuration": {
                "fstab": {
                    "present": True,
                    "entryCount": 1,
                    "rootEntryPresent": True,
                    "efiEntryPresent": False,
                    "swapEntryCount": 0,
                    "networkEntryCount": 0,
                    "malformedLineCount": 0,
                },
                "machineIdPresent": True,
            },
            "packageDatabases": {
                "dpkgStatusPresent": True,
                "rpmDatabasePresent": False,
                "pacmanDatabasePresent": False,
            },
        }
        normalized_windows = {
            "family": "windows",
            "installationConfirmed": True,
            "installationMarkers": {
                "windowsDirectoryPresent": True,
                "system32DirectoryPresent": True,
                "kernelPresent": True,
                "systemHivePresent": True,
                "softwareHivePresent": True,
                "usersDirectoryPresent": True,
            },
            "boot": {"bootManagerPresent": True, "bcdPresent": True, "efiBcdPresent": False},
            "servicing": {
                "pendingXmlPresent": True,
                "rebootPendingMarkerPresent": False,
            },
        }
        with (
            tempfile.TemporaryDirectory() as mount_base,
            patch.object(offline_inspector, "MOUNT_BASE", mount_base),
            patch.object(offline_inspector, "_ensure_mount_base"),
            patch.object(
                offline_inspector, "_target_already_mounted", return_value=False
            ),
            patch.object(
                offline_inspector,
                "_open_bound_block_device",
                return_value=(descriptor, 8, 2),
            ),
            patch.object(offline_inspector, "_assert_block_fd"),
            patch.object(offline_inspector, "_mount_call", side_effect=mount_call),
            patch.object(offline_inspector, "_verify_mounted"),
            patch.object(offline_inspector, "collect_linux", return_value=normalized_linux),
            patch.object(
                offline_inspector, "collect_windows", return_value=normalized_windows
            ),
            patch.object(offline_inspector, "_umount_call", side_effect=umount_call),
            patch.object(offline_inspector, "_verify_unmounted"),
        ):
            result = engine.inspect(REQUEST, time.monotonic() + 2)
        return result, calls

    def test_mount_policy_is_fixed_no_replay_and_cleanup_precedes_success(self) -> None:
        result, calls = self.run_engine()
        mount = next(call for call in calls if call[0] == "mount")
        self.assertRegex(mount[1].decode("ascii"), r"^/proc/self/fd/[0-9]+$")
        self.assertEqual(mount[3], b"ext4")
        flags = mount[4]
        for required in (
            offline_inspector.MS_RDONLY,
            offline_inspector.MS_NOSUID,
            offline_inspector.MS_NODEV,
            offline_inspector.MS_NOEXEC,
            offline_inspector.MS_NOSYMFOLLOW,
        ):
            self.assertEqual(flags & required, required)
        self.assertEqual(mount[5], b"noload")
        self.assertEqual(calls[-1][0], "umount")
        self.assertEqual(calls[-1][2], 0)
        self.assertTrue(result["claims"]["filesystemContentInspected"])
        self.assertTrue(result["claims"]["mountCleanupVerified"])
        self.assertFalse(result["claims"]["mutationPerformed"])
        self.assertFalse(result["claims"]["diagnosisProduced"])
        self.assertFalse(result["claims"]["repairAttempted"])
        self.assertNotIn("majorMinor", json.dumps(result))

    def test_normal_unmount_failure_is_fatal_and_never_uses_lazy_detach(self) -> None:
        with self.assertRaises(offline_inspector.InspectionError) as context:
            self.run_engine(umount_error=OSError(errno := 16, os.strerror(errno)))
        self.assertEqual(context.exception.code, "mount-cleanup-failed")
        self.assertTrue(context.exception.fatal_cleanup)
        self.assertFalse(context.exception.claims["mountCleanupVerified"])
        with self.assertRaises(ValueError):
            offline_inspector._umount_call(b"/run/test", offline_inspector.MNT_DETACH)

    def test_a_b_resolution_change_after_unmount_fails_closed(self) -> None:
        targets = FakeTargets()
        original = targets.resolve_installed_target

        def changed(request: dict[str, object], *, deadline: float):
            selected, resolved = original(request, deadline=deadline)
            if targets.resolve_count == 2:
                resolved["majorMinor"] = "8:3"
            return selected, resolved

        targets.resolve_installed_target = changed  # type: ignore[method-assign]
        with self.assertRaises(offline_inspector.InspectionError) as context:
            self.run_engine(targets)
        self.assertEqual(context.exception.code, "target-identity-changed")

    def test_ntfs_mount_is_read_only_without_force_and_volume_state_unqualified(self) -> None:
        targets = FakeTargets(resolution("ntfs", family="windows"))
        result, calls = self.run_engine(targets)
        mount = next(call for call in calls if call[0] == "mount")
        self.assertEqual(mount[3], b"ntfs3")
        self.assertEqual(mount[4] & offline_inspector.MS_RDONLY, offline_inspector.MS_RDONLY)
        self.assertIsNone(mount[5])
        self.assertEqual(
            result["inspection"]["dirtyVolumePolicy"],
            "read-only-no-force-driver-replay-not-applied",
        )
        self.assertEqual(
            result["inspection"]["volumeStateQualification"], "unqualified"
        )
        self.assertIn(
            "ntfs-dirty-and-hibernated-state-was-not-qualified",
            result["limitations"],
        )
        self.assertNotIn("ntfsinfo", INSPECTOR_PATH.read_text(encoding="utf-8"))

    def test_ntfs_mount_verification_rejects_force_superoption(self) -> None:
        entry = {
            "mountpoint": "/run/test",
            "majorMinor": "8:2",
            "filesystem": "ntfs3",
            "options": {"ro", "nodev", "nosuid", "noexec", "nosymfollow"},
            "superOptions": {"ro"},
        }
        metadata = type("Metadata", (), {"st_dev": os.makedev(8, 2)})()
        statvfs = type("Statvfs", (), {"f_flag": os.ST_RDONLY})()
        with (
            patch.object(offline_inspector, "_assert_block_fd"),
            patch.object(offline_inspector, "_mountinfo_entries", return_value=[entry]),
            patch.object(offline_inspector.os, "stat", return_value=metadata),
            patch.object(offline_inspector.os, "statvfs", return_value=statvfs),
        ):
            offline_inspector._verify_mounted(
                "/run/test", "8:2", "ntfs3", None, 7, 8, 2
            )
            entry["superOptions"] = {"ro", "force"}
            with self.assertRaises(offline_inspector.InspectionError) as context:
                offline_inspector._verify_mounted(
                    "/run/test", "8:2", "ntfs3", None, 7, 8, 2
                )
        self.assertEqual(context.exception.code, "mount-verification-failed")

    def test_mountinfo_reader_consumes_short_reads_to_eof(self) -> None:
        payload = (
            b"36 25 8:2 / /run/test ro,nodev,nosuid,noexec,nosymfollow"
            b" - ntfs3 /dev/vda2 ro\n"
        )
        with (
            patch.object(offline_inspector.os, "open", return_value=91),
            patch.object(
                offline_inspector.os,
                "read",
                side_effect=[payload[:17], payload[17:53], payload[53:], b""],
            ),
            patch.object(offline_inspector.os, "close"),
        ):
            entries = offline_inspector._mountinfo_entries()
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["majorMinor"], "8:2")
        self.assertEqual(entries[0]["filesystem"], "ntfs3")
        self.assertEqual(entries[0]["superOptions"], {"ro"})


class BoundaryTests(unittest.TestCase):
    def test_boot_key_file_load_is_stable_across_helper_instances(self) -> None:
        expected = bytes(range(32))
        with tempfile.TemporaryDirectory() as directory:
            key_path = Path(directory) / "target-id.key"
            key_path.write_bytes(expected)
            key_path.chmod(0o600)
            real_fstat = os.fstat

            def root_owned_fstat(descriptor: int) -> object:
                metadata = real_fstat(descriptor)
                return type(
                    "RootOwnedMetadata",
                    (),
                    {
                        "st_mode": metadata.st_mode,
                        "st_uid": 0,
                        "st_gid": 0,
                        "st_nlink": metadata.st_nlink,
                        "st_size": metadata.st_size,
                        "st_dev": metadata.st_dev,
                        "st_ino": metadata.st_ino,
                        "st_mtime_ns": metadata.st_mtime_ns,
                    },
                )()

            with (
                patch.object(rescue_server, "TARGET_ID_KEY_FILE", str(key_path)),
                patch.dict(
                    os.environ,
                    {"KERNAID_TARGET_ID_KEY_FILE": str(key_path)},
                    clear=False,
                ),
                patch.object(
                    rescue_server.os, "fstat", side_effect=root_owned_fstat
                ),
            ):
                first_instance_key = rescue_server._load_target_id_key()
                second_instance_key = rescue_server._load_target_id_key()
        self.assertEqual(first_instance_key, expected)
        self.assertEqual(second_instance_key, expected)

    def test_systemd_activation_consumes_connected_fd3(self) -> None:
        parent_connection, child_connection = socket.socketpair(
            socket.AF_UNIX, socket.SOCK_STREAM
        )
        read_status, write_status = os.pipe()
        child_pid = os.fork()
        if child_pid == 0:
            try:
                parent_connection.close()
                os.close(read_status)
                child_fd = child_connection.detach()
                if child_fd != 3:
                    os.dup2(child_fd, 3)
                    os.close(child_fd)
                os.environ["LISTEN_PID"] = str(os.getpid())
                os.environ["LISTEN_FDS"] = "1"
                offline_inspector.SOCKET_PATH = ""
                activated = offline_inspector._systemd_connection()
                activated.sendall(b"connected-fd3")
                activated.close()
                os.write(write_status, b"ok")
                os.close(write_status)
                os._exit(0)
            except BaseException as error:
                os.write(write_status, type(error).__name__.encode("ascii", "replace"))
                os.close(write_status)
                os._exit(1)
        child_connection.close()
        os.close(write_status)
        with parent_connection:
            parent_connection.settimeout(2)
            payload = parent_connection.recv(64)
        status_payload = os.read(read_status, 64)
        os.close(read_status)
        _pid, wait_status = os.waitpid(child_pid, 0)
        self.assertEqual(wait_status, 0, status_payload.decode("ascii", "replace"))
        self.assertEqual(status_payload, b"ok")
        self.assertEqual(payload, b"connected-fd3")

    def test_one_shot_helper_handles_exactly_one_connected_frame(self) -> None:
        server_connection, client_connection = socket.socketpair(
            socket.AF_UNIX, socket.SOCK_STREAM
        )
        service = offline_inspector.OfflineInspectorService(FakeTargets())
        with patch.object(offline_inspector, "make_mount_namespace_private"):
            thread = threading.Thread(
                target=offline_inspector.serve_connection,
                args=(server_connection, service),
            )
            thread.start()
            with client_connection:
                client_connection.sendall(b'{"operation":"scan"}\n')
                client_connection.shutdown(socket.SHUT_WR)
                payload = bytearray()
                while True:
                    chunk = client_connection.recv(4096)
                    if not chunk:
                        break
                    payload.extend(chunk)
            thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(payload.count(b"\n"), 1)
        response = json.loads(payload)
        self.assertTrue(response["ok"])
        self.assertTrue(response["result"]["deadlineActive"])

    def test_fstat_failure_remains_a_typed_identity_error(self) -> None:
        with (
            patch.object(offline_inspector.os, "fstat", side_effect=OSError("gone")),
            self.assertRaises(offline_inspector.InspectionError) as context,
        ):
            offline_inspector._assert_block_fd(9, 8, 2)
        self.assertEqual(context.exception.code, "target-identity-changed")
        self.assertEqual(context.exception.status, 409)
        self.assertTrue(context.exception.retryable)

    def test_root_helper_reuses_the_process_group_bounded_target_resolver(self) -> None:
        source = SERVER_PATH.read_text(encoding="utf-8")
        self.assertEqual(
            offline_inspector.TARGET_MODULE_PATH,
            "/usr/lib/kernaid/rescue_server.py",
        )
        self.assertIn("start_new_session=True", source)
        self.assertIn("os.killpg(process.pid, signal.SIGKILL)", source)
        self.assertIn("process.wait(timeout=", source)
        service = offline_inspector.OfflineInspectorService(FakeTargets())
        response = service.handle({"operation": "scan"})
        self.assertTrue(response["ok"])
        self.assertTrue(response["result"]["deadlineActive"])

    def test_server_internal_resolution_never_enters_public_scan(self) -> None:
        fixture = {
            "blockdevices": [
                {
                    "name": "vda",
                    "maj:min": "254:0",
                    "type": "disk",
                    "size": 134_217_728,
                    "ro": False,
                    "rm": False,
                    "tran": "virtio",
                    "fstype": "ext4",
                    "fsver": "1.0",
                    "mountpoints": [],
                    "uuid": "CUSTOMER-SECRET-UUID",
                    "partuuid": None,
                    "ptuuid": None,
                    "pttype": None,
                    "parttype": None,
                    "serial": "CUSTOMER-SECRET-SERIAL",
                    "wwn": None,
                }
            ]
        }
        snapshot, resolutions = rescue_server._normalize_installed_targets_with_resolutions(
            json.dumps(fixture)
        )
        target = snapshot["candidates"][0]
        internal = resolutions[target["targetId"]]
        self.assertEqual(internal["majorMinor"], "254:0")
        self.assertEqual(internal["filesystem"], "ext4")
        public = json.dumps(snapshot, sort_keys=True)
        self.assertNotIn("254:0", public)
        self.assertNotIn("CUSTOMER-SECRET", public)

    def test_helper_protocol_rejects_paths_commands_and_extra_fields(self) -> None:
        service = offline_inspector.OfflineInspectorService(FakeTargets())
        for invalid in (
            {"operation": "inspect", "request": {**REQUEST, "path": "/dev/sda"}},
            {"operation": "mount", "request": REQUEST},
            {"operation": "inspect", "request": {"device": "/dev/sda"}},
            {"operation": "inspect", "request": REQUEST, "command": "sh"},
        ):
            response = service.handle(invalid)
            self.assertFalse(response["ok"])
            self.assertEqual(response["status"], 400)

    def test_server_ipc_parser_requires_exact_typed_response(self) -> None:
        error_claims = {
            field: False for field in rescue_server.OFFLINE_INSPECTION_CLAIM_FIELDS
        }
        response = {
            "ok": False,
            "status": 422,
            "error": {
                "code": "unsupported-filesystem",
                "message": "Filesystem non supportato.",
                "retryable": False,
                "claims": error_claims,
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "helper.sock")
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(path)
            listener.listen(1)

            def answer() -> None:
                connection, _address = listener.accept()
                with connection:
                    request = b""
                    while not request.endswith(b"\n"):
                        request += connection.recv(4096)
                    self.assertEqual(
                        json.loads(request),
                        {"operation": "inspect", "request": REQUEST},
                    )
                    connection.sendall(json.dumps(response).encode() + b"\n")

            thread = threading.Thread(target=answer)
            thread.start()
            try:
                with (
                    patch.object(rescue_server, "OFFLINE_HELPER_SOCKET", path),
                    self.assertRaises(rescue_server.PrivilegedHelperError) as context,
                ):
                    rescue_server._privileged_helper_call("inspect", REQUEST)
            finally:
                thread.join(2)
                listener.close()
        self.assertEqual(context.exception.status, 422)
        self.assertEqual(context.exception.error["code"], "unsupported-filesystem")

    def test_http_inspection_endpoint_is_same_origin_exact_and_no_store(self) -> None:
        result = {
            "apiVersion": offline_inspector.API_VERSION,
            "status": "installed-os-content-inspected",
            "trust": "observed-untrusted",
        }
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
            rescue_server, "_privileged_helper_call", return_value=result
        ) as helper:
            connection = HTTPConnection("127.0.0.1", port)
            connection.request(
                "POST",
                "/api/rescue/inspect-installed-target",
                body=json.dumps(REQUEST),
                headers={
                    "Host": "127.0.0.1:4173",
                    "Origin": "http://127.0.0.1:4173",
                    "Content-Type": "application/json",
                },
            )
            response = connection.getresponse()
            body = json.loads(response.read())
            self.assertEqual(response.status, 200)
            self.assertEqual(response.getheader("Cache-Control"), "no-store")
            self.assertEqual(body, result)
            connection.close()
        helper.assert_called_once_with("inspect", REQUEST)

        connection = HTTPConnection("127.0.0.1", port)
        connection.request(
            "POST",
            "/api/rescue/inspect-installed-target",
            body=json.dumps(REQUEST),
            headers={
                "Host": "127.0.0.1:4173",
                "Origin": "https://attacker.invalid",
                "Content-Type": "application/json",
            },
        )
        self.assertEqual(connection.getresponse().status, 403)
        connection.close()

    def test_systemd_boundary_keeps_ui_unprivileged_and_helper_isolated(self) -> None:
        ui = UI_SERVICE.read_text(encoding="utf-8")
        helper = HELPER_SERVICE.read_text(encoding="utf-8")
        key_service = HELPER_KEY_SERVICE.read_text(encoding="utf-8")
        helper_socket = HELPER_SOCKET.read_text(encoding="utf-8")
        self.assertIn("DynamicUser=yes", ui)
        self.assertIn("NoNewPrivileges=yes", ui)
        self.assertNotIn("CAP_SYS_ADMIN", ui)
        self.assertIn("SupplementaryGroups=kernaid-inspect", ui)
        self.assertIn("SocketMode=0660", helper_socket)
        self.assertIn("SocketGroup=kernaid-inspect", helper_socket)
        self.assertNotIn("0666", helper_socket)
        self.assertIn("Accept=yes", helper_socket)
        self.assertIn("MaxConnections=1", helper_socket)
        self.assertNotIn("Service=", helper_socket)
        self.assertIn("PrivateMounts=yes", helper)
        self.assertIn("PrivateNetwork=yes", helper)
        self.assertIn("CapabilityBoundingSet=CAP_SYS_ADMIN CAP_DAC_READ_SEARCH", helper)
        self.assertIn("KillMode=control-group", helper)
        self.assertIn("RuntimeMaxSec=20", helper)
        self.assertIn("Restart=no", helper)
        self.assertIn("KERNAID_TARGET_ID_KEY_FILE=", helper)
        self.assertIn("RuntimeDirectory=kernaid-offline-inspector", key_service)
        self.assertIn("--initialize-target-key", key_service)
        self.assertEqual(rescue_server.TARGET_ID_SCOPE, "ephemeral-rescue-process")
        self.assertIn("ephemeral-rescue-boot", SERVER_PATH.read_text(encoding="utf-8"))
        self.assertIn(
            'data.get("identifierScope") == "ephemeral-rescue-boot"',
            READY_CHECK.read_text(encoding="utf-8"),
        )
        hook = SAFETY_HOOK.read_text(encoding="utf-8")
        self.assertIn("chown root:root", hook)
        self.assertIn("chmod 0644", hook)

    def test_qemu_contract_requires_real_inspection_and_zero_write_hash(self) -> None:
        ready = READY_CHECK.read_text(encoding="utf-8")
        smoke = QEMU_SMOKE.read_text(encoding="utf-8")
        opt_in = ready.index('if [ "$offline_inspection_smoke" = "1" ]')
        endpoint = ready.index("/api/rescue/inspect-installed-target", opt_in)
        self.assertIn("installed-os-content-inspected", ready)
        self.assertIn("journalReplayPrevented", ready)
        self.assertIn("KERNAID_RESCUE_OFFLINE_INSPECTION_READY", ready)
        self.assertLess(opt_in, endpoint)
        self.assertIn("KERNAID_RESCUE_OFFLINE_INSPECTION_READY", smoke)
        self.assertIn("name=opt/kernaid-offline-inspection,string=v1", smoke)
        self.assertIn("debugfs", smoke)
        self.assertIn("feature needs_recovery", smoke)
        self.assertIn("mkfs.ntfs", smoke)
        self.assertIn("ntfsfix", smoke)
        self.assertNotIn('"norecover"', ready)
        self.assertNotIn("ntfsinfo", ready)
        self.assertNotIn("unsafe-ntfs-volume-state", ready)
        self.assertIn("read-only-no-force-driver-replay-not-applied", ready)
        self.assertIn("volumeStateQualification", ready)
        self.assertIn("ntfs-dirty-and-hibernated-state-was-not-qualified", ready)
        self.assertIn("len(candidates) == 2", ready)
        self.assertIn("Windows fixture targets are not distinct", ready)
        self.assertNotIn("dirty_windows_", smoke)
        self.assertIn("windows_target_hash_before=", smoke)
        self.assertIn("windows_target_hash_after=", smoke)
        self.assertIn(
            '"$windows_target_hash_after" != "$windows_target_hash_before"', smoke
        )
        self.assertIn("altered_windows_target_hash_before=", smoke)
        self.assertIn("altered_windows_target_hash_after=", smoke)
        self.assertIn(
            '"$altered_windows_target_hash_after" != "$altered_windows_target_hash_before"',
            smoke,
        )
        self.assertIn("KERNAID_QEMU_OFFLINE_INSPECTION_ATTESTATION_V1", smoke)
        before = smoke.index("target_hash_before=")
        inspection = smoke.index("KERNAID_RESCUE_OFFLINE_INSPECTION_READY")
        after = smoke.index("target_hash_after=", inspection)
        comparison = smoke.index('"$target_hash_after" != "$target_hash_before"', after)
        self.assertLess(before, inspection)
        self.assertLess(inspection, after)
        self.assertLess(after, comparison)


if __name__ == "__main__":
    unittest.main()
