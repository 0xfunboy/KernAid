#!/usr/bin/python3
"""Disabled-by-default root handoff for one Rescue repair target capability.

The normal operation accepts boot-ephemeral opaque identifiers. The recovery
operation accepts only a reboot-stable opaque digest. Both rescan twice and
return fresh path-free claims plus an ordered, closed read-only capability
bundle: selected leaf, physical parent, sealed UUID inventory and detached
ext4 mount. No writable device or attached mount crosses this boundary.
"""

from __future__ import annotations

import array
import ctypes
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import socket
import stat
import struct
import sys
import time
import types


API_VERSION = "kernaid.dev/rescue-target-capability/v1alpha2"
ACQUIRE_OPERATION = "target.readonly.acquire"
RECOVERY_OPERATION = "target.recovery.readonly.acquire"
# Kept as the existing operation alias for callers which only use acquisition.
OPERATION = ACQUIRE_OPERATION
SOCKET_PATH = "/run/kernaid-rescue-target-capability.sock"
WRITE_SOCKET_PATH = "/run/kernaid-rescue-target-write-capability.sock"
VAULT_HELPER_SOCKET_PATH = "/run/kernaid-rescue-vault/repair-target-helper-v1.sock"
PROFILE_READONLY = "readonly"
PROFILE_WRITE = "write"
WRITE_OPERATION = "target.pending.readwrite.acquire"
VAULT_API_VERSION = "kernaid.dev/rescue-vault/v1alpha1"
VAULT_WRITE_OPERATION = "repair.transaction.write-lease.consume"
TARGET_MODULE_PATH = "/usr/lib/kernaid/rescue_server.py"
PASSWD_PATH = "/etc/passwd"
REPAIR_BROKER_NAME = b"kernaid-repair"
REPAIR_BROKER_GECOS = b"KernAid Rescue repair broker"
ISOLATED_HOME = b"/nonexistent"
ISOLATED_SHELL = b"/usr/sbin/nologin"
MAX_PASSWD_BYTES = 256 * 1024
MAX_REQUEST_BYTES = 1024
MAX_RESPONSE_BYTES = 2048
# One acquisition performs repeated inventory/identity observations around the
# detached mount. Keep the helper bounded while allowing the same closed path
# to complete on slow recovery media and under the QEMU TCG qualification.
IO_TIMEOUT_SECONDS = 30
UUID_INVENTORY_SCHEMA = "kernaid.dev/rescue-uuid-inventory/v1"
MAX_UUID_INVENTORY_ENTRIES = 4096
MAX_UUID_BYTES = 128
MAX_UUID_INVENTORY_BYTES = 536_635
BUNDLE_CAPABILITY = "linux-ext4-direct-leaf-readonly-bundle-v2"
BUNDLE_DESCRIPTOR_TYPES = (
    "selected-target-block-readonly",
    "physical-parent-block-identity-path",
    "uuid-inventory-memfd-sealed",
    "selected-target-ext4-mount-readonly-detached",
)
WRITE_CAPABILITY = "linux-ext4-direct-leaf-readwrite-mount-v1"
WRITE_DESCRIPTOR_TYPE = "selected-target-ext4-mount-readwrite-detached"
VAULT_WRITE_CAPABILITY = "fstab-direct-leaf-rw-v1"
REPAIR_ACTION = "linux.fstab.disable-missing-uuid.v1"
REPAIR_RESOURCE = "rescue:selected-linux-root:etc/fstab"
BLOCK_INVENTORY_COLLECTOR = "linux.block.inventory"

# Linux UAPI values from linux/memfd.h, linux/fcntl.h and linux/mount.h.  The
# numeric fallbacks keep the closed helper usable with Python builds which do
# not publish every Linux-only constant while still requiring the kernel to
# enforce the requested flags.
MFD_CLOEXEC = getattr(os, "MFD_CLOEXEC", 0x0001)
MFD_ALLOW_SEALING = getattr(os, "MFD_ALLOW_SEALING", 0x0002)
F_ADD_SEALS = getattr(fcntl, "F_ADD_SEALS", 1033)
F_GET_SEALS = getattr(fcntl, "F_GET_SEALS", 1034)
F_SEAL_SEAL = getattr(fcntl, "F_SEAL_SEAL", 0x0001)
F_SEAL_SHRINK = getattr(fcntl, "F_SEAL_SHRINK", 0x0002)
F_SEAL_GROW = getattr(fcntl, "F_SEAL_GROW", 0x0004)
F_SEAL_WRITE = getattr(fcntl, "F_SEAL_WRITE", 0x0008)
UUID_INVENTORY_SEALS = F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL

FSOPEN_CLOEXEC = 0x00000001
FSCONFIG_SET_FLAG = 0
FSCONFIG_SET_STRING = 1
FSCONFIG_CMD_CREATE_EXCL = 8
FSMOUNT_CLOEXEC = 0x00000001
MOUNT_ATTR_RDONLY = 0x00000001
MOUNT_ATTR_NOSUID = 0x00000002
MOUNT_ATTR_NODEV = 0x00000004
MOUNT_ATTR_NOEXEC = 0x00000008
REQUIRED_MOUNT_ATTRIBUTES = (
    MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV | MOUNT_ATTR_NOEXEC
)
REQUIRED_WRITE_MOUNT_ATTRIBUTES = MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV | MOUNT_ATTR_NOEXEC
EXT4_SUPER_MAGIC = 0xEF53
BLKSSZGET = 0x1268
BLKGETSIZE64 = 0x80081272
BLKGETDISKSEQ = 0x80081280
KERNEL_SECTOR_BYTES = 512

_REQUEST_ID = re.compile(
    r"^R-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
_EPHEMERAL_ID = {
    prefix: re.compile(rf"^{prefix}:[0-9a-f]{{64}}$")
    for prefix in ("scan", "target")
}
_TARGET_FINGERPRINT = re.compile(r"^sha256:[0-9a-f]{64}$")
_RECOVERY_FINGERPRINT = re.compile(r"^recovery:[0-9a-f]{64}$")
_RESERVATION_ID = re.compile(r"^B-[0-9a-f]{32}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_OPAQUE_ID = re.compile(r"^[A-Za-z0-9_:.\-]{1,128}$")
_PREFIXED_ID = re.compile(r"^[SPA]-[A-Za-z0-9\-]{1,126}$")
_VAULT_ID = re.compile(r"^V-[0-9a-f]{32}$")
_MAJOR_MINOR = re.compile(r"^(0|[1-9][0-9]{0,9}):(0|[1-9][0-9]{0,9})$")
_SAFE_DEVNAME = re.compile(r"^[A-Za-z0-9._+-]{1,128}$")
_UUID = re.compile(r"^[0-9a-f-]{1,128}$")
_ERRORS = {
    "INVALID_REQUEST",
    "TARGET_UNAVAILABLE",
    "TARGET_UNSUPPORTED",
    "TARGET_CHANGED",
    "DEVICE_UNAVAILABLE",
    "INTERNAL",
}


class HandoffFailure(Exception):
    def __init__(
        self,
        token: str,
        request_id: str | None = None,
        operation: str | None = None,
    ) -> None:
        if token not in _ERRORS:
            raise ValueError("unknown handoff failure")
        super().__init__(token)
        self.token = token
        self.request_id = request_id
        self.operation = operation


def _reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON member")
        result[key] = value
    return result


def _profile() -> str:
    value = os.environ.get("KERNAID_TARGET_HANDOFF_PROFILE", PROFILE_READONLY)
    if value not in {PROFILE_READONLY, PROFILE_WRITE}:
        raise RuntimeError("invalid target handoff profile")
    return value


def _decode_request(payload: bytes, profile: str = PROFILE_READONLY) -> dict[str, str]:
    try:
        value = json.loads(
            payload.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicates,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise HandoffFailure("INVALID_REQUEST") from error
    if not isinstance(value, dict):
        raise HandoffFailure("INVALID_REQUEST")
    request_id = value.get("requestId")
    operation = value.get("operation")
    if (
        not isinstance(request_id, str)
        or _REQUEST_ID.fullmatch(request_id) is None
        or value.get("apiVersion") != API_VERSION
        or operation not in {ACQUIRE_OPERATION, RECOVERY_OPERATION, WRITE_OPERATION}
    ):
        raise HandoffFailure("INVALID_REQUEST")
    common = {"apiVersion", "requestId", "operation"}
    if operation == WRITE_OPERATION:
        if profile != PROFILE_WRITE or set(value) != common | {
            "reservationId", "transactionBindingSha256"
        }:
            raise HandoffFailure("INVALID_REQUEST", request_id, operation)
        reservation = value.get("reservationId")
        binding = value.get("transactionBindingSha256")
        if (not isinstance(reservation, str) or _RESERVATION_ID.fullmatch(reservation) is None
                or not isinstance(binding, str) or _SHA256.fullmatch(binding) is None):
            raise HandoffFailure("INVALID_REQUEST", request_id, operation)
        return {"apiVersion": API_VERSION, "requestId": request_id,
                "operation": operation, "reservationId": reservation,
                "transactionBindingSha256": binding}
    if profile != PROFILE_READONLY:
        raise HandoffFailure("INVALID_REQUEST", request_id, operation)
    if operation == RECOVERY_OPERATION:
        if set(value) != common | {"recoveryFingerprint"}:
            raise HandoffFailure("INVALID_REQUEST", request_id, operation)
        recovery_fingerprint = value.get("recoveryFingerprint")
        if (
            not isinstance(recovery_fingerprint, str)
            or _RECOVERY_FINGERPRINT.fullmatch(recovery_fingerprint) is None
        ):
            raise HandoffFailure("INVALID_REQUEST", request_id, operation)
        return {
            "apiVersion": API_VERSION,
            "requestId": request_id,
            "operation": operation,
            "recoveryFingerprint": recovery_fingerprint,
        }
    if set(value) != common | {
        "scanFingerprint",
        "targetFingerprint",
        "targetId",
    }:
        raise HandoffFailure("INVALID_REQUEST", request_id, operation)
    scan = value.get("scanFingerprint")
    target_fingerprint = value.get("targetFingerprint")
    target = value.get("targetId")
    if (
        not isinstance(scan, str)
        or _EPHEMERAL_ID["scan"].fullmatch(scan) is None
        or not isinstance(target_fingerprint, str)
        or _TARGET_FINGERPRINT.fullmatch(target_fingerprint) is None
        or not isinstance(target, str)
        or _EPHEMERAL_ID["target"].fullmatch(target) is None
    ):
        raise HandoffFailure("INVALID_REQUEST", request_id, operation)
    return {
        "apiVersion": API_VERSION,
        "requestId": request_id,
        "operation": operation,
        "scanFingerprint": scan,
        "targetFingerprint": target_fingerprint,
        "targetId": target,
    }


def _load_target_module(path: str = TARGET_MODULE_PATH) -> object:
    module_path = Path(path)
    if not module_path.is_absolute():
        raise RuntimeError("target resolver path must be absolute")
    descriptor = os.open(module_path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != 0
            or stat.S_IMODE(before.st_mode) & 0o022
            or before.st_size <= 0
            or before.st_size > 512 * 1024
        ):
            raise RuntimeError("target resolver is not a bounded root-owned file")
        payload = bytearray()
        while len(payload) < before.st_size:
            chunk = os.read(descriptor, min(64 * 1024, before.st_size - len(payload)))
            if not chunk:
                raise RuntimeError("target resolver ended early")
            payload.extend(chunk)
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise RuntimeError("target resolver changed while loading")
    finally:
        os.close(descriptor)
    module = types.ModuleType("kernaid_repair_target_resolver")
    module.__file__ = str(module_path)
    exec(
        compile(bytes(payload), str(module_path), "exec", dont_inherit=True),
        module.__dict__,
    )
    return module


def _canonical_id(value: bytes) -> int:
    if (
        not value
        or not value.isascii()
        or not value.isdigit()
        or (len(value) > 1 and value.startswith(b"0"))
    ):
        raise RuntimeError("invalid system account database")
    identifier = int(value)
    if identifier > 4_294_967_294:
        raise RuntimeError("invalid system account database")
    return identifier


def _repair_broker_uid_from_passwd(payload: bytes) -> int:
    if (
        not payload
        or len(payload) > MAX_PASSWD_BYTES
        or not payload.endswith(b"\n")
        or b"\0" in payload
        or b"\r" in payload
    ):
        raise RuntimeError("invalid system account database")

    entries: list[tuple[bytes, int, int]] = []
    repair: tuple[int, int] | None = None
    for line in payload[:-1].split(b"\n"):
        if not line or len(line) > 4096:
            raise RuntimeError("invalid system account database")
        fields = line.split(b":")
        if len(fields) != 7 or not fields[0]:
            raise RuntimeError("invalid system account database")
        uid = _canonical_id(fields[2])
        gid = _canonical_id(fields[3])
        entries.append((fields[0], uid, gid))
        if fields[0] == REPAIR_BROKER_NAME:
            if (
                repair is not None
                or uid == 0
                or uid == 1000
                or gid != uid
                or fields[4] != REPAIR_BROKER_GECOS
                or fields[5] != ISOLATED_HOME
                or fields[6] != ISOLATED_SHELL
            ):
                raise RuntimeError("invalid dedicated repair broker account")
            repair = (uid, gid)

    if repair is None:
        raise RuntimeError("dedicated repair broker account is unavailable")
    repair_uid, repair_gid = repair
    if (
        sum(name == REPAIR_BROKER_NAME for name, _uid, _gid in entries) != 1
        or sum(uid == repair_uid for _name, uid, _gid in entries) != 1
        or sum(gid == repair_gid for _name, _uid, gid in entries) != 1
    ):
        raise RuntimeError("dedicated repair broker identity collides")
    return repair_uid


def _read_root_owned_passwd(path: str = PASSWD_PATH) -> bytes:
    if path != PASSWD_PATH:
        raise RuntimeError("system account database path is not allowed")
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        named_before = os.stat(path, follow_symlinks=False)
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_ISLNK(named_before.st_mode)
            or before.st_uid != 0
            or before.st_gid != 0
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) & 0o022
            or before.st_size <= 0
            or before.st_size > MAX_PASSWD_BYTES
            or (named_before.st_dev, named_before.st_ino)
            != (before.st_dev, before.st_ino)
        ):
            raise RuntimeError("system account database is not trusted")
        payload = bytearray()
        while len(payload) < before.st_size:
            chunk = os.read(
                descriptor, min(16 * 1024, before.st_size - len(payload))
            )
            if not chunk:
                raise RuntimeError("system account database ended early")
            payload.extend(chunk)
        if os.read(descriptor, 1):
            raise RuntimeError("system account database grew while reading")
        after = os.fstat(descriptor)
        named_after = os.stat(path, follow_symlinks=False)
        identity = (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_uid,
            before.st_gid,
            before.st_nlink,
            before.st_size,
            before.st_mtime_ns,
        )
        if identity != (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_uid,
            after.st_gid,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
        ) or (named_after.st_dev, named_after.st_ino) != (
            after.st_dev,
            after.st_ino,
        ):
            raise RuntimeError("system account database changed while reading")
        return bytes(payload)
    finally:
        os.close(descriptor)


def _repair_broker_uid() -> int:
    return _repair_broker_uid_from_passwd(_read_root_owned_passwd())


def _validate_peer(
    connection: socket.socket,
    expected_uid: int,
    *,
    expected_local: str | None = SOCKET_PATH,
) -> None:
    if (
        not isinstance(expected_uid, int)
        or isinstance(expected_uid, bool)
        or expected_uid <= 0
    ):
        raise HandoffFailure("INVALID_REQUEST")
    try:
        credentials = connection.getsockopt(
            socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
        )
        pid, uid, _gid = struct.unpack("3i", credentials)
        socket_type = connection.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE)
        accepting = connection.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)
        local = connection.getsockname()
    except (OSError, struct.error) as error:
        raise HandoffFailure("INVALID_REQUEST") from error
    if (
        connection.family != socket.AF_UNIX
        or socket_type != socket.SOCK_SEQPACKET
        or accepting != 0
        or pid <= 0
        or uid != expected_uid
        or (expected_local is not None and local != expected_local)
    ):
        raise HandoffFailure("INVALID_REQUEST")


def _major_minor(value: object) -> tuple[int, int]:
    if not isinstance(value, str) or _MAJOR_MINOR.fullmatch(value) is None:
        raise HandoffFailure("TARGET_UNSUPPORTED")
    major_text, minor_text = value.split(":", 1)
    major, minor = int(major_text), int(minor_text)
    if major > 4_294_967_295 or minor > 4_294_967_295:
        raise HandoffFailure("TARGET_UNSUPPORTED")
    return major, minor


def _qualify(
    targets: object,
    request: dict[str, str],
    selection: object,
    resolution: object,
    *,
    expected_recovery_fingerprint: str | None = None,
) -> tuple[str, str, int, int, str, int, int, int, int]:
    request_id = request["requestId"]
    if not isinstance(selection, dict) or not isinstance(resolution, dict):
        raise HandoffFailure("TARGET_UNSUPPORTED", request_id)
    selected_target = selection.get("target")
    scan_fingerprint = selection.get("scanFingerprint")
    target_id = (
        selected_target.get("targetId")
        if isinstance(selected_target, dict)
        else None
    )
    reference = {
        "scanFingerprint": scan_fingerprint,
        "targetId": target_id,
    }
    try:
        selected_candidate = targets.validate_target_selection(selection, reference)
    except Exception as error:
        raise HandoffFailure("TARGET_UNSUPPORTED", request_id) from error
    candidate = resolution.get("candidate")
    identity = resolution.get("deviceIdentity")
    major_minor = resolution.get("majorMinor")
    physical_parent = resolution.get("physicalParent")
    parent_identity = (
        physical_parent.get("deviceIdentity")
        if isinstance(physical_parent, dict)
        else None
    )
    parent_major_minor = (
        physical_parent.get("majorMinor")
        if isinstance(physical_parent, dict)
        else None
    )
    kernel_kind = resolution.get("kernelKind")
    recovery_fingerprint = resolution.get("recoveryFingerprint")
    ephemeral_request = request.get("operation") == ACQUIRE_OPERATION
    if (
        not isinstance(scan_fingerprint, str)
        or _EPHEMERAL_ID["scan"].fullmatch(scan_fingerprint) is None
        or not isinstance(target_id, str)
        or _EPHEMERAL_ID["target"].fullmatch(target_id) is None
        or (ephemeral_request and scan_fingerprint != request.get("scanFingerprint"))
        or (ephemeral_request and target_id != request.get("targetId"))
        or not isinstance(candidate, dict)
        or candidate != selected_candidate
        or candidate.get("osFamilyHint") != "linux"
        or candidate.get("requiresUnlock") is not False
        or candidate.get("selectionEligible") is not True
        or resolution.get("filesystem") != "ext4"
        or kernel_kind not in {"disk", "part"}
        or resolution.get("leaf") is not True
        or resolution.get("directOnDisk") is not True
        or not isinstance(identity, dict)
        or identity.get("maj:min") != major_minor
        or identity.get("type") != kernel_kind
        or identity.get("fstype") != "ext4"
        or identity.get("ro") is not False
        or not isinstance(identity.get("mountpoints"), list)
        or any(bool(item) for item in identity["mountpoints"])
        or not isinstance(physical_parent, dict)
        or set(physical_parent)
        != {"deviceIdentity", "majorMinor", "kernelKind"}
        or physical_parent.get("kernelKind") != "disk"
        or not isinstance(parent_identity, dict)
        or parent_identity.get("maj:min") != parent_major_minor
        or parent_identity.get("type") != "disk"
        or parent_identity.get("ro") is not False
        or not isinstance(parent_identity.get("mountpoints"), list)
        or any(bool(item) for item in parent_identity["mountpoints"])
        or not isinstance(identity.get("size"), int)
        or isinstance(identity.get("size"), bool)
        or int(identity["size"]) <= 0
        or not isinstance(parent_identity.get("size"), int)
        or isinstance(parent_identity.get("size"), bool)
        or int(parent_identity["size"]) < int(identity["size"])
        or (kernel_kind == "disk" and parent_major_minor != major_minor)
        or (kernel_kind == "part" and parent_major_minor == major_minor)
        or (
            kernel_kind == "disk"
            and _canonical(parent_identity) != _canonical(identity)
        )
        or not isinstance(recovery_fingerprint, str)
        or _RECOVERY_FINGERPRINT.fullmatch(recovery_fingerprint) is None
        or resolution.get("recoveryUnique") is not True
        or (
            expected_recovery_fingerprint is not None
            and recovery_fingerprint != expected_recovery_fingerprint
        )
    ):
        raise HandoffFailure("TARGET_UNSUPPORTED", request_id)
    try:
        major, minor = _major_minor(major_minor)
        parent_major, parent_minor = _major_minor(parent_major_minor)
    except HandoffFailure as error:
        error.request_id = request_id
        raise
    return (
        recovery_fingerprint,
        str(major_minor),
        major,
        minor,
        str(parent_major_minor),
        parent_major,
        parent_minor,
        int(identity["size"]),
        int(parent_identity["size"]),
    )


def _mountinfo_has_device(major_minor: str) -> bool:
    descriptor = os.open(
        "/proc/self/mountinfo", os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    )
    try:
        payload = bytearray()
        while len(payload) <= 1024 * 1024:
            chunk = os.read(descriptor, min(64 * 1024, 1024 * 1024 + 1 - len(payload)))
            if not chunk:
                break
            payload.extend(chunk)
    finally:
        os.close(descriptor)
    if len(payload) > 1024 * 1024:
        raise HandoffFailure("TARGET_UNAVAILABLE")
    try:
        lines = bytes(payload).decode("utf-8", errors="strict").splitlines()
    except UnicodeDecodeError as error:
        raise HandoffFailure("TARGET_UNAVAILABLE") from error
    for line in lines:
        fields = line.partition(" - ")[0].split()
        if len(fields) < 6:
            raise HandoffFailure("TARGET_UNAVAILABLE")
        if fields[2] == major_minor:
            return True
    return False


def _assert_block_fd(
    descriptor: int, major: int, minor: int, *, writable: bool = False
) -> None:
    metadata = os.fstat(descriptor)
    flags = fcntl.fcntl(descriptor, fcntl.F_GETFL)
    fd_flags = fcntl.fcntl(descriptor, fcntl.F_GETFD)
    if (
        not stat.S_ISBLK(metadata.st_mode)
        or os.major(metadata.st_rdev) != major
        or os.minor(metadata.st_rdev) != minor
        or flags & os.O_ACCMODE != (os.O_RDWR if writable else os.O_RDONLY)
        or not flags & os.O_NONBLOCK
        or not fd_flags & fcntl.FD_CLOEXEC
    ):
        raise HandoffFailure("DEVICE_UNAVAILABLE")


def _assert_readonly_block_capability(descriptor: int) -> None:
    metadata = os.fstat(descriptor)
    flags = fcntl.fcntl(descriptor, fcntl.F_GETFL)
    fd_flags = fcntl.fcntl(descriptor, fcntl.F_GETFD)
    if (
        not stat.S_ISBLK(metadata.st_mode)
        or flags & os.O_ACCMODE != os.O_RDONLY
        or not flags & os.O_NONBLOCK
        or not fd_flags & fcntl.FD_CLOEXEC
    ):
        raise HandoffFailure("DEVICE_UNAVAILABLE")


def _assert_block_identity_fd(descriptor: int, major: int, minor: int) -> None:
    metadata = os.fstat(descriptor)
    flags = fcntl.fcntl(descriptor, fcntl.F_GETFL)
    fd_flags = fcntl.fcntl(descriptor, fcntl.F_GETFD)
    if (
        not stat.S_ISBLK(metadata.st_mode)
        or os.major(metadata.st_rdev) != major
        or os.minor(metadata.st_rdev) != minor
        or flags & os.O_PATH != os.O_PATH
        or not fd_flags & fcntl.FD_CLOEXEC
    ):
        raise HandoffFailure("DEVICE_UNAVAILABLE")


def _probe_u64(descriptor: int, request: int) -> int:
    buffer = bytearray(8)
    try:
        fcntl.ioctl(descriptor, request, buffer, True)
        value = struct.unpack("=Q", buffer)[0]
    except (OSError, struct.error) as error:
        raise HandoffFailure("DEVICE_UNAVAILABLE") from error
    if not 0 < value <= 0xFFFF_FFFF_FFFF_FFFF:
        raise HandoffFailure("DEVICE_UNAVAILABLE")
    return value


def _probe_u32(descriptor: int, request: int) -> int:
    buffer = bytearray(4)
    try:
        fcntl.ioctl(descriptor, request, buffer, True)
        value = struct.unpack("=I", buffer)[0]
    except (OSError, struct.error) as error:
        raise HandoffFailure("DEVICE_UNAVAILABLE") from error
    if not 0 < value <= 0xFFFF_FFFF:
        raise HandoffFailure("DEVICE_UNAVAILABLE")
    return value


def _probe_physical_parent_claims(
    leaf_descriptor: int,
    parent_descriptor: int,
    leaf_size_bytes: int,
    parent_size_bytes: int,
    parent_major: int,
    parent_minor: int,
) -> dict[str, int]:
    leaf_disk_sequence = _probe_u64(leaf_descriptor, BLKGETDISKSEQ)
    parent_disk_sequence = _probe_u64(parent_descriptor, BLKGETDISKSEQ)
    leaf_size = _probe_u64(leaf_descriptor, BLKGETSIZE64)
    parent_size = _probe_u64(parent_descriptor, BLKGETSIZE64)
    leaf_sector_bytes = _probe_u32(leaf_descriptor, BLKSSZGET)
    parent_sector_bytes = _probe_u32(parent_descriptor, BLKSSZGET)
    if (
        leaf_disk_sequence != parent_disk_sequence
        or leaf_size != leaf_size_bytes
        or parent_size != parent_size_bytes
        or leaf_size > parent_size
        or leaf_size % KERNEL_SECTOR_BYTES
        or parent_size % KERNEL_SECTOR_BYTES
        or leaf_sector_bytes != parent_sector_bytes
        or not KERNEL_SECTOR_BYTES <= parent_sector_bytes <= 65_536
        or parent_sector_bytes & (parent_sector_bytes - 1)
    ):
        raise HandoffFailure("TARGET_CHANGED")
    return {
        "parentMajor": parent_major,
        "parentMinor": parent_minor,
        "diskSequence": parent_disk_sequence,
        "mediaSectorCount": parent_size // KERNEL_SECTOR_BYTES,
        "logicalSectorBytes": parent_sector_bytes,
        "leafSectorCount": leaf_size // KERNEL_SECTOR_BYTES,
    }


def _validate_physical_parent_claims_wire(value: object) -> dict[str, int]:
    keys = {
        "parentMajor",
        "parentMinor",
        "diskSequence",
        "mediaSectorCount",
        "logicalSectorBytes",
        "leafSectorCount",
    }
    if not isinstance(value, dict) or set(value) != keys:
        raise HandoffFailure("INTERNAL")
    if any(not isinstance(value[key], int) or isinstance(value[key], bool) for key in keys):
        raise HandoffFailure("INTERNAL")
    claims = {key: int(value[key]) for key in keys}
    if (
        not 0 <= claims["parentMajor"] <= 0xFFFF_FFFF
        or not 0 <= claims["parentMinor"] <= 0xFFFF_FFFF
        or not 0 < claims["diskSequence"] <= 0xFFFF_FFFF_FFFF_FFFF
        or not 0 < claims["mediaSectorCount"] <= 0xFFFF_FFFF_FFFF_FFFF // 512
        or not 0 < claims["leafSectorCount"] <= claims["mediaSectorCount"]
        or not KERNEL_SECTOR_BYTES <= claims["logicalSectorBytes"] <= 65_536
        or claims["logicalSectorBytes"] & (claims["logicalSectorBytes"] - 1)
    ):
        raise HandoffFailure("INTERNAL")
    return claims


def _open_bound_block_device(
    major_minor: str, major: int, minor: int, *, writable: bool = False
) -> int:
    dev_fd = os.open(
        "/dev", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    )
    matches: list[str] = []
    try:
        with os.scandir(dev_fd) as entries:
            for index, entry in enumerate(entries, start=1):
                if index > 4096:
                    raise HandoffFailure("DEVICE_UNAVAILABLE")
                if _SAFE_DEVNAME.fullmatch(entry.name) is None:
                    continue
                try:
                    metadata = entry.stat(follow_symlinks=False)
                except OSError:
                    continue
                if (
                    stat.S_ISBLK(metadata.st_mode)
                    and os.major(metadata.st_rdev) == major
                    and os.minor(metadata.st_rdev) == minor
                ):
                    matches.append(entry.name)
        if len(matches) != 1:
            raise HandoffFailure("DEVICE_UNAVAILABLE")
        descriptor = os.open(
            matches[0],
            (os.O_RDWR if writable else os.O_RDONLY)
            | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=dev_fd,
        )
        try:
            _assert_block_fd(descriptor, major, minor, writable=writable)
            current = os.stat(matches[0], dir_fd=dev_fd, follow_symlinks=False)
            if current.st_rdev != os.fstat(descriptor).st_rdev:
                raise HandoffFailure("DEVICE_UNAVAILABLE")
        except Exception:
            os.close(descriptor)
            raise
        return descriptor
    finally:
        os.close(dev_fd)


def _open_bound_block_identity(major: int, minor: int) -> int:
    dev_fd = os.open(
        "/dev", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    )
    matches: list[str] = []
    try:
        with os.scandir(dev_fd) as entries:
            for index, entry in enumerate(entries, start=1):
                if index > 4096:
                    raise HandoffFailure("DEVICE_UNAVAILABLE")
                if _SAFE_DEVNAME.fullmatch(entry.name) is None:
                    continue
                try:
                    metadata = entry.stat(follow_symlinks=False)
                except OSError:
                    continue
                if (
                    stat.S_ISBLK(metadata.st_mode)
                    and os.major(metadata.st_rdev) == major
                    and os.minor(metadata.st_rdev) == minor
                ):
                    matches.append(entry.name)
        if len(matches) != 1:
            raise HandoffFailure("DEVICE_UNAVAILABLE")
        descriptor = os.open(
            matches[0],
            os.O_PATH | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=dev_fd,
        )
        try:
            _assert_block_identity_fd(descriptor, major, minor)
            current = os.stat(matches[0], dir_fd=dev_fd, follow_symlinks=False)
            if current.st_rdev != os.fstat(descriptor).st_rdev:
                raise HandoffFailure("DEVICE_UNAVAILABLE")
        except Exception:
            os.close(descriptor)
            raise
        return descriptor
    finally:
        os.close(dev_fd)


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _normalize_uuid_inventory(values: object) -> tuple[str, ...]:
    if not isinstance(values, list) or len(values) > MAX_UUID_INVENTORY_ENTRIES:
        raise HandoffFailure("TARGET_UNAVAILABLE")
    normalized: set[str] = set()
    for value in values:
        if not isinstance(value, str) or not value.isascii():
            raise HandoffFailure("TARGET_UNAVAILABLE")
        canonical = value.lower()
        if (
            not 1 <= len(canonical) <= MAX_UUID_BYTES
            or _UUID.fullmatch(canonical) is None
            or canonical.startswith("-")
            or canonical.endswith("-")
        ):
            raise HandoffFailure("TARGET_UNAVAILABLE")
        normalized.add(canonical)
    ordered = tuple(sorted(normalized))
    if not 1 <= len(ordered) <= MAX_UUID_INVENTORY_ENTRIES:
        raise HandoffFailure("TARGET_UNAVAILABLE")
    return ordered


def _uuid_inventory_from_observations(
    observations: list[dict[str, object]], request_id: str
) -> tuple[str, ...]:
    matches = [
        item
        for item in observations
        if isinstance(item, dict)
        and item.get("collector") == BLOCK_INVENTORY_COLLECTOR
    ]
    if len(matches) != 1:
        raise HandoffFailure("TARGET_UNAVAILABLE", request_id)
    observation = matches[0]
    output = observation.get("output")
    if (
        observation.get("success") is not True
        or observation.get("truncated") is True
        or not isinstance(output, str)
        or not output
        or len(output.encode("utf-8")) > MAX_UUID_INVENTORY_BYTES
    ):
        raise HandoffFailure("TARGET_UNAVAILABLE", request_id)
    try:
        decoded = json.loads(
            output,
            object_pairs_hook=_reject_duplicates,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        )
    except (json.JSONDecodeError, ValueError) as error:
        raise HandoffFailure("TARGET_UNAVAILABLE", request_id) from error
    if not isinstance(decoded, dict) or set(decoded) != {"blockdevices"}:
        raise HandoffFailure("TARGET_UNAVAILABLE", request_id)
    roots = decoded.get("blockdevices")
    if not isinstance(roots, list):
        raise HandoffFailure("TARGET_UNAVAILABLE", request_id)

    values: list[str] = []
    device_count = 0

    def visit(device: object, depth: int) -> None:
        nonlocal device_count
        if depth > 8 or not isinstance(device, dict) or "uuid" not in device:
            raise HandoffFailure("TARGET_UNAVAILABLE", request_id)
        device_count += 1
        if device_count > MAX_UUID_INVENTORY_ENTRIES:
            raise HandoffFailure("TARGET_UNAVAILABLE", request_id)
        value = device.get("uuid")
        if value is not None:
            if not isinstance(value, str):
                raise HandoffFailure("TARGET_UNAVAILABLE", request_id)
            values.append(value)
        children = device.get("children", [])
        if not isinstance(children, list):
            raise HandoffFailure("TARGET_UNAVAILABLE", request_id)
        for child in children:
            visit(child, depth + 1)

    for root in roots:
        visit(root, 0)
    try:
        return _normalize_uuid_inventory(values)
    except HandoffFailure as error:
        error.request_id = request_id
        raise


def _uuid_inventory_payload(uuids: tuple[str, ...]) -> bytes:
    payload = _canonical({"schema": UUID_INVENTORY_SCHEMA, "uuids": list(uuids)})
    if not payload or len(payload) > MAX_UUID_INVENTORY_BYTES:
        raise HandoffFailure("TARGET_UNAVAILABLE")
    return payload


def _assert_uuid_inventory_fd(descriptor: int, payload: bytes) -> None:
    metadata = os.fstat(descriptor)
    fd_flags = fcntl.fcntl(descriptor, fcntl.F_GETFD)
    status = fcntl.fcntl(descriptor, fcntl.F_GETFL)
    seals = fcntl.fcntl(descriptor, F_GET_SEALS)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o400
        or metadata.st_size != len(payload)
        or len(payload) > MAX_UUID_INVENTORY_BYTES
        or not fd_flags & fcntl.FD_CLOEXEC
        or status & os.O_ACCMODE != os.O_RDWR
        or seals != UUID_INVENTORY_SEALS
        or os.lseek(descriptor, 0, os.SEEK_CUR) != 0
        or os.pread(descriptor, len(payload) + 1, 0) != payload
    ):
        raise HandoffFailure("DEVICE_UNAVAILABLE")


def _create_uuid_inventory_memfd(
    uuids: tuple[str, ...],
) -> tuple[int, dict[str, object]]:
    payload = _uuid_inventory_payload(uuids)
    try:
        descriptor = os.memfd_create(
            "kernaid-rescue-uuid-inventory",
            MFD_CLOEXEC | MFD_ALLOW_SEALING,
        )
    except (AttributeError, OSError) as error:
        raise HandoffFailure("DEVICE_UNAVAILABLE") from error
    try:
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise OSError("short UUID inventory write")
            offset += written
        os.fchmod(descriptor, 0o400)
        os.lseek(descriptor, 0, os.SEEK_SET)
        fcntl.fcntl(descriptor, F_ADD_SEALS, UUID_INVENTORY_SEALS)
        _assert_uuid_inventory_fd(descriptor, payload)
    except Exception:
        os.close(descriptor)
        raise
    return (
        descriptor,
        {
            "schema": UUID_INVENTORY_SCHEMA,
            "entryCount": len(uuids),
            "byteLength": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
        },
    )


class _GlibcMountApi:
    def __init__(self) -> None:
        try:
            library = ctypes.CDLL(None, use_errno=True)
            self.fsopen = library.fsopen
            self.fsconfig = library.fsconfig
            self.fsmount = library.fsmount
            self.fstatfs = library.fstatfs
        except (AttributeError, OSError) as error:
            raise HandoffFailure("DEVICE_UNAVAILABLE") from error
        self.fsopen.argtypes = [ctypes.c_char_p, ctypes.c_uint]
        self.fsopen.restype = ctypes.c_int
        self.fsconfig.argtypes = [
            ctypes.c_int,
            ctypes.c_uint,
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_int,
        ]
        self.fsconfig.restype = ctypes.c_int
        self.fsmount.argtypes = [ctypes.c_int, ctypes.c_uint, ctypes.c_uint]
        self.fsmount.restype = ctypes.c_int
        self.fstatfs.argtypes = [ctypes.c_int, ctypes.c_void_p]
        self.fstatfs.restype = ctypes.c_int


def _checked_mount_call(function: object, *arguments: object) -> int:
    if not callable(function):
        raise HandoffFailure("DEVICE_UNAVAILABLE")
    ctypes.set_errno(0)
    result = int(function(*arguments))
    if result < 0:
        code = ctypes.get_errno() or errno.EIO
        raise OSError(code, "Linux mount API call failed")
    return result


def _configured_ext4_context(
    api: _GlibcMountApi, leaf_descriptor: int, create_command: int
) -> int:
    context = _checked_mount_call(api.fsopen, b"ext4", FSOPEN_CLOEXEC)
    try:
        source = f"/proc/self/fd/{leaf_descriptor}".encode("ascii")
        _checked_mount_call(
            api.fsconfig,
            context,
            FSCONFIG_SET_STRING,
            b"source",
            source,
            0,
        )
        _checked_mount_call(
            api.fsconfig, context, FSCONFIG_SET_FLAG, b"ro", None, 0
        )
        _checked_mount_call(
            api.fsconfig, context, FSCONFIG_SET_FLAG, b"noload", None, 0
        )
        _checked_mount_call(api.fsconfig, context, create_command, None, None, 0)
        return context
    except Exception:
        os.close(context)
        raise


def _ext4_super_magic(api: _GlibcMountApi, descriptor: int) -> int:
    # f_type is the first native long in every Linux struct statfs ABI.  A
    # deliberately oversized writable buffer avoids mirroring the remaining
    # architecture-dependent structure in Python.
    buffer = ctypes.create_string_buffer(512)
    _checked_mount_call(api.fstatfs, descriptor, ctypes.byref(buffer))
    return int(ctypes.c_long.from_buffer(buffer).value)


def _assert_detached_ext4_mount_fd(
    descriptor: int,
    leaf_major: int,
    leaf_minor: int,
    *,
    api: _GlibcMountApi | None = None,
) -> None:
    mount_api = _GlibcMountApi() if api is None else api
    metadata = os.fstat(descriptor)
    fd_flags = fcntl.fcntl(descriptor, fcntl.F_GETFD)
    status = fcntl.fcntl(descriptor, fcntl.F_GETFL)
    filesystem = os.fstatvfs(descriptor)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_dev != os.makedev(leaf_major, leaf_minor)
        or not fd_flags & fcntl.FD_CLOEXEC
        or status & os.O_PATH != os.O_PATH
        or _ext4_super_magic(mount_api, descriptor) != EXT4_SUPER_MAGIC
        or filesystem.f_flag & REQUIRED_MOUNT_ATTRIBUTES
        != REQUIRED_MOUNT_ATTRIBUTES
    ):
        raise HandoffFailure("DEVICE_UNAVAILABLE")


def _create_detached_ext4_mount(
    leaf_descriptor: int, leaf_major: int, leaf_minor: int
) -> int:
    api = _GlibcMountApi()
    try:
        context = _configured_ext4_context(
            api, leaf_descriptor, FSCONFIG_CMD_CREATE_EXCL
        )
    except OSError as error:
        raise HandoffFailure("DEVICE_UNAVAILABLE") from error
    try:
        descriptor = _checked_mount_call(
            api.fsmount,
            context,
            FSMOUNT_CLOEXEC,
            REQUIRED_MOUNT_ATTRIBUTES,
        )
    except OSError as error:
        raise HandoffFailure("DEVICE_UNAVAILABLE") from error
    finally:
        os.close(context)
    try:
        _assert_detached_ext4_mount_fd(
            descriptor, leaf_major, leaf_minor, api=api
        )
    except Exception:
        os.close(descriptor)
        raise
    return descriptor


def _configured_ext4_write_context(api: _GlibcMountApi, leaf_descriptor: int) -> int:
    context = _checked_mount_call(api.fsopen, b"ext4", FSOPEN_CLOEXEC)
    try:
        source = f"/proc/self/fd/{leaf_descriptor}".encode("ascii")
        _checked_mount_call(api.fsconfig, context, FSCONFIG_SET_STRING,
                            b"source", source, 0)
        _checked_mount_call(api.fsconfig, context, FSCONFIG_CMD_CREATE_EXCL,
                            None, None, 0)
        return context
    except Exception:
        os.close(context)
        raise


def _assert_detached_ext4_write_mount_fd(
    descriptor: int, leaf_major: int, leaf_minor: int, *, api: _GlibcMountApi | None = None
) -> None:
    mount_api = _GlibcMountApi() if api is None else api
    metadata = os.fstat(descriptor)
    flags = os.fstatvfs(descriptor).f_flag
    if (not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_dev != os.makedev(leaf_major, leaf_minor)
            or not fcntl.fcntl(descriptor, fcntl.F_GETFD) & fcntl.FD_CLOEXEC
            or fcntl.fcntl(descriptor, fcntl.F_GETFL) & os.O_PATH != os.O_PATH
            or _ext4_super_magic(mount_api, descriptor) != EXT4_SUPER_MAGIC
            or flags & REQUIRED_WRITE_MOUNT_ATTRIBUTES != REQUIRED_WRITE_MOUNT_ATTRIBUTES
            or flags & MOUNT_ATTR_RDONLY):
        raise HandoffFailure("DEVICE_UNAVAILABLE")


def _create_detached_ext4_write_mount(
    leaf_descriptor: int, leaf_major: int, leaf_minor: int
) -> int:
    api = _GlibcMountApi()
    descriptor: int | None = None
    try:
        context = _configured_ext4_write_context(api, leaf_descriptor)
        try:
            descriptor = _checked_mount_call(api.fsmount, context, FSMOUNT_CLOEXEC,
                                             REQUIRED_WRITE_MOUNT_ATTRIBUTES)
        finally:
            os.close(context)
        _assert_detached_ext4_write_mount_fd(descriptor, leaf_major, leaf_minor, api=api)
        return descriptor
    except Exception as error:
        if descriptor is not None:
            os.close(descriptor)
        if isinstance(error, HandoffFailure):
            raise
        raise HandoffFailure("DEVICE_UNAVAILABLE") from error


def _hash_fields(domain: bytes, fields: list[bytes]) -> str:
    digest = hashlib.sha256(domain)
    for field in fields:
        digest.update(len(field).to_bytes(8, "big"))
        digest.update(field)
    return digest.hexdigest()


def _digest(value: object, *, prefixed: str | None = None) -> bytes:
    if not isinstance(value, str):
        raise HandoffFailure("INTERNAL")
    raw = value
    if prefixed is not None:
        if not value.startswith(prefixed):
            raise HandoffFailure("INTERNAL")
        raw = value[len(prefixed):]
    if _SHA256.fullmatch(raw) is None:
        raise HandoffFailure("INTERNAL")
    return bytes.fromhex(raw)


def _physical_parent_fingerprint(claims: dict[str, int]) -> str:
    digest = hashlib.sha256(b"KERNAID-REPAIR-PHYSICAL-PARENT-V1\0")
    for key, width in (("parentMajor", 4), ("parentMinor", 4),
                       ("diskSequence", 8), ("mediaSectorCount", 8),
                       ("logicalSectorBytes", 8)):
        digest.update(claims[key].to_bytes(width, "big"))
    return digest.hexdigest()


def _strict_object(value: object, keys: set[str]) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        raise HandoffFailure("INTERNAL")
    return value


def _validate_write_lease(payload: object, reservation: str, binding: str) -> dict[str, str]:
    lease = _strict_object(payload, {"capability", "bootEpochSha256",
                                     "leaseBindingSha256", "transaction"})
    transaction = _strict_object(lease["transaction"],
                                 {"phase", "transactionBindingSha256", "backup"})
    backup_keys = {"state", "reservationId", "draftBindingSha256", "locator", "vaultId",
                   "vaultIdentityFingerprint", "physicalParentFingerprint", "reservedBytes",
                   "backupSize", "expectedBackupSha256", "metadataSha256", "planId",
                   "planSha256", "approvalId", "approvalSha256", "resourceId",
                   "resourceSha256", "executionIntent"}
    backup = _strict_object(transaction["backup"], backup_keys)
    intent_keys = {"actionId", "sessionId", "approvalSequence", "targetId", "scanFingerprint",
                   "targetFingerprint", "targetPhysicalParentFingerprint",
                   "targetRecoveryFingerprint", "lockIdentity", "beforeSha256", "afterSha256",
                   "diffSha256", "observedUuidSetSha256", "beforeMetadata"}
    intent = _strict_object(backup["executionIntent"], intent_keys)
    metadata = _strict_object(intent["beforeMetadata"], {"mode", "uid", "gid", "xattrs", "posixAcl"})
    digests = ["draftBindingSha256", "vaultIdentityFingerprint", "physicalParentFingerprint",
               "expectedBackupSha256", "metadataSha256", "planSha256", "approvalSha256",
               "resourceSha256"]
    if (lease["capability"] != VAULT_WRITE_CAPABILITY or transaction["phase"] != "pending"
            or transaction["transactionBindingSha256"] != binding
            or backup["state"] != "durable" or backup["reservationId"] != reservation
            or backup["locator"] != "vault://repair/" + reservation
            or backup["resourceId"] != REPAIR_RESOURCE or intent["actionId"] != REPAIR_ACTION
            or intent["targetRecoveryFingerprint"] is None
            or _RECOVERY_FINGERPRINT.fullmatch(str(intent["targetRecoveryFingerprint"])) is None
            or not isinstance(intent["targetPhysicalParentFingerprint"], str)
            or _SHA256.fullmatch(intent["targetPhysicalParentFingerprint"]) is None
            or not isinstance(intent["sessionId"], str) or _PREFIXED_ID.fullmatch(intent["sessionId"]) is None
            or not intent["sessionId"].startswith("S-")
            or not isinstance(intent["targetId"], str) or _OPAQUE_ID.fullmatch(intent["targetId"]) is None
            or ".." in intent["targetId"]
            or not isinstance(intent["scanFingerprint"], str) or _EPHEMERAL_ID["scan"].fullmatch(intent["scanFingerprint"]) is None
            or not isinstance(intent["approvalSequence"], int) or isinstance(intent["approvalSequence"], bool)
            or not 1 <= intent["approvalSequence"] <= 9_007_199_254_740_991
            or not isinstance(backup["planId"], str) or not backup["planId"].startswith("P-")
            or _PREFIXED_ID.fullmatch(backup["planId"]) is None
            or not isinstance(backup["approvalId"], str) or not backup["approvalId"].startswith("A-")
            or _PREFIXED_ID.fullmatch(backup["approvalId"]) is None
            or not isinstance(backup["vaultId"], str) or _VAULT_ID.fullmatch(backup["vaultId"]) is None
            or not isinstance(backup["reservedBytes"], int) or isinstance(backup["reservedBytes"], bool)
            or not isinstance(backup["backupSize"], int) or isinstance(backup["backupSize"], bool)
            or not 1 <= backup["backupSize"] <= backup["reservedBytes"] <= 16 * 1024 * 1024
            or not isinstance(metadata["mode"], int) or not 0 <= metadata["mode"] <= 0o7777
            or not isinstance(metadata["uid"], int) or not 0 <= metadata["uid"] <= 0xffffffff
            or not isinstance(metadata["gid"], int) or not 0 <= metadata["gid"] <= 0xffffffff
            or metadata["xattrs"] != "none" or metadata["posixAcl"] != "none"):
        raise HandoffFailure("INTERNAL")
    for key in digests:
        _digest(backup[key])
    boot = _digest(lease["bootEpochSha256"])
    if not any(boot):
        raise HandoffFailure("INTERNAL")
    for key in ("targetFingerprint", "targetPhysicalParentFingerprint"):
        _digest(intent[key])
    for key in ("beforeSha256", "afterSha256", "diffSha256", "observedUuidSetSha256"):
        _digest(intent[key])
    metadata_hash = _hash_fields(b"KERNAID-REPAIR-FILE-METADATA-V1\0", [
        metadata["mode"].to_bytes(4, "big"), metadata["uid"].to_bytes(4, "big"),
        metadata["gid"].to_bytes(4, "big"), b"\0", b"\0"])
    if (backup["metadataSha256"] != metadata_hash
            or backup["expectedBackupSha256"] != intent["beforeSha256"]
            or backup["metadataSha256"] != metadata_hash
            or backup["physicalParentFingerprint"]
            == intent["targetPhysicalParentFingerprint"]):
        raise HandoffFailure("INTERNAL")
    expected_draft = _hash_fields(b"KERNAID-REPAIR-RESERVATION-V1\0", [
        intent["sessionId"].encode(), intent["targetId"].encode(),
        _digest(intent["targetFingerprint"]),
        intent["targetRecoveryFingerprint"].encode(), _digest(backup["expectedBackupSha256"]),
        _digest(backup["metadataSha256"]), backup["backupSize"].to_bytes(8, "big"),
        backup["reservedBytes"].to_bytes(8, "big")])
    if backup["draftBindingSha256"] != expected_draft:
        raise HandoffFailure("INTERNAL")
    intent_binding = _hash_fields(b"KERNAID-REPAIR-EXECUTION-INTENT-V1\0", [
        intent["actionId"].encode(), intent["sessionId"].encode(),
        intent["approvalSequence"].to_bytes(8, "big"), intent["targetId"].encode(),
        intent["scanFingerprint"].encode(), _digest(intent["targetFingerprint"]),
        _digest(intent["targetPhysicalParentFingerprint"]),
        intent["targetRecoveryFingerprint"].encode(), str(intent["lockIdentity"]).encode(),
        _digest(intent["beforeSha256"]), _digest(intent["afterSha256"]),
        _digest(intent["diffSha256"]), _digest(intent["observedUuidSetSha256"]),
        _digest(metadata_hash)])
    expected_transaction = _hash_fields(b"KERNAID-REPAIR-TRANSACTION-V1\0", [
        reservation.encode(), _digest(backup["draftBindingSha256"]), backup["locator"].encode(),
        backup["vaultId"].encode(), _digest(backup["vaultIdentityFingerprint"]),
        _digest(backup["physicalParentFingerprint"]), backup["reservedBytes"].to_bytes(8, "big"),
        backup["backupSize"].to_bytes(8, "big"), _digest(backup["expectedBackupSha256"]),
        _digest(backup["metadataSha256"]), backup["planId"].encode(),
        _digest(backup["planSha256"]), backup["approvalId"].encode(),
        _digest(backup["approvalSha256"]), backup["resourceId"].encode(),
        _digest(backup["resourceSha256"]), _digest(intent_binding)])
    if expected_transaction != binding:
        raise HandoffFailure("INTERNAL")
    expected_lock = "lock:" + _hash_fields(
        b"kernaid:rescue-fstab:target-lock:v2\0",
        [str(intent["targetRecoveryFingerprint"]).encode(), REPAIR_RESOURCE.encode()])
    if intent["lockIdentity"] != expected_lock or backup["resourceSha256"] != intent["beforeSha256"]:
        raise HandoffFailure("INTERNAL")
    expected_lease = _hash_fields(b"KERNAID-REPAIR-WRITE-LEASE-V1\0", [
        VAULT_WRITE_CAPABILITY.encode(), _digest(binding), boot,
        str(intent["targetRecoveryFingerprint"]).encode(), expected_lock.encode()])
    if lease["leaseBindingSha256"] != expected_lease:
        raise HandoffFailure("INTERNAL")
    return {"recoveryFingerprint": str(intent["targetRecoveryFingerprint"]),
            "leaseBindingSha256": expected_lease}


def _fresh_request_id() -> str:
    raw = secrets.token_hex(16)
    return f"R-{raw[:8]}-{raw[8:12]}-{raw[12:16]}-{raw[16:20]}-{raw[20:]}"


def _vault_exchange(request: dict[str, object], deadline: float) -> dict[str, object]:
    _ensure_deadline(deadline)
    endpoint = os.stat(VAULT_HELPER_SOCKET_PATH, follow_symlinks=False)
    if (not stat.S_ISSOCK(endpoint.st_mode) or endpoint.st_uid != 0
            or stat.S_IMODE(endpoint.st_mode) != 0o600):
        raise HandoffFailure("INTERNAL")
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
    try:
        connection.settimeout(max(0.001, deadline - time.monotonic()))
        connection.connect(VAULT_HELPER_SOCKET_PATH)
        credentials = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        _pid, uid, _gid = struct.unpack("3i", credentials)
        if (uid != 0 or connection.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE)
                != socket.SOCK_SEQPACKET or connection.getpeername() != VAULT_HELPER_SOCKET_PATH):
            raise HandoffFailure("INTERNAL")
        encoded = _canonical(request)
        if connection.sendmsg([encoded]) != len(encoded):
            raise HandoffFailure("INTERNAL")
        payload, ancillary, flags, _address = connection.recvmsg(64 * 1024 + 1, socket.CMSG_SPACE(4))
        if (not payload or len(payload) > 64 * 1024 or ancillary
                or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)):
            raise HandoffFailure("INTERNAL")
        response = json.loads(payload.decode("utf-8", errors="strict"),
                              object_pairs_hook=_reject_duplicates,
                              parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()))
        after = os.stat(VAULT_HELPER_SOCKET_PATH, follow_symlinks=False)
        if (endpoint.st_dev, endpoint.st_ino, endpoint.st_uid, endpoint.st_mode) != (
                after.st_dev, after.st_ino, after.st_uid, after.st_mode):
            raise HandoffFailure("INTERNAL")
        return response
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise HandoffFailure("INTERNAL") from error
    finally:
        connection.close()


def _consume_write_lease(reservation: str, binding: str, deadline: float) -> dict[str, str]:
    state_version = 0
    for attempt in range(2):
        request_id = _fresh_request_id()
        request = {"apiVersion": VAULT_API_VERSION, "requestId": request_id,
                   "expectedStateVersion": state_version, "operation": VAULT_WRITE_OPERATION,
                   "payload": {"selector": {"kind": "exact", "reservationId": reservation,
                                              "transactionBindingSha256": binding}}}
        response = _vault_exchange(request, deadline)
        common = {"apiVersion", "requestId", "stateVersion", "operation", "outcome"}
        if (not isinstance(response, dict) or response.get("apiVersion") != VAULT_API_VERSION
                or response.get("requestId") != request_id
                or response.get("operation") != VAULT_WRITE_OPERATION
                or not isinstance(response.get("stateVersion"), int)
                or isinstance(response.get("stateVersion"), bool)
                or not 0 <= response["stateVersion"] <= 9_007_199_254_740_991):
            raise HandoffFailure("INTERNAL")
        if response.get("outcome") == "error":
            if (set(response) == common | {"error"} and attempt == 0
                    and response.get("error") == "STALE_STATE"
                    and response["stateVersion"] != state_version):
                state_version = response["stateVersion"]
                continue
            raise HandoffFailure("INTERNAL")
        if response.get("outcome") != "ok" or set(response) != common | {"payload"}:
            raise HandoffFailure("INTERNAL")
        return _validate_write_lease(response["payload"], reservation, binding)
    raise HandoffFailure("INTERNAL")


def _close_descriptors(descriptors: list[int]) -> None:
    while descriptors:
        descriptor = descriptors.pop()
        try:
            os.close(descriptor)
        except OSError:
            pass


def _observed_inventory_fingerprint(
    targets: object, deadline: float, request_id: str
) -> tuple[str, tuple[str, ...]]:
    observations = targets.inventory(deadline=deadline)
    if not isinstance(observations, list):
        raise HandoffFailure("TARGET_UNAVAILABLE", request_id)
    try:
        identity_observations = [
            item
            for item in observations
            if isinstance(item, dict)
            and isinstance(item.get("collector"), str)
            and targets.is_identity_observation(str(item["collector"]))
        ]
        if not identity_observations or any(
            item.get("success") is not True or item.get("truncated") is True
            for item in identity_observations
        ):
            raise HandoffFailure("TARGET_UNAVAILABLE", request_id)
        fingerprint = targets.inventory_fingerprint(observations)
    except HandoffFailure:
        raise
    except Exception as error:
        raise HandoffFailure("INTERNAL", request_id) from error
    if (
        not isinstance(fingerprint, str)
        or _TARGET_FINGERPRINT.fullmatch(fingerprint) is None
    ):
        raise HandoffFailure("INTERNAL", request_id)
    return fingerprint, _uuid_inventory_from_observations(observations, request_id)


def _recompute_target_fingerprint(
    targets: object,
    runtime_inventory_fingerprint: str,
    scan_fingerprint: str,
    candidate: dict[str, object],
    request_id: str,
) -> str:
    try:
        fingerprint = targets.rescue_target_fingerprint(
            runtime_inventory_fingerprint, scan_fingerprint, candidate
        )
    except Exception as error:
        raise HandoffFailure("INTERNAL", request_id) from error
    if (
        not isinstance(fingerprint, str)
        or _TARGET_FINGERPRINT.fullmatch(fingerprint) is None
    ):
        raise HandoffFailure("INTERNAL", request_id)
    return fingerprint


def _ensure_deadline(deadline: float, request_id: str) -> None:
    if time.monotonic() >= deadline:
        raise HandoffFailure("TARGET_UNAVAILABLE", request_id)


def _open_block_pair(
    leaf_major_minor: str,
    leaf_major: int,
    leaf_minor: int,
    parent_major_minor: str,
    parent_major: int,
    parent_minor: int,
    request_id: str,
) -> list[int]:
    if _mountinfo_has_device(leaf_major_minor) or _mountinfo_has_device(
        parent_major_minor
    ):
        raise HandoffFailure("TARGET_UNSUPPORTED", request_id)
    descriptors: list[int] = []
    try:
        descriptors.append(
            _open_bound_block_device(leaf_major_minor, leaf_major, leaf_minor)
        )
        descriptors.append(
            _open_bound_block_device(parent_major_minor, parent_major, parent_minor)
        )
        _assert_block_fd(descriptors[0], leaf_major, leaf_minor)
        _assert_block_fd(descriptors[1], parent_major, parent_minor)
    except Exception:
        _close_descriptors(descriptors)
        raise
    return descriptors


def _revalidate_block_pair(
    descriptors: list[int],
    leaf_major_minor: str,
    leaf_major: int,
    leaf_minor: int,
    parent_major_minor: str,
    parent_major: int,
    parent_minor: int,
    request_id: str,
    *,
    writable_leaf: bool = False,
) -> None:
    if len(descriptors) < 2:
        raise HandoffFailure("DEVICE_UNAVAILABLE", request_id)
    _assert_block_fd(descriptors[0], leaf_major, leaf_minor, writable=writable_leaf)
    _assert_block_fd(descriptors[1], parent_major, parent_minor)
    if _mountinfo_has_device(leaf_major_minor) or _mountinfo_has_device(
        parent_major_minor
    ):
        raise HandoffFailure("TARGET_CHANGED", request_id)


def _complete_read_only_bundle(
    descriptors: list[int],
    uuids: tuple[str, ...],
    leaf_major_minor: str,
    leaf_major: int,
    leaf_minor: int,
    parent_major_minor: str,
    parent_major: int,
    parent_minor: int,
    leaf_size_bytes: int,
    parent_size_bytes: int,
    deadline: float,
    request_id: str,
) -> tuple[dict[str, object], dict[str, int]]:
    _ensure_deadline(deadline, request_id)
    uuid_descriptor, uuid_metadata = _create_uuid_inventory_memfd(uuids)
    descriptors.append(uuid_descriptor)
    _ensure_deadline(deadline, request_id)
    descriptors.append(
        _create_detached_ext4_mount(descriptors[0], leaf_major, leaf_minor)
    )
    _ensure_deadline(deadline, request_id)
    _revalidate_block_pair(
        descriptors,
        leaf_major_minor,
        leaf_major,
        leaf_minor,
        parent_major_minor,
        parent_major,
        parent_minor,
        request_id,
    )
    _assert_uuid_inventory_fd(descriptors[2], _uuid_inventory_payload(uuids))
    _assert_detached_ext4_mount_fd(descriptors[3], leaf_major, leaf_minor)
    physical_parent_claims = _probe_physical_parent_claims(
        descriptors[0],
        descriptors[1],
        leaf_size_bytes,
        parent_size_bytes,
        parent_major,
        parent_minor,
    )
    parent_identity = _open_bound_block_identity(parent_major, parent_minor)
    try:
        _assert_block_identity_fd(parent_identity, parent_major, parent_minor)
    except Exception:
        os.close(parent_identity)
        raise
    parent_readable = descriptors[1]
    descriptors[1] = parent_identity
    os.close(parent_readable)
    return uuid_metadata, physical_parent_claims


def _descriptor_manifest() -> list[dict[str, object]]:
    return [
        {"index": index, "type": descriptor_type}
        for index, descriptor_type in enumerate(BUNDLE_DESCRIPTOR_TYPES)
    ]


def _revalidate_final_bundle(
    descriptors: list[int],
    uuids: tuple[str, ...],
    claims: dict[str, int],
    leaf_major_minor: str,
    leaf_major: int,
    leaf_minor: int,
    parent_major_minor: str,
    parent_major: int,
    parent_minor: int,
    request_id: str,
) -> None:
    claims = _validate_physical_parent_claims_wire(claims)
    if len(descriptors) != len(BUNDLE_DESCRIPTOR_TYPES):
        raise HandoffFailure("DEVICE_UNAVAILABLE", request_id)
    _assert_block_fd(descriptors[0], leaf_major, leaf_minor)
    _assert_block_identity_fd(descriptors[1], parent_major, parent_minor)
    if (
        _probe_u64(descriptors[0], BLKGETDISKSEQ) != claims["diskSequence"]
        or _probe_u64(descriptors[0], BLKGETSIZE64)
        != claims["leafSectorCount"] * KERNEL_SECTOR_BYTES
        or _probe_u32(descriptors[0], BLKSSZGET)
        != claims["logicalSectorBytes"]
        or claims["parentMajor"] != parent_major
        or claims["parentMinor"] != parent_minor
        or claims["leafSectorCount"] > claims["mediaSectorCount"]
        or _mountinfo_has_device(leaf_major_minor)
        or _mountinfo_has_device(parent_major_minor)
    ):
        raise HandoffFailure("TARGET_CHANGED", request_id)
    _assert_uuid_inventory_fd(descriptors[2], _uuid_inventory_payload(uuids))
    _assert_detached_ext4_mount_fd(descriptors[3], leaf_major, leaf_minor)


class RepairTargetHandoff:
    def __init__(self, targets: object | None = None) -> None:
        self.targets = _load_target_module() if targets is None else targets

    def acquire(self, request: dict[str, str]) -> tuple[dict[str, object], list[int]]:
        if request.get("operation") == WRITE_OPERATION:
            return self._acquire_write(request)
        if request.get("operation") == RECOVERY_OPERATION:
            return self._recover(request)
        return self._acquire_selected(request)

    def _acquire_write(
        self, request: dict[str, str]
    ) -> tuple[dict[str, object], list[int]]:
        request_id = request["requestId"]
        deadline = time.monotonic() + IO_TIMEOUT_SECONDS
        descriptors: list[int] = []
        try:
            # Consumption is deliberately first and is never retried except for
            # one explicit authenticated stale-state response.
            lease = _consume_write_lease(request["reservationId"],
                                         request["transactionBindingSha256"], deadline)
            recovery = lease["recoveryFingerprint"]
            reference = {"recoveryFingerprint": recovery}
            selection_a, resolution_a = self.targets.resolve_recovery_target(
                reference, deadline=deadline)
            qualified_a = _qualify(self.targets, request, selection_a, resolution_a,
                                   expected_recovery_fingerprint=recovery)
            (_recovery, major_minor, major, minor, parent_major_minor, parent_major,
             parent_minor, leaf_size_bytes, parent_size_bytes) = qualified_a
            if _mountinfo_has_device(major_minor) or _mountinfo_has_device(parent_major_minor):
                raise HandoffFailure("TARGET_UNSUPPORTED", request_id)
            descriptors = [
                _open_bound_block_device(major_minor, major, minor, writable=True),
                _open_bound_block_device(parent_major_minor, parent_major, parent_minor),
            ]
            claims = _probe_physical_parent_claims(
                descriptors[0], descriptors[1], leaf_size_bytes, parent_size_bytes,
                parent_major, parent_minor)
            current_parent_fingerprint = _physical_parent_fingerprint(claims)
            selection_b, resolution_b = self.targets.resolve_recovery_target(
                reference, deadline=deadline)
            qualified_b = _qualify(self.targets, request, selection_b, resolution_b,
                                   expected_recovery_fingerprint=recovery)
            if (self.targets.canonical_target_selection(selection_a)
                    != self.targets.canonical_target_selection(selection_b)
                    or _canonical(resolution_a) != _canonical(resolution_b)
                    or qualified_a != qualified_b):
                raise HandoffFailure("TARGET_CHANGED", request_id)
            _revalidate_block_pair(descriptors, major_minor, major, minor,
                                   parent_major_minor, parent_major, parent_minor, request_id,
                                   writable_leaf=True)
            mount = _create_detached_ext4_write_mount(descriptors[0], major, minor)
            descriptors.append(mount)
            selection_c, resolution_c = self.targets.resolve_recovery_target(
                reference, deadline=deadline)
            qualified_c = _qualify(self.targets, request, selection_c, resolution_c,
                                   expected_recovery_fingerprint=recovery)
            if (self.targets.canonical_target_selection(selection_a)
                    != self.targets.canonical_target_selection(selection_c)
                    or _canonical(resolution_a) != _canonical(resolution_c)
                    or qualified_a != qualified_c):
                raise HandoffFailure("TARGET_CHANGED", request_id)
            _revalidate_block_pair(descriptors, major_minor, major, minor,
                                   parent_major_minor, parent_major, parent_minor, request_id,
                                   writable_leaf=True)
            fresh_claims = _probe_physical_parent_claims(
                descriptors[0], descriptors[1], leaf_size_bytes, parent_size_bytes,
                parent_major, parent_minor)
            # The transaction's physical-parent digest is intentionally
            # boot-local. Durable recovery is authorized by the stable
            # recovery fingerprint, while this helper requires the freshly
            # probed current-boot parent to remain byte-identical throughout
            # all three resolutions and detached-mount creation.
            if (fresh_claims != claims
                    or _physical_parent_fingerprint(fresh_claims)
                    != current_parent_fingerprint):
                raise HandoffFailure("TARGET_CHANGED", request_id)
            _assert_detached_ext4_write_mount_fd(mount, major, minor)
            # Raw block capabilities remain inside the root helper TCB.
            os.close(descriptors.pop(1))
            os.close(descriptors.pop(0))
        except HandoffFailure as error:
            _close_descriptors(descriptors)
            if error.request_id is None:
                error.request_id = request_id
            raise
        except Exception as error:
            _close_descriptors(descriptors)
            raise HandoffFailure("INTERNAL", request_id) from error
        return ({"apiVersion": API_VERSION, "requestId": request_id,
                 "operation": WRITE_OPERATION, "outcome": "ok",
                 "capability": WRITE_CAPABILITY,
                 "reservationId": request["reservationId"],
                 "transactionBindingSha256": request["transactionBindingSha256"],
                 "targetRecoveryFingerprint": recovery,
                 "leaseBindingSha256": lease["leaseBindingSha256"],
                 "descriptor": {"type": WRITE_DESCRIPTOR_TYPE, "count": 1}}, descriptors)

    def _acquire_selected(
        self, request: dict[str, str]
    ) -> tuple[dict[str, object], list[int]]:
        request_id = request["requestId"]
        reference = {
            "scanFingerprint": request["scanFingerprint"],
            "targetId": request["targetId"],
        }
        deadline = time.monotonic() + IO_TIMEOUT_SECONDS
        descriptors: list[int] = []
        try:
            selection_a, resolution_a = self.targets.resolve_installed_target(
                reference, deadline=deadline
            )
            qualified_a = _qualify(
                self.targets, request, selection_a, resolution_a
            )
            (
                recovery_fingerprint_a,
                major_minor,
                major,
                minor,
                parent_major_minor,
                parent_major,
                parent_minor,
                leaf_size_bytes,
                parent_size_bytes,
            ) = qualified_a
            descriptors = _open_block_pair(
                major_minor,
                major,
                minor,
                parent_major_minor,
                parent_major,
                parent_minor,
                request_id,
            )
            runtime_fingerprint, uuids = _observed_inventory_fingerprint(
                self.targets, deadline, request_id
            )
            selection_b, resolution_b = self.targets.resolve_installed_target(
                reference, deadline=deadline
            )
            qualified_b = _qualify(self.targets, request, selection_b, resolution_b)
            if (
                self.targets.canonical_target_selection(selection_a)
                != self.targets.canonical_target_selection(selection_b)
                or _canonical(resolution_a) != _canonical(resolution_b)
                or qualified_a != qualified_b
            ):
                raise HandoffFailure("TARGET_CHANGED", request_id)
            candidate_a = resolution_a.get("candidate")
            candidate_b = resolution_b.get("candidate")
            if not isinstance(candidate_a, dict) or not isinstance(candidate_b, dict):
                raise HandoffFailure("INTERNAL", request_id)
            fingerprint_a = _recompute_target_fingerprint(
                self.targets,
                runtime_fingerprint,
                request["scanFingerprint"],
                candidate_a,
                request_id,
            )
            fingerprint_b = _recompute_target_fingerprint(
                self.targets,
                runtime_fingerprint,
                request["scanFingerprint"],
                candidate_b,
                request_id,
            )
            if (
                fingerprint_a != fingerprint_b
                or fingerprint_a != request["targetFingerprint"]
            ):
                raise HandoffFailure("TARGET_CHANGED", request_id)
            _revalidate_block_pair(
                descriptors,
                major_minor,
                major,
                minor,
                parent_major_minor,
                parent_major,
                parent_minor,
                request_id,
            )
            uuid_metadata, physical_parent_claims = _complete_read_only_bundle(
                descriptors,
                uuids,
                major_minor,
                major,
                minor,
                parent_major_minor,
                parent_major,
                parent_minor,
                leaf_size_bytes,
                parent_size_bytes,
                deadline,
                request_id,
            )
            _ensure_deadline(deadline, request_id)
            selection_c, resolution_c = self.targets.resolve_installed_target(
                reference, deadline=deadline
            )
            qualified_c = _qualify(self.targets, request, selection_c, resolution_c)
            if (
                self.targets.canonical_target_selection(selection_a)
                != self.targets.canonical_target_selection(selection_c)
                or _canonical(resolution_a) != _canonical(resolution_c)
                or qualified_a != qualified_c
            ):
                raise HandoffFailure("TARGET_CHANGED", request_id)
            _revalidate_final_bundle(
                descriptors,
                uuids,
                physical_parent_claims,
                major_minor,
                major,
                minor,
                parent_major_minor,
                parent_major,
                parent_minor,
                request_id,
            )
        except HandoffFailure as error:
            _close_descriptors(descriptors)
            if error.request_id is None:
                error.request_id = request_id
            raise
        except Exception as error:
            _close_descriptors(descriptors)
            target_errors = tuple(
                error_type
                for error_type in (
                    getattr(self.targets, "InventoryBusy", None),
                    getattr(self.targets, "TargetScanBusy", None),
                    getattr(self.targets, "TargetScanError", None),
                    getattr(self.targets, "TargetSelectionError", None),
                    TimeoutError,
                )
                if isinstance(error_type, type)
            )
            token = "TARGET_UNAVAILABLE" if isinstance(error, target_errors) else "INTERNAL"
            raise HandoffFailure(token, request_id) from error
        return (
            {
                "apiVersion": API_VERSION,
                "requestId": request_id,
                "operation": ACQUIRE_OPERATION,
                "scanFingerprint": request["scanFingerprint"],
                "targetFingerprint": fingerprint_a,
                "targetId": request["targetId"],
                "recoveryFingerprint": recovery_fingerprint_a,
                "outcome": "ok",
                "capability": BUNDLE_CAPABILITY,
                "descriptors": _descriptor_manifest(),
                "physicalParentClaims": physical_parent_claims,
                "uuidInventory": uuid_metadata,
            },
            descriptors,
        )

    def _recover(
        self, request: dict[str, str]
    ) -> tuple[dict[str, object], list[int]]:
        request_id = request["requestId"]
        recovery_fingerprint = request["recoveryFingerprint"]
        reference = {"recoveryFingerprint": recovery_fingerprint}
        deadline = time.monotonic() + IO_TIMEOUT_SECONDS
        descriptors: list[int] = []
        try:
            selection_a, resolution_a = self.targets.resolve_recovery_target(
                reference, deadline=deadline
            )
            qualified_a = _qualify(
                self.targets,
                request,
                selection_a,
                resolution_a,
                expected_recovery_fingerprint=recovery_fingerprint,
            )
            (
                recovery_fingerprint_a,
                major_minor,
                major,
                minor,
                parent_major_minor,
                parent_major,
                parent_minor,
                leaf_size_bytes,
                parent_size_bytes,
            ) = qualified_a
            descriptors = _open_block_pair(
                major_minor,
                major,
                minor,
                parent_major_minor,
                parent_major,
                parent_minor,
                request_id,
            )
            try:
                runtime_fingerprint, uuids = _observed_inventory_fingerprint(
                    self.targets, deadline, request_id
                )
                selection_b, resolution_b = self.targets.resolve_recovery_target(
                    reference, deadline=deadline
                )
                qualified_b = _qualify(
                    self.targets,
                    request,
                    selection_b,
                    resolution_b,
                    expected_recovery_fingerprint=recovery_fingerprint,
                )
            except Exception as error:
                raise HandoffFailure("TARGET_CHANGED", request_id) from error
            if (
                self.targets.canonical_target_selection(selection_a)
                != self.targets.canonical_target_selection(selection_b)
                or _canonical(resolution_a) != _canonical(resolution_b)
                or qualified_a != qualified_b
            ):
                raise HandoffFailure("TARGET_CHANGED", request_id)
            candidate_a = resolution_a.get("candidate")
            candidate_b = resolution_b.get("candidate")
            if not isinstance(candidate_a, dict) or not isinstance(candidate_b, dict):
                raise HandoffFailure("INTERNAL", request_id)
            scan_fingerprint = selection_a.get("scanFingerprint")
            target_id = candidate_a.get("targetId")
            if not isinstance(scan_fingerprint, str) or not isinstance(target_id, str):
                raise HandoffFailure("INTERNAL", request_id)
            fingerprint_a = _recompute_target_fingerprint(
                self.targets,
                runtime_fingerprint,
                scan_fingerprint,
                candidate_a,
                request_id,
            )
            fingerprint_b = _recompute_target_fingerprint(
                self.targets,
                runtime_fingerprint,
                scan_fingerprint,
                candidate_b,
                request_id,
            )
            if fingerprint_a != fingerprint_b:
                raise HandoffFailure("TARGET_CHANGED", request_id)
            _revalidate_block_pair(
                descriptors,
                major_minor,
                major,
                minor,
                parent_major_minor,
                parent_major,
                parent_minor,
                request_id,
            )
            uuid_metadata, physical_parent_claims = _complete_read_only_bundle(
                descriptors,
                uuids,
                major_minor,
                major,
                minor,
                parent_major_minor,
                parent_major,
                parent_minor,
                leaf_size_bytes,
                parent_size_bytes,
                deadline,
                request_id,
            )
            _ensure_deadline(deadline, request_id)
            selection_c, resolution_c = self.targets.resolve_recovery_target(
                reference, deadline=deadline
            )
            qualified_c = _qualify(
                self.targets,
                request,
                selection_c,
                resolution_c,
                expected_recovery_fingerprint=recovery_fingerprint,
            )
            if (
                self.targets.canonical_target_selection(selection_a)
                != self.targets.canonical_target_selection(selection_c)
                or _canonical(resolution_a) != _canonical(resolution_c)
                or qualified_a != qualified_c
            ):
                raise HandoffFailure("TARGET_CHANGED", request_id)
            _revalidate_final_bundle(
                descriptors,
                uuids,
                physical_parent_claims,
                major_minor,
                major,
                minor,
                parent_major_minor,
                parent_major,
                parent_minor,
                request_id,
            )
        except HandoffFailure as error:
            _close_descriptors(descriptors)
            if error.request_id is None:
                error.request_id = request_id
            raise
        except Exception as error:
            _close_descriptors(descriptors)
            target_errors = tuple(
                error_type
                for error_type in (
                    getattr(self.targets, "InventoryBusy", None),
                    getattr(self.targets, "TargetScanBusy", None),
                    getattr(self.targets, "TargetScanError", None),
                    getattr(self.targets, "TargetSelectionError", None),
                    TimeoutError,
                )
                if isinstance(error_type, type)
            )
            token = "TARGET_UNAVAILABLE" if isinstance(error, target_errors) else "INTERNAL"
            raise HandoffFailure(token, request_id) from error
        return (
            {
                "apiVersion": API_VERSION,
                "requestId": request_id,
                "operation": RECOVERY_OPERATION,
                "scanFingerprint": scan_fingerprint,
                "targetFingerprint": fingerprint_a,
                "targetId": target_id,
                "recoveryFingerprint": recovery_fingerprint_a,
                "outcome": "ok",
                "capability": BUNDLE_CAPABILITY,
                "descriptors": _descriptor_manifest(),
                "physicalParentClaims": physical_parent_claims,
                "uuidInventory": uuid_metadata,
            },
            descriptors,
        )


def _received_record(connection: socket.socket) -> bytes:
    payload, ancillary, flags, _address = connection.recvmsg(
        MAX_REQUEST_BYTES + 1,
        socket.CMSG_SPACE(4 * array.array("i").itemsize),
        getattr(socket, "MSG_CMSG_CLOEXEC", 0),
    )
    for level, kind, data in ancillary:
        if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
            descriptors = array.array("i")
            descriptors.frombytes(data[: len(data) - len(data) % descriptors.itemsize])
            for descriptor in descriptors:
                os.close(descriptor)
    if (
        not payload
        or len(payload) > MAX_REQUEST_BYTES
        or ancillary
        or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
    ):
        raise HandoffFailure("INVALID_REQUEST")
    return payload


def _send_record(
    connection: socket.socket,
    response: dict[str, object],
    descriptors: list[int],
) -> None:
    encoded = _canonical(response)
    if len(encoded) >= MAX_RESPONSE_BYTES:
        request_id = response.get("requestId")
        raise HandoffFailure(
            "INTERNAL", request_id if isinstance(request_id, str) else None
        )
    success = response.get("outcome") == "ok"
    if success:
        if response.get("capability") == WRITE_CAPABILITY:
            if (response.get("descriptor") != {"type": WRITE_DESCRIPTOR_TYPE, "count": 1}
                    or len(descriptors) != 1):
                raise HandoffFailure("INTERNAL", response.get("requestId"))
            return _send_encoded_record(connection, encoded, descriptors)
        claims = _validate_physical_parent_claims_wire(
            response.get("physicalParentClaims")
        )
        if (
            response.get("capability") != BUNDLE_CAPABILITY
            or response.get("descriptors") != _descriptor_manifest()
            or len(descriptors) != len(BUNDLE_DESCRIPTOR_TYPES)
            or len(set(descriptors)) != len(descriptors)
            or any(
                not isinstance(item, int) or isinstance(item, bool)
                for item in descriptors
            )
        ):
            request_id = response.get("requestId")
            raise HandoffFailure(
                "INTERNAL", request_id if isinstance(request_id, str) else None
            )
        _assert_readonly_block_capability(descriptors[0])
        _assert_block_identity_fd(
            descriptors[1], claims["parentMajor"], claims["parentMinor"]
        )
    elif descriptors:
        request_id = response.get("requestId")
        raise HandoffFailure(
            "INTERNAL", request_id if isinstance(request_id, str) else None
        )
    _send_encoded_record(connection, encoded, descriptors)


def _send_encoded_record(connection: socket.socket, encoded: bytes, descriptors: list[int]) -> None:
    ancillary = []
    if descriptors:
        ancillary = [
            (
                socket.SOL_SOCKET,
                socket.SCM_RIGHTS,
                array.array("i", descriptors).tobytes(),
            )
        ]
    if connection.sendmsg([encoded], ancillary) != len(encoded):
        raise OSError("short SOCK_SEQPACKET send")


def serve_connection(
    connection: socket.socket,
    expected_peer_uid: int,
    service: RepairTargetHandoff | None = None,
    *,
    expected_local: str | None = SOCKET_PATH,
    profile: str = PROFILE_READONLY,
) -> None:
    descriptors: list[int] = []
    request: dict[str, str] | None = None
    try:
        _validate_peer(connection, expected_peer_uid, expected_local=expected_local)
    except HandoffFailure:
        return
    try:
        request = _decode_request(_received_record(connection), profile)
        response, descriptors = (service or RepairTargetHandoff()).acquire(request)
        _send_record(connection, response, descriptors)
    except HandoffFailure as error:
        if error.request_id is None:
            return
        operation = (
            error.operation
            if error.operation in {ACQUIRE_OPERATION, RECOVERY_OPERATION, WRITE_OPERATION}
            else request.get("operation") if request is not None else None
        )
        if operation not in {ACQUIRE_OPERATION, RECOVERY_OPERATION, WRITE_OPERATION}:
            operation = WRITE_OPERATION if profile == PROFILE_WRITE else ACQUIRE_OPERATION
        response: dict[str, object] = {
            "apiVersion": API_VERSION,
            "requestId": error.request_id,
            "operation": operation,
            "outcome": "error",
            "error": error.token,
        }
        try:
            _send_record(connection, response, [])
        except (HandoffFailure, OSError):
            pass
    except Exception:
        if request is None:
            return
        try:
            _send_record(
                connection,
                {
                    "apiVersion": API_VERSION,
                    "requestId": request["requestId"],
                    "operation": request["operation"],
                    "outcome": "error",
                    "error": "INTERNAL",
                },
                [],
            )
        except (HandoffFailure, OSError):
            pass
    finally:
        _close_descriptors(descriptors)


def _systemd_connection(profile: str) -> socket.socket:
    expected_name = "target-write-capability" if profile == PROFILE_WRITE else "target-capability"
    expected_path = WRITE_SOCKET_PATH if profile == PROFILE_WRITE else SOCKET_PATH
    if (
        os.environ.get("LISTEN_PID") != str(os.getpid())
        or os.environ.get("LISTEN_FDS") != "1"
        or os.environ.get("LISTEN_FDNAMES") != expected_name
    ):
        raise RuntimeError("exactly one named accepted connection is required")
    connection = socket.socket(fileno=3)
    fcntl.fcntl(connection.fileno(), fcntl.F_SETFD, fcntl.FD_CLOEXEC)
    if (
        connection.family != socket.AF_UNIX
        or connection.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE)
        != socket.SOCK_SEQPACKET
        or connection.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 0
        or connection.getsockname() != expected_path
    ):
        connection.close()
        raise RuntimeError("accepted connection does not match fixed endpoint")
    return connection


def main() -> int:
    if os.geteuid() != 0 or sys.argv != [sys.argv[0]]:
        return 1
    try:
        profile = _profile()
        expected_uid = _repair_broker_uid()
        connection = _systemd_connection(profile)
    except (RuntimeError, OSError):
        return 1
    with connection:
        connection.settimeout(IO_TIMEOUT_SECONDS)
        serve_connection(connection, expected_uid,
                         expected_local=(WRITE_SOCKET_PATH if profile == PROFILE_WRITE else SOCKET_PATH),
                         profile=profile)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
