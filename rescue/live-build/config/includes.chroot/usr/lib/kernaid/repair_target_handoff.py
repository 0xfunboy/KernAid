#!/usr/bin/python3
"""Disabled-by-default root handoff for one selected Rescue repair target.

The caller supplies only boot-ephemeral opaque identifiers.  The helper loads
the fixed Rescue target resolver, resolves the selection twice, and returns a
single read-only block-device descriptor.  No unit or account enables this
candidate in the shipping image yet.
"""

from __future__ import annotations

import array
import fcntl
import json
import os
from pathlib import Path
import re
import socket
import stat
import struct
import sys
import time
import types


API_VERSION = "kernaid.dev/rescue-target-capability/v1alpha1"
OPERATION = "target.readonly.acquire"
SOCKET_PATH = "/run/kernaid-rescue-target-capability.sock"
TARGET_MODULE_PATH = "/usr/lib/kernaid/rescue_server.py"
PEER_UID_ENV = "KERNAID_REPAIR_BROKER_UID"
# Candidate-only test seam.  Future packaging must resolve the exact dedicated
# account in its root-owned launcher/unit; it must not ship a hard-coded UID.
MAX_REQUEST_BYTES = 1024
MAX_RESPONSE_BYTES = 1024
IO_TIMEOUT_SECONDS = 8

_REQUEST_ID = re.compile(
    r"^R-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
_EPHEMERAL_ID = {
    prefix: re.compile(rf"^{prefix}:[0-9a-f]{{64}}$")
    for prefix in ("scan", "target")
}
_MAJOR_MINOR = re.compile(r"^(0|[1-9][0-9]{0,9}):(0|[1-9][0-9]{0,9})$")
_SAFE_DEVNAME = re.compile(r"^[A-Za-z0-9._+-]{1,128}$")
_ERRORS = {
    "INVALID_REQUEST",
    "TARGET_UNAVAILABLE",
    "TARGET_UNSUPPORTED",
    "TARGET_CHANGED",
    "DEVICE_UNAVAILABLE",
    "INTERNAL",
}


class HandoffFailure(Exception):
    def __init__(self, token: str, request_id: str | None = None) -> None:
        if token not in _ERRORS:
            raise ValueError("unknown handoff failure")
        super().__init__(token)
        self.token = token
        self.request_id = request_id


def _reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON member")
        result[key] = value
    return result


def _decode_request(payload: bytes) -> dict[str, str]:
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
    if (
        not isinstance(request_id, str)
        or _REQUEST_ID.fullmatch(request_id) is None
        or value.get("apiVersion") != API_VERSION
        or value.get("operation") != OPERATION
    ):
        raise HandoffFailure("INVALID_REQUEST")
    if set(value) != {
        "apiVersion",
        "scanFingerprint",
        "targetId",
        "requestId",
        "operation",
    }:
        raise HandoffFailure("INVALID_REQUEST", request_id)
    scan = value.get("scanFingerprint")
    target = value.get("targetId")
    if (
        not isinstance(scan, str)
        or _EPHEMERAL_ID["scan"].fullmatch(scan) is None
        or not isinstance(target, str)
        or _EPHEMERAL_ID["target"].fullmatch(target) is None
    ):
        raise HandoffFailure("INVALID_REQUEST", request_id)
    return {
        "apiVersion": API_VERSION,
        "requestId": request_id,
        "operation": OPERATION,
        "scanFingerprint": scan,
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


def _peer_uid_from_environment() -> int:
    value = os.environ.get(PEER_UID_ENV, "")
    if not value.isascii() or not value.isdecimal() or value != str(int(value)):
        raise RuntimeError("dedicated repair broker UID is not configured")
    uid = int(value)
    if uid <= 0 or uid > 4_294_967_294:
        raise RuntimeError("dedicated repair broker UID is invalid")
    return uid


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
) -> tuple[str, int, int]:
    request_id = request["requestId"]
    if not isinstance(selection, dict) or not isinstance(resolution, dict):
        raise HandoffFailure("TARGET_UNSUPPORTED", request_id)
    try:
        selected_candidate = targets.validate_target_selection(
            selection,
            {
                "scanFingerprint": request["scanFingerprint"],
                "targetId": request["targetId"],
            },
        )
    except Exception as error:
        raise HandoffFailure("TARGET_UNSUPPORTED", request_id) from error
    candidate = resolution.get("candidate")
    identity = resolution.get("deviceIdentity")
    major_minor = resolution.get("majorMinor")
    if (
        selection.get("scanFingerprint") != request["scanFingerprint"]
        or not isinstance(selection.get("target"), dict)
        or selection["target"].get("targetId") != request["targetId"]
        or not isinstance(candidate, dict)
        or candidate != selected_candidate
        or candidate.get("osFamilyHint") != "linux"
        or candidate.get("requiresUnlock") is not False
        or candidate.get("selectionEligible") is not True
        or resolution.get("filesystem") != "ext4"
        or resolution.get("kernelKind") not in {"disk", "part"}
        or resolution.get("leaf") is not True
        or resolution.get("directOnDisk") is not True
        or not isinstance(identity, dict)
        or identity.get("maj:min") != major_minor
        or identity.get("type") != resolution.get("kernelKind")
        or identity.get("fstype") != "ext4"
        or identity.get("ro") is not False
        or not isinstance(identity.get("mountpoints"), list)
        or any(bool(item) for item in identity["mountpoints"])
    ):
        raise HandoffFailure("TARGET_UNSUPPORTED", request_id)
    try:
        major, minor = _major_minor(major_minor)
    except HandoffFailure as error:
        error.request_id = request_id
        raise
    return str(major_minor), major, minor


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


def _assert_block_fd(descriptor: int, major: int, minor: int) -> None:
    metadata = os.fstat(descriptor)
    flags = fcntl.fcntl(descriptor, fcntl.F_GETFL)
    fd_flags = fcntl.fcntl(descriptor, fcntl.F_GETFD)
    if (
        not stat.S_ISBLK(metadata.st_mode)
        or os.major(metadata.st_rdev) != major
        or os.minor(metadata.st_rdev) != minor
        or flags & os.O_ACCMODE != os.O_RDONLY
        or not flags & os.O_NONBLOCK
        or not fd_flags & fcntl.FD_CLOEXEC
    ):
        raise HandoffFailure("DEVICE_UNAVAILABLE")


def _open_bound_block_device(major_minor: str, major: int, minor: int) -> int:
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
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=dev_fd,
        )
        try:
            _assert_block_fd(descriptor, major, minor)
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


class RepairTargetHandoff:
    def __init__(self, targets: object | None = None) -> None:
        self.targets = _load_target_module() if targets is None else targets

    def acquire(self, request: dict[str, str]) -> tuple[dict[str, object], int]:
        request_id = request["requestId"]
        reference = {
            "scanFingerprint": request["scanFingerprint"],
            "targetId": request["targetId"],
        }
        deadline = time.monotonic() + IO_TIMEOUT_SECONDS
        try:
            selection_a, resolution_a = self.targets.resolve_installed_target(
                reference, deadline=deadline
            )
            major_minor, major, minor = _qualify(
                self.targets, request, selection_a, resolution_a
            )
            if _mountinfo_has_device(major_minor):
                raise HandoffFailure("TARGET_UNSUPPORTED", request_id)
            descriptor = _open_bound_block_device(major_minor, major, minor)
            try:
                selection_b, resolution_b = self.targets.resolve_installed_target(
                    reference, deadline=deadline
                )
                _qualify(self.targets, request, selection_b, resolution_b)
                if (
                    self.targets.canonical_target_selection(selection_a)
                    != self.targets.canonical_target_selection(selection_b)
                    or _canonical(resolution_a) != _canonical(resolution_b)
                ):
                    raise HandoffFailure("TARGET_CHANGED", request_id)
                _assert_block_fd(descriptor, major, minor)
                if _mountinfo_has_device(major_minor):
                    raise HandoffFailure("TARGET_CHANGED", request_id)
            except Exception:
                os.close(descriptor)
                raise
        except HandoffFailure as error:
            if error.request_id is None:
                error.request_id = request_id
            raise
        except Exception as error:
            target_errors = tuple(
                error_type
                for error_type in (
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
                "operation": OPERATION,
                "scanFingerprint": request["scanFingerprint"],
                "targetId": request["targetId"],
                "outcome": "ok",
                "capability": "linux-ext4-direct-leaf-readonly-block-v1",
                "descriptor": {
                    "type": "selected-target-block-readonly",
                    "count": 1,
                },
            },
            descriptor,
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
    descriptor: int | None,
) -> None:
    encoded = _canonical(response)
    if len(encoded) > MAX_RESPONSE_BYTES:
        request_id = response.get("requestId")
        raise HandoffFailure(
            "INTERNAL", request_id if isinstance(request_id, str) else None
        )
    ancillary = []
    if descriptor is not None:
        ancillary = [
            (
                socket.SOL_SOCKET,
                socket.SCM_RIGHTS,
                array.array("i", [descriptor]).tobytes(),
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
) -> None:
    descriptor: int | None = None
    request: dict[str, str] | None = None
    try:
        _validate_peer(connection, expected_peer_uid, expected_local=expected_local)
    except HandoffFailure:
        return
    try:
        request = _decode_request(_received_record(connection))
        response, descriptor = (service or RepairTargetHandoff()).acquire(request)
        _send_record(connection, response, descriptor)
    except HandoffFailure as error:
        if error.request_id is None:
            return
        response: dict[str, object] = {
            "apiVersion": API_VERSION,
            "requestId": error.request_id,
            "operation": OPERATION,
            "outcome": "error",
            "error": error.token,
        }
        try:
            _send_record(connection, response, None)
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
                    "operation": OPERATION,
                    "outcome": "error",
                    "error": "INTERNAL",
                },
                None,
            )
        except (HandoffFailure, OSError):
            pass
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _systemd_connection() -> socket.socket:
    if (
        os.environ.get("LISTEN_PID") != str(os.getpid())
        or os.environ.get("LISTEN_FDS") != "1"
        or os.environ.get("LISTEN_FDNAMES") != "target-capability"
    ):
        raise RuntimeError("exactly one named accepted connection is required")
    connection = socket.socket(fileno=3)
    fcntl.fcntl(connection.fileno(), fcntl.F_SETFD, fcntl.FD_CLOEXEC)
    if (
        connection.family != socket.AF_UNIX
        or connection.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE)
        != socket.SOCK_SEQPACKET
        or connection.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 0
        or connection.getsockname() != SOCKET_PATH
    ):
        connection.close()
        raise RuntimeError("accepted connection does not match fixed endpoint")
    return connection


def main() -> int:
    if os.geteuid() != 0 or sys.argv != [sys.argv[0]]:
        return 1
    try:
        expected_uid = _peer_uid_from_environment()
        connection = _systemd_connection()
    except (RuntimeError, OSError):
        return 1
    with connection:
        connection.settimeout(IO_TIMEOUT_SECONDS)
        serve_connection(connection, expected_uid)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
