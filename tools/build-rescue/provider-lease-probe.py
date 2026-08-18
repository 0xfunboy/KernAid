#!/usr/bin/python3
"""QEMU-only, credential-loaded probe for the OpenAI vault lease boundary.

The probe deliberately validates the borrowed pipe without consuming its
contents.  It emits only one closed success token on its inherited control
socket and never writes provider material or operating-system diagnostics.
"""

from __future__ import annotations

import array
import ctypes
import fcntl
import json
import os
import re
import select
import signal
import socket
import stat
import struct
import time
from typing import NoReturn


API_VERSION = "kernaid.dev/rescue-vault/v1alpha1"
VAULT_SOCKET = "/run/kernaid-rescue-vault.sock"
PROVIDER_API_VERSION = "kernaid.dev/rescue-openai/v1alpha1"
PROVIDER_SOCKET = "/run/kernaid-rescue-openai.sock"
KILL_SOCKET = "/run/kernaid-provider-lease-kill-vaultd.sock"
MAX_DATAGRAM_BYTES = 64 * 1024
MAX_PROVIDER_RESPONSE_BYTES = 64 * 1024
MAX_SAFE_JSON_INTEGER = 9_007_199_254_740_991
MAX_OPENAI_KEY_BYTES = 512
PIPEFS_MAGIC = 0x5049_5045
FIONREAD = 0x541B
IO_TIMEOUT_SECONDS = 15.0
REQUEST_ID = "R-4c819593-60dd-4eca-8bcc-9e684520892f"
DEVICE_ID = re.compile(r"KA-[0-9a-f]{24}\Z")
NORMAL_COMMAND = b"NORMAL\n"
HOLD_COMMAND = b"HOLD\n"
STATUS_COMMAND = b"STATUS\n"
NORMAL_RESULT = b"KERNAID_PROVIDER_LEASE_PROBE_NORMAL_V1 borrowed=true unread=true\n"
HOLD_RESULT = b"KERNAID_PROVIDER_LEASE_PROBE_HOLD_V1 borrowed=true unread=true\n"
STATUS_RESULT = b"KERNAID_PROVIDER_EXECUTOR_STATUS_PROBE_V1 status=true shipping=true\n"


class ProbeFailure(Exception):
    """Closed failure type which never retains peer or provider bytes."""


class LinuxStatFs(ctypes.Structure):
    _fields_ = [
        ("f_type", ctypes.c_long),
        ("f_bsize", ctypes.c_long),
        ("f_blocks", ctypes.c_ulong),
        ("f_bfree", ctypes.c_ulong),
        ("f_bavail", ctypes.c_ulong),
        ("f_files", ctypes.c_ulong),
        ("f_ffree", ctypes.c_ulong),
        ("f_fsid", ctypes.c_int * 2),
        ("f_namelen", ctypes.c_long),
        ("f_frsize", ctypes.c_long),
        ("f_flags", ctypes.c_long),
        ("f_spare", ctypes.c_long * 4),
    ]


LIBC = ctypes.CDLL(None, use_errno=True)
LIBC.fstatfs.argtypes = (ctypes.c_int, ctypes.POINTER(LinuxStatFs))
LIBC.fstatfs.restype = ctypes.c_int


def _fail() -> NoReturn:
    raise ProbeFailure


def _closed_json(data: bytes) -> dict[str, object]:
    def pairs_hook(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                _fail()
            result[key] = value
        return result

    def reject_constant(_value: str) -> NoReturn:
        _fail()

    try:
        decoded = json.loads(
            data.decode("utf-8", errors="strict"),
            object_pairs_hook=pairs_hook,
            parse_constant=reject_constant,
        )
    except (UnicodeError, ValueError, TypeError, ProbeFailure) as error:
        raise ProbeFailure from error
    if type(decoded) is not dict:
        _fail()
    return decoded


def _exact_integer(value: object, *, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        _fail()
    return value


def _peer_is_root(connection: socket.socket) -> None:
    try:
        pid, uid, gid = struct.unpack(
            "3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        )
    except (OSError, struct.error) as error:
        raise ProbeFailure from error
    if pid <= 0 or uid != 0 or gid != 0:
        _fail()


def _connect_vault() -> socket.socket:
    connection = socket.socket(
        socket.AF_UNIX,
        socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC,
    )
    try:
        connection.settimeout(IO_TIMEOUT_SECONDS)
        connection.connect(VAULT_SOCKET)
        _peer_is_root(connection)
        return connection
    except BaseException:
        connection.close()
        raise


def _request(operation: str, expected_state_version: int) -> bytes:
    encoded = json.dumps(
        {
            "apiVersion": API_VERSION,
            "requestId": REQUEST_ID,
            "expectedStateVersion": expected_state_version,
            "operation": operation,
            "payload": {},
        },
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("ascii")
    if not encoded or len(encoded) > MAX_DATAGRAM_BYTES:
        _fail()
    return encoded


def _receive_packet(
    connection: socket.socket, *, require_descriptor: bool
) -> tuple[dict[str, object], int | None]:
    descriptor_size = array.array("i").itemsize
    received_fds: list[int] = []
    try:
        data, ancillary, flags, _address = connection.recvmsg(
            MAX_DATAGRAM_BYTES + 1,
            socket.CMSG_SPACE(descriptor_size),
            getattr(socket, "MSG_CMSG_CLOEXEC", 0),
        )
        if (
            not data
            or len(data) > MAX_DATAGRAM_BYTES
            or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
        ):
            _fail()
        for level, kind, value in ancillary:
            if (
                level != socket.SOL_SOCKET
                or kind != socket.SCM_RIGHTS
                or len(value) != descriptor_size
            ):
                _fail()
            descriptors = array.array("i")
            descriptors.frombytes(value)
            received_fds.extend(descriptors.tolist())
        expected_count = 1 if require_descriptor else 0
        if len(received_fds) != expected_count:
            _fail()
        decoded = _closed_json(data)
        if require_descriptor:
            return decoded, received_fds.pop()
        return decoded, None
    finally:
        for descriptor in received_fds:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _validate_envelope(
    response: dict[str, object], *, operation: str, state_version: int | None
) -> tuple[int, dict[str, object]]:
    if set(response) != {
        "apiVersion",
        "requestId",
        "stateVersion",
        "operation",
        "outcome",
        "payload",
    }:
        _fail()
    observed_version = _exact_integer(
        response.get("stateVersion"), minimum=0, maximum=MAX_SAFE_JSON_INTEGER
    )
    if (
        response.get("apiVersion") != API_VERSION
        or response.get("requestId") != REQUEST_ID
        or response.get("operation") != operation
        or response.get("outcome") != "ok"
        or (state_version is not None and observed_version != state_version)
    ):
        _fail()
    payload = response.get("payload")
    if type(payload) is not dict:
        _fail()
    return observed_version, payload


def _observe_unlocked() -> int:
    with _connect_vault() as connection:
        request = _request("vault.status", 0)
        if connection.send(request) != len(request):
            _fail()
        response, descriptor = _receive_packet(connection, require_descriptor=False)
        if descriptor is not None:
            _fail()
    state_version, payload = _validate_envelope(
        response, operation="vault.status", state_version=None
    )
    if set(payload) != {"vaultState", "deviceId"}:
        _fail()
    device_id = payload.get("deviceId")
    if (
        payload.get("vaultState") != "unlocked"
        or type(device_id) is not str
        or DEVICE_ID.fullmatch(device_id) is None
    ):
        _fail()
    return state_version


def _shipping_executor_status() -> None:
    request = json.dumps(
        {
            "apiVersion": PROVIDER_API_VERSION,
            "requestId": "O-4c819593-60dd-4eca-8bcc-9e684520892f",
            "operation": "provider.status",
            "payload": {},
        },
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("ascii") + b"\n"
    connection = socket.socket(
        socket.AF_UNIX,
        socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC,
    )
    received_fds: list[int] = []
    try:
        connection.settimeout(IO_TIMEOUT_SECONDS)
        connection.connect(PROVIDER_SOCKET)
        _peer_is_root(connection)
        if connection.send(request) != len(request):
            _fail()
        data, ancillary, flags, _address = connection.recvmsg(
            MAX_PROVIDER_RESPONSE_BYTES + 1,
            socket.CMSG_SPACE(array.array("i").itemsize),
            getattr(socket, "MSG_CMSG_CLOEXEC", 0),
        )
        for level, kind, value in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                descriptors = array.array("i")
                usable = len(value) - (len(value) % descriptors.itemsize)
                descriptors.frombytes(value[:usable])
                received_fds.extend(descriptors.tolist())
        if (
            len(data) < 3
            or len(data) > MAX_PROVIDER_RESPONSE_BYTES
            or data[-1:] != b"\n"
            or data[:1] != b"{"
            or data[-2:-1] != b"}"
            or b"\n" in data[:-1]
            or b"\r" in data
            or ancillary
            or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
        ):
            _fail()
        response = _closed_json(data[:-1])
        if set(response) != {
            "apiVersion",
            "requestId",
            "operation",
            "ok",
            "payload",
        }:
            _fail()
        if (
            response.get("apiVersion") != PROVIDER_API_VERSION
            or response.get("requestId")
            != "O-4c819593-60dd-4eca-8bcc-9e684520892f"
            or response.get("operation") != "provider.status"
            or response.get("ok") is not True
        ):
            _fail()
        payload = response.get("payload")
        if type(payload) is not dict or payload != {
            "provider": "openai",
            "profile": "rescue-default",
            "vault": "unlocked",
            "credential": "configured",
        }:
            _fail()
    finally:
        for descriptor in received_fds:
            try:
                os.close(descriptor)
            except OSError:
                pass
        connection.close()


def _borrow(state_version: int) -> tuple[socket.socket, int, int]:
    connection = _connect_vault()
    descriptor: int | None = None
    try:
        request = _request("provider.openai.borrow", state_version)
        if connection.send(request) != len(request):
            _fail()
        response, descriptor = _receive_packet(connection, require_descriptor=True)
        observed_version, payload = _validate_envelope(
            response,
            operation="provider.openai.borrow",
            state_version=state_version,
        )
        if observed_version != state_version or set(payload) != {"output"}:
            _fail()
        output = payload.get("output")
        if type(output) is not dict or set(output) != {"type", "size"}:
            _fail()
        declared_size = _exact_integer(
            output.get("size"), minimum=1, maximum=MAX_OPENAI_KEY_BYTES
        )
        if output.get("type") != "openai-api-key-pipe" or descriptor is None:
            _fail()
        return connection, descriptor, declared_size
    except BaseException:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        connection.close()
        raise


def _pipe_filesystem_type(descriptor: int) -> int:
    filesystem = LinuxStatFs()
    ctypes.set_errno(0)
    if LIBC.fstatfs(descriptor, ctypes.byref(filesystem)) != 0:
        _fail()
    return int(filesystem.f_type)


def _validate_unread_pipe(descriptor: int, declared_size: int) -> None:
    metadata = os.fstat(descriptor)
    status_flags = fcntl.fcntl(descriptor, fcntl.F_GETFL)
    descriptor_flags = fcntl.fcntl(descriptor, fcntl.F_GETFD)
    if (
        not stat.S_ISFIFO(metadata.st_mode)
        or metadata.st_size != 0
        or _pipe_filesystem_type(descriptor) != PIPEFS_MAGIC
        or status_flags != os.O_NONBLOCK
        or descriptor_flags != fcntl.FD_CLOEXEC
    ):
        _fail()

    deadline = time.monotonic() + IO_TIMEOUT_SECONDS
    poller = select.poll()
    poller.register(descriptor, select.POLLIN | select.POLLHUP | select.POLLERR)
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            _fail()
        events = poller.poll(max(1, int(remaining * 1000)))
        if not events:
            _fail()
        if len(events) != 1 or events[0][0] != descriptor:
            _fail()
        observed = events[0][1]
        if observed & (select.POLLERR | select.POLLNVAL):
            _fail()
        if observed & select.POLLHUP:
            break

    available = array.array("i", [0])
    fcntl.ioctl(descriptor, FIONREAD, available, True)
    if available[0] != declared_size:
        _fail()


def _read_command(control: socket.socket) -> bytes:
    control.settimeout(3.0)
    command = bytearray()
    while True:
        chunk = control.recv(8)
        if not chunk:
            break
        command.extend(chunk)
        if len(command) > len(NORMAL_COMMAND):
            _fail()
    value = bytes(command)
    command[:] = b"\x00" * len(command)
    if value not in {NORMAL_COMMAND, HOLD_COMMAND, STATUS_COMMAND}:
        _fail()
    return value


def _command_socket() -> socket.socket:
    control = socket.socket(fileno=0)
    try:
        if control.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM:
            _fail()
        pid, uid, _gid = struct.unpack(
            "3i", control.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        )
        if pid <= 0 or uid != 1000:
            _fail()
        return control
    except BaseException:
        control.close()
        raise


def _trigger_vault_kill() -> socket.socket:
    trigger = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM | socket.SOCK_CLOEXEC)
    try:
        trigger.settimeout(3.0)
        trigger.connect(KILL_SOCKET)
        _peer_is_root(trigger)
        return trigger
    except BaseException:
        trigger.close()
        raise


def run() -> int:
    control = _command_socket()
    lease: socket.socket | None = None
    key_pipe: int | None = None
    trigger: socket.socket | None = None
    try:
        command = _read_command(control)
        if command == STATUS_COMMAND:
            _shipping_executor_status()
            control.sendall(STATUS_RESULT)
            return 0
        state_version = _observe_unlocked()
        lease, key_pipe, declared_size = _borrow(state_version)
        _validate_unread_pipe(key_pipe, declared_size)
        control.sendall(NORMAL_RESULT if command == NORMAL_COMMAND else HOLD_RESULT)
        if command == HOLD_COMMAND:
            # Give the serial controller one fixed, bounded observation window
            # after the success frame and before the root-only kill trigger.
            time.sleep(15.0)
            trigger = _trigger_vault_kill()
            while True:
                signal.pause()
        return 0
    finally:
        if trigger is not None:
            trigger.close()
        if key_pipe is not None:
            try:
                os.close(key_pipe)
            except OSError:
                pass
        if lease is not None:
            lease.close()
        control.close()


def main() -> int:
    try:
        return run()
    except BaseException:
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
