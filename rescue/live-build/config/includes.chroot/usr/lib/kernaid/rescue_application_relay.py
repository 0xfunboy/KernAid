#!/usr/bin/python3
"""Closed Rescue Application relay between the loopback UI and vaultd.

The accepted socket identifies the UI process.  The relay itself runs under
the dedicated ``kernaid-application`` account, so vaultd can mint the
Application role from SO_PEERCRED instead of trusting a role in JSON.
"""

from __future__ import annotations

import array
import ctypes
import fcntl
import hashlib
import hmac
import json
import os
import re
import select
import socket
import stat
import struct
import threading
import time
import uuid


RELAY_API_VERSION = "kernaid.dev/rescue-application-relay/v1alpha1"
VAULT_API_VERSION = "kernaid.dev/rescue-vault/v1alpha1"
APPLICATION_SOCKET = "/run/kernaid-rescue-application.sock"
VAULT_SOCKET = "/run/kernaid-rescue-vault.sock"
MAX_FRAME_BYTES = 64 * 1024
MAX_REPORT_BYTES = 1024 * 1024
MAX_ENVELOPE_BYTES = 1536 * 1024
MAX_STATE_VERSION = 9_007_199_254_740_991
MAX_AUDIT_SEQUENCE = 1_000_000
PIPEFS_MAGIC = 0x5049_5045
IO_TIMEOUT_SECONDS = 20
REPORT_ID = re.compile(
    r"^RP-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
SHA256 = re.compile(r"^[0-9a-f]{64}$")
DEVICE_ID = re.compile(r"^KA-[0-9a-f]{24}$")
SESSION_ID = re.compile(r"^S-[A-Za-z0-9-]+$")
TARGET_FINGERPRINT = re.compile(r"^sha256:[a-f0-9]{64}$")
AUDIT_EVENTS = {
    "agent-session-start",
    "agent-diagnosis-complete",
    "agent-session-end",
}
AUDIT_OUTCOMES = {"succeeded", "rejected", "failed"}
VAULT_STATES = {
    "absent",
    "unprovisioned",
    "locked",
    "unlocking",
    "unlocked",
    "locking",
    "faulted-reboot-required",
}
VAULT_ERRORS = {
    "ABSENT",
    "UNPROVISIONED",
    "LOCKED",
    "BAD_PASSPHRASE",
    "MEDIA_CHANGED",
    "PROFILE_MISMATCH",
    "STALE_STATE",
    "FD_REQUIRED",
    "FD_FORBIDDEN",
    "NOT_AUTHORIZED",
    "RATE_LIMITED",
    "BUSY",
    "PROVIDER_UNCONFIGURED",
    "REPORT_TOO_LARGE",
    "IO_FAILED",
    "REBOOT_REQUIRED",
}


class RelayFailure(Exception):
    """A closed failure token safe to return to the loopback bridge."""

    def __init__(self, token: str, state_version: int | None = None) -> None:
        super().__init__(token)
        self.token = token
        self.state_version = state_version


class _StatFs(ctypes.Structure):
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


_LIBC = ctypes.CDLL(None, use_errno=True)
_LIBC.fstatfs.argtypes = (ctypes.c_int, ctypes.POINTER(_StatFs))
_LIBC.fstatfs.restype = ctypes.c_int


def _reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON member")
        result[key] = value
    return result


def _strict_object(payload: bytes, maximum: int) -> dict[str, object]:
    if not 2 <= len(payload) <= maximum:
        raise ValueError("invalid JSON object framing")
    value = json.loads(
        payload.decode("utf-8", errors="strict"),
        object_pairs_hook=_reject_duplicates,
        parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("constant")),
    )
    if not isinstance(value, dict):
        raise ValueError("JSON value is not an object")
    return value


def _preliminary_session_report(value: dict[str, object]) -> None:
    if set(value) != {
        "schemaVersion",
        "sessionId",
        "targetFingerprint",
        "facts",
        "inferences",
        "decisions",
        "events",
        "verification",
        "unresolvedRisks",
    }:
        raise RelayFailure("INVALID_REQUEST")
    session_id = value.get("sessionId")
    target = value.get("targetFingerprint")
    facts = value.get("facts")
    inferences = value.get("inferences")
    decisions = value.get("decisions")
    events = value.get("events")
    risks = value.get("unresolvedRisks")
    if (
        value.get("schemaVersion") != "1.0"
        or not isinstance(session_id, str)
        or len(session_id) > 128
        or SESSION_ID.fullmatch(session_id) is None
        or not isinstance(target, str)
        or TARGET_FINGERPRINT.fullmatch(target) is None
        or not isinstance(facts, list)
        or len(facts) > 128
        or not all(isinstance(item, dict) for item in facts)
        or not isinstance(inferences, list)
        or len(inferences) > 128
        or not all(isinstance(item, dict) for item in inferences)
        or not isinstance(decisions, list)
        or len(decisions) > 128
        or not all(isinstance(item, dict) for item in decisions)
        or not isinstance(events, list)
        or len(events) > 1024
        or not all(isinstance(item, dict) for item in events)
        or not isinstance(value.get("verification"), str)
        or value.get("verification") not in {"not-run", "passed", "failed"}
        or not isinstance(risks, list)
        or len(risks) > 128
        or not all(isinstance(item, str) and len(item) <= 8192 for item in risks)
        or len(set(risks)) != len(risks)
    ):
        raise RelayFailure("INVALID_REQUEST")


def _valid_state_version(value: object) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 <= value <= MAX_STATE_VERSION
    )


def _validate_ui_peer(connection: socket.socket) -> None:
    """Authenticate the kernel-gated client without trusting request JSON.

    The root-owned listener admits only members of the otherwise empty
    ``kernaid-application-client`` group.  systemd adds that group only to the
    DynamicUser HTTP service; SO_PEERCRED additionally rejects root and proves
    that this record came from a live, non-privileged local process.
    """
    try:
        credentials = connection.getsockopt(
            socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
        )
        pid, uid, _gid = struct.unpack("3i", credentials)
        socket_type = connection.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE)
        local = connection.getsockname()
    except (OSError, struct.error) as error:
        raise RelayFailure("PEER_NOT_AUTHORIZED") from error
    if (
        connection.family != socket.AF_UNIX
        or socket_type != socket.SOCK_SEQPACKET
        or local != APPLICATION_SOCKET
        or pid <= 0
        or uid == 0
    ):
        raise RelayFailure("PEER_NOT_AUTHORIZED")


def _validate_root_vault_peer(connection: socket.socket) -> None:
    try:
        credentials = connection.getsockopt(
            socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
        )
        pid, uid, gid = struct.unpack("3i", credentials)
        socket_type = connection.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE)
        peer = connection.getpeername()
    except (OSError, struct.error) as error:
        raise RelayFailure("VAULT_UNAVAILABLE") from error
    if (
        connection.family != socket.AF_UNIX
        or socket_type != socket.SOCK_SEQPACKET
        or peer != VAULT_SOCKET
        or pid <= 0
        or uid != 0
        or gid != 0
    ):
        raise RelayFailure("VAULT_UNAVAILABLE")


def _received_record(
    connection: socket.socket, maximum: int
) -> tuple[bytes, list[int]]:
    flags = getattr(socket, "MSG_CMSG_CLOEXEC", 0)
    payload, ancillary, message_flags, _address = connection.recvmsg(
        maximum + 1, socket.CMSG_SPACE(array.array("i", [0, 0]).itemsize * 2), flags
    )
    if (
        not payload
        or len(payload) > maximum
        or message_flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
    ):
        raise RelayFailure("INVALID_FRAME")
    descriptors: list[int] = []
    for level, kind, data in ancillary:
        if level != socket.SOL_SOCKET or kind != socket.SCM_RIGHTS:
            for descriptor in descriptors:
                os.close(descriptor)
            raise RelayFailure("INVALID_FRAME")
        values = array.array("i")
        usable = len(data) - (len(data) % values.itemsize)
        values.frombytes(data[:usable])
        descriptors.extend(values.tolist())
    if len(descriptors) > 1:
        for descriptor in descriptors:
            os.close(descriptor)
        raise RelayFailure("INVALID_FRAME")
    for descriptor in descriptors:
        fcntl.fcntl(descriptor, fcntl.F_SETFD, fcntl.FD_CLOEXEC)
    return payload, descriptors


def _send_record(connection: socket.socket, payload: bytes, descriptor: int | None = None) -> None:
    ancillary: list[tuple[int, int, bytes]] = []
    if descriptor is not None:
        rights = array.array("i", [descriptor])
        ancillary.append((socket.SOL_SOCKET, socket.SCM_RIGHTS, rights.tobytes()))
    sent = connection.sendmsg([payload], ancillary, getattr(socket, "MSG_NOSIGNAL", 0))
    if sent != len(payload):
        raise RelayFailure("TRANSPORT")


def _validate_read_pipe(descriptor: int) -> None:
    metadata = os.fstat(descriptor)
    filesystem = _StatFs()
    if _LIBC.fstatfs(descriptor, ctypes.byref(filesystem)) != 0:
        raise RelayFailure("INVALID_FRAME")
    status_flags = fcntl.fcntl(descriptor, fcntl.F_GETFL)
    descriptor_flags = fcntl.fcntl(descriptor, fcntl.F_GETFD)
    if (
        not stat.S_ISFIFO(metadata.st_mode)
        or filesystem.f_type != PIPEFS_MAGIC
        or metadata.st_size != 0
        or status_flags & os.O_ACCMODE != os.O_RDONLY
        or not descriptor_flags & fcntl.FD_CLOEXEC
    ):
        raise RelayFailure("INVALID_FRAME")


def _read_exact_pipe(descriptor: int, size: int, deadline: float) -> bytes:
    _validate_read_pipe(descriptor)
    os.set_blocking(descriptor, False)
    retained = bytearray()
    while len(retained) < size:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RelayFailure("TIMEOUT")
        readable, _writable, _errors = select.select([descriptor], [], [], remaining)
        if not readable:
            raise RelayFailure("TIMEOUT")
        block = os.read(descriptor, min(64 * 1024, size - len(retained)))
        if not block:
            raise RelayFailure("INVALID_FRAME")
        retained.extend(block)
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RelayFailure("TIMEOUT")
        readable, _writable, _errors = select.select([descriptor], [], [], remaining)
        if not readable:
            raise RelayFailure("TIMEOUT")
        extra = os.read(descriptor, 1)
        if not extra:
            break
        raise RelayFailure("INVALID_FRAME")
    return bytes(retained)


def _write_pipe(descriptor: int, payload: bytes, deadline: float, failure: list[bool]) -> None:
    try:
        os.set_blocking(descriptor, False)
        offset = 0
        while offset < len(payload):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError
            _readable, writable, _errors = select.select([], [descriptor], [], remaining)
            if not writable:
                raise TimeoutError
            offset += os.write(descriptor, payload[offset : offset + 64 * 1024])
    except (OSError, TimeoutError):
        failure.append(True)
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass


def _report_summary(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != {
        "reportId",
        "envelopeSize",
        "envelopeSha256",
    }:
        raise RelayFailure("VAULT_INVALID_RESPONSE")
    report_id = value.get("reportId")
    envelope_size = value.get("envelopeSize")
    envelope_sha256 = value.get("envelopeSha256")
    if (
        not isinstance(report_id, str)
        or REPORT_ID.fullmatch(report_id) is None
        or not isinstance(envelope_size, int)
        or isinstance(envelope_size, bool)
        or not 2 <= envelope_size <= MAX_ENVELOPE_BYTES
        or not isinstance(envelope_sha256, str)
        or SHA256.fullmatch(envelope_sha256) is None
    ):
        raise RelayFailure("VAULT_INVALID_RESPONSE")
    return value


def _validate_local_request(
    request: dict[str, object], descriptor_count: int
) -> tuple[str, int, dict[str, object]]:
    if set(request) != {"apiVersion", "operation", "expectedStateVersion", "payload"}:
        raise RelayFailure("INVALID_REQUEST")
    if request.get("apiVersion") != RELAY_API_VERSION:
        raise RelayFailure("INVALID_REQUEST")
    operation = request.get("operation")
    expected = request.get("expectedStateVersion")
    payload = request.get("payload")
    if (
        not isinstance(operation, str)
        or operation
        not in {"vault.status", "audit.append", "report.persist", "report.list", "report.get"}
        or not _valid_state_version(expected)
        or not isinstance(payload, dict)
    ):
        raise RelayFailure("INVALID_REQUEST")
    if operation in {"vault.status", "report.list"}:
        valid = not payload and descriptor_count == 0
    elif operation == "report.get":
        valid = (
            set(payload) == {"reportId"}
            and isinstance(payload.get("reportId"), str)
            and REPORT_ID.fullmatch(str(payload["reportId"])) is not None
            and descriptor_count == 0
        )
    elif operation == "audit.append":
        outcome = payload.get("outcome")
        error = payload.get("error")
        valid = (
            set(payload)
            in (
                {"sequence", "event", "outcome"},
                {"sequence", "event", "outcome", "error"},
            )
            and isinstance(payload.get("sequence"), int)
            and not isinstance(payload.get("sequence"), bool)
            and 1 <= int(payload["sequence"]) <= MAX_AUDIT_SEQUENCE
            and isinstance(payload.get("event"), str)
            and payload.get("event") in AUDIT_EVENTS
            and isinstance(outcome, str)
            and outcome in AUDIT_OUTCOMES
            and (
                (outcome == "succeeded" and "error" not in payload)
                or (
                    outcome != "succeeded"
                    and isinstance(error, str)
                    and error in VAULT_ERRORS
                )
            )
            and descriptor_count == 0
        )
    else:
        input_value = payload.get("input")
        valid = (
            set(payload) == {"reportId", "payloadSha256", "input"}
            and isinstance(payload.get("reportId"), str)
            and REPORT_ID.fullmatch(str(payload["reportId"])) is not None
            and isinstance(payload.get("payloadSha256"), str)
            and SHA256.fullmatch(str(payload["payloadSha256"])) is not None
            and isinstance(input_value, dict)
            and set(input_value) == {"type", "size"}
            and input_value.get("type") == "session-report-json-pipe"
            and isinstance(input_value.get("size"), int)
            and not isinstance(input_value.get("size"), bool)
            and 2 <= int(input_value["size"]) <= MAX_REPORT_BYTES
            and descriptor_count == 1
        )
    if not valid:
        raise RelayFailure("INVALID_REQUEST")
    return str(operation), int(expected), payload


def _vault_exchange(
    operation: str,
    expected: int,
    payload: dict[str, object],
    input_descriptor: int | None,
    deadline: float,
) -> tuple[int, dict[str, object], int | None]:
    request_id = f"R-{uuid.uuid4()}"
    frame = json.dumps(
        {
            "apiVersion": VAULT_API_VERSION,
            "requestId": request_id,
            "expectedStateVersion": expected,
            "operation": operation,
            "payload": payload,
        },
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
    output_descriptor: int | None = None
    try:
        connection.settimeout(max(0.1, deadline - time.monotonic()))
        connection.connect(VAULT_SOCKET)
        _validate_root_vault_peer(connection)
        _send_record(connection, frame, input_descriptor)
        response_bytes, descriptors = _received_record(connection, MAX_FRAME_BYTES)
        if len(descriptors) == 1:
            output_descriptor = descriptors[0]
        try:
            response = _strict_object(response_bytes, MAX_FRAME_BYTES)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
            if output_descriptor is not None:
                os.close(output_descriptor)
                output_descriptor = None
            raise RelayFailure("VAULT_INVALID_RESPONSE") from error
    except socket.timeout as error:
        raise RelayFailure("TIMEOUT") from error
    except OSError as error:
        raise RelayFailure("VAULT_UNAVAILABLE") from error
    finally:
        connection.close()

    required = {"apiVersion", "requestId", "stateVersion", "operation", "outcome"}
    if (
        response.get("apiVersion") != VAULT_API_VERSION
        or response.get("requestId") != request_id
        or response.get("operation") != operation
        or not _valid_state_version(response.get("stateVersion"))
        or not isinstance(response.get("outcome"), str)
        or response.get("outcome") not in {"ok", "error"}
    ):
        if output_descriptor is not None:
            os.close(output_descriptor)
        raise RelayFailure("VAULT_INVALID_RESPONSE")
    state_version = int(response["stateVersion"])
    if response["outcome"] == "error":
        if (
            set(response) != required | {"error"}
            or not isinstance(response.get("error"), str)
            or response.get("error") not in VAULT_ERRORS
            or output_descriptor is not None
        ):
            if output_descriptor is not None:
                os.close(output_descriptor)
            raise RelayFailure("VAULT_INVALID_RESPONSE")
        raise RelayFailure(str(response["error"]), state_version)
    if set(response) != required | {"payload"} or not isinstance(
        response.get("payload"), dict
    ):
        if output_descriptor is not None:
            os.close(output_descriptor)
        raise RelayFailure("VAULT_INVALID_RESPONSE")
    return state_version, response["payload"], output_descriptor


def _perform(
    operation: str,
    expected: int,
    payload: dict[str, object],
    descriptors: list[int],
    deadline: float,
) -> tuple[dict[str, object], int | None]:
    input_descriptor: int | None = descriptors[0] if descriptors else None
    writer: threading.Thread | None = None
    writer_failure: list[bool] = []
    relay_read = -1
    if operation == "report.persist":
        assert input_descriptor is not None
        report_size = int(dict(payload["input"])["size"])
        exact_report = _read_exact_pipe(input_descriptor, report_size, deadline)
        expected_hash = str(payload["payloadSha256"])
        if not hmac.compare_digest(hashlib.sha256(exact_report).hexdigest(), expected_hash):
            raise RelayFailure("INVALID_REQUEST")
        try:
            report = _strict_object(exact_report, MAX_REPORT_BYTES)
            _preliminary_session_report(report)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
            raise RelayFailure("INVALID_REQUEST") from error
        relay_read, relay_write = os.pipe2(os.O_CLOEXEC)
        writer = threading.Thread(
            target=_write_pipe,
            args=(relay_write, exact_report, deadline, writer_failure),
            daemon=True,
        )
        writer.start()
        input_descriptor = relay_read

    try:
        state_version, vault_payload, output_descriptor = _vault_exchange(
            operation, expected, payload, input_descriptor, deadline
        )
    finally:
        if relay_read >= 0:
            os.close(relay_read)
        if writer is not None:
            writer.join(timeout=max(0.0, deadline - time.monotonic()))

    if writer_failure or (writer is not None and writer.is_alive()):
        if output_descriptor is not None:
            os.close(output_descriptor)
        raise RelayFailure("TRANSPORT")

    if operation == "vault.status":
        vault_state = vault_payload.get("vaultState")
        valid = (
            isinstance(vault_state, str)
            and set(vault_payload) == {"vaultState"}
            and vault_state in VAULT_STATES - {"unlocked"}
        )
        if vault_state == "unlocked":
            valid = (
                set(vault_payload) == {"vaultState", "deviceId"}
                and isinstance(vault_payload.get("deviceId"), str)
                and DEVICE_ID.fullmatch(str(vault_payload["deviceId"])) is not None
            )
        if not valid or output_descriptor is not None:
            if output_descriptor is not None:
                os.close(output_descriptor)
            raise RelayFailure("VAULT_INVALID_RESPONSE")
    elif operation == "audit.append":
        valid = (
            set(vault_payload) == {"sequence"}
            and vault_payload.get("sequence") == payload.get("sequence")
            and output_descriptor is None
        )
        if not valid:
            if output_descriptor is not None:
                os.close(output_descriptor)
            raise RelayFailure("VAULT_INVALID_RESPONSE")
    elif operation == "report.persist":
        _report_summary(vault_payload)
        if (
            vault_payload.get("reportId") != payload.get("reportId")
            or output_descriptor is not None
        ):
            if output_descriptor is not None:
                os.close(output_descriptor)
            raise RelayFailure("VAULT_INVALID_RESPONSE")
    elif operation == "report.list":
        reports = vault_payload.get("reports")
        if (
            set(vault_payload) != {"reports"}
            or not isinstance(reports, list)
            or len(reports) > 256
            or output_descriptor is not None
        ):
            if output_descriptor is not None:
                os.close(output_descriptor)
            raise RelayFailure("VAULT_INVALID_RESPONSE")
        seen: set[str] = set()
        for report in reports:
            summary = _report_summary(report)
            report_id = str(summary["reportId"])
            if report_id in seen:
                raise RelayFailure("VAULT_INVALID_RESPONSE")
            seen.add(report_id)
    else:
        report = vault_payload.get("report")
        output = vault_payload.get("output")
        summary = _report_summary(report)
        if (
            set(vault_payload) != {"report", "output"}
            or summary.get("reportId") != payload.get("reportId")
            or not isinstance(output, dict)
            or set(output) != {"type", "size"}
            or output.get("type") != "signed-report-envelope-pipe"
            or output.get("size") != summary.get("envelopeSize")
            or output_descriptor is None
        ):
            if output_descriptor is not None:
                os.close(output_descriptor)
            raise RelayFailure("VAULT_INVALID_RESPONSE")
        _validate_read_pipe(output_descriptor)

    return {
        "apiVersion": RELAY_API_VERSION,
        "operation": operation,
        "outcome": "ok",
        "stateVersion": state_version,
        "payload": vault_payload,
    }, output_descriptor


def _encoded(value: dict[str, object]) -> bytes:
    payload = json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("ascii")
    if len(payload) > MAX_FRAME_BYTES:
        raise RelayFailure("VAULT_INVALID_RESPONSE")
    return payload


def _handle_connection(connection: socket.socket) -> None:
    fcntl.fcntl(connection.fileno(), fcntl.F_SETFD, fcntl.FD_CLOEXEC)
    descriptors: list[int] = []
    output_descriptor: int | None = None
    operation: str | None = None
    try:
        _validate_ui_peer(connection)
        request_bytes, descriptors = _received_record(connection, MAX_FRAME_BYTES)
        request = _strict_object(request_bytes, MAX_FRAME_BYTES)
        operation, expected, payload = _validate_local_request(request, len(descriptors))
        response, output_descriptor = _perform(
            operation,
            expected,
            payload,
            descriptors,
            time.monotonic() + IO_TIMEOUT_SECONDS,
        )
        _send_record(connection, _encoded(response), output_descriptor)
        return
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        failure = RelayFailure("INVALID_REQUEST")
    except OSError:
        failure = RelayFailure("TRANSPORT")
    except RelayFailure as error:
        failure = error
    finally:
        for descriptor in descriptors:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if output_descriptor is not None:
            try:
                os.close(output_descriptor)
            except OSError:
                pass

    # Peer-authentication failures are close-only.  Once authenticated, every
    # reflected value comes from a closed enum, never from peer text.
    if failure.token == "PEER_NOT_AUTHORIZED":
        return
    response: dict[str, object] = {
        "apiVersion": RELAY_API_VERSION,
        "outcome": "error",
        "error": failure.token,
    }
    if operation is not None:
        response["operation"] = operation
    if failure.state_version is not None:
        response["stateVersion"] = failure.state_version
    try:
        _send_record(connection, _encoded(response))
    except (OSError, RelayFailure):
        pass


def _systemd_listener() -> socket.socket:
    try:
        listen_pid = int(os.environ.get("LISTEN_PID", "0"))
        listen_fds = int(os.environ.get("LISTEN_FDS", "0"))
    except ValueError as error:
        raise RelayFailure("INVALID_LISTENER") from error
    if (
        listen_pid != os.getpid()
        or listen_fds != 1
        or os.environ.get("LISTEN_FDNAMES") != "application"
    ):
        raise RelayFailure("INVALID_LISTENER")
    listener = socket.socket(fileno=3)
    fcntl.fcntl(listener.fileno(), fcntl.F_SETFD, fcntl.FD_CLOEXEC)
    try:
        socket_type = listener.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE)
        accepting = listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)
        local = listener.getsockname()
    except OSError as error:
        listener.close()
        raise RelayFailure("INVALID_LISTENER") from error
    if (
        listener.family != socket.AF_UNIX
        or socket_type != socket.SOCK_SEQPACKET
        or accepting != 1
        or local != APPLICATION_SOCKET
    ):
        listener.close()
        raise RelayFailure("INVALID_LISTENER")
    return listener


def main() -> int:
    try:
        listener = _systemd_listener()
    except RelayFailure:
        return 1
    with listener:
        while True:
            try:
                connection, _address = listener.accept()
            except InterruptedError:
                continue
            except OSError:
                return 1
            with connection:
                connection.settimeout(IO_TIMEOUT_SECONDS)
                _handle_connection(connection)


if __name__ == "__main__":
    raise SystemExit(main())
