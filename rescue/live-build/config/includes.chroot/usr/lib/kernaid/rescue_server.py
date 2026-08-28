#!/usr/bin/python3
"""Loopback-only static UI and fixed, read-only inventory bridge for KernAid Rescue."""

from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from concurrent.futures import ThreadPoolExecutor
import array
import fcntl
import hashlib
import hmac
import json
import os
import re
import select
import signal
import socket
import stat
import struct
import subprocess
import threading
import time

MAX_OUTPUT_BYTES = 64 * 1024
COLLECTOR_TIMEOUT_SECONDS = 15
COLLECTOR_KILL_GRACE_SECONDS = 2
WEB_ROOT = "/opt/kernaid/desk"
COMMANDS = (
    ("system.hostname", ("/usr/bin/hostname",)),
    (
        "linux.hardware.inventory",
        ("/usr/lib/kernaid/kernaid-linux-hardware-inventory",),
    ),
    (
        "linux.block.inventory",
        (
            "/usr/bin/lsblk",
            "--json",
            "--bytes",
            "--output",
            "NAME,TYPE,SIZE,RO,FSTYPE,MOUNTPOINTS,SERIAL,WWN,UUID,PARTUUID,PTUUID",
        ),
    ),
    ("linux.network.links", ("/usr/sbin/ip", "-json", "link")),
    ("linux.systemd.failed", ("/usr/bin/systemctl", "--failed", "--no-pager", "--plain")),
    ("linux.systemd.state", ("/usr/bin/systemctl", "show", "--property=SystemState", "--no-pager")),
    ("linux.df", ("/usr/bin/df", "--block-size=1", "--portability")),
    ("linux.network.routes", ("/usr/sbin/ip", "-json", "route")),
    ("linux.dpkg.audit", ("/usr/bin/dpkg", "--audit")),
)
TARGET_SCAN_COMMAND = (
    "/usr/bin/lsblk",
    "--json",
    "--bytes",
    "--tree",
    "--output",
    (
        "NAME,MAJ:MIN,TYPE,SIZE,RO,RM,TRAN,FSTYPE,FSVER,MOUNTPOINTS,UUID,PARTUUID,"
        "PTUUID,PTTYPE,PARTTYPE,SERIAL,WWN"
    ),
)
MAX_REQUEST_BYTES = 8 * 1024
MAX_BROKER_SESSIONS = 1_024
MAX_SERVER_THREADS = 8
SOCKET_TIMEOUT_SECONDS = 5
REQUEST_DEADLINE_SECONDS = 30
AUTHORIZE_DEADLINE_SECONDS = 18
PROVIDER_REQUEST_DEADLINE_SECONDS = 142
PROVIDER_SOCKET_TIMEOUT_SECONDS = 140
PROVIDER_SOCKET = "/run/kernaid-rescue-openai.sock"
MAX_PROVIDER_REQUEST_FRAME_BYTES = 96 * 1024
MAX_PROVIDER_RESPONSE_FRAME_BYTES = 64 * 1024
APPLICATION_HTTP_API_VERSION = "kernaid.dev/rescue-application-http/v1alpha1"
APPLICATION_RELAY_API_VERSION = "kernaid.dev/rescue-application-relay/v1alpha1"
APPLICATION_RELAY_SOCKET = "/run/kernaid-rescue-application.sock"
MAX_APPLICATION_RELAY_FRAME_BYTES = 64 * 1024
MAX_APPLICATION_REPORT_BYTES = 1024 * 1024
MAX_APPLICATION_ENVELOPE_BYTES = 1536 * 1024
# reportJson is an exact JSON string, so quotes and escapes can make the HTTP
# wrapper larger than the decoded report bytes.  The decoded UTF-8 domain is
# still capped independently at one MiB before any pipe is created.
MAX_APPLICATION_HTTP_REQUEST_BYTES = 2_097_664
APPLICATION_REQUEST_DEADLINE_SECONDS = 28
MAX_STATE_VERSION = 9_007_199_254_740_991
MAX_AUDIT_SEQUENCE = 1_000_000
APPLICATION_REPORT_ID = re.compile(
    r"^RP-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
APPLICATION_SHA256 = re.compile(r"^[0-9a-f]{64}$")
APPLICATION_SESSION_ID = re.compile(r"^S-[A-Za-z0-9-]+$")
APPLICATION_TARGET_FINGERPRINT = re.compile(r"^sha256:[a-f0-9]{64}$")
APPLICATION_AUDIT_EVENTS = {
    "agent-session-start",
    "agent-diagnosis-complete",
    "agent-session-end",
}
APPLICATION_AUDIT_OUTCOMES = {"succeeded", "rejected", "failed"}
APPLICATION_VAULT_ERROR_TOKENS = {
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
APPLICATION_ERROR_TOKENS = {
    *APPLICATION_VAULT_ERROR_TOKENS,
    "INVALID_REQUEST",
    "INVALID_FRAME",
    "VAULT_UNAVAILABLE",
    "VAULT_INVALID_RESPONSE",
    "TIMEOUT",
    "TRANSPORT",
    "RELAY_UNAVAILABLE",
}
MAX_TARGET_DEVICES = 128
MAX_TARGET_DEPTH = 8
MAX_TARGET_FIELD_BYTES = 4 * 1024
MAX_TARGET_RESPONSE_BYTES = 64 * 1024
TARGET_SCAN_API_VERSION = "kernaid.dev/rescue-targets/v1alpha1"
RESCUE_TARGET_FINGERPRINT_DOMAIN = "kernaid-rescue-observe-target-v1"
RECOVERY_TARGET_FINGERPRINT_DOMAIN = b"kernaid-rescue-ext4-recovery-target-v1"
RECOVERY_UUID = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
RECOVERY_DISK_ID = re.compile(r"^[A-Za-z0-9._:+-]{1,128}$")
ALLOWED_HOSTS = {"127.0.0.1:4173", "localhost:4173"}
ALLOWED_ORIGINS = {"http://127.0.0.1:4173", "http://localhost:4173"}
CONTENT_SECURITY_POLICY = (
    "default-src 'none'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    "connect-src 'self'; "
    "manifest-src 'self'; "
    "base-uri 'none'; "
    "form-action 'none'; "
    "frame-ancestors 'none'; "
    "object-src 'none'"
)
TARGET_ID_KEY_FILE = "/run/kernaid-offline-inspector/target-id.key"
PROVIDER_RELAY_LOCK = threading.Lock()


def _load_target_id_key() -> bytes:
    """Load the boot-scoped helper key, or use a process-local UI key."""
    configured = os.environ.get("KERNAID_TARGET_ID_KEY_FILE")
    if configured is None:
        return os.urandom(32)
    if configured != TARGET_ID_KEY_FILE:
        raise RuntimeError("the target identifier key path is not allowed")
    descriptor = os.open(
        configured, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    )
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != 0
            or before.st_gid != 0
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_nlink != 1
            or before.st_size != 32
        ):
            raise RuntimeError("the target identifier key is not a secure file")
        key = os.read(descriptor, 33)
        after = os.fstat(descriptor)
        if (
            len(key) != 32
            or (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
            )
            != (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
            )
        ):
            raise RuntimeError("the target identifier key changed while loading")
        return key
    finally:
        os.close(descriptor)


TARGET_ID_KEY = _load_target_id_key()
TARGET_ID_SCOPE = (
    "ephemeral-rescue-boot"
    if os.environ.get("KERNAID_TARGET_ID_KEY_FILE") == TARGET_ID_KEY_FILE
    else "ephemeral-rescue-process"
)
OFFLINE_HELPER_SOCKET = "/run/kernaid-offline-inspector.sock"
OFFLINE_HELPER_ENABLED = os.environ.get("KERNAID_PRIVILEGED_INSPECTOR") == "1"
OFFLINE_HELPER_TIMEOUT_SECONDS = 20
MAX_OFFLINE_HELPER_RESPONSE_BYTES = 64 * 1024
OFFLINE_INSPECTION_CLAIM_FIELDS = {
    "installedOsConfirmed",
    "filesystemContentInspected",
    "mountOperationAttempted",
    "mountOperationPerformed",
    "mountCleanupVerified",
    "autoUnlockAttempted",
    "mutationPerformed",
    "diagnosisProduced",
    "repairAttempted",
}

TARGET_DEVICE_FIELDS = {
    "name",
    "maj:min",
    "type",
    "size",
    "ro",
    "rm",
    "tran",
    "fstype",
    "fsver",
    "mountpoints",
    "uuid",
    "partuuid",
    "ptuuid",
    "pttype",
    "parttype",
    "serial",
    "wwn",
}
LINUX_FILESYSTEMS = {"btrfs", "ext2", "ext3", "ext4", "f2fs", "xfs"}
WINDOWS_FILESYSTEMS = {"bitlocker", "ntfs"}
MACOS_FILESYSTEMS = {"apfs", "hfs", "hfsplus"}
ENCRYPTED_FILESYSTEMS = {"bitlocker", "crypto_luks"}
LIVE_IMAGE_FILESYSTEMS = {"iso9660", "squashfs", "udf"}
LINUX_ROOT_PARTITION_TYPES = {
    "4f68bce3-e8cd-4db1-96e7-fbcaf984b709",  # x86-64 root
    "44479540-f297-41b2-9af7-d131d5f0458a",  # x86 root
}
EFI_SYSTEM_PARTITION_TYPE = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"
EFI_SYSTEM_FILESYSTEMS = {"fat", "vfat"}
APPLE_APFS_PARTITION_TYPE = "7c3457ef-0000-11aa-aa11-00306543ecac"
OBSERVE_AUTHORIZATION_FIELDS = {
    "sessionId",
    "planId",
    "targetFingerprint",
    "sequence",
    "action",
    "rescueTarget",
}
RESCUE_TARGET_REFERENCE_FIELDS = {"scanFingerprint", "targetId"}
TARGET_CANDIDATE_FIELDS = {
    "targetId",
    "sourceRef",
    "diskId",
    "osFamilyHint",
    "confidence",
    "status",
    "detectionBasis",
    "requiresUnlock",
    "inspectionMode",
    "selectionEligible",
}
TARGET_SELECTION_FIELDS = {
    "apiVersion",
    "status",
    "scanFingerprint",
    "target",
    "claims",
}
TARGET_SELECTION_CLAIM_FIELDS = {
    "installedOsConfirmed",
    "filesystemContentInspected",
    "mountOperationPerformed",
    "mutationPerformed",
}


class BrokerError(Exception):
    """A safe error that can be returned to the local Desk UI."""


class InventoryBusy(Exception):
    """Another bounded inventory collection is already in progress."""


class TargetScanBusy(Exception):
    """Another bounded installed-target scan is already in progress."""


class TargetScanError(Exception):
    """The installed-target metadata could not be normalized safely."""


class TargetSelectionError(Exception):
    """The local target selection request is invalid or stale."""

    def __init__(self, message: str, status: int = 409) -> None:
        super().__init__(message)
        self.status = status


class PrivilegedHelperError(Exception):
    """A typed failure returned by the fixed root inspection service."""

    def __init__(self, error: dict[str, object], status: int) -> None:
        super().__init__(str(error["message"]))
        self.error = error
        self.status = status


class ProviderRelayError(Exception):
    """A closed local-provider transport failure without peer detail."""

    def __init__(self, code: str, status: int) -> None:
        super().__init__(code)
        self.code = code
        self.status = status


class ApplicationRelayError(Exception):
    """A closed Application/vault error safe for the local HTTP response."""

    def __init__(
        self, code: str, status: int, state_version: int | None = None
    ) -> None:
        super().__init__(code)
        self.code = code
        self.status = status
        self.state_version = state_version


def _application_http_status(token: str) -> int:
    if token in {"INVALID_REQUEST", "INVALID_FRAME"}:
        return 400
    if token in {"NOT_AUTHORIZED", "FD_REQUIRED", "FD_FORBIDDEN"}:
        return 403
    if token in {"ABSENT", "UNPROVISIONED", "LOCKED"}:
        return 423
    if token in {"STALE_STATE", "MEDIA_CHANGED", "PROFILE_MISMATCH"}:
        return 409
    if token in {"RATE_LIMITED", "BUSY"}:
        return 429
    if token == "REPORT_TOO_LARGE":
        return 413
    if token == "TIMEOUT":
        return 504
    return 503


def _reject_json_duplicates(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON member")
        result[key] = value
    return result


def _strict_json_object(payload: bytes, maximum: int) -> dict[str, object]:
    if (
        not 2 <= len(payload) <= maximum
    ):
        raise ValueError("invalid JSON object framing")
    value = json.loads(
        payload.decode("utf-8", errors="strict"),
        object_pairs_hook=_reject_json_duplicates,
        parse_constant=lambda _value: (_ for _ in ()).throw(
            ValueError("invalid JSON constant")
        ),
    )
    if not isinstance(value, dict):
        raise ValueError("JSON value is not an object")
    return value


def _preliminary_application_report(value: dict[str, object]) -> None:
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
        raise ApplicationRelayError("INVALID_REQUEST", 400)
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
        or APPLICATION_SESSION_ID.fullmatch(session_id) is None
        or not isinstance(target, str)
        or APPLICATION_TARGET_FINGERPRINT.fullmatch(target) is None
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
        raise ApplicationRelayError("INVALID_REQUEST", 400)


def _valid_application_state_version(value: object) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 <= value <= MAX_STATE_VERSION
    )


def _validate_application_relay_peer(connection: socket.socket) -> None:
    # With Accept=no the root system manager owns the listening endpoint; the
    # long-running unprivileged relay only inherits it and accepts connections.
    # Client-side SO_PEERCRED therefore authenticates PID 1, while vaultd sees
    # the stable kernaid-application PID on the relay's outbound connection.
    try:
        peer = connection.getpeername()
        socket_type = connection.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE)
        credentials = connection.getsockopt(
            socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
        )
        pid, uid, gid = struct.unpack("3i", credentials)
    except (OSError, struct.error) as error:
        raise ApplicationRelayError("RELAY_UNAVAILABLE", 503) from error
    if (
        connection.family != socket.AF_UNIX
        or socket_type != socket.SOCK_SEQPACKET
        or peer != APPLICATION_RELAY_SOCKET
        or pid != 1
        or uid != 0
        or gid != 0
    ):
        raise ApplicationRelayError("RELAY_UNAVAILABLE", 503)


def _application_record(
    connection: socket.socket,
) -> tuple[bytes, list[int]]:
    receive_flags = getattr(socket, "MSG_CMSG_CLOEXEC", 0)
    payload, ancillary, flags, _address = connection.recvmsg(
        MAX_APPLICATION_RELAY_FRAME_BYTES + 1,
        socket.CMSG_SPACE(array.array("i", [0, 0]).itemsize * 2),
        receive_flags,
    )
    if (
        not payload
        or len(payload) > MAX_APPLICATION_RELAY_FRAME_BYTES
        or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
    ):
        raise ApplicationRelayError("INVALID_FRAME", 502)
    descriptors: list[int] = []
    for level, kind, data in ancillary:
        if level != socket.SOL_SOCKET or kind != socket.SCM_RIGHTS:
            for descriptor in descriptors:
                os.close(descriptor)
            raise ApplicationRelayError("INVALID_FRAME", 502)
        values = array.array("i")
        usable = len(data) - len(data) % values.itemsize
        values.frombytes(data[:usable])
        descriptors.extend(values.tolist())
    if len(descriptors) > 1:
        for descriptor in descriptors:
            os.close(descriptor)
        raise ApplicationRelayError("INVALID_FRAME", 502)
    for descriptor in descriptors:
        fcntl.fcntl(descriptor, fcntl.F_SETFD, fcntl.FD_CLOEXEC)
    return payload, descriptors


def _send_application_record(
    connection: socket.socket, payload: bytes, descriptor: int | None
) -> None:
    ancillary: list[tuple[int, int, bytes]] = []
    if descriptor is not None:
        ancillary.append(
            (
                socket.SOL_SOCKET,
                socket.SCM_RIGHTS,
                array.array("i", [descriptor]).tobytes(),
            )
        )
    sent = connection.sendmsg(
        [payload], ancillary, getattr(socket, "MSG_NOSIGNAL", 0)
    )
    if sent != len(payload):
        raise ApplicationRelayError("TRANSPORT", 503)


def relay_application_request(
    operation: str,
    expected_state_version: int,
    payload: dict[str, object],
    deadline: float,
    input_descriptor: int | None = None,
) -> tuple[dict[str, object], int | None]:
    frame = json.dumps(
        {
            "apiVersion": APPLICATION_RELAY_API_VERSION,
            "operation": operation,
            "expectedStateVersion": expected_state_version,
            "payload": payload,
        },
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    if len(frame) > MAX_APPLICATION_RELAY_FRAME_BYTES:
        raise ApplicationRelayError("INVALID_REQUEST", 400)
    connection: socket.socket | None = None
    received_descriptors: list[int] = []
    try:
        connection = socket.socket(
            socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC
        )
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ApplicationRelayError("TIMEOUT", 504)
        connection.settimeout(remaining)
        connection.connect(APPLICATION_RELAY_SOCKET)
        _validate_application_relay_peer(connection)
        _send_application_record(connection, frame, input_descriptor)
        response_bytes, received_descriptors = _application_record(connection)
        try:
            response = _strict_json_object(
                response_bytes, MAX_APPLICATION_RELAY_FRAME_BYTES
            )
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
            raise ApplicationRelayError("INVALID_FRAME", 502) from error
    except socket.timeout as error:
        raise ApplicationRelayError("TIMEOUT", 504) from error
    except ApplicationRelayError:
        for descriptor in received_descriptors:
            os.close(descriptor)
        received_descriptors.clear()
        raise
    except OSError as error:
        raise ApplicationRelayError("RELAY_UNAVAILABLE", 503) from error
    finally:
        if connection is not None:
            connection.close()

    if (
        response.get("apiVersion") != APPLICATION_RELAY_API_VERSION
        or not isinstance(response.get("outcome"), str)
        or response.get("outcome") not in {"ok", "error"}
    ):
        for descriptor in received_descriptors:
            os.close(descriptor)
        raise ApplicationRelayError("INVALID_FRAME", 502)
    if response["outcome"] == "error":
        allowed = {"apiVersion", "outcome", "error", "operation", "stateVersion"}
        code = response.get("error")
        state_version = response.get("stateVersion")
        if (
            not set(response).issubset(allowed)
            or set(response) - {"operation", "stateVersion"}
            != {"apiVersion", "outcome", "error"}
            or not isinstance(code, str)
            or code not in APPLICATION_ERROR_TOKENS
            or (
                "operation" in response
                and response.get("operation") != operation
            )
            or (
                "stateVersion" in response
                and not _valid_application_state_version(state_version)
            )
            or received_descriptors
        ):
            for descriptor in received_descriptors:
                os.close(descriptor)
            raise ApplicationRelayError("INVALID_FRAME", 502)
        raise ApplicationRelayError(
            str(code),
            _application_http_status(str(code)),
            int(state_version) if isinstance(state_version, int) else None,
        )

    if (
        set(response)
        != {"apiVersion", "operation", "outcome", "stateVersion", "payload"}
        or response.get("operation") != operation
        or not _valid_application_state_version(response.get("stateVersion"))
        or not isinstance(response.get("payload"), dict)
        or (operation == "report.get") != (len(received_descriptors) == 1)
    ):
        for descriptor in received_descriptors:
            os.close(descriptor)
        raise ApplicationRelayError("INVALID_FRAME", 502)
    return response, received_descriptors[0] if received_descriptors else None


def _write_application_pipe(
    descriptor: int,
    payload: bytes,
    deadline: float,
    failures: list[bool],
) -> None:
    try:
        os.set_blocking(descriptor, False)
        offset = 0
        while offset < len(payload):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError
            _readable, writable, _errors = select.select(
                [], [descriptor], [], remaining
            )
            if not writable:
                raise TimeoutError
            offset += os.write(
                descriptor, payload[offset : offset + 64 * 1024]
            )
    except (OSError, TimeoutError):
        failures.append(True)
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass


def relay_application_report(
    expected_state_version: int,
    report_id: str,
    payload_sha256: str,
    report_bytes: bytes,
    deadline: float,
) -> dict[str, object]:
    read_descriptor, write_descriptor = os.pipe2(os.O_CLOEXEC)
    failures: list[bool] = []
    writer = threading.Thread(
        target=_write_application_pipe,
        args=(write_descriptor, report_bytes, deadline, failures),
        daemon=True,
    )
    writer.start()
    try:
        response, output = relay_application_request(
            "report.persist",
            expected_state_version,
            {
                "reportId": report_id,
                "payloadSha256": payload_sha256,
                "input": {
                    "type": "session-report-json-pipe",
                    "size": len(report_bytes),
                },
            },
            deadline,
            read_descriptor,
        )
        if output is not None:
            os.close(output)
            raise ApplicationRelayError("INVALID_FRAME", 502)
    finally:
        os.close(read_descriptor)
        writer.join(timeout=max(0.0, deadline - time.monotonic()))
    if writer.is_alive() or failures:
        raise ApplicationRelayError("TRANSPORT", 503)
    return response


def _application_status(deadline: float) -> dict[str, object]:
    response, descriptor = relay_application_request(
        "vault.status", 0, {}, deadline
    )
    if descriptor is not None:
        os.close(descriptor)
        raise ApplicationRelayError("INVALID_FRAME", 502)
    payload = response["payload"]
    vault_state = payload.get("vaultState")
    if not isinstance(vault_state, str) or vault_state not in {
        "absent",
        "unprovisioned",
        "locked",
        "unlocking",
        "unlocked",
        "locking",
        "faulted-reboot-required",
    }:
        raise ApplicationRelayError("INVALID_FRAME", 502)
    return response


def _versioned_application_read(
    operation: str, payload: dict[str, object], deadline: float
) -> tuple[dict[str, object], int | None]:
    # Status is the sole operation that accepts bootstrap zero.  A concurrent
    # vault transition can make the following read stale; retry that closed
    # race once, never a transport or storage failure.
    for attempt in range(2):
        status = _application_status(deadline)
        try:
            return relay_application_request(
                operation, int(status["stateVersion"]), payload, deadline
            )
        except ApplicationRelayError as error:
            if error.code != "STALE_STATE" or attempt != 0:
                raise
    raise ApplicationRelayError("STALE_STATE", 409)


def _read_application_output(
    descriptor: int, size: int, expected_sha256: str, deadline: float
) -> bytes:
    if not 2 <= size <= MAX_APPLICATION_ENVELOPE_BYTES:
        raise ApplicationRelayError("INVALID_FRAME", 502)
    os.set_blocking(descriptor, False)
    retained = bytearray()
    while len(retained) < size:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ApplicationRelayError("TIMEOUT", 504)
        readable, _writable, _errors = select.select(
            [descriptor], [], [], remaining
        )
        if not readable:
            raise ApplicationRelayError("TIMEOUT", 504)
        block = os.read(descriptor, min(64 * 1024, size - len(retained)))
        if not block:
            raise ApplicationRelayError("INVALID_FRAME", 502)
        retained.extend(block)
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ApplicationRelayError("TIMEOUT", 504)
        readable, _writable, _errors = select.select(
            [descriptor], [], [], remaining
        )
        if not readable:
            raise ApplicationRelayError("TIMEOUT", 504)
        extra = os.read(descriptor, 1)
        if not extra:
            break
        raise ApplicationRelayError("INVALID_FRAME", 502)
    exact = bytes(retained)
    if not hmac.compare_digest(hashlib.sha256(exact).hexdigest(), expected_sha256):
        raise ApplicationRelayError("INVALID_FRAME", 502)
    try:
        _strict_json_object(exact, MAX_APPLICATION_ENVELOPE_BYTES)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ApplicationRelayError("INVALID_FRAME", 502) from error
    return exact


def _application_report_summary(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != {
        "reportId",
        "envelopeSize",
        "envelopeSha256",
    }:
        raise ApplicationRelayError("INVALID_FRAME", 502)
    report_id = value.get("reportId")
    envelope_size = value.get("envelopeSize")
    envelope_sha256 = value.get("envelopeSha256")
    if (
        not isinstance(report_id, str)
        or APPLICATION_REPORT_ID.fullmatch(report_id) is None
        or not isinstance(envelope_size, int)
        or isinstance(envelope_size, bool)
        or not 2 <= envelope_size <= MAX_APPLICATION_ENVELOPE_BYTES
        or not isinstance(envelope_sha256, str)
        or APPLICATION_SHA256.fullmatch(envelope_sha256) is None
    ):
        raise ApplicationRelayError("INVALID_FRAME", 502)
    return value


def _validate_provider_frame(
    frame: bytes, maximum: int, oversized_code: str
) -> None:
    if len(frame) > maximum:
        status = 413 if oversized_code == "request_too_large" else 502
        raise ProviderRelayError(oversized_code, status)
    if (
        len(frame) < 3
        or frame[:1] != b"{"
        or frame[-2:] != b"}\n"
        or b"\n" in frame[:-1]
        or b"\r" in frame
    ):
        request_frame = oversized_code == "request_too_large"
        code = "invalid_request" if request_frame else "invalid_response"
        raise ProviderRelayError(code, 400 if request_frame else 502)


def _validate_root_provider_peer(connection: socket.socket) -> None:
    try:
        peer = connection.getpeername()
        socket_type = connection.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE)
        credentials = connection.getsockopt(
            socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
        )
        pid, uid, gid = struct.unpack("3i", credentials)
    except (OSError, struct.error) as error:
        raise ProviderRelayError("transport", 503) from error
    if (
        connection.family != socket.AF_UNIX
        or socket_type != socket.SOCK_SEQPACKET
        or peer != PROVIDER_SOCKET
        or pid <= 0
        or uid != 0
        or gid != 0
    ):
        raise ProviderRelayError("transport", 503)


def _set_provider_socket_deadline(
    connection: socket.socket, deadline: float
) -> None:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ProviderRelayError("timeout", 504)
    connection.settimeout(remaining)


def relay_openai_provider(frame: bytes, deadline: float) -> bytes:
    """Forward one already-framed record to the fixed shipping executor."""
    _validate_provider_frame(
        frame, MAX_PROVIDER_REQUEST_FRAME_BYTES, "request_too_large"
    )
    if not PROVIDER_RELAY_LOCK.acquire(blocking=False):
        raise ProviderRelayError("busy", 429)
    connection: socket.socket | None = None
    try:
        connection = socket.socket(
            socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC
        )
        _set_provider_socket_deadline(connection, deadline)
        connection.connect(PROVIDER_SOCKET)
        _validate_root_provider_peer(connection)
        _set_provider_socket_deadline(connection, deadline)
        if connection.send(frame) != len(frame):
            raise ProviderRelayError("transport", 503)
        _set_provider_socket_deadline(connection, deadline)
        response, ancillary, flags, _address = connection.recvmsg(
            MAX_PROVIDER_RESPONSE_FRAME_BYTES + 1, 0
        )
        if ancillary or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
            raise ProviderRelayError("invalid_response", 502)
        _validate_provider_frame(
            response, MAX_PROVIDER_RESPONSE_FRAME_BYTES, "response_too_large"
        )
        return response
    except socket.timeout as error:
        raise ProviderRelayError("timeout", 504) from error
    except ProviderRelayError:
        raise
    except OSError as error:
        raise ProviderRelayError("transport", 503) from error
    finally:
        try:
            if connection is not None:
                try:
                    connection.close()
                except OSError:
                    pass
        finally:
            PROVIDER_RELAY_LOCK.release()


def _remaining_seconds(deadline: float | None) -> float | None:
    """Return the remaining monotonic budget, or fail once it is exhausted."""
    if deadline is None:
        return None
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("Deadline dell'autorizzazione Rescue scaduta.")
    return remaining


def _bounded_timeout(per_command: float, deadline: float | None) -> float:
    remaining = _remaining_seconds(deadline)
    return per_command if remaining is None else min(per_command, remaining)


def _check_deadline(deadline: float | None) -> None:
    _remaining_seconds(deadline)


def _validate_helper_error(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != {
        "code",
        "message",
        "retryable",
        "claims",
    }:
        raise BrokerError("Risposta dell'ispettore privilegiato non valida.")
    code = value.get("code")
    message = value.get("message")
    retryable = value.get("retryable")
    claims = value.get("claims")
    if (
        not isinstance(code, str)
        or not code
        or len(code) > 64
        or not code.isascii()
        or any(character not in "abcdefghijklmnopqrstuvwxyz0123456789-" for character in code)
        or not isinstance(message, str)
        or not message
        or len(message.encode("utf-8")) > 512
        or any(ord(character) < 32 or ord(character) == 127 for character in message)
        or not isinstance(retryable, bool)
        or not isinstance(claims, dict)
        or set(claims) != OFFLINE_INSPECTION_CLAIM_FIELDS
        or any(not isinstance(claims[field], bool) for field in claims)
    ):
        raise BrokerError("Risposta dell'ispettore privilegiato non valida.")
    return value


def _privileged_helper_call(
    operation: str, request: dict[str, object] | None = None
) -> object:
    if operation not in {"inspect", "scan", "select"}:
        raise BrokerError("Operazione dell'ispettore privilegiato non valida.")
    frame: dict[str, object] = {"operation": operation}
    if request is not None:
        frame["request"] = request
    encoded = json.dumps(
        frame, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("utf-8") + b"\n"
    if len(encoded) > MAX_REQUEST_BYTES:
        raise BrokerError("Richiesta all'ispettore privilegiato oltre il limite.")
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(OFFLINE_HELPER_TIMEOUT_SECONDS)
            connection.connect(OFFLINE_HELPER_SOCKET)
            connection.sendall(encoded)
            connection.shutdown(socket.SHUT_WR)
            payload = bytearray()
            while len(payload) <= MAX_OFFLINE_HELPER_RESPONSE_BYTES:
                chunk = connection.recv(
                    min(
                        8 * 1024,
                        MAX_OFFLINE_HELPER_RESPONSE_BYTES + 1 - len(payload),
                    )
                )
                if not chunk:
                    break
                payload.extend(chunk)
    except (OSError, TimeoutError) as error:
        raise PrivilegedHelperError(
            {
                "code": "privileged-helper-unavailable",
                "message": "L'ispettore privilegiato locale non è disponibile.",
                "retryable": True,
                "claims": {field: False for field in OFFLINE_INSPECTION_CLAIM_FIELDS},
            },
            503,
        ) from error
    if (
        len(payload) > MAX_OFFLINE_HELPER_RESPONSE_BYTES
        or payload.count(b"\n") != 1
        or not payload.endswith(b"\n")
    ):
        raise BrokerError("Frame dell'ispettore privilegiato non valido.")
    try:
        response = json.loads(payload[:-1].decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BrokerError("JSON dell'ispettore privilegiato non valido.") from error
    if not isinstance(response, dict) or not isinstance(response.get("ok"), bool):
        raise BrokerError("Risposta dell'ispettore privilegiato non valida.")
    if response["ok"] is True:
        if set(response) != {"ok", "result"}:
            raise BrokerError("Risposta dell'ispettore privilegiato non valida.")
        return response["result"]
    if set(response) != {"ok", "status", "error"}:
        raise BrokerError("Risposta dell'ispettore privilegiato non valida.")
    status = response.get("status")
    if (
        not isinstance(status, int)
        or isinstance(status, bool)
        or status not in {400, 408, 409, 422, 429, 503}
    ):
        raise BrokerError("Risposta dell'ispettore privilegiato non valida.")
    raise PrivilegedHelperError(_validate_helper_error(response["error"]), status)


class ObserveBroker:
    def __init__(
        self, target_fingerprint: str, rescue_target: dict[str, str]
    ) -> None:
        self.target_fingerprint = target_fingerprint
        self.rescue_target = dict(rescue_target)
        self.last_sequence = 0

    def authorize(
        self, request: dict[str, object], deadline: float | None = None
    ) -> None:
        _session_id, rescue_target = validate_observe_request(request)
        fingerprint = request["targetFingerprint"]
        sequence = request["sequence"]
        if rescue_target != self.rescue_target:
            raise BrokerError("Il target Rescue è cambiato: ripetere la selezione.")
        if fingerprint != self.target_fingerprint:
            raise BrokerError("Il target è cambiato: piano annullato, ripetere la diagnosi.")
        if not isinstance(sequence, int) or isinstance(sequence, bool):
            raise BrokerError("Richiesta al broker non valida.")
        if sequence <= self.last_sequence:
            raise BrokerError("Richiesta già eseguita o fuori sequenza.")
        # This is the authorization commit point. The caller holds BROKER_LOCK;
        # never advance a session whose end-to-end monotonic budget expired.
        _check_deadline(deadline)
        self.last_sequence = sequence


BROKERS: dict[str, ObserveBroker] = {}
BROKER_LOCK = threading.Lock()
INVENTORY_LOCK = threading.Lock()
TARGET_SCAN_LOCK = threading.Lock()


def observe(
    collector: str,
    command: tuple[str, ...],
    deadline: float | None = None,
) -> dict[str, object]:
    try:
        _check_deadline(deadline)
        process = subprocess.Popen(
            command,
            env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        retained = bytearray()
        stdout_truncated = False
        stderr_truncated = False

        def drain_stdout() -> None:
            nonlocal stdout_truncated
            if process.stdout is None:
                return
            try:
                while chunk := process.stdout.read(8 * 1024):
                    remaining = MAX_OUTPUT_BYTES - len(retained)
                    if len(chunk) > remaining:
                        stdout_truncated = True
                    if remaining > 0:
                        retained.extend(chunk[:remaining])
            except (OSError, ValueError):
                stdout_truncated = True

        def drain_stderr() -> None:
            nonlocal stderr_truncated
            if process.stderr is None:
                return
            observed = 0
            try:
                while chunk := process.stderr.read(8 * 1024):
                    observed += len(chunk)
                    if observed > MAX_OUTPUT_BYTES:
                        stderr_truncated = True
            except (OSError, ValueError):
                stderr_truncated = True

        readers = (
            threading.Thread(target=drain_stdout, daemon=True),
            threading.Thread(target=drain_stderr, daemon=True),
        )
        for reader in readers:
            reader.start()

        def terminate_process_group() -> None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
                return
            except OSError:
                pass
            try:
                process.kill()
            except OSError:
                pass

        timed_out = False
        budget_timeout = False
        deadline_limited = False
        try:
            wait_timeout = _bounded_timeout(COLLECTOR_TIMEOUT_SECONDS, deadline)
            deadline_limited = (
                deadline is not None and wait_timeout < COLLECTOR_TIMEOUT_SECONDS
            )
            process.wait(timeout=wait_timeout)
        except TimeoutError:
            timed_out = True
            budget_timeout = True
            terminate_process_group()
            cleanup_limit = time.monotonic() + COLLECTOR_KILL_GRACE_SECONDS
            if deadline is not None:
                cleanup_limit = min(cleanup_limit, deadline)
            try:
                process.wait(timeout=max(0.0, cleanup_limit - time.monotonic()))
            except subprocess.TimeoutExpired:
                pass
        except subprocess.TimeoutExpired:
            timed_out = True
            budget_timeout = deadline_limited
            terminate_process_group()
            cleanup_limit = time.monotonic() + COLLECTOR_KILL_GRACE_SECONDS
            if deadline is not None:
                cleanup_limit = min(cleanup_limit, deadline)
            try:
                process.wait(timeout=max(0.0, cleanup_limit - time.monotonic()))
            except subprocess.TimeoutExpired:
                pass

        reader_limit = time.monotonic() + COLLECTOR_KILL_GRACE_SECONDS
        if deadline is not None:
            reader_limit = min(reader_limit, deadline)
        for reader in readers:
            reader.join(timeout=max(0.0, reader_limit - time.monotonic()))
        streams_incomplete = any(reader.is_alive() for reader in readers)
        if streams_incomplete:
            terminate_process_group()
        reader_limit = time.monotonic() + COLLECTOR_KILL_GRACE_SECONDS
        if deadline is not None:
            reader_limit = min(reader_limit, deadline)
        for reader in readers:
            reader.join(timeout=max(0.0, reader_limit - time.monotonic()))
        streams_incomplete = streams_incomplete or any(
            reader.is_alive() for reader in readers
        )
        cleanup_pending = process.poll() is None or any(
            reader.is_alive() for reader in readers
        )
        if cleanup_pending:
            # SIGKILL is already pending. Reap and close asynchronously rather
            # than let cleanup push the request worker beyond its budget.
            def finish_cleanup() -> None:
                try:
                    process.wait()
                except OSError:
                    pass
                for reader in readers:
                    reader.join()
                for stream in (process.stdout, process.stderr):
                    if stream is not None:
                        try:
                            stream.close()
                        except OSError:
                            pass

            threading.Thread(target=finish_cleanup, daemon=True).start()
        else:
            for stream in (process.stdout, process.stderr):
                if stream is not None:
                    stream.close()
        try:
            output = bytes(retained).decode("utf-8", errors="strict")
            valid_utf8 = True
        except UnicodeDecodeError:
            output = ""
            valid_utf8 = False
        truncated = stdout_truncated or stderr_truncated or streams_incomplete
        if budget_timeout:
            raise TimeoutError("Deadline dell'autorizzazione Rescue scaduta.")
        _check_deadline(deadline)
        return {
            "collector": collector,
            "trust": "observed-untrusted",
            "output": output,
            "success": (
                not timed_out
                and process.returncode == 0
                and not truncated
                and valid_utf8
            ),
            "truncated": truncated,
        }
    except TimeoutError:
        raise
    except (OSError, subprocess.TimeoutExpired):
        return {
            "collector": collector,
            "trust": "observed-untrusted",
            "output": "",
            "success": False,
            "truncated": False,
        }


def inventory(deadline: float | None = None) -> list[dict[str, object]]:
    _check_deadline(deadline)
    if not INVENTORY_LOCK.acquire(blocking=False):
        raise InventoryBusy("Inventario locale già in corso; riprovare.")
    try:
        _check_deadline(deadline)
        with ThreadPoolExecutor(max_workers=len(COMMANDS)) as executor:
            if deadline is None:
                futures = [
                    executor.submit(observe, collector, command)
                    for collector, command in COMMANDS
                ]
            else:
                futures = [
                    executor.submit(observe, collector, command, deadline)
                    for collector, command in COMMANDS
                ]
            observations = [
                future.result(timeout=_remaining_seconds(deadline))
                if deadline is not None
                else future.result()
                for future in futures
            ]
        _check_deadline(deadline)
        return observations
    finally:
        INVENTORY_LOCK.release()


def _target_text(value: object, field: str, *, required: bool = False) -> str | None:
    if value is None and not required:
        return None
    if not isinstance(value, str) or (required and not value):
        raise TargetScanError(f"Metadato {field} non valido.")
    if len(value.encode("utf-8")) > MAX_TARGET_FIELD_BYTES:
        raise TargetScanError(f"Metadato {field} oltre il limite.")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise TargetScanError(f"Metadato {field} contiene caratteri non validi.")
    return value


def _target_flag(value: object, field: str) -> bool:
    if not isinstance(value, bool):
        raise TargetScanError(f"Metadato {field} non valido.")
    return value


def _target_size(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise TargetScanError("Dimensione del dispositivo non valida.")
    return value


def _target_major_minor(value: object) -> str:
    normalized = _target_text(value, "maj:min", required=True)
    if normalized is None:
        raise TargetScanError("Identità kernel del dispositivo non valida.")
    parts = normalized.split(":")
    if (
        len(parts) != 2
        or not all(part.isascii() and part.isdecimal() for part in parts)
        or any(len(part) > 10 for part in parts)
        or any(int(part) > 4_294_967_295 for part in parts)
    ):
        raise TargetScanError("Identità kernel del dispositivo non valida.")
    return f"{int(parts[0])}:{int(parts[1])}"


def _parse_target_device(
    value: object, depth: int, device_count: list[int]
) -> dict[str, object]:
    if depth > MAX_TARGET_DEPTH or not isinstance(value, dict):
        raise TargetScanError("Topologia dei dispositivi non valida.")
    allowed_fields = TARGET_DEVICE_FIELDS | {"children"}
    if not TARGET_DEVICE_FIELDS.issubset(value) or not set(value).issubset(
        allowed_fields
    ):
        raise TargetScanError("Schema dei metadati dei dispositivi non valido.")
    device_count[0] += 1
    if device_count[0] > MAX_TARGET_DEVICES:
        raise TargetScanError("Troppi dispositivi per una scansione sicura.")

    text_fields = {
        field: _target_text(value[field], field, required=field in {"name", "type"})
        for field in (
            "name",
            "type",
            "tran",
            "fstype",
            "fsver",
            "uuid",
            "partuuid",
            "ptuuid",
            "pttype",
            "parttype",
            "serial",
            "wwn",
        )
    }
    mountpoints = value["mountpoints"]
    if not isinstance(mountpoints, list) or len(mountpoints) > 32:
        raise TargetScanError("Metadati dei mount point non validi.")
    normalized_mountpoints: list[str | None] = []
    for mountpoint in mountpoints:
        normalized_mountpoints.append(_target_text(mountpoint, "mountpoint"))

    raw_children = value.get("children", [])
    if not isinstance(raw_children, list):
        raise TargetScanError("Topologia figlia dei dispositivi non valida.")
    children = [
        _parse_target_device(child, depth + 1, device_count)
        for child in raw_children
    ]
    identity = {
        **text_fields,
        "maj:min": _target_major_minor(value["maj:min"]),
        "size": _target_size(value["size"]),
        "ro": _target_flag(value["ro"], "ro"),
        "rm": _target_flag(value["rm"], "rm"),
        "mountpoints": normalized_mountpoints,
    }
    return {
        "identity": identity,
        "name": text_fields["name"],
        "major_minor": identity["maj:min"],
        "kind": str(text_fields["type"]).lower(),
        "size": identity["size"],
        "read_only": identity["ro"],
        "removable": identity["rm"],
        "transport": (text_fields["tran"] or "").lower(),
        "filesystem": (text_fields["fstype"] or "").lower(),
        "partition_table": (text_fields["pttype"] or "").lower(),
        "partition_type": (text_fields["parttype"] or "").lower(),
        "mounted": any(bool(mountpoint) for mountpoint in normalized_mountpoints),
        "children": children,
    }


def _canonical_target_device(device: dict[str, object]) -> dict[str, object]:
    children = device["children"]
    if not isinstance(children, list):
        raise TargetScanError("Topologia normalizzata non valida.")
    canonical_children = [_canonical_target_device(child) for child in children]
    canonical_children.sort(
        key=lambda child: json.dumps(child, sort_keys=True, separators=(",", ":"))
    )
    return {"identity": device["identity"], "children": canonical_children}


def _stable_disk_identity(value: object, *, casefold: bool = False) -> str | None:
    """Return one strict internal identity value without ever publishing it."""
    if (
        not isinstance(value, str)
        or RECOVERY_DISK_ID.fullmatch(value) is None
        or len(value.encode("ascii")) > 128
    ):
        return None
    return value.casefold() if casefold else value


def _stable_uuid(value: object) -> str | None:
    if not isinstance(value, str) or RECOVERY_UUID.fullmatch(value) is None:
        return None
    return value.casefold()


def _recovery_target_fingerprint(
    disk: dict[str, object], candidate: dict[str, object]
) -> str | None:
    """Derive a reboot-stable digest from strong, non-public block claims.

    Boot-local names, major/minor numbers and keyed target identifiers are
    deliberately excluded. A partition additionally requires GPT and a
    PARTUUID; every target requires an ext4 UUID and a disk WWN or serial.
    """
    disk_identity = disk.get("identity")
    leaf_identity = candidate.get("identity")
    if not isinstance(disk_identity, dict) or not isinstance(leaf_identity, dict):
        return None
    leaf_kind = candidate.get("kind")
    disk_size = disk.get("size")
    leaf_size = candidate.get("size")
    filesystem_uuid = _stable_uuid(leaf_identity.get("uuid"))
    disk_wwn = _stable_disk_identity(disk_identity.get("wwn"), casefold=True)
    disk_serial = _stable_disk_identity(disk_identity.get("serial"))
    if (
        disk.get("kind") != "disk"
        or leaf_kind not in {"disk", "part"}
        or candidate.get("filesystem") != "ext4"
        or not isinstance(disk_size, int)
        or isinstance(disk_size, bool)
        or disk_size <= 0
        or not isinstance(leaf_size, int)
        or isinstance(leaf_size, bool)
        or leaf_size <= 0
        or leaf_size > disk_size
        or filesystem_uuid is None
        or (disk_wwn is None and disk_serial is None)
    ):
        return None
    partition_uuid: str | None = None
    if leaf_kind == "part":
        partition_uuid = _stable_uuid(leaf_identity.get("partuuid"))
        if disk.get("partition_table") != "gpt" or partition_uuid is None:
            return None
    elif candidate is not disk:
        return None

    # Prefer the globally scoped WWN. The serial is a strict fallback only,
    # which keeps the identity stable when both fields are available.
    anchor_kind = "wwn" if disk_wwn is not None else "serial"
    anchor_value = disk_wwn if disk_wwn is not None else disk_serial
    claims = {
        "diskAnchorKind": anchor_kind,
        "diskAnchorValue": anchor_value,
        "diskSizeBytes": disk_size,
        "diskType": "disk",
        "filesystem": "ext4",
        "filesystemUuid": filesystem_uuid,
        "leafSizeBytes": leaf_size,
        "leafType": leaf_kind,
        "partitionUuid": partition_uuid,
    }
    canonical = json.dumps(
        claims, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("ascii")
    digest = hashlib.sha256(
        RECOVERY_TARGET_FINGERPRINT_DOMAIN + b"\0" + canonical
    ).hexdigest()
    return f"recovery:{digest}"


def _walk_target_devices(device: dict[str, object]) -> list[dict[str, object]]:
    children = device["children"]
    if not isinstance(children, list):
        raise TargetScanError("Topologia normalizzata non valida.")
    return [device] + [
        descendant
        for child in children
        for descendant in _walk_target_devices(child)
    ]


def _complex_topology_disks(
    disks: list[dict[str, object]],
) -> dict[int, set[str]]:
    by_major_minor: dict[
        str, list[tuple[dict[str, object], dict[str, object]]]
    ] = {}
    by_kernel_name: dict[
        str, list[tuple[dict[str, object], dict[str, object]]]
    ] = {}
    btrfs_members: dict[
        str, list[tuple[dict[str, object], dict[str, object]]]
    ] = {}
    for disk in disks:
        for device in _walk_target_devices(disk):
            major_minor = device["major_minor"]
            name = device["name"]
            if not isinstance(major_minor, str) or not isinstance(name, str):
                raise TargetScanError("Indice della topologia non valido.")
            by_major_minor.setdefault(major_minor, []).append((disk, device))
            by_kernel_name.setdefault(name, []).append((disk, device))
            identity = device["identity"]
            if not isinstance(identity, dict):
                raise TargetScanError("Identità normalizzata non valida.")
            filesystem_uuid = identity.get("uuid")
            if (
                device["filesystem"] == "btrfs"
                and isinstance(filesystem_uuid, str)
                and filesystem_uuid
            ):
                btrfs_members.setdefault(filesystem_uuid.casefold(), []).append(
                    (disk, device)
                )

    conflicts: dict[int, set[str]] = {}

    def mark(
        occurrences: list[tuple[dict[str, object], dict[str, object]]], reason: str
    ) -> None:
        for disk, _device in occurrences:
            conflicts.setdefault(id(disk), set()).add(reason)

    for occurrences in by_major_minor.values():
        if len(occurrences) < 2:
            continue
        # A repeated N:M is an N-to-M graph, even when lsblk renders coherent
        # duplicate subtrees. Incoherent copies are treated identically: none of
        # their owning disks may produce a selectable target.
        canonical_copies = {
            json.dumps(
                _canonical_target_device(device),
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            )
            for _disk, device in occurrences
        }
        mark(occurrences, "repeated-major-minor")
        if len(canonical_copies) != 1:
            mark(occurrences, "incoherent-duplicate-identity")

    for occurrences in by_kernel_name.values():
        if len({str(device["major_minor"]) for _disk, device in occurrences}) > 1:
            mark(occurrences, "kernel-name-maps-to-multiple-devices")

    for occurrences in btrfs_members.values():
        if len({str(device["major_minor"]) for _disk, device in occurrences}) > 1:
            mark(occurrences, "shared-btrfs-filesystem")
    return conflicts


def _ephemeral_target_id(prefix: str, payload: object) -> str:
    canonical = json.dumps(
        payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode()
    digest = hmac.new(TARGET_ID_KEY, canonical, hashlib.sha256).hexdigest()
    return f"{prefix}:{digest}"


def _subtree_matches(device: dict[str, object], predicate: object) -> bool:
    if not callable(predicate):
        raise TargetScanError("Predicato di scansione non valido.")
    if predicate(device):
        return True
    children = device["children"]
    if not isinstance(children, list):
        raise TargetScanError("Topologia normalizzata non valida.")
    return any(_subtree_matches(child, predicate) for child in children)


def _public_transport(value: object) -> str:
    if value in {"ata", "mmc", "nvme", "sata", "sas", "scsi", "usb", "virtio"}:
        return str(value)
    return "unknown"


def _public_partition_table(value: object) -> str:
    if value in {"bsd", "dos", "gpt", "mac", "sun"}:
        return str(value)
    return "unknown"


def _public_filesystem(value: object) -> str:
    known = (
        LINUX_FILESYSTEMS
        | WINDOWS_FILESYSTEMS
        | MACOS_FILESYSTEMS
        | ENCRYPTED_FILESYSTEMS
        | LIVE_IMAGE_FILESYSTEMS
        | {
            "exfat",
            "fat",
            "lvm2_member",
            "linux_raid_member",
            "swap",
            "vfat",
        }
    )
    if value in known:
        return str(value)
    return "unknown" if not value else "other"


def _public_device_kind(value: object) -> str:
    if value == "part":
        return "partition"
    if value == "lvm":
        return "logical-volume"
    if value == "crypt":
        return "encrypted-mapping"
    if value == "disk":
        return "whole-disk-filesystem"
    if isinstance(value, str) and (value.startswith("raid") or value == "md"):
        return "raid-volume"
    return "other"


def _candidate_classification(
    device: dict[str, object]
) -> tuple[str, list[str], bool] | None:
    filesystem = device["filesystem"]
    partition_type = device["partition_type"]
    families: set[str] = set()
    basis: list[str] = []
    requires_unlock = filesystem in ENCRYPTED_FILESYSTEMS

    if filesystem in LINUX_FILESYSTEMS:
        families.add("linux")
        basis.append("linux-filesystem-signature")
    elif filesystem == "ntfs":
        families.add("windows")
        basis.append("ntfs-filesystem-signature")
    elif filesystem == "bitlocker":
        families.add("windows")
        basis.append("bitlocker-container-signature")
    elif filesystem in MACOS_FILESYSTEMS:
        families.add("macos")
        basis.append("apple-filesystem-signature")
    elif filesystem == "crypto_luks":
        families.add("unknown-encrypted")
        basis.append("luks-container-signature")

    if partition_type in LINUX_ROOT_PARTITION_TYPES:
        families.add("linux")
        basis.append("linux-root-partition-type")
    elif partition_type == APPLE_APFS_PARTITION_TYPE:
        families.add("macos")
        basis.append("apple-apfs-partition-type")

    if not families:
        return None
    if len(families) == 1:
        family = next(iter(families))
    else:
        family = "unknown"
        basis.append("conflicting-metadata-signatures")
    return family, sorted(set(basis)), requires_unlock


def _candidate_nodes(device: dict[str, object]) -> list[dict[str, object]]:
    children = device["children"]
    if not isinstance(children, list):
        raise TargetScanError("Topologia normalizzata non valida.")
    child_candidates = [
        candidate for child in children for candidate in _candidate_nodes(child)
    ]
    if child_candidates:
        return child_candidates
    if device["kind"] not in {"crypt", "disk", "lvm", "part"}:
        return []
    return [device] if _candidate_classification(device) is not None else []


def _associated_efi_system_partition(
    disk: dict[str, object], candidate: dict[str, object]
) -> dict[str, object]:
    """Resolve one direct GPT ESP sibling without exposing it publicly."""
    if disk["partition_table"] != "gpt" or candidate is disk:
        return {"state": "not-present"}
    children = disk["children"]
    if not isinstance(children, list):
        raise TargetScanError("Topologia ESP normalizzata non valida.")
    if not any(child is candidate for child in children):
        return {"state": "unsupported"}
    matches = [
        child
        for child in children
        if child is not candidate
        and child["partition_type"] == EFI_SYSTEM_PARTITION_TYPE
    ]
    if not matches:
        return {"state": "not-present"}
    if len(matches) != 1:
        return {"state": "ambiguous"}
    selected = matches[0]
    selected_children = selected["children"]
    if not isinstance(selected_children, list):
        raise TargetScanError("Topologia ESP normalizzata non valida.")
    if (
        selected["kind"] != "part"
        or selected_children
        or selected["filesystem"] not in EFI_SYSTEM_FILESYSTEMS
        or selected["mounted"] is not False
    ):
        return {"state": "unsupported"}
    return {
        "state": "eligible",
        "deviceIdentity": selected["identity"],
        "majorMinor": selected["major_minor"],
        "filesystem": selected["filesystem"],
        "kernelKind": selected["kind"],
        "leaf": True,
        "directOnDisk": True,
    }


def _flatten_target_volumes(
    disk: dict[str, object], disk_ref: str
) -> tuple[list[dict[str, object]], dict[int, str]]:
    volumes: list[dict[str, object]] = []
    references: dict[int, str] = {id(disk): disk_ref}

    def append_children(device: dict[str, object], parent_ref: str) -> None:
        children = device["children"]
        if not isinstance(children, list):
            raise TargetScanError("Topologia normalizzata non valida.")
        for child in sorted(children, key=lambda item: str(item["name"])):
            volume_ref = f"{disk_ref}/volume-{len(volumes) + 1}"
            references[id(child)] = volume_ref
            volumes.append(
                {
                    "ref": volume_ref,
                    "parentRef": parent_ref,
                    "kind": _public_device_kind(child["kind"]),
                    "sizeBytes": child["size"],
                    "filesystem": _public_filesystem(child["filesystem"]),
                    "mediaReadOnly": child["read_only"],
                    "mounted": child["mounted"],
                    "encrypted": child["filesystem"] in ENCRYPTED_FILESYSTEMS,
                }
            )
            append_children(child, volume_ref)

    append_children(disk, disk_ref)
    return volumes, references


def _normalize_installed_targets_with_resolutions(
    output: str,
) -> tuple[dict[str, object], dict[str, dict[str, object]]]:
    try:
        decoded = json.loads(output)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise TargetScanError("Output della scansione dei target non valido.") from error
    if not isinstance(decoded, dict) or set(decoded) != {"blockdevices"}:
        raise TargetScanError("Schema della scansione dei target non valido.")
    raw_devices = decoded["blockdevices"]
    if not isinstance(raw_devices, list):
        raise TargetScanError("Elenco dei dispositivi non valido.")
    device_count = [0]
    roots = [_parse_target_device(device, 0, device_count) for device in raw_devices]
    disks = sorted(
        (root for root in roots if root["kind"] == "disk"),
        key=lambda item: str(item["name"]),
    )
    complex_topology_disks = _complex_topology_disks(disks)
    canonical_disks = [_canonical_target_device(disk) for disk in disks]
    scan_fingerprint = _ephemeral_target_id("scan", canonical_disks)

    public_disks: list[dict[str, object]] = []
    public_candidates: list[dict[str, object]] = []
    resolutions: dict[str, dict[str, object]] = {}
    seen_target_ids: set[str] = set()
    for disk_index, disk in enumerate(disks, start=1):
        disk_ref = f"disk-{disk_index}"
        canonical_disk = _canonical_target_device(disk)
        disk_id = _ephemeral_target_id("disk", canonical_disk)
        subtree_mounted = _subtree_matches(disk, lambda node: node["mounted"] is True)
        live_image = _subtree_matches(
            disk, lambda node: node["filesystem"] in LIVE_IMAGE_FILESYSTEMS
        )
        exclusion_reasons: list[str] = []
        if subtree_mounted:
            exclusion_reasons.append("disk-or-descendant-mounted")
        if live_image:
            exclusion_reasons.append("live-or-optical-filesystem-signature")
        if id(disk) in complex_topology_disks:
            exclusion_reasons.append("complex-multi-parent-topology")
        if disk["size"] == 0:
            exclusion_reasons.append("zero-capacity-device")
        selection_eligible = not exclusion_reasons
        volumes, references = _flatten_target_volumes(disk, disk_ref)
        public_disks.append(
            {
                "id": disk_id,
                "ref": disk_ref,
                "sizeBytes": disk["size"],
                "transport": _public_transport(disk["transport"]),
                "partitionTable": _public_partition_table(disk["partition_table"]),
                "mediaReadOnly": disk["read_only"],
                "removable": disk["removable"],
                "mounted": subtree_mounted,
                "selectionEligible": selection_eligible,
                "exclusionReasons": exclusion_reasons,
                "volumes": volumes,
            }
        )
        if not selection_eligible:
            continue
        for candidate in _candidate_nodes(disk):
            classification = _candidate_classification(candidate)
            if classification is None:
                continue
            family, basis, requires_unlock = classification
            target_id = _ephemeral_target_id(
                "target", {"disk": canonical_disk, "device": candidate["identity"]}
            )
            if target_id in seen_target_ids:
                raise TargetScanError(
                    "Identificatore target duplicato; scansione rifiutata."
                )
            seen_target_ids.add(target_id)
            public_candidate = {
                "targetId": target_id,
                "sourceRef": references[id(candidate)],
                "diskId": disk_id,
                "osFamilyHint": family,
                "confidence": "low",
                "status": "unverified-installation-candidate",
                "detectionBasis": basis,
                "requiresUnlock": requires_unlock,
                "inspectionMode": "metadata-only-no-mount",
                "selectionEligible": True,
            }
            public_candidates.append(public_candidate)
            disk_children = disk["children"]
            candidate_children = candidate["children"]
            if not isinstance(disk_children, list) or not isinstance(
                candidate_children, list
            ):
                raise TargetScanError("Topologia normalizzata non valida.")
            direct_child = any(child is candidate for child in disk_children)
            recovery_fingerprint = (
                _recovery_target_fingerprint(disk, candidate)
                if not candidate_children
                and (candidate is disk or direct_child)
                else None
            )
            topology_kinds = sorted(
                {
                    str(node["kind"])
                    for node in _walk_target_devices(disk)
                }
            )
            topology_filesystems = sorted(
                {
                    str(node["filesystem"])
                    for node in _walk_target_devices(disk)
                    if node["filesystem"]
                }
            )
            resolutions[target_id] = {
                "candidate": public_candidate,
                "deviceIdentity": candidate["identity"],
                "majorMinor": candidate["major_minor"],
                "filesystem": candidate["filesystem"],
                "kernelKind": candidate["kind"],
                "leaf": not candidate_children,
                "directOnDisk": candidate is disk or direct_child,
                "recoveryFingerprint": recovery_fingerprint,
                "recoveryUnique": False,
                "topologyKinds": topology_kinds,
                "topologyFilesystems": topology_filesystems,
                "associatedEfiSystemPartition": _associated_efi_system_partition(
                    disk, candidate
                ),
            }

    recovery_counts: dict[str, int] = {}
    for resolution in resolutions.values():
        recovery_fingerprint = resolution.get("recoveryFingerprint")
        if isinstance(recovery_fingerprint, str):
            recovery_counts[recovery_fingerprint] = (
                recovery_counts.get(recovery_fingerprint, 0) + 1
            )
    for resolution in resolutions.values():
        recovery_fingerprint = resolution.get("recoveryFingerprint")
        resolution["recoveryUnique"] = (
            isinstance(recovery_fingerprint, str)
            and recovery_counts.get(recovery_fingerprint) == 1
        )

    snapshot: dict[str, object] = {
        "apiVersion": TARGET_SCAN_API_VERSION,
        "mode": "observe-r0",
        "trust": "observed-untrusted",
        "scanFingerprint": scan_fingerprint,
        "identifierScope": TARGET_ID_SCOPE,
        "disks": public_disks,
        "candidates": public_candidates,
        "claims": {
            "installedOsConfirmed": False,
            "filesystemContentInspected": False,
            "mountOperationPerformed": False,
            "mutationPerformed": False,
            "rawDeviceIdentifiersReturned": False,
        },
        "limitations": [
            "os-family-is-only-a-low-confidence-metadata-hint",
            "filesystem-content-was-not-inspected",
            "locked-or-complex-storage-was-not-activated",
            "mounted-and-live-image-disks-are-not-selectable",
        ],
    }
    encoded = json.dumps(snapshot, ensure_ascii=True, separators=(",", ":")).encode()
    if len(encoded) > MAX_TARGET_RESPONSE_BYTES:
        raise TargetScanError("Risposta della scansione dei target oltre il limite.")
    return snapshot, resolutions


def normalize_installed_targets(output: str) -> dict[str, object]:
    snapshot, _resolutions = _normalize_installed_targets_with_resolutions(output)
    return snapshot


def _target_scan_output(deadline: float | None = None) -> str:
    if deadline is None:
        observation = observe("rescue.installed-targets.metadata", TARGET_SCAN_COMMAND)
    else:
        observation = observe(
            "rescue.installed-targets.metadata", TARGET_SCAN_COMMAND, deadline
        )
    _check_deadline(deadline)
    if observation.get("success") is not True or observation.get("truncated") is True:
        raise TargetScanError("Scansione dei target incompleta; riprovare.")
    output = observation.get("output")
    if not isinstance(output, str):
        raise TargetScanError("Output della scansione dei target non valido.")
    return output


def installed_targets(deadline: float | None = None) -> dict[str, object]:
    if OFFLINE_HELPER_ENABLED:
        _check_deadline(deadline)
        result = _privileged_helper_call("scan")
        if not isinstance(result, dict):
            raise TargetScanError("Risposta privilegiata dei target non valida.")
        return result
    _check_deadline(deadline)
    if not TARGET_SCAN_LOCK.acquire(blocking=False):
        raise TargetScanBusy("Scansione dei target già in corso; riprovare.")
    try:
        _check_deadline(deadline)
        return normalize_installed_targets(_target_scan_output(deadline))
    finally:
        TARGET_SCAN_LOCK.release()


def resolve_installed_target(
    request: dict[str, object], deadline: float | None = None
) -> tuple[dict[str, object], dict[str, object]]:
    """Resolve an opaque selection to one internal identity in this process.

    The internal resolution is for the privileged offline inspector only. It
    must never be serialized by the HTTP bridge because it contains raw kernel
    identity and storage metadata.
    """
    _check_deadline(deadline)
    if set(request) != {"scanFingerprint", "targetId"}:
        raise TargetSelectionError(
            "Richiesta di selezione del target non valida.", status=400
        )
    requested_fingerprint = request["scanFingerprint"]
    requested_target = request["targetId"]
    if not _valid_ephemeral_id(
        requested_fingerprint, "scan"
    ) or not _valid_ephemeral_id(requested_target, "target"):
        raise TargetSelectionError(
            "Richiesta di selezione del target non valida.", status=400
        )
    if not TARGET_SCAN_LOCK.acquire(blocking=False):
        raise TargetScanBusy("Scansione dei target già in corso; riprovare.")
    try:
        snapshot, resolutions = _normalize_installed_targets_with_resolutions(
            _target_scan_output(deadline)
        )
    finally:
        TARGET_SCAN_LOCK.release()
    _check_deadline(deadline)
    if snapshot["scanFingerprint"] != requested_fingerprint:
        raise TargetSelectionError(
            "La topologia dei dischi è cambiata; ripetere la selezione."
        )
    if not isinstance(requested_target, str):
        raise TargetSelectionError(
            "Richiesta di selezione del target non valida.", status=400
        )
    resolution = resolutions.get(requested_target)
    if resolution is None:
        raise TargetSelectionError(
            "Il target non è più disponibile in modalità Observe; ripetere la selezione."
        )
    candidate = resolution.get("candidate")
    canonical_target_candidate(candidate)
    selection = {
        "apiVersion": TARGET_SCAN_API_VERSION,
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
    return selection, resolution


def valid_recovery_target_fingerprint(value: object) -> bool:
    if not isinstance(value, str) or not value.startswith("recovery:"):
        return False
    digest = value.removeprefix("recovery:")
    return len(digest) == 64 and all(
        character in "0123456789abcdef" for character in digest
    )


def resolve_recovery_target(
    request: dict[str, object], deadline: float | None = None
) -> tuple[dict[str, object], dict[str, object]]:
    """Reacquire exactly one target from a reboot-stable opaque digest.

    The digest is the only caller-provided target selector. Fresh boot-local
    claims are returned internally with the resolution; raw stable claims and
    device paths never cross this boundary.
    """
    _check_deadline(deadline)
    if set(request) != {"recoveryFingerprint"} or not valid_recovery_target_fingerprint(
        request.get("recoveryFingerprint")
    ):
        raise TargetSelectionError(
            "Richiesta di recupero del target non valida.", status=400
        )
    requested = request["recoveryFingerprint"]
    if not TARGET_SCAN_LOCK.acquire(blocking=False):
        raise TargetScanBusy("Scansione dei target già in corso; riprovare.")
    try:
        snapshot, resolutions = _normalize_installed_targets_with_resolutions(
            _target_scan_output(deadline)
        )
    finally:
        TARGET_SCAN_LOCK.release()
    _check_deadline(deadline)
    matches = [
        resolution
        for resolution in resolutions.values()
        if resolution.get("recoveryFingerprint") == requested
        and resolution.get("recoveryUnique") is True
    ]
    if len(matches) != 1:
        raise TargetSelectionError(
            "Il target di recupero non è disponibile in modo univoco."
        )
    resolution = matches[0]
    candidate = resolution.get("candidate")
    canonical_target_candidate(candidate)
    selection = {
        "apiVersion": TARGET_SCAN_API_VERSION,
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
    return selection, resolution


def _valid_ephemeral_id(value: object, prefix: str) -> bool:
    if not isinstance(value, str) or not value.startswith(f"{prefix}:"):
        return False
    digest = value.removeprefix(f"{prefix}:")
    return len(digest) == 64 and all(
        character in "0123456789abcdef" for character in digest
    )


def select_installed_target(
    request: dict[str, object], deadline: float | None = None
) -> dict[str, object]:
    if OFFLINE_HELPER_ENABLED:
        _check_deadline(deadline)
        result = _privileged_helper_call("select", request)
        if not isinstance(result, dict):
            raise TargetSelectionError(
                "Risposta privilegiata di selezione non valida.", status=503
            )
        return result
    _check_deadline(deadline)
    if set(request) != {"scanFingerprint", "targetId"}:
        raise TargetSelectionError(
            "Richiesta di selezione del target non valida.", status=400
        )
    requested_fingerprint = request["scanFingerprint"]
    requested_target = request["targetId"]
    if not _valid_ephemeral_id(
        requested_fingerprint, "scan"
    ) or not _valid_ephemeral_id(requested_target, "target"):
        raise TargetSelectionError(
            "Richiesta di selezione del target non valida.", status=400
        )

    _check_deadline(deadline)
    snapshot = (
        installed_targets()
        if deadline is None
        else installed_targets(deadline)
    )
    _check_deadline(deadline)
    if snapshot["scanFingerprint"] != requested_fingerprint:
        raise TargetSelectionError(
            "La topologia dei dischi è cambiata; ripetere la selezione."
        )
    candidates = snapshot["candidates"]
    if not isinstance(candidates, list):
        raise TargetScanError("Risposta normalizzata dei target non valida.")
    selected = next(
        (
            candidate
            for candidate in candidates
            if isinstance(candidate, dict)
            and candidate.get("targetId") == requested_target
            and candidate.get("selectionEligible") is True
        ),
        None,
    )
    if selected is None:
        raise TargetSelectionError(
            "Il target non è più disponibile in modalità Observe; ripetere la selezione."
        )
    selection = {
        "apiVersion": TARGET_SCAN_API_VERSION,
        "status": "observe-target-validated",
        "scanFingerprint": snapshot["scanFingerprint"],
        "target": selected,
        "claims": {
            "installedOsConfirmed": False,
            "filesystemContentInspected": False,
            "mountOperationPerformed": False,
            "mutationPerformed": False,
        },
    }
    _check_deadline(deadline)
    return selection


def inspect_installed_target(request: dict[str, object]) -> dict[str, object]:
    if set(request) != {"scanFingerprint", "targetId"}:
        raise PrivilegedHelperError(
            {
                "code": "invalid-inspection-request",
                "message": "Richiesta di ispezione del target non valida.",
                "retryable": False,
                "claims": {
                    field: False for field in OFFLINE_INSPECTION_CLAIM_FIELDS
                },
            },
            400,
        )
    if not _valid_ephemeral_id(
        request.get("scanFingerprint"), "scan"
    ) or not _valid_ephemeral_id(request.get("targetId"), "target"):
        raise PrivilegedHelperError(
            {
                "code": "invalid-inspection-request",
                "message": "Richiesta di ispezione del target non valida.",
                "retryable": False,
                "claims": {
                    field: False for field in OFFLINE_INSPECTION_CLAIM_FIELDS
                },
            },
            400,
        )
    result = _privileged_helper_call("inspect", request)
    if not isinstance(result, dict):
        raise BrokerError("Risposta privilegiata di ispezione non valida.")
    return result


def is_identity_observation(collector: str) -> bool:
    return (
        "hostname" in collector
        or "block.inventory" in collector
        or collector.endswith(".disks")
        or collector.endswith(".system")
        or collector.endswith(".storage.identity")
    )


def inventory_fingerprint(observations: list[dict[str, object]]) -> str:
    canonical = "\0".join(
        f"{item['collector']}\0{item['output']}"
        for item in observations
        if isinstance(item.get("collector"), str)
        and is_identity_observation(str(item["collector"]))
    )
    return f"sha256:{hashlib.sha256(canonical.encode()).hexdigest()}"


def valid_fingerprint(value: object) -> bool:
    if not isinstance(value, str) or not value.startswith("sha256:"):
        return False
    digest = value.removeprefix("sha256:")
    return len(digest) == 64 and all(character in "0123456789abcdef" for character in digest)


def validate_rescue_target_reference(value: object) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != RESCUE_TARGET_REFERENCE_FIELDS:
        raise BrokerError("Selezione del target Rescue non valida.")
    scan_fingerprint = value.get("scanFingerprint")
    target_id = value.get("targetId")
    if not _valid_ephemeral_id(
        scan_fingerprint, "scan"
    ) or not _valid_ephemeral_id(target_id, "target"):
        raise BrokerError("Selezione del target Rescue non valida.")
    if not isinstance(scan_fingerprint, str) or not isinstance(target_id, str):
        raise BrokerError("Selezione del target Rescue non valida.")
    return {"scanFingerprint": scan_fingerprint, "targetId": target_id}


def validate_observe_request(
    request: dict[str, object]
) -> tuple[str, dict[str, str]]:
    if set(request) != OBSERVE_AUTHORIZATION_FIELDS:
        raise BrokerError("Richiesta al broker non valida.")
    if request.get("action") != "system.observe.noop":
        raise BrokerError("Azione non consentita dal broker locale.")
    session_id = request.get("sessionId")
    plan_id = request.get("planId")
    fingerprint = request.get("targetFingerprint")
    sequence = request.get("sequence")
    if (
        not isinstance(session_id, str)
        or not session_id.strip()
        or len(session_id) > 128
        or not isinstance(plan_id, str)
        or not plan_id.strip()
        or len(plan_id) > 128
        or not isinstance(fingerprint, str)
        or not valid_fingerprint(fingerprint)
        or not isinstance(sequence, int)
        or isinstance(sequence, bool)
        or sequence <= 0
    ):
        raise BrokerError("Richiesta al broker non valida.")
    return session_id, validate_rescue_target_reference(request.get("rescueTarget"))


def canonical_target_candidate(candidate: object) -> str:
    if not isinstance(candidate, dict) or set(candidate) != TARGET_CANDIDATE_FIELDS:
        raise BrokerError("Candidato target Rescue non valido.")
    target_id = candidate.get("targetId")
    disk_id = candidate.get("diskId")
    source_ref = candidate.get("sourceRef")
    detection_basis = candidate.get("detectionBasis")
    if (
        not _valid_ephemeral_id(target_id, "target")
        or not _valid_ephemeral_id(disk_id, "disk")
        or not isinstance(source_ref, str)
        or not source_ref.startswith("disk-")
        or len(source_ref) > 64
        or not source_ref.isascii()
        or any(
            character not in "abcdefghijklmnopqrstuvwxyz0123456789-/"
            for character in source_ref
        )
        or candidate.get("osFamilyHint")
        not in {"linux", "macos", "unknown", "unknown-encrypted", "windows"}
        or candidate.get("confidence") != "low"
        or candidate.get("status") != "unverified-installation-candidate"
        or candidate.get("inspectionMode") != "metadata-only-no-mount"
        or candidate.get("selectionEligible") is not True
        or not isinstance(candidate.get("requiresUnlock"), bool)
        or not isinstance(detection_basis, list)
        or not detection_basis
        or len(detection_basis) > 8
        or any(
            not isinstance(item, str)
            or not item
            or len(item) > 64
            or not item.isascii()
            or any(
                character not in "abcdefghijklmnopqrstuvwxyz0123456789-"
                for character in item
            )
            for item in detection_basis
        )
        or detection_basis != sorted(set(detection_basis))
    ):
        raise BrokerError("Candidato target Rescue non valido.")
    return json.dumps(
        candidate, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    )


def validate_target_selection(
    selection: object, rescue_target: dict[str, str]
) -> dict[str, object]:
    if not isinstance(selection, dict) or set(selection) != TARGET_SELECTION_FIELDS:
        raise BrokerError("Rivalidazione del target Rescue non valida.")
    if (
        selection.get("apiVersion") != TARGET_SCAN_API_VERSION
        or selection.get("status") != "observe-target-validated"
        or selection.get("scanFingerprint") != rescue_target["scanFingerprint"]
    ):
        raise BrokerError("Rivalidazione del target Rescue non valida.")
    claims = selection.get("claims")
    if (
        not isinstance(claims, dict)
        or set(claims) != TARGET_SELECTION_CLAIM_FIELDS
        or any(claims.get(field) is not False for field in TARGET_SELECTION_CLAIM_FIELDS)
    ):
        raise BrokerError("Rivalidazione del target Rescue non valida.")
    candidate = selection.get("target")
    canonical_target_candidate(candidate)
    if not isinstance(candidate, dict) or candidate.get("targetId") != rescue_target["targetId"]:
        raise BrokerError("Rivalidazione del target Rescue non valida.")
    return candidate


def rescue_target_fingerprint(
    runtime_inventory_fingerprint: str,
    scan_fingerprint: str,
    candidate: dict[str, object],
) -> str:
    """Hash the documented NUL-delimited Rescue target binding."""
    if not valid_fingerprint(
        runtime_inventory_fingerprint
    ) or not _valid_ephemeral_id(scan_fingerprint, "scan"):
        raise BrokerError("Fingerprint composito del target Rescue non valido.")
    candidate_json = canonical_target_candidate(candidate)
    target_id = candidate.get("targetId")
    if not isinstance(target_id, str):
        raise BrokerError("Fingerprint composito del target Rescue non valido.")
    material = "\0".join(
        (
            RESCUE_TARGET_FINGERPRINT_DOMAIN,
            runtime_inventory_fingerprint,
            scan_fingerprint,
            target_id,
            candidate_json,
        )
    )
    return f"sha256:{hashlib.sha256(material.encode('utf-8')).hexdigest()}"


def canonical_target_selection(selection: object) -> str:
    return json.dumps(
        selection, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    )


def authorize_observe(
    request: dict[str, object], deadline: float | None = None
) -> None:
    started = time.monotonic()
    internal_deadline = started + AUTHORIZE_DEADLINE_SECONDS
    deadline = internal_deadline if deadline is None else min(deadline, internal_deadline)
    _check_deadline(deadline)
    session_id, rescue_target = validate_observe_request(request)
    _check_deadline(deadline)
    selection_before = select_installed_target(rescue_target, deadline=deadline)
    _check_deadline(deadline)
    candidate_before = validate_target_selection(selection_before, rescue_target)
    _check_deadline(deadline)
    observations = inventory(deadline=deadline)
    _check_deadline(deadline)
    selection_after = select_installed_target(rescue_target, deadline=deadline)
    _check_deadline(deadline)
    candidate_after = validate_target_selection(selection_after, rescue_target)
    if (
        canonical_target_selection(selection_before)
        != canonical_target_selection(selection_after)
        or canonical_target_candidate(candidate_before)
        != canonical_target_candidate(candidate_after)
    ):
        raise BrokerError("Il target Rescue è cambiato durante la rivalidazione.")
    identity_observations = [
        item
        for item in observations
        if isinstance(item.get("collector"), str)
        and is_identity_observation(str(item["collector"]))
    ]
    if not identity_observations or any(
        item.get("success") is not True or item.get("truncated") is True
        for item in identity_observations
    ):
        raise BrokerError("Inventario di identità incompleto; ripetere la raccolta.")
    runtime_fingerprint = inventory_fingerprint(observations)
    current_fingerprint = rescue_target_fingerprint(
        runtime_fingerprint,
        rescue_target["scanFingerprint"],
        candidate_before,
    )
    if request.get("targetFingerprint") != current_fingerprint:
        raise BrokerError("Il target è cambiato: piano annullato, ripetere la diagnosi.")
    _check_deadline(deadline)
    remaining = _remaining_seconds(deadline)
    if remaining is None or not BROKER_LOCK.acquire(timeout=remaining):
        raise TimeoutError("Deadline dell'autorizzazione Rescue scaduta.")
    try:
        # Decisive anti-ghost check: no session can be created or advanced after
        # the request's monotonic end-to-end authorization budget has expired.
        _check_deadline(deadline)
        if session_id not in BROKERS and len(BROKERS) >= MAX_BROKER_SESSIONS:
            raise BrokerError("Limite delle sessioni locali raggiunto; riavviare KernAid.")
        broker = BROKERS.get(session_id)
        if broker is None:
            pending_broker = ObserveBroker(current_fingerprint, rescue_target)
            pending_broker.authorize(request, deadline=deadline)
            _check_deadline(deadline)
            BROKERS[session_id] = pending_broker
        else:
            broker.authorize(request, deadline=deadline)
    finally:
        BROKER_LOCK.release()


class RescueHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args: object, **kwargs: object) -> None:
        self._request_started = 0.0
        self._request_deadline_lock = threading.Lock()
        self._request_deadline_generation = 0
        self._request_deadline_timer: threading.Timer | None = None
        super().__init__(*args, directory=WEB_ROOT, **kwargs)

    def _arm_request_deadline(self, maximum_seconds: float) -> None:
        with self._request_deadline_lock:
            self._request_deadline_generation += 1
            generation = self._request_deadline_generation
            if self._request_deadline_timer is not None:
                self._request_deadline_timer.cancel()
            remaining = max(
                0.0,
                self._request_started + maximum_seconds - time.monotonic(),
            )

            def expire_request() -> None:
                with self._request_deadline_lock:
                    if generation != self._request_deadline_generation:
                        return
                try:
                    self.connection.shutdown(2)
                except OSError:
                    pass
                self.connection.close()

            deadline = threading.Timer(remaining, expire_request)
            deadline.daemon = True
            self._request_deadline_timer = deadline
            deadline.start()

    def _cancel_request_deadline(self) -> None:
        with self._request_deadline_lock:
            self._request_deadline_generation += 1
            if self._request_deadline_timer is not None:
                self._request_deadline_timer.cancel()
                self._request_deadline_timer = None

    def handle(self) -> None:
        self._request_started = time.monotonic()
        self.authorization_deadline = (
            self._request_started + AUTHORIZE_DEADLINE_SECONDS
        )
        self._arm_request_deadline(REQUEST_DEADLINE_SECONDS)
        try:
            try:
                super().handle()
            except (BrokenPipeError, ConnectionResetError):
                pass
        finally:
            self._cancel_request_deadline()

    def local_authority(self) -> bool:
        return self.headers.get("Host") in ALLOWED_HOSTS

    def same_site_request(self) -> bool:
        origin = self.headers.get("Origin")
        fetch_site = self.headers.get("Sec-Fetch-Site")
        return (origin is None or origin in ALLOWED_ORIGINS) and fetch_site in {
            None,
            "none",
            "same-origin",
        }

    def end_headers(self) -> None:
        # These headers protect both the immutable Desk bundle and API error
        # responses.  The Tauri shell loads this exact loopback origin without
        # granting it any native capability.
        self.send_header("Content-Security-Policy", CONTENT_SECURITY_POLICY)
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header(
            "Permissions-Policy",
            "accelerometer=(), camera=(), geolocation=(), gyroscope=(), "
            "microphone=(), payment=(), usb=()",
        )
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        super().end_headers()

    def _application_deadline(self) -> float:
        self._arm_request_deadline(APPLICATION_REQUEST_DEADLINE_SECONDS)
        return self._request_started + APPLICATION_REQUEST_DEADLINE_SECONDS - 1

    def _send_application_json(
        self, status: int, value: dict[str, object]
    ) -> None:
        body = json.dumps(
            value,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        if status == 429:
            self.send_header("Retry-After", "1")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_application_failure(self, error: ApplicationRelayError) -> None:
        body: dict[str, object] = {
            "apiVersion": APPLICATION_HTTP_API_VERSION,
            "error": error.code,
        }
        self._send_application_json(error.status, body)

    def _application_post_headers(self) -> bool:
        hosts = self.headers.get_all("Host", [])
        origins = self.headers.get_all("Origin", [])
        fetch_sites = self.headers.get_all("Sec-Fetch-Site", [])
        if len(hosts) != 1 or hosts[0] not in ALLOWED_HOSTS:
            self.send_error(421)
            return False
        if (
            len(origins) != 1
            or origins[0] not in ALLOWED_ORIGINS
            or origins[0] != f"http://{hosts[0]}"
        ):
            self.send_error(403)
            return False
        if len(fetch_sites) > 1 or (
            fetch_sites and fetch_sites[0] not in {"none", "same-origin"}
        ):
            self.send_error(403)
            return False
        if self.headers.get_all("Transfer-Encoding") or self.headers.get_all(
            "Content-Encoding"
        ):
            self._send_application_failure(
                ApplicationRelayError("INVALID_REQUEST", 400)
            )
            return False
        if self.headers.get_all("Content-Type", []) != ["application/json"]:
            self._send_application_failure(
                ApplicationRelayError("INVALID_REQUEST", 415)
            )
            return False
        return True

    def _application_post_body(self) -> dict[str, object]:
        lengths = self.headers.get_all("Content-Length", [])
        if (
            len(lengths) != 1
            or not lengths[0].isascii()
            or not lengths[0].isdigit()
        ):
            raise ApplicationRelayError("INVALID_REQUEST", 400)
        length = int(lengths[0])
        if not 2 <= length <= MAX_APPLICATION_HTTP_REQUEST_BYTES:
            raise ApplicationRelayError(
                "INVALID_REQUEST", 413 if length > 0 else 400
            )
        encoded = self.rfile.read(length)
        if len(encoded) != length:
            raise ApplicationRelayError("INVALID_REQUEST", 400)
        try:
            return _strict_json_object(
                encoded, MAX_APPLICATION_HTTP_REQUEST_BYTES
            )
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
            raise ApplicationRelayError("INVALID_REQUEST", 400) from error

    def _handle_application_get(self) -> bool:
        if self.path == "/api/rescue/vault/status":
            deadline = self._application_deadline()
            try:
                response = _application_status(deadline)
                payload = response["payload"]
                self._send_application_json(
                    200,
                    {
                        "apiVersion": APPLICATION_HTTP_API_VERSION,
                        "stateVersion": response["stateVersion"],
                        "vaultState": payload["vaultState"],
                    },
                )
            except ApplicationRelayError as error:
                self._send_application_failure(error)
            return True

        if self.path == "/api/rescue/reports":
            deadline = self._application_deadline()
            try:
                response, descriptor = _versioned_application_read(
                    "report.list", {}, deadline
                )
                if descriptor is not None:
                    os.close(descriptor)
                    raise ApplicationRelayError("INVALID_FRAME", 502)
                payload = response["payload"]
                reports = payload.get("reports")
                if (
                    set(payload) != {"reports"}
                    or not isinstance(reports, list)
                    or len(reports) > 256
                ):
                    raise ApplicationRelayError("INVALID_FRAME", 502)
                seen: set[str] = set()
                for report in reports:
                    summary = _application_report_summary(report)
                    report_id = str(summary["reportId"])
                    if report_id in seen:
                        raise ApplicationRelayError("INVALID_FRAME", 502)
                    seen.add(report_id)
                self._send_application_json(
                    200,
                    {
                        "apiVersion": APPLICATION_HTTP_API_VERSION,
                        "stateVersion": response["stateVersion"],
                        "reports": reports,
                    },
                )
            except ApplicationRelayError as error:
                self._send_application_failure(error)
            return True

        prefix = "/api/rescue/reports/"
        if not self.path.startswith(prefix):
            return False
        report_id = self.path.removeprefix(prefix)
        if APPLICATION_REPORT_ID.fullmatch(report_id) is None:
            self._send_application_failure(
                ApplicationRelayError("INVALID_REQUEST", 400)
            )
            return True
        deadline = self._application_deadline()
        descriptor: int | None = None
        try:
            response, descriptor = _versioned_application_read(
                "report.get", {"reportId": report_id}, deadline
            )
            payload = response["payload"]
            if set(payload) != {"report", "output"}:
                raise ApplicationRelayError("INVALID_FRAME", 502)
            report = _application_report_summary(payload["report"])
            output = payload["output"]
            if (
                report["reportId"] != report_id
                or not isinstance(output, dict)
                or set(output) != {"type", "size"}
                or output.get("type") != "signed-report-envelope-pipe"
                or output.get("size") != report["envelopeSize"]
                or descriptor is None
            ):
                raise ApplicationRelayError("INVALID_FRAME", 502)
            envelope = _read_application_output(
                descriptor,
                int(report["envelopeSize"]),
                str(report["envelopeSha256"]),
                deadline,
            )
            self.send_response(200)
            self.send_header(
                "Content-Type", "application/vnd.kernaid.signed-report+json"
            )
            self.send_header("Cache-Control", "no-store")
            self.send_header(
                "X-KernAid-Envelope-Sha256", str(report["envelopeSha256"])
            )
            self.send_header(
                "ETag", f'"sha256-{report["envelopeSha256"]}"'
            )
            self.send_header("Content-Length", str(len(envelope)))
            self.end_headers()
            self.wfile.write(envelope)
        except ApplicationRelayError as error:
            self._send_application_failure(error)
        finally:
            if descriptor is not None:
                os.close(descriptor)
        return True

    def _handle_application_post(self) -> bool:
        if self.path not in {
            "/api/rescue/audit-append",
            "/api/rescue/report-persist",
        }:
            return False
        if not self._application_post_headers():
            return True
        deadline = self._application_deadline()
        try:
            request = self._application_post_body()
            expected = request.get("expectedStateVersion")
            if not _valid_application_state_version(expected):
                raise ApplicationRelayError("INVALID_REQUEST", 400)
            if self.path == "/api/rescue/audit-append":
                outcome = request.get("outcome")
                error = request.get("error")
                if (
                    set(request)
                    not in (
                        {
                            "expectedStateVersion",
                            "sequence",
                            "event",
                            "outcome",
                        },
                        {
                            "expectedStateVersion",
                            "sequence",
                            "event",
                            "outcome",
                            "error",
                        },
                    )
                    or not isinstance(request.get("sequence"), int)
                    or isinstance(request.get("sequence"), bool)
                    or not 1
                    <= int(request["sequence"])
                    <= MAX_AUDIT_SEQUENCE
                    or not isinstance(request.get("event"), str)
                    or request.get("event") not in APPLICATION_AUDIT_EVENTS
                    or not isinstance(outcome, str)
                    or outcome not in APPLICATION_AUDIT_OUTCOMES
                    or not (
                        outcome == "succeeded" and "error" not in request
                        or outcome != "succeeded"
                        and isinstance(error, str)
                        and error in APPLICATION_VAULT_ERROR_TOKENS
                    )
                ):
                    raise ApplicationRelayError("INVALID_REQUEST", 400)
                payload = {
                    key: value
                    for key, value in request.items()
                    if key != "expectedStateVersion"
                }
                response, descriptor = relay_application_request(
                    "audit.append", int(expected), payload, deadline
                )
                if descriptor is not None:
                    os.close(descriptor)
                    raise ApplicationRelayError("INVALID_FRAME", 502)
                result = response["payload"]
                if (
                    set(result) != {"sequence"}
                    or result.get("sequence") != request["sequence"]
                ):
                    raise ApplicationRelayError("INVALID_FRAME", 502)
                self._send_application_json(
                    200,
                    {
                        "apiVersion": APPLICATION_HTTP_API_VERSION,
                        "stateVersion": response["stateVersion"],
                        "sequence": result["sequence"],
                    },
                )
                return True

            if set(request) != {
                "expectedStateVersion",
                "reportId",
                "payloadSha256",
                "reportJson",
            }:
                raise ApplicationRelayError("INVALID_REQUEST", 400)
            report_id = request.get("reportId")
            payload_sha256 = request.get("payloadSha256")
            report_json = request.get("reportJson")
            if (
                not isinstance(report_id, str)
                or APPLICATION_REPORT_ID.fullmatch(report_id) is None
                or not isinstance(payload_sha256, str)
                or APPLICATION_SHA256.fullmatch(payload_sha256) is None
                or not isinstance(report_json, str)
            ):
                raise ApplicationRelayError("INVALID_REQUEST", 400)
            try:
                report_bytes = report_json.encode("utf-8")
            except UnicodeEncodeError as error:
                raise ApplicationRelayError("INVALID_REQUEST", 400) from error
            if not 2 <= len(report_bytes) <= MAX_APPLICATION_REPORT_BYTES:
                raise ApplicationRelayError(
                    "REPORT_TOO_LARGE" if len(report_bytes) > 1 else "INVALID_REQUEST",
                    413 if len(report_bytes) > 1 else 400,
                )
            if not hmac.compare_digest(
                hashlib.sha256(report_bytes).hexdigest(), payload_sha256
            ):
                raise ApplicationRelayError("INVALID_REQUEST", 400)
            try:
                report = _strict_json_object(
                    report_bytes, MAX_APPLICATION_REPORT_BYTES
                )
                _preliminary_application_report(report)
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
                raise ApplicationRelayError("INVALID_REQUEST", 400) from error
            response = relay_application_report(
                int(expected),
                report_id,
                payload_sha256,
                report_bytes,
                deadline,
            )
            report = _application_report_summary(response["payload"])
            if report["reportId"] != report_id:
                raise ApplicationRelayError("INVALID_FRAME", 502)
            self._send_application_json(
                200,
                {
                    "apiVersion": APPLICATION_HTTP_API_VERSION,
                    "stateVersion": response["stateVersion"],
                    "report": report,
                },
            )
        except ApplicationRelayError as error:
            self._send_application_failure(error)
        return True

    def do_GET(self) -> None:
        if not self.local_authority():
            self.send_error(421)
            return
        if not self.same_site_request():
            self.send_error(403)
            return
        if self._handle_application_get():
            return
        if self.path == "/api/inventory":
            try:
                body = json.dumps(inventory()).encode()
                status = 200
            except InventoryBusy as error:
                body = json.dumps({"error": str(error)}).encode()
                status = 429
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            if status == 429:
                self.send_header("Retry-After", "1")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/api/rescue/installed-targets":
            try:
                body = json.dumps(
                    installed_targets(), ensure_ascii=True, separators=(",", ":")
                ).encode()
                status = 200
            except TargetScanBusy as error:
                body = json.dumps({"error": str(error)}).encode()
                status = 429
            except TargetScanError as error:
                body = json.dumps({"error": str(error)}).encode()
                status = 503
            except PrivilegedHelperError as error:
                body = json.dumps(
                    {"error": error.error},
                    ensure_ascii=True,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
                status = error.status
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            if status == 429:
                self.send_header("Retry-After", "1")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        super().do_GET()

    def do_POST(self) -> None:
        if self._handle_application_post():
            return
        authorization_deadline = (
            self.authorization_deadline
            if self.path == "/api/authorize-observe"
            else None
        )
        provider_request = self.path == "/api/rescue/provider/openai"
        if provider_request:
            hosts = self.headers.get_all("Host", [])
            origins = self.headers.get_all("Origin", [])
            fetch_sites = self.headers.get_all("Sec-Fetch-Site", [])
            if len(hosts) != 1 or hosts[0] not in ALLOWED_HOSTS:
                self.send_error(421)
                return
            if (
                len(origins) != 1
                or origins[0] not in ALLOWED_ORIGINS
                or origins[0] != f"http://{hosts[0]}"
            ):
                self.send_error(403)
                return
            if len(fetch_sites) > 1 or (
                fetch_sites and fetch_sites[0] not in {"none", "same-origin"}
            ):
                self.send_error(403)
                return
        else:
            if not self.local_authority():
                self.send_error(421)
                return
            if self.headers.get("Origin") not in ALLOWED_ORIGINS:
                self.send_error(403)
                return
        if self.path not in {
            "/api/authorize-observe",
            "/api/rescue/inspect-installed-target",
            "/api/rescue/provider/openai",
            "/api/rescue/select-installed-target",
        }:
            self.send_error(405)
            return
        if provider_request:
            self._arm_request_deadline(PROVIDER_REQUEST_DEADLINE_SECONDS)
            if self.headers.get_all("Transfer-Encoding") or self.headers.get_all(
                "Content-Encoding"
            ):
                self.send_error(400)
                return
            content_types = self.headers.get_all("Content-Type", [])
            if content_types != ["application/json"]:
                self.send_error(415)
                return
        elif self.headers.get_content_type() != "application/json":
            self.send_error(415)
            return
        content_lengths = self.headers.get_all("Content-Length", [])
        if provider_request and len(content_lengths) != 1:
            self.send_error(400)
            return
        try:
            content_length_value = (
                content_lengths[0]
                if provider_request
                else self.headers.get("Content-Length", "0")
            )
            if content_length_value is None or (
                provider_request
                and (
                    not content_length_value.isascii()
                    or not content_length_value.isdigit()
                )
            ):
                raise ValueError
            content_length = int(content_length_value)
        except ValueError:
            self.send_error(400)
            return
        maximum_request_bytes = (
            MAX_PROVIDER_REQUEST_FRAME_BYTES
            if provider_request
            else MAX_REQUEST_BYTES
        )
        if content_length <= 0 or content_length > maximum_request_bytes:
            self.send_error(413)
            return
        try:
            encoded = self.rfile.read(content_length)
            if len(encoded) != content_length:
                self.send_error(400)
                return
            if provider_request:
                body = relay_openai_provider(
                    encoded,
                    self._request_started + PROVIDER_SOCKET_TIMEOUT_SECONDS,
                )
                status = 200
                request = None
            else:
                request = json.loads(encoded)
            if not provider_request and not isinstance(request, dict):
                if self.path == "/api/rescue/inspect-installed-target":
                    raise PrivilegedHelperError(
                        {
                            "code": "invalid-inspection-request",
                            "message": "Richiesta di ispezione del target non valida.",
                            "retryable": False,
                            "claims": {
                                field: False
                                for field in OFFLINE_INSPECTION_CLAIM_FIELDS
                            },
                        },
                        400,
                    )
                if self.path == "/api/rescue/select-installed-target":
                    raise TargetSelectionError(
                        "Richiesta di selezione del target non valida.", status=400
                    )
                raise BrokerError("Richiesta al broker non valida.")
            if provider_request:
                pass
            elif self.path == "/api/authorize-observe":
                authorize_observe(request, deadline=authorization_deadline)
                body = b'{"status":"observed"}'
            elif self.path == "/api/rescue/inspect-installed-target":
                body = json.dumps(
                    inspect_installed_target(request),
                    ensure_ascii=True,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
            else:
                body = json.dumps(
                    select_installed_target(request),
                    ensure_ascii=True,
                    separators=(",", ":"),
                ).encode()
            status = 200
        except TimeoutError:
            body = json.dumps({"error": "Timeout della richiesta locale."}).encode()
            status = 408
        except ProviderRelayError as error:
            body = json.dumps(
                {"error": {"code": error.code}},
                ensure_ascii=True,
                separators=(",", ":"),
            ).encode()
            status = error.status
        except (json.JSONDecodeError, UnicodeDecodeError):
            body = json.dumps({"error": "JSON non valido."}).encode()
            status = 400
        except BrokerError as error:
            body = json.dumps({"error": str(error)}).encode()
            status = 409
        except PrivilegedHelperError as error:
            body = json.dumps(
                {"error": error.error},
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
            status = error.status
        except TargetSelectionError as error:
            body = json.dumps({"error": str(error)}).encode()
            status = error.status
        except InventoryBusy as error:
            body = json.dumps({"error": str(error)}).encode()
            status = 429
        except TargetScanBusy as error:
            body = json.dumps({"error": str(error)}).encode()
            status = 429
        except TargetScanError as error:
            body = json.dumps({"error": str(error)}).encode()
            status = 503
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        if status == 429:
            self.send_header("Retry-After", "1")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *args: object) -> None:
        return


class BoundedThreadingHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = MAX_SERVER_THREADS

    def __init__(self, *args: object, **kwargs: object) -> None:
        self.slots = threading.BoundedSemaphore(MAX_SERVER_THREADS)
        super().__init__(*args, **kwargs)

    def get_request(self) -> tuple[object, object]:
        request, client_address = super().get_request()
        request.settimeout(SOCKET_TIMEOUT_SECONDS)
        return request, client_address

    def process_request(self, request: object, client_address: object) -> None:
        if not self.slots.acquire(blocking=False):
            request.close()  # type: ignore[attr-defined]
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request: object, client_address: object) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()


if __name__ == "__main__":
    BoundedThreadingHTTPServer(("127.0.0.1", 4173), RescueHandler).serve_forever()
