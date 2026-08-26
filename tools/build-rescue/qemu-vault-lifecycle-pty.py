#!/usr/bin/env python3
"""Bounded PTY/QMP controller for the Rescue vault lifecycle smoke.

The controller deliberately never persists or reproduces QEMU serial/process output.
Its only output is a closed, machine-validated attestation or failure line.
Vault passphrases arrive on already-open file descriptors and are never added
to a child argv, environment, firmware configuration, or diagnostic.
"""

from __future__ import annotations

import argparse
import ctypes
import dataclasses
import errno
import fcntl
import json
import os
import re
import selectors
import signal
import socket
import stat
import struct
import subprocess
import sys
import threading
import time
import tty
from pathlib import Path
from typing import Callable, Sequence


SERIAL_LIMIT = 2 * 1024 * 1024
QEMU_OUTPUT_LIMIT = 128 * 1024
QMP_LIMIT = 128 * 1024
SECRET_BYTES = 64
LOGIN_SECRET_LIMIT = 128
LIVE_CONFIG_LIMIT = 64 * 1024
RATE_LIMIT_WAIT_SECONDS = 2.25
QEMU_START_TIMEOUT_SECONDS = 15.0
READINESS_TIMEOUT_SECONDS = 1200.0
CONTROLLER_TIMEOUT_SECONDS = 1800
ACPI_SHUTDOWN_SECONDS = 180.0
SHUTDOWN_RESERVE_SECONDS = ACPI_SHUTDOWN_SECONDS + 15.0
PROCESS_CLEANUP_SECONDS = 5.0
PROBE_OUTPUT_LIMIT = 256
PROBE_STDERR_LIMIT = 256
PROBE_TIMEOUT_SECONDS = 620.0
CODEX_STATUS_SOCKET_TIMEOUT_SECONDS = 180.0
CODEX_STATUS_PROOF_TIMEOUT_SECONDS = 195.0

LOOP_CLR_FD = 0x4C01
LOOP_GET_STATUS64 = 0x4C05
LO_FLAGS_READ_ONLY = 1
LO_FLAGS_AUTOCLEAR = 4
LOOP_INFO64 = struct.Struct("=QQQQQIIII64s64s32sQQ")

READY_LINE = b"KERNAID_RESCUE_READY"
NOT_READY_LINE_PREFIX = b"KERNAID_RESCUE_NOT_READY:"
LOGIN_OK_LINE = b"KERNAID_VAULT_LOGIN_V1 uid=1000 user=kernaid group=true"
LOGIN_FAIL_LINE = b"KERNAID_VAULT_LOGIN_V1 invalid=true"
# Interactive Bash places this one bracketed-paste disable sequence between an
# echoed command and its first output line. Only trusted shell-emitted markers
# opt in to this exact optional prefix at a line boundary.
BRACKETED_PASTE_DISABLE_PREFIX = b"\x1b[?2004l\r"
_TRUSTED_SHELL_MARKER_START = (
    rb"(?:^|\r?\n)(?:" + re.escape(BRACKETED_PASTE_DISABLE_PREFIX) + rb")?"
)
# Unlike the generic transcript patterns above, a proof transaction advances
# its cursor past the preceding newline.  Keep that boundary zero-width so an
# immediately adjacent marker remains visible from the exact cursor.
_TRUSTED_SHELL_ZERO_WIDTH_START = (
    rb"(?:\A|(?<=\n))(?:(?:" + re.escape(BRACKETED_PASTE_DISABLE_PREFIX) + rb"))?"
)
NOT_READY_PREFIX_PATTERN = re.compile(
    rb"(?:^|\r?\n)" + re.escape(NOT_READY_LINE_PREFIX)
)
NOT_READY_SCAN_OVERLAP = len(NOT_READY_LINE_PREFIX) + 2
READY_RESULT_PATTERN = re.compile(
    rb"(?:^|\r?\n)(?:"
    + re.escape(READY_LINE)
    + rb"|kernaid-rescue login: "
    + re.escape(READY_LINE)
    + rb")\r?\n"
)
LOGIN_RESULT_PATTERN = re.compile(
    _TRUSTED_SHELL_MARKER_START
    + rb"(KERNAID_VAULT_LOGIN_V1 (?:uid=1000 user=kernaid group=true|invalid=true))"
    + rb"\r?\n"
)
RUNTIME_RESULT_PATTERN = re.compile(
    _TRUSTED_SHELL_MARKER_START
    + rb"(KERNAID_VAULT_RUNTIME_V1 [^\r\n]{1,1024})\r?\n"
)
PROVIDER_PROOF_UI_STAGES = (
    "ui-diagnose-unconfigured",
    "ui-status-configured",
)
PROVIDER_PROOF_CLOSED_STAGES = PROVIDER_PROOF_UI_STAGES + (
    "codex-status",
    "production-status",
    "normal-release",
    "signed-report",
    "hold-kill",
    "post-fault",
)
PROVIDER_PROOF_UI_CHECKPOINTS = (
    "ui-identity",
    "socket-baseline",
    "http-response",
    "relay-busy",
    "socket-accounting",
    "quiescence",
    "envelope",
    "outcome",
    "outcome-busy",
    "outcome-invalid-request",
    "outcome-invalid-response",
    "outcome-request-too-large",
    "outcome-response-too-large",
    "outcome-timeout",
    "outcome-transport",
    "outcome-upstream",
)
PROVIDER_PROOF_CODEX_CHECKPOINTS = (
    "unit",
    "socket",
    "accepted",
    "connection-drain",
    "connect",
    "send",
    "receive",
    "receive-active",
    "receive-ended",
    "receive-state",
    "frame",
    "decode",
    "response",
    "server-transport",
    "vault-locked",
    "vault-unconfigured",
    "busy",
    "reboot-required",
    "transport",
    "cli-unavailable",
    "cli-failed",
    "timed-out",
    "unsafe-home",
    "unsafe-executable",
)
PROVIDER_PROOF_CODEX_REMOTE_ERRORS = (
    "vault-locked",
    "vault-unconfigured",
    "busy",
    "reboot-required",
    "transport",
    "cli-unavailable",
    "cli-failed",
    "timed-out",
    "unsafe-home",
    "unsafe-executable",
)
PROVIDER_PROOF_UI_ERROR_CHECKPOINTS = (
    ("busy", "outcome-busy"),
    ("invalid_request", "outcome-invalid-request"),
    ("invalid_response", "outcome-invalid-response"),
    ("request_too_large", "outcome-request-too-large"),
    ("response_too_large", "outcome-response-too-large"),
    ("timeout", "outcome-timeout"),
    ("transport", "outcome-transport"),
    ("upstream", "outcome-upstream"),
)
PROVIDER_PROOF_SUCCESS_PREFIX = b"KERNAID_QEMU_PROVIDER_PROOF_V1"
PROVIDER_PROOF_FAILURE_PREFIX = b"KERNAID_QEMU_PROVIDER_PROOF_FAILURE_V1"
CAP_SYS_ADMIN_ONLY = "0000000000200000"
CAP_SYS_ADMIN_AND_KILL = "0000000000200020"
ZERO_CAPS = "0000000000000000"

FAILURE_PREFIX = "KERNAID_QEMU_VAULT_LIFECYCLE_FAILURE_V1"
ATTESTATION_PREFIX = "KERNAID_QEMU_VAULT_LIFECYCLE_BOOT_V1"
TOKEN_RE = re.compile(r"^[a-z0-9-]+$")
DEVICE_ID_RE = re.compile(r"^KA-[0-9a-f]{24}$")
MAX_SAFE_STATE_VERSION = 9_007_199_254_740_991

# Public protocol errors are safe to classify in the sanitized lifecycle
# evidence. Keep this mapping explicit: an unknown or malformed server token
# must retain the generic fail-closed result rather than becoming output.
UNLOCK_REMOTE_FAILURE_CODES = {
    "ABSENT": "absent",
    "UNPROVISIONED": "unprovisioned",
    "LOCKED": "locked",
    "MEDIA_CHANGED": "media-changed",
    "PROFILE_MISMATCH": "profile-mismatch",
    "STALE_STATE": "stale-state",
    "FD_REQUIRED": "fd-required",
    "FD_FORBIDDEN": "fd-forbidden",
    "NOT_AUTHORIZED": "not-authorized",
    "RATE_LIMITED": "rate-limited",
    "BUSY": "busy",
    "PROVIDER_UNCONFIGURED": "provider-unconfigured",
    "REPORT_TOO_LARGE": "report-too-large",
    "IO_FAILED": "io-failed",
    "REBOOT_REQUIRED": "reboot-required",
}

UNLOCK_IO_DIAGNOSTIC_PREFIX = "KERNAID_RESCUE_VAULT_UNLOCK_DIAGNOSTIC_V1"
UNLOCK_IO_DIAGNOSTIC_REASONS = (
    "probe-io",
    "probe-classifier",
    "mapper-name",
    "manager-unsupported-platform",
    "manager-privilege-required",
    "manager-invalid-mapper-name",
    "manager-classifier-unavailable",
    "manager-passphrase-unavailable",
    "manager-unsupported-filesystem",
    "manager-unsafe-mount-root",
    "manager-mount-failed",
    "manager-mount-verification-failed",
    "manager-secure-state-unavailable",
    "manager-tool-unavailable",
    "application-store",
    "device-id",
)
UNLOCK_IO_DIAGNOSTIC_RESULT_PREFIX = "KERNAID_VAULT_UNLOCK_DIAGNOSTIC_V1"
UNLOCK_IO_DIAGNOSTIC_RESULT_PATTERN = re.compile(
    _TRUSTED_SHELL_MARKER_START
    + rb"(KERNAID_VAULT_UNLOCK_DIAGNOSTIC_V1 reason=("
    + rb"|".join(
        re.escape(reason.encode("ascii"))
        for reason in (*UNLOCK_IO_DIAGNOSTIC_REASONS, "diagnostic-unavailable")
    )
    + rb"))\r?\n"
)


class ClosedFailure(Exception):
    """Failure carrying only closed diagnostic tokens."""

    def __init__(self, stage: str, code: str) -> None:
        if TOKEN_RE.fullmatch(stage) is None or TOKEN_RE.fullmatch(code) is None:
            stage, code = "controller", "invalid-diagnostic"
        self.stage = stage
        self.code = code
        super().__init__(f"{stage}:{code}")


class UnlockRemoteFailure(ClosedFailure):
    """Closed remote unlock failure retaining only its safe state version."""

    def __init__(self, code: str, state_version: int) -> None:
        super().__init__("response", code)
        self.state_version = state_version


class CaptureLimitError(Exception):
    pass


class SecretExposureError(Exception):
    pass


def clear_owned_loop_fd(
    loop_fd: int,
    backing_fd: int,
    *,
    expected_number: int,
    expected_offset: int,
    expected_size_limit: int,
    expected_read_only: bool,
) -> None:
    """Validate and clear one loop mapping through the same pinned descriptor."""

    if loop_fd == backing_fd or min(loop_fd, backing_fd) < 3:
        raise ClosedFailure("loop-detach", "descriptor-invalid")
    try:
        loop_status = os.fstat(loop_fd)
        backing_status = os.fstat(backing_fd)
        if (
            not stat.S_ISBLK(loop_status.st_mode)
            or os.major(loop_status.st_rdev) != 7
            or os.minor(loop_status.st_rdev) != expected_number
            or not stat.S_ISREG(backing_status.st_mode)
            or backing_status.st_nlink != 1
        ):
            raise ClosedFailure("loop-detach", "identity-invalid")

        descriptor_flags = fcntl.fcntl(loop_fd, fcntl.F_GETFD)
        fcntl.fcntl(loop_fd, fcntl.F_SETFD, descriptor_flags | fcntl.FD_CLOEXEC)
        backing_flags = fcntl.fcntl(backing_fd, fcntl.F_GETFD)
        fcntl.fcntl(backing_fd, fcntl.F_SETFD, backing_flags | fcntl.FD_CLOEXEC)

        encoded = bytearray(LOOP_INFO64.size)
        try:
            fcntl.ioctl(loop_fd, LOOP_GET_STATUS64, encoded, True)
        except OSError as error:
            raise ClosedFailure("loop-detach", "status-failed") from error
        fields = LOOP_INFO64.unpack(encoded)
        (
            backing_device,
            backing_inode,
            backing_rdevice,
            offset,
            size_limit,
            loop_number,
            encryption_type,
            encryption_key_size,
            loop_flags,
            *_reserved,
        ) = fields
        allowed_flags = LO_FLAGS_READ_ONLY | LO_FLAGS_AUTOCLEAR
        if (
            backing_device != backing_status.st_dev
            or backing_inode != backing_status.st_ino
            or backing_rdevice != backing_status.st_rdev
            or offset != expected_offset
            or size_limit != expected_size_limit
            or loop_number != expected_number
            or encryption_type != 0
            or encryption_key_size != 0
            or loop_flags & ~allowed_flags != 0
            or bool(loop_flags & LO_FLAGS_READ_ONLY) != expected_read_only
        ):
            raise ClosedFailure("loop-detach", "mapping-mismatch")

        for attempt in range(8):
            try:
                fcntl.ioctl(loop_fd, LOOP_CLR_FD)
                break
            except OSError as error:
                if error.errno == errno.EINTR and attempt != 7:
                    continue
                raise ClosedFailure("loop-detach", "clear-failed") from error
    finally:
        for descriptor in (loop_fd, backing_fd):
            try:
                os.close(descriptor)
            except OSError:
                pass


class ControllerSignal(BaseException):
    """One of the wrapper-forwarded termination signals."""


HANDLED_SIGNALS = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT)


def _raise_controller_signal(signum: int, frame: object) -> None:
    del signum, frame
    try:
        signal.pthread_sigmask(signal.SIG_BLOCK, HANDLED_SIGNALS)
    except (AttributeError, OSError):
        pass
    raise ControllerSignal


class BoundedCapture:
    """In-memory-only bounded capture that rejects forbidden byte sequences."""

    def __init__(self, limit: int, forbidden: Sequence[bytearray]) -> None:
        if limit <= 0:
            raise ValueError("capture limit must be positive")
        self._limit = limit
        self._forbidden = tuple(forbidden)
        self._data = bytearray()
        self._lock = threading.Lock()

    def append(self, chunk: bytes | bytearray | memoryview) -> None:
        if not chunk:
            return
        with self._lock:
            if len(chunk) > self._limit - len(self._data):
                raise CaptureLimitError
            self._data.extend(chunk)
            if any(secret and self._data.find(secret) >= 0 for secret in self._forbidden):
                raise SecretExposureError

    def snapshot(self) -> bytes:
        with self._lock:
            return bytes(self._data)

    def contains_contextual_line(
        self, value: bytearray, *, start: int, end: int
    ) -> bool:
        """Detect an echoed secret only within its exact prompt response window."""

        if not value:
            return False
        with self._lock:
            bounded_start = max(0, start)
            bounded_end = min(len(self._data), end)
            cursor = bounded_start
            while cursor < bounded_end:
                found = self._data.find(value, cursor, bounded_end)
                if found < 0:
                    return False
                before = found == bounded_start or self._data[found - 1] in (10, 13)
                after_offset = found + len(value)
                after = after_offset < bounded_end and self._data[after_offset] in (10, 13)
                if before and after:
                    return True
                cursor = found + 1
            return False

    def __len__(self) -> int:
        with self._lock:
            return len(self._data)

    def wipe(self) -> None:
        with self._lock:
            self._data[:] = b"\x00" * len(self._data)
            self._data.clear()


def _line_pattern(line: bytes) -> re.Pattern[bytes]:
    return re.compile(rb"(?:^|\r?\n)" + re.escape(line) + rb"\r?\n")


def _trusted_shell_line_pattern(line: bytes) -> re.Pattern[bytes]:
    return re.compile(_TRUSTED_SHELL_MARKER_START + re.escape(line) + rb"\r?\n")


def _return_code_line_pattern(line: bytes) -> re.Pattern[bytes]:
    return re.compile(
        rb"(?:^|\r?\n)" + re.escape(line) + rb" rc=([0-9]{1,3})\r?\n"
    )


def _provider_proof_event_pattern(end: bytes) -> re.Pattern[bytes]:
    """Match the earliest closed proof marker or its exact transaction END."""

    return re.compile(
        _TRUSTED_SHELL_ZERO_WIDTH_START
        + rb"(?:"
        + rb"(?P<success>"
        + re.escape(PROVIDER_PROOF_SUCCESS_PREFIX)
        + rb" stage=(?P<success_stage>[a-z0-9-]+) result=true)"
        + rb"|(?P<failure>"
        + re.escape(PROVIDER_PROOF_FAILURE_PREFIX)
        + rb" stage=(?P<failure_stage>[a-z0-9-]+) checkpoint="
        + rb"(?P<failure_checkpoint>[a-z0-9-]+))"
        + rb"|(?P<end>"
        + re.escape(end)
        + rb" rc=(?P<return_code>[0-9]{1,3}))"
        + rb")\r?\n"
    )


def _canonical_return_code(value: bytes) -> int:
    if re.fullmatch(rb"0|[1-9][0-9]{0,2}", value) is None:
        raise ClosedFailure("provider-proof", "return-code-invalid")
    result = int(value)
    if result > 255:
        raise ClosedFailure("provider-proof", "return-code-invalid")
    return result


def _normalize(block: bytes) -> list[bytes]:
    normalized = block.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    lines = normalized.split(b"\n")
    while lines and lines[0] == b"":
        lines.pop(0)
    while lines and lines[-1] == b"":
        lines.pop()
    return lines


def wipe(value: bytearray) -> None:
    value[:] = b"\x00" * len(value)
    value.clear()


def read_secret_fd(fd: int, *, expected_uid: int = 0) -> bytearray:
    """Read one exact printable 64-hex passphrase without immutable copies."""

    try:
        metadata = os.fstat(fd)
    except OSError as error:
        try:
            os.close(fd)
        except OSError:
            pass
        raise ClosedFailure("secret", "descriptor-invalid") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_uid != expected_uid
        or metadata.st_nlink != 1
        or metadata.st_size != SECRET_BYTES
    ):
        try:
            os.close(fd)
        except OSError:
            pass
        raise ClosedFailure("secret", "metadata-invalid")
    value = bytearray(SECRET_BYTES + 1)
    view = memoryview(value)
    total = 0
    read_failed = False
    try:
        while total < len(value):
            try:
                read = os.readv(fd, [view[total:]])
            except InterruptedError:
                continue
            except OSError:
                read_failed = True
                break
            if read == 0:
                break
            total += read
    finally:
        view.release()
        try:
            os.close(fd)
        except OSError:
            pass
    if read_failed:
        wipe(value)
        raise ClosedFailure("secret", "read-failed")
    if total != SECRET_BYTES:
        wipe(value)
        raise ClosedFailure("secret", "size-invalid")
    del value[SECRET_BYTES:]
    if any(not (48 <= byte <= 57 or 97 <= byte <= 102) for byte in value):
        wipe(value)
        raise ClosedFailure("secret", "alphabet-invalid")
    return value


def read_login_credential_fd(fd: int, *, expected_uid: int = 0) -> bytearray:
    """Read the dynamically extracted live credential from one root-only file."""

    try:
        metadata = os.fstat(fd)
    except OSError as error:
        try:
            os.close(fd)
        except OSError:
            pass
        raise ClosedFailure("login-secret", "descriptor-invalid") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_uid != expected_uid
        or metadata.st_nlink != 1
        or metadata.st_size < 1
        or metadata.st_size > LOGIN_SECRET_LIMIT
    ):
        try:
            os.close(fd)
        except OSError:
            pass
        raise ClosedFailure("login-secret", "metadata-invalid")
    value = bytearray(metadata.st_size + 1)
    view = memoryview(value)
    total = 0
    failed = False
    try:
        while total < len(value):
            try:
                count = os.readv(fd, [view[total:]])
            except InterruptedError:
                continue
            except OSError:
                failed = True
                break
            if count == 0:
                break
            total += count
    finally:
        view.release()
        try:
            os.close(fd)
        except OSError:
            pass
    if failed or total != metadata.st_size:
        wipe(value)
        raise ClosedFailure("login-secret", "read-failed")
    del value[metadata.st_size:]
    if any(byte < 33 or byte > 126 or byte in (34, 39, 92) for byte in value):
        wipe(value)
        raise ClosedFailure("login-secret", "alphabet-invalid")
    return value


def _read_bounded_fd(fd: int, maximum: int) -> bytearray:
    value = bytearray()
    try:
        while len(value) <= maximum:
            try:
                chunk = os.read(fd, min(4096, maximum + 1 - len(value)))
            except InterruptedError:
                continue
            except OSError as error:
                wipe(value)
                raise ClosedFailure("credential-extract", "read-failed") from error
            if not chunk:
                return value
            value.extend(chunk)
            if len(value) > maximum:
                wipe(value)
                raise ClosedFailure("credential-extract", "source-oversized")
    finally:
        try:
            os.close(fd)
        except OSError:
            pass
    wipe(value)
    raise ClosedFailure("credential-extract", "source-oversized")


def _crypt_matches(password: bytearray, encoded: bytearray) -> bool:
    """Validate the script's crypt assignment without invoking a child process."""

    try:
        library = ctypes.CDLL("libcrypt.so.1")
        crypt = library.crypt
        crypt.argtypes = (ctypes.c_char_p, ctypes.c_char_p)
        crypt.restype = ctypes.c_char_p
        password_buffer = (ctypes.c_char * (len(password) + 1))()
        encoded_buffer = (ctypes.c_char * (len(encoded) + 1))()
        password_source = (ctypes.c_ubyte * len(password)).from_buffer(password)
        encoded_source = (ctypes.c_ubyte * len(encoded)).from_buffer(encoded)
        ctypes.memmove(password_buffer, password_source, len(password))
        ctypes.memmove(encoded_buffer, encoded_source, len(encoded))
        result = crypt(password_buffer, encoded_buffer)
        matches = result is not None and ctypes.string_at(result) == bytes(encoded)
        ctypes.memset(password_buffer, 0, len(password_buffer))
        return matches
    except (AttributeError, OSError, ValueError):
        return False


def extract_live_credential(
    source_fd: int,
    credential_fd: int,
    *,
    expected_uid: int = 0,
    expected_gid: int = 0,
) -> None:
    """Extract and validate the single documented live-config credential."""

    if source_fd == credential_fd or min(source_fd, credential_fd) < 3:
        raise ClosedFailure("credential-extract", "descriptor-invalid")
    try:
        output = os.fstat(credential_fd)
    except OSError as error:
        raise ClosedFailure("credential-extract", "output-invalid") from error
    if (
        not stat.S_ISREG(output.st_mode)
        or stat.S_IMODE(output.st_mode) != 0o600
        or output.st_uid != expected_uid
        or output.st_gid != expected_gid
        or output.st_nlink != 1
        or output.st_size != 0
    ):
        raise ClosedFailure("credential-extract", "output-invalid")

    try:
        source = _read_bounded_fd(source_fd, LIVE_CONFIG_LIMIT)
    except BaseException:
        try:
            os.close(credential_fd)
        except OSError:
            pass
        raise
    password = bytearray()
    encoded = bytearray()
    try:
        if not source or source[-1] != 10 or 0 in source:
            raise ClosedFailure("credential-extract", "source-invalid")
        password_prefix = bytearray(b"\t# Default password is: ")
        encoded_prefix = bytearray(b'\t_PASSWORD="')
        password_count = 0
        encoded_count = 0
        line_start = 0
        while line_start < len(source):
            line_end = source.find(b"\n", line_start)
            if line_end < 0:
                raise ClosedFailure("credential-extract", "source-invalid")
            if source.startswith(password_prefix, line_start, line_end):
                password_count += 1
                wipe(password)
                password = bytearray(
                    source[line_start + len(password_prefix) : line_end]
                )
            if source.startswith(encoded_prefix, line_start, line_end) and source[
                line_end - 1
            ] == 34:
                encoded_count += 1
                wipe(encoded)
                encoded = bytearray(
                    source[line_start + len(encoded_prefix) : line_end - 1]
                )
            line_start = line_end + 1
        if password_count != 1 or encoded_count != 1:
            raise ClosedFailure("credential-extract", "declaration-invalid")
        if (
            not 1 <= len(password) <= LOGIN_SECRET_LIMIT
            or any(byte < 33 or byte > 126 or byte in (34, 39, 92) for byte in password)
            or len(encoded) != 13
            or any(
                not (
                    48 <= byte <= 57
                    or 65 <= byte <= 90
                    or 97 <= byte <= 122
                    or byte in (46, 47)
                )
                for byte in encoded
            )
            or not _crypt_matches(password, encoded)
        ):
            raise ClosedFailure("credential-extract", "declaration-invalid")
        view = memoryview(password)
        written = 0
        try:
            while written < len(view):
                try:
                    count = os.write(credential_fd, view[written:])
                except InterruptedError:
                    continue
                except OSError as error:
                    raise ClosedFailure("credential-extract", "write-failed") from error
                if count <= 0:
                    raise ClosedFailure("credential-extract", "write-failed")
                written += count
        finally:
            view.release()
        os.fsync(credential_fd)
        final = os.fstat(credential_fd)
        if final.st_size != len(password) or stat.S_IMODE(final.st_mode) != 0o600:
            raise ClosedFailure("credential-extract", "output-invalid")
    finally:
        wipe(source)
        wipe(password)
        wipe(encoded)
        try:
            os.close(credential_fd)
        except OSError:
            pass


def process_metadata_excludes_secrets(
    arguments: Sequence[str], environment: dict[str, str], secrets: Sequence[bytearray]
) -> bool:
    fields = [os.fsencode(value) for value in arguments]
    fields.extend(os.fsencode(key) for key in environment)
    fields.extend(os.fsencode(value) for value in environment.values())
    return not any(secret and any(field.find(secret) >= 0 for field in fields) for secret in secrets)


def validate_owned_pgid_fd(
    fd: int, *, expected_uid: int | None = None, expected_gid: int | None = None
) -> None:
    """Validate the private regular file used to publish an owned process group."""

    if fd < 3:
        raise ClosedFailure("process-group", "descriptor-invalid")
    if expected_uid is None:
        expected_uid = os.geteuid()
    if expected_gid is None:
        expected_gid = os.getegid()
    try:
        metadata = os.fstat(fd)
    except OSError as error:
        raise ClosedFailure("process-group", "descriptor-invalid") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_uid != expected_uid
        or metadata.st_gid != expected_gid
        or metadata.st_nlink != 1
        or metadata.st_size != 0
    ):
        raise ClosedFailure("process-group", "metadata-invalid")


def publish_owned_process_group(fd: int, process: subprocess.Popen[bytes]) -> None:
    """Publish a newly created session/process-group leader through a private FD."""

    try:
        validate_owned_pgid_fd(fd)
        if os.getpgid(process.pid) != process.pid or os.getsid(process.pid) != process.pid:
            raise ClosedFailure("process-group", "ownership-invalid")
        payload = f"{process.pid}\n".encode("ascii")
        view = memoryview(payload)
        written = 0
        try:
            while written < len(view):
                try:
                    count = os.write(fd, view[written:])
                except InterruptedError:
                    continue
                except OSError as error:
                    raise ClosedFailure("process-group", "publish-failed") from error
                if count <= 0:
                    raise ClosedFailure("process-group", "publish-failed")
                written += count
        finally:
            view.release()
        os.fsync(fd)
        final = os.fstat(fd)
        if final.st_size != len(payload) or stat.S_IMODE(final.st_mode) != 0o600:
            raise ClosedFailure("process-group", "publish-failed")
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def process_group_exists(process_group: int) -> bool:
    try:
        os.killpg(process_group, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def cleanup_owned_process_group(process: subprocess.Popen[bytes]) -> None:
    """Terminate and reap a session plus every remaining process in its group."""

    process_group = process.pid
    cleanup_failed = False
    process_was_running = process.poll() is None
    unexpected_descendant = (
        not process_was_running and process_group_exists(process_group)
    )
    deadline = time.monotonic() + PROCESS_CLEANUP_SECONDS
    try:
        if process_group_exists(process_group):
            os.killpg(process_group, signal.SIGTERM)
        while process_group_exists(process_group) and time.monotonic() < deadline:
            process.poll()
            time.sleep(0.02)
        if process_group_exists(process_group):
            os.killpg(process_group, signal.SIGKILL)
            kill_deadline = time.monotonic() + PROCESS_CLEANUP_SECONDS
            while process_group_exists(process_group) and time.monotonic() < kill_deadline:
                process.poll()
                time.sleep(0.02)
        if process.poll() is None:
            process.wait(timeout=PROCESS_CLEANUP_SECONDS)
        process.poll()
        if process_group_exists(process_group) or process.poll() is None:
            cleanup_failed = True
    except (OSError, subprocess.SubprocessError):
        cleanup_failed = True
        try:
            os.killpg(process_group, signal.SIGKILL)
        except OSError:
            pass
    if cleanup_failed or unexpected_descendant:
        raise ClosedFailure("cleanup", "process-group-residue")


@dataclasses.dataclass(frozen=True)
class CompanionResponse:
    state_version: int
    vault_state: str | None
    device_id: str | None
    error: str | None
    return_code: int


@dataclasses.dataclass(frozen=True)
class ProviderCompanionResponse:
    state_version: int
    openai: str | None
    codex: str | None
    error: str | None
    return_code: int


def parse_companion_response(
    block: bytes, *, command: str, return_code: int
) -> CompanionResponse:
    """Parse an exact production companion TTY response block."""

    lines = _normalize(block)
    if command == "unlock":
        if lines[:2] != [b"READY", b"Vault passphrase: "]:
            raise ClosedFailure("response", "prompt-invalid")
        lines = lines[2:]
    elif command not in {"status", "lock"}:
        raise ClosedFailure("response", "command-invalid")

    if not lines or re.fullmatch(rb"stateVersion: (0|[1-9][0-9]*)", lines[0]) is None:
        raise ClosedFailure("response", "version-invalid")
    version = int(lines.pop(0).split(b": ", 1)[1])

    state: str | None = None
    device_id: str | None = None
    error: str | None = None
    if lines and re.fullmatch(
        rb"vaultState: (absent|unprovisioned|locked|unlocking|unlocked|locking|faulted-reboot-required)",
        lines[0],
    ):
        state = lines.pop(0).split(b": ", 1)[1].decode("ascii")
        if lines and re.fullmatch(rb"deviceId: KA-[0-9a-f]{24}", lines[0]):
            device_id = lines.pop(0).split(b": ", 1)[1].decode("ascii")
    elif lines and re.fullmatch(rb"error: [A-Z][A-Z0-9_]*", lines[0]):
        error = lines.pop(0).split(b": ", 1)[1].decode("ascii")
    if (
        command == "lock"
        and return_code == 1
        and state == "faulted-reboot-required"
        and device_id is None
        and lines == [b"error: REBOOT_REQUIRED"]
    ):
        # The production companion intentionally prints the public state
        # snapshot before the command-level error. Classify only this exact
        # closed compound response; arbitrary output remains rejected below.
        raise ClosedFailure("response", "lock-remote-reboot-required")
    if lines:
        raise ClosedFailure("response", "extra-output")

    if command == "status" and not (
        return_code == 0 and state is not None and error is None
    ):
        raise ClosedFailure("response", "status-invalid")
    if command == "lock" and not (
        return_code == 0 and state == "locked" and device_id is None and error is None
    ):
        raise ClosedFailure("response", "lock-invalid")
    if command == "unlock":
        success = (
            return_code == 0
            and state == "unlocked"
            and device_id is not None
            and error is None
        )
        rejected = (
            return_code != 0
            and state is None
            and device_id is None
            and error == "BAD_PASSPHRASE"
        )
        if not (success or rejected):
            remote_code = (
                UNLOCK_REMOTE_FAILURE_CODES.get(error)
                if return_code != 0
                and state is None
                and device_id is None
                and error is not None
                else None
            )
            if remote_code is not None:
                raise UnlockRemoteFailure(
                    f"unlock-remote-{remote_code}", version
                )
            raise ClosedFailure("response", "unlock-invalid")
    return CompanionResponse(version, state, device_id, error, return_code)


def parse_provider_companion_response(
    block: bytes, *, command: str, return_code: int
) -> ProviderCompanionResponse:
    """Parse one exact production provider companion TTY response block."""

    lines = _normalize(block)
    if command == "openai-configure":
        if lines[:2] != [b"READY", b"OpenAI API key: "]:
            raise ClosedFailure("provider-response", "prompt-invalid")
        lines = lines[2:]
    elif command != "provider-status":
        raise ClosedFailure("provider-response", "command-invalid")
    if not lines or re.fullmatch(rb"stateVersion: (0|[1-9][0-9]*)", lines[0]) is None:
        raise ClosedFailure("provider-response", "version-invalid")
    version = int(lines.pop(0).split(b": ", 1)[1])
    openai: str | None = None
    codex: str | None = None
    error: str | None = None
    if len(lines) >= 2 and re.fullmatch(
        rb"openai: (unconfigured|configured)", lines[0]
    ):
        openai = lines.pop(0).split(b": ", 1)[1].decode("ascii")
        if not lines or re.fullmatch(
            rb"codex: (unconfigured|configured)", lines[0]
        ) is None:
            raise ClosedFailure("provider-response", "status-invalid")
        codex = lines.pop(0).split(b": ", 1)[1].decode("ascii")
    elif (
        command == "provider-status"
        and lines[:2]
        == [
            b"vaultState: faulted-reboot-required",
            b"error: REBOOT_REQUIRED",
        ]
    ):
        lines = lines[2:]
        error = "REBOOT_REQUIRED"
    elif (
        command == "openai-configure"
        and lines
        and re.fullmatch(rb"error: [A-Z][A-Z0-9_]*", lines[0])
    ):
        error = lines.pop(0).split(b": ", 1)[1].decode("ascii")
    if lines:
        raise ClosedFailure("provider-response", "extra-output")
    success = (
        return_code == 0
        and openai is not None
        and codex is not None
        and error is None
    )
    rejected = (
        return_code == 1
        and openai is None
        and codex is None
        and error is not None
    )
    if not (success or rejected):
        raise ClosedFailure("provider-response", "result-invalid")
    return ProviderCompanionResponse(
        version, openai, codex, error, return_code
    )


@dataclasses.dataclass(frozen=True)
class RuntimeSnapshot:
    stage: str
    service_pid: int
    worker_pid: int
    worker_ppid: int
    invocation_id: str
    service_caps: tuple[str, str, str, str]
    worker_caps: tuple[str, str, str, str]
    service_ambient: str
    worker_ambient: str
    service_no_new_privs: int
    worker_no_new_privs: int
    service_core: tuple[int, int]
    worker_core: tuple[int, int]
    mapper_count: int
    shell_mount: bool


RUNTIME_RE = re.compile(
    rb"^KERNAID_VAULT_RUNTIME_V1 "
    rb"stage=([a-z0-9-]+) service_pid=([1-9][0-9]*) worker_pid=([1-9][0-9]*) "
    rb"worker_ppid=([1-9][0-9]*) "
    rb"invocation_id=([0-9a-f]{32}) "
    rb"service_caps=([0-9a-f]{16}):([0-9a-f]{16}):([0-9a-f]{16}):([0-9a-f]{16}) "
    rb"worker_caps=([0-9a-f]{16}):([0-9a-f]{16}):([0-9a-f]{16}):([0-9a-f]{16}) "
    rb"service_ambient=(0000000000000000) worker_ambient=(0000000000000000) "
    rb"service_nnp=(1) worker_nnp=(1) service_core=(0):(0) worker_core=(0):(0) "
    rb"systemd_control_group=unit service_cgroup=supervisor "
    rb"worker_cgroup=worker identity_stable=true "
    rb"mapper_count=([0-9]+) shell_mount=(false|true) "
    rb"swaps_empty=true service_state=active-running socket_state=operational$"
)

# This second grammar is diagnostic-only. RUNTIME_RE above remains the sole
# acceptance boundary; a line rejected there may be classified only when it
# still has the exact field order and bounded, control-free token shapes.
# Values are compared below, and no observed value is ever copied into a
# diagnostic.
RUNTIME_EVIDENCE_SHAPE_RE = re.compile(
    rb"^KERNAID_VAULT_RUNTIME_V1 "
    rb"stage=(?P<stage>[a-z0-9-]{1,64}) "
    rb"service_pid=(?P<service_pid>[0-9]{1,20}) "
    rb"worker_pid=(?P<worker_pid>[0-9]{1,20}) "
    rb"worker_ppid=(?P<worker_ppid>[a-z0-9-]{1,32}) "
    rb"invocation_id=(?P<invocation_id>[a-z0-9-]{1,64}) "
    rb"service_caps=(?P<service_caps>[a-z0-9:]{1,131}) "
    rb"worker_caps=(?P<worker_caps>[a-z0-9:]{1,131}) "
    rb"service_ambient=(?P<service_ambient>[a-z0-9]{1,32}) "
    rb"worker_ambient=(?P<worker_ambient>[a-z0-9]{1,32}) "
    rb"service_nnp=(?P<service_nnp>[a-z0-9]{1,20}) "
    rb"worker_nnp=(?P<worker_nnp>[a-z0-9]{1,20}) "
    rb"service_core=(?P<service_core>[a-z0-9:]{1,65}) "
    rb"worker_core=(?P<worker_core>[a-z0-9:]{1,65}) "
    rb"systemd_control_group=(?P<systemd_control_group>[a-z0-9-]{1,32}) "
    rb"service_cgroup=(?P<service_cgroup>[a-z0-9-]{1,32}) "
    rb"worker_cgroup=(?P<worker_cgroup>[a-z0-9-]{1,32}) "
    rb"identity_stable=(?P<identity_stable>[a-z0-9-]{1,32}) "
    rb"mapper_count=(?P<mapper_count>[a-z0-9-]{1,32}) "
    rb"shell_mount=(?P<shell_mount>[a-z0-9-]{1,32}) "
    rb"swaps_empty=(?P<swaps_empty>[a-z0-9-]{1,32}) "
    rb"service_state=(?P<service_state>[a-z0-9-]{1,32}) "
    rb"socket_state=(?P<socket_state>[a-z0-9-]{1,32})$"
)
RUNTIME_CAPABILITIES_SHAPE_RE = re.compile(
    rb"^[0-9a-f]{16}:[0-9a-f]{16}:[0-9a-f]{16}:[0-9a-f]{16}$"
)
RUNTIME_EVIDENCE_FAILURE_CODES = frozenset(
    {
        "evidence-invalid",
        "stage-invalid",
        "capabilities-invalid",
        "service-pid-invalid",
        "worker-pid-invalid",
        "worker-ppid-invalid",
        "worker-parent-invalid",
        "invocation-id-invalid",
        "service-capabilities-invalid",
        "worker-capabilities-invalid",
        "service-ambient-invalid",
        "worker-ambient-invalid",
        "service-nnp-invalid",
        "worker-nnp-invalid",
        "service-core-invalid",
        "worker-core-invalid",
        "systemd-control-group-invalid",
        "service-cgroup-invalid",
        "worker-cgroup-invalid",
        "identity-stability-invalid",
        "mapper-count-invalid",
        "shell-mount-invalid",
        "swaps-invalid",
        "service-state-invalid",
        "socket-state-invalid",
    }
)
assert all(
    TOKEN_RE.fullmatch(code) is not None
    for code in RUNTIME_EVIDENCE_FAILURE_CODES
)

BOUNDED_CHILD_PID_FUNCTION = (
    'child(){ v=$(/usr/bin/pgrep -P "$1" 2>/dev/null|'
    '/usr/bin/head -n 2);case "$v" in \'\'|*[!0-9]*)printf 0;;'
    '*)printf %s "$v";;esac;};'
)
RUNTIME_IDENTITY_STABILITY_COMMAND = (
    'stable=false;[ "$svc2:$worker2:$wppid:$wppid2:$inv2" = '
    '"$svc:$worker:$svc:$svc:$inv" ]&&[ "$control2:$scg2:$wcg2" = '
    '"$control:$scg:$wcg" ]&&stable=true;'
)


def _runtime_evidence_failure_code(line: bytes, expected_stage: str) -> str:
    if len(line) > 1024 or TOKEN_RE.fullmatch(expected_stage) is None:
        return "evidence-invalid"
    match = RUNTIME_EVIDENCE_SHAPE_RE.fullmatch(line)
    if match is None:
        return "evidence-invalid"
    expected = expected_stage.encode("ascii")
    checks = (
        (match["stage"] == expected, "stage-invalid"),
        (
            re.fullmatch(rb"[1-9][0-9]*", match["service_pid"]) is not None,
            "service-pid-invalid",
        ),
        (
            re.fullmatch(rb"[1-9][0-9]*", match["worker_pid"]) is not None,
            "worker-pid-invalid",
        ),
        (
            re.fullmatch(rb"[1-9][0-9]*", match["worker_ppid"]) is not None,
            "worker-ppid-invalid",
        ),
        (
            re.fullmatch(rb"[0-9a-f]{32}", match["invocation_id"]) is not None,
            "invocation-id-invalid",
        ),
        (
            RUNTIME_CAPABILITIES_SHAPE_RE.fullmatch(match["service_caps"])
            is not None,
            "service-capabilities-invalid",
        ),
        (
            RUNTIME_CAPABILITIES_SHAPE_RE.fullmatch(match["worker_caps"])
            is not None,
            "worker-capabilities-invalid",
        ),
        (
            match["service_ambient"] == ZERO_CAPS.encode("ascii"),
            "service-ambient-invalid",
        ),
        (
            match["worker_ambient"] == ZERO_CAPS.encode("ascii"),
            "worker-ambient-invalid",
        ),
        (match["service_nnp"] == b"1", "service-nnp-invalid"),
        (match["worker_nnp"] == b"1", "worker-nnp-invalid"),
        (match["service_core"] == b"0:0", "service-core-invalid"),
        (match["worker_core"] == b"0:0", "worker-core-invalid"),
        (
            match["systemd_control_group"] == b"unit",
            "systemd-control-group-invalid",
        ),
        (match["service_cgroup"] == b"supervisor", "service-cgroup-invalid"),
        (match["worker_cgroup"] == b"worker", "worker-cgroup-invalid"),
        (
            match["identity_stable"] == b"true",
            "identity-stability-invalid",
        ),
        (
            re.fullmatch(rb"[0-9]+", match["mapper_count"]) is not None,
            "mapper-count-invalid",
        ),
        (match["shell_mount"] in {b"false", b"true"}, "shell-mount-invalid"),
        (match["swaps_empty"] == b"true", "swaps-invalid"),
        (match["service_state"] == b"active-running", "service-state-invalid"),
        (match["socket_state"] == b"operational", "socket-state-invalid"),
    )
    for valid, code in checks:
        if not valid:
            assert code in RUNTIME_EVIDENCE_FAILURE_CODES
            return code
    return "evidence-invalid"


def parse_runtime_snapshot(line: bytes, expected_stage: str) -> RuntimeSnapshot:
    match = RUNTIME_RE.fullmatch(line)
    if match is None:
        raise ClosedFailure(
            "runtime", _runtime_evidence_failure_code(line, expected_stage)
        )
    if match.group(1).decode("ascii") != expected_stage:
        raise ClosedFailure("runtime", "stage-invalid")
    if match.group(4) != match.group(2):
        raise ClosedFailure("runtime", "worker-parent-invalid")
    service_caps = tuple(item.decode("ascii") for item in match.groups()[5:9])
    worker_caps = tuple(item.decode("ascii") for item in match.groups()[9:13])
    exact_service_caps = (
        ZERO_CAPS,
        CAP_SYS_ADMIN_AND_KILL,
        CAP_SYS_ADMIN_AND_KILL,
        CAP_SYS_ADMIN_AND_KILL,
    )
    exact_worker_caps = (
        ZERO_CAPS,
        CAP_SYS_ADMIN_ONLY,
        CAP_SYS_ADMIN_ONLY,
        CAP_SYS_ADMIN_ONLY,
    )
    if service_caps != exact_service_caps or worker_caps != exact_worker_caps:
        raise ClosedFailure("runtime", "capabilities-invalid")
    return RuntimeSnapshot(
        stage=expected_stage,
        service_pid=int(match.group(2)),
        worker_pid=int(match.group(3)),
        worker_ppid=int(match.group(4)),
        invocation_id=match.group(5).decode("ascii"),
        service_caps=service_caps,
        worker_caps=worker_caps,
        service_ambient=match.group(14).decode("ascii"),
        worker_ambient=match.group(15).decode("ascii"),
        service_no_new_privs=int(match.group(16)),
        worker_no_new_privs=int(match.group(17)),
        service_core=(int(match.group(18)), int(match.group(19))),
        worker_core=(int(match.group(20)), int(match.group(21))),
        mapper_count=int(match.group(22)),
        shell_mount=match.group(23) == b"true",
    )


def validate_lifecycle(
    initial: CompanionResponse,
    wrong: CompanionResponse,
    after_wrong: CompanionResponse,
    unlocked: CompanionResponse,
    status_unlocked: CompanionResponse,
    locked: CompanionResponse,
    status_locked: CompanionResponse,
) -> str:
    if initial.vault_state != "locked" or initial.device_id is not None:
        raise ClosedFailure("lifecycle", "initial-state-invalid")
    if wrong.error != "BAD_PASSPHRASE" or wrong.state_version != initial.state_version + 2:
        raise ClosedFailure("lifecycle", "wrong-key-invalid")
    if after_wrong != CompanionResponse(
        wrong.state_version, "locked", None, None, 0
    ):
        raise ClosedFailure("lifecycle", "wrong-key-residue")
    if (
        unlocked.state_version != wrong.state_version + 2
        or unlocked.vault_state != "unlocked"
        or unlocked.device_id is None
        or DEVICE_ID_RE.fullmatch(unlocked.device_id) is None
    ):
        raise ClosedFailure("lifecycle", "unlock-invalid")
    if status_unlocked != unlocked:
        raise ClosedFailure("lifecycle", "unlocked-status-mismatch")
    if (
        locked.state_version != unlocked.state_version + 2
        or locked.vault_state != "locked"
        or locked.device_id is not None
    ):
        raise ClosedFailure("lifecycle", "lock-invalid")
    if status_locked != locked:
        raise ClosedFailure("lifecycle", "locked-status-mismatch")
    return unlocked.device_id


def validate_provider_fault_lifecycle(
    initial: CompanionResponse,
    wrong: CompanionResponse,
    after_wrong: CompanionResponse,
    unlocked: CompanionResponse,
    status_unlocked: CompanionResponse,
    prior_provider: ProviderCompanionResponse,
    configured: ProviderCompanionResponse,
    provider_status: ProviderCompanionResponse,
    report_status: CompanionResponse,
    faulted: CompanionResponse,
    provider_faulted: ProviderCompanionResponse,
    boot: int,
) -> str:
    if initial.vault_state != "locked" or initial.device_id is not None:
        raise ClosedFailure("lifecycle", "initial-state-invalid")
    if wrong.error != "BAD_PASSPHRASE" or wrong.state_version != initial.state_version + 2:
        raise ClosedFailure("lifecycle", "wrong-key-invalid")
    if after_wrong != CompanionResponse(
        wrong.state_version, "locked", None, None, 0
    ):
        raise ClosedFailure("lifecycle", "wrong-key-residue")
    if (
        unlocked.state_version != wrong.state_version + 2
        or unlocked.vault_state != "unlocked"
        or unlocked.device_id is None
        or DEVICE_ID_RE.fullmatch(unlocked.device_id) is None
        or status_unlocked != unlocked
    ):
        raise ClosedFailure("lifecycle", "unlock-invalid")
    validate_provider_configuration(
        unlocked, prior_provider, configured, provider_status, boot
    )
    if (
        report_status
        != CompanionResponse(
            configured.state_version + 8,
            "unlocked",
            unlocked.device_id,
            None,
            0,
        )
        or faulted.return_code != 0
        or faulted.vault_state != "faulted-reboot-required"
        or faulted.device_id is not None
        or faulted.error is not None
        or provider_faulted.state_version != faulted.state_version
        or provider_faulted.return_code == 0
        or provider_faulted.openai is not None
        or provider_faulted.codex is not None
        or provider_faulted.error != "REBOOT_REQUIRED"
    ):
        raise ClosedFailure("lifecycle", "persistent-fault-invalid")
    return unlocked.device_id


def validate_provider_configuration(
    unlocked: CompanionResponse,
    prior_provider: ProviderCompanionResponse,
    configured: ProviderCompanionResponse,
    provider_status: ProviderCompanionResponse,
    boot: int,
) -> None:
    if boot not in {1, 2}:
        raise ClosedFailure("lifecycle", "boot-invalid")
    expected_prior = ProviderCompanionResponse(
        unlocked.state_version,
        "unconfigured" if boot == 1 else "configured",
        "unconfigured",
        None,
        0,
    )
    expected_configured = ProviderCompanionResponse(
        unlocked.state_version + 2,
        "configured",
        "unconfigured",
        None,
        0,
    )
    if (
        prior_provider != expected_prior
        or configured != expected_configured
        or provider_status != expected_configured
    ):
        raise ClosedFailure("lifecycle", "provider-configure-invalid")


def validate_clean_provider_lifecycle(
    initial: CompanionResponse,
    wrong: CompanionResponse,
    after_wrong: CompanionResponse,
    unlocked: CompanionResponse,
    status_unlocked: CompanionResponse,
    prior_provider: ProviderCompanionResponse,
    configured: ProviderCompanionResponse,
    provider_status: ProviderCompanionResponse,
    report_status: CompanionResponse,
    locked: CompanionResponse,
    status_locked: CompanionResponse,
    boot: int,
) -> str:
    if initial.vault_state != "locked" or initial.device_id is not None:
        raise ClosedFailure("lifecycle", "initial-state-invalid")
    if wrong.error != "BAD_PASSPHRASE" or wrong.state_version != initial.state_version + 2:
        raise ClosedFailure("lifecycle", "wrong-key-invalid")
    if after_wrong != CompanionResponse(
        wrong.state_version, "locked", None, None, 0
    ):
        raise ClosedFailure("lifecycle", "wrong-key-residue")
    if (
        unlocked.state_version != wrong.state_version + 2
        or unlocked.vault_state != "unlocked"
        or unlocked.device_id is None
        or DEVICE_ID_RE.fullmatch(unlocked.device_id) is None
        or status_unlocked != unlocked
    ):
        raise ClosedFailure("lifecycle", "unlock-invalid")
    validate_provider_configuration(
        unlocked, prior_provider, configured, provider_status, boot
    )
    if (
        report_status
        != CompanionResponse(
            configured.state_version + 8,
            "unlocked",
            unlocked.device_id,
            None,
            0,
        )
        or locked.state_version != report_status.state_version + 2
        or locked.vault_state != "locked"
        or locked.device_id is not None
        or locked.error is not None
        or status_locked != locked
    ):
        raise ClosedFailure("lifecycle", "lock-invalid")
    return unlocked.device_id


def validate_provider_runtime_sequence(
    snapshots: Sequence[RuntimeSnapshot],
) -> None:
    if len(snapshots) != 3:
        raise ClosedFailure("runtime", "sequence-invalid")
    baseline = snapshots[0]
    for snapshot in snapshots:
        if (
            snapshot.service_pid != baseline.service_pid
            or snapshot.worker_pid != baseline.worker_pid
            or snapshot.worker_ppid != baseline.worker_ppid
            or snapshot.invocation_id != baseline.invocation_id
            or snapshot.service_caps != baseline.service_caps
            or snapshot.worker_caps != baseline.worker_caps
            or snapshot.service_ambient != baseline.service_ambient
            or snapshot.worker_ambient != baseline.worker_ambient
            or snapshot.service_no_new_privs != baseline.service_no_new_privs
            or snapshot.worker_no_new_privs != baseline.worker_no_new_privs
            or snapshot.service_core != baseline.service_core
            or snapshot.worker_core != baseline.worker_core
            or snapshot.shell_mount
        ):
            raise ClosedFailure("runtime", "stability-invalid")
    if tuple(item.mapper_count for item in snapshots) != (0, 0, 1):
        raise ClosedFailure("runtime", "mapper-sequence-invalid")


def validate_runtime_sequence(snapshots: Sequence[RuntimeSnapshot]) -> None:
    if len(snapshots) != 4:
        raise ClosedFailure("runtime", "sequence-invalid")
    baseline = snapshots[0]
    for snapshot in snapshots:
        if (
            snapshot.service_pid != baseline.service_pid
            or snapshot.worker_pid != baseline.worker_pid
            or snapshot.worker_ppid != baseline.worker_ppid
            or snapshot.invocation_id != baseline.invocation_id
            or snapshot.service_caps != baseline.service_caps
            or snapshot.worker_caps != baseline.worker_caps
            or snapshot.service_ambient != baseline.service_ambient
            or snapshot.worker_ambient != baseline.worker_ambient
            or snapshot.service_no_new_privs != baseline.service_no_new_privs
            or snapshot.worker_no_new_privs != baseline.worker_no_new_privs
            or snapshot.service_core != baseline.service_core
            or snapshot.worker_core != baseline.worker_core
            or snapshot.shell_mount
        ):
            raise ClosedFailure("runtime", "stability-invalid")
    expected_mappers = (0, 0, 1, 0)
    if tuple(item.mapper_count for item in snapshots) != expected_mappers:
        raise ClosedFailure("runtime", "mapper-residue")


class QmpClient:
    def __init__(self, connection: socket.socket, deadline: float) -> None:
        self._socket = connection
        self._deadline = deadline
        self._buffer = bytearray()
        self._next_id = 1

    def set_deadline(self, deadline: float) -> None:
        self._deadline = deadline

    @classmethod
    def connect(cls, path: Path, deadline: float) -> "QmpClient":
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.setblocking(False)
        while True:
            if time.monotonic() >= deadline:
                connection.close()
                raise ClosedFailure("qmp", "connect-timeout")
            try:
                connection.connect(os.fspath(path))
                break
            except BlockingIOError:
                _, writable, _ = select_socket([], [connection], deadline)
                if not writable:
                    continue
                error = connection.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                if error == 0:
                    break
                if error in {errno.ENOENT, errno.ECONNREFUSED}:
                    connection.close()
                    time.sleep(0.05)
                    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    connection.setblocking(False)
                    continue
                connection.close()
                raise ClosedFailure("qmp", "connect-failed")
            except OSError as error:
                if error.errno in {errno.ENOENT, errno.ECONNREFUSED}:
                    time.sleep(0.05)
                    continue
                connection.close()
                raise ClosedFailure("qmp", "connect-failed") from error
        client = cls(connection, deadline)
        greeting = client._receive_object()
        if not isinstance(greeting.get("QMP"), dict):
            client.close()
            raise ClosedFailure("qmp", "greeting-invalid")
        client.execute("qmp_capabilities")
        return client

    def _receive_object(self) -> dict[str, object]:
        while True:
            newline = self._buffer.find(b"\n")
            if newline >= 0:
                raw = bytes(self._buffer[:newline]).rstrip(b"\r")
                del self._buffer[: newline + 1]
                try:
                    decoded = json.loads(raw)
                except (UnicodeDecodeError, json.JSONDecodeError) as error:
                    raise ClosedFailure("qmp", "json-invalid") from error
                if not isinstance(decoded, dict):
                    raise ClosedFailure("qmp", "message-invalid")
                return decoded
            if time.monotonic() >= self._deadline:
                raise ClosedFailure("qmp", "response-timeout")
            readable, _, _ = select_socket([self._socket], [], self._deadline)
            if not readable:
                continue
            try:
                chunk = self._socket.recv(4096)
            except BlockingIOError:
                continue
            if not chunk:
                raise ClosedFailure("qmp", "closed")
            if len(chunk) > QMP_LIMIT - len(self._buffer):
                raise ClosedFailure("qmp", "oversized")
            self._buffer.extend(chunk)

    def execute(self, command: str) -> None:
        request_id = self._next_id
        self._next_id += 1
        payload = json.dumps(
            {"execute": command, "id": request_id}, separators=(",", ":")
        ).encode("ascii") + b"\r\n"
        view = memoryview(payload)
        sent = 0
        try:
            while sent < len(view):
                if time.monotonic() >= self._deadline:
                    raise ClosedFailure("qmp", "send-timeout")
                _, writable, _ = select_socket([], [self._socket], self._deadline)
                if not writable:
                    continue
                try:
                    written = self._socket.send(view[sent:])
                except BlockingIOError:
                    continue
                except OSError as error:
                    raise ClosedFailure("qmp", "send-failed") from error
                if written <= 0:
                    raise ClosedFailure("qmp", "send-failed")
                sent += written
        finally:
            view.release()
        while True:
            response = self._receive_object()
            if response.get("id") != request_id:
                if "event" in response:
                    continue
                raise ClosedFailure("qmp", "correlation-invalid")
            if "error" in response or response.get("return") != {}:
                raise ClosedFailure("qmp", "command-failed")
            return

    def system_powerdown(self) -> None:
        self.execute("system_powerdown")

    def quit(self) -> None:
        self.execute("quit")

    def close(self) -> None:
        try:
            self._socket.close()
        finally:
            self._buffer[:] = b"\x00" * len(self._buffer)
            self._buffer.clear()


def select_socket(
    readers: Sequence[socket.socket], writers: Sequence[socket.socket], deadline: float
) -> tuple[list[socket.socket], list[socket.socket], list[socket.socket]]:
    import select

    remaining = max(0.0, deadline - time.monotonic())
    return select.select(list(readers), list(writers), [], min(remaining, 0.1))


class StderrDrainer:
    def __init__(
        self, stream: object, capture: BoundedCapture, stage: str = "qemu-stderr"
    ) -> None:
        if TOKEN_RE.fullmatch(stage) is None:
            raise ClosedFailure("capture", "stage-invalid")
        self._stream = stream
        self._capture = capture
        self._stage = stage
        self._error: BaseException | None = None
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def _run(self) -> None:
        try:
            while True:
                chunk = self._stream.read(4096)  # type: ignore[attr-defined]
                if not chunk:
                    return
                self._capture.append(chunk)
        except BaseException as error:  # propagated without its message
            self._error = error

    def check(self) -> None:
        if isinstance(self._error, SecretExposureError):
            raise ClosedFailure(self._stage, "secret-exposure")
        if isinstance(self._error, CaptureLimitError):
            raise ClosedFailure(self._stage, "oversized")
        if self._error is not None:
            raise ClosedFailure(self._stage, "read-failed")

    def join(self, timeout: float = 1.0) -> None:
        self._thread.join(timeout)
        if self._thread.is_alive():
            raise ClosedFailure(self._stage, "cleanup-timeout")
        self.check()


PROBE_ATTESTATION_RE = re.compile(
    rb"^KERNAID_RESCUE_VAULT_PROBE_ATTESTATION_V1 "
    rb"mode=(initialize|verify) journal_binding=device-identity-bound-v1 "
    rb"identity_public_key=([0-9a-f]{64}) clean_shutdown=true\n$"
)


def _write_secret_to_pipe(
    stream: object, secret: bytearray, *, deadline: float
) -> None:
    descriptor = stream.fileno()  # type: ignore[attr-defined]
    os.set_blocking(descriptor, False)
    view = memoryview(secret)
    offset = 0
    try:
        while offset < len(view):
            if time.monotonic() >= deadline:
                raise ClosedFailure("probe", "input-timeout")
            try:
                written = os.write(descriptor, view[offset:])
            except InterruptedError:
                continue
            except BlockingIOError:
                import select

                select.select([], [descriptor], [], 0.05)
                continue
            except OSError as error:
                raise ClosedFailure("probe", "input-failed") from error
            if written <= 0:
                raise ClosedFailure("probe", "input-failed")
            offset += written
    finally:
        view.release()
        try:
            stream.close()  # type: ignore[attr-defined]
        except OSError:
            pass


def _validate_probe_arguments(
    probe: Path, device: str, mapper: str, mode: str
) -> None:
    if (
        not probe.is_absolute()
        or not probe.is_file()
        or probe.is_symlink()
        or not os.access(probe, os.X_OK)
    ):
        raise ClosedFailure("probe", "executable-invalid")
    try:
        probe_metadata = probe.stat()
        device_metadata = os.stat(device, follow_symlinks=False)
    except OSError as error:
        raise ClosedFailure("probe", "target-invalid") from error
    if (
        not stat.S_ISREG(probe_metadata.st_mode)
        or probe_metadata.st_mode & 0o022 != 0
        or re.fullmatch(r"/dev/loop[0-9]+", device) is None
        or not stat.S_ISBLK(device_metadata.st_mode)
        or not re.fullmatch(r"kernaid-vault-[0-9a-f]{16}", mapper)
        or mode not in {"initialize", "verify"}
    ):
        raise ClosedFailure("probe", "target-invalid")


def run_bounded_probe(parsed: argparse.Namespace) -> str:
    """Run the host probe with bounded pipes, deadline, and group cleanup."""

    correct = bytearray()
    wrong = bytearray()
    stdout_capture: BoundedCapture | None = None
    stderr_capture: BoundedCapture | None = None
    stdout_drainer: StderrDrainer | None = None
    stderr_drainer: StderrDrainer | None = None
    process: subprocess.Popen[bytes] | None = None
    failure: BaseException | None = None
    result: str | None = None
    owned_pgid_fd = parsed.owned_pgid_fd
    try:
        validate_owned_pgid_fd(owned_pgid_fd)
        _validate_probe_arguments(
            parsed.probe, parsed.device, parsed.mapper, parsed.mode
        )
        correct = read_secret_fd(parsed.correct_key_fd, expected_uid=os.geteuid())
        wrong = read_secret_fd(parsed.wrong_key_fd, expected_uid=os.geteuid())
        if correct == wrong:
            raise ClosedFailure("secret", "not-distinct")
        command = [
            os.fspath(parsed.probe),
            "--device",
            parsed.device,
            "--mapper",
            parsed.mapper,
            "--mode",
            parsed.mode,
        ]
        environment = {
            "HOME": "/",
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        }
        if not process_metadata_excludes_secrets(
            command, environment, [correct, wrong]
        ):
            raise ClosedFailure("probe", "secret-metadata")
        stdout_capture = BoundedCapture(PROBE_OUTPUT_LIMIT, [correct, wrong])
        stderr_capture = BoundedCapture(PROBE_STDERR_LIMIT, [correct, wrong])
        try:
            process = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                close_fds=True,
                start_new_session=True,
                env=environment,
            )
        except OSError as error:
            raise ClosedFailure("probe", "start-failed") from error
        publishing_fd = owned_pgid_fd
        owned_pgid_fd = -1
        publish_owned_process_group(publishing_fd, process)
        assert process.stdin is not None
        assert process.stdout is not None
        assert process.stderr is not None
        stdout_drainer = StderrDrainer(
            process.stdout, stdout_capture, "probe-stdout"
        )
        stderr_drainer = StderrDrainer(
            process.stderr, stderr_capture, "probe-stderr"
        )
        stdout_drainer.start()
        stderr_drainer.start()
        deadline = time.monotonic() + min(
            float(parsed.timeout), PROBE_TIMEOUT_SECONDS
        )
        _write_secret_to_pipe(process.stdin, correct, deadline=deadline)
        while process.poll() is None:
            stdout_drainer.check()
            stderr_drainer.check()
            if time.monotonic() >= deadline:
                raise ClosedFailure("probe", "timeout")
            time.sleep(0.02)
        stdout_drainer.join(1.0)
        stderr_drainer.join(1.0)
        if process.returncode != 0:
            raise ClosedFailure("probe", "failed")
        if stderr_capture.snapshot():
            raise ClosedFailure("probe-stderr", "unexpected")
        output = stdout_capture.snapshot()
        match = PROBE_ATTESTATION_RE.fullmatch(output)
        if match is None or match.group(1).decode("ascii") != parsed.mode:
            raise ClosedFailure("probe-stdout", "invalid")
        result = output[:-1].decode("ascii")
    except BaseException as error:
        failure = error
    finally:
        if owned_pgid_fd >= 3:
            try:
                os.close(owned_pgid_fd)
            except OSError:
                failure = ClosedFailure("cleanup", "process-group-fd")
        if process is not None:
            try:
                cleanup_owned_process_group(process)
            except BaseException:
                failure = ClosedFailure("cleanup", "probe-residue")
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None:
                    try:
                        stream.close()
                    except OSError:
                        failure = ClosedFailure("cleanup", "probe-pipe")
        for drainer in (stdout_drainer, stderr_drainer):
            if drainer is not None:
                try:
                    drainer.join(PROCESS_CLEANUP_SECONDS)
                except ClosedFailure as error:
                    if error.code == "cleanup-timeout":
                        failure = ClosedFailure("cleanup", "probe-drainer")
                    elif failure is None:
                        failure = error
                except BaseException:
                    failure = ClosedFailure("cleanup", "probe-drainer")
        if stdout_capture is not None:
            stdout_capture.wipe()
        if stderr_capture is not None:
            stderr_capture.wipe()
        wipe(correct)
        wipe(wrong)
    if failure is not None:
        raise failure
    if result is None:
        raise ClosedFailure("probe", "unexpected")
    return result


class SerialConsole:
    def __init__(
        self,
        fd: int,
        capture: BoundedCapture,
        health: Callable[[], None],
    ) -> None:
        self.fd = fd
        self.capture = capture
        self._health = health
        self._selector = selectors.DefaultSelector()
        self._selector.register(fd, selectors.EVENT_READ)
        self._not_ready_scan_start = 0

    def send(self, value: bytes | bytearray, *, deadline: float) -> None:
        offset = 0
        view = memoryview(value)
        try:
            while offset < len(value):
                self._health()
                if time.monotonic() >= deadline:
                    raise ClosedFailure("serial", "write-timeout")
                try:
                    written = os.write(self.fd, view[offset:])
                except BlockingIOError:
                    remaining = max(0.0, deadline - time.monotonic())
                    if remaining == 0.0:
                        raise ClosedFailure("serial", "write-timeout")
                    import select

                    select.select([], [self.fd], [], min(remaining, 0.05))
                    continue
                except OSError as error:
                    raise ClosedFailure("serial", "write-failed") from error
                if written <= 0:
                    raise ClosedFailure("serial", "write-failed")
                offset += written
        finally:
            view.release()

    def wait_regex(
        self, pattern: re.Pattern[bytes], *, start: int, deadline: float, stage: str
    ) -> re.Match[bytes]:
        while True:
            self._health()
            self._drain_immediately_available()
            snapshot = self.capture.snapshot()
            self._raise_if_not_ready(snapshot)
            match = pattern.search(snapshot, start)
            if match is not None:
                return match
            if time.monotonic() >= deadline:
                raise ClosedFailure(stage, "timeout")
            events = self._selector.select(min(0.1, max(0.0, deadline - time.monotonic())))
            if not events:
                continue

    def _drain_immediately_available(self) -> None:
        while self._selector.select(0):
            self._health()
            try:
                chunk = os.read(self.fd, 4096)
            except InterruptedError:
                continue
            except BlockingIOError:
                return
            except OSError as error:
                if error.errno == errno.EIO:
                    raise ClosedFailure("serial", "closed") from error
                raise ClosedFailure("serial", "read-failed") from error
            if not chunk:
                raise ClosedFailure("serial", "closed")
            try:
                self.capture.append(chunk)
            except SecretExposureError as error:
                raise ClosedFailure("serial", "secret-exposure") from error
            except CaptureLimitError as error:
                raise ClosedFailure("serial", "oversized") from error

    def _raise_if_not_ready(self, snapshot: bytes) -> None:
        if NOT_READY_PREFIX_PATTERN.search(snapshot, self._not_ready_scan_start) is not None:
            raise ClosedFailure("readiness", "not-ready")
        self._not_ready_scan_start = max(0, len(snapshot) - NOT_READY_SCAN_OVERLAP)

    def wait_line(self, line: bytes, *, start: int, deadline: float, stage: str) -> int:
        return self.wait_regex(
            _line_pattern(line), start=start, deadline=deadline, stage=stage
        ).end()

    def close(self) -> None:
        self._selector.close()
        try:
            os.close(self.fd)
        except OSError:
            pass


class QemuHarness:
    PTY_RE = re.compile(rb"char device redirected to (/dev/pts/[0-9]+) \(label serial0\)")

    def __init__(
        self,
        qemu: str,
        qemu_arguments: Sequence[str],
        qmp_path: Path,
        capture_secrets: Sequence[bytearray],
        metadata_secrets: Sequence[bytearray] | None = None,
        owned_pgid_fd: int | None = None,
    ) -> None:
        self.qmp_path = qmp_path
        self.serial_capture = BoundedCapture(SERIAL_LIMIT, capture_secrets)
        self.output_capture = BoundedCapture(QEMU_OUTPUT_LIMIT, capture_secrets)
        self.process: subprocess.Popen[bytes] | None = None
        self._qmp_path_owned = False
        self.output_drainer: StderrDrainer | None = None
        self.console: SerialConsole | None = None
        self.qmp: QmpClient | None = None
        self._owned_pgid_fd = owned_pgid_fd
        if self._owned_pgid_fd is not None:
            validate_owned_pgid_fd(self._owned_pgid_fd)
        self._supplied_arguments = tuple(qemu_arguments)
        self._command = [
            qemu,
            *qemu_arguments,
            "-display",
            "none",
            "-serial",
            "pty",
            "-qmp",
            f"unix:{qmp_path},server=on,wait=off",
            "-no-reboot",
        ]
        self._environment = {
            "HOME": "/",
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        }
        if not process_metadata_excludes_secrets(
            self._command,
            self._environment,
            metadata_secrets if metadata_secrets is not None else capture_secrets,
        ):
            raise ClosedFailure("qemu", "secret-metadata")

    def start(self, deadline: float) -> tuple[SerialConsole, QmpClient]:
        forbidden = {
            "-serial",
            "-qmp",
            "-monitor",
            "-chardev",
            "-daemonize",
            "-nographic",
            "-display",
            "-debugcon",
            "-D",
            "-pidfile",
        }
        if any(argument in forbidden for argument in self._supplied_arguments):
            raise ClosedFailure("qemu", "argument-conflict")
        if os.path.lexists(self.qmp_path) or not self.qmp_path.parent.is_dir():
            raise ClosedFailure("qmp", "path-invalid")
        parent = self.qmp_path.parent.lstat()
        if (
            not stat.S_ISDIR(parent.st_mode)
            or stat.S_IMODE(parent.st_mode) != 0o700
            or parent.st_uid != os.geteuid()
        ):
            raise ClosedFailure("qmp", "parent-invalid")
        try:
            self.process = subprocess.Popen(
                self._command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                close_fds=True,
                start_new_session=True,
                env=self._environment,
            )
        except OSError as error:
            raise ClosedFailure("qemu", "start-failed") from error
        self._qmp_path_owned = True
        if self._owned_pgid_fd is not None:
            owned_pgid_fd = self._owned_pgid_fd
            self._owned_pgid_fd = None
            publish_owned_process_group(owned_pgid_fd, self.process)
        assert self.process.stdout is not None
        os.set_blocking(self.process.stdout.fileno(), False)
        pty_path: str | None = None
        while time.monotonic() < deadline:
            self.check_health()
            try:
                chunk = self.process.stdout.read(4096)
            except BlockingIOError:
                chunk = None
            if chunk:
                try:
                    self.output_capture.append(chunk)
                except SecretExposureError as error:
                    raise ClosedFailure("qemu-output", "secret-exposure") from error
                except CaptureLimitError as error:
                    raise ClosedFailure("qemu-output", "oversized") from error
                match = self.PTY_RE.search(self.output_capture.snapshot())
                if match is not None:
                    pty_path = os.fsdecode(match.group(1))
                    break
            time.sleep(0.02)
        if pty_path is None:
            raise ClosedFailure("serial", "pty-missing")
        os.set_blocking(self.process.stdout.fileno(), True)
        self.output_drainer = StderrDrainer(
            self.process.stdout, self.output_capture, "qemu-output"
        )
        self.output_drainer.start()
        try:
            serial_fd = os.open(
                pty_path,
                os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK | os.O_CLOEXEC,
            )
        except OSError as error:
            raise ClosedFailure("serial", "pty-open-failed") from error
        try:
            # The host PTY is only a byte transport. Guest ttyS0 retains its
            # independent line discipline, including the companion's verified
            # echo-off transition before READY.
            tty.setraw(serial_fd)
        except OSError as error:
            os.close(serial_fd)
            raise ClosedFailure("serial", "pty-mode-failed") from error
        self.console = SerialConsole(serial_fd, self.serial_capture, self.check_health)
        self.qmp = QmpClient.connect(self.qmp_path, deadline)
        return self.console, self.qmp

    def check_health(self) -> None:
        if self.output_drainer is not None:
            self.output_drainer.check()
        if self.process is not None and self.process.poll() is not None:
            raise ClosedFailure("qemu", "exited-early")

    def wait_for_shutdown(self, deadline: float) -> None:
        if self.process is None:
            raise ClosedFailure("qemu", "not-started")
        while self.process.poll() is None and time.monotonic() < deadline:
            if self.output_drainer is not None:
                self.output_drainer.check()
            time.sleep(0.05)
        if self.process.poll() is None:
            raise ClosedFailure("qemu", "shutdown-timeout")
        if self.process.returncode != 0:
            raise ClosedFailure("qemu", "shutdown-failed")
        if self.output_drainer is not None:
            self.output_drainer.join()

    def cleanup(self) -> None:
        cleanup_failed = False
        if self.qmp is not None:
            try:
                self.qmp.close()
            except BaseException:
                cleanup_failed = True
            self.qmp = None
        if self.console is not None:
            try:
                self.console.close()
            except BaseException:
                cleanup_failed = True
            self.console = None
        if self.process is not None:
            try:
                cleanup_owned_process_group(self.process)
            except BaseException:
                cleanup_failed = True
        if self.output_drainer is not None:
            try:
                self.output_drainer.join(PROCESS_CLEANUP_SECONDS)
            except BaseException:
                cleanup_failed = True
            self.output_drainer = None
        if self.process is not None:
            for stream in (self.process.stdout, self.process.stderr):
                if stream is not None:
                    try:
                        stream.close()
                    except OSError:
                        cleanup_failed = True
        if self._qmp_path_owned and os.path.lexists(self.qmp_path):
            try:
                os.unlink(self.qmp_path)
            except OSError:
                cleanup_failed = True
        if self._qmp_path_owned and os.path.lexists(self.qmp_path):
            cleanup_failed = True
        if self._owned_pgid_fd is not None:
            try:
                os.close(self._owned_pgid_fd)
            except OSError:
                cleanup_failed = True
            self._owned_pgid_fd = None
        self.serial_capture.wipe()
        self.output_capture.wipe()
        if cleanup_failed:
            raise ClosedFailure("cleanup", "qemu-residue")


def _deadline(aggregate: float, seconds: float) -> float:
    return min(aggregate, time.monotonic() + seconds)


def establish_live_session(
    console: SerialConsole, aggregate: float, login_credential: bytearray
) -> int:
    ready = console.wait_regex(
        READY_RESULT_PATTERN,
        start=0,
        deadline=_deadline(aggregate, READINESS_TIMEOUT_SECONDS),
        stage="readiness",
    )
    cursor = ready.end()
    console.send(b"\n", deadline=_deadline(aggregate, 5.0))
    login_prompt = console.wait_regex(
        re.compile(rb"(?:^|\r?\n)kernaid-rescue login: $"),
        start=cursor,
        deadline=_deadline(aggregate, 20.0),
        stage="login-prompt",
    )
    console.send(b"kernaid\n", deadline=_deadline(aggregate, 5.0))
    password_prompt = console.wait_regex(
        re.compile(rb"(?:^|\r?\n)Password: $"),
        start=login_prompt.end(),
        deadline=_deadline(aggregate, 20.0),
        stage="login-password",
    )
    echo_window_start = password_prompt.end()
    console.send(login_credential, deadline=_deadline(aggregate, 5.0))
    console.send(b"\n", deadline=_deadline(aggregate, 5.0))
    shell_prompt = console.wait_regex(
        re.compile(
            rb"(?:^|\r?\n)[^\r\n]{0,192}kernaid@kernaid-rescue"
            rb"[^\r\n]{0,64}:[^\r\n]{0,128}\$ $"
        ),
        start=echo_window_start,
        deadline=_deadline(aggregate, 30.0),
        stage="login-shell",
    )
    if console.capture.contains_contextual_line(
        login_credential, start=echo_window_start, end=shell_prompt.end()
    ):
        raise ClosedFailure("login", "credential-echoed")
    cursor = shell_prompt.end()
    proof = (
        "if [ \"$(id -u)\" = 1000 ] && [ \"$(id -un)\" = kernaid ] "
        "&& id -nG | tr ' ' '\\n' | grep -Fxq kernaid-vault; then "
        "printf '%s\\n' 'KERNAID_VAULT_LOGIN_V1 uid=1000 user=kernaid group=true'; "
        "else printf '%s\\n' 'KERNAID_VAULT_LOGIN_V1 invalid=true'; fi\n"
    ).encode("ascii")
    console.send(b"\n" + proof, deadline=_deadline(aggregate, 5.0))
    match = console.wait_regex(
        LOGIN_RESULT_PATTERN,
        start=cursor,
        deadline=_deadline(aggregate, 15.0),
        stage="login",
    )
    if match.group(1) != LOGIN_OK_LINE:
        raise ClosedFailure("login", "identity-invalid")
    return match.end()


def _runtime_command(stage: str) -> bytes:
    if TOKEN_RE.fullmatch(stage) is None:
        raise ClosedFailure("runtime", "stage-invalid")
    # UID 1000 cannot traverse the daemon's root-only worker cgroup. This
    # evidence therefore observes only systemd's public unit facts and exact
    # /proc identities. The daemon separately re-attests its retained,
    # descriptor-bound cgroup topology before and after every worker request.
    # Every dynamic field is reduced to a closed proof token before it reaches
    # the single marker. The shell mount test remains separate from the
    # daemon's private mount namespace.
    source = f"""
stage='{stage}'; unit='kernaid-rescue-vaultd.service'; socket='kernaid-rescue-vaultd.socket';
{BOUNDED_CHILD_PID_FUNCTION}
show() {{ /usr/bin/systemctl show --property="$1" --value "$2" 2>/dev/null; }};
caps() {{ /usr/bin/awk 'BEGIN{{i=p=e=b=""}} $1=="CapInh:"{{i=$2}} $1=="CapPrm:"{{p=$2}} $1=="CapEff:"{{e=$2}} $1=="CapBnd:"{{b=$2}} END{{if(i!=""&&p!=""&&e!=""&&b!="")printf "%s:%s:%s:%s",i,p,e,b;else exit 1}}' "$1"; }};
field() {{ /usr/bin/awk -v key="$2" 'BEGIN{{v="";n=0}} $1==key{{v=$2;n++}} END{{if(n==1&&v!="")printf "%s",v;else exit 1}}' "$1"; }};
core() {{ /usr/bin/awk 'BEGIN{{v="";n=0}} $1=="Max"&&$2=="core"&&$3=="file"&&$4=="size"{{v=$5 ":" $6;n++}} END{{if(n==1)printf "%s",v;else exit 1}}' "$1"; }};
svc=$(show MainPID "$unit") || svc=0; case "$svc" in ''|*[!0-9]*) svc=0;; esac; worker=$(child "$svc");
inv=$(show InvocationID "$unit") || inv=invalid; case "$inv" in ''|*[!0-9a-f]*) inv=invalid;; esac; [ "${{#inv}}" = 32 ] || inv=invalid;
scaps=$(caps "/proc/$svc/status" 2>/dev/null) || scaps=invalid;
wcaps=$(caps "/proc/$worker/status" 2>/dev/null) || wcaps=invalid;
samb=$(field "/proc/$svc/status" CapAmb: 2>/dev/null) || samb=invalid; wamb=$(field "/proc/$worker/status" CapAmb: 2>/dev/null) || wamb=invalid;
snnp=$(field "/proc/$svc/status" NoNewPrivs: 2>/dev/null) || snnp=invalid; wnnp=$(field "/proc/$worker/status" NoNewPrivs: 2>/dev/null) || wnnp=invalid;
score=$(core "/proc/$svc/limits" 2>/dev/null) || score=invalid; wcore=$(core "/proc/$worker/limits" 2>/dev/null) || wcore=invalid;
wppid=$(field "/proc/$worker/status" PPid: 2>/dev/null) || wppid=invalid;
scg=$(/usr/bin/cat "/proc/$svc/cgroup" 2>/dev/null) || scg=invalid; wcg=$(/usr/bin/cat "/proc/$worker/cgroup" 2>/dev/null) || wcg=invalid;
control=$(show ControlGroup "$unit") || control=invalid;
controlproof=invalid; scgproof=invalid; wcgproof=invalid;
[ "$control" = "/system.slice/kernaid-rescue-vaultd.service" ] && controlproof=unit;
[ "$scg" = "0::/system.slice/kernaid-rescue-vaultd.service/supervisor" ] && scgproof=supervisor;
[ "$wcg" = "0::/system.slice/kernaid-rescue-vaultd.service/worker" ] && wcgproof=worker;
mc=0; for n in /sys/block/dm-*/dm/name; do [ -r "$n" ] || continue; read -r v <"$n" || v=; case "$v" in kernaid-vault-*) mc=$((mc+1));; esac; done;
sm=false; /usr/bin/awk '$5=="/run/kernaid/vault"||index($5,"/run/kernaid/vault/")==1{{found=1}} END{{exit found?0:1}}' /proc/self/mountinfo && sm=true;
swaps=false; [ "$(/usr/bin/awk 'END{{print NR}}' /proc/swaps 2>/dev/null)" = 1 ] && swaps=true;
sraw="$(show ActiveState "$unit"):$(show SubState "$unit")"; sstate=invalid; [ "$sraw" = active:running ] && sstate=active-running;
oraw="$(show ActiveState "$socket"):$(show SubState "$socket")"; ostate=invalid; case "$oraw" in active:listening|active:running) ostate=operational;; esac;
svc2=$(show MainPID "$unit") || svc2=0; case "$svc2" in ''|*[!0-9]*) svc2=0;; esac; worker2=$(child "$svc2");
inv2=$(show InvocationID "$unit") || inv2=invalid; case "$inv2" in ''|*[!0-9a-f]*) inv2=invalid;; esac; [ "${{#inv2}}" = 32 ] || inv2=invalid;
wppid2=$(field "/proc/$worker2/status" PPid: 2>/dev/null) || wppid2=invalid;
scg2=$(/usr/bin/cat "/proc/$svc2/cgroup" 2>/dev/null) || scg2=invalid; wcg2=$(/usr/bin/cat "/proc/$worker2/cgroup" 2>/dev/null) || wcg2=invalid;
control2=$(show ControlGroup "$unit") || control2=invalid;
{RUNTIME_IDENTITY_STABILITY_COMMAND}
printf '%s\\n' "KERNAID_VAULT_RUNTIME_V1 stage=$stage service_pid=$svc worker_pid=$worker worker_ppid=$wppid invocation_id=$inv service_caps=$scaps worker_caps=$wcaps service_ambient=$samb worker_ambient=$wamb service_nnp=$snnp worker_nnp=$wnnp service_core=$score worker_core=$wcore systemd_control_group=$controlproof service_cgroup=$scgproof worker_cgroup=$wcgproof identity_stable=$stable mapper_count=$mc shell_mount=$sm swaps_empty=$swaps service_state=$sstate socket_state=$ostate"
"""
    return " ".join(line.strip() for line in source.splitlines() if line.strip()).encode(
        "ascii"
    ) + b"\n"


def collect_runtime(
    console: SerialConsole, stage: str, cursor: int, aggregate: float
) -> tuple[RuntimeSnapshot, int]:
    console.send(_runtime_command(stage), deadline=_deadline(aggregate, 5.0))
    match = console.wait_regex(
        RUNTIME_RESULT_PATTERN,
        start=cursor,
        deadline=_deadline(aggregate, 15.0),
        stage="runtime",
    )
    return parse_runtime_snapshot(match.group(1), stage), match.end()


@dataclasses.dataclass(frozen=True)
class UnlockDiagnosticExpectation:
    service_pid: int
    invocation_id: str
    request_state_version: int


def _unlock_diagnostic_command(
    expectation: UnlockDiagnosticExpectation, response_state_version: int
) -> bytes:
    if (
        expectation.service_pid <= 1
        or re.fullmatch(r"[0-9a-f]{32}", expectation.invocation_id) is None
        or not 0 <= expectation.request_state_version <= MAX_SAFE_STATE_VERSION
        or not 0 <= response_state_version <= MAX_SAFE_STATE_VERSION
    ):
        raise ClosedFailure("unlock-diagnostic", "expectation-invalid")
    final_cases = " ".join(
        f'"{UNLOCK_IO_DIAGNOSTIC_PREFIX} reason={reason} '
        f'state-version={response_state_version}${{nl}}.rc=0") '
        f"result='{reason}'; break;;"
        for reason in UNLOCK_IO_DIAGNOSTIC_REASONS
    )
    source = f"""
unit='kernaid-rescue-vaultd.service';
nl=$(printf '\\nX'); nl=${{nl%X}};
bounded() {{ {{ /usr/bin/systemctl show --property="$1" --value "$unit" 2>/dev/null; printf '.rc=%s' "$?"; }} | /usr/bin/head -c "$2"; }};
result='diagnostic-unavailable'; attempt=0;
while [ "$attempt" -lt 50 ]; do
pid1=$(bounded MainPID 64); inv1=$(bounded InvocationID 64); status=$(bounded StatusText 256); pid2=$(bounded MainPID 64); inv2=$(bounded InvocationID 64);
if [ "$pid1" != "{expectation.service_pid}${{nl}}.rc=0" ] || [ "$pid2" != "{expectation.service_pid}${{nl}}.rc=0" ] || [ "$inv1" != "{expectation.invocation_id}${{nl}}.rc=0" ] || [ "$inv2" != "{expectation.invocation_id}${{nl}}.rc=0" ]; then break; fi;
case "$status" in {final_cases} "{UNLOCK_IO_DIAGNOSTIC_PREFIX} reason=in-progress state-version={expectation.request_state_version}${{nl}}.rc=0") ;; *) ;; esac;
attempt=$((attempt+1)); [ "$attempt" -ge 50 ] || /usr/bin/sleep 0.1;
done;
printf '%s\\n' "{UNLOCK_IO_DIAGNOSTIC_RESULT_PREFIX} reason=$result";
"""
    command = " ".join(line.strip() for line in source.splitlines() if line.strip())
    return command.encode("ascii") + b"\n"


def collect_unlock_diagnostic(
    console: SerialConsole,
    expectation: UnlockDiagnosticExpectation,
    response_state_version: int,
    cursor: int,
    aggregate: float,
) -> tuple[str, int]:
    console.send(
        _unlock_diagnostic_command(expectation, response_state_version),
        deadline=_deadline(aggregate, 5.0),
    )
    match = console.wait_regex(
        UNLOCK_IO_DIAGNOSTIC_RESULT_PATTERN,
        start=cursor,
        deadline=_deadline(aggregate, 15.0),
        stage="unlock-diagnostic",
    )
    return match.group(2).decode("ascii"), match.end()


def run_companion(
    console: SerialConsole,
    command: str,
    stage: str,
    cursor: int,
    aggregate: float,
    secret: bytearray | None = None,
    unlock_diagnostic: UnlockDiagnosticExpectation | None = None,
) -> tuple[CompanionResponse, int]:
    if command not in {"status", "unlock", "lock"} or TOKEN_RE.fullmatch(stage) is None:
        raise ClosedFailure("command", "invalid")
    begin = f"KERNAID_VAULT_CTL_BEGIN_V1_{stage}".encode("ascii")
    end = f"KERNAID_VAULT_CTL_END_V1_{stage}".encode("ascii")
    shell = (
        b"printf '%s\\n' '"
        + begin
        + b"'; /usr/bin/kernaid-rescue-vaultctl "
        + command.encode("ascii")
        + b"; rc=$?; printf '%s rc=%s\\n' '"
        + end
        + b"' \"$rc\"\n"
    )
    console.send(shell, deadline=_deadline(aggregate, 5.0))
    begin_match = console.wait_regex(
        _trusted_shell_line_pattern(begin),
        start=cursor,
        deadline=_deadline(aggregate, 10.0),
        stage="command-start",
    )
    if command == "unlock":
        if secret is None:
            raise ClosedFailure("command", "secret-missing")
        prompt = re.compile(rb"READY\r?\nVault passphrase: ")
        prompt_match = console.wait_regex(
            prompt,
            start=begin_match.end(),
            deadline=_deadline(aggregate, 30.0),
            stage="secret-prompt",
        )
        if prompt_match.start() != begin_match.end():
            raise ClosedFailure(stage, "response-prompt-invalid")
        console.send(secret, deadline=_deadline(aggregate, 5.0))
        console.send(b"\n", deadline=_deadline(aggregate, 5.0))
    end_pattern = _return_code_line_pattern(end)
    end_match = console.wait_regex(
        end_pattern,
        start=begin_match.end(),
        deadline=_deadline(aggregate, 620.0 if command != "status" else 15.0),
        stage="command-finish",
    )
    return_code = int(end_match.group(1))
    block = console.capture.snapshot()[begin_match.end() : end_match.start()]
    try:
        response = parse_companion_response(
            block, command=command, return_code=return_code
        )
    except UnlockRemoteFailure as error:
        if error.code == "unlock-remote-io-failed" and unlock_diagnostic is not None:
            try:
                reason, _ = collect_unlock_diagnostic(
                    console,
                    unlock_diagnostic,
                    error.state_version,
                    end_match.end(),
                    aggregate,
                )
            except ClosedFailure as diagnostic_error:
                if (
                    diagnostic_error.stage == "readiness"
                    and diagnostic_error.code == "not-ready"
                ):
                    raise
                reason = "diagnostic-unavailable"
            except CaptureLimitError:
                reason = "diagnostic-unavailable"
            raise ClosedFailure(
                stage, f"response-{error.code}-{reason}"
            ) from error
        raise ClosedFailure(stage, f"response-{error.code}") from error
    except ClosedFailure as error:
        if error.stage == "response":
            raise ClosedFailure(stage, f"response-{error.code}") from error
        raise
    return response, end_match.end()


def run_provider_companion(
    console: SerialConsole,
    command: str,
    stage: str,
    cursor: int,
    aggregate: float,
    secret: bytearray | None = None,
) -> tuple[ProviderCompanionResponse, int]:
    if command not in {"provider-status", "openai-configure"} or TOKEN_RE.fullmatch(
        stage
    ) is None:
        raise ClosedFailure("provider-command", "invalid")
    begin = f"KERNAID_PROVIDER_CTL_BEGIN_V1_{stage}".encode("ascii")
    end = f"KERNAID_PROVIDER_CTL_END_V1_{stage}".encode("ascii")
    shell = (
        b"printf '%s\\n' '"
        + begin
        + b"'; /usr/bin/kernaid-rescue-vaultctl "
        + command.encode("ascii")
        + b"; rc=$?; printf '%s rc=%s\\n' '"
        + end
        + b"' \"$rc\"\n"
    )
    console.send(shell, deadline=_deadline(aggregate, 5.0))
    begin_match = console.wait_regex(
        _trusted_shell_line_pattern(begin),
        start=cursor,
        deadline=_deadline(aggregate, 10.0),
        stage="provider-command-start",
    )
    if command == "openai-configure":
        if secret is None:
            raise ClosedFailure("provider-command", "secret-missing")
        prompt_match = console.wait_regex(
            re.compile(rb"READY\r?\nOpenAI API key: "),
            start=begin_match.end(),
            deadline=_deadline(aggregate, 30.0),
            stage="provider-secret-prompt",
        )
        if prompt_match.start() != begin_match.end():
            raise ClosedFailure("provider-response", "prompt-invalid")
        console.send(secret, deadline=_deadline(aggregate, 5.0))
        console.send(b"\n", deadline=_deadline(aggregate, 5.0))
    end_match = console.wait_regex(
        _return_code_line_pattern(end),
        start=begin_match.end(),
        deadline=_deadline(
            aggregate, 620.0 if command == "openai-configure" else 15.0
        ),
        stage="provider-command-finish",
    )
    block = console.capture.snapshot()[begin_match.end() : end_match.start()]
    response = parse_provider_companion_response(
        block, command=command, return_code=int(end_match.group(1))
    )
    return response, end_match.end()


def _shell_single_quote(value: bytes) -> bytes:
    return b"'" + value.replace(b"'", b"'\"'\"'") + b"'"


def run_guest_proof(
    console: SerialConsole,
    stage: str,
    python_source: bytes,
    cursor: int,
    aggregate: float,
    *,
    timeout: float = 45.0,
) -> int:
    """Run one source-fixed guest proof and accept only its closed marker."""

    if (
        TOKEN_RE.fullmatch(stage) is None
        or not python_source
        or b"\x00" in python_source
        or len(python_source) > 16 * 1024
    ):
        raise ClosedFailure("provider-proof", "source-invalid")
    begin = f"KERNAID_PROVIDER_PROOF_BEGIN_V1_{stage}".encode("ascii")
    end = f"KERNAID_PROVIDER_PROOF_END_V1_{stage}".encode("ascii")
    started = time.monotonic()
    # Reserve the complete local transaction before sending anything.  This
    # prevents the aggregate lifecycle deadline from silently shortening a
    # proof and misclassifying aggregate exhaustion as a guest timeout.
    required = 15.0 + timeout + 10.0
    if aggregate - started < required:
        raise ClosedFailure("provider-proof", "aggregate-budget")
    shell = (
        b"printf '%s\\n' '"
        + begin
        + b"'; /usr/bin/python3 -I -B -c "
        + _shell_single_quote(python_source)
        + b"; rc=$?; printf '%s rc=%s\\n' '"
        + end
        + b"' \"$rc\"\n"
    )
    console.send(shell, deadline=started + 5.0)
    begin_match = console.wait_regex(
        _trusted_shell_line_pattern(begin),
        start=cursor,
        deadline=started + 15.0,
        stage="provider-proof-start",
    )
    proof_deadline = time.monotonic() + timeout
    end_deadline = proof_deadline + 10.0
    if end_deadline > aggregate:
        raise ClosedFailure("provider-proof", "aggregate-budget")
    event_pattern = _provider_proof_event_pattern(end)
    event_match = console.wait_regex(
        event_pattern,
        start=begin_match.end(),
        deadline=proof_deadline,
        stage="provider-proof",
    )
    expected = (
        f"KERNAID_QEMU_PROVIDER_PROOF_V1 stage={stage} result=true".encode(
            "ascii"
        )
    )
    if event_match.group("end") is not None:
        return_code = _canonical_return_code(event_match.group("return_code"))
        if return_code != 0 and stage in PROVIDER_PROOF_CLOSED_STAGES:
            # The stage is selected by this controller from the closed tuple
            # above; no guest output or return-code text reaches the artifact.
            raise ClosedFailure("provider-proof", f"{stage}-command-failed")
        raise ClosedFailure(
            "provider-proof",
            "marker-missing" if return_code == 0 else "command-failed",
        )

    marker = event_match.group("success") or event_match.group("failure")
    if marker is None:
        raise ClosedFailure("provider-proof", "marker-invalid")
    end_match = console.wait_regex(
        event_pattern,
        start=event_match.end(),
        deadline=end_deadline,
        stage="provider-proof-finish",
    )
    if end_match.group("end") is None:
        raise ClosedFailure("provider-proof", "output-invalid")
    return_code = _canonical_return_code(end_match.group("return_code"))
    block = console.capture.snapshot()[begin_match.end() : end_match.start()]

    if event_match.group("success") is not None:
        if marker != expected:
            raise ClosedFailure("provider-proof", "marker-invalid")
        if return_code != 0:
            raise ClosedFailure("provider-proof", "command-failed")
        if _normalize(block) != [expected]:
            raise ClosedFailure("provider-proof", "output-invalid")
        return end_match.end()

    failure_stage = event_match.group("failure_stage").decode("ascii")
    failure_checkpoint = event_match.group("failure_checkpoint").decode("ascii")
    closed_checkpoint = (
        failure_stage in PROVIDER_PROOF_UI_STAGES
        and failure_checkpoint in PROVIDER_PROOF_UI_CHECKPOINTS
    ) or (
        failure_stage == "codex-status"
        and failure_checkpoint in PROVIDER_PROOF_CODEX_CHECKPOINTS
    )
    if failure_stage != stage or not closed_checkpoint:
        raise ClosedFailure("provider-proof", "marker-invalid")
    expected_failure = (
        f"KERNAID_QEMU_PROVIDER_PROOF_FAILURE_V1 stage={failure_stage} "
        f"checkpoint={failure_checkpoint}"
    ).encode("ascii")
    if marker != expected_failure or _normalize(block) != [expected_failure]:
        raise ClosedFailure("provider-proof", "output-invalid")
    if return_code != 45:
        raise ClosedFailure("provider-proof", "command-failed")
    # Both components were matched against closed tuples above; no guest text
    # or exception material can reach the sanitized lifecycle artifact.
    raise ClosedFailure("provider-proof", f"{failure_stage}-{failure_checkpoint}")


PROVIDER_STATUS_PROBE_SOCKET = "/run/kernaid-provider-executor-status-probe.sock"
PROVIDER_LEASE_PROBE_SOCKET = "/run/kernaid-provider-lease-probe.sock"
PROVIDER_LEASE_KILL_SOCKET = "/run/kernaid-provider-lease-kill-vaultd.sock"
PROVIDER_EXECUTOR_SOCKET_UNIT = "kernaid-rescue-openai-executor.socket"
PROVIDER_EXECUTOR_PROOF_UNIT = (
    "kernaid-rescue-openai-executor@kernaid-qemu-proof.service"
)
PROVIDER_EXECUTOR_TEMPLATE_PATH = (
    "/etc/systemd/system/kernaid-rescue-openai-executor@.service"
)
PROVIDER_LEASE_PROOF_UNIT = "kernaid-provider-lease-probe@kernaid-qemu-proof.service"
PROVIDER_LEASE_TEMPLATE_PATH = (
    "/etc/systemd/system/kernaid-provider-lease-probe@.service"
)
PROVIDER_EGRESS_SERVICE_UNIT = "kernaid-rescue-openai-egress.service"
PROVIDER_UI_SERVICE_UNIT = "kernaid-ui.service"
CODEX_SOCKET_UNIT = "kernaid-rescue-codex.socket"
CODEX_PROOF_UNIT = "kernaid-rescue-codex@kernaid-qemu-proof.service"
CODEX_TEMPLATE_PATH = "/etc/systemd/system/kernaid-rescue-codex@.service"
TEST_CREDENTIAL_PREFIXES = (
    "kernaid-provider-executor-status-probe@",
    "kernaid-provider-lease-probe@",
    "kernaid-provider-lease-kill-vaultd@",
)


def _socket_probe_source(
    stage: str, path: str, request: bytes, expected: bytes
) -> bytes:
    if (
        TOKEN_RE.fullmatch(stage) is None
        or not path.startswith("/run/kernaid-")
        or not request.endswith(b"\n")
        or not expected.endswith(b"\n")
        or max(len(request), len(expected)) > 256
    ):
        raise ClosedFailure("provider-proof", "source-invalid")
    proof = f"KERNAID_QEMU_PROVIDER_PROOF_V1 stage={stage} result=true\n"
    return f'''import socket,subprocess,sys
def show(prop,unit):
    result=subprocess.run(["/usr/bin/systemctl","show","--property="+prop,"--value",unit],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=3,check=False)
    if result.returncode!=0 or len(result.stdout)>512:
        raise RuntimeError()
    return result.stdout.rstrip(b"\\n")
try:
    template={PROVIDER_LEASE_PROOF_UNIT!r}
    if show("LoadState",template)!=b"loaded" or show("FragmentPath",template)!={PROVIDER_LEASE_TEMPLATE_PATH.encode('ascii')!r} or show("BindsTo",template)!=b"kernaid-rescue-vaultd.service":
        raise RuntimeError()
    connection=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
    connection.settimeout(30.0)
    connection.connect({path!r})
    connection.sendall({request!r})
    connection.shutdown(socket.SHUT_WR)
    observed=bytearray()
    while True:
        chunk=connection.recv(256)
        if not chunk:
            break
        observed.extend(chunk)
        if len(observed)>256:
            raise RuntimeError()
    connection.close()
    if bytes(observed)!={expected!r}:
        raise RuntimeError()
except BaseException:
    sys.exit(41)
sys.stdout.write({proof!r})
'''.encode("ascii")


def _production_status_probe_source() -> bytes:
    stage = "production-status"
    request = b"STATUS\n"
    expected = (
        b"KERNAID_PROVIDER_EXECUTOR_STATUS_PROBE_V1 "
        b"status=true shipping=true\n"
    )
    proof = f"KERNAID_QEMU_PROVIDER_PROOF_V1 stage={stage} result=true\n"
    return f'''import re,socket,subprocess,sys,time
def show(prop,unit):
    result=subprocess.run(["/usr/bin/systemctl","show","--property="+prop,"--value",unit],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=3,check=False)
    if result.returncode!=0 or len(result.stdout)>512:
        raise RuntimeError()
    return result.stdout.rstrip(b"\\n")
try:
    template={PROVIDER_EXECUTOR_PROOF_UNIT!r}
    if show("LoadState",template)!=b"loaded" or show("FragmentPath",template)!={PROVIDER_EXECUTOR_TEMPLATE_PATH.encode('ascii')!r} or show("BindsTo",template)!=b"kernaid-rescue-vaultd.service":
        raise RuntimeError()
    if show("ActiveState","kernaid-rescue-openai-egress.service")!=b"inactive":
        raise RuntimeError()
    connection=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
    connection.settimeout(30.0)
    connection.connect({PROVIDER_STATUS_PROBE_SOCKET!r})
    connection.sendall({request!r})
    connection.shutdown(socket.SHUT_WR)
    observed=bytearray()
    while True:
        chunk=connection.recv(256)
        if not chunk:
            break
        observed.extend(chunk)
        if len(observed)>256:
            raise RuntimeError()
    connection.close()
    if bytes(observed)!={expected!r}:
        raise RuntimeError()
    deadline=time.monotonic()+5.0
    while show("ActiveState","kernaid-rescue-openai-egress.service")!=b"inactive":
        if time.monotonic()>=deadline:
            raise RuntimeError()
        time.sleep(0.05)
except BaseException:
    sys.exit(42)
sys.stdout.write({proof!r})
'''.encode("ascii")


def _codex_status_probe_source() -> bytes:
    """Exercise the shipping Codex bridge protocol and pinned CLI, offline."""

    stage = "codex-status"
    proof = f"KERNAID_QEMU_PROVIDER_PROOF_V1 stage={stage} result=true\n"
    failures = "\n".join(
        f"    {checkpoint!r}: "
        f"{'KERNAID_QEMU_PROVIDER_PROOF_FAILURE_V1 ' f'stage={stage} checkpoint={checkpoint}\n'!r},"
        for checkpoint in PROVIDER_PROOF_CODEX_CHECKPOINTS
    )
    error_codes = PROVIDER_PROOF_CODEX_REMOTE_ERRORS
    return f'''import json,re,socket,subprocess,sys,time
API="kernaid.dev/rescue-codex-auth/v1alpha1"
REQUEST_ID="C-90000000-0000-4000-8000-000000000003"
SOCKET_PATH="/run/kernaid-rescue-codex.sock"
ERROR_CODES={error_codes!r}
FAILURES={{
{failures}
}}
def show(prop,unit):
    result=subprocess.run(["/usr/bin/systemctl","show","--property="+prop,"--value",unit],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=3,check=False)
    if result.returncode!=0 or len(result.stdout)>512:
        raise RuntimeError()
    return result.stdout.rstrip(b"\\n")
def fail(checkpoint):
    marker=FAILURES.get(checkpoint)
    if marker is None:
        sys.exit(46)
    sys.stdout.write(marker)
    sys.exit(45)
def unique(pairs):
    result={{}}
    for key,value in pairs:
        if type(key) is not str or key in result:
            raise ValueError()
        result[key]=value
    return result
def rejected(_value):
    raise ValueError()
checkpoint="unit"
connection=None
try:
    template={CODEX_PROOF_UNIT!r}
    if show("LoadState",template)!=b"loaded" or show("FragmentPath",template)!={CODEX_TEMPLATE_PATH.encode('ascii')!r} or show("BindsTo",template)!=b"kernaid-rescue-vaultd.service" or show("User",template)!=b"kernaid-codex" or show("Group",template)!=b"kernaid-codex" or show("SupplementaryGroups",template)!=b"kernaid-vault":
        raise RuntimeError()
    checkpoint="socket"
    if show("ActiveState",{CODEX_SOCKET_UNIT!r})!=b"active" or show("SubState",{CODEX_SOCKET_UNIT!r})!=b"listening":
        raise RuntimeError()
    checkpoint="accepted"
    accepted=show("NAccepted",{CODEX_SOCKET_UNIT!r})
    if re.fullmatch(rb"0|[1-9][0-9]*",accepted) is None:
        raise RuntimeError()
    before=int(accepted)
    request={{"apiVersion":API,"requestId":REQUEST_ID,"operation":"status"}}
    encoded=json.dumps(request,ensure_ascii=True,separators=(",",":")).encode("ascii")
    checkpoint="connect"
    connection=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET|socket.SOCK_CLOEXEC)
    connection.settimeout({CODEX_STATUS_SOCKET_TIMEOUT_SECONDS!r})
    connection.connect(SOCKET_PATH)
    checkpoint="send"
    if connection.send(encoded)!=len(encoded):
        raise RuntimeError()
    connection.shutdown(socket.SHUT_WR)
    checkpoint="receive"
    frame,ancillary,flags,_address=connection.recvmsg(2049)
    checkpoint="frame"
    if ancillary or flags&(socket.MSG_TRUNC|socket.MSG_CTRUNC) or not frame or len(frame)>2048 or not frame.endswith(b"\\n") or b"\\n" in frame[:-1] or b"\\r" in frame:
        raise RuntimeError()
    connection.close()
    connection=None
    checkpoint="decode"
    response=json.loads(frame[:-1].decode("ascii"),object_pairs_hook=unique,parse_constant=rejected)
    checkpoint="response"
    if type(response) is not dict or response.get("apiVersion")!=API or response.get("requestId")!=REQUEST_ID or response.get("operation")!="status":
        raise RuntimeError()
    remote_error=None
    if response.get("stage")=="error":
        if set(response)!={{"apiVersion","requestId","operation","stage","code"}} or response.get("code") not in ERROR_CODES:
            raise RuntimeError()
        remote_error=response["code"]
    elif set(response)!={{"apiVersion","requestId","operation","stage","status"}} or response.get("stage")!="complete" or response.get("status")!="signed-out":
        raise RuntimeError()
    checkpoint="accepted"
    if show("NAccepted",{CODEX_SOCKET_UNIT!r})!=str(before+1).encode("ascii"):
        raise RuntimeError()
    checkpoint="connection-drain"
    deadline=time.monotonic()+5.0
    while show("NConnections",{CODEX_SOCKET_UNIT!r})!=b"0":
        if time.monotonic()>=deadline:
            raise RuntimeError()
        time.sleep(0.05)
    if remote_error is not None:
        if remote_error=="transport":
            fail("server-transport")
        fail(remote_error)
except SystemExit:
    raise
except BaseException:
    if checkpoint=="receive":
        try:
            connections=show("NConnections",{CODEX_SOCKET_UNIT!r})
        except BaseException:
            fail("receive-state")
        if connections==b"1":
            fail("receive-active")
        if connections==b"0":
            fail("receive-ended")
        fail("receive-state")
    fail(checkpoint)
finally:
    if connection is not None:
        connection.close()
sys.stdout.write({proof!r})
'''.encode("ascii")


def _signed_report_probe_source(boot: int, expected_state_version: int) -> bytes:
    """Prove the shipping UI audit/report path and cross-boot persistence."""

    if (
        boot not in {1, 2}
        or not 0 <= expected_state_version <= MAX_SAFE_STATE_VERSION - 8
    ):
        raise ClosedFailure("provider-proof", "source-invalid")
    reports: dict[str, str] = {}
    for index in range(1, boot + 1):
        report_id = f"RP-90000000-0000-4000-8000-{index:012d}"
        reports[report_id] = json.dumps(
            {
                "schemaVersion": "1.0",
                "sessionId": f"S-qemu-signed-report-{index}",
                "targetFingerprint": f"sha256:{'a' * 64}",
                "facts": [],
                "inferences": [],
                "decisions": [],
                "events": [],
                "verification": "not-run",
                "unresolvedRisks": ["QEMU qualification report"],
            },
            ensure_ascii=True,
            separators=(",", ":"),
        )
    current_report_id = next(reversed(reports))
    proof = "KERNAID_QEMU_PROVIDER_PROOF_V1 stage=signed-report result=true\n"
    return f'''import base64,errno,hashlib,http.client,json,os,re,select,stat,sys,time
API="kernaid.dev/rescue-application-http/v1alpha1"
HOST="127.0.0.1:4173"
ORIGIN="http://127.0.0.1:4173"
SIGNED_MEDIA="application/vnd.kernaid.signed-report+json"
REPORTS={reports!r}
CURRENT={current_report_id!r}
EXPECTED_VERSION={expected_state_version}
MAX_BODY=1536*1024
def rejected(_value):
    raise ValueError()
def unique(pairs):
    result={{}}
    for key,value in pairs:
        if type(key) is not str or key in result:
            raise ValueError()
        result[key]=value
    return result
def decode(data):
    return json.loads(data.decode("ascii"),object_pairs_hook=unique,parse_float=rejected,parse_constant=rejected)
def exact(value,keys):
    if type(value) is not dict or set(value)!=set(keys):
        raise RuntimeError()
    return value
def request(method,path,body=None,accept="application/json"):
    encoded=None
    headers={{"Host":HOST,"Origin":ORIGIN,"Sec-Fetch-Site":"same-origin","Accept":accept}}
    if body is not None:
        encoded=json.dumps(body,ensure_ascii=True,separators=(",", ":")).encode("ascii")
        headers["Content-Type"]="application/json"
    connection=http.client.HTTPConnection("127.0.0.1",4173,timeout=15.0)
    try:
        connection.request(method,path,body=encoded,headers=headers)
        response=connection.getresponse()
        data=response.read(MAX_BODY+1)
        if len(data)>MAX_BODY:
            raise RuntimeError()
        return response.status,response.headers,data
    finally:
        connection.close()
def json_response(method,path,body=None):
    status,headers,data=request(method,path,body)
    if status!=200 or headers.get_all("Content-Type")!=["application/json"] or headers.get_all("Content-Length")!=[str(len(data))]:
        raise RuntimeError()
    return decode(data)
def safe_version(value):
    return type(value) is int and 0<=value<=9007199254740991
def summary(value):
    item=exact(value,("reportId","envelopeSize","envelopeSha256"))
    if type(item["reportId"]) is not str or re.fullmatch(r"RP-[0-9a-f]{{8}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-[0-9a-f]{{12}}",item["reportId"]) is None or type(item["envelopeSize"]) is not int or not 2<=item["envelopeSize"]<=MAX_BODY or type(item["envelopeSha256"]) is not str or re.fullmatch(r"[0-9a-f]{{64}}",item["envelopeSha256"]) is None:
        raise RuntimeError()
    return item
def urlsafe(value,size):
    if type(value) is not str or re.fullmatch(r"[A-Za-z0-9_-]+",value) is None:
        raise RuntimeError()
    try:
        decoded=base64.b64decode(value+"="*((4-len(value)%4)%4),altchars=b"-_",validate=True)
    except BaseException as error:
        raise RuntimeError() from error
    if len(decoded)!=size:
        raise RuntimeError()
    return decoded
def companion(arguments):
    pid,master=os.forkpty()
    if pid==0:
        try:
            os.execv("/usr/bin/kernaid-rescue-vaultctl",["kernaid-rescue-vaultctl",*arguments])
        except BaseException:
            os._exit(127)
    output=bytearray()
    child_status=None
    eof=False
    deadline=time.monotonic()+15.0
    os.set_blocking(master,False)
    try:
        while child_status is None or not eof:
            if time.monotonic()>=deadline:
                if child_status is None:
                    os.kill(pid,9)
                    child_status=os.waitpid(pid,0)[1]
                raise RuntimeError()
            if child_status is None:
                waited,status=os.waitpid(pid,os.WNOHANG)
                if waited==pid:
                    child_status=status
            readable,_,_=select.select([master],[],[],0.1)
            if readable:
                try:
                    chunk=os.read(master,4096)
                except OSError as error:
                    if error.errno!=errno.EIO:
                        raise
                    chunk=b""
                if chunk:
                    output.extend(chunk)
                    if len(output)>2048:
                        raise RuntimeError()
                else:
                    eof=True
        if child_status is None or os.waitstatus_to_exitcode(child_status)!=0:
            raise RuntimeError()
        return bytes(output).replace(b"\\r\\n",b"\\n")
    finally:
        if child_status is None:
            try:
                os.kill(pid,9)
            except ProcessLookupError:
                pass
            try:
                os.waitpid(pid,0)
            except ChildProcessError:
                pass
        os.close(master)
try:
    status=json_response("GET","/api/rescue/vault/status")
    exact(status,("apiVersion","stateVersion","vaultState"))
    if status["apiVersion"]!=API or status["vaultState"]!="unlocked" or not safe_version(status["stateVersion"]) or status["stateVersion"]!=EXPECTED_VERSION:
        raise RuntimeError()
    version=EXPECTED_VERSION
    for sequence,event in enumerate(("agent-session-start","agent-diagnosis-complete","agent-session-end"),1):
        outcome=json_response("POST","/api/rescue/audit-append",{{"expectedStateVersion":version,"sequence":sequence,"event":event,"outcome":"succeeded"}})
        exact(outcome,("apiVersion","stateVersion","sequence"))
        version+=2
        if not safe_version(outcome["stateVersion"]) or type(outcome["sequence"]) is not int or outcome!={{"apiVersion":API,"stateVersion":version,"sequence":sequence}}:
            raise RuntimeError()
    report_json=REPORTS[CURRENT]
    payload_sha256=hashlib.sha256(report_json.encode("ascii")).hexdigest()
    stored=json_response("POST","/api/rescue/report-persist",{{"expectedStateVersion":version,"reportId":CURRENT,"payloadSha256":payload_sha256,"reportJson":report_json}})
    exact(stored,("apiVersion","stateVersion","report"))
    version+=2
    current_summary=summary(stored["report"])
    if stored["apiVersion"]!=API or not safe_version(stored["stateVersion"]) or stored["stateVersion"]!=version or current_summary["reportId"]!=CURRENT or version!=EXPECTED_VERSION+8:
        raise RuntimeError()
    listing=json_response("GET","/api/rescue/reports")
    exact(listing,("apiVersion","stateVersion","reports"))
    if listing["apiVersion"]!=API or not safe_version(listing["stateVersion"]) or listing["stateVersion"]!=version or type(listing["reports"]) is not list or len(listing["reports"])!=len(REPORTS):
        raise RuntimeError()
    indexed={{item["reportId"]:item for item in map(summary,listing["reports"])}}
    if set(indexed)!=set(REPORTS) or indexed[CURRENT]!=current_summary:
        raise RuntimeError()
    signers=set()
    current_envelope=None
    for report_id,expected_json in REPORTS.items():
        item=indexed[report_id]
        status_code,headers,envelope_bytes=request("GET","/api/rescue/reports/"+report_id,accept=SIGNED_MEDIA)
        if status_code!=200 or headers.get_all("Content-Type")!=[SIGNED_MEDIA] or headers.get_all("Content-Length")!=[str(item["envelopeSize"])] or headers.get_all("X-KernAid-Envelope-Sha256")!=[item["envelopeSha256"]] or headers.get_all("ETag")!=['"sha256-'+item["envelopeSha256"]+'"'] or len(envelope_bytes)!=item["envelopeSize"] or hashlib.sha256(envelope_bytes).hexdigest()!=item["envelopeSha256"]:
            raise RuntimeError()
        envelope=exact(decode(envelope_bytes),("schema","kind","algorithm","deviceId","journalSequence","journalEntryHash","payloadMediaType","payloadSha256","payload","publicKey","signature"))
        expected_payload=expected_json.encode("ascii")
        if envelope["schema"]!="https://schemas.kernaid.dev/v1/signed-report-envelope.json" or envelope["kind"]!="kernaid.signed-report" or envelope["algorithm"]!="Ed25519" or type(envelope["deviceId"]) is not str or re.fullmatch(r"KA-[0-9a-f]{{24}}",envelope["deviceId"]) is None or type(envelope["journalSequence"]) is not int or envelope["journalSequence"]<1 or envelope["payloadMediaType"]!="application/json" or envelope["payloadSha256"]!=hashlib.sha256(expected_payload).hexdigest() or urlsafe(envelope["journalEntryHash"],32) is None or urlsafe(envelope["payload"],len(expected_payload))!=expected_payload or urlsafe(envelope["publicKey"],32) is None or urlsafe(envelope["signature"],64) is None:
            raise RuntimeError()
        signers.add((envelope["deviceId"],envelope["publicKey"]))
        if report_id==CURRENT:
            current_envelope=envelope_bytes
    if len(signers)!=1 or current_envelope is None:
        raise RuntimeError()
    item=indexed[CURRENT]
    export_path="/home/kernaid/KernAid-Reports/"+CURRENT+".signed.json"
    expected_output=("stateVersion: "+str(version)+"\\nreportId: "+CURRENT+"\\nenvelopeSize: "+str(item["envelopeSize"])+"\\nenvelopeSha256: "+item["envelopeSha256"]+"\\npath: "+export_path+"\\n").encode("ascii")
    if companion(["report-export",CURRENT])!=expected_output:
        raise RuntimeError()
    directory_stat=os.lstat("/home/kernaid/KernAid-Reports")
    named_stat=os.lstat(export_path)
    descriptor=os.open(export_path,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW)
    try:
        file_stat=os.fstat(descriptor)
        exported=bytearray()
        while len(exported)<=MAX_BODY:
            chunk=os.read(descriptor,min(65536,MAX_BODY+1-len(exported)))
            if not chunk:
                break
            exported.extend(chunk)
    finally:
        os.close(descriptor)
    if not stat.S_ISDIR(directory_stat.st_mode) or stat.S_IMODE(directory_stat.st_mode)!=0o700 or directory_stat.st_uid!=1000 or directory_stat.st_gid!=1000 or (named_stat.st_dev,named_stat.st_ino)!=(file_stat.st_dev,file_stat.st_ino) or not stat.S_ISREG(file_stat.st_mode) or stat.S_IMODE(file_stat.st_mode)!=0o600 or file_stat.st_uid!=1000 or file_stat.st_gid!=1000 or file_stat.st_nlink!=1 or file_stat.st_size!=len(current_envelope):
        raise RuntimeError()
    if bytes(exported)!=current_envelope or hashlib.sha256(exported).hexdigest()!=item["envelopeSha256"]:
        raise RuntimeError()
except BaseException:
    sys.exit(47)
sys.stdout.write({proof!r})
'''.encode("ascii")


def _production_ui_relay_probe_source(stage: str) -> bytes:
    """Exercise the shipping HTTP relay without placing a wire frame in the PTY."""

    if stage == "ui-diagnose-unconfigured":
        operation = "provider.openai.diagnose"
        request_id = "O-90000000-0000-0000-0000-000000000001"
        timeout = 130.0
        budget = 140.0
    elif stage == "ui-status-configured":
        operation = "provider.status"
        request_id = "O-90000000-0000-0000-0000-000000000002"
        timeout = 5.0
        budget = 10.0
    else:
        raise ClosedFailure("provider-proof", "stage-invalid")
    proof = f"KERNAID_QEMU_PROVIDER_PROOF_V1 stage={stage} result=true\n"
    failures = "\n".join(
        f"    {checkpoint!r}: "
        f"{'KERNAID_QEMU_PROVIDER_PROOF_FAILURE_V1 ' f'stage={stage} checkpoint={checkpoint}\n'!r},"
        for checkpoint in PROVIDER_PROOF_UI_CHECKPOINTS
    )
    outcome_checkpoints = "\n".join(
        f"    {error!r}: {checkpoint!r},"
        for error, checkpoint in PROVIDER_PROOF_UI_ERROR_CHECKPOINTS
    )
    return f'''import http.client,json,os,re,subprocess,sys,time
API="kernaid.dev/rescue-openai/v1alpha1"
ENDPOINT="/api/rescue/provider/openai"
HOST="127.0.0.1:4173"
ORIGIN="http://127.0.0.1:4173"
PORT=4173
EXECUTOR={PROVIDER_EXECUTOR_SOCKET_UNIT!r}
EGRESS={PROVIDER_EGRESS_SERVICE_UNIT!r}
UI={PROVIDER_UI_SERVICE_UNIT!r}
OPERATION={operation!r}
REQUEST_ID={request_id!r}
TIMEOUT={timeout!r}
BUDGET={budget!r}
MAX_REQUEST=96*1024
MAX_RESPONSE=64*1024
MAX_BUSY_RETRIES=5
BUSY_BODY=b'{{"error":{{"code":"busy"}}}}'
BUSY=object()
FAILURES={{
{failures}
}}
OUTCOME_CHECKPOINTS={{
{outcome_checkpoints}
}}
DEADLINE=time.monotonic()+BUDGET
checkpoint="ui-identity"
def remaining(limit):
    value=DEADLINE-time.monotonic()
    if value<=0:
        raise RuntimeError()
    return min(limit,value)
def show(prop,unit):
    result=subprocess.run(["/usr/bin/systemctl","show","--property="+prop,"--value",unit],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=remaining(3.0),check=False)
    if result.returncode!=0 or len(result.stdout)>512:
        raise RuntimeError()
    return result.stdout.rstrip(b"\\n")
def number(prop,unit):
    value=show(prop,unit)
    if re.fullmatch(rb"0|[1-9][0-9]*",value) is None:
        raise RuntimeError()
    return int(value)
def unique(pairs):
    result={{}}
    for key,value in pairs:
        if key in result:
            raise ValueError()
        result[key]=value
    return result
def rejected(_value):
    raise ValueError()
def exact(value,keys):
    if type(value) is not dict or set(value)!=set(keys):
        raise RuntimeError()
    return value
def wait_retry_interval():
    target=time.monotonic()+1.0
    if target>=DEADLINE:
        raise RuntimeError()
    while True:
        delay=target-time.monotonic()
        if delay<=0:
            return
        time.sleep(delay)
def exchange(request):
    encoded=json.dumps(request,ensure_ascii=True,separators=(",",":")).encode("ascii")
    body=bytearray(encoded)
    body.append(10)
    if len(body)>MAX_REQUEST or body[:1]!=b"{{" or body[-2:]!=b"}}\\n" or b"\\n" in body[:-1] or b"\\r" in body:
        raise RuntimeError()
    connection=http.client.HTTPConnection("127.0.0.1",PORT,timeout=remaining(TIMEOUT))
    observed=bytearray()
    response=None
    transport=None
    try:
        connection.putrequest("POST",ENDPOINT,skip_host=True,skip_accept_encoding=True)
        connection.putheader("Host",HOST)
        connection.putheader("Origin",ORIGIN)
        connection.putheader("Sec-Fetch-Site","same-origin")
        connection.putheader("Content-Type","application/json")
        connection.putheader("Content-Length",str(len(body)))
        connection.putheader("Connection","close")
        connection.endheaders(body)
        if connection.sock is None:
            raise RuntimeError()
        transport=connection.sock
        transport.settimeout(remaining(TIMEOUT))
        response=connection.getresponse()
        lengths=response.headers.get_all("Content-Length",[])
        retries=response.headers.get_all("Retry-After",[])
        if response.status not in (200,429) or response.headers.get_all("Content-Type",[])!=["application/json"] or response.headers.get_all("Cache-Control",[])!=["no-store"] or response.headers.get_all("X-Content-Type-Options",[])!=["nosniff"] or response.headers.get_all("Transfer-Encoding",[]) or response.headers.get_all("Content-Encoding",[]) or len(lengths)!=1 or re.fullmatch(r"0|[1-9][0-9]*",lengths[0]) is None:
            raise RuntimeError()
        declared=int(lengths[0])
        if declared>MAX_RESPONSE:
            raise RuntimeError()
        transport.settimeout(remaining(TIMEOUT))
        observed.extend(response.read(declared+1))
        if len(observed)!=declared:
            raise RuntimeError()
        if response.status==429:
            if lengths!=["25"] or retries!=["1"] or bytes(observed)!=BUSY_BODY:
                raise RuntimeError()
            return BUSY
        if retries or observed[:1]!=b"{{" or observed[-2:]!=b"}}\\n" or b"\\n" in observed[:-1] or b"\\r" in observed:
            raise RuntimeError()
        text=observed[:-1].decode("utf-8","strict")
        parsed=json.loads(text,object_pairs_hook=unique,parse_int=rejected,parse_float=rejected,parse_constant=rejected)
        del text
        return parsed
    finally:
        if response is not None:
            response.close()
        connection.close()
        if transport is not None:
            transport.close()
        body[:]=b"\\0"*len(body)
        observed[:]=b"\\0"*len(observed)
def exchange_with_busy_retry(request,baseline):
    for attempt in range(MAX_BUSY_RETRIES+1):
        attempt_baseline=baseline()
        response=exchange(request)
        if response is not BUSY:
            return response,attempt_baseline
        if attempt==MAX_BUSY_RETRIES:
            return BUSY,None
        wait_retry_interval()
    raise RuntimeError()
try:
    checkpoint="ui-identity"
    if show("ActiveState",UI)!=b"active" or show("SubState",UI)!=b"running" or show("FragmentPath",UI)!=b"/etc/systemd/system/kernaid-ui.service":
        raise RuntimeError()
    ui_pid=show("MainPID",UI)
    if re.fullmatch(rb"[1-9][0-9]*",ui_pid) is None:
        raise RuntimeError()
    with open("/proc/"+ui_pid.decode("ascii")+"/cmdline","rb") as stream:
        if stream.read(256)!=b"/usr/bin/python3\\0-I\\0/usr/lib/kernaid/rescue_server.py\\0":
            raise RuntimeError()
    def capture_baseline():
        global checkpoint
        checkpoint="socket-baseline"
        if show("ActiveState",EXECUTOR)!=b"active" or show("SubState",EXECUTOR) not in (b"listening",b"running") or number("NConnections",EXECUTOR)!=0:
            raise RuntimeError()
        accepted=number("NAccepted",EXECUTOR)
        egress_enter=show("ActiveEnterTimestampMonotonic",EGRESS)
        if show("ActiveState",EGRESS)!=b"inactive":
            raise RuntimeError()
        checkpoint="http-response"
        return accepted,egress_enter
    if OPERATION=="provider.openai.diagnose":
        corpus={{"family":"windows","installationConfirmed":False,"installationMarkers":{{"windowsDirectoryPresent":False,"system32DirectoryPresent":False,"kernelPresent":False,"systemHivePresent":False,"softwareHivePresent":False,"usersDirectoryPresent":False}},"boot":{{"bootManagerPresent":False,"bcdPresent":False,"efiSystemPartition":{{"state":"not-present","microsoftBootManagerPresent":None,"bcdPresent":None,"fallbackBootloaderPresent":None}}}},"servicing":{{"pendingXmlPresent":False,"rebootPendingMarkerPresent":False}}}}
        payload={{"objective":"Qualifica il relay Rescue in sola lettura","evidence":[{{"schemaVersion":"1.0","id":"E-QEMU-RELAY","collector":"rescue.installed-target.filesystem-content.read-only.v1","target":"selected-installed-target","contentType":"application/json","trust":"observed-untrusted","summary":"Corpus statico windows acquisito read-only; installazione non confermata","content":json.dumps(corpus,ensure_ascii=True,separators=(",",":"))}}]}}
    else:
        payload={{}}
    request={{"apiVersion":API,"requestId":REQUEST_ID,"operation":OPERATION,"payload":payload}}
    checkpoint="http-response"
    response,attempt_baseline=exchange_with_busy_retry(request,capture_baseline)
    if response is BUSY or attempt_baseline is None:
        checkpoint="relay-busy"
        raise RuntimeError()
    accepted_before,egress_before=attempt_baseline
    checkpoint="socket-accounting"
    accepted_after=number("NAccepted",EXECUTOR)
    if accepted_after!=accepted_before+1 or show("ActiveState",EGRESS)!=b"inactive" or show("ActiveEnterTimestampMonotonic",EGRESS)!=egress_before:
        raise RuntimeError()
    checkpoint="quiescence"
    deadline=min(time.monotonic()+5.0,DEADLINE)
    while number("NConnections",EXECUTOR)!=0:
        if time.monotonic()>=deadline:
            raise RuntimeError()
        time.sleep(0.05)
    checkpoint="envelope"
    envelope=exact(response,("apiVersion","requestId","operation","ok","error") if OPERATION=="provider.openai.diagnose" else ("apiVersion","requestId","operation","ok","payload"))
    if envelope["apiVersion"]!=API or envelope["requestId"]!=REQUEST_ID or envelope["operation"]!=OPERATION:
        raise RuntimeError()
    checkpoint="outcome"
    if OPERATION=="provider.openai.diagnose":
        error=exact(envelope["error"],("code",))
        if envelope["ok"] is not False:
            raise RuntimeError()
        if error["code"]!="credential_unavailable":
            checkpoint=OUTCOME_CHECKPOINTS.get(error["code"],"outcome")
            raise RuntimeError()
    else:
        status=exact(envelope["payload"],("provider","profile","vault","credential"))
        if envelope["ok"] is not True or status!={{"provider":"openai","profile":"rescue-default","vault":"unlocked","credential":"configured"}}:
            raise RuntimeError()
except BaseException:
    sys.stdout.write(FAILURES[checkpoint])
    sys.exit(45)
sys.stdout.write({proof!r})
'''.encode("ascii")


def _hold_probe_source(old_service_pid: int, old_worker_pid: int) -> bytes:
    if min(old_service_pid, old_worker_pid) <= 1:
        raise ClosedFailure("provider-proof", "identity-invalid")
    stage = "hold-kill"
    expected = (
        b"KERNAID_PROVIDER_LEASE_PROBE_HOLD_V1 borrowed=true unread=true\n"
    )
    proof = f"KERNAID_QEMU_PROVIDER_PROOF_V1 stage={stage} result=true\n"
    return f'''import os,re,socket,subprocess,sys,time
def run(args):
    result=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=3,check=False)
    if len(result.stdout)>4096:
        raise RuntimeError()
    return result
def show(prop,unit):
    result=run(["/usr/bin/systemctl","show","--property="+prop,"--value",unit])
    if result.returncode!=0:
        raise RuntimeError()
    return result.stdout.rstrip(b"\\n")
try:
    connection=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
    connection.settimeout(45.0)
    connection.connect({PROVIDER_LEASE_PROBE_SOCKET!r})
    hold_started=time.monotonic()
    connection.sendall(b"HOLD\\n")
    connection.shutdown(socket.SHUT_WR)
    discovery_deadline=time.monotonic()+10.0
    names=[]
    while not names:
        units=run(["/usr/bin/systemctl","list-units","--all","--no-legend","--plain","--state=running","kernaid-provider-lease-probe@*.service"])
        if units.returncode!=0:
            raise RuntimeError()
        names=[line.split(None,1)[0].decode("ascii") for line in units.stdout.splitlines() if line]
        names=[name for name in names if name.startswith("kernaid-provider-lease-probe@") and name.endswith(".service")]
        if len(names)>1 or (not names and time.monotonic()>=discovery_deadline):
            raise RuntimeError()
        if not names:
            time.sleep(0.05)
    unit=names[0]
    helper_pid=show("MainPID",unit).decode("ascii")
    invocation=show("InvocationID",unit).decode("ascii")
    if re.fullmatch(r"[1-9][0-9]*",helper_pid) is None or re.fullmatch(r"[0-9a-f]{{32}}",invocation) is None:
        raise RuntimeError()
    observed=bytearray()
    while b"\\n" not in observed:
        chunk=connection.recv(256)
        if not chunk:
            raise RuntimeError()
        observed.extend(chunk)
        if len(observed)>256:
            raise RuntimeError()
    if bytes(observed)!={expected!r}:
        raise RuntimeError()
    while True:
        chunk=connection.recv(256)
        if not chunk:
            break
        raise RuntimeError()
    if time.monotonic()-hold_started<15.0:
        raise RuntimeError()
    connection.close()
    deadline=time.monotonic()+15.0
    watched=(helper_pid,str({old_service_pid}),str({old_worker_pid}))
    trigger_paths=({PROVIDER_STATUS_PROBE_SOCKET!r},{PROVIDER_LEASE_PROBE_SOCKET!r},{PROVIDER_LEASE_KILL_SOCKET!r})
    while True:
        processes_gone=not any(os.path.lexists("/proc/"+pid) for pid in watched)
        sockets_gone=not any(os.path.lexists(path) for path in trigger_paths)
        credentials_gone=not any(name.startswith({TEST_CREDENTIAL_PREFIXES!r}) for name in os.listdir("/run/credentials"))
        if processes_gone and sockets_gone and credentials_gone:
            break
        if time.monotonic()>=deadline:
            raise RuntimeError()
        time.sleep(0.05)
except BaseException:
    sys.exit(43)
sys.stdout.write({proof!r})
'''.encode("ascii")


def _post_fault_probe_source(
    old_service_pid: int, old_worker_pid: int, old_invocation_id: str
) -> bytes:
    if (
        min(old_service_pid, old_worker_pid) <= 1
        or re.fullmatch(r"[0-9a-f]{32}", old_invocation_id) is None
    ):
        raise ClosedFailure("provider-proof", "identity-invalid")
    stage = "post-fault"
    proof = f"KERNAID_QEMU_PROVIDER_PROOF_V1 stage={stage} result=true\n"
    return f'''import glob,os,re,subprocess,sys
def run(args):
    result=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=3,check=False)
    if len(result.stdout)>4096:
        raise RuntimeError()
    return result
def show(prop,unit):
    result=run(["/usr/bin/systemctl","show","--property="+prop,"--value",unit])
    if result.returncode!=0:
        raise RuntimeError()
    return result.stdout.rstrip(b"\\n")
try:
    new_pid=show("MainPID","kernaid-rescue-vaultd.service").decode("ascii")
    new_invocation=show("InvocationID","kernaid-rescue-vaultd.service").decode("ascii")
    if re.fullmatch(r"[1-9][0-9]*",new_pid) is None or new_pid==str({old_service_pid}):
        raise RuntimeError()
    if re.fullmatch(r"[0-9a-f]{{32}}",new_invocation) is None or new_invocation=={old_invocation_id!r}:
        raise RuntimeError()
    children=run(["/usr/bin/pgrep","-P",new_pid])
    if children.returncode not in (1,) or children.stdout:
        raise RuntimeError()
    if os.path.lexists("/proc/{old_service_pid}") or os.path.lexists("/proc/{old_worker_pid}"):
        raise RuntimeError()
    mapper_count=0
    for name_path in glob.glob("/sys/block/dm-*/dm/name"):
        with open(name_path,"rb") as stream:
            name=stream.read(256).rstrip(b"\\n")
        if name.startswith(b"kernaid-vault-"):
            mapper_count+=1
    if mapper_count!=0:
        raise RuntimeError()
    with open("/proc/swaps","rb") as stream:
        if len(stream.readlines())!=1:
            raise RuntimeError()
    for path in ({PROVIDER_STATUS_PROBE_SOCKET!r},{PROVIDER_LEASE_PROBE_SOCKET!r},{PROVIDER_LEASE_KILL_SOCKET!r}):
        if os.path.lexists(path):
            raise RuntimeError()
    if any(name.startswith({TEST_CREDENTIAL_PREFIXES!r}) for name in os.listdir("/run/credentials")):
        raise RuntimeError()
    if any(name.startswith("kernaid-provider-") and name!="kernaid-rescue-openai.sock" for name in os.listdir("/run")):
        raise RuntimeError()
except BaseException:
    sys.exit(44)
sys.stdout.write({proof!r})
'''.encode("ascii")


def run_lifecycle(
    console: SerialConsole,
    aggregate: float,
    login_credential: bytearray,
    correct: bytearray,
    wrong: bytearray,
    provider_key: bytearray,
    boot: int,
) -> tuple[int, int, int, str]:
    if boot not in {1, 2}:
        raise ClosedFailure("lifecycle", "boot-invalid")
    cursor = establish_live_session(console, aggregate, login_credential)
    initial_runtime, cursor = collect_runtime(console, "initial", cursor, aggregate)
    initial, cursor = run_companion(console, "status", "initial-status", cursor, aggregate)
    wrong_response, cursor = run_companion(
        console, "unlock", "wrong-unlock", cursor, aggregate, wrong
    )
    after_wrong, cursor = run_companion(
        console, "status", "after-wrong-status", cursor, aggregate
    )
    wrong_runtime, cursor = collect_runtime(console, "after-wrong", cursor, aggregate)

    wait_started = time.monotonic()
    wait_until = wait_started + RATE_LIMIT_WAIT_SECONDS
    while time.monotonic() < wait_until:
        time.sleep(min(0.05, wait_until - time.monotonic()))
    if time.monotonic() - wait_started < RATE_LIMIT_WAIT_SECONDS:
        raise ClosedFailure("rate-limit", "wait-short")

    unlocked, cursor = run_companion(
        console,
        "unlock",
        "correct-unlock",
        cursor,
        aggregate,
        correct,
        UnlockDiagnosticExpectation(
            service_pid=wrong_runtime.service_pid,
            invocation_id=wrong_runtime.invocation_id,
            request_state_version=wrong_response.state_version,
        ),
    )
    status_unlocked, cursor = run_companion(
        console, "status", "unlocked-status", cursor, aggregate
    )
    unlocked_runtime, cursor = collect_runtime(console, "unlocked", cursor, aggregate)
    if boot == 1:
        cursor = run_guest_proof(
            console,
            "ui-diagnose-unconfigured",
            _production_ui_relay_probe_source("ui-diagnose-unconfigured"),
            cursor,
            aggregate,
            timeout=150.0,
        )
    prior_provider, cursor = run_provider_companion(
        console,
        "provider-status",
        "prior-provider-status",
        cursor,
        aggregate,
    )
    cursor = run_guest_proof(
        console,
        "codex-status",
        _codex_status_probe_source(),
        cursor,
        aggregate,
        timeout=CODEX_STATUS_PROOF_TIMEOUT_SECONDS,
    )
    configured, cursor = run_provider_companion(
        console,
        "openai-configure",
        "openai-configure",
        cursor,
        aggregate,
        provider_key,
    )
    provider_status, cursor = run_provider_companion(
        console,
        "provider-status",
        "configured-provider-status",
        cursor,
        aggregate,
    )
    cursor = run_guest_proof(
        console,
        "ui-status-configured",
        _production_ui_relay_probe_source("ui-status-configured"),
        cursor,
        aggregate,
        timeout=15.0,
    )
    cursor = run_guest_proof(
        console,
        "production-status",
        _production_status_probe_source(),
        cursor,
        aggregate,
    )
    cursor = run_guest_proof(
        console,
        "normal-release",
        _socket_probe_source(
            "normal-release",
            PROVIDER_LEASE_PROBE_SOCKET,
            b"NORMAL\n",
            b"KERNAID_PROVIDER_LEASE_PROBE_NORMAL_V1 "
            b"borrowed=true unread=true\n",
        ),
        cursor,
        aggregate,
    )
    cursor = run_guest_proof(
        console,
        "signed-report",
        _signed_report_probe_source(boot, configured.state_version),
        cursor,
        aggregate,
        timeout=150.0,
    )
    report_status, cursor = run_companion(
        console, "status", "signed-report-status", cursor, aggregate
    )
    if boot == 1:
        locked, cursor = run_companion(console, "lock", "lock", cursor, aggregate)
        status_locked, cursor = run_companion(
            console, "status", "locked-status", cursor, aggregate
        )
        final_runtime, _ = collect_runtime(console, "final", cursor, aggregate)
        device_id = validate_clean_provider_lifecycle(
            initial,
            wrong_response,
            after_wrong,
            unlocked,
            status_unlocked,
            prior_provider,
            configured,
            provider_status,
            report_status,
            locked,
            status_locked,
            boot,
        )
        validate_runtime_sequence(
            [initial_runtime, wrong_runtime, unlocked_runtime, final_runtime]
        )
        return (
            initial.state_version,
            report_status.state_version,
            locked.state_version,
            device_id,
        )

    cursor = run_guest_proof(
        console,
        "hold-kill",
        _hold_probe_source(
            unlocked_runtime.service_pid, unlocked_runtime.worker_pid
        ),
        cursor,
        aggregate,
        timeout=90.0,
    )
    faulted, cursor = run_companion(
        console, "status", "faulted-status", cursor, aggregate
    )
    provider_faulted, cursor = run_provider_companion(
        console,
        "provider-status",
        "faulted-provider-status",
        cursor,
        aggregate,
    )
    run_guest_proof(
        console,
        "post-fault",
        _post_fault_probe_source(
            unlocked_runtime.service_pid,
            unlocked_runtime.worker_pid,
            unlocked_runtime.invocation_id,
        ),
        cursor,
        aggregate,
    )
    device_id = validate_provider_fault_lifecycle(
        initial,
        wrong_response,
        after_wrong,
        unlocked,
        status_unlocked,
        prior_provider,
        configured,
        provider_status,
        report_status,
        faulted,
        provider_faulted,
        boot,
    )
    validate_provider_runtime_sequence(
        [initial_runtime, wrong_runtime, unlocked_runtime]
    )
    return (
        initial.state_version,
        report_status.state_version,
        faulted.state_version,
        device_id,
    )


class ClosedArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        del message
        raise ClosedFailure("arguments", "invalid")


def parse_arguments(arguments: Sequence[str]) -> argparse.Namespace:
    parser = ClosedArgumentParser(add_help=False)
    parser.add_argument("--firmware", choices=("bios", "uefi"), required=True)
    parser.add_argument("--boot", type=int, choices=(1, 2), required=True)
    parser.add_argument("--correct-key-fd", type=int, required=True)
    parser.add_argument("--wrong-key-fd", type=int, required=True)
    parser.add_argument("--login-credential-fd", type=int, required=True)
    parser.add_argument("--provider-key-fd", type=int, required=True)
    parser.add_argument("--owned-pgid-fd", type=int, required=True)
    parser.add_argument("--qmp-socket", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=CONTROLLER_TIMEOUT_SECONDS)
    parser.add_argument("--qemu", required=True)
    parser.add_argument("qemu_args", nargs=argparse.REMAINDER)
    parsed = parser.parse_args(arguments)
    if parsed.timeout < 300 or parsed.timeout > CONTROLLER_TIMEOUT_SECONDS:
        raise ClosedFailure("arguments", "timeout-invalid")
    descriptors = {
        parsed.correct_key_fd,
        parsed.wrong_key_fd,
        parsed.login_credential_fd,
        parsed.provider_key_fd,
        parsed.owned_pgid_fd,
    }
    if len(descriptors) != 5 or min(descriptors) < 3:
        raise ClosedFailure("arguments", "descriptor-invalid")
    if parsed.qemu_args[:1] == ["--"]:
        parsed.qemu_args = parsed.qemu_args[1:]
    if not parsed.qemu_args:
        raise ClosedFailure("arguments", "qemu-arguments-missing")
    return parsed


def parse_probe_arguments(arguments: Sequence[str]) -> argparse.Namespace:
    parser = ClosedArgumentParser(add_help=False)
    parser.add_argument("--run-bounded-probe", action="store_true", required=True)
    parser.add_argument("--probe", type=Path, required=True)
    parser.add_argument("--device", required=True)
    parser.add_argument("--mapper", required=True)
    parser.add_argument("--mode", choices=("initialize", "verify"), required=True)
    parser.add_argument("--correct-key-fd", type=int, required=True)
    parser.add_argument("--wrong-key-fd", type=int, required=True)
    parser.add_argument("--owned-pgid-fd", type=int, required=True)
    parser.add_argument("--timeout", type=int, default=620)
    parsed = parser.parse_args(arguments)
    descriptors = {
        parsed.correct_key_fd,
        parsed.wrong_key_fd,
        parsed.owned_pgid_fd,
    }
    if len(descriptors) != 3 or min(descriptors) < 3:
        raise ClosedFailure("arguments", "descriptor-invalid")
    if parsed.timeout < 1 or parsed.timeout > int(PROBE_TIMEOUT_SECONDS):
        raise ClosedFailure("arguments", "timeout-invalid")
    return parsed


def parse_extraction_arguments(arguments: Sequence[str]) -> argparse.Namespace:
    parser = ClosedArgumentParser(add_help=False)
    parser.add_argument("--extract-live-credential", action="store_true", required=True)
    parser.add_argument("--source-fd", type=int, required=True)
    parser.add_argument("--credential-fd", type=int, required=True)
    parsed = parser.parse_args(arguments)
    if (
        parsed.source_fd == parsed.credential_fd
        or min(parsed.source_fd, parsed.credential_fd) < 3
    ):
        raise ClosedFailure("credential-extract", "descriptor-invalid")
    return parsed


def parse_loop_detach_arguments(arguments: Sequence[str]) -> argparse.Namespace:
    parser = ClosedArgumentParser(add_help=False)
    parser.add_argument("--clear-owned-loop", action="store_true", required=True)
    parser.add_argument("--loop-fd", type=int, required=True)
    parser.add_argument("--backing-fd", type=int, required=True)
    parser.add_argument("--loop-number", type=int, required=True)
    parser.add_argument("--offset", type=int, required=True)
    parser.add_argument("--size-limit", type=int, required=True)
    parser.add_argument("--read-only", choices=("0", "1"), required=True)
    parsed = parser.parse_args(arguments)
    if (
        parsed.loop_fd == parsed.backing_fd
        or min(parsed.loop_fd, parsed.backing_fd) < 3
        or parsed.loop_number < 0
        or parsed.loop_number > 1_048_575
        or parsed.offset < 0
        or parsed.offset > (1 << 63) - 1
        or parsed.size_limit < 0
        or parsed.size_limit > (1 << 63) - 1
    ):
        raise ClosedFailure("loop-detach", "arguments-invalid")
    return parsed


def boot_attestation(
    firmware: str,
    boot: int,
    initial_version: int,
    pre_terminal_version: int,
    terminal_epoch_version: int,
    device_id: str,
) -> str:
    # `cgroup_topology_exact` is a composed claim: boot readiness follows the
    # root daemon's descriptor-bound topology setup; every successful lifecycle
    # operation re-attests that topology internally before and after worker
    # dispatch; and UID-1000 RuntimeSnapshots independently bind the
    # stable systemd MainPID/direct child to their exact /proc memberships.
    # It never claims that this controller traversed the root-only worker
    # cgroup directory.
    if (
        pre_terminal_version != initial_version + 14
        or boot not in {1, 2}
        or (boot == 1 and terminal_epoch_version != pre_terminal_version + 2)
        or terminal_epoch_version < 0
    ):
        raise ClosedFailure("attestation", "version-invalid")
    terminal = "clean-lock" if boot == 1 else "persistent-fault"
    fault_proof = "false" if boot == 1 else "true"
    line = (
        f"{ATTESTATION_PREFIX} firmware={firmware} boot={boot} "
        f"initial_version={initial_version} "
        f"pre_terminal_version={pre_terminal_version} "
        f"terminal_epoch_version={terminal_epoch_version} terminal={terminal} "
        f"device_id={device_id} wrong_key_rejected=true rate_limit_waited=true "
        "pre_terminal_daemon_stable=true pre_terminal_worker_stable=true "
        "pre_terminal_cgroup_stable=true pre_terminal_caps_stable=true "
        "ambient_zero=true no_new_privs=true core_limits_zero=true swaps_empty=true "
        "cgroup_topology_exact=true shell_mount_absent=true provider_configured=true "
        "production_executor_unit_binds_to_exact=true "
        "production_executor_status_path=true conditioned_agent_binds_to_runtime=true "
        "codex_status_path=true "
        "production_ui_provider_relay_path=true "
        "signed_report_path=true "
        "normal_triple_release=true lifecycle_marker_active_before_borrow=true "
        f"hold_killed_vaultd={fault_proof} helper_binds_to_terminated={fault_proof} "
        f"worker_pdeath_cleanup={fault_proof} test_trigger_sockets_gone={fault_proof} "
        f"unit_credentials_cleaned={fault_proof} persistent_fault_status_only={fault_proof} "
        f"lifecycle_marker_persisted={fault_proof} provider_network_used=false "
        "tls_openai_qualified=false residue_absent=true "
        "acpi_shutdown=true"
    )
    pattern = re.compile(
        rf"^{ATTESTATION_PREFIX} firmware=(bios|uefi) boot=[12] "
        r"initial_version=(0|[1-9][0-9]*) "
        r"pre_terminal_version=(0|[1-9][0-9]*) "
        r"terminal_epoch_version=(0|[1-9][0-9]*) "
        r"terminal=(clean-lock|persistent-fault) "
        r"device_id=KA-[0-9a-f]{24} wrong_key_rejected=true rate_limit_waited=true "
        r"pre_terminal_daemon_stable=true pre_terminal_worker_stable=true "
        r"pre_terminal_cgroup_stable=true pre_terminal_caps_stable=true "
        r"ambient_zero=true no_new_privs=true core_limits_zero=true swaps_empty=true "
        r"cgroup_topology_exact=true shell_mount_absent=true provider_configured=true "
        r"production_executor_unit_binds_to_exact=true "
        r"production_executor_status_path=true conditioned_agent_binds_to_runtime=true "
        r"codex_status_path=true "
        r"production_ui_provider_relay_path=true "
        r"signed_report_path=true "
        r"normal_triple_release=true lifecycle_marker_active_before_borrow=true "
        r"hold_killed_vaultd=(true|false) helper_binds_to_terminated=(true|false) "
        r"worker_pdeath_cleanup=(true|false) test_trigger_sockets_gone=(true|false) "
        r"unit_credentials_cleaned=(true|false) persistent_fault_status_only=(true|false) "
        r"lifecycle_marker_persisted=(true|false) provider_network_used=false "
        r"tls_openai_qualified=false residue_absent=true "
        r"acpi_shutdown=true$"
    )
    if pattern.fullmatch(line) is None:
        raise ClosedFailure("attestation", "invalid")
    return line


def install_signal_guard() -> tuple[dict[signal.Signals, object], set[signal.Signals] | None]:
    previous_handlers: dict[signal.Signals, object] = {}
    try:
        previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, [])
    except (AttributeError, OSError):
        previous_mask = None
    for handled in HANDLED_SIGNALS:
        previous_handlers[handled] = signal.signal(handled, _raise_controller_signal)
    return previous_handlers, previous_mask


def enter_signal_safe_cleanup(previous_handlers: dict[signal.Signals, object]) -> None:
    try:
        signal.pthread_sigmask(signal.SIG_BLOCK, HANDLED_SIGNALS)
    except (AttributeError, OSError):
        pass
    for handled in previous_handlers:
        signal.signal(handled, signal.SIG_IGN)


def restore_signal_guard(
    previous_handlers: dict[signal.Signals, object],
    previous_mask: set[signal.Signals] | None,
) -> None:
    for handled, previous in previous_handlers.items():
        signal.signal(handled, previous)
    if previous_mask is not None:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)


def main(arguments: Sequence[str]) -> int:
    if arguments[:1] == ["--clear-owned-loop"]:
        try:
            loop_detach = parse_loop_detach_arguments(arguments)
            clear_owned_loop_fd(
                loop_detach.loop_fd,
                loop_detach.backing_fd,
                expected_number=loop_detach.loop_number,
                expected_offset=loop_detach.offset,
                expected_size_limit=loop_detach.size_limit,
                expected_read_only=loop_detach.read_only == "1",
            )
            return 0
        except ClosedFailure as error:
            print(
                f"{FAILURE_PREFIX} stage={error.stage} code={error.code}",
                file=sys.stderr,
                flush=True,
            )
            return 1
        except BaseException:
            print(
                f"{FAILURE_PREFIX} stage=loop-detach code=unexpected",
                file=sys.stderr,
                flush=True,
            )
            return 1

    if arguments[:1] == ["--extract-live-credential"]:
        try:
            extraction = parse_extraction_arguments(arguments)
            extract_live_credential(extraction.source_fd, extraction.credential_fd)
            return 0
        except ClosedFailure as error:
            print(
                f"{FAILURE_PREFIX} stage={error.stage} code={error.code}",
                file=sys.stderr,
                flush=True,
            )
            return 1
        except BaseException:
            print(
                f"{FAILURE_PREFIX} stage=credential-extract code=unexpected",
                file=sys.stderr,
                flush=True,
            )
            return 1

    if arguments[:1] == ["--run-bounded-probe"]:
        previous_handlers: dict[signal.Signals, object] = {}
        previous_signal_mask: set[signal.Signals] | None = None
        failure: ClosedFailure | None = None
        attestation: str | None = None
        try:
            previous_handlers, previous_signal_mask = install_signal_guard()
            parsed_probe = parse_probe_arguments(arguments)
            attestation = run_bounded_probe(parsed_probe)
        except ClosedFailure as error:
            failure = error
        except (ControllerSignal, KeyboardInterrupt, SystemExit):
            failure = ClosedFailure("probe", "interrupted")
        except BaseException:
            failure = ClosedFailure("probe", "unexpected")
        finally:
            enter_signal_safe_cleanup(previous_handlers)
            restore_signal_guard(previous_handlers, previous_signal_mask)
        if failure is not None:
            print(
                f"{FAILURE_PREFIX} stage={failure.stage} code={failure.code}",
                file=sys.stderr,
                flush=True,
            )
            return 1
        if attestation is None:
            print(
                f"{FAILURE_PREFIX} stage=probe code=unexpected",
                file=sys.stderr,
                flush=True,
            )
            return 1
        print(attestation, flush=True)
        return 0

    login_credential = bytearray()
    correct = bytearray()
    wrong = bytearray()
    provider_key = bytearray()
    harness: QemuHarness | None = None
    failure: ClosedFailure | None = None
    attestation: str | None = None
    previous_handlers: dict[signal.Signals, object] = {}
    previous_signal_mask: set[signal.Signals] | None = None
    try:
        previous_handlers, previous_signal_mask = install_signal_guard()
        parsed = parse_arguments(arguments)
        aggregate = time.monotonic() + parsed.timeout
        correct = read_secret_fd(parsed.correct_key_fd)
        wrong = read_secret_fd(parsed.wrong_key_fd)
        login_credential = read_login_credential_fd(parsed.login_credential_fd)
        provider_key = read_secret_fd(parsed.provider_key_fd)
        if (
            correct == wrong
            or provider_key == correct
            or provider_key == wrong
            or provider_key == login_credential
        ):
            raise ClosedFailure("secret", "not-distinct")
        harness = QemuHarness(
            parsed.qemu,
            parsed.qemu_args,
            parsed.qmp_socket,
            [correct, wrong, provider_key],
            [correct, wrong, login_credential, provider_key],
            parsed.owned_pgid_fd,
        )
        console, qmp = harness.start(
            _deadline(aggregate, QEMU_START_TIMEOUT_SECONDS)
        )
        lifecycle_deadline = aggregate - SHUTDOWN_RESERVE_SECONDS
        if lifecycle_deadline <= time.monotonic():
            raise ClosedFailure("lifecycle", "shutdown-reserve-exhausted")
        initial_version, pre_terminal_version, terminal_epoch_version, device_id = (
            run_lifecycle(
                console,
                lifecycle_deadline,
                login_credential,
                correct,
                wrong,
                provider_key,
                parsed.boot,
            )
        )
        qmp.set_deadline(_deadline(aggregate, 10.0))
        qmp.system_powerdown()
        harness.wait_for_shutdown(_deadline(aggregate, ACPI_SHUTDOWN_SECONDS))
        attestation = boot_attestation(
            parsed.firmware,
            parsed.boot,
            initial_version,
            pre_terminal_version,
            terminal_epoch_version,
            device_id,
        )
    except ClosedFailure as error:
        failure = error
    except (ControllerSignal, KeyboardInterrupt, SystemExit):
        failure = ClosedFailure("controller", "interrupted")
    except BaseException:
        failure = ClosedFailure("controller", "unexpected")
    finally:
        enter_signal_safe_cleanup(previous_handlers)
        if harness is not None:
            try:
                harness.cleanup()
            except ClosedFailure as error:
                failure = error
            except BaseException:
                failure = ClosedFailure("cleanup", "unexpected")
        wipe(login_credential)
        wipe(correct)
        wipe(wrong)
        wipe(provider_key)
        restore_signal_guard(previous_handlers, previous_signal_mask)
    if failure is not None:
        print(
            f"{FAILURE_PREFIX} stage={failure.stage} code={failure.code}",
            file=sys.stderr,
            flush=True,
        )
        return 1
    if attestation is None:
        print(
            f"{FAILURE_PREFIX} stage=controller code=unexpected",
            file=sys.stderr,
            flush=True,
        )
        return 1
    print(attestation, flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
