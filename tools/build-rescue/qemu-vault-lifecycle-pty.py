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
ACPI_SHUTDOWN_SECONDS = 180.0
SHUTDOWN_RESERVE_SECONDS = ACPI_SHUTDOWN_SECONDS + 15.0
PROCESS_CLEANUP_SECONDS = 5.0
PROBE_OUTPUT_LIMIT = 256
PROBE_STDERR_LIMIT = 256
PROBE_TIMEOUT_SECONDS = 620.0

LOOP_CLR_FD = 0x4C01
LOOP_GET_STATUS64 = 0x4C05
LO_FLAGS_READ_ONLY = 1
LO_FLAGS_AUTOCLEAR = 4
LOOP_INFO64 = struct.Struct("=QQQQQIIII64s64s32sQQ")

READY_LINE = b"KERNAID_RESCUE_READY"
LOGIN_OK_LINE = b"KERNAID_VAULT_LOGIN_V1 uid=1000 user=kernaid group=true"
LOGIN_FAIL_LINE = b"KERNAID_VAULT_LOGIN_V1 invalid=true"
# Interactive Bash places this one bracketed-paste disable sequence between an
# echoed command and its first output line. Only trusted shell-emitted markers
# opt in to this exact optional prefix at a line boundary.
BRACKETED_PASTE_DISABLE_PREFIX = b"\x1b[?2004l\r"
_TRUSTED_SHELL_MARKER_START = (
    rb"(?:^|\r?\n)(?:" + re.escape(BRACKETED_PASTE_DISABLE_PREFIX) + rb")?"
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
CAP_SYS_ADMIN_ONLY = "0000000000200000"
ZERO_CAPS = "0000000000000000"

FAILURE_PREFIX = "KERNAID_QEMU_VAULT_LIFECYCLE_FAILURE_V1"
ATTESTATION_PREFIX = "KERNAID_QEMU_VAULT_LIFECYCLE_BOOT_V1"
TOKEN_RE = re.compile(r"^[a-z0-9-]+$")
DEVICE_ID_RE = re.compile(r"^KA-[0-9a-f]{24}$")


class ClosedFailure(Exception):
    """Failure carrying only closed diagnostic tokens."""

    def __init__(self, stage: str, code: str) -> None:
        if TOKEN_RE.fullmatch(stage) is None or TOKEN_RE.fullmatch(code) is None:
            stage, code = "controller", "invalid-diagnostic"
        self.stage = stage
        self.code = code
        super().__init__(f"{stage}:{code}")


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
            raise ClosedFailure("response", "unlock-invalid")
    return CompanionResponse(version, state, device_id, error, return_code)


@dataclasses.dataclass(frozen=True)
class RuntimeSnapshot:
    stage: str
    service_pid: int
    worker_pid: int
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
    rb"service_caps=([0-9a-f]{16}):([0-9a-f]{16}):([0-9a-f]{16}):([0-9a-f]{16}) "
    rb"worker_caps=([0-9a-f]{16}):([0-9a-f]{16}):([0-9a-f]{16}):([0-9a-f]{16}) "
    rb"service_ambient=(0000000000000000) worker_ambient=(0000000000000000) "
    rb"service_nnp=(1) worker_nnp=(1) service_core=(0):(0) worker_core=(0):(0) "
    rb"parent_procs=empty supervisor_procs=service worker_procs=worker "
    rb"subtree_control=pids parent_descendants=(2) supervisor_descendants=(0) "
    rb"worker_descendants=(0) worker_pids_current=(1) leaf_exact=true "
    rb"mapper_count=([0-9]+) shell_mount=(false|true) "
    rb"swaps_empty=true service_active=true socket_listening=true cgroups_exact=true$"
)

SOCKET_OPERATIONAL_CASE = (
    'case "$socket_state" in '
    'active:listening|active:running) listening=true;; '
    'esac;'
)


def parse_runtime_snapshot(line: bytes, expected_stage: str) -> RuntimeSnapshot:
    match = RUNTIME_RE.fullmatch(line)
    if match is None or match.group(1).decode("ascii") != expected_stage:
        raise ClosedFailure("runtime", "evidence-invalid")
    service_caps = tuple(item.decode("ascii") for item in match.groups()[3:7])
    worker_caps = tuple(item.decode("ascii") for item in match.groups()[7:11])
    exact_caps = (ZERO_CAPS, CAP_SYS_ADMIN_ONLY, CAP_SYS_ADMIN_ONLY, CAP_SYS_ADMIN_ONLY)
    if service_caps != exact_caps or worker_caps != exact_caps:
        raise ClosedFailure("runtime", "capabilities-invalid")
    return RuntimeSnapshot(
        stage=expected_stage,
        service_pid=int(match.group(2)),
        worker_pid=int(match.group(3)),
        service_caps=service_caps,
        worker_caps=worker_caps,
        service_ambient=match.group(12).decode("ascii"),
        worker_ambient=match.group(13).decode("ascii"),
        service_no_new_privs=int(match.group(14)),
        worker_no_new_privs=int(match.group(15)),
        service_core=(int(match.group(16)), int(match.group(17))),
        worker_core=(int(match.group(18)), int(match.group(19))),
        mapper_count=int(match.group(24)),
        shell_mount=match.group(25) == b"true",
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


def validate_runtime_sequence(snapshots: Sequence[RuntimeSnapshot]) -> None:
    if len(snapshots) != 4:
        raise ClosedFailure("runtime", "sequence-invalid")
    baseline = snapshots[0]
    for snapshot in snapshots:
        if (
            snapshot.service_pid != baseline.service_pid
            or snapshot.worker_pid != baseline.worker_pid
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
            snapshot = self.capture.snapshot()
            match = pattern.search(snapshot, start)
            if match is not None:
                return match
            if time.monotonic() >= deadline:
                raise ClosedFailure(stage, "timeout")
            events = self._selector.select(min(0.1, max(0.0, deadline - time.monotonic())))
            if not events:
                continue
            try:
                chunk = os.read(self.fd, 4096)
            except BlockingIOError:
                continue
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
        re.compile(
            rb"(?:^|\r?\n)(?:"
            + re.escape(READY_LINE)
            + rb"|kernaid-rescue login: "
            + re.escape(READY_LINE)
            + rb")\r?\n"
        ),
        start=0,
        deadline=_deadline(aggregate, 620.0),
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
    # Every dynamic field is constrained before it reaches the single marker.
    # The shell namespace mount test is intentionally separate from the
    # daemon's private mount namespace.
    source = f"""
stage='{stage}'; unit='kernaid-rescue-vaultd.service'; base='/sys/fs/cgroup/system.slice/kernaid-rescue-vaultd.service'; sup="$base/supervisor"; work="$base/worker";
svc=$(systemctl show --property=MainPID --value "$unit" 2>/dev/null) || svc=0; case "$svc" in ''|*[!0-9]*) svc=0;; esac;
wprocs=$(cat "$work/cgroup.procs" 2>/dev/null) || wprocs=invalid; case "$wprocs" in ''|*[!0-9]*) worker=0;; *) worker="$wprocs";; esac;
caps() {{ awk 'BEGIN{{i=p=e=b=""}} $1=="CapInh:"{{i=$2}} $1=="CapPrm:"{{p=$2}} $1=="CapEff:"{{e=$2}} $1=="CapBnd:"{{b=$2}} END{{if(i!=""&&p!=""&&e!=""&&b!="")printf "%s:%s:%s:%s",i,p,e,b;else exit 1}}' "$1"; }};
field() {{ awk -v key="$2" 'BEGIN{{v="";n=0}} $1==key{{v=$2;n++}} END{{if(n==1&&v!="")printf "%s",v;else exit 1}}' "$1"; }};
core() {{ awk 'BEGIN{{v="";n=0}} $1=="Max"&&$2=="core"&&$3=="file"&&$4=="size"{{v=$5 ":" $6;n++}} END{{if(n==1)printf "%s",v;else exit 1}}' "$1"; }};
metric() {{ awk -v key="$2" 'BEGIN{{v="";n=0}} $1==key{{v=$2;n++}} END{{if(n==1&&v~/^(0|[1-9][0-9]*)$/)printf "%s",v;else exit 1}}' "$1"; }};
scaps=$(caps "/proc/$svc/status" 2>/dev/null) || scaps=invalid;
wcaps=$(caps "/proc/$worker/status" 2>/dev/null) || wcaps=invalid;
samb=$(field "/proc/$svc/status" CapAmb: 2>/dev/null) || samb=invalid; wamb=$(field "/proc/$worker/status" CapAmb: 2>/dev/null) || wamb=invalid;
snnp=$(field "/proc/$svc/status" NoNewPrivs: 2>/dev/null) || snnp=invalid; wnnp=$(field "/proc/$worker/status" NoNewPrivs: 2>/dev/null) || wnnp=invalid;
score=$(core "/proc/$svc/limits" 2>/dev/null) || score=invalid; wcore=$(core "/proc/$worker/limits" 2>/dev/null) || wcore=invalid;
scg=$(cat "/proc/$svc/cgroup" 2>/dev/null) || scg=invalid;
wcg=$(cat "/proc/$worker/cgroup" 2>/dev/null) || wcg=invalid;
pp=$(cat "$base/cgroup.procs" 2>/dev/null) || pp=invalid; sp=$(cat "$sup/cgroup.procs" 2>/dev/null) || sp=invalid;
pproof=invalid; sproof=invalid; wproof=invalid; [ -z "$pp" ] && pproof=empty; [ "$sp" = "$svc" ] && sproof=service; [ "$wprocs" = "$worker" ] && [ "$worker" != 0 ] && wproof=worker;
subtree=$(cat "$base/cgroup.subtree_control" 2>/dev/null) || subtree=invalid;
pd=$(metric "$base/cgroup.stat" nr_descendants 2>/dev/null) || pd=invalid; sd=$(metric "$sup/cgroup.stat" nr_descendants 2>/dev/null) || sd=invalid; wd=$(metric "$work/cgroup.stat" nr_descendants 2>/dev/null) || wd=invalid;
wcurrent=$(cat "$work/pids.current" 2>/dev/null) || wcurrent=invalid; leaf=false; [ "$sd:$wd" = 0:0 ] && leaf=true;
mc=0; for n in /sys/block/dm-*/dm/name; do [ -r "$n" ] || continue; read -r v <"$n" || v=; case "$v" in kernaid-vault-*) mc=$((mc+1));; esac; done;
sm=false; awk '$5=="/run/kernaid/vault"||index($5,"/run/kernaid/vault/")==1{{found=1}} END{{exit found?0:1}}' /proc/self/mountinfo && sm=true;
swaps=false; [ "$(awk 'END{{print NR}}' /proc/swaps 2>/dev/null)" = 1 ] && swaps=true;
active=false; listening=false; cgroups=false;
[ "$(systemctl show --property=ActiveState --value "$unit" 2>/dev/null)" = active ] && active=true;
socket_state="$(systemctl show -p ActiveState --value kernaid-rescue-vaultd.socket 2>/dev/null):$(systemctl show -p SubState --value kernaid-rescue-vaultd.socket 2>/dev/null)";
{SOCKET_OPERATIONAL_CASE}
[ "$scg" = "0::/system.slice/kernaid-rescue-vaultd.service/supervisor" ] && [ "$wcg" = "0::/system.slice/kernaid-rescue-vaultd.service/worker" ] && [ "$pproof:$sproof:$wproof:$subtree:$pd:$sd:$wd:$wcurrent:$leaf" = empty:service:worker:pids:2:0:0:1:true ] && cgroups=true;
printf '%s\\n' "KERNAID_VAULT_RUNTIME_V1 stage=$stage service_pid=$svc worker_pid=$worker service_caps=$scaps worker_caps=$wcaps service_ambient=$samb worker_ambient=$wamb service_nnp=$snnp worker_nnp=$wnnp service_core=$score worker_core=$wcore parent_procs=$pproof supervisor_procs=$sproof worker_procs=$wproof subtree_control=$subtree parent_descendants=$pd supervisor_descendants=$sd worker_descendants=$wd worker_pids_current=$wcurrent leaf_exact=$leaf mapper_count=$mc shell_mount=$sm swaps_empty=$swaps service_active=$active socket_listening=$listening cgroups_exact=$cgroups"
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


def run_companion(
    console: SerialConsole,
    command: str,
    stage: str,
    cursor: int,
    aggregate: float,
    secret: bytearray | None = None,
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
            raise ClosedFailure("response", "prompt-invalid")
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
    response = parse_companion_response(block, command=command, return_code=return_code)
    return response, end_match.end()


def run_lifecycle(
    console: SerialConsole,
    aggregate: float,
    login_credential: bytearray,
    correct: bytearray,
    wrong: bytearray,
) -> tuple[int, int, str]:
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
        console, "unlock", "correct-unlock", cursor, aggregate, correct
    )
    status_unlocked, cursor = run_companion(
        console, "status", "unlocked-status", cursor, aggregate
    )
    unlocked_runtime, cursor = collect_runtime(console, "unlocked", cursor, aggregate)
    locked, cursor = run_companion(console, "lock", "lock", cursor, aggregate)
    status_locked, cursor = run_companion(
        console, "status", "locked-status", cursor, aggregate
    )
    final_runtime, _ = collect_runtime(console, "final", cursor, aggregate)

    device_id = validate_lifecycle(
        initial,
        wrong_response,
        after_wrong,
        unlocked,
        status_unlocked,
        locked,
        status_locked,
    )
    validate_runtime_sequence(
        [initial_runtime, wrong_runtime, unlocked_runtime, final_runtime]
    )
    return initial.state_version, locked.state_version, device_id


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
    parser.add_argument("--owned-pgid-fd", type=int, required=True)
    parser.add_argument("--qmp-socket", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=1200)
    parser.add_argument("--qemu", required=True)
    parser.add_argument("qemu_args", nargs=argparse.REMAINDER)
    parsed = parser.parse_args(arguments)
    if parsed.timeout < 300 or parsed.timeout > 1200:
        raise ClosedFailure("arguments", "timeout-invalid")
    descriptors = {
        parsed.correct_key_fd,
        parsed.wrong_key_fd,
        parsed.login_credential_fd,
        parsed.owned_pgid_fd,
    }
    if len(descriptors) != 4 or min(descriptors) < 3:
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
    firmware: str, boot: int, initial_version: int, final_version: int, device_id: str
) -> str:
    if final_version != initial_version + 6:
        raise ClosedFailure("attestation", "version-invalid")
    line = (
        f"{ATTESTATION_PREFIX} firmware={firmware} boot={boot} "
        f"initial_version={initial_version} final_version={final_version} "
        f"device_id={device_id} wrong_key_rejected=true rate_limit_waited=true "
        "daemon_stable=true worker_stable=true cgroup_stable=true caps_stable=true "
        "ambient_zero=true no_new_privs=true core_limits_zero=true swaps_empty=true "
        "cgroup_topology_exact=true shell_mount_absent=true residue_absent=true "
        "acpi_shutdown=true"
    )
    pattern = re.compile(
        rf"^{ATTESTATION_PREFIX} firmware=(bios|uefi) boot=[12] "
        r"initial_version=(0|[1-9][0-9]*) final_version=(0|[1-9][0-9]*) "
        r"device_id=KA-[0-9a-f]{24} wrong_key_rejected=true rate_limit_waited=true "
        r"daemon_stable=true worker_stable=true cgroup_stable=true caps_stable=true "
        r"ambient_zero=true no_new_privs=true core_limits_zero=true swaps_empty=true "
        r"cgroup_topology_exact=true shell_mount_absent=true residue_absent=true "
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
        if correct == wrong:
            raise ClosedFailure("secret", "not-distinct")
        harness = QemuHarness(
            parsed.qemu,
            parsed.qemu_args,
            parsed.qmp_socket,
            [correct, wrong],
            [correct, wrong, login_credential],
            parsed.owned_pgid_fd,
        )
        console, qmp = harness.start(_deadline(aggregate, 15.0))
        lifecycle_deadline = aggregate - SHUTDOWN_RESERVE_SECONDS
        if lifecycle_deadline <= time.monotonic():
            raise ClosedFailure("lifecycle", "shutdown-reserve-exhausted")
        initial_version, final_version, device_id = run_lifecycle(
            console, lifecycle_deadline, login_credential, correct, wrong
        )
        qmp.set_deadline(_deadline(aggregate, 10.0))
        qmp.system_powerdown()
        harness.wait_for_shutdown(_deadline(aggregate, ACPI_SHUTDOWN_SECONDS))
        attestation = boot_attestation(
            parsed.firmware,
            parsed.boot,
            initial_version,
            final_version,
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
