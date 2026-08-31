#!/usr/bin/python3
"""Privileged, path-free, read-only inspector for selected Rescue targets.

The HTTP/UI process never imports or executes this module.  A root service in a
private mount namespace owns the fixed Unix socket protocol and resolves opaque
target identifiers itself.  The protocol accepts no command, device path,
mount option, filesystem type, or filesystem path from its caller.
"""

from __future__ import annotations

import ctypes
import errno
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
import tempfile
import time
import types
from typing import Callable


API_VERSION = "kernaid.dev/rescue-offline-inspection/v1alpha1"
SOCKET_PATH = "/run/kernaid-offline-inspector.sock"
TARGET_MODULE_PATH = "/usr/lib/kernaid/rescue_server.py"
MOUNT_BASE = "/run/kernaid-offline-inspector"
TARGET_ID_KEY_PATH = f"{MOUNT_BASE}/target-id.key"
MAX_PROTOCOL_REQUEST_BYTES = 8 * 1024
MAX_PROTOCOL_RESPONSE_BYTES = 64 * 1024
MAX_INSPECTION_RESPONSE_BYTES = 48 * 1024
OPERATION_TIMEOUT_SECONDS = 18
STORAGE_HEALTH_BINARY = "/usr/lib/kernaid/kernaid-linux-storage-health"
MAX_STORAGE_HEALTH_BYTES = 64 * 1024
FILESYSTEM_HEALTH_BINARY = "/usr/lib/kernaid/kernaid-linux-filesystem-health"
MAX_FILESYSTEM_HEALTH_BYTES = 16 * 1024
FILESYSTEM_HEALTH_OPERATION_TIMEOUT_SECONDS = 34
MAX_TEXT_FILE_BYTES = 64 * 1024
MAX_OS_RELEASE_BYTES = 16 * 1024
MAX_DIRECTORY_ENTRIES = 512
MAX_RELEASE_VALUE_BYTES = 256

MS_RDONLY = 1
MS_NOSUID = 2
MS_NODEV = 4
MS_NOEXEC = 8
MS_REMOUNT = 32
MS_REC = 16_384
MS_PRIVATE = 1 << 18
MS_NOSYMFOLLOW = 256
MNT_FORCE = 1
MNT_DETACH = 2

SUPPORTED_FILESYSTEMS = {
    "ext4": ("ext4", "noload", "linux", "journal-replay-disabled"),
    # The in-kernel ntfs3 driver has no `norecover` option.  A read-only
    # mount skips applying log replay; `force` is never supplied or accepted.
    # The volume's clean/dirty/hibernated state remains deliberately unqualified.
    "ntfs": (
        "ntfs3",
        None,
        "windows",
        "read-only-no-force-driver-replay-not-applied",
    ),
}
EFI_SYSTEM_FILESYSTEMS = {"fat": "vfat", "vfat": "vfat"}
EFI_SYSTEM_PARTITION_TYPE = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"
EFI_SYSTEM_PARTITION_STATES = {
    "eligible",
    "not-present",
    "ambiguous",
    "unsupported",
}
DEVICE_IDENTITY_FIELDS = {
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
STACKED_KINDS = {"crypt", "lvm", "md", "raid", "raid0", "raid1", "raid4", "raid5", "raid6", "raid10"}
STACKED_FILESYSTEMS = {
    "apfs",
    "bitlocker",
    "crypto_luks",
    "linux_raid_member",
    "lvm2_member",
}

_MAJOR_MINOR = re.compile(r"^(0|[1-9][0-9]{0,9}):(0|[1-9][0-9]{0,9})$")
_OS_RELEASE_KEY = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_SAFE_DEVNAME = re.compile(r"^[A-Za-z0-9._+-]{1,128}$")
_LIBC = ctypes.CDLL(None, use_errno=True)
_LIBC.mount.argtypes = (
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_ulong,
    ctypes.c_char_p,
)
_LIBC.mount.restype = ctypes.c_int
_LIBC.umount2.argtypes = (ctypes.c_char_p, ctypes.c_int)
_LIBC.umount2.restype = ctypes.c_int


def _empty_claims() -> dict[str, bool]:
    return {
        "installedOsConfirmed": False,
        "filesystemContentInspected": False,
        "mountOperationAttempted": False,
        "mountOperationPerformed": False,
        "mountCleanupVerified": False,
        "autoUnlockAttempted": False,
        "mutationPerformed": False,
        "diagnosisProduced": False,
        "repairAttempted": False,
    }


def initialize_target_id_key() -> None:
    """Create or validate the root-only key shared by one-shot helpers."""
    if os.geteuid() != 0:
        raise RuntimeError("target identifier key initialization requires root")
    directory = os.lstat(MOUNT_BASE)
    if (
        not stat.S_ISDIR(directory.st_mode)
        or stat.S_ISLNK(directory.st_mode)
        or directory.st_uid != 0
        or directory.st_gid != 0
        or stat.S_IMODE(directory.st_mode) != 0o700
    ):
        raise RuntimeError("the target identifier runtime directory is unsafe")
    try:
        descriptor = os.open(
            TARGET_ID_KEY_PATH,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
        )
    except FileExistsError:
        descriptor = os.open(
            TARGET_ID_KEY_PATH, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
        )
        writable = False
    else:
        writable = True
    try:
        if writable:
            key = os.urandom(32)
            written = 0
            while written < len(key):
                count = os.write(descriptor, key[written:])
                if count <= 0:
                    raise RuntimeError("the target identifier key write failed")
                written += count
            os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_gid != 0
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
            or metadata.st_size != 32
        ):
            raise RuntimeError("the target identifier key is unsafe")
    finally:
        os.close(descriptor)


class InspectionError(Exception):
    """Typed failure safe to return across the local socket and HTTP bridge."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        status: int = 422,
        retryable: bool = False,
        claims: dict[str, bool] | None = None,
        fatal_cleanup: bool = False,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.status = status
        self.retryable = retryable
        self.claims = _empty_claims() if claims is None else dict(claims)
        self.fatal_cleanup = fatal_cleanup

    def public(self) -> dict[str, object]:
        return {
            "code": self.code,
            "message": str(self),
            "retryable": self.retryable,
            "claims": self.claims,
        }


def _check_deadline(deadline: float) -> None:
    if time.monotonic() >= deadline:
        raise InspectionError(
            "inspection-timeout",
            "L'ispezione offline ha superato il limite temporale.",
            status=408,
            retryable=True,
        )


def _load_target_module(path: str = TARGET_MODULE_PATH) -> object:
    module_path = Path(path)
    if not module_path.is_absolute():
        raise RuntimeError("the target resolver path must be absolute")
    descriptor = os.open(
        module_path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    )
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size <= 0
            or before.st_size > 512 * 1024
            or before.st_uid != 0
            or stat.S_IMODE(before.st_mode) & 0o022 != 0
        ):
            raise RuntimeError("the fixed target resolver is not a bounded file")
        payload = bytearray()
        while len(payload) < before.st_size:
            chunk = os.read(descriptor, min(64 * 1024, before.st_size - len(payload)))
            if not chunk:
                raise RuntimeError("the fixed target resolver ended early")
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
            raise RuntimeError("the fixed target resolver changed while loading")
    finally:
        os.close(descriptor)
    module = types.ModuleType("kernaid_privileged_target_resolver")
    module.__file__ = str(module_path)
    exec(
        compile(bytes(payload), str(module_path), "exec", dont_inherit=True),
        module.__dict__,
    )
    return module


def _mount_call(
    source: bytes | None,
    target: bytes,
    filesystem: bytes | None,
    flags: int,
    data: bytes | None,
) -> None:
    if _LIBC.mount(source, target, filesystem, flags, data) != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number))


def _umount_call(target: bytes, flags: int = 0) -> None:
    if flags & (MNT_FORCE | MNT_DETACH):
        raise ValueError("forced or lazy unmount is forbidden")
    if _LIBC.umount2(target, flags) != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number))


def make_mount_namespace_private() -> None:
    """Keep all inspection mounts inside the helper's service namespace."""
    _mount_call(None, b"/", None, MS_REC | MS_PRIVATE, None)


def _decode_mountinfo_path(value: str) -> str:
    replacements = {"\\040": " ", "\\011": "\t", "\\012": "\n", "\\134": "\\"}
    for escaped, decoded in replacements.items():
        value = value.replace(escaped, decoded)
    return value


def _mountinfo_entries() -> list[dict[str, object]]:
    try:
        descriptor = os.open(
            "/proc/self/mountinfo", os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
        )
        try:
            payload = bytearray()
            while len(payload) <= 1024 * 1024:
                chunk = os.read(
                    descriptor,
                    min(64 * 1024, 1024 * 1024 + 1 - len(payload)),
                )
                if not chunk:
                    break
                payload.extend(chunk)
        finally:
            os.close(descriptor)
    except OSError as error:
        raise InspectionError(
            "mount-postcondition-failed",
            "Impossibile verificare lo stato dei mount temporanei.",
            status=503,
            retryable=True,
            fatal_cleanup=True,
        ) from error
    if len(payload) > 1024 * 1024:
        raise InspectionError(
            "mount-postcondition-failed",
            "La tabella mount supera il limite di verifica.",
            status=503,
            retryable=True,
            fatal_cleanup=True,
        )
    try:
        text = bytes(payload).decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise InspectionError(
            "mount-postcondition-failed",
            "La tabella mount non è valida.",
            status=503,
            retryable=True,
            fatal_cleanup=True,
        ) from error
    entries: list[dict[str, object]] = []
    for line in text.splitlines():
        before, separator, after = line.partition(" - ")
        fields = before.split()
        trailing = after.split()
        if not separator or len(fields) < 6 or len(trailing) < 3:
            raise InspectionError(
                "mount-postcondition-failed",
                "La tabella mount non è valida.",
                status=503,
                retryable=True,
                fatal_cleanup=True,
            )
        entries.append(
            {
                "majorMinor": fields[2],
                "mountpoint": _decode_mountinfo_path(fields[4]),
                "options": set(fields[5].split(",")),
                "filesystem": trailing[0],
                "superOptions": set(trailing[2].split(",")),
            }
        )
    return entries


def _major_minor_parts(value: object) -> tuple[int, int]:
    if not isinstance(value, str) or _MAJOR_MINOR.fullmatch(value) is None:
        raise InspectionError(
            "target-identity-invalid",
            "L'identità kernel del target non è valida.",
            status=409,
        )
    major_text, minor_text = value.split(":", 1)
    major = int(major_text)
    minor = int(minor_text)
    if major > 4_294_967_295 or minor > 4_294_967_295:
        raise InspectionError(
            "target-identity-invalid",
            "L'identità kernel del target non è valida.",
            status=409,
        )
    return major, minor


def _assert_block_fd(descriptor: int, major: int, minor: int) -> os.stat_result:
    try:
        metadata = os.fstat(descriptor)
    except OSError as error:
        raise InspectionError(
            "target-identity-changed",
            "Il dispositivo selezionato non è più disponibile.",
            status=409,
            retryable=True,
        ) from error
    if (
        not stat.S_ISBLK(metadata.st_mode)
        or os.major(metadata.st_rdev) != major
        or os.minor(metadata.st_rdev) != minor
    ):
        raise InspectionError(
            "target-identity-changed",
            "L'identità del dispositivo selezionato è cambiata.",
            status=409,
        )
    return metadata


def _open_bound_block_device(
    major_minor: str, deadline: float
) -> tuple[int, int, int]:
    """Open exactly one direct devtmpfs node, never a caller-controlled path."""
    major, minor = _major_minor_parts(major_minor)
    dev_fd = os.open("/dev", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    matches: list[str] = []
    try:
        observed = 0
        with os.scandir(dev_fd) as entries:
            for entry in entries:
                observed += 1
                if observed > 4_096:
                    raise InspectionError(
                        "target-device-ambiguous",
                        "Troppi nodi dispositivo per una risoluzione sicura.",
                        status=503,
                        retryable=True,
                    )
                _check_deadline(deadline)
                name = entry.name
                if _SAFE_DEVNAME.fullmatch(name) is None:
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
                    matches.append(name)
        if len(matches) != 1:
            raise InspectionError(
                "target-device-ambiguous",
                "Il nodo del dispositivo selezionato è assente o ambiguo.",
                status=409,
                retryable=not matches,
            )
        descriptor = os.open(
            matches[0],
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=dev_fd,
        )
        try:
            _assert_block_fd(descriptor, major, minor)
            path_metadata = os.stat(
                matches[0], dir_fd=dev_fd, follow_symlinks=False
            )
            if (
                not stat.S_ISBLK(path_metadata.st_mode)
                or path_metadata.st_rdev != os.fstat(descriptor).st_rdev
            ):
                raise InspectionError(
                    "target-identity-changed",
                    "Il nodo del dispositivo è cambiato durante l'apertura.",
                    status=409,
                )
        except Exception:
            os.close(descriptor)
            raise
    finally:
        os.close(dev_fd)
    return descriptor, major, minor


def _ensure_mount_base() -> None:
    try:
        os.mkdir(MOUNT_BASE, 0o700)
    except FileExistsError:
        pass
    metadata = os.lstat(MOUNT_BASE)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise InspectionError(
            "mount-root-unsafe",
            "La directory dei mount temporanei non è sicura.",
            status=503,
            fatal_cleanup=True,
        )


def _target_already_mounted(major_minor: str) -> bool:
    return any(
        entry["majorMinor"] == major_minor for entry in _mountinfo_entries()
    )


def _verify_mounted(
    mountpoint: str,
    major_minor: str,
    expected_filesystem: str,
    replay_option: str | None,
    descriptor: int,
    major: int,
    minor: int,
) -> None:
    _assert_block_fd(descriptor, major, minor)
    matches = [
        entry
        for entry in _mountinfo_entries()
        if entry["mountpoint"] == mountpoint
    ]
    if len(matches) != 1:
        raise InspectionError(
            "mount-verification-failed",
            "Il mount temporaneo non è legato in modo univoco al target.",
            status=503,
        )
    entry = matches[0]
    required = {"ro", "nodev", "nosuid", "noexec", "nosymfollow"}
    options = entry["options"]
    super_options = entry["superOptions"]
    if (
        entry["majorMinor"] != major_minor
        or entry["filesystem"] != expected_filesystem
        or not isinstance(options, set)
        or not isinstance(super_options, set)
        or not required.issubset(options)
        or "ro" not in super_options
    ):
        raise InspectionError(
            "mount-verification-failed",
            "Il mount temporaneo non rispetta la policy read-only.",
            status=503,
        )
    if expected_filesystem == "ext4" and not {
        "noload",
        "norecovery",
    }.intersection(super_options):
        raise InspectionError(
            "mount-verification-failed",
            "Il mount ext4 non espone la policy no-replay richiesta.",
            status=503,
        )
    if (
        expected_filesystem == "ntfs3"
        and (replay_option is not None or "force" in super_options)
    ):
        raise InspectionError(
            "mount-verification-failed",
            "Il mount NTFS espone un'opzione di recovery non consentita.",
            status=503,
        )
    root_metadata = os.stat(mountpoint, follow_symlinks=False)
    if os.major(root_metadata.st_dev) != major or os.minor(root_metadata.st_dev) != minor:
        raise InspectionError(
            "mount-verification-failed",
            "Il filesystem montato non corrisponde al dispositivo selezionato.",
            status=503,
        )
    if not os.statvfs(mountpoint).f_flag & os.ST_RDONLY:
        raise InspectionError(
            "mount-verification-failed",
            "Il kernel non riporta il mount come read-only.",
            status=503,
        )


def _verify_unmounted(mountpoint: str, major_minor: str) -> None:
    entries = _mountinfo_entries()
    if any(entry["mountpoint"] == mountpoint for entry in entries) or any(
        entry["majorMinor"] == major_minor for entry in entries
    ):
        raise InspectionError(
            "mount-cleanup-failed",
            "Il mount temporaneo non è stato rimosso completamente.",
            status=503,
            retryable=False,
            fatal_cleanup=True,
        )


def _open_directory_chain(root_fd: int, components: tuple[str, ...]) -> int | None:
    root_device = os.fstat(root_fd).st_dev
    descriptor = os.dup(root_fd)
    try:
        for component in components:
            try:
                next_descriptor = os.open(
                    component,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                    dir_fd=descriptor,
                )
            except FileNotFoundError:
                os.close(descriptor)
                return None
            except OSError as error:
                raise InspectionError(
                    "unsafe-target-content",
                    "Un elemento del filesystem ispezionato non è sicuro.",
                ) from error
            if os.fstat(next_descriptor).st_dev != root_device:
                os.close(next_descriptor)
                raise InspectionError(
                    "unsupported-cross-device-content",
                    "Il corpus Linux non attraversa filesystem separati.",
                )
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _read_regular(
    root_fd: int,
    components: tuple[str, ...],
    limit: int,
    *,
    symlink_is_absent: bool = False,
    deadline: float | None = None,
) -> bytes | None:
    parent = _open_directory_chain(root_fd, components[:-1])
    if parent is None:
        return None
    try:
        try:
            descriptor = os.open(
                components[-1],
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
                dir_fd=parent,
            )
        except FileNotFoundError:
            return None
        except OSError as error:
            if symlink_is_absent and error.errno == errno.ELOOP:
                return None
            raise InspectionError(
                "unsafe-target-content",
                "Un file del filesystem ispezionato non è sicuro.",
            ) from error
        try:
            metadata = os.fstat(descriptor)
            if (
                metadata.st_dev != os.fstat(root_fd).st_dev
                or not stat.S_ISREG(metadata.st_mode)
                or metadata.st_size > limit
            ):
                raise InspectionError(
                    "unsafe-target-content",
                    "Un file del filesystem ispezionato non rispetta i limiti.",
                )
            payload = bytearray()
            while len(payload) <= limit:
                if deadline is not None:
                    _check_deadline(deadline)
                chunk = os.read(descriptor, min(8 * 1024, limit + 1 - len(payload)))
                if not chunk:
                    break
                payload.extend(chunk)
            if len(payload) > limit:
                raise InspectionError(
                    "unsafe-target-content",
                    "Un file del filesystem ispezionato supera il limite.",
                )
            after = os.fstat(descriptor)
            if (
                (
                    metadata.st_dev,
                    metadata.st_ino,
                    metadata.st_size,
                    metadata.st_mtime_ns,
                    metadata.st_ctime_ns,
                )
                != (
                    after.st_dev,
                    after.st_ino,
                    after.st_size,
                    after.st_mtime_ns,
                    after.st_ctime_ns,
                )
                or len(payload) != metadata.st_size
            ):
                raise InspectionError(
                    "unsafe-target-content",
                    "Un file del filesystem è cambiato durante l'ispezione.",
                )
            return bytes(payload)
        finally:
            os.close(descriptor)
    finally:
        os.close(parent)


def _path_kind(root_fd: int, components: tuple[str, ...]) -> str:
    parent = _open_directory_chain(root_fd, components[:-1])
    if parent is None:
        return "absent"
    try:
        try:
            metadata = os.stat(
                components[-1], dir_fd=parent, follow_symlinks=False
            )
        except FileNotFoundError:
            return "absent"
    finally:
        os.close(parent)
    if metadata.st_dev != os.fstat(root_fd).st_dev:
        raise InspectionError(
            "unsupported-cross-device-content",
            "Il corpus Linux non attraversa filesystem separati.",
        )
    if stat.S_ISREG(metadata.st_mode):
        return "regular"
    if stat.S_ISDIR(metadata.st_mode):
        return "directory"
    if stat.S_ISLNK(metadata.st_mode):
        return "symlink"
    return "other"


def _require_safe_kind(
    root_fd: int, components: tuple[str, ...], allowed: set[str]
) -> str:
    kind = _path_kind(root_fd, components)
    if kind not in allowed | {"absent"}:
        raise InspectionError(
            "unsafe-target-content",
            "Un elemento del filesystem ispezionato non è sicuro.",
        )
    return kind


def _bounded_release_value(value: str) -> str | None:
    if not value or len(value.encode("utf-8")) > MAX_RELEASE_VALUE_BYTES:
        return None
    if any(
        ord(character) < 32 or 127 <= ord(character) <= 159
        for character in value
    ):
        return None
    return value


def _unquote_os_release(value: str) -> str | None:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        quote = value[0]
        body = value[1:-1]
        decoded: list[str] = []
        index = 0
        while index < len(body):
            character = body[index]
            if character == "\\":
                index += 1
                if index >= len(body) or body[index] not in {"\\", quote, "$", "`"}:
                    return None
                character = body[index]
            decoded.append(character)
            index += 1
        value = "".join(decoded)
    elif any(character.isspace() for character in value):
        return None
    return _bounded_release_value(value)


def _parse_os_release(payload: bytes | None) -> dict[str, str | None]:
    selected: dict[str, str | None] = {
        "id": None,
        "name": None,
        "prettyName": None,
        "versionId": None,
    }
    if payload is None:
        return selected
    if any(
        byte == 13 and (index + 1 == len(payload) or payload[index + 1] != 10)
        for index, byte in enumerate(payload)
    ):
        raise InspectionError(
            "invalid-installed-os-metadata",
            "Il formato di os-release non è valido.",
        )
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise InspectionError(
            "invalid-installed-os-metadata",
            "I metadati del sistema Linux non sono UTF-8 validi.",
        ) from error
    mapping = {"ID": "id", "NAME": "name", "PRETTY_NAME": "prettyName", "VERSION_ID": "versionId"}
    seen: set[str] = set()
    for raw_line in text.split("\n"):
        line = raw_line[:-1] if raw_line.endswith("\r") else raw_line
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator or _OS_RELEASE_KEY.fullmatch(key) is None:
            raise InspectionError(
                "invalid-installed-os-metadata",
                "Il formato di os-release non è valido.",
            )
        if key in seen:
            raise InspectionError(
                "invalid-installed-os-metadata",
                "os-release contiene chiavi duplicate.",
            )
        seen.add(key)
        parsed = _unquote_os_release(value)
        if parsed is None:
            raise InspectionError(
                "invalid-installed-os-metadata",
                "Un valore di os-release non è valido.",
            )
        if key in mapping:
            selected[mapping[key]] = parsed
    return selected


def _fstab_projection(
    payload: bytes | None,
) -> tuple[dict[str, object], dict[str, object]]:
    summary: dict[str, object] = {
        "present": payload is not None,
        "entryCount": 0,
        "rootEntryPresent": False,
        "efiEntryPresent": False,
        "swapEntryCount": 0,
        "networkEntryCount": 0,
        "malformedLineCount": 0,
    }
    topology: dict[str, object] = {
        "collectionScope": "root-filesystem-only",
        "separateEtcMountPresent": False,
        "separateBootMountPresent": False,
        "separateUsrMountPresent": False,
        "separateVarMountPresent": False,
        "relevantSeparateMountPresent": False,
        "supported": True,
    }
    if payload is None:
        return summary, topology
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise InspectionError(
            "invalid-installed-os-metadata",
            "Il file fstab non è UTF-8 valido.",
        ) from error
    if any(
        (ord(character) < 32 or 127 <= ord(character) <= 159)
        and character not in {"\n", "\t", "\r"}
        for character in text
    ):
        raise InspectionError(
            "invalid-installed-os-metadata",
            "Il file fstab contiene caratteri di controllo non validi.",
        )
    lines = [line[:-1] if line.endswith("\r") else line for line in text.split("\n")]
    for line in lines:
        stripped = line.lstrip(" \t\r\n\v\f")
        if not stripped or stripped.startswith("#"):
            continue
        fields = _parse_fstab_line(stripped)
        if fields is None:
            summary["malformedLineCount"] = int(summary["malformedLineCount"]) + 1
            continue
        _source, target, filesystem, options = fields[:4]
        if not _canonical_fstab_target(target):
            raise InspectionError(
                "invalid-installed-os-metadata",
                "fstab contiene un mountpoint non canonico.",
            )
        summary["entryCount"] = int(summary["entryCount"]) + 1
        if target == "/":
            summary["rootEntryPresent"] = True
        if target in {"/boot/efi", "/efi"}:
            summary["efiEntryPresent"] = True
        topology["separateEtcMountPresent"] = bool(
            topology["separateEtcMountPresent"]
            or _mount_target_is_within(target, "/etc")
        )
        topology["separateBootMountPresent"] = bool(
            topology["separateBootMountPresent"]
            or _mount_target_is_within(target, "/boot")
            or _mount_target_is_within(target, "/efi")
        )
        topology["separateUsrMountPresent"] = bool(
            topology["separateUsrMountPresent"]
            or _mount_target_is_within(target, "/usr")
        )
        topology["separateVarMountPresent"] = bool(
            topology["separateVarMountPresent"]
            or _mount_target_is_within(target, "/var")
        )
        if filesystem == "swap" or target == "none" and "sw" in options.split(","):
            summary["swapEntryCount"] = int(summary["swapEntryCount"]) + 1
        if filesystem in {"cifs", "nfs", "nfs4", "sshfs"}:
            summary["networkEntryCount"] = int(summary["networkEntryCount"]) + 1
    topology["relevantSeparateMountPresent"] = any(
        topology[key]
        for key in (
            "separateEtcMountPresent",
            "separateBootMountPresent",
            "separateUsrMountPresent",
            "separateVarMountPresent",
        )
    )
    topology["supported"] = not topology["relevantSeparateMountPresent"]
    return summary, topology


def _mount_target_is_within(target: str, root: str) -> bool:
    return target == root or target.startswith(f"{root}/")


def _canonical_fstab_target(target: str) -> bool:
    if target in {"none", "/"}:
        return True
    if not target.startswith("/"):
        return False
    return all(segment not in {"", ".", ".."} for segment in target[1:].split("/"))


def _parse_fstab_line(line: str) -> list[str] | None:
    raw_fields: list[bytes] = []
    for raw_field in line.encode("utf-8").split():
        if raw_field.startswith(b"#"):
            break
        raw_fields.append(raw_field)
        if len(raw_fields) > 6:
            return None
    if len(raw_fields) < 4:
        return None
    fields: list[str] = []
    for raw_field in raw_fields:
        decoded = _decode_fstab_field(raw_field)
        if decoded is None:
            return None
        fields.append(decoded)
    for numeric in fields[4:]:
        if re.fullmatch(r"\+?[0-9]+", numeric) is None:
            return None
        if int(numeric, 10) > 4_294_967_295:
            return None
    return fields


def _decode_fstab_field(field: bytes) -> str | None:
    decoded = bytearray()
    index = 0
    while index < len(field):
        if field[index] != ord("\\"):
            decoded.append(field[index])
            index += 1
            continue
        if index + 3 >= len(field):
            return None
        digits = field[index + 1 : index + 4]
        if any(digit < ord("0") or digit > ord("7") for digit in digits):
            return None
        value = (digits[0] - ord("0")) * 64
        value += (digits[1] - ord("0")) * 8
        value += digits[2] - ord("0")
        if value > 255:
            return None
        decoded.append(value)
        index += 4
    try:
        value = bytes(decoded).decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return None
    if (
        not value
        or len(value.encode("utf-8")) > 1024
        or any(
            ord(character) < 32 or 127 <= ord(character) <= 159
            for character in value
        )
    ):
        return None
    return value


def _boot_summary(root_fd: int, deadline: float) -> dict[str, int | bool]:
    boot_fd = _open_directory_chain(root_fd, ("boot",))
    if boot_fd is None:
        return {
            "directoryPresent": False,
            "kernelArtifactCount": 0,
            "initramfsArtifactCount": 0,
            "bootloaderDirectoryCount": 0,
            "symlinkArtifactCount": 0,
    }
    try:
        kernel_count = 0
        initramfs_count = 0
        loader_count = 0
        symlink_count = 0
        observed = 0
        with os.scandir(boot_fd) as entries:
            for entry in entries:
                observed += 1
                if observed > MAX_DIRECTORY_ENTRIES:
                    raise InspectionError(
                        "unsafe-target-content",
                        "La directory boot supera il limite di ispezione.",
                    )
                _check_deadline(deadline)
                name = entry.name
                if not name or name in {".", ".."}:
                    continue
                metadata = entry.stat(follow_symlinks=False)
                _require_same_device(root_fd, metadata)
                if stat.S_ISLNK(metadata.st_mode):
                    symlink_count += 1
                elif stat.S_ISREG(metadata.st_mode):
                    if name.startswith(("vmlinuz-", "vmlinux-")):
                        kernel_count += 1
                    if name.startswith(("initrd.img-", "initramfs-")):
                        initramfs_count += 1
                elif stat.S_ISDIR(metadata.st_mode) and name in {
                    "efi",
                    "grub",
                    "loader",
                }:
                    loader_count += 1
        return {
            "directoryPresent": True,
            "kernelArtifactCount": min(kernel_count, MAX_DIRECTORY_ENTRIES),
            "initramfsArtifactCount": min(initramfs_count, MAX_DIRECTORY_ENTRIES),
            "bootloaderDirectoryCount": min(loader_count, 3),
            "symlinkArtifactCount": min(symlink_count, MAX_DIRECTORY_ENTRIES),
        }
    finally:
        os.close(boot_fd)


def _require_same_device(root_fd: int, metadata: object) -> None:
    if getattr(metadata, "st_dev", None) != os.fstat(root_fd).st_dev:
        raise InspectionError(
            "unsupported-cross-device-content",
            "Il corpus Linux non attraversa filesystem separati.",
        )


def collect_linux(root_fd: int, deadline: float) -> dict[str, object]:
    _check_deadline(deadline)
    fstab_payload = _read_regular(
        root_fd,
        ("etc", "fstab"),
        MAX_TEXT_FILE_BYTES,
        deadline=deadline,
    )
    fstab, topology = _fstab_projection(fstab_payload)
    release_payload = (
        None
        if topology["separateEtcMountPresent"]
        else _read_regular(
            root_fd,
            ("etc", "os-release"),
            MAX_OS_RELEASE_BYTES,
            symlink_is_absent=True,
            deadline=deadline,
        )
    )
    release_source = "etc-os-release" if release_payload is not None else "absent"
    if (
        release_payload is None
        and not topology["separateEtcMountPresent"]
        and not topology["separateUsrMountPresent"]
    ):
        release_payload = _read_regular(
            root_fd,
            ("usr", "lib", "os-release"),
            MAX_OS_RELEASE_BYTES,
            deadline=deadline,
        )
        release_source = "usr-lib-os-release" if release_payload is not None else "absent"
    release = _parse_os_release(release_payload)
    _check_deadline(deadline)
    boot = (
        {
            "directoryPresent": False,
            "kernelArtifactCount": 0,
            "initramfsArtifactCount": 0,
            "bootloaderDirectoryCount": 0,
            "symlinkArtifactCount": 0,
        }
        if topology["separateBootMountPresent"]
        else _boot_summary(root_fd, deadline)
    )
    package_databases = (
        {
            "dpkgStatusPresent": False,
            "rpmDatabasePresent": False,
            "pacmanDatabasePresent": False,
        }
        if topology["separateVarMountPresent"]
        else {
            "dpkgStatusPresent": _require_safe_kind(
                root_fd, ("var", "lib", "dpkg", "status"), {"regular"}
            )
            == "regular",
            "rpmDatabasePresent": _require_safe_kind(
                root_fd, ("var", "lib", "rpm"), {"directory"}
            )
            == "directory",
            "pacmanDatabasePresent": _require_safe_kind(
                root_fd, ("var", "lib", "pacman", "local"), {"directory"}
            )
            == "directory",
        }
    )
    machine_id_kind = (
        "absent"
        if topology["separateEtcMountPresent"]
        else _require_safe_kind(root_fd, ("etc", "machine-id"), {"regular"})
    )
    installation_confirmed = bool(
        release["id"]
        and not topology["separateEtcMountPresent"]
        and _require_safe_kind(root_fd, ("etc",), {"directory"}) == "directory"
        and not topology["separateUsrMountPresent"]
        and _require_safe_kind(root_fd, ("usr",), {"directory"}) == "directory"
    )
    return {
        "family": "linux",
        "scope": "installed-root-static",
        "installationConfirmed": installation_confirmed,
        "topology": topology,
        "release": {**release, "source": release_source},
        "boot": boot,
        "configuration": {
            "fstab": fstab,
            "machineIdPresent": machine_id_kind == "regular",
        },
        "packageDatabases": package_databases,
    }


def collect_windows(root_fd: int, deadline: float) -> dict[str, object]:
    _check_deadline(deadline)
    kinds = {
        "windowsDirectory": _require_safe_kind(
            root_fd, ("Windows",), {"directory"}
        ),
        "system32Directory": _require_safe_kind(
            root_fd, ("Windows", "System32"), {"directory"}
        ),
        "kernel": _require_safe_kind(
            root_fd, ("Windows", "System32", "ntoskrnl.exe"), {"regular"}
        ),
        "systemHive": _require_safe_kind(
            root_fd, ("Windows", "System32", "config", "SYSTEM"), {"regular"}
        ),
        "softwareHive": _require_safe_kind(
            root_fd, ("Windows", "System32", "config", "SOFTWARE"), {"regular"}
        ),
    }
    installation_confirmed = (
        kinds["windowsDirectory"] == "directory"
        and kinds["system32Directory"] == "directory"
        and kinds["kernel"] == "regular"
        and kinds["systemHive"] == "regular"
        and kinds["softwareHive"] == "regular"
    )
    _check_deadline(deadline)
    return {
        "family": "windows",
        "installationConfirmed": installation_confirmed,
        "installationMarkers": {
            "windowsDirectoryPresent": kinds["windowsDirectory"] == "directory",
            "system32DirectoryPresent": kinds["system32Directory"] == "directory",
            "kernelPresent": kinds["kernel"] == "regular",
            "systemHivePresent": kinds["systemHive"] == "regular",
            "softwareHivePresent": kinds["softwareHive"] == "regular",
            "usersDirectoryPresent": _require_safe_kind(
                root_fd, ("Users",), {"directory"}
            )
            == "directory",
        },
        "boot": {
            "bootManagerPresent": _require_safe_kind(
                root_fd, ("bootmgr",), {"regular"}
            )
            == "regular",
            "bcdPresent": _require_safe_kind(
                root_fd, ("Boot", "BCD"), {"regular"}
            )
            == "regular",
        },
        "servicing": {
            "pendingXmlPresent": _require_safe_kind(
                root_fd, ("Windows", "WinSxS", "pending.xml"), {"regular"}
            )
            == "regular",
            "rebootPendingMarkerPresent": _require_safe_kind(
                root_fd,
                ("Windows", "WinSxS", "reboot.xml"),
                {"regular"},
            )
            == "regular",
        },
    }


def collect_efi_system_partition(root_fd: int) -> dict[str, bool]:
    """Collect fixed x86-64 boot markers without returning names or bytes."""
    return {
        "microsoftBootManagerPresent": _require_safe_kind(
            root_fd,
            ("EFI", "Microsoft", "Boot", "bootmgfw.efi"),
            {"regular"},
        )
        == "regular",
        "bcdPresent": _require_safe_kind(
            root_fd, ("EFI", "Microsoft", "Boot", "BCD"), {"regular"}
        )
        == "regular",
        "fallbackBootloaderPresent": _require_safe_kind(
            root_fd, ("EFI", "BOOT", "BOOTX64.EFI"), {"regular"}
        )
        == "regular",
    }


def _qualify_resolution(
    resolution: object,
) -> tuple[str, str | None, str, str]:
    if not isinstance(resolution, dict):
        raise InspectionError(
            "target-resolution-invalid",
            "La risoluzione interna del target non è valida.",
            status=503,
        )
    candidate = resolution.get("candidate")
    filesystem = resolution.get("filesystem")
    major_minor = resolution.get("majorMinor")
    if not isinstance(candidate, dict):
        raise InspectionError(
            "target-resolution-invalid",
            "La risoluzione interna del target non è valida.",
            status=503,
        )
    if candidate.get("requiresUnlock") is True or filesystem in {
        "bitlocker",
        "crypto_luks",
    }:
        raise InspectionError(
            "unsupported-encrypted-storage",
            "Il target è cifrato: KernAid non tenta sblocco automatico.",
        )
    if filesystem in {"apfs", "hfs", "hfsplus"}:
        raise InspectionError(
            "unsupported-apple-filesystem",
            "L'ispezione APFS/HFS richiede un percorso Apple nativo.",
        )
    topology_kinds = resolution.get("topologyKinds")
    topology_filesystems = resolution.get("topologyFilesystems")
    if (
        resolution.get("kernelKind") not in {"disk", "part"}
        or resolution.get("leaf") is not True
        or resolution.get("directOnDisk") is not True
        or not isinstance(topology_kinds, list)
        or not isinstance(topology_filesystems, list)
        or any(kind in STACKED_KINDS or str(kind).startswith("raid") for kind in topology_kinds)
        or any(item in STACKED_FILESYSTEMS for item in topology_filesystems)
    ):
        raise InspectionError(
            "unsupported-complex-storage",
            "LVM, mdraid e topologie storage impilate non sono attivati automaticamente.",
        )
    if filesystem not in SUPPORTED_FILESYSTEMS:
        raise InspectionError(
            "unsupported-filesystem",
            "Questo filesystem non è ancora qualificato per l'ispezione offline.",
        )
    mount_filesystem, replay_option, expected_family, recovery_policy = (
        SUPPORTED_FILESYSTEMS[filesystem]
    )
    if candidate.get("osFamilyHint") != expected_family:
        raise InspectionError(
            "ambiguous-os-family",
            "I metadati del target non identificano una sola famiglia OS compatibile.",
        )
    if not isinstance(major_minor, str):
        raise InspectionError(
            "target-resolution-invalid",
            "La risoluzione interna del target non è valida.",
            status=503,
        )
    _major_minor_parts(major_minor)
    return mount_filesystem, replay_option, expected_family, recovery_policy


def _qualify_efi_system_partition(
    resolution: object,
) -> tuple[str, str | None, str | None]:
    if not isinstance(resolution, dict):
        raise InspectionError(
            "target-resolution-invalid",
            "La risoluzione interna della partizione EFI non è valida.",
            status=503,
        )
    state = resolution.get("state")
    if state not in EFI_SYSTEM_PARTITION_STATES:
        raise InspectionError(
            "target-resolution-invalid",
            "La risoluzione interna della partizione EFI non è valida.",
            status=503,
        )
    if state != "eligible":
        if set(resolution) != {"state"}:
            raise InspectionError(
                "target-resolution-invalid",
                "La risoluzione interna della partizione EFI non è valida.",
                status=503,
            )
        return str(state), None, None
    if set(resolution) != {
        "state",
        "deviceIdentity",
        "majorMinor",
        "filesystem",
        "kernelKind",
        "leaf",
        "directOnDisk",
    }:
        raise InspectionError(
            "target-resolution-invalid",
            "La risoluzione interna della partizione EFI non è valida.",
            status=503,
        )
    major_minor = resolution.get("majorMinor")
    filesystem = resolution.get("filesystem")
    device_identity = resolution.get("deviceIdentity")
    identity_text_fields = (
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
    if (
        not isinstance(device_identity, dict)
        or set(device_identity) != DEVICE_IDENTITY_FIELDS
        or not isinstance(major_minor, str)
        or device_identity.get("maj:min") != major_minor
        or not isinstance(device_identity.get("name"), str)
        or not device_identity.get("name")
        or not isinstance(device_identity.get("type"), str)
        or str(device_identity.get("type")).lower() != "part"
        or any(
            device_identity.get(field) is not None
            and not isinstance(device_identity.get(field), str)
            for field in identity_text_fields
        )
        or not isinstance(device_identity.get("size"), int)
        or isinstance(device_identity.get("size"), bool)
        or int(device_identity.get("size", -1)) < 0
        or not isinstance(device_identity.get("ro"), bool)
        or not isinstance(device_identity.get("rm"), bool)
        or not isinstance(device_identity.get("mountpoints"), list)
        or len(device_identity.get("mountpoints", [])) > 32
        or any(
            entry is not None and not isinstance(entry, str)
            for entry in device_identity.get("mountpoints", [])
        )
        or any(device_identity.get("mountpoints", []))
        or not isinstance(device_identity.get("fstype"), str)
        or str(device_identity.get("fstype")).lower() != filesystem
        or not isinstance(device_identity.get("parttype"), str)
        or str(device_identity.get("parttype")).lower()
        != EFI_SYSTEM_PARTITION_TYPE
        or filesystem not in EFI_SYSTEM_FILESYSTEMS
        or resolution.get("kernelKind") != "part"
        or resolution.get("leaf") is not True
        or resolution.get("directOnDisk") is not True
    ):
        raise InspectionError(
            "target-resolution-invalid",
            "La risoluzione interna della partizione EFI non è valida.",
            status=503,
        )
    _major_minor_parts(major_minor)
    return "eligible", major_minor, EFI_SYSTEM_FILESYSTEMS[str(filesystem)]


def _canonical_resolution(value: object) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _empty_efi_system_partition(state: str) -> dict[str, object]:
    return {
        "state": state,
        "microsoftBootManagerPresent": None,
        "bcdPresent": None,
        "fallbackBootloaderPresent": None,
    }


def _assert_target_resolution_unchanged(
    targets: object,
    request: dict[str, object],
    selection_before: dict[str, object],
    resolution_before: dict[str, object],
    deadline: float,
    claims: dict[str, bool],
) -> None:
    selection_after, resolution_after = targets.resolve_installed_target(
        request, deadline=deadline
    )
    if (
        targets.canonical_target_selection(selection_before)
        != targets.canonical_target_selection(selection_after)
        or _canonical_resolution(resolution_before)
        != _canonical_resolution(resolution_after)
    ):
        raise InspectionError(
            "target-identity-changed",
            "Il target è cambiato durante l'ispezione offline.",
            status=409,
            claims=claims,
        )


def _inspect_associated_efi_system_partition(
    targets: object,
    request: dict[str, object],
    selection_before: dict[str, object],
    resolution_before: dict[str, object],
    claims: dict[str, bool],
    deadline: float,
) -> dict[str, object]:
    try:
        state, major_minor, mount_filesystem = _qualify_efi_system_partition(
            resolution_before.get("associatedEfiSystemPartition")
        )
    except InspectionError as error:
        error.claims = dict(claims)
        raise
    if state != "eligible":
        return _empty_efi_system_partition(state)
    if major_minor is None or mount_filesystem != "vfat":
        raise InspectionError(
            "target-resolution-invalid",
            "La risoluzione interna della partizione EFI non è valida.",
            status=503,
            claims=claims,
        )

    _assert_target_resolution_unchanged(
        targets,
        request,
        selection_before,
        resolution_before,
        deadline,
        claims,
    )
    descriptor = -1
    major = -1
    minor = -1
    mountpoint = ""
    mounted = False
    observed: dict[str, bool] | None = None
    primary_error: BaseException | None = None
    try:
        _check_deadline(deadline)
        if _target_already_mounted(major_minor):
            raise InspectionError(
                "associated-efi-already-mounted",
                "La partizione EFI associata risulta già montata; l'ispezione è stata annullata.",
                status=409,
                retryable=True,
                claims=claims,
            )
        descriptor, major, minor = _open_bound_block_device(major_minor, deadline)
        _assert_block_fd(descriptor, major, minor)
        mountpoint = tempfile.mkdtemp(prefix="efi-inspection-", dir=MOUNT_BASE)
        os.chmod(mountpoint, 0o700)
        claims["mountCleanupVerified"] = False
        claims["mountOperationAttempted"] = True
        try:
            _mount_call(
                f"/proc/self/fd/{descriptor}".encode("ascii"),
                os.fsencode(mountpoint),
                b"vfat",
                MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_NOSYMFOLLOW,
                None,
            )
        except OSError as error:
            raise InspectionError(
                "associated-efi-read-only-mount-failed",
                "La partizione EFI associata non può essere montata con la policy read-only richiesta.",
                claims=claims,
            ) from error
        mounted = True
        claims["mountOperationPerformed"] = True
        _verify_mounted(
            mountpoint,
            major_minor,
            "vfat",
            None,
            descriptor,
            major,
            minor,
        )
        root_fd = os.open(
            mountpoint,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        try:
            _assert_block_fd(descriptor, major, minor)
            _check_deadline(deadline)
            observed = collect_efi_system_partition(root_fd)
            _check_deadline(deadline)
            _assert_block_fd(descriptor, major, minor)
            _verify_mounted(
                mountpoint,
                major_minor,
                "vfat",
                None,
                descriptor,
                major,
                minor,
            )
        finally:
            os.close(root_fd)
    except BaseException as error:
        primary_error = error
    finally:
        cleanup_error: BaseException | None = None
        if mounted:
            try:
                _umount_call(os.fsencode(mountpoint), 0)
                mounted = False
            except BaseException as error:
                cleanup_error = InspectionError(
                    "mount-cleanup-failed",
                    "Il mount temporaneo EFI non può essere rimosso in modo verificato.",
                    status=503,
                    claims=claims,
                    fatal_cleanup=True,
                )
                cleanup_error.__cause__ = error
        if descriptor >= 0:
            try:
                _assert_block_fd(descriptor, major, minor)
                if not mounted:
                    _verify_unmounted(mountpoint, major_minor)
                    _assert_target_resolution_unchanged(
                        targets,
                        request,
                        selection_before,
                        resolution_before,
                        deadline,
                        claims,
                    )
                    claims["mountCleanupVerified"] = True
            except BaseException as error:
                cleanup_error = cleanup_error or error
            finally:
                os.close(descriptor)
        if mountpoint:
            try:
                os.rmdir(mountpoint)
            except OSError as error:
                cleanup_error = cleanup_error or InspectionError(
                    "mount-cleanup-failed",
                    "La directory temporanea EFI non può essere rimossa.",
                    status=503,
                    claims=claims,
                    fatal_cleanup=True,
                )
                if cleanup_error.__cause__ is None:
                    cleanup_error.__cause__ = error
        if cleanup_error is not None:
            primary_error = cleanup_error
    if primary_error is not None:
        if isinstance(primary_error, InspectionError):
            primary_error.claims = dict(claims)
            raise primary_error
        raise InspectionError(
            "associated-efi-inspection-failed",
            "L'ispezione della partizione EFI associata non è stata completata in sicurezza.",
            status=503,
            retryable=True,
            claims=claims,
        ) from primary_error
    if observed is None or claims["mountCleanupVerified"] is not True:
        raise InspectionError(
            "associated-efi-inspection-failed",
            "L'ispezione della partizione EFI associata non ha prodotto un risultato verificato.",
            status=503,
            claims=claims,
        )
    return {"state": "inspected", **observed}


class OfflineInspectionEngine:
    def __init__(self, target_module: object) -> None:
        self.targets = target_module

    def filesystem_health(
        self, request: dict[str, object], deadline: float
    ) -> dict[str, object]:
        """Check one freshly resolved target without mounting or returning tool text."""
        _check_deadline(deadline)
        selection_before, resolution_before = self.targets.resolve_installed_target(
            request, deadline=deadline
        )
        _qualify_resolution(resolution_before)
        target = selection_before.get("target")
        filesystem = resolution_before.get("filesystem")
        major_minor = resolution_before.get("majorMinor")
        if (
            not isinstance(target, dict)
            or not isinstance(target.get("sourceRef"), str)
            or not isinstance(filesystem, str)
            or filesystem not in {"ext4", "ntfs"}
            or not isinstance(major_minor, str)
        ):
            raise InspectionError(
                "target-resolution-invalid",
                "La risoluzione interna del target non è valida.",
                status=503,
            )
        source_ref = target["sourceRef"]
        _assert_target_resolution_unchanged(
            self.targets,
            request,
            selection_before,
            resolution_before,
            deadline,
            _empty_claims(),
        )
        timeout = max(0.1, deadline - time.monotonic())
        try:
            completed = subprocess.run(
                [
                    FILESYSTEM_HEALTH_BINARY,
                    "--selected",
                    source_ref,
                    filesystem,
                    major_minor,
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=timeout,
                cwd="/",
                env={
                    "LANG": "C",
                    "LC_ALL": "C",
                    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                },
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise InspectionError(
                "filesystem-health-unavailable",
                "La diagnostica filesystem read-only non è disponibile.",
                status=503,
                retryable=True,
            ) from error
        _check_deadline(deadline)
        if (
            completed.returncode != 0
            or not completed.stdout
            or len(completed.stdout) > MAX_FILESYSTEM_HEALTH_BYTES
        ):
            raise InspectionError(
                "filesystem-health-unavailable",
                "La diagnostica filesystem read-only non è disponibile.",
                status=503,
                retryable=True,
            )
        try:
            text = completed.stdout.decode("utf-8", errors="strict")
            snapshot = json.loads(text)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise InspectionError(
                "filesystem-health-invalid",
                "Il risultato filesystem normalizzato non è valido.",
                status=503,
            ) from error
        expected_keys = (
            "schemaVersion",
            "kind",
            "targetRef",
            "filesystem",
            "state",
            "checkMode",
            "mountedAtCheck",
            "finding",
        )
        fixed_findings = {
            "repair-required": {
                "ruleId": "KA-LNX-FS-001",
                "ruleVersion": 1,
                "severity": "critical",
                "summary": "The fixed read-only filesystem check reports errors that require repair.",
                "nextAction": "Back up recoverable data, then use the operating system's native repair workflow with explicit write authorization; KernAid did not modify this filesystem.",
            },
            "degraded": {
                "ruleId": "KA-LNX-FS-002",
                "ruleVersion": 1,
                "severity": "high",
                "summary": "The filesystem was checked while mounted, so a clean result cannot be qualified.",
                "nextAction": "Boot KernAid Rescue and repeat the fixed read-only check on the unmounted selected target.",
            },
            "unsupported": {
                "ruleId": "KA-LNX-FS-003",
                "ruleVersion": 1,
                "severity": "low",
                "summary": "The fixed read-only filesystem check is unsupported or unavailable.",
                "nextAction": "Use a qualified read-only diagnostic for this filesystem; do not infer that it is healthy.",
            },
        }
        state = snapshot.get("state") if isinstance(snapshot, dict) else None
        expected_finding = None if state == "healthy" else fixed_findings.get(state)
        expected_mode = {
            "ext4": "e2fsck-read-only",
            "ntfs": "ntfsfix-no-action",
        }.get(filesystem)
        if (
            not isinstance(snapshot, dict)
            or tuple(snapshot) != expected_keys
            or snapshot.get("schemaVersion") != "1.0"
            or snapshot.get("kind") != "linux-filesystem-health"
            or snapshot.get("targetRef") != source_ref
            or snapshot.get("filesystem") != filesystem
            or state
            not in {"healthy", "degraded", "repair-required", "unsupported"}
            or not isinstance(snapshot.get("mountedAtCheck"), bool)
            or (state == "unsupported")
            != (snapshot.get("checkMode") == "unavailable")
            or (
                state != "unsupported"
                and snapshot.get("checkMode") != expected_mode
            )
            or snapshot.get("finding") != expected_finding
            or json.dumps(snapshot, ensure_ascii=True, separators=(",", ":"))
            != text
        ):
            raise InspectionError(
                "filesystem-health-invalid",
                "Il risultato filesystem normalizzato non è valido.",
                status=503,
            )
        _assert_target_resolution_unchanged(
            self.targets,
            request,
            selection_before,
            resolution_before,
            deadline,
            _empty_claims(),
        )
        return snapshot

    def inspect(self, request: dict[str, object], deadline: float) -> dict[str, object]:
        _check_deadline(deadline)
        selection_before, resolution_before = self.targets.resolve_installed_target(
            request, deadline=deadline
        )
        (
            mount_filesystem,
            replay_option,
            expected_family,
            recovery_policy,
        ) = _qualify_resolution(resolution_before)
        major_minor = resolution_before["majorMinor"]
        filesystem = resolution_before["filesystem"]
        if not isinstance(major_minor, str) or not isinstance(filesystem, str):
            raise InspectionError(
                "target-resolution-invalid",
                "La risoluzione interna del target non è valida.",
                status=503,
            )
        claims = _empty_claims()
        descriptor = -1
        mountpoint = ""
        mounted = False
        collected: dict[str, object] | None = None
        primary_error: BaseException | None = None
        try:
            _ensure_mount_base()
            if _target_already_mounted(major_minor):
                raise InspectionError(
                    "target-already-mounted",
                    "Il target risulta già montato; l'ispezione è stata annullata.",
                    status=409,
                    retryable=True,
                    claims=claims,
                )
            descriptor, major, minor = _open_bound_block_device(
                major_minor, deadline
            )
            _assert_block_fd(descriptor, major, minor)
            mountpoint = tempfile.mkdtemp(prefix="inspection-", dir=MOUNT_BASE)
            os.chmod(mountpoint, 0o700)
            source = f"/proc/self/fd/{descriptor}".encode("ascii")
            flags = MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_NOSYMFOLLOW
            claims["mountOperationAttempted"] = True
            try:
                _mount_call(
                    source,
                    os.fsencode(mountpoint),
                    mount_filesystem.encode("ascii"),
                    flags,
                    (
                        replay_option.encode("ascii")
                        if replay_option is not None
                        else None
                    ),
                )
            except OSError as error:
                raise InspectionError(
                    "read-only-mount-failed",
                    "Il target non può essere montato con la policy read-only richiesta.",
                    status=422,
                    retryable=False,
                    claims=claims,
                ) from error
            mounted = True
            claims["mountOperationPerformed"] = True
            _verify_mounted(
                mountpoint,
                major_minor,
                mount_filesystem,
                replay_option,
                descriptor,
                major,
                minor,
            )
            root_fd = os.open(
                mountpoint,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
            try:
                _assert_block_fd(descriptor, major, minor)
                collected = (
                    collect_linux(root_fd, deadline)
                    if expected_family == "linux"
                    else collect_windows(root_fd, deadline)
                )
                claims["filesystemContentInspected"] = True
                claims["installedOsConfirmed"] = bool(
                    collected["installationConfirmed"]
                )
                _assert_block_fd(descriptor, major, minor)
                _verify_mounted(
                    mountpoint,
                    major_minor,
                    mount_filesystem,
                    replay_option,
                    descriptor,
                    major,
                    minor,
                )
            finally:
                os.close(root_fd)
        except BaseException as error:
            primary_error = error
        finally:
            cleanup_error: BaseException | None = None
            if mounted:
                try:
                    _umount_call(os.fsencode(mountpoint), 0)
                    mounted = False
                except BaseException as error:
                    cleanup_error = InspectionError(
                        "mount-cleanup-failed",
                        "Il mount temporaneo non può essere rimosso in modo verificato.",
                        status=503,
                        claims=claims,
                        fatal_cleanup=True,
                    )
                    cleanup_error.__cause__ = error
            if descriptor >= 0:
                try:
                    _assert_block_fd(descriptor, major, minor)
                    if not mounted:
                        _verify_unmounted(mountpoint, major_minor)
                        _assert_target_resolution_unchanged(
                            self.targets,
                            request,
                            selection_before,
                            resolution_before,
                            deadline,
                            claims,
                        )
                        claims["mountCleanupVerified"] = True
                except BaseException as error:
                    cleanup_error = cleanup_error or error
                finally:
                    os.close(descriptor)
            if mountpoint:
                try:
                    os.rmdir(mountpoint)
                except OSError as error:
                    cleanup_error = cleanup_error or InspectionError(
                        "mount-cleanup-failed",
                        "La directory temporanea non può essere rimossa.",
                        status=503,
                        claims=claims,
                        fatal_cleanup=True,
                    )
                    if cleanup_error.__cause__ is None:
                        cleanup_error.__cause__ = error
            if cleanup_error is not None:
                primary_error = cleanup_error
        if primary_error is not None:
            if isinstance(primary_error, InspectionError):
                primary_error.claims = dict(claims)
                raise primary_error
            raise InspectionError(
                "inspection-failed",
                "L'ispezione offline non è stata completata in sicurezza.",
                status=503,
                retryable=True,
                claims=claims,
            ) from primary_error
        if collected is None or claims["mountCleanupVerified"] is not True:
            raise InspectionError(
                "inspection-failed",
                "L'ispezione offline non ha prodotto un risultato verificato.",
                status=503,
                claims=claims,
            )
        efi_state: str | None = None
        if expected_family == "windows":
            efi = _inspect_associated_efi_system_partition(
                self.targets,
                request,
                selection_before,
                resolution_before,
                claims,
                deadline,
            )
            boot = collected.get("boot")
            if not isinstance(boot, dict):
                raise InspectionError(
                    "inspection-failed",
                    "L'ispezione Windows non ha prodotto un risultato valido.",
                    status=503,
                    claims=claims,
                )
            boot["efiSystemPartition"] = efi
            efi_state = str(efi["state"])
        candidate = selection_before["target"]
        if not isinstance(candidate, dict):
            raise InspectionError(
                "target-resolution-invalid",
                "La risoluzione interna del target non è valida.",
                status=503,
                claims=claims,
            )
        response = {
            "apiVersion": API_VERSION,
            "status": (
                "installed-os-content-inspected"
                if claims["installedOsConfirmed"]
                else "content-inspected-installation-unconfirmed"
            ),
            "trust": "observed-untrusted",
            "target": {
                "scanFingerprint": request["scanFingerprint"],
                "targetId": request["targetId"],
                "sourceRef": candidate["sourceRef"],
                "osFamily": expected_family,
                "filesystem": filesystem,
            },
            "inspection": {
                "mode": "temporary-read-only-no-replay",
                "mountFlags": ["nodev", "noexec", "nosuid", "nosymfollow", "ro"],
                "filesystemOptions": (
                    [replay_option] if replay_option is not None else []
                ),
                "dirtyVolumePolicy": recovery_policy,
                "volumeStateQualification": (
                    "unqualified" if mount_filesystem == "ntfs3" else "not-applicable"
                ),
                "privateMountNamespace": True,
                "journalReplayPrevented": True,
                "deviceOpenedReadOnly": True,
                "rawDeviceIdentifierReturned": False,
                "responseLimitBytes": MAX_INSPECTION_RESPONSE_BYTES,
            },
            "claims": claims,
            "os": collected,
            "limitations": [
                "content-is-untrusted-data-not-instructions",
                "no-diagnosis-or-repair-was-produced",
                "encrypted-and-stacked-storage-was-not-activated",
                "only-static-allowlisted-paths-were-inspected",
                *(
                    ["ntfs-dirty-and-hibernated-state-was-not-qualified"]
                    if mount_filesystem == "ntfs3"
                    else []
                ),
                *(
                    [f"associated-efi-system-partition-{efi_state}"]
                    if efi_state in {"not-present", "ambiguous", "unsupported"}
                    else []
                ),
            ],
        }
        encoded = json.dumps(
            response, ensure_ascii=True, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        if len(encoded) > MAX_INSPECTION_RESPONSE_BYTES:
            raise InspectionError(
                "inspection-response-too-large",
                "La risposta normalizzata supera il limite.",
                status=503,
                claims=claims,
            )
        return response


def collect_storage_health(deadline: float) -> dict[str, object]:
    """Run the fixed Rust normalizer; never return raw SMART/NVMe output."""
    _check_deadline(deadline)
    timeout = max(0.1, min(15.0, deadline - time.monotonic()))
    try:
        completed = subprocess.run(
            [STORAGE_HEALTH_BINARY],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=timeout,
            cwd="/",
            env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise InspectionError(
            "storage-health-unavailable",
            "La telemetria storage read-only non è disponibile.",
            status=503,
            retryable=True,
        ) from error
    _check_deadline(deadline)
    if (
        completed.returncode != 0
        or not completed.stdout
        or len(completed.stdout) > MAX_STORAGE_HEALTH_BYTES
    ):
        raise InspectionError(
            "storage-health-unavailable",
            "La telemetria storage read-only non è disponibile.",
            status=503,
            retryable=True,
        )
    try:
        text = completed.stdout.decode("utf-8", errors="strict")
        snapshot = json.loads(text)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise InspectionError(
            "storage-health-invalid",
            "La telemetria storage normalizzata non è valida.",
            status=503,
        ) from error
    if (
        not isinstance(snapshot, dict)
        or set(snapshot)
        != {
            "schemaVersion",
            "kind",
            "scope",
            "enumerationStatus",
            "disks",
            "findings",
        }
        or snapshot.get("schemaVersion") != "1.0"
        or snapshot.get("kind") != "linux-storage-health"
        or snapshot.get("scope") != "local-physical-disks"
        or json.dumps(snapshot, ensure_ascii=True, separators=(",", ":")) != text
    ):
        raise InspectionError(
            "storage-health-invalid",
            "La telemetria storage normalizzata non è valida.",
            status=503,
        )
    forbidden = {"serial", "serialNumber", "wwn", "device", "path", "raw"}

    def contains_forbidden(value: object) -> bool:
        if isinstance(value, dict):
            return any(
                key in forbidden or contains_forbidden(child)
                for key, child in value.items()
            )
        if isinstance(value, list):
            return any(contains_forbidden(child) for child in value)
        return False

    if contains_forbidden(snapshot):
        raise InspectionError(
            "storage-health-invalid",
            "La telemetria storage normalizzata non è valida.",
            status=503,
        )
    return snapshot


class OfflineInspectorService:
    def __init__(self, target_module: object | None = None) -> None:
        self.targets = _load_target_module() if target_module is None else target_module
        self.engine = OfflineInspectionEngine(self.targets)
        self.fatal_cleanup = False

    def dispatch(self, value: object) -> dict[str, object]:
        if not isinstance(value, dict) or set(value) not in (
            {"operation"},
            {"operation", "request"},
        ):
            raise InspectionError(
                "invalid-helper-request",
                "Richiesta all'ispettore privilegiato non valida.",
                status=400,
            )
        operation = value.get("operation")
        deadline = time.monotonic() + (
            FILESYSTEM_HEALTH_OPERATION_TIMEOUT_SECONDS
            if operation == "filesystem-health"
            else OPERATION_TIMEOUT_SECONDS
        )
        if operation == "scan" and set(value) == {"operation"}:
            return self.targets.installed_targets(deadline=deadline)
        if operation == "storage-health" and set(value) == {"operation"}:
            return collect_storage_health(deadline)
        request = value.get("request")
        if not isinstance(request, dict) or set(request) != {
            "scanFingerprint",
            "targetId",
        }:
            raise InspectionError(
                "invalid-helper-request",
                "Richiesta all'ispettore privilegiato non valida.",
                status=400,
            )
        if operation == "select" and set(value) == {"operation", "request"}:
            return self.targets.select_installed_target(request, deadline=deadline)
        if operation == "inspect" and set(value) == {"operation", "request"}:
            return self.engine.inspect(request, deadline)
        if operation == "filesystem-health" and set(value) == {
            "operation",
            "request",
        }:
            return self.engine.filesystem_health(request, deadline)
        raise InspectionError(
            "invalid-helper-request",
            "Operazione dell'ispettore privilegiato non consentita.",
            status=400,
        )

    def handle(self, value: object) -> dict[str, object]:
        try:
            return {"ok": True, "result": self.dispatch(value)}
        except InspectionError as error:
            self.fatal_cleanup = self.fatal_cleanup or error.fatal_cleanup
            return {"ok": False, "status": error.status, "error": error.public()}
        except TimeoutError:
            error = InspectionError(
                "inspection-timeout",
                "L'operazione privilegiata ha superato il limite temporale.",
                status=408,
                retryable=True,
            )
            return {"ok": False, "status": error.status, "error": error.public()}
        except Exception as error:
            target_errors = tuple(
                error_type
                for error_type in (
                    getattr(self.targets, "TargetScanBusy", None),
                    getattr(self.targets, "TargetScanError", None),
                    getattr(self.targets, "TargetSelectionError", None),
                )
                if isinstance(error_type, type)
            )
            if target_errors and isinstance(error, target_errors):
                status = int(getattr(error, "status", 409))
                mapped = InspectionError(
                    "target-revalidation-failed",
                    "Il target selezionato non ha superato la rivalidazione.",
                    status=status,
                    retryable=status in {408, 409, 429, 503},
                )
                return {"ok": False, "status": status, "error": mapped.public()}
            mapped = InspectionError(
                "privileged-helper-failed",
                "L'ispettore privilegiato ha interrotto l'operazione in sicurezza.",
                status=503,
                retryable=True,
            )
            return {"ok": False, "status": 503, "error": mapped.public()}


def _read_request(connection: socket.socket) -> object:
    connection.settimeout(OPERATION_TIMEOUT_SECONDS + 2)
    payload = bytearray()
    while len(payload) <= MAX_PROTOCOL_REQUEST_BYTES:
        chunk = connection.recv(min(4 * 1024, MAX_PROTOCOL_REQUEST_BYTES + 1 - len(payload)))
        if not chunk:
            break
        payload.extend(chunk)
        if b"\n" in chunk:
            break
    if len(payload) > MAX_PROTOCOL_REQUEST_BYTES or payload.count(b"\n") != 1 or not payload.endswith(b"\n"):
        raise InspectionError(
            "invalid-helper-request",
            "Frame IPC non valido.",
            status=400,
        )
    try:
        return json.loads(payload[:-1].decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise InspectionError(
            "invalid-helper-request",
            "JSON IPC non valido.",
            status=400,
        ) from error


def serve_connection(
    connection: socket.socket, service: OfflineInspectorService
) -> None:
    """Serve exactly one accepted socket inside this service cgroup/namespace."""
    make_mount_namespace_private()
    with connection:
        try:
            request = _read_request(connection)
            response = service.handle(request)
        except InspectionError as error:
            response = {"ok": False, "status": error.status, "error": error.public()}
        encoded = json.dumps(
            response, ensure_ascii=True, sort_keys=True, separators=(",", ":")
        ).encode("utf-8") + b"\n"
        if len(encoded) > MAX_PROTOCOL_RESPONSE_BYTES:
            fallback = InspectionError(
                "helper-response-too-large",
                "La risposta IPC supera il limite.",
                status=503,
            )
            encoded = json.dumps(
                {"ok": False, "status": 503, "error": fallback.public()},
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8") + b"\n"
        connection.sendall(encoded)


def _systemd_connection() -> socket.socket:
    if os.environ.get("LISTEN_PID") != str(os.getpid()) or os.environ.get("LISTEN_FDS") != "1":
        raise RuntimeError("exactly one accepted systemd connection is required")
    connection = socket.fromfd(3, socket.AF_UNIX, socket.SOCK_STREAM)
    os.close(3)
    os.set_inheritable(connection.fileno(), False)
    if (
        connection.family != socket.AF_UNIX
        or connection.type & socket.SOCK_STREAM != socket.SOCK_STREAM
        or connection.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 0
        or connection.getsockname() != SOCKET_PATH
    ):
        connection.close()
        raise RuntimeError("the accepted socket does not match the fixed endpoint")
    return connection


if __name__ == "__main__":
    if sys.argv == [sys.argv[0], "--initialize-target-key"]:
        initialize_target_id_key()
    elif sys.argv == [sys.argv[0]]:
        serve_connection(_systemd_connection(), OfflineInspectorService())
    else:
        raise SystemExit("unsupported offline-inspector invocation")
