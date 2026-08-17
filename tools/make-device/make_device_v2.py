"""Fail-closed catalog-v2 Rescue media writer and encrypted-vault provisioner.

This module is imported only after ``make-device-v2.py`` validates the
root-owned installed bundle.  Unit tests import it directly from the trusted
checkout.  The v1 writer remains operationally separate: there is no catalog
or execution fallback in this module.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import fcntl
import hashlib
import hmac
import json
import os
import re
import selectors
import signal
import stat
import struct
import sys
import tempfile
import termios
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Iterable, Mapping, Sequence


MODULE_DIRECTORY = Path(__file__).resolve().parent


def _load_sibling(name: str, filename: str) -> ModuleType:
    path = MODULE_DIRECTORY / filename
    expected = path.lstat()
    if not stat.S_ISREG(expected.st_mode) or not 0 < expected.st_size <= 4 * 1024 * 1024:
        raise RuntimeError(f"required writer module has an unsafe size: {filename}")
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise RuntimeError(f"cannot open required writer module {filename}") from error
    try:
        observed = os.fstat(descriptor)
        if (
            (observed.st_dev, observed.st_ino, observed.st_mode)
            != (expected.st_dev, expected.st_ino, expected.st_mode)
            or observed.st_size != expected.st_size
        ):
            raise RuntimeError(f"required writer module changed: {filename}")
        chunks: list[bytes] = []
        remaining = expected.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                raise RuntimeError(f"required writer module ended early: {filename}")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise RuntimeError(f"required writer module grew while reading: {filename}")
        source = b"".join(chunks)
    finally:
        os.close(descriptor)
    module = ModuleType(name)
    module.__file__ = str(path)
    module.__package__ = ""
    sys.modules[name] = module
    try:
        code = compile(source, str(path), "exec", dont_inherit=True)
        exec(code, module.__dict__)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module


v1 = _load_sibling("kernaid_make_device_v1_for_v2", "make-device.py")
catalog_v2 = _load_sibling("kernaid_catalog_v2_for_writer", "catalog_v2.py")

SafetyError = v1.SafetyError
WriteError = v1.WriteError
OperationInterrupted = v1.OperationInterrupted
OperationState = v1.OperationState
WritePhase = v1.WritePhase

SAFE_ENV = {"LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}
LSBLK_PATHS = ("/usr/bin/lsblk", "/bin/lsblk")
LOSETUP_PATHS = ("/usr/sbin/losetup", "/sbin/losetup", "/usr/bin/losetup")
UDEVADM_PATHS = ("/usr/bin/udevadm", "/bin/udevadm", "/usr/sbin/udevadm")
WIPEFS_PATHS = ("/usr/sbin/wipefs", "/sbin/wipefs", "/usr/bin/wipefs")
CRYPTSETUP_PATHS = ("/usr/sbin/cryptsetup", "/sbin/cryptsetup", "/usr/bin/cryptsetup")
MKFS_EXT4_PATHS = ("/usr/sbin/mkfs.ext4", "/sbin/mkfs.ext4", "/usr/bin/mkfs.ext4")
TUNE2FS_PATHS = ("/usr/sbin/tune2fs", "/sbin/tune2fs", "/usr/bin/tune2fs")
BLKID_PATHS = ("/usr/sbin/blkid", "/sbin/blkid", "/usr/bin/blkid")
MOUNT_PATHS = ("/usr/bin/mount", "/bin/mount")
UMOUNT_PATHS = ("/usr/bin/umount", "/bin/umount")

CATALOG_FILENAME = "trusted-rescue-images.v2.json"
LAYOUT_FILENAME = "device-layout.v1.json"
VAULT_LABEL = "KERNAID_VAULT"
VAULT_MARKER_NAME = ".kernaid-rescue-vault"
VAULT_MARKER = b"KERNAID-RESCUE-VAULT-V1\n"
VAULT_LOCK_NAME = ".kernaid-rescue-secrets.lock"
STATE_DIRECTORY = ".kernaid-secure-state-v1"
IDENTITY_NAME = "device-identity"
IDENTITY_PREFIX = b"kernaid-rescue-secret-v1:device-identity-seed-v1:"
IDENTITY_SEED_BYTES = 32
MAX_SECRET_BYTES = 1024
MIN_SECRET_BYTES = 12
MAX_COMMAND_OUTPUT = 4 * 1024 * 1024
MAX_SYSFS_BYTES = 4096
COMMAND_TIMEOUT_SECONDS = 30
FORMAT_TIMEOUT_SECONDS = 180
COPY_TIMEOUT_SECONDS = 2 * 60 * 60
CHILD_STOP_SECONDS = 3
COPY_CHUNK_BYTES = 4 * 1024 * 1024
BLKRRPART = 0x125F
UUID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z"
)
LUKS_CIPHER = "aes-xts-plain64"
LUKS_KEY_BITS = 512
LUKS_SECTOR_BYTES = 512
LUKS_AF_HASH = "sha256"
LUKS_AF_STRIPES = 4000
LUKS_PBKDF = "argon2id"
LUKS_PBKDF_TIME = 4
LUKS_PBKDF_MEMORY_KIB = 65536
LUKS_PBKDF_CPUS = 1
LUKS_METADATA_BYTES = 16384
LUKS_KEYSLOTS_BYTES = 16744448
LUKS_KEYSLOT = 0
LUKS_KEYSLOT_AREA_OFFSET_BYTES = 32768
LUKS_KEYSLOT_AREA_BYTES = 258048
LUKS_DATA_OFFSET_BYTES = 16777216
LUKS_DIGEST_HASH = "sha256"
LUKS_DIGEST_ITERATIONS = 1000
EXT4_BLOCK_BYTES = 4096
EXT4_INODE_BYTES = 256
EXT4_BYTES_PER_INODE = 16384
EXT4_BLOCKS_PER_GROUP = 32768
EXT4_FLEX_GROUP_SIZE = 16
EXT4_FLEX_GROUP_LOG = 4
EXT4_JOURNAL_MIB = 128
EXT4_COMPAT_FEATURES = 0x0000003C
EXT4_INCOMPAT_FEATURES = 0x000002C2
EXT4_RO_COMPAT_FEATURES = 0x0000046B
EXT4_RESERVED_PERCENT = 0
EXT4_DEFAULT_MOUNT_OPTIONS = "none"
EXT4_ERRORS = "remount-ro"
VAULT_PROFILE_VERSION = 1
VAULT_PROFILE_SHA256 = (
    "b4801359bd4f31ce67fbd3ec15b6c81c44aa6759ba43b2a4e099a7dfcc25a37c"
)
SAFE_SYSFS_NAME_RE = re.compile(r"[A-Za-z0-9._!+#:@~-]+\Z")
MAPPER_NAME_RE = re.compile(r"kernaid-vault-[0-9a-f]{16}\Z")
BASE64URL_ALPHABET = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: bytes
    stderr: bytes


@dataclass(frozen=True)
class PartitionIdentity:
    path: str
    major_minor: str
    parent_major_minor: str
    start_lba: int
    sector_count: int
    size: int
    node_device: int
    node_inode: int
    node_rdev: int
    sysfs_path: str


@dataclass(frozen=True)
class MapperIdentity:
    name: str
    alias_path: str
    node_path: str
    major_minor: str
    backing_major_minor: str
    size: int
    node_device: int
    node_inode: int
    node_rdev: int
    dm_uuid: str


@dataclass(frozen=True)
class VaultEvidence:
    luks_uuid: str
    filesystem_uuid: str
    marker_sha256: str
    identity_sha256: str


@dataclass
class VaultLifecycle:
    mapper: MapperIdentity | None = None
    mapper_lease_fd: int = -1
    pending_mapper_name: str | None = None
    mountpoint: str | None = None
    mount_major_minor: str | None = None
    mountpoint_device: int | None = None
    mountpoint_inode: int | None = None


@dataclass(frozen=True)
class ToolIdentity:
    name: str
    path: str
    device: int
    inode: int
    size: int
    mode: int
    mtime_ns: int
    owner: int
    group: int
    ctime_ns: int


_PREFLIGHT_TOOLS: dict[str, ToolIdentity] | None = None


def implemented_vault_profile_document() -> dict[str, object]:
    """Return the profile represented by the writer's effective constants.

    Keeping this construction next to the constants makes the profile binding
    executable: a changed formatter/verifier constant cannot continue to claim
    the immutable profile-v1 digest merely because a duplicated hash was left
    untouched.
    """

    return {
        "schema": "kernaid.vault-profile.v1",
        "luks2": {
            "afHash": LUKS_AF_HASH,
            "afStripes": LUKS_AF_STRIPES,
            "cipher": LUKS_CIPHER,
            "dataOffsetBytes": LUKS_DATA_OFFSET_BYTES,
            "digestHash": LUKS_DIGEST_HASH,
            "digestIterations": LUKS_DIGEST_ITERATIONS,
            "keyBits": LUKS_KEY_BITS,
            "keyslot": LUKS_KEYSLOT,
            "keyslotAreaBytes": LUKS_KEYSLOT_AREA_BYTES,
            "keyslotAreaOffsetBytes": LUKS_KEYSLOT_AREA_OFFSET_BYTES,
            "keyslotsBytes": LUKS_KEYSLOTS_BYTES,
            "metadataBytes": LUKS_METADATA_BYTES,
            "pbkdf": LUKS_PBKDF,
            "pbkdfCpus": LUKS_PBKDF_CPUS,
            "pbkdfMemoryKiB": LUKS_PBKDF_MEMORY_KIB,
            "pbkdfTime": LUKS_PBKDF_TIME,
            "sectorBytes": LUKS_SECTOR_BYTES,
        },
        "ext4": {
            "blockBytes": EXT4_BLOCK_BYTES,
            "blocksPerGroup": EXT4_BLOCKS_PER_GROUP,
            "bytesPerInode": EXT4_BYTES_PER_INODE,
            "defaultMountOptions": EXT4_DEFAULT_MOUNT_OPTIONS,
            "errors": EXT4_ERRORS,
            "featuresCompat": EXT4_COMPAT_FEATURES,
            "featuresIncompat": EXT4_INCOMPAT_FEATURES,
            "featuresRoCompat": EXT4_RO_COMPAT_FEATURES,
            "flexGroupSize": EXT4_FLEX_GROUP_SIZE,
            "inodeBytes": EXT4_INODE_BYTES,
            "journalMiB": EXT4_JOURNAL_MIB,
            "reservedPercent": EXT4_RESERVED_PERCENT,
        },
    }


def verify_implemented_vault_profile() -> None:
    implemented = implemented_vault_profile_document()
    canonical = json.dumps(
        implemented, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    digest = hashlib.sha256(canonical).hexdigest()
    if (
        EXT4_FLEX_GROUP_SIZE <= 0
        or EXT4_FLEX_GROUP_SIZE & (EXT4_FLEX_GROUP_SIZE - 1)
        or EXT4_FLEX_GROUP_LOG != EXT4_FLEX_GROUP_SIZE.bit_length() - 1
        or EXT4_DEFAULT_MOUNT_OPTIONS != "none"
        or EXT4_ERRORS != "remount-ro"
        or implemented != catalog_v2.VAULT_PROFILE_DOCUMENT
        or VAULT_PROFILE_VERSION != catalog_v2.VAULT_PROFILE_VERSION
        or digest != VAULT_PROFILE_SHA256
        or digest != catalog_v2.VAULT_PROFILE_SHA256
    ):
        raise SafetyError(
            "writer implementation diverges from the canonical vault profile"
        )


def _fixed_binary(paths: Sequence[str], name: str) -> str:
    if _PREFLIGHT_TOOLS is not None and name in _PREFLIGHT_TOOLS:
        identity = _PREFLIGHT_TOOLS[name]
        try:
            details = os.stat(identity.path, follow_symlinks=False)
        except OSError as error:
            raise SafetyError(f"preflighted system tool disappeared: {name}") from error
        if (
            not stat.S_ISREG(details.st_mode)
            or not os.access(identity.path, os.X_OK)
            or (
                details.st_dev,
                details.st_ino,
                details.st_size,
                details.st_mode,
                details.st_mtime_ns,
                details.st_uid,
                details.st_gid,
                details.st_ctime_ns,
            )
            != (
                identity.device,
                identity.inode,
                identity.size,
                identity.mode,
                identity.mtime_ns,
                identity.owner,
                identity.group,
                identity.ctime_ns,
            )
        ):
            raise SafetyError(f"preflighted system tool identity changed: {name}")
        return identity.path
    return v1._fixed_binary(paths, name)


def _process_group_exists(process_group: int) -> bool:
    try:
        os.killpg(process_group, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def _stop_process(process) -> None:
    process_group = process.pid
    previous_mask = None
    if hasattr(signal, "pthread_sigmask"):
        previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, v1.MANAGED_SIGNALS)

    try:
        try:
            os.killpg(process_group, signal.SIGTERM)
        except ProcessLookupError:
            pass
        term_deadline = time.monotonic() + CHILD_STOP_SECONDS
        while _process_group_exists(process_group) and time.monotonic() < term_deadline:
            process.poll()
            time.sleep(0.02)
        process.poll()
        if _process_group_exists(process_group):
            try:
                os.killpg(process_group, signal.SIGKILL)
            except ProcessLookupError:
                pass
        kill_deadline = time.monotonic() + CHILD_STOP_SECONDS
        while _process_group_exists(process_group) and time.monotonic() < kill_deadline:
            process.poll()
            time.sleep(0.02)
        process.poll()
        try:
            process.wait(timeout=max(0.01, kill_deadline - time.monotonic()))
        except __import__("subprocess").TimeoutExpired as error:
            raise WriteError("a child process leader could not be reaped safely") from error
        if _process_group_exists(process_group):
            raise WriteError("a descendant process group could not be stopped safely")
    finally:
        if previous_mask is not None:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)


@contextmanager
def defer_managed_signals():
    """Keep mutator cleanup atomic while child processes inherit no blocked signal."""

    if not hasattr(signal, "pthread_sigmask"):
        raise WriteError("managed signal deferral is unavailable")
    pending_signals: list[int] = []
    previous_handlers: dict[signal.Signals, object] = {}

    def defer_signal(signal_number: int, _frame: object) -> None:
        if not pending_signals:
            pending_signals.append(signal_number)

    entry_mask = signal.pthread_sigmask(signal.SIG_BLOCK, v1.MANAGED_SIGNALS)
    try:
        for managed_signal in v1.MANAGED_SIGNALS:
            previous_handlers[managed_signal] = signal.getsignal(managed_signal)
            signal.signal(managed_signal, defer_signal)
    except BaseException:
        for managed_signal, previous_handler in previous_handlers.items():
            signal.signal(managed_signal, previous_handler)
        signal.pthread_sigmask(signal.SIG_SETMASK, entry_mask)
        raise
    active_mask = set(entry_mask).difference(v1.MANAGED_SIGNALS)
    signal.pthread_sigmask(signal.SIG_SETMASK, active_mask)
    try:
        yield defer_signal
    finally:
        signal.pthread_sigmask(signal.SIG_BLOCK, v1.MANAGED_SIGNALS)
        try:
            for managed_signal, previous_handler in previous_handlers.items():
                signal.signal(managed_signal, previous_handler)
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, entry_mask)
    if pending_signals:
        raise OperationInterrupted(pending_signals[0])


def _spawn_command(
    argv: Sequence[str],
    pass_fds: Sequence[int],
    deferred_signal_handler: object | None = None,
):
    """Spawn atomically with respect to managed termination signals."""

    import subprocess

    if not hasattr(signal, "pthread_sigmask"):
        raise WriteError("managed signal transitions are unavailable")
    if deferred_signal_handler is not None:
        current_mask = signal.pthread_sigmask(signal.SIG_BLOCK, ())
        if set(current_mask).intersection(v1.MANAGED_SIGNALS) or any(
            signal.getsignal(managed_signal) is not deferred_signal_handler
            for managed_signal in v1.MANAGED_SIGNALS
        ):
            raise WriteError("cleanup signal deferral context is not active")
        return subprocess.Popen(
            list(argv),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=SAFE_ENV,
            close_fds=True,
            pass_fds=tuple(pass_fds),
            start_new_session=True,
        )
    pending_signals: list[int] = []
    previous_handlers: dict[signal.Signals, object] = {}

    def defer_signal(signal_number: int, _frame: object) -> None:
        if not pending_signals:
            pending_signals.append(signal_number)

    previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, v1.MANAGED_SIGNALS)
    try:
        if set(previous_mask).intersection(v1.MANAGED_SIGNALS):
            raise WriteError("a managed termination signal was already blocked")
        for managed_signal in v1.MANAGED_SIGNALS:
            previous_handlers[managed_signal] = signal.getsignal(managed_signal)
            signal.signal(managed_signal, defer_signal)
    except BaseException:
        for managed_signal, previous_handler in previous_handlers.items():
            signal.signal(managed_signal, previous_handler)
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
        raise
    signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)

    process = None
    try:
        try:
            if pending_signals:
                raise OperationInterrupted(pending_signals[0])
            process = subprocess.Popen(
                list(argv),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=SAFE_ENV,
                close_fds=True,
                pass_fds=tuple(pass_fds),
                start_new_session=True,
            )
        finally:
            restore_mask = signal.pthread_sigmask(
                signal.SIG_BLOCK, v1.MANAGED_SIGNALS
            )
            try:
                for managed_signal, previous_handler in previous_handlers.items():
                    signal.signal(managed_signal, previous_handler)
            finally:
                signal.pthread_sigmask(signal.SIG_SETMASK, restore_mask)
        if pending_signals:
            raise OperationInterrupted(pending_signals[0])
        assert process is not None
        return process
    except BaseException:
        if process is None:
            raise
        cleanup_error = None
        try:
            _stop_process(process)
        except BaseException as error:
            cleanup_error = error
        finally:
            if process.stdout is not None:
                process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()
        if cleanup_error is not None:
            raise WriteError(
                "spawned process group could not be supervised after interruption"
            ) from cleanup_error
        raise


def run_command(
    argv: Sequence[str],
    *,
    label: str,
    timeout: int = COMMAND_TIMEOUT_SECONDS,
    pass_fds: Sequence[int] = (),
    allowed_returncodes: Iterable[int] = (0,),
    maximum_output: int = MAX_COMMAND_OUTPUT,
    deferred_signal_handler: object | None = None,
) -> CommandResult:
    """Run one fixed command with bounded output and process-group cleanup."""

    import subprocess

    if (
        not argv
        or not os.path.isabs(argv[0])
        or not os.path.isfile(argv[0])
        or not os.access(argv[0], os.X_OK)
    ):
        raise SafetyError(f"{label} is not a fixed executable")
    if timeout <= 0 or maximum_output <= 0:
        raise ValueError("command limits must be positive")
    allowed = frozenset(allowed_returncodes)
    process = None
    group_cleanup_required = False
    selector = selectors.DefaultSelector()
    stdout = bytearray()
    stderr = bytearray()
    deadline = time.monotonic() + timeout
    try:
        process = _spawn_command(argv, pass_fds, deferred_signal_handler)
        group_cleanup_required = True
        assert process.stdout is not None and process.stderr is not None
        for stream, destination in ((process.stdout, stdout), (process.stderr, stderr)):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, destination)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise WriteError(f"{label} exceeded its deadline")
            events = selector.select(min(remaining, 0.25))
            if not events and process.poll() is not None:
                events = [(key, selectors.EVENT_READ) for key in selector.get_map().values()]
            for key, _ in events:
                destination = key.data
                try:
                    chunk = os.read(key.fileobj.fileno(), 65536)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                destination.extend(chunk)
                if len(stdout) + len(stderr) > maximum_output:
                    raise WriteError(f"{label} output exceeded the safety limit")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise WriteError(f"{label} exceeded its deadline")
        returncode = process.wait(timeout=remaining)
        if _process_group_exists(process.pid):
            raise WriteError(f"{label} left unexpected surviving descendants")
        group_cleanup_required = False
        if returncode not in allowed:
            detail = stderr.decode("utf-8", "replace").strip()[:500]
            raise WriteError(f"{label} failed: {detail or 'no bounded diagnostic'}")
    except BaseException:
        if process is not None and group_cleanup_required:
            _stop_process(process)
        raise
    finally:
        selector.close()
        if process is not None:
            if process.stdout is not None:
                process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()
    return CommandResult(returncode, bytes(stdout), bytes(stderr))


def _strict_text(raw: bytes, label: str) -> str:
    try:
        return raw.decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise SafetyError(f"{label} is not strict UTF-8") from error


def _luks_format_command(
    cryptsetup: str,
    key_path: str,
    key_size: int,
    device_path: str,
    luks_uuid: str,
    *,
    test_args: bool = False,
) -> list[str]:
    command = [
        cryptsetup,
        "luksFormat",
        "--type",
        "luks2",
        "--batch-mode",
        "--label",
        VAULT_LABEL,
        "--uuid",
        luks_uuid,
        "--cipher",
        LUKS_CIPHER,
        "--key-size",
        str(LUKS_KEY_BITS),
        "--hash",
        LUKS_AF_HASH,
        "--sector-size",
        str(LUKS_SECTOR_BYTES),
        "--pbkdf",
        LUKS_PBKDF,
        "--pbkdf-force-iterations",
        str(LUKS_PBKDF_TIME),
        "--pbkdf-memory",
        str(LUKS_PBKDF_MEMORY_KIB),
        "--pbkdf-parallel",
        str(LUKS_PBKDF_CPUS),
        "--key-slot",
        str(LUKS_KEYSLOT),
        "--keyslot-cipher",
        LUKS_CIPHER,
        "--keyslot-key-size",
        str(LUKS_KEY_BITS),
        "--luks2-metadata-size",
        str(LUKS_METADATA_BYTES),
        "--luks2-keyslots-size",
        str(LUKS_KEYSLOTS_BYTES),
        "--use-urandom",
        "--key-file",
        key_path,
        "--keyfile-size",
        str(key_size),
    ]
    if test_args:
        command.append("--test-args")
    command.append(device_path)
    return command


def _luks_open_command(
    cryptsetup: str,
    key_path: str,
    key_size: int,
    device_path: str,
    name: str,
    *,
    test_args: bool = False,
) -> list[str]:
    command = [
        cryptsetup,
        "open",
        "--type",
        "luks2",
        "--batch-mode",
        "--tries",
        "1",
        "--disable-external-tokens",
        "--key-file",
        key_path,
        "--keyfile-size",
        str(key_size),
    ]
    if test_args:
        command.append("--test-args")
    command.extend((device_path, name))
    return command


def _mkfs_ext4_command(
    mkfs: str, device_path: str, filesystem_uuid: str, *, no_action: bool = False
) -> list[str]:
    command = [mkfs, "-q"]
    if no_action:
        command.append("-n")
    command.extend(
        [
            "-F",
            "-t",
            "ext4",
            "-b",
            str(EXT4_BLOCK_BYTES),
            "-I",
            str(EXT4_INODE_BYTES),
            "-i",
            str(EXT4_BYTES_PER_INODE),
            "-g",
            str(EXT4_BLOCKS_PER_GROUP),
            "-G",
            str(EXT4_FLEX_GROUP_SIZE),
            "-m",
            str(EXT4_RESERVED_PERCENT),
            "-o",
            "linux",
            "-e",
            EXT4_ERRORS,
            "-J",
            f"size={EXT4_JOURNAL_MIB}",
            "-E",
            "lazy_itable_init=0,lazy_journal_init=0",
            "-O",
            (
                "none,has_journal,ext_attr,resize_inode,dir_index,filetype,"
                "extent,64bit,flex_bg,sparse_super,large_file,huge_file,"
                "dir_nlink,extra_isize,metadata_csum"
            ),
            "-L",
            VAULT_LABEL,
            "-U",
            filesystem_uuid,
            "-M",
            "/",
            device_path,
        ]
    )
    return command


def _tune2fs_command(tune2fs: str, device_path: str) -> list[str]:
    return [
        tune2fs,
        "-c",
        "0",
        "-i",
        "0",
        "-e",
        EXT4_ERRORS,
        "-m",
        str(EXT4_RESERVED_PERCENT),
        "-o",
        "^acl,^user_xattr",
        "-M",
        "/",
        device_path,
    ]


def _resolve_preflight_tool(paths: Sequence[str], name: str) -> ToolIdentity:
    selected = v1._fixed_binary(paths, name)
    path = os.path.realpath(selected)
    details = os.stat(path, follow_symlinks=False)
    if (
        not os.path.isabs(path)
        or not stat.S_ISREG(details.st_mode)
        or details.st_uid != 0
        or stat.S_IMODE(details.st_mode) & 0o022
        or not os.access(path, os.X_OK)
    ):
        raise SafetyError(f"required system tool has unsafe ownership: {name}")
    return ToolIdentity(
        name,
        path,
        details.st_dev,
        details.st_ino,
        details.st_size,
        details.st_mode,
        details.st_mtime_ns,
        details.st_uid,
        details.st_gid,
        details.st_ctime_ns,
    )


def bind_preflight_tools() -> Mapping[str, ToolIdentity]:
    """Resolve without spawning, then publish one identity-bound tool set."""

    global _PREFLIGHT_TOOLS
    specs = (
        ("lsblk", LSBLK_PATHS),
        ("losetup", LOSETUP_PATHS),
        ("udevadm", UDEVADM_PATHS),
        ("wipefs", WIPEFS_PATHS),
        ("cryptsetup", CRYPTSETUP_PATHS),
        ("mkfs.ext4", MKFS_EXT4_PATHS),
        ("tune2fs", TUNE2FS_PATHS),
        ("blkid", BLKID_PATHS),
        ("mount", MOUNT_PATHS),
        ("umount", UMOUNT_PATHS),
    )
    if _PREFLIGHT_TOOLS is not None:
        for name, paths in specs:
            _fixed_binary(paths, name)
        return dict(_PREFLIGHT_TOOLS)
    resolved = {
        name: _resolve_preflight_tool(paths, name) for name, paths in specs
    }
    _PREFLIGHT_TOOLS = dict(resolved)
    return resolved


def _preflight_identity_lease_capability() -> None:
    if not hasattr(os, "O_PATH") or not os.path.isdir("/proc/self/fd"):
        raise SafetyError("Linux O_PATH/procfd identity leases are required")
    lease_fd = -1
    data_fd = -1
    try:
        with defer_managed_signals():
            flags = os.O_PATH | os.O_CLOEXEC
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            lease_fd = os.open("/dev/null", flags)
            expected = _block_identity_tuple(os.fstat(lease_fd))
            data_fd = os.open(f"/proc/self/fd/{lease_fd}", os.O_RDONLY | os.O_CLOEXEC)
            if (
                not stat.S_ISCHR(expected[2])
                or _block_identity_tuple(os.fstat(data_fd)) != expected
            ):
                raise SafetyError("O_PATH/procfd identity lease preflight diverged")
    finally:
        if data_fd >= 0:
            os.close(data_fd)
        if lease_fd >= 0:
            os.close(lease_fd)


def _require_tool_version(
    result: CommandResult, product: str, minimum: tuple[int, int, int]
) -> None:
    raw = result.stdout + result.stderr
    text = _strict_text(raw, f"{product} version output")
    match = re.search(
        rf"(?:\A|\n){re.escape(product)}\s+(\d+)\.(\d+)\.(\d+)(?:\s|\Z)",
        text,
    )
    if match is None:
        raise SafetyError(f"{product} version output is not machine-recognizable")
    observed = tuple(int(part) for part in match.groups())
    if observed < minimum:
        required = ".".join(str(part) for part in minimum)
        raise SafetyError(f"{product} {required} or newer is required")


def _preflight_mount_capability(tools: Mapping[str, ToolIdentity]) -> None:
    mountpoint: str | None = None
    mountpoint_details = None
    with defer_managed_signals() as deferred_signal_handler:
        try:
            mountpoint = tempfile.mkdtemp(
                prefix="kernaid-make-device-v2-preflight.", dir="/run"
            )
            initial_mountpoint = os.lstat(mountpoint)
            os.chmod(mountpoint, 0o700)
            mountpoint_details = os.lstat(mountpoint)
            if (
                not stat.S_ISDIR(initial_mountpoint.st_mode)
                or (initial_mountpoint.st_dev, initial_mountpoint.st_ino)
                != (mountpoint_details.st_dev, mountpoint_details.st_ino)
                or not stat.S_ISDIR(mountpoint_details.st_mode)
                or mountpoint_details.st_uid != 0
                or mountpoint_details.st_gid != 0
                or stat.S_IMODE(mountpoint_details.st_mode) != 0o700
            ):
                raise SafetyError("/run cannot provide a safe writer mountpoint")
            run_command(
                [
                    tools["mount"].path,
                    "--fake",
                    "--no-mtab",
                    "--types",
                    "ext4",
                    "--options",
                    "ro,nosuid,nodev,noexec,nosymfollow",
                    "/dev/null",
                    mountpoint,
                ],
                label="hardened mount option capability preflight",
                timeout=10,
                maximum_output=16 * 1024,
                deferred_signal_handler=deferred_signal_handler,
            )
            run_command(
                [
                    tools["umount"].path,
                    "--fake",
                    "--no-mtab",
                    "--",
                    mountpoint,
                ],
                label="umount capability preflight",
                timeout=10,
                maximum_output=16 * 1024,
                deferred_signal_handler=deferred_signal_handler,
            )
            if parse_mountinfo_for_path(mountpoint):
                raise SafetyError("mount preflight unexpectedly changed mount state")
        finally:
            if mountpoint is not None:
                observed = os.lstat(mountpoint)
                if mountpoint_details is None:
                    safe_unowned_transition = (
                        os.path.dirname(mountpoint) == "/run"
                        and re.fullmatch(
                            r"kernaid-make-device-v2-preflight\.[A-Za-z0-9_-]+",
                            os.path.basename(mountpoint),
                        )
                        is not None
                        and stat.S_ISDIR(observed.st_mode)
                        and observed.st_uid == 0
                        and observed.st_gid == 0
                        and stat.S_IMODE(observed.st_mode) == 0o700
                    )
                    if not safe_unowned_transition:
                        raise SafetyError("preflight mountpoint ownership is ambiguous")
                elif (
                    observed.st_dev,
                    observed.st_ino,
                    observed.st_mode,
                    observed.st_uid,
                    observed.st_gid,
                ) != (
                    mountpoint_details.st_dev,
                    mountpoint_details.st_ino,
                    mountpoint_details.st_mode,
                    mountpoint_details.st_uid,
                    mountpoint_details.st_gid,
                ):
                    raise SafetyError("preflight mountpoint identity changed")
                os.rmdir(mountpoint)


def preflight_writer_environment() -> Mapping[str, ToolIdentity]:
    verify_implemented_vault_profile()
    _preflight_identity_lease_capability()
    tools = bind_preflight_tools()

    cryptsetup = tools["cryptsetup"].path
    crypt_version = run_command(
        [cryptsetup, "--version"],
        label="cryptsetup version preflight",
        timeout=10,
        maximum_output=16 * 1024,
    )
    _require_tool_version(crypt_version, "cryptsetup", (2, 6, 0))
    preflight_uuid = "11111111-1111-4111-8111-111111111111"
    run_command(
        _luks_format_command(
            cryptsetup,
            "/proc/self/fd/0",
            MIN_SECRET_BYTES,
            "/dev/null",
            preflight_uuid,
            test_args=True,
        ),
        label="cryptsetup pinned LUKS2 format capability preflight",
        timeout=10,
        maximum_output=16 * 1024,
    )
    run_command(
        _luks_open_command(
            cryptsetup,
            "/proc/self/fd/0",
            MIN_SECRET_BYTES,
            "/dev/null",
            "kernaid-vault-0123456789abcdef",
            test_args=True,
        ),
        label="cryptsetup hardened open capability preflight",
        timeout=10,
        maximum_output=16 * 1024,
    )
    run_command(
        [cryptsetup, "luksDump", "--dump-json-metadata", "--test-args", "/dev/null"],
        label="cryptsetup JSON metadata capability preflight",
        timeout=10,
        maximum_output=16 * 1024,
    )
    preflight_secret = bytearray(b"KernAid profile preflight only")
    try:
        with tempfile.TemporaryFile(
            prefix="kernaid-make-device-v2-luks-preflight.", dir="/var/tmp"
        ) as luks_probe:
            os.ftruncate(luks_probe.fileno(), 128 * 1024 * 1024)
            run_secret_command(
                lambda key_path, key_size: _luks_format_command(
                    cryptsetup,
                    key_path,
                    key_size,
                    f"/proc/self/fd/{luks_probe.fileno()}",
                    preflight_uuid,
                ),
                preflight_secret,
                label="pinned LUKS2 profile capability preflight",
                timeout=FORMAT_TIMEOUT_SECONDS,
                pass_fds=(luks_probe.fileno(),),
            )
            os.fsync(luks_probe.fileno())
            verify_luks_metadata(luks_probe.fileno(), preflight_uuid)
    finally:
        _wipe_bytearray(preflight_secret)

    mkfs = tools["mkfs.ext4"].path
    mkfs_version = run_command(
        [mkfs, "-V"],
        label="mkfs.ext4 version preflight",
        timeout=10,
        maximum_output=16 * 1024,
    )
    _require_tool_version(mkfs_version, "mke2fs", (1, 46, 0))
    probe_capacity = 1024 * 1024 * 1024
    probe_uuid = "22222222-2222-4222-8222-222222222222"
    with tempfile.TemporaryFile(
        prefix="kernaid-make-device-v2-preflight.", dir="/var/tmp"
    ) as probe:
        os.ftruncate(probe.fileno(), probe_capacity)
        run_command(
            _mkfs_ext4_command(
                mkfs,
                f"/proc/self/fd/{probe.fileno()}",
                probe_uuid,
            ),
            label="pinned ext4 profile capability preflight",
            timeout=FORMAT_TIMEOUT_SECONDS,
            pass_fds=(probe.fileno(),),
            maximum_output=256 * 1024,
        )
        tune2fs = tools["tune2fs"].path
        run_command(
            _tune2fs_command(tune2fs, f"/proc/self/fd/{probe.fileno()}"),
            label="tune2fs profile capability preflight",
            timeout=30,
            pass_fds=(probe.fileno(),),
            maximum_output=256 * 1024,
        )
        os.fsync(probe.fileno())
        verify_ext4_superblock(
            probe.fileno(), probe_uuid, capacity_bytes=probe_capacity
        )
        blkid = tools["blkid"].path
        blkid_result = run_command(
            [
                blkid,
                "--probe",
                "--output",
                "export",
                f"/proc/self/fd/{probe.fileno()}",
            ],
            label="blkid export capability preflight",
            timeout=15,
            pass_fds=(probe.fileno(),),
            maximum_output=64 * 1024,
        )
        fields = parse_blkid_export(blkid_result.stdout)
        if (
            fields.get("TYPE") != "ext4"
            or fields.get("UUID") != probe_uuid
            or fields.get("LABEL") != VAULT_LABEL
        ):
            raise SafetyError("blkid cannot verify the pinned ext4 profile")

    kernel_match = re.match(r"(\d+)\.(\d+)", os.uname().release)
    if kernel_match is None or tuple(int(part) for part in kernel_match.groups()) < (5, 10):
        raise SafetyError("Linux 5.10 or newer is required for nosymfollow mounts")
    filesystems = v1._read_bounded("/proc/filesystems", 256 * 1024).splitlines()
    if not any(line.split()[-1:] == ["ext4"] for line in filesystems):
        raise SafetyError("the running kernel does not expose ext4 support")
    _preflight_mount_capability(tools)

    return dict(tools)


def run_lsblk() -> object:
    lsblk = _fixed_binary(LSBLK_PATHS, "lsblk")
    result = run_command(
        [
            lsblk,
            "--json",
            "--bytes",
            "--paths",
            "--list",
            "--output",
            v1.LSBLK_COLUMNS,
        ],
        label="lsblk inventory",
        timeout=15,
        maximum_output=v1.MAX_LSBLK_OUTPUT,
    )
    return v1.Inventory.from_json(_strict_text(result.stdout, "lsblk JSON"))


def parse_udev_properties(raw: bytes, candidate) -> object:
    text = _strict_text(raw, "udevadm properties")
    if len(raw) > v1.MAX_PROBE_OUTPUT:
        raise SafetyError("udevadm property output exceeded the safety limit")
    properties: dict[str, str] = {}
    for line in text.splitlines():
        if not line or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if (
            not re.fullmatch(r"[A-Z0-9_]+", key)
            or v1.CONTROL_RE.search(value)
            or len(value) > 4096
            or key in properties
        ):
            raise SafetyError("udevadm returned malformed or duplicate properties")
        properties[key] = value
    if properties.get("ID_BUS") != "usb":
        raise SafetyError("udev does not identify the target as USB media")
    if properties.get("ID_SERIAL_SHORT") != candidate.serial:
        raise SafetyError("udev serial identity does not match lsblk")
    if not properties.get("ID_PATH"):
        raise SafetyError("udev did not provide a stable physical USB path")
    if properties.get("ID_TYPE") not in (None, "disk"):
        raise SafetyError("udev identifies the target as non-disk USB media")
    if any(properties.get(key) == "1" for key in v1.CARD_READER_PROPERTIES):
        raise SafetyError("USB card readers and removable memory cards are unsupported")
    combined = " ".join((candidate.vendor, candidate.model, properties.get("ID_MODEL", "")))
    if v1.CARD_READER_MODEL_RE.search(combined):
        raise SafetyError("target model appears to be a USB card reader")
    proof_keys = (
        "ID_BUS",
        "ID_TYPE",
        "ID_SERIAL_SHORT",
        "ID_PATH",
        "ID_VENDOR",
        "ID_MODEL",
        *sorted(v1.OPTIONAL_USB_MEDIA_PROPERTIES),
        *sorted(v1.CARD_READER_PROPERTIES),
    )
    return v1.UsbMediaProof(tuple((key, properties.get(key, "")) for key in proof_keys))


def probe_usb_media(candidate) -> object:
    udevadm = _fixed_binary(UDEVADM_PATHS, "udevadm")
    result = run_command(
        [udevadm, "info", "--query=property", f"--name={candidate.path}"],
        label="udevadm USB identity probe",
        timeout=10,
        maximum_output=v1.MAX_PROBE_OUTPUT,
    )
    return parse_udev_properties(result.stdout, candidate)


def verify_ci_loop_partition_scan(candidate) -> str:
    """Require an identity-bound loop with ``LO_FLAGS_PARTSCAN`` enabled.

    A disposable loop is attached before the finalized MBR is copied.  Linux
    will reject ``BLKRRPART`` on a loop that was created without partscan, so
    discovering that capability only after the raw write would unnecessarily
    turn a safe CI refusal into partial media.  This check is intentionally
    loop-only; physical USB media continue to use the ordinary mandatory
    ``BLKRRPART`` path without any fallback.
    """

    if (
        candidate.kind != "loop"
        or not v1.LOOP_PATH_RE.fullmatch(candidate.path)
        or os.path.basename(candidate.kname) != os.path.basename(candidate.path)
        or not v1.MAJ_MIN_RE.fullmatch(candidate.major_minor)
    ):
        raise SafetyError("CI partition-scan capability requires one exact /dev/loopN")
    loop_name = os.path.basename(candidate.path)
    expected_sysfs = f"/sys/devices/virtual/block/{loop_name}"
    major_minor_link = f"/sys/dev/block/{candidate.major_minor}"
    class_link = f"/sys/class/block/{loop_name}"
    resolved = os.path.realpath(major_minor_link)
    if (
        resolved != expected_sysfs
        or os.path.realpath(class_link) != expected_sysfs
        or not os.path.isdir(expected_sysfs)
    ):
        raise SafetyError("CI loop sysfs identity is not exact")

    before = os.stat(candidate.path, follow_symlinks=False)
    observed_major_minor = f"{os.major(before.st_rdev)}:{os.minor(before.st_rdev)}"
    if not stat.S_ISBLK(before.st_mode) or observed_major_minor != candidate.major_minor:
        raise SafetyError("CI loop path no longer matches its major:minor")
    if _read_small_text(
        f"{expected_sysfs}/loop/partscan", "CI loop partition-scan flag"
    ) != "1":
        raise SafetyError(
            "CI loop was not created with the required LO_FLAGS_PARTSCAN capability"
        )

    after = os.stat(candidate.path, follow_symlinks=False)
    if (
        (after.st_dev, after.st_ino, after.st_mode, after.st_rdev)
        != (before.st_dev, before.st_ino, before.st_mode, before.st_rdev)
        or os.path.realpath(major_minor_link) != expected_sysfs
        or os.path.realpath(class_link) != expected_sysfs
    ):
        raise SafetyError("CI loop identity changed during partition-scan validation")
    return expected_sysfs


def inspect_loop_backing(candidate, image) -> object:
    verify_ci_loop_partition_scan(candidate)
    losetup = _fixed_binary(LOSETUP_PATHS, "losetup")
    result = run_command(
        [
            losetup,
            "--json",
            "--list",
            "--output",
            "NAME,BACK-FILE,BACK-INO,BACK-MAJ:MIN,MAJ:MIN",
            candidate.path,
        ],
        label="losetup disposable backing probe",
        timeout=10,
        maximum_output=v1.MAX_PROBE_OUTPUT,
    )
    try:
        document = json.loads(_strict_text(result.stdout, "losetup JSON"))
    except json.JSONDecodeError as error:
        raise SafetyError("losetup did not return valid JSON") from error
    rows = document.get("loopdevices") if isinstance(document, dict) else None
    if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
        raise SafetyError("losetup did not resolve exactly one loop device")
    row = rows[0]
    name = v1._safe_text(row.get("name"), "losetup name", allow_empty=False)
    major_minor = v1._safe_text(row.get("maj:min"), "losetup maj:min", allow_empty=False)
    backing_raw = v1._safe_text(row.get("back-file"), "losetup back-file", allow_empty=False)
    try:
        bound_inode = int(row.get("back-ino"))
    except (TypeError, ValueError) as error:
        raise SafetyError("losetup returned an invalid backing inode") from error
    bound_major_minor = v1._safe_text(
        row.get("back-maj:min"), "losetup back-maj:min", allow_empty=False
    )
    if bound_inode <= 0 or not v1.MAJ_MIN_RE.fullmatch(bound_major_minor):
        raise SafetyError("losetup returned an invalid backing-file identity")
    if os.path.realpath(name) != os.path.realpath(candidate.path):
        raise SafetyError("losetup resolved a different loop device")
    if major_minor != candidate.major_minor:
        raise SafetyError("loop device major:minor changed")
    if not os.path.isabs(backing_raw) or backing_raw.endswith(" (deleted)"):
        raise SafetyError("loop backing file is not a stable absolute path")
    backing = os.path.realpath(backing_raw)
    if backing != backing_raw:
        raise SafetyError("loop backing file must not be a symlink")
    allowed_roots = (os.path.realpath("/tmp"), os.path.realpath("/var/tmp"))
    if not any(v1._is_within(backing, root) for root in allowed_roots):
        raise SafetyError("disposable loop backing file must be under /tmp or /var/tmp")
    if not os.path.basename(backing).startswith("kernaid-disposable-"):
        raise SafetyError("disposable loop backing filename is not reserved for KernAid")
    details = os.lstat(backing)
    file_major_minor = f"{os.major(details.st_dev)}:{os.minor(details.st_dev)}"
    if (
        not stat.S_ISREG(details.st_mode)
        or details.st_ino != bound_inode
        or file_major_minor != bound_major_minor
        or details.st_nlink != 1
        or details.st_uid != os.geteuid()
        or stat.S_IMODE(details.st_mode) & 0o077
        or details.st_size < candidate.size
    ):
        raise SafetyError("disposable loop backing-file identity or permissions changed")
    if (details.st_dev, details.st_ino) == (image.device, image.inode):
        raise SafetyError("ISO source and disposable loop backing are identical")
    verify_ci_loop_partition_scan(candidate)
    return v1.LoopBacking(
        backing,
        details.st_dev,
        details.st_ino,
        details.st_size,
        details.st_uid,
        stat.S_IMODE(details.st_mode),
        details.st_nlink,
    )


def load_installed_trust() -> tuple[object, object]:
    """Load only the installed v2 catalog and its fixed sibling manifest."""

    catalog_path = MODULE_DIRECTORY / CATALOG_FILENAME
    layout_path = MODULE_DIRECTORY / LAYOUT_FILENAME
    try:
        layout = catalog_v2.load_device_layout(layout_path)
        raw = catalog_v2.read_regular_file(
            catalog_path,
            catalog_v2.MAX_CATALOG_BYTES,
            "Rescue trust catalog v2",
        )
        parsed = catalog_v2.parse_trust_catalog_v2(raw.decode("utf-8", "strict"))
    except catalog_v2.CatalogV2Error as error:
        raise SafetyError(str(error)) from error
    except UnicodeDecodeError as error:
        raise SafetyError("Rescue trust catalog v2 is not strict UTF-8") from error
    if not parsed.images:
        raise SafetyError(
            "Rescue trust catalog v2 is inactive: no real two-boot vault evidence is trusted"
        )
    return parsed, layout


def verify_finalized_image_layout(source_fd: int, image, layout) -> None:
    if image.size > layout.vault_partition.start_lba * layout.logical_sector_bytes:
        raise SafetyError("trusted ISO overlaps the reserved vault partition")
    try:
        sector = os.pread(source_fd, 512, 0)
    except OSError as error:
        raise SafetyError(f"cannot inspect trusted ISO MBR: {error}") from error
    if len(sector) != 512 or sector[510:512] != b"\x55\xaa":
        raise SafetyError("trusted ISO has no exact MBR signature")
    entries = [sector[446 + index * 16 : 446 + (index + 1) * 16] for index in range(4)]
    entry = entries[2]
    if len(entry) != 16:
        raise SafetyError("trusted ISO has no complete MBR slot 3")
    status = entry[0]
    type_code = entry[4]
    start_lba = int.from_bytes(entry[8:12], "little")
    sector_count = int.from_bytes(entry[12:16], "little")
    if (
        status != 0
        or type_code != int(layout.vault_partition.mbr_type, 16)
        or start_lba != layout.vault_partition.start_lba
        or sector_count != layout.vault_partition.sector_count
    ):
        raise SafetyError("trusted ISO MBR slot 3 diverges from the authorized layout")
    vault_end_lba = start_lba + sector_count
    for index, other in enumerate(entries):
        if index == 2:
            continue
        other_start = int.from_bytes(other[8:12], "little")
        other_count = int.from_bytes(other[12:16], "little")
        if other_count == 0:
            continue
        other_end = other_start + other_count
        if max(other_start, start_lba) < min(other_end, vault_end_lba):
            raise SafetyError(
                f"trusted ISO MBR slot {index + 1} overlaps reserved vault slot 3"
            )


def validate_v2_candidate(candidate, layout) -> None:
    verify_implemented_vault_profile()
    if (
        layout.vault_profile_version != VAULT_PROFILE_VERSION
        or layout.vault_profile_sha256 != VAULT_PROFILE_SHA256
    ):
        raise SafetyError("device layout does not bind the implemented vault profile")
    if candidate.size < layout.minimum_advertised_media_bytes:
        raise SafetyError(
            "catalog-v2 media must expose at least "
            f"{layout.minimum_advertised_media_bytes} bytes"
        )
    vault_end = (
        layout.vault_partition.start_lba + layout.vault_partition.sector_count
    ) * layout.logical_sector_bytes
    if vault_end != layout.minimum_media_bytes or candidate.size < vault_end:
        raise SafetyError("target capacity does not contain the exact authorized vault layout")


def _wipe_bytearray(value: bytearray) -> None:
    for index in range(len(value)):
        value[index] = 0
    value.clear()


def _read_once_into_buffer(fd: int, *, terminal: bool) -> bytearray:
    buffer = bytearray(MAX_SECRET_BYTES + 3)
    try:
        count = os.readv(fd, (buffer,))
    except OSError as error:
        _wipe_bytearray(buffer)
        raise SafetyError(
            "cannot read the vault passphrase from the protected descriptor"
        ) from error
    if count <= 0:
        _wipe_bytearray(buffer)
        raise SafetyError("vault passphrase was not provided")
    del buffer[count:]
    if terminal:
        if not buffer.endswith(b"\n"):
            _wipe_bytearray(buffer)
            raise SafetyError("vault passphrase exceeded the terminal safety limit")
        while buffer and buffer[-1] in (10, 13):
            buffer[-1] = 0
            del buffer[-1]
    else:
        probe = bytearray(1)
        try:
            extra = os.readv(fd, (probe,))
        except OSError as error:
            _wipe_bytearray(buffer)
            _wipe_bytearray(probe)
            raise SafetyError("cannot verify passphrase descriptor EOF") from error
        _wipe_bytearray(probe)
        if extra != 0:
            _wipe_bytearray(buffer)
            raise SafetyError("vault passphrase exceeded the descriptor safety limit")
    if len(buffer) < MIN_SECRET_BYTES or len(buffer) > MAX_SECRET_BYTES or 0 in buffer:
        _wipe_bytearray(buffer)
        raise SafetyError(
            f"vault passphrase must contain {MIN_SECRET_BYTES}-{MAX_SECRET_BYTES} non-NUL bytes"
        )
    return buffer


def acquire_passphrase_from_tty() -> bytearray:
    flags = os.O_RDWR | os.O_CLOEXEC | getattr(os, "O_NOCTTY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        tty_fd = os.open("/dev/tty", flags)
    except OSError as error:
        raise SafetyError("double passphrase entry requires a controlling TTY") from error
    first = bytearray()
    second = bytearray()
    try:
        details = os.fstat(tty_fd)
        if not stat.S_ISCHR(details.st_mode) or not os.isatty(tty_fd):
            raise SafetyError("/dev/tty is not an interactive character terminal")
        original = termios.tcgetattr(tty_fd)

        def set_attributes(attributes: list[object]) -> None:
            previous_mask = signal.pthread_sigmask(
                signal.SIG_BLOCK, v1.MANAGED_SIGNALS
            )
            try:
                termios.tcsetattr(tty_fd, termios.TCSAFLUSH, attributes)
            finally:
                signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)

        def read_prompt(prompt: bytes) -> bytearray:
            attributes = termios.tcgetattr(tty_fd)
            attributes[3] &= ~termios.ECHO
            try:
                # The no-echo syscall is inside the protected try: even an
                # interruption reported immediately after its side effect
                # reaches the restore path below.
                set_attributes(attributes)
                os.write(tty_fd, prompt)
                return _read_once_into_buffer(tty_fd, terminal=True)
            finally:
                set_attributes(original)
                os.write(tty_fd, b"\n")

        first = read_prompt(b"Vault passphrase: ")
        second = read_prompt(b"Repeat vault passphrase: ")
        if not hmac.compare_digest(first, second):
            raise SafetyError("the two vault passphrase entries did not match")
        return first
    except BaseException:
        _wipe_bytearray(first)
        raise
    finally:
        _wipe_bytearray(second)
        os.close(tty_fd)


def acquire_passphrase_from_ci_fd(fd_number: int) -> bytearray:
    if isinstance(fd_number, bool) or fd_number < 3:
        raise SafetyError("CI passphrase descriptor is invalid")
    try:
        details = os.fstat(fd_number)
    except OSError as error:
        raise SafetyError("CI passphrase descriptor is not open") from error
    if not stat.S_ISFIFO(details.st_mode) or details.st_uid != os.geteuid():
        raise SafetyError("CI passphrase input must be an inherited anonymous pipe")
    try:
        descriptor_target = os.readlink(f"/proc/self/fd/{fd_number}")
    except OSError as error:
        raise SafetyError("cannot bind the CI passphrase pipe identity") from error
    if not re.fullmatch(r"pipe:\[[1-9][0-9]*\]", descriptor_target):
        raise SafetyError("CI passphrase input must not be a named FIFO")
    descriptor_flags = fcntl.fcntl(fd_number, fcntl.F_GETFD)
    if not descriptor_flags & fcntl.FD_CLOEXEC:
        fcntl.fcntl(fd_number, fcntl.F_SETFD, descriptor_flags | fcntl.FD_CLOEXEC)
    return _read_once_into_buffer(fd_number, terminal=False)


def _secret_pipe(secret: bytearray) -> tuple[int, int]:
    flags = getattr(os, "O_CLOEXEC", 0)
    read_fd, write_fd = os.pipe2(flags) if hasattr(os, "pipe2") else os.pipe()
    try:
        total = 0
        view = memoryview(secret)
        while total < len(secret):
            written = os.write(write_fd, view[total:])
            if written <= 0:
                raise WriteError("could not transfer passphrase to a protected pipe")
            total += written
        return read_fd, write_fd
    except BaseException:
        os.close(read_fd)
        os.close(write_fd)
        raise


def run_secret_command(
    build_argv,
    secret: bytearray,
    *,
    label: str,
    timeout: int = COMMAND_TIMEOUT_SECONDS,
    allowed_returncodes: Iterable[int] = (0,),
    pass_fds: Sequence[int] = (),
) -> CommandResult:
    read_fd, write_fd = _secret_pipe(secret)
    try:
        os.close(write_fd)
        write_fd = -1
        argv = build_argv(f"/proc/self/fd/{read_fd}", len(secret))
        return run_command(
            argv,
            label=label,
            timeout=timeout,
            pass_fds=tuple(pass_fds) + (read_fd,),
            allowed_returncodes=allowed_returncodes,
        )
    finally:
        if write_fd >= 0:
            os.close(write_fd)
        os.close(read_fd)


def _revalidate_target_fd(
    target_fd: int, candidate, *, logical_sector_bytes: int | None = None
) -> None:
    details = os.fstat(target_fd)
    actual_major_minor = f"{os.major(details.st_rdev)}:{os.minor(details.st_rdev)}"
    if not stat.S_ISBLK(details.st_mode) or actual_major_minor != candidate.major_minor:
        raise SafetyError("whole-device descriptor identity changed")
    if v1._ioctl_value(target_fd, v1.BLKGETSIZE64, "=Q", "BLKGETSIZE64") != candidate.size:
        raise SafetyError("whole-device descriptor capacity changed")
    if v1._ioctl_value(target_fd, v1.BLKROGET, "=I", "BLKROGET") != 0:
        raise SafetyError("whole-device descriptor became read-only")
    if (
        v1._ioctl_value(target_fd, v1.BLKGETDISKSEQ, "=Q", "BLKGETDISKSEQ")
        != candidate.disk_sequence
    ):
        raise SafetyError("whole-device descriptor disk sequence changed")
    if (
        logical_sector_bytes is not None
        and v1._ioctl_value(target_fd, v1.BLKSSZGET, "=I", "BLKSSZGET")
        != logical_sector_bytes
    ):
        raise SafetyError("whole-device logical sector size diverges from the manifest")
    path_details = os.stat(candidate.path, follow_symlinks=False)
    if (
        not stat.S_ISBLK(path_details.st_mode)
        or path_details.st_rdev != details.st_rdev
        or path_details.st_ino != details.st_ino
        or path_details.st_dev != details.st_dev
    ):
        raise SafetyError("whole-device path no longer names the held descriptor")


def _block_identity_tuple(details) -> tuple[int, int, int, int]:
    return (details.st_dev, details.st_ino, details.st_mode, details.st_rdev)


def _close_owned_descriptors(descriptors: Sequence[int], label: str) -> None:
    owned = [descriptor for descriptor in descriptors if descriptor >= 0]
    errors: list[str] = []
    if len(owned) != len(set(owned)):
        errors.append("descriptor ownership is duplicated")
    unique_owned = list(dict.fromkeys(owned))
    with defer_managed_signals():
        for descriptor in unique_owned:
            try:
                os.close(descriptor)
            except OSError as error:
                errors.append(f"fd {descriptor}: {error}")
    if errors:
        raise WriteError(f"{label} descriptor cleanup failed ({'; '.join(errors)})")


def _verify_block_identity_lease(
    lease_fd: int,
    path: str,
    major_minor: str,
    label: str,
    *,
    expected: tuple[int, int, int, int] | None = None,
) -> tuple[int, int, int, int]:
    if lease_fd < 0 or not os.path.isabs(path) or not v1.MAJ_MIN_RE.fullmatch(major_minor):
        raise SafetyError(f"{label} identity lease is incomplete")
    held = os.fstat(lease_fd)
    named = os.stat(path, follow_symlinks=False)
    identity = _block_identity_tuple(held)
    descriptor_flags = fcntl.fcntl(lease_fd, fcntl.F_GETFL)
    if (
        not hasattr(os, "O_PATH")
        or descriptor_flags & os.O_PATH != os.O_PATH
        or not stat.S_ISBLK(held.st_mode)
        or identity != _block_identity_tuple(named)
        or f"{os.major(held.st_rdev)}:{os.minor(held.st_rdev)}" != major_minor
        or (expected is not None and identity != expected)
        or os.path.realpath(f"/proc/self/fd/{lease_fd}") != path
    ):
        raise SafetyError(f"{label} identity lease/path changed")
    return identity


def _open_block_identity_lease_from_data_fd(
    data_fd: int, path: str, major_minor: str, label: str
) -> int:
    if not hasattr(os, "O_PATH"):
        raise SafetyError("Linux O_PATH identity leases are unavailable")
    baseline = os.fstat(data_fd)
    expected = _block_identity_tuple(baseline)
    if (
        not stat.S_ISBLK(baseline.st_mode)
        or f"{os.major(baseline.st_rdev)}:{os.minor(baseline.st_rdev)}"
        != major_minor
    ):
        raise SafetyError(f"{label} data descriptor identity is invalid")
    flags = os.O_PATH | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    lease_fd = os.open(path, flags)
    try:
        _verify_block_identity_lease(
            lease_fd, path, major_minor, label, expected=expected
        )
        return lease_fd
    except BaseException:
        os.close(lease_fd)
        raise


def _open_data_fd_from_block_lease(
    lease_fd: int,
    path: str,
    major_minor: str,
    label: str,
    *,
    writable: bool,
) -> int:
    """Open one short-lived data FD while preserving lease identity exactly."""

    data_fd = -1
    try:
        with defer_managed_signals():
            expected = _verify_block_identity_lease(
                lease_fd, path, major_minor, label
            )
            # /proc/self/fd/N is a kernel-owned link to the already validated
            # O_PATH lease.  O_NOFOLLOW would reject that intentional link.
            flags = (os.O_RDWR if writable else os.O_RDONLY) | os.O_CLOEXEC
            data_fd = os.open(f"/proc/self/fd/{lease_fd}", flags)
            observed = os.fstat(data_fd)
            observed_flags = fcntl.fcntl(data_fd, fcntl.F_GETFL)
            expected_access = os.O_RDWR if writable else os.O_RDONLY
            if (
                _block_identity_tuple(observed) != expected
                or observed_flags & getattr(os, "O_PATH", 0)
                or observed_flags & os.O_ACCMODE != expected_access
            ):
                raise SafetyError(f"{label} data descriptor diverged from its lease")
            _verify_block_identity_lease(
                lease_fd, path, major_minor, label, expected=expected
            )
        return data_fd
    except BaseException:
        if data_fd >= 0:
            os.close(data_fd)
        raise


def _verify_partition_leases(
    target_lease_fd: int,
    partition_lease_fd: int,
    partition: PartitionIdentity,
    candidate,
    layout,
) -> None:
    target_data_fd = _open_data_fd_from_block_lease(
        target_lease_fd,
        candidate.path,
        candidate.major_minor,
        "whole-device",
        writable=False,
    )
    try:
        partition_data_fd = _open_data_fd_from_block_lease(
            partition_lease_fd,
            partition.path,
            partition.major_minor,
            "vault partition",
            writable=False,
        )
        try:
            verify_partition_fd(
                partition_data_fd,
                partition,
                target_data_fd,
                candidate,
                layout,
            )
        finally:
            os.close(partition_data_fd)
    finally:
        os.close(target_data_fd)


def handoff_partition_to_identity_leases(
    target_fd: int,
    partition_fd: int,
    partition: PartitionIdentity,
    candidate,
    layout,
) -> tuple[int, int]:
    """Consume exclusive/data descriptors and return non-claiming O_PATH leases."""

    owned_target_fd = target_fd
    owned_partition_fd = partition_fd
    target_lease_fd = -1
    partition_lease_fd = -1
    try:
        with defer_managed_signals():
            verify_partition_fd(
                owned_partition_fd,
                partition,
                owned_target_fd,
                candidate,
                layout,
            )
            target_lease_fd = _open_block_identity_lease_from_data_fd(
                owned_target_fd,
                candidate.path,
                candidate.major_minor,
                "whole-device",
            )
            partition_lease_fd = _open_block_identity_lease_from_data_fd(
                owned_partition_fd,
                partition.path,
                partition.major_minor,
                "vault partition",
            )
            closing_partition_fd = owned_partition_fd
            owned_partition_fd = -1
            os.close(closing_partition_fd)
            closing_target_fd = owned_target_fd
            owned_target_fd = -1
            os.close(closing_target_fd)
            _verify_partition_leases(
                target_lease_fd,
                partition_lease_fd,
                partition,
                candidate,
                layout,
            )
        return target_lease_fd, partition_lease_fd
    except BaseException:
        cleanup_descriptors = (
            owned_partition_fd,
            owned_target_fd,
            partition_lease_fd,
            target_lease_fd,
        )
        owned_partition_fd = -1
        owned_target_fd = -1
        partition_lease_fd = -1
        target_lease_fd = -1
        _close_owned_descriptors(cleanup_descriptors, "block handoff")
        raise


def _reject_tail_signatures(target_fd: int, candidate, image) -> None:
    wipefs = _fixed_binary(WIPEFS_PATHS, "wipefs")
    descriptor_path = f"/proc/self/fd/{target_fd}"
    result = run_command(
        [
            wipefs,
            "--json",
            "--no-act",
            "--lock=no",
            "--output",
            "OFFSET,LENGTH,TYPE",
            descriptor_path,
        ],
        label="wipefs whole-device tail probe",
        timeout=15,
        pass_fds=(target_fd,),
        maximum_output=v1.MAX_PROBE_OUTPUT,
    )
    try:
        document = json.loads(_strict_text(result.stdout, "wipefs JSON"))
    except json.JSONDecodeError as error:
        raise SafetyError("wipefs did not return valid JSON") from error
    signatures = document.get("signatures") if isinstance(document, dict) else None
    if not isinstance(signatures, list):
        raise SafetyError("wipefs JSON is missing signatures")
    for value in signatures:
        signature = v1._exact_object(value, {"offset", "length", "type"}, "wipefs signature")
        offset = v1._parse_wipefs_offset(signature["offset"], "offset")
        length = v1._parse_wipefs_offset(signature["length"], "length")
        signature_type = v1._catalog_text(signature["type"], "wipefs signature type")
        if length <= 0 or offset + length > candidate.size:
            raise SafetyError("wipefs reported an out-of-range signature")
        if offset >= image.size or offset + length > image.size:
            raise SafetyError(
                f"recognized {signature_type} signature conflicts with the preserved tail"
            )


def write_and_verify_prefix(
    source_fd: int,
    image,
    candidate,
    target_fd: int,
    state: OperationState,
    layout,
) -> str:
    v1._assert_image_unchanged(source_fd, image)
    _revalidate_target_fd(
        target_fd,
        candidate,
        logical_sector_bytes=layout.logical_sector_bytes,
    )
    _reject_tail_signatures(target_fd, candidate, image)
    v1._reject_stale_tail_metadata(target_fd, candidate, image)
    if not hmac.compare_digest(v1._sha256_fd(source_fd, image.size), image.sha256):
        raise SafetyError("ISO checksum changed immediately before the write")
    deadline = time.monotonic() + COPY_TIMEOUT_SECONDS
    offset = 0
    while offset < image.size:
        if time.monotonic() >= deadline:
            raise WriteError("raw image write exceeded its deadline")
        amount = min(COPY_CHUNK_BYTES, image.size - offset)
        chunk = os.pread(source_fd, amount, offset)
        if len(chunk) != amount:
            raise WriteError(f"ISO ended during raw write at byte {offset}")
        written = 0
        while written < amount:
            if not state.target_overwritten_or_partial:
                state.advance(WritePhase.WRITE_MAY_HAVE_STARTED, candidate.path)
            count = os.pwrite(target_fd, chunk[written:], offset + written)
            if count <= 0:
                raise WriteError(f"short device write at byte {offset + written}")
            written += count
        offset += amount
    state.advance(WritePhase.DD_COMPLETED, candidate.path)
    os.fsync(target_fd)
    os.sync()
    fcntl.ioctl(target_fd, v1.BLKFLSBUF)
    state.advance(WritePhase.CACHE_FLUSHED, candidate.path)

    source_digest = hashlib.sha256()
    target_digest = hashlib.sha256()
    deadline = time.monotonic() + COPY_TIMEOUT_SECONDS
    offset = 0
    while offset < image.size:
        if time.monotonic() >= deadline:
            raise WriteError("raw image verification exceeded its deadline")
        amount = min(COPY_CHUNK_BYTES, image.size - offset)
        source = os.pread(source_fd, amount, offset)
        target = os.pread(target_fd, amount, offset)
        if len(source) != amount or len(target) != amount:
            raise WriteError(f"short read during raw verification at byte {offset}")
        if not hmac.compare_digest(source, target):
            raise WriteError(f"byte verification failed at byte {offset}")
        source_digest.update(source)
        target_digest.update(target)
        offset += amount
    if not hmac.compare_digest(source_digest.hexdigest(), image.sha256):
        raise WriteError("ISO source changed during raw verification")
    verified = target_digest.hexdigest()
    if not hmac.compare_digest(verified, image.sha256):
        raise WriteError("written ISO prefix digest is not exact")
    state.advance(WritePhase.PREFIX_VERIFIED, candidate.path)
    return verified


def _read_small_text(path: str, label: str) -> str:
    raw = v1._read_bounded(path, MAX_SYSFS_BYTES).strip()
    if not raw or v1.CONTROL_RE.search(raw):
        raise SafetyError(f"{label} is empty or malformed")
    return raw


def _strict_positive(value: str, label: str, *, allow_zero: bool = False) -> int:
    if not value.isascii() or not value.isdigit():
        raise SafetyError(f"{label} is not a decimal integer")
    parsed = int(value)
    if parsed < (0 if allow_zero else 1):
        raise SafetyError(f"{label} is outside the accepted range")
    return parsed


def _parse_uevent(path: str) -> dict[str, str]:
    raw = v1._read_bounded(path, MAX_SYSFS_BYTES)
    values: dict[str, str] = {}
    for line in raw.splitlines():
        if "=" not in line:
            raise SafetyError("partition uevent contains a malformed line")
        key, value = line.split("=", 1)
        if not re.fullmatch(r"[A-Z0-9_]+", key) or key in values or v1.CONTROL_RE.search(value):
            raise SafetyError("partition uevent contains unsafe fields")
        values[key] = value
    return values


def _rescan_partition_table(
    target_fd: int,
    candidate,
    *,
    ci_mode: bool,
    logical_sector_bytes: int | None = None,
) -> None:
    _revalidate_target_fd(
        target_fd, candidate, logical_sector_bytes=logical_sector_bytes
    )
    if ci_mode:
        verify_ci_loop_partition_scan(candidate)
    try:
        fcntl.ioctl(target_fd, BLKRRPART)
    except OSError as error:
        raise WriteError(
            f"kernel refused the exact partition-table rescan: {error}"
        ) from error
    _revalidate_target_fd(
        target_fd, candidate, logical_sector_bytes=logical_sector_bytes
    )


def discover_partition(
    target_fd: int, candidate, layout, *, ci_mode: bool = False
) -> tuple[int, PartitionIdentity]:
    _revalidate_target_fd(
        target_fd,
        candidate,
        logical_sector_bytes=layout.logical_sector_bytes,
    )
    _rescan_partition_table(
        target_fd,
        candidate,
        ci_mode=ci_mode,
        logical_sector_bytes=layout.logical_sector_bytes,
    )
    udevadm = _fixed_binary(UDEVADM_PATHS, "udevadm")
    run_command(
        [udevadm, "settle", "--timeout=20"],
        label="udev partition settle",
        timeout=25,
    )
    _revalidate_target_fd(
        target_fd,
        candidate,
        logical_sector_bytes=layout.logical_sector_bytes,
    )

    parent_link = f"/sys/dev/block/{candidate.major_minor}"
    parent_sysfs = os.path.realpath(parent_link)
    if not parent_sysfs.startswith("/sys/devices/") or not os.path.isdir(parent_sysfs):
        raise SafetyError("whole-device sysfs identity is unsafe")
    matches: list[tuple[str, str]] = []
    with os.scandir(parent_sysfs) as entries:
        for count, entry in enumerate(entries, start=1):
            if count > 256:
                raise SafetyError("whole-device sysfs child set is unbounded")
            partition_file = os.path.join(parent_sysfs, entry.name, "partition")
            try:
                number = _read_small_text(partition_file, "partition number")
            except (FileNotFoundError, SafetyError):
                continue
            if _strict_positive(number, "partition number") == layout.vault_partition.number:
                matches.append((entry.name, os.path.join(parent_sysfs, entry.name)))
    if len(matches) != 1:
        raise SafetyError("kernel did not expose exactly one authorized partition 3")
    sysfs_name, sysfs_path = matches[0]
    if not SAFE_SYSFS_NAME_RE.fullmatch(sysfs_name) or os.path.realpath(sysfs_path) != sysfs_path:
        raise SafetyError("partition sysfs identity is unsafe")
    start_lba = _strict_positive(
        _read_small_text(f"{sysfs_path}/start", "partition start"),
        "partition start",
    )
    sector_count = _strict_positive(
        _read_small_text(f"{sysfs_path}/size", "partition size"),
        "partition size",
    )
    major_minor = _read_small_text(f"{sysfs_path}/dev", "partition major:minor")
    if not v1.MAJ_MIN_RE.fullmatch(major_minor):
        raise SafetyError("partition sysfs major:minor is invalid")
    uevent = _parse_uevent(f"{sysfs_path}/uevent")
    devname = uevent.get("DEVNAME", "")
    if (
        uevent.get("DEVTYPE") != "partition"
        or uevent.get("PARTN") != str(layout.vault_partition.number)
        or not devname
        or devname.startswith("/")
        or any(component in ("", ".", "..") for component in devname.split("/"))
        or any(not SAFE_SYSFS_NAME_RE.fullmatch(component) for component in devname.split("/"))
    ):
        raise SafetyError("partition uevent identity is incomplete or unsafe")
    path = os.path.normpath(f"/dev/{devname}")
    if not path.startswith("/dev/"):
        raise SafetyError("partition node escaped /dev")
    flags = os.O_RDWR | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        partition_fd = os.open(path, flags)
    except OSError as error:
        raise WriteError(f"cannot open the exact vault partition node: {error}") from error
    try:
        details = os.fstat(partition_fd)
        actual_major_minor = f"{os.major(details.st_rdev)}:{os.minor(details.st_rdev)}"
        size = v1._ioctl_value(partition_fd, v1.BLKGETSIZE64, "=Q", "partition BLKGETSIZE64")
        identity = PartitionIdentity(
            path=path,
            major_minor=major_minor,
            parent_major_minor=candidate.major_minor,
            start_lba=start_lba,
            sector_count=sector_count,
            size=size,
            node_device=details.st_dev,
            node_inode=details.st_ino,
            node_rdev=details.st_rdev,
            sysfs_path=sysfs_path,
        )
        verify_partition_fd(partition_fd, identity, target_fd, candidate, layout)
        return partition_fd, identity
    except BaseException:
        os.close(partition_fd)
        raise


def verify_partition_fd(
    partition_fd: int,
    identity: PartitionIdentity,
    target_fd: int,
    candidate,
    layout,
) -> None:
    _revalidate_target_fd(
        target_fd,
        candidate,
        logical_sector_bytes=layout.logical_sector_bytes,
    )
    details = os.fstat(partition_fd)
    named = os.stat(identity.path, follow_symlinks=False)
    if (
        not stat.S_ISBLK(details.st_mode)
        or (details.st_dev, details.st_ino, details.st_rdev)
        != (identity.node_device, identity.node_inode, identity.node_rdev)
        or (named.st_dev, named.st_ino, named.st_rdev)
        != (identity.node_device, identity.node_inode, identity.node_rdev)
    ):
        raise SafetyError("vault partition descriptor/path identity changed")
    if f"{os.major(details.st_rdev)}:{os.minor(details.st_rdev)}" != identity.major_minor:
        raise SafetyError("vault partition major:minor changed")
    expected_bytes = layout.vault_partition.sector_count * layout.logical_sector_bytes
    if (
        identity.parent_major_minor != candidate.major_minor
        or identity.start_lba != layout.vault_partition.start_lba
        or identity.sector_count != layout.vault_partition.sector_count
        or identity.size != expected_bytes
        or v1._ioctl_value(
            partition_fd, v1.BLKGETSIZE64, "=Q", "partition BLKGETSIZE64"
        )
        != expected_bytes
        or v1._ioctl_value(partition_fd, v1.BLKROGET, "=I", "partition BLKROGET") != 0
        or v1._ioctl_value(
            partition_fd, v1.BLKSSZGET, "=I", "partition BLKSSZGET"
        )
        != layout.logical_sector_bytes
    ):
        raise SafetyError("vault partition geometry diverged from the manifest")
    if os.path.realpath(f"/sys/dev/block/{identity.major_minor}") != identity.sysfs_path:
        raise SafetyError("vault partition sysfs link changed")
    if os.path.dirname(identity.sysfs_path) != os.path.realpath(
        f"/sys/dev/block/{candidate.major_minor}"
    ):
        raise SafetyError("vault partition parent changed")
    if (
        _strict_positive(
            _read_small_text(
                f"{identity.sysfs_path}/partition", "partition number"
            ),
            "partition number",
        )
        != layout.vault_partition.number
    ):
        raise SafetyError("vault partition number changed")
    if (
        _strict_positive(
            _read_small_text(f"{identity.sysfs_path}/start", "partition start"),
            "partition start",
        )
        != identity.start_lba
    ):
        raise SafetyError("vault partition start changed")
    if (
        _strict_positive(
            _read_small_text(f"{identity.sysfs_path}/size", "partition size"),
            "partition size",
        )
        != identity.sector_count
    ):
        raise SafetyError("vault partition size changed")


def reject_partition_signature(partition_fd: int) -> None:
    wipefs = _fixed_binary(WIPEFS_PATHS, "wipefs")
    result = run_command(
        [
            wipefs,
            "--json",
            "--no-act",
            "--lock=no",
            "--output",
            "OFFSET,LENGTH,TYPE",
            f"/proc/self/fd/{partition_fd}",
        ],
        label="wipefs vault-partition probe",
        timeout=15,
        pass_fds=(partition_fd,),
        maximum_output=v1.MAX_PROBE_OUTPUT,
    )
    try:
        document = json.loads(_strict_text(result.stdout, "wipefs partition JSON"))
    except json.JSONDecodeError as error:
        raise SafetyError("wipefs partition probe returned invalid JSON") from error
    signatures = document.get("signatures") if isinstance(document, dict) else None
    if not isinstance(signatures, list):
        raise SafetyError("wipefs partition JSON is missing signatures")
    if signatures:
        raise SafetyError("vault partition contains a conflicting recognized tail signature")


def parse_blkid_export(raw: bytes) -> dict[str, str]:
    text = _strict_text(raw, "blkid export")
    values: dict[str, str] = {}
    for line in text.splitlines():
        if not line or "=" not in line:
            raise SafetyError("blkid export contains a malformed line")
        key, value = line.split("=", 1)
        if (
            not re.fullmatch(r"[A-Z][A-Z0-9_]*", key)
            or key in values
            or not value
            or len(value) > 4096
            or v1.CONTROL_RE.search(value)
        ):
            raise SafetyError("blkid export contains unsafe or duplicate fields")
        values[key] = value
    if not values:
        raise SafetyError("blkid export is empty")
    return values


def probe_blkid(fd: int, label: str) -> dict[str, str]:
    blkid = _fixed_binary(BLKID_PATHS, "blkid")
    result = run_command(
        [blkid, "--probe", "--output", "export", f"/proc/self/fd/{fd}"],
        label=label,
        timeout=15,
        pass_fds=(fd,),
    )
    return parse_blkid_export(result.stdout)


def _exact_luks_object(value: object, fields: set[str], label: str) -> dict[str, object]:
    try:
        return v1._exact_object(value, fields, label)
    except SafetyError as error:
        raise WriteError(f"{label} structure is not exact") from error


def _luks_integer(value: object, expected: int, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value != expected:
        raise WriteError(f"LUKS2 {label} is not the pinned value")


def _luks_text(value: object, expected: str, label: str) -> None:
    if not isinstance(value, str) or value != expected:
        raise WriteError(f"LUKS2 {label} is not the pinned value")


def _require_base64_32(value: object, label: str) -> None:
    if not isinstance(value, str) or len(value) != 44:
        raise WriteError(f"LUKS2 {label} is not canonical base64")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error) as error:
        raise WriteError(f"LUKS2 {label} is not canonical base64") from error
    if len(decoded) != 32 or base64.b64encode(decoded).decode("ascii") != value:
        raise WriteError(f"LUKS2 {label} is not canonical base64")


def _reject_luks_duplicate_keys(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    document: dict[str, object] = {}
    for key, value in pairs:
        if key in document:
            raise WriteError(f"LUKS2 JSON metadata repeats key {key!r}")
        document[key] = value
    return document


def parse_luks_json_metadata(raw: bytes) -> object:
    if not raw or len(raw) > 256 * 1024:
        raise WriteError("cryptsetup returned unbounded LUKS2 JSON metadata")
    try:
        return json.loads(
            _strict_text(raw, "LUKS2 JSON metadata"),
            object_pairs_hook=_reject_luks_duplicate_keys,
        )
    except (json.JSONDecodeError, WriteError) as error:
        if isinstance(error, WriteError):
            raise
        raise WriteError("cryptsetup returned invalid LUKS2 JSON metadata") from error


def verify_luks_json_document(document: object) -> None:
    verify_implemented_vault_profile()
    root = _exact_luks_object(
        document,
        {"keyslots", "tokens", "segments", "digests", "config"},
        "LUKS2 metadata",
    )
    keyslots = _exact_luks_object(root["keyslots"], {"0"}, "LUKS2 keyslots")
    keyslot = _exact_luks_object(
        keyslots["0"], {"type", "key_size", "af", "area", "kdf"}, "LUKS2 keyslot 0"
    )
    _luks_text(keyslot["type"], "luks2", "keyslot type")
    _luks_integer(keyslot["key_size"], LUKS_KEY_BITS // 8, "keyslot key size")
    af = _exact_luks_object(keyslot["af"], {"type", "stripes", "hash"}, "LUKS2 AF")
    _luks_text(af["type"], "luks1", "AF type")
    _luks_integer(af["stripes"], LUKS_AF_STRIPES, "AF stripes")
    _luks_text(af["hash"], LUKS_AF_HASH, "AF hash")
    area = _exact_luks_object(
        keyslot["area"], {"type", "offset", "size", "encryption", "key_size"}, "LUKS2 keyslot area"
    )
    _luks_text(area["type"], "raw", "keyslot area type")
    _luks_text(
        area["offset"], str(LUKS_KEYSLOT_AREA_OFFSET_BYTES), "keyslot area offset"
    )
    _luks_text(area["size"], str(LUKS_KEYSLOT_AREA_BYTES), "keyslot area size")
    _luks_text(area["encryption"], LUKS_CIPHER, "keyslot area cipher")
    _luks_integer(area["key_size"], LUKS_KEY_BITS // 8, "keyslot area key size")
    kdf = _exact_luks_object(
        keyslot["kdf"], {"type", "time", "memory", "cpus", "salt"}, "LUKS2 KDF"
    )
    _luks_text(kdf["type"], LUKS_PBKDF, "KDF type")
    _luks_integer(kdf["time"], LUKS_PBKDF_TIME, "KDF time")
    _luks_integer(kdf["memory"], LUKS_PBKDF_MEMORY_KIB, "KDF memory")
    _luks_integer(kdf["cpus"], LUKS_PBKDF_CPUS, "KDF CPUs")
    _require_base64_32(kdf["salt"], "KDF salt")
    _exact_luks_object(root["tokens"], set(), "LUKS2 tokens")
    segments = _exact_luks_object(root["segments"], {"0"}, "LUKS2 segments")
    segment = _exact_luks_object(
        segments["0"],
        {"type", "offset", "size", "iv_tweak", "encryption", "sector_size"},
        "LUKS2 segment 0",
    )
    _luks_text(segment["type"], "crypt", "segment type")
    _luks_text(segment["offset"], str(LUKS_DATA_OFFSET_BYTES), "segment offset")
    _luks_text(segment["size"], "dynamic", "segment size")
    _luks_text(segment["iv_tweak"], "0", "segment IV tweak")
    _luks_text(segment["encryption"], LUKS_CIPHER, "segment cipher")
    _luks_integer(segment["sector_size"], LUKS_SECTOR_BYTES, "segment sector size")
    digests = _exact_luks_object(root["digests"], {"0"}, "LUKS2 digests")
    digest = _exact_luks_object(
        digests["0"],
        {"type", "keyslots", "segments", "hash", "iterations", "salt", "digest"},
        "LUKS2 digest 0",
    )
    _luks_text(digest["type"], "pbkdf2", "digest type")
    if digest["keyslots"] != ["0"] or digest["segments"] != ["0"]:
        raise WriteError("LUKS2 digest binding is not exact")
    _luks_text(digest["hash"], LUKS_DIGEST_HASH, "digest hash")
    _luks_integer(
        digest["iterations"], LUKS_DIGEST_ITERATIONS, "digest iterations"
    )
    _require_base64_32(digest["salt"], "digest salt")
    _require_base64_32(digest["digest"], "digest value")
    config = _exact_luks_object(
        root["config"], {"json_size", "keyslots_size"}, "LUKS2 config"
    )
    _luks_text(config["json_size"], str(LUKS_METADATA_BYTES - 4096), "JSON size")
    _luks_text(config["keyslots_size"], str(LUKS_KEYSLOTS_BYTES), "keyslots size")


def verify_luks_json_profile(partition_fd: int) -> None:
    cryptsetup = _fixed_binary(CRYPTSETUP_PATHS, "cryptsetup")
    result = run_command(
        [
            cryptsetup,
            "luksDump",
            "--dump-json-metadata",
            f"/proc/self/fd/{partition_fd}",
        ],
        label="cryptsetup LUKS2 JSON profile probe",
        timeout=15,
        pass_fds=(partition_fd,),
        maximum_output=256 * 1024,
    )
    verify_luks_json_document(parse_luks_json_metadata(result.stdout))


def verify_luks_metadata(partition_fd: int, expected_uuid: str) -> None:
    fields = probe_blkid(partition_fd, "blkid LUKS2 metadata probe")
    if (
        fields.get("TYPE") != "crypto_LUKS"
        or fields.get("VERSION") != "2"
        or fields.get("LABEL") != VAULT_LABEL
        or fields.get("UUID") != expected_uuid
    ):
        raise WriteError("LUKS2 type, label, version, or UUID is not exact")
    cryptsetup = _fixed_binary(CRYPTSETUP_PATHS, "cryptsetup")
    run_command(
        [cryptsetup, "isLuks", "--type", "luks2", f"/proc/self/fd/{partition_fd}"],
        label="cryptsetup LUKS2 verification",
        timeout=15,
        pass_fds=(partition_fd,),
    )
    verify_luks_json_profile(partition_fd)


def _random_bytes(size: int) -> bytearray:
    if size <= 0:
        raise ValueError("random byte count must be positive")
    output = bytearray(size)
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open("/dev/urandom", flags)
    try:
        offset = 0
        while offset < size:
            count = os.readv(fd, (memoryview(output)[offset:],))
            if count <= 0:
                raise WriteError("kernel random source ended unexpectedly")
            offset += count
        return output
    except BaseException:
        _wipe_bytearray(output)
        raise
    finally:
        os.close(fd)


def _random_mapper_name() -> str:
    random = _random_bytes(8)
    try:
        return "kernaid-vault-" + "".join(f"{byte:02x}" for byte in random)
    finally:
        _wipe_bytearray(random)


def _sysfs_mapper_by_name(name: str) -> list[str]:
    previous: list[str] | None = None
    for _attempt in range(2):
        matches: list[str] = []
        with os.scandir("/sys/class/block") as entries:
            for count, entry in enumerate(entries, start=1):
                if count > 4096:
                    raise SafetyError("sysfs block class is unbounded")
                if not entry.name.startswith("dm-"):
                    continue
                try:
                    observed = _read_small_text(
                        f"/sys/class/block/{entry.name}/dm/name",
                        "device-mapper name",
                    )
                except SafetyError as error:
                    # Only an entry which genuinely vanished between scandir
                    # and open is retryable.  Permission, malformed content or
                    # I/O errors can never be interpreted as mapper absence.
                    if isinstance(error.__cause__, FileNotFoundError):
                        continue
                    raise
                if observed == name:
                    matches.append(entry.name)
        matches.sort()
        if previous is not None and matches == previous:
            return matches
        previous = matches
        time.sleep(0.01)
    raise SafetyError("device-mapper sysfs identity did not stabilize")


def require_mapper_absent(name: str) -> None:
    if not MAPPER_NAME_RE.fullmatch(name):
        raise SafetyError("generated mapper name is invalid")
    alias = f"/dev/mapper/{name}"
    try:
        os.lstat(alias)
    except FileNotFoundError:
        pass
    else:
        raise SafetyError("generated mapper alias already exists")
    if _sysfs_mapper_by_name(name):
        raise SafetyError("generated mapper name already exists in sysfs")


def capture_mapper(
    name: str,
    partition: PartitionIdentity,
    luks_uuid: str,
    *,
    require_alias: bool = True,
) -> tuple[int, MapperIdentity]:
    if not MAPPER_NAME_RE.fullmatch(name):
        raise SafetyError("mapper name is invalid")
    alias = f"/dev/mapper/{name}"
    matches = _sysfs_mapper_by_name(name)
    if len(matches) != 1:
        raise SafetyError("mapper sysfs identity is ambiguous")
    node_path = f"/dev/{matches[0]}"
    try:
        alias_details = os.lstat(alias)
    except FileNotFoundError:
        if require_alias:
            raise SafetyError("mapper alias is missing") from None
    else:
        if (
            not stat.S_ISLNK(alias_details.st_mode)
            or os.path.realpath(alias) != node_path
        ):
            raise SafetyError("mapper alias/sysfs identity is ambiguous")
    flags = os.O_RDWR | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    mapper_fd = os.open(node_path, flags)
    try:
        details = os.fstat(mapper_fd)
        if not stat.S_ISBLK(details.st_mode):
            raise SafetyError("mapper node is not a block device")
        major_minor = f"{os.major(details.st_rdev)}:{os.minor(details.st_rdev)}"
        sysfs_path = os.path.realpath(f"/sys/dev/block/{major_minor}")
        if sysfs_path != os.path.realpath(f"/sys/class/block/{matches[0]}"):
            raise SafetyError("mapper sysfs link is inconsistent")
        observed_name = _read_small_text(f"{sysfs_path}/dm/name", "device-mapper name")
        dm_uuid = _read_small_text(f"{sysfs_path}/dm/uuid", "device-mapper UUID")
        normalized_uuid = luks_uuid.replace("-", "")
        if (
            observed_name != name
            or not dm_uuid.startswith(f"CRYPT-LUKS2-{normalized_uuid}-")
        ):
            raise SafetyError("mapper is not bound to the expected LUKS2 UUID")
        slaves_path = f"{sysfs_path}/slaves"
        slaves: list[str] = []
        with os.scandir(slaves_path) as entries:
            for count, entry in enumerate(entries, start=1):
                if count > 2:
                    raise SafetyError("mapper has multiple backing devices")
                slave_sysfs = os.path.realpath(f"{slaves_path}/{entry.name}")
                slave_mm = _read_small_text(f"{slave_sysfs}/dev", "mapper slave major:minor")
                slaves.append(slave_mm)
        if slaves != [partition.major_minor]:
            raise SafetyError("mapper is not backed by the exact vault partition")
        size = v1._ioctl_value(mapper_fd, v1.BLKGETSIZE64, "=Q", "mapper BLKGETSIZE64")
        expected_size = partition.size - LUKS_DATA_OFFSET_BYTES
        if expected_size <= 0 or size != expected_size:
            raise SafetyError("mapper payload size is not the exact profile size")
        identity = MapperIdentity(
            name=name,
            alias_path=alias,
            node_path=node_path,
            major_minor=major_minor,
            backing_major_minor=partition.major_minor,
            size=size,
            node_device=details.st_dev,
            node_inode=details.st_ino,
            node_rdev=details.st_rdev,
            dm_uuid=dm_uuid,
        )
        verify_mapper_fd(
            mapper_fd,
            identity,
            partition,
            luks_uuid,
            require_alias=require_alias,
        )
        return mapper_fd, identity
    except BaseException:
        os.close(mapper_fd)
        raise


def verify_mapper_fd(
    mapper_fd: int,
    identity: MapperIdentity,
    partition: PartitionIdentity,
    luks_uuid: str,
    *,
    require_alias: bool = True,
) -> None:
    details = os.fstat(mapper_fd)
    named = os.stat(identity.node_path, follow_symlinks=False)
    try:
        alias = os.lstat(identity.alias_path)
    except FileNotFoundError:
        if require_alias:
            raise SafetyError("mapper alias disappeared") from None
        alias = None
    if (
        not stat.S_ISBLK(details.st_mode)
        or (
            alias is not None
            and (
                not stat.S_ISLNK(alias.st_mode)
                or os.path.realpath(identity.alias_path) != identity.node_path
            )
        )
        or (details.st_dev, details.st_ino, details.st_rdev)
        != (identity.node_device, identity.node_inode, identity.node_rdev)
        or (named.st_dev, named.st_ino, named.st_rdev)
        != (identity.node_device, identity.node_inode, identity.node_rdev)
        or f"{os.major(details.st_rdev)}:{os.minor(details.st_rdev)}" != identity.major_minor
        or identity.backing_major_minor != partition.major_minor
        or identity.size != partition.size - LUKS_DATA_OFFSET_BYTES
        or v1._ioctl_value(
            mapper_fd, v1.BLKGETSIZE64, "=Q", "mapper BLKGETSIZE64"
        )
        != identity.size
    ):
        raise SafetyError("mapper descriptor/path identity changed")
    sysfs = os.path.realpath(f"/sys/dev/block/{identity.major_minor}")
    if _read_small_text(f"{sysfs}/dm/name", "device-mapper name") != identity.name:
        raise SafetyError("mapper sysfs name changed")
    dm_uuid = _read_small_text(f"{sysfs}/dm/uuid", "device-mapper UUID")
    if dm_uuid != identity.dm_uuid or not dm_uuid.startswith(
        f"CRYPT-LUKS2-{luks_uuid.replace('-', '')}-"
    ):
        raise SafetyError("mapper LUKS UUID identity changed")
    with os.scandir(f"{sysfs}/slaves") as entries:
        slaves = [
            _read_small_text(
                f"{os.path.realpath(f'{sysfs}/slaves/{entry.name}')}/dev",
                "mapper slave major:minor",
            )
            for entry in entries
        ]
    if slaves != [partition.major_minor]:
        raise SafetyError("mapper backing device changed")


def verify_mapper_lease(
    mapper_lease_fd: int,
    identity: MapperIdentity,
    partition: PartitionIdentity,
    luks_uuid: str,
    *,
    require_alias: bool = True,
) -> None:
    mapper_data_fd = _open_data_fd_from_block_lease(
        mapper_lease_fd,
        identity.node_path,
        identity.major_minor,
        "vault mapper",
        writable=False,
    )
    try:
        verify_mapper_fd(
            mapper_data_fd,
            identity,
            partition,
            luks_uuid,
            require_alias=require_alias,
        )
    finally:
        os.close(mapper_data_fd)


def _capture_lifecycle_mapper(
    lifecycle: VaultLifecycle,
    name: str,
    partition: PartitionIdentity,
    luks_uuid: str,
    *,
    require_alias: bool,
) -> MapperIdentity:
    if lifecycle.mapper is not None or lifecycle.mapper_lease_fd >= 0:
        raise WriteError("vault lifecycle already owns a mapper")
    if lifecycle.pending_mapper_name != name:
        raise WriteError("vault mapper recovery name is not lifecycle-bound")
    previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, v1.MANAGED_SIGNALS)
    mapper_data_fd = -1
    mapper_lease_fd = -1
    try:
        mapper_data_fd, mapper = capture_mapper(
            name,
            partition,
            luks_uuid,
            require_alias=require_alias,
        )
        mapper_lease_fd = _open_block_identity_lease_from_data_fd(
            mapper_data_fd,
            mapper.node_path,
            mapper.major_minor,
            "vault mapper",
        )
        closing_mapper_data_fd = mapper_data_fd
        mapper_data_fd = -1
        os.close(closing_mapper_data_fd)
        lifecycle.mapper_lease_fd = mapper_lease_fd
        mapper_lease_fd = -1
        lifecycle.mapper = mapper
    finally:
        if mapper_data_fd >= 0:
            os.close(mapper_data_fd)
        if mapper_lease_fd >= 0:
            os.close(mapper_lease_fd)
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
    return mapper


def _register_pending_mapper(lifecycle: VaultLifecycle, name: str) -> None:
    if (
        lifecycle.mapper is not None
        or lifecycle.mapper_lease_fd >= 0
        or lifecycle.pending_mapper_name is not None
    ):
        raise WriteError("vault lifecycle already owns a mapper transition")
    previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, v1.MANAGED_SIGNALS)
    try:
        lifecycle.pending_mapper_name = name
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)


def _clear_pending_mapper(lifecycle: VaultLifecycle) -> None:
    previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, v1.MANAGED_SIGNALS)
    try:
        lifecycle.pending_mapper_name = None
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)


def _release_lifecycle_mapper_lease(lifecycle: VaultLifecycle) -> None:
    if lifecycle.mapper_lease_fd < 0:
        return
    previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, v1.MANAGED_SIGNALS)
    try:
        mapper_lease_fd = lifecycle.mapper_lease_fd
        lifecycle.mapper_lease_fd = -1
        os.close(mapper_lease_fd)
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)


def _acquire_existing_mapper_for_cleanup(
    lifecycle: VaultLifecycle,
    name: str,
    partition: PartitionIdentity,
    luks_uuid: str,
    *,
    deferred_signal_handler: object | None = None,
) -> bool:
    if lifecycle.mapper is not None:
        return True
    if not _sysfs_mapper_by_name(name) and not os.path.lexists(f"/dev/mapper/{name}"):
        return False
    udevadm = _fixed_binary(UDEVADM_PATHS, "udevadm")
    try:
        run_command(
            [udevadm, "settle", "--timeout=5"],
            label="udev mapper recovery settle",
            timeout=10,
            deferred_signal_handler=deferred_signal_handler,
        )
    except BaseException:
        # The direct dm node and sysfs claims below are authoritative for
        # cleanup; a failed alias settle must not strand an exact mapping.
        pass
    deadline = time.monotonic() + 5
    last_error: BaseException | None = None
    while time.monotonic() < deadline:
        try:
            _capture_lifecycle_mapper(
                lifecycle,
                name,
                partition,
                luks_uuid,
                require_alias=False,
            )
            return True
        except BaseException as error:
            if lifecycle.mapper is not None and lifecycle.mapper_lease_fd >= 0:
                return True
            last_error = error
            time.sleep(0.05)
    raise WriteError("could not acquire the exact mapper for cleanup") from last_error


def verify_ext4_superblock(
    mapper_fd: int, expected_uuid: str, *, capacity_bytes: int | None = None
) -> None:
    superblock = os.pread(mapper_fd, 1024, 1024)
    if len(superblock) != 1024:
        raise WriteError("ext4 superblock could not be read exactly")

    def u16(offset: int) -> int:
        return struct.unpack_from("<H", superblock, offset)[0]

    def u32(offset: int) -> int:
        return struct.unpack_from("<I", superblock, offset)[0]

    log_block_size = u32(0x18)
    log_cluster_size = u32(0x1C)
    if log_block_size > 6 or log_cluster_size > 6:
        raise WriteError("ext4 block geometry is outside the bounded profile")
    block_size = 1024 << log_block_size
    cluster_size = 1024 << log_cluster_size
    expected_label = VAULT_LABEL.encode("ascii").ljust(16, b"\x00")
    try:
        expected_uuid_bytes = uuid.UUID(expected_uuid).bytes
    except ValueError as error:
        raise WriteError("expected ext4 UUID is invalid") from error
    blocks_count = u32(0x04) | (u32(0x150) << 32)
    inodes_count = u32(0x00)
    inodes_per_group = u32(0x28)
    reserved_blocks = u32(0x08) | (u32(0x154) << 32)
    if capacity_bytes is None:
        capacity_bytes = v1._ioctl_value(
            mapper_fd, v1.BLKGETSIZE64, "=Q", "ext4 backing BLKGETSIZE64"
        )
    if (
        u16(0x38) != 0xEF53
        or u32(0x4C) != 1
        or u32(0x48) != 0
        or u16(0x3A) != 1
        or u16(0x3C) != (2 if EXT4_ERRORS == "remount-ro" else -1)
        or u16(0x36) != 0xFFFF
        or u32(0x44) != 0
        or u32(0x54) != 11
        or u16(0x58) != EXT4_INODE_BYTES
        or block_size != EXT4_BLOCK_BYTES
        or cluster_size != EXT4_BLOCK_BYTES
        or u32(0x20) != EXT4_BLOCKS_PER_GROUP
        or u32(0x24) != EXT4_BLOCKS_PER_GROUP
        or reserved_blocks != 0
        or u32(0x5C) != EXT4_COMPAT_FEATURES
        or u32(0x60) != EXT4_INCOMPAT_FEATURES
        or u32(0x64) != EXT4_RO_COMPAT_FEATURES
        or superblock[0x68:0x78] != expected_uuid_bytes
        or superblock[0x78:0x88] != expected_label
        or u32(0xE0) != 8
        or superblock[0xFD] != 1
        or u32(0x14C) != EXT4_JOURNAL_MIB * 1024 * 1024
        or u16(0xFE) != 64
        or u32(0x100) != (0 if EXT4_DEFAULT_MOUNT_OPTIONS == "none" else -1)
        or superblock[0x174] != EXT4_FLEX_GROUP_LOG
        or blocks_count <= 0
        or blocks_count * EXT4_BLOCK_BYTES != capacity_bytes
        or inodes_count <= 0
        or inodes_count * EXT4_BYTES_PER_INODE != capacity_bytes
        or inodes_per_group <= 0
        or inodes_per_group
        * ((blocks_count + EXT4_BLOCKS_PER_GROUP - 1) // EXT4_BLOCKS_PER_GROUP)
        != inodes_count
    ):
        raise WriteError("ext4 binary superblock profile is not exact")


def verify_filesystem(
    mapper_lease_fd: int,
    mapper: MapperIdentity,
    partition: PartitionIdentity,
    luks_uuid: str,
    expected_uuid: str,
) -> None:
    verify_mapper_lease(mapper_lease_fd, mapper, partition, luks_uuid)
    fields = probe_blkid(mapper_lease_fd, "blkid ext4 metadata probe")
    if (
        fields.get("TYPE") != "ext4"
        or fields.get("LABEL") != VAULT_LABEL
        or fields.get("UUID") != expected_uuid
    ):
        raise WriteError("ext4 type, label, or UUID is not exact")
    if fields.get("BLOCK_SIZE") not in (None, str(EXT4_BLOCK_BYTES)) or fields.get(
        "FSBLOCKSIZE"
    ) not in (None, str(EXT4_BLOCK_BYTES)):
        raise WriteError("ext4 blkid block-size profile is not exact")
    mapper_data_fd = _open_data_fd_from_block_lease(
        mapper_lease_fd,
        mapper.node_path,
        mapper.major_minor,
        "vault mapper",
        writable=False,
    )
    try:
        verify_ext4_superblock(
            mapper_data_fd, expected_uuid, capacity_bytes=mapper.size
        )
    finally:
        os.close(mapper_data_fd)
    verify_mapper_lease(mapper_lease_fd, mapper, partition, luks_uuid)


def parse_mountinfo_for_path(path: str) -> list[tuple[str, str, frozenset[str], frozenset[str]]]:
    raw = v1._read_bounded("/proc/self/mountinfo", v1.MAX_PROC_OUTPUT)
    matches: list[tuple[str, str, frozenset[str], frozenset[str]]] = []
    for line in raw.splitlines():
        fields = line.split()
        if len(fields) < 10 or "-" not in fields:
            raise SafetyError("mountinfo contains a malformed record")
        separator = fields.index("-")
        if separator + 3 >= len(fields):
            raise SafetyError("mountinfo separator is malformed")
        mountpoint = os.path.normpath(v1._unescape_mountinfo(fields[4]))
        if mountpoint != path:
            continue
        major_minor = fields[2]
        filesystem = fields[separator + 1]
        mount_options = frozenset(fields[5].split(","))
        super_options = frozenset(fields[separator + 3].split(","))
        matches.append((major_minor, filesystem, mount_options, super_options))
    return matches


def verify_mount(mountpoint: str, mapper: MapperIdentity, *, read_only: bool) -> None:
    matches = parse_mountinfo_for_path(mountpoint)
    if len(matches) != 1:
        raise SafetyError("vault mountpoint is missing or ambiguous")
    major_minor, filesystem, mount_options, super_options = matches[0]
    required = {"nosuid", "nodev", "noexec", "nosymfollow"}
    required.add("ro" if read_only else "rw")
    if (
        major_minor != mapper.major_minor
        or filesystem != "ext4"
        or not required.issubset(mount_options)
        or (not read_only and "errors=remount-ro" not in super_options)
    ):
        raise SafetyError("vault mount does not match the hardened exact policy")
    details = os.lstat(mountpoint)
    if not stat.S_ISDIR(details.st_mode) or details.st_uid != 0 or details.st_gid != 0:
        raise SafetyError("vault mountpoint ownership or type is unsafe")


def _write_exact_file(directory_fd: int, name: str, contents: bytearray | bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(name, flags, 0o600, dir_fd=directory_fd)
    try:
        view = memoryview(contents)
        offset = 0
        while offset < len(contents):
            count = os.write(fd, view[offset:])
            if count <= 0:
                raise WriteError(f"vault layout file {name} was not written completely")
            offset += count
        os.fsync(fd)
        details = os.fstat(fd)
        if (
            not stat.S_ISREG(details.st_mode)
            or stat.S_IMODE(details.st_mode) != 0o600
            or details.st_uid != 0
            or details.st_gid != 0
            or details.st_nlink != 1
            or details.st_size != len(contents)
        ):
            raise WriteError(f"vault layout file {name} has unsafe metadata")
    finally:
        os.close(fd)


def _base64url_encode(value: bytearray) -> bytearray:
    output = bytearray()
    for offset in range(0, len(value), 3):
        remaining = len(value) - offset
        first = value[offset]
        second = value[offset + 1] if remaining > 1 else 0
        third = value[offset + 2] if remaining > 2 else 0
        combined = (first << 16) | (second << 8) | third
        output.append(BASE64URL_ALPHABET[(combined >> 18) & 63])
        output.append(BASE64URL_ALPHABET[(combined >> 12) & 63])
        if remaining > 1:
            output.append(BASE64URL_ALPHABET[(combined >> 6) & 63])
        if remaining > 2:
            output.append(BASE64URL_ALPHABET[combined & 63])
    return output


def _bind_mount_root_fd(
    root_fd: int,
    mountpoint: str,
    mapper: MapperIdentity,
    *,
    read_only: bool,
):
    initial = os.fstat(root_fd)
    observed_major_minor = f"{os.major(initial.st_dev)}:{os.minor(initial.st_dev)}"
    if (
        not stat.S_ISDIR(initial.st_mode)
        or initial.st_uid != 0
        or initial.st_gid != 0
        or observed_major_minor != mapper.major_minor
    ):
        raise WriteError("vault root FD is not bound to the exact mapper filesystem")
    verify_mount(mountpoint, mapper, read_only=read_only)
    final = os.fstat(root_fd)
    if (
        final.st_dev,
        final.st_ino,
        final.st_mode,
        final.st_uid,
        final.st_gid,
    ) != (
        initial.st_dev,
        initial.st_ino,
        initial.st_mode,
        initial.st_uid,
        initial.st_gid,
    ):
        raise WriteError("vault root FD identity changed during mount binding")
    return final


def create_vault_layout(mountpoint: str, mapper: MapperIdentity) -> VaultEvidence:
    verify_mount(mountpoint, mapper, read_only=False)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    root_fd = os.open(mountpoint, flags)
    seed = bytearray()
    encoded = bytearray()
    envelope = bytearray()
    try:
        _bind_mount_root_fd(root_fd, mountpoint, mapper, read_only=False)
        os.fchmod(root_fd, 0o700)
        root_details = os.fstat(root_fd)
        if (
            not stat.S_ISDIR(root_details.st_mode)
            or f"{os.major(root_details.st_dev)}:{os.minor(root_details.st_dev)}"
            != mapper.major_minor
            or root_details.st_uid != 0
            or root_details.st_gid != 0
            or stat.S_IMODE(root_details.st_mode) != 0o700
        ):
            raise WriteError("vault filesystem root ownership or mode is unsafe")
        existing = sorted(os.listdir(root_fd))
        if existing not in ([], ["lost+found"]):
            raise WriteError("new ext4 vault contains unexpected pre-existing objects")
        if existing == ["lost+found"]:
            lost = os.stat("lost+found", dir_fd=root_fd, follow_symlinks=False)
            if not stat.S_ISDIR(lost.st_mode) or lost.st_uid != 0 or lost.st_gid != 0:
                raise WriteError("ext4 lost+found metadata is unsafe")
        _write_exact_file(root_fd, VAULT_MARKER_NAME, VAULT_MARKER)
        _write_exact_file(root_fd, VAULT_LOCK_NAME, b"")
        os.mkdir(STATE_DIRECTORY, 0o700, dir_fd=root_fd)
        state_fd = os.open(STATE_DIRECTORY, flags, dir_fd=root_fd)
        try:
            state_details = os.fstat(state_fd)
            if (
                not stat.S_ISDIR(state_details.st_mode)
                or f"{os.major(state_details.st_dev)}:{os.minor(state_details.st_dev)}"
                != mapper.major_minor
                or state_details.st_uid != 0
                or state_details.st_gid != 0
                or stat.S_IMODE(state_details.st_mode) != 0o700
            ):
                raise WriteError("secure-state directory metadata is unsafe")
            seed = _random_bytes(IDENTITY_SEED_BYTES)
            encoded = _base64url_encode(seed)
            envelope.extend(IDENTITY_PREFIX)
            envelope.extend(encoded)
            envelope.extend(b"\n")
            _write_exact_file(state_fd, IDENTITY_NAME, envelope)
            os.fsync(state_fd)
        finally:
            os.close(state_fd)
        os.fsync(root_fd)
        marker_sha = hashlib.sha256(VAULT_MARKER).hexdigest()
        identity_sha = hashlib.sha256(envelope).hexdigest()
        return VaultEvidence("", "", marker_sha, identity_sha)
    finally:
        _wipe_bytearray(seed)
        _wipe_bytearray(encoded)
        _wipe_bytearray(envelope)
        os.close(root_fd)


def _verify_regular_at(
    directory_fd: int, name: str, expected_sha: str, expected_size: int
) -> None:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(name, flags, dir_fd=directory_fd)
    try:
        details = os.fstat(fd)
        if (
            not stat.S_ISREG(details.st_mode)
            or stat.S_IMODE(details.st_mode) != 0o600
            or details.st_uid != 0
            or details.st_gid != 0
            or details.st_nlink != 1
            or details.st_size != expected_size
        ):
            raise WriteError(f"vault layout file {name} metadata changed")
        digest = hashlib.sha256()
        remaining = expected_size
        while remaining:
            chunk = os.read(fd, remaining)
            if not chunk:
                raise WriteError(f"vault layout file {name} ended early")
            digest.update(chunk)
            remaining -= len(chunk)
        if os.read(fd, 1) or not hmac.compare_digest(digest.hexdigest(), expected_sha):
            raise WriteError(f"vault layout file {name} content changed")
    finally:
        os.close(fd)


def verify_vault_layout(mountpoint: str, mapper: MapperIdentity, evidence: VaultEvidence) -> None:
    verify_mount(mountpoint, mapper, read_only=True)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    root_fd = os.open(mountpoint, flags)
    try:
        root = _bind_mount_root_fd(root_fd, mountpoint, mapper, read_only=True)
        if (
            root.st_uid != 0
            or root.st_gid != 0
            or stat.S_IMODE(root.st_mode) != 0o700
        ):
            raise WriteError("vault root metadata changed after reopen")
        expected_root = {VAULT_MARKER_NAME, VAULT_LOCK_NAME, STATE_DIRECTORY}
        entries = set(os.listdir(root_fd))
        entries.discard("lost+found")
        if entries != expected_root:
            raise WriteError("vault root layout changed after reopen")
        _verify_regular_at(root_fd, VAULT_MARKER_NAME, evidence.marker_sha256, len(VAULT_MARKER))
        _verify_regular_at(root_fd, VAULT_LOCK_NAME, hashlib.sha256(b"").hexdigest(), 0)
        state_fd = os.open(STATE_DIRECTORY, flags, dir_fd=root_fd)
        try:
            state = os.fstat(state_fd)
            if (
                not stat.S_ISDIR(state.st_mode)
                or f"{os.major(state.st_dev)}:{os.minor(state.st_dev)}"
                != mapper.major_minor
                or state.st_uid != 0
                or state.st_gid != 0
                or stat.S_IMODE(state.st_mode) != 0o700
            ):
                raise WriteError("secure-state directory metadata changed")
            if set(os.listdir(state_fd)) != {IDENTITY_NAME}:
                raise WriteError("secure-state directory contains an unexpected object")
            identity_size = len(IDENTITY_PREFIX) + 43 + 1
            _verify_regular_at(state_fd, IDENTITY_NAME, evidence.identity_sha256, identity_size)
        finally:
            os.close(state_fd)
    finally:
        os.close(root_fd)


def _mount_mapper(
    mapper_lease_fd: int,
    mapper: MapperIdentity,
    lifecycle: VaultLifecycle,
    *,
    read_only: bool,
) -> str:
    if lifecycle.mountpoint is not None:
        raise WriteError("vault lifecycle already owns a mount")
    previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, v1.MANAGED_SIGNALS)
    mountpoint: str | None = None
    try:
        mountpoint = tempfile.mkdtemp(prefix="kernaid-make-device-v2.", dir="/run")
        os.chmod(mountpoint, 0o700)
        mountpoint_details = os.lstat(mountpoint)
        if (
            not stat.S_ISDIR(mountpoint_details.st_mode)
            or mountpoint_details.st_uid != 0
            or mountpoint_details.st_gid != 0
            or stat.S_IMODE(mountpoint_details.st_mode) != 0o700
        ):
            raise WriteError("temporary vault mountpoint metadata is unsafe")
        lifecycle.mountpoint = mountpoint
        lifecycle.mount_major_minor = mapper.major_minor
        lifecycle.mountpoint_device = mountpoint_details.st_dev
        lifecycle.mountpoint_inode = mountpoint_details.st_ino
    except BaseException:
        if mountpoint is not None and lifecycle.mountpoint is None:
            try:
                os.rmdir(mountpoint)
            except OSError:
                pass
        raise
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
    assert mountpoint is not None
    options = "ro,nosuid,nodev,noexec,nosymfollow" if read_only else (
        "rw,nosuid,nodev,noexec,nosymfollow,relatime,errors=remount-ro"
    )
    mount = _fixed_binary(MOUNT_PATHS, "mount")
    try:
        run_command(
            [
                mount,
                "--types",
                "ext4",
                "--options",
                options,
                f"/proc/self/fd/{mapper_lease_fd}",
                mountpoint,
            ],
            label="hardened ext4 vault mount",
            timeout=30,
            pass_fds=(mapper_lease_fd,),
        )
        verify_mount(mountpoint, mapper, read_only=read_only)
        return mountpoint
    except BaseException:
        # Ownership was recorded before the mutating command, so the common
        # cleanup path can reconcile both "mount never happened" and "mount
        # happened but the runner was interrupted" without guessing.
        raise


def _remove_owned_mountpoint(lifecycle: VaultLifecycle) -> None:
    mountpoint = lifecycle.mountpoint
    if (
        mountpoint is None
        or lifecycle.mountpoint_device is None
        or lifecycle.mountpoint_inode is None
    ):
        raise WriteError("vault mount lifecycle identity is incomplete")
    try:
        details = os.lstat(mountpoint)
    except FileNotFoundError:
        return
    if (
        not stat.S_ISDIR(details.st_mode)
        or details.st_uid != 0
        or details.st_gid != 0
        or stat.S_IMODE(details.st_mode) != 0o700
        or (details.st_dev, details.st_ino)
        != (lifecycle.mountpoint_device, lifecycle.mountpoint_inode)
    ):
        raise WriteError("temporary vault mountpoint identity changed")
    os.rmdir(mountpoint)


def _clear_mount_lifecycle(lifecycle: VaultLifecycle) -> None:
    lifecycle.mountpoint = None
    lifecycle.mount_major_minor = None
    lifecycle.mountpoint_device = None
    lifecycle.mountpoint_inode = None


def _unmount(
    lifecycle: VaultLifecycle, *, deferred_signal_handler: object | None = None
) -> None:
    mountpoint = lifecycle.mountpoint
    if mountpoint is None:
        return
    if (
        lifecycle.mount_major_minor is None
        or lifecycle.mountpoint_device is None
        or lifecycle.mountpoint_inode is None
    ):
        raise WriteError("vault mount lifecycle identity is incomplete")
    matches = parse_mountinfo_for_path(mountpoint)
    if len(matches) > 1 or (
        len(matches) == 1 and matches[0][0] != lifecycle.mount_major_minor
    ):
        raise WriteError("cannot safely identify the vault mount during cleanup")
    original_error: BaseException | None = None
    if matches:
        umount = _fixed_binary(UMOUNT_PATHS, "umount")
        try:
            run_command(
                [umount, "--", mountpoint],
                label="vault unmount",
                timeout=30,
                deferred_signal_handler=deferred_signal_handler,
            )
        except BaseException as error:
            original_error = error

    # Reconciliation is signal-atomic.  Zero mountinfo rows are an idempotent
    # success only when the exact root-owned directory we created is still
    # present (or has already been removed by an earlier interrupted cleanup).
    previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, v1.MANAGED_SIGNALS)
    try:
        remaining = parse_mountinfo_for_path(mountpoint)
        if remaining:
            if original_error is not None:
                raise original_error
            raise WriteError("vault mount remained active after unmount")
        _remove_owned_mountpoint(lifecycle)
        _clear_mount_lifecycle(lifecycle)
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
    if original_error is not None:
        raise original_error


def _close_mapper(
    lifecycle: VaultLifecycle,
    partition: PartitionIdentity,
    luks_uuid: str,
    *,
    deferred_signal_handler: object | None = None,
) -> None:
    mapper = lifecycle.mapper
    if mapper is None:
        _release_lifecycle_mapper_lease(lifecycle)
        pending_name = lifecycle.pending_mapper_name
        if pending_name is None:
            return
        alias_exists = os.path.lexists(f"/dev/mapper/{pending_name}")
        sysfs_matches = _sysfs_mapper_by_name(pending_name)
        if not alias_exists and not sysfs_matches:
            _clear_pending_mapper(lifecycle)
            return
        _acquire_existing_mapper_for_cleanup(
            lifecycle,
            pending_name,
            partition,
            luks_uuid,
            deferred_signal_handler=deferred_signal_handler,
        )
        mapper = lifecycle.mapper
        if mapper is None:
            raise WriteError("vault mapper recovery did not acquire ownership")
    if lifecycle.mountpoint is not None:
        raise WriteError("refusing to close a mapper while its vault is mounted")
    _release_lifecycle_mapper_lease(lifecycle)
    alias_exists = os.path.lexists(mapper.alias_path)
    sysfs_matches = _sysfs_mapper_by_name(mapper.name)
    if not alias_exists and not sysfs_matches:
        lifecycle.mapper = None
        _clear_pending_mapper(lifecycle)
        return
    # Re-capture through sysfs before issuing a state-changing close.  The
    # descriptor used by earlier operations is intentionally closed first.
    previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, v1.MANAGED_SIGNALS)
    probe_fd = -1
    try:
        probe_fd, observed = capture_mapper(
            mapper.name,
            partition,
            luks_uuid,
            require_alias=False,
        )
        os.close(probe_fd)
        probe_fd = -1
    finally:
        if probe_fd >= 0:
            os.close(probe_fd)
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
    if observed != mapper:
        raise WriteError("mapper identity changed before cleanup")
    cryptsetup = _fixed_binary(CRYPTSETUP_PATHS, "cryptsetup")
    original_error: BaseException | None = None
    try:
        run_command(
            [cryptsetup, "close", mapper.name],
            label="cryptsetup mapper close",
            timeout=30,
            deferred_signal_handler=deferred_signal_handler,
        )
    except BaseException as error:
        original_error = error
    mapping_exists = os.path.lexists(mapper.alias_path) or bool(
        _sysfs_mapper_by_name(mapper.name)
    )
    if mapping_exists:
        if original_error is not None:
            raise original_error
        raise WriteError("vault mapper remained active after close")
    lifecycle.mapper = None
    _clear_pending_mapper(lifecycle)
    if original_error is not None:
        raise original_error


def cleanup_lifecycle(
    lifecycle: VaultLifecycle,
    partition: PartitionIdentity,
    luks_uuid: str,
    *,
    deferred_signal_handler: object | None = None,
) -> None:
    errors: list[str] = []
    try:
        _unmount(
            lifecycle, deferred_signal_handler=deferred_signal_handler
        )
    except BaseException as error:
        errors.append(f"unmount: {error}")
    try:
        _close_mapper(
            lifecycle,
            partition,
            luks_uuid,
            deferred_signal_handler=deferred_signal_handler,
        )
    except BaseException as error:
        errors.append(f"mapper close: {error}")
    if errors:
        raise WriteError("vault cleanup incomplete (" + "; ".join(errors) + ")")


def _cleanup_lifecycle_with_signals_deferred(
    lifecycle: VaultLifecycle, partition: PartitionIdentity, luks_uuid: str
) -> None:
    with defer_managed_signals() as deferred_signal_handler:
        cleanup_lifecycle(
            lifecycle,
            partition,
            luks_uuid,
            deferred_signal_handler=deferred_signal_handler,
        )


def _open_mapper(
    partition_lease_fd: int,
    partition: PartitionIdentity,
    luks_uuid: str,
    passphrase: bytearray,
    name: str,
    lifecycle: VaultLifecycle,
) -> tuple[int, MapperIdentity]:
    require_mapper_absent(name)
    _register_pending_mapper(lifecycle, name)
    cryptsetup = _fixed_binary(CRYPTSETUP_PATHS, "cryptsetup")
    run_secret_command(
        lambda key_path, key_size: _luks_open_command(
            cryptsetup,
            key_path,
            key_size,
            f"/proc/self/fd/{partition_lease_fd}",
            name,
        ),
        passphrase,
        label="cryptsetup LUKS2 open",
        timeout=FORMAT_TIMEOUT_SECONDS,
        pass_fds=(partition_lease_fd,),
    )
    udevadm = _fixed_binary(UDEVADM_PATHS, "udevadm")
    run_command(
        [udevadm, "settle", "--timeout=20"],
        label="udev mapper settle",
        timeout=25,
    )
    mapper = _capture_lifecycle_mapper(
        lifecycle,
        name,
        partition,
        luks_uuid,
        require_alias=True,
    )
    return lifecycle.mapper_lease_fd, mapper


def _verify_wrong_key_rejected(
    partition_lease_fd: int,
    partition: PartitionIdentity,
    luks_uuid: str,
) -> None:
    wrong = _random_bytes(32)
    name = _random_mapper_name()
    lifecycle = VaultLifecycle()
    cryptsetup = _fixed_binary(CRYPTSETUP_PATHS, "cryptsetup")
    original_error: BaseException | None = None
    try:
        require_mapper_absent(name)
        _register_pending_mapper(lifecycle, name)
        try:
            result = run_secret_command(
                lambda key_path, key_size: _luks_open_command(
                    cryptsetup,
                    key_path,
                    key_size,
                    f"/proc/self/fd/{partition_lease_fd}",
                    name,
                ),
                wrong,
                label="cryptsetup wrong-key rejection probe",
                timeout=FORMAT_TIMEOUT_SECONDS,
                allowed_returncodes=(0, 2),
                pass_fds=(partition_lease_fd,),
            )
        except BaseException as error:
            original_error = error
            result = None
        mapping_exists = bool(_sysfs_mapper_by_name(name)) or os.path.lexists(
            f"/dev/mapper/{name}"
        )
        if mapping_exists:
            raise WriteError("wrong-key probe left a mapper active")
        if original_error is not None:
            raise original_error
        assert result is not None
        if result.returncode == 0:
            raise WriteError("LUKS2 unexpectedly accepted an incorrect passphrase")
        if result.returncode != 2:
            raise WriteError("cryptsetup returned an ambiguous wrong-key status")
        _clear_pending_mapper(lifecycle)
    finally:
        _wipe_bytearray(wrong)
        if lifecycle.mapper is not None or lifecycle.pending_mapper_name is not None:
            _cleanup_lifecycle_with_signals_deferred(
                lifecycle, partition, luks_uuid
            )


def provision_vault(
    target_lease_fd: int,
    candidate,
    partition_lease_fd: int,
    partition: PartitionIdentity,
    layout,
    passphrase: bytearray,
) -> VaultEvidence:
    _verify_partition_leases(
        target_lease_fd,
        partition_lease_fd,
        partition,
        candidate,
        layout,
    )
    reject_partition_signature(partition_lease_fd)
    cryptsetup = _fixed_binary(CRYPTSETUP_PATHS, "cryptsetup")
    luks_uuid = str(uuid.uuid4())
    filesystem_uuid = str(uuid.uuid4())
    if not UUID_RE.fullmatch(luks_uuid) or not UUID_RE.fullmatch(filesystem_uuid):
        raise WriteError("generated vault UUID is not canonical")

    run_secret_command(
        lambda key_path, key_size: _luks_format_command(
            cryptsetup,
            key_path,
            key_size,
            f"/proc/self/fd/{partition_lease_fd}",
            luks_uuid,
        ),
        passphrase,
        label="cryptsetup LUKS2 format",
        timeout=FORMAT_TIMEOUT_SECONDS,
        pass_fds=(partition_lease_fd,),
    )
    partition_data_fd = _open_data_fd_from_block_lease(
        partition_lease_fd,
        partition.path,
        partition.major_minor,
        "vault partition",
        writable=True,
    )
    try:
        os.fsync(partition_data_fd)
    finally:
        os.close(partition_data_fd)
    _verify_partition_leases(
        target_lease_fd,
        partition_lease_fd,
        partition,
        candidate,
        layout,
    )
    verify_luks_metadata(partition_lease_fd, luks_uuid)
    _verify_partition_leases(
        target_lease_fd,
        partition_lease_fd,
        partition,
        candidate,
        layout,
    )
    _verify_wrong_key_rejected(partition_lease_fd, partition, luks_uuid)

    lifecycle = VaultLifecycle()
    mapper_lease_fd = -1
    evidence: VaultEvidence | None = None
    original_error: BaseException | None = None
    try:
        name = _random_mapper_name()
        _verify_partition_leases(
            target_lease_fd,
            partition_lease_fd,
            partition,
            candidate,
            layout,
        )
        mapper_lease_fd, mapper = _open_mapper(
            partition_lease_fd, partition, luks_uuid, passphrase, name, lifecycle
        )
        verify_mapper_lease(mapper_lease_fd, mapper, partition, luks_uuid)
        mkfs = _fixed_binary(MKFS_EXT4_PATHS, "mkfs.ext4")
        run_command(
            _mkfs_ext4_command(
                mkfs, f"/proc/self/fd/{mapper_lease_fd}", filesystem_uuid
            ),
            label="mkfs.ext4 vault format",
            timeout=FORMAT_TIMEOUT_SECONDS,
            pass_fds=(mapper_lease_fd,),
        )
        verify_mapper_lease(mapper_lease_fd, mapper, partition, luks_uuid)
        tune2fs = _fixed_binary(TUNE2FS_PATHS, "tune2fs")
        run_command(
            _tune2fs_command(tune2fs, f"/proc/self/fd/{mapper_lease_fd}"),
            label="tune2fs pinned vault profile",
            timeout=FORMAT_TIMEOUT_SECONDS,
            pass_fds=(mapper_lease_fd,),
        )
        mapper_data_fd = _open_data_fd_from_block_lease(
            mapper_lease_fd,
            mapper.node_path,
            mapper.major_minor,
            "vault mapper",
            writable=True,
        )
        try:
            os.fsync(mapper_data_fd)
        finally:
            os.close(mapper_data_fd)
        verify_filesystem(
            mapper_lease_fd,
            mapper,
            partition,
            luks_uuid,
            filesystem_uuid,
        )
        mountpoint = _mount_mapper(
            mapper_lease_fd, mapper, lifecycle, read_only=False
        )
        created = create_vault_layout(mountpoint, mapper)
        evidence = VaultEvidence(
            luks_uuid,
            filesystem_uuid,
            created.marker_sha256,
            created.identity_sha256,
        )
        _unmount(lifecycle)
        _close_mapper(lifecycle, partition, luks_uuid)
        mapper_lease_fd = -1

        _verify_partition_leases(
            target_lease_fd,
            partition_lease_fd,
            partition,
            candidate,
            layout,
        )
        verify_luks_metadata(partition_lease_fd, luks_uuid)
        _verify_partition_leases(
            target_lease_fd,
            partition_lease_fd,
            partition,
            candidate,
            layout,
        )
        mapper_lease_fd, mapper = _open_mapper(
            partition_lease_fd,
            partition,
            luks_uuid,
            passphrase,
            _random_mapper_name(),
            lifecycle,
        )
        verify_filesystem(
            mapper_lease_fd,
            mapper,
            partition,
            luks_uuid,
            filesystem_uuid,
        )
        mountpoint = _mount_mapper(
            mapper_lease_fd, mapper, lifecycle, read_only=True
        )
        verify_vault_layout(mountpoint, mapper, evidence)
        _unmount(lifecycle)
        _close_mapper(lifecycle, partition, luks_uuid)
        mapper_lease_fd = -1
    except BaseException as error:
        original_error = error
    finally:
        try:
            _cleanup_lifecycle_with_signals_deferred(
                lifecycle, partition, luks_uuid
            )
        except BaseException as cleanup_error:
            if original_error is None:
                original_error = cleanup_error
            else:
                original_error = WriteError(
                    f"{original_error}; additionally, {cleanup_error}"
                )
    if original_error is not None:
        raise original_error
    if evidence is None:
        raise WriteError("vault provisioning produced no verified evidence")
    _verify_partition_leases(
        target_lease_fd,
        partition_lease_fd,
        partition,
        candidate,
        layout,
    )
    verify_luks_metadata(partition_lease_fd, luks_uuid)
    target_data_fd = _open_data_fd_from_block_lease(
        target_lease_fd,
        candidate.path,
        candidate.major_minor,
        "whole-device",
        writable=True,
    )
    try:
        os.fsync(target_data_fd)
    finally:
        os.close(target_data_fd)
    return evidence


def _ci_environment_present() -> bool:
    return any(
        os.environ.get(name, "").strip().lower() not in ("", "0", "false", "no")
        for name in ("CI", "GITHUB_ACTIONS", "BUILD_BUILDID")
    )


def _checkpoint_candidate(
    device_path: str,
    baseline,
    image,
    *,
    ci_mode: bool,
    usb_proof,
    loop_backing,
    ci_token: str | None,
):
    inventory = run_lsblk()
    host_use = v1.read_host_use(inventory)
    candidate = inventory.resolve_explicit(device_path)
    v1.validate_candidate(inventory, candidate, image, host_use, ci_loop=ci_mode)
    if candidate.fingerprint() != baseline.fingerprint():
        raise SafetyError("target path/major:minor/disk sequence identity changed")
    if ci_mode:
        observed = inspect_loop_backing(candidate, image)
        if loop_backing is None or observed.fingerprint() != loop_backing.fingerprint():
            raise SafetyError("disposable loop backing identity changed")
        expected = v1.ci_token(candidate, observed)
        if ci_token is None or not hmac.compare_digest(ci_token, expected):
            raise SafetyError("disposable loop authorization token became stale")
    else:
        if usb_proof is None or probe_usb_media(candidate) != usb_proof:
            raise SafetyError("physical USB identity changed")
    return candidate


def fresh_media_attestation_phrase(candidate) -> str:
    return (
        "FACTORY-NEW NEVER-USED-FOR-DATA "
        f"{candidate.path} {candidate.serial} {candidate.disk_sequence}"
    )


def require_fresh_media_attestation(candidate, input_stream) -> bool:
    if not input_stream.isatty():
        raise SafetyError("fresh-media attestation requires an interactive terminal")
    phrase = fresh_media_attestation_phrase(candidate)
    print(
        "V2 POLICY: this physical support must be factory-new and must never have "
        "stored user data. KernAid cannot technically prove freshness, does not "
        "wipe unknown raw remnants, and has no recovery/reprovision flow.",
        file=sys.stderr,
    )
    print("Type this second exact policy attestation:", file=sys.stderr)
    print(phrase, file=sys.stderr)
    entered = input_stream.readline()
    if not entered or entered.rstrip("\r\n") != phrase:
        raise SafetyError("factory-new/never-used media attestation did not match")
    return True


def make_report(
    candidate,
    image,
    trusted,
    catalog_revision: int,
    layout,
    partition: PartitionIdentity,
    verified_sha256: str,
    evidence: VaultEvidence,
    *,
    ci_mode: bool,
    usb_proof,
    operator_fresh_media_attestation: bool | None,
) -> Mapping[str, object]:
    if ci_mode:
        if operator_fresh_media_attestation is not None:
            raise WriteError("CI report cannot claim a human fresh-media attestation")
        rendered_usb: Mapping[str, object] = {
            "applicable": False,
            "reason": "private disposable loop test mode",
        }
    else:
        if usb_proof is None or operator_fresh_media_attestation is not True:
            raise WriteError(
                "physical report is missing USB or fresh-media operator evidence"
            )
        rendered_usb = {
            "applicable": True,
            "verified": True,
            "properties": dict(usb_proof.properties),
        }
    return {
        "schema": "dev.kernaid.make-device-report.v2",
        "status": "verified",
        "completedAt": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
        "reportAuthenticity": {
            "status": "unsigned-unauthenticated",
            "signed": False,
            "authenticated": False,
        },
        "mediaPolicy": {
            "recognizedConflictingSignatures": "refused-without-implicit-wipe",
            "blankOrUnrecognizedTailProvesFreshMedia": False,
            "technicalFreshnessVerified": False,
            "operatorFreshMediaAttestationApplicable": not ci_mode,
            "operatorFreshMediaAttestation": (
                operator_fresh_media_attestation is True
            ),
            "ciDisposableLoopPolicy": (
                "private-token-bound-test-fixture" if ci_mode else "not-applicable"
            ),
            "usedPhysicalMediaAuthorized": False,
            "authenticatedRecoveryOrReprovisionImplemented": False,
            "operatorPolicyAfterAnyFailedWrite": "do-not-boot-or-reuse",
            "requiredFutureFlow": "separate-authenticated-recovery",
        },
        "mode": "ci-disposable-loop" if ci_mode else "interactive-removable-usb",
        "trust": {
            "catalog": "v2-only",
            "catalogRevision": catalog_revision,
            "artifactName": trusted.artifact_name,
            "artifactVersion": trusted.artifact_version,
            "layoutManifestSha256": layout.manifest_sha256,
            "vaultProfileVersion": layout.vault_profile_version,
            "vaultProfileSha256": layout.vault_profile_sha256,
            "biosTwoBootUsbAndVaultEvidence": True,
            "uefiTwoBootUsbAndVaultEvidence": True,
        },
        "source": {
            "path": image.path,
            "bytes": image.size,
            "sha256": image.sha256,
        },
        "target": {
            "path": candidate.path,
            "majorMinor": candidate.major_minor,
            "diskSequence": candidate.disk_sequence,
            "capacityBytes": candidate.size,
            "minimumRequiredBytes": layout.minimum_advertised_media_bytes,
            "serial": candidate.serial or None,
            "udevProof": rendered_usb,
        },
        "imageVerification": {
            "method": "exact-byte-prefix-after-fsync-and-BLKFLSBUF",
            "verifiedBytes": image.size,
            "sha256": verified_sha256,
        },
        "vaultPartition": {
            "number": layout.vault_partition.number,
            "path": partition.path,
            "majorMinor": partition.major_minor,
            "parentMajorMinor": partition.parent_major_minor,
            "startLba": partition.start_lba,
            "sectorCount": partition.sector_count,
            "bytes": partition.size,
        },
        "vault": {
            "provisioned": True,
            "luksVersion": 2,
            "luksLabel": VAULT_LABEL,
            "luksUuid": evidence.luks_uuid,
            "filesystem": "ext4",
            "filesystemLabel": VAULT_LABEL,
            "filesystemUuid": evidence.filesystem_uuid,
            "vaultProfileVersion": layout.vault_profile_version,
            "vaultProfileSha256": layout.vault_profile_sha256,
            "markerSha256": evidence.marker_sha256,
            "deviceIdentityEnvelopeSha256": evidence.identity_sha256,
            "wrongKeyRejected": True,
            "reopenedAndVerified": True,
            "mapperClosed": True,
            "unmounted": True,
        },
        "residualTail": {
            "policy": "fail-on-recognized-conflict, otherwise preserve outside layout",
            "vaultEndByte": layout.minimum_media_bytes,
            "mediaEndByte": candidate.size,
        },
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Write a catalog-v2 trusted KernAid Rescue image and provision "
            "its exact encrypted vault."
        )
    )
    parser.add_argument("--iso", required=True, help="absolute path to the trusted Rescue ISO")
    parser.add_argument("--sha256", required=True, help="official lowercase ISO SHA-256")
    parser.add_argument("--device", required=True, help="explicit absolute whole-device path")
    parser.add_argument(
        "--ci-disposable-loop-token",
        metavar="TOKEN",
        help="allow only one exact private disposable /dev/loopN target",
    )
    parser.add_argument(
        "--ci-passphrase-fd",
        type=int,
        metavar="FD",
        help="CI-only inherited anonymous-pipe descriptor; never allowed for physical media",
    )
    return parser


def _emit_failure(state: OperationState, error: BaseException) -> int:
    detail = v1._error_text(error)
    if state.target_overwritten_or_partial:
        message = (
            "FAILED: MEDIA PARTIAL / NON-BOOTABLE; do not boot or reuse it. "
            "No authenticated recovery/reprovision flow is implemented; a future "
            "run may refuse recognized partial signatures, while blank/unrecognized "
            "tail data cannot prove that media is fresh "
            f"({state.target_path}, phase={state.phase.name}): {detail}"
        )
        exit_code = 4
    elif isinstance(error, (SafetyError, OperationInterrupted, KeyboardInterrupt)):
        message = f"REFUSED: target was not written: {detail}"
        exit_code = 3
    else:
        message = f"FAILED before target write: {detail}"
        exit_code = 5
    try:
        os.write(2, (message + "\n").encode("utf-8", "replace"))
    except OSError:
        pass
    return exit_code


def execute(args: argparse.Namespace, state: OperationState) -> Mapping[str, object]:
    if sys.platform != "linux":
        raise SafetyError("make-device-v2 is supported only on Linux")
    if not sys.flags.isolated:
        raise SafetyError("invoke the installed make-device-v2 launcher with /usr/bin/python3 -I")
    if os.geteuid() != 0:
        raise SafetyError("make-device-v2 requires effective uid 0")
    ci_mode = args.ci_disposable_loop_token is not None
    if _ci_environment_present() and not ci_mode:
        raise SafetyError("CI environments cannot address physical block devices")
    if ci_mode != (args.ci_passphrase_fd is not None):
        raise SafetyError("disposable loop mode requires both its exact token and passphrase pipe")

    catalog, layout = load_installed_trust()
    # No subprocess is permitted before every executable has been identity-
    # bound and its required capability/profile proven on disposable files.
    preflight_writer_environment()
    initial_inventory = run_lsblk()
    initial_host = v1.read_host_use(initial_inventory)
    source_fd, image = v1.open_verified_image(args.iso, args.sha256, initial_host.mounts)
    passphrase = bytearray()
    operator_fresh_media_attestation: bool | None = None
    target_fd = -1
    partition_fd = -1
    target_lease_fd = -1
    partition_lease_fd = -1
    try:
        verify_finalized_image_layout(source_fd, image, layout)
        try:
            trusted = catalog.authorize(
                os.path.basename(image.path),
                image.sha256,
                image.size,
                current_layout=layout,
            )
        except catalog_v2.CatalogV2Error as error:
            raise SafetyError(str(error)) from error
        initial_candidate = initial_inventory.resolve_explicit(args.device)
        v1.validate_candidate(
            initial_inventory,
            initial_candidate,
            image,
            initial_host,
            ci_loop=ci_mode,
        )
        validate_v2_candidate(initial_candidate, layout)
        usb_proof = None if ci_mode else probe_usb_media(initial_candidate)
        loop_backing = None
        if ci_mode:
            loop_backing = inspect_loop_backing(initial_candidate, image)
            expected_token = v1.ci_token(initial_candidate, loop_backing)
            if not hmac.compare_digest(args.ci_disposable_loop_token, expected_token):
                raise SafetyError("disposable loop token does not bind the exact target")
            passphrase = acquire_passphrase_from_ci_fd(args.ci_passphrase_fd)
        else:
            v1.require_confirmation(initial_candidate, sys.stdin)
            operator_fresh_media_attestation = require_fresh_media_attestation(
                initial_candidate, sys.stdin
            )
            passphrase = acquire_passphrase_from_tty()

        final_candidate = _checkpoint_candidate(
            args.device,
            initial_candidate,
            image,
            ci_mode=ci_mode,
            usb_proof=usb_proof,
            loop_backing=loop_backing,
            ci_token=args.ci_disposable_loop_token,
        )
        validate_v2_candidate(final_candidate, layout)
        v1._assert_image_path_matches(image)
        v1._assert_image_unchanged(source_fd, image)
        target_fd = v1._open_target(final_candidate)
        _revalidate_target_fd(
            target_fd,
            final_candidate,
            logical_sector_bytes=layout.logical_sector_bytes,
        )
        _checkpoint_candidate(
            args.device,
            final_candidate,
            image,
            ci_mode=ci_mode,
            usb_proof=usb_proof,
            loop_backing=loop_backing,
            ci_token=args.ci_disposable_loop_token,
        )
        verified_sha256 = write_and_verify_prefix(
            source_fd, image, final_candidate, target_fd, state, layout
        )
        _revalidate_target_fd(
            target_fd,
            final_candidate,
            logical_sector_bytes=layout.logical_sector_bytes,
        )
        verify_finalized_image_layout(target_fd, image, layout)
        partition_fd, partition = discover_partition(
            target_fd, final_candidate, layout, ci_mode=ci_mode
        )
        # The raw writer's O_EXCL whole-device claim and the partition data FD
        # must not remain open while cryptsetup/mkfs acquire their own kernel
        # claims.  Transfer ownership atomically to non-claiming O_PATH leases;
        # the helper consumes both input descriptors on every outcome.
        exclusive_target_fd = target_fd
        discovered_partition_fd = partition_fd
        target_fd = -1
        partition_fd = -1
        target_lease_fd, partition_lease_fd = handoff_partition_to_identity_leases(
            exclusive_target_fd,
            discovered_partition_fd,
            partition,
            final_candidate,
            layout,
        )
        _checkpoint_candidate(
            args.device,
            final_candidate,
            image,
            ci_mode=ci_mode,
            usb_proof=usb_proof,
            loop_backing=loop_backing,
            ci_token=args.ci_disposable_loop_token,
        )
        _verify_partition_leases(
            target_lease_fd,
            partition_lease_fd,
            partition,
            final_candidate,
            layout,
        )
        evidence = provision_vault(
            target_lease_fd,
            final_candidate,
            partition_lease_fd,
            partition,
            layout,
            passphrase,
        )
        completed_leases = (partition_lease_fd, target_lease_fd)
        partition_lease_fd = -1
        target_lease_fd = -1
        _close_owned_descriptors(completed_leases, "completed block lease")
        _checkpoint_candidate(
            args.device,
            final_candidate,
            image,
            ci_mode=ci_mode,
            usb_proof=usb_proof,
            loop_backing=loop_backing,
            ci_token=args.ci_disposable_loop_token,
        )
        return make_report(
            final_candidate,
            image,
            trusted,
            catalog.revision,
            layout,
            partition,
            verified_sha256,
            evidence,
            ci_mode=ci_mode,
            usb_proof=usb_proof,
            operator_fresh_media_attestation=operator_fresh_media_attestation,
        )
    finally:
        _wipe_bytearray(passphrase)
        remaining_descriptors = (
            partition_fd,
            target_fd,
            partition_lease_fd,
            target_lease_fd,
            source_fd,
        )
        partition_fd = -1
        target_fd = -1
        partition_lease_fd = -1
        target_lease_fd = -1
        source_fd = -1
        _close_owned_descriptors(remaining_descriptors, "writer")


def main(argv: Sequence[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    state = OperationState()
    previous_handlers: dict[signal.Signals, object] = {}
    exit_code = 5
    try:
        for managed_signal in v1.MANAGED_SIGNALS:
            previous_handlers[managed_signal] = signal.getsignal(managed_signal)
            signal.signal(managed_signal, v1._signal_interrupted)
        try:
            report = execute(arguments, state)
            rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
            sys.stdout.write(rendered)
            sys.stdout.flush()
            state.advance(WritePhase.REPORT_EMITTED, state.target_path or arguments.device)
            exit_code = 0
        except BaseException as error:
            exit_code = _emit_failure(state, error)
    except BaseException as error:
        exit_code = _emit_failure(state, error)
    finally:
        try:
            if state.target_overwritten_or_partial and hasattr(signal, "pthread_sigmask"):
                signal.pthread_sigmask(signal.SIG_BLOCK, v1.MANAGED_SIGNALS)
            for managed_signal, previous_handler in previous_handlers.items():
                signal.signal(managed_signal, previous_handler)
        except BaseException as error:
            exit_code = _emit_failure(state, error)
    return exit_code


__all__ = [
    "CommandResult",
    "MapperIdentity",
    "PartitionIdentity",
    "VaultEvidence",
    "VaultLifecycle",
    "acquire_passphrase_from_ci_fd",
    "build_parser",
    "execute",
    "_emit_failure",
    "main",
    "parse_blkid_export",
    "parse_mountinfo_for_path",
    "parse_udev_properties",
    "reject_partition_signature",
    "run_command",
    "validate_v2_candidate",
    "verify_finalized_image_layout",
]
