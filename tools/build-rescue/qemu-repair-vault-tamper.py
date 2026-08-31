#!/usr/bin/env python3
"""Tamper one disposable QEMU repair backup while the VM is stopped.

This helper is intentionally narrower than a generic image editor.  It accepts
only the canonical candidate work directory, p3 geometry and one exact backup
name discovered inside the qualification Vault.  It never mounts the Vault.
"""

from __future__ import annotations

import argparse
import errno
import fcntl
import os
import re
import selectors
import signal
import shutil
import stat
import struct
import subprocess
import sys
import time
from pathlib import Path


MEDIA_BYTES = 32_000_000_000
P3_OFFSET = 17_179_869_184
P3_BYTES = 8_589_934_592
BACKUP_DIRECTORY = (
    "/.kernaid-secure-state-v1/.kernaid-repair-store-v1/backups"
)
BACKUP_NAME = re.compile(r"backup-B-[0-9a-f]{32}")
DEBUGFS_INODE_SIZE = re.compile(
    rb"(?:^|\n)(?:"
    rb"Size:[ \t]+|"
    rb"User:[ \t]+[0-9]+[ \t]+Group:[ \t]+[0-9]+"
    rb"(?:[ \t]+Project:[ \t]+[0-9]+)?[ \t]+Size:[ \t]+"
    rb")([0-9]+)[ \t]*(?=\n|$)"
)
WORK_DIRECTORY = re.compile(r"kernaid-qemu-repair-candidate\.[A-Za-z0-9]{8}")
MEDIA_NAME = "rescue-usb.raw"
KEY_NAME = "vault-key"
HEX_BYTES = frozenset(b"0123456789abcdef")
LOOP_NAME = re.compile(r"loop([0-9]+)")
LOOP_GET_STATUS64 = 0x4C05
LOOP_INFO64 = struct.Struct("=QQQQQIIII64s64s32sQQ")
TOOL_TIMEOUT_SECONDS = 15.0
CLEANUP_TOOL_TIMEOUT_SECONDS = 5.0
CLEANUP_WAIT_SECONDS = 2.0
TOTAL_CLEANUP_SECONDS = 25.0
OUTPUT_LIMIT_BYTES = 64 * 1024
PIPE_READ_BYTES = 16 * 1024
SYSFS_BLOCK_LIMIT = 4096
ATTESTATION = (
    "KERNAID_QEMU_REPAIR_VAULT_TAMPER_ATTESTATION_V1 "
    "object=single-authenticated-backup mutation=inode-size-one "
    "mount=false cleanup=complete ready=true"
)
FAILURE_CODES = frozenset(
    {
        "arguments-invalid",
        "backup-invalid",
        "caller-invalid",
        "input-invalid",
        "key-invalid",
        "loop-collision",
        "loop-correlation-invalid",
        "loop-discovery-failed",
        "loop-output-invalid",
        "loop-setup-failed",
        "loop-shape-invalid",
        "mapper-collision",
        "mapper-discovery-failed",
        "mapper-open-failed",
        "tamper-unverified",
        "tool-failed",
        "tool-missing",
    }
)
PUBLIC_FAILURE_CODES = FAILURE_CODES | {"cleanup-failed", "unexpected"}


class ClosedFailure(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code if code in FAILURE_CODES else "unexpected"
        super().__init__(self.code)


def public_failure_code(
    failure: BaseException | None, *, cleanup_failed: bool
) -> str:
    """Return one allowlisted diagnostic without exposing exception content."""

    if cleanup_failed:
        return "cleanup-failed"
    if isinstance(failure, ClosedFailure):
        return failure.code
    return "unexpected"


def command(name: str) -> str:
    value = shutil.which(name, path="/usr/sbin:/usr/bin:/sbin:/bin")
    if value is None:
        raise ClosedFailure("tool-missing")
    return value


def run(
    arguments: list[str],
    *,
    timeout: float = TOOL_TIMEOUT_SECONDS,
    pass_fds: tuple[int, ...] = (),
) -> bytes:
    process: subprocess.Popen[bytes] | None = None
    selector: selectors.BaseSelector | None = None
    stdout = bytearray()
    stderr = bytearray()
    completed = False
    try:
        process = subprocess.Popen(
            arguments,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"},
            close_fds=True,
            pass_fds=pass_fds,
            start_new_session=True,
        )
        if process.stdout is None or process.stderr is None:
            raise ClosedFailure("tool-failed")
        selector = selectors.DefaultSelector()
        streams = (
            (process.stdout, stdout),
            (process.stderr, stderr),
        )
        for stream, buffer in streams:
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, buffer)
        deadline = time.monotonic() + timeout
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(arguments, timeout)
            for key, _events in selector.select(min(remaining, 0.05)):
                try:
                    chunk = os.read(key.fd, PIPE_READ_BYTES)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                buffer = key.data
                buffer.extend(chunk)
                if len(buffer) > OUTPUT_LIMIT_BYTES:
                    raise ClosedFailure("tool-failed")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired(arguments, timeout)
        return_code = process.wait(timeout=remaining)
        completed = True
        if return_code != 0:
            raise ClosedFailure("tool-failed")
        result = bytes(stdout)
        return result
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ClosedFailure("tool-failed") from error
    finally:
        if process is not None and not completed:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except OSError as error:
                if error.errno != errno.ESRCH:
                    pass
            try:
                process.wait(timeout=1.0)
            except (OSError, subprocess.TimeoutExpired):
                pass
        if selector is not None:
            selector.close()
        if process is not None:
            for stream in (process.stdout, process.stderr):
                if stream is not None:
                    stream.close()
        stdout[:] = b"\x00" * len(stdout)
        stderr[:] = b"\x00" * len(stderr)
        stdout.clear()
        stderr.clear()


def _same_identity(first: os.stat_result, second: os.stat_result) -> bool:
    return (
        first.st_dev,
        first.st_ino,
        first.st_mode,
        first.st_nlink,
        first.st_uid,
        first.st_gid,
        first.st_size,
        first.st_mtime_ns,
        first.st_ctime_ns,
    ) == (
        second.st_dev,
        second.st_ino,
        second.st_mode,
        second.st_nlink,
        second.st_uid,
        second.st_gid,
        second.st_size,
        second.st_mtime_ns,
        second.st_ctime_ns,
    )


def _validate_file_metadata(
    metadata: os.stat_result, *, size: int, mode: int, owner: int
) -> None:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != owner
        or stat.S_IMODE(metadata.st_mode) != mode
        or metadata.st_nlink != 1
        or metadata.st_size != size
    ):
        raise ClosedFailure("input-invalid")


def open_qualification_inputs(
    media_path: Path, key_path: Path, *, owner: int
) -> tuple[int, int]:
    """Pin both exact inputs below one private dir without following links."""

    media_text = os.fspath(media_path)
    key_text = os.fspath(key_path)
    media_parent, media_name = os.path.split(media_text)
    key_parent, key_name = os.path.split(key_text)
    parent_parent, parent_name = os.path.split(media_parent)
    if (
        not media_path.is_absolute()
        or not key_path.is_absolute()
        or media_parent != key_parent
        or parent_parent != "/tmp"
        or WORK_DIRECTORY.fullmatch(parent_name) is None
        or media_name != MEDIA_NAME
        or key_name != KEY_NAME
    ):
        raise ClosedFailure("input-invalid")

    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    temporary_fd = parent_fd = media_fd = key_fd = -1
    try:
        temporary_fd = os.open("/tmp", directory_flags)
        temporary = os.fstat(temporary_fd)
        if (
            not stat.S_ISDIR(temporary.st_mode)
            or temporary.st_uid != 0
            or stat.S_IMODE(temporary.st_mode) & stat.S_ISVTX == 0
        ):
            raise ClosedFailure("input-invalid")
        parent_fd = os.open(
            parent_name, directory_flags, dir_fd=temporary_fd
        )
        parent = os.fstat(parent_fd)
        if (
            not stat.S_ISDIR(parent.st_mode)
            or parent.st_uid != owner
            or stat.S_IMODE(parent.st_mode) != 0o700
        ):
            raise ClosedFailure("input-invalid")

        media_fd = os.open(
            MEDIA_NAME,
            os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=parent_fd,
        )
        key_fd = os.open(
            KEY_NAME,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=parent_fd,
        )
        media = os.fstat(media_fd)
        key = os.fstat(key_fd)
        named_media = os.stat(MEDIA_NAME, dir_fd=parent_fd, follow_symlinks=False)
        named_key = os.stat(KEY_NAME, dir_fd=parent_fd, follow_symlinks=False)
        _validate_file_metadata(media, size=MEDIA_BYTES, mode=0o600, owner=owner)
        _validate_file_metadata(key, size=64, mode=0o600, owner=owner)
        if (
            not _same_identity(media, named_media)
            or not _same_identity(key, named_key)
            or (media.st_dev, media.st_ino) == (key.st_dev, key.st_ino)
        ):
            raise ClosedFailure("input-invalid")
    except OSError as error:
        for descriptor in (key_fd, media_fd):
            if descriptor >= 0:
                os.close(descriptor)
        raise ClosedFailure("input-invalid") from error
    except BaseException:
        for descriptor in (key_fd, media_fd):
            if descriptor >= 0:
                os.close(descriptor)
        raise
    finally:
        for descriptor in (parent_fd, temporary_fd):
            if descriptor >= 0:
                os.close(descriptor)
    return media_fd, key_fd


def validate_key(descriptor: int) -> None:
    value = bytearray(65)
    view = memoryview(value)
    try:
        count = os.preadv(descriptor, [view], 0)
        if count != 64 or any(byte not in HEX_BYTES for byte in view[:count]):
            raise ClosedFailure("key-invalid")
    except OSError as error:
        raise ClosedFailure("key-invalid") from error
    finally:
        view.release()
        value[:] = b"\x00" * len(value)
        value.clear()


def proc_fd(descriptor: int) -> str:
    return f"/proc/self/fd/{descriptor}"


def huge_device_matches(encoded: int, device: int) -> bool:
    """Compare loop_info64's huge_encode_dev value with a stat dev_t."""

    return (encoded >> 32, encoded & 0xFFFFFFFF) == (
        os.major(device),
        os.minor(device),
    )


def loop_devices(media: os.stat_result, *, require_pristine_shape: bool) -> set[str]:
    """Find only loops backed by the pinned inode and exact p3 geometry."""

    matches: set[str] = set()
    try:
        names = os.listdir("/dev")
    except OSError as error:
        raise ClosedFailure("loop-discovery-failed") from error
    for name in names:
        number_match = LOOP_NAME.fullmatch(name)
        if number_match is None:
            continue
        descriptor = -1
        try:
            descriptor = os.open(
                f"/dev/{name}",
                os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
            device = os.fstat(descriptor)
            if not stat.S_ISBLK(device.st_mode):
                continue
            encoded = bytearray(LOOP_INFO64.size)
            fcntl.ioctl(descriptor, LOOP_GET_STATUS64, encoded, True)
            fields = LOOP_INFO64.unpack(encoded)
        except OSError as error:
            if error.errno in (errno.ENOENT, errno.ENXIO, errno.ENODEV, errno.EINVAL):
                continue
            raise ClosedFailure("loop-discovery-failed") from error
        finally:
            if descriptor >= 0:
                os.close(descriptor)
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
        correlated = (
            huge_device_matches(backing_device, media.st_dev)
            and backing_inode == media.st_ino
            and huge_device_matches(backing_rdevice, media.st_rdev)
            and offset == P3_OFFSET
            and size_limit == P3_BYTES
            and loop_number == int(number_match.group(1))
        )
        pristine = (
            encryption_type == 0
            and encryption_key_size == 0
            and loop_flags == 0
        )
        if correlated and (pristine or not require_pristine_shape):
            matches.add(f"/dev/{name}")
    return matches


def correlated_loop_devices(media: os.stat_result) -> set[str]:
    """Find cleanup authority even if an owned loop became AUTOCLEAR."""

    return loop_devices(media, require_pristine_shape=False)


def exact_loop_devices(media: os.stat_result) -> set[str]:
    """Find a newly configured writable loop with no extra flags."""

    return loop_devices(media, require_pristine_shape=True)


def kernel_mapper_names() -> set[str]:
    """Read bounded device-mapper names from kernel sysfs, independent of udev."""

    names: set[str] = set()
    try:
        with os.scandir("/sys/class/block") as entries:
            for count, entry in enumerate(entries, start=1):
                if count > SYSFS_BLOCK_LIMIT:
                    raise ClosedFailure("mapper-discovery-failed")
                if re.fullmatch(r"dm-[0-9]+", entry.name) is None:
                    continue
                descriptor = -1
                try:
                    descriptor = os.open(
                        os.path.join(entry.path, "dm/name"),
                        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                    )
                    value = os.read(descriptor, 257)
                    trailing = os.read(descriptor, 1)
                except OSError as error:
                    if error.errno in (errno.ENOENT, errno.ENODEV):
                        continue
                    raise ClosedFailure("mapper-discovery-failed") from error
                finally:
                    if descriptor >= 0:
                        os.close(descriptor)
                if trailing or not value.endswith(b"\n") or len(value) < 2:
                    raise ClosedFailure("mapper-discovery-failed")
                try:
                    name = value[:-1].decode("ascii")
                except UnicodeDecodeError as error:
                    raise ClosedFailure("mapper-discovery-failed") from error
                if re.fullmatch(r"[A-Za-z0-9+_.-]{1,255}", name) is None:
                    raise ClosedFailure("mapper-discovery-failed")
                names.add(name)
    except OSError as error:
        raise ClosedFailure("mapper-discovery-failed") from error
    return names


def mapper_exists(mapper: str, mapper_path: str) -> bool:
    return os.path.lexists(mapper_path) or mapper in kernel_mapper_names()


def parse_debugfs_inode_size(output: bytes) -> int:
    """Parse exactly one canonical inode-size field, never a fragment size."""

    matches = DEBUGFS_INODE_SIZE.findall(output)
    if len(matches) != 1:
        raise ClosedFailure("backup-invalid")
    return int(matches[0])


def close_mapper_bounded(mapper: str, mapper_path: str, deadline: float) -> bool:
    for _attempt in range(3):
        if not mapper_exists(mapper, mapper_path):
            return True
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        try:
            run(
                [command("cryptsetup"), "close", mapper],
                timeout=min(CLEANUP_TOOL_TIMEOUT_SECONDS, remaining),
            )
        except BaseException:
            pass
        wait_deadline = min(deadline, time.monotonic() + 0.5)
        while mapper_exists(mapper, mapper_path) and time.monotonic() < wait_deadline:
            time.sleep(0.02)
    return not mapper_exists(mapper, mapper_path)


def detach_loop_bounded(loop: str, media: os.stat_result, deadline: float) -> bool:
    if loop not in correlated_loop_devices(media):
        return True
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return False
    try:
        run(
            [command("losetup"), "--detach", loop],
            timeout=min(CLEANUP_TOOL_TIMEOUT_SECONDS, remaining),
        )
    except BaseException:
        pass
    wait_deadline = min(deadline, time.monotonic() + CLEANUP_WAIT_SECONDS)
    while time.monotonic() < wait_deadline:
        if loop not in correlated_loop_devices(media):
            return True
        time.sleep(0.02)
    return loop not in correlated_loop_devices(media)


def discover_backup(mapper_path: str, reservation_id: str) -> str:
    listing = run([command("debugfs"), "-R", f"ls -p {BACKUP_DIRECTORY}", mapper_path])
    try:
        text = listing.decode("ascii")
    except UnicodeDecodeError as error:
        raise ClosedFailure("backup-invalid") from error
    names: list[str] = []
    for line in text.splitlines():
        fields = line.split("/")
        if len(fields) >= 6 and BACKUP_NAME.fullmatch(fields[5] or ""):
            names.append(fields[5])
    expected = f"backup-{reservation_id}"
    if names != [expected]:
        raise ClosedFailure("backup-invalid")
    path = f"{BACKUP_DIRECTORY}/{expected}"
    before = run([command("debugfs"), "-R", f"stat {path}", mapper_path])
    if parse_debugfs_inode_size(before) <= 1:
        raise ClosedFailure("backup-invalid")
    return path


def main() -> int:
    parser = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
    parser.add_argument("--media", type=Path, required=True)
    parser.add_argument("--key-file", type=Path, required=True)
    parser.add_argument("--reservation-id", required=True)
    parser.add_argument("--p3-offset", type=int, required=True)
    parser.add_argument("--p3-bytes", type=int, required=True)
    media_fd = key_fd = -1
    failure: BaseException | None = None
    cleanup_failed = False
    baseline_loops: set[str] = set()
    owned_loops: set[str] = set()
    loop_setup_attempted = False
    mapper = f"kernaid-repair-tamper-{os.getpid()}"
    mapper_path = f"/dev/mapper/{mapper}"
    mapper_baseline = False
    mapper_open_attempted = False
    mapper_owned = False
    media_metadata: os.stat_result | None = None
    try:
        parsed = parser.parse_args()
        if (
            os.geteuid() != 0
            or parsed.p3_offset != P3_OFFSET
            or parsed.p3_bytes != P3_BYTES
            or re.fullmatch(r"B-[0-9a-f]{32}", parsed.reservation_id) is None
        ):
            raise ClosedFailure("arguments-invalid")
        invoking_uid_text = os.environ.get("SUDO_UID")
        if invoking_uid_text is None or re.fullmatch(r"[1-9][0-9]{0,9}", invoking_uid_text) is None:
            raise ClosedFailure("caller-invalid")
        invoking_uid = int(invoking_uid_text)
        media_fd, key_fd = open_qualification_inputs(
            parsed.media, parsed.key_file, owner=invoking_uid
        )
        validate_key(key_fd)
        media_metadata = os.fstat(media_fd)
        baseline_loops = correlated_loop_devices(media_metadata)
        if baseline_loops:
            raise ClosedFailure("loop-collision")
        mapper_baseline = mapper_exists(mapper, mapper_path)
        if mapper_baseline:
            raise ClosedFailure("mapper-collision")

        loop_output = b""
        setup_failure: BaseException | None = None
        loop_setup_attempted = True
        try:
            loop_output = run(
                [
                    command("losetup"),
                    "--find",
                    "--show",
                    "--nooverlap",
                    "--offset",
                    str(P3_OFFSET),
                    "--sizelimit",
                    str(P3_BYTES),
                    "--",
                    proc_fd(media_fd),
                ],
                pass_fds=(media_fd,),
            )
        except BaseException as error:
            setup_failure = error
        observed_loops = correlated_loop_devices(media_metadata)
        owned_loops.update(observed_loops - baseline_loops)
        try:
            loop = loop_output.decode("ascii").strip()
        except UnicodeDecodeError as error:
            raise ClosedFailure("loop-invalid") from error
        if setup_failure is not None:
            raise ClosedFailure("loop-setup-failed") from setup_failure
        if re.fullmatch(r"/dev/loop[0-9]+", loop) is None:
            raise ClosedFailure("loop-output-invalid")
        if observed_loops != baseline_loops | {loop}:
            raise ClosedFailure("loop-correlation-invalid")
        if exact_loop_devices(media_metadata) != {loop}:
            raise ClosedFailure("loop-shape-invalid")

        open_failure: BaseException | None = None
        mapper_open_attempted = True
        try:
            run(
                [
                    command("cryptsetup"),
                    "open",
                    "--type",
                    "luks2",
                    "--batch-mode",
                    "--tries",
                    "1",
                    "--disable-external-tokens",
                    "--key-file",
                    proc_fd(key_fd),
                    "--keyfile-size",
                    "64",
                    loop,
                    mapper,
                ],
                pass_fds=(key_fd,),
            )
        except BaseException as error:
            open_failure = error
        mapper_owned = not mapper_baseline and mapper_exists(mapper, mapper_path)
        if open_failure is not None or not mapper_owned:
            raise ClosedFailure("mapper-open-failed") from open_failure

        backup = discover_backup(mapper_path, parsed.reservation_id)
        run([command("debugfs"), "-w", "-R", f"set_inode_field {backup} size 1", mapper_path])
        run([command("blockdev"), "--flushbufs", mapper_path])
        after = run([command("debugfs"), "-R", f"stat {backup}", mapper_path])
        if parse_debugfs_inode_size(after) != 1:
            raise ClosedFailure("tamper-unverified")
    except BaseException as error:
        failure = error
    finally:
        cleanup_deadline = time.monotonic() + TOTAL_CLEANUP_SECONDS
        mapper_still_open = True
        try:
            mapper_now = mapper_exists(mapper, mapper_path)
            if mapper_open_attempted and not mapper_baseline and mapper_now:
                mapper_owned = True
            if mapper_owned and mapper_now and not close_mapper_bounded(
                mapper, mapper_path, cleanup_deadline
            ):
                cleanup_failed = True
            mapper_still_open = mapper_exists(mapper, mapper_path)
        except BaseException:
            cleanup_failed = True
        if media_metadata is not None and not mapper_still_open:
            try:
                if loop_setup_attempted:
                    owned_loops.update(
                        correlated_loop_devices(media_metadata) - baseline_loops
                    )
                for loop in sorted(owned_loops):
                    if not detach_loop_bounded(
                        loop, media_metadata, cleanup_deadline
                    ):
                        cleanup_failed = True
                if correlated_loop_devices(media_metadata) - baseline_loops:
                    cleanup_failed = True
            except BaseException:
                cleanup_failed = True
        elif media_metadata is not None and owned_loops:
            cleanup_failed = True
        if mapper_owned and mapper_still_open:
            cleanup_failed = True
        for descriptor in (key_fd, media_fd):
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    cleanup_failed = True

    if failure is not None or cleanup_failed:
        code = public_failure_code(failure, cleanup_failed=cleanup_failed)
        print(
            f"KERNAID_QEMU_REPAIR_VAULT_TAMPER_FAILURE_V1 code={code}",
            file=sys.stderr,
        )
        return 1
    print(ATTESTATION)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
