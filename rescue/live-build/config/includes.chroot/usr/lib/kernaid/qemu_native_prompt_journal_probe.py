#!/usr/bin/python3
"""QEMU-only root proof that a high-entropy Vault secret is absent from this boot journal."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import select
import stat
import subprocess
import sys
import time


DIGEST_PATH = Path(
    "/sys/firmware/qemu_fw_cfg/by_name/opt/kernaid-native-vault-secret-digest/raw"
)
MARKER_DIRECTORY = Path("/run/kernaid-qemu-native-prompt-journal-proof")
MAX_JOURNAL_BYTES = 16 * 1024 * 1024
MAX_COVERAGE_BYTES = 1024 * 1024
TIMEOUT_SECONDS = 15.0
HEX_WINDOW = re.compile(rb"(?=([0-9a-f]{64}))")
EXPECTED_UNITS = {
    "boot1": ("kernaid-rescue-firstboot.service",),
    "boot2": (
        "kernaid-rescue-native-vault-unlock.service",
        "kernaid-rescue-native-prompt.service",
    ),
}


class ProbeFailure(RuntimeError):
    pass


def _digest() -> bytes:
    metadata = DIGEST_PATH.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or metadata.st_nlink != 1
        or metadata.st_size != 0
    ):
        raise ProbeFailure
    descriptor = os.open(DIGEST_PATH, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    value = bytearray(65)
    view = memoryview(value)
    total = 0
    try:
        while total < len(value):
            count = os.readv(descriptor, [view[total:]])
            if count == 0:
                break
            total += count
    finally:
        view.release()
        os.close(descriptor)
    if total != 64:
        value[:] = b"\0" * len(value)
        raise ProbeFailure
    del value[64:]
    if re.fullmatch(rb"[0-9a-f]{64}", value) is None:
        value[:] = b"\0" * len(value)
        raise ProbeFailure
    result = bytes.fromhex(value.decode("ascii"))
    value[:] = b"\0" * len(value)
    value.clear()
    return result


def _capture(arguments: list[str], maximum: int) -> bytearray:
    process = subprocess.Popen(
        arguments,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        close_fds=True,
        env={"HOME": "/", "LANG": "C", "LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
    )
    assert process.stdout is not None
    descriptor = process.stdout.fileno()
    os.set_blocking(descriptor, False)
    value = bytearray(maximum + 1)
    view = memoryview(value)
    view_released = False
    total = 0
    deadline = time.monotonic() + TIMEOUT_SECONDS
    try:
        while total < len(value):
            try:
                count = os.readv(descriptor, [view[total:]])
            except BlockingIOError:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ProbeFailure
                readable, _, _ = select.select([descriptor], [], [], remaining)
                if not readable:
                    raise ProbeFailure
                continue
            except InterruptedError:
                continue
            if count == 0:
                break
            total += count
        if total > maximum:
            raise ProbeFailure
        remaining = deadline - time.monotonic()
        if remaining <= 0 or process.wait(timeout=remaining) != 0:
            raise ProbeFailure
        view.release()
        view_released = True
        del value[total:]
        return value
    except BaseException:
        process.kill()
        try:
            process.wait(timeout=2)
        except subprocess.SubprocessError:
            pass
        if not view_released:
            view.release()
            view_released = True
        value[:] = b"\0" * len(value)
        value.clear()
        raise
    finally:
        if not view_released:
            view.release()
        process.stdout.close()


def _journal(arguments: list[str], maximum: int) -> bytearray:
    return _capture(
        [
            "/usr/bin/journalctl",
            "--boot=0",
            "--no-pager",
            "--output=export",
            "--all",
            *arguments,
        ],
        maximum,
    )


def _secret_absent(payload: bytearray, expected_digest: bytes) -> bool:
    view = memoryview(payload)
    try:
        for match in HEX_WINDOW.finditer(payload):
            start, end = match.span(1)
            if hashlib.sha256(view[start:end]).digest() == expected_digest:
                return False
        return True
    finally:
        view.release()


def _marker_metadata_valid(metadata: os.stat_result, size: int, owner: int) -> bool:
    return (
        stat.S_ISREG(metadata.st_mode)
        and metadata.st_uid == owner
        and metadata.st_gid == owner
        and metadata.st_nlink == 1
        and stat.S_IMODE(metadata.st_mode) == 0o444
        and metadata.st_size == size
    )


def _write_all(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    try:
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise ProbeFailure
            view = view[written:]
    finally:
        view.release()


def _publish(stage: str) -> None:
    MARKER_DIRECTORY.mkdir(mode=0o755, parents=False, exist_ok=True)
    directory_metadata = MARKER_DIRECTORY.lstat()
    if (
        not stat.S_ISDIR(directory_metadata.st_mode)
        or directory_metadata.st_uid != 0
        or directory_metadata.st_gid != 0
        or stat.S_IMODE(directory_metadata.st_mode) != 0o755
    ):
        raise ProbeFailure
    directory = os.open(MARKER_DIRECTORY, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    temporary = f".{stage}.tmp"
    marker = stage
    payload = (
        f"KERNAID_QEMU_NATIVE_PROMPT_JOURNAL_PROOF_V1 stage={stage} "
        "euid=root scope=full-current-boot entries=true coverage=true secret-absent=true\n"
    ).encode("ascii")
    descriptor = -1
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
            dir_fd=directory,
        )
        _write_all(descriptor, payload)
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o444)
        os.close(descriptor)
        descriptor = -1
        os.link(temporary, marker, src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
        os.unlink(temporary, dir_fd=directory)
        published = os.stat(marker, dir_fd=directory, follow_symlinks=False)
        if not _marker_metadata_valid(published, len(payload), 0):
            raise ProbeFailure
        reader = os.open(marker, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=directory)
        try:
            if os.read(reader, len(payload) + 1) != payload:
                raise ProbeFailure
        finally:
            os.close(reader)
        os.fsync(directory)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary, dir_fd=directory)
        except FileNotFoundError:
            pass
        os.close(directory)


def run(stage: str) -> None:
    if os.geteuid() != 0 or os.getegid() != 0 or stage not in EXPECTED_UNITS:
        raise ProbeFailure
    expected_digest = _digest()
    journal = _journal([], MAX_JOURNAL_BYTES)
    try:
        if (
            not journal.startswith(b"__CURSOR=")
            or b"\n_BOOT_ID=" not in journal
            or b"\n\n" not in journal
            or not _secret_absent(journal, expected_digest)
        ):
            raise ProbeFailure
    finally:
        journal[:] = b"\0" * len(journal)
        journal.clear()
    for unit in EXPECTED_UNITS[stage]:
        coverage = _journal([f"--unit={unit}", "--lines=1"], MAX_COVERAGE_BYTES)
        try:
            if not coverage.startswith(b"__CURSOR=") or b"\n\n" not in coverage:
                raise ProbeFailure
        finally:
            coverage[:] = b"\0" * len(coverage)
            coverage.clear()
    _publish(stage)


def main() -> int:
    try:
        if len(sys.argv) != 2:
            raise ProbeFailure
        run(sys.argv[1])
    except (OSError, ProbeFailure, subprocess.SubprocessError, ValueError):
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
