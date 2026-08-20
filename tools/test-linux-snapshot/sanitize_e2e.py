#!/usr/bin/env python3
"""Publish only fixed Linux snapshot E2E digest attestations."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import stat


MAX_INPUT_BYTES = 8 * 1024 * 1024
MAX_LINE_BYTES = 4096
RESIDENT = re.compile(
    rb"KERNAID_RESIDENT_LINUX_SNAPSHOT_E2E_V1 "
    rb"semantic_sha256=([0-9a-f]{64})"
)
RESCUE = re.compile(
    rb"KERNAID_RESCUE_LINUX_SNAPSHOT_E2E_V1 "
    rb"semantic_sha256=([0-9a-f]{64})"
)
QEMU = re.compile(
    rb"KERNAID_QEMU_LINUX_SNAPSHOT_E2E_V1 "
    rb"firmware=(bios|uefi) semantic_sha256=([0-9a-f]{64}) "
    rb"semantic_equal=true"
)
FORBIDDEN_MARKERS = (
    b"fixture-machine-id-must-never-be-projected",
    b"fixture-secret-package-name",
    b"UUID=fixture-root",
    b"server:/fixture",
    b"KERNAID_CALLER_PATH_MARKER_MUST_BE_IGNORED",
)


class EvidenceError(RuntimeError):
    """The raw input could not be reduced to the closed evidence grammar."""


def _bounded_lines(path: Path) -> list[bytes]:
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size <= 0
        or metadata.st_size > MAX_INPUT_BYTES
    ):
        raise EvidenceError("snapshot E2E input identity or size was unsafe")
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        payload = bytearray()
        while len(payload) <= MAX_INPUT_BYTES:
            chunk = os.read(descriptor, min(64 * 1024, MAX_INPUT_BYTES + 1 - len(payload)))
            if not chunk:
                break
            payload.extend(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        len(payload) > MAX_INPUT_BYTES
        or (metadata.st_dev, metadata.st_ino, metadata.st_size)
        != (before.st_dev, before.st_ino, before.st_size)
        or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        or len(payload) != before.st_size
        or b"\0" in payload
        or any(marker in payload for marker in FORBIDDEN_MARKERS)
    ):
        raise EvidenceError("snapshot E2E input changed or contained a raw marker")
    lines = bytes(payload).splitlines()
    if not lines or any(len(line) > MAX_LINE_BYTES for line in lines):
        raise EvidenceError("snapshot E2E input framing was invalid")
    return lines


def _one_prefixed(
    lines: list[bytes], prefix: bytes, pattern: re.Pattern[bytes]
) -> re.Match[bytes]:
    candidates = [line for line in lines if line.startswith(prefix)]
    if len(candidates) != 1:
        raise EvidenceError("snapshot E2E marker was not unique")
    match = pattern.fullmatch(candidates[0])
    if match is None:
        raise EvidenceError("snapshot E2E marker was outside the allowlist")
    return match


def sanitize(resident_path: Path, bios_path: Path, uefi_path: Path) -> bytes:
    resident_lines = _bounded_lines(resident_path)
    if len(resident_lines) != 1:
        raise EvidenceError("Resident digest evidence contained extra output")
    resident = _one_prefixed(
        resident_lines,
        b"KERNAID_RESIDENT_LINUX_SNAPSHOT_E2E_V1 ",
        RESIDENT,
    ).group(1)
    rows: list[tuple[bytes, bytes]] = []
    for firmware, path in ((b"bios", bios_path), (b"uefi", uefi_path)):
        lines = _bounded_lines(path)
        rescue = _one_prefixed(
            lines,
            b"KERNAID_RESCUE_LINUX_SNAPSHOT_E2E_V1 ",
            RESCUE,
        ).group(1)
        qemu = _one_prefixed(
            lines,
            b"KERNAID_QEMU_LINUX_SNAPSHOT_E2E_V1 ",
            QEMU,
        )
        if qemu.group(1) != firmware or qemu.group(2) != rescue:
            raise EvidenceError("Rescue snapshot digest was not bound to its firmware run")
        rows.append((firmware, rescue))
    if any(digest != resident for _firmware, digest in rows):
        raise EvidenceError("Resident and Rescue semantic snapshot digests differed")
    digest = resident.decode("ascii")
    output = [
        f"KERNAID_LINUX_SNAPSHOT_E2E_V1 source=resident semantic_sha256={digest}",
        *(
            f"KERNAID_LINUX_SNAPSHOT_E2E_V1 source=rescue-{firmware.decode('ascii')} "
            f"semantic_sha256={value.decode('ascii')}"
            for firmware, value in rows
        ),
        f"KERNAID_LINUX_SNAPSHOT_PARITY_V1 semantic_sha256={digest} equal=true",
    ]
    return ("\n".join(output) + "\n").encode("ascii")


def _publish(path: Path, payload: bytes) -> None:
    parent = path.parent
    parent_metadata = parent.stat()
    if not stat.S_ISDIR(parent_metadata.st_mode) or path.exists() or path.is_symlink():
        raise EvidenceError("snapshot E2E evidence destination was unsafe")
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
    )
    published = False
    try:
        written = 0
        while written < len(payload):
            count = os.write(descriptor, payload[written:])
            if count <= 0:
                raise EvidenceError("snapshot E2E evidence write failed")
            written += count
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size != len(payload)
        ):
            raise EvidenceError("snapshot E2E evidence was not durable")
        published = True
    finally:
        os.close(descriptor)
        if not published:
            try:
                path.unlink()
            except FileNotFoundError:
                pass
    directory = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--resident", required=True, type=Path)
    parser.add_argument("--bios", required=True, type=Path)
    parser.add_argument("--uefi", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    payload = sanitize(arguments.resident, arguments.bios, arguments.uefi)
    _publish(arguments.output, payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
