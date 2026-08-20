#!/usr/bin/env python3
"""Fingerprint controlled snapshot fixture trees without observing atime."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import stat
import struct


DOMAIN = b"KERNAID_LINUX_SNAPSHOT_FIXTURE_TREE_V1\0"
MAX_ENTRIES = 4_096
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024


class FingerprintError(RuntimeError):
    """The controlled fixture tree could not be fingerprinted safely."""


@dataclass(frozen=True)
class FingerprintRecord:
    path: bytes
    kind: bytes
    mode: int
    size: int
    mtime_ns: int
    ctime_ns: int
    content_sha256: bytes


def _field(value: bytes) -> bytes:
    return struct.pack(">Q", len(value)) + value


def fingerprint_records(records: list[FingerprintRecord]) -> str:
    ordered = sorted(records, key=lambda item: item.path)
    if len({item.path for item in ordered}) != len(ordered):
        raise FingerprintError("fixture fingerprint paths were not unique")
    digest = hashlib.sha256(DOMAIN)
    for item in ordered:
        fields = (
            item.path,
            item.kind,
            str(item.mode).encode("ascii"),
            str(item.size).encode("ascii"),
            str(item.mtime_ns).encode("ascii"),
            str(item.ctime_ns).encode("ascii"),
            item.content_sha256,
        )
        record = b"".join(_field(field) for field in fields)
        digest.update(_field(record))
    return digest.hexdigest()


def _file_digest(path: bytes, expected: os.stat_result) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        identity = (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        expected_identity = (
            expected.st_dev,
            expected.st_ino,
            expected.st_mode,
            expected.st_size,
            expected.st_mtime_ns,
            expected.st_ctime_ns,
        )
        if identity != expected_identity or before.st_size > MAX_FILE_BYTES:
            raise FingerprintError("fixture file identity or size was unsafe")
        digest = hashlib.sha256()
        observed = 0
        while True:
            chunk = os.read(descriptor, min(64 * 1024, MAX_FILE_BYTES + 1 - observed))
            if not chunk:
                break
            observed += len(chunk)
            if observed > MAX_FILE_BYTES:
                raise FingerprintError("fixture file exceeded the fingerprint bound")
            digest.update(chunk)
        after = os.fstat(descriptor)
        after_identity = (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if observed != before.st_size or after_identity != identity:
            raise FingerprintError("fixture file changed while fingerprinting")
        return digest.digest()
    finally:
        os.close(descriptor)


def collect_records(root: Path) -> list[FingerprintRecord]:
    root_bytes = os.fsencode(root)
    root_metadata = os.lstat(root_bytes)
    if not stat.S_ISDIR(root_metadata.st_mode):
        raise FingerprintError("fixture fingerprint root was not a directory")
    records: list[FingerprintRecord] = []
    total_file_bytes = 0

    def visit(directory: bytes, relative: bytes) -> None:
        nonlocal total_file_bytes
        with os.scandir(directory) as iterator:
            entries = sorted(iterator, key=lambda item: item.name)
        for entry in entries:
            name = entry.name
            child_relative = name if not relative else relative + b"/" + name
            metadata = entry.stat(follow_symlinks=False)
            if stat.S_ISREG(metadata.st_mode):
                kind = b"file"
                content_sha256 = _file_digest(entry.path, metadata)
                total_file_bytes += metadata.st_size
                if total_file_bytes > MAX_TOTAL_BYTES:
                    raise FingerprintError("fixture tree exceeded the fingerprint bound")
            elif stat.S_ISDIR(metadata.st_mode):
                kind = b"directory"
                content_sha256 = b""
            else:
                raise FingerprintError("fixture tree contained an unsupported entry")
            records.append(
                FingerprintRecord(
                    path=child_relative,
                    kind=kind,
                    mode=stat.S_IMODE(metadata.st_mode),
                    size=metadata.st_size,
                    mtime_ns=metadata.st_mtime_ns,
                    ctime_ns=metadata.st_ctime_ns,
                    content_sha256=content_sha256,
                )
            )
            if len(records) > MAX_ENTRIES:
                raise FingerprintError("fixture tree exceeded the entry bound")
            if kind == b"directory":
                visit(entry.path, child_relative)

    visit(root_bytes, b"")
    return records


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    arguments = parser.parse_args()
    try:
        fingerprint = fingerprint_records(collect_records(arguments.root))
    except (FingerprintError, OSError):
        parser.error("fixture tree fingerprint failed")
    print(fingerprint)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
