#!/usr/bin/python3 -I
"""Verify and describe a fixed 32 GB compressed Rescue retail image."""

from __future__ import annotations

import argparse
import hashlib
import json
import lzma
import os
from pathlib import Path
import stat
import sys

NAMES = {
    "diagnosis": {
        "iso": "KernAid-Rescue-amd64.iso",
        "raw": "KernAid-Rescue-amd64-retail.img",
        "metadata": "KernAid-Rescue-amd64-retail.json",
        "schema": "dev.kernaid.rescue-retail-image.v1",
    },
    "repair": {
        "iso": "KernAid-Rescue-Repair-amd64.iso",
        "raw": "KernAid-Rescue-Repair-amd64-retail.img",
        "metadata": "KernAid-Rescue-Repair-amd64-retail.json",
        "schema": "dev.kernaid.rescue-repair-retail-image.v1",
    },
}
# Compatibility aliases for callers and tests of the diagnosis-only product.
RAW_NAME = NAMES["diagnosis"]["raw"]
XZ_NAME = f"{RAW_NAME}.xz"
METADATA_NAME = NAMES["diagnosis"]["metadata"]
RAW_BYTES = 32_000_000_000
P3_START = 17_179_869_184
P3_BYTES = 8_589_934_592
P3_ZERO_SHA256 = "ebfb4ef19ae410f190327b5ebd312711263bc7579970e87d9c1e2d84e06b3c25"
CHUNK = 4 * 1024 * 1024
MAX_COMPRESSED_BYTES = 1_999_999_998


def fail(message: str) -> None:
    raise RuntimeError(message)


def regular(path: Path, expected: str) -> os.stat_result:
    if not path.is_absolute() or path.name != expected:
        fail(f"{expected} path or filename is not exact")
    entry = path.lstat()
    if not stat.S_ISREG(entry.st_mode) or entry.st_nlink != 1 or entry.st_size <= 0:
        fail(f"{expected} is not a regular single-link file")
    return entry


def digest_file(path: Path) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb", buffering=0) as source:
        while chunk := source.read(CHUNK):
            digest.update(chunk)
            size += len(chunk)
    return size, digest.hexdigest()


def verify(iso: Path, archive: Path, variant: str = "diagnosis") -> dict[str, object]:
    try:
        names = NAMES[variant]
    except KeyError:
        fail("retail image variant is unsupported")
    raw_name = names["raw"]
    archive_name = f"{raw_name}.xz"
    iso_entry = regular(iso, names["iso"])
    archive_entry = regular(archive, archive_name)
    if iso_entry.st_size >= P3_START or archive_entry.st_size > MAX_COMPRESSED_BYTES:
        fail("ISO or compressed retail image size is outside fixed bounds")
    iso_size, iso_sha256 = digest_file(iso)
    compressed_size, compressed_sha256 = digest_file(archive)

    raw_digest = hashlib.sha256()
    p3_digest = hashlib.sha256()
    raw_offset = 0
    with iso.open("rb", buffering=0) as expected, lzma.open(archive, "rb") as stream:
        while raw_offset < RAW_BYTES:
            chunk = stream.read(min(CHUNK, RAW_BYTES - raw_offset))
            if not chunk:
                fail("compressed retail image ended before 32,000,000,000 bytes")
            raw_digest.update(chunk)
            begin = raw_offset
            end = begin + len(chunk)
            if begin < iso_size:
                prefix_end = min(end, iso_size)
                wanted = expected.read(prefix_end - begin)
                if chunk[: len(wanted)] != wanted:
                    fail("retail raw image does not contain the exact ISO prefix")
            zero_begin = max(begin, iso_size)
            if zero_begin < end:
                zero_slice = chunk[zero_begin - begin :]
                if zero_slice.count(0) != len(zero_slice):
                    fail("retail raw image contains non-zero bytes after the ISO prefix")
            overlap_begin = max(begin, P3_START)
            overlap_end = min(end, P3_START + P3_BYTES)
            if overlap_begin < overlap_end:
                p3_digest.update(chunk[overlap_begin - begin : overlap_end - begin])
            raw_offset = end
        if stream.read(1):
            fail("compressed retail image exceeds 32,000,000,000 bytes")
        if expected.read(1):
            fail("ISO prefix comparison did not consume the exact ISO")

    p3_sha256 = p3_digest.hexdigest()
    if p3_sha256 != P3_ZERO_SHA256:
        fail("retail p3 does not match the fixed 8 GiB zero digest")
    return {
        "compressed": {
            "bytes": compressed_size,
            "name": archive_name,
            "sha256": compressed_sha256,
        },
        "isoPrefix": {"bytes": iso_size, "sha256": iso_sha256},
        "p3": {
            "bytes": P3_BYTES,
            "sha256": p3_sha256,
            "startBytes": P3_START,
            "zero": True,
        },
        "raw": {"bytes": RAW_BYTES, "name": raw_name, "sha256": raw_digest.hexdigest()},
        "schema": names["schema"],
        "tailZero": True,
    }


def canonical(document: dict[str, object]) -> bytes:
    return (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iso", required=True, type=Path)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--variant", choices=tuple(NAMES), default="diagnosis", help="product boundary"
    )
    arguments = parser.parse_args()
    try:
        expected_metadata = NAMES[arguments.variant]["metadata"]
        if not arguments.output.is_absolute() or arguments.output.name != expected_metadata:
            fail("retail metadata path or filename is not exact")
        payload = canonical(verify(arguments.iso, arguments.archive, arguments.variant))
        descriptor = os.open(arguments.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o644)
        try:
            view = memoryview(payload)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    fail("retail metadata could not be written")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except (OSError, EOFError, lzma.LZMAError, RuntimeError) as error:
        print(f"REFUSED: {error}", file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
