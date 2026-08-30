#!/usr/bin/python3
"""Render the shipping Rescue HTTP server for one exact image profile."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import stat
import sys


BEGIN = "# KERNAID_REPAIR_CANDIDATE_BEGIN"
END = "# KERNAID_REPAIR_CANDIDATE_END"
EXPECTED_BLOCKS = 5
MAX_SOURCE_BYTES = 512 * 1024


def _same_file(before: os.stat_result, after: os.stat_result) -> bool:
    return (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_nlink,
        before.st_uid,
        before.st_gid,
        before.st_size,
    ) == (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_nlink,
        after.st_uid,
        after.st_gid,
        after.st_size,
    )


def render_source(
    source: str, include_candidate: bool, expected_blocks: int = EXPECTED_BLOCKS
) -> str:
    rendered: list[str] = []
    inside = False
    blocks = 0
    for line in source.splitlines(keepends=True):
        marker = line.strip()
        if marker == BEGIN:
            if inside:
                raise ValueError("nested repair-candidate marker")
            inside = True
            blocks += 1
            continue
        if marker == END:
            if not inside:
                raise ValueError("unmatched repair-candidate end marker")
            inside = False
            continue
        if not inside or include_candidate:
            rendered.append(line)
    if inside:
        raise ValueError("unterminated repair-candidate marker")
    if blocks != expected_blocks:
        raise ValueError(
            f"expected {expected_blocks} repair-candidate blocks, found {blocks}"
        )
    result = "".join(rendered)
    if BEGIN in result or END in result:
        raise ValueError("repair-candidate marker survived rendering")
    compile(result, "rescue_server.py", "exec", dont_inherit=True)
    return result


def read_source(path: Path) -> str:
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or not 0 < metadata.st_size <= MAX_SOURCE_BYTES
    ):
        raise ValueError("Rescue server template is not a bounded regular file")
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            payload = stream.read(MAX_SOURCE_BYTES + 1)
        if len(payload) != metadata.st_size or not _same_file(
            metadata, os.fstat(descriptor)
        ):
            raise ValueError("Rescue server template changed while reading")
    finally:
        os.close(descriptor)
    if b"\0" in payload:
        raise ValueError("Rescue server template contains NUL")
    return payload.decode("utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("stable", "candidate"), required=True)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--expected-blocks", type=int, default=EXPECTED_BLOCKS)
    args = parser.parse_args()
    try:
        rendered = render_source(
            read_source(args.input),
            args.mode == "candidate",
            args.expected_blocks,
        )
    except (OSError, UnicodeDecodeError, ValueError, SyntaxError) as error:
        parser.error(str(error))
    sys.stdout.buffer.write(rendered.encode("utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
