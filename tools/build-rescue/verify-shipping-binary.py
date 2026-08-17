#!/usr/bin/python3
"""Fail-closed ABI gate for binaries staged into the Rescue live image."""

from __future__ import annotations

import os
import re
import resource
import stat
import subprocess
import sys
import tempfile
from pathlib import Path


READELF = Path("/usr/bin/x86_64-linux-gnu-readelf")
MAX_BINARY_BYTES = 128 * 1024 * 1024
MAX_TOOL_OUTPUT_BYTES = 64 * 1024
TOOL_TIMEOUT_SECONDS = 5
EXPECTED_INTERPRETER = "/lib64/ld-linux-x86-64.so.2"
ALLOWED_NEEDED = frozenset(
    {
        "ld-linux-x86-64.so.2",
        "libc.so.6",
        "libgcc_s.so.1",
        "libm.so.6",
    }
)
NEEDED_PATTERN = re.compile(r"\(NEEDED\).*Shared library: \[([^\[\]]+)\]")
INTERPRETER_PATTERN = re.compile(r"Requesting program interpreter: ([^\[\]]+)\]")


class VerificationError(Exception):
    """A sanitized shipping-binary policy failure."""


def _open_exact_regular(path: Path, *, require_root_0755: bool) -> int:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise VerificationError("required input is unavailable") from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise VerificationError("required input is not an exact regular file")
        if require_root_0755 and (
            metadata.st_uid != 0
            or metadata.st_gid != 0
            or stat.S_IMODE(metadata.st_mode) != 0o755
        ):
            raise VerificationError("required input ownership or mode is unsafe")
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _limit_readelf_output() -> None:
    resource.setrlimit(
        resource.RLIMIT_FSIZE,
        (MAX_TOOL_OUTPUT_BYTES, MAX_TOOL_OUTPUT_BYTES),
    )


def _readelf(binary_descriptor: int, readelf_descriptor: int) -> str:
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        try:
            result = subprocess.run(
                [
                    f"/proc/self/fd/{readelf_descriptor}",
                    "--wide",
                    "--program-headers",
                    "--dynamic",
                    f"/proc/self/fd/{binary_descriptor}",
                ],
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                check=False,
                close_fds=True,
                pass_fds=(binary_descriptor, readelf_descriptor),
                env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"},
                timeout=TOOL_TIMEOUT_SECONDS,
                preexec_fn=_limit_readelf_output,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise VerificationError("bounded ELF inspection failed") from error
        if result.returncode != 0:
            raise VerificationError("bounded ELF inspection was rejected")
        output_size = os.fstat(stdout.fileno()).st_size
        error_size = os.fstat(stderr.fileno()).st_size
        if output_size > MAX_TOOL_OUTPUT_BYTES or error_size > MAX_TOOL_OUTPUT_BYTES:
            raise VerificationError("bounded ELF inspection exceeded its output limit")
        stdout.seek(0)
        try:
            return stdout.read(MAX_TOOL_OUTPUT_BYTES + 1).decode("ascii")
        except UnicodeDecodeError as error:
            raise VerificationError("ELF inspection output is not ASCII") from error


def parse_readelf_output(output: str) -> frozenset[str]:
    if len(output.encode("ascii")) > MAX_TOOL_OUTPUT_BYTES:
        raise VerificationError("ELF inspection output exceeded its limit")
    if "(RPATH)" in output or "(RUNPATH)" in output:
        raise VerificationError("shipping binary contains a runtime search path")

    interpreters = INTERPRETER_PATTERN.findall(output)
    if interpreters != [EXPECTED_INTERPRETER]:
        raise VerificationError("shipping binary has an unexpected ELF interpreter")

    dependencies: set[str] = set()
    for line in output.splitlines():
        if "(NEEDED)" not in line:
            continue
        match = NEEDED_PATTERN.search(line)
        if match is None:
            raise VerificationError("shipping binary has malformed dependency metadata")
        dependency = match.group(1)
        if dependency not in ALLOWED_NEEDED:
            raise VerificationError("shipping binary has an unapproved runtime dependency")
        dependencies.add(dependency)
    if "libc.so.6" not in dependencies:
        raise VerificationError("shipping binary is missing its pinned libc dependency")
    return frozenset(dependencies)


def verify(path: Path) -> None:
    binary_descriptor = _open_exact_regular(path, require_root_0755=True)
    try:
        metadata = os.fstat(binary_descriptor)
        if not 0 < metadata.st_size <= MAX_BINARY_BYTES:
            raise VerificationError("shipping binary size is outside policy")
        header = os.pread(binary_descriptor, 20, 0)
        if (
            len(header) != 20
            or header[:6] != b"\x7fELF\x02\x01"
            or int.from_bytes(header[18:20], "little") != 62
        ):
            raise VerificationError("shipping binary is not ELF64 amd64")

        readelf_descriptor = _open_exact_regular(READELF, require_root_0755=True)
        try:
            parse_readelf_output(_readelf(binary_descriptor, readelf_descriptor))
        finally:
            os.close(readelf_descriptor)
    finally:
        os.close(binary_descriptor)


def main(arguments: list[str]) -> int:
    if len(arguments) != 1:
        print("usage: verify-shipping-binary.py BINARY", file=sys.stderr)
        return 2
    try:
        verify(Path(arguments[0]))
    except VerificationError as error:
        print(f"Rescue shipping binary rejected: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
