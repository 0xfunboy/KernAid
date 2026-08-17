#!/usr/bin/python3 -I
"""Bounded, source-only verifier for the immutable Rescue vault profile.

The writer and QEMU evidence gate deliberately execute the same binary LUKS2
JSON/ext4 superblock checks.  This helper never formats, opens, mounts, or
otherwise mutates the supplied device.
"""

from __future__ import annotations

import argparse
import os
import re
import stat
import sys
import uuid
from pathlib import Path
from types import ModuleType


MAX_SOURCE_BYTES = 4 * 1024 * 1024
MAX_JSON_BYTES = 256 * 1024
REPO_DIRECTORY = Path(__file__).resolve().parents[2]
CORE_PATH = REPO_DIRECTORY / "tools/make-device/make_device_v2.py"


def _load_source_module(name: str, path: Path) -> ModuleType:
    expected = path.lstat()
    if (
        not stat.S_ISREG(expected.st_mode)
        or expected.st_size <= 0
        or expected.st_size > MAX_SOURCE_BYTES
    ):
        raise RuntimeError("vault profile verifier source is unsafe")
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        observed = os.fstat(descriptor)
        if (
            observed.st_dev,
            observed.st_ino,
            observed.st_mode,
            observed.st_size,
        ) != (
            expected.st_dev,
            expected.st_ino,
            expected.st_mode,
            expected.st_size,
        ):
            raise RuntimeError("vault profile verifier source changed while opening")
        source = bytearray()
        while len(source) <= MAX_SOURCE_BYTES:
            chunk = os.read(descriptor, min(1024 * 1024, MAX_SOURCE_BYTES + 1 - len(source)))
            if not chunk:
                break
            source.extend(chunk)
        if len(source) != expected.st_size:
            raise RuntimeError("vault profile verifier source changed while reading")
    finally:
        os.close(descriptor)
    module = ModuleType(name)
    module.__file__ = str(path)
    module.__package__ = ""
    sys.modules[name] = module
    try:
        exec(compile(bytes(source), str(path), "exec", dont_inherit=True), module.__dict__)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module


def _read_stdin_bounded() -> bytes:
    chunks: list[bytes] = []
    total = 0
    while total <= MAX_JSON_BYTES:
        chunk = os.read(0, min(65536, MAX_JSON_BYTES + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    if total <= 0 or total > MAX_JSON_BYTES:
        raise RuntimeError("LUKS2 JSON input is empty or exceeds its bound")
    return b"".join(chunks)


def _open_block_device(path: str) -> int:
    if not os.path.isabs(path) or os.path.realpath(path) != path:
        raise RuntimeError("ext4 verifier requires one canonical direct device path")
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    details = os.fstat(descriptor)
    if not stat.S_ISBLK(details.st_mode):
        os.close(descriptor)
        raise RuntimeError("ext4 verifier input is not a block device")
    return descriptor


def _block_identity(descriptor: int, path: str) -> tuple[int, int, int, int]:
    held = os.fstat(descriptor)
    named = os.stat(path, follow_symlinks=False)
    identity = (held.st_dev, held.st_ino, held.st_rdev, held.st_mode)
    if (
        not stat.S_ISBLK(held.st_mode)
        or identity
        != (named.st_dev, named.st_ino, named.st_rdev, named.st_mode)
    ):
        raise RuntimeError("block device descriptor/path identity changed")
    return identity


def _read_sysfs_text(path: str) -> str:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        value = os.read(descriptor, 4097)
        if len(value) > 4096 or os.read(descriptor, 1):
            raise RuntimeError("device-mapper sysfs value exceeds its bound")
    finally:
        os.close(descriptor)
    try:
        text = value.decode("ascii", "strict").strip()
    except UnicodeDecodeError as error:
        raise RuntimeError("device-mapper sysfs value is not ASCII") from error
    if not text or any(ord(character) < 0x20 for character in text):
        raise RuntimeError("device-mapper sysfs value is malformed")
    return text


def _dm_snapshot(
    mapper_fd: int,
    mapper_path: str,
    mapper_name: str,
    backing_fd: int,
    backing_path: str,
) -> tuple[object, ...]:
    mapper_identity = _block_identity(mapper_fd, mapper_path)
    backing_identity = _block_identity(backing_fd, backing_path)
    mapper_major_minor = (
        f"{os.major(mapper_identity[2])}:{os.minor(mapper_identity[2])}"
    )
    backing_major_minor = (
        f"{os.major(backing_identity[2])}:{os.minor(backing_identity[2])}"
    )
    sysfs = os.path.realpath(f"/sys/dev/block/{mapper_major_minor}")
    if (
        not sysfs.startswith("/sys/devices/virtual/block/dm-")
        or os.path.basename(sysfs) != os.path.basename(mapper_path)
        or _read_sysfs_text(f"{sysfs}/dm/name") != mapper_name
    ):
        raise RuntimeError("device-mapper name, node, or sysfs identity is not exact")
    slaves: list[str] = []
    with os.scandir(f"{sysfs}/slaves") as entries:
        for count, entry in enumerate(entries, start=1):
            if count > 1:
                raise RuntimeError("device-mapper has more than one backing device")
            slave = os.path.realpath(f"{sysfs}/slaves/{entry.name}")
            if not slave.startswith("/sys/devices/"):
                raise RuntimeError("device-mapper slave sysfs identity is unsafe")
            slaves.append(_read_sysfs_text(f"{slave}/dev"))
    if slaves != [backing_major_minor]:
        raise RuntimeError("device-mapper is not backed by the exact p3 loop")
    return (
        mapper_identity,
        backing_identity,
        mapper_major_minor,
        backing_major_minor,
        sysfs,
        tuple(slaves),
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Verify KernAid vault profile-v1")
    parser.add_argument("--profile", required=True)
    subparsers = parser.add_subparsers(dest="kind", required=True)
    subparsers.add_parser("luks-json")
    ext4 = subparsers.add_parser("ext4")
    ext4.add_argument("--device", required=True)
    ext4.add_argument("--mapper-name", required=True)
    ext4.add_argument("--backing-device", required=True)
    ext4.add_argument("--uuid", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    if not sys.flags.isolated or not sys.flags.dont_write_bytecode:
        raise RuntimeError("invoke vault profile verifier with python3 -I -B")
    arguments = _parser().parse_args(argv)
    profile_path = Path(arguments.profile)
    if not profile_path.is_absolute():
        raise RuntimeError("vault profile path must be absolute")
    core = _load_source_module("kernaid_vault_profile_verifier_core", CORE_PATH)
    core.verify_implemented_vault_profile()
    digest = core.catalog_v2.load_vault_profile(profile_path)

    if arguments.kind == "luks-json":
        document = core.parse_luks_json_metadata(_read_stdin_bounded())
        core.verify_luks_json_document(document)
    else:
        if re.fullmatch(r"kernaid-inspect-[0-9a-f]{16}", arguments.mapper_name) is None:
            raise RuntimeError("ext4 verifier mapper name is invalid")
        try:
            expected_uuid = str(uuid.UUID(arguments.uuid))
        except ValueError as error:
            raise RuntimeError("ext4 verifier UUID is invalid") from error
        if expected_uuid != arguments.uuid:
            raise RuntimeError("ext4 verifier UUID is not canonical lowercase")
        descriptor = _open_block_device(arguments.device)
        try:
            backing_descriptor = _open_block_device(arguments.backing_device)
            try:
                before = _dm_snapshot(
                    descriptor,
                    arguments.device,
                    arguments.mapper_name,
                    backing_descriptor,
                    arguments.backing_device,
                )
                core.verify_ext4_superblock(descriptor, expected_uuid)
                after = _dm_snapshot(
                    descriptor,
                    arguments.device,
                    arguments.mapper_name,
                    backing_descriptor,
                    arguments.backing_device,
                )
                if before != after:
                    raise RuntimeError("ext4 verifier mapper/backing identity changed")
            finally:
                os.close(backing_descriptor)
        finally:
            os.close(descriptor)
    os.write(
        1,
        (
            "KERNAID_VAULT_PROFILE_CHECK_V1 "
            f"kind={arguments.kind} sha256={digest} verified=true\n"
        ).encode("ascii"),
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError) as error:
        os.write(2, f"vault profile verification refused: {error}\n".encode("utf-8", "replace"))
        raise SystemExit(2)
