#!/usr/bin/env python3
"""Finalize and verify the immutable Phase 0 MBR device layout.

This tool operates only on a regular image file.  It writes exactly the third
16-byte MBR partition entry and never extends the image.  The partition points
beyond the ISO EOF so that a later, explicitly provisioned vault can live
outside the byte-for-byte attested ISO prefix.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Sequence


MBR_BYTES: Final = 512
MBR_SIGNATURE_OFFSET: Final = 510
MBR_SIGNATURE: Final = b"\x55\xaa"
PARTITION_TABLE_OFFSET: Final = 446
PARTITION_ENTRY_BYTES: Final = 16
UINT32_LIMIT: Final = 1 << 32
MAX_MANIFEST_BYTES: Final = 64 * 1024
VAULT_PROFILE_FILENAME: Final = "vault-profile.v1.json"

EXPECTED_SCHEMA: Final = "kernaid.rescue-device-layout.v1"
EXPECTED_LAYOUT_VERSION: Final = 1
EXPECTED_PARTITION_TABLE: Final = "mbr"
EXPECTED_SECTOR_BYTES: Final = 512
EXPECTED_MINIMUM_MEDIA_BYTES: Final = 24 * 1024**3
EXPECTED_ADVERTISED_MEDIA_BYTES: Final = 32_000_000_000
EXPECTED_ADVERTISED_MEDIA_LABEL: Final = "32 GB"
EXPECTED_VAULT_PROFILE_VERSION: Final = 1
EXPECTED_VAULT_PROFILE_SHA256: Final = (
    "b4801359bd4f31ce67fbd3ec15b6c81c44aa6759ba43b2a4e099a7dfcc25a37c"
)
EXPECTED_VAULT_NUMBER: Final = 3
EXPECTED_VAULT_NAME: Final = "KERNAID_VAULT"
EXPECTED_VAULT_TYPE: Final = 0x83
EXPECTED_VAULT_START_LBA: Final = 33_554_432
EXPECTED_VAULT_SECTORS: Final = 16_777_216


class LayoutError(RuntimeError):
    """The manifest or image cannot safely represent layout-v1."""


@dataclass(frozen=True)
class DeviceLayout:
    logical_sector_bytes: int
    minimum_media_bytes: int
    minimum_advertised_media_bytes: int
    minimum_advertised_media_label: str
    vault_profile_version: int
    vault_profile_sha256: str
    vault_number: int
    vault_name: str
    vault_type: int
    vault_start_lba: int
    vault_sector_count: int

    @property
    def vault_start_bytes(self) -> int:
        return self.vault_start_lba * self.logical_sector_bytes

    @property
    def vault_end_lba(self) -> int:
        return self.vault_start_lba + self.vault_sector_count

    @property
    def vault_end_bytes(self) -> int:
        return self.vault_end_lba * self.logical_sector_bytes


@dataclass(frozen=True)
class PartitionEntry:
    slot: int
    raw: bytes
    status: int
    type_code: int
    start_lba: int
    sector_count: int

    @property
    def is_empty(self) -> bool:
        return self.raw == bytes(PARTITION_ENTRY_BYTES)

    @property
    def end_lba(self) -> int:
        return self.start_lba + self.sector_count


@dataclass(frozen=True)
class FinalizeResult:
    action: str
    image_size: int
    vault_entry: bytes


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise LayoutError(f"manifest contains duplicate key: {key}")
        result[key] = value
    return result


def _read_manifest_document(
    path: Path, *, label: str = "layout manifest"
) -> dict[str, Any]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise LayoutError(f"cannot open {label}: {error}") from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise LayoutError(f"{label} must be a regular file")
        if metadata.st_size <= 0 or metadata.st_size > MAX_MANIFEST_BYTES:
            raise LayoutError(f"{label} has an invalid size")
        chunks: list[bytes] = []
        remaining = metadata.st_size + 1
        while remaining > 0:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        encoded = b"".join(chunks)
        if len(encoded) != metadata.st_size:
            raise LayoutError(f"{label} changed while it was read")
    finally:
        os.close(descriptor)

    try:
        document = json.loads(
            encoded.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys
        )
    except (UnicodeDecodeError, json.JSONDecodeError, LayoutError) as error:
        if isinstance(error, LayoutError):
            raise
        raise LayoutError(f"{label} is not strict UTF-8 JSON: {error}") from error
    if not isinstance(document, dict):
        raise LayoutError(f"{label} root must be an object")
    return document


def _verify_vault_profile(path: Path) -> None:
    document = _read_manifest_document(path, label="vault profile manifest")
    canonical = json.dumps(
        document, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    if hashlib.sha256(canonical).hexdigest() != EXPECTED_VAULT_PROFILE_SHA256:
        raise LayoutError("vault profile manifest changes immutable profile-v1")


def _require_exact_keys(
    value: dict[str, Any], expected: set[str], location: str
) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise LayoutError(
            f"{location} keys are not exact (missing={missing}, extra={extra})"
        )


def _require_int(value: Any, location: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise LayoutError(f"{location} must be an integer")
    return value


def _require_string(value: Any, location: str) -> str:
    if not isinstance(value, str):
        raise LayoutError(f"{location} must be a string")
    return value


def parse_layout_manifest(path: Path) -> DeviceLayout:
    document = _read_manifest_document(path)
    _require_exact_keys(
        document,
        {
            "schema",
            "layoutVersion",
            "partitionTable",
            "logicalSectorBytes",
            "minimumMediaBytes",
            "minimumAdvertisedMediaBytes",
            "minimumAdvertisedMediaLabel",
            "vaultProfileVersion",
            "vaultProfileSha256",
            "vaultPartition",
        },
        "manifest",
    )
    vault_document = document["vaultPartition"]
    if not isinstance(vault_document, dict):
        raise LayoutError("manifest.vaultPartition must be an object")
    _require_exact_keys(
        vault_document,
        {"number", "name", "mbrType", "startLba", "sectorCount"},
        "manifest.vaultPartition",
    )

    schema = _require_string(document["schema"], "manifest.schema")
    layout_version = _require_int(
        document["layoutVersion"], "manifest.layoutVersion"
    )
    partition_table = _require_string(
        document["partitionTable"], "manifest.partitionTable"
    )
    sector_bytes = _require_int(
        document["logicalSectorBytes"], "manifest.logicalSectorBytes"
    )
    minimum_media_bytes = _require_int(
        document["minimumMediaBytes"], "manifest.minimumMediaBytes"
    )
    advertised_bytes = _require_int(
        document["minimumAdvertisedMediaBytes"],
        "manifest.minimumAdvertisedMediaBytes",
    )
    advertised_label = _require_string(
        document["minimumAdvertisedMediaLabel"],
        "manifest.minimumAdvertisedMediaLabel",
    )
    vault_profile_version = _require_int(
        document["vaultProfileVersion"], "manifest.vaultProfileVersion"
    )
    vault_profile_sha256 = _require_string(
        document["vaultProfileSha256"], "manifest.vaultProfileSha256"
    )
    vault_number = _require_int(
        vault_document["number"], "manifest.vaultPartition.number"
    )
    vault_name = _require_string(
        vault_document["name"], "manifest.vaultPartition.name"
    )
    vault_type_text = _require_string(
        vault_document["mbrType"], "manifest.vaultPartition.mbrType"
    )
    if len(vault_type_text) != 4 or not vault_type_text.startswith("0x"):
        raise LayoutError("manifest.vaultPartition.mbrType must be 0xNN")
    try:
        vault_type = int(vault_type_text[2:], 16)
    except ValueError as error:
        raise LayoutError("manifest.vaultPartition.mbrType must be 0xNN") from error
    vault_start_lba = _require_int(
        vault_document["startLba"], "manifest.vaultPartition.startLba"
    )
    vault_sectors = _require_int(
        vault_document["sectorCount"], "manifest.vaultPartition.sectorCount"
    )

    for value, location in (
        (vault_start_lba, "manifest.vaultPartition.startLba"),
        (vault_sectors, "manifest.vaultPartition.sectorCount"),
    ):
        if value <= 0 or value >= UINT32_LIMIT:
            raise LayoutError(f"{location} must fit a non-zero unsigned 32-bit MBR field")
    if vault_start_lba + vault_sectors > UINT32_LIMIT:
        raise LayoutError("vault partition end exceeds the MBR LBA address space")

    layout = DeviceLayout(
        logical_sector_bytes=sector_bytes,
        minimum_media_bytes=minimum_media_bytes,
        minimum_advertised_media_bytes=advertised_bytes,
        minimum_advertised_media_label=advertised_label,
        vault_profile_version=vault_profile_version,
        vault_profile_sha256=vault_profile_sha256,
        vault_number=vault_number,
        vault_name=vault_name,
        vault_type=vault_type,
        vault_start_lba=vault_start_lba,
        vault_sector_count=vault_sectors,
    )
    immutable_values = (
        (schema, EXPECTED_SCHEMA, "schema"),
        (layout_version, EXPECTED_LAYOUT_VERSION, "layoutVersion"),
        (partition_table, EXPECTED_PARTITION_TABLE, "partitionTable"),
        (sector_bytes, EXPECTED_SECTOR_BYTES, "logicalSectorBytes"),
        (
            minimum_media_bytes,
            EXPECTED_MINIMUM_MEDIA_BYTES,
            "minimumMediaBytes",
        ),
        (
            advertised_bytes,
            EXPECTED_ADVERTISED_MEDIA_BYTES,
            "minimumAdvertisedMediaBytes",
        ),
        (
            advertised_label,
            EXPECTED_ADVERTISED_MEDIA_LABEL,
            "minimumAdvertisedMediaLabel",
        ),
        (
            vault_profile_version,
            EXPECTED_VAULT_PROFILE_VERSION,
            "vaultProfileVersion",
        ),
        (
            vault_profile_sha256,
            EXPECTED_VAULT_PROFILE_SHA256,
            "vaultProfileSha256",
        ),
        (vault_number, EXPECTED_VAULT_NUMBER, "vaultPartition.number"),
        (vault_name, EXPECTED_VAULT_NAME, "vaultPartition.name"),
        (vault_type, EXPECTED_VAULT_TYPE, "vaultPartition.mbrType"),
        (
            vault_start_lba,
            EXPECTED_VAULT_START_LBA,
            "vaultPartition.startLba",
        ),
        (
            vault_sectors,
            EXPECTED_VAULT_SECTORS,
            "vaultPartition.sectorCount",
        ),
    )
    for actual, expected, location in immutable_values:
        if actual != expected:
            raise LayoutError(
                f"manifest.{location} changes immutable layout-v1 geometry"
            )
    if layout.vault_end_bytes != layout.minimum_media_bytes:
        raise LayoutError("minimum media bytes must equal the end of the vault partition")
    if layout.minimum_advertised_media_bytes < layout.minimum_media_bytes:
        raise LayoutError("advertised media capacity cannot be below the layout minimum")
    _verify_vault_profile(path.with_name(VAULT_PROFILE_FILENAME))
    return layout


def _partition_offset(slot: int) -> int:
    if slot < 1 or slot > 4:
        raise LayoutError(f"invalid MBR partition slot: {slot}")
    return PARTITION_TABLE_OFFSET + (slot - 1) * PARTITION_ENTRY_BYTES


def _parse_partition(mbr: bytes, slot: int) -> PartitionEntry:
    if len(mbr) != MBR_BYTES:
        raise LayoutError("MBR read must be exactly 512 bytes")
    offset = _partition_offset(slot)
    raw = mbr[offset : offset + PARTITION_ENTRY_BYTES]
    start_lba, sector_count = struct.unpack_from("<II", raw, 8)
    return PartitionEntry(
        slot=slot,
        raw=raw,
        status=raw[0],
        type_code=raw[4],
        start_lba=start_lba,
        sector_count=sector_count,
    )


def _encode_partition(
    *, status: int, type_code: int, start_lba: int, sector_count: int
) -> bytes:
    for value, location in (
        (status, "status"),
        (type_code, "type"),
    ):
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or not 0 <= value <= 0xFF
        ):
            raise LayoutError(f"partition {location} must fit in one byte")
    for value, location in (
        (start_lba, "start LBA"),
        (sector_count, "sector count"),
    ):
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or value <= 0
            or value >= UINT32_LIMIT
        ):
            raise LayoutError(
                f"partition {location} must fit a non-zero unsigned 32-bit field"
            )
    if start_lba + sector_count > UINT32_LIMIT:
        raise LayoutError("partition end exceeds the MBR LBA address space")
    maximum_chs = b"\xfe\xff\xff"
    return (
        bytes((status,))
        + maximum_chs
        + bytes((type_code,))
        + maximum_chs
        + struct.pack("<II", start_lba, sector_count)
    )


def expected_vault_entry(layout: DeviceLayout) -> bytes:
    return _encode_partition(
        status=0,
        type_code=layout.vault_type,
        start_lba=layout.vault_start_lba,
        sector_count=layout.vault_sector_count,
    )


def _validate_occupied_partition(
    entry: PartitionEntry, image_sector_count: int
) -> None:
    if entry.is_empty:
        raise LayoutError(f"MBR partition slot {entry.slot} must be populated")
    if entry.status not in (0x00, 0x80):
        raise LayoutError(f"MBR partition slot {entry.slot} has invalid status")
    if entry.start_lba == 0 or entry.sector_count == 0:
        raise LayoutError(f"MBR partition slot {entry.slot} has an empty LBA range")
    if entry.end_lba > UINT32_LIMIT:
        raise LayoutError(f"MBR partition slot {entry.slot} exceeds MBR bounds")
    if entry.end_lba > image_sector_count:
        raise LayoutError(f"MBR partition slot {entry.slot} extends beyond ISO EOF")


def _ranges_overlap(first: PartitionEntry, second: PartitionEntry) -> bool:
    return first.start_lba < second.end_lba and second.start_lba < first.end_lba


def _is_debian_isohybrid_envelope(
    first: PartitionEntry, second: PartitionEntry
) -> bool:
    # Debian's isohybrid MBR intentionally uses a bootable type-0x00 slot 1 as
    # an image envelope, with the UEFI 0xEF partition in slot 2 nested inside.
    return (
        first.status == 0x80
        and first.type_code == 0x00
        and second.status == 0x00
        and second.type_code == 0xEF
        and first.start_lba < second.start_lba
        and second.end_lba <= first.end_lba
    )


def _validate_mbr(
    mbr: bytes,
    *,
    image_size: int,
    layout: DeviceLayout,
    require_finalized: bool,
) -> bool:
    if len(mbr) != MBR_BYTES:
        raise LayoutError("image is too small for an MBR")
    if mbr[MBR_SIGNATURE_OFFSET:] != MBR_SIGNATURE:
        raise LayoutError("image does not have the MBR boot signature 0x55aa")
    if image_size >= layout.vault_start_bytes:
        raise LayoutError("ISO EOF must remain strictly before the vault start")

    image_sector_count = (image_size + layout.logical_sector_bytes - 1) // (
        layout.logical_sector_bytes
    )
    first = _parse_partition(mbr, 1)
    second = _parse_partition(mbr, 2)
    third = _parse_partition(mbr, 3)
    fourth = _parse_partition(mbr, 4)
    _validate_occupied_partition(first, image_sector_count)
    _validate_occupied_partition(second, image_sector_count)
    if first.status != 0x80:
        raise LayoutError("MBR partition slot 1 must be the bootable entry")
    if second.status != 0x00:
        raise LayoutError("MBR partition slot 2 must not be bootable")
    if first.start_lba >= second.start_lba:
        raise LayoutError("MBR partition slots 1 and 2 are not in ascending order")
    overlap = _ranges_overlap(first, second)
    isohybrid_envelope = _is_debian_isohybrid_envelope(first, second)
    if overlap and not isohybrid_envelope:
        raise LayoutError(
            "MBR partition slots 1 and 2 overlap outside the Debian isohybrid envelope"
        )
    if first.type_code == 0x00 and not isohybrid_envelope:
        raise LayoutError(
            "MBR type-0x00 slot 1 is valid only as the Debian isohybrid envelope"
        )

    expected = expected_vault_entry(layout)
    if not fourth.is_empty:
        raise LayoutError("MBR partition slot 4 must be all-zero and reserved")
    if third.raw == expected:
        return True
    if not third.is_empty:
        raise LayoutError("MBR partition slot 3 conflicts with immutable layout-v1")
    if require_finalized:
        raise LayoutError("MBR partition slot 3 has not been finalized")
    return False


def _pread_exact(descriptor: int, length: int, offset: int) -> bytes:
    chunks: list[bytes] = []
    consumed = 0
    while consumed < length:
        chunk = os.pread(descriptor, length - consumed, offset + consumed)
        if not chunk:
            break
        chunks.append(chunk)
        consumed += len(chunk)
    value = b"".join(chunks)
    if len(value) != length:
        raise LayoutError(f"short image read at byte offset {offset}")
    return value


def _pwrite_exact(descriptor: int, value: bytes, offset: int) -> None:
    written = 0
    while written < len(value):
        count = os.pwrite(descriptor, value[written:], offset + written)
        if count <= 0:
            raise LayoutError(f"short image write at byte offset {offset + written}")
        written += count


def process_image(
    image_path: Path, layout: DeviceLayout, *, verify_only: bool
) -> FinalizeResult:
    flags = (os.O_RDONLY if verify_only else os.O_RDWR) | getattr(
        os, "O_CLOEXEC", 0
    )
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(image_path, flags)
    except OSError as error:
        raise LayoutError(f"cannot open image: {error}") from error
    try:
        metadata_before = os.fstat(descriptor)
        if not stat.S_ISREG(metadata_before.st_mode):
            raise LayoutError("image must be a regular file, never a block device")
        mbr_before = _pread_exact(descriptor, MBR_BYTES, 0)
        finalized = _validate_mbr(
            mbr_before,
            image_size=metadata_before.st_size,
            layout=layout,
            require_finalized=verify_only,
        )
        expected = expected_vault_entry(layout)
        if verify_only:
            action = "verified"
        elif finalized:
            action = "already-finalized"
        else:
            _pwrite_exact(descriptor, expected, _partition_offset(layout.vault_number))
            os.fsync(descriptor)
            action = "finalized"

        metadata_after = os.fstat(descriptor)
        if metadata_after.st_size != metadata_before.st_size:
            raise LayoutError("finalization changed the ISO file size")
        mbr_after = _pread_exact(descriptor, MBR_BYTES, 0)
        _validate_mbr(
            mbr_after,
            image_size=metadata_after.st_size,
            layout=layout,
            require_finalized=True,
        )
        if mbr_before[: _partition_offset(layout.vault_number)] != mbr_after[
            : _partition_offset(layout.vault_number)
        ] or mbr_before[
            _partition_offset(layout.vault_number) + PARTITION_ENTRY_BYTES :
        ] != mbr_after[
            _partition_offset(layout.vault_number) + PARTITION_ENTRY_BYTES :
        ]:
            raise LayoutError("bytes outside MBR partition slot 3 changed")
        return FinalizeResult(
            action=action,
            image_size=metadata_after.st_size,
            vault_entry=expected,
        )
    finally:
        os.close(descriptor)


def _argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Finalize or verify KernAid Rescue MBR layout-v1"
    )
    subparsers = parser.add_subparsers(dest="operation", required=True)
    for operation in ("finalize", "verify"):
        operation_parser = subparsers.add_parser(operation)
        operation_parser.add_argument("--image", required=True, type=Path)
        operation_parser.add_argument("--manifest", required=True, type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _argument_parser().parse_args(argv)
    try:
        layout = parse_layout_manifest(arguments.manifest)
        result = process_image(
            arguments.image, layout, verify_only=arguments.operation == "verify"
        )
    except LayoutError as error:
        print(f"device layout error: {error}", file=sys.stderr)
        return 2
    print(
        f"layout-v1 {result.action}: image_bytes={result.image_size} "
        f"vault_start_lba={layout.vault_start_lba} "
        f"vault_sector_count={layout.vault_sector_count}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
