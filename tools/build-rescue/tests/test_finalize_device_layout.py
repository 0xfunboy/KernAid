from __future__ import annotations

import importlib.util
import json
import os
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


TOOLS_DIR = Path(__file__).resolve().parents[1]
REPO_DIR = Path(__file__).resolve().parents[3]
MODULE_PATH = TOOLS_DIR / "finalize-device-layout.py"
MANIFEST_PATH = REPO_DIR / "rescue/image-layout/device-layout.v1.json"
SPEC = importlib.util.spec_from_file_location("kernaid_device_layout", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
device_layout = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = device_layout
SPEC.loader.exec_module(device_layout)


def partition_entry(
    *, status: int, type_code: int, start_lba: int, sector_count: int
) -> bytes:
    return (
        bytes((status,))
        + b"\x00\x02\x00"
        + bytes((type_code,))
        + b"\xfe\xff\xff"
        + struct.pack("<II", start_lba, sector_count)
    )


def mbr_bytes(
    *,
    first: bytes | None = None,
    second: bytes | None = None,
    third: bytes | None = None,
    fourth: bytes | None = None,
    valid_signature: bool = True,
) -> bytes:
    # This is the exact exceptional shape emitted by Debian isohybrid:
    # bootable type-0x00 p1 contains the type-0xEF ESP in p2.
    first = first or partition_entry(
        status=0x80, type_code=0x00, start_lba=64, sector_count=8000
    )
    second = second or partition_entry(
        status=0x00, type_code=0xEF, start_lba=512, sector_count=256
    )
    value = bytearray(device_layout.MBR_BYTES)
    value[:32] = bytes(range(32))
    for slot, entry in enumerate(
        (first, second, third or bytes(16), fourth or bytes(16)), start=1
    ):
        offset = device_layout._partition_offset(slot)
        value[offset : offset + 16] = entry
    value[510:512] = b"\x55\xaa" if valid_signature else b"\x00\x00"
    return bytes(value)


def write_sparse_image(path: Path, mbr: bytes, *, size: int = 4 * 1024 * 1024) -> None:
    with path.open("wb") as stream:
        stream.write(mbr)
        stream.truncate(size)


class ManifestTests(unittest.TestCase):
    def test_repository_manifest_has_exact_immutable_geometry(self) -> None:
        layout = device_layout.parse_layout_manifest(MANIFEST_PATH)
        self.assertEqual(layout.logical_sector_bytes, 512)
        self.assertEqual(layout.vault_number, 3)
        self.assertEqual(layout.vault_name, "KERNAID_VAULT")
        self.assertEqual(layout.vault_type, 0x83)
        self.assertEqual(layout.vault_start_lba, 33_554_432)
        self.assertEqual(layout.vault_sector_count, 16_777_216)
        self.assertEqual(layout.vault_start_bytes, 16 * 1024**3)
        self.assertEqual(layout.vault_end_bytes, 24 * 1024**3)
        self.assertEqual(layout.minimum_media_bytes, 24 * 1024**3)
        self.assertEqual(layout.minimum_advertised_media_bytes, 32_000_000_000)
        self.assertEqual(layout.minimum_advertised_media_label, "32 GB")

    def _write_manifest(self, directory: Path, document: object) -> Path:
        path = directory / "layout.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        return path

    def test_rejects_malformed_json_and_duplicate_keys(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            malformed = directory / "malformed.json"
            malformed.write_text("{", encoding="utf-8")
            with self.assertRaisesRegex(device_layout.LayoutError, "strict UTF-8 JSON"):
                device_layout.parse_layout_manifest(malformed)

            duplicate = directory / "duplicate.json"
            duplicate.write_text('{"schema":"a","schema":"b"}', encoding="utf-8")
            with self.assertRaisesRegex(device_layout.LayoutError, "duplicate key"):
                device_layout.parse_layout_manifest(duplicate)

    def test_rejects_missing_extra_and_non_integer_fields(self) -> None:
        document = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            missing = dict(document)
            del missing["partitionTable"]
            with self.assertRaisesRegex(device_layout.LayoutError, "keys are not exact"):
                device_layout.parse_layout_manifest(
                    self._write_manifest(directory, missing)
                )

            extra = dict(document)
            extra["unexpected"] = 1
            with self.assertRaisesRegex(device_layout.LayoutError, "keys are not exact"):
                device_layout.parse_layout_manifest(
                    self._write_manifest(directory, extra)
                )

            boolean = dict(document)
            boolean["logicalSectorBytes"] = True
            with self.assertRaisesRegex(device_layout.LayoutError, "must be an integer"):
                device_layout.parse_layout_manifest(
                    self._write_manifest(directory, boolean)
                )

    def test_rejects_changed_or_out_of_bounds_geometry(self) -> None:
        document = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            changed = json.loads(json.dumps(document))
            changed["vaultPartition"]["startLba"] += 1
            with self.assertRaisesRegex(device_layout.LayoutError, "immutable layout-v1"):
                device_layout.parse_layout_manifest(
                    self._write_manifest(directory, changed)
                )

            out_of_bounds = json.loads(json.dumps(document))
            out_of_bounds["vaultPartition"]["startLba"] = 1 << 32
            with self.assertRaisesRegex(device_layout.LayoutError, "unsigned 32-bit"):
                device_layout.parse_layout_manifest(
                    self._write_manifest(directory, out_of_bounds)
                )

            wrong_encoding = json.loads(json.dumps(document))
            wrong_encoding["vaultPartition"]["mbrType"] = "83"
            with self.assertRaisesRegex(device_layout.LayoutError, "must be 0xNN"):
                device_layout.parse_layout_manifest(
                    self._write_manifest(directory, wrong_encoding)
                )


class FinalizerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.layout = device_layout.parse_layout_manifest(MANIFEST_PATH)

    def _image(self, directory: Path, **mbr_arguments: object) -> Path:
        path = directory / "rescue.iso"
        write_sparse_image(path, mbr_bytes(**mbr_arguments))
        return path

    def test_finalizes_only_exact_slot_three_offsets_without_growth(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = self._image(Path(temporary))
            before = path.read_bytes()
            size_before = path.stat().st_size

            result = device_layout.process_image(
                path, self.layout, verify_only=False
            )

            after = path.read_bytes()
            self.assertEqual(result.action, "finalized")
            self.assertEqual(path.stat().st_size, size_before)
            offset = device_layout._partition_offset(3)
            expected = device_layout.expected_vault_entry(self.layout)
            self.assertEqual(after[offset : offset + 16], expected)
            changed = {
                index
                for index, (old_byte, new_byte) in enumerate(zip(before, after))
                if old_byte != new_byte
            }
            expected_changed = {
                offset + index for index, byte in enumerate(expected) if byte != 0
            }
            self.assertEqual(changed, expected_changed)
            self.assertEqual(struct.unpack("<II", expected[8:16]), (33_554_432, 16_777_216))
            self.assertNotEqual(
                struct.unpack(">II", expected[8:16]), (33_554_432, 16_777_216)
            )

    def test_is_idempotent_only_for_the_exact_existing_entry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = self._image(Path(temporary))
            device_layout.process_image(path, self.layout, verify_only=False)
            before = path.read_bytes()
            with mock.patch.object(
                device_layout,
                "_pwrite_exact",
                side_effect=AssertionError("idempotence attempted a write"),
            ):
                result = device_layout.process_image(
                    path, self.layout, verify_only=False
                )
            self.assertEqual(result.action, "already-finalized")
            self.assertEqual(path.read_bytes(), before)

    def test_verify_is_read_only_and_requires_finalization(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = self._image(Path(temporary))
            with self.assertRaisesRegex(device_layout.LayoutError, "not been finalized"):
                device_layout.process_image(path, self.layout, verify_only=True)
            device_layout.process_image(path, self.layout, verify_only=False)
            with mock.patch.object(
                device_layout,
                "_pwrite_exact",
                side_effect=AssertionError("verify attempted a write"),
            ):
                result = device_layout.process_image(
                    path, self.layout, verify_only=True
                )
            self.assertEqual(result.action, "verified")

    def test_accepts_only_the_exact_debian_isohybrid_overlap(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = self._image(Path(temporary))
            result = device_layout.process_image(
                path, self.layout, verify_only=False
            )
            self.assertEqual(result.action, "finalized")

    def test_accepts_conventional_disjoint_ordered_partitions(self) -> None:
        first = partition_entry(
            status=0x80, type_code=0x17, start_lba=64, sector_count=256
        )
        second = partition_entry(
            status=0, type_code=0xEF, start_lba=512, sector_count=256
        )
        with tempfile.TemporaryDirectory() as temporary:
            path = self._image(Path(temporary), first=first, second=second)
            result = device_layout.process_image(
                path, self.layout, verify_only=False
            )
            self.assertEqual(result.action, "finalized")

    def test_rejects_every_other_partition_overlap(self) -> None:
        cases = {
            "wrong envelope type": (
                partition_entry(
                    status=0x80,
                    type_code=0x17,
                    start_lba=64,
                    sector_count=8000,
                ),
                partition_entry(
                    status=0, type_code=0xEF, start_lba=512, sector_count=256
                ),
            ),
            "wrong nested type": (
                partition_entry(
                    status=0x80,
                    type_code=0x00,
                    start_lba=64,
                    sector_count=8000,
                ),
                partition_entry(
                    status=0, type_code=0x83, start_lba=512, sector_count=256
                ),
            ),
            "partial containment": (
                partition_entry(
                    status=0x80,
                    type_code=0x00,
                    start_lba=64,
                    sector_count=600,
                ),
                partition_entry(
                    status=0, type_code=0xEF, start_lba=512, sector_count=256
                ),
            ),
        }
        for label, (first, second) in cases.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                path = self._image(
                    Path(temporary), first=first, second=second
                )
                with self.assertRaisesRegex(device_layout.LayoutError, "overlap"):
                    device_layout.process_image(
                        path, self.layout, verify_only=False
                    )

    def test_rejects_reversed_partition_order(self) -> None:
        first = partition_entry(
            status=0x80, type_code=0x17, start_lba=1024, sector_count=128
        )
        second = partition_entry(
            status=0, type_code=0xEF, start_lba=64, sector_count=128
        )
        with tempfile.TemporaryDirectory() as temporary:
            path = self._image(Path(temporary), first=first, second=second)
            with self.assertRaisesRegex(device_layout.LayoutError, "ascending order"):
                device_layout.process_image(path, self.layout, verify_only=False)

    def test_rejects_slot_conflicts(self) -> None:
        conflicting = partition_entry(
            status=0, type_code=0x83, start_lba=2048, sector_count=4096
        )
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            third = self._image(directory, third=conflicting)
            with self.assertRaisesRegex(device_layout.LayoutError, "slot 3 conflicts"):
                device_layout.process_image(third, self.layout, verify_only=False)

            fourth_path = directory / "fourth.iso"
            write_sparse_image(fourth_path, mbr_bytes(fourth=conflicting))
            with self.assertRaisesRegex(device_layout.LayoutError, "slot 4"):
                device_layout.process_image(
                    fourth_path, self.layout, verify_only=False
                )

    def test_rejects_malformed_mbr_and_partitions_outside_iso(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            bad_signature = self._image(directory, valid_signature=False)
            with self.assertRaisesRegex(device_layout.LayoutError, "boot signature"):
                device_layout.process_image(
                    bad_signature, self.layout, verify_only=False
                )

            outside_path = directory / "outside.iso"
            outside = partition_entry(
                status=0, type_code=0xEF, start_lba=7000, sector_count=2000
            )
            write_sparse_image(outside_path, mbr_bytes(second=outside))
            with self.assertRaisesRegex(device_layout.LayoutError, "beyond ISO EOF"):
                device_layout.process_image(
                    outside_path, self.layout, verify_only=False
                )

            short_path = directory / "short.iso"
            short_path.write_bytes(b"too short")
            with self.assertRaisesRegex(device_layout.LayoutError, "short image read"):
                device_layout.process_image(
                    short_path, self.layout, verify_only=False
                )

    def test_rejects_iso_eof_at_or_after_vault_start(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for label, size in (
                ("at", self.layout.vault_start_bytes),
                ("after", self.layout.vault_start_bytes + 1),
            ):
                with self.subTest(label=label):
                    path = directory / f"{label}.iso"
                    write_sparse_image(path, mbr_bytes(), size=size)
                    with self.assertRaisesRegex(
                        device_layout.LayoutError, "strictly before"
                    ):
                        device_layout.process_image(
                            path, self.layout, verify_only=False
                        )

    def test_rejects_non_regular_image(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with self.assertRaisesRegex(
                device_layout.LayoutError, "regular file|cannot open image"
            ):
                device_layout.process_image(
                    directory, self.layout, verify_only=False
                )

            target = directory / "target.iso"
            write_sparse_image(target, mbr_bytes())
            symlink = directory / "link.iso"
            symlink.symlink_to(target)
            with self.assertRaisesRegex(device_layout.LayoutError, "cannot open image"):
                device_layout.process_image(
                    symlink, self.layout, verify_only=False
                )


class EncodingTests(unittest.TestCase):
    def test_partition_encoder_rejects_field_and_end_overflow(self) -> None:
        with self.assertRaisesRegex(device_layout.LayoutError, "unsigned 32-bit"):
            device_layout._encode_partition(
                status=0,
                type_code=0x83,
                start_lba=1 << 32,
                sector_count=2,
            )
        with self.assertRaisesRegex(device_layout.LayoutError, "address space"):
            device_layout._encode_partition(
                status=0,
                type_code=0x83,
                start_lba=(1 << 32) - 1,
                sector_count=2,
            )


if __name__ == "__main__":
    unittest.main()
