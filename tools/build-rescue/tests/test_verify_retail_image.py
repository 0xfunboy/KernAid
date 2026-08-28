from __future__ import annotations

import importlib.util
import hashlib
import lzma
import subprocess
from pathlib import Path
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "verify-retail-image.py"


class VerifyRetailImageTests(unittest.TestCase):
    def setUp(self) -> None:
        spec = importlib.util.spec_from_file_location("verify_retail_image", SCRIPT)
        assert spec is not None and spec.loader is not None
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        self.module.RAW_BYTES = 4096
        self.module.P3_START = 2048
        self.module.P3_BYTES = 1024
        self.module.P3_ZERO_SHA256 = hashlib.sha256(b"\0" * 1024).hexdigest()
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.iso = self.root / "KernAid-Rescue-amd64.iso"
        self.archive = self.root / "KernAid-Rescue-amd64-retail.img.xz"
        self.iso.write_bytes(b"exact-iso-prefix")

    def write_raw(self, raw: bytes) -> None:
        with lzma.open(self.archive, "wb", preset=6, check=lzma.CHECK_SHA256) as output:
            output.write(raw)

    def test_accepts_exact_prefix_and_zero_remainder(self) -> None:
        raw = self.iso.read_bytes().ljust(self.module.RAW_BYTES, b"\0")
        self.write_raw(raw)
        metadata = self.module.verify(self.iso, self.archive)
        self.assertEqual(metadata["raw"]["bytes"], self.module.RAW_BYTES)
        self.assertTrue(metadata["p3"]["zero"])
        self.assertTrue(metadata["tailZero"])

    def test_rejects_nonzero_tail(self) -> None:
        raw = bytearray(self.iso.read_bytes().ljust(self.module.RAW_BYTES, b"\0"))
        raw[self.module.P3_START] = 1
        self.write_raw(bytes(raw))
        with self.assertRaisesRegex(RuntimeError, "non-zero bytes"):
            self.module.verify(self.iso, self.archive)

    def test_rejects_compressed_asset_at_the_release_bound_before_decompression(self) -> None:
        self.archive.write_bytes(b"not-an-xz")
        self.module.MAX_COMPRESSED_BYTES = self.archive.stat().st_size - 1
        with self.assertRaisesRegex(RuntimeError, "outside fixed bounds"):
            self.module.verify(self.iso, self.archive)

    def test_shipping_xz_command_is_deterministic_on_sparse_fixture(self) -> None:
        raw = self.root / "KernAid-Rescue-amd64-retail.img"
        with raw.open("xb") as output:
            output.write(self.iso.read_bytes())
            output.truncate(self.module.RAW_BYTES)
        command = [
            "env", "-u", "XZ_OPT", "-u", "XZ_DEFAULTS", "xz",
            "--format=xz", "--threads=1", "--check=sha256",
            "--lzma2=preset=6", "--stdout", "--", str(raw),
        ]
        second = self.root / "second.img.xz"
        for destination in (self.archive, second):
            with destination.open("xb") as output:
                subprocess.run(command, check=True, stdout=output, timeout=10)
        self.assertEqual(self.archive.read_bytes(), second.read_bytes())
        self.module.verify(self.iso, self.archive)


if __name__ == "__main__":
    unittest.main()
