from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import signal
import stat
import subprocess
import sys
import tempfile
import base64
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest import mock


TOOLS_DIR = Path(__file__).resolve().parents[1]
REPO_DIR = Path(__file__).resolve().parents[3]
CORE_PATH = TOOLS_DIR / "make_device_v2.py"
LAUNCHER_PATH = TOOLS_DIR / "make-device-v2.py"
MANIFEST_PATH = REPO_DIR / "rescue/image-layout/device-layout.v1.json"
PROFILE_PATH = REPO_DIR / "rescue/image-layout/vault-profile.v1.json"


def load_module():
    specification = importlib.util.spec_from_file_location(
        "test_kernaid_make_device_v2", CORE_PATH
    )
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


writer = load_module()


def candidate(*, size: int = 32_000_000_000):
    return SimpleNamespace(size=size)


def mbr_slot3(*, start_lba: int = 33_554_432, sectors: int = 16_777_216, type_code: int = 0x83):
    sector = bytearray(512)
    entry = 446 + 2 * 16
    sector[entry + 4] = type_code
    sector[entry + 8 : entry + 12] = start_lba.to_bytes(4, "little")
    sector[entry + 12 : entry + 16] = sectors.to_bytes(4, "little")
    sector[510:512] = b"\x55\xaa"
    return sector


class CatalogAndLayoutTests(unittest.TestCase):
    def setUp(self) -> None:
        self.layout = writer.catalog_v2.load_device_layout(MANIFEST_PATH)

    def test_checked_in_empty_catalog_is_inactive_without_v1_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / writer.LAYOUT_FILENAME).write_bytes(MANIFEST_PATH.read_bytes())
            (directory / writer.catalog_v2.VAULT_PROFILE_FILENAME).write_bytes(
                PROFILE_PATH.read_bytes()
            )
            (directory / writer.CATALOG_FILENAME).write_text(
                json.dumps(
                    {
                        "schema": "dev.kernaid.trusted-rescue-images.v2",
                        "catalogRevision": 0,
                        "images": [],
                    }
                ),
                encoding="utf-8",
            )
            with mock.patch.object(writer, "MODULE_DIRECTORY", directory):
                with self.assertRaisesRegex(writer.SafetyError, "inactive"):
                    writer.load_installed_trust()

    def test_media_claim_requires_full_32_billion_bytes(self) -> None:
        writer.validate_v2_candidate(candidate(), self.layout)
        with self.assertRaisesRegex(writer.SafetyError, "32000000000"):
            writer.validate_v2_candidate(candidate(size=31_999_999_999), self.layout)

    def test_writer_constants_are_cryptographically_bound_to_profile(self) -> None:
        writer.verify_implemented_vault_profile()
        self.assertEqual(
            writer.implemented_vault_profile_document(),
            writer.catalog_v2.VAULT_PROFILE_DOCUMENT,
        )
        with mock.patch.object(writer, "LUKS_PBKDF_MEMORY_KIB", 32768):
            with self.assertRaisesRegex(writer.SafetyError, "canonical vault profile"):
                writer.verify_implemented_vault_profile()

    def test_finalized_iso_slot3_is_exact(self) -> None:
        with tempfile.TemporaryFile() as image_file:
            image_file.write(mbr_slot3())
            image_file.flush()
            image = SimpleNamespace(size=4096)
            writer.verify_finalized_image_layout(image_file.fileno(), image, self.layout)

    def test_finalized_iso_rejects_geometry_type_and_overlap(self) -> None:
        mutations = (
            mbr_slot3(start_lba=33_554_433),
            mbr_slot3(sectors=16_777_215),
            mbr_slot3(type_code=0x07),
        )
        for content in mutations:
            with self.subTest(content=hashlib.sha256(content).hexdigest()):
                with tempfile.TemporaryFile() as image_file:
                    image_file.write(content)
                    image_file.flush()
                    with self.assertRaisesRegex(writer.SafetyError, "diverges"):
                        writer.verify_finalized_image_layout(
                            image_file.fileno(), SimpleNamespace(size=4096), self.layout
                        )
        with tempfile.TemporaryFile() as image_file:
            image_file.write(mbr_slot3())
            image_file.flush()
            with self.assertRaisesRegex(writer.SafetyError, "overlaps"):
                writer.verify_finalized_image_layout(
                    image_file.fileno(),
                    SimpleNamespace(size=33_554_432 * 512 + 1),
                    self.layout,
                )

    def test_finalized_iso_rejects_other_mbr_slot_overlapping_vault(self) -> None:
        content = mbr_slot3()
        slot_one = 446
        content[slot_one + 4] = 0x83
        content[slot_one + 8 : slot_one + 12] = (33_554_431).to_bytes(4, "little")
        content[slot_one + 12 : slot_one + 16] = (2).to_bytes(4, "little")
        with tempfile.TemporaryFile() as image_file:
            image_file.write(content)
            image_file.flush()
            with self.assertRaisesRegex(writer.SafetyError, "slot 1 overlaps"):
                writer.verify_finalized_image_layout(
                    image_file.fileno(), SimpleNamespace(size=4096), self.layout
                )


class MachineFormatParserTests(unittest.TestCase):
    @staticmethod
    def luks_profile_document() -> dict[str, object]:
        encoded = base64.b64encode(b"x" * 32).decode("ascii")
        return {
            "keyslots": {
                "0": {
                    "type": "luks2",
                    "key_size": 64,
                    "af": {"type": "luks1", "stripes": 4000, "hash": "sha256"},
                    "area": {
                        "type": "raw",
                        "offset": "32768",
                        "size": "258048",
                        "encryption": writer.LUKS_CIPHER,
                        "key_size": 64,
                    },
                    "kdf": {
                        "type": "argon2id",
                        "time": 4,
                        "memory": 65536,
                        "cpus": 1,
                        "salt": encoded,
                    },
                }
            },
            "tokens": {},
            "segments": {
                "0": {
                    "type": "crypt",
                    "offset": "16777216",
                    "size": "dynamic",
                    "iv_tweak": "0",
                    "encryption": writer.LUKS_CIPHER,
                    "sector_size": 512,
                }
            },
            "digests": {
                "0": {
                    "type": "pbkdf2",
                    "keyslots": ["0"],
                    "segments": ["0"],
                    "hash": "sha256",
                    "iterations": 1000,
                    "salt": encoded,
                    "digest": encoded,
                }
            },
            "config": {"json_size": "12288", "keyslots_size": "16744448"},
        }

    def test_blkid_export_is_strict_and_locale_independent(self) -> None:
        parsed = writer.parse_blkid_export(
            b"DEVNAME=/dev/dm-2\nUUID=11111111-1111-1111-1111-111111111111\n"
            b"LABEL=KERNAID_VAULT\nTYPE=ext4\n"
        )
        self.assertEqual(parsed["TYPE"], "ext4")
        for raw in (
            b"TYPE=ext4\nTYPE=crypto_LUKS\n",
            b"localized text without equals\n",
            b"TYPE=ext4\nLABEL=bad\x00value\n",
            b"",
        ):
            with self.subTest(raw=raw):
                with self.assertRaises(writer.SafetyError):
                    writer.parse_blkid_export(raw)

    def test_udev_parser_binds_bus_serial_path_and_rejects_duplicates(self) -> None:
        target = SimpleNamespace(
            serial="USB-7", vendor="KernAid", model="Flash"
        )
        proof = writer.parse_udev_properties(
            b"ID_BUS=usb\nID_TYPE=disk\nID_SERIAL_SHORT=USB-7\n"
            b"ID_PATH=pci-0000-usb-0:1\nID_MODEL=Flash\n",
            target,
        )
        self.assertEqual(dict(proof.properties)["ID_PATH"], "pci-0000-usb-0:1")
        rejected = (
            b"ID_BUS=ata\nID_SERIAL_SHORT=USB-7\nID_PATH=x\n",
            b"ID_BUS=usb\nID_SERIAL_SHORT=OTHER\nID_PATH=x\n",
            b"ID_BUS=usb\nID_SERIAL_SHORT=USB-7\n",
            b"ID_BUS=usb\nID_BUS=usb\nID_SERIAL_SHORT=USB-7\nID_PATH=x\n",
        )
        for raw in rejected:
            with self.subTest(raw=raw):
                with self.assertRaises(writer.SafetyError):
                    writer.parse_udev_properties(raw, target)

    def test_mountinfo_parser_keeps_exact_path_and_machine_fields(self) -> None:
        raw = (
            "44 31 253:7 / /run/kernaid-make-device-v2.ABCDEF "
            "ro,nosuid,nodev,noexec,nosymfollow - ext4 /dev/mapper/x rw\n"
        )
        with mock.patch.object(writer.v1, "_read_bounded", return_value=raw):
            rows = writer.parse_mountinfo_for_path(
                "/run/kernaid-make-device-v2.ABCDEF"
            )
        self.assertEqual(rows[0][0], "253:7")
        self.assertEqual(rows[0][1], "ext4")
        self.assertIn("nosymfollow", rows[0][2])

    def test_luks_json_profile_is_exact_and_host_default_independent(self) -> None:
        document = self.luks_profile_document()

        def verify(value: object) -> None:
            rendered = json.dumps(value, separators=(",", ":")).encode("ascii")
            with (
                mock.patch.object(writer, "_fixed_binary", return_value="/usr/sbin/cryptsetup"),
                mock.patch.object(
                    writer,
                    "run_command",
                    return_value=writer.CommandResult(0, rendered, b""),
                ),
            ):
                writer.verify_luks_json_profile(51)

        verify(document)
        changed = json.loads(json.dumps(document))
        changed["keyslots"]["0"]["kdf"]["memory"] = 32768
        with self.assertRaisesRegex(writer.WriteError, "KDF memory"):
            verify(changed)

    def test_ext4_binary_superblock_profile_is_exact(self) -> None:
        expected_uuid = "22222222-2222-4222-8222-222222222222"
        block = bytearray(1024)

        def u16(offset: int, value: int) -> None:
            writer.struct.pack_into("<H", block, offset, value)

        def u32(offset: int, value: int) -> None:
            writer.struct.pack_into("<I", block, offset, value)

        u32(0x04, 262144)
        u32(0x00, 65536)
        u32(0x08, 0)
        u32(0x18, 2)
        u32(0x1C, 2)
        u32(0x20, writer.EXT4_BLOCKS_PER_GROUP)
        u32(0x24, writer.EXT4_BLOCKS_PER_GROUP)
        u32(0x28, 8192)
        u16(0x36, 0xFFFF)
        u16(0x38, 0xEF53)
        u16(0x3A, 1)
        u16(0x3C, 2)
        u32(0x44, 0)
        u32(0x48, 0)
        u32(0x4C, 1)
        u32(0x54, 11)
        u16(0x58, writer.EXT4_INODE_BYTES)
        u32(0x5C, writer.EXT4_COMPAT_FEATURES)
        u32(0x60, writer.EXT4_INCOMPAT_FEATURES)
        u32(0x64, writer.EXT4_RO_COMPAT_FEATURES)
        block[0x68:0x78] = writer.uuid.UUID(expected_uuid).bytes
        block[0x78:0x88] = writer.VAULT_LABEL.encode("ascii").ljust(16, b"\x00")
        u32(0xE0, 8)
        block[0xFD] = 1
        u32(0x14C, writer.EXT4_JOURNAL_MIB * 1024 * 1024)
        u16(0xFE, 64)
        u32(0x100, 0)
        block[0x174] = writer.EXT4_FLEX_GROUP_LOG

        def pread(_fd: int, amount: int, offset: int) -> bytes:
            if (amount, offset) == (1024, 1024):
                return bytes(block)
            self.fail(f"unexpected pread amount={amount} offset={offset}")

        with mock.patch.object(writer.os, "pread", side_effect=pread):
            writer.verify_ext4_superblock(
                51, expected_uuid, capacity_bytes=1024 * 1024 * 1024
            )
        mutations = (
            ("bytes per inode", lambda: u32(0x00, 32768)),
            ("flex group", lambda: block.__setitem__(0x174, 3)),
            (
                "journal size",
                lambda: u32(0x14C, 64 * 1024 * 1024),
            ),
        )
        for label, mutate in mutations:
            with self.subTest(label=label):
                saved_block = bytes(block)
                mutate()
                with mock.patch.object(writer.os, "pread", side_effect=pread):
                    with self.assertRaisesRegex(writer.WriteError, "profile|journal"):
                        writer.verify_ext4_superblock(
                            51,
                            expected_uuid,
                            capacity_bytes=1024 * 1024 * 1024,
                        )
                block[:] = saved_block
        u32(0x64, writer.EXT4_RO_COMPAT_FEATURES | 0x100)
        with mock.patch.object(writer.os, "pread", side_effect=pread):
            with self.assertRaisesRegex(writer.WriteError, "profile is not exact"):
                writer.verify_ext4_superblock(
                    51, expected_uuid, capacity_bytes=1024 * 1024 * 1024
                )

    def test_profile_commands_pin_luks_and_ext4_without_host_defaults(self) -> None:
        luks = writer._luks_format_command(
            "/usr/sbin/cryptsetup",
            "/proc/self/fd/9",
            32,
            "/proc/self/fd/8",
            "1" * 36,
        )
        for option in (
            "--cipher",
            "--key-size",
            "--sector-size",
            "--pbkdf-force-iterations",
            "--pbkdf-memory",
            "--luks2-metadata-size",
            "--luks2-keyslots-size",
        ):
            self.assertIn(option, luks)
        mkfs = writer._mkfs_ext4_command(
            "/usr/sbin/mkfs.ext4", "/proc/self/fd/7", "2" * 36
        )
        self.assertIn("none,has_journal", " ".join(mkfs))
        self.assertIn("lazy_itable_init=0,lazy_journal_init=0", mkfs)


class SecretHandlingTests(unittest.TestCase):
    def test_physical_media_requires_a_distinct_exact_freshness_attestation(self) -> None:
        target = SimpleNamespace(
            path="/dev/sdz", serial="SERIAL-7", disk_sequence=81
        )
        phrase = writer.fresh_media_attestation_phrase(target)

        class TtyInput(io.StringIO):
            def isatty(self) -> bool:
                return True

        with redirect_stderr(io.StringIO()):
            self.assertTrue(
                writer.require_fresh_media_attestation(
                    target, TtyInput(phrase + "\n")
                )
            )
            with self.assertRaisesRegex(writer.SafetyError, "did not match"):
                writer.require_fresh_media_attestation(
                    target, TtyInput("FACTORY-NEW but not identity-bound\n")
                )

    def test_ci_secret_accepts_only_bounded_anonymous_pipe(self) -> None:
        read_fd, write_fd = os.pipe()
        try:
            os.write(write_fd, b"correct horse battery staple")
            os.close(write_fd)
            write_fd = -1
            secret = writer.acquire_passphrase_from_ci_fd(read_fd)
            self.assertEqual(secret, b"correct horse battery staple")
            self.assertTrue(
                writer.fcntl.fcntl(read_fd, writer.fcntl.F_GETFD)
                & writer.fcntl.FD_CLOEXEC
            )
            writer._wipe_bytearray(secret)
            self.assertEqual(secret, b"")
        finally:
            os.close(read_fd)
            if write_fd >= 0:
                os.close(write_fd)

    def test_ci_secret_rejects_regular_file_short_and_nul(self) -> None:
        with tempfile.TemporaryFile() as regular:
            regular.write(b"correct horse battery staple")
            regular.seek(0)
            with self.assertRaisesRegex(writer.SafetyError, "anonymous pipe"):
                writer.acquire_passphrase_from_ci_fd(regular.fileno())
        for value in (b"short", b"twelve-bytes\x00bad"):
            read_fd, write_fd = os.pipe()
            try:
                os.write(write_fd, value)
                os.close(write_fd)
                write_fd = -1
                with self.assertRaises(writer.SafetyError):
                    writer.acquire_passphrase_from_ci_fd(read_fd)
            finally:
                os.close(read_fd)
                if write_fd >= 0:
                    os.close(write_fd)

    def test_ci_secret_rejects_named_fifo(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fifo = Path(temporary) / "passphrase.fifo"
            os.mkfifo(fifo, 0o600)
            descriptor = os.open(fifo, os.O_RDWR | os.O_NONBLOCK)
            try:
                with self.assertRaisesRegex(writer.SafetyError, "named FIFO"):
                    writer.acquire_passphrase_from_ci_fd(descriptor)
            finally:
                os.close(descriptor)

    def test_secret_command_uses_fd_path_never_secret_argv_or_environment(self) -> None:
        secret = bytearray(b"correct horse battery staple")
        observed: dict[str, object] = {}

        def fake_run(argv, **kwargs):
            observed["argv"] = list(argv)
            observed["pass_fds"] = kwargs["pass_fds"]
            key_path = argv[-1]
            fd = int(key_path.rsplit("/", 1)[1])
            observed["secret"] = os.read(fd, 100)
            return writer.CommandResult(0, b"", b"")

        with mock.patch.object(writer, "run_command", side_effect=fake_run):
            writer.run_secret_command(
                lambda key_path, _size: ["/usr/sbin/cryptsetup", "test", key_path],
                secret,
                label="test secret command",
            )
        rendered = " ".join(observed["argv"])
        self.assertNotIn("correct horse", rendered)
        self.assertEqual(observed["secret"], bytes(secret))
        self.assertEqual(len(observed["pass_fds"]), 1)

    def test_physical_tty_path_reads_twice_and_rejects_mismatch(self) -> None:
        tty_stat = SimpleNamespace(st_mode=stat.S_IFCHR | 0o600)
        attributes = [0, 0, 0, writer.termios.ECHO, 0, 0, []]
        common = (
            mock.patch.object(writer.os, "open", return_value=71),
            mock.patch.object(writer.os, "fstat", return_value=tty_stat),
            mock.patch.object(writer.os, "isatty", return_value=True),
            mock.patch.object(writer.os, "write", return_value=1),
            mock.patch.object(writer.os, "close"),
            mock.patch.object(writer.termios, "tcgetattr", return_value=attributes),
            mock.patch.object(writer.termios, "tcsetattr"),
        )
        with common[0], common[1], common[2], common[3], common[4], common[5], common[6]:
            with mock.patch.object(
                writer,
                "_read_once_into_buffer",
                side_effect=(bytearray(b"correct horse battery"), bytearray(b"correct horse battery")),
            ) as read:
                secret = writer.acquire_passphrase_from_tty()
        self.assertEqual(read.call_count, 2)
        writer._wipe_bytearray(secret)

        with (
            mock.patch.object(writer.os, "open", return_value=72),
            mock.patch.object(writer.os, "fstat", return_value=tty_stat),
            mock.patch.object(writer.os, "isatty", return_value=True),
            mock.patch.object(writer.os, "write", return_value=1),
            mock.patch.object(writer.os, "close"),
            mock.patch.object(writer.termios, "tcgetattr", return_value=attributes),
            mock.patch.object(writer.termios, "tcsetattr"),
            mock.patch.object(
                writer,
                "_read_once_into_buffer",
                side_effect=(bytearray(b"correct horse battery"), bytearray(b"different horse battery")),
            ),
        ):
            with self.assertRaisesRegex(writer.SafetyError, "did not match"):
                writer.acquire_passphrase_from_tty()

    def test_tty_noecho_transition_always_restores_after_interrupt(self) -> None:
        tty_stat = SimpleNamespace(st_mode=stat.S_IFCHR | 0o600)
        original = [0, 0, 0, writer.termios.ECHO, 0, 0, []]
        transitions: list[list[object]] = []

        def apply_then_interrupt(_fd, _when, attributes):
            transitions.append(list(attributes))
            if len(transitions) == 1:
                raise writer.OperationInterrupted(signal.SIGTERM)

        with (
            mock.patch.object(writer.os, "open", return_value=73),
            mock.patch.object(writer.os, "fstat", return_value=tty_stat),
            mock.patch.object(writer.os, "isatty", return_value=True),
            mock.patch.object(writer.os, "write", return_value=1),
            mock.patch.object(writer.os, "close"),
            mock.patch.object(
                writer.termios,
                "tcgetattr",
                side_effect=lambda _fd: [*original[:6], list(original[6])],
            ),
            mock.patch.object(
                writer.termios, "tcsetattr", side_effect=apply_then_interrupt
            ),
        ):
            with self.assertRaises(writer.OperationInterrupted):
                writer.acquire_passphrase_from_tty()
        self.assertEqual(len(transitions), 2)
        self.assertFalse(transitions[0][3] & writer.termios.ECHO)
        self.assertTrue(transitions[1][3] & writer.termios.ECHO)

    def test_identity_seed_encoding_is_canonical_unpadded_base64url(self) -> None:
        for size in range(1, 40):
            value = bytearray(range(size))
            encoded = writer._base64url_encode(value)
            self.assertEqual(encoded, base64.urlsafe_b64encode(value).rstrip(b"="))
            writer._wipe_bytearray(encoded)


class ProcessAndLifecycleTests(unittest.TestCase):
    @staticmethod
    def mapper_identity() -> writer.MapperIdentity:
        return writer.MapperIdentity(
            name="kernaid-vault-0123456789abcdef",
            alias_path="/dev/mapper/kernaid-vault-0123456789abcdef",
            node_path="/dev/dm-7",
            major_minor="253:7",
            backing_major_minor="7:3",
            size=1024,
            node_device=41,
            node_inode=42,
            node_rdev=os.makedev(253, 7),
            dm_uuid="CRYPT-LUKS2-11111111111111111111111111111111-test",
        )

    def test_bounded_runner_rejects_ambiguous_exit_and_output(self) -> None:
        false = "/usr/bin/false" if Path("/usr/bin/false").exists() else "/bin/false"
        with mock.patch.object(
            writer, "_stop_process", wraps=writer._stop_process
        ) as stop_process:
            with self.assertRaisesRegex(writer.WriteError, "failed"):
                writer.run_command([false], label="false fixture")
        stop_process.assert_not_called()
        printf = "/usr/bin/printf" if Path("/usr/bin/printf").exists() else "/bin/printf"
        with self.assertRaisesRegex(writer.WriteError, "output exceeded"):
            writer.run_command(
                [printf, "%02048d", "0"],
                label="bounded fixture",
                maximum_output=64,
            )

    def test_bounded_runner_terminates_timed_out_process_group(self) -> None:
        started = __import__("time").monotonic()
        with self.assertRaisesRegex(writer.WriteError, "deadline"):
            writer.run_command(
                ["/usr/bin/python3", "-I", "-c", "import time; time.sleep(30)"],
                label="timeout fixture",
                timeout=0.1,
            )
        self.assertLess(__import__("time").monotonic() - started, 5)

    def test_bounded_runner_kills_orphan_holding_output_pipe(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            pid_path = Path(temporary) / "descendant.pid"
            program = (
                "import os,signal,sys,time\n"
                "pid=os.fork()\n"
                "if pid:\n"
                "    with open(sys.argv[1], 'x') as target: target.write(str(pid))\n"
                "    os._exit(0)\n"
                "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
                "time.sleep(30)\n"
            )
            with self.assertRaisesRegex(writer.WriteError, "deadline"):
                writer.run_command(
                    ["/usr/bin/python3", "-I", "-c", program, str(pid_path)],
                    label="orphan pipe fixture",
                    timeout=0.2,
                )
            descendant = int(pid_path.read_text(encoding="ascii"))
            deadline = __import__("time").monotonic() + 3
            while Path(f"/proc/{descendant}").exists() and __import__("time").monotonic() < deadline:
                __import__("time").sleep(0.02)
            self.assertFalse(Path(f"/proc/{descendant}").exists())

    def test_bounded_runner_rejects_descendant_that_closed_output_pipes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            pid_path = Path(temporary) / "detached-output-descendant.pid"
            program = (
                "import os,sys,time\n"
                "pid=os.fork()\n"
                "if pid:\n"
                "    with open(sys.argv[1], 'x') as target: target.write(str(pid))\n"
                "    os._exit(0)\n"
                "os.close(1)\n"
                "os.close(2)\n"
                "time.sleep(30)\n"
            )
            with mock.patch.object(
                writer, "_stop_process", wraps=writer._stop_process
            ) as stop_process:
                with self.assertRaisesRegex(writer.WriteError, "surviving descendants"):
                    writer.run_command(
                        ["/usr/bin/python3", "-I", "-c", program, str(pid_path)],
                        label="closed-pipe descendant fixture",
                        timeout=10,
                    )
            stop_process.assert_called_once()
            descendant = int(pid_path.read_text(encoding="ascii"))
            deadline = __import__("time").monotonic() + 3
            while Path(f"/proc/{descendant}").exists() and __import__("time").monotonic() < deadline:
                __import__("time").sleep(0.02)
            self.assertFalse(Path(f"/proc/{descendant}").exists())

    def test_signal_delivered_inside_popen_window_cleans_spawned_group(self) -> None:
        original_popen = subprocess.Popen
        spawned: list[subprocess.Popen[bytes]] = []

        def spawn_then_signal(*args, **kwargs):
            process = original_popen(*args, **kwargs)
            spawned.append(process)
            handler = signal.getsignal(signal.SIGTERM)
            self.assertTrue(callable(handler))
            handler(signal.SIGTERM, None)  # type: ignore[operator]
            return process

        with mock.patch.object(subprocess, "Popen", side_effect=spawn_then_signal):
            with self.assertRaises(writer.OperationInterrupted):
                writer.run_command(
                    ["/usr/bin/python3", "-I", "-c", "import time; time.sleep(30)"],
                    label="spawn signal fixture",
                    timeout=10,
                )
        self.assertEqual(len(spawned), 1)
        self.assertIsNotNone(spawned[0].poll())
        with self.assertRaises(ProcessLookupError):
            os.killpg(spawned[0].pid, 0)

    def test_kernel_signal_pending_in_handler_restore_window_cleans_group(self) -> None:
        original_popen = subprocess.Popen
        original_sigmask = signal.pthread_sigmask
        spawned: list[subprocess.Popen[bytes]] = []
        mask_calls = 0
        injected = False

        def capture_spawn(*args, **kwargs):
            process = original_popen(*args, **kwargs)
            spawned.append(process)
            return process

        def inject_pending_signal(how, signals):
            nonlocal mask_calls, injected
            mask_calls += 1
            if (
                not injected
                and mask_calls >= 4
                and how == signal.SIG_SETMASK
            ):
                injected = True
                os.kill(os.getpid(), signal.SIGTERM)
            return original_sigmask(how, signals)

        previous_handler = signal.getsignal(signal.SIGTERM)
        signal.signal(signal.SIGTERM, writer.v1._signal_interrupted)
        try:
            with (
                mock.patch.object(subprocess, "Popen", side_effect=capture_spawn),
                mock.patch.object(
                    writer.signal,
                    "pthread_sigmask",
                    side_effect=inject_pending_signal,
                ),
            ):
                with self.assertRaises(writer.OperationInterrupted):
                    writer.run_command(
                        [
                            "/usr/bin/python3",
                            "-I",
                            "-c",
                            "import time; time.sleep(30)",
                        ],
                        label="restore-window signal fixture",
                        timeout=10,
                    )
        finally:
            signal.signal(signal.SIGTERM, previous_handler)
            original_sigmask(signal.SIG_UNBLOCK, (signal.SIGTERM,))
        self.assertTrue(injected)
        self.assertEqual(len(spawned), 1)
        self.assertIsNotNone(spawned[0].poll())
        with self.assertRaises(ProcessLookupError):
            os.killpg(spawned[0].pid, 0)

    def test_whole_device_sector_size_is_checked_before_write(self) -> None:
        details = SimpleNamespace(
            st_mode=stat.S_IFBLK | 0o600,
            st_rdev=os.makedev(7, 9),
            st_dev=42,
            st_ino=77,
        )
        target = SimpleNamespace(
            path="/dev/loop9",
            major_minor="7:9",
            size=32_000_000_000,
            disk_sequence=901,
        )
        with (
            mock.patch.object(writer.os, "fstat", return_value=details),
            mock.patch.object(writer.os, "stat", return_value=details),
            mock.patch.object(
                writer.v1,
                "_ioctl_value",
                side_effect=(target.size, 0, target.disk_sequence, 4096),
            ),
        ):
            with self.assertRaisesRegex(writer.SafetyError, "logical sector"):
                writer._revalidate_target_fd(51, target, logical_sector_bytes=512)

    def test_ci_loop_partscan_is_identity_bound_and_required(self) -> None:
        target = SimpleNamespace(
            kind="loop",
            path="/dev/loop9",
            kname="/dev/loop9",
            major_minor="7:9",
        )
        details = SimpleNamespace(
            st_mode=stat.S_IFBLK | 0o600,
            st_rdev=os.makedev(7, 9),
            st_dev=42,
            st_ino=77,
        )
        expected_sysfs = "/sys/devices/virtual/block/loop9"

        def resolve(path: str) -> str:
            if path in ("/sys/dev/block/7:9", "/sys/class/block/loop9"):
                return expected_sysfs
            return path

        with (
            mock.patch.object(writer.os.path, "realpath", side_effect=resolve),
            mock.patch.object(writer.os.path, "isdir", return_value=True),
            mock.patch.object(writer.os, "stat", return_value=details),
            mock.patch.object(writer, "_read_small_text", return_value="1") as read,
        ):
            self.assertEqual(
                writer.verify_ci_loop_partition_scan(target), expected_sysfs
            )
        read.assert_called_once_with(
            f"{expected_sysfs}/loop/partscan", "CI loop partition-scan flag"
        )

        with (
            mock.patch.object(writer.os.path, "realpath", side_effect=resolve),
            mock.patch.object(writer.os.path, "isdir", return_value=True),
            mock.patch.object(writer.os, "stat", return_value=details),
            mock.patch.object(writer, "_read_small_text", return_value="0"),
        ):
            with self.assertRaisesRegex(writer.SafetyError, "LO_FLAGS_PARTSCAN"):
                writer.verify_ci_loop_partition_scan(target)

    def test_loop_backing_probe_refuses_disabled_partscan_before_subprocess(self) -> None:
        target = SimpleNamespace(path="/dev/loop9")
        image = SimpleNamespace(device=1, inode=2)
        with (
            mock.patch.object(
                writer,
                "verify_ci_loop_partition_scan",
                side_effect=writer.SafetyError("LO_FLAGS_PARTSCAN is disabled"),
            ),
            mock.patch.object(writer, "_fixed_binary") as fixed_binary,
            mock.patch.object(writer, "run_command") as runner,
        ):
            with self.assertRaisesRegex(writer.SafetyError, "LO_FLAGS_PARTSCAN"):
                writer.inspect_loop_backing(target, image)
        fixed_binary.assert_not_called()
        runner.assert_not_called()

    def test_partition_rescan_never_weakens_the_physical_path(self) -> None:
        target = SimpleNamespace(path="/dev/sdz", major_minor="8:240")
        with (
            mock.patch.object(writer, "_revalidate_target_fd") as revalidate,
            mock.patch.object(writer, "verify_ci_loop_partition_scan") as partscan,
            mock.patch.object(
                writer.fcntl,
                "ioctl",
                side_effect=OSError(22, "Invalid argument"),
            ) as ioctl,
        ):
            with self.assertRaisesRegex(writer.WriteError, "partition-table rescan"):
                writer._rescan_partition_table(
                    51, target, ci_mode=False, logical_sector_bytes=512
                )
        revalidate.assert_called_once_with(51, target, logical_sector_bytes=512)
        partscan.assert_not_called()
        ioctl.assert_called_once_with(51, writer.BLKRRPART)

    def test_ci_rescan_requires_partscan_before_the_kernel_ioctl(self) -> None:
        target = SimpleNamespace(path="/dev/loop9", major_minor="7:9")
        events: list[str] = []
        with (
            mock.patch.object(
                writer,
                "_revalidate_target_fd",
                side_effect=lambda *_args, **_kwargs: events.append("identity"),
            ),
            mock.patch.object(
                writer,
                "verify_ci_loop_partition_scan",
                side_effect=lambda *_args, **_kwargs: events.append("partscan"),
            ),
            mock.patch.object(
                writer.fcntl,
                "ioctl",
                side_effect=lambda *_args, **_kwargs: events.append("ioctl"),
            ),
        ):
            writer._rescan_partition_table(
                51, target, ci_mode=True, logical_sector_bytes=512
            )
        self.assertEqual(events, ["identity", "partscan", "ioctl", "identity"])

        with (
            mock.patch.object(writer, "_revalidate_target_fd"),
            mock.patch.object(
                writer,
                "verify_ci_loop_partition_scan",
                side_effect=writer.SafetyError("partscan disabled"),
            ),
            mock.patch.object(writer.fcntl, "ioctl") as ioctl,
        ):
            with self.assertRaisesRegex(writer.SafetyError, "partscan disabled"):
                writer._rescan_partition_table(
                    51, target, ci_mode=True, logical_sector_bytes=512
                )
        ioctl.assert_not_called()

    def test_privileged_loop_fixture_enables_partscan_before_writer_start(self) -> None:
        fixture = (
            REPO_DIR / "tools/make-device/tests/loop-v2-smoke.sh"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "losetup --find --show --nooverlap --partscan --sector-size 512",
            fixture,
        )
        self.assertLess(
            fixture.index("--nooverlap --partscan --sector-size 512"),
            fixture.index('--device "$loop_device"'),
        )

    def test_partition_signature_probe_fails_closed_on_any_recognized_type(self) -> None:
        empty = writer.CommandResult(0, b'{"signatures": []}\n', b"")
        conflict = writer.CommandResult(
            0,
            b'{"signatures": [{"offset": "0x0", "length": "8", "type": "crypto_LUKS"}]}\n',
            b"",
        )
        with (
            mock.patch.object(writer, "_fixed_binary", return_value="/usr/sbin/wipefs"),
            mock.patch.object(writer, "run_command", return_value=empty),
        ):
            writer.reject_partition_signature(51)
        with (
            mock.patch.object(writer, "_fixed_binary", return_value="/usr/sbin/wipefs"),
            mock.patch.object(writer, "run_command", return_value=conflict),
        ):
            with self.assertRaisesRegex(writer.SafetyError, "conflicting"):
                writer.reject_partition_signature(51)

    def test_cleanup_attempts_mapper_close_even_when_unmount_fails(self) -> None:
        lifecycle = writer.VaultLifecycle()
        partition = SimpleNamespace()
        with (
            mock.patch.object(writer, "_unmount", side_effect=writer.WriteError("injected")) as unmount,
            mock.patch.object(writer, "_close_mapper") as close_mapper,
        ):
            with self.assertRaisesRegex(writer.WriteError, "cleanup incomplete"):
                writer.cleanup_lifecycle(lifecycle, partition, "1" * 36)
        unmount.assert_called_once_with(lifecycle, deferred_signal_handler=None)
        close_mapper.assert_called_once_with(
            lifecycle,
            partition,
            "1" * 36,
            deferred_signal_handler=None,
        )

    def test_unmount_reconciles_already_unmounted_owned_directory(self) -> None:
        lifecycle = writer.VaultLifecycle(
            mapper=self.mapper_identity(),
            mapper_fd=73,
            mountpoint="/run/kernaid-make-device-v2.fixture",
            mount_major_minor="253:7",
            mountpoint_device=51,
            mountpoint_inode=52,
        )
        details = SimpleNamespace(
            st_mode=stat.S_IFDIR | 0o700,
            st_uid=0,
            st_gid=0,
            st_dev=51,
            st_ino=52,
        )
        partition = SimpleNamespace()
        with (
            mock.patch.object(writer, "parse_mountinfo_for_path", return_value=[]),
            mock.patch.object(writer.os, "lstat", return_value=details),
            mock.patch.object(writer.os, "rmdir") as rmdir,
            mock.patch.object(writer, "_close_mapper") as close_mapper,
        ):
            writer.cleanup_lifecycle(lifecycle, partition, "1" * 36)
        rmdir.assert_called_once_with("/run/kernaid-make-device-v2.fixture")
        self.assertIsNone(lifecycle.mountpoint)
        self.assertIsNone(lifecycle.mount_major_minor)
        self.assertIsNone(lifecycle.mountpoint_device)
        self.assertIsNone(lifecycle.mountpoint_inode)
        close_mapper.assert_called_once_with(
            lifecycle,
            partition,
            "1" * 36,
            deferred_signal_handler=None,
        )

    def test_unmount_postcondition_clears_state_when_runner_raises(self) -> None:
        lifecycle = writer.VaultLifecycle(
            mapper=self.mapper_identity(),
            mapper_fd=73,
            mountpoint="/run/kernaid-make-device-v2.fixture",
            mount_major_minor="253:7",
            mountpoint_device=51,
            mountpoint_inode=52,
        )
        mounted = [("253:7", "ext4", frozenset(), frozenset())]
        details = SimpleNamespace(
            st_mode=stat.S_IFDIR | 0o700,
            st_uid=0,
            st_gid=0,
            st_dev=51,
            st_ino=52,
        )
        partition = SimpleNamespace()
        with (
            mock.patch.object(
                writer, "parse_mountinfo_for_path", side_effect=(mounted, [])
            ),
            mock.patch.object(writer, "_fixed_binary", return_value="/usr/bin/umount"),
            mock.patch.object(
                writer,
                "run_command",
                side_effect=writer.OperationInterrupted(signal.SIGTERM),
            ),
            mock.patch.object(writer.os, "lstat", return_value=details),
            mock.patch.object(writer.os, "rmdir"),
            mock.patch.object(writer, "_close_mapper") as close_mapper,
        ):
            with self.assertRaisesRegex(writer.WriteError, "cleanup incomplete"):
                writer.cleanup_lifecycle(lifecycle, partition, "1" * 36)
        self.assertIsNone(lifecycle.mountpoint)
        close_mapper.assert_called_once_with(
            lifecycle,
            partition,
            "1" * 36,
            deferred_signal_handler=None,
        )

    def test_mount_creation_failure_removes_preownership_directory(self) -> None:
        lifecycle = writer.VaultLifecycle()
        mountpoint = "/run/kernaid-make-device-v2.failure-fixture"
        with (
            mock.patch.object(writer.tempfile, "mkdtemp", return_value=mountpoint),
            mock.patch.object(
                writer.os,
                "chmod",
                side_effect=writer.OperationInterrupted(signal.SIGTERM),
            ),
            mock.patch.object(writer.os, "rmdir") as rmdir,
        ):
            with self.assertRaises(writer.OperationInterrupted):
                writer._mount_mapper(
                    73, self.mapper_identity(), lifecycle, read_only=False
                )
        rmdir.assert_called_once_with(mountpoint)
        self.assertIsNone(lifecycle.mountpoint)

    def test_mapper_fd_lifecycle_closes_each_descriptor_exactly_once(self) -> None:
        mapper = self.mapper_identity()
        lifecycle = writer.VaultLifecycle(mapper=mapper, mapper_fd=73)
        partition = SimpleNamespace()
        closed: set[int] = set()

        def close_exactly_once(descriptor: int) -> None:
            if descriptor in closed:
                raise AssertionError(f"descriptor {descriptor} closed twice")
            closed.add(descriptor)

        with (
            mock.patch.object(writer.os, "close", side_effect=close_exactly_once),
            mock.patch.object(writer.os.path, "lexists", side_effect=(True, False)),
            mock.patch.object(writer, "_sysfs_mapper_by_name", side_effect=(["dm-7"], [])),
            mock.patch.object(writer, "capture_mapper", return_value=(74, mapper)),
            mock.patch.object(writer, "_fixed_binary", return_value="/usr/sbin/cryptsetup"),
            mock.patch.object(
                writer,
                "run_command",
                return_value=writer.CommandResult(0, b"", b""),
            ),
        ):
            writer._close_mapper(lifecycle, partition, "1" * 36)
        self.assertEqual(closed, {73, 74})
        self.assertEqual(lifecycle.mapper_fd, -1)
        self.assertIsNone(lifecycle.mapper)

    def test_mapper_close_reconciles_mapping_already_absent(self) -> None:
        lifecycle = writer.VaultLifecycle(
            mapper=self.mapper_identity(), mapper_fd=73
        )
        with (
            mock.patch.object(writer.os, "close") as close_fd,
            mock.patch.object(writer.os.path, "lexists", return_value=False),
            mock.patch.object(writer, "_sysfs_mapper_by_name", return_value=[]),
            mock.patch.object(writer, "run_command") as command,
        ):
            writer._close_mapper(lifecycle, SimpleNamespace(), "1" * 36)
        close_fd.assert_called_once_with(73)
        command.assert_not_called()
        self.assertEqual(lifecycle.mapper_fd, -1)
        self.assertIsNone(lifecycle.mapper)

    def test_pending_mapper_survives_first_signal_and_second_is_deferred(self) -> None:
        mapper = self.mapper_identity()
        lifecycle = writer.VaultLifecycle()
        partition = SimpleNamespace()
        secret = bytearray(b"correct horse battery staple")
        with (
            mock.patch.object(writer, "require_mapper_absent"),
            mock.patch.object(writer, "_fixed_binary", return_value="/usr/sbin/cryptsetup"),
            mock.patch.object(
                writer,
                "run_secret_command",
                side_effect=writer.OperationInterrupted(signal.SIGTERM),
            ),
        ):
            with self.assertRaises(writer.OperationInterrupted):
                writer._open_mapper(
                    71,
                    partition,
                    "1" * 36,
                    secret,
                    mapper.name,
                    lifecycle,
                )
        self.assertEqual(lifecycle.pending_mapper_name, mapper.name)

        capture_count = 0

        def capture_with_second_signal(*_args, **_kwargs):
            nonlocal capture_count
            capture_count += 1
            if capture_count == 1:
                handler = signal.getsignal(signal.SIGTERM)
                self.assertTrue(callable(handler))
                handler(signal.SIGTERM, None)  # type: ignore[operator]
                return 73, mapper
            return 74, mapper

        commands: list[str] = []

        def cleanup_command(_argv, **kwargs):
            self.assertIsNotNone(kwargs["deferred_signal_handler"])
            commands.append(kwargs["label"])
            return writer.CommandResult(0, b"", b"")

        with (
            mock.patch.object(writer.os.path, "lexists", side_effect=(True, True, False)),
            mock.patch.object(
                writer,
                "_sysfs_mapper_by_name",
                side_effect=(["dm-7"], ["dm-7"], ["dm-7"], []),
            ),
            mock.patch.object(writer, "capture_mapper", side_effect=capture_with_second_signal),
            mock.patch.object(writer, "_fixed_binary", side_effect=lambda _paths, name: f"/usr/bin/{name}"),
            mock.patch.object(writer, "run_command", side_effect=cleanup_command),
            mock.patch.object(writer.os, "close"),
        ):
            with self.assertRaises(writer.OperationInterrupted):
                writer._cleanup_lifecycle_with_signals_deferred(
                    lifecycle, partition, "1" * 36
                )
        writer._wipe_bytearray(secret)
        self.assertIn("udev mapper recovery settle", commands)
        self.assertIn("cryptsetup mapper close", commands)
        self.assertIsNone(lifecycle.mapper)
        self.assertIsNone(lifecycle.pending_mapper_name)
        self.assertEqual(lifecycle.mapper_fd, -1)

    def test_deferred_cleanup_runs_mutators_with_managed_signals_unblocked(self) -> None:
        mapper = self.mapper_identity()
        lifecycle = writer.VaultLifecycle(
            mapper=mapper,
            mapper_fd=73,
            mountpoint="/run/kernaid-make-device-v2.fixture",
            mount_major_minor="253:7",
            mountpoint_device=51,
            mountpoint_inode=52,
        )
        mounted = [("253:7", "ext4", frozenset(), frozenset())]
        mountpoint_details = SimpleNamespace(
            st_mode=stat.S_IFDIR | 0o700,
            st_uid=0,
            st_gid=0,
            st_dev=51,
            st_ino=52,
        )
        original_close = writer.os.close

        def close_fixture(descriptor: int) -> None:
            if descriptor not in (73, 74):
                original_close(descriptor)

        with (
            mock.patch.object(
                writer, "parse_mountinfo_for_path", side_effect=(mounted, [])
            ),
            mock.patch.object(writer.os, "lstat", return_value=mountpoint_details),
            mock.patch.object(writer.os, "rmdir"),
            mock.patch.object(writer.os, "close", side_effect=close_fixture),
            mock.patch.object(writer.os.path, "lexists", side_effect=(True, False)),
            mock.patch.object(writer, "_sysfs_mapper_by_name", side_effect=(["dm-7"], [])),
            mock.patch.object(writer, "capture_mapper", return_value=(74, mapper)),
            mock.patch.object(writer, "_fixed_binary", return_value="/usr/bin/true"),
            mock.patch.object(
                writer, "_spawn_command", wraps=writer._spawn_command
            ) as spawn_command,
        ):
            writer._cleanup_lifecycle_with_signals_deferred(
                lifecycle, SimpleNamespace(), "1" * 36
            )
        self.assertEqual(spawn_command.call_count, 2)
        for call in spawn_command.call_args_list:
            self.assertIsNotNone(call.args[2])
        self.assertIsNone(lifecycle.mountpoint)
        self.assertIsNone(lifecycle.mapper)
        self.assertEqual(lifecycle.mapper_fd, -1)

    def test_wrong_key_claim_accepts_only_cryptsetup_status_two(self) -> None:
        partition = SimpleNamespace()

        def exercise(returncode: int) -> None:
            with (
                mock.patch.object(writer, "_random_bytes", return_value=bytearray(b"x" * 32)),
                mock.patch.object(writer, "_random_mapper_name", return_value="kernaid-vault-0123456789abcdef"),
                mock.patch.object(writer, "require_mapper_absent"),
                mock.patch.object(writer, "_fixed_binary", return_value="/usr/sbin/cryptsetup"),
                mock.patch.object(
                    writer,
                    "run_secret_command",
                    return_value=writer.CommandResult(returncode, b"", b""),
                ),
                mock.patch.object(writer.os.path, "lexists", return_value=False),
                mock.patch.object(writer, "_sysfs_mapper_by_name", return_value=[]),
            ):
                writer._verify_wrong_key_rejected(51, partition, "1" * 36)

        exercise(2)
        for returncode in (1, 4):
            with self.subTest(returncode=returncode):
                with self.assertRaisesRegex(writer.WriteError, "ambiguous"):
                    exercise(returncode)

    def test_unreadable_mapper_sysfs_never_counts_as_absent(self) -> None:
        unreadable = writer.SafetyError("cannot read mapper name")
        unreadable.__cause__ = PermissionError("injected")
        scan = mock.MagicMock()
        scan.__enter__.return_value = [SimpleNamespace(name="dm-7")]
        scan.__exit__.return_value = False
        with (
            mock.patch.object(writer.os, "scandir", return_value=scan),
            mock.patch.object(writer, "_read_small_text", side_effect=unreadable),
        ):
            with self.assertRaisesRegex(writer.SafetyError, "cannot read"):
                writer._sysfs_mapper_by_name("kernaid-vault-0123456789abcdef")

    def test_failure_after_write_is_explicit_partial_and_non_bootable(self) -> None:
        state = writer.OperationState()
        state.advance(writer.WritePhase.WRITE_MAY_HAVE_STARTED, "/dev/loop7")
        emitted: list[bytes] = []
        with mock.patch.object(
            writer.os,
            "write",
            side_effect=lambda _fd, value: emitted.append(value) or len(value),
        ):
            self.assertEqual(writer._emit_failure(state, RuntimeError("injected")), 4)
        self.assertIn(b"MEDIA PARTIAL", emitted[0])
        self.assertIn(b"NON-BOOTABLE", emitted[0])
        self.assertIn(b"No authenticated recovery/reprovision", emitted[0])
        self.assertIn(b"cannot prove that media is fresh", emitted[0])

    def test_failure_before_write_is_refused_not_partial(self) -> None:
        emitted: list[bytes] = []
        with mock.patch.object(
            writer.os,
            "write",
            side_effect=lambda _fd, value: emitted.append(value) or len(value),
        ):
            self.assertEqual(
                writer._emit_failure(writer.OperationState(), writer.SafetyError("no")),
                3,
            )
        self.assertTrue(emitted[0].startswith(b"REFUSED:"))
        self.assertNotIn(b"MEDIA PARTIAL", emitted[0])

    def test_physical_mode_is_unreachable_when_ci_is_declared(self) -> None:
        args = SimpleNamespace(
            ci_disposable_loop_token=None,
            ci_passphrase_fd=None,
        )
        state = writer.OperationState()
        with (
            mock.patch.dict(writer.os.environ, {"CI": "true"}, clear=False),
            mock.patch.object(writer.sys, "flags", SimpleNamespace(isolated=1)),
            mock.patch.object(writer.os, "geteuid", return_value=0),
        ):
            with self.assertRaisesRegex(writer.SafetyError, "cannot address physical"):
                writer.execute(args, state)

    def test_execute_preflights_bound_tools_before_first_inventory_process(self) -> None:
        arguments = SimpleNamespace(
            ci_disposable_loop_token=None,
            ci_passphrase_fd=None,
            iso="/tmp/not-opened.iso",
            sha256="0" * 64,
            device="/dev/not-opened",
        )
        inventory = mock.Mock(side_effect=AssertionError("lsblk was spawned"))
        with (
            mock.patch.object(writer.sys, "platform", "linux"),
            mock.patch.object(writer.sys, "flags", SimpleNamespace(isolated=1)),
            mock.patch.object(writer.os, "geteuid", return_value=0),
            mock.patch.object(writer, "_ci_environment_present", return_value=False),
            mock.patch.object(
                writer, "load_installed_trust", return_value=(object(), object())
            ),
            mock.patch.object(
                writer,
                "preflight_writer_environment",
                side_effect=writer.SafetyError("unsafe lsblk ownership"),
            ),
            mock.patch.object(writer, "run_lsblk", inventory),
        ):
            with self.assertRaisesRegex(writer.SafetyError, "unsafe lsblk"):
                writer.execute(arguments, writer.OperationState())
        inventory.assert_not_called()

    def test_preflight_binds_all_tools_before_spawning_any_probe(self) -> None:
        with (
            mock.patch.object(writer, "_PREFLIGHT_TOOLS", None),
            mock.patch.object(
                writer,
                "_resolve_preflight_tool",
                side_effect=writer.SafetyError("unsafe tool ownership"),
            ),
            mock.patch.object(writer, "run_command") as runner,
        ):
            with self.assertRaisesRegex(writer.SafetyError, "unsafe tool ownership"):
                writer.preflight_writer_environment()
        runner.assert_not_called()

    def test_mount_preflight_uses_no_mtab_and_cleans_after_interruption(self) -> None:
        path = "/run/kernaid-make-device-v2-preflight.TEST123"
        details = SimpleNamespace(
            st_mode=stat.S_IFDIR | 0o700,
            st_uid=0,
            st_gid=0,
            st_dev=41,
            st_ino=42,
        )
        tools = {
            "mount": SimpleNamespace(path="/usr/bin/mount"),
            "umount": SimpleNamespace(path="/usr/bin/umount"),
        }
        present = True

        def remove(observed: str) -> None:
            nonlocal present
            self.assertEqual(observed, path)
            present = False

        with (
            mock.patch.object(writer.tempfile, "mkdtemp", return_value=path),
            mock.patch.object(writer.os, "lstat", return_value=details),
            mock.patch.object(writer.os, "chmod"),
            mock.patch.object(writer.os, "rmdir", side_effect=remove),
            mock.patch.object(writer, "parse_mountinfo_for_path", return_value=[]),
            mock.patch.object(writer, "run_command") as runner,
        ):
            writer._preflight_mount_capability(tools)
        self.assertFalse(present)
        self.assertEqual(runner.call_count, 2)
        for call in runner.call_args_list:
            self.assertIn("--no-mtab", call.args[0])

        present = True
        with (
            mock.patch.object(writer.tempfile, "mkdtemp", return_value=path),
            mock.patch.object(writer.os, "lstat", return_value=details),
            mock.patch.object(writer.os, "chmod"),
            mock.patch.object(writer.os, "rmdir", side_effect=remove),
            mock.patch.object(
                writer,
                "run_command",
                side_effect=writer.OperationInterrupted(signal.SIGTERM),
            ),
        ):
            with self.assertRaises(writer.OperationInterrupted):
                writer._preflight_mount_capability(tools)
        self.assertFalse(present)

    def test_vault_root_fd_wrong_filesystem_fails_before_layout_io(self) -> None:
        mapper = self.mapper_identity()
        wrong_root = SimpleNamespace(
            st_mode=stat.S_IFDIR | 0o700,
            st_uid=0,
            st_gid=0,
            st_dev=os.makedev(8, 1),
            st_ino=99,
        )
        for operation in (
            lambda: writer.create_vault_layout("/run/vault", mapper),
            lambda: writer.verify_vault_layout(
                "/run/vault",
                mapper,
                writer.VaultEvidence("", "", "a" * 64, "b" * 64),
            ),
        ):
            with (
                self.subTest(operation=operation),
                mock.patch.object(writer, "verify_mount"),
                mock.patch.object(writer.os, "open", return_value=91),
                mock.patch.object(writer.os, "fstat", return_value=wrong_root),
                mock.patch.object(writer.os, "close"),
                mock.patch.object(writer.os, "fchmod") as chmod,
                mock.patch.object(writer.os, "listdir") as listing,
            ):
                with self.assertRaisesRegex(writer.WriteError, "exact mapper"):
                    operation()
            chmod.assert_not_called()
            listing.assert_not_called()


class LauncherTests(unittest.TestCase):
    @staticmethod
    def load_launcher_source() -> ModuleType:
        module = ModuleType("test_kernaid_make_device_v2_launcher")
        module.__file__ = str(LAUNCHER_PATH)
        module.__package__ = ""
        exec(
            compile(
                LAUNCHER_PATH.read_bytes(),
                str(LAUNCHER_PATH),
                "exec",
                dont_inherit=True,
            ),
            module.__dict__,
        )
        return module

    @staticmethod
    def populate_bundle(directory: Path) -> None:
        for name in (
            "make-device-v2.py",
            "make_device_v2.py",
            "make-device.py",
            "catalog_v2.py",
            "trusted-rescue-images.v2.json",
        ):
            (directory / name).write_bytes((TOOLS_DIR / name).read_bytes())
        (directory / "device-layout.v1.json").write_bytes(MANIFEST_PATH.read_bytes())
        (directory / "vault-profile.v1.json").write_bytes(PROFILE_PATH.read_bytes())

    def test_launcher_loads_validated_sources_without_bytecode_cache(self) -> None:
        previous_dont_write = sys.dont_write_bytecode
        saved_modules = {
            name: sys.modules.get(name)
            for name in (
                "kernaid_make_device_v2_core",
                "kernaid_make_device_v1_for_v2",
                "kernaid_catalog_v2_for_writer",
            )
        }
        try:
            launcher = self.load_launcher_source()
            with tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                self.populate_bundle(directory)
                launcher.__file__ = str(directory / "make-device-v2.py")
                with mock.patch.object(launcher, "_require_root_owned"):
                    loaded = launcher._load_validated_core()
                self.assertEqual(loaded.__file__, str(directory / "make_device_v2.py"))
                self.assertFalse((directory / "__pycache__").exists())
        finally:
            sys.dont_write_bytecode = previous_dont_write
            for name, previous in saved_modules.items():
                if previous is None:
                    sys.modules.pop(name, None)
                else:
                    sys.modules[name] = previous

    def test_launcher_rejects_preexisting_cache_and_bundle_symlink(self) -> None:
        previous_dont_write = sys.dont_write_bytecode
        try:
            launcher = self.load_launcher_source()
            for forbidden_kind in ("cache", "legacy-bytecode", "symlink"):
                with self.subTest(forbidden_kind=forbidden_kind):
                    with tempfile.TemporaryDirectory() as temporary:
                        directory = Path(temporary)
                        self.populate_bundle(directory)
                        launcher.__file__ = str(directory / "make-device-v2.py")
                        if forbidden_kind == "cache":
                            cache = directory / "__pycache__"
                            cache.mkdir()
                            (cache / "make_device_v2.cpython-311.pyc").write_bytes(
                                b"stale-unvalidated-bytecode"
                            )
                        elif forbidden_kind == "legacy-bytecode":
                            (directory / "make_device_v2.pyc").write_bytes(
                                b"stale-unvalidated-bytecode"
                            )
                        else:
                            (directory / "untrusted-link").symlink_to("make_device_v2.py")
                        with mock.patch.object(launcher, "_require_root_owned"):
                            with self.assertRaisesRegex(
                                RuntimeError, "forbidden|symlink"
                            ):
                                launcher._load_validated_core()
        finally:
            sys.dont_write_bytecode = previous_dont_write

    def test_success_report_declares_precise_media_and_profile_policy(self) -> None:
        layout = SimpleNamespace(
            manifest_sha256="a" * 64,
            minimum_advertised_media_bytes=32_000_000_000,
            minimum_media_bytes=25_769_803_776,
            vault_profile_version=writer.VAULT_PROFILE_VERSION,
            vault_profile_sha256=writer.VAULT_PROFILE_SHA256,
            vault_partition=SimpleNamespace(
                number=3, start_lba=33_554_432, sector_count=16_777_216
            ),
        )
        report = writer.make_report(
            SimpleNamespace(
                path="/dev/loop7",
                major_minor="7:7",
                disk_sequence=77,
                size=32_000_000_000,
                serial=None,
            ),
            SimpleNamespace(path="/tmp/rescue.iso", size=4096, sha256="b" * 64),
            SimpleNamespace(artifact_name="KernAid-Rescue-test.iso", artifact_version="test"),
            1,
            layout,
            SimpleNamespace(
                path="/dev/loop7p3",
                major_minor="259:3",
                parent_major_minor="7:7",
                start_lba=33_554_432,
                sector_count=16_777_216,
                size=8_589_934_592,
            ),
            "b" * 64,
            writer.VaultEvidence("1" * 36, "2" * 36, "c" * 64, "d" * 64),
            ci_mode=True,
            usb_proof=None,
            operator_fresh_media_attestation=None,
        )
        self.assertEqual(
            report["mediaPolicy"]["recognizedConflictingSignatures"],
            "refused-without-implicit-wipe",
        )
        self.assertFalse(
            report["mediaPolicy"]["blankOrUnrecognizedTailProvesFreshMedia"]
        )
        self.assertFalse(report["mediaPolicy"]["technicalFreshnessVerified"])
        self.assertFalse(
            report["mediaPolicy"]["operatorFreshMediaAttestationApplicable"]
        )
        self.assertFalse(
            report["mediaPolicy"]["operatorFreshMediaAttestation"]
        )
        self.assertEqual(
            report["mediaPolicy"]["ciDisposableLoopPolicy"],
            "private-token-bound-test-fixture",
        )
        self.assertFalse(
            report["mediaPolicy"]["authenticatedRecoveryOrReprovisionImplemented"]
        )

    def test_checkout_launcher_refuses_before_import_when_not_root_owned(self) -> None:
        result = subprocess.run(
            ["/usr/bin/python3", "-I", str(LAUNCHER_PATH)],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
            env={"LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
        )
        # A developer checkout is intentionally not an install surface.  On a
        # root-owned checkout this test accepts argparse's later exit instead.
        if TOOLS_DIR.stat().st_uid != 0 or stat.S_IMODE(TOOLS_DIR.stat().st_mode) & 0o022:
            self.assertEqual(result.returncode, 3)
            self.assertIn("trust bootstrap failed", result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
