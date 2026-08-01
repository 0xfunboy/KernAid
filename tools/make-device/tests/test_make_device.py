from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
from contextlib import ExitStack, redirect_stderr
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


MODULE_PATH = Path(__file__).resolve().parents[1] / "make-device.py"
SPEC = importlib.util.spec_from_file_location("kernaid_make_device", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
make_device = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = make_device
SPEC.loader.exec_module(make_device)


def node(
    path: str,
    *,
    kind: str = "disk",
    kname: str | None = None,
    parent: str | None = None,
    removable: bool = True,
    read_only: bool = False,
    rotational: bool = False,
    size: int = 16_000_000,
    serial: str | None = "USB-SERIAL-7",
    model: str | None = "KernAid Test Flash",
    vendor: str | None = "TestVendor",
    transport: str | None = "usb",
    subsystems: str | None = "block:scsi:usb:pci",
    mounts: list[str | None] | None = None,
    major_minor: str = "8:16",
    disk_sequence: int = 900,
    children: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    return {
        "name": path,
        "path": path,
        "kname": kname or path.removeprefix("/dev/"),
        "type": kind,
        "pkname": parent,
        "rm": removable,
        "ro": read_only,
        "rota": rotational,
        "size": size,
        "serial": serial,
        "model": model,
        "vendor": vendor,
        "tran": transport,
        "subsystems": subsystems,
        "mountpoints": mounts if mounts is not None else [None],
        "maj:min": major_minor,
        "disk-seq": disk_sequence,
        "children": children or [],
    }


def inventory(*roots: dict[str, object]):
    return make_device.Inventory.from_json(json.dumps({"blockdevices": list(roots)}))


def image(*, size: int = 8_000_000, backing: str = "0:42"):
    return make_device.ImageInfo(
        path="/var/lib/kernaid/KernAid.iso",
        size=size,
        sha256="a" * 64,
        device=111,
        inode=222,
        mtime_ns=333,
        backing_major_minor=backing,
    )


def host(
    *,
    mounts: tuple[object, ...] | None = None,
    swaps: frozenset[str] = frozenset(),
    holders: frozenset[str] = frozenset(),
):
    return make_device.HostUse(
        mounts=mounts
        if mounts is not None
        else (make_device.MountRecord("0:42", "/var/lib/kernaid"),),
        swaps=swaps,
        holders=holders,
    )


def hybrid_iso_bytes(size: int = 64 * 2048) -> bytearray:
    content = bytearray(size)
    content[510:512] = b"\x55\xaa"
    partition = 446
    content[partition] = 0x80
    content[partition + 4] = 0x17
    content[partition + 8 : partition + 12] = (0).to_bytes(4, "little")
    content[partition + 12 : partition + 16] = (size // 512).to_bytes(4, "little")

    primary = 16 * 2048
    content[primary] = 1
    content[primary + 1 : primary + 6] = b"CD001"
    content[primary + 6] = 1

    boot_record = 17 * 2048
    content[boot_record] = 0
    content[boot_record + 1 : boot_record + 6] = b"CD001"
    content[boot_record + 6] = 1
    system_id = b"EL TORITO SPECIFICATION".ljust(32, b" ")
    content[boot_record + 7 : boot_record + 39] = system_id
    content[boot_record + 71 : boot_record + 75] = (20).to_bytes(4, "little")

    terminator = 18 * 2048
    content[terminator] = 255
    content[terminator + 1 : terminator + 6] = b"CD001"
    content[terminator + 6] = 1

    catalog = 20 * 2048
    validation = bytearray(32)
    validation[0] = 1
    validation[30:32] = b"\x55\xaa"
    checksum = (-sum(struct.unpack("<16H", validation))) & 0xFFFF
    validation[28:30] = checksum.to_bytes(2, "little")
    content[catalog : catalog + 32] = validation
    content[catalog + 32] = 0x88
    content[catalog + 38 : catalog + 40] = (4).to_bytes(2, "little")
    content[catalog + 40 : catalog + 44] = (24).to_bytes(4, "little")
    content[catalog + 64] = 0x91
    content[catalog + 65] = 0xEF
    content[catalog + 66 : catalog + 68] = (1).to_bytes(2, "little")
    content[catalog + 96] = 0x88
    content[catalog + 102 : catalog + 104] = (4).to_bytes(2, "little")
    content[catalog + 104 : catalog + 108] = (26).to_bytes(4, "little")
    content[24 * 2048 : 24 * 2048 + 2048] = b"B" * 2048
    content[26 * 2048 : 26 * 2048 + 2048] = b"U" * 2048
    return content


def fixture_authorization():
    return make_device.ImageAuthorization(
        "ci-fixture", 0, "fixture.iso", "fixture-only", None, None
    )


def usb_proof():
    return make_device.UsbMediaProof(
        (
            ("ID_BUS", "usb"),
            ("ID_TYPE", "disk"),
            ("ID_SERIAL_SHORT", "USB-SERIAL-7"),
            ("ID_PATH", "pci-0000:00:14.0-usb-0:1:1.0-scsi-0:0:0:0"),
        )
    )


def catalog_document(
    *, sha256: str = "a" * 64, size: int = 8_000_000
) -> dict[str, object]:
    def attestation(firmware: str, run_id: int):
        return {
            "passed": True,
            "workflowRunId": run_id,
            "workflowRunUrl": (
                f"https://github.com/0xfunboy/KernAid/actions/runs/{run_id}"
            ),
            "logSha256": ("b" if firmware == "bios" else "c") * 64,
        }

    return {
        "schema": make_device.TRUST_CATALOG_SCHEMA,
        "catalogRevision": 1,
        "images": [
            {
                "artifactName": "KernAid-Rescue-amd64.iso",
                "artifactVersion": "1.0.0",
                "sha256": sha256,
                "bytes": size,
                "qemuAttestations": {
                    "bios": attestation("bios", 1001),
                    "uefi": attestation("uefi", 1002),
                },
            }
        ],
    }


class InventoryTests(unittest.TestCase):
    def test_accepts_safe_removable_usb(self) -> None:
        devices = inventory(node("/dev/sdb"))
        candidate = devices.resolve_explicit("/dev/sdb")
        make_device.validate_candidate(
            devices, candidate, image(), host(), ci_loop=False
        )

    def test_requires_explicit_absolute_device(self) -> None:
        devices = inventory(node("/dev/sdb"))
        with self.assertRaisesRegex(make_device.SafetyError, "explicit and absolute"):
            devices.resolve_explicit("sdb")

    def test_rejects_lsblk_path_that_escapes_dev(self) -> None:
        with self.assertRaisesRegex(make_device.SafetyError, "unsafe device path"):
            inventory(node("/dev/../etc/passwd"))

    def test_rejects_partition_target(self) -> None:
        devices = inventory(node("/dev/sdb1", kind="part", kname="sdb1"))
        with self.assertRaisesRegex(make_device.SafetyError, "partition"):
            make_device.validate_candidate(
                devices, devices.resolve_explicit("/dev/sdb1"), image(), host(), ci_loop=False
            )

    def test_rejects_read_only_target(self) -> None:
        devices = inventory(node("/dev/sdb", read_only=True))
        with self.assertRaisesRegex(make_device.SafetyError, "read-only"):
            make_device.validate_candidate(
                devices, devices.resolve_explicit("/dev/sdb"), image(), host(), ci_loop=False
            )

    def test_rejects_target_smaller_than_iso(self) -> None:
        devices = inventory(node("/dev/sdb", size=4_000_000))
        with self.assertRaisesRegex(make_device.SafetyError, "too small"):
            make_device.validate_candidate(
                devices, devices.resolve_explicit("/dev/sdb"), image(), host(), ci_loop=False
            )

    def test_rejects_mounted_descendant(self) -> None:
        partition = node(
            "/dev/sdb1",
            kind="part",
            kname="sdb1",
            parent="sdb",
            mounts=["/media/operator/data"],
            major_minor="8:17",
        )
        devices = inventory(node("/dev/sdb", children=[partition]))
        with self.assertRaisesRegex(make_device.SafetyError, "mounted"):
            make_device.validate_candidate(
                devices, devices.resolve_explicit("/dev/sdb"), image(), host(), ci_loop=False
            )

    def test_rejects_root_backing_through_stacked_child(self) -> None:
        root = node(
            "/dev/dm-0",
            kind="crypt",
            kname="dm-0",
            parent="sda2",
            removable=False,
            serial=None,
            transport=None,
            mounts=["/"],
            major_minor="253:0",
        )
        partition = node(
            "/dev/sda2",
            kind="part",
            kname="sda2",
            parent="sda",
            removable=False,
            serial=None,
            transport=None,
            major_minor="8:2",
            children=[root],
        )
        devices = inventory(
            node(
                "/dev/sda",
                kname="sda",
                removable=False,
                serial="SYSTEM",
                transport="sata",
                major_minor="8:0",
                children=[partition],
            )
        )
        with self.assertRaisesRegex(make_device.SafetyError, "root/boot"):
            make_device.validate_candidate(
                devices, devices.resolve_explicit("/dev/sda"), image(), host(), ci_loop=False
            )

    def test_rejects_rescue_source_mount(self) -> None:
        partition = node(
            "/dev/sdb1",
            kind="part",
            kname="sdb1",
            parent="sdb",
            mounts=["/run/live/medium"],
            major_minor="8:17",
        )
        devices = inventory(node("/dev/sdb", children=[partition]))
        with self.assertRaisesRegex(make_device.SafetyError, "Rescue source"):
            make_device.validate_candidate(
                devices, devices.resolve_explicit("/dev/sdb"), image(), host(), ci_loop=False
            )

    def test_rejects_iso_stored_on_target(self) -> None:
        devices = inventory(node("/dev/sdb"))
        source_host = host(
            mounts=(make_device.MountRecord("8:16", "/var/lib/kernaid"),)
        )
        with self.assertRaisesRegex(make_device.SafetyError, "ISO source"):
            make_device.validate_candidate(
                devices,
                devices.resolve_explicit("/dev/sdb"),
                image(backing="8:16"),
                source_host,
                ci_loop=False,
            )

    def test_rejects_active_holder(self) -> None:
        devices = inventory(node("/dev/sdb"))
        with self.assertRaisesRegex(make_device.SafetyError, "active device-mapper"):
            make_device.validate_candidate(
                devices,
                devices.resolve_explicit("/dev/sdb"),
                image(),
                host(holders=frozenset(("8:16",))),
                ci_loop=False,
            )

    def test_rejects_active_swap(self) -> None:
        devices = inventory(node("/dev/sdb"))
        with self.assertRaisesRegex(make_device.SafetyError, "active swap"):
            make_device.validate_candidate(
                devices,
                devices.resolve_explicit("/dev/sdb"),
                image(),
                host(swaps=frozenset(("/dev/sdb",))),
                ci_loop=False,
            )

    def test_rejects_non_removable_or_non_usb_disk(self) -> None:
        for candidate_node in (
            node("/dev/sdb", removable=False),
            node("/dev/sdb", transport="sata"),
        ):
            with self.subTest(candidate=candidate_node):
                devices = inventory(candidate_node)
                with self.assertRaisesRegex(make_device.SafetyError, "removable USB"):
                    make_device.validate_candidate(
                        devices,
                        devices.resolve_explicit("/dev/sdb"),
                        image(),
                        host(),
                        ci_loop=False,
                    )

    def test_rejects_physical_usb_without_stable_serial(self) -> None:
        devices = inventory(node("/dev/sdb", serial=None))
        with self.assertRaisesRegex(make_device.SafetyError, "stable serial"):
            make_device.validate_candidate(
                devices,
                devices.resolve_explicit("/dev/sdb"),
                image(),
                host(),
                ci_loop=False,
            )

    def test_rejects_loop_in_default_mode_and_disk_in_ci_mode(self) -> None:
        loop_inventory = inventory(
            node(
                "/dev/loop7",
                kind="loop",
                kname="loop7",
                removable=False,
                serial=None,
                transport=None,
                major_minor="7:7",
            )
        )
        with self.assertRaisesRegex(make_device.SafetyError, "whole physical disk"):
            make_device.validate_candidate(
                loop_inventory,
                loop_inventory.resolve_explicit("/dev/loop7"),
                image(),
                host(),
                ci_loop=False,
            )
        disk_inventory = inventory(node("/dev/sdb"))
        with self.assertRaisesRegex(make_device.SafetyError, "restricted"):
            make_device.validate_candidate(
                disk_inventory,
                disk_inventory.resolve_explicit("/dev/sdb"),
                image(),
                host(),
                ci_loop=True,
            )


class PrimitiveTests(unittest.TestCase):
    def test_checked_in_catalog_is_valid_and_intentionally_empty(self) -> None:
        catalog_path = MODULE_PATH.parent / make_device.TRUST_CATALOG_FILENAME
        catalog = make_device.parse_trust_catalog(
            catalog_path.read_text(encoding="utf-8")
        )
        self.assertEqual(catalog.revision, 0)
        self.assertEqual(catalog.images, ())
        schema = json.loads(
            (MODULE_PATH.parent / "trusted-rescue-images.schema.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(schema["properties"]["schema"]["const"], make_device.TRUST_CATALOG_SCHEMA)

    def test_catalog_entry_tool_emits_a_schema_compatible_attested_entry(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            iso_path = Path(directory) / "KernAid-Rescue-amd64.iso"
            iso_path.write_bytes(b"catalog-entry-fixture")
            digest = hashlib.sha256(iso_path.read_bytes()).hexdigest()
            logs: dict[str, Path] = {}
            for firmware in ("bios", "uefi"):
                log_path = Path(directory) / f"rescue-smoke-{firmware}.log"
                log_path.write_text(
                    "QEMU boot output\n"
                    f"KERNAID_QEMU_ATTESTATION_V1 firmware={firmware} "
                    f"iso_sha256={digest} target_before_sha256={'d' * 64} "
                    f"target_after_sha256={'d' * 64} ready=true\n",
                    encoding="utf-8",
                )
                logs[firmware] = log_path
            command = [
                "/usr/bin/python3",
                "-I",
                str(MODULE_PATH.parent / "catalog-entry.py"),
                "--iso",
                str(iso_path),
                "--sha256",
                digest,
                "--artifact-version",
                "1.2.3",
                "--bios-run-id",
                "2001",
                "--bios-run-url",
                "https://github.com/0xfunboy/KernAid/actions/runs/2001",
                "--bios-log",
                str(logs["bios"]),
                "--uefi-run-id",
                "2002",
                "--uefi-run-url",
                "https://github.com/0xfunboy/KernAid/actions/runs/2002",
                "--uefi-log",
                str(logs["uefi"]),
            ]
            result = subprocess.run(command, check=False, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            entry = json.loads(result.stdout)
            document = {
                "schema": make_device.TRUST_CATALOG_SCHEMA,
                "catalogRevision": 1,
                "images": [entry],
            }
            parsed = make_device.parse_trust_catalog(json.dumps(document))
            self.assertEqual(parsed.images[0].artifact_version, "1.2.3")
            self.assertEqual(
                parsed.images[0].bios.log_sha256,
                hashlib.sha256(logs["bios"].read_bytes()).hexdigest(),
            )

            logs["uefi"].write_text(
                "KERNAID_QEMU_ATTESTATION_V1 firmware=uefi "
                f"iso_sha256={'0' * 64} target_before_sha256={'d' * 64} "
                f"target_after_sha256={'d' * 64} ready=true\n",
                encoding="utf-8",
            )
            refused = subprocess.run(
                command, check=False, capture_output=True, text=True
            )
            self.assertEqual(refused.returncode, 3)
            self.assertIn("does not prove this ISO", refused.stderr)

    def test_empty_official_catalog_fails_closed_for_every_image(self) -> None:
        catalog = make_device.parse_trust_catalog(
            json.dumps(
                {
                    "schema": make_device.TRUST_CATALOG_SCHEMA,
                    "catalogRevision": 0,
                    "images": [],
                }
            )
        )
        with self.assertRaisesRegex(make_device.SafetyError, "not present"):
            catalog.authorize(image())

    def test_official_catalog_binds_name_version_digest_size_and_qemu(self) -> None:
        trusted_image = make_device.ImageInfo(
            path="/releases/KernAid-Rescue-amd64.iso",
            size=8_000_000,
            sha256="a" * 64,
            device=1,
            inode=2,
            mtime_ns=3,
            backing_major_minor="0:42",
        )
        catalog = make_device.parse_trust_catalog(json.dumps(catalog_document()))
        authorized = make_device.authorize_image(
            catalog, trusted_image, ci_loop=False, fixture_token=None
        )
        self.assertEqual(authorized.artifact_version, "1.0.0")
        self.assertEqual(authorized.bios.firmware, "bios")  # type: ignore[union-attr]
        self.assertEqual(authorized.uefi.firmware, "uefi")  # type: ignore[union-attr]

        wrong_size = make_device.ImageInfo(
            **{**trusted_image.__dict__, "size": trusted_image.size + 1}
        )
        with self.assertRaisesRegex(make_device.SafetyError, "not present"):
            catalog.authorize(wrong_size)

        failed_qemu = catalog_document()
        failed_qemu["images"][0]["qemuAttestations"]["uefi"][  # type: ignore[index]
            "passed"
        ] = False
        with self.assertRaisesRegex(make_device.SafetyError, "not passing"):
            make_device.parse_trust_catalog(json.dumps(failed_qemu))

    def test_fixture_trust_is_impossible_for_a_physical_device(self) -> None:
        catalog = make_device.TrustCatalog(0, ())
        fixture = image()
        token = make_device.ci_fixture_image_token(fixture)
        with self.assertRaisesRegex(make_device.SafetyError, "disposable CI loops"):
            make_device.authorize_image(
                catalog, fixture, ci_loop=False, fixture_token=token
            )
        authorized = make_device.authorize_image(
            catalog, fixture, ci_loop=True, fixture_token=token
        )
        self.assertEqual(authorized.mode, "ci-fixture")

    def test_mountinfo_unescapes_paths(self) -> None:
        records = make_device.parse_mountinfo(
            "36 29 8:17 / /media/My\\040USB rw,relatime - ext4 /dev/sdb1 rw\n"
        )
        self.assertEqual(records[0].mountpoint, "/media/My USB")

    def test_confirmation_binds_path_serial_and_exact_size(self) -> None:
        candidate = inventory(node("/dev/sdb")).resolve_explicit("/dev/sdb")
        self.assertEqual(
            make_device.confirmation_phrase(candidate),
            'ERASE direct-usb-media path=/dev/sdb serial="USB-SERIAL-7" '
            'model="KernAid Test Flash" size=16000000',
        )
        fake_tty = io.StringIO(make_device.confirmation_phrase(candidate) + "\n")
        fake_tty.isatty = lambda: True  # type: ignore[method-assign]
        with redirect_stderr(io.StringIO()):
            make_device.require_confirmation(candidate, fake_tty)

    def test_physical_device_confirmation_refuses_non_tty_input(self) -> None:
        candidate = inventory(node("/dev/sdb")).resolve_explicit("/dev/sdb")
        with self.assertRaisesRegex(make_device.SafetyError, "requires a terminal"):
            make_device.require_confirmation(candidate, io.StringIO("anything\n"))

    def test_dd_is_bounded_by_exact_byte_count(self) -> None:
        command = make_device.dd_command("/usr/bin/dd", 12_345)
        self.assertIn("count=12345", command)
        self.assertIn("iflag=count_bytes,fullblock", command)
        self.assertIn("conv=fsync,notrunc", command)

    def test_ci_token_binds_device_and_backing_inode(self) -> None:
        candidate = inventory(
            node(
                "/dev/loop7",
                kind="loop",
                kname="loop7",
                removable=False,
                serial=None,
                transport=None,
                major_minor="7:7",
            )
        ).resolve_explicit("/dev/loop7")
        backing = make_device.LoopBacking(
            path="/tmp/kernaid-disposable-test.img",
            device=44,
            inode=55,
            size=16_000_000,
            uid=0,
            mode=0o600,
            links=1,
        )
        self.assertEqual(
            make_device.ci_token(candidate, backing),
            "KERNAID_CI_DISPOSABLE_LOOP path=/dev/loop7 majmin=7:7 "
            "size=16000000 diskseq=900 backing=44:55",
        )

    def test_loop_inspection_binds_losetup_to_private_backing_inode(self) -> None:
        candidate = inventory(
            node(
                "/dev/loop7",
                kind="loop",
                kname="loop7",
                removable=False,
                serial=None,
                transport=None,
                major_minor="7:7",
            )
        ).resolve_explicit("/dev/loop7")
        descriptor, backing_path = tempfile.mkstemp(
            prefix="kernaid-disposable-test-", dir="/tmp"
        )
        try:
            os.fchmod(descriptor, 0o600)
            os.ftruncate(descriptor, candidate.size)
            details = os.fstat(descriptor)
            payload = {
                "loopdevices": [
                    {
                        "name": candidate.path,
                        "back-file": backing_path,
                        "back-ino": details.st_ino,
                        "back-maj:min": (
                            f"{os.major(details.st_dev)}:{os.minor(details.st_dev)}"
                        ),
                        "maj:min": candidate.major_minor,
                    }
                ]
            }
            result = SimpleNamespace(
                returncode=0, stdout=json.dumps(payload), stderr=""
            )
            with mock.patch.object(make_device.subprocess, "run", return_value=result):
                inspected = make_device.inspect_loop_backing(candidate, image())
            self.assertEqual(inspected.inode, details.st_ino)

            payload["loopdevices"][0]["back-ino"] = details.st_ino + 1
            result.stdout = json.dumps(payload)
            with mock.patch.object(make_device.subprocess, "run", return_value=result):
                with self.assertRaisesRegex(make_device.SafetyError, "different backing"):
                    make_device.inspect_loop_backing(candidate, image())
        finally:
            os.close(descriptor)
            os.unlink(backing_path)

    def test_udev_allows_generic_usb_disk_without_optional_media_labels(self) -> None:
        candidate = inventory(node("/dev/sdb")).resolve_explicit("/dev/sdb")
        safe_properties = "\n".join(
            (
                "ID_BUS=usb",
                "ID_TYPE=disk",
                "ID_SERIAL_SHORT=USB-SERIAL-7",
                "ID_PATH=pci-0000:00:14.0-usb-0:1:1.0-scsi-0:0:0:0",
                "ID_VENDOR=TestVendor",
                "ID_MODEL=Portable_Flash",
            )
        )
        result = SimpleNamespace(returncode=0, stdout=safe_properties, stderr="")
        with mock.patch.object(make_device.subprocess, "run", return_value=result):
            proof = make_device.probe_usb_media(candidate)
        self.assertIn(("ID_TYPE", "disk"), proof.properties)
        self.assertIn(
            ("ID_PATH", "pci-0000:00:14.0-usb-0:1:1.0-scsi-0:0:0:0"),
            proof.properties,
        )

        result.stdout = safe_properties + "\nID_DRIVE_FLASH_SD=1\n"
        with mock.patch.object(make_device.subprocess, "run", return_value=result):
            with self.assertRaisesRegex(make_device.SafetyError, "card readers"):
                make_device.probe_usb_media(candidate)

    def test_udev_refuses_non_disk_type_and_card_reader_model(self) -> None:
        candidate = inventory(node("/dev/sdb")).resolve_explicit("/dev/sdb")
        base = (
            "ID_BUS=usb\n"
            "ID_SERIAL_SHORT=USB-SERIAL-7\n"
            "ID_PATH=pci-0000:00:14.0-usb-0:1:1.0-scsi-0:0:0:0\n"
        )
        result = SimpleNamespace(
            returncode=0, stdout=base + "ID_TYPE=cd\n", stderr=""
        )
        with mock.patch.object(make_device.subprocess, "run", return_value=result):
            with self.assertRaisesRegex(make_device.SafetyError, "non-disk"):
                make_device.probe_usb_media(candidate)

        result.stdout = base + "ID_TYPE=disk\nID_MODEL=Multi_Card_Reader\n"
        with mock.patch.object(make_device.subprocess, "run", return_value=result):
            with self.assertRaisesRegex(make_device.SafetyError, "card reader"):
                make_device.probe_usb_media(candidate)

    def test_verified_image_requires_matching_checksum_and_iso_magic(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            iso_path = Path(directory) / "rescue.iso"
            content = hybrid_iso_bytes()
            iso_path.write_bytes(content)
            digest = hashlib.sha256(content).hexdigest()
            mount = make_device.MountRecord(
                f"{os.major(os.stat(iso_path).st_dev)}:{os.minor(os.stat(iso_path).st_dev)}",
                directory,
            )
            fd, verified = make_device.open_verified_image(
                str(iso_path), digest, (mount,)
            )
            try:
                self.assertEqual(verified.sha256, digest)
            finally:
                os.close(fd)
            with self.assertRaisesRegex(make_device.SafetyError, "checksum mismatch"):
                make_device.open_verified_image(str(iso_path), "0" * 64, (mount,))

            content[
                make_device.MBR_SIGNATURE_OFFSET : make_device.MBR_SIGNATURE_OFFSET + 2
            ] = b"\x00\x00"
            iso_path.write_bytes(content)
            non_hybrid_digest = hashlib.sha256(content).hexdigest()
            with self.assertRaisesRegex(make_device.SafetyError, "hybrid MBR"):
                make_device.open_verified_image(
                    str(iso_path), non_hybrid_digest, (mount,)
                )

            content[510:512] = b"\x55\xaa"
            content[20 * 2048 + 38 : 20 * 2048 + 40] = b"\x00\x00"
            iso_path.write_bytes(content)
            no_boot_entry_digest = hashlib.sha256(content).hexdigest()
            with self.assertRaisesRegex(make_device.SafetyError, "zero size"):
                make_device.open_verified_image(
                    str(iso_path), no_boot_entry_digest, (mount,)
                )

    def test_iso_boot_catalog_rejects_zero_boot_image_and_bad_platform(self) -> None:
        content = hybrid_iso_bytes()
        with tempfile.TemporaryDirectory() as directory:
            iso_path = Path(directory) / "fixture.iso"
            iso_path.write_bytes(content)
            descriptor = os.open(iso_path, os.O_RDONLY)
            try:
                zero_boot = bytearray(content)
                zero_boot[24 * 2048 : 24 * 2048 + 2048] = b"\x00" * 2048
                iso_path.write_bytes(zero_boot)
                with self.assertRaisesRegex(make_device.SafetyError, "only zero bytes"):
                    make_device._validate_hybrid_boot_metadata(
                        descriptor, len(zero_boot)
                    )
            finally:
                os.close(descriptor)

            out_of_range = hybrid_iso_bytes()
            out_of_range[20 * 2048 + 38 : 20 * 2048 + 40] = (8).to_bytes(
                2, "little"
            )
            out_of_range[20 * 2048 + 40 : 20 * 2048 + 44] = (63).to_bytes(
                4, "little"
            )
            iso_path.write_bytes(out_of_range)
            descriptor = os.open(iso_path, os.O_RDONLY)
            try:
                with self.assertRaisesRegex(make_device.SafetyError, "outside"):
                    make_device._validate_hybrid_boot_metadata(
                        descriptor, len(out_of_range)
                    )
            finally:
                os.close(descriptor)

            bad_platform = hybrid_iso_bytes()
            bad_platform[20 * 2048 + 65] = 0x01
            iso_path.write_bytes(bad_platform)
            descriptor = os.open(iso_path, os.O_RDONLY)
            try:
                with self.assertRaisesRegex(make_device.SafetyError, "unsupported platform"):
                    make_device._validate_hybrid_boot_metadata(
                        descriptor, len(bad_platform)
                    )
            finally:
                os.close(descriptor)

    def test_report_explicitly_declares_vault_not_created(self) -> None:
        candidate = inventory(node("/dev/sdb")).resolve_explicit("/dev/sdb")
        report = make_device.make_report(
            candidate,
            image(),
            "a" * 64,
            False,
            fixture_authorization(),
            usb_proof(),
        )
        self.assertEqual(report["status"], "verified")
        self.assertEqual(report["vault"]["created"], False)  # type: ignore[index]
        self.assertIn("deferred", report["vault"]["reason"])  # type: ignore[index]
        self.assertEqual(report["residualTail"]["policy"], "preserved")  # type: ignore[index]
        self.assertEqual(
            report["reportAuthenticity"]["status"],  # type: ignore[index]
            "unsigned-unauthenticated",
        )
        self.assertFalse(report["reportAuthenticity"]["signed"])  # type: ignore[index]
        target_proof = report["target"]["udevProof"]  # type: ignore[index]
        self.assertTrue(target_proof["idPathVerified"])  # type: ignore[index]
        self.assertEqual(
            target_proof["idPath"],  # type: ignore[index]
            "pci-0000:00:14.0-usb-0:1:1.0-scsi-0:0:0:0",
        )
        self.assertTrue(target_proof["knownCardReaderMarkersRejected"])
        self.assertTrue(target_proof["operatorConfirmedDirectUsbMedia"])

    def test_physical_report_cannot_claim_verification_without_udev_proof(self) -> None:
        candidate = inventory(node("/dev/sdb")).resolve_explicit("/dev/sdb")
        with self.assertRaisesRegex(make_device.WriteError, "missing udev proof"):
            make_device.make_report(
                candidate,
                image(),
                "a" * 64,
                False,
                fixture_authorization(),
                None,
            )

    def test_open_target_binds_size_read_only_state_and_disk_sequence(self) -> None:
        candidate = inventory(node("/dev/sdb")).resolve_explicit("/dev/sdb")
        block_stat = SimpleNamespace(
            st_mode=stat.S_IFBLK | 0o600,
            st_rdev=os.makedev(8, 16),
        )
        with (
            mock.patch.object(make_device.os, "lstat", return_value=block_stat),
            mock.patch.object(make_device.os, "open", return_value=91),
            mock.patch.object(make_device.os, "fstat", return_value=block_stat),
            mock.patch.object(
                make_device,
                "_ioctl_value",
                side_effect=(candidate.size, 0, candidate.disk_sequence),
            ) as ioctl_value,
        ):
            self.assertEqual(make_device._open_target(candidate), 91)
        self.assertEqual(
            [call.args[2] for call in ioctl_value.call_args_list],
            ["=Q", "=I", "=Q"],
        )

        with (
            mock.patch.object(make_device.os, "lstat", return_value=block_stat),
            mock.patch.object(make_device.os, "open", return_value=92),
            mock.patch.object(make_device.os, "fstat", return_value=block_stat),
            mock.patch.object(
                make_device,
                "_ioctl_value",
                side_effect=(candidate.size + 1, 0, candidate.disk_sequence),
            ),
            mock.patch.object(make_device.os, "close") as close,
        ):
            with self.assertRaisesRegex(make_device.SafetyError, "capacity changed"):
                make_device._open_target(candidate)
            close.assert_called_once_with(92)

    def test_stale_backup_gpt_is_refused_instead_of_erased(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target_path = Path(directory) / "stale-gpt.img"
            content = bytearray(4096)
            content[-512:-504] = b"EFI PART"
            target_path.write_bytes(content)
            target_fd = os.open(target_path, os.O_RDWR)
            candidate = inventory(node("/dev/sdb", size=len(content))).resolve_explicit(
                "/dev/sdb"
            )
            try:
                with mock.patch.object(
                    make_device, "_ioctl_value", return_value=512
                ):
                    with self.assertRaisesRegex(make_device.SafetyError, "backup GPT"):
                        make_device._reject_stale_tail_metadata(
                            target_fd, candidate, image(size=1024)
                        )
            finally:
                os.close(target_fd)

    def test_wipefs_read_only_probe_refuses_recognized_tail_signature(self) -> None:
        candidate = inventory(node("/dev/sdb")).resolve_explicit("/dev/sdb")
        target_fd = 71
        probe = SimpleNamespace(
            returncode=0,
            stdout=json.dumps(
                {
                    "signatures": [
                        {"offset": "0x900000", "length": 8, "type": "gpt"}
                    ]
                }
            ),
            stderr="",
        )
        with mock.patch.object(
            make_device.subprocess, "run", return_value=probe
        ) as run:
            with self.assertRaisesRegex(make_device.SafetyError, "remains beyond"):
                make_device._reject_recognized_tail_signatures(
                    target_fd, candidate, image(size=8_000_000)
                )
        self.assertEqual(run.call_args.args[0][-1], "/proc/self/fd/71")
        self.assertEqual(run.call_args.kwargs["pass_fds"], (target_fd,))
        self.assertTrue(run.call_args.kwargs["close_fds"])

        probe.stdout = json.dumps(
            {
                "signatures": [
                    {"offset": "0x438", "length": 2, "type": "ext4"}
                ]
            }
        )
        with mock.patch.object(make_device.subprocess, "run", return_value=probe):
            make_device._reject_recognized_tail_signatures(
                target_fd, candidate, image(size=8_000_000)
            )


class WritePathTests(unittest.TestCase):
    def _files(self, directory: str):
        source_path = Path(directory) / "source.iso"
        target_path = Path(directory) / "target.img"
        source_bytes = bytes((index % 251 for index in range(32_777)))
        target_bytes = b"Z" * (len(source_bytes) + 8192)
        source_path.write_bytes(source_bytes)
        target_path.write_bytes(target_bytes)
        source_fd = os.open(source_path, os.O_RDONLY)
        source_stat = os.fstat(source_fd)
        source = make_device.ImageInfo(
            path=str(source_path),
            size=len(source_bytes),
            sha256=hashlib.sha256(source_bytes).hexdigest(),
            device=source_stat.st_dev,
            inode=source_stat.st_ino,
            mtime_ns=source_stat.st_mtime_ns,
            backing_major_minor="0:42",
        )
        candidate = inventory(
            node("/dev/sdb", size=len(target_bytes))
        ).resolve_explicit("/dev/sdb")
        return source_path, target_path, source_bytes, target_bytes, source_fd, source, candidate

    def test_bounded_write_flushes_cache_verifies_prefix_and_preserves_tail(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            (
                _source_path,
                target_path,
                source_bytes,
                original_target,
                source_fd,
                source,
                candidate,
            ) = self._files(directory)
            target_fd = os.open(target_path, os.O_RDWR)
            checks: list[bool] = []
            open_sequence: list[str] = []
            state = make_device.OperationState()

            def fake_popen(_command, **kwargs):
                source_descriptor = kwargs["stdin"]
                target_descriptor = kwargs["stdout"]
                source_size = os.fstat(source_descriptor).st_size
                os.pwrite(
                    target_descriptor,
                    os.pread(source_descriptor, source_size, 0),
                    0,
                )
                return SimpleNamespace(
                    pid=999_001,
                    wait=lambda timeout=None: 0,
                    poll=lambda: 0,
                )

            def open_target(_candidate):
                open_sequence.append("exclusive-open")
                return target_fd

            def wipefs_probe(descriptor, _candidate, _image):
                self.assertEqual(descriptor, target_fd)
                open_sequence.append("descriptor-wipefs")

            try:
                with (
                    mock.patch.object(
                        make_device, "_open_target", side_effect=open_target
                    ),
                    mock.patch.object(
                        make_device, "_reject_stale_tail_metadata"
                    ) as tail_check,
                    mock.patch.object(
                        make_device,
                        "_reject_recognized_tail_signatures",
                        side_effect=wipefs_probe,
                    ),
                    mock.patch.object(
                        make_device.subprocess, "Popen", side_effect=fake_popen
                    ),
                    mock.patch.object(make_device.fcntl, "ioctl", return_value=0) as ioctl,
                    mock.patch.object(make_device.os, "sync"),
                    redirect_stderr(io.StringIO()),
                ):
                    verified = make_device.write_and_verify(
                        source_fd,
                        source,
                        candidate,
                        lambda: checks.append(True),
                        state,
                    )
                written = target_path.read_bytes()
                self.assertEqual(verified, source.sha256)
                self.assertEqual(written[: source.size], source_bytes)
                self.assertEqual(written[source.size :], original_target[source.size :])
                self.assertEqual(checks, [True])
                self.assertEqual(
                    open_sequence, ["exclusive-open", "descriptor-wipefs"]
                )
                self.assertEqual(state.phase, make_device.WritePhase.PREFIX_VERIFIED)
                tail_check.assert_called_once_with(target_fd, candidate, source)
                ioctl.assert_called_once_with(target_fd, make_device.BLKFLSBUF)
            finally:
                os.close(source_fd)

    def test_interrupt_after_first_written_byte_is_a_partial_write_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            (
                _source_path,
                target_path,
                _source_bytes,
                _original_target,
                source_fd,
                source,
                candidate,
            ) = self._files(directory)
            target_fd = os.open(target_path, os.O_RDWR)
            state = make_device.OperationState()

            class InterruptedProcess:
                pid = 999_002

                def __init__(self):
                    self.interrupted = False

                def wait(self, timeout=None):
                    del timeout
                    self.interrupted = True
                    raise KeyboardInterrupt

                def poll(self):
                    return -signal.SIGINT if self.interrupted else None

            def interrupted_popen(_command, **kwargs):
                os.pwrite(kwargs["stdout"], b"partial", 0)
                return InterruptedProcess()

            try:
                with (
                    mock.patch.object(make_device, "_open_target", return_value=target_fd),
                    mock.patch.object(make_device, "_reject_stale_tail_metadata"),
                    mock.patch.object(
                        make_device, "_reject_recognized_tail_signatures"
                    ),
                    mock.patch.object(
                        make_device.subprocess,
                        "Popen",
                        side_effect=interrupted_popen,
                    ),
                    redirect_stderr(io.StringIO()),
                ):
                    with self.assertRaises(KeyboardInterrupt):
                        make_device.write_and_verify(
                            source_fd, source, candidate, lambda: None, state
                        )
                self.assertTrue(state.target_overwritten_or_partial)
            finally:
                os.close(source_fd)

    def test_dd_fsync_flush_and_readback_errors_are_all_post_write_failures(self) -> None:
        for fault in ("dd", "fsync", "flush", "readback"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                (
                    _source_path,
                    target_path,
                    _source_bytes,
                    _original_target,
                    source_fd,
                    source,
                    candidate,
                ) = self._files(directory)
                target_fd = os.open(target_path, os.O_RDWR)
                state = make_device.OperationState()
                real_pread = os.pread

                def popen(_command, **kwargs):
                    if fault != "dd":
                        amount = os.fstat(kwargs["stdin"]).st_size
                        os.pwrite(
                            kwargs["stdout"], real_pread(kwargs["stdin"], amount, 0), 0
                        )
                    return SimpleNamespace(
                        pid=999_100,
                        wait=lambda timeout=None: 1 if fault == "dd" else 0,
                        poll=lambda: 1 if fault == "dd" else 0,
                    )

                def pread(descriptor, amount, offset):
                    if fault == "readback" and descriptor == target_fd:
                        raise OSError("injected readback error")
                    return real_pread(descriptor, amount, offset)

                try:
                    with ExitStack() as stack:
                        stack.enter_context(
                            mock.patch.object(
                                make_device, "_open_target", return_value=target_fd
                            )
                        )
                        stack.enter_context(
                            mock.patch.object(
                                make_device, "_reject_stale_tail_metadata"
                            )
                        )
                        stack.enter_context(
                            mock.patch.object(
                                make_device, "_reject_recognized_tail_signatures"
                            )
                        )
                        stack.enter_context(
                            mock.patch.object(
                                make_device.subprocess, "Popen", side_effect=popen
                            )
                        )
                        stack.enter_context(mock.patch.object(make_device.os, "sync"))
                        if fault == "fsync":
                            stack.enter_context(
                                mock.patch.object(
                                    make_device.os,
                                    "fsync",
                                    side_effect=OSError("injected fsync error"),
                                )
                            )
                        if fault == "flush":
                            stack.enter_context(
                                mock.patch.object(
                                    make_device.fcntl,
                                    "ioctl",
                                    side_effect=OSError("injected flush error"),
                                )
                            )
                        else:
                            stack.enter_context(
                                mock.patch.object(
                                    make_device.fcntl, "ioctl", return_value=0
                                )
                            )
                        stack.enter_context(
                            mock.patch.object(make_device.os, "pread", side_effect=pread)
                        )
                        stack.enter_context(redirect_stderr(io.StringIO()))
                        with self.assertRaises(make_device.WriteError):
                            make_device.write_and_verify(
                                source_fd,
                                source,
                                candidate,
                                lambda: None,
                                state,
                            )
                    self.assertTrue(state.target_overwritten_or_partial)
                    emitted: list[bytes] = []
                    with mock.patch.object(
                        make_device.os,
                        "write",
                        side_effect=lambda _fd, data: emitted.append(data) or len(data),
                    ):
                        self.assertEqual(
                            make_device._emit_failure(
                                state, RuntimeError(f"injected {fault} failure")
                            ),
                            4,
                        )
                    self.assertIn(b"target overwritten-or-partial", emitted[0])
                finally:
                    os.close(source_fd)

    def test_dd_process_group_is_terminated_with_a_bounded_escalation(self) -> None:
        class HungProcess:
            pid = 999_200

            def __init__(self):
                self.wait_calls = 0

            def wait(self, timeout=None):
                self.wait_calls += 1
                if self.wait_calls == 1:
                    raise make_device.OperationInterrupted(signal.SIGTERM)
                if self.wait_calls == 2:
                    raise make_device.subprocess.TimeoutExpired("dd", timeout)
                return -signal.SIGKILL

            def poll(self):
                return None

        state = make_device.OperationState()
        process = HungProcess()
        with (
            mock.patch.object(make_device.subprocess, "Popen", return_value=process),
            mock.patch.object(make_device.os, "killpg") as killpg,
            mock.patch.object(make_device.signal, "pthread_sigmask", return_value=set()),
        ):
            with self.assertRaises(make_device.OperationInterrupted):
                make_device._run_bounded_dd(
                    "/usr/bin/dd", 10, 11, 4096, state, "/dev/loop7"
                )
        self.assertEqual(
            [call.args[1] for call in killpg.call_args_list],
            [signal.SIGTERM, signal.SIGKILL],
        )
        self.assertTrue(state.target_overwritten_or_partial)

    def test_pending_signal_after_popen_is_supervised(self) -> None:
        process = SimpleNamespace(pid=999_201, wait=lambda timeout=None: 0, poll=lambda: None)

        def popen_with_signal(_command, **_kwargs):
            handler = signal.getsignal(signal.SIGTERM)
            self.assertTrue(callable(handler))
            handler(signal.SIGTERM, None)  # type: ignore[operator]
            return process

        state = make_device.OperationState()
        with (
            mock.patch.object(
                make_device.subprocess, "Popen", side_effect=popen_with_signal
            ),
            mock.patch.object(make_device, "_stop_dd_process") as stop_dd,
        ):
            with self.assertRaises(make_device.OperationInterrupted):
                make_device._run_bounded_dd(
                    "/usr/bin/dd", 10, 11, 4096, state, "/dev/loop7"
                )
        stop_dd.assert_called_once_with(process)
        self.assertTrue(state.target_overwritten_or_partial)

    def test_pending_signal_before_popen_restores_handlers_without_spawning(self) -> None:
        setmask_calls = 0
        original_handlers = {
            managed_signal: signal.getsignal(managed_signal)
            for managed_signal in make_device.MANAGED_SIGNALS
        }

        def deliver_on_first_unmask(how, _signals):
            nonlocal setmask_calls
            if how == signal.SIG_SETMASK:
                setmask_calls += 1
                if setmask_calls == 1:
                    handler = signal.getsignal(signal.SIGTERM)
                    self.assertTrue(callable(handler))
                    handler(signal.SIGTERM, None)  # type: ignore[operator]
            return set()

        state = make_device.OperationState()
        with (
            mock.patch.object(
                make_device.signal,
                "pthread_sigmask",
                side_effect=deliver_on_first_unmask,
            ),
            mock.patch.object(make_device.subprocess, "Popen") as popen,
        ):
            with self.assertRaises(make_device.OperationInterrupted):
                make_device._run_bounded_dd(
                    "/usr/bin/dd", 10, 11, 4096, state, "/dev/loop7"
                )
        popen.assert_not_called()
        for managed_signal, original_handler in original_handlers.items():
            self.assertIs(signal.getsignal(managed_signal), original_handler)
        self.assertTrue(state.target_overwritten_or_partial)

    def test_dd_is_spawned_with_managed_signals_unblocked(self) -> None:
        observed_mask: set[signal.Signals] = set()
        process = SimpleNamespace(pid=999_202, wait=lambda timeout=None: 0, poll=lambda: 0)

        def inspect_mask(_command, **_kwargs):
            observed_mask.update(signal.pthread_sigmask(signal.SIG_BLOCK, ()))
            return process

        state = make_device.OperationState()
        with mock.patch.object(
            make_device.subprocess, "Popen", side_effect=inspect_mask
        ):
            make_device._run_bounded_dd(
                "/usr/bin/dd", 10, 11, 4096, state, "/dev/loop7"
            )
        self.assertTrue(set(make_device.MANAGED_SIGNALS).isdisjoint(observed_mask))
        self.assertEqual(state.phase, make_device.WritePhase.DD_COMPLETED)


class LifecycleTests(unittest.TestCase):
    def test_every_managed_signal_is_failed_after_write_and_refused_before(self) -> None:
        for managed_signal in make_device.MANAGED_SIGNALS:
            with self.subTest(signal=managed_signal):
                with self.assertRaises(make_device.OperationInterrupted) as raised:
                    make_device._signal_interrupted(managed_signal, None)
                self.assertEqual(raised.exception.signal_number, managed_signal)
                error = make_device.OperationInterrupted(managed_signal)
                messages: list[bytes] = []
                with mock.patch.object(
                    make_device.os,
                    "write",
                    side_effect=lambda _fd, data: messages.append(data) or len(data),
                ):
                    self.assertEqual(
                        make_device._emit_failure(make_device.OperationState(), error), 3
                    )
                self.assertTrue(messages[0].startswith(b"REFUSED:"))

                state = make_device.OperationState()
                state.advance(
                    make_device.WritePhase.WRITE_MAY_HAVE_STARTED, "/dev/loop7"
                )
                messages.clear()
                with mock.patch.object(
                    make_device.os,
                    "write",
                    side_effect=lambda _fd, data: messages.append(data) or len(data),
                ):
                    self.assertEqual(make_device._emit_failure(state, error), 4)
                self.assertTrue(messages[0].startswith(b"FAILED:"))
                self.assertIn(b"overwritten-or-partial", messages[0])

    def test_report_or_close_failure_after_verify_is_never_refused(self) -> None:
        def verified_then_fail(_args, state):
            state.advance(make_device.WritePhase.PREFIX_VERIFIED, "/dev/loop7")
            raise OSError("injected post-verify close failure")

        messages: list[bytes] = []
        argv = [
            "--iso",
            "/tmp/fixture.iso",
            "--sha256",
            "a" * 64,
            "--device",
            "/dev/loop7",
        ]
        with (
            mock.patch.object(make_device, "execute", side_effect=verified_then_fail),
            mock.patch.object(
                make_device.os,
                "write",
                side_effect=lambda _fd, data: messages.append(data) or len(data),
            ),
        ):
            self.assertEqual(make_device.main(argv), 4)
        self.assertIn(b"target overwritten-or-partial", messages[0])

        post_report = make_device.OperationState()
        post_report.advance(make_device.WritePhase.REPORT_EMITTED, "/dev/loop7")
        messages.clear()
        with mock.patch.object(
            make_device.os,
            "write",
            side_effect=lambda _fd, data: messages.append(data) or len(data),
        ):
            self.assertEqual(
                make_device._emit_failure(
                    post_report, OSError("injected post-report failure")
                ),
                4,
            )
        self.assertIn(b"phase=REPORT_EMITTED", messages[0])

        def verified_report(_args, state):
            state.advance(make_device.WritePhase.PREFIX_VERIFIED, "/dev/loop7")
            return {"status": "verified"}

        messages.clear()
        with (
            mock.patch.object(make_device, "execute", side_effect=verified_report),
            mock.patch.object(
                make_device.sys.stdout,
                "write",
                side_effect=make_device.OperationInterrupted(signal.SIGHUP),
            ),
            mock.patch.object(
                make_device.os,
                "write",
                side_effect=lambda _fd, data: messages.append(data) or len(data),
            ),
        ):
            self.assertEqual(make_device.main(argv), 4)
        self.assertIn(b"target overwritten-or-partial", messages[0])


if __name__ == "__main__":
    unittest.main()
