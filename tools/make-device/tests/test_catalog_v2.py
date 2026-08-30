from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator


TOOLS_DIR = Path(__file__).resolve().parents[1]
REPO_DIR = Path(__file__).resolve().parents[3]
PARSER_PATH = TOOLS_DIR / "catalog_v2.py"
GENERATOR_PATH = TOOLS_DIR / "catalog-entry-v2.py"
MANIFEST_PATH = REPO_DIR / "rescue/image-layout/device-layout.v1.json"
PROFILE_PATH = REPO_DIR / "rescue/image-layout/vault-profile.v1.json"
CATALOG_PATH = TOOLS_DIR / "trusted-rescue-images.v2.json"
SCHEMA_PATH = TOOLS_DIR / "trusted-rescue-images.v2.schema.json"


def load_module(name: str, path: Path):
    specification = importlib.util.spec_from_file_location(name, path)
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


catalog_v2 = load_module("test_kernaid_catalog_v2", PARSER_PATH)
entry_v2 = load_module("test_kernaid_catalog_entry_v2", GENERATOR_PATH)


def sha(character: str) -> str:
    return character * 64


def uuid(character: str) -> str:
    return (
        character * 8
        + "-"
        + character * 4
        + "-"
        + character * 4
        + "-"
        + character * 4
        + "-"
        + character * 12
    )


def render_fields(prefix: str, fields: dict[str, str]) -> str:
    return prefix + " ".join(f"{key}={value}" for key, value in fields.items())


def mbr_partition(
    status: int, type_code: int, start_lba: int, sector_count: int
) -> bytes:
    maximum_chs = b"\xfe\xff\xff"
    return (
        bytes((status,))
        + maximum_chs
        + bytes((type_code,))
        + maximum_chs
        + struct.pack("<II", start_lba, sector_count)
    )


def synthetic_finalized_iso(slot3: str = "finalized") -> bytes:
    image = bytearray(4096)
    partition_table_offset = 446
    partition_entry_bytes = 16
    entries = (
        mbr_partition(0x80, 0x83, 1, 2),
        mbr_partition(0x00, 0xEF, 4, 2),
        mbr_partition(0x00, 0x83, 33_554_432, 16_777_216),
    )
    for index, entry in enumerate(entries):
        offset = partition_table_offset + index * partition_entry_bytes
        image[offset : offset + partition_entry_bytes] = entry
    if slot3 == "empty":
        offset = partition_table_offset + 2 * partition_entry_bytes
        image[offset : offset + partition_entry_bytes] = bytes(
            partition_entry_bytes
        )
    elif slot3 == "wrong":
        offset = partition_table_offset + 2 * partition_entry_bytes
        image[offset : offset + partition_entry_bytes] = mbr_partition(
            0x00, 0x83, 33_554_433, 16_777_216
        )
    elif slot3 != "finalized":
        raise ValueError(f"unsupported synthetic slot-3 state: {slot3}")
    image[510:512] = b"\x55\xaa"
    return bytes(image)


def synthetic_log(
    firmware: str,
    *,
    iso_size: int,
    iso_sha256: str,
    layout_sha256: str,
    include_vault: bool = True,
    include_legacy: bool = False,
    marker_boots: tuple[int, ...] = (1, 2),
    usb_overrides: dict[str, str] | None = None,
    vault_overrides: dict[str, str] | None = None,
) -> str:
    discriminator = "b" if firmware == "bios" else "c"
    # Keep this order identical to the final printf in qemu-usb-smoke.sh.
    usb = {
        "firmware": firmware,
        "transport": "usb-storage",
        "boot_count": "2",
        "ready_boots": "2",
        "uefi_vars": "fresh-per-boot" if firmware == "uefi" else "not-applicable",
        "media_bytes": "32000000000",
        "iso_bytes": str(iso_size),
        "layout_manifest_sha256": layout_sha256,
        "iso_sha256": iso_sha256,
        "prefix_before_sha256": iso_sha256,
        "prefix_after_sha256": iso_sha256,
        "p3_start_bytes": "17179869184",
        "p3_bytes": "8589934592",
        "p3_before_sha256": sha(discriminator),
        "p3_after_sha256": sha(discriminator),
        "target_before_sha256": sha("d"),
        "target_after_sha256": sha("d"),
        "ready": "true",
    }
    vault = {
        "firmware": firmware,
        "boot_count": "2",
        "luks_version": "2",
        "luks_label": "KERNAID_VAULT",
        "luks_uuid_before": uuid(discriminator),
        "luks_uuid_after": uuid(discriminator),
        "filesystem": "ext4",
        "filesystem_label": "KERNAID_VAULT",
        "vault_profile_version": "1",
        "vault_profile_sha256": catalog_v2.VAULT_PROFILE_SHA256,
        "filesystem_uuid_before": uuid("e" if firmware == "bios" else "f"),
        "filesystem_uuid_after": uuid("e" if firmware == "bios" else "f"),
        "journal_binding_before_sha256": entry_v2.JOURNAL_IDENTITY_BINDING_SHA256,
        "journal_binding_after_sha256": entry_v2.JOURNAL_IDENTITY_BINDING_SHA256,
        "identity_before_sha256": sha("2"),
        "identity_after_sha256": sha("2"),
        "vault_layout_verified": "true",
        "wrong_key_rejected": "true",
        "clean_shutdowns": "2",
    }
    usb.update(usb_overrides or {})
    vault.update(vault_overrides or {})
    lines = [f"synthetic {firmware} QEMU USB log"]
    if include_legacy:
        lines.append(
            "KERNAID_QEMU_ATTESTATION_V1 firmware="
            f"{firmware} iso_sha256={iso_sha256} ready=true"
        )
    for boot in marker_boots:
        lines.append(
            "KERNAID_QEMU_USB_BOOT_READY_V1 "
            f"firmware={firmware} boot={boot} ready=true"
        )
    lines.append(render_fields(entry_v2.USB_ATTESTATION_PREFIX, usb))
    if include_vault:
        for stage in ("post-initialize", "post-boot-verify"):
            for kind in ("luks2", "ext4"):
                lines.append(
                    render_fields(
                        entry_v2.VAULT_PROFILE_CHECK_PREFIX,
                        {
                            "firmware": firmware,
                            "stage": stage,
                            "kind": kind,
                            "vault_profile_version": "1",
                            "vault_profile_sha256": catalog_v2.VAULT_PROFILE_SHA256,
                            "verified": "true",
                        },
                    )
                )
        lines.append(render_fields(entry_v2.VAULT_ATTESTATION_PREFIX, vault))
    return "\n".join(lines) + "\n"


class CatalogV2Tests(unittest.TestCase):
    def test_checked_in_catalog_pins_the_qualified_release(self) -> None:
        catalog_raw = CATALOG_PATH.read_text(encoding="utf-8")
        catalog_document = json.loads(catalog_raw)
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(catalog_document)

        catalog = catalog_v2.parse_trust_catalog_v2(catalog_raw)
        self.assertEqual(catalog.revision, 5)
        self.assertEqual(len(catalog.images), 1)
        image = catalog.images[0]
        self.assertEqual(image.artifact_name, "KernAid-Rescue-amd64.iso")
        self.assertEqual(image.artifact_version, "ci-33259104331-1")
        self.assertEqual(
            image.sha256,
            "3df9a44f0c8b992f583b887fb10636a41fa7fae7bc4a2dc6284aa34ffcfc0c28",
        )
        self.assertEqual(image.size, 1_223_540_736)
        layout = catalog_v2.load_device_layout(MANIFEST_PATH)
        self.assertEqual(
            catalog.authorize(
                image.artifact_name,
                image.sha256,
                image.size,
                current_layout=layout,
            ),
            image,
        )
        with self.assertRaisesRegex(catalog_v2.CatalogV2Error, "not uniquely authorized"):
            catalog.authorize(
                "KernAid-Rescue-amd64.iso",
                sha("a"),
                1,
                current_layout=layout,
            )

    def test_layout_manifest_hash_and_geometry_are_immutable(self) -> None:
        layout = catalog_v2.load_device_layout(MANIFEST_PATH)
        self.assertEqual(
            layout.manifest_sha256,
            hashlib.sha256(MANIFEST_PATH.read_bytes()).hexdigest(),
        )
        self.assertEqual(layout.logical_sector_bytes, 512)
        self.assertEqual(layout.minimum_media_bytes, 25_769_803_776)
        self.assertEqual(layout.minimum_advertised_media_bytes, 32_000_000_000)
        self.assertEqual(layout.vault_profile_version, 1)
        self.assertEqual(
            layout.vault_profile_sha256, catalog_v2.VAULT_PROFILE_SHA256
        )
        self.assertEqual(layout.vault_partition.number, 3)
        self.assertEqual(layout.vault_partition.start_lba, 33_554_432)
        self.assertEqual(layout.vault_partition.sector_count, 16_777_216)

        document = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        document["vaultPartition"]["startLba"] += 1
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "layout.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaisesRegex(
                catalog_v2.CatalogV2Error, "immutable layout-v1"
            ):
                catalog_v2.load_device_layout(path)

    def test_canonical_vault_profile_document_and_digest_are_required(self) -> None:
        self.assertEqual(
            catalog_v2.load_vault_profile(PROFILE_PATH),
            catalog_v2.VAULT_PROFILE_SHA256,
        )
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            layout = directory / "device-layout.v1.json"
            profile = directory / catalog_v2.VAULT_PROFILE_FILENAME
            layout.write_bytes(MANIFEST_PATH.read_bytes())
            profile.write_bytes(PROFILE_PATH.read_bytes())
            document = json.loads(profile.read_text(encoding="utf-8"))
            document["luks2"]["dataOffsetBytes"] //= 2
            profile.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaisesRegex(
                catalog_v2.CatalogV2Error, "immutable profile-v1"
            ):
                catalog_v2.load_device_layout(layout)

    def _fixture(
        self, directory: Path, *, slot3: str = "finalized"
    ) -> tuple[Path, str, object, Path, Path]:
        iso = directory / "KernAid-Rescue-amd64.iso"
        iso.write_bytes(synthetic_finalized_iso(slot3))
        iso_sha256 = hashlib.sha256(iso.read_bytes()).hexdigest()
        layout = catalog_v2.load_device_layout(MANIFEST_PATH)
        bios_log = directory / "bios.log"
        uefi_log = directory / "uefi.log"
        bios_log.write_text(
            synthetic_log(
                "bios",
                iso_size=iso.stat().st_size,
                iso_sha256=iso_sha256,
                layout_sha256=layout.manifest_sha256,
            ),
            encoding="utf-8",
        )
        uefi_log.write_text(
            synthetic_log(
                "uefi",
                iso_size=iso.stat().st_size,
                iso_sha256=iso_sha256,
                layout_sha256=layout.manifest_sha256,
            ),
            encoding="utf-8",
        )
        return iso, iso_sha256, layout, bios_log, uefi_log

    def _generator_command(
        self,
        iso: Path,
        iso_sha256: str,
        bios_log: Path,
        uefi_log: Path,
    ) -> list[str]:
        return [
            sys.executable,
            "-I",
            "-B",
            str(GENERATOR_PATH),
            "--iso",
            str(iso),
            "--sha256",
            iso_sha256,
            "--layout-manifest",
            str(MANIFEST_PATH),
            "--artifact-version",
            "ci-4242-1",
            "--bios-run-id",
            "4242",
            "--bios-run-url",
            "https://github.com/0xfunboy/KernAid/actions/runs/4242",
            "--bios-log",
            str(bios_log),
            "--uefi-run-id",
            "4242",
            "--uefi-run-url",
            "https://github.com/0xfunboy/KernAid/actions/runs/4242",
            "--uefi-log",
            str(uefi_log),
        ]

    def _generated_entry(
        self, directory: Path
    ) -> tuple[dict[str, object], str, object]:
        iso, digest, layout, bios_log, uefi_log = self._fixture(directory)
        result = subprocess.run(
            self._generator_command(iso, digest, bios_log, uefi_log),
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout), digest, layout

    def test_generator_emits_only_a_fully_bound_v2_entry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            iso, digest, layout, bios_log, uefi_log = self._fixture(Path(temporary))
            result = subprocess.run(
                self._generator_command(iso, digest, bios_log, uefi_log),
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        entry = json.loads(result.stdout)
        self.assertEqual(entry["sha256"], digest)
        self.assertEqual(entry["bytes"], len(synthetic_finalized_iso()))
        self.assertEqual(
            entry["deviceLayout"]["manifestSha256"], layout.manifest_sha256
        )
        self.assertEqual(
            entry["qemuUsbBootAttestations"]["bios"]["bootTransport"],
            "usb-storage",
        )
        self.assertTrue(
            entry["qemuVaultAttestations"]["uefi"]["identityVerified"]
        )
        parsed = catalog_v2.parse_trust_catalog_v2(
            json.dumps(
                {
                    "schema": catalog_v2.CATALOG_SCHEMA,
                    "catalogRevision": 1,
                    "images": [entry],
                }
            )
        )
        self.assertEqual(len(parsed.images), 1)
        self.assertEqual(
            parsed.authorize(
                entry["artifactName"],
                digest,
                entry["bytes"],
                current_layout=layout,
            ).sha256,
            digest,
        )

    def test_generator_rejects_unfinalized_or_wrong_slot_3(self) -> None:
        for slot3 in ("empty", "wrong"):
            with self.subTest(slot3=slot3), tempfile.TemporaryDirectory() as temporary:
                iso, digest, _layout, bios_log, uefi_log = self._fixture(
                    Path(temporary), slot3=slot3
                )
                result = subprocess.run(
                    self._generator_command(iso, digest, bios_log, uefi_log),
                    check=False,
                    capture_output=True,
                    text=True,
                )
            self.assertEqual(result.returncode, 3)
            self.assertEqual(result.stdout, "")
            self.assertIn("not finalized as immutable layout-v1", result.stderr)
            self.assertIn("partition slot 3", result.stderr)

    def test_layout_only_usb_log_cannot_be_promoted_as_vault_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            iso, digest, layout, bios_log, uefi_log = self._fixture(directory)
            bios_log.write_text(
                synthetic_log(
                    "bios",
                    iso_size=iso.stat().st_size,
                    iso_sha256=digest,
                    layout_sha256=layout.manifest_sha256,
                    include_vault=False,
                ),
                encoding="utf-8",
            )
            result = subprocess.run(
                self._generator_command(iso, digest, bios_log, uefi_log),
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertEqual(result.returncode, 3)
        self.assertEqual(result.stdout, "")
        self.assertIn("independent vault attestation", result.stderr)

    def test_legacy_cdrom_attestation_is_never_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            iso, digest, layout, bios_log, _uefi_log = self._fixture(directory)
            bios_log.write_text(
                synthetic_log(
                    "bios",
                    iso_size=iso.stat().st_size,
                    iso_sha256=digest,
                    layout_sha256=layout.manifest_sha256,
                    include_legacy=True,
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "legacy CD-ROM"):
                entry_v2.attested_log(
                    bios_log,
                    firmware="bios",
                    iso_size=iso.stat().st_size,
                    iso_sha256=digest,
                    layout=layout,
                )

    def test_usb_evidence_requires_two_markers_and_stable_regions(self) -> None:
        cases = (
            ({}, (1,), "ready marker"),
            ({"boot_count": "1"}, (1, 2), "exactly two boots"),
            ({"transport": "cdrom"}, (1, 2), "not booted as USB"),
            ({"ready_boots": "1"}, (1, 2), "reach readiness twice"),
            ({"ready": "false"}, (1, 2), "did not pass readiness"),
            ({"p3_start_bytes": "17179869696"}, (1, 2), "p3 start"),
            ({"p3_bytes": "8589934080"}, (1, 2), "p3 size"),
            ({"p3_after_sha256": sha("9")}, (1, 2), "vault partition changed"),
            ({"target_after_sha256": sha("9")}, (1, 2), "Observe target changed"),
        )
        for overrides, markers, error in cases:
            with self.subTest(overrides=overrides), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                iso, digest, layout, bios_log, _uefi_log = self._fixture(directory)
                bios_log.write_text(
                    synthetic_log(
                        "bios",
                        iso_size=iso.stat().st_size,
                        iso_sha256=digest,
                        layout_sha256=layout.manifest_sha256,
                        marker_boots=markers,
                        usb_overrides=overrides,
                    ),
                    encoding="utf-8",
                )
                with self.assertRaisesRegex(ValueError, error):
                    entry_v2.attested_log(
                        bios_log,
                        firmware="bios",
                        iso_size=iso.stat().st_size,
                        iso_sha256=digest,
                        layout=layout,
                    )

    def test_exact_qemu_usb_smoke_attestation_shape_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            iso, digest, layout, bios_log, _uefi_log = self._fixture(
                Path(temporary)
            )
            usb_line = next(
                line
                for line in bios_log.read_text(encoding="utf-8").splitlines()
                if line.startswith(entry_v2.USB_ATTESTATION_PREFIX)
            )
            keys = [
                token.partition("=")[0]
                for token in usb_line.removeprefix(
                    entry_v2.USB_ATTESTATION_PREFIX
                ).split()
            ]
            self.assertEqual(
                keys,
                [
                    "firmware",
                    "transport",
                    "boot_count",
                    "ready_boots",
                    "uefi_vars",
                    "media_bytes",
                    "iso_bytes",
                    "layout_manifest_sha256",
                    "iso_sha256",
                    "prefix_before_sha256",
                    "prefix_after_sha256",
                    "p3_start_bytes",
                    "p3_bytes",
                    "p3_before_sha256",
                    "p3_after_sha256",
                    "target_before_sha256",
                    "target_after_sha256",
                    "ready",
                ],
            )
            self.assertRegex(
                entry_v2.attested_log(
                    bios_log,
                    firmware="bios",
                    iso_size=iso.stat().st_size,
                    iso_sha256=digest,
                    layout=layout,
                ),
                r"^[0-9a-f]{64}$",
            )
            lines = bios_log.read_text(encoding="utf-8").splitlines()
            removed = False
            incomplete: list[str] = []
            for line in lines:
                if (
                    not removed
                    and line.startswith(entry_v2.VAULT_PROFILE_CHECK_PREFIX)
                ):
                    removed = True
                    continue
                incomplete.append(line)
            bios_log.write_text("\n".join(incomplete) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "four exact vault profile checks"):
                entry_v2.attested_log(
                    bios_log,
                    firmware="bios",
                    iso_size=iso.stat().st_size,
                    iso_sha256=digest,
                    layout=layout,
                )

    def test_vault_evidence_requires_luks_ext4_and_stable_state(self) -> None:
        cases = (
            ({"luks_version": "1"}, "not LUKS2"),
            ({"filesystem": "btrfs"}, "wrong inner filesystem"),
            ({"luks_uuid_after": uuid("9")}, "LUKS UUID"),
            (
                {"journal_binding_after_sha256": sha("9")},
                "journal identity binding changed",
            ),
            ({"identity_after_sha256": sha("9")}, "device identity changed"),
            ({"wrong_key_rejected": "false"}, "wrong_key_rejected"),
        )
        for overrides, error in cases:
            with self.subTest(overrides=overrides), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                iso, digest, layout, bios_log, _uefi_log = self._fixture(directory)
                bios_log.write_text(
                    synthetic_log(
                        "bios",
                        iso_size=iso.stat().st_size,
                        iso_sha256=digest,
                        layout_sha256=layout.manifest_sha256,
                        vault_overrides=overrides,
                    ),
                    encoding="utf-8",
                )
                with self.assertRaisesRegex(ValueError, error):
                    entry_v2.attested_log(
                        bios_log,
                        firmware="bios",
                        iso_size=iso.stat().st_size,
                        iso_sha256=digest,
                        layout=layout,
                    )

    def test_vault_evidence_pins_the_exact_journal_identity_binding(self) -> None:
        for digest in (
            "f248a3890e9b96b45e1e371fa4dda54b944ada7cae48c96f66f4951bc6e6515e",
            sha("9"),
        ):
            with self.subTest(digest=digest), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                iso, iso_digest, layout, bios_log, _uefi_log = self._fixture(directory)
                bios_log.write_text(
                    synthetic_log(
                        "bios",
                        iso_size=iso.stat().st_size,
                        iso_sha256=iso_digest,
                        layout_sha256=layout.manifest_sha256,
                        vault_overrides={
                            "journal_binding_before_sha256": digest,
                            "journal_binding_after_sha256": digest,
                        },
                    ),
                    encoding="utf-8",
                )
                with self.assertRaisesRegex(ValueError, "wrong journal identity binding"):
                    entry_v2.attested_log(
                        bios_log,
                        firmware="bios",
                        iso_size=iso.stat().st_size,
                        iso_sha256=iso_digest,
                        layout=layout,
                    )

    def test_catalog_parser_rejects_changed_layout_and_false_vault_claims(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            iso, digest, _layout, bios_log, uefi_log = self._fixture(Path(temporary))
            result = subprocess.run(
                self._generator_command(iso, digest, bios_log, uefi_log),
                check=True,
                capture_output=True,
                text=True,
            )
        entry = json.loads(result.stdout)
        base = {
            "schema": catalog_v2.CATALOG_SCHEMA,
            "catalogRevision": 1,
            "images": [entry],
        }
        changed_layout = copy.deepcopy(base)
        changed_layout["images"][0]["deviceLayout"]["vaultPartition"][
            "startLba"
        ] += 1
        with self.assertRaisesRegex(catalog_v2.CatalogV2Error, "immutable layout-v1"):
            catalog_v2.parse_trust_catalog_v2(json.dumps(changed_layout))

        false_vault = copy.deepcopy(base)
        false_vault["images"][0]["qemuVaultAttestations"]["bios"][
            "journalIdentityBindingVerified"
        ] = False
        with self.assertRaisesRegex(
            catalog_v2.CatalogV2Error, "journal identity binding"
        ):
            catalog_v2.parse_trust_catalog_v2(json.dumps(false_vault))

    def test_authorization_rejects_a_stale_manifest_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            entry, digest, current_layout = self._generated_entry(
                Path(temporary)
            )
        stale_entry = copy.deepcopy(entry)
        stale_entry["deviceLayout"]["manifestSha256"] = sha("9")
        catalog = catalog_v2.parse_trust_catalog_v2(
            json.dumps(
                {
                    "schema": catalog_v2.CATALOG_SCHEMA,
                    "catalogRevision": 1,
                    "images": [stale_entry],
                }
            )
        )
        with self.assertRaisesRegex(
            catalog_v2.CatalogV2Error, "current device layout manifest"
        ):
            catalog.authorize(
                stale_entry["artifactName"],
                digest,
                stale_entry["bytes"],
                current_layout=current_layout,
            )

    def test_parser_rejects_cross_field_evidence_mismatches(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            entry, _digest, _layout = self._generated_entry(Path(temporary))
        base = {
            "schema": catalog_v2.CATALOG_SCHEMA,
            "catalogRevision": 1,
            "images": [entry],
        }

        different_vault_run = copy.deepcopy(base)
        bios_vault = different_vault_run["images"][0][
            "qemuVaultAttestations"
        ]["bios"]
        bios_vault["workflowRunId"] = 4243
        bios_vault["workflowRunUrl"] = (
            "https://github.com/0xfunboy/KernAid/actions/runs/4243"
        )
        with self.assertRaisesRegex(
            catalog_v2.CatalogV2Error, "same workflow log"
        ):
            catalog_v2.parse_trust_catalog_v2(
                json.dumps(different_vault_run)
            )

        reused_firmware_log = copy.deepcopy(base)
        bios_log_sha256 = reused_firmware_log["images"][0][
            "qemuUsbBootAttestations"
        ]["bios"]["logSha256"]
        for family in (
            "qemuUsbBootAttestations",
            "qemuVaultAttestations",
        ):
            reused_firmware_log["images"][0][family]["uefi"][
                "logSha256"
            ] = bios_log_sha256
        with self.assertRaisesRegex(
            catalog_v2.CatalogV2Error, "cannot reuse one log"
        ):
            catalog_v2.parse_trust_catalog_v2(
                json.dumps(reused_firmware_log)
            )

    def test_parser_rejects_duplicate_image_identity_or_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            entry, _digest, _layout = self._generated_entry(Path(temporary))

        duplicate_identity = copy.deepcopy(entry)
        duplicate_identity["sha256"] = sha("7")
        with self.assertRaisesRegex(
            catalog_v2.CatalogV2Error, "duplicate image identity"
        ):
            catalog_v2.parse_trust_catalog_v2(
                json.dumps(
                    {
                        "schema": catalog_v2.CATALOG_SCHEMA,
                        "catalogRevision": 1,
                        "images": [entry, duplicate_identity],
                    }
                )
            )

        duplicate_digest = copy.deepcopy(entry)
        duplicate_digest["artifactName"] = "KernAid-Rescue-copy.iso"
        duplicate_digest["artifactVersion"] = "ci-4242-2"
        with self.assertRaisesRegex(
            catalog_v2.CatalogV2Error, "duplicate image identity"
        ):
            catalog_v2.parse_trust_catalog_v2(
                json.dumps(
                    {
                        "schema": catalog_v2.CATALOG_SCHEMA,
                        "catalogRevision": 1,
                        "images": [entry, duplicate_digest],
                    }
                )
            )

    def test_draft_2020_schema_accepts_a_generated_entry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            entry, _digest, _layout = self._generated_entry(Path(temporary))
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        catalog = {
            "schema": catalog_v2.CATALOG_SCHEMA,
            "catalogRevision": 1,
            "images": [entry],
        }
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(catalog)

    def test_catalog_v2_never_falls_back_to_v1_schema(self) -> None:
        document = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
        document["schema"] = "dev.kernaid.trusted-rescue-images.v1"
        with self.assertRaisesRegex(catalog_v2.CatalogV2Error, "unsupported"):
            catalog_v2.parse_trust_catalog_v2(json.dumps(document))

    def test_schema_keeps_boot_and_vault_claims_separate(self) -> None:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        image = schema["$defs"]["image"]
        self.assertIn("qemuUsbBootAttestations", image["required"])
        self.assertIn("qemuVaultAttestations", image["required"])
        self.assertNotIn(
            "vaultPersistenceVerified",
            schema["$defs"]["usbBootAttestation"]["required"],
        )
        self.assertIn(
            "journalIdentityBindingVerified",
            schema["$defs"]["vaultAttestation"]["required"],
        )
        self.assertIn("cross-field", schema["$comment"])
        self.assertIn("same workflow", image["description"])


if __name__ == "__main__":
    unittest.main()
