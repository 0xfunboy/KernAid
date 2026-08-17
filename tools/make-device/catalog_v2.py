#!/usr/bin/python3 -I
"""Strict, side-effect-free parser for the KernAid Rescue trust catalog v2.

Catalog v2 is deliberately separate from the active v1 writer.  It binds an
image to the immutable Phase 0 device layout and to two-boot BIOS and UEFI
QEMU runs which used the image as USB mass storage.  This module performs no
block-device operations and does not load the v1 catalog as a fallback.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final


CATALOG_SCHEMA: Final = "dev.kernaid.trusted-rescue-images.v2"
LAYOUT_SCHEMA: Final = "kernaid.rescue-device-layout.v1"
PARTITION_TABLE: Final = "mbr"
LOGICAL_SECTOR_BYTES: Final = 512
MINIMUM_MEDIA_BYTES: Final = 25_769_803_776
MINIMUM_ADVERTISED_MEDIA_BYTES: Final = 32_000_000_000
MINIMUM_ADVERTISED_MEDIA_LABEL: Final = "32 GB"
VAULT_PARTITION_NUMBER: Final = 3
VAULT_PARTITION_NAME: Final = "KERNAID_VAULT"
VAULT_MBR_TYPE: Final = "0x83"
VAULT_START_LBA: Final = 33_554_432
VAULT_SECTOR_COUNT: Final = 16_777_216
BOOT_TRANSPORT: Final = "usb-storage"
REQUIRED_BOOT_COUNT: Final = 2
VAULT_PROFILE_VERSION: Final = 1
VAULT_PROFILE_SHA256: Final = (
    "b4801359bd4f31ce67fbd3ec15b6c81c44aa6759ba43b2a4e099a7dfcc25a37c"
)

MAX_CATALOG_BYTES: Final = 2 * 1024 * 1024
MAX_MANIFEST_BYTES: Final = 64 * 1024
MAX_PROFILE_BYTES: Final = 64 * 1024
VAULT_PROFILE_FILENAME: Final = "vault-profile.v1.json"
READ_CHUNK_BYTES: Final = 1024 * 1024
SHA256_RE: Final = re.compile(r"[0-9a-f]{64}\Z")
ARTIFACT_NAME_RE: Final = re.compile(
    r"KernAid-Rescue-[A-Za-z0-9._-]+\.iso\Z"
)
ARTIFACT_VERSION_RE: Final = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}\Z"
)
CONTROL_RE: Final = re.compile(r"[\x00-\x1f\x7f]")
TRUSTED_RUN_URL_PREFIX: Final = (
    "https://github.com/0xfunboy/KernAid/actions/runs/"
)


class CatalogV2Error(RuntimeError):
    """The v2 catalog or its immutable device-layout binding is invalid."""


VAULT_PROFILE_DOCUMENT: Final = {
    "schema": "kernaid.vault-profile.v1",
    "luks2": {
        "afHash": "sha256",
        "afStripes": 4000,
        "cipher": "aes-xts-plain64",
        "dataOffsetBytes": 16777216,
        "digestHash": "sha256",
        "digestIterations": 1000,
        "keyBits": 512,
        "keyslot": 0,
        "keyslotAreaBytes": 258048,
        "keyslotAreaOffsetBytes": 32768,
        "keyslotsBytes": 16744448,
        "metadataBytes": 16384,
        "pbkdf": "argon2id",
        "pbkdfCpus": 1,
        "pbkdfMemoryKiB": 65536,
        "pbkdfTime": 4,
        "sectorBytes": 512,
    },
    "ext4": {
        "blockBytes": 4096,
        "blocksPerGroup": 32768,
        "bytesPerInode": 16384,
        "defaultMountOptions": "none",
        "errors": "remount-ro",
        "featuresCompat": 60,
        "featuresIncompat": 706,
        "featuresRoCompat": 1131,
        "flexGroupSize": 16,
        "inodeBytes": 256,
        "journalMiB": 128,
        "reservedPercent": 0,
    },
}


@dataclass(frozen=True)
class VaultPartition:
    number: int
    name: str
    mbr_type: str
    start_lba: int
    sector_count: int

    def as_document(self) -> dict[str, object]:
        return {
            "number": self.number,
            "name": self.name,
            "mbrType": self.mbr_type,
            "startLba": self.start_lba,
            "sectorCount": self.sector_count,
        }


@dataclass(frozen=True)
class DeviceLayout:
    schema: str
    manifest_sha256: str
    partition_table: str
    logical_sector_bytes: int
    minimum_media_bytes: int
    minimum_advertised_media_bytes: int
    minimum_advertised_media_label: str
    vault_profile_version: int
    vault_profile_sha256: str
    vault_partition: VaultPartition

    def as_document(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "manifestSha256": self.manifest_sha256,
            "partitionTable": self.partition_table,
            "logicalSectorBytes": self.logical_sector_bytes,
            "minimumMediaBytes": self.minimum_media_bytes,
            "minimumAdvertisedMediaBytes": self.minimum_advertised_media_bytes,
            "minimumAdvertisedMediaLabel": self.minimum_advertised_media_label,
            "vaultProfileVersion": self.vault_profile_version,
            "vaultProfileSha256": self.vault_profile_sha256,
            "vaultPartition": self.vault_partition.as_document(),
        }


@dataclass(frozen=True)
class QemuUsbBootAttestation:
    firmware: str
    workflow_run_id: int
    workflow_run_url: str
    log_sha256: str

    def as_document(self) -> dict[str, object]:
        return {
            "passed": True,
            "bootTransport": BOOT_TRANSPORT,
            "bootCount": REQUIRED_BOOT_COUNT,
            "targetZeroWritesVerified": True,
            "workflowRunId": self.workflow_run_id,
            "workflowRunUrl": self.workflow_run_url,
            "logSha256": self.log_sha256,
        }


@dataclass(frozen=True)
class QemuVaultAttestation:
    firmware: str
    workflow_run_id: int
    workflow_run_url: str
    log_sha256: str

    def as_document(self) -> dict[str, object]:
        return {
            "passed": True,
            "bootCount": REQUIRED_BOOT_COUNT,
            "luksVersion": 2,
            "luksLabel": VAULT_PARTITION_NAME,
            "filesystem": "ext4",
            "filesystemLabel": VAULT_PARTITION_NAME,
            "vaultProfileVersion": VAULT_PROFILE_VERSION,
            "vaultProfileSha256": VAULT_PROFILE_SHA256,
            "stableUuidsVerified": True,
            "journalIdentityBindingVerified": True,
            "identityVerified": True,
            "wrongKeyRejected": True,
            "workflowRunId": self.workflow_run_id,
            "workflowRunUrl": self.workflow_run_url,
            "logSha256": self.log_sha256,
        }


@dataclass(frozen=True)
class TrustedImageV2:
    artifact_name: str
    artifact_version: str
    sha256: str
    size: int
    device_layout: DeviceLayout
    bios_usb_boot: QemuUsbBootAttestation
    uefi_usb_boot: QemuUsbBootAttestation
    bios_vault: QemuVaultAttestation
    uefi_vault: QemuVaultAttestation

    def as_document(self) -> dict[str, object]:
        return {
            "artifactName": self.artifact_name,
            "artifactVersion": self.artifact_version,
            "sha256": self.sha256,
            "bytes": self.size,
            "deviceLayout": self.device_layout.as_document(),
            "qemuUsbBootAttestations": {
                "bios": self.bios_usb_boot.as_document(),
                "uefi": self.uefi_usb_boot.as_document(),
            },
            "qemuVaultAttestations": {
                "bios": self.bios_vault.as_document(),
                "uefi": self.uefi_vault.as_document(),
            },
        }


@dataclass(frozen=True)
class TrustCatalogV2:
    revision: int
    images: tuple[TrustedImageV2, ...]

    def authorize(
        self,
        artifact_name: str,
        sha256: str,
        size: int,
        *,
        current_layout: DeviceLayout,
    ) -> TrustedImageV2:
        if not isinstance(current_layout, DeviceLayout):
            raise CatalogV2Error(
                "authorization requires the current validated device layout"
            )
        matches = [
            image
            for image in self.images
            if image.artifact_name == artifact_name
            and hmac.compare_digest(image.sha256, sha256)
            and image.size == size
        ]
        if len(matches) != 1:
            raise CatalogV2Error(
                "image is not uniquely authorized by the Rescue trust catalog v2"
            )
        image = matches[0]
        if image.device_layout != current_layout:
            raise CatalogV2Error(
                "image is not bound to the current device layout manifest"
            )
        return image


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CatalogV2Error(f"JSON contains duplicate key: {key}")
        result[key] = value
    return result


def _exact_object(
    value: object, expected_keys: set[str], location: str
) -> dict[str, object]:
    if not isinstance(value, dict):
        raise CatalogV2Error(f"{location} must be an object")
    actual_keys = set(value)
    if actual_keys != expected_keys:
        missing = sorted(expected_keys - actual_keys)
        extra = sorted(actual_keys - expected_keys)
        raise CatalogV2Error(
            f"{location} keys are not exact (missing={missing}, extra={extra})"
        )
    return value


def _text(value: object, location: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 4096:
        raise CatalogV2Error(f"{location} must be a bounded non-empty string")
    if CONTROL_RE.search(value):
        raise CatalogV2Error(f"{location} contains control characters")
    return value


def _integer(value: object, location: str, *, minimum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise CatalogV2Error(
            f"{location} must be an integer greater than or equal to {minimum}"
        )
    return value


def _sha256(value: object, location: str) -> str:
    digest = _text(value, location)
    if not SHA256_RE.fullmatch(digest):
        raise CatalogV2Error(f"{location} must be lowercase SHA-256")
    return digest


def _parse_json_bytes(raw: bytes, *, maximum: int, location: str) -> object:
    if not raw or len(raw) > maximum:
        raise CatalogV2Error(f"{location} has an invalid size")
    try:
        decoded = raw.decode("utf-8", "strict")
        return json.loads(decoded, object_pairs_hook=_reject_duplicate_keys)
    except UnicodeDecodeError as error:
        raise CatalogV2Error(f"{location} is not strict UTF-8") from error
    except json.JSONDecodeError as error:
        raise CatalogV2Error(f"{location} is not valid JSON") from error


def read_regular_file(path: Path, maximum: int, location: str) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise CatalogV2Error(f"cannot open {location}: {error}") from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size <= 0
            or before.st_size > maximum
        ):
            raise CatalogV2Error(f"{location} must be a bounded regular file")
        chunks: list[bytes] = []
        total = 0
        while total < before.st_size:
            try:
                chunk = os.read(
                    descriptor, min(READ_CHUNK_BYTES, before.st_size - total)
                )
            except OSError as error:
                raise CatalogV2Error(f"cannot read {location}: {error}") from error
            if not chunk:
                raise CatalogV2Error(f"{location} ended while being read")
            chunks.append(chunk)
            total += len(chunk)
        after = os.fstat(descriptor)
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        )
        if identity_before != identity_after:
            raise CatalogV2Error(f"{location} changed while being read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def sha256_regular_file(path: Path, location: str) -> tuple[int, str]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise CatalogV2Error(f"cannot open {location}: {error}") from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size <= 0:
            raise CatalogV2Error(f"{location} must be a non-empty regular file")
        digest = hashlib.sha256()
        total = 0
        while total < before.st_size:
            try:
                chunk = os.read(
                    descriptor, min(READ_CHUNK_BYTES, before.st_size - total)
                )
            except OSError as error:
                raise CatalogV2Error(f"cannot hash {location}: {error}") from error
            if not chunk:
                raise CatalogV2Error(f"{location} ended while being hashed")
            digest.update(chunk)
            total += len(chunk)
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise CatalogV2Error(f"{location} changed while being hashed")
        return before.st_size, digest.hexdigest()
    finally:
        os.close(descriptor)


def _vault_partition(document: object, location: str) -> VaultPartition:
    value = _exact_object(
        document,
        {"number", "name", "mbrType", "startLba", "sectorCount"},
        location,
    )
    partition = VaultPartition(
        number=_integer(value["number"], f"{location}.number", minimum=1),
        name=_text(value["name"], f"{location}.name"),
        mbr_type=_text(value["mbrType"], f"{location}.mbrType"),
        start_lba=_integer(value["startLba"], f"{location}.startLba", minimum=1),
        sector_count=_integer(
            value["sectorCount"], f"{location}.sectorCount", minimum=1
        ),
    )
    expected = VaultPartition(
        VAULT_PARTITION_NUMBER,
        VAULT_PARTITION_NAME,
        VAULT_MBR_TYPE,
        VAULT_START_LBA,
        VAULT_SECTOR_COUNT,
    )
    if partition != expected:
        raise CatalogV2Error(f"{location} changes immutable layout-v1 geometry")
    return partition


def load_vault_profile(path: Path) -> str:
    raw = read_regular_file(path, MAX_PROFILE_BYTES, "vault profile manifest")
    document = _parse_json_bytes(
        raw, maximum=MAX_PROFILE_BYTES, location="vault profile manifest"
    )
    if document != VAULT_PROFILE_DOCUMENT:
        raise CatalogV2Error("vault profile manifest changes immutable profile-v1")
    canonical = json.dumps(
        document, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    digest = hashlib.sha256(canonical).hexdigest()
    if digest != VAULT_PROFILE_SHA256:
        raise CatalogV2Error("vault profile canonical SHA-256 is not immutable profile-v1")
    return digest


def load_device_layout(path: Path) -> DeviceLayout:
    raw = read_regular_file(path, MAX_MANIFEST_BYTES, "device layout manifest")
    document = _parse_json_bytes(
        raw, maximum=MAX_MANIFEST_BYTES, location="device layout manifest"
    )
    value = _exact_object(
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
        "device layout manifest",
    )
    layout_version = _integer(
        value["layoutVersion"], "device layout manifest.layoutVersion", minimum=1
    )
    layout = DeviceLayout(
        schema=_text(value["schema"], "device layout manifest.schema"),
        manifest_sha256=hashlib.sha256(raw).hexdigest(),
        partition_table=_text(
            value["partitionTable"], "device layout manifest.partitionTable"
        ),
        logical_sector_bytes=_integer(
            value["logicalSectorBytes"],
            "device layout manifest.logicalSectorBytes",
            minimum=1,
        ),
        minimum_media_bytes=_integer(
            value["minimumMediaBytes"],
            "device layout manifest.minimumMediaBytes",
            minimum=1,
        ),
        minimum_advertised_media_bytes=_integer(
            value["minimumAdvertisedMediaBytes"],
            "device layout manifest.minimumAdvertisedMediaBytes",
            minimum=1,
        ),
        minimum_advertised_media_label=_text(
            value["minimumAdvertisedMediaLabel"],
            "device layout manifest.minimumAdvertisedMediaLabel",
        ),
        vault_profile_version=_integer(
            value["vaultProfileVersion"],
            "device layout manifest.vaultProfileVersion",
            minimum=1,
        ),
        vault_profile_sha256=_sha256(
            value["vaultProfileSha256"],
            "device layout manifest.vaultProfileSha256",
        ),
        vault_partition=_vault_partition(
            value["vaultPartition"], "device layout manifest.vaultPartition"
        ),
    )
    immutable = (
        (layout.schema, LAYOUT_SCHEMA),
        (layout_version, 1),
        (layout.partition_table, PARTITION_TABLE),
        (layout.logical_sector_bytes, LOGICAL_SECTOR_BYTES),
        (layout.minimum_media_bytes, MINIMUM_MEDIA_BYTES),
        (
            layout.minimum_advertised_media_bytes,
            MINIMUM_ADVERTISED_MEDIA_BYTES,
        ),
        (
            layout.minimum_advertised_media_label,
            MINIMUM_ADVERTISED_MEDIA_LABEL,
        ),
        (layout.vault_profile_version, VAULT_PROFILE_VERSION),
        (layout.vault_profile_sha256, VAULT_PROFILE_SHA256),
    )
    if any(actual != expected for actual, expected in immutable):
        raise CatalogV2Error("device layout manifest changes immutable layout-v1")
    vault_end = (
        layout.vault_partition.start_lba
        + layout.vault_partition.sector_count
    ) * layout.logical_sector_bytes
    if vault_end != layout.minimum_media_bytes:
        raise CatalogV2Error(
            "device layout minimum media bytes must equal the vault end"
        )
    if layout.minimum_advertised_media_bytes < layout.minimum_media_bytes:
        raise CatalogV2Error(
            "device layout advertised capacity is below the layout minimum"
        )
    profile_digest = load_vault_profile(path.with_name(VAULT_PROFILE_FILENAME))
    if (
        layout.vault_profile_version != VAULT_PROFILE_VERSION
        or layout.vault_profile_sha256 != profile_digest
    ):
        raise CatalogV2Error("device layout does not bind the canonical vault profile")
    return layout


def _catalog_layout(document: object) -> DeviceLayout:
    location = "catalog image.deviceLayout"
    value = _exact_object(
        document,
        {
            "schema",
            "manifestSha256",
            "partitionTable",
            "logicalSectorBytes",
            "minimumMediaBytes",
            "minimumAdvertisedMediaBytes",
            "minimumAdvertisedMediaLabel",
            "vaultProfileVersion",
            "vaultProfileSha256",
            "vaultPartition",
        },
        location,
    )
    layout = DeviceLayout(
        schema=_text(value["schema"], f"{location}.schema"),
        manifest_sha256=_sha256(
            value["manifestSha256"], f"{location}.manifestSha256"
        ),
        partition_table=_text(
            value["partitionTable"], f"{location}.partitionTable"
        ),
        logical_sector_bytes=_integer(
            value["logicalSectorBytes"], f"{location}.logicalSectorBytes", minimum=1
        ),
        minimum_media_bytes=_integer(
            value["minimumMediaBytes"], f"{location}.minimumMediaBytes", minimum=1
        ),
        minimum_advertised_media_bytes=_integer(
            value["minimumAdvertisedMediaBytes"],
            f"{location}.minimumAdvertisedMediaBytes",
            minimum=1,
        ),
        minimum_advertised_media_label=_text(
            value["minimumAdvertisedMediaLabel"],
            f"{location}.minimumAdvertisedMediaLabel",
        ),
        vault_profile_version=_integer(
            value["vaultProfileVersion"],
            f"{location}.vaultProfileVersion",
            minimum=1,
        ),
        vault_profile_sha256=_sha256(
            value["vaultProfileSha256"],
            f"{location}.vaultProfileSha256",
        ),
        vault_partition=_vault_partition(
            value["vaultPartition"], f"{location}.vaultPartition"
        ),
    )
    expected = (
        (layout.schema, LAYOUT_SCHEMA),
        (layout.partition_table, PARTITION_TABLE),
        (layout.logical_sector_bytes, LOGICAL_SECTOR_BYTES),
        (layout.minimum_media_bytes, MINIMUM_MEDIA_BYTES),
        (
            layout.minimum_advertised_media_bytes,
            MINIMUM_ADVERTISED_MEDIA_BYTES,
        ),
        (
            layout.minimum_advertised_media_label,
            MINIMUM_ADVERTISED_MEDIA_LABEL,
        ),
        (layout.vault_profile_version, VAULT_PROFILE_VERSION),
        (layout.vault_profile_sha256, VAULT_PROFILE_SHA256),
    )
    if any(actual != immutable for actual, immutable in expected):
        raise CatalogV2Error(
            "catalog image.deviceLayout changes immutable layout-v1"
        )
    return layout


def _workflow_identity(
    value: dict[str, object], location: str
) -> tuple[int, str, str]:
    run_id = _integer(
        value["workflowRunId"], f"{location}.workflowRunId", minimum=1
    )
    run_url = _text(value["workflowRunUrl"], f"{location}.workflowRunUrl")
    suffix = run_url.removeprefix(TRUSTED_RUN_URL_PREFIX)
    run_component = suffix.split("/", 1)[0]
    if (
        not run_url.startswith(TRUSTED_RUN_URL_PREFIX)
        or not run_component.isdigit()
        or int(run_component) != run_id
    ):
        raise CatalogV2Error(f"{location} URL is not its KernAid Actions run")
    return (
        run_id,
        run_url,
        _sha256(value["logSha256"], f"{location}.logSha256"),
    )


def _usb_boot_attestation(
    document: object, firmware: str
) -> QemuUsbBootAttestation:
    location = f"catalog image.qemuUsbBootAttestations.{firmware}"
    value = _exact_object(
        document,
        {
            "passed",
            "bootTransport",
            "bootCount",
            "targetZeroWritesVerified",
            "workflowRunId",
            "workflowRunUrl",
            "logSha256",
        },
        location,
    )
    if value["passed"] is not True:
        raise CatalogV2Error(f"{location}.passed must be true")
    if value["bootTransport"] != BOOT_TRANSPORT:
        raise CatalogV2Error(f"{location} is not a USB mass-storage boot")
    if _integer(value["bootCount"], f"{location}.bootCount", minimum=1) != 2:
        raise CatalogV2Error(f"{location} must attest exactly two boots")
    if value["targetZeroWritesVerified"] is not True:
        raise CatalogV2Error(f"{location} did not verify zero target writes")
    run_id, run_url, log_sha256 = _workflow_identity(value, location)
    return QemuUsbBootAttestation(
        firmware=firmware,
        workflow_run_id=run_id,
        workflow_run_url=run_url,
        log_sha256=log_sha256,
    )


def _vault_attestation(
    document: object, firmware: str
) -> QemuVaultAttestation:
    location = f"catalog image.qemuVaultAttestations.{firmware}"
    value = _exact_object(
        document,
        {
            "passed",
            "bootCount",
            "luksVersion",
            "luksLabel",
            "filesystem",
            "filesystemLabel",
            "vaultProfileVersion",
            "vaultProfileSha256",
            "stableUuidsVerified",
            "journalIdentityBindingVerified",
            "identityVerified",
            "wrongKeyRejected",
            "workflowRunId",
            "workflowRunUrl",
            "logSha256",
        },
        location,
    )
    if value["passed"] is not True:
        raise CatalogV2Error(f"{location}.passed must be true")
    if _integer(value["bootCount"], f"{location}.bootCount", minimum=1) != 2:
        raise CatalogV2Error(f"{location} must attest exactly two boots")
    if _integer(value["luksVersion"], f"{location}.luksVersion", minimum=1) != 2:
        raise CatalogV2Error(f"{location} did not verify LUKS2")
    if value["luksLabel"] != VAULT_PARTITION_NAME:
        raise CatalogV2Error(f"{location} has the wrong LUKS label")
    if value["filesystem"] != "ext4":
        raise CatalogV2Error(f"{location} did not verify ext4")
    if value["filesystemLabel"] != VAULT_PARTITION_NAME:
        raise CatalogV2Error(f"{location} has the wrong filesystem label")
    if (
        _integer(
            value["vaultProfileVersion"],
            f"{location}.vaultProfileVersion",
            minimum=1,
        )
        != VAULT_PROFILE_VERSION
        or _sha256(
            value["vaultProfileSha256"],
            f"{location}.vaultProfileSha256",
        )
        != VAULT_PROFILE_SHA256
    ):
        raise CatalogV2Error(f"{location} did not verify the immutable vault profile")
    for field, description in (
        ("stableUuidsVerified", "stable LUKS and filesystem UUIDs"),
        ("journalIdentityBindingVerified", "the authenticated journal identity binding"),
        ("identityVerified", "the persistent device identity"),
        ("wrongKeyRejected", "wrong-key rejection"),
    ):
        if value[field] is not True:
            raise CatalogV2Error(f"{location} did not verify {description}")
    run_id, run_url, log_sha256 = _workflow_identity(value, location)
    return QemuVaultAttestation(
        firmware=firmware,
        workflow_run_id=run_id,
        workflow_run_url=run_url,
        log_sha256=log_sha256,
    )


def parse_trust_catalog_v2(raw: str) -> TrustCatalogV2:
    try:
        encoded = raw.encode("utf-8", "strict")
    except UnicodeEncodeError as error:
        raise CatalogV2Error("catalog is not strict UTF-8") from error
    document = _parse_json_bytes(
        encoded, maximum=MAX_CATALOG_BYTES, location="Rescue trust catalog v2"
    )
    value = _exact_object(
        document,
        {"schema", "catalogRevision", "images"},
        "Rescue trust catalog v2",
    )
    if value["schema"] != CATALOG_SCHEMA:
        raise CatalogV2Error("Rescue trust catalog v2 schema is unsupported")
    revision = _integer(
        value["catalogRevision"], "catalogRevision", minimum=0
    )
    image_values = value["images"]
    if not isinstance(image_values, list):
        raise CatalogV2Error("catalog images must be an array")

    images: list[TrustedImageV2] = []
    identities: set[tuple[str, str]] = set()
    digests: set[str] = set()
    for index, image_value in enumerate(image_values):
        location = f"catalog image {index}"
        image_document = _exact_object(
            image_value,
            {
                "artifactName",
                "artifactVersion",
                "sha256",
                "bytes",
                "deviceLayout",
                "qemuUsbBootAttestations",
                "qemuVaultAttestations",
            },
            location,
        )
        artifact_name = _text(
            image_document["artifactName"], f"{location}.artifactName"
        )
        artifact_version = _text(
            image_document["artifactVersion"], f"{location}.artifactVersion"
        )
        if not ARTIFACT_NAME_RE.fullmatch(artifact_name):
            raise CatalogV2Error(f"{location}.artifactName is invalid")
        if not ARTIFACT_VERSION_RE.fullmatch(artifact_version):
            raise CatalogV2Error(f"{location}.artifactVersion is invalid")
        digest = _sha256(image_document["sha256"], f"{location}.sha256")
        size = _integer(image_document["bytes"], f"{location}.bytes", minimum=1)
        layout = _catalog_layout(image_document["deviceLayout"])
        usb_attestations = _exact_object(
            image_document["qemuUsbBootAttestations"],
            {"bios", "uefi"},
            f"{location}.qemuUsbBootAttestations",
        )
        vault_attestations = _exact_object(
            image_document["qemuVaultAttestations"],
            {"bios", "uefi"},
            f"{location}.qemuVaultAttestations",
        )
        bios_usb = _usb_boot_attestation(usb_attestations["bios"], "bios")
        uefi_usb = _usb_boot_attestation(usb_attestations["uefi"], "uefi")
        bios_vault = _vault_attestation(vault_attestations["bios"], "bios")
        uefi_vault = _vault_attestation(vault_attestations["uefi"], "uefi")
        for firmware, usb, vault in (
            ("bios", bios_usb, bios_vault),
            ("uefi", uefi_usb, uefi_vault),
        ):
            if (
                usb.workflow_run_id,
                usb.workflow_run_url,
                usb.log_sha256,
            ) != (
                vault.workflow_run_id,
                vault.workflow_run_url,
                vault.log_sha256,
            ):
                raise CatalogV2Error(
                    f"{firmware} USB and vault claims must bind the same workflow log"
                )
        if hmac.compare_digest(bios_usb.log_sha256, uefi_usb.log_sha256):
            raise CatalogV2Error("BIOS and UEFI attestations cannot reuse one log")
        identity = (artifact_name, artifact_version)
        if identity in identities or digest in digests:
            raise CatalogV2Error("catalog contains a duplicate image identity")
        identities.add(identity)
        digests.add(digest)
        images.append(
            TrustedImageV2(
                artifact_name,
                artifact_version,
                digest,
                size,
                layout,
                bios_usb,
                uefi_usb,
                bios_vault,
                uefi_vault,
            )
        )
    return TrustCatalogV2(revision, tuple(images))


__all__ = [
    "ARTIFACT_NAME_RE",
    "ARTIFACT_VERSION_RE",
    "BOOT_TRANSPORT",
    "CATALOG_SCHEMA",
    "CatalogV2Error",
    "DeviceLayout",
    "MINIMUM_ADVERTISED_MEDIA_BYTES",
    "QemuUsbBootAttestation",
    "QemuVaultAttestation",
    "REQUIRED_BOOT_COUNT",
    "SHA256_RE",
    "TRUSTED_RUN_URL_PREFIX",
    "TrustCatalogV2",
    "TrustedImageV2",
    "VAULT_SECTOR_COUNT",
    "VAULT_START_LBA",
    "load_device_layout",
    "parse_trust_catalog_v2",
    "read_regular_file",
    "sha256_regular_file",
]
