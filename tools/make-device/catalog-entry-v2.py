#!/usr/bin/python3 -I
"""Emit one catalog-v2 entry from USB boot and vault-persistence evidence.

The layout-only `KERNAID_QEMU_USB_ATTESTATION_V1` line is necessary but not
sufficient.  Each firmware log must also contain the independent vault line
defined below, proving that a provisioned LUKS2/ext4 vault, its sentinel and
its device identity survived two boots.  Legacy CD-ROM attestations and a USB
log without vault evidence fail closed.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import importlib.util
import json
import os
import re
import sys
from pathlib import Path
from typing import Final, Sequence


MODULE_PATH: Final = Path(__file__).resolve().with_name("catalog_v2.py")
SPEC = importlib.util.spec_from_file_location("kernaid_catalog_v2", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load the catalog-v2 parser")
catalog_v2 = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = catalog_v2
SPEC.loader.exec_module(catalog_v2)

FINALIZER_PATH: Final = (
    Path(__file__).resolve().parents[1]
    / "build-rescue"
    / "finalize-device-layout.py"
)
FINALIZER_SPEC = importlib.util.spec_from_file_location(
    "kernaid_finalize_device_layout", FINALIZER_PATH
)
if FINALIZER_SPEC is None or FINALIZER_SPEC.loader is None:
    raise RuntimeError("cannot load the canonical layout-v1 verifier")
finalize_device_layout = importlib.util.module_from_spec(FINALIZER_SPEC)
sys.modules[FINALIZER_SPEC.name] = finalize_device_layout
FINALIZER_SPEC.loader.exec_module(finalize_device_layout)

MAX_LOG_BYTES: Final = 16 * 1024 * 1024
USB_ATTESTATION_PREFIX: Final = "KERNAID_QEMU_USB_ATTESTATION_V1 "
VAULT_ATTESTATION_PREFIX: Final = "KERNAID_QEMU_USB_VAULT_ATTESTATION_V1 "
BOOT_READY_PREFIX: Final = "KERNAID_QEMU_USB_BOOT_READY_V1 "
LEGACY_CDROM_ATTESTATION: Final = "KERNAID_QEMU_ATTESTATION_V1"
UUID_RE: Final = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z"
)
DECIMAL_RE: Final = re.compile(r"(?:0|[1-9][0-9]*)\Z")

USB_ATTESTATION_FIELDS: Final = frozenset(
    (
        "firmware",
        "boot_count",
        "transport",
        "media_bytes",
        "iso_bytes",
        "iso_sha256",
        "layout_manifest_sha256",
        "prefix_before_sha256",
        "prefix_after_sha256",
        "p3_start_bytes",
        "p3_bytes",
        "p3_before_sha256",
        "p3_after_sha256",
        "target_before_sha256",
        "target_after_sha256",
        "ready_boots",
        "ready",
        "uefi_vars",
    )
)
VAULT_ATTESTATION_FIELDS: Final = frozenset(
    (
        "firmware",
        "boot_count",
        "luks_version",
        "luks_label",
        "luks_uuid_before",
        "luks_uuid_after",
        "filesystem",
        "filesystem_label",
        "filesystem_uuid_before",
        "filesystem_uuid_after",
        "sentinel_before_sha256",
        "sentinel_after_sha256",
        "identity_before_sha256",
        "identity_after_sha256",
        "vault_layout_verified",
        "wrong_key_rejected",
        "clean_shutdowns",
    )
)
BOOT_READY_FIELDS: Final = frozenset(("firmware", "boot", "ready"))


def _tokens(line: str, prefix: str, expected: frozenset[str], label: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for token in line.removeprefix(prefix).split():
        key, separator, value = token.partition("=")
        if (
            not separator
            or not key
            or not value
            or key in fields
            or len(key) > 128
            or len(value) > 4096
        ):
            raise ValueError(f"{label} contains malformed or duplicate fields")
        fields[key] = value
    if set(fields) != expected:
        raise ValueError(f"{label} fields are not exact")
    return fields


def _decimal(value: str, label: str) -> int:
    if not DECIMAL_RE.fullmatch(value):
        raise ValueError(f"{label} is not an unsigned decimal integer")
    return int(value)


def _sha256(value: str, label: str) -> str:
    if not catalog_v2.SHA256_RE.fullmatch(value):
        raise ValueError(f"{label} is not lowercase SHA-256")
    return value


def _stable_sha256(fields: dict[str, str], before: str, after: str, label: str) -> str:
    before_digest = _sha256(fields[before], f"{label} before")
    after_digest = _sha256(fields[after], f"{label} after")
    if not hmac.compare_digest(before_digest, after_digest):
        raise ValueError(f"{label} changed across the two USB boots")
    return before_digest


def _stable_uuid(fields: dict[str, str], before: str, after: str, label: str) -> str:
    before_uuid = fields[before]
    after_uuid = fields[after]
    if (
        not UUID_RE.fullmatch(before_uuid)
        or not UUID_RE.fullmatch(after_uuid)
        or not hmac.compare_digest(before_uuid, after_uuid)
    ):
        raise ValueError(f"{label} UUID is invalid or changed across USB boots")
    return before_uuid


def _validate_boot_markers(lines: list[str], firmware: str) -> None:
    markers = [line for line in lines if line.startswith(BOOT_READY_PREFIX)]
    if len(markers) != 2:
        raise ValueError(
            f"{firmware} log must contain exactly one ready marker for each boot"
        )
    observed: set[int] = set()
    for marker in markers:
        fields = _tokens(
            marker,
            BOOT_READY_PREFIX,
            BOOT_READY_FIELDS,
            f"{firmware} boot-ready marker",
        )
        boot = _decimal(fields["boot"], f"{firmware} ready boot")
        if fields["firmware"] != firmware or fields["ready"] != "true":
            raise ValueError(f"{firmware} boot-ready marker is not passing")
        if boot not in (1, 2) or boot in observed:
            raise ValueError(f"{firmware} boot-ready markers are not boot 1 and boot 2")
        observed.add(boot)
    if observed != {1, 2}:
        raise ValueError(f"{firmware} boot-ready markers are incomplete")


def _validate_usb_line(
    fields: dict[str, str],
    *,
    firmware: str,
    iso_size: int,
    iso_sha256: str,
    layout: object,
) -> None:
    if fields["firmware"] != firmware:
        raise ValueError(f"{firmware} USB attestation names another firmware")
    if fields["transport"] != catalog_v2.BOOT_TRANSPORT:
        raise ValueError(f"{firmware} attestation was not booted as USB storage")
    if _decimal(fields["boot_count"], f"{firmware} boot_count") != 2:
        raise ValueError(f"{firmware} attestation must cover exactly two boots")
    if _decimal(fields["ready_boots"], f"{firmware} ready_boots") != 2:
        raise ValueError(f"{firmware} attestation did not reach readiness twice")
    if fields["ready"] != "true":
        raise ValueError(f"{firmware} USB attestation did not pass readiness")
    media_bytes = _decimal(fields["media_bytes"], f"{firmware} media_bytes")
    if media_bytes < layout.minimum_advertised_media_bytes:
        raise ValueError(f"{firmware} USB image is below the advertised media minimum")
    if _decimal(fields["iso_bytes"], f"{firmware} iso_bytes") != iso_size:
        raise ValueError(f"{firmware} attestation names a different ISO size")
    if not hmac.compare_digest(
        _sha256(fields["iso_sha256"], f"{firmware} iso_sha256"), iso_sha256
    ):
        raise ValueError(f"{firmware} attestation names a different ISO")
    if not hmac.compare_digest(
        _sha256(
            fields["layout_manifest_sha256"],
            f"{firmware} layout_manifest_sha256",
        ),
        layout.manifest_sha256,
    ):
        raise ValueError(f"{firmware} attestation names a different device layout")

    expected_p3_start_bytes = (
        layout.vault_partition.start_lba * layout.logical_sector_bytes
    )
    expected_p3_bytes = (
        layout.vault_partition.sector_count * layout.logical_sector_bytes
    )
    if (
        _decimal(fields["p3_start_bytes"], f"{firmware} p3_start_bytes")
        != expected_p3_start_bytes
    ):
        raise ValueError(f"{firmware} p3 start does not match the device layout")
    if (
        _decimal(fields["p3_bytes"], f"{firmware} p3_bytes")
        != expected_p3_bytes
    ):
        raise ValueError(f"{firmware} p3 size does not match the device layout")

    prefix = _stable_sha256(
        fields,
        "prefix_before_sha256",
        "prefix_after_sha256",
        f"{firmware} ISO prefix",
    )
    if not hmac.compare_digest(prefix, iso_sha256):
        raise ValueError(f"{firmware} written prefix is not the attested ISO")
    _stable_sha256(
        fields,
        "p3_before_sha256",
        "p3_after_sha256",
        f"{firmware} vault partition",
    )
    _stable_sha256(
        fields,
        "target_before_sha256",
        "target_after_sha256",
        f"{firmware} Observe target",
    )
    vault_end = expected_p3_start_bytes + expected_p3_bytes
    if iso_size >= expected_p3_start_bytes:
        raise ValueError("ISO reaches the reserved vault partition")
    if vault_end > media_bytes:
        raise ValueError(f"{firmware} USB media does not contain the complete vault")
    expected_uefi_vars = "fresh-per-boot" if firmware == "uefi" else "not-applicable"
    if fields["uefi_vars"] != expected_uefi_vars:
        raise ValueError(f"{firmware} UEFI variable policy is not isolated per boot")


def _validate_vault_line(fields: dict[str, str], firmware: str) -> None:
    if fields["firmware"] != firmware:
        raise ValueError(f"{firmware} vault attestation names another firmware")
    if _decimal(fields["boot_count"], f"{firmware} vault boot_count") != 2:
        raise ValueError(f"{firmware} vault evidence must cover two boots")
    if _decimal(fields["luks_version"], f"{firmware} luks_version") != 2:
        raise ValueError(f"{firmware} vault is not LUKS2")
    if fields["luks_label"] != "KERNAID_VAULT":
        raise ValueError(f"{firmware} vault has the wrong LUKS label")
    if fields["filesystem"] != "ext4" or fields["filesystem_label"] != "KERNAID_VAULT":
        raise ValueError(f"{firmware} vault has the wrong inner filesystem")
    _stable_uuid(
        fields, "luks_uuid_before", "luks_uuid_after", f"{firmware} LUKS"
    )
    _stable_uuid(
        fields,
        "filesystem_uuid_before",
        "filesystem_uuid_after",
        f"{firmware} filesystem",
    )
    _stable_sha256(
        fields,
        "sentinel_before_sha256",
        "sentinel_after_sha256",
        f"{firmware} vault sentinel",
    )
    _stable_sha256(
        fields,
        "identity_before_sha256",
        "identity_after_sha256",
        f"{firmware} device identity",
    )
    for field in ("vault_layout_verified", "wrong_key_rejected"):
        if fields[field] != "true":
            raise ValueError(f"{firmware} vault attestation did not prove {field}")
    if _decimal(fields["clean_shutdowns"], f"{firmware} clean_shutdowns") != 2:
        raise ValueError(f"{firmware} vault lifecycle did not close cleanly twice")


def attested_log(
    path: Path,
    *,
    firmware: str,
    iso_size: int,
    iso_sha256: str,
    layout: object,
) -> str:
    raw = catalog_v2.read_regular_file(
        path, MAX_LOG_BYTES, f"{firmware} USB QEMU log"
    )
    try:
        lines = raw.decode("utf-8", "strict").splitlines()
    except UnicodeDecodeError as error:
        raise ValueError(f"{firmware} USB QEMU log is not strict UTF-8") from error
    if any(LEGACY_CDROM_ATTESTATION in line for line in lines):
        raise ValueError(f"{firmware} log contains a legacy CD-ROM attestation")
    usb_lines = [line for line in lines if line.startswith(USB_ATTESTATION_PREFIX)]
    if len(usb_lines) != 1:
        raise ValueError(f"{firmware} log must contain exactly one USB attestation")
    vault_lines = [line for line in lines if line.startswith(VAULT_ATTESTATION_PREFIX)]
    if len(vault_lines) != 1:
        raise ValueError(
            f"{firmware} log must contain exactly one independent vault attestation"
        )
    _validate_boot_markers(lines, firmware)
    usb_fields = _tokens(
        usb_lines[0],
        USB_ATTESTATION_PREFIX,
        USB_ATTESTATION_FIELDS,
        f"{firmware} USB attestation",
    )
    vault_fields = _tokens(
        vault_lines[0],
        VAULT_ATTESTATION_PREFIX,
        VAULT_ATTESTATION_FIELDS,
        f"{firmware} vault attestation",
    )
    _validate_usb_line(
        usb_fields,
        firmware=firmware,
        iso_size=iso_size,
        iso_sha256=iso_sha256,
        layout=layout,
    )
    _validate_vault_line(vault_fields, firmware)
    return hashlib.sha256(raw).hexdigest()


def _absolute_path(value: str, label: str) -> Path:
    if not os.path.isabs(value):
        raise ValueError(f"{label} path must be absolute")
    return Path(os.path.normpath(value))


def _workflow_attestations(
    *, firmware: str, run_id: int, run_url: str, log_sha256: str
) -> tuple[object, object]:
    usb = catalog_v2.QemuUsbBootAttestation(
        firmware, run_id, run_url, log_sha256
    )
    vault = catalog_v2.QemuVaultAttestation(
        firmware, run_id, run_url, log_sha256
    )
    return usb, vault


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--iso", required=True)
    result.add_argument("--sha256", required=True)
    result.add_argument("--layout-manifest", required=True)
    result.add_argument("--artifact-version", required=True)
    for firmware in ("bios", "uefi"):
        result.add_argument(f"--{firmware}-run-id", required=True, type=int)
        result.add_argument(f"--{firmware}-run-url", required=True)
        result.add_argument(f"--{firmware}-log", required=True)
    return result


def build_entry(arguments: argparse.Namespace) -> object:
    iso_path = _absolute_path(arguments.iso, "ISO")
    manifest_path = _absolute_path(arguments.layout_manifest, "layout manifest")
    bios_log = _absolute_path(arguments.bios_log, "BIOS log")
    uefi_log = _absolute_path(arguments.uefi_log, "UEFI log")
    layout = catalog_v2.load_device_layout(manifest_path)
    try:
        canonical_layout = finalize_device_layout.parse_layout_manifest(
            manifest_path
        )
        finalize_device_layout.process_image(
            iso_path, canonical_layout, verify_only=True
        )
    except finalize_device_layout.LayoutError as error:
        raise ValueError(
            f"Rescue ISO is not finalized as immutable layout-v1: {error}"
        ) from error

    iso_size, iso_sha256 = catalog_v2.sha256_regular_file(iso_path, "Rescue ISO")
    expected_sha256 = arguments.sha256.lower()
    if (
        not catalog_v2.SHA256_RE.fullmatch(expected_sha256)
        or not hmac.compare_digest(iso_sha256, expected_sha256)
    ):
        raise ValueError("ISO SHA-256 does not match the expected release digest")
    artifact_name = iso_path.name
    if not catalog_v2.ARTIFACT_NAME_RE.fullmatch(artifact_name):
        raise ValueError("ISO filename is not a KernAid Rescue artifact name")
    if not catalog_v2.ARTIFACT_VERSION_RE.fullmatch(arguments.artifact_version):
        raise ValueError("artifact version is invalid")
    bios_log_sha256 = attested_log(
        bios_log,
        firmware="bios",
        iso_size=iso_size,
        iso_sha256=iso_sha256,
        layout=layout,
    )
    uefi_log_sha256 = attested_log(
        uefi_log,
        firmware="uefi",
        iso_size=iso_size,
        iso_sha256=iso_sha256,
        layout=layout,
    )
    bios_usb, bios_vault = _workflow_attestations(
        firmware="bios",
        run_id=arguments.bios_run_id,
        run_url=arguments.bios_run_url,
        log_sha256=bios_log_sha256,
    )
    uefi_usb, uefi_vault = _workflow_attestations(
        firmware="uefi",
        run_id=arguments.uefi_run_id,
        run_url=arguments.uefi_run_url,
        log_sha256=uefi_log_sha256,
    )
    image = catalog_v2.TrustedImageV2(
        artifact_name,
        arguments.artifact_version,
        iso_sha256,
        iso_size,
        layout,
        bios_usb,
        uefi_usb,
        bios_vault,
        uefi_vault,
    )
    entry = image.as_document()
    # The strict catalog parser is the final authority.  Self-validate the
    # emitted shape rather than relying only on construction helpers.
    catalog_v2.parse_trust_catalog_v2(
        json.dumps(
            {
                "schema": catalog_v2.CATALOG_SCHEMA,
                "catalogRevision": 1,
                "images": [entry],
            }
        )
    )
    return entry


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    try:
        entry = build_entry(arguments)
    except (OSError, ValueError, catalog_v2.CatalogV2Error) as error:
        print(f"REFUSED: {error}", file=sys.stderr)
        return 3
    print(json.dumps(entry, indent=2, sort_keys=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
