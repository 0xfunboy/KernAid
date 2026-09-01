#!/usr/bin/python3 -I
"""Create or verify the fail-closed Rescue Repair qualification bundle.

This contract deliberately describes an engineering Repair candidate.  It is
separate from the diagnosis-only Rescue qualification and does not claim
physical-machine qualification.  Every published byte and every accepted QEMU
attestation is bound to one first-party workflow run.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any, Final, Mapping, Sequence


SCHEMA: Final = "dev.kernaid.rescue-repair-qualified-release.v1"
CATALOG_SCHEMA: Final = "dev.kernaid.rescue-repair-catalog-entry.v1"
RETAIL_SCHEMA: Final = "dev.kernaid.rescue-repair-retail-image.v1"
REPOSITORY: Final = "0xfunboy/KernAid"
WORKFLOW: Final = ".github/workflows/rescue-repair-candidate.yml"
ISO_NAME: Final = "KernAid-Rescue-Repair-amd64.iso"
CHECKSUM_NAME: Final = f"{ISO_NAME}.sha256"
RETAIL_NAME: Final = "KernAid-Rescue-Repair-amd64-retail.img.xz"
RETAIL_CHECKSUM_NAME: Final = f"{RETAIL_NAME}.sha256"
RETAIL_METADATA_NAME: Final = "KernAid-Rescue-Repair-amd64-retail.json"
CATALOG_NAME: Final = "KernAid-Rescue-Repair-amd64.catalog-entry.json"
MANIFEST_NAME: Final = "KernAid-Rescue-Repair-amd64.qualified.json"
EVIDENCE_NAMES: Final = {
    "bios": "kernaid-rescue-repair-bios.sanitized.log",
    "uefi": "kernaid-rescue-repair-uefi.sanitized.log",
    "batch": "kernaid-rescue-repair-qualification-batch.sanitized.log",
}
COMPILED_ACTIONS: Final = (
    "linux.crypttab.disable-missing-uuid.v1",
    "linux.ext4.fsck-preen-with-undo.v1",
    "linux.fstab.disable-missing-uuid.v1",
    "linux.network.restore-resolver-link.v1",
)
QUALIFIED_ACTIONS: Final = COMPILED_ACTIONS
ATTESTED_ACTIONS: Final = (
    "linux.fstab.disable-missing-uuid.v1",
    "linux.crypttab.disable-missing-uuid.v1",
    "linux.ext4.fsck-preen-with-undo.v1",
    "linux.network.restore-resolver-link.v1",
)
SCENARIOS: Final = (
    "bios-apply",
    "uefi-apply",
    "uefi-rollback",
    "uefi-interrupt-reconcile",
    "uefi-stale-target",
    "uefi-cancel",
    "uefi-backup-tamper",
    "uefi-repaird-termination",
    "uefi-auto-restore",
    "uefi-crypttab-lifecycle",
    "uefi-ext4-apply",
    "uefi-resolver-link-apply",
)
P3_ZERO_SHA256: Final = "ebfb4ef19ae410f190327b5ebd312711263bc7579970e87d9c1e2d84e06b3c25"
COMMIT_RE: Final = re.compile(r"[0-9a-f]{40}\Z")
SHA256_RE: Final = re.compile(r"[0-9a-f]{64}\Z")
MAX_JSON_BYTES: Final = 2 * 1024 * 1024
MAX_ISO_BYTES: Final = 16 * 1024 * 1024 * 1024
MAX_RETAIL_BYTES: Final = 1_999_999_998
MAX_EVIDENCE_BYTES: Final = 64 * 1024
CHUNK_BYTES: Final = 4 * 1024 * 1024


class RepairQualificationError(RuntimeError):
    """A candidate input does not prove the exact Repair qualification."""


def _regular_file(
    path: Path, expected_name: str, label: str, maximum: int, *, capture: bool
) -> tuple[int, str, bytes | None]:
    if not path.is_absolute() or path.name != expected_name:
        raise RepairQualificationError(f"{label} path or filename is not exact")
    try:
        entry = path.lstat()
    except OSError as error:
        raise RepairQualificationError(f"{label} is unavailable") from error
    if (
        not stat.S_ISREG(entry.st_mode)
        or entry.st_nlink != 1
        or entry.st_size <= 0
        or entry.st_size > maximum
    ):
        raise RepairQualificationError(
            f"{label} is not a bounded single-link regular file"
        )
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise RepairQualificationError(f"{label} cannot be opened safely") from error
    digest = hashlib.sha256()
    content = bytearray() if capture else None
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or (entry.st_dev, entry.st_ino, entry.st_size)
            != (before.st_dev, before.st_ino, before.st_size)
        ):
            raise RepairQualificationError(f"{label} identity changed before hashing")
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(CHUNK_BYTES, remaining))
            if not chunk:
                raise RepairQualificationError(f"{label} ended while hashing")
            digest.update(chunk)
            if content is not None:
                content.extend(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise RepairQualificationError(f"{label} grew while hashing")
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
            raise RepairQualificationError(f"{label} changed while hashing")
    finally:
        os.close(descriptor)
    return before.st_size, digest.hexdigest(), bytes(content) if content is not None else None


def _metadata(path: Path, name: str, label: str, maximum: int) -> dict[str, Any]:
    size, digest, _content = _regular_file(path, name, label, maximum, capture=False)
    return {"bytes": size, "name": name, "sha256": digest}


def _duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RepairQualificationError(f"JSON contains duplicate key: {key}")
        result[key] = value
    return result


def _json_file(
    path: Path, name: str, label: str
) -> tuple[dict[str, Any], dict[str, Any], bytes]:
    size, digest, content = _regular_file(
        path, name, label, MAX_JSON_BYTES, capture=True
    )
    assert content is not None
    try:
        document = json.loads(
            content.decode("utf-8", "strict"),
            object_pairs_hook=_duplicate_keys,
            parse_constant=lambda value: (_ for _ in ()).throw(
                RepairQualificationError(f"{label} contains non-finite JSON: {value}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RepairQualificationError(f"{label} is not strict UTF-8 JSON") from error
    if not isinstance(document, dict):
        raise RepairQualificationError(f"{label} root must be an object")
    return document, {"bytes": size, "name": name, "sha256": digest}, content


def _exact(value: object, fields: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise RepairQualificationError(f"{label} fields are not exact")
    return value


def _source(arguments: argparse.Namespace) -> dict[str, Any]:
    if arguments.repository != REPOSITORY:
        raise RepairQualificationError("qualification is restricted to the official repository")
    if COMMIT_RE.fullmatch(arguments.commit) is None:
        raise RepairQualificationError("source commit must be a lowercase full Git commit")
    if arguments.run_id <= 0 or arguments.run_attempt <= 0:
        raise RepairQualificationError("workflow run identity must be positive")
    expected_url = f"https://github.com/{REPOSITORY}/actions/runs/{arguments.run_id}"
    if arguments.run_url != expected_url:
        raise RepairQualificationError("workflow run URL is not the exact official run")
    if arguments.artifact_version != (
        f"repair-ci-{arguments.run_id}-{arguments.run_attempt}"
    ):
        raise RepairQualificationError("artifact version is not bound to this run attempt")
    return {
        "commit": arguments.commit,
        "repository": arguments.repository,
        "workflow": WORKFLOW,
        "workflowRunAttempt": arguments.run_attempt,
        "workflowRunId": arguments.run_id,
        "workflowRunUrl": arguments.run_url,
    }


def _checksum(
    path: Path, name: str, label: str, subject: Mapping[str, Any], subject_name: str
) -> dict[str, Any]:
    size, digest, content = _regular_file(path, name, label, 1024, capture=True)
    assert content is not None
    expected = f"{subject['sha256']}  {subject_name}\n".encode("ascii")
    if not hmac.compare_digest(content, expected):
        raise RepairQualificationError(f"{label} does not bind the exact subject")
    return {"bytes": size, "name": name, "sha256": digest}


def _retail_metadata(
    path: Path, iso: Mapping[str, Any], retail: Mapping[str, Any]
) -> tuple[dict[str, Any], dict[str, Any]]:
    document, metadata, raw = _json_file(
        path, RETAIL_METADATA_NAME, "Repair retail metadata"
    )
    if not hmac.compare_digest(raw, canonical_bytes(document)):
        raise RepairQualificationError("Repair retail metadata is not canonical")
    root = _exact(
        document,
        {"compressed", "isoPrefix", "p3", "raw", "schema", "tailZero"},
        "Repair retail metadata",
    )
    raw_image = _exact(root["raw"], {"bytes", "name", "sha256"}, "retail raw")
    p3 = _exact(root["p3"], {"bytes", "sha256", "startBytes", "zero"}, "retail p3")
    if (
        root["schema"] != RETAIL_SCHEMA
        or root["compressed"] != retail
        or root["isoPrefix"] != {"bytes": iso["bytes"], "sha256": iso["sha256"]}
        or raw_image["bytes"] != 32_000_000_000
        or raw_image["name"] != "KernAid-Rescue-Repair-amd64-retail.img"
        or not isinstance(raw_image["sha256"], str)
        or SHA256_RE.fullmatch(raw_image["sha256"]) is None
        or p3
        != {
            "bytes": 8_589_934_592,
            "sha256": P3_ZERO_SHA256,
            "startBytes": 17_179_869_184,
            "zero": True,
        }
        or root["tailZero"] is not True
    ):
        raise RepairQualificationError(
            "Repair retail metadata does not bind the fixed image layout"
        )
    return document, metadata


def _evidence(path: Path, kind: str, iso_sha256: str) -> dict[str, Any]:
    name = EVIDENCE_NAMES[kind]
    size, digest, content = _regular_file(
        path, name, f"{kind} Repair evidence", MAX_EVIDENCE_BYTES, capture=True
    )
    assert content is not None
    sha = iso_sha256.encode("ascii")
    digest_pattern = rb"[0-9a-f]{64}"
    if kind in ("bios", "uefi"):
        firmware = kind.encode("ascii")
        boot = re.fullmatch(
            rb"KERNAID_QEMU_ATTESTATION_V1 firmware="
            + firmware
            + rb" iso_sha256=("
            + digest_pattern
            + rb") target_before_sha256=("
            + digest_pattern
            + rb") target_after_sha256=("
            + digest_pattern
            + rb") ready=true\n",
            content.split(b"KERNAID_QEMU_SECURE_BOOT_ATTESTATION_V1", 1)[0],
        )
        if boot is None or boot.group(1) != sha or boot.group(2) != boot.group(3):
            raise RepairQualificationError(
                f"{kind} boot evidence is not immutable or ISO-bound"
            )
        if kind == "bios":
            if content != boot.group(0):
                raise RepairQualificationError("BIOS evidence contains extra lines")
        else:
            secure = (
                b"KERNAID_QEMU_SECURE_BOOT_ATTESTATION_V1 firmware=uefi machine=q35 "
                b"ovmf_profile=ms-enrolled secure_boot=enabled setup_mode=disabled "
                b"shim_validation=enabled iso_sha256="
                + sha
                + b" ready=true\n"
            )
            if content != boot.group(0) + secure:
                raise RepairQualificationError(
                    "UEFI evidence does not prove the exact Secure Boot profile"
                )
    else:
        expected = (
            "KERNAID_QEMU_REPAIR_QUALIFICATION_BATCH_ATTESTATION_V1 "
            "provisioning=host-probe-canonical-v1 "
            "guest_firstboot=not-claimed "
            "standard_firstboot_gate=unchanged-separate "
            "guest_readiness=repair-service-v1 "
            "guest_readiness_marker="
            "KERNAID_RESCUE_REPAIR_QUALIFICATION_READY_V1 "
            "standard_full_readiness_gate=unchanged-separate "
            f"scenarios={','.join(SCENARIOS)} "
            f"actions={','.join(ATTESTED_ACTIONS)} "
            "vault_profile=canonical-v1 "
            "vault_identity=initialize-verify-stable p3=exact "
            "key=private-mode-0600 target=separate base_immutable=true "
            "isolated_sparse_copies=true "
            f"iso_sha256={iso_sha256} iso_prefix_immutable=true "
            "host_physical_devices=false ready=true\n"
        ).encode("ascii")
        if not hmac.compare_digest(content, expected):
            raise RepairQualificationError(
                "Repair batch evidence does not prove the exact scenario set"
            )
    return {"bytes": size, "name": name, "sha256": digest}


def _build(arguments: argparse.Namespace) -> tuple[dict[str, Any], dict[str, Any]]:
    source = _source(arguments)
    iso = _metadata(arguments.iso, ISO_NAME, "Repair ISO", MAX_ISO_BYTES)
    checksum = _checksum(
        arguments.checksum, CHECKSUM_NAME, "Repair ISO checksum", iso, ISO_NAME
    )
    retail = _metadata(
        arguments.retail_image, RETAIL_NAME, "Repair retail image", MAX_RETAIL_BYTES
    )
    retail_checksum = _checksum(
        arguments.retail_checksum,
        RETAIL_CHECKSUM_NAME,
        "Repair retail checksum",
        retail,
        RETAIL_NAME,
    )
    retail_layout, retail_metadata = _retail_metadata(
        arguments.retail_metadata, iso, retail
    )
    evidence = {
        "biosBoot": _evidence(arguments.bios_evidence, "bios", iso["sha256"]),
        "repairBatch": _evidence(arguments.batch_evidence, "batch", iso["sha256"]),
        "uefiSecureBoot": _evidence(arguments.uefi_evidence, "uefi", iso["sha256"]),
    }
    vault_base = {
        "guestFirstbootClaimed": False,
        "profile": "canonical-v1",
        "projectProbe": "initialize-verify",
        "provisioning": "host-probe-canonical-v1",
        "standardFirstbootGate": "unchanged-separate",
    }
    readiness = {
        "guestGate": "repair-service-v1",
        "guestMarker": "KERNAID_RESCUE_REPAIR_QUALIFICATION_READY_V1",
        "standardFullGate": "unchanged-separate",
    }
    qualification = {
        "environment": "qemu",
        "evidence": evidence,
        "readiness": readiness,
        "scenarios": list(SCENARIOS),
        "secureBoot": True,
        "vaultBase": vault_base,
    }
    catalog = {
        "artifactName": ISO_NAME,
        "artifactVersion": arguments.artifact_version,
        "bytes": iso["bytes"],
        "channel": "repair",
        "compiledRepairActions": list(COMPILED_ACTIONS),
        "diagnosisOnly": False,
        "physicalQualification": False,
        "qualification": qualification,
        "qualifiedRepairActions": list(QUALIFIED_ACTIONS),
        "readiness": readiness,
        "releaseClass": "engineering-candidate",
        "repairEnabled": True,
        "schema": CATALOG_SCHEMA,
        "sha256": iso["sha256"],
        "source": source,
        "vaultBase": vault_base,
    }
    catalog_payload = canonical_bytes(catalog)
    catalog_metadata = {
        "bytes": len(catalog_payload),
        "name": CATALOG_NAME,
        "sha256": hashlib.sha256(catalog_payload).hexdigest(),
    }
    manifest = {
        "artifactVersion": arguments.artifact_version,
        "artifacts": {
            "catalogEntry": catalog_metadata,
            "iso": {**iso, "checksum": checksum},
            "retailImage": {
                **retail,
                "checksum": retail_checksum,
                "layout": retail_layout,
                "metadata": retail_metadata,
            },
        },
        "capabilities": {
            "compiledRepairActions": list(COMPILED_ACTIONS),
            "qualifiedRepairActions": list(QUALIFIED_ACTIONS),
        },
        "channel": "repair",
        "diagnosisOnly": False,
        "evidence": evidence,
        "physicalQualification": False,
        "qualificationEnvironment": "qemu",
        "readiness": readiness,
        "releaseClass": "engineering-candidate",
        "repairEnabled": True,
        "requiredJobs": ["build-and-smoke-test"],
        "schema": SCHEMA,
        "source": source,
        "vaultBase": vault_base,
    }
    return catalog, manifest


def canonical_bytes(document: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(
            document,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("ascii")


def _write_new(path: Path, name: str, label: str, payload: bytes) -> None:
    if not path.is_absolute() or path.name != name:
        raise RepairQualificationError(f"{label} output path or filename is not exact")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o644)
    except OSError as error:
        raise RepairQualificationError(f"{label} could not be created exclusively") from error
    published = False
    try:
        os.fchmod(descriptor, 0o644)
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise RepairQualificationError(f"{label} could not be written")
            view = view[written:]
        os.fsync(descriptor)
        details = os.fstat(descriptor)
        if (
            not stat.S_ISREG(details.st_mode)
            or details.st_nlink != 1
            or details.st_size != len(payload)
            or stat.S_IMODE(details.st_mode) != 0o644
        ):
            raise RepairQualificationError(f"{label} output identity is unsafe")
        published = True
    finally:
        os.close(descriptor)
        if not published:
            try:
                path.unlink()
            except FileNotFoundError:
                pass


def _common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--repository", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--run-id", required=True, type=int)
    parser.add_argument("--run-attempt", required=True, type=int)
    parser.add_argument("--run-url", required=True)
    parser.add_argument("--artifact-version", required=True)
    parser.add_argument("--iso", required=True, type=Path)
    parser.add_argument("--checksum", required=True, type=Path)
    parser.add_argument("--retail-image", required=True, type=Path)
    parser.add_argument("--retail-checksum", required=True, type=Path)
    parser.add_argument("--retail-metadata", required=True, type=Path)
    parser.add_argument("--bios-evidence", required=True, type=Path)
    parser.add_argument("--uefi-evidence", required=True, type=Path)
    parser.add_argument("--batch-evidence", required=True, type=Path)
    parser.add_argument("--catalog", required=True, type=Path)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create", help="create a new Repair bundle contract")
    _common(create)
    create.add_argument("--output", required=True, type=Path)
    verify = commands.add_parser("verify", help="recompute and verify a Repair bundle")
    _common(verify)
    verify.add_argument("--manifest", required=True, type=Path)
    return result


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    try:
        catalog, manifest = _build(arguments)
        catalog_payload = canonical_bytes(catalog)
        manifest_payload = canonical_bytes(manifest)
        if arguments.command == "create":
            _write_new(arguments.catalog, CATALOG_NAME, "Repair catalog", catalog_payload)
            try:
                _write_new(arguments.output, MANIFEST_NAME, "Repair manifest", manifest_payload)
            except Exception:
                arguments.catalog.unlink(missing_ok=True)
                raise
        else:
            _catalog, _catalog_metadata, catalog_raw = _json_file(
                arguments.catalog, CATALOG_NAME, "Repair catalog"
            )
            _manifest, _manifest_metadata, manifest_raw = _json_file(
                arguments.manifest, MANIFEST_NAME, "Repair manifest"
            )
            if not hmac.compare_digest(catalog_raw, catalog_payload):
                raise RepairQualificationError("Repair catalog is not exact and canonical")
            if not hmac.compare_digest(manifest_raw, manifest_payload):
                raise RepairQualificationError("Repair manifest is not exact and canonical")
        print(
            "KERNAID_RESCUE_REPAIR_QUALIFIED_V1 "
            f"manifest_sha256={hashlib.sha256(manifest_payload).hexdigest()}"
        )
    except (OSError, RepairQualificationError, ValueError) as error:
        print(f"REFUSED: {error}", file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
