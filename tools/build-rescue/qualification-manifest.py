#!/usr/bin/python3 -I
"""Create or verify the canonical Rescue qualification manifest.

The manifest is deliberately assembled only from immutable artifacts downloaded
by the final same-run GitHub Actions job.  It contains no timestamp, runner path
or other non-reproducible field.
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


SCHEMA: Final = "dev.kernaid.rescue-qualified-release.v1"
REPOSITORY: Final = "0xfunboy/KernAid"
WORKFLOW: Final = ".github/workflows/rescue.yml"
ISO_NAME: Final = "KernAid-Rescue-amd64.iso"
CHECKSUM_NAME: Final = f"{ISO_NAME}.sha256"
CATALOG_NAME: Final = "KernAid-Rescue-amd64.catalog-entry-v2.json"
SBOM_NAME: Final = "KernAid-Rescue-amd64.codex.cdx.json"
SNAPSHOT_EVIDENCE_NAME: Final = "kernaid-linux-snapshot-e2e.sanitized.log"
USB_EVIDENCE_NAMES: Final = {
    "bios": "rescue-usb-smoke-bios.log",
    "uefi": "rescue-usb-smoke-uefi.log",
}
LIFECYCLE_EVIDENCE_NAMES: Final = {
    "bios": "kernaid-vault-lifecycle-bios.sanitized.log",
    "uefi": "kernaid-vault-lifecycle-uefi.sanitized.log",
}
REQUIRED_JOBS: Final = (
    "build-and-smoke-test",
    "vault-lifecycle-bios",
    "vault-lifecycle-uefi",
)
COMMIT_RE: Final = re.compile(r"[0-9a-f]{40}\Z")
CHUNK_BYTES: Final = 4 * 1024 * 1024
MAX_ISO_BYTES: Final = 16 * 1024 * 1024 * 1024
MAX_JSON_BYTES: Final = 16 * 1024 * 1024
MAX_USB_EVIDENCE_BYTES: Final = 16 * 1024 * 1024
MAX_SMALL_EVIDENCE_BYTES: Final = 64 * 1024


class QualificationError(RuntimeError):
    """An input did not prove the exact qualified Rescue release."""


def _regular_file(
    path: Path, label: str, maximum: int, *, capture: bool
) -> tuple[int, str, bytes | None]:
    if not path.is_absolute() or path.name in ("", ".", ".."):
        raise QualificationError(f"{label} path must be absolute")
    try:
        entry = path.lstat()
    except OSError as error:
        raise QualificationError(f"{label} is unavailable") from error
    if (
        not stat.S_ISREG(entry.st_mode)
        or entry.st_nlink != 1
        or entry.st_size <= 0
        or entry.st_size > maximum
    ):
        raise QualificationError(f"{label} is not a bounded regular file")
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise QualificationError(f"{label} cannot be opened safely") from error
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
            raise QualificationError(f"{label} identity changed before hashing")
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(CHUNK_BYTES, remaining))
            if not chunk:
                raise QualificationError(f"{label} ended while hashing")
            digest.update(chunk)
            if content is not None:
                content.extend(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise QualificationError(f"{label} grew while hashing")
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
            raise QualificationError(f"{label} changed while hashing")
    finally:
        os.close(descriptor)
    return before.st_size, digest.hexdigest(), bytes(content) if content is not None else None


def _metadata(path: Path, expected_name: str, label: str, maximum: int) -> dict[str, Any]:
    if path.name != expected_name:
        raise QualificationError(f"{label} filename is not exact")
    size, digest, _content = _regular_file(path, label, maximum, capture=False)
    return {"bytes": size, "name": expected_name, "sha256": digest}


def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise QualificationError(f"JSON object contains duplicate key: {key}")
        result[key] = value
    return result


def _json_document(path: Path, expected_name: str, label: str) -> tuple[dict[str, Any], dict[str, Any]]:
    if path.name != expected_name:
        raise QualificationError(f"{label} filename is not exact")
    size, digest, content = _regular_file(path, label, MAX_JSON_BYTES, capture=True)
    assert content is not None
    try:
        document = json.loads(
            content.decode("utf-8", "strict"),
            object_pairs_hook=_object_without_duplicate_keys,
            parse_constant=lambda value: (_ for _ in ()).throw(
                QualificationError(f"{label} contains non-finite JSON: {value}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise QualificationError(f"{label} is not strict JSON") from error
    if not isinstance(document, dict):
        raise QualificationError(f"{label} root must be an object")
    return document, {"bytes": size, "name": expected_name, "sha256": digest}


def _exact_mapping(value: object, keys: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise QualificationError(f"{label} fields are not exact")
    return value


def _validate_source(
    repository: str,
    commit: str,
    run_id: int,
    run_attempt: int,
    run_url: str,
    artifact_version: str,
) -> None:
    if repository != REPOSITORY:
        raise QualificationError("qualification is restricted to the official repository")
    if not COMMIT_RE.fullmatch(commit):
        raise QualificationError("source commit must be a lowercase full Git commit")
    if run_id <= 0 or run_attempt <= 0:
        raise QualificationError("workflow run identity must be positive")
    expected_url = f"https://github.com/{REPOSITORY}/actions/runs/{run_id}"
    if run_url != expected_url:
        raise QualificationError("workflow run URL is not the exact official run")
    if artifact_version != f"ci-{run_id}-{run_attempt}":
        raise QualificationError("artifact version is not bound to this run attempt")


def _validate_checksum(path: Path, iso: Mapping[str, Any]) -> dict[str, Any]:
    if path.name != CHECKSUM_NAME:
        raise QualificationError("ISO checksum filename is not exact")
    size, digest, content = _regular_file(path, "ISO checksum", 1024, capture=True)
    assert content is not None
    expected = f"{iso['sha256']}  {ISO_NAME}\n".encode("ascii")
    if not hmac.compare_digest(content, expected):
        raise QualificationError("ISO checksum file does not name the exact ISO digest")
    return {"bytes": size, "name": CHECKSUM_NAME, "sha256": digest}


def _validate_catalog(
    catalog: Mapping[str, Any],
    *,
    artifact_version: str,
    iso: Mapping[str, Any],
    run_id: int,
    run_url: str,
    usb_evidence: Mapping[str, Mapping[str, Any]],
) -> None:
    expected_fields = {
        "artifactName",
        "artifactVersion",
        "sha256",
        "bytes",
        "deviceLayout",
        "qemuUsbBootAttestations",
        "qemuVaultAttestations",
    }
    if set(catalog) != expected_fields:
        raise QualificationError("catalog-v2 entry fields are not exact")
    if (
        catalog["artifactName"] != ISO_NAME
        or catalog["artifactVersion"] != artifact_version
        or catalog["sha256"] != iso["sha256"]
        or type(catalog["bytes"]) is not int
        or catalog["bytes"] != iso["bytes"]
        or not isinstance(catalog["deviceLayout"], dict)
    ):
        raise QualificationError("catalog-v2 entry does not bind the exact ISO")
    for group_name in ("qemuUsbBootAttestations", "qemuVaultAttestations"):
        group = _exact_mapping(catalog[group_name], {"bios", "uefi"}, group_name)
        for firmware in ("bios", "uefi"):
            attestation = group[firmware]
            if not isinstance(attestation, dict):
                raise QualificationError(f"{group_name}.{firmware} is not an object")
            if (
                attestation.get("passed") is not True
                or type(attestation.get("workflowRunId")) is not int
                or attestation.get("workflowRunId") != run_id
                or attestation.get("workflowRunUrl") != run_url
                or attestation.get("logSha256") != usb_evidence[firmware]["sha256"]
            ):
                raise QualificationError(
                    f"{group_name}.{firmware} is not bound to this run and evidence"
                )


def _validate_sbom(sbom: Mapping[str, Any]) -> None:
    if (
        sbom.get("bomFormat") != "CycloneDX"
        or sbom.get("specVersion") != "1.6"
        or type(sbom.get("version")) is not int
        or sbom.get("version", 0) <= 0
        or not isinstance(sbom.get("metadata"), dict)
        or not isinstance(sbom.get("components"), list)
        or not sbom["components"]
    ):
        raise QualificationError("Codex SBOM tranche is not the expected CycloneDX document")


def _validate_snapshot_evidence(content: bytes) -> None:
    pattern = re.compile(
        rb"KERNAID_LINUX_SNAPSHOT_E2E_V1 source=resident semantic_sha256=([0-9a-f]{64})\n"
        rb"KERNAID_LINUX_SNAPSHOT_E2E_V1 source=rescue-bios semantic_sha256=([0-9a-f]{64})\n"
        rb"KERNAID_LINUX_SNAPSHOT_E2E_V1 source=rescue-uefi semantic_sha256=([0-9a-f]{64})\n"
        rb"KERNAID_LINUX_SNAPSHOT_PARITY_V1 semantic_sha256=([0-9a-f]{64}) equal=true\n\Z"
    )
    match = pattern.fullmatch(content)
    if match is None or len(set(match.groups())) != 1:
        raise QualificationError("Linux snapshot evidence does not prove exact parity")


def _validate_lifecycle_evidence(content: bytes, firmware: str) -> None:
    try:
        lines = content.decode("ascii", "strict").splitlines()
    except UnicodeDecodeError as error:
        raise QualificationError(f"{firmware} lifecycle evidence is not ASCII") from error
    prefixes = (
        "KERNAID_QEMU_VAULT_LIFECYCLE_BOOT_V1 ",
        "KERNAID_QEMU_VAULT_LIFECYCLE_BOOT_V1 ",
        "KERNAID_QEMU_VAULT_LIFECYCLE_RAW_V1 ",
        "KERNAID_QEMU_VAULT_LIFECYCLE_ATTESTATION_V1 ",
    )
    if (
        not content.endswith(b"\n")
        or len(lines) != len(prefixes)
        or any(not line.startswith(prefix) for line, prefix in zip(lines, prefixes))
        or any(f"firmware={firmware} " not in line for line in lines)
        or "boot=1 " not in lines[0]
        or "boot=2 " not in lines[1]
        or not lines[-1].endswith(" ready=true")
    ):
        raise QualificationError(f"{firmware} lifecycle evidence framing is not passing")


def build_manifest(arguments: argparse.Namespace) -> dict[str, Any]:
    _validate_source(
        arguments.repository,
        arguments.commit,
        arguments.run_id,
        arguments.run_attempt,
        arguments.run_url,
        arguments.artifact_version,
    )
    iso = _metadata(arguments.iso, ISO_NAME, "Rescue ISO", MAX_ISO_BYTES)
    checksum = _validate_checksum(arguments.checksum, iso)

    usb_evidence: dict[str, dict[str, Any]] = {}
    for firmware in ("bios", "uefi"):
        path = getattr(arguments, f"usb_{firmware}_evidence")
        usb_evidence[firmware] = _metadata(
            path,
            USB_EVIDENCE_NAMES[firmware],
            f"{firmware} USB evidence",
            MAX_USB_EVIDENCE_BYTES,
        )

    catalog, catalog_metadata = _json_document(
        arguments.catalog, CATALOG_NAME, "catalog-v2 entry"
    )
    _validate_catalog(
        catalog,
        artifact_version=arguments.artifact_version,
        iso=iso,
        run_id=arguments.run_id,
        run_url=arguments.run_url,
        usb_evidence=usb_evidence,
    )
    sbom, sbom_metadata = _json_document(arguments.sbom, SBOM_NAME, "Codex SBOM tranche")
    _validate_sbom(sbom)

    snapshot_path = arguments.snapshot_evidence
    if snapshot_path.name != SNAPSHOT_EVIDENCE_NAME:
        raise QualificationError("Linux snapshot evidence filename is not exact")
    snapshot_size, snapshot_digest, snapshot_content = _regular_file(
        snapshot_path,
        "Linux snapshot evidence",
        MAX_SMALL_EVIDENCE_BYTES,
        capture=True,
    )
    assert snapshot_content is not None
    _validate_snapshot_evidence(snapshot_content)
    snapshot_metadata = {
        "bytes": snapshot_size,
        "name": SNAPSHOT_EVIDENCE_NAME,
        "sha256": snapshot_digest,
    }

    lifecycle_evidence: dict[str, dict[str, Any]] = {}
    for firmware in ("bios", "uefi"):
        path = getattr(arguments, f"lifecycle_{firmware}_evidence")
        if path.name != LIFECYCLE_EVIDENCE_NAMES[firmware]:
            raise QualificationError(f"{firmware} lifecycle evidence filename is not exact")
        size, digest, content = _regular_file(
            path,
            f"{firmware} lifecycle evidence",
            MAX_SMALL_EVIDENCE_BYTES,
            capture=True,
        )
        assert content is not None
        _validate_lifecycle_evidence(content, firmware)
        lifecycle_evidence[firmware] = {
            "bytes": size,
            "name": LIFECYCLE_EVIDENCE_NAMES[firmware],
            "sha256": digest,
        }

    return {
        "artifactVersion": arguments.artifact_version,
        "artifacts": {
            "catalogV2Entry": catalog_metadata,
            "codexSbomTranche": sbom_metadata,
            "iso": {**iso, "checksum": checksum},
        },
        "evidence": {
            "linuxSnapshotE2e": snapshot_metadata,
            "qemuUsbBoot": usb_evidence,
            "vaultLifecycle": lifecycle_evidence,
        },
        "requiredJobs": list(REQUIRED_JOBS),
        "schema": SCHEMA,
        "source": {
            "commit": arguments.commit,
            "repository": arguments.repository,
            "workflow": WORKFLOW,
            "workflowRunAttempt": arguments.run_attempt,
            "workflowRunId": arguments.run_id,
            "workflowRunUrl": arguments.run_url,
        },
    }


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


def _write_new(path: Path, payload: bytes) -> None:
    if not path.is_absolute():
        raise QualificationError("manifest output path must be absolute")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o644)
    except OSError as error:
        raise QualificationError("manifest output could not be created exclusively") from error
    published = False
    try:
        os.fchmod(descriptor, 0o644)
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise QualificationError("manifest output could not be written")
            view = view[written:]
        os.fsync(descriptor)
        details = os.fstat(descriptor)
        if (
            not stat.S_ISREG(details.st_mode)
            or details.st_nlink != 1
            or details.st_size != len(payload)
            or stat.S_IMODE(details.st_mode) != 0o644
        ):
            raise QualificationError("manifest output identity is unsafe")
        published = True
    finally:
        os.close(descriptor)
        if not published:
            try:
                path.unlink()
            except FileNotFoundError:
                pass


def _add_common_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--repository", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--run-id", required=True, type=int)
    parser.add_argument("--run-attempt", required=True, type=int)
    parser.add_argument("--run-url", required=True)
    parser.add_argument("--artifact-version", required=True)
    parser.add_argument("--iso", required=True, type=Path)
    parser.add_argument("--checksum", required=True, type=Path)
    parser.add_argument("--catalog", required=True, type=Path)
    parser.add_argument("--sbom", required=True, type=Path)
    parser.add_argument("--snapshot-evidence", required=True, type=Path)
    parser.add_argument("--usb-bios-evidence", required=True, type=Path)
    parser.add_argument("--usb-uefi-evidence", required=True, type=Path)
    parser.add_argument("--lifecycle-bios-evidence", required=True, type=Path)
    parser.add_argument("--lifecycle-uefi-evidence", required=True, type=Path)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create", help="create a new canonical manifest")
    _add_common_arguments(create)
    create.add_argument("--output", required=True, type=Path)
    verify = commands.add_parser("verify", help="recompute and verify a manifest")
    _add_common_arguments(verify)
    verify.add_argument("--manifest", required=True, type=Path)
    return result


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    try:
        payload = canonical_bytes(build_manifest(arguments))
        if arguments.command == "create":
            _write_new(arguments.output, payload)
        else:
            _size, _digest, actual = _regular_file(
                arguments.manifest,
                "qualification manifest",
                MAX_JSON_BYTES,
                capture=True,
            )
            assert actual is not None
            if not hmac.compare_digest(actual, payload):
                raise QualificationError("qualification manifest is not exact and canonical")
        print(f"KERNAID_RESCUE_QUALIFIED_V1 manifest_sha256={hashlib.sha256(payload).hexdigest()}")
    except (OSError, QualificationError, ValueError) as error:
        print(f"REFUSED: {error}", file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
