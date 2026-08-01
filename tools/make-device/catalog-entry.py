#!/usr/bin/python3 -I
"""Emit one reviewed trust-catalog entry from a CI-attested Rescue ISO."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import stat
import sys


SHA256_RE = re.compile(r"[0-9a-fA-F]{64}\Z")
NAME_RE = re.compile(r"KernAid-Rescue-[A-Za-z0-9._-]+\.iso\Z")
VERSION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}\Z")
RUN_PREFIX = "https://github.com/0xfunboy/KernAid/actions/runs/"
CHUNK_BYTES = 4 * 1024 * 1024
MAX_LOG_BYTES = 16 * 1024 * 1024
ATTESTATION_PREFIX = "KERNAID_QEMU_ATTESTATION_V1 "
ATTESTATION_FIELDS = frozenset(
    (
        "firmware",
        "iso_sha256",
        "target_before_sha256",
        "target_after_sha256",
        "ready",
    )
)


def sha256_file(path: str) -> tuple[int, str]:
    if not os.path.isabs(path):
        raise ValueError("ISO path must be absolute")
    canonical = os.path.realpath(path)
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(canonical, flags)
    try:
        details = os.fstat(descriptor)
        if not stat.S_ISREG(details.st_mode) or details.st_size <= 0:
            raise ValueError("ISO must be a non-empty regular file")
        digest = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, CHUNK_BYTES)
            if not chunk:
                break
            digest.update(chunk)
        after = os.fstat(descriptor)
        if (
            details.st_dev,
            details.st_ino,
            details.st_size,
            details.st_mtime_ns,
        ) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise ValueError("ISO changed while hashing")
        return details.st_size, digest.hexdigest()
    finally:
        os.close(descriptor)


def attested_log_sha256(path: str, firmware: str, iso_sha256: str) -> str:
    if not os.path.isabs(path):
        raise ValueError(f"{firmware} QEMU log path must be absolute")
    canonical = os.path.realpath(path)
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(canonical, flags)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size <= 0
            or before.st_size > MAX_LOG_BYTES
        ):
            raise ValueError(f"{firmware} QEMU log must be a bounded regular file")
        digest = hashlib.sha256()
        chunks: list[bytes] = []
        total = 0
        while total < before.st_size:
            chunk = os.read(descriptor, min(CHUNK_BYTES, before.st_size - total))
            if not chunk:
                raise ValueError(f"{firmware} QEMU log ended while being read")
            digest.update(chunk)
            chunks.append(chunk)
            total += len(chunk)
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        ) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise ValueError(f"{firmware} QEMU log changed while hashing")
    finally:
        os.close(descriptor)

    try:
        lines = b"".join(chunks).decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise ValueError(f"{firmware} QEMU log is not valid UTF-8") from error
    attestation_lines = [
        line for line in lines if line.startswith(ATTESTATION_PREFIX)
    ]
    if len(attestation_lines) != 1:
        raise ValueError(
            f"{firmware} QEMU log must contain exactly one structured attestation"
        )
    fields: dict[str, str] = {}
    for token in attestation_lines[0].removeprefix(ATTESTATION_PREFIX).split():
        key, separator, value = token.partition("=")
        if not separator or not key or not value or key in fields:
            raise ValueError(f"{firmware} QEMU attestation is malformed")
        fields[key] = value
    if set(fields) != ATTESTATION_FIELDS:
        raise ValueError(f"{firmware} QEMU attestation fields are invalid")
    before_sha256 = fields["target_before_sha256"]
    after_sha256 = fields["target_after_sha256"]
    if (
        fields["firmware"] != firmware
        or fields["ready"] != "true"
        or not SHA256_RE.fullmatch(fields["iso_sha256"])
        or not hmac.compare_digest(fields["iso_sha256"], iso_sha256)
        or not SHA256_RE.fullmatch(before_sha256)
        or not SHA256_RE.fullmatch(after_sha256)
        or not hmac.compare_digest(before_sha256, after_sha256)
    ):
        raise ValueError(
            f"{firmware} QEMU attestation does not prove this ISO and zero target writes"
        )
    return digest.hexdigest()


def attestation(run_id: int, run_url: str, log_sha256: str) -> dict[str, object]:
    run_suffix = run_url.removeprefix(RUN_PREFIX)
    run_component = run_suffix.split("/", 1)[0]
    if (
        run_id <= 0
        or not run_url.startswith(RUN_PREFIX)
        or not run_component.isdigit()
        or int(run_component) != run_id
    ):
        raise ValueError("QEMU workflow run must be a KernAid GitHub Actions run")
    if not SHA256_RE.fullmatch(log_sha256):
        raise ValueError("QEMU log SHA-256 is invalid")
    return {
        "passed": True,
        "workflowRunId": run_id,
        "workflowRunUrl": run_url,
        "logSha256": log_sha256.lower(),
    }


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--iso", required=True)
    result.add_argument("--sha256", required=True)
    result.add_argument("--artifact-version", required=True)
    for firmware in ("bios", "uefi"):
        result.add_argument(f"--{firmware}-run-id", required=True, type=int)
        result.add_argument(f"--{firmware}-run-url", required=True)
        result.add_argument(f"--{firmware}-log", required=True)
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        size, actual_sha256 = sha256_file(args.iso)
        expected_sha256 = args.sha256.lower()
        artifact_name = os.path.basename(os.path.realpath(args.iso))
        if not SHA256_RE.fullmatch(expected_sha256) or actual_sha256 != expected_sha256:
            raise ValueError("ISO SHA-256 does not match the expected release digest")
        if not NAME_RE.fullmatch(artifact_name):
            raise ValueError("ISO filename is not a KernAid Rescue artifact name")
        if not VERSION_RE.fullmatch(args.artifact_version):
            raise ValueError("artifact version is invalid")
        bios_log_sha256 = attested_log_sha256(
            args.bios_log, "bios", actual_sha256
        )
        uefi_log_sha256 = attested_log_sha256(
            args.uefi_log, "uefi", actual_sha256
        )
        entry = {
            "artifactName": artifact_name,
            "artifactVersion": args.artifact_version,
            "sha256": actual_sha256,
            "bytes": size,
            "qemuAttestations": {
                "bios": attestation(
                    args.bios_run_id, args.bios_run_url, bios_log_sha256
                ),
                "uefi": attestation(
                    args.uefi_run_id, args.uefi_run_url, uefi_log_sha256
                ),
            },
        }
    except (OSError, ValueError) as error:
        print(f"REFUSED: {error}", file=sys.stderr)
        return 3
    print(json.dumps(entry, indent=2, sort_keys=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
