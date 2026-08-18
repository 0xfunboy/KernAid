#!/usr/bin/python3
"""Offline, fail-closed verifier for the pinned Rescue Codex CLI."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import pwd
import re
import resource
import ssl
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, NamedTuple


LOCK_SCHEMA = "kernaid.codex-cli-lock.v1"
OPENSSL = Path("/usr/bin/openssl")
MAX_LOCK_BYTES = 64 * 1024
MAX_ARCHIVE_BYTES = 105 * 1024 * 1024
MAX_BINARY_BYTES = 300 * 1024 * 1024
MAX_SIGSTORE_BYTES = 64 * 1024
MAX_TOOL_OUTPUT_BYTES = 64 * 1024
TOOL_TIMEOUT_SECONDS = 10
COPY_CHUNK_BYTES = 1024 * 1024
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
SHA1_PATTERN = re.compile(r"[0-9a-f]{40}")
VERSION_PATTERN = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
TIMESTAMP_PATTERN = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")


class VerificationError(Exception):
    """A sanitized Codex supply-chain verification failure."""


class SigstoreEvidence(NamedTuple):
    certificate_pem: bytes
    certificate_der: bytes
    signature: bytes
    rekor_payload: bytes
    rekor_set_signature: bytes


def _expect_mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise VerificationError(f"{label} is not an object")
    return value


def _expect_exact_keys(
    value: Mapping[str, Any], expected: frozenset[str], label: str
) -> None:
    if frozenset(value) != expected:
        raise VerificationError(f"{label} has unexpected fields")


def _expect_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise VerificationError(f"{label} is not a non-empty string")
    return value


def _expect_integer(value: Any, label: str) -> int:
    if type(value) is not int:
        raise VerificationError(f"{label} is not an integer")
    return value


def _expect_sha256(value: Any, label: str) -> str:
    digest = _expect_string(value, label)
    if SHA256_PATTERN.fullmatch(digest) is None:
        raise VerificationError(f"{label} is not a lowercase SHA-256 digest")
    return digest


def _expect_sha1(value: Any, label: str) -> str:
    digest = _expect_string(value, label)
    if SHA1_PATTERN.fullmatch(digest) is None:
        raise VerificationError(f"{label} is not a lowercase Git object id")
    return digest


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise VerificationError("lock file contains a duplicate JSON key")
        result[key] = value
    return result


def _open_exact_regular(path: Path, maximum_size: int) -> int:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise VerificationError("required input is unavailable") from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise VerificationError("required input is not an exact regular file")
        if not 0 < metadata.st_size <= maximum_size:
            raise VerificationError("required input size is outside policy")
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _read_descriptor(descriptor: int, maximum_size: int) -> bytes:
    metadata = os.fstat(descriptor)
    if not 0 < metadata.st_size <= maximum_size:
        raise VerificationError("required input size is outside policy")
    result = bytearray()
    offset = 0
    while offset < metadata.st_size:
        chunk = os.pread(
            descriptor,
            min(COPY_CHUNK_BYTES, metadata.st_size - offset),
            offset,
        )
        if not chunk:
            raise VerificationError("required input changed while being read")
        result.extend(chunk)
        offset += len(chunk)
    after = os.fstat(descriptor)
    if (
        after.st_dev != metadata.st_dev
        or after.st_ino != metadata.st_ino
        or after.st_size != metadata.st_size
        or after.st_mtime_ns != metadata.st_mtime_ns
    ):
        raise VerificationError("required input changed while being read")
    return bytes(result)


def _sha256_descriptor(descriptor: int, expected_size: int) -> str:
    metadata = os.fstat(descriptor)
    if metadata.st_size != expected_size:
        raise VerificationError("required input has an unexpected size")
    digest = hashlib.sha256()
    offset = 0
    while offset < expected_size:
        chunk = os.pread(
            descriptor,
            min(COPY_CHUNK_BYTES, expected_size - offset),
            offset,
        )
        if not chunk:
            raise VerificationError("required input changed while being hashed")
        digest.update(chunk)
        offset += len(chunk)
    after = os.fstat(descriptor)
    if (
        after.st_dev != metadata.st_dev
        or after.st_ino != metadata.st_ino
        or after.st_size != metadata.st_size
        or after.st_mtime_ns != metadata.st_mtime_ns
    ):
        raise VerificationError("required input changed while being hashed")
    return digest.hexdigest()


def _validate_lock_document(document: dict[str, Any]) -> None:
    _expect_exact_keys(
        document,
        frozenset({"schema", "upstream", "release", "artifact"}),
        "lock file",
    )
    if document["schema"] != LOCK_SCHEMA:
        raise VerificationError("lock file schema is unsupported")

    upstream = _expect_mapping(document["upstream"], "upstream metadata")
    _expect_exact_keys(
        upstream,
        frozenset({"repository", "tag", "commit", "version", "license"}),
        "upstream metadata",
    )
    repository = _expect_string(upstream["repository"], "upstream repository")
    if repository != "https://github.com/openai/codex":
        raise VerificationError("upstream repository is not the approved source")
    version = _expect_string(upstream["version"], "upstream version")
    if VERSION_PATTERN.fullmatch(version) is None:
        raise VerificationError("upstream version is malformed")
    tag = _expect_string(upstream["tag"], "upstream tag")
    if tag != f"rust-v{version}" or "latest" in tag.lower():
        raise VerificationError("upstream tag is not an exact version pin")
    _expect_sha1(upstream["commit"], "upstream commit")

    license_data = _expect_mapping(upstream["license"], "license metadata")
    _expect_exact_keys(
        license_data,
        frozenset({"spdxId", "name", "url", "gitBlobSha1"}),
        "license metadata",
    )
    if (
        license_data["spdxId"] != "Apache-2.0"
        or license_data["name"] != "Apache License 2.0"
        or license_data["url"]
        != f"https://github.com/openai/codex/blob/{tag}/LICENSE"
    ):
        raise VerificationError("license metadata is not the approved upstream license")
    _expect_sha1(license_data["gitBlobSha1"], "license Git blob")

    release = _expect_mapping(document["release"], "release metadata")
    _expect_exact_keys(release, frozenset({"url", "publishedAt"}), "release metadata")
    if release["url"] != f"https://github.com/openai/codex/releases/tag/{tag}":
        raise VerificationError("release URL does not match the exact tag")
    published_at = _expect_string(release["publishedAt"], "release timestamp")
    if TIMESTAMP_PATTERN.fullmatch(published_at) is None:
        raise VerificationError("release timestamp is malformed")

    artifact = _expect_mapping(document["artifact"], "artifact metadata")
    _expect_exact_keys(
        artifact,
        frozenset({"platform", "archive", "binary", "sigstore"}),
        "artifact metadata",
    )
    platform = _expect_string(artifact["platform"], "artifact platform")
    if platform != "x86_64-unknown-linux-musl":
        raise VerificationError("artifact platform is unsupported")

    archive = _expect_mapping(artifact["archive"], "archive metadata")
    _expect_exact_keys(
        archive,
        frozenset({"name", "url", "mediaType", "sizeBytes", "sha256", "entry"}),
        "archive metadata",
    )
    archive_name = f"codex-{platform}.tar.gz"
    if archive["name"] != archive_name:
        raise VerificationError("archive name is not exact")
    archive_url = f"https://github.com/openai/codex/releases/download/{tag}/{archive_name}"
    if archive["url"] != archive_url or "latest" in archive_url.lower():
        raise VerificationError("archive URL is not an exact release asset")
    if archive["mediaType"] != "application/gzip":
        raise VerificationError("archive media type is unsupported")
    archive_size = _expect_integer(archive["sizeBytes"], "archive size")
    if not 0 < archive_size <= MAX_ARCHIVE_BYTES:
        raise VerificationError("archive size is outside policy")
    _expect_sha256(archive["sha256"], "archive SHA-256")

    entry = _expect_mapping(archive["entry"], "archive entry metadata")
    _expect_exact_keys(
        entry,
        frozenset({"path", "type", "mode", "sizeBytes"}),
        "archive entry metadata",
    )
    if (
        entry["path"] != f"codex-{platform}"
        or entry["type"] != "regular"
        or entry["mode"] != "0755"
    ):
        raise VerificationError("archive entry contract is unsupported")

    binary = _expect_mapping(artifact["binary"], "binary metadata")
    _expect_exact_keys(
        binary,
        frozenset(
            {
                "name",
                "sizeBytes",
                "sha256",
                "installPath",
                "ownerUid",
                "ownerGid",
                "mode",
                "versionArgs",
                "versionOutput",
                "elf",
            }
        ),
        "binary metadata",
    )
    binary_size = _expect_integer(binary["sizeBytes"], "binary size")
    entry_size = _expect_integer(entry["sizeBytes"], "archive entry size")
    if binary_size != entry_size or not 0 < binary_size <= MAX_BINARY_BYTES:
        raise VerificationError("binary size is outside policy")
    binary_sha256 = _expect_sha256(binary["sha256"], "binary SHA-256")
    if (
        binary["name"] != "codex"
        or binary["installPath"] != "/usr/lib/kernaid/codex"
        or binary["ownerUid"] != 0
        or binary["ownerGid"] != 0
        or binary["mode"] != "0755"
    ):
        raise VerificationError("binary install contract is unsupported")
    if binary["versionArgs"] != ["--version"]:
        raise VerificationError("binary version command is not exact")
    if binary["versionOutput"] != f"codex-cli {version}\n":
        raise VerificationError("binary version output does not match the pin")

    elf = _expect_mapping(binary["elf"], "ELF metadata")
    _expect_exact_keys(
        elf,
        frozenset(
            {
                "class",
                "data",
                "osAbi",
                "type",
                "machine",
                "programHeaderCount",
                "interpreter",
                "staticPie",
                "executableStack",
            }
        ),
        "ELF metadata",
    )
    expected_elf = {
        "class": "ELF64",
        "data": "little-endian",
        "osAbi": "SYSV",
        "type": "ET_DYN",
        "machine": "EM_X86_64",
        "interpreter": None,
        "staticPie": True,
        "executableStack": False,
    }
    for field, expected in expected_elf.items():
        if elf[field] != expected:
            raise VerificationError("ELF lock metadata is unsupported")
    header_count = _expect_integer(elf["programHeaderCount"], "ELF program header count")
    if not 1 <= header_count <= 64:
        raise VerificationError("ELF program header count is outside policy")

    sigstore = _expect_mapping(artifact["sigstore"], "Sigstore metadata")
    _expect_exact_keys(
        sigstore,
        frozenset(
            {
                "name",
                "url",
                "sizeBytes",
                "sha256",
                "signedBinarySha256",
                "leafCertificateSha256",
                "certificateIdentity",
                "certificateOidcIssuer",
                "rekorLogId",
                "rekorLogIndex",
                "rekorIntegratedTime",
                "trustRoot",
            }
        ),
        "Sigstore metadata",
    )
    sigstore_name = f"codex-{platform}.sigstore"
    if sigstore["name"] != sigstore_name:
        raise VerificationError("Sigstore asset name is not exact")
    sigstore_url = (
        f"https://github.com/openai/codex/releases/download/{tag}/{sigstore_name}"
    )
    if sigstore["url"] != sigstore_url or "latest" in sigstore_url.lower():
        raise VerificationError("Sigstore URL is not an exact release asset")
    sigstore_size = _expect_integer(sigstore["sizeBytes"], "Sigstore asset size")
    if not 0 < sigstore_size <= MAX_SIGSTORE_BYTES:
        raise VerificationError("Sigstore asset size is outside policy")
    _expect_sha256(sigstore["sha256"], "Sigstore asset SHA-256")
    if _expect_sha256(
        sigstore["signedBinarySha256"], "Sigstore signed binary SHA-256"
    ) != binary_sha256:
        raise VerificationError("Sigstore metadata does not bind the pinned binary")
    _expect_sha256(sigstore["leafCertificateSha256"], "Sigstore leaf certificate")
    expected_identity = (
        "https://github.com/openai/codex/.github/workflows/"
        f"rust-release.yml@refs/tags/{tag}"
    )
    if sigstore["certificateIdentity"] != expected_identity:
        raise VerificationError("Sigstore certificate identity is not exact")
    if sigstore["certificateOidcIssuer"] != "https://token.actions.githubusercontent.com":
        raise VerificationError("Sigstore certificate issuer is not approved")
    _expect_sha256(sigstore["rekorLogId"], "Rekor log id")
    if _expect_integer(sigstore["rekorLogIndex"], "Rekor log index") < 0:
        raise VerificationError("Rekor log index is invalid")
    if _expect_integer(sigstore["rekorIntegratedTime"], "Rekor integrated time") <= 0:
        raise VerificationError("Rekor integrated time is invalid")

    trust_root = _expect_mapping(sigstore["trustRoot"], "Sigstore trust root")
    _expect_exact_keys(
        trust_root,
        frozenset(
            {
                "sourceUrl",
                "sourceSha256",
                "rekorPublicKeyDerBase64",
                "rekorPublicKeySha256",
                "fulcioIntermediateCertificateDerBase64",
                "fulcioIntermediateCertificateSha256",
                "fulcioRootCertificateDerBase64",
                "fulcioRootCertificateSha256",
            }
        ),
        "Sigstore trust root",
    )
    source_sha256 = _expect_sha256(
        trust_root["sourceSha256"], "Sigstore trust root source SHA-256"
    )
    expected_source = (
        "https://tuf-repo-cdn.sigstore.dev/targets/"
        f"{source_sha256}.trusted_root.json"
    )
    if trust_root["sourceUrl"] != expected_source:
        raise VerificationError("Sigstore trust root source is not exactly pinned")
    trust_material = (
        (
            "rekorPublicKeyDerBase64",
            "rekorPublicKeySha256",
            "Rekor public key",
            4096,
        ),
        (
            "fulcioIntermediateCertificateDerBase64",
            "fulcioIntermediateCertificateSha256",
            "Fulcio intermediate certificate",
            16 * 1024,
        ),
        (
            "fulcioRootCertificateDerBase64",
            "fulcioRootCertificateSha256",
            "Fulcio root certificate",
            16 * 1024,
        ),
    )
    for data_field, digest_field, label, maximum_size in trust_material:
        decoded = _decode_base64(trust_root[data_field], label, maximum_size)
        expected_digest = _expect_sha256(trust_root[digest_field], f"{label} SHA-256")
        if hashlib.sha256(decoded).hexdigest() != expected_digest:
            raise VerificationError(f"{label} does not match its pinned SHA-256")
    if trust_root["rekorPublicKeySha256"] != sigstore["rekorLogId"]:
        raise VerificationError("Rekor public key does not match the pinned log id")


def load_lock(path: Path) -> dict[str, Any]:
    descriptor = _open_exact_regular(path, MAX_LOCK_BYTES)
    try:
        raw = _read_descriptor(descriptor, MAX_LOCK_BYTES)
    finally:
        os.close(descriptor)
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except VerificationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise VerificationError("lock file is not canonical UTF-8 JSON") from error
    root = _expect_mapping(document, "lock file")
    _validate_lock_document(root)
    return root


def _validate_archive_metadata(descriptor: int, lock: Mapping[str, Any]) -> None:
    archive = lock["artifact"]["archive"]
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise VerificationError("archive is not an exact regular file")
    if metadata.st_size != archive["sizeBytes"]:
        raise VerificationError("archive size does not match the lock")
    if _sha256_descriptor(descriptor, archive["sizeBytes"]) != archive["sha256"]:
        raise VerificationError("archive SHA-256 does not match the lock")


def _write_all(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise VerificationError("temporary output could not be written")
        view = view[written:]


def _reopen_at_start(descriptor: int) -> int:
    source = os.fstat(descriptor)
    try:
        reopened = os.open(
            f"/proc/self/fd/{descriptor}",
            os.O_RDONLY | os.O_CLOEXEC,
        )
    except OSError as error:
        raise VerificationError("archive descriptor cannot be independently reopened") from error
    try:
        metadata = os.fstat(reopened)
        if (
            metadata.st_dev != source.st_dev
            or metadata.st_ino != source.st_ino
            or metadata.st_size != source.st_size
            or not stat.S_ISREG(metadata.st_mode)
        ):
            raise VerificationError("archive descriptor changed while being reopened")
        if os.lseek(reopened, 0, os.SEEK_SET) != 0:
            raise VerificationError("archive descriptor cannot be rewound")
        return reopened
    except Exception:
        os.close(reopened)
        raise


def _extract_archive_payload(
    archive_descriptor: int,
    output_descriptor: int,
    lock: Mapping[str, Any],
) -> None:
    archive_spec = lock["artifact"]["archive"]
    entry_spec = archive_spec["entry"]
    binary_spec = lock["artifact"]["binary"]
    archive_metadata = os.fstat(archive_descriptor)
    output_metadata = os.fstat(output_descriptor)
    if (
        not stat.S_ISREG(output_metadata.st_mode)
        or (archive_metadata.st_dev, archive_metadata.st_ino)
        == (output_metadata.st_dev, output_metadata.st_ino)
    ):
        raise VerificationError("archive output descriptor is unsafe")
    try:
        os.ftruncate(output_descriptor, 0)
        os.lseek(output_descriptor, 0, os.SEEK_SET)
        with os.fdopen(_reopen_at_start(archive_descriptor), "rb", closefd=True) as stream:
            with tarfile.open(fileobj=stream, mode="r:gz") as archive:
                member = archive.next()
                if member is None:
                    raise VerificationError("archive is empty")
                path = PurePosixPath(member.name)
                if (
                    path.is_absolute()
                    or any(part in {"", ".", ".."} for part in path.parts)
                    or member.name != entry_spec["path"]
                    or not member.isfile()
                    or member.type not in {tarfile.REGTYPE, tarfile.AREGTYPE}
                    or member.linkname != ""
                    or member.sparse is not None
                    or member.pax_headers
                    or member.offset != 0
                    or member.offset_data != 512
                    or stat.S_IMODE(member.mode) != int(entry_spec["mode"], 8)
                    or member.size != entry_spec["sizeBytes"]
                ):
                    raise VerificationError("archive entry violates the exact contract")
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise VerificationError("archive entry cannot be read")
                digest = hashlib.sha256()
                total = 0
                while total < member.size:
                    chunk = extracted.read(min(COPY_CHUNK_BYTES, member.size - total))
                    if not chunk:
                        raise VerificationError("archive entry is truncated")
                    total += len(chunk)
                    if total > MAX_BINARY_BYTES:
                        raise VerificationError("archive entry exceeded its bound")
                    digest.update(chunk)
                    _write_all(output_descriptor, chunk)
                if extracted.read(1):
                    raise VerificationError("archive entry exceeds its declared size")
                if archive.next() is not None:
                    raise VerificationError("archive contains more than one entry")
    except VerificationError:
        raise
    except (OSError, tarfile.TarError, EOFError) as error:
        raise VerificationError("archive could not be inspected safely") from error

    if total != binary_spec["sizeBytes"] or digest.hexdigest() != binary_spec["sha256"]:
        raise VerificationError("archive payload does not match the pinned binary")
    os.fsync(output_descriptor)
    inspect_elf(output_descriptor, lock)


def verify_archive(
    descriptor: int,
    lock: Mapping[str, Any],
    output_descriptor: int | None = None,
) -> None:
    _validate_archive_metadata(descriptor, lock)
    if output_descriptor is not None:
        _extract_archive_payload(descriptor, output_descriptor, lock)
        _validate_archive_metadata(descriptor, lock)
        return
    with tempfile.TemporaryFile() as temporary:
        _extract_archive_payload(descriptor, temporary.fileno(), lock)
    _validate_archive_metadata(descriptor, lock)


def inspect_elf(descriptor: int, lock: Mapping[str, Any]) -> None:
    binary = lock["artifact"]["binary"]
    elf = binary["elf"]
    metadata = os.fstat(descriptor)
    if metadata.st_size != binary["sizeBytes"]:
        raise VerificationError("binary size does not match ELF metadata")
    header = os.pread(descriptor, 64, 0)
    if len(header) != 64:
        raise VerificationError("binary has a truncated ELF header")
    try:
        (
            identity,
            file_type,
            machine,
            version,
            entry_point,
            program_offset,
            _section_offset,
            flags,
            header_size,
            program_entry_size,
            program_count,
            _section_entry_size,
            _section_count,
            _section_name_index,
        ) = struct.unpack("<16sHHIQQQIHHHHHH", header)
    except struct.error as error:
        raise VerificationError("binary has malformed ELF metadata") from error
    if (
        identity[:9] != b"\x7fELF\x02\x01\x01\x00\x00"
        or any(identity[9:])
        or file_type != 3
        or machine != 62
        or version != 1
        or entry_point == 0
        or flags != 0
        or header_size != 64
        or program_entry_size != 56
        or program_count != elf["programHeaderCount"]
        or program_offset < 64
        or program_offset + program_count * program_entry_size > metadata.st_size
    ):
        raise VerificationError("binary ELF identity does not match the lock")

    program_table = os.pread(
        descriptor,
        program_count * program_entry_size,
        program_offset,
    )
    if len(program_table) != program_count * program_entry_size:
        raise VerificationError("binary has a truncated ELF program table")
    interpreter_count = 0
    dynamic_count = 0
    stack_flags: list[int] = []
    executable_load = False
    for index in range(program_count):
        start = index * program_entry_size
        fields = struct.unpack("<IIQQQQQQ", program_table[start : start + 56])
        segment_type, segment_flags = fields[0], fields[1]
        if segment_type == 3:
            interpreter_count += 1
        elif segment_type == 2:
            dynamic_count += 1
        elif segment_type == 0x6474E551:
            stack_flags.append(segment_flags)
        if segment_type == 1 and segment_flags & 1:
            executable_load = True
    if (
        interpreter_count != 0
        or dynamic_count != 1
        or stack_flags != [6]
        or not executable_load
    ):
        raise VerificationError("binary is not the pinned static PIE ELF shape")


def _decode_base64(value: Any, label: str, maximum_size: int) -> bytes:
    encoded = _expect_string(value, label)
    if len(encoded) > maximum_size * 2:
        raise VerificationError(f"{label} exceeds its bound")
    try:
        decoded = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as error:
        raise VerificationError(f"{label} is not strict base64") from error
    if not 0 < len(decoded) <= maximum_size:
        raise VerificationError(f"{label} exceeds its bound")
    return decoded


def verify_sigstore(descriptor: int, lock: Mapping[str, Any]) -> SigstoreEvidence:
    sigstore_spec = lock["artifact"]["sigstore"]
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise VerificationError("Sigstore asset is not an exact regular file")
    if metadata.st_size != sigstore_spec["sizeBytes"]:
        raise VerificationError("Sigstore asset size does not match the lock")
    if (
        _sha256_descriptor(descriptor, sigstore_spec["sizeBytes"])
        != sigstore_spec["sha256"]
    ):
        raise VerificationError("Sigstore asset SHA-256 does not match the lock")
    raw = _read_descriptor(descriptor, MAX_SIGSTORE_BYTES)
    if hashlib.sha256(raw).hexdigest() != sigstore_spec["sha256"]:
        raise VerificationError("Sigstore asset changed after verification")
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except VerificationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise VerificationError("Sigstore asset is not bounded UTF-8 JSON") from error
    root = _expect_mapping(document, "Sigstore asset")
    _expect_exact_keys(
        root,
        frozenset({"base64Signature", "cert", "rekorBundle"}),
        "Sigstore asset",
    )
    signature = _decode_base64(root["base64Signature"], "Sigstore signature", 1024)
    certificate_pem = _decode_base64(root["cert"], "Sigstore certificate", 16 * 1024)
    try:
        certificate_text = certificate_pem.decode("ascii")
        certificate_der = ssl.PEM_cert_to_DER_cert(certificate_text)
    except (UnicodeDecodeError, ValueError, ssl.SSLError) as error:
        raise VerificationError("Sigstore certificate is malformed") from error
    if hashlib.sha256(certificate_der).hexdigest() != sigstore_spec[
        "leafCertificateSha256"
    ]:
        raise VerificationError("Sigstore leaf certificate does not match the lock")
    if (
        sigstore_spec["certificateIdentity"].encode("ascii") not in certificate_der
        or sigstore_spec["certificateOidcIssuer"].encode("ascii") not in certificate_der
    ):
        raise VerificationError("Sigstore certificate identity does not match the lock")

    rekor = _expect_mapping(root["rekorBundle"], "Rekor bundle")
    _expect_exact_keys(
        rekor,
        frozenset({"Payload", "SignedEntryTimestamp"}),
        "Rekor bundle",
    )
    rekor_set_signature = _decode_base64(
        rekor["SignedEntryTimestamp"], "Rekor signed entry timestamp", 1024
    )
    payload = _expect_mapping(rekor["Payload"], "Rekor payload")
    _expect_exact_keys(
        payload,
        frozenset({"body", "integratedTime", "logID", "logIndex"}),
        "Rekor payload",
    )
    if (
        payload["integratedTime"] != sigstore_spec["rekorIntegratedTime"]
        or payload["logID"] != sigstore_spec["rekorLogId"]
        or payload["logIndex"] != sigstore_spec["rekorLogIndex"]
    ):
        raise VerificationError("Rekor coordinates do not match the lock")
    body_raw = _decode_base64(payload["body"], "Rekor body", 16 * 1024)
    try:
        body_document = json.loads(
            body_raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys
        )
    except VerificationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise VerificationError("Rekor body is not bounded UTF-8 JSON") from error
    body = _expect_mapping(body_document, "Rekor body")
    _expect_exact_keys(body, frozenset({"apiVersion", "kind", "spec"}), "Rekor body")
    if body["apiVersion"] != "0.0.1" or body["kind"] != "hashedrekord":
        raise VerificationError("Rekor body type is unsupported")
    spec = _expect_mapping(body["spec"], "Rekor specification")
    _expect_exact_keys(spec, frozenset({"data", "signature"}), "Rekor specification")
    data = _expect_mapping(spec["data"], "Rekor data")
    _expect_exact_keys(data, frozenset({"hash"}), "Rekor data")
    hash_data = _expect_mapping(data["hash"], "Rekor hash")
    _expect_exact_keys(hash_data, frozenset({"algorithm", "value"}), "Rekor hash")
    if (
        hash_data["algorithm"] != "sha256"
        or hash_data["value"] != sigstore_spec["signedBinarySha256"]
    ):
        raise VerificationError("Rekor body does not bind the pinned binary")
    signature_data = _expect_mapping(spec["signature"], "Rekor signature")
    _expect_exact_keys(
        signature_data,
        frozenset({"content", "publicKey"}),
        "Rekor signature",
    )
    public_key = _expect_mapping(signature_data["publicKey"], "Rekor public key")
    _expect_exact_keys(public_key, frozenset({"content"}), "Rekor public key")
    if (
        signature_data["content"] != root["base64Signature"]
        or public_key["content"] != root["cert"]
    ):
        raise VerificationError("Rekor body is inconsistent with the Sigstore envelope")
    try:
        rekor_payload = json.dumps(
            payload,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise VerificationError("Rekor payload is not canonical JSON") from error
    return SigstoreEvidence(
        certificate_pem=certificate_pem,
        certificate_der=certificate_der,
        signature=signature,
        rekor_payload=rekor_payload,
        rekor_set_signature=rekor_set_signature,
    )


def _validate_install_metadata(
    metadata: os.stat_result,
    lock: Mapping[str, Any],
    *,
    require_root: bool,
) -> None:
    binary = lock["artifact"]["binary"]
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise VerificationError("Codex binary is not an exact regular file")
    if metadata.st_size != binary["sizeBytes"]:
        raise VerificationError("Codex binary size does not match the lock")
    if stat.S_IMODE(metadata.st_mode) != int(binary["mode"], 8):
        raise VerificationError("Codex binary mode violates the install contract")
    if require_root and (
        metadata.st_uid != binary["ownerUid"] or metadata.st_gid != binary["ownerGid"]
    ):
        raise VerificationError("Codex binary ownership violates the install contract")


def verify_binary(
    descriptor: int,
    lock: Mapping[str, Any],
    *,
    require_root: bool,
) -> None:
    _validate_install_metadata(os.fstat(descriptor), lock, require_root=require_root)
    binary = lock["artifact"]["binary"]
    if _sha256_descriptor(descriptor, binary["sizeBytes"]) != binary["sha256"]:
        raise VerificationError("Codex binary SHA-256 does not match the lock")
    inspect_elf(descriptor, lock)


def _open_trusted_openssl() -> int:
    descriptor = _open_exact_regular(OPENSSL, 16 * 1024 * 1024)
    metadata = os.fstat(descriptor)
    if (
        metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o755
    ):
        os.close(descriptor)
        raise VerificationError("OpenSSL executable has unsafe metadata")
    return descriptor


def _limit_tool_output() -> None:
    resource.setrlimit(
        resource.RLIMIT_FSIZE,
        (MAX_TOOL_OUTPUT_BYTES, MAX_TOOL_OUTPUT_BYTES),
    )


def _run_openssl(
    openssl_descriptor: int,
    arguments: list[str],
    *,
    label: str,
    pass_fds: tuple[int, ...] = (),
    input_data: bytes | None = None,
) -> bytes:
    with (
        tempfile.TemporaryFile() as stdin,
        tempfile.TemporaryFile() as stdout,
        tempfile.TemporaryFile() as stderr,
    ):
        selected_stdin: int | object = subprocess.DEVNULL
        if input_data is not None:
            _write_all(stdin.fileno(), input_data)
            stdin.seek(0)
            selected_stdin = stdin
        inherited = tuple(dict.fromkeys((openssl_descriptor, *pass_fds)))
        try:
            result = subprocess.run(
                [f"/proc/self/fd/{openssl_descriptor}", *arguments],
                stdin=selected_stdin,
                stdout=stdout,
                stderr=stderr,
                check=False,
                close_fds=True,
                pass_fds=inherited,
                env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"},
                timeout=TOOL_TIMEOUT_SECONDS,
                preexec_fn=_limit_tool_output,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise VerificationError(f"bounded {label} failed") from error
        stdout_size = os.fstat(stdout.fileno()).st_size
        stderr_size = os.fstat(stderr.fileno()).st_size
        if (
            result.returncode != 0
            or stdout_size > MAX_TOOL_OUTPUT_BYTES
            or stderr_size != 0
        ):
            raise VerificationError(f"{label} was rejected")
        stdout.seek(0)
        return stdout.read(MAX_TOOL_OUTPUT_BYTES + 1)


def verify_sigstore_signature(
    binary_descriptor: int,
    evidence: SigstoreEvidence,
    lock: Mapping[str, Any],
) -> None:
    sigstore = lock["artifact"]["sigstore"]
    trust_root = sigstore["trustRoot"]
    rekor_public_key = _decode_base64(
        trust_root["rekorPublicKeyDerBase64"], "Rekor public key", 4096
    )
    fulcio_intermediate_der = _decode_base64(
        trust_root["fulcioIntermediateCertificateDerBase64"],
        "Fulcio intermediate certificate",
        16 * 1024,
    )
    fulcio_root_der = _decode_base64(
        trust_root["fulcioRootCertificateDerBase64"],
        "Fulcio root certificate",
        16 * 1024,
    )
    try:
        fulcio_intermediate_pem = ssl.DER_cert_to_PEM_cert(
            fulcio_intermediate_der
        ).encode("ascii")
        fulcio_root_pem = ssl.DER_cert_to_PEM_cert(fulcio_root_der).encode("ascii")
    except (ValueError, ssl.SSLError, UnicodeEncodeError) as error:
        raise VerificationError("pinned Fulcio trust material is malformed") from error

    openssl_descriptor = _open_trusted_openssl()
    try:
        san_output = _run_openssl(
            openssl_descriptor,
            ["x509", "-noout", "-ext", "subjectAltName"],
            label="Sigstore subject alternative name inspection",
            input_data=evidence.certificate_pem,
        )
        try:
            san_lines = [
                line.strip()
                for line in san_output.decode("ascii").splitlines()
                if line.strip()
            ]
        except UnicodeDecodeError as error:
            raise VerificationError("Sigstore certificate SAN output is malformed") from error
        if san_lines != [
            "X509v3 Subject Alternative Name: critical",
            f"URI:{sigstore['certificateIdentity']}",
        ]:
            raise VerificationError("Sigstore certificate identity extension is not exact")

        certificate_text = _run_openssl(
            openssl_descriptor,
            ["x509", "-noout", "-text"],
            label="Sigstore certificate extension inspection",
            input_data=evidence.certificate_pem,
        )
        try:
            extension_lines = certificate_text.decode("ascii").splitlines()
        except UnicodeDecodeError as error:
            raise VerificationError(
                "Sigstore certificate extension output is malformed"
            ) from error
        expected_extensions = {
            "1.3.6.1.4.1.57264.1.1:": sigstore["certificateOidcIssuer"],
            "1.3.6.1.4.1.57264.1.3:": lock["upstream"]["commit"],
            "1.3.6.1.4.1.57264.1.5:": "openai/codex",
            "1.3.6.1.4.1.57264.1.6:": f"refs/tags/{lock['upstream']['tag']}",
        }
        for oid, expected_value in expected_extensions.items():
            positions = [
                index
                for index, line in enumerate(extension_lines)
                if line.strip() == oid
            ]
            if (
                len(positions) != 1
                or positions[0] + 1 >= len(extension_lines)
                or extension_lines[positions[0] + 1].strip() != expected_value
            ):
                raise VerificationError(
                    "Sigstore source provenance extension is not exact"
                )

        with (
            tempfile.TemporaryFile() as public_key,
            tempfile.TemporaryFile() as signature,
            tempfile.TemporaryFile() as rekor_key,
            tempfile.TemporaryFile() as rekor_payload,
            tempfile.TemporaryFile() as rekor_set,
            tempfile.TemporaryFile() as leaf_certificate,
            tempfile.TemporaryFile() as intermediate_certificate,
            tempfile.TemporaryFile() as root_certificate,
        ):
            public_key_bytes = _run_openssl(
                openssl_descriptor,
                ["x509", "-pubkey", "-noout"],
                label="Sigstore certificate public key extraction",
                input_data=evidence.certificate_pem,
            )
            if not 0 < len(public_key_bytes) <= MAX_TOOL_OUTPUT_BYTES:
                raise VerificationError("Sigstore public key output is outside policy")
            for stream, value in (
                (public_key, public_key_bytes),
                (signature, evidence.signature),
                (rekor_key, rekor_public_key),
                (rekor_payload, evidence.rekor_payload),
                (rekor_set, evidence.rekor_set_signature),
                (leaf_certificate, evidence.certificate_pem),
                (intermediate_certificate, fulcio_intermediate_pem),
                (root_certificate, fulcio_root_pem),
            ):
                _write_all(stream.fileno(), value)
                stream.flush()

            chain_output = _run_openssl(
                openssl_descriptor,
                [
                    "verify",
                    "-no-CAfile",
                    "-no-CApath",
                    "-no-CAstore",
                    "-attime",
                    str(sigstore["rekorIntegratedTime"]),
                    "-purpose",
                    "any",
                    "-CAfile",
                    f"/proc/self/fd/{root_certificate.fileno()}",
                    "-untrusted",
                    f"/proc/self/fd/{intermediate_certificate.fileno()}",
                    f"/proc/self/fd/{leaf_certificate.fileno()}",
                ],
                label="Fulcio certificate chain verification",
                pass_fds=(
                    root_certificate.fileno(),
                    intermediate_certificate.fileno(),
                    leaf_certificate.fileno(),
                ),
            )
            if (
                len(chain_output.splitlines()) != 1
                or not chain_output.endswith(b": OK\n")
            ):
                raise VerificationError("Fulcio certificate chain output is malformed")

            rekor_output = _run_openssl(
                openssl_descriptor,
                [
                    "dgst",
                    "-sha256",
                    "-verify",
                    f"/proc/self/fd/{rekor_key.fileno()}",
                    "-keyform",
                    "DER",
                    "-signature",
                    f"/proc/self/fd/{rekor_set.fileno()}",
                    f"/proc/self/fd/{rekor_payload.fileno()}",
                ],
                label="Rekor signed entry timestamp verification",
                pass_fds=(
                    rekor_key.fileno(),
                    rekor_set.fileno(),
                    rekor_payload.fileno(),
                ),
            )
            if rekor_output != b"Verified OK\n":
                raise VerificationError("Rekor signed entry timestamp output is malformed")

            signature_output = _run_openssl(
                openssl_descriptor,
                [
                    "dgst",
                    "-sha256",
                    "-verify",
                    f"/proc/self/fd/{public_key.fileno()}",
                    "-signature",
                    f"/proc/self/fd/{signature.fileno()}",
                    f"/proc/self/fd/{binary_descriptor}",
                ],
                label="Sigstore detached binary signature verification",
                pass_fds=(
                    public_key.fileno(),
                    signature.fileno(),
                    binary_descriptor,
                ),
            )
            if signature_output != b"Verified OK\n":
                raise VerificationError("Sigstore signature output is malformed")
    finally:
        os.close(openssl_descriptor)


def run_pinned_version(
    binary_descriptor: int,
    lock: Mapping[str, Any],
    *,
    archive_verified: bool,
    sigstore_verified: bool,
) -> None:
    if not archive_verified or not sigstore_verified:
        raise VerificationError("refusing to execute before supply-chain verification")
    binary = lock["artifact"]["binary"]
    try:
        account_home = Path(pwd.getpwuid(os.geteuid()).pw_dir)
        home_metadata = account_home.stat(follow_symlinks=False)
    except (KeyError, OSError) as error:
        raise VerificationError("trusted account home is unavailable") from error
    if (
        not stat.S_ISDIR(home_metadata.st_mode)
        or home_metadata.st_uid != os.geteuid()
        or stat.S_IMODE(home_metadata.st_mode) & 0o022
    ):
        raise VerificationError("trusted account home has unsafe metadata")
    with (
        tempfile.TemporaryDirectory(
            prefix=".kernaid-codex-version-", dir=account_home
        ) as temporary_home,
        tempfile.TemporaryFile() as stdout,
        tempfile.TemporaryFile() as stderr,
    ):
        try:
            result = subprocess.run(
                [f"/proc/self/fd/{binary_descriptor}", *binary["versionArgs"]],
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                check=False,
                close_fds=True,
                cwd=temporary_home,
                pass_fds=(binary_descriptor,),
                env={
                    "CODEX_HOME": temporary_home,
                    "HOME": temporary_home,
                    "LC_ALL": "C",
                    "NO_COLOR": "1",
                    "PATH": "/usr/bin:/bin",
                },
                timeout=TOOL_TIMEOUT_SECONDS,
                preexec_fn=_limit_tool_output,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise VerificationError("bounded Codex version check failed") from error
        if result.returncode != 0:
            raise VerificationError("Codex version command was rejected")
        stdout_size = os.fstat(stdout.fileno()).st_size
        stderr_size = os.fstat(stderr.fileno()).st_size
        if stdout_size > MAX_TOOL_OUTPUT_BYTES or stderr_size != 0:
            raise VerificationError("Codex version output is outside policy")
        stdout.seek(0)
        if stdout.read(MAX_TOOL_OUTPUT_BYTES + 1) != binary["versionOutput"].encode("ascii"):
            raise VerificationError("Codex version output does not match the lock")


def verify_paths(
    lock_path: Path,
    archive_path: Path,
    sigstore_path: Path,
    binary_path: Path,
) -> None:
    lock = load_lock(lock_path)
    archive_descriptor: int | None = None
    sigstore_descriptor: int | None = None
    binary_descriptor: int | None = None
    try:
        archive_descriptor = _open_exact_regular(archive_path, MAX_ARCHIVE_BYTES)
        sigstore_descriptor = _open_exact_regular(sigstore_path, MAX_SIGSTORE_BYTES)
        binary_descriptor = _open_exact_regular(binary_path, MAX_BINARY_BYTES)
        verify_archive(archive_descriptor, lock)
        evidence = verify_sigstore(sigstore_descriptor, lock)
        verify_binary(binary_descriptor, lock, require_root=True)
        verify_sigstore_signature(binary_descriptor, evidence, lock)
        run_pinned_version(
            binary_descriptor,
            lock,
            archive_verified=True,
            sigstore_verified=True,
        )
    finally:
        for descriptor in (
            binary_descriptor,
            sigstore_descriptor,
            archive_descriptor,
        ):
            if descriptor is not None:
                os.close(descriptor)


def parse_arguments(arguments: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verify an installed Rescue Codex CLI without network access."
    )
    parser.add_argument("--lock", required=True, type=Path)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--sigstore", required=True, type=Path)
    parser.add_argument("binary", type=Path)
    return parser.parse_args(arguments)


def main(arguments: list[str]) -> int:
    options = parse_arguments(arguments)
    try:
        verify_paths(options.lock, options.archive, options.sigstore, options.binary)
    except VerificationError as error:
        print(f"Rescue Codex CLI rejected: {error}", file=sys.stderr)
        return 2
    except OSError:
        print("Rescue Codex CLI rejected: bounded local verification failed", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
