from __future__ import annotations

import base64
import copy
import fcntl
import hashlib
import importlib.util
import io
import json
import os
import ssl
import stat
import struct
import subprocess
import tarfile
import tempfile
import time
import unittest
from pathlib import Path
from types import ModuleType
from unittest import mock


REPO_DIR = Path(__file__).resolve().parents[3]
LOCK_PATH = REPO_DIR / "rescue/codex/codex-cli.lock.json"
VERIFY_PATH = REPO_DIR / "tools/build-rescue/verify-codex-cli.py"
FETCH_PATH = REPO_DIR / "tools/build-rescue/fetch-codex-cli.py"
SBOM_PATH = REPO_DIR / "tools/build-rescue/generate-rescue-sbom.py"


def load_module(name: str, path: Path) -> ModuleType:
    specification = importlib.util.spec_from_file_location(name, path)
    if specification is None or specification.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


verify = load_module("kernaid_test_verify_codex", VERIFY_PATH)
fetch = load_module("kernaid_test_fetch_codex", FETCH_PATH)
sbom = load_module("kernaid_test_codex_sbom", SBOM_PATH)
PINNED_LOCK = verify.load_lock(LOCK_PATH)


def fake_elf() -> bytes:
    identity = b"\x7fELF\x02\x01\x01" + b"\x00" * 9
    header = struct.pack(
        "<16sHHIQQQIHHHHHH",
        identity,
        3,
        62,
        1,
        0x1000,
        64,
        0,
        0,
        64,
        56,
        9,
        64,
        0,
        0,
    )
    segment_types_and_flags = [
        (1, 4),
        (1, 5),
        (2, 6),
        (7, 4),
        (4, 4),
        (0x6474E550, 4),
        (0x6474E551, 6),
        (0x6474E552, 4),
        (0, 0),
    ]
    programs = b"".join(
        struct.pack("<IIQQQQQQ", segment_type, flags, 0, 0, 0, 0, 0, 0x1000)
        for segment_type, flags in segment_types_and_flags
    )
    return (header + programs).ljust(1024, b"\x00")


def write_archive(path: Path, entries: list[tuple[str, bytes, bytes]]) -> bytes:
    with tarfile.open(path, "w:gz", format=tarfile.GNU_FORMAT) as archive:
        for name, payload, member_type in entries:
            member = tarfile.TarInfo(name)
            member.mode = 0o755
            member.uid = 1001
            member.gid = 1001
            member.uname = "runner"
            member.gname = "runner"
            member.mtime = 0
            member.type = member_type
            if member_type in {tarfile.SYMTYPE, tarfile.LNKTYPE}:
                member.linkname = "elsewhere"
                member.size = 0
                archive.addfile(member)
            else:
                member.size = len(payload)
                archive.addfile(member, io.BytesIO(payload))
    return path.read_bytes()


def fixture_lock(binary: bytes, archive: bytes | None = None) -> dict[str, object]:
    lock = copy.deepcopy(PINNED_LOCK)
    binary_spec = lock["artifact"]["binary"]
    entry_spec = lock["artifact"]["archive"]["entry"]
    binary_spec["sizeBytes"] = len(binary)
    binary_spec["sha256"] = hashlib.sha256(binary).hexdigest()
    entry_spec["sizeBytes"] = len(binary)
    lock["artifact"]["sigstore"]["signedBinarySha256"] = binary_spec["sha256"]
    if archive is not None:
        archive_spec = lock["artifact"]["archive"]
        archive_spec["sizeBytes"] = len(archive)
        archive_spec["sha256"] = hashlib.sha256(archive).hexdigest()
    return lock


class FakeHeaders:
    def __init__(self, values: dict[str, list[str]]) -> None:
        self.values = values

    def get_all(self, key: str, default: list[str]) -> list[str]:
        return self.values.get(key, default)


class FakeResponse(io.BytesIO):
    status = 200

    def __init__(self, payload: bytes, length: int, *, encoding: str | None = None):
        super().__init__(payload)
        values = {"Content-Length": [str(length)]}
        if encoding is not None:
            values["Content-Encoding"] = [encoding]
        self.headers = FakeHeaders(values)

    def geturl(self) -> str:
        return "https://release-assets.githubusercontent.com/asset?signature=pinned"

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *arguments: object) -> None:
        self.close()


class FakeOpener:
    def __init__(self, response: FakeResponse):
        self.response = response

    def open(self, request: object, timeout: int) -> FakeResponse:
        self.request = request
        self.timeout = timeout
        return self.response


class CodexLockTests(unittest.TestCase):
    def test_lock_is_an_exact_non_latest_release_pin(self) -> None:
        upstream = PINNED_LOCK["upstream"]
        artifact = PINNED_LOCK["artifact"]
        self.assertEqual(upstream["tag"], "rust-v0.147.0")
        self.assertEqual(upstream["commit"], "be6e8eac029b183056b7e4402879f15d2c85f61b")
        self.assertEqual(upstream["license"]["spdxId"], "Apache-2.0")
        self.assertEqual(
            artifact["archive"]["sha256"],
            "0246e2e773834e07f0fb5249ed6ebad12e4591e608f8c7bb97dd6a9690544c36",
        )
        self.assertEqual(
            artifact["binary"]["sha256"],
            "cb0a15567e9a60a5820d54b0f6ae86d504dc3805c1eab21a47f70e3eb7b73a40",
        )
        self.assertEqual(
            artifact["binary"]["installPath"], "/usr/lib/kernaid/codex"
        )
        sigstore = artifact["sigstore"]
        self.assertEqual(
            sigstore["leafCertificateSha256"],
            "0cd70c48dbbb777f1910538d62604b16be271028b8195325bb8eae58fcf255c8",
        )
        self.assertEqual(
            sigstore["trustRoot"]["rekorPublicKeySha256"],
            sigstore["rekorLogId"],
        )
        self.assertEqual(artifact["binary"]["versionOutput"], "codex-cli 0.147.0\n")
        for url in (
            PINNED_LOCK["release"]["url"],
            artifact["archive"]["url"],
            artifact["sigstore"]["url"],
        ):
            self.assertNotIn("latest", url.lower())

    def test_lock_rejects_duplicate_keys(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.json"
            path.write_text('{"schema":"one","schema":"two"}', encoding="utf-8")
            with self.assertRaisesRegex(verify.VerificationError, "duplicate JSON key"):
                verify.load_lock(path)

    def test_lock_rejects_mutable_release_url(self) -> None:
        lock = copy.deepcopy(PINNED_LOCK)
        lock["artifact"]["archive"]["url"] = (
            "https://github.com/openai/codex/releases/latest/download/codex.tar.gz"
        )
        with self.assertRaisesRegex(verify.VerificationError, "exact release asset"):
            verify._validate_lock_document(lock)

    def test_root_install_contract_is_exact(self) -> None:
        lock = fixture_lock(fake_elf())
        size = lock["artifact"]["binary"]["sizeBytes"]
        safe = os.stat_result((stat.S_IFREG | 0o755, 1, 1, 1, 0, 0, size, 0, 0, 0))
        verify._validate_install_metadata(safe, lock, require_root=True)
        wrong_owner = os.stat_result(
            (stat.S_IFREG | 0o755, 1, 1, 1, 1000, 1000, size, 0, 0, 0)
        )
        wrong_mode = os.stat_result((stat.S_IFREG | 0o775, 1, 1, 1, 0, 0, size, 0, 0, 0))
        hardlinked = os.stat_result((stat.S_IFREG | 0o755, 1, 1, 2, 0, 0, size, 0, 0, 0))
        for metadata in (wrong_owner, wrong_mode, hardlinked):
            with self.assertRaises(verify.VerificationError):
                verify._validate_install_metadata(metadata, lock, require_root=True)


class CodexArchiveTests(unittest.TestCase):
    def verify_fixture(self, entries: list[tuple[str, bytes, bytes]]) -> None:
        binary = fake_elf()
        with tempfile.TemporaryDirectory() as directory:
            archive_path = Path(directory) / "codex.tar.gz"
            archive = write_archive(archive_path, entries)
            lock = fixture_lock(binary, archive)
            archive_descriptor = os.open(archive_path, os.O_RDONLY | os.O_CLOEXEC)
            try:
                verify.verify_archive(archive_descriptor, lock)
            finally:
                os.close(archive_descriptor)

    def test_exact_single_regular_archive_is_accepted(self) -> None:
        entry = PINNED_LOCK["artifact"]["archive"]["entry"]["path"]
        self.verify_fixture([(entry, fake_elf(), tarfile.REGTYPE)])

    def test_archive_is_read_from_start_when_download_fd_is_at_eof(self) -> None:
        binary = fake_elf()
        entry = PINNED_LOCK["artifact"]["archive"]["entry"]["path"]
        with tempfile.TemporaryDirectory() as directory:
            archive_path = Path(directory) / "codex.tar.gz"
            archive = write_archive(
                archive_path, [(entry, binary, tarfile.REGTYPE)]
            )
            lock = fixture_lock(binary, archive)
            descriptor = os.open(archive_path, os.O_RDONLY | os.O_CLOEXEC)
            try:
                self.assertEqual(
                    os.lseek(descriptor, 0, os.SEEK_END), len(archive)
                )
                verify.verify_archive(descriptor, lock)
                self.assertEqual(os.lseek(descriptor, 0, os.SEEK_CUR), len(archive))
            finally:
                os.close(descriptor)

    def test_archive_rejects_path_traversal(self) -> None:
        with self.assertRaisesRegex(verify.VerificationError, "exact contract"):
            self.verify_fixture(
                [("../codex-x86_64-unknown-linux-musl", fake_elf(), tarfile.REGTYPE)]
            )

    def test_archive_rejects_symlink(self) -> None:
        entry = PINNED_LOCK["artifact"]["archive"]["entry"]["path"]
        with self.assertRaisesRegex(verify.VerificationError, "exact contract"):
            self.verify_fixture([(entry, b"", tarfile.SYMTYPE)])

    def test_archive_rejects_multiple_entries(self) -> None:
        entry = PINNED_LOCK["artifact"]["archive"]["entry"]["path"]
        with self.assertRaisesRegex(verify.VerificationError, "more than one"):
            self.verify_fixture(
                [
                    (entry, fake_elf(), tarfile.REGTYPE),
                    ("unexpected", b"x", tarfile.REGTYPE),
                ]
            )

    def test_archive_rejects_hidden_gnu_longname_preamble(self) -> None:
        binary = fake_elf()
        entry = PINNED_LOCK["artifact"]["archive"]["entry"]["path"]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "codex.tar.gz"
            with tarfile.open(path, "w:gz", format=tarfile.GNU_FORMAT) as archive:
                longname_payload = entry.encode("ascii") + b"\x00"
                longname = tarfile.TarInfo("././@LongLink")
                longname.type = tarfile.GNUTYPE_LONGNAME
                longname.mode = 0o644
                longname.size = len(longname_payload)
                archive.addfile(longname, io.BytesIO(longname_payload))
                member = tarfile.TarInfo("ignored-by-longlink")
                member.type = tarfile.REGTYPE
                member.mode = 0o755
                member.size = len(binary)
                archive.addfile(member, io.BytesIO(binary))
            archive_bytes = path.read_bytes()
            lock = fixture_lock(binary, archive_bytes)
            descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
            try:
                with self.assertRaisesRegex(verify.VerificationError, "exact contract"):
                    verify.verify_archive(descriptor, lock)
            finally:
                os.close(descriptor)

    def test_archive_hash_is_checked_before_tar_parsing(self) -> None:
        binary = fake_elf()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "codex.tar.gz"
            archive = write_archive(
                path,
                [
                    (
                        PINNED_LOCK["artifact"]["archive"]["entry"]["path"],
                        binary,
                        tarfile.REGTYPE,
                    )
                ],
            )
            lock = fixture_lock(binary, archive)
            damaged = bytearray(archive)
            damaged[-1] ^= 1
            path.write_bytes(damaged)
            descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
            try:
                with self.assertRaisesRegex(verify.VerificationError, "archive SHA-256"):
                    verify.verify_archive(descriptor, lock)
            finally:
                os.close(descriptor)

    def test_elf_rejects_an_interpreter_segment(self) -> None:
        binary = bytearray(fake_elf())
        struct.pack_into("<I", binary, 64, 3)
        lock = fixture_lock(bytes(binary))
        with tempfile.TemporaryFile() as stream:
            stream.write(binary)
            stream.flush()
            with self.assertRaisesRegex(verify.VerificationError, "static PIE"):
                verify.inspect_elf(stream.fileno(), lock)


class CodexSigstoreTests(unittest.TestCase):
    def make_evidence(
        self, directory: Path, binary_path: Path, lock: dict[str, object]
    ) -> tuple[Path, dict[str, object]]:
        identity = lock["artifact"]["sigstore"]["certificateIdentity"]
        issuer = lock["artifact"]["sigstore"]["certificateOidcIssuer"]
        commit = lock["upstream"]["commit"]
        tag_ref = f"refs/tags/{lock['upstream']['tag']}"
        key = directory / "key.pem"
        certificate = directory / "certificate.pem"
        signature = directory / "signature.bin"
        subprocess.run(
            [
                "/usr/bin/openssl",
                "req",
                "-x509",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:prime256v1",
                "-nodes",
                "-keyout",
                key,
                "-out",
                certificate,
                "-days",
                "1",
                "-subj",
                "/CN=KernAid test",
                "-addext",
                f"subjectAltName=critical,URI:{identity}",
                "-addext",
                f"1.3.6.1.4.1.57264.1.1=DER:{issuer.encode('ascii').hex()}",
                "-addext",
                f"1.3.6.1.4.1.57264.1.3=DER:{commit.encode('ascii').hex()}",
                "-addext",
                f"1.3.6.1.4.1.57264.1.5=DER:{'openai/codex'.encode('ascii').hex()}",
                "-addext",
                f"1.3.6.1.4.1.57264.1.6=DER:{tag_ref.encode('ascii').hex()}",
            ],
            check=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"},
        )
        subprocess.run(
            [
                "/usr/bin/openssl",
                "dgst",
                "-sha256",
                "-sign",
                key,
                "-out",
                signature,
                binary_path,
            ],
            check=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"},
        )
        signature_base64 = base64.b64encode(signature.read_bytes()).decode("ascii")
        certificate_base64 = base64.b64encode(certificate.read_bytes()).decode("ascii")
        sigstore_spec = lock["artifact"]["sigstore"]
        sigstore_spec["rekorIntegratedTime"] = int(time.time())
        certificate_der = ssl.PEM_cert_to_DER_cert(
            certificate.read_text(encoding="ascii")
        )
        sigstore_spec["leafCertificateSha256"] = hashlib.sha256(
            certificate_der
        ).hexdigest()
        body = {
            "apiVersion": "0.0.1",
            "kind": "hashedrekord",
            "spec": {
                "data": {
                    "hash": {
                        "algorithm": "sha256",
                        "value": sigstore_spec["signedBinarySha256"],
                    }
                },
                "signature": {
                    "content": signature_base64,
                    "publicKey": {"content": certificate_base64},
                },
            },
        }
        bundle = {
            "base64Signature": signature_base64,
            "cert": certificate_base64,
            "rekorBundle": {
                "Payload": {
                    "body": base64.b64encode(
                        json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
                    ).decode("ascii"),
                    "integratedTime": sigstore_spec["rekorIntegratedTime"],
                    "logID": sigstore_spec["rekorLogId"],
                    "logIndex": sigstore_spec["rekorLogIndex"],
                },
                "SignedEntryTimestamp": base64.b64encode(b"test-set").decode("ascii"),
            },
        }
        raw = json.dumps(bundle, sort_keys=True, separators=(",", ":")).encode("ascii")
        bundle_path = directory / "codex.sigstore"
        bundle_path.write_bytes(raw)
        sigstore_spec["sizeBytes"] = len(raw)
        sigstore_spec["sha256"] = hashlib.sha256(raw).hexdigest()
        return bundle_path, lock

    def make_locally_trusted_evidence(
        self, directory: Path, binary_path: Path, lock: dict[str, object]
    ) -> tuple[Path, dict[str, object]]:
        bundle_path, lock = self.make_evidence(directory, binary_path, lock)
        sigstore_spec = lock["artifact"]["sigstore"]
        trust_root = sigstore_spec["trustRoot"]
        certificate = directory / "certificate.pem"
        certificate_der = ssl.PEM_cert_to_DER_cert(
            certificate.read_text(encoding="ascii")
        )
        certificate_base64 = base64.b64encode(certificate_der).decode("ascii")
        certificate_sha256 = hashlib.sha256(certificate_der).hexdigest()
        trust_root["fulcioIntermediateCertificateDerBase64"] = certificate_base64
        trust_root["fulcioIntermediateCertificateSha256"] = certificate_sha256
        trust_root["fulcioRootCertificateDerBase64"] = certificate_base64
        trust_root["fulcioRootCertificateSha256"] = certificate_sha256

        rekor_key = directory / "rekor-key.pem"
        rekor_public_key = directory / "rekor-public-key.der"
        rekor_set = directory / "rekor-set.bin"
        subprocess.run(
            [
                "/usr/bin/openssl",
                "genpkey",
                "-algorithm",
                "EC",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-out",
                rekor_key,
            ],
            check=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"},
        )
        subprocess.run(
            [
                "/usr/bin/openssl",
                "pkey",
                "-in",
                rekor_key,
                "-pubout",
                "-outform",
                "DER",
                "-out",
                rekor_public_key,
            ],
            check=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"},
        )
        rekor_key_der = rekor_public_key.read_bytes()
        rekor_log_id = hashlib.sha256(rekor_key_der).hexdigest()
        trust_root["rekorPublicKeyDerBase64"] = base64.b64encode(
            rekor_key_der
        ).decode("ascii")
        trust_root["rekorPublicKeySha256"] = rekor_log_id
        sigstore_spec["rekorLogId"] = rekor_log_id

        bundle = json.loads(bundle_path.read_text(encoding="ascii"))
        payload = bundle["rekorBundle"]["Payload"]
        payload["logID"] = rekor_log_id
        canonical_payload = json.dumps(
            payload, sort_keys=True, separators=(",", ":")
        ).encode("ascii")
        payload_path = directory / "rekor-payload.json"
        payload_path.write_bytes(canonical_payload)
        subprocess.run(
            [
                "/usr/bin/openssl",
                "dgst",
                "-sha256",
                "-sign",
                rekor_key,
                "-out",
                rekor_set,
                payload_path,
            ],
            check=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"},
        )
        bundle["rekorBundle"]["SignedEntryTimestamp"] = base64.b64encode(
            rekor_set.read_bytes()
        ).decode("ascii")
        raw = json.dumps(bundle, sort_keys=True, separators=(",", ":")).encode("ascii")
        bundle_path.write_bytes(raw)
        sigstore_spec["sizeBytes"] = len(raw)
        sigstore_spec["sha256"] = hashlib.sha256(raw).hexdigest()
        return bundle_path, lock

    def test_self_signed_bundle_is_not_a_sigstore_trust_proof(self) -> None:
        binary = fake_elf()
        lock = fixture_lock(binary)
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            binary_path = directory / "codex"
            binary_path.write_bytes(binary)
            binary_path.chmod(0o755)
            bundle_path, lock = self.make_evidence(directory, binary_path, lock)
            bundle_descriptor = os.open(bundle_path, os.O_RDONLY | os.O_CLOEXEC)
            binary_descriptor = os.open(binary_path, os.O_RDONLY | os.O_CLOEXEC)
            try:
                evidence = verify.verify_sigstore(bundle_descriptor, lock)
                verify.verify_binary(binary_descriptor, lock, require_root=False)
                with self.assertRaisesRegex(
                    verify.VerificationError, "Fulcio certificate chain"
                ):
                    verify.verify_sigstore_signature(binary_descriptor, evidence, lock)
            finally:
                os.close(binary_descriptor)
                os.close(bundle_descriptor)

    def test_fulcio_chain_rekor_set_and_detached_signature_are_required(self) -> None:
        binary = fake_elf()
        lock = fixture_lock(binary)
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            binary_path = directory / "codex"
            binary_path.write_bytes(binary)
            binary_path.chmod(0o755)
            bundle_path, lock = self.make_locally_trusted_evidence(
                directory, binary_path, lock
            )
            bundle_descriptor = os.open(bundle_path, os.O_RDONLY | os.O_CLOEXEC)
            binary_descriptor = os.open(binary_path, os.O_RDONLY | os.O_CLOEXEC)
            try:
                evidence = verify.verify_sigstore(bundle_descriptor, lock)
                verify.verify_binary(binary_descriptor, lock, require_root=False)
                verify.verify_sigstore_signature(binary_descriptor, evidence, lock)
                original_commit = lock["upstream"]["commit"]
                lock["upstream"]["commit"] = "0" * 40
                with self.assertRaisesRegex(
                    verify.VerificationError, "source provenance"
                ):
                    verify.verify_sigstore_signature(binary_descriptor, evidence, lock)
                lock["upstream"]["commit"] = original_commit
            finally:
                os.close(binary_descriptor)
                os.close(bundle_descriptor)

    def test_invalid_rekor_set_is_rejected_with_a_trusted_certificate(self) -> None:
        binary = fake_elf()
        lock = fixture_lock(binary)
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            binary_path = directory / "codex"
            binary_path.write_bytes(binary)
            binary_path.chmod(0o755)
            bundle_path, lock = self.make_locally_trusted_evidence(
                directory, binary_path, lock
            )
            bundle = json.loads(bundle_path.read_text(encoding="ascii"))
            bundle["rekorBundle"]["SignedEntryTimestamp"] = base64.b64encode(
                b"invalid-set"
            ).decode("ascii")
            raw = json.dumps(bundle, sort_keys=True, separators=(",", ":")).encode(
                "ascii"
            )
            bundle_path.write_bytes(raw)
            sigstore_spec = lock["artifact"]["sigstore"]
            sigstore_spec["sizeBytes"] = len(raw)
            sigstore_spec["sha256"] = hashlib.sha256(raw).hexdigest()
            bundle_descriptor = os.open(bundle_path, os.O_RDONLY | os.O_CLOEXEC)
            binary_descriptor = os.open(binary_path, os.O_RDONLY | os.O_CLOEXEC)
            try:
                evidence = verify.verify_sigstore(bundle_descriptor, lock)
                with self.assertRaisesRegex(verify.VerificationError, "Rekor signed"):
                    verify.verify_sigstore_signature(binary_descriptor, evidence, lock)
            finally:
                os.close(binary_descriptor)
                os.close(bundle_descriptor)

    def test_execution_guard_runs_before_subprocess(self) -> None:
        with tempfile.TemporaryFile() as binary:
            with mock.patch.object(verify.subprocess, "run") as run:
                with self.assertRaisesRegex(verify.VerificationError, "before supply-chain"):
                    verify.run_pinned_version(
                        binary.fileno(),
                        PINNED_LOCK,
                        archive_verified=False,
                        sigstore_verified=True,
                    )
                run.assert_not_called()


class CodexDownloadTests(unittest.TestCase):
    def test_exact_bounded_download_is_accepted(self) -> None:
        payload = b"pinned"
        opener = FakeOpener(FakeResponse(payload, len(payload)))
        with tempfile.TemporaryFile() as output:
            fetch.download_exact(
                PINNED_LOCK["artifact"]["archive"]["url"],
                len(payload),
                len(payload),
                output.fileno(),
                opener=opener,
            )
            output.seek(0)
            self.assertEqual(output.read(), payload)
        self.assertEqual(opener.timeout, fetch.DOWNLOAD_TIMEOUT_SECONDS)

    def test_download_to_archive_verification_keeps_eof_offset_isolated(self) -> None:
        binary = fake_elf()
        entry = PINNED_LOCK["artifact"]["archive"]["entry"]["path"]
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source.tar.gz"
            archive = write_archive(source, [(entry, binary, tarfile.REGTYPE)])
            lock = fixture_lock(binary, archive)
            descriptor, raw_output = tempfile.mkstemp(dir=directory)
            output = Path(raw_output)
            try:
                fetch.download_exact(
                    PINNED_LOCK["artifact"]["archive"]["url"],
                    len(archive),
                    len(archive),
                    descriptor,
                    opener=FakeOpener(FakeResponse(archive, len(archive))),
                )
                self.assertEqual(os.lseek(descriptor, 0, os.SEEK_CUR), len(archive))
                verify.verify_archive(descriptor, lock)
                self.assertEqual(os.lseek(descriptor, 0, os.SEEK_CUR), len(archive))
            finally:
                os.close(descriptor)
                output.unlink()

    def test_download_rejects_extra_bytes(self) -> None:
        payload = b"pinned"
        opener = FakeOpener(FakeResponse(payload + b"x", len(payload)))
        with tempfile.TemporaryFile() as output:
            with self.assertRaisesRegex(fetch.verifier.VerificationError, "exceeded"):
                fetch.download_exact(
                    PINNED_LOCK["artifact"]["archive"]["url"],
                    len(payload),
                    len(payload),
                    output.fileno(),
                    opener=opener,
                )

    def test_download_rejects_content_transformation(self) -> None:
        payload = b"pinned"
        opener = FakeOpener(FakeResponse(payload, len(payload), encoding="gzip"))
        with tempfile.TemporaryFile() as output:
            with self.assertRaisesRegex(fetch.verifier.VerificationError, "encoded"):
                fetch.download_exact(
                    PINNED_LOCK["artifact"]["archive"]["url"],
                    len(payload),
                    len(payload),
                    output.fileno(),
                    opener=opener,
                )

    def test_redirect_policy_rejects_non_github_hosts(self) -> None:
        with self.assertRaisesRegex(fetch.verifier.VerificationError, "HTTPS policy"):
            fetch._validate_download_url(
                "https://example.invalid/codex.tar.gz", allow_release_storage=True
            )

    def test_installer_has_no_arbitrary_output_override(self) -> None:
        with mock.patch.object(fetch.sys, "stderr", io.StringIO()):
            with self.assertRaises(SystemExit):
                fetch.parse_arguments(
                    [
                        "--lock",
                        str(LOCK_PATH),
                        "--output",
                        "/usr/bin/codex",
                    ]
                )
        source = FETCH_PATH.read_text(encoding="utf-8")
        self.assertNotIn('parser.add_argument("--output"', source)
        self.assertEqual(
            fetch._derive_output(PINNED_LOCK, None),
            Path("/usr/lib/kernaid/codex"),
        )

    def test_mkstemp_writer_is_closed_before_version_execution(self) -> None:
        script = b"#!/bin/sh\nprintf 'codex-cli 0.147.0\\n'\n"
        with tempfile.TemporaryDirectory() as directory:
            writer, raw_path = tempfile.mkstemp(dir=directory)
            path = Path(raw_path)
            readonly: int | None = None
            try:
                os.write(writer, script)
                os.fchmod(writer, 0o755)
                os.fsync(writer)
                metadata = os.fstat(writer)
                with self.assertRaisesRegex(
                    verify.VerificationError, "version check failed"
                ):
                    verify.run_pinned_version(
                        writer,
                        PINNED_LOCK,
                        archive_verified=True,
                        sigstore_verified=True,
                    )
                os.close(writer)
                writer = -1
                readonly = fetch._open_same_binary_readonly(path, metadata)
                self.assertEqual(
                    fcntl.fcntl(readonly, fcntl.F_GETFL) & os.O_ACCMODE,
                    os.O_RDONLY,
                )
                verify.run_pinned_version(
                    readonly,
                    PINNED_LOCK,
                    archive_verified=True,
                    sigstore_verified=True,
                )
            finally:
                if readonly is not None:
                    os.close(readonly)
                if writer >= 0:
                    os.close(writer)
                path.unlink()


class RescueSbomTests(unittest.TestCase):
    def test_cyclonedx_output_is_deterministic_and_relates_codex(self) -> None:
        first = sbom.serialize_document(sbom.generate_document(PINNED_LOCK))
        second = sbom.serialize_document(sbom.generate_document(PINNED_LOCK))
        self.assertEqual(first, second)
        document = json.loads(first)
        self.assertEqual(document["bomFormat"], "CycloneDX")
        self.assertEqual(document["specVersion"], "1.6")
        self.assertNotIn("timestamp", document["metadata"])
        component = document["components"][0]
        self.assertEqual(
            component["hashes"],
            [
                {
                    "alg": "SHA-256",
                    "content": PINNED_LOCK["artifact"]["binary"]["sha256"],
                }
            ],
        )
        self.assertEqual(component["licenses"][0]["license"]["id"], "Apache-2.0")
        self.assertEqual(
            document["dependencies"][0],
            {
                "ref": sbom.ROOT_BOM_REF,
                "dependsOn": [component["bom-ref"]],
            },
        )
        self.assertIn("placeholder", document["metadata"]["component"]["properties"][0]["name"])

    def test_sbom_write_is_atomic_regular_0644(self) -> None:
        content = sbom.serialize_document(sbom.generate_document(PINNED_LOCK))
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "rescue.cdx.json"
            sbom.write_atomic(output, content)
            self.assertEqual(output.read_bytes(), content)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o644)
            sbom.write_atomic(output, content)
            self.assertEqual(output.read_bytes(), content)


if __name__ == "__main__":
    unittest.main()
