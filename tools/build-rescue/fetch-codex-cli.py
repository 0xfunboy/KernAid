#!/usr/bin/python3
"""Fetch and atomically install the exactly pinned Rescue Codex CLI."""

from __future__ import annotations

import argparse
import fcntl
import importlib.util
import os
import stat
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from types import ModuleType
from typing import Any, Mapping
from urllib.parse import urlsplit


DOWNLOAD_TIMEOUT_SECONDS = 30
DOWNLOAD_DEADLINE_SECONDS = 180
DOWNLOAD_CHUNK_BYTES = 1024 * 1024
ALLOWED_DOWNLOAD_HOSTS = frozenset(
    {
        "github.com",
        "release-assets.githubusercontent.com",
    }
)


def _load_verifier() -> ModuleType:
    path = Path(__file__).resolve().with_name("verify-codex-cli.py")
    specification = importlib.util.spec_from_file_location(
        "kernaid_verify_codex_cli", path
    )
    if specification is None or specification.loader is None:
        raise RuntimeError("Codex verifier module is unavailable")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


verifier = _load_verifier()


class SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Permit only bounded urllib redirects to GitHub release storage."""

    def redirect_request(
        self,
        request: urllib.request.Request,
        file_pointer: object,
        code: int,
        message: str,
        headers: object,
        new_url: str,
    ) -> urllib.request.Request | None:
        _validate_download_url(new_url, allow_release_storage=True)
        return super().redirect_request(
            request, file_pointer, code, message, headers, new_url
        )


def _validate_download_url(url: str, *, allow_release_storage: bool) -> None:
    parsed = urlsplit(url)
    allowed_hosts = (
        ALLOWED_DOWNLOAD_HOSTS if allow_release_storage else frozenset({"github.com"})
    )
    if (
        parsed.scheme != "https"
        or parsed.hostname not in allowed_hosts
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port not in {None, 443}
        or parsed.fragment
    ):
        raise verifier.VerificationError("download URL violates HTTPS policy")


def _write_all(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise verifier.VerificationError("download output could not be written")
        view = view[written:]


def download_exact(
    url: str,
    expected_size: int,
    maximum_size: int,
    descriptor: int,
    *,
    opener: urllib.request.OpenerDirector | None = None,
) -> None:
    _validate_download_url(url, allow_release_storage=False)
    if not 0 < expected_size <= maximum_size:
        raise verifier.VerificationError("download size is outside policy")
    selected_opener = opener or urllib.request.build_opener(SafeRedirectHandler())
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/octet-stream",
            "Accept-Encoding": "identity",
            "User-Agent": "KernAid-Rescue-Codex-Fetch/1",
        },
        method="GET",
    )
    deadline = time.monotonic() + DOWNLOAD_DEADLINE_SECONDS
    try:
        with selected_opener.open(request, timeout=DOWNLOAD_TIMEOUT_SECONDS) as response:
            if getattr(response, "status", None) != 200:
                raise verifier.VerificationError("release asset returned an unexpected status")
            _validate_download_url(response.geturl(), allow_release_storage=True)
            content_lengths = response.headers.get_all("Content-Length", [])
            if (
                len(content_lengths) != 1
                or not content_lengths[0].isascii()
                or not content_lengths[0].isdigit()
                or int(content_lengths[0]) != expected_size
            ):
                raise verifier.VerificationError(
                    "release asset length does not match the lock"
                )
            content_encodings = response.headers.get_all("Content-Encoding", [])
            if content_encodings and content_encodings != ["identity"]:
                raise verifier.VerificationError("encoded release responses are forbidden")
            os.ftruncate(descriptor, 0)
            os.lseek(descriptor, 0, os.SEEK_SET)
            total = 0
            while total < expected_size:
                if time.monotonic() >= deadline:
                    raise verifier.VerificationError("release asset download timed out")
                chunk = response.read(
                    min(DOWNLOAD_CHUNK_BYTES, expected_size - total + 1)
                )
                if not chunk:
                    raise verifier.VerificationError("release asset download is truncated")
                total += len(chunk)
                if total > expected_size or total > maximum_size:
                    raise verifier.VerificationError("release asset exceeded its bound")
                _write_all(descriptor, chunk)
            if response.read(1):
                raise verifier.VerificationError("release asset exceeded its exact size")
            os.fsync(descriptor)
    except verifier.VerificationError:
        raise
    except (OSError, urllib.error.URLError) as error:
        raise verifier.VerificationError("bounded release asset download failed") from error


def _validate_output(output: Path) -> tuple[Path, int]:
    if not output.is_absolute() or output != Path(os.path.normpath(output)):
        raise verifier.VerificationError("Codex output path must be absolute and normalized")
    parent = output.parent
    try:
        resolved_parent = parent.resolve(strict=True)
        metadata = parent.stat(follow_symlinks=False)
    except OSError as error:
        raise verifier.VerificationError("Codex output directory is unavailable") from error
    if resolved_parent != parent:
        raise verifier.VerificationError("Codex output directory cannot contain symlinks")
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise verifier.VerificationError("Codex output directory has unsafe metadata")
    try:
        os.lstat(output)
    except FileNotFoundError:
        pass
    except OSError as error:
        raise verifier.VerificationError("Codex output target is unavailable") from error
    else:
        raise verifier.VerificationError("refusing to overwrite a Codex output target")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        parent_descriptor = os.open(parent, flags)
    except OSError as error:
        raise verifier.VerificationError("Codex output directory cannot be pinned") from error
    pinned = os.fstat(parent_descriptor)
    if pinned.st_dev != metadata.st_dev or pinned.st_ino != metadata.st_ino:
        os.close(parent_descriptor)
        raise verifier.VerificationError("Codex output directory changed during validation")
    return parent, parent_descriptor


def _temporary_file(parent: Path, label: str) -> tuple[int, Path]:
    descriptor, raw_path = tempfile.mkstemp(prefix=f".codex-{label}-", dir=parent)
    path = Path(raw_path)
    try:
        os.fchmod(descriptor, 0o600)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise verifier.VerificationError("temporary output is not an exact regular file")
        return descriptor, path
    except Exception:
        os.close(descriptor)
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        raise


def _cleanup_temporary(descriptor: int | None, path: Path | None) -> None:
    if descriptor is not None:
        try:
            os.close(descriptor)
        except OSError:
            pass
    if path is not None:
        try:
            path.unlink()
        except FileNotFoundError:
            pass


def _open_same_binary_readonly(path: Path, expected: os.stat_result) -> int:
    descriptor = verifier._open_exact_regular(path, verifier.MAX_BINARY_BYTES)
    try:
        metadata = os.fstat(descriptor)
        if (
            metadata.st_dev != expected.st_dev
            or metadata.st_ino != expected.st_ino
            or metadata.st_size != expected.st_size
            or fcntl.fcntl(descriptor, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDONLY
        ):
            raise verifier.VerificationError(
                "Codex binary changed while being reopened read-only"
            )
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _derive_output(lock: Mapping[str, Any], install_root: Path | None) -> Path:
    root = install_root or Path("/")
    if not root.is_absolute() or root != Path(os.path.normpath(root)):
        raise verifier.VerificationError("Codex install root must be absolute and normalized")
    try:
        resolved_root = root.resolve(strict=True)
        metadata = root.stat(follow_symlinks=False)
    except OSError as error:
        raise verifier.VerificationError("Codex install root is unavailable") from error
    if (
        resolved_root != root
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise verifier.VerificationError("Codex install root has unsafe metadata")
    relative = Path(lock["artifact"]["binary"]["installPath"]).relative_to("/")
    return root / relative


def fetch_and_install(lock_path: Path, install_root: Path | None) -> Path:
    if os.geteuid() != 0:
        raise verifier.VerificationError("Codex installation requires effective uid 0")
    lock = verifier.load_lock(lock_path)
    selected_output = _derive_output(lock, install_root)
    parent, parent_descriptor = _validate_output(selected_output)
    archive_descriptor: int | None = None
    archive_path: Path | None = None
    sigstore_descriptor: int | None = None
    sigstore_path: Path | None = None
    binary_descriptor: int | None = None
    binary_path: Path | None = None
    installed_identity: tuple[int, int] | None = None
    try:
        archive_descriptor, archive_path = _temporary_file(parent, "archive")
        sigstore_descriptor, sigstore_path = _temporary_file(parent, "sigstore")
        binary_descriptor, binary_path = _temporary_file(parent, "binary")

        archive = lock["artifact"]["archive"]
        sigstore = lock["artifact"]["sigstore"]
        download_exact(
            archive["url"],
            archive["sizeBytes"],
            verifier.MAX_ARCHIVE_BYTES,
            archive_descriptor,
        )
        verifier.verify_archive(archive_descriptor, lock, binary_descriptor)

        download_exact(
            sigstore["url"],
            sigstore["sizeBytes"],
            verifier.MAX_SIGSTORE_BYTES,
            sigstore_descriptor,
        )
        evidence = verifier.verify_sigstore(sigstore_descriptor, lock)

        binary = lock["artifact"]["binary"]
        os.fchown(binary_descriptor, binary["ownerUid"], binary["ownerGid"])
        os.fchmod(binary_descriptor, int(binary["mode"], 8))
        os.fsync(binary_descriptor)
        writable_metadata = os.fstat(binary_descriptor)
        os.close(binary_descriptor)
        binary_descriptor = None
        binary_descriptor = _open_same_binary_readonly(binary_path, writable_metadata)
        verifier.verify_binary(binary_descriptor, lock, require_root=True)
        verifier.verify_sigstore_signature(binary_descriptor, evidence, lock)
        verifier.run_pinned_version(
            binary_descriptor,
            lock,
            archive_verified=True,
            sigstore_verified=True,
        )

        binary_metadata = os.fstat(binary_descriptor)
        installed_identity = (binary_metadata.st_dev, binary_metadata.st_ino)
        try:
            os.link(binary_path, selected_output, follow_symlinks=False)
        except FileExistsError as error:
            raise verifier.VerificationError(
                "refusing to overwrite a Codex output target"
            ) from error
        binary_path.unlink()
        binary_path = None
        os.fsync(parent_descriptor)

        installed_descriptor = verifier._open_exact_regular(
            selected_output, verifier.MAX_BINARY_BYTES
        )
        try:
            verifier.verify_binary(installed_descriptor, lock, require_root=True)
        finally:
            os.close(installed_descriptor)
        return selected_output
    except Exception:
        if installed_identity is not None:
            try:
                metadata = os.lstat(selected_output)
                if (metadata.st_dev, metadata.st_ino) == installed_identity:
                    selected_output.unlink()
                    os.fsync(parent_descriptor)
            except FileNotFoundError:
                pass
        raise
    finally:
        _cleanup_temporary(binary_descriptor, binary_path)
        _cleanup_temporary(sigstore_descriptor, sigstore_path)
        _cleanup_temporary(archive_descriptor, archive_path)
        os.close(parent_descriptor)


def parse_arguments(arguments: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Fetch the exact locked Codex CLI and install it atomically."
    )
    parser.add_argument("--lock", required=True, type=Path)
    parser.add_argument(
        "--root",
        type=Path,
        help="canonical root of a prepared sysroot (default: /)",
    )
    return parser.parse_args(arguments)


def main(arguments: list[str]) -> int:
    options = parse_arguments(arguments)
    try:
        output = fetch_and_install(options.lock, options.root)
    except verifier.VerificationError as error:
        print(f"Rescue Codex CLI fetch rejected: {error}", file=sys.stderr)
        return 2
    except OSError:
        print("Rescue Codex CLI fetch rejected: bounded local installation failed", file=sys.stderr)
        return 2
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
