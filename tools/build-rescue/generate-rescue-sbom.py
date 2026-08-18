#!/usr/bin/python3
"""Generate the deterministic Codex component tranche of the Rescue SBOM."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import stat
import sys
import tempfile
from pathlib import Path
from types import ModuleType
from typing import Any, Mapping


ROOT_BOM_REF = "urn:kernaid:rescue-image:unreleased"


def _load_verifier() -> ModuleType:
    path = Path(__file__).resolve().with_name("verify-codex-cli.py")
    specification = importlib.util.spec_from_file_location(
        "kernaid_verify_codex_cli_for_sbom", path
    )
    if specification is None or specification.loader is None:
        raise RuntimeError("Codex verifier module is unavailable")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


verifier = _load_verifier()


def generate_document(lock: Mapping[str, Any]) -> dict[str, Any]:
    upstream = lock["upstream"]
    release = lock["release"]
    artifact = lock["artifact"]
    archive = artifact["archive"]
    binary = artifact["binary"]
    sigstore = artifact["sigstore"]
    license_data = upstream["license"]
    component_ref = f"pkg:github/openai/codex@{upstream['tag']}"
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "component": {
                "type": "operating-system",
                "bom-ref": ROOT_BOM_REF,
                "name": "KernAid Rescue image",
                "version": "UNRELEASED",
                "properties": [
                    {
                        "name": "kernaid:sbom:release-assembly-placeholder",
                        "value": (
                            "replace this metadata component when merging the "
                            "release-wide Rescue SBOM"
                        ),
                    }
                ],
            }
        },
        "components": [
            {
                "type": "application",
                "bom-ref": component_ref,
                "supplier": {"name": "OpenAI"},
                "group": "openai",
                "name": "Codex CLI",
                "version": upstream["version"],
                "purl": component_ref,
                "hashes": [
                    {
                        "alg": "SHA-256",
                        "content": binary["sha256"],
                    }
                ],
                "licenses": [
                    {
                        "license": {
                            "id": license_data["spdxId"],
                            "url": license_data["url"],
                        }
                    }
                ],
                "externalReferences": [
                    {
                        "type": "vcs",
                        "url": (
                            f"{upstream['repository']}/tree/{upstream['commit']}"
                        ),
                    },
                    {
                        "type": "release-notes",
                        "url": release["url"],
                    },
                    {
                        "type": "distribution",
                        "url": archive["url"],
                        "hashes": [
                            {
                                "alg": "SHA-256",
                                "content": archive["sha256"],
                            }
                        ],
                    },
                    {
                        "type": "distribution",
                        "url": sigstore["url"],
                        "comment": "Detached Sigstore bundle for the pinned binary",
                        "hashes": [
                            {
                                "alg": "SHA-256",
                                "content": sigstore["sha256"],
                            }
                        ],
                    },
                    {
                        "type": "license",
                        "url": license_data["url"],
                    },
                ],
                "properties": [
                    {
                        "name": "kernaid:codex-cli:source-tag",
                        "value": upstream["tag"],
                    },
                    {
                        "name": "kernaid:codex-cli:source-commit",
                        "value": upstream["commit"],
                    },
                    {
                        "name": "kernaid:codex-cli:platform",
                        "value": artifact["platform"],
                    },
                    {
                        "name": "kernaid:codex-cli:install-path",
                        "value": binary["installPath"],
                    },
                    {
                        "name": "kernaid:codex-cli:signature-certificate-identity",
                        "value": sigstore["certificateIdentity"],
                    },
                    {
                        "name": "kernaid:codex-cli:license-git-blob-sha1",
                        "value": license_data["gitBlobSha1"],
                    },
                ],
            }
        ],
        "dependencies": [
            {
                "ref": ROOT_BOM_REF,
                "dependsOn": [component_ref],
            },
            {
                "ref": component_ref,
                "dependsOn": [],
            },
        ],
    }


def serialize_document(document: Mapping[str, Any]) -> bytes:
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


def write_atomic(output: Path, content: bytes) -> None:
    if not output.is_absolute():
        output = output.resolve(strict=False)
    parent = output.parent
    try:
        parent_metadata = parent.stat(follow_symlinks=False)
    except OSError as error:
        raise verifier.VerificationError("SBOM output directory is unavailable") from error
    if not stat.S_ISDIR(parent_metadata.st_mode) or parent.resolve(strict=True) != parent:
        raise verifier.VerificationError("SBOM output directory is unsafe")
    try:
        target_metadata = output.lstat()
    except FileNotFoundError:
        pass
    except OSError as error:
        raise verifier.VerificationError("SBOM output target is unavailable") from error
    else:
        if not stat.S_ISREG(target_metadata.st_mode) or target_metadata.st_nlink != 1:
            raise verifier.VerificationError("SBOM output target is not an exact regular file")

    descriptor, temporary_name = tempfile.mkstemp(prefix=".rescue-sbom-", dir=parent)
    temporary: Path | None = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o644)
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise verifier.VerificationError("SBOM output could not be written")
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, output)
        temporary = None
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        directory_descriptor = os.open(parent, flags)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary is not None:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass


def parse_arguments(arguments: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate a deterministic CycloneDX Codex CLI SBOM tranche."
    )
    parser.add_argument("--lock", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args(arguments)


def main(arguments: list[str]) -> int:
    options = parse_arguments(arguments)
    try:
        lock = verifier.load_lock(options.lock)
        write_atomic(options.output, serialize_document(generate_document(lock)))
    except verifier.VerificationError as error:
        print(f"Rescue SBOM generation rejected: {error}", file=sys.stderr)
        return 2
    except OSError:
        print("Rescue SBOM generation rejected: bounded local write failed", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
