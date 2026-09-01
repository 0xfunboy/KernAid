#!/usr/bin/python3 -I
"""Create and verify the canonical KernAid release-channel manifest v1.

The channel is a deterministic, hash-bound inventory.  It deliberately does
not claim that an artifact is signed, qualified, or supported merely because
the artifact is listed.  Those properties need their own verified metadata.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
from typing import Any, Final, Mapping, Sequence
from urllib.parse import unquote, urlsplit


SCHEMA: Final = "dev.kernaid.release-channel.v1"
INPUT_SCHEMA: Final = "dev.kernaid.release-channel-input.v1"
REPOSITORY: Final = "0xfunboy/KernAid"
MAX_JSON_BYTES: Final = 2 * 1024 * 1024
MAX_ARTIFACT_BYTES: Final = 1_999_999_998
CHUNK_BYTES: Final = 4 * 1024 * 1024
COMMIT_RE: Final = re.compile(r"[0-9a-f]{40}\Z")
SHA256_RE: Final = re.compile(r"[0-9a-f]{64}\Z")
CHANNEL_RE: Final = re.compile(r"[a-z][a-z0-9-]{0,31}\Z")
VERSION_RE: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}\Z")
FILENAME_RE: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,159}\Z")
MEDIA_TYPE_RE: Final = re.compile(
    r"[a-z0-9][a-z0-9!#$&^_.+-]{0,63}/[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,63}\Z"
)
COMPONENTS: Final = frozenset(("desk", "rescue"))
PLATFORMS: Final = frozenset(("linux", "windows", "macos", "rescue"))
ARCHITECTURES: Final = frozenset(("x86_64", "aarch64"))
VARIANTS_BY_PLATFORM: Final = {
    "linux": frozenset(("appimage", "deb", "rpm")),
    "windows": frozenset(("msi", "nsis")),
    "macos": frozenset(("app", "dmg")),
    "rescue": frozenset(
        (
            "qualified-iso",
            "qualified-zip",
            "retail-img-xz",
            "repair-qualified-iso",
            "repair-qualified-zip",
            "repair-retail-img-xz",
        )
    ),
}
KINDS: Final = frozenset(
    ("package", "image", "checksum", "qualification", "sbom", "signature")
)
DESKTOP_WORKFLOW: Final = ".github/workflows/desktop.yml"
RESCUE_WORKFLOW: Final = ".github/workflows/rescue.yml"
REPAIR_WORKFLOW: Final = ".github/workflows/rescue-repair-candidate.yml"
WORKFLOWS: Final = frozenset((DESKTOP_WORKFLOW, RESCUE_WORKFLOW, REPAIR_WORKFLOW))
REPAIR_VARIANTS: Final = frozenset(
    ("repair-qualified-iso", "repair-qualified-zip", "repair-retail-img-xz")
)


class ReleaseChannelError(RuntimeError):
    """The release-channel input, manifest, or artifact is unsafe or invalid."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReleaseChannelError(f"JSON object contains duplicate key: {key}")
        result[key] = value
    return result


def _regular_file(
    path: Path,
    label: str,
    maximum: int,
    *,
    capture: bool,
) -> tuple[int, str, bytes | None]:
    if not path.is_absolute() or path.name in ("", ".", ".."):
        raise ReleaseChannelError(f"{label} path must be an absolute file path")
    try:
        entry = path.lstat()
    except OSError as error:
        raise ReleaseChannelError(f"{label} is unavailable") from error
    if (
        not stat.S_ISREG(entry.st_mode)
        or entry.st_nlink != 1
        or entry.st_size <= 0
        or entry.st_size > maximum
    ):
        raise ReleaseChannelError(f"{label} is not a bounded single-link regular file")

    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ReleaseChannelError(f"{label} cannot be opened safely") from error

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
            raise ReleaseChannelError(f"{label} identity changed before hashing")
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(CHUNK_BYTES, remaining))
            if not chunk:
                raise ReleaseChannelError(f"{label} ended while hashing")
            digest.update(chunk)
            if content is not None:
                content.extend(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise ReleaseChannelError(f"{label} grew while hashing")
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
            raise ReleaseChannelError(f"{label} changed while hashing")
    finally:
        os.close(descriptor)
    return before.st_size, digest.hexdigest(), bytes(content) if content is not None else None


def _json_document(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    _size, _digest, content = _regular_file(path, label, MAX_JSON_BYTES, capture=True)
    assert content is not None
    try:
        document = json.loads(
            content.decode("utf-8", "strict"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ReleaseChannelError(f"{label} contains non-finite JSON: {value}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReleaseChannelError(f"{label} is not strict UTF-8 JSON") from error
    if not isinstance(document, dict):
        raise ReleaseChannelError(f"{label} root must be an object")
    return document, content


def _exact_object(value: object, expected: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise ReleaseChannelError(f"{label} fields are not exact")
    return value


def _text(value: object, label: str, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise ReleaseChannelError(f"{label} has an invalid value")
    return value


def _choice(value: object, allowed: frozenset[str], label: str) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise ReleaseChannelError(f"{label} is unsupported")
    return value


def _positive_integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ReleaseChannelError(f"{label} must be a positive integer")
    return value


def _published_at(value: object) -> str:
    if not isinstance(value, str) or len(value) != 20:
        raise ReleaseChannelError("publishedAt must use canonical UTC seconds")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as error:
        raise ReleaseChannelError("publishedAt must use canonical UTC seconds") from error
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise ReleaseChannelError("publishedAt is not a real canonical UTC timestamp")
    return value


def _source(value: object) -> dict[str, str]:
    source = _exact_object(value, {"commit", "repository"}, "source")
    repository = source["repository"]
    commit = source["commit"]
    if repository != REPOSITORY:
        raise ReleaseChannelError("source repository is not the official KernAid repository")
    if not isinstance(commit, str) or COMMIT_RE.fullmatch(commit) is None:
        raise ReleaseChannelError("source commit must be a lowercase full Git commit")
    return {"commit": commit, "repository": repository}


def _previous(value: object, sequence: int) -> dict[str, Any] | None:
    if sequence == 1:
        if value is not None:
            raise ReleaseChannelError("sequence 1 must not name a previous manifest")
        return None
    previous = _exact_object(value, {"sequence", "sha256"}, "previous")
    previous_sequence = _positive_integer(previous["sequence"], "previous.sequence")
    if previous_sequence != sequence - 1:
        raise ReleaseChannelError("previous.sequence must immediately precede sequence")
    digest = _text(previous["sha256"], "previous.sha256", SHA256_RE)
    return {"sequence": previous_sequence, "sha256": digest}


def _url(value: object, filename: str, label: str) -> str:
    if not isinstance(value, str) or len(value) > 4096:
        raise ReleaseChannelError(f"{label} must be a bounded HTTPS URL")
    try:
        parsed = urlsplit(value)
        _port = parsed.port
    except ValueError as error:
        raise ReleaseChannelError(f"{label} is malformed") from error
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or unquote(PurePosixPath(parsed.path).name) != filename
    ):
        raise ReleaseChannelError(
            f"{label} must be a stable credential-free HTTPS URL ending in filename"
        )
    return value


def _provenance(
    value: object, component: str, variant: str, label: str
) -> dict[str, Any]:
    provenance = _exact_object(value, {"runAttempt", "runId", "workflow"}, label)
    workflow = _choice(provenance["workflow"], WORKFLOWS, f"{label}.workflow")
    expected_workflow = (
        DESKTOP_WORKFLOW
        if component == "desk"
        else REPAIR_WORKFLOW
        if variant in REPAIR_VARIANTS
        else RESCUE_WORKFLOW
    )
    if workflow != expected_workflow:
        raise ReleaseChannelError(f"{label}.workflow does not match the component")
    return {
        "runAttempt": _positive_integer(provenance["runAttempt"], f"{label}.runAttempt"),
        "runId": _positive_integer(provenance["runId"], f"{label}.runId"),
        "workflow": workflow,
    }


def _artifact_common(value: object, label: str, *, input_document: bool) -> dict[str, Any]:
    common = {
        "architecture",
        "component",
        "kind",
        "mediaType",
        "platform",
        "provenance",
        "url",
        "variant",
        "version",
    }
    expected = common | ({"path"} if input_document else {"bytes", "filename", "sha256"})
    artifact = _exact_object(value, expected, label)

    component = _choice(artifact["component"], COMPONENTS, f"{label}.component")
    platform = _choice(artifact["platform"], PLATFORMS, f"{label}.platform")
    architecture = _choice(
        artifact["architecture"], ARCHITECTURES, f"{label}.architecture"
    )
    kind = _choice(artifact["kind"], KINDS, f"{label}.kind")
    if (component == "rescue") != (platform == "rescue"):
        raise ReleaseChannelError(f"{label} component/platform combination is invalid")
    variant = _choice(
        artifact["variant"], VARIANTS_BY_PLATFORM[platform], f"{label}.variant"
    )
    if (component == "desk" and kind == "image") or (
        component == "rescue" and kind == "package"
    ):
        raise ReleaseChannelError(f"{label} primary artifact kind is invalid")

    version = _text(artifact["version"], f"{label}.version", VERSION_RE)
    media_type = _text(artifact["mediaType"], f"{label}.mediaType", MEDIA_TYPE_RE)
    result: dict[str, Any] = {
        "architecture": architecture,
        "component": component,
        "kind": kind,
        "mediaType": media_type,
        "platform": platform,
        "provenance": _provenance(
            artifact["provenance"], component, variant, f"{label}.provenance"
        ),
        "variant": variant,
        "version": version,
    }

    if input_document:
        path_value = artifact["path"]
        if not isinstance(path_value, str):
            raise ReleaseChannelError(f"{label}.path must be a string")
        path = Path(path_value)
        filename = _text(path.name, f"{label}.path filename", FILENAME_RE)
        size, digest, _content = _regular_file(
            path, f"{label} artifact", MAX_ARTIFACT_BYTES, capture=False
        )
        result.update({"bytes": size, "filename": filename, "sha256": digest})
    else:
        filename = _text(artifact["filename"], f"{label}.filename", FILENAME_RE)
        size = _positive_integer(artifact["bytes"], f"{label}.bytes")
        if size > MAX_ARTIFACT_BYTES:
            raise ReleaseChannelError(f"{label}.bytes exceeds the supported bound")
        digest = _text(artifact["sha256"], f"{label}.sha256", SHA256_RE)
        result.update({"bytes": size, "filename": filename, "sha256": digest})
    result["url"] = _url(artifact["url"], filename, f"{label}.url")
    return result


def _artifact_sort_key(artifact: Mapping[str, Any]) -> tuple[str, ...]:
    return (
        artifact["component"],
        artifact["platform"],
        artifact["architecture"],
        artifact["version"],
        artifact["variant"],
        artifact["kind"],
        artifact["filename"],
    )


def _validate_artifact_set(
    artifacts: list[dict[str, Any]], *, channel: str, require_sorted: bool
) -> None:
    if not 1 <= len(artifacts) <= 64:
        raise ReleaseChannelError("artifacts must contain between 1 and 64 entries")
    if require_sorted and artifacts != sorted(artifacts, key=_artifact_sort_key):
        raise ReleaseChannelError("artifacts are not in canonical order")

    repair = [artifact for artifact in artifacts if artifact["variant"] in REPAIR_VARIANTS]
    if repair:
        if channel != "repair-internal" or len(repair) != len(artifacts):
            raise ReleaseChannelError(
                "Repair artifacts require the isolated repair-internal channel"
            )
    elif channel == "repair-internal":
        raise ReleaseChannelError(
            "repair-internal channel requires exclusively Repair artifacts"
        )

    names: set[str] = set()
    urls: set[str] = set()
    identities: set[tuple[str, ...]] = set()
    groups: dict[tuple[str, ...], list[dict[str, Any]]] = {}
    for artifact in artifacts:
        name = artifact["filename"]
        url = artifact["url"]
        identity = _artifact_sort_key(artifact)[:-1]
        group = identity[:-1]
        if name in names or url in urls or identity in identities:
            raise ReleaseChannelError("artifact filenames, URLs, and identities must be unique")
        names.add(name)
        urls.add(url)
        identities.add(identity)
        groups.setdefault(group, []).append(artifact)

    for group, group_artifacts in groups.items():
        component = group[0]
        primary = "package" if component == "desk" else "image"
        kinds = [artifact["kind"] for artifact in group_artifacts]
        if kinds.count(primary) != 1:
            raise ReleaseChannelError(
                f"release group {group!r} must contain exactly one {primary}"
            )
        provenance = group_artifacts[0]["provenance"]
        if any(artifact["provenance"] != provenance for artifact in group_artifacts[1:]):
            raise ReleaseChannelError(
                f"release group {group!r} must have one exact workflow run provenance"
            )


def build_manifest(descriptor: Mapping[str, Any]) -> dict[str, Any]:
    document = _exact_object(
        descriptor,
        {"artifacts", "channel", "previous", "publishedAt", "schema", "sequence", "source"},
        "release descriptor",
    )
    if document["schema"] != INPUT_SCHEMA:
        raise ReleaseChannelError("release descriptor schema is not v1")
    channel = _text(document["channel"], "channel", CHANNEL_RE)
    sequence = _positive_integer(document["sequence"], "sequence")
    published_at = _published_at(document["publishedAt"])
    source = _source(document["source"])
    previous = _previous(document["previous"], sequence)
    raw_artifacts = document["artifacts"]
    if not isinstance(raw_artifacts, list):
        raise ReleaseChannelError("artifacts must be an array")
    artifacts = [
        _artifact_common(value, f"artifacts[{index}]", input_document=True)
        for index, value in enumerate(raw_artifacts)
    ]
    artifacts.sort(key=_artifact_sort_key)
    _validate_artifact_set(artifacts, channel=channel, require_sorted=True)
    return {
        "artifacts": artifacts,
        "channel": channel,
        "previous": previous,
        "publishedAt": published_at,
        "schema": SCHEMA,
        "sequence": sequence,
        "source": source,
    }


def validate_manifest(document: Mapping[str, Any]) -> dict[str, Any]:
    manifest = _exact_object(
        document,
        {"artifacts", "channel", "previous", "publishedAt", "schema", "sequence", "source"},
        "release-channel manifest",
    )
    if manifest["schema"] != SCHEMA:
        raise ReleaseChannelError("release-channel manifest schema is not v1")
    channel = _text(manifest["channel"], "channel", CHANNEL_RE)
    sequence = _positive_integer(manifest["sequence"], "sequence")
    published_at = _published_at(manifest["publishedAt"])
    source = _source(manifest["source"])
    previous = _previous(manifest["previous"], sequence)
    raw_artifacts = manifest["artifacts"]
    if not isinstance(raw_artifacts, list):
        raise ReleaseChannelError("artifacts must be an array")
    artifacts = [
        _artifact_common(value, f"artifacts[{index}]", input_document=False)
        for index, value in enumerate(raw_artifacts)
    ]
    _validate_artifact_set(artifacts, channel=channel, require_sorted=True)
    return {
        "artifacts": artifacts,
        "channel": channel,
        "previous": previous,
        "publishedAt": published_at,
        "schema": SCHEMA,
        "sequence": sequence,
        "source": source,
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
        raise ReleaseChannelError("manifest output path must be absolute")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o644)
    except OSError as error:
        raise ReleaseChannelError("manifest output could not be created exclusively") from error
    published = False
    try:
        os.fchmod(descriptor, 0o644)
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise ReleaseChannelError("manifest output could not be written")
            view = view[written:]
        os.fsync(descriptor)
        details = os.fstat(descriptor)
        if (
            not stat.S_ISREG(details.st_mode)
            or details.st_nlink != 1
            or details.st_size != len(payload)
            or stat.S_IMODE(details.st_mode) != 0o644
        ):
            raise ReleaseChannelError("manifest output identity is unsafe")
        published = True
    finally:
        os.close(descriptor)
        if not published:
            try:
                path.unlink()
            except FileNotFoundError:
                pass


def _verify_artifacts(root: Path, artifacts: Sequence[Mapping[str, Any]]) -> None:
    if not root.is_absolute():
        raise ReleaseChannelError("artifact root must be absolute")
    try:
        details = root.lstat()
    except OSError as error:
        raise ReleaseChannelError("artifact root is unavailable") from error
    if not stat.S_ISDIR(details.st_mode):
        raise ReleaseChannelError("artifact root must be a real directory")
    for artifact in artifacts:
        filename = artifact["filename"]
        size, digest, _content = _regular_file(
            root / filename,
            f"artifact {filename}",
            MAX_ARTIFACT_BYTES,
            capture=False,
        )
        if size != artifact["bytes"] or not hmac.compare_digest(digest, artifact["sha256"]):
            raise ReleaseChannelError(f"artifact {filename} does not match the manifest")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create", help="hash staged artifacts and create a new manifest")
    create.add_argument("--descriptor", required=True, type=Path)
    create.add_argument("--output", required=True, type=Path)
    verify = commands.add_parser("verify", help="verify a canonical manifest and all staged artifacts")
    verify.add_argument("--manifest", required=True, type=Path)
    verify.add_argument("--artifact-root", required=True, type=Path)
    return result


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    try:
        if arguments.command == "create":
            descriptor, _raw = _json_document(arguments.descriptor, "release descriptor")
            document = build_manifest(descriptor)
            payload = canonical_bytes(document)
            _write_new(arguments.output, payload)
        else:
            raw_document, raw = _json_document(arguments.manifest, "release-channel manifest")
            document = validate_manifest(raw_document)
            payload = canonical_bytes(document)
            if not hmac.compare_digest(raw, payload):
                raise ReleaseChannelError("release-channel manifest is not exact and canonical")
            _verify_artifacts(arguments.artifact_root, document["artifacts"])
        print(
            "KERNAID_RELEASE_CHANNEL_V1 "
            f"sequence={document['sequence']} manifest_sha256={hashlib.sha256(payload).hexdigest()}"
        )
    except (OSError, ReleaseChannelError, ValueError) as error:
        print(f"REFUSED: {error}", file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
