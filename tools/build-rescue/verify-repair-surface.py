#!/usr/bin/python3
"""Fail closed if stable/candidate repair surfaces are mixed in a build."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile


MAX_ISO_BYTES = 8 * 1024 * 1024 * 1024
MAX_DESK_FILE_BYTES = 16 * 1024 * 1024
MAX_DESK_TOTAL_BYTES = 64 * 1024 * 1024
MAX_SERVER_BYTES = 512 * 1024
MAX_HANDOFF_BYTES = 512 * 1024
MAX_VAULTD_BYTES = 128 * 1024 * 1024
MAX_SQUASHFS_LIST_BYTES = 32 * 1024 * 1024

DESK_REPAIR_TOKENS = (
    b"/api/rescue/repair",
    b"repair.fstab.rollback.prepare",
    b"repair.crypttab.rollback.prepare",
    b"DISABILITA VOCE FSTAB",
    b"RIPRISTINA FSTAB ORIGINALE",
    b"RIPRISTINA CRYPTTAB ORIGINALE",
)
DESK_DIAGNOSIS_TOKENS = (
    b"/api/rescue/inspect-installed-target",
    b"Diagnostica",
)
SERVER_REPAIR_TOKENS = (
    b"/api/rescue/repair",
    b"kernaid.dev/rescue-repair-service/v1alpha1",
    b"kernaid.dev/rescue-repair-service/v1alpha2",
    b"repair.fstab.rollback.prepare",
    b"repair.crypttab.rollback.prepare",
)
SERVER_DIAGNOSIS_TOKENS = (
    b"/api/inventory",
    b"/api/rescue/inspect-installed-target",
    b"/api/authorize-observe",
    b"/api/rescue/provider/openai",
)
MARKER_TOKENS = (
    b"KERNAID_REPAIR_CANDIDATE_BEGIN",
    b"KERNAID_REPAIR_CANDIDATE_END",
)
HANDOFF_READONLY_TOKENS = (
    b"target.readonly.acquire",
    b"target.recovery.readonly.acquire",
    b"linux-ext4-direct-leaf-readonly-bundle-v2",
)
HANDOFF_WRITE_TOKENS = (
    b"target.pending.readwrite.acquire",
    b"target.rollback.pending.readwrite.acquire",
    b"/run/kernaid-rescue-target-write-capability.sock",
    b"/run/kernaid-rescue-vault/repair-target-helper-v1.sock",
    b"repair.transaction.write-lease.consume",
    b"repair.rollback.write-lease.consume",
    b"linux-ext4-direct-leaf-readwrite-mount-v1",
    b"fstab-rollback-direct-leaf-rw-v1",
    b"crypttab-direct-leaf-rw-v1",
    b"crypttab-rollback-direct-leaf-rw-v1",
    b"selected-target-ext4-mount-readwrite-detached",
    b"linux.fstab.disable-missing-uuid.v1",
    b"linux.fstab.restore",
    b"linux.crypttab.disable-missing-uuid.v1",
    b"linux.crypttab.disable-missing-source.v1",
    b"rescue:selected-linux-root:etc/fstab",
    b"rescue:selected-linux-root:etc/crypttab",
)
VAULT_WRITE_TOKENS = (
    b".kernaid-repair-store-v1",
    b"repair.transaction.write-lease.consume",
    b"repair.rollback.write-lease.consume",
)


def _same_file(before: os.stat_result, after: os.stat_result) -> bool:
    return (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_nlink,
        before.st_uid,
        before.st_gid,
        before.st_size,
    ) == (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_nlink,
        after.st_uid,
        after.st_gid,
        after.st_size,
    )


def _regular_payload(path: Path, maximum: int) -> bytes:
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or not 0 < metadata.st_size <= maximum
    ):
        raise ValueError(f"not a bounded regular file: {path}")
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            payload = stream.read(maximum + 1)
        current = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if len(payload) != metadata.st_size or not _same_file(metadata, current):
        raise ValueError(f"file changed while reading: {path}")
    return payload


def _desk_payloads(root: Path) -> list[bytes]:
    root_metadata = root.lstat()
    if not stat.S_ISDIR(root_metadata.st_mode):
        raise ValueError(f"Desk root is not a directory: {root}")
    payloads: list[bytes] = []
    total = 0
    for directory, directories, filenames in os.walk(root, followlinks=False):
        directory_path = Path(directory)
        for name in directories:
            child = directory_path / name
            if child.is_symlink():
                raise ValueError(f"Desk bundle contains a symlink: {child}")
        for name in filenames:
            child = directory_path / name
            payload = _regular_payload(child, MAX_DESK_FILE_BYTES)
            total += len(payload)
            if total > MAX_DESK_TOTAL_BYTES:
                raise ValueError("Desk bundle exceeds the verification bound")
            payloads.append(payload)
    if not payloads:
        raise ValueError("Desk bundle is empty")
    return payloads


def _assert_tokens(
    label: str, payloads: list[bytes], tokens: tuple[bytes, ...], present: bool
) -> None:
    for token in tokens:
        found = any(token in payload for payload in payloads)
        if found != present:
            expectation = "present" if present else "absent"
            raise ValueError(
                f"{label}: expected {token.decode('ascii')} to be {expectation}"
            )


def verify_desk(root: Path, mode: str) -> None:
    payloads = _desk_payloads(root)
    _assert_tokens("Desk diagnosis surface", payloads, DESK_DIAGNOSIS_TOKENS, True)
    _assert_tokens(
        "Desk repair surface", payloads, DESK_REPAIR_TOKENS, mode == "candidate"
    )


def verify_server(path: Path, mode: str) -> None:
    payload = _regular_payload(path, MAX_SERVER_BYTES)
    _assert_tokens(
        "Rescue diagnosis relay", [payload], SERVER_DIAGNOSIS_TOKENS, True
    )
    _assert_tokens(
        "Rescue repair relay", [payload], SERVER_REPAIR_TOKENS, mode == "candidate"
    )
    _assert_tokens("Rescue renderer markers", [payload], MARKER_TOKENS, False)
    compile(payload, str(path), "exec", dont_inherit=True)


def verify_handoff(path: Path, mode: str) -> None:
    payload = _regular_payload(path, MAX_HANDOFF_BYTES)
    _assert_tokens(
        "Rescue read-only target capability",
        [payload],
        HANDOFF_READONLY_TOKENS,
        True,
    )
    _assert_tokens(
        "Rescue write target capability",
        [payload],
        HANDOFF_WRITE_TOKENS,
        mode == "candidate",
    )
    _assert_tokens("Rescue handoff renderer markers", [payload], MARKER_TOKENS, False)
    compile(payload, str(path), "exec", dont_inherit=True)


def verify_vaultd(path: Path, mode: str) -> None:
    payload = _regular_payload(path, MAX_VAULTD_BYTES)
    _assert_tokens(
        "Rescue Vault repair store",
        [payload],
        VAULT_WRITE_TOKENS,
        mode == "candidate",
    )


def _tool(name: str) -> str:
    resolved = shutil.which(name)
    if resolved is None:
        raise ValueError(f"required image verification tool is missing: {name}")
    return resolved


def verify_iso(path: Path, mode: str) -> None:
    iso_metadata = path.lstat()
    if (
        not stat.S_ISREG(iso_metadata.st_mode)
        or iso_metadata.st_nlink != 1
        or not 0 < iso_metadata.st_size <= MAX_ISO_BYTES
    ):
        raise ValueError(f"ISO is not a bounded regular file: {path}")
    with tempfile.TemporaryDirectory(prefix="kernaid-repair-surface-") as temporary:
        temporary_path = Path(temporary)
        squashfs = temporary_path / "filesystem.squashfs"
        root = temporary_path / "root"
        subprocess.run(
            [
                _tool("xorriso"),
                "-osirrox",
                "on",
                "-return_with",
                "FAILURE",
                "32",
                "-indev",
                str(path),
                "-extract",
                "/live/filesystem.squashfs",
                str(squashfs),
            ],
            check=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
        )
        subprocess.run(
            [
                _tool("unsquashfs"),
                "-no-progress",
                "-d",
                str(root),
                str(squashfs),
                "usr/lib/kernaid/rescue_server.py",
                "usr/lib/kernaid/repair_target_handoff.py",
                "usr/lib/kernaid/kernaid-rescue-vaultd",
                "usr/lib/kernaid/kernaid-rescue-repaird",
                "usr/lib/kernaid/kernaid-blockfd-probe",
                "usr/lib/kernaid/repair-candidate-image-v1",
                "etc/systemd/system/kernaid-rescue-repaird.service",
                "etc/systemd/system/kernaid-rescue-repaird.socket",
                "etc/systemd/system/kernaid-rescue-target-write-capability.socket",
                "etc/systemd/system/kernaid-rescue-target-write-capability@.service",
                "etc/sysusers.d/kernaid-repair-candidate.conf",
                "usr/lib/tmpfiles.d/kernaid-repair-candidate.conf",
                "etc/systemd/system/kernaid-ui.service.d/50-kernaid-repair-candidate.conf",
                "etc/systemd/system/kernaid-ready.service.d/50-kernaid-repair-candidate.conf",
                "etc/systemd/system/sockets.target.wants/kernaid-rescue-repaird.socket",
                "opt/kernaid/desk",
            ],
            check=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
        )
        verify_server(root / "usr/lib/kernaid/rescue_server.py", mode)
        verify_handoff(root / "usr/lib/kernaid/repair_target_handoff.py", mode)
        verify_vaultd(root / "usr/lib/kernaid/kernaid-rescue-vaultd", mode)
        verify_desk(root / "opt/kernaid/desk", mode)
        candidate_paths = (
            root / "usr/lib/kernaid/kernaid-rescue-repaird",
            root / "usr/lib/kernaid/kernaid-blockfd-probe",
            root / "usr/lib/kernaid/repair-candidate-image-v1",
            root / "etc/systemd/system/kernaid-rescue-repaird.service",
            root / "etc/systemd/system/kernaid-rescue-repaird.socket",
            root
            / "etc/systemd/system/kernaid-rescue-target-write-capability.socket",
            root
            / "etc/systemd/system/kernaid-rescue-target-write-capability@.service",
            root / "etc/sysusers.d/kernaid-repair-candidate.conf",
            root / "usr/lib/tmpfiles.d/kernaid-repair-candidate.conf",
            root
            / "etc/systemd/system/kernaid-ui.service.d/50-kernaid-repair-candidate.conf",
            root
            / "etc/systemd/system/kernaid-ready.service.d/50-kernaid-repair-candidate.conf",
            root
            / "etc/systemd/system/sockets.target.wants/kernaid-rescue-repaird.socket",
        )
        for candidate_path in candidate_paths:
            exists = candidate_path.exists() or candidate_path.is_symlink()
            if exists != (mode == "candidate"):
                expectation = "present" if mode == "candidate" else "absent"
                raise ValueError(
                    f"expected candidate artifact to be {expectation}: {candidate_path}"
                )
        if mode == "candidate":
            write_service = _regular_payload(candidate_paths[6], 64 * 1024)
            for token in (
                b"Environment=KERNAID_TARGET_HANDOFF_PROFILE=write",
                b"DeviceAllow=block-* rw",
            ):
                if token not in write_service:
                    raise ValueError(
                        f"candidate write-capability unit lacks {token.decode('ascii')}"
                    )
            enabled_socket = candidate_paths[-1]
            if not enabled_socket.is_symlink():
                raise ValueError("candidate repair socket is not enabled")
            link_target = os.readlink(enabled_socket)
            if not link_target.endswith("/kernaid-rescue-repaird.socket"):
                raise ValueError("candidate repair socket enablement target is invalid")
        listing = subprocess.run(
            [_tool("unsquashfs"), "-ll", str(squashfs)],
            check=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        ).stdout
        if len(listing) > MAX_SQUASHFS_LIST_BYTES:
            raise ValueError("SquashFS listing exceeds the verification bound")
        for line in listing.splitlines():
            if b"/usr/lib/kernaid/" in line and (
                b"/__pycache__" in line or line.endswith((b".pyc", b".pyo"))
            ):
                raise ValueError("Python bytecode leaked into the Rescue SquashFS")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("stable", "candidate"), required=True)
    inputs = parser.add_mutually_exclusive_group(required=True)
    inputs.add_argument("--desk-root", type=Path)
    inputs.add_argument("--iso", type=Path)
    args = parser.parse_args()
    try:
        if args.desk_root is not None:
            verify_desk(args.desk_root, args.mode)
        else:
            verify_iso(args.iso, args.mode)
    except (OSError, subprocess.CalledProcessError, ValueError, SyntaxError) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
