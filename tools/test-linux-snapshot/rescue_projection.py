#!/usr/bin/env python3
"""Fixture-only Rescue projection for the cross-language parity gate.

The accepted fixture name is closed over the repository test corpus. This is
not a production entrypoint and cannot turn a caller-provided path into a
privileged read target.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import time


sys.dont_write_bytecode = True
HASH_DOMAIN = b"KERNAID_LINUX_NORMALIZED_SNAPSHOT_V1\0"
FIXTURE_NAMES = {"healthy", "multi-fs"}


def _load_inspector(repo: Path):
    path = (
        repo
        / "rescue/live-build/config/includes.chroot/usr/lib/kernaid/offline_inspector.py"
    )
    specification = importlib.util.spec_from_file_location(
        "kernaid_snapshot_parity_offline_inspector", path
    )
    if specification is None or specification.loader is None:
        raise RuntimeError("offline inspector module is unavailable")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("fixture", choices=sorted(FIXTURE_NAMES))
    parser.add_argument(
        "--projection", choices=("envelope", "snapshot"), default="envelope"
    )
    arguments = parser.parse_args()

    repo = Path(__file__).resolve().parents[2]
    fixture_root = (
        repo
        / "tests/fixtures/linux-normalized-snapshot"
        / arguments.fixture
        / "root"
    ).resolve(strict=True)
    expected_parent = (
        repo / "tests/fixtures/linux-normalized-snapshot" / arguments.fixture
    ).resolve(strict=True)
    if fixture_root.parent != expected_parent or not fixture_root.is_dir():
        raise RuntimeError("fixture root escaped the closed test corpus")

    inspector = _load_inspector(repo)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    root_fd = os.open(fixture_root, flags)
    try:
        snapshot = inspector.collect_linux(root_fd, time.monotonic() + 10)
    finally:
        os.close(root_fd)

    canonical_snapshot = _canonical(snapshot)
    snapshot_hash = hashlib.sha256(HASH_DOMAIN + canonical_snapshot).hexdigest()
    if arguments.projection == "snapshot":
        output = canonical_snapshot
    else:
        output = _canonical(
            {
                "schemaVersion": "1.0",
                "kind": "linux-normalized-snapshot",
                "snapshotSha256": snapshot_hash,
                "capture": {
                    "mode": "rescue",
                    "targetScope": "selected-installed-target",
                    "accessPolicy": "temporary-read-only-no-replay",
                    "deviceOpenedReadOnly": True,
                    "journalReplayPrevented": True,
                    "privateMountNamespace": True,
                    "mountCleanupVerified": True,
                    "mutationPerformed": False,
                    "crossDeviceTraversalAllowed": False,
                },
                "snapshot": snapshot,
            }
        )
    sys.stdout.buffer.write(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
