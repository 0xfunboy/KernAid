#!/usr/bin/python3 -IB
"""Root-owned launcher for the inactive KernAid make-device v2 writer.

The launcher validates every executable trust input before importing sibling
Python code.  The shipped catalog is intentionally empty, so this entrypoint
cannot authorize a production image until real catalog-v2 evidence is added.
"""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path
from types import ModuleType


# Production must never consult or create timestamp-based bytecode beside the
# root-owned trust inputs.  The local modules are also compiled directly from
# their validated source bytes below, so a stale cache cannot influence them.
sys.dont_write_bytecode = True


REQUIRED_SIBLINGS = (
    "make-device-v2.py",
    "make_device_v2.py",
    "make-device.py",
    "catalog_v2.py",
    "trusted-rescue-images.v2.json",
    "device-layout.v1.json",
    "vault-profile.v1.json",
)


def _require_root_owned(path: Path, *, directory: bool) -> None:
    details = path.lstat()
    expected_type = stat.S_ISDIR(details.st_mode) if directory else stat.S_ISREG(
        details.st_mode
    )
    if (
        not expected_type
        or details.st_uid != 0
        or stat.S_IMODE(details.st_mode) & 0o022
    ):
        raise RuntimeError(
            f"unsafe installed make-device-v2 trust path: {path}"
        )


def _reject_bundle_cache_and_symlinks(directory: Path) -> None:
    try:
        with os.scandir(directory) as entries:
            for count, entry in enumerate(entries, start=1):
                if count > 128:
                    raise RuntimeError(
                        "installed make-device-v2 bundle is unexpectedly large"
                    )
                details = entry.stat(follow_symlinks=False)
                if stat.S_ISLNK(details.st_mode):
                    raise RuntimeError(
                        f"symlink is forbidden in make-device-v2 bundle: {entry.path}"
                    )
                suffix = os.path.splitext(entry.name)[1]
                if entry.name == "__pycache__" or suffix in {".pyc", ".pyo"}:
                    raise RuntimeError(
                        f"Python bytecode/cache is forbidden in bundle: {entry.path}"
                    )
    except OSError as error:
        raise RuntimeError("cannot enumerate the installed make-device-v2 bundle") from error


def _load_source_only(name: str, path: Path) -> ModuleType:
    expected = path.lstat()
    if not stat.S_ISREG(expected.st_mode) or not 0 < expected.st_size <= 4 * 1024 * 1024:
        raise RuntimeError(f"validated writer source has an unsafe size: {path.name}")
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise RuntimeError(f"cannot open validated writer source: {path.name}") from error
    try:
        observed = os.fstat(descriptor)
        if (
            (observed.st_dev, observed.st_ino, observed.st_mode, observed.st_uid, observed.st_gid)
            != (expected.st_dev, expected.st_ino, expected.st_mode, expected.st_uid, expected.st_gid)
            or observed.st_size != expected.st_size
        ):
            raise RuntimeError(f"validated writer source identity changed: {path.name}")
        chunks: list[bytes] = []
        remaining = expected.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                raise RuntimeError(f"validated writer source ended early: {path.name}")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise RuntimeError(f"validated writer source grew while reading: {path.name}")
        source = b"".join(chunks)
    finally:
        os.close(descriptor)
    module = ModuleType(name)
    module.__file__ = str(path)
    module.__package__ = ""
    sys.modules[name] = module
    try:
        code = compile(source, str(path), "exec", dont_inherit=True)
        exec(code, module.__dict__)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module


def _load_validated_core():
    if sys.pycache_prefix is not None:
        raise RuntimeError("an external Python bytecode cache prefix is forbidden")
    launcher = Path(__file__).resolve(strict=True)
    directory = launcher.parent
    current = directory
    while True:
        _require_root_owned(current, directory=True)
        parent = current.parent
        if parent == current:
            break
        current = parent
    for name in REQUIRED_SIBLINGS:
        _require_root_owned(directory / name, directory=False)
    _reject_bundle_cache_and_symlinks(directory)

    core_path = directory / "make_device_v2.py"
    return _load_source_only("kernaid_make_device_v2_core", core_path)


def main() -> int:
    if sys.platform != "linux":
        os.write(2, b"REFUSED: make-device-v2 is supported only on Linux\n")
        return 3
    if not sys.flags.isolated:
        os.write(2, b"REFUSED: invoke make-device-v2 with /usr/bin/python3 -I\n")
        return 3
    try:
        return int(_load_validated_core().main())
    except BaseException as error:
        detail = str(error).strip() or error.__class__.__name__
        os.write(
            2,
            f"REFUSED: make-device-v2 trust bootstrap failed: {detail}\n".encode(
                "utf-8", "replace"
            ),
        )
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
