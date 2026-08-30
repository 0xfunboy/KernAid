#!/usr/bin/python3 -I
"""Emit one bounded attestation only when UEFI Secure Boot is enforcing."""

from __future__ import annotations

import os
from pathlib import Path
import stat
import sys


EFIVARS_DIRECTORY = Path("/sys/firmware/efi/efivars")
EFI_GLOBAL_VARIABLE_GUID = "8be4df61-93ca-11d2-aa0d-00e098032b8c"
SHIM_LOCK_GUID = "605dab50-e046-4300-abb6-3dd810dd8b23"
ATTESTATION = (
    "KERNAID_RESCUE_SECURE_BOOT_V1 firmware=uefi secure_boot=enabled "
    "setup_mode=disabled shim_validation=enabled ready=true"
)


class SecureBootStateError(RuntimeError):
    """The firmware state did not prove enforced Secure Boot."""


def _variable(name: str, guid: str, *, required: bool) -> int | None:
    path = EFIVARS_DIRECTORY / f"{name}-{guid}"
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        if required:
            raise SecureBootStateError("required firmware variable is absent") from None
        return None
    except OSError as error:
        raise SecureBootStateError("firmware variable cannot be opened") from error

    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size != 5
        ):
            raise SecureBootStateError("firmware variable identity is invalid")
        payload = os.read(descriptor, 6)
        if len(payload) != 5 or os.read(descriptor, 1):
            raise SecureBootStateError("firmware variable framing is invalid")
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
            raise SecureBootStateError("firmware variable changed while reading")
    finally:
        os.close(descriptor)
    return payload[4]


def attest() -> str:
    secure_boot = _variable(
        "SecureBoot", EFI_GLOBAL_VARIABLE_GUID, required=True
    )
    setup_mode = _variable("SetupMode", EFI_GLOBAL_VARIABLE_GUID, required=True)
    shim_disabled = _variable("MokSBStateRT", SHIM_LOCK_GUID, required=False)
    if secure_boot != 1 or setup_mode != 0 or shim_disabled not in (None, 0):
        raise SecureBootStateError("Secure Boot is not enforcing")
    return ATTESTATION


def main() -> int:
    try:
        print(attest())
    except (OSError, SecureBootStateError):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
