#!/usr/bin/python3
"""Create fixed-only QEMU evidence for the Rescue shell IP sandbox."""

from __future__ import annotations

import json
import os
import socket
import stat
import subprocess
import sys
import time


FW_CFG_PATH = (
    "/sys/firmware/qemu_fw_cfg/by_name/opt/kernaid-tauri-sandbox-probe/raw"
)
PROBE_ADDRESS = "192.0.2.1"
PROBE_PORT = 41917
BASELINE_DIRECTORY = "/run/kernaid-tauri-network-probe"
BASELINE_PATH = f"{BASELINE_DIRECTORY}/baseline-v1"
BASELINE = b"KERNAID_RESCUE_TAURI_NETWORK_BASELINE_V1 connected=true\n"
MAX_IP_OUTPUT_BYTES = 64 * 1024
FW_CFG_WAIT_SECONDS = 5.0
FW_CFG_POLL_SECONDS = 0.05


class ProbeError(Exception):
    """A fixed-only probe failure."""


def _read_fw_cfg() -> None:
    descriptor = os.open(
        FW_CFG_PATH, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    )
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_gid != 0
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) & 0o222
            or metadata.st_size not in (0, 2, 3)
        ):
            raise ProbeError
        payload = os.read(descriptor, 4)
    finally:
        os.close(descriptor)
    if payload not in (b"v1", b"v1\0"):
        raise ProbeError


def _wait_for_fw_cfg() -> None:
    deadline = time.monotonic() + FW_CFG_WAIT_SECONDS
    while True:
        try:
            _read_fw_cfg()
            return
        except FileNotFoundError:
            if time.monotonic() >= deadline:
                raise ProbeError
            time.sleep(FW_CFG_POLL_SECONDS)


def _alias_ready() -> None:
    try:
        result = subprocess.run(
            ["/usr/sbin/ip", "-j", "-4", "address", "show", "dev", "lo"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=3,
            env={"LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ProbeError from error
    if result.returncode != 0 or len(result.stdout) > MAX_IP_OUTPUT_BYTES:
        raise ProbeError
    try:
        interfaces = json.loads(result.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProbeError from error
    matches = [
        entry
        for interface in interfaces
        if interface.get("ifname") == "lo"
        for entry in interface.get("addr_info", [])
        if entry.get("family") == "inet"
        and entry.get("local") == PROBE_ADDRESS
        and entry.get("prefixlen") == 32
    ]
    if len(matches) != 1:
        raise ProbeError


def _connect() -> None:
    try:
        connection = socket.create_connection((PROBE_ADDRESS, PROBE_PORT), 2)
    except OSError as error:
        raise ProbeError from error
    connection.close()


def _write_baseline() -> None:
    directory = os.open(
        BASELINE_DIRECTORY,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    try:
        directory_metadata = os.fstat(directory)
        if (
            not stat.S_ISDIR(directory_metadata.st_mode)
            or directory_metadata.st_uid != 0
            or directory_metadata.st_gid != 0
            or stat.S_IMODE(directory_metadata.st_mode) != 0o755
        ):
            raise ProbeError
        marker = os.open(
            "baseline-v1",
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_CLOEXEC
            | os.O_NOFOLLOW,
            0o444,
            dir_fd=directory,
        )
        try:
            if os.write(marker, BASELINE) != len(BASELINE):
                raise ProbeError
            os.fchmod(marker, 0o444)
            os.fsync(marker)
            metadata = os.fstat(marker)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != 0
                or metadata.st_gid != 0
                or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) != 0o444
                or metadata.st_size != len(BASELINE)
            ):
                raise ProbeError
        finally:
            os.close(marker)
    finally:
        os.close(directory)


def run(mode: str) -> None:
    if mode == "wait-marker":
        _wait_for_fw_cfg()
        return
    _read_fw_cfg()
    if mode == "verify-marker":
        return
    if mode == "verify-alias":
        _alias_ready()
        return
    if mode == "baseline":
        _alias_ready()
        _connect()
        _write_baseline()
        return
    raise ProbeError


def main() -> int:
    try:
        if len(sys.argv) != 2:
            raise ProbeError
        run(sys.argv[1])
    except (ProbeError, OSError, ValueError):
        print("KernAid Tauri network probe failed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
