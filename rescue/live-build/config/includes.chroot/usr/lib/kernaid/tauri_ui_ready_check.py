#!/usr/bin/python3
"""Attest the shipping Rescue Tauri/WebKit window without exposing UI data."""

from __future__ import annotations

import os
import pwd
import re
import resource
import stat
import subprocess
import tempfile
import time


SHELL_PATH = "/usr/bin/kernaid-rescue-desk-shell"
XORG_PATH = "/usr/lib/xorg/Xorg"
ACTIVE_TTY_PATH = "/sys/class/tty/tty0/active"
WEBKIT_ROOT = "/usr/lib/x86_64-linux-gnu/webkit2gtk-4.1"
WEBKIT_EXECUTABLES = {
    f"{WEBKIT_ROOT}/WebKitNetworkProcess",
    f"{WEBKIT_ROOT}/WebKitWebProcess",
}
FORBIDDEN_BROWSER_NAMES = {"chrome", "chromium", "chromium-browser"}
WINDOW_TITLE_PATTERN = "^KernAid Rescue$"
DISPLAY = ":0"
MAX_PROCESS_FILE_BYTES = 64 * 1024
MAX_PROCESSES = 4096
MAX_PROCESS_ARGUMENTS = 256
MAX_TOOL_OUTPUT_BYTES = 4 * 1024
PROBE_TIMEOUT_SECONDS = 180
TOOL_TIMEOUT_SECONDS = 3


class AttestationError(Exception):
    """A sanitized, fail-closed UI attestation error."""


def _bounded_file(path: str) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        payload = os.read(descriptor, MAX_PROCESS_FILE_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(payload) > MAX_PROCESS_FILE_BYTES:
        raise AttestationError("process metadata exceeded its bound")
    return payload


def _process_identity(pid: int) -> tuple[int, tuple[int, int, int, int], str] | None:
    try:
        stat_payload = _bounded_file(f"/proc/{pid}/stat")
        status_payload = _bounded_file(f"/proc/{pid}/status")
        executable = os.readlink(f"/proc/{pid}/exe")
    except (FileNotFoundError, ProcessLookupError, PermissionError):
        return None
    except OSError:
        return None
    close_parenthesis = stat_payload.rfind(b") ")
    fields = stat_payload[close_parenthesis + 2 :].split()
    if close_parenthesis < 0 or len(fields) < 2:
        return None
    try:
        parent_pid = int(fields[1])
    except ValueError:
        return None
    uid_line = next(
        (line for line in status_payload.splitlines() if line.startswith(b"Uid:\t")),
        None,
    )
    if uid_line is None:
        return None
    uid_fields = uid_line.removeprefix(b"Uid:\t").split()
    if len(uid_fields) != 4:
        return None
    try:
        uids = tuple(int(value) for value in uid_fields)
    except ValueError:
        return None
    if len(uids) != 4:
        return None
    return parent_pid, uids, executable


def _processes() -> dict[int, tuple[int, tuple[int, int, int, int], str]]:
    snapshot: dict[int, tuple[int, tuple[int, int, int, int], str]] = {}
    numeric_entries = 0
    with os.scandir("/proc") as entries:
        for entry in entries:
            if not entry.name.isascii() or not entry.name.isdecimal():
                continue
            numeric_entries += 1
            if numeric_entries > MAX_PROCESSES:
                raise AttestationError("the process table exceeded its bound")
            pid = int(entry.name)
            identity = _process_identity(pid)
            if identity is not None:
                snapshot[pid] = identity
    return snapshot


def _descends_from(
    pid: int,
    ancestor: int,
    processes: dict[int, tuple[int, tuple[int, int, int, int], str]],
) -> bool:
    visited: set[int] = set()
    current = pid
    for _ in range(16):
        if current == ancestor:
            return True
        if current <= 1 or current in visited or current not in processes:
            return False
        visited.add(current)
        current = processes[current][0]
    return False


def _shipping_process() -> tuple[int, bool]:
    processes = _processes()
    for _pid, (_parent, _uids, executable) in processes.items():
        if os.path.basename(executable).lower() in FORBIDDEN_BROWSER_NAMES:
            raise AttestationError("a fallback browser process is running")
    shells = [
        pid
        for pid, (_parent, uids, executable) in processes.items()
        if executable == SHELL_PATH and uids == (1000, 1000, 1000, 1000)
    ]
    if len(shells) > 1:
        raise AttestationError("multiple Rescue shell processes are running")
    if len(shells) != 1:
        return 0, False
    shell_pid = shells[0]
    renderer = any(
        executable == f"{WEBKIT_ROOT}/WebKitWebProcess"
        and uids == (1000, 1000, 1000, 1000)
        and _descends_from(pid, shell_pid, processes)
        for pid, (_parent, uids, executable) in processes.items()
    )
    if any(
        executable in WEBKIT_EXECUTABLES
        and uids != (1000, 1000, 1000, 1000)
        and _descends_from(pid, shell_pid, processes)
        for pid, (_parent, uids, executable) in processes.items()
    ):
        raise AttestationError("the WebKit process identity is unsafe")
    return shell_pid, renderer


def _active_vt_from_payload(payload: bytes) -> int:
    match = re.fullmatch(rb"tty([1-9]|[1-5][0-9]|6[0-3])\n?", payload)
    if match is None:
        raise AttestationError("the active virtual terminal was invalid")
    return int(match.group(1))


def _xorg_vt_from_cmdline(payload: bytes) -> int | None:
    if not payload or not payload.endswith(b"\0"):
        raise AttestationError("the Xorg command line was invalid")
    arguments = payload[:-1].split(b"\0")
    if not arguments or len(arguments) > MAX_PROCESS_ARGUMENTS or b"" in arguments:
        raise AttestationError("the Xorg argument vector was invalid")
    if arguments.count(DISPLAY.encode("ascii")) != 1:
        return None
    vt_arguments = [
        match
        for argument in arguments
        if (match := re.fullmatch(rb"vt([1-9]|[1-5][0-9]|6[0-3])", argument))
    ]
    if len(vt_arguments) != 1:
        return None
    return int(vt_arguments[0].group(1))


def _default_display_is_active_xorg() -> bool:
    active_vt = _active_vt_from_payload(_bounded_file(ACTIVE_TTY_PATH))
    processes = _processes()
    xorg_pids = [
        pid
        for pid, (_parent, _uids, executable) in processes.items()
        if executable == XORG_PATH
    ]
    if len(xorg_pids) > 1:
        raise AttestationError("multiple Xorg processes are running")
    if not xorg_pids:
        return False
    try:
        xorg_vt = _xorg_vt_from_cmdline(
            _bounded_file(f"/proc/{xorg_pids[0]}/cmdline")
        )
    except (FileNotFoundError, ProcessLookupError, PermissionError):
        return False
    return xorg_vt is not None and xorg_vt == active_vt


def _trusted_xauthority(home: str) -> str:
    path = os.path.join(home, ".Xauthority")
    metadata = os.lstat(path)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 1000
        or metadata.st_gid != 1000
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise AttestationError("the X authority file is unsafe")
    return path


def _limit_tool_output() -> None:
    resource.setrlimit(
        resource.RLIMIT_FSIZE,
        (MAX_TOOL_OUTPUT_BYTES, MAX_TOOL_OUTPUT_BYTES),
    )


def _run_as_live_user(arguments: list[str], home: str, xauthority: str) -> str:
    command = [
        "/usr/sbin/runuser",
        "--user",
        "kernaid",
        "--",
        "/usr/bin/env",
        "-i",
        f"HOME={home}",
        f"DISPLAY={DISPLAY}",
        f"XAUTHORITY={xauthority}",
        *arguments,
    ]
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        try:
            result = subprocess.run(
                command,
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                check=False,
                timeout=TOOL_TIMEOUT_SECONDS,
                env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"},
                preexec_fn=_limit_tool_output,
            )
        except (OSError, subprocess.TimeoutExpired):
            return ""
        output_size = os.fstat(stdout.fileno()).st_size
        error_size = os.fstat(stderr.fileno()).st_size
        if (
            result.returncode != 0
            or output_size > MAX_TOOL_OUTPUT_BYTES
            or error_size > MAX_TOOL_OUTPUT_BYTES
        ):
            return ""
        stdout.seek(0)
        try:
            return stdout.read(MAX_TOOL_OUTPUT_BYTES + 1).decode("ascii")
        except UnicodeDecodeError:
            return ""


def _visible_window(shell_pid: int, home: str, xauthority: str) -> tuple[int, int] | None:
    search = _run_as_live_user(
        [
            "/usr/bin/xdotool",
            "search",
            "--onlyvisible",
            "--pid",
            str(shell_pid),
            "--name",
            WINDOW_TITLE_PATTERN,
        ],
        home,
        xauthority,
    )
    identifiers = [line for line in search.splitlines() if line.isdecimal()]
    if len(identifiers) != 1:
        return None
    geometry = _run_as_live_user(
        [
            "/usr/bin/xdotool",
            "getwindowgeometry",
            "--shell",
            identifiers[0],
        ],
        home,
        xauthority,
    )
    values = dict(
        match.groups()
        for line in geometry.splitlines()
        if (match := re.fullmatch(r"(WIDTH|HEIGHT)=([1-9][0-9]{0,4})", line))
    )
    if set(values) != {"WIDTH", "HEIGHT"}:
        return None
    width, height = int(values["WIDTH"]), int(values["HEIGHT"])
    if width < 640 or height < 480 or width > 8192 or height > 8192:
        return None
    return width, height


def attest() -> tuple[int, int]:
    shell_metadata = os.lstat(SHELL_PATH)
    if (
        not stat.S_ISREG(shell_metadata.st_mode)
        or shell_metadata.st_uid != 0
        or shell_metadata.st_gid != 0
        or shell_metadata.st_nlink != 1
        or stat.S_IMODE(shell_metadata.st_mode) != 0o755
    ):
        raise AttestationError("the shipping shell binary is unsafe")
    account = pwd.getpwnam("kernaid")
    if (
        account.pw_uid != 1000
        or account.pw_gid != 1000
        or account.pw_dir != "/home/kernaid"
    ):
        raise AttestationError("the live account identity is unsafe")
    deadline = time.monotonic() + PROBE_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        try:
            xauthority = _trusted_xauthority(account.pw_dir)
        except FileNotFoundError:
            time.sleep(0.5)
            continue
        shell_pid, renderer_ready = _shipping_process()
        if shell_pid and renderer_ready:
            window = _visible_window(shell_pid, account.pw_dir, xauthority)
            if window is not None and _default_display_is_active_xorg():
                return window
        time.sleep(0.5)
    raise AttestationError("the Tauri WebKit window did not become ready")


def main() -> int:
    try:
        width, height = attest()
    except (AttestationError, KeyError, OSError):
        print("KernAid Rescue Tauri UI attestation failed")
        return 1
    print(
        "KERNAID_RESCUE_TAURI_GUEST_V1 "
        "shell=shipping renderer=webkit2gtk-4.1 window=visible "
        f"display=active-xorg width={width} height={height}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
