#!/usr/bin/python3
"""Attest the shipping Rescue Tauri/WebKit window without exposing UI data."""

from __future__ import annotations

import errno
import grp
import contextlib
import os
import pwd
import re
import resource
import select
import signal
import socket
import stat
import subprocess
import tempfile
import time
from typing import NamedTuple


SHELL_UNIT = "kernaid-rescue-desk-shell.service"
SESSION_READY_UNIT = "kernaid-rescue-ui-session-ready.service"
SHELL_PATH = "/usr/bin/kernaid-rescue-desk-shell"
WINDOW_MANAGER_PATH = "/usr/bin/matchbox-window-manager"
XORG_PATH = "/usr/lib/xorg/Xorg"
LIGHTDM_PATH = "/usr/sbin/lightdm"
UI_ACCOUNT = "kernaid-rescue-ui"
UI_SHELL = "/usr/sbin/nologin"
UI_RUNTIME = "/run/kernaid-rescue-ui-session"
UI_HOME = f"{UI_RUNTIME}/home"
SHELL_RUNTIME = "/run/kernaid-rescue-desk-shell"
XAUTHORITY = "/run/lightdm/kernaid-rescue-ui/xauthority"
POLKIT_RULE_PATH = "/etc/polkit-1/rules.d/49-kernaid-observe.rules"
POLKIT_RULE = b'''polkit.addRule(function(action, subject) {
  if (subject.user == "kernaid-rescue-ui") {
    return polkit.Result.NO;
  }
  if (subject.user == "kernaid" && action.id.indexOf("org.freedesktop.udisks2.filesystem-mount") == 0) {
    return polkit.Result.NO;
  }
});
'''
FAKE_SESSION_BUS = "unix:path=/run/kernaid-rescue-desk-shell/no-session-bus"
FAKE_SYSTEM_BUS = "unix:path=/run/kernaid-rescue-desk-shell/no-system-bus"
ACTIVE_TTY_PATH = "/sys/class/tty/tty0/active"
SANDBOX_STATUS_QEMU = (
    "KERNAID_RESCUE_TAURI_SANDBOX_V1 identity=isolated pidns=private "
    "shell-bus=mount-masked session-bus=env-disabled-polkit-denied "
    "http=loopback x11=connected privileged-fs-sockets=absent "
    "nonloopback=denied"
)
SANDBOX_STATUS_NORMAL = (
    "KERNAID_RESCUE_TAURI_SANDBOX_V1 identity=isolated pidns=private "
    "shell-bus=mount-masked session-bus=env-disabled-polkit-denied "
    "http=loopback x11=connected privileged-fs-sockets=absent "
    "nonloopback=systemd-policy"
)
SANDBOX_FAILURE_PREFIX = "KERNAID_RESCUE_TAURI_SANDBOX_FAILURE_V1 stage="
SHELL_FAILURE_STAGES = {
    "http",
    "x11",
    "http-x11",
    "socket-offline-inspector",
    "socket-vault",
    "socket-openai-executor",
    "socket-openai-egress",
    "socket-codex",
    "system-bus",
    "probe-mode",
    "baseline",
    "nonloopback",
    "identity",
    "pidns",
    "session-bus",
    "notify",
    "window-startup",
}
GUEST_FAILURE_STAGES = SHELL_FAILURE_STAGES | {
    "service",
    "process-tree",
    "renderer",
    "window",
    "display",
    "xauthority",
    "run-view",
    "devices",
    "device-fds",
    "proc-alias",
    "endpoint-post",
}
QEMU_PROBE_MARKER_PATH = (
    "/sys/firmware/qemu_fw_cfg/by_name/opt/kernaid-tauri-sandbox-probe/raw"
)
QEMU_BASELINE_PATH = "/run/kernaid-tauri-network-probe/baseline-v1"
QEMU_BASELINE = b"KERNAID_RESCUE_TAURI_NETWORK_BASELINE_V1 connected=true\n"
QEMU_PROBE_ADDRESS = "192.0.2.1"
QEMU_PROBE_PORT = 41917
WEBKIT_ROOT = "/usr/lib/x86_64-linux-gnu/webkit2gtk-4.1"
WEBKIT_EXECUTABLES = {
    f"{WEBKIT_ROOT}/WebKitGPUProcess",
    f"{WEBKIT_ROOT}/WebKitNetworkProcess",
    f"{WEBKIT_ROOT}/WebKitWebProcess",
}
FORBIDDEN_UI_PROCESS_NAMES = {
    "chrome",
    "chromium",
    "chromium-browser",
    "lightdm-gtk-greeter",
    "slick-greeter",
    "xterm",
    "xfwm4",
    "xfce4-appfinder",
    "xfce4-panel",
    "xfce4-terminal",
}
PRIVILEGED_GROUPS = {
    "kernaid-vault",
    "kernaid-provider-client",
    "kernaid-codex-client",
    "kernaid-codex",
}
PRIVILEGED_SOCKET_ENDPOINTS = (
    (
        "/run/kernaid-offline-inspector.sock",
        "kernaid-offline-inspector.socket",
        "kernaid-inspect",
        0o660,
        "socket-offline-inspector",
    ),
    (
        "/run/kernaid-rescue-vault.sock",
        "kernaid-rescue-vaultd.socket",
        "kernaid-vault",
        0o660,
        "socket-vault",
    ),
    (
        "/run/kernaid-rescue-openai.sock",
        "kernaid-rescue-openai-executor.socket",
        "kernaid-provider-client",
        0o660,
        "socket-openai-executor",
    ),
    (
        "/run/kernaid-rescue-openai-egress.sock",
        "kernaid-rescue-openai-egress.socket",
        "kernaid-openai",
        0o660,
        "socket-openai-egress",
    ),
    (
        "/run/kernaid-rescue-codex.sock",
        "kernaid-rescue-codex.socket",
        "kernaid-codex-client",
        0o660,
        "socket-codex",
    ),
    (
        "/run/dbus/system_bus_socket",
        "dbus.socket",
        None,
        0o666,
        "system-bus",
    ),
)
FORBIDDEN_DEVICE_PATHS = (
    "/dev/input",
    "/dev/uinput",
    "/dev/dri",
    "/dev/disk",
    "/dev/mapper",
    "/dev/bsg",
    "/dev/kvm",
    "/dev/mem",
    "/dev/kmem",
    "/dev/port",
    "/dev/kmsg",
)
FORBIDDEN_DEVICE_NAME = re.compile(
    r"^(?:hidraw|video|fb|loop|sr)[0-9]+$"
    r"|^(?:sd|vd|xvd)[a-z][0-9]*$"
    r"|^nvme[0-9]+n[0-9]+(?:p[0-9]+)?$"
    r"|^dm-[0-9]+$"
)
WINDOW_TITLE_PATTERN = "^KernAid Rescue$"
DISPLAY = ":0"
DISPLAY_ZERO = {b":0", b":0.0", b"unix:0", b"unix:0.0"}
MAX_PROCESS_FILE_BYTES = 64 * 1024
MAX_PROCESSES = 4096
MAX_PRIVATE_PROCESSES = 32
MAX_PROCESS_ARGUMENTS = 256
MAX_FDS_PER_NATIVE_PROCESS = 256
MAX_NATIVE_FDS = 1024
MAX_TOOL_OUTPUT_BYTES = 4 * 1024
# The root attestor keeps a bounded 620-second window because WebKitGTK can
# initialize slowly under QEMU TCG.  The shell's systemd READY state attests
# only its completed sandbox preflight; this checker still requires the exact
# renderer, visible window and post-start endpoint proof.
PROBE_TIMEOUT_SECONDS = 620
TOOL_TIMEOUT_SECONDS = 3


class AttestationError(Exception):
    """A sanitized, fail-closed UI attestation error."""


class SandboxFailure(AttestationError):
    """An allowlisted Rescue shell or guest sandbox failure."""

    def __init__(self, stage: str) -> None:
        if stage not in GUEST_FAILURE_STAGES:
            raise AttestationError("the sandbox failure stage was invalid")
        super().__init__("the Rescue shell sandbox failed")
        self.stage = stage


class ProcessIdentity(NamedTuple):
    parent: int
    uids: tuple[int, int, int, int]
    gids: tuple[int, int, int, int]
    groups: frozenset[int]
    executable: str
    environment: dict[bytes, bytes]


def _bounded_file(path: str) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        payload = os.read(descriptor, MAX_PROCESS_FILE_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(payload) > MAX_PROCESS_FILE_BYTES:
        raise AttestationError("process metadata exceeded its bound")
    return payload


def _status_values(payload: bytes, prefix: bytes, count: int | None) -> tuple[int, ...]:
    line = next((line for line in payload.splitlines() if line.startswith(prefix)), None)
    if line is None:
        raise AttestationError("process identity metadata was incomplete")
    try:
        values = tuple(int(value) for value in line.removeprefix(prefix).split())
    except ValueError as error:
        raise AttestationError("process identity metadata was invalid") from error
    if count is not None and len(values) != count:
        raise AttestationError("process identity metadata was invalid")
    return values


def _environment(payload: bytes) -> dict[bytes, bytes]:
    values: dict[bytes, bytes] = {}
    for item in payload.rstrip(b"\0").split(b"\0") if payload else ():
        if b"=" not in item:
            raise AttestationError("process environment metadata was invalid")
        name, value = item.split(b"=", 1)
        if name in values:
            raise AttestationError("process environment metadata was invalid")
        values[name] = value
    return values


def _process_identity(
    pid: int,
    environment_uids: frozenset[int],
    environment_gids: frozenset[int],
    environment_names: frozenset[str],
) -> ProcessIdentity | None:
    try:
        stat_payload = _bounded_file(f"/proc/{pid}/stat")
        status_payload = _bounded_file(f"/proc/{pid}/status")
        executable = os.readlink(f"/proc/{pid}/exe")
    except (FileNotFoundError, ProcessLookupError):
        return None
    except PermissionError as error:
        raise AttestationError("process identity access was denied") from error
    close_parenthesis = stat_payload.rfind(b") ")
    if close_parenthesis < 0:
        raise AttestationError("process relationship metadata was invalid")
    fields = stat_payload[close_parenthesis + 2 :].split()
    if len(fields) < 2:
        raise AttestationError("process relationship metadata was invalid")
    try:
        parent_pid = int(fields[1])
    except ValueError as error:
        raise AttestationError("process relationship metadata was invalid") from error
    uids = _status_values(status_payload, b"Uid:\t", 4)
    gids = _status_values(status_payload, b"Gid:\t", 4)
    groups = frozenset(_status_values(status_payload, b"Groups:", None))
    environment = {}
    if environment_uids.intersection(uids) or environment_gids.intersection(
        groups | frozenset(gids)
    ) or os.path.basename(executable) in environment_names:
        try:
            environment = _environment(_bounded_file(f"/proc/{pid}/environ"))
        except (FileNotFoundError, ProcessLookupError):
            return None
    return ProcessIdentity(parent_pid, uids, gids, groups, executable, environment)


def _processes(
    environment_uids: frozenset[int] = frozenset(),
    environment_gids: frozenset[int] = frozenset(),
    environment_names: frozenset[str] = frozenset(),
) -> dict[int, ProcessIdentity]:
    snapshot: dict[int, ProcessIdentity] = {}
    numeric_entries = 0
    with os.scandir("/proc") as entries:
        for entry in entries:
            if not entry.name.isascii() or not entry.name.isdecimal():
                continue
            numeric_entries += 1
            if numeric_entries > MAX_PROCESSES:
                raise AttestationError("the process table exceeded its bound")
            identity = _process_identity(
                int(entry.name), environment_uids, environment_gids, environment_names
            )
            if identity is not None:
                snapshot[int(entry.name)] = identity
    return snapshot


def _descends_from(pid: int, ancestor: int, processes: dict[int, ProcessIdentity]) -> bool:
    visited: set[int] = set()
    current = pid
    for _ in range(16):
        if current == ancestor:
            return True
        if current <= 1 or current in visited or current not in processes:
            return False
        visited.add(current)
        current = processes[current].parent
    return False


def _account() -> tuple[pwd.struct_passwd, pwd.struct_passwd]:
    ui = pwd.getpwnam(UI_ACCOUNT)
    live = pwd.getpwnam("kernaid")
    ui_group = grp.getgrgid(ui.pw_gid)
    if (
        ui.pw_uid in (0, 1000)
        or ui.pw_gid in (0, 1000)
        or ui.pw_dir != UI_HOME
        or ui.pw_shell != UI_SHELL
        or ui_group.gr_name != UI_ACCOUNT
        or ui_group.gr_mem
        or set(os.getgrouplist(UI_ACCOUNT, ui.pw_gid)) != {ui.pw_gid}
        or live.pw_uid != 1000
        or live.pw_gid != 1000
        or live.pw_dir != "/home/kernaid"
    ):
        raise SandboxFailure("identity")
    return ui, live


def _shipping_process(
    ui: pwd.struct_passwd, expected_main_pid: int
) -> tuple[int, int, dict[int, ProcessIdentity]]:
    privileged_gids = {grp.getgrnam(name).gr_gid for name in PRIVILEGED_GROUPS}
    lightdm_uid = pwd.getpwnam("lightdm").pw_uid
    processes = _processes(
        frozenset({ui.pw_uid, 1000, lightdm_uid}),
        frozenset(privileged_gids),
        frozenset(FORBIDDEN_UI_PROCESS_NAMES | {"lightdm", "Xorg"}),
    )
    ui_uids = (ui.pw_uid,) * 4
    ui_gids = (ui.pw_gid,) * 4
    for identity in processes.values():
        if os.path.basename(identity.executable).lower() in FORBIDDEN_UI_PROCESS_NAMES:
            raise SandboxFailure("process-tree")
        display_access = (
            identity.environment.get(b"DISPLAY") in DISPLAY_ZERO
            or identity.environment.get(b"XAUTHORITY") == XAUTHORITY.encode("ascii")
        )
        if display_access and ui.pw_uid not in identity.uids:
            raise SandboxFailure("identity")
        if ui.pw_uid in identity.uids and (
            identity.uids != ui_uids
            or identity.gids != ui_gids
            or not identity.groups.issubset({ui.pw_gid})
        ):
            raise SandboxFailure("identity")
    shells = [
        pid
        for pid, identity in processes.items()
        if identity.executable == SHELL_PATH and identity.uids == ui_uids
    ]
    window_managers = [
        pid
        for pid, identity in processes.items()
        if (
            identity.executable == WINDOW_MANAGER_PATH
            and identity.uids == ui_uids
        )
    ]
    if (
        len(shells) != 1
        or shells[0] != expected_main_pid
        or len(window_managers) != 1
    ):
        return 0, 0, {}
    shell_pid = shells[0]
    window_manager_pid = window_managers[0]
    renderer = False
    native_processes: dict[int, ProcessIdentity] = {}
    ui_processes = 0
    for pid, identity in processes.items():
        if identity.uids != ui_uids:
            continue
        ui_processes += 1
        if ui_processes > MAX_PRIVATE_PROCESSES + 1:
            raise SandboxFailure("process-tree")
        if pid == window_manager_pid:
            if (
                identity.environment.get(b"DISPLAY") != DISPLAY.encode("ascii")
                or identity.environment.get(b"XAUTHORITY")
                != XAUTHORITY.encode("ascii")
                or identity.environment.get(b"XDG_RUNTIME_DIR")
                != UI_RUNTIME.encode("ascii")
                or identity.environment.get(b"HOME")
                != f"{UI_RUNTIME}/home".encode("ascii")
                or identity.environment.get(b"DBUS_SESSION_BUS_ADDRESS")
                != f"unix:path={UI_RUNTIME}/no-session-bus".encode("ascii")
                or identity.environment.get(b"DBUS_SYSTEM_BUS_ADDRESS")
                != f"unix:path={UI_RUNTIME}/no-system-bus".encode("ascii")
            ):
                raise SandboxFailure("session-bus")
            continue
        if identity.executable not in WEBKIT_EXECUTABLES | {SHELL_PATH} or not _descends_from(
            pid, shell_pid, processes
        ):
            raise SandboxFailure("process-tree")
        native_processes[pid] = identity
        if (
            identity.environment.get(b"DISPLAY") != DISPLAY.encode("ascii")
            or identity.environment.get(b"XAUTHORITY")
            != XAUTHORITY.encode("ascii")
            or identity.environment.get(b"XDG_RUNTIME_DIR")
            != SHELL_RUNTIME.encode("ascii")
            or identity.environment.get(b"DBUS_SESSION_BUS_ADDRESS")
            != FAKE_SESSION_BUS.encode("ascii")
            or identity.environment.get(b"DBUS_SYSTEM_BUS_ADDRESS")
            != FAKE_SYSTEM_BUS.encode("ascii")
        ):
            raise SandboxFailure("session-bus")
        if identity.executable == f"{WEBKIT_ROOT}/WebKitWebProcess":
            renderer = True
    return shell_pid, window_manager_pid, native_processes if renderer else {}


def _safe_native_character_device(metadata: os.stat_result) -> bool:
    major = os.major(metadata.st_rdev)
    minor = os.minor(metadata.st_rdev)
    return major == 1 and minor in {3, 5, 7, 8, 9}


def _privileged_device_fds_absent(
    native_processes: dict[int, ProcessIdentity], ui: pwd.struct_passwd
) -> bool | None:
    if not native_processes:
        return None
    total_descriptors = 0
    for pid, expected_identity in native_processes.items():
        try:
            with os.scandir(f"/proc/{pid}/fd") as entries:
                descriptors = [
                    entry
                    for entry in entries
                    if entry.name.isascii() and entry.name.isdecimal()
                ]
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            return None
        if not 0 < len(descriptors) <= MAX_FDS_PER_NATIVE_PROCESS:
            return False
        total_descriptors += len(descriptors)
        if total_descriptors > MAX_NATIVE_FDS:
            return False
        for descriptor in descriptors:
            try:
                metadata = os.stat(descriptor.path, follow_symlinks=True)
            except (FileNotFoundError, ProcessLookupError, PermissionError):
                return None
            if stat.S_ISBLK(metadata.st_mode) or (
                stat.S_ISCHR(metadata.st_mode)
                and not _safe_native_character_device(metadata)
            ):
                return False
        rebound = _process_identity(
            pid,
            frozenset({ui.pw_uid}),
            frozenset(),
            frozenset(
                os.path.basename(executable)
                for executable in WEBKIT_EXECUTABLES | {SHELL_PATH}
            ),
        )
        if rebound is None or rebound != expected_identity:
            return None
    rebound_processes = _processes(
        frozenset({ui.pw_uid}),
        frozenset(),
        frozenset(
            os.path.basename(executable)
            for executable in WEBKIT_EXECUTABLES
            | {SHELL_PATH, WINDOW_MANAGER_PATH}
        ),
    )
    rebound_native = {
        pid: identity
        for pid, identity in rebound_processes.items()
        if ui.pw_uid in identity.uids
        and identity.executable != WINDOW_MANAGER_PATH
    }
    if rebound_native != native_processes:
        return None
    return True


def _active_vt_from_payload(payload: bytes) -> int:
    match = re.fullmatch(rb"tty([1-9]|[1-5][0-9]|6[0-3])\n?", payload)
    if match is None:
        raise SandboxFailure("display")
    return int(match.group(1))


def _xorg_launch_from_cmdline(payload: bytes) -> tuple[int, str] | None:
    if not payload or not payload.endswith(b"\0"):
        raise SandboxFailure("display")
    arguments = payload[:-1].split(b"\0")
    if not arguments or len(arguments) > MAX_PROCESS_ARGUMENTS or b"" in arguments:
        raise SandboxFailure("display")
    if arguments.count(DISPLAY.encode("ascii")) != 1:
        return None
    vt_arguments = [
        match
        for argument in arguments
        if (match := re.fullmatch(rb"vt([1-9]|[1-5][0-9]|6[0-3])", argument))
    ]
    if len(vt_arguments) != 1:
        return None
    auth_indices = [index for index, value in enumerate(arguments) if value == b"-auth"]
    if len(auth_indices) != 1 or auth_indices[0] + 1 >= len(arguments):
        return None
    try:
        auth_path = arguments[auth_indices[0] + 1].decode("ascii")
    except UnicodeDecodeError:
        return None
    if auth_path not in ("/run/lightdm/root/:0", "/var/run/lightdm/root/:0"):
        return None
    nolisten = [
        index for index, value in enumerate(arguments) if value == b"-nolisten"
    ]
    if (
        len(nolisten) != 1
        or nolisten[0] + 1 >= len(arguments)
        or arguments[nolisten[0] + 1] != b"tcp"
        or b"-listen" in arguments
    ):
        return None
    extension_indices = [
        index for index, value in enumerate(arguments) if value == b"-extension"
    ]
    if (
        len(extension_indices) != 3
        or any(index + 1 >= len(arguments) for index in extension_indices)
        or {arguments[index + 1] for index in extension_indices}
        != {b"DRI2", b"DRI3", b"XTEST"}
        or b"+extension" in arguments
    ):
        return None
    return int(vt_arguments[0].group(1)), auth_path


def _xorg_vt_from_cmdline(payload: bytes) -> int | None:
    launch = _xorg_launch_from_cmdline(payload)
    return None if launch is None else launch[0]


def _xorg_authority_ready(path: str) -> bool:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError:
        return False
    try:
        metadata = os.fstat(descriptor)
        payload = os.read(descriptor, MAX_PROCESS_FILE_BYTES + 1)
    finally:
        os.close(descriptor)
    return (
        stat.S_ISREG(metadata.st_mode)
        and metadata.st_uid == 0
        and metadata.st_gid == 0
        and metadata.st_nlink == 1
        and stat.S_IMODE(metadata.st_mode) == 0o600
        and 0 < metadata.st_size <= MAX_PROCESS_FILE_BYTES
        and len(payload) == metadata.st_size
    )


def _default_display_is_active_xorg() -> bool:
    active_vt = _active_vt_from_payload(_bounded_file(ACTIVE_TTY_PATH))
    processes = _processes()
    xorg_pids = [
        pid for pid, identity in processes.items() if identity.executable == XORG_PATH
    ]
    if len(xorg_pids) > 1:
        raise SandboxFailure("display")
    if not xorg_pids:
        return False
    xorg_pid = xorg_pids[0]
    identity = processes[xorg_pid]
    parent = processes.get(identity.parent)
    if (
        identity.uids != (0, 0, 0, 0)
        or identity.gids != (0, 0, 0, 0)
        or not identity.groups.issubset({0})
        or parent is None
        or parent.executable != LIGHTDM_PATH
        or parent.uids != (0, 0, 0, 0)
        or parent.gids != (0, 0, 0, 0)
        or not parent.groups.issubset({0})
    ):
        raise SandboxFailure("display")
    try:
        launch = _xorg_launch_from_cmdline(_bounded_file(f"/proc/{xorg_pid}/cmdline"))
    except (FileNotFoundError, ProcessLookupError):
        return False
    return (
        launch is not None
        and launch[0] == active_vt
        and _xorg_authority_ready(launch[1])
    )


def _fixed_file(path: str, expected: bytes, uid: int, gid: int, mode: int) -> bool:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(descriptor)
        payload = os.read(descriptor, len(expected) + 1)
    finally:
        os.close(descriptor)
    return (
        stat.S_ISREG(metadata.st_mode)
        and metadata.st_uid == uid
        and metadata.st_gid == gid
        and metadata.st_nlink == 1
        and stat.S_IMODE(metadata.st_mode) == mode
        and metadata.st_size == len(expected)
        and payload == expected
    )


def _qemu_probe_mode(path: str = QEMU_PROBE_MARKER_PATH) -> bool:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except FileNotFoundError:
        return False
    try:
        metadata = os.fstat(descriptor)
        payload = os.read(descriptor, 4)
    finally:
        os.close(descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) & 0o222
        or metadata.st_size not in (0, 2, 3)
        or payload not in (b"v1", b"v1\0")
    ):
        raise SandboxFailure("probe-mode")
    return True


def _qemu_endpoint_post_ready() -> bool:
    try:
        connection = socket.create_connection((QEMU_PROBE_ADDRESS, QEMU_PROBE_PORT), 2)
    except OSError:
        return False
    connection.close()
    return True


def _systemctl_show(unit: str, properties: tuple[str, ...]) -> dict[str, str] | None:
    command = [
        "/usr/bin/systemctl",
        "show",
        unit,
        *(f"--property={name}" for name in properties),
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
            return None
        if (
            result.returncode != 0
            or os.fstat(stdout.fileno()).st_size > MAX_TOOL_OUTPUT_BYTES
            or os.fstat(stderr.fileno()).st_size > MAX_TOOL_OUTPUT_BYTES
        ):
            return None
        stdout.seek(0)
        try:
            lines = stdout.read(MAX_TOOL_OUTPUT_BYTES + 1).decode("ascii").splitlines()
        except UnicodeDecodeError as error:
            raise SandboxFailure("service") from error
    values: dict[str, str] = {}
    for line in lines:
        if "=" not in line:
            raise SandboxFailure("service")
        name, value = line.split("=", 1)
        if name not in properties or name in values:
            raise SandboxFailure("service")
        values[name] = value
    if set(values) != set(properties):
        raise SandboxFailure("service")
    return values


def _host_privileged_sockets_ready() -> None:
    for path, unit, group_name, mode, failure_stage in PRIVILEGED_SOCKET_ENDPOINTS:
        values = _systemctl_show(unit, ("ActiveState", "SubState", "Result"))
        if (
            values is None
            or values.get("ActiveState") != "active"
            or values.get("SubState") not in {"listening", "running"}
            or values.get("Result") != "success"
        ):
            raise SandboxFailure(failure_stage)
        try:
            expected_gid = 0 if group_name is None else grp.getgrnam(group_name).gr_gid
            metadata = os.lstat(path)
        except (KeyError, OSError) as error:
            raise SandboxFailure(failure_stage) from error
        if (
            not stat.S_ISSOCK(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_gid != expected_gid
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != mode
        ):
            raise SandboxFailure(failure_stage)


def _shell_service_ready(_qemu_probe: bool) -> int:
    properties = (
        "ActiveState",
        "SubState",
        "MainPID",
        "User",
        "Group",
        "Type",
        "PrivateDevices",
        "DevicePolicy",
    )
    values = _systemctl_show(SHELL_UNIT, properties)
    if values is None:
        return 0
    if (
        values["ActiveState"] != "active"
        or values["SubState"] != "running"
        or values["User"] != UI_ACCOUNT
        or values["Group"] != UI_ACCOUNT
        or values["Type"] != "exec"
        or values["PrivateDevices"] != "yes"
        or values["DevicePolicy"] != "closed"
        or not values["MainPID"].isdecimal()
        or int(values["MainPID"]) <= 1
    ):
        return 0
    ready = _systemctl_show(
        SESSION_READY_UNIT, ("ActiveState", "SubState", "Result")
    )
    if ready != {"ActiveState": "active", "SubState": "exited", "Result": "success"}:
        raise SandboxFailure("service")
    return int(values["MainPID"])


def _valid_xauthority_payload(payload: bytes) -> bool:
    records: list[tuple[int, bytes, bytes, bytes, bytes]] = []
    offset = 0

    def take(length: int) -> bytes:
        nonlocal offset
        end = offset + length
        if end > len(payload):
            raise ValueError
        value = payload[offset:end]
        offset = end
        return value

    def field() -> bytes:
        return take(int.from_bytes(take(2), "big"))

    try:
        while offset < len(payload):
            records.append((int.from_bytes(take(2), "big"), field(), field(), field(), field()))
            if len(records) > 4:
                return False
    except ValueError:
        return False
    if not records or not any(family == 256 for family, *_ in records):
        return False
    cookies = set()
    for family, address, number, name, cookie in records:
        if (
            family not in (0, 6, 256)
            or not 0 < len(address) <= 255
            or any(byte < 0x21 or byte > 0x7E for byte in address)
            or number != b"0"
            or name != b"MIT-MAGIC-COOKIE-1"
            or len(cookie) != 16
            or not any(cookie)
        ):
            return False
        cookies.add(cookie)
    return len(cookies) == 1


def _trusted_xauthority(ui: pwd.struct_passwd) -> bytes:
    descriptor = os.open(XAUTHORITY, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(descriptor)
        payload = os.read(descriptor, MAX_PROCESS_FILE_BYTES + 1)
    finally:
        os.close(descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != ui.pw_uid
        or metadata.st_gid != ui.pw_gid
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or not 0 < metadata.st_size <= MAX_PROCESS_FILE_BYTES
        or len(payload) != metadata.st_size
        or not _valid_xauthority_payload(payload)
    ):
        raise SandboxFailure("xauthority")
    return payload


@contextlib.contextmanager
def _pinned_xauthority(ui: pwd.struct_passwd, payload: bytes):
    directory_path = tempfile.mkdtemp(prefix="kernaid-xauth-", dir="/run")
    directory = os.open(
        directory_path,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    try:
        os.fchown(directory, 0, ui.pw_gid)
        os.fchmod(directory, 0o710)
        authority = os.open(
            "xauthority",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o400,
            dir_fd=directory,
        )
        try:
            offset = 0
            while offset < len(payload):
                written = os.write(authority, payload[offset:])
                if written <= 0:
                    raise SandboxFailure("xauthority")
                offset += written
            os.fchown(authority, 0, ui.pw_gid)
            os.fchmod(authority, 0o440)
            os.fsync(authority)
            metadata = os.fstat(authority)
            if (
                metadata.st_uid != 0
                or metadata.st_gid != ui.pw_gid
                or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) != 0o440
                or metadata.st_size != len(payload)
            ):
                raise SandboxFailure("xauthority")
        finally:
            os.close(authority)
        yield f"{directory_path}/xauthority"
    finally:
        try:
            os.unlink("xauthority", dir_fd=directory)
        except FileNotFoundError:
            pass
        os.close(directory)
        os.rmdir(directory_path)


def _limit_tool_output() -> None:
    resource.setrlimit(
        resource.RLIMIT_FSIZE,
        (MAX_TOOL_OUTPUT_BYTES, MAX_TOOL_OUTPUT_BYTES),
    )


def _run_as_ui(arguments: list[str], ui: pwd.struct_passwd, xauthority: str) -> str:
    command = [
        "/usr/sbin/runuser",
        "--user",
        UI_ACCOUNT,
        "--",
        "/usr/bin/env",
        "-i",
        f"HOME={UI_RUNTIME}/home",
        f"DISPLAY={DISPLAY}",
        f"XAUTHORITY={xauthority}",
        f"XDG_RUNTIME_DIR={UI_RUNTIME}",
        f"DBUS_SESSION_BUS_ADDRESS={FAKE_SESSION_BUS}",
        f"DBUS_SYSTEM_BUS_ADDRESS={FAKE_SYSTEM_BUS}",
        "NO_AT_BRIDGE=1",
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


def _live_user_x11_denied(live: pwd.struct_passwd, xauthority: str) -> bool:
    command = [
        "/usr/sbin/runuser",
        "--user",
        "kernaid",
        "--",
        "/usr/bin/env",
        "-i",
        f"HOME={live.pw_dir}",
        f"DISPLAY={DISPLAY}",
        f"XAUTHORITY={xauthority}",
        "/usr/bin/xdotool",
        "getdisplaygeometry",
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
            return False
        return (
            result.returncode == 1
            and os.fstat(stdout.fileno()).st_size <= MAX_TOOL_OUTPUT_BYTES
            and os.fstat(stderr.fileno()).st_size <= MAX_TOOL_OUTPUT_BYTES
        )


def _visible_window(shell_pid: int, ui: pwd.struct_passwd, xauthority: str) -> tuple[int, int] | None:
    search = _run_as_ui(
        [
            "/usr/bin/xdotool",
            "search",
            "--onlyvisible",
            "--name",
            WINDOW_TITLE_PATTERN,
        ],
        ui,
        xauthority,
    )
    identifiers = [line for line in search.splitlines() if line.isdecimal()]
    if len(identifiers) != 1:
        return None
    # The Tauri parent is PID 1 inside PrivatePIDs, even though systemd exposes
    # its distinct host MainPID.  GTK therefore publishes exact inner PID 1 in
    # _NET_WM_PID; the host PID is bound separately through systemd and /proc.
    window_pid = _run_as_ui(
        ["/usr/bin/xdotool", "getwindowpid", identifiers[0]], ui, xauthority
    )
    if window_pid != "1\n":
        return None
    geometry = _run_as_ui(
        [
            "/usr/bin/xdotool",
            "getwindowgeometry",
            "--shell",
            identifiers[0],
        ],
        ui,
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


def _drop_identity_probe(uid: int, gid: int, probe: object) -> bool:
    read_descriptor, write_descriptor = os.pipe2(os.O_CLOEXEC)
    child = os.fork()
    if child == 0:
        os.close(read_descriptor)
        result = False
        try:
            os.setgroups([])
            os.setresgid(gid, gid, gid)
            os.setresuid(uid, uid, uid)
            result = (
                os.getresuid() == (uid, uid, uid)
                and os.getresgid() == (gid, gid, gid)
                and not os.getgroups()
                and bool(probe())  # type: ignore[operator]
            )
        except BaseException:
            result = False
        try:
            os.write(write_descriptor, b"1" if result else b"0")
        finally:
            os._exit(0)
    os.close(write_descriptor)
    try:
        readable, _, _ = select.select([read_descriptor], [], [], TOOL_TIMEOUT_SECONDS)
        if not readable:
            os.kill(child, signal.SIGKILL)
            os.waitpid(child, 0)
            return False
        payload = os.read(read_descriptor, 2)
        _, status_value = os.waitpid(child, 0)
        return payload == b"1" and os.waitstatus_to_exitcode(status_value) == 0
    finally:
        os.close(read_descriptor)


def _open_denied(path: str) -> bool:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError as error:
        return error.errno in (errno.EACCES, errno.EPERM)
    os.close(descriptor)
    return False


def _path_absent(path: str) -> bool:
    try:
        os.lstat(path)
    except FileNotFoundError:
        return True
    except OSError:
        return False
    return False


def _private_pid_namespace_aliases(
    shell_pid: int, window_manager_pid: int
) -> list[str] | None:
    try:
        if os.stat(f"/proc/{shell_pid}/ns/pid").st_ino == os.stat("/proc/1/ns/pid").st_ino:
            return None
        nspid = _status_values(
            _bounded_file(f"/proc/{shell_pid}/status"), b"NSpid:", None
        )
        if len(nspid) < 2 or nspid[0] != shell_pid or nspid[-1] != 1:
            return None
        private_proc = f"/proc/{shell_pid}/root/proc"
        entries = [
            entry.name
            for entry in os.scandir(private_proc)
            if entry.name.isascii() and entry.name.isdecimal()
        ]
        if not 2 <= len(entries) <= MAX_PRIVATE_PROCESSES or "1" not in entries:
            return None
        if os.path.lexists(f"{private_proc}/{window_manager_pid}"):
            return None
        return [f"/proc/{shell_pid}/root"] + [
            f"{private_proc}/{inner_pid}/root" for inner_pid in entries
        ]
    except (AttestationError, OSError):
        return None


def _proc_aliases_absent(
    shell_pid: int, aliases: list[str], ui: pwd.struct_passwd
) -> bool:
    absent_paths = tuple(path for path, *_rest in PRIVILEGED_SOCKET_ENDPOINTS) + (
        f"/run/user/{ui.pw_uid}",
    )
    try:
        if not all(
            _path_absent(f"{alias}{path}")
            for alias in aliases
            for path in absent_paths
        ):
            return False
        return _drop_identity_probe(
            ui.pw_uid,
            ui.pw_gid,
            lambda: all(
                _open_absent(f"/proc/{shell_pid}/root{path}")
                for path in absent_paths
            ),
        )
    except (AttestationError, OSError):
        return False


def _private_run_ready(shell_pid: int, ui: pwd.struct_passwd, qemu_probe: bool) -> bool:
    root = f"/proc/{shell_pid}/root"
    required_socket_paths: set[str] = set()
    observed_sockets: set[str] = set()
    entries_seen = 0
    try:
        for current, directories, files in os.walk(f"{root}/run", followlinks=False):
            entries_seen += len(directories) + len(files)
            if entries_seen > 64:
                return False
            for name in directories + files:
                candidate = os.path.join(current, name)
                metadata = os.lstat(candidate)
                if stat.S_ISLNK(metadata.st_mode):
                    return False
                if stat.S_ISSOCK(metadata.st_mode):
                    observed_sockets.add(candidate.removeprefix(root))
        if observed_sockets != required_socket_paths:
            return False
        forbidden = (
            "/run/user/{uid}",
            "/run/user/{uid}/bus",
            "/run/user/{uid}/systemd/private",
            "/run/udev/control",
            "/run/systemd/notify",
            "/run/systemd/private",
            "/run/systemd/journal/socket",
            "/run/systemd/journal/stdout",
        )
        if any(os.path.lexists(f"{root}{path.format(uid=ui.pw_uid)}") for path in forbidden):
            return False
        runtime = os.lstat(f"{root}{SHELL_RUNTIME}")
        if (
            not stat.S_ISDIR(runtime.st_mode)
            or runtime.st_uid != ui.pw_uid
            or runtime.st_gid != ui.pw_gid
            or stat.S_IMODE(runtime.st_mode) != 0o700
        ):
            return False
        if qemu_probe:
            if not _fixed_file(
                f"{root}{QEMU_BASELINE_PATH}", QEMU_BASELINE, 0, 0, 0o444
            ):
                return False
        elif os.path.lexists(f"{root}{QEMU_BASELINE_PATH}"):
            return False
    except OSError:
        return False
    return True


def _private_tmp_ready(shell_pid: int) -> bool:
    root = f"/proc/{shell_pid}/root"
    expected = "/tmp/.X11-unix/X0"
    observed_sockets: set[str] = set()
    entries_seen = 0
    try:
        for current, directories, files in os.walk(f"{root}/tmp", followlinks=False):
            entries_seen += len(directories) + len(files)
            if entries_seen > 64:
                return False
            for name in directories + files:
                candidate = os.path.join(current, name)
                metadata = os.lstat(candidate)
                if stat.S_ISLNK(metadata.st_mode):
                    return False
                if stat.S_ISSOCK(metadata.st_mode):
                    observed_sockets.add(candidate.removeprefix(root))
        metadata = os.lstat(f"{root}{expected}")
    except OSError:
        return False
    return (
        observed_sockets == {expected}
        and stat.S_ISSOCK(metadata.st_mode)
        and metadata.st_uid == 0
        and metadata.st_gid == 0
        and metadata.st_nlink == 1
        and stat.S_IMODE(metadata.st_mode) == 0o777
    )


def _open_absent(path: str) -> bool:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError as error:
        return error.errno in (errno.ENOENT, errno.ENOTDIR)
    os.close(descriptor)
    return False


def _private_devices_ready(shell_pid: int, ui: pwd.struct_passwd) -> bool:
    root = f"/proc/{shell_pid}/root"
    entries_seen = 0
    try:
        metadata = os.lstat(f"{root}/dev")
        if not stat.S_ISDIR(metadata.st_mode):
            return False
        for current, directories, files in os.walk(
            f"{root}/dev", followlinks=False
        ):
            entries_seen += len(directories) + len(files)
            if entries_seen > 128:
                return False
            relative_directory = current.removeprefix(f"{root}/dev").lstrip("/")
            if relative_directory.split("/", 1)[0] in {
                "input",
                "dri",
                "disk",
                "mapper",
                "bsg",
            }:
                return False
            for name in directories + files:
                entry = os.lstat(os.path.join(current, name))
                if stat.S_ISBLK(entry.st_mode) or FORBIDDEN_DEVICE_NAME.fullmatch(
                    name
                ):
                    return False
        if any(os.path.lexists(f"{root}{path}") for path in FORBIDDEN_DEVICE_PATHS):
            return False
        return _drop_identity_probe(
            ui.pw_uid,
            ui.pw_gid,
            lambda: all(
                _open_absent(f"/proc/{shell_pid}/root{path}")
                for path in FORBIDDEN_DEVICE_PATHS
            ),
        )
    except OSError:
        return False


def attest() -> tuple[int, int, bool]:
    shell_metadata = os.lstat(SHELL_PATH)
    if (
        not stat.S_ISREG(shell_metadata.st_mode)
        or shell_metadata.st_uid != 0
        or shell_metadata.st_gid != 0
        or shell_metadata.st_nlink != 1
        or stat.S_IMODE(shell_metadata.st_mode) != 0o755
    ):
        raise SandboxFailure("identity")
    ui, live = _account()
    try:
        polkit_ready = _fixed_file(POLKIT_RULE_PATH, POLKIT_RULE, 0, 0, 0o644)
    except OSError:
        polkit_ready = False
    if not polkit_ready:
        raise SandboxFailure("system-bus")
    qemu_probe = _qemu_probe_mode()
    last_stage = "service"
    deadline = time.monotonic() + PROBE_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        shell_pid = _shell_service_ready(qemu_probe)
        if not shell_pid:
            last_stage = "service"
            time.sleep(0.5)
            continue
        _host_privileged_sockets_ready()
        try:
            xauthority_payload = _trusted_xauthority(ui)
        except FileNotFoundError:
            last_stage = "xauthority"
            time.sleep(0.5)
            continue
        if not _drop_identity_probe(
            live.pw_uid, live.pw_gid, lambda: _open_denied(XAUTHORITY)
        ):
            raise SandboxFailure("xauthority")
        shell_pid, window_manager_pid, native_processes = _shipping_process(
            ui, shell_pid
        )
        if not shell_pid:
            last_stage = "process-tree"
            time.sleep(0.5)
            continue
        if not native_processes:
            last_stage = "renderer"
            time.sleep(0.5)
            continue
        device_fds_ready = _privileged_device_fds_absent(native_processes, ui)
        if device_fds_ready is None:
            last_stage = "device-fds"
            time.sleep(0.5)
            continue
        if not device_fds_ready:
            raise SandboxFailure("device-fds")
        aliases = _private_pid_namespace_aliases(shell_pid, window_manager_pid)
        if aliases is None:
            raise SandboxFailure("pidns")
        if not _proc_aliases_absent(shell_pid, aliases, ui):
            raise SandboxFailure("proc-alias")
        if not _private_run_ready(shell_pid, ui, qemu_probe):
            raise SandboxFailure("run-view")
        if not _private_tmp_ready(shell_pid):
            raise SandboxFailure("run-view")
        if not _private_devices_ready(shell_pid, ui):
            raise SandboxFailure("devices")
        with _pinned_xauthority(ui, xauthority_payload) as xauthority:
            if not _live_user_x11_denied(live, xauthority):
                raise SandboxFailure("xauthority")
            window = _visible_window(shell_pid, ui, xauthority)
        if window is None:
            last_stage = "window"
            time.sleep(0.5)
            continue
        if not _default_display_is_active_xorg():
            last_stage = "display"
            time.sleep(0.5)
            continue
        if qemu_probe and not _qemu_endpoint_post_ready():
            last_stage = "endpoint-post"
            time.sleep(0.5)
            continue
        return *window, qemu_probe
    raise SandboxFailure(last_stage)


def main() -> int:
    try:
        width, height, qemu_probe = attest()
    except SandboxFailure as error:
        print(f"KERNAID_RESCUE_TAURI_GUEST_FAILURE_V1 stage={error.stage}")
        return 1
    except (AttestationError, KeyError, OSError):
        print("KERNAID_RESCUE_TAURI_GUEST_FAILURE_V1 stage=service")
        return 1
    print(
        "KERNAID_RESCUE_TAURI_GUEST_V1 "
        "identity=isolated pidns=private shell-bus=mount-masked "
        "session-bus=env-disabled-polkit-denied "
        "fs-sockets=allowlisted abstract-unix=not-attested "
        "devices=private device-fds=no-privileged "
        "shell=shipping renderer=webkit2gtk-4.1 window=visible "
        "display=active-xorg http=loopback x11=connected "
        "privileged-fs-sockets=absent "
        f"nonloopback={'denied' if qemu_probe else 'systemd-policy'} "
        f"width={width} height={height}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
