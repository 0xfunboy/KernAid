#!/usr/bin/python3
"""Fail closed until the isolated LightDM Rescue UI session is ready."""

from __future__ import annotations

import grp
import os
import pwd
import stat
import time


UI_ACCOUNT = "kernaid-rescue-ui"
UI_HOME = "/nonexistent"
UI_SHELL = "/usr/sbin/nologin"
UI_RUNTIME = "/run/kernaid-rescue-ui-session"
XAUTHORITY = "/run/lightdm/kernaid-rescue-ui/xauthority"
XFWM_PATH = "/usr/bin/xfwm4"
DISPLAY = b":0"
DISPLAY_ZERO = {b":0", b":0.0", b"unix:0", b"unix:0.0"}
MAX_FILE_BYTES = 64 * 1024
MAX_PROCESSES = 4096
# QEMU's TCG BIOS path can spend most of systemd's historical 90-second
# default start timeout bringing up Xorg and LightDM.  Keep this gate bounded,
# but give the real graphical session (rather than runner speed) the deadline.
READY_TIMEOUT_SECONDS = 240
PRIVILEGED_GROUPS = (
    "kernaid-vault",
    "kernaid-provider-client",
    "kernaid-codex-client",
    "kernaid-codex",
)
FORBIDDEN_UI_PROCESS_NAMES = {
    "chrome",
    "chromium",
    "chromium-browser",
    "lightdm-gtk-greeter",
    "slick-greeter",
    "xterm",
    "xfce4-appfinder",
    "xfce4-panel",
    "xfce4-terminal",
}
SESSION_FAILURE_STAGES = frozenset(
    {
        "account",
        "user-runtime-mask",
        "xauthority",
        "runtime",
        "process",
        "timeout",
        "internal",
    }
)
SESSION_FAILURE_PREFIX = "KERNAID_RESCUE_UI_SESSION_FAILURE_V1 stage="


class SessionError(Exception):
    """A sanitized UI-session readiness failure."""

    def __init__(self, stage: str = "internal") -> None:
        sanitized = stage if stage in SESSION_FAILURE_STAGES else "internal"
        super().__init__(sanitized)
        self.stage = sanitized


def _at_stage(stage: str, operation):
    try:
        return operation()
    except (KeyError, OSError, SessionError) as error:
        raise SessionError(stage) from error


def _bounded_file(path: str) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        payload = os.read(descriptor, MAX_FILE_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(payload) > MAX_FILE_BYTES:
        raise SessionError
    return payload


def _account() -> pwd.struct_passwd:
    account = pwd.getpwnam(UI_ACCOUNT)
    group = grp.getgrgid(account.pw_gid)
    if (
        account.pw_uid in (0, 1000)
        or account.pw_gid in (0, 1000)
        or account.pw_dir != UI_HOME
        or account.pw_shell != UI_SHELL
        or group.gr_name != UI_ACCOUNT
        or group.gr_mem
        or set(os.getgrouplist(UI_ACCOUNT, account.pw_gid)) != {account.pw_gid}
    ):
        raise SessionError
    return account


def _safe_directory(
    descriptor: int,
    *,
    uid: int,
    gid: int | None,
    exact_mode: int | None = None,
) -> None:
    metadata = os.fstat(descriptor)
    mode = stat.S_IMODE(metadata.st_mode)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != uid
        or (gid is not None and metadata.st_gid != gid)
        or (exact_mode is not None and mode != exact_mode)
        or (exact_mode is None and mode & 0o022)
    ):
        raise SessionError


def _read_all(descriptor: int) -> bytes:
    payload = bytearray()
    while len(payload) <= MAX_FILE_BYTES:
        block = os.read(descriptor, MAX_FILE_BYTES + 1 - len(payload))
        if not block:
            break
        payload.extend(block)
    if not 0 < len(payload) <= MAX_FILE_BYTES:
        raise SessionError
    return bytes(payload)


def _xauthority_records(payload: bytes) -> list[tuple[int, bytes, bytes, bytes, bytes]]:
    records: list[tuple[int, bytes, bytes, bytes, bytes]] = []
    offset = 0

    def take(length: int) -> bytes:
        nonlocal offset
        end = offset + length
        if end > len(payload):
            raise SessionError
        value = payload[offset:end]
        offset = end
        return value

    def take_field() -> bytes:
        return take(int.from_bytes(take(2), "big"))

    while offset < len(payload):
        family = int.from_bytes(take(2), "big")
        records.append(
            (family, take_field(), take_field(), take_field(), take_field())
        )
        if len(records) > 4:
            raise SessionError
    return records


def _valid_xauthority_payload(payload: bytes) -> bool:
    try:
        records = _xauthority_records(payload)
    except SessionError:
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


def _xauthority_ready(account: pwd.struct_passwd) -> bool:
    descriptors: list[int] = []
    try:
        run = os.open(
            "/run", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
        )
        descriptors.append(run)
        _safe_directory(run, uid=0, gid=0)
        lightdm = os.open(
            "lightdm",
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=run,
        )
        descriptors.append(lightdm)
        _safe_directory(lightdm, uid=0, gid=None)
        user_directory = os.open(
            UI_ACCOUNT,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=lightdm,
        )
        descriptors.append(user_directory)
        _safe_directory(
            user_directory, uid=account.pw_uid, gid=account.pw_gid, exact_mode=0o700
        )
        authority = os.open(
            "xauthority",
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=user_directory,
        )
        descriptors.append(authority)
        metadata = os.fstat(authority)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != account.pw_uid
            or metadata.st_gid != account.pw_gid
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or not 0 < metadata.st_size <= MAX_FILE_BYTES
        ):
            raise SessionError
        return _valid_xauthority_payload(_read_all(authority))
    except FileNotFoundError:
        return False
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _runtime_ready(account: pwd.struct_passwd) -> bool:
    try:
        descriptor = os.open(
            UI_RUNTIME,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
    except FileNotFoundError:
        return False
    try:
        _safe_directory(
            descriptor, uid=account.pw_uid, gid=account.pw_gid, exact_mode=0o700
        )
        entries = set(os.listdir(descriptor))
    finally:
        os.close(descriptor)
    if "bus" in entries or "systemd" in entries:
        raise SessionError
    return True


def _prepare_masked_user_runtime(account: pwd.struct_passwd) -> None:
    parent = os.open(
        "/run/user", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    )
    try:
        _safe_directory(parent, uid=0, gid=0)
        name = str(account.pw_uid)
        try:
            os.mkdir(name, 0, dir_fd=parent)
        except FileExistsError:
            pass
        runtime = os.open(
            name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=parent,
        )
        try:
            _safe_directory(runtime, uid=0, gid=0, exact_mode=0)
            if os.listdir(runtime):
                raise SessionError
        finally:
            os.close(runtime)
    finally:
        os.close(parent)


def _quad(status: bytes, prefix: bytes) -> tuple[int, int, int, int]:
    line = next((line for line in status.splitlines() if line.startswith(prefix)), None)
    if line is None:
        raise SessionError
    try:
        values = tuple(int(value) for value in line.removeprefix(prefix).split())
    except ValueError as error:
        raise SessionError from error
    if len(values) != 4:
        raise SessionError
    return values


def _groups(status: bytes) -> set[int]:
    line = next((line for line in status.splitlines() if line.startswith(b"Groups:")), None)
    if line is None:
        raise SessionError
    try:
        return {int(value) for value in line.removeprefix(b"Groups:").split()}
    except ValueError as error:
        raise SessionError from error


def _environment(pid: int) -> dict[bytes, bytes]:
    values: dict[bytes, bytes] = {}
    environment = _bounded_file(f"/proc/{pid}/environ")
    for item in environment.rstrip(b"\0").split(b"\0") if environment else ():
        if b"=" not in item:
            raise SessionError
        name, value = item.split(b"=", 1)
        if name in values:
            raise SessionError
        values[name] = value
    return values


def _session_process_ready(account: pwd.struct_passwd) -> bool:
    privileged_gids = {grp.getgrnam(name).gr_gid for name in PRIVILEGED_GROUPS}
    lightdm_uid = pwd.getpwnam("lightdm").pw_uid
    numeric_entries = 0
    xfwm = 0
    with os.scandir("/proc") as entries:
        for entry in entries:
            if not entry.name.isascii() or not entry.name.isdecimal():
                continue
            numeric_entries += 1
            if numeric_entries > MAX_PROCESSES:
                raise SessionError
            pid = int(entry.name)
            try:
                status = _bounded_file(f"/proc/{pid}/status")
                uids = _quad(status, b"Uid:\t")
                gids = _quad(status, b"Gid:\t")
                groups = _groups(status)
            except (FileNotFoundError, ProcessLookupError):
                continue
            try:
                executable = os.readlink(f"/proc/{pid}/exe")
            except (FileNotFoundError, ProcessLookupError):
                continue
            executable_name = os.path.basename(executable).lower()
            if executable_name in FORBIDDEN_UI_PROCESS_NAMES:
                # LightDM may briefly own a greeter while the fixed autologin
                # session is being handed over.  This is not a success state,
                # but it is a readiness observation rather than an immediate
                # permanent failure.  A persistent greeter still fails closed
                # at the bounded deadline and the final root attestor repeats
                # the process-tree exclusion before Rescue can become ready.
                return False
            if (
                account.pw_uid not in uids
                and 1000 not in uids
                and lightdm_uid not in uids
                and not privileged_gids.intersection(groups | set(gids))
                and executable_name not in {"lightdm", "xorg"}
            ):
                continue
            try:
                environment = _environment(pid)
            except (FileNotFoundError, ProcessLookupError):
                continue
            display_access = (
                environment.get(b"DISPLAY") in DISPLAY_ZERO
                or environment.get(b"XAUTHORITY") == XAUTHORITY.encode("ascii")
            )
            if display_access and account.pw_uid not in uids:
                raise SessionError
            if account.pw_uid not in uids:
                continue
            if (
                uids != (account.pw_uid,) * 4
                or gids != (account.pw_gid,) * 4
                or not groups.issubset({account.pw_gid})
            ):
                raise SessionError
            # LightDM executes the fixed wrapper and session scripts through
            # dash before the process becomes xfwm4.  Seeing that non-final
            # UI-owned process is a retryable readiness observation: it can
            # never produce success, and a persistent process still reaches
            # the bounded timeout.  Once xfwm4 exists, every identity and
            # environment mismatch remains an immediate hard failure.
            if executable != XFWM_PATH:
                return False
            if (
                environment.get(b"DISPLAY") != DISPLAY
                or environment.get(b"XAUTHORITY") != XAUTHORITY.encode("ascii")
                or environment.get(b"XDG_RUNTIME_DIR") != UI_RUNTIME.encode("ascii")
                or environment.get(b"HOME") != f"{UI_RUNTIME}/home".encode("ascii")
                or environment.get(b"DBUS_SESSION_BUS_ADDRESS")
                != f"unix:path={UI_RUNTIME}/no-session-bus".encode("ascii")
                or environment.get(b"DBUS_SYSTEM_BUS_ADDRESS")
                != f"unix:path={UI_RUNTIME}/no-system-bus".encode("ascii")
            ):
                raise SessionError
            xfwm += 1
    if xfwm > 1:
        raise SessionError
    return xfwm == 1


def attest() -> None:
    account = _at_stage("account", _account)
    _at_stage("user-runtime-mask", lambda: _prepare_masked_user_runtime(account))
    deadline = time.monotonic() + READY_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        if (
            _at_stage("xauthority", lambda: _xauthority_ready(account))
            and _at_stage("runtime", lambda: _runtime_ready(account))
            and _at_stage("process", lambda: _session_process_ready(account))
        ):
            return
        time.sleep(0.5)
    raise SessionError("timeout")


def main() -> int:
    try:
        attest()
    except SessionError as error:
        print(f"{SESSION_FAILURE_PREFIX}{error.stage}")
        return 1
    except (KeyError, OSError):
        print(f"{SESSION_FAILURE_PREFIX}internal")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
