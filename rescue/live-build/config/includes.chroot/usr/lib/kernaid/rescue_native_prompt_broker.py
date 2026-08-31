#!/usr/bin/python3
"""Root-owned closed broker for the feature-gated Rescue VT prompt.

The only admitted operation focuses a dedicated VT and starts the existing
UID-1000 Vault companion.  This process never receives prompt input or secret
bytes; those remain on the companion's controlling terminal.
"""

from __future__ import annotations

from collections import deque
import grp
import json
import os
import pwd
import re
import select
import signal
import socket
import stat
import struct
import subprocess
import threading
import time


API_VERSION = "kernaid.dev/rescue-native-prompt/v1alpha1"
SOCKET_PATH = "/run/kernaid-rescue-native-prompt.sock"
STATE_DIRECTORY = "/run/kernaid-rescue-native-prompt"
RETURN_VT_PATH = f"{STATE_DIRECTORY}/return-vt"
SHELL_CGROUP = "/system.slice/kernaid-rescue-desk-shell.service"
SHELL_EXECUTABLE = "/usr/bin/kernaid-rescue-desk-shell"
SHELL_UNIT = "kernaid-rescue-desk-shell.service"
SHELL_UNIT_PATH = "/etc/systemd/system/kernaid-rescue-desk-shell.service"
UI_ACCOUNT = "kernaid-rescue-ui"
PROMPT_UNIT = "kernaid-rescue-native-vault-unlock.service"
PROMPT_ADAPTER = "/usr/lib/kernaid/rescue-native-vault-unlock"
PROMPT_COMPANION = "/usr/bin/kernaid-rescue-vaultctl"
PROMPT_VT = 8
MAX_FRAME_BYTES = 512
MAX_PROC_BYTES = 64 * 1024
MAX_TOOL_BYTES = 4 * 1024
MAX_SEEN_REQUESTS = 1024
SO_PEERPIDFD = 77
TOOL_TIMEOUT_SECONDS = 4
START_TIMEOUT_SECONDS = 8
MONITOR_INTERVAL_SECONDS = 0.25
REQUEST_ID = re.compile(
    r"^N-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
    r"[0-9a-f]{4}-[0-9a-f]{12}$"
)
ACTIVE_VT = re.compile(rb"^tty([1-9]|[1-5][0-9]|6[0-3])\n$")
OUTCOMES = frozenset({"opened", "focused", "busy", "unavailable", "failed"})
PROMPT_STATES = frozenset({"idle", "active"})
NATIVE_PROMPT_FLAG = "kernaid.native-prompt=vt-v1"


class BrokerFailure(Exception):
    """Internal closed failure; its text is never returned or logged."""


def _reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate member")
        result[key] = value
    return result


def _strict_request(payload: bytes) -> dict[str, str]:
    if not 2 <= len(payload) <= MAX_FRAME_BYTES:
        raise BrokerFailure
    try:
        value = json.loads(
            payload.decode("ascii"),
            object_pairs_hook=_reject_duplicates,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise BrokerFailure from error
    if not isinstance(value, dict) or set(value) != {
        "apiVersion",
        "requestId",
        "operation",
        "kind",
    }:
        raise BrokerFailure
    request_id = value.get("requestId")
    if (
        value.get("apiVersion") != API_VERSION
        or value.get("operation") != "prompt.open-or-focus"
        or value.get("kind") != "vault-unlock"
        or not isinstance(request_id, str)
        or REQUEST_ID.fullmatch(request_id) is None
    ):
        raise BrokerFailure
    return value


def _response(request_id: str, outcome: str) -> bytes:
    if REQUEST_ID.fullmatch(request_id) is None or outcome not in OUTCOMES:
        raise BrokerFailure
    return json.dumps(
        {
            "apiVersion": API_VERSION,
            "requestId": request_id,
            "outcome": outcome,
        },
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def _status_response(prompt_state: str) -> bytes:
    if prompt_state not in PROMPT_STATES:
        raise BrokerFailure
    return json.dumps(
        {
            "apiVersion": API_VERSION,
            "kind": "vault-unlock",
            "availability": "available",
            "promptState": prompt_state,
        },
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def _bounded_file(path: str) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        payload = bytearray()
        while len(payload) <= MAX_PROC_BYTES:
            block = os.read(descriptor, MAX_PROC_BYTES + 1 - len(payload))
            if not block:
                break
            payload.extend(block)
        if len(payload) > MAX_PROC_BYTES:
            raise BrokerFailure
        return bytes(payload)
    finally:
        os.close(descriptor)


def _native_prompt_gate(payload: bytes | None = None) -> None:
    encoded = _bounded_file("/proc/cmdline") if payload is None else payload
    try:
        tokens = encoded.decode("ascii").split()
    except UnicodeDecodeError as error:
        raise BrokerFailure from error
    prompt_tokens = [
        token
        for token in tokens
        if token == "kernaid.native-prompt"
        or token.startswith("kernaid.native-prompt=")
    ]
    if tokens.count("boot=live") != 1 or prompt_tokens != [NATIVE_PROMPT_FLAG]:
        raise BrokerFailure


def _peer_identity(connection: socket.socket) -> int:
    pidfd = -1
    try:
        pidfd = connection.getsockopt(socket.SOL_SOCKET, SO_PEERPIDFD)
        if not isinstance(pidfd, int) or pidfd < 0:
            raise BrokerFailure
        os.set_inheritable(pidfd, False)
        if os.get_inheritable(pidfd):
            raise BrokerFailure
        credentials = connection.getsockopt(
            socket.SOL_SOCKET, socket.SO_PEERCRED, 12
        )
        pid, uid, gid = struct.unpack("3i", credentials)
        account = pwd.getpwnam(UI_ACCOUNT)
        group = grp.getgrgid(account.pw_gid)
    except (KeyError, OSError, OverflowError, ValueError, struct.error) as error:
        if pidfd >= 0:
            os.close(pidfd)
        raise BrokerFailure from error
    if (
        connection.family != socket.AF_UNIX
        or connection.type & socket.SOCK_STREAM != socket.SOCK_STREAM
        or pid <= 1
        or uid != account.pw_uid
        or gid != account.pw_gid
        or account.pw_uid in (0, 1000)
        or account.pw_gid in (0, 1000)
        or group.gr_name != UI_ACCOUNT
        or group.gr_mem
    ):
        os.close(pidfd)
        raise BrokerFailure
    try:
        if select.select([pidfd], [], [], 0)[0]:
            raise BrokerFailure
        _shell_service_identity(pid, account, group)
        if select.select([pidfd], [], [], 0)[0]:
            raise BrokerFailure
        return pidfd
    except (OSError, ValueError, BrokerFailure):
        os.close(pidfd)
        raise


def _listener_from_systemd() -> socket.socket:
    if (
        os.environ.get("LISTEN_PID") != str(os.getpid())
        or os.environ.get("LISTEN_FDS") != "1"
        or os.environ.get("LISTEN_FDNAMES") != "native-prompt"
    ):
        raise BrokerFailure
    for name in ("LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"):
        os.environ.pop(name, None)
    listener = socket.socket(fileno=3)
    os.set_inheritable(listener.fileno(), False)
    try:
        metadata = os.lstat(SOCKET_PATH)
        local = listener.getsockname()
        accepting = listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)
        account = pwd.getpwnam(UI_ACCOUNT)
    except (KeyError, OSError) as error:
        listener.close()
        raise BrokerFailure from error
    if (
        listener.family != socket.AF_UNIX
        or listener.type & socket.SOCK_STREAM != socket.SOCK_STREAM
        or local != SOCKET_PATH
        or accepting != 1
        or not stat.S_ISSOCK(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != account.pw_gid
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o660
    ):
        listener.close()
        raise BrokerFailure
    return listener


def _receive(connection: socket.socket) -> bytes:
    connection.settimeout(2)
    payload = bytearray()
    while len(payload) <= MAX_FRAME_BYTES:
        block = connection.recv(MAX_FRAME_BYTES + 1 - len(payload))
        if not block:
            break
        payload.extend(block)
    if len(payload) > MAX_FRAME_BYTES:
        raise BrokerFailure
    return bytes(payload)


def _tool(arguments: tuple[str, ...]) -> tuple[int, bytes]:
    try:
        result = subprocess.run(
            arguments,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=TOOL_TIMEOUT_SECONDS,
            env={"LC_ALL": "C", "PATH": "/usr/bin:/bin", "SYSTEMD_COLORS": "0"},
            close_fds=True,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise BrokerFailure from error
    if len(result.stdout) > MAX_TOOL_BYTES:
        raise BrokerFailure
    return result.returncode, result.stdout


def _systemctl_properties(unit: str, properties: tuple[str, ...]) -> dict[str, str]:
    code, output = _tool(
        (
            "/usr/bin/systemctl",
            "show",
            unit,
            *(f"--property={name}" for name in properties),
        )
    )
    if code != 0:
        raise BrokerFailure
    try:
        lines = output.decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        raise BrokerFailure from error
    values: dict[str, str] = {}
    for line in lines:
        if "=" not in line:
            raise BrokerFailure
        name, value = line.split("=", 1)
        if name not in properties or name in values:
            raise BrokerFailure
        values[name] = value
    if set(values) != set(properties):
        raise BrokerFailure
    return values


def _shell_service_identity(
    pid: int, account: pwd.struct_passwd, group: grp.struct_group
) -> None:
    properties = (
        "LoadState",
        "ActiveState",
        "SubState",
        "MainPID",
        "ExecMainPID",
        "ControlGroup",
        "User",
        "Group",
        "FragmentPath",
        "DropInPaths",
    )
    values = _systemctl_properties(SHELL_UNIT, properties)
    expected_pid = str(pid)
    if values != {
        "LoadState": "loaded",
        "ActiveState": "active",
        "SubState": "running",
        "MainPID": expected_pid,
        "ExecMainPID": expected_pid,
        "ControlGroup": SHELL_CGROUP,
        "User": account.pw_name,
        "Group": group.gr_name,
        "FragmentPath": SHELL_UNIT_PATH,
        "DropInPaths": "",
    }:
        raise BrokerFailure
    descriptor = os.open(
        SHELL_UNIT_PATH, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    )
    try:
        metadata = os.fstat(descriptor)
        unit_bytes = os.read(descriptor, 64 * 1024 + 1)
    finally:
        os.close(descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o644
        or not 1 <= metadata.st_size <= 64 * 1024
        or len(unit_bytes) != metadata.st_size
    ):
        raise BrokerFailure
    exec_lines = [
        line for line in unit_bytes.splitlines() if line.startswith(b"ExecStart")
    ]
    if exec_lines != [f"ExecStart={SHELL_EXECUTABLE}".encode("ascii")]:
        raise BrokerFailure


def _unit_state() -> tuple[str, str, str]:
    values = _systemctl_properties(
        PROMPT_UNIT, ("ActiveState", "SubState", "Result")
    )
    return values["ActiveState"], values["SubState"], values["Result"]


def _prompt_backend_ready() -> None:
    for path in (PROMPT_ADAPTER, PROMPT_COMPANION):
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            metadata = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_gid != 0
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o755
            or not 1 <= metadata.st_size <= 128 * 1024 * 1024
        ):
            raise BrokerFailure
    code, output = _tool(
        ("/usr/bin/systemctl", "show", PROMPT_UNIT, "--property=LoadState")
    )
    if code != 0 or output != b"LoadState=loaded\n":
        raise BrokerFailure


def _active_vt(payload: bytes | None = None) -> int:
    value = _bounded_file("/sys/class/tty/tty0/active") if payload is None else payload
    match = ACTIVE_VT.fullmatch(value)
    if match is None:
        raise BrokerFailure
    return int(match.group(1))


def _switch_vt(number: int) -> None:
    try:
        if not 1 <= number <= 63:
            raise BrokerFailure
        code, output = _tool(("/usr/bin/chvt", str(number)))
        if code != 0 or output:
            raise BrokerFailure
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            if _active_vt() == number:
                return
            time.sleep(0.02)
        raise BrokerFailure
    except OSError as error:
        raise BrokerFailure from error


def _write_return_vt(number: int) -> None:
    if not 1 <= number <= 63 or number == PROMPT_VT:
        raise BrokerFailure
    directory = os.open(
        STATE_DIRECTORY, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    )
    temporary = ".return-vt-new"
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
            dir_fd=directory,
        )
        try:
            payload = f"tty{number}\n".encode("ascii")
            if os.write(descriptor, payload) != len(payload):
                raise BrokerFailure
            os.fchmod(descriptor, 0o600)
            os.fchown(descriptor, 0, 0)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.rename(temporary, "return-vt", src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
    except BaseException:
        try:
            os.unlink(temporary, dir_fd=directory)
        except FileNotFoundError:
            pass
        raise
    finally:
        os.close(directory)


def _read_return_vt() -> int | None:
    try:
        descriptor = os.open(
            RETURN_VT_PATH, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
        )
    except FileNotFoundError:
        return None
    try:
        metadata = os.fstat(descriptor)
        payload = os.read(descriptor, 16)
        extra = os.read(descriptor, 1)
    finally:
        os.close(descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or extra
    ):
        raise BrokerFailure
    number = _active_vt(payload)
    if number == PROMPT_VT:
        raise BrokerFailure
    return number


def _remove_return_vt() -> None:
    try:
        os.unlink(RETURN_VT_PATH)
    except FileNotFoundError:
        return
    directory = os.open(
        STATE_DIRECTORY, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    )
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _stop_prompt_unit() -> None:
    code, output = _tool(("/usr/bin/systemctl", "stop", PROMPT_UNIT))
    if code != 0 or output:
        raise BrokerFailure
    state, substate, _result = _unit_state()
    if state != "inactive" or substate != "dead":
        raise BrokerFailure


def _return_to_vt(number: int) -> None:
    last_error: BaseException | None = None
    for _attempt in range(4):
        try:
            _switch_vt(number)
            _remove_return_vt()
            return
        except (BrokerFailure, OSError) as error:
            last_error = error
            time.sleep(0.1)
    raise BrokerFailure from last_error


def _terminate_for_recovery() -> None:
    os.kill(os.getpid(), signal.SIGTERM)


class PromptController:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._active = False
        self._generation = 0

    def recover(self) -> None:
        return_vt = _read_return_vt()
        if return_vt is None:
            return
        _stop_prompt_unit()
        _return_to_vt(return_vt)

    def status(self) -> str:
        with self._lock:
            _prompt_backend_ready()
            return "active" if self._active else "idle"

    def open_or_focus(self) -> str:
        with self._lock:
            _prompt_backend_ready()
            if self._active:
                try:
                    state, substate, result = _unit_state()
                    if (state, substate, result) == ("active", "running", "success"):
                        _switch_vt(PROMPT_VT)
                        return "focused"
                except BrokerFailure:
                    pass
                _terminate_for_recovery()
                return "failed"
            return_vt = _active_vt()
            if return_vt == PROMPT_VT:
                return "busy"
            _write_return_vt(return_vt)
            try:
                code, output = _tool(
                    ("/usr/bin/systemctl", "start", "--no-block", PROMPT_UNIT)
                )
                if code != 0 or output:
                    raise BrokerFailure
                deadline = time.monotonic() + START_TIMEOUT_SECONDS
                while time.monotonic() < deadline:
                    state, substate, result = _unit_state()
                    if (state, substate, result) == ("active", "running", "success"):
                        break
                    # `systemctl start --no-block` can return before systemd
                    # publishes the queued job as `activating`.  During that
                    # bounded hand-off the unit still reports its previous
                    # clean inactive state.  Wait for the job instead of
                    # cancelling it immediately; every other inactive or
                    # failed state remains a closed failure.
                    if state == "activating" or (
                        state == "inactive"
                        and substate == "dead"
                        and result in {"", "success"}
                    ):
                        time.sleep(0.05)
                        continue
                    raise BrokerFailure
                else:
                    raise BrokerFailure
                _switch_vt(PROMPT_VT)
            except BrokerFailure:
                try:
                    _stop_prompt_unit()
                    _return_to_vt(return_vt)
                except BrokerFailure:
                    _terminate_for_recovery()
                return "failed"
            self._active = True
            self._generation += 1
            generation = self._generation
            threading.Thread(
                target=self._monitor,
                args=(generation, return_vt),
                name="native-prompt-monitor",
                daemon=True,
            ).start()
            return "opened"

    def _monitor(self, generation: int, return_vt: int) -> None:
        failures = 0
        while True:
            time.sleep(MONITOR_INTERVAL_SECONDS)
            try:
                state, _substate, _result = _unit_state()
            except BrokerFailure:
                failures += 1
                if failures < 20:
                    continue
                try:
                    _stop_prompt_unit()
                except BrokerFailure:
                    _terminate_for_recovery()
                    return
                break
            failures = 0
            if state not in {"active", "activating", "reloading"}:
                break
        with self._lock:
            if generation != self._generation:
                return
            try:
                _return_to_vt(return_vt)
            except BrokerFailure:
                _terminate_for_recovery()
                return
            self._active = False

    def stop(self) -> None:
        with self._lock:
            self._generation += 1
            return_vt = _read_return_vt()
            _stop_prompt_unit()
            if return_vt is not None:
                _return_to_vt(return_vt)
            self._active = False


class Broker:
    def __init__(self, controller: PromptController) -> None:
        self.controller = controller
        self._seen: set[str] = set()
        self._seen_order: deque[str] = deque()

    def handle(self, connection: socket.socket) -> None:
        request_id: str | None = None
        pidfd: int | None = None
        try:
            pidfd = _peer_identity(connection)
            payload = _receive(connection)
            if not payload:
                connection.sendall(_status_response(self.controller.status()))
                return
            request = _strict_request(payload)
            request_id = request["requestId"]
            if request_id in self._seen:
                raise BrokerFailure
            self._seen.add(request_id)
            self._seen_order.append(request_id)
            if len(self._seen_order) > MAX_SEEN_REQUESTS:
                self._seen.discard(self._seen_order.popleft())
            if select.select([pidfd], [], [], 0)[0]:
                raise BrokerFailure
            outcome = self.controller.open_or_focus()
            connection.sendall(_response(request_id, outcome))
        except (BrokerFailure, OSError, TimeoutError):
            if request_id is not None and REQUEST_ID.fullmatch(request_id):
                try:
                    connection.sendall(_response(request_id, "failed"))
                except OSError:
                    pass
        finally:
            if pidfd is not None:
                os.close(pidfd)


def run() -> None:
    _native_prompt_gate()
    listener = _listener_from_systemd()
    controller = PromptController()
    controller.recover()
    broker = Broker(controller)
    stopping = threading.Event()

    def stop(_signal: int, _frame: object) -> None:
        stopping.set()
        listener.close()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        while not stopping.is_set():
            try:
                connection, _address = listener.accept()
            except OSError:
                if stopping.is_set():
                    break
                raise
            with connection:
                broker.handle(connection)
    finally:
        controller.stop()
        listener.close()


def main() -> int:
    try:
        run()
    except (BrokerFailure, OSError):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
