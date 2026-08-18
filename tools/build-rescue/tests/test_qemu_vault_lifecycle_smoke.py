from __future__ import annotations

import contextlib
import ctypes
import errno
import importlib.util
import io
import json
import os
import re
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


TOOLS_DIR = Path(__file__).resolve().parents[1]
CONTROLLER = TOOLS_DIR / "qemu-vault-lifecycle-pty.py"
SCRIPT = TOOLS_DIR / "qemu-vault-lifecycle-smoke.sh"


def load_controller() -> object:
    spec = importlib.util.spec_from_file_location(
        "kernaid_qemu_vault_lifecycle_controller", CONTROLLER
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


controller = load_controller()


def synthetic_login_credential() -> bytes:
    """Create a per-test printable credential without a credential fixture."""

    alphabet = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
    entropy = bytearray(os.urandom(24))
    try:
        return bytes(alphabet[value % len(alphabet)] for value in entropy)
    finally:
        controller.wipe(entropy)


def synthetic_des_verifier(credential: bytes) -> bytes:
    """Build the legacy live-config verifier from per-test runtime material."""

    alphabet = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    entropy = bytearray(os.urandom(2))
    password = ctypes.create_string_buffer(credential)
    try:
        salt = bytes(alphabet[value % len(alphabet)] for value in entropy)
        library = ctypes.CDLL("libcrypt.so.1")
        crypt = library.crypt
        crypt.argtypes = (ctypes.c_char_p, ctypes.c_char_p)
        crypt.restype = ctypes.c_char_p
        encoded = crypt(password, salt)
        if encoded is None:
            raise AssertionError("synthetic verifier generation failed")
        result = ctypes.string_at(encoded)
        if len(result) != 13:
            raise AssertionError("synthetic verifier has an unexpected form")
        return result
    finally:
        ctypes.memset(password, 0, len(password))
        controller.wipe(entropy)


def response(
    version: int,
    state: str | None = None,
    device_id: str | None = None,
    error: str | None = None,
    return_code: int = 0,
) -> object:
    return controller.CompanionResponse(
        version, state, device_id, error, return_code
    )


def runtime_line(stage: str, mapper_count: int) -> bytes:
    zero = controller.ZERO_CAPS
    cap = controller.CAP_SYS_ADMIN_ONLY
    return (
        f"KERNAID_VAULT_RUNTIME_V1 stage={stage} service_pid=101 worker_pid=102 "
        f"service_caps={zero}:{cap}:{cap}:{cap} "
        f"worker_caps={zero}:{cap}:{cap}:{cap} "
        f"service_ambient={zero} worker_ambient={zero} "
        "service_nnp=1 worker_nnp=1 service_core=0:0 worker_core=0:0 "
        "parent_procs=empty supervisor_procs=service worker_procs=worker "
        "subtree_control=pids parent_descendants=2 supervisor_descendants=0 "
        "worker_descendants=0 worker_pids_current=1 leaf_exact=true "
        f"mapper_count={mapper_count} shell_mount=false swaps_empty=true "
        "service_active=true "
        "socket_listening=true cgroups_exact=true"
    ).encode("ascii")


class CaptureTests(unittest.TestCase):
    def test_capture_is_bounded_and_detects_cross_chunk_secret(self) -> None:
        secret = bytearray(b"a" * 64)
        capture = controller.BoundedCapture(128, [secret])
        capture.append(b"prefix" + b"a" * 32)
        with self.assertRaises(controller.SecretExposureError):
            capture.append(b"a" * 32 + b"suffix")
        capture.wipe()
        self.assertEqual(len(capture), 0)

        bounded = controller.BoundedCapture(4, [])
        bounded.append(b"1234")
        with self.assertRaises(controller.CaptureLimitError):
            bounded.append(b"5")

    def test_contextual_login_echo_ignores_incidental_boot_text(self) -> None:
        credential = bytearray(synthetic_login_credential())
        capture = controller.BoundedCapture(256, [])
        capture.append(b"boot=live components\r\nPassword: ")
        start = len(capture)
        capture.append(b"welcome to the live environment\r\n")
        self.assertFalse(
            capture.contains_contextual_line(
                credential, start=start, end=len(capture)
            )
        )
        capture.append(credential + b"\r\n")
        self.assertTrue(
            capture.contains_contextual_line(
                credential, start=start, end=len(capture)
            )
        )
        controller.wipe(credential)
        capture.wipe()

    def test_serial_console_reads_a_real_pty_without_persisting_it(self) -> None:
        master, slave = os.openpty()
        capture = controller.BoundedCapture(1024, [])
        console = controller.SerialConsole(slave, capture, lambda: None)
        try:
            os.write(master, b"noise\r\nEXACT_READY\r\n")
            cursor = console.wait_line(
                b"EXACT_READY",
                start=0,
                deadline=time.monotonic() + 1,
                stage="test",
            )
            self.assertGreater(cursor, 0)
            with self.assertRaises(controller.ClosedFailure) as failure:
                console.send(b"x", deadline=time.monotonic() - 1)
            self.assertEqual(failure.exception.code, "write-timeout")
        finally:
            console.close()
            os.close(master)
            capture.wipe()


class SecretDescriptorTests(unittest.TestCase):
    def test_secret_fd_requires_exact_file_and_alphabet(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "key"
            value = b"0123456789abcdef" * 4
            path.write_bytes(value)
            path.chmod(0o600)
            descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
            observed = controller.read_secret_fd(
                descriptor, expected_uid=os.getuid()
            )
            self.assertEqual(observed, bytearray(value))
            controller.wipe(observed)

            path.write_bytes(b"g" * 64)
            descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
            with self.assertRaises(controller.ClosedFailure) as failure:
                controller.read_secret_fd(descriptor, expected_uid=os.getuid())
            self.assertEqual(failure.exception.code, "alphabet-invalid")

    def test_process_metadata_gate_rejects_secret_in_argv_or_environment(self) -> None:
        secret = bytearray(b"0123456789abcdef" * 4)
        safe = ["qemu-system-x86_64", "-m", "2048"]
        environment = {"PATH": "/usr/bin", "LANG": "C"}
        self.assertTrue(
            controller.process_metadata_excludes_secrets(safe, environment, [secret])
        )
        self.assertFalse(
            controller.process_metadata_excludes_secrets(
                safe + [secret.decode("ascii")], environment, [secret]
            )
        )
        self.assertFalse(
            controller.process_metadata_excludes_secrets(
                safe, {**environment, "BAD": secret.decode("ascii")}, [secret]
            )
        )

    def test_login_credential_fd_is_root_modeled_and_variable_length(self) -> None:
        credential = synthetic_login_credential()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "login"
            path.write_bytes(credential)
            path.chmod(0o600)
            descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
            observed = controller.read_login_credential_fd(
                descriptor, expected_uid=os.getuid()
            )
            self.assertEqual(observed, bytearray(credential))
            controller.wipe(observed)

            path.chmod(0o644)
            descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
            with self.assertRaises(controller.ClosedFailure) as failure:
                controller.read_login_credential_fd(
                    descriptor, expected_uid=os.getuid()
                )
            self.assertEqual(failure.exception.code, "metadata-invalid")

    def test_live_config_credential_extraction_is_strict_and_descriptor_only(self) -> None:
        credential = synthetic_login_credential()
        assignment = b'\t_PASSWORD="' + synthetic_des_verifier(credential) + b'"\n'

        def source(extra: bytes = b"", password: bytes = credential) -> bytes:
            return (
                b"#!/bin/sh\n"
                + b"\t# Default password is: "
                + password
                + b"\n"
                + assignment
                + extra
            )

        def extract(value: bytes) -> tuple[bytes, str | None]:
            with tempfile.TemporaryDirectory() as directory:
                source_path = Path(directory) / "source"
                output_path = Path(directory) / "credential"
                source_path.write_bytes(value)
                output_path.write_bytes(b"")
                output_path.chmod(0o600)
                source_fd = os.open(source_path, os.O_RDONLY | os.O_CLOEXEC)
                output_fd = os.open(output_path, os.O_WRONLY | os.O_CLOEXEC)
                try:
                    controller.extract_live_credential(
                        source_fd,
                        output_fd,
                        expected_uid=os.getuid(),
                        expected_gid=os.getgid(),
                    )
                except controller.ClosedFailure as failure:
                    return b"", failure.code
                return output_path.read_bytes(), None

        observed, error = extract(source())
        self.assertIsNone(error)
        self.assertEqual(observed, credential)

        duplicate = synthetic_login_credential()
        _, error = extract(
            source(b"\t# Default password is: " + duplicate + b"\n")
        )
        self.assertEqual(error, "declaration-invalid")
        mismatch = synthetic_login_credential()
        _, error = extract(source(password=mismatch))
        self.assertEqual(error, "declaration-invalid")
        _, error = extract(source() + b"x" * controller.LIVE_CONFIG_LIMIT)
        self.assertEqual(error, "source-oversized")


class LiveLoginTests(unittest.TestCase):
    class ScriptedConsole:
        def __init__(
            self,
            ready: bytes,
            credential: bytes,
            *,
            echo_credential: bool = False,
        ) -> None:
            self.capture = controller.BoundedCapture(8192, [])
            self.capture.append(ready)
            self.echo_credential = echo_credential
            self.credential = bytearray(credential)
            self.sent: list[bytes] = []

        def send(self, value: bytes | bytearray, *, deadline: float) -> None:
            if deadline <= time.monotonic():
                raise AssertionError("send deadline was not absolute and future")
            self.sent.append(bytes(value))

        def wait_regex(
            self, pattern: object, *, start: int, deadline: float, stage: str
        ) -> object:
            self.assert_deadline = deadline
            additions = {
                "login-prompt": b"\r\nkernaid-rescue login: ",
                "login-password": b"\r\nPassword: ",
                "login-shell": (
                    (self.credential + b"\r\n") if self.echo_credential else b"\r\n"
                )
                + b"kernaid@kernaid-rescue:~$ ",
                "login": b"\r\nKERNAID_VAULT_LOGIN_V1 uid=1000 user=kernaid group=true\r\n",
            }
            addition = additions.get(stage)
            if addition is not None:
                self.capture.append(addition)
            match = pattern.search(self.capture.snapshot(), start)
            if match is None:
                raise controller.ClosedFailure("scripted", "missing")
            return match

    @contextlib.contextmanager
    def real_interactive_bash_console(
        self,
    ) -> Iterator[tuple[object, object, bytearray]]:
        credential = bytearray(synthetic_login_credential())
        wrapper = r"""
set -eu
printf 'KERNAID_RESCUE_READY\n'
IFS= read -r ignored
printf 'kernaid-rescue login: '
IFS= read -r ignored
stty -echo
printf 'Password: '
IFS= read -r ignored
stty echo
printf '\n'
id() {
    case "${1-}" in
        -u) printf '1000\n' ;;
        -un) printf 'kernaid\n' ;;
        -nG) printf 'kernaid kernaid-vault\n' ;;
        *) command id "$@" ;;
    esac
}
export -f id
PS1='kernaid@kernaid-rescue:~$ '
PROMPT_COMMAND=
export PS1 PROMPT_COMMAND
exec /bin/bash --noprofile --norc -i
"""
        child_pid, master = os.forkpty()
        if child_pid == 0:
            environment = os.environ.copy()
            environment.update(
                {
                    "TERM": "xterm-256color",
                    "LC_ALL": "C",
                    "LANG": "C",
                }
            )
            try:
                os.execve(
                    "/bin/bash",
                    ["/bin/bash", "--noprofile", "--norc", "-c", wrapper],
                    environment,
                )
            except BaseException:
                os._exit(127)

        os.set_blocking(master, False)
        capture = controller.BoundedCapture(64 * 1024, [credential])
        console = controller.SerialConsole(master, capture, lambda: None)
        try:
            yield console, capture, credential
        finally:
            console.close()
            try:
                os.kill(child_pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            wait_deadline = time.monotonic() + 2.0
            while True:
                waited, _ = os.waitpid(child_pid, os.WNOHANG)
                if waited == child_pid:
                    break
                if time.monotonic() >= wait_deadline:
                    try:
                        os.kill(child_pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    os.waitpid(child_pid, 0)
                    break
                time.sleep(0.01)
            controller.wipe(credential)
            capture.wipe()

    def test_real_login_accepts_standalone_or_exact_prefixed_ready(self) -> None:
        for ready in (
            b"KERNAID_RESCUE_READY\r\n",
            b"kernaid-rescue login: KERNAID_RESCUE_READY\r\n",
        ):
            with self.subTest(ready=ready):
                credential = bytearray(synthetic_login_credential())
                scripted = self.ScriptedConsole(ready, bytes(credential))
                cursor = controller.establish_live_session(
                    scripted, time.monotonic() + 60, credential
                )
                self.assertGreater(cursor, 0)
                self.assertEqual(
                    scripted.sent[:4],
                    [b"\n", b"kernaid\n", bytes(credential), b"\n"],
                )
                controller.wipe(credential)
                controller.wipe(scripted.credential)
                scripted.capture.wipe()

    def test_real_login_fails_if_password_is_echoed_in_prompt_window(self) -> None:
        credential = bytearray(synthetic_login_credential())
        scripted = self.ScriptedConsole(
            b"KERNAID_RESCUE_READY\r\n",
            bytes(credential),
            echo_credential=True,
        )
        with self.assertRaises(controller.ClosedFailure) as failure:
            controller.establish_live_session(
                scripted, time.monotonic() + 60, credential
            )
        self.assertEqual(failure.exception.code, "credential-echoed")
        controller.wipe(credential)
        controller.wipe(scripted.credential)
        scripted.capture.wipe()

    def test_trusted_shell_markers_accept_only_exact_optional_bracketed_paste_prefix(
        self,
    ) -> None:
        runtime = runtime_line("initial", 0)
        begin = b"KERNAID_VAULT_CTL_BEGIN_V1_marker-test"
        end = b"KERNAID_VAULT_CTL_END_V1_marker-test"
        cases = (
            ("login", controller.LOGIN_RESULT_PATTERN, controller.LOGIN_OK_LINE),
            (
                "login-failure",
                controller.LOGIN_RESULT_PATTERN,
                controller.LOGIN_FAIL_LINE,
            ),
            ("runtime", controller.RUNTIME_RESULT_PATTERN, runtime),
            (
                "companion-begin",
                controller._trusted_shell_line_pattern(begin),
                begin,
            ),
        )
        for name, pattern, marker in cases:
            for prefix in (b"", controller.BRACKETED_PASTE_DISABLE_PREFIX):
                with self.subTest(name=name, prefix=prefix):
                    transcript = b"command\r\n" + prefix + marker + b"\r\n"
                    self.assertIsNotNone(pattern.search(transcript))

        malformed_prefixes = (
            b"\x1b[?2004h\r",
            b"\x1b[?2004l",
            b"\x1b[?2004l\rX",
            b"X\x1b[?2004l\r",
            b"\x1b[31m",
            b"\x1b[?2004l\r\x1b[?2004l\r",
        )
        for name, pattern, marker in cases:
            for prefix in malformed_prefixes:
                with self.subTest(name=name, malformed_prefix=prefix):
                    transcript = b"command\r\n" + prefix + marker + b"\r\n"
                    self.assertIsNone(pattern.search(transcript))

        end_pattern = controller._return_code_line_pattern(end)
        self.assertIsNotNone(
            end_pattern.search(b"output\r\n" + end + b" rc=0\r\n")
        )
        self.assertIsNone(
            end_pattern.search(
                b"output\r\n"
                + controller.BRACKETED_PASTE_DISABLE_PREFIX
                + end
                + b" rc=0\r\n"
            )
        )

    @unittest.skipUnless(Path("/bin/bash").is_file(), "interactive bash required")
    def test_live_session_uses_real_interactive_bash_bracketed_paste_output(
        self,
    ) -> None:
        with self.real_interactive_bash_console() as (
            console,
            capture,
            credential,
        ):
            cursor = controller.establish_live_session(
                console, time.monotonic() + 10.0, credential
            )
            self.assertGreater(cursor, 0)
            self.assertIn(
                controller.BRACKETED_PASTE_DISABLE_PREFIX
                + controller.LOGIN_OK_LINE
                + b"\r\n",
                capture.snapshot(),
            )

    @unittest.skipUnless(Path("/bin/bash").is_file(), "interactive bash required")
    def test_real_interactive_bash_runtime_and_companion_markers(self) -> None:
        with self.real_interactive_bash_console() as (
            console,
            capture,
            credential,
        ):
            aggregate = time.monotonic() + 15.0
            cursor = controller.establish_live_session(
                console, aggregate, credential
            )

            runtime = runtime_line("initial", 0)
            runtime_command = b"printf '%s\\n' '" + runtime + b"'\n"
            with mock.patch.object(
                controller, "_runtime_command", return_value=runtime_command
            ):
                snapshot, cursor = controller.collect_runtime(
                    console, "initial", cursor, aggregate
                )
            self.assertEqual(snapshot.stage, "initial")
            self.assertIn(
                controller.BRACKETED_PASTE_DISABLE_PREFIX + runtime + b"\r\n",
                capture.snapshot(),
            )

            invalid_runtime = runtime_line("diagnostic", 0).replace(
                b"subtree_control=pids", b"subtree_control=cpu pids"
            )
            invalid_command = b"printf '%s\\n' '" + invalid_runtime + b"'\n"
            with mock.patch.object(
                controller, "_runtime_command", return_value=invalid_command
            ), self.assertRaises(controller.ClosedFailure) as failure:
                controller.collect_runtime(
                    console, "diagnostic", cursor, aggregate
                )
            self.assertEqual(failure.exception.stage, "runtime")
            self.assertEqual(
                failure.exception.code, "subtree-control-invalid"
            )
            self.assertEqual(
                str(failure.exception), "runtime:subtree-control-invalid"
            )
            invalid_match = controller.RUNTIME_RESULT_PATTERN.search(
                capture.snapshot(), cursor
            )
            self.assertIsNotNone(invalid_match)
            assert invalid_match is not None
            cursor = invalid_match.end()
            self.assertIn(
                controller.BRACKETED_PASTE_DISABLE_PREFIX
                + invalid_runtime
                + b"\r\n",
                capture.snapshot(),
            )

            setup = b"KERNAID_TEST_COMPANION_READY"
            console.send(
                b"function /usr/bin/kernaid-rescue-vaultctl { "
                b"printf '%s\\n' 'stateVersion: 10' 'vaultState: locked'; "
                b"}; printf '%s\\n' '"
                + setup
                + b"'\n",
                deadline=aggregate,
            )
            setup_match = console.wait_regex(
                controller._trusted_shell_line_pattern(setup),
                start=cursor,
                deadline=aggregate,
                stage="test-companion-setup",
            )
            observed, _ = controller.run_companion(
                console,
                "status",
                "real-bash-status",
                setup_match.end(),
                aggregate,
            )
            self.assertEqual(observed, response(10, "locked"))
            self.assertEqual(observed.return_code, 0)
            begin = b"KERNAID_VAULT_CTL_BEGIN_V1_real-bash-status"
            end = b"KERNAID_VAULT_CTL_END_V1_real-bash-status"
            transcript = capture.snapshot()
            self.assertIn(
                controller.BRACKETED_PASTE_DISABLE_PREFIX + begin + b"\r\n",
                transcript,
            )
            self.assertIn(b"\r\n" + end + b" rc=0\r\n", transcript)
            self.assertNotIn(
                controller.BRACKETED_PASTE_DISABLE_PREFIX + end + b" rc=0\r\n",
                transcript,
            )


class ResponseParserTests(unittest.TestCase):
    def test_exact_status_wrong_unlock_success_and_lock(self) -> None:
        self.assertEqual(
            controller.parse_companion_response(
                b"stateVersion: 20\r\nvaultState: locked\r\n",
                command="status",
                return_code=0,
            ),
            response(20, "locked"),
        )
        self.assertEqual(
            controller.parse_companion_response(
                b"READY\r\nVault passphrase: \r\n"
                b"stateVersion: 22\r\nerror: BAD_PASSPHRASE\r\n",
                command="unlock",
                return_code=1,
            ),
            response(22, error="BAD_PASSPHRASE", return_code=1),
        )
        self.assertEqual(
            controller.parse_companion_response(
                b"READY\nVault passphrase: \nstateVersion: 24\n"
                b"vaultState: unlocked\ndeviceId: KA-0123456789abcdef01234567\n",
                command="unlock",
                return_code=0,
            ),
            response(24, "unlocked", "KA-0123456789abcdef01234567"),
        )
        self.assertEqual(
            controller.parse_companion_response(
                b"stateVersion: 26\nvaultState: locked\n",
                command="lock",
                return_code=0,
            ),
            response(26, "locked"),
        )

    def test_parser_rejects_prompt_before_ready_extra_output_and_bad_device(self) -> None:
        invalid = [
            b"Vault passphrase: \nREADY\nstateVersion: 2\nerror: BAD_PASSPHRASE\n",
            b"READY\nVault passphrase: \nstateVersion: 2\nerror: BAD_PASSPHRASE\nextra\n",
            b"READY\nVault passphrase: \nstateVersion: 2\nvaultState: unlocked\ndeviceId: KA-ABC\n",
        ]
        for block in invalid:
            with self.subTest(block=block), self.assertRaises(
                controller.ClosedFailure
            ):
                controller.parse_companion_response(
                    block, command="unlock", return_code=1
                )

    def test_lifecycle_requires_exact_plus_two_and_stable_device_id(self) -> None:
        device_id = "KA-0123456789abcdef01234567"
        observed = controller.validate_lifecycle(
            response(100, "locked"),
            response(102, error="BAD_PASSPHRASE", return_code=1),
            response(102, "locked"),
            response(104, "unlocked", device_id),
            response(104, "unlocked", device_id),
            response(106, "locked"),
            response(106, "locked"),
        )
        self.assertEqual(observed, device_id)
        with self.assertRaises(controller.ClosedFailure):
            controller.validate_lifecycle(
                response(100, "locked"),
                response(103, error="BAD_PASSPHRASE", return_code=1),
                response(103, "locked"),
                response(105, "unlocked", device_id),
                response(105, "unlocked", device_id),
                response(107, "locked"),
                response(107, "locked"),
            )

    def test_unlock_writes_secret_only_after_exact_ready_prompt(self) -> None:
        secret = bytearray(b"0123456789abcdef" * 4)
        stage = "ordered-unlock"
        transcript = (
            b"KERNAID_VAULT_CTL_BEGIN_V1_ordered-unlock\r\n"
            b"READY\r\nVault passphrase: \r\n"
            b"stateVersion: 12\r\nerror: BAD_PASSPHRASE\r\n"
            b"KERNAID_VAULT_CTL_END_V1_ordered-unlock rc=1\r\n"
        )

        class ScriptedConsole:
            def __init__(self, data: bytes) -> None:
                self.capture = controller.BoundedCapture(4096, [])
                self.capture.append(data)
                self.sent: list[bytes] = []
                self.waited: list[bytes] = []

            def send(self, value: bytes | bytearray, *, deadline: float) -> None:
                self.assert_deadline = deadline
                self.sent.append(bytes(value))

            def wait_regex(
                self, pattern: object, *, start: int, deadline: float, stage: str
            ) -> object:
                del deadline, stage
                self.waited.append(pattern.pattern)
                match = pattern.search(self.capture.snapshot(), start)
                if match is None:
                    raise controller.ClosedFailure("scripted", "missing")
                return match

        console = ScriptedConsole(transcript)
        parsed, _ = controller.run_companion(
            console,
            "unlock",
            stage,
            0,
            time.monotonic() + 10,
            secret,
        )
        self.assertEqual(parsed.error, "BAD_PASSPHRASE")
        self.assertIn(b"READY", console.waited[1])
        self.assertEqual(console.sent[1:], [bytes(secret), b"\n"])

        missing_ready = transcript.replace(b"READY\r\n", b"NOT_READY\r\n")
        blocked = ScriptedConsole(missing_ready)
        with self.assertRaises(controller.ClosedFailure):
            controller.run_companion(
                blocked,
                "unlock",
                stage,
                0,
                time.monotonic() + 10,
                secret,
            )
        self.assertEqual(len(blocked.sent), 1, "the secret must remain unsent")


class RuntimeEvidenceTests(unittest.TestCase):
    def test_socket_operational_state_is_an_exact_closed_set(self) -> None:
        for active_state, substate, expected in (
            ("active", "listening", "true"),
            ("active", "running", "true"),
            ("active", "dead", "false"),
            ("active", "failed", "false"),
            ("inactive", "listening", "false"),
            ("inactive", "running", "false"),
            ("invalid", "invalid", "false"),
        ):
            with self.subTest(active_state=active_state, substate=substate):
                script = (
                    f"socket_state={f'{active_state}:{substate}'!r}; "
                    "listening=false; "
                    f"{controller.SOCKET_OPERATIONAL_CASE} "
                    'printf "%s" "$listening"'
                )
                observed = subprocess.run(
                    ["sh", "-c", script],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(observed.stdout, expected)

        runtime_command = controller._runtime_command("socket-state-test").decode(
            "ascii"
        )
        self.assertIn(controller.SOCKET_OPERATIONAL_CASE, runtime_command)

    def test_runtime_sequence_requires_stable_processes_caps_and_mapper_cleanup(self) -> None:
        snapshots = [
            controller.parse_runtime_snapshot(runtime_line("initial", 0), "initial"),
            controller.parse_runtime_snapshot(
                runtime_line("after-wrong", 0), "after-wrong"
            ),
            controller.parse_runtime_snapshot(
                runtime_line("unlocked", 1), "unlocked"
            ),
            controller.parse_runtime_snapshot(runtime_line("final", 0), "final"),
        ]
        controller.validate_runtime_sequence(snapshots)
        changed = list(snapshots)
        changed[3] = controller.dataclasses.replace(
            snapshots[3], service_pid=999
        )
        with self.assertRaises(controller.ClosedFailure):
            controller.validate_runtime_sequence(changed)

    def test_runtime_classifier_never_relaxes_the_strict_acceptance_path(self) -> None:
        valid = runtime_line("initial", 0)
        with mock.patch.object(
            controller,
            "_runtime_evidence_failure_code",
            side_effect=AssertionError("diagnostic classifier was reached"),
        ):
            snapshot = controller.parse_runtime_snapshot(valid, "initial")
        self.assertEqual(snapshot.stage, "initial")

        excess = valid.replace(
            controller.CAP_SYS_ADMIN_ONLY.encode("ascii"),
            b"0000000000600000",
            1,
        )
        self.assertIsNotNone(controller.RUNTIME_RE.fullmatch(excess))
        with mock.patch.object(
            controller,
            "_runtime_evidence_failure_code",
            side_effect=AssertionError("diagnostic classifier was reached"),
        ), self.assertRaises(controller.ClosedFailure) as failure:
            controller.parse_runtime_snapshot(excess, "initial")
        self.assertEqual(failure.exception.code, "capabilities-invalid")

    def test_runtime_parser_rejects_excess_capabilities_and_shell_mount(self) -> None:
        line = runtime_line("initial", 0).replace(
            controller.CAP_SYS_ADMIN_ONLY.encode("ascii"), b"0000000000600000", 1
        )
        with self.assertRaises(controller.ClosedFailure) as failure:
            controller.parse_runtime_snapshot(line, "initial")
        self.assertEqual(failure.exception.code, "capabilities-invalid")
        mounted = runtime_line("initial", 0).replace(
            b"shell_mount=false", b"shell_mount=true"
        )
        snapshot = controller.parse_runtime_snapshot(mounted, "initial")
        with self.assertRaises(controller.ClosedFailure):
            controller.validate_runtime_sequence([snapshot] * 4)

    def test_runtime_rejection_classifier_covers_every_emitted_field(self) -> None:
        valid = runtime_line("initial", 0)
        zero = controller.ZERO_CAPS.encode("ascii")
        cap = controller.CAP_SYS_ADMIN_ONLY.encode("ascii")
        mutations = [
            (b"stage=initial", b"stage=other", "stage-invalid"),
            (b"service_pid=101", b"service_pid=0", "service-pid-invalid"),
            (b"worker_pid=102", b"worker_pid=0", "worker-pid-invalid"),
            (
                b"service_caps=" + b":".join((zero, cap, cap, cap)),
                b"service_caps=invalid",
                "service-capabilities-invalid",
            ),
            (
                b"worker_caps=" + b":".join((zero, cap, cap, cap)),
                b"worker_caps=invalid",
                "worker-capabilities-invalid",
            ),
            (
                b"service_ambient=" + zero,
                b"service_ambient=0000000000000001",
                "service-ambient-invalid",
            ),
            (
                b"worker_ambient=" + zero,
                b"worker_ambient=0000000000000001",
                "worker-ambient-invalid",
            ),
            (b"service_nnp=1", b"service_nnp=0", "service-nnp-invalid"),
            (b"worker_nnp=1", b"worker_nnp=0", "worker-nnp-invalid"),
            (
                b"service_core=0:0",
                b"service_core=0:unlimited",
                "service-core-invalid",
            ),
            (
                b"worker_core=0:0",
                b"worker_core=0:unlimited",
                "worker-core-invalid",
            ),
            (
                b"parent_procs=empty",
                b"parent_procs=invalid",
                "parent-procs-invalid",
            ),
            (
                b"supervisor_procs=service",
                b"supervisor_procs=invalid",
                "supervisor-procs-invalid",
            ),
            (
                b"worker_procs=worker",
                b"worker_procs=invalid",
                "worker-procs-invalid",
            ),
            (
                b"subtree_control=pids",
                b"subtree_control=cpu pids",
                "subtree-control-invalid",
            ),
            (
                b"parent_descendants=2",
                b"parent_descendants=3",
                "parent-descendants-invalid",
            ),
            (
                b"supervisor_descendants=0",
                b"supervisor_descendants=1",
                "supervisor-descendants-invalid",
            ),
            (
                b"worker_descendants=0",
                b"worker_descendants=1",
                "worker-descendants-invalid",
            ),
            (
                b"worker_pids_current=1",
                b"worker_pids_current=2",
                "worker-pids-current-invalid",
            ),
            (
                b"leaf_exact=true",
                b"leaf_exact=false",
                "leaf-exact-invalid",
            ),
            (
                b"mapper_count=0",
                b"mapper_count=invalid",
                "mapper-count-invalid",
            ),
            (
                b"shell_mount=false",
                b"shell_mount=invalid",
                "shell-mount-invalid",
            ),
            (
                b"swaps_empty=true",
                b"swaps_empty=false",
                "swaps-invalid",
            ),
            (
                b"service_active=true",
                b"service_active=false",
                "service-state-invalid",
            ),
            (
                b"socket_listening=true",
                b"socket_listening=false",
                "socket-state-invalid",
            ),
            (
                b"cgroups_exact=true",
                b"cgroups_exact=false",
                "cgroups-invalid",
            ),
        ]
        observed_codes = set()
        for expected, replacement, code in mutations:
            with self.subTest(field=expected, code=code), self.assertRaises(
                controller.ClosedFailure
            ) as failure:
                controller.parse_runtime_snapshot(
                    valid.replace(expected, replacement), "initial"
                )
            self.assertEqual(failure.exception.stage, "runtime")
            self.assertEqual(failure.exception.code, code)
            self.assertEqual(str(failure.exception), f"runtime:{code}")
            observed_codes.add(code)
        self.assertEqual(
            observed_codes,
            controller.RUNTIME_EVIDENCE_FAILURE_CODES
            - {"evidence-invalid", "capabilities-invalid"},
        )

    def test_runtime_rejection_classifier_keeps_malformed_data_closed(self) -> None:
        valid = runtime_line("initial", 0)
        malformed = (
            valid.replace(b" worker_pid=102", b""),
            valid.replace(
                b"service_pid=101",
                b"service_pid=101 service_pid=101",
            ),
            valid.replace(
                b"service_pid=101 worker_pid=102",
                b"worker_pid=102 service_pid=101",
            ),
            valid.replace(b"stage=initial", b"stage=initial\x1b[31m"),
            valid.replace(b"parent_procs=empty", b"parent_procs=empty\nspoof"),
            valid.replace(b"worker_pid=102", b"unknown=1 worker_pid=102"),
            b"\x1b[?2004l\r" + valid,
            valid + (b"x" * 1025),
        )
        for line in malformed:
            with self.subTest(line_length=len(line)), self.assertRaises(
                controller.ClosedFailure
            ) as failure:
                controller.parse_runtime_snapshot(line, "initial")
            self.assertEqual(failure.exception.stage, "runtime")
            self.assertEqual(failure.exception.code, "evidence-invalid")
            self.assertEqual(str(failure.exception), "runtime:evidence-invalid")


class ProbeRunnerTests(unittest.TestCase):
    def run_probe_fixture(
        self, script_body: str, *, timeout: float = 2.0
    ) -> tuple[str | None, controller.ClosedFailure | None, int]:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            probe = root / "probe"
            probe.write_text("#!/bin/sh\nset -eu\n" + script_body, encoding="ascii")
            probe.chmod(0o700)
            correct = os.urandom(32).hex().encode("ascii")
            wrong = os.urandom(32).hex().encode("ascii")
            while wrong == correct:
                wrong = os.urandom(32).hex().encode("ascii")
            correct_path = root / "correct"
            wrong_path = root / "wrong"
            pgid_path = root / "pgid"
            correct_path.write_bytes(correct)
            wrong_path.write_bytes(wrong)
            pgid_path.write_bytes(b"")
            for path in (correct_path, wrong_path, pgid_path):
                path.chmod(0o600)
            parsed = SimpleNamespace(
                probe=probe,
                device="/dev/loop999",
                mapper="kernaid-vault-0123456789abcdef",
                mode="verify",
                correct_key_fd=os.open(correct_path, os.O_RDONLY | os.O_CLOEXEC),
                wrong_key_fd=os.open(wrong_path, os.O_RDONLY | os.O_CLOEXEC),
                owned_pgid_fd=os.open(pgid_path, os.O_WRONLY | os.O_CLOEXEC),
                timeout=timeout,
            )
            observed: str | None = None
            failure: controller.ClosedFailure | None = None
            with mock.patch.object(controller, "_validate_probe_arguments"):
                try:
                    observed = controller.run_bounded_probe(parsed)
                except controller.ClosedFailure as error:
                    failure = error
            process_group = int(pgid_path.read_text(encoding="ascii").strip())
            self.assertFalse(controller.process_group_exists(process_group))
            return observed, failure, process_group

    def test_probe_capture_is_bounded_secret_scanned_and_group_cleaned(self) -> None:
        valid_line = (
            "KERNAID_RESCUE_VAULT_PROBE_ATTESTATION_V1 mode=verify "
            "journal_binding=device-identity-bound-v1 "
            f"identity_public_key={'0' * 64} clean_shutdown=true"
        )
        observed, failure, _ = self.run_probe_fixture(
            "IFS= read -r value || :\n" f"printf '%s\\n' '{valid_line}'\n"
        )
        self.assertIsNone(failure)
        self.assertEqual(observed, valid_line)

        _, failure, _ = self.run_probe_fixture(
            "IFS= read -r value || :\nprintf '%s\\n' \"$value\"\n"
        )
        self.assertIsNotNone(failure)
        self.assertEqual((failure.stage, failure.code), ("probe-stdout", "secret-exposure"))

        _, failure, _ = self.run_probe_fixture(
            "IFS= read -r value || :\nwhile :; do printf '%064d' 0; done\n"
        )
        self.assertIsNotNone(failure)
        self.assertEqual((failure.stage, failure.code), ("probe-stdout", "oversized"))

        _, failure, _ = self.run_probe_fixture(
            "IFS= read -r value || :\nsleep 60\n", timeout=0.1
        )
        self.assertIsNotNone(failure)
        self.assertEqual((failure.stage, failure.code), ("probe", "timeout"))

    def test_owned_pgid_publication_requires_a_private_single_link_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "pgid"
            path.write_bytes(b"")
            path.chmod(0o644)
            descriptor = os.open(path, os.O_WRONLY | os.O_CLOEXEC)
            try:
                with self.assertRaises(controller.ClosedFailure) as failure:
                    controller.validate_owned_pgid_fd(
                        descriptor,
                        expected_uid=os.getuid(),
                        expected_gid=os.getgid(),
                    )
                self.assertEqual(failure.exception.code, "metadata-invalid")
            finally:
                os.close(descriptor)


class QmpTests(unittest.TestCase):
    def test_qmp_capabilities_and_acpi_powerdown_are_correlated(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "qmp.sock"
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(os.fspath(path))
            listener.listen(1)
            commands: list[str] = []

            def serve() -> None:
                connection, _ = listener.accept()
                with connection:
                    connection.sendall(
                        json.dumps(
                            {
                                "QMP": {
                                    "version": {"qemu": {"major": 9}},
                                    "capabilities": [],
                                }
                            }
                        ).encode("ascii")
                        + b"\r\n"
                    )
                    stream = connection.makefile("rb")
                    for _ in range(2):
                        request = json.loads(stream.readline())
                        commands.append(request["execute"])
                        connection.sendall(
                            json.dumps(
                                {"return": {}, "id": request["id"]},
                                separators=(",", ":"),
                            ).encode("ascii")
                            + b"\r\n"
                        )

            thread = threading.Thread(target=serve)
            thread.start()
            try:
                client = controller.QmpClient.connect(
                    path, time.monotonic() + 2
                )
                client.set_deadline(time.monotonic() + 2)
                client.system_powerdown()
                client.close()
            finally:
                thread.join(2)
                listener.close()
            self.assertFalse(thread.is_alive())
            self.assertEqual(commands, ["qmp_capabilities", "system_powerdown"])

    def test_qemu_harness_discovers_stdout_pty_from_merged_bounded_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            master, slave = os.openpty()
            pty_path = os.ttyname(slave)
            output = root / "qemu-output"
            output.write_bytes(
                f"char device redirected to {pty_path} (label serial0)\n".encode(
                    "ascii"
                )
            )
            fake_qemu = self._fake_qemu(root)
            harness = controller.QemuHarness(
                os.fspath(fake_qemu), [os.fspath(output)], root / "qmp.sock", []
            )
            qmp = mock.Mock()
            try:
                with mock.patch.object(
                    controller.QmpClient, "connect", return_value=qmp
                ):
                    console, observed_qmp = harness.start(time.monotonic() + 2)
                self.assertIs(observed_qmp, qmp)
                self.assertIsNotNone(console)
                self.assertIn(
                    b"diagnostic-on-stderr\nchar device redirected to ",
                    harness.output_capture.snapshot(),
                )
            finally:
                harness.cleanup()
                os.close(slave)
                os.close(master)

    def test_qemu_harness_output_failures_are_closed_and_bounded(self) -> None:
        secret = bytearray(os.urandom(32).hex().encode("ascii"))
        try:
            for name, output_bytes, expected in [
                ("missing", b"ordinary diagnostic\n", ("serial", "pty-missing")),
                (
                    "malformed",
                    b"char device redirected to /tmp/not-a-pty (label serial0)\n",
                    ("serial", "pty-missing"),
                ),
                (
                    "oversized",
                    b"x" * (controller.QEMU_OUTPUT_LIMIT + 1),
                    ("qemu-output", "oversized"),
                ),
                ("secret", bytes(secret), ("qemu-output", "secret-exposure")),
            ]:
                with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    root.chmod(0o700)
                    output = root / "qemu-output"
                    output.write_bytes(output_bytes)
                    fake_qemu = self._fake_qemu(root)
                    capture_secrets = [secret] if name == "secret" else []
                    harness = controller.QemuHarness(
                        os.fspath(fake_qemu),
                        [os.fspath(output)],
                        root / "qmp.sock",
                        capture_secrets,
                    )
                    try:
                        with self.assertRaises(controller.ClosedFailure) as failure:
                            deadline_seconds = 2.0 if name in {"oversized", "secret"} else 0.25
                            harness.start(time.monotonic() + deadline_seconds)
                        self.assertEqual(
                            (failure.exception.stage, failure.exception.code), expected
                        )
                    finally:
                        harness.cleanup()
        finally:
            controller.wipe(secret)

    @staticmethod
    def _fake_qemu(root: Path) -> Path:
        fake_qemu = root / "fake-qemu"
        fake_qemu.write_text(
            """#!/usr/bin/python3
import os
import sys
import time

os.write(2, b"diagnostic-on-stderr\\n")
with open(sys.argv[1], "rb", buffering=0) as source:
    while True:
        chunk = source.read(4096)
        if not chunk:
            break
        os.write(1, chunk)
time.sleep(60)
""",
            encoding="ascii",
        )
        fake_qemu.chmod(0o700)
        return fake_qemu

    def test_cleanup_kills_the_entire_owned_process_group_boundedly(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            harness = controller.QemuHarness(
                "/bin/true", [], Path(directory) / "qmp.sock", []
            )
            harness.process = subprocess.Popen(
                ["/bin/sh", "-c", "sleep 60"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
            process_group = harness.process.pid
            harness.cleanup()
            self.assertIsNotNone(harness.process.poll())
            with self.assertRaises(ProcessLookupError):
                os.killpg(process_group, 0)

    def test_cleanup_rejects_a_descendant_left_after_successful_parent_exit(self) -> None:
        process = subprocess.Popen(
            ["/bin/sh", "-c", "trap '' HUP; sleep 60 & exit 0"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        process.wait(timeout=2)
        with self.assertRaises(controller.ClosedFailure) as failure:
            controller.cleanup_owned_process_group(process)
        self.assertEqual(failure.exception.code, "process-group-residue")
        self.assertFalse(controller.process_group_exists(process.pid))

    def test_cleanup_never_unlinks_a_preexisting_unowned_qmp_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            qmp_path = Path(directory) / "qmp.sock"
            qmp_path.write_bytes(b"preexisting")
            harness = controller.QemuHarness("/bin/true", [], qmp_path, [])
            with self.assertRaises(controller.ClosedFailure):
                harness.start(time.monotonic() + 1)
            harness.cleanup()
            self.assertEqual(qmp_path.read_bytes(), b"preexisting")


class SanitizedOutputTests(unittest.TestCase):
    def test_main_mock_never_emits_secret_or_qemu_data(self) -> None:
        correct_raw = b"0123456789abcdef" * 4
        wrong_raw = b"fedcba9876543210" * 4
        fake_qmp = mock.Mock()
        fake_harness = mock.Mock()
        fake_harness.start.return_value = (mock.Mock(), fake_qmp)
        parsed = SimpleNamespace(
            firmware="bios",
            boot=1,
            correct_key_fd=3,
            wrong_key_fd=4,
            login_credential_fd=5,
            owned_pgid_fd=6,
            qmp_socket=Path("/tmp/qmp-test.sock"),
            timeout=1200,
            qemu="/usr/bin/qemu-system-x86_64",
            qemu_args=["-m", "2048"],
        )
        login_credential = synthetic_login_credential()
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            mock.patch.object(controller, "parse_arguments", return_value=parsed),
            mock.patch.object(
                controller,
                "read_secret_fd",
                side_effect=[bytearray(correct_raw), bytearray(wrong_raw)],
            ),
            mock.patch.object(
                controller,
                "read_login_credential_fd",
                return_value=bytearray(login_credential),
            ),
            mock.patch.object(controller, "QemuHarness", return_value=fake_harness),
            mock.patch.object(
                controller,
                "run_lifecycle",
                return_value=(10, 16, "KA-0123456789abcdef01234567"),
            ),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            self.assertEqual(controller.main([]), 0)
        combined = (stdout.getvalue() + stderr.getvalue()).encode("ascii")
        self.assertNotIn(correct_raw, combined)
        self.assertNotIn(wrong_raw, combined)
        self.assertNotIn(login_credential, combined)
        self.assertEqual(stderr.getvalue(), "")
        self.assertRegex(
            stdout.getvalue(),
            r"^KERNAID_QEMU_VAULT_LIFECYCLE_BOOT_V1 .+ acpi_shutdown=true\n$",
        )
        fake_qmp.system_powerdown.assert_called_once_with()
        fake_harness.wait_for_shutdown.assert_called_once()
        fake_harness.cleanup.assert_called_once_with()

    def test_cleanup_failure_dominates_a_success_attestation(self) -> None:
        correct_raw = b"0123456789abcdef" * 4
        wrong_raw = b"fedcba9876543210" * 4
        fake_harness = mock.Mock()
        fake_harness.start.return_value = (mock.Mock(), mock.Mock())
        fake_harness.cleanup.side_effect = controller.ClosedFailure(
            "cleanup", "qemu-residue"
        )
        parsed = SimpleNamespace(
            firmware="bios",
            boot=1,
            correct_key_fd=3,
            wrong_key_fd=4,
            login_credential_fd=5,
            owned_pgid_fd=6,
            qmp_socket=Path("/tmp/qmp-test.sock"),
            timeout=1200,
            qemu="/usr/bin/qemu-system-x86_64",
            qemu_args=["-m", "2048"],
        )
        login_credential = synthetic_login_credential()
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            mock.patch.object(controller, "parse_arguments", return_value=parsed),
            mock.patch.object(
                controller,
                "read_secret_fd",
                side_effect=[bytearray(correct_raw), bytearray(wrong_raw)],
            ),
            mock.patch.object(
                controller,
                "read_login_credential_fd",
                return_value=bytearray(login_credential),
            ),
            mock.patch.object(controller, "QemuHarness", return_value=fake_harness),
            mock.patch.object(
                controller,
                "run_lifecycle",
                return_value=(10, 16, "KA-0123456789abcdef01234567"),
            ),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            self.assertEqual(controller.main([]), 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(
            stderr.getvalue(),
            "KERNAID_QEMU_VAULT_LIFECYCLE_FAILURE_V1 "
            "stage=cleanup code=qemu-residue\n",
        )

    def test_controller_signal_maps_to_closed_interruption(self) -> None:
        if not hasattr(signal, "pthread_sigmask") or not hasattr(signal, "sigwait"):
            self.skipTest("POSIX signal masks are required")
        original = signal.pthread_sigmask(signal.SIG_BLOCK, [])
        try:
            with self.assertRaises(controller.ControllerSignal):
                controller._raise_controller_signal(signal.SIGINT, None)
            blocked = signal.pthread_sigmask(signal.SIG_BLOCK, [])
            self.assertTrue(set(controller.HANDLED_SIGNALS).issubset(blocked))
            os.kill(os.getpid(), signal.SIGTERM)
            self.assertIn(signal.SIGTERM, signal.sigpending())
            self.assertEqual(signal.sigwait({signal.SIGTERM}), signal.SIGTERM)
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, original)

    def test_failure_is_one_closed_line(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            mock.patch.object(
                controller,
                "parse_arguments",
                side_effect=controller.ClosedFailure("arguments", "invalid"),
            ),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            self.assertEqual(controller.main([]), 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(
            stderr.getvalue(),
            "KERNAID_QEMU_VAULT_LIFECYCLE_FAILURE_V1 "
            "stage=arguments code=invalid\n",
        )

    def test_argument_parser_never_repeats_an_attacker_value(self) -> None:
        attacker_value = "DO_NOT_REPEAT_0123456789abcdef"
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            self.assertEqual(controller.main(["--unknown", attacker_value]), 1)
        combined = stdout.getvalue() + stderr.getvalue()
        self.assertNotIn(attacker_value, combined)
        self.assertEqual(
            combined,
            "KERNAID_QEMU_VAULT_LIFECYCLE_FAILURE_V1 "
            "stage=arguments code=invalid\n",
        )


class LoopDetachTests(unittest.TestCase):
    @staticmethod
    def loop_status(
        backing: object,
        *,
        number: int = 7,
        offset: int = 4096,
        size_limit: int = 8192,
        flags: int = 0,
    ) -> bytes:
        return controller.LOOP_INFO64.pack(
            backing.st_dev,
            backing.st_ino,
            backing.st_rdev,
            offset,
            size_limit,
            number,
            0,
            0,
            flags,
            b"",
            b"",
            b"",
            0,
            0,
        )

    def invoke_clear(
        self,
        encoded: bytes,
        *,
        clear_errors: list[int] | None = None,
    ) -> list[tuple[int, int]]:
        loop_fd = os.open("/dev/null", os.O_RDONLY)
        backing_fd = os.open("/dev/null", os.O_RDONLY)
        loop_status = SimpleNamespace(
            st_mode=stat.S_IFBLK | 0o660,
            st_rdev=os.makedev(7, 7),
        )
        backing_status = SimpleNamespace(
            st_mode=stat.S_IFREG | 0o600,
            st_dev=41,
            st_ino=73,
            st_rdev=0,
            st_nlink=1,
        )
        calls: list[tuple[int, int]] = []
        errors = list(clear_errors or [])

        def fake_ioctl(descriptor: int, operation: int, *args: object) -> int:
            calls.append((descriptor, operation))
            if operation == controller.LOOP_GET_STATUS64:
                buffer = args[0]
                assert isinstance(buffer, bytearray)
                buffer[:] = encoded
                return 0
            if operation == controller.LOOP_CLR_FD:
                if errors:
                    raise OSError(errors.pop(0), "injected")
                return 0
            raise AssertionError("unexpected ioctl")

        with (
            mock.patch.object(
                controller.os,
                "fstat",
                side_effect=lambda descriptor: (
                    loop_status if descriptor == loop_fd else backing_status
                ),
            ),
            mock.patch.object(controller.fcntl, "fcntl", return_value=0),
            mock.patch.object(controller.fcntl, "ioctl", side_effect=fake_ioctl),
        ):
            controller.clear_owned_loop_fd(
                loop_fd,
                backing_fd,
                expected_number=7,
                expected_offset=4096,
                expected_size_limit=8192,
                expected_read_only=False,
            )
        return calls

    def test_same_descriptor_validates_full_mapping_then_clears(self) -> None:
        backing = SimpleNamespace(st_dev=41, st_ino=73, st_rdev=0)
        calls = self.invoke_clear(self.loop_status(backing))
        self.assertEqual(
            [operation for _, operation in calls],
            [controller.LOOP_GET_STATUS64, controller.LOOP_CLR_FD],
        )
        self.assertEqual(calls[0][0], calls[1][0])

        retried = self.invoke_clear(
            self.loop_status(backing), clear_errors=[errno.EINTR, errno.EINTR]
        )
        self.assertEqual(
            [operation for _, operation in retried],
            [
                controller.LOOP_GET_STATUS64,
                controller.LOOP_CLR_FD,
                controller.LOOP_CLR_FD,
                controller.LOOP_CLR_FD,
            ],
        )
        self.assertEqual(len({descriptor for descriptor, _ in retried}), 1)

    def test_mismatched_identity_slice_or_flags_never_clears(self) -> None:
        backing = SimpleNamespace(st_dev=41, st_ino=73, st_rdev=0)
        mismatches = [
            self.loop_status(SimpleNamespace(st_dev=42, st_ino=73, st_rdev=0)),
            self.loop_status(backing, number=8),
            self.loop_status(backing, offset=4097),
            self.loop_status(backing, size_limit=8193),
            self.loop_status(backing, flags=controller.LO_FLAGS_READ_ONLY),
            self.loop_status(backing, flags=8),
        ]
        for encoded in mismatches:
            with self.assertRaises(controller.ClosedFailure) as failure:
                self.invoke_clear(encoded)
            self.assertEqual(failure.exception.code, "mapping-mismatch")

    def test_controller_invocation_has_an_outer_wall_clock_bound(self) -> None:
        shell = SCRIPT.read_text(encoding="utf-8")
        self.assertIn(
            "timeout --foreground --signal=TERM --kill-after=1s 3s \\\n"
            '    python3 -I -B "$controller" --clear-owned-loop',
            shell,
        )
        started = time.monotonic()
        result = subprocess.run(
            [
                "timeout",
                "--foreground",
                "--signal=TERM",
                "--kill-after=1s",
                "0.1s",
                sys.executable,
                "-c",
                "import time; time.sleep(60)",
            ],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2,
        )
        self.assertEqual(result.returncode, 124)
        self.assertLess(time.monotonic() - started, 2)


class StaticContractTests(unittest.TestCase):

    def test_new_shell_is_syntactically_valid_and_scope_is_separate(self) -> None:
        subprocess.run(["bash", "-n", SCRIPT], check=True)
        shell = SCRIPT.read_text(encoding="utf-8")
        python = CONTROLLER.read_text(encoding="utf-8")
        self.assertIn("readonly media_bytes=32000000000", shell)
        self.assertIn("readonly boot_count=2", shell)
        self.assertIn("/dev/shm/kernaid-qemu-vault-lifecycle-key.", shell)
        self.assertIn("--correct-key-fd 3 --wrong-key-fd 4", shell)
        self.assertIn('3<"$correct_key" 4<"$wrong_key"', shell)
        self.assertIn("--login-credential-fd 5", shell)
        self.assertIn('5<"$login_credential"', shell)
        self.assertIn("unsquashfs -cat", shell)
        self.assertIn("0030-user-setup", shell)
        self.assertIn("squashfs-tools", shell)
        self.assertIn("--extract-live-credential", shell)
        self.assertIn("--clear-owned-loop", shell)
        self.assertIn('6<"$loop_device" 7<"$expected_backing"', shell)
        self.assertNotIn("losetup -d --", shell)
        self.assertIn("--timeout 1200", shell)
        self.assertIn('kill -s "$signal_name" "$controller_pid"', shell)
        self.assertNotIn("-fw_cfg", shell)
        self.assertNotIn('sha256_file "$correct_key"', shell)
        self.assertNotIn('sha256_file "$wrong_key"', shell)
        sources = shell + python + Path(__file__).read_text(encoding="utf-8")
        self.assertIsNone(
            re.search(r"Default password is: [./0-9A-Za-z]+", sources),
            "no default login credential may be stored in source or fixtures",
        )
        self.assertIsNone(
            re.search(r'_PASSWORD=[\\\"\']+[./0-9A-Za-z]{13}', sources),
            "no production-style login verifier may be stored in source or fixtures",
        )
        self.assertIsNone(
            re.search(
                r"(?:bytes|bytearray)\(\(\s*(?:[0-9]{2,3}\s*,\s*){3,}",
                sources,
            ),
            "credentials must not be hidden as integer byte fixtures",
        )
        self.assertIn("p3_expected_rw=true", shell)
        self.assertNotIn(
            '"$p3_after_sha256" == "$p3_before_sha256"', shell
        )
        self.assertIn("observe_immutable=true", shell)
        self.assertIn("swap_immutable=true", shell)
        self.assertIn("p3_guest_after_sha256=", shell)
        self.assertIn("p3_post_verify_sha256=", shell)
        self.assertIn("run_host_probe postverify verify", shell)
        self.assertIn("--run-bounded-probe", shell)
        self.assertIn("PROBE_OUTPUT_LIMIT = 256", python)
        self.assertIn("start_new_session=True", python)
        self.assertIn("--owned-pgid-fd 6", shell)
        self.assertIn("guest_device_id_derived=true", shell)
        self.assertIn('"-serial",\n            "pty"', python)
        self.assertIn("qmp.system_powerdown()", python)
        self.assertIn("close_fds=True", python)
        self.assertIn("SERIAL_LIMIT = 2 * 1024 * 1024", python)
        self.assertIn("ACPI_SHUTDOWN_SECONDS = 180.0", python)
        self.assertIn("parent_procs=empty", python)
        self.assertIn("swaps_empty=true", python)
        self.assertLess(
            len(controller._runtime_command("maximum-stage")),
            4096,
            "the guest TTY canonical input line must remain bounded",
        )


if __name__ == "__main__":
    unittest.main()
