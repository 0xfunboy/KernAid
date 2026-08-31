from __future__ import annotations

import contextlib
import ctypes
import errno
import importlib.util
import inspect
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
import tty
import unittest
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


TOOLS_DIR = Path(__file__).resolve().parents[1]
REPO_DIR = Path(__file__).resolve().parents[3]
CONTROLLER = TOOLS_DIR / "qemu-vault-lifecycle-pty.py"
SCRIPT = TOOLS_DIR / "qemu-vault-lifecycle-smoke.sh"
VAULT_SERVICE = (
    REPO_DIR
    / "rescue/live-build/config/includes.chroot/etc/systemd/system"
    / "kernaid-rescue-vaultd.service"
)
READY_CHECK = (
    REPO_DIR
    / "rescue/live-build/config/includes.chroot/usr/lib/kernaid/ready-check"
)


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
    service_cap = controller.CAP_SYS_ADMIN_AND_KILL
    worker_cap = controller.CAP_SYS_ADMIN_ONLY
    return (
        f"KERNAID_VAULT_RUNTIME_V1 stage={stage} service_pid=101 worker_pid=102 "
        "worker_ppid=101 "
        "invocation_id=0123456789abcdef0123456789abcdef "
        f"service_caps={zero}:{service_cap}:{service_cap}:{service_cap} "
        f"worker_caps={zero}:{worker_cap}:{worker_cap}:{worker_cap} "
        f"service_ambient={zero} worker_ambient={zero} "
        "service_nnp=1 worker_nnp=1 service_core=0:0 worker_core=0:0 "
        "systemd_control_group=unit service_cgroup=supervisor "
        "worker_cgroup=worker identity_stable=true "
        f"mapper_count={mapper_count} shell_mount=false swaps_empty=true "
        "service_state=active-running socket_state=operational"
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

    def test_serial_close_rechecks_and_reports_a_sanitized_qemu_signal(self) -> None:
        read_fd, write_fd = os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC)
        capture = controller.BoundedCapture(1024, [])
        checks = 0

        def health() -> None:
            nonlocal checks
            checks += 1
            if checks >= 2:
                raise controller.ClosedFailure("qemu", "exited-signal")

        console = controller.SerialConsole(read_fd, capture, health)
        os.close(write_fd)
        try:
            with self.assertRaises(controller.ClosedFailure) as failure:
                console._drain_immediately_available()
            self.assertEqual(
                (failure.exception.stage, failure.exception.code),
                ("qemu", "exited-signal"),
            )
            self.assertEqual(str(failure.exception), "qemu:exited-signal")
            self.assertGreaterEqual(checks, 2)
            self.assertEqual(capture.snapshot(), b"")
        finally:
            console.close()
            capture.wipe()

    def test_serial_close_stays_generic_when_qemu_remains_live(self) -> None:
        read_fd, write_fd = os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC)
        capture = controller.BoundedCapture(1024, [])
        console = controller.SerialConsole(read_fd, capture, lambda: None)
        os.close(write_fd)
        started = time.monotonic()
        try:
            with self.assertRaises(controller.ClosedFailure) as failure:
                console._drain_immediately_available()
            self.assertEqual(
                (failure.exception.stage, failure.exception.code),
                ("serial", "closed"),
            )
            self.assertLess(time.monotonic() - started, 0.25)
        finally:
            console.close()
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

    def test_real_interactive_bash_proof_success_and_failure_are_prompt(self) -> None:
        for success in (True, False):
            with self.subTest(success=success), self.real_interactive_bash_console() as (
                console,
                _capture,
                credential,
            ):
                aggregate = time.monotonic() + 60.0
                cursor = controller.establish_live_session(
                    console, aggregate, credential
                )
                stage = "real-pty-proof"
                if success:
                    source = (
                        "import sys;sys.stdout.write("
                        f"'KERNAID_QEMU_PROVIDER_PROOF_V1 stage={stage} "
                        "result=true\\n')"
                    ).encode()
                else:
                    source = b"raise SystemExit(45)"
                started = time.monotonic()
                if success:
                    self.assertGreater(
                        controller.run_guest_proof(
                            console,
                            stage,
                            source,
                            cursor,
                            aggregate,
                            timeout=2.0,
                        ),
                        cursor,
                    )
                else:
                    with self.assertRaises(controller.ClosedFailure) as failure:
                        controller.run_guest_proof(
                            console,
                            stage,
                            source,
                            cursor,
                            aggregate,
                            timeout=2.0,
                        )
                    self.assertEqual(
                        (failure.exception.stage, failure.exception.code),
                        ("provider-proof", "command-failed"),
                    )
                self.assertLess(time.monotonic() - started, 1.0)

    def test_real_pty_not_ready_precedes_ready_without_exposing_reason(self) -> None:
        master, slave = os.openpty()
        tty.setraw(slave)
        credential = bytearray(synthetic_login_credential())
        capture = controller.BoundedCapture(4096, [credential])
        console = controller.SerialConsole(slave, capture, lambda: None)
        private_reason = b"private-reason=must-not-escape"
        try:
            os.write(
                master,
                b"midline KERNAID_RESCUE_NOT_READY: decoy\r\n"
                + controller.READY_LINE
                + b"\r\n"
                + controller.NOT_READY_LINE_PREFIX
                + b" "
                + private_reason
                + b"\r\n",
            )
            with self.assertRaises(controller.ClosedFailure) as failure:
                controller.establish_live_session(
                    console, time.monotonic() + 2.0, credential
                )
            self.assertEqual(
                (failure.exception.stage, failure.exception.code),
                ("readiness", "not-ready"),
            )
            self.assertNotIn(
                private_reason.decode("ascii"), str(failure.exception)
            )
            self.assertIsNone(
                controller.NOT_READY_PREFIX_PATTERN.search(
                    b"midline " + controller.NOT_READY_LINE_PREFIX
                )
            )
        finally:
            console.close()
            os.close(master)
            controller.wipe(credential)
            capture.wipe()

    def test_not_ready_exposes_only_a_contextual_allowlisted_tauri_stage(self) -> None:
        declared_stages = set(
            re.findall(
                rb"KERNAID_RESCUE_TAURI_GUEST_FAILURE_V1 stage=([a-z0-9-]+)",
                READY_CHECK.read_bytes(),
            )
        )
        self.assertEqual(set(controller.TAURI_GUEST_FAILURE_STAGES), declared_stages)
        private_reason = b"private-reason=must-not-escape"
        cases = (
            (
                b"\r\nKERNAID_RESCUE_TAURI_GUEST_FAILURE_V1 stage=renderer\r\n\r\n",
                "not-ready-tauri-renderer",
            ),
            (
                b"midline KERNAID_RESCUE_TAURI_GUEST_FAILURE_V1 stage=renderer\r\n\r\n",
                "not-ready",
            ),
            (
                b"\r\nKERNAID_RESCUE_TAURI_GUEST_FAILURE_V1 stage=private-stage\r\n\r\n",
                "not-ready",
            ),
            (
                b"\r\nKERNAID_RESCUE_TAURI_GUEST_FAILURE_V1 stage=renderer\r\n"
                b"unrelated line\r\n",
                "not-ready",
            ),
        )
        for prefix, expected_code in cases:
            with self.subTest(expected_code=expected_code, prefix=prefix):
                master, slave = os.openpty()
                tty.setraw(slave)
                capture = controller.BoundedCapture(4096, [])
                console = controller.SerialConsole(slave, capture, lambda: None)
                try:
                    os.write(
                        master,
                        prefix
                        + controller.NOT_READY_LINE_PREFIX
                        + b" "
                        + private_reason
                        + b"\r\n",
                    )
                    with self.assertRaises(controller.ClosedFailure) as failure:
                        console.wait_line(
                            b"KERNAID_TEST_NEVER_READY",
                            start=0,
                            deadline=time.monotonic() + 1.0,
                            stage="requested",
                        )
                    self.assertEqual(
                        (failure.exception.stage, failure.exception.code),
                        ("readiness", expected_code),
                    )
                    self.assertNotIn(
                        private_reason.decode("ascii"), str(failure.exception)
                    )
                finally:
                    console.close()
                    os.close(master)
                    capture.wipe()

    def test_real_pty_ready_then_not_ready_aborts_a_completable_login(self) -> None:
        import select

        master, slave = os.openpty()
        tty.setraw(slave)
        credential = bytearray(synthetic_login_credential())
        capture = controller.BoundedCapture(8192, [credential])
        console = controller.SerialConsole(slave, capture, lambda: None)
        private_reason = b"private-reason=must-not-escape"
        responder_errors: list[str] = []

        def read_line(timeout: float) -> bytes | None:
            deadline = time.monotonic() + timeout
            received = bytearray()
            while time.monotonic() < deadline:
                readable, _, _ = select.select(
                    [master], [], [], max(0.0, deadline - time.monotonic())
                )
                if not readable:
                    continue
                chunk = os.read(master, 4096)
                if not chunk:
                    return None
                received.extend(chunk)
                if b"\n" in received:
                    return bytes(received)
            return None

        def complete_login_if_controller_continues() -> None:
            try:
                os.write(master, controller.READY_LINE + b"\r\n")
                if read_line(1.0) is None:
                    responder_errors.append("ready-not-consumed")
                    return
                os.write(
                    master,
                    controller.NOT_READY_LINE_PREFIX
                    + b" "
                    + private_reason
                    + b"\r\n",
                )
                os.write(master, b"kernaid-rescue login: ")
                if read_line(0.25) is None:
                    return
                os.write(master, b"\r\nPassword: ")
                if read_line(0.25) is None:
                    return
                os.write(master, b"\r\nkernaid@kernaid-rescue:~$ ")
                if read_line(0.25) is None:
                    return
                os.write(
                    master,
                    b"\r\n" + controller.LOGIN_OK_LINE + b"\r\n",
                )
            except BaseException:
                responder_errors.append("responder-failed")

        responder = threading.Thread(target=complete_login_if_controller_continues)
        responder.start()
        try:
            with self.assertRaises(controller.ClosedFailure) as failure:
                controller.establish_live_session(
                    console, time.monotonic() + 3.0, credential
                )
            self.assertEqual(
                (failure.exception.stage, failure.exception.code),
                ("readiness", "not-ready"),
            )
            self.assertNotIn(private_reason.decode("ascii"), str(failure.exception))
        finally:
            responder.join(2.0)
            console.close()
            os.close(master)
            controller.wipe(credential)
            capture.wipe()
        self.assertFalse(responder.is_alive())
        self.assertEqual(responder_errors, [])

    def test_wait_regex_retains_overlap_and_prioritizes_queued_not_ready(self) -> None:
        master, slave = os.openpty()
        tty.setraw(slave)
        capture = controller.BoundedCapture(4096, [])
        console = controller.SerialConsole(slave, capture, lambda: None)
        private_reason = b"private-reason=must-not-escape"
        split = len(controller.NOT_READY_LINE_PREFIX) - 5
        prefix_part = controller.NOT_READY_LINE_PREFIX[:split]
        suffix_part = controller.NOT_READY_LINE_PREFIX[split:]
        target = b"KERNAID_TEST_REQUESTED_MATCH_V1"
        try:
            os.write(master, b"x" * 128 + b"\r\n" + prefix_part)
            partial = console.wait_regex(
                re.compile(re.escape(prefix_part) + rb"$"),
                start=0,
                deadline=time.monotonic() + 1.0,
                stage="partial",
            )
            self.assertGreater(partial.start(), controller.NOT_READY_SCAN_OVERLAP)
            os.write(
                master,
                suffix_part
                + b" "
                + private_reason
                + b"\r\n"
                + target
                + b"\r\n",
            )
            with self.assertRaises(controller.ClosedFailure) as failure:
                console.wait_line(
                    target,
                    start=partial.end(),
                    deadline=time.monotonic() + 1.0,
                    stage="requested",
                )
            self.assertEqual(
                (failure.exception.stage, failure.exception.code),
                ("readiness", "not-ready"),
            )
            self.assertNotIn(private_reason.decode("ascii"), str(failure.exception))
        finally:
            console.close()
            os.close(master)
            capture.wipe()

    def test_wait_regex_drains_queued_not_ready_before_a_captured_match(self) -> None:
        import select

        master, slave = os.openpty()
        tty.setraw(slave)
        private_reason = b"private-reason=must-not-escape"
        capture = controller.BoundedCapture(4096, [])
        capture.append(controller.READY_LINE + b"\r\n")
        console = controller.SerialConsole(slave, capture, lambda: None)
        try:
            os.write(
                master,
                controller.NOT_READY_LINE_PREFIX
                + b" "
                + private_reason
                + b"\r\n",
            )
            readable, _, _ = select.select([slave], [], [], 1.0)
            self.assertEqual(readable, [slave])
            with self.assertRaises(controller.ClosedFailure) as failure:
                console.wait_regex(
                    controller.READY_RESULT_PATTERN,
                    start=0,
                    deadline=time.monotonic() + 1.0,
                    stage="requested",
                )
            self.assertEqual(
                (failure.exception.stage, failure.exception.code),
                ("readiness", "not-ready"),
            )
            self.assertNotIn(private_reason.decode("ascii"), str(failure.exception))
        finally:
            console.close()
            os.close(master)
            capture.wipe()

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
                b"systemd_control_group=unit",
                b"systemd_control_group=invalid",
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
                failure.exception.code, "systemd-control-group-invalid"
            )
            self.assertEqual(
                str(failure.exception),
                "runtime:systemd-control-group-invalid",
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

    def test_unlock_parser_classifies_only_closed_public_remote_errors(self) -> None:
        with self.assertRaises(controller.ClosedFailure) as classified:
            controller.parse_companion_response(
                b"READY\nVault passphrase: \nstateVersion: 24\nerror: IO_FAILED\n",
                command="unlock",
                return_code=1,
            )
        self.assertEqual(classified.exception.stage, "response")
        self.assertEqual(classified.exception.code, "unlock-remote-io-failed")
        self.assertIsInstance(classified.exception, controller.UnlockRemoteFailure)
        self.assertEqual(classified.exception.state_version, 24)
        self.assertNotIn("24", str(classified.exception))

        with self.assertRaises(controller.ClosedFailure) as unknown:
            controller.parse_companion_response(
                b"READY\nVault passphrase: \nstateVersion: 24\nerror: FUTURE_ERROR\n",
                command="unlock",
                return_code=1,
            )
        self.assertEqual(unknown.exception.stage, "response")
        self.assertEqual(unknown.exception.code, "unlock-invalid")

    def test_lock_parser_classifies_only_exact_faulted_reboot_response(self) -> None:
        with self.assertRaises(controller.ClosedFailure) as classified:
            controller.parse_companion_response(
                b"stateVersion: 28\nvaultState: faulted-reboot-required\n"
                b"error: REBOOT_REQUIRED\n",
                command="lock",
                return_code=1,
            )
        self.assertEqual(classified.exception.stage, "response")
        self.assertEqual(
            classified.exception.code, "lock-remote-reboot-required"
        )

        for block in [
            b"stateVersion: 28\nvaultState: faulted-reboot-required\n"
            b"error: FUTURE_ERROR\n",
            b"stateVersion: 28\nvaultState: faulted-reboot-required\n"
            b"error: REBOOT_REQUIRED\nextra\n",
        ]:
            with self.subTest(block=block), self.assertRaises(
                controller.ClosedFailure
            ) as rejected:
                controller.parse_companion_response(
                    block, command="lock", return_code=1
                )
            self.assertEqual(rejected.exception.code, "extra-output")

    def test_provider_companion_parser_is_exact_and_boot_prior_is_correlated(self) -> None:
        configured = controller.ProviderCompanionResponse(
            16, "configured", "unconfigured", None, 0
        )
        self.assertEqual(
            controller.parse_provider_companion_response(
                b"READY\nOpenAI API key: \nstateVersion: 16\n"
                b"openai: configured\ncodex: unconfigured\n",
                command="openai-configure",
                return_code=0,
            ),
            configured,
        )
        self.assertEqual(
            controller.parse_provider_companion_response(
                b"stateVersion: 0\nvaultState: faulted-reboot-required\n"
                b"error: REBOOT_REQUIRED\n",
                command="provider-status",
                return_code=1,
            ),
            controller.ProviderCompanionResponse(
                0, None, None, "REBOOT_REQUIRED", 1
            ),
        )
        for invalid_fault in (
            b"stateVersion: 0\nerror: REBOOT_REQUIRED\n",
            b"stateVersion: 0\nvaultState: faulted-reboot-required\n",
            b"stateVersion: 0\nerror: REBOOT_REQUIRED\n"
            b"vaultState: faulted-reboot-required\n",
            b"stateVersion: 0\nvaultState: faulted-reboot-required\n"
            b"error: OTHER\n",
        ):
            with self.subTest(invalid_fault=invalid_fault), self.assertRaises(
                controller.ClosedFailure
            ):
                controller.parse_provider_companion_response(
                    invalid_fault,
                    command="provider-status",
                    return_code=1,
                )
        with self.assertRaises(controller.ClosedFailure):
            controller.parse_provider_companion_response(
                b"stateVersion: 0\nvaultState: faulted-reboot-required\n"
                b"error: REBOOT_REQUIRED\n",
                command="provider-status",
                return_code=2,
            )
        unlocked = response(
            14, "unlocked", "KA-0123456789abcdef01234567"
        )
        for boot, prior_state in ((1, "unconfigured"), (2, "configured")):
            with self.subTest(boot=boot):
                controller.validate_provider_configuration(
                    unlocked,
                    controller.ProviderCompanionResponse(
                        14, prior_state, "unconfigured", None, 0
                    ),
                    configured,
                    configured,
                    boot,
                )
        with self.assertRaises(controller.ClosedFailure):
            controller.validate_provider_configuration(
                unlocked,
                controller.ProviderCompanionResponse(
                    14, "unconfigured", "unconfigured", None, 0
                ),
                configured,
                configured,
                2,
            )

    def test_clean_provider_lifecycle_versions_lock_after_configure(self) -> None:
        device_id = "KA-0123456789abcdef01234567"
        initial = response(10, "locked")
        wrong = response(12, error="BAD_PASSPHRASE", return_code=1)
        after_wrong = response(12, "locked")
        unlocked = response(14, "unlocked", device_id)
        prior = controller.ProviderCompanionResponse(
            14, "unconfigured", "unconfigured", None, 0
        )
        configured = controller.ProviderCompanionResponse(
            16, "configured", "unconfigured", None, 0
        )
        report_status = response(24, "unlocked", device_id)
        locked = response(26, "locked")
        self.assertEqual(
            controller.validate_clean_provider_lifecycle(
                initial,
                wrong,
                after_wrong,
                unlocked,
                unlocked,
                prior,
                configured,
                configured,
                report_status,
                locked,
                locked,
                1,
            ),
            device_id,
        )
        with self.assertRaises(controller.ClosedFailure):
            controller.validate_clean_provider_lifecycle(
                initial,
                wrong,
                after_wrong,
                unlocked,
                unlocked,
                prior,
                configured,
                configured,
                report_status,
                response(24, "locked"),
                response(24, "locked"),
                1,
            )

    def test_fault_epoch_statuses_must_match_without_mutation(self) -> None:
        device_id = "KA-0123456789abcdef01234567"
        lifecycle = (
            response(10, "locked"),
            response(12, error="BAD_PASSPHRASE", return_code=1),
            response(12, "locked"),
            response(14, "unlocked", device_id),
            response(14, "unlocked", device_id),
            controller.ProviderCompanionResponse(
                14, "configured", "unconfigured", None, 0
            ),
            controller.ProviderCompanionResponse(
                16, "configured", "unconfigured", None, 0
            ),
            controller.ProviderCompanionResponse(
                16, "configured", "unconfigured", None, 0
            ),
            response(24, "unlocked", device_id),
            response(0, "faulted-reboot-required"),
        )
        self.assertEqual(
            controller.validate_provider_fault_lifecycle(
                *lifecycle,
                controller.ProviderCompanionResponse(
                    0, None, None, "REBOOT_REQUIRED", 1
                ),
                2,
            ),
            device_id,
        )
        with self.assertRaises(controller.ClosedFailure) as failure:
            controller.validate_provider_fault_lifecycle(
                *lifecycle,
                controller.ProviderCompanionResponse(
                    1, None, None, "REBOOT_REQUIRED", 1
                ),
                2,
            )
        self.assertEqual(failure.exception.code, "persistent-fault-invalid")

    def test_boot_attestation_separates_clean_and_fault_epochs(self) -> None:
        device_id = "KA-0123456789abcdef01234567"
        clean = controller.boot_attestation("bios", 1, 10, 24, 26, device_id)
        self.assertIn("terminal=clean-lock", clean)
        self.assertIn("hold_killed_vaultd=false", clean)
        self.assertIn("pre_terminal_daemon_stable=true", clean)
        self.assertIn("production_ui_provider_relay_path=true", clean)
        self.assertIn("signed_report_path=true", clean)
        self.assertNotIn(" daemon_stable=true", clean)
        fault = controller.boot_attestation("uefi", 2, 10, 24, 0, device_id)
        self.assertIn("terminal=persistent-fault", fault)
        self.assertIn("hold_killed_vaultd=true", fault)
        self.assertIn("pre_terminal_caps_stable=true", fault)
        self.assertNotIn(" caps_stable=true", fault)
        with self.assertRaises(controller.ClosedFailure):
            controller.boot_attestation("bios", 1, 10, 24, 0, device_id)

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

        malformed = ScriptedConsole(
            transcript.replace(
                b"stateVersion: 12\r\n", b"[  12.000000] external console line\r\n"
            )
        )
        with self.assertRaises(controller.ClosedFailure) as observed:
            controller.run_companion(
                malformed,
                "unlock",
                stage,
                0,
                time.monotonic() + 10,
                secret,
            )
        self.assertEqual(observed.exception.stage, stage)
        self.assertEqual(observed.exception.code, "response-version-invalid")
        self.assertIsInstance(observed.exception, controller.ResponseShapeFailure)
        self.assertGreater(observed.exception.block_bytes, 0)
        self.assertEqual(observed.exception.block_lines, 2)
        self.assertRegex(observed.exception.block_sha256, r"^[0-9a-f]{64}$")
        self.assertEqual(observed.exception.first_class, "kernel-timestamp")
        self.assertEqual(observed.exception.return_code, 1)

        remote = ScriptedConsole(
            transcript.replace(
                b"error: BAD_PASSPHRASE", b"error: MEDIA_CHANGED"
            )
        )
        with self.assertRaises(controller.ClosedFailure) as observed:
            controller.run_companion(
                remote,
                "unlock",
                stage,
                0,
                time.monotonic() + 10,
                secret,
            )
        self.assertEqual(observed.exception.stage, stage)
        self.assertEqual(
            observed.exception.code, "response-unlock-remote-media-changed"
        )

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


class UnlockDiagnosticTests(unittest.TestCase):
    expectation = controller.UnlockDiagnosticExpectation(
        service_pid=101,
        invocation_id="0123456789abcdef0123456789abcdef",
        request_state_version=10,
    )

    def run_closed_shell_classifier(
        self,
        status: str,
        *,
        pid: str = "101\n",
        invocation: str = "0123456789abcdef0123456789abcdef\n",
        return_code: int = 0,
    ) -> bytes:
        command = controller._unlock_diagnostic_command(self.expectation, 12)
        command = command.replace(b"/usr/bin/systemctl", b"mock_systemctl")
        command = command.replace(b"/usr/bin/sleep 0.1", b":")
        command = command.replace(b'"$attempt" -lt 50', b'"$attempt" -lt 2')
        command = command.replace(b'"$attempt" -ge 50', b'"$attempt" -ge 2')
        source = b"""
mock_systemctl() {
    case "$2" in
        --property=MainPID) printf '%s' "$TEST_PID" ;;
        --property=InvocationID) printf '%s' "$TEST_INVOCATION" ;;
        --property=StatusText) printf '%s' "$TEST_STATUS" ;;
        *) return 9 ;;
    esac
    return "$TEST_RC"
}
""" + command
        environment = os.environ.copy()
        environment.update(
            {
                "TEST_PID": pid,
                "TEST_INVOCATION": invocation,
                "TEST_STATUS": status,
                "TEST_RC": str(return_code),
            }
        )
        completed = subprocess.run(
            ["/bin/bash", "-c", source],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            timeout=2,
            check=False,
        )
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed.stderr, b"")
        return completed.stdout

    @unittest.skipUnless(Path("/bin/bash").is_file(), "bash required")
    def test_closed_shell_accepts_only_correlated_final_status(self) -> None:
        for reason in controller.UNLOCK_IO_DIAGNOSTIC_REASONS:
            with self.subTest(reason=reason):
                status = (
                    f"{controller.UNLOCK_IO_DIAGNOSTIC_PREFIX} reason={reason} "
                    "state-version=12\n"
                )
                self.assertEqual(
                    self.run_closed_shell_classifier(status),
                    (
                        f"{controller.UNLOCK_IO_DIAGNOSTIC_RESULT_PREFIX} "
                        f"reason={reason}\n"
                    ).encode("ascii"),
                )

        unavailable = (
            f"{controller.UNLOCK_IO_DIAGNOSTIC_RESULT_PREFIX} "
            "reason=diagnostic-unavailable\n"
        ).encode("ascii")
        exact_prefix = controller.UNLOCK_IO_DIAGNOSTIC_PREFIX
        invalid = [
            (f"{exact_prefix} reason=in-progress state-version=10\n", {}),
            (f"{exact_prefix} reason=non-io state-version=12\n", {}),
            (f"{exact_prefix} reason=manager-unsafe-mount-root state-version=11\n", {}),
            (f"{exact_prefix} reason=manager-unsafe-mount-root state-version=012\n", {}),
            (f"{exact_prefix} reason=manager-unsafe-mount-root state-version=12\nextra\n", {}),
            (f"{exact_prefix} reason=future-reason state-version=12\n", {}),
            (f"{exact_prefix} reason=manager-unsafe-mount-root state-version=12", {}),
            ("X" * 300, {}),
            (
                f"{exact_prefix} reason=manager-unsafe-mount-root state-version=12\n",
                {"pid": "102\n"},
            ),
            (
                f"{exact_prefix} reason=manager-unsafe-mount-root state-version=12\n",
                {"invocation": "1123456789abcdef0123456789abcdef\n"},
            ),
            (
                f"{exact_prefix} reason=manager-unsafe-mount-root state-version=12\n",
                {"return_code": 1},
            ),
        ]
        for status, overrides in invalid:
            with self.subTest(status=status[:64], overrides=overrides):
                output = self.run_closed_shell_classifier(status, **overrides)
                self.assertEqual(output, unavailable)
                self.assertNotIn(status.encode("ascii"), output)

    def test_command_is_bounded_and_rejects_invalid_expectations(self) -> None:
        command = controller._unlock_diagnostic_command(self.expectation, 12)
        self.assertIn(b"status=$(bounded StatusText 256)", command)
        self.assertIn(b'/usr/bin/head -c "$2"', command)
        self.assertIn(b'case "$status" in', command)
        self.assertIn(b'pid1=$(bounded MainPID 64)', command)
        self.assertIn(b'pid2=$(bounded MainPID 64)', command)
        self.assertIn(b'inv1=$(bounded InvocationID 64)', command)
        self.assertIn(b'inv2=$(bounded InvocationID 64)', command)
        self.assertNotIn(b"echo", command)
        self.assertNotIn(b'printf \'%s\\n\' "$status"', command)
        self.assertLess(len(command), 8192)

        invalid = [
            controller.UnlockDiagnosticExpectation(
                1, self.expectation.invocation_id, 10
            ),
            controller.UnlockDiagnosticExpectation(
                101, "A" * 32, 10
            ),
            controller.UnlockDiagnosticExpectation(
                101,
                self.expectation.invocation_id,
                controller.MAX_SAFE_STATE_VERSION + 1,
            ),
        ]
        for expectation in invalid:
            with self.subTest(expectation=expectation), self.assertRaises(
                controller.ClosedFailure
            ):
                controller._unlock_diagnostic_command(expectation, 12)
        with self.assertRaises(controller.ClosedFailure):
            controller._unlock_diagnostic_command(
                self.expectation, controller.MAX_SAFE_STATE_VERSION + 1
            )

    def test_exact_io_response_is_refined_without_copying_status(self) -> None:
        secret = bytearray(b"TEST_ONLY_SECRET")
        transcript = (
            b"KERNAID_VAULT_CTL_BEGIN_V1_correct-unlock\r\n"
            b"READY\r\nVault passphrase: \r\n"
            b"stateVersion: 12\r\nerror: IO_FAILED\r\n"
            b"KERNAID_VAULT_CTL_END_V1_correct-unlock rc=1\r\n"
            b"diagnostic-command-echo\r\n"
            b"KERNAID_VAULT_UNLOCK_DIAGNOSTIC_V1 "
            b"reason=manager-unsafe-mount-root\r\n"
        )

        class ScriptedConsole:
            def __init__(self, data: bytes) -> None:
                self.capture = controller.BoundedCapture(16384, [])
                self.capture.append(data)
                self.sent: list[bytes] = []

            def send(self, value: bytes | bytearray, *, deadline: float) -> None:
                del deadline
                self.sent.append(bytes(value))

            def wait_regex(
                self, pattern: object, *, start: int, deadline: float, stage: str
            ) -> object:
                del deadline, stage
                match = pattern.search(self.capture.snapshot(), start)
                if match is None:
                    raise controller.ClosedFailure("scripted", "missing")
                return match

        console = ScriptedConsole(transcript)
        with self.assertRaises(controller.ClosedFailure) as failure:
            controller.run_companion(
                console,
                "unlock",
                "correct-unlock",
                0,
                time.monotonic() + 10,
                secret,
                self.expectation,
            )
        self.assertEqual(failure.exception.stage, "correct-unlock")
        self.assertEqual(
            failure.exception.code,
            "response-unlock-remote-io-failed-manager-unsafe-mount-root",
        )
        self.assertEqual(console.sent[1:3], [bytes(secret), b"\n"])
        self.assertNotIn(bytes(secret), console.sent[-1])
        self.assertIn(b"state-version=12", console.sent[-1])
        self.assertIn(b"state-version=10", console.sent[-1])


class RuntimeEvidenceTests(unittest.TestCase):
    @unittest.skipUnless(
        Path("/usr/bin/pgrep").is_file() and Path("/usr/bin/head").is_file(),
        "pgrep and head required",
    )
    def test_worker_pid_is_one_bounded_direct_child(
        self,
    ) -> None:
        derivation = controller.BOUNDED_CHILD_PID_FUNCTION
        self.assertIn('/usr/bin/pgrep -P "$1"', derivation)
        self.assertIn("/usr/bin/head -n 2", derivation)
        helper_source = """
import subprocess
import sys
import time

count = int(sys.argv[1])
children = [subprocess.Popen(["/bin/sleep", "30"]) for _ in range(count)]
print(" ".join(str(child.pid) for child in children), flush=True)
time.sleep(30)
"""
        for child_count in (1, 2):
            with self.subTest(child_count=child_count):
                helper = subprocess.Popen(
                    [sys.executable, "-c", helper_source, str(child_count)],
                    stdout=subprocess.PIPE,
                    text=True,
                    start_new_session=True,
                )
                try:
                    assert helper.stdout is not None
                    children = helper.stdout.readline().strip().split()
                    self.assertEqual(len(children), child_count)
                    observed = subprocess.run(
                        [
                            "/bin/bash",
                            "--noprofile",
                            "--norc",
                            "-c",
                            f"{derivation} child {helper.pid}",
                        ],
                        check=True,
                        capture_output=True,
                        text=True,
                        timeout=5,
                    )
                    expected = children[0] if child_count == 1 else "0"
                    self.assertEqual(observed.stdout, expected)
                finally:
                    if helper.stdout is not None:
                        helper.stdout.close()
                    os.killpg(helper.pid, signal.SIGKILL)
                    helper.wait(timeout=5)

    @unittest.skipIf(os.geteuid() == 0, "real non-root EUID required")
    def test_entire_runtime_command_uses_only_nonroot_systemd_and_proc_evidence(
        self,
    ) -> None:
        self.assertEqual(os.getuid(), os.geteuid())
        shipping = controller._runtime_command("nonroot-fixture").decode("ascii")
        for forbidden in (
            "/sys/fs/cgroup",
            "cgroup.procs",
            "cgroup.stat",
            "pids.current",
            "cgroup.subtree_control",
            "base='/sys/fs/cgroup",
            '"$base/',
            '"$sup/',
            '"$work/',
        ):
            self.assertNotIn(forbidden, shipping)
        self.assertIn("/usr/bin/systemctl", shipping)
        self.assertIn("/usr/bin/pgrep", shipping)
        self.assertIn("/usr/bin/head -n 2", shipping)
        self.assertIn('field "/proc/$worker/status" PPid:', shipping)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            proc = root / "proc"
            system_block = root / "sys" / "block"
            fakebin = root / "bin"
            for path in (proc / "101", proc / "102", proc / "self", system_block, fakebin):
                path.mkdir(parents=True, exist_ok=True)

            zero = controller.ZERO_CAPS
            def write_process(
                pid: int, parent: int, membership: str, capability: str
            ) -> None:
                (proc / str(pid) / "status").write_text(
                    "\n".join(
                        (
                            f"PPid:\t{parent}",
                            f"CapInh:\t{zero}",
                            f"CapPrm:\t{capability}",
                            f"CapEff:\t{capability}",
                            f"CapBnd:\t{capability}",
                            f"CapAmb:\t{zero}",
                            "NoNewPrivs:\t1",
                        )
                    )
                    + "\n",
                    encoding="ascii",
                )
                (proc / str(pid) / "limits").write_text(
                    "Max core file size        0                    0                    bytes\n",
                    encoding="ascii",
                )
                (proc / str(pid) / "cgroup").write_text(
                    membership + "\n", encoding="ascii"
                )

            write_process(
                101,
                1,
                "0::/system.slice/kernaid-rescue-vaultd.service/supervisor",
                controller.CAP_SYS_ADMIN_AND_KILL,
            )
            write_process(
                102,
                101,
                "0::/system.slice/kernaid-rescue-vaultd.service/worker",
                controller.CAP_SYS_ADMIN_ONLY,
            )
            (proc / "self" / "mountinfo").write_text("", encoding="ascii")
            (proc / "swaps").write_text(
                "Filename Type Size Used Priority\n", encoding="ascii"
            )

            systemctl = fakebin / "systemctl"
            systemctl.write_text(
                """#!/bin/sh
case "$*" in
  *MainPID*) printf '%s\n' 101 ;;
  *InvocationID*) printf '%s\n' 0123456789abcdef0123456789abcdef ;;
  *ControlGroup*) printf '%s\n' /system.slice/kernaid-rescue-vaultd.service ;;
  *ActiveState*) printf '%s\n' active ;;
  *SubState*kernaid-rescue-vaultd.socket*) printf '%s\n' listening ;;
  *SubState*) printf '%s\n' running ;;
  *) exit 1 ;;
esac
""",
                encoding="ascii",
            )
            systemctl.chmod(0o700)
            pgrep = fakebin / "pgrep"
            pgrep.write_text(
                """#!/bin/sh
[ "$1:$2" = '-P:101' ] || exit 1
printf '%s\n' 102
""",
                encoding="ascii",
            )
            pgrep.chmod(0o700)

            fixture = shipping.replace("/usr/bin/systemctl", os.fspath(systemctl))
            fixture = fixture.replace("/usr/bin/pgrep", os.fspath(pgrep))
            fixture = fixture.replace("/proc", os.fspath(proc))
            fixture = fixture.replace("/sys/block", os.fspath(system_block))
            observed = subprocess.run(
                ["/bin/bash", "--noprofile", "--norc", "-c", fixture],
                check=True,
                capture_output=True,
                timeout=5,
            )
        expected = runtime_line("nonroot-fixture", 0)
        self.assertEqual(observed.stdout, expected + b"\n")
        snapshot = controller.parse_runtime_snapshot(expected, "nonroot-fixture")
        self.assertEqual(snapshot.worker_ppid, snapshot.service_pid)

    def test_service_and_socket_states_are_closed_exact_tokens(self) -> None:
        runtime_command = controller._runtime_command("state-test").decode("ascii")
        self.assertIn('[ "$sraw" = active:running ] && sstate=active-running', runtime_command)
        self.assertIn(
            'case "$oraw" in active:listening|active:running) ostate=operational',
            runtime_command,
        )

    def test_end_reread_comparison_rejects_each_identity_race(self) -> None:
        stable = {
            "svc": "101",
            "worker": "102",
            "wppid": "101",
            "control": "/system.slice/kernaid-rescue-vaultd.service",
            "scg": "0::/system.slice/kernaid-rescue-vaultd.service/supervisor",
            "wcg": "0::/system.slice/kernaid-rescue-vaultd.service/worker",
            "inv": "0123456789abcdef0123456789abcdef",
            "svc2": "101",
            "worker2": "102",
            "wppid2": "101",
            "control2": "/system.slice/kernaid-rescue-vaultd.service",
            "scg2": "0::/system.slice/kernaid-rescue-vaultd.service/supervisor",
            "wcg2": "0::/system.slice/kernaid-rescue-vaultd.service/worker",
            "inv2": "0123456789abcdef0123456789abcdef",
        }
        for changed in (
            "svc2",
            "worker2",
            "wppid",
            "wppid2",
            "control2",
            "scg2",
            "wcg2",
            "inv2",
        ):
            values = dict(stable)
            values[changed] = "changed"
            assignments = ";".join(
                f"{name}={value!r}" for name, value in values.items()
            )
            observed = subprocess.run(
                [
                    "/bin/bash",
                    "--noprofile",
                    "--norc",
                    "-c",
                    assignments
                    + ";"
                    + controller.RUNTIME_IDENTITY_STABILITY_COMMAND
                    + "printf '%s' \"$stable\"",
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            with self.subTest(changed=changed):
                self.assertEqual(observed.stdout, "false")

        runtime_command = controller._runtime_command("reread-test").decode("ascii")
        self.assertIn(controller.RUNTIME_IDENTITY_STABILITY_COMMAND, runtime_command)
        self.assertEqual(runtime_command.count('show MainPID "$unit"'), 2)
        self.assertEqual(runtime_command.count('show ControlGroup "$unit"'), 2)
        self.assertEqual(runtime_command.count('show InvocationID "$unit"'), 2)

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
        changed[3] = controller.dataclasses.replace(
            snapshots[3], invocation_id="f" * 32
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
            controller.CAP_SYS_ADMIN_AND_KILL.encode("ascii"),
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
            controller.CAP_SYS_ADMIN_AND_KILL.encode("ascii"),
            b"0000000000600000",
            1,
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
        service_cap = controller.CAP_SYS_ADMIN_AND_KILL.encode("ascii")
        worker_cap = controller.CAP_SYS_ADMIN_ONLY.encode("ascii")
        mutations = [
            (b"stage=initial", b"stage=other", "stage-invalid"),
            (b"service_pid=101", b"service_pid=0", "service-pid-invalid"),
            (b"worker_pid=102", b"worker_pid=0", "worker-pid-invalid"),
            (b"worker_ppid=101", b"worker_ppid=0", "worker-ppid-invalid"),
            (
                b"worker_ppid=101",
                b"worker_ppid=999",
                "worker-parent-invalid",
            ),
            (
                b"invocation_id=0123456789abcdef0123456789abcdef",
                b"invocation_id=invalid",
                "invocation-id-invalid",
            ),
            (
                b"service_caps="
                + b":".join((zero, service_cap, service_cap, service_cap)),
                b"service_caps=invalid",
                "service-capabilities-invalid",
            ),
            (
                b"worker_caps="
                + b":".join((zero, worker_cap, worker_cap, worker_cap)),
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
                b"systemd_control_group=unit",
                b"systemd_control_group=invalid",
                "systemd-control-group-invalid",
            ),
            (
                b"service_cgroup=supervisor",
                b"service_cgroup=invalid",
                "service-cgroup-invalid",
            ),
            (
                b"worker_cgroup=worker",
                b"worker_cgroup=invalid",
                "worker-cgroup-invalid",
            ),
            (
                b"identity_stable=true",
                b"identity_stable=false",
                "identity-stability-invalid",
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
                b"service_state=active-running",
                b"service_state=inactive",
                "service-state-invalid",
            ),
            (
                b"socket_state=operational",
                b"socket_state=inactive",
                "socket-state-invalid",
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
            valid.replace(
                b"systemd_control_group=unit",
                b"systemd_control_group=unit\nspoof",
            ),
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
    def test_firstboot_hex_line_is_paced_one_key_per_qmp_request(self) -> None:
        secret = bytearray(b"0123456789abcdef" * 4)
        client = controller.QmpClient(mock.Mock(), time.monotonic() + 5)
        calls: list[tuple[str, dict[str, object]]] = []

        def accept(command: str, arguments: dict[str, object]) -> None:
            calls.append((command, arguments))

        try:
            with (
                mock.patch.object(client, "execute", side_effect=accept),
                mock.patch.object(controller.time, "sleep") as sleep,
            ):
                client.send_hex_line(secret)
        finally:
            controller.wipe(secret)

        expected_qcodes = list("0123456789abcdef" * 4) + ["ret"]
        self.assertEqual(len(calls), len(expected_qcodes))
        for (command, arguments), expected_qcode in zip(
            calls, expected_qcodes, strict=True
        ):
            self.assertEqual(command, "input-send-event")
            events = arguments["events"]
            self.assertEqual(len(events), 2)
            self.assertEqual(
                [event["data"]["down"] for event in events], [True, False]
            )
            self.assertEqual(
                [event["data"]["key"] for event in events],
                [{"type": "qcode", "data": expected_qcode}] * 2,
            )
        self.assertEqual(
            sleep.call_args_list,
            [mock.call(controller.QMP_KEY_SETTLE_SECONDS)] * len(expected_qcodes),
        )

    def test_firstboot_hex_line_rejects_invalid_alphabet_before_qmp(self) -> None:
        client = controller.QmpClient(mock.Mock(), time.monotonic() + 5)
        with (
            mock.patch.object(client, "execute") as execute,
            self.assertRaises(controller.ClosedFailure) as failure,
        ):
            client.send_hex_line(bytearray(b"NOT_HEX"))
        self.assertEqual(
            (failure.exception.stage, failure.exception.code),
            ("firstboot", "key-alphabet-invalid"),
        )
        execute.assert_not_called()

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

    def test_qemu_health_classifies_signal_without_exposing_its_number(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            harness = controller.QemuHarness(
                "/bin/true", [], Path(directory) / "qmp.sock", []
            )
            process = mock.Mock()
            harness.process = process
            for return_code, expected in (
                (-signal.SIGKILL, "exited-signal"),
                (1, "exited-early"),
                (0, "exited-early"),
            ):
                with self.subTest(return_code=return_code):
                    process.poll.return_value = return_code
                    with self.assertRaises(controller.ClosedFailure) as failure:
                        harness.check_health()
                    self.assertEqual(
                        (failure.exception.stage, failure.exception.code),
                        ("qemu", expected),
                    )
                    self.assertNotIn(str(abs(return_code)), str(failure.exception))

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
        provider_raw = b"abcdef0123456789" * 4
        fake_qmp = mock.Mock()
        fake_harness = mock.Mock()
        fake_harness.start.return_value = (mock.Mock(), fake_qmp)
        parsed = SimpleNamespace(
            firmware="bios",
            boot=1,
            correct_key_fd=3,
            wrong_key_fd=4,
            login_credential_fd=5,
            provider_key_fd=7,
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
                side_effect=[
                    bytearray(correct_raw),
                    bytearray(wrong_raw),
                    bytearray(provider_raw),
                ],
            ),
            mock.patch.object(
                controller,
                "read_login_credential_fd",
                return_value=bytearray(login_credential),
            ),
            mock.patch.object(controller, "QemuHarness", return_value=fake_harness),
            mock.patch.object(controller, "wait_firstboot_attestation"),
            mock.patch.object(
                controller,
                "run_lifecycle",
                return_value=(10, 24, 26, "KA-0123456789abcdef01234567"),
            ),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            self.assertEqual(controller.main([]), 0)
        combined = (stdout.getvalue() + stderr.getvalue()).encode("ascii")
        self.assertNotIn(correct_raw, combined)
        self.assertNotIn(wrong_raw, combined)
        self.assertNotIn(provider_raw, combined)
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
        provider_raw = b"abcdef0123456789" * 4
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
            provider_key_fd=7,
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
                side_effect=[
                    bytearray(correct_raw),
                    bytearray(wrong_raw),
                    bytearray(provider_raw),
                ],
            ),
            mock.patch.object(
                controller,
                "read_login_credential_fd",
                return_value=bytearray(login_credential),
            ),
            mock.patch.object(controller, "QemuHarness", return_value=fake_harness),
            mock.patch.object(controller, "wait_firstboot_attestation"),
            mock.patch.object(
                controller,
                "run_lifecycle",
                return_value=(10, 16, 18, "KA-0123456789abcdef01234567"),
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


def run_proof_transcript(
    stage: str, transcript: bytes, *, timeout: float = 0.1
) -> int:
    """Exercise the real nonblocking serial parser with a fixed transcript."""

    local, peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    capture = controller.BoundedCapture(64 * 1024, [])
    console = None
    try:
        local.setblocking(False)
        peer.sendall(transcript)
        console = controller.SerialConsole(local.detach(), capture, lambda: None)
        return controller.run_guest_proof(
            console,
            stage,
            b"raise SystemExit(0)",
            0,
            time.monotonic() + 30.0,
            timeout=timeout,
        )
    finally:
        if console is not None:
            console.close()
        local.close()
        peer.close()
        capture.wipe()


class StaticContractTests(unittest.TestCase):

    def test_firstboot_result_requires_success_attestation(self) -> None:
        success = (
            b"\n[   81.726552] kernaid-rescue-firstboot[860]: "
            b"KERNAID_RESCUE_FIRSTBOOT_ATTESTATION_V1 state=provisioned "
            b"verified=true cleanup=complete "
            b"luks_uuid=12345678-1234-4abc-8def-123456789abc "
            b"filesystem_uuid=abcdef01-2345-4abc-9def-123456789abc "
            b"device_id=KA-0123456789abcdef01234567\r\n"
        )
        failure = (
            b"\nKERNAID_RESCUE_FIRSTBOOT_FAILURE_V1 "
            b"code=vault-profile-mismatch success=false\r\n"
        )
        success_match = controller.FIRSTBOOT_RESULT_PATTERN.search(success)
        failure_match = controller.FIRSTBOOT_RESULT_PATTERN.search(failure)
        self.assertIsNotNone(success_match)
        self.assertIsNotNone(failure_match)
        assert success_match is not None and failure_match is not None
        self.assertIsNone(success_match.group(1))
        self.assertEqual(failure_match.group(1), b"vault-profile-mismatch")
        self.assertIsNone(
            controller.FIRSTBOOT_RESULT_PATTERN.search(
                success.replace(
                    b"kernaid-rescue-firstboot[860]",
                    b"untrusted-firstboot[860]",
                )
            )
        )

        console = mock.Mock()
        console.wait_regex.return_value = failure_match
        with self.assertRaises(controller.ClosedFailure) as rejected:
            controller.wait_firstboot_attestation(console, 7, time.monotonic() + 1)
        self.assertEqual(
            (rejected.exception.stage, rejected.exception.code),
            ("firstboot", "provisioning-failed"),
        )

    def test_shipping_codex_status_proof_is_real_offline_and_closed(self) -> None:
        source = controller._codex_status_probe_source().decode("ascii")
        self.assertNotIn("/usr/bin/kernaid-codex-auth", source)
        self.assertNotIn("KernAid Codex: disconnesso", source)
        self.assertIn("kernaid.dev/rescue-codex-auth/v1alpha1", source)
        self.assertIn("/run/kernaid-rescue-codex.sock", source)
        self.assertIn("socket.SOCK_SEQPACKET|socket.SOCK_CLOEXEC", source)
        self.assertIn('"operation":"status"', source)
        self.assertIn("connection.shutdown(socket.SHUT_WR)", source)
        self.assertIn("connection.recvmsg(2049)", source)
        self.assertIn("socket.MSG_TRUNC|socket.MSG_CTRUNC", source)
        self.assertIn('response.get("status")!="signed-out"', source)
        self.assertIn("kernaid-rescue-codex@kernaid-qemu-proof.service", source)
        self.assertIn("kernaid-rescue-vaultd.service", source)
        self.assertIn('show("ActiveState"', source)
        self.assertIn('show("SubState"', source)
        self.assertIn('show("NAccepted"', source)
        self.assertIn('show("NConnections"', source)
        self.assertEqual(controller.CODEX_STATUS_SOCKET_TIMEOUT_SECONDS, 180.0)
        self.assertEqual(controller.CODEX_STATUS_PROOF_TIMEOUT_SECONDS, 195.0)
        self.assertLess(
            controller.CODEX_STATUS_SOCKET_TIMEOUT_SECONDS,
            controller.CODEX_STATUS_PROOF_TIMEOUT_SECONDS,
        )
        self.assertIn("connection.settimeout(180.0)", source)
        for checkpoint in controller.PROVIDER_PROOF_CODEX_CHECKPOINTS:
            self.assertIn(
                "KERNAID_QEMU_PROVIDER_PROOF_FAILURE_V1 "
                f"stage=codex-status checkpoint={checkpoint}",
                source,
            )
        self.assertLessEqual(
            set(controller.PROVIDER_PROOF_CODEX_REMOTE_ERRORS),
            set(controller.PROVIDER_PROOF_CODEX_CHECKPOINTS),
        )
        for local_checkpoint in (
            "connect",
            "send",
            "receive",
            "receive-active",
            "receive-ended",
            "receive-state",
            "frame",
            "decode",
            "response",
            "server-transport",
        ):
            self.assertNotIn(
                local_checkpoint,
                controller.PROVIDER_PROOF_CODEX_REMOTE_ERRORS,
            )
        lifecycle = inspect.getsource(controller.run_lifecycle)
        self.assertIn('"codex-status",', lifecycle)
        self.assertIn("timeout=CODEX_STATUS_PROOF_TIMEOUT_SECONDS", lifecycle)
        for forbidden in (
            "auth.json",
            "device-login",
            "http://",
            "https://",
            "/run/kernaid-codex-diag",
            "bridge-diagnostic",
        ):
            self.assertNotIn(forbidden, source)
        compile(source, "<codex-status-proof>", "exec", dont_inherit=True)
        self.assertIn("codex_status_path=true", controller.boot_attestation(
            "bios", 1, 10, 24, 26, "KA-0123456789abcdef01234567"
        ))

    def test_readiness_controller_and_wrapper_deadlines_are_strictly_nested(
        self,
    ) -> None:
        shell = SCRIPT.read_text(encoding="utf-8")
        unit = VAULT_SERVICE.read_text(encoding="utf-8")

        def readonly_integer(name: str) -> int:
            match = re.search(
                rf"^readonly {re.escape(name)}=([0-9]+)$",
                shell,
                re.MULTILINE,
            )
            if match is None:
                raise AssertionError(f"missing exact readonly integer: {name}")
            return int(match.group(1))

        vault_match = re.search(
            r"^TimeoutStartSec=([0-9]+)s$", unit, re.MULTILINE
        )
        self.assertIsNotNone(vault_match)
        assert vault_match is not None
        vault_start_seconds = int(vault_match.group(1))
        probe_controller_seconds = readonly_integer(
            "probe_controller_timeout_seconds"
        )
        probe_wrapper_seconds = readonly_integer("probe_wrapper_timeout_seconds")
        qemu_controller_seconds = readonly_integer(
            "qemu_controller_timeout_seconds"
        )
        qemu_wrapper_seconds = readonly_integer("qemu_wrapper_timeout_seconds")

        self.assertEqual(vault_start_seconds, 620)
        self.assertGreaterEqual(
            controller.READINESS_TIMEOUT_SECONDS,
            180 + vault_start_seconds + 370 + 30,
        )
        self.assertGreaterEqual(
            qemu_controller_seconds,
            controller.QEMU_START_TIMEOUT_SECONDS
            + controller.READINESS_TIMEOUT_SECONDS
            + 370
            + controller.SHUTDOWN_RESERVE_SECONDS,
        )
        self.assertEqual(
            qemu_controller_seconds, controller.CONTROLLER_TIMEOUT_SECONDS
        )
        self.assertGreaterEqual(qemu_wrapper_seconds, qemu_controller_seconds + 30)
        self.assertEqual(
            probe_controller_seconds, int(controller.PROBE_TIMEOUT_SECONDS)
        )
        self.assertGreaterEqual(probe_wrapper_seconds, probe_controller_seconds + 20)
        self.assertIn(
            '--timeout "$qemu_controller_timeout_seconds"', shell
        )
        self.assertIn(
            '--timeout "$probe_controller_timeout_seconds"', shell
        )
        for anchor, deadline in (
            (
                'python3 -I -B "$controller" --run-bounded-probe',
                'controller_deadline=$((SECONDS + probe_wrapper_timeout_seconds))',
            ),
            (
                '--timeout "$qemu_controller_timeout_seconds" --qemu',
                'controller_deadline=$((SECONDS + qemu_wrapper_timeout_seconds))',
            ),
        ):
            spawn = shell.index(anchor)
            pid_capture = shell.index("controller_pid=$!", spawn)
            deadline_capture = shell.index(deadline, pid_capture)
            publication_wait = shell.index(
                "await_owned_group_publication", deadline_capture
            )
            self.assertLess(pid_capture, deadline_capture)
            self.assertLess(deadline_capture, publication_wait)

    def test_provider_proof_accepts_adjacent_lf_and_crlf_markers(self) -> None:
        stage = "adjacent-proof"
        for newline in (b"\n", b"\r\n"):
            with self.subTest(newline=newline):
                transcript = newline.join(
                    (
                        f"KERNAID_PROVIDER_PROOF_BEGIN_V1_{stage}".encode(),
                        f"KERNAID_QEMU_PROVIDER_PROOF_V1 stage={stage} "
                        "result=true".encode(),
                        f"KERNAID_PROVIDER_PROOF_END_V1_{stage} rc=0".encode(),
                        b"",
                    )
                )
                self.assertEqual(run_proof_transcript(stage, transcript), len(transcript))

    def test_provider_proof_classifies_end_before_marker_without_waiting(self) -> None:
        stage = "failed-proof"
        transcript = (
            f"KERNAID_PROVIDER_PROOF_BEGIN_V1_{stage}\r\n"
            f"KERNAID_PROVIDER_PROOF_END_V1_{stage} rc=45\r\n"
        ).encode()
        started = time.monotonic()
        with self.assertRaises(controller.ClosedFailure) as failure:
            run_proof_transcript(stage, transcript, timeout=2.0)
        self.assertLess(time.monotonic() - started, 0.5)
        self.assertEqual(failure.exception.stage, "provider-proof")
        self.assertEqual(failure.exception.code, "command-failed")

    def test_provider_proof_classifies_closed_stage_command_failures(self) -> None:
        self.assertEqual(
            controller.PROVIDER_PROOF_CLOSED_STAGES,
            (
                "ui-diagnose-unconfigured",
                "ui-status-configured",
                "codex-status",
                "production-status",
                "normal-release",
                "signed-report",
                "hold-kill",
                "post-fault",
                "repair-apply",
                "native-post",
                "native-journal-boot1",
                "native-journal-boot2",
            ),
        )
        for stage in controller.PROVIDER_PROOF_CLOSED_STAGES:
            with self.subTest(stage=stage):
                transcript = (
                    f"KERNAID_PROVIDER_PROOF_BEGIN_V1_{stage}\r\n"
                    f"KERNAID_PROVIDER_PROOF_END_V1_{stage} rc=45\r\n"
                ).encode()
                with self.assertRaises(controller.ClosedFailure) as failure:
                    run_proof_transcript(stage, transcript)
                self.assertEqual(failure.exception.stage, "provider-proof")
                self.assertEqual(
                    failure.exception.code,
                    f"{stage}-command-failed",
                )

    def test_provider_proof_failure_checkpoints_are_closed_and_correlated(self) -> None:
        self.assertEqual(
            controller.PROVIDER_PROOF_UI_ERROR_CHECKPOINTS,
            (
                ("busy", "outcome-busy"),
                ("invalid_request", "outcome-invalid-request"),
                ("invalid_response", "outcome-invalid-response"),
                ("request_too_large", "outcome-request-too-large"),
                ("response_too_large", "outcome-response-too-large"),
                ("timeout", "outcome-timeout"),
                ("transport", "outcome-transport"),
                ("upstream", "outcome-upstream"),
            ),
        )
        self.assertEqual(
            len(dict(controller.PROVIDER_PROOF_UI_ERROR_CHECKPOINTS)),
            len(controller.PROVIDER_PROOF_UI_ERROR_CHECKPOINTS),
        )
        self.assertTrue(
            {
                checkpoint
                for _error, checkpoint in controller.PROVIDER_PROOF_UI_ERROR_CHECKPOINTS
            }.issubset(controller.PROVIDER_PROOF_UI_CHECKPOINTS)
        )
        for stage in controller.PROVIDER_PROOF_UI_STAGES:
            for checkpoint in controller.PROVIDER_PROOF_UI_CHECKPOINTS:
                with self.subTest(stage=stage, checkpoint=checkpoint):
                    transcript = (
                        f"KERNAID_PROVIDER_PROOF_BEGIN_V1_{stage}\r\n"
                        "KERNAID_QEMU_PROVIDER_PROOF_FAILURE_V1 "
                        f"stage={stage} checkpoint={checkpoint}\r\n"
                        f"KERNAID_PROVIDER_PROOF_END_V1_{stage} rc=45\r\n"
                    ).encode()
                    with self.assertRaises(controller.ClosedFailure) as failure:
                        run_proof_transcript(stage, transcript)
                    self.assertEqual(failure.exception.stage, "provider-proof")
                    self.assertEqual(
                        failure.exception.code, f"{stage}-{checkpoint}"
                    )

    def test_native_failure_checkpoints_are_closed_and_correlated(self) -> None:
        self.assertEqual(
            controller.PROVIDER_PROOF_NATIVE_STAGES,
            ("native-pre", "native-ready"),
        )
        for stage in controller.PROVIDER_PROOF_NATIVE_STAGES:
            for checkpoint in controller.PROVIDER_PROOF_NATIVE_CHECKPOINTS:
                with self.subTest(stage=stage, checkpoint=checkpoint):
                    transcript = (
                        f"KERNAID_PROVIDER_PROOF_BEGIN_V1_{stage}\r\n"
                        "KERNAID_QEMU_PROVIDER_PROOF_FAILURE_V1 "
                        f"stage={stage} checkpoint={checkpoint}\r\n"
                        f"KERNAID_PROVIDER_PROOF_END_V1_{stage} rc=45\r\n"
                    ).encode()
                    with self.assertRaises(controller.ClosedFailure) as failure:
                        run_proof_transcript(stage, transcript)
                    self.assertEqual(
                        (failure.exception.stage, failure.exception.code),
                        ("provider-proof", f"{stage}-{checkpoint}"),
                    )

    def test_codex_status_failure_checkpoints_are_closed_and_correlated(self) -> None:
        self.assertEqual(
            controller.PROVIDER_PROOF_CODEX_CHECKPOINTS,
            (
                "unit",
                "socket",
                "accepted",
                "connection-drain",
                "connect",
                "send",
                "receive",
                "receive-active",
                "receive-ended",
                "receive-state",
                "frame",
                "decode",
                "response",
                "server-transport",
                "vault-locked",
                "vault-unconfigured",
                "busy",
                "reboot-required",
                "transport",
                "cli-unavailable",
                "cli-failed",
                "timed-out",
                "unsafe-home",
                "unsafe-executable",
            ),
        )
        stage = "codex-status"
        for checkpoint in controller.PROVIDER_PROOF_CODEX_CHECKPOINTS:
            with self.subTest(checkpoint=checkpoint):
                transcript = (
                    f"KERNAID_PROVIDER_PROOF_BEGIN_V1_{stage}\r\n"
                    "KERNAID_QEMU_PROVIDER_PROOF_FAILURE_V1 "
                    f"stage={stage} checkpoint={checkpoint}\r\n"
                    f"KERNAID_PROVIDER_PROOF_END_V1_{stage} rc=45\r\n"
                ).encode()
                with self.assertRaises(controller.ClosedFailure) as failure:
                    run_proof_transcript(stage, transcript)
                self.assertEqual(failure.exception.stage, "provider-proof")
                self.assertEqual(
                    failure.exception.code, f"{stage}-{checkpoint}"
                )

        for checkpoint in ("future-checkpoint", "ui-identity"):
            with self.subTest(rejected=checkpoint):
                transcript = (
                    f"KERNAID_PROVIDER_PROOF_BEGIN_V1_{stage}\r\n"
                    "KERNAID_QEMU_PROVIDER_PROOF_FAILURE_V1 "
                    f"stage={stage} checkpoint={checkpoint}\r\n"
                    f"KERNAID_PROVIDER_PROOF_END_V1_{stage} rc=45\r\n"
                ).encode()
                with self.assertRaises(controller.ClosedFailure) as failure:
                    run_proof_transcript(stage, transcript)
                self.assertEqual(failure.exception.code, "marker-invalid")

    def test_provider_proof_rejects_malformed_conflicting_and_noisy_results(
        self,
    ) -> None:
        stage = "ui-diagnose-unconfigured"
        begin = f"KERNAID_PROVIDER_PROOF_BEGIN_V1_{stage}\r\n"
        end = f"KERNAID_PROVIDER_PROOF_END_V1_{stage} rc=45\r\n"
        invalid = {
            "unknown-checkpoint": (
                begin
                + "KERNAID_QEMU_PROVIDER_PROOF_FAILURE_V1 "
                f"stage={stage} checkpoint=future-check\r\n"
                + end,
                "marker-invalid",
            ),
            "wrong-stage": (
                begin
                + "KERNAID_QEMU_PROVIDER_PROOF_FAILURE_V1 "
                "stage=ui-status-configured checkpoint=ui-identity\r\n"
                + end,
                "marker-invalid",
            ),
            "duplicate": (
                begin
                + f"KERNAID_QEMU_PROVIDER_PROOF_V1 stage={stage} result=true\r\n"
                + f"KERNAID_QEMU_PROVIDER_PROOF_V1 stage={stage} result=true\r\n"
                + f"KERNAID_PROVIDER_PROOF_END_V1_{stage} rc=0\r\n",
                "output-invalid",
            ),
            "extra-output": (
                begin
                + f"KERNAID_QEMU_PROVIDER_PROOF_V1 stage={stage} result=true\r\n"
                + "untrusted detail\r\n"
                + f"KERNAID_PROVIDER_PROOF_END_V1_{stage} rc=0\r\n",
                "output-invalid",
            ),
            "failure-with-zero": (
                begin
                + "KERNAID_QEMU_PROVIDER_PROOF_FAILURE_V1 "
                f"stage={stage} checkpoint=ui-identity\r\n"
                + f"KERNAID_PROVIDER_PROOF_END_V1_{stage} rc=0\r\n",
                "command-failed",
            ),
            "success-with-failure-return": (
                begin
                + f"KERNAID_QEMU_PROVIDER_PROOF_V1 stage={stage} result=true\r\n"
                + end,
                "command-failed",
            ),
            "end-zero-without-marker": (
                begin + f"KERNAID_PROVIDER_PROOF_END_V1_{stage} rc=0\r\n",
                "marker-missing",
            ),
            "noncanonical-return": (
                begin + f"KERNAID_PROVIDER_PROOF_END_V1_{stage} rc=00\r\n",
                "return-code-invalid",
            ),
            "out-of-range-return": (
                begin + f"KERNAID_PROVIDER_PROOF_END_V1_{stage} rc=999\r\n",
                "return-code-invalid",
            ),
        }
        for name, (transcript, expected_code) in invalid.items():
            with self.subTest(name=name), self.assertRaises(
                controller.ClosedFailure
            ) as failure:
                run_proof_transcript(stage, transcript.encode())
            self.assertEqual(failure.exception.code, expected_code)

    def test_provider_proof_requires_its_complete_local_budget_before_send(
        self,
    ) -> None:
        class NoSendConsole:
            def send(self, _value: bytes, *, deadline: float) -> None:
                del deadline
                raise AssertionError("proof sent before aggregate budget validation")

        with self.assertRaises(controller.ClosedFailure) as failure:
            controller.run_guest_proof(
                NoSendConsole(),
                "budget-proof",
                b"raise SystemExit(0)",
                0,
                time.monotonic() + 24.0,
                timeout=1.0,
            )
        self.assertEqual(
            (failure.exception.stage, failure.exception.code),
            ("provider-proof", "aggregate-budget"),
        )

    def test_provider_guest_proofs_are_closed_bounded_and_role_separated(self) -> None:
        normal = controller._socket_probe_source(
            "normal-release",
            controller.PROVIDER_LEASE_PROBE_SOCKET,
            b"NORMAL\n",
            b"KERNAID_PROVIDER_LEASE_PROBE_NORMAL_V1 "
            b"borrowed=true unread=true\n",
        ).decode("ascii")
        self.assertIn("connection.sendall(b'NORMAL\\n')", normal)
        self.assertIn("connection.shutdown(socket.SHUT_WR)", normal)
        self.assertIn(controller.PROVIDER_LEASE_PROOF_UNIT, normal)
        self.assertIn(controller.PROVIDER_LEASE_TEMPLATE_PATH, normal)
        for property_name in ("LoadState", "FragmentPath", "BindsTo"):
            self.assertIn(f'show("{property_name}",template)', normal)
        self.assertIsNone(
            re.search(r"[\"']kernaid-provider-lease-probe@\.service[\"']", normal)
        )
        self.assertIn("kernaid-rescue-vaultd.service", normal)

        status = controller._production_status_probe_source().decode("ascii")
        self.assertIn(controller.PROVIDER_STATUS_PROBE_SOCKET, status)
        self.assertIn("connection.sendall(b'STATUS\\n')", status)
        self.assertIn(controller.PROVIDER_EXECUTOR_PROOF_UNIT, status)
        self.assertIn(controller.PROVIDER_EXECUTOR_TEMPLATE_PATH, status)
        for property_name in ("LoadState", "FragmentPath", "BindsTo"):
            self.assertIn(f'show("{property_name}",template)', status)
        self.assertIsNone(
            re.search(r"[\"']kernaid-rescue-openai-executor@\.service[\"']", status)
        )
        self.assertIn("kernaid-rescue-openai-egress.service", status)
        self.assertIn('!=b"inactive"', status)

        hold = controller._hold_probe_source(101, 102).decode("ascii")
        self.assertIn('connection.sendall(b"HOLD\\n")', hold)
        self.assertLess(
            hold.index("hold_started=time.monotonic()"),
            hold.index('connection.sendall(b"HOLD\\n")'),
        )
        self.assertIn(
            "while True:\n"
            "        chunk=connection.recv(256)\n"
            "        if not chunk:\n"
            "            break\n"
            "        raise RuntimeError()\n"
            "    if time.monotonic()-hold_started<15.0:\n"
            "        raise RuntimeError()",
            hold,
        )
        self.assertIn("InvocationID", hold)
        self.assertIn("MainPID", hold)
        self.assertIn("/run/credentials", hold)
        for prefix in controller.TEST_CREDENTIAL_PREFIXES:
            self.assertIn(prefix, hold)
        for path in (
            controller.PROVIDER_STATUS_PROBE_SOCKET,
            controller.PROVIDER_LEASE_PROBE_SOCKET,
            controller.PROVIDER_LEASE_KILL_SOCKET,
        ):
            self.assertIn(path, hold)
        self.assertNotIn("api_key", normal.lower() + status.lower() + hold.lower())

    def test_shipping_ui_relay_proofs_are_same_origin_correlated_and_secret_closed(
        self,
    ) -> None:
        diagnose = controller._production_ui_relay_probe_source(
            "ui-diagnose-unconfigured"
        ).decode("ascii")
        status = controller._production_ui_relay_probe_source(
            "ui-status-configured"
        ).decode("ascii")
        for stage, source in (
            ("ui-diagnose-unconfigured", diagnose),
            ("ui-status-configured", status),
        ):
            support, separator, _transaction = source.partition(
                'try:\n    checkpoint="ui-identity"'
            )
            self.assertEqual(separator, 'try:\n    checkpoint="ui-identity"')
            namespace: dict[str, object] = {}
            exec(compile(support, "<ui-relay-support>", "exec"), namespace)
            self.assertEqual(
                namespace["OUTCOME_CHECKPOINTS"],
                dict(controller.PROVIDER_PROOF_UI_ERROR_CHECKPOINTS),
            )
            self.assertIn('ENDPOINT="/api/rescue/provider/openai"', source)
            self.assertIn('HOST="127.0.0.1:4173"', source)
            self.assertIn('ORIGIN="http://127.0.0.1:4173"', source)
            self.assertIn(
                'connection.putheader("Sec-Fetch-Site","same-origin")', source
            )
            self.assertIn('connection.putheader("Content-Type","application/json")', source)
            self.assertIn('connection.putheader("Content-Length",str(len(body)))', source)
            self.assertIn('response.headers.get_all("Retry-After",[])', source)
            self.assertIn("MAX_BUSY_RETRIES=5", source)
            self.assertIn("BUSY_BODY=b'{\"error\":{\"code\":\"busy\"}}'", source)
            self.assertIn("def exchange_with_busy_retry(request,baseline):", source)
            self.assertIn("wait_retry_interval()", source)
            self.assertIn('checkpoint="relay-busy"', source)
            self.assertIn("def capture_baseline():", source)
            self.assertIn('accepted=number("NAccepted",EXECUTOR)', source)
            self.assertIn("accepted_before,egress_before=attempt_baseline", source)
            self.assertIn('accepted_after=number("NAccepted",EXECUTOR)', source)
            self.assertIn("accepted_after!=accepted_before+1", source)
            self.assertIn('number("NConnections",EXECUTOR)!=0', source)
            self.assertIn('show("ActiveEnterTimestampMonotonic",EGRESS)', source)
            self.assertIn(
                'b"/usr/bin/python3\\0-I\\0/usr/lib/kernaid/rescue_server.py\\0"',
                source,
            )
            self.assertIn("object_pairs_hook=unique", source)
            self.assertIn("observed[:]=b\"\\0\"*len(observed)", source)
            self.assertIn("encoded=json.dumps(request", source)
            self.assertIn("DEADLINE=time.monotonic()+BUDGET", source)
            self.assertIn("timeout=remaining(3.0)", source)
            self.assertIn("transport=connection.sock", source)
            self.assertIn("transport.settimeout(remaining(TIMEOUT))", source)
            self.assertIn("response.close()", source)
            self.assertIn("transport.close()", source)
            for checkpoint in controller.PROVIDER_PROOF_UI_CHECKPOINTS:
                self.assertIn(
                    "KERNAID_QEMU_PROVIDER_PROOF_FAILURE_V1 "
                    f"stage={stage} checkpoint={checkpoint}",
                    source,
                )
            for checkpoint in controller.PROVIDER_PROOF_UI_CHECKPOINTS[:7]:
                self.assertIn(f'checkpoint="{checkpoint}"', source)
            for error, checkpoint in controller.PROVIDER_PROOF_UI_ERROR_CHECKPOINTS:
                self.assertIn(f"{error!r}: {checkpoint!r}", source)
            self.assertNotIn("encoded=b'", source)
            self.assertNotIn('encoded=b"', source)
            self.assertNotIn("body=bytearray(b'", source)
            self.assertNotIn("api_key", source.lower())
            self.assertLess(max(map(len, source.splitlines())), 1024)
            compile(source.encode("ascii"), "<ui-relay-proof>", "exec", dont_inherit=True)

        self.assertIn("OPERATION='provider.openai.diagnose'", diagnose)
        self.assertIn("TIMEOUT=130.0", diagnose)
        self.assertIn("BUDGET=140.0", diagnose)
        self.assertIn(
            '"contextSha256":"sha256:422dbebc0f179cff9223cd1be89d41e8facce32145ca86ef8b4a59db779a04fb"',
            diagnose,
        )
        self.assertIn('error["code"]!="credential_unavailable"', diagnose)
        self.assertIn("OPERATION='provider.status'", status)
        self.assertIn("TIMEOUT=5.0", status)
        self.assertIn("BUDGET=10.0", status)
        self.assertIn(
            'status!={"provider":"openai","profile":"rescue-default",'
            '"vault":"unlocked","credential":"configured"}',
            status,
        )
        with self.assertRaises(controller.ClosedFailure) as failure:
            controller._production_ui_relay_probe_source("invalid-stage")
        self.assertEqual(failure.exception.code, "stage-invalid")

        lifecycle = CONTROLLER.read_text(encoding="utf-8")
        diagnose_call = (
            'if boot == 1:\n'
            '        cursor = run_guest_proof(\n'
            '            console,\n'
            '            "ui-diagnose-unconfigured"'
        )
        self.assertIn(diagnose_call, lifecycle)
        self.assertEqual(
            lifecycle.count('_production_ui_relay_probe_source("ui-status-configured")'),
            1,
        )

    def test_signed_report_proof_uses_shipping_http_path_and_two_boot_index(
        self,
    ) -> None:
        first = controller._signed_report_probe_source(1, 16).decode("ascii")
        second = controller._signed_report_probe_source(2, 30).decode("ascii")
        for source, version, report_count in ((first, 16, 1), (second, 30, 2)):
            self.assertIn(f"EXPECTED_VERSION={version}", source)
            self.assertIn('"/api/rescue/audit-append"', source)
            self.assertIn('"/api/rescue/report-persist"', source)
            self.assertIn('"/api/rescue/reports"', source)
            self.assertIn('ORIGIN="http://127.0.0.1:4173"', source)
            self.assertIn('"Sec-Fetch-Site":"same-origin"', source)
            self.assertIn("payloadSha256", source)
            self.assertIn(
                'urlsafe(envelope["payloadSha256"],32)'
                "!=hashlib.sha256(expected_payload).digest()",
                source,
            )
            self.assertNotIn(
                'envelope["payloadSha256"]'
                "!=hashlib.sha256(expected_payload).hexdigest()",
                source,
            )
            self.assertIn("journalEntryHash", source)
            self.assertIn("signature", source)
            self.assertIn('["report-export",CURRENT]', source)
            self.assertIn('KernAid-Reports/"+CURRENT+".signed.json"', source)
            self.assertIn("stat.S_IMODE(file_stat.st_mode)!=0o600", source)
            self.assertEqual(source.count("S-qemu-signed-report-"), report_count)
            self.assertLess(len(source), 16 * 1024)
            compile(source, "<signed-report-proof>", "exec", dont_inherit=True)
        self.assertNotIn("000000000002", first)
        self.assertIn("000000000001", second)
        self.assertIn("000000000002", second)
        with self.assertRaises(controller.ClosedFailure):
            controller._signed_report_probe_source(3, 16)
        with self.assertRaises(controller.ClosedFailure):
            controller._signed_report_probe_source(1, controller.MAX_SAFE_STATE_VERSION)
        lifecycle = inspect.getsource(controller.run_lifecycle)
        self.assertIn('"signed-report",', lifecycle)
        self.assertIn("_signed_report_probe_source(boot, configured.state_version)", lifecycle)
        self.assertIn("timeout=150.0", lifecycle)

    def test_ui_relay_exchange_reads_a_real_http10_connection_close_response(
        self,
    ) -> None:
        source = controller._production_ui_relay_probe_source(
            "ui-diagnose-unconfigured"
        ).decode("ascii")
        support, separator, _transaction = source.partition(
            'try:\n    checkpoint="ui-identity"'
        )
        self.assertEqual(separator, 'try:\n    checkpoint="ui-identity"')
        namespace: dict[str, object] = {}
        exec(compile(support, "<ui-relay-support>", "exec"), namespace)

        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(2.0)
        port = listener.getsockname()[1]
        server_errors: list[str] = []
        response_body = b'{"ok":false}\n'

        def serve_http10() -> None:
            try:
                connection, _address = listener.accept()
                with connection:
                    connection.settimeout(2.0)
                    request = bytearray()
                    while b"\r\n\r\n" not in request:
                        chunk = connection.recv(4096)
                        if not chunk:
                            raise AssertionError("request headers truncated")
                        request.extend(chunk)
                        if len(request) > 128 * 1024:
                            raise AssertionError("request oversized")
                    headers, body = request.split(b"\r\n\r\n", 1)
                    length_match = re.search(
                        rb"(?:^|\r\n)Content-Length: ([0-9]+)(?:\r\n|$)",
                        headers,
                    )
                    if length_match is None:
                        raise AssertionError("content length missing")
                    declared = int(length_match.group(1))
                    while len(body) < declared:
                        chunk = connection.recv(4096)
                        if not chunk:
                            raise AssertionError("request body truncated")
                        body += chunk
                    if len(body) != declared or not body.endswith(b"\n"):
                        raise AssertionError("request body invalid")
                    connection.sendall(
                        b"HTTP/1.0 200 OK\r\n"
                        b"Content-Type: application/json\r\n"
                        b"Cache-Control: no-store\r\n"
                        b"X-Content-Type-Options: nosniff\r\n"
                        + f"Content-Length: {len(response_body)}\r\n".encode()
                        + b"Connection: close\r\n\r\n"
                        + response_body
                    )
            except BaseException as error:
                server_errors.append(type(error).__name__)

        server = threading.Thread(target=serve_http10)
        server.start()
        try:
            namespace["PORT"] = port
            namespace["TIMEOUT"] = 2.0
            namespace["DEADLINE"] = time.monotonic() + 3.0
            observed = namespace["exchange"]({"probe": "fixed"})
            self.assertEqual(observed, {"ok": False})
        finally:
            server.join(3.0)
            listener.close()
        self.assertFalse(server.is_alive())
        self.assertEqual(server_errors, [])

    def test_ui_relay_retries_only_a_canonical_busy_response(self) -> None:
        source = controller._production_ui_relay_probe_source(
            "ui-status-configured"
        ).decode("ascii")
        support, separator, _transaction = source.partition(
            'try:\n    checkpoint="ui-identity"'
        )
        self.assertEqual(separator, 'try:\n    checkpoint="ui-identity"')
        namespace: dict[str, object] = {}
        exec(compile(support, "<ui-relay-support>", "exec"), namespace)

        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(2)
        listener.settimeout(3.0)
        port = listener.getsockname()[1]
        server_errors: list[str] = []
        bodies = (b'{"error":{"code":"busy"}}', b'{"ok":false}\n')

        def serve_busy_then_success() -> None:
            try:
                for index, response_body in enumerate(bodies):
                    connection, _address = listener.accept()
                    with connection:
                        connection.settimeout(2.0)
                        request = bytearray()
                        while b"\r\n\r\n" not in request:
                            chunk = connection.recv(4096)
                            if not chunk:
                                raise AssertionError("request headers truncated")
                            request.extend(chunk)
                            if len(request) > 128 * 1024:
                                raise AssertionError("request oversized")
                        headers, body = request.split(b"\r\n\r\n", 1)
                        length_match = re.search(
                            rb"(?:^|\r\n)Content-Length: ([0-9]+)(?:\r\n|$)",
                            headers,
                        )
                        if length_match is None:
                            raise AssertionError("content length missing")
                        declared = int(length_match.group(1))
                        while len(body) < declared:
                            chunk = connection.recv(4096)
                            if not chunk:
                                raise AssertionError("request body truncated")
                            body += chunk
                        if len(body) != declared:
                            raise AssertionError("request body invalid")
                        status = (
                            b"429 Too Many Requests" if index == 0 else b"200 OK"
                        )
                        retry = b"Retry-After: 1\r\n" if index == 0 else b""
                        connection.sendall(
                            b"HTTP/1.0 "
                            + status
                            + b"\r\nContent-Type: application/json\r\n"
                            b"Cache-Control: no-store\r\n"
                            b"X-Content-Type-Options: nosniff\r\n"
                            + retry
                            + f"Content-Length: {len(response_body)}\r\n".encode()
                            + b"Connection: close\r\n\r\n"
                            + response_body
                        )
            except BaseException as error:
                server_errors.append(type(error).__name__)

        server = threading.Thread(target=serve_busy_then_success)
        server.start()
        baselines: list[int] = []

        def baseline() -> int:
            baselines.append(len(baselines) + 1)
            return baselines[-1]

        started = time.monotonic()
        try:
            namespace["PORT"] = port
            namespace["TIMEOUT"] = 2.0
            namespace["DEADLINE"] = started + 4.0
            observed, accepted_baseline = namespace["exchange_with_busy_retry"](
                {"probe": "fixed"}, baseline
            )
        finally:
            server.join(3.0)
            listener.close()
        self.assertFalse(server.is_alive())
        self.assertEqual(server_errors, [])
        self.assertEqual(observed, {"ok": False})
        self.assertEqual(accepted_baseline, 2)
        self.assertEqual(baselines, [1, 2])
        self.assertGreaterEqual(time.monotonic() - started, 1.0)

    def test_ui_relay_busy_retry_is_bounded_by_count_and_absolute_deadline(
        self,
    ) -> None:
        source = controller._production_ui_relay_probe_source(
            "ui-status-configured"
        ).decode("ascii")
        support, separator, _transaction = source.partition(
            'try:\n    checkpoint="ui-identity"'
        )
        self.assertEqual(separator, 'try:\n    checkpoint="ui-identity"')
        namespace: dict[str, object] = {}
        exec(compile(support, "<ui-relay-support>", "exec"), namespace)

        class FakeTime:
            def __init__(self) -> None:
                self.now = 0.0

            def monotonic(self) -> float:
                return self.now

            def sleep(self, delay: float) -> None:
                if delay < 0:
                    raise AssertionError("negative retry delay")
                self.now += delay

        fake_time = FakeTime()
        calls: list[int] = []
        baselines: list[int] = []
        namespace["time"] = fake_time
        namespace["DEADLINE"] = 10.0
        namespace["exchange"] = lambda _request: (
            calls.append(len(calls) + 1) or namespace["BUSY"]
        )

        def baseline() -> int:
            baselines.append(len(baselines) + 1)
            return baselines[-1]

        observed, accepted_baseline = namespace["exchange_with_busy_retry"](
            {"probe": "fixed"}, baseline
        )
        self.assertIs(observed, namespace["BUSY"])
        self.assertIsNone(accepted_baseline)
        self.assertEqual(calls, [1, 2, 3, 4, 5, 6])
        self.assertEqual(baselines, [1, 2, 3, 4, 5, 6])
        self.assertEqual(fake_time.now, 5.0)

        fake_time.now = 0.0
        namespace["DEADLINE"] = 0.5
        with self.assertRaises(RuntimeError):
            namespace["exchange_with_busy_retry"]({"probe": "fixed"}, baseline)

    def test_ui_relay_rejects_noncanonical_busy_without_retry(self) -> None:
        source = controller._production_ui_relay_probe_source(
            "ui-status-configured"
        ).decode("ascii")
        support, separator, _transaction = source.partition(
            'try:\n    checkpoint="ui-identity"'
        )
        self.assertEqual(separator, 'try:\n    checkpoint="ui-identity"')
        namespace: dict[str, object] = {}
        exec(compile(support, "<ui-relay-support>", "exec"), namespace)

        canonical_body = b'{"error":{"code":"busy"}}'
        common = (
            b"Content-Type: application/json\r\n"
            b"Cache-Control: no-store\r\n"
            b"X-Content-Type-Options: nosniff\r\n"
        )
        malformed = {
            "missing-retry": common,
            "duplicate-retry": common
            + b"Retry-After: 1\r\nRetry-After: 1\r\n",
            "wrong-retry": common + b"Retry-After: 2\r\n",
            "encoded": common
            + b"Retry-After: 1\r\nContent-Encoding: identity\r\n",
            "newline-body": common + b"Retry-After: 1\r\n",
            "altered-body": common + b"Retry-After: 1\r\n",
        }
        for name, headers in malformed.items():
            with self.subTest(name=name):
                response_body = canonical_body
                if name == "newline-body":
                    response_body += b"\n"
                elif name == "altered-body":
                    response_body = b'{"error":{"code":"basy"}}'
                listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind(("127.0.0.1", 0))
                listener.listen(1)
                listener.settimeout(2.0)
                port = listener.getsockname()[1]
                server_errors: list[str] = []

                def serve_malformed() -> None:
                    try:
                        connection, _address = listener.accept()
                        with connection:
                            connection.settimeout(2.0)
                            request = bytearray()
                            while b"\r\n\r\n" not in request:
                                chunk = connection.recv(4096)
                                if not chunk:
                                    raise AssertionError("request truncated")
                                request.extend(chunk)
                            connection.sendall(
                                b"HTTP/1.0 429 Too Many Requests\r\n"
                                + headers
                                + f"Content-Length: {len(response_body)}\r\n".encode()
                                + b"Connection: close\r\n\r\n"
                                + response_body
                            )
                    except BaseException as error:
                        server_errors.append(type(error).__name__)

                server = threading.Thread(target=serve_malformed)
                server.start()
                baseline_calls: list[int] = []

                def baseline() -> int:
                    baseline_calls.append(1)
                    return 1

                try:
                    namespace["PORT"] = port
                    namespace["TIMEOUT"] = 1.0
                    namespace["DEADLINE"] = time.monotonic() + 2.0
                    with self.assertRaises(RuntimeError):
                        namespace["exchange_with_busy_retry"](
                            {"probe": "fixed"}, baseline
                        )
                finally:
                    server.join(2.0)
                    listener.close()
                self.assertFalse(server.is_alive())
                self.assertEqual(server_errors, [])
                self.assertEqual(baseline_calls, [1])

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
        self.assertIn("--provider-key-fd 7", shell)
        self.assertIn('7<"$provider_key"', shell)
        self.assertIn("unsquashfs -cat", shell)
        self.assertIn("0030-user-setup", shell)
        self.assertIn("squashfs-tools", shell)
        self.assertIn("--extract-live-credential", shell)
        self.assertIn("--clear-owned-loop", shell)
        self.assertIn('6<"$loop_device" 7<"$expected_backing"', shell)
        self.assertNotIn("losetup -d --", shell)
        self.assertIn('--timeout "$qemu_controller_timeout_seconds"', shell)
        self.assertEqual(shell.count("    -nic none\n"), 1)
        self.assertIn("production_ui_provider_relay_path=true", shell)
        self.assertIn("signed_report_path=true", shell)
        self.assertIn('kill -s "$signal_name" "$controller_pid"', shell)
        self.assertIn(
            "-fw_cfg \"name=opt/io.systemd.credentials/provider-lease-probe,"
            "file=$provider_probe_helper\"",
            shell,
        )
        self.assertEqual(
            shell.count(
                '    -fw_cfg "name=opt/kernaid-tauri-sandbox-probe,string=v1"\n'
            ),
            1,
        )
        self.assertNotIn("opt/kernaid-offline-inspection", shell)
        self.assertIn("provider-probe-in-iso", shell)
        self.assertIn("provider-probe-in-squashfs", shell)
        self.assertIn(
            "23470d54d04fd4d025988e9fabf7401b12c9157c6d58162295c01817c103a08f",
            shell,
        )
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
        self.assertIn("p3_initially_zero=true", shell)
        self.assertIn("firstboot_tty1_qmp=true", shell)
        self.assertIn("qmp.send_hex_line(correct)", python)
        self.assertIn(
            "KERNAID_RESCUE_FIRSTBOOT_PROMPT_READY_V1 step=passphrase", python
        )
        self.assertIn(
            "KERNAID_RESCUE_FIRSTBOOT_PROMPT_READY_V1 step=confirmation", python
        )
        self.assertNotIn("cryptsetup luksFormat", shell)
        self.assertIn('"-serial",\n            "pty"', python)
        self.assertIn("qmp.system_powerdown()", python)
        self.assertIn("close_fds=True", python)
        self.assertIn("SERIAL_LIMIT = 2 * 1024 * 1024", python)
        self.assertIn("ACPI_SHUTDOWN_SECONDS = 180.0", python)
        self.assertIn("systemd_control_group=unit", python)
        self.assertIn("service_cgroup=supervisor", python)
        self.assertIn("worker_cgroup=worker", python)
        self.assertIn("`cgroup_topology_exact` is a composed claim", python)
        self.assertNotIn("parent_procs=empty", python)
        self.assertNotIn("worker_pids_current=1", python)
        self.assertIn("swaps_empty=true", python)
        self.assertLess(
            len(controller._runtime_command("maximum-stage")),
            4096,
            "the guest TTY canonical input line must remain bounded",
        )


if __name__ == "__main__":
    unittest.main()
