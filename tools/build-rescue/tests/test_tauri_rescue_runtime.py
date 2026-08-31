from __future__ import annotations

import importlib.util
import io
import json
import os
import socket
import stat
import struct
import sys
import tempfile
import threading
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock


TOOLS_DIR = Path(__file__).resolve().parents[1]
REPO_DIR = Path(__file__).resolve().parents[3]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("module spec unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    previous_bytecode_policy = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = previous_bytecode_policy
    return module


qemu_ui = load_module(
    "kernaid_qemu_tauri_ui_smoke",
    TOOLS_DIR / "qemu-tauri-ui-smoke.py",
)
guest_ui = load_module(
    "kernaid_guest_tauri_ui_ready",
    REPO_DIR
    / "rescue/live-build/config/includes.chroot/usr/lib/kernaid"
    / "tauri_ui_ready_check.py",
)
session_ui = load_module(
    "kernaid_rescue_ui_session_ready",
    REPO_DIR
    / "rescue/live-build/config/includes.chroot/usr/lib/kernaid"
    / "rescue_ui_session_ready.py",
)
network_probe = load_module(
    "kernaid_tauri_network_probe",
    REPO_DIR
    / "rescue/live-build/config/includes.chroot/usr/lib/kernaid"
    / "tauri_network_probe.py",
)
native_prompt = load_module(
    "kernaid_rescue_native_prompt",
    REPO_DIR
    / "rescue/live-build/config/includes.chroot/usr/lib/kernaid"
    / "rescue_native_prompt_broker.py",
)
binary_verifier = load_module(
    "kernaid_shipping_binary_profiles",
    TOOLS_DIR / "verify-shipping-binary.py",
)


class TauriFramebufferTests(unittest.TestCase):
    @staticmethod
    def branded_ppm() -> bytes:
        width, height = 640, 480
        pixels = bytearray(qemu_ui.BRAND_DARK * (width * height))

        def set_pixel(index: int, color: tuple[int, int, int]) -> None:
            offset = index * 3
            pixels[offset : offset + 3] = bytes(color)

        for index in range(32):
            set_pixel(index, qemu_ui.BRAND_LIME)
            set_pixel(64 + index, qemu_ui.BRAND_CYAN)
        for index, color in enumerate(
            (
                (32, 48, 64),
                (64, 80, 96),
                (96, 112, 128),
                (128, 144, 160),
                (160, 176, 192),
                (192, 208, 224),
                (224, 240, 128),
                (240, 128, 224),
            )
        ):
            set_pixel(97 * (index + 1), color)
        return f"P6\n{width} {height}\n255\n".encode() + bytes(pixels)

    def test_real_brand_signature_is_required(self) -> None:
        width, height, pixels = qemu_ui.parse_ppm(self.branded_ppm())
        self.assertEqual((width, height), (640, 480))
        self.assertEqual(
            qemu_ui.frame_signature(width, height, pixels),
            "dimension=standard dark=true lime=true cyan=true quantized8=true",
        )
        qemu_ui.attest_kernaid_render(pixels)
        blank = b"\0" * len(pixels)
        self.assertEqual(
            qemu_ui.frame_signature(width, height, blank),
            "dimension=standard dark=false lime=false cyan=false quantized8=false",
        )
        with self.assertRaises(qemu_ui.SmokeError):
            qemu_ui.attest_kernaid_render(blank)

    def test_keyboard_gate_counts_actual_rgb_pixel_changes(self) -> None:
        _width, _height, before = qemu_ui.parse_ppm(self.branded_ppm())
        after = bytearray(before)
        for index in range(137):
            offset = (1000 + index) * 3
            after[offset : offset + 3] = b"\x50\xd8\xe8"
        self.assertEqual(qemu_ui.changed_pixels(before, bytes(after)), 137)
        with self.assertRaises(qemu_ui.SmokeError):
            qemu_ui.changed_pixels(before, bytes(after[:-3]))

    def test_ppm_parser_rejects_weak_or_oversized_frames(self) -> None:
        for payload in (
            b"P3\n640 480\n255\n",
            b"P6\n639 480\n255\n" + b"\0" * (639 * 480 * 3),
            b"P6\n640 480\n65535\n",
        ):
            with self.subTest(payload=payload[:16]):
                with self.assertRaises(qemu_ui.SmokeError):
                    qemu_ui.parse_ppm(payload)

    def test_qmp_handshake_sends_a_real_tab_and_attests_the_pixel_delta(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            work_directory = Path(temporary)
            work_directory.chmod(0o700)
            socket_path = work_directory / "qmp.sock"
            server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            server.bind(str(socket_path))
            socket_path.chmod(0o700)
            server.listen(1)
            commands: list[dict[str, object]] = []
            server_errors: list[BaseException] = []

            def serve() -> None:
                try:
                    connection, _ = server.accept()
                    with connection, connection.makefile("rwb", buffering=0) as stream:
                        stream.write(
                            b'{"QMP":{"version":{},"capabilities":[]}}\r\n'
                        )
                        screendumps = 0
                        for _ in range(6):
                            request = json.loads(stream.readline())
                            commands.append(request)
                            if request["execute"] == "screendump":
                                if screendumps == 0:
                                    payload = b"P6\n640 480\n255\n" + b"\0" * (
                                        640 * 480 * 3
                                    )
                                else:
                                    payload = self.branded_ppm()
                                if screendumps == 2:
                                    width, height, pixels = qemu_ui.parse_ppm(payload)
                                    changed = bytearray(pixels)
                                    for index in range(137):
                                        offset = (1000 + index) * 3
                                        changed[offset : offset + 3] = b"\x50\xd8\xe8"
                                    payload = (
                                        f"P6\n{width} {height}\n255\n".encode()
                                        + bytes(changed)
                                    )
                                Path(request["arguments"]["filename"]).write_bytes(
                                    payload
                                )
                                screendumps += 1
                            response = {"return": {}, "id": request["id"]}
                            if request["execute"] == "query-status":
                                response["return"] = {"running": True}
                            stream.write(
                                json.dumps(response, separators=(",", ":")).encode()
                                + b"\r\n"
                            )
                except BaseException as error:  # Preserve a thread failure.
                    server_errors.append(error)
                finally:
                    server.close()

            thread = threading.Thread(target=serve, daemon=True)
            thread.start()
            diagnostics = io.StringIO()
            with redirect_stderr(diagnostics):
                marker = qemu_ui.run(socket_path, work_directory, "bios")
            thread.join(timeout=5)
            self.assertFalse(thread.is_alive())
            self.assertEqual(server_errors, [])
            self.assertEqual(
                marker,
                "KERNAID_QEMU_TAURI_UI_ATTESTATION_V1 firmware=bios "
                "shell=shipping renderer=webkit2gtk-4.1 display=default "
                "rendered=true "
                "input=true width=640 height=480 changed_pixels=137",
            )
            self.assertEqual(
                [command["execute"] for command in commands],
                [
                    "qmp_capabilities",
                    "query-status",
                    "screendump",
                    "screendump",
                    "input-send-event",
                    "screendump",
                ],
            )
            self.assertEqual(
                commands[4]["execute"],
                "input-send-event",
            )
            input_events = commands[4]["arguments"]["events"]
            self.assertEqual(
                input_events,
                [
                    {
                        "type": "key",
                        "data": {
                            "down": True,
                            "key": {"type": "qcode", "data": "tab"},
                        },
                    },
                    {
                        "type": "key",
                        "data": {
                            "down": False,
                            "key": {"type": "qcode", "data": "tab"},
                        },
                    },
                ],
            )
            self.assertFalse((work_directory / "before.ppm").exists())
            self.assertFalse((work_directory / "after.ppm").exists())
            diagnostic_lines = diagnostics.getvalue().splitlines()
            self.assertEqual(len(diagnostic_lines), 3)
            self.assertEqual(
                diagnostic_lines[0],
                "KERNAID_QEMU_TAURI_FRAME_V1 dimension=standard dark=false "
                "lime=false cyan=false quantized8=false",
            )
            self.assertTrue(
                all(
                    line
                    == "KERNAID_QEMU_TAURI_FRAME_V1 dimension=standard "
                    "dark=true lime=true cyan=true quantized8=true"
                    for line in diagnostic_lines[1:]
                )
            )


class RescueTauriBoundaryTests(unittest.TestCase):
    def test_session_timeout_reports_the_complete_fixed_pending_set(self) -> None:
        for states, expected in (
            ((True, True, True), None),
            ((False, True, True), "wait-xauthority"),
            ((True, False, True), "wait-runtime"),
            ((True, True, False), "wait-process"),
            ((False, False, True), "wait-xauthority-runtime"),
            ((False, True, False), "wait-xauthority-process"),
            ((True, False, False), "wait-runtime-process"),
            ((False, False, False), "wait-xauthority-runtime-process"),
        ):
            with self.subTest(states=states):
                self.assertEqual(session_ui._pending_stage(*states), expected)
                if expected is not None:
                    self.assertIn(expected, session_ui.SESSION_FAILURE_STAGES)

    def test_session_gate_retries_only_the_nonfinal_ui_executable(self) -> None:
        account = mock.Mock(pw_uid=991, pw_gid=991)
        valid_status = (
            b"Uid:\t991\t991\t991\t991\n"
            b"Gid:\t991\t991\t991\t991\n"
            b"Groups:\t991\n"
        )
        scanner = mock.MagicMock()
        entry = mock.Mock()
        entry.name = "41"
        scanner.__enter__.return_value = [entry]
        final_environment = {
            b"DISPLAY": session_ui.DISPLAY,
            b"XAUTHORITY": session_ui.XAUTHORITY.encode("ascii"),
            b"XDG_RUNTIME_DIR": session_ui.UI_RUNTIME.encode("ascii"),
            b"HOME": f"{session_ui.UI_RUNTIME}/home".encode("ascii"),
            b"DBUS_SESSION_BUS_ADDRESS": (
                f"unix:path={session_ui.UI_RUNTIME}/no-session-bus".encode("ascii")
            ),
            b"DBUS_SYSTEM_BUS_ADDRESS": (
                f"unix:path={session_ui.UI_RUNTIME}/no-system-bus".encode("ascii")
            ),
        }

        def observe(executable: str, status: bytes, environment: dict[bytes, bytes]):
            with (
                mock.patch.object(session_ui.os, "scandir", return_value=scanner),
                mock.patch.object(session_ui, "_bounded_file", return_value=status),
                mock.patch.object(session_ui.os, "readlink", return_value=executable),
                mock.patch.object(
                    session_ui, "_environment", return_value=environment
                ),
            ):
                return session_ui._session_process_ready(account)

        self.assertFalse(observe("/usr/bin/dash", valid_status, final_environment))
        self.assertTrue(
            observe(
                session_ui.WINDOW_MANAGER_PATH,
                valid_status,
                final_environment,
            )
        )
        handoff_scanner = mock.MagicMock()
        handoff_entries = [mock.Mock(), mock.Mock()]
        handoff_entries[0].name = "40"
        handoff_entries[1].name = "41"
        handoff_scanner.__enter__.return_value = handoff_entries

        def handoff_executable(path: str) -> str:
            return (
                "/usr/bin/dash"
                if path == "/proc/40/exe"
                else session_ui.WINDOW_MANAGER_PATH
            )

        with (
            mock.patch.object(session_ui.os, "scandir", return_value=handoff_scanner),
            mock.patch.object(session_ui, "_bounded_file", return_value=valid_status),
            mock.patch.object(session_ui.os, "readlink", side_effect=handoff_executable),
            mock.patch.object(
                session_ui, "_environment", return_value=final_environment
            ),
        ):
            self.assertTrue(session_ui._session_process_ready(account))
        with self.assertRaises(session_ui.SessionError) as environment_error:
            observe(
                session_ui.WINDOW_MANAGER_PATH,
                valid_status,
                final_environment | {b"XDG_RUNTIME_DIR": b"/run/user/991"},
            )
        self.assertEqual(environment_error.exception.stage, "process-environment")
        with self.assertRaises(session_ui.SessionError) as identity_error:
            observe(
                session_ui.WINDOW_MANAGER_PATH,
                valid_status.replace(b"Groups:\t991", b"Groups:\t992"),
                final_environment,
            )
        self.assertEqual(identity_error.exception.stage, "process-identity")
        foreign_status = (
            b"Uid:\t1000\t1000\t1000\t1000\n"
            b"Gid:\t1000\t1000\t1000\t1000\n"
            b"Groups:\t1000\n"
        )
        self.assertFalse(
            observe(
                "/usr/bin/sleep",
                foreign_status,
                {b"DISPLAY": session_ui.DISPLAY},
            )
        )

        with (
            mock.patch.object(session_ui.os, "scandir", return_value=scanner),
            mock.patch.object(
                session_ui,
                "_process_identity",
                side_effect=session_ui.SessionError(),
            ),
        ):
            self.assertFalse(session_ui._session_process_ready(account))

    def test_session_failure_marker_exposes_only_an_allowlisted_stage(self) -> None:
        for stage in (
            "process",
            "process-foreign-display",
            "user-runtime-mask",
            "not-allowlisted",
        ):
            with self.subTest(stage=stage):
                output = io.StringIO()
                with (
                    mock.patch.object(
                        session_ui,
                        "attest",
                        side_effect=session_ui.SessionError(stage),
                    ),
                    redirect_stdout(output),
                ):
                    self.assertEqual(session_ui.main(), 1)
                expected = stage if stage in session_ui.SESSION_FAILURE_STAGES else "internal"
                self.assertEqual(
                    output.getvalue(),
                    f"{session_ui.SESSION_FAILURE_PREFIX}{expected}\n",
                )

    def test_shell_readiness_is_root_attested_not_a_uid_marker(self) -> None:
        normal = {
            "ActiveState": "active",
            "SubState": "running",
            "MainPID": "431",
            "User": guest_ui.UI_ACCOUNT,
            "Group": guest_ui.UI_ACCOUNT,
            "Type": "exec",
            "PrivateDevices": "yes",
            "DevicePolicy": "closed",
        }
        session = {
            "ActiveState": "active",
            "SubState": "exited",
            "Result": "success",
        }
        with mock.patch.object(
            guest_ui, "_systemctl_show", side_effect=[normal, session]
        ):
            self.assertEqual(guest_ui._shell_service_ready(False), 431)
        with mock.patch.object(
            guest_ui, "_systemctl_show", return_value=normal | {"Type": "notify"}
        ):
            self.assertEqual(guest_ui._shell_service_ready(True), 0)

    def test_privileged_socket_accepts_both_operational_substates(self) -> None:
        endpoint = (
            "/run/test.sock",
            "test.socket",
            "test-group",
            0o660,
            "socket-vault",
        )
        metadata = mock.Mock(
            st_mode=stat.S_IFSOCK | 0o660,
            st_uid=0,
            st_gid=77,
            st_nlink=1,
        )
        with (
            mock.patch.object(
                guest_ui, "PRIVILEGED_SOCKET_ENDPOINTS", (endpoint,)
            ),
            mock.patch.object(
                guest_ui.grp, "getgrnam", return_value=mock.Mock(gr_gid=77)
            ),
            mock.patch.object(guest_ui.os, "lstat", return_value=metadata),
        ):
            for substate in ("listening", "running"):
                with (
                    self.subTest(substate=substate),
                    mock.patch.object(
                        guest_ui,
                        "_systemctl_show",
                        return_value={
                            "ActiveState": "active",
                            "SubState": substate,
                            "Result": "success",
                        },
                    ),
                ):
                    guest_ui._host_privileged_sockets_ready()
            with (
                mock.patch.object(
                    guest_ui,
                    "_systemctl_show",
                    return_value={
                        "ActiveState": "active",
                        "SubState": "dead",
                        "Result": "success",
                    },
                ),
                self.assertRaises(guest_ui.SandboxFailure),
            ):
                guest_ui._host_privileged_sockets_ready()

    def test_guest_requires_the_default_display_xorg_vt_to_be_active(self) -> None:
        self.assertEqual(guest_ui._active_vt_from_payload(b"tty7\n"), 7)
        self.assertEqual(
            guest_ui._xorg_vt_from_cmdline(
                b"/usr/lib/xorg/Xorg\0:0\0-seat\0seat0\0"
                b"-auth\0/run/lightdm/root/:0\0-nolisten\0tcp\0"
                b"-extension\0DRI2\0-extension\0DRI3\0"
                b"-extension\0XTEST\0"
                b"vt7\0-novtswitch\0"
            ),
            7,
        )
        self.assertIsNone(
            guest_ui._xorg_vt_from_cmdline(
                b"/usr/lib/xorg/Xorg\0:1\0-auth\0/run/lightdm/root/:0\0"
                b"-nolisten\0tcp\0vt7\0"
            )
        )
        for payload in (b"tty0\n", b"tty64\n", b"tty7 private\n"):
            with self.subTest(payload=payload):
                with self.assertRaises(guest_ui.AttestationError):
                    guest_ui._active_vt_from_payload(payload)

    def test_guest_renderer_must_descend_from_the_shipping_shell(self) -> None:
        processes = {
            pid: guest_ui.ProcessIdentity(
                parent,
                (991, 991, 991, 991),
                (991, 991, 991, 991),
                frozenset(),
                executable,
                {},
            )
            for pid, parent, executable in (
                (10, 1, guest_ui.SHELL_PATH),
                (11, 10, f"{guest_ui.WEBKIT_ROOT}/WebKitNetworkProcess"),
                (12, 11, f"{guest_ui.WEBKIT_ROOT}/WebKitWebProcess"),
                (20, 1, f"{guest_ui.WEBKIT_ROOT}/WebKitWebProcess"),
            )
        }
        self.assertTrue(guest_ui._descends_from(12, 10, processes))
        self.assertFalse(guest_ui._descends_from(20, 10, processes))

    def test_process_observation_retries_only_unstable_snapshots(self) -> None:
        expected = object()
        self.assertEqual(
            guest_ui._retryable_process_observation(
                lambda: expected, "process-metadata-access"
            ),
            (expected, None),
        )
        for error in (
            guest_ui.AttestationError("unstable process metadata"),
            PermissionError("process changed during observation"),
        ):
            operation = mock.Mock(side_effect=error)
            self.assertEqual(
                guest_ui._retryable_process_observation(
                    operation, "process-metadata-access"
                ),
                (None, "process-metadata-access"),
            )
        observation_error = guest_ui.ProcessObservationFailure(
            "process-environ-access"
        )
        self.assertEqual(
            guest_ui._retryable_process_observation(
                mock.Mock(side_effect=observation_error),
                "process-metadata-access",
            ),
            (None, "process-environ-access"),
        )
        with self.assertRaises(guest_ui.SandboxFailure):
            guest_ui._retryable_process_observation(
                mock.Mock(side_effect=guest_ui.SandboxFailure("identity")),
                "process-metadata-access",
            )

    def test_process_environment_extracts_only_attested_unique_names(self) -> None:
        self.assertEqual(
            guest_ui._environment(
                b"PATH=/bin\0PATH=/usr/bin\0malformed\0DISPLAY=:0\0"
                b"XAUTHORITY=/run/lightdm/kernaid-rescue-ui/xauthority\0"
            ),
            {
                b"DISPLAY": b":0",
                b"XAUTHORITY": (
                    b"/run/lightdm/kernaid-rescue-ui/xauthority"
                ),
            },
        )
        with self.assertRaises(guest_ui.AttestationError):
            guest_ui._environment(b"DISPLAY=:0\0DISPLAY=:0.0\0")

    def test_pid_namespace_failure_path_returns_only_none(self) -> None:
        with mock.patch.object(guest_ui.os, "stat") as stat_result:
            stat_result.return_value.st_ino = 7
            self.assertIsNone(guest_ui._private_pid_namespace_aliases(41, 42))

    def test_private_device_inventory_rejects_block_and_sensitive_devices(self) -> None:
        ui = mock.Mock(pw_uid=991, pw_gid=991)
        root = "/proc/431/root/dev"
        directory = os.stat_result((stat.S_IFDIR | 0o755,) + (0,) * 9)
        character = os.stat_result((stat.S_IFCHR | 0o666,) + (0,) * 9)
        block = os.stat_result((stat.S_IFBLK | 0o600,) + (0,) * 9)

        with (
            mock.patch.object(
                guest_ui.os, "walk", return_value=[(root, [], ["null"])]
            ),
            mock.patch.object(
                guest_ui.os,
                "lstat",
                side_effect=lambda path: directory if path == root else character,
            ),
            mock.patch.object(guest_ui.os.path, "lexists", return_value=False),
            mock.patch.object(
                guest_ui, "_drop_identity_probe", return_value=True
            ) as dropped,
        ):
            self.assertTrue(guest_ui._private_devices_ready(431, ui))
            dropped.assert_called_once()

        with (
            mock.patch.object(
                guest_ui.os, "walk", return_value=[(root, [], ["physical0"])]
            ),
            mock.patch.object(
                guest_ui.os,
                "lstat",
                side_effect=lambda path: directory if path == root else block,
            ),
        ):
            self.assertFalse(guest_ui._private_devices_ready(431, ui))

        with tempfile.TemporaryDirectory() as temporary_directory:
            missing = os.path.join(temporary_directory, "missing-device")
            present = os.path.join(temporary_directory, "present-device")
            Path(present).touch()
            self.assertTrue(guest_ui._open_absent(missing))
            self.assertFalse(guest_ui._open_absent(present))

        self.assertTrue(
            guest_ui._safe_native_character_device(
                mock.Mock(st_rdev=os.makedev(1, 3))
            )
        )
        for major, minor in ((5, 0), (10, 223), (13, 64), (29, 0), (226, 128)):
            with self.subTest(major=major, minor=minor):
                self.assertFalse(
                    guest_ui._safe_native_character_device(
                        mock.Mock(st_rdev=os.makedev(major, minor))
                    )
                )

    def test_native_xauthority_parser_is_bounded_and_exact(self) -> None:
        def field(value: bytes) -> bytes:
            return struct.pack(">H", len(value)) + value

        payload = b"".join(
            (
                struct.pack(">H", 256),
                field(b"rescue-host"),
                field(b"0"),
                field(b"MIT-MAGIC-COOKIE-1"),
                field(bytes(range(1, 17))),
            )
        )
        self.assertTrue(session_ui._valid_xauthority_payload(payload))
        with tempfile.TemporaryFile() as empty:
            self.assertEqual(session_ui._read_all(empty.fileno()), b"")
        self.assertFalse(session_ui._valid_xauthority_payload(b""))
        self.assertFalse(session_ui._valid_xauthority_payload(payload[:-1]))
        self.assertFalse(
            session_ui._valid_xauthority_payload(
                payload.replace(b"MIT-MAGIC-COOKIE-1", b"MIT-MAGIC-COOKIE-2")
            )
        )

    def test_process_metadata_bounded_read_collects_fragmented_chunks(self) -> None:
        expected = b"DISPLAY=:0\0XAUTHORITY=/run/lightdm/rescue/xauthority\0"
        fragments = [expected[:11], expected[11:37], expected[37:], b""]
        for module in (session_ui, guest_ui):
            with self.subTest(module=module.__name__):
                with (
                    mock.patch.object(module.os, "open", return_value=71),
                    mock.patch.object(
                        module.os,
                        "read",
                        side_effect=fragments.copy(),
                    ) as read,
                    mock.patch.object(module.os, "close") as close,
                ):
                    self.assertEqual(module._bounded_file("/proc/71/environ"), expected)
                self.assertEqual(read.call_count, len(fragments))
                close.assert_called_once_with(71)

    def test_process_metadata_bounded_read_rejects_oversize_payload(self) -> None:
        cases = (
            (session_ui, session_ui.MAX_FILE_BYTES, session_ui.SessionError),
            (
                guest_ui,
                guest_ui.MAX_PROCESS_FILE_BYTES,
                guest_ui.AttestationError,
            ),
        )
        for module, limit, error in cases:
            with self.subTest(module=module.__name__):
                with (
                    mock.patch.object(module.os, "open", return_value=72),
                    mock.patch.object(
                        module.os,
                        "read",
                        side_effect=[b"x" * limit, b"x"],
                    ),
                    mock.patch.object(module.os, "close") as close,
                ):
                    with self.assertRaises(error):
                        module._bounded_file("/proc/72/environ")
                close.assert_called_once_with(72)

    def test_session_gate_retries_an_incomplete_xauthority_handoff(self) -> None:
        account = mock.Mock()
        with mock.patch.object(
            session_ui,
            "_xauthority_ready",
            side_effect=[session_ui.SessionError("xauthority"), True],
        ):
            self.assertFalse(session_ui._xauthority_observation(account))
            self.assertTrue(session_ui._xauthority_observation(account))

    def test_window_binds_inner_pid_one_not_systemd_host_pid(self) -> None:
        ui = mock.Mock()
        with mock.patch.object(
            guest_ui,
            "_run_as_ui",
            side_effect=["77\n", "1\n", "WIDTH=1024\nHEIGHT=768\n"],
        ) as runner:
            self.assertEqual(
                guest_ui._visible_window(431, ui, "/run/pinned-xauthority"),
                (1024, 768),
            )
        self.assertNotIn("--pid", runner.call_args_list[0].args[0])
        self.assertEqual(runner.call_args_list[1].args[0][1], "getwindowpid")

        with mock.patch.object(
            guest_ui, "_run_as_ui", side_effect=["77\n", "431\n"]
        ):
            self.assertIsNone(
                guest_ui._visible_window(431, ui, "/run/pinned-xauthority")
            )

    def test_rescue_config_grants_only_closed_prompt_status_and_open(self) -> None:
        config = json.loads(
            (
                REPO_DIR / "apps/desk/src-tauri-rescue/tauri.conf.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(config["app"]["windows"], [])
        capabilities = config["app"]["security"]["capabilities"]
        self.assertEqual(len(capabilities), 1)
        self.assertIs(capabilities[0]["local"], False)
        self.assertEqual(
            capabilities[0]["permissions"],
            [
                "allow-rescue-native-prompt-status",
                "allow-open-rescue-native-prompt",
            ],
        )
        self.assertEqual(
            capabilities[0]["remote"]["urls"],
            ["http://127.0.0.1:4173/*"],
        )

        source = (
            REPO_DIR
            / "apps/desk/src-tauri-rescue/src/main.rs"
        ).read_text(encoding="utf-8")
        self.assertEqual(source.count(".invoke_handler("), 1)
        self.assertEqual(source.count("rescue_native_prompt_status,"), 1)
        self.assertEqual(source.count("open_rescue_native_prompt\n"), 1)
        self.assertNotIn("Command::new", source)
        self.assertIn("tauri::generate_context!()", source)
        self.assertLess(
            source.index("let status = attest_rescue_sandbox()"),
            source.index("tauri::Builder::default()"),
        )
        self.assertLess(
            source.index("bootstrap_native_prompt_transport(status"),
            source.index("WebviewWindowBuilder::new"),
        )
        self.assertIn(
            "bootstrap_native_prompt_transport(status, relay_native_prompt_status)",
            source,
        )
        self.assertLess(
            source.index("let status = attest_rescue_sandbox()"),
            source.index('eprintln!("{status}")'),
        )
        self.assertLess(
            source.index('eprintln!("{status}")'),
            source.index("tauri::Builder::default()"),
        )
        self.assertLess(
            source.index("tauri::Builder::default()"),
            source.index("WebviewWindowBuilder::new"),
        )
        self.assertIn("RunEvent::ExitRequested", source)
        self.assertIn("!window_created.load(Ordering::Acquire)", source)
        self.assertIn("api.prevent_exit()", source)
        self.assertLess(
            source.index("WebviewWindowBuilder::new"),
            source.index("setup_window_created.store(true, Ordering::Release)"),
        )
        self.assertNotIn("notify_systemd", source)
        self.assertNotIn("sandbox-attestation-v1", source)
        self.assertNotIn("sandbox-failure-v1", source)
        self.assertIn('["", "/proc/1/root", "/proc/self/root"]', source)
        self.assertIn("on_navigation(allowed_rescue_navigation)", source)
        self.assertIn("on_new_window(|_, _| NewWindowResponse::Deny)", source)
        self.assertIn("on_download(|_, _| false)", source)

        workspace = (REPO_DIR / "Cargo.toml").read_text(encoding="utf-8")
        self.assertIn('"apps/desk/src-tauri-rescue"', workspace)
        self.assertNotIn("tauri.rescue.conf.json", source)

    def test_live_image_has_one_unprivileged_supervised_shell(self) -> None:
        service = (
            REPO_DIR
            / "rescue/live-build/config/includes.chroot/etc/systemd/system"
            / "kernaid-rescue-desk-shell.service"
        ).read_text(encoding="utf-8")
        legacy_autostart = (
            REPO_DIR
            / "rescue/live-build/config/includes.chroot/etc/xdg/autostart"
            / "kernaid.desktop"
        )
        packages = (
            REPO_DIR
            / "rescue/live-build/config/package-lists/kernaid.list.chroot"
        ).read_text(encoding="utf-8").splitlines()
        safety_hook = (
            REPO_DIR
            / "rescue/live-build/config/hooks/live/0100-kernaid-safety.hook.chroot"
        ).read_text(encoding="utf-8")
        ready_service = (
            REPO_DIR
            / "rescue/live-build/config/includes.chroot/etc/systemd/system"
            / "kernaid-ready.service"
        ).read_text(encoding="utf-8")
        self.assertFalse(legacy_autostart.exists())
        self.assertIn("ExecStart=/usr/bin/kernaid-rescue-desk-shell", service)
        self.assertIn("Type=exec", service)
        self.assertNotIn("NotifyAccess=", service)
        self.assertNotIn("/run/systemd/notify", service)
        self.assertIn("User=kernaid-rescue-ui", service)
        self.assertIn("Group=kernaid-rescue-ui", service)
        self.assertIn("Restart=always", service)
        self.assertNotIn("TimeoutStartSec=", service)
        self.assertEqual(guest_ui.PROBE_TIMEOUT_SECONDS, 620)
        ready_check = (
            REPO_DIR
            / "rescue/live-build/config/includes.chroot/usr/lib/kernaid/ready-check"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "/usr/bin/timeout --signal=TERM --kill-after=2s 630s", ready_check
        )
        self.assertIn("StandardOutput=journal+console", service)
        self.assertIn("StandardError=journal+console", service)
        self.assertIn("NoNewPrivileges=yes", service)
        self.assertIn("CapabilityBoundingSet=\n", service)
        shipping_sockets = {
            "kernaid-offline-inspector.socket": "/run/kernaid-offline-inspector.sock",
            "kernaid-rescue-vaultd.socket": "/run/kernaid-rescue-vault.sock",
            "kernaid-rescue-openai-executor.socket": "/run/kernaid-rescue-openai.sock",
            "kernaid-rescue-openai-egress.socket": "/run/kernaid-rescue-openai-egress.sock",
            "kernaid-rescue-codex.socket": "/run/kernaid-rescue-codex.sock",
        }
        unit_values: dict[str, set[str]] = {}
        for line in service.splitlines():
            if "=" not in line:
                continue
            directive, value = line.split("=", 1)
            unit_values.setdefault(directive, set()).update(value.split())
        for directive in ("Requires", "After"):
            self.assertTrue(shipping_sockets.keys() <= unit_values[directive])
        for directive in ("Requires", "After"):
            self.assertIn(
                "kernaid-tauri-network-probe-baseline.service",
                unit_values[directive],
            )
        self.assertNotIn(
            "kernaid-tauri-network-probe-baseline.service", unit_values["Wants"]
        )
        self.assertNotIn("InaccessiblePaths", unit_values)
        self.assertEqual(
            unit_values["RestrictAddressFamilies"],
            {"AF_UNIX", "AF_INET", "AF_INET6", "AF_NETLINK"},
        )
        self.assertEqual(unit_values["IPAddressDeny"], {"any"})
        self.assertEqual(unit_values["IPAddressAllow"], {"localhost"})
        self.assertEqual(unit_values["RuntimeDirectory"], {"kernaid-rescue-desk-shell"})
        self.assertEqual(unit_values["TemporaryFileSystem"], {"/run:ro"})
        self.assertEqual(unit_values["PrivatePIDs"], {"yes"})
        self.assertEqual(unit_values["PrivateDevices"], {"yes"})
        self.assertEqual(unit_values["DevicePolicy"], {"closed"})
        self.assertEqual(unit_values["PrivateTmp"], {"yes"})
        self.assertTrue(
            {
                "/run/lightdm/kernaid-rescue-ui/xauthority",
                "-/run/kernaid-tauri-network-probe/baseline-v1",
                "-/run/kernaid-rescue-native-prompt.sock",
                "/tmp/.X11-unix/X0",
            }
            <= unit_values["BindReadOnlyPaths"]
        )
        self.assertEqual(
            unit_values["BindPaths"], {"/run/kernaid-rescue-desk-shell"}
        )
        self.assertIn("DBUS_SESSION_BUS_ADDRESS=unix:path=/run/kernaid-rescue-desk-shell/no-session-bus", service)
        self.assertIn("DBUS_SYSTEM_BUS_ADDRESS=unix:path=/run/kernaid-rescue-desk-shell/no-system-bus", service)
        self.assertIn("WEBKIT_DISABLE_COMPOSITING_MODE=1", service)
        self.assertIn("WEBKIT_DMABUF_RENDERER_FORCE_SHM=1", service)
        self.assertIn("WEBKIT_DMABUF_RENDERER_DISABLE_GBM=1", service)
        self.assertIn("WEBKIT_SKIA_ENABLE_CPU_RENDERING=1", service)
        self.assertIn("LIBGL_ALWAYS_SOFTWARE=1", service)
        self.assertIn("MESA_SHADER_CACHE_DISABLE=true", service)
        self.assertNotIn("WEBKIT_DISABLE_DMABUF_RENDERER=1", service)
        self.assertNotIn("ExecStartPre=", service)
        self.assertNotIn("chromium", service.lower())
        self.assertIn("systemctl enable kernaid-rescue-desk-shell.service", safety_hook)
        self.assertIn("kernaid-rescue-desk-shell.service", ready_service)
        self.assertIn("libwebkit2gtk-4.1-0", packages)
        self.assertIn("xdotool", packages)
        self.assertIn("matchbox-window-manager", packages)
        self.assertIn("kbd", packages)
        self.assertNotIn("xfwm4", packages)
        self.assertIn("xserver-xorg", packages)
        self.assertNotIn("xorg", packages)
        self.assertNotIn("xfce4", packages)
        self.assertNotIn("xfce4-terminal", packages)
        self.assertNotIn("dbus-user-session", packages)
        self.assertNotIn("chromium", packages)
        self.assertIn(
            "systemctl enable kernaid-rescue-native-prompt.socket", safety_hook
        )

        baseline_service = (
            REPO_DIR
            / "rescue/live-build/config/includes.chroot/etc/systemd/system"
            / "kernaid-tauri-network-probe-baseline.service"
        ).read_text(encoding="utf-8")
        address_service = (
            REPO_DIR
            / "rescue/live-build/config/includes.chroot/etc/systemd/system"
            / "kernaid-tauri-network-probe-address.service"
        ).read_text(encoding="utf-8")
        socket_service = (
            REPO_DIR
            / "rescue/live-build/config/includes.chroot/etc/systemd/system"
            / "kernaid-tauri-network-probe.socket"
        ).read_text(encoding="utf-8")
        sink_service = (
            REPO_DIR
            / "rescue/live-build/config/includes.chroot/etc/systemd/system"
            / "kernaid-tauri-network-probe@.service"
        ).read_text(encoding="utf-8")
        modules_load = (
            REPO_DIR
            / "rescue/live-build/config/includes.chroot/etc/modules-load.d"
            / "kernaid-qemu-fw-cfg.conf"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "RestrictAddressFamilies=AF_UNIX AF_INET AF_NETLINK",
            baseline_service,
        )
        for probe_unit in (
            address_service,
            socket_service,
            baseline_service,
            sink_service,
        ):
            self.assertNotIn("ConditionPathExists=", probe_unit)
            self.assertIn("ConditionVirtualization=|qemu", probe_unit)
            self.assertIn("ConditionVirtualization=|kvm", probe_unit)
        self.assertIn("FreeBind=yes", socket_service)
        socket_unit_values: dict[str, set[str]] = {}
        for raw_line in socket_service.splitlines():
            line = raw_line.strip()
            if not line or line.startswith(("#", ";")) or "=" not in line:
                continue
            directive, value = line.split("=", 1)
            socket_unit_values.setdefault(directive, set()).update(value.split())
        # DefaultDependencies=no is the guard against the implicit
        # socket -> sockets.target edge that would close an ordering cycle.
        self.assertEqual(socket_unit_values["DefaultDependencies"], {"no"})
        self.assertEqual(
            socket_unit_values["Requires"],
            {"basic.target", "kernaid-tauri-network-probe-address.service"},
        )
        self.assertEqual(
            socket_unit_values["After"],
            {"basic.target", "kernaid-tauri-network-probe-address.service"},
        )
        self.assertEqual(socket_unit_values["Conflicts"], {"shutdown.target"})
        self.assertEqual(
            socket_unit_values["Before"],
            {
                "kernaid-tauri-network-probe-baseline.service",
                "kernaid-rescue-desk-shell.service",
                "shutdown.target",
            },
        )
        self.assertFalse(
            any(
                "sockets.target" in values
                for values in socket_unit_values.values()
            )
        )
        self.assertIn(
            "Wants=systemd-modules-load.service systemd-udev-settle.service "
            "live-config.service NetworkManager.service "
            "NetworkManager-wait-online.service",
            address_service,
        )
        self.assertIn(
            "After=systemd-modules-load.service systemd-udev-settle.service "
            "live-config.service NetworkManager.service "
            "NetworkManager-wait-online.service",
            address_service,
        )
        self.assertIn(
            "ExecStartPre=/usr/bin/python3 -I /usr/lib/kernaid/tauri_network_probe.py wait-marker",
            address_service,
        )
        self.assertIn("TimeoutStartSec=240s", address_service)
        self.assertIn("TimeoutStartSec=90s", baseline_service)
        self.assertIn("RuntimeDirectory=kernaid-tauri-network-probe", baseline_service)
        self.assertIn("RuntimeDirectoryMode=0755", baseline_service)
        self.assertIn("RemainAfterExit=yes", baseline_service)
        self.assertEqual(network_probe.FW_CFG_WAIT_SECONDS, 180.0)
        self.assertEqual(network_probe.SCHEDULING_WAIT_SECONDS, 30.0)
        for probe_service in (address_service, baseline_service):
            self.assertIn("StandardOutput=journal+console", probe_service)
            self.assertIn("StandardError=journal+console", probe_service)
        self.assertEqual(modules_load, "qemu_fw_cfg\n")

    def test_network_probe_retries_alias_and_baseline_connect(self) -> None:
        with (
            mock.patch.object(network_probe, "_read_fw_cfg"),
            mock.patch.object(
                network_probe,
                "_alias_ready_once",
                side_effect=[network_probe.ProbeError(), None, None],
            ) as alias,
            mock.patch.object(
                network_probe,
                "_connect_once",
                side_effect=[network_probe.ProbeError(), None],
            ) as connect,
            mock.patch.object(network_probe, "_write_baseline") as write,
            mock.patch.object(network_probe.time, "sleep"),
        ):
            network_probe.run("verify-alias")
            network_probe.run("baseline")
        self.assertEqual(alias.call_count, 3)
        self.assertEqual(connect.call_count, 2)
        write.assert_called_once_with()

    def test_network_probe_scheduling_retry_is_bounded(self) -> None:
        with (
            mock.patch.object(
                network_probe,
                "_alias_ready_once",
                side_effect=network_probe.ProbeError(),
            ),
            mock.patch.object(
                network_probe.time, "monotonic", side_effect=[0.0, 31.0]
            ),
            mock.patch.object(network_probe.time, "sleep") as sleep,
        ):
            with self.assertRaises(network_probe.ProbeError):
                network_probe._wait_for_alias()
        sleep.assert_not_called()

    def test_network_probe_failure_is_fixed_and_stage_only(self) -> None:
        for mode in ("wait-marker", "verify-alias", "baseline"):
            with self.subTest(mode=mode):
                output = io.StringIO()
                with (
                    mock.patch.object(network_probe.sys, "argv", ["probe", mode]),
                    mock.patch.object(
                        network_probe,
                        "run",
                        side_effect=network_probe.ProbeError(),
                    ),
                    redirect_stderr(output),
                ):
                    self.assertEqual(network_probe.main(), 1)
                self.assertEqual(
                    output.getvalue(),
                    f"KERNAID_TAURI_NETWORK_PROBE_FAILURE_V1 stage={mode}\n",
                )

    def test_guest_defers_live_endpoint_to_the_final_retrying_gate(self) -> None:
        source = (
            REPO_DIR
            / "rescue/live-build/config/includes.chroot/usr/lib/kernaid"
            / "tauri_ui_ready_check.py"
        ).read_text(encoding="utf-8")
        attest_source = source[source.index("def attest()") : source.index("\ndef main()")]
        self.assertNotIn("_qemu_baseline_ready", source)
        self.assertLess(
            attest_source.index("_private_run_ready"),
            attest_source.index("_qemu_endpoint_post_ready"),
        )
        self.assertIn('last_stage = "endpoint-post"', attest_source)
        self.assertIn("continue\n        return *window, qemu_probe", attest_source)

    def test_lightdm_session_is_minimal_and_busless(self) -> None:
        root = REPO_DIR / "rescue/live-build/config/includes.chroot"
        sysusers = (root / "etc/sysusers.d/kernaid.conf").read_text(encoding="utf-8")
        tmpfiles = (root / "usr/lib/tmpfiles.d/kernaid.conf").read_text(encoding="utf-8")
        lightdm = (
            root / "etc/lightdm/lightdm.conf.d/99-kernaid-rescue-ui.conf"
        ).read_text(encoding="utf-8")
        pam = (root / "etc/pam.d/kernaid-rescue-ui-autologin").read_text(
            encoding="utf-8"
        )
        session = (root / "usr/lib/kernaid/rescue-ui-session").read_text(
            encoding="utf-8"
        )
        keyboard_map = (root / "usr/lib/kernaid/matchbox-kbdconfig").read_text(
            encoding="utf-8"
        )
        attestor_unit = (
            root / "etc/systemd/system/kernaid-rescue-ui-session-ready.service"
        ).read_text(encoding="utf-8")
        safety_hook = (
            REPO_DIR
            / "rescue/live-build/config/hooks/live/0100-kernaid-safety.hook.chroot"
        ).read_text(encoding="utf-8")
        ui_home = "/run/kernaid-rescue-ui-session/home"
        self.assertIn(
            'u kernaid-rescue-ui - "KernAid Rescue isolated graphical shell" '
            f"{ui_home} /usr/sbin/nologin",
            sysusers,
        )
        self.assertIn(
            "d /run/kernaid-rescue-ui-session 0700 kernaid-rescue-ui kernaid-rescue-ui -",
            tmpfiles,
        )
        self.assertIn(
            f"d {ui_home} 0700 kernaid-rescue-ui kernaid-rescue-ui -",
            tmpfiles,
        )
        self.assertEqual(session_ui.UI_HOME, ui_home)
        self.assertEqual(guest_ui.UI_HOME, ui_home)
        rescue_shell = (
            REPO_DIR / "apps/desk/src-tauri-rescue/src/main.rs"
        ).read_text(encoding="utf-8")
        self.assertIn(f'const UI_HOME: &str = "{ui_home}";', rescue_shell)
        self.assertNotIn("qemu_fw_cfg", rescue_shell)
        self.assertIn(
            "fs::symlink_metadata(QEMU_BASELINE_MARKER_PATH)", rescue_shell
        )
        self.assertIn("autologin-user=kernaid-rescue-ui", lightdm)
        self.assertIn("autologin-session=kernaid-rescue-ui", lightdm)
        self.assertIn("run-directory=/run/lightdm", lightdm)
        self.assertIn(
            "xserver-command=X -extension DRI2 -extension DRI3 -extension XTEST",
            lightdm,
        )
        self.assertIn("allow-user-switching=false", lightdm)
        self.assertNotIn("common-session", pam)
        self.assertNotIn("pam_systemd", pam)
        self.assertIn("exec /usr/bin/matchbox-window-manager", session)
        self.assertIn(
            "-kbdconfig /usr/lib/kernaid/matchbox-kbdconfig", session
        )
        self.assertNotIn("=", keyboard_map)
        self.assertEqual(
            safety_hook.count("/usr/lib/kernaid/matchbox-kbdconfig"), 2
        )
        self.assertIn(
            "unset MB_HUNG_APP_HANDLER MB_AGGRESSIVE_PING MB_SYNC SESSION_MANAGER",
            session,
        )
        self.assertNotIn("install -d", session)
        self.assertIn("stat -c '%u:%g:%a' \"$session_home\"", session)
        self.assertNotIn("xfce4-session", session)
        self.assertNotIn("xfwm4", session)
        self.assertIn("no-session-bus", session)
        self.assertIn("no-system-bus", session)
        self.assertIn(
            "CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_SYS_PTRACE",
            attestor_unit,
        )
        self.assertIn("AmbientCapabilities=\n", attestor_unit)
        self.assertIn("PrivateNetwork=yes", attestor_unit)
        self.assertIn("TimeoutStartSec=270s", attestor_unit)
        self.assertIn("StandardOutput=journal+console", attestor_unit)
        self.assertIn("StandardError=journal+console", attestor_unit)
        self.assertNotIn("ProtectHome=", attestor_unit)
        self.assertIn("InaccessiblePaths=/home /root", attestor_unit)
        self.assertIn("BindPaths=/run/user", attestor_unit)
        self.assertIn(
            "SystemCallFilter=~ptrace process_vm_readv process_vm_writev kcmp",
            attestor_unit,
        )
        self.assertIn('if (subject.user == "kernaid-rescue-ui")', safety_hook)
        self.assertIn("return polkit.Result.NO;", safety_hook)

    def test_guest_contract_repeats_identity_pid_bus_and_socket_gates(self) -> None:
        source = (
            REPO_DIR
            / "rescue/live-build/config/includes.chroot/usr/lib/kernaid"
            / "tauri_ui_ready_check.py"
        ).read_text(encoding="utf-8")
        for token in (
            "identity=isolated",
            "pidns=private",
            "shell-bus=mount-masked",
            "session-bus=env-disabled-polkit-denied",
            "fs-sockets=allowlisted",
            "abstract-unix=not-attested",
            "_private_pid_namespace_aliases",
            "_proc_aliases_absent",
            "_private_run_ready",
            "_private_tmp_ready",
            "_private_devices_ready",
            "devices=private",
            "_live_user_x11_denied",
            "WebKitGPUProcess",
            "os.setresuid",
            "os.setgroups([])",
            'values["Type"] != "exec"',
        ):
            self.assertIn(token, source)
        self.assertNotIn("sandbox-attestation-v1", source)
        self.assertNotIn("sandbox-failure-v1", source)

        ready_check = (
            REPO_DIR
            / "rescue/live-build/config/includes.chroot/usr/lib/kernaid/ready-check"
        ).read_text(encoding="utf-8")
        qemu_smoke = (TOOLS_DIR / "qemu-smoke.sh").read_text(encoding="utf-8")
        boundary = (
            "identity=isolated pidns=private shell-bus=mount-masked "
            "session-bus=env-disabled-polkit-denied fs-sockets=allowlisted "
            "abstract-unix=not-attested devices=private "
            "device-fds=no-privileged shell=shipping"
        )
        self.assertIn(boundary, ready_check)
        self.assertIn(boundary, qemu_smoke)
        self.assertIn('"devices=private device-fds=no-privileged "', source)
        self.assertIn(
            '"KERNAID_RESCUE_TAURI_GUEST_FAILURE_V1 stage=devices"',
            ready_check,
        )
        self.assertIn("|devices|device-fds|proc-alias|", qemu_smoke)
        self.assertIn("|notify|window-startup|service|", qemu_smoke)
        self.assertIn("|process-executable|process-ancestry|", qemu_smoke)
        self.assertEqual(
            guest_ui.GSTREAMER_PLUGIN_SCANNER,
            "/usr/lib/x86_64-linux-gnu/gstreamer1.0/"
            "gstreamer-1.0/gst-plugin-scanner",
        )
        self.assertIn(
            guest_ui.GSTREAMER_PLUGIN_SCANNER,
            guest_ui.SHIPPING_NATIVE_EXECUTABLES,
        )
        self.assertIn(
            "KERNAID_RESCUE_TAURI_SANDBOX_FAILURE_V1 "
            "stage=(http|x11|http-x11|socket-offline-inspector|socket-vault|",
            qemu_smoke,
        )
        self.assertIn(
            "KERNAID_TAURI_NETWORK_PROBE_FAILURE_V1 "
            "stage=(wait-marker|verify-marker|verify-alias|baseline)",
            qemu_smoke,
        )

    def test_qemu_bios_and_uefi_share_the_render_and_input_gate(self) -> None:
        script = (TOOLS_DIR / "qemu-smoke.sh").read_text(encoding="utf-8")
        self.assertIn('-qmp "unix:$qmp_socket,server=on,wait=off"', script)
        self.assertIn("qemu-tauri-ui-smoke.py", script)
        self.assertIn("KERNAID_RESCUE_TAURI_GUEST_V1", script)
        self.assertIn("display=active-xorg", script)
        self.assertIn(
            "identity=isolated pidns=private shell-bus=mount-masked",
            script,
        )
        self.assertIn("KERNAID_QEMU_TAURI_UI_ATTESTATION_V1", script)
        self.assertEqual(script.count("qemu_args=(-machine"), 1)


class TauriShippingAbiTests(unittest.TestCase):
    def test_tauri_profile_requires_the_exact_webkit_stack(self) -> None:
        dependencies = sorted(binary_verifier.TAURI_WEBKIT_ALLOWED_NEEDED)
        dynamic = "\n".join(
            f" 0x0000000000000001 (NEEDED) Shared library: [{dependency}]"
            for dependency in dependencies
        )
        readelf = (
            "[Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]\n"
            + dynamic
        )
        parsed = binary_verifier.parse_readelf_output(readelf, "tauri-webkit")
        self.assertIn("libwebkit2gtk-4.1.so.0", parsed)

        missing_webkit_dependencies = [
            dependency
            for dependency in dependencies
            if dependency != "libwebkit2gtk-4.1.so.0"
        ]
        missing_webkit = (
            "[Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]\n"
            + "\n".join(
                " 0x0000000000000001 (NEEDED) Shared library: "
                f"[{dependency}]"
                for dependency in missing_webkit_dependencies
            )
        )
        with self.assertRaises(binary_verifier.VerificationError):
            binary_verifier.parse_readelf_output(missing_webkit, "tauri-webkit")

        unexpected = readelf + (
            "\n 0x0000000000000001 (NEEDED) Shared library: [libcurl.so.4]"
        )
        with self.assertRaises(binary_verifier.VerificationError):
            binary_verifier.parse_readelf_output(unexpected, "tauri-webkit")


    def test_native_prompt_wire_is_closed_and_duplicate_safe(self) -> None:
        request_id = "N-01234567-89ab-cdef-0123-456789abcdef"
        request = native_prompt._strict_request(
            json.dumps(
                {
                    "apiVersion": native_prompt.API_VERSION,
                    "requestId": request_id,
                    "operation": "prompt.open-or-focus",
                    "kind": "vault-unlock",
                },
                separators=(",", ":"),
            ).encode("ascii")
        )
        self.assertEqual(request["requestId"], request_id)
        response = json.loads(native_prompt._response(request_id, "opened"))
        self.assertEqual(
            response,
            {
                "apiVersion": native_prompt.API_VERSION,
                "requestId": request_id,
                "outcome": "opened",
            },
        )
        self.assertEqual(
            json.loads(native_prompt._status_response("idle")),
            {
                "apiVersion": native_prompt.API_VERSION,
                "kind": "vault-unlock",
                "availability": "available",
                "promptState": "idle",
            },
        )
        with self.assertRaises(native_prompt.BrokerFailure):
            native_prompt._status_response("unlocking")
        for invalid in (
            b'{"apiVersion":"kernaid.dev/rescue-native-prompt/v1alpha1",'
            b'"requestId":"N-01234567-89ab-cdef-0123-456789abcdef",'
            b'"operation":"prompt.open-or-focus","kind":"vault-unlock",'
            b'"path":"/dev/sda"}',
            b'{"apiVersion":"kernaid.dev/rescue-native-prompt/v1alpha1",'
            b'"requestId":"N-01234567-89ab-cdef-0123-456789abcdef",'
            b'"requestId":"N-01234567-89ab-cdef-0123-456789abcdef",'
            b'"operation":"prompt.open-or-focus","kind":"vault-unlock"}',
            b'{"apiVersion":"kernaid.dev/rescue-native-prompt/v1alpha1",'
            b'"requestId":"N-01234567-89ab-cdef-0123-456789abcdef",'
            b'"operation":"shell","kind":"vault-unlock"}',
        ):
            with self.subTest(invalid=invalid):
                with self.assertRaises(native_prompt.BrokerFailure):
                    native_prompt._strict_request(invalid)

    def test_native_prompt_gate_and_vt_grammar_are_exact(self) -> None:
        self.assertFalse(guest_ui._native_prompt_enabled(b"boot=live quiet\n"))
        self.assertTrue(
            guest_ui._native_prompt_enabled(
                b"boot=live kernaid.native-prompt=vt-v1 quiet\n"
            )
        )
        for invalid in (
            b"boot=live kernaid.native-prompt=vt-v2\n",
            b"boot=live kernaid.native-prompt=vt-v1 kernaid.native-prompt=vt-v1\n",
        ):
            with self.subTest(invalid=invalid):
                with self.assertRaises(guest_ui.SandboxFailure):
                    guest_ui._native_prompt_enabled(invalid)
                with self.assertRaises(native_prompt.BrokerFailure):
                    native_prompt._native_prompt_gate(invalid)
        native_prompt._native_prompt_gate(
            b"boot=live kernaid.native-prompt=vt-v1 quiet\n"
        )
        with self.assertRaises(native_prompt.BrokerFailure):
            native_prompt._native_prompt_gate(
                b"kernaid.native-prompt=vt-v1 quiet\n"
            )
        self.assertEqual(native_prompt._active_vt(b"tty7\n"), 7)
        for invalid in (b"tty0\n", b"tty64\n", b"tty7 extra\n"):
            with self.assertRaises(native_prompt.BrokerFailure):
                native_prompt._active_vt(invalid)

    def test_native_prompt_empty_authenticated_frame_is_status_only(self) -> None:
        controller = mock.Mock()
        controller.status.return_value = "idle"
        broker = native_prompt.Broker(controller)
        connection = mock.Mock()
        with (
            mock.patch.object(native_prompt, "_peer_identity", return_value=91),
            mock.patch.object(native_prompt, "_receive", return_value=b""),
            mock.patch.object(native_prompt.os, "close") as close,
        ):
            broker.handle(connection)
        controller.open_or_focus.assert_not_called()
        connection.sendall.assert_called_once_with(
            native_prompt._status_response("idle")
        )
        close.assert_called_once_with(91)

    def test_native_prompt_controller_opens_then_focuses_only_tty8(self) -> None:
        controller = native_prompt.PromptController()
        monitor = mock.Mock()
        with (
            mock.patch.object(native_prompt, "_prompt_backend_ready"),
            mock.patch.object(native_prompt, "_active_vt", return_value=7),
            mock.patch.object(native_prompt, "_write_return_vt") as write_state,
            mock.patch.object(native_prompt, "_tool", return_value=(0, b"")) as tool,
            mock.patch.object(
                native_prompt, "_unit_state", return_value=("active", "running", "success")
            ),
            mock.patch.object(native_prompt, "_switch_vt") as switch,
            mock.patch.object(native_prompt.threading, "Thread", return_value=monitor),
        ):
            self.assertEqual(controller.status(), "idle")
            self.assertEqual(controller.open_or_focus(), "opened")
            self.assertEqual(controller.status(), "active")
            self.assertEqual(controller.open_or_focus(), "focused")
        write_state.assert_called_once_with(7)
        tool.assert_called_once_with(
            (
                "/usr/bin/systemctl",
                "start",
                "--no-block",
                native_prompt.PROMPT_UNIT,
            )
        )
        self.assertEqual(switch.call_args_list, [mock.call(8), mock.call(8)])
        monitor.start.assert_called_once_with()

    def test_native_prompt_open_waits_for_notify_ready_before_switching_vt(self) -> None:
        controller = native_prompt.PromptController()
        monitor = mock.Mock()
        with (
            mock.patch.object(native_prompt, "_prompt_backend_ready"),
            mock.patch.object(native_prompt, "_active_vt", return_value=7),
            mock.patch.object(native_prompt, "_write_return_vt"),
            mock.patch.object(native_prompt, "_tool", return_value=(0, b"")),
            mock.patch.object(
                native_prompt,
                "_unit_state",
                side_effect=(
                    ("activating", "start", "success"),
                    ("active", "running", "success"),
                ),
            ) as unit_state,
            mock.patch.object(native_prompt, "_switch_vt") as switch,
            mock.patch.object(native_prompt.time, "sleep") as sleep,
            mock.patch.object(native_prompt.threading, "Thread", return_value=monitor),
        ):
            self.assertEqual(controller.open_or_focus(), "opened")
        self.assertEqual(unit_state.call_count, 2)
        sleep.assert_called_once_with(0.05)
        switch.assert_called_once_with(8)
        monitor.start.assert_called_once_with()

    def test_native_prompt_units_keep_secrets_on_the_fixed_uid1000_tty(self) -> None:
        units = REPO_DIR / "rescue/live-build/config/includes.chroot/etc/systemd/system"
        broker = (units / "kernaid-rescue-native-prompt.service").read_text()
        control = (units / "kernaid-rescue-native-prompt.socket").read_text()
        prompt = (units / "kernaid-rescue-native-vault-unlock.service").read_text()
        adapter = (
            REPO_DIR
            / "rescue/live-build/config/includes.chroot/usr/lib/kernaid"
            / "rescue-native-vault-unlock"
        ).read_text()
        for unit in (broker, control, prompt):
            self.assertIn("ConditionKernelCommandLine=kernaid.native-prompt=vt-v1", unit)
        self.assertIn("User=root", broker)
        self.assertIn("StandardOutput=null", broker)
        self.assertIn("CapabilityBoundingSet=CAP_SYS_TTY_CONFIG", broker)
        self.assertNotIn("CAP_SYS_PTRACE", broker)
        self.assertIn("SocketMode=0660", control)
        self.assertIn("SocketGroup=kernaid-rescue-ui", control)
        self.assertIn("User=kernaid", prompt)
        self.assertIn("SupplementaryGroups=kernaid-vault", prompt)
        self.assertIn("Type=notify", prompt)
        self.assertIn("NotifyAccess=main", prompt)
        self.assertIn("TTYPath=/dev/tty8", prompt)
        self.assertIn("StandardInput=tty-force", prompt)
        self.assertIn("RuntimeMaxSec=620s", prompt)
        self.assertIn("ProcSubset=all", prompt)
        self.assertNotIn("RestrictSUIDSGID=yes", prompt)
        self.assertIn("CapabilityBoundingSet=\n", prompt)
        self.assertIn("exec /usr/bin/kernaid-rescue-vaultctl unlock", adapter)
        self.assertIn("kernaid.native-prompt=vt-v1", adapter)
        self.assertNotIn("$1", adapter)
        self.assertNotIn("eval", adapter)
        broker_source = (
            REPO_DIR
            / "rescue/live-build/config/includes.chroot/usr/lib/kernaid"
            / "rescue_native_prompt_broker.py"
        ).read_text()
        self.assertIn("SO_PEERPIDFD = 77", broker_source)
        self.assertIn("getsockopt(socket.SOL_SOCKET, SO_PEERPIDFD)", broker_source)
        self.assertNotIn("pidfd_open", broker_source)

        wizard_source = (
            REPO_DIR / "apps/desk/src/rescue-diagnosis-wizard.tsx"
        ).read_text()
        main_source = (REPO_DIR / "apps/desk/src/main.tsx").read_text()
        self.assertIn('accessKey="u"', wizard_source)
        self.assertIn('aria-keyshortcuts="Alt+U"', wizard_source)
        self.assertIn("vaultUnlockEligible &&", wizard_source)
        self.assertIn('openAiStatus.vault === "locked"', main_source)


if __name__ == "__main__":
    unittest.main()
