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
from contextlib import redirect_stderr
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
    def test_shell_status_is_root_owned_systemd_state_not_a_uid_marker(self) -> None:
        normal = {
            "ActiveState": "active",
            "SubState": "running",
            "MainPID": "431",
            "StatusText": guest_ui.SANDBOX_STATUS_NORMAL,
            "User": guest_ui.UI_ACCOUNT,
            "Group": guest_ui.UI_ACCOUNT,
            "Type": "notify",
            "NotifyAccess": "main",
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
        with mock.patch.object(guest_ui, "_systemctl_show", return_value=normal):
            self.assertEqual(guest_ui._shell_service_ready(True), 0)

        failure = normal | {
            "StatusText": (
                "KERNAID_RESCUE_TAURI_SANDBOX_FAILURE_V1 stage=system-bus"
            )
        }
        with mock.patch.object(guest_ui, "_systemctl_show", return_value=failure):
            with self.assertRaises(guest_ui.SandboxFailure) as caught:
                guest_ui._shell_service_ready(False)
        self.assertEqual(caught.exception.stage, "system-bus")

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
        self.assertFalse(session_ui._valid_xauthority_payload(payload[:-1]))
        self.assertFalse(
            session_ui._valid_xauthority_payload(
                payload.replace(b"MIT-MAGIC-COOKIE-1", b"MIT-MAGIC-COOKIE-2")
            )
        )

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

    def test_rescue_config_has_no_remote_or_local_tauri_permissions(self) -> None:
        config = json.loads(
            (
                REPO_DIR / "apps/desk/src-tauri-rescue/tauri.conf.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(config["app"]["windows"], [])
        capabilities = config["app"]["security"]["capabilities"]
        self.assertEqual(len(capabilities), 1)
        self.assertIs(capabilities[0]["local"], False)
        self.assertEqual(capabilities[0]["permissions"], [])
        self.assertNotIn("remote", capabilities[0])

        source = (
            REPO_DIR
            / "apps/desk/src-tauri-rescue/src/main.rs"
        ).read_text(encoding="utf-8")
        self.assertNotIn("invoke_handler(", source)
        self.assertNotIn("generate_handler!", source)
        self.assertIn("tauri::generate_context!()", source)
        self.assertLess(
            source.index("let status = attest_rescue_sandbox()"),
            source.index("tauri::Builder::default()"),
        )
        self.assertLess(
            source.index(".build()?;"), source.index("notify_systemd(status, true)")
        )
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
        self.assertIn("Type=notify", service)
        self.assertIn("NotifyAccess=main", service)
        self.assertIn("User=kernaid-rescue-ui", service)
        self.assertIn("Group=kernaid-rescue-ui", service)
        self.assertIn("Restart=on-failure", service)
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
                "/run/systemd/notify",
                "-/run/kernaid-tauri-network-probe/baseline-v1",
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
        self.assertIn("WEBKIT_DISABLE_DMABUF_RENDERER=1", service)
        self.assertNotIn("ExecStartPre=", service)
        self.assertNotIn("chromium", service.lower())
        self.assertIn("systemctl enable kernaid-rescue-desk-shell.service", safety_hook)
        self.assertIn("kernaid-rescue-desk-shell.service", ready_service)
        self.assertIn("libwebkit2gtk-4.1-0", packages)
        self.assertIn("xdotool", packages)
        self.assertIn("xfwm4", packages)
        self.assertIn("xserver-xorg", packages)
        self.assertNotIn("xorg", packages)
        self.assertNotIn("xfce4", packages)
        self.assertNotIn("xfce4-terminal", packages)
        self.assertNotIn("dbus-user-session", packages)
        self.assertNotIn("chromium", packages)

        baseline_service = (
            REPO_DIR
            / "rescue/live-build/config/includes.chroot/etc/systemd/system"
            / "kernaid-tauri-network-probe-baseline.service"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "RestrictAddressFamilies=AF_UNIX AF_INET AF_NETLINK",
            baseline_service,
        )

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
        attestor_unit = (
            root / "etc/systemd/system/kernaid-rescue-ui-session-ready.service"
        ).read_text(encoding="utf-8")
        safety_hook = (
            REPO_DIR
            / "rescue/live-build/config/hooks/live/0100-kernaid-safety.hook.chroot"
        ).read_text(encoding="utf-8")
        self.assertIn(
            'u kernaid-rescue-ui - "KernAid Rescue isolated graphical shell" /nonexistent /usr/sbin/nologin',
            sysusers,
        )
        self.assertIn(
            "d /run/kernaid-rescue-ui-session 0700 kernaid-rescue-ui kernaid-rescue-ui -",
            tmpfiles,
        )
        self.assertIn("autologin-user=kernaid-rescue-ui", lightdm)
        self.assertIn("autologin-session=kernaid-rescue-ui", lightdm)
        self.assertIn(
            "xserver-command=X -extension DRI2 -extension DRI3 -extension XTEST",
            lightdm,
        )
        self.assertIn("allow-user-switching=false", lightdm)
        self.assertNotIn("common-session", pam)
        self.assertNotIn("pam_systemd", pam)
        self.assertIn("exec /usr/bin/xfwm4", session)
        self.assertNotIn("xfce4-session", session)
        self.assertIn("no-session-bus", session)
        self.assertIn("no-system-bus", session)
        self.assertIn(
            "CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_SYS_PTRACE",
            attestor_unit,
        )
        self.assertIn("AmbientCapabilities=\n", attestor_unit)
        self.assertIn("PrivateNetwork=yes", attestor_unit)
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
            "StatusText",
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


if __name__ == "__main__":
    unittest.main()
