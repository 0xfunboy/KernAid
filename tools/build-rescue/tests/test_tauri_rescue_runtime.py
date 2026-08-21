from __future__ import annotations

import importlib.util
import io
import json
import socket
import sys
import tempfile
import threading
import unittest
from contextlib import redirect_stderr
from pathlib import Path


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
    def test_guest_requires_the_default_display_xorg_vt_to_be_active(self) -> None:
        self.assertEqual(guest_ui._active_vt_from_payload(b"tty7\n"), 7)
        self.assertEqual(
            guest_ui._xorg_vt_from_cmdline(
                b"/usr/lib/xorg/Xorg\0:0\0-seat\0seat0\0vt7\0-novtswitch\0"
            ),
            7,
        )
        self.assertIsNone(
            guest_ui._xorg_vt_from_cmdline(
                b"/usr/lib/xorg/Xorg\0:1\0-seat\0seat0\0vt7\0"
            )
        )
        for payload in (b"tty0\n", b"tty64\n", b"tty7 private\n"):
            with self.subTest(payload=payload):
                with self.assertRaises(guest_ui.AttestationError):
                    guest_ui._active_vt_from_payload(payload)

    def test_guest_renderer_must_descend_from_the_shipping_shell(self) -> None:
        processes = {
            10: (1, (1000, 1000, 1000, 1000), guest_ui.SHELL_PATH),
            11: (10, (1000, 1000, 1000, 1000), "/usr/bin/bwrap"),
            12: (
                11,
                (1000, 1000, 1000, 1000),
                f"{guest_ui.WEBKIT_ROOT}/WebKitWebProcess",
            ),
            20: (
                1,
                (1000, 1000, 1000, 1000),
                f"{guest_ui.WEBKIT_ROOT}/WebKitWebProcess",
            ),
        }
        self.assertTrue(guest_ui._descends_from(12, 10, processes))
        self.assertFalse(guest_ui._descends_from(20, 10, processes))

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
            source.index("wait_for_rescue_ui()?"),
            source.index("tauri::Builder::default()"),
        )
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
        self.assertIn("User=kernaid", service)
        self.assertIn("Group=kernaid", service)
        self.assertIn("Restart=on-failure", service)
        self.assertIn("NoNewPrivileges=yes", service)
        self.assertIn("CapabilityBoundingSet=\n", service)
        self.assertNotIn("chromium", service.lower())
        self.assertIn("systemctl enable kernaid-rescue-desk-shell.service", safety_hook)
        self.assertIn("kernaid-rescue-desk-shell.service", ready_service)
        self.assertIn("libwebkit2gtk-4.1-0", packages)
        self.assertIn("xdotool", packages)
        self.assertNotIn("chromium", packages)

    def test_qemu_bios_and_uefi_share_the_render_and_input_gate(self) -> None:
        script = (TOOLS_DIR / "qemu-smoke.sh").read_text(encoding="utf-8")
        self.assertIn('-qmp "unix:$qmp_socket,server=on,wait=off"', script)
        self.assertIn("qemu-tauri-ui-smoke.py", script)
        self.assertIn("KERNAID_RESCUE_TAURI_GUEST_V1", script)
        self.assertIn("display=active-xorg", script)
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
