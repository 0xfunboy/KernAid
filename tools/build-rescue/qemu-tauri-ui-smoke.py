#!/usr/bin/python3
"""Prove real KernAid rendering and keyboard input through QEMU QMP."""

from __future__ import annotations

import argparse
import json
import os
import socket
import stat
import sys
import time
from pathlib import Path


MAX_QMP_LINE_BYTES = 64 * 1024
MAX_SCREENSHOT_BYTES = 64 * 1024 * 1024
MIN_WIDTH = 640
MIN_HEIGHT = 480
MAX_WIDTH = 8192
MAX_HEIGHT = 8192
INPUT_ATTEMPTS = 8
RENDER_ATTEMPTS = 20
QMP_TIMEOUT_SECONDS = 5
INPUT_SETTLE_SECONDS = 0.4
RENDER_SETTLE_SECONDS = 0.5
BRAND_DARK = (13, 17, 16)
BRAND_LIME = (199, 255, 61)
BRAND_CYAN = (80, 216, 232)


class SmokeError(Exception):
    """A privacy-safe QMP or framebuffer rejection."""


class QmpClient:
    def __init__(self, socket_path: Path) -> None:
        self._socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._socket.settimeout(QMP_TIMEOUT_SECONDS)
        try:
            self._socket.connect(str(socket_path))
            self._stream = self._socket.makefile("rwb", buffering=0)
            greeting = self._read_message()
            if not isinstance(greeting.get("QMP"), dict):
                raise SmokeError("QMP greeting was invalid")
            self._sequence = 0
            self.execute("qmp_capabilities")
        except Exception:
            self._socket.close()
            raise

    def close(self) -> None:
        try:
            self._stream.close()
        finally:
            self._socket.close()

    def _read_message(self) -> dict[str, object]:
        line = self._stream.readline(MAX_QMP_LINE_BYTES + 1)
        if not line or len(line) > MAX_QMP_LINE_BYTES or not line.endswith(b"\n"):
            raise SmokeError("QMP response exceeded its bound")
        try:
            message = json.loads(line)
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise SmokeError("QMP response was not JSON") from error
        if not isinstance(message, dict):
            raise SmokeError("QMP response was not an object")
        return message

    def execute(
        self, command: str, arguments: dict[str, object] | None = None
    ) -> object:
        self._sequence += 1
        request: dict[str, object] = {
            "execute": command,
            "id": self._sequence,
        }
        if arguments is not None:
            request["arguments"] = arguments
        encoded = json.dumps(
            request, ensure_ascii=True, separators=(",", ":")
        ).encode("ascii") + b"\n"
        if len(encoded) > MAX_QMP_LINE_BYTES:
            raise SmokeError("QMP request exceeded its bound")
        self._stream.write(encoded)
        while True:
            response = self._read_message()
            if response.get("id") != self._sequence:
                if "event" in response and "id" not in response:
                    continue
                raise SmokeError("QMP response identity was invalid")
            if "error" in response or "return" not in response:
                raise SmokeError("QMP command failed")
            return response["return"]


def _validate_private_work_directory(path: Path) -> None:
    if not path.is_absolute():
        raise SmokeError("work directory was not absolute")
    metadata = path.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_gid != os.getgid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise SmokeError("work directory identity was unsafe")


def _validate_qmp_socket(path: Path, work_directory: Path) -> None:
    if path.parent != work_directory or path.name != "qmp.sock":
        raise SmokeError("QMP socket location was not fixed")
    metadata = path.lstat()
    if (
        not stat.S_ISSOCK(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_gid != os.getgid()
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise SmokeError("QMP socket identity was unsafe")


def _read_exact_screenshot(path: Path, work_directory: Path) -> bytes:
    if path.parent != work_directory or path.name not in {"before.ppm", "after.ppm"}:
        raise SmokeError("screenshot location was not fixed")
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_gid != os.getgid()
            or metadata.st_nlink != 1
            or not 0 < metadata.st_size <= MAX_SCREENSHOT_BYTES
        ):
            raise SmokeError("screenshot identity was unsafe")
        chunks = bytearray()
        while len(chunks) <= metadata.st_size:
            block = os.read(
                descriptor,
                min(1024 * 1024, metadata.st_size + 1 - len(chunks)),
            )
            if not block:
                break
            chunks.extend(block)
        if len(chunks) != metadata.st_size:
            raise SmokeError("screenshot changed while reading")
        return bytes(chunks)
    finally:
        os.close(descriptor)


def _remove_screenshot(path: Path, work_directory: Path) -> None:
    if not path.exists() and not path.is_symlink():
        return
    _read_exact_screenshot(path, work_directory)
    path.unlink()


def _ppm_token(payload: bytes, position: int) -> tuple[bytes, int]:
    while position < len(payload):
        if payload[position] == 35:
            newline = payload.find(b"\n", position + 1)
            if newline < 0:
                raise SmokeError("PPM comment was unterminated")
            position = newline + 1
        elif payload[position] in b" \t\r\n":
            position += 1
        else:
            break
    start = position
    while position < len(payload) and payload[position] not in b" \t\r\n#":
        position += 1
    if start == position:
        raise SmokeError("PPM header token was missing")
    return payload[start:position], position


def parse_ppm(payload: bytes) -> tuple[int, int, bytes]:
    magic, position = _ppm_token(payload, 0)
    width_token, position = _ppm_token(payload, position)
    height_token, position = _ppm_token(payload, position)
    maximum_token, position = _ppm_token(payload, position)
    if magic != b"P6" or maximum_token != b"255":
        raise SmokeError("framebuffer was not an eight-bit binary PPM")
    try:
        width, height = int(width_token), int(height_token)
    except ValueError as error:
        raise SmokeError("PPM dimensions were invalid") from error
    if not (MIN_WIDTH <= width <= MAX_WIDTH and MIN_HEIGHT <= height <= MAX_HEIGHT):
        raise SmokeError("framebuffer dimensions were outside policy")
    if position >= len(payload) or payload[position] not in b" \t\r\n":
        raise SmokeError("PPM header terminator was missing")
    if payload[position : position + 2] == b"\r\n":
        position += 2
    else:
        position += 1
    pixels = payload[position:]
    if len(pixels) != width * height * 3:
        raise SmokeError("framebuffer payload length was invalid")
    return width, height, pixels


def _near(pixel: tuple[int, int, int], expected: tuple[int, int, int]) -> bool:
    return all(abs(actual - wanted) <= 10 for actual, wanted in zip(pixel, expected))


def _render_thresholds(pixels: bytes) -> tuple[bool, bool, bool, bool]:
    if not pixels or len(pixels) % 3:
        raise SmokeError("framebuffer RGB payload was invalid")
    total = len(pixels) // 3
    dark = 0
    lime = 0
    cyan = 0
    quantized: set[tuple[int, int, int]] = set()
    for offset in range(0, len(pixels), 3):
        pixel = (pixels[offset], pixels[offset + 1], pixels[offset + 2])
        if _near(pixel, BRAND_DARK):
            dark += 1
        if _near(pixel, BRAND_LIME):
            lime += 1
        if _near(pixel, BRAND_CYAN):
            cyan += 1
        if offset % 291 == 0 and len(quantized) < 256:
            quantized.add(tuple(channel // 16 for channel in pixel))
    return (
        dark >= total // 20,
        lime >= 16,
        cyan >= 16,
        len(quantized) >= 8,
    )


def frame_signature(width: int, height: int, pixels: bytes) -> str:
    if len(pixels) != width * height * 3:
        raise SmokeError("framebuffer dimensions and RGB payload disagreed")
    dimension = "standard" if width <= 1920 and height <= 1200 else "large"
    dark, lime, cyan, quantized = _render_thresholds(pixels)
    truth = {True: "true", False: "false"}
    return (
        f"dimension={dimension} dark={truth[dark]} lime={truth[lime]} "
        f"cyan={truth[cyan]} quantized8={truth[quantized]}"
    )


def is_kernaid_render(pixels: bytes) -> bool:
    return all(_render_thresholds(pixels))


def attest_kernaid_render(pixels: bytes) -> None:
    if not is_kernaid_render(pixels):
        raise SmokeError("the KernAid visual signature was not rendered")


def changed_pixels(left: bytes, right: bytes) -> int:
    if len(left) != len(right) or len(left) % 3:
        raise SmokeError("framebuffer dimensions changed during input")
    return sum(
        left[offset : offset + 3] != right[offset : offset + 3]
        for offset in range(0, len(left), 3)
    )


def _screendump(client: QmpClient, path: Path, work_directory: Path) -> bytes:
    if path.exists() or path.is_symlink():
        raise SmokeError("screenshot output already existed")
    client.execute("screendump", {"filename": str(path)})
    return _read_exact_screenshot(path, work_directory)


def _capture_frame(
    client: QmpClient, path: Path, work_directory: Path
) -> tuple[int, int, bytes]:
    payload = _screendump(client, path, work_directory)
    try:
        width, height, pixels = parse_ppm(payload)
        print(
            "KERNAID_QEMU_TAURI_FRAME_V1 "
            f"{frame_signature(width, height, pixels)}",
            file=sys.stderr,
        )
        return width, height, pixels
    finally:
        _remove_screenshot(path, work_directory)


def _find_rendered_frame(
    client: QmpClient, path: Path, work_directory: Path
) -> tuple[int, int, bytes]:
    width, height, pixels = _capture_frame(client, path, work_directory)
    if is_kernaid_render(pixels):
        return width, height, pixels
    # A mapped WebKit window can precede its first complete React paint.  Give
    # the already-active display a bounded opportunity to render.  Deliberately
    # do not switch virtual terminals: the gate must prove the UI a user sees
    # by default, not repair a hidden graphical session from the test harness.
    for _ in range(RENDER_ATTEMPTS - 1):
        time.sleep(RENDER_SETTLE_SECONDS)
        width, height, pixels = _capture_frame(client, path, work_directory)
        if is_kernaid_render(pixels):
            return width, height, pixels
    raise SmokeError("the default QEMU display did not render the KernAid bundle")


def _send_tab(client: QmpClient) -> None:
    client.execute(
        "input-send-event",
        {
            "events": [
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
            ]
        },
    )


def run(socket_path: Path, work_directory: Path, firmware: str) -> str:
    if firmware not in {"bios", "uefi"}:
        raise SmokeError("firmware value was invalid")
    _validate_private_work_directory(work_directory)
    _validate_qmp_socket(socket_path, work_directory)
    before_path = work_directory / "before.ppm"
    after_path = work_directory / "after.ppm"
    client = QmpClient(socket_path)
    try:
        status = client.execute("query-status")
        if not isinstance(status, dict) or status.get("running") is not True:
            raise SmokeError("QEMU was not running")
        width, height, previous = _find_rendered_frame(
            client, before_path, work_directory
        )
        maximum_change = max(500, width * height // 20)
        minimum_change = 24
        accepted_change = 0
        for _ in range(INPUT_ATTEMPTS):
            _send_tab(client)
            time.sleep(INPUT_SETTLE_SECONDS)
            next_width, next_height, current = _capture_frame(
                client, after_path, work_directory
            )
            if (next_width, next_height) != (width, height):
                raise SmokeError("framebuffer dimensions changed during input")
            attest_kernaid_render(current)
            difference = changed_pixels(previous, current)
            if minimum_change <= difference <= maximum_change:
                accepted_change = difference
                break
            previous = current
        if accepted_change == 0:
            raise SmokeError("keyboard input did not change the rendered bundle")
        return (
            "KERNAID_QEMU_TAURI_UI_ATTESTATION_V1 "
            f"firmware={firmware} shell=shipping renderer=webkit2gtk-4.1 "
            f"display=default rendered=true input=true width={width} height={height} "
            f"changed_pixels={accepted_change}"
        )
    finally:
        try:
            _remove_screenshot(before_path, work_directory)
            _remove_screenshot(after_path, work_directory)
        finally:
            client.close()


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", required=True, type=Path)
    parser.add_argument("--work-dir", required=True, type=Path)
    parser.add_argument("--firmware", required=True, choices=("bios", "uefi"))
    return parser.parse_args()


def main() -> int:
    options = arguments()
    try:
        marker = run(options.socket, options.work_dir, options.firmware)
    except (OSError, SmokeError, socket.timeout):
        print("KernAid QEMU Tauri UI smoke rejected", file=sys.stderr)
        return 1
    print(marker)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
