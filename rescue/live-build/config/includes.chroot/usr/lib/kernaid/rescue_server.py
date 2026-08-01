#!/usr/bin/python3
"""Loopback-only static UI and fixed, read-only inventory bridge for KernAid Rescue."""

from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
import subprocess

MAX_OUTPUT_BYTES = 64 * 1024
WEB_ROOT = "/opt/kernaid/desk"
COMMANDS = (
    ("system.hostname", ("hostname",)),
    (
        "linux.block.inventory",
        (
            "lsblk",
            "--json",
            "--bytes",
            "--output",
            "NAME,TYPE,SIZE,RO,TRAN,FSTYPE,MOUNTPOINTS,MODEL",
        ),
    ),
    ("linux.network.links", ("ip", "-json", "link")),
    ("linux.failed.units", ("systemctl", "--failed", "--no-pager", "--plain")),
)


def observe(collector: str, command: tuple[str, ...]) -> dict[str, object]:
    try:
        result = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
            timeout=15,
        )
        output = result.stdout[:MAX_OUTPUT_BYTES].decode("utf-8", errors="replace")
        return {
            "collector": collector,
            "trust": "observed-untrusted",
            "output": output,
            "success": result.returncode == 0,
        }
    except (OSError, subprocess.TimeoutExpired) as error:
        return {
            "collector": collector,
            "trust": "observed-untrusted",
            "output": f"collector unavailable: {error}",
            "success": False,
        }


class RescueHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, directory=WEB_ROOT, **kwargs)

    def do_GET(self) -> None:
        if self.path == "/api/inventory":
            body = json.dumps([observe(name, command) for name, command in COMMANDS]).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        super().do_GET()

    def do_POST(self) -> None:
        self.send_error(405)

    def log_message(self, _format: str, *args: object) -> None:
        return


ThreadingHTTPServer(("127.0.0.1", 4173), RescueHandler).serve_forever()
