#!/usr/bin/python3
"""Loopback-only static UI and fixed, read-only inventory bridge for KernAid Rescue."""

from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import hashlib
import json
import subprocess
import threading

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
MAX_REQUEST_BYTES = 8 * 1024
MAX_BROKER_SESSIONS = 1_024
ALLOWED_HOSTS = {"127.0.0.1:4173", "localhost:4173"}
ALLOWED_ORIGINS = {"http://127.0.0.1:4173", "http://localhost:4173"}


class BrokerError(Exception):
    """A safe error that can be returned to the local Desk UI."""


class ObserveBroker:
    def __init__(self, target_fingerprint: str) -> None:
        self.target_fingerprint = target_fingerprint
        self.last_sequence = 0

    def authorize(self, request: dict[str, object]) -> None:
        if set(request) != {"sessionId", "targetFingerprint", "sequence", "action"}:
            raise BrokerError("Richiesta al broker non valida.")
        if request["action"] != "system.observe.noop":
            raise BrokerError("Azione non consentita dal broker locale.")
        session_id = request["sessionId"]
        fingerprint = request["targetFingerprint"]
        sequence = request["sequence"]
        if (
            not isinstance(session_id, str)
            or not session_id.strip()
            or len(session_id) > 128
            or not isinstance(fingerprint, str)
            or not valid_fingerprint(fingerprint)
            or not isinstance(sequence, int)
            or isinstance(sequence, bool)
        ):
            raise BrokerError("Richiesta al broker non valida.")
        if fingerprint != self.target_fingerprint:
            raise BrokerError("Il target è cambiato: piano annullato, ripetere la diagnosi.")
        if sequence <= self.last_sequence:
            raise BrokerError("Richiesta già eseguita o fuori sequenza.")
        self.last_sequence = sequence


BROKERS: dict[str, ObserveBroker] = {}
BROKER_LOCK = threading.Lock()


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


def inventory() -> list[dict[str, object]]:
    return [observe(name, command) for name, command in COMMANDS]


def is_identity_observation(collector: str) -> bool:
    return (
        "hostname" in collector
        or "block.inventory" in collector
        or collector.endswith(".disks")
        or collector.endswith(".system")
    )


def inventory_fingerprint(observations: list[dict[str, object]]) -> str:
    canonical = "\0".join(
        f"{item['collector']}\0{item['output']}"
        for item in observations
        if isinstance(item.get("collector"), str)
        and is_identity_observation(str(item["collector"]))
    )
    return f"sha256:{hashlib.sha256(canonical.encode()).hexdigest()}"


def valid_fingerprint(value: str) -> bool:
    if not value.startswith("sha256:"):
        return False
    digest = value.removeprefix("sha256:")
    return len(digest) == 64 and all(character in "0123456789abcdef" for character in digest)


def authorize_observe(request: dict[str, object]) -> None:
    session_id = request.get("sessionId")
    if not isinstance(session_id, str) or not session_id.strip():
        raise BrokerError("Richiesta al broker non valida.")
    current_fingerprint = inventory_fingerprint(inventory())
    if request.get("targetFingerprint") != current_fingerprint:
        raise BrokerError("Il target è cambiato: piano annullato, ripetere la diagnosi.")
    with BROKER_LOCK:
        if session_id not in BROKERS and len(BROKERS) >= MAX_BROKER_SESSIONS:
            raise BrokerError("Limite delle sessioni locali raggiunto; riavviare KernAid.")
        broker = BROKERS.setdefault(session_id, ObserveBroker(current_fingerprint))
        broker.authorize(request)


class RescueHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, directory=WEB_ROOT, **kwargs)

    def local_authority(self) -> bool:
        return self.headers.get("Host") in ALLOWED_HOSTS

    def do_GET(self) -> None:
        if not self.local_authority():
            self.send_error(421)
            return
        if self.path == "/api/inventory":
            body = json.dumps(inventory()).encode()
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
        if not self.local_authority():
            self.send_error(421)
            return
        if self.headers.get("Origin") not in ALLOWED_ORIGINS:
            self.send_error(403)
            return
        if self.path != "/api/authorize-observe":
            self.send_error(405)
            return
        if self.headers.get_content_type() != "application/json":
            self.send_error(415)
            return
        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_error(400)
            return
        if content_length <= 0 or content_length > MAX_REQUEST_BYTES:
            self.send_error(413)
            return
        try:
            request = json.loads(self.rfile.read(content_length))
            if not isinstance(request, dict):
                raise BrokerError("Richiesta al broker non valida.")
            authorize_observe(request)
            body = b'{"status":"observed"}'
            status = 200
        except (json.JSONDecodeError, UnicodeDecodeError):
            body = json.dumps({"error": "JSON non valido."}).encode()
            status = 400
        except BrokerError as error:
            body = json.dumps({"error": str(error)}).encode()
            status = 409
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *args: object) -> None:
        return


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", 4173), RescueHandler).serve_forever()
