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
    ("system.hostname", ("/usr/bin/hostname",)),
    (
        "linux.block.inventory",
        (
            "/usr/bin/lsblk",
            "--json",
            "--bytes",
            "--output",
            "NAME,KNAME,MAJ:MIN,TYPE,SIZE,RO,TRAN,FSTYPE,MOUNTPOINTS,MODEL,SERIAL,WWN,UUID,PARTUUID,PTUUID",
        ),
    ),
    ("linux.network.links", ("/usr/sbin/ip", "-json", "link")),
    ("linux.failed.units", ("/usr/bin/systemctl", "--failed", "--no-pager", "--plain")),
)
MAX_REQUEST_BYTES = 8 * 1024
MAX_BROKER_SESSIONS = 1_024
MAX_SERVER_THREADS = 8
ALLOWED_HOSTS = {"127.0.0.1:4173", "localhost:4173"}
ALLOWED_ORIGINS = {"http://127.0.0.1:4173", "http://localhost:4173"}


class BrokerError(Exception):
    """A safe error that can be returned to the local Desk UI."""


class ObserveBroker:
    def __init__(self, target_fingerprint: str) -> None:
        self.target_fingerprint = target_fingerprint
        self.last_sequence = 0

    def authorize(self, request: dict[str, object]) -> None:
        if set(request) != {"sessionId", "planId", "targetFingerprint", "sequence", "action"}:
            raise BrokerError("Richiesta al broker non valida.")
        if request["action"] != "system.observe.noop":
            raise BrokerError("Azione non consentita dal broker locale.")
        session_id = request["sessionId"]
        plan_id = request["planId"]
        fingerprint = request["targetFingerprint"]
        sequence = request["sequence"]
        if (
            not isinstance(session_id, str)
            or not session_id.strip()
            or len(session_id) > 128
            or not isinstance(plan_id, str)
            or not plan_id.strip()
            or len(plan_id) > 128
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
INVENTORY_LOCK = threading.Lock()


def observe(collector: str, command: tuple[str, ...]) -> dict[str, object]:
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        retained = bytearray()

        def drain_output() -> None:
            if process.stdout is None:
                return
            while chunk := process.stdout.read(8 * 1024):
                remaining = MAX_OUTPUT_BYTES - len(retained)
                if remaining > 0:
                    retained.extend(chunk[:remaining])

        reader = threading.Thread(target=drain_output, daemon=True)
        reader.start()
        timed_out = False
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            timed_out = True
            process.kill()
            process.wait(timeout=2)
        reader.join(timeout=2)
        if process.stdout is not None:
            process.stdout.close()
        output = bytes(retained).decode("utf-8", errors="replace")
        if timed_out:
            output = f"{output}\ncollector unavailable: command timed out".lstrip()
        return {
            "collector": collector,
            "trust": "observed-untrusted",
            "output": output,
            "success": not timed_out and process.returncode == 0,
        }
    except (OSError, subprocess.TimeoutExpired) as error:
        return {
            "collector": collector,
            "trust": "observed-untrusted",
            "output": f"collector unavailable: {error}",
            "success": False,
        }


def inventory() -> list[dict[str, object]]:
    with INVENTORY_LOCK:
        return [observe(name, command) for name, command in COMMANDS]


def is_identity_observation(collector: str) -> bool:
    return (
        "hostname" in collector
        or "block.inventory" in collector
        or collector.endswith(".disks")
        or collector.endswith(".system")
        or collector.endswith(".storage.identity")
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

    def same_site_request(self) -> bool:
        origin = self.headers.get("Origin")
        fetch_site = self.headers.get("Sec-Fetch-Site")
        return (origin is None or origin in ALLOWED_ORIGINS) and fetch_site in {
            None,
            "none",
            "same-origin",
        }

    def do_GET(self) -> None:
        if not self.local_authority():
            self.send_error(421)
            return
        if not self.same_site_request():
            self.send_error(403)
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


class BoundedThreadingHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = MAX_SERVER_THREADS

    def __init__(self, *args: object, **kwargs: object) -> None:
        self.slots = threading.BoundedSemaphore(MAX_SERVER_THREADS)
        super().__init__(*args, **kwargs)

    def process_request(self, request: object, client_address: object) -> None:
        if not self.slots.acquire(blocking=False):
            request.close()  # type: ignore[attr-defined]
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request: object, client_address: object) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()


if __name__ == "__main__":
    BoundedThreadingHTTPServer(("127.0.0.1", 4173), RescueHandler).serve_forever()
