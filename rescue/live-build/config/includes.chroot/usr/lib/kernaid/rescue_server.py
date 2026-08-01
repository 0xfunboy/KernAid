#!/usr/bin/python3
"""Loopback-only static UI and fixed, read-only inventory bridge for KernAid Rescue."""

from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
import signal
import subprocess
import threading

MAX_OUTPUT_BYTES = 64 * 1024
COLLECTOR_TIMEOUT_SECONDS = 15
COLLECTOR_KILL_GRACE_SECONDS = 2
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
            "NAME,TYPE,SIZE,RO,FSTYPE,MOUNTPOINTS,SERIAL,WWN,UUID,PARTUUID,PTUUID",
        ),
    ),
    ("linux.network.links", ("/usr/sbin/ip", "-json", "link")),
    ("linux.systemd.failed", ("/usr/bin/systemctl", "--failed", "--no-pager", "--plain")),
    ("linux.systemd.state", ("/usr/bin/systemctl", "show", "--property=SystemState", "--no-pager")),
    ("linux.df", ("/usr/bin/df", "--block-size=1", "--portability")),
    ("linux.network.routes", ("/usr/sbin/ip", "-json", "route")),
    ("linux.dpkg.audit", ("/usr/bin/dpkg", "--audit")),
)
MAX_REQUEST_BYTES = 8 * 1024
MAX_BROKER_SESSIONS = 1_024
MAX_SERVER_THREADS = 8
SOCKET_TIMEOUT_SECONDS = 5
REQUEST_DEADLINE_SECONDS = 30
ALLOWED_HOSTS = {"127.0.0.1:4173", "localhost:4173"}
ALLOWED_ORIGINS = {"http://127.0.0.1:4173", "http://localhost:4173"}


class BrokerError(Exception):
    """A safe error that can be returned to the local Desk UI."""


class InventoryBusy(Exception):
    """Another bounded inventory collection is already in progress."""


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
            env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        retained = bytearray()
        stdout_truncated = False
        stderr_truncated = False

        def drain_stdout() -> None:
            nonlocal stdout_truncated
            if process.stdout is None:
                return
            try:
                while chunk := process.stdout.read(8 * 1024):
                    remaining = MAX_OUTPUT_BYTES - len(retained)
                    if len(chunk) > remaining:
                        stdout_truncated = True
                    if remaining > 0:
                        retained.extend(chunk[:remaining])
            except (OSError, ValueError):
                stdout_truncated = True

        def drain_stderr() -> None:
            nonlocal stderr_truncated
            if process.stderr is None:
                return
            observed = 0
            try:
                while chunk := process.stderr.read(8 * 1024):
                    observed += len(chunk)
                    if observed > MAX_OUTPUT_BYTES:
                        stderr_truncated = True
            except (OSError, ValueError):
                stderr_truncated = True

        readers = (
            threading.Thread(target=drain_stdout, daemon=True),
            threading.Thread(target=drain_stderr, daemon=True),
        )
        for reader in readers:
            reader.start()

        def terminate_process_group() -> None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
                return
            except OSError:
                pass
            try:
                process.kill()
            except OSError:
                pass

        timed_out = False
        try:
            process.wait(timeout=COLLECTOR_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            timed_out = True
            terminate_process_group()
            try:
                process.wait(timeout=COLLECTOR_KILL_GRACE_SECONDS)
            except subprocess.TimeoutExpired:
                pass
        for reader in readers:
            reader.join(timeout=COLLECTOR_KILL_GRACE_SECONDS)
        streams_incomplete = any(reader.is_alive() for reader in readers)
        if streams_incomplete:
            terminate_process_group()
        for reader in readers:
            reader.join(timeout=COLLECTOR_KILL_GRACE_SECONDS)
        streams_incomplete = streams_incomplete or any(
            reader.is_alive() for reader in readers
        )
        for reader, stream in zip(readers, (process.stdout, process.stderr), strict=True):
            if stream is not None and not reader.is_alive():
                stream.close()
        try:
            output = bytes(retained).decode("utf-8", errors="strict")
            valid_utf8 = True
        except UnicodeDecodeError:
            output = ""
            valid_utf8 = False
        truncated = stdout_truncated or stderr_truncated or streams_incomplete
        return {
            "collector": collector,
            "trust": "observed-untrusted",
            "output": output,
            "success": (
                not timed_out
                and process.returncode == 0
                and not truncated
                and valid_utf8
            ),
            "truncated": truncated,
        }
    except (OSError, subprocess.TimeoutExpired):
        return {
            "collector": collector,
            "trust": "observed-untrusted",
            "output": "",
            "success": False,
            "truncated": False,
        }


def inventory() -> list[dict[str, object]]:
    if not INVENTORY_LOCK.acquire(blocking=False):
        raise InventoryBusy("Inventario locale già in corso; riprovare.")
    try:
        with ThreadPoolExecutor(max_workers=len(COMMANDS)) as executor:
            futures = [
                executor.submit(observe, collector, command)
                for collector, command in COMMANDS
            ]
            return [future.result() for future in futures]
    finally:
        INVENTORY_LOCK.release()


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
    observations = inventory()
    identity_observations = [
        item
        for item in observations
        if isinstance(item.get("collector"), str)
        and is_identity_observation(str(item["collector"]))
    ]
    if not identity_observations or any(
        item.get("success") is not True or item.get("truncated") is True
        for item in identity_observations
    ):
        raise BrokerError("Inventario di identità incompleto; ripetere la raccolta.")
    current_fingerprint = inventory_fingerprint(observations)
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

    def handle(self) -> None:
        def expire_request() -> None:
            try:
                self.connection.shutdown(2)
            except OSError:
                pass
            self.connection.close()

        deadline = threading.Timer(REQUEST_DEADLINE_SECONDS, expire_request)
        deadline.daemon = True
        deadline.start()
        try:
            try:
                super().handle()
            except (BrokenPipeError, ConnectionResetError):
                pass
        finally:
            deadline.cancel()

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
            try:
                body = json.dumps(inventory()).encode()
                status = 200
            except InventoryBusy as error:
                body = json.dumps({"error": str(error)}).encode()
                status = 429
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            if status == 429:
                self.send_header("Retry-After", "1")
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
            encoded = self.rfile.read(content_length)
            if len(encoded) != content_length:
                self.send_error(400)
                return
            request = json.loads(encoded)
            if not isinstance(request, dict):
                raise BrokerError("Richiesta al broker non valida.")
            authorize_observe(request)
            body = b'{"status":"observed"}'
            status = 200
        except TimeoutError:
            body = json.dumps({"error": "Timeout della richiesta locale."}).encode()
            status = 408
        except (json.JSONDecodeError, UnicodeDecodeError):
            body = json.dumps({"error": "JSON non valido."}).encode()
            status = 400
        except BrokerError as error:
            body = json.dumps({"error": str(error)}).encode()
            status = 409
        except InventoryBusy as error:
            body = json.dumps({"error": str(error)}).encode()
            status = 429
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        if status == 429:
            self.send_header("Retry-After", "1")
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

    def get_request(self) -> tuple[object, object]:
        request, client_address = super().get_request()
        request.settimeout(SOCKET_TIMEOUT_SECONDS)
        return request, client_address

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
