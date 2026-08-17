#!/usr/bin/python3
"""Loopback-only static UI and fixed, read-only inventory bridge for KernAid Rescue."""

from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from concurrent.futures import ThreadPoolExecutor
import hashlib
import hmac
import json
import os
import signal
import socket
import stat
import subprocess
import threading
import time

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
TARGET_SCAN_COMMAND = (
    "/usr/bin/lsblk",
    "--json",
    "--bytes",
    "--tree",
    "--output",
    (
        "NAME,MAJ:MIN,TYPE,SIZE,RO,RM,TRAN,FSTYPE,FSVER,MOUNTPOINTS,UUID,PARTUUID,"
        "PTUUID,PTTYPE,PARTTYPE,SERIAL,WWN"
    ),
)
MAX_REQUEST_BYTES = 8 * 1024
MAX_BROKER_SESSIONS = 1_024
MAX_SERVER_THREADS = 8
SOCKET_TIMEOUT_SECONDS = 5
REQUEST_DEADLINE_SECONDS = 30
AUTHORIZE_DEADLINE_SECONDS = 18
MAX_TARGET_DEVICES = 128
MAX_TARGET_DEPTH = 8
MAX_TARGET_FIELD_BYTES = 4 * 1024
MAX_TARGET_RESPONSE_BYTES = 64 * 1024
TARGET_SCAN_API_VERSION = "kernaid.dev/rescue-targets/v1alpha1"
RESCUE_TARGET_FINGERPRINT_DOMAIN = "kernaid-rescue-observe-target-v1"
ALLOWED_HOSTS = {"127.0.0.1:4173", "localhost:4173"}
ALLOWED_ORIGINS = {"http://127.0.0.1:4173", "http://localhost:4173"}
TARGET_ID_KEY_FILE = "/run/kernaid-offline-inspector/target-id.key"


def _load_target_id_key() -> bytes:
    """Load the boot-scoped helper key, or use a process-local UI key."""
    configured = os.environ.get("KERNAID_TARGET_ID_KEY_FILE")
    if configured is None:
        return os.urandom(32)
    if configured != TARGET_ID_KEY_FILE:
        raise RuntimeError("the target identifier key path is not allowed")
    descriptor = os.open(
        configured, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    )
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != 0
            or before.st_gid != 0
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_nlink != 1
            or before.st_size != 32
        ):
            raise RuntimeError("the target identifier key is not a secure file")
        key = os.read(descriptor, 33)
        after = os.fstat(descriptor)
        if (
            len(key) != 32
            or (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
            )
            != (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
            )
        ):
            raise RuntimeError("the target identifier key changed while loading")
        return key
    finally:
        os.close(descriptor)


TARGET_ID_KEY = _load_target_id_key()
TARGET_ID_SCOPE = (
    "ephemeral-rescue-boot"
    if os.environ.get("KERNAID_TARGET_ID_KEY_FILE") == TARGET_ID_KEY_FILE
    else "ephemeral-rescue-process"
)
OFFLINE_HELPER_SOCKET = "/run/kernaid-offline-inspector.sock"
OFFLINE_HELPER_ENABLED = os.environ.get("KERNAID_PRIVILEGED_INSPECTOR") == "1"
OFFLINE_HELPER_TIMEOUT_SECONDS = 20
MAX_OFFLINE_HELPER_RESPONSE_BYTES = 64 * 1024
OFFLINE_INSPECTION_CLAIM_FIELDS = {
    "installedOsConfirmed",
    "filesystemContentInspected",
    "mountOperationAttempted",
    "mountOperationPerformed",
    "mountCleanupVerified",
    "autoUnlockAttempted",
    "mutationPerformed",
    "diagnosisProduced",
    "repairAttempted",
}

TARGET_DEVICE_FIELDS = {
    "name",
    "maj:min",
    "type",
    "size",
    "ro",
    "rm",
    "tran",
    "fstype",
    "fsver",
    "mountpoints",
    "uuid",
    "partuuid",
    "ptuuid",
    "pttype",
    "parttype",
    "serial",
    "wwn",
}
LINUX_FILESYSTEMS = {"btrfs", "ext2", "ext3", "ext4", "f2fs", "xfs"}
WINDOWS_FILESYSTEMS = {"bitlocker", "ntfs"}
MACOS_FILESYSTEMS = {"apfs", "hfs", "hfsplus"}
ENCRYPTED_FILESYSTEMS = {"bitlocker", "crypto_luks"}
LIVE_IMAGE_FILESYSTEMS = {"iso9660", "squashfs", "udf"}
LINUX_ROOT_PARTITION_TYPES = {
    "4f68bce3-e8cd-4db1-96e7-fbcaf984b709",  # x86-64 root
    "44479540-f297-41b2-9af7-d131d5f0458a",  # x86 root
}
APPLE_APFS_PARTITION_TYPE = "7c3457ef-0000-11aa-aa11-00306543ecac"
OBSERVE_AUTHORIZATION_FIELDS = {
    "sessionId",
    "planId",
    "targetFingerprint",
    "sequence",
    "action",
    "rescueTarget",
}
RESCUE_TARGET_REFERENCE_FIELDS = {"scanFingerprint", "targetId"}
TARGET_CANDIDATE_FIELDS = {
    "targetId",
    "sourceRef",
    "diskId",
    "osFamilyHint",
    "confidence",
    "status",
    "detectionBasis",
    "requiresUnlock",
    "inspectionMode",
    "selectionEligible",
}
TARGET_SELECTION_FIELDS = {
    "apiVersion",
    "status",
    "scanFingerprint",
    "target",
    "claims",
}
TARGET_SELECTION_CLAIM_FIELDS = {
    "installedOsConfirmed",
    "filesystemContentInspected",
    "mountOperationPerformed",
    "mutationPerformed",
}


class BrokerError(Exception):
    """A safe error that can be returned to the local Desk UI."""


class InventoryBusy(Exception):
    """Another bounded inventory collection is already in progress."""


class TargetScanBusy(Exception):
    """Another bounded installed-target scan is already in progress."""


class TargetScanError(Exception):
    """The installed-target metadata could not be normalized safely."""


class TargetSelectionError(Exception):
    """The local target selection request is invalid or stale."""

    def __init__(self, message: str, status: int = 409) -> None:
        super().__init__(message)
        self.status = status


class PrivilegedHelperError(Exception):
    """A typed failure returned by the fixed root inspection service."""

    def __init__(self, error: dict[str, object], status: int) -> None:
        super().__init__(str(error["message"]))
        self.error = error
        self.status = status


def _remaining_seconds(deadline: float | None) -> float | None:
    """Return the remaining monotonic budget, or fail once it is exhausted."""
    if deadline is None:
        return None
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("Deadline dell'autorizzazione Rescue scaduta.")
    return remaining


def _bounded_timeout(per_command: float, deadline: float | None) -> float:
    remaining = _remaining_seconds(deadline)
    return per_command if remaining is None else min(per_command, remaining)


def _check_deadline(deadline: float | None) -> None:
    _remaining_seconds(deadline)


def _validate_helper_error(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != {
        "code",
        "message",
        "retryable",
        "claims",
    }:
        raise BrokerError("Risposta dell'ispettore privilegiato non valida.")
    code = value.get("code")
    message = value.get("message")
    retryable = value.get("retryable")
    claims = value.get("claims")
    if (
        not isinstance(code, str)
        or not code
        or len(code) > 64
        or not code.isascii()
        or any(character not in "abcdefghijklmnopqrstuvwxyz0123456789-" for character in code)
        or not isinstance(message, str)
        or not message
        or len(message.encode("utf-8")) > 512
        or any(ord(character) < 32 or ord(character) == 127 for character in message)
        or not isinstance(retryable, bool)
        or not isinstance(claims, dict)
        or set(claims) != OFFLINE_INSPECTION_CLAIM_FIELDS
        or any(not isinstance(claims[field], bool) for field in claims)
    ):
        raise BrokerError("Risposta dell'ispettore privilegiato non valida.")
    return value


def _privileged_helper_call(
    operation: str, request: dict[str, object] | None = None
) -> object:
    if operation not in {"inspect", "scan", "select"}:
        raise BrokerError("Operazione dell'ispettore privilegiato non valida.")
    frame: dict[str, object] = {"operation": operation}
    if request is not None:
        frame["request"] = request
    encoded = json.dumps(
        frame, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("utf-8") + b"\n"
    if len(encoded) > MAX_REQUEST_BYTES:
        raise BrokerError("Richiesta all'ispettore privilegiato oltre il limite.")
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(OFFLINE_HELPER_TIMEOUT_SECONDS)
            connection.connect(OFFLINE_HELPER_SOCKET)
            connection.sendall(encoded)
            connection.shutdown(socket.SHUT_WR)
            payload = bytearray()
            while len(payload) <= MAX_OFFLINE_HELPER_RESPONSE_BYTES:
                chunk = connection.recv(
                    min(
                        8 * 1024,
                        MAX_OFFLINE_HELPER_RESPONSE_BYTES + 1 - len(payload),
                    )
                )
                if not chunk:
                    break
                payload.extend(chunk)
    except (OSError, TimeoutError) as error:
        raise PrivilegedHelperError(
            {
                "code": "privileged-helper-unavailable",
                "message": "L'ispettore privilegiato locale non è disponibile.",
                "retryable": True,
                "claims": {field: False for field in OFFLINE_INSPECTION_CLAIM_FIELDS},
            },
            503,
        ) from error
    if (
        len(payload) > MAX_OFFLINE_HELPER_RESPONSE_BYTES
        or payload.count(b"\n") != 1
        or not payload.endswith(b"\n")
    ):
        raise BrokerError("Frame dell'ispettore privilegiato non valido.")
    try:
        response = json.loads(payload[:-1].decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BrokerError("JSON dell'ispettore privilegiato non valido.") from error
    if not isinstance(response, dict) or not isinstance(response.get("ok"), bool):
        raise BrokerError("Risposta dell'ispettore privilegiato non valida.")
    if response["ok"] is True:
        if set(response) != {"ok", "result"}:
            raise BrokerError("Risposta dell'ispettore privilegiato non valida.")
        return response["result"]
    if set(response) != {"ok", "status", "error"}:
        raise BrokerError("Risposta dell'ispettore privilegiato non valida.")
    status = response.get("status")
    if (
        not isinstance(status, int)
        or isinstance(status, bool)
        or status not in {400, 408, 409, 422, 429, 503}
    ):
        raise BrokerError("Risposta dell'ispettore privilegiato non valida.")
    raise PrivilegedHelperError(_validate_helper_error(response["error"]), status)


class ObserveBroker:
    def __init__(
        self, target_fingerprint: str, rescue_target: dict[str, str]
    ) -> None:
        self.target_fingerprint = target_fingerprint
        self.rescue_target = dict(rescue_target)
        self.last_sequence = 0

    def authorize(
        self, request: dict[str, object], deadline: float | None = None
    ) -> None:
        _session_id, rescue_target = validate_observe_request(request)
        fingerprint = request["targetFingerprint"]
        sequence = request["sequence"]
        if rescue_target != self.rescue_target:
            raise BrokerError("Il target Rescue è cambiato: ripetere la selezione.")
        if fingerprint != self.target_fingerprint:
            raise BrokerError("Il target è cambiato: piano annullato, ripetere la diagnosi.")
        if not isinstance(sequence, int) or isinstance(sequence, bool):
            raise BrokerError("Richiesta al broker non valida.")
        if sequence <= self.last_sequence:
            raise BrokerError("Richiesta già eseguita o fuori sequenza.")
        # This is the authorization commit point. The caller holds BROKER_LOCK;
        # never advance a session whose end-to-end monotonic budget expired.
        _check_deadline(deadline)
        self.last_sequence = sequence


BROKERS: dict[str, ObserveBroker] = {}
BROKER_LOCK = threading.Lock()
INVENTORY_LOCK = threading.Lock()
TARGET_SCAN_LOCK = threading.Lock()


def observe(
    collector: str,
    command: tuple[str, ...],
    deadline: float | None = None,
) -> dict[str, object]:
    try:
        _check_deadline(deadline)
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
        budget_timeout = False
        deadline_limited = False
        try:
            wait_timeout = _bounded_timeout(COLLECTOR_TIMEOUT_SECONDS, deadline)
            deadline_limited = (
                deadline is not None and wait_timeout < COLLECTOR_TIMEOUT_SECONDS
            )
            process.wait(timeout=wait_timeout)
        except TimeoutError:
            timed_out = True
            budget_timeout = True
            terminate_process_group()
            cleanup_limit = time.monotonic() + COLLECTOR_KILL_GRACE_SECONDS
            if deadline is not None:
                cleanup_limit = min(cleanup_limit, deadline)
            try:
                process.wait(timeout=max(0.0, cleanup_limit - time.monotonic()))
            except subprocess.TimeoutExpired:
                pass
        except subprocess.TimeoutExpired:
            timed_out = True
            budget_timeout = deadline_limited
            terminate_process_group()
            cleanup_limit = time.monotonic() + COLLECTOR_KILL_GRACE_SECONDS
            if deadline is not None:
                cleanup_limit = min(cleanup_limit, deadline)
            try:
                process.wait(timeout=max(0.0, cleanup_limit - time.monotonic()))
            except subprocess.TimeoutExpired:
                pass

        reader_limit = time.monotonic() + COLLECTOR_KILL_GRACE_SECONDS
        if deadline is not None:
            reader_limit = min(reader_limit, deadline)
        for reader in readers:
            reader.join(timeout=max(0.0, reader_limit - time.monotonic()))
        streams_incomplete = any(reader.is_alive() for reader in readers)
        if streams_incomplete:
            terminate_process_group()
        reader_limit = time.monotonic() + COLLECTOR_KILL_GRACE_SECONDS
        if deadline is not None:
            reader_limit = min(reader_limit, deadline)
        for reader in readers:
            reader.join(timeout=max(0.0, reader_limit - time.monotonic()))
        streams_incomplete = streams_incomplete or any(
            reader.is_alive() for reader in readers
        )
        cleanup_pending = process.poll() is None or any(
            reader.is_alive() for reader in readers
        )
        if cleanup_pending:
            # SIGKILL is already pending. Reap and close asynchronously rather
            # than let cleanup push the request worker beyond its budget.
            def finish_cleanup() -> None:
                try:
                    process.wait()
                except OSError:
                    pass
                for reader in readers:
                    reader.join()
                for stream in (process.stdout, process.stderr):
                    if stream is not None:
                        try:
                            stream.close()
                        except OSError:
                            pass

            threading.Thread(target=finish_cleanup, daemon=True).start()
        else:
            for stream in (process.stdout, process.stderr):
                if stream is not None:
                    stream.close()
        try:
            output = bytes(retained).decode("utf-8", errors="strict")
            valid_utf8 = True
        except UnicodeDecodeError:
            output = ""
            valid_utf8 = False
        truncated = stdout_truncated or stderr_truncated or streams_incomplete
        if budget_timeout:
            raise TimeoutError("Deadline dell'autorizzazione Rescue scaduta.")
        _check_deadline(deadline)
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
    except TimeoutError:
        raise
    except (OSError, subprocess.TimeoutExpired):
        return {
            "collector": collector,
            "trust": "observed-untrusted",
            "output": "",
            "success": False,
            "truncated": False,
        }


def inventory(deadline: float | None = None) -> list[dict[str, object]]:
    _check_deadline(deadline)
    if not INVENTORY_LOCK.acquire(blocking=False):
        raise InventoryBusy("Inventario locale già in corso; riprovare.")
    try:
        _check_deadline(deadline)
        with ThreadPoolExecutor(max_workers=len(COMMANDS)) as executor:
            if deadline is None:
                futures = [
                    executor.submit(observe, collector, command)
                    for collector, command in COMMANDS
                ]
            else:
                futures = [
                    executor.submit(observe, collector, command, deadline)
                    for collector, command in COMMANDS
                ]
            observations = [
                future.result(timeout=_remaining_seconds(deadline))
                if deadline is not None
                else future.result()
                for future in futures
            ]
        _check_deadline(deadline)
        return observations
    finally:
        INVENTORY_LOCK.release()


def _target_text(value: object, field: str, *, required: bool = False) -> str | None:
    if value is None and not required:
        return None
    if not isinstance(value, str) or (required and not value):
        raise TargetScanError(f"Metadato {field} non valido.")
    if len(value.encode("utf-8")) > MAX_TARGET_FIELD_BYTES:
        raise TargetScanError(f"Metadato {field} oltre il limite.")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise TargetScanError(f"Metadato {field} contiene caratteri non validi.")
    return value


def _target_flag(value: object, field: str) -> bool:
    if not isinstance(value, bool):
        raise TargetScanError(f"Metadato {field} non valido.")
    return value


def _target_size(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise TargetScanError("Dimensione del dispositivo non valida.")
    return value


def _target_major_minor(value: object) -> str:
    normalized = _target_text(value, "maj:min", required=True)
    if normalized is None:
        raise TargetScanError("Identità kernel del dispositivo non valida.")
    parts = normalized.split(":")
    if (
        len(parts) != 2
        or not all(part.isascii() and part.isdecimal() for part in parts)
        or any(len(part) > 10 for part in parts)
        or any(int(part) > 4_294_967_295 for part in parts)
    ):
        raise TargetScanError("Identità kernel del dispositivo non valida.")
    return f"{int(parts[0])}:{int(parts[1])}"


def _parse_target_device(
    value: object, depth: int, device_count: list[int]
) -> dict[str, object]:
    if depth > MAX_TARGET_DEPTH or not isinstance(value, dict):
        raise TargetScanError("Topologia dei dispositivi non valida.")
    allowed_fields = TARGET_DEVICE_FIELDS | {"children"}
    if not TARGET_DEVICE_FIELDS.issubset(value) or not set(value).issubset(
        allowed_fields
    ):
        raise TargetScanError("Schema dei metadati dei dispositivi non valido.")
    device_count[0] += 1
    if device_count[0] > MAX_TARGET_DEVICES:
        raise TargetScanError("Troppi dispositivi per una scansione sicura.")

    text_fields = {
        field: _target_text(value[field], field, required=field in {"name", "type"})
        for field in (
            "name",
            "type",
            "tran",
            "fstype",
            "fsver",
            "uuid",
            "partuuid",
            "ptuuid",
            "pttype",
            "parttype",
            "serial",
            "wwn",
        )
    }
    mountpoints = value["mountpoints"]
    if not isinstance(mountpoints, list) or len(mountpoints) > 32:
        raise TargetScanError("Metadati dei mount point non validi.")
    normalized_mountpoints: list[str | None] = []
    for mountpoint in mountpoints:
        normalized_mountpoints.append(_target_text(mountpoint, "mountpoint"))

    raw_children = value.get("children", [])
    if not isinstance(raw_children, list):
        raise TargetScanError("Topologia figlia dei dispositivi non valida.")
    children = [
        _parse_target_device(child, depth + 1, device_count)
        for child in raw_children
    ]
    identity = {
        **text_fields,
        "maj:min": _target_major_minor(value["maj:min"]),
        "size": _target_size(value["size"]),
        "ro": _target_flag(value["ro"], "ro"),
        "rm": _target_flag(value["rm"], "rm"),
        "mountpoints": normalized_mountpoints,
    }
    return {
        "identity": identity,
        "name": text_fields["name"],
        "major_minor": identity["maj:min"],
        "kind": str(text_fields["type"]).lower(),
        "size": identity["size"],
        "read_only": identity["ro"],
        "removable": identity["rm"],
        "transport": (text_fields["tran"] or "").lower(),
        "filesystem": (text_fields["fstype"] or "").lower(),
        "partition_table": (text_fields["pttype"] or "").lower(),
        "partition_type": (text_fields["parttype"] or "").lower(),
        "mounted": any(bool(mountpoint) for mountpoint in normalized_mountpoints),
        "children": children,
    }


def _canonical_target_device(device: dict[str, object]) -> dict[str, object]:
    children = device["children"]
    if not isinstance(children, list):
        raise TargetScanError("Topologia normalizzata non valida.")
    canonical_children = [_canonical_target_device(child) for child in children]
    canonical_children.sort(
        key=lambda child: json.dumps(child, sort_keys=True, separators=(",", ":"))
    )
    return {"identity": device["identity"], "children": canonical_children}


def _walk_target_devices(device: dict[str, object]) -> list[dict[str, object]]:
    children = device["children"]
    if not isinstance(children, list):
        raise TargetScanError("Topologia normalizzata non valida.")
    return [device] + [
        descendant
        for child in children
        for descendant in _walk_target_devices(child)
    ]


def _complex_topology_disks(
    disks: list[dict[str, object]],
) -> dict[int, set[str]]:
    by_major_minor: dict[
        str, list[tuple[dict[str, object], dict[str, object]]]
    ] = {}
    by_kernel_name: dict[
        str, list[tuple[dict[str, object], dict[str, object]]]
    ] = {}
    btrfs_members: dict[
        str, list[tuple[dict[str, object], dict[str, object]]]
    ] = {}
    for disk in disks:
        for device in _walk_target_devices(disk):
            major_minor = device["major_minor"]
            name = device["name"]
            if not isinstance(major_minor, str) or not isinstance(name, str):
                raise TargetScanError("Indice della topologia non valido.")
            by_major_minor.setdefault(major_minor, []).append((disk, device))
            by_kernel_name.setdefault(name, []).append((disk, device))
            identity = device["identity"]
            if not isinstance(identity, dict):
                raise TargetScanError("Identità normalizzata non valida.")
            filesystem_uuid = identity.get("uuid")
            if (
                device["filesystem"] == "btrfs"
                and isinstance(filesystem_uuid, str)
                and filesystem_uuid
            ):
                btrfs_members.setdefault(filesystem_uuid.casefold(), []).append(
                    (disk, device)
                )

    conflicts: dict[int, set[str]] = {}

    def mark(
        occurrences: list[tuple[dict[str, object], dict[str, object]]], reason: str
    ) -> None:
        for disk, _device in occurrences:
            conflicts.setdefault(id(disk), set()).add(reason)

    for occurrences in by_major_minor.values():
        if len(occurrences) < 2:
            continue
        # A repeated N:M is an N-to-M graph, even when lsblk renders coherent
        # duplicate subtrees. Incoherent copies are treated identically: none of
        # their owning disks may produce a selectable target.
        canonical_copies = {
            json.dumps(
                _canonical_target_device(device),
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            )
            for _disk, device in occurrences
        }
        mark(occurrences, "repeated-major-minor")
        if len(canonical_copies) != 1:
            mark(occurrences, "incoherent-duplicate-identity")

    for occurrences in by_kernel_name.values():
        if len({str(device["major_minor"]) for _disk, device in occurrences}) > 1:
            mark(occurrences, "kernel-name-maps-to-multiple-devices")

    for occurrences in btrfs_members.values():
        if len({str(device["major_minor"]) for _disk, device in occurrences}) > 1:
            mark(occurrences, "shared-btrfs-filesystem")
    return conflicts


def _ephemeral_target_id(prefix: str, payload: object) -> str:
    canonical = json.dumps(
        payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode()
    digest = hmac.new(TARGET_ID_KEY, canonical, hashlib.sha256).hexdigest()
    return f"{prefix}:{digest}"


def _subtree_matches(device: dict[str, object], predicate: object) -> bool:
    if not callable(predicate):
        raise TargetScanError("Predicato di scansione non valido.")
    if predicate(device):
        return True
    children = device["children"]
    if not isinstance(children, list):
        raise TargetScanError("Topologia normalizzata non valida.")
    return any(_subtree_matches(child, predicate) for child in children)


def _public_transport(value: object) -> str:
    if value in {"ata", "mmc", "nvme", "sata", "sas", "scsi", "usb", "virtio"}:
        return str(value)
    return "unknown"


def _public_partition_table(value: object) -> str:
    if value in {"bsd", "dos", "gpt", "mac", "sun"}:
        return str(value)
    return "unknown"


def _public_filesystem(value: object) -> str:
    known = (
        LINUX_FILESYSTEMS
        | WINDOWS_FILESYSTEMS
        | MACOS_FILESYSTEMS
        | ENCRYPTED_FILESYSTEMS
        | LIVE_IMAGE_FILESYSTEMS
        | {
            "exfat",
            "fat",
            "lvm2_member",
            "linux_raid_member",
            "swap",
            "vfat",
        }
    )
    if value in known:
        return str(value)
    return "unknown" if not value else "other"


def _public_device_kind(value: object) -> str:
    if value == "part":
        return "partition"
    if value == "lvm":
        return "logical-volume"
    if value == "crypt":
        return "encrypted-mapping"
    if value == "disk":
        return "whole-disk-filesystem"
    if isinstance(value, str) and (value.startswith("raid") or value == "md"):
        return "raid-volume"
    return "other"


def _candidate_classification(
    device: dict[str, object]
) -> tuple[str, list[str], bool] | None:
    filesystem = device["filesystem"]
    partition_type = device["partition_type"]
    families: set[str] = set()
    basis: list[str] = []
    requires_unlock = filesystem in ENCRYPTED_FILESYSTEMS

    if filesystem in LINUX_FILESYSTEMS:
        families.add("linux")
        basis.append("linux-filesystem-signature")
    elif filesystem == "ntfs":
        families.add("windows")
        basis.append("ntfs-filesystem-signature")
    elif filesystem == "bitlocker":
        families.add("windows")
        basis.append("bitlocker-container-signature")
    elif filesystem in MACOS_FILESYSTEMS:
        families.add("macos")
        basis.append("apple-filesystem-signature")
    elif filesystem == "crypto_luks":
        families.add("unknown-encrypted")
        basis.append("luks-container-signature")

    if partition_type in LINUX_ROOT_PARTITION_TYPES:
        families.add("linux")
        basis.append("linux-root-partition-type")
    elif partition_type == APPLE_APFS_PARTITION_TYPE:
        families.add("macos")
        basis.append("apple-apfs-partition-type")

    if not families:
        return None
    if len(families) == 1:
        family = next(iter(families))
    else:
        family = "unknown"
        basis.append("conflicting-metadata-signatures")
    return family, sorted(set(basis)), requires_unlock


def _candidate_nodes(device: dict[str, object]) -> list[dict[str, object]]:
    children = device["children"]
    if not isinstance(children, list):
        raise TargetScanError("Topologia normalizzata non valida.")
    child_candidates = [
        candidate for child in children for candidate in _candidate_nodes(child)
    ]
    if child_candidates:
        return child_candidates
    if device["kind"] not in {"crypt", "disk", "lvm", "part"}:
        return []
    return [device] if _candidate_classification(device) is not None else []


def _flatten_target_volumes(
    disk: dict[str, object], disk_ref: str
) -> tuple[list[dict[str, object]], dict[int, str]]:
    volumes: list[dict[str, object]] = []
    references: dict[int, str] = {id(disk): disk_ref}

    def append_children(device: dict[str, object], parent_ref: str) -> None:
        children = device["children"]
        if not isinstance(children, list):
            raise TargetScanError("Topologia normalizzata non valida.")
        for child in sorted(children, key=lambda item: str(item["name"])):
            volume_ref = f"{disk_ref}/volume-{len(volumes) + 1}"
            references[id(child)] = volume_ref
            volumes.append(
                {
                    "ref": volume_ref,
                    "parentRef": parent_ref,
                    "kind": _public_device_kind(child["kind"]),
                    "sizeBytes": child["size"],
                    "filesystem": _public_filesystem(child["filesystem"]),
                    "mediaReadOnly": child["read_only"],
                    "mounted": child["mounted"],
                    "encrypted": child["filesystem"] in ENCRYPTED_FILESYSTEMS,
                }
            )
            append_children(child, volume_ref)

    append_children(disk, disk_ref)
    return volumes, references


def _normalize_installed_targets_with_resolutions(
    output: str,
) -> tuple[dict[str, object], dict[str, dict[str, object]]]:
    try:
        decoded = json.loads(output)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise TargetScanError("Output della scansione dei target non valido.") from error
    if not isinstance(decoded, dict) or set(decoded) != {"blockdevices"}:
        raise TargetScanError("Schema della scansione dei target non valido.")
    raw_devices = decoded["blockdevices"]
    if not isinstance(raw_devices, list):
        raise TargetScanError("Elenco dei dispositivi non valido.")
    device_count = [0]
    roots = [_parse_target_device(device, 0, device_count) for device in raw_devices]
    disks = sorted(
        (root for root in roots if root["kind"] == "disk"),
        key=lambda item: str(item["name"]),
    )
    complex_topology_disks = _complex_topology_disks(disks)
    canonical_disks = [_canonical_target_device(disk) for disk in disks]
    scan_fingerprint = _ephemeral_target_id("scan", canonical_disks)

    public_disks: list[dict[str, object]] = []
    public_candidates: list[dict[str, object]] = []
    resolutions: dict[str, dict[str, object]] = {}
    seen_target_ids: set[str] = set()
    for disk_index, disk in enumerate(disks, start=1):
        disk_ref = f"disk-{disk_index}"
        canonical_disk = _canonical_target_device(disk)
        disk_id = _ephemeral_target_id("disk", canonical_disk)
        subtree_mounted = _subtree_matches(disk, lambda node: node["mounted"] is True)
        live_image = _subtree_matches(
            disk, lambda node: node["filesystem"] in LIVE_IMAGE_FILESYSTEMS
        )
        exclusion_reasons: list[str] = []
        if subtree_mounted:
            exclusion_reasons.append("disk-or-descendant-mounted")
        if live_image:
            exclusion_reasons.append("live-or-optical-filesystem-signature")
        if id(disk) in complex_topology_disks:
            exclusion_reasons.append("complex-multi-parent-topology")
        if disk["size"] == 0:
            exclusion_reasons.append("zero-capacity-device")
        selection_eligible = not exclusion_reasons
        volumes, references = _flatten_target_volumes(disk, disk_ref)
        public_disks.append(
            {
                "id": disk_id,
                "ref": disk_ref,
                "sizeBytes": disk["size"],
                "transport": _public_transport(disk["transport"]),
                "partitionTable": _public_partition_table(disk["partition_table"]),
                "mediaReadOnly": disk["read_only"],
                "removable": disk["removable"],
                "mounted": subtree_mounted,
                "selectionEligible": selection_eligible,
                "exclusionReasons": exclusion_reasons,
                "volumes": volumes,
            }
        )
        if not selection_eligible:
            continue
        for candidate in _candidate_nodes(disk):
            classification = _candidate_classification(candidate)
            if classification is None:
                continue
            family, basis, requires_unlock = classification
            target_id = _ephemeral_target_id(
                "target", {"disk": canonical_disk, "device": candidate["identity"]}
            )
            if target_id in seen_target_ids:
                continue
            seen_target_ids.add(target_id)
            public_candidate = {
                "targetId": target_id,
                "sourceRef": references[id(candidate)],
                "diskId": disk_id,
                "osFamilyHint": family,
                "confidence": "low",
                "status": "unverified-installation-candidate",
                "detectionBasis": basis,
                "requiresUnlock": requires_unlock,
                "inspectionMode": "metadata-only-no-mount",
                "selectionEligible": True,
            }
            public_candidates.append(public_candidate)
            disk_children = disk["children"]
            candidate_children = candidate["children"]
            if not isinstance(disk_children, list) or not isinstance(
                candidate_children, list
            ):
                raise TargetScanError("Topologia normalizzata non valida.")
            direct_child = any(child is candidate for child in disk_children)
            topology_kinds = sorted(
                {
                    str(node["kind"])
                    for node in _walk_target_devices(disk)
                }
            )
            topology_filesystems = sorted(
                {
                    str(node["filesystem"])
                    for node in _walk_target_devices(disk)
                    if node["filesystem"]
                }
            )
            resolutions[target_id] = {
                "candidate": public_candidate,
                "deviceIdentity": candidate["identity"],
                "majorMinor": candidate["major_minor"],
                "filesystem": candidate["filesystem"],
                "kernelKind": candidate["kind"],
                "leaf": not candidate_children,
                "directOnDisk": candidate is disk or direct_child,
                "topologyKinds": topology_kinds,
                "topologyFilesystems": topology_filesystems,
            }

    snapshot: dict[str, object] = {
        "apiVersion": TARGET_SCAN_API_VERSION,
        "mode": "observe-r0",
        "trust": "observed-untrusted",
        "scanFingerprint": scan_fingerprint,
        "identifierScope": TARGET_ID_SCOPE,
        "disks": public_disks,
        "candidates": public_candidates,
        "claims": {
            "installedOsConfirmed": False,
            "filesystemContentInspected": False,
            "mountOperationPerformed": False,
            "mutationPerformed": False,
            "rawDeviceIdentifiersReturned": False,
        },
        "limitations": [
            "os-family-is-only-a-low-confidence-metadata-hint",
            "filesystem-content-was-not-inspected",
            "locked-or-complex-storage-was-not-activated",
            "mounted-and-live-image-disks-are-not-selectable",
        ],
    }
    encoded = json.dumps(snapshot, ensure_ascii=True, separators=(",", ":")).encode()
    if len(encoded) > MAX_TARGET_RESPONSE_BYTES:
        raise TargetScanError("Risposta della scansione dei target oltre il limite.")
    return snapshot, resolutions


def normalize_installed_targets(output: str) -> dict[str, object]:
    snapshot, _resolutions = _normalize_installed_targets_with_resolutions(output)
    return snapshot


def _target_scan_output(deadline: float | None = None) -> str:
    if deadline is None:
        observation = observe("rescue.installed-targets.metadata", TARGET_SCAN_COMMAND)
    else:
        observation = observe(
            "rescue.installed-targets.metadata", TARGET_SCAN_COMMAND, deadline
        )
    _check_deadline(deadline)
    if observation.get("success") is not True or observation.get("truncated") is True:
        raise TargetScanError("Scansione dei target incompleta; riprovare.")
    output = observation.get("output")
    if not isinstance(output, str):
        raise TargetScanError("Output della scansione dei target non valido.")
    return output


def installed_targets(deadline: float | None = None) -> dict[str, object]:
    if OFFLINE_HELPER_ENABLED:
        _check_deadline(deadline)
        result = _privileged_helper_call("scan")
        if not isinstance(result, dict):
            raise TargetScanError("Risposta privilegiata dei target non valida.")
        return result
    _check_deadline(deadline)
    if not TARGET_SCAN_LOCK.acquire(blocking=False):
        raise TargetScanBusy("Scansione dei target già in corso; riprovare.")
    try:
        _check_deadline(deadline)
        return normalize_installed_targets(_target_scan_output(deadline))
    finally:
        TARGET_SCAN_LOCK.release()


def resolve_installed_target(
    request: dict[str, object], deadline: float | None = None
) -> tuple[dict[str, object], dict[str, object]]:
    """Resolve an opaque selection to one internal identity in this process.

    The internal resolution is for the privileged offline inspector only. It
    must never be serialized by the HTTP bridge because it contains raw kernel
    identity and storage metadata.
    """
    _check_deadline(deadline)
    if set(request) != {"scanFingerprint", "targetId"}:
        raise TargetSelectionError(
            "Richiesta di selezione del target non valida.", status=400
        )
    requested_fingerprint = request["scanFingerprint"]
    requested_target = request["targetId"]
    if not _valid_ephemeral_id(
        requested_fingerprint, "scan"
    ) or not _valid_ephemeral_id(requested_target, "target"):
        raise TargetSelectionError(
            "Richiesta di selezione del target non valida.", status=400
        )
    if not TARGET_SCAN_LOCK.acquire(blocking=False):
        raise TargetScanBusy("Scansione dei target già in corso; riprovare.")
    try:
        snapshot, resolutions = _normalize_installed_targets_with_resolutions(
            _target_scan_output(deadline)
        )
    finally:
        TARGET_SCAN_LOCK.release()
    _check_deadline(deadline)
    if snapshot["scanFingerprint"] != requested_fingerprint:
        raise TargetSelectionError(
            "La topologia dei dischi è cambiata; ripetere la selezione."
        )
    if not isinstance(requested_target, str):
        raise TargetSelectionError(
            "Richiesta di selezione del target non valida.", status=400
        )
    resolution = resolutions.get(requested_target)
    if resolution is None:
        raise TargetSelectionError(
            "Il target non è più disponibile in modalità Observe; ripetere la selezione."
        )
    candidate = resolution.get("candidate")
    canonical_target_candidate(candidate)
    selection = {
        "apiVersion": TARGET_SCAN_API_VERSION,
        "status": "observe-target-validated",
        "scanFingerprint": snapshot["scanFingerprint"],
        "target": candidate,
        "claims": {
            "installedOsConfirmed": False,
            "filesystemContentInspected": False,
            "mountOperationPerformed": False,
            "mutationPerformed": False,
        },
    }
    return selection, resolution


def _valid_ephemeral_id(value: object, prefix: str) -> bool:
    if not isinstance(value, str) or not value.startswith(f"{prefix}:"):
        return False
    digest = value.removeprefix(f"{prefix}:")
    return len(digest) == 64 and all(
        character in "0123456789abcdef" for character in digest
    )


def select_installed_target(
    request: dict[str, object], deadline: float | None = None
) -> dict[str, object]:
    if OFFLINE_HELPER_ENABLED:
        _check_deadline(deadline)
        result = _privileged_helper_call("select", request)
        if not isinstance(result, dict):
            raise TargetSelectionError(
                "Risposta privilegiata di selezione non valida.", status=503
            )
        return result
    _check_deadline(deadline)
    if set(request) != {"scanFingerprint", "targetId"}:
        raise TargetSelectionError(
            "Richiesta di selezione del target non valida.", status=400
        )
    requested_fingerprint = request["scanFingerprint"]
    requested_target = request["targetId"]
    if not _valid_ephemeral_id(
        requested_fingerprint, "scan"
    ) or not _valid_ephemeral_id(requested_target, "target"):
        raise TargetSelectionError(
            "Richiesta di selezione del target non valida.", status=400
        )

    _check_deadline(deadline)
    snapshot = (
        installed_targets()
        if deadline is None
        else installed_targets(deadline)
    )
    _check_deadline(deadline)
    if snapshot["scanFingerprint"] != requested_fingerprint:
        raise TargetSelectionError(
            "La topologia dei dischi è cambiata; ripetere la selezione."
        )
    candidates = snapshot["candidates"]
    if not isinstance(candidates, list):
        raise TargetScanError("Risposta normalizzata dei target non valida.")
    selected = next(
        (
            candidate
            for candidate in candidates
            if isinstance(candidate, dict)
            and candidate.get("targetId") == requested_target
            and candidate.get("selectionEligible") is True
        ),
        None,
    )
    if selected is None:
        raise TargetSelectionError(
            "Il target non è più disponibile in modalità Observe; ripetere la selezione."
        )
    selection = {
        "apiVersion": TARGET_SCAN_API_VERSION,
        "status": "observe-target-validated",
        "scanFingerprint": snapshot["scanFingerprint"],
        "target": selected,
        "claims": {
            "installedOsConfirmed": False,
            "filesystemContentInspected": False,
            "mountOperationPerformed": False,
            "mutationPerformed": False,
        },
    }
    _check_deadline(deadline)
    return selection


def inspect_installed_target(request: dict[str, object]) -> dict[str, object]:
    if set(request) != {"scanFingerprint", "targetId"}:
        raise PrivilegedHelperError(
            {
                "code": "invalid-inspection-request",
                "message": "Richiesta di ispezione del target non valida.",
                "retryable": False,
                "claims": {
                    field: False for field in OFFLINE_INSPECTION_CLAIM_FIELDS
                },
            },
            400,
        )
    if not _valid_ephemeral_id(
        request.get("scanFingerprint"), "scan"
    ) or not _valid_ephemeral_id(request.get("targetId"), "target"):
        raise PrivilegedHelperError(
            {
                "code": "invalid-inspection-request",
                "message": "Richiesta di ispezione del target non valida.",
                "retryable": False,
                "claims": {
                    field: False for field in OFFLINE_INSPECTION_CLAIM_FIELDS
                },
            },
            400,
        )
    result = _privileged_helper_call("inspect", request)
    if not isinstance(result, dict):
        raise BrokerError("Risposta privilegiata di ispezione non valida.")
    return result


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


def valid_fingerprint(value: object) -> bool:
    if not isinstance(value, str) or not value.startswith("sha256:"):
        return False
    digest = value.removeprefix("sha256:")
    return len(digest) == 64 and all(character in "0123456789abcdef" for character in digest)


def validate_rescue_target_reference(value: object) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != RESCUE_TARGET_REFERENCE_FIELDS:
        raise BrokerError("Selezione del target Rescue non valida.")
    scan_fingerprint = value.get("scanFingerprint")
    target_id = value.get("targetId")
    if not _valid_ephemeral_id(
        scan_fingerprint, "scan"
    ) or not _valid_ephemeral_id(target_id, "target"):
        raise BrokerError("Selezione del target Rescue non valida.")
    if not isinstance(scan_fingerprint, str) or not isinstance(target_id, str):
        raise BrokerError("Selezione del target Rescue non valida.")
    return {"scanFingerprint": scan_fingerprint, "targetId": target_id}


def validate_observe_request(
    request: dict[str, object]
) -> tuple[str, dict[str, str]]:
    if set(request) != OBSERVE_AUTHORIZATION_FIELDS:
        raise BrokerError("Richiesta al broker non valida.")
    if request.get("action") != "system.observe.noop":
        raise BrokerError("Azione non consentita dal broker locale.")
    session_id = request.get("sessionId")
    plan_id = request.get("planId")
    fingerprint = request.get("targetFingerprint")
    sequence = request.get("sequence")
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
        or sequence <= 0
    ):
        raise BrokerError("Richiesta al broker non valida.")
    return session_id, validate_rescue_target_reference(request.get("rescueTarget"))


def canonical_target_candidate(candidate: object) -> str:
    if not isinstance(candidate, dict) or set(candidate) != TARGET_CANDIDATE_FIELDS:
        raise BrokerError("Candidato target Rescue non valido.")
    target_id = candidate.get("targetId")
    disk_id = candidate.get("diskId")
    source_ref = candidate.get("sourceRef")
    detection_basis = candidate.get("detectionBasis")
    if (
        not _valid_ephemeral_id(target_id, "target")
        or not _valid_ephemeral_id(disk_id, "disk")
        or not isinstance(source_ref, str)
        or not source_ref.startswith("disk-")
        or len(source_ref) > 64
        or not source_ref.isascii()
        or any(
            character not in "abcdefghijklmnopqrstuvwxyz0123456789-/"
            for character in source_ref
        )
        or candidate.get("osFamilyHint")
        not in {"linux", "macos", "unknown", "unknown-encrypted", "windows"}
        or candidate.get("confidence") != "low"
        or candidate.get("status") != "unverified-installation-candidate"
        or candidate.get("inspectionMode") != "metadata-only-no-mount"
        or candidate.get("selectionEligible") is not True
        or not isinstance(candidate.get("requiresUnlock"), bool)
        or not isinstance(detection_basis, list)
        or not detection_basis
        or len(detection_basis) > 8
        or any(
            not isinstance(item, str)
            or not item
            or len(item) > 64
            or not item.isascii()
            or any(
                character not in "abcdefghijklmnopqrstuvwxyz0123456789-"
                for character in item
            )
            for item in detection_basis
        )
        or detection_basis != sorted(set(detection_basis))
    ):
        raise BrokerError("Candidato target Rescue non valido.")
    return json.dumps(
        candidate, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    )


def validate_target_selection(
    selection: object, rescue_target: dict[str, str]
) -> dict[str, object]:
    if not isinstance(selection, dict) or set(selection) != TARGET_SELECTION_FIELDS:
        raise BrokerError("Rivalidazione del target Rescue non valida.")
    if (
        selection.get("apiVersion") != TARGET_SCAN_API_VERSION
        or selection.get("status") != "observe-target-validated"
        or selection.get("scanFingerprint") != rescue_target["scanFingerprint"]
    ):
        raise BrokerError("Rivalidazione del target Rescue non valida.")
    claims = selection.get("claims")
    if (
        not isinstance(claims, dict)
        or set(claims) != TARGET_SELECTION_CLAIM_FIELDS
        or any(claims.get(field) is not False for field in TARGET_SELECTION_CLAIM_FIELDS)
    ):
        raise BrokerError("Rivalidazione del target Rescue non valida.")
    candidate = selection.get("target")
    canonical_target_candidate(candidate)
    if not isinstance(candidate, dict) or candidate.get("targetId") != rescue_target["targetId"]:
        raise BrokerError("Rivalidazione del target Rescue non valida.")
    return candidate


def rescue_target_fingerprint(
    runtime_inventory_fingerprint: str,
    scan_fingerprint: str,
    candidate: dict[str, object],
) -> str:
    """Hash the documented NUL-delimited Rescue target binding."""
    if not valid_fingerprint(
        runtime_inventory_fingerprint
    ) or not _valid_ephemeral_id(scan_fingerprint, "scan"):
        raise BrokerError("Fingerprint composito del target Rescue non valido.")
    candidate_json = canonical_target_candidate(candidate)
    target_id = candidate.get("targetId")
    if not isinstance(target_id, str):
        raise BrokerError("Fingerprint composito del target Rescue non valido.")
    material = "\0".join(
        (
            RESCUE_TARGET_FINGERPRINT_DOMAIN,
            runtime_inventory_fingerprint,
            scan_fingerprint,
            target_id,
            candidate_json,
        )
    )
    return f"sha256:{hashlib.sha256(material.encode('utf-8')).hexdigest()}"


def canonical_target_selection(selection: object) -> str:
    return json.dumps(
        selection, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    )


def authorize_observe(
    request: dict[str, object], deadline: float | None = None
) -> None:
    started = time.monotonic()
    internal_deadline = started + AUTHORIZE_DEADLINE_SECONDS
    deadline = internal_deadline if deadline is None else min(deadline, internal_deadline)
    _check_deadline(deadline)
    session_id, rescue_target = validate_observe_request(request)
    _check_deadline(deadline)
    selection_before = select_installed_target(rescue_target, deadline=deadline)
    _check_deadline(deadline)
    candidate_before = validate_target_selection(selection_before, rescue_target)
    _check_deadline(deadline)
    observations = inventory(deadline=deadline)
    _check_deadline(deadline)
    selection_after = select_installed_target(rescue_target, deadline=deadline)
    _check_deadline(deadline)
    candidate_after = validate_target_selection(selection_after, rescue_target)
    if (
        canonical_target_selection(selection_before)
        != canonical_target_selection(selection_after)
        or canonical_target_candidate(candidate_before)
        != canonical_target_candidate(candidate_after)
    ):
        raise BrokerError("Il target Rescue è cambiato durante la rivalidazione.")
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
    runtime_fingerprint = inventory_fingerprint(observations)
    current_fingerprint = rescue_target_fingerprint(
        runtime_fingerprint,
        rescue_target["scanFingerprint"],
        candidate_before,
    )
    if request.get("targetFingerprint") != current_fingerprint:
        raise BrokerError("Il target è cambiato: piano annullato, ripetere la diagnosi.")
    _check_deadline(deadline)
    remaining = _remaining_seconds(deadline)
    if remaining is None or not BROKER_LOCK.acquire(timeout=remaining):
        raise TimeoutError("Deadline dell'autorizzazione Rescue scaduta.")
    try:
        # Decisive anti-ghost check: no session can be created or advanced after
        # the request's monotonic end-to-end authorization budget has expired.
        _check_deadline(deadline)
        if session_id not in BROKERS and len(BROKERS) >= MAX_BROKER_SESSIONS:
            raise BrokerError("Limite delle sessioni locali raggiunto; riavviare KernAid.")
        broker = BROKERS.get(session_id)
        if broker is None:
            pending_broker = ObserveBroker(current_fingerprint, rescue_target)
            pending_broker.authorize(request, deadline=deadline)
            _check_deadline(deadline)
            BROKERS[session_id] = pending_broker
        else:
            broker.authorize(request, deadline=deadline)
    finally:
        BROKER_LOCK.release()


class RescueHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, directory=WEB_ROOT, **kwargs)

    def handle(self) -> None:
        request_started = time.monotonic()
        self.authorization_deadline = (
            request_started + AUTHORIZE_DEADLINE_SECONDS
        )

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
        if self.path == "/api/rescue/installed-targets":
            try:
                body = json.dumps(
                    installed_targets(), ensure_ascii=True, separators=(",", ":")
                ).encode()
                status = 200
            except TargetScanBusy as error:
                body = json.dumps({"error": str(error)}).encode()
                status = 429
            except TargetScanError as error:
                body = json.dumps({"error": str(error)}).encode()
                status = 503
            except PrivilegedHelperError as error:
                body = json.dumps(
                    {"error": error.error},
                    ensure_ascii=True,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
                status = error.status
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
        authorization_deadline = (
            self.authorization_deadline
            if self.path == "/api/authorize-observe"
            else None
        )
        if not self.local_authority():
            self.send_error(421)
            return
        if self.headers.get("Origin") not in ALLOWED_ORIGINS:
            self.send_error(403)
            return
        if self.path not in {
            "/api/authorize-observe",
            "/api/rescue/inspect-installed-target",
            "/api/rescue/select-installed-target",
        }:
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
                if self.path == "/api/rescue/inspect-installed-target":
                    raise PrivilegedHelperError(
                        {
                            "code": "invalid-inspection-request",
                            "message": "Richiesta di ispezione del target non valida.",
                            "retryable": False,
                            "claims": {
                                field: False
                                for field in OFFLINE_INSPECTION_CLAIM_FIELDS
                            },
                        },
                        400,
                    )
                if self.path == "/api/rescue/select-installed-target":
                    raise TargetSelectionError(
                        "Richiesta di selezione del target non valida.", status=400
                    )
                raise BrokerError("Richiesta al broker non valida.")
            if self.path == "/api/authorize-observe":
                authorize_observe(request, deadline=authorization_deadline)
                body = b'{"status":"observed"}'
            elif self.path == "/api/rescue/inspect-installed-target":
                body = json.dumps(
                    inspect_installed_target(request),
                    ensure_ascii=True,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
            else:
                body = json.dumps(
                    select_installed_target(request),
                    ensure_ascii=True,
                    separators=(",", ":"),
                ).encode()
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
        except PrivilegedHelperError as error:
            body = json.dumps(
                {"error": error.error},
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
            status = error.status
        except TargetSelectionError as error:
            body = json.dumps({"error": str(error)}).encode()
            status = error.status
        except InventoryBusy as error:
            body = json.dumps({"error": str(error)}).encode()
            status = 429
        except TargetScanBusy as error:
            body = json.dumps({"error": str(error)}).encode()
            status = 429
        except TargetScanError as error:
            body = json.dumps({"error": str(error)}).encode()
            status = 503
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
