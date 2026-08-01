#!/usr/bin/python3 -I
"""Write a verified KernAid Rescue ISO to one explicitly selected device.

This utility is deliberately Linux-only.  It treats lsblk and /proc as safety
inputs, revalidates them immediately before opening the device, and never
constructs a target from a glob or an environment variable.
"""

from __future__ import annotations

import argparse
import datetime as dt
import enum
import fcntl
import hashlib
import hmac
import json
import os
import re
import signal
import stat
import struct
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Mapping, Sequence, TextIO


LSBLK_PATHS = ("/usr/bin/lsblk", "/bin/lsblk")
LOSETUP_PATHS = ("/usr/sbin/losetup", "/sbin/losetup", "/usr/bin/losetup")
DD_PATHS = ("/usr/bin/dd", "/bin/dd")
WIPEFS_PATHS = ("/usr/sbin/wipefs", "/sbin/wipefs", "/usr/bin/wipefs")
UDEVADM_PATHS = ("/usr/bin/udevadm", "/bin/udevadm", "/usr/sbin/udevadm")
SAFE_ENV = {"LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}
LSBLK_COLUMNS = (
    "NAME,KNAME,PATH,TYPE,PKNAME,RM,RO,ROTA,SIZE,SERIAL,MODEL,VENDOR,TRAN,"
    "SUBSYSTEMS,MOUNTPOINTS,MAJ:MIN,DISK-SEQ"
)
SHA256_RE = re.compile(r"[0-9a-fA-F]{64}\Z")
MAJ_MIN_RE = re.compile(r"(0|[1-9][0-9]*):(0|[1-9][0-9]*)\Z")
LOOP_PATH_RE = re.compile(r"/dev/loop[0-9]+\Z")
CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
ISO9660_MAGIC_OFFSET = 16 * 2048 + 1
ISO9660_MAGIC = b"CD001"
MBR_SIGNATURE_OFFSET = 510
MBR_SIGNATURE = b"\x55\xaa"
ISO_SECTOR_BYTES = 2048
EL_TORITO_SYSTEM_ID = b"EL TORITO SPECIFICATION"
BLKROGET = 0x125E
BLKFLSBUF = 0x1261
BLKSSZGET = 0x1268
BLKGETSIZE64 = 0x80081272
BLKGETDISKSEQ = 0x80081280
COPY_CHUNK_BYTES = 4 * 1024 * 1024
VERIFY_CHUNK_BYTES = 4 * 1024 * 1024
MAX_LSBLK_OUTPUT = 16 * 1024 * 1024
MAX_PROC_OUTPUT = 16 * 1024 * 1024
MAX_PROBE_OUTPUT = 16 * 1024 * 1024
MAX_CATALOG_BYTES = 2 * 1024 * 1024
TRUST_CATALOG_FILENAME = "trusted-rescue-images.v1.json"
TRUST_CATALOG_SCHEMA = "dev.kernaid.trusted-rescue-images.v1"
ARTIFACT_NAME_RE = re.compile(r"KernAid-Rescue-[A-Za-z0-9._-]+\.iso\Z")
ARTIFACT_VERSION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}\Z")
TRUSTED_RUN_URL_PREFIX = "https://github.com/0xfunboy/KernAid/actions/runs/"
CRITICAL_MOUNTS = frozenset(("/", "/boot", "/boot/efi"))
RESCUE_MOUNT_PREFIXES = (
    "/run/live/medium",
    "/lib/live/mount/medium",
    "/run/archiso/bootmnt",
    "/run/initramfs/live",
    "/cdrom",
)
ACTIVE_STACK_TYPES = frozenset(("crypt", "dm", "lvm", "md", "mpath"))
CARD_READER_PROPERTIES = frozenset(
    (
        "ID_DRIVE_FLASH_CF",
        "ID_DRIVE_FLASH_MS",
        "ID_DRIVE_FLASH_SD",
        "ID_DRIVE_FLASH_SM",
        "ID_DRIVE_FLASH_MMC",
    )
)
OPTIONAL_USB_MEDIA_PROPERTIES = frozenset(
    ("ID_DRIVE_THUMB", "ID_DRIVE_FLASH_USB", "ID_DRIVE_EXTERNAL")
)
CARD_READER_MODEL_RE = re.compile(
    r"(?:card[ _-]*reader|multi[ _-]*card|sd/mmc|memory[ _-]*card)", re.IGNORECASE
)
MANAGED_SIGNALS = tuple(
    candidate
    for candidate in (
        signal.SIGINT,
        signal.SIGTERM,
        getattr(signal, "SIGHUP", None),
        getattr(signal, "SIGQUIT", None),
    )
    if candidate is not None
)
CHILD_TERMINATE_TIMEOUT_SECONDS = 3


class SafetyError(RuntimeError):
    """A precondition failed before the destructive write."""


class WriteError(RuntimeError):
    """The write or post-write verification failed."""


class OperationInterrupted(KeyboardInterrupt):
    """A managed termination signal interrupted the operation."""

    def __init__(self, signal_number: int):
        super().__init__(signal_number)
        self.signal_number = signal_number


class WritePhase(enum.IntEnum):
    PRE_WRITE = 0
    WRITE_MAY_HAVE_STARTED = 1
    DD_COMPLETED = 2
    CACHE_FLUSHED = 3
    PREFIX_VERIFIED = 4
    REPORT_EMITTED = 5


@dataclass
class OperationState:
    phase: WritePhase = WritePhase.PRE_WRITE
    target_path: str | None = None

    @property
    def target_overwritten_or_partial(self) -> bool:
        return self.phase >= WritePhase.WRITE_MAY_HAVE_STARTED

    def advance(self, phase: WritePhase, target_path: str) -> None:
        if phase < self.phase:
            raise RuntimeError("write lifecycle cannot move backwards")
        self.phase = phase
        self.target_path = target_path


def _signal_interrupted(signal_number: int, _frame: object) -> None:
    raise OperationInterrupted(signal_number)


@dataclass(frozen=True)
class BlockDevice:
    path: str
    kname: str
    kind: str
    parent_key: str | None
    removable: bool
    read_only: bool
    rotational: bool
    size: int
    serial: str
    model: str
    vendor: str
    transport: str
    subsystems: str
    mountpoints: tuple[str, ...]
    major_minor: str
    disk_sequence: int | None

    def fingerprint(self) -> tuple[object, ...]:
        return (
            self.path,
            self.kname,
            self.kind,
            self.parent_key,
            self.removable,
            self.read_only,
            self.rotational,
            self.size,
            self.serial,
            self.model,
            self.vendor,
            self.transport,
            self.subsystems,
            self.major_minor,
            self.disk_sequence,
        )


@dataclass(frozen=True)
class MountRecord:
    major_minor: str
    mountpoint: str


@dataclass(frozen=True)
class HostUse:
    mounts: tuple[MountRecord, ...]
    swaps: frozenset[str]
    holders: frozenset[str]


@dataclass(frozen=True)
class ImageInfo:
    path: str
    size: int
    sha256: str
    device: int
    inode: int
    mtime_ns: int
    backing_major_minor: str

    def identity(self) -> tuple[int, int, int, int]:
        return (self.device, self.inode, self.size, self.mtime_ns)


@dataclass(frozen=True)
class QemuAttestation:
    firmware: str
    workflow_run_id: int
    workflow_run_url: str
    log_sha256: str


@dataclass(frozen=True)
class TrustedImage:
    artifact_name: str
    artifact_version: str
    sha256: str
    size: int
    bios: QemuAttestation
    uefi: QemuAttestation


@dataclass(frozen=True)
class TrustCatalog:
    revision: int
    images: tuple[TrustedImage, ...]

    def authorize(self, image: ImageInfo) -> TrustedImage:
        artifact_name = os.path.basename(image.path)
        matches = [
            entry
            for entry in self.images
            if entry.artifact_name == artifact_name
            and entry.sha256 == image.sha256
            and entry.size == image.size
        ]
        if len(matches) != 1:
            raise SafetyError(
                "ISO is not present in the root-owned official KernAid trust catalog"
            )
        return matches[0]


@dataclass(frozen=True)
class ImageAuthorization:
    mode: str
    catalog_revision: int
    artifact_name: str
    artifact_version: str
    bios: QemuAttestation | None
    uefi: QemuAttestation | None


@dataclass(frozen=True)
class LoopBacking:
    path: str
    device: int
    inode: int
    size: int
    uid: int
    mode: int
    links: int

    def fingerprint(self) -> tuple[object, ...]:
        return (
            self.path,
            self.device,
            self.inode,
            self.size,
            self.uid,
            self.mode,
            self.links,
        )


@dataclass(frozen=True)
class UsbMediaProof:
    properties: tuple[tuple[str, str], ...]


def _fixed_binary(candidates: Sequence[str], name: str) -> str:
    for candidate in candidates:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    raise SafetyError(f"required system tool is unavailable at a fixed path: {name}")


def _exact_object(value: object, expected: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != expected:
        raise SafetyError(f"{label} has unexpected or missing fields")
    return value


def _catalog_text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 4096:
        raise SafetyError(f"{label} must be a bounded non-empty string")
    if CONTROL_RE.search(value):
        raise SafetyError(f"{label} contains control characters")
    return value


def _catalog_positive_integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise SafetyError(f"{label} must be a positive integer")
    return value


def _parse_attestation(value: object, firmware: str) -> QemuAttestation:
    document = _exact_object(
        value,
        {"passed", "workflowRunId", "workflowRunUrl", "logSha256"},
        f"{firmware} QEMU attestation",
    )
    if document["passed"] is not True:
        raise SafetyError(f"{firmware} QEMU attestation is not passing")
    run_id = _catalog_positive_integer(
        document["workflowRunId"], f"{firmware} workflowRunId"
    )
    run_url = _catalog_text(document["workflowRunUrl"], f"{firmware} workflowRunUrl")
    run_suffix = run_url.removeprefix(TRUSTED_RUN_URL_PREFIX)
    run_component = run_suffix.split("/", 1)[0]
    if (
        not run_url.startswith(TRUSTED_RUN_URL_PREFIX)
        or not run_component.isdigit()
        or int(run_component) != run_id
    ):
        raise SafetyError(f"{firmware} workflow URL is not a KernAid Actions run")
    log_sha256 = _catalog_text(document["logSha256"], f"{firmware} logSha256").lower()
    if not SHA256_RE.fullmatch(log_sha256):
        raise SafetyError(f"{firmware} logSha256 is invalid")
    return QemuAttestation(firmware, run_id, run_url, log_sha256)


def parse_trust_catalog(raw: str) -> TrustCatalog:
    if len(raw.encode("utf-8")) > MAX_CATALOG_BYTES:
        raise SafetyError("official trust catalog exceeded the safety limit")
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        raise SafetyError("official trust catalog is not valid JSON") from error
    document = _exact_object(
        value,
        {"schema", "catalogRevision", "images"},
        "official trust catalog",
    )
    if document["schema"] != TRUST_CATALOG_SCHEMA:
        raise SafetyError("official trust catalog schema is unsupported")
    revision = document["catalogRevision"]
    if isinstance(revision, bool) or not isinstance(revision, int) or revision < 0:
        raise SafetyError("catalogRevision must be a non-negative integer")
    images_value = document["images"]
    if not isinstance(images_value, list):
        raise SafetyError("official trust catalog images must be an array")
    images: list[TrustedImage] = []
    names: set[str] = set()
    digests: set[str] = set()
    for index, entry_value in enumerate(images_value):
        entry = _exact_object(
            entry_value,
            {
                "artifactName",
                "artifactVersion",
                "sha256",
                "bytes",
                "qemuAttestations",
            },
            f"catalog image {index}",
        )
        artifact_name = _catalog_text(entry["artifactName"], "artifactName")
        artifact_version = _catalog_text(entry["artifactVersion"], "artifactVersion")
        digest = _catalog_text(entry["sha256"], "image sha256").lower()
        size = _catalog_positive_integer(entry["bytes"], "image bytes")
        if not ARTIFACT_NAME_RE.fullmatch(artifact_name):
            raise SafetyError("catalog artifactName is not a KernAid Rescue ISO name")
        if not ARTIFACT_VERSION_RE.fullmatch(artifact_version):
            raise SafetyError("catalog artifactVersion is invalid")
        if not SHA256_RE.fullmatch(digest):
            raise SafetyError("catalog image sha256 is invalid")
        qemu = _exact_object(
            entry["qemuAttestations"], {"bios", "uefi"}, "qemuAttestations"
        )
        if artifact_name in names or digest in digests:
            raise SafetyError("official trust catalog contains a duplicate image")
        names.add(artifact_name)
        digests.add(digest)
        images.append(
            TrustedImage(
                artifact_name,
                artifact_version,
                digest,
                size,
                _parse_attestation(qemu["bios"], "bios"),
                _parse_attestation(qemu["uefi"], "uefi"),
            )
        )
    return TrustCatalog(revision, tuple(images))


def _check_root_owned_path(path: str, *, directory: bool) -> None:
    try:
        details = os.lstat(path)
    except OSError as error:
        raise SafetyError(f"cannot inspect installed trust path {path}: {error}") from error
    expected_type = stat.S_ISDIR(details.st_mode) if directory else stat.S_ISREG(details.st_mode)
    if not expected_type or details.st_uid != 0 or stat.S_IMODE(details.st_mode) & 0o022:
        raise SafetyError(
            f"installed trust path must be root-owned and not group/world-writable: {path}"
        )


def load_installed_trust_catalog() -> TrustCatalog:
    script_path = os.path.realpath(__file__)
    catalog_path = os.path.join(os.path.dirname(script_path), TRUST_CATALOG_FILENAME)
    _check_root_owned_path(script_path, directory=False)
    current = os.path.dirname(script_path)
    while True:
        _check_root_owned_path(current, directory=True)
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(catalog_path, flags)
    except OSError as error:
        raise SafetyError(f"cannot open root-owned official trust catalog: {error}") from error
    try:
        details = os.fstat(fd)
        if (
            not stat.S_ISREG(details.st_mode)
            or details.st_uid != 0
            or stat.S_IMODE(details.st_mode) & 0o022
            or details.st_size > MAX_CATALOG_BYTES
        ):
            raise SafetyError("official trust catalog ownership or mode is unsafe")
        chunks: list[bytes] = []
        total = 0
        while total <= MAX_CATALOG_BYTES:
            chunk = os.read(fd, min(65536, MAX_CATALOG_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        raw = b"".join(chunks)
        if len(raw) > MAX_CATALOG_BYTES:
            raise SafetyError("official trust catalog exceeded the safety limit")
        after = os.fstat(fd)
        if (
            details.st_dev,
            details.st_ino,
            details.st_size,
            details.st_mtime_ns,
        ) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise SafetyError("official trust catalog changed while being read")
        try:
            decoded = raw.decode("utf-8", "strict")
        except UnicodeDecodeError as error:
            raise SafetyError("official trust catalog is not UTF-8") from error
        return parse_trust_catalog(decoded)
    finally:
        os.close(fd)


def _safe_text(value: object, field: str, *, allow_empty: bool = True) -> str:
    if value is None:
        text = ""
    elif isinstance(value, str):
        text = value.strip()
    else:
        raise SafetyError(f"lsblk field {field} has an unexpected type")
    if CONTROL_RE.search(text):
        raise SafetyError(f"lsblk field {field} contains control characters")
    if not allow_empty and not text:
        raise SafetyError(f"lsblk field {field} is empty")
    if len(text) > 4096:
        raise SafetyError(f"lsblk field {field} is unreasonably long")
    return text


def _boolean(value: object, field: str) -> bool:
    if value in (True, 1, "1", "true", "True", "yes"):
        return True
    if value in (False, 0, "0", "false", "False", "no", None):
        return False
    raise SafetyError(f"lsblk field {field} is not boolean")


def _size(value: object) -> int:
    if isinstance(value, bool):
        raise SafetyError("lsblk size is not an integer")
    try:
        parsed = int(value)
    except (TypeError, ValueError) as error:
        raise SafetyError("lsblk size is not an integer") from error
    if parsed <= 0:
        raise SafetyError("lsblk reported a non-positive device size")
    return parsed


def _disk_sequence(value: object) -> int | None:
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        raise SafetyError("lsblk disk-seq is not an integer")
    try:
        parsed = int(value)
    except (TypeError, ValueError) as error:
        raise SafetyError("lsblk disk-seq is not an integer") from error
    if parsed <= 0:
        raise SafetyError("lsblk reported a non-positive disk sequence")
    return parsed


def _mountpoints(value: object) -> tuple[str, ...]:
    if value is None:
        return ()
    values: Iterable[object]
    if isinstance(value, list):
        values = value
    elif isinstance(value, str):
        values = (value,)
    else:
        raise SafetyError("lsblk mountpoints has an unexpected type")
    result: list[str] = []
    for item in values:
        if item is None:
            continue
        point = _safe_text(item, "mountpoints")
        if point:
            result.append(point)
    return tuple(result)


class Inventory:
    def __init__(self, devices: Sequence[BlockDevice]):
        if not devices:
            raise SafetyError("lsblk returned no block devices")
        self.devices = tuple(devices)
        self.by_path: dict[str, BlockDevice] = {}
        self.by_kname: dict[str, BlockDevice] = {}
        self.by_major_minor: dict[str, BlockDevice] = {}
        for device in self.devices:
            if device.path in self.by_path:
                raise SafetyError(f"lsblk returned duplicate path {device.path}")
            if device.kname in self.by_kname:
                raise SafetyError(f"lsblk returned duplicate kernel name {device.kname}")
            if device.major_minor in self.by_major_minor:
                raise SafetyError(
                    f"lsblk returned duplicate major:minor {device.major_minor}"
                )
            self.by_path[device.path] = device
            self.by_kname[device.kname] = device
            self.by_major_minor[device.major_minor] = device

        self.children: dict[str, set[str]] = {device.path: set() for device in devices}
        for device in devices:
            if not device.parent_key:
                continue
            parent = self.by_path.get(device.parent_key) or self.by_kname.get(
                device.parent_key
            )
            if parent is not None and parent.path != device.path:
                self.children[parent.path].add(device.path)

    @classmethod
    def from_json(cls, raw: str) -> "Inventory":
        if len(raw.encode("utf-8")) > MAX_LSBLK_OUTPUT:
            raise SafetyError("lsblk output exceeded the safety limit")
        try:
            document = json.loads(raw)
        except json.JSONDecodeError as error:
            raise SafetyError("lsblk did not return valid JSON") from error
        roots = document.get("blockdevices") if isinstance(document, dict) else None
        if not isinstance(roots, list):
            raise SafetyError("lsblk JSON is missing blockdevices")

        devices: list[BlockDevice] = []

        def visit(node: object, inherited_parent: str | None) -> None:
            if not isinstance(node, dict):
                raise SafetyError("lsblk returned a non-object device")
            path = _safe_text(
                node.get("path") or node.get("name"), "path", allow_empty=False
            )
            normalized_path = os.path.normpath(path)
            if not os.path.isabs(path) or not normalized_path.startswith("/dev/"):
                raise SafetyError(f"lsblk returned an unsafe device path: {path}")
            kname = _safe_text(node.get("kname"), "kname", allow_empty=False)
            kind = _safe_text(node.get("type"), "type", allow_empty=False).lower()
            parent_key = _safe_text(node.get("pkname"), "pkname") or inherited_parent
            major_minor = _safe_text(
                node.get("maj:min"), "maj:min", allow_empty=False
            )
            if not MAJ_MIN_RE.fullmatch(major_minor):
                raise SafetyError(f"lsblk returned invalid major:minor: {major_minor}")
            devices.append(
                BlockDevice(
                    path=normalized_path,
                    kname=kname,
                    kind=kind,
                    parent_key=parent_key,
                    removable=_boolean(node.get("rm"), "rm"),
                    read_only=_boolean(node.get("ro"), "ro"),
                    rotational=_boolean(node.get("rota"), "rota"),
                    size=_size(node.get("size")),
                    serial=_safe_text(node.get("serial"), "serial"),
                    model=_safe_text(node.get("model"), "model"),
                    vendor=_safe_text(node.get("vendor"), "vendor"),
                    transport=_safe_text(node.get("tran"), "tran").lower(),
                    subsystems=_safe_text(node.get("subsystems"), "subsystems"),
                    mountpoints=_mountpoints(node.get("mountpoints")),
                    major_minor=major_minor,
                    disk_sequence=_disk_sequence(node.get("disk-seq")),
                )
            )
            children = node.get("children", [])
            if children is None:
                children = []
            if not isinstance(children, list):
                raise SafetyError("lsblk children has an unexpected type")
            for child in children:
                visit(child, kname)

        for root in roots:
            visit(root, None)
        return cls(devices)

    def resolve_explicit(self, supplied_path: str) -> BlockDevice:
        if not supplied_path or not os.path.isabs(supplied_path):
            raise SafetyError("device path must be explicit and absolute")
        if CONTROL_RE.search(supplied_path):
            raise SafetyError("device path contains control characters")
        canonical = os.path.realpath(supplied_path)
        if not canonical.startswith("/dev/"):
            raise SafetyError("resolved device path is outside /dev")
        matches = [
            device
            for device in self.devices
            if os.path.realpath(device.path) == canonical
        ]
        if len(matches) != 1:
            raise SafetyError(
                "device path did not resolve to exactly one lsblk JSON entry"
            )
        return matches[0]

    def descendants(self, root: BlockDevice) -> tuple[BlockDevice, ...]:
        pending = [root.path]
        visited: set[str] = set()
        result: list[BlockDevice] = []
        while pending:
            path = pending.pop()
            if path in visited:
                continue
            visited.add(path)
            device = self.by_path.get(path)
            if device is None:
                continue
            result.append(device)
            pending.extend(sorted(self.children.get(path, ()), reverse=True))
        return tuple(result)


def run_lsblk() -> Inventory:
    lsblk = _fixed_binary(LSBLK_PATHS, "lsblk")
    try:
        result = subprocess.run(
            [
                lsblk,
                "--json",
                "--bytes",
                "--paths",
                "--list",
                "--output",
                LSBLK_COLUMNS,
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
            env=SAFE_ENV,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise SafetyError(f"cannot run lsblk safely: {error}") from error
    if result.returncode != 0:
        detail = result.stderr.strip()[:500]
        raise SafetyError(f"lsblk failed: {detail or 'no diagnostic'}")
    return Inventory.from_json(result.stdout)


def probe_usb_media(candidate: BlockDevice) -> UsbMediaProof:
    udevadm = _fixed_binary(UDEVADM_PATHS, "udevadm")
    try:
        result = subprocess.run(
            [
                udevadm,
                "info",
                "--query=property",
                f"--name={candidate.path}",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
            env=SAFE_ENV,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise SafetyError(f"cannot inspect USB media class with udevadm: {error}") from error
    if result.returncode != 0:
        detail = result.stderr.strip()[:500]
        raise SafetyError(f"udevadm USB probe failed: {detail or 'no diagnostic'}")
    if len(result.stdout.encode("utf-8")) > MAX_PROBE_OUTPUT:
        raise SafetyError("udevadm property output exceeded the safety limit")
    properties: dict[str, str] = {}
    for line in result.stdout.splitlines():
        if not line or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if (
            not re.fullmatch(r"[A-Z0-9_]+", key)
            or CONTROL_RE.search(value)
            or len(value) > 4096
            or key in properties
        ):
            raise SafetyError("udevadm returned malformed or duplicate properties")
        properties[key] = value
    if properties.get("ID_BUS") != "usb":
        raise SafetyError("udev does not identify the target as USB media")
    if properties.get("ID_SERIAL_SHORT") != candidate.serial:
        raise SafetyError("udev serial identity does not match lsblk")
    if not properties.get("ID_PATH"):
        raise SafetyError("udev did not provide a stable physical USB path")
    media_type = properties.get("ID_TYPE")
    if media_type is not None and media_type != "disk":
        raise SafetyError("udev identifies the target as a non-disk USB device")
    if any(properties.get(key) == "1" for key in CARD_READER_PROPERTIES):
        raise SafetyError("USB card readers and removable memory cards are not supported")
    combined_model = " ".join(
        (candidate.vendor, candidate.model, properties.get("ID_MODEL", ""))
    )
    if CARD_READER_MODEL_RE.search(combined_model):
        raise SafetyError("target model appears to be a USB card reader")
    proof_keys = (
        "ID_BUS",
        "ID_TYPE",
        "ID_SERIAL_SHORT",
        "ID_PATH",
        "ID_VENDOR",
        "ID_MODEL",
        *sorted(OPTIONAL_USB_MEDIA_PROPERTIES),
        *sorted(CARD_READER_PROPERTIES),
    )
    return UsbMediaProof(
        tuple((key, properties.get(key, "")) for key in proof_keys)
    )


def _unescape_mountinfo(value: str) -> str:
    def replace(match: re.Match[str]) -> str:
        return chr(int(match.group(1), 8))

    return re.sub(r"\\([0-7]{3})", replace, value)


def parse_mountinfo(raw: str) -> tuple[MountRecord, ...]:
    if len(raw.encode("utf-8")) > MAX_PROC_OUTPUT:
        raise SafetyError("mountinfo exceeded the safety limit")
    records: list[MountRecord] = []
    for line in raw.splitlines():
        fields = line.split()
        if len(fields) < 10 or "-" not in fields:
            raise SafetyError("/proc/self/mountinfo contains a malformed record")
        major_minor = fields[2]
        if not MAJ_MIN_RE.fullmatch(major_minor):
            raise SafetyError("mountinfo contains an invalid major:minor")
        mountpoint = _unescape_mountinfo(fields[4])
        if not os.path.isabs(mountpoint):
            raise SafetyError("mountinfo contains a relative mountpoint")
        records.append(MountRecord(major_minor, os.path.normpath(mountpoint)))
    return tuple(records)


def _read_bounded(path: str, limit: int) -> str:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as error:
        raise SafetyError(f"cannot open {path} safely: {error}") from error
    try:
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(65536, limit + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > limit:
                raise SafetyError(f"{path} exceeded the safety limit")
        return b"".join(chunks).decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise SafetyError(f"{path} is not valid UTF-8") from error
    except OSError as error:
        raise SafetyError(f"cannot read {path} safely: {error}") from error
    finally:
        os.close(fd)


def _read_swaps() -> frozenset[str]:
    raw = _read_bounded("/proc/swaps", MAX_PROC_OUTPUT)
    lines = raw.splitlines()
    if not lines or not lines[0].startswith("Filename"):
        raise SafetyError("/proc/swaps has an unexpected format")
    result: set[str] = set()
    for line in lines[1:]:
        fields = line.split()
        if len(fields) < 5:
            raise SafetyError("/proc/swaps contains a malformed record")
        path = _unescape_mountinfo(fields[0])
        if os.path.isabs(path):
            result.add(os.path.realpath(path))
    return frozenset(result)


def read_host_use(inventory: Inventory) -> HostUse:
    mounts = parse_mountinfo(_read_bounded("/proc/self/mountinfo", MAX_PROC_OUTPUT))
    swaps = _read_swaps()
    holders: set[str] = set()
    for device in inventory.devices:
        holder_dir = f"/sys/dev/block/{device.major_minor}/holders"
        try:
            with os.scandir(holder_dir) as entries:
                if next(entries, None) is not None:
                    holders.add(device.major_minor)
        except FileNotFoundError:
            raise SafetyError(f"sysfs entry disappeared for {device.path}") from None
        except OSError as error:
            raise SafetyError(f"cannot inspect holders for {device.path}: {error}") from error
    return HostUse(mounts, swaps, frozenset(holders))


def _is_within(path: str, mountpoint: str) -> bool:
    if mountpoint == "/":
        return path.startswith("/")
    return path == mountpoint or path.startswith(mountpoint.rstrip("/") + "/")


def backing_major_minor(path: str, mounts: Sequence[MountRecord]) -> str:
    matches = [record for record in mounts if _is_within(path, record.mountpoint)]
    if not matches:
        raise SafetyError(f"cannot determine the backing filesystem for {path}")
    matches.sort(key=lambda record: len(record.mountpoint), reverse=True)
    return matches[0].major_minor


def _is_rescue_mount(path: str) -> bool:
    normalized = os.path.normpath(path)
    return any(_is_within(normalized, prefix) for prefix in RESCUE_MOUNT_PREFIXES)


def validate_candidate(
    inventory: Inventory,
    candidate: BlockDevice,
    image: ImageInfo,
    host_use: HostUse,
    *,
    ci_loop: bool,
) -> None:
    descendants = inventory.descendants(candidate)
    descendant_paths = {os.path.realpath(device.path) for device in descendants}
    descendant_major_minors = {device.major_minor for device in descendants}

    if candidate.kind == "part":
        raise SafetyError("refusing a partition; select the whole removable device")
    if candidate.read_only:
        raise SafetyError("target device is read-only")
    if candidate.disk_sequence is None:
        raise SafetyError("target has no stable kernel disk sequence")
    if candidate.size < image.size:
        raise SafetyError(
            f"target is too small ({candidate.size} bytes for {image.size} bytes)"
        )

    source_major_minor = image.backing_major_minor
    current_source_major_minor = backing_major_minor(image.path, host_use.mounts)
    if current_source_major_minor != source_major_minor:
        raise SafetyError("ISO backing filesystem changed during validation")
    if source_major_minor in descendant_major_minors:
        raise SafetyError("ISO source is stored on the selected target device")

    for device in descendants:
        for mountpoint in device.mountpoints:
            if mountpoint in CRITICAL_MOUNTS:
                raise SafetyError(
                    f"target backs the running root/boot filesystem at {mountpoint}"
                )
            if _is_rescue_mount(mountpoint):
                raise SafetyError(
                    f"target is the mounted Rescue source at {mountpoint}"
                )
            raise SafetyError(
                f"target or descendant {device.path} is mounted at {mountpoint}"
            )

    for record in host_use.mounts:
        if record.major_minor not in descendant_major_minors:
            continue
        if record.mountpoint in CRITICAL_MOUNTS:
            raise SafetyError(
                f"target backs the running root/boot filesystem at {record.mountpoint}"
            )
        if _is_rescue_mount(record.mountpoint):
            raise SafetyError(
                f"target is the mounted Rescue source at {record.mountpoint}"
            )
        raise SafetyError(
            f"target has a mounted descendant at {record.mountpoint}"
        )

    if any(os.path.realpath(path) in descendant_paths for path in host_use.swaps):
        raise SafetyError("target contains active swap")
    if descendant_major_minors.intersection(host_use.holders):
        raise SafetyError("target backs an active device-mapper, md, or stacked device")
    for device in descendants:
        if device is candidate:
            continue
        if device.kind in ACTIVE_STACK_TYPES or device.kind.startswith("raid"):
            raise SafetyError(
                f"target backs active stacked device {device.path} ({device.kind})"
            )

    kernel_name = os.path.basename(candidate.kname)
    virtual_name = (
        kernel_name.startswith("loop")
        or kernel_name.startswith("dm-")
        or kernel_name.startswith("md")
    )
    if ci_loop:
        if candidate.kind != "loop" or not LOOP_PATH_RE.fullmatch(candidate.path):
            raise SafetyError("CI mode is restricted to /dev/loopN disposable devices")
    else:
        if candidate.kind != "disk" or virtual_name:
            raise SafetyError("target must be a whole physical disk, not loop/dm/md")
        if not candidate.removable or candidate.transport != "usb":
            raise SafetyError("default mode accepts only removable USB devices")
        if candidate.rotational:
            raise SafetyError("rotational USB hard drives are not supported")
        if "usb" not in candidate.subsystems.lower().split(":"):
            raise SafetyError("lsblk subsystem ancestry is not USB")
        if CARD_READER_MODEL_RE.search(f"{candidate.vendor} {candidate.model}"):
            raise SafetyError("target model appears to be a USB card reader")
        if not candidate.serial:
            raise SafetyError("physical USB target has no stable serial identity")


def _sha256_fd(fd: int, size: int) -> str:
    digest = hashlib.sha256()
    offset = 0
    while offset < size:
        try:
            chunk = os.pread(fd, min(VERIFY_CHUNK_BYTES, size - offset), offset)
        except OSError as error:
            raise SafetyError(f"cannot read ISO while hashing: {error}") from error
        if not chunk:
            raise SafetyError("ISO became shorter while hashing")
        digest.update(chunk)
        offset += len(chunk)
    return digest.hexdigest()


def _read_iso_region(fd: int, size: int, offset: int, length: int, label: str) -> bytes:
    if offset < 0 or length <= 0 or offset + length > size:
        raise SafetyError(f"ISO {label} points outside the image")
    try:
        result = os.pread(fd, length, offset)
    except OSError as error:
        raise SafetyError(f"cannot inspect ISO {label}: {error}") from error
    if len(result) != length:
        raise SafetyError(f"ISO {label} ended unexpectedly")
    return result


def _iso_region_has_nonzero_bytes(
    fd: int, size: int, offset: int, length: int, label: str
) -> bool:
    if offset < 0 or length <= 0 or offset + length > size:
        raise SafetyError(f"ISO {label} points outside the image")
    inspected = 0
    while inspected < length:
        chunk = _read_iso_region(
            fd,
            size,
            offset + inspected,
            min(VERIFY_CHUNK_BYTES, length - inspected),
            label,
        )
        if any(chunk):
            return True
        inspected += len(chunk)
    return False


def _validate_hybrid_boot_metadata(fd: int, size: int) -> None:
    mbr = _read_iso_region(fd, size, 0, 512, "hybrid MBR")
    if mbr[MBR_SIGNATURE_OFFSET : MBR_SIGNATURE_OFFSET + 2] != MBR_SIGNATURE:
        raise SafetyError(
            "source is ISO9660 but lacks the expected hybrid MBR signature"
        )
    partition_entries = [mbr[446 + index * 16 : 462 + index * 16] for index in range(4)]
    iso_sectors = (size + 511) // 512
    bounded_partition_found = False
    for entry in partition_entries:
        start_sector = int.from_bytes(entry[8:12], "little")
        sector_count = int.from_bytes(entry[12:16], "little")
        if (
            entry[4] != 0
            and sector_count > 0
            and start_sector < iso_sectors
            and sector_count <= iso_sectors - start_sector
        ):
            bounded_partition_found = True
            break
    if not bounded_partition_found:
        raise SafetyError("hybrid MBR contains no bounded partition entry")

    primary_descriptor_found = False
    catalog_lba: int | None = None
    descriptor_count = min(size // ISO_SECTOR_BYTES, 256)
    for sector_number in range(16, descriptor_count):
        descriptor = _read_iso_region(
            fd,
            size,
            sector_number * ISO_SECTOR_BYTES,
            ISO_SECTOR_BYTES,
            "volume descriptor",
        )
        if descriptor[1:6] != ISO9660_MAGIC:
            continue
        if descriptor[0] == 1 and descriptor[6] == 1:
            primary_descriptor_found = True
        if (
            descriptor[0] == 0
            and descriptor[6] == 1
            and descriptor[7:39].rstrip(b"\x00 ") == EL_TORITO_SYSTEM_ID
        ):
            catalog_lba = int.from_bytes(descriptor[71:75], "little")
        if descriptor[0] == 255:
            break
    if not primary_descriptor_found:
        raise SafetyError("ISO has no primary ISO9660 volume descriptor")
    if not catalog_lba:
        raise SafetyError("ISO has no El Torito boot-record descriptor")

    catalog = _read_iso_region(
        fd,
        size,
        catalog_lba * ISO_SECTOR_BYTES,
        ISO_SECTOR_BYTES,
        "El Torito boot catalog",
    )
    validation = catalog[:32]
    if (
        validation[0] != 1
        or validation[30:32] != MBR_SIGNATURE
        or sum(struct.unpack("<16H", validation)) & 0xFFFF
    ):
        raise SafetyError("El Torito validation entry is invalid")

    boot_platforms: set[int] = set()

    def inspect_boot_entry(entry: bytes, platform: int) -> None:
        if entry[0] != 0x88:
            return
        sector_count = int.from_bytes(entry[6:8], "little")
        boot_lba = int.from_bytes(entry[8:12], "little")
        if platform not in (0x00, 0xEF):
            raise SafetyError("El Torito boot entry uses an unsupported platform")
        if sector_count <= 0 or boot_lba <= 0:
            raise SafetyError("El Torito boot entry has zero size or location")
        boot_offset = boot_lba * ISO_SECTOR_BYTES
        boot_size = sector_count * 512
        if not _iso_region_has_nonzero_bytes(
            fd, size, boot_offset, boot_size, "El Torito boot image"
        ):
            raise SafetyError("El Torito boot image contains only zero bytes")
        boot_platforms.add(platform)

    default_platform = validation[1]
    inspect_boot_entry(catalog[32:64], default_platform)
    offset = 64
    while offset + 32 <= len(catalog):
        header = catalog[offset : offset + 32]
        if not any(header):
            break
        if header[0] not in (0x90, 0x91):
            offset += 32
            continue
        section_platform = header[1]
        entry_count = int.from_bytes(header[2:4], "little")
        if entry_count <= 0 or offset + (entry_count + 1) * 32 > len(catalog):
            raise SafetyError("El Torito section header has an invalid entry count")
        for entry_index in range(entry_count):
            entry_offset = offset + (entry_index + 1) * 32
            inspect_boot_entry(catalog[entry_offset : entry_offset + 32], section_platform)
        offset += (entry_count + 1) * 32
        if header[0] == 0x91:
            break
    if boot_platforms != {0x00, 0xEF}:
        raise SafetyError("ISO must contain non-empty BIOS and UEFI El Torito boot images")


def open_verified_image(
    path: str, expected_sha256: str, mounts: Sequence[MountRecord]
) -> tuple[int, ImageInfo]:
    if not os.path.isabs(path):
        raise SafetyError("ISO path must be explicit and absolute")
    if not SHA256_RE.fullmatch(expected_sha256):
        raise SafetyError("--sha256 must be exactly 64 hexadecimal characters")
    canonical = os.path.realpath(path)
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(canonical, flags)
    except OSError as error:
        raise SafetyError(f"cannot open ISO safely: {error}") from error
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise SafetyError("ISO source must be a regular file")
        try:
            fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except OSError as error:
            raise SafetyError(
                f"cannot lock ISO source against cooperative writers: {error}"
            ) from error
        if before.st_size < ISO9660_MAGIC_OFFSET + len(ISO9660_MAGIC):
            raise SafetyError("ISO source is too small to be an ISO9660 image")
        try:
            magic = os.pread(fd, len(ISO9660_MAGIC), ISO9660_MAGIC_OFFSET)
        except OSError as error:
            raise SafetyError(f"cannot inspect ISO volume descriptor: {error}") from error
        if magic != ISO9660_MAGIC:
            raise SafetyError("source does not contain the ISO9660 volume descriptor")
        _validate_hybrid_boot_metadata(fd, before.st_size)
        actual_sha256 = _sha256_fd(fd, before.st_size)
        after = os.fstat(fd)
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        )
        if identity_before != identity_after:
            raise SafetyError("ISO changed while its checksum was being verified")
        if not hmac.compare_digest(actual_sha256, expected_sha256.lower()):
            raise SafetyError(
                f"ISO checksum mismatch: expected {expected_sha256.lower()}, got {actual_sha256}"
            )
        image = ImageInfo(
            path=canonical,
            size=before.st_size,
            sha256=actual_sha256,
            device=before.st_dev,
            inode=before.st_ino,
            mtime_ns=before.st_mtime_ns,
            backing_major_minor=backing_major_minor(canonical, mounts),
        )
        return fd, image
    except Exception:
        os.close(fd)
        raise


def inspect_loop_backing(candidate: BlockDevice, image: ImageInfo) -> LoopBacking:
    losetup = _fixed_binary(LOSETUP_PATHS, "losetup")
    try:
        result = subprocess.run(
            [
                losetup,
                "--json",
                "--list",
                "--output",
                "NAME,BACK-FILE,BACK-INO,BACK-MAJ:MIN,MAJ:MIN",
                candidate.path,
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
            env=SAFE_ENV,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise SafetyError(f"cannot run losetup safely: {error}") from error
    if result.returncode != 0:
        raise SafetyError("cannot inspect disposable loop backing file")
    try:
        document = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise SafetyError("losetup did not return valid JSON") from error
    rows = document.get("loopdevices") if isinstance(document, dict) else None
    if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
        raise SafetyError("losetup did not resolve exactly one loop device")
    row = rows[0]
    name = _safe_text(row.get("name"), "losetup name", allow_empty=False)
    major_minor = _safe_text(
        row.get("maj:min"), "losetup maj:min", allow_empty=False
    )
    backing_raw = _safe_text(
        row.get("back-file"), "losetup back-file", allow_empty=False
    )
    try:
        bound_inode = int(row.get("back-ino"))
    except (TypeError, ValueError) as error:
        raise SafetyError("losetup returned an invalid backing inode") from error
    bound_major_minor = _safe_text(
        row.get("back-maj:min"), "losetup back-maj:min", allow_empty=False
    )
    if bound_inode <= 0 or not MAJ_MIN_RE.fullmatch(bound_major_minor):
        raise SafetyError("losetup returned an invalid backing-file identity")
    if os.path.realpath(name) != os.path.realpath(candidate.path):
        raise SafetyError("losetup resolved a different loop device")
    if major_minor != candidate.major_minor:
        raise SafetyError("loop device major:minor changed")
    if not os.path.isabs(backing_raw) or backing_raw.endswith(" (deleted)"):
        raise SafetyError("loop backing file is not a stable absolute path")
    backing = os.path.realpath(backing_raw)
    if backing != backing_raw:
        raise SafetyError("loop backing file must not be a symlink")
    allowed_roots = (os.path.realpath("/tmp"), os.path.realpath("/var/tmp"))
    if not any(_is_within(backing, root) for root in allowed_roots):
        raise SafetyError("disposable loop backing file must be under /tmp or /var/tmp")
    if not os.path.basename(backing).startswith("kernaid-disposable-"):
        raise SafetyError(
            "disposable loop backing filename must start with kernaid-disposable-"
        )
    try:
        details = os.lstat(backing)
    except OSError as error:
        raise SafetyError(f"cannot inspect loop backing file: {error}") from error
    if not stat.S_ISREG(details.st_mode):
        raise SafetyError("loop backing path is not a regular file")
    file_major_minor = f"{os.major(details.st_dev)}:{os.minor(details.st_dev)}"
    if details.st_ino != bound_inode or file_major_minor != bound_major_minor:
        raise SafetyError("loop device is bound to a different backing-file inode")
    if details.st_nlink != 1:
        raise SafetyError("loop backing file has multiple hard links")
    if details.st_uid != os.geteuid():
        raise SafetyError("loop backing file is not owned by the effective user")
    if stat.S_IMODE(details.st_mode) & 0o077:
        raise SafetyError("loop backing file permissions are not private")
    if details.st_size < candidate.size:
        raise SafetyError("loop backing file is smaller than the loop device")
    if (details.st_dev, details.st_ino) == (image.device, image.inode):
        raise SafetyError("ISO source and disposable loop backing file are identical")
    return LoopBacking(
        path=backing,
        device=details.st_dev,
        inode=details.st_ino,
        size=details.st_size,
        uid=details.st_uid,
        mode=stat.S_IMODE(details.st_mode),
        links=details.st_nlink,
    )


def confirmation_phrase(candidate: BlockDevice) -> str:
    if not candidate.serial:
        raise SafetyError("cannot confirm a physical target without a stable serial")
    return (
        f"ERASE direct-usb-media path={candidate.path} "
        f"serial={json.dumps(candidate.serial, ensure_ascii=True)} "
        f"model={json.dumps(candidate.model, ensure_ascii=True)} size={candidate.size}"
    )


def ci_token(candidate: BlockDevice, backing: LoopBacking) -> str:
    return (
        "KERNAID_CI_DISPOSABLE_LOOP "
        f"path={candidate.path} majmin={candidate.major_minor} size={candidate.size} "
        f"diskseq={candidate.disk_sequence} backing={backing.device}:{backing.inode}"
    )


def ci_fixture_image_token(image: ImageInfo) -> str:
    return (
        "KERNAID_CI_FIXTURE_IMAGE "
        f"sha256={image.sha256} bytes={image.size} boot=bios+uefi"
    )


def authorize_image(
    catalog: TrustCatalog,
    image: ImageInfo,
    *,
    ci_loop: bool,
    fixture_token: str | None,
) -> ImageAuthorization:
    if fixture_token is not None:
        if not ci_loop:
            raise SafetyError("fixture image trust is restricted to disposable CI loops")
        expected = ci_fixture_image_token(image)
        if not hmac.compare_digest(fixture_token, expected):
            raise SafetyError("CI fixture image token did not match the verified image")
        return ImageAuthorization(
            "ci-fixture",
            catalog.revision,
            os.path.basename(image.path),
            "fixture-only",
            None,
            None,
        )
    trusted = catalog.authorize(image)
    return ImageAuthorization(
        "official-catalog",
        catalog.revision,
        trusted.artifact_name,
        trusted.artifact_version,
        trusted.bios,
        trusted.uefi,
    )


def require_confirmation(candidate: BlockDevice, input_stream: TextIO) -> None:
    if not input_stream.isatty():
        raise SafetyError(
            "interactive confirmation requires a terminal; CI may use only the loop mode"
        )
    phrase = confirmation_phrase(candidate)
    print("WARNING: every byte currently stored on this USB target may be lost.", file=sys.stderr)
    print(
        "Udev cannot identify every generic USB card reader. Confirm physically "
        "that this is the direct USB flash drive or portable SSD you intend to erase.",
        file=sys.stderr,
    )
    print(f"Target: {candidate.path}", file=sys.stderr)
    print(f"Serial: {candidate.serial}", file=sys.stderr)
    print(f"Vendor: {candidate.vendor or '<not reported>'}", file=sys.stderr)
    print(f"Model:  {candidate.model or '<not reported>'}", file=sys.stderr)
    print(f"Size:   {candidate.size} bytes", file=sys.stderr)
    print("Type this exact confirmation:", file=sys.stderr)
    print(phrase, file=sys.stderr)
    entered = input_stream.readline()
    if not entered:
        raise SafetyError("confirmation was not provided")
    if entered.rstrip("\r\n") != phrase:
        raise SafetyError(
            "confirmation did not match media acknowledgement, path, serial, model, and size"
        )


def _assert_image_unchanged(fd: int, image: ImageInfo) -> None:
    try:
        details = os.fstat(fd)
    except OSError as error:
        raise SafetyError(f"cannot revalidate ISO descriptor: {error}") from error
    current = (details.st_dev, details.st_ino, details.st_size, details.st_mtime_ns)
    if current != image.identity():
        raise SafetyError("ISO changed after checksum verification")


def _assert_image_path_matches(image: ImageInfo) -> None:
    try:
        details = os.stat(image.path, follow_symlinks=False)
    except OSError as error:
        raise SafetyError(f"ISO path changed after verification: {error}") from error
    current = (details.st_dev, details.st_ino, details.st_size, details.st_mtime_ns)
    if current != image.identity() or not stat.S_ISREG(details.st_mode):
        raise SafetyError("ISO path no longer names the checksum-verified file")


def dd_command(dd_path: str, size: int) -> list[str]:
    if size <= 0:
        raise ValueError("copy size must be positive")
    return [
        dd_path,
        f"bs={COPY_CHUNK_BYTES}",
        f"count={size}",
        "iflag=count_bytes,fullblock",
        "conv=fsync,notrunc",
        "status=progress",
    ]


def _ioctl_value(fd: int, request: int, format_code: str, label: str) -> int:
    buffer = bytearray(struct.calcsize(format_code))
    try:
        fcntl.ioctl(fd, request, buffer, True)
    except OSError as error:
        raise SafetyError(f"cannot read {label} from the target descriptor: {error}") from error
    return int(struct.unpack(format_code, buffer)[0])


def _open_target(candidate: BlockDevice) -> int:
    try:
        path_details = os.lstat(candidate.path)
    except OSError as error:
        raise SafetyError(f"cannot inspect target device node: {error}") from error
    if not stat.S_ISBLK(path_details.st_mode):
        raise SafetyError("target path is no longer a block device")
    flags = os.O_RDWR | os.O_CLOEXEC | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(candidate.path, flags)
    except OSError as error:
        raise SafetyError(
            f"cannot exclusively open target device (it may be in use): {error}"
        ) from error
    try:
        details = os.fstat(fd)
        actual_major_minor = f"{os.major(details.st_rdev)}:{os.minor(details.st_rdev)}"
        if (
            not stat.S_ISBLK(details.st_mode)
            or actual_major_minor != candidate.major_minor
        ):
            raise SafetyError("opened target identity does not match the validated device")
        descriptor_size = _ioctl_value(fd, BLKGETSIZE64, "=Q", "BLKGETSIZE64")
        descriptor_read_only = _ioctl_value(fd, BLKROGET, "=I", "BLKROGET")
        descriptor_disk_sequence = _ioctl_value(
            fd, BLKGETDISKSEQ, "=Q", "BLKGETDISKSEQ"
        )
        if descriptor_size != candidate.size:
            raise SafetyError("target capacity changed between lsblk and exclusive open")
        if descriptor_read_only != 0:
            raise SafetyError("exclusively opened target is read-only")
        if descriptor_disk_sequence != candidate.disk_sequence:
            raise SafetyError("target disk sequence changed after confirmation")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _reject_stale_tail_metadata(
    target_fd: int, candidate: BlockDevice, image: ImageInfo
) -> None:
    if candidate.size <= image.size:
        return
    logical_sector = _ioctl_value(target_fd, BLKSSZGET, "=I", "BLKSSZGET")
    if (
        logical_sector < 512
        or logical_sector > 4096
        or logical_sector & (logical_sector - 1)
    ):
        raise SafetyError("target reported an unsafe logical sector size")
    last_sector_offset = candidate.size - logical_sector
    if last_sector_offset < image.size:
        return
    try:
        last_sector = os.pread(target_fd, logical_sector, last_sector_offset)
    except OSError as error:
        raise SafetyError(f"cannot inspect the target tail safely: {error}") from error
    if len(last_sector) != logical_sector:
        raise SafetyError("target ended while inspecting its final logical sector")
    if last_sector.startswith(b"EFI PART"):
        raise SafetyError(
            "target has a backup GPT beyond the ISO; refusing to leave conflicting "
            "tail metadata"
        )


def _parse_wipefs_offset(value: object, label: str) -> int:
    if isinstance(value, bool):
        raise SafetyError(f"wipefs {label} is not an integer")
    try:
        parsed = int(value, 0) if isinstance(value, str) else int(value)
    except (TypeError, ValueError) as error:
        raise SafetyError(f"wipefs {label} is not an integer") from error
    if parsed < 0:
        raise SafetyError(f"wipefs {label} is negative")
    return parsed


def _reject_recognized_tail_signatures(
    target_fd: int, candidate: BlockDevice, image: ImageInfo
) -> None:
    wipefs = _fixed_binary(WIPEFS_PATHS, "wipefs")
    descriptor_path = f"/proc/self/fd/{target_fd}"
    try:
        result = subprocess.run(
            [
                wipefs,
                "--json",
                "--no-act",
                "--lock=no",
                "--output",
                "OFFSET,LENGTH,TYPE",
                descriptor_path,
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
            env=SAFE_ENV,
            close_fds=True,
            pass_fds=(target_fd,),
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise SafetyError(f"cannot run wipefs read-only probe safely: {error}") from error
    if result.returncode != 0:
        detail = result.stderr.strip()[:500]
        raise SafetyError(f"wipefs read-only probe failed: {detail or 'no diagnostic'}")
    if len(result.stdout.encode("utf-8")) > MAX_PROBE_OUTPUT:
        raise SafetyError("wipefs JSON exceeded the safety limit")
    try:
        document = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise SafetyError("wipefs did not return valid JSON") from error
    signatures = document.get("signatures") if isinstance(document, dict) else None
    if not isinstance(signatures, list):
        raise SafetyError("wipefs JSON is missing signatures")
    for signature_value in signatures:
        signature = _exact_object(
            signature_value, {"offset", "length", "type"}, "wipefs signature"
        )
        offset = _parse_wipefs_offset(signature["offset"], "offset")
        length = _parse_wipefs_offset(signature["length"], "length")
        signature_type = _catalog_text(signature["type"], "wipefs signature type")
        if length <= 0 or offset + length > candidate.size:
            raise SafetyError("wipefs reported an out-of-range signature")
        if offset >= image.size or offset + length > image.size:
            raise SafetyError(
                f"recognized {signature_type} signature remains beyond the ISO "
                f"at byte {offset}; refusing without erasing it"
            )


def _stop_dd_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    previous_mask: set[signal.Signals] | None = None
    if hasattr(signal, "pthread_sigmask"):
        previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, MANAGED_SIGNALS)
    try:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=CHILD_TERMINATE_TIMEOUT_SECONDS)
            return
        except subprocess.TimeoutExpired:
            pass
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=CHILD_TERMINATE_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired as error:
            raise WriteError(
                "dd process group could not be stopped within the deadline"
            ) from error
    finally:
        if previous_mask is not None:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)


def _run_bounded_dd(
    dd: str,
    source_fd: int,
    target_fd: int,
    image_size: int,
    state: OperationState,
    target_path: str,
) -> None:
    state.advance(WritePhase.WRITE_MAY_HAVE_STARTED, target_path)
    process: subprocess.Popen[bytes] | None = None
    pending_signals: list[int] = []
    previous_handlers: dict[signal.Signals, object] = {}

    def defer_signal(signal_number: int, _frame: object) -> None:
        if not pending_signals:
            pending_signals.append(signal_number)

    try:
        if not hasattr(signal, "pthread_sigmask"):
            raise WriteError("managed signal transitions are unavailable")
        previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, MANAGED_SIGNALS)
        try:
            if set(previous_mask).intersection(MANAGED_SIGNALS):
                raise WriteError("a managed termination signal was already blocked")
            for managed_signal in MANAGED_SIGNALS:
                previous_handlers[managed_signal] = signal.getsignal(managed_signal)
                signal.signal(managed_signal, defer_signal)
        except BaseException:
            for managed_signal, previous_handler in previous_handlers.items():
                signal.signal(managed_signal, previous_handler)
            raise
        finally:
            # Handler changes are atomic with respect to managed signals.  They
            # are unblocked before Popen, so dd never inherits the transition
            # mask that protects this parent process.
            signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
        try:
            if pending_signals:
                raise OperationInterrupted(pending_signals[0])
            process = subprocess.Popen(
                dd_command(dd, image_size),
                stdin=source_fd,
                stdout=target_fd,
                env=SAFE_ENV,
                close_fds=True,
                start_new_session=True,
            )
        finally:
            restore_mask = signal.pthread_sigmask(signal.SIG_BLOCK, MANAGED_SIGNALS)
            try:
                for managed_signal, previous_handler in previous_handlers.items():
                    signal.signal(managed_signal, previous_handler)
            finally:
                # Any signal received while handlers were restored is delivered
                # only after `process` has been assigned, so the outer handler
                # can supervise the complete dd process group.
                signal.pthread_sigmask(signal.SIG_SETMASK, restore_mask)
        if pending_signals:
            raise OperationInterrupted(pending_signals[0])
        return_code = process.wait()
    except BaseException as error:
        if process is not None:
            try:
                _stop_dd_process(process)
            except BaseException as stop_error:
                raise WriteError(
                    "dd was interrupted and its process group could not be supervised safely"
                ) from stop_error
        raise
    if return_code != 0:
        raise WriteError(f"bounded dd failed with exit status {return_code}")
    state.advance(WritePhase.DD_COMPLETED, target_path)


def write_and_verify(
    source_fd: int,
    image: ImageInfo,
    candidate: BlockDevice,
    prewrite_check: Callable[[], None],
    state: OperationState,
) -> str:
    dd = _fixed_binary(DD_PATHS, "dd")
    _assert_image_unchanged(source_fd, image)
    target_fd = _open_target(candidate)
    try:
        _reject_recognized_tail_signatures(target_fd, candidate, image)
        _reject_stale_tail_metadata(target_fd, candidate, image)
        prewrite_check()
        _assert_image_unchanged(source_fd, image)
        print("Rechecking the ISO checksum immediately before writing...", file=sys.stderr)
        if not hmac.compare_digest(_sha256_fd(source_fd, image.size), image.sha256):
            raise SafetyError("ISO checksum changed immediately before the write")
        os.lseek(source_fd, 0, os.SEEK_SET)
        os.lseek(target_fd, 0, os.SEEK_SET)
        print(
            f"Writing exactly {image.size} bytes to {candidate.path}...",
            file=sys.stderr,
        )
        _run_bounded_dd(
            dd, source_fd, target_fd, image.size, state, candidate.path
        )
        try:
            os.fsync(target_fd)
            os.sync()
        except OSError as error:
            raise WriteError(f"device sync failed: {error}") from error
        try:
            fcntl.ioctl(target_fd, BLKFLSBUF)
        except OSError as error:
            raise WriteError(
                f"could not flush the target block cache before verification: {error}"
            ) from error
        state.advance(WritePhase.CACHE_FLUSHED, candidate.path)

        print("Verifying the complete written prefix byte-for-byte...", file=sys.stderr)
        source_digest = hashlib.sha256()
        target_digest = hashlib.sha256()
        offset = 0
        while offset < image.size:
            amount = min(VERIFY_CHUNK_BYTES, image.size - offset)
            try:
                source = os.pread(source_fd, amount, offset)
                target = os.pread(target_fd, amount, offset)
            except OSError as error:
                raise WriteError(
                    f"read failed during verification at byte offset {offset}: {error}"
                ) from error
            if len(source) != amount or len(target) != amount:
                raise WriteError(
                    f"short read during verification at byte offset {offset}"
                )
            source_digest.update(source)
            target_digest.update(target)
            if not hmac.compare_digest(source, target):
                raise WriteError(
                    f"byte-for-byte verification failed at byte offset {offset}"
                )
            offset += amount
        if source_digest.hexdigest() != image.sha256:
            raise WriteError("ISO source changed during post-write verification")
        verified = target_digest.hexdigest()
        if not hmac.compare_digest(verified, image.sha256):
            raise WriteError("written prefix checksum does not match the verified ISO")
        state.advance(WritePhase.PREFIX_VERIFIED, candidate.path)
        return verified
    finally:
        os.close(target_fd)


def make_report(
    candidate: BlockDevice,
    image: ImageInfo,
    verified_sha256: str,
    ci_loop: bool,
    authorization: ImageAuthorization,
    usb_proof: UsbMediaProof | None,
) -> Mapping[str, object]:
    qemu_attestations: dict[str, object] | None = None
    if authorization.bios is not None and authorization.uefi is not None:
        qemu_attestations = {
            attestation.firmware: {
                "workflowRunId": attestation.workflow_run_id,
                "workflowRunUrl": attestation.workflow_run_url,
                "logSha256": attestation.log_sha256,
            }
            for attestation in (authorization.bios, authorization.uefi)
        }
    if ci_loop:
        if usb_proof is not None:
            raise WriteError("CI loop report unexpectedly contains physical USB proof")
        rendered_usb_proof: Mapping[str, object] = {
            "applicable": False,
            "reason": "disposable loop test mode",
        }
    else:
        if usb_proof is None:
            raise WriteError("verified physical target report is missing udev proof")
        properties = dict(usb_proof.properties)
        id_path = properties.get("ID_PATH", "")
        if (
            properties.get("ID_BUS") != "usb"
            or properties.get("ID_SERIAL_SHORT") != candidate.serial
            or not id_path
        ):
            raise WriteError("verified physical target report has invalid udev proof")
        rendered_usb_proof = {
            "applicable": True,
            "verified": True,
            "probe": "udevadm info --query=property",
            "idPathVerified": True,
            "idPath": id_path,
            "knownCardReaderMarkersRejected": True,
            "operatorConfirmedDirectUsbMedia": True,
            "properties": properties,
        }
    return {
        "schema": "dev.kernaid.make-device-report.v1",
        "status": "verified",
        "completedAt": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
        "reportAuthenticity": {
            "status": "unsigned-unauthenticated",
            "signed": False,
            "authenticated": False,
            "warning": (
                "This local JSON report is unsigned and unauthenticated; retain it "
                "only as operational evidence, not as a cryptographic receipt."
            ),
        },
        "mode": "ci-disposable-loop" if ci_loop else "interactive-removable-usb",
        "source": {
            "path": image.path,
            "bytes": image.size,
            "sha256": image.sha256,
            "checksumBinding": "operator-supplied-sha256",
            "releaseSignatureVerified": False,
        },
        "trust": {
            "mode": authorization.mode,
            "catalogRevision": authorization.catalog_revision,
            "artifactName": authorization.artifact_name,
            "artifactVersion": authorization.artifact_version,
            "qemuAttestations": qemu_attestations,
        },
        "target": {
            "path": candidate.path,
            "majorMinor": candidate.major_minor,
            "diskSequence": candidate.disk_sequence,
            "serial": candidate.serial or None,
            "capacityBytes": candidate.size,
            "bytesWritten": image.size,
            "udevProof": rendered_usb_proof,
        },
        "verification": {
            "method": "byte-for-byte-prefix-after-BLKFLSBUF",
            "verifiedBytes": image.size,
            "sha256": verified_sha256,
        },
        "residualTail": {
            "policy": "preserved",
            "startsAtByte": image.size,
            "bytes": candidate.size - image.size,
            "backupGptChecked": True,
            "recognizedSignaturesCheckedWith": (
                "wipefs --no-act via inherited exclusive target descriptor"
            ),
            "warning": (
                "Bytes beyond the ISO were not erased; old data or unrecognized "
                "signatures may remain recoverable."
            ),
        },
        "vault": {
            "created": False,
            "reason": (
                "Vault provisioning is intentionally deferred until partitioning, "
                "key enrollment, crash recovery, and rollback are implemented safely."
            ),
        },
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Safely write a catalog-trusted KernAid Rescue ISO to one USB device."
        )
    )
    parser.add_argument("--iso", required=True, help="absolute path to the Rescue ISO")
    parser.add_argument("--sha256", required=True, help="expected ISO SHA-256 digest")
    parser.add_argument(
        "--device", required=True, help="explicit absolute whole-device path, e.g. /dev/sdb"
    )
    parser.add_argument(
        "--ci-disposable-loop-token",
        metavar="TOKEN",
        help="non-interactive mode, restricted to a private disposable /dev/loopN",
    )
    parser.add_argument(
        "--ci-fixture-image-token",
        metavar="TOKEN",
        help="trust an artificial boot fixture only when writing a disposable CI loop",
    )
    return parser


def execute(
    args: argparse.Namespace,
    state: OperationState,
    input_stream: TextIO = sys.stdin,
) -> Mapping[str, object]:
    if sys.platform != "linux":
        raise SafetyError("make-device is supported only on Linux")
    if not sys.flags.isolated:
        raise SafetyError("invoke the installed executable with /usr/bin/python3 -I")
    if os.geteuid() != 0:
        raise SafetyError("run as root so the selected block device can be opened exclusively")

    ci_mode = args.ci_disposable_loop_token is not None
    if args.ci_fixture_image_token is not None and not ci_mode:
        raise SafetyError("fixture image trust cannot be used for a physical device")
    catalog = load_installed_trust_catalog()
    if not catalog.images and args.ci_fixture_image_token is None:
        raise SafetyError(
            "official KernAid trust catalog contains no released ISO hashes"
        )
    initial_inventory = run_lsblk()
    initial_host = read_host_use(initial_inventory)
    print("Verifying the ISO format and SHA-256 checksum...", file=sys.stderr)
    source_fd, image = open_verified_image(args.iso, args.sha256, initial_host.mounts)
    try:
        initial_candidate = initial_inventory.resolve_explicit(args.device)
        validate_candidate(
            initial_inventory,
            initial_candidate,
            image,
            initial_host,
            ci_loop=ci_mode,
        )
        initial_usb_proof = None if ci_mode else probe_usb_media(initial_candidate)

        initial_backing: LoopBacking | None = None
        if ci_mode:
            initial_backing = inspect_loop_backing(initial_candidate, image)
            expected_token = ci_token(initial_candidate, initial_backing)
            if not hmac.compare_digest(args.ci_disposable_loop_token, expected_token):
                raise SafetyError("CI disposable-loop token did not match the exact target")
        authorization = authorize_image(
            catalog,
            image,
            ci_loop=ci_mode,
            fixture_token=args.ci_fixture_image_token,
        )
        if not ci_mode:
            require_confirmation(initial_candidate, input_stream)

        final_inventory = run_lsblk()
        final_host = read_host_use(final_inventory)
        final_candidate = final_inventory.resolve_explicit(args.device)
        validate_candidate(
            final_inventory,
            final_candidate,
            image,
            final_host,
            ci_loop=ci_mode,
        )
        if final_candidate.fingerprint() != initial_candidate.fingerprint():
            raise SafetyError("target identity changed after confirmation")
        if not ci_mode and probe_usb_media(final_candidate) != initial_usb_proof:
            raise SafetyError("USB physical identity changed after confirmation")
        _assert_image_path_matches(image)
        if ci_mode:
            assert initial_backing is not None
            final_backing = inspect_loop_backing(final_candidate, image)
            if final_backing.fingerprint() != initial_backing.fingerprint():
                raise SafetyError("disposable loop backing file changed after validation")
            if not hmac.compare_digest(
                args.ci_disposable_loop_token, ci_token(final_candidate, final_backing)
            ):
                raise SafetyError("CI disposable-loop token became stale")

        _assert_image_unchanged(source_fd, image)

        def prewrite_check() -> None:
            open_inventory = run_lsblk()
            open_host = read_host_use(open_inventory)
            open_candidate = open_inventory.resolve_explicit(args.device)
            validate_candidate(
                open_inventory,
                open_candidate,
                image,
                open_host,
                ci_loop=ci_mode,
            )
            if open_candidate.fingerprint() != final_candidate.fingerprint():
                raise SafetyError("target identity changed while it was being opened")
            if not ci_mode and probe_usb_media(open_candidate) != initial_usb_proof:
                raise SafetyError("USB physical identity changed before the write")
            _assert_image_path_matches(image)
            if ci_mode:
                assert initial_backing is not None
                open_backing = inspect_loop_backing(open_candidate, image)
                if open_backing.fingerprint() != initial_backing.fingerprint():
                    raise SafetyError("disposable loop backing changed before the write")
                if not hmac.compare_digest(
                    args.ci_disposable_loop_token,
                    ci_token(open_candidate, open_backing),
                ):
                    raise SafetyError("CI disposable-loop token became stale")

        verified_sha256 = write_and_verify(
            source_fd, image, final_candidate, prewrite_check, state
        )
        return make_report(
            final_candidate,
            image,
            verified_sha256,
            ci_mode,
            authorization,
            initial_usb_proof,
        )
    finally:
        os.close(source_fd)


def _error_text(error: BaseException) -> str:
    if isinstance(error, OperationInterrupted):
        try:
            return f"received {signal.Signals(error.signal_number).name}"
        except ValueError:
            return f"received signal {error.signal_number}"
    if isinstance(error, KeyboardInterrupt):
        return "received keyboard interrupt"
    return str(error).strip() or error.__class__.__name__


def _emit_failure(state: OperationState, error: BaseException) -> int:
    detail = _error_text(error)
    if state.target_overwritten_or_partial:
        message = (
            "FAILED: target overwritten-or-partial; do not boot or reuse it "
            f"until reflashed ({state.target_path}, phase={state.phase.name}): {detail}"
        )
        exit_code = 4
    elif isinstance(error, (SafetyError, OperationInterrupted, KeyboardInterrupt)):
        message = f"REFUSED: target was not written: {detail}"
        exit_code = 3
    else:
        message = f"FAILED before target write: {detail}"
        exit_code = 5
    try:
        os.write(2, (message + "\n").encode("utf-8", "replace"))
    except OSError:
        pass
    return exit_code


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    state = OperationState()
    previous_handlers: dict[signal.Signals, object] = {}
    exit_code = 5
    try:
        for managed_signal in MANAGED_SIGNALS:
            previous_handlers[managed_signal] = signal.getsignal(managed_signal)
            signal.signal(managed_signal, _signal_interrupted)
        try:
            report = execute(args, state)
            rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
            sys.stdout.write(rendered)
            sys.stdout.flush()
            state.advance(WritePhase.REPORT_EMITTED, state.target_path or "<unknown>")
            exit_code = 0
        except BaseException as error:
            exit_code = _emit_failure(state, error)
    except BaseException as error:
        exit_code = _emit_failure(state, error)
    finally:
        try:
            if (
                state.target_overwritten_or_partial
                and __name__ == "__main__"
                and hasattr(signal, "pthread_sigmask")
            ):
                # The CLI exits immediately after main returns.  Keeping these
                # signals blocked closes the final handler-restoration window.
                signal.pthread_sigmask(signal.SIG_BLOCK, MANAGED_SIGNALS)
            for managed_signal, previous_handler in previous_handlers.items():
                signal.signal(managed_signal, previous_handler)
        except BaseException as error:
            exit_code = _emit_failure(state, error)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
