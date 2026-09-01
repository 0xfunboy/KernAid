#!/usr/bin/env python3
"""Bounded PTY controller for the disposable Rescue repair qualification."""

from __future__ import annotations

import argparse
import importlib.util
import os
import re
import signal
import stat
import subprocess
import sys
import textwrap
import time
from pathlib import Path
from typing import Sequence


TOOLS = Path(__file__).resolve().parent
LIFECYCLE_PATH = TOOLS / "qemu-vault-lifecycle-pty.py"
SPEC = importlib.util.spec_from_file_location("kernaid_qemu_lifecycle", LIFECYCLE_PATH)
if SPEC is None or SPEC.loader is None:
    raise SystemExit(2)
LIFECYCLE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = LIFECYCLE
SPEC.loader.exec_module(LIFECYCLE)

FAILURE_PREFIX = "KERNAID_QEMU_REPAIR_CANDIDATE_FAILURE_V1"
ATTESTATION_PREFIX = "KERNAID_QEMU_REPAIR_CANDIDATE_GUEST_V1"
TARGET_NODE = "kernaid_repair_target"
TARGET_QDEV = "/machine/peripheral/kernaid_repair_target_device/virtio-backend"
FAULT_CREDENTIAL = "kernaid-repair-fault"
FAULT_TERMINATE_AFTER_PENDING = "terminate-after-pending-v1"
FAULT_FAIL_AFTER_INSTALLED = "fail-after-installed-v1"
FAILURE_SCENARIOS = (
    "stale-target",
    "cancel",
    "backup-tamper",
    "repaird-termination",
    "auto-restore",
)
PACK_QUALIFICATION_SCENARIOS = (
    "crypttab-lifecycle",
    "ext4-apply",
    "resolver-link-apply",
)
TAMPER_HELPER_FAILURE_CODES = frozenset(
    {
        "arguments-invalid",
        "backup-invalid",
        "caller-invalid",
        "cleanup-failed",
        "input-invalid",
        "key-invalid",
        "loop-collision",
        "loop-discovery-failed",
        "loop-invalid",
        "mapper-collision",
        "mapper-discovery-failed",
        "mapper-open-failed",
        "tamper-unverified",
        "tool-failed",
        "tool-missing",
        "unexpected",
    }
)
TAMPER_HELPER_FAILURE = re.compile(
    rb"KERNAID_QEMU_REPAIR_VAULT_TAMPER_FAILURE_V1 code=([a-z0-9-]+)\n"
)
OVMF_ROOTS = (Path("/usr/share/OVMF"), Path("/usr/share/edk2"))
# The Rescue Vault may legitimately consume its 120-second stop budget while
# systemd is also draining live-media and device jobs under TCG.  Keep clean
# ACPI shutdown mandatory, but do not misclassify that bounded shutdown as a
# repair failure merely because it exceeds the generic 180-second VM budget.
REPAIR_ACPI_SHUTDOWN_SECONDS = 300.0
# Provisioning the disposable 32 GB repair medium must prove the future Vault
# extent is zero before the first write.  Under two-vCPU TCG both the interval
# before the confirmation prompt and the post-confirmation proof can exceed the
# generic lifecycle budgets. Keep both waits repair-specific and bounded.
REPAIR_FIRSTBOOT_PROMPT_TIMEOUT_SECONDS = 1200.0
REPAIR_FIRSTBOOT_RESULT_TIMEOUT_SECONDS = 1800.0
REPAIR_FIRSTBOOT_PROMPT_SETTLE_SECONDS = 1.0
REPAIR_QMP_KEY_SETTLE_SECONDS = 0.1
REPAIR_QMP_INPUT_TIMEOUT_SECONDS = 30.0

EXECUTE_STATE_CLASSIFIER_SOURCE = r'''
def execute_state_checkpoint(value):
    fallback="execute-state"
    if not isinstance(value,dict):
        return fallback
    detail=value.get("detail")
    required={"kind","terminalOutcome","reservationId","transactionBindingSha256","rebootRequired","prepareFailureStage"}
    if not isinstance(detail,dict) or set(detail)!=required or detail.get("kind")!="terminal" or detail.get("prepareFailureStage") is not None:
        return fallback
    reservation=detail.get("reservationId")
    binding=detail.get("transactionBindingSha256")
    valid_reservation=isinstance(reservation,str) and reservation.startswith("B-") and len(reservation)==34 and all(character in "0123456789abcdef" for character in reservation[2:])
    valid_binding=isinstance(binding,str) and binding.startswith("sha256:") and len(binding)==71 and all(character in "0123456789abcdef" for character in binding[7:])
    has_transaction=valid_reservation and valid_binding
    no_transaction=reservation is None and binding is None
    state=value.get("state")
    outcome=detail.get("terminalOutcome")
    reboot=detail.get("rebootRequired")
    if state=="restored" and outcome=="closed-before-unchanged" and reboot is False and has_transaction:
        return "execute-state-closed-before-unchanged"
    if state=="restored" and outcome=="closed-before-restored" and reboot is False and has_transaction:
        return "execute-state-closed-before-restored"
    if state=="manual-reconciliation-required" and outcome=="manual-reconciliation-required" and reboot is True and (has_transaction or no_transaction):
        return "execute-state-manual-reconciliation-required"
    if state=="failed" and outcome=="failed" and reboot is False and no_transaction:
        return "execute-state-failed"
    return fallback
'''


class ClosedParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        del message
        raise LIFECYCLE.ClosedFailure("arguments", "invalid")


def parser() -> ClosedParser:
    value = ClosedParser(add_help=False, allow_abbrev=False)
    value.add_argument("--qemu", required=True)
    value.add_argument("--qmp-socket", type=Path, required=True)
    value.add_argument("--firmware", choices=("bios", "uefi"), required=True)
    value.add_argument(
        "--scenario",
        choices=(
            "apply",
            "rollback",
            "interrupt-reconcile",
            "provision-base",
            *FAILURE_SCENARIOS,
            *PACK_QUALIFICATION_SCENARIOS,
        ),
        required=True,
    )
    value.add_argument("--already-provisioned", action="store_true")
    value.add_argument("--ovmf-code", type=Path)
    value.add_argument("--ovmf-vars-template", type=Path)
    value.add_argument("--vault-key-fd", type=int, required=True)
    value.add_argument("--login-credential-fd", type=int, required=True)
    value.add_argument("--before-sha256", required=True)
    value.add_argument("--after-sha256", required=True)
    value.add_argument("--media-path", type=Path)
    value.add_argument("--vault-key-path", type=Path)
    value.add_argument("--tamper-helper", type=Path)
    value.add_argument("--timeout", type=float, default=900.0)
    value.add_argument("qemu_args", nargs=argparse.REMAINDER)
    return value


def trusted_firmware_file(path: Path) -> Path:
    """Resolve one immutable, root-owned system firmware file."""

    try:
        resolved = path.resolve(strict=True)
        metadata = resolved.stat()
    except OSError as error:
        raise LIFECYCLE.ClosedFailure("firmware", "file-invalid") from error
    if not any(resolved.is_relative_to(root) for root in OVMF_ROOTS):
        raise LIFECYCLE.ClosedFailure("firmware", "path-invalid")
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or metadata.st_mode & 0o022
    ):
        raise LIFECYCLE.ClosedFailure("firmware", "file-untrusted")
    current = resolved.parent
    while True:
        try:
            parent = current.stat()
        except OSError as error:
            raise LIFECYCLE.ClosedFailure("firmware", "parent-invalid") from error
        if (
            not stat.S_ISDIR(parent.st_mode)
            or parent.st_uid != 0
            or parent.st_gid != 0
            or parent.st_mode & 0o022
        ):
            raise LIFECYCLE.ClosedFailure("firmware", "parent-untrusted")
        if current == Path("/"):
            break
        current = current.parent
    return resolved


def copy_fresh_ovmf_vars(source: Path, destination: Path) -> None:
    """Create one private VARS store without following a destination link."""

    if os.path.lexists(destination):
        raise LIFECYCLE.ClosedFailure("firmware", "vars-reuse")
    source_fd = destination_fd = -1
    try:
        source_fd = os.open(source, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        before = os.fstat(source_fd)
        destination_fd = os.open(
            destination,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_CLOEXEC
            | os.O_NOFOLLOW,
            0o600,
        )
        copied = 0
        while True:
            chunk = os.read(source_fd, 1024 * 1024)
            if not chunk:
                break
            view = memoryview(chunk)
            offset = 0
            try:
                while offset < len(view):
                    written = os.write(destination_fd, view[offset:])
                    if written <= 0:
                        raise OSError()
                    offset += written
            finally:
                view.release()
            copied += len(chunk)
        os.fsync(destination_fd)
        after = os.fstat(source_fd)
        copied_metadata = os.fstat(destination_fd)
        if (
            (before.st_dev, before.st_ino, before.st_size)
            != (after.st_dev, after.st_ino, after.st_size)
            or copied != before.st_size
            or copied_metadata.st_size != before.st_size
            or stat.S_IMODE(copied_metadata.st_mode) != 0o600
            or copied_metadata.st_uid != os.geteuid()
        ):
            raise LIFECYCLE.ClosedFailure("firmware", "vars-copy-invalid")
    except LIFECYCLE.ClosedFailure:
        raise
    except OSError as error:
        raise LIFECYCLE.ClosedFailure("firmware", "vars-copy-failed") from error
    finally:
        for descriptor in (destination_fd, source_fd):
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass


def qemu_args_for_boot(
    base: Sequence[str],
    firmware: str,
    boot: int,
    qmp_socket: Path,
    ovmf_code: Path | None,
    ovmf_vars_template: Path | None,
) -> list[str]:
    if any(
        argument in {"-bios", "-pflash"} or "if=pflash" in argument
        for argument in base
    ):
        raise LIFECYCLE.ClosedFailure("arguments", "firmware-conflict")
    result = list(base)
    if firmware == "uefi":
        if ovmf_code is None or ovmf_vars_template is None:
            raise LIFECYCLE.ClosedFailure("firmware", "pair-missing")
        destination = qmp_socket.parent / f"OVMF_VARS.repair-boot-{boot}.fd"
        copy_fresh_ovmf_vars(ovmf_vars_template, destination)
        result.extend(
            (
                "-drive",
                f"if=pflash,format=raw,readonly=on,unit=0,file={ovmf_code}",
                "-drive",
                f"if=pflash,format=raw,unit=1,file={destination}",
            )
        )
    elif ovmf_code is not None or ovmf_vars_template is not None:
        raise LIFECYCLE.ClosedFailure("firmware", "pair-forbidden")
    return result


def qualification_fault(base: Sequence[str], work_directory: Path) -> str | None:
    """Read the one closed QEMU credential token, if supplied."""

    needle = f"opt/io.systemd.credentials/{FAULT_CREDENTIAL}"
    prefix = f"name=opt/io.systemd.credentials/{FAULT_CREDENTIAL},file="
    related = [argument for argument in base if needle in argument]
    if not related:
        return None
    if len(related) != 1 or not related[0].startswith(prefix):
        raise LIFECYCLE.ClosedFailure("arguments", "fault-credential-invalid")
    path = Path(related[0][len(prefix) :])
    descriptor = -1
    try:
        resolved = path.resolve(strict=True)
        expected = (work_directory / "qualification-fault").resolve(strict=True)
        if path != resolved or resolved != expected:
            raise LIFECYCLE.ClosedFailure("arguments", "fault-credential-invalid")
        parent = resolved.parent.stat()
        descriptor = os.open(
            resolved, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
        )
        before = os.fstat(descriptor)
        value = os.read(descriptor, 65)
        trailing = os.read(descriptor, 1)
        after = os.fstat(descriptor)
    except OSError as error:
        raise LIFECYCLE.ClosedFailure("arguments", "fault-credential-invalid") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    identity = lambda metadata: (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )
    if (
        not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != os.geteuid()
        or stat.S_IMODE(parent.st_mode) != 0o700
        or not stat.S_ISREG(before.st_mode)
        or before.st_uid != os.geteuid()
        or stat.S_IMODE(before.st_mode) != 0o600
        or before.st_nlink != 1
        or identity(before) != identity(after)
        or trailing
        or len(value) != before.st_size
        or value not in {
            FAULT_TERMINATE_AFTER_PENDING.encode("ascii"),
            FAULT_FAIL_AFTER_INSTALLED.encode("ascii"),
        }
    ):
        raise LIFECYCLE.ClosedFailure("arguments", "fault-credential-invalid")
    return value.decode("ascii")


def repair_source(
    before_sha256: str,
    after_sha256: str,
    *,
    interrupt_arm: bool = False,
    emit_receipt: bool = False,
) -> bytes:
    # This source is fixed by the qualification controller. It supplies only
    # opaque target claims and the exact typed approval accepted by production.
    checkpoints = ",".join(
        repr(checkpoint)
        for checkpoint in LIFECYCLE.PROVIDER_PROOF_REPAIR_CHECKPOINTS
    )
    stage = "repair-interrupt-arm" if interrupt_arm else "repair-apply"
    source = f'''import hashlib,http.client,json,os,secrets,subprocess,sys,time
HOST="127.0.0.1:4173"
ORIGIN="http://127.0.0.1:4173"
API="kernaid.dev/rescue-repair-service/v1alpha1"
BEFORE={before_sha256!r}
AFTER={after_sha256!r}
INTERRUPT_ARM={interrupt_arm!r}
EMIT_RECEIPT={emit_receipt!r}
STAGE={stage!r}
CHECKPOINTS=({checkpoints},)
{EXECUTE_STATE_CLASSIFIER_SOURCE}
counter=0
checkpoint="service-ready"
def capability_unit_checkpoint():
    try:
        result=subprocess.run(["systemctl","show","--all","--property=Id,Result,ActiveState,SubState,ExecMainCode,ExecMainStatus","kernaid-rescue-target-capability@*.service"],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=5,check=False)
        if result.returncode!=0 or len(result.stdout)>8192:
            return "prepare-target-capability-unavailable-unit-other"
        blocks=[block for block in result.stdout.decode("ascii").strip().split("\\n\\n") if block]
        if not blocks:
            return "prepare-target-capability-unavailable-unit-collected"
        if len(blocks)!=1:
            return "prepare-target-capability-unavailable-unit-other"
        values={{}}
        for line in blocks[0].splitlines():
            key,separator,value=line.partition("=")
            if not separator or key in values:
                return "prepare-target-capability-unavailable-unit-other"
            values[key]=value
        if values.get("Result")=="timeout":
            return "prepare-target-capability-unavailable-unit-runtime-max"
        if values.get("ActiveState")=="failed":
            return "prepare-target-capability-unavailable-unit-failed"
        return "prepare-target-capability-unavailable-unit-other"
    except BaseException:
        return "prepare-target-capability-unavailable-unit-other"
def execution_error_checkpoint():
    prefix="KERNAID_RESCUE_REPAIR_EXECUTION_FAILURE_V1 stage="
    stages={{prefix+stage for stage in ("approval-proof","approval-binding","approval-admission","approval-authorize","approval-cancel","authority","target","lock","timeout","vault","write","mutation","recovery")}}
    deadline=time.monotonic()+2
    while time.monotonic()<deadline:
        try:
            result=subprocess.run(["systemctl","show","--property=StatusText","--value","kernaid-rescue-repaird.service"],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=1,check=False)
            status=result.stdout.decode("ascii").strip()
            if result.returncode==0 and len(result.stdout)<=192 and status in stages:
                return "execute-error-"+status[len(prefix):]
        except BaseException:
            pass
        time.sleep(.1)
    return "execute-state-failed"
def fail(value):
    if value=="prepare-target-capability-unavailable":
        value=capability_unit_checkpoint()
    if value not in CHECKPOINTS:
        sys.exit(46)
    sys.stdout.write("KERNAID_QEMU_PROVIDER_PROOF_FAILURE_V1 stage="+STAGE+" checkpoint="+value+"\\n")
    sys.exit(45)
def request_id():
    global counter
    counter+=1
    return "R-00000000-0000-0000-0000-"+format(counter,"012x")
def call(path,body=None,timeout=25):
    encoded=None if body is None else json.dumps(body,ensure_ascii=True,separators=(",",":")).encode("ascii")
    headers={{"Host":HOST}}
    if encoded is not None:
        headers.update({{"Origin":ORIGIN,"Content-Type":"application/json"}})
    connection=http.client.HTTPConnection("127.0.0.1",4173,timeout=timeout)
    connection.request("GET" if encoded is None else "POST",path,body=encoded,headers=headers)
    response=connection.getresponse()
    payload=response.read(65537)
    status=response.status
    connection.close()
    if len(payload)>65536:
        raise RuntimeError()
    return status,json.loads(payload)
def repair(body):
    status,value=call("/api/rescue/repair",body)
    if status!=200 or value.get("outcome")!="ok":
        raise RuntimeError()
    return value
def status_until(states,deadline):
    while time.monotonic()<deadline:
        value=repair({{"apiVersion":API,"requestId":request_id(),"operation":"repair.status"}})
        if value.get("state") in states:
            return value
        time.sleep(.2)
    raise RuntimeError()
try:
    deadline=time.monotonic()+360
    while True:
        try:
            initial=repair({{"apiVersion":API,"requestId":request_id(),"operation":"repair.status"}})
            if initial.get("state")=="idle":
                break
        except BaseException:
            pass
        if time.monotonic()>=deadline:
            raise RuntimeError()
        time.sleep(.5)
    checkpoint="inventory-ready"
    while True:
        try:
            code,inventory=call("/api/inventory")
            code2,scan=call("/api/rescue/installed-targets")
            if code==200 and code2==200:
                break
        except BaseException:
            pass
        if time.monotonic()>=deadline:
            raise RuntimeError()
        time.sleep(.5)
    checkpoint="target-count"
    candidates=[item for item in scan["candidates"] if item.get("osFamilyHint")=="linux" and item.get("requiresUnlock") is False]
    if len(candidates)!=1:
        raise RuntimeError()
    candidate=candidates[0]
    checkpoint="target-selection"
    selection_body={{"scanFingerprint":scan["scanFingerprint"],"targetId":candidate["targetId"]}}
    selected_code,selected=call("/api/rescue/select-installed-target",selection_body)
    inspected_code,inspected=call("/api/rescue/inspect-installed-target",selection_body)
    if selected_code!=200 or selected.get("target")!=candidate or inspected_code!=200 or inspected.get("status")!="installed-os-content-inspected" or inspected.get("target",{{}}).get("filesystem")!="ext4":
        raise RuntimeError()
    checkpoint="target-identity"
    identity=[item for item in inventory if "hostname" in item.get("collector","") or "block.inventory" in item.get("collector","") or item.get("collector","").endswith((".disks",".system",".storage.identity"))]
    if not identity or any(item.get("success") is not True or item.get("truncated") is True for item in identity):
        raise RuntimeError()
    canonical="\\0".join(item["collector"]+"\\0"+item["output"] for item in identity)
    runtime="sha256:"+hashlib.sha256(canonical.encode()).hexdigest()
    candidate_json=json.dumps(candidate,ensure_ascii=True,sort_keys=True,separators=(",",":"))
    material="\\0".join(("kernaid-rescue-observe-target-v1",runtime,scan["scanFingerprint"],candidate["targetId"],candidate_json))
    target_fingerprint="sha256:"+hashlib.sha256(material.encode()).hexdigest()
    checkpoint="prepare-submit"
    prepare=repair({{"apiVersion":API,"requestId":request_id(),"operation":"repair.fstab.prepare","target":{{"scanFingerprint":scan["scanFingerprint"],"targetFingerprint":target_fingerprint,"targetId":candidate["targetId"]}}}})
    if prepare.get("state") not in ("preparing","prepared"):
        raise RuntimeError()
    checkpoint="prepare-terminal"
    prepared=prepare if prepare.get("state")=="prepared" else status_until({{"prepared","failed","restored","manual-reconciliation-required"}},deadline)
    checkpoint="prepare-state"
    if prepared.get("state")!="prepared":
        checkpoint={{
            "target-capability-timed-out":"prepare-target-capability-timed-out",
            "target-capability-identity-changed":"prepare-target-capability-identity-changed",
            "target-capability-unavailable":"prepare-target-capability-unavailable",
            "observation-preview":"prepare-observation-preview",
            "vault-reserve":"prepare-vault-reserve",
            "admission-internal":"prepare-admission-internal",
        }}.get(prepared.get("detail",{{}}).get("prepareFailureStage"),checkpoint)
        raise RuntimeError()
    checkpoint="prepare-contract"
    detail=prepared.get("detail",{{}})
    if detail.get("actionId")!="linux.fstab.disable-missing-uuid.v1" or detail.get("beforeSha256")!=BEFORE or detail.get("afterSha256")!=AFTER or detail.get("backup")!={{"state":"reserved","vaultDistinct":True}} or detail.get("confirmationRequired")!="DISABILITA VOCE FSTAB":
        raise RuntimeError()
    approval={{"apiVersion":API,"requestId":request_id(),"operation":"repair.fstab.approve","preparedId":detail["preparedId"],"sessionId":detail["sessionId"],"planId":detail["planId"],"planHash":detail["planHash"],"approvalId":"A-"+secrets.token_hex(16),"approvalSequence":detail["nextApprovalSequence"],"typedConfirmation":"DISABILITA VOCE FSTAB"}}
    checkpoint="approve-submit"
    if INTERRUPT_ARM:
        child=os.fork()
        if child==0:
            try:
                os.setsid()
                null=os.open("/dev/null",os.O_RDWR|os.O_CLOEXEC)
                for descriptor in (0,1,2):
                    os.dup2(null,descriptor)
                if null>2:
                    os.close(null)
                time.sleep(2)
                approved=repair(approval)
                if approved.get("state") not in ("executing","succeeded","restored","failed","manual-reconciliation-required","cancelled"):
                    os._exit(47)
                os._exit(0)
            except BaseException:
                os._exit(47)
    else:
        approved=repair(approval)
        if approved.get("state") not in ("executing","succeeded","restored","failed","manual-reconciliation-required","cancelled"):
            raise RuntimeError()
        checkpoint="execute-terminal"
        terminal=approved if approved.get("state")!="executing" else status_until({{"succeeded","restored","failed","manual-reconciliation-required","cancelled"}},deadline)
        checkpoint="execute-state"
        if terminal.get("state")!="succeeded":
            checkpoint=execute_state_checkpoint(terminal)
            if checkpoint=="execute-state-failed" or checkpoint in (
                "execute-state-closed-before-unchanged",
                "execute-state-closed-before-restored",
            ):
                diagnostic=execution_error_checkpoint()
                if diagnostic.startswith("execute-error-") or checkpoint=="execute-state-failed":
                    checkpoint=diagnostic
            raise RuntimeError()
        checkpoint="execute-contract"
        terminal_detail=terminal.get("detail",{{}})
        if terminal_detail.get("terminalOutcome")!="committed" or not isinstance(terminal_detail.get("reservationId"),str) or not isinstance(terminal_detail.get("transactionBindingSha256"),str):
            raise RuntimeError()
except BaseException:
    fail(checkpoint)
if EMIT_RECEIPT:
    sys.stdout.write("KERNAID_QEMU_REPAIR_RECEIPT_V1 reservation_id="+terminal_detail["reservationId"]+" binding="+terminal_detail["transactionBindingSha256"]+"\\n")
else:
    sys.stdout.write("KERNAID_QEMU_PROVIDER_PROOF_V1 stage="+STAGE+" result=true\\n")
'''
    return textwrap.dedent(source).encode("ascii")


def pack_qualification_source(
    scenario: str,
    before_sha256: str,
    after_sha256: str,
) -> bytes:
    """Return one closed exact-image proof for an additional repair pack."""

    configurations = {
        "crypttab-lifecycle": {
            "kind": "crypttab-prepared",
            "prepare": "repair.crypttab.prepare",
            "approve": "repair.crypttab.approve",
            "action": "linux.crypttab.disable-missing-uuid.v1",
            "resource": "rescue:selected-linux-root:etc/crypttab",
            "risk": "R2",
            "confirmation": "DISABILITA VOCE CRYPTTAB",
            "expected_before": before_sha256,
            "expected_after": after_sha256,
        },
        "ext4-apply": {
            "kind": "ext4-fsck-prepared",
            "prepare": "repair.ext4.prepare",
            "approve": "repair.ext4.approve",
            "action": "linux.ext4.fsck-preen-with-undo.v1",
            "resource": "rescue:selected-linux-filesystem:ext4",
            "risk": "R3",
            "confirmation": "REPAIR EXT4 OFFLINE",
            "expected_before": None,
            "expected_after": None,
        },
        "resolver-link-apply": {
            "kind": "resolver-link-prepared",
            "prepare": "repair.resolver-link.prepare",
            "approve": "repair.resolver-link.approve",
            "action": "linux.network.restore-resolver-link.v1",
            "resource": "rescue:selected-linux-root:etc/resolver-link",
            "risk": "R2",
            "confirmation": "RESTORE RESOLVER LINK",
            "expected_before": before_sha256,
            "expected_after": after_sha256,
        },
    }
    try:
        configuration = configurations[scenario]
    except KeyError as error:
        raise ValueError("unsupported pack qualification scenario") from error
    for digest in (before_sha256, after_sha256):
        if re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None:
            raise ValueError("invalid pack qualification digest")
    if before_sha256 == after_sha256:
        raise ValueError("pack qualification digests must be distinct")

    source = r'''import hashlib,http.client,json,re,secrets,sys,time
HOST="127.0.0.1:4173"
ORIGIN="http://127.0.0.1:4173"
API="kernaid.dev/rescue-repair-service/v1alpha1"
ROLLBACK_API="kernaid.dev/rescue-repair-service/v1alpha2"
SCENARIO=__SCENARIO__
KIND=__KIND__
PREPARE=__PREPARE__
APPROVE=__APPROVE__
ACTION=__ACTION__
RESOURCE=__RESOURCE__
RISK=__RISK__
CONFIRMATION=__CONFIRMATION__
EXPECTED_BEFORE=__EXPECTED_BEFORE__
EXPECTED_AFTER=__EXPECTED_AFTER__
counter=0
def fail():
    sys.exit(46)
def request_id():
    global counter
    counter+=1
    return "R-40000000-0000-0000-0000-"+format(counter,"012x")
def valid_hex_id(value,prefix):
    return isinstance(value,str) and len(value)==len(prefix)+32 and value.startswith(prefix) and all(character in "0123456789abcdef" for character in value[len(prefix):])
def valid_hash(value):
    return isinstance(value,str) and re.fullmatch(r"sha256:[0-9a-f]{64}",value) is not None
def exchange(path,body=None,timeout=25):
    encoded=None if body is None else json.dumps(body,ensure_ascii=True,separators=(",",":")).encode("ascii")
    headers={"Host":HOST}
    if encoded is not None:
        headers.update({"Origin":ORIGIN,"Content-Type":"application/json"})
    connection=http.client.HTTPConnection("127.0.0.1",4173,timeout=timeout)
    try:
        connection.request("GET" if encoded is None else "POST",path,body=encoded,headers=headers)
        response=connection.getresponse()
        payload=response.read(65537)
        status=response.status
    finally:
        connection.close()
    if len(payload)>65536:
        raise RuntimeError()
    return status,json.loads(payload)
def repair(api,operation,extra=None):
    body={"apiVersion":api,"requestId":request_id(),"operation":operation}
    if extra is not None:
        body.update(extra)
    status,value=exchange("/api/rescue/repair",body)
    keys={"apiVersion","requestId","operation","outcome","stateVersion","state","detail"}
    if status!=200 or not isinstance(value,dict) or set(value)!=keys or value.get("apiVersion")!=api or value.get("requestId")!=body["requestId"] or value.get("operation")!=operation or value.get("outcome")!="ok" or isinstance(value.get("stateVersion"),bool) or not isinstance(value.get("stateVersion"),int):
        raise RuntimeError()
    return value
def wait(api,operation,states,deadline):
    while time.monotonic()<deadline:
        value=repair(api,operation)
        if value.get("state") in states:
            return value
        time.sleep(.2)
    raise RuntimeError()
def terminal(value,state,outcome,reservation=None,binding=None):
    detail=value.get("detail")
    keys={"kind","terminalOutcome","reservationId","transactionBindingSha256","rebootRequired","prepareFailureStage"}
    return value.get("state")==state and isinstance(detail,dict) and set(detail)==keys and detail.get("kind")=="terminal" and detail.get("terminalOutcome")==outcome and detail.get("rebootRequired") is False and detail.get("prepareFailureStage") is None and valid_hex_id(detail.get("reservationId"),"B-") and valid_hash(detail.get("transactionBindingSha256")) and (reservation is None or detail.get("reservationId")==reservation) and (binding is None or detail.get("transactionBindingSha256")==binding)
deadline=time.monotonic()+600
try:
    while True:
        try:
            initial=repair(API,"repair.status")
            if initial.get("state")=="idle":
                break
        except BaseException:
            pass
        if time.monotonic()>=deadline:
            raise RuntimeError()
        time.sleep(.25)
    while True:
        try:
            inventory_code,inventory=exchange("/api/inventory")
            scan_code,scan=exchange("/api/rescue/installed-targets")
            if inventory_code==200 and scan_code==200:
                break
        except BaseException:
            pass
        if time.monotonic()>=deadline:
            raise RuntimeError()
        time.sleep(.25)
    candidates=[item for item in scan["candidates"] if item.get("osFamilyHint")=="linux" and item.get("requiresUnlock") is False]
    if len(candidates)!=1:
        raise RuntimeError()
    candidate=candidates[0]
    selection={"scanFingerprint":scan["scanFingerprint"],"targetId":candidate["targetId"]}
    selected_code,selected=exchange("/api/rescue/select-installed-target",selection)
    inspected_code,inspected=exchange("/api/rescue/inspect-installed-target",selection)
    if selected_code!=200 or selected.get("target")!=candidate or inspected_code!=200 or inspected.get("status")!="installed-os-content-inspected" or inspected.get("target",{}).get("filesystem")!="ext4":
        raise RuntimeError()
    identity=[item for item in inventory if "hostname" in item.get("collector","") or "block.inventory" in item.get("collector","") or item.get("collector","").endswith((".disks",".system",".storage.identity"))]
    if not identity or any(item.get("success") is not True or item.get("truncated") is True for item in identity):
        raise RuntimeError()
    canonical="\0".join(item["collector"]+"\0"+item["output"] for item in identity)
    runtime="sha256:"+hashlib.sha256(canonical.encode()).hexdigest()
    candidate_json=json.dumps(candidate,ensure_ascii=True,sort_keys=True,separators=(",",":"))
    material="\0".join(("kernaid-rescue-observe-target-v1",runtime,scan["scanFingerprint"],candidate["targetId"],candidate_json))
    target_fingerprint="sha256:"+hashlib.sha256(material.encode()).hexdigest()
    target={"scanFingerprint":scan["scanFingerprint"],"targetFingerprint":target_fingerprint,"targetId":candidate["targetId"]}
    prepared=repair(API,PREPARE,{"target":target})
    if prepared.get("state")=="preparing":
        prepared=wait(API,"repair.status",{"prepared","failed","restored","manual-reconciliation-required"},deadline)
    detail=prepared.get("detail")
    prepared_keys={"kind","preparedId","sessionId","planId","planHash","targetFingerprint","beforeSha256","afterSha256","diffSha256","resourceId","backupLocator","actionId","risk","backup","nextApprovalSequence","confirmationRequired"}
    if prepared.get("state")!="prepared" or not isinstance(detail,dict) or set(detail)!=prepared_keys or detail.get("kind")!=KIND or not valid_hex_id(detail.get("preparedId"),"Q-") or not valid_hex_id(detail.get("sessionId"),"S-") or not valid_hex_id(detail.get("planId"),"P-") or not all(valid_hash(detail.get(field)) for field in ("planHash","targetFingerprint","beforeSha256","afterSha256","diffSha256")) or detail.get("targetFingerprint")!=target_fingerprint or detail.get("beforeSha256")==detail.get("afterSha256") or detail.get("resourceId")!=RESOURCE or not isinstance(detail.get("backupLocator"),str) or re.fullmatch(r"vault://repair/B-[0-9a-f]{32}",detail["backupLocator"]) is None or detail.get("actionId")!=ACTION or detail.get("risk")!=RISK or detail.get("backup")!={"state":"reserved","vaultDistinct":True} or detail.get("nextApprovalSequence")!=1 or detail.get("confirmationRequired")!=CONFIRMATION:
        raise RuntimeError()
    if EXPECTED_BEFORE is not None and detail.get("beforeSha256")!=EXPECTED_BEFORE:
        raise RuntimeError()
    if EXPECTED_AFTER is not None and detail.get("afterSha256")!=EXPECTED_AFTER:
        raise RuntimeError()
    source_reservation=detail["backupLocator"].removeprefix("vault://repair/")
    apply_approval="A-"+secrets.token_hex(16)
    approved=repair(API,APPROVE,{"preparedId":detail["preparedId"],"sessionId":detail["sessionId"],"planId":detail["planId"],"planHash":detail["planHash"],"approvalId":apply_approval,"approvalSequence":detail["nextApprovalSequence"],"typedConfirmation":CONFIRMATION})
    if approved.get("state")=="executing":
        approved=wait(API,"repair.status",{"succeeded","restored","failed","manual-reconciliation-required","cancelled"},deadline)
    if not terminal(approved,"succeeded","committed",source_reservation):
        raise RuntimeError()
    receipt={"reservationId":approved["detail"]["reservationId"],"transactionBindingSha256":approved["detail"]["transactionBindingSha256"]}
    if SCENARIO=="crypttab-lifecycle":
        rollback=repair(ROLLBACK_API,"repair.crypttab.rollback.prepare",{"source":receipt})
        if rollback.get("state")=="preparing":
            rollback=wait(ROLLBACK_API,"repair.crypttab.rollback.status",{"prepared","succeeded","failed","restored","manual-reconciliation-required"},deadline)
        item=rollback.get("detail")
        rollback_keys={"kind","preparedId","rollbackId","sessionId","planId","planHash","targetFingerprint","source","resourceId","backupLocator","actionId","risk","nextApprovalSequence","confirmationRequired"}
        if rollback.get("state")!="prepared" or not isinstance(item,dict) or set(item)!=rollback_keys or item.get("kind")!="crypttab-rollback-prepared" or not valid_hex_id(item.get("preparedId"),"Q-") or not valid_hex_id(item.get("rollbackId"),"RB-") or not valid_hex_id(item.get("sessionId"),"S-") or not valid_hex_id(item.get("planId"),"P-") or not valid_hash(item.get("planHash")) or item.get("targetFingerprint")!=target_fingerprint or item.get("source")!=receipt or item.get("resourceId")!=RESOURCE or item.get("backupLocator")!="vault://repair/"+receipt["reservationId"] or item.get("actionId")!="linux.crypttab.disable-missing-source.v1" or item.get("risk")!="R2" or item.get("nextApprovalSequence")!=2 or item.get("confirmationRequired")!="RIPRISTINA CRYPTTAB ORIGINALE":
            raise RuntimeError()
        rollback_approval="A-"+secrets.token_hex(16)
        while rollback_approval==apply_approval:
            rollback_approval="A-"+secrets.token_hex(16)
        rolled=repair(ROLLBACK_API,"repair.crypttab.rollback.approve",{"preparedId":item["preparedId"],"rollbackId":item["rollbackId"],"sessionId":item["sessionId"],"planId":item["planId"],"planHash":item["planHash"],"source":receipt,"approvalId":rollback_approval,"approvalSequence":item["nextApprovalSequence"],"typedConfirmation":item["confirmationRequired"]})
        if rolled.get("state")=="executing":
            rolled=wait(ROLLBACK_API,"repair.crypttab.rollback.status",{"restored","failed","manual-reconciliation-required","cancelled"},deadline)
        if not terminal(rolled,"restored","rolled-back-original",receipt["reservationId"],receipt["transactionBindingSha256"]):
            raise RuntimeError()
except BaseException:
    fail()
sys.stdout.write("KERNAID_QEMU_PROVIDER_PROOF_V1 stage=repair-"+SCENARIO+" result=true\n")
'''
    replacements = {
        "__SCENARIO__": repr(scenario),
        "__KIND__": repr(configuration["kind"]),
        "__PREPARE__": repr(configuration["prepare"]),
        "__APPROVE__": repr(configuration["approve"]),
        "__ACTION__": repr(configuration["action"]),
        "__RESOURCE__": repr(configuration["resource"]),
        "__RISK__": repr(configuration["risk"]),
        "__CONFIRMATION__": repr(configuration["confirmation"]),
        "__EXPECTED_BEFORE__": repr(configuration["expected_before"]),
        "__EXPECTED_AFTER__": repr(configuration["expected_after"]),
    }
    for needle, replacement in replacements.items():
        source = source.replace(needle, replacement)
    encoded = textwrap.dedent(source).encode("ascii")
    if len(encoded) > 16 * 1024:
        raise ValueError("pack qualification source exceeds guest proof bound")
    return encoded


def failure_path_source(mode: str, before_sha256: str, after_sha256: str) -> bytes:
    """Return one source-fixed proof for a no-write or injected failure path."""

    if mode not in {
        "stale-target",
        "cancel",
        "repaird-termination",
        "auto-restore",
    }:
        raise ValueError("unsupported failure mode")
    source = r'''import hashlib,http.client,json,secrets,subprocess,sys,time
HOST="127.0.0.1:4173"
ORIGIN="http://127.0.0.1:4173"
API="kernaid.dev/rescue-repair-service/v1alpha1"
MODE=__MODE__
BEFORE=__BEFORE__
AFTER=__AFTER__
counter=0
def request_id():
    global counter
    counter+=1
    return "R-30000000-0000-0000-0000-"+format(counter,"012x")
def valid_id(value,prefix):
    return isinstance(value,str) and value.startswith(prefix) and len(value)==len(prefix)+32 and all(character in "0123456789abcdef" for character in value[len(prefix):])
def valid_hash(value):
    return isinstance(value,str) and value.startswith("sha256:") and len(value)==71 and all(character in "0123456789abcdef" for character in value[7:])
def exchange(path,body=None,timeout=25):
    encoded=None if body is None else json.dumps(body,ensure_ascii=True,separators=(",",":")).encode("ascii")
    headers={"Host":HOST}
    if encoded is not None:
        headers.update({"Origin":ORIGIN,"Content-Type":"application/json"})
    connection=http.client.HTTPConnection("127.0.0.1",4173,timeout=timeout)
    try:
        connection.request("GET" if encoded is None else "POST",path,body=encoded,headers=headers)
        response=connection.getresponse()
        payload=response.read(65537)
        status=response.status
    finally:
        connection.close()
    if len(payload)>65536:
        raise RuntimeError()
    return status,json.loads(payload)
def repair(operation,extra=None):
    request={"apiVersion":API,"requestId":request_id(),"operation":operation}
    if extra is not None:
        request.update(extra)
    status,value=exchange("/api/rescue/repair",request)
    if status!=200 or not isinstance(value,dict) or value.get("outcome")!="ok" or value.get("operation")!=operation or value.get("requestId")!=request["requestId"]:
        raise RuntimeError()
    return value
def wait(states,deadline):
    while time.monotonic()<deadline:
        try:
            value=repair("repair.status")
            if value.get("state") in states:
                return value
        except BaseException:
            pass
        time.sleep(.2)
    raise RuntimeError()
def terminal(value,state,outcome,transaction,prepare_stage=None):
    detail=value.get("detail")
    keys={"kind","terminalOutcome","reservationId","transactionBindingSha256","rebootRequired","prepareFailureStage"}
    if value.get("state")!=state or not isinstance(detail,dict) or set(detail)!=keys or detail.get("kind")!="terminal" or detail.get("terminalOutcome")!=outcome or detail.get("rebootRequired") is not False or detail.get("prepareFailureStage")!=prepare_stage:
        return False
    has_transaction=valid_id(detail.get("reservationId"),"B-") and valid_hash(detail.get("transactionBindingSha256"))
    no_transaction=detail.get("reservationId") is None and detail.get("transactionBindingSha256") is None
    return has_transaction if transaction else no_transaction
def repaird_pid():
    result=subprocess.run(["systemctl","show","--property=MainPID","--value","kernaid-rescue-repaird.service"],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=5,check=False)
    text=result.stdout.decode("ascii").strip()
    if result.returncode!=0 or not text.isdigit() or int(text)<=1:
        raise RuntimeError()
    return int(text)
def mutation_diagnostic(deadline):
    expected="KERNAID_RESCUE_REPAIR_EXECUTION_FAILURE_V1 stage=mutation"
    while time.monotonic()<deadline:
        result=subprocess.run(["systemctl","show","--property=StatusText","--value","kernaid-rescue-repaird.service"],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=5,check=False)
        if result.returncode==0 and len(result.stdout)<=192 and result.stdout.decode("ascii").strip()==expected:
            return True
        time.sleep(.1)
    return False
deadline=time.monotonic()+420
try:
    while True:
        try:
            initial=repair("repair.status")
            if initial.get("state")=="idle":
                break
        except BaseException:
            pass
        if time.monotonic()>=deadline:
            raise RuntimeError()
        time.sleep(.25)
    while True:
        try:
            inventory_code,inventory=exchange("/api/inventory")
            scan_code,scan=exchange("/api/rescue/installed-targets")
            if inventory_code==200 and scan_code==200:
                break
        except BaseException:
            pass
        if time.monotonic()>=deadline:
            raise RuntimeError()
        time.sleep(.25)
    candidates=[item for item in scan["candidates"] if item.get("osFamilyHint")=="linux" and item.get("requiresUnlock") is False]
    if len(candidates)!=1:
        raise RuntimeError()
    candidate=candidates[0]
    selection={"scanFingerprint":scan["scanFingerprint"],"targetId":candidate["targetId"]}
    selected_code,selected=exchange("/api/rescue/select-installed-target",selection)
    inspected_code,inspected=exchange("/api/rescue/inspect-installed-target",selection)
    if selected_code!=200 or selected.get("target")!=candidate or inspected_code!=200 or inspected.get("status")!="installed-os-content-inspected" or inspected.get("target",{}).get("filesystem")!="ext4":
        raise RuntimeError()
    identity=[item for item in inventory if "hostname" in item.get("collector","") or "block.inventory" in item.get("collector","") or item.get("collector","").endswith((".disks",".system",".storage.identity"))]
    if not identity or any(item.get("success") is not True or item.get("truncated") is True for item in identity):
        raise RuntimeError()
    canonical="\0".join(item["collector"]+"\0"+item["output"] for item in identity)
    runtime="sha256:"+hashlib.sha256(canonical.encode()).hexdigest()
    candidate_json=json.dumps(candidate,ensure_ascii=True,sort_keys=True,separators=(",",":"))
    material="\0".join(("kernaid-rescue-observe-target-v1",runtime,scan["scanFingerprint"],candidate["targetId"],candidate_json))
    target_fingerprint="sha256:"+hashlib.sha256(material.encode()).hexdigest()
    if MODE=="stale-target":
        target_fingerprint=target_fingerprint[:-1]+("0" if target_fingerprint[-1]!="0" else "1")
    prepared=repair("repair.fstab.prepare",{"target":{"scanFingerprint":scan["scanFingerprint"],"targetFingerprint":target_fingerprint,"targetId":candidate["targetId"]}})
    if MODE=="stale-target":
        if prepared.get("state")=="preparing":
            prepared=wait({"failed","restored","manual-reconciliation-required"},deadline)
        if not terminal(prepared,"failed","failed",False,"target-capability-identity-changed"):
            raise RuntimeError()
    else:
        if prepared.get("state")=="preparing":
            prepared=wait({"prepared","failed","restored","manual-reconciliation-required"},deadline)
        detail=prepared.get("detail")
        keys={"kind","preparedId","sessionId","planId","planHash","targetFingerprint","beforeSha256","afterSha256","diffSha256","resourceId","backupLocator","actionId","risk","backup","nextApprovalSequence","confirmationRequired"}
        if prepared.get("state")!="prepared" or not isinstance(detail,dict) or set(detail)!=keys or detail.get("kind")!="fstab-prepared" or detail.get("targetFingerprint")!=target_fingerprint or detail.get("beforeSha256")!=BEFORE or detail.get("afterSha256")!=AFTER or detail.get("backup")!={"state":"reserved","vaultDistinct":True} or detail.get("confirmationRequired")!="DISABILITA VOCE FSTAB" or not valid_id(detail.get("preparedId"),"Q-") or not valid_hash(detail.get("planHash")):
            raise RuntimeError()
        if MODE=="cancel":
            cancelled=repair("repair.fstab.cancel",{"preparedId":detail["preparedId"],"planHash":detail["planHash"]})
            if cancelled.get("state")=="executing":
                cancelled=wait({"cancelled","failed","restored","manual-reconciliation-required"},deadline)
            if not terminal(cancelled,"cancelled","cancelled",False):
                raise RuntimeError()
        else:
            old_pid=repaird_pid() if MODE=="repaird-termination" else None
            approval={"preparedId":detail["preparedId"],"sessionId":detail["sessionId"],"planId":detail["planId"],"planHash":detail["planHash"],"approvalId":"A-"+secrets.token_hex(16),"approvalSequence":detail["nextApprovalSequence"],"typedConfirmation":"DISABILITA VOCE FSTAB"}
            approved=None
            try:
                approved=repair("repair.fstab.approve",approval)
            except BaseException:
                if MODE!="repaird-termination":
                    raise
            if MODE=="repaird-termination":
                approved=wait({"restored","failed","manual-reconciliation-required"},deadline)
                new_pid=repaird_pid()
                if new_pid==old_pid or not terminal(approved,"restored","closed-before-unchanged",True):
                    raise RuntimeError()
            else:
                if approved.get("state")=="executing":
                    approved=wait({"succeeded","restored","failed","manual-reconciliation-required"},deadline)
                if not terminal(approved,"restored","closed-before-restored",True) or not mutation_diagnostic(deadline):
                    raise RuntimeError()
except BaseException:
    sys.exit(46)
sys.stdout.write("KERNAID_QEMU_PROVIDER_PROOF_V1 stage=repair-"+MODE+" result=true\n")
'''
    generated = (
        textwrap.dedent(source)
        .replace("__MODE__", repr(mode))
        .replace("__BEFORE__", repr(before_sha256))
        .replace("__AFTER__", repr(after_sha256))
        .encode("ascii")
    )
    if len(generated) > 16 * 1024:
        raise ValueError("failure proof exceeds guest source limit")
    return generated


def tampered_backup_source(reservation_id: str, binding: str) -> bytes:
    """Return a source-fixed proof that an authenticated backup tamper closes."""

    source = r'''import http.client,json,sys,time
HOST="127.0.0.1:4173"
ORIGIN="http://127.0.0.1:4173"
API="kernaid.dev/rescue-repair-service/v1alpha2"
SOURCE={"reservationId":__RESERVATION__,"transactionBindingSha256":__BINDING__}
CLOSED={"apiVersion":"kernaid.dev/rescue-repair-service/v1alpha1","outcome":"error","error":"relay-unavailable"}
counter=0
def request_id():
    global counter
    counter+=1
    return "R-40000000-0000-0000-0000-"+format(counter,"012x")
def valid_id(value):
    return isinstance(value,str) and value.startswith("B-") and len(value)==34 and all(character in "0123456789abcdef" for character in value[2:])
def valid_hash(value):
    return isinstance(value,str) and value.startswith("sha256:") and len(value)==71 and all(character in "0123456789abcdef" for character in value[7:])
def repair(operation,extra=None,allow_recovery_closed=False):
    request={"apiVersion":API,"requestId":request_id(),"operation":operation}
    if extra is not None:
        request.update(extra)
    encoded=json.dumps(request,ensure_ascii=True,separators=(",",":")).encode("ascii")
    connection=http.client.HTTPConnection("127.0.0.1",4173,timeout=25)
    try:
        connection.request("POST","/api/rescue/repair",body=encoded,headers={"Host":HOST,"Origin":ORIGIN,"Content-Type":"application/json"})
        response=connection.getresponse()
        payload=response.read(65537)
        status=response.status
    finally:
        connection.close()
    if status!=200 or len(payload)>65536:
        if not allow_recovery_closed or status!=503 or len(payload)>65536 or json.loads(payload)!=CLOSED:
            raise RuntimeError()
        return None
    value=json.loads(payload)
    if value.get("outcome")!="ok" or value.get("operation")!=operation or value.get("requestId")!=request["requestId"]:
        raise RuntimeError()
    return value
def committed(value):
    detail=value.get("detail")
    keys={"kind","terminalOutcome","reservationId","transactionBindingSha256","rebootRequired","prepareFailureStage"}
    return value.get("state")=="succeeded" and isinstance(detail,dict) and set(detail)==keys and detail.get("kind")=="terminal" and detail.get("terminalOutcome")=="committed" and valid_id(detail.get("reservationId")) and valid_hash(detail.get("transactionBindingSha256")) and detail.get("rebootRequired") is False and detail.get("prepareFailureStage") is None
deadline=time.monotonic()+420
try:
    if not valid_id(SOURCE["reservationId"]) or not valid_hash(SOURCE["transactionBindingSha256"]):
        raise RuntimeError()
    initial=repair("repair.fstab.rollback.status",allow_recovery_closed=True)
    if initial is None:
        if repair("repair.fstab.rollback.prepare",{"source":SOURCE},allow_recovery_closed=True) is not None:
            raise RuntimeError()
    else:
        if initial.get("state")!="idle" or initial.get("detail") is not None:
            raise RuntimeError()
        result=repair("repair.fstab.rollback.prepare",{"source":SOURCE})
        if result.get("state")=="prepared":
            raise RuntimeError()
        while result.get("state")=="preparing" and time.monotonic()<deadline:
            time.sleep(.2)
            result=repair("repair.fstab.rollback.status")
        if result.get("state")!="idle" or result.get("detail") is not None:
            raise RuntimeError()
except BaseException:
    sys.exit(46)
sys.stdout.write("KERNAID_QEMU_PROVIDER_PROOF_V1 stage=repair-backup-tamper result=true\n")
'''
    return (
        textwrap.dedent(source)
        .replace("__RESERVATION__", repr(reservation_id))
        .replace("__BINDING__", repr(binding))
        .encode("ascii")
    )


def rollback_source(before_sha256: str, after_sha256: str) -> bytes:
    """Return a source-fixed one-boot proof of committed repair and rollback."""

    source = r'''import hashlib,http.client,json,secrets,subprocess,sys,time
HOST="127.0.0.1:4173"
ORIGIN="http://127.0.0.1:4173"
APPLY_API="kernaid.dev/rescue-repair-service/v1alpha1"
ROLLBACK_API="kernaid.dev/rescue-repair-service/v1alpha2"
BEFORE=__BEFORE__
AFTER=__AFTER__
RESOURCE="rescue:selected-linux-root:etc/fstab"
APPLY_CONFIRMATION="DISABILITA VOCE FSTAB"
ROLLBACK_CONFIRMATION="RIPRISTINA FSTAB ORIGINALE"
counter=0
checkpoint="service-ready"
CHECKPOINTS=("service-ready","service-ready-internal","service-ready-transport","service-ready-http","service-ready-response-invalid","service-ready-non-idle","inventory-ready","target-selection","target-identity","apply-prepare","apply-prepare-terminal","apply-contract","apply-approve","apply-terminal","apply-terminal-contract","rollback-status","rollback-prepare","rollback-prepare-terminal","rollback-prepare-error-authority","rollback-prepare-error-target","rollback-prepare-error-lock","rollback-prepare-error-timeout","rollback-prepare-error-vault","rollback-prepare-error-recovery","rollback-prepare-error-unavailable","rollback-contract","rollback-approve","rollback-terminal","rollback-terminal-contract")
ROLLBACK_FAILURE_STAGES=("authority","target","lock","timeout","vault","recovery")
STATES=("idle","preparing","prepared","executing","succeeded","restored","cancelled","manual-reconciliation-required","failed")
def request_id():
    global counter
    counter+=1
    return "R-20000000-0000-0000-0000-"+format(counter,"012x")
def valid_hex(value,prefix):
    return isinstance(value,str) and value.startswith(prefix) and len(value)==len(prefix)+32 and all(character in "0123456789abcdef" for character in value[len(prefix):])
def valid_hash(value):
    return isinstance(value,str) and value.startswith("sha256:") and len(value)==71 and all(character in "0123456789abcdef" for character in value[7:])
def exchange(path,body=None,timeout=25):
    encoded=None if body is None else json.dumps(body,ensure_ascii=True,separators=(",",":")).encode("ascii")
    headers={"Host":HOST}
    if encoded is not None:
        headers.update({"Origin":ORIGIN,"Content-Type":"application/json"})
    connection=http.client.HTTPConnection("127.0.0.1",4173,timeout=timeout)
    try:
        connection.request("GET" if encoded is None else "POST",path,body=encoded,headers=headers)
        response=connection.getresponse()
        payload=response.read(65537)
        status=response.status
    finally:
        connection.close()
    return status,payload
def decode(payload):
    if len(payload)>65536:
        raise RuntimeError()
    return json.loads(payload)
def call(path,body=None,timeout=25):
    status,payload=exchange(path,body,timeout)
    return status,decode(payload)
def valid_response(value,api,operation,request):
    return isinstance(value,dict) and set(value)=={"apiVersion","requestId","operation","outcome","stateVersion","state","detail"} and value.get("apiVersion")==api and value.get("requestId")==request["requestId"] and value.get("operation")==operation and value.get("outcome")=="ok" and type(value.get("stateVersion")) is int and value.get("stateVersion")>=1 and value.get("state") in STATES and (value.get("detail") is None or isinstance(value.get("detail"),dict))
def repair(api,operation,extra=None):
    request={"apiVersion":api,"requestId":request_id(),"operation":operation}
    if extra is not None:
        request.update(extra)
    status,value=call("/api/rescue/repair",request)
    if status!=200 or not valid_response(value,api,operation,request):
        raise RuntimeError()
    return value
def service_ready():
    try:
        return service_ready_inner()
    except BaseException:
        return "service-ready-internal"
def service_ready_inner():
    request={"apiVersion":APPLY_API,"requestId":request_id(),"operation":"repair.status"}
    try:
        status,payload=exchange("/api/rescue/repair",request)
    except (OSError,http.client.HTTPException):
        return "service-ready-transport"
    except BaseException:
        return "service-ready-response-invalid"
    if status!=200:
        return "service-ready-http"
    try:
        value=decode(payload)
    except BaseException:
        return "service-ready-response-invalid"
    if not valid_response(value,APPLY_API,"repair.status",request):
        return "service-ready-response-invalid"
    if value["state"]=="idle":
        return None
    return "service-ready-non-idle"
def wait(api,operation,states,deadline):
    while time.monotonic()<deadline:
        value=repair(api,operation)
        if value.get("state") in states:
            return value
        time.sleep(.2)
    raise RuntimeError()
def rollback_prepare_failure_checkpoint():
    try:
        result=subprocess.run(["/usr/bin/systemctl","show","--property=StatusText","--value","kernaid-rescue-repaird.service"],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=5,check=False)
    except BaseException:
        return "rollback-prepare-error-unavailable"
    if result.returncode!=0 or len(result.stdout)>256:
        return "rollback-prepare-error-unavailable"
    prefix=b"KERNAID_RESCUE_REPAIR_EXECUTION_FAILURE_V1 stage="
    value=result.stdout.strip()
    if not value.startswith(prefix):
        return "rollback-prepare-error-unavailable"
    try:
        stage=value[len(prefix):].decode("ascii")
    except BaseException:
        return "rollback-prepare-error-unavailable"
    if stage not in ROLLBACK_FAILURE_STAGES or value!=prefix+stage.encode("ascii"):
        return "rollback-prepare-error-unavailable"
    return "rollback-prepare-error-"+stage
def fail(value):
    if value not in CHECKPOINTS:
        sys.exit(46)
    sys.stdout.write("KERNAID_QEMU_PROVIDER_PROOF_FAILURE_V1 stage=repair-rollback checkpoint="+value+"\n")
    sys.exit(45)
try:
    deadline=time.monotonic()+840
    while True:
        checkpoint="service-ready-internal"
        service_ready_checkpoint=service_ready()
        if service_ready_checkpoint is None:
            break
        checkpoint=service_ready_checkpoint
        if time.monotonic()>=deadline:
            raise RuntimeError()
        time.sleep(.5)
    checkpoint="inventory-ready"
    while True:
        try:
            inventory_code,inventory=call("/api/inventory")
            scan_code,scan=call("/api/rescue/installed-targets")
            if inventory_code==200 and scan_code==200:
                break
        except BaseException:
            pass
        if time.monotonic()>=deadline:
            raise RuntimeError()
        time.sleep(.5)
    checkpoint="target-selection"
    candidates=[item for item in scan["candidates"] if item.get("osFamilyHint")=="linux" and item.get("requiresUnlock") is False]
    if len(candidates)!=1:
        raise RuntimeError()
    candidate=candidates[0]
    selection={"scanFingerprint":scan["scanFingerprint"],"targetId":candidate["targetId"]}
    selected_code,selected=call("/api/rescue/select-installed-target",selection)
    inspected_code,inspected=call("/api/rescue/inspect-installed-target",selection)
    if selected_code!=200 or selected.get("target")!=candidate or inspected_code!=200 or inspected.get("status")!="installed-os-content-inspected" or inspected.get("target",{}).get("filesystem")!="ext4":
        raise RuntimeError()
    checkpoint="target-identity"
    identity=[item for item in inventory if "hostname" in item.get("collector","") or "block.inventory" in item.get("collector","") or item.get("collector","").endswith((".disks",".system",".storage.identity"))]
    if not identity or any(item.get("success") is not True or item.get("truncated") is True for item in identity):
        raise RuntimeError()
    canonical="\0".join(item["collector"]+"\0"+item["output"] for item in identity)
    runtime="sha256:"+hashlib.sha256(canonical.encode()).hexdigest()
    candidate_json=json.dumps(candidate,ensure_ascii=True,sort_keys=True,separators=(",",":"))
    material="\0".join(("kernaid-rescue-observe-target-v1",runtime,scan["scanFingerprint"],candidate["targetId"],candidate_json))
    target_fingerprint="sha256:"+hashlib.sha256(material.encode()).hexdigest()
    checkpoint="apply-prepare"
    prepared=repair(APPLY_API,"repair.fstab.prepare",{"target":{"scanFingerprint":scan["scanFingerprint"],"targetFingerprint":target_fingerprint,"targetId":candidate["targetId"]}})
    checkpoint="apply-prepare-terminal"
    if prepared.get("state")=="preparing":
        prepared=wait(APPLY_API,"repair.status",{"prepared","failed","restored","manual-reconciliation-required"},deadline)
    checkpoint="apply-contract"
    detail=prepared.get("detail")
    apply_keys={"kind","preparedId","sessionId","planId","planHash","targetFingerprint","beforeSha256","afterSha256","diffSha256","resourceId","backupLocator","actionId","risk","backup","nextApprovalSequence","confirmationRequired"}
    if prepared.get("state")!="prepared" or not isinstance(detail,dict) or set(detail)!=apply_keys or detail.get("kind")!="fstab-prepared" or detail.get("actionId")!="linux.fstab.disable-missing-uuid.v1" or detail.get("targetFingerprint")!=target_fingerprint or detail.get("beforeSha256")!=BEFORE or detail.get("afterSha256")!=AFTER or detail.get("resourceId")!=RESOURCE or detail.get("risk")!="R2" or detail.get("backup")!={"state":"reserved","vaultDistinct":True} or detail.get("confirmationRequired")!=APPLY_CONFIRMATION or not valid_hash(detail.get("planHash")) or not valid_hash(detail.get("diffSha256")) or not valid_hex(detail.get("preparedId"),"Q-") or not valid_hex(detail.get("sessionId"),"S-") or not valid_hex(detail.get("planId"),"P-") or isinstance(detail.get("nextApprovalSequence"),bool) or not isinstance(detail.get("nextApprovalSequence"),int) or detail.get("nextApprovalSequence")<1:
        raise RuntimeError()
    locator=detail.get("backupLocator")
    source_reservation=locator[len("vault://repair/"):] if isinstance(locator,str) and locator.startswith("vault://repair/") else None
    if not valid_hex(source_reservation,"B-"):
        raise RuntimeError()
    apply_sequence=detail["nextApprovalSequence"]
    apply_approval_id="A-"+secrets.token_hex(16)
    checkpoint="apply-approve"
    approved=repair(APPLY_API,"repair.fstab.approve",{"preparedId":detail["preparedId"],"sessionId":detail["sessionId"],"planId":detail["planId"],"planHash":detail["planHash"],"approvalId":apply_approval_id,"approvalSequence":apply_sequence,"typedConfirmation":APPLY_CONFIRMATION})
    checkpoint="apply-terminal"
    if approved.get("state")=="executing":
        approved=wait(APPLY_API,"repair.status",{"succeeded","restored","failed","manual-reconciliation-required","cancelled"},deadline)
    checkpoint="apply-terminal-contract"
    source_detail=approved.get("detail")
    terminal_keys={"kind","terminalOutcome","reservationId","transactionBindingSha256","rebootRequired","prepareFailureStage"}
    if approved.get("state")!="succeeded" or not isinstance(source_detail,dict) or set(source_detail)!=terminal_keys or source_detail.get("kind")!="terminal" or source_detail.get("terminalOutcome")!="committed" or source_detail.get("reservationId")!=source_reservation or not valid_hash(source_detail.get("transactionBindingSha256")) or source_detail.get("rebootRequired") is not False or source_detail.get("prepareFailureStage") is not None:
        raise RuntimeError()
    source_receipt={"reservationId":source_detail["reservationId"],"transactionBindingSha256":source_detail["transactionBindingSha256"]}
    checkpoint="rollback-status"
    rollback_status=repair(ROLLBACK_API,"repair.fstab.rollback.status")
    if rollback_status.get("state")!="succeeded" or rollback_status.get("detail")!=source_detail:
        raise RuntimeError()
    checkpoint="rollback-prepare"
    rollback_prepared=repair(ROLLBACK_API,"repair.fstab.rollback.prepare",{"source":source_receipt})
    checkpoint="rollback-prepare-terminal"
    if rollback_prepared.get("state")=="preparing":
        rollback_prepared=wait(ROLLBACK_API,"repair.fstab.rollback.status",{"prepared","succeeded","failed","restored","manual-reconciliation-required"},deadline)
    if rollback_prepared.get("state")=="succeeded":
        checkpoint=rollback_prepare_failure_checkpoint()
        raise RuntimeError()
    checkpoint="rollback-contract"
    rollback=rollback_prepared.get("detail")
    rollback_keys={"kind","preparedId","rollbackId","sessionId","planId","planHash","targetFingerprint","source","resourceId","backupLocator","actionId","risk","nextApprovalSequence","confirmationRequired"}
    if rollback_prepared.get("state")!="prepared" or not isinstance(rollback,dict) or set(rollback)!=rollback_keys or rollback.get("kind")!="fstab-rollback-prepared" or not valid_hex(rollback.get("preparedId"),"Q-") or not valid_hex(rollback.get("rollbackId"),"RB-") or not valid_hex(rollback.get("sessionId"),"S-") or not valid_hex(rollback.get("planId"),"P-") or not valid_hash(rollback.get("planHash")) or rollback.get("targetFingerprint")!=target_fingerprint or rollback.get("source")!=source_receipt or rollback.get("resourceId")!=RESOURCE or rollback.get("backupLocator")!="vault://repair/"+source_receipt["reservationId"] or rollback.get("actionId")!="linux.fstab.restore" or rollback.get("risk")!="R2" or rollback.get("nextApprovalSequence")!=apply_sequence+1 or rollback.get("confirmationRequired")!=ROLLBACK_CONFIRMATION:
        raise RuntimeError()
    rollback_approval_id="A-"+secrets.token_hex(16)
    while rollback_approval_id==apply_approval_id:
        rollback_approval_id="A-"+secrets.token_hex(16)
    checkpoint="rollback-approve"
    rolled_back=repair(ROLLBACK_API,"repair.fstab.rollback.approve",{"preparedId":rollback["preparedId"],"rollbackId":rollback["rollbackId"],"sessionId":rollback["sessionId"],"planId":rollback["planId"],"planHash":rollback["planHash"],"source":source_receipt,"approvalId":rollback_approval_id,"approvalSequence":rollback["nextApprovalSequence"],"typedConfirmation":ROLLBACK_CONFIRMATION})
    checkpoint="rollback-terminal"
    if rolled_back.get("state")=="executing":
        rolled_back=wait(ROLLBACK_API,"repair.fstab.rollback.status",{"restored","failed","manual-reconciliation-required","cancelled"},deadline)
    checkpoint="rollback-terminal-contract"
    result=rolled_back.get("detail")
    if rolled_back.get("state")!="restored" or not isinstance(result,dict) or set(result)!=terminal_keys or result.get("kind")!="terminal" or result.get("terminalOutcome")!="rolled-back-original" or result.get("reservationId")!=source_receipt["reservationId"] or result.get("transactionBindingSha256")!=source_receipt["transactionBindingSha256"] or result.get("rebootRequired") is not False or result.get("prepareFailureStage") is not None:
        raise RuntimeError()
except BaseException:
    fail(checkpoint)
sys.stdout.write("KERNAID_QEMU_PROVIDER_PROOF_V1 stage=repair-rollback result=true\n")
'''
    return textwrap.dedent(source).replace(
        "__BEFORE__", repr(before_sha256)
    ).replace("__AFTER__", repr(after_sha256)).encode("ascii")


def reconcile_source() -> bytes:
    """Return a source-fixed boot-two proof for the recovery barrier."""

    source = f'''import http.client,json,sys,time
HOST="127.0.0.1:4173"
ORIGIN="http://127.0.0.1:4173"
API="kernaid.dev/rescue-repair-service/v1alpha1"
{EXECUTE_STATE_CLASSIFIER_SOURCE}
counter=0
def request_id():
    global counter
    counter+=1
    return "R-10000000-0000-0000-0000-"+format(counter,"012x")
def status():
    body={{"apiVersion":API,"requestId":request_id(),"operation":"repair.status"}}
    encoded=json.dumps(body,ensure_ascii=True,separators=(",",":")).encode("ascii")
    connection=http.client.HTTPConnection("127.0.0.1",4173,timeout=25)
    connection.request("POST","/api/rescue/repair",body=encoded,headers={{"Host":HOST,"Origin":ORIGIN,"Content-Type":"application/json"}})
    response=connection.getresponse()
    payload=response.read(65537)
    code=response.status
    connection.close()
    if code!=200 or len(payload)>65536:
        raise RuntimeError()
    value=json.loads(payload)
    if not isinstance(value,dict) or value.get("outcome")!="ok":
        raise RuntimeError()
    return value
deadline=time.monotonic()+420
terminal=None
while time.monotonic()<deadline:
    try:
        candidate=status()
        if candidate.get("state") in ("restored","succeeded","failed","manual-reconciliation-required","cancelled","idle"):
            terminal=candidate
            break
    except BaseException:
        pass
    time.sleep(.25)
if terminal is None or execute_state_checkpoint(terminal) not in (
    "execute-state-closed-before-unchanged",
    "execute-state-closed-before-restored",
):
    sys.exit(46)
sys.stdout.write("KERNAID_QEMU_PROVIDER_PROOF_V1 stage=repair-reconcile result=true\\n")
'''
    return textwrap.dedent(source).encode("ascii")


def run_receipt_guest_proof(
    console: object,
    source: bytes,
    cursor: int,
    aggregate: float,
) -> tuple[str, str, int]:
    """Run the committed apply and retain its bounded receipt only in memory."""

    if not source or b"\x00" in source or len(source) > 16 * 1024:
        raise LIFECYCLE.ClosedFailure("receipt", "source-invalid")
    begin = b"KERNAID_PROVIDER_PROOF_BEGIN_V1_repair-backup-tamper-apply"
    end = b"KERNAID_PROVIDER_PROOF_END_V1_repair-backup-tamper-apply"
    started = time.monotonic()
    if aggregate - started < 455.0:
        raise LIFECYCLE.ClosedFailure("receipt", "aggregate-budget")
    shell = (
        b"printf '%s\\n' '"
        + begin
        + b"'; /usr/bin/python3 -I -B -c "
        + LIFECYCLE._shell_single_quote(source)
        + b"; rc=$?; printf '%s rc=%s\\n' '"
        + end
        + b"' \"$rc\"\n"
    )
    console.send(shell, deadline=started + 5.0)
    begin_match = console.wait_regex(
        LIFECYCLE._trusted_shell_line_pattern(begin),
        start=cursor,
        deadline=started + 15.0,
        stage="receipt-start",
    )
    receipt_pattern = re.compile(
        rb"(?:\A|(?<=\n))(?:\x1b\[\?2004l\r)?"
        rb"(KERNAID_QEMU_REPAIR_RECEIPT_V1 "
        rb"reservation_id=(B-[0-9a-f]{32}) "
        rb"binding=(sha256:[0-9a-f]{64}))\r?\n"
    )
    receipt = console.wait_regex(
        receipt_pattern,
        start=begin_match.end(),
        deadline=started + 435.0,
        stage="receipt",
    )
    end_match = console.wait_regex(
        LIFECYCLE._return_code_line_pattern(end),
        # The return-code matcher consumes its leading line boundary.  The
        # receipt matcher has already consumed that newline, so reopen only
        # its final validated LF; starting at receipt.end() makes an adjacent
        # END marker impossible to match.
        start=receipt.end() - 1,
        deadline=started + 445.0,
        stage="receipt-finish",
    )
    if LIFECYCLE._canonical_return_code(end_match.group(1)) != 0:
        raise LIFECYCLE.ClosedFailure("receipt", "command-failed")
    block = console.capture.snapshot()[begin_match.end() : end_match.start()]
    marker = receipt.group(1)
    if LIFECYCLE._normalize(block) != [marker]:
        raise LIFECYCLE.ClosedFailure("receipt", "output-invalid")
    return (
        receipt.group(2).decode("ascii"),
        receipt.group(3).decode("ascii"),
        end_match.end(),
    )


def invoke_vault_tamper(
    helper: Path,
    media: Path,
    key_file: Path,
    reservation_id: str,
    aggregate: float,
) -> None:
    """Run the root-only, no-mount disposable Vault tamper helper."""

    try:
        resolved = helper.resolve(strict=True)
        metadata = resolved.stat()
    except OSError as error:
        raise LIFECYCLE.ClosedFailure("tamper", "helper-invalid") from error
    if (
        resolved != TOOLS / "qemu-repair-vault-tamper.py"
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_mode & 0o022
    ):
        raise LIFECYCLE.ClosedFailure("tamper", "helper-invalid")
    remaining = aggregate - time.monotonic()
    if remaining < 185.0:
        raise LIFECYCLE.ClosedFailure("tamper", "deadline")
    timeout = min(180.0, remaining - 5.0)
    try:
        result = subprocess.run(
            [
                "/usr/bin/sudo",
                "-n",
                "--",
                "/usr/bin/python3",
                "-I",
                "-B",
                os.fspath(resolved),
                "--media",
                os.fspath(media),
                "--key-file",
                os.fspath(key_file),
                "--reservation-id",
                reservation_id,
                "--p3-offset",
                "17179869184",
                "--p3-bytes",
                "8589934592",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"},
            check=False,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise LIFECYCLE.ClosedFailure("tamper", "helper-failed") from error
    expected = (
        b"KERNAID_QEMU_REPAIR_VAULT_TAMPER_ATTESTATION_V1 "
        b"object=single-authenticated-backup mutation=inode-size-one "
        b"mount=false cleanup=complete ready=true\n"
    )
    if result.returncode != 0 or result.stdout != expected or result.stderr:
        raise LIFECYCLE.ClosedFailure(
            "tamper",
            tamper_helper_failure_code(
                result.returncode, result.stdout, result.stderr
            ),
        )


def tamper_helper_failure_code(
    returncode: int, stdout: bytes, stderr: bytes
) -> str:
    """Preserve only an exact allowlisted helper diagnostic token."""

    if returncode != 1 or stdout:
        return "helper-failed"
    match = TAMPER_HELPER_FAILURE.fullmatch(stderr)
    if match is None:
        return "helper-failed"
    code = match.group(1).decode("ascii")
    if code not in TAMPER_HELPER_FAILURE_CODES:
        return "helper-failed"
    return f"helper-failed-{code}"


def provision_firstboot(
    console: object, qmp: object, key: bytearray, aggregate: float
) -> None:
    """Provision exactly one zero-p3 disposable Rescue medium."""

    passphrase = LIFECYCLE.wait_firstboot_prompt(
        console,
        "passphrase",
        0,
        LIFECYCLE._deadline(aggregate, REPAIR_FIRSTBOOT_PROMPT_TIMEOUT_SECONDS),
        "firstboot-start",
    )
    time.sleep(REPAIR_FIRSTBOOT_PROMPT_SETTLE_SECONDS)
    qmp.set_deadline(
        LIFECYCLE._deadline(aggregate, REPAIR_QMP_INPUT_TIMEOUT_SECONDS)
    )
    qmp.send_hex_line(key, settle_seconds=REPAIR_QMP_KEY_SETTLE_SECONDS)
    confirmation = LIFECYCLE.wait_firstboot_prompt(
        console,
        "confirmation",
        passphrase.end(),
        LIFECYCLE._deadline(aggregate, REPAIR_FIRSTBOOT_PROMPT_TIMEOUT_SECONDS),
        "firstboot-confirmation",
    )
    time.sleep(REPAIR_FIRSTBOOT_PROMPT_SETTLE_SECONDS)
    qmp.set_deadline(
        LIFECYCLE._deadline(aggregate, REPAIR_QMP_INPUT_TIMEOUT_SECONDS)
    )
    qmp.send_hex_line(key, settle_seconds=REPAIR_QMP_KEY_SETTLE_SECONDS)
    LIFECYCLE.wait_firstboot_attestation(
        console,
        confirmation.end(),
        LIFECYCLE._deadline(
            aggregate, REPAIR_FIRSTBOOT_RESULT_TIMEOUT_SECONDS
        ),
    )


def run_repair_unlock_companion(
    console: object,
    stage: str,
    cursor: int,
    aggregate: float,
    key: bytearray,
) -> tuple[object, int]:
    """Recover one known serial-noise shape through a fresh exact status."""

    unlock_stage = f"{stage}-unlock"
    try:
        return LIFECYCLE.run_companion(
            console, "unlock", unlock_stage, cursor, aggregate, key
        )
    except LIFECYCLE.ResponseShapeFailure as failure:
        if not (
            failure.stage == unlock_stage
            and failure.code == "response-version-invalid"
            and type(failure.return_code) is int
            and failure.return_code == 0
            and failure.first_class == "kernel-timestamp"
            and failure.block_lines == 4
            and 0 < failure.block_bytes <= 512
        ):
            raise

    # Do not parse, filter, or trust the contaminated unlock response. Start a
    # separate framed transaction after everything captured so far and accept
    # only the production companion's exact unlocked status contract.
    recovery_cursor = len(console.capture)
    recovered, recovery_cursor = LIFECYCLE.run_companion(
        console,
        "status",
        f"{unlock_stage}-recovery-status",
        recovery_cursor,
        aggregate,
    )
    if (
        recovered.vault_state != "unlocked"
        or recovered.device_id is None
        or recovered.error is not None
        or recovered.return_code != 0
    ):
        raise LIFECYCLE.ClosedFailure(unlock_stage, "noise-recovery-invalid")
    return recovered, recovery_cursor


def unlock_repair_vault(
    console: object,
    aggregate: float,
    login: bytearray,
    key: bytearray,
    *,
    stage: str,
) -> int:
    """Enter the live session and require a locked-to-unlocked transition."""

    cursor = LIFECYCLE.establish_live_session(console, aggregate, login)
    _, cursor = LIFECYCLE.collect_runtime(console, f"{stage}-initial", cursor, aggregate)
    initial, cursor = LIFECYCLE.run_companion(
        console, "status", f"{stage}-initial-status", cursor, aggregate
    )
    if initial.vault_state != "locked" or initial.device_id is not None:
        raise LIFECYCLE.ClosedFailure("vault", "initial-status-invalid")
    unlocked, cursor = run_repair_unlock_companion(
        console, stage, cursor, aggregate, key
    )
    if (
        unlocked.state_version != initial.state_version + 2
        or unlocked.vault_state != "unlocked"
        or unlocked.device_id is None
        or LIFECYCLE.DEVICE_ID_RE.fullmatch(unlocked.device_id) is None
    ):
        raise LIFECYCLE.ClosedFailure("vault", "unlock-invalid")
    return cursor


def target_write_bytes(qmp: object) -> int:
    """Return completed guest writes for the exact target BlockBackend."""

    result = qmp.execute_result("query-blockstats")
    if not isinstance(result, list) or len(result) > 64:
        raise LIFECYCLE.ClosedFailure("interruption", "blockstats-invalid")
    matches = [
        item
        for item in result
        if (
            isinstance(item, dict)
            and item.get("device") == ""
            and item.get("node-name") == TARGET_NODE
            and item.get("qdev") == TARGET_QDEV
        )
    ]
    if len(matches) != 1:
        raise LIFECYCLE.ClosedFailure("interruption", "target-backend-invalid")
    stats = matches[0].get("stats")
    if not isinstance(stats, dict):
        raise LIFECYCLE.ClosedFailure("interruption", "blockstats-invalid")
    counters = [
        stats.get(name)
        for name in (
            "wr_bytes",
            "wr_operations",
            "failed_wr_operations",
            "invalid_wr_operations",
        )
    ]
    if any(
        isinstance(value, bool) or not isinstance(value, int) or value < 0
        for value in counters
    ):
        raise LIFECYCLE.ClosedFailure("interruption", "write-counter-invalid")
    writes, operations, failed, invalid = counters
    if failed != 0 or invalid != 0 or (writes == 0) != (operations == 0):
        raise LIFECYCLE.ClosedFailure("interruption", "write-counter-invalid")
    return writes


def hard_power_cut(harness: object, deadline: float) -> None:
    """Kill the exact QEMU process and require a bounded SIGKILL reap."""

    process = getattr(harness, "process", None)
    if process is None or process.poll() is not None:
        raise LIFECYCLE.ClosedFailure("interruption", "qemu-not-running")
    try:
        process.kill()
    except OSError as error:
        raise LIFECYCLE.ClosedFailure("interruption", "power-cut-failed") from error
    while process.poll() is None and time.monotonic() < deadline:
        time.sleep(0.01)
    if process.poll() != -signal.SIGKILL:
        raise LIFECYCLE.ClosedFailure("interruption", "power-cut-invalid")


def interrupt_after_first_target_write(
    harness: object, qmp: object, aggregate: float
) -> None:
    # The shipping write-capability helper can write through this device only
    # after the exact Pending record has passed its durable persist-and-readback
    # barrier. Thus the first completed BlockBackend write is an external
    # witness that the cut occurs after Pending, without adding a guest hook.
    # Named-node statistics do not account writes in this QEMU topology.
    qmp.set_deadline(LIFECYCLE._deadline(aggregate, 10.0))
    if target_write_bytes(qmp) != 0:
        raise LIFECYCLE.ClosedFailure("interruption", "target-wrote-before-approval")
    witness_deadline = LIFECYCLE._deadline(aggregate, 180.0)
    while time.monotonic() < witness_deadline:
        # Keep the guest running while polling one correlated, completed-write
        # counter at no more than ten queries per second. A completed write
        # remains the fail-closed witness; an already-resolved commit is
        # rejected by boot-two reconciliation.
        time.sleep(0.1)
        if time.monotonic() >= witness_deadline:
            break
        qmp.set_deadline(LIFECYCLE._deadline(aggregate, 15.0))
        if target_write_bytes(qmp) > 0:
            hard_power_cut(harness, LIFECYCLE._deadline(aggregate, 10.0))
            return
    raise LIFECYCLE.ClosedFailure("interruption", "target-write-timeout")


def main(arguments: Sequence[str]) -> int:
    if arguments[:1] == ["--extract-live-credential"]:
        extract = ClosedParser(add_help=False, allow_abbrev=False)
        extract.add_argument("--source-fd", type=int, required=True)
        extract.add_argument("--credential-fd", type=int, required=True)
        try:
            parsed = extract.parse_args(arguments[1:])
            LIFECYCLE.extract_live_credential(
                parsed.source_fd,
                parsed.credential_fd,
                expected_uid=os.geteuid(),
                expected_gid=os.getegid(),
            )
            return 0
        except BaseException:
            print(f"{FAILURE_PREFIX} stage=credential code=invalid", file=sys.stderr)
            return 1

    key = bytearray()
    login = bytearray()
    harness = None
    failure = None
    prior_handlers = {}
    prior_mask = None
    try:
        parsed = parser().parse_args(arguments)
        if parsed.qemu_args[:1] != ["--"]:
            raise LIFECYCLE.ClosedFailure("arguments", "invalid")
        if (
            parsed.scenario
            in {
                "rollback",
                "interrupt-reconcile",
                *FAILURE_SCENARIOS,
                *PACK_QUALIFICATION_SCENARIOS,
            }
            and parsed.firmware != "uefi"
        ):
            raise LIFECYCLE.ClosedFailure("arguments", "scenario-firmware-invalid")
        if parsed.scenario == "provision-base" and parsed.already_provisioned:
            raise LIFECYCLE.ClosedFailure("arguments", "provision-state-invalid")
        for digest in (parsed.before_sha256, parsed.after_sha256):
            if re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None:
                raise LIFECYCLE.ClosedFailure("arguments", "digest-invalid")
        if parsed.scenario == "provision-base":
            timeout_maximum = 3000
        elif parsed.scenario in {
            "rollback",
            "interrupt-reconcile",
            "backup-tamper",
        }:
            timeout_maximum = 1800
        else:
            timeout_maximum = 1200
        if (
            parsed.before_sha256 == parsed.after_sha256
            or not 300 <= parsed.timeout <= timeout_maximum
        ):
            raise LIFECYCLE.ClosedFailure("arguments", "invalid")
        if parsed.firmware == "uefi":
            if parsed.ovmf_code is None or parsed.ovmf_vars_template is None:
                raise LIFECYCLE.ClosedFailure("firmware", "pair-missing")
            ovmf_code = trusted_firmware_file(parsed.ovmf_code)
            ovmf_vars_template = trusted_firmware_file(parsed.ovmf_vars_template)
            code_metadata = ovmf_code.stat()
            vars_metadata = ovmf_vars_template.stat()
            if (code_metadata.st_dev, code_metadata.st_ino) == (
                vars_metadata.st_dev,
                vars_metadata.st_ino,
            ):
                raise LIFECYCLE.ClosedFailure("firmware", "pair-invalid")
        else:
            if parsed.ovmf_code is not None or parsed.ovmf_vars_template is not None:
                raise LIFECYCLE.ClosedFailure("firmware", "pair-forbidden")
            ovmf_code = None
            ovmf_vars_template = None
        fault = qualification_fault(parsed.qemu_args[1:], parsed.qmp_socket.parent)
        expected_fault = {
            "repaird-termination": FAULT_TERMINATE_AFTER_PENDING,
            "auto-restore": FAULT_FAIL_AFTER_INSTALLED,
        }.get(parsed.scenario)
        if fault != expected_fault:
            raise LIFECYCLE.ClosedFailure("arguments", "fault-credential-mismatch")
        tamper_arguments = (
            parsed.media_path,
            parsed.vault_key_path,
            parsed.tamper_helper,
        )
        if parsed.scenario == "backup-tamper":
            if any(value is None for value in tamper_arguments):
                raise LIFECYCLE.ClosedFailure("arguments", "tamper-input-missing")
        elif any(value is not None for value in tamper_arguments):
            raise LIFECYCLE.ClosedFailure("arguments", "tamper-input-forbidden")
        prior_handlers, prior_mask = LIFECYCLE.install_signal_guard()
        key = LIFECYCLE.read_secret_fd(parsed.vault_key_fd, expected_uid=os.geteuid())
        login = LIFECYCLE.read_login_credential_fd(
            parsed.login_credential_fd, expected_uid=os.geteuid()
        )
        aggregate = time.monotonic() + parsed.timeout
        first_boot_arguments = qemu_args_for_boot(
            parsed.qemu_args[1:],
            parsed.firmware,
            1,
            parsed.qmp_socket,
            ovmf_code,
            ovmf_vars_template,
        )
        harness = LIFECYCLE.QemuHarness(
            parsed.qemu,
            first_boot_arguments,
            parsed.qmp_socket,
            [key],
            [key, login],
        )
        console, qmp = harness.start(LIFECYCLE._deadline(aggregate, 15.0))
        if not parsed.already_provisioned:
            provision_firstboot(console, qmp, key, aggregate)
        if parsed.scenario == "provision-base":
            qmp.set_deadline(LIFECYCLE._deadline(aggregate, 10.0))
            qmp.system_powerdown()
            harness.wait_for_shutdown(
                LIFECYCLE._deadline(aggregate, REPAIR_ACPI_SHUTDOWN_SECONDS)
            )
        else:
            cursor = unlock_repair_vault(
                console, aggregate, login, key, stage="repair"
            )
        if parsed.scenario == "apply":
            LIFECYCLE.run_guest_proof(
                console,
                "repair-apply",
                repair_source(parsed.before_sha256, parsed.after_sha256),
                cursor,
                aggregate,
                timeout=420.0,
            )
            qmp.set_deadline(LIFECYCLE._deadline(aggregate, 10.0))
            qmp.system_powerdown()
            harness.wait_for_shutdown(
                LIFECYCLE._deadline(aggregate, REPAIR_ACPI_SHUTDOWN_SECONDS)
            )
        elif parsed.scenario in PACK_QUALIFICATION_SCENARIOS:
            LIFECYCLE.run_guest_proof(
                console,
                f"repair-{parsed.scenario}",
                pack_qualification_source(
                    parsed.scenario,
                    parsed.before_sha256,
                    parsed.after_sha256,
                ),
                cursor,
                aggregate,
                timeout=620.0,
            )
            qmp.set_deadline(LIFECYCLE._deadline(aggregate, 10.0))
            if target_write_bytes(qmp) <= 0:
                raise LIFECYCLE.ClosedFailure(
                    "pack-qualification", "write-witness-missing"
                )
            qmp.system_powerdown()
            harness.wait_for_shutdown(
                LIFECYCLE._deadline(aggregate, REPAIR_ACPI_SHUTDOWN_SECONDS)
            )
        elif parsed.scenario == "rollback":
            LIFECYCLE.run_guest_proof(
                console,
                "repair-rollback",
                rollback_source(parsed.before_sha256, parsed.after_sha256),
                cursor,
                aggregate,
                timeout=900.0,
            )
            qmp.set_deadline(LIFECYCLE._deadline(aggregate, 10.0))
            qmp.system_powerdown()
            harness.wait_for_shutdown(
                LIFECYCLE._deadline(aggregate, REPAIR_ACPI_SHUTDOWN_SECONDS)
            )
        elif parsed.scenario in {
            "stale-target",
            "cancel",
            "repaird-termination",
            "auto-restore",
        }:
            LIFECYCLE.run_guest_proof(
                console,
                f"repair-{parsed.scenario}",
                failure_path_source(
                    parsed.scenario,
                    parsed.before_sha256,
                    parsed.after_sha256,
                ),
                cursor,
                aggregate,
                timeout=440.0,
            )
            qmp.set_deadline(LIFECYCLE._deadline(aggregate, 10.0))
            writes = target_write_bytes(qmp)
            if parsed.scenario == "auto-restore":
                if writes <= 0:
                    raise LIFECYCLE.ClosedFailure("failure-path", "write-witness-missing")
            elif writes != 0:
                raise LIFECYCLE.ClosedFailure("failure-path", "unexpected-target-write")
            qmp.system_powerdown()
            harness.wait_for_shutdown(
                LIFECYCLE._deadline(aggregate, REPAIR_ACPI_SHUTDOWN_SECONDS)
            )
        elif parsed.scenario == "backup-tamper":
            reservation_id, binding, cursor = run_receipt_guest_proof(
                console,
                repair_source(
                    parsed.before_sha256,
                    parsed.after_sha256,
                    emit_receipt=True,
                ),
                cursor,
                aggregate,
            )
            qmp.set_deadline(LIFECYCLE._deadline(aggregate, 10.0))
            if target_write_bytes(qmp) <= 0:
                raise LIFECYCLE.ClosedFailure("tamper", "apply-write-witness-missing")
            qmp.system_powerdown()
            harness.wait_for_shutdown(
                LIFECYCLE._deadline(aggregate, REPAIR_ACPI_SHUTDOWN_SECONDS)
            )
            harness.cleanup()
            harness = None

            media_path = parsed.media_path
            vault_key_path = parsed.vault_key_path
            tamper_helper = parsed.tamper_helper
            if media_path is None or vault_key_path is None or tamper_helper is None:
                raise LIFECYCLE.ClosedFailure("tamper", "input-missing")
            invoke_vault_tamper(
                tamper_helper,
                media_path,
                vault_key_path,
                reservation_id,
                aggregate,
            )

            second_boot_arguments = qemu_args_for_boot(
                parsed.qemu_args[1:],
                parsed.firmware,
                2,
                parsed.qmp_socket,
                ovmf_code,
                ovmf_vars_template,
            )
            harness = LIFECYCLE.QemuHarness(
                parsed.qemu,
                second_boot_arguments,
                parsed.qmp_socket,
                [key],
                [key, login],
            )
            console, qmp = harness.start(LIFECYCLE._deadline(aggregate, 15.0))
            cursor = unlock_repair_vault(
                console, aggregate, login, key, stage="repair-tamper-recovery"
            )
            LIFECYCLE.run_guest_proof(
                console,
                "repair-backup-tamper",
                tampered_backup_source(reservation_id, binding),
                cursor,
                aggregate,
                timeout=440.0,
            )
            qmp.set_deadline(LIFECYCLE._deadline(aggregate, 10.0))
            if target_write_bytes(qmp) != 0:
                raise LIFECYCLE.ClosedFailure("tamper", "unexpected-target-write")
            qmp.system_powerdown()
            harness.wait_for_shutdown(
                LIFECYCLE._deadline(aggregate, REPAIR_ACPI_SHUTDOWN_SECONDS)
            )
        elif parsed.scenario == "interrupt-reconcile":
            LIFECYCLE.run_guest_proof(
                console,
                "repair-interrupt-arm",
                repair_source(
                    parsed.before_sha256,
                    parsed.after_sha256,
                    interrupt_arm=True,
                ),
                cursor,
                aggregate,
                timeout=420.0,
            )
            interrupt_after_first_target_write(harness, qmp, aggregate)
            harness.cleanup()
            harness = None

            second_boot_arguments = qemu_args_for_boot(
                parsed.qemu_args[1:],
                parsed.firmware,
                2,
                parsed.qmp_socket,
                ovmf_code,
                ovmf_vars_template,
            )
            harness = LIFECYCLE.QemuHarness(
                parsed.qemu,
                second_boot_arguments,
                parsed.qmp_socket,
                [key],
                [key, login],
            )
            console, qmp = harness.start(LIFECYCLE._deadline(aggregate, 15.0))
            cursor = unlock_repair_vault(
                console, aggregate, login, key, stage="repair-recovery"
            )
            LIFECYCLE.run_guest_proof(
                console,
                "repair-reconcile",
                reconcile_source(),
                cursor,
                aggregate,
                timeout=440.0,
            )
            qmp.set_deadline(LIFECYCLE._deadline(aggregate, 10.0))
            qmp.system_powerdown()
            harness.wait_for_shutdown(
                LIFECYCLE._deadline(aggregate, REPAIR_ACPI_SHUTDOWN_SECONDS)
            )
        elif parsed.scenario != "provision-base":
            raise LIFECYCLE.ClosedFailure("arguments", "scenario-invalid")
    except LIFECYCLE.ClosedFailure as error:
        failure = error
    except (LIFECYCLE.ControllerSignal, KeyboardInterrupt, SystemExit):
        failure = LIFECYCLE.ClosedFailure("controller", "interrupted")
    except BaseException:
        failure = LIFECYCLE.ClosedFailure("controller", "unexpected")
    finally:
        LIFECYCLE.enter_signal_safe_cleanup(prior_handlers)
        if harness is not None:
            try:
                harness.cleanup()
            except BaseException:
                failure = LIFECYCLE.ClosedFailure("cleanup", "qemu-residue")
        LIFECYCLE.wipe(key)
        LIFECYCLE.wipe(login)
        LIFECYCLE.restore_signal_guard(prior_handlers, prior_mask)
    if failure is not None:
        evidence = ""
        if isinstance(failure, LIFECYCLE.ResponseShapeFailure):
            evidence = (
                f" bytes={failure.block_bytes} lines={failure.block_lines}"
                f" sha256={failure.block_sha256} first={failure.first_class}"
            )
        print(
            f"{FAILURE_PREFIX} stage={failure.stage} code={failure.code}{evidence}",
            file=sys.stderr,
            flush=True,
        )
        return 1
    digest_suffix = (
        f"before_sha256={parsed.before_sha256} "
        f"after_sha256={parsed.after_sha256}"
    )
    if parsed.scenario == "apply":
        action = "linux.fstab.disable-missing-uuid.v1"
        suffix = "terminal=committed approval=typed-single-use"
    elif parsed.scenario == "crypttab-lifecycle":
        action = "linux.crypttab.disable-missing-source.v1"
        suffix = (
            "apply=committed terminal=rolled-back-original "
            "rollback=fresh-typed-single-use exact_bytes=restored"
        )
    elif parsed.scenario == "ext4-apply":
        action = "linux.ext4.fsck-preen-with-undo.v1"
        digest_suffix = "contract_hashes=validated"
        suffix = (
            "terminal=committed postcheck=clean same_boot_undo=armed "
            "postcommit_rollback=unavailable approval=typed-single-use"
        )
    elif parsed.scenario == "resolver-link-apply":
        action = "linux.network.restore-resolver-link.v1"
        suffix = (
            "terminal=committed link=resolved-stub-relative "
            "rollback=automatic-on-failure approval=typed-single-use"
        )
    elif parsed.scenario == "rollback":
        action = "linux.fstab.restore"
        suffix = (
            "source_terminal=committed terminal=rolled-back-original "
            "state=restored approval=fresh-typed-single-use"
        )
    elif parsed.scenario == "interrupt-reconcile":
        action = "linux.fstab.disable-missing-uuid.v1"
        suffix = (
            "terminal=restored interruption=qmp-after-target-write recovery=closed"
        )
    elif parsed.scenario == "provision-base":
        action = "none"
        suffix = "terminal=provisioned reusable_base=true"
    elif parsed.scenario == "stale-target":
        action = "linux.fstab.disable-missing-uuid.v1"
        suffix = "terminal=failed stale_target=rejected target_writes=zero"
    elif parsed.scenario == "cancel":
        action = "linux.fstab.disable-missing-uuid.v1"
        suffix = "terminal=cancelled authority=released target_writes=zero"
    elif parsed.scenario == "backup-tamper":
        action = "linux.fstab.restore"
        suffix = "terminal=rejected backup_tamper=authenticated target_writes_second_boot=zero"
    elif parsed.scenario == "repaird-termination":
        action = "linux.fstab.disable-missing-uuid.v1"
        suffix = "terminal=restored process=repaird-only recovery=closed-before-unchanged target_writes=zero"
    else:
        action = "linux.fstab.disable-missing-uuid.v1"
        suffix = "terminal=restored fault=after-installed recovery=closed-before-restored target_writes=positive"
    print(
        f"{ATTESTATION_PREFIX} action={action} "
        f"firmware={parsed.firmware} scenario={parsed.scenario} "
        f"{digest_suffix} "
        f"vault_distinct=true {suffix} ready=true",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
