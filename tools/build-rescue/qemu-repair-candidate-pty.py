#!/usr/bin/env python3
"""Bounded PTY controller for the disposable Rescue repair qualification."""

from __future__ import annotations

import argparse
import importlib.util
import os
import re
import signal
import stat
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
OVMF_ROOTS = (Path("/usr/share/OVMF"), Path("/usr/share/edk2"))

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
        choices=("apply", "rollback", "interrupt-reconcile"),
        required=True,
    )
    value.add_argument("--ovmf-code", type=Path)
    value.add_argument("--ovmf-vars-template", type=Path)
    value.add_argument("--vault-key-fd", type=int, required=True)
    value.add_argument("--login-credential-fd", type=int, required=True)
    value.add_argument("--before-sha256", required=True)
    value.add_argument("--after-sha256", required=True)
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


def repair_source(
    before_sha256: str, after_sha256: str, *, interrupt_arm: bool = False
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
sys.stdout.write("KERNAID_QEMU_PROVIDER_PROOF_V1 stage="+STAGE+" result=true\\n")
'''
    return textwrap.dedent(source).encode("ascii")


def rollback_source(before_sha256: str, after_sha256: str) -> bytes:
    """Return a source-fixed one-boot proof of committed repair and rollback."""

    source = r'''import hashlib,http.client,json,secrets,sys,time
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
def request_id():
    global counter
    counter+=1
    return "R-20000000-0000-0000-0000-"+format(counter,"012x")
def valid_hex(value,prefix):
    return isinstance(value,str) and value.startswith(prefix) and len(value)==len(prefix)+32 and all(character in "0123456789abcdef" for character in value[len(prefix):])
def valid_hash(value):
    return isinstance(value,str) and value.startswith("sha256:") and len(value)==71 and all(character in "0123456789abcdef" for character in value[7:])
def http(path,body=None,timeout=25):
    encoded=None if body is None else json.dumps(body,ensure_ascii=True,separators=(",",":")).encode("ascii")
    headers={"Host":HOST}
    if encoded is not None:
        headers.update({"Origin":ORIGIN,"Content-Type":"application/json"})
    connection=http.client.HTTPConnection("127.0.0.1",4173,timeout=timeout)
    connection.request("GET" if encoded is None else "POST",path,body=encoded,headers=headers)
    response=connection.getresponse()
    payload=response.read(65537)
    status=response.status
    connection.close()
    if len(payload)>65536:
        raise RuntimeError()
    return status,json.loads(payload)
def repair(api,operation,extra=None):
    request={"apiVersion":api,"requestId":request_id(),"operation":operation}
    if extra is not None:
        request.update(extra)
    status,value=http("/api/rescue/repair",request)
    if status!=200 or not isinstance(value,dict) or set(value)!={"apiVersion","requestId","operation","outcome","stateVersion","state","detail"} or value.get("apiVersion")!=api or value.get("requestId")!=request["requestId"] or value.get("operation")!=operation or value.get("outcome")!="ok" or isinstance(value.get("stateVersion"),bool) or not isinstance(value.get("stateVersion"),int):
        raise RuntimeError()
    return value
def wait(api,operation,states,deadline):
    while time.monotonic()<deadline:
        value=repair(api,operation)
        if value.get("state") in states:
            return value
        time.sleep(.2)
    raise RuntimeError()
try:
    deadline=time.monotonic()+720
    while True:
        try:
            if repair(APPLY_API,"repair.status").get("state")=="idle":
                break
        except BaseException:
            pass
        if time.monotonic()>=deadline:
            raise RuntimeError()
        time.sleep(.5)
    while True:
        try:
            inventory_code,inventory=http("/api/inventory")
            scan_code,scan=http("/api/rescue/installed-targets")
            if inventory_code==200 and scan_code==200:
                break
        except BaseException:
            pass
        if time.monotonic()>=deadline:
            raise RuntimeError()
        time.sleep(.5)
    candidates=[item for item in scan["candidates"] if item.get("osFamilyHint")=="linux" and item.get("requiresUnlock") is False]
    if len(candidates)!=1:
        raise RuntimeError()
    candidate=candidates[0]
    selection={"scanFingerprint":scan["scanFingerprint"],"targetId":candidate["targetId"]}
    selected_code,selected=http("/api/rescue/select-installed-target",selection)
    inspected_code,inspected=http("/api/rescue/inspect-installed-target",selection)
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
    prepared=repair(APPLY_API,"repair.fstab.prepare",{"target":{"scanFingerprint":scan["scanFingerprint"],"targetFingerprint":target_fingerprint,"targetId":candidate["targetId"]}})
    if prepared.get("state")=="preparing":
        prepared=wait(APPLY_API,"repair.status",{"prepared","failed","restored","manual-reconciliation-required"},deadline)
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
    approved=repair(APPLY_API,"repair.fstab.approve",{"preparedId":detail["preparedId"],"sessionId":detail["sessionId"],"planId":detail["planId"],"planHash":detail["planHash"],"approvalId":apply_approval_id,"approvalSequence":apply_sequence,"typedConfirmation":APPLY_CONFIRMATION})
    if approved.get("state")=="executing":
        approved=wait(APPLY_API,"repair.status",{"succeeded","restored","failed","manual-reconciliation-required","cancelled"},deadline)
    source_detail=approved.get("detail")
    terminal_keys={"kind","terminalOutcome","reservationId","transactionBindingSha256","rebootRequired","prepareFailureStage"}
    if approved.get("state")!="succeeded" or not isinstance(source_detail,dict) or set(source_detail)!=terminal_keys or source_detail.get("kind")!="terminal" or source_detail.get("terminalOutcome")!="committed" or source_detail.get("reservationId")!=source_reservation or not valid_hash(source_detail.get("transactionBindingSha256")) or source_detail.get("rebootRequired") is not False or source_detail.get("prepareFailureStage") is not None:
        raise RuntimeError()
    source_receipt={"reservationId":source_detail["reservationId"],"transactionBindingSha256":source_detail["transactionBindingSha256"]}
    rollback_status=repair(ROLLBACK_API,"repair.fstab.rollback.status")
    if rollback_status.get("state")!="succeeded" or rollback_status.get("detail")!=source_detail:
        raise RuntimeError()
    rollback_prepared=repair(ROLLBACK_API,"repair.fstab.rollback.prepare",{"source":source_receipt})
    if rollback_prepared.get("state")=="preparing":
        rollback_prepared=wait(ROLLBACK_API,"repair.fstab.rollback.status",{"prepared","failed","restored","manual-reconciliation-required"},deadline)
    rollback=rollback_prepared.get("detail")
    rollback_keys={"kind","preparedId","rollbackId","sessionId","planId","planHash","targetFingerprint","source","resourceId","backupLocator","actionId","risk","nextApprovalSequence","confirmationRequired"}
    if rollback_prepared.get("state")!="prepared" or not isinstance(rollback,dict) or set(rollback)!=rollback_keys or rollback.get("kind")!="fstab-rollback-prepared" or not valid_hex(rollback.get("preparedId"),"Q-") or not valid_hex(rollback.get("rollbackId"),"RB-") or not valid_hex(rollback.get("sessionId"),"S-") or not valid_hex(rollback.get("planId"),"P-") or not valid_hash(rollback.get("planHash")) or rollback.get("targetFingerprint")!=target_fingerprint or rollback.get("source")!=source_receipt or rollback.get("resourceId")!=RESOURCE or rollback.get("backupLocator")!="vault://repair/"+source_receipt["reservationId"] or rollback.get("actionId")!="linux.fstab.restore" or rollback.get("risk")!="R2" or rollback.get("nextApprovalSequence")!=apply_sequence+1 or rollback.get("confirmationRequired")!=ROLLBACK_CONFIRMATION:
        raise RuntimeError()
    rollback_approval_id="A-"+secrets.token_hex(16)
    while rollback_approval_id==apply_approval_id:
        rollback_approval_id="A-"+secrets.token_hex(16)
    rolled_back=repair(ROLLBACK_API,"repair.fstab.rollback.approve",{"preparedId":rollback["preparedId"],"rollbackId":rollback["rollbackId"],"sessionId":rollback["sessionId"],"planId":rollback["planId"],"planHash":rollback["planHash"],"source":source_receipt,"approvalId":rollback_approval_id,"approvalSequence":rollback["nextApprovalSequence"],"typedConfirmation":ROLLBACK_CONFIRMATION})
    if rolled_back.get("state")=="executing":
        rolled_back=wait(ROLLBACK_API,"repair.fstab.rollback.status",{"restored","failed","manual-reconciliation-required","cancelled"},deadline)
    result=rolled_back.get("detail")
    if rolled_back.get("state")!="restored" or not isinstance(result,dict) or set(result)!=terminal_keys or result.get("kind")!="terminal" or result.get("terminalOutcome")!="rolled-back-original" or result.get("reservationId")!=source_receipt["reservationId"] or result.get("transactionBindingSha256")!=source_receipt["transactionBindingSha256"] or result.get("rebootRequired") is not False or result.get("prepareFailureStage") is not None:
        raise RuntimeError()
except BaseException:
    sys.exit(46)
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


def target_write_bytes(qmp: object) -> int:
    """Return the completed write-byte counter for the exact target node."""

    result = qmp.execute_result("query-blockstats", {"query-nodes": True})
    if not isinstance(result, list) or len(result) > 64:
        raise LIFECYCLE.ClosedFailure("interruption", "blockstats-invalid")
    matches = [
        item
        for item in result
        if isinstance(item, dict) and item.get("node-name") == TARGET_NODE
    ]
    if len(matches) != 1:
        raise LIFECYCLE.ClosedFailure("interruption", "target-node-invalid")
    stats = matches[0].get("stats")
    if not isinstance(stats, dict):
        raise LIFECYCLE.ClosedFailure("interruption", "blockstats-invalid")
    writes = stats.get("wr_bytes")
    if isinstance(writes, bool) or not isinstance(writes, int) or writes < 0:
        raise LIFECYCLE.ClosedFailure("interruption", "write-counter-invalid")
    return writes


def pause_vm(qmp: object, deadline: float) -> None:
    qmp.set_deadline(LIFECYCLE._deadline(deadline, 10.0))
    qmp.execute("stop")
    status_value = qmp.execute_result("query-status")
    if (
        not isinstance(status_value, dict)
        or status_value.get("running") is not False
        or status_value.get("status") != "paused"
    ):
        raise LIFECYCLE.ClosedFailure("interruption", "pause-invalid")


def interrupt_after_first_target_write(
    harness: object, qmp: object, aggregate: float
) -> None:
    # The shipping write-capability helper can expose this node only after the
    # exact Pending record has passed its durable persist-and-readback barrier.
    # Thus the first completed target write is an external witness that the cut
    # occurs after Pending, without adding a fault hook to the guest image.
    qmp.set_deadline(LIFECYCLE._deadline(aggregate, 10.0))
    if target_write_bytes(qmp) != 0:
        raise LIFECYCLE.ClosedFailure("interruption", "target-wrote-before-approval")
    pause_vm(qmp, aggregate)
    witness_deadline = LIFECYCLE._deadline(aggregate, 180.0)
    while time.monotonic() < witness_deadline:
        qmp.set_deadline(LIFECYCLE._deadline(witness_deadline, 10.0))
        qmp.execute("cont")
        time.sleep(0.005)
        pause_vm(qmp, witness_deadline)
        if target_write_bytes(qmp) > 0:
            qmp.set_deadline(LIFECYCLE._deadline(aggregate, 10.0))
            qmp.quit()
            harness.wait_for_shutdown(LIFECYCLE._deadline(aggregate, 30.0))
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
        if parsed.scenario in {"rollback", "interrupt-reconcile"} and parsed.firmware != "uefi":
            raise LIFECYCLE.ClosedFailure("arguments", "scenario-firmware-invalid")
        for digest in (parsed.before_sha256, parsed.after_sha256):
            if re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None:
                raise LIFECYCLE.ClosedFailure("arguments", "digest-invalid")
        timeout_maximum = (
            1800 if parsed.scenario in {"rollback", "interrupt-reconcile"} else 1200
        )
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
        console.wait_regex(
            re.compile(rb"KERNAID_RESCUE_FIRSTBOOT_PROMPT_READY_V1 step=passphrase"),
            start=0,
            deadline=LIFECYCLE._deadline(aggregate, 600.0),
            stage="firstboot-start",
        )
        qmp.set_deadline(LIFECYCLE._deadline(aggregate, 10.0))
        qmp.send_hex_line(key)
        confirmation = console.wait_regex(
            re.compile(rb"KERNAID_RESCUE_FIRSTBOOT_PROMPT_READY_V1 step=confirmation"),
            start=0,
            deadline=LIFECYCLE._deadline(aggregate, 600.0),
            stage="firstboot-confirmation",
        )
        qmp.set_deadline(LIFECYCLE._deadline(aggregate, 10.0))
        qmp.send_hex_line(key)
        LIFECYCLE.wait_firstboot_attestation(
            console, confirmation.end(), LIFECYCLE._deadline(aggregate, 600.0)
        )
        cursor = LIFECYCLE.establish_live_session(console, aggregate, login)
        unlocked, cursor = LIFECYCLE.run_companion(
            console, "unlock", "repair-unlock", cursor, aggregate, key
        )
        if unlocked.vault_state != "unlocked" or unlocked.device_id is None:
            raise LIFECYCLE.ClosedFailure("vault", "unlock-invalid")
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
            harness.wait_for_shutdown(LIFECYCLE._deadline(aggregate, 180.0))
        elif parsed.scenario == "rollback":
            LIFECYCLE.run_guest_proof(
                console,
                "repair-rollback",
                rollback_source(parsed.before_sha256, parsed.after_sha256),
                cursor,
                aggregate,
                timeout=720.0,
            )
            qmp.set_deadline(LIFECYCLE._deadline(aggregate, 10.0))
            qmp.system_powerdown()
            harness.wait_for_shutdown(LIFECYCLE._deadline(aggregate, 180.0))
        else:
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
            cursor = LIFECYCLE.establish_live_session(console, aggregate, login)
            unlocked, cursor = LIFECYCLE.run_companion(
                console, "unlock", "repair-recovery-unlock", cursor, aggregate, key
            )
            if unlocked.vault_state != "unlocked" or unlocked.device_id is None:
                raise LIFECYCLE.ClosedFailure("vault", "recovery-unlock-invalid")
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
            harness.wait_for_shutdown(LIFECYCLE._deadline(aggregate, 180.0))
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
        print(
            f"{FAILURE_PREFIX} stage={failure.stage} code={failure.code}",
            file=sys.stderr,
            flush=True,
        )
        return 1
    if parsed.scenario == "apply":
        action = "linux.fstab.disable-missing-uuid.v1"
        suffix = "terminal=committed approval=typed-single-use"
    elif parsed.scenario == "rollback":
        action = "linux.fstab.restore"
        suffix = (
            "source_terminal=committed terminal=rolled-back-original "
            "state=restored approval=fresh-typed-single-use"
        )
    else:
        action = "linux.fstab.disable-missing-uuid.v1"
        suffix = (
            "terminal=restored interruption=qmp-after-target-write recovery=closed"
        )
    print(
        f"{ATTESTATION_PREFIX} action={action} "
        f"firmware={parsed.firmware} scenario={parsed.scenario} "
        f"before_sha256={parsed.before_sha256} after_sha256={parsed.after_sha256} "
        f"vault_distinct=true {suffix} ready=true",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
