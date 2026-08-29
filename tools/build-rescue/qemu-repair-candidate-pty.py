#!/usr/bin/env python3
"""Bounded PTY controller for the disposable Rescue repair qualification."""

from __future__ import annotations

import argparse
import importlib.util
import os
import re
import signal
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
    value.add_argument("--vault-key-fd", type=int, required=True)
    value.add_argument("--login-credential-fd", type=int, required=True)
    value.add_argument("--before-sha256", required=True)
    value.add_argument("--after-sha256", required=True)
    value.add_argument("--timeout", type=float, default=900.0)
    value.add_argument("qemu_args", nargs=argparse.REMAINDER)
    return value


def repair_source(before_sha256: str, after_sha256: str) -> bytes:
    # This source is fixed by the qualification controller. It supplies only
    # opaque target claims and the exact typed approval accepted by production.
    checkpoints = ",".join(
        repr(checkpoint)
        for checkpoint in LIFECYCLE.PROVIDER_PROOF_REPAIR_CHECKPOINTS
    )
    source = f'''import hashlib,http.client,json,secrets,subprocess,sys,time
HOST="127.0.0.1:4173"
ORIGIN="http://127.0.0.1:4173"
API="kernaid.dev/rescue-repair-service/v1alpha1"
BEFORE={before_sha256!r}
AFTER={after_sha256!r}
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
    sys.stdout.write("KERNAID_QEMU_PROVIDER_PROOF_FAILURE_V1 stage=repair-apply checkpoint="+value+"\\n")
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
    checkpoint="approve-submit"
    approved=repair({{"apiVersion":API,"requestId":request_id(),"operation":"repair.fstab.approve","preparedId":detail["preparedId"],"sessionId":detail["sessionId"],"planId":detail["planId"],"planHash":detail["planHash"],"approvalId":"A-"+secrets.token_hex(16),"approvalSequence":detail["nextApprovalSequence"],"typedConfirmation":"DISABILITA VOCE FSTAB"}})
    if approved.get("state") not in ("executing","succeeded","restored","failed","manual-reconciliation-required","cancelled"):
        raise RuntimeError()
    checkpoint="execute-terminal"
    terminal=approved if approved.get("state")!="executing" else status_until({{"succeeded","restored","failed","manual-reconciliation-required","cancelled"}},deadline)
    checkpoint="execute-state"
    if terminal.get("state")!="succeeded":
        checkpoint=execute_state_checkpoint(terminal)
        if checkpoint=="execute-state-failed":
            checkpoint=execution_error_checkpoint()
        raise RuntimeError()
    checkpoint="execute-contract"
    terminal_detail=terminal.get("detail",{{}})
    if terminal_detail.get("terminalOutcome")!="committed" or not isinstance(terminal_detail.get("reservationId"),str) or not isinstance(terminal_detail.get("transactionBindingSha256"),str):
        raise RuntimeError()
except BaseException:
    fail(checkpoint)
sys.stdout.write("KERNAID_QEMU_PROVIDER_PROOF_V1 stage=repair-apply result=true\\n")
'''
    return textwrap.dedent(source).encode("ascii")


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
        for digest in (parsed.before_sha256, parsed.after_sha256):
            if re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None:
                raise LIFECYCLE.ClosedFailure("arguments", "digest-invalid")
        if parsed.before_sha256 == parsed.after_sha256 or not 300 <= parsed.timeout <= 1200:
            raise LIFECYCLE.ClosedFailure("arguments", "invalid")
        prior_handlers, prior_mask = LIFECYCLE.install_signal_guard()
        key = LIFECYCLE.read_secret_fd(parsed.vault_key_fd, expected_uid=os.geteuid())
        login = LIFECYCLE.read_login_credential_fd(
            parsed.login_credential_fd, expected_uid=os.geteuid()
        )
        aggregate = time.monotonic() + parsed.timeout
        harness = LIFECYCLE.QemuHarness(
            parsed.qemu,
            parsed.qemu_args[1:],
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
    print(
        f"{ATTESTATION_PREFIX} action=linux.fstab.disable-missing-uuid.v1 "
        f"before_sha256={parsed.before_sha256} after_sha256={parsed.after_sha256} "
        "vault_distinct=true terminal=committed approval=typed-single-use ready=true",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
