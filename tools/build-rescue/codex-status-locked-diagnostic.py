#!/usr/bin/env python3
"""Run the closed Codex status probe against an exact, still-locked Rescue ISO."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import time


def load_controller(path: Path):
    spec = importlib.util.spec_from_file_location("kernaid_lifecycle_diagnostic", path)
    if spec is None or spec.loader is None:
        raise RuntimeError
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def main() -> int:
    if len(sys.argv) != 4:
        print("KERNAID_CODEX_LOCKED_DIAGNOSTIC_V1 stage=arguments code=invalid")
        return 1
    controller_path = Path(sys.argv[1])
    iso_path = Path(sys.argv[2])
    credential_path = Path(sys.argv[3])
    controller = load_controller(controller_path)
    credential = bytearray()
    harness = None
    failure_stage = "diagnostic"
    failure_code = "unexpected"
    try:
        credential_fd = os.open(
            credential_path,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        credential = controller.read_login_credential_fd(credential_fd)
        with tempfile.TemporaryDirectory(prefix="kernaid-codex-locked-") as temporary:
            temporary_path = Path(temporary)
            os.chmod(temporary_path, 0o700)
            aggregate = time.monotonic() + 1_200.0
            harness = controller.QemuHarness(
                "/usr/bin/qemu-system-x86_64",
                (
                    "-machine",
                    "accel=tcg",
                    "-m",
                    "2048",
                    "-smp",
                    "2",
                    "-nic",
                    "none",
                    "-boot",
                    "d",
                    "-drive",
                    f"file={iso_path},media=cdrom,format=raw,readonly=on",
                ),
                temporary_path / "qmp.sock",
                (credential,),
                (credential,),
            )
            console, qmp = harness.start(controller._deadline(aggregate, 30.0))
            cursor = controller.establish_live_session(console, aggregate, credential)
            try:
                controller.run_guest_proof(
                    console,
                    "codex-status",
                    controller._codex_status_probe_source(),
                    cursor,
                    aggregate,
                    timeout=75.0,
                )
            except controller.ClosedFailure as error:
                failure_stage = error.stage
                failure_code = error.code
            else:
                failure_stage = "codex-status"
                failure_code = "unexpected-unlocked"
            try:
                qmp.set_deadline(controller._deadline(aggregate, 10.0))
                qmp.system_powerdown()
                harness.wait_for_shutdown(controller._deadline(aggregate, 60.0))
            except BaseException:
                pass
    except controller.ClosedFailure as error:
        failure_stage = error.stage
        failure_code = error.code
    except BaseException:
        failure_stage = "diagnostic"
        failure_code = "unexpected"
    finally:
        if harness is not None:
            try:
                harness.cleanup()
            except BaseException:
                failure_stage = "cleanup"
                failure_code = "failed"
        controller.wipe(credential)
    if controller.TOKEN_RE.fullmatch(failure_stage) is None:
        failure_stage = "diagnostic"
        failure_code = "invalid-token"
    if controller.TOKEN_RE.fullmatch(failure_code) is None:
        failure_stage = "diagnostic"
        failure_code = "invalid-token"
    print(
        "KERNAID_CODEX_LOCKED_DIAGNOSTIC_V1 "
        f"stage={failure_stage} code={failure_code}"
    )
    expected = (
        failure_stage == "provider-proof"
        and failure_code == "codex-status-client-vault-locked"
    )
    return 0 if expected else 1


if __name__ == "__main__":
    raise SystemExit(main())
