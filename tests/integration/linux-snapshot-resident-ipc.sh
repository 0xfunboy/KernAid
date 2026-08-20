#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
fixture="$repo_dir/tests/fixtures/linux-normalized-snapshot/healthy/root"
fingerprint_helper="$repo_dir/tools/test-linux-snapshot/tree_fingerprint.py"
readonly probe_name=tests::resident_linux_snapshot_tauri_ipc_chroot_probe
readonly marker_prefix=KERNAID_RESIDENT_LINUX_SNAPSHOT_E2E_V1
readonly hardware_probe_name=tests::resident_linux_hardware_tauri_ipc_probe
readonly hardware_marker_prefix=KERNAID_RESIDENT_LINUX_HARDWARE_IPC_V1

for command in cargo unshare; do
  command -v "$command" >/dev/null || {
    echo "Missing Resident IPC probe command: $command" >&2
    exit 2
  }
done
[[ "$EUID" -ne 0 ]] || {
  echo "The Resident IPC probe must start as an unprivileged user" >&2
  exit 2
}
[[ -d "$fixture" && ! -L "$fixture" ]] || {
  echo "The fixed healthy snapshot fixture is unavailable" >&2
  exit 2
}

temporary_dir="$(mktemp -d)"
cleanup() {
  rm -rf -- "$temporary_dir"
}
trap cleanup EXIT

tree_fingerprint() {
  /usr/bin/python3 -I -B "$fingerprint_helper" "$fixture"
}

before="$(tree_fingerprint)"
cargo test --locked -p kernaid-desk-shell --bin kernaid-desk-shell \
  --no-run --message-format=json >"$temporary_dir/build.jsonl"

test_executable="$(python3 -I -B - "$temporary_dir/build.jsonl" <<'PY'
import json
import os
import sys

matches = []
with open(sys.argv[1], "rb") as stream:
    for raw_line in stream:
        try:
            message = json.loads(raw_line)
        except json.JSONDecodeError:
            continue
        target = message.get("target", {})
        executable = message.get("executable")
        if (
            message.get("reason") == "compiler-artifact"
            and target.get("name") == "kernaid-desk-shell"
            and target.get("kind") == ["bin"]
            and message.get("profile", {}).get("test") is True
            and isinstance(executable, str)
        ):
            matches.append(executable)
if len(matches) != 1:
    raise SystemExit("Resident IPC test executable was not unique")
path = os.path.realpath(matches[0])
if not os.path.isfile(path) or not os.access(path, os.X_OK):
    raise SystemExit("Resident IPC test executable was not runnable")
print(path)
PY
)"

"$test_executable" \
  --exact "$hardware_probe_name" --ignored --nocapture --test-threads=1 \
  >"$temporary_dir/hardware.raw" 2>&1

python3 -I -B - "$temporary_dir/hardware.raw" "$hardware_marker_prefix" <<'PY'
import re
import sys

path, prefix = sys.argv[1:]
with open(path, "rb") as stream:
    payload = stream.read(64 * 1024 + 1)
if len(payload) > 64 * 1024 or b"\0" in payload:
    raise SystemExit("Resident hardware IPC probe output framing was invalid")
if b"KERNAID_HARDWARE_CALLER_PATH_MUST_BE_IGNORED" in payload:
    raise SystemExit("the caller path marker escaped the hardware IPC probe")
pattern = re.compile(
    rb"^" + re.escape(prefix.encode("ascii"))
    + rb" document_sha256=([0-9a-f]{64})$",
    re.MULTILINE,
)
if len(pattern.findall(payload)) != 1:
    raise SystemExit("Resident hardware IPC digest marker was not unique")
PY

unshare --user --map-root-user --mount --pid --fork \
  "$test_executable" \
  --exact "$probe_name" --ignored --nocapture --test-threads=1 \
  >"$temporary_dir/probe.raw" 2>&1

[[ "$before" == "$(tree_fingerprint)" ]] || {
  echo "The Resident IPC probe changed the shared healthy fixture" >&2
  exit 1
}

python3 -I -B - "$temporary_dir/probe.raw" "$marker_prefix" <<'PY'
import re
import sys

path, prefix = sys.argv[1:]
with open(path, "rb") as stream:
    payload = stream.read(64 * 1024 + 1)
if len(payload) > 64 * 1024 or b"\0" in payload:
    raise SystemExit("Resident IPC probe output framing was invalid")
for forbidden in (
    b"fixture-machine-id-must-never-be-projected",
    b"fixture-secret-package-name",
    b"UUID=fixture-root",
    b"server:/fixture",
    b"KERNAID_CALLER_PATH_MARKER_MUST_BE_IGNORED",
):
    if forbidden in payload:
        raise SystemExit("a raw fixture or caller marker escaped the IPC probe")
pattern = re.compile(
    rb"^" + re.escape(prefix.encode("ascii"))
    + rb" semantic_sha256=([0-9a-f]{64})$",
    re.MULTILINE,
)
matches = pattern.findall(payload)
if len(matches) != 1:
    raise SystemExit("Resident IPC digest marker was not unique")
sys.stdout.write(f"{prefix} semantic_sha256={matches[0].decode('ascii')}\n")
PY
