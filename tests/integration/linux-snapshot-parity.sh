#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
expected_dir="$repo_dir/tests/fixtures/linux-normalized-snapshot/expected"
fingerprint_helper="$repo_dir/tools/test-linux-snapshot/tree_fingerprint.py"

temporary_dir="$(mktemp -d)"
cleanup() {
  rm -rf -- "$temporary_dir"
}
trap cleanup EXIT

tree_fingerprint() {
  local fixture="$1"
  /usr/bin/python3 -I -B "$fingerprint_helper" "$fixture"
}

if cargo run --quiet \
  -p kernaid-linux-pack \
  --features fixture-snapshot-cli \
  --bin kernaid-linux-snapshot-fixture \
  -- "$repo_dir/tests/fixtures/linux-normalized-snapshot/healthy/root" >/dev/null 2>&1; then
  echo "fixture collector accepted a caller-supplied path" >&2
  exit 3
fi

for fixture_name in healthy multi-fs; do
  fixture="$repo_dir/tests/fixtures/linux-normalized-snapshot/$fixture_name/root"
  case "$fixture" in
    "$repo_dir"/tests/fixtures/linux-normalized-snapshot/healthy/root|\
    "$repo_dir"/tests/fixtures/linux-normalized-snapshot/multi-fs/root) ;;
    *) echo "unsafe Linux snapshot fixture path" >&2; exit 2 ;;
  esac
  if [[ "$fixture_name" == "healthy" ]]; then
    expected_snapshot="$expected_dir/snapshot.v1.json"
    expected_hash="$expected_dir/snapshot.v1.sha256"
  else
    expected_snapshot="$expected_dir/multi-fs.snapshot.v1.json"
    expected_hash="$expected_dir/multi-fs.snapshot.v1.sha256"
  fi
  before="$(tree_fingerprint "$fixture")"
  cargo run --quiet \
    -p kernaid-linux-pack \
    --features fixture-snapshot-cli \
    --bin kernaid-linux-snapshot-fixture \
    -- "$fixture_name" >"$temporary_dir/$fixture_name.resident.json"
  test "$before" = "$(tree_fingerprint "$fixture")"

  python3 "$repo_dir/tools/test-linux-snapshot/rescue_projection.py" "$fixture_name" \
    >"$temporary_dir/$fixture_name.rescue.json"
  test "$before" = "$(tree_fingerprint "$fixture")"

  python3 - \
  "$temporary_dir/$fixture_name.resident.json" \
  "$temporary_dir/$fixture_name.rescue.json" \
  "$expected_snapshot" \
  "$expected_hash" \
  "$fixture_name" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

resident_path, rescue_path, golden_path, hash_path = map(Path, sys.argv[1:5])
fixture_name = sys.argv[5]
resident_bytes = resident_path.read_bytes()
rescue_bytes = rescue_path.read_bytes()
resident = json.loads(resident_bytes)
rescue = json.loads(rescue_bytes)
golden_bytes = golden_path.read_bytes().rstrip(b"\n")
expected_hash = hash_path.read_text(encoding="ascii").strip()

for secret in (
    b"fixture-machine-id-must-never-be-projected",
    b"fixture-secret-package-name",
    b"UUID=fixture-root",
    b"server:/fixture",
    b"cross-device-kernel-placeholder-must-not-be-consumed",
    b"cross-device-usr-placeholder-must-not-be-consumed",
    b"cross-device-var-placeholder-must-not-be-consumed",
):
    assert secret not in resident_bytes
    assert secret not in rescue_bytes

assert resident_bytes == json.dumps(
    resident, ensure_ascii=False, separators=(",", ":")
).encode("utf-8")
assert rescue_bytes == json.dumps(
    rescue, ensure_ascii=False, separators=(",", ":")
).encode("utf-8")
assert resident["capture"] == {
    "mode": "resident",
    "targetScope": "running-root",
    "accessPolicy": "fixed-descriptor-read-only",
    "callerSuppliedPath": False,
    "mutationRequested": False,
    "crossDeviceTraversalAllowed": False,
}
assert rescue["capture"] == {
    "mode": "rescue",
    "targetScope": "selected-installed-target",
    "accessPolicy": "temporary-read-only-no-replay",
    "deviceOpenedReadOnly": True,
    "journalReplayPrevented": True,
    "privateMountNamespace": True,
    "mountCleanupVerified": True,
    "mutationPerformed": False,
    "crossDeviceTraversalAllowed": False,
}
assert resident["snapshot"] == rescue["snapshot"]
snapshot_bytes = json.dumps(
    resident["snapshot"], ensure_ascii=False, separators=(",", ":")
).encode("utf-8")
assert snapshot_bytes == golden_bytes
actual_hash = hashlib.sha256(
    b"KERNAID_LINUX_NORMALIZED_SNAPSHOT_V1\0" + snapshot_bytes
).hexdigest()
assert actual_hash == resident["snapshotSha256"]
assert actual_hash == rescue["snapshotSha256"]
assert actual_hash == expected_hash
if fixture_name == "healthy":
    assert resident["snapshot"]["topology"]["supported"] is True
else:
    topology = resident["snapshot"]["topology"]
    assert topology["relevantSeparateMountPresent"] is True
    assert topology["supported"] is False
    assert resident["snapshot"]["release"]["source"] == "absent"
    assert resident["snapshot"]["configuration"]["machineIdPresent"] is False
    assert resident["snapshot"]["boot"]["directoryPresent"] is False
    assert not any(resident["snapshot"]["packageDatabases"].values())
PY
done

echo "PASS: Resident and Rescue snapshots match goldens without content or tracked-metadata changes"
