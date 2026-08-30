#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd -- "${BASH_SOURCE[0]%/*}/../.." && pwd -P)"
readonly resident_harness="$repo_dir/tests/integration/linux-snapshot-resident-ipc.sh"
readonly qemu_smoke="$repo_dir/tools/build-rescue/qemu-smoke.sh"

if (( $# < 1 || $# > 2 )); then
  echo "Usage: $0 [bios|uefi|secureboot] [iso]" >&2
  exit 2
fi
readonly firmware="$1"
readonly iso="${2:-$repo_dir/KernAid-Rescue-amd64.iso}"
if [[ "$firmware" != "bios" && "$firmware" != "uefi" \
  && "$firmware" != "secureboot" ]]; then
  echo "Usage: $0 [bios|uefi|secureboot] [iso]" >&2
  exit 2
fi

resident_marker="$($resident_harness)"
if [[ ! "$resident_marker" =~ ^KERNAID_RESIDENT_LINUX_SNAPSHOT_E2E_V1\ semantic_sha256=([0-9a-f]{64})$ ]]; then
  echo "Resident snapshot evidence was outside the allowlist" >&2
  exit 1
fi
export KERNAID_RESIDENT_SNAPSHOT_SEMANTIC_SHA256="${BASH_REMATCH[1]}"

exec "$qemu_smoke" "$firmware" "$iso"
