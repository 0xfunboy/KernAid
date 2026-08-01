#!/usr/bin/env bash
set -euo pipefail
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
iso="${1:-$repo_dir/KernAid-Rescue-amd64.iso}"
test -f "$iso" || { echo "ISO not found: $iso" >&2; exit 2; }
log="$(mktemp)"
trap 'rm -f "$log"' EXIT
set +e
timeout 240 qemu-system-x86_64 -machine accel=tcg -m 2048 -smp 2 -cdrom "$iso" -boot d -display none -serial stdio -no-reboot >"$log" 2>&1
status=$?
set -e
if [[ "$status" -ne 0 && "$status" -ne 124 ]]; then cat "$log"; exit "$status"; fi
grep -q "KERNAID_RESCUE_READY" "$log" || { tail -n 200 "$log"; echo "Rescue readiness marker not observed" >&2; exit 1; }
echo "PASS: KernAid Rescue booted in QEMU without an attached target disk"
