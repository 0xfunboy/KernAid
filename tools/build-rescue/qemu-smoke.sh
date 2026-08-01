#!/usr/bin/env bash
set -euo pipefail
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
firmware="${1:-bios}"
iso="${2:-$repo_dir/KernAid-Rescue-amd64.iso}"
if [[ "$firmware" != "bios" && "$firmware" != "uefi" ]]; then
  echo "Usage: $0 [bios|uefi] [iso]" >&2
  exit 2
fi
test -f "$iso" || { echo "ISO not found: $iso" >&2; exit 2; }
log="$(mktemp)"
trap 'rm -f "$log"' EXIT

qemu_args=(-machine accel=tcg -m 2048 -smp 2 -cdrom "$iso" -boot d -display none -serial stdio -no-reboot)
if [[ "$firmware" == "uefi" ]]; then
  ovmf_code=""
  for candidate in /usr/share/OVMF/OVMF_CODE_4M.fd /usr/share/OVMF/OVMF_CODE.fd; do
    if [[ -f "$candidate" ]]; then
      ovmf_code="$candidate"
      break
    fi
  done
  [[ -n "$ovmf_code" ]] || { echo "OVMF firmware not found" >&2; exit 2; }
  qemu_args+=(-drive "if=pflash,format=raw,readonly=on,file=$ovmf_code")
fi

set +e
timeout 240 qemu-system-x86_64 "${qemu_args[@]}" >"$log" 2>&1
status=$?
set -e
if [[ "$status" -ne 0 && "$status" -ne 124 ]]; then cat "$log"; exit "$status"; fi
grep -q "KERNAID_RESCUE_READY" "$log" || { tail -n 200 "$log"; echo "Rescue readiness marker not observed" >&2; exit 1; }
echo "PASS: KernAid Rescue booted with $firmware firmware in QEMU without an attached target disk"
