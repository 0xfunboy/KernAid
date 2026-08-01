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
log="${KERNAID_SMOKE_LOG:-$(mktemp)}"
temporary_log=0
if [[ -z "${KERNAID_SMOKE_LOG:-}" ]]; then temporary_log=1; fi
target_image="$(mktemp)"
truncate -s 64M "$target_image"
target_hash_before="$(sha256sum "$target_image" | awk '{print $1}')"
qemu_pid=""
cleanup() {
  if [[ -n "$qemu_pid" ]]; then kill "$qemu_pid" 2>/dev/null || true; fi
  if [[ "$temporary_log" == "1" ]]; then rm -f "$log"; fi
  rm -f "$target_image"
}
trap cleanup EXIT

qemu_args=(-machine accel=tcg -m 2048 -smp 2 -cdrom "$iso" -drive "file=$target_image,if=virtio,format=raw,cache=none" -boot d -display none -serial stdio -no-reboot)
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

qemu-system-x86_64 "${qemu_args[@]}" >"$log" 2>&1 &
qemu_pid=$!
for _attempt in $(seq 1 240); do
  if grep -q "KERNAID_RESCUE_READY" "$log"; then
    kill "$qemu_pid" 2>/dev/null || true
    wait "$qemu_pid" 2>/dev/null || true
    qemu_pid=""
    target_hash_after="$(sha256sum "$target_image" | awk '{print $1}')"
    if [[ "$target_hash_after" != "$target_hash_before" ]]; then
      echo "Rescue Observe boot modified the disposable target image" >&2
      exit 1
    fi
    echo "PASS: KernAid Rescue booted with $firmware firmware and made zero target-image writes"
    exit 0
  fi
  if ! kill -0 "$qemu_pid" 2>/dev/null; then
    set +e
    wait "$qemu_pid"
    status=$?
    set -e
    qemu_pid=""
    cat "$log"
    echo "QEMU exited before the Rescue readiness marker (status $status)" >&2
    exit 1
  fi
  sleep 1
done
tail -n 200 "$log"
echo "Rescue readiness marker not observed within 240 seconds" >&2
exit 1
