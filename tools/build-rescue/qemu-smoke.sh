#!/usr/bin/env bash
set -euo pipefail
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
firmware="${1:-bios}"
iso="${2:-$repo_dir/KernAid-Rescue-amd64.iso}"
for command in python3 qemu-system-x86_64 sha256sum mkfs.ext4 tee truncate; do
  command -v "$command" >/dev/null || { echo "Missing required command: $command" >&2; exit 2; }
done
if [[ "$firmware" != "bios" && "$firmware" != "uefi" ]]; then
  echo "Usage: $0 [bios|uefi] [iso]" >&2
  exit 2
fi
test -f "$iso" || { echo "ISO not found: $iso" >&2; exit 2; }
python3 -I "$repo_dir/tools/build-rescue/finalize-device-layout.py" verify \
  --manifest "$repo_dir/rescue/image-layout/device-layout.v1.json" \
  --image "$iso"
iso_hash_before="$(sha256sum "$iso" | awk '{print $1}')"
log="${KERNAID_SMOKE_LOG:-$(mktemp)}"
temporary_log=0
if [[ -z "${KERNAID_SMOKE_LOG:-}" ]]; then temporary_log=1; fi
target_image="$(mktemp)"
target_seed_dir="$(mktemp -d)"
printf '%s\n' KERNAID_OBSERVE_TARGET_SENTINEL > "$target_seed_dir/README.txt"
truncate -s 128M "$target_image"
mkfs.ext4 -q -F -L KERNAID_TARGET -d "$target_seed_dir" "$target_image"
target_hash_before="$(sha256sum "$target_image" | awk '{print $1}')"
qemu_pid=""
# shellcheck disable=SC2329  # Invoked indirectly by the EXIT trap below.
# This callback is reached indirectly through the EXIT trap below.
# shellcheck disable=SC2317
cleanup() {
  if [[ -n "$qemu_pid" ]]; then kill "$qemu_pid" 2>/dev/null || true; fi
  if [[ "$temporary_log" == "1" ]]; then rm -f "$log"; fi
  rm -f "$target_image"
  rm -rf "$target_seed_dir"
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
  if grep -q "KERNAID_RESCUE_READY" "$log" \
    && grep -q "KERNAID_RESCUE_TARGET_SELECTION_READY" "$log"; then
    kill "$qemu_pid" 2>/dev/null || true
    wait "$qemu_pid" 2>/dev/null || true
    qemu_pid=""
    target_hash_after="$(sha256sum "$target_image" | awk '{print $1}')"
    if [[ "$target_hash_after" != "$target_hash_before" ]]; then
      echo "Rescue Observe boot modified the disposable target image" >&2
      exit 1
    fi
    iso_hash_after="$(sha256sum "$iso" | awk '{print $1}')"
    if [[ "$iso_hash_after" != "$iso_hash_before" ]]; then
      echo "Rescue ISO changed during the QEMU smoke test" >&2
      exit 1
    fi
    printf '%s\n' \
      "KERNAID_QEMU_ATTESTATION_V1 firmware=$firmware iso_sha256=$iso_hash_after target_before_sha256=$target_hash_before target_after_sha256=$target_hash_after ready=true" \
      | tee -a "$log"
    echo "PASS: KernAid Rescue booted with $firmware firmware, validated the fixture target selection, and made zero target-image writes"
    exit 0
  fi
  if ! kill -0 "$qemu_pid" 2>/dev/null; then
    set +e
    wait "$qemu_pid"
    status=$?
    set -e
    qemu_pid=""
    cat "$log"
    echo "QEMU exited before both Rescue readiness markers (status $status)" >&2
    exit 1
  fi
  sleep 1
done
tail -n 200 "$log"
echo "The required Rescue readiness markers were not both observed within 240 seconds" >&2
exit 1
