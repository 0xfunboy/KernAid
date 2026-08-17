#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
firmware="${1:-bios}"
iso="${2:-$repo_dir/KernAid-Rescue-amd64.iso}"
layout_manifest="$repo_dir/rescue/image-layout/device-layout.v1.json"

# These values are the immutable layout-v1 geometry validated by
# finalize-device-layout.py.  The media is deliberately sparse and p3 remains
# unprovisioned: this smoke test proves only bootability and byte invariance.
readonly media_bytes=32000000000
readonly p3_start_bytes=17179869184
readonly p3_bytes=8589934592
readonly boot_count=2
readonly boot_timeout_seconds=240

for command in awk cat cp dd dirname grep mkdir mkfs.ext4 mktemp \
  qemu-system-x86_64 rm sha256sum sleep stat tail tee truncate python3; do
  command -v "$command" >/dev/null || {
    echo "Missing required command: $command" >&2
    exit 2
  }
done

if [[ "$firmware" != "bios" && "$firmware" != "uefi" ]]; then
  echo "Usage: $0 [bios|uefi] [iso]" >&2
  exit 2
fi
[[ -f "$iso" ]] || { echo "ISO not found: $iso" >&2; exit 2; }
[[ -f "$layout_manifest" ]] || {
  echo "Layout manifest not found: $layout_manifest" >&2
  exit 2
}

python3 -I "$repo_dir/tools/build-rescue/finalize-device-layout.py" verify \
  --manifest "$layout_manifest" \
  --image "$iso"

iso_bytes="$(stat -c '%s' -- "$iso")"
if [[ ! "$iso_bytes" =~ ^[0-9]+$ ]] \
  || ((iso_bytes < 512 || iso_bytes >= p3_start_bytes)); then
  echo "Finalized ISO size is outside layout-v1 bounds" >&2
  exit 2
fi

sha256_file() {
  sha256sum -- "$1" | awk 'NR == 1 { print $1 }'
}

sha256_region() {
  local path="$1"
  local offset="$2"
  local length="$3"
  dd if="$path" bs=4M iflag=skip_bytes,count_bytes \
    skip="$offset" count="$length" status=none \
    | sha256sum | awk 'NR == 1 { print $1 }'
}

require_sha256() {
  local label="$1"
  local value="$2"
  if [[ ! "$value" =~ ^[0-9a-f]{64}$ ]]; then
    echo "$label is not a lowercase SHA-256 digest" >&2
    exit 2
  fi
}

iso_sha256="$(sha256_file "$iso")"
layout_manifest_sha256="$(sha256_file "$layout_manifest")"
require_sha256 "ISO digest" "$iso_sha256"
require_sha256 "layout manifest digest" "$layout_manifest_sha256"

log="${KERNAID_USB_SMOKE_LOG:-}"
temporary_log=0
if [[ -z "$log" ]]; then
  log="$(mktemp -t kernaid-qemu-usb-log.XXXXXXXX)"
  temporary_log=1
else
  if [[ -L "$log" || (-e "$log" && ! -f "$log") ]]; then
    echo "USB smoke log must be a regular, non-symlink path" >&2
    exit 2
  fi
  log_parent="$(dirname "$log")"
  [[ -d "$log_parent" ]] || {
    echo "USB smoke log parent directory does not exist: $log_parent" >&2
    exit 2
  }
  : >"$log"
fi

work_dir="$(mktemp -d -t kernaid-qemu-usb.XXXXXXXX)"
rescue_media="$work_dir/KernAid-Rescue-usb.raw"
target_image="$work_dir/disposable-target.raw"
target_seed_dir="$work_dir/target-seed"
mkdir "$target_seed_dir"
printf '%s\n' KERNAID_OBSERVE_TARGET_SENTINEL >"$target_seed_dir/README.txt"

qemu_pid=""
# shellcheck disable=SC2329  # Invoked indirectly by the EXIT trap below.
# shellcheck disable=SC2317
cleanup() {
  if [[ -n "$qemu_pid" ]]; then
    kill "$qemu_pid" 2>/dev/null || true
    wait "$qemu_pid" 2>/dev/null || true
    qemu_pid=""
  fi
  if [[ "$temporary_log" == "1" ]]; then
    rm -f -- "$log"
  fi
  case "$work_dir" in
    /tmp/kernaid-qemu-usb.* | "${TMPDIR:-/tmp}"/kernaid-qemu-usb.*)
      rm -rf -- "$work_dir"
      ;;
    *)
      echo "Refusing to remove unexpected temporary path: $work_dir" >&2
      ;;
  esac
}
trap cleanup EXIT

truncate -s "$media_bytes" -- "$rescue_media"
# The ISO is copied only into the media prefix.  conv=notrunc is essential:
# the sparse 32,000,000,000-byte media and its p3 region must remain present.
dd if="$iso" of="$rescue_media" bs=4M conv=notrunc status=none
actual_media_bytes="$(stat -c '%s' -- "$rescue_media")"
if [[ "$actual_media_bytes" != "$media_bytes" ]]; then
  echo "USB-style raw media has the wrong byte length" >&2
  exit 1
fi

truncate -s 128M -- "$target_image"
mkfs.ext4 -q -F -L KERNAID_TARGET -d "$target_seed_dir" "$target_image"

prefix_before_sha256="$(sha256_region "$rescue_media" 0 "$iso_bytes")"
p3_before_sha256="$(
  sha256_region "$rescue_media" "$p3_start_bytes" "$p3_bytes"
)"
target_before_sha256="$(sha256_file "$target_image")"
require_sha256 "media prefix digest" "$prefix_before_sha256"
require_sha256 "p3 digest" "$p3_before_sha256"
require_sha256 "target digest" "$target_before_sha256"
if [[ "$prefix_before_sha256" != "$iso_sha256" ]]; then
  echo "USB-style media prefix does not match the finalized ISO" >&2
  exit 1
fi

ovmf_code=""
ovmf_vars_template=""
uefi_vars_attestation="not-applicable"
if [[ "$firmware" == "uefi" ]]; then
  for pair in \
    "/usr/share/OVMF/OVMF_CODE_4M.fd:/usr/share/OVMF/OVMF_VARS_4M.fd" \
    "/usr/share/OVMF/OVMF_CODE.fd:/usr/share/OVMF/OVMF_VARS.fd"; do
    candidate_code="${pair%%:*}"
    candidate_vars="${pair#*:}"
    if [[ -f "$candidate_code" && -f "$candidate_vars" ]]; then
      ovmf_code="$candidate_code"
      ovmf_vars_template="$candidate_vars"
      break
    fi
  done
  if [[ -z "$ovmf_code" || -z "$ovmf_vars_template" ]]; then
    echo "A matching OVMF CODE/VARS firmware pair was not found" >&2
    exit 2
  fi
  uefi_vars_attestation="fresh-per-boot"
fi

stop_qemu() {
  if [[ -n "$qemu_pid" ]]; then
    kill "$qemu_pid" 2>/dev/null || true
    wait "$qemu_pid" 2>/dev/null || true
    qemu_pid=""
  fi
}

assert_images_unchanged() {
  local boot="$1"
  local prefix_after
  local p3_after
  local target_after

  prefix_after="$(sha256_region "$rescue_media" 0 "$iso_bytes")"
  p3_after="$(sha256_region "$rescue_media" "$p3_start_bytes" "$p3_bytes")"
  target_after="$(sha256_file "$target_image")"
  require_sha256 "boot $boot media prefix digest" "$prefix_after"
  require_sha256 "boot $boot p3 digest" "$p3_after"
  require_sha256 "boot $boot target digest" "$target_after"

  if [[ "$prefix_after" != "$iso_sha256" ]] \
    || [[ "$prefix_after" != "$prefix_before_sha256" ]]; then
    echo "Boot $boot modified the finalized ISO prefix" >&2
    exit 1
  fi
  if [[ "$p3_after" != "$p3_before_sha256" ]]; then
    echo "Boot $boot modified the unprovisioned p3 region" >&2
    exit 1
  fi
  if [[ "$target_after" != "$target_before_sha256" ]]; then
    echo "Boot $boot modified the disposable virtio target" >&2
    exit 1
  fi
}

run_boot() {
  local boot="$1"
  local boot_log="$work_dir/qemu-$firmware-boot-$boot.log"
  # QEMU's -drive and -device values are deliberately comma-delimited strings.
  # shellcheck disable=SC2054
  local qemu_args=(
    -machine accel=tcg
    -m 2048
    -smp 2
    -device qemu-xhci,id=kernaid_xhci
    -drive "if=none,id=kernaid_rescue_usb,file=$rescue_media,format=raw,cache=none,aio=threads"
    -device "usb-storage,bus=kernaid_xhci.0,drive=kernaid_rescue_usb,bootindex=1"
    -drive "file=$target_image,if=virtio,format=raw,cache=none,aio=threads"
    -display none
    -serial stdio
    -no-reboot
  )

  if [[ "$firmware" == "uefi" ]]; then
    local ovmf_vars_copy="$work_dir/OVMF_VARS.boot-$boot.fd"
    [[ ! -e "$ovmf_vars_copy" ]] || {
      echo "Refusing to reuse UEFI VARS for boot $boot" >&2
      exit 2
    }
    cp --reflink=auto --sparse=always -- "$ovmf_vars_template" "$ovmf_vars_copy"
    qemu_args+=(
      -drive "if=pflash,format=raw,readonly=on,file=$ovmf_code"
      -drive "if=pflash,format=raw,file=$ovmf_vars_copy"
    )
  fi

  qemu-system-x86_64 "${qemu_args[@]}" >"$boot_log" 2>&1 &
  qemu_pid=$!
  for ((attempt = 1; attempt <= boot_timeout_seconds; attempt++)); do
    if grep -Fq "KERNAID_RESCUE_READY" "$boot_log" \
      && grep -Fq "KERNAID_RESCUE_TARGET_SELECTION_READY" "$boot_log"; then
      stop_qemu
      {
        printf '%s\n' "===== QEMU USB $firmware boot $boot ====="
        cat "$boot_log"
      } >>"$log"
      assert_images_unchanged "$boot"
      printf '%s\n' \
        "KERNAID_QEMU_USB_BOOT_READY_V1 firmware=$firmware boot=$boot ready=true" \
        | tee -a "$log"
      return 0
    fi
    if ! kill -0 "$qemu_pid" 2>/dev/null; then
      set +e
      wait "$qemu_pid"
      status=$?
      set -e
      qemu_pid=""
      {
        printf '%s\n' "===== QEMU USB $firmware boot $boot ====="
        cat "$boot_log"
      } >>"$log"
      tail -n 200 "$boot_log"
      echo "QEMU USB boot $boot exited before both readiness markers (status $status)" >&2
      return 1
    fi
    sleep 1
  done

  stop_qemu
  {
    printf '%s\n' "===== QEMU USB $firmware boot $boot ====="
    cat "$boot_log"
  } >>"$log"
  tail -n 200 "$boot_log"
  echo "QEMU USB boot $boot did not become ready within $boot_timeout_seconds seconds" >&2
  return 1
}

for ((boot = 1; boot <= boot_count; boot++)); do
  run_boot "$boot"
done

prefix_after_sha256="$(sha256_region "$rescue_media" 0 "$iso_bytes")"
p3_after_sha256="$(
  sha256_region "$rescue_media" "$p3_start_bytes" "$p3_bytes"
)"
target_after_sha256="$(sha256_file "$target_image")"
layout_manifest_after_sha256="$(sha256_file "$layout_manifest")"
for digest in \
  "$prefix_after_sha256" "$p3_after_sha256" "$target_after_sha256" \
  "$layout_manifest_after_sha256"; do
  require_sha256 "final USB smoke digest" "$digest"
done

if [[ "$prefix_after_sha256" != "$iso_sha256" ]] \
  || [[ "$prefix_after_sha256" != "$prefix_before_sha256" ]] \
  || [[ "$p3_after_sha256" != "$p3_before_sha256" ]] \
  || [[ "$target_after_sha256" != "$target_before_sha256" ]] \
  || [[ "$layout_manifest_after_sha256" != "$layout_manifest_sha256" ]]; then
  echo "Final USB-style media invariants do not match their baselines" >&2
  exit 1
fi

printf '%s\n' \
  "KERNAID_QEMU_USB_ATTESTATION_V1 firmware=$firmware transport=usb-storage boot_count=$boot_count ready_boots=$boot_count uefi_vars=$uefi_vars_attestation media_bytes=$media_bytes iso_bytes=$iso_bytes layout_manifest_sha256=$layout_manifest_sha256 iso_sha256=$iso_sha256 prefix_before_sha256=$prefix_before_sha256 prefix_after_sha256=$prefix_after_sha256 p3_start_bytes=$p3_start_bytes p3_bytes=$p3_bytes p3_before_sha256=$p3_before_sha256 p3_after_sha256=$p3_after_sha256 target_before_sha256=$target_before_sha256 target_after_sha256=$target_after_sha256 ready=true" \
  | tee -a "$log"
echo "PASS: KernAid Rescue completed two $firmware USB-storage boots with unchanged prefix, p3, and virtio target"
