#!/usr/bin/env bash
set -euo pipefail
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
firmware="${1:-bios}"
iso="${2:-$repo_dir/KernAid-Rescue-amd64.iso}"
for command in cp debugfs findmnt fusermount3 mkfs.ext4 mkfs.ntfs ntfs-3g \
  ntfsfix python3 qemu-system-x86_64 sha256sum sync tee truncate; do
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
windows_target_image="$(mktemp)"
altered_windows_target_image="$(mktemp)"
target_seed_dir="$(mktemp -d)"
windows_seed_mount="$(mktemp -d)"
qemu_pid=""
windows_fixture_mounted=0
# shellcheck disable=SC2329  # Invoked indirectly by the EXIT trap below.
# This callback is reached indirectly through the EXIT trap below.
# shellcheck disable=SC2317
cleanup() {
  if [[ -n "$qemu_pid" ]]; then kill "$qemu_pid" 2>/dev/null || true; fi
  if [[ "$windows_fixture_mounted" == "1" ]]; then
    fusermount3 -u "$windows_seed_mount" 2>/dev/null || true
  fi
  if [[ "$temporary_log" == "1" ]]; then rm -f "$log"; fi
  rm -f "$target_image" "$windows_target_image" "$altered_windows_target_image"
  rm -rf "$target_seed_dir" "$windows_seed_mount"
}
trap cleanup EXIT
mkdir -p "$target_seed_dir/etc" "$target_seed_dir/usr/lib" \
  "$target_seed_dir/boot/grub" "$target_seed_dir/var/lib/dpkg"
cat >"$target_seed_dir/etc/os-release" <<'EOF'
ID=kernaid-qemu-fixture
NAME="KernAid QEMU Fixture"
PRETTY_NAME="KernAid deterministic installed-Linux fixture"
VERSION_ID="1"
EOF
cat >"$target_seed_dir/etc/fstab" <<'EOF'
LABEL=KERNAID_TARGET / ext4 defaults 0 1
EOF
printf '%s\n' KERNAID_OBSERVE_TARGET_SENTINEL > \
  "$target_seed_dir/boot/vmlinuz-kernaid-fixture"
printf '%s\n' 'Package: kernaid-fixture' > \
  "$target_seed_dir/var/lib/dpkg/status"
truncate -s 128M "$target_image"
mkfs.ext4 -q -F -L KERNAID_TARGET -d "$target_seed_dir" "$target_image"
# A read-only ext4 mount can still replay a journal. Mark the disposable
# fixture as needing recovery before the baseline hash; the qualified helper
# must mount it with noload and leave every raw byte unchanged.
debugfs -w -R 'feature needs_recovery' "$target_image" >/dev/null 2>&1
target_hash_before="$(sha256sum "$target_image" | awk '{print $1}')"
truncate -s 128M "$windows_target_image"
mkfs.ntfs -q -F -L KERNAID_WINDOWS_TARGET "$windows_target_image"
ntfs-3g "$windows_target_image" "$windows_seed_mount" \
  -o rw,nodev,nosuid,noexec
windows_fixture_mounted=1
mkdir -p "$windows_seed_mount/Windows/System32/config" \
  "$windows_seed_mount/Windows/WinSxS" "$windows_seed_mount/Users" \
  "$windows_seed_mount/Boot"
printf '%s\n' KERNAID_WINDOWS_KERNEL_FIXTURE > \
  "$windows_seed_mount/Windows/System32/ntoskrnl.exe"
printf '%s\n' KERNAID_WINDOWS_SYSTEM_HIVE_FIXTURE > \
  "$windows_seed_mount/Windows/System32/config/SYSTEM"
printf '%s\n' KERNAID_WINDOWS_SOFTWARE_HIVE_FIXTURE > \
  "$windows_seed_mount/Windows/System32/config/SOFTWARE"
printf '%s\n' KERNAID_WINDOWS_PENDING_FIXTURE > \
  "$windows_seed_mount/Windows/WinSxS/pending.xml"
printf '%s\n' KERNAID_WINDOWS_BOOT_MANAGER_FIXTURE > \
  "$windows_seed_mount/bootmgr"
printf '%s\n' KERNAID_WINDOWS_BCD_FIXTURE > \
  "$windows_seed_mount/Boot/BCD"
sync "$windows_seed_mount"
fusermount3 -u "$windows_seed_mount"
if findmnt -rn --mountpoint "$windows_seed_mount" >/dev/null; then
  echo "Disposable Windows fixture remained mounted" >&2
  exit 1
fi
windows_fixture_mounted=0
windows_target_hash_before="$(sha256sum "$windows_target_image" | awk '{print $1}')"
cp --reflink=auto --sparse=always \
  "$windows_target_image" "$altered_windows_target_image"
# ntfsfix deliberately schedules this disposable clone for a Windows check.
# The guest must inspect it through the kernel ntfs3 driver using MS_RDONLY,
# without `force` and without claiming that its volume state is qualified.
ntfsfix "$altered_windows_target_image" >/dev/null
altered_windows_target_hash_before="$(sha256sum "$altered_windows_target_image" | awk '{print $1}')"

qemu_args=(-machine accel=tcg -m 2048 -smp 2 -cdrom "$iso" \
  -drive "file=$target_image,if=virtio,format=raw,cache=none" \
  -drive "file=$windows_target_image,if=virtio,format=raw,cache=none" \
  -drive "file=$altered_windows_target_image,if=virtio,format=raw,cache=none" \
  -fw_cfg "name=opt/kernaid-offline-inspection,string=v1" \
  -boot d -display none -serial stdio -no-reboot)
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
    && grep -q "KERNAID_RESCUE_TARGET_SELECTION_READY" "$log" \
    && grep -q "KERNAID_RESCUE_OFFLINE_INSPECTION_READY" "$log"; then
    kill "$qemu_pid" 2>/dev/null || true
    wait "$qemu_pid" 2>/dev/null || true
    qemu_pid=""
    target_hash_after="$(sha256sum "$target_image" | awk '{print $1}')"
    if [[ "$target_hash_after" != "$target_hash_before" ]]; then
      echo "Rescue Observe boot modified the disposable target image" >&2
      exit 1
    fi
    windows_target_hash_after="$(sha256sum "$windows_target_image" | awk '{print $1}')"
    if [[ "$windows_target_hash_after" != "$windows_target_hash_before" ]]; then
      echo "Rescue offline inspection modified the disposable Windows target image" >&2
      exit 1
    fi
    altered_windows_target_hash_after="$(sha256sum "$altered_windows_target_image" | awk '{print $1}')"
    if [[ "$altered_windows_target_hash_after" != "$altered_windows_target_hash_before" ]]; then
      echo "Rescue offline inspection modified the disposable ntfsfix-altered Windows target image" >&2
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
    printf '%s\n' \
      "KERNAID_QEMU_OFFLINE_INSPECTION_ATTESTATION_V1 firmware=$firmware linux_before_sha256=$target_hash_before linux_after_sha256=$target_hash_after windows_before_sha256=$windows_target_hash_before windows_after_sha256=$windows_target_hash_after windows_altered_before_sha256=$altered_windows_target_hash_before windows_altered_after_sha256=$altered_windows_target_hash_after ready=true" \
      | tee -a "$log"
    echo "PASS: KernAid Rescue booted with $firmware firmware, inspected Linux ext4 plus two volume-state-unqualified Windows NTFS fixtures read-only, and made zero target-image writes"
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
