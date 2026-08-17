#!/usr/bin/env bash
set -euo pipefail
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
firmware="${1:-bios}"
iso="${2:-$repo_dir/KernAid-Rescue-amd64.iso}"
readonly boot_timeout_seconds=600
for command in cp dd debugfs mcopy mmd mkfs.ext4 mkfs.ntfs mkfs.vfat ntfsfix \
  python3 qemu-system-x86_64 sgdisk sha256sum sync tee truncate; do
  command -v "$command" >/dev/null || { echo "Missing required command: $command" >&2; exit 2; }
done
if [[ "$EUID" -eq 0 ]]; then
  echo "qemu-smoke.sh must run as an unprivileged user; only disposable NTFS fixture setup uses sudo" >&2
  exit 2
fi
ntfs_3g_command="/usr/bin/ntfs-3g"
sudo_command="/usr/bin/sudo"
umount_command="/usr/bin/umount"
findmnt_command="/usr/bin/findmnt"
stat_command="/usr/bin/stat"
readlink_command="/usr/bin/readlink"
mktemp_command="/usr/bin/mktemp"

trusted_root_directory_chain() {
  local directory="$1"
  local file_type owner_uid owner_gid permissions
  while true; do
    if [[ ! -d "$directory" || -L "$directory" ]]; then
      echo "Privileged fixture tool has an unsafe parent directory: $directory" >&2
      return 1
    fi
    IFS=: read -r file_type owner_uid owner_gid permissions \
      <<<"$(LC_ALL=C "$stat_command" -c '%F:%u:%g:%a' -- "$directory")"
    if [[ "$file_type" != "directory" || "$owner_uid" != "0" \
      || "$owner_gid" != "0" || -z "$permissions" \
      || $((8#$permissions & 0022)) -ne 0 ]]; then
      echo "Privileged fixture tool has an untrusted parent directory: $directory" >&2
      return 1
    fi
    [[ "$directory" == "/" ]] && return 0
    directory="${directory%/*}"
    [[ -n "$directory" ]] || directory="/"
  done
}

trusted_privileged_tool() {
  local path="$1"
  local current="$path"
  local parent link_target
  local hop=0
  local file_type owner_uid owner_gid permissions
  while [[ -L "$current" ]]; do
    hop=$((hop + 1))
    if [[ "$hop" -gt 8 ]]; then
      echo "Privileged fixture tool symlink chain is too deep: $path" >&2
      return 1
    fi
    parent="${current%/*}"
    [[ -n "$parent" ]] || parent="/"
    trusted_root_directory_chain "$parent" || return 1
    IFS=: read -r file_type owner_uid owner_gid \
      <<<"$(LC_ALL=C "$stat_command" -c '%F:%u:%g' -- "$current")"
    if [[ "$file_type" != "symbolic link" || "$owner_uid" != "0" \
      || "$owner_gid" != "0" ]]; then
      echo "Privileged fixture tool has an untrusted symlink: $current" >&2
      return 1
    fi
    link_target="$("$readlink_command" -- "$current")"
    if [[ "$link_target" == /* ]]; then
      current="$link_target"
    else
      case "/$link_target/" in
        *"/../"*|*"/./"*)
          echo "Privileged fixture tool has a non-canonical relative symlink: $current" >&2
          return 1
          ;;
      esac
      current="$parent/$link_target"
    fi
  done
  case "$current" in
    /usr/bin/*|/usr/sbin/*|/usr/lib/*) ;;
    *)
      echo "Privileged fixture tool resolved outside the system allowlist: $path" >&2
      return 1
      ;;
  esac
  parent="${current%/*}"
  trusted_root_directory_chain "$parent" || return 1
  if [[ ! -f "$current" || ! -x "$current" ]]; then
    echo "Privileged fixture tool is not a regular executable: $path" >&2
    return 1
  fi
  IFS=: read -r file_type owner_uid owner_gid permissions \
    <<<"$(LC_ALL=C "$stat_command" -c '%F:%u:%g:%a' -- "$current")"
  if [[ "$file_type" != "regular file" || "$owner_uid" != "0" \
    || "$owner_gid" != "0" || -z "$permissions" \
    || $((8#$permissions & 0022)) -ne 0 ]]; then
    echo "Privileged fixture tool failed root ownership and mode validation: $path" >&2
    return 1
  fi
}

for inspection_tool in "$findmnt_command" "$stat_command" "$readlink_command" /usr/bin/id; do
  [[ -x "$inspection_tool" ]] \
    || { echo "Missing fixed system tool: $inspection_tool" >&2; exit 2; }
done
for privileged_tool in "$ntfs_3g_command" "$sudo_command" "$umount_command"; do
  trusted_privileged_tool "$privileged_tool" || exit 2
done
mktemp_resolved="$($readlink_command -f -- "$mktemp_command")"
[[ -n "$mktemp_resolved" ]] || { echo "Missing fixed system tool: $mktemp_command" >&2; exit 2; }
trusted_privileged_tool "$mktemp_resolved" || exit 2
if [[ "$firmware" != "bios" && "$firmware" != "uefi" ]]; then
  echo "Usage: $0 [bios|uefi] [iso]" >&2
  exit 2
fi
test -f "$iso" || { echo "ISO not found: $iso" >&2; exit 2; }
python3 -I "$repo_dir/tools/build-rescue/finalize-device-layout.py" verify \
  --manifest "$repo_dir/rescue/image-layout/device-layout.v1.json" \
  --image "$iso"
iso_hash_before="$(sha256sum "$iso" | awk '{print $1}')"
log="${KERNAID_SMOKE_LOG:-$($mktemp_command)}"
temporary_log=0
if [[ -z "${KERNAID_SMOKE_LOG:-}" ]]; then temporary_log=1; fi
target_image="$($mktemp_command)"
windows_target_image="$($mktemp_command)"
windows_esp_image="$($mktemp_command)"
windows_gpt_target_image="$($mktemp_command)"
altered_windows_target_image="$($mktemp_command)"
target_seed_dir="$($mktemp_command -d)"
windows_esp_seed_dir="$($mktemp_command -d)"
windows_seed_mount="$($mktemp_command -d)"
qemu_pid=""
windows_fixture_mounted=0
windows_fixture_cleanup_safe=1
fixture_uid="$(/usr/bin/id -u)"
fixture_gid="$(/usr/bin/id -g)"

verify_disposable_windows_fixture_mount() {
  local require_policy="${1:-yes}"
  local mount_record mounted_source mounted_target mounted_fstype mounted_options
  if [[ -z "${windows_fixture_identity:-}" \
    || -z "${windows_mountpoint_identity:-}" \
    || -L "$windows_target_image" || ! -f "$windows_target_image" \
    || "$($stat_command -c '%d:%i:%s:%u:%g:%a:%h' -- "$windows_target_image")" \
      != "$windows_fixture_identity" \
    || -L "$windows_seed_mount" || ! -d "$windows_seed_mount" ]]; then
    echo "Disposable Windows fixture path identity is no longer exact" >&2
    return 1
  fi
  mount_record="$($findmnt_command -rn -o SOURCE,TARGET,FSTYPE,OPTIONS \
    --mountpoint "$windows_seed_mount")" || return 1
  IFS=' ' read -r mounted_source mounted_target mounted_fstype mounted_options \
    <<<"$mount_record"
  if [[ "$mounted_source" != "$windows_target_image" \
    || "$mounted_target" != "$windows_seed_mount" \
    || ( "$mounted_fstype" != "fuse" && "$mounted_fstype" != "fuseblk" ) ]]; then
    echo "Disposable Windows fixture mount provenance was not exact" >&2
    return 1
  fi
  if [[ "$require_policy" == "yes" ]]; then
    mounted_options=",$mounted_options,"
    for required_option in rw nodev nosuid noexec; do
      if [[ "$mounted_options" != *",$required_option,"* ]]; then
        echo "Disposable Windows fixture mount lost option: $required_option" >&2
        return 1
      fi
    done
  fi
}

verify_disposable_windows_fixture_unmounted() {
  if [[ -L "$windows_target_image" || ! -f "$windows_target_image" \
    || "$($stat_command -c '%d:%i:%s:%u:%g:%a:%h' -- "$windows_target_image")" \
      != "$windows_fixture_identity" \
    || -L "$windows_seed_mount" || ! -d "$windows_seed_mount" \
    || "$($stat_command -c '%d:%i:%u:%g:%a' -- "$windows_seed_mount")" \
      != "$windows_mountpoint_identity" ]]; then
    echo "Disposable Windows fixture identity changed across the privileged mount" >&2
    windows_fixture_cleanup_safe=0
    return 1
  fi
}

unmount_disposable_windows_fixture() {
  local require_policy="${1:-yes}"
  if ! "$findmnt_command" -rn --mountpoint "$windows_seed_mount" >/dev/null; then
    windows_fixture_mounted=0
    return 0
  fi
  verify_disposable_windows_fixture_mount "$require_policy" || return 1
  "$sudo_command" -n -- "$umount_command" -- "$windows_seed_mount" || return 1
  if "$findmnt_command" -rn --mountpoint "$windows_seed_mount" >/dev/null; then
    echo "Disposable Windows fixture remained mounted" >&2
    return 1
  fi
  windows_fixture_mounted=0
  verify_disposable_windows_fixture_unmounted
}

# shellcheck disable=SC2329  # Invoked indirectly by the EXIT trap below.
# This callback is reached indirectly through the EXIT trap below.
# shellcheck disable=SC2317
cleanup() {
  local status="$1"
  local cleanup_failed=0
  trap - EXIT
  if [[ -n "$qemu_pid" ]]; then kill "$qemu_pid" 2>/dev/null || true; fi
  if [[ "$windows_fixture_mounted" == "1" ]] \
    || "$findmnt_command" -rn --mountpoint "$windows_seed_mount" >/dev/null; then
    if ! unmount_disposable_windows_fixture no; then
      echo "Failed to unmount the disposable Windows fixture during cleanup" >&2
      cleanup_failed=1
    fi
  fi
  if [[ "$temporary_log" == "1" ]]; then rm -f "$log"; fi
  rm -f "$target_image"
  rm -rf "$target_seed_dir"
  if [[ "$windows_fixture_cleanup_safe" == "1" ]] \
    && ! "$findmnt_command" -rn --mountpoint "$windows_seed_mount" >/dev/null; then
    rm -f "$windows_target_image" "$windows_esp_image" \
      "$windows_gpt_target_image" "$altered_windows_target_image"
    rm -rf "$windows_esp_seed_dir" "$windows_seed_mount"
  else
    echo "Preserving the still-mounted disposable Windows fixture for runner cleanup" >&2
    cleanup_failed=1
  fi
  if [[ "$cleanup_failed" == "1" ]]; then exit 1; fi
  exit "$status"
}
trap 'cleanup $?' EXIT
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
windows_fixture_identity="$("$stat_command" -c '%d:%i:%s:%u:%g:%a:%h' -- "$windows_target_image")"
windows_mountpoint_identity="$("$stat_command" -c '%d:%i:%u:%g:%a' -- "$windows_seed_mount")"
if [[ -L "$windows_target_image" || ! -f "$windows_target_image" \
  || "$windows_fixture_identity" != *":$fixture_uid:$fixture_gid:600:1" ]]; then
  echo "Disposable Windows fixture image ownership or mode is unsafe" >&2
  exit 1
fi
if [[ -L "$windows_seed_mount" || ! -d "$windows_seed_mount" \
  || "$windows_mountpoint_identity" != *":$fixture_uid:$fixture_gid:700" ]]; then
  echo "Disposable Windows fixture mountpoint ownership or mode is unsafe" >&2
  exit 1
fi
if "$findmnt_command" -rn --mountpoint "$windows_seed_mount" >/dev/null; then
  echo "Disposable Windows fixture mountpoint was already in use" >&2
  exit 1
fi
# GitHub-hosted runners forbid an unprivileged ntfs-3g FUSE mount.  Limit
# elevation to mounting this freshly-created mode-0600 disposable image and
# its normal unmount.  QEMU itself is rejected above when the script is root.
"$sudo_command" -n -- "$ntfs_3g_command" \
  "$windows_target_image" "$windows_seed_mount" \
  -o "rw,nodev,nosuid,noexec,allow_other,uid=$fixture_uid,gid=$fixture_gid,umask=0077"
windows_fixture_mounted=1
verify_disposable_windows_fixture_mount yes
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
sync -f "$windows_seed_mount"
unmount_disposable_windows_fixture
cp --reflink=auto --sparse=always \
  "$windows_target_image" "$altered_windows_target_image"
# ntfsfix deliberately schedules this disposable clone for a Windows check.
# The guest must inspect it through the kernel ntfs3 driver using MS_RDONLY,
# without `force` and without claiming that its volume state is qualified.
ntfsfix "$altered_windows_target_image" >/dev/null
altered_windows_target_hash_before="$(sha256sum "$altered_windows_target_image" | awk '{print $1}')"

# Build a same-disk GPT Windows fixture without a host loop device.  The
# filesystem images are populated separately, then copied at fixed sector
# offsets into the disposable GPT image.
truncate -s 64M "$windows_esp_image"
mkfs.vfat -F 32 -n KERNAID_ESP "$windows_esp_image" >/dev/null
printf '%s\n' KERNAID_WINDOWS_EFI_BOOT_MANAGER_FIXTURE > \
  "$windows_esp_seed_dir/bootmgfw.efi"
printf '%s\n' KERNAID_WINDOWS_EFI_BCD_FIXTURE > \
  "$windows_esp_seed_dir/BCD"
printf '%s\n' KERNAID_WINDOWS_EFI_FALLBACK_FIXTURE > \
  "$windows_esp_seed_dir/BOOTX64.EFI"
MTOOLSRC=/dev/null mmd -i "$windows_esp_image" ::/EFI
MTOOLSRC=/dev/null mmd -i "$windows_esp_image" ::/EFI/Microsoft
MTOOLSRC=/dev/null mmd -i "$windows_esp_image" ::/EFI/Microsoft/Boot
MTOOLSRC=/dev/null mmd -i "$windows_esp_image" ::/EFI/BOOT
MTOOLSRC=/dev/null mcopy -i "$windows_esp_image" "$windows_esp_seed_dir/bootmgfw.efi" \
  ::/EFI/Microsoft/Boot/bootmgfw.efi
MTOOLSRC=/dev/null mcopy -i "$windows_esp_image" "$windows_esp_seed_dir/BCD" \
  ::/EFI/Microsoft/Boot/BCD
MTOOLSRC=/dev/null mcopy -i "$windows_esp_image" "$windows_esp_seed_dir/BOOTX64.EFI" \
  ::/EFI/BOOT/BOOTX64.EFI
truncate -s 256M "$windows_gpt_target_image"
sgdisk --zap-all "$windows_gpt_target_image" >/dev/null
sgdisk \
  --new=1:2048:133119 --typecode=1:ef00 --change-name=1:KERNAID_ESP \
  --new=2:133120:395263 --typecode=2:0700 --change-name=2:KERNAID_WINDOWS \
  "$windows_gpt_target_image" >/dev/null
sgdisk --verify "$windows_gpt_target_image" >/dev/null
dd if="$windows_esp_image" of="$windows_gpt_target_image" bs=512 \
  seek=2048 count=131072 conv=notrunc status=none
dd if="$windows_target_image" of="$windows_gpt_target_image" bs=512 \
  seek=133120 count=262144 conv=notrunc status=none
windows_gpt_target_hash_before="$(sha256sum "$windows_gpt_target_image" | awk '{print $1}')"

qemu_args=(-machine accel=tcg -m 2048 -smp 2 -cdrom "$iso" \
  -drive "file=$target_image,if=virtio,format=raw,cache=none" \
  -drive "file=$windows_gpt_target_image,if=virtio,format=raw,cache=none" \
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
for ((_attempt = 1; _attempt <= boot_timeout_seconds; _attempt++)); do
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
    windows_gpt_target_hash_after="$(sha256sum "$windows_gpt_target_image" | awk '{print $1}')"
    if [[ "$windows_gpt_target_hash_after" != "$windows_gpt_target_hash_before" ]]; then
      echo "Rescue offline inspection modified the disposable GPT Windows target image" >&2
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
      "KERNAID_QEMU_OFFLINE_INSPECTION_ATTESTATION_V1 firmware=$firmware linux_before_sha256=$target_hash_before linux_after_sha256=$target_hash_after windows_gpt_before_sha256=$windows_gpt_target_hash_before windows_gpt_after_sha256=$windows_gpt_target_hash_after windows_altered_before_sha256=$altered_windows_target_hash_before windows_altered_after_sha256=$altered_windows_target_hash_after ready=true" \
      | tee -a "$log"
    echo "PASS: KernAid Rescue booted with $firmware firmware, inspected Linux ext4, a same-disk GPT Windows NTFS plus ESP fixture, and an altered NTFS fixture read-only with zero target-image writes"
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
echo "The required Rescue readiness markers were not both observed within $boot_timeout_seconds seconds" >&2
exit 1
