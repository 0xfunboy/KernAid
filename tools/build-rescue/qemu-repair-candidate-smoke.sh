#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
iso="${1:-$repo_dir/KernAid-Rescue-amd64-repair-candidate.iso}"
controller="$repo_dir/tools/build-rescue/qemu-repair-candidate-pty.py"
readonly media_bytes=32000000000
readonly p3_start_bytes=17179869184

if [[ "$EUID" -eq 0 ]]; then
  echo "qemu-repair-candidate-smoke.sh must run as an unprivileged user" >&2
  exit 2
fi
for command in debugfs dd mkfs.ext4 mktemp od python3 qemu-system-x86_64 \
  sha256sum stat truncate unsquashfs xorriso; do
  command -v "$command" >/dev/null \
    || { echo "Missing required command: $command" >&2; exit 2; }
done
[[ -f "$iso" && ! -L "$iso" ]] || { echo "Candidate ISO not found" >&2; exit 2; }

work_dir="$(mktemp -d /tmp/kernaid-qemu-repair-candidate.XXXXXXXX)"
cleanup() {
  local status=$?
  trap - EXIT INT TERM HUP
  case "$work_dir" in
    /tmp/kernaid-qemu-repair-candidate.*)
      rm -rf -- "$work_dir" 2>/dev/null || true
      ;;
  esac
  exit "$status"
}
trap cleanup EXIT INT TERM HUP

rescue_media="$work_dir/rescue-usb.raw"
target_image="$work_dir/repair-target.raw"
seed="$work_dir/seed"
squashfs="$work_dir/filesystem.squashfs"
login_credential="$work_dir/login"
vault_key="$work_dir/vault-key"
observed_fstab="$work_dir/observed-fstab"
observed_sentinel="$work_dir/observed-sentinel"
expected_after="$work_dir/expected-after"
controller_output="$work_dir/controller.out"
controller_error="$work_dir/controller.err"
qmp_socket="$work_dir/qmp.sock"

mkdir -p -- "$seed/etc" "$seed/boot" "$seed/var/lib/dpkg" "$seed/srv/archive"
printf '%s\n' \
  'ID=kernaid-repair-fixture' \
  'NAME="KernAid repair qualification fixture"' \
  'VERSION_ID="1"' >"$seed/etc/os-release"
printf '%s\n' '0123456789abcdef0123456789abcdef' >"$seed/etc/machine-id"
printf '%s\n' \
  'UUID=11111111-1111-4111-8111-111111111111 / ext4 defaults 0 1' \
  'UUID=deadbeef-dead-4eef-8ead-deadbeef0001 /srv/archive ext4 defaults 0 2' \
  >"$seed/etc/fstab"
printf '%s\n' \
  'UUID=11111111-1111-4111-8111-111111111111 / ext4 defaults 0 1' \
  '# KernAid Rescue disabled missing UUID: UUID=deadbeef-dead-4eef-8ead-deadbeef0001 /srv/archive ext4 defaults 0 2' \
  >"$expected_after"
printf '%s\n' KERNAID_REPAIR_TARGET_SENTINEL >"$seed/boot/vmlinuz-kernaid-repair"
printf '%s\n' 'Package: kernaid-repair-fixture' >"$seed/var/lib/dpkg/status"

before_sha256="sha256:$(sha256sum "$seed/etc/fstab" | awk '{print $1}')"
after_sha256="sha256:$(sha256sum "$expected_after" | awk '{print $1}')"
[[ "$before_sha256" =~ ^sha256:[0-9a-f]{64}$ \
  && "$after_sha256" =~ ^sha256:[0-9a-f]{64}$ \
  && "$before_sha256" != "$after_sha256" ]] || exit 1

truncate -s 256M -- "$target_image"
mkfs.ext4 -q -F -U 11111111-1111-4111-8111-111111111111 \
  -L KERNAID_REPAIR_TARGET -d "$seed" "$target_image"
# mkfs.ext4 -d preserves the unprivileged runner ownership and umask.  Normalize
# the disposable guest fixture to the production metadata contract before boot.
debugfs -w -R "set_inode_field /etc uid 0" "$target_image" >/dev/null 2>&1
debugfs -w -R "set_inode_field /etc gid 0" "$target_image" >/dev/null 2>&1
debugfs -w -R "set_inode_field /etc mode 040755" "$target_image" >/dev/null 2>&1
debugfs -w -R "set_inode_field /etc/fstab uid 0" "$target_image" >/dev/null 2>&1
debugfs -w -R "set_inode_field /etc/fstab gid 0" "$target_image" >/dev/null 2>&1
debugfs -w -R "set_inode_field /etc/fstab mode 0100644" "$target_image" >/dev/null 2>&1
target_before_sha256="$(sha256sum "$target_image" | awk '{print $1}')"

iso_bytes="$(stat -c '%s' -- "$iso")"
[[ "$iso_bytes" =~ ^[1-9][0-9]*$ && "$iso_bytes" -le "$p3_start_bytes" ]] || exit 1
truncate -s "$media_bytes" -- "$rescue_media"
dd if="$iso" of="$rescue_media" bs=4M conv=notrunc status=none
iso_sha256="$(sha256sum "$iso" | awk '{print $1}')"

xorriso -osirrox on -indev "$iso" \
  -extract /live/filesystem.squashfs "$squashfs" >/dev/null 2>&1
: >"$login_credential"
chmod 600 -- "$login_credential"
set +e
unsquashfs -cat "$squashfs" usr/lib/live/config/0030-user-setup 2>/dev/null \
  | python3 -I -B "$controller" --extract-live-credential \
      --source-fd 6 --credential-fd 7 6<&0 7>"$login_credential"
extract_status=("${PIPESTATUS[@]}")
set -e
[[ "${extract_status[*]}" == "0 0" ]] || exit 1
od -An -N32 -tx1 /dev/urandom | tr -d '[:space:]' >"$vault_key"
chmod 600 -- "$vault_key"
[[ "$(stat -c '%s' -- "$vault_key")" == 64 ]] || exit 1

# QEMU's drive and device specifications are intentionally comma-delimited.
# shellcheck disable=SC2054
qemu_args=(
  -machine accel=tcg
  -m 2048
  -smp 2
  -nic none
  -device qemu-xhci,id=kernaid_xhci
  -drive "if=none,id=kernaid_rescue_usb,file=$rescue_media,format=raw,cache=none,aio=threads"
  -device "usb-storage,bus=kernaid_xhci.0,drive=kernaid_rescue_usb,bootindex=1"
  -drive "if=none,id=kernaid_repair_target,file=$target_image,format=raw,cache=none,aio=threads"
  -device virtio-blk-pci,drive=kernaid_repair_target,serial=KERNAID-REPAIR-V1
  -fw_cfg name=opt/kernaid-tauri-sandbox-probe,string=v1
)

set +e
python3 -I -B "$controller" \
  --qemu "$(command -v qemu-system-x86_64)" \
  --qmp-socket "$qmp_socket" \
  --vault-key-fd 3 --login-credential-fd 4 \
  --before-sha256 "$before_sha256" --after-sha256 "$after_sha256" \
  --timeout 900 -- "${qemu_args[@]}" \
  3<"$vault_key" 4<"$login_credential" \
  >"$controller_output" 2>"$controller_error"
controller_status=$?
set -e
if [[ "$controller_status" -ne 0 ]]; then
  cat "$controller_error" >&2
  exit "$controller_status"
fi
[[ ! -s "$controller_error" ]] || { cat "$controller_error" >&2; exit 1; }
expected_guest="KERNAID_QEMU_REPAIR_CANDIDATE_GUEST_V1 action=linux.fstab.disable-missing-uuid.v1 before_sha256=$before_sha256 after_sha256=$after_sha256 vault_distinct=true terminal=committed approval=typed-single-use ready=true"
[[ "$(cat "$controller_output")" == "$expected_guest" ]] || exit 1

debugfs -R "dump -p /etc/fstab $observed_fstab" "$target_image" >/dev/null 2>&1
debugfs -R "dump -p /boot/vmlinuz-kernaid-repair $observed_sentinel" \
  "$target_image" >/dev/null 2>&1
cmp -s -- "$expected_after" "$observed_fstab"
[[ "$(cat "$observed_sentinel")" == KERNAID_REPAIR_TARGET_SENTINEL ]]
target_after_sha256="$(sha256sum "$target_image" | awk '{print $1}')"
[[ "$target_after_sha256" != "$target_before_sha256" ]]
prefix_after_sha256="$(dd if="$rescue_media" bs=4M iflag=count_bytes \
  count="$iso_bytes" status=none | sha256sum | awk '{print $1}')"
[[ "$prefix_after_sha256" == "$iso_sha256" ]]

printf '%s\n' \
  "KERNAID_QEMU_REPAIR_CANDIDATE_ATTESTATION_V1 action=linux.fstab.disable-missing-uuid.v1 firmware=bios drives=rescue-usb,target-ext4 physical_parents=distinct vault=luks2-ext4 before_sha256=$before_sha256 after_sha256=$after_sha256 exact_bytes=true terminal=committed iso_prefix_immutable=true host_physical_devices=false ready=true"
