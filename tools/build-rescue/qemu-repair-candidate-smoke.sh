#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
firmware="${1:-bios}"
scenario="${2:-apply}"
iso="${3:-$repo_dir/KernAid-Rescue-amd64-repair-candidate.iso}"
controller="$repo_dir/tools/build-rescue/qemu-repair-candidate-pty.py"
readonly media_bytes=32000000000
readonly p3_start_bytes=17179869184
controller_timeout=900
readonly qemu_smp="${KERNAID_QEMU_SMP:-2}"

if [[ "$firmware" != bios && "$firmware" != uefi ]]; then
  echo "Usage: $0 [bios|uefi] [apply|rollback|interrupt-reconcile] [iso]" >&2
  exit 2
fi
if [[ "$scenario" != apply && "$scenario" != rollback \
  && "$scenario" != interrupt-reconcile ]]; then
  echo "Usage: $0 [bios|uefi] [apply|rollback|interrupt-reconcile] [iso]" >&2
  exit 2
fi
if [[ "$scenario" == rollback || "$scenario" == interrupt-reconcile ]]; then
  [[ "$firmware" == uefi ]] || {
    echo "$scenario is qualified only with UEFI" >&2
    exit 2
  }
fi
if [[ "$scenario" == rollback ]]; then
  controller_timeout=1500
elif [[ "$scenario" == interrupt-reconcile ]]; then
  controller_timeout=1800
fi

case "$qemu_smp" in
  1|2|4|8) ;;
  *)
    echo "KERNAID_QEMU_SMP must be one of: 1, 2, 4, 8" >&2
    exit 2
    ;;
esac

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
ovmf_code=""
ovmf_vars_template=""

mkdir -p -- \
  "$seed/etc" \
  "$seed/boot" \
  "$seed/usr" \
  "$seed/var/lib/dpkg" \
  "$seed/srv/archive"
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
  -return_with FAILURE 32 \
  -extract /live/filesystem.squashfs "$squashfs" >/dev/null 2>&1
# The finalized hybrid image deliberately advertises its future Vault p3 beyond
# the current ISO EOF. xorriso reports that known layout as SORRY, while the
# stricter FAILURE threshold still rejects extraction or image-read failures.
[[ -f "$squashfs" && ! -L "$squashfs" ]] || exit 1
squashfs_bytes="$(stat -c '%s' -- "$squashfs")"
[[ "$squashfs_bytes" =~ ^[1-9][0-9]*$ && "$squashfs_bytes" -le 8589934592 ]] \
  || exit 1
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

if [[ "$firmware" == uefi ]]; then
  for pair in \
    /usr/share/OVMF/OVMF_CODE_4M.fd:/usr/share/OVMF/OVMF_VARS_4M.fd \
    /usr/share/OVMF/OVMF_CODE.fd:/usr/share/OVMF/OVMF_VARS.fd; do
    candidate_code="${pair%%:*}"
    candidate_vars="${pair#*:}"
    if [[ -f "$candidate_code" && -f "$candidate_vars" ]]; then
      ovmf_code="$candidate_code"
      ovmf_vars_template="$candidate_vars"
      break
    fi
  done
  [[ -n "$ovmf_code" && -n "$ovmf_vars_template" ]] || {
    echo "A matching OVMF CODE/VARS firmware pair was not found" >&2
    exit 2
  }
fi

# QEMU's drive and device specifications are intentionally comma-delimited.
# shellcheck disable=SC2054
qemu_args=(
  -machine accel=tcg
  -m 2048
  -smp "$qemu_smp"
  -nic none
  -device qemu-xhci,id=kernaid_xhci
  -drive "if=none,id=kernaid_rescue_usb,file=$rescue_media,format=raw,cache=none,aio=threads"
  -device "usb-storage,bus=kernaid_xhci.0,drive=kernaid_rescue_usb,bootindex=1"
  -blockdev "driver=file,node-name=kernaid_repair_target_file,filename=$target_image,cache.direct=on,cache.no-flush=off,aio=threads"
  -blockdev driver=raw,node-name=kernaid_repair_target,file=kernaid_repair_target_file
  -device virtio-blk-pci,drive=kernaid_repair_target,serial=KERNAID-REPAIR-V1
  -fw_cfg name=opt/kernaid-tauri-sandbox-probe,string=v1
)

set +e
controller_args=(
  --qemu "$(command -v qemu-system-x86_64)"
  --qmp-socket "$qmp_socket"
  --firmware "$firmware"
  --scenario "$scenario"
  --vault-key-fd 3 --login-credential-fd 4
  --before-sha256 "$before_sha256" --after-sha256 "$after_sha256"
  --timeout "$controller_timeout"
)
if [[ "$firmware" == uefi ]]; then
  controller_args+=(
    --ovmf-code "$ovmf_code"
    --ovmf-vars-template "$ovmf_vars_template"
  )
fi
python3 -I -B "$controller" \
  "${controller_args[@]}" -- "${qemu_args[@]}" \
  3<"$vault_key" 4<"$login_credential" \
  >"$controller_output" 2>"$controller_error"
controller_status=$?
set -e
if [[ "$controller_status" -ne 0 ]]; then
  cat "$controller_error" >&2
  exit "$controller_status"
fi
[[ ! -s "$controller_error" ]] || { cat "$controller_error" >&2; exit 1; }
if [[ "$scenario" == apply ]]; then
  expected_guest="KERNAID_QEMU_REPAIR_CANDIDATE_GUEST_V1 action=linux.fstab.disable-missing-uuid.v1 firmware=$firmware scenario=apply before_sha256=$before_sha256 after_sha256=$after_sha256 vault_distinct=true terminal=committed approval=typed-single-use ready=true"
  expected_fstab="$expected_after"
  expected_terminal=committed
elif [[ "$scenario" == rollback ]]; then
  expected_guest="KERNAID_QEMU_REPAIR_CANDIDATE_GUEST_V1 action=linux.fstab.restore firmware=$firmware scenario=rollback before_sha256=$before_sha256 after_sha256=$after_sha256 vault_distinct=true source_terminal=committed terminal=rolled-back-original state=restored approval=fresh-typed-single-use ready=true"
  expected_fstab="$seed/etc/fstab"
  expected_terminal=rolled-back-original
else
  expected_guest="KERNAID_QEMU_REPAIR_CANDIDATE_GUEST_V1 action=linux.fstab.disable-missing-uuid.v1 firmware=$firmware scenario=interrupt-reconcile before_sha256=$before_sha256 after_sha256=$after_sha256 vault_distinct=true terminal=restored interruption=qmp-after-target-write recovery=closed ready=true"
  expected_fstab="$seed/etc/fstab"
  expected_terminal=restored
fi
[[ "$(cat "$controller_output")" == "$expected_guest" ]] || exit 1

debugfs -R "dump -p /etc/fstab $observed_fstab" "$target_image" >/dev/null 2>&1
debugfs -R "dump -p /boot/vmlinuz-kernaid-repair $observed_sentinel" \
  "$target_image" >/dev/null 2>&1
cmp -s -- "$expected_fstab" "$observed_fstab"
[[ "$(cat "$observed_sentinel")" == KERNAID_REPAIR_TARGET_SENTINEL ]]
target_after_sha256="$(sha256sum "$target_image" | awk '{print $1}')"
if [[ "$scenario" == apply ]]; then
  [[ "$target_after_sha256" != "$target_before_sha256" ]]
fi
prefix_after_sha256="$(dd if="$rescue_media" bs=4M iflag=count_bytes \
  count="$iso_bytes" status=none | sha256sum | awk '{print $1}')"
[[ "$prefix_after_sha256" == "$iso_sha256" ]]

if [[ "$scenario" == rollback ]]; then
  attested_action=linux.fstab.restore
else
  attested_action=linux.fstab.disable-missing-uuid.v1
fi
printf '%s\n' \
  "KERNAID_QEMU_REPAIR_CANDIDATE_ATTESTATION_V1 action=$attested_action firmware=$firmware scenario=$scenario drives=rescue-usb,target-ext4 physical_parents=distinct vault=luks2-ext4 before_sha256=$before_sha256 after_sha256=$after_sha256 exact_bytes=true terminal=$expected_terminal iso_prefix_immutable=true host_physical_devices=false ready=true"
