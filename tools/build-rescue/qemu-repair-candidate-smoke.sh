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
readonly p3_bytes=8589934592
# A first boot can spend up to fifteen minutes proving that the future Vault
# is entirely zero before its first write. Keep one aggregate budget that also
# covers the TCG boot, repair proof and clean shutdown.
controller_timeout=1800
readonly qemu_smp="${KERNAID_QEMU_SMP:-2}"
readonly provisioned_base="${KERNAID_REPAIR_PROVISIONED_BASE:-}"
readonly provisioned_key="${KERNAID_REPAIR_PROVISIONED_KEY:-}"
readonly provisioned_target="${KERNAID_REPAIR_TARGET_BASE:-}"
readonly tamper_helper="$repo_dir/tools/build-rescue/qemu-repair-vault-tamper.py"
readonly host_vault_provisioner="$repo_dir/tools/build-rescue/provision-repair-vault-base.sh"
readonly vault_probe="$repo_dir/target/release/kernaid-rescue-vault-probe"

if [[ "$firmware" != bios && "$firmware" != uefi ]]; then
  echo "Usage: $0 [bios|uefi] [apply|rollback|interrupt-reconcile|crypttab-lifecycle|ext4-apply|resolver-link-apply|failure-paths|qualification-batch] [iso]" >&2
  exit 2
fi
if [[ "$scenario" != apply && "$scenario" != rollback \
  && "$scenario" != interrupt-reconcile && "$scenario" != failure-paths \
  && "$scenario" != stale-target && "$scenario" != cancel \
  && "$scenario" != backup-tamper && "$scenario" != repaird-termination \
  && "$scenario" != auto-restore && "$scenario" != crypttab-lifecycle \
  && "$scenario" != ext4-apply && "$scenario" != resolver-link-apply \
  && "$scenario" != qualification-batch ]]; then
  echo "Usage: $0 [bios|uefi] [apply|rollback|interrupt-reconcile|crypttab-lifecycle|ext4-apply|resolver-link-apply|failure-paths|qualification-batch] [iso]" >&2
  exit 2
fi
if [[ "$scenario" == qualification-batch && "$firmware" != uefi ]]; then
  echo "qualification-batch must start from UEFI provisioning" >&2
  exit 2
fi
if [[ "$scenario" != apply ]]; then
  [[ "$firmware" == uefi ]] || {
    echo "$scenario is qualified only with UEFI" >&2
    exit 2
  }
fi
if [[ "$scenario" == rollback ]]; then
  controller_timeout=1500
elif [[ "$scenario" == interrupt-reconcile || "$scenario" == backup-tamper ]]; then
  controller_timeout=1800
elif [[ "$scenario" == failure-paths ]]; then
  controller_timeout=1200
elif [[ "$scenario" == stale-target || "$scenario" == cancel \
  || "$scenario" == repaird-termination || "$scenario" == auto-restore \
  || "$scenario" == crypttab-lifecycle || "$scenario" == ext4-apply \
  || "$scenario" == resolver-link-apply ]]; then
  # Reserve the full bounded repair shutdown window after the guest proof.
  controller_timeout=1200
fi

if [[ -n "$provisioned_base" || -n "$provisioned_key" \
  || -n "$provisioned_target" ]]; then
  [[ -n "$provisioned_base" && -n "$provisioned_key" \
    && -n "$provisioned_target" \
    && "$scenario" != failure-paths \
    && "$scenario" != qualification-batch ]] || {
    echo "Invalid internal provisioned-base handoff" >&2
    exit 2
  }
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
required_commands=(
  debugfs dd mkfs.ext4 mktemp od python3 qemu-system-x86_64
  realpath sha256sum stat truncate unsquashfs xorriso
)
if [[ "$scenario" == ext4-apply ]]; then
  required_commands+=(e2fsck)
fi
if [[ "$scenario" == failure-paths || "$scenario" == backup-tamper \
  || "$scenario" == qualification-batch ]]; then
  required_commands+=(blockdev cryptsetup losetup sudo)
fi
for command in "${required_commands[@]}"; do
  command -v "$command" >/dev/null \
    || { echo "Missing required command: $command" >&2; exit 2; }
done
[[ -f "$iso" && ! -L "$iso" ]] || { echo "Candidate ISO not found" >&2; exit 2; }
if [[ "$scenario" == failure-paths || "$scenario" == backup-tamper ]]; then
  [[ -f "$tamper_helper" && ! -L "$tamper_helper" ]] \
    || { echo "Vault tamper helper not found" >&2; exit 2; }
fi
if [[ "$scenario" == qualification-batch ]]; then
  [[ -f "$host_vault_provisioner" && ! -L "$host_vault_provisioner" \
    && -x "$host_vault_provisioner" ]] || {
    echo "Host Repair Vault provisioner not found" >&2
    exit 2
  }
  [[ -f "$vault_probe" && ! -L "$vault_probe" && -x "$vault_probe" ]] || {
    echo "Host-only project Vault probe not found" >&2
    exit 2
  }
fi

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
observed_fstab_stat="$work_dir/observed-fstab.stat"
observed_crypttab="$work_dir/observed-crypttab"
observed_crypttab_stat="$work_dir/observed-crypttab.stat"
observed_resolver_stat="$work_dir/observed-resolver.stat"
observed_etc_listing="$work_dir/observed-etc.list"
expected_after="$work_dir/expected-after"
expected_crypttab_after="$work_dir/expected-crypttab-after"
controller_output="$work_dir/controller.out"
controller_error="$work_dir/controller.err"
qmp_socket="$work_dir/qmp.sock"
ovmf_code=""
ovmf_vars_template=""

mkdir -p -- \
  "$seed/etc" \
  "$seed/etc/systemd/system/multi-user.target.wants" \
  "$seed/boot" \
  "$seed/usr/lib/systemd/system" \
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
printf '%s\n' \
  'system UUID=11111111-1111-4111-8111-111111111111 none luks' \
  'archive UUID=deadbeef-dead-4eef-8ead-deadbeef0002 none luks' \
  >"$seed/etc/crypttab"
printf '%s\n' \
  'system UUID=11111111-1111-4111-8111-111111111111 none luks' \
  '# KernAid Rescue disabled missing crypttab UUID: archive UUID=deadbeef-dead-4eef-8ead-deadbeef0002 none luks' \
  >"$expected_crypttab_after"
printf '%s\n' \
  '[Unit]' \
  'Description=KernAid resolver qualification fixture' \
  >"$seed/usr/lib/systemd/system/systemd-resolved.service"
ln -s -- /usr/lib/systemd/system/systemd-resolved.service \
  "$seed/etc/systemd/system/multi-user.target.wants/systemd-resolved.service"
printf '%s\n' KERNAID_REPAIR_TARGET_SENTINEL >"$seed/boot/vmlinuz-kernaid-repair"
printf '%s\n' 'Package: kernaid-repair-fixture' >"$seed/var/lib/dpkg/status"
printf '%s\n' KERNAID_EXT4_REPAIR_MARKER >"$seed/srv/archive/ext4-repair-marker"

before_sha256="sha256:$(sha256sum "$seed/etc/fstab" | awk '{print $1}')"
after_sha256="sha256:$(sha256sum "$expected_after" | awk '{print $1}')"
crypttab_before_sha256="sha256:$(sha256sum "$seed/etc/crypttab" | awk '{print $1}')"
crypttab_after_sha256="sha256:$(sha256sum "$expected_crypttab_after" | awk '{print $1}')"
resolver_before_sha256="sha256:$(printf %s 'resolver-link-state:v1:missing' | sha256sum | awk '{print $1}')"
resolver_after_sha256="sha256:$(printf %s 'resolver-link-state:v1:resolved-stub-relative' | sha256sum | awk '{print $1}')"
[[ "$before_sha256" =~ ^sha256:[0-9a-f]{64}$ \
  && "$after_sha256" =~ ^sha256:[0-9a-f]{64}$ \
  && "$crypttab_before_sha256" =~ ^sha256:[0-9a-f]{64}$ \
  && "$crypttab_after_sha256" =~ ^sha256:[0-9a-f]{64}$ \
  && "$resolver_before_sha256" =~ ^sha256:[0-9a-f]{64}$ \
  && "$resolver_after_sha256" =~ ^sha256:[0-9a-f]{64}$ \
  && "$before_sha256" != "$after_sha256" \
  && "$crypttab_before_sha256" != "$crypttab_after_sha256" \
  && "$resolver_before_sha256" != "$resolver_after_sha256" ]] || exit 1

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
for directory in \
  /usr /usr/lib /usr/lib/systemd /usr/lib/systemd/system \
  /etc/systemd /etc/systemd/system /etc/systemd/system/multi-user.target.wants; do
  debugfs -w -R "set_inode_field $directory uid 0" "$target_image" >/dev/null 2>&1
  debugfs -w -R "set_inode_field $directory gid 0" "$target_image" >/dev/null 2>&1
  debugfs -w -R "set_inode_field $directory mode 040755" "$target_image" >/dev/null 2>&1
done
for regular in /etc/crypttab /usr/lib/systemd/system/systemd-resolved.service; do
  debugfs -w -R "set_inode_field $regular uid 0" "$target_image" >/dev/null 2>&1
  debugfs -w -R "set_inode_field $regular gid 0" "$target_image" >/dev/null 2>&1
  debugfs -w -R "set_inode_field $regular mode 0100644" "$target_image" >/dev/null 2>&1
done
debugfs -w -R "set_inode_field /etc/systemd/system/multi-user.target.wants/systemd-resolved.service uid 0" "$target_image" >/dev/null 2>&1
debugfs -w -R "set_inode_field /etc/systemd/system/multi-user.target.wants/systemd-resolved.service gid 0" "$target_image" >/dev/null 2>&1
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

already_provisioned=false
if [[ -n "$provisioned_base" ]]; then
  expected_handoffs=(
    "$provisioned_base:rescue-usb.raw"
    "$provisioned_key:vault-key"
    "$provisioned_target:repair-target.raw"
  )
  provisioned_parent=""
  for handoff_spec in "${expected_handoffs[@]}"; do
    handoff="${handoff_spec%%:*}"
    expected_name="${handoff_spec#*:}"
    resolved_handoff="$(realpath -e -- "$handoff")" || exit 2
    handoff_parent="$(dirname -- "$resolved_handoff")"
    [[ "$resolved_handoff" == "$handoff" \
      && "$(basename -- "$resolved_handoff")" == "$expected_name" \
      && "$(basename -- "$handoff_parent")" =~ ^kernaid-qemu-repair-candidate\.[A-Za-z0-9]{8}$ \
      && "$(dirname -- "$handoff_parent")" == /tmp \
      && -f "$resolved_handoff" && ! -L "$resolved_handoff" \
      && "$(stat -c '%u:%a' -- "$resolved_handoff")" == "$EUID:600" \
      && "$(stat -c '%h' -- "$resolved_handoff")" == 1 \
      && "$(stat -c '%u:%a' -- "$handoff_parent")" == "$EUID:700" ]] || {
      echo "Invalid internal provisioned-base file" >&2
      exit 2
    }
    if [[ -n "$provisioned_parent" && "$handoff_parent" != "$provisioned_parent" ]]; then
      echo "Invalid internal provisioned-base parent" >&2
      exit 2
    fi
    provisioned_parent="$handoff_parent"
  done
  [[ "$(stat -c '%s' -- "$provisioned_base")" == "$media_bytes" \
    && "$(stat -c '%s' -- "$provisioned_key")" == 64 \
    && "$(stat -c '%s' -- "$provisioned_target")" == 268435456 \
    && "$(tr -d '0-9a-f' <"$provisioned_key")" == "" ]] || {
    echo "Invalid internal provisioned-base content" >&2
    exit 2
  }
  cp --reflink=auto --sparse=always -- "$provisioned_base" "$rescue_media"
  cp --reflink=auto --sparse=always -- "$provisioned_target" "$target_image"
  cp -- "$provisioned_key" "$vault_key"
  chmod 600 -- "$rescue_media" "$target_image" "$vault_key"
  target_before_sha256="$(sha256sum "$target_image" | awk '{print $1}')"
  already_provisioned=true
fi

if [[ "$scenario" == qualification-batch ]]; then
  # The full guest first-boot lifecycle remains a separate, unchanged product
  # gate. This consolidated Repair matrix needs one reusable Vault base, so it
  # provisions that base once on the host with the same canonical profile and
  # descriptor-bound project probe already exercised by the USB lifecycle
  # qualification. No guest first-boot claim is made by this batch.
  host_provision_output="$work_dir/host-vault-provision.out"
  host_provision_error="$work_dir/host-vault-provision.err"
  readonly expected_host_provision="KERNAID_REPAIR_HOST_VAULT_BASE_ATTESTATION_V1 geometry=layout-v1 p3=exact-zero-before-first-write profile=canonical-v1 probe=initialize-verify identity=stable key=private-mode-0600 cleanup=complete target_access=none host_physical_devices=false ready=true"

  prefix_before_host_sha256="$(dd if="$rescue_media" bs=4M iflag=count_bytes \
    count="$iso_bytes" status=none | sha256sum | awk '{print $1}')"
  key_before_host_sha256="$(sha256sum "$vault_key" | awk '{print $1}')"
  target_before_host_sha256="$(sha256sum "$target_image" | awk '{print $1}')"
  [[ "$prefix_before_host_sha256" == "$iso_sha256" \
    && "$(stat -c '%d:%i' -- "$rescue_media")" \
      != "$(stat -c '%d:%i' -- "$target_image")" ]] || exit 1

  set +e
  # The unprivileged harness intentionally owns these bounded evidence files;
  # sudo applies only to the host provisioning helper.
  # shellcheck disable=SC2024
  sudo -n -- "$host_vault_provisioner" \
    --media "$rescue_media" --key "$vault_key" --probe "$vault_probe" \
    >"$host_provision_output" 2>"$host_provision_error"
  host_provision_status=$?
  set -e
  if [[ "$host_provision_status" -ne 0 ]]; then
    cat "$host_provision_error" >&2
    exit "$host_provision_status"
  fi
  [[ ! -s "$host_provision_error" \
    && "$(cat "$host_provision_output")" == "$expected_host_provision" ]] \
    || exit 1
  cat "$host_provision_output" >&2

  prefix_after_host_sha256="$(dd if="$rescue_media" bs=4M iflag=count_bytes \
    count="$iso_bytes" status=none | sha256sum | awk '{print $1}')"
  p3_base_sha256="$(dd if="$rescue_media" bs=4M iflag=skip_bytes,count_bytes \
    skip="$p3_start_bytes" count="$p3_bytes" status=none \
    | sha256sum | awk '{print $1}')"
  [[ "$prefix_after_host_sha256" == "$iso_sha256" \
    && "$p3_base_sha256" =~ ^[0-9a-f]{64}$ \
    && "$(sha256sum "$vault_key" | awk '{print $1}')" \
      == "$key_before_host_sha256" \
    && "$(stat -c '%u:%a:%h:%s' -- "$vault_key")" \
      == "$EUID:600:1:64" \
    && "$(sha256sum "$target_image" | awk '{print $1}')" \
      == "$target_before_host_sha256" ]] || exit 1

  qualification_cases=(
    bios:apply
    uefi:apply
    uefi:rollback
    uefi:interrupt-reconcile
    uefi:stale-target
    uefi:cancel
    uefi:backup-tamper
    uefi:repaird-termination
    uefi:auto-restore
    uefi:crypttab-lifecycle
    uefi:ext4-apply
    uefi:resolver-link-apply
  )
  for qualification_case in "${qualification_cases[@]}"; do
    case_firmware="${qualification_case%%:*}"
    case_scenario="${qualification_case#*:}"
    printf 'KERNAID_QEMU_REPAIR_QUALIFICATION_CASE_V1 firmware=%s scenario=%s\n' \
      "$case_firmware" "$case_scenario" >&2
    case_output="$(
      KERNAID_REPAIR_PROVISIONED_BASE="$rescue_media" \
      KERNAID_REPAIR_PROVISIONED_KEY="$vault_key" \
      KERNAID_REPAIR_TARGET_BASE="$target_image" \
      KERNAID_QEMU_SMP="$qemu_smp" \
        "$repo_dir/tools/build-rescue/qemu-repair-candidate-smoke.sh" \
        "$case_firmware" "$case_scenario" "$iso"
    )"
    case_pattern="^KERNAID_QEMU_REPAIR_CANDIDATE_ATTESTATION_V1 .* firmware=$case_firmware scenario=$case_scenario .* iso_sha256=$iso_sha256 .* ready=true$"
    [[ "$case_output" != *$'\n'* && "$case_output" =~ $case_pattern ]] \
      || exit 1
  done

  p3_after_cases_sha256="$(dd if="$rescue_media" bs=4M \
    iflag=skip_bytes,count_bytes skip="$p3_start_bytes" count="$p3_bytes" \
    status=none | sha256sum | awk '{print $1}')"
  prefix_after_sha256="$(dd if="$rescue_media" bs=4M iflag=count_bytes \
    count="$iso_bytes" status=none | sha256sum | awk '{print $1}')"
  [[ "$prefix_after_sha256" == "$iso_sha256" \
    && "$p3_after_cases_sha256" == "$p3_base_sha256" \
    && "$(sha256sum "$target_image" | awk '{print $1}')" \
      == "$target_before_host_sha256" \
    && "$(sha256sum "$vault_key" | awk '{print $1}')" \
      == "$key_before_host_sha256" \
    && "$(stat -c '%u:%a:%h:%s' -- "$vault_key")" \
      == "$EUID:600:1:64" ]] || exit 1
  printf '%s\n' \
    "KERNAID_QEMU_REPAIR_QUALIFICATION_BATCH_ATTESTATION_V1 provisioning=host-probe-canonical-v1 guest_firstboot=not-claimed standard_firstboot_gate=unchanged-separate scenarios=bios-apply,uefi-apply,uefi-rollback,uefi-interrupt-reconcile,uefi-stale-target,uefi-cancel,uefi-backup-tamper,uefi-repaird-termination,uefi-auto-restore,uefi-crypttab-lifecycle,uefi-ext4-apply,uefi-resolver-link-apply actions=linux.fstab.disable-missing-uuid.v1,linux.crypttab.disable-missing-uuid.v1,linux.ext4.fsck-preen-with-undo.v1,linux.network.restore-resolver-link.v1 vault_profile=canonical-v1 vault_identity=initialize-verify-stable p3=exact key=private-mode-0600 target=separate base_immutable=true isolated_sparse_copies=true iso_sha256=$iso_sha256 iso_prefix_immutable=true host_physical_devices=false ready=true"
  exit 0
fi

if [[ "$scenario" == ext4-apply ]]; then
  # Create one deterministic, preen-repairable inconsistency only in this
  # isolated scenario copy. The shared provisioned base remains byte-exact.
  ext4_marker_inode="$(
    debugfs -R "stat /srv/archive/ext4-repair-marker" "$target_image" 2>/dev/null \
      | awk '/^Inode:/ {print $2}'
  )"
  [[ "$ext4_marker_inode" =~ ^[1-9][0-9]*$ ]] || exit 1
  debugfs -w -R "clri <$ext4_marker_inode>" "$target_image" >/dev/null 2>&1
  set +e
  e2fsck -f -n "$target_image" >"$work_dir/ext4-preflight.out" 2>&1
  ext4_preflight_status=$?
  set -e
  [[ "$ext4_preflight_status" -eq 4 ]] || exit 1
  target_before_sha256="$(sha256sum "$target_image" | awk '{print $1}')"
fi

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
  -device virtio-blk-pci,id=kernaid_repair_target_device,drive=kernaid_repair_target,serial=KERNAID-REPAIR-V1
  -fw_cfg name=opt/kernaid-tauri-sandbox-probe,string=v1
)

qualification_fault=""
if [[ "$scenario" == repaird-termination || "$scenario" == auto-restore ]]; then
  qualification_fault="$work_dir/qualification-fault"
  if [[ "$scenario" == repaird-termination ]]; then
    printf %s terminate-after-pending-v1 >"$qualification_fault"
  else
    printf %s fail-after-installed-v1 >"$qualification_fault"
  fi
  chmod 600 -- "$qualification_fault"
  qemu_args+=(
    -fw_cfg
    "name=opt/io.systemd.credentials/kernaid-repair-fault,file=$qualification_fault"
  )
fi

set +e
controller_scenario="$scenario"
if [[ "$scenario" == failure-paths ]]; then
  controller_scenario=provision-base
fi
controller_before_sha256="$before_sha256"
controller_after_sha256="$after_sha256"
if [[ "$scenario" == crypttab-lifecycle ]]; then
  controller_before_sha256="$crypttab_before_sha256"
  controller_after_sha256="$crypttab_after_sha256"
elif [[ "$scenario" == resolver-link-apply ]]; then
  controller_before_sha256="$resolver_before_sha256"
  controller_after_sha256="$resolver_after_sha256"
fi
controller_args=(
  --qemu "$(command -v qemu-system-x86_64)"
  --qmp-socket "$qmp_socket"
  --firmware "$firmware"
  --scenario "$controller_scenario"
  --vault-key-fd 3 --login-credential-fd 4
  --before-sha256 "$controller_before_sha256"
  --after-sha256 "$controller_after_sha256"
  --timeout "$controller_timeout"
)
if [[ "$already_provisioned" == true ]]; then
  controller_args+=(--already-provisioned)
fi
if [[ "$scenario" == backup-tamper ]]; then
  controller_args+=(
    --media-path "$rescue_media"
    --vault-key-path "$vault_key"
    --tamper-helper "$tamper_helper"
  )
fi
if [[ "$firmware" == uefi ]]; then
  controller_args+=(
    --ovmf-code "$ovmf_code"
    --ovmf-vars-template "$ovmf_vars_template"
  )
fi
if [[ "$scenario" == failure-paths ]]; then
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
  expected_base="KERNAID_QEMU_REPAIR_CANDIDATE_GUEST_V1 action=none firmware=uefi scenario=provision-base before_sha256=$before_sha256 after_sha256=$after_sha256 vault_distinct=true terminal=provisioned reusable_base=true ready=true"
  [[ "$(cat "$controller_output")" == "$expected_base" ]] || exit 1
  [[ "$(sha256sum "$target_image" | awk '{print $1}')" == "$target_before_sha256" ]] \
    || exit 1

  failure_cases=(
    stale-target
    cancel
    backup-tamper
    repaird-termination
    auto-restore
  )
  for failure_case in "${failure_cases[@]}"; do
    printf 'KERNAID_QEMU_REPAIR_FAILURE_CASE_V1 scenario=%s\n' \
      "$failure_case" >&2
    case_output="$(
      KERNAID_REPAIR_PROVISIONED_BASE="$rescue_media" \
      KERNAID_REPAIR_PROVISIONED_KEY="$vault_key" \
      KERNAID_REPAIR_TARGET_BASE="$target_image" \
      KERNAID_QEMU_SMP="$qemu_smp" \
        "$repo_dir/tools/build-rescue/qemu-repair-candidate-smoke.sh" \
        uefi "$failure_case" "$iso"
    )"
    case_pattern="^KERNAID_QEMU_REPAIR_CANDIDATE_ATTESTATION_V1 .* scenario=$failure_case .* iso_sha256=$iso_sha256 .* ready=true$"
    [[ "$case_output" != *$'\n'* \
      && "$case_output" =~ $case_pattern ]] \
      || exit 1
  done
  [[ "$(sha256sum "$target_image" | awk '{print $1}')" == "$target_before_sha256" \
    && "$(stat -c '%s' -- "$vault_key")" == 64 \
    && "$(tr -d '0-9a-f' <"$vault_key")" == "" ]] || exit 1
  prefix_after_sha256="$(dd if="$rescue_media" bs=4M iflag=count_bytes \
    count="$iso_bytes" status=none | sha256sum | awk '{print $1}')"
  [[ "$prefix_after_sha256" == "$iso_sha256" ]] || exit 1
  printf '%s\n' \
    "KERNAID_QEMU_REPAIR_FAILURE_PATHS_ATTESTATION_V1 firmware=uefi scenarios=stale-target,cancel,backup-tamper,repaird-termination,auto-restore provisioning=shared isolated_sparse_copies=true stale_target=rejected cancellation=closed backup_tamper=rejected repaird_restart=closed automatic_restore=closed-before-restored iso_sha256=$iso_sha256 iso_prefix_immutable=true host_physical_devices=false ready=true"
  exit 0
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
elif [[ "$scenario" == interrupt-reconcile ]]; then
  expected_guest="KERNAID_QEMU_REPAIR_CANDIDATE_GUEST_V1 action=linux.fstab.disable-missing-uuid.v1 firmware=$firmware scenario=interrupt-reconcile before_sha256=$before_sha256 after_sha256=$after_sha256 vault_distinct=true terminal=restored interruption=qmp-after-target-write recovery=closed ready=true"
  expected_fstab="$seed/etc/fstab"
  expected_terminal=restored
elif [[ "$scenario" == stale-target ]]; then
  expected_guest="KERNAID_QEMU_REPAIR_CANDIDATE_GUEST_V1 action=linux.fstab.disable-missing-uuid.v1 firmware=uefi scenario=stale-target before_sha256=$before_sha256 after_sha256=$after_sha256 vault_distinct=true terminal=failed stale_target=rejected target_writes=zero ready=true"
  expected_fstab="$seed/etc/fstab"
  expected_terminal=failed
elif [[ "$scenario" == cancel ]]; then
  expected_guest="KERNAID_QEMU_REPAIR_CANDIDATE_GUEST_V1 action=linux.fstab.disable-missing-uuid.v1 firmware=uefi scenario=cancel before_sha256=$before_sha256 after_sha256=$after_sha256 vault_distinct=true terminal=cancelled authority=released target_writes=zero ready=true"
  expected_fstab="$seed/etc/fstab"
  expected_terminal=cancelled
elif [[ "$scenario" == backup-tamper ]]; then
  expected_guest="KERNAID_QEMU_REPAIR_CANDIDATE_GUEST_V1 action=linux.fstab.restore firmware=uefi scenario=backup-tamper before_sha256=$before_sha256 after_sha256=$after_sha256 vault_distinct=true terminal=rejected backup_tamper=authenticated target_writes_second_boot=zero ready=true"
  expected_fstab="$expected_after"
  expected_terminal=rejected
elif [[ "$scenario" == repaird-termination ]]; then
  expected_guest="KERNAID_QEMU_REPAIR_CANDIDATE_GUEST_V1 action=linux.fstab.disable-missing-uuid.v1 firmware=uefi scenario=repaird-termination before_sha256=$before_sha256 after_sha256=$after_sha256 vault_distinct=true terminal=restored process=repaird-only recovery=closed-before-unchanged target_writes=zero ready=true"
  expected_fstab="$seed/etc/fstab"
  expected_terminal=restored
elif [[ "$scenario" == crypttab-lifecycle ]]; then
  expected_guest="KERNAID_QEMU_REPAIR_CANDIDATE_GUEST_V1 action=linux.crypttab.disable-missing-source.v1 firmware=uefi scenario=crypttab-lifecycle before_sha256=$controller_before_sha256 after_sha256=$controller_after_sha256 vault_distinct=true apply=committed terminal=rolled-back-original rollback=fresh-typed-single-use exact_bytes=restored ready=true"
  expected_fstab="$seed/etc/fstab"
  expected_terminal=rolled-back-original
elif [[ "$scenario" == ext4-apply ]]; then
  expected_guest="KERNAID_QEMU_REPAIR_CANDIDATE_GUEST_V1 action=linux.ext4.fsck-preen-with-undo.v1 firmware=uefi scenario=ext4-apply contract_hashes=validated vault_distinct=true terminal=committed postcheck=clean same_boot_undo=armed postcommit_rollback=unavailable approval=typed-single-use ready=true"
  expected_fstab="$seed/etc/fstab"
  expected_terminal=committed
elif [[ "$scenario" == resolver-link-apply ]]; then
  expected_guest="KERNAID_QEMU_REPAIR_CANDIDATE_GUEST_V1 action=linux.network.restore-resolver-link.v1 firmware=uefi scenario=resolver-link-apply before_sha256=$controller_before_sha256 after_sha256=$controller_after_sha256 vault_distinct=true terminal=committed link=resolved-stub-relative rollback=automatic-on-failure approval=typed-single-use ready=true"
  expected_fstab="$seed/etc/fstab"
  expected_terminal=committed
else
  expected_guest="KERNAID_QEMU_REPAIR_CANDIDATE_GUEST_V1 action=linux.fstab.disable-missing-uuid.v1 firmware=uefi scenario=auto-restore before_sha256=$before_sha256 after_sha256=$after_sha256 vault_distinct=true terminal=restored fault=after-installed recovery=closed-before-restored target_writes=positive ready=true"
  expected_fstab="$seed/etc/fstab"
  expected_terminal=restored
fi
[[ "$(cat "$controller_output")" == "$expected_guest" ]] || exit 1

debugfs -R "dump -p /etc/fstab $observed_fstab" "$target_image" >/dev/null 2>&1
debugfs -R "dump -p /boot/vmlinuz-kernaid-repair $observed_sentinel" \
  "$target_image" >/dev/null 2>&1
debugfs -R "stat /etc/fstab" "$target_image" >"$observed_fstab_stat" 2>/dev/null
debugfs -R "ls -p /etc" "$target_image" >"$observed_etc_listing" 2>/dev/null
cmp -s -- "$expected_fstab" "$observed_fstab"
[[ "$(cat "$observed_sentinel")" == KERNAID_REPAIR_TARGET_SENTINEL ]]
grep -Eq '^Inode: [0-9]+[[:space:]]+Type: regular[[:space:]]+Mode:[[:space:]]+0644' \
  "$observed_fstab_stat"
grep -Eq '^User:[[:space:]]+0[[:space:]]+Group:[[:space:]]+0([[:space:]]|$)' \
  "$observed_fstab_stat"
grep -Eq '^File ACL:[[:space:]]+0([[:space:]]|$)' "$observed_fstab_stat"
if grep -Eq '^Extended attributes:' "$observed_fstab_stat"; then
  exit 1
fi
if grep -Eq 'kernaid-(fstab|crypttab|resolv\.conf)-(stage|restore)-v1' \
  "$observed_etc_listing"; then
  exit 1
fi

if [[ "$scenario" == crypttab-lifecycle ]]; then
  debugfs -R "dump -p /etc/crypttab $observed_crypttab" \
    "$target_image" >/dev/null 2>&1
  debugfs -R "stat /etc/crypttab" "$target_image" \
    >"$observed_crypttab_stat" 2>/dev/null
  cmp -s -- "$seed/etc/crypttab" "$observed_crypttab"
  grep -Eq '^Inode: [0-9]+[[:space:]]+Type: regular[[:space:]]+Mode:[[:space:]]+0644' \
    "$observed_crypttab_stat"
  grep -Eq '^User:[[:space:]]+0[[:space:]]+Group:[[:space:]]+0([[:space:]]|$)' \
    "$observed_crypttab_stat"
  grep -Eq '^File ACL:[[:space:]]+0([[:space:]]|$)' "$observed_crypttab_stat"
  if grep -Eq '^Extended attributes:' "$observed_crypttab_stat"; then
    exit 1
  fi
elif [[ "$scenario" == resolver-link-apply ]]; then
  debugfs -R "stat /etc/resolv.conf" "$target_image" \
    >"$observed_resolver_stat" 2>/dev/null
  grep -Eq '^Inode: [0-9]+[[:space:]]+Type: symlink[[:space:]]+Mode:[[:space:]]+0777' \
    "$observed_resolver_stat"
  grep -Eq '^User:[[:space:]]+0[[:space:]]+Group:[[:space:]]+0([[:space:]]|$)' \
    "$observed_resolver_stat"
  grep -Fqx 'Fast link dest: "../run/systemd/resolve/stub-resolv.conf"' \
    "$observed_resolver_stat"
  grep -Eq '^File ACL:[[:space:]]+0([[:space:]]|$)' "$observed_resolver_stat"
  if grep -Eq '^Extended attributes:' "$observed_resolver_stat"; then
    exit 1
  fi
elif [[ "$scenario" == ext4-apply ]]; then
  ext4_before_postcheck_sha256="$(sha256sum "$target_image" | awk '{print $1}')"
  set +e
  e2fsck -f -n "$target_image" >"$work_dir/ext4-postcheck.out" 2>&1
  ext4_postcheck_status=$?
  set -e
  [[ "$ext4_postcheck_status" -eq 0 \
    && "$(sha256sum "$target_image" | awk '{print $1}')" \
      == "$ext4_before_postcheck_sha256" ]] || exit 1
fi
target_after_sha256="$(sha256sum "$target_image" | awk '{print $1}')"
if [[ "$scenario" == apply || "$scenario" == crypttab-lifecycle \
  || "$scenario" == ext4-apply || "$scenario" == resolver-link-apply ]]; then
  [[ "$target_after_sha256" != "$target_before_sha256" ]]
elif [[ "$scenario" == stale-target || "$scenario" == cancel \
  || "$scenario" == repaird-termination ]]; then
  [[ "$target_after_sha256" == "$target_before_sha256" ]]
elif [[ "$scenario" == backup-tamper || "$scenario" == auto-restore ]]; then
  [[ "$target_after_sha256" != "$target_before_sha256" ]]
fi
prefix_after_sha256="$(dd if="$rescue_media" bs=4M iflag=count_bytes \
  count="$iso_bytes" status=none | sha256sum | awk '{print $1}')"
[[ "$prefix_after_sha256" == "$iso_sha256" ]]

if [[ "$scenario" == rollback || "$scenario" == backup-tamper ]]; then
  attested_action=linux.fstab.restore
elif [[ "$scenario" == crypttab-lifecycle ]]; then
  attested_action=linux.crypttab.disable-missing-source.v1
elif [[ "$scenario" == ext4-apply ]]; then
  attested_action=linux.ext4.fsck-preen-with-undo.v1
elif [[ "$scenario" == resolver-link-apply ]]; then
  attested_action=linux.network.restore-resolver-link.v1
else
  attested_action=linux.fstab.disable-missing-uuid.v1
fi
case "$scenario" in
  stale-target|cancel|repaird-termination)
    failure_attestation=" target_writes=zero target_raw_immutable=true"
    ;;
  backup-tamper)
    failure_attestation=" target_writes_second_boot=zero final_state=after"
    ;;
  auto-restore)
    failure_attestation=" target_writes=positive final_state=before recovery=closed-before-restored"
    ;;
  crypttab-lifecycle)
    failure_attestation=" apply=committed rollback=fresh-typed-single-use target_writes=positive"
    ;;
  ext4-apply)
    failure_attestation=" target_writes=positive"
    ;;
  resolver-link-apply)
    failure_attestation=" rollback=automatic-on-failure target_writes=positive"
    ;;
  *)
    failure_attestation=""
    ;;
esac
resource_attestation="before_sha256=$controller_before_sha256 after_sha256=$controller_after_sha256 exact_bytes=true metadata=mode-uid-gid-no-xattrs"
if [[ "$scenario" == crypttab-lifecycle ]]; then
  resource_attestation="before_sha256=$controller_before_sha256 after_sha256=$controller_after_sha256 exact_bytes=restored metadata=mode-uid-gid-no-xattrs"
elif [[ "$scenario" == ext4-apply ]]; then
  resource_attestation="contract_hashes=validated postcheck=clean same_boot_undo=armed"
elif [[ "$scenario" == resolver-link-apply ]]; then
  resource_attestation="before_sha256=$controller_before_sha256 after_sha256=$controller_after_sha256 exact_link=resolved-stub-relative metadata=uid-gid-no-xattrs"
fi
printf '%s\n' \
  "KERNAID_QEMU_REPAIR_CANDIDATE_ATTESTATION_V1 action=$attested_action firmware=$firmware scenario=$scenario drives=rescue-usb,target-ext4 physical_parents=distinct vault=luks2-ext4 $resource_attestation stage_cleanup=true terminal=$expected_terminal iso_sha256=$iso_sha256 iso_prefix_immutable=true host_physical_devices=false${failure_attestation} ready=true"
