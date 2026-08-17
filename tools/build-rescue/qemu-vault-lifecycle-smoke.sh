#!/usr/bin/env bash
set -Eeuo pipefail

umask 077

# Preserve one private diagnostic descriptor, then suppress every uncontrolled
# tool diagnostic. Only the closed failure vocabulary is ever copied out.
exec 8>&2
exec 2>/dev/null

readonly failure_prefix=KERNAID_QEMU_VAULT_LIFECYCLE_FAILURE_V1
readonly boot_prefix=KERNAID_QEMU_VAULT_LIFECYCLE_BOOT_V1
readonly raw_prefix=KERNAID_QEMU_VAULT_LIFECYCLE_RAW_V1
readonly attestation_prefix=KERNAID_QEMU_VAULT_LIFECYCLE_ATTESTATION_V1
readonly media_bytes=32000000000
readonly p3_start_bytes=17179869184
readonly p3_bytes=8589934592
readonly boot_count=2

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
firmware="${1:-bios}"
iso="${2:-$repo_dir/KernAid-Rescue-amd64.iso}"
probe_binary="${3:-$repo_dir/target/release/kernaid-rescue-vault-probe}"
controller="$repo_dir/tools/build-rescue/qemu-vault-lifecycle-pty.py"
layout_manifest="$repo_dir/rescue/image-layout/device-layout.v1.json"

failure_emitted=0
work_dir=""
key_dir=""
vault_loop=""
iso_loop=""
iso_mount=""
iso_mounted=0
provision_mapper=""
manager_mapper=""
provision_mount=""
provision_open=0
provision_mounted=0
controller_pid=""
owned_pgid=""
owned_pgid_file=""
owned_executable=""
owned_group_validated=0
wrapper_interrupted=0

emit_failure() {
  local stage="$1"
  local code="$2"
  if [[ ! "$stage" =~ ^[a-z0-9-]+$ || ! "$code" =~ ^[a-z0-9-]+$ ]]; then
    stage=wrapper
    code=invalid-diagnostic
  fi
  if [[ "$failure_emitted" == 0 ]]; then
    printf '%s\n' "$failure_prefix stage=$stage code=$code" >&8
    failure_emitted=1
  fi
}

fail() {
  emit_failure "$1" "$2"
  exit 1
}

mapper_active() {
  [[ -n "$1" ]] && cryptsetup status "$1" >/dev/null 2>&1
}

owned_group_exists() {
  [[ "$owned_pgid" =~ ^[1-9][0-9]*$ ]] \
    && kill -0 -- "-$owned_pgid" >/dev/null 2>&1
}

owned_group_matches() {
  local observed_executable observed_pgid observed_sid
  [[ "$owned_pgid" =~ ^[1-9][0-9]*$ && "$owned_pgid" -gt 1 \
    && -n "$owned_executable" && -e "/proc/$owned_pgid/exe" ]] || return 1
  observed_executable="$(readlink -f -- "/proc/$owned_pgid/exe" 2>/dev/null)" \
    || return 1
  observed_pgid="$(ps -o pgid= -p "$owned_pgid" 2>/dev/null | tr -d '[:space:]')" \
    || return 1
  observed_sid="$(ps -o sid= -p "$owned_pgid" 2>/dev/null | tr -d '[:space:]')" \
    || return 1
  [[ "$observed_executable" == "$(readlink -f -- "$owned_executable")" \
    && "$observed_pgid" == "$owned_pgid" && "$observed_sid" == "$owned_pgid" ]]
}

terminate_owned_group() {
  local deadline
  owned_group_exists || return 0
  [[ "$owned_group_validated" == 1 ]] || return 1
  kill -TERM -- "-$owned_pgid" >/dev/null 2>&1 || return 1
  deadline=$((SECONDS + 5))
  while owned_group_exists && ((SECONDS < deadline)); do
    sleep 0.05 || true
  done
  if owned_group_exists; then
    kill -KILL -- "-$owned_pgid" >/dev/null 2>&1 || return 1
    deadline=$((SECONDS + 5))
    while owned_group_exists && ((SECONDS < deadline)); do
      sleep 0.05 || true
    done
  fi
  ! owned_group_exists
}

stop_active_controller() {
  local signal_name="${1:-TERM}"
  local deadline
  local failed=0
  local load_status=0
  if [[ -z "$owned_pgid" && -n "$owned_pgid_file" \
    && -e "$owned_pgid_file" ]]; then
    if load_owned_group_publication; then
      load_status=0
    else
      load_status=$?
    fi
    [[ "$load_status" != 1 ]] || failed=1
  fi
  if [[ "$controller_pid" =~ ^[1-9][0-9]*$ ]] \
    && kill -0 "$controller_pid" 2>/dev/null; then
    kill -s "$signal_name" "$controller_pid" 2>/dev/null || failed=1
    deadline=$((SECONDS + 10))
    while kill -0 "$controller_pid" 2>/dev/null && ((SECONDS < deadline)); do
      sleep 0.05 || true
    done
    if kill -0 "$controller_pid" 2>/dev/null; then
      kill -KILL "$controller_pid" 2>/dev/null || failed=1
    fi
    wait "$controller_pid" 2>/dev/null || true
  fi
  controller_pid=""
  if [[ -z "$owned_pgid" && -n "$owned_pgid_file" \
    && -e "$owned_pgid_file" ]]; then
    if load_owned_group_publication; then
      load_status=0
    else
      load_status=$?
    fi
    [[ "$load_status" != 1 ]] || failed=1
  fi
  if owned_group_exists; then
    terminate_owned_group || failed=1
  fi
  owned_group_exists && failed=1
  return "$failed"
}

prepare_owned_group_file() {
  local path="$1"
  local executable="$2"
  : >"$path" || return 1
  chmod 600 -- "$path" >/dev/null 2>&1 || return 1
  [[ "$(stat -c '%a:%u:%g:%h:%s' -- "$path" 2>/dev/null)" == 600:0:0:1:0 ]] \
    || return 1
  owned_pgid=""
  owned_pgid_file="$path"
  owned_executable="$executable"
  owned_group_validated=0
}

load_owned_group_publication() {
  local observed_ppid metadata published_size final_byte
  local -a pgid_lines=()
  metadata="$(stat -c '%a:%u:%g:%h:%s' -- "$owned_pgid_file" 2>/dev/null)" \
    || return 1
  [[ "$metadata" =~ ^600:0:0:1:([0-9]{1,2})$ \
    && "${BASH_REMATCH[1]}" -le 32 ]] || return 1
  published_size="${BASH_REMATCH[1]}"
  [[ "$published_size" != 0 ]] || return 2
  final_byte="$(
    od -An -j "$((published_size - 1))" -N1 -tu1 -- "$owned_pgid_file" \
      2>/dev/null | tr -d '[:space:]'
  )" || return 1
  if [[ "$final_byte" != 10 ]]; then
    if [[ "$controller_pid" =~ ^[1-9][0-9]*$ ]] \
      && kill -0 "$controller_pid" 2>/dev/null; then
      return 2
    fi
    return 1
  fi
  mapfile -t pgid_lines <"$owned_pgid_file" || return 1
  [[ "${#pgid_lines[@]}" != 0 ]] || return 1
  if [[ "${#pgid_lines[@]}" != 1 \
    || ! "${pgid_lines[0]}" =~ ^[1-9][0-9]*$ ]]; then
    if [[ "$controller_pid" =~ ^[1-9][0-9]*$ ]] \
      && kill -0 "$controller_pid" 2>/dev/null; then
      return 2
    fi
    return 1
  fi
  owned_pgid="${pgid_lines[0]}"
  if ! owned_group_exists; then
    owned_pgid=""
    owned_group_validated=0
    return 0
  fi
  if ! owned_group_matches; then
    if [[ "$controller_pid" =~ ^[1-9][0-9]*$ ]] \
      && kill -0 "$controller_pid" 2>/dev/null; then
      owned_pgid=""
      return 2
    fi
    return 1
  fi
  if [[ "$controller_pid" =~ ^[1-9][0-9]*$ ]] \
    && kill -0 "$controller_pid" 2>/dev/null; then
    observed_ppid="$(ps -o ppid= -p "$owned_pgid" 2>/dev/null | tr -d '[:space:]')" \
      || return 1
    [[ "$observed_ppid" == "$controller_pid" ]] || return 1
  fi
  owned_group_validated=1
}

await_owned_group_publication() {
  local deadline=$((SECONDS + 15))
  local load_status
  while ((SECONDS < deadline)); do
    if load_owned_group_publication; then
      return 0
    else
      load_status=$?
    fi
    [[ "$load_status" == 2 ]] || return 1
    if [[ ! "$controller_pid" =~ ^[1-9][0-9]*$ ]] \
      || ! kill -0 "$controller_pid" 2>/dev/null; then
      return 2
    fi
    sleep 0.05 || true
  done
  return 1
}

clear_owned_group_tracking() {
  if [[ -n "$owned_pgid_file" && -e "$owned_pgid_file" ]]; then
    rm -f -- "$owned_pgid_file" >/dev/null 2>&1 || return 1
  fi
  owned_pgid=""
  owned_pgid_file=""
  owned_executable=""
  owned_group_validated=0
}

cleanup() {
  local status="$1"
  local cleanup_failed=0
  trap - EXIT INT TERM HUP QUIT
  set +e
  stop_active_controller TERM || cleanup_failed=1
  clear_owned_group_tracking || cleanup_failed=1
  if [[ "$provision_mounted" == 1 && -n "$provision_mount" ]]; then
    umount -- "$provision_mount" >/dev/null 2>&1 || cleanup_failed=1
    provision_mounted=0
  fi
  if [[ "$provision_open" == 1 ]] && mapper_active "$provision_mapper"; then
    cryptsetup close "$provision_mapper" >/dev/null 2>&1 || cleanup_failed=1
    provision_open=0
  fi
  if mapper_active "$manager_mapper"; then
    manager_mount="/run/kernaid/vault/$manager_mapper"
    if mountpoint -q "$manager_mount" >/dev/null 2>&1; then
      umount -- "$manager_mount" >/dev/null 2>&1 || cleanup_failed=1
    fi
    cryptsetup close "$manager_mapper" >/dev/null 2>&1 || cleanup_failed=1
  fi
  if [[ "$vault_loop" =~ ^/dev/loop[0-9]+$ ]]; then
    losetup -d -- "$vault_loop" >/dev/null 2>&1 || cleanup_failed=1
    vault_loop=""
  fi
  if [[ "$iso_mounted" == 1 && -n "$iso_mount" ]]; then
    umount -- "$iso_mount" >/dev/null 2>&1 || cleanup_failed=1
    iso_mounted=0
  fi
  if [[ "$iso_loop" =~ ^/dev/loop[0-9]+$ ]]; then
    losetup -d -- "$iso_loop" >/dev/null 2>&1 || cleanup_failed=1
    iso_loop=""
  fi
  if [[ -n "$key_dir" ]]; then
    case "$key_dir" in
      /dev/shm/kernaid-qemu-vault-lifecycle-key.*)
        rm -f -- "$key_dir/correct" "$key_dir/wrong" "$key_dir/login" \
          >/dev/null 2>&1 || cleanup_failed=1
        rmdir -- "$key_dir" >/dev/null 2>&1 || cleanup_failed=1
        ;;
      *) cleanup_failed=1 ;;
    esac
  fi
  if [[ -n "$work_dir" ]]; then
    case "$work_dir" in
      /tmp/kernaid-qemu-vault-lifecycle.*)
        rm -rf -- "$work_dir" >/dev/null 2>&1 || cleanup_failed=1
        ;;
      *) cleanup_failed=1 ;;
    esac
  fi
  if mapper_active "$provision_mapper" || mapper_active "$manager_mapper"; then
    cleanup_failed=1
  fi
  if [[ "$cleanup_failed" != 0 ]]; then
    status=1
    emit_failure cleanup residue
  fi
  if [[ "$status" -ne 0 && "$failure_emitted" == 0 ]]; then
    emit_failure wrapper unexpected
  fi
  exit "$status"
}

trap 'cleanup $?' EXIT

forward_signal() {
  local signal_name="$1"
  local exit_status="$2"
  wrapper_interrupted="$exit_status"
  trap - INT TERM HUP QUIT
  if ! stop_active_controller "$signal_name"; then
    emit_failure cleanup residue
  else
    emit_failure wrapper interrupted
  fi
  exit "$exit_status"
}

trap 'forward_signal INT 130' INT
trap 'forward_signal TERM 143' TERM
trap 'forward_signal HUP 129' HUP
trap 'forward_signal QUIT 131' QUIT

if [[ "$firmware" != bios && "$firmware" != uefi ]]; then
  fail arguments firmware-invalid
fi

# Future workflow wiring must install squashfs-tools; this separate smoke
# fail-closes here until its unsquashfs reader is available.
for command in awk blkid chmod cmp cp cryptsetup dd findmnt grep id losetup \
  mkdir mkfs.ext4 mktemp mkswap mount mountpoint od python3 qemu-system-x86_64 \
  ps readlink rm rmdir sha256sum sleep stat sync timeout tr truncate tune2fs \
  udevadm umount unsquashfs; do
  command -v "$command" >/dev/null 2>&1 || fail preflight tool-missing
done

[[ "$(id -u)" == 0 ]] || fail preflight root-required
[[ "$(findmnt -n -o FSTYPE --target /dev/shm 2>/dev/null)" == tmpfs ]] \
  || fail preflight secret-tmpfs-required
[[ -f "$iso" && ! -L "$iso" ]] || fail preflight iso-invalid
[[ -f "$layout_manifest" && ! -L "$layout_manifest" ]] \
  || fail preflight layout-invalid
[[ -f "$controller" && ! -L "$controller" ]] || fail preflight controller-invalid
[[ -f "$probe_binary" && -x "$probe_binary" && ! -L "$probe_binary" ]] \
  || fail preflight probe-invalid

qemu_binary="$(command -v qemu-system-x86_64)"
[[ "$qemu_binary" == /* && -x "$qemu_binary" && ! -L "$qemu_binary" ]] \
  || fail preflight qemu-invalid

python3 -I "$repo_dir/tools/build-rescue/finalize-device-layout.py" verify \
  --manifest "$layout_manifest" --image "$iso" >/dev/null 2>&1 \
  || fail preflight iso-layout-invalid

iso_bytes="$(stat -c '%s' -- "$iso" 2>/dev/null)" \
  || fail preflight iso-stat-failed
[[ "$iso_bytes" =~ ^[0-9]+$ ]] || fail preflight iso-size-invalid
((iso_bytes >= 512 && iso_bytes < p3_start_bytes)) \
  || fail preflight iso-size-invalid

work_dir="$(mktemp -d /tmp/kernaid-qemu-vault-lifecycle.XXXXXXXX)" \
  || fail allocation workdir-failed
key_dir="$(mktemp -d /dev/shm/kernaid-qemu-vault-lifecycle-key.XXXXXXXX)" \
  || fail allocation keydir-failed
chmod 700 -- "$work_dir" "$key_dir" >/dev/null 2>&1 \
  || fail allocation mode-failed
[[ "$(stat -c '%a:%u:%g:%h' -- "$work_dir")" == 700:0:0:2 ]] \
  || fail allocation workdir-metadata
[[ "$(stat -c '%a:%u:%g:%h' -- "$key_dir")" == 700:0:0:2 ]] \
  || fail allocation keydir-metadata

iso_mount="$work_dir/iso"
mkdir -- "$iso_mount" >/dev/null 2>&1 || fail credential mountpoint-failed
chmod 700 -- "$iso_mount" >/dev/null 2>&1 || fail credential mountpoint-mode
iso_loops_before="$(losetup -j "$iso" 2>/dev/null)" \
  || fail credential iso-loop-inspect
iso_loop="$(losetup --find --show --read-only -- "$iso" 2>/dev/null)" \
  || fail credential iso-loop-failed
[[ "$iso_loop" =~ ^/dev/loop[0-9]+$ && -b "$iso_loop" ]] \
  || fail credential iso-loop-invalid
iso_loop_backing="$(
  losetup --noheadings --raw --output BACK-FILE -- "$iso_loop" 2>/dev/null
)" || fail credential iso-loop-inspect
iso_loop_read_only="$(
  losetup --noheadings --raw --output RO -- "$iso_loop" 2>/dev/null \
    | tr -d '[:space:]'
)" || fail credential iso-loop-inspect
[[ "$(readlink -f -- "$iso_loop_backing")" == "$(readlink -f -- "$iso")" \
  && "$iso_loop_read_only" == 1 ]] || fail credential iso-loop-scope
mount -t iso9660 -o ro,nosuid,nodev,noexec -- "$iso_loop" "$iso_mount" \
  >/dev/null 2>&1 || fail credential iso-mount-failed
iso_mounted=1
[[ "$(findmnt -n -o FSTYPE --target "$iso_mount" 2>/dev/null)" == iso9660 ]] \
  || fail credential iso-filesystem-invalid
iso_mount_options="$(findmnt -n -o OPTIONS --target "$iso_mount" 2>/dev/null)" \
  || fail credential iso-mount-inspect
for required_option in ro nosuid nodev noexec; do
  grep -Eq "(^|,)${required_option}(,|$)" <<<"$iso_mount_options" \
    || fail credential iso-mount-options
done
squashfs="$iso_mount/live/filesystem.squashfs"
[[ -f "$squashfs" && ! -L "$squashfs" ]] \
  || fail credential squashfs-invalid
squashfs_bytes="$(stat -c '%s' -- "$squashfs" 2>/dev/null)" \
  || fail credential squashfs-stat
[[ "$squashfs_bytes" =~ ^[1-9][0-9]*$ ]] \
  || fail credential squashfs-size
((squashfs_bytes <= 8589934592)) || fail credential squashfs-size

login_credential="$key_dir/login"
set +e
timeout --signal=TERM --kill-after=2s 30s \
  unsquashfs -cat "$squashfs" usr/lib/live/config/0030-user-setup \
  | python3 -I -B "$controller" --extract-live-credential \
      --source-fd 6 --credential-fd 7 6<&0 7>"$login_credential"
extract_status=("${PIPESTATUS[@]}")
set -e
[[ "${#extract_status[@]}" == 2 \
  && "${extract_status[0]}" == 0 && "${extract_status[1]}" == 0 ]] \
  || fail credential extraction-failed
login_metadata="$(stat -c '%a:%u:%g:%h:%s' -- "$login_credential" 2>/dev/null)" \
  || fail credential metadata-invalid
[[ "$login_metadata" =~ ^600:0:0:1:([1-9][0-9]{0,2})$ ]] \
  || fail credential metadata-invalid
((BASH_REMATCH[1] <= 128)) || fail credential metadata-invalid
umount -- "$iso_mount" >/dev/null 2>&1 || fail credential iso-unmount-failed
iso_mounted=0
losetup -d -- "$iso_loop" >/dev/null 2>&1 \
  || fail credential iso-loop-detach-failed
iso_loop=""
[[ "$(losetup -j "$iso" 2>/dev/null)" == "$iso_loops_before" ]] \
  || fail credential iso-loop-residue

correct_key="$key_dir/correct"
wrong_key="$key_dir/wrong"
if ! od -An -N32 -tx1 /dev/urandom | tr -d '[:space:]' >"$correct_key"; then
  fail secret generation-failed
fi
if ! od -An -N32 -tx1 /dev/urandom | tr -d '[:space:]' >"$wrong_key"; then
  fail secret generation-failed
fi
chmod 600 -- "$correct_key" "$wrong_key" >/dev/null 2>&1 \
  || fail secret mode-failed
for secret_file in "$correct_key" "$wrong_key"; do
  [[ "$(stat -c '%a:%u:%g:%h:%s' -- "$secret_file")" == 600:0:0:1:64 ]] \
    || fail secret metadata-invalid
  grep -Eq '^[0-9a-f]{64}$' "$secret_file" \
    || fail secret alphabet-invalid
done
if cmp -s -- "$correct_key" "$wrong_key"; then
  fail secret not-distinct
fi

run_host_probe() {
  local stage="$1"
  local mode="$2"
  local probe_output="$work_dir/probe-$mode.out"
  local probe_error="$work_dir/probe-$mode.err"
  local probe_pgid_file="$work_dir/probe-$mode.pgid"
  local controller_deadline controller_status controller_timed_out
  local publication_status residue=0
  local -a probe_lines=() probe_errors=()

  : >"$probe_output" || fail "$stage" probe-output-create
  : >"$probe_error" || fail "$stage" probe-error-create
  chmod 600 -- "$probe_output" "$probe_error" >/dev/null 2>&1 \
    || fail "$stage" probe-output-mode
  prepare_owned_group_file "$probe_pgid_file" "$probe_binary" \
    || fail "$stage" probe-pgid-file
  python3 -I -B "$controller" --run-bounded-probe \
    --probe "$probe_binary" --device "$vault_loop" \
    --mapper "$manager_mapper" --mode "$mode" \
    --correct-key-fd 3 --wrong-key-fd 4 --owned-pgid-fd 6 \
    --timeout 620 3<"$correct_key" 4<"$wrong_key" \
    6>"$probe_pgid_file" >"$probe_output" 2>"$probe_error" &
  controller_pid=$!
  if await_owned_group_publication; then
    publication_status=0
  else
    publication_status=$?
  fi
  if [[ "$publication_status" == 1 ]]; then
    stop_active_controller TERM || true
    clear_owned_group_tracking || true
    fail "$stage" probe-pgid-invalid
  fi

  controller_deadline=$((SECONDS + 640))
  controller_timed_out=0
  while kill -0 "$controller_pid" 2>/dev/null; do
    if ((SECONDS >= controller_deadline)); then
      controller_timed_out=1
      stop_active_controller TERM || true
      break
    fi
    sleep 0.05 || true
  done
  if [[ "$controller_timed_out" == 0 ]]; then
    set +e
    wait "$controller_pid"
    controller_status=$?
    set -e
    controller_pid=""
  else
    controller_status=124
  fi
  if owned_group_exists; then
    terminate_owned_group || residue=1
    residue=1
  fi
  clear_owned_group_tracking || residue=1
  [[ "$residue" == 0 ]] || fail cleanup probe-residue
  [[ "$controller_timed_out" == 0 ]] || fail "$stage" probe-timeout
  if [[ "$controller_status" -ne 0 ]]; then
    if [[ "$(stat -c '%s' -- "$probe_error" 2>/dev/null)" =~ ^[0-9]+$ \
      && "$(stat -c '%s' -- "$probe_error" 2>/dev/null)" -le 256 ]]; then
      mapfile -t probe_errors <"$probe_error"
      if [[ "${#probe_errors[@]}" == 1 \
        && "${probe_errors[0]}" =~ ^${failure_prefix}\ stage=[a-z0-9-]+\ code=[a-z0-9-]+$ ]]; then
        printf '%s\n' "${probe_errors[0]}" >&8
        failure_emitted=1
        exit 1
      fi
    fi
    fail "$stage" probe-failed
  fi
  [[ ! -s "$probe_error" ]] || fail "$stage" probe-error-invalid
  [[ "$(stat -c '%a:%u:%g:%h:%s' -- "$probe_output" 2>/dev/null)" \
    =~ ^600:0:0:1:([1-9][0-9]{0,2})$ \
    && "${BASH_REMATCH[1]}" -le 256 ]] || fail "$stage" probe-output-invalid
  mapfile -t probe_lines <"$probe_output"
  [[ "${#probe_lines[@]}" == 1 \
    && "${probe_lines[0]}" =~ ^KERNAID_RESCUE_VAULT_PROBE_ATTESTATION_V1\ mode=${mode}\ journal_binding=device-identity-bound-v1\ identity_public_key=[0-9a-f]{64}\ clean_shutdown=true$ ]] \
    || fail "$stage" probe-output-invalid
  probe_line="${probe_lines[0]}"
}

rescue_media="$work_dir/KernAid-Rescue-usb.raw"
observe_image="$work_dir/observe-target.raw"
swap_image="$work_dir/decoy-swap.raw"
observe_seed="$work_dir/observe-seed"
provision_mount="$work_dir/provision"
mkdir -p -- "$observe_seed/etc" "$observe_seed/boot" \
  "$observe_seed/var/lib/dpkg" "$provision_mount" >/dev/null 2>&1 \
  || fail provisioning directory-failed
printf '%s\n' \
  'ID=kernaid-lifecycle-fixture' \
  'NAME="KernAid lifecycle Observe fixture"' \
  'VERSION_ID="1"' >"$observe_seed/etc/os-release"
printf '%s\n' 'LABEL=KERNAID_OBSERVE / ext4 defaults 0 1' \
  >"$observe_seed/etc/fstab"
printf '%s\n' KERNAID_OBSERVE_TARGET_SENTINEL \
  >"$observe_seed/boot/vmlinuz-kernaid-lifecycle"
printf '%s\n' 'Package: kernaid-lifecycle-fixture' \
  >"$observe_seed/var/lib/dpkg/status"

truncate -s "$media_bytes" -- "$rescue_media" >/dev/null 2>&1 \
  || fail media allocate-failed
dd if="$iso" of="$rescue_media" bs=4M conv=notrunc status=none \
  || fail media iso-copy-failed
[[ "$(stat -c '%s' -- "$rescue_media")" == "$media_bytes" ]] \
  || fail media size-invalid
truncate -s 128M -- "$observe_image" >/dev/null 2>&1 \
  || fail observe allocate-failed
mkfs.ext4 -q -F -L KERNAID_OBSERVE -d "$observe_seed" "$observe_image" \
  >/dev/null 2>&1 || fail observe format-failed
truncate -s 64M -- "$swap_image" >/dev/null 2>&1 \
  || fail swap allocate-failed
mkswap -L KERNAID_SWAP_DECOY -- "$swap_image" >/dev/null 2>&1 \
  || fail swap format-failed
chmod 600 -- "$rescue_media" "$observe_image" "$swap_image" >/dev/null 2>&1 \
  || fail media mode-failed

random_suffix="$(od -An -N8 -tx1 /dev/urandom | tr -d '[:space:]')" \
  || fail provisioning suffix-failed
[[ "$random_suffix" =~ ^[0-9a-f]{16}$ ]] \
  || fail provisioning suffix-invalid
provision_mapper="kernaid-provision-$random_suffix"
manager_mapper="kernaid-vault-$random_suffix"

vault_loop="$(
  losetup --find --show --offset "$p3_start_bytes" \
    --sizelimit "$p3_bytes" -- "$rescue_media" 2>/dev/null
)" || fail provisioning loop-failed
[[ "$vault_loop" =~ ^/dev/loop[0-9]+$ && -b "$vault_loop" ]] \
  || fail provisioning loop-invalid
udevadm settle >/dev/null 2>&1 || fail provisioning udev-failed
observed_backing="$(
  losetup --noheadings --raw --output BACK-FILE -- "$vault_loop" 2>/dev/null
)" || fail provisioning loop-inspect-failed
observed_offset="$(
  losetup --noheadings --raw --output OFFSET -- "$vault_loop" 2>/dev/null \
    | tr -d '[:space:]'
)" || fail provisioning loop-inspect-failed
observed_limit="$(
  losetup --noheadings --raw --output SIZELIMIT -- "$vault_loop" 2>/dev/null \
    | tr -d '[:space:]'
)" || fail provisioning loop-inspect-failed
[[ "$(readlink -f -- "$observed_backing")" == "$(readlink -f -- "$rescue_media")" \
  && "$observed_offset" == "$p3_start_bytes" \
  && "$observed_limit" == "$p3_bytes" ]] \
  || fail provisioning loop-scope-invalid

cryptsetup luksFormat --type luks2 --batch-mode --label KERNAID_VAULT \
  --cipher aes-xts-plain64 --key-size 512 --hash sha256 --sector-size 512 \
  --pbkdf argon2id --pbkdf-force-iterations 4 --pbkdf-memory 65536 \
  --pbkdf-parallel 1 --key-slot 0 --keyslot-cipher aes-xts-plain64 \
  --keyslot-key-size 512 --luks2-metadata-size 16384 \
  --luks2-keyslots-size 16744448 --use-urandom \
  --key-file - --keyfile-size 64 "$vault_loop" <"$correct_key" \
  >/dev/null 2>&1 || fail provisioning luks-format-failed
cryptsetup open --type luks2 --batch-mode --tries 1 \
  --disable-external-tokens --key-file - --keyfile-size 64 \
  "$vault_loop" "$provision_mapper" <"$correct_key" \
  >/dev/null 2>&1 || fail provisioning luks-open-failed
provision_open=1
udevadm settle >/dev/null 2>&1 || fail provisioning udev-failed
mkfs.ext4 -q -F -t ext4 -b 4096 -I 256 -i 16384 -g 32768 -G 16 \
  -m 0 -o linux -e remount-ro -J size=128 \
  -E lazy_itable_init=0,lazy_journal_init=0 \
  -O none,has_journal,ext_attr,resize_inode,dir_index,filetype,extent,64bit,flex_bg,sparse_super,large_file,huge_file,dir_nlink,extra_isize,metadata_csum \
  -L KERNAID_VAULT -M / "/dev/mapper/$provision_mapper" \
  >/dev/null 2>&1 || fail provisioning ext4-format-failed
tune2fs -c 0 -i 0 -e remount-ro -m 0 -o '^acl,^user_xattr' -M / \
  "/dev/mapper/$provision_mapper" >/dev/null 2>&1 \
  || fail provisioning ext4-profile-failed
mount -t ext4 -o rw,nosuid,nodev,noexec,nosymfollow \
  "/dev/mapper/$provision_mapper" "$provision_mount" >/dev/null 2>&1 \
  || fail provisioning mount-failed
provision_mounted=1
chmod 700 -- "$provision_mount" >/dev/null 2>&1 \
  || fail provisioning mount-mode-failed
printf 'KERNAID-RESCUE-VAULT-V1\n' >"$provision_mount/.kernaid-rescue-vault"
chmod 600 -- "$provision_mount/.kernaid-rescue-vault" >/dev/null 2>&1 \
  || fail provisioning marker-mode-failed
mkdir -- "$provision_mount/.kernaid-secure-state-v1" >/dev/null 2>&1 \
  || fail provisioning state-directory-failed
chmod 700 -- "$provision_mount/.kernaid-secure-state-v1" >/dev/null 2>&1 \
  || fail provisioning state-mode-failed
: >"$provision_mount/.kernaid-rescue-secrets.lock"
chmod 600 -- "$provision_mount/.kernaid-rescue-secrets.lock" >/dev/null 2>&1 \
  || fail provisioning lock-mode-failed
[[ "$(stat -c '%a:%u:%g' -- "$provision_mount/.kernaid-rescue-vault")" == 600:0:0 \
  && "$(stat -c '%a:%u:%g' -- "$provision_mount/.kernaid-rescue-secrets.lock")" == 600:0:0 \
  && "$(stat -c '%a:%u:%g' -- "$provision_mount/.kernaid-secure-state-v1")" == 700:0:0 ]] \
  || fail provisioning layout-metadata-invalid
sync -f "$provision_mount" >/dev/null 2>&1 || fail provisioning sync-failed
umount -- "$provision_mount" >/dev/null 2>&1 \
  || fail provisioning unmount-failed
provision_mounted=0
cryptsetup close "$provision_mapper" >/dev/null 2>&1 \
  || fail provisioning close-failed
provision_open=0

probe_line=""
run_host_probe provisioning initialize
initial_identity_public_key="${probe_line#* identity_public_key=}"
initial_identity_public_key="${initial_identity_public_key%% *}"
[[ "$initial_identity_public_key" =~ ^[0-9a-f]{64}$ ]] \
  || fail provisioning initialize-identity-invalid
if mapper_active "$manager_mapper" \
  || mountpoint -q "/run/kernaid/vault/$manager_mapper" >/dev/null 2>&1; then
  fail provisioning initialize-residue
fi

cryptsetup isLuks --type luks2 "$vault_loop" >/dev/null 2>&1 \
  || fail provisioning luks-profile-invalid
[[ "$(blkid --probe --cache-file /dev/null --no-encoding --output value --match-tag TYPE "$vault_loop" 2>/dev/null)" == crypto_LUKS \
  && "$(blkid --probe --cache-file /dev/null --no-encoding --output value --match-tag VERSION "$vault_loop" 2>/dev/null)" == 2 \
  && "$(blkid --probe --cache-file /dev/null --no-encoding --output value --match-tag LABEL "$vault_loop" 2>/dev/null)" == KERNAID_VAULT ]] \
  || fail provisioning luks-profile-invalid

losetup -d -- "$vault_loop" >/dev/null 2>&1 \
  || fail provisioning loop-detach-failed
vault_loop=""
udevadm settle >/dev/null 2>&1 || fail provisioning udev-failed
[[ -z "$(losetup -j "$rescue_media" 2>/dev/null)" ]] \
  || fail provisioning loop-residue

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
  [[ "$1" =~ ^[0-9a-f]{64}$ ]] || fail digest invalid
}

iso_sha256="$(sha256_file "$iso")" || fail digest iso-failed
prefix_before_sha256="$(sha256_region "$rescue_media" 0 "$iso_bytes")" \
  || fail digest prefix-failed
p3_before_sha256="$(sha256_region "$rescue_media" "$p3_start_bytes" "$p3_bytes")" \
  || fail digest p3-failed
observe_before_sha256="$(sha256_file "$observe_image")" \
  || fail digest observe-failed
swap_before_sha256="$(sha256_file "$swap_image")" \
  || fail digest swap-failed
for digest in "$iso_sha256" "$prefix_before_sha256" "$p3_before_sha256" \
  "$observe_before_sha256" "$swap_before_sha256"; do
  require_sha256 "$digest"
done
[[ "$prefix_before_sha256" == "$iso_sha256" ]] \
  || fail digest prefix-mismatch

ovmf_code=""
ovmf_vars_template=""
if [[ "$firmware" == uefi ]]; then
  for pair in \
    /usr/share/OVMF/OVMF_CODE_4M.fd:/usr/share/OVMF/OVMF_VARS_4M.fd \
    /usr/share/OVMF/OVMF_CODE.fd:/usr/share/OVMF/OVMF_VARS.fd; do
    candidate_code="${pair%%:*}"
    candidate_vars="${pair#*:}"
    if [[ -f "$candidate_code" && ! -L "$candidate_code" \
      && -f "$candidate_vars" && ! -L "$candidate_vars" ]]; then
      ovmf_code="$candidate_code"
      ovmf_vars_template="$candidate_vars"
      break
    fi
  done
  [[ -n "$ovmf_code" && -n "$ovmf_vars_template" ]] \
    || fail firmware ovmf-missing
fi

device_id=""
for ((boot = 1; boot <= boot_count; boot++)); do
  qmp_socket="$work_dir/qmp-$firmware-$boot.sock"
  boot_output="$work_dir/boot-$boot.out"
  boot_error="$work_dir/boot-$boot.err"
  qemu_pgid_file="$work_dir/qemu-$firmware-$boot.pgid"
  # QEMU drive/device values are intentionally comma-delimited single items.
  # shellcheck disable=SC2054
  qemu_args=(
    -machine accel=tcg
    -m 2048
    -smp 2
    -device qemu-xhci,id=kernaid_xhci
    -drive "if=none,id=kernaid_rescue_usb,file=$rescue_media,format=raw,cache=none,aio=threads"
    -device "usb-storage,bus=kernaid_xhci.0,drive=kernaid_rescue_usb,bootindex=1"
    -drive "file=$observe_image,if=virtio,format=raw,cache=none,aio=threads"
    -drive "file=$swap_image,if=virtio,format=raw,cache=none,aio=threads"
  )
  if [[ "$firmware" == uefi ]]; then
    ovmf_vars_copy="$work_dir/OVMF_VARS.boot-$boot.fd"
    [[ ! -e "$ovmf_vars_copy" && ! -L "$ovmf_vars_copy" ]] \
      || fail firmware vars-reuse
    cp --reflink=auto --sparse=always -- "$ovmf_vars_template" "$ovmf_vars_copy" \
      >/dev/null 2>&1 || fail firmware vars-copy-failed
    chmod 600 -- "$ovmf_vars_copy" >/dev/null 2>&1 \
      || fail firmware vars-mode-failed
    qemu_args+=(
      -drive "if=pflash,format=raw,readonly=on,file=$ovmf_code"
      -drive "if=pflash,format=raw,file=$ovmf_vars_copy"
    )
  fi

  prepare_owned_group_file "$qemu_pgid_file" "$qemu_binary" \
    || fail controller pgid-file
  python3 -I -B "$controller" \
    --firmware "$firmware" --boot "$boot" \
    --correct-key-fd 3 --wrong-key-fd 4 \
    --login-credential-fd 5 --owned-pgid-fd 6 --qmp-socket "$qmp_socket" \
    --timeout 1200 --qemu "$qemu_binary" -- \
    "${qemu_args[@]}" 3<"$correct_key" 4<"$wrong_key" \
    5<"$login_credential" 6>"$qemu_pgid_file" \
    >"$boot_output" 2>"$boot_error" &
  controller_pid=$!
  if await_owned_group_publication; then
    publication_status=0
  else
    publication_status=$?
  fi
  if [[ "$publication_status" == 1 ]]; then
    stop_active_controller TERM || true
    clear_owned_group_tracking || true
    fail controller pgid-invalid
  fi
  controller_deadline=$((SECONDS + 1230))
  controller_timed_out=0
  while kill -0 "$controller_pid" 2>/dev/null; do
    if ((SECONDS >= controller_deadline)); then
      controller_timed_out=1
      stop_active_controller TERM || true
      break
    fi
    sleep 0.1 || true
  done
  if [[ "$controller_timed_out" == 0 ]]; then
    set +e
    wait "$controller_pid"
    controller_status=$?
    set -e
    controller_pid=""
  else
    controller_status=124
  fi
  qemu_residue=0
  if owned_group_exists; then
    terminate_owned_group || qemu_residue=1
    qemu_residue=1
  fi
  clear_owned_group_tracking || qemu_residue=1
  [[ "$qemu_residue" == 0 ]] || fail cleanup qemu-residue
  if [[ "$wrapper_interrupted" -ne 0 ]]; then
    exit "$wrapper_interrupted"
  fi
  [[ "$controller_timed_out" == 0 ]] || fail controller timeout
  if [[ "$controller_status" -ne 0 ]]; then
    if [[ "$(stat -c '%s' -- "$boot_error" 2>/dev/null)" =~ ^[0-9]+$ \
      && "$(stat -c '%s' -- "$boot_error" 2>/dev/null)" -le 256 ]]; then
      mapfile -t controller_errors <"$boot_error"
      if [[ "${#controller_errors[@]}" == 1 \
        && "${controller_errors[0]}" =~ ^${failure_prefix}\ stage=[a-z0-9-]+\ code=[a-z0-9-]+$ ]]; then
        printf '%s\n' "${controller_errors[0]}" >&8
        failure_emitted=1
        exit 1
      fi
    fi
    fail controller invalid-failure
  fi
  [[ ! -s "$boot_error" ]] || fail controller unexpected-stderr
  [[ "$(stat -c '%s' -- "$boot_output")" =~ ^[0-9]+$ \
    && "$(stat -c '%s' -- "$boot_output")" -le 768 ]] \
    || fail controller output-invalid
  mapfile -t boot_lines <"$boot_output"
  [[ "${#boot_lines[@]}" == 1 ]] || fail controller output-invalid
  boot_line="${boot_lines[0]}"
  if [[ ! "$boot_line" =~ ^${boot_prefix}\ firmware=${firmware}\ boot=${boot}\ initial_version=([0-9]+)\ final_version=([0-9]+)\ device_id=(KA-[0-9a-f]{24})\ wrong_key_rejected=true\ rate_limit_waited=true\ daemon_stable=true\ worker_stable=true\ cgroup_stable=true\ caps_stable=true\ ambient_zero=true\ no_new_privs=true\ core_limits_zero=true\ swaps_empty=true\ cgroup_topology_exact=true\ shell_mount_absent=true\ residue_absent=true\ acpi_shutdown=true$ ]]; then
    fail controller output-invalid
  fi
  boot_device_id="${BASH_REMATCH[3]}"
  if [[ -z "$device_id" ]]; then
    device_id="$boot_device_id"
  elif [[ "$device_id" != "$boot_device_id" ]]; then
    fail lifecycle device-id-changed
  fi
  if grep -Fq -f "$correct_key" "$boot_output" "$boot_error" \
    || grep -Fq -f "$wrong_key" "$boot_output" "$boot_error"; then
    fail controller secret-exposure
  fi
  printf '%s\n' "$boot_line"

  prefix_now="$(sha256_region "$rescue_media" 0 "$iso_bytes")" \
    || fail digest prefix-failed
  observe_now="$(sha256_file "$observe_image")" \
    || fail digest observe-failed
  swap_now="$(sha256_file "$swap_image")" \
    || fail digest swap-failed
  for digest in "$prefix_now" "$observe_now" "$swap_now"; do
    require_sha256 "$digest"
  done
  [[ "$prefix_now" == "$prefix_before_sha256" \
    && "$observe_now" == "$observe_before_sha256" \
    && "$swap_now" == "$swap_before_sha256" ]] \
    || fail lifecycle immutable-object-changed
done

prefix_after_sha256="$prefix_now"
observe_after_sha256="$observe_now"
swap_after_sha256="$swap_now"
p3_guest_after_sha256="$(sha256_region "$rescue_media" "$p3_start_bytes" "$p3_bytes")" \
  || fail digest p3-failed
for digest in "$prefix_after_sha256" "$observe_after_sha256" \
  "$swap_after_sha256" "$p3_guest_after_sha256"; do
  require_sha256 "$digest"
done
[[ "$prefix_after_sha256" == "$iso_sha256" \
  && "$observe_after_sha256" == "$observe_before_sha256" \
  && "$swap_after_sha256" == "$swap_before_sha256" ]] \
  || fail lifecycle immutable-object-changed

# Reattach the exact disposable p3 window after both guest boots and run the
# production host verifier. The verifier is allowed to write filesystem
# shutdown metadata, so its post-verify digest is distinct from the guest
# window digest and deliberately has no equality assertion.
vault_loop="$(
  losetup --find --show --offset "$p3_start_bytes" \
    --sizelimit "$p3_bytes" -- "$rescue_media" 2>/dev/null
)" || fail postverify loop-failed
[[ "$vault_loop" =~ ^/dev/loop[0-9]+$ && -b "$vault_loop" ]] \
  || fail postverify loop-invalid
udevadm settle >/dev/null 2>&1 || fail postverify udev-failed
observed_backing="$(
  losetup --noheadings --raw --output BACK-FILE -- "$vault_loop" 2>/dev/null
)" || fail postverify loop-inspect-failed
observed_offset="$(
  losetup --noheadings --raw --output OFFSET -- "$vault_loop" 2>/dev/null \
    | tr -d '[:space:]'
)" || fail postverify loop-inspect-failed
observed_limit="$(
  losetup --noheadings --raw --output SIZELIMIT -- "$vault_loop" 2>/dev/null \
    | tr -d '[:space:]'
)" || fail postverify loop-inspect-failed
observed_read_only="$(
  losetup --noheadings --raw --output RO -- "$vault_loop" 2>/dev/null \
    | tr -d '[:space:]'
)" || fail postverify loop-inspect-failed
[[ "$(readlink -f -- "$observed_backing")" == "$(readlink -f -- "$rescue_media")" \
  && "$observed_offset" == "$p3_start_bytes" \
  && "$observed_limit" == "$p3_bytes" && "$observed_read_only" == 0 ]] \
  || fail postverify loop-scope-invalid

probe_line=""
run_host_probe postverify verify
final_identity_public_key="${probe_line#* identity_public_key=}"
final_identity_public_key="${final_identity_public_key%% *}"
[[ "$final_identity_public_key" =~ ^[0-9a-f]{64}$ \
  && "$final_identity_public_key" == "$initial_identity_public_key" ]] \
  || fail postverify identity-changed

device_id_from_public_key() {
  python3 -I -B -c \
    'import hashlib,re,sys; value=sys.stdin.buffer.read(65); sys.exit(2) if re.fullmatch(b"[0-9a-f]{64}",value) is None else print("KA-"+hashlib.sha256(bytes.fromhex(value.decode("ascii"))).hexdigest()[:24])'
}
initial_derived_device_id="$(
  printf '%s' "$initial_identity_public_key" | device_id_from_public_key
)" || fail postverify device-id-derive-failed
final_derived_device_id="$(
  printf '%s' "$final_identity_public_key" | device_id_from_public_key
)" || fail postverify device-id-derive-failed
[[ "$initial_derived_device_id" =~ ^KA-[0-9a-f]{24}$ \
  && "$initial_derived_device_id" == "$final_derived_device_id" \
  && "$initial_derived_device_id" == "$device_id" ]] \
  || fail postverify device-id-mismatch

cryptsetup isLuks --type luks2 "$vault_loop" >/dev/null 2>&1 \
  || fail postverify luks-profile-invalid
[[ "$(blkid --probe --cache-file /dev/null --no-encoding --output value --match-tag TYPE "$vault_loop" 2>/dev/null)" == crypto_LUKS \
  && "$(blkid --probe --cache-file /dev/null --no-encoding --output value --match-tag VERSION "$vault_loop" 2>/dev/null)" == 2 \
  && "$(blkid --probe --cache-file /dev/null --no-encoding --output value --match-tag LABEL "$vault_loop" 2>/dev/null)" == KERNAID_VAULT ]] \
  || fail postverify luks-profile-invalid
if mapper_active "$manager_mapper" \
  || mountpoint -q "/run/kernaid/vault/$manager_mapper" >/dev/null 2>&1; then
  fail postverify residue
fi
losetup -d -- "$vault_loop" >/dev/null 2>&1 \
  || fail postverify loop-detach-failed
vault_loop=""
udevadm settle >/dev/null 2>&1 || fail postverify udev-failed
[[ -z "$(losetup -j "$rescue_media" 2>/dev/null)" ]] \
  || fail postverify loop-residue
p3_post_verify_sha256="$(sha256_region "$rescue_media" "$p3_start_bytes" "$p3_bytes")" \
  || fail digest p3-failed
require_sha256 "$p3_post_verify_sha256"

printf '%s\n' \
  "$raw_prefix firmware=$firmware media_bytes=$media_bytes iso_bytes=$iso_bytes prefix_before_sha256=$prefix_before_sha256 prefix_after_sha256=$prefix_after_sha256 observe_before_sha256=$observe_before_sha256 observe_after_sha256=$observe_after_sha256 swap_before_sha256=$swap_before_sha256 swap_after_sha256=$swap_after_sha256 p3_before_sha256=$p3_before_sha256 p3_guest_after_sha256=$p3_guest_after_sha256 p3_post_verify_sha256=$p3_post_verify_sha256 prefix_immutable=true observe_immutable=true swap_immutable=true p3_expected_rw=true"
printf '%s\n' \
  "$attestation_prefix firmware=$firmware boot_count=$boot_count same_usb=true device_id=$device_id device_id_stable=true identity_public_key_stable=true guest_device_id_derived=true host_postverify=true clean_shutdown=true luks_profile_valid=true versions_exact_plus_two=true wrong_key_rejected=true rate_limit_waited=true locked_after_each_boot=true daemon_processes_stable=true cgroups_exact=true capabilities_exact=true ambient_zero=true no_new_privs=true core_limits_zero=true swaps_empty=true shell_mount_absent=true residue_absent=true qmp_acpi_shutdowns=2 uefi_vars=$([[ "$firmware" == uefi ]] && printf fresh-per-boot || printf not-applicable) ready=true"
