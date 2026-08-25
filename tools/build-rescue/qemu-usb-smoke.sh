#!/usr/bin/env bash
set -euo pipefail

umask 077

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
firmware="${1:-bios}"
iso="${2:-$repo_dir/KernAid-Rescue-amd64.iso}"
probe_binary="${3:-$repo_dir/target/release/kernaid-rescue-vault-probe}"
layout_manifest="$repo_dir/rescue/image-layout/device-layout.v1.json"
vault_profile_manifest="$repo_dir/rescue/image-layout/vault-profile.v1.json"
vault_profile_verifier="$repo_dir/tools/build-rescue/verify-vault-profile.py"
readonly vault_profile_sha256=b4801359bd4f31ce67fbd3ec15b6c81c44aa6759ba43b2a4e099a7dfcc25a37c

# These values are the immutable layout-v1 geometry validated by
# finalize-device-layout.py. Provisioning is confined to the p3 slice of one
# newly created disposable raw medium and is never copied into the Rescue ISO.
readonly media_bytes=32000000000
readonly p3_start_bytes=17179869184
readonly p3_bytes=8589934592
readonly boot_count=2
readonly boot_timeout_seconds=1200
readonly qemu_identity_capture_seconds=5
readonly qemu_term_grace_seconds=5
readonly qemu_kill_grace_seconds=5
readonly qemu_stop_poll_seconds=0.05
readonly probe_prefix=KERNAID_RESCUE_VAULT_PROBE_ATTESTATION_V1
readonly probe_failure_prefix=KERNAID_RESCUE_VAULT_PROBE_FAILURE_V1
readonly journal_binding_value=device-identity-bound-v1

for command in awk blkid cat chmod chown cp cryptsetup dd dirname findmnt grep id \
  kill losetup mkdir mkfs.ext4 mktemp mount mountpoint od python3 \
  qemu-system-x86_64 readlink rm rmdir sha256sum sleep stat sync tail tee tr \
  truncate tune2fs udevadm umount; do
  command -v "$command" >/dev/null || {
    echo "Missing required command: $command" >&2
    exit 2
  }
done
[[ -x /usr/bin/python3 ]] || {
  echo "Missing fixed pidfd helper interpreter: /usr/bin/python3" >&2
  exit 2
}

if [[ "$firmware" != "bios" && "$firmware" != "uefi" ]]; then
  echo "Usage: $0 [bios|uefi] [iso] [vault-probe]" >&2
  exit 2
fi
if [[ "$(id -u)" != "0" ]]; then
  echo "The disposable USB vault smoke test must run as root" >&2
  exit 2
fi
if [[ "$(findmnt -n -o FSTYPE --target /dev/shm)" != "tmpfs" ]]; then
  echo "Refusing to place disposable vault keys outside tmpfs" >&2
  exit 2
fi
[[ -f "$iso" ]] || { echo "ISO not found: $iso" >&2; exit 2; }
[[ -f "$layout_manifest" ]] || {
  echo "Layout manifest not found: $layout_manifest" >&2
  exit 2
}
[[ -f "$vault_profile_manifest" && -f "$vault_profile_verifier" ]] || {
  echo "Vault profile manifest or exact verifier is missing" >&2
  exit 2
}
if [[ "$probe_binary" != /* ]]; then
  probe_binary="$PWD/$probe_binary"
fi
if [[ ! -f "$probe_binary" || ! -x "$probe_binary" || -L "$probe_binary" ]]; then
  echo "Vault probe must be an executable regular non-symlink file" >&2
  exit 2
fi

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

sha256_text() {
  printf '%s' "$1" | sha256sum | awk 'NR == 1 { print $1 }'
}

require_sha256() {
  local label="$1"
  local value="$2"
  if [[ ! "$value" =~ ^[0-9a-f]{64}$ ]]; then
    echo "$label is not a lowercase SHA-256 digest" >&2
    exit 2
  fi
}

require_uuid() {
  local label="$1"
  local value="$2"
  if [[ ! "$value" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
    echo "$label is not a canonical lowercase UUID" >&2
    exit 1
  fi
}

iso_sha256="$(sha256_file "$iso")"
layout_manifest_sha256="$(sha256_file "$layout_manifest")"
probe_sha256="$(sha256_file "$probe_binary")"
require_sha256 "ISO digest" "$iso_sha256"
require_sha256 "layout manifest digest" "$layout_manifest_sha256"
require_sha256 "vault probe digest" "$probe_sha256"

random_suffix="$(od -An -N8 -tx1 /dev/urandom | tr -d '[:space:]')"
if [[ ! "$random_suffix" =~ ^[0-9a-f]{16}$ ]]; then
  echo "Failed to generate a safe disposable mapper suffix" >&2
  exit 1
fi
manager_mapper="kernaid-vault-$random_suffix"
provision_mapper="kernaid-provision-$random_suffix"
inspection_mapper="kernaid-inspect-$random_suffix"
manager_mount="/run/kernaid/vault/$manager_mapper"

log="${KERNAID_USB_SMOKE_LOG:-}"
temporary_log=0
work_dir=""
key_dir=""

# Cover failures while the two temporary directories are being allocated;
# the full resource-aware trap replaces this one before any block operation.
# shellcheck disable=SC2329  # Invoked indirectly by the EXIT trap below.
# shellcheck disable=SC2317
early_cleanup() {
  local result="$1"
  trap - EXIT
  set +e
  if [[ -n "$key_dir" ]]; then
    case "$key_dir" in
      /dev/shm/kernaid-qemu-usb-vault-key.*) rmdir -- "$key_dir" ;;
      *) echo "Refusing to remove an unexpected early key directory" >&2 ;;
    esac
  fi
  if [[ -n "$work_dir" ]]; then
    case "$work_dir" in
      /tmp/kernaid-qemu-usb-vault.*) rmdir -- "$work_dir" ;;
      *) echo "Refusing to remove an unexpected early work directory" >&2 ;;
    esac
  fi
  if [[ "$temporary_log" == "1" && -n "$log" ]]; then
    rm -f -- "$log"
  fi
  exit "$result"
}
trap 'early_cleanup $?' EXIT

if [[ -z "$log" ]]; then
  log="$(mktemp /tmp/kernaid-qemu-usb-vault-log.XXXXXXXX)"
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

work_dir="$(mktemp -d /tmp/kernaid-qemu-usb-vault.XXXXXXXX)"
key_dir="$(mktemp -d /dev/shm/kernaid-qemu-usb-vault-key.XXXXXXXX)"
rescue_media="$work_dir/KernAid-Rescue-usb.raw"
target_image="$work_dir/disposable-target.raw"
target_seed_dir="$work_dir/target-seed"
provision_mount="$work_dir/provision"
key_file="$key_dir/key"
wrong_key_file="$key_dir/wrong-key"

qemu_pid=""
qemu_process_identity=""
qemu_start_fd=""
qemu_last_status=""
qemu_cleanup_safe=true
vault_loop=""
provision_open=false
provision_mounted=false
inspection_open=false
profile_luks_checks=0
profile_ext4_checks=0
last_prefix_sha256=""
last_p3_sha256=""
last_target_sha256=""
clean_shutdowns=0

mapper_is_active() {
  cryptsetup status "$1" >/dev/null 2>&1
}

read_qemu_process_state_and_identity() {
  local pid="$1"
  local process_stat process_tail
  local -a process_fields
  [[ -r "/proc/$pid/stat" ]] || return 1
  IFS= read -r process_stat <"/proc/$pid/stat" || return 1
  [[ "$process_stat" == *") "* ]] || return 1
  process_tail="${process_stat##*) }"
  read -r -a process_fields <<<"$process_tail"
  [[ "${#process_fields[@]}" -ge 20 ]] || return 1
  printf '%s:%s\n' "${process_fields[0]}" "${process_fields[19]}"
}

capture_qemu_process_identity_bounded() {
  local deadline observation state identity
  deadline=$((SECONDS + qemu_identity_capture_seconds))
  while ((SECONDS < deadline)); do
    if observation="$(read_qemu_process_state_and_identity "$qemu_pid")"; then
      state="${observation%%:*}"
      identity="${observation#*:}"
      if [[ "$identity" =~ ^[0-9]+$ ]]; then
        case "$state" in
          Z|X) return 1 ;;
          *)
            qemu_process_identity="$identity"
            return 0
            ;;
        esac
      fi
    elif [[ ! -e "/proc/$qemu_pid" ]]; then
      return 1
    fi
    sleep "$qemu_stop_poll_seconds" || true
  done
  return 1
}

close_qemu_start_gate() {
  if [[ -z "$qemu_start_fd" ]]; then
    return 0
  fi
  if [[ ! "$qemu_start_fd" =~ ^[0-9]+$ ]]; then
    echo "QEMU start-gate descriptor is invalid" >&2
    return 1
  fi
  exec {qemu_start_fd}>&-
  qemu_start_fd=""
}

# shellcheck disable=SC2317,SC2329  # Invoked indirectly by the EXIT cleanup trap.
recover_qemu_start_gate_tracking() {
  local spawned_fd="${QEMU_PROCESS[1]:-}"
  local spawned_pid="${QEMU_PROCESS_PID:-}"
  [[ -z "$qemu_process_identity" && -n "$spawned_pid" ]] || return 0
  if [[ ! "$spawned_pid" =~ ^[1-9][0-9]*$ \
    || ! "$spawned_fd" =~ ^[0-9]+$ \
    || ( -n "$qemu_pid" && "$qemu_pid" != "$spawned_pid" ) \
    || ( -n "$qemu_start_fd" && "$qemu_start_fd" != "$spawned_fd" ) ]]; then
    echo "QEMU start-gate launch tracking is inconsistent" >&2
    return 1
  fi
  qemu_pid="$spawned_pid"
  qemu_start_fd="$spawned_fd"
}

release_qemu_start_gate() {
  local process_status
  process_status="$(qemu_process_status)"
  if [[ "$process_status" != "live" ]]; then
    echo "QEMU start-gate process state is untrusted: $process_status" >&2
    return 1
  fi
  if [[ ! "$qemu_start_fd" =~ ^[0-9]+$ ]] \
    || ! printf '%s\n' KERNAID_QEMU_START_V1 >&"$qemu_start_fd"; then
    close_qemu_start_gate || true
    return 1
  fi
  close_qemu_start_gate
}

qemu_process_status() {
  local observation state identity
  if ! observation="$(read_qemu_process_state_and_identity "$qemu_pid")"; then
    if [[ -e "/proc/$qemu_pid" ]]; then
      printf 'unknown\n'
    else
      printf 'gone\n'
    fi
    return 0
  fi
  state="${observation%%:*}"
  identity="${observation#*:}"
  if [[ "$identity" != "$qemu_process_identity" ]]; then
    printf 'identity-mismatch\n'
  elif [[ "$state" == "Z" || "$state" == "X" ]]; then
    printf 'reapable\n'
  else
    printf 'live\n'
  fi
}

reap_stopped_qemu() {
  local process_status
  process_status="$(qemu_process_status)"
  case "$process_status" in
    gone|reapable)
      if wait "$qemu_pid" 2>/dev/null; then
        qemu_last_status=0
      else
        qemu_last_status=$?
      fi
      qemu_pid=""
      qemu_process_identity=""
      return 0
      ;;
    *) return 1 ;;
  esac
}

reap_unidentified_qemu() {
  local observation state
  if observation="$(read_qemu_process_state_and_identity "$qemu_pid")"; then
    state="${observation%%:*}"
    [[ "$state" == "Z" || "$state" == "X" ]] || return 1
  elif [[ -e "/proc/$qemu_pid" ]]; then
    return 1
  fi
  if wait "$qemu_pid" 2>/dev/null; then
    qemu_last_status=0
  else
    qemu_last_status=$?
  fi
  qemu_pid=""
  qemu_process_identity=""
}

abort_unidentified_qemu_bounded() {
  local deadline
  close_qemu_start_gate || return 1
  deadline=$((SECONDS + qemu_identity_capture_seconds))
  while ((SECONDS < deadline)); do
    if reap_unidentified_qemu; then
      return 0
    fi
    sleep "$qemu_stop_poll_seconds" || true
  done
  reap_unidentified_qemu
}

signal_qemu_identity_bound() {
  local signal_name="$1"
  /usr/bin/python3 -I - "$qemu_pid" "$qemu_process_identity" "$signal_name" <<'PY'
import os
import signal
import sys

signals = {"CHECK": 0, "TERM": signal.SIGTERM, "KILL": signal.SIGKILL}
try:
    pid_text, expected_start, signal_name = sys.argv[1:]
    if (
        not pid_text.isascii()
        or not pid_text.isdecimal()
        or int(pid_text) <= 0
        or not expected_start.isascii()
        or not expected_start.isdecimal()
        or signal_name not in signals
    ):
        raise ValueError
    pid = int(pid_text)
except (TypeError, ValueError):
    raise SystemExit(4)

try:
    pidfd = os.pidfd_open(pid, 0)
except ProcessLookupError:
    raise SystemExit(3)
except (AttributeError, OSError):
    raise SystemExit(4)

try:
    try:
        with open(f"/proc/{pid}/stat", "rb", buffering=0) as process_stat:
            payload = process_stat.read(4096)
    except FileNotFoundError:
        raise SystemExit(3)
    except OSError:
        raise SystemExit(4)
    close_paren = payload.rfind(b") ")
    if close_paren < 0:
        raise SystemExit(4)
    fields = payload[close_paren + 2 :].split()
    if len(fields) < 20 or fields[19] != expected_start.encode("ascii"):
        raise SystemExit(4)
    try:
        signal.pidfd_send_signal(pidfd, signals[signal_name], None, 0)
    except ProcessLookupError:
        raise SystemExit(3)
    except (AttributeError, OSError):
        raise SystemExit(4)
finally:
    os.close(pidfd)
PY
}

terminate_qemu_bounded() {
  local deadline process_status signal_status
  if [[ -z "$qemu_pid" ]]; then
    return 0
  fi
  if [[ ! "$qemu_pid" =~ ^[1-9][0-9]*$ \
    || ! "$qemu_process_identity" =~ ^[0-9]+$ ]]; then
    echo "QEMU process identity is invalid during cleanup" >&2
    return 1
  fi
  if reap_stopped_qemu; then
    return 0
  fi
  process_status="$(qemu_process_status)"
  if [[ "$process_status" != "live" ]]; then
    echo "QEMU process state is untrusted during cleanup: $process_status" >&2
    return 1
  fi
  if signal_qemu_identity_bound TERM; then
    signal_status=0
  else
    signal_status=$?
  fi
  if [[ "$signal_status" -eq 3 ]] && reap_stopped_qemu; then
    return 0
  elif [[ "$signal_status" -ne 0 ]]; then
    echo "QEMU identity-bound TERM failed closed (status $signal_status)" >&2
    return 1
  fi
  deadline=$((SECONDS + qemu_term_grace_seconds))
  while ((SECONDS < deadline)); do
    if reap_stopped_qemu; then
      return 0
    fi
    [[ "$(qemu_process_status)" == "live" ]] || break
    sleep "$qemu_stop_poll_seconds" || true
  done
  if reap_stopped_qemu; then
    return 0
  fi
  process_status="$(qemu_process_status)"
  if [[ "$process_status" != "live" ]]; then
    echo "QEMU process state is untrusted after TERM: $process_status" >&2
    return 1
  fi
  if signal_qemu_identity_bound KILL; then
    signal_status=0
  else
    signal_status=$?
  fi
  if [[ "$signal_status" -eq 3 ]] && reap_stopped_qemu; then
    return 0
  elif [[ "$signal_status" -ne 0 ]]; then
    echo "QEMU identity-bound KILL failed closed (status $signal_status)" >&2
    return 1
  fi
  deadline=$((SECONDS + qemu_kill_grace_seconds))
  while ((SECONDS < deadline)); do
    if reap_stopped_qemu; then
      return 0
    fi
    [[ "$(qemu_process_status)" == "live" ]] || break
    sleep "$qemu_stop_poll_seconds" || true
  done
  if ! reap_stopped_qemu; then
    process_status="$(qemu_process_status)"
    echo "QEMU did not terminate within the bounded cleanup window" >&2
    echo "QEMU terminal process state: $process_status" >&2
    return 1
  fi
}

# shellcheck disable=SC2329  # Invoked indirectly by the EXIT trap below.
# shellcheck disable=SC2317
cleanup() {
  local result="$1"
  local cleanup_failed=false
  trap - EXIT
  set +e

  if ! recover_qemu_start_gate_tracking; then
    qemu_cleanup_safe=false
    cleanup_failed=true
  fi
  if [[ -n "$qemu_pid" && -z "$qemu_process_identity" ]]; then
    if ! abort_unidentified_qemu_bounded; then
      qemu_cleanup_safe=false
      cleanup_failed=true
    fi
  elif ! terminate_qemu_bounded; then
    qemu_cleanup_safe=false
    cleanup_failed=true
  fi
  if [[ "$qemu_cleanup_safe" == true ]]; then
    if mountpoint -q "$manager_mount" 2>/dev/null; then
      if ! umount "$manager_mount"; then
        echo "Failed to unmount the disposable managed vault" >&2
        cleanup_failed=true
      fi
    fi
    if mapper_is_active "$manager_mapper"; then
      if ! cryptsetup close "$manager_mapper"; then
        echo "Failed to close the disposable managed mapper" >&2
        cleanup_failed=true
      fi
    fi
    if [[ "$provision_mounted" == true ]] \
      || mountpoint -q "$provision_mount" 2>/dev/null; then
      if ! umount "$provision_mount"; then
        echo "Failed to unmount the disposable provisioning vault" >&2
        cleanup_failed=true
      fi
      provision_mounted=false
    fi
    if [[ "$provision_open" == true ]] || mapper_is_active "$provision_mapper"; then
      if ! cryptsetup close "$provision_mapper"; then
        echo "Failed to close the disposable provisioning mapper" >&2
        cleanup_failed=true
      fi
      provision_open=false
    fi
    if [[ "$inspection_open" == true ]] || mapper_is_active "$inspection_mapper"; then
      if ! cryptsetup close "$inspection_mapper"; then
        echo "Failed to close the disposable inspection mapper" >&2
        cleanup_failed=true
      fi
      inspection_open=false
    fi
    if [[ -n "$vault_loop" ]]; then
      if [[ "$vault_loop" =~ ^/dev/loop[0-9]+$ ]]; then
        udevadm settle
        if ! losetup -d "$vault_loop"; then
          echo "Failed to detach the disposable p3 loop" >&2
          cleanup_failed=true
        else
          vault_loop=""
        fi
      else
        echo "Refusing to detach an unexpected loop path" >&2
        cleanup_failed=true
      fi
    fi
  else
    echo "Preserving QEMU backing files because termination was not confirmed" >&2
  fi

  case "$key_dir" in
    /dev/shm/kernaid-qemu-usb-vault-key.*)
      rm -f -- "$key_file" "$wrong_key_file"
      rmdir -- "$key_dir" 2>/dev/null || cleanup_failed=true
      ;;
    *)
      echo "Refusing to remove an unexpected key directory" >&2
      cleanup_failed=true
      ;;
  esac
  case "$work_dir" in
    /tmp/kernaid-qemu-usb-vault.*)
      if [[ "$qemu_cleanup_safe" == true && "$cleanup_failed" == false ]]; then
        rm -rf -- "$work_dir"
      else
        echo "Preserving disposable media after cleanup failure: $work_dir" >&2
      fi
      ;;
    *)
      echo "Refusing to remove an unexpected temporary path" >&2
      cleanup_failed=true
      ;;
  esac
  if [[ "$temporary_log" == "1" ]]; then
    rm -f -- "$log"
  fi

  if [[ "$result" -eq 0 && "$cleanup_failed" == true ]]; then
    result=1
  fi
  exit "$result"
}
trap 'cleanup $?' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

allocate_vault_loop() {
  if [[ -n "$vault_loop" ]]; then
    echo "Refusing to allocate a second p3 loop" >&2
    exit 1
  fi
  vault_loop="$(
    losetup --find --show --offset "$p3_start_bytes" \
      --sizelimit "$p3_bytes" -- "$rescue_media"
  )"
  if [[ ! "$vault_loop" =~ ^/dev/loop[0-9]+$ || ! -b "$vault_loop" ]]; then
    echo "The disposable loop allocator returned an unexpected device" >&2
    exit 1
  fi
  udevadm settle

  local observed_backing
  local observed_offset
  local observed_limit
  observed_backing="$(
    losetup --noheadings --raw --output BACK-FILE -- "$vault_loop"
  )"
  observed_offset="$(
    losetup --noheadings --raw --output OFFSET -- "$vault_loop" \
      | tr -d '[:space:]'
  )"
  observed_limit="$(
    losetup --noheadings --raw --output SIZELIMIT -- "$vault_loop" \
      | tr -d '[:space:]'
  )"
  if [[ "$(readlink -f -- "$observed_backing")" != "$(readlink -f -- "$rescue_media")" ]] \
    || [[ "$observed_offset" != "$p3_start_bytes" ]] \
    || [[ "$observed_limit" != "$p3_bytes" ]]; then
    echo "The newly allocated loop does not bind the exact disposable p3 slice" >&2
    exit 1
  fi
}

detach_vault_loop() {
  if [[ ! "$vault_loop" =~ ^/dev/loop[0-9]+$ ]]; then
    echo "No validated disposable p3 loop is attached" >&2
    exit 1
  fi
  udevadm settle
  losetup -d "$vault_loop"
  vault_loop=""
  udevadm settle
  if [[ -n "$(losetup -j "$rescue_media")" ]]; then
    echo "A loop device still references the disposable Rescue medium" >&2
    exit 1
  fi
}

assert_vault_resources_clean() {
  local stage="$1"
  if mountpoint -q "$manager_mount" \
    || mountpoint -q "$provision_mount" \
    || mapper_is_active "$manager_mapper" \
    || mapper_is_active "$provision_mapper" \
    || mapper_is_active "$inspection_mapper"; then
    echo "$stage left a disposable vault mount or mapper active" >&2
    exit 1
  fi
}

parse_probe_attestation() {
  local expected_mode="$1"
  local output_file="$2"
  local line
  local output_bytes
  local -a lines

  output_bytes="$(stat -c '%s' -- "$output_file")"
  if [[ ! "$output_bytes" =~ ^[0-9]+$ ]] || ((output_bytes > 512)); then
    echo "The vault probe emitted oversized lifecycle evidence" >&2
    exit 1
  fi
  mapfile -t lines <"$output_file"
  if [[ "${#lines[@]}" -ne 1 ]]; then
    echo "The vault probe emitted an unexpected number of lines" >&2
    exit 1
  fi
  line="${lines[0]}"
  if [[ ! "$line" =~ ^${probe_prefix}\ mode=(initialize|verify)\ journal_binding=(${journal_binding_value})\ identity_public_key=([0-9a-f]{64})\ clean_shutdown=true$ ]]; then
    echo "The vault probe emitted malformed lifecycle evidence" >&2
    exit 1
  fi
  probe_mode="${BASH_REMATCH[1]}"
  probe_journal_binding="${BASH_REMATCH[2]}"
  probe_identity_public_key="${BASH_REMATCH[3]}"
  if [[ "$probe_mode" != "$expected_mode" ]]; then
    echo "The vault probe attested the wrong lifecycle mode" >&2
    exit 1
  fi
}

run_probe() {
  local mode="$1"
  local output_file="$2"
  local error_file="$3"
  if ! "$probe_binary" --device "$vault_loop" --mapper "$manager_mapper" \
    --mode "$mode" <"$key_file" >"$output_file" 2>"$error_file"; then
    local diagnostic
    local error_bytes
    local -a error_lines
    error_bytes="$(stat -c '%s' -- "$error_file")"
    error_lines=()
    if [[ "$error_bytes" =~ ^[0-9]+$ ]] && ((error_bytes <= 512)); then
      mapfile -t error_lines <"$error_file"
    fi
    if [[ "${#error_lines[@]}" -eq 1 \
      && "${error_lines[0]}" =~ ^${probe_failure_prefix}\ stage=[a-z0-9-]+\ code=[a-z0-9-]+$ ]]; then
      diagnostic="${error_lines[0]}"
    else
      # Never copy arbitrary stderr into a workflow log: it could contain an
      # OS path, command output, mapper identity, or passphrase material.
      diagnostic="$probe_failure_prefix stage=wrapper code=invalid-diagnostic"
    fi
    printf '%s\n' "$diagnostic" | tee -a "$log" >&2
    echo "The Rescue vault probe failed in $mode mode" >&2
    exit 1
  fi
  parse_probe_attestation "$mode" "$output_file"
  cat "$output_file" >>"$log"
  assert_vault_resources_clean "The $mode probe"
  ((clean_shutdowns += 1))
}

reject_wrong_key() {
  local output_file="$work_dir/probe-wrong-key.out"
  if "$probe_binary" --device "$vault_loop" --mapper "$manager_mapper" \
    --mode verify <"$wrong_key_file" >"$output_file" 2>&1; then
    echo "The Rescue manager accepted an incorrect vault key" >&2
    exit 1
  fi
  if grep -Fq "$probe_prefix" "$output_file"; then
    echo "The failed unlock emitted a successful probe attestation" >&2
    exit 1
  fi
  assert_vault_resources_clean "The wrong-key probe"
  printf '%s\n' \
    "KERNAID_RESCUE_VAULT_WRONG_KEY_V1 firmware=$firmware rejected=true residue=false" \
    >>"$log"
}

blkid_value() {
  local device="$1"
  local tag="$2"
  blkid --probe --cache-file /dev/null --no-encoding \
    --output value --match-tag "$tag" "$device"
}

verify_luks_profile() {
  local stage="$1"
  local stage_token="$2"
  local observed
  observed="$(
    cryptsetup luksDump --dump-json-metadata "$vault_loop" \
      | python3 -I -B "$vault_profile_verifier" \
          --profile "$vault_profile_manifest" luks-json
  )"
  if [[ "$observed" != "KERNAID_VAULT_PROFILE_CHECK_V1 kind=luks-json sha256=$vault_profile_sha256 verified=true" ]]; then
    echo "$stage did not pass the exact machine-readable LUKS2 profile gate" >&2
    exit 1
  fi
  ((profile_luks_checks += 1))
  printf '%s\n' \
    "KERNAID_QEMU_USB_VAULT_PROFILE_CHECK_V1 firmware=$firmware stage=$stage_token kind=luks2 vault_profile_version=1 vault_profile_sha256=$vault_profile_sha256 verified=true" \
    >>"$log"
}

verify_ext4_profile() {
  local stage="$1"
  local stage_token="$2"
  local filesystem_uuid="$3"
  local mapper_node
  local observed
  mapper_node="$(readlink -f -- "/dev/mapper/$inspection_mapper")"
  if [[ ! "$mapper_node" =~ ^/dev/dm-[0-9]+$ ]]; then
    echo "$stage mapper did not resolve to one direct device-mapper node" >&2
    exit 1
  fi
  observed="$(
    python3 -I -B "$vault_profile_verifier" \
      --profile "$vault_profile_manifest" ext4 \
      --device "$mapper_node" --mapper-name "$inspection_mapper" \
      --backing-device "$vault_loop" --uuid "$filesystem_uuid"
  )"
  if [[ "$observed" != "KERNAID_VAULT_PROFILE_CHECK_V1 kind=ext4 sha256=$vault_profile_sha256 verified=true" ]]; then
    echo "$stage did not pass the exact binary ext4 profile gate" >&2
    exit 1
  fi
  ((profile_ext4_checks += 1))
  printf '%s\n' \
    "KERNAID_QEMU_USB_VAULT_PROFILE_CHECK_V1 firmware=$firmware stage=$stage_token kind=ext4 vault_profile_version=1 vault_profile_sha256=$vault_profile_sha256 verified=true" \
    >>"$log"
}

inspect_vault_metadata() {
  local stage="$1"
  local stage_token
  case "$stage" in
    Post-initialize) stage_token=post-initialize ;;
    Post-boot\ verify) stage_token=post-boot-verify ;;
    *) echo "Unknown exact vault profile inspection stage" >&2; exit 1 ;;
  esac
  cryptsetup isLuks --type luks2 "$vault_loop"
  observed_luks_uuid="$(cryptsetup luksUUID --type luks2 "$vault_loop")"
  observed_luks_type="$(blkid_value "$vault_loop" TYPE)"
  observed_luks_version="$(blkid_value "$vault_loop" VERSION)"
  observed_luks_label="$(blkid_value "$vault_loop" LABEL)"
  require_uuid "$stage LUKS UUID" "$observed_luks_uuid"
  if [[ "$observed_luks_type" != "crypto_LUKS" \
    || "$observed_luks_version" != "2" \
    || "$observed_luks_label" != "KERNAID_VAULT" ]]; then
    echo "$stage did not observe the exact LUKS2 KERNAID_VAULT header" >&2
    exit 1
  fi
  verify_luks_profile "$stage" "$stage_token"

  cryptsetup open --type luks2 --readonly --batch-mode --tries 1 \
    --disable-external-tokens --key-file "$key_file" --keyfile-size 64 \
    "$vault_loop" "$inspection_mapper"
  inspection_open=true
  udevadm settle
  observed_filesystem="$(blkid_value "/dev/mapper/$inspection_mapper" TYPE)"
  observed_filesystem_label="$(blkid_value "/dev/mapper/$inspection_mapper" LABEL)"
  observed_filesystem_uuid="$(blkid_value "/dev/mapper/$inspection_mapper" UUID)"
  require_uuid "$stage filesystem UUID" "$observed_filesystem_uuid"
  if [[ "$observed_filesystem" != "ext4" \
    || "$observed_filesystem_label" != "KERNAID_VAULT" ]]; then
    echo "$stage did not observe the exact ext4 KERNAID_VAULT filesystem" >&2
    exit 1
  fi
  verify_ext4_profile "$stage" "$stage_token" "$observed_filesystem_uuid"
  cryptsetup close "$inspection_mapper"
  inspection_open=false
  assert_vault_resources_clean "$stage metadata inspection"
}

mkdir "$target_seed_dir" "$provision_mount"
printf '%s\n' KERNAID_OBSERVE_TARGET_SENTINEL >"$target_seed_dir/README.txt"
dd if=/dev/urandom of="$key_file" bs=64 count=1 status=none
dd if=/dev/urandom of="$wrong_key_file" bs=64 count=1 status=none
chmod 600 "$key_file" "$wrong_key_file"
if [[ "$(stat -c '%a:%u:%g' -- "$key_file")" != "600:0:0" \
  || "$(stat -c '%a:%u:%g' -- "$wrong_key_file")" != "600:0:0" ]]; then
  echo "Disposable vault keys are not root-owned mode 0600 files" >&2
  exit 1
fi
if [[ "$(sha256_file "$key_file")" == "$(sha256_file "$wrong_key_file")" ]]; then
  echo "Disposable correct and incorrect vault keys are unexpectedly identical" >&2
  exit 1
fi

truncate -s "$media_bytes" -- "$rescue_media"
# The ISO is copied only into the media prefix. conv=notrunc is essential:
# the sparse 32,000,000,000-byte medium and its p3 region remain present.
dd if="$iso" of="$rescue_media" bs=4M conv=notrunc status=none
actual_media_bytes="$(stat -c '%s' -- "$rescue_media")"
if [[ "$actual_media_bytes" != "$media_bytes" ]]; then
  echo "USB-style raw media has the wrong byte length" >&2
  exit 1
fi

truncate -s 128M -- "$target_image"
mkfs.ext4 -q -F -L KERNAID_TARGET -d "$target_seed_dir" "$target_image"

# Provisioning exists only in this root-owned disposable CI work directory.
# Neither this code, the passphrase, nor the probe is packaged in the ISO.
allocate_vault_loop
cryptsetup luksFormat --type luks2 --batch-mode --label KERNAID_VAULT \
  --cipher aes-xts-plain64 --key-size 512 --hash sha256 --sector-size 512 \
  --pbkdf argon2id --pbkdf-force-iterations 4 --pbkdf-memory 65536 \
  --pbkdf-parallel 1 --key-slot 0 --keyslot-cipher aes-xts-plain64 \
  --keyslot-key-size 512 --luks2-metadata-size 16384 \
  --luks2-keyslots-size 16744448 --use-urandom \
  --key-file "$key_file" --keyfile-size 64 "$vault_loop"
cryptsetup open --type luks2 --batch-mode --tries 1 \
  --disable-external-tokens --key-file "$key_file" --keyfile-size 64 \
  "$vault_loop" "$provision_mapper"
provision_open=true
udevadm settle
mkfs.ext4 -q -F -t ext4 -b 4096 -I 256 -i 16384 -g 32768 -G 16 \
  -m 0 -o linux -e remount-ro -J size=128 \
  -E lazy_itable_init=0,lazy_journal_init=0 \
  -O none,has_journal,ext_attr,resize_inode,dir_index,filetype,extent,64bit,flex_bg,sparse_super,large_file,huge_file,dir_nlink,extra_isize,metadata_csum \
  -L KERNAID_VAULT -M / "/dev/mapper/$provision_mapper"
tune2fs -c 0 -i 0 -e remount-ro -m 0 -o '^acl,^user_xattr' -M / \
  "/dev/mapper/$provision_mapper"
mount -t ext4 -o rw,nosuid,nodev,noexec,nosymfollow \
  "/dev/mapper/$provision_mapper" "$provision_mount"
provision_mounted=true
chmod 700 "$provision_mount"
printf 'KERNAID-RESCUE-VAULT-V1\n' >"$provision_mount/.kernaid-rescue-vault"
chmod 600 "$provision_mount/.kernaid-rescue-vault"
mkdir "$provision_mount/.kernaid-secure-state-v1"
chmod 700 "$provision_mount/.kernaid-secure-state-v1"
: >"$provision_mount/.kernaid-rescue-secrets.lock"
chmod 600 "$provision_mount/.kernaid-rescue-secrets.lock"
mkdir "$provision_mount/.kernaid-codex-home-v1"
chmod 700 "$provision_mount/.kernaid-codex-home-v1"
chown 973:973 "$provision_mount/.kernaid-codex-home-v1"
printf 'cli_auth_credentials_store = "file"\n' \
  >"$provision_mount/.kernaid-codex-home-v1/config.toml"
chmod 600 "$provision_mount/.kernaid-codex-home-v1/config.toml"
chown 973:973 "$provision_mount/.kernaid-codex-home-v1/config.toml"
if [[ "$(stat -c '%a:%u:%g' -- "$provision_mount/.kernaid-rescue-vault")" != "600:0:0" \
  || "$(stat -c '%a:%u:%g' -- "$provision_mount/.kernaid-rescue-secrets.lock")" != "600:0:0" \
  || "$(stat -c '%a:%u:%g' -- "$provision_mount/.kernaid-secure-state-v1")" != "700:0:0" \
  || "$(stat -c '%a:%u:%g' -- "$provision_mount/.kernaid-codex-home-v1")" != "700:973:973" \
  || "$(stat -c '%a:%u:%g:%s' -- "$provision_mount/.kernaid-codex-home-v1/config.toml")" != "600:973:973:36" ]]; then
  echo "The disposable vault layout has unsafe ownership or permissions" >&2
  exit 1
fi
sync
umount "$provision_mount"
provision_mounted=false
cryptsetup close "$provision_mapper"
provision_open=false
assert_vault_resources_clean "Provisioning"

initialize_output="$work_dir/probe-initialize.out"
initialize_error="$work_dir/probe-initialize.err"
run_probe initialize "$initialize_output" "$initialize_error"
journal_binding_before_sha256="$(sha256_text "$probe_journal_binding")"
identity_before_sha256="$(sha256_text "$probe_identity_public_key")"
require_sha256 "initial journal identity binding digest" "$journal_binding_before_sha256"
require_sha256 "initial identity digest" "$identity_before_sha256"

inspect_vault_metadata "Post-initialize"
luks_uuid_before="$observed_luks_uuid"
filesystem_uuid_before="$observed_filesystem_uuid"
detach_vault_loop

# The raw-byte baseline begins only after provisioning and initialize have
# closed cleanly. No host mount or mapping occurs between these two QEMU boots.
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
  if ! terminate_qemu_bounded; then
    qemu_cleanup_safe=false
    echo "QEMU could not be stopped before USB image validation" >&2
    return 1
  fi
}

rescue_not_ready_observed() {
  local boot_log="$1"
  LC_ALL=C grep -aq '^KERNAID_RESCUE_NOT_READY:' "$boot_log"
}

report_rescue_not_ready() {
  local boot_log="$1"
  local marker
  marker="$(
    LC_ALL=C tr -d '\r' <"$boot_log" \
      | grep -aE '^KERNAID_RESCUE_TAURI_GUEST_FAILURE_V1 stage=(http|x11|http-x11|socket-offline-inspector|socket-vault|socket-openai-executor|socket-openai-egress|socket-codex|system-bus|probe-mode|baseline|nonloopback|identity|pidns|session-bus|notify|window-startup|service|process-tree|process-count|process-forbidden|process-executable|process-ancestry|process-metadata-access|process-metadata-format|process-environ-access|process-environ-format|renderer|window|display|xauthority|run-view|devices|device-fds|proc-alias|endpoint-post)$' \
      | tail -n 1 \
      || true
  )"
  if [[ -n "$marker" ]]; then
    printf '%s\n' "$marker" >&2
  fi
  echo "Rescue guest reported a not-ready marker" >&2
}

assert_boot_images_unchanged() {
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

  if [[ "$prefix_after" != "$iso_sha256" ]]; then
    echo "Boot $boot no longer contains the finalized ISO prefix" >&2
    exit 1
  fi
  if [[ "$prefix_after" != "$prefix_before_sha256" ]]; then
    echo "Boot $boot modified the finalized ISO prefix" >&2
    exit 1
  fi
  if [[ "$p3_after" != "$p3_before_sha256" ]]; then
    echo "Boot $boot modified the provisioned p3 region" >&2
    exit 1
  fi
  if [[ "$target_after" != "$target_before_sha256" ]]; then
    echo "Boot $boot modified the disposable virtio target" >&2
    exit 1
  fi
  last_prefix_sha256="$prefix_after"
  last_p3_sha256="$p3_after"
  last_target_sha256="$target_after"
}

run_boot() {
  local boot="$1"
  local boot_log="$work_dir/qemu-$firmware-boot-$boot.log"
  local qemu_deadline qemu_runtime_status status
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
    -fw_cfg "name=opt/kernaid-tauri-sandbox-probe,string=v1"
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

  coproc QEMU_PROCESS {
    IFS= read -r qemu_start_token
    [[ "$qemu_start_token" == KERNAID_QEMU_START_V1 ]] || exit 125
    exec qemu-system-x86_64 "${qemu_args[@]}"
  } >"$boot_log" 2>&1
  qemu_pid="$QEMU_PROCESS_PID" qemu_start_fd="${QEMU_PROCESS[1]}"
  qemu_last_status=""
  if ! capture_qemu_process_identity_bounded; then
    echo "QEMU process identity could not be captured" >&2
    if ! abort_unidentified_qemu_bounded; then
      qemu_cleanup_safe=false
      echo "QEMU start-gate child could not be reaped within the bounded window" >&2
    fi
    return 1
  fi
  if ! signal_qemu_identity_bound CHECK; then
    echo "QEMU pidfd identity preflight failed closed" >&2
    if ! abort_unidentified_qemu_bounded; then
      qemu_cleanup_safe=false
      echo "QEMU start-gate child could not be reaped within the bounded window" >&2
    fi
    return 1
  fi
  if ! release_qemu_start_gate; then
    echo "QEMU start gate could not be released safely" >&2
    return 1
  fi
  qemu_deadline=$((SECONDS + boot_timeout_seconds))
  while ((SECONDS < qemu_deadline)); do
    if rescue_not_ready_observed "$boot_log"; then
      if ! stop_qemu; then
        return 1
      fi
      report_rescue_not_ready "$boot_log"
      return 1
    fi
    if grep -Fq "KERNAID_RESCUE_READY" "$boot_log" \
      && grep -Fq "KERNAID_RESCUE_TARGET_SELECTION_READY" "$boot_log"; then
      stop_qemu
      if rescue_not_ready_observed "$boot_log"; then
        report_rescue_not_ready "$boot_log"
        return 1
      fi
      {
        printf '%s\n' "===== QEMU USB $firmware boot $boot ====="
        cat "$boot_log"
      } >>"$log"
      assert_boot_images_unchanged "$boot"
      printf '%s\n' \
        "KERNAID_QEMU_USB_BOOT_READY_V1 firmware=$firmware boot=$boot ready=true" \
        | tee -a "$log"
      return 0
    fi
    qemu_runtime_status="$(qemu_process_status)"
    if [[ "$qemu_runtime_status" == "gone" \
      || "$qemu_runtime_status" == "reapable" ]]; then
      reap_stopped_qemu || {
        echo "QEMU stopped but could not be reaped safely" >&2
        return 1
      }
      status="$qemu_last_status"
      if rescue_not_ready_observed "$boot_log"; then
        report_rescue_not_ready "$boot_log"
        return 1
      fi
      {
        printf '%s\n' "===== QEMU USB $firmware boot $boot ====="
        cat "$boot_log"
      } >>"$log"
      tail -n 200 "$boot_log"
      echo "QEMU USB boot $boot exited before both readiness markers (status $status)" >&2
      return 1
    elif [[ "$qemu_runtime_status" != "live" ]]; then
      qemu_cleanup_safe=false
      echo "QEMU process state became untrusted: $qemu_runtime_status" >&2
      return 1
    fi
    sleep 1
  done

  stop_qemu
  if rescue_not_ready_observed "$boot_log"; then
    report_rescue_not_ready "$boot_log"
    return 1
  fi
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

# Freeze the catalog-v2 raw-byte window before any post-boot host unlock. The
# later verify mount is logically necessary and may update ordinary ext4 mount
# metadata; it is deliberately outside this p3 hash window.
prefix_after_sha256="$last_prefix_sha256"
p3_after_sha256="$last_p3_sha256"
target_after_sha256="$last_target_sha256"
for digest in "$prefix_after_sha256" "$p3_after_sha256" "$target_after_sha256"; do
  require_sha256 "post-boot USB smoke digest" "$digest"
done
if [[ "$prefix_after_sha256" != "$prefix_before_sha256" \
  || "$p3_after_sha256" != "$p3_before_sha256" \
  || "$target_after_sha256" != "$target_before_sha256" ]]; then
  echo "Two-boot USB media invariants do not match their post-initialize baselines" >&2
  exit 1
fi

allocate_vault_loop
reject_wrong_key
verify_output="$work_dir/probe-verify.out"
verify_error="$work_dir/probe-verify.err"
run_probe verify "$verify_output" "$verify_error"
journal_binding_after_sha256="$(sha256_text "$probe_journal_binding")"
identity_after_sha256="$(sha256_text "$probe_identity_public_key")"
require_sha256 "verified journal identity binding digest" "$journal_binding_after_sha256"
require_sha256 "verified identity digest" "$identity_after_sha256"
if [[ "$journal_binding_after_sha256" != "$journal_binding_before_sha256" \
  || "$identity_after_sha256" != "$identity_before_sha256" ]]; then
  echo "The journal identity binding or DeviceIdentity changed across the two boots" >&2
  exit 1
fi
if [[ "$clean_shutdowns" -ne 2 ]]; then
  echo "The disposable vault did not complete exactly two managed shutdowns" >&2
  exit 1
fi

inspect_vault_metadata "Post-boot verify"
luks_uuid_after="$observed_luks_uuid"
filesystem_uuid_after="$observed_filesystem_uuid"
if [[ "$luks_uuid_after" != "$luks_uuid_before" \
  || "$filesystem_uuid_after" != "$filesystem_uuid_before" ]]; then
  echo "A vault UUID changed across the two USB boots" >&2
  exit 1
fi
detach_vault_loop

# Recheck every non-vault immutable object after the final managed lifecycle.
# A separate digest records the current p3 bytes without pretending that a
# legitimate rw ext4 verify mount is byte-inert.
prefix_post_verify_sha256="$(sha256_region "$rescue_media" 0 "$iso_bytes")"
p3_post_verify_sha256="$(
  sha256_region "$rescue_media" "$p3_start_bytes" "$p3_bytes"
)"
target_post_verify_sha256="$(sha256_file "$target_image")"
layout_manifest_after_sha256="$(sha256_file "$layout_manifest")"
for digest in \
  "$prefix_post_verify_sha256" "$p3_post_verify_sha256" \
  "$target_post_verify_sha256" "$layout_manifest_after_sha256"; do
  require_sha256 "final USB vault smoke digest" "$digest"
done
if [[ "$prefix_post_verify_sha256" != "$iso_sha256" ]]; then
  echo "The final media no longer contains the finalized ISO prefix" >&2
  exit 1
fi
if [[ "$prefix_post_verify_sha256" != "$prefix_before_sha256" ]]; then
  echo "The final probe changed the ISO prefix" >&2
  exit 1
fi
if [[ "$target_post_verify_sha256" != "$target_before_sha256" ]]; then
  echo "The final probe changed the Observe target" >&2
  exit 1
fi
if [[ "$layout_manifest_after_sha256" != "$layout_manifest_sha256" ]]; then
  echo "The final probe changed the layout manifest" >&2
  exit 1
fi
assert_vault_resources_clean "Final verification"
if [[ "$profile_luks_checks" != "$boot_count" \
  || "$profile_ext4_checks" != "$boot_count" ]]; then
  echo "Exact vault profile checks did not pass before and after the boot window" >&2
  exit 1
fi
if [[ -n "$(losetup -j "$rescue_media")" ]]; then
  echo "Final verification left a loop attached to the disposable medium" >&2
  exit 1
fi

printf '%s\n' \
  "KERNAID_QEMU_USB_VAULT_RAW_SCOPE_V1 firmware=$firmware p3_boot_before_sha256=$p3_before_sha256 p3_boot_after_sha256=$p3_after_sha256 p3_post_verify_sha256=$p3_post_verify_sha256 raw_boot_window_unchanged=true post_verify_mount_outside_raw_window=true" \
  | tee -a "$log"
printf '%s\n' \
  "KERNAID_QEMU_USB_ATTESTATION_V1 firmware=$firmware transport=usb-storage boot_count=$boot_count ready_boots=$boot_count uefi_vars=$uefi_vars_attestation media_bytes=$media_bytes iso_bytes=$iso_bytes layout_manifest_sha256=$layout_manifest_sha256 iso_sha256=$iso_sha256 prefix_before_sha256=$prefix_before_sha256 prefix_after_sha256=$prefix_after_sha256 p3_start_bytes=$p3_start_bytes p3_bytes=$p3_bytes p3_before_sha256=$p3_before_sha256 p3_after_sha256=$p3_after_sha256 target_before_sha256=$target_before_sha256 target_after_sha256=$target_after_sha256 ready=true" \
  | tee -a "$log"
printf '%s\n' \
  "KERNAID_QEMU_USB_VAULT_ATTESTATION_V1 firmware=$firmware boot_count=$boot_count luks_version=2 luks_label=KERNAID_VAULT luks_uuid_before=$luks_uuid_before luks_uuid_after=$luks_uuid_after filesystem=ext4 filesystem_label=KERNAID_VAULT vault_profile_version=1 vault_profile_sha256=b4801359bd4f31ce67fbd3ec15b6c81c44aa6759ba43b2a4e099a7dfcc25a37c filesystem_uuid_before=$filesystem_uuid_before filesystem_uuid_after=$filesystem_uuid_after journal_binding_before_sha256=$journal_binding_before_sha256 journal_binding_after_sha256=$journal_binding_after_sha256 identity_before_sha256=$identity_before_sha256 identity_after_sha256=$identity_after_sha256 vault_layout_verified=true wrong_key_rejected=true clean_shutdowns=$clean_shutdowns" \
  | tee -a "$log"
printf '%s\n' \
  "KERNAID_RESCUE_VAULT_HOST_PROBE_V1 sha256=$probe_sha256 invocation_scope=host-only" \
  >>"$log"
echo "PASS: KernAid Rescue completed two $firmware USB boots with a persistent disposable LUKS2 vault and no target writes"
