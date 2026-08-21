#!/usr/bin/env bash
set -euo pipefail
umask 077
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
firmware="${1:-bios}"
iso="${2:-$repo_dir/KernAid-Rescue-amd64.iso}"
snapshot_fixture="$repo_dir/tests/fixtures/linux-normalized-snapshot/healthy/root"
snapshot_golden="$repo_dir/tests/fixtures/linux-normalized-snapshot/expected/snapshot.v1.json"
readonly boot_timeout_seconds=1200
readonly qemu_identity_capture_seconds=5
readonly qemu_term_grace_seconds=5
readonly qemu_kill_grace_seconds=5
readonly qemu_stop_poll_seconds=0.05
for command in cp dd debugfs mcopy mmd mkfs.ext4 mkfs.ntfs mkfs.vfat ntfsfix \
  python3 qemu-system-x86_64 sgdisk sha256sum sync tee tr truncate; do
  command -v "$command" >/dev/null || { echo "Missing required command: $command" >&2; exit 2; }
done
[[ -x /usr/bin/python3 ]] || {
  echo "Missing fixed pidfd helper interpreter: /usr/bin/python3" >&2
  exit 2
}
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
ovmf_directory="/usr/share/OVMF"

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

resolve_trusted_firmware_file() {
  local path="$1"
  local resolved parent file_type owner_uid owner_gid permissions
  case "$path" in
    "$ovmf_directory"/*.fd) ;;
    *)
      echo "OVMF firmware path is outside the fixed system directory: $path" >&2
      return 1
      ;;
  esac
  parent="${path%/*}"
  trusted_root_directory_chain "$parent" || return 1
  resolved="$($readlink_command -f -- "$path")"
  [[ -n "$resolved" ]] || {
    echo "OVMF firmware path did not resolve: $path" >&2
    return 1
  }
  case "$resolved" in
    "$ovmf_directory"/*|/usr/share/edk2/*) ;;
    *)
      echo "OVMF firmware resolved outside the system allowlist: $path" >&2
      return 1
      ;;
  esac
  parent="${resolved%/*}"
  trusted_root_directory_chain "$parent" || return 1
  if [[ ! -f "$resolved" || -L "$resolved" ]]; then
    echo "OVMF firmware is not a resolved regular file: $path" >&2
    return 1
  fi
  IFS=: read -r file_type owner_uid owner_gid permissions \
    <<<"$(LC_ALL=C "$stat_command" -c '%F:%u:%g:%a' -- "$resolved")"
  if [[ "$file_type" != "regular file" || "$owner_uid" != "0" \
    || "$owner_gid" != "0" || -z "$permissions" \
    || $((8#$permissions & 0022)) -ne 0 ]]; then
    echo "OVMF firmware failed root ownership and mode validation: $path" >&2
    return 1
  fi
  printf '%s\n' "$resolved"
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
[[ -d "$snapshot_fixture" && ! -L "$snapshot_fixture" ]] \
  || { echo "Shared Linux snapshot fixture not found" >&2; exit 2; }
snapshot_golden_semantic_sha256="$(/usr/bin/python3 -I -B - "$snapshot_golden" <<'PY'
import hashlib
import json
import sys

with open(sys.argv[1], "rb") as stream:
    snapshot = json.load(stream)
canonical = json.dumps(
    snapshot, ensure_ascii=False, sort_keys=True, separators=(",", ":")
).encode("utf-8")
print(
    hashlib.sha256(
        b"KERNAID_LINUX_NORMALIZED_SNAPSHOT_E2E_SEMANTIC_V1\0" + canonical
    ).hexdigest()
)
PY
)" || { echo "Shared Linux snapshot semantic digest failed" >&2; exit 2; }
if [[ ! "$snapshot_golden_semantic_sha256" =~ ^[0-9a-f]{64}$ ]]; then
  echo "Shared Linux snapshot semantic digest is invalid" >&2
  exit 2
fi
resident_snapshot_semantic_sha256="${KERNAID_RESIDENT_SNAPSHOT_SEMANTIC_SHA256:-}"
if [[ -z "$resident_snapshot_semantic_sha256" ]]; then
  echo "Resident Linux snapshot digest is required" >&2
  exit 2
fi
if [[ ! "$resident_snapshot_semantic_sha256" =~ ^[0-9a-f]{64}$ \
  || "$resident_snapshot_semantic_sha256" != "$snapshot_golden_semantic_sha256" ]]; then
  echo "Resident Linux snapshot digest did not match the shared healthy fixture" >&2
  exit 2
fi
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
ovmf_vars=""
ovmf_vars_path_identity=""
qemu_pid=""
qemu_process_identity=""
qemu_start_fd=""
qemu_last_status=""
qemu_cleanup_safe=1
windows_fixture_mounted=0
windows_fixture_cleanup_safe=1
fixture_uid="$(/usr/bin/id -u)"
fixture_gid="$(/usr/bin/id -g)"
ui_smoke_dir="$($mktemp_command -d)"
ui_smoke_dir_identity="$($stat_command -c '%d:%i:%u:%g:%a' -- "$ui_smoke_dir")"
qmp_socket="$ui_smoke_dir/qmp.sock"
if [[ -L "$ui_smoke_dir" || ! -d "$ui_smoke_dir" \
  || "$ui_smoke_dir_identity" != *":$fixture_uid:$fixture_gid:700" ]]; then
  echo "Disposable Tauri UI smoke directory is unsafe" >&2
  exit 1
fi

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

rescue_not_ready_observed() {
  LC_ALL=C grep -aq '^KERNAID_RESCUE_NOT_READY:' "$log"
}

report_tauri_sandbox_failure() {
  local marker
  marker="$(
    LC_ALL=C tr -d '\r' <"$log" \
      | grep -aE '^KERNAID_RESCUE_TAURI_GUEST_FAILURE_V1 stage=(http|x11|http-x11|socket-offline-inspector|socket-vault|socket-openai-executor|socket-openai-egress|socket-codex|system-bus|probe-mode|baseline|nonloopback|identity|pidns|session-bus|notify|service|process-tree|renderer|window|display|xauthority|run-view|devices|device-fds|proc-alias|endpoint-post)$' \
      | tail -n 1 \
      || true
  )"
  if [[ -n "$marker" ]]; then
    printf '%s\n' "$marker" >&2
  fi
}

report_rescue_not_ready() {
  report_tauri_sandbox_failure
  echo "Rescue guest reported a not-ready marker" >&2
}

hardware_inventory_ready_observed() {
  LC_ALL=C tr -d '\r' <"$log" \
    | grep -aE '^KERNAID_RESCUE_HARDWARE_INVENTORY_READY$' >/dev/null
}

# shellcheck disable=SC2317,SC2329  # Invoked indirectly by the EXIT cleanup trap.
cleanup_ui_smoke_directory() {
  local path file_type owner_uid owner_gid hard_links
  if [[ -L "$ui_smoke_dir" || ! -d "$ui_smoke_dir" \
    || "$($stat_command -c '%d:%i:%u:%g:%a' -- "$ui_smoke_dir")" \
      != "$ui_smoke_dir_identity" ]]; then
    echo "Preserving a Tauri UI smoke directory whose identity changed" >&2
    return 1
  fi
  for path in "$qmp_socket" "$ui_smoke_dir/before.ppm" "$ui_smoke_dir/after.ppm"; do
    if [[ ! -e "$path" && ! -L "$path" ]]; then
      continue
    fi
    if [[ -L "$path" ]]; then
      echo "Preserving a symlink in the Tauri UI smoke directory" >&2
      return 1
    fi
    IFS=: read -r file_type owner_uid owner_gid hard_links \
      <<<"$(LC_ALL=C "$stat_command" -c '%F:%u:%g:%h' -- "$path")"
    if [[ "$owner_uid" != "$fixture_uid" || "$owner_gid" != "$fixture_gid" \
      || "$hard_links" != "1" ]]; then
      echo "Preserving a Tauri UI smoke artifact whose identity is unsafe" >&2
      return 1
    fi
    if [[ "$path" == "$qmp_socket" && "$file_type" != "socket" ]]; then
      echo "Preserving a non-socket QMP path" >&2
      return 1
    fi
    if [[ "$path" != "$qmp_socket" && "$file_type" != "regular file" ]]; then
      echo "Preserving a non-regular Tauri UI screenshot" >&2
      return 1
    fi
    rm -f -- "$path"
  done
  if ! rmdir -- "$ui_smoke_dir"; then
    echo "Tauri UI smoke directory contained an unexpected entry" >&2
    return 1
  fi
}

# shellcheck disable=SC2329  # Invoked indirectly by the EXIT trap below.
# This callback is reached indirectly through the EXIT trap below.
# shellcheck disable=SC2317
cleanup() {
  local status="$1"
  local cleanup_failed=0
  trap - EXIT
  if ! recover_qemu_start_gate_tracking; then
    qemu_cleanup_safe=0
    cleanup_failed=1
  fi
  if [[ -n "$qemu_pid" && -z "$qemu_process_identity" ]]; then
    if ! abort_unidentified_qemu_bounded; then
      qemu_cleanup_safe=0
      cleanup_failed=1
    fi
  elif ! terminate_qemu_bounded; then
    qemu_cleanup_safe=0
    cleanup_failed=1
  fi
  if [[ "$windows_fixture_mounted" == "1" ]] \
    || "$findmnt_command" -rn --mountpoint "$windows_seed_mount" >/dev/null; then
    if ! unmount_disposable_windows_fixture no; then
      echo "Failed to unmount the disposable Windows fixture during cleanup" >&2
      cleanup_failed=1
    fi
  fi
  if [[ "$qemu_cleanup_safe" == "1" ]]; then
    if [[ "$temporary_log" == "1" ]]; then rm -f "$log"; fi
    if [[ -n "$ovmf_vars" ]]; then
      if [[ -z "$ovmf_vars_path_identity" || -L "$ovmf_vars" \
        || ! -f "$ovmf_vars" \
        || "$($stat_command -c '%d:%i:%u:%g:%a:%h' -- "$ovmf_vars")" \
          != "$ovmf_vars_path_identity" ]]; then
        echo "Preserving an OVMF variable store whose disposable identity changed" >&2
        cleanup_failed=1
      else
        rm -f -- "$ovmf_vars"
        if [[ -e "$ovmf_vars" || -L "$ovmf_vars" ]]; then
          echo "Failed to remove the disposable OVMF variable store" >&2
          cleanup_failed=1
        fi
      fi
    fi
    if ! cleanup_ui_smoke_directory; then
      cleanup_failed=1
    fi
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
  else
    echo "Preserving QEMU backing files because termination was not confirmed" >&2
    cleanup_failed=1
  fi
  if [[ "$cleanup_failed" == "1" ]]; then exit 1; fi
  exit "$status"
}
trap 'cleanup $?' EXIT
cp -a -- "$snapshot_fixture/." "$target_seed_dir/"
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
  -fw_cfg "name=opt/kernaid-tauri-sandbox-probe,string=v1" \
  -qmp "unix:$qmp_socket,server=on,wait=off" \
  -boot d -vga std -display none -serial stdio -nic none -no-reboot)
if [[ "$firmware" == "uefi" ]]; then
  ovmf_code_4m="$ovmf_directory/OVMF_CODE_4M.fd"
  ovmf_vars_4m="$ovmf_directory/OVMF_VARS_4M.fd"
  ovmf_code_legacy="$ovmf_directory/OVMF_CODE.fd"
  ovmf_vars_legacy="$ovmf_directory/OVMF_VARS.fd"
  ovmf_code=""
  ovmf_vars_template=""
  if [[ -e "$ovmf_code_4m" || -L "$ovmf_code_4m" \
    || -e "$ovmf_vars_4m" || -L "$ovmf_vars_4m" ]]; then
    if [[ ! -f "$ovmf_code_4m" || ! -f "$ovmf_vars_4m" ]]; then
      echo "OVMF 4M CODE/VARS firmware pair is incomplete" >&2
      exit 2
    fi
    ovmf_code="$ovmf_code_4m"
    ovmf_vars_template="$ovmf_vars_4m"
  elif [[ -e "$ovmf_code_legacy" || -L "$ovmf_code_legacy" \
    || -e "$ovmf_vars_legacy" || -L "$ovmf_vars_legacy" ]]; then
    if [[ ! -f "$ovmf_code_legacy" || ! -f "$ovmf_vars_legacy" ]]; then
      echo "OVMF legacy CODE/VARS firmware pair is incomplete" >&2
      exit 2
    fi
    ovmf_code="$ovmf_code_legacy"
    ovmf_vars_template="$ovmf_vars_legacy"
  else
    echo "OVMF CODE/VARS firmware pair not found" >&2
    exit 2
  fi
  ovmf_code_resolved="$(resolve_trusted_firmware_file "$ovmf_code")" || exit 2
  ovmf_vars_template_resolved="$(resolve_trusted_firmware_file "$ovmf_vars_template")" \
    || exit 2
  if [[ "$($stat_command -c '%d:%i' -- "$ovmf_code_resolved")" \
    == "$($stat_command -c '%d:%i' -- "$ovmf_vars_template_resolved")" ]]; then
    echo "OVMF CODE and VARS firmware files have the same identity" >&2
    exit 2
  fi
  ovmf_vars_template_identity="$($stat_command -c '%d:%i:%s:%u:%g:%a:%h' -- \
    "$ovmf_vars_template_resolved")"
  ovmf_vars="$($mktemp_command)"
  ovmf_vars_path_identity="$($stat_command -c '%d:%i:%u:%g:%a:%h' -- "$ovmf_vars")"
  if [[ -L "$ovmf_vars" || ! -f "$ovmf_vars" \
    || "$ovmf_vars_path_identity" != *":$fixture_uid:$fixture_gid:600:1" ]]; then
    echo "Disposable OVMF variable store ownership or mode is unsafe" >&2
    exit 1
  fi
  cp -- "$ovmf_vars_template_resolved" "$ovmf_vars"
  if [[ "$($stat_command -c '%d:%i:%s:%u:%g:%a:%h' -- \
      "$ovmf_vars_template_resolved")" \
      != "$ovmf_vars_template_identity" \
    || -L "$ovmf_vars" || ! -f "$ovmf_vars" \
    || "$($stat_command -c '%d:%i:%u:%g:%a:%h' -- "$ovmf_vars")" \
      != "$ovmf_vars_path_identity" \
    || "$($stat_command -c '%s' -- "$ovmf_vars")" \
      != "$($stat_command -c '%s' -- "$ovmf_vars_template_resolved")" ]]; then
    echo "Disposable OVMF variable store copy failed identity validation" >&2
    exit 1
  fi
  qemu_args+=(
    -drive "if=pflash,format=raw,readonly=on,unit=0,file=$ovmf_code_resolved"
    -drive "if=pflash,format=raw,unit=1,file=$ovmf_vars"
  )
fi

coproc QEMU_PROCESS {
  IFS= read -r qemu_start_token
  [[ "$qemu_start_token" == KERNAID_QEMU_START_V1 ]] || exit 125
  exec qemu-system-x86_64 "${qemu_args[@]}"
} >"$log" 2>&1
qemu_pid="$QEMU_PROCESS_PID" qemu_start_fd="${QEMU_PROCESS[1]}"
qemu_last_status=""
if ! capture_qemu_process_identity_bounded; then
  echo "QEMU process identity could not be captured" >&2
  if ! abort_unidentified_qemu_bounded; then
    qemu_cleanup_safe=0
    echo "QEMU start-gate child could not be reaped within the bounded window" >&2
  fi
  exit 1
fi
if ! signal_qemu_identity_bound CHECK; then
  echo "QEMU pidfd identity preflight failed closed" >&2
  if ! abort_unidentified_qemu_bounded; then
    qemu_cleanup_safe=0
    echo "QEMU start-gate child could not be reaped within the bounded window" >&2
  fi
  exit 1
fi
if ! release_qemu_start_gate; then
  echo "QEMU start gate could not be released safely" >&2
  exit 1
fi
qemu_deadline=$((SECONDS + boot_timeout_seconds))
while ((SECONDS < qemu_deadline)); do
  if rescue_not_ready_observed; then
    if ! terminate_qemu_bounded; then
      echo "QEMU could not be stopped after the not-ready marker" >&2
      exit 1
    fi
    report_rescue_not_ready
    exit 1
  fi
  if grep -q "KERNAID_RESCUE_READY" "$log" \
    && hardware_inventory_ready_observed \
    && grep -q "KERNAID_RESCUE_TARGET_SELECTION_READY" "$log" \
    && grep -q "KERNAID_RESCUE_OFFLINE_INSPECTION_READY" "$log" \
    && grep -q '^KERNAID_RESCUE_TAURI_GUEST_V1 identity=isolated pidns=private shell-bus=mount-masked session-bus=env-disabled-polkit-denied fs-sockets=allowlisted abstract-unix=not-attested devices=private device-fds=no-privileged shell=shipping renderer=webkit2gtk-4[.]1 window=visible display=active-xorg http=loopback x11=connected privileged-fs-sockets=absent nonloopback=denied ' "$log" \
    && grep -q '^KERNAID_RESCUE_LINUX_SNAPSHOT_E2E_V1 semantic_sha256=' "$log"; then
    tauri_ui_attestation="$(
      /usr/bin/python3 -I -B "$repo_dir/tools/build-rescue/qemu-tauri-ui-smoke.py" \
        --socket "$qmp_socket" --work-dir "$ui_smoke_dir" --firmware "$firmware"
    )" || {
      echo "QEMU Tauri UI render/input gate failed closed" >&2
      exit 1
    }
    if [[ ! "$tauri_ui_attestation" =~ ^KERNAID_QEMU_TAURI_UI_ATTESTATION_V1\ firmware=(bios|uefi)\ shell=shipping\ renderer=webkit2gtk-4\.1\ display=default\ rendered=true\ input=true\ width=[1-9][0-9]{2,3}\ height=[1-9][0-9]{2,3}\ changed_pixels=[1-9][0-9]*$ \
      || "${BASH_REMATCH[1]}" != "$firmware" ]]; then
      echo "QEMU Tauri UI attestation was outside the sanitized allowlist" >&2
      exit 1
    fi
    printf '%s\n' "$tauri_ui_attestation" | tee -a "$log"
    if ! terminate_qemu_bounded; then
      echo "QEMU could not be stopped before target-image validation" >&2
      exit 1
    fi
    if rescue_not_ready_observed; then
      report_rescue_not_ready
      exit 1
    fi
    mapfile -t hardware_inventory_ready_markers \
      < <(LC_ALL=C tr -d '\r' <"$log" \
        | grep -aE '^KERNAID_RESCUE_HARDWARE_INVENTORY_READY$')
    if [[ "${#hardware_inventory_ready_markers[@]}" -ne 1 ]]; then
      echo "Rescue hardware inventory marker was not unique" >&2
      exit 1
    fi
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
    mapfile -t rescue_snapshot_markers \
      < <(LC_ALL=C tr -d '\r' <"$log" \
        | grep -aE '^KERNAID_RESCUE_LINUX_SNAPSHOT_E2E_V1 semantic_sha256=[0-9a-f]{64}$')
    if [[ "${#rescue_snapshot_markers[@]}" -ne 1 ]]; then
      echo "Rescue Linux snapshot digest marker was not unique" >&2
      exit 1
    fi
    rescue_snapshot_semantic_sha256="${rescue_snapshot_markers[0]##*=}"
    if [[ "$rescue_snapshot_semantic_sha256" != "$resident_snapshot_semantic_sha256" ]]; then
      echo "Resident and Rescue Linux snapshots were not semantically equal" >&2
      exit 1
    fi
    printf '%s\n' \
      "KERNAID_QEMU_LINUX_SNAPSHOT_E2E_V1 firmware=$firmware semantic_sha256=$rescue_snapshot_semantic_sha256 semantic_equal=true" \
      | tee -a "$log"
    printf '%s\n' \
      "KERNAID_QEMU_ATTESTATION_V1 firmware=$firmware iso_sha256=$iso_hash_after target_before_sha256=$target_hash_before target_after_sha256=$target_hash_after ready=true" \
      | tee -a "$log"
    printf '%s\n' \
      "KERNAID_QEMU_OFFLINE_INSPECTION_ATTESTATION_V1 firmware=$firmware linux_before_sha256=$target_hash_before linux_after_sha256=$target_hash_after windows_gpt_before_sha256=$windows_gpt_target_hash_before windows_gpt_after_sha256=$windows_gpt_target_hash_after windows_altered_before_sha256=$altered_windows_target_hash_before windows_altered_after_sha256=$altered_windows_target_hash_after ready=true" \
      | tee -a "$log"
    echo "PASS: KernAid Rescue booted its Tauri/WebKit UI with rendered keyboard interaction under $firmware firmware, inspected Linux ext4, a same-disk GPT Windows NTFS plus ESP fixture, and an altered NTFS fixture read-only with zero target-image writes"
    exit 0
  fi
  qemu_runtime_status="$(qemu_process_status)"
  if [[ "$qemu_runtime_status" == "gone" \
    || "$qemu_runtime_status" == "reapable" ]]; then
    reap_stopped_qemu || {
      echo "QEMU stopped but could not be reaped safely" >&2
      exit 1
    }
    status="$qemu_last_status"
    if rescue_not_ready_observed; then
      report_rescue_not_ready
      exit 1
    fi
    cat "$log"
    echo "QEMU exited before both Rescue readiness markers (status $status)" >&2
    exit 1
  elif [[ "$qemu_runtime_status" != "live" ]]; then
    echo "QEMU process state became untrusted: $qemu_runtime_status" >&2
    exit 1
  fi
  sleep 1
done
if ! terminate_qemu_bounded; then
  echo "QEMU could not be stopped after the readiness timeout" >&2
  exit 1
fi
if rescue_not_ready_observed; then
  report_rescue_not_ready
  exit 1
fi
tail -n 200 "$log"
echo "The required Rescue readiness markers were not both observed within $boot_timeout_seconds seconds" >&2
exit 1
