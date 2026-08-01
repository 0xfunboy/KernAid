#!/usr/bin/env bash
set -euo pipefail

umask 077

for command in cryptsetup losetup sgdisk mkfs.ext4 mount umount mountpoint \
  partprobe udevadm findmnt dd od tr cmp grep stat truncate sync; do
  command -v "$command" >/dev/null || {
    echo "Missing required command: $command" >&2
    exit 2
  }
done
if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run inside a disposable root-capable CI environment." >&2
  exit 2
fi

random_suffix="$(od -An -N16 -tx1 /dev/urandom | tr -d '[:space:]')"
[[ "$random_suffix" =~ ^[0-9a-f]{32}$ ]] || {
  echo "Failed to generate a cryptographically random mapper name." >&2
  exit 1
}
mapper_name="kernaid-vault-test-$random_suffix"

work_dir="$(mktemp -d /tmp/kernaid-vault.XXXXXX)"
image="$work_dir/vault-disk.img"
mount_dir="$work_dir/mount"
key_dir=""
key_file=""
wrong_key_file=""
loop_device=""
loop_attached=false
mapper_opened=false
mount_active=false

create_key_dir() {
  local run_filesystem
  local fallback_filesystem

  if ! run_filesystem="$(findmnt -n -o FSTYPE --target /run)"; then
    echo "Refusing to create vault keys: could not inspect /run." >&2
    return 1
  fi
  if [[ "$run_filesystem" != "tmpfs" ]]; then
    echo "Refusing to create vault keys: /run is not backed by tmpfs." >&2
    return 1
  fi

  if key_dir="$(mktemp -d /run/kernaid-vault-key.XXXXXX 2>/dev/null)"; then
    return 0
  fi

  echo "WARNING: /run is not writable; attempting the tmpfs-only /dev/shm fallback." >&2
  if ! fallback_filesystem="$(findmnt -n -o FSTYPE --target /dev/shm)"; then
    echo "Refusing to create vault keys: could not inspect /dev/shm." >&2
    return 1
  fi
  if [[ "$fallback_filesystem" != "tmpfs" ]]; then
    echo "Refusing to create vault keys: /dev/shm is not backed by tmpfs." >&2
    return 1
  fi
  if ! key_dir="$(mktemp -d /dev/shm/kernaid-vault-key.XXXXXX 2>/dev/null)"; then
    echo "Refusing to continue without a writable tmpfs for vault keys." >&2
    return 1
  fi
}

open_mapper_with_key() {
  local candidate_key="$1"

  # Mark the mapper before invoking cryptsetup so an EXIT trap between the
  # device-mapper operation and the return to Bash still attempts cleanup.
  mapper_opened=true
  if cryptsetup open --type luks2 --batch-mode --key-file "$candidate_key" \
    "$partition" "$mapper_name"; then
    return 0
  fi

  if ! cryptsetup status "$mapper_name" >/dev/null 2>&1; then
    mapper_opened=false
  fi
  return 1
}

attach_loop_device() {
  loop_attached=true
  if loop_device="$(losetup --find --show --partscan "$image")"; then
    return 0
  fi
  if [[ ! "$loop_device" =~ ^/dev/loop[0-9]+$ ]] || \
    ! losetup "$loop_device" >/dev/null 2>&1; then
    loop_attached=false
  fi
  return 1
}

close_mapper() {
  cryptsetup close "$mapper_name"
  mapper_opened=false
}

mount_mapper() {
  mount_active=true
  if mount "$@"; then
    return 0
  fi
  if ! mountpoint -q "$mount_dir"; then
    mount_active=false
  fi
  return 1
}

unmount_mapper() {
  umount "$mount_dir"
  mount_active=false
}

cleanup() {
  local result="$1"
  local cleanup_failed=false
  local work_dir_removable=true

  trap - EXIT
  set +e

  if [[ "$mount_active" == true ]] || mountpoint -q "$mount_dir" 2>/dev/null; then
    if umount "$mount_dir"; then
      mount_active=false
    else
      echo "Cleanup failed: could not unmount $mount_dir" >&2
      cleanup_failed=true
      work_dir_removable=false
    fi
  fi

  if [[ "$mapper_opened" == true ]]; then
    if ! cryptsetup status "$mapper_name" >/dev/null 2>&1; then
      mapper_opened=false
    elif cryptsetup close "$mapper_name"; then
      mapper_opened=false
    else
      echo "Cleanup failed: could not close mapper $mapper_name" >&2
      cleanup_failed=true
      work_dir_removable=false
    fi
  fi

  if [[ "$loop_attached" == true ]]; then
    if [[ ! "$loop_device" =~ ^/dev/loop[0-9]+$ ]]; then
      echo "Cleanup failed: attached loop device has an unexpected name." >&2
      cleanup_failed=true
      work_dir_removable=false
    elif losetup -d "$loop_device"; then
      loop_attached=false
    else
      udevadm settle
      if losetup -d "$loop_device"; then
        loop_attached=false
      else
        echo "Cleanup failed: could not detach $loop_device" >&2
        cleanup_failed=true
        work_dir_removable=false
      fi
    fi
  fi

  case "$key_dir" in
    /run/kernaid-vault-key.* | /dev/shm/kernaid-vault-key.*)
      if [[ -n "$key_file" ]]; then
        rm -f -- "$key_file"
      fi
      if [[ -n "$wrong_key_file" ]]; then
        rm -f -- "$wrong_key_file"
      fi
      if ! rmdir -- "$key_dir"; then
        echo "Cleanup failed: could not remove temporary key directory." >&2
        cleanup_failed=true
      fi
      ;;
    "") ;;
    *)
      echo "Cleanup refused an unexpected key directory: $key_dir" >&2
      cleanup_failed=true
      ;;
  esac

  if [[ "$work_dir_removable" == true ]]; then
    case "$work_dir" in
      /tmp/kernaid-vault.*) rm -rf -- "$work_dir" ;;
      *)
        echo "Cleanup refused an unexpected work directory: $work_dir" >&2
        cleanup_failed=true
        ;;
    esac
  else
    echo "Preserving $work_dir because a block device is still in use." >&2
  fi

  if [[ "$result" -eq 0 && "$cleanup_failed" == true ]]; then
    result=1
  fi
  exit "$result"
}
trap 'cleanup $?' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if cryptsetup status "$mapper_name" >/dev/null 2>&1; then
  echo "Refusing to reuse an existing device-mapper name: $mapper_name" >&2
  exit 1
fi

create_key_dir
key_file="$key_dir/key"
wrong_key_file="$key_dir/wrong-key"
chmod 700 "$key_dir"
dd if=/dev/urandom of="$key_file" bs=64 count=1 status=none
dd if=/dev/urandom of="$wrong_key_file" bs=64 count=1 status=none
chmod 600 "$key_file" "$wrong_key_file"
[[ "$(stat -c '%a' "$key_dir")" == "700" ]]
[[ "$(stat -c '%a' "$key_file")" == "600" ]]
[[ "$(stat -c '%a' "$wrong_key_file")" == "600" ]]
if cmp -s "$key_file" "$wrong_key_file"; then
  echo "Random key generation unexpectedly produced identical test keys." >&2
  exit 1
fi

truncate -s 512M "$image"
test -f "$image"
attach_loop_device
[[ "$loop_device" =~ ^/dev/loop[0-9]+$ ]] || {
  echo "Unexpected loop device" >&2
  exit 1
}

sgdisk --clear --new=1:2048:0 --typecode=1:8309 \
  --change-name=1:KERNAID_VAULT "$loop_device" >/dev/null
partprobe "$loop_device"
udevadm settle
partition="${loop_device}p1"
test -b "$partition"

cryptsetup luksFormat --type luks2 --batch-mode --key-file "$key_file" "$partition"
luks_dump="$(cryptsetup luksDump "$partition")"
grep -q '^Version:[[:space:]]*2$' <<<"$luks_dump"

if open_mapper_with_key "$wrong_key_file" >"$work_dir/wrong-key.log" 2>&1; then
  echo "Vault opened with an incorrect key." >&2
  exit 1
fi
if [[ "$mapper_opened" == true ]]; then
  echo "Incorrect-key attempt left an unexpected mapper open." >&2
  exit 1
fi

open_mapper_with_key "$key_file"
mkfs.ext4 -q -L KERNAID_VAULT "/dev/mapper/$mapper_name"
mkdir "$mount_dir"
mount_mapper -o nosuid,nodev,noexec "/dev/mapper/$mapper_name" "$mount_dir"

sentinel="KERNAID_VAULT_ROUNDTRIP_$RANDOM$RANDOM"
printf '%s\n' "$sentinel" >"$mount_dir/roundtrip.txt"
sync -f "$mount_dir/roundtrip.txt"
unmount_mapper
close_mapper

if grep -a -q "$sentinel" "$image"; then
  echo "Vault plaintext leaked into the raw image" >&2
  exit 1
fi

open_mapper_with_key "$key_file"
mount_mapper -o ro,nosuid,nodev,noexec "/dev/mapper/$mapper_name" "$mount_dir"
test "$(cat "$mount_dir/roundtrip.txt")" = "$sentinel"
unmount_mapper
close_mapper

echo "PASS: LUKS2 rejects the wrong key, survives close/reopen, and leaks no sentinel plaintext"
