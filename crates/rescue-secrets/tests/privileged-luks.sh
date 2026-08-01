#!/usr/bin/env bash
set -euo pipefail

umask 077

if [[ "$#" -ne 1 || ! -x "$1" ]]; then
  echo "usage: $0 /absolute/path/to/kernaid-rescue-vault-probe" >&2
  exit 2
fi
probe_binary="$1"
if [[ "$probe_binary" != /* ]]; then
  probe_binary="$PWD/$probe_binary"
fi
if [[ ! -x "$probe_binary" ]]; then
  echo "the Rescue vault probe is not executable" >&2
  exit 2
fi
if [[ "$(id -u)" -ne 0 ]]; then
  echo "run this disposable LUKS2 probe as root" >&2
  exit 2
fi

for command in chmod cryptsetup dd findmnt id losetup mkdir mkfs.ext4 mktemp \
  mount mountpoint od rm rmdir sync tr truncate umount udevadm; do
  command -v "$command" >/dev/null || {
    echo "missing required disposable-probe tooling" >&2
    exit 2
  }
done
if [[ "$(findmnt -n -o FSTYPE --target /dev/shm)" != "tmpfs" ]]; then
  echo "refusing to place the disposable LUKS key outside tmpfs" >&2
  exit 2
fi

random_suffix="$(od -An -N8 -tx1 /dev/urandom | tr -d '[:space:]')"
if [[ ! "$random_suffix" =~ ^[0-9a-f]{16}$ ]]; then
  echo "failed to generate a safe disposable suffix" >&2
  exit 1
fi
manager_mapper="kernaid-vault-$random_suffix"
provision_mapper="kernaid-provision-$random_suffix"
manager_mount="/run/kernaid/vault/$manager_mapper"
work_dir="$(mktemp -d /tmp/kernaid-rescue-manager.XXXXXX)"
key_dir="$(mktemp -d /dev/shm/kernaid-rescue-manager-key.XXXXXX)"
image="$work_dir/vault.img"
key_file="$key_dir/key"
wrong_key_file="$key_dir/wrong-key"
provision_mount="$work_dir/provision"
loop_device=""
provision_open=false
provision_mounted=false

cleanup() {
  local result="$1"
  local cleanup_failed=false
  trap - EXIT
  set +e

  if mountpoint -q "$manager_mount" 2>/dev/null; then
    if ! umount "$manager_mount"; then
      echo "failed to unmount the disposable managed vault" >&2
      cleanup_failed=true
    fi
  fi
  if cryptsetup status "$manager_mapper" >/dev/null 2>&1; then
    if ! cryptsetup close "$manager_mapper"; then
      echo "failed to close the disposable managed mapper" >&2
      cleanup_failed=true
    fi
  fi
  if [[ "$provision_mounted" == true ]] || mountpoint -q "$provision_mount" 2>/dev/null; then
    if ! umount "$provision_mount"; then
      echo "failed to unmount the disposable provisioning vault" >&2
      cleanup_failed=true
    fi
    provision_mounted=false
  fi
  if [[ "$provision_open" == true ]] || cryptsetup status "$provision_mapper" >/dev/null 2>&1; then
    if ! cryptsetup close "$provision_mapper"; then
      echo "failed to close the disposable provisioning mapper" >&2
      cleanup_failed=true
    fi
    provision_open=false
  fi
  if [[ -n "$loop_device" ]]; then
    if [[ "$loop_device" =~ ^/dev/loop[0-9]+$ ]]; then
      udevadm settle
      if ! losetup -d "$loop_device"; then
        echo "failed to detach the disposable loop device" >&2
        cleanup_failed=true
      fi
    else
      echo "refusing to detach an unexpected loop path" >&2
      cleanup_failed=true
    fi
  fi

  case "$key_dir" in
    /dev/shm/kernaid-rescue-manager-key.*)
      rm -f -- "$key_file" "$wrong_key_file"
      rmdir -- "$key_dir" 2>/dev/null || cleanup_failed=true
      ;;
    *)
      echo "refusing to remove an unexpected key directory" >&2
      cleanup_failed=true
      ;;
  esac
  case "$work_dir" in
    /tmp/kernaid-rescue-manager.*)
      if [[ "$cleanup_failed" == false ]]; then
        rm -rf -- "$work_dir"
      else
        echo "preserving the disposable work directory after cleanup failure" >&2
      fi
      ;;
    *)
      echo "refusing to remove an unexpected work directory" >&2
      cleanup_failed=true
      ;;
  esac

  if [[ "$result" -eq 0 && "$cleanup_failed" == true ]]; then
    result=1
  fi
  exit "$result"
}
trap 'cleanup $?' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

truncate -s 256M "$image"
dd if=/dev/urandom of="$key_file" bs=64 count=1 status=none
dd if=/dev/urandom of="$wrong_key_file" bs=64 count=1 status=none
chmod 600 "$key_file"
chmod 600 "$wrong_key_file"
loop_device="$(losetup --find --show "$image")"
if [[ ! "$loop_device" =~ ^/dev/loop[0-9]+$ ]]; then
  echo "the disposable loop allocator returned an unexpected path" >&2
  exit 1
fi

# Provisioning is intentionally confined to this disposable CI image. The
# production Rust manager exposes no format, erase, repair, or raw-write API.
cryptsetup luksFormat --type luks2 --batch-mode --label KERNAID_VAULT \
  --key-file "$key_file" "$loop_device"
cryptsetup open --type luks2 --batch-mode --key-file "$key_file" \
  "$loop_device" "$provision_mapper"
provision_open=true
mkfs.ext4 -q -L KERNAID_VAULT "/dev/mapper/$provision_mapper"
mkdir "$provision_mount"
chmod 700 "$provision_mount"
mount -t ext4 "/dev/mapper/$provision_mapper" "$provision_mount"
provision_mounted=true
chmod 700 "$provision_mount"
printf 'KERNAID-RESCUE-VAULT-V1\n' >"$provision_mount/.kernaid-rescue-vault"
chmod 600 "$provision_mount/.kernaid-rescue-vault"
mkdir "$provision_mount/.kernaid-secure-state-v1"
chmod 700 "$provision_mount/.kernaid-secure-state-v1"
: >"$provision_mount/.kernaid-rescue-secrets.lock"
chmod 600 "$provision_mount/.kernaid-rescue-secrets.lock"
sync
umount "$provision_mount"
provision_mounted=false
cryptsetup close "$provision_mapper"
provision_open=false

# The block device is an explicit positional argument. The passphrase enters
# only on stdin; neither value is inferred from an environment variable/glob.
if "$probe_binary" --device "$loop_device" --mapper "$manager_mapper" \
  --mode initialize <"$wrong_key_file"; then
  echo "the Rescue manager accepted an incorrect passphrase" >&2
  exit 1
fi
if mountpoint -q "$manager_mount" || cryptsetup status "$manager_mapper" >/dev/null 2>&1; then
  echo "the failed unlock left a mount or mapping active" >&2
  exit 1
fi

"$probe_binary" --device "$loop_device" --mapper "$manager_mapper" \
  --mode initialize <"$key_file"
"$probe_binary" --device "$loop_device" --mapper "$manager_mapper" \
  --mode verify <"$key_file"

if mountpoint -q "$manager_mount" || cryptsetup status "$manager_mapper" >/dev/null 2>&1; then
  echo "the Rescue manager left a mount or mapping active" >&2
  exit 1
fi

echo "PASS: Rescue manager rejected a wrong key and persisted journal/identity across reopen"
