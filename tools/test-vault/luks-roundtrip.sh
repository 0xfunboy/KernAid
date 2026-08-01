#!/usr/bin/env bash
set -euo pipefail

for command in cryptsetup losetup sgdisk mkfs.ext4 mount umount mountpoint partprobe udevadm; do
  command -v "$command" >/dev/null || { echo "Missing required command: $command" >&2; exit 2; }
done
if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run inside a disposable root-capable CI environment." >&2
  exit 2
fi

work_dir="$(mktemp -d /tmp/kernaid-vault.XXXXXX)"
image="$work_dir/vault-disk.img"
mount_dir="$work_dir/mount"
key_file="$work_dir/key"
mapper_name="kernaid-vault-test-$$"
loop_device=""

cleanup() {
  mountpoint -q "$mount_dir" && umount "$mount_dir" || true
  cryptsetup status "$mapper_name" >/dev/null 2>&1 && cryptsetup close "$mapper_name" || true
  if [[ -n "$loop_device" && "$loop_device" =~ ^/dev/loop[0-9]+$ ]]; then losetup -d "$loop_device" || true; fi
  case "$work_dir" in /tmp/kernaid-vault.*) rm -rf -- "$work_dir" ;; esac
}
trap cleanup EXIT

truncate -s 512M "$image"
test -f "$image"
loop_device="$(losetup --find --show --partscan "$image")"
[[ "$loop_device" =~ ^/dev/loop[0-9]+$ ]] || { echo "Unexpected loop device" >&2; exit 1; }

sgdisk --clear --new=1:2048:0 --typecode=1:8309 --change-name=1:KERNAID_VAULT "$loop_device" >/dev/null
partprobe "$loop_device"
udevadm settle
partition="${loop_device}p1"
test -b "$partition"

umask 077
dd if=/dev/urandom of="$key_file" bs=64 count=1 status=none
cryptsetup luksFormat --type luks2 --batch-mode --key-file "$key_file" "$partition"
luks_dump="$(cryptsetup luksDump "$partition")"
grep -q '^Version:[[:space:]]*2$' <<<"$luks_dump"
cryptsetup open --key-file "$key_file" "$partition" "$mapper_name"
mkfs.ext4 -q -L KERNAID_VAULT "/dev/mapper/$mapper_name"
mkdir "$mount_dir"
mount -o nosuid,nodev,noexec "/dev/mapper/$mapper_name" "$mount_dir"

sentinel="KERNAID_VAULT_ROUNDTRIP_$RANDOM$RANDOM"
printf '%s\n' "$sentinel" > "$mount_dir/roundtrip.txt"
sync -f "$mount_dir/roundtrip.txt"
umount "$mount_dir"
cryptsetup close "$mapper_name"

if grep -a -q "$sentinel" "$image"; then
  echo "Vault plaintext leaked into the raw image" >&2
  exit 1
fi

cryptsetup open --key-file "$key_file" "$partition" "$mapper_name"
mount -o ro,nosuid,nodev,noexec "/dev/mapper/$mapper_name" "$mount_dir"
test "$(cat "$mount_dir/roundtrip.txt")" = "$sentinel"
echo "PASS: LUKS2 vault survives close/reopen and raw image contains no sentinel plaintext"
