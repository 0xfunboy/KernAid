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

for command in blockdev chmod cryptsetup dd dmsetup findmnt grep id losetup mkdir \
  mkfs.ext4 mktemp mount mountpoint od rm rmdir sha256sum sleep stat sync tr \
  truncate tune2fs umount unshare udevadm; do
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
manager_mapper_path="/dev/mapper/$manager_mapper"
manager_mount="/run/kernaid/vault/$manager_mapper"
work_dir="$(mktemp -d /tmp/kernaid-rescue-manager.XXXXXX)"
key_dir="$(mktemp -d /dev/shm/kernaid-rescue-manager-key.XXXXXX)"
image="$work_dir/vault.img"
key_file="$key_dir/key"
wrong_key_file="$key_dir/wrong-key"
provision_mount="$work_dir/provision"
crash_log="$work_dir/crash-cleanup.log"
loop_device=""
crash_pid=""
provision_open=false
provision_mounted=false
logical_sector_bytes=512
vault_sector_count=16777216
vault_bytes=8589934592
luks_data_offset_bytes=16777216
payload_bytes=8573157376
payload_sector_count=16744448
luks_header_span_bytes=32768

cleanup() {
  local result="$1"
  local cleanup_failed=false
  trap - EXIT
  set +e

  # The background crash probe is always a direct child because unshare is
  # deliberately invoked without --fork. Every error path kills and reaps it
  # before attempting mount, mapper, or loop-device cleanup.
  if [[ -n "$crash_pid" ]]; then
    if kill -0 "$crash_pid" 2>/dev/null; then
      if ! kill -KILL "$crash_pid" 2>/dev/null; then
        echo "failed to terminate the disposable crash probe" >&2
        cleanup_failed=true
      fi
    fi
    wait "$crash_pid" >/dev/null 2>&1
    crash_pid=""
    if [[ "$result" -eq 0 ]]; then
      echo "the disposable crash probe required unexpected EXIT cleanup" >&2
      cleanup_failed=true
    fi
  fi

  if mountpoint -q "$manager_mount" 2>/dev/null; then
    if ! umount "$manager_mount"; then
      echo "failed to unmount the disposable managed vault" >&2
      cleanup_failed=true
    fi
  fi
  if cryptsetup status "$manager_mapper" >/dev/null 2>&1 ||
    dmsetup info "$manager_mapper" >/dev/null 2>&1; then
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

mapper_is_absent() {
  if cryptsetup status "$manager_mapper" >/dev/null 2>&1; then
    return 1
  fi
  if dmsetup info "$manager_mapper" >/dev/null 2>&1; then
    return 1
  fi
  [[ ! -e "$manager_mapper_path" && ! -L "$manager_mapper_path" ]]
}

if ((vault_sector_count * logical_sector_bytes != vault_bytes)) ||
  ((vault_bytes - luks_data_offset_bytes != payload_bytes)) ||
  ((payload_bytes / logical_sector_bytes != payload_sector_count)); then
  echo "the disposable vault geometry constants are inconsistent" >&2
  exit 1
fi
truncate -s "$vault_bytes" "$image"
if [[ "$(stat -c %s "$image")" != "$vault_bytes" ]] ||
  [[ "$(stat -c %b "$image")" != 0 ]]; then
  echo "failed to create the exact sparse disposable p3 image" >&2
  exit 1
fi
dd if=/dev/urandom of="$key_file" bs=64 count=1 status=none
dd if=/dev/urandom of="$wrong_key_file" bs=64 count=1 status=none
chmod 600 "$key_file"
chmod 600 "$wrong_key_file"
loop_device="$(losetup --find --show "$image")"
if [[ ! "$loop_device" =~ ^/dev/loop[0-9]+$ ]]; then
  echo "the disposable loop allocator returned an unexpected path" >&2
  exit 1
fi
associated_loop="$(losetup --associated "$image" --noheadings --output NAME | tr -d '[:space:]')"
if [[ "$associated_loop" != "$loop_device" ]] ||
  [[ "$(blockdev --getss "$loop_device")" != "$logical_sector_bytes" ]] ||
  [[ "$(blockdev --getsz "$loop_device")" != "$vault_sector_count" ]] ||
  [[ "$(blockdev --getsize64 "$loop_device")" != "$vault_bytes" ]]; then
  echo "the disposable loop does not bind the exact 8 GiB p3 geometry" >&2
  exit 1
fi

# Provisioning is intentionally confined to this disposable CI image. The
# production Rust manager exposes no format, erase, repair, or raw-write API.
cryptsetup luksFormat --type luks2 --batch-mode --label KERNAID_VAULT \
  --cipher aes-xts-plain64 --key-size 512 --hash sha256 --sector-size 512 \
  --pbkdf argon2id --pbkdf-force-iterations 4 --pbkdf-memory 65536 \
  --pbkdf-parallel 1 --key-slot 0 --keyslot-cipher aes-xts-plain64 \
  --keyslot-key-size 512 --luks2-metadata-size 16384 \
  --luks2-keyslots-size 16744448 --use-urandom \
  --key-file "$key_file" --keyfile-size 64 "$loop_device"
cryptsetup open --type luks2 --batch-mode --tries 1 \
  --disable-external-tokens --key-file "$key_file" --keyfile-size 64 \
  "$loop_device" "$provision_mapper"
provision_open=true
if [[ "$(blockdev --getss "/dev/mapper/$provision_mapper")" != "$logical_sector_bytes" ]] ||
  [[ "$(blockdev --getsz "/dev/mapper/$provision_mapper")" != "$payload_sector_count" ]] ||
  [[ "$(blockdev --getsize64 "/dev/mapper/$provision_mapper")" != "$payload_bytes" ]]; then
  echo "the disposable LUKS mapping does not expose the pinned payload geometry" >&2
  exit 1
fi
mkfs.ext4 -q -F -t ext4 -b 4096 -I 256 -i 16384 -g 32768 -G 16 \
  -m 0 -o linux -e remount-ro -J size=128 \
  -E lazy_itable_init=0,lazy_journal_init=0 \
  -O none,has_journal,ext_attr,resize_inode,dir_index,filetype,extent,64bit,flex_bg,sparse_super,large_file,huge_file,dir_nlink,extra_isize,metadata_csum \
  -L KERNAID_VAULT -M / "/dev/mapper/$provision_mapper"
tune2fs -c 0 -i 0 -e remount-ro -m 0 -o '^acl,^user_xattr' -M / \
  "/dev/mapper/$provision_mapper"
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

header_digest_before="$(
  dd if="$loop_device" bs="$luks_header_span_bytes" count=1 status=none | sha256sum
)"
header_digest_before="${header_digest_before%% *}"
if [[ ! "$header_digest_before" =~ ^[0-9a-f]{64}$ ]]; then
  echo "failed to fingerprint the disposable dual LUKS2 headers" >&2
  exit 1
fi

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

initialize_attestation="$(
  "$probe_binary" --device "$loop_device" --mapper "$manager_mapper" \
    --mode initialize <"$key_file"
)"
if [[ ! "$initialize_attestation" =~ ^KERNAID_RESCUE_VAULT_PROBE_ATTESTATION_V1\ mode=initialize\ journal_binding=device-identity-bound-v1\ identity_public_key=([0-9a-f]{64})\ clean_shutdown=true$ ]]; then
  echo "the initial real-profile attestation was not canonical" >&2
  exit 1
fi
identity_public_key="${BASH_REMATCH[1]}"
printf '%s\n' "$initialize_attestation"

verify_attestation="$(
  "$probe_binary" --device "$loop_device" --mapper "$manager_mapper" \
    --mode verify <"$key_file"
)"
if [[ ! "$verify_attestation" =~ ^KERNAID_RESCUE_VAULT_PROBE_ATTESTATION_V1\ mode=verify\ journal_binding=device-identity-bound-v1\ identity_public_key=([0-9a-f]{64})\ clean_shutdown=true$ ]] ||
  [[ "${BASH_REMATCH[1]:-}" != "$identity_public_key" ]]; then
  echo "the reopened real-profile attestation was not canonical and stable" >&2
  exit 1
fi
printf '%s\n' "$verify_attestation"

# Without --fork, unshare execs the probe in place and the shell retains the
# exact process PID whose death also releases the private mount namespace.
unshare --mount --propagation private -- \
  "$probe_binary" --device "$loop_device" --mapper "$manager_mapper" \
  --mode crash-cleanup <"$key_file" >"$crash_log" 2>&1 &
crash_pid="$!"
if [[ ! "$crash_pid" =~ ^[1-9][0-9]*$ ]]; then
  echo "the crash-cleanup probe did not expose a direct child PID" >&2
  exit 1
fi

crash_ready=false
for ((attempt = 0; attempt < 400; attempt += 1)); do
  if grep -Fxq \
    'KERNAID_RESCUE_VAULT_PROBE_CRASH_POINT_V1 mode=crash-cleanup unlock_complete=true cleanup=awaiting-sigkill' \
    "$crash_log"; then
    crash_ready=true
    break
  fi
  if ! kill -0 "$crash_pid" 2>/dev/null; then
    break
  fi
  sleep 0.05
done
if [[ "$crash_ready" != true ]]; then
  echo "the crash-cleanup probe did not prove a completed unlock" >&2
  exit 1
fi
if ! kill -KILL "$crash_pid" 2>/dev/null; then
  echo "the crash-cleanup probe exited before the owned SIGKILL" >&2
  exit 1
fi
crash_status=0
if wait "$crash_pid" >/dev/null 2>&1; then
  crash_status=0
else
  crash_status="$?"
fi
crash_pid=""
if [[ "$crash_status" -ne 137 ]]; then
  echo "the crash-cleanup probe did not terminate with owned SIGKILL status" >&2
  exit 1
fi

mapper_absent=false
for ((attempt = 0; attempt < 200; attempt += 1)); do
  if mapper_is_absent; then
    mapper_absent=true
    break
  fi
  sleep 0.05
done
if [[ "$mapper_absent" != true ]]; then
  echo "deferred removal did not release the crashed probe mapper" >&2
  exit 1
fi

post_crash_attestation="$(
  "$probe_binary" --device "$loop_device" --mapper "$manager_mapper" \
    --mode verify <"$key_file"
)"
if [[ ! "$post_crash_attestation" =~ ^KERNAID_RESCUE_VAULT_PROBE_ATTESTATION_V1\ mode=verify\ journal_binding=device-identity-bound-v1\ identity_public_key=([0-9a-f]{64})\ clean_shutdown=true$ ]] ||
  [[ "${BASH_REMATCH[1]:-}" != "$identity_public_key" ]]; then
  echo "the vault did not reopen canonically after crash cleanup" >&2
  exit 1
fi
printf '%s\n' "$post_crash_attestation"

if mountpoint -q "$manager_mount" || ! mapper_is_absent; then
  echo "the Rescue manager left a mount or mapping active" >&2
  exit 1
fi

header_digest_after="$(
  dd if="$loop_device" bs="$luks_header_span_bytes" count=1 status=none | sha256sum
)"
header_digest_after="${header_digest_after%% *}"
if [[ "$header_digest_after" != "$header_digest_before" ]]; then
  echo "the Rescue profile checks modified a disposable LUKS2 header" >&2
  exit 1
fi

echo "PASS: exact sparse 8 GiB p3 profile survived clean reopen and no-Drop crash cleanup without a residual mapper"
