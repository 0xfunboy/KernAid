#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

# This helper is intentionally host-only. It provisions exactly the p3 slice of
# one caller-owned disposable Repair medium, then asks the project's privileged
# descriptor-bound probe to initialize and verify the canonical Vault identity.
# It never receives a target image or a physical-device path.

readonly media_bytes=32000000000
readonly p3_start_bytes=17179869184
readonly p3_bytes=8589934592
readonly p3_zero_sha256=ebfb4ef19ae410f190327b5ebd312711263bc7579970e87d9c1e2d84e06b3c25
readonly probe_prefix=KERNAID_RESCUE_VAULT_PROBE_ATTESTATION_V1
readonly probe_failure_prefix=KERNAID_RESCUE_VAULT_PROBE_FAILURE_V1
readonly journal_binding=device-identity-bound-v1

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

if [[ "$EUID" -ne 0 || ! "${SUDO_UID:-}" =~ ^[1-9][0-9]*$ ]]; then
  echo "Repair Vault base provisioning requires sudo from an unprivileged caller" >&2
  exit 2
fi
if [[ "$#" -ne 6 || "$1" != --media || "$3" != --key || "$5" != --probe ]]; then
  echo "Usage: $0 --media FILE --key FILE --probe FILE" >&2
  exit 2
fi

media="$2"
key_file="$4"
probe_binary="$6"

for command in awk chmod chown cryptsetup dd dirname losetup mkdir mkfs.ext4 \
  mktemp mount mountpoint od readlink realpath rm rmdir sha256sum stat sync \
  tr tune2fs udevadm umount; do
  command -v "$command" >/dev/null || {
    echo "Missing required host provisioning command: $command" >&2
    exit 2
  }
done

resolved_media="$(realpath -e -- "$media")" || exit 2
resolved_key="$(realpath -e -- "$key_file")" || exit 2
resolved_probe="$(realpath -e -- "$probe_binary")" || exit 2
expected_probe="$(realpath -e -- "$repo_dir/target/release/kernaid-rescue-vault-probe")" \
  || exit 2
media_parent="$(dirname -- "$resolved_media")"

if [[ "$resolved_media" != "$media" || "$resolved_key" != "$key_file" \
  || "$resolved_probe" != "$probe_binary" || "$resolved_probe" != "$expected_probe" \
  || "$(dirname -- "$resolved_key")" != "$media_parent" \
  || "$(basename -- "$resolved_media")" != rescue-usb.raw \
  || "$(basename -- "$resolved_key")" != vault-key \
  || "$(dirname -- "$media_parent")" != /tmp \
  || ! "$(basename -- "$media_parent")" =~ ^kernaid-qemu-repair-candidate\.[A-Za-z0-9]{8}$ \
  || "$(stat -c '%u:%a' -- "$media_parent")" != "${SUDO_UID}:700" ]]; then
  echo "Repair Vault base inputs are outside the exact disposable boundary" >&2
  exit 2
fi

for input in "$resolved_media" "$resolved_key"; do
  if [[ ! -f "$input" || -L "$input" \
    || "$(stat -c '%u:%a:%h' -- "$input")" != "${SUDO_UID}:600:1" ]]; then
    echo "Repair Vault base input identity is unsafe" >&2
    exit 2
  fi
done
if [[ "$(stat -c '%s' -- "$resolved_media")" != "$media_bytes" \
  || "$(stat -c '%s' -- "$resolved_key")" != 64 \
  || "$(tr -d '0-9a-f' <"$resolved_key")" != "" ]]; then
  echo "Repair Vault base input content is outside the exact contract" >&2
  exit 2
fi
if [[ ! -f "$resolved_probe" || -L "$resolved_probe" || ! -x "$resolved_probe" \
  || "$(stat -c '%h' -- "$resolved_probe")" != 1 ]]; then
  echo "The project Vault probe identity is unsafe" >&2
  exit 2
fi
probe_mode="$(stat -c '%a' -- "$resolved_probe")"
if [[ ! "$probe_mode" =~ ^[0-7]{3,4}$ ]] \
  || (( (8#$probe_mode & 8#022) != 0 )); then
  echo "The project Vault probe is writable outside its owner" >&2
  exit 2
fi
if [[ -n "$(losetup -j "$resolved_media")" ]]; then
  echo "The disposable Repair medium already has a loop binding" >&2
  exit 2
fi

random_suffix="$(od -An -N8 -tx1 /dev/urandom | tr -d '[:space:]')"
[[ "$random_suffix" =~ ^[0-9a-f]{16}$ ]] || exit 1
provision_mapper="kernaid-repair-provision-$random_suffix"
manager_mapper="kernaid-vault-$random_suffix"
root_work="$(mktemp -d /run/kernaid-repair-host-vault.XXXXXXXX)"
provision_mount="$root_work/provision"
initialize_output="$root_work/probe-initialize.out"
initialize_error="$root_work/probe-initialize.err"
verify_output="$root_work/probe-verify.out"
verify_error="$root_work/probe-verify.err"
vault_loop=""
provision_open=false
provision_mounted=false

mapper_is_active() {
  cryptsetup status "$1" >/dev/null 2>&1
}

# shellcheck disable=SC2317,SC2329  # Called by the EXIT trap.
cleanup() {
  local result="$1"
  local cleanup_failed=false
  trap - EXIT INT TERM HUP
  set +e

  if [[ "$provision_mounted" == true ]] \
    || mountpoint -q "$provision_mount" 2>/dev/null; then
    umount "$provision_mount" || cleanup_failed=true
    provision_mounted=false
  fi
  if [[ "$provision_open" == true ]] || mapper_is_active "$provision_mapper"; then
    cryptsetup close "$provision_mapper" || cleanup_failed=true
    provision_open=false
  fi
  if mapper_is_active "$manager_mapper"; then
    cryptsetup close "$manager_mapper" || cleanup_failed=true
  fi
  if [[ -n "$vault_loop" ]]; then
    if [[ "$vault_loop" =~ ^/dev/loop[0-9]+$ ]]; then
      udevadm settle || cleanup_failed=true
      losetup -d "$vault_loop" || cleanup_failed=true
      vault_loop=""
    else
      cleanup_failed=true
    fi
  fi
  if [[ -n "$(losetup -j "$resolved_media" 2>/dev/null)" ]]; then
    cleanup_failed=true
  fi

  case "$root_work" in
    /run/kernaid-repair-host-vault.*)
      rm -f -- "$initialize_output" "$initialize_error" \
        "$verify_output" "$verify_error" || cleanup_failed=true
      rmdir -- "$provision_mount" 2>/dev/null || cleanup_failed=true
      rmdir -- "$root_work" 2>/dev/null || cleanup_failed=true
      ;;
    *) cleanup_failed=true ;;
  esac
  if [[ "$result" -eq 0 && "$cleanup_failed" == true ]]; then
    result=1
  fi
  exit "$result"
}
trap 'cleanup $?' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP

mkdir -- "$provision_mount"

p3_before_sha256="$(
  dd if="$resolved_media" bs=4M iflag=skip_bytes,count_bytes \
    skip="$p3_start_bytes" count="$p3_bytes" status=none \
    | sha256sum | awk 'NR == 1 { print $1 }'
)"
if [[ "$p3_before_sha256" != "$p3_zero_sha256" ]]; then
  echo "The exact disposable p3 slice is not zero before first write" >&2
  exit 1
fi

vault_loop="$(
  losetup --find --show --offset "$p3_start_bytes" \
    --sizelimit "$p3_bytes" -- "$resolved_media"
)"
if [[ ! "$vault_loop" =~ ^/dev/loop[0-9]+$ || ! -b "$vault_loop" ]]; then
  echo "The disposable p3 loop identity is invalid" >&2
  exit 1
fi
udevadm settle
observed_backing="$(losetup --noheadings --raw --output BACK-FILE -- "$vault_loop")"
observed_offset="$(
  losetup --noheadings --raw --output OFFSET -- "$vault_loop" \
    | tr -d '[:space:]'
)"
observed_limit="$(
  losetup --noheadings --raw --output SIZELIMIT -- "$vault_loop" \
    | tr -d '[:space:]'
)"
if [[ "$(readlink -f -- "$observed_backing")" != "$resolved_media" \
  || "$observed_offset" != "$p3_start_bytes" \
  || "$observed_limit" != "$p3_bytes" ]]; then
  echo "The loop does not bind the exact disposable p3 slice" >&2
  exit 1
fi

cryptsetup luksFormat --type luks2 --batch-mode --label KERNAID_VAULT \
  --cipher aes-xts-plain64 --key-size 512 --hash sha256 --sector-size 512 \
  --pbkdf argon2id --pbkdf-force-iterations 4 --pbkdf-memory 65536 \
  --pbkdf-parallel 1 --key-slot 0 --keyslot-cipher aes-xts-plain64 \
  --keyslot-key-size 512 --luks2-metadata-size 16384 \
  --luks2-keyslots-size 16744448 --use-urandom \
  --key-file "$resolved_key" --keyfile-size 64 "$vault_loop"
cryptsetup open --type luks2 --batch-mode --tries 1 \
  --disable-external-tokens --key-file "$resolved_key" --keyfile-size 64 \
  "$vault_loop" "$provision_mapper"
provision_open=true
udevadm settle
mkfs.ext4 -q -F -t ext4 -b 4096 -I 256 -i 16384 -g 32768 -G 16 \
  -m 0 -o linux -e remount-ro -J size=128 \
  -E lazy_itable_init=0,lazy_journal_init=0 \
  -O none,has_journal,ext_attr,resize_inode,dir_index,filetype,extent,64bit,flex_bg,sparse_super,large_file,huge_file,dir_nlink,extra_isize,metadata_csum \
  -L KERNAID_VAULT -M / "/dev/mapper/$provision_mapper"
tune2fs -c 0 -i 0 -e remount-ro -m 0 -o '^acl,^user_xattr' -M / \
  "/dev/mapper/$provision_mapper" >/dev/null
mount -t ext4 -o rw,nosuid,nodev,noexec,nosymfollow \
  "/dev/mapper/$provision_mapper" "$provision_mount"
provision_mounted=true
chmod 700 -- "$provision_mount"
printf 'KERNAID-RESCUE-VAULT-V1\n' >"$provision_mount/.kernaid-rescue-vault"
chmod 600 -- "$provision_mount/.kernaid-rescue-vault"
mkdir -- "$provision_mount/.kernaid-secure-state-v1"
chmod 700 -- "$provision_mount/.kernaid-secure-state-v1"
: >"$provision_mount/.kernaid-rescue-secrets.lock"
chmod 600 -- "$provision_mount/.kernaid-rescue-secrets.lock"
mkdir -- "$provision_mount/.kernaid-codex-home-v1"
chmod 700 -- "$provision_mount/.kernaid-codex-home-v1"
chown 973:973 -- "$provision_mount/.kernaid-codex-home-v1"
printf 'cli_auth_credentials_store = "file"\n' \
  >"$provision_mount/.kernaid-codex-home-v1/config.toml"
chmod 600 -- "$provision_mount/.kernaid-codex-home-v1/config.toml"
chown 973:973 -- "$provision_mount/.kernaid-codex-home-v1/config.toml"
if [[ "$(stat -c '%a:%u:%g' -- "$provision_mount/.kernaid-rescue-vault")" != "600:0:0" \
  || "$(stat -c '%a:%u:%g' -- "$provision_mount/.kernaid-rescue-secrets.lock")" != "600:0:0" \
  || "$(stat -c '%a:%u:%g' -- "$provision_mount/.kernaid-secure-state-v1")" != "700:0:0" \
  || "$(stat -c '%a:%u:%g' -- "$provision_mount/.kernaid-codex-home-v1")" != "700:973:973" \
  || "$(stat -c '%a:%u:%g:%s' -- "$provision_mount/.kernaid-codex-home-v1/config.toml")" != "600:973:973:36" ]]; then
  echo "The canonical Vault layout metadata is invalid" >&2
  exit 1
fi
sync
umount "$provision_mount"
provision_mounted=false
cryptsetup close "$provision_mapper"
provision_open=false

parse_probe_attestation() {
  local expected_mode="$1"
  local output_file="$2"
  local line output_bytes
  local -a lines

  output_bytes="$(stat -c '%s' -- "$output_file")"
  [[ "$output_bytes" =~ ^[0-9]+$ ]] && ((output_bytes <= 512)) || return 1
  mapfile -t lines <"$output_file"
  [[ "${#lines[@]}" -eq 1 ]] || return 1
  line="${lines[0]}"
  [[ "$line" =~ ^${probe_prefix}\ mode=(initialize|verify)\ journal_binding=(${journal_binding})\ identity_public_key=([0-9a-f]{64})\ clean_shutdown=true$ ]] \
    || return 1
  [[ "${BASH_REMATCH[1]}" == "$expected_mode" ]] || return 1
  probe_identity="${BASH_REMATCH[3]}"
}

run_probe() {
  local mode="$1"
  local output_file="$2"
  local error_file="$3"
  local error_line=""
  if ! "$resolved_probe" --device "$vault_loop" --mapper "$manager_mapper" \
    --mode "$mode" <"$resolved_key" >"$output_file" 2>"$error_file"; then
    if [[ "$(stat -c '%s' -- "$error_file")" =~ ^[0-9]+$ ]] \
      && (( $(stat -c '%s' -- "$error_file") <= 512 )); then
      IFS= read -r error_line <"$error_file" || true
    fi
    if [[ "$error_line" =~ ^${probe_failure_prefix}\ stage=[a-z0-9-]+\ code=[a-z0-9-]+$ ]]; then
      printf '%s\n' "$error_line" >&2
    else
      printf '%s\n' "$probe_failure_prefix stage=wrapper code=invalid-diagnostic" >&2
    fi
    return 1
  fi
  [[ ! -s "$error_file" ]] || return 1
  parse_probe_attestation "$mode" "$output_file"
  ! mapper_is_active "$manager_mapper"
}

run_probe initialize "$initialize_output" "$initialize_error"
initialize_identity="$probe_identity"
run_probe verify "$verify_output" "$verify_error"
verify_identity="$probe_identity"
if [[ "$initialize_identity" != "$verify_identity" ]]; then
  echo "The project probe observed an unstable Vault identity" >&2
  exit 1
fi

udevadm settle
losetup -d "$vault_loop"
vault_loop=""
udevadm settle
if [[ -n "$(losetup -j "$resolved_media")" ]]; then
  echo "The disposable Repair medium retained a loop binding" >&2
  exit 1
fi

p3_after_sha256="$(
  dd if="$resolved_media" bs=4M iflag=skip_bytes,count_bytes \
    skip="$p3_start_bytes" count="$p3_bytes" status=none \
    | sha256sum | awk 'NR == 1 { print $1 }'
)"
if [[ ! "$p3_after_sha256" =~ ^[0-9a-f]{64}$ \
  || "$p3_after_sha256" == "$p3_zero_sha256" ]]; then
  echo "The canonical Vault did not occupy the exact p3 slice" >&2
  exit 1
fi

printf '%s\n' \
  'KERNAID_REPAIR_HOST_VAULT_BASE_ATTESTATION_V1 geometry=layout-v1 p3=exact-zero-before-first-write profile=canonical-v1 probe=initialize-verify identity=stable key=private-mode-0600 cleanup=complete target_access=none host_physical_devices=false ready=true'
