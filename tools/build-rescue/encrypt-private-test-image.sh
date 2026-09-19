#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ "$#" -ne 2 || -z "${KERNAID_TEST_ISO_PASSPHRASE:-}" ]]; then
  echo "Usage: KERNAID_TEST_ISO_PASSPHRASE=<secret> bash $0 ISO OUTPUT.tar.gpg" >&2
  exit 2
fi
iso="$1"
output="$2"
checksum="$iso.sha256"
for input in "$iso" "$checksum"; do
  [[ -f "$input" && ! -L "$input" && -s "$input" ]] || {
    echo "Private testing image input must be a nonempty regular file" >&2
    exit 2
  }
done
[[ "$output" = *-PRIVATE-testing.tar.gpg && ! -e "$output" && ! -L "$output" ]] || {
  echo "Encrypted output must be a new PRIVATE-testing.tar.gpg path" >&2
  exit 2
}
iso_dir="$(cd "$(dirname "$iso")" && pwd)"
iso_name="$(basename "$iso")"
[[ "$iso_name" = "KernAid-Rescue-amd64.iso" ]] || {
  echo "Private testing input must use the standard Rescue ISO filename" >&2
  exit 2
}
(
  cd "$iso_dir"
  sha256sum --check --strict "$iso_name.sha256"
)

# Keep the encrypted temporary file on the output filesystem so publication
# can use an exclusive hard link without duplicating the image's disk usage.
work_dir="$(mktemp -d "$(dirname "$output")/kernaid-private-iso.XXXXXXXX")"
cleanup() {
  rm -f -- "$work_dir/image.tar.gpg"
  rm -rf -- "$work_dir/gnupg"
  rmdir -- "$work_dir"
}
trap cleanup EXIT
install -d -m 0700 "$work_dir/gnupg"
private_passphrase="$KERNAID_TEST_ISO_PASSPHRASE"
unset KERNAID_TEST_ISO_PASSPHRASE
tar -C "$iso_dir" -cf - -- "$iso_name" "$iso_name.sha256" | gpg --no-options \
  --homedir "$work_dir/gnupg" --batch --pinentry-mode loopback \
  --passphrase-fd 3 --no-symkey-cache --symmetric --cipher-algo AES256 \
  --compress-algo none --output "$work_dir/image.tar.gpg" \
  3< <(printf '%s\n' "$private_passphrase")
unset private_passphrase
# Exclusive creation also prevents overwriting an output introduced mid-build.
ln -- "$work_dir/image.tar.gpg" "$output"
test -s "$output"
test "$(stat -c '%a' "$output")" = 600
