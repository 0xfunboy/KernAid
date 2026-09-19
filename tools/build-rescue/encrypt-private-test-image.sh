#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ ( "$#" -ne 2 && "$#" -ne 3 ) || -z "${KERNAID_TEST_ISO_PASSPHRASE:-}" \
  || ( "$#" -eq 3 && "$3" != "--diagnostics" ) ]]; then
  echo "Usage: KERNAID_TEST_ISO_PASSPHRASE=<secret> bash $0 ISO OUTPUT.tar.gpg [--diagnostics]" >&2
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
  rm -f -- "$work_dir/image.tar.gpg" "$work_dir/private-test-status.txt" \
    "$work_dir/rescue-smoke-bios.log" "$work_dir/rescue-smoke-uefi.log" \
    "$work_dir/rescue-usb-smoke-bios.log" "$work_dir/rescue-usb-smoke-uefi.log"
  rm -rf -- "$work_dir/gnupg"
  rmdir -- "$work_dir"
}
trap cleanup EXIT
install -d -m 0700 "$work_dir/gnupg"
tar_inputs=(-C "$iso_dir" "$iso_name" "$iso_name.sha256")
if [[ "${3:-}" = "--diagnostics" ]]; then
  {
    printf '%s\n' 'PRIVATE TESTING DIAGNOSTIC BUNDLE; NOT A QUALIFIED RELEASE' \
      'qualified=false' 'log_policy=last-8388608-bytes-per-fixed-log'
    printf 'source_commit=%s\nrun_id=%s\n' "${GITHUB_SHA:-local}" "${GITHUB_RUN_ID:-local}"
    for gate in BUILD REPAIR_SURFACE BIOS UEFI SNAPSHOT USB_BIOS USB_UEFI; do
      outcome_variable="KERNAID_PRIVATE_${gate}_OUTCOME"
      outcome="${!outcome_variable:-unknown}"
      case "$outcome" in
        success|failure|skipped|cancelled|unknown) ;;
        *) echo "Private testing gate outcome is invalid" >&2; exit 2 ;;
      esac
      printf '%s=%s\n' "$gate" "$outcome"
    done
  } >"$work_dir/private-test-status.txt"
  tar_inputs+=(-C "$work_dir" private-test-status.txt)
  for log_name in rescue-smoke-bios.log rescue-smoke-uefi.log \
    rescue-usb-smoke-bios.log rescue-usb-smoke-uefi.log; do
    log_input="$iso_dir/$log_name"
    if [[ -f "$log_input" && ! -L "$log_input" ]]; then
      tail -c 8388608 -- "$log_input" >"$work_dir/$log_name"
      tar_inputs+=("$log_name")
    fi
  done
fi
private_passphrase="$KERNAID_TEST_ISO_PASSPHRASE"
unset KERNAID_TEST_ISO_PASSPHRASE
tar -cf - "${tar_inputs[@]}" | gpg --no-options \
  --homedir "$work_dir/gnupg" --batch --pinentry-mode loopback \
  --passphrase-fd 3 --no-symkey-cache --symmetric --cipher-algo AES256 \
  --compress-algo none --output "$work_dir/image.tar.gpg" \
  3< <(printf '%s\n' "$private_passphrase")
unset private_passphrase
# Exclusive creation also prevents overwriting an output introduced mid-build.
ln -- "$work_dir/image.tar.gpg" "$output"
test -s "$output"
test "$(stat -c '%a' "$output")" = 600
