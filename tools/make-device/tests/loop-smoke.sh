#!/bin/bash
set -euo pipefail

umask 077
export LC_ALL=C
export PATH=/usr/sbin:/usr/bin:/sbin:/bin

for command in cmp dd install losetup lsblk sha256sum stat truncate python3; do
  command -v "$command" >/dev/null || {
    echo "Missing required command: $command" >&2
    exit 2
  }
done
if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run this optional test as root in a disposable test environment." >&2
  exit 2
fi

tool_source_dir="$(cd "$(dirname "$0")/.." && pwd)"
test_dir=""
install_dir=""
backing=""
iso=""
loop_device=""

cleanup() {
  local result="$?"
  local directory_removable=true
  trap - EXIT
  set +e
  if [[ -n "$loop_device" ]]; then
    if [[ ! "$loop_device" =~ ^/dev/loop[0-9]+$ ]]; then
      echo "Refusing cleanup of an unexpected loop path: $loop_device" >&2
      result=1
      directory_removable=false
    elif ! losetup -d "$loop_device"; then
      echo "Could not detach $loop_device; preserving its backing file." >&2
      result=1
      directory_removable=false
    fi
  fi
  if [[ "$directory_removable" == true ]]; then
    case "$test_dir" in
      /tmp/kernaid-disposable-loop-smoke.*) rm -rf -- "$test_dir" || result=1 ;;
      "") ;;
      *)
        echo "Refusing cleanup of unexpected directory: $test_dir" >&2
        result=1
        ;;
    esac
  else
    echo "Preserved disposable test directory: $test_dir" >&2
  fi
  case "$install_dir" in
    /run/kernaid-make-device-test.*) rm -rf -- "$install_dir" || result=1 ;;
    "") ;;
    *)
      echo "Refusing cleanup of unexpected install directory: $install_dir" >&2
      result=1
      ;;
  esac
  exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
trap 'exit 131' QUIT

test_dir="$(mktemp -d /tmp/kernaid-disposable-loop-smoke.XXXXXX)"
install_dir="$(mktemp -d /run/kernaid-make-device-test.XXXXXX)"
backing="$test_dir/kernaid-disposable-device.img"
iso="$test_dir/rescue.iso"
install -o root -g root -m 0755 "$tool_source_dir/make-device.py" \
  "$install_dir/make-device.py"
install -o root -g root -m 0644 "$tool_source_dir/trusted-rescue-images.v1.json" \
  "$install_dir/trusted-rescue-images.v1.json"

truncate -s 64M "$backing"
truncate -s 8M "$iso"
python3 - "$iso" <<'PY'
import struct
import sys

path = sys.argv[1]
image_size = 8 * 1024 * 1024
mbr = bytearray(512)
mbr[446] = 0x80
mbr[450] = 0x17
mbr[458:462] = (image_size // 512).to_bytes(4, "little")
mbr[510:512] = b"\x55\xaa"

primary = bytearray(2048)
primary[0] = 1
primary[1:6] = b"CD001"
primary[6] = 1

boot_record = bytearray(2048)
boot_record[0] = 0
boot_record[1:6] = b"CD001"
boot_record[6] = 1
boot_record[7:39] = b"EL TORITO SPECIFICATION".ljust(32, b" ")
boot_record[71:75] = (20).to_bytes(4, "little")

terminator = bytearray(2048)
terminator[0] = 255
terminator[1:6] = b"CD001"
terminator[6] = 1

catalog = bytearray(2048)
catalog[0] = 1
catalog[30:32] = b"\x55\xaa"
catalog[28:30] = ((-sum(struct.unpack("<16H", catalog[:32]))) & 0xFFFF).to_bytes(
    2, "little"
)
catalog[32] = 0x88
catalog[38:40] = (4).to_bytes(2, "little")
catalog[40:44] = (24).to_bytes(4, "little")
catalog[64] = 0x91
catalog[65] = 0xEF
catalog[66:68] = (1).to_bytes(2, "little")
catalog[96] = 0x88
catalog[102:104] = (4).to_bytes(2, "little")
catalog[104:108] = (26).to_bytes(4, "little")

with open(path, "r+b", buffering=0) as image:
    image.seek(0)
    image.write(mbr)
    image.seek(16 * 2048)
    image.write(primary)
    image.seek(17 * 2048)
    image.write(boot_record)
    image.seek(18 * 2048)
    image.write(terminator)
    image.seek(20 * 2048)
    image.write(catalog)
    image.seek(24 * 2048)
    image.write(b"B" * 2048)
    image.seek(26 * 2048)
    image.write(b"U" * 2048)
PY
loop_device="$(losetup --find --show "$backing")"
[[ "$loop_device" =~ ^/dev/loop[0-9]+$ ]] || {
  echo "losetup returned an unexpected device path" >&2
  exit 1
}

read -r major_minor device_size disk_sequence < <(
  lsblk --bytes --noheadings --nodeps --output MAJ:MIN,SIZE,DISK-SEQ "$loop_device"
)
[[ "$major_minor" =~ ^[0-9]+:[0-9]+$ && "$device_size" =~ ^[0-9]+$ && \
  "$disk_sequence" =~ ^[0-9]+$ ]] || {
  echo "Could not resolve loop identity with lsblk" >&2
  exit 1
}
read -r backing_device backing_inode < <(stat --format='%d %i' "$backing")
checksum="$(sha256sum "$iso")"
checksum="${checksum%% *}"
iso_size="$(stat --format='%s' "$iso")"
token="KERNAID_CI_DISPOSABLE_LOOP path=$loop_device majmin=$major_minor"
token+=" size=$device_size diskseq=$disk_sequence"
token+=" backing=$backing_device:$backing_inode"
fixture_token="KERNAID_CI_FIXTURE_IMAGE sha256=$checksum bytes=$iso_size boot=bios+uefi"

"$install_dir/make-device.py" \
  --iso "$iso" \
  --sha256 "$checksum" \
  --device "$loop_device" \
  --ci-disposable-loop-token "$token" \
  --ci-fixture-image-token "$fixture_token"

cmp --bytes="$iso_size" "$iso" "$loop_device"
