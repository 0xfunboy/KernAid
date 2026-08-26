#!/bin/bash
set -euo pipefail

umask 077
export LC_ALL=C
export PATH=/usr/sbin:/usr/bin:/sbin:/bin

for command in awk blkid cmp cryptsetup findmnt grep install losetup lsblk mkfs.ext4 mount python3 sha256sum stat truncate tune2fs udevadm umount wipefs; do
  command -v "$command" >/dev/null || {
    echo "Missing required command: $command" >&2
    exit 2
  }
done
if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run this privileged smoke only in a disposable root test environment." >&2
  exit 2
fi

tool_source_dir="$(cd "$(dirname "$0")/.." && pwd)"
repo_dir="$(cd "$tool_source_dir/../.." && pwd)"
test_dir=""
install_dir=""
backing=""
iso=""
loop_device=""
pass_fd=""
major_minor=""
device_size=""
disk_sequence=""
backing_device=""
backing_inode=""

cleanup() {
  local result="$?"
  local removable=true
  trap - EXIT
  set +e
  if [[ -n "$pass_fd" ]]; then
    exec {pass_fd}<&-
  fi
  if [[ -n "$loop_device" ]]; then
    if [[ ! "$loop_device" =~ ^/dev/loop[0-9]+$ ]]; then
      echo "Refusing cleanup of unexpected loop path: $loop_device" >&2
      result=1
      removable=false
    else
      observed_backing="$(losetup --json --output NAME,BACK-FILE "$loop_device" 2>/dev/null | \
        python3 -c 'import json,sys; d=json.load(sys.stdin); rows=d.get("loopdevices", []); print(rows[0].get("back-file", "") if len(rows)==1 else "")' 2>/dev/null)"
      read -r observed_major observed_size observed_sequence < <(
        lsblk --bytes --noheadings --nodeps --output MAJ:MIN,SIZE,DISK-SEQ "$loop_device" 2>/dev/null
      )
      read -r observed_backing_device observed_backing_inode < <(
        stat --format='%d %i' "$backing" 2>/dev/null
      )
      if [[ "$observed_backing" != "$backing" || \
        "$observed_major" != "$major_minor" || \
        "$observed_size" != "$device_size" || \
        "$observed_sequence" != "$disk_sequence" || \
        "$observed_backing_device" != "$backing_device" || \
        "$observed_backing_inode" != "$backing_inode" ]]; then
        echo "Loop identity changed; refusing detach and preserving its sparse backing." >&2
        result=1
        removable=false
      elif ! losetup -d "$loop_device"; then
        echo "Could not detach $loop_device; preserving its sparse backing." >&2
        result=1
        removable=false
      fi
    fi
  fi
  if [[ "$removable" == true ]]; then
    case "$test_dir" in
      /tmp/kernaid-disposable-v2-smoke.*) rm -rf -- "$test_dir" || result=1 ;;
      "") ;;
      *) echo "Refusing cleanup of unexpected test directory: $test_dir" >&2; result=1 ;;
    esac
  fi
  case "$install_dir" in
    /run/kernaid-make-device-v2-test.*) rm -rf -- "$install_dir" || result=1 ;;
    "") ;;
    *) echo "Refusing cleanup of unexpected install directory: $install_dir" >&2; result=1 ;;
  esac
  exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
trap 'exit 131' QUIT

test_dir="$(mktemp -d /tmp/kernaid-disposable-v2-smoke.XXXXXX)"
install_dir="$(mktemp -d /run/kernaid-make-device-v2-test.XXXXXX)"
backing="$test_dir/kernaid-disposable-v2-device.img"
iso="$test_dir/KernAid-Rescue-amd64.iso"

install -o root -g root -m 0755 "$tool_source_dir/make-device-v2.py" \
  "$install_dir/make-device-v2.py"
install -o root -g root -m 0644 \
  "$tool_source_dir/make_device_v2.py" \
  "$tool_source_dir/make-device.py" \
  "$tool_source_dir/catalog_v2.py" \
  "$install_dir/"
install -o root -g root -m 0644 \
  "$repo_dir/rescue/image-layout/device-layout.v1.json" \
  "$install_dir/device-layout.v1.json"
install -o root -g root -m 0644 \
  "$repo_dir/rescue/image-layout/vault-profile.v1.json" \
  "$install_dir/vault-profile.v1.json"
install -o root -g root -m 0644 \
  "$tool_source_dir/trusted-rescue-images.v2.json" \
  "$install_dir/trusted-rescue-images.v2.json"

truncate -s 8M "$iso"
python3 - "$iso" <<'PY'
import struct
import sys

path = sys.argv[1]
image_size = 8 * 1024 * 1024
mbr = bytearray(512)
mbr[446] = 0x80
mbr[450] = 0x17
mbr[454:458] = (1).to_bytes(4, "little")
mbr[458:462] = ((image_size // 512) - 1).to_bytes(4, "little")
p3 = 446 + 2 * 16
mbr[p3 + 4] = 0x83
mbr[p3 + 8:p3 + 12] = (33_554_432).to_bytes(4, "little")
mbr[p3 + 12:p3 + 16] = (16_777_216).to_bytes(4, "little")
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
catalog[28:30] = ((-sum(struct.unpack("<16H", catalog[:32]))) & 0xFFFF).to_bytes(2, "little")
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

checksum="$(sha256sum "$iso")"
checksum="${checksum%% *}"
iso_size="$(stat --format='%s' "$iso")"
exec {untrusted_fd}< <(printf 'catalog-untrusted-fixture')
set +e
"$install_dir/make-device-v2.py" \
  --iso "$iso" \
  --sha256 "$checksum" \
  --device /dev/kernaid-must-not-exist \
  --ci-disposable-loop-token catalog-untrusted-fixture \
  --ci-passphrase-fd "$untrusted_fd" \
  >"$test_dir/untrusted.stdout" 2>"$test_dir/untrusted.stderr"
untrusted_result="$?"
set -e
exec {untrusted_fd}<&-
if [[ "$untrusted_result" -ne 3 ]] || \
  ! grep -Fq 'not uniquely authorized' "$test_dir/untrusted.stderr"; then
  echo "Root-owned bundle did not reject an image absent from the shipping catalog" >&2
  exit 1
fi

python3 - "$install_dir/device-layout.v1.json" "$checksum" "$iso_size" \
  "$test_dir/trusted-rescue-images.v2.fixture.json" <<'PY'
import hashlib
import json
import sys

layout_path, digest, size, output = sys.argv[1:]
layout_raw = open(layout_path, "rb").read()
layout = json.loads(layout_raw)
bound_layout = {
    "schema": layout["schema"],
    "manifestSha256": hashlib.sha256(layout_raw).hexdigest(),
    "partitionTable": layout["partitionTable"],
    "logicalSectorBytes": layout["logicalSectorBytes"],
    "minimumMediaBytes": layout["minimumMediaBytes"],
    "minimumAdvertisedMediaBytes": layout["minimumAdvertisedMediaBytes"],
    "minimumAdvertisedMediaLabel": layout["minimumAdvertisedMediaLabel"],
    "vaultProfileVersion": layout["vaultProfileVersion"],
    "vaultProfileSha256": layout["vaultProfileSha256"],
    "vaultPartition": layout["vaultPartition"],
}

def usb(firmware, run_id, log_hash):
    return {
        "passed": True,
        "bootTransport": "usb-storage",
        "bootCount": 2,
        "targetZeroWritesVerified": True,
        "workflowRunId": run_id,
        "workflowRunUrl": f"https://github.com/0xfunboy/KernAid/actions/runs/{run_id}",
        "logSha256": log_hash,
    }

def vault(firmware, run_id, log_hash):
    return {
        "passed": True,
        "bootCount": 2,
        "luksVersion": 2,
        "luksLabel": "KERNAID_VAULT",
        "filesystem": "ext4",
        "filesystemLabel": "KERNAID_VAULT",
        "vaultProfileVersion": layout["vaultProfileVersion"],
        "vaultProfileSha256": layout["vaultProfileSha256"],
        "stableUuidsVerified": True,
        "journalIdentityBindingVerified": True,
        "identityVerified": True,
        "wrongKeyRejected": True,
        "workflowRunId": run_id,
        "workflowRunUrl": f"https://github.com/0xfunboy/KernAid/actions/runs/{run_id}",
        "logSha256": log_hash,
    }

bios_hash = "b" * 64
uefi_hash = "c" * 64
document = {
    "schema": "dev.kernaid.trusted-rescue-images.v2",
    "catalogRevision": 1,
    "images": [{
        "artifactName": "KernAid-Rescue-amd64.iso",
        "artifactVersion": "privileged-loop-fixture",
        "sha256": digest,
        "bytes": int(size),
        "deviceLayout": bound_layout,
        "qemuUsbBootAttestations": {
            "bios": usb("bios", 1001, bios_hash),
            "uefi": usb("uefi", 1002, uefi_hash),
        },
        "qemuVaultAttestations": {
            "bios": vault("bios", 1001, bios_hash),
            "uefi": vault("uefi", 1002, uefi_hash),
        },
    }],
}
with open(output, "x", encoding="utf-8") as target:
    json.dump(document, target, indent=2, sort_keys=True)
    target.write("\n")
PY
install -o root -g root -m 0644 \
  "$test_dir/trusted-rescue-images.v2.fixture.json" \
  "$install_dir/trusted-rescue-images.v2.json"

truncate -s 32000000000 "$backing"
chmod 0600 "$backing"
loop_device="$(
  losetup --find --show --nooverlap --partscan --sector-size 512 "$backing"
)"
[[ "$loop_device" =~ ^/dev/loop[0-9]+$ ]] || {
  echo "losetup returned an unexpected path" >&2
  exit 1
}
read -r major_minor device_size disk_sequence < <(
  lsblk --bytes --noheadings --nodeps --output MAJ:MIN,SIZE,DISK-SEQ "$loop_device"
)
[[ "$major_minor" =~ ^[0-9]+:[0-9]+$ && "$device_size" == 32000000000 && \
  "$disk_sequence" =~ ^[0-9]+$ ]] || {
  echo "Could not bind the exact 32,000,000,000-byte loop identity" >&2
  exit 1
}
read -r backing_device backing_inode < <(stat --format='%d %i' "$backing")
if [[ "$(<"/sys/dev/block/$major_minor/loop/partscan")" != "1" ]]; then
  echo "Disposable loop does not expose the required LO_FLAGS_PARTSCAN flag" >&2
  exit 1
fi
token="KERNAID_CI_DISPOSABLE_LOOP path=$loop_device majmin=$major_minor"
token+=" size=$device_size diskseq=$disk_sequence"
token+=" backing=$backing_device:$backing_inode"

exec {pass_fd}< <(python3 - <<'PY'
import base64
import os
secret = bytearray(os.urandom(48))
try:
    os.write(1, base64.urlsafe_b64encode(secret).rstrip(b"="))
finally:
    for index in range(len(secret)):
        secret[index] = 0
PY
)
"$install_dir/make-device-v2.py" \
  --iso "$iso" \
  --sha256 "$checksum" \
  --device "$loop_device" \
  --ci-disposable-loop-token "$token" \
  --ci-passphrase-fd "$pass_fd" \
  >"$test_dir/report.json"
exec {pass_fd}<&-
pass_fd=""

cmp --bytes="$iso_size" "$iso" "$loop_device"
p3_path="$(lsblk --noheadings --paths --raw --output PATH,PARTN "$loop_device" | awk '$2 == 3 {print $1}')"
[[ "$p3_path" =~ ^/dev/loop[0-9]+p3$ ]] || {
  echo "Could not resolve the exact loop p3 node" >&2
  exit 1
}
test "$(blkid --probe --output value --match-tag TYPE "$p3_path")" = crypto_LUKS
test "$(blkid --probe --output value --match-tag LABEL "$p3_path")" = KERNAID_VAULT
test "$(blkid --probe --output value --match-tag VERSION "$p3_path")" = 2
python3 - "$test_dir/report.json" "$loop_device" "$p3_path" <<'PY'
import json
import sys

report_path, loop_path, p3_path = sys.argv[1:]
with open(report_path, "r", encoding="utf-8") as source:
    report = json.load(source)
assert report["schema"] == "dev.kernaid.make-device-report.v2"
assert report["status"] == "verified"
assert report["mode"] == "ci-disposable-loop"
assert report["target"]["path"] == loop_path
assert report["target"]["capacityBytes"] == 32_000_000_000
assert report["vaultPartition"]["path"] == p3_path
assert report["vaultPartition"]["startLba"] == 33_554_432
assert report["vaultPartition"]["sectorCount"] == 16_777_216
assert report["vault"]["luksVersion"] == 2
assert report["vault"]["luksLabel"] == "KERNAID_VAULT"
assert report["vault"]["filesystem"] == "ext4"
assert report["vault"]["filesystemLabel"] == "KERNAID_VAULT"
assert report["vault"]["vaultProfileVersion"] == 1
assert report["vault"]["vaultProfileSha256"] == "b4801359bd4f31ce67fbd3ec15b6c81c44aa6759ba43b2a4e099a7dfcc25a37c"
assert report["vault"]["wrongKeyRejected"] is True
assert report["vault"]["reopenedAndVerified"] is True
assert report["vault"]["mapperClosed"] is True
assert report["vault"]["unmounted"] is True
assert len(report["vault"]["deviceIdentityEnvelopeSha256"]) == 64
assert report["mediaPolicy"]["blankOrUnrecognizedTailProvesFreshMedia"] is False
assert report["mediaPolicy"]["technicalFreshnessVerified"] is False
assert report["mediaPolicy"]["operatorFreshMediaAttestationApplicable"] is False
assert report["mediaPolicy"]["operatorFreshMediaAttestation"] is False
assert report["mediaPolicy"]["ciDisposableLoopPolicy"] == "private-token-bound-test-fixture"
assert report["mediaPolicy"]["authenticatedRecoveryOrReprovisionImplemented"] is False
PY

if findmnt --noheadings --source "$p3_path" | grep -q .; then
  echo "Writer left the vault partition mounted" >&2
  exit 1
fi
if grep -R -x -l 'kernaid-vault-[0-9a-f]\{16\}' /sys/class/block/dm-*/dm/name 2>/dev/null | grep -q .; then
  echo "Writer left a KernAid mapper active" >&2
  exit 1
fi
if findmnt --raw --noheadings --output TARGET | grep -Eq '^/run/kernaid-make-device-v2\.'; then
  echo "Writer left a temporary KernAid mount active" >&2
  exit 1
fi
shopt -s nullglob
residual_mount_directories=(/run/kernaid-make-device-v2.*)
shopt -u nullglob
if (( ${#residual_mount_directories[@]} != 0 )); then
  echo "Writer left a temporary KernAid mount directory" >&2
  exit 1
fi

echo "PASS: catalog-v2 loop media was written, provisioned, reopened, verified, and cleaned"
