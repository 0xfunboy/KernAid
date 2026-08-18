#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
build_dir="$repo_dir/rescue/live-build"
vaultd_binary="${KERNAID_RESCUE_VAULTD_BINARY:-$repo_dir/target/release/kernaid-rescue-vaultd}"
vaultctl_binary="${KERNAID_RESCUE_VAULTCTL_BINARY:-$repo_dir/target/release/kernaid-rescue-vaultctl}"
openai_executor_binary="${KERNAID_RESCUE_OPENAI_EXECUTOR_BINARY:-$repo_dir/target/release/kernaid-rescue-openai-executor}"
vaultd_destination="$build_dir/config/includes.chroot/usr/lib/kernaid/kernaid-rescue-vaultd"
vaultctl_destination="$build_dir/config/includes.chroot/usr/bin/kernaid-rescue-vaultctl"
openai_executor_destination="$build_dir/config/includes.chroot/usr/lib/kernaid/kernaid-rescue-openai-executor"
vaultd_destination_dir="$(dirname "$vaultd_destination")"
vaultctl_destination_dir="$(dirname "$vaultctl_destination")"
vaultctl_destination_dir_created=0

for command in lb python3; do
  command -v "$command" >/dev/null || { echo "Missing required command: $command" >&2; exit 2; }
done

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run this script as root inside a disposable Debian build environment." >&2
  exit 2
fi

validate_amd64_elf() {
  local binary="$1"
  local label="$2"
  [[ -f "$binary" && ! -L "$binary" && -x "$binary" ]] || {
    echo "$label is missing, non-regular, symlinked, or not executable: $binary" >&2
    exit 2
  }
  python3 -I - "$binary" "$label" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
if not 0 < path.stat().st_size <= 128 * 1024 * 1024:
    raise SystemExit(f"{sys.argv[2]} size is outside the shipping policy")
with path.open("rb") as stream:
    header = stream.read(20)
if len(header) != 20 or header[:6] != b"\x7fELF\x02\x01" or int.from_bytes(header[18:20], "little") != 62:
    raise SystemExit(f"{sys.argv[2]} is not a little-endian ELF64 amd64 binary")
PY
}

validate_amd64_elf "$vaultd_binary" "Rescue vault daemon"
validate_amd64_elf "$vaultctl_binary" "Rescue vault companion"
validate_amd64_elf "$openai_executor_binary" "Rescue OpenAI executor"

for destination in "$vaultd_destination" "$vaultctl_destination" "$openai_executor_destination"; do
  if [[ -e "$destination" || -L "$destination" ]]; then
    echo "Refusing to overwrite a pre-existing staged Rescue binary: $destination" >&2
    exit 2
  fi
done

[[ -d "$vaultd_destination_dir" && ! -L "$vaultd_destination_dir" ]] || {
  echo "Rescue daemon staging directory is missing or unsafe" >&2
  exit 2
}
if [[ -e "$vaultctl_destination_dir" || -L "$vaultctl_destination_dir" ]]; then
  [[ -d "$vaultctl_destination_dir" && ! -L "$vaultctl_destination_dir" ]] || {
    echo "Rescue companion staging directory is unsafe" >&2
    exit 2
  }
else
  install -d -m 0755 "$vaultctl_destination_dir"
  vaultctl_destination_dir_created=1
fi

cleanup_staged_binaries() {
  rm -f -- "$vaultd_destination" "$vaultctl_destination" "$openai_executor_destination"
  if [[ "$vaultctl_destination_dir_created" = "1" ]]; then
    rmdir -- "$vaultctl_destination_dir"
  fi
}
trap cleanup_staged_binaries EXIT

install -o root -g root -m 0755 "$vaultd_binary" "$vaultd_destination"
install -o root -g root -m 0755 "$vaultctl_binary" "$vaultctl_destination"
install -o root -g root -m 0755 "$openai_executor_binary" "$openai_executor_destination"
test "$(stat -c '%u:%g:%a' "$vaultd_destination")" = "0:0:755"
test "$(stat -c '%u:%g:%a' "$vaultctl_destination")" = "0:0:755"
test "$(stat -c '%u:%g:%a' "$openai_executor_destination")" = "0:0:755"
python3 -I "$repo_dir/tools/build-rescue/verify-shipping-binary.py" "$vaultd_destination"
python3 -I "$repo_dir/tools/build-rescue/verify-shipping-binary.py" "$vaultctl_destination"
python3 -I "$repo_dir/tools/build-rescue/verify-shipping-binary.py" "$openai_executor_destination"

cd "$repo_dir"
if [[ "${KERNAID_DESK_PREBUILT:-0}" != "1" ]]; then
  command -v pnpm >/dev/null || { echo "Missing required command: pnpm" >&2; exit 2; }
  pnpm --filter @kernaid/desk build
fi
test -f apps/desk/dist/index.html || { echo "Desk production bundle is missing" >&2; exit 2; }

install -d "$build_dir/config/includes.chroot/opt/kernaid/desk"
rm -rf "$build_dir/config/includes.chroot/opt/kernaid/desk/assets"
install -m 0644 apps/desk/dist/index.html "$build_dir/config/includes.chroot/opt/kernaid/desk/index.html"
cp -a apps/desk/dist/assets "$build_dir/config/includes.chroot/opt/kernaid/desk/assets"

cd "$build_dir"
lb clean || true
lb config \
  --mode debian \
  --distribution trixie \
  --architectures amd64 \
  --binary-images iso-hybrid \
  --archive-areas "main contrib non-free-firmware" \
  --debian-installer none \
  --apt-recommends false \
  --bootappend-live "boot=live components noroot username=kernaid hostname=kernaid-rescue live-config.user-default-groups=audio,cdrom,dip,floppy,video,plugdev,netdev,powerdev,scanner,bluetooth,kernaid-vault systemd.swap=0 quiet loglevel=5 console=tty0 console=ttyS0,115200n8"
lb build

iso="$(find . -maxdepth 1 -name 'live-image-amd64*.hybrid.iso' -o -name 'live-image-amd64*.iso' | head -n 1)"
test -n "$iso"
python3 -I "$repo_dir/tools/build-rescue/finalize-device-layout.py" finalize \
  --manifest "$repo_dir/rescue/image-layout/device-layout.v1.json" \
  --image "$iso"
mv "$iso" "$repo_dir/KernAid-Rescue-amd64.iso"
cd "$repo_dir"
sha256sum KernAid-Rescue-amd64.iso > KernAid-Rescue-amd64.iso.sha256
