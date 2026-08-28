#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
build_dir="$repo_dir/rescue/live-build"
vaultd_binary="${KERNAID_RESCUE_VAULTD_BINARY:-$repo_dir/target/release/kernaid-rescue-vaultd}"
firstboot_binary="${KERNAID_RESCUE_FIRSTBOOT_BINARY:-$repo_dir/target/release/kernaid-rescue-firstboot}"
codex_mounter_binary="${KERNAID_RESCUE_CODEX_MOUNTER_BINARY:-$repo_dir/target/release/kernaid-rescue-codex-mounter}"
vaultctl_binary="${KERNAID_RESCUE_VAULTCTL_BINARY:-$repo_dir/target/release/kernaid-rescue-vaultctl}"
openai_executor_binary="${KERNAID_RESCUE_OPENAI_EXECUTOR_BINARY:-$repo_dir/target/release/kernaid-rescue-openai-executor}"
hardware_inventory_binary="${KERNAID_LINUX_HARDWARE_INVENTORY_BINARY:-$repo_dir/target/release/kernaid-linux-hardware-inventory}"
hardware_inventory_destination="$build_dir/config/includes.chroot/usr/lib/kernaid/kernaid-linux-hardware-inventory"
codex_bridge_binary="${KERNAID_RESCUE_CODEX_BRIDGE_BINARY:-$repo_dir/target/release/kernaid-rescue-codex}"
codex_client_binary="${KERNAID_RESCUE_CODEX_CLIENT_BINARY:-$repo_dir/target/release/kernaid-codex-auth}"
codex_cli_binary="${KERNAID_RESCUE_CODEX_CLI_BINARY:-$repo_dir/target/rescue-codex-root/usr/lib/kernaid/codex}"
vaultd_destination="$build_dir/config/includes.chroot/usr/lib/kernaid/kernaid-rescue-vaultd"
firstboot_destination="$build_dir/config/includes.chroot/usr/lib/kernaid/kernaid-rescue-firstboot"
codex_mounter_destination="$build_dir/config/includes.chroot/usr/lib/kernaid/kernaid-rescue-codex-mounter"
vaultctl_destination="$build_dir/config/includes.chroot/usr/bin/kernaid-rescue-vaultctl"
openai_executor_destination="$build_dir/config/includes.chroot/usr/lib/kernaid/kernaid-rescue-openai-executor"
codex_bridge_destination="$build_dir/config/includes.chroot/usr/lib/kernaid/kernaid-rescue-codex"
codex_client_destination="$build_dir/config/includes.chroot/usr/bin/kernaid-codex-auth"
codex_cli_destination="$build_dir/config/includes.chroot/usr/lib/kernaid/codex"
desk_shell_binary="${KERNAID_RESCUE_DESK_SHELL_BINARY:-$repo_dir/target/release/kernaid-rescue-desk-shell}"
desk_shell_destination="$build_dir/config/includes.chroot/usr/bin/kernaid-rescue-desk-shell"
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
validate_amd64_elf "$firstboot_binary" "Rescue first-boot vault provisioner"
validate_amd64_elf "$codex_mounter_binary" "Rescue Codex mount broker"
validate_amd64_elf "$vaultctl_binary" "Rescue vault companion"
validate_amd64_elf "$openai_executor_binary" "Rescue OpenAI executor"
validate_amd64_elf "$hardware_inventory_binary" "Linux hardware inventory collector"
validate_amd64_elf "$codex_bridge_binary" "Rescue Codex bridge"
validate_amd64_elf "$codex_client_binary" "Rescue Codex client"
validate_amd64_elf "$desk_shell_binary" "Rescue Tauri Desk shell"

python3 -I - "$repo_dir/tools/build-rescue/verify-codex-cli.py" \
  "$repo_dir/rescue/codex/codex-cli.lock.json" "$codex_cli_binary" <<'PY'
import importlib.util
import os
from pathlib import Path
import sys

module_path, lock_path, binary_path = map(Path, sys.argv[1:])
spec = importlib.util.spec_from_file_location("kernaid_verify_codex_cli_for_build", module_path)
if spec is None or spec.loader is None:
    raise SystemExit("Codex verifier cannot be loaded")
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)
lock = verifier.load_lock(lock_path)
descriptor = verifier._open_exact_regular(binary_path, verifier.MAX_BINARY_BYTES)
try:
    verifier.verify_binary(descriptor, lock, require_root=True)
finally:
    os.close(descriptor)
PY

for destination in \
  "$vaultd_destination" \
  "$firstboot_destination" \
  "$codex_mounter_destination" \
  "$vaultctl_destination" \
  "$openai_executor_destination" \
  "$hardware_inventory_destination" \
  "$codex_bridge_destination" \
  "$codex_client_destination" \
  "$codex_cli_destination" \
  "$desk_shell_destination"; do
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
  rm -f -- \
    "$vaultd_destination" \
    "$firstboot_destination" \
    "$codex_mounter_destination" \
    "$vaultctl_destination" \
    "$openai_executor_destination" \
    "$hardware_inventory_destination" \
    "$codex_bridge_destination" \
    "$codex_client_destination" \
    "$codex_cli_destination" \
    "$desk_shell_destination"
  if [[ "$vaultctl_destination_dir_created" = "1" ]]; then
    rmdir -- "$vaultctl_destination_dir"
  fi
}
trap cleanup_staged_binaries EXIT

install -o root -g root -m 0755 "$vaultd_binary" "$vaultd_destination"
install -o root -g root -m 0755 "$firstboot_binary" "$firstboot_destination"
install -o root -g root -m 0755 "$codex_mounter_binary" "$codex_mounter_destination"
install -o root -g root -m 0755 "$vaultctl_binary" "$vaultctl_destination"
install -o root -g root -m 0755 "$openai_executor_binary" "$openai_executor_destination"
install -o root -g root -m 0755 "$hardware_inventory_binary" "$hardware_inventory_destination"
install -o root -g root -m 0755 "$codex_bridge_binary" "$codex_bridge_destination"
install -o root -g root -m 0755 "$codex_client_binary" "$codex_client_destination"
install -o root -g root -m 0755 "$codex_cli_binary" "$codex_cli_destination"
install -o root -g root -m 0755 "$desk_shell_binary" "$desk_shell_destination"
for destination in \
  "$vaultd_destination" \
  "$firstboot_destination" \
  "$codex_mounter_destination" \
  "$vaultctl_destination" \
  "$openai_executor_destination" \
  "$hardware_inventory_destination" \
  "$codex_bridge_destination" \
  "$codex_client_destination" \
  "$codex_cli_destination" \
  "$desk_shell_destination"; do
  test "$(stat -c '%u:%g:%a' "$destination")" = "0:0:755"
done
python3 -I "$repo_dir/tools/build-rescue/verify-shipping-binary.py" "$vaultd_destination"
python3 -I "$repo_dir/tools/build-rescue/verify-shipping-binary.py" "$firstboot_destination"
python3 -I "$repo_dir/tools/build-rescue/verify-shipping-binary.py" "$codex_mounter_destination"
python3 -I "$repo_dir/tools/build-rescue/verify-shipping-binary.py" "$vaultctl_destination"
python3 -I "$repo_dir/tools/build-rescue/verify-shipping-binary.py" "$openai_executor_destination"
python3 -I "$repo_dir/tools/build-rescue/verify-shipping-binary.py" "$hardware_inventory_destination"
python3 -I "$repo_dir/tools/build-rescue/verify-shipping-binary.py" "$codex_bridge_destination"
python3 -I "$repo_dir/tools/build-rescue/verify-shipping-binary.py" "$codex_client_destination"
python3 -I - "$repo_dir/tools/build-rescue/verify-codex-cli.py" \
  "$repo_dir/rescue/codex/codex-cli.lock.json" "$codex_cli_destination" <<'PY'
import importlib.util
import os
from pathlib import Path
import sys

module_path, lock_path, binary_path = map(Path, sys.argv[1:])
spec = importlib.util.spec_from_file_location("kernaid_verify_staged_codex_cli", module_path)
if spec is None or spec.loader is None:
    raise SystemExit("Codex verifier cannot be loaded")
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)
lock = verifier.load_lock(lock_path)
descriptor = verifier._open_exact_regular(binary_path, verifier.MAX_BINARY_BYTES)
try:
    verifier.verify_binary(descriptor, lock, require_root=True)
finally:
    os.close(descriptor)
PY
python3 -I "$repo_dir/tools/build-rescue/verify-shipping-binary.py" \
  --profile tauri-webkit "$desk_shell_destination"

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
# Keep Debian live-config from rewriting LightDM's pinned isolated autologin
# identity to the regular live user from username=kernaid.
lb config \
  --mode debian \
  --distribution trixie \
  --architectures amd64 \
  --binary-images iso-hybrid \
  --archive-areas "main contrib non-free-firmware" \
  --debian-installer none \
  --apt-recommends false \
  --bootappend-live "boot=live components noroot username=kernaid hostname=kernaid-rescue live-config.nox11autologin live-config.user-default-groups=audio,cdrom,dip,floppy,video,plugdev,netdev,powerdev,scanner,bluetooth,kernaid-vault,kernaid-codex-client systemd.swap=0 quiet loglevel=5 console=tty0 console=ttyS0,115200n8"
lb build

iso="$(find . -maxdepth 1 -name 'live-image-amd64*.hybrid.iso' -o -name 'live-image-amd64*.iso' | head -n 1)"
test -n "$iso"
python3 -I "$repo_dir/tools/build-rescue/finalize-device-layout.py" finalize \
  --manifest "$repo_dir/rescue/image-layout/device-layout.v1.json" \
  --image "$iso"
mv "$iso" "$repo_dir/KernAid-Rescue-amd64.iso"
cd "$repo_dir"
sha256sum KernAid-Rescue-amd64.iso > KernAid-Rescue-amd64.iso.sha256
