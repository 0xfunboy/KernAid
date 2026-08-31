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
storage_health_binary="${KERNAID_LINUX_STORAGE_HEALTH_BINARY:-$repo_dir/target/release/kernaid-linux-storage-health}"
storage_health_destination="$build_dir/config/includes.chroot/usr/lib/kernaid/kernaid-linux-storage-health"
filesystem_health_binary="${KERNAID_LINUX_FILESYSTEM_HEALTH_BINARY:-$repo_dir/target/release/kernaid-linux-filesystem-health}"
filesystem_health_destination="$build_dir/config/includes.chroot/usr/lib/kernaid/kernaid-linux-filesystem-health"
boot_critical_path_binary="${KERNAID_LINUX_BOOT_CRITICAL_PATH_BINARY:-$repo_dir/target/release/kernaid-linux-boot-critical-path}"
boot_critical_path_destination="$build_dir/config/includes.chroot/usr/lib/kernaid/kernaid-linux-boot-critical-path"
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
repair_candidate="${KERNAID_REPAIR_CANDIDATE-0}"
repaird_binary="${KERNAID_RESCUE_REPAIRD_BINARY:-$repo_dir/target/release/kernaid-rescue-repaird}"
repaird_destination="$build_dir/config/includes.chroot/usr/lib/kernaid/kernaid-rescue-repaird"
blockfd_probe_binary="${KERNAID_BLOCKFD_PROBE_BINARY:-$repo_dir/target/release/kernaid-blockfd-probe}"
blockfd_probe_destination="$build_dir/config/includes.chroot/usr/lib/kernaid/kernaid-blockfd-probe"
repair_candidate_source="$build_dir/candidate"
repair_candidate_marker_source="$repair_candidate_source/repair-candidate-image-v1"
repair_candidate_marker_destination="$build_dir/config/includes.chroot/usr/lib/kernaid/repair-candidate-image-v1"
repair_service_source="$repair_candidate_source/kernaid-rescue-repaird.service"
repair_service_destination="$build_dir/config/includes.chroot/etc/systemd/system/kernaid-rescue-repaird.service"
repair_socket_source="$repair_candidate_source/kernaid-rescue-repaird.socket"
repair_socket_destination="$build_dir/config/includes.chroot/etc/systemd/system/kernaid-rescue-repaird.socket"
repair_sysusers_source="$repair_candidate_source/kernaid-repair-candidate.conf"
repair_sysusers_destination="$build_dir/config/includes.chroot/etc/sysusers.d/kernaid-repair-candidate.conf"
repair_tmpfiles_source="$repair_candidate_source/kernaid-repair-candidate.tmpfiles.conf"
repair_tmpfiles_destination="$build_dir/config/includes.chroot/usr/lib/tmpfiles.d/kernaid-repair-candidate.conf"
repair_ui_dropin_source="$repair_candidate_source/50-kernaid-repair-candidate.conf"
repair_ui_dropin_dir="$build_dir/config/includes.chroot/etc/systemd/system/kernaid-ui.service.d"
repair_ui_dropin_destination="$repair_ui_dropin_dir/50-kernaid-repair-candidate.conf"
repair_ready_dropin_source="$repair_candidate_source/50-kernaid-repair-candidate-ready.conf"
repair_ready_dropin_dir="$build_dir/config/includes.chroot/etc/systemd/system/kernaid-ready.service.d"
repair_ready_dropin_destination="$repair_ready_dropin_dir/50-kernaid-repair-candidate.conf"
vaultd_destination_dir="$(dirname "$vaultd_destination")"
vaultctl_destination_dir="$(dirname "$vaultctl_destination")"
vaultctl_destination_dir_created=0
repair_ui_dropin_dir_created=0
repair_ready_dropin_dir_created=0

case "$repair_candidate" in
  0|1) ;;
  *)
    echo "KERNAID_REPAIR_CANDIDATE must be exactly 0 or 1" >&2
    exit 2
    ;;
esac
repair_surface_mode=stable
if [[ "$repair_candidate" = "1" ]]; then
  repair_surface_mode=candidate
fi

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
validate_amd64_elf "$storage_health_binary" "Linux storage health collector"
validate_amd64_elf "$filesystem_health_binary" "Linux filesystem health collector"
validate_amd64_elf "$boot_critical_path_binary" "Linux boot critical path collector"
validate_amd64_elf "$codex_bridge_binary" "Rescue Codex bridge"
validate_amd64_elf "$codex_client_binary" "Rescue Codex client"
validate_amd64_elf "$desk_shell_binary" "Rescue Tauri Desk shell"
if [[ "$repair_candidate" = "1" ]]; then
  validate_amd64_elf "$repaird_binary" "Rescue fstab repair candidate broker"
  validate_amd64_elf "$blockfd_probe_binary" "Rescue block descriptor probe"
fi

if [[ "$repair_candidate" = "1" ]]; then
  for candidate_source in \
    "$repair_candidate_marker_source" \
    "$repair_service_source" \
    "$repair_socket_source" \
    "$repair_sysusers_source" \
    "$repair_tmpfiles_source" \
    "$repair_ui_dropin_source" \
    "$repair_ready_dropin_source"; do
    [[ -f "$candidate_source" && ! -L "$candidate_source" ]] || {
      echo "Rescue repair candidate packaging source is missing or unsafe: $candidate_source" >&2
      exit 2
    }
  done
fi

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
  "$storage_health_destination" \
  "$filesystem_health_destination" \
  "$boot_critical_path_destination" \
  "$codex_bridge_destination" \
  "$codex_client_destination" \
  "$codex_cli_destination" \
  "$desk_shell_destination" \
  "$repaird_destination" \
  "$blockfd_probe_destination" \
  "$repair_candidate_marker_destination" \
  "$repair_service_destination" \
  "$repair_socket_destination" \
  "$repair_sysusers_destination" \
  "$repair_tmpfiles_destination" \
  "$repair_ui_dropin_destination" \
  "$repair_ready_dropin_destination"; do
  if [[ -e "$destination" || -L "$destination" ]]; then
    echo "Refusing to overwrite a pre-existing staged Rescue binary: $destination" >&2
    exit 2
  fi
done

cleanup_staged_binaries() {
  rm -f -- \
    "$vaultd_destination" \
    "$firstboot_destination" \
    "$codex_mounter_destination" \
    "$vaultctl_destination" \
    "$openai_executor_destination" \
    "$hardware_inventory_destination" \
    "$storage_health_destination" \
    "$filesystem_health_destination" \
    "$boot_critical_path_destination" \
    "$codex_bridge_destination" \
    "$codex_client_destination" \
    "$codex_cli_destination" \
    "$desk_shell_destination" \
    "$repaird_destination" \
    "$blockfd_probe_destination" \
    "$repair_candidate_marker_destination" \
    "$repair_service_destination" \
    "$repair_socket_destination" \
    "$repair_sysusers_destination" \
    "$repair_tmpfiles_destination" \
    "$repair_ui_dropin_destination" \
    "$repair_ready_dropin_destination"
  if [[ "$vaultctl_destination_dir_created" = "1" ]]; then
    rmdir -- "$vaultctl_destination_dir"
  fi
  if [[ "$repair_ui_dropin_dir_created" = "1" ]]; then
    rmdir -- "$repair_ui_dropin_dir"
  fi
  if [[ "$repair_ready_dropin_dir_created" = "1" ]]; then
    rmdir -- "$repair_ready_dropin_dir"
  fi
}
trap cleanup_staged_binaries EXIT

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
if [[ "$repair_candidate" = "1" ]]; then
  if [[ -e "$repair_ui_dropin_dir" || -L "$repair_ui_dropin_dir" ]]; then
    [[ -d "$repair_ui_dropin_dir" && ! -L "$repair_ui_dropin_dir" ]] || {
      echo "Rescue repair UI drop-in staging directory is unsafe" >&2
      exit 2
    }
  else
    install -d -m 0755 "$repair_ui_dropin_dir"
    repair_ui_dropin_dir_created=1
  fi
  if [[ -e "$repair_ready_dropin_dir" || -L "$repair_ready_dropin_dir" ]]; then
    [[ -d "$repair_ready_dropin_dir" && ! -L "$repair_ready_dropin_dir" ]] || {
      echo "Rescue repair readiness drop-in staging directory is unsafe" >&2
      exit 2
    }
  else
    install -d -m 0755 "$repair_ready_dropin_dir"
    repair_ready_dropin_dir_created=1
  fi
fi

install -o root -g root -m 0755 "$vaultd_binary" "$vaultd_destination"
install -o root -g root -m 0755 "$firstboot_binary" "$firstboot_destination"
install -o root -g root -m 0755 "$codex_mounter_binary" "$codex_mounter_destination"
install -o root -g root -m 0755 "$vaultctl_binary" "$vaultctl_destination"
install -o root -g root -m 0755 "$openai_executor_binary" "$openai_executor_destination"
install -o root -g root -m 0755 "$hardware_inventory_binary" "$hardware_inventory_destination"
install -o root -g root -m 0755 "$storage_health_binary" "$storage_health_destination"
install -o root -g root -m 0755 "$filesystem_health_binary" "$filesystem_health_destination"
install -o root -g root -m 0755 "$boot_critical_path_binary" "$boot_critical_path_destination"
install -o root -g root -m 0755 "$codex_bridge_binary" "$codex_bridge_destination"
install -o root -g root -m 0755 "$codex_client_binary" "$codex_client_destination"
install -o root -g root -m 0755 "$codex_cli_binary" "$codex_cli_destination"
install -o root -g root -m 0755 "$desk_shell_binary" "$desk_shell_destination"
if [[ "$repair_candidate" = "1" ]]; then
  install -o root -g root -m 0755 "$repaird_binary" "$repaird_destination"
  install -o root -g root -m 0755 \
    "$blockfd_probe_binary" "$blockfd_probe_destination"
  install -o root -g root -m 0644 \
    "$repair_candidate_marker_source" "$repair_candidate_marker_destination"
  install -o root -g root -m 0644 \
    "$repair_service_source" "$repair_service_destination"
  install -o root -g root -m 0644 \
    "$repair_socket_source" "$repair_socket_destination"
  install -o root -g root -m 0644 \
    "$repair_sysusers_source" "$repair_sysusers_destination"
  install -o root -g root -m 0644 \
    "$repair_tmpfiles_source" "$repair_tmpfiles_destination"
  install -o root -g root -m 0644 \
    "$repair_ui_dropin_source" "$repair_ui_dropin_destination"
  install -o root -g root -m 0644 \
    "$repair_ready_dropin_source" "$repair_ready_dropin_destination"
fi
for destination in \
  "$vaultd_destination" \
  "$firstboot_destination" \
  "$codex_mounter_destination" \
  "$vaultctl_destination" \
  "$openai_executor_destination" \
  "$hardware_inventory_destination" \
  "$storage_health_destination" \
  "$filesystem_health_destination" \
  "$boot_critical_path_destination" \
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
python3 -I "$repo_dir/tools/build-rescue/verify-shipping-binary.py" "$storage_health_destination"
python3 -I "$repo_dir/tools/build-rescue/verify-shipping-binary.py" "$filesystem_health_destination"
python3 -I "$repo_dir/tools/build-rescue/verify-shipping-binary.py" "$boot_critical_path_destination"
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
if [[ "$repair_candidate" = "1" ]]; then
  test "$(stat -c '%u:%g:%a' "$repaird_destination")" = "0:0:755"
  test "$(stat -c '%u:%g:%a' "$blockfd_probe_destination")" = "0:0:755"
  for candidate_configuration in \
    "$repair_candidate_marker_destination" \
    "$repair_service_destination" \
    "$repair_socket_destination" \
    "$repair_sysusers_destination" \
    "$repair_tmpfiles_destination" \
    "$repair_ui_dropin_destination" \
    "$repair_ready_dropin_destination"; do
    test "$(stat -c '%u:%g:%a' "$candidate_configuration")" = "0:0:644"
  done
  python3 -I "$repo_dir/tools/build-rescue/verify-shipping-binary.py" \
    "$repaird_destination"
  python3 -I "$repo_dir/tools/build-rescue/verify-shipping-binary.py" \
    "$blockfd_probe_destination"
fi

cd "$repo_dir"
if [[ "${KERNAID_DESK_PREBUILT:-0}" != "1" ]]; then
  command -v pnpm >/dev/null || { echo "Missing required command: pnpm" >&2; exit 2; }
  pnpm --filter @kernaid/desk build
fi
test -f apps/desk/dist/index.html || { echo "Desk production bundle is missing" >&2; exit 2; }
python3 -I -B "$repo_dir/tools/build-rescue/verify-repair-surface.py" \
  --mode "$repair_surface_mode" \
  --desk-root "$repo_dir/apps/desk/dist"

install -d "$build_dir/config/includes.chroot/opt/kernaid/desk"
rm -rf "$build_dir/config/includes.chroot/opt/kernaid/desk/assets"
install -m 0644 apps/desk/dist/index.html "$build_dir/config/includes.chroot/opt/kernaid/desk/index.html"
cp -a apps/desk/dist/assets "$build_dir/config/includes.chroot/opt/kernaid/desk/assets"

cd "$build_dir"
lb clean || true
# Keep Debian live-config from rewriting LightDM's pinned isolated autologin
# identity to the regular live user from username=kernaid.
repair_bootappend_suffix=""
iso_basename="KernAid-Rescue-amd64.iso"
if [[ "$repair_candidate" = "1" ]]; then
  repair_bootappend_suffix=" kernaid.repair=fstab-v1"
  iso_basename="KernAid-Rescue-amd64-repair-candidate.iso"
fi
# The BIOS/UEFI boot menus remain fully KernAid branded. Do not start the
# initramfs Plymouth daemon here: it owns tty1 before PID 1 can launch the
# mandatory first-boot Vault prompt. The Desk shell supplies the next branded
# visual stage once the prompt boundary has completed.
bootappend_live="boot=live components noroot username=kernaid hostname=kernaid-rescue live-config.nox11autologin live-config.user-default-groups=audio,cdrom,dip,floppy,video,plugdev,netdev,powerdev,scanner,bluetooth,kernaid-vault,kernaid-codex-client systemd.swap=0 quiet loglevel=5 console=tty0 console=ttyS0,115200n8${repair_bootappend_suffix}"
bootappend_compat="$bootappend_live nomodeset kernaid.graphics=compat"
lb config \
  --mode debian \
  --distribution trixie \
  --architectures amd64 \
  --binary-images iso-hybrid \
  --archive-areas "main contrib non-free-firmware" \
  --debian-installer none \
  --apt-recommends false \
  --uefi-secure-boot enable \
  --bootappend-live "$bootappend_live" \
  --bootappend-live-failsafe "$bootappend_compat" \
  --iso-application "KernAid Rescue" \
  --iso-publisher "KernAid" \
  --iso-volume "KERNAID_RESCUE"
lb build

iso="$(find . -maxdepth 1 -name 'live-image-amd64*.hybrid.iso' -o -name 'live-image-amd64*.iso' | head -n 1)"
test -n "$iso"
python3 -I "$repo_dir/tools/build-rescue/finalize-device-layout.py" finalize \
  --manifest "$repo_dir/rescue/image-layout/device-layout.v1.json" \
  --image "$iso"
mv "$iso" "$repo_dir/$iso_basename"
cd "$repo_dir"
sha256sum "$iso_basename" > "$iso_basename.sha256"
