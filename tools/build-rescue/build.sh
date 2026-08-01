#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
build_dir="$repo_dir/rescue/live-build"

for command in lb; do
  command -v "$command" >/dev/null || { echo "Missing required command: $command" >&2; exit 2; }
done

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run this script as root inside a disposable Debian build environment." >&2
  exit 2
fi

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
  --bootappend-live "boot=live components noroot username=kernaid hostname=kernaid-rescue console=tty0 console=ttyS0,115200n8"
lb build

iso="$(find . -maxdepth 1 -name 'live-image-amd64*.hybrid.iso' -o -name 'live-image-amd64*.iso' | head -n 1)"
test -n "$iso"
mv "$iso" "$repo_dir/KernAid-Rescue-amd64.iso"
cd "$repo_dir"
sha256sum KernAid-Rescue-amd64.iso > KernAid-Rescue-amd64.iso.sha256
