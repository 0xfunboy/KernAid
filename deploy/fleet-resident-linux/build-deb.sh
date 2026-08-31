#!/usr/bin/env bash
set -euo pipefail

if (($# != 3)); then
  echo "Usage: $0 VERSION ARCH OUTPUT_DIRECTORY" >&2
  exit 2
fi

version="$1"
architecture="$2"
output_directory="$3"
case "$version" in
  ''|*[!0-9A-Za-z.+~:-]*) echo "Invalid package version." >&2; exit 2 ;;
esac
case "$architecture" in
  amd64|arm64) ;;
  *) echo "Unsupported package architecture." >&2; exit 2 ;;
esac

repo_root="$(cd "$(dirname "$0")/../.." && pwd -P)"
if [[ -L "$repo_root" || ! -d "$repo_root" ]]; then
  echo "Repository root is unsafe." >&2
  exit 2
fi

for binary in \
  kernaid-fleet-resident-sync \
  kernaid-fleet-resident-work-orders \
  kernaid-fleet-resident-update \
  kernaid-fleet-resident-activator; do
  if [[ ! -f "$repo_root/target/release/$binary" || -L "$repo_root/target/release/$binary" ]]; then
    echo "Missing release binary: $binary" >&2
    exit 1
  fi
done

install -d -m 0755 "$output_directory"
output_directory="$(cd "$output_directory" && pwd -P)"
staging="$(mktemp -d)"
trap 'rm -rf -- "$staging"' EXIT
package_root="$staging/kernaid-fleet-resident"

install -d -m 0755 \
  "$package_root/DEBIAN" \
  "$package_root/usr/bin" \
  "$package_root/usr/libexec" \
  "$package_root/usr/lib/systemd/system" \
  "$package_root/usr/share/doc/kernaid-fleet-resident" \
  "$package_root/usr/share/kernaid-fleet-resident/examples" \
  "$package_root/usr/share/kernaid-fleet-resident/systemd/user"

for binary in \
  kernaid-fleet-resident-sync \
  kernaid-fleet-resident-work-orders \
  kernaid-fleet-resident-update \
  kernaid-fleet-resident-activator; do
  install -m 0755 "$repo_root/target/release/$binary" "$package_root/usr/libexec/$binary"
done
install -m 0755 "$repo_root/deploy/fleet-resident-linux/kernaid-fleet-resident-setup" \
  "$package_root/usr/bin/kernaid-fleet-resident-setup"

install -m 0644 "$repo_root/deploy/fleet-resident/config.example.json" \
  "$package_root/usr/share/kernaid-fleet-resident/examples/fleet-resident.json"
install -m 0644 "$repo_root/deploy/fleet-resident-work-orders/config.example.json" \
  "$package_root/usr/share/kernaid-fleet-resident/examples/fleet-work-orders.json"
install -m 0644 "$repo_root/deploy/fleet-resident-update/config.example.json" \
  "$package_root/usr/share/kernaid-fleet-resident/examples/fleet-update.json"
install -m 0644 "$repo_root/deploy/fleet-resident-update/config.ab.example.json" \
  "$package_root/usr/share/kernaid-fleet-resident/examples/fleet-update-ab.json"
install -m 0644 "$repo_root/deploy/fleet-resident-update/fleet-resident-activator.example.json" \
  "$package_root/usr/share/kernaid-fleet-resident/examples/fleet-resident-activator.json"

install -m 0644 "$repo_root/deploy/fleet-resident/kernaid-fleet-resident-sync.service" \
  "$package_root/usr/share/kernaid-fleet-resident/systemd/user/"
install -m 0644 "$repo_root/deploy/fleet-resident-work-orders/kernaid-fleet-resident-work-orders.service" \
  "$package_root/usr/share/kernaid-fleet-resident/systemd/user/"
install -m 0644 "$repo_root/deploy/fleet-resident-update/kernaid-fleet-resident-update.service" \
  "$package_root/usr/share/kernaid-fleet-resident/systemd/user/"

for unit in \
  kernaid-fleet-resident-update-system.service \
  kernaid-fleet-resident-activator.path \
  kernaid-fleet-resident-activator.service \
  kernaid-fleet-resident-rollback.service; do
  install -m 0644 "$repo_root/deploy/fleet-resident-update/$unit" \
    "$package_root/usr/lib/systemd/system/$unit"
done

install -m 0644 "$repo_root/deploy/fleet-resident-linux/README.md" \
  "$package_root/usr/share/doc/kernaid-fleet-resident/README.md"
install -m 0644 "$repo_root/LICENSE" \
  "$package_root/usr/share/doc/kernaid-fleet-resident/copyright"

installed_size="$(du -sk "$package_root/usr" | cut -f1)"
cat > "$package_root/DEBIAN/control" <<EOF
Package: kernaid-fleet-resident
Version: $version
Section: admin
Priority: optional
Architecture: $architecture
Installed-Size: $installed_size
Maintainer: KernAid <0xfunboy@gmail.com>
Depends: ca-certificates, dbus-user-session, libsecret-1-0, systemd
Description: KernAid Fleet diagnostic and recovery resident
 Device-bound Fleet synchronization, typed diagnostic work orders and signed
 update staging. Services remain disabled until explicit local enrollment.
EOF

epoch="${SOURCE_DATE_EPOCH:-0}"
find "$package_root" -type d -exec chmod 0755 {} +
find "$package_root" -exec touch -h -d "@$epoch" {} +
package_path="$output_directory/kernaid-fleet-resident_${version}_${architecture}.deb"
dpkg-deb --root-owner-group --build "$package_root" "$package_path"
sha256sum "$package_path" > "$package_path.sha256"
dpkg-deb --info "$package_path" >/dev/null
echo "$package_path"
