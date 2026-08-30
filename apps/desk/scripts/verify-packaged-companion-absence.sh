#!/usr/bin/env bash
set -euo pipefail

if (($# < 1 || $# > 2)); then
  printf 'usage: verify-packaged-companion-absence.sh BUNDLE_ROOT [--qualified-first-launch-probe]\n' >&2
  exit 2
fi
bundle_root="$1"
run_qualified_probe=0
if (($# == 2)); then
  if [[ "$2" != '--qualified-first-launch-probe' ]]; then
    printf 'unsupported packaged verification option\n' >&2
    exit 2
  fi
  run_qualified_probe=1
fi
companion_pattern='kernaid-provider-key'
main_executable='kernaid-desk-shell'
probe_flag='--qualified-first-launch-probe'
probe_marker='KERNAID_QUALIFIED_FIRST_LAUNCH_PROBE_OK_V1'
temporary_directories=()
private_directory=''

cleanup() {
  local directory
  for directory in "${temporary_directories[@]}"; do
    if [[ -d "$directory" && ! -L "$directory" ]]; then
      rm -rf -- "$directory"
    fi
  done
}
trap cleanup EXIT

private_temporary_directory() {
  local directory mode
  directory="$(mktemp -d)"
  temporary_directories+=("$directory")
  chmod 0700 "$directory"
  if [[ ! -d "$directory" || -L "$directory" || ! -O "$directory" ]]; then
    printf 'could not establish a private package extraction directory\n' >&2
    return 1
  fi
  if [[ "$(uname -s)" == Darwin ]]; then
    mode="$(stat -f '%Lp' "$directory")"
  else
    mode="$(stat -c '%a' "$directory")"
  fi
  if [[ "$mode" != 700 ]]; then
    printf 'package extraction directory has unsafe permissions\n' >&2
    return 1
  fi
  private_directory="$directory"
}

run_main_probe() {
  local root="$1"
  local label="$2"
  local output binary native_arch architectures
  local -a matches
  while IFS= read -r -d '' binary; do
    matches+=("$binary")
  done < <(find -P "$root" -type f -name "$main_executable" -print0)
  if ((${#matches[@]} != 1)) || [[ -L "${matches[0]-}" || ! -x "${matches[0]-}" ]]; then
    printf 'expected exactly one executable main in extracted %s\n' "$label" >&2
    return 1
  fi
  binary="${matches[0]}"
  if [[ "$(uname -s)" == Darwin ]]; then
    native_arch="$(uname -m)"
    architectures="$(lipo -archs "$binary")"
    if [[ " $architectures " != *" $native_arch "* ]]; then
      printf 'packaged macOS main is not native to this runner\n' >&2
      return 1
    fi
  fi
  if [[ "$(uname -s)" == Linux ]]; then
    if ! output="$(
      LD_LIBRARY_PATH="$root/usr/lib:$root/usr/lib/x86_64-linux-gnu:$root/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
        "$binary" "$probe_flag"
    )"; then
      printf 'qualified first-launch probe failed for extracted %s\n' "$label" >&2
      return 1
    fi
  elif ! output="$("$binary" "$probe_flag")"; then
    printf 'qualified first-launch probe failed for extracted %s\n' "$label" >&2
    return 1
  fi
  if [[ "$output" != "$probe_marker" ]]; then
    printf 'qualified first-launch marker mismatch for extracted %s\n' "$label" >&2
    return 1
  fi
}

fail_if_listed() {
  local label="$1"
  local listing="$2"
  local matches
  matches="$(grep -Fim 20 -- "$companion_pattern" <<<"$listing" || true)"
  if [[ -n "$matches" ]]; then
    printf 'credential companion leaked into %s:\n%s\n' "$label" "$matches" >&2
    return 1
  fi
}

require_matches() {
  local label="$1"
  shift
  if (($# == 0)); then
    printf 'no packaged %s found under %s\n' "$label" "$bundle_root" >&2
    return 1
  fi
}

case "$(uname -s)" in
  Linux)
    shopt -s nullglob
    debs=("$bundle_root"/deb/*.deb)
    rpms=("$bundle_root"/rpm/*.rpm)
    appimages=("$bundle_root"/appimage/*.AppImage)
    require_matches DEB "${debs[@]}"
    require_matches RPM "${rpms[@]}"
    require_matches AppImage "${appimages[@]}"

    for package in "${debs[@]}"; do
      fail_if_listed "$package" "$(dpkg-deb --contents "$package")"
      if ((run_qualified_probe)); then
        private_temporary_directory
        extract_parent="$private_directory"
        extract_root="$extract_parent/root"
        mkdir -m 0700 "$extract_root"
        dpkg-deb --extract "$package" "$extract_root"
        run_main_probe "$extract_root" DEB
        rm -rf -- "$extract_parent"
      fi
    done
    for package in "${rpms[@]}"; do
      fail_if_listed "$package" "$(rpm -qpl "$package")"
    done
    for package in "${appimages[@]}"; do
      if ! offset_text="$(python3 - "$package" <<'PY'
from pathlib import Path
import sys

payload = Path(sys.argv[1]).read_bytes()
offsets = []
cursor = 0
while True:
    cursor = payload.find(b"hsqs", cursor)
    if cursor < 0:
        break
    offsets.append(cursor)
    if len(offsets) > 64:
        raise SystemExit("too many SquashFS magic candidates")
    cursor += 1
print("\n".join(str(offset) for offset in offsets))
PY
      )" || [[ -z "$offset_text" ]]; then
        printf 'could not enumerate bounded SquashFS candidates in AppImage %s\n' "$package" >&2
        exit 1
      fi
      mapfile -t squashfs_candidates <<<"$offset_text"
      valid_offsets=()
      for offset in "${squashfs_candidates[@]}"; do
        if unsquashfs -s -o "$offset" "$package" >/dev/null 2>&1; then
          valid_offsets+=("$offset")
        fi
      done
      if ((${#valid_offsets[@]} != 1)); then
        printf 'expected exactly one valid SquashFS filesystem in AppImage %s, found %s\n' \
          "$package" "${#valid_offsets[@]}" >&2
        exit 1
      fi
      if ! listing="$(unsquashfs -o "${valid_offsets[0]}" -ll "$package")"; then
        printf 'could not inspect AppImage %s\n' "$package" >&2
        exit 1
      fi
      fail_if_listed "$package" "$listing"
      if ((run_qualified_probe)); then
        private_temporary_directory
        extract_parent="$private_directory"
        extract_root="$extract_parent/root"
        if ! unsquashfs -no-progress -o "${valid_offsets[0]}" -d "$extract_root" \
          "$package" >/dev/null; then
          printf 'could not extract AppImage %s\n' "$package" >&2
          exit 1
        fi
        run_main_probe "$extract_root" AppImage
        rm -rf -- "$extract_parent"
      fi
    done
    ;;
  Darwin)
    shopt -s nullglob
    apps=("$bundle_root"/macos/*.app)
    dmgs=("$bundle_root"/dmg/*.dmg)
    require_matches 'macOS APP' "${apps[@]}"
    require_matches DMG "${dmgs[@]}"

    for package in "${apps[@]}"; do
      fail_if_listed "$package" "$(find "$package" -print)"
      if ((run_qualified_probe)); then
        run_main_probe "$package/Contents/MacOS" 'macOS APP'
      fi
    done
    for package in "${dmgs[@]}"; do
      mount_root="$(mktemp -d)"
      if ! hdiutil attach -readonly -nobrowse -mountpoint "$mount_root" "$package" >/dev/null; then
        rmdir "$mount_root"
        printf 'could not mount DMG %s\n' "$package" >&2
        exit 1
      fi
      if ! listing="$(find "$mount_root" -print)"; then
        hdiutil detach "$mount_root" >/dev/null || true
        rmdir "$mount_root" || true
        printf 'could not inspect DMG %s\n' "$package" >&2
        exit 1
      fi
      if ! hdiutil detach "$mount_root" >/dev/null; then
        printf 'could not detach DMG %s\n' "$package" >&2
        exit 1
      fi
      rmdir "$mount_root"
      fail_if_listed "$package" "$listing"
    done
    ;;
  *)
    printf 'unsupported packaged-companion gate platform\n' >&2
    exit 1
    ;;
esac

printf 'credential companion is absent from every packaged Desk bundle in %s\n' "$bundle_root"
