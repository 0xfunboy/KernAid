#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd -- "${BASH_SOURCE[0]%/*}/../.." && pwd -P)"
readonly resident_harness="$repo_dir/tests/integration/linux-snapshot-resident-ipc.sh"

if (( $# != 0 )); then
  echo "The hosted CI Resident IPC runner accepts no arguments" >&2
  exit 2
fi
if [[ "${GITHUB_ACTIONS:-}" != true \
  || "${RUNNER_OS:-}" != Linux \
  || "${RUNNER_ENVIRONMENT:-}" != github-hosted ]]; then
  echo "The temporary user-namespace policy runner is hosted-CI only" >&2
  exit 2
fi
if [[ "$EUID" -eq 0 ]]; then
  echo "The hosted CI Resident IPC runner must remain unprivileged" >&2
  exit 2
fi
for fixed_tool in /usr/bin/sudo /usr/bin/unshare /usr/sbin/sysctl; do
  [[ -x "$fixed_tool" ]] || {
    echo "A fixed hosted CI isolation tool is unavailable" >&2
    exit 2
  }
done
[[ -r /proc/sys/user/max_user_namespaces ]] || {
  echo "The user-namespace capacity policy is unavailable" >&2
  exit 2
}
max_user_namespaces="$(</proc/sys/user/max_user_namespaces)"
[[ "$max_user_namespaces" =~ ^[1-9][0-9]*$ ]] || {
  echo "The hosted runner has no user-namespace capacity" >&2
  exit 2
}

unprivileged_clone_before=""
unprivileged_clone_changed=0
apparmor_userns_before=""
apparmor_userns_changed=0
if [[ -e /proc/sys/kernel/unprivileged_userns_clone ]]; then
  unprivileged_clone_before="$(</proc/sys/kernel/unprivileged_userns_clone)"
  [[ "$unprivileged_clone_before" =~ ^[01]$ ]] || {
    echo "The unprivileged user-namespace policy was outside the allowlist" >&2
    exit 2
  }
fi
if [[ -e /proc/sys/kernel/apparmor_restrict_unprivileged_userns ]]; then
  apparmor_userns_before="$(</proc/sys/kernel/apparmor_restrict_unprivileged_userns)"
  [[ "$apparmor_userns_before" =~ ^[01]$ ]] || {
    echo "The AppArmor user-namespace policy was outside the allowlist" >&2
    exit 2
  }
fi

restore_userns_policy() {
  local restore_status=0
  if [[ "$apparmor_userns_changed" == 1 ]]; then
    if /usr/bin/sudo -n /usr/sbin/sysctl -q -w \
      "kernel.apparmor_restrict_unprivileged_userns=$apparmor_userns_before" \
      && [[ "$(</proc/sys/kernel/apparmor_restrict_unprivileged_userns)" == "$apparmor_userns_before" ]]; then
      apparmor_userns_changed=0
    else
      echo "Failed to restore AppArmor user-namespace policy" >&2
      restore_status=1
    fi
  fi
  if [[ "$unprivileged_clone_changed" == 1 ]]; then
    if /usr/bin/sudo -n /usr/sbin/sysctl -q -w \
      "kernel.unprivileged_userns_clone=$unprivileged_clone_before" \
      && [[ "$(</proc/sys/kernel/unprivileged_userns_clone)" == "$unprivileged_clone_before" ]]; then
      unprivileged_clone_changed=0
    else
      echo "Failed to restore unprivileged user-namespace policy" >&2
      restore_status=1
    fi
  fi
  return "$restore_status"
}

finish_userns_policy() {
  local exit_status="$?"
  trap - EXIT INT TERM
  if ! restore_userns_policy; then
    exit_status=1
  fi
  exit "$exit_status"
}
trap finish_userns_policy EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if [[ -n "$unprivileged_clone_before" && "$unprivileged_clone_before" != 1 ]]; then
  unprivileged_clone_changed=1
  /usr/bin/sudo -n /usr/sbin/sysctl -q -w kernel.unprivileged_userns_clone=1
fi
if [[ -n "$apparmor_userns_before" && "$apparmor_userns_before" != 0 ]]; then
  apparmor_userns_changed=1
  /usr/bin/sudo -n /usr/sbin/sysctl -q -w \
    kernel.apparmor_restrict_unprivileged_userns=0
fi
if [[ -n "$unprivileged_clone_before" ]]; then
  [[ "$(</proc/sys/kernel/unprivileged_userns_clone)" == 1 ]]
fi
if [[ -n "$apparmor_userns_before" ]]; then
  [[ "$(</proc/sys/kernel/apparmor_restrict_unprivileged_userns)" == 0 ]]
fi
/usr/bin/unshare --user --map-root-user /usr/bin/true

resident_marker="$($resident_harness)"
if [[ ! "$resident_marker" =~ ^KERNAID_RESIDENT_LINUX_SNAPSHOT_E2E_V1\ semantic_sha256=([0-9a-f]{64})$ ]]; then
  echo "Resident snapshot evidence was outside the allowlist" >&2
  exit 1
fi
readonly resident_digest="${BASH_REMATCH[1]}"

restore_userns_policy || exit 1
trap - EXIT INT TERM
printf 'KERNAID_RESIDENT_LINUX_SNAPSHOT_E2E_V1 semantic_sha256=%s\n' \
  "$resident_digest"
