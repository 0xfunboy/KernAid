#!/usr/bin/env bash
set -euo pipefail
# The private workflow creates its input credential under umask 077. Public
# runtime directories must remain traversable after the image hook makes them
# root-owned; pnpm and git otherwise inherit owner-only directory permissions.
# This child-shell mask does not affect the caller, and credentials below are
# still installed with an explicit 0600 mode.
umask 022
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
image_root="$repo_dir/rescue/live-build/config/includes.chroot"
private_key_destination="$image_root/etc/kernaid-assistant/gemrouter.key"
private_dropin_destination="$image_root/etc/systemd/system/kernaid-assistant.service.d/50-private-credential.conf"
# Never silently reuse credentials from an earlier local staging operation.
for private_destination in "$private_key_destination" "$private_dropin_destination"; do
  if [[ -e "$private_destination" || -L "$private_destination" ]]; then
    echo "Refusing to reuse a pre-existing private assistant credential staging path" >&2
    exit 2
  fi
done
if [[ -n "${KERNAID_PRIVATE_GEMROUTER_KEY_FILE:-}" ]]; then
  if [[ "${GITHUB_ACTIONS:-false}" = "true" ]]; then
    if [[ "${KERNAID_PRIVATE_TESTING:-0}" != "1" \
      || "${GITHUB_EVENT_NAME:-}" != "workflow_dispatch" \
      || "${GITHUB_REF:-}" != "refs/heads/main" ]]; then
      echo "CI credentials are restricted to private testing dispatches on main" >&2
      exit 2
    fi
  fi
  test -f "$KERNAID_PRIVATE_GEMROUTER_KEY_FILE"
  test ! -L "$KERNAID_PRIVATE_GEMROUTER_KEY_FILE"
  test -s "$KERNAID_PRIVATE_GEMROUTER_KEY_FILE"
fi
test "$(node --version)" = v24.18.0
test ! -e "$image_root/opt/kernaid/assistant"
test ! -e "$image_root/opt/kernaid/searxng-source"
cd "$repo_dir"
pnpm --filter @kernaid/rescue-assistant --prod deploy "$image_root/opt/kernaid/assistant"
install -m 0755 "$(command -v node)" "$image_root/opt/kernaid/assistant/node"
# Catch missing production dependencies before entering the image build.
"$image_root/opt/kernaid/assistant/node" --input-type=module -e \
  'await import(process.argv[1])' \
  "file://$image_root/opt/kernaid/assistant/runtime.mjs"
git clone --quiet https://github.com/searxng/searxng.git "$image_root/opt/kernaid/searxng-source" --depth 1
git -C "$image_root/opt/kernaid/searxng-source" fetch --quiet --depth 1 origin c0042add30116a315ebacfcb84781bb3e1e4e77e
git -C "$image_root/opt/kernaid/searxng-source" checkout --quiet --detach c0042add30116a315ebacfcb84781bb3e1e4e77e
# Public builds contain no default secret. Optional private test media can
# provision a root-only credential supplied explicitly outside the repository.
if [[ -n "${KERNAID_PRIVATE_GEMROUTER_KEY_FILE:-}" ]]; then
  install -m 0600 "$KERNAID_PRIVATE_GEMROUTER_KEY_FILE" "$private_key_destination"
  install -d "$image_root/etc/systemd/system/kernaid-assistant.service.d"
  install -m 0644 "$repo_dir/services/rescue-assistant/private-credential.conf" "$private_dropin_destination"
fi
