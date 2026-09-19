#!/usr/bin/env bash
set -euo pipefail
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
image_root="$repo_dir/rescue/live-build/config/includes.chroot"
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
  test -f "$KERNAID_PRIVATE_GEMROUTER_KEY_FILE"
  test ! -L "$KERNAID_PRIVATE_GEMROUTER_KEY_FILE"
  install -m 0600 "$KERNAID_PRIVATE_GEMROUTER_KEY_FILE" "$image_root/etc/kernaid-assistant/gemrouter.key"
  install -d "$image_root/etc/systemd/system/kernaid-assistant.service.d"
  install -m 0644 "$repo_dir/services/rescue-assistant/private-credential.conf" "$image_root/etc/systemd/system/kernaid-assistant.service.d/50-private-credential.conf"
fi
