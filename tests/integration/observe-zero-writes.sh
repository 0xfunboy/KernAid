#!/usr/bin/env bash
set -euo pipefail
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
fixture="$repo_dir/tests/fixtures/linux-root"
case "$fixture" in "$repo_dir"/tests/fixtures/*) ;; *) echo "unsafe fixture path" >&2; exit 2;; esac
before="$(find "$fixture" -type f -print0 | sort -z | xargs -0 sha256sum)"
cargo run --quiet -p kernaid-linux-pack --bin kernaid-linux-inventory -- "$fixture" >/dev/null
after="$(find "$fixture" -type f -print0 | sort -z | xargs -0 sha256sum)"
test "$before" = "$after"
echo "PASS: Observe collector made zero content writes"
