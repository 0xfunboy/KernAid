#!/usr/bin/env bash
set -euo pipefail
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
"$repo_dir/tools/verify-release/validate-schemas.sh"
test -f "$repo_dir/SECURITY.md"
test -f "$repo_dir/AGENTS.md"
echo "Phase 0 static release checks passed; QEMU and hardware gates remain open."
