#!/usr/bin/env bash
set -euo pipefail
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
count=0
for schema in "$repo_dir"/packages/schemas/*.schema.json; do python3 -m json.tool "$schema" >/dev/null; count=$((count+1)); done
test "$count" -eq 6
echo "PASS: $count versioned schemas parse as JSON"
