#!/usr/bin/env bash
set -euo pipefail
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
schema_dir="$repo_dir/packages/schemas"
expected_schemas=(
  approval.schema.json
  diagnosis-proposal.schema.json
  evidence.schema.json
  execution-event.schema.json
  linux-hardware-inventory.schema.json
  linux-normalized-snapshot.schema.json
  rescue-fstab-repair-approval.schema.json
  rescue-openai-request.schema.json
  rescue-openai-response.schema.json
  rescue-vault-repair-request.schema.json
  rescue-vault-repair-response.schema.json
  rescue-vault-request.schema.json
  rescue-vault-response.schema.json
  session-report.schema.json
  validated-plan.schema.json
)

print_lines() {
  local value
  for value in "$@"; do
    printf '%s\n' "$value"
  done
}

LC_ALL=C
export LC_ALL
shopt -s nullglob
schema_paths=("$schema_dir"/*.schema.json)
actual_schemas=("${schema_paths[@]##*/}")

if ! diff -u \
  <(print_lines "${expected_schemas[@]}") \
  <(print_lines "${actual_schemas[@]}"); then
  echo "ERROR: published schema basenames do not match the expected release set" >&2
  exit 1
fi

for schema in "${expected_schemas[@]}"; do
  python3 -m json.tool "$schema_dir/$schema" >/dev/null
done

echo "PASS: ${#expected_schemas[@]} expected versioned schemas parse as JSON"
