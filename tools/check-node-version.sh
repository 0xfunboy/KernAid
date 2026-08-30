#!/usr/bin/env bash
set -euo pipefail

readonly required_node_version="24.18.0"
unset CDPATH
script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly script_directory
repository_root="$(cd -- "$script_directory/.." && pwd -P)"
readonly repository_root
readonly pin_file="$repository_root/.node-version"

if [[ ! -f "$pin_file" || -L "$pin_file" ]]; then
  echo "KernAid requires a regular .node-version file." >&2
  exit 1
fi

pinned_node_version="$(<"$pin_file")"
readonly pinned_node_version
if [[ "$pinned_node_version" != "$required_node_version" ]]; then
  echo "KernAid's Node.js pin must be exactly $required_node_version." >&2
  exit 1
fi

if ! command -v node >/dev/null 2>&1; then
  echo "KernAid requires Node.js $required_node_version; node was not found." >&2
  exit 1
fi

observed_node_version="$(node --version)"
readonly observed_node_version
if [[ "$observed_node_version" != "v$required_node_version" ]]; then
  echo "KernAid requires Node.js v$required_node_version; found $observed_node_version." >&2
  exit 1
fi
