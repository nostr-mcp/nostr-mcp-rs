#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

output="$(cargo guard-registry-drift 2>&1)"
printf '%s\n' "$output"

if [[ "$output" != *"test result: ok. 1 passed;"* ]]; then
  echo "registry drift guard did not execute the expected test"
  exit 1
fi
