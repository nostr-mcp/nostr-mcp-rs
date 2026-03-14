#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

output="$(cargo guard-coverage-contract 2>&1)"
printf '%s\n' "$output"

if [[ "$output" != *"coverage contract valid"* ]]; then
  echo "coverage contract guard did not report a valid contract"
  exit 1
fi
