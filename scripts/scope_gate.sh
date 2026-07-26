#!/usr/bin/env bash
set -euo pipefail

expected_module="module github.com/Project-Helianthus/helianthus-modbus"
if [[ "$(head -n 1 go.mod)" != "$expected_module" ]]; then
  echo "Unexpected Go module path."
  exit 1
fi

for marker in "read-only" "FC03" "FC04" "FC2B/MEI type 0x0E"; do
  if ! grep -Fq "$marker" README.md; then
    echo "README is missing scope marker: $marker"
    exit 1
  fi
done

python3 scripts/validate_scope_policy.py
