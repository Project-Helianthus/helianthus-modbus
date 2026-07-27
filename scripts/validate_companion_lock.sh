#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
docs_repository="https://github.com/Project-Helianthus/helianthus-docs-ebus.git"
docs_commit="711a556fee344c6fe7f1ecf3253fcdb3f5f22d06"
trust_anchor="e633fa22a6a6fe3e4f3b74a68eb44401fe26f38d"
consumer_lock="$repo_root/policy/modbus-companion-consumer-lock-v1.json"
temporary_root="$(mktemp -d "${TMPDIR:-/tmp}/helianthus-modbus-docs.XXXXXX")"
trap 'rm -rf "$temporary_root"' EXIT

git_command=(
  env
  -u GIT_DIR
  -u GIT_WORK_TREE
  -u GIT_INDEX_FILE
  -u GIT_OBJECT_DIRECTORY
  -u GIT_ALTERNATE_OBJECT_DIRECTORIES
  GIT_CONFIG_NOSYSTEM=1
  GIT_CONFIG_GLOBAL=/dev/null
  git
  -c core.hooksPath=/dev/null
)

"${git_command[@]}" clone \
  --filter=blob:none \
  --no-checkout \
  "$docs_repository" \
  "$temporary_root/docs"
"${git_command[@]}" -C "$temporary_root/docs" fetch \
  --depth=1 \
  origin \
  "$docs_commit"
"${git_command[@]}" -C "$temporary_root/docs" checkout \
  --detach \
  "$docs_commit"
test "$("${git_command[@]}" -C "$temporary_root/docs" rev-parse HEAD)" = "$docs_commit"

PYTHONDONTWRITEBYTECODE=1 python3 \
  "$temporary_root/docs/scripts/validate_modbus_companion.py" \
  --root "$temporary_root/docs" \
  --consumer-lock "$consumer_lock" \
  --docs-commit-sha "$docs_commit" \
  --expected-trust-anchor-sha "$trust_anchor"
