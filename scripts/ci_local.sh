#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
export GOWORK=off

echo "==> terminology gate"
if rg -nIwi 'm[a]ster|s[l]ave' . --glob '!.git/**'; then
  echo "Found legacy terminology."
  exit 1
fi

echo "==> Modbus companion consumer lock"
./scripts/validate_companion_lock.sh

echo "==> scope gate"
./scripts/scope_gate.sh

echo "==> read-only AST surface"
GOWORK=off go run ./scripts/read_only_surface .

echo "==> FMV3-M1-02 acceptance map"
python3 scripts/validate_m1_02_acceptance.py

echo "==> scope policy mutation tests"
python3 -m unittest discover -s tests -p 'test_*.py'

echo "==> gofmt"
unformatted="$(
  while IFS= read -r go_file; do
    gofmt -l "$go_file"
  done < <(rg --files -g '*.go' -g '!.git/**' | sort)
)"
if [[ -n "$unformatted" ]]; then
  echo "gofmt required for:"
  echo "$unformatted"
  exit 1
fi

echo "==> go vet"
go vet ./...

echo "==> go build"
go build ./...

echo "==> go test (race)"
go test -race -count=1 ./...

if command -v golangci-lint >/dev/null 2>&1; then
  echo "==> golangci-lint"
  if ! golangci-lint version | grep -Fq "version 2.11.4 "; then
    echo "golangci-lint v2.11.4 is required."
    exit 1
  fi
  golangci-lint run ./...
elif [[ "${HELIANTHUS_EXTERNAL_LINT_JOB:-}" == "1" ]]; then
  echo "==> golangci-lint delegated to required CI lint job"
else
  echo "golangci-lint is required for local CI."
  exit 1
fi
