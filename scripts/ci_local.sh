#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
export GOWORK=off

echo "==> terminology gate"
legacy_pattern='m[a]ster|s[l]ave'
legacy_found=0
tracked_status=0
tracked_matches="$(git grep -nIwiE "$legacy_pattern" -- .)" || tracked_status=$?
if (( tracked_status > 1 )); then
  echo "Terminology scan failed."
  exit "$tracked_status"
fi
if (( tracked_status == 0 )); then
  printf '%s\n' "$tracked_matches"
  legacy_found=1
fi
while IFS= read -r -d '' untracked_file; do
  untracked_status=0
  untracked_matches="$(
    grep -nIwiE -- "$legacy_pattern" "$untracked_file"
  )" || untracked_status=$?
  if (( untracked_status > 1 )); then
    echo "Terminology scan failed for $untracked_file."
    exit "$untracked_status"
  fi
  if (( untracked_status == 0 )); then
    printf '%s:%s\n' "$untracked_file" "$untracked_matches"
    legacy_found=1
  fi
done < <(git ls-files --others --exclude-standard -z)
if (( legacy_found != 0 )); then
  echo "Found legacy terminology."
  exit 1
fi

echo "==> scope gate"
./scripts/scope_gate.sh

echo "==> read-only AST surface"
GOWORK=off go run ./scripts/read_only_surface .

echo "==> FMV3-M1-02 acceptance map"
python3 scripts/validate_m1_02_acceptance.py

echo "==> FMV3-M1-03 offline RTU acceptance map"
if [[ "${GITHUB_ACTIONS:-}" == "true" ]]; then
  python3 scripts/validate_m1_03_acceptance.py
else
  python3 scripts/validate_m1_03_acceptance.py --candidate
fi

echo "==> FMV3-M1-04 transport conformance matrix"
if [[ "${GITHUB_ACTIONS:-}" == "true" ]]; then
  python3 scripts/validate_m1_04_acceptance.py
else
  python3 scripts/validate_m1_04_acceptance.py --candidate
fi

echo "==> FMV3-M1-06 opaque runtime acquisition conformance"
python3 scripts/validate_m1_06_conformance.py

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

echo "==> go build (linux/386 portability)"
GOOS=linux GOARCH=386 go test -c -o /dev/null .

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
