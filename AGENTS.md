# AGENTS.md

## Purpose and ownership

`helianthus-modbus` owns vendor-neutral Modbus PDU, TCP, and RTU runtime
behavior: framing, codecs, sessions, retries, scheduling, replay, and safe
read execution. It does not own vendor semantics, vendor profiles, canonical
or universal semantics, gateway composition, or consumer/output bindings.

Keep vendor-specific identities, maps, decoders, function admission, and
qualification in the profile registry. The standard public PDU surface is
read-only FC03, FC04, and FC2B/MEI0E. Byte-opaque private-function framing is
transport infrastructure only; it is not a vendor decoder, profile, or
operation-admission mechanism. Preserve valid per-field state on partial
failure where the owning API permits it; never replace last-known-good state
wholesale.

## Workflow

1. Reconcile `origin/main`, the working tree, related issues, branches, pull
   requests, reviews, and checks before editing.
2. Use one scoped issue and an `issue/<number>-<slug>` branch created from
   current `origin/main`. Keep unrelated work out of the branch.
3. For behavioral, transport, recovery, concurrency, persistence, or safety
   work, commit focused RED tests first and record their observed failure before
   implementation. Low-risk mechanical changes may use focused tests instead.
4. Run `./scripts/ci_local.sh` and every applicable unit, race, lint,
   conformance, and transport-matrix check before pushing. Include exact
   commands and results in the pull request.
5. Open a linked pull request stating scope, tests, documentation-gate and
   transport-gate status, plus residual risk.
6. Resolve valid P0-P2 findings, then obtain a fresh exact-HEAD
   `NO_BLOCKING_FINDINGS` review verdict. P3/P4 findings are triaged as fix,
   backlog, or by design.
7. Squash merge only after all applicable checks and gates are green and the
   exact-HEAD blocker review is clear. Verify remote `main`, issue, PR, and
   branch state, then stop at the requested boundary.

## Safety and public boundaries

Reads must be bounded and fail-closed; runtime defaults must not create a
global vendor/function-code allowlist or vendor dispatch map. Public builds,
tests, fixtures, and documentation must be self-contained and must not require
private repositories, artifacts, credentials, local network access, or personal
laboratory equipment. Any real installation, credential use, destructive or
irreversible action, safety-relevant control, or live-device write requires
explicit operator confirmation at action time.
