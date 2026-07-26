# AGENTS

This repository is part of the Helianthus multi-protocol gateway platform.
Workspace orchestration is governed by the workspace-root `AGENTS.md` and the
cruise-control skills referenced there.

## Repository Rules

1. Work one issue at a time and keep at most one open pull request.
2. Use `issue/<id>-<slug>` branches and squash merge only.
3. Run `./scripts/ci_local.sh` before pushing.
4. Product implementation requires a test-only RED commit observed by CI before
   the implementation commit.
5. Protocol, transport, recovery, scheduling, or exported behavior changes
   require their merged or companion public documentation gate.
6. React and reply to every review comment; resolve findings with evidence.

## Ownership Invariants

- This repository owns Modbus PDUs and TCP/RTU runtime behavior.
- It does not own vendor semantics, canonical semantics, gateway composition,
  or output bindings.
- Phase one exposes only FC03, FC04, and FC2B/MEI0E read operations.
- No generic write primitive or arbitrary function-code escape hatch is allowed.
- Public builds and tests must never require private repositories or artifacts.
- Stop before gateway work unless a later execution authorization explicitly
  permits it.
