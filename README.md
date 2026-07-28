# helianthus-modbus

`helianthus-modbus` is the public Modbus protocol and transport/runtime
foundation for Helianthus.

## Status

The repository implements the strict vendor-neutral phase-one PDU layer and
the bounded Modbus TCP runtime: MBAP streaming, socket ownership, transaction
correlation, scheduling, pooling, coalescing, cancellation, and recovery.
Modbus RTU runtime ownership remains separately authorized follow-up work.

`NewTCPEndpoint` is the single public construction root for the current
FC03/FC04 runtime. It owns the connection pool, scheduler, transaction owners,
reconnect backoff, monotonic clock, and replay event sequence. The lower-level
runtime components cannot be constructed independently by package consumers.
FC2B/MEI type 0x0E is available at the strict codec/owner layer; aggregate TCP
execution through `TCPEndpoint` is an explicit FMV3-M1-04 deliverable.

`OpenConnection` accepts a raw `*net.TCPConn` in production, verifies its
remote address against the configured `tcp://<ip-literal>:<port>` identity,
and claims both the physical remote and the concrete socket globally. A second
endpoint root for the same gateway, an arbitrary connection wrapper, or a
mismatched remote is rejected before activation and remains caller-owned.
Synthetic `net.Conn` implementations are not a public admission path.
Package-private trusted decorators exist only for deterministic fault-injection
tests. This prevents competing schedulers, transaction allocators, or
correlation maps around one gateway or byte stream.

## Ownership

This repository owns:

- Modbus protocol data units and validation;
- Modbus TCP and Modbus RTU transports;
- endpoint ownership, scheduling, cancellation, timeout, quarantine, and
  recovery;
- exact raw-word and request-provenance delivery to profile consumers.

This repository does not own:

- vendor register meanings, detection, qualification, or value normalization;
- canonical energy/PV semantics or publication policy;
- gateway composition, GraphQL, Home Assistant, eeBUS, or Matter bindings.

Vendor and standard-family profiles live together in
[`helianthus-modbusreg`](https://github.com/Project-Helianthus/helianthus-modbusreg).
Canonical protocol-independent semantics remain owned by
`helianthus-ebusreg`. Gateway composition is a later, separately authorized
milestone.

## Phase-One Boundary

Phase one is read-only. Its complete implemented PDU operation allowlist is:

- FC03, Read Holding Registers;
- FC04, Read Input Registers;
- FC2B/MEI type 0x0E, Read Device Identification.

This list is both the implemented PDU boundary and the ceiling for later
phase-one transports. There is no generic function-code escape hatch and no
write PDU, probe, or control API. Write support requires a separate safety plan
and authorization.

The operation allowlist does not imply that every operation has reached every
runtime layer in M1-02. M1-02 owns the aggregate FC03/FC04 endpoint. M1-04 adds
bounded FC2B/MEI type 0x0E endpoint execution without exposing a lower-level
socket bypass.

Every queued TCP read receives one immutable absolute monotonic deadline.
Queueing, transport write, response wait, cancellation, and reconnect backoff
consume that same deadline; none starts a new relative window. A response-wait
timeout tombstones only the transmitted transaction. Other safe in-flight
transactions continue on the socket, and a late matching frame remains
request-bound diagnostic evidence without becoming deliverable.

Retryable read state remains endpoint-owned and bounded while moving between
socket generations. A provable zero-byte write may re-enter the fair queue
without reconnect backoff. Any possibly transmitted write invalidates the
socket and requires endpoint-owned backoff before retry on a new generation.
Canceling the last retry does not bypass that endpoint recovery debt; the
terminal handle remains a bounded recovery-only token until backoff completes.
Per-dependent cancellation narrows the retained read plan, so retry cannot
revive a cancelled logical view. `Close` terminalizes active and retryable work,
retires every socket, and is idempotent.

Endpoint events use one owner-assigned sequence across every socket and record
enqueue, admission, queue service, coalescing, write invocation/result,
cancellation, response receipt, timer, tombstone, reconnect, and jitter/backoff
evidence. Equal monotonic offsets are therefore replayed in exact sequence
order. Physical request events retain function, logical table, zero-based
offset, quantity, and the exact immutable hex ADU; response events retain both
requested and received function identity plus the exact received ADU.
`TCPEndpoint.Snapshot` exposes the corresponding read-only health, finite
resource utilization, queue wait, coalescing, response-class, timeout, retry,
reconnect, cancellation, and observation-gap metrics. Event sinks may inspect
that snapshot synchronously. Event-producing endpoint operations fail fast with
`event_sink_reentry` while a callback is active, preventing callback re-entry
from deadlocking runtime ownership locks. Sink panics are contained and counted
without poisoning endpoint ownership state.

The normative cross-repository boundary is
[`modbus-multivendor-boundaries.md`](https://github.com/Project-Helianthus/helianthus-docs-ebus/blob/main/docs/platform/modbus-multivendor-boundaries.md).

## Development

Prerequisites:

- Go 1.22 or newer;
- `golangci-lint` available on `PATH`.

Run the complete local gate:

```bash
./scripts/ci_local.sh
```

The gate validates the exact machine-readable
[`policy/phase1-readonly.json`](policy/phase1-readonly.json), rejects
unauthorized Helianthus dependencies and vendor/write surface tokens, and runs
mutation tests for those boundaries. The product source inventory is closed by
the `m1_protocol` policy lock. Tests may expand without weakening that product
inventory, but still pass the same dependency, vendor-token, and read-only
gates. CI also validates
[`modbus-companion-consumer-lock-v1.json`](policy/modbus-companion-consumer-lock-v1.json)
against the exact merged public companion before compiling product code.
FMV3-M1-02 runtime evidence is machine-checked by
[`policy/m1-02-acceptance.json`](policy/m1-02-acceptance.json) against that
pinned contract. The gate executes every mapped test, requires explicit
run/pass events without skips, and locks the complete Go test-file inventory so
helpers and harness code cannot drift independently of the reviewed evidence.

The repository follows one issue and one pull request at a time, squash merge,
strict test-first implementation, and applicable documentation/protocol gates.
GitHub protects `main` with required `checks` and `lint` jobs, linear history,
conversation resolution, and disabled merge/rebase commit methods. A separate
required `adversarial-review` status is emitted only for an exact head that has
a fresh OpenAI-only `NO_FINDINGS` verdict. All protections apply to
administrators.
See [CONTRIBUTING.md](CONTRIBUTING.md) and [AGENTS.md](AGENTS.md).

## License

Implementation code and repository documentation are licensed under
[AGPL-3.0](LICENSE). Implementation-neutral protocol facts belong in the
Helianthus public `CC0-1.0` protocol-documentation lane, not in private
bindings. See the
[Helianthus licensing model](https://github.com/Project-Helianthus/.github/blob/main/LICENSING.md).
