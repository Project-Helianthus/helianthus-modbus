# helianthus-modbus

`helianthus-modbus` is the public Modbus protocol and transport/runtime
foundation for Helianthus.

## Status

The repository implements the strict vendor-neutral phase-one PDU layer and
the bounded Modbus TCP runtime: MBAP streaming, socket ownership, transaction
correlation, scheduling, pooling, coalescing, cancellation, and recovery.
It also implements typed RTU framing, deterministic timing, and a serialized
offline fixture owner for abandonment, quarantine, and recovery tests.

The RTU capability is experimental, disabled by default, and exactly
`FIXTURE_ONLY_NO_HARDWARE`. It exposes no serial port, device path, physical
reader/writer, or hardware-qualified claim. `NewRTUFixtureEndpoint` operates
only on an in-memory `RTUFixtureLine`; physical RTU admission remains separate
qualification work.

`NewTCPEndpoint` is the single public construction root for the current
read-only FC03/FC04 and FC2B/MEI type 0x0E runtime. It owns the connection
pool, scheduler, transaction owners, reconnect backoff, monotonic clock, and
replay event sequence. The lower-level runtime components cannot be
constructed independently by package consumers. Device Identification
traversal is bounded, preserves exact per-segment provenance, and publishes
only a complete validated aggregate.

`NewRuntimeAcquisitionSource` provides the optional bounded trust root for
successful TCP logical views. A configured endpoint marks only correlated,
coherent, still-attached `successful_data` views as eligible. The source binds
each issued capability to an exact documentary attempt key and a fresh opaque
attempt instance. Callers bind an immutable zero-based dependency ordinal at
issuance, so closing freezes declared membership independently of concurrent
registration order. Claims require that exact instance, copied capability
views share one one-shot state, and `CancelOpen` drains only that instance.
Fixture RTU views, synthetic values,
non-success responses, and offline normalization records have no issuance
authority. Capability and attempt state cannot be serialized or reconstructed.

Normalization is validated before retention and preserves its exact admitted
encoding, including whitespace, key order, escapes, and bounded unknown
extensions, through `Bytes` or `AppendJSON`. A successful restart export
atomically retires the old source before its sequence state can be restored.
Full wire and logical
provenance remains separate from capability identity. Live capabilities,
attempts, claim lifetime, terminal sequences, and non-reconstructing
tombstones are finite and configured before activation.

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
`helianthus-ebusreg`. Gateway composition is a later operator-requested
milestone.

## Phase-One Boundary

Phase one is read-only. Its complete implemented PDU operation allowlist is:

- FC03, Read Holding Registers;
- FC04, Read Input Registers;
- FC2B/MEI type 0x0E, Read Device Identification.

This list is both the implemented PDU boundary and the ceiling for later
phase-one transports. There is no generic function-code escape hatch and no
write PDU, probe, or control API. Write support requires separate safety work
and action-time confirmation before any live mutation.

M1-02 owns the aggregate FC03/FC04 endpoint. M1-04 owns bounded FC2B/MEI type
0x0E endpoint execution without exposing a lower-level socket bypass.

M1-03 owns typed FC03/FC04 RTU ADUs, CRC-16/Modbus, t1.5/t3.5 timing, and the
fixture owner state machine. It never opens or writes a physical serial line.
Possibly transmitted results and full-transmit response-wait abandonment enter
quarantine before waiter resolution. Quarantine discards every frame and
releases only after the configured response-latency horizon plus a complete
inter-frame idle proof. Failed quiescence requires explicit recovery and a new
transport generation.

Every queued TCP read receives one immutable absolute monotonic deadline.
Queueing, transport write, response wait, cancellation, and reconnect backoff
consume that same deadline; none starts a new relative window. A response-wait
timeout tombstones only the transmitted transaction. Other safe in-flight
transactions continue on the socket, and a late matching frame remains
request-bound diagnostic evidence without becoming deliverable.

Retryable read and Device Identification state remains endpoint-owned and
bounded while moving between socket generations. Device Identification retry
restarts at the initial cursor and discards every partial aggregate from the
failed attempt. A provable zero-byte write may re-enter the fair queue without
reconnect backoff. Any possibly transmitted write invalidates the socket and
requires endpoint-owned backoff before retry on a new generation. Canceling
the last retry does not bypass that endpoint recovery debt; the terminal handle
remains a bounded recovery-only token until backoff completes. Per-dependent
cancellation narrows the retained register-read plan, so retry cannot revive a
cancelled logical view. `Close` terminalizes active and retryable work, retires
every socket, and is idempotent.

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
gates. CI validates structural companion identities, acceptance mappings, and
their behavioral evidence without treating documentation hashes as authority.
Historical RED SHAs and run URLs are passive metadata: M1-02 through M1-04
validators are deterministic current-tree checks and do not fetch Git history
or query GitHub.
FMV3-M1-06 proves `OPAQUE_RUNTIME_ACQUISITION_V1`
through the source-owned API and executable behavioral inventory without
treating a documentation digest as runtime authority. Its RED evidence,
structural scope stop, and transport regression gate are recorded in
[`m1-06-conformance.json`](policy/m1-06-conformance.json).
FMV3-M1-02 runtime evidence is machine-checked by
[`policy/m1-02-acceptance.json`](policy/m1-02-acceptance.json) against that
structural contract identity. The gate executes every mapped test, requires explicit
run/pass events without skips, and locks every test file owned by M1-02 while
allowing later milestone test manifests to own their own files.
FMV3-M1-03 is independently checked by
[`policy/m1-03-acceptance.json`](policy/m1-03-acceptance.json) and its
fixture-only [RTU transport matrix](policy/m1-03-transport-matrix.json). That
gate proves the RED chain, offline-only product boundary, exact
`FIXTURE_ONLY_NO_HARDWARE` disposition, and every mapped RTU test. It performs
no gateway, serial-device, or physical-hardware validation.
FMV3-M1-04 is checked by
[`policy/m1-04-acceptance.json`](policy/m1-04-acceptance.json) and its combined
[transport matrix](policy/m1-04-transport-matrix.json). It proves bounded TCP
Device Identification traversal plus fixture-only RTU parity and recovery. It
also performs no gateway, serial-device, or physical-hardware validation.

The repository follows one issue and one pull request at a time, squash merge,
strict test-first implementation, and applicable documentation/protocol gates.
GitHub protects `main` with required `checks` and `lint` jobs, linear history,
conversation resolution, and disabled merge/rebase commit methods. Review and
merge require a fresh exact-HEAD `NO_BLOCKING_FINDINGS` verdict with
every P0-P2 finding resolved or independently validated by design. P3/P4
findings are triaged as fix, backlog, or by-design and do not force another
review round. No external review status or attestation is required. All
protections apply to administrators.
See [CONTRIBUTING.md](CONTRIBUTING.md) and [AGENTS.md](AGENTS.md).

## License

Implementation code and repository documentation are licensed under
[AGPL-3.0](LICENSE). Implementation-neutral protocol facts belong in the
Helianthus public `CC0-1.0` protocol-documentation lane, not in private
bindings. See the
[Helianthus licensing model](https://github.com/Project-Helianthus/.github/blob/main/LICENSING.md).
