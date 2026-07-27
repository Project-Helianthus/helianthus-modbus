# helianthus-modbus

`helianthus-modbus` is the public Modbus protocol and transport/runtime
foundation for Helianthus.

## Status

The repository implements the strict vendor-neutral phase-one PDU layer:
validated FC03 and FC04 register reads, typed exception responses, and bounded
FC2B/MEI0E Device Identification segments and aggregation. TCP and RTU runtime
ownership remain separately authorized follow-up work.

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
