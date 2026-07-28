// Package modbus is the public Modbus protocol and runtime foundation for
// Helianthus.
//
// The package exposes strict vendor-neutral phase-one PDU codecs and a bounded,
// endpoint-owned FC03/FC04 Modbus TCP runtime. NewTCPEndpoint is the sole
// construction root for that current aggregate and owns pooling, scheduling,
// absolute deadlines, correlation, bounded retry state, replay ordering,
// reconnect backoff, and shutdown. The RTU surface is an offline, fixture-only
// FC03/FC04 owner with no serial-device admission and the explicit experimental
// disposition FIXTURE_ONLY_NO_HARDWARE. FC2B aggregate execution, physical RTU
// qualification, and vendor semantics remain explicit later milestones.
package modbus
