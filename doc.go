// Package modbus is the public Modbus protocol and runtime foundation for
// Helianthus.
//
// The package exposes strict vendor-neutral phase-one PDU codecs and a bounded,
// endpoint-owned FC03/FC04 Modbus TCP runtime. NewTCPEndpoint is the sole
// construction root for that current aggregate and owns pooling, scheduling,
// absolute deadlines, correlation, bounded retry state, replay ordering,
// reconnect backoff, and shutdown. FC2B aggregate execution, RTU, and vendor
// semantics remain explicit later milestones.
package modbus
