// Package modbus is the public Modbus protocol and runtime foundation for
// Helianthus.
//
// The package exposes strict vendor-neutral phase-one PDU codecs and a bounded,
// endpoint-owned FC03/FC04 plus FC2B/MEI0E Modbus TCP runtime. NewTCPEndpoint
// is the sole construction root for that aggregate and owns pooling,
// scheduling, absolute deadlines, correlation, bounded retry state, replay
// ordering, reconnect backoff, and shutdown. The RTU fixture surface remains
// offline-only and has the explicit experimental disposition
// FIXTURE_ONLY_NO_HARDWARE. RTUSerialStream is a generic, explicitly
// configured Linux byte-stream boundary; it does not discover devices, select
// vendor codecs, or admit operations. Physical qualification and vendor
// semantics remain separately owned qualification obligations.
//
// OpenRTUProductionEndpoint separately owns an explicitly enabled serial stream
// for upstream-admitted FC03/FC04 reads and an optional opaque private-function
// exchange. Private framing never selects a vendor codec or authorizes an
// operation. The standard public PDU reads are FC03, FC04, and FC2B/MEI0E;
// vendor identities, register meaning, profile admission, and qualification
// belong to the profile registry, not this package.
//
// Endpoint and session owners serialize their mutable transport state. Caller
// supplied clocks, streams, admission callbacks, and event sinks must honor their
// individual contracts. Results that retain native bytes or successful logical
// views alongside an error remain useful evidence; consumers must inspect both
// the result and error rather than discarding valid partial state.
package modbus
