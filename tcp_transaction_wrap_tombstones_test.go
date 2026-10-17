package modbus

import (
	"bytes"
	"reflect"
	"testing"
)

func TestTcpTransactionWrapSkipsActiveAndAbandonedIDs(t *testing.T) {
	owner, err := newTCPConnectionOwner("synthetic-wrap", 1, ConnectionLimits{
		MaxInFlight: 3, MaxTombstones: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	owner.nextTransactionID = 65535

	reserve := func(unit byte, offset, quantity uint16) TCPReservation {
		t.Helper()
		request, err := NewReadRegistersRequest(FunctionReadHoldingRegisters, offset, quantity)
		if err != nil {
			t.Fatal(err)
		}
		reservation, err := owner.ReserveRead(unit, request)
		if err != nil {
			t.Fatal(err)
		}
		return reservation
	}
	transmit := func(reservation TCPReservation) {
		t.Helper()
		if err := owner.MarkWriteInvoked(reservation); err != nil {
			t.Fatal(err)
		}
		transition, err := owner.RecordTransmit(reservation, TransmitComplete)
		if err != nil || transition.CloseConnection() || len(transition.FailedReservations()) != 0 {
			t.Fatalf("complete transmit: transition=%#v, err=%v", transition, err)
		}
	}

	abandoned := reserve(11, 10, 1)
	if abandoned.TransactionID() != 65535 || abandoned.PhysicalRequestID() != 1 {
		t.Fatalf("initial reservation: transaction=%d physical=%d", abandoned.TransactionID(), abandoned.PhysicalRequestID())
	}
	transmit(abandoned)
	if err := owner.AbandonResponseWait(abandoned, AbandonTimeout); err != nil {
		t.Fatal(err)
	}
	active := reserve(22, 20, 2)
	if active.TransactionID() != 0 || active.PhysicalRequestID() != 2 {
		t.Fatalf("wrapped active reservation: transaction=%d physical=%d", active.TransactionID(), active.PhysicalRequestID())
	}
	transmit(active)
	if len(owner.tombstones) != 1 || owner.tombstones[65535].physicalRequestID != 1 ||
		len(owner.inFlight) != 1 || owner.inFlight[0] == nil || owner.inFlight[0].physicalRequestID != 2 {
		t.Fatal("owner transitions did not establish tombstone 65535 and active ID 0")
	}

	// Only the cursor is reset; both occupied namespaces remain owner-managed.
	owner.nextTransactionID = 65535
	wrapped := reserve(33, 30, 3)
	if wrapped.TransactionID() != 1 || wrapped.PhysicalRequestID() != 3 {
		t.Errorf("free reservation: transaction=%d physical=%d; want transaction=1 physical=3", wrapped.TransactionID(), wrapped.PhysicalRequestID())
	}
	if len(owner.tombstones) != 1 || owner.tombstones[65535].physicalRequestID != 1 {
		t.Error("allocation replaced the abandoned record")
	}
	if len(owner.inFlight) != 2 || owner.inFlight[0] == nil || owner.inFlight[0].physicalRequestID != 2 {
		t.Error("allocation replaced the active record")
	}
	transmit(wrapped)

	cases := []struct {
		name        string
		transaction uint16
		physical    uint64
		unit        byte
		offset      uint16
		quantity    uint16
		pdu         []byte
		words       []uint16
		outcome     WireOutcome
		deliverable bool
	}{
		{"late abandoned", 65535, 1, 11, 10, 1, []byte{3, 2, 0x11, 0x11}, []uint16{0x1111}, WireLateAfterAbandonment, false},
		{"original active", 0, 2, 22, 20, 2, []byte{3, 4, 0x22, 0x22, 0x33, 0x33}, []uint16{0x2222, 0x3333}, WireSuccessfulData, true},
		{"new wrapped", 1, 3, 33, 30, 3, []byte{3, 6, 0x44, 0x44, 0x55, 0x55, 0x66, 0x66}, []uint16{0x4444, 0x5555, 0x6666}, WireSuccessfulData, true},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Literal wire IDs are independent of the allocator's returned handle.
			raw := []byte{byte(tc.transaction >> 8), byte(tc.transaction), 0, 0, 0, byte(len(tc.pdu) + 1), tc.unit}
			raw = append(raw, tc.pdu...)
			decoder, err := NewTCPStreamDecoder(260)
			if err != nil {
				t.Fatal(err)
			}
			frames, err := decoder.Feed(raw)
			if err != nil || len(frames) != 1 {
				t.Fatalf("synthetic frame: count=%d err=%v", len(frames), err)
			}
			response, err := owner.Correlate(1, frames[0])
			if err != nil {
				t.Fatal(err)
			}
			if response.Outcome() != tc.outcome || response.Deliverable() != tc.deliverable ||
				response.PhysicalRequestID() != tc.physical || response.WireResponseID() != uint64(i+1) ||
				response.DiagnosticFrameID() != 0 {
				t.Errorf("response identity/outcome = %#v", response)
			}
			provenance := response.Provenance()
			if provenance.UnitID != tc.unit || provenance.Offset != tc.offset || provenance.Quantity != tc.quantity ||
				provenance.RequestedFunction != FunctionReadHoldingRegisters || provenance.ReceivedFunction != FunctionReadHoldingRegisters {
				t.Errorf("response attribution = %#v", provenance)
			}
			if !bytes.Equal(response.Bytes(), raw) || !reflect.DeepEqual(response.Words(), tc.words) {
				t.Errorf("response content: bytes=%v words=%v", response.Bytes(), response.Words())
			}
		})
	}
	if len(owner.inFlight) != 0 || len(owner.tombstones) != 1 || owner.tombstones[65535].physicalRequestID != 1 {
		t.Fatal("responses did not complete active requests while retaining the original tombstone")
	}
}
