package modbus

import (
	"math"
	"reflect"
	"sync"
	"testing"
	"time"
)

func testTCPFrame(t *testing.T, transactionID uint16, unitID byte, pdu []byte) TCPADU {
	t.Helper()
	length := len(pdu) + 1
	raw := []byte{
		byte(transactionID >> 8),
		byte(transactionID),
		0,
		0,
		byte(length >> 8),
		byte(length),
		unitID,
	}
	raw = append(raw, pdu...)
	decoder, err := NewTCPStreamDecoder(260)
	if err != nil {
		t.Fatal(err)
	}
	frames, err := decoder.Feed(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 1 {
		t.Fatalf("frames = %d", len(frames))
	}
	return frames[0]
}

func newTestConnectionOwner(t *testing.T, maxInFlight, maxTombstones int) *TCPConnectionOwner {
	t.Helper()
	owner, err := newTCPConnectionOwner(
		"tcp://192.0.2.10:502",
		1,
		ConnectionLimits{
			MaxInFlight:   maxInFlight,
			MaxTombstones: maxTombstones,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return owner
}

func TestOwnerCloseRetainsAllInFlightFailuresAcrossReconnect(t *testing.T) {
	owner := newTestConnectionOwner(t, 2, 2)
	request, _ := NewReadRegistersRequest(FunctionReadHoldingRegisters, 0, 1)
	first, _ := owner.ReserveRead(1, request)
	second, _ := owner.ReserveRead(2, request)
	owner.Close()
	if generation := owner.Reconnect(); generation != 2 {
		t.Fatalf("generation = %d", generation)
	}
	failed := owner.DrainFailedReservations()
	if len(failed) != 2 {
		t.Fatalf("failed reservations = %#v", failed)
	}
	got := map[uint64]bool{
		failed[0].PhysicalRequestID(): true,
		failed[1].PhysicalRequestID(): true,
	}
	if !got[first.PhysicalRequestID()] || !got[second.PhysicalRequestID()] {
		t.Fatalf("failed reservations = %#v", failed)
	}
}

func TestWireResponseRetainsCompleteReadProvenance(t *testing.T) {
	owner := newTestConnectionOwner(t, 1, 2)
	request, _ := NewReadRegistersRequest(
		FunctionReadInputRegisters,
		0x1234,
		2,
	)
	reservation, _ := owner.ReserveRead(7, request)
	_ = owner.MarkWriteInvoked(reservation)
	_, _ = owner.RecordTransmit(reservation, TransmitComplete)
	response, err := owner.Correlate(
		1,
		testTCPFrame(t, reservation.TransactionID(), 7, []byte{
			4, 4, 0x11, 0x22, 0x33, 0x44,
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	provenance := response.Provenance()
	if provenance.Endpoint != "tcp://192.0.2.10:502" ||
		provenance.Transport != TransportTCP ||
		provenance.TransportGeneration != 1 ||
		provenance.UnitID != 7 ||
		provenance.RequestedFunction != FunctionReadInputRegisters ||
		provenance.ReceivedFunction != FunctionReadInputRegisters ||
		provenance.Table != InputRegisters ||
		provenance.Offset != 0x1234 ||
		provenance.Quantity != 2 {
		t.Fatalf("provenance = %#v", provenance)
	}
	if !reflect.DeepEqual(response.Words(), []uint16{0x1122, 0x3344}) {
		t.Fatalf("words = %#v", response.Words())
	}
}

func TestWireResponseRetainsDeviceIDCursorProvenance(t *testing.T) {
	owner := newTestConnectionOwner(t, 1, 2)
	request, err := NewDeviceIDRequest(DeviceIDIndividual, 5)
	if err != nil {
		t.Fatal(err)
	}
	reservation, err := owner.ReserveDeviceID(3, request)
	if err != nil {
		t.Fatal(err)
	}
	_ = owner.MarkWriteInvoked(reservation)
	_, _ = owner.RecordTransmit(reservation, TransmitComplete)
	response, err := owner.Correlate(
		1,
		testTCPFrame(t, reservation.TransactionID(), 3, []byte{
			0x2b, 0x0e, 0x04, 0x83, 0, 0, 1, 5, 1, 'x',
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	provenance := response.Provenance()
	if provenance.DeviceIDAccess != DeviceIDIndividual ||
		provenance.DeviceIDObjectID != 5 ||
		provenance.RequestedFunction != FunctionEncapsulatedInterface {
		t.Fatalf("provenance = %#v", provenance)
	}
	segment, ok := response.DeviceIDSegment()
	if !ok ||
		segment.MoreFollows() ||
		segment.NextObjectID() != 0 ||
		len(segment.Objects()) != 1 ||
		segment.Objects()[0].ID != 5 {
		t.Fatalf("segment = %#v, %v", segment, ok)
	}
}

func TestConnectionOwnerUsesOneAllocatorAcrossUnits(t *testing.T) {
	owner := newTestConnectionOwner(t, 4, 4)
	request, _ := NewReadRegistersRequest(FunctionReadHoldingRegisters, 0, 1)
	first, err := owner.ReserveRead(1, request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := owner.ReserveRead(2, request)
	if err != nil {
		t.Fatal(err)
	}
	if first.TransactionID() == second.TransactionID() {
		t.Fatal("units received duplicate live transaction IDs")
	}
	if first.Generation() != 1 || second.Generation() != 1 {
		t.Fatal("reservation lost active generation")
	}
	if first.PhysicalRequestID() == second.PhysicalRequestID() {
		t.Fatal("physical request identities are not unique")
	}
}

func TestConnectionOwnerEnforcesInFlightBound(t *testing.T) {
	owner := newTestConnectionOwner(t, 1, 2)
	request, _ := NewReadRegistersRequest(FunctionReadInputRegisters, 0, 1)
	if _, err := owner.ReserveRead(1, request); err != nil {
		t.Fatal(err)
	}
	_, err := owner.ReserveRead(2, request)
	_ = requireProtocolError(t, err, ErrorInvalidRange)
}

func TestCancellationBeforeWriteAndProvableZeroDoNotTombstone(t *testing.T) {
	for _, mode := range []string{"cancel_before_write", "provable_zero"} {
		t.Run(mode, func(t *testing.T) {
			owner := newTestConnectionOwner(t, 1, 1)
			request, _ := NewReadRegistersRequest(FunctionReadHoldingRegisters, 0, 1)
			reservation, err := owner.ReserveRead(1, request)
			if err != nil {
				t.Fatal(err)
			}
			transactionID := reservation.TransactionID()
			if mode == "cancel_before_write" {
				if err := owner.CancelBeforeWrite(reservation); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := owner.MarkWriteInvoked(reservation); err != nil {
					t.Fatal(err)
				}
				transition, err := owner.RecordTransmit(
					reservation,
					TransmitProvableZero,
				)
				if err != nil {
					t.Fatal(err)
				}
				if transition.CloseConnection() {
					t.Fatal("provable-zero closed connection")
				}
			}
			next, err := owner.ReserveRead(1, request)
			if err != nil {
				t.Fatal(err)
			}
			if next.TransactionID() != transactionID {
				t.Fatalf("released ID = %d, reused %d", transactionID, next.TransactionID())
			}
		})
	}
}

func TestResponseWaitAbandonmentTombstonesAndDropsLateResponse(t *testing.T) {
	owner := newTestConnectionOwner(t, 2, 2)
	request, _ := NewReadRegistersRequest(FunctionReadHoldingRegisters, 0, 1)
	reservation, _ := owner.ReserveRead(7, request)
	if err := owner.MarkWriteInvoked(reservation); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.RecordTransmit(reservation, TransmitComplete); err != nil {
		t.Fatal(err)
	}
	if err := owner.AbandonResponseWait(reservation, AbandonTimeout); err != nil {
		t.Fatal(err)
	}
	next, err := owner.ReserveRead(7, request)
	if err != nil {
		t.Fatal(err)
	}
	if next.TransactionID() == reservation.TransactionID() {
		t.Fatal("same-socket tombstone was reused")
	}

	late, err := owner.Correlate(
		1,
		testTCPFrame(t, reservation.TransactionID(), 7, []byte{3, 2, 0, 1}),
	)
	if err != nil {
		t.Fatal(err)
	}
	if late.Outcome() != WireLateAfterAbandonment || late.Deliverable() {
		t.Fatalf("late response = %#v", late)
	}
	if late.WireResponseID() == 0 ||
		late.PhysicalRequestID() != reservation.PhysicalRequestID() {
		t.Fatal("late response lost request-bound identity")
	}
}

func TestSimultaneousResponseExpiryUsesPhysicalRequestIdentityOrder(
	t *testing.T,
) {
	owner := newTestConnectionOwner(t, 3, 3)
	request, _ := NewReadRegistersRequest(
		FunctionReadHoldingRegisters,
		0,
		1,
	)
	deadline := 5 * time.Second
	reservations := make([]TCPReservation, 0, 3)
	for unitID := byte(1); unitID <= 3; unitID++ {
		reservation, err := owner.reserveReadUntil(
			unitID,
			request,
			deadline,
		)
		if err != nil {
			t.Fatal(err)
		}
		if err := owner.MarkWriteInvoked(reservation); err != nil {
			t.Fatal(err)
		}
		if _, err := owner.RecordTransmit(
			reservation,
			TransmitComplete,
		); err != nil {
			t.Fatal(err)
		}
		reservations = append(reservations, reservation)
	}
	expired, transition, err := owner.abandonExpired(deadline)
	if err != nil || transition.CloseConnection() {
		t.Fatalf("transition=%#v err=%v", transition, err)
	}
	got := make([]uint64, 0, len(expired))
	for _, reservation := range expired {
		got = append(got, reservation.PhysicalRequestID())
	}
	want := []uint64{
		reservations[0].PhysicalRequestID(),
		reservations[1].PhysicalRequestID(),
		reservations[2].PhysicalRequestID(),
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expiry order=%v want=%v", got, want)
	}
}

func TestPossiblyTransmittedResultForcesReconnectGeneration(t *testing.T) {
	results := []TransmitResult{
		TransmitPartial,
		TransmitIndeterminate,
		TransmitCancellationRace,
		TransmitAmbiguous,
	}
	for _, result := range results {
		t.Run(result.String(), func(t *testing.T) {
			owner := newTestConnectionOwner(t, 1, 2)
			request, _ := NewReadRegistersRequest(FunctionReadInputRegisters, 0, 1)
			reservation, _ := owner.ReserveRead(1, request)
			if err := owner.MarkWriteInvoked(reservation); err != nil {
				t.Fatal(err)
			}
			transition, err := owner.RecordTransmit(reservation, result)
			if err != nil {
				t.Fatal(err)
			}
			if !transition.CloseConnection() || !owner.Closed() {
				t.Fatal("possibly transmitted result kept socket active")
			}
			if _, err := owner.ReserveRead(1, request); err == nil {
				t.Fatal("closed generation accepted new request")
			}
			if generation := owner.Reconnect(); generation != 2 {
				t.Fatalf("generation = %d, want 2", generation)
			}
			next, err := owner.ReserveRead(1, request)
			if err != nil {
				t.Fatal(err)
			}
			if next.Generation() != 2 {
				t.Fatal("new request retained old generation")
			}
			old, err := owner.Correlate(
				1,
				testTCPFrame(t, reservation.TransactionID(), 1, []byte{4, 2, 0, 1}),
			)
			if err != nil {
				t.Fatal(err)
			}
			if old.Outcome() != WireDroppedUncorrelated {
				t.Fatalf("old-generation response = %#v", old)
			}
		})
	}
}

func TestCorrelationValidatesUnitFunctionAndResponseShape(t *testing.T) {
	tests := []struct {
		name    string
		unitID  byte
		pdu     []byte
		outcome WireOutcome
	}{
		{"success", 3, []byte{3, 2, 0x12, 0x34}, WireSuccessfulData},
		{"exception", 3, []byte{0x83, 0x02}, WireProtocolException},
		{"malformed shape", 3, []byte{3, 4, 0, 1}, WireMalformedResponse},
		{"wrong unit", 4, []byte{3, 2, 0, 1}, WireDroppedUncorrelated},
		{"wrong function", 3, []byte{4, 2, 0, 1}, WireDroppedUncorrelated},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			owner := newTestConnectionOwner(t, 1, 2)
			request, _ := NewReadRegistersRequest(FunctionReadHoldingRegisters, 0, 1)
			reservation, _ := owner.ReserveRead(3, request)
			if err := owner.MarkWriteInvoked(reservation); err != nil {
				t.Fatal(err)
			}
			if _, err := owner.RecordTransmit(reservation, TransmitComplete); err != nil {
				t.Fatal(err)
			}
			response, err := owner.Correlate(
				1,
				testTCPFrame(t, reservation.TransactionID(), test.unitID, test.pdu),
			)
			if err != nil && test.outcome != WireMalformedResponse &&
				test.outcome != WireProtocolException {
				t.Fatal(err)
			}
			if response.Outcome() != test.outcome {
				t.Fatalf("outcome = %q, want %q", response.Outcome(), test.outcome)
			}
			if test.outcome == WireSuccessfulData && !response.Deliverable() {
				t.Fatal("successful response is not deliverable")
			}
			if test.outcome != WireSuccessfulData && response.Deliverable() {
				t.Fatal("non-success response became deliverable")
			}
		})
	}
}

func TestTombstoneExhaustionClosesSocket(t *testing.T) {
	owner := newTestConnectionOwner(t, 2, 1)
	request, _ := NewReadRegistersRequest(FunctionReadHoldingRegisters, 0, 1)
	first, _ := owner.ReserveRead(1, request)
	_ = owner.MarkWriteInvoked(first)
	_, _ = owner.RecordTransmit(first, TransmitComplete)
	_ = owner.AbandonResponseWait(first, AbandonCancellation)

	second, _ := owner.ReserveRead(1, request)
	_ = owner.MarkWriteInvoked(second)
	_, _ = owner.RecordTransmit(second, TransmitComplete)
	err := owner.AbandonResponseWait(second, AbandonTimeout)
	_ = requireProtocolError(t, err, ErrorInvalidRange)
	if !owner.Closed() {
		t.Fatal("tombstone exhaustion did not close socket")
	}
	late, correlateErr := owner.Correlate(
		1,
		testTCPFrame(
			t,
			second.TransactionID(),
			1,
			[]byte{3, 2, 0, 1},
		),
	)
	if correlateErr != nil {
		t.Fatal(correlateErr)
	}
	if late.Outcome() != WireLateAfterAbandonment ||
		late.PhysicalRequestID() != second.PhysicalRequestID() {
		t.Fatalf("closing tombstone response = %#v", late)
	}
}

func TestLateMalformedResponseRetainsIdentityButIsNotLateSuccess(t *testing.T) {
	owner := newTestConnectionOwner(t, 1, 2)
	request, _ := NewReadRegistersRequest(FunctionReadHoldingRegisters, 0, 1)
	reservation, _ := owner.ReserveRead(1, request)
	_ = owner.MarkWriteInvoked(reservation)
	_, _ = owner.RecordTransmit(reservation, TransmitComplete)
	_ = owner.AbandonResponseWait(reservation, AbandonTimeout)
	response, err := owner.Correlate(
		1,
		testTCPFrame(
			t,
			reservation.TransactionID(),
			1,
			[]byte{3, 4, 0, 1, 0, 2},
		),
	)
	_ = requireProtocolError(t, err, ErrorMalformedResponse)
	if response.Outcome() != WireMalformedResponse ||
		response.Deliverable() ||
		response.WireResponseID() == 0 ||
		response.PhysicalRequestID() != reservation.PhysicalRequestID() {
		t.Fatalf("malformed late response = %#v", response)
	}
}

func TestResponseBetweenWriteInvocationAndTransmitResultIsNotLost(t *testing.T) {
	owner := newTestConnectionOwner(t, 1, 2)
	request, _ := NewReadRegistersRequest(FunctionReadHoldingRegisters, 0, 1)
	reservation, _ := owner.ReserveRead(1, request)
	if err := owner.MarkWriteInvoked(reservation); err != nil {
		t.Fatal(err)
	}
	response, err := owner.Correlate(
		1,
		testTCPFrame(
			t,
			reservation.TransactionID(),
			1,
			[]byte{3, 2, 0, 1},
		),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !response.Deliverable() {
		t.Fatal("peer response proving full transmit was dropped")
	}
	if _, err := owner.RecordTransmit(reservation, TransmitComplete); err != nil {
		t.Fatal("late transport completion rejected:", err)
	}
}

func TestCorrelationAndAbandonmentRaceHasOneLinearizedOutcome(t *testing.T) {
	for iteration := 0; iteration < 100; iteration++ {
		owner := newTestConnectionOwner(t, 1, 2)
		request, _ := NewReadRegistersRequest(
			FunctionReadHoldingRegisters,
			0,
			1,
		)
		reservation, _ := owner.ReserveRead(1, request)
		_ = owner.MarkWriteInvoked(reservation)
		_, _ = owner.RecordTransmit(reservation, TransmitComplete)
		frame := testTCPFrame(
			t,
			reservation.TransactionID(),
			1,
			[]byte{3, 2, 0, 1},
		)
		start := make(chan struct{})
		var response WireResponse
		var responseErr error
		var abandonErr error
		var wait sync.WaitGroup
		wait.Add(2)
		go func() {
			defer wait.Done()
			<-start
			response, responseErr = owner.Correlate(1, frame)
		}()
		go func() {
			defer wait.Done()
			<-start
			abandonErr = owner.AbandonResponseWait(
				reservation,
				AbandonCancellation,
			)
		}()
		close(start)
		wait.Wait()
		if responseErr != nil {
			t.Fatal(responseErr)
		}
		deliveredFirst := response.Outcome() == WireSuccessfulData &&
			response.Deliverable() &&
			abandonErr != nil
		abandonedFirst := response.Outcome() == WireLateAfterAbandonment &&
			!response.Deliverable() &&
			abandonErr == nil
		if !deliveredFirst && !abandonedFirst {
			t.Fatalf(
				"response=%#v abandonErr=%v",
				response,
				abandonErr,
			)
		}
	}
}

func TestUncorrelatedFrameRetainsDiagnosticIdentityAndReceiptProvenance(
	t *testing.T,
) {
	owner := newTestConnectionOwner(t, 1, 2)
	owner.connectionID = 9
	request, _ := NewReadRegistersRequest(
		FunctionReadHoldingRegisters,
		0,
		1,
	)
	reservation, _ := owner.ReserveRead(3, request)
	_ = owner.MarkWriteInvoked(reservation)
	_, _ = owner.RecordTransmit(reservation, TransmitComplete)
	frame := testTCPFrame(
		t,
		reservation.TransactionID(),
		4,
		[]byte{3, 2, 0x12, 0x34},
	)
	response, err := owner.Correlate(1, frame)
	if err != nil {
		t.Fatal(err)
	}
	if response.Outcome() != WireDroppedUncorrelated ||
		response.DiagnosticFrameID() == 0 ||
		response.WireResponseID() != 0 ||
		response.PhysicalRequestID() != 0 ||
		!reflect.DeepEqual(response.Bytes(), frame.Bytes()) {
		t.Fatalf("diagnostic response = %#v", response)
	}
	provenance := response.DiagnosticProvenance()
	if provenance.Endpoint != "tcp://192.0.2.10:502" ||
		provenance.ConnectionID != 9 ||
		provenance.ReceivedTransportGeneration != 1 ||
		provenance.ActiveTransportGeneration != 1 ||
		provenance.UnitID != 4 ||
		provenance.ReceivedFunction != FunctionReadHoldingRegisters {
		t.Fatalf("diagnostic provenance = %#v", provenance)
	}

	owner.Close()
	if generation := owner.Reconnect(); generation != 2 {
		t.Fatalf("generation = %d", generation)
	}
	old, err := owner.Correlate(1, frame)
	if err != nil {
		t.Fatal(err)
	}
	oldProvenance := old.DiagnosticProvenance()
	if old.DiagnosticFrameID() == 0 ||
		old.DiagnosticFrameID() == response.DiagnosticFrameID() ||
		old.WireResponseID() != 0 ||
		old.PhysicalRequestID() != 0 ||
		!reflect.DeepEqual(old.Bytes(), frame.Bytes()) ||
		oldProvenance.ReceivedTransportGeneration != 1 ||
		oldProvenance.ActiveTransportGeneration != 2 {
		t.Fatalf("old-generation diagnostic = %#v", old)
	}
}

func TestOwnerIdentityCountersFailClosedAfterWrap(t *testing.T) {
	owner := newTestConnectionOwner(t, 2, 2)
	owner.nextPhysicalRequestID = math.MaxUint64
	request, _ := NewReadRegistersRequest(FunctionReadHoldingRegisters, 0, 1)
	last, err := owner.ReserveRead(1, request)
	if err != nil || last.PhysicalRequestID() != math.MaxUint64 {
		t.Fatalf("last physical identity = %#v, %v", last, err)
	}
	_, err = owner.ReserveRead(1, request)
	_ = requireProtocolError(t, err, ErrorInvalidRange)

	owner = newTestConnectionOwner(t, 2, 2)
	owner.nextWireResponseID = math.MaxUint64
	first, _ := owner.ReserveRead(1, request)
	_ = owner.MarkWriteInvoked(first)
	_, _ = owner.RecordTransmit(first, TransmitComplete)
	response, err := owner.Correlate(
		1,
		testTCPFrame(t, first.TransactionID(), 1, []byte{3, 2, 0, 1}),
	)
	if err != nil || response.WireResponseID() != math.MaxUint64 {
		t.Fatalf("last wire identity = %#v, %v", response, err)
	}
	second, _ := owner.ReserveRead(1, request)
	_ = owner.MarkWriteInvoked(second)
	_, _ = owner.RecordTransmit(second, TransmitComplete)
	_, err = owner.Correlate(
		1,
		testTCPFrame(t, second.TransactionID(), 1, []byte{3, 2, 0, 1}),
	)
	_ = requireProtocolError(t, err, ErrorInvalidRange)

	owner = newTestConnectionOwner(t, 1, 2)
	owner.nextDiagnosticFrameID = math.MaxUint64
	frame := testTCPFrame(t, 7, 1, []byte{3, 2, 0, 1})
	lastDiagnostic, err := owner.Correlate(1, frame)
	if err != nil ||
		lastDiagnostic.DiagnosticFrameID() != math.MaxUint64 {
		t.Fatalf("last diagnostic identity = %#v, %v", lastDiagnostic, err)
	}
	_, err = owner.Correlate(1, frame)
	_ = requireProtocolError(t, err, ErrorInvalidRange)
	if !owner.Closed() {
		t.Fatal("diagnostic identity exhaustion did not fail closed")
	}
}

func TestUnsafeTransmitTerminalizesSiblingInflightRequests(t *testing.T) {
	owner := newTestConnectionOwner(t, 2, 2)
	request, _ := NewReadRegistersRequest(FunctionReadHoldingRegisters, 0, 1)
	waiting, _ := owner.ReserveRead(1, request)
	_ = owner.MarkWriteInvoked(waiting)
	_, _ = owner.RecordTransmit(waiting, TransmitComplete)
	unsafe, _ := owner.ReserveRead(2, request)
	_ = owner.MarkWriteInvoked(unsafe)
	transition, err := owner.RecordTransmit(unsafe, TransmitPartial)
	if err != nil {
		t.Fatal(err)
	}
	failed := transition.FailedReservations()
	if len(failed) != 1 ||
		failed[0].PhysicalRequestID() != waiting.PhysicalRequestID() {
		t.Fatalf("sibling failures = %#v", failed)
	}
	if owner.Reconnect() != 2 {
		t.Fatal("controlled reconnect did not increment generation")
	}
	response, err := owner.Correlate(
		1,
		testTCPFrame(t, waiting.TransactionID(), 1, []byte{3, 2, 0, 1}),
	)
	if err != nil || response.Outcome() != WireDroppedUncorrelated {
		t.Fatalf("old sibling response = %#v, %v", response, err)
	}
}
