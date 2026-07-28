package modbus

import (
	"context"
	"errors"
	"io"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"
)

type blockingWriteConn struct {
	net.Conn
	started chan struct{}
	release chan struct{}
	closed  chan struct{}
	once    sync.Once
}

func (conn *blockingWriteConn) Write(buffer []byte) (int, error) {
	close(conn.started)
	select {
	case <-conn.release:
		return len(buffer), nil
	case <-conn.closed:
		return 0, net.ErrClosed
	}
}

func (conn *blockingWriteConn) Close() error {
	conn.once.Do(func() {
		close(conn.closed)
	})
	return conn.Conn.Close()
}

type delayedWriteReturnConn struct {
	net.Conn
	written chan struct{}
	release chan struct{}
}

func (conn *blockingWriteConn) Unwrap() net.Conn {
	return conn.Conn
}

func (conn *delayedWriteReturnConn) Unwrap() net.Conn {
	return conn.Conn
}

func (*blockingWriteConn) modbusTCPTrustedDecorator()      {}
func (*delayedWriteReturnConn) modbusTCPTrustedDecorator() {}

func (conn *delayedWriteReturnConn) Write(buffer []byte) (int, error) {
	written, err := conn.Conn.Write(buffer)
	close(conn.written)
	<-conn.release
	return written, err
}

func CoalesceReads(
	intents []ReadIntent,
	maxDependents int,
) (*CoalescedRead, error) {
	if maxDependents <= 0 || maxDependents > maxCoalescedDependents {
		return coalesceReads(intents, maxDependents)
	}
	total := maxDependents + 1
	scheduler, err := newEndpointScheduler(SchedulerLimits{
		MaxActiveAdmissionKeys:         1,
		ProtectedSlotsPerKey:           1,
		SharedBurstSlots:               1,
		TotalQueued:                    total,
		MaxQueuedPerKey:                total,
		MaxQueuedPerAuthorizationScope: total,
		MaxCoalescedDependentsPerKey:   maxDependents,
		MaxRetryAttempts:               1,
		MaxInFlightRequests:            1,
	})
	if err != nil {
		return nil, err
	}
	group, err := scheduleCoalescedForTest(scheduler, intents)
	if err != nil {
		return nil, err
	}
	if request, ok := scheduler.Dispatch(0); !ok ||
		request.RequestID != intents[0].spec.LogicalViewID {
		return nil, protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"test_coalesced_dispatch",
			-1,
		)
	}
	return group, nil
}

func scheduleCoalescedForTest(
	scheduler *EndpointScheduler,
	intents []ReadIntent,
) (*CoalescedRead, error) {
	if len(intents) == 0 {
		return nil, protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"test_coalesced_intents",
			-1,
		)
	}
	spec := intents[0].spec
	return scheduler.ScheduleCoalesced(
		ScheduledRequest{
			RequestID: spec.LogicalViewID,
			Key: AdmissionKey{
				AuthorizationScope: spec.AuthorizationScope,
				UnitID:             spec.UnitID,
			},
			DeadlineOffset: 1 << 62,
		},
		intents,
	)
}

func testReadIntent(
	t *testing.T,
	logicalViewID uint64,
	offset uint16,
	quantity uint16,
) ReadIntent {
	t.Helper()
	request, err := NewReadRegistersRequest(
		FunctionReadHoldingRegisters,
		offset,
		quantity,
	)
	if err != nil {
		t.Fatal(err)
	}
	intent, err := NewReadIntent(ReadIntentSpec{
		LogicalViewID:       logicalViewID,
		Endpoint:            "tcp://192.0.2.10:502",
		Transport:           TransportTCP,
		TransportGeneration: 7,
		UnitID:              1,
		AuthorizationScope:  "site-a",
		PollGeneration:      11,
		DeadlineIdentity:    13,
		Request:             request,
	})
	if err != nil {
		t.Fatal(err)
	}
	return intent
}

func TestCoalesceUnequalOverlappingReadsAndReplayExactViews(t *testing.T) {
	first := testReadIntent(t, 101, 10, 5)
	second := testReadIntent(t, 102, 12, 5)

	group, err := CoalesceReads([]ReadIntent{first, second}, 2)
	if err != nil {
		t.Fatal(err)
	}
	physical := group.PhysicalRequest()
	if physical.Offset() != 10 || physical.Quantity() != 7 {
		t.Fatalf(
			"physical range = [%d,%d), want [10,17)",
			physical.Offset(),
			uint32(physical.Offset())+uint32(physical.Quantity()),
		)
	}
	slices := group.Slices()
	if len(slices) != 2 {
		t.Fatalf("slices = %d", len(slices))
	}
	if slices[0].SliceOffset() != 0 || slices[0].SliceWordCount() != 5 {
		t.Fatalf("first slice = %#v", slices[0])
	}
	if slices[1].SliceOffset() != 2 || slices[1].SliceWordCount() != 5 {
		t.Fatalf("second slice = %#v", slices[1])
	}

	response := successfulCoalescedResponse(
		t,
		group,
		[]uint16{10, 11, 12, 13, 14, 15, 16},
	)
	views, err := group.ReplaySuccessfulResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	if len(views) != 2 {
		t.Fatalf("views = %d", len(views))
	}
	if views[0].WireResponseID() != response.WireResponseID() ||
		views[1].WireResponseID() != response.WireResponseID() {
		t.Fatal("logical views lost shared wire response identity")
	}
	if views[0].LogicalViewID() == views[1].LogicalViewID() {
		t.Fatal("coalesced dependents share a logical view identity")
	}
	if !reflect.DeepEqual(views[0].Words(), []uint16{10, 11, 12, 13, 14}) {
		t.Fatalf("first words = %#v", views[0].Words())
	}
	if !reflect.DeepEqual(views[1].Words(), []uint16{12, 13, 14, 15, 16}) {
		t.Fatalf("second words = %#v", views[1].Words())
	}
	if views[1].LogicalOffset() != 12 ||
		views[1].LogicalWordCount() != 5 ||
		views[1].SliceOffset() != 2 ||
		views[1].SliceWordCount() != 5 {
		t.Fatalf("second provenance = %#v", views[1])
	}
	provenance := views[1].Provenance()
	if provenance.PhysicalRequestID != response.PhysicalRequestID() ||
		provenance.Wire.TransportGeneration != 7 ||
		provenance.AuthorizationScope != "site-a" ||
		provenance.PollGeneration != 11 ||
		provenance.DeadlineIdentity != 13 ||
		provenance.LogicalOffset != 12 ||
		provenance.SliceOffset != 2 {
		t.Fatalf("self-contained provenance = %#v", provenance)
	}
	words := views[0].Words()
	words[0] = 0xffff
	if views[0].Words()[0] != 10 {
		t.Fatal("logical view aliases caller-owned words")
	}
}

func TestCoalescedQueuedCancellationRecomputesMinimalUnion(t *testing.T) {
	group, err := CoalesceReads(
		[]ReadIntent{
			testReadIntent(t, 1, 10, 2),
			testReadIntent(t, 2, 11, 1),
		},
		2,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := group.Cancel(1); err != nil {
		t.Fatal(err)
	}
	physical := group.PhysicalRequest()
	if physical.Offset() != 11 || physical.Quantity() != 1 {
		t.Fatalf(
			"physical offset=%d quantity=%d",
			physical.Offset(),
			physical.Quantity(),
		)
	}
}

func TestCoalescingRefusesEveryIdentityMismatchWithoutMutation(t *testing.T) {
	base := testReadIntent(t, 1, 10, 5)
	baseSpec := base.Spec()
	tests := []struct {
		name   string
		change func(*ReadIntentSpec)
	}{
		{"endpoint", func(spec *ReadIntentSpec) { spec.Endpoint = "tcp://192.0.2.11:502" }},
		{"transport", func(spec *ReadIntentSpec) { spec.Transport = TransportRTU }},
		{"generation", func(spec *ReadIntentSpec) { spec.TransportGeneration++ }},
		{"unit", func(spec *ReadIntentSpec) { spec.UnitID++ }},
		{"function and table", func(spec *ReadIntentSpec) {
			spec.Request, _ = NewReadRegistersRequest(FunctionReadInputRegisters, 12, 5)
		}},
		{"authorization", func(spec *ReadIntentSpec) { spec.AuthorizationScope = "site-b" }},
		{"poll generation", func(spec *ReadIntentSpec) { spec.PollGeneration++ }},
		{"deadline identity", func(spec *ReadIntentSpec) { spec.DeadlineIdentity++ }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			otherSpec := baseSpec
			otherSpec.LogicalViewID = 2
			otherSpec.Request, _ = NewReadRegistersRequest(
				FunctionReadHoldingRegisters,
				12,
				5,
			)
			test.change(&otherSpec)
			other, err := NewReadIntent(otherSpec)
			if err != nil {
				t.Fatal(err)
			}
			beforeBase := base.Spec()
			beforeOther := other.Spec()
			_, err = CoalesceReads([]ReadIntent{base, other}, 2)
			_ = requireProtocolError(t, err, ErrorInvalidRequest)
			if !reflect.DeepEqual(base.Spec(), beforeBase) ||
				!reflect.DeepEqual(other.Spec(), beforeOther) {
				t.Fatal("refused coalescing mutated an input")
			}
		})
	}
}

func TestCoalescingRefusesAdjacentDisjointAndOversizedUnion(t *testing.T) {
	tests := []struct {
		name   string
		first  ReadIntent
		second ReadIntent
	}{
		{"adjacent", testReadIntent(t, 1, 10, 5), testReadIntent(t, 2, 15, 5)},
		{"disjoint", testReadIntent(t, 1, 10, 5), testReadIntent(t, 2, 20, 5)},
		{"union over limit", testReadIntent(t, 1, 0, 125), testReadIntent(t, 2, 124, 2)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := CoalesceReads(
				[]ReadIntent{test.first, test.second},
				2,
			)
			_ = requireProtocolError(t, err, ErrorInvalidRange)
		})
	}
}

func TestCoalescedDependentCancellationTransitions(t *testing.T) {
	t.Run("queued final dependent suppresses physical request", func(t *testing.T) {
		group, err := CoalesceReads(
			[]ReadIntent{testReadIntent(t, 1, 10, 2)},
			1,
		)
		if err != nil {
			t.Fatal(err)
		}
		transition, err := group.Cancel(1)
		if err != nil {
			t.Fatal(err)
		}
		if transition.TransmitPhysical() || transition.AbandonTransport() {
			t.Fatalf("queued cancellation transition = %#v", transition)
		}
		if group.ActiveDependentCount() != 0 {
			t.Fatal("queued cancellation retained dependent")
		}
	})

	t.Run("bound pre-write final cancellation releases reservation", func(t *testing.T) {
		group, err := CoalesceReads(
			[]ReadIntent{testReadIntent(t, 1, 10, 2)},
			1,
		)
		if err != nil {
			t.Fatal(err)
		}
		owner, err := newTCPConnectionOwner(
			group.endpoint,
			group.intentGeneration,
			ConnectionLimits{MaxInFlight: 1, MaxTombstones: 1},
		)
		if err != nil {
			t.Fatal(err)
		}
		reservation, _ := owner.ReserveRead(
			group.unitID,
			group.PhysicalRequest(),
		)
		if err := group.BindReservation(reservation); err != nil {
			t.Fatal(err)
		}
		if _, err := group.Cancel(1); err != nil {
			t.Fatal(err)
		}
		if _, err := owner.ReserveRead(
			group.unitID,
			group.PhysicalRequest(),
		); err != nil {
			t.Fatal("pre-write cancellation leaked in-flight slot:", err)
		}
	})

	t.Run("attached cancellation detaches only that view", func(t *testing.T) {
		group, err := CoalesceReads(
			[]ReadIntent{
				testReadIntent(t, 1, 10, 3),
				testReadIntent(t, 2, 11, 2),
			},
			2,
		)
		if err != nil {
			t.Fatal(err)
		}
		owner, reservation := bindCoalescedGroup(t, group)
		transition, err := group.Cancel(1)
		if err != nil {
			t.Fatal(err)
		}
		if transition.AbandonTransport() {
			t.Fatal("one cancelled dependent abandoned active peer")
		}
		response := completeCoalescedResponse(
			t,
			owner,
			reservation,
			[]uint16{10, 11, 12},
		)
		views, err := group.ReplaySuccessfulResponse(response)
		if err != nil {
			t.Fatal(err)
		}
		if len(views) != 1 || views[0].LogicalViewID() != 2 {
			t.Fatalf("delivered views = %#v", views)
		}
	})

	t.Run("final attached cancellation abandons transport", func(t *testing.T) {
		group, err := CoalesceReads(
			[]ReadIntent{testReadIntent(t, 1, 10, 2)},
			1,
		)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = bindCoalescedGroup(t, group)
		transition, err := group.Cancel(1)
		if err != nil {
			t.Fatal(err)
		}
		if !transition.AbandonTransport() {
			t.Fatal("final attached cancellation did not abandon transport")
		}
	})

	t.Run("final cancellation after full transmit tombstones response", func(t *testing.T) {
		group, err := CoalesceReads(
			[]ReadIntent{testReadIntent(t, 1, 10, 2)},
			1,
		)
		if err != nil {
			t.Fatal(err)
		}
		owner, reservation := bindCoalescedGroup(t, group)
		if _, err := owner.RecordTransmit(
			reservation,
			TransmitComplete,
		); err != nil {
			t.Fatal(err)
		}
		transition, err := group.Cancel(1)
		if err != nil {
			t.Fatal(err)
		}
		if !transition.AbandonTransport() {
			t.Fatal("final cancellation did not report abandonment")
		}
		response, err := owner.Correlate(
			reservation.Generation(),
			testTCPFrame(
				t,
				reservation.TransactionID(),
				group.unitID,
				[]byte{3, 4, 0, 1, 0, 2},
			),
		)
		if err != nil {
			t.Fatal(err)
		}
		if response.Outcome() != WireLateAfterAbandonment ||
			response.Deliverable() {
			t.Fatalf("late response = %#v", response)
		}
	})
}

func bindCoalescedGroup(
	t *testing.T,
	group *CoalescedRead,
) (*TCPConnectionOwner, TCPReservation) {
	t.Helper()
	owner, err := newTCPConnectionOwner(
		group.endpoint,
		group.intentGeneration,
		ConnectionLimits{MaxInFlight: 2, MaxTombstones: 2},
	)
	if err != nil {
		t.Fatal(err)
	}
	reservation, err := owner.ReserveRead(group.unitID, group.PhysicalRequest())
	if err != nil {
		t.Fatal(err)
	}
	if err := group.BindReservation(reservation); err != nil {
		t.Fatal(err)
	}
	if _, err := group.invokeWrite(nil, func(
		TCPReservation,
	) (OwnerTransition, error) {
		return OwnerTransition{}, nil
	}); err != nil {
		t.Fatal(err)
	}
	return owner, reservation
}

func TestTCPTransportOwnsCoalescedWriteBoundary(t *testing.T) {
	group, err := CoalesceReads(
		[]ReadIntent{
			testReadIntent(t, 1, 10, 2),
			testReadIntent(t, 2, 11, 2),
		},
		2,
	)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := newTCPConnectionOwner(
		group.endpoint,
		group.intentGeneration,
		ConnectionLimits{MaxInFlight: 1, MaxTombstones: 1},
	)
	if err != nil {
		t.Fatal(err)
	}
	reservation, err := owner.ReserveRead(group.unitID, group.PhysicalRequest())
	if err != nil {
		t.Fatal(err)
	}
	if err := group.BindReservation(reservation); err != nil {
		t.Fatal(err)
	}
	client, server := net.Pipe()
	defer func() { _ = server.Close() }()
	transport, err := newTCPTransport(client, owner, 260)
	if err != nil {
		t.Fatal(err)
	}
	serverDone := make(chan error, 1)
	go func() {
		requestADU := make([]byte, 12)
		_, err := io.ReadFull(server, requestADU)
		serverDone <- err
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := transport.WriteCoalesced(ctx, group); err != nil {
		t.Fatal(err)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	states := group.DependentStates()
	if states[1] != DependentAttached || states[2] != DependentAttached {
		t.Fatalf("dependent states = %#v", states)
	}
	if _, err := owner.RecordTransmit(reservation, TransmitComplete); err == nil {
		t.Fatal("transport write did not own transmit classification")
	}
}

func TestCoalescedGroupRegisteredBeforeEarlyResponseAndUnregisteredOnReplay(
	t *testing.T,
) {
	group, err := CoalesceReads(
		[]ReadIntent{
			testReadIntent(t, 1, 10, 2),
			testReadIntent(t, 2, 11, 2),
		},
		2,
	)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := newTCPConnectionOwner(
		group.endpoint,
		group.intentGeneration,
		ConnectionLimits{MaxInFlight: 1, MaxTombstones: 1},
	)
	if err != nil {
		t.Fatal(err)
	}
	reservation, err := owner.ReserveRead(group.unitID, group.PhysicalRequest())
	if err != nil {
		t.Fatal(err)
	}
	if err := group.BindReservation(reservation); err != nil {
		t.Fatal(err)
	}
	client, server := net.Pipe()
	defer func() { _ = server.Close() }()
	conn := &delayedWriteReturnConn{
		Conn:    client,
		written: make(chan struct{}),
		release: make(chan struct{}),
	}
	transport, err := newTCPTransport(conn, owner, 260)
	if err != nil {
		t.Fatal(err)
	}
	serverDone := make(chan error, 1)
	go func() {
		requestADU := make([]byte, 12)
		if _, err := io.ReadFull(server, requestADU); err != nil {
			serverDone <- err
			return
		}
		_, err := server.Write(
			[]byte{
				0, 0, 0, 0, 0, 9, 1, 3, 6,
				0, 10, 0, 11, 0, 12,
			},
		)
		serverDone <- err
	}()
	writeDone := make(chan error, 1)
	go func() {
		_, err := transport.WriteCoalesced(context.Background(), group)
		writeDone <- err
	}()
	<-conn.written
	if got := registeredCoalescedCount(transport); got != 1 {
		t.Fatalf("registered groups before write return = %d", got)
	}
	responses, transition, err := transport.ReadResponses(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if transition.CloseConnection() || len(responses) != 1 {
		t.Fatalf("responses=%#v transition=%#v", responses, transition)
	}
	if got := registeredCoalescedCount(transport); got != 0 {
		t.Fatalf("registered groups after correlation = %d", got)
	}
	views, err := group.ReplaySuccessfulResponse(responses[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(views) != 2 {
		t.Fatalf("logical views = %#v", views)
	}
	close(conn.release)
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	if got := registeredCoalescedCount(transport); got != 0 {
		t.Fatalf("completed group leaked registration = %d", got)
	}
}

func registeredCoalescedCount(transport *TCPTransport) int {
	transport.closeMu.Lock()
	defer transport.closeMu.Unlock()
	return len(transport.coalesced)
}

func TestSocketLossBeforeCoalescedWriteTerminatesDependents(t *testing.T) {
	group, err := CoalesceReads(
		[]ReadIntent{
			testReadIntent(t, 1, 10, 2),
			testReadIntent(t, 2, 11, 2),
		},
		2,
	)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := newTCPConnectionOwner(
		group.endpoint,
		group.intentGeneration,
		ConnectionLimits{MaxInFlight: 1, MaxTombstones: 1},
	)
	if err != nil {
		t.Fatal(err)
	}
	reservation, _ := owner.ReserveRead(group.unitID, group.PhysicalRequest())
	if err := group.BindReservation(reservation); err != nil {
		t.Fatal(err)
	}
	client, server := net.Pipe()
	defer func() { _ = server.Close() }()
	transport, err := newTCPTransport(client, owner, 260)
	if err != nil {
		t.Fatal(err)
	}
	owner.Close()
	if _, err := transport.WriteCoalesced(
		context.Background(),
		group,
	); err == nil {
		t.Fatal("stale transport write returned nil")
	}
	states := group.DependentStates()
	if states[1] != DependentFailed || states[2] != DependentFailed {
		t.Fatalf("dependent states = %#v", states)
	}
	if _, err := scheduleCoalescedForTest(
		group.scheduler,
		[]ReadIntent{
			testReadIntent(t, 3, 20, 2),
			testReadIntent(t, 4, 21, 2),
		},
	); err != nil {
		t.Fatal("failed group retained scheduler capacity:", err)
	}
}

func TestSocketLossAfterCoalescedWriteTerminatesDependents(t *testing.T) {
	group, err := CoalesceReads(
		[]ReadIntent{
			testReadIntent(t, 1, 10, 2),
			testReadIntent(t, 2, 11, 2),
		},
		2,
	)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := newTCPConnectionOwner(
		group.endpoint,
		group.intentGeneration,
		ConnectionLimits{MaxInFlight: 1, MaxTombstones: 1},
	)
	if err != nil {
		t.Fatal(err)
	}
	reservation, _ := owner.ReserveRead(group.unitID, group.PhysicalRequest())
	if err := group.BindReservation(reservation); err != nil {
		t.Fatal(err)
	}
	client, server := net.Pipe()
	transport, err := newTCPTransport(client, owner, 260)
	if err != nil {
		t.Fatal(err)
	}
	serverDone := make(chan error, 1)
	go func() {
		requestADU := make([]byte, 12)
		_, err := io.ReadFull(server, requestADU)
		serverDone <- err
	}()
	if _, err := transport.WriteCoalesced(
		context.Background(),
		group,
	); err != nil {
		t.Fatal(err)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	if _, transition, err := transport.ReadResponses(
		context.Background(),
	); !errors.Is(err, io.EOF) || !transition.CloseConnection() {
		t.Fatalf("read error=%v transition=%#v", err, transition)
	}
	states := group.DependentStates()
	if states[1] != DependentFailed || states[2] != DependentFailed {
		t.Fatalf("dependent states = %#v", states)
	}
	if _, err := scheduleCoalescedForTest(
		group.scheduler,
		[]ReadIntent{
			testReadIntent(t, 3, 20, 2),
			testReadIntent(t, 4, 21, 2),
		},
	); err != nil {
		t.Fatal("terminal group retained scheduler capacity:", err)
	}
}

func TestCoalescedCancellationCannotCrossWriteInvocationGap(t *testing.T) {
	group, err := CoalesceReads([]ReadIntent{
		testReadIntent(t, 1, 10, 2),
	}, 1)
	if err != nil {
		t.Fatal(err)
	}
	owner, _ := newTCPConnectionOwner(
		group.endpoint,
		group.intentGeneration,
		ConnectionLimits{MaxInFlight: 1, MaxTombstones: 1},
	)
	reservation, _ := owner.ReserveRead(group.unitID, group.PhysicalRequest())
	if err := group.BindReservation(reservation); err != nil {
		t.Fatal(err)
	}
	client, server := net.Pipe()
	defer func() { _ = server.Close() }()
	conn := &blockingWriteConn{
		Conn:    client,
		started: make(chan struct{}),
		release: make(chan struct{}),
		closed:  make(chan struct{}),
	}
	transport, err := newTCPTransport(conn, owner, 260)
	if err != nil {
		t.Fatal(err)
	}
	writeDone := make(chan error, 1)
	go func() {
		_, err := transport.WriteCoalesced(context.Background(), group)
		writeDone <- err
	}()
	<-conn.started
	cancelAttempted := make(chan struct{})
	cancelDone := make(chan struct {
		transition CoalescedTransition
		err        error
	}, 1)
	go func() {
		close(cancelAttempted)
		transition, err := group.Cancel(1)
		cancelDone <- struct {
			transition CoalescedTransition
			err        error
		}{transition: transition, err: err}
	}()
	<-cancelAttempted
	var cancelled struct {
		transition CoalescedTransition
		err        error
	}
	select {
	case cancelled = <-cancelDone:
	case <-time.After(time.Second):
		t.Fatal("dependent cancellation blocked behind active socket write")
	}
	if cancelled.err != nil {
		t.Fatal(cancelled.err)
	}
	if !cancelled.transition.AbandonTransport() ||
		!cancelled.transition.CloseConnection() ||
		!owner.Closed() {
		t.Fatalf(
			"transition=%#v owner_closed=%v",
			cancelled.transition,
			owner.Closed(),
		)
	}
	if err := <-writeDone; err == nil {
		t.Fatal("abandoned active write returned nil")
	}
	if states := group.DependentStates(); states[1] != DependentCancelled {
		t.Fatalf("dependent states = %#v", states)
	}
}

func TestOwnerCloseAfterCoalescedReservationTerminalizesGroup(t *testing.T) {
	group, err := CoalesceReads(
		[]ReadIntent{
			testReadIntent(t, 1, 10, 2),
			testReadIntent(t, 2, 11, 2),
		},
		2,
	)
	if err != nil {
		t.Fatal(err)
	}
	owner, _ := newTCPConnectionOwner(
		group.endpoint,
		group.intentGeneration,
		ConnectionLimits{MaxInFlight: 1, MaxTombstones: 1},
	)
	reservation, _ := owner.ReserveRead(group.unitID, group.PhysicalRequest())
	if err := group.BindReservation(reservation); err != nil {
		t.Fatal(err)
	}
	client, server := net.Pipe()
	defer func() { _ = server.Close() }()
	conn := &blockingWriteConn{
		Conn:    client,
		started: make(chan struct{}),
		release: make(chan struct{}),
		closed:  make(chan struct{}),
	}
	transport, err := newTCPTransport(conn, owner, 260)
	if err != nil {
		t.Fatal(err)
	}
	writeDone := make(chan error, 1)
	go func() {
		_, err := transport.WriteCoalesced(context.Background(), group)
		writeDone <- err
	}()
	<-conn.started
	owner.Close()
	select {
	case err := <-writeDone:
		if err == nil {
			t.Fatal("owner close race returned nil")
		}
	case <-time.After(time.Second):
		t.Fatal("owner close did not interrupt active write")
	}
	states := group.DependentStates()
	if states[1] != DependentFailed || states[2] != DependentFailed {
		t.Fatalf("dependent states = %#v", states)
	}
	if _, err := scheduleCoalescedForTest(
		group.scheduler,
		[]ReadIntent{
			testReadIntent(t, 3, 20, 2),
			testReadIntent(t, 4, 21, 2),
		},
	); err != nil {
		t.Fatal("close race retained scheduler capacity:", err)
	}
}

func TestCoalescedMarkWriteFailureUnregistersAndReleasesReservation(
	t *testing.T,
) {
	group, err := CoalesceReads([]ReadIntent{
		testReadIntent(t, 1, 10, 2),
	}, 1)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := newTCPConnectionOwner(
		group.endpoint,
		group.intentGeneration,
		ConnectionLimits{MaxInFlight: 1, MaxTombstones: 1},
	)
	if err != nil {
		t.Fatal(err)
	}
	reservation, err := owner.ReserveRead(
		group.unitID,
		group.PhysicalRequest(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := group.BindReservation(reservation); err != nil {
		t.Fatal(err)
	}
	client, server := net.Pipe()
	defer func() { _ = server.Close() }()
	var corruptOnce sync.Once
	sink := &recordingTCPEventSink{
		hook: func(event TCPTransportEvent) {
			if event.Kind != TCPEventWritePrepared {
				return
			}
			corruptOnce.Do(func() {
				owner.mu.Lock()
				owner.inFlight[reservation.TransactionID()].
					physicalRequestID++
				owner.mu.Unlock()
			})
		},
	}
	transport, err := newTCPTransportWithConfig(
		client,
		owner,
		TCPTransportConfig{
			MaxBufferedBytes: 260,
			RequestDeadline:  time.Second,
			ResponseDeadline: time.Second,
			Clock:            &virtualTCPClock{},
			EventSink:        sink,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	transition, err := transport.WriteCoalesced(
		context.Background(),
		group,
	)
	if err == nil {
		t.Fatal("corrupt coalesced reservation reached socket write")
	}
	if transition.CloseConnection() || owner.Closed() {
		t.Fatalf(
			"recoverable mark failure closed transport: %#v",
			transition,
		)
	}
	if got := registeredCoalescedCount(transport); got != 0 {
		t.Fatalf("failed mark retained %d coalesced registrations", got)
	}
	if states := group.DependentStates(); states[1] != DependentFailed {
		t.Fatalf("dependent states = %#v", states)
	}
	if _, err := owner.ReserveRead(
		group.unitID,
		group.PhysicalRequest(),
	); err != nil {
		t.Fatal("failed mark retained owner capacity:", err)
	}
	owner.Close()
}

func TestClosedTransportRegistrationDoesNotDeadlockGroup(t *testing.T) {
	group, err := CoalesceReads([]ReadIntent{
		testReadIntent(t, 1, 10, 2),
	}, 1)
	if err != nil {
		t.Fatal(err)
	}
	owner, _ := newTCPConnectionOwner(
		group.endpoint,
		group.intentGeneration,
		ConnectionLimits{MaxInFlight: 1, MaxTombstones: 1},
	)
	reservation, _ := owner.ReserveRead(group.unitID, group.PhysicalRequest())
	if err := group.BindReservation(reservation); err != nil {
		t.Fatal(err)
	}
	client, server := net.Pipe()
	defer func() { _ = server.Close() }()
	transport, err := newTCPTransport(client, owner, 260)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := group.invokeWrite(
		transport,
		func(reservation TCPReservation) (OwnerTransition, error) {
			return owner.RecordTransmit(reservation, TransmitComplete)
		},
	); err != nil {
		t.Fatal(err)
	}
	if _, err := transport.closeTerminal(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- transport.registerCoalesced(reservation, group)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("closed transport registration deadlocked")
	}
	if states := group.DependentStates(); states[1] != DependentFailed {
		t.Fatalf("dependent states = %#v", states)
	}
}

func TestOwnerCloseAfterSuccessfulCoalescedWriteFailsGroup(t *testing.T) {
	group, err := CoalesceReads(
		[]ReadIntent{
			testReadIntent(t, 1, 10, 2),
			testReadIntent(t, 2, 11, 2),
		},
		2,
	)
	if err != nil {
		t.Fatal(err)
	}
	owner, _ := newTCPConnectionOwner(
		group.endpoint,
		group.intentGeneration,
		ConnectionLimits{MaxInFlight: 1, MaxTombstones: 1},
	)
	reservation, _ := owner.ReserveRead(group.unitID, group.PhysicalRequest())
	if err := group.BindReservation(reservation); err != nil {
		t.Fatal(err)
	}
	client, server := net.Pipe()
	transport, err := newTCPTransport(client, owner, 260)
	if err != nil {
		t.Fatal(err)
	}
	serverDone := make(chan error, 1)
	go func() {
		requestADU := make([]byte, 12)
		_, err := io.ReadFull(server, requestADU)
		serverDone <- err
	}()
	if _, err := transport.WriteCoalesced(
		context.Background(),
		group,
	); err != nil {
		t.Fatal(err)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	owner.Close()
	states := group.DependentStates()
	if states[1] != DependentFailed || states[2] != DependentFailed {
		t.Fatalf("dependent states = %#v", states)
	}
	if _, err := scheduleCoalescedForTest(
		group.scheduler,
		[]ReadIntent{
			testReadIntent(t, 3, 20, 2),
			testReadIntent(t, 4, 21, 2),
		},
	); err != nil {
		t.Fatal("owner close retained scheduler capacity:", err)
	}
	buffer := make([]byte, 1)
	if _, err := server.Read(buffer); !errors.Is(err, io.EOF) {
		t.Fatalf("peer read error = %v", err)
	}
}

func TestCoalescedTombstoneExhaustionReleasesPooledTransport(t *testing.T) {
	pool, _ := newTCPEndpointPool(
		"tcp://192.0.2.10:502",
		EndpointPoolLimits{
			MaxConnections: 1,
			Connection: ConnectionLimits{
				MaxInFlight:   1,
				MaxTombstones: 1,
			},
		},
	)
	lease, _ := pool.openConnection()
	owner := lease.ownerForEndpoint()
	client, server := net.Pipe()
	defer func() { _ = server.Close() }()
	transport, err := newTCPTransport(client, owner, 260)
	if err != nil {
		t.Fatal(err)
	}
	makeGroup := func(viewID uint64, offset uint16) *CoalescedRead {
		intent := testReadIntent(t, viewID, offset, 1)
		intent.spec.TransportGeneration = owner.Generation()
		group, err := CoalesceReads([]ReadIntent{intent}, 1)
		if err != nil {
			t.Fatal(err)
		}
		reservation, err := owner.ReserveRead(
			group.unitID,
			group.PhysicalRequest(),
		)
		if err != nil {
			t.Fatal(err)
		}
		if err := group.BindReservation(reservation); err != nil {
			t.Fatal(err)
		}
		if _, err := group.invokeWrite(
			transport,
			func(reservation TCPReservation) (OwnerTransition, error) {
				return owner.RecordTransmit(reservation, TransmitComplete)
			},
		); err != nil {
			t.Fatal(err)
		}
		if err := transport.registerCoalesced(reservation, group); err != nil {
			t.Fatal(err)
		}
		return group
	}
	first := makeGroup(1, 10)
	if transition, err := first.Cancel(1); err != nil ||
		!transition.AbandonTransport() {
		t.Fatalf("first cancel transition=%#v error=%v", transition, err)
	}
	second := makeGroup(2, 20)
	transition, err := second.Cancel(2)
	if err == nil || !transition.AbandonTransport() {
		t.Fatalf("second cancel transition=%#v error=%v", transition, err)
	}
	if pool.ActiveConnections() != 0 || lease.ownerForEndpoint() != nil {
		t.Fatalf(
			"active=%d lease_owner=%p",
			pool.ActiveConnections(),
			lease.ownerForEndpoint(),
		)
	}
	if _, err := pool.openConnection(); err != nil {
		t.Fatal("coalesced exhaustion retained pool slot:", err)
	}
}

func completeCoalescedResponse(
	t *testing.T,
	owner *TCPConnectionOwner,
	reservation TCPReservation,
	words []uint16,
) WireResponse {
	t.Helper()
	if _, err := owner.RecordTransmit(reservation, TransmitComplete); err != nil {
		t.Fatal(err)
	}
	pdu := []byte{
		byte(FunctionReadHoldingRegisters),
		byte(len(words) * 2),
	}
	for _, word := range words {
		pdu = append(pdu, byte(word>>8), byte(word))
	}
	response, err := owner.Correlate(
		reservation.Generation(),
		testTCPFrame(t, reservation.TransactionID(), groupUnitID(t, owner, reservation), pdu),
	)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func groupUnitID(
	t *testing.T,
	owner *TCPConnectionOwner,
	reservation TCPReservation,
) byte {
	t.Helper()
	owner.mu.Lock()
	defer owner.mu.Unlock()
	request := owner.inFlight[reservation.TransactionID()]
	if request == nil {
		t.Fatal("missing bound request")
	}
	return request.unitID
}

func successfulCoalescedResponse(
	t *testing.T,
	group *CoalescedRead,
	words []uint16,
) WireResponse {
	t.Helper()
	owner, reservation := bindCoalescedGroup(t, group)
	return completeCoalescedResponse(t, owner, reservation, words)
}

func TestCoalescedReplayRequiresBoundPostWriteCorrelatedResponse(t *testing.T) {
	group, err := CoalesceReads(
		[]ReadIntent{testReadIntent(t, 1, 10, 2)},
		1,
	)
	if err != nil {
		t.Fatal(err)
	}
	_, err = group.ReplaySuccessfulResponse(WireResponse{})
	_ = requireProtocolError(t, err, ErrorInvalidRequest)

	otherGroup, err := CoalesceReads(
		[]ReadIntent{testReadIntent(t, 2, 10, 2)},
		1,
	)
	if err != nil {
		t.Fatal(err)
	}
	otherResponse := successfulCoalescedResponse(
		t,
		otherGroup,
		[]uint16{1, 2},
	)
	owner, reservation := bindCoalescedGroup(t, group)
	_, err = group.ReplaySuccessfulResponse(otherResponse)
	_ = requireProtocolError(t, err, ErrorInvalidRequest)
	response := completeCoalescedResponse(
		t,
		owner,
		reservation,
		[]uint16{1, 2},
	)
	if _, err := group.ReplaySuccessfulResponse(response); err != nil {
		t.Fatal(err)
	}
}

func TestCoalescingEnforcesDependentBoundBeforeAllocation(t *testing.T) {
	_, err := CoalesceReads(
		[]ReadIntent{
			testReadIntent(t, 1, 10, 2),
			testReadIntent(t, 2, 10, 2),
			testReadIntent(t, 3, 10, 2),
		},
		2,
	)
	_ = requireProtocolError(t, err, ErrorInvalidRange)
	for _, limit := range []int{0, -1, maxCoalescedDependents + 1} {
		_, err = CoalesceReads(
			[]ReadIntent{testReadIntent(t, 1, 10, 2)},
			limit,
		)
		_ = requireProtocolError(t, err, ErrorInvalidRequest)
	}
}

func TestCoalescedFailureTerminatesAttachedDependents(t *testing.T) {
	group, err := CoalesceReads(
		[]ReadIntent{
			testReadIntent(t, 1, 10, 2),
			testReadIntent(t, 2, 10, 2),
		},
		2,
	)
	if err != nil {
		t.Fatal(err)
	}
	owner, reservation := bindCoalescedGroup(t, group)
	if _, err := owner.RecordTransmit(reservation, TransmitComplete); err != nil {
		t.Fatal(err)
	}
	response, correlateErr := owner.Correlate(
		reservation.Generation(),
		testTCPFrame(
			t,
			reservation.TransactionID(),
			1,
			[]byte{0x83, 0x02},
		),
	)
	_ = requireProtocolError(t, correlateErr, ErrorExceptionResponse)
	if err := group.Fail(response); err != nil {
		t.Fatal(err)
	}
	states := group.DependentStates()
	if states[1] != DependentFailed || states[2] != DependentFailed {
		t.Fatalf("terminal states = %#v", states)
	}
	if _, err := group.Cancel(1); err == nil {
		t.Fatal("failed dependent accepted cancellation")
	}
	if _, err := group.ReplaySuccessfulResponse(response); err == nil {
		t.Fatal("failed group accepted replay")
	}
}

func TestCoalescedTransportFailureTerminatesQueuedDependents(t *testing.T) {
	group, err := CoalesceReads(
		[]ReadIntent{testReadIntent(t, 1, 10, 2)},
		1,
	)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := newTCPConnectionOwner(
		group.endpoint,
		group.intentGeneration,
		ConnectionLimits{MaxInFlight: 1, MaxTombstones: 1},
	)
	if err != nil {
		t.Fatal(err)
	}
	reservation, err := owner.ReserveRead(1, group.PhysicalRequest())
	if err != nil {
		t.Fatal(err)
	}
	if err := group.BindReservation(reservation); err != nil {
		t.Fatal(err)
	}
	if err := group.FailTransport(); err != nil {
		t.Fatal(err)
	}
	if group.DependentStates()[1] != DependentFailed {
		t.Fatalf("states = %#v", group.DependentStates())
	}
}

func TestCoalescedBindingRejectsWrongGenerationUnitAndRange(t *testing.T) {
	tests := []struct {
		name       string
		generation uint64
		unitID     byte
		offset     uint16
	}{
		{"generation", 8, 1, 10},
		{"unit", 7, 2, 10},
		{"range", 7, 1, 20},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			group, err := CoalesceReads(
				[]ReadIntent{testReadIntent(t, 1, 10, 2)},
				1,
			)
			if err != nil {
				t.Fatal(err)
			}
			owner, err := newTCPConnectionOwner(
				group.endpoint,
				test.generation,
				ConnectionLimits{MaxInFlight: 1, MaxTombstones: 1},
			)
			if err != nil {
				t.Fatal(err)
			}
			request, _ := NewReadRegistersRequest(
				FunctionReadHoldingRegisters,
				test.offset,
				2,
			)
			reservation, err := owner.ReserveRead(test.unitID, request)
			if err != nil {
				t.Fatal(err)
			}
			err = group.BindReservation(reservation)
			_ = requireProtocolError(t, err, ErrorInvalidRequest)
		})
	}
}

func TestSchedulerOwnsAggregateCoalescedDependentBound(t *testing.T) {
	scheduler := testScheduler(t)
	first, err := scheduleCoalescedForTest(scheduler, []ReadIntent{
		testReadIntent(t, 1, 10, 2),
		testReadIntent(t, 2, 10, 2),
		testReadIntent(t, 3, 10, 2),
		testReadIntent(t, 4, 10, 2),
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = scheduleCoalescedForTest(
		scheduler,
		[]ReadIntent{testReadIntent(t, 5, 10, 2)},
	)
	_ = requireProtocolError(t, err, ErrorInvalidRange)
	for id := uint64(1); id <= 4; id++ {
		if _, err := first.Cancel(id); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := scheduleCoalescedForTest(
		scheduler,
		[]ReadIntent{testReadIntent(t, 5, 10, 2)},
	); err != nil {
		t.Fatal("terminal dependents did not release configured bound:", err)
	}
}
