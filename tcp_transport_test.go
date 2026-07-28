package modbus

import (
	"context"
	"errors"
	"io"
	"net"
	"reflect"
	"runtime"
	"sync"
	"testing"
	"time"
)

type fullWriteAfterCancelConn struct {
	net.Conn
	started chan struct{}
	release chan struct{}
}

type rejectingDeadlineConn struct {
	net.Conn
}

type writeStartedConn struct {
	net.Conn
	started chan struct{}
}

type delayedReadReturnConn struct {
	net.Conn
	read    chan struct{}
	release chan struct{}
}

type scriptedWriteConn struct {
	net.Conn
	written       int
	writeErr      error
	fullWrite     bool
	started       chan struct{}
	release       chan struct{}
	interrupted   chan struct{}
	interruptOnce sync.Once
}

type provableZeroTestError struct{}

type admissionBlockingConn struct {
	net.Conn
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (conn *fullWriteAfterCancelConn) Unwrap() net.Conn {
	return conn.Conn
}

func (conn *rejectingDeadlineConn) Unwrap() net.Conn {
	return conn.Conn
}

func (conn *writeStartedConn) Unwrap() net.Conn {
	return conn.Conn
}

func (conn *delayedReadReturnConn) Unwrap() net.Conn {
	return conn.Conn
}

func (conn *scriptedWriteConn) Unwrap() net.Conn {
	return conn.Conn
}

func (conn *admissionBlockingConn) Unwrap() net.Conn {
	return conn.Conn
}

func (*fullWriteAfterCancelConn) modbusTCPTrustedDecorator() {}
func (*rejectingDeadlineConn) modbusTCPTrustedDecorator()    {}
func (*writeStartedConn) modbusTCPTrustedDecorator()         {}
func (*delayedReadReturnConn) modbusTCPTrustedDecorator()    {}
func (*scriptedWriteConn) modbusTCPTrustedDecorator()        {}
func (*admissionBlockingConn) modbusTCPTrustedDecorator()    {}

type recordingTCPEventSink struct {
	mu     sync.Mutex
	events []TCPTransportEvent
	hook   func(TCPTransportEvent)
}

type virtualTCPClock struct {
	mu            sync.Mutex
	now           time.Duration
	nextOrder     uint64
	timers        []*virtualTCPTimer
	advanceOnStop bool
}

type virtualTCPTimer struct {
	clock    *virtualTCPClock
	due      time.Duration
	order    uint64
	callback func()
	active   bool
}

type cancellationOnAfterFuncStopContext struct {
	context.Context
	done chan struct{}
	once sync.Once
	mu   sync.Mutex
	err  error
}

func newCancellationOnAfterFuncStopContext() *cancellationOnAfterFuncStopContext {
	return &cancellationOnAfterFuncStopContext{
		Context: context.Background(),
		done:    make(chan struct{}),
	}
}

func (ctx *cancellationOnAfterFuncStopContext) Done() <-chan struct{} {
	return ctx.done
}

func (ctx *cancellationOnAfterFuncStopContext) Err() error {
	ctx.mu.Lock()
	defer ctx.mu.Unlock()
	return ctx.err
}

func (ctx *cancellationOnAfterFuncStopContext) AfterFunc(
	func(),
) func() bool {
	return func() bool {
		ctx.once.Do(func() {
			ctx.mu.Lock()
			ctx.err = context.Canceled
			ctx.mu.Unlock()
			close(ctx.done)
		})
		return true
	}
}

func (sink *recordingTCPEventSink) RecordTCPTransportEvent(
	event TCPTransportEvent,
) {
	sink.mu.Lock()
	sink.events = append(sink.events, event)
	hook := sink.hook
	sink.mu.Unlock()
	if hook != nil {
		hook(event)
	}
}

func (sink *recordingTCPEventSink) snapshot() []TCPTransportEvent {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	return append([]TCPTransportEvent(nil), sink.events...)
}

func (clock *virtualTCPClock) ContractVersion() string {
	return "test-virtual-monotonic-v1"
}

func (clock *virtualTCPClock) Now() time.Duration {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.now
}

func (clock *virtualTCPClock) AfterFunc(
	delay time.Duration,
	callback func(),
) TCPTransportTimer {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	clock.nextOrder++
	timer := &virtualTCPTimer{
		clock:    clock,
		due:      clock.now + delay,
		order:    clock.nextOrder,
		callback: callback,
		active:   true,
	}
	clock.timers = append(clock.timers, timer)
	return timer
}

func (clock *virtualTCPClock) Advance(delta time.Duration) {
	clock.mu.Lock()
	target := clock.now + delta
	clock.mu.Unlock()
	for {
		clock.mu.Lock()
		var next *virtualTCPTimer
		for _, timer := range clock.timers {
			if !timer.active || timer.due > target {
				continue
			}
			if next == nil ||
				timer.due < next.due ||
				(timer.due == next.due && timer.order < next.order) {
				next = timer
			}
		}
		if next == nil {
			clock.now = target
			clock.mu.Unlock()
			return
		}
		clock.now = next.due
		next.active = false
		callback := next.callback
		clock.mu.Unlock()
		callback()
	}
}

func (timer *virtualTCPTimer) Stop() bool {
	timer.clock.mu.Lock()
	defer timer.clock.mu.Unlock()
	if !timer.active {
		return false
	}
	if timer.clock.advanceOnStop && timer.clock.now < timer.due {
		timer.clock.now = timer.due
	}
	timer.active = false
	return true
}

func (provableZeroTestError) Error() string {
	return "no bytes reached peer"
}

func (provableZeroTestError) ProvablyNoBytesTransmitted() bool {
	return true
}

func (conn *scriptedWriteConn) Write(buffer []byte) (int, error) {
	if conn.started != nil {
		close(conn.started)
	}
	if conn.release != nil {
		<-conn.release
	}
	if conn.fullWrite {
		return len(buffer), conn.writeErr
	}
	return conn.written, conn.writeErr
}

func (conn *scriptedWriteConn) SetWriteDeadline(deadline time.Time) error {
	if conn.interrupted != nil &&
		deadline.Equal(expiredSocketDeadline) {
		conn.interruptOnce.Do(func() {
			close(conn.interrupted)
		})
	}
	return nil
}

func (conn *admissionBlockingConn) Write(buffer []byte) (int, error) {
	conn.once.Do(func() {
		close(conn.started)
		<-conn.release
	})
	return len(buffer), nil
}

func (conn *rejectingDeadlineConn) SetReadDeadline(time.Time) error {
	return errors.New("read deadlines unsupported")
}

func (conn *rejectingDeadlineConn) SetWriteDeadline(time.Time) error {
	return errors.New("write deadlines unsupported")
}

func (conn *writeStartedConn) Write(buffer []byte) (int, error) {
	close(conn.started)
	return conn.Conn.Write(buffer)
}

func (conn *delayedReadReturnConn) Read(buffer []byte) (int, error) {
	count, err := conn.Conn.Read(buffer)
	close(conn.read)
	<-conn.release
	return count, err
}

func (conn *fullWriteAfterCancelConn) Write(buffer []byte) (int, error) {
	close(conn.started)
	<-conn.release
	return len(buffer), nil
}

func TestTCPTransportOwnsConcreteWriteAndReadCorrelation(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = server.Close() }()
	owner := newTestConnectionOwner(t, 1, 2)
	transport, err := newTCPTransport(client, owner, 260)
	if err != nil {
		t.Fatal(err)
	}
	request, _ := NewReadRegistersRequest(FunctionReadHoldingRegisters, 10, 2)
	reservation, _ := owner.ReserveRead(1, request)
	serverDone := make(chan error, 1)
	go func() {
		requestADU := make([]byte, 12)
		if _, err := io.ReadFull(server, requestADU); err != nil {
			serverDone <- err
			return
		}
		want := []byte{0, 0, 0, 0, 0, 6, 1, 3, 0, 10, 0, 2}
		if !reflect.DeepEqual(requestADU, want) {
			serverDone <- &ProtocolError{Kind: ErrorMalformedResponse}
			return
		}
		_, err := server.Write(
			[]byte{0, 0, 0, 0, 0, 7, 1, 3, 4, 0, 1, 0, 2},
		)
		serverDone <- err
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := transport.WriteReservation(ctx, reservation); err != nil {
		t.Fatal(err)
	}
	responses, transition, err := transport.ReadResponses(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if transition.CloseConnection() {
		t.Fatal("successful response closed transport")
	}
	if len(responses) != 1 ||
		!responses[0].Deliverable() ||
		!reflect.DeepEqual(responses[0].Words(), []uint16{1, 2}) {
		t.Fatalf("responses = %#v", responses)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestTCPTransportQueuesReadDeadlineRefreshWithoutActiveRead(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = server.Close() }()
	owner := newTestConnectionOwner(t, 1, 1)
	transport, err := newTCPTransport(client, owner, 260)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = transport.closeTerminal() }()

	transport.refreshActiveReadDeadline()
	interrupter := newSocketInterrupter(client, client.SetReadDeadline)
	active := transport.registerActiveRead(10*time.Second, interrupter)
	if !active.rearm {
		t.Fatal("deadline refresh was lost before active read registration")
	}
	if transport.pendingReadRearm {
		t.Fatal("pending deadline refresh was not consumed")
	}
	transport.finishActiveRead(active)
	if err := interrupter.Reset(); err != nil {
		t.Fatal(err)
	}
}

func TestTCPTransportEOFClosesOwnerAndFailsSiblingWaiters(t *testing.T) {
	client, server := net.Pipe()
	owner := newTestConnectionOwner(t, 2, 2)
	transport, err := newTCPTransport(client, owner, 260)
	if err != nil {
		t.Fatal(err)
	}
	request, _ := NewReadRegistersRequest(FunctionReadHoldingRegisters, 0, 1)
	first, _ := owner.ReserveRead(1, request)
	second, _ := owner.ReserveRead(2, request)
	if err := owner.MarkWriteInvoked(first); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.RecordTransmit(first, TransmitComplete); err != nil {
		t.Fatal(err)
	}
	if err := owner.MarkWriteInvoked(second); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.RecordTransmit(second, TransmitComplete); err != nil {
		t.Fatal(err)
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	responses, transition, err := transport.ReadResponses(context.Background())
	if !errors.Is(err, io.EOF) {
		t.Fatalf("read error = %v", err)
	}
	if len(responses) != 0 || !transition.CloseConnection() ||
		len(transition.FailedReservations()) != 2 || !owner.Closed() {
		t.Fatalf(
			"responses=%v transition=%#v closed=%v",
			responses,
			transition,
			owner.Closed(),
		)
	}
	if _, err := owner.ReserveRead(1, request); err == nil {
		t.Fatal("terminal owner accepted a reservation")
	}
}

func TestTCPTransportCancellationWithoutDeadlineUnblocksRead(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = server.Close() }()
	owner := newTestConnectionOwner(t, 1, 1)
	transport, err := newTCPTransport(client, owner, 260)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, transition, err := transport.ReadResponses(ctx)
		if !transition.CloseConnection() {
			result <- &ProtocolError{Kind: ErrorInvalidRequest}
			return
		}
		result <- err
	}()
	cancel()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("cancelled read returned nil")
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled read remained blocked")
	}
}

func TestTCPTransportOldSocketCannotServeReconnectedGeneration(t *testing.T) {
	oldClient, oldServer := net.Pipe()
	defer func() { _ = oldServer.Close() }()
	owner := newTestConnectionOwner(t, 1, 1)
	oldTransport, err := newTCPTransport(oldClient, owner, 260)
	if err != nil {
		t.Fatal(err)
	}
	owner.Close()
	if generation := owner.Reconnect(); generation != 2 {
		t.Fatalf("generation = %d", generation)
	}
	newClient, newServer := net.Pipe()
	defer func() { _ = newServer.Close() }()
	if _, err := newTCPTransport(newClient, owner, 260); err != nil {
		t.Fatal(err)
	}
	if _, _, err := oldTransport.ReadResponses(context.Background()); err == nil {
		t.Fatal("stale socket remained usable after reconnect")
	}
}

func TestTCPTransportReturnsCorrelatedTerminalResponseWithoutClosing(t *testing.T) {
	tests := []struct {
		name     string
		response []byte
		outcome  WireOutcome
	}{
		{
			name:     "exception",
			response: []byte{0, 0, 0, 0, 0, 3, 1, 0x83, 0x02},
			outcome:  WireProtocolException,
		},
		{
			name:     "malformed",
			response: []byte{0, 0, 0, 0, 0, 5, 1, 3, 4, 0, 1},
			outcome:  WireMalformedResponse,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, server := net.Pipe()
			defer func() { _ = server.Close() }()
			owner := newTestConnectionOwner(t, 2, 2)
			transport, err := newTCPTransport(client, owner, 260)
			if err != nil {
				t.Fatal(err)
			}
			request, _ := NewReadRegistersRequest(
				FunctionReadHoldingRegisters,
				0,
				2,
			)
			reservation, _ := owner.ReserveRead(1, request)
			if err := owner.MarkWriteInvoked(reservation); err != nil {
				t.Fatal(err)
			}
			if _, err := owner.RecordTransmit(
				reservation,
				TransmitComplete,
			); err != nil {
				t.Fatal(err)
			}
			go func() {
				_, _ = server.Write(test.response)
			}()
			responses, transition, err := transport.ReadResponses(
				context.Background(),
			)
			if err == nil {
				t.Fatal("terminal response lost typed error")
			}
			if transition.CloseConnection() || owner.Closed() {
				t.Fatal("request-level terminal response closed socket")
			}
			if len(responses) != 1 ||
				responses[0].Outcome() != test.outcome ||
				responses[0].WireResponseID() == 0 ||
				responses[0].PhysicalRequestID() !=
					reservation.PhysicalRequestID() {
				t.Fatalf("responses = %#v", responses)
			}
			if _, err := owner.ReserveRead(1, request); err != nil {
				t.Fatal("socket unusable after terminal response:", err)
			}
		})
	}
}

func TestTCPTransportCancellationBeforeWriteReleasesReservation(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()
	owner := newTestConnectionOwner(t, 1, 1)
	transport, err := newTCPTransport(client, owner, 260)
	if err != nil {
		t.Fatal(err)
	}
	request, _ := NewReadRegistersRequest(FunctionReadHoldingRegisters, 0, 1)
	reservation, _ := owner.ReserveRead(1, request)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := transport.WriteReservation(ctx, reservation); err != context.Canceled {
		t.Fatalf("write error = %v", err)
	}
	if _, err := owner.ReserveRead(1, request); err != nil {
		t.Fatal("cancelled pre-write reservation retained capacity:", err)
	}
}

func TestTCPTransportCancellationWithoutDeadlineUnblocksWrite(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = server.Close() }()
	started := make(chan struct{})
	owner := newTestConnectionOwner(t, 1, 1)
	transport, err := newTCPTransport(
		&writeStartedConn{Conn: client, started: started},
		owner,
		260,
	)
	if err != nil {
		t.Fatal(err)
	}
	request, _ := NewReadRegistersRequest(FunctionReadHoldingRegisters, 0, 1)
	reservation, _ := owner.ReserveRead(1, request)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		transition, err := transport.WriteReservation(ctx, reservation)
		if !transition.CloseConnection() {
			result <- &ProtocolError{Kind: ErrorInvalidRequest}
			return
		}
		result <- err
	}()
	<-started
	cancel()
	select {
	case err := <-result:
		var writeErr *TransportWriteError
		if !errors.As(err, &writeErr) ||
			writeErr.Result != TransmitCancellationRace {
			t.Fatalf("write error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled write remained blocked")
	}
}

func TestTCPTransportFullByteCountDoesNotMaskCancellationRace(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = server.Close() }()
	clock := &virtualTCPClock{}
	cancellationRecorded := make(chan struct{})
	var cancellationOnce sync.Once
	sink := &recordingTCPEventSink{
		hook: func(event TCPTransportEvent) {
			if event.Kind == TCPEventCallerCancellation {
				cancellationOnce.Do(func() {
					close(cancellationRecorded)
				})
			}
		},
	}
	conn := &fullWriteAfterCancelConn{
		Conn:    client,
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	owner := newTestConnectionOwner(t, 1, 1)
	transport, err := newTCPTransportWithConfig(
		conn,
		owner,
		TCPTransportConfig{
			MaxBufferedBytes: 260,
			RequestDeadline:  time.Second,
			ResponseDeadline: time.Second,
			Clock:            clock,
			EventSink:        sink,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	request, _ := NewReadRegistersRequest(FunctionReadHoldingRegisters, 0, 1)
	reservation, _ := owner.ReserveRead(1, request)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan struct {
		transition OwnerTransition
		err        error
	}, 1)
	go func() {
		transition, err := transport.WriteReservation(ctx, reservation)
		result <- struct {
			transition OwnerTransition
			err        error
		}{transition: transition, err: err}
	}()
	<-conn.started
	cancel()
	select {
	case <-cancellationRecorded:
	case <-time.After(time.Second):
		t.Fatal("cancellation event did not linearize")
	}
	close(conn.release)
	got := <-result
	var writeErr *TransportWriteError
	if !errors.As(got.err, &writeErr) ||
		writeErr.Result != TransmitCancellationRace ||
		!got.transition.CloseConnection() ||
		!owner.Closed() {
		t.Fatalf(
			"transition=%#v error=%v closed=%v",
			got.transition,
			got.err,
			owner.Closed(),
		)
	}
	assertTCPEventTieOrder(
		t,
		sink.snapshot(),
		TCPEventCallerCancellation,
		TCPEventWriteReturn,
	)
}

func TestTCPTransportFullTransmitCompletionWinsCancellationTie(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = server.Close() }()
	clock := &virtualTCPClock{}
	writeReturnRecorded := make(chan struct{})
	releaseWriteReturn := make(chan struct{})
	var writeReturnOnce sync.Once
	sink := &recordingTCPEventSink{
		hook: func(event TCPTransportEvent) {
			if event.Kind != TCPEventWriteReturn {
				return
			}
			writeReturnOnce.Do(func() {
				close(writeReturnRecorded)
				<-releaseWriteReturn
			})
		},
	}
	conn := &fullWriteAfterCancelConn{
		Conn:    client,
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	owner := newTestConnectionOwner(t, 1, 2)
	transport, err := newTCPTransportWithConfig(
		conn,
		owner,
		TCPTransportConfig{
			MaxBufferedBytes: 260,
			RequestDeadline:  time.Second,
			ResponseDeadline: time.Second,
			Clock:            clock,
			EventSink:        sink,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	request, _ := NewReadRegistersRequest(
		FunctionReadHoldingRegisters,
		0,
		1,
	)
	reservation, _ := owner.ReserveRead(1, request)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan struct {
		transition OwnerTransition
		err        error
	}, 1)
	go func() {
		transition, err := transport.WriteReservation(ctx, reservation)
		result <- struct {
			transition OwnerTransition
			err        error
		}{transition: transition, err: err}
	}()
	<-conn.started
	close(conn.release)
	<-writeReturnRecorded
	cancel()
	close(releaseWriteReturn)
	got := <-result
	var writeErr *TransportWriteError
	if !errors.As(got.err, &writeErr) ||
		writeErr.Result != TransmitComplete ||
		!errors.Is(got.err, context.Canceled) {
		t.Fatalf("write error = %v", got.err)
	}
	if got.transition.CloseConnection() || owner.Closed() {
		t.Fatalf(
			"completion winner closed transport: transition=%#v closed=%v",
			got.transition,
			owner.Closed(),
		)
	}
	assertTCPEventTieOrder(
		t,
		sink.snapshot(),
		TCPEventWriteReturn,
		TCPEventCallerCancellation,
	)
	replacement, err := owner.ReserveRead(1, request)
	if err != nil {
		t.Fatal("response-wait abandonment retained capacity:", err)
	}
	if replacement.TransactionID() == reservation.TransactionID() {
		t.Fatal("response-wait abandonment reused tombstoned transaction")
	}
	response, err := owner.Correlate(
		reservation.Generation(),
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
	if response.Outcome() != WireLateAfterAbandonment ||
		response.Deliverable() {
		t.Fatalf("completion winner did not abandon response wait: %#v", response)
	}
	owner.Close()
}

func TestTCPTransportAfterFuncStopRaceCannotLoseCancellation(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = server.Close() }()
	owner := newTestConnectionOwner(t, 1, 2)
	transport, err := newTCPTransportWithConfig(
		&scriptedWriteConn{Conn: client, fullWrite: true},
		owner,
		TCPTransportConfig{
			MaxBufferedBytes: 260,
			RequestDeadline:  time.Second,
			ResponseDeadline: time.Second,
			Clock:            &virtualTCPClock{},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	request, _ := NewReadRegistersRequest(
		FunctionReadHoldingRegisters,
		0,
		1,
	)
	reservation, _ := owner.ReserveRead(1, request)
	ctx := newCancellationOnAfterFuncStopContext()
	transition, err := transport.WriteReservation(ctx, reservation)
	var writeErr *TransportWriteError
	if !errors.As(err, &writeErr) ||
		writeErr.Result != TransmitComplete ||
		!errors.Is(err, context.Canceled) {
		t.Fatalf("write error = %v", err)
	}
	if transition.CloseConnection() || owner.Closed() {
		t.Fatalf(
			"stop-race cancellation closed transport: %#v",
			transition,
		)
	}
	replacement, err := owner.ReserveRead(1, request)
	if err != nil {
		t.Fatal("stop-race cancellation retained capacity:", err)
	}
	if replacement.TransactionID() == reservation.TransactionID() {
		t.Fatal("stop-race cancellation reused tombstoned transaction")
	}
	owner.Close()
}

func TestTCPTransportPreparedFieldsSerializeWithCancellation(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = server.Close() }()
	owner := newTestConnectionOwner(t, 1, 1)
	sink := &recordingTCPEventSink{}
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
	defer owner.Close()

	const iterations = 1000
	for range iterations {
		operation := &tcpTransportOperation{
			transport: transport,
			done:      make(chan struct{}),
		}
		start := make(chan struct{})
		var wait sync.WaitGroup
		wait.Add(2)
		go func() {
			defer wait.Done()
			<-start
			operation.mutateEventFields(func(fields *tcpEventFields) {
				fields.RequestedFunction = FunctionReadHoldingRegisters
				runtime.Gosched()
				fields.LogicalTable = HoldingRegisters
				fields.PhysicalOffset = 10
				fields.PhysicalQuantity = 2
				fields.RawADUHex = "complete"
			})
		}()
		go func() {
			defer wait.Done()
			<-start
			operation.cancel(
				transportInternalDeadline,
				TCPEventRequestTimerFire,
				context.DeadlineExceeded,
			)
		}()
		close(start)
		wait.Wait()
	}

	events := sink.snapshot()
	if len(events) != iterations {
		t.Fatalf("timer events = %d, want %d", len(events), iterations)
	}
	for _, event := range events {
		blank := event.RequestedFunction == 0 &&
			event.LogicalTable == "" &&
			event.PhysicalOffset == 0 &&
			event.PhysicalQuantity == 0 &&
			event.RawADUHex == ""
		complete := event.RequestedFunction ==
			FunctionReadHoldingRegisters &&
			event.LogicalTable == HoldingRegisters &&
			event.PhysicalOffset == 10 &&
			event.PhysicalQuantity == 2 &&
			event.RawADUHex == "complete"
		if !blank && !complete {
			t.Fatalf("partially prepared timer event: %#v", event)
		}
	}
}

func TestTCPTransportTimerStopRaceCannotLoseDeadline(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = server.Close() }()
	const limit = 5 * time.Second
	clock := &virtualTCPClock{advanceOnStop: true}
	sink := &recordingTCPEventSink{}
	owner := newTestConnectionOwner(t, 1, 2)
	transport, err := newTCPTransportWithConfig(
		&scriptedWriteConn{Conn: client, fullWrite: true},
		owner,
		TCPTransportConfig{
			MaxBufferedBytes: 260,
			RequestDeadline:  limit,
			ResponseDeadline: 2 * limit,
			Clock:            clock,
			EventSink:        sink,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	request, _ := NewReadRegistersRequest(
		FunctionReadHoldingRegisters,
		0,
		1,
	)
	reservation, _ := owner.ReserveRead(1, request)
	transition, err := transport.WriteReservation(
		context.Background(),
		reservation,
	)
	var writeErr *TransportWriteError
	if !errors.As(err, &writeErr) ||
		writeErr.Result != TransmitComplete ||
		!errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("write error = %v", err)
	}
	if transition.CloseConnection() || owner.Closed() {
		t.Fatalf(
			"timer-stop race closed transport: %#v",
			transition,
		)
	}
	events := sink.snapshot()
	assertTCPEventOffset(
		t,
		events,
		TCPEventRequestTimerFire,
		limit,
	)
	assertTCPEventOrder(
		t,
		events,
		TCPEventWriteReturn,
		TCPEventRequestTimerFire,
	)
	replacement, err := owner.ReserveRead(1, request)
	if err != nil {
		t.Fatal("timer-stop race retained capacity:", err)
	}
	if replacement.TransactionID() == reservation.TransactionID() {
		t.Fatal("timer-stop race reused tombstoned transaction")
	}
	owner.Close()
}

func TestTCPTransportResponseReceiveCancellationTie(t *testing.T) {
	tests := []struct {
		name               string
		firstEvent         TCPTransportEventKind
		secondEvent        TCPTransportEventKind
		cancelBeforeReturn bool
		wantDeliverable    bool
		wantClose          bool
	}{
		{
			name:               "cancellation wins",
			firstEvent:         TCPEventCallerCancellation,
			secondEvent:        TCPEventReadReturn,
			cancelBeforeReturn: true,
			wantClose:          true,
		},
		{
			name:            "response receive wins",
			firstEvent:      TCPEventReadReturn,
			secondEvent:     TCPEventCallerCancellation,
			wantDeliverable: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, server := net.Pipe()
			defer func() { _ = server.Close() }()
			clock := &virtualTCPClock{}
			firstRecorded := make(chan struct{})
			releaseFirst := make(chan struct{})
			var firstOnce sync.Once
			sink := &recordingTCPEventSink{
				hook: func(event TCPTransportEvent) {
					if event.Kind != test.firstEvent {
						return
					}
					firstOnce.Do(func() {
						close(firstRecorded)
						if !test.cancelBeforeReturn {
							<-releaseFirst
						}
					})
				},
			}
			conn := &delayedReadReturnConn{
				Conn:    client,
				read:    make(chan struct{}),
				release: make(chan struct{}),
			}
			owner := newTestConnectionOwner(t, 1, 2)
			transport, err := newTCPTransportWithConfig(
				conn,
				owner,
				TCPTransportConfig{
					MaxBufferedBytes: 260,
					RequestDeadline:  time.Second,
					ResponseDeadline: time.Second,
					Clock:            clock,
					EventSink:        sink,
				},
			)
			if err != nil {
				t.Fatal(err)
			}
			request, _ := NewReadRegistersRequest(
				FunctionReadHoldingRegisters,
				0,
				1,
			)
			reservation, _ := owner.ReserveRead(1, request)
			if err := owner.MarkWriteInvoked(reservation); err != nil {
				t.Fatal(err)
			}
			if _, err := owner.RecordTransmit(
				reservation,
				TransmitComplete,
			); err != nil {
				t.Fatal(err)
			}
			serverDone := make(chan error, 1)
			go func() {
				_, err := server.Write(
					[]byte{0, 0, 0, 0, 0, 5, 1, 3, 2, 0, 1},
				)
				serverDone <- err
			}()
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct {
				responses  []WireResponse
				transition OwnerTransition
				err        error
			}, 1)
			go func() {
				responses, transition, err := transport.ReadResponses(ctx)
				done <- struct {
					responses  []WireResponse
					transition OwnerTransition
					err        error
				}{
					responses:  responses,
					transition: transition,
					err:        err,
				}
			}()
			<-conn.read
			if test.cancelBeforeReturn {
				cancel()
				<-firstRecorded
				close(conn.release)
			} else {
				close(conn.release)
				<-firstRecorded
				cancel()
				close(releaseFirst)
			}
			got := <-done
			if got.transition.CloseConnection() != test.wantClose {
				t.Fatalf(
					"transition=%#v error=%v",
					got.transition,
					got.err,
				)
			}
			if test.wantClose {
				if !errors.Is(got.err, context.Canceled) ||
					len(got.responses) != 0 ||
					!transitionContainsReservation(
						got.transition,
						reservation,
					) {
					t.Fatalf(
						"responses=%#v transition=%#v error=%v",
						got.responses,
						got.transition,
						got.err,
					)
				}
			} else if got.err != nil ||
				len(got.responses) != 1 ||
				got.responses[0].Deliverable() != test.wantDeliverable {
				t.Fatalf(
					"responses=%#v transition=%#v error=%v",
					got.responses,
					got.transition,
					got.err,
				)
			}
			assertTCPEventTieOrder(
				t,
				sink.snapshot(),
				test.firstEvent,
				test.secondEvent,
			)
			if err := <-serverDone; err != nil {
				t.Fatal(err)
			}
			owner.Close()
		})
	}
}

func TestTCPTransportCancellationClosesWhenDeadlinesUnsupported(t *testing.T) {
	t.Run("read", func(t *testing.T) {
		client, server := net.Pipe()
		defer func() { _ = server.Close() }()
		owner := newTestConnectionOwner(t, 1, 1)
		transport, err := newTCPTransport(
			&rejectingDeadlineConn{Conn: client},
			owner,
			260,
		)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		result := make(chan error, 1)
		go func() {
			_, transition, err := transport.ReadResponses(ctx)
			if !transition.CloseConnection() {
				result <- &ProtocolError{Kind: ErrorInvalidRequest}
				return
			}
			result <- err
		}()
		cancel()
		select {
		case err := <-result:
			if err == nil {
				t.Fatal("cancelled read returned nil")
			}
		case <-time.After(time.Second):
			t.Fatal("read remained blocked without deadline support")
		}
	})

	t.Run("write", func(t *testing.T) {
		client, server := net.Pipe()
		defer func() { _ = server.Close() }()
		started := make(chan struct{})
		owner := newTestConnectionOwner(t, 1, 1)
		transport, err := newTCPTransport(
			&rejectingDeadlineConn{
				Conn: &writeStartedConn{
					Conn:    client,
					started: started,
				},
			},
			owner,
			260,
		)
		if err != nil {
			t.Fatal(err)
		}
		request, _ := NewReadRegistersRequest(
			FunctionReadHoldingRegisters,
			0,
			1,
		)
		reservation, _ := owner.ReserveRead(1, request)
		ctx, cancel := context.WithCancel(context.Background())
		result := make(chan error, 1)
		go func() {
			transition, err := transport.WriteReservation(ctx, reservation)
			if !transition.CloseConnection() {
				result <- &ProtocolError{Kind: ErrorInvalidRequest}
				return
			}
			result <- err
		}()
		<-started
		cancel()
		select {
		case err := <-result:
			if err == nil {
				t.Fatal("cancelled write returned nil")
			}
		case <-time.After(time.Second):
			t.Fatal("write remained blocked without deadline support")
		}
	})
}

func TestTCPTransportWriteResultClassificationLifecycle(t *testing.T) {
	tests := []struct {
		name              string
		written           int
		writeErr          error
		fullWrite         bool
		cancelDuringWrite bool
		want              TransmitResult
		wantClose         bool
	}{
		{
			name:      "provable zero",
			writeErr:  provableZeroTestError{},
			want:      TransmitProvableZero,
			wantClose: false,
		},
		{
			name:      "partial",
			written:   4,
			writeErr:  errors.New("short write"),
			want:      TransmitPartial,
			wantClose: true,
		},
		{
			name:      "indeterminate",
			writeErr:  errors.New("unknown write failure"),
			want:      TransmitIndeterminate,
			wantClose: true,
		},
		{
			name:              "cancellation race",
			fullWrite:         true,
			cancelDuringWrite: true,
			want:              TransmitCancellationRace,
			wantClose:         true,
		},
		{
			name:      "ambiguous completion",
			fullWrite: true,
			writeErr:  errors.New("completion status unknown"),
			want:      TransmitAmbiguous,
			wantClose: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, server := net.Pipe()
			defer func() { _ = server.Close() }()
			conn := &scriptedWriteConn{
				Conn:      client,
				written:   test.written,
				writeErr:  test.writeErr,
				fullWrite: test.fullWrite,
			}
			if test.cancelDuringWrite {
				conn.started = make(chan struct{})
				conn.release = make(chan struct{})
				conn.interrupted = make(chan struct{})
			}
			owner := newTestConnectionOwner(t, 2, 4)
			transport, err := newTCPTransport(conn, owner, 260)
			if err != nil {
				t.Fatal(err)
			}
			request, _ := NewReadRegistersRequest(
				FunctionReadHoldingRegisters,
				0,
				1,
			)
			reservation, _ := owner.ReserveRead(1, request)
			sibling, _ := owner.ReserveRead(2, request)
			ctx, cancel := context.WithCancel(context.Background())
			result := make(chan struct {
				transition OwnerTransition
				err        error
			}, 1)
			go func() {
				transition, err := transport.WriteReservation(ctx, reservation)
				result <- struct {
					transition OwnerTransition
					err        error
				}{transition: transition, err: err}
			}()
			if test.cancelDuringWrite {
				<-conn.started
				cancel()
				<-conn.interrupted
				close(conn.release)
			}
			got := <-result
			cancel()
			var writeErr *TransportWriteError
			if !errors.As(got.err, &writeErr) ||
				writeErr.Result != test.want {
				t.Fatalf("write error = %v, want %s", got.err, test.want)
			}
			if got.transition.CloseConnection() != test.wantClose ||
				owner.Closed() != test.wantClose {
				t.Fatalf(
					"transition=%#v owner_closed=%v",
					got.transition,
					owner.Closed(),
				)
			}
			if !test.wantClose {
				replacement, err := owner.ReserveRead(1, request)
				if err != nil {
					t.Fatal("provable-zero retained reservation:", err)
				}
				if replacement.Generation() != reservation.Generation() {
					t.Fatal("provable-zero changed socket generation")
				}
				if err := owner.MarkWriteInvoked(sibling); err != nil {
					t.Fatal("provable-zero failed sibling:", err)
				}
				owner.Close()
				return
			}
			if !transitionContainsReservation(got.transition, sibling) {
				t.Fatalf(
					"sibling %d absent from transition %#v",
					sibling.TransactionID(),
					got.transition,
				)
			}
			if generation := owner.Reconnect(); generation != 2 {
				t.Fatalf("reconnect generation = %d", generation)
			}
			oldResponse, oldErr := owner.Correlate(
				reservation.Generation(),
				testTCPFrame(
					t,
					reservation.TransactionID(),
					1,
					[]byte{3, 2, 0, 1},
				),
			)
			if oldResponse.Deliverable() ||
				oldResponse.Outcome() != WireDroppedUncorrelated {
				t.Fatalf(
					"old generation response=%#v error=%v",
					oldResponse,
					oldErr,
				)
			}
		})
	}
}

func TestTCPTransportFullTransmitAbandonmentTombstonesLateResponse(
	t *testing.T,
) {
	client, server := net.Pipe()
	defer func() { _ = server.Close() }()
	conn := &scriptedWriteConn{Conn: client, fullWrite: true}
	owner := newTestConnectionOwner(t, 2, 2)
	transport, err := newTCPTransport(conn, owner, 260)
	if err != nil {
		t.Fatal(err)
	}
	request, _ := NewReadRegistersRequest(FunctionReadHoldingRegisters, 0, 1)
	reservation, _ := owner.ReserveRead(1, request)
	if transition, err := transport.WriteReservation(
		context.Background(),
		reservation,
	); err != nil || transition.CloseConnection() {
		t.Fatalf("write transition=%#v error=%v", transition, err)
	}
	transition, err := owner.AbandonAfterWrite(
		reservation,
		AbandonCancellation,
	)
	if err != nil || transition.CloseConnection() || owner.Closed() {
		t.Fatalf("abandon transition=%#v error=%v", transition, err)
	}
	response, err := owner.Correlate(
		reservation.Generation(),
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
	if response.Outcome() != WireLateAfterAbandonment ||
		response.Deliverable() {
		t.Fatalf("late response = %#v", response)
	}
}

func TestTCPTransportFiniteInternalDeadlines(t *testing.T) {
	t.Run("invalid configuration", func(t *testing.T) {
		tests := []TCPTransportConfig{
			{
				MaxBufferedBytes: 260,
				RequestDeadline:  0,
				ResponseDeadline: time.Second,
			},
			{
				MaxBufferedBytes: 260,
				RequestDeadline:  time.Second,
				ResponseDeadline: -time.Second,
			},
		}
		for _, config := range tests {
			client, server := net.Pipe()
			owner := newTestConnectionOwner(t, 1, 1)
			if _, err := newTCPTransportWithConfig(
				client,
				owner,
				config,
			); err == nil {
				t.Fatalf("accepted config %#v", config)
			}
			_ = client.Close()
			_ = server.Close()
		}
	})

	t.Run("background write", func(t *testing.T) {
		client, server := net.Pipe()
		defer func() { _ = server.Close() }()
		owner := newTestConnectionOwner(t, 1, 1)
		transport, err := newTCPTransportWithConfig(
			client,
			owner,
			TCPTransportConfig{
				MaxBufferedBytes: 260,
				RequestDeadline:  25 * time.Millisecond,
				ResponseDeadline: time.Second,
			},
		)
		if err != nil {
			t.Fatal(err)
		}
		request, _ := NewReadRegistersRequest(
			FunctionReadHoldingRegisters,
			0,
			1,
		)
		reservation, _ := owner.ReserveRead(1, request)
		done := make(chan struct {
			transition OwnerTransition
			err        error
		}, 1)
		go func() {
			transition, err := transport.WriteReservation(
				context.Background(),
				reservation,
			)
			done <- struct {
				transition OwnerTransition
				err        error
			}{transition: transition, err: err}
		}()
		select {
		case got := <-done:
			if got.err == nil || !got.transition.CloseConnection() {
				t.Fatalf("transition=%#v error=%v", got.transition, got.err)
			}
		case <-time.After(time.Second):
			t.Fatal("background write exceeded configured request deadline")
		}
	})

	t.Run("background response read", func(t *testing.T) {
		client, server := net.Pipe()
		defer func() { _ = server.Close() }()
		owner := newTestConnectionOwner(t, 1, 1)
		transport, err := newTCPTransportWithConfig(
			client,
			owner,
			TCPTransportConfig{
				MaxBufferedBytes: 260,
				RequestDeadline:  time.Second,
				ResponseDeadline: 25 * time.Millisecond,
			},
		)
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan struct {
			transition OwnerTransition
			err        error
		}, 1)
		go func() {
			_, transition, err := transport.ReadResponses(
				context.Background(),
			)
			done <- struct {
				transition OwnerTransition
				err        error
			}{transition: transition, err: err}
		}()
		select {
		case got := <-done:
			if !errors.Is(got.err, context.DeadlineExceeded) ||
				got.transition.CloseConnection() ||
				owner.Closed() {
				t.Fatalf("transition=%#v error=%v", got.transition, got.err)
			}
		case <-time.After(time.Second):
			t.Fatal("background read exceeded configured response deadline")
		}
	})
}

func TestTCPTransportDefaultClockIsFiniteMonotonicSource(t *testing.T) {
	config := DefaultTCPTransportConfig(260)
	if config.Clock == nil {
		t.Fatal("default configuration omitted monotonic clock")
	}
	if got := config.Clock.ContractVersion(); got != tcpClockContractVersion {
		t.Fatalf("clock contract = %q", got)
	}
	first := config.Clock.Now()
	second := config.Clock.Now()
	if first < 0 || second < first {
		t.Fatalf("non-monotonic offsets: first=%s second=%s", first, second)
	}
}

func TestTCPTransportVirtualClockDrivesFiniteDeadlines(t *testing.T) {
	const limit = 5 * time.Second
	t.Run("request write", func(t *testing.T) {
		client, server := net.Pipe()
		defer func() { _ = server.Close() }()
		clock := &virtualTCPClock{}
		sink := &recordingTCPEventSink{}
		started := make(chan struct{})
		owner := newTestConnectionOwner(t, 1, 1)
		transport, err := newTCPTransportWithConfig(
			&writeStartedConn{Conn: client, started: started},
			owner,
			TCPTransportConfig{
				MaxBufferedBytes: 260,
				RequestDeadline:  limit,
				ResponseDeadline: 2 * limit,
				Clock:            clock,
				EventSink:        sink,
			},
		)
		if err != nil {
			t.Fatal(err)
		}
		request, _ := NewReadRegistersRequest(
			FunctionReadHoldingRegisters,
			0,
			1,
		)
		reservation, _ := owner.ReserveRead(1, request)
		done := make(chan struct {
			transition OwnerTransition
			err        error
		}, 1)
		go func() {
			transition, err := transport.WriteReservation(
				context.Background(),
				reservation,
			)
			done <- struct {
				transition OwnerTransition
				err        error
			}{transition: transition, err: err}
		}()
		<-started
		clock.Advance(limit)
		got := <-done
		var writeErr *TransportWriteError
		if !errors.As(got.err, &writeErr) ||
			writeErr.Result != TransmitCancellationRace ||
			!errors.Is(got.err, context.DeadlineExceeded) ||
			!got.transition.CloseConnection() {
			t.Fatalf("transition=%#v error=%v", got.transition, got.err)
		}
		assertTCPEventOffset(
			t,
			sink.snapshot(),
			TCPEventRequestTimerArm,
			0,
		)
		assertTCPEventOffset(
			t,
			sink.snapshot(),
			TCPEventRequestTimerFire,
			limit,
		)
		assertTCPEventOrder(
			t,
			sink.snapshot(),
			TCPEventRequestTimerFire,
			TCPEventWriteReturn,
		)
	})

	t.Run("response read", func(t *testing.T) {
		client, server := net.Pipe()
		defer func() { _ = server.Close() }()
		clock := &virtualTCPClock{}
		readInvoked := make(chan struct{})
		var readInvokedOnce sync.Once
		sink := &recordingTCPEventSink{
			hook: func(event TCPTransportEvent) {
				if event.Kind == TCPEventReadInvocation {
					readInvokedOnce.Do(func() {
						close(readInvoked)
					})
				}
			},
		}
		owner := newTestConnectionOwner(t, 1, 1)
		transport, err := newTCPTransportWithConfig(
			client,
			owner,
			TCPTransportConfig{
				MaxBufferedBytes: 260,
				RequestDeadline:  2 * limit,
				ResponseDeadline: limit,
				Clock:            clock,
				EventSink:        sink,
			},
		)
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan struct {
			transition OwnerTransition
			err        error
		}, 1)
		go func() {
			_, transition, err := transport.ReadResponses(
				context.Background(),
			)
			done <- struct {
				transition OwnerTransition
				err        error
			}{transition: transition, err: err}
		}()
		<-readInvoked
		clock.Advance(limit)
		got := <-done
		if !errors.Is(got.err, context.DeadlineExceeded) ||
			got.transition.CloseConnection() ||
			owner.Closed() {
			t.Fatalf("transition=%#v error=%v", got.transition, got.err)
		}
		events := sink.snapshot()
		assertTCPEventOffset(
			t,
			events,
			TCPEventResponseTimerArm,
			0,
		)
		assertTCPEventOffset(
			t,
			events,
			TCPEventResponseTimerFire,
			limit,
		)
		assertTCPEventOrder(
			t,
			events,
			TCPEventResponseTimerFire,
			TCPEventReadReturn,
		)
	})
}

func TestTCPTransportWriteAdmissionIsContextAware(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = server.Close() }()
	conn := &admissionBlockingConn{
		Conn:    client,
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	owner := newTestConnectionOwner(t, 2, 2)
	transport, err := newTCPTransportWithConfig(
		conn,
		owner,
		TCPTransportConfig{
			MaxBufferedBytes: 260,
			RequestDeadline:  2 * time.Second,
			ResponseDeadline: 2 * time.Second,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	request, _ := NewReadRegistersRequest(FunctionReadHoldingRegisters, 0, 1)
	first, _ := owner.ReserveRead(1, request)
	second, _ := owner.ReserveRead(2, request)
	firstDone := make(chan error, 1)
	go func() {
		_, err := transport.WriteReservation(context.Background(), first)
		firstDone <- err
	}()
	<-conn.started
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	secondDone := make(chan error, 1)
	go func() {
		_, err := transport.WriteReservation(ctx, second)
		secondDone <- err
	}()
	select {
	case err := <-secondDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("second write error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled write admission blocked behind active write")
	}
	close(conn.release)
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
	if _, err := owner.ReserveRead(2, request); err != nil {
		t.Fatal("cancelled admission retained reservation:", err)
	}
}

func TestTCPTransportDeadlineFallbackReturnsSiblingTransition(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = server.Close() }()
	started := make(chan struct{})
	owner := newTestConnectionOwner(t, 2, 2)
	transport, err := newTCPTransport(
		&rejectingDeadlineConn{
			Conn: &writeStartedConn{Conn: client, started: started},
		},
		owner,
		260,
	)
	if err != nil {
		t.Fatal(err)
	}
	request, _ := NewReadRegistersRequest(FunctionReadHoldingRegisters, 0, 1)
	reservation, _ := owner.ReserveRead(1, request)
	sibling, _ := owner.ReserveRead(2, request)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct {
		transition OwnerTransition
		err        error
	}, 1)
	go func() {
		transition, err := transport.WriteReservation(ctx, reservation)
		done <- struct {
			transition OwnerTransition
			err        error
		}{transition: transition, err: err}
	}()
	<-started
	cancel()
	got := <-done
	if got.err == nil ||
		!got.transition.CloseConnection() ||
		!transitionContainsReservation(got.transition, sibling) {
		t.Fatalf("transition=%#v error=%v", got.transition, got.err)
	}
	if failed := owner.DrainFailedReservations(); len(failed) != 0 {
		t.Fatalf("fallback transition was duplicated in drain: %#v", failed)
	}
}

func TestTCPTransportPreWriteFailuresReleaseReservation(t *testing.T) {
	request, err := NewReadRegistersRequest(
		FunctionReadHoldingRegisters,
		0,
		1,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("stale transport", func(t *testing.T) {
		oldClient, oldServer := net.Pipe()
		defer func() { _ = oldServer.Close() }()
		owner := newTestConnectionOwner(t, 1, 1)
		oldTransport, err := newTCPTransport(oldClient, owner, 260)
		if err != nil {
			t.Fatal(err)
		}
		owner.Close()
		if generation := owner.Reconnect(); generation != 2 {
			t.Fatalf("generation = %d", generation)
		}
		newClient, newServer := net.Pipe()
		defer func() { _ = newServer.Close() }()
		if _, err := newTCPTransport(newClient, owner, 260); err != nil {
			t.Fatal(err)
		}
		reservation, err := owner.ReserveRead(1, request)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := oldTransport.WriteReservation(
			context.Background(),
			reservation,
		); err == nil {
			t.Fatal("stale transport accepted reservation")
		}
		if _, err := owner.ReserveRead(1, request); err != nil {
			t.Fatal("stale transport leaked reservation capacity:", err)
		}
		owner.Close()
	})

	t.Run("encode failure", func(t *testing.T) {
		client, server := net.Pipe()
		defer func() { _ = server.Close() }()
		owner := newTestConnectionOwner(t, 1, 1)
		transport, err := newTCPTransport(client, owner, 260)
		if err != nil {
			t.Fatal(err)
		}
		reservation, err := owner.ReserveRead(1, request)
		if err != nil {
			t.Fatal(err)
		}
		owner.mu.Lock()
		owner.inFlight[reservation.TransactionID()].read.quantity = 0
		owner.mu.Unlock()
		if _, err := transport.WriteReservation(
			context.Background(),
			reservation,
		); err == nil {
			t.Fatal("invalid encoded request returned nil")
		}
		if _, err := owner.ReserveRead(1, request); err != nil {
			t.Fatal("encode failure leaked reservation capacity:", err)
		}
		owner.Close()
	})

	t.Run("mark write invoked failure", func(t *testing.T) {
		client, server := net.Pipe()
		defer func() { _ = server.Close() }()
		owner := newTestConnectionOwner(t, 1, 1)
		var reservation TCPReservation
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
		reservation, err = owner.ReserveRead(1, request)
		if err != nil {
			t.Fatal(err)
		}
		transition, err := transport.WriteReservation(
			context.Background(),
			reservation,
		)
		if err == nil {
			t.Fatal("corrupt reservation identity reached socket write")
		}
		if transition.CloseConnection() || owner.Closed() {
			t.Fatalf(
				"recoverable mark failure closed transport: %#v",
				transition,
			)
		}
		if _, err := owner.ReserveRead(1, request); err != nil {
			t.Fatal("mark failure leaked reservation capacity:", err)
		}
		owner.Close()
	})
}

func TestTCPTransportConcurrentCloseConsumesSiblingFailuresOnce(
	t *testing.T,
) {
	client, server := net.Pipe()
	defer func() { _ = server.Close() }()
	owner := newTestConnectionOwner(t, 2, 2)
	transport, err := newTCPTransport(client, owner, 260)
	if err != nil {
		t.Fatal(err)
	}
	request, _ := NewReadRegistersRequest(
		FunctionReadHoldingRegisters,
		0,
		1,
	)
	first, _ := owner.ReserveRead(1, request)
	second, _ := owner.ReserveRead(2, request)
	start := make(chan struct{})
	results := make(chan OwnerTransition, 2)
	errs := make(chan error, 2)
	var ready sync.WaitGroup
	ready.Add(2)
	for range 2 {
		go func() {
			ready.Done()
			<-start
			transition, err := transport.closeTerminal()
			results <- transition
			errs <- err
		}()
	}
	ready.Wait()
	close(start)
	seen := make(map[uint64]int)
	for range 2 {
		transition := <-results
		if !transition.CloseConnection() {
			t.Fatalf("close transition = %#v", transition)
		}
		for _, reservation := range transition.FailedReservations() {
			seen[reservation.PhysicalRequestID()]++
		}
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	if seen[first.PhysicalRequestID()] != 1 ||
		seen[second.PhysicalRequestID()] != 1 ||
		len(seen) != 2 {
		t.Fatalf("consumed sibling failures = %#v", seen)
	}
	later, err := transport.closeTerminal()
	if err != nil {
		t.Fatal(err)
	}
	if !later.CloseConnection() || len(later.FailedReservations()) != 0 {
		t.Fatalf("later close transition = %#v", later)
	}
}

func tcpEvent(
	t *testing.T,
	events []TCPTransportEvent,
	kind TCPTransportEventKind,
) TCPTransportEvent {
	t.Helper()
	for _, event := range events {
		if event.Kind == kind {
			return event
		}
	}
	t.Fatalf("event %q absent from %#v", kind, events)
	return TCPTransportEvent{}
}

func assertTCPEventOffset(
	t *testing.T,
	events []TCPTransportEvent,
	kind TCPTransportEventKind,
	want time.Duration,
) {
	t.Helper()
	event := tcpEvent(t, events, kind)
	if event.MonotonicOffset != want {
		t.Fatalf(
			"event %q offset = %s, want %s",
			kind,
			event.MonotonicOffset,
			want,
		)
	}
	if event.ClockContractVersion == "" {
		t.Fatalf("event %q omitted clock contract", kind)
	}
}

func assertTCPEventOrder(
	t *testing.T,
	events []TCPTransportEvent,
	firstKind TCPTransportEventKind,
	secondKind TCPTransportEventKind,
) {
	t.Helper()
	first := tcpEvent(t, events, firstKind)
	second := tcpEvent(t, events, secondKind)
	if first.Sequence >= second.Sequence {
		t.Fatalf(
			"event order %q=%d %q=%d",
			firstKind,
			first.Sequence,
			secondKind,
			second.Sequence,
		)
	}
}

func assertTCPEventTieOrder(
	t *testing.T,
	events []TCPTransportEvent,
	firstKind TCPTransportEventKind,
	secondKind TCPTransportEventKind,
) {
	t.Helper()
	first := tcpEvent(t, events, firstKind)
	second := tcpEvent(t, events, secondKind)
	if first.MonotonicOffset != second.MonotonicOffset {
		t.Fatalf(
			"tie offsets %q=%s %q=%s",
			firstKind,
			first.MonotonicOffset,
			secondKind,
			second.MonotonicOffset,
		)
	}
	assertTCPEventOrder(t, events, firstKind, secondKind)
}

func transitionContainsReservation(
	transition OwnerTransition,
	target TCPReservation,
) bool {
	for _, reservation := range transition.FailedReservations() {
		if reservation.TransactionID() == target.TransactionID() &&
			reservation.Generation() == target.Generation() &&
			reservation.PhysicalRequestID() == target.PhysicalRequestID() {
			return true
		}
	}
	return false
}
