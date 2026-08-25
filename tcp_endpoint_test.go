package modbus

import (
	"context"
	"encoding/hex"
	"errors"
	"go/ast"
	"go/build"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// endpointDelayWaiter makes backoff observable without consulting wall time.
type endpointDelayWaiter struct {
	delays []time.Duration
	err    error
}

func TestTCPUnitZeroReadIsCorrelatedEndToEnd(t *testing.T) {
	clock := &virtualTCPClock{}
	endpoint, err := NewTCPEndpoint(endpointConfigForTest(clock, nil))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = endpoint.Close() }()
	client, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	connection, err := endpoint.openTestConnection(client)
	if err != nil {
		t.Fatal(err)
	}
	plan := endpointPlan(t, connection, time.Second, 91, 30000)
	plan.UnitID = 0
	handle, err := endpoint.EnqueueRead(plan)
	if err != nil {
		t.Fatal(err)
	}
	dispatch, ok := endpoint.Dispatch()
	if !ok {
		t.Fatal("unit-zero request not dispatched")
	}
	request := endpointWriteOne(t, endpoint, dispatch, peer)
	if request[6] != 0 {
		t.Fatalf("MBAP unit=%d", request[6])
	}
	sent := endpointSendFrame(peer, endpointResponse(request, 0, 0x1234))
	batch, err := endpoint.Read(context.Background(), connection)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-sent; err != nil {
		t.Fatal(err)
	}
	if len(batch.Responses) != 1 ||
		batch.Responses[0].PhysicalRequestID() != handle.RequestID() ||
		batch.Responses[0].Provenance().UnitID != 0 ||
		!reflect.DeepEqual(batch.Responses[0].Words(), []uint16{0x1234}) {
		t.Fatalf("unit-zero batch=%#v", batch)
	}
}

func TestTCPEndpointUnitZeroWrappedDeviceIDStream(t *testing.T) {
	clock := &virtualTCPClock{}
	endpoint, err := NewTCPEndpoint(endpointConfigForTest(clock, nil))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = endpoint.Close() }()
	client, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	connection, err := endpoint.openTestConnection(client)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := NewExtendedDeviceIDStreamRequest(0x87)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := endpoint.EnqueueDeviceID(TCPDeviceIDPlan{
		Connection: connection, UnitID: 0, AuthorizationScope: "unit-zero-device-id",
		PollGeneration: 1, DeadlineIdentity: 1, Timeout: time.Second,
		Request: initial, Limits: DefaultDeviceIDLimits(),
	})
	if err != nil {
		t.Fatal(err)
	}
	responses := []struct {
		wantObject byte
		pdu        []byte
	}{
		{0x87, []byte{0x2b, 0x0e, 0x03, 0x83, 0xff, 0xff, 1, 0x87, 1, 'c'}},
		{0xff, []byte{0x2b, 0x0e, 0x03, 0x83, 0xff, 0x00, 1, 0xff, 1, 'h'}},
		{0x00, []byte{0x2b, 0x0e, 0x03, 0x83, 0x00, 0x00, 1, 0x00, 1, 'l'}},
	}
	var completion TCPDeviceIDCompletion
	for index, step := range responses {
		dispatch, ok := endpoint.Dispatch()
		if !ok {
			t.Fatalf("dispatch %d absent", index)
		}
		request := endpointWriteDeviceID(t, endpoint, dispatch, peer)
		if request[6] != 0 || request[10] != step.wantObject {
			t.Fatalf("request %d=%x", index, request)
		}
		frame := testTCPFrame(t, uint16(request[0])<<8|uint16(request[1]), 0, step.pdu)
		sent := endpointSendFrame(peer, frame.Bytes())
		batch, readErr := endpoint.Read(context.Background(), connection)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if err := <-sent; err != nil {
			t.Fatal(err)
		}
		if index < len(responses)-1 && len(batch.DeviceIDs) != 0 {
			t.Fatalf("partial completion at %d: %#v", index, batch.DeviceIDs)
		}
		if index == len(responses)-1 {
			if len(batch.DeviceIDs) != 1 {
				t.Fatalf("completions=%d", len(batch.DeviceIDs))
			}
			completion = batch.DeviceIDs[0]
		}
	}
	if completion.RequestID != handle.RequestID() || len(completion.Result.Objects) != 3 {
		t.Fatalf("completion=%#v", completion)
	}
	want := []byte{0x87, 0xff, 0x00}
	for index, object := range completion.Result.Objects {
		if object.ID != want[index] {
			t.Fatalf("object[%d]=0x%02x", index, object.ID)
		}
	}
}

func (waiter *endpointDelayWaiter) Wait(
	ctx context.Context,
	delay time.Duration,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	waiter.delays = append(waiter.delays, delay)
	return waiter.err
}

type endpointBlockingWaiter struct {
	started chan struct{}
	release chan struct{}
}

type endpointSnapshotSink struct {
	endpoint *TCPEndpoint
	seen     chan TCPEndpointSnapshot
}

func (sink *endpointSnapshotSink) RecordTCPTransportEvent(
	TCPTransportEvent,
) {
	if sink.endpoint != nil {
		sink.seen <- sink.endpoint.Snapshot()
	}
}

type endpointReentrantCancelSink struct {
	endpoint *TCPEndpoint
	request  TCPRequestHandle
	result   chan error
}

func (sink *endpointReentrantCancelSink) RecordTCPTransportEvent(
	event TCPTransportEvent,
) {
	if event.Kind == TCPEventResponseReceive {
		sink.result <- sink.endpoint.Cancel(sink.request)
	}
}

func (waiter *endpointBlockingWaiter) Wait(
	ctx context.Context,
	_ time.Duration,
) error {
	close(waiter.started)
	select {
	case <-waiter.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type endpointZeroJitter struct{}

func (endpointZeroJitter) Next(time.Duration) time.Duration { return 0 }

type endpointFailOnceConn struct {
	net.Conn
	mu     sync.Mutex
	failed bool
}

func (conn *endpointFailOnceConn) Write(bytes []byte) (int, error) {
	conn.mu.Lock()
	if !conn.failed {
		conn.failed = true
		conn.mu.Unlock()
		return 0, provableZeroTestError{}
	}
	conn.mu.Unlock()
	return conn.Conn.Write(bytes)
}

type endpointPartialWriteConn struct {
	net.Conn
	mu     sync.Mutex
	failed bool
}

func (conn *endpointPartialWriteConn) Write(bytes []byte) (int, error) {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	if !conn.failed {
		conn.failed = true
		return 1, provableZeroTestError{}
	}
	return conn.Conn.Write(bytes)
}

type endpointProvableZeroConn struct {
	net.Conn
}

func (conn *endpointProvableZeroConn) Write([]byte) (int, error) {
	return 0, provableZeroTestError{}
}

type endpointSafeThenUnsafeConn struct {
	net.Conn
	mu     sync.Mutex
	writes int
}

type endpointFullThenPartialConn struct {
	net.Conn
	mu     sync.Mutex
	writes int
}

func (conn *endpointFullThenPartialConn) Write(bytes []byte) (int, error) {
	conn.mu.Lock()
	conn.writes++
	writes := conn.writes
	conn.mu.Unlock()
	if writes == 1 {
		return conn.Conn.Write(bytes)
	}
	return 1, provableZeroTestError{}
}

func (conn *endpointSafeThenUnsafeConn) Write([]byte) (int, error) {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	conn.writes++
	if conn.writes == 1 {
		return 0, provableZeroTestError{}
	}
	return 1, provableZeroTestError{}
}

type endpointDelayedWriteReturnConn struct {
	net.Conn
	transmitted chan struct{}
	release     chan struct{}
}

func (conn *endpointFailOnceConn) Unwrap() net.Conn {
	return conn.Conn
}

func (conn *endpointPartialWriteConn) Unwrap() net.Conn {
	return conn.Conn
}

func (conn *endpointProvableZeroConn) Unwrap() net.Conn {
	return conn.Conn
}

func (conn *endpointSafeThenUnsafeConn) Unwrap() net.Conn {
	return conn.Conn
}

func (conn *endpointFullThenPartialConn) Unwrap() net.Conn {
	return conn.Conn
}

func (conn *endpointDelayedWriteReturnConn) Unwrap() net.Conn {
	return conn.Conn
}

type endpointConnAlias struct {
	net.Conn
}

func (conn *endpointConnAlias) Unwrap() net.Conn {
	return conn.Conn
}

func (*endpointFailOnceConn) modbusTCPTrustedDecorator()           {}
func (*endpointPartialWriteConn) modbusTCPTrustedDecorator()       {}
func (*endpointProvableZeroConn) modbusTCPTrustedDecorator()       {}
func (*endpointSafeThenUnsafeConn) modbusTCPTrustedDecorator()     {}
func (*endpointFullThenPartialConn) modbusTCPTrustedDecorator()    {}
func (*endpointDelayedWriteReturnConn) modbusTCPTrustedDecorator() {}
func (*endpointConnAlias) modbusTCPTrustedDecorator()              {}

func (endpoint *TCPEndpoint) openTestConnection(
	conn net.Conn,
) (TCPConnectionHandle, error) {
	return endpoint.OpenConnection(&endpointConnAlias{Conn: conn})
}

type endpointOpaqueConnAlias struct {
	net.Conn
}

type endpointEarlyResponsePartialConn struct {
	net.Conn
	transmitted chan struct{}
	release     chan struct{}
}

type endpointDelayedReadDeadlineConn struct {
	net.Conn
	readStarted    chan struct{}
	expiredStarted chan struct{}
	releaseExpired chan struct{}
	readOnce       sync.Once
	expiredOnce    sync.Once
}

func (conn *endpointDelayedReadDeadlineConn) Unwrap() net.Conn {
	return conn.Conn
}

func (*endpointDelayedReadDeadlineConn) modbusTCPTrustedDecorator() {}

func (conn *endpointDelayedReadDeadlineConn) Read(buffer []byte) (int, error) {
	conn.readOnce.Do(func() {
		close(conn.readStarted)
	})
	return conn.Conn.Read(buffer)
}

func (conn *endpointDelayedReadDeadlineConn) SetReadDeadline(
	deadline time.Time,
) error {
	if deadline.Equal(expiredSocketDeadline) {
		conn.expiredOnce.Do(func() {
			close(conn.expiredStarted)
			<-conn.releaseExpired
		})
	}
	return conn.Conn.SetReadDeadline(deadline)
}

func (conn *endpointEarlyResponsePartialConn) Unwrap() net.Conn {
	return conn.Conn
}

func (*endpointEarlyResponsePartialConn) modbusTCPTrustedDecorator() {}

func (conn *endpointEarlyResponsePartialConn) Write(buffer []byte) (int, error) {
	_, err := conn.Conn.Write(buffer)
	close(conn.transmitted)
	<-conn.release
	if err != nil {
		return 0, err
	}
	return 1, errors.New("partial result after peer received request")
}

func (conn *endpointDelayedWriteReturnConn) Write(bytes []byte) (int, error) {
	written, err := conn.Conn.Write(bytes)
	close(conn.transmitted)
	<-conn.release
	return written, err
}

type endpointAdvanceWaiter struct {
	clock   *virtualTCPClock
	advance time.Duration
}

func (waiter endpointAdvanceWaiter) Wait(
	ctx context.Context,
	delay time.Duration,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	advance := waiter.advance
	if advance == 0 {
		advance = delay
	}
	waiter.clock.Advance(advance)
	return nil
}

func endpointConfigForTest(
	clock TCPMonotonicClock,
	sink TCPTransportEventSink,
) TCPEndpointConfig {
	return TCPEndpointConfig{
		Endpoint: "tcp://192.0.2.10:502",
		PoolLimits: EndpointPoolLimits{
			MaxConnections: 2,
			Connection: ConnectionLimits{
				MaxInFlight:   4,
				MaxTombstones: 4,
			},
		},
		SchedulerLimits: SchedulerLimits{
			MaxActiveAdmissionKeys:         2,
			ProtectedSlotsPerKey:           1,
			SharedBurstSlots:               2,
			TotalQueued:                    4,
			MaxQueuedPerKey:                3,
			MaxQueuedPerAuthorizationScope: 4,
			MaxCoalescedDependentsPerKey:   3,
			MaxRetryAttempts:               3,
			MaxInFlightRequests:            4,
		},
		Backoff: BackoffConfig{
			Floor:             time.Second,
			Ceiling:           4 * time.Second,
			MaxAttempts:       3,
			Jitter:            endpointZeroJitter{},
			JitterAlgorithmID: "test-zero",
			JitterVersion:     "v1",
			JitterEvidence:    "zero",
		},
		MaxBufferedBytes:    260,
		MaxRequestDeadline:  30 * time.Second,
		MaxResponseDeadline: 30 * time.Second,
		Clock:               clock,
		EventSink:           sink,
	}
}

func endpointPlan(
	t *testing.T,
	connection TCPConnectionHandle,
	timeout time.Duration,
	deadlineIdentity uint64,
	offset uint16,
) TCPReadPlan {
	t.Helper()
	read, err := NewReadRegistersRequest(
		FunctionReadHoldingRegisters,
		offset,
		1,
	)
	if err != nil {
		t.Fatal(err)
	}
	return TCPReadPlan{
		Connection:         connection,
		UnitID:             1,
		AuthorizationScope: "endpoint-test",
		PollGeneration:     1,
		DeadlineIdentity:   deadlineIdentity,
		Timeout:            timeout,
		Reads: []TCPLogicalRead{{
			LogicalViewID: deadlineIdentity,
			Request:       read,
		}},
	}
}

func endpointWriteOne(
	t *testing.T,
	endpoint *TCPEndpoint,
	dispatch TCPDispatch,
	peer net.Conn,
) []byte {
	t.Helper()
	written := make(chan struct {
		bytes []byte
		err   error
	}, 1)
	go func() {
		bytes := make([]byte, 12)
		_, err := io.ReadFull(peer, bytes)
		written <- struct {
			bytes []byte
			err   error
		}{bytes: bytes, err: err}
	}()
	if _, err := endpoint.Write(context.Background(), dispatch); err != nil {
		t.Fatal(err)
	}
	result := <-written
	if result.err != nil {
		t.Fatal(result.err)
	}
	return result.bytes
}

func waitForActiveReadDeadline(
	t *testing.T,
	endpoint *TCPEndpoint,
	connection TCPConnectionHandle,
	want time.Duration,
) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		endpoint.mu.Lock()
		state := endpoint.connections[connection.connectionID]
		endpoint.mu.Unlock()
		if state == nil {
			t.Fatal("connection closed while waiting for read deadline")
		}
		state.transport.readDeadlineMu.Lock()
		active := state.transport.activeRead
		matches := active != nil && active.deadline == want
		state.transport.readDeadlineMu.Unlock()
		if matches {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("active read deadline did not become %s", want)
}

func endpointFailUnsafeWrite(
	t *testing.T,
	endpoint *TCPEndpoint,
	connection TCPConnectionHandle,
	timeout time.Duration,
	deadlineIdentity uint64,
	offset uint16,
) TCPRequestHandle {
	t.Helper()
	request, err := endpoint.EnqueueRead(
		endpointPlan(
			t,
			connection,
			timeout,
			deadlineIdentity,
			offset,
		),
	)
	if err != nil {
		t.Fatal(err)
	}
	dispatch, ok := endpoint.Dispatch()
	if !ok {
		t.Fatal("dispatch missing")
	}
	transition, err := endpoint.Write(context.Background(), dispatch)
	if err == nil || !transition.CloseConnection() {
		t.Fatalf("unsafe write transition=%#v err=%v", transition, err)
	}
	return request
}

func endpointResponse(request []byte, unit byte, word uint16) []byte {
	return []byte{
		request[0], request[1], 0, 0, 0, 5, unit,
		byte(FunctionReadHoldingRegisters), 2, byte(word >> 8), byte(word),
	}
}

func endpointSendFrame(peer net.Conn, frame []byte) <-chan error {
	done := make(chan error, 1)
	go func() {
		_, err := peer.Write(frame)
		done <- err
	}()
	return done
}

func TestTCPEndpointInvalidConfigFailsBeforeActivation(t *testing.T) {
	clock := &virtualTCPClock{}
	sink := &recordingTCPEventSink{}
	valid := endpointConfigForTest(clock, sink)
	tests := []struct {
		name   string
		mutate func(*TCPEndpointConfig)
	}{
		{"endpoint identity", func(config *TCPEndpointConfig) { config.Endpoint = "" }},
		{"endpoint scheme", func(config *TCPEndpointConfig) { config.Endpoint = "http://192.0.2.10:502" }},
		{"endpoint hostname", func(config *TCPEndpointConfig) { config.Endpoint = "tcp://gateway.invalid:502" }},
		{"endpoint port", func(config *TCPEndpointConfig) { config.Endpoint = "tcp://192.0.2.10:0" }},
		{"endpoint path", func(config *TCPEndpointConfig) { config.Endpoint = "tcp://192.0.2.10:502/path" }},
		{"pool", func(config *TCPEndpointConfig) { config.PoolLimits.MaxConnections = 0 }},
		{"scheduler", func(config *TCPEndpointConfig) { config.SchedulerLimits.TotalQueued = 0 }},
		{"backoff", func(config *TCPEndpointConfig) { config.Backoff.Jitter = nil }},
		{"buffer below header", func(config *TCPEndpointConfig) { config.MaxBufferedBytes = mbapHeaderSize - 1 }},
		{"buffer above cap", func(config *TCPEndpointConfig) { config.MaxBufferedBytes = maxTCPDecoderBuffer + 1 }},
		{"coalescing above cap", func(config *TCPEndpointConfig) {
			config.SchedulerLimits.TotalQueued = maxCoalescedDependents + 1
			config.SchedulerLimits.MaxQueuedPerKey = maxCoalescedDependents + 1
			config.SchedulerLimits.MaxQueuedPerAuthorizationScope = maxCoalescedDependents + 1
			config.SchedulerLimits.MaxCoalescedDependentsPerKey = maxCoalescedDependents + 1
		}},
		{"request bound", func(config *TCPEndpointConfig) { config.MaxRequestDeadline = 0 }},
		{"response bound", func(config *TCPEndpointConfig) { config.MaxResponseDeadline = 0 }},
		{"clock", func(config *TCPEndpointConfig) { config.Clock = nil }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := valid
			test.mutate(&config)
			if endpoint, err := NewTCPEndpoint(config); err == nil || endpoint != nil {
				t.Fatalf("endpoint=%#v err=%v", endpoint, err)
			}
			if events := sink.snapshot(); len(events) != 0 {
				t.Fatalf("invalid config activated event sink: %#v", events)
			}
		})
	}
}

func TestTCPEndpointRejectsDuplicateSocketOwnership(t *testing.T) {
	endpoint, err := NewTCPEndpoint(
		endpointConfigForTest(&virtualTCPClock{}, nil),
	)
	if err != nil {
		t.Fatal(err)
	}
	client, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	first, err := endpoint.openTestConnection(&endpointConnAlias{Conn: client})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := endpoint.openTestConnection(
		&endpointConnAlias{Conn: client},
	); err == nil {
		t.Fatal("socket alias acquired a second owner")
	}
	otherEndpoint, err := NewTCPEndpoint(
		endpointConfigForTest(&virtualTCPClock{}, nil),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := otherEndpoint.openTestConnection(
		&endpointConnAlias{Conn: client},
	); err == nil {
		t.Fatal("socket alias acquired an owner in another endpoint")
	}
	request, err := endpoint.EnqueueRead(
		endpointPlan(t, first, time.Second, 1, 10),
	)
	if err != nil {
		t.Fatal(err)
	}
	dispatch, ok := endpoint.Dispatch()
	if !ok {
		t.Fatal("dispatch missing")
	}
	wire := endpointWriteOne(t, endpoint, dispatch, peer)
	sent := endpointSendFrame(peer, endpointResponse(wire, 1, 0x1234))
	batch, err := endpoint.Read(context.Background(), first)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-sent; err != nil {
		t.Fatal(err)
	}
	if len(batch.Views) != 1 ||
		batch.Views[0].LogicalViewID() != request.RequestID() {
		t.Fatalf("first owner was disturbed: %#v", batch)
	}
	if err := endpoint.CloseConnection(first); err != nil {
		t.Fatal(err)
	}
	identity, err := canonicalTCPConnectionIdentity(client)
	if err != nil {
		t.Fatal(err)
	}
	tcpConnectionClaims.Lock()
	_, retained := tcpConnectionClaims.owners[identity]
	tcpConnectionClaims.Unlock()
	if retained {
		t.Fatal("closed socket retained its global ownership claim")
	}
}

func TestTCPEndpointClaimsSocketAliasesAtomically(t *testing.T) {
	endpoints := make([]*TCPEndpoint, 2)
	for index := range endpoints {
		endpoint, err := NewTCPEndpoint(
			endpointConfigForTest(&virtualTCPClock{}, nil),
		)
		if err != nil {
			t.Fatal(err)
		}
		endpoints[index] = endpoint
	}
	client, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	type openResult struct {
		index  int
		handle TCPConnectionHandle
		err    error
	}
	start := make(chan struct{})
	results := make(chan openResult, len(endpoints))
	for index, endpoint := range endpoints {
		go func() {
			<-start
			handle, err := endpoint.openTestConnection(
				&endpointConnAlias{Conn: client},
			)
			results <- openResult{index: index, handle: handle, err: err}
		}()
	}
	close(start)
	var winner openResult
	successes := 0
	for range endpoints {
		result := <-results
		if result.err == nil {
			winner = result
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent ownership successes=%d want=1", successes)
	}
	request, err := endpoints[winner.index].EnqueueRead(
		endpointPlan(t, winner.handle, time.Second, 1, 10),
	)
	if err != nil {
		t.Fatal(err)
	}
	dispatch, ok := endpoints[winner.index].Dispatch()
	if !ok {
		t.Fatal("winner dispatch missing")
	}
	wire := endpointWriteOne(t, endpoints[winner.index], dispatch, peer)
	sent := endpointSendFrame(peer, endpointResponse(wire, 1, 0x4321))
	batch, err := endpoints[winner.index].Read(
		context.Background(),
		winner.handle,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-sent; err != nil {
		t.Fatal(err)
	}
	if len(batch.Views) != 1 ||
		batch.Views[0].LogicalViewID() != request.RequestID() {
		t.Fatalf("winning owner was disturbed: %#v", batch)
	}
	if err := endpoints[winner.index].CloseConnection(winner.handle); err != nil {
		t.Fatal(err)
	}
}

func TestTCPEndpointRejectsOpaqueSocketAliasBeforeActivation(t *testing.T) {
	endpoint, err := NewTCPEndpoint(
		endpointConfigForTest(&virtualTCPClock{}, nil),
	)
	if err != nil {
		t.Fatal(err)
	}
	client, peer := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = peer.Close() }()
	if _, err := endpoint.openTestConnection(
		&endpointOpaqueConnAlias{Conn: client},
	); err == nil {
		t.Fatal("opaque socket alias was accepted without a stable identity")
	}
	writeDone := make(chan error, 1)
	go func() {
		_, err := peer.Write([]byte{0xAA})
		writeDone <- err
	}()
	buffer := make([]byte, 1)
	if _, err := client.Read(buffer); err != nil {
		t.Fatal(err)
	}
	if err := <-writeDone; err != nil {
		t.Fatalf("identity rejection closed caller-owned socket: %v", err)
	}
}

func TestTCPEndpointPublicAdmissionRejectsSyntheticSocket(t *testing.T) {
	endpoint, err := NewTCPEndpoint(
		endpointConfigForTest(&virtualTCPClock{}, nil),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = endpoint.Close() }()
	client, peer := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = peer.Close() }()
	if _, err := endpoint.OpenConnection(client); err == nil {
		t.Fatal("public endpoint admitted a socket without TCP provenance")
	}
	if snapshot := endpoint.Snapshot(); snapshot.Resources.ActiveConnections != 0 {
		t.Fatalf("rejected socket activated endpoint resources: %#v", snapshot)
	}
}

func TestTCPEndpointEventSinkCanInspectSnapshot(t *testing.T) {
	clock := &virtualTCPClock{}
	sink := &endpointSnapshotSink{
		seen: make(chan TCPEndpointSnapshot, 16),
	}
	endpoint, err := NewTCPEndpoint(endpointConfigForTest(clock, sink))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = endpoint.Close() }()
	sink.endpoint = endpoint
	client, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	connection, err := endpoint.openTestConnection(client)
	if err != nil {
		t.Fatal(err)
	}
	plan := endpointPlan(t, connection, time.Second, 1, 10)
	done := make(chan error, 1)
	go func() {
		_, enqueueErr := endpoint.EnqueueRead(plan)
		done <- enqueueErr
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("snapshot inspection deadlocked the event sink")
	}
	select {
	case snapshot := <-sink.seen:
		if snapshot.Endpoint != endpoint.config.Endpoint {
			t.Fatalf("snapshot endpoint=%q", snapshot.Endpoint)
		}
	default:
		t.Fatal("event sink did not inspect a snapshot")
	}
	clock.Advance(2 * time.Second)
	dispatchDone := make(chan bool, 1)
	go func() {
		_, ok := endpoint.Dispatch()
		dispatchDone <- ok
	}()
	select {
	case ok := <-dispatchDone:
		if ok {
			t.Fatal("expired request was dispatched")
		}
	case <-time.After(time.Second):
		t.Fatal("expiry event snapshot deadlocked the scheduler")
	}
}

func TestTCPEndpointEventSinkReentryFailsWithoutDeadlock(t *testing.T) {
	clock := &virtualTCPClock{}
	sink := &endpointReentrantCancelSink{
		result: make(chan error, 1),
	}
	endpoint, err := NewTCPEndpoint(endpointConfigForTest(clock, sink))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = endpoint.Close() }()
	sink.endpoint = endpoint
	client, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	connection, err := endpoint.openTestConnection(client)
	if err != nil {
		t.Fatal(err)
	}
	request, err := endpoint.EnqueueRead(
		endpointPlan(t, connection, time.Second, 1, 10),
	)
	if err != nil {
		t.Fatal(err)
	}
	sink.request = request
	dispatch, ok := endpoint.Dispatch()
	if !ok {
		t.Fatal("dispatch missing")
	}
	wire := endpointWriteOne(t, endpoint, dispatch, peer)
	sent := endpointSendFrame(peer, endpointResponse(wire, 1, 0x1234))
	readDone := make(chan struct {
		batch TCPReadBatch
		err   error
	}, 1)
	go func() {
		batch, readErr := endpoint.Read(context.Background(), connection)
		readDone <- struct {
			batch TCPReadBatch
			err   error
		}{batch: batch, err: readErr}
	}()
	var result struct {
		batch TCPReadBatch
		err   error
	}
	select {
	case result = <-readDone:
	case <-time.After(time.Second):
		t.Fatal("event sink re-entry deadlocked response delivery")
	}
	if err := <-sent; err != nil {
		t.Fatal(err)
	}
	if result.err != nil ||
		len(result.batch.Views) != 1 ||
		result.batch.Views[0].Words()[0] != 0x1234 {
		t.Fatalf("response batch=%#v err=%v", result.batch, result.err)
	}
	reentryErr := <-sink.result
	var protocolErr *ProtocolError
	if !errors.As(reentryErr, &protocolErr) ||
		protocolErr.Field != "event_sink_reentry" {
		t.Fatalf("reentrant cancellation error=%v", reentryErr)
	}
}

func TestTCPEndpointPublicTraceRetainsExactPhysicalOperation(t *testing.T) {
	clock := &virtualTCPClock{}
	sink := &recordingTCPEventSink{}
	endpoint, err := NewTCPEndpoint(endpointConfigForTest(clock, sink))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = endpoint.Close() }()
	client, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	connection, err := endpoint.openTestConnection(client)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := endpoint.EnqueueRead(
		endpointPlan(t, connection, time.Second, 1, 10),
	); err != nil {
		t.Fatal(err)
	}
	dispatch, ok := endpoint.Dispatch()
	if !ok {
		t.Fatal("dispatch missing")
	}
	wire := endpointWriteOne(t, endpoint, dispatch, peer)
	var prepared *TCPTransportEvent
	for _, event := range sink.snapshot() {
		if event.Kind == TCPEventWritePrepared {
			candidate := event
			prepared = &candidate
			break
		}
	}
	if prepared == nil {
		t.Fatal("write preparation event missing")
	}
	if prepared.RequestedFunction != FunctionReadHoldingRegisters ||
		prepared.LogicalTable != HoldingRegisters ||
		prepared.PhysicalOffset != 10 ||
		prepared.PhysicalQuantity != 1 ||
		prepared.RawADUHex != hex.EncodeToString(wire) {
		t.Fatalf("physical operation trace=%#v wire=%x", *prepared, wire)
	}
	responseADU := endpointResponse(wire, 1, 0x1234)
	sent := endpointSendFrame(peer, responseADU)
	if _, err := endpoint.Read(context.Background(), connection); err != nil {
		t.Fatal(err)
	}
	if err := <-sent; err != nil {
		t.Fatal(err)
	}
	var received *TCPTransportEvent
	for _, event := range sink.snapshot() {
		if event.Kind == TCPEventResponseReceive {
			candidate := event
			received = &candidate
		}
	}
	if received == nil ||
		received.RequestedFunction != FunctionReadHoldingRegisters ||
		received.ReceivedFunction != FunctionReadHoldingRegisters ||
		received.RawADUHex != hex.EncodeToString(responseADU) {
		t.Fatalf("response operation trace=%#v", received)
	}
}

func TestTCPEndpointPublicTraceDistinguishesFC03AndFC04(t *testing.T) {
	trace := func(function FunctionCode) ([]TCPTransportEvent, []byte) {
		t.Helper()
		clock := &virtualTCPClock{}
		sink := &recordingTCPEventSink{}
		endpoint, err := NewTCPEndpoint(endpointConfigForTest(clock, sink))
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = endpoint.Close() }()
		client, peer := net.Pipe()
		defer func() { _ = peer.Close() }()
		connection, err := endpoint.openTestConnection(client)
		if err != nil {
			t.Fatal(err)
		}
		request, err := NewReadRegistersRequest(function, 10, 1)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := endpoint.EnqueueRead(TCPReadPlan{
			Connection:         connection,
			UnitID:             1,
			AuthorizationScope: "trace-test",
			PollGeneration:     1,
			DeadlineIdentity:   1,
			Timeout:            time.Second,
			Reads: []TCPLogicalRead{{
				LogicalViewID: 1,
				Request:       request,
			}},
		}); err != nil {
			t.Fatal(err)
		}
		dispatch, ok := endpoint.Dispatch()
		if !ok {
			t.Fatal("dispatch missing")
		}
		wire := endpointWriteOne(t, endpoint, dispatch, peer)
		return sink.snapshot(), wire
	}
	holdingEvents, holdingWire := trace(FunctionReadHoldingRegisters)
	inputEvents, inputWire := trace(FunctionReadInputRegisters)
	if reflect.DeepEqual(holdingWire, inputWire) {
		t.Fatalf("different operations encoded equal ADUs: %x", holdingWire)
	}
	if reflect.DeepEqual(holdingEvents, inputEvents) {
		t.Fatal("public trace erased FC03/FC04 operation identity")
	}
}

func TestTCPEndpointTransactionIDExhaustionClosesAndReleasesSocket(t *testing.T) {
	config := endpointConfigForTest(&virtualTCPClock{}, nil)
	config.PoolLimits.Connection.MaxInFlight = 1 << 16
	config.PoolLimits.Connection.MaxTombstones = 1 << 16
	endpoint, err := NewTCPEndpoint(config)
	if err != nil {
		t.Fatal(err)
	}
	client, peer := net.Pipe()
	connection, err := endpoint.openTestConnection(client)
	if err != nil {
		t.Fatal(err)
	}
	endpoint.mu.Lock()
	owner := endpoint.connections[connection.connectionID].lease.ownerForEndpoint()
	endpoint.mu.Unlock()
	owner.mu.Lock()
	for transactionID := 0; transactionID < 1<<16; transactionID++ {
		id := uint16(transactionID)
		owner.tombstones[id] = ownedRequest{transactionID: id}
	}
	owner.mu.Unlock()
	if _, err := endpoint.EnqueueRead(
		endpointPlan(t, connection, 10*time.Second, 1, 10),
	); err != nil {
		t.Fatal(err)
	}
	dispatch, ok := endpoint.Dispatch()
	if !ok {
		t.Fatal("dispatch missing")
	}
	transition, err := endpoint.Write(context.Background(), dispatch)
	if err == nil || !transition.CloseConnection() {
		t.Fatalf("transition=%#v err=%v", transition, err)
	}
	buffer := make([]byte, 1)
	if _, err := peer.Read(buffer); !errors.Is(err, io.EOF) {
		t.Fatalf("peer read err=%v", err)
	}
	if active := endpoint.pool.ActiveConnections(); active != 0 {
		t.Fatalf("active pool connections=%d", active)
	}
}

func TestTCPEndpointUsesOneGlobalEventSequenceAcrossSockets(t *testing.T) {
	clock := &virtualTCPClock{}
	sink := &recordingTCPEventSink{}
	endpoint, err := NewTCPEndpoint(endpointConfigForTest(clock, sink))
	if err != nil {
		t.Fatal(err)
	}
	firstClient, firstPeer := net.Pipe()
	defer func() { _ = firstPeer.Close() }()
	secondClient, secondPeer := net.Pipe()
	defer func() { _ = secondPeer.Close() }()
	first, err := endpoint.openTestConnection(firstClient)
	if err != nil {
		t.Fatal(err)
	}
	second, err := endpoint.openTestConnection(secondClient)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := endpoint.EnqueueRead(endpointPlan(t, first, time.Second, 1, 10)); err != nil {
		t.Fatal(err)
	}
	if _, err := endpoint.EnqueueRead(endpointPlan(t, second, time.Second, 2, 20)); err != nil {
		t.Fatal(err)
	}
	firstDispatch, ok := endpoint.Dispatch()
	if !ok {
		t.Fatal("first dispatch missing")
	}
	endpointWriteOne(t, endpoint, firstDispatch, firstPeer)
	secondDispatch, ok := endpoint.Dispatch()
	if !ok {
		t.Fatal("second dispatch missing")
	}
	endpointWriteOne(t, endpoint, secondDispatch, secondPeer)

	events := sink.snapshot()
	if len(events) == 0 {
		t.Fatal("endpoint emitted no events")
	}
	for index, event := range events {
		if event.Sequence != uint64(index+1) {
			t.Fatalf("event[%d] sequence=%d events=%#v", index, event.Sequence, events)
		}
		if event.ClockContractVersion != clock.ContractVersion() {
			t.Fatalf("event clock contract=%q", event.ClockContractVersion)
		}
		if event.RequestID != 0 {
			if event.AuthorizationScope != "endpoint-test" ||
				event.PollGeneration != 1 ||
				event.DeadlineIdentity != event.RequestID ||
				event.DeadlineOffset != time.Second {
				t.Fatalf("event operation identity=%#v", event)
			}
		}
	}
	required := map[TCPTransportEventKind]bool{
		TCPEventEnqueue:         false,
		TCPEventAdmission:       false,
		TCPEventQueueService:    false,
		TCPEventWriteInvocation: false,
		TCPEventTransmitResult:  false,
	}
	for _, event := range events {
		if _, ok := required[event.Kind]; ok {
			required[event.Kind] = true
		}
	}
	for kind, seen := range required {
		if !seen {
			t.Fatalf("endpoint timeline omitted %q: %#v", kind, events)
		}
	}
}

func TestTCPEndpointPublishesAdmissionBeforeDispatchCanConsumeIt(t *testing.T) {
	endpoint, err := NewTCPEndpoint(
		endpointConfigForTest(&virtualTCPClock{}, nil),
	)
	if err != nil {
		t.Fatal(err)
	}
	client, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	connection, err := endpoint.openTestConnection(client)
	if err != nil {
		t.Fatal(err)
	}
	scheduled := make(chan struct{})
	release := make(chan struct{})
	endpoint.afterSchedule = func() {
		close(scheduled)
		<-release
	}
	enqueueDone := make(chan error, 1)
	go func() {
		_, err := endpoint.EnqueueRead(
			endpointPlan(t, connection, time.Second, 1, 10),
		)
		enqueueDone <- err
	}()
	<-scheduled
	if endpoint.scheduleMu.TryLock() {
		endpoint.scheduleMu.Unlock()
		t.Fatal("scheduler publication lock was not held")
	}
	dispatchDone := make(chan bool, 1)
	go func() {
		_, ok := endpoint.Dispatch()
		dispatchDone <- ok
	}()
	close(release)
	if err := <-enqueueDone; err != nil {
		t.Fatal(err)
	}
	if ok := <-dispatchDone; !ok {
		t.Fatal("published request was lost by dispatch")
	}
}

func TestTCPEndpointEventSequenceExhaustionRejectsAdmission(t *testing.T) {
	endpoint, err := NewTCPEndpoint(
		endpointConfigForTest(&virtualTCPClock{}, nil),
	)
	if err != nil {
		t.Fatal(err)
	}
	client, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	connection, err := endpoint.openTestConnection(client)
	if err != nil {
		t.Fatal(err)
	}
	endpoint.timeline.mu.Lock()
	endpoint.timeline.sequence = ^uint64(0) - 1
	endpoint.timeline.mu.Unlock()
	if _, err := endpoint.EnqueueRead(
		endpointPlan(t, connection, time.Second, 1, 10),
	); err == nil {
		t.Fatal("admission continued after event sequence exhaustion")
	}
	endpoint.mu.Lock()
	requests := len(endpoint.requests)
	endpoint.mu.Unlock()
	if requests != 0 {
		t.Fatalf("requests admitted after sequence exhaustion=%d", requests)
	}
	snapshot := endpoint.Snapshot()
	if !snapshot.Closed ||
		snapshot.DisableReason != "event_sequence_exhausted" ||
		snapshot.Resources.ActiveConnections != 0 {
		t.Fatalf("event exhaustion did not fail closed: %#v", snapshot)
	}
}

func TestTCPEndpointEventSequenceExhaustionClosesDispatchedWork(
	t *testing.T,
) {
	endpoint, err := NewTCPEndpoint(
		endpointConfigForTest(&virtualTCPClock{}, nil),
	)
	if err != nil {
		t.Fatal(err)
	}
	client, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	connection, err := endpoint.openTestConnection(client)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := endpoint.EnqueueRead(
		endpointPlan(t, connection, time.Second, 1, 10),
	); err != nil {
		t.Fatal(err)
	}
	endpoint.timeline.mu.Lock()
	endpoint.timeline.sequence = ^uint64(0) - 1
	endpoint.timeline.mu.Unlock()
	if _, ok := endpoint.Dispatch(); ok {
		t.Fatal("dispatch escaped event sequence exhaustion")
	}
	snapshot := endpoint.Snapshot()
	if !snapshot.Closed ||
		snapshot.DisableReason != "event_sequence_exhausted" ||
		snapshot.Resources.LiveRequests != 0 ||
		snapshot.Resources.QueuedRequests != 0 ||
		snapshot.Resources.InFlightRequests != 0 {
		t.Fatalf("event exhaustion stranded dispatch state: %#v", snapshot)
	}
}

func TestTCPEndpointEventSequenceExhaustionClosesWrite(t *testing.T) {
	endpoint, err := NewTCPEndpoint(
		endpointConfigForTest(&virtualTCPClock{}, nil),
	)
	if err != nil {
		t.Fatal(err)
	}
	client, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	connection, err := endpoint.openTestConnection(client)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := endpoint.EnqueueRead(
		endpointPlan(t, connection, time.Second, 1, 10),
	); err != nil {
		t.Fatal(err)
	}
	dispatch, ok := endpoint.Dispatch()
	if !ok {
		t.Fatal("dispatch missing")
	}
	endpoint.timeline.mu.Lock()
	endpoint.timeline.sequence = ^uint64(0) - 1
	endpoint.timeline.mu.Unlock()
	peerRead := make(chan error, 1)
	go func() {
		frame := make([]byte, 12)
		_, readErr := io.ReadFull(peer, frame)
		peerRead <- readErr
	}()
	if _, err := endpoint.Write(context.Background(), dispatch); err == nil {
		t.Fatal("write escaped event sequence exhaustion")
	}
	if err := <-peerRead; err != nil {
		t.Fatal(err)
	}
	snapshot := endpoint.Snapshot()
	if !snapshot.Closed ||
		snapshot.DisableReason != "event_sequence_exhausted" ||
		snapshot.Resources.LiveRequests != 0 {
		t.Fatalf("event exhaustion stranded write state: %#v", snapshot)
	}
}

func TestTCPEndpointEventSequenceExhaustionClosesResponseRead(
	t *testing.T,
) {
	endpoint, err := NewTCPEndpoint(
		endpointConfigForTest(&virtualTCPClock{}, nil),
	)
	if err != nil {
		t.Fatal(err)
	}
	client, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	connection, err := endpoint.openTestConnection(client)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := endpoint.EnqueueRead(
		endpointPlan(t, connection, time.Second, 1, 10),
	); err != nil {
		t.Fatal(err)
	}
	dispatch, ok := endpoint.Dispatch()
	if !ok {
		t.Fatal("dispatch missing")
	}
	wire := endpointWriteOne(t, endpoint, dispatch, peer)
	endpoint.timeline.mu.Lock()
	endpoint.timeline.sequence = ^uint64(0) - 1
	endpoint.timeline.mu.Unlock()
	sent := endpointSendFrame(peer, endpointResponse(wire, 1, 0x1234))
	if _, err := endpoint.Read(context.Background(), connection); err == nil {
		t.Fatal("response read escaped event sequence exhaustion")
	}
	if err := <-sent; err != nil {
		t.Fatal(err)
	}
	snapshot := endpoint.Snapshot()
	if !snapshot.Closed ||
		snapshot.DisableReason != "event_sequence_exhausted" ||
		snapshot.Resources.LiveRequests != 0 {
		t.Fatalf("event exhaustion stranded response state: %#v", snapshot)
	}
}

func TestTCPEndpointDispatchIdentityExhaustionDisablesEndpoint(t *testing.T) {
	endpoint, err := NewTCPEndpoint(
		endpointConfigForTest(&virtualTCPClock{}, nil),
	)
	if err != nil {
		t.Fatal(err)
	}
	client, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	connection, err := endpoint.openTestConnection(client)
	if err != nil {
		t.Fatal(err)
	}
	for identity := uint64(1); identity <= 2; identity++ {
		if _, err := endpoint.EnqueueRead(
			endpointPlan(
				t,
				connection,
				time.Second,
				identity,
				uint16(identity),
			),
		); err != nil {
			t.Fatal(err)
		}
	}
	endpoint.mu.Lock()
	endpoint.nextDispatchID = ^uint64(0)
	endpoint.mu.Unlock()
	if _, ok := endpoint.Dispatch(); !ok {
		t.Fatal("final dispatch identity was not usable")
	}
	if _, ok := endpoint.Dispatch(); ok {
		t.Fatal("dispatch wrapped identity")
	}
	snapshot := endpoint.Snapshot()
	if !snapshot.Closed ||
		snapshot.DisableReason != "dispatch_identity_exhausted" ||
		snapshot.Resources.QueuedRequests != 0 ||
		snapshot.Resources.LiveRequests != 0 {
		t.Fatalf("dispatch exhaustion did not fail closed: %#v", snapshot)
	}
}

func TestTCPEndpointRejectedPlanDoesNotConsumeLastRequestIdentity(
	t *testing.T,
) {
	endpoint, err := NewTCPEndpoint(
		endpointConfigForTest(&virtualTCPClock{}, nil),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = endpoint.Close() }()
	client, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	connection, err := endpoint.openTestConnection(client)
	if err != nil {
		t.Fatal(err)
	}
	endpoint.mu.Lock()
	endpoint.nextRequestID = ^uint64(0)
	endpoint.mu.Unlock()
	invalid := endpointPlan(t, connection, time.Second, 1, 10)
	invalid.Reads[0].LogicalViewID = 0
	if _, err := endpoint.EnqueueRead(invalid); err == nil {
		t.Fatal("invalid plan was admitted")
	}
	endpoint.mu.Lock()
	next := endpoint.nextRequestID
	endpoint.mu.Unlock()
	if next != ^uint64(0) {
		t.Fatalf("rejected plan consumed request identity: %d", next)
	}
	if _, err := endpoint.EnqueueRead(
		endpointPlan(t, connection, time.Second, 2, 20),
	); err != nil {
		t.Fatalf("last request identity was poisoned: %v", err)
	}
}

func TestTCPEndpointPublicSurfaceHasNoLowLevelConstructorBypass(t *testing.T) {
	root, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	set := token.NewFileSet()
	packages, err := parser.ParseDir(set, root, func(info os.FileInfo) bool {
		if !strings.HasSuffix(info.Name(), ".go") || strings.HasSuffix(info.Name(), "_test.go") {
			return false
		}
		included, matchErr := build.Default.MatchFile(root, info.Name())
		return matchErr == nil && included
	}, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	pkg := packages["modbus"]
	if pkg == nil {
		t.Fatal("modbus package absent")
	}
	files := make([]*ast.File, 0, len(pkg.Files))
	for path, file := range pkg.Files {
		if filepath.Ext(path) == ".go" && filepath.Base(path) != "tcp_endpoint_test.go" {
			files = append(files, file)
		}
	}
	check := types.Config{Importer: importer.Default()}
	checked, err := check.Check(
		"github.com/Project-Helianthus/helianthus-modbus",
		set,
		files,
		nil,
	)
	if err != nil {
		t.Fatalf("package must remain type-checkable without tests: %v", err)
	}
	leaked := lowLevelRuntimeFactories(checked)
	if len(leaked) != 0 {
		t.Fatalf("aggregate API leaked low-level constructors: %v", leaked)
	}
}

func TestTCPEndpointPublicSurfaceScannerRejectsFactoryAliases(t *testing.T) {
	set := token.NewFileSet()
	file, err := parser.ParseFile(
		set,
		"alias.go",
		`package modbus
type TCPTransport struct{}
func newTCPTransport() *TCPTransport { return nil }
var OpenTCPTransport = newTCPTransport
func BuildTCPTransport() *TCPTransport { return nil }
`,
		0,
	)
	if err != nil {
		t.Fatal(err)
	}
	check := types.Config{}
	checked, err := check.Check(
		"github.com/Project-Helianthus/helianthus-modbus",
		set,
		[]*ast.File{file},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := lowLevelRuntimeFactories(checked); !reflect.DeepEqual(
		got,
		[]string{"BuildTCPTransport", "OpenTCPTransport"},
	) {
		t.Fatalf("factory leaks=%v", got)
	}
}

func lowLevelRuntimeFactories(pkg *types.Package) []string {
	if pkg == nil {
		return nil
	}
	protected := map[string]bool{
		"EndpointScheduler":  true,
		"ReconnectBackoff":   true,
		"TCPConnectionOwner": true,
		"TCPEndpointPool":    true,
		"TCPTransport":       true,
	}
	var leaked []string
	scope := pkg.Scope()
	for _, name := range scope.Names() {
		if !token.IsExported(name) {
			continue
		}
		object := scope.Lookup(name)
		switch object.(type) {
		case *types.Var:
			leaked = append(leaked, name)
		case *types.Func:
			if typeExposesProtectedRuntime(object.Type(), protected) {
				leaked = append(leaked, name)
			}
		}
	}
	sort.Strings(leaked)
	return leaked
}

func typeExposesProtectedRuntime(
	value types.Type,
	protected map[string]bool,
) bool {
	switch current := value.(type) {
	case *types.Named:
		return current.Obj() != nil && protected[current.Obj().Name()]
	case *types.Pointer:
		return typeExposesProtectedRuntime(current.Elem(), protected)
	case *types.Signature:
		return tupleExposesProtectedRuntime(current.Params(), protected) ||
			tupleExposesProtectedRuntime(current.Results(), protected)
	case *types.Slice:
		return typeExposesProtectedRuntime(current.Elem(), protected)
	case *types.Array:
		return typeExposesProtectedRuntime(current.Elem(), protected)
	case *types.Map:
		return typeExposesProtectedRuntime(current.Key(), protected) ||
			typeExposesProtectedRuntime(current.Elem(), protected)
	case *types.Chan:
		return typeExposesProtectedRuntime(current.Elem(), protected)
	default:
		return false
	}
}

func tupleExposesProtectedRuntime(
	tuple *types.Tuple,
	protected map[string]bool,
) bool {
	if tuple == nil {
		return false
	}
	for index := 0; index < tuple.Len(); index++ {
		if typeExposesProtectedRuntime(tuple.At(index).Type(), protected) {
			return true
		}
	}
	return false
}

func TestTCPEndpointAbsoluteDeadlineIncludesQueueDelay(t *testing.T) {
	clock := &virtualTCPClock{}
	endpoint, err := NewTCPEndpoint(endpointConfigForTest(clock, nil))
	if err != nil {
		t.Fatal(err)
	}
	client, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	readStarted := make(chan struct{})
	connection, err := endpoint.openTestConnection(&readStartedConn{
		Conn:    client,
		started: readStarted,
	})
	if err != nil {
		t.Fatal(err)
	}
	request, err := endpoint.EnqueueRead(endpointPlan(t, connection, 10*time.Second, 1, 10))
	if err != nil {
		t.Fatal(err)
	}
	clock.Advance(7 * time.Second)
	dispatch, ok := endpoint.Dispatch()
	if !ok {
		t.Fatal("request disappeared before its absolute deadline")
	}
	endpointWriteOne(t, endpoint, dispatch, peer)

	readDone := make(chan error, 1)
	go func() {
		_, err := endpoint.Read(context.Background(), connection)
		readDone <- err
	}()
	select {
	case <-readStarted:
	case <-time.After(time.Second):
		t.Fatal("response read never reached the socket")
	}
	clock.Advance(3 * time.Second)
	select {
	case err := <-readDone:
		if err == nil {
			t.Fatal("response wait survived its enqueue-time absolute deadline")
		}
	case <-time.After(time.Second):
		t.Fatal("response wait restarted deadline after queue delay")
	}
	if err := endpoint.Cancel(request); err == nil {
		t.Fatal("expired request remained cancellable")
	}
}

func TestTCPEndpointCorrelatesResponseBeforeWriteReturns(t *testing.T) {
	clock := &virtualTCPClock{}
	endpoint, err := NewTCPEndpoint(endpointConfigForTest(clock, nil))
	if err != nil {
		t.Fatal(err)
	}
	client, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	delayed := &endpointDelayedWriteReturnConn{
		Conn:        client,
		transmitted: make(chan struct{}),
		release:     make(chan struct{}),
	}
	connection, err := endpoint.openTestConnection(delayed)
	if err != nil {
		t.Fatal(err)
	}
	request, err := endpoint.EnqueueRead(
		endpointPlan(t, connection, 10*time.Second, 1, 10),
	)
	if err != nil {
		t.Fatal(err)
	}
	dispatch, ok := endpoint.Dispatch()
	if !ok {
		t.Fatal("dispatch missing")
	}
	writeDone := make(chan error, 1)
	go func() {
		_, err := endpoint.Write(context.Background(), dispatch)
		writeDone <- err
	}()
	wire := make([]byte, 12)
	if _, err := io.ReadFull(peer, wire); err != nil {
		t.Fatal(err)
	}
	<-delayed.transmitted
	sent := endpointSendFrame(peer, endpointResponse(wire, 1, 0x4455))
	batch, err := endpoint.Read(context.Background(), connection)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-sent; err != nil {
		t.Fatal(err)
	}
	if len(batch.Views) != 1 ||
		batch.Views[0].LogicalViewID() != 1 ||
		batch.Views[0].Words()[0] != 0x4455 {
		t.Fatalf("early response batch=%#v request=%d", batch, request.RequestID())
	}
	close(delayed.release)
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
}

func TestTCPEndpointUsesEarlierOperationDeadlineNearClockLimit(t *testing.T) {
	clock := &virtualTCPClock{
		now: time.Duration(1<<63-1) - time.Second,
	}
	config := endpointConfigForTest(clock, nil)
	config.PoolLimits.Connection.MaxInFlight = 1
	config.SchedulerLimits.MaxInFlightRequests = 1
	config.MaxRequestDeadline = 2 * time.Second
	config.MaxResponseDeadline = 2 * time.Second
	endpoint, err := NewTCPEndpoint(config)
	if err != nil {
		t.Fatal(err)
	}
	client, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	connection, err := endpoint.openTestConnection(client)
	if err != nil {
		t.Fatal(err)
	}
	request, err := endpoint.EnqueueRead(
		endpointPlan(t, connection, 500*time.Millisecond, 1, 10),
	)
	if err != nil {
		t.Fatal(err)
	}
	dispatch, ok := endpoint.Dispatch()
	if !ok {
		t.Fatal("dispatch missing")
	}
	wire := endpointWriteOne(t, endpoint, dispatch, peer)
	sent := endpointSendFrame(peer, endpointResponse(wire, 1, 0x7788))
	batch, err := endpoint.Read(context.Background(), connection)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-sent; err != nil {
		t.Fatal(err)
	}
	if len(batch.Views) != 1 ||
		batch.Views[0].Words()[0] != 0x7788 {
		t.Fatalf("batch=%#v request=%d", batch, request.RequestID())
	}
}

func TestTCPEndpointAbsoluteDeadlineDoesNotRestartAtWrite(t *testing.T) {
	clock := &virtualTCPClock{}
	endpoint, err := NewTCPEndpoint(endpointConfigForTest(clock, nil))
	if err != nil {
		t.Fatal(err)
	}
	client, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	writeStarted := make(chan struct{})
	connection, err := endpoint.openTestConnection(&writeStartedConn{
		Conn:    client,
		started: writeStarted,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := endpoint.EnqueueRead(endpointPlan(t, connection, 10*time.Second, 1, 10)); err != nil {
		t.Fatal(err)
	}
	clock.Advance(7 * time.Second)
	dispatch, ok := endpoint.Dispatch()
	if !ok {
		t.Fatal("dispatch missing")
	}
	writeDone := make(chan error, 1)
	go func() {
		_, err := endpoint.Write(context.Background(), dispatch)
		writeDone <- err
	}()
	select {
	case <-writeStarted:
	case <-time.After(time.Second):
		t.Fatal("write never reached the socket")
	}
	clock.Advance(3 * time.Second)
	select {
	case err := <-writeDone:
		if err == nil {
			t.Fatal("write survived its enqueue-time absolute deadline")
		}
	case <-time.After(time.Second):
		t.Fatal("write restarted deadline after queue delay")
	}
}

func TestTCPEndpointActiveReaderAdoptsEarlierResponseDeadline(t *testing.T) {
	clock := &virtualTCPClock{}
	endpoint, err := NewTCPEndpoint(endpointConfigForTest(clock, nil))
	if err != nil {
		t.Fatal(err)
	}
	client, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	connection, err := endpoint.openTestConnection(client)
	if err != nil {
		t.Fatal(err)
	}
	first, err := endpoint.EnqueueRead(
		endpointPlan(t, connection, 10*time.Second, 1, 10),
	)
	if err != nil {
		t.Fatal(err)
	}
	firstDispatch, ok := endpoint.Dispatch()
	if !ok {
		t.Fatal("first dispatch missing")
	}
	firstWire := endpointWriteOne(t, endpoint, firstDispatch, peer)
	readDone := make(chan struct {
		batch TCPReadBatch
		err   error
	}, 1)
	go func() {
		batch, err := endpoint.Read(context.Background(), connection)
		readDone <- struct {
			batch TCPReadBatch
			err   error
		}{batch: batch, err: err}
	}()
	waitForReadDeadline := func(want time.Duration) {
		t.Helper()
		deadline := time.Now().Add(time.Second)
		for time.Now().Before(deadline) {
			endpoint.mu.Lock()
			transport := endpoint.connections[connection.connectionID].transport
			endpoint.mu.Unlock()
			transport.readDeadlineMu.Lock()
			active := transport.activeRead
			matches := active != nil && active.deadline == want
			transport.readDeadlineMu.Unlock()
			if matches {
				return
			}
			time.Sleep(time.Millisecond)
		}
		t.Fatalf("active read deadline did not become %s", want)
	}
	waitForReadDeadline(10 * time.Second)
	second, err := endpoint.EnqueueRead(
		endpointPlan(t, connection, time.Second, 2, 20),
	)
	if err != nil {
		t.Fatal(err)
	}
	secondDispatch, ok := endpoint.Dispatch()
	if !ok {
		t.Fatal("second dispatch missing")
	}
	secondWire := endpointWriteOne(t, endpoint, secondDispatch, peer)
	waitForReadDeadline(time.Second)
	clock.Advance(2 * time.Second)
	expired := <-readDone
	if expired.err == nil || len(expired.batch.Views) != 0 {
		t.Fatalf("expired batch=%#v err=%v", expired.batch, expired.err)
	}
	lateSent := endpointSendFrame(
		peer,
		endpointResponse(secondWire, 1, 0x2222),
	)
	lateBatch, err := endpoint.Read(context.Background(), connection)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-lateSent; err != nil {
		t.Fatal(err)
	}
	if len(lateBatch.Views) != 0 {
		t.Fatalf("late second response delivered=%#v", lateBatch.Views)
	}
	firstSent := endpointSendFrame(
		peer,
		endpointResponse(firstWire, 1, 0x1111),
	)
	firstBatch, err := endpoint.Read(context.Background(), connection)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-firstSent; err != nil {
		t.Fatal(err)
	}
	if len(firstBatch.Views) != 1 ||
		firstBatch.Views[0].LogicalViewID() != first.RequestID() ||
		firstBatch.Views[0].Words()[0] != 0x1111 {
		t.Fatalf(
			"first batch=%#v first=%d second=%d",
			firstBatch,
			first.RequestID(),
			second.RequestID(),
		)
	}
}

func TestTCPEndpointQueueExpiryPerformsZeroWrites(t *testing.T) {
	clock := &virtualTCPClock{}
	endpoint, err := NewTCPEndpoint(endpointConfigForTest(clock, nil))
	if err != nil {
		t.Fatal(err)
	}
	client, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	connection, err := endpoint.openTestConnection(client)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := endpoint.EnqueueRead(endpointPlan(t, connection, time.Second, 1, 10)); err != nil {
		t.Fatal(err)
	}
	clock.Advance(time.Second)
	if dispatch, ok := endpoint.Dispatch(); ok {
		t.Fatalf("expired request dispatched: %#v", dispatch)
	}
	if err := peer.SetReadDeadline(time.Now().Add(25 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 1)
	if count, err := peer.Read(buffer); count != 0 || err == nil {
		t.Fatalf("queue expiry wrote count=%d err=%v", count, err)
	}
}

func TestTCPEndpointSimultaneousExpiryUsesRequestIdentityOrder(t *testing.T) {
	clock := &virtualTCPClock{}
	sink := &recordingTCPEventSink{}
	endpoint, err := NewTCPEndpoint(endpointConfigForTest(clock, sink))
	if err != nil {
		t.Fatal(err)
	}
	client, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	connection, err := endpoint.openTestConnection(client)
	if err != nil {
		t.Fatal(err)
	}
	first, err := endpoint.EnqueueRead(
		endpointPlan(t, connection, time.Second, 1, 10),
	)
	if err != nil {
		t.Fatal(err)
	}
	second, err := endpoint.EnqueueRead(
		endpointPlan(t, connection, time.Second, 2, 20),
	)
	if err != nil {
		t.Fatal(err)
	}
	clock.Advance(time.Second)
	if _, ok := endpoint.Dispatch(); ok {
		t.Fatal("simultaneously expired work was dispatched")
	}
	var fired []uint64
	for _, event := range sink.snapshot() {
		if event.Kind == TCPEventRequestTimerFire {
			fired = append(fired, event.RequestID)
		}
	}
	if !reflect.DeepEqual(
		fired,
		[]uint64{first.RequestID(), second.RequestID()},
	) {
		t.Fatalf("expiry order=%v", fired)
	}
}

func TestTCPEndpointResponseTimeoutTombstonesOnlyExpiredRequest(t *testing.T) {
	clock := &virtualTCPClock{}
	endpoint, err := NewTCPEndpoint(endpointConfigForTest(clock, nil))
	if err != nil {
		t.Fatal(err)
	}
	client, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	connection, err := endpoint.openTestConnection(client)
	if err != nil {
		t.Fatal(err)
	}
	first, err := endpoint.EnqueueRead(endpointPlan(t, connection, time.Second, 1, 10))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := endpoint.EnqueueRead(endpointPlan(t, connection, 10*time.Second, 2, 20)); err != nil {
		t.Fatal(err)
	}
	firstDispatch, ok := endpoint.Dispatch()
	if !ok {
		t.Fatal("first dispatch missing")
	}
	firstWire := endpointWriteOne(t, endpoint, firstDispatch, peer)
	secondDispatch, ok := endpoint.Dispatch()
	if !ok {
		t.Fatal("second dispatch missing")
	}
	secondWire := endpointWriteOne(t, endpoint, secondDispatch, peer)
	clock.Advance(time.Second)
	secondSent := endpointSendFrame(peer, endpointResponse(secondWire, 1, 0x2222))
	batch, err := endpoint.Read(context.Background(), connection)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-secondSent; err != nil {
		t.Fatal(err)
	}
	responses := batch.Responses
	if len(responses) != 1 || responses[0].Outcome() != WireSuccessfulData ||
		responses[0].Words()[0] != 0x2222 {
		t.Fatalf("safe sibling response=%#v", responses)
	}
	if err := endpoint.Cancel(first); err == nil {
		t.Fatal("expired request was not tombstoned")
	}
	lateSent := endpointSendFrame(peer, endpointResponse(firstWire, 1, 0x1111))
	lateBatch, err := endpoint.Read(context.Background(), connection)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-lateSent; err != nil {
		t.Fatal(err)
	}
	late := lateBatch.Responses
	if len(late) != 1 || late[0].Outcome() != WireLateAfterAbandonment ||
		late[0].WireResponseID() == 0 || late[0].Deliverable() {
		t.Fatalf("late response=%#v", late)
	}
}

func TestTCPEndpointCancellationPrecedesItsLateResponseEvent(t *testing.T) {
	clock := &virtualTCPClock{}
	sink := &recordingTCPEventSink{}
	endpoint, err := NewTCPEndpoint(endpointConfigForTest(clock, sink))
	if err != nil {
		t.Fatal(err)
	}
	client, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	connection, err := endpoint.openTestConnection(client)
	if err != nil {
		t.Fatal(err)
	}
	request, err := endpoint.EnqueueRead(
		endpointPlan(t, connection, 10*time.Second, 1, 10),
	)
	if err != nil {
		t.Fatal(err)
	}
	dispatch, ok := endpoint.Dispatch()
	if !ok {
		t.Fatal("dispatch missing")
	}
	wire := endpointWriteOne(t, endpoint, dispatch, peer)
	if _, err := endpoint.CancelLogical(request, 1); err != nil {
		t.Fatal(err)
	}
	sent := endpointSendFrame(peer, endpointResponse(wire, 1, 0x1111))
	batch, err := endpoint.Read(context.Background(), connection)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-sent; err != nil {
		t.Fatal(err)
	}
	if len(batch.Views) != 0 {
		t.Fatalf("cancelled response views=%#v", batch.Views)
	}
	var cancellationSequence uint64
	var responseSequence uint64
	for _, event := range sink.snapshot() {
		if event.RequestID != request.RequestID() {
			continue
		}
		switch event.Kind {
		case TCPEventCallerCancellation:
			cancellationSequence = event.Sequence
		case TCPEventResponseReceive:
			responseSequence = event.Sequence
		}
	}
	if cancellationSequence == 0 ||
		responseSequence == 0 ||
		cancellationSequence >= responseSequence {
		t.Fatalf(
			"cancellation sequence=%d response sequence=%d",
			cancellationSequence,
			responseSequence,
		)
	}
}

func TestTCPEndpointUncorrelatedFramesKeepDiagnosticReceiptProvenance(t *testing.T) {
	clock := &virtualTCPClock{}
	endpoint, err := NewTCPEndpoint(endpointConfigForTest(clock, nil))
	if err != nil {
		t.Fatal(err)
	}
	client, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	connection, err := endpoint.openTestConnection(client)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := endpoint.EnqueueRead(endpointPlan(t, connection, 10*time.Second, 1, 10)); err != nil {
		t.Fatal(err)
	}
	dispatch, ok := endpoint.Dispatch()
	if !ok {
		t.Fatal("dispatch missing")
	}
	wire := endpointWriteOne(t, endpoint, dispatch, peer)
	old := []byte{0x7f, 0xff, 0, 0, 0, 5, 1, 3, 2, 0x12, 0x34}
	sent := endpointSendFrame(peer, old)
	batch, err := endpoint.Read(context.Background(), connection)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-sent; err != nil {
		t.Fatal(err)
	}
	responses := batch.Responses
	if len(responses) != 1 {
		t.Fatalf("responses=%#v", responses)
	}
	response := responses[0]
	if response.Outcome() != WireDroppedUncorrelated ||
		response.DiagnosticFrameID() == 0 || response.WireResponseID() != 0 ||
		!reflect.DeepEqual(response.Bytes(), old) {
		t.Fatalf("diagnostic response=%#v", response)
	}
	provenance := response.DiagnosticProvenance()
	if provenance.Endpoint != "tcp://192.0.2.10:502" ||
		provenance.UnitID != 1 ||
		provenance.ReceivedFunction != FunctionReadHoldingRegisters ||
		provenance.ReceivedTransportGeneration == 0 ||
		provenance.ActiveTransportGeneration == 0 {
		t.Fatalf("diagnostic provenance=%#v", provenance)
	}
	mismatch := endpointResponse(wire, 2, 0x5678)
	mismatchSent := endpointSendFrame(peer, mismatch)
	mismatchBatch, err := endpoint.Read(context.Background(), connection)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-mismatchSent; err != nil {
		t.Fatal(err)
	}
	if len(mismatchBatch.Responses) != 1 {
		t.Fatalf("mismatch responses=%#v", mismatchBatch.Responses)
	}
	mismatchResponse := mismatchBatch.Responses[0]
	if mismatchResponse.Outcome() != WireDroppedUncorrelated ||
		mismatchResponse.DiagnosticFrameID() == 0 ||
		mismatchResponse.DiagnosticFrameID() == response.DiagnosticFrameID() ||
		mismatchResponse.WireResponseID() != 0 ||
		!reflect.DeepEqual(mismatchResponse.Bytes(), mismatch) {
		t.Fatalf("mismatch response=%#v", mismatchResponse)
	}
}

func TestTCPEndpointBackoffUsesAbsoluteDeadlineAndResetsOnlyOnValidResponse(t *testing.T) {
	clock := &virtualTCPClock{}
	endpoint, err := NewTCPEndpoint(endpointConfigForTest(clock, nil))
	if err != nil {
		t.Fatal(err)
	}
	firstClient, firstPeer := net.Pipe()
	defer func() { _ = firstPeer.Close() }()
	firstConnection, err := endpoint.openTestConnection(
		&endpointPartialWriteConn{Conn: firstClient},
	)
	if err != nil {
		t.Fatal(err)
	}
	request := endpointFailUnsafeWrite(
		t,
		endpoint,
		firstConnection,
		10*time.Second,
		1,
		10,
	)
	waiter := &endpointDelayWaiter{}
	if err := endpoint.WaitReconnect(context.Background(), request, waiter); err != nil {
		t.Fatal(err)
	}
	clock.Advance(7 * time.Second)
	if err := endpoint.WaitReconnect(context.Background(), request, waiter); err == nil {
		t.Fatal("backoff restarted request deadline after queue delay")
	}
	if !reflect.DeepEqual(waiter.delays, []time.Duration{time.Second}) {
		t.Fatalf("waited=%v", waiter.delays)
	}

	// A successful TCP connect is not evidence of a valid Modbus response.
	secondClient, secondPeer := net.Pipe()
	defer func() { _ = secondPeer.Close() }()
	secondConnection, err := endpoint.openTestConnection(
		&endpointPartialWriteConn{Conn: secondClient},
	)
	if err != nil {
		t.Fatal(err)
	}
	request = endpointFailUnsafeWrite(
		t,
		endpoint,
		secondConnection,
		10*time.Second,
		2,
		20,
	)
	if err := endpoint.WaitReconnect(context.Background(), request, waiter); err != nil {
		t.Fatal(err)
	}
	if got := waiter.delays[len(waiter.delays)-1]; got != 2*time.Second {
		t.Fatalf("connection reset backoff to %v", got)
	}

	thirdClient, thirdPeer := net.Pipe()
	defer func() { _ = thirdPeer.Close() }()
	thirdConnection, err := endpoint.openTestConnection(thirdClient)
	if err != nil {
		t.Fatal(err)
	}
	if err := endpoint.Retry(request, thirdConnection); err != nil {
		t.Fatal(err)
	}
	dispatch, ok := endpoint.Dispatch()
	if !ok {
		t.Fatal("dispatch missing")
	}
	wire := endpointWriteOne(t, endpoint, dispatch, thirdPeer)
	sent := endpointSendFrame(thirdPeer, endpointResponse(wire, 1, 1))
	if _, err := endpoint.Read(context.Background(), thirdConnection); err != nil {
		t.Fatal(err)
	}
	if err := <-sent; err != nil {
		t.Fatal(err)
	}

	fourthClient, fourthPeer := net.Pipe()
	defer func() { _ = fourthPeer.Close() }()
	fourthConnection, err := endpoint.openTestConnection(
		&endpointPartialWriteConn{Conn: fourthClient},
	)
	if err != nil {
		t.Fatal(err)
	}
	next := endpointFailUnsafeWrite(
		t,
		endpoint,
		fourthConnection,
		10*time.Second,
		3,
		30,
	)
	if err := endpoint.WaitReconnect(context.Background(), next, waiter); err != nil {
		t.Fatal(err)
	}
	if got := waiter.delays[len(waiter.delays)-1]; got != time.Second {
		t.Fatalf("valid response did not reset backoff: %v", got)
	}
}

func TestTCPEndpointCloseDoesNotWaitForReconnectBackoff(t *testing.T) {
	clock := &virtualTCPClock{}
	endpoint, err := NewTCPEndpoint(endpointConfigForTest(clock, nil))
	if err != nil {
		t.Fatal(err)
	}
	client, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	connection, err := endpoint.openTestConnection(
		&endpointPartialWriteConn{Conn: client},
	)
	if err != nil {
		t.Fatal(err)
	}
	request := endpointFailUnsafeWrite(
		t,
		endpoint,
		connection,
		10*time.Second,
		1,
		10,
	)
	waiter := &endpointBlockingWaiter{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	waitDone := make(chan error, 1)
	go func() {
		waitDone <- endpoint.WaitReconnect(
			context.Background(),
			request,
			waiter,
		)
	}()
	<-waiter.started

	closeDone := make(chan error, 1)
	go func() {
		closeDone <- endpoint.Close()
	}()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("endpoint close blocked on reconnect waiter")
	}
	close(waiter.release)
	if err := <-waitDone; err == nil {
		t.Fatal("backoff wait survived endpoint shutdown")
	}
}

func TestTCPEndpointCompletedBackoffUnlocksFreshOpenAfterCancellation(t *testing.T) {
	clock := &virtualTCPClock{}
	endpoint, err := NewTCPEndpoint(endpointConfigForTest(clock, nil))
	if err != nil {
		t.Fatal(err)
	}
	client, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	connection, err := endpoint.openTestConnection(
		&endpointPartialWriteConn{Conn: client},
	)
	if err != nil {
		t.Fatal(err)
	}
	request := endpointFailUnsafeWrite(
		t,
		endpoint,
		connection,
		10*time.Second,
		1,
		10,
	)
	waiter := &endpointBlockingWaiter{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	waitDone := make(chan error, 1)
	go func() {
		waitDone <- endpoint.WaitReconnect(
			context.Background(),
			request,
			waiter,
		)
	}()
	<-waiter.started
	if err := endpoint.Cancel(request); err != nil {
		t.Fatal(err)
	}
	close(waiter.release)
	if err := <-waitDone; err == nil {
		t.Fatal("cancelled backoff waiter reported retryable success")
	}
	newClient, newPeer := net.Pipe()
	defer func() { _ = newPeer.Close() }()
	if _, err := endpoint.openTestConnection(newClient); err != nil {
		t.Fatalf("completed endpoint backoff did not unlock open: %v", err)
	}
}

func TestTCPEndpointRetryReentersNormalQueueWithSameIdentity(t *testing.T) {
	clock := &virtualTCPClock{}
	sink := &recordingTCPEventSink{}
	endpoint, err := NewTCPEndpoint(endpointConfigForTest(clock, sink))
	if err != nil {
		t.Fatal(err)
	}
	client, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	connection, err := endpoint.openTestConnection(&endpointFailOnceConn{Conn: client})
	if err != nil {
		t.Fatal(err)
	}
	request, err := endpoint.EnqueueRead(
		endpointPlan(t, connection, 10*time.Second, 1, 10),
	)
	if err != nil {
		t.Fatal(err)
	}
	firstDispatch, ok := endpoint.Dispatch()
	if !ok {
		t.Fatal("first dispatch missing")
	}
	if _, err := endpoint.Write(
		context.Background(),
		firstDispatch,
	); err == nil {
		t.Fatal("provable-zero write unexpectedly succeeded")
	}
	clock.Advance(3 * time.Second)
	if err := endpoint.Retry(request, connection); err != nil {
		t.Fatal(err)
	}
	secondDispatch, ok := endpoint.Dispatch()
	if !ok {
		t.Fatal("retry dispatch missing")
	}
	if secondDispatch.RequestID() != request.RequestID() {
		t.Fatalf(
			"retry request=%d original=%d",
			secondDispatch.RequestID(),
			request.RequestID(),
		)
	}
	wire := endpointWriteOne(t, endpoint, secondDispatch, peer)
	sent := endpointSendFrame(peer, endpointResponse(wire, 1, 0x1234))
	batch, err := endpoint.Read(context.Background(), connection)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-sent; err != nil {
		t.Fatal(err)
	}
	if len(batch.Views) != 1 ||
		batch.Views[0].LogicalViewID() != 1 ||
		batch.Views[0].Words()[0] != 0x1234 {
		t.Fatalf("retry views=%#v", batch.Views)
	}
	if err := endpoint.Retry(request, connection); err == nil {
		t.Fatal("terminal successful request accepted another retry")
	}
	retryAdmission := false
	for _, event := range sink.snapshot() {
		if event.Kind == TCPEventAdmission &&
			event.RequestID == request.RequestID() &&
			event.Detail == "retry_admitted" {
			retryAdmission = true
		}
	}
	if !retryAdmission {
		t.Fatal("retry was not represented in endpoint admission timeline")
	}
}

func TestTCPEndpointUnsafeRetryRequiresReconnectBackoff(t *testing.T) {
	clock := &virtualTCPClock{}
	sink := &recordingTCPEventSink{}
	endpoint, err := NewTCPEndpoint(endpointConfigForTest(clock, sink))
	if err != nil {
		t.Fatal(err)
	}
	oldClient, oldPeer := net.Pipe()
	defer func() { _ = oldPeer.Close() }()
	oldConnection, err := endpoint.openTestConnection(
		&endpointPartialWriteConn{Conn: oldClient},
	)
	if err != nil {
		t.Fatal(err)
	}
	request, err := endpoint.EnqueueRead(
		endpointPlan(t, oldConnection, 10*time.Second, 1, 10),
	)
	if err != nil {
		t.Fatal(err)
	}
	dispatch, ok := endpoint.Dispatch()
	if !ok {
		t.Fatal("dispatch missing")
	}
	transition, err := endpoint.Write(context.Background(), dispatch)
	if err == nil || !transition.CloseConnection() {
		t.Fatalf("partial write transition=%#v err=%v", transition, err)
	}

	newClient, newPeer := net.Pipe()
	defer func() { _ = newPeer.Close() }()
	if _, err := endpoint.openTestConnection(newClient); err == nil {
		t.Fatal("fresh connection bypassed reconnect backoff")
	}
	waiter := &endpointDelayWaiter{}
	if err := endpoint.WaitReconnect(
		context.Background(),
		request,
		waiter,
	); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(waiter.delays, []time.Duration{time.Second}) {
		t.Fatalf("reconnect delays=%v", waiter.delays)
	}
	newConnection, err := endpoint.openTestConnection(newClient)
	if err != nil {
		t.Fatal(err)
	}
	if err := endpoint.Retry(request, newConnection); err != nil {
		t.Fatal(err)
	}
	retryDispatch, ok := endpoint.Dispatch()
	if !ok {
		t.Fatal("retry dispatch missing")
	}
	wire := endpointWriteOne(t, endpoint, retryDispatch, newPeer)
	sent := endpointSendFrame(newPeer, endpointResponse(wire, 1, 0x4321))
	batch, err := endpoint.Read(context.Background(), newConnection)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-sent; err != nil {
		t.Fatal(err)
	}
	if len(batch.Views) != 1 || batch.Views[0].Words()[0] != 0x4321 {
		t.Fatalf("retry batch=%#v", batch)
	}
}

func TestTCPEndpointOneBackoffSatisfiesSocketLossSiblings(t *testing.T) {
	clock := &virtualTCPClock{}
	endpoint, err := NewTCPEndpoint(endpointConfigForTest(clock, nil))
	if err != nil {
		t.Fatal(err)
	}
	client, peer := net.Pipe()
	wrapped := &endpointFullThenPartialConn{Conn: client}
	connection, err := endpoint.openTestConnection(wrapped)
	if err != nil {
		t.Fatal(err)
	}
	first, err := endpoint.EnqueueRead(
		endpointPlan(t, connection, 10*time.Second, 1, 10),
	)
	if err != nil {
		t.Fatal(err)
	}
	firstDispatch, ok := endpoint.Dispatch()
	if !ok {
		t.Fatal("first dispatch missing")
	}
	endpointWriteOne(t, endpoint, firstDispatch, peer)
	second, err := endpoint.EnqueueRead(
		endpointPlan(t, connection, 10*time.Second, 2, 20),
	)
	if err != nil {
		t.Fatal(err)
	}
	secondDispatch, ok := endpoint.Dispatch()
	if !ok {
		t.Fatal("second dispatch missing")
	}
	if transition, err := endpoint.Write(
		context.Background(),
		secondDispatch,
	); err == nil || !transition.CloseConnection() {
		t.Fatalf("transition=%#v err=%v", transition, err)
	}
	if err := endpoint.WaitReconnect(
		context.Background(),
		second,
		&endpointDelayWaiter{},
	); err != nil {
		t.Fatal(err)
	}
	if err := endpoint.WaitReconnect(
		context.Background(),
		first,
		&endpointDelayWaiter{},
	); err == nil {
		t.Fatal("sibling accepted a duplicate endpoint backoff")
	}
	newClient, newPeer := net.Pipe()
	defer func() { _ = newPeer.Close() }()
	newConnection, err := endpoint.openTestConnection(newClient)
	if err != nil {
		t.Fatal(err)
	}
	if err := endpoint.Retry(first, newConnection); err != nil {
		t.Fatal(err)
	}
	if err := endpoint.Retry(second, newConnection); err != nil {
		t.Fatal(err)
	}
}

func TestTCPEndpointRetryCarriesSyntheticBackoffIntoDeadline(t *testing.T) {
	clock := &virtualTCPClock{}
	endpoint, err := NewTCPEndpoint(endpointConfigForTest(clock, nil))
	if err != nil {
		t.Fatal(err)
	}
	oldClient, oldPeer := net.Pipe()
	defer func() { _ = oldPeer.Close() }()
	oldConnection, err := endpoint.openTestConnection(
		&endpointPartialWriteConn{Conn: oldClient},
	)
	if err != nil {
		t.Fatal(err)
	}
	request, err := endpoint.EnqueueRead(
		endpointPlan(t, oldConnection, 3*time.Second, 1, 10),
	)
	if err != nil {
		t.Fatal(err)
	}
	dispatch, ok := endpoint.Dispatch()
	if !ok {
		t.Fatal("dispatch missing")
	}
	if transition, err := endpoint.Write(
		context.Background(),
		dispatch,
	); err == nil || !transition.CloseConnection() {
		t.Fatalf("partial write transition=%#v err=%v", transition, err)
	}

	newClient, newPeer := net.Pipe()
	defer func() { _ = newPeer.Close() }()
	waiter := &endpointDelayWaiter{}
	if err := endpoint.WaitReconnect(
		context.Background(),
		request,
		waiter,
	); err != nil {
		t.Fatal(err)
	}
	newConnection, err := endpoint.openTestConnection(newClient)
	if err != nil {
		t.Fatal(err)
	}
	if err := endpoint.Retry(request, newConnection); err != nil {
		t.Fatal(err)
	}
	clock.Advance(2 * time.Second)
	if dispatch, ok := endpoint.Dispatch(); ok {
		t.Fatalf("synthetic wait restarted deadline: %#v", dispatch)
	}
	if err := endpoint.Retry(request, newConnection); err == nil {
		t.Fatal("expired synthetic-wait request remained retryable")
	}
}

func TestTCPEndpointWaitReconnectCannotSucceedAtDeadline(t *testing.T) {
	clock := &virtualTCPClock{}
	endpoint, err := NewTCPEndpoint(endpointConfigForTest(clock, nil))
	if err != nil {
		t.Fatal(err)
	}
	client, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	connection, err := endpoint.openTestConnection(
		&endpointPartialWriteConn{Conn: client},
	)
	if err != nil {
		t.Fatal(err)
	}
	request := endpointFailUnsafeWrite(
		t,
		endpoint,
		connection,
		2*time.Second,
		1,
		10,
	)
	err = endpoint.WaitReconnect(
		context.Background(),
		request,
		endpointAdvanceWaiter{clock: clock, advance: 2 * time.Second},
	)
	if err == nil {
		t.Fatal("reconnect wait succeeded at immutable deadline")
	}
	request.backoff.mu.Lock()
	lifecycle := request.backoff.lifecycle
	request.backoff.mu.Unlock()
	if lifecycle != tcpRequestTerminal {
		t.Fatalf("deadline lifecycle=%d", lifecycle)
	}
}

func TestTCPEndpointBoundsRetainedRetryableRequests(t *testing.T) {
	clock := &virtualTCPClock{}
	config := endpointConfigForTest(clock, nil)
	config.SchedulerLimits.MaxInFlightRequests = 2
	endpoint, err := NewTCPEndpoint(config)
	if err != nil {
		t.Fatal(err)
	}
	client, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	connection, err := endpoint.openTestConnection(
		&endpointProvableZeroConn{Conn: client},
	)
	if err != nil {
		t.Fatal(err)
	}
	handles := make([]TCPRequestHandle, 0, 3)
	for requestID := uint64(1); requestID <= 3; requestID++ {
		request, err := endpoint.EnqueueRead(
			endpointPlan(
				t,
				connection,
				10*time.Second,
				requestID,
				uint16(requestID),
			),
		)
		if err != nil {
			t.Fatal(err)
		}
		dispatch, ok := endpoint.Dispatch()
		if !ok {
			t.Fatal("dispatch missing")
		}
		transition, err := endpoint.Write(context.Background(), dispatch)
		if err == nil || transition.CloseConnection() {
			t.Fatalf(
				"provable-zero transition=%#v err=%v",
				transition,
				err,
			)
		}
		handles = append(handles, request)
	}
	endpoint.mu.Lock()
	retained := len(endpoint.retryable)
	endpoint.mu.Unlock()
	if retained != config.SchedulerLimits.MaxInFlightRequests {
		t.Fatalf("retained retryable=%d", retained)
	}
	for index, handle := range handles {
		handle.backoff.mu.Lock()
		lifecycle := handle.backoff.lifecycle
		handle.backoff.mu.Unlock()
		want := tcpRequestRetryable
		if index == len(handles)-1 {
			want = tcpRequestTerminal
		}
		if lifecycle != want {
			t.Fatalf(
				"handle[%d] lifecycle=%d want=%d",
				index,
				lifecycle,
				want,
			)
		}
	}
	if err := endpoint.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestTCPEndpointCancelsRetainedRetryableRequest(t *testing.T) {
	endpoint, err := NewTCPEndpoint(
		endpointConfigForTest(&virtualTCPClock{}, nil),
	)
	if err != nil {
		t.Fatal(err)
	}
	client, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	connection, err := endpoint.openTestConnection(
		&endpointProvableZeroConn{Conn: client},
	)
	if err != nil {
		t.Fatal(err)
	}
	request, err := endpoint.EnqueueRead(
		endpointPlan(t, connection, 10*time.Second, 1, 10),
	)
	if err != nil {
		t.Fatal(err)
	}
	dispatch, ok := endpoint.Dispatch()
	if !ok {
		t.Fatal("dispatch missing")
	}
	if _, err := endpoint.Write(context.Background(), dispatch); err == nil {
		t.Fatal("provable-zero write unexpectedly succeeded")
	}
	if err := endpoint.Cancel(request); err != nil {
		t.Fatal(err)
	}
	if err := endpoint.Retry(request, connection); err == nil {
		t.Fatal("cancelled retryable request was revived")
	}
	endpoint.mu.Lock()
	retained := len(endpoint.retryable)
	endpoint.mu.Unlock()
	if retained != 0 {
		t.Fatalf("cancelled retryable retained=%d", retained)
	}
}

func TestTCPEndpointReapsExpiredRetryableBeforeCapacityCheck(t *testing.T) {
	clock := &virtualTCPClock{}
	config := endpointConfigForTest(clock, nil)
	config.SchedulerLimits.MaxInFlightRequests = 1
	endpoint, err := NewTCPEndpoint(config)
	if err != nil {
		t.Fatal(err)
	}
	client, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	connection, err := endpoint.openTestConnection(
		&endpointProvableZeroConn{Conn: client},
	)
	if err != nil {
		t.Fatal(err)
	}
	fail := func(identity uint64, timeout time.Duration) TCPRequestHandle {
		request, err := endpoint.EnqueueRead(
			endpointPlan(t, connection, timeout, identity, uint16(identity)),
		)
		if err != nil {
			t.Fatal(err)
		}
		dispatch, ok := endpoint.Dispatch()
		if !ok {
			t.Fatal("dispatch missing")
		}
		if _, err := endpoint.Write(context.Background(), dispatch); err == nil {
			t.Fatal("provable-zero write unexpectedly succeeded")
		}
		return request
	}
	first := fail(1, time.Second)
	clock.Advance(2 * time.Second)
	second := fail(2, 10*time.Second)
	first.backoff.mu.Lock()
	firstLifecycle := first.backoff.lifecycle
	first.backoff.mu.Unlock()
	second.backoff.mu.Lock()
	secondLifecycle := second.backoff.lifecycle
	second.backoff.mu.Unlock()
	if firstLifecycle != tcpRequestTerminal ||
		secondLifecycle != tcpRequestRetryable {
		t.Fatalf(
			"lifecycles first=%d second=%d",
			firstLifecycle,
			secondLifecycle,
		)
	}
	endpoint.mu.Lock()
	retained := len(endpoint.retryable)
	endpoint.mu.Unlock()
	if retained != 1 {
		t.Fatalf("retained retryable=%d", retained)
	}
}

func TestTCPEndpointRetainsUnsafeBackoffWhenRetryCapacityIsFull(t *testing.T) {
	clock := &virtualTCPClock{}
	config := endpointConfigForTest(clock, nil)
	config.SchedulerLimits.MaxInFlightRequests = 1
	endpoint, err := NewTCPEndpoint(config)
	if err != nil {
		t.Fatal(err)
	}
	client, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	connection, err := endpoint.openTestConnection(
		&endpointSafeThenUnsafeConn{Conn: client},
	)
	if err != nil {
		t.Fatal(err)
	}
	fail := func(identity uint64) TCPRequestHandle {
		request, err := endpoint.EnqueueRead(
			endpointPlan(
				t,
				connection,
				10*time.Second,
				identity,
				uint16(identity),
			),
		)
		if err != nil {
			t.Fatal(err)
		}
		dispatch, ok := endpoint.Dispatch()
		if !ok {
			t.Fatal("dispatch missing")
		}
		if _, err := endpoint.Write(context.Background(), dispatch); err == nil {
			t.Fatal("scripted write unexpectedly succeeded")
		}
		return request
	}
	safe := fail(1)
	unsafe := fail(2)
	safe.backoff.mu.Lock()
	safeLifecycle := safe.backoff.lifecycle
	safe.backoff.mu.Unlock()
	unsafe.backoff.mu.Lock()
	unsafeLifecycle := unsafe.backoff.lifecycle
	unsafe.backoff.mu.Unlock()
	if safeLifecycle != tcpRequestTerminal ||
		unsafeLifecycle != tcpRequestRetryable {
		t.Fatalf(
			"lifecycles safe=%d unsafe=%d",
			safeLifecycle,
			unsafeLifecycle,
		)
	}
	if err := endpoint.WaitReconnect(
		context.Background(),
		unsafe,
		&endpointDelayWaiter{},
	); err != nil {
		t.Fatal(err)
	}
}

func TestTCPEndpointRetryLimitTerminalizesRetainedRequest(t *testing.T) {
	clock := &virtualTCPClock{}
	config := endpointConfigForTest(clock, nil)
	config.SchedulerLimits.MaxRetryAttempts = 1
	endpoint, err := NewTCPEndpoint(config)
	if err != nil {
		t.Fatal(err)
	}
	client, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	connection, err := endpoint.openTestConnection(
		&endpointProvableZeroConn{Conn: client},
	)
	if err != nil {
		t.Fatal(err)
	}
	request, err := endpoint.EnqueueRead(
		endpointPlan(t, connection, 10*time.Second, 1, 10),
	)
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		dispatch, ok := endpoint.Dispatch()
		if !ok {
			t.Fatal("dispatch missing")
		}
		transition, err := endpoint.Write(context.Background(), dispatch)
		if err == nil || transition.CloseConnection() {
			t.Fatalf(
				"provable-zero transition=%#v err=%v",
				transition,
				err,
			)
		}
		if attempt == 0 {
			if err := endpoint.Retry(request, connection); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := endpoint.Retry(request, connection); err == nil {
		t.Fatal("retry limit accepted another attempt")
	}
	request.backoff.mu.Lock()
	lifecycle := request.backoff.lifecycle
	request.backoff.mu.Unlock()
	if lifecycle != tcpRequestTerminal {
		t.Fatalf("retry-limit lifecycle=%d", lifecycle)
	}
	endpoint.mu.Lock()
	retained := len(endpoint.retryable)
	endpoint.mu.Unlock()
	if retained != 0 {
		t.Fatalf("retry-limit retained=%d", retained)
	}
}

func TestTCPEndpointRetryDoesNotReviveCancelledLogicalView(t *testing.T) {
	clock := &virtualTCPClock{}
	endpoint, err := NewTCPEndpoint(endpointConfigForTest(clock, nil))
	if err != nil {
		t.Fatal(err)
	}
	client, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	connection, err := endpoint.openTestConnection(&endpointFailOnceConn{Conn: client})
	if err != nil {
		t.Fatal(err)
	}
	wide, _ := NewReadRegistersRequest(
		FunctionReadHoldingRegisters,
		10,
		2,
	)
	narrow, _ := NewReadRegistersRequest(
		FunctionReadHoldingRegisters,
		11,
		1,
	)
	request, err := endpoint.EnqueueRead(TCPReadPlan{
		Connection:         connection,
		UnitID:             1,
		AuthorizationScope: "endpoint-test",
		PollGeneration:     1,
		DeadlineIdentity:   1,
		Timeout:            10 * time.Second,
		Reads: []TCPLogicalRead{
			{LogicalViewID: 1, Request: wide},
			{LogicalViewID: 2, Request: narrow},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := endpoint.CancelLogical(request, 1); err != nil {
		t.Fatal(err)
	}
	firstDispatch, ok := endpoint.Dispatch()
	if !ok {
		t.Fatal("first dispatch missing")
	}
	if _, err := endpoint.Write(
		context.Background(),
		firstDispatch,
	); err == nil {
		t.Fatal("provable-zero write unexpectedly succeeded")
	}
	if err := endpoint.Retry(request, connection); err != nil {
		t.Fatal(err)
	}
	secondDispatch, ok := endpoint.Dispatch()
	if !ok {
		t.Fatal("retry dispatch missing")
	}
	wire := endpointWriteOne(t, endpoint, secondDispatch, peer)
	if !reflect.DeepEqual(wire[8:12], []byte{0, 11, 0, 1}) {
		t.Fatalf("retry revived cancelled range: %v", wire)
	}
	sent := endpointSendFrame(peer, endpointResponse(wire, 1, 0x2222))
	batch, err := endpoint.Read(context.Background(), connection)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-sent; err != nil {
		t.Fatal(err)
	}
	if len(batch.Views) != 1 ||
		batch.Views[0].LogicalViewID() != 2 ||
		batch.Views[0].Words()[0] != 0x2222 {
		t.Fatalf("retry views=%#v", batch.Views)
	}
}

func TestTCPEndpointPreWriteCancellationShrinksReservedPhysicalRead(
	t *testing.T,
) {
	clock := &virtualTCPClock{}
	sink := &recordingTCPEventSink{}
	endpoint, err := NewTCPEndpoint(endpointConfigForTest(clock, sink))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = endpoint.Close() }()
	client, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	connection, err := endpoint.openTestConnection(client)
	if err != nil {
		t.Fatal(err)
	}
	first, _ := NewReadRegistersRequest(
		FunctionReadHoldingRegisters,
		10,
		4,
	)
	second, _ := NewReadRegistersRequest(
		FunctionReadHoldingRegisters,
		12,
		4,
	)
	request, err := endpoint.EnqueueRead(TCPReadPlan{
		Connection:         connection,
		UnitID:             1,
		AuthorizationScope: "endpoint-test",
		PollGeneration:     1,
		DeadlineIdentity:   1,
		Timeout:            10 * time.Second,
		Reads: []TCPLogicalRead{
			{LogicalViewID: 1, Request: first},
			{LogicalViewID: 2, Request: second},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	dispatch, ok := endpoint.Dispatch()
	if !ok {
		t.Fatal("dispatch missing")
	}
	endpoint.mu.Lock()
	state := endpoint.connections[connection.connectionID]
	endpoint.mu.Unlock()
	if state == nil {
		t.Fatal("connection state missing")
	}
	<-state.transport.writeGate
	writeDone := make(chan error, 1)
	go func() {
		_, writeErr := endpoint.Write(context.Background(), dispatch)
		writeDone <- writeErr
	}()
	deadline := time.Now().Add(time.Second)
	for {
		endpoint.mu.Lock()
		active := endpoint.requests[request.requestID]
		endpoint.mu.Unlock()
		if active == nil {
			t.Fatal("request disappeared before reservation binding")
		}
		active.group.mu.Lock()
		bound := active.group.owner != nil
		active.group.mu.Unlock()
		if bound {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("write did not bind reservation before gate")
		}
		time.Sleep(time.Millisecond)
	}
	if _, err := endpoint.CancelLogical(request, 1); err != nil {
		t.Fatal(err)
	}
	wireDone := make(chan struct {
		wire []byte
		err  error
	}, 1)
	go func() {
		wire := make([]byte, 12)
		_, readErr := io.ReadFull(peer, wire)
		wireDone <- struct {
			wire []byte
			err  error
		}{wire: wire, err: readErr}
	}()
	state.transport.writeGate <- struct{}{}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	wireResult := <-wireDone
	if wireResult.err != nil {
		t.Fatal(wireResult.err)
	}
	if !reflect.DeepEqual(
		wireResult.wire[8:12],
		[]byte{0, 12, 0, 4},
	) {
		t.Fatalf(
			"cancelled range remains on wire: %v",
			wireResult.wire[8:12],
		)
	}
	required := map[TCPTransportEventKind]bool{
		TCPEventRequestTimerArm: false,
		TCPEventWritePrepared:   false,
		TCPEventWriteInvocation: false,
		TCPEventWriteReturn:     false,
		TCPEventTransmitResult:  false,
	}
	for _, event := range sink.snapshot() {
		if event.Kind == TCPEventRequestTimerArm {
			required[event.Kind] = true
			if event.RequestedFunction != 0 ||
				event.LogicalTable != "" ||
				event.PhysicalOffset != 0 ||
				event.PhysicalQuantity != 0 ||
				event.RawADUHex != "" {
				t.Fatalf(
					"pre-bound timer published mutable physical range: %#v",
					event,
				)
			}
			continue
		}
		if _, ok := required[event.Kind]; !ok {
			continue
		}
		required[event.Kind] = true
		if event.RequestedFunction != FunctionReadHoldingRegisters ||
			event.LogicalTable != HoldingRegisters ||
			event.PhysicalOffset != 12 ||
			event.PhysicalQuantity != 4 ||
			event.RawADUHex != hex.EncodeToString(wireResult.wire) {
			t.Fatalf(
				"shrunken physical operation trace=%#v wire=%x",
				event,
				wireResult.wire,
			)
		}
	}
	for kind, seen := range required {
		if !seen {
			t.Fatalf("shrunken operation omitted event %q", kind)
		}
	}
}

func TestTCPEndpointContainsEventSinkPanicWithoutPoisoningOutcome(
	t *testing.T,
) {
	var panicOnce sync.Once
	sink := &recordingTCPEventSink{
		hook: func(event TCPTransportEvent) {
			if event.Kind == TCPEventCallerCancellation {
				panicOnce.Do(func() { panic("sink failure") })
			}
		},
	}
	clock := &virtualTCPClock{}
	endpoint, err := NewTCPEndpoint(endpointConfigForTest(clock, sink))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = endpoint.Close() }()
	client, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	connection, err := endpoint.openTestConnection(client)
	if err != nil {
		t.Fatal(err)
	}
	request, err := endpoint.EnqueueRead(
		endpointPlan(t, connection, 10*time.Second, 1, 10),
	)
	if err != nil {
		t.Fatal(err)
	}
	dispatch, ok := endpoint.Dispatch()
	if !ok {
		t.Fatal("dispatch missing")
	}
	_ = endpointWriteOne(t, endpoint, dispatch, peer)
	if _, err := endpoint.CancelLogical(request, 1); err != nil {
		t.Fatal(err)
	}
	if endpoint.Snapshot().Metrics.EventSinkPanics != 1 {
		t.Fatalf(
			"sink panic metric=%d",
			endpoint.Snapshot().Metrics.EventSinkPanics,
		)
	}
	done := make(chan error, 1)
	go func() {
		_, cancelErr := endpoint.CancelLogical(request, 1)
		done <- cancelErr
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("second cancellation unexpectedly succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("event sink panic poisoned endpoint outcome state")
	}
}

func TestTCPEndpointCloseRetiresAllOwnedState(t *testing.T) {
	clock := &virtualTCPClock{}
	endpoint, err := NewTCPEndpoint(endpointConfigForTest(clock, nil))
	if err != nil {
		t.Fatal(err)
	}
	firstClient, firstPeer := net.Pipe()
	defer func() { _ = firstPeer.Close() }()
	secondClient, secondPeer := net.Pipe()
	defer func() { _ = secondPeer.Close() }()
	firstConnection, err := endpoint.openTestConnection(firstClient)
	if err != nil {
		t.Fatal(err)
	}
	secondConnection, err := endpoint.openTestConnection(secondClient)
	if err != nil {
		t.Fatal(err)
	}
	waiting, err := endpoint.EnqueueRead(
		endpointPlan(t, firstConnection, 10*time.Second, 1, 10),
	)
	if err != nil {
		t.Fatal(err)
	}
	dispatch, ok := endpoint.Dispatch()
	if !ok {
		t.Fatal("dispatch missing")
	}
	_ = endpointWriteOne(t, endpoint, dispatch, firstPeer)
	queued, err := endpoint.EnqueueRead(
		endpointPlan(t, secondConnection, 10*time.Second, 2, 20),
	)
	if err != nil {
		t.Fatal(err)
	}

	if err := endpoint.Close(); err != nil {
		t.Fatal(err)
	}
	if err := endpoint.Close(); err != nil {
		t.Fatalf("idempotent close: %v", err)
	}
	if endpoint.pool.ActiveConnections() != 0 {
		t.Fatalf(
			"active connections=%d",
			endpoint.pool.ActiveConnections(),
		)
	}
	if size := endpoint.scheduler.OrderMetadataSize(); size != 0 {
		t.Fatalf("scheduler metadata=%d", size)
	}
	endpoint.mu.Lock()
	closed := endpoint.closed
	connectionCount := len(endpoint.connections)
	requestCount := len(endpoint.requests)
	physicalCount := len(endpoint.physical)
	retryableCount := len(endpoint.retryable)
	endpoint.mu.Unlock()
	if !closed ||
		connectionCount != 0 ||
		requestCount != 0 ||
		physicalCount != 0 ||
		retryableCount != 0 {
		t.Fatalf(
			"closed=%v connections=%d requests=%d physical=%d retryable=%d",
			closed,
			connectionCount,
			requestCount,
			physicalCount,
			retryableCount,
		)
	}
	if err := endpoint.Retry(waiting, firstConnection); err == nil {
		t.Fatal("close left waiting request retryable")
	}
	if err := endpoint.Retry(queued, secondConnection); err == nil {
		t.Fatal("close left queued request retryable")
	}
	thirdClient, thirdPeer := net.Pipe()
	defer func() { _ = thirdClient.Close() }()
	defer func() { _ = thirdPeer.Close() }()
	if _, err := endpoint.openTestConnection(thirdClient); err == nil {
		t.Fatal("closed endpoint accepted a socket")
	}
}

func TestTCPEndpointRejectsSecondRootForPhysicalRemote(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	firstClient, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = firstClient.Close() }()
	firstPeer, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = firstPeer.Close() }()
	secondClient, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = secondClient.Close() }()
	secondPeer, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = secondPeer.Close() }()

	config := endpointConfigForTest(NewRealTCPMonotonicClock(), nil)
	config.Endpoint = "tcp://" + listener.Addr().String()
	first, err := NewTCPEndpoint(config)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = first.Close() }()
	second, err := NewTCPEndpoint(config)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = second.Close() }()
	if _, err := first.openTestConnection(firstClient); err != nil {
		t.Fatal(err)
	}
	if _, err := second.openTestConnection(secondClient); err == nil {
		t.Fatal("second endpoint root acquired the same physical remote")
	}
}

func TestTCPEndpointRejectsMismatchedRemoteBeforeSocketClaim(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	peer, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = peer.Close() }()

	wrongConfig := endpointConfigForTest(NewRealTCPMonotonicClock(), nil)
	wrongConfig.Endpoint = "tcp://127.0.0.1:1"
	wrong, err := NewTCPEndpoint(wrongConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = wrong.Close() }()
	if _, err := wrong.openTestConnection(client); err == nil {
		t.Fatal("mismatched remote was accepted")
	}

	rightConfig := endpointConfigForTest(NewRealTCPMonotonicClock(), nil)
	rightConfig.Endpoint = "tcp://" + listener.Addr().String()
	right, err := NewTCPEndpoint(rightConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = right.Close() }()
	if _, err := right.openTestConnection(client); err != nil {
		t.Fatalf("rejected provenance check polluted socket claim: %v", err)
	}
}

func TestTCPEndpointDispatchedDeadlineReleasesSchedulerSlot(t *testing.T) {
	clock := &virtualTCPClock{}
	config := endpointConfigForTest(clock, nil)
	config.SchedulerLimits.MaxInFlightRequests = 1
	endpoint, err := NewTCPEndpoint(config)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = endpoint.Close() }()
	client, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	connection, err := endpoint.openTestConnection(client)
	if err != nil {
		t.Fatal(err)
	}
	first, err := endpoint.EnqueueRead(
		endpointPlan(t, connection, time.Second, 1, 10),
	)
	if err != nil {
		t.Fatal(err)
	}
	second, err := endpoint.EnqueueRead(
		endpointPlan(t, connection, 10*time.Second, 2, 20),
	)
	if err != nil {
		t.Fatal(err)
	}
	dispatch, ok := endpoint.Dispatch()
	if !ok || dispatch.RequestID() != first.RequestID() {
		t.Fatal("first dispatch missing")
	}
	clock.Advance(time.Second)
	dispatch, ok = endpoint.Dispatch()
	if !ok || dispatch.RequestID() != second.RequestID() {
		t.Fatalf("expired dispatch retained scheduler slot: %#v", dispatch)
	}
	if _, err := endpoint.Write(context.Background(), TCPDispatch{
		endpoint:   endpoint,
		dispatchID: 1,
		requestID:  first.RequestID(),
	}); err == nil {
		t.Fatal("expired dispatch token remained writable")
	}
}

func TestTCPEndpointCancelCannotBeLostDuringRetryAdmission(t *testing.T) {
	clock := &virtualTCPClock{}
	endpoint, err := NewTCPEndpoint(endpointConfigForTest(clock, nil))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = endpoint.Close() }()
	client, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	connection, err := endpoint.openTestConnection(
		&endpointProvableZeroConn{Conn: client},
	)
	if err != nil {
		t.Fatal(err)
	}
	request, err := endpoint.EnqueueRead(
		endpointPlan(t, connection, 10*time.Second, 1, 10),
	)
	if err != nil {
		t.Fatal(err)
	}
	dispatch, ok := endpoint.Dispatch()
	if !ok {
		t.Fatal("dispatch missing")
	}
	if _, err := endpoint.Write(context.Background(), dispatch); err == nil {
		t.Fatal("provable-zero write unexpectedly succeeded")
	}
	retryScheduled := make(chan struct{})
	releaseRetry := make(chan struct{})
	endpoint.afterSchedule = func() {
		close(retryScheduled)
		<-releaseRetry
	}
	retryDone := make(chan error, 1)
	go func() {
		retryDone <- endpoint.Retry(request, connection)
	}()
	<-retryScheduled
	if err := endpoint.Cancel(request); err != nil {
		t.Fatalf("cancel was lost during retry admission: %v", err)
	}
	close(releaseRetry)
	if err := <-retryDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("retry result=%v", err)
	}
	if next, ok := endpoint.Dispatch(); ok {
		t.Fatalf("cancelled retry became dispatchable: %#v", next)
	}
}

func TestTCPEndpointCancelledUnsafeRetryRetainsRecoveryBackoff(t *testing.T) {
	clock := &virtualTCPClock{}
	endpoint, err := NewTCPEndpoint(endpointConfigForTest(clock, nil))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = endpoint.Close() }()
	client, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	connection, err := endpoint.openTestConnection(
		&endpointPartialWriteConn{Conn: client},
	)
	if err != nil {
		t.Fatal(err)
	}
	request := endpointFailUnsafeWrite(
		t,
		endpoint,
		connection,
		10*time.Second,
		1,
		10,
	)
	if err := endpoint.Cancel(request); err != nil {
		t.Fatal(err)
	}
	blocked, blockedPeer := net.Pipe()
	defer func() { _ = blockedPeer.Close() }()
	if _, err := endpoint.openTestConnection(blocked); err == nil {
		t.Fatal("cancel bypassed mandatory endpoint backoff")
	}
	if err := endpoint.WaitReconnect(
		context.Background(),
		request,
		&endpointDelayWaiter{},
	); err != nil {
		t.Fatalf("terminal recovery backoff failed: %v", err)
	}
	replacement, replacementPeer := net.Pipe()
	defer func() { _ = replacementPeer.Close() }()
	if _, err := endpoint.openTestConnection(replacement); err != nil {
		t.Fatalf("completed recovery did not unlock endpoint: %v", err)
	}
}

func TestTCPEndpointEarlyResponseThenUnsafeWriteDropsConnection(t *testing.T) {
	clock := &virtualTCPClock{}
	endpoint, err := NewTCPEndpoint(endpointConfigForTest(clock, nil))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = endpoint.Close() }()
	client, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	wrapped := &endpointEarlyResponsePartialConn{
		Conn:        client,
		transmitted: make(chan struct{}),
		release:     make(chan struct{}),
	}
	connection, err := endpoint.openTestConnection(wrapped)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := endpoint.EnqueueRead(
		endpointPlan(t, connection, 10*time.Second, 1, 10),
	); err != nil {
		t.Fatal(err)
	}
	dispatch, ok := endpoint.Dispatch()
	if !ok {
		t.Fatal("dispatch missing")
	}
	writeDone := make(chan struct {
		transition OwnerTransition
		err        error
	}, 1)
	go func() {
		transition, err := endpoint.Write(context.Background(), dispatch)
		writeDone <- struct {
			transition OwnerTransition
			err        error
		}{transition: transition, err: err}
	}()
	wire := make([]byte, 12)
	if _, err := io.ReadFull(peer, wire); err != nil {
		t.Fatal(err)
	}
	<-wrapped.transmitted
	sent := endpointSendFrame(peer, endpointResponse(wire, 1, 0x1234))
	batch, err := endpoint.Read(context.Background(), connection)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-sent; err != nil {
		t.Fatal(err)
	}
	if len(batch.Views) != 1 || batch.Views[0].Words()[0] != 0x1234 {
		t.Fatalf("early response batch=%#v", batch)
	}
	close(wrapped.release)
	result := <-writeDone
	if result.err == nil || !result.transition.CloseConnection() {
		t.Fatalf("transition=%#v err=%v", result.transition, result.err)
	}
	endpoint.mu.Lock()
	connectionCount := len(endpoint.connections)
	endpoint.mu.Unlock()
	if connectionCount != 0 || endpoint.pool.ActiveConnections() != 0 {
		t.Fatalf(
			"closed transport retained state: endpoint=%d pool=%d",
			connectionCount,
			endpoint.pool.ActiveConnections(),
		)
	}
}

func TestTCPEndpointExpiredFullTransmitEmitsResponseWaitTombstone(t *testing.T) {
	clock := &virtualTCPClock{advanceOnStop: true}
	sink := &recordingTCPEventSink{}
	endpoint, err := NewTCPEndpoint(endpointConfigForTest(clock, sink))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = endpoint.Close() }()
	client, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	connection, err := endpoint.openTestConnection(client)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := endpoint.EnqueueRead(
		endpointPlan(t, connection, time.Second, 1, 10),
	); err != nil {
		t.Fatal(err)
	}
	dispatch, ok := endpoint.Dispatch()
	if !ok {
		t.Fatal("dispatch missing")
	}
	readDone := make(chan error, 1)
	go func() {
		wire := make([]byte, 12)
		_, err := io.ReadFull(peer, wire)
		readDone <- err
	}()
	if _, err := endpoint.Write(context.Background(), dispatch); err == nil {
		t.Fatal("expired write unexpectedly succeeded")
	}
	if err := <-readDone; err != nil {
		t.Fatal(err)
	}
	for _, event := range sink.snapshot() {
		if event.Kind == TCPEventQuarantineTransition &&
			event.Detail == "tcp_response_wait_tombstone" {
			return
		}
	}
	t.Fatal("expired full transmit omitted response-wait tombstone event")
}

func TestTCPEndpointDelayedReadInterruptCannotPoisonNextRead(t *testing.T) {
	clock := &virtualTCPClock{}
	endpoint, err := NewTCPEndpoint(endpointConfigForTest(clock, nil))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = endpoint.Close() }()
	client, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	wrapped := &endpointDelayedReadDeadlineConn{
		Conn:           client,
		readStarted:    make(chan struct{}),
		expiredStarted: make(chan struct{}),
		releaseExpired: make(chan struct{}),
	}
	connection, err := endpoint.openTestConnection(wrapped)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := endpoint.EnqueueRead(
		endpointPlan(t, connection, 10*time.Second, 1, 10),
	); err != nil {
		t.Fatal(err)
	}
	firstDispatch, ok := endpoint.Dispatch()
	if !ok {
		t.Fatal("first dispatch missing")
	}
	firstWire := endpointWriteOne(t, endpoint, firstDispatch, peer)
	firstReadDone := make(chan struct {
		batch TCPReadBatch
		err   error
	}, 1)
	go func() {
		batch, err := endpoint.Read(context.Background(), connection)
		firstReadDone <- struct {
			batch TCPReadBatch
			err   error
		}{batch: batch, err: err}
	}()
	<-wrapped.readStarted

	if _, err := endpoint.EnqueueRead(
		endpointPlan(t, connection, time.Second, 2, 20),
	); err != nil {
		t.Fatal(err)
	}
	secondDispatch, ok := endpoint.Dispatch()
	if !ok {
		t.Fatal("second dispatch missing")
	}
	secondWireRead := make(chan []byte, 1)
	go func() {
		wire := make([]byte, 12)
		_, _ = io.ReadFull(peer, wire)
		secondWireRead <- wire
	}()
	secondWriteDone := make(chan error, 1)
	go func() {
		_, err := endpoint.Write(context.Background(), secondDispatch)
		secondWriteDone <- err
	}()
	<-wrapped.expiredStarted
	firstSent := endpointSendFrame(
		peer,
		endpointResponse(firstWire, 1, 0x1111),
	)
	select {
	case result := <-firstReadDone:
		t.Fatalf("read escaped before interrupt serialization: %#v", result)
	case <-time.After(20 * time.Millisecond):
	}
	close(wrapped.releaseExpired)
	firstResult := <-firstReadDone
	if firstResult.err != nil ||
		len(firstResult.batch.Views) != 1 ||
		firstResult.batch.Views[0].Words()[0] != 0x1111 {
		t.Fatalf("first read batch=%#v err=%v", firstResult.batch, firstResult.err)
	}
	if err := <-firstSent; err != nil {
		t.Fatal(err)
	}
	if err := <-secondWriteDone; err != nil {
		t.Fatal(err)
	}
	secondWire := <-secondWireRead
	secondSent := endpointSendFrame(
		peer,
		endpointResponse(secondWire, 1, 0x2222),
	)
	secondBatch, err := endpoint.Read(context.Background(), connection)
	if err != nil {
		t.Fatalf("stale expired deadline poisoned next read: %v", err)
	}
	if err := <-secondSent; err != nil {
		t.Fatal(err)
	}
	if len(secondBatch.Views) != 1 ||
		secondBatch.Views[0].Words()[0] != 0x2222 {
		t.Fatalf("second read batch=%#v", secondBatch)
	}
}

func TestTCPEndpointUnsafeCloseGatesOpenBeforePoolRelease(t *testing.T) {
	clock := &virtualTCPClock{}
	endpoint, err := NewTCPEndpoint(endpointConfigForTest(clock, nil))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = endpoint.Close() }()
	client, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	connection, err := endpoint.openTestConnection(
		&endpointPartialWriteConn{Conn: client},
	)
	if err != nil {
		t.Fatal(err)
	}
	request, err := endpoint.EnqueueRead(
		endpointPlan(t, connection, 10*time.Second, 1, 10),
	)
	if err != nil {
		t.Fatal(err)
	}
	dispatch, ok := endpoint.Dispatch()
	if !ok {
		t.Fatal("dispatch missing")
	}
	request.backoff.mu.Lock()
	writeDone := make(chan error, 1)
	go func() {
		_, err := endpoint.Write(context.Background(), dispatch)
		writeDone <- err
	}()
	deadline := time.After(time.Second)
	for endpoint.pool.ActiveConnections() != 0 {
		select {
		case <-deadline:
			request.backoff.mu.Unlock()
			t.Fatal("unsafe transport did not release pool slot")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	replacement, replacementPeer := net.Pipe()
	defer func() { _ = replacementPeer.Close() }()
	if _, err := endpoint.openTestConnection(replacement); err == nil {
		request.backoff.mu.Unlock()
		t.Fatal("replacement opened before unsafe backoff publication")
	}
	request.backoff.mu.Unlock()
	if err := <-writeDone; err == nil {
		t.Fatal("unsafe write unexpectedly succeeded")
	}
}

func TestTCPEndpointResponseOutcomeLinearizesBeforeConcurrentCancel(t *testing.T) {
	clock := &virtualTCPClock{}
	responseRecorded := make(chan struct{})
	releaseResponse := make(chan struct{})
	var responseOnce sync.Once
	sink := &recordingTCPEventSink{
		hook: func(event TCPTransportEvent) {
			if event.Kind == TCPEventResponseReceive {
				responseOnce.Do(func() {
					close(responseRecorded)
					<-releaseResponse
				})
			}
		},
	}
	endpoint, err := NewTCPEndpoint(endpointConfigForTest(clock, sink))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = endpoint.Close() }()
	client, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	connection, err := endpoint.openTestConnection(client)
	if err != nil {
		t.Fatal(err)
	}
	request, err := endpoint.EnqueueRead(
		endpointPlan(t, connection, 10*time.Second, 1, 10),
	)
	if err != nil {
		t.Fatal(err)
	}
	dispatch, ok := endpoint.Dispatch()
	if !ok {
		t.Fatal("dispatch missing")
	}
	wire := endpointWriteOne(t, endpoint, dispatch, peer)
	sent := endpointSendFrame(peer, endpointResponse(wire, 1, 0x1234))
	readDone := make(chan struct {
		batch TCPReadBatch
		err   error
	}, 1)
	go func() {
		batch, err := endpoint.Read(context.Background(), connection)
		readDone <- struct {
			batch TCPReadBatch
			err   error
		}{batch: batch, err: err}
	}()
	<-responseRecorded
	cancelDone := make(chan error, 1)
	go func() {
		_, err := endpoint.CancelLogical(request, 1)
		cancelDone <- err
	}()
	var cancelErr error
	select {
	case cancelErr = <-cancelDone:
	case <-time.After(time.Second):
		t.Fatal("cancel blocked inside event sink delivery")
	}
	var protocolErr *ProtocolError
	if !errors.As(cancelErr, &protocolErr) ||
		protocolErr.Field != "event_sink_reentry" {
		t.Fatalf("cancel during event delivery error=%v", cancelErr)
	}
	close(releaseResponse)
	result := <-readDone
	if result.err != nil ||
		len(result.batch.Views) != 1 ||
		result.batch.Views[0].Words()[0] != 0x1234 {
		t.Fatalf("response batch=%#v err=%v", result.batch, result.err)
	}
	if err := <-sent; err != nil {
		t.Fatal(err)
	}
	for _, event := range sink.snapshot() {
		if event.Kind == TCPEventCallerCancellation &&
			event.RequestID == request.RequestID() {
			t.Fatal("losing cancellation was recorded as terminal outcome")
		}
	}
}

func TestTCPEndpointSnapshotReportsQueueCoalescingAndResources(t *testing.T) {
	clock := &virtualTCPClock{}
	endpoint, err := NewTCPEndpoint(endpointConfigForTest(clock, nil))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = endpoint.Close() }()
	if snapshot := endpoint.Snapshot(); snapshot.Healthy {
		t.Fatalf("socketless endpoint reported healthy: %#v", snapshot)
	}
	client, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	connection, err := endpoint.openTestConnection(client)
	if err != nil {
		t.Fatal(err)
	}
	plan := endpointPlan(t, connection, 10*time.Second, 1, 10)
	secondRead, err := NewReadRegistersRequest(
		FunctionReadHoldingRegisters,
		10,
		1,
	)
	if err != nil {
		t.Fatal(err)
	}
	plan.Reads = append(plan.Reads, TCPLogicalRead{
		LogicalViewID: 2,
		Request:       secondRead,
	})
	if _, err := endpoint.EnqueueRead(plan); err != nil {
		t.Fatal(err)
	}
	queued := endpoint.Snapshot()
	if !queued.Healthy ||
		queued.Resources.ActiveConnections != 1 ||
		queued.Resources.QueuedRequests != 1 ||
		queued.Resources.LiveRequests != 1 ||
		queued.Resources.CoalescedDependents != 2 ||
		queued.Metrics.CoalescedPhysicalReads != 1 ||
		queued.Metrics.CoalescedLogicalViews != 2 ||
		queued.Metrics.CoalescedWireReadSavings != 1 {
		t.Fatalf("queued snapshot=%#v", queued)
	}
	clock.Advance(2 * time.Second)
	dispatch, ok := endpoint.Dispatch()
	if !ok {
		t.Fatal("dispatch missing")
	}
	dispatched := endpoint.Snapshot()
	if dispatched.Resources.QueuedRequests != 0 ||
		dispatched.Resources.InFlightRequests != 1 ||
		dispatched.Metrics.QueueServices != 1 ||
		dispatched.Metrics.TotalQueueWait != 2*time.Second ||
		dispatched.Metrics.MaxQueueWait != 2*time.Second {
		t.Fatalf("dispatched snapshot=%#v", dispatched)
	}
	endpointWriteOne(t, endpoint, dispatch, peer)
	waiting := endpoint.Snapshot()
	if waiting.Resources.WaitingResponses != 1 {
		t.Fatalf("waiting snapshot=%#v", waiting)
	}
}

func TestTCPEndpointSnapshotCountsResponseCancellationAndReconnect(t *testing.T) {
	clock := &virtualTCPClock{}
	endpoint, err := NewTCPEndpoint(endpointConfigForTest(clock, nil))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = endpoint.Close() }()
	client, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	connection, err := endpoint.openTestConnection(client)
	if err != nil {
		t.Fatal(err)
	}
	request, err := endpoint.EnqueueRead(
		endpointPlan(t, connection, 10*time.Second, 1, 10),
	)
	if err != nil {
		t.Fatal(err)
	}
	dispatch, ok := endpoint.Dispatch()
	if !ok {
		t.Fatal("dispatch missing")
	}
	wire := endpointWriteOne(t, endpoint, dispatch, peer)
	if _, err := endpoint.CancelLogical(request, 1); err != nil {
		t.Fatal(err)
	}
	lateSent := endpointSendFrame(peer, endpointResponse(wire, 1, 0x1111))
	if _, err := endpoint.Read(context.Background(), connection); err != nil {
		t.Fatal(err)
	}
	if err := <-lateSent; err != nil {
		t.Fatal(err)
	}
	afterLate := endpoint.Snapshot()
	if afterLate.Metrics.Cancellations != 1 ||
		afterLate.Metrics.Responses.LateAfterAbandonment != 1 {
		t.Fatalf("late snapshot=%#v", afterLate)
	}

	unsafeClient, unsafePeer := net.Pipe()
	defer func() { _ = unsafePeer.Close() }()
	unsafeConnection, err := endpoint.openTestConnection(
		&endpointPartialWriteConn{Conn: unsafeClient},
	)
	if err != nil {
		t.Fatal(err)
	}
	unsafe := endpointFailUnsafeWrite(
		t,
		endpoint,
		unsafeConnection,
		10*time.Second,
		2,
		20,
	)
	if err := endpoint.WaitReconnect(
		context.Background(),
		unsafe,
		&endpointDelayWaiter{},
	); err != nil {
		t.Fatal(err)
	}
	replacement, replacementPeer := net.Pipe()
	defer func() { _ = replacementPeer.Close() }()
	if _, err := endpoint.openTestConnection(replacement); err != nil {
		t.Fatal(err)
	}
	reconnected := endpoint.Snapshot()
	if reconnected.Metrics.Reconnects != 1 ||
		reconnected.Metrics.SourceObservationGaps != 0 {
		t.Fatalf("reconnected snapshot=%#v", reconnected)
	}
}

func TestTCPEndpointSnapshotBoundsPendingQueueMetricState(t *testing.T) {
	clock := &virtualTCPClock{}
	endpoint, err := NewTCPEndpoint(endpointConfigForTest(clock, nil))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = endpoint.Close() }()
	client, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	connection, err := endpoint.openTestConnection(client)
	if err != nil {
		t.Fatal(err)
	}
	const cancellations = 100
	for index := 0; index < cancellations; index++ {
		request, err := endpoint.EnqueueRead(
			endpointPlan(
				t,
				connection,
				10*time.Second,
				uint64(index+1),
				uint16(index),
			),
		)
		if err != nil {
			t.Fatal(err)
		}
		if err := endpoint.Cancel(request); err != nil {
			t.Fatal(err)
		}
	}
	endpoint.timeline.mu.Lock()
	pendingWaits := len(endpoint.timeline.enqueued)
	endpoint.timeline.mu.Unlock()
	snapshot := endpoint.Snapshot()
	if pendingWaits != 0 ||
		snapshot.Resources.LiveRequests != 0 ||
		snapshot.Resources.QueuedRequests != 0 ||
		snapshot.Metrics.Cancellations != cancellations {
		t.Fatalf(
			"pending=%d snapshot=%#v",
			pendingWaits,
			snapshot,
		)
	}
}

func TestTCPEndpointFullTransmitCancellationRetainsRecoveryHandle(
	t *testing.T,
) {
	endpoint, err := NewTCPEndpoint(
		endpointConfigForTest(&virtualTCPClock{}, nil),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = endpoint.Close() }()
	client, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	delayed := &endpointDelayedWriteReturnConn{
		Conn:        client,
		transmitted: make(chan struct{}),
		release:     make(chan struct{}),
	}
	connection, err := endpoint.openTestConnection(delayed)
	if err != nil {
		t.Fatal(err)
	}
	request, err := endpoint.EnqueueRead(
		endpointPlan(t, connection, time.Second, 1, 10),
	)
	if err != nil {
		t.Fatal(err)
	}
	dispatch, ok := endpoint.Dispatch()
	if !ok {
		t.Fatal("dispatch missing")
	}
	peerRead := make(chan error, 1)
	go func() {
		frame := make([]byte, 12)
		_, err := io.ReadFull(peer, frame)
		peerRead <- err
	}()
	ctx, cancel := context.WithCancel(context.Background())
	writeDone := make(chan error, 1)
	go func() {
		_, writeErr := endpoint.Write(ctx, dispatch)
		writeDone <- writeErr
	}()
	<-delayed.transmitted
	cancel()
	close(delayed.release)
	if err := <-writeDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("write error=%v, want cancellation", err)
	}
	if err := <-peerRead; err != nil {
		t.Fatal(err)
	}
	snapshot := endpoint.Snapshot()
	if !snapshot.ReconnectRequired ||
		snapshot.Resources.RetainedRetries != 1 {
		t.Fatalf("unsafe cancellation lost recovery state: %#v", snapshot)
	}
	if err := endpoint.WaitReconnect(
		context.Background(),
		request,
		&endpointDelayWaiter{},
	); err != nil {
		t.Fatalf("reconnect backoff failed: %v", err)
	}
}

func TestTCPEndpointBackoffExhaustionDisablesEndpoint(t *testing.T) {
	clock := &virtualTCPClock{}
	config := endpointConfigForTest(clock, nil)
	config.Backoff.MaxAttempts = 1
	endpoint, err := NewTCPEndpoint(config)
	if err != nil {
		t.Fatal(err)
	}
	client, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	connection, err := endpoint.openTestConnection(
		&endpointPartialWriteConn{Conn: client},
	)
	if err != nil {
		t.Fatal(err)
	}
	request := endpointFailUnsafeWrite(
		t,
		endpoint,
		connection,
		10*time.Second,
		1,
		10,
	)
	endpoint.backoff.mu.Lock()
	endpoint.backoff.attempt = 1
	endpoint.backoff.mu.Unlock()
	if err := endpoint.WaitReconnect(
		context.Background(),
		request,
		&endpointDelayWaiter{},
	); err == nil {
		t.Fatal("exhausted backoff unexpectedly succeeded")
	}
	snapshot := endpoint.Snapshot()
	if !snapshot.Closed ||
		snapshot.DisableReason != "reconnect_backoff_exhausted" ||
		snapshot.Resources.LiveRequests != 0 ||
		snapshot.Resources.RetainedRetries != 0 {
		t.Fatalf("backoff exhaustion did not fail closed: %#v", snapshot)
	}
}

func TestTCPEndpointCancelledEarliestDeadlineKeepsLiveSibling(
	t *testing.T,
) {
	clock := &virtualTCPClock{}
	endpoint, err := NewTCPEndpoint(endpointConfigForTest(clock, nil))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = endpoint.Close() }()
	client, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	connection, err := endpoint.openTestConnection(client)
	if err != nil {
		t.Fatal(err)
	}
	first, err := endpoint.EnqueueRead(
		endpointPlan(t, connection, time.Second, 1, 10),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := endpoint.EnqueueRead(
		endpointPlan(t, connection, 10*time.Second, 2, 20),
	); err != nil {
		t.Fatal(err)
	}
	firstDispatch, ok := endpoint.Dispatch()
	if !ok {
		t.Fatal("first dispatch missing")
	}
	_ = endpointWriteOne(t, endpoint, firstDispatch, peer)
	secondDispatch, ok := endpoint.Dispatch()
	if !ok {
		t.Fatal("second dispatch missing")
	}
	secondWire := endpointWriteOne(t, endpoint, secondDispatch, peer)
	readDone := make(chan struct {
		batch TCPReadBatch
		err   error
	}, 1)
	go func() {
		batch, readErr := endpoint.Read(context.Background(), connection)
		readDone <- struct {
			batch TCPReadBatch
			err   error
		}{batch: batch, err: readErr}
	}()
	waitForActiveReadDeadline(t, endpoint, connection, time.Second)
	if _, err := endpoint.CancelLogical(first, 1); err != nil {
		t.Fatal(err)
	}
	waitForActiveReadDeadline(t, endpoint, connection, 10*time.Second)
	clock.Advance(time.Second)
	select {
	case result := <-readDone:
		t.Fatalf("stale deadline completed live read: %#v", result)
	case <-time.After(20 * time.Millisecond):
	}
	sent := endpointSendFrame(
		peer,
		endpointResponse(secondWire, 1, 0x2222),
	)
	result := <-readDone
	if err := <-sent; err != nil {
		t.Fatal(err)
	}
	if result.err != nil ||
		len(result.batch.Views) != 1 ||
		result.batch.Views[0].Words()[0] != 0x2222 {
		t.Fatalf("live sibling batch=%#v err=%v", result.batch, result.err)
	}
}

func TestTCPEndpointRejectsForgedAndCrossEndpointHandles(t *testing.T) {
	clock := &virtualTCPClock{}
	first, err := NewTCPEndpoint(endpointConfigForTest(clock, nil))
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewTCPEndpoint(endpointConfigForTest(clock, nil))
	if err != nil {
		t.Fatal(err)
	}
	client, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	connection, err := first.openTestConnection(client)
	if err != nil {
		t.Fatal(err)
	}
	request, err := first.EnqueueRead(endpointPlan(t, connection, time.Second, 1, 10))
	if err != nil {
		t.Fatal(err)
	}
	if err := second.CloseConnection(connection); err == nil {
		t.Fatal("foreign endpoint accepted connection handle")
	}
	if _, err := second.EnqueueRead(endpointPlan(t, connection, time.Second, 1, 10)); err == nil {
		t.Fatal("foreign endpoint accepted connection in read plan")
	}
	if err := second.Cancel(request); err == nil {
		t.Fatal("foreign endpoint accepted request handle")
	}
	dispatch, ok := first.Dispatch()
	if !ok {
		t.Fatal("dispatch missing")
	}
	if _, err := second.Write(context.Background(), dispatch); err == nil {
		t.Fatal("foreign endpoint accepted dispatch token")
	}
	if _, err := first.Write(context.Background(), TCPDispatch{}); err == nil {
		t.Fatal("forged zero dispatch token accepted")
	}
	if err := first.CloseConnection(TCPConnectionHandle{}); err == nil {
		t.Fatal("forged zero connection handle accepted")
	}
	if err := first.Cancel(TCPRequestHandle{}); err == nil {
		t.Fatal("forged zero request handle accepted")
	}
}
