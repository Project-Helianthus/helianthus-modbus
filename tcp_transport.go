package modbus

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultTCPRequestDeadline  = 30 * time.Second
	defaultTCPResponseDeadline = 30 * time.Second
	tcpClockContractVersion    = "helianthus-tcp-monotonic-v1"
)

// TCPTransportTimer is an injected one-shot monotonic timer. Stop returns true
// only when it prevents the callback; after false, the callback must finish.
type TCPTransportTimer interface {
	Stop() bool
}

// TCPMonotonicClock owns monotonic offsets and finite operation timers. Now
// must be nondecreasing, and AfterFunc must use that same monotonic timeline.
type TCPMonotonicClock interface {
	ContractVersion() string
	Now() time.Duration
	AfterFunc(time.Duration, func()) TCPTransportTimer
}

// TCPTransportEventKind identifies one replayable transport event.
type TCPTransportEventKind string

const (
	TCPEventEnqueue              TCPTransportEventKind = "enqueue"
	TCPEventAdmission            TCPTransportEventKind = "admission"
	TCPEventQueueService         TCPTransportEventKind = "queue_service"
	TCPEventCoalescing           TCPTransportEventKind = "coalescing"
	TCPEventReconnect            TCPTransportEventKind = "reconnect"
	TCPEventRequestTimerArm      TCPTransportEventKind = "request_timer_arm"
	TCPEventRequestTimerFire     TCPTransportEventKind = "request_timer_fire"
	TCPEventResponseTimerArm     TCPTransportEventKind = "response_timer_arm"
	TCPEventResponseTimerFire    TCPTransportEventKind = "response_timer_fire"
	TCPEventCallerCancellation   TCPTransportEventKind = "caller_cancellation"
	TCPEventWritePrepared        TCPTransportEventKind = "write_prepared"
	TCPEventWriteInvocation      TCPTransportEventKind = "write_invocation"
	TCPEventWriteReturn          TCPTransportEventKind = "write_return"
	TCPEventReadInvocation       TCPTransportEventKind = "read_invocation"
	TCPEventReadReturn           TCPTransportEventKind = "read_return"
	TCPEventTransmitResult       TCPTransportEventKind = "transmit_result"
	TCPEventResponseReceive      TCPTransportEventKind = "response_receive"
	TCPEventQuarantineTransition TCPTransportEventKind = "quarantine_transition"
	TCPEventJitterBackoff        TCPTransportEventKind = "jitter_backoff"
)

// TCPTransportEvent binds a monotonic offset to owner-assigned tie order.
type TCPTransportEvent struct {
	ClockContractVersion string
	Endpoint             string
	Kind                 TCPTransportEventKind
	MonotonicOffset      time.Duration
	Sequence             uint64
	ConnectionID         uint64
	TransportGeneration  uint64
	RequestID            uint64
	LogicalViewID        uint64
	LogicalViewCount     int
	PhysicalRequestID    uint64
	WireResponseID       uint64
	DiagnosticFrameID    uint64
	TransactionID        uint16
	UnitID               byte
	AuthorizationScope   string
	PollGeneration       uint64
	DeadlineIdentity     uint64
	DeadlineOffset       time.Duration
	Delay                time.Duration
	RequestedFunction    FunctionCode
	ReceivedFunction     FunctionCode
	LogicalTable         LogicalTable
	PhysicalOffset       uint16
	PhysicalQuantity     uint16
	RawADUHex            string
	TransmitResult       TransmitResult
	WireOutcome          WireOutcome
	Detail               string
}

// TCPResponseClassMetrics counts immutable wire outcome classes.
type TCPResponseClassMetrics struct {
	SuccessfulData       uint64
	ProtocolException    uint64
	MalformedResponse    uint64
	LateAfterAbandonment uint64
	DroppedUncorrelated  uint64
}

// TCPEndpointMetrics is the cumulative bounded operability view.
type TCPEndpointMetrics struct {
	QueueServices            uint64
	TotalQueueWait           time.Duration
	MaxQueueWait             time.Duration
	CoalescedPhysicalReads   uint64
	CoalescedLogicalViews    uint64
	CoalescedWireReadSavings uint64
	Retries                  uint64
	RequestTimeouts          uint64
	ResponseTimeouts         uint64
	Reconnects               uint64
	Cancellations            uint64
	SourceObservationGaps    uint64
	EventSinkPanics          uint64
	Responses                TCPResponseClassMetrics
}

// TCPTransportEventSink receives events synchronously in sequence order. A
// sink may inspect endpoint snapshots. Endpoint operations that could emit
// another event fail with event_sink_reentry while a callback is active.
// Implementations must still return promptly. Sink panics are contained and
// counted in TCPEndpointMetrics.
type TCPTransportEventSink interface {
	RecordTCPTransportEvent(TCPTransportEvent)
}

type tcpEventFields struct {
	ConnectionID        uint64
	TransportGeneration uint64
	RequestID           uint64
	LogicalViewID       uint64
	LogicalViewCount    int
	PhysicalRequestID   uint64
	WireResponseID      uint64
	DiagnosticFrameID   uint64
	TransactionID       uint16
	UnitID              byte
	AuthorizationScope  string
	PollGeneration      uint64
	DeadlineIdentity    uint64
	DeadlineOffset      time.Duration
	Delay               time.Duration
	RequestedFunction   FunctionCode
	ReceivedFunction    FunctionCode
	LogicalTable        LogicalTable
	PhysicalOffset      uint16
	PhysicalQuantity    uint16
	RawADUHex           string
	TransmitResult      TransmitResult
	WireOutcome         WireOutcome
	Detail              string
}

type tcpEndpointTimeline struct {
	emitMu    sync.Mutex
	mu        sync.Mutex
	callback  atomic.Bool
	endpoint  string
	clock     TCPMonotonicClock
	sink      TCPTransportEventSink
	sequence  uint64
	exhausted bool
	metrics   TCPEndpointMetrics
	enqueued  map[uint64]time.Duration
}

func newTCPEndpointTimeline(
	endpoint string,
	clock TCPMonotonicClock,
	sink TCPTransportEventSink,
) *tcpEndpointTimeline {
	return &tcpEndpointTimeline{
		endpoint: endpoint,
		clock:    clock,
		sink:     sink,
		enqueued: make(map[uint64]time.Duration),
	}
}

func (timeline *tcpEndpointTimeline) record(
	kind TCPTransportEventKind,
	fields tcpEventFields,
) TCPTransportEvent {
	if timeline == nil || timeline.clock == nil {
		return TCPTransportEvent{}
	}
	timeline.emitMu.Lock()
	defer timeline.emitMu.Unlock()
	timeline.mu.Lock()
	if timeline.exhausted || timeline.sequence == math.MaxUint64 {
		timeline.exhausted = true
		event := TCPTransportEvent{
			ClockContractVersion: timeline.clock.ContractVersion(),
			Endpoint:             timeline.endpoint,
			Kind:                 kind,
			MonotonicOffset:      timeline.clock.Now(),
			Detail:               "event_sequence_exhausted",
		}
		timeline.mu.Unlock()
		return event
	}
	timeline.sequence++
	exhaustedNow := timeline.sequence == math.MaxUint64
	if exhaustedNow {
		timeline.exhausted = true
	}
	event := TCPTransportEvent{
		ClockContractVersion: timeline.clock.ContractVersion(),
		Endpoint:             timeline.endpoint,
		Kind:                 kind,
		MonotonicOffset:      timeline.clock.Now(),
		Sequence:             timeline.sequence,
		ConnectionID:         fields.ConnectionID,
		TransportGeneration:  fields.TransportGeneration,
		RequestID:            fields.RequestID,
		LogicalViewID:        fields.LogicalViewID,
		LogicalViewCount:     fields.LogicalViewCount,
		PhysicalRequestID:    fields.PhysicalRequestID,
		WireResponseID:       fields.WireResponseID,
		DiagnosticFrameID:    fields.DiagnosticFrameID,
		TransactionID:        fields.TransactionID,
		UnitID:               fields.UnitID,
		AuthorizationScope:   fields.AuthorizationScope,
		PollGeneration:       fields.PollGeneration,
		DeadlineIdentity:     fields.DeadlineIdentity,
		DeadlineOffset:       fields.DeadlineOffset,
		Delay:                fields.Delay,
		RequestedFunction:    fields.RequestedFunction,
		ReceivedFunction:     fields.ReceivedFunction,
		LogicalTable:         fields.LogicalTable,
		PhysicalOffset:       fields.PhysicalOffset,
		PhysicalQuantity:     fields.PhysicalQuantity,
		RawADUHex:            fields.RawADUHex,
		TransmitResult:       fields.TransmitResult,
		WireOutcome:          fields.WireOutcome,
		Detail:               fields.Detail,
	}
	if exhaustedNow {
		if event.Detail != "" {
			event.Detail += ";"
		}
		event.Detail += "event_sequence_exhausted"
	}
	timeline.observeMetricsLocked(event)
	sink := timeline.sink
	timeline.mu.Unlock()
	if sink != nil {
		func() {
			timeline.callback.Store(true)
			defer timeline.callback.Store(false)
			defer func() {
				if recover() != nil {
					timeline.mu.Lock()
					saturatingIncrement(
						&timeline.metrics.EventSinkPanics,
					)
					timeline.mu.Unlock()
				}
			}()
			sink.RecordTCPTransportEvent(event)
		}()
	}
	return event
}

func (timeline *tcpEndpointTimeline) callbackActive() bool {
	return timeline != nil && timeline.callback.Load()
}

func (timeline *tcpEndpointTimeline) observeMetricsLocked(
	event TCPTransportEvent,
) {
	switch event.Kind {
	case TCPEventEnqueue:
		if event.RequestID != 0 {
			timeline.enqueued[event.RequestID] = event.MonotonicOffset
		}
	case TCPEventAdmission:
		if event.Detail == "retry_admitted" {
			saturatingIncrement(&timeline.metrics.Retries)
		}
		if event.Detail != "admitted" && event.Detail != "retry_admitted" {
			delete(timeline.enqueued, event.RequestID)
		}
	case TCPEventQueueService:
		saturatingIncrement(&timeline.metrics.QueueServices)
		enqueuedAt, ok := timeline.enqueued[event.RequestID]
		delete(timeline.enqueued, event.RequestID)
		if ok && event.MonotonicOffset >= enqueuedAt {
			wait := event.MonotonicOffset - enqueuedAt
			timeline.metrics.TotalQueueWait = saturatingDurationAdd(
				timeline.metrics.TotalQueueWait,
				wait,
			)
			if wait > timeline.metrics.MaxQueueWait {
				timeline.metrics.MaxQueueWait = wait
			}
		}
	case TCPEventCoalescing:
		if event.LogicalViewCount >= 2 {
			saturatingIncrement(&timeline.metrics.CoalescedPhysicalReads)
			saturatingAdd(
				&timeline.metrics.CoalescedLogicalViews,
				uint64(event.LogicalViewCount),
			)
			saturatingAdd(
				&timeline.metrics.CoalescedWireReadSavings,
				uint64(event.LogicalViewCount-1),
			)
		}
	case TCPEventReconnect:
		saturatingIncrement(&timeline.metrics.Reconnects)
	case TCPEventRequestTimerFire:
		saturatingIncrement(&timeline.metrics.RequestTimeouts)
		saturatingIncrement(&timeline.metrics.SourceObservationGaps)
	case TCPEventResponseTimerFire:
		saturatingIncrement(&timeline.metrics.ResponseTimeouts)
		saturatingIncrement(&timeline.metrics.SourceObservationGaps)
	case TCPEventCallerCancellation:
		saturatingIncrement(&timeline.metrics.Cancellations)
	case TCPEventResponseReceive:
		switch event.WireOutcome {
		case WireSuccessfulData:
			saturatingIncrement(&timeline.metrics.Responses.SuccessfulData)
		case WireProtocolException:
			saturatingIncrement(&timeline.metrics.Responses.ProtocolException)
		case WireMalformedResponse:
			saturatingIncrement(&timeline.metrics.Responses.MalformedResponse)
		case WireLateAfterAbandonment:
			saturatingIncrement(&timeline.metrics.Responses.LateAfterAbandonment)
		case WireDroppedUncorrelated:
			saturatingIncrement(&timeline.metrics.Responses.DroppedUncorrelated)
		}
	}
}

func (timeline *tcpEndpointTimeline) recordCoalescing(
	fields tcpEventFields,
	logicalViews int,
) {
	if timeline == nil || logicalViews < 2 {
		return
	}
	fields.LogicalViewCount = logicalViews
	timeline.record(TCPEventCoalescing, fields)
}

func (timeline *tcpEndpointTimeline) recordReconnect(fields tcpEventFields) {
	if timeline == nil {
		return
	}
	fields.Detail = "connected"
	timeline.record(TCPEventReconnect, fields)
}

func (timeline *tcpEndpointTimeline) metricsSnapshot() TCPEndpointMetrics {
	if timeline == nil {
		return TCPEndpointMetrics{}
	}
	timeline.mu.Lock()
	defer timeline.mu.Unlock()
	return timeline.metrics
}

func (timeline *tcpEndpointTimeline) forgetEnqueue(requestID uint64) {
	if timeline == nil || requestID == 0 {
		return
	}
	timeline.mu.Lock()
	delete(timeline.enqueued, requestID)
	timeline.mu.Unlock()
}

func saturatingIncrement(value *uint64) {
	saturatingAdd(value, 1)
}

func saturatingAdd(value *uint64, delta uint64) {
	if value == nil || delta == 0 {
		return
	}
	if *value > math.MaxUint64-delta {
		*value = math.MaxUint64
		return
	}
	*value += delta
}

func saturatingDurationAdd(
	current time.Duration,
	delta time.Duration,
) time.Duration {
	if delta <= 0 {
		return current
	}
	if current > time.Duration(math.MaxInt64)-delta {
		return time.Duration(math.MaxInt64)
	}
	return current + delta
}

func (timeline *tcpEndpointTimeline) Exhausted() bool {
	if timeline == nil {
		return true
	}
	timeline.mu.Lock()
	defer timeline.mu.Unlock()
	return timeline.exhausted
}

// TCPTransportConfig declares finite per-operation transport bounds.
type TCPTransportConfig struct {
	MaxBufferedBytes int
	RequestDeadline  time.Duration
	ResponseDeadline time.Duration
	Clock            TCPMonotonicClock
	EventSink        TCPTransportEventSink
	timeline         *tcpEndpointTimeline
	beforeClose      func()
}

// DefaultTCPTransportConfig returns the bounded compatibility configuration.
func DefaultTCPTransportConfig(maxBuffered int) TCPTransportConfig {
	return TCPTransportConfig{
		MaxBufferedBytes: maxBuffered,
		RequestDeadline:  defaultTCPRequestDeadline,
		ResponseDeadline: defaultTCPResponseDeadline,
		Clock:            NewRealTCPMonotonicClock(),
	}
}

// NewRealTCPMonotonicClock returns the production monotonic timer source.
func NewRealTCPMonotonicClock() TCPMonotonicClock {
	return &realTCPMonotonicClock{origin: time.Now()}
}

type realTCPMonotonicClock struct {
	origin time.Time
}

func (clock *realTCPMonotonicClock) ContractVersion() string {
	return tcpClockContractVersion
}

func (clock *realTCPMonotonicClock) Now() time.Duration {
	return time.Since(clock.origin)
}

func (clock *realTCPMonotonicClock) AfterFunc(
	delay time.Duration,
	callback func(),
) TCPTransportTimer {
	return time.AfterFunc(delay, callback)
}

// ProvableZeroWriteError is the only generic TCP write error that can prove
// that no byte reached the peer.
type ProvableZeroWriteError interface {
	error
	ProvablyNoBytesTransmitted() bool
}

// TransportWriteError retains the mandatory write-result classification.
type TransportWriteError struct {
	Result TransmitResult
	Cause  error
}

func (err *TransportWriteError) Error() string {
	if err.Cause != nil {
		return err.Result.String() + ": " + err.Cause.Error()
	}
	return err.Result.String()
}

func (err *TransportWriteError) Unwrap() error {
	return err.Cause
}

// TCPTransport owns one concrete net.Conn, decoder, and connection owner.
type TCPTransport struct {
	conn             net.Conn
	socketIdentity   tcpConnectionIdentity
	owner            *TCPConnectionOwner
	decoder          *TCPStreamDecoder
	writeGate        chan struct{}
	readGate         chan struct{}
	readDeadlineMu   sync.Mutex
	activeRead       *tcpActiveRead
	pendingReadRearm bool
	closeMu          sync.Mutex
	generation       uint64
	requestDeadline  time.Duration
	responseDeadline time.Duration
	clock            TCPMonotonicClock
	timeline         *tcpEndpointTimeline
	beforeClose      func()
	closed           bool
	closeFailures    []TCPReservation
	coalesced        map[uint64]*CoalescedRead
}

type tcpActiveRead struct {
	deadline    time.Duration
	interrupter *socketInterrupter
	rearm       bool
}

var tcpConnectionClaims = struct {
	sync.Mutex
	owners map[tcpConnectionIdentity]*TCPTransport
}{
	owners: make(map[tcpConnectionIdentity]*TCPTransport),
}

type trustedTCPConnectionDecorator interface {
	net.Conn
	Unwrap() net.Conn
	modbusTCPTrustedDecorator()
}

type tcpConnectionIdentity struct {
	network string
	local   string
	remote  string
	object  net.Conn
}

func canonicalTCPConnectionIdentity(
	conn net.Conn,
) (tcpConnectionIdentity, error) {
	conn, err := trustedTCPBaseConnection(conn)
	if err != nil {
		return tcpConnectionIdentity{}, err
	}
	if _, ok := conn.(*net.TCPConn); ok {
		local := conn.LocalAddr()
		remote := conn.RemoteAddr()
		if local == nil || remote == nil {
			return tcpConnectionIdentity{}, connectionIdentityError()
		}
		return tcpConnectionIdentity{
			network: local.Network() + "/" + remote.Network(),
			local:   local.String(),
			remote:  remote.String(),
		}, nil
	}
	if fmt.Sprintf("%T", conn) != "*net.pipe" ||
		!comparableTCPConnection(conn) {
		return tcpConnectionIdentity{}, connectionIdentityError()
	}
	return tcpConnectionIdentity{object: conn}, nil
}

func trustedTCPBaseConnection(conn net.Conn) (net.Conn, error) {
	if conn == nil {
		return nil, connectionIdentityError()
	}
	for depth := 0; depth < 32; depth++ {
		if unwrapper, ok := conn.(trustedTCPConnectionDecorator); ok {
			conn = unwrapper.Unwrap()
			if conn == nil {
				return nil, connectionIdentityError()
			}
			continue
		}
		return conn, nil
	}
	return nil, connectionIdentityError()
}

func comparableTCPConnection(conn net.Conn) (comparable bool) {
	if conn == nil {
		return false
	}
	comparable = true
	defer func() {
		if recover() != nil {
			comparable = false
		}
	}()
	_ = conn == conn
	return comparable
}

func claimTCPConnection(
	identity tcpConnectionIdentity,
	transport *TCPTransport,
) (claimed bool) {
	if transport == nil {
		return false
	}
	defer func() {
		if recover() != nil {
			claimed = false
		}
	}()
	tcpConnectionClaims.Lock()
	defer tcpConnectionClaims.Unlock()
	if _, exists := tcpConnectionClaims.owners[identity]; exists {
		return false
	}
	tcpConnectionClaims.owners[identity] = transport
	return true
}

func releaseTCPConnection(
	identity tcpConnectionIdentity,
	transport *TCPTransport,
) {
	if transport == nil {
		return
	}
	defer func() {
		_ = recover()
	}()
	tcpConnectionClaims.Lock()
	defer tcpConnectionClaims.Unlock()
	if tcpConnectionClaims.owners[identity] == transport {
		delete(tcpConnectionClaims.owners, identity)
	}
}

func connectionIdentityError() error {
	return protocolError(
		ErrorInvalidRequest,
		0,
		0,
		"connection_identity",
		-1,
	)
}

var errReadDeadlineRearmed = errors.New("tcp read deadline rearmed")

func (transport *TCPTransport) registerActiveRead(
	deadline time.Duration,
	interrupter *socketInterrupter,
) *tcpActiveRead {
	active := &tcpActiveRead{
		deadline:    deadline,
		interrupter: interrupter,
	}
	transport.readDeadlineMu.Lock()
	transport.activeRead = active
	if transport.pendingReadRearm {
		transport.pendingReadRearm = false
		active.rearm = true
		active.interrupter.Interrupt()
	}
	transport.readDeadlineMu.Unlock()
	return active
}

func (transport *TCPTransport) finishActiveRead(
	active *tcpActiveRead,
) bool {
	transport.readDeadlineMu.Lock()
	defer transport.readDeadlineMu.Unlock()
	if transport.activeRead == active {
		transport.activeRead = nil
	}
	return active.rearm
}

func (transport *TCPTransport) requestEarlierReadDeadline(
	deadline time.Duration,
) {
	if transport == nil || deadline <= 0 {
		return
	}
	transport.readDeadlineMu.Lock()
	active := transport.activeRead
	if active == nil || deadline >= active.deadline {
		transport.readDeadlineMu.Unlock()
		return
	}
	active.deadline = deadline
	active.rearm = true
	active.interrupter.Interrupt()
	transport.readDeadlineMu.Unlock()
}

func (transport *TCPTransport) refreshActiveReadDeadline() {
	if transport == nil {
		return
	}
	transport.readDeadlineMu.Lock()
	active := transport.activeRead
	if active == nil {
		transport.pendingReadRearm = true
		transport.readDeadlineMu.Unlock()
		return
	}
	active.rearm = true
	active.interrupter.Interrupt()
	transport.readDeadlineMu.Unlock()
}

// newTCPTransport binds one live socket to exactly one owner and decoder.
func newTCPTransport(
	conn net.Conn,
	owner *TCPConnectionOwner,
	maxBuffered int,
) (*TCPTransport, error) {
	return newTCPTransportWithConfig(
		conn,
		owner,
		DefaultTCPTransportConfig(maxBuffered),
	)
}

// newTCPTransportWithConfig binds a socket with explicit finite deadlines.
func newTCPTransportWithConfig(
	conn net.Conn,
	owner *TCPConnectionOwner,
	config TCPTransportConfig,
) (*TCPTransport, error) {
	if conn == nil || owner == nil || owner.Closed() {
		return nil, protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"tcp_transport",
			-1,
		)
	}
	socketIdentity, err := canonicalTCPConnectionIdentity(conn)
	if err != nil {
		return nil, err
	}
	if config.MaxBufferedBytes <= 0 ||
		config.RequestDeadline <= 0 ||
		config.ResponseDeadline <= 0 {
		return nil, protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"tcp_transport_config",
			-1,
		)
	}
	if config.Clock == nil {
		config.Clock = NewRealTCPMonotonicClock()
	}
	if config.Clock.ContractVersion() == "" {
		return nil, protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"tcp_clock_contract",
			-1,
		)
	}
	decoder, err := NewTCPStreamDecoder(config.MaxBufferedBytes)
	if err != nil {
		return nil, err
	}
	writeGate := make(chan struct{}, 1)
	writeGate <- struct{}{}
	readGate := make(chan struct{}, 1)
	readGate <- struct{}{}
	transport := &TCPTransport{
		conn:             conn,
		socketIdentity:   socketIdentity,
		owner:            owner,
		decoder:          decoder,
		writeGate:        writeGate,
		readGate:         readGate,
		requestDeadline:  config.RequestDeadline,
		responseDeadline: config.ResponseDeadline,
		clock:            config.Clock,
		timeline:         config.timeline,
		beforeClose:      config.beforeClose,
		coalesced:        make(map[uint64]*CoalescedRead),
	}
	if !claimTCPConnection(socketIdentity, transport) {
		return nil, protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"connection_already_owned",
			-1,
		)
	}
	if transport.timeline == nil {
		transport.timeline = newTCPEndpointTimeline(
			owner.endpoint,
			config.Clock,
			config.EventSink,
		)
	}
	generation, err := owner.bindTransport(transport)
	if err != nil {
		releaseTCPConnection(socketIdentity, transport)
		return nil, err
	}
	transport.generation = generation
	return transport, nil
}

// WriteReservation owns write invocation, classification, and close recovery.
func (transport *TCPTransport) WriteReservation(
	ctx context.Context,
	reservation TCPReservation,
) (OwnerTransition, error) {
	deadline, err := transport.relativeDeadline(transport.requestDeadline)
	if err != nil {
		return OwnerTransition{}, err
	}
	return transport.writeReservationUntil(ctx, reservation, deadline, 0)
}

func (transport *TCPTransport) writeReservationUntil(
	ctx context.Context,
	reservation TCPReservation,
	deadlineOffset time.Duration,
	requestID uint64,
) (OwnerTransition, error) {
	if transport == nil || ctx == nil {
		return OwnerTransition{}, protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"tcp_transport",
			-1,
		)
	}
	operation := newTCPTransportOperation(
		transport,
		ctx,
		deadlineOffset,
		TCPEventRequestTimerArm,
		TCPEventRequestTimerFire,
		TCPEventWriteInvocation,
		TCPEventWriteReturn,
		tcpEventFields{
			RequestID:         requestID,
			PhysicalRequestID: reservation.PhysicalRequestID(),
			TransactionID:     reservation.TransactionID(),
			DeadlineOffset:    deadlineOffset,
		},
	)
	defer operation.stopAndJoin()
	if err := acquireOperationGate(operation, transport.writeGate); err != nil {
		transition, cleanupErr := transport.releasePreWrite(reservation)
		return transition, combineErrors(err, cleanupErr)
	}
	defer releaseTransportGate(transport.writeGate)
	if !transport.owner.transportCurrent(
		transport,
		transport.generation,
	) {
		staleErr := protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"stale_transport",
			-1,
		)
		transition, cleanupErr := transport.releasePreWrite(reservation)
		return transition, combineErrors(staleErr, cleanupErr)
	}
	if err := operation.preInvocationError(); err != nil {
		transition, cleanupErr := transport.releasePreWrite(reservation)
		return transition, combineErrors(err, cleanupErr)
	}
	adu, err := transport.owner.encodeReservation(reservation)
	if err != nil {
		transition, cleanupErr := transport.releasePreWrite(reservation)
		return transition, combineErrors(err, cleanupErr)
	}
	operation.fields.RawADUHex = hex.EncodeToString(adu)
	operation.recordOnly(TCPEventWritePrepared)
	interrupter := newSocketInterrupter(
		transport.conn,
		transport.conn.SetWriteDeadline,
	)
	operation.setInterrupt(interrupter.Interrupt)
	if err := operation.beginInvocation(func() error {
		return transport.owner.MarkWriteInvoked(reservation)
	}); err != nil {
		transition, cleanupErr := transport.releasePreWrite(reservation)
		return transition, combineErrors(err, cleanupErr)
	}
	return transport.performInvokedWrite(
		operation,
		interrupter,
		reservation,
		adu,
	)
}

// WriteCoalesced atomically attaches dependents at the transport write boundary.
func (transport *TCPTransport) WriteCoalesced(
	ctx context.Context,
	group *CoalescedRead,
) (OwnerTransition, error) {
	deadline, err := transport.relativeDeadline(transport.requestDeadline)
	if err != nil {
		return OwnerTransition{}, err
	}
	return transport.writeCoalescedUntil(
		ctx,
		group,
		deadline,
		tcpEventFields{},
	)
}

func (transport *TCPTransport) writeCoalescedUntil(
	ctx context.Context,
	group *CoalescedRead,
	deadlineOffset time.Duration,
	fields tcpEventFields,
) (OwnerTransition, error) {
	if transport == nil || ctx == nil || group == nil {
		return OwnerTransition{}, protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"tcp_transport",
			-1,
		)
	}
	timerFields := fields
	timerFields.RequestedFunction = 0
	timerFields.LogicalTable = ""
	timerFields.PhysicalOffset = 0
	timerFields.PhysicalQuantity = 0
	timerFields.RawADUHex = ""
	operation := newTCPTransportOperation(
		transport,
		ctx,
		deadlineOffset,
		TCPEventRequestTimerArm,
		TCPEventRequestTimerFire,
		TCPEventWriteInvocation,
		TCPEventWriteReturn,
		timerFields,
	)
	defer operation.stopAndJoin()
	if err := acquireOperationGate(operation, transport.writeGate); err != nil {
		return OwnerTransition{}, errors.Join(err, group.FailTransport())
	}
	defer releaseTransportGate(transport.writeGate)
	if !transport.owner.transportCurrent(
		transport,
		transport.generation,
	) {
		staleErr := protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"stale_transport",
			-1,
		)
		return OwnerTransition{}, errors.Join(staleErr, group.FailTransport())
	}
	if err := operation.preInvocationError(); err != nil {
		return OwnerTransition{}, errors.Join(err, group.FailTransport())
	}
	var reservation TCPReservation
	var adu []byte
	interrupter := newSocketInterrupter(
		transport.conn,
		transport.conn.SetWriteDeadline,
	)
	operation.setInterrupt(interrupter.Interrupt)
	err := group.withWriteLock(func() error {
		var prepareErr error
		reservation, prepareErr = group.reservationForTransportLocked(
			transport.owner,
			transport.generation,
		)
		if prepareErr != nil {
			return prepareErr
		}
		physical := group.physical
		operation.fields.RequestedFunction = physical.Function()
		operation.fields.LogicalTable = physical.Table()
		operation.fields.PhysicalOffset = physical.Offset()
		operation.fields.PhysicalQuantity = physical.Quantity()
		adu, prepareErr =
			transport.owner.encodeReservation(reservation)
		if prepareErr != nil {
			return prepareErr
		}
		operation.fields.RawADUHex = hex.EncodeToString(adu)
		operation.recordOnly(TCPEventWritePrepared)
		return operation.beginInvocation(func() error {
			begunReservation, beginErr :=
				group.beginWriteLocked(transport)
			if beginErr == nil {
				reservation = begunReservation
				operation.setRequestIdentity(
					reservation.PhysicalRequestID(),
					reservation.TransactionID(),
				)
			}
			return beginErr
		})
	})
	if err != nil {
		groupErr := group.FailTransport()
		var transition OwnerTransition
		var cleanupErr error
		if reservation.owner != nil {
			transition, cleanupErr =
				transport.releasePreWrite(reservation)
		}
		return transition, errors.Join(err, groupErr, cleanupErr)
	}
	transition, writeErr := transport.performInvokedWrite(
		operation,
		interrupter,
		reservation,
		adu,
	)
	if writeErr != nil {
		group.finishWriteFailure()
		return transition, errors.Join(writeErr, group.FailTransport())
	}
	return transition, nil
}

func (transport *TCPTransport) performInvokedWrite(
	operation *tcpTransportOperation,
	interrupter *socketInterrupter,
	reservation TCPReservation,
	adu []byte,
) (OwnerTransition, error) {
	written, writeErr := transport.conn.Write(adu)
	operation.markReturn()
	operation.stopAndJoin()
	contextErr := operation.cause()
	resetErr := interrupter.Reset()
	result := classifyNetWrite(
		len(adu),
		written,
		writeErr,
		operation.cancellationWonDuringIO(),
	)
	responseDeadline, deadlineErr := transport.responseWaitDeadline(
		reservation.deadlineOffset,
	)
	transition, recordErr := transport.owner.recordTransmitUntil(
		reservation,
		result,
		responseDeadline,
	)
	resultFields := operation.fields
	resultFields.PhysicalRequestID = reservation.PhysicalRequestID()
	resultFields.TransactionID = reservation.TransactionID()
	resultFields.DeadlineOffset = responseDeadline
	resultFields.TransmitResult = result
	transport.recordEventFields(TCPEventTransmitResult, resultFields)
	if result == TransmitComplete &&
		(contextErr != nil || deadlineErr != nil) {
		reason := AbandonCancellation
		if deadlineErr != nil ||
			errors.Is(contextErr, context.DeadlineExceeded) {
			reason = AbandonTimeout
		}
		abandonTransition, abandonErr := transport.owner.AbandonAfterWrite(
			reservation,
			reason,
		)
		transition = mergeOwnerTransitions(transition, abandonTransition)
		recordErr = errors.Join(recordErr, abandonErr)
	}
	var closeErr error
	if transition.CloseConnection() || resetErr != nil {
		if transport.beforeClose != nil {
			transport.beforeClose()
		}
		closeTransition, terminalErr := transport.closeTerminal()
		transition = mergeOwnerTransitions(transition, closeTransition)
		closeErr = terminalErr
	}
	if result == TransmitComplete &&
		writeErr == nil &&
		contextErr == nil &&
		deadlineErr == nil &&
		recordErr == nil &&
		resetErr == nil &&
		closeErr == nil {
		return transition, nil
	}
	cause := errors.Join(
		writeErr,
		contextErr,
		deadlineErr,
		recordErr,
		resetErr,
		closeErr,
	)
	return transition, &TransportWriteError{Result: result, Cause: cause}
}

func (transport *TCPTransport) responseWaitDeadline(
	operationDeadline time.Duration,
) (time.Duration, error) {
	now := transport.clock.Now()
	if now < 0 {
		return 0, protocolError(
			ErrorInvalidRange,
			0,
			0,
			"operation_deadline",
			-1,
		)
	}
	if operationDeadline > 0 {
		if operationDeadline <= now {
			return 0, protocolError(
				ErrorInvalidRange,
				0,
				0,
				"operation_deadline",
				-1,
			)
		}
		if operationDeadline-now <= transport.responseDeadline {
			return operationDeadline, nil
		}
	}
	if transport.responseDeadline >
		time.Duration(math.MaxInt64)-now {
		return 0, protocolError(
			ErrorInvalidRange,
			0,
			0,
			"operation_deadline",
			-1,
		)
	}
	deadline := now + transport.responseDeadline
	if operationDeadline > 0 && operationDeadline < deadline {
		return operationDeadline, nil
	}
	return deadline, nil
}

type transportOperationState uint32

const (
	operationPending transportOperationState = iota
	operationInvoked
	operationReturned
	operationCancelledBeforeInvocation
	operationTimedOutBeforeInvocation
	operationCancelledDuringIO
	operationTimedOutDuringIO
	operationReturnedThenCancelled
	operationReturnedThenTimedOut
	operationInvocationFailed
)

type transportCancellationSource byte

const (
	transportCallerCancellation transportCancellationSource = iota + 1
	transportInternalDeadline
)

type joinedCallback struct {
	stop func() bool
	done <-chan struct{}
}

func (callback joinedCallback) stopAndJoin(observe func()) {
	if callback.stop() {
		observe()
		return
	}
	<-callback.done
}

type joinedTimer struct {
	timer TCPTransportTimer
	done  <-chan struct{}
}

func (timer joinedTimer) stopAndJoin(observe func()) {
	if timer.timer.Stop() {
		observe()
		return
	}
	<-timer.done
}

type tcpTransportOperation struct {
	transport      *TCPTransport
	invocationKind TCPTransportEventKind
	returnKind     TCPTransportEventKind
	fields         tcpEventFields
	state          atomic.Uint32
	eventMu        sync.Mutex
	causeErr       error
	done           chan struct{}
	doneOnce       sync.Once
	timer          joinedTimer
	cancellation   joinedCallback
	observeLimits  func()
	stopOnce       sync.Once
	interruptMu    sync.Mutex
	interrupt      func()
	interruptDue   bool
	interrupted    bool
}

func newTCPTransportOperation(
	transport *TCPTransport,
	ctx context.Context,
	deadlineOffset time.Duration,
	armKind TCPTransportEventKind,
	fireKind TCPTransportEventKind,
	invocationKind TCPTransportEventKind,
	returnKind TCPTransportEventKind,
	fields tcpEventFields,
) *tcpTransportOperation {
	operation := &tcpTransportOperation{
		transport:      transport,
		invocationKind: invocationKind,
		returnKind:     returnKind,
		fields:         fields,
		done:           make(chan struct{}),
	}
	operation.fields.DeadlineOffset = deadlineOffset
	armEvent := operation.recordOnly(armKind)
	delay := deadlineOffset - armEvent.MonotonicOffset
	if delay < 0 {
		delay = 0
	}
	timerDone := make(chan struct{})
	var deadlineOnce sync.Once
	runDeadline := func() {
		deadlineOnce.Do(func() {
			operation.cancel(
				transportInternalDeadline,
				fireKind,
				context.DeadlineExceeded,
			)
		})
	}
	timer := transport.clock.AfterFunc(delay, func() {
		defer close(timerDone)
		runDeadline()
	})
	operation.timer = joinedTimer{timer: timer, done: timerDone}
	cancelDone := make(chan struct{})
	var cancelOnce sync.Once
	runCancellation := func() {
		cancelOnce.Do(func() {
			cause := ctx.Err()
			if cause == nil {
				cause = context.Canceled
			}
			operation.cancel(
				transportCallerCancellation,
				TCPEventCallerCancellation,
				cause,
			)
		})
	}
	stopCancellation := context.AfterFunc(ctx, func() {
		defer close(cancelDone)
		runCancellation()
	})
	operation.cancellation = joinedCallback{
		stop: stopCancellation,
		done: cancelDone,
	}
	operation.observeLimits = func() {
		if ctx.Err() != nil {
			runCancellation()
		}
		if transport.clock.Now() >= deadlineOffset {
			runDeadline()
		}
	}
	operation.observeLimits()
	return operation
}

func (operation *tcpTransportOperation) recordOnly(
	kind TCPTransportEventKind,
) TCPTransportEvent {
	operation.eventMu.Lock()
	event := operation.transport.recordEventFields(kind, operation.fields)
	operation.eventMu.Unlock()
	return event
}

func (operation *tcpTransportOperation) setRequestIdentity(
	physicalRequestID uint64,
	transactionID uint16,
) {
	operation.fields.PhysicalRequestID = physicalRequestID
	operation.fields.TransactionID = transactionID
}

func (operation *tcpTransportOperation) beginInvocation(
	mark func() error,
) error {
	operation.observeLimits()
	operation.eventMu.Lock()
	defer operation.eventMu.Unlock()
	state := transportOperationState(operation.state.Load())
	if state != operationPending {
		if operation.causeErr != nil {
			return operation.causeErr
		}
		return protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"transport_operation_state",
			-1,
		)
	}
	if mark != nil {
		if err := mark(); err != nil {
			operation.state.CompareAndSwap(
				uint32(operationPending),
				uint32(operationInvocationFailed),
			)
			return err
		}
	}
	if !operation.state.CompareAndSwap(
		uint32(operationPending),
		uint32(operationInvoked),
	) {
		return protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"transport_invocation_cas",
			-1,
		)
	}
	operation.transport.recordEventFields(
		operation.invocationKind,
		operation.fields,
	)
	return nil
}

// markReturn is the write-completion linearization point. Cancellation and
// completion both serialize event sequence assignment with this CAS. A CAS
// from invoked to returned proves completion won; a prior cancellation CAS
// leaves the operation in a during-I/O state and forces cancellation_race.
func (operation *tcpTransportOperation) markReturn() {
	operation.observeLimits()
	operation.eventMu.Lock()
	state := transportOperationState(operation.state.Load())
	if state == operationInvoked {
		operation.state.CompareAndSwap(
			uint32(operationInvoked),
			uint32(operationReturned),
		)
	}
	operation.transport.recordEventFields(operation.returnKind, operation.fields)
	operation.eventMu.Unlock()
}

func (operation *tcpTransportOperation) cancel(
	source transportCancellationSource,
	eventKind TCPTransportEventKind,
	cause error,
) {
	closeDone := false
	interrupt := false
	changed := false
	operation.eventMu.Lock()
	state := transportOperationState(operation.state.Load())
	target := state
	switch state {
	case operationPending:
		if source == transportInternalDeadline {
			target = operationTimedOutBeforeInvocation
		} else {
			target = operationCancelledBeforeInvocation
		}
		closeDone = true
	case operationInvoked:
		if source == transportInternalDeadline {
			target = operationTimedOutDuringIO
		} else {
			target = operationCancelledDuringIO
		}
		closeDone = true
		interrupt = true
	case operationReturned:
		if source == transportInternalDeadline {
			target = operationReturnedThenTimedOut
		} else {
			target = operationReturnedThenCancelled
		}
	}
	if target != state && operation.state.CompareAndSwap(
		uint32(state),
		uint32(target),
	) {
		changed = true
		operation.causeErr = cause
	}
	operation.transport.recordEventFields(eventKind, operation.fields)
	operation.eventMu.Unlock()
	if changed && closeDone {
		operation.doneOnce.Do(func() {
			close(operation.done)
		})
	}
	if changed && interrupt {
		operation.requestInterrupt()
	}
}

func (operation *tcpTransportOperation) setInterrupt(interrupt func()) {
	operation.interruptMu.Lock()
	operation.interrupt = interrupt
	call := operation.interruptDue && !operation.interrupted
	if call {
		operation.interrupted = true
	}
	operation.interruptMu.Unlock()
	if call {
		interrupt()
	}
}

func (operation *tcpTransportOperation) requestInterrupt() {
	operation.interruptMu.Lock()
	operation.interruptDue = true
	interrupt := operation.interrupt
	call := interrupt != nil && !operation.interrupted
	if call {
		operation.interrupted = true
	}
	operation.interruptMu.Unlock()
	if call {
		interrupt()
	}
}

func (operation *tcpTransportOperation) stopAndJoin() {
	operation.stopOnce.Do(func() {
		operation.observeLimits()
		operation.cancellation.stopAndJoin(operation.observeLimits)
		operation.timer.stopAndJoin(operation.observeLimits)
		// This final observation is the operation-completion cutoff. Both
		// asynchronous callbacks are now stopped or joined, so a cancellation
		// recorded before this point participates in the CAS ordering and one
		// arriving after it is later than the completed operation.
		operation.observeLimits()
	})
}

func (operation *tcpTransportOperation) preInvocationError() error {
	operation.observeLimits()
	operation.eventMu.Lock()
	defer operation.eventMu.Unlock()
	switch transportOperationState(operation.state.Load()) {
	case operationCancelledBeforeInvocation,
		operationTimedOutBeforeInvocation:
		return operation.causeErr
	default:
		return nil
	}
}

func (operation *tcpTransportOperation) cause() error {
	operation.eventMu.Lock()
	defer operation.eventMu.Unlock()
	return operation.causeErr
}

func (operation *tcpTransportOperation) cancellationWonDuringIO() bool {
	state := transportOperationState(operation.state.Load())
	return state == operationCancelledDuringIO ||
		state == operationTimedOutDuringIO
}

func (operation *tcpTransportOperation) callerCancellationWonDuringIO() bool {
	return transportOperationState(operation.state.Load()) ==
		operationCancelledDuringIO
}

func (operation *tcpTransportOperation) deadlineWonDuringIO() bool {
	return transportOperationState(operation.state.Load()) ==
		operationTimedOutDuringIO
}

func acquireOperationGate(
	operation *tcpTransportOperation,
	gate chan struct{},
) error {
	select {
	case <-operation.done:
		operation.stopAndJoin()
		return operation.cause()
	case <-gate:
		if err := operation.preInvocationError(); err != nil {
			releaseTransportGate(gate)
			operation.stopAndJoin()
			return err
		}
		return nil
	}
}

func releaseTransportGate(gate chan<- struct{}) {
	gate <- struct{}{}
}

func (transport *TCPTransport) relativeDeadline(
	limit time.Duration,
) (time.Duration, error) {
	if transport == nil ||
		limit <= 0 ||
		transport.clock == nil {
		return 0, protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"operation_deadline",
			-1,
		)
	}
	now := transport.clock.Now()
	if now < 0 || limit > time.Duration(math.MaxInt64)-now {
		return 0, protocolError(
			ErrorInvalidRange,
			0,
			0,
			"operation_deadline",
			-1,
		)
	}
	return now + limit, nil
}

func (transport *TCPTransport) recordEventFields(
	kind TCPTransportEventKind,
	fields tcpEventFields,
) TCPTransportEvent {
	if fields.ConnectionID == 0 && transport.owner != nil {
		fields.ConnectionID = transport.owner.connectionID
	}
	if fields.TransportGeneration == 0 {
		fields.TransportGeneration = transport.generation
	}
	return transport.timeline.record(kind, fields)
}

var expiredSocketDeadline = time.Unix(1, 0)

type socketInterrupter struct {
	socket      net.Conn
	setDeadline func(time.Time) error
	once        sync.Once
	deadlineSet atomic.Bool
}

func newSocketInterrupter(
	conn net.Conn,
	setDeadline func(time.Time) error,
) *socketInterrupter {
	return &socketInterrupter{
		socket:      conn,
		setDeadline: setDeadline,
	}
}

func (interrupter *socketInterrupter) Interrupt() {
	interrupter.once.Do(func() {
		if err := interrupter.setDeadline(expiredSocketDeadline); err == nil {
			interrupter.deadlineSet.Store(true)
			return
		}
		_ = interrupter.socket.Close()
	})
}

func (interrupter *socketInterrupter) Reset() error {
	if !interrupter.deadlineSet.Swap(false) {
		return nil
	}
	return interrupter.setDeadline(time.Time{})
}

func combineErrors(errs ...error) error {
	filtered := make([]error, 0, len(errs))
	for _, err := range errs {
		if err != nil {
			filtered = append(filtered, err)
		}
	}
	switch len(filtered) {
	case 0:
		return nil
	case 1:
		return filtered[0]
	default:
		return errors.Join(filtered...)
	}
}

func (transport *TCPTransport) releasePreWrite(
	reservation TCPReservation,
) (OwnerTransition, error) {
	if err := transport.owner.CancelBeforeWrite(reservation); err == nil {
		return OwnerTransition{}, nil
	}
	canonical, state, exists := canonicalLiveReservation(
		transport.owner,
		reservation,
	)
	if !exists {
		return OwnerTransition{}, nil
	}
	if state == requestReserved {
		if err := transport.owner.CancelBeforeWrite(canonical); err == nil {
			return OwnerTransition{}, nil
		} else {
			return OwnerTransition{}, err
		}
	}
	if transport.owner.transportCurrent(
		transport,
		transport.generation,
	) {
		return transport.closeTerminal()
	}
	transport.owner.Close()
	return OwnerTransition{closeConnection: true}, nil
}

func canonicalLiveReservation(
	owner *TCPConnectionOwner,
	reservation TCPReservation,
) (TCPReservation, requestState, bool) {
	if owner == nil || reservation.owner != owner {
		return TCPReservation{}, 0, false
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	request := owner.inFlight[reservation.transactionID]
	if request == nil || request.generation != reservation.generation {
		return TCPReservation{}, 0, false
	}
	return TCPReservation{
		owner:             owner,
		transactionID:     request.transactionID,
		physicalRequestID: request.physicalRequestID,
		generation:        request.generation,
		deadlineOffset:    request.deadlineOffset,
	}, request.state, true
}

func (transport *TCPTransport) registerCoalesced(
	reservation TCPReservation,
	group *CoalescedRead,
) error {
	group.mu.Lock()
	defer group.mu.Unlock()
	return transport.registerCoalescedLocked(reservation, group)
}

func (transport *TCPTransport) registerCoalescedLocked(
	reservation TCPReservation,
	group *CoalescedRead,
) error {
	if group.completed || group.activeDependentCountLocked() == 0 {
		return nil
	}
	transport.closeMu.Lock()
	defer transport.closeMu.Unlock()
	if transport.closed {
		return protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"closed_transport",
			-1,
		)
	}
	transport.coalesced[reservation.PhysicalRequestID()] = group
	return nil
}

func (transport *TCPTransport) forgetCoalesced(physicalRequestID uint64) {
	if physicalRequestID == 0 {
		return
	}
	transport.closeMu.Lock()
	delete(transport.coalesced, physicalRequestID)
	transport.closeMu.Unlock()
}

func classifyNetWrite(
	expected int,
	written int,
	writeErr error,
	cancellationWon bool,
) TransmitResult {
	if cancellationWon {
		return TransmitCancellationRace
	}
	if written == expected && writeErr == nil {
		return TransmitComplete
	}
	if written > 0 && written < expected {
		return TransmitPartial
	}
	if written == 0 && writeErr != nil {
		var proof ProvableZeroWriteError
		if errors.As(writeErr, &proof) &&
			proof.ProvablyNoBytesTransmitted() {
			return TransmitProvableZero
		}
		return TransmitIndeterminate
	}
	return TransmitAmbiguous
}

func mergeOwnerTransitions(
	first OwnerTransition,
	second OwnerTransition,
) OwnerTransition {
	return OwnerTransition{
		closeConnection: first.closeConnection || second.closeConnection,
		failed: append(
			first.FailedReservations(),
			second.FailedReservations()...,
		),
	}
}

// ReadResponses reads one socket chunk and correlates every complete ADU.
func (transport *TCPTransport) ReadResponses(
	ctx context.Context,
) ([]WireResponse, OwnerTransition, error) {
	deadline, err := transport.relativeDeadline(transport.responseDeadline)
	if err != nil {
		return nil, OwnerTransition{}, err
	}
	responses, transition, _, err := transport.readResponsesUntil(ctx, deadline)
	return responses, transition, err
}

func (transport *TCPTransport) readResponsesUntil(
	ctx context.Context,
	deadlineOffset time.Duration,
) ([]WireResponse, OwnerTransition, []TCPReservation, error) {
	if transport == nil || ctx == nil {
		return nil, OwnerTransition{}, nil, protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"tcp_transport",
			-1,
		)
	}
	if ctx.Err() != nil {
		return nil, OwnerTransition{}, nil, ctx.Err()
	}
	if transport.clock.Now() >= deadlineOffset {
		abandoned, transition, abandonErr :=
			transport.owner.abandonExpired(transport.clock.Now())
		if transition.CloseConnection() {
			closeTransition, closeErr := transport.closeTerminal()
			transition = mergeOwnerTransitions(transition, closeTransition)
			abandonErr = errors.Join(abandonErr, closeErr)
		}
		return nil, transition, abandoned, errors.Join(
			context.DeadlineExceeded,
			abandonErr,
		)
	}
	operation := newTCPTransportOperation(
		transport,
		ctx,
		deadlineOffset,
		TCPEventResponseTimerArm,
		TCPEventResponseTimerFire,
		TCPEventReadInvocation,
		TCPEventReadReturn,
		tcpEventFields{DeadlineOffset: deadlineOffset},
	)
	defer operation.stopAndJoin()
	if err := acquireOperationGate(operation, transport.readGate); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			abandoned, transition, abandonErr :=
				transport.owner.abandonExpired(transport.clock.Now())
			return nil, transition, abandoned, errors.Join(err, abandonErr)
		}
		return nil, OwnerTransition{}, nil, err
	}
	defer releaseTransportGate(transport.readGate)
	if !transport.owner.transportCurrent(
		transport,
		transport.generation,
	) {
		return nil, OwnerTransition{}, nil, protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"stale_transport",
			-1,
		)
	}
	if err := operation.preInvocationError(); err != nil {
		return nil, OwnerTransition{}, nil, err
	}
	interrupter := newSocketInterrupter(
		transport.conn,
		transport.conn.SetReadDeadline,
	)
	activeRead := transport.registerActiveRead(deadlineOffset, interrupter)
	operation.setInterrupt(interrupter.Interrupt)
	if err := operation.beginInvocation(nil); err != nil {
		transport.finishActiveRead(activeRead)
		return nil, OwnerTransition{}, nil, err
	}
	buffer := make([]byte, maxTCPADUSize)
	count, readErr := transport.conn.Read(buffer)
	readReturnOffset := transport.clock.Now()
	operation.markReturn()
	operation.stopAndJoin()
	contextErr := operation.cause()
	rearmed := transport.finishActiveRead(activeRead)
	resetErr := interrupter.Reset()
	if operation.callerCancellationWonDuringIO() {
		transition, closeErr := transport.closeTerminal()
		return nil, transition, nil, errors.Join(
			readErr,
			contextErr,
			resetErr,
			closeErr,
		)
	}
	var abandoned []TCPReservation
	var abandonmentTransition OwnerTransition
	var abandonmentErr error
	deadlineWon := operation.deadlineWonDuringIO()
	abandoned, abandonmentTransition, abandonmentErr =
		transport.owner.abandonExpired(readReturnOffset)
	if rearmed && count == 0 && isTimeoutError(readErr) &&
		contextErr == nil && resetErr == nil &&
		!abandonmentTransition.CloseConnection() {
		return nil, OwnerTransition{}, abandoned, errReadDeadlineRearmed
	}
	frames, decodeErr := transport.decoder.Feed(buffer[:count])
	if errors.Is(readErr, io.EOF) {
		decodeErr = errors.Join(decodeErr, transport.decoder.Finish())
	}
	if decodeErr != nil || resetErr != nil {
		transition, closeErr := transport.closeTerminal()
		return nil, transition, abandoned, errors.Join(
			decodeErr,
			contextErr,
			resetErr,
			abandonmentErr,
			closeErr,
		)
	}
	responses := make([]WireResponse, 0, len(frames))
	var responseErr error
	for _, frame := range frames {
		response, correlateErr := transport.owner.Correlate(
			transport.generation,
			frame,
		)
		transport.forgetCoalesced(response.PhysicalRequestID())
		if correlateErr != nil {
			if response.WireResponseID() != 0 &&
				(response.Outcome() == WireProtocolException ||
					response.Outcome() == WireMalformedResponse) {
				responses = append(responses, response)
				responseErr = errors.Join(responseErr, correlateErr)
				continue
			}
			transition, closeErr := transport.closeTerminal()
			return responses, transition, abandoned, errors.Join(
				responseErr,
				correlateErr,
				closeErr,
			)
		}
		responses = append(responses, response)
	}
	if abandonmentTransition.CloseConnection() {
		closeTransition, closeErr := transport.closeTerminal()
		abandonmentTransition = mergeOwnerTransitions(
			abandonmentTransition,
			closeTransition,
		)
		abandonmentErr = errors.Join(abandonmentErr, closeErr)
	}
	if deadlineWon {
		return responses, abandonmentTransition, abandoned, errors.Join(
			responseErr,
			contextErr,
			abandonmentErr,
		)
	}
	if readErr != nil && (!rearmed || !isTimeoutError(readErr)) {
		transition, closeErr := transport.closeTerminal()
		return responses, transition, abandoned, errors.Join(
			responseErr,
			readErr,
			contextErr,
			closeErr,
		)
	}
	return responses, OwnerTransition{}, abandoned, responseErr
}

func isTimeoutError(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func (transport *TCPTransport) closeTerminal() (OwnerTransition, error) {
	transport.closeMu.Lock()
	if transport.closed {
		transition := transport.consumeCloseTransitionLocked()
		transport.closeMu.Unlock()
		return transition, nil
	}
	transport.closed = true
	groups := make([]*CoalescedRead, 0, len(transport.coalesced))
	for _, group := range transport.coalesced {
		groups = append(groups, group)
	}
	transport.coalesced = make(map[uint64]*CoalescedRead)
	ownerTransition := transport.owner.loseTransport(transport)
	transport.closeFailures = append(
		transport.closeFailures,
		ownerTransition.FailedReservations()...,
	)
	transition := transport.consumeCloseTransitionLocked()
	closeErr := transport.conn.Close()
	releaseTCPConnection(transport.socketIdentity, transport)
	transport.closeMu.Unlock()
	var groupErr error
	for _, group := range groups {
		groupErr = errors.Join(groupErr, group.FailTransport())
	}
	if ownerTransition.CloseConnection() {
		transport.owner.releasePoolSlot()
	}
	return transition, errors.Join(closeErr, groupErr)
}

func (transport *TCPTransport) consumeCloseTransitionLocked() OwnerTransition {
	failed := transport.closeFailures
	transport.closeFailures = nil
	return OwnerTransition{
		closeConnection: true,
		failed:          failed,
	}
}

func (transport *TCPTransport) closeDetached() error {
	transport.closeMu.Lock()
	if transport.closed {
		transport.closeMu.Unlock()
		return nil
	}
	transport.closed = true
	groups := make([]*CoalescedRead, 0, len(transport.coalesced))
	for _, group := range transport.coalesced {
		groups = append(groups, group)
	}
	transport.coalesced = make(map[uint64]*CoalescedRead)
	transport.closeFailures = nil
	closeErr := transport.conn.Close()
	releaseTCPConnection(transport.socketIdentity, transport)
	transport.closeMu.Unlock()
	var groupErr error
	for _, group := range groups {
		groupErr = errors.Join(groupErr, group.FailTransport())
	}
	return errors.Join(closeErr, groupErr)
}
