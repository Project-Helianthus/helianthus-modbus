package modbus

import (
	"context"
	"encoding/hex"
	"errors"
	"math"
	"sync"
	"sync/atomic"
	"time"
)

var (
	errRTUFrameDiscarded = errors.New("rtu frame discarded during quarantine")
	errRTUState          = errors.New("invalid rtu fixture endpoint state")
	errRTUEventReentry   = errors.New("rtu event sink reentry")
)

// IsRTUFrameDiscarded reports whether quarantine consumed the frame.
func IsRTUFrameDiscarded(err error) bool {
	return errors.Is(err, errRTUFrameDiscarded)
}

// RTUMonotonicClock supplies deterministic offsets to the fixture owner.
type RTUMonotonicClock interface {
	ContractVersion() string
	Now() time.Duration
}

// RTUEventKind identifies a serialized fixture owner transition.
type RTUEventKind string

const (
	RTUEventBeginRead            RTUEventKind = "begin_read"
	RTUEventTransmitResult       RTUEventKind = "transmit_result"
	RTUEventResponseReceive      RTUEventKind = "response_receive"
	RTUEventQuarantineTransition RTUEventKind = "quarantine_transition"
	RTUEventWaiterResolved       RTUEventKind = "waiter_resolved"
	RTUEventFrameDiscarded       RTUEventKind = "frame_discarded"
	RTUEventResynchronized       RTUEventKind = "resynchronized"
	RTUEventRecoveryRequired     RTUEventKind = "recovery_required"
	RTUEventRecovered            RTUEventKind = "recovered"
	RTUEventClosed               RTUEventKind = "closed"
)

// RTUEvent is one replayable owner-assigned fixture transition.
type RTUEvent struct {
	ClockContractVersion string
	Endpoint             string
	Kind                 RTUEventKind
	MonotonicOffset      time.Duration
	Sequence             uint64
	Generation           uint64
	RequestID            uint64
	UnitID               byte
	RequestedFunction    FunctionCode
	ReceivedFunction     FunctionCode
	Table                LogicalTable
	Offset               uint16
	Quantity             uint16
	AuthorizationScope   string
	PollGeneration       uint64
	DeadlineIdentity     uint64
	DeadlineOffset       time.Duration
	LogicalViewID        uint64
	RequestADUHex        string
	ResponseADUHex       string
	WireResponseID       uint64
	DiagnosticFrameID    uint64
	WireOutcome          WireOutcome
	State                RTUEndpointState
	TransmitResult       TransmitResult
	Detail               string
}

// RTUEventSink consumes serialized fixture events.
type RTUEventSink interface {
	RecordRTUEvent(RTUEvent)
}

// RTUEndpointState is the fixture owner finite-state-machine state.
type RTUEndpointState string

const (
	RTUStateIdle             RTUEndpointState = "idle"
	RTUStateWriting          RTUEndpointState = "writing"
	RTUStateResponseWait     RTUEndpointState = "response_wait"
	RTUStateInterFrameGuard  RTUEndpointState = "inter_frame_guard"
	RTUStateQuarantine       RTUEndpointState = "quarantine"
	RTUStateRecoveryRequired RTUEndpointState = "recovery_required"
	RTUStateClosed           RTUEndpointState = "closed"
)

// RTUFixtureLine is an in-memory identity with one endpoint owner.
type RTUFixtureLine struct {
	mu       sync.Mutex
	identity string
	owner    *RTUFixtureEndpoint
}

// NewRTUFixtureLine creates a non-physical, in-memory RTU line identity.
func NewRTUFixtureLine(identity string) (*RTUFixtureLine, error) {
	if identity == "" {
		return nil, protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"rtu_fixture_identity",
			-1,
		)
	}
	return &RTUFixtureLine{identity: identity}, nil
}

// RTUFixtureEndpointConfig configures only the offline fixture runtime.
type RTUFixtureEndpointConfig struct {
	Endpoint           string
	Line               *RTUFixtureLine
	Timing             RTUTiming
	Clock              RTUMonotonicClock
	EventSink          RTUEventSink
	FixtureOptIn       bool
	MaxDiscardedFrames uint64
}

// RTUReadPlan is one typed read admitted to the fixture owner.
type RTUReadPlan struct {
	UnitID             byte
	AuthorizationScope string
	PollGeneration     uint64
	DeadlineIdentity   uint64
	LogicalViewID      uint64
	Timeout            time.Duration
	Request            ReadRegistersRequest
}

// RTURequestHandle identifies one generation-scoped fixture request.
type RTURequestHandle struct {
	endpoint   *RTUFixtureEndpoint
	requestID  uint64
	generation uint64
}

// RequestID returns the owner-assigned physical request identity.
func (handle RTURequestHandle) RequestID() uint64 {
	return handle.requestID
}

// Generation returns the fixture transport generation.
func (handle RTURequestHandle) Generation() uint64 {
	return handle.generation
}

type rtuOwnedRequest struct {
	handle             RTURequestHandle
	plan               RTUReadPlan
	context            context.Context
	frame              []byte
	writeInvocation    time.Duration
	deadline           time.Duration
	transmitCompletion time.Duration
}

// RTUFixtureEndpoint is a serialized, offline-only RTU owner.
type RTUFixtureEndpoint struct {
	emitMu              sync.Mutex
	mu                  sync.Mutex
	callback            atomic.Bool
	endpoint            string
	line                *RTUFixtureLine
	timing              RTUTiming
	decoder             *RTUFrameDecoder
	clock               RTUMonotonicClock
	sink                RTUEventSink
	maxDiscardedFrames  uint64
	state               RTUEndpointState
	generation          uint64
	nextRequestID       uint64
	nextWireResponseID  uint64
	nextDiagnosticID    uint64
	nextSequence        uint64
	current             *rtuOwnedRequest
	quarantined         *rtuOwnedRequest
	lastClock           time.Duration
	haveClock           bool
	quarantineAnchor    time.Duration
	latencyDeadline     time.Duration
	quiescenceDeadline  time.Duration
	idleDeadline        time.Duration
	guardDeadline       time.Duration
	guardRequestID      uint64
	guardUnitID         byte
	discardedFrames     uint64
	quarantineDiscarded uint64
	quarantineSawBytes  bool
	eventSinkPanics     uint64
	pendingRecovery     string
	lastObservedByte    time.Duration
	haveObservedByte    bool
}

// NewRTUFixtureEndpoint claims one fixture line for an offline owner.
func NewRTUFixtureEndpoint(
	config RTUFixtureEndpointConfig,
) (*RTUFixtureEndpoint, error) {
	minimumQuiescence, timingOK := checkedRTUOffsetAdd(
		config.Timing.MaxResponseLatency(),
		config.Timing.InterFrame(),
	)
	if config.Endpoint == "" ||
		config.Line == nil ||
		config.Clock == nil ||
		config.Clock.ContractVersion() == "" ||
		!config.FixtureOptIn ||
		config.MaxDiscardedFrames == 0 ||
		config.Timing.characterTime <= 0 ||
		!timingOK ||
		minimumQuiescence > config.Timing.MaxQuiescence() {
		return nil, protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"rtu_fixture_config",
			-1,
		)
	}
	decoder, err := NewRTUFrameDecoder(config.Timing)
	if err != nil {
		return nil, err
	}
	endpoint := &RTUFixtureEndpoint{
		endpoint:           config.Endpoint,
		line:               config.Line,
		timing:             config.Timing,
		decoder:            decoder,
		clock:              config.Clock,
		sink:               config.EventSink,
		maxDiscardedFrames: config.MaxDiscardedFrames,
		state:              RTUStateIdle,
		generation:         1,
		nextRequestID:      1,
		nextWireResponseID: 1,
		nextDiagnosticID:   1,
	}
	config.Line.mu.Lock()
	defer config.Line.mu.Unlock()
	if config.Line.owner != nil {
		return nil, protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"rtu_fixture_owner",
			-1,
		)
	}
	config.Line.owner = endpoint
	return endpoint, nil
}

func (endpoint *RTUFixtureEndpoint) beginEventOperation() error {
	if endpoint.callback.Load() {
		return errRTUEventReentry
	}
	endpoint.emitMu.Lock()
	if endpoint.callback.Load() {
		endpoint.emitMu.Unlock()
		return errRTUEventReentry
	}
	return nil
}

func checkedRTUOffsetAdd(
	offset time.Duration,
	delay time.Duration,
) (time.Duration, bool) {
	if offset < 0 || delay < 0 || offset > time.Duration(math.MaxInt64)-delay {
		return 0, false
	}
	return offset + delay, true
}

func (endpoint *RTUFixtureEndpoint) canEmitLocked(count uint64) bool {
	return count > 0 &&
		endpoint.nextSequence <= math.MaxUint64-count
}

func (endpoint *RTUFixtureEndpoint) requireRecoveryLocked(detail string) {
	endpoint.state = RTUStateRecoveryRequired
	if endpoint.pendingRecovery == "" {
		endpoint.pendingRecovery = detail
	}
}

func (endpoint *RTUFixtureEndpoint) nowLocked() (time.Duration, error) {
	now := endpoint.clock.Now()
	if now < 0 || (endpoint.haveClock && now < endpoint.lastClock) {
		endpoint.requireRecoveryLocked("clock_regression")
		endpoint.current = nil
		endpoint.quarantined = nil
		return 0, errRTUState
	}
	endpoint.lastClock = now
	endpoint.haveClock = true
	return now, nil
}

// BeginRead admits one typed read and returns its exact fixture frame.
func (endpoint *RTUFixtureEndpoint) BeginRead(
	ctx context.Context,
	plan RTUReadPlan,
) (RTURequestHandle, []byte, error) {
	if endpoint == nil || ctx == nil {
		return RTURequestHandle{}, nil, errRTUState
	}
	if err := endpoint.beginEventOperation(); err != nil {
		return RTURequestHandle{}, nil, err
	}
	defer endpoint.emitMu.Unlock()
	if err := ctx.Err(); err != nil {
		return RTURequestHandle{}, nil, err
	}
	frame, err := EncodeRTUReadADU(plan.UnitID, plan.Request)
	if err != nil {
		return RTURequestHandle{}, nil, err
	}
	if plan.AuthorizationScope == "" ||
		plan.PollGeneration == 0 ||
		plan.DeadlineIdentity == 0 ||
		plan.LogicalViewID == 0 ||
		plan.Timeout <= 0 {
		return RTURequestHandle{}, nil, protocolError(
			ErrorInvalidRequest,
			plan.Request.Function(),
			0,
			"rtu_read_plan",
			-1,
		)
	}
	endpoint.mu.Lock()
	if endpoint.state != RTUStateIdle {
		endpoint.mu.Unlock()
		return RTURequestHandle{}, nil, errRTUState
	}
	if endpoint.nextRequestID == 0 ||
		endpoint.nextRequestID == math.MaxUint64 ||
		!endpoint.canEmitLocked(1) {
		endpoint.requireRecoveryLocked("request_identity_or_event_capacity")
		endpoint.mu.Unlock()
		return RTURequestHandle{}, nil, errRTUState
	}
	now, err := endpoint.nowLocked()
	if err != nil {
		endpoint.mu.Unlock()
		return RTURequestHandle{}, nil, err
	}
	deadline, ok := checkedRTUOffsetAdd(now, plan.Timeout)
	if !ok {
		endpoint.mu.Unlock()
		return RTURequestHandle{}, nil, protocolError(
			ErrorInvalidRange,
			plan.Request.Function(),
			0,
			"rtu_deadline",
			-1,
		)
	}
	handle := RTURequestHandle{
		endpoint:   endpoint,
		requestID:  endpoint.nextRequestID,
		generation: endpoint.generation,
	}
	endpoint.nextRequestID++
	endpoint.state = RTUStateWriting
	endpoint.lastObservedByte = 0
	endpoint.haveObservedByte = false
	endpoint.current = &rtuOwnedRequest{
		handle:          handle,
		plan:            plan,
		context:         ctx,
		frame:           cloneBytes(frame),
		writeInvocation: now,
		deadline:        deadline,
	}
	event := endpoint.eventLocked(
		RTUEventBeginRead,
		handle.requestID,
		plan.UnitID,
		0,
		"",
	)
	endpoint.mu.Unlock()
	endpoint.dispatch(event)
	return handle, cloneBytes(frame), nil
}

// CompleteTransmit classifies one fixture write invocation result.
func (endpoint *RTUFixtureEndpoint) CompleteTransmit(
	handle RTURequestHandle,
	result TransmitResult,
) error {
	if endpoint == nil {
		return errRTUState
	}
	if err := endpoint.beginEventOperation(); err != nil {
		return err
	}
	defer endpoint.emitMu.Unlock()
	endpoint.mu.Lock()
	if !endpoint.matchesLocked(handle) || endpoint.state != RTUStateWriting {
		endpoint.mu.Unlock()
		return errRTUState
	}
	switch result {
	case TransmitProvableZero, TransmitComplete:
	case TransmitPartial,
		TransmitIndeterminate,
		TransmitCancellationRace,
		TransmitAmbiguous:
	default:
		endpoint.mu.Unlock()
		return errRTUState
	}
	current := endpoint.current
	now, err := endpoint.nowLocked()
	if err != nil {
		endpoint.mu.Unlock()
		return err
	}
	cancelled := current.context.Err() != nil
	expired := now >= current.deadline
	eventCount := uint64(1)
	if result == TransmitProvableZero {
		eventCount = 2
	} else if result != TransmitComplete || cancelled || expired {
		eventCount = 3
	}
	if !endpoint.canEmitLocked(eventCount) {
		endpoint.requireRecoveryLocked("event_capacity")
		endpoint.current = nil
		endpoint.mu.Unlock()
		return errRTUState
	}
	var events []RTUEvent
	switch result {
	case TransmitProvableZero:
		endpoint.state = RTUStateIdle
		detail := result.String()
		if expired {
			detail = "timeout_before_provable_zero"
		}
		if cancelled {
			detail = "cancellation_before_provable_zero"
		}
		events = append(events, endpoint.eventLocked(
			RTUEventTransmitResult,
			handle.requestID,
			current.plan.UnitID,
			result,
			result.String(),
		), endpoint.eventLocked(
			RTUEventWaiterResolved,
			handle.requestID,
			current.plan.UnitID,
			result,
			detail,
		))
		endpoint.current = nil
		endpoint.lastObservedByte = 0
		endpoint.haveObservedByte = false
	case TransmitComplete:
		current.transmitCompletion = now
		if !cancelled && !expired {
			endpoint.state = RTUStateResponseWait
			events = append(events, endpoint.eventLocked(
				RTUEventTransmitResult,
				handle.requestID,
				current.plan.UnitID,
				result,
				result.String(),
			))
			break
		}
		detail := "timeout"
		if cancelled {
			detail = "cancellation"
		}
		deadlines, err := endpoint.prepareQuarantineLocked(now)
		if err != nil {
			endpoint.mu.Unlock()
			return err
		}
		endpoint.setQuarantineLocked(current, now, deadlines)
		events = append(events, endpoint.eventLocked(
			RTUEventTransmitResult,
			handle.requestID,
			current.plan.UnitID,
			result,
			result.String(),
		), endpoint.eventLocked(
			RTUEventQuarantineTransition,
			handle.requestID,
			current.plan.UnitID,
			0,
			detail,
		), endpoint.eventLocked(
			RTUEventWaiterResolved,
			handle.requestID,
			current.plan.UnitID,
			0,
			detail,
		))
	default:
		horizon, err := endpoint.timing.FrameTransmitHorizon(len(current.frame))
		if err != nil {
			endpoint.requireRecoveryLocked("transmit_horizon")
			endpoint.current = nil
			endpoint.mu.Unlock()
			return err
		}
		anchor, ok := checkedRTUOffsetAdd(current.writeInvocation, horizon)
		if !ok {
			endpoint.requireRecoveryLocked("transmit_anchor")
			endpoint.current = nil
			endpoint.mu.Unlock()
			return errRTUState
		}
		if anchor < now {
			anchor = now
		}
		deadlines, err := endpoint.prepareQuarantineLocked(anchor)
		if err != nil {
			endpoint.mu.Unlock()
			return err
		}
		endpoint.setQuarantineLocked(current, anchor, deadlines)
		events = append(events, endpoint.eventLocked(
			RTUEventTransmitResult,
			handle.requestID,
			current.plan.UnitID,
			result,
			result.String(),
		), endpoint.eventLocked(
			RTUEventQuarantineTransition,
			handle.requestID,
			current.plan.UnitID,
			0,
			result.String(),
		), endpoint.eventLocked(
			RTUEventWaiterResolved,
			handle.requestID,
			current.plan.UnitID,
			0,
			result.String(),
		))
	}
	endpoint.mu.Unlock()
	endpoint.dispatch(events...)
	return nil
}

// Tick owns context cancellation and deadline expiry for the active request.
func (endpoint *RTUFixtureEndpoint) Tick() error {
	if endpoint == nil {
		return errRTUState
	}
	if err := endpoint.beginEventOperation(); err != nil {
		return err
	}
	defer endpoint.emitMu.Unlock()

	endpoint.mu.Lock()
	now, err := endpoint.nowLocked()
	if err != nil {
		endpoint.mu.Unlock()
		return err
	}
	if endpoint.state == RTUStateQuarantine {
		if now <= endpoint.quiescenceDeadline {
			endpoint.mu.Unlock()
			return nil
		}
		if !endpoint.canEmitLocked(1) {
			endpoint.requireRecoveryLocked("event_capacity")
			endpoint.quarantined = nil
			endpoint.decoder.reset()
			endpoint.mu.Unlock()
			return errRTUState
		}
		requestID := uint64(0)
		unitID := byte(0)
		if endpoint.quarantined != nil {
			requestID = endpoint.quarantined.handle.requestID
			unitID = endpoint.quarantined.plan.UnitID
		}
		endpoint.state = RTUStateRecoveryRequired
		endpoint.quarantined = nil
		endpoint.decoder.reset()
		event := endpoint.eventLocked(
			RTUEventRecoveryRequired,
			requestID,
			unitID,
			0,
			"quiescence_timeout",
		)
		endpoint.mu.Unlock()
		endpoint.dispatch(event)
		return errRTUState
	}
	current := endpoint.current
	if current == nil {
		endpoint.mu.Unlock()
		return nil
	}
	cancelled := current.context.Err() != nil
	expired := now >= current.deadline
	if !cancelled && !expired {
		endpoint.mu.Unlock()
		return nil
	}

	switch endpoint.state {
	case RTUStateWriting:
		if !endpoint.canEmitLocked(3) {
			endpoint.requireRecoveryLocked("event_capacity")
			endpoint.current = nil
			endpoint.mu.Unlock()
			return errRTUState
		}
		result := TransmitAmbiguous
		detail := "deadline_during_write"
		if cancelled {
			result = TransmitCancellationRace
			detail = "cancellation_during_write"
		}
		horizon, err := endpoint.timing.FrameTransmitHorizon(len(current.frame))
		if err != nil {
			endpoint.requireRecoveryLocked("transmit_horizon")
			endpoint.current = nil
			endpoint.mu.Unlock()
			return err
		}
		anchor, ok := checkedRTUOffsetAdd(current.writeInvocation, horizon)
		if !ok {
			endpoint.requireRecoveryLocked("transmit_anchor")
			endpoint.current = nil
			endpoint.mu.Unlock()
			return errRTUState
		}
		if anchor < now {
			anchor = now
		}
		deadlines, err := endpoint.prepareQuarantineLocked(anchor)
		if err != nil {
			endpoint.mu.Unlock()
			return err
		}
		endpoint.setQuarantineLocked(current, anchor, deadlines)
		events := []RTUEvent{
			endpoint.eventLocked(
				RTUEventTransmitResult,
				current.handle.requestID,
				current.plan.UnitID,
				result,
				detail,
			),
			endpoint.eventLocked(
				RTUEventQuarantineTransition,
				current.handle.requestID,
				current.plan.UnitID,
				0,
				detail,
			),
			endpoint.eventLocked(
				RTUEventWaiterResolved,
				current.handle.requestID,
				current.plan.UnitID,
				0,
				detail,
			),
		}
		endpoint.mu.Unlock()
		endpoint.dispatch(events...)
		return nil
	case RTUStateResponseWait:
		if !endpoint.canEmitLocked(2) {
			endpoint.requireRecoveryLocked("event_capacity")
			endpoint.current = nil
			endpoint.mu.Unlock()
			return errRTUState
		}
		detail := "timeout"
		if cancelled {
			detail = "cancellation"
		}
		deadlines, err := endpoint.prepareQuarantineLocked(
			current.transmitCompletion,
		)
		if err != nil {
			endpoint.mu.Unlock()
			return err
		}
		endpoint.setQuarantineLocked(
			current,
			current.transmitCompletion,
			deadlines,
		)
		events := []RTUEvent{
			endpoint.eventLocked(
				RTUEventQuarantineTransition,
				current.handle.requestID,
				current.plan.UnitID,
				0,
				detail,
			),
			endpoint.eventLocked(
				RTUEventWaiterResolved,
				current.handle.requestID,
				current.plan.UnitID,
				0,
				detail,
			),
		}
		endpoint.mu.Unlock()
		endpoint.dispatch(events...)
		return nil
	default:
		endpoint.mu.Unlock()
		return errRTUState
	}
}

// Abandon moves a full-transmit response waiter into quarantine.
func (endpoint *RTUFixtureEndpoint) Abandon(
	handle RTURequestHandle,
	reason AbandonReason,
) error {
	if endpoint == nil ||
		(reason != AbandonTimeout && reason != AbandonCancellation) {
		return errRTUState
	}
	if err := endpoint.beginEventOperation(); err != nil {
		return err
	}
	defer endpoint.emitMu.Unlock()
	endpoint.mu.Lock()
	if !endpoint.matchesLocked(handle) ||
		endpoint.state != RTUStateResponseWait {
		endpoint.mu.Unlock()
		return errRTUState
	}
	if !endpoint.canEmitLocked(2) {
		endpoint.requireRecoveryLocked("event_capacity")
		endpoint.current = nil
		endpoint.mu.Unlock()
		return errRTUState
	}
	current := endpoint.current
	if _, err := endpoint.nowLocked(); err != nil {
		endpoint.mu.Unlock()
		return err
	}
	detail := "timeout"
	if reason == AbandonCancellation {
		detail = "cancellation"
	}
	deadlines, err := endpoint.prepareQuarantineLocked(
		current.transmitCompletion,
	)
	if err != nil {
		endpoint.mu.Unlock()
		return err
	}
	endpoint.setQuarantineLocked(
		current,
		current.transmitCompletion,
		deadlines,
	)
	events := []RTUEvent{
		endpoint.eventLocked(
			RTUEventQuarantineTransition,
			current.handle.requestID,
			current.plan.UnitID,
			0,
			detail,
		),
		endpoint.eventLocked(
			RTUEventWaiterResolved,
			current.handle.requestID,
			current.plan.UnitID,
			0,
			detail,
		),
	}
	endpoint.mu.Unlock()
	endpoint.dispatch(events...)
	return nil
}

type rtuQuarantineDeadlines struct {
	latency          time.Duration
	quiescence       time.Duration
	idle             time.Duration
	hadBufferedBytes bool
}

func (endpoint *RTUFixtureEndpoint) prepareQuarantineLocked(
	anchor time.Duration,
) (rtuQuarantineDeadlines, error) {
	latencyDeadline, ok := checkedRTUOffsetAdd(
		anchor,
		endpoint.timing.MaxResponseLatency(),
	)
	if !ok {
		endpoint.requireRecoveryLocked("latency_deadline")
		endpoint.current = nil
		return rtuQuarantineDeadlines{}, errRTUState
	}
	quiescenceDeadline, ok := checkedRTUOffsetAdd(
		anchor,
		endpoint.timing.MaxQuiescence(),
	)
	if !ok {
		endpoint.requireRecoveryLocked("quiescence_deadline")
		endpoint.current = nil
		return rtuQuarantineDeadlines{}, errRTUState
	}
	idleDeadline, ok := checkedRTUOffsetAdd(
		latencyDeadline,
		endpoint.timing.InterFrame(),
	)
	if !ok || idleDeadline > quiescenceDeadline {
		endpoint.requireRecoveryLocked("idle_deadline")
		endpoint.current = nil
		return rtuQuarantineDeadlines{}, errRTUState
	}
	if endpoint.haveObservedByte {
		bufferedIdle, valid := checkedRTUOffsetAdd(
			endpoint.lastObservedByte,
			endpoint.timing.InterFrame(),
		)
		if !valid || bufferedIdle > quiescenceDeadline {
			endpoint.requireRecoveryLocked("observed_idle_deadline")
			endpoint.current = nil
			return rtuQuarantineDeadlines{}, errRTUState
		}
		if bufferedIdle > idleDeadline {
			idleDeadline = bufferedIdle
		}
	}
	return rtuQuarantineDeadlines{
		latency:          latencyDeadline,
		quiescence:       quiescenceDeadline,
		idle:             idleDeadline,
		hadBufferedBytes: endpoint.haveObservedByte,
	}, nil
}

func (endpoint *RTUFixtureEndpoint) setQuarantineLocked(
	current *rtuOwnedRequest,
	anchor time.Duration,
	deadlines rtuQuarantineDeadlines,
) {
	endpoint.state = RTUStateQuarantine
	endpoint.quarantineAnchor = anchor
	endpoint.latencyDeadline = deadlines.latency
	endpoint.quiescenceDeadline = deadlines.quiescence
	endpoint.idleDeadline = deadlines.idle
	endpoint.quarantined = current
	endpoint.current = nil
	endpoint.quarantineDiscarded = 0
	endpoint.quarantineSawBytes = deadlines.hadBufferedBytes
	endpoint.decoder.reset()
}

// RTUReadResult is one request-bound fixture response.
type RTUReadResult struct {
	deliverable bool
	response    ReadRegistersResponse
	wire        WireResponse
	logical     LogicalReadView
}

// Deliverable reports whether the response completed the active request.
func (result RTUReadResult) Deliverable() bool {
	return result.deliverable
}

// Response returns a copy of the decoded register response.
func (result RTUReadResult) Response() ReadRegistersResponse {
	response := result.response
	response.Words = append([]uint16(nil), response.Words...)
	return response
}

// WireResponse returns the shared transport-neutral wire response view.
func (result RTUReadResult) WireResponse() WireResponse {
	return result.wire
}

// LogicalView returns the single read's shared logical view.
func (result RTUReadResult) LogicalView() (LogicalReadView, bool) {
	return result.logical, result.deliverable
}

func (endpoint *RTUFixtureEndpoint) expireQuarantineLocked(
	now time.Duration,
) (RTUEvent, bool, error) {
	if endpoint.state != RTUStateQuarantine ||
		now <= endpoint.quiescenceDeadline {
		return RTUEvent{}, false, nil
	}
	if !endpoint.canEmitLocked(1) {
		endpoint.requireRecoveryLocked("event_capacity")
		endpoint.quarantined = nil
		endpoint.decoder.reset()
		return RTUEvent{}, true, errRTUState
	}
	requestID := uint64(0)
	unitID := byte(0)
	if endpoint.quarantined != nil {
		requestID = endpoint.quarantined.handle.requestID
		unitID = endpoint.quarantined.plan.UnitID
	}
	endpoint.state = RTUStateRecoveryRequired
	endpoint.quarantined = nil
	endpoint.quarantineSawBytes = false
	endpoint.decoder.reset()
	return endpoint.eventLocked(
		RTUEventRecoveryRequired,
		requestID,
		unitID,
		0,
		"quiescence_timeout",
	), true, errRTUState
}

// FeedByte gives the fixture owner one byte at the injected monotonic offset.
func (endpoint *RTUFixtureEndpoint) FeedByte(value byte) error {
	if endpoint == nil {
		return errRTUState
	}
	if err := endpoint.beginEventOperation(); err != nil {
		return err
	}
	defer endpoint.emitMu.Unlock()
	endpoint.mu.Lock()
	now, err := endpoint.nowLocked()
	if err != nil {
		endpoint.mu.Unlock()
		return err
	}
	recovery, expired, err := endpoint.expireQuarantineLocked(now)
	if expired {
		endpoint.mu.Unlock()
		endpoint.dispatch(recovery)
		return err
	}
	var result error
	var events []RTUEvent
	switch endpoint.state {
	case RTUStateQuarantine:
		endpoint.lastObservedByte = now
		endpoint.haveObservedByte = true
		idleDeadline, ok := checkedRTUOffsetAdd(
			now,
			endpoint.timing.InterFrame(),
		)
		if !ok {
			endpoint.requireRecoveryLocked("idle_deadline")
			endpoint.quarantined = nil
			result = errRTUState
			break
		}
		if idleDeadline < endpoint.latencyDeadline {
			idleDeadline = endpoint.latencyDeadline
		}
		endpoint.idleDeadline = idleDeadline
		endpoint.quarantineSawBytes = true
		if err := endpoint.decoder.FeedByte(now, value); err != nil {
			endpoint.decoder.reset()
		}
	case RTUStateResponseWait:
		endpoint.lastObservedByte = now
		endpoint.haveObservedByte = true
		result = endpoint.decoder.FeedByte(now, value)
	case RTUStateInterFrameGuard:
		guardDeadline, ok := checkedRTUOffsetAdd(
			now,
			endpoint.timing.InterFrame(),
		)
		if !ok ||
			endpoint.discardedFrames == math.MaxUint64 ||
			!endpoint.canEmitLocked(1) {
			endpoint.requireRecoveryLocked("inter_frame_guard_activity")
			result = errRTUState
			break
		}
		endpoint.guardDeadline = guardDeadline
		endpoint.discardedFrames++
		events = append(events, endpoint.eventLocked(
			RTUEventFrameDiscarded,
			endpoint.guardRequestID,
			endpoint.guardUnitID,
			0,
			"inter_frame_guard_activity",
		))
		result = errRTUFrameDiscarded
	default:
		result = errRTUState
	}
	endpoint.mu.Unlock()
	endpoint.dispatch(events...)
	return result
}

// EndFrame completes the currently observed fixture frame after t3.5 idle.
func (endpoint *RTUFixtureEndpoint) EndFrame() (RTUReadResult, error) {
	if endpoint == nil {
		return RTUReadResult{}, errRTUState
	}
	if err := endpoint.beginEventOperation(); err != nil {
		return RTUReadResult{}, err
	}
	defer endpoint.emitMu.Unlock()
	endpoint.mu.Lock()
	now, err := endpoint.nowLocked()
	if err != nil {
		endpoint.mu.Unlock()
		return RTUReadResult{}, err
	}
	recovery, expired, err := endpoint.expireQuarantineLocked(now)
	if expired {
		endpoint.mu.Unlock()
		endpoint.dispatch(recovery)
		return RTUReadResult{}, err
	}
	switch endpoint.state {
	case RTUStateQuarantine:
		if !endpoint.quarantineSawBytes {
			endpoint.mu.Unlock()
			return RTUReadResult{}, errRTUState
		}
		endpoint.decoder.reset()
		endpoint.quarantineSawBytes = false
		endpoint.lastObservedByte = 0
		endpoint.haveObservedByte = false
		events, err := endpoint.discardQuarantineFrameLocked()
		endpoint.mu.Unlock()
		endpoint.dispatch(events...)
		if err != nil {
			return RTUReadResult{}, err
		}
		return RTUReadResult{}, errRTUFrameDiscarded
	case RTUStateResponseWait:
		current := endpoint.current
		adu, frameErr := endpoint.decoder.EndFrame(now)
		if frameErr != nil && len(adu.Bytes()) == 0 {
			endpoint.mu.Unlock()
			return RTUReadResult{}, frameErr
		}
		cancelled := current.context.Err() != nil
		expired := now >= current.deadline
		if cancelled || expired {
			if endpoint.discardedFrames == math.MaxUint64 ||
				!endpoint.canEmitLocked(3) {
				endpoint.requireRecoveryLocked(
					"discard_identity_or_event_capacity",
				)
				endpoint.current = nil
				endpoint.decoder.reset()
				endpoint.mu.Unlock()
				return RTUReadResult{}, errRTUState
			}
			detail := "timeout"
			if cancelled {
				detail = "cancellation"
			}
			deadlines, err := endpoint.prepareQuarantineLocked(
				current.transmitCompletion,
			)
			if err != nil {
				endpoint.mu.Unlock()
				return RTUReadResult{}, err
			}
			endpoint.setQuarantineLocked(
				current,
				current.transmitCompletion,
				deadlines,
			)
			endpoint.quarantineSawBytes = false
			endpoint.lastObservedByte = 0
			endpoint.haveObservedByte = false
			endpoint.discardedFrames++
			endpoint.quarantineDiscarded++
			events := []RTUEvent{
				endpoint.eventLocked(
					RTUEventQuarantineTransition,
					current.handle.requestID,
					current.plan.UnitID,
					0,
					detail,
				),
				endpoint.eventLocked(
					RTUEventWaiterResolved,
					current.handle.requestID,
					current.plan.UnitID,
					0,
					detail,
				),
				endpoint.eventLocked(
					RTUEventFrameDiscarded,
					current.handle.requestID,
					current.plan.UnitID,
					0,
					"expired_response",
				),
			}
			endpoint.mu.Unlock()
			endpoint.dispatch(events...)
			return RTUReadResult{}, errRTUFrameDiscarded
		}
		result, event, receiveErr := endpoint.receiveFrameLocked(
			current,
			adu.Bytes(),
			now,
		)
		endpoint.mu.Unlock()
		if event.Sequence != 0 {
			endpoint.dispatch(event)
		}
		return result, receiveErr
	default:
		endpoint.mu.Unlock()
		return RTUReadResult{}, errRTUState
	}
}

func (endpoint *RTUFixtureEndpoint) discardQuarantineFrameLocked() ([]RTUEvent, error) {
	if endpoint.discardedFrames == math.MaxUint64 ||
		endpoint.quarantineDiscarded == math.MaxUint64 {
		endpoint.requireRecoveryLocked("discard_identity")
		endpoint.quarantined = nil
		return nil, errRTUState
	}
	recovery := endpoint.quarantineDiscarded >= endpoint.maxDiscardedFrames
	eventCount := uint64(1)
	if recovery {
		eventCount++
	}
	if !endpoint.canEmitLocked(eventCount) {
		endpoint.requireRecoveryLocked("event_capacity")
		endpoint.quarantined = nil
		return nil, errRTUState
	}
	endpoint.discardedFrames++
	endpoint.quarantineDiscarded++
	requestID := uint64(0)
	unitID := byte(0)
	if endpoint.quarantined != nil {
		requestID = endpoint.quarantined.handle.requestID
		unitID = endpoint.quarantined.plan.UnitID
	}
	events := []RTUEvent{
		endpoint.eventLocked(
			RTUEventFrameDiscarded,
			requestID,
			unitID,
			0,
			"quarantine",
		),
	}
	if recovery {
		endpoint.state = RTUStateRecoveryRequired
		endpoint.quarantined = nil
		events = append(events, endpoint.eventLocked(
			RTUEventRecoveryRequired,
			requestID,
			unitID,
			0,
			"discard_bound",
		))
	}
	return events, nil
}

func (endpoint *RTUFixtureEndpoint) receiveFrameLocked(
	current *rtuOwnedRequest,
	frame []byte,
	now time.Duration,
) (RTUReadResult, RTUEvent, error) {
	decoded, err := DecodeRTUReadResponseADU(
		current.plan.UnitID,
		current.plan.Request,
		frame,
	)
	var receivedUnitID byte
	var receivedFunction FunctionCode
	if len(frame) != 0 {
		receivedUnitID = frame[0]
	}
	if len(frame) > 1 {
		receivedFunction = FunctionCode(frame[1])
	}
	candidate := receivedUnitID == current.plan.UnitID &&
		(receivedFunction == current.plan.Request.Function() ||
			receivedFunction == current.plan.Request.Function()|0x80)
	if !candidate {
		if endpoint.nextDiagnosticID == 0 ||
			endpoint.nextDiagnosticID == math.MaxUint64 ||
			!endpoint.canEmitLocked(1) {
			endpoint.requireRecoveryLocked(
				"diagnostic_identity_or_event_capacity",
			)
			endpoint.current = nil
			return RTUReadResult{}, RTUEvent{}, errRTUState
		}
		diagnosticID := endpoint.nextDiagnosticID
		endpoint.nextDiagnosticID++
		wire := WireResponse{
			outcome:           WireDroppedUncorrelated,
			diagnosticFrameID: diagnosticID,
			diagnostic: DiagnosticFrameProvenance{
				Endpoint:                    endpoint.endpoint,
				ReceivedTransportGeneration: endpoint.generation,
				ActiveTransportGeneration:   endpoint.generation,
				UnitID:                      receivedUnitID,
				ReceivedFunction:            receivedFunction,
			},
			bytes: decoded.Bytes(),
		}
		event := endpoint.eventLocked(
			RTUEventResponseReceive,
			0,
			receivedUnitID,
			0,
			string(WireDroppedUncorrelated),
		)
		event.ReceivedFunction = receivedFunction
		event.ResponseADUHex = hex.EncodeToString(decoded.Bytes())
		event.DiagnosticFrameID = diagnosticID
		event.WireOutcome = WireDroppedUncorrelated
		return RTUReadResult{wire: wire}, event, err
	}
	guardDeadline, ok := checkedRTUOffsetAdd(
		now,
		endpoint.timing.InterFrame(),
	)
	if !ok {
		endpoint.requireRecoveryLocked("guard_deadline")
		endpoint.current = nil
		return RTUReadResult{}, RTUEvent{}, errRTUState
	}
	if !endpoint.canEmitLocked(1) {
		endpoint.requireRecoveryLocked("event_capacity")
		endpoint.current = nil
		return RTUReadResult{}, RTUEvent{}, errRTUState
	}
	if endpoint.nextWireResponseID == 0 ||
		endpoint.nextWireResponseID == math.MaxUint64 {
		endpoint.requireRecoveryLocked("wire_response_identity")
		endpoint.current = nil
		return RTUReadResult{}, RTUEvent{}, errRTUState
	}
	response := decoded.Response()
	wireID := endpoint.nextWireResponseID
	endpoint.nextWireResponseID++
	provenance := WireProvenance{
		Endpoint:            endpoint.endpoint,
		Transport:           TransportRTU,
		TransportGeneration: endpoint.generation,
		UnitID:              current.plan.UnitID,
		RequestedFunction:   current.plan.Request.Function(),
		ReceivedFunction:    receivedFunction,
		Table:               current.plan.Request.Table(),
		Offset:              current.plan.Request.Offset(),
		Quantity:            current.plan.Request.Quantity(),
	}
	outcome := WireSuccessfulData
	deliverable := true
	if err != nil {
		deliverable = false
		if protocolErr, ok := err.(*ProtocolError); ok &&
			protocolErr.Kind == ErrorExceptionResponse {
			outcome = WireProtocolException
		} else {
			outcome = WireMalformedResponse
		}
	}
	wire := WireResponse{
		outcome:           outcome,
		deliverable:       deliverable,
		wireResponseID:    wireID,
		physicalRequestID: current.handle.requestID,
		provenance:        provenance,
		words:             append([]uint16(nil), response.Words...),
		bytes:             decoded.Bytes(),
	}
	var logical LogicalReadView
	if deliverable {
		logical = LogicalReadView{
			logicalViewID:  current.plan.LogicalViewID,
			wireResponseID: wireID,
			logicalOffset:  current.plan.Request.Offset(),
			logicalWords:   current.plan.Request.Quantity(),
			sliceWordCount: current.plan.Request.Quantity(),
			words:          append([]uint16(nil), response.Words...),
			provenance: LogicalViewProvenance{
				PhysicalRequestID:  current.handle.requestID,
				Wire:               provenance,
				AuthorizationScope: current.plan.AuthorizationScope,
				PollGeneration:     current.plan.PollGeneration,
				DeadlineIdentity:   current.plan.DeadlineIdentity,
				LogicalOffset:      current.plan.Request.Offset(),
				LogicalWordCount:   current.plan.Request.Quantity(),
				SliceWordCount:     current.plan.Request.Quantity(),
			},
		}
	}
	endpoint.state = RTUStateInterFrameGuard
	endpoint.guardDeadline = guardDeadline
	endpoint.guardRequestID = current.handle.requestID
	endpoint.guardUnitID = current.plan.UnitID
	event := endpoint.eventLocked(
		RTUEventResponseReceive,
		current.handle.requestID,
		current.plan.UnitID,
		TransmitComplete,
		string(outcome),
	)
	event.ReceivedFunction = receivedFunction
	event.ResponseADUHex = hex.EncodeToString(decoded.Bytes())
	event.WireResponseID = wireID
	event.WireOutcome = outcome
	endpoint.current = nil
	return RTUReadResult{
		deliverable: deliverable,
		response:    response,
		wire:        wire,
		logical:     logical,
	}, event, err
}

// TryResynchronize releases a guard only after its complete timing proof.
func (endpoint *RTUFixtureEndpoint) TryResynchronize() error {
	if endpoint == nil {
		return errRTUState
	}
	if err := endpoint.beginEventOperation(); err != nil {
		return err
	}
	defer endpoint.emitMu.Unlock()
	endpoint.mu.Lock()
	now, err := endpoint.nowLocked()
	if err != nil {
		endpoint.mu.Unlock()
		return err
	}
	quarantine := endpoint.state == RTUStateQuarantine
	switch endpoint.state {
	case RTUStateInterFrameGuard:
		if now < endpoint.guardDeadline {
			endpoint.mu.Unlock()
			return errRTUState
		}
	case RTUStateQuarantine:
		if now > endpoint.quiescenceDeadline {
			if !endpoint.canEmitLocked(1) {
				endpoint.requireRecoveryLocked("event_capacity")
				endpoint.mu.Unlock()
				return errRTUState
			}
			endpoint.state = RTUStateRecoveryRequired
			event := endpoint.eventLocked(
				RTUEventRecoveryRequired,
				0,
				0,
				0,
				"quiescence_timeout",
			)
			endpoint.mu.Unlock()
			endpoint.dispatch(event)
			return errRTUState
		}
		if now < endpoint.latencyDeadline || now < endpoint.idleDeadline {
			endpoint.mu.Unlock()
			return errRTUState
		}
	default:
		endpoint.mu.Unlock()
		return errRTUState
	}
	eventCount := uint64(1)
	if quarantine && endpoint.quarantineSawBytes {
		eventCount++
	}
	if !endpoint.canEmitLocked(eventCount) {
		endpoint.requireRecoveryLocked("event_capacity")
		endpoint.quarantined = nil
		endpoint.decoder.reset()
		endpoint.mu.Unlock()
		return errRTUState
	}
	var events []RTUEvent
	if quarantine && endpoint.quarantineSawBytes {
		if endpoint.discardedFrames == math.MaxUint64 ||
			endpoint.quarantineDiscarded == math.MaxUint64 {
			endpoint.state = RTUStateRecoveryRequired
			endpoint.quarantined = nil
			endpoint.decoder.reset()
			event := endpoint.eventLocked(
				RTUEventRecoveryRequired,
				0,
				0,
				0,
				"discard_bound",
			)
			endpoint.mu.Unlock()
			endpoint.dispatch(event)
			return errRTUState
		}
		endpoint.discardedFrames++
		endpoint.quarantineDiscarded++
		requestID := uint64(0)
		unitID := byte(0)
		if endpoint.quarantined != nil {
			requestID = endpoint.quarantined.handle.requestID
			unitID = endpoint.quarantined.plan.UnitID
		}
		events = append(events, endpoint.eventLocked(
			RTUEventFrameDiscarded,
			requestID,
			unitID,
			0,
			"buffered_at_resynchronization",
		))
		if endpoint.quarantineDiscarded > endpoint.maxDiscardedFrames {
			endpoint.state = RTUStateRecoveryRequired
			endpoint.quarantined = nil
			endpoint.quarantineSawBytes = false
			endpoint.decoder.reset()
			events = append(events, endpoint.eventLocked(
				RTUEventRecoveryRequired,
				requestID,
				unitID,
				0,
				"discard_bound",
			))
			endpoint.mu.Unlock()
			endpoint.dispatch(events...)
			return errRTUState
		}
	}
	endpoint.state = RTUStateIdle
	endpoint.quarantined = nil
	endpoint.quarantineSawBytes = false
	endpoint.quarantineDiscarded = 0
	endpoint.lastObservedByte = 0
	endpoint.haveObservedByte = false
	endpoint.decoder.reset()
	events = append(events, endpoint.eventLocked(
		RTUEventResynchronized,
		endpoint.guardRequestID,
		endpoint.guardUnitID,
		0,
		"",
	))
	endpoint.guardRequestID = 0
	endpoint.guardUnitID = 0
	endpoint.mu.Unlock()
	endpoint.dispatch(events...)
	return nil
}

// FailQuiescence disables a quarantined endpoint pending explicit recovery.
func (endpoint *RTUFixtureEndpoint) FailQuiescence() error {
	if endpoint == nil {
		return errRTUState
	}
	if err := endpoint.beginEventOperation(); err != nil {
		return err
	}
	defer endpoint.emitMu.Unlock()
	endpoint.mu.Lock()
	if endpoint.state != RTUStateQuarantine {
		endpoint.mu.Unlock()
		return errRTUState
	}
	if _, err := endpoint.nowLocked(); err != nil {
		endpoint.mu.Unlock()
		return err
	}
	if !endpoint.canEmitLocked(1) {
		endpoint.requireRecoveryLocked("event_capacity")
		endpoint.mu.Unlock()
		return errRTUState
	}
	endpoint.state = RTUStateRecoveryRequired
	event := endpoint.eventLocked(
		RTUEventRecoveryRequired,
		0,
		0,
		0,
		"quiescence",
	)
	endpoint.mu.Unlock()
	endpoint.dispatch(event)
	return nil
}

// Recover creates a new fixture transport generation after explicit recovery.
func (endpoint *RTUFixtureEndpoint) Recover() error {
	if endpoint == nil {
		return errRTUState
	}
	if err := endpoint.beginEventOperation(); err != nil {
		return err
	}
	defer endpoint.emitMu.Unlock()
	endpoint.mu.Lock()
	if endpoint.state != RTUStateRecoveryRequired ||
		endpoint.generation == math.MaxUint64 {
		endpoint.mu.Unlock()
		return errRTUState
	}
	if _, err := endpoint.nowLocked(); err != nil {
		endpoint.mu.Unlock()
		return err
	}
	eventCount := uint64(1)
	if endpoint.pendingRecovery != "" {
		eventCount++
	}
	if !endpoint.canEmitLocked(eventCount) {
		endpoint.mu.Unlock()
		return errRTUState
	}
	var events []RTUEvent
	if endpoint.pendingRecovery != "" {
		events = append(events, endpoint.eventLocked(
			RTUEventRecoveryRequired,
			0,
			0,
			0,
			endpoint.pendingRecovery,
		))
		endpoint.pendingRecovery = ""
	}
	endpoint.generation++
	endpoint.nextRequestID = 1
	endpoint.nextWireResponseID = 1
	endpoint.nextDiagnosticID = 1
	endpoint.state = RTUStateIdle
	endpoint.current = nil
	endpoint.quarantined = nil
	endpoint.quarantineAnchor = 0
	endpoint.latencyDeadline = 0
	endpoint.quiescenceDeadline = 0
	endpoint.idleDeadline = 0
	endpoint.guardDeadline = 0
	endpoint.guardRequestID = 0
	endpoint.guardUnitID = 0
	endpoint.quarantineDiscarded = 0
	endpoint.quarantineSawBytes = false
	endpoint.lastObservedByte = 0
	endpoint.haveObservedByte = false
	endpoint.decoder.reset()
	events = append(events, endpoint.eventLocked(
		RTUEventRecovered,
		0,
		0,
		0,
		"",
	))
	endpoint.mu.Unlock()
	endpoint.dispatch(events...)
	return nil
}

// RTUFixtureEndpointSnapshot is an immutable endpoint state view.
type RTUFixtureEndpointSnapshot struct {
	state           RTUEndpointState
	generation      uint64
	discardedFrames uint64
	eventSinkPanics uint64
}

// State returns the current fixture owner state.
func (snapshot RTUFixtureEndpointSnapshot) State() RTUEndpointState {
	return snapshot.state
}

// Generation returns the current fixture transport generation.
func (snapshot RTUFixtureEndpointSnapshot) Generation() uint64 {
	return snapshot.generation
}

// DiscardedFrames returns the cumulative quarantine discard count.
func (snapshot RTUFixtureEndpointSnapshot) DiscardedFrames() uint64 {
	return snapshot.discardedFrames
}

// EventSinkPanics returns the number of contained event-sink panics.
func (snapshot RTUFixtureEndpointSnapshot) EventSinkPanics() uint64 {
	return snapshot.eventSinkPanics
}

// Snapshot returns one immutable endpoint state view.
func (endpoint *RTUFixtureEndpoint) Snapshot() RTUFixtureEndpointSnapshot {
	if endpoint == nil {
		return RTUFixtureEndpointSnapshot{}
	}
	endpoint.mu.Lock()
	defer endpoint.mu.Unlock()
	return RTUFixtureEndpointSnapshot{
		state:           endpoint.state,
		generation:      endpoint.generation,
		discardedFrames: endpoint.discardedFrames,
		eventSinkPanics: endpoint.eventSinkPanics,
	}
}

// FixtureLine returns the in-memory line identity for controlled replacement.
func (endpoint *RTUFixtureEndpoint) FixtureLine() *RTUFixtureLine {
	if endpoint == nil {
		return nil
	}
	return endpoint.line
}

// Close releases the fixture line and terminalizes the owner idempotently.
func (endpoint *RTUFixtureEndpoint) Close() error {
	if endpoint == nil {
		return nil
	}
	if err := endpoint.beginEventOperation(); err != nil {
		return err
	}
	defer endpoint.emitMu.Unlock()
	endpoint.mu.Lock()
	if endpoint.state == RTUStateClosed {
		endpoint.mu.Unlock()
		return nil
	}
	if _, err := endpoint.nowLocked(); err != nil {
		endpoint.state = RTUStateClosed
		endpoint.current = nil
		endpoint.quarantined = nil
		line := endpoint.line
		endpoint.mu.Unlock()
		if line != nil {
			line.mu.Lock()
			if line.owner == endpoint {
				line.owner = nil
			}
			line.mu.Unlock()
		}
		return err
	}
	if !endpoint.canEmitLocked(1) {
		endpoint.state = RTUStateClosed
		endpoint.current = nil
		line := endpoint.line
		endpoint.mu.Unlock()
		if line != nil {
			line.mu.Lock()
			if line.owner == endpoint {
				line.owner = nil
			}
			line.mu.Unlock()
		}
		return errRTUState
	}
	endpoint.state = RTUStateClosed
	endpoint.current = nil
	endpoint.quarantined = nil
	endpoint.guardRequestID = 0
	endpoint.guardUnitID = 0
	endpoint.lastObservedByte = 0
	endpoint.haveObservedByte = false
	endpoint.decoder.reset()
	event := endpoint.eventLocked(RTUEventClosed, 0, 0, 0, "")
	line := endpoint.line
	endpoint.mu.Unlock()
	if line != nil {
		line.mu.Lock()
		if line.owner == endpoint {
			line.owner = nil
		}
		line.mu.Unlock()
	}
	endpoint.dispatch(event)
	return nil
}

func (endpoint *RTUFixtureEndpoint) matchesLocked(
	handle RTURequestHandle,
) bool {
	return endpoint.current != nil &&
		handle.endpoint == endpoint &&
		handle.requestID != 0 &&
		handle.requestID == endpoint.current.handle.requestID &&
		handle.generation == endpoint.generation
}

func (endpoint *RTUFixtureEndpoint) eventLocked(
	kind RTUEventKind,
	requestID uint64,
	unitID byte,
	result TransmitResult,
	detail string,
) RTUEvent {
	if endpoint.nextSequence == math.MaxUint64 {
		endpoint.state = RTUStateRecoveryRequired
		return RTUEvent{}
	}
	endpoint.nextSequence++
	event := RTUEvent{
		ClockContractVersion: endpoint.clock.ContractVersion(),
		Endpoint:             endpoint.endpoint,
		Kind:                 kind,
		MonotonicOffset:      endpoint.lastClock,
		Sequence:             endpoint.nextSequence,
		Generation:           endpoint.generation,
		RequestID:            requestID,
		UnitID:               unitID,
		State:                endpoint.state,
		TransmitResult:       result,
		Detail:               detail,
	}
	var current *rtuOwnedRequest
	if endpoint.current != nil &&
		endpoint.current.handle.requestID == requestID {
		current = endpoint.current
	} else if endpoint.quarantined != nil &&
		endpoint.quarantined.handle.requestID == requestID {
		current = endpoint.quarantined
	}
	if current != nil {
		event.RequestedFunction = current.plan.Request.Function()
		event.Table = current.plan.Request.Table()
		event.Offset = current.plan.Request.Offset()
		event.Quantity = current.plan.Request.Quantity()
		event.AuthorizationScope = current.plan.AuthorizationScope
		event.PollGeneration = current.plan.PollGeneration
		event.DeadlineIdentity = current.plan.DeadlineIdentity
		event.DeadlineOffset = current.deadline
		event.LogicalViewID = current.plan.LogicalViewID
		event.RequestADUHex = hex.EncodeToString(current.frame)
	}
	return event
}

func (endpoint *RTUFixtureEndpoint) dispatch(events ...RTUEvent) {
	if endpoint.sink == nil {
		return
	}
	for _, event := range events {
		if event.Sequence == 0 {
			continue
		}
		panicked := false
		func() {
			endpoint.callback.Store(true)
			defer endpoint.callback.Store(false)
			defer func() {
				if recover() != nil {
					panicked = true
				}
			}()
			endpoint.sink.RecordRTUEvent(event)
		}()
		if panicked {
			endpoint.mu.Lock()
			if endpoint.eventSinkPanics < math.MaxUint64 {
				endpoint.eventSinkPanics++
			}
			endpoint.mu.Unlock()
		}
	}
}
