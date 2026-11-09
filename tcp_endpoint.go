package modbus

import (
	"context"
	"errors"
	"sync"
	"time"
)

// TCPEndpointConfig declares every bounded resource owned by one endpoint.
type TCPEndpointConfig struct {
	// Endpoint identifies the configured transport owner; it carries no vendor meaning.
	Endpoint string
	// PoolLimits bounds endpoint-owned connections and per-connection correlation state.
	PoolLimits EndpointPoolLimits
	// SchedulerLimits bounds queues, admission keys, dependents, and retry state.
	SchedulerLimits SchedulerLimits
	// Backoff supplies bounded reconnect progression and replayable jitter identity.
	Backoff BackoffConfig
	// MaxBufferedBytes caps retained stream-decoder bytes per connection.
	MaxBufferedBytes int
	// MaxRequestDeadline caps the positive timeout accepted for one endpoint operation.
	MaxRequestDeadline time.Duration
	// MaxResponseDeadline caps a response wait and must not exceed MaxRequestDeadline.
	MaxResponseDeadline time.Duration
	// Clock supplies the owner's monotonic time domain.
	Clock TCPMonotonicClock
	// EventSink receives ordered diagnostic transitions; implementations must return promptly.
	EventSink TCPTransportEventSink
	// RuntimeAcquisitionSource optionally observes successful logical views through a bounded
	// source owner.
	RuntimeAcquisitionSource *RuntimeAcquisitionSource
	// Framing selects the MBAP framing policy for every connection. The zero
	// value is TCPFramingStrict. TCPFramingTolerant requires MaxBufferedBytes
	// to hold a frame carrying a MaxTolerantPDUSize-byte PDU.
	Framing TCPFraming
}

// TCPLogicalRead is one logical FC03/FC04 view in a physical read plan.
type TCPLogicalRead struct {
	// LogicalViewID identifies the caller's logical read within a physical exchange.
	LogicalViewID uint64
	// Request retains the validated request used for correlation and decoding.
	Request ReadRegistersRequest
}

// TCPReadPlan is one bounded, scheduler-owned endpoint operation.
type TCPReadPlan struct {
	// Connection binds this plan to one endpoint-owned live connection handle.
	Connection TCPConnectionHandle
	// UnitID retains the addressed unit byte for correlation and admission.
	UnitID byte
	// AuthorizationScope is the caller's isolation key; it does not itself grant operation authority.
	AuthorizationScope string
	// PollGeneration separates reads belonging to different caller polling cycles.
	PollGeneration uint64
	// DeadlineIdentity separates caller deadline domains even when register ranges coincide.
	DeadlineIdentity uint64
	// Timeout bounds the operation with a positive duration on the owner's monotonic clock.
	Timeout time.Duration
	// Reads lists logical FC03/FC04 views to validate and coalesce within this operation.
	Reads []TCPLogicalRead
}

// TCPDeviceIDPlan is one bounded, scheduler-owned FC2B/MEI0E traversal.
type TCPDeviceIDPlan struct {
	// Connection binds this plan to one endpoint-owned live connection handle.
	Connection TCPConnectionHandle
	// UnitID retains the addressed unit byte for correlation and admission.
	UnitID byte
	// AuthorizationScope is the caller's isolation key; it does not itself grant operation authority.
	AuthorizationScope string
	// PollGeneration separates reads belonging to different caller polling cycles.
	PollGeneration uint64
	// DeadlineIdentity separates caller deadline domains even when register ranges coincide.
	DeadlineIdentity uint64
	// Timeout bounds the operation with a positive duration on the owner's monotonic clock.
	Timeout time.Duration
	// Request retains the validated request used for correlation and decoding.
	Request DeviceIDRequest
	// Limits supplies the finite bounds validated before allocating owner state.
	Limits DeviceIDLimits
	// Decoding selects strict (the zero value) or tolerant page decoding.
	Decoding DeviceIDDecoding
}

// TCPConnectionHandle is an opaque endpoint-owned live socket identity.
type TCPConnectionHandle struct {
	endpoint     *TCPEndpoint
	connectionID uint64
	generation   uint64
}

// ConnectionID returns the endpoint-local, non-reused connection identity.
func (handle TCPConnectionHandle) ConnectionID() uint64 {
	return handle.connectionID
}

// Generation returns the transport generation bound to this handle.
func (handle TCPConnectionHandle) Generation() uint64 {
	return handle.generation
}

// TCPRequestHandle is an opaque endpoint-owned operation identity.
type TCPRequestHandle struct {
	endpoint       *TCPEndpoint
	requestID      uint64
	deadlineOffset time.Duration
	backoff        *tcpRequestBackoffState
}

// RequestID returns the endpoint-assigned logical operation identity.
func (handle TCPRequestHandle) RequestID() uint64 {
	return handle.requestID
}

// DeadlineOffset returns the immutable absolute monotonic operation deadline.
func (handle TCPRequestHandle) DeadlineOffset() time.Duration {
	return handle.deadlineOffset
}

// TCPDispatch is a one-use scheduler-service token.
type TCPDispatch struct {
	endpoint   *TCPEndpoint
	dispatchID uint64
	requestID  uint64
}

// RequestID returns the request selected by deterministic queue service.
func (dispatch TCPDispatch) RequestID() uint64 {
	return dispatch.requestID
}

// TCPDeviceIDCompletion is one endpoint traversal result. A strict traversal
// publishes only a fully validated Result. A tolerant traversal leaves Result
// empty and publishes Tolerant, which keeps every page byte and names every
// deviation.
type TCPDeviceIDCompletion struct {
	// RequestID identifies the operation within its owning endpoint.
	RequestID uint64
	// Result holds a fully validated strict traversal; tolerant decoding leaves it empty.
	Result DeviceIDResult
	// Decoding selects strict aggregation or tolerant evidence-preserving decoding.
	Decoding DeviceIDDecoding
	// Tolerant holds tolerant traversal evidence while the strict Result remains empty.
	Tolerant DeviceIDTolerantResult
}

// TCPReadBatch retains every frame and successful result from one socket read.
type TCPReadBatch struct {
	// Responses retains every classified frame from the read, even when other frames fail.
	Responses []WireResponse
	// Views contains successful logical register views derived from correlated responses.
	Views []LogicalReadView
	// DeviceIDs contains completed device-identification traversals.
	DeviceIDs []TCPDeviceIDCompletion
}

// TCPEndpointResources reports current bounded endpoint resource use.
type TCPEndpointResources struct {
	// ActiveConnections counts currently retained endpoint connections.
	ActiveConnections int
	// MaxConnections caps simultaneously owned connections.
	MaxConnections int
	// QueuedRequests counts requests currently awaiting queue service.
	QueuedRequests int
	// InFlightRequests counts requests admitted to active service.
	InFlightRequests int
	// MaxInFlightRequests caps simultaneously active scheduler requests.
	MaxInFlightRequests int
	// ActiveAdmissionKeys counts currently retained authorization-scope and unit partitions.
	ActiveAdmissionKeys int
	// MaxAdmissionKeys caps retained admission partitions.
	MaxAdmissionKeys int
	// CoalescedDependents counts logical dependents retained by coalescing state.
	CoalescedDependents int
	// MaxCoalescedPerKey caps coalesced dependents per admission partition.
	MaxCoalescedPerKey int
	// LiveRequests counts retained endpoint request records.
	LiveRequests int
	// WaitingResponses counts requests currently waiting for a response.
	WaitingResponses int
	// RetainedRetries counts retained handles available for explicit retry decisions.
	RetainedRetries int
	// RetiredResponseState counts retired physical exchanges retained for response handling.
	RetiredResponseState int
}

// TCPEndpointSnapshot is the read-only operational state for one runtime root.
type TCPEndpointSnapshot struct {
	// Endpoint identifies the configured transport owner; it carries no vendor meaning.
	Endpoint string
	// Healthy requires an open endpoint, no reconnect requirement, and at least one active connection.
	Healthy bool
	// Closed reports terminal endpoint shutdown.
	Closed bool
	// DisableReason records why the endpoint stopped admitting work.
	DisableReason string
	// ReconnectRequired reports that socket recovery is required before further service.
	ReconnectRequired bool
	// ReconnectReady reports that the reconnect delay has elapsed.
	ReconnectReady bool
	// ReconnectWaiting reports a reconnect delay currently in progress.
	ReconnectWaiting bool
	// Resources reports current bounded resource use.
	Resources TCPEndpointResources
	// Metrics reports cumulative transport and scheduling observations.
	Metrics TCPEndpointMetrics
}

type endpointRequestPhase byte

const (
	endpointRequestQueued endpointRequestPhase = iota + 1
	endpointRequestDispatched
	endpointRequestWriting
	endpointRequestWaiting
)

type endpointConnection struct {
	lease     TCPConnectionLease
	transport *TCPTransport
	handle    TCPConnectionHandle
}

type endpointRequest struct {
	handle              TCPRequestHandle
	connectionID        uint64
	transportGeneration uint64
	unitID              byte
	authorizationScope  string
	pollGeneration      uint64
	deadlineIdentity    uint64
	group               *CoalescedRead
	deviceID            DeviceIDRequest
	deviceIDInitial     DeviceIDRequest
	deviceIDLimits      DeviceIDLimits
	deviceIDDecoding    DeviceIDDecoding
	deviceIDSegments    []DeviceIDSegment
	deviceIDTraversal   *deviceIDTolerantTraversal
	operationDeadline   time.Duration
	phase               endpointRequestPhase
	dispatchID          uint64
	physicalRequestID   uint64
	transactionID       uint16
	responseDeadline    time.Duration
	writeCancel         context.CancelFunc
	writeDone           chan struct{}
	cancelPending       bool
}

func (request *endpointRequest) isDeviceID() bool {
	return request != nil && request.group == nil
}

type tcpRequestBackoffState struct {
	mu                 sync.Mutex
	clockDebt          time.Duration
	lifecycle          tcpRequestLifecycle
	retries            int
	unitID             byte
	authorizationScope string
	pollGeneration     uint64
	deadlineIdentity   uint64
	reads              []TCPLogicalRead
	deviceID           DeviceIDRequest
	deviceIDLimits     DeviceIDLimits
	deviceIDDecoding   DeviceIDDecoding
	requiresBackoff    bool
	backoffSatisfied   bool
	backoffWaiting     bool
}

func (endpoint *TCPEndpoint) failRequest(
	request *endpointRequest,
) error {
	endpoint.scheduleMu.Lock()
	defer endpoint.scheduleMu.Unlock()
	return endpoint.failRequestSchedulingLocked(request)
}

func (endpoint *TCPEndpoint) failRequestSchedulingLocked(
	request *endpointRequest,
) error {
	if request == nil {
		return nil
	}
	if request.group != nil {
		return request.group.FailTransport()
	}
	if request.phase == endpointRequestQueued {
		endpoint.scheduler.CancelQueued(request.handle.requestID)
		return nil
	}
	err := endpoint.scheduler.Complete(request.handle.requestID)
	var protocolErr *ProtocolError
	if errors.As(err, &protocolErr) &&
		protocolErr.Field == "request_state" {
		return nil
	}
	return err
}

type tcpRequestLifecycle byte

const (
	tcpRequestActive tcpRequestLifecycle = iota + 1
	tcpRequestRetrying
	tcpRequestRetryable
	tcpRequestTerminal
)

type endpointPhysicalKey struct {
	connectionID      uint64
	physicalRequestID uint64
}

// TCPEndpoint is the only public constructor root for the read-only TCP runtime.
type TCPEndpoint struct {
	mu                sync.Mutex
	enqueueMu         sync.Mutex
	scheduleMu        sync.Mutex
	outcomeMu         sync.Mutex
	config            TCPEndpointConfig
	pool              *TCPEndpointPool
	scheduler         *EndpointScheduler
	backoff           *ReconnectBackoff
	timeline          *tcpEndpointTimeline
	connections       map[uint64]*endpointConnection
	requests          map[uint64]*endpointRequest
	physical          map[endpointPhysicalKey]uint64
	retiredPhysical   map[endpointPhysicalKey]tcpEventFields
	retryable         map[uint64]TCPRequestHandle
	nextRequestID     uint64
	nextDispatchID    uint64
	reconnectRequired bool
	reconnectReady    bool
	reconnectWaiting  bool
	afterSchedule     func()
	afterWrite        func()
	beforeOutcome     func()
	remoteEndpoint    string
	claimedRemote     bool
	disableReason     string
	closed            bool
}

var tcpEndpointClaims = struct {
	sync.Mutex
	owners map[string]*TCPEndpoint
}{
	owners: make(map[string]*TCPEndpoint),
}

// NewTCPEndpoint validates and atomically constructs one bounded endpoint.
func (endpoint *TCPEndpoint) requestEventFieldsLocked(
	request *endpointRequest,
) tcpEventFields {
	return endpoint.requestEventFields(request)
}

func (endpoint *TCPEndpoint) requestEventFields(
	request *endpointRequest,
) tcpEventFields {
	if request == nil {
		return tcpEventFields{}
	}
	fields := tcpEventFields{
		ConnectionID:        request.connectionID,
		TransportGeneration: request.transportGeneration,
		RequestID:           request.handle.requestID,
		PhysicalRequestID:   request.physicalRequestID,
		TransactionID:       request.transactionID,
		UnitID:              request.unitID,
		AuthorizationScope:  request.authorizationScope,
		PollGeneration:      request.pollGeneration,
		DeadlineIdentity:    request.deadlineIdentity,
		DeadlineOffset: func() time.Duration {
			if request.responseDeadline > 0 {
				return request.responseDeadline
			}
			return request.handle.deadlineOffset
		}(),
	}
	if request.isDeviceID() {
		fields.RequestedFunction = FunctionEncapsulatedInterface
		return fields
	}
	physical := request.group.PhysicalRequest()
	fields.RequestedFunction = physical.Function()
	fields.LogicalTable = physical.Table()
	fields.PhysicalOffset = physical.Offset()
	fields.PhysicalQuantity = physical.Quantity()
	return fields
}
