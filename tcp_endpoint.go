package modbus

import (
	"context"
	"errors"
	"sync"
	"time"
)

// TCPEndpointConfig declares every bounded resource owned by one endpoint.
type TCPEndpointConfig struct {
	Endpoint                 string
	PoolLimits               EndpointPoolLimits
	SchedulerLimits          SchedulerLimits
	Backoff                  BackoffConfig
	MaxBufferedBytes         int
	MaxRequestDeadline       time.Duration
	MaxResponseDeadline      time.Duration
	Clock                    TCPMonotonicClock
	EventSink                TCPTransportEventSink
	RuntimeAcquisitionSource *RuntimeAcquisitionSource
}

// TCPLogicalRead is one logical FC03/FC04 view in a physical read plan.
type TCPLogicalRead struct {
	LogicalViewID uint64
	Request       ReadRegistersRequest
}

// TCPReadPlan is one bounded, scheduler-owned endpoint operation.
type TCPReadPlan struct {
	Connection         TCPConnectionHandle
	UnitID             byte
	AuthorizationScope string
	PollGeneration     uint64
	DeadlineIdentity   uint64
	Timeout            time.Duration
	Reads              []TCPLogicalRead
}

// TCPDeviceIDPlan is one bounded, scheduler-owned FC2B/MEI0E traversal.
type TCPDeviceIDPlan struct {
	Connection         TCPConnectionHandle
	UnitID             byte
	AuthorizationScope string
	PollGeneration     uint64
	DeadlineIdentity   uint64
	Timeout            time.Duration
	Request            DeviceIDRequest
	Limits             DeviceIDLimits
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

// TCPDeviceIDCompletion is one fully validated endpoint traversal result.
type TCPDeviceIDCompletion struct {
	RequestID uint64
	Result    DeviceIDResult
}

// TCPReadBatch retains every frame and successful result from one socket read.
type TCPReadBatch struct {
	Responses []WireResponse
	Views     []LogicalReadView
	DeviceIDs []TCPDeviceIDCompletion
}

// TCPEndpointResources reports current bounded endpoint resource use.
type TCPEndpointResources struct {
	ActiveConnections    int
	MaxConnections       int
	QueuedRequests       int
	InFlightRequests     int
	MaxInFlightRequests  int
	ActiveAdmissionKeys  int
	MaxAdmissionKeys     int
	CoalescedDependents  int
	MaxCoalescedPerKey   int
	LiveRequests         int
	WaitingResponses     int
	RetainedRetries      int
	RetiredResponseState int
}

// TCPEndpointSnapshot is the read-only operational state for one runtime root.
type TCPEndpointSnapshot struct {
	Endpoint          string
	Healthy           bool
	Closed            bool
	DisableReason     string
	ReconnectRequired bool
	ReconnectReady    bool
	ReconnectWaiting  bool
	Resources         TCPEndpointResources
	Metrics           TCPEndpointMetrics
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
	deviceIDSegments    []DeviceIDSegment
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
