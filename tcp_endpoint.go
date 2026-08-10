package modbus

import (
	"context"
	"encoding/hex"
	"errors"
	"math"
	"net"
	"net/url"
	"sort"
	"strconv"
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
func NewTCPEndpoint(config TCPEndpointConfig) (*TCPEndpoint, error) {
	remoteEndpoint, remoteErr := configuredTCPRemote(config.Endpoint)
	if remoteErr != nil ||
		config.MaxBufferedBytes < mbapHeaderSize ||
		config.MaxBufferedBytes > maxTCPDecoderBuffer ||
		config.MaxRequestDeadline <= 0 ||
		config.MaxResponseDeadline <= 0 ||
		config.MaxResponseDeadline > config.MaxRequestDeadline ||
		config.Clock == nil ||
		config.Clock.ContractVersion() == "" ||
		config.Clock.Now() < 0 ||
		config.PoolLimits.MaxConnections <= 0 ||
		config.PoolLimits.Connection.MaxInFlight <= 0 ||
		config.PoolLimits.MaxConnections >
			math.MaxInt/config.PoolLimits.Connection.MaxInFlight ||
		config.SchedulerLimits.MaxInFlightRequests >
			config.PoolLimits.MaxConnections*
				config.PoolLimits.Connection.MaxInFlight {
		return nil, invalidEndpointConfig()
	}
	pool, err := newTCPEndpointPool(config.Endpoint, config.PoolLimits)
	if err != nil {
		return nil, err
	}
	scheduler, err := newEndpointScheduler(config.SchedulerLimits)
	if err != nil {
		return nil, err
	}
	backoff, err := newReconnectBackoff(config.Backoff)
	if err != nil {
		return nil, err
	}
	timeline := newTCPEndpointTimeline(
		config.Endpoint,
		config.Clock,
		config.EventSink,
	)
	return &TCPEndpoint{
		config:          config,
		pool:            pool,
		scheduler:       scheduler,
		backoff:         backoff,
		timeline:        timeline,
		connections:     make(map[uint64]*endpointConnection),
		requests:        make(map[uint64]*endpointRequest),
		physical:        make(map[endpointPhysicalKey]uint64),
		retiredPhysical: make(map[endpointPhysicalKey]tcpEventFields),
		retryable:       make(map[uint64]TCPRequestHandle),
		nextRequestID:   1,
		nextDispatchID:  1,
		remoteEndpoint:  remoteEndpoint,
	}, nil
}

func configuredTCPRemote(endpoint string) (string, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil ||
		parsed.Scheme != "tcp" ||
		parsed.Host == "" ||
		parsed.User != nil ||
		parsed.Path != "" ||
		parsed.RawQuery != "" ||
		parsed.Fragment != "" {
		return "", invalidEndpointConfig()
	}
	host, portText, err := net.SplitHostPort(parsed.Host)
	ip := net.ParseIP(host)
	if err != nil || ip == nil {
		return "", invalidEndpointConfig()
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "", invalidEndpointConfig()
	}
	return net.JoinHostPort(ip.String(), strconv.Itoa(port)), nil
}

func invalidEndpointConfig() error {
	return protocolError(
		ErrorInvalidRequest,
		0,
		0,
		"tcp_endpoint_config",
		-1,
	)
}

func eventSequenceError() error {
	return protocolError(
		ErrorInvalidRange,
		0,
		0,
		"event_sequence",
		-1,
	)
}

func (endpoint *TCPEndpoint) timelineAvailable() bool {
	if endpoint == nil || endpoint.timeline == nil {
		return false
	}
	if !endpoint.timeline.Exhausted() {
		return true
	}
	return false
}

func (endpoint *TCPEndpoint) eventSinkCallbackActive() bool {
	return endpoint != nil &&
		endpoint.timeline != nil &&
		endpoint.timeline.callbackActive()
}

func eventSinkReentryError() error {
	return protocolError(
		ErrorInvalidRequest,
		0,
		0,
		"event_sink_reentry",
		-1,
	)
}

// Snapshot returns current health, bounded resource use, and cumulative metrics.
func (endpoint *TCPEndpoint) Snapshot() TCPEndpointSnapshot {
	if endpoint == nil {
		return TCPEndpointSnapshot{}
	}
	endpoint.scheduleMu.Lock()
	scheduler := endpoint.scheduler.resourceSnapshot()
	endpoint.mu.Lock()
	resources := TCPEndpointResources{
		ActiveConnections:    endpoint.pool.ActiveConnections(),
		MaxConnections:       endpoint.config.PoolLimits.MaxConnections,
		QueuedRequests:       scheduler.queuedRequests,
		InFlightRequests:     scheduler.inFlightRequests,
		MaxInFlightRequests:  endpoint.config.SchedulerLimits.MaxInFlightRequests,
		ActiveAdmissionKeys:  scheduler.activeAdmissionKeys,
		MaxAdmissionKeys:     endpoint.config.SchedulerLimits.MaxActiveAdmissionKeys,
		CoalescedDependents:  scheduler.coalescedDependents,
		MaxCoalescedPerKey:   endpoint.config.SchedulerLimits.MaxCoalescedDependentsPerKey,
		LiveRequests:         len(endpoint.requests),
		RetainedRetries:      len(endpoint.retryable),
		RetiredResponseState: len(endpoint.retiredPhysical),
	}
	for _, request := range endpoint.requests {
		if request.phase == endpointRequestWaiting {
			resources.WaitingResponses++
		}
	}
	snapshot := TCPEndpointSnapshot{
		Endpoint:          endpoint.config.Endpoint,
		Closed:            endpoint.closed,
		DisableReason:     endpoint.disableReason,
		ReconnectRequired: endpoint.reconnectRequired,
		ReconnectReady:    endpoint.reconnectReady,
		ReconnectWaiting:  endpoint.reconnectWaiting,
		Resources:         resources,
	}
	snapshot.Healthy = !snapshot.Closed &&
		!snapshot.ReconnectRequired &&
		resources.ActiveConnections > 0
	endpoint.mu.Unlock()
	endpoint.scheduleMu.Unlock()
	snapshot.Metrics = endpoint.timeline.metricsSnapshot()
	return snapshot
}

// OpenConnection binds one raw production TCP socket to its configured remote.
// Only package-private test decorators may wrap a connection.
func (endpoint *TCPEndpoint) OpenConnection(
	conn net.Conn,
) (TCPConnectionHandle, error) {
	if endpoint == nil || conn == nil {
		return TCPConnectionHandle{}, invalidEndpointConfig()
	}
	if endpoint.eventSinkCallbackActive() {
		return TCPConnectionHandle{}, eventSinkReentryError()
	}
	if !endpoint.timelineAvailable() {
		endpoint.disable("event_sequence_exhausted")
		return TCPConnectionHandle{}, invalidEndpointConfig()
	}
	endpoint.mu.Lock()
	if endpoint.closed {
		endpoint.mu.Unlock()
		return TCPConnectionHandle{}, invalidEndpointConfig()
	}
	if endpoint.reconnectRequired && !endpoint.reconnectReady {
		endpoint.mu.Unlock()
		return TCPConnectionHandle{}, protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"reconnect_backoff",
			-1,
		)
	}
	newRemoteClaim, err := endpoint.claimRemoteForConnection(conn)
	if err != nil {
		endpoint.mu.Unlock()
		return TCPConnectionHandle{}, err
	}
	lease, err := endpoint.pool.openConnection()
	if err != nil {
		endpoint.releaseRemoteClaimIfUnused(newRemoteClaim)
		endpoint.mu.Unlock()
		return TCPConnectionHandle{}, err
	}
	owner := lease.ownerForEndpoint()
	transport, err := newTCPTransportWithConfig(
		conn,
		owner,
		TCPTransportConfig{
			MaxBufferedBytes: endpoint.config.MaxBufferedBytes,
			RequestDeadline:  endpoint.config.MaxRequestDeadline,
			ResponseDeadline: endpoint.config.MaxResponseDeadline,
			Clock:            endpoint.config.Clock,
			EventSink:        endpoint.config.EventSink,
			timeline:         endpoint.timeline,
			beforeClose:      endpoint.markReconnectRequired,
		},
	)
	if err != nil {
		_ = endpoint.pool.closeConnection(lease)
		endpoint.releaseRemoteClaimIfUnused(newRemoteClaim)
		endpoint.mu.Unlock()
		if !isConnectionClaimError(err) {
			_ = conn.Close()
		}
		return TCPConnectionHandle{}, err
	}
	handle := TCPConnectionHandle{
		endpoint:     endpoint,
		connectionID: lease.ConnectionID(),
		generation:   owner.Generation(),
	}
	endpoint.connections[handle.connectionID] = &endpointConnection{
		lease:     lease,
		transport: transport,
		handle:    handle,
	}
	reconnected := endpoint.reconnectRequired
	if endpoint.reconnectRequired {
		endpoint.reconnectRequired = false
		endpoint.reconnectReady = false
	}
	endpoint.backoff.Connected()
	endpoint.mu.Unlock()
	if reconnected {
		endpoint.timeline.recordReconnect(tcpEventFields{
			ConnectionID:        handle.connectionID,
			TransportGeneration: handle.generation,
		})
		if !endpoint.timelineAvailable() {
			endpoint.disable("event_sequence_exhausted")
			return TCPConnectionHandle{}, eventSequenceError()
		}
	}
	return handle, nil
}

func (endpoint *TCPEndpoint) claimRemoteForConnection(
	conn net.Conn,
) (bool, error) {
	_, trustedDecorator := conn.(trustedTCPConnectionDecorator)
	base, err := trustedTCPBaseConnection(conn)
	if err != nil {
		return false, err
	}
	tcpConn, production := base.(*net.TCPConn)
	if !production {
		if !trustedDecorator {
			return false, protocolError(
				ErrorInvalidRequest,
				0,
				0,
				"endpoint_remote_identity",
				-1,
			)
		}
		return false, nil
	}
	remote := tcpConn.RemoteAddr()
	if remote == nil || remote.String() != endpoint.remoteEndpoint {
		return false, protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"endpoint_remote_identity",
			-1,
		)
	}
	tcpEndpointClaims.Lock()
	defer tcpEndpointClaims.Unlock()
	current := tcpEndpointClaims.owners[endpoint.remoteEndpoint]
	if current != nil && current != endpoint {
		return false, protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"endpoint_already_owned",
			-1,
		)
	}
	if current == endpoint {
		return false, nil
	}
	tcpEndpointClaims.owners[endpoint.remoteEndpoint] = endpoint
	endpoint.claimedRemote = true
	return true, nil
}

func (endpoint *TCPEndpoint) releaseRemoteClaimIfUnused(newClaim bool) {
	if !newClaim || len(endpoint.connections) != 0 {
		return
	}
	tcpEndpointClaims.Lock()
	if tcpEndpointClaims.owners[endpoint.remoteEndpoint] == endpoint {
		delete(tcpEndpointClaims.owners, endpoint.remoteEndpoint)
		endpoint.claimedRemote = false
	}
	tcpEndpointClaims.Unlock()
}

func isConnectionClaimError(err error) bool {
	var protocolErr *ProtocolError
	return errors.As(err, &protocolErr) &&
		(protocolErr.Field == "connection_already_owned" ||
			protocolErr.Field == "connection_identity" ||
			protocolErr.Field == "endpoint_already_owned" ||
			protocolErr.Field == "endpoint_remote_identity")
}

// CloseConnection retires one exact handle and all work bound to its socket.
func (endpoint *TCPEndpoint) CloseConnection(
	handle TCPConnectionHandle,
) error {
	if endpoint == nil {
		return invalidEndpointConfig()
	}
	if endpoint.eventSinkCallbackActive() {
		return eventSinkReentryError()
	}
	endpoint.mu.Lock()
	connection, ok := endpoint.connectionLocked(handle)
	if !ok {
		endpoint.mu.Unlock()
		return invalidConnectionHandle()
	}
	delete(endpoint.connections, handle.connectionID)
	for key := range endpoint.retiredPhysical {
		if key.connectionID == handle.connectionID {
			delete(endpoint.retiredPhysical, key)
		}
	}
	requests := endpoint.removeConnectionRequestsLocked(handle.connectionID)
	endpoint.mu.Unlock()
	err := endpoint.pool.closeConnection(connection.lease)
	for _, request := range requests {
		setTCPRequestLifecycle(request.handle, tcpRequestTerminal)
		err = errors.Join(err, endpoint.failRequest(request))
	}
	return err
}

// Close retires every socket and terminalizes all endpoint-owned work.
func (endpoint *TCPEndpoint) Close() error {
	if endpoint == nil {
		return invalidEndpointConfig()
	}
	if endpoint.eventSinkCallbackActive() {
		return eventSinkReentryError()
	}
	endpoint.mu.Lock()
	if endpoint.closed {
		endpoint.mu.Unlock()
		return nil
	}
	endpoint.closed = true
	if endpoint.disableReason == "" {
		endpoint.disableReason = "closed"
	}
	endpoint.reconnectRequired = false
	endpoint.reconnectReady = false
	endpoint.reconnectWaiting = false

	connectionIDs := make([]uint64, 0, len(endpoint.connections))
	for connectionID := range endpoint.connections {
		connectionIDs = append(connectionIDs, connectionID)
	}
	sort.Slice(connectionIDs, func(first, second int) bool {
		return connectionIDs[first] < connectionIDs[second]
	})
	connections := make([]*endpointConnection, 0, len(connectionIDs))
	for _, connectionID := range connectionIDs {
		connections = append(connections, endpoint.connections[connectionID])
		delete(endpoint.connections, connectionID)
	}
	endpoint.retiredPhysical = make(
		map[endpointPhysicalKey]tcpEventFields,
	)

	requestIDs := make([]uint64, 0, len(endpoint.requests))
	for requestID := range endpoint.requests {
		requestIDs = append(requestIDs, requestID)
	}
	sort.Slice(requestIDs, func(first, second int) bool {
		return requestIDs[first] < requestIDs[second]
	})
	requests := make([]*endpointRequest, 0, len(requestIDs))
	for _, requestID := range requestIDs {
		requests = append(requests, endpoint.requests[requestID])
		endpoint.removeRequestLocked(requestID)
	}
	retryableIDs := make([]uint64, 0, len(endpoint.retryable))
	for requestID := range endpoint.retryable {
		retryableIDs = append(retryableIDs, requestID)
	}
	sort.Slice(retryableIDs, func(first, second int) bool {
		return retryableIDs[first] < retryableIDs[second]
	})
	retryable := make([]TCPRequestHandle, 0, len(retryableIDs))
	for _, requestID := range retryableIDs {
		retryable = append(retryable, endpoint.retryable[requestID])
		delete(endpoint.retryable, requestID)
	}
	endpoint.mu.Unlock()

	var closeErr error
	for _, handle := range retryable {
		handle.backoff.mu.Lock()
		handle.backoff.lifecycle = tcpRequestTerminal
		handle.backoff.requiresBackoff = false
		handle.backoff.backoffSatisfied = false
		handle.backoff.mu.Unlock()
	}
	for _, request := range requests {
		setTCPRequestLifecycle(request.handle, tcpRequestTerminal)
		closeErr = errors.Join(closeErr, endpoint.failRequest(request))
	}
	for _, connection := range connections {
		closeErr = errors.Join(
			closeErr,
			endpoint.pool.closeConnection(connection.lease),
		)
	}
	endpoint.releaseRemoteClaim()
	return closeErr
}

func (endpoint *TCPEndpoint) releaseRemoteClaim() {
	tcpEndpointClaims.Lock()
	if endpoint.claimedRemote &&
		tcpEndpointClaims.owners[endpoint.remoteEndpoint] == endpoint {
		delete(tcpEndpointClaims.owners, endpoint.remoteEndpoint)
	}
	tcpEndpointClaims.Unlock()
	endpoint.claimedRemote = false
}

func invalidConnectionHandle() error {
	return protocolError(
		ErrorInvalidRequest,
		0,
		0,
		"tcp_connection_handle",
		-1,
	)
}

func (endpoint *TCPEndpoint) connectionLocked(
	handle TCPConnectionHandle,
) (*endpointConnection, bool) {
	if handle.endpoint != endpoint ||
		handle.connectionID == 0 ||
		handle.generation == 0 {
		return nil, false
	}
	connection := endpoint.connections[handle.connectionID]
	if connection == nil ||
		connection.handle.generation != handle.generation ||
		connection.lease.ownerForEndpoint() == nil {
		return nil, false
	}
	return connection, true
}

func (endpoint *TCPEndpoint) removeConnectionRequestsLocked(
	connectionID uint64,
) []*endpointRequest {
	requests := make([]*endpointRequest, 0)
	requestIDs := make([]uint64, 0)
	for requestID, request := range endpoint.requests {
		if request.connectionID != connectionID {
			continue
		}
		requestIDs = append(requestIDs, requestID)
	}
	sort.Slice(requestIDs, func(first, second int) bool {
		return requestIDs[first] < requestIDs[second]
	})
	for _, requestID := range requestIDs {
		request := endpoint.requests[requestID]
		requests = append(requests, request)
		endpoint.removeRequestLocked(requestID)
	}
	return requests
}

// EnqueueRead admits one physical-union candidate under endpoint bounds.
func (endpoint *TCPEndpoint) EnqueueRead(
	plan TCPReadPlan,
) (TCPRequestHandle, error) {
	if endpoint == nil {
		return TCPRequestHandle{}, invalidEndpointConfig()
	}
	if endpoint.eventSinkCallbackActive() {
		return TCPRequestHandle{}, eventSinkReentryError()
	}
	endpoint.enqueueMu.Lock()
	defer endpoint.enqueueMu.Unlock()
	if !endpoint.timelineAvailable() {
		endpoint.disable("event_sequence_exhausted")
		return TCPRequestHandle{}, invalidEndpointConfig()
	}
	now := endpoint.config.Clock.Now()
	endpoint.mu.Lock()
	connection, ok := endpoint.connectionLocked(plan.Connection)
	if !ok ||
		endpoint.closed ||
		plan.UnitID == 0 ||
		plan.UnitID > 247 ||
		plan.AuthorizationScope == "" ||
		plan.PollGeneration == 0 ||
		plan.DeadlineIdentity == 0 ||
		plan.Timeout <= 0 ||
		plan.Timeout > endpoint.config.MaxRequestDeadline ||
		len(plan.Reads) == 0 ||
		now < 0 ||
		plan.Timeout > time.Duration(math.MaxInt64)-now {
		endpoint.mu.Unlock()
		return TCPRequestHandle{}, protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"tcp_read_plan",
			-1,
		)
	}
	if endpoint.nextRequestID == 0 {
		endpoint.mu.Unlock()
		endpoint.disable("request_identity_exhausted")
		return TCPRequestHandle{}, protocolError(
			ErrorInvalidRange,
			0,
			0,
			"request_identity",
			-1,
		)
	}
	requestID := endpoint.nextRequestID
	connectionID := connection.handle.connectionID
	transportGeneration := connection.handle.generation
	endpoint.mu.Unlock()
	deadline := now + plan.Timeout
	handle := TCPRequestHandle{
		endpoint:       endpoint,
		requestID:      requestID,
		deadlineOffset: deadline,
		backoff: &tcpRequestBackoffState{
			lifecycle:          tcpRequestActive,
			unitID:             plan.UnitID,
			authorizationScope: plan.AuthorizationScope,
			pollGeneration:     plan.PollGeneration,
			deadlineIdentity:   plan.DeadlineIdentity,
			reads: append(
				[]TCPLogicalRead(nil),
				plan.Reads...,
			),
		},
	}
	intents := make([]ReadIntent, 0, len(plan.Reads))
	for _, logical := range plan.Reads {
		intent, err := NewReadIntent(ReadIntentSpec{
			LogicalViewID:       logical.LogicalViewID,
			Endpoint:            endpoint.config.Endpoint,
			Transport:           TransportTCP,
			TransportGeneration: transportGeneration,
			UnitID:              plan.UnitID,
			AuthorizationScope:  plan.AuthorizationScope,
			PollGeneration:      plan.PollGeneration,
			DeadlineIdentity:    plan.DeadlineIdentity,
			Request:             logical.Request,
		})
		if err != nil {
			return TCPRequestHandle{}, err
		}
		intents = append(intents, intent)
	}
	eventFields := tcpEventFields{
		ConnectionID:        connectionID,
		TransportGeneration: transportGeneration,
		RequestID:           requestID,
		UnitID:              plan.UnitID,
		AuthorizationScope:  plan.AuthorizationScope,
		PollGeneration:      plan.PollGeneration,
		DeadlineIdentity:    plan.DeadlineIdentity,
		DeadlineOffset:      deadline,
	}
	endpoint.timeline.record(TCPEventEnqueue, eventFields)
	if !endpoint.timelineAvailable() {
		setTCPRequestLifecycle(handle, tcpRequestTerminal)
		endpoint.disable("event_sequence_exhausted")
		return TCPRequestHandle{}, eventSequenceError()
	}
	endpoint.scheduleMu.Lock()
	group, err := endpoint.scheduler.ScheduleCoalesced(
		ScheduledRequest{
			RequestID: requestID,
			Key: AdmissionKey{
				AuthorizationScope: plan.AuthorizationScope,
				UnitID:             plan.UnitID,
			},
			DeadlineOffset: int64(deadline),
		},
		intents,
	)
	if err != nil {
		endpoint.scheduleMu.Unlock()
		eventFields.Detail = "rejected"
		endpoint.timeline.record(TCPEventAdmission, eventFields)
		return TCPRequestHandle{}, err
	}
	if endpoint.afterSchedule != nil {
		endpoint.afterSchedule()
	}
	group.setOperationDeadline(deadline)
	group.setRuntimeAcquisitionSource(endpoint.config.RuntimeAcquisitionSource)
	endpoint.mu.Lock()
	if endpoint.closed {
		endpoint.mu.Unlock()
		_ = group.FailTransport()
		endpoint.scheduleMu.Unlock()
		eventFields.Detail = "closed"
		endpoint.timeline.record(TCPEventAdmission, eventFields)
		return TCPRequestHandle{}, invalidEndpointConfig()
	}
	if _, ok := endpoint.connectionLocked(plan.Connection); !ok {
		endpoint.mu.Unlock()
		_ = group.FailTransport()
		endpoint.scheduleMu.Unlock()
		eventFields.Detail = "stale_connection"
		endpoint.timeline.record(TCPEventAdmission, eventFields)
		return TCPRequestHandle{}, invalidConnectionHandle()
	}
	if endpoint.nextRequestID != requestID {
		endpoint.mu.Unlock()
		_ = group.FailTransport()
		endpoint.scheduleMu.Unlock()
		eventFields.Detail = "request_identity_changed"
		endpoint.timeline.record(TCPEventAdmission, eventFields)
		endpoint.disable("request_identity_invariant")
		return TCPRequestHandle{}, protocolError(
			ErrorInvalidRange,
			0,
			0,
			"request_identity",
			-1,
		)
	}
	endpoint.requests[requestID] = &endpointRequest{
		handle:              handle,
		connectionID:        connectionID,
		transportGeneration: transportGeneration,
		unitID:              plan.UnitID,
		authorizationScope:  plan.AuthorizationScope,
		pollGeneration:      plan.PollGeneration,
		deadlineIdentity:    plan.DeadlineIdentity,
		group:               group,
		operationDeadline:   deadline,
		phase:               endpointRequestQueued,
	}
	endpoint.nextRequestID++
	endpoint.mu.Unlock()
	endpoint.scheduleMu.Unlock()
	endpoint.timeline.recordCoalescing(eventFields, len(plan.Reads))
	eventFields.Detail = "admitted"
	endpoint.timeline.record(TCPEventAdmission, eventFields)
	endpoint.timeline.record(TCPEventRequestTimerArm, eventFields)
	if !endpoint.timelineAvailable() {
		endpoint.disable("event_sequence_exhausted")
		return TCPRequestHandle{}, eventSequenceError()
	}
	return handle, nil
}

// EnqueueDeviceID admits one complete FC2B/MEI0E traversal.
func (endpoint *TCPEndpoint) EnqueueDeviceID(
	plan TCPDeviceIDPlan,
) (TCPRequestHandle, error) {
	if endpoint == nil {
		return TCPRequestHandle{}, invalidEndpointConfig()
	}
	if endpoint.eventSinkCallbackActive() {
		return TCPRequestHandle{}, eventSinkReentryError()
	}
	if err := validateDeviceIDRequest(plan.Request); err != nil {
		return TCPRequestHandle{}, err
	}
	if err := validateDeviceIDLimits(plan.Limits); err != nil {
		return TCPRequestHandle{}, err
	}
	endpoint.enqueueMu.Lock()
	defer endpoint.enqueueMu.Unlock()
	if !endpoint.timelineAvailable() {
		endpoint.disable("event_sequence_exhausted")
		return TCPRequestHandle{}, invalidEndpointConfig()
	}
	now := endpoint.config.Clock.Now()
	endpoint.mu.Lock()
	connection, ok := endpoint.connectionLocked(plan.Connection)
	if !ok ||
		endpoint.closed ||
		plan.UnitID == 0 ||
		plan.UnitID > 247 ||
		plan.AuthorizationScope == "" ||
		plan.PollGeneration == 0 ||
		plan.DeadlineIdentity == 0 ||
		plan.Timeout <= 0 ||
		plan.Timeout > endpoint.config.MaxRequestDeadline ||
		now < 0 ||
		plan.Timeout > time.Duration(math.MaxInt64)-now {
		endpoint.mu.Unlock()
		return TCPRequestHandle{}, protocolError(
			ErrorInvalidRequest,
			FunctionEncapsulatedInterface,
			0,
			"tcp_device_id_plan",
			-1,
		)
	}
	if endpoint.nextRequestID == 0 {
		endpoint.mu.Unlock()
		endpoint.disable("request_identity_exhausted")
		return TCPRequestHandle{}, protocolError(
			ErrorInvalidRange,
			FunctionEncapsulatedInterface,
			0,
			"request_identity",
			-1,
		)
	}
	requestID := endpoint.nextRequestID
	connectionID := connection.handle.connectionID
	transportGeneration := connection.handle.generation
	endpoint.mu.Unlock()

	deadline := now + plan.Timeout
	handle := TCPRequestHandle{
		endpoint:       endpoint,
		requestID:      requestID,
		deadlineOffset: deadline,
		backoff: &tcpRequestBackoffState{
			lifecycle:          tcpRequestActive,
			unitID:             plan.UnitID,
			authorizationScope: plan.AuthorizationScope,
			pollGeneration:     plan.PollGeneration,
			deadlineIdentity:   plan.DeadlineIdentity,
			deviceID:           plan.Request,
			deviceIDLimits:     plan.Limits,
		},
	}
	fields := tcpEventFields{
		ConnectionID:        connectionID,
		TransportGeneration: transportGeneration,
		RequestID:           requestID,
		UnitID:              plan.UnitID,
		AuthorizationScope:  plan.AuthorizationScope,
		PollGeneration:      plan.PollGeneration,
		DeadlineIdentity:    plan.DeadlineIdentity,
		DeadlineOffset:      deadline,
		RequestedFunction:   FunctionEncapsulatedInterface,
	}
	endpoint.timeline.record(TCPEventEnqueue, fields)
	if !endpoint.timelineAvailable() {
		setTCPRequestLifecycle(handle, tcpRequestTerminal)
		endpoint.disable("event_sequence_exhausted")
		return TCPRequestHandle{}, eventSequenceError()
	}
	endpoint.scheduleMu.Lock()
	err := endpoint.scheduler.Enqueue(ScheduledRequest{
		RequestID: requestID,
		Key: AdmissionKey{
			AuthorizationScope: plan.AuthorizationScope,
			UnitID:             plan.UnitID,
		},
		DeadlineOffset: int64(deadline),
	})
	if err != nil {
		endpoint.scheduleMu.Unlock()
		fields.Detail = "rejected"
		endpoint.timeline.record(TCPEventAdmission, fields)
		return TCPRequestHandle{}, err
	}
	endpoint.mu.Lock()
	current, currentOK := endpoint.connectionLocked(plan.Connection)
	if endpoint.closed ||
		!currentOK ||
		current.handle.generation != transportGeneration ||
		endpoint.nextRequestID != requestID {
		endpoint.mu.Unlock()
		_ = endpoint.scheduler.CancelQueued(requestID)
		endpoint.scheduleMu.Unlock()
		fields.Detail = "stale_connection"
		endpoint.timeline.record(TCPEventAdmission, fields)
		return TCPRequestHandle{}, invalidConnectionHandle()
	}
	endpoint.requests[requestID] = &endpointRequest{
		handle:              handle,
		connectionID:        connectionID,
		transportGeneration: transportGeneration,
		unitID:              plan.UnitID,
		authorizationScope:  plan.AuthorizationScope,
		pollGeneration:      plan.PollGeneration,
		deadlineIdentity:    plan.DeadlineIdentity,
		deviceID:            plan.Request,
		deviceIDInitial:     plan.Request,
		deviceIDLimits:      plan.Limits,
		operationDeadline:   deadline,
		phase:               endpointRequestQueued,
	}
	endpoint.nextRequestID++
	endpoint.mu.Unlock()
	endpoint.scheduleMu.Unlock()
	fields.Detail = "admitted"
	endpoint.timeline.record(TCPEventAdmission, fields)
	endpoint.timeline.record(TCPEventRequestTimerArm, fields)
	if !endpoint.timelineAvailable() {
		endpoint.disable("event_sequence_exhausted")
		return TCPRequestHandle{}, eventSequenceError()
	}
	return handle, nil
}

// Dispatch returns the next live fair request as a one-use opaque token.
func (endpoint *TCPEndpoint) Dispatch() (TCPDispatch, bool) {
	if endpoint == nil {
		return TCPDispatch{}, false
	}
	if endpoint.eventSinkCallbackActive() {
		return TCPDispatch{}, false
	}
	if !endpoint.timelineAvailable() {
		endpoint.disable("event_sequence_exhausted")
		return TCPDispatch{}, false
	}
	for {
		endpoint.mu.Lock()
		dispatchIdentityAvailable := endpoint.nextDispatchID != 0
		endpoint.mu.Unlock()
		if !dispatchIdentityAvailable {
			endpoint.disable("dispatch_identity_exhausted")
			return TCPDispatch{}, false
		}
		now := endpoint.config.Clock.Now()
		endpoint.scheduleMu.Lock()
		scheduled, ok := endpoint.scheduler.Dispatch(int64(now))
		expiredFields := endpoint.pruneExpired(now)
		if !ok {
			endpoint.scheduleMu.Unlock()
			endpoint.recordRequestTimerFires(expiredFields)
			if len(expiredFields) > 0 {
				continue
			}
			return TCPDispatch{}, false
		}
		endpoint.mu.Lock()
		request := endpoint.requests[scheduled.RequestID]
		if request == nil ||
			request.phase != endpointRequestQueued ||
			request.operationDeadline <= now {
			if request != nil {
				endpoint.removeRequestLocked(scheduled.RequestID)
			}
			endpoint.mu.Unlock()
			endpoint.scheduleMu.Unlock()
			endpoint.recordRequestTimerFires(expiredFields)
			if request != nil {
				setTCPRequestLifecycle(
					request.handle,
					tcpRequestTerminal,
				)
				_ = endpoint.failRequestSchedulingLocked(request)
			}
			continue
		}
		connection := endpoint.connections[request.connectionID]
		if connection == nil ||
			connection.handle.generation != request.transportGeneration {
			endpoint.removeRequestLocked(scheduled.RequestID)
			endpoint.mu.Unlock()
			endpoint.scheduleMu.Unlock()
			endpoint.recordRequestTimerFires(expiredFields)
			endpoint.setRequestRetryState(
				request.handle,
				tcpRequestRetryable,
				true,
			)
			_ = endpoint.failRequestSchedulingLocked(request)
			continue
		}
		dispatchID := endpoint.nextDispatchID
		endpoint.nextDispatchID++
		request.phase = endpointRequestDispatched
		request.dispatchID = dispatchID
		dispatch := TCPDispatch{
			endpoint:   endpoint,
			dispatchID: dispatchID,
			requestID:  scheduled.RequestID,
		}
		fields := endpoint.requestEventFieldsLocked(request)
		endpoint.mu.Unlock()
		endpoint.scheduleMu.Unlock()
		endpoint.recordRequestTimerFires(expiredFields)
		endpoint.timeline.record(TCPEventQueueService, fields)
		if !endpoint.timelineAvailable() {
			endpoint.disable("event_sequence_exhausted")
			return TCPDispatch{}, false
		}
		return dispatch, true
	}
}

func (endpoint *TCPEndpoint) pruneExpired(
	now time.Duration,
) []tcpEventFields {
	var expired []*endpointRequest
	endpoint.mu.Lock()
	for requestID, request := range endpoint.requests {
		if (request.phase != endpointRequestQueued &&
			request.phase != endpointRequestDispatched) ||
			request.operationDeadline > now {
			continue
		}
		expired = append(expired, request)
		endpoint.removeRequestLocked(requestID)
	}
	endpoint.mu.Unlock()
	sort.Slice(expired, func(first, second int) bool {
		if expired[first].handle.deadlineOffset !=
			expired[second].handle.deadlineOffset {
			return expired[first].handle.deadlineOffset <
				expired[second].handle.deadlineOffset
		}
		return expired[first].handle.requestID <
			expired[second].handle.requestID
	})
	fields := make([]tcpEventFields, 0, len(expired))
	for _, request := range expired {
		setTCPRequestLifecycle(request.handle, tcpRequestTerminal)
		_ = endpoint.failRequestSchedulingLocked(request)
		fields = append(fields, endpoint.requestEventFields(request))
	}
	return fields
}

func (endpoint *TCPEndpoint) recordRequestTimerFires(
	fields []tcpEventFields,
) {
	for _, eventFields := range fields {
		endpoint.timeline.record(TCPEventRequestTimerFire, eventFields)
	}
}

// Write crosses the transport invocation boundary for one dispatch token.
func (endpoint *TCPEndpoint) Write(
	ctx context.Context,
	dispatch TCPDispatch,
) (OwnerTransition, error) {
	if endpoint == nil || ctx == nil {
		return OwnerTransition{}, invalidEndpointConfig()
	}
	if endpoint.eventSinkCallbackActive() {
		return OwnerTransition{}, eventSinkReentryError()
	}
	if !endpoint.timelineAvailable() {
		endpoint.disable("event_sequence_exhausted")
		return OwnerTransition{}, invalidEndpointConfig()
	}
	endpoint.mu.Lock()
	request, connection, ok := endpoint.dispatchLocked(dispatch)
	if !ok {
		endpoint.mu.Unlock()
		return OwnerTransition{}, protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"tcp_dispatch",
			-1,
		)
	}
	writeContext, writeCancel := context.WithCancel(ctx)
	writeDone := make(chan struct{})
	request.phase = endpointRequestWriting
	request.writeCancel = writeCancel
	request.writeDone = writeDone
	endpoint.mu.Unlock()
	defer func() {
		writeCancel()
		close(writeDone)
	}()
	owner := connection.lease.ownerForEndpoint()
	if owner == nil {
		_ = endpoint.failRequest(request)
		endpoint.finishRequestRetryable(
			request.handle.requestID,
			true,
		)
		return OwnerTransition{}, invalidConnectionHandle()
	}
	var reservation TCPReservation
	var err error
	if request.isDeviceID() {
		reservation, err = owner.reserveDeviceIDUntil(
			request.unitID,
			request.deviceID,
			request.operationDeadline,
		)
	} else {
		reservation, err = owner.reserveReadUntil(
			request.unitID,
			request.group.PhysicalRequest(),
			request.operationDeadline,
		)
	}
	if err != nil {
		_ = endpoint.failRequest(request)
		if owner.Closed() {
			transition, closeErr := connection.transport.closeTerminal()
			endpoint.finishRequestRetryable(
				request.handle.requestID,
				true,
			)
			endpoint.dropConnection(request.connectionID)
			return transition, errors.Join(err, closeErr)
		}
		endpoint.finishRequestRetryable(
			request.handle.requestID,
			false,
		)
		return OwnerTransition{}, err
	}
	if !request.isDeviceID() {
		if err := request.group.BindReservation(reservation); err != nil {
			_ = owner.CancelBeforeWrite(reservation)
			_ = endpoint.failRequest(request)
			endpoint.finishRequestRetryable(
				request.handle.requestID,
				false,
			)
			return OwnerTransition{}, err
		}
	}
	endpoint.mu.Lock()
	current := endpoint.requests[request.handle.requestID]
	if current != request {
		endpoint.mu.Unlock()
		_ = owner.CancelBeforeWrite(reservation)
		_ = endpoint.failRequest(request)
		return OwnerTransition{}, protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"tcp_request_state",
			-1,
		)
	}
	request.physicalRequestID = reservation.PhysicalRequestID()
	request.transactionID = reservation.TransactionID()
	endpoint.physical[endpointPhysicalKey{
		connectionID:      request.connectionID,
		physicalRequestID: request.physicalRequestID,
	}] = request.handle.requestID
	writeFields := endpoint.requestEventFieldsLocked(request)
	endpoint.mu.Unlock()
	var transition OwnerTransition
	if request.isDeviceID() {
		transition, err = connection.transport.writeReservationUntil(
			writeContext,
			reservation,
			request.operationDeadline,
			request.handle.requestID,
		)
	} else {
		transition, err = connection.transport.writeCoalescedUntil(
			writeContext,
			request.group,
			request.operationDeadline,
			writeFields,
		)
	}
	if !endpoint.timelineAvailable() {
		endpoint.disable("event_sequence_exhausted")
		return transition, errors.Join(err, eventSequenceError())
	}
	if endpoint.afterWrite != nil {
		endpoint.afterWrite()
	}
	endpoint.mu.Lock()
	current = endpoint.requests[request.handle.requestID]
	if current != request {
		endpoint.mu.Unlock()
		if transition.CloseConnection() {
			endpoint.setRequestRetryState(
				request.handle,
				tcpRequestTerminal,
				true,
			)
			endpoint.dropConnection(request.connectionID)
		}
		return transition, err
	}
	if err != nil {
		abandonedAfterWrite := fullTransmitAbandonment(err)
		abandonmentFields := endpoint.requestEventFieldsLocked(request)
		if abandonedAfterWrite && request.physicalRequestID != 0 {
			endpoint.retiredPhysical[endpointPhysicalKey{
				connectionID:      request.connectionID,
				physicalRequestID: request.physicalRequestID,
			}] = abandonmentFields
		}
		endpoint.removeRequestLocked(request.handle.requestID)
		endpoint.mu.Unlock()
		err = errors.Join(err, endpoint.failRequest(request))
		if retryableTransportFailure(err) &&
			endpoint.config.Clock.Now() < request.operationDeadline {
			endpoint.setRequestRetryState(
				request.handle,
				tcpRequestRetryable,
				transition.CloseConnection(),
			)
		} else {
			endpoint.setRequestRetryState(
				request.handle,
				tcpRequestTerminal,
				transition.CloseConnection(),
			)
		}
		if abandonedAfterWrite {
			abandonmentFields.Detail = "tcp_response_wait_tombstone"
			endpoint.timeline.record(
				TCPEventQuarantineTransition,
				abandonmentFields,
			)
		}
		if transition.CloseConnection() {
			endpoint.dropConnection(request.connectionID)
		}
		return transition, err
	}
	responseDeadline, ok := owner.responseDeadline(reservation)
	if !ok {
		endpoint.removeRequestLocked(request.handle.requestID)
		endpoint.mu.Unlock()
		_ = endpoint.failRequest(request)
		closeTransition, closeErr := connection.transport.closeTerminal()
		transition = mergeOwnerTransitions(transition, closeTransition)
		endpoint.dropConnection(request.connectionID)
		return transition, errors.Join(protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"response_deadline",
			-1,
		), closeErr)
	}
	request.responseDeadline = responseDeadline
	request.phase = endpointRequestWaiting
	request.writeCancel = nil
	endpoint.mu.Unlock()
	connection.transport.requestEarlierReadDeadline(responseDeadline)
	return transition, nil
}

func retryableTransportFailure(err error) bool {
	if err == nil ||
		errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var writeErr *TransportWriteError
	return errors.As(err, &writeErr) &&
		writeErr.Result != TransmitComplete
}

func fullTransmitAbandonment(err error) bool {
	if err == nil {
		return false
	}
	var writeErr *TransportWriteError
	if !errors.As(err, &writeErr) ||
		(writeErr.Result != TransmitComplete &&
			writeErr.Result != TransmitCancellationRace) {
		return false
	}
	if errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var protocolErr *ProtocolError
	return errors.As(err, &protocolErr) &&
		protocolErr.Field == "operation_deadline"
}

func (endpoint *TCPEndpoint) markReconnectRequired() {
	if endpoint == nil {
		return
	}
	endpoint.mu.Lock()
	if !endpoint.closed {
		endpoint.reconnectRequired = true
		endpoint.reconnectReady = false
	}
	endpoint.mu.Unlock()
}

func (endpoint *TCPEndpoint) dispatchLocked(
	dispatch TCPDispatch,
) (*endpointRequest, *endpointConnection, bool) {
	if dispatch.endpoint != endpoint ||
		dispatch.dispatchID == 0 ||
		dispatch.requestID == 0 {
		return nil, nil, false
	}
	request := endpoint.requests[dispatch.requestID]
	if request == nil ||
		request.phase != endpointRequestDispatched ||
		request.dispatchID != dispatch.dispatchID {
		return nil, nil, false
	}
	connection := endpoint.connections[request.connectionID]
	if connection == nil ||
		connection.handle.generation != request.transportGeneration {
		return nil, nil, false
	}
	return request, connection, true
}

func deviceIDSegmentsWithinLimits(
	segments []DeviceIDSegment,
	limits DeviceIDLimits,
) bool {
	if len(segments) == 0 || len(segments) > limits.MaxSegments {
		return false
	}
	objects := 0
	valueBytes := 0
	for _, segment := range segments {
		for _, object := range segment.Objects() {
			objects++
			if objects > limits.MaxObjects ||
				len(object.Value) > limits.MaxValueBytes-valueBytes {
				return false
			}
			valueBytes += len(object.Value)
		}
	}
	return true
}

func (endpoint *TCPEndpoint) requeueDeviceIDContinuation(
	request *endpointRequest,
	next DeviceIDRequest,
) error {
	endpoint.scheduleMu.Lock()
	defer endpoint.scheduleMu.Unlock()
	if err := endpoint.scheduler.Complete(
		request.handle.requestID,
	); err != nil {
		return err
	}
	if err := endpoint.scheduler.Enqueue(ScheduledRequest{
		RequestID: request.handle.requestID,
		Key: AdmissionKey{
			AuthorizationScope: request.authorizationScope,
			UnitID:             request.unitID,
		},
		DeadlineOffset: int64(request.operationDeadline),
	}); err != nil {
		return err
	}
	endpoint.mu.Lock()
	if endpoint.requests[request.handle.requestID] != request ||
		endpoint.connections[request.connectionID] == nil {
		endpoint.mu.Unlock()
		endpoint.scheduler.CancelQueued(request.handle.requestID)
		return context.Canceled
	}
	delete(endpoint.physical, endpointPhysicalKey{
		connectionID:      request.connectionID,
		physicalRequestID: request.physicalRequestID,
	})
	request.deviceID = next
	request.phase = endpointRequestQueued
	request.dispatchID = 0
	request.physicalRequestID = 0
	request.transactionID = 0
	request.responseDeadline = 0
	endpoint.mu.Unlock()
	return nil
}

func (endpoint *TCPEndpoint) acceptDeviceIDResponse(
	request *endpointRequest,
	response WireResponse,
) (*TCPDeviceIDCompletion, bool, error) {
	endpoint.mu.Lock()
	current := endpoint.requests[request.handle.requestID]
	endpoint.mu.Unlock()
	if current != request {
		return nil, false, context.Canceled
	}
	segment, ok := response.DeviceIDSegment()
	if !ok {
		return nil, false, protocolError(
			ErrorInvalidRequest,
			FunctionEncapsulatedInterface,
			0,
			"device_id_segment",
			-1,
		)
	}
	request.deviceIDSegments = append(
		request.deviceIDSegments,
		segment,
	)
	if !deviceIDSegmentsWithinLimits(
		request.deviceIDSegments,
		request.deviceIDLimits,
	) {
		return nil, false, protocolError(
			ErrorInvalidRange,
			FunctionEncapsulatedInterface,
			0,
			"aggregate_limit",
			-1,
		)
	}
	if segment.MoreFollows() {
		next, err := NextDeviceIDRequest(segment)
		if err != nil {
			return nil, false, err
		}
		if err := endpoint.requeueDeviceIDContinuation(
			request,
			next,
		); err != nil {
			return nil, false, err
		}
		return nil, true, nil
	}

	var result DeviceIDResult
	var err error
	if request.deviceIDInitial.Access() == DeviceIDIndividual {
		result = DeviceIDResult{
			Conformity: segment.Conformity(),
			Objects:    segment.Objects(),
			Segments:   append([]DeviceIDSegment(nil), segment),
		}
	} else {
		result, err = AggregateDeviceID(
			request.deviceIDInitial,
			request.deviceIDSegments,
			request.deviceIDLimits,
		)
	}
	if err != nil {
		return nil, false, err
	}
	if err := endpoint.failRequest(request); err != nil {
		return nil, false, err
	}
	return &TCPDeviceIDCompletion{
		RequestID: request.handle.requestID,
		Result:    result,
	}, false, nil
}

// Read consumes one socket chunk, correlates frames, and replays exact views.
func (endpoint *TCPEndpoint) Read(
	ctx context.Context,
	handle TCPConnectionHandle,
) (TCPReadBatch, error) {
	if endpoint == nil || ctx == nil {
		return TCPReadBatch{}, invalidEndpointConfig()
	}
	if endpoint.eventSinkCallbackActive() {
		return TCPReadBatch{}, eventSinkReentryError()
	}
	if !endpoint.timelineAvailable() {
		endpoint.disable("event_sequence_exhausted")
		return TCPReadBatch{}, invalidEndpointConfig()
	}
	endpoint.mu.Lock()
	connection, ok := endpoint.connectionLocked(handle)
	if !ok {
		endpoint.mu.Unlock()
		return TCPReadBatch{}, invalidConnectionHandle()
	}
	owner := connection.lease.ownerForEndpoint()
	now := endpoint.config.Clock.Now()
	endpoint.mu.Unlock()
	abandonedBeforeRead, preTransition, preErr :=
		owner.abandonExpired(now)
	var expirationErr error
	for _, reservation := range abandonedBeforeRead {
		if request := endpoint.requestForPhysical(
			handle.connectionID,
			reservation.PhysicalRequestID(),
		); request != nil {
			endpoint.timeline.record(
				TCPEventResponseTimerFire,
				endpoint.requestEventFields(request),
			)
		}
		expirationErr = errors.Join(
			expirationErr,
			endpoint.failPhysical(
				handle.connectionID,
				reservation.PhysicalRequestID(),
				TCPEventQuarantineTransition,
			),
		)
	}
	if preTransition.CloseConnection() {
		_, closeErr := connection.transport.closeTerminal()
		endpoint.dropConnection(handle.connectionID)
		return TCPReadBatch{}, errors.Join(
			preErr,
			expirationErr,
			closeErr,
		)
	}
	endpoint.mu.Lock()
	deadline, ok := endpoint.earliestWaitingDeadlineLocked(
		handle.connectionID,
	)
	endpoint.mu.Unlock()
	if !ok {
		if owner.hasTombstones() {
			if endpoint.config.MaxResponseDeadline >
				time.Duration(math.MaxInt64)-now {
				return TCPReadBatch{}, protocolError(
					ErrorInvalidRange,
					0,
					0,
					"operation_deadline",
					-1,
				)
			}
			deadline = now + endpoint.config.MaxResponseDeadline
		} else if len(abandonedBeforeRead) > 0 {
			return TCPReadBatch{}, errors.Join(
				context.DeadlineExceeded,
				preErr,
				expirationErr,
			)
		} else {
			return TCPReadBatch{}, protocolError(
				ErrorInvalidRequest,
				0,
				0,
				"response_wait",
				-1,
			)
		}
	}
	var responses []WireResponse
	var transition OwnerTransition
	var abandoned []TCPReservation
	var readErr error
	var rearmErr error
	for {
		currentResponses, currentTransition, currentAbandoned, currentErr :=
			connection.transport.readResponsesUntil(ctx, deadline)
		responses = append(responses, currentResponses...)
		transition = mergeOwnerTransitions(transition, currentTransition)
		if !errors.Is(currentErr, errReadDeadlineRearmed) {
			abandoned = append(abandoned, currentAbandoned...)
			readErr = errors.Join(rearmErr, currentErr)
			break
		}
		for _, reservation := range currentAbandoned {
			rearmErr = errors.Join(
				rearmErr,
				endpoint.failPhysical(
					handle.connectionID,
					reservation.PhysicalRequestID(),
					TCPEventQuarantineTransition,
				),
			)
		}
		if len(currentAbandoned) > 0 {
			readErr = errors.Join(rearmErr, context.DeadlineExceeded)
			break
		}
		endpoint.mu.Lock()
		deadline, ok = endpoint.earliestWaitingDeadlineLocked(
			handle.connectionID,
		)
		endpoint.mu.Unlock()
		if !ok {
			now = endpoint.config.Clock.Now()
			if owner.hasTombstones() &&
				endpoint.config.MaxResponseDeadline <=
					time.Duration(math.MaxInt64)-now {
				deadline = now + endpoint.config.MaxResponseDeadline
				continue
			}
			readErr = errors.Join(rearmErr, context.DeadlineExceeded)
			break
		}
	}
	if !endpoint.timelineAvailable() {
		endpoint.disable("event_sequence_exhausted")
		return TCPReadBatch{}, errors.Join(readErr, eventSequenceError())
	}
	batch := TCPReadBatch{
		Responses: append([]WireResponse(nil), responses...),
	}
	var replayErr error
	for _, reservation := range abandoned {
		replayErr = errors.Join(
			replayErr,
			endpoint.failPhysical(
				handle.connectionID,
				reservation.PhysicalRequestID(),
				TCPEventQuarantineTransition,
			),
		)
	}
	for _, response := range responses {
		provenance := response.Provenance()
		diagnostic := response.DiagnosticProvenance()
		unitID := provenance.UnitID
		receivedFunction := provenance.ReceivedFunction
		if response.DiagnosticFrameID() != 0 {
			unitID = diagnostic.UnitID
			receivedFunction = diagnostic.ReceivedFunction
		}
		request := endpoint.requestForPhysical(
			handle.connectionID,
			response.PhysicalRequestID(),
		)
		retiredResponse := false
		fields := tcpEventFields{
			ConnectionID:        handle.connectionID,
			TransportGeneration: handle.generation,
			PhysicalRequestID:   response.PhysicalRequestID(),
			UnitID:              unitID,
			WireResponseID:      response.WireResponseID(),
			DiagnosticFrameID:   response.DiagnosticFrameID(),
			RequestedFunction:   provenance.RequestedFunction,
			ReceivedFunction:    receivedFunction,
			LogicalTable:        provenance.Table,
			PhysicalOffset:      provenance.Offset,
			PhysicalQuantity:    provenance.Quantity,
			RawADUHex:           hex.EncodeToString(response.Bytes()),
			WireOutcome:         response.Outcome(),
		}
		if request != nil {
			requestFields := endpoint.requestEventFields(request)
			requestFields.WireResponseID = response.WireResponseID()
			requestFields.DiagnosticFrameID =
				response.DiagnosticFrameID()
			requestFields.ReceivedFunction =
				provenance.ReceivedFunction
			requestFields.RawADUHex =
				hex.EncodeToString(response.Bytes())
			requestFields.WireOutcome = response.Outcome()
			fields = requestFields
		} else if retiredFields, retired := endpoint.takeRetiredPhysicalFields(
			handle.connectionID,
			response.PhysicalRequestID(),
		); retired {
			retiredResponse = true
			retiredFields.WireResponseID = response.WireResponseID()
			retiredFields.DiagnosticFrameID = response.DiagnosticFrameID()
			retiredFields.ReceivedFunction =
				provenance.ReceivedFunction
			retiredFields.RawADUHex =
				hex.EncodeToString(response.Bytes())
			retiredFields.WireOutcome = response.Outcome()
			fields = retiredFields
		}
		if endpoint.beforeOutcome != nil {
			endpoint.beforeOutcome()
		}
		endpoint.outcomeMu.Lock()
		endpoint.timeline.record(TCPEventResponseReceive, fields)
		if !endpoint.timelineAvailable() {
			endpoint.outcomeMu.Unlock()
			endpoint.disable("event_sequence_exhausted")
			return batch, errors.Join(
				preErr,
				expirationErr,
				readErr,
				replayErr,
				eventSequenceError(),
			)
		}
		if response.WireResponseID() != 0 &&
			(response.Outcome() == WireSuccessfulData ||
				response.Outcome() == WireProtocolException) {
			endpoint.backoff.ValidCorrelatedResponse()
		}
		if request == nil {
			if response.Deliverable() && !retiredResponse {
				replayErr = errors.Join(
					replayErr,
					protocolError(
						ErrorInvalidRequest,
						0,
						0,
						"endpoint_response_identity",
						-1,
					),
				)
			}
			endpoint.outcomeMu.Unlock()
			continue
		}
		switch response.Outcome() {
		case WireSuccessfulData:
			if !response.Deliverable() {
				endpoint.outcomeMu.Unlock()
				continue
			}
			if request.isDeviceID() {
				completion, continued, err :=
					endpoint.acceptDeviceIDResponse(request, response)
				replayErr = errors.Join(replayErr, err)
				if err != nil {
					replayErr = errors.Join(
						replayErr,
						endpoint.failRequest(request),
					)
				}
				if continued {
					endpoint.outcomeMu.Unlock()
					continue
				}
				if completion != nil {
					batch.DeviceIDs = append(
						batch.DeviceIDs,
						*completion,
					)
				}
			} else {
				views, err :=
					request.group.ReplaySuccessfulResponse(response)
				batch.Views = append(batch.Views, views...)
				replayErr = errors.Join(replayErr, err)
			}
		case WireProtocolException, WireMalformedResponse:
			if request.isDeviceID() {
				replayErr = errors.Join(
					replayErr,
					endpoint.failRequest(request),
				)
			} else {
				replayErr = errors.Join(
					replayErr,
					request.group.Fail(response),
				)
			}
		}
		endpoint.finishRequest(request.handle.requestID)
		endpoint.outcomeMu.Unlock()
	}
	if transition.CloseConnection() {
		endpoint.dropConnection(handle.connectionID)
	}
	return batch, errors.Join(preErr, expirationErr, readErr, replayErr)
}

func (endpoint *TCPEndpoint) earliestWaitingDeadlineLocked(
	connectionID uint64,
) (time.Duration, bool) {
	var earliest time.Duration
	for _, request := range endpoint.requests {
		if request.connectionID != connectionID ||
			(request.phase != endpointRequestWaiting &&
				request.phase != endpointRequestWriting) {
			continue
		}
		deadline := request.responseDeadline
		if deadline <= 0 {
			deadline = request.handle.deadlineOffset
		}
		if earliest == 0 || deadline < earliest {
			earliest = deadline
		}
	}
	return earliest, earliest > 0
}

func (endpoint *TCPEndpoint) takeRetiredPhysicalFields(
	connectionID uint64,
	physicalRequestID uint64,
) (tcpEventFields, bool) {
	endpoint.mu.Lock()
	defer endpoint.mu.Unlock()
	key := endpointPhysicalKey{
		connectionID:      connectionID,
		physicalRequestID: physicalRequestID,
	}
	fields, ok := endpoint.retiredPhysical[key]
	if ok {
		delete(endpoint.retiredPhysical, key)
	}
	return fields, ok
}

func (endpoint *TCPEndpoint) requestForPhysical(
	connectionID uint64,
	physicalRequestID uint64,
) *endpointRequest {
	endpoint.mu.Lock()
	defer endpoint.mu.Unlock()
	requestID := endpoint.physical[endpointPhysicalKey{
		connectionID:      connectionID,
		physicalRequestID: physicalRequestID,
	}]
	return endpoint.requests[requestID]
}

func (endpoint *TCPEndpoint) failPhysical(
	connectionID uint64,
	physicalRequestID uint64,
	kind TCPTransportEventKind,
) error {
	endpoint.mu.Lock()
	key := endpointPhysicalKey{
		connectionID:      connectionID,
		physicalRequestID: physicalRequestID,
	}
	requestID := endpoint.physical[key]
	request := endpoint.requests[requestID]
	if request != nil {
		endpoint.removeRequestLocked(requestID)
	}
	endpoint.mu.Unlock()
	if request == nil {
		return nil
	}
	setTCPRequestLifecycle(request.handle, tcpRequestTerminal)
	fields := endpoint.requestEventFields(request)
	endpoint.mu.Lock()
	endpoint.retiredPhysical[endpointPhysicalKey{
		connectionID:      connectionID,
		physicalRequestID: physicalRequestID,
	}] = fields
	endpoint.mu.Unlock()
	if kind == TCPEventQuarantineTransition {
		fields.Detail = "tcp_response_wait_tombstone"
	}
	endpoint.timeline.record(kind, fields)
	return endpoint.failRequest(request)
}

func (endpoint *TCPEndpoint) finishRequest(requestID uint64) {
	endpoint.mu.Lock()
	request := endpoint.requests[requestID]
	endpoint.removeRequestLocked(requestID)
	endpoint.mu.Unlock()
	if request != nil {
		setTCPRequestLifecycle(request.handle, tcpRequestTerminal)
	}
}

func (endpoint *TCPEndpoint) finishRequestRetryable(
	requestID uint64,
	requiresBackoff bool,
) {
	endpoint.mu.Lock()
	request := endpoint.requests[requestID]
	endpoint.removeRequestLocked(requestID)
	endpoint.mu.Unlock()
	if request == nil {
		return
	}
	lifecycle := tcpRequestRetryable
	if endpoint.config.Clock.Now() >= request.operationDeadline {
		lifecycle = tcpRequestTerminal
	}
	endpoint.setRequestRetryState(
		request.handle,
		lifecycle,
		requiresBackoff,
	)
}

func setTCPRequestLifecycle(
	handle TCPRequestHandle,
	lifecycle tcpRequestLifecycle,
) {
	if handle.backoff == nil {
		return
	}
	handle.backoff.mu.Lock()
	handle.backoff.lifecycle = lifecycle
	handle.backoff.mu.Unlock()
}

func (endpoint *TCPEndpoint) setRequestRetryState(
	handle TCPRequestHandle,
	lifecycle tcpRequestLifecycle,
	requiresBackoff bool,
) {
	if handle.backoff == nil {
		return
	}
	handle.backoff.mu.Lock()
	handle.backoff.lifecycle = lifecycle
	handle.backoff.requiresBackoff = requiresBackoff
	handle.backoff.backoffSatisfied = false
	handle.backoff.mu.Unlock()
	if lifecycle == tcpRequestRetryable && requiresBackoff {
		endpoint.mu.Lock()
		endpoint.reconnectRequired = true
		endpoint.reconnectReady = false
		endpoint.mu.Unlock()
	}
	endpoint.trackRetryableState(handle, lifecycle)
}

func (endpoint *TCPEndpoint) trackRetryableState(
	handle TCPRequestHandle,
	lifecycle tcpRequestLifecycle,
) {
	if endpoint == nil || handle.backoff == nil || handle.requestID == 0 {
		return
	}
	if lifecycle == tcpRequestRetryable {
		endpoint.pruneRetryable(endpoint.config.Clock.Now())
	}
	handle.backoff.mu.Lock()
	incomingRequiresBackoff := handle.backoff.requiresBackoff
	handle.backoff.mu.Unlock()
	endpoint.mu.Lock()
	closed := endpoint.closed
	overflow := false
	var evicted TCPRequestHandle
	retain := lifecycle == tcpRequestRetryable ||
		lifecycle == tcpRequestRetrying ||
		(lifecycle == tcpRequestTerminal && incomingRequiresBackoff)
	if retain && !closed {
		if _, exists := endpoint.retryable[handle.requestID]; exists ||
			len(endpoint.retryable) <
				endpoint.config.SchedulerLimits.MaxInFlightRequests {
			endpoint.retryable[handle.requestID] = handle
		} else if incomingRequiresBackoff {
			var evictID uint64
			for requestID, candidate := range endpoint.retryable {
				candidate.backoff.mu.Lock()
				safe := !candidate.backoff.requiresBackoff
				candidate.backoff.mu.Unlock()
				if safe && (evictID == 0 || requestID < evictID) {
					evictID = requestID
				}
			}
			if evictID != 0 {
				evicted = endpoint.retryable[evictID]
				delete(endpoint.retryable, evictID)
				endpoint.retryable[handle.requestID] = handle
			} else {
				overflow = true
			}
		} else {
			overflow = true
		}
	} else {
		delete(endpoint.retryable, handle.requestID)
	}
	endpoint.mu.Unlock()
	if evicted.backoff != nil {
		evicted.backoff.mu.Lock()
		evicted.backoff.lifecycle = tcpRequestTerminal
		evicted.backoff.requiresBackoff = false
		evicted.backoff.backoffSatisfied = false
		evicted.backoff.mu.Unlock()
	}
	if (closed || overflow) && retain {
		handle.backoff.mu.Lock()
		handle.backoff.lifecycle = tcpRequestTerminal
		handle.backoff.requiresBackoff = false
		handle.backoff.backoffSatisfied = false
		handle.backoff.mu.Unlock()
	}
}

func (endpoint *TCPEndpoint) pruneRetryable(now time.Duration) {
	if endpoint == nil || now < 0 {
		return
	}
	endpoint.mu.Lock()
	handles := make([]TCPRequestHandle, 0, len(endpoint.retryable))
	for _, handle := range endpoint.retryable {
		handles = append(handles, handle)
	}
	endpoint.mu.Unlock()
	sort.Slice(handles, func(first, second int) bool {
		return handles[first].requestID < handles[second].requestID
	})
	for _, handle := range handles {
		handle.backoff.mu.Lock()
		effectiveDeadline, valid := effectiveRequestDeadlineLocked(handle)
		expired := handle.backoff.lifecycle == tcpRequestRetryable &&
			(!valid || now >= effectiveDeadline)
		if expired {
			handle.backoff.lifecycle = tcpRequestTerminal
			handle.backoff.backoffSatisfied = false
		}
		terminal := handle.backoff.lifecycle == tcpRequestTerminal &&
			!handle.backoff.requiresBackoff
		handle.backoff.mu.Unlock()
		if terminal {
			endpoint.mu.Lock()
			current, exists := endpoint.retryable[handle.requestID]
			if exists && current.backoff == handle.backoff {
				delete(endpoint.retryable, handle.requestID)
			}
			endpoint.mu.Unlock()
		}
	}
}

func (endpoint *TCPEndpoint) terminalizeRetryable(
	handle TCPRequestHandle,
) {
	if endpoint == nil || handle.backoff == nil {
		return
	}
	handle.backoff.mu.Lock()
	requiresBackoff := handle.backoff.requiresBackoff
	handle.backoff.lifecycle = tcpRequestTerminal
	handle.backoff.backoffSatisfied = false
	handle.backoff.mu.Unlock()
	if !requiresBackoff {
		handle.backoff.mu.Lock()
		handle.backoff.requiresBackoff = false
		handle.backoff.mu.Unlock()
	}
	endpoint.trackRetryableState(handle, tcpRequestTerminal)
}

func (endpoint *TCPEndpoint) removeRequestLocked(requestID uint64) {
	request := endpoint.requests[requestID]
	if request == nil {
		return
	}
	delete(endpoint.requests, requestID)
	endpoint.timeline.forgetEnqueue(requestID)
	if request.physicalRequestID != 0 {
		delete(endpoint.physical, endpointPhysicalKey{
			connectionID:      request.connectionID,
			physicalRequestID: request.physicalRequestID,
		})
	}
}

func (endpoint *TCPEndpoint) dropConnection(connectionID uint64) {
	endpoint.mu.Lock()
	delete(endpoint.connections, connectionID)
	for key := range endpoint.retiredPhysical {
		if key.connectionID == connectionID {
			delete(endpoint.retiredPhysical, key)
		}
	}
	requests := endpoint.removeConnectionRequestsLocked(connectionID)
	endpoint.mu.Unlock()
	now := endpoint.config.Clock.Now()
	for _, request := range requests {
		lifecycle := tcpRequestRetryable
		if now >= request.operationDeadline {
			lifecycle = tcpRequestTerminal
		}
		endpoint.setRequestRetryState(
			request.handle,
			lifecycle,
			lifecycle == tcpRequestRetryable,
		)
		_ = endpoint.failRequest(request)
	}
}

// CancelLogical terminalizes one coalesced dependent without affecting peers.
func (endpoint *TCPEndpoint) CancelLogical(
	handle TCPRequestHandle,
	logicalViewID uint64,
) (CoalescedTransition, error) {
	if endpoint == nil ||
		handle.endpoint != endpoint ||
		handle.requestID == 0 ||
		handle.backoff == nil ||
		logicalViewID == 0 {
		return CoalescedTransition{}, protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"tcp_request_handle",
			-1,
		)
	}
	if endpoint.eventSinkCallbackActive() {
		return CoalescedTransition{}, eventSinkReentryError()
	}
	if !endpoint.timelineAvailable() {
		endpoint.disable("event_sequence_exhausted")
		return CoalescedTransition{}, invalidEndpointConfig()
	}
	endpoint.mu.Lock()
	request := endpoint.requests[handle.requestID]
	retryable, retained := endpoint.retryable[handle.requestID]
	if request == nil && retained &&
		retryable.backoff == handle.backoff &&
		retryable.deadlineOffset == handle.deadlineOffset {
		handle.backoff.mu.Lock()
		if handle.backoff.lifecycle != tcpRequestRetryable &&
			handle.backoff.lifecycle != tcpRequestRetrying {
			handle.backoff.mu.Unlock()
			endpoint.mu.Unlock()
			return CoalescedTransition{}, protocolError(
				ErrorInvalidRequest,
				0,
				0,
				"tcp_request_lifecycle",
				-1,
			)
		}
		index := -1
		for candidate, logical := range handle.backoff.reads {
			if logical.LogicalViewID == logicalViewID {
				index = candidate
				break
			}
		}
		if index < 0 {
			handle.backoff.mu.Unlock()
			endpoint.mu.Unlock()
			return CoalescedTransition{}, protocolError(
				ErrorInvalidRequest,
				0,
				0,
				"logical_view_id",
				-1,
			)
		}
		fields := endpoint.retryableEventFieldsLocked(handle)
		fields.LogicalViewID = logicalViewID
		handle.backoff.reads = append(
			handle.backoff.reads[:index],
			handle.backoff.reads[index+1:]...,
		)
		terminal := len(handle.backoff.reads) == 0
		if terminal {
			handle.backoff.lifecycle = tcpRequestTerminal
			handle.backoff.backoffSatisfied = false
		} else if handle.backoff.lifecycle == tcpRequestRetrying {
			handle.backoff.lifecycle = tcpRequestRetryable
		}
		requiresBackoff := handle.backoff.requiresBackoff
		handle.backoff.mu.Unlock()
		if terminal && !requiresBackoff {
			delete(endpoint.retryable, handle.requestID)
		}
		endpoint.mu.Unlock()
		endpoint.timeline.record(TCPEventCallerCancellation, fields)
		if !endpoint.timelineAvailable() {
			endpoint.disable("event_sequence_exhausted")
			return CoalescedTransition{}, eventSequenceError()
		}
		return CoalescedTransition{}, nil
	}
	if request == nil || request.handle.deadlineOffset != handle.deadlineOffset {
		endpoint.mu.Unlock()
		return CoalescedTransition{}, protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"tcp_request_handle",
			-1,
		)
	}
	if request.isDeviceID() {
		endpoint.mu.Unlock()
		return CoalescedTransition{}, protocolError(
			ErrorInvalidRequest,
			FunctionEncapsulatedInterface,
			0,
			"logical_view_id",
			-1,
		)
	}
	fields := endpoint.requestEventFieldsLocked(request)
	endpoint.mu.Unlock()
	fields.LogicalViewID = logicalViewID
	endpoint.outcomeMu.Lock()
	transition, err := request.group.Cancel(logicalViewID)
	if err != nil {
		endpoint.outcomeMu.Unlock()
		return transition, err
	}
	endpoint.timeline.record(TCPEventCallerCancellation, fields)
	endpoint.outcomeMu.Unlock()
	if !endpoint.timelineAvailable() {
		endpoint.disable("event_sequence_exhausted")
		return CoalescedTransition{}, eventSequenceError()
	}
	handle.backoff.mu.Lock()
	activeReads := handle.backoff.reads[:0]
	for _, logical := range handle.backoff.reads {
		if logical.LogicalViewID != logicalViewID {
			activeReads = append(activeReads, logical)
		}
	}
	handle.backoff.reads = activeReads
	handle.backoff.mu.Unlock()
	if transition.AbandonTransport() {
		endpoint.mu.Lock()
		endpoint.retiredPhysical[endpointPhysicalKey{
			connectionID:      request.connectionID,
			physicalRequestID: request.physicalRequestID,
		}] = fields
		endpoint.mu.Unlock()
		fields.Detail = "tcp_response_wait_tombstone"
		endpoint.timeline.record(TCPEventQuarantineTransition, fields)
	}
	if request.group.ActiveDependentCount() == 0 {
		endpoint.finishRequest(handle.requestID)
		if transition.CloseConnection() {
			endpoint.dropConnection(request.connectionID)
		}
	}
	if !transition.CloseConnection() {
		endpoint.refreshConnectionReadDeadline(request.connectionID)
	}
	return transition, nil
}

func (endpoint *TCPEndpoint) refreshConnectionReadDeadline(
	connectionID uint64,
) {
	endpoint.mu.Lock()
	connection := endpoint.connections[connectionID]
	endpoint.mu.Unlock()
	if connection != nil {
		connection.transport.refreshActiveReadDeadline()
	}
}

// Cancel terminalizes every active dependent represented by one request.
func (endpoint *TCPEndpoint) Cancel(handle TCPRequestHandle) error {
	if endpoint == nil ||
		handle.endpoint != endpoint ||
		handle.requestID == 0 ||
		handle.backoff == nil {
		return protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"tcp_request_handle",
			-1,
		)
	}
	if endpoint.eventSinkCallbackActive() {
		return eventSinkReentryError()
	}
	if !endpoint.timelineAvailable() {
		endpoint.disable("event_sequence_exhausted")
		return invalidEndpointConfig()
	}
	endpoint.mu.Lock()
	request := endpoint.requests[handle.requestID]
	retryable, retained := endpoint.retryable[handle.requestID]
	if request == nil && retained &&
		retryable.backoff == handle.backoff &&
		retryable.deadlineOffset == handle.deadlineOffset {
		handle.backoff.mu.Lock()
		if handle.backoff.lifecycle != tcpRequestRetryable &&
			handle.backoff.lifecycle != tcpRequestRetrying {
			handle.backoff.mu.Unlock()
			endpoint.mu.Unlock()
			return protocolError(
				ErrorInvalidRequest,
				0,
				0,
				"tcp_request_lifecycle",
				-1,
			)
		}
		logicalViewIDs := make([]uint64, 0, len(handle.backoff.reads))
		for _, logical := range handle.backoff.reads {
			logicalViewIDs = append(logicalViewIDs, logical.LogicalViewID)
		}
		fields := endpoint.retryableEventFieldsLocked(handle)
		handle.backoff.lifecycle = tcpRequestTerminal
		handle.backoff.backoffSatisfied = false
		handle.backoff.reads = nil
		requiresBackoff := handle.backoff.requiresBackoff
		handle.backoff.mu.Unlock()
		if !requiresBackoff {
			delete(endpoint.retryable, handle.requestID)
		}
		endpoint.mu.Unlock()
		sort.Slice(logicalViewIDs, func(first, second int) bool {
			return logicalViewIDs[first] < logicalViewIDs[second]
		})
		for _, logicalViewID := range logicalViewIDs {
			fields.LogicalViewID = logicalViewID
			endpoint.timeline.record(TCPEventCallerCancellation, fields)
		}
		if !endpoint.timelineAvailable() {
			endpoint.disable("event_sequence_exhausted")
			return eventSequenceError()
		}
		return nil
	}
	if request == nil || request.handle.deadlineOffset != handle.deadlineOffset {
		endpoint.mu.Unlock()
		return protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"tcp_request_handle",
			-1,
		)
	}
	if request.isDeviceID() {
		endpoint.mu.Unlock()
		endpoint.outcomeMu.Lock()
		defer endpoint.outcomeMu.Unlock()
		endpoint.mu.Lock()
		request = endpoint.requests[handle.requestID]
		if request == nil ||
			!request.isDeviceID() ||
			request.handle.deadlineOffset != handle.deadlineOffset {
			endpoint.mu.Unlock()
			return protocolError(
				ErrorInvalidRequest,
				FunctionEncapsulatedInterface,
				0,
				"tcp_request_handle",
				-1,
			)
		}
		if request.phase == endpointRequestWriting {
			cancelWrite := request.writeCancel
			writeDone := request.writeDone
			request.cancelPending = true
			endpoint.mu.Unlock()
			if cancelWrite == nil || writeDone == nil {
				return protocolError(
					ErrorInvalidRequest,
					FunctionEncapsulatedInterface,
					0,
					"tcp_request_lifecycle",
					-1,
				)
			}
			cancelWrite()
			<-writeDone
			endpoint.mu.Lock()
			request = endpoint.requests[handle.requestID]
			if request == nil {
				endpoint.mu.Unlock()
				return nil
			}
			if !request.isDeviceID() ||
				request.handle.deadlineOffset != handle.deadlineOffset ||
				request.phase != endpointRequestWaiting {
				endpoint.mu.Unlock()
				return protocolError(
					ErrorInvalidRequest,
					FunctionEncapsulatedInterface,
					0,
					"tcp_request_lifecycle",
					-1,
				)
			}
		}
		connection := endpoint.connections[request.connectionID]
		fields := endpoint.requestEventFieldsLocked(request)
		waiting := request.phase == endpointRequestWaiting
		reservation := TCPReservation{}
		if waiting && connection != nil {
			reservation = TCPReservation{
				owner:             connection.lease.ownerForEndpoint(),
				transactionID:     request.transactionID,
				physicalRequestID: request.physicalRequestID,
				generation:        request.transportGeneration,
				deadlineOffset:    request.responseDeadline,
			}
			endpoint.retiredPhysical[endpointPhysicalKey{
				connectionID:      request.connectionID,
				physicalRequestID: request.physicalRequestID,
			}] = fields
		}
		endpoint.removeRequestLocked(handle.requestID)
		endpoint.mu.Unlock()

		var cancelErr error
		closeConnection := false
		if waiting && reservation.owner != nil {
			transition, err := reservation.owner.AbandonAfterWrite(
				reservation,
				AbandonCancellation,
			)
			var protocolErr *ProtocolError
			if errors.As(err, &protocolErr) &&
				protocolErr.Field == "reservation_state" {
				err = nil
			}
			cancelErr = errors.Join(cancelErr, err)
			closeConnection = transition.CloseConnection()
		}
		cancelErr = errors.Join(
			cancelErr,
			endpoint.failRequest(request),
		)
		setTCPRequestLifecycle(handle, tcpRequestTerminal)
		endpoint.timeline.record(TCPEventCallerCancellation, fields)
		if waiting {
			fields.Detail = "tcp_response_wait_tombstone"
			endpoint.timeline.record(TCPEventQuarantineTransition, fields)
		}
		if closeConnection && connection != nil {
			_, closeErr := connection.transport.closeTerminal()
			cancelErr = errors.Join(cancelErr, closeErr)
			endpoint.dropConnection(request.connectionID)
		} else {
			endpoint.refreshConnectionReadDeadline(request.connectionID)
		}
		return cancelErr
	}
	states := request.group.DependentStates()
	endpoint.mu.Unlock()
	logicalViewIDs := make([]uint64, 0, len(states))
	for logicalViewID, state := range states {
		if state == DependentQueued || state == DependentAttached {
			logicalViewIDs = append(logicalViewIDs, logicalViewID)
		}
	}
	sort.Slice(logicalViewIDs, func(first, second int) bool {
		return logicalViewIDs[first] < logicalViewIDs[second]
	})
	var cancelErr error
	for _, logicalViewID := range logicalViewIDs {
		_, err := endpoint.CancelLogical(handle, logicalViewID)
		cancelErr = errors.Join(cancelErr, err)
	}
	return cancelErr
}

func (endpoint *TCPEndpoint) retryableEventFieldsLocked(
	handle TCPRequestHandle,
) tcpEventFields {
	return tcpEventFields{
		RequestID:          handle.requestID,
		UnitID:             handle.backoff.unitID,
		AuthorizationScope: handle.backoff.authorizationScope,
		PollGeneration:     handle.backoff.pollGeneration,
		DeadlineIdentity:   handle.backoff.deadlineIdentity,
		DeadlineOffset:     handle.deadlineOffset,
	}
}

// Retry re-enters a failed idempotent read at the normal queue tail.
func (endpoint *TCPEndpoint) Retry(
	handle TCPRequestHandle,
	connectionHandle TCPConnectionHandle,
) error {
	if endpoint == nil ||
		handle.endpoint != endpoint ||
		handle.requestID == 0 ||
		handle.backoff == nil {
		return protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"tcp_request_handle",
			-1,
		)
	}
	if endpoint.eventSinkCallbackActive() {
		return eventSinkReentryError()
	}
	if !endpoint.timelineAvailable() {
		endpoint.disable("event_sequence_exhausted")
		return invalidEndpointConfig()
	}
	handle.backoff.mu.Lock()
	if handle.backoff.lifecycle != tcpRequestRetryable {
		handle.backoff.mu.Unlock()
		return protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"tcp_request_lifecycle",
			-1,
		)
	}
	if handle.backoff.backoffWaiting {
		handle.backoff.mu.Unlock()
		return protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"reconnect_backoff",
			-1,
		)
	}
	if handle.backoff.retries >=
		endpoint.config.SchedulerLimits.MaxRetryAttempts {
		handle.backoff.lifecycle = tcpRequestTerminal
		handle.backoff.requiresBackoff = false
		handle.backoff.backoffSatisfied = false
		handle.backoff.mu.Unlock()
		endpoint.trackRetryableState(handle, tcpRequestTerminal)
		return protocolError(
			ErrorInvalidRange,
			0,
			0,
			"retry_attempts",
			-1,
		)
	}
	if handle.backoff.requiresBackoff &&
		!handle.backoff.backoffSatisfied {
		handle.backoff.mu.Unlock()
		return protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"reconnect_backoff",
			-1,
		)
	}
	effectiveDeadline, ok := effectiveRequestDeadlineLocked(handle)
	if !ok || endpoint.config.Clock.Now() >= effectiveDeadline {
		handle.backoff.lifecycle = tcpRequestTerminal
		handle.backoff.mu.Unlock()
		endpoint.trackRetryableState(handle, tcpRequestTerminal)
		return protocolError(
			ErrorInvalidRange,
			0,
			0,
			"operation_deadline",
			-1,
		)
	}
	handle.backoff.lifecycle = tcpRequestRetrying
	unitID := handle.backoff.unitID
	authorizationScope := handle.backoff.authorizationScope
	pollGeneration := handle.backoff.pollGeneration
	deadlineIdentity := handle.backoff.deadlineIdentity
	reads := append([]TCPLogicalRead(nil), handle.backoff.reads...)
	deviceID := handle.backoff.deviceID
	deviceIDLimits := handle.backoff.deviceIDLimits
	deviceIDRetry := deviceID.access != 0
	handle.backoff.mu.Unlock()
	endpoint.trackRetryableState(handle, tcpRequestRetrying)

	endpoint.mu.Lock()
	connection, ok := endpoint.connectionLocked(connectionHandle)
	_, duplicate := endpoint.requests[handle.requestID]
	endpoint.mu.Unlock()
	if !ok || duplicate {
		endpoint.restoreRetryLifecycle(handle)
		if !ok {
			return invalidConnectionHandle()
		}
		return protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"request_id",
			-1,
		)
	}
	intents := make([]ReadIntent, 0, len(reads))
	for _, logical := range reads {
		intent, err := NewReadIntent(ReadIntentSpec{
			LogicalViewID:       logical.LogicalViewID,
			Endpoint:            endpoint.config.Endpoint,
			Transport:           TransportTCP,
			TransportGeneration: connection.handle.generation,
			UnitID:              unitID,
			AuthorizationScope:  authorizationScope,
			PollGeneration:      pollGeneration,
			DeadlineIdentity:    deadlineIdentity,
			Request:             logical.Request,
		})
		if err != nil {
			endpoint.restoreRetryLifecycle(handle)
			return err
		}
		intents = append(intents, intent)
	}
	fields := tcpEventFields{
		ConnectionID:        connection.handle.connectionID,
		TransportGeneration: connection.handle.generation,
		RequestID:           handle.requestID,
		UnitID:              unitID,
		AuthorizationScope:  authorizationScope,
		PollGeneration:      pollGeneration,
		DeadlineIdentity:    deadlineIdentity,
		DeadlineOffset:      handle.deadlineOffset,
		Detail:              "retry",
	}
	endpoint.timeline.record(TCPEventEnqueue, fields)
	if !endpoint.timelineAvailable() {
		endpoint.restoreRetryLifecycle(handle)
		endpoint.disable("event_sequence_exhausted")
		return eventSequenceError()
	}
	endpoint.scheduleMu.Lock()
	scheduledRequest := ScheduledRequest{
		RequestID: handle.requestID,
		Key: AdmissionKey{
			AuthorizationScope: authorizationScope,
			UnitID:             unitID,
		},
		DeadlineOffset: int64(effectiveDeadline),
	}
	var group *CoalescedRead
	var err error
	if deviceIDRetry {
		err = endpoint.scheduler.Enqueue(scheduledRequest)
	} else {
		group, err = endpoint.scheduler.ScheduleCoalesced(
			scheduledRequest,
			intents,
		)
	}
	if err != nil {
		endpoint.scheduleMu.Unlock()
		fields.Detail = "retry_rejected"
		endpoint.timeline.record(TCPEventAdmission, fields)
		endpoint.restoreRetryLifecycle(handle)
		return err
	}
	if !deviceIDRetry && endpoint.afterSchedule != nil {
		endpoint.afterSchedule()
	}
	if group != nil {
		group.setOperationDeadline(effectiveDeadline)
		group.setRuntimeAcquisitionSource(endpoint.config.RuntimeAcquisitionSource)
	}
	endpoint.mu.Lock()
	handle.backoff.mu.Lock()
	currentConnection, current := endpoint.connectionLocked(connectionHandle)
	_, duplicate = endpoint.requests[handle.requestID]
	retainedHandle, retained := endpoint.retryable[handle.requestID]
	retryStillOwned := retained &&
		retainedHandle.backoff == handle.backoff &&
		retainedHandle.deadlineOffset == handle.deadlineOffset &&
		handle.backoff.lifecycle == tcpRequestRetrying
	if !current || duplicate || endpoint.closed || !retryStillOwned {
		lifecycle := handle.backoff.lifecycle
		handle.backoff.mu.Unlock()
		endpoint.mu.Unlock()
		if group != nil {
			_ = group.FailTransport()
		} else {
			endpoint.scheduler.CancelQueued(handle.requestID)
		}
		endpoint.scheduleMu.Unlock()
		endpoint.restoreRetryLifecycle(handle)
		fields.Detail = "retry_stale_connection"
		endpoint.timeline.record(TCPEventAdmission, fields)
		if !retryStillOwned &&
			(lifecycle == tcpRequestRetryable ||
				lifecycle == tcpRequestTerminal) {
			return context.Canceled
		}
		if !current {
			return invalidConnectionHandle()
		}
		return invalidEndpointConfig()
	}
	endpoint.requests[handle.requestID] = &endpointRequest{
		handle:              handle,
		connectionID:        currentConnection.handle.connectionID,
		transportGeneration: currentConnection.handle.generation,
		unitID:              unitID,
		authorizationScope:  authorizationScope,
		pollGeneration:      pollGeneration,
		deadlineIdentity:    deadlineIdentity,
		group:               group,
		deviceID:            deviceID,
		deviceIDInitial:     deviceID,
		deviceIDLimits:      deviceIDLimits,
		operationDeadline:   effectiveDeadline,
		phase:               endpointRequestQueued,
	}
	handle.backoff.retries++
	handle.backoff.lifecycle = tcpRequestActive
	handle.backoff.requiresBackoff = false
	handle.backoff.backoffSatisfied = false
	delete(endpoint.retryable, handle.requestID)
	handle.backoff.mu.Unlock()
	endpoint.mu.Unlock()
	endpoint.scheduleMu.Unlock()
	if !deviceIDRetry {
		endpoint.timeline.recordCoalescing(fields, len(reads))
	}
	fields.Detail = "retry_admitted"
	endpoint.timeline.record(TCPEventAdmission, fields)
	endpoint.timeline.record(TCPEventRequestTimerArm, fields)
	if !endpoint.timelineAvailable() {
		endpoint.disable("event_sequence_exhausted")
		return eventSequenceError()
	}
	return nil
}

func (endpoint *TCPEndpoint) restoreRetryLifecycle(
	handle TCPRequestHandle,
) {
	if handle.backoff == nil {
		return
	}
	handle.backoff.mu.Lock()
	lifecycle := handle.backoff.lifecycle
	if handle.backoff.lifecycle == tcpRequestRetrying {
		effectiveDeadline, ok := effectiveRequestDeadlineLocked(handle)
		if !ok || endpoint.config.Clock.Now() >= effectiveDeadline {
			handle.backoff.lifecycle = tcpRequestTerminal
		} else {
			handle.backoff.lifecycle = tcpRequestRetryable
		}
		lifecycle = handle.backoff.lifecycle
	}
	handle.backoff.mu.Unlock()
	endpoint.trackRetryableState(handle, lifecycle)
}

func effectiveRequestDeadlineLocked(
	handle TCPRequestHandle,
) (time.Duration, bool) {
	if handle.backoff == nil ||
		handle.deadlineOffset <= 0 ||
		handle.backoff.clockDebt < 0 ||
		handle.backoff.clockDebt >= handle.deadlineOffset {
		return 0, false
	}
	return handle.deadlineOffset - handle.backoff.clockDebt, true
}

// WaitReconnect applies endpoint-owned jitter/backoff to the same deadline.
func (endpoint *TCPEndpoint) WaitReconnect(
	ctx context.Context,
	handle TCPRequestHandle,
	waiter DelayWaiter,
) error {
	if endpoint == nil ||
		ctx == nil ||
		waiter == nil ||
		handle.endpoint != endpoint ||
		handle.requestID == 0 ||
		handle.backoff == nil {
		return protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"backoff_wait",
			-1,
		)
	}
	if endpoint.eventSinkCallbackActive() {
		return eventSinkReentryError()
	}
	if !endpoint.timelineAvailable() {
		endpoint.disable("event_sequence_exhausted")
		return invalidEndpointConfig()
	}
	handle.backoff.mu.Lock()
	recoveryOnly := handle.backoff.lifecycle == tcpRequestTerminal &&
		handle.backoff.requiresBackoff
	startedRecoveryOnly := recoveryOnly
	if (handle.backoff.lifecycle != tcpRequestRetryable &&
		!recoveryOnly) ||
		!handle.backoff.requiresBackoff ||
		handle.backoff.backoffSatisfied ||
		handle.backoff.backoffWaiting {
		handle.backoff.mu.Unlock()
		return protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"tcp_request_lifecycle",
			-1,
		)
	}
	debt := handle.backoff.clockDebt
	handle.backoff.backoffWaiting = true
	handle.backoff.mu.Unlock()
	endpoint.mu.Lock()
	if !endpoint.reconnectRequired || endpoint.reconnectWaiting {
		endpoint.mu.Unlock()
		handle.backoff.mu.Lock()
		handle.backoff.backoffWaiting = false
		handle.backoff.mu.Unlock()
		return protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"reconnect_backoff",
			-1,
		)
	}
	endpoint.reconnectWaiting = true
	endpoint.mu.Unlock()
	clearWaiting := func() {
		handle.backoff.mu.Lock()
		handle.backoff.backoffWaiting = false
		handle.backoff.mu.Unlock()
		endpoint.mu.Lock()
		endpoint.reconnectWaiting = false
		endpoint.mu.Unlock()
	}
	before := endpoint.config.Clock.Now()
	if before < 0 ||
		debt > time.Duration(math.MaxInt64)-before {
		clearWaiting()
		endpoint.terminalizeRetryable(handle)
		return protocolError(
			ErrorInvalidRange,
			0,
			0,
			"operation_deadline",
			-1,
		)
	}
	effectiveNow := before + debt
	if !recoveryOnly && handle.deadlineOffset <= effectiveNow {
		clearWaiting()
		endpoint.terminalizeRetryable(handle)
		return protocolError(
			ErrorInvalidRange,
			0,
			0,
			"operation_deadline",
			-1,
		)
	}
	remaining := endpoint.config.MaxRequestDeadline
	if !recoveryOnly {
		remaining = handle.deadlineOffset - effectiveNow
	}
	delay, err := endpoint.backoff.nextDelayBefore(remaining)
	if err != nil {
		clearWaiting()
		var protocolErr *ProtocolError
		if errors.As(err, &protocolErr) &&
			protocolErr.Field == "backoff_attempts" {
			endpoint.disable("reconnect_backoff_exhausted")
			return err
		}
		endpoint.terminalizeRetryable(handle)
		return err
	}
	fields := tcpEventFields{
		RequestID:      handle.requestID,
		DeadlineOffset: handle.deadlineOffset,
		Delay:          delay,
		Detail: endpoint.backoff.JitterAlgorithmID() + "@" +
			endpoint.backoff.JitterVersion() + ":" +
			endpoint.backoff.JitterEvidence(),
	}
	if recoveryOnly {
		fields.Detail += ";recovery_only"
	}
	endpoint.timeline.record(TCPEventJitterBackoff, fields)
	if !endpoint.timelineAvailable() {
		clearWaiting()
		endpoint.terminalizeRetryable(handle)
		endpoint.disable("event_sequence_exhausted")
		return eventSequenceError()
	}
	if err := waiter.Wait(ctx, delay); err != nil {
		clearWaiting()
		return err
	}
	after := endpoint.config.Clock.Now()
	if after < before {
		clearWaiting()
		endpoint.terminalizeRetryable(handle)
		return protocolError(
			ErrorInvalidRange,
			0,
			0,
			"monotonic_clock",
			-1,
		)
	}
	elapsed := after - before
	additionalDebt := time.Duration(0)
	if elapsed < delay {
		additionalDebt = delay - elapsed
	}
	handle.backoff.mu.Lock()
	handle.backoff.backoffWaiting = false
	recoveryOnly = handle.backoff.lifecycle == tcpRequestTerminal &&
		handle.backoff.requiresBackoff
	if (handle.backoff.lifecycle != tcpRequestRetryable &&
		!recoveryOnly) ||
		!handle.backoff.requiresBackoff {
		handle.backoff.mu.Unlock()
		endpoint.completeReconnectBackoff(after, additionalDebt)
		return protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"tcp_request_lifecycle",
			-1,
		)
	}
	if additionalDebt >
		time.Duration(math.MaxInt64)-handle.backoff.clockDebt {
		handle.backoff.lifecycle = tcpRequestTerminal
		handle.backoff.requiresBackoff = false
		handle.backoff.backoffSatisfied = false
		handle.backoff.mu.Unlock()
		endpoint.completeReconnectBackoff(after, additionalDebt)
		endpoint.trackRetryableState(handle, tcpRequestTerminal)
		return protocolError(
			ErrorInvalidRange,
			0,
			0,
			"operation_deadline",
			-1,
		)
	}
	handle.backoff.mu.Unlock()
	endpoint.completeReconnectBackoff(after, additionalDebt)
	handle.backoff.mu.Lock()
	lifecycle := handle.backoff.lifecycle
	satisfied := handle.backoff.backoffSatisfied
	handle.backoff.mu.Unlock()
	if lifecycle == tcpRequestTerminal {
		if !startedRecoveryOnly {
			return context.Canceled
		}
		return nil
	}
	if lifecycle != tcpRequestRetryable || !satisfied {
		return protocolError(
			ErrorInvalidRange,
			0,
			0,
			"operation_deadline",
			-1,
		)
	}
	return nil
}

func (endpoint *TCPEndpoint) disable(reason string) {
	if endpoint == nil {
		return
	}
	endpoint.mu.Lock()
	if endpoint.disableReason == "" {
		endpoint.disableReason = reason
	}
	endpoint.mu.Unlock()
	_ = endpoint.Close()
}

func (endpoint *TCPEndpoint) completeReconnectBackoff(
	after time.Duration,
	additionalDebt time.Duration,
) {
	endpoint.mu.Lock()
	handles := make([]TCPRequestHandle, 0, len(endpoint.retryable))
	for _, handle := range endpoint.retryable {
		handles = append(handles, handle)
	}
	endpoint.mu.Unlock()
	sort.Slice(handles, func(first, second int) bool {
		return handles[first].requestID < handles[second].requestID
	})
	for _, handle := range handles {
		handle.backoff.mu.Lock()
		if !handle.backoff.requiresBackoff {
			handle.backoff.mu.Unlock()
			continue
		}
		if handle.backoff.lifecycle == tcpRequestTerminal {
			handle.backoff.requiresBackoff = false
			handle.backoff.backoffSatisfied = false
			handle.backoff.mu.Unlock()
			endpoint.trackRetryableState(handle, tcpRequestTerminal)
			continue
		}
		if handle.backoff.lifecycle != tcpRequestRetryable {
			handle.backoff.mu.Unlock()
			continue
		}
		terminal := additionalDebt >
			time.Duration(math.MaxInt64)-handle.backoff.clockDebt
		newDebt := handle.backoff.clockDebt
		if !terminal {
			newDebt += additionalDebt
			terminal = newDebt > time.Duration(math.MaxInt64)-after ||
				after+newDebt >= handle.deadlineOffset
		}
		if terminal {
			handle.backoff.lifecycle = tcpRequestTerminal
			handle.backoff.requiresBackoff = false
			handle.backoff.backoffSatisfied = false
		} else {
			handle.backoff.clockDebt = newDebt
			handle.backoff.backoffSatisfied = true
		}
		lifecycle := handle.backoff.lifecycle
		handle.backoff.mu.Unlock()
		if lifecycle == tcpRequestTerminal {
			endpoint.trackRetryableState(handle, tcpRequestTerminal)
		}
	}
	endpoint.mu.Lock()
	if endpoint.reconnectRequired {
		endpoint.reconnectReady = true
	}
	endpoint.reconnectWaiting = false
	endpoint.mu.Unlock()
}

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
