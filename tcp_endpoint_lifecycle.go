package modbus

import (
	"errors"
	"math"
	"net"
	"net/url"
	"sort"
	"strconv"
)

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
