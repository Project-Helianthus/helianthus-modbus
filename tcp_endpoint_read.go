package modbus

import (
	"math"
	"sort"
	"time"
)

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
