package modbus

import (
	"context"
	"errors"
	"math"
	"sort"
	"time"
)

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
