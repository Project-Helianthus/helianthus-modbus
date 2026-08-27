package modbus

import (
	"context"
	"errors"
)

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
	} else if request.deviceIDInitial.extended {
		result, err = AggregateExtendedDeviceIDStream(
			request.deviceIDInitial,
			request.deviceIDSegments,
			request.deviceIDLimits,
		)
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
