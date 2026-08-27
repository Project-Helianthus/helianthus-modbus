package modbus

import (
	"context"
	"encoding/hex"
	"errors"
	"math"
	"time"
)

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
