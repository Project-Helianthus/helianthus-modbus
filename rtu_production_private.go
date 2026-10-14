package modbus

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"
)

// maxRTUProductionPrivateResponses is the transport ceiling on correlated
// normal frames one private-function exchange may collect. It is a resource
// bound, not a device or vendor fact; the endpoint configuration selects a
// value from 1 through this ceiling.
const maxRTUProductionPrivateResponses = 8

// RTUPrivateFunctionConfig opts one production endpoint into the generic
// private-function exchange. The zero value disables it. Admission and
// MaxResponses are set together or not at all.
type RTUPrivateFunctionConfig struct {
	Admission    RTUPrivateFunctionAdmission
	MaxResponses int
}

func validateRTUPrivateFunctionConfig(config RTUPrivateFunctionConfig) error {
	if config.Admission == nil && config.MaxResponses == 0 {
		return nil
	}
	if config.Admission == nil || config.MaxResponses < 1 || config.MaxResponses > maxRTUProductionPrivateResponses {
		return protocolError(ErrorInvalidRequest, 0, 0, "rtu_private_function_config", -1)
	}
	return nil
}

// RTUPrivateFunctionAdmission is an upstream-owned, fail-closed decision for
// one private-function request. The registry that owns profile selection and
// operation qualification must admit only operations it has qualified for
// this endpoint and unit. The transport cannot tell whether a private
// operation changes device state; that classification belongs upstream.
type RTUPrivateFunctionAdmission interface {
	AdmitRTUPrivateFunction(RTUPrivateFunctionAdmissionRequest) bool
}

// RTUPrivateFunctionAdmissionRequest describes one candidate exchange. Payload
// is an independent copy; changing it does not change the bytes sent.
type RTUPrivateFunctionAdmissionRequest struct {
	Endpoint   string
	Generation uint64
	UnitID     byte
	Function   PrivateFunctionCode
	Payload    []byte
}

// RTUPrivateFunctionDisposition is a caller-owned classification of one
// correlated normal response frame. The zero value is invalid.
type RTUPrivateFunctionDisposition uint8

const (
	// RTUPrivateFunctionContinue keeps the exchange open for another frame.
	RTUPrivateFunctionContinue RTUPrivateFunctionDisposition = iota + 1
	// RTUPrivateFunctionTerminal completes the exchange successfully.
	RTUPrivateFunctionTerminal
)

// RTUPrivateFunctionResponseClassifier is supplied by the codec the registry
// selected for the operation. The transport calls it only for frames that
// already passed RTU integrity, unit, and function correlation, and never
// interprets the payload itself.
type RTUPrivateFunctionResponseClassifier interface {
	ClassifyRTUPrivateFunctionResponse(RTUPrivateFunctionResponseADU) (RTUPrivateFunctionDisposition, error)
}

var errRTUPrivateFunctionClassifier = errors.New("rtu private-function classifier panicked")

// RTUPrivateFunctionEvidence is an immutable-by-value terminal receipt for one
// private-function exchange. ResponseADUs holds every received frame in
// arrival order, including a final exception, malformed, CRC-failed, or
// partial frame; it is nil when no response byte arrived. IntegrityValid
// reports that at least one frame was retained and every retained frame passed
// RTU integrity, unit, and function correlation (a correlated exception
// included); it is false for any malformed, CRC-failed, mismatched, or partial
// frame and when no frame arrived.
type RTUPrivateFunctionEvidence struct {
	Endpoint        string
	Generation      uint64
	RequestID       uint64
	UnitID          byte
	Function        PrivateFunctionCode
	RequestADU      []byte
	ResponseADUs    [][]byte
	SentAt          time.Duration
	ReceivedAt      time.Duration
	IntegrityValid  bool
	TerminalOutcome string
	Current         bool
	ReceiptWall     time.Time
	ClockEpoch      string
}

func (e RTUPrivateFunctionEvidence) copy() RTUPrivateFunctionEvidence {
	e.RequestADU = cloneBytes(e.RequestADU)
	if e.ResponseADUs != nil {
		frames := make([][]byte, len(e.ResponseADUs))
		for index, frame := range e.ResponseADUs {
			frames[index] = cloneBytes(frame)
		}
		e.ResponseADUs = frames
	}
	return e
}

// productionPrivateFunctionCode reports whether a code lies in the Modbus
// user-defined function-code ranges 65-72 and 100-110 (Modbus Application
// Protocol Specification V1.1b3, section 5). Public function codes, including
// FC03/FC04 and every write function, never use this exchange.
func productionPrivateFunctionCode(code PrivateFunctionCode) bool {
	value := code.Byte()
	return (value >= 65 && value <= 72) || (value >= 100 && value <= 110)
}

// ExchangePrivateFunction performs exactly one send attempt of one admitted
// private-function request and collects correlated response frames.
//
// Without a classifier the first correlated normal frame is terminal. With a
// classifier, each correlated normal frame is passed to it in order until it
// returns RTUPrivateFunctionTerminal; reaching the configured MaxResponses
// without a terminal frame is a fenced "response_bound" fault. Each frame must
// complete within the response timeout measured from the send or from the end
// of the previous frame, so one exchange is bounded by MaxResponses response
// timeouts plus caller classification time.
//
// A correlated exception is terminal evidence and does not fence. A write
// fault, timeout, cancellation, read fault, malformed, CRC-failed, unit or
// function mismatched frame, classifier fault, or response-count overrun
// fences the generation; Recover must complete before a successor exchange.
// Responses are returned only on success; every other outcome returns nil
// responses and retains the received frames in evidence only.
func (e *RTUProductionEndpoint) ExchangePrivateFunction(
	ctx context.Context,
	unit byte,
	request PrivateFunctionRequest,
	policy PrivateFunctionResponsePolicy,
	classifier RTUPrivateFunctionResponseClassifier,
) ([]RTUPrivateFunctionResponseADU, RTUPrivateFunctionEvidence, error) {
	if e == nil || ctx == nil {
		return nil, RTUPrivateFunctionEvidence{}, errRTUSessionState
	}
	function := request.FunctionCode()
	if !productionPrivateFunctionCode(function) || policy.MaxAttempts() != 1 {
		return nil, RTUPrivateFunctionEvidence{}, protocolError(ErrorInvalidRequest, FunctionCode(function.Byte()), 0, "rtu_private_function_admission", -1)
	}
	frame, err := EncodeRTUPrivateFunctionADU(unit, request)
	if err != nil {
		return nil, RTUPrivateFunctionEvidence{}, err
	}
	e.mu.Lock()
	if e.closed || e.fenced || e.inflight {
		e.mu.Unlock()
		return nil, RTUPrivateFunctionEvidence{}, errRTUSessionState
	}
	admission := e.private.Admission
	maxResponses := e.private.MaxResponses
	candidate := RTUPrivateFunctionAdmissionRequest{Endpoint: e.endpoint, Generation: e.generation, UnitID: unit, Function: function, Payload: request.Payload()}
	if admission == nil || !admission.AdmitRTUPrivateFunction(candidate) {
		e.mu.Unlock()
		return nil, RTUPrivateFunctionEvidence{}, protocolError(ErrorInvalidRequest, FunctionCode(function.Byte()), 0, "rtu_private_function_admission", -1)
	}
	e.inflight = true
	e.nextID++
	evidence := RTUPrivateFunctionEvidence{Endpoint: e.endpoint, Generation: e.generation, RequestID: e.nextID, UnitID: unit, Function: function, RequestADU: cloneBytes(frame), SentAt: e.stream.RTUOffset(), ClockEpoch: "system-monotonic-v1"}
	e.mu.Unlock()
	defer func() { e.mu.Lock(); e.inflight = false; e.mu.Unlock() }()

	written, writeErr := e.stream.WriteRTU(ctx, frame)
	if writeErr != nil || written != len(frame) {
		if writeErr == nil {
			writeErr = io.ErrShortWrite
		}
		return nil, e.finishPrivate(evidence, time.Time{}, false, "write_fault", true), writeErr
	}

	responses := make([]RTUPrivateFunctionResponseADU, 0, maxResponses)
	receiptWall := time.Time{}
	for {
		frameCtx, cancelFrame := context.WithTimeout(ctx, e.timeout)
		raw, complete, wall, readErr := e.readPrivateFrame(frameCtx)
		cancelFrame()
		if receiptWall.IsZero() {
			receiptWall = wall
		}
		if len(raw) != 0 {
			evidence.ResponseADUs = append(evidence.ResponseADUs, raw)
		}
		if readErr != nil {
			// Earlier correlated frames keep their integrity result when the
			// failing read itself delivered no byte.
			integrity := len(raw) == 0 && len(evidence.ResponseADUs) != 0
			return nil, e.finishPrivate(evidence, receiptWall, integrity, "transport_fault", true), readErr
		}
		response, decodeErr := DecodeRTUPrivateFunctionResponseADU(unit, request, complete)
		if decodeErr != nil {
			var pe *ProtocolError
			if errors.As(decodeErr, &pe) && pe.Kind == ErrorExceptionResponse {
				return nil, e.finishPrivate(evidence, receiptWall, true, "exception", false), decodeErr
			}
			return nil, e.finishPrivate(evidence, receiptWall, false, "transport_fault", true), decodeErr
		}
		responses = append(responses, response)
		disposition := RTUPrivateFunctionTerminal
		if classifier != nil {
			var classifyErr error
			disposition, classifyErr = classifyRTUPrivateFunctionResponse(classifier, response)
			if classifyErr == nil && disposition != RTUPrivateFunctionContinue && disposition != RTUPrivateFunctionTerminal {
				classifyErr = protocolError(ErrorInvalidRequest, FunctionCode(function.Byte()), 0, "rtu_private_function_disposition", int(disposition))
			}
			if classifyErr != nil {
				return nil, e.finishPrivate(evidence, receiptWall, true, "classifier_fault", true), classifyErr
			}
		}
		if disposition == RTUPrivateFunctionTerminal {
			return responses, e.finishPrivate(evidence, receiptWall, true, "success", false), nil
		}
		if len(responses) >= maxResponses {
			return nil, e.finishPrivate(evidence, receiptWall, true, "response_bound", true), protocolError(ErrorMalformedResponse, FunctionCode(function.Byte()), 0, "rtu_private_function_response_count", len(responses))
		}
	}
}

// classifyRTUPrivateFunctionResponse contains a caller classifier panic so the
// exchange still fences its generation and releases single-flight ownership.
func classifyRTUPrivateFunctionResponse(
	classifier RTUPrivateFunctionResponseClassifier,
	response RTUPrivateFunctionResponseADU,
) (disposition RTUPrivateFunctionDisposition, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			disposition = 0
			err = fmt.Errorf("%w: %v", errRTUPrivateFunctionClassifier, recovered)
		}
	}()
	return classifier.ClassifyRTUPrivateFunctionResponse(response)
}

// readPrivateFrame reads one RTU frame. The first byte and the t3.5 frame end
// must both occur before ctx ends; bytes are separated by at most t1.5. It
// returns every received byte as raw evidence and, on success, the complete
// integrity-checked frame.
func (e *RTUProductionEndpoint) readPrivateFrame(ctx context.Context) ([]byte, []byte, time.Time, error) {
	decoder, err := NewRTUFrameDecoder(e.timing)
	if err != nil {
		return nil, nil, time.Time{}, err
	}
	haveBytes := false
	raw := []byte(nil)
	receiptWall := time.Time{}
	for {
		readCtx := ctx
		cancelRead := func() {}
		if haveBytes {
			readCtx, cancelRead = context.WithTimeout(ctx, e.timing.InterFrame())
		}
		v, offset, readErr := e.stream.ReadRTUByte(readCtx)
		cancelRead()
		if readErr == nil {
			raw = append(raw, v)
			if receiptWall.IsZero() {
				receiptWall = time.Now()
			}
			if err := decoder.FeedByte(offset, v); err != nil {
				return raw, nil, receiptWall, err
			}
			haveBytes = true
			continue
		}
		if !errors.Is(readErr, context.DeadlineExceeded) {
			return raw, nil, receiptWall, readErr
		}
		if ctx.Err() != nil {
			return raw, nil, receiptWall, ctx.Err()
		}
		if !haveBytes {
			continue
		}
		adu, endErr := decoder.EndFrame(offset)
		if endErr != nil {
			return raw, nil, receiptWall, endErr
		}
		complete := adu.Bytes()
		return complete, complete, receiptWall, nil
	}
}

func (e *RTUProductionEndpoint) finishPrivate(ev RTUPrivateFunctionEvidence, receiptWall time.Time, integrity bool, outcome string, fence bool) RTUPrivateFunctionEvidence {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(ev.ResponseADUs) != 0 {
		ev.ReceiptWall = receiptWall
	}
	ev.IntegrityValid = integrity
	ev.TerminalOutcome = outcome
	ev.ReceivedAt = e.stream.RTUOffset()
	ev.Current = outcome == "success" && !fence && !e.closed && !e.fenced
	if fence {
		e.fenceLocked()
	}
	e.lastPrivate = ev.copy()
	e.haveLastPrivate = true
	return ev.copy()
}

// LastPrivateFunctionEvidence returns a copy of the latest private-function
// receipt. It is historical and cannot be rebound to a successor exchange.
func (e *RTUProductionEndpoint) LastPrivateFunctionEvidence() (RTUPrivateFunctionEvidence, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.lastPrivate.copy(), e.haveLastPrivate
}
