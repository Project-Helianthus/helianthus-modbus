package modbus

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"
)

// RTUProductionConfig configures one opt-in, vendor-neutral FC03/FC04 endpoint.
// Endpoint is a public label, never the serial path.
type RTUProductionConfig struct {
	Endpoint        string
	Serial          RTUSerialConfig
	Timing          RTUTiming
	ResponseTimeout time.Duration
	Enabled         bool
	Admission       RTUReadAdmission
}

// RTUReadAdmission is an upstream-owned, fail-closed decision. It carries no
// vendor/profile meaning and does not mint or persist transport authority.
type RTUReadAdmission interface {
	AdmitRTURead(RTUReadAdmissionRequest) bool
}
type RTUReadAdmissionRequest struct {
	Endpoint         string
	Generation       uint64
	UnitID           byte
	Function         FunctionCode
	Offset, Quantity uint16
}

// RTUReadEvidence is an immutable-by-value terminal exchange receipt.
type RTUReadEvidence struct {
	Endpoint        string
	Generation      uint64
	RequestID       uint64
	UnitID          byte
	Function        FunctionCode
	Offset          uint16
	Quantity        uint16
	RequestADU      []byte
	ResponseADU     []byte
	SentAt          time.Duration
	ReceivedAt      time.Duration
	IntegrityValid  bool
	TerminalOutcome string
	Current         bool
	Words           []uint16
	ReceiptWall     time.Time
	ClockEpoch      string
}

func (e RTUReadEvidence) copy() RTUReadEvidence {
	e.RequestADU = cloneBytes(e.RequestADU)
	e.ResponseADU = cloneBytes(e.ResponseADU)
	e.Words = append([]uint16(nil), e.Words...)
	return e
}

// RTUProductionEndpoint owns one configured stream and permits one typed read.
type RTUProductionEndpoint struct {
	mu                sync.Mutex
	endpoint          string
	stream            RTUByteStream
	timing            RTUTiming
	timeout           time.Duration
	generation        uint64
	nextID            uint64
	inflight          bool
	fenced            bool
	closed            bool
	recoveryAttempted bool
	admission         RTUReadAdmission
	quarantineUntil   time.Duration
	last              RTUReadEvidence
	haveLast          bool
}

// OpenRTUProductionEndpoint opens the explicit Linux serial configuration only
// after opt-in. It performs no discovery, profile admission, or request send.
func OpenRTUProductionEndpoint(config RTUProductionConfig) (*RTUProductionEndpoint, error) {
	if err := validateRTUProductionConfig(config); err != nil {
		return nil, err
	}
	stream, err := OpenRTUSerial(config.Serial)
	if err != nil {
		return nil, err
	}
	endpoint, err := newRTUProductionEndpoint(config, stream)
	if err != nil {
		_ = stream.Close()
		return nil, err
	}
	return endpoint, nil
}

func newRTUProductionEndpoint(config RTUProductionConfig, stream RTUByteStream) (*RTUProductionEndpoint, error) {
	if err := validateRTUProductionConfig(config); err != nil || stream == nil {
		return nil, protocolError(ErrorInvalidRequest, 0, 0, "rtu_production_config", -1)
	}
	return &RTUProductionEndpoint{endpoint: config.Endpoint, stream: stream, timing: config.Timing, timeout: config.ResponseTimeout, generation: 1, admission: config.Admission}, nil
}

func validateRTUProductionConfig(config RTUProductionConfig) error {
	bits := uint8(1 + config.Serial.DataBits + config.Serial.StopBits)
	if config.Serial.Parity != RTUParityNone {
		bits++
	}
	limit := config.ResponseTimeout + config.Timing.InterFrame()
	if limit < config.ResponseTimeout || !config.Enabled || config.Endpoint == "" || config.Admission == nil || config.Serial.Validate() != nil || config.Serial.Baud != config.Timing.baud || bits != config.Timing.bitsPerCharacter || config.ResponseTimeout <= 0 || config.ResponseTimeout > 30*time.Second || config.Timing.MaxResponseLatency() <= 0 || config.Timing.MaxResponseLatency() > config.ResponseTimeout || config.Timing.MaxQuiescence() <= config.Timing.MaxResponseLatency() || config.Timing.MaxQuiescence() > limit || config.Timing.MaxQuiescence() > 60*time.Second {
		return protocolError(ErrorInvalidRequest, 0, 0, "rtu_production_config", -1)
	}
	return nil
}

// Read performs exactly one FC03/FC04 send attempt and returns immutable evidence.
func (e *RTUProductionEndpoint) Read(ctx context.Context, unit byte, request ReadRegistersRequest) (ReadRegistersResponse, RTUReadEvidence, error) {
	if e == nil || ctx == nil {
		return ReadRegistersResponse{}, RTUReadEvidence{}, errRTUSessionState
	}
	frame, err := EncodeRTUReadADU(unit, request)
	if err != nil {
		return ReadRegistersResponse{}, RTUReadEvidence{}, err
	}
	e.mu.Lock()
	if e.closed || e.fenced || e.inflight {
		e.mu.Unlock()
		return ReadRegistersResponse{}, RTUReadEvidence{}, errRTUSessionState
	}
	admission := e.admission
	candidate := RTUReadAdmissionRequest{Endpoint: e.endpoint, Generation: e.generation, UnitID: unit, Function: request.Function(), Offset: request.Offset(), Quantity: request.Quantity()}
	if !admission.AdmitRTURead(candidate) {
		e.mu.Unlock()
		return ReadRegistersResponse{}, RTUReadEvidence{}, protocolError(ErrorInvalidRequest, request.Function(), 0, "rtu_read_admission", -1)
	}
	e.inflight = true
	e.nextID++
	evidence := RTUReadEvidence{Endpoint: e.endpoint, Generation: e.generation, RequestID: e.nextID, UnitID: unit, Function: request.Function(), Offset: request.Offset(), Quantity: request.Quantity(), RequestADU: cloneBytes(frame), SentAt: e.stream.RTUOffset(), ClockEpoch: "system-monotonic-v1"}
	e.mu.Unlock()
	defer func() { e.mu.Lock(); e.inflight = false; e.mu.Unlock() }()
	written, writeErr := e.stream.WriteRTU(ctx, frame)
	if writeErr != nil || written != len(frame) {
		if writeErr == nil {
			writeErr = io.ErrShortWrite
		}
		return ReadRegistersResponse{}, e.finish(evidence, nil, time.Time{}, false, "write_fault", true), writeErr
	}
	response, raw, receiveAt, receiptWall, err := e.receive(ctx, unit, request)
	if err != nil {
		var pe *ProtocolError
		if errors.As(err, &pe) && pe.Kind == ErrorExceptionResponse {
			return ReadRegistersResponse{}, e.finish(evidence, raw, receiptWall, true, "exception", false), err
		}
		return ReadRegistersResponse{}, e.finish(evidence, raw, receiptWall, false, "transport_fault", true), err
	}
	evidence.ReceivedAt = receiveAt
	evidence.Words = append([]uint16(nil), response.Words...)
	return response, e.finish(evidence, raw, receiptWall, true, "success", false), nil
}

func (e *RTUProductionEndpoint) receive(ctx context.Context, unit byte, request ReadRegistersRequest) (ReadRegistersResponse, []byte, time.Duration, time.Time, error) {
	deadline, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()
	decoder, err := NewRTUFrameDecoder(e.timing)
	if err != nil {
		return ReadRegistersResponse{}, nil, 0, time.Time{}, err
	}
	haveBytes := false
	raw := []byte(nil)
	receiptWall := time.Time{}
	for {
		readCtx := deadline
		cancelRead := func() {}
		if haveBytes {
			readCtx, cancelRead = context.WithTimeout(deadline, e.timing.InterFrame())
		}
		v, offset, readErr := e.stream.ReadRTUByte(readCtx)
		cancelRead()
		if readErr == nil {
			raw = append(raw, v)
			if receiptWall.IsZero() {
				receiptWall = time.Now()
			}
			if err := decoder.FeedByte(offset, v); err != nil {
				return ReadRegistersResponse{}, raw, offset, receiptWall, err
			}
			haveBytes = true
			continue
		}
		if !errors.Is(readErr, context.DeadlineExceeded) {
			return ReadRegistersResponse{}, raw, offset, receiptWall, readErr
		}
		if deadline.Err() != nil {
			return ReadRegistersResponse{}, raw, offset, receiptWall, deadline.Err()
		}
		if !haveBytes {
			continue
		}
		frame, endErr := decoder.EndFrame(offset)
		if endErr != nil {
			return ReadRegistersResponse{}, raw, offset, receiptWall, endErr
		}
		raw = frame.Bytes()
		decoded, decodeErr := DecodeRTUReadResponseADU(unit, request, raw)
		if decodeErr != nil {
			return ReadRegistersResponse{}, raw, offset, receiptWall, decodeErr
		}
		return decoded.Response(), raw, offset, receiptWall, nil
	}
}

func (e *RTUProductionEndpoint) finish(ev RTUReadEvidence, response []byte, receiptWall time.Time, integrity bool, outcome string, fence bool) RTUReadEvidence {
	e.mu.Lock()
	defer e.mu.Unlock()
	ev.ResponseADU = cloneBytes(response)
	if len(response) != 0 {
		ev.ReceiptWall = receiptWall
	}
	ev.IntegrityValid = integrity
	ev.TerminalOutcome = outcome
	ev.ReceivedAt = e.stream.RTUOffset()
	ev.Current = outcome == "success" && !fence && !e.closed && !e.fenced
	if fence {
		e.fenced = true
		now := e.stream.RTUOffset()
		until := now + e.timing.MaxResponseLatency()
		if until < now {
			e.closed = true
		} else {
			e.quarantineUntil = until
		}
	}
	e.last = ev.copy()
	e.haveLast = true
	return ev.copy()
}

// Recover performs exactly one bounded quiet recovery and creates a successor generation.
func (e *RTUProductionEndpoint) Recover(ctx context.Context) error {
	if e == nil || ctx == nil {
		return errRTUSessionState
	}
	e.mu.Lock()
	// A failing Read fences and releases its single-flight ownership in one
	// completion path. Do not let recovery publish a successor generation
	// while that retiring call can still clear or otherwise affect ownership.
	if e.closed || !e.fenced || e.inflight || e.recoveryAttempted {
		e.mu.Unlock()
		return errRTUSessionState
	}
	e.recoveryAttempted = true
	s := e.stream
	quiet := e.timing.InterFrame()
	bound := e.timeout + quiet
	until := e.quarantineUntil
	e.mu.Unlock()
	deadline, cancel := context.WithTimeout(ctx, bound)
	defer cancel()
	for {
		qctx, stop := context.WithTimeout(deadline, quiet)
		_, _, err := s.ReadRTUByte(qctx)
		stop()
		if err == nil {
			continue
		}
		if !errors.Is(err, context.DeadlineExceeded) || deadline.Err() != nil {
			return err
		}
		if s.RTUOffset() < until {
			continue
		}
		e.mu.Lock()
		e.generation++
		e.fenced = false
		e.recoveryAttempted = false
		e.mu.Unlock()
		return nil
	}
}

// LastEvidence returns a copy; historical evidence cannot be rebound to a read.
func (e *RTUProductionEndpoint) LastEvidence() (RTUReadEvidence, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.last.copy(), e.haveLast
}

// Close fences the current generation and releases the owned stream when possible.
func (e *RTUProductionEndpoint) Close() error {
	if e == nil {
		return errRTUSessionState
	}
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return nil
	}
	e.closed = true
	e.fenced = true
	e.generation++
	s := e.stream
	e.mu.Unlock()
	if closer, ok := s.(interface{ Close() error }); ok {
		return closer.Close()
	}
	return nil
}
