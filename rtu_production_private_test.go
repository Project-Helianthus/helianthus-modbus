package modbus

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"
)

// privateProductionStream replays RTU response frames separated by line
// silence. Each segment is delivered byte by byte at 1 ms offsets; once a
// segment is exhausted the next read blocks until its context ends, advances
// the monotonic offset by 10 ms (more than t3.5 at 9600 baud), and only then
// exposes the following segment.
type privateProductionStream struct {
	mu       sync.Mutex
	segments [][]byte
	offset   time.Duration
	writes   [][]byte
	short    bool
}

func (s *privateProductionStream) WriteRTU(_ context.Context, b []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.writes = append(s.writes, cloneBytes(b))
	if s.short {
		return 1, nil
	}
	return len(b), nil
}

func (s *privateProductionStream) ReadRTUByte(ctx context.Context) (byte, time.Duration, error) {
	s.mu.Lock()
	if len(s.segments) > 0 && len(s.segments[0]) > 0 {
		b := s.segments[0][0]
		s.segments[0] = s.segments[0][1:]
		s.offset += time.Millisecond
		offset := s.offset
		s.mu.Unlock()
		return b, offset, nil
	}
	s.mu.Unlock()
	<-ctx.Done()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.segments) > 0 {
		s.segments = s.segments[1:]
	}
	s.offset += 10 * time.Millisecond
	return 0, s.offset, ctx.Err()
}

func (s *privateProductionStream) RTUOffset() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.offset
}

func (s *privateProductionStream) queue(segments ...[]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.segments = nil
	for _, segment := range segments {
		s.segments = append(s.segments, cloneBytes(segment))
	}
}

func (s *privateProductionStream) writeCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.writes)
}

type privateProductionAdmission struct {
	mu        sync.Mutex
	admit     bool
	requests  []RTUPrivateFunctionAdmissionRequest
	mutatePay bool
}

func (a *privateProductionAdmission) AdmitRTUPrivateFunction(request RTUPrivateFunctionAdmissionRequest) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.requests = append(a.requests, request)
	if a.mutatePay && len(request.Payload) > 0 {
		request.Payload[0] ^= 0xff
	}
	return a.admit
}

// privateClassifierFunc is a test-local caller-owned classifier.
type privateClassifierFunc func(RTUPrivateFunctionResponseADU) (RTUPrivateFunctionDisposition, error)

func (f privateClassifierFunc) ClassifyRTUPrivateFunctionResponse(response RTUPrivateFunctionResponseADU) (RTUPrivateFunctionDisposition, error) {
	return f(response)
}

// echoThenTerminal treats a byte-exact echo of the request payload as an
// intermediate frame and anything else as terminal. It models a caller codec;
// the transport itself never inspects payload meaning.
func echoThenTerminal(request PrivateFunctionRequest) privateClassifierFunc {
	return func(response RTUPrivateFunctionResponseADU) (RTUPrivateFunctionDisposition, error) {
		if bytes.Equal(response.Payload(), request.Payload()) {
			return RTUPrivateFunctionContinue, nil
		}
		return RTUPrivateFunctionTerminal, nil
	}
}

func privateProductionTiming(t *testing.T) RTUTiming {
	t.Helper()
	timing, err := NewRTUTiming(RTUTimingConfig{Baud: 9600, DataBits: 8, Parity: RTUParityEven, StopBits: 1, MaxResponseLatency: 20 * time.Millisecond, MaxQuiescence: 24 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	return timing
}

func privateProductionConfig(t *testing.T, private RTUPrivateFunctionConfig) RTUProductionConfig {
	t.Helper()
	return RTUProductionConfig{Endpoint: "rtu-a", Serial: RTUSerialConfig{Path: "configured", Baud: 9600, DataBits: 8, Parity: RTUParityEven, StopBits: 1}, Timing: privateProductionTiming(t), ResponseTimeout: 20 * time.Millisecond, Enabled: true, Admission: productionAdmission(true), PrivateFunction: private}
}

func privateProductionEndpoint(t *testing.T, stream RTUByteStream, admission RTUPrivateFunctionAdmission, maxResponses int) *RTUProductionEndpoint {
	t.Helper()
	e, err := newRTUProductionEndpoint(privateProductionConfig(t, RTUPrivateFunctionConfig{Admission: admission, MaxResponses: maxResponses}), stream)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func privateProductionRequest(t *testing.T, code byte, payload []byte) PrivateFunctionRequest {
	t.Helper()
	function, err := NewPrivateFunctionCode(code)
	if err != nil {
		t.Fatal(err)
	}
	request, err := NewPrivateFunctionRequest(function, payload)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func privateProductionFrame(t *testing.T, unit byte, function byte, payload []byte) []byte {
	t.Helper()
	frame, err := encodeRTUADU(unit, append([]byte{function}, payload...))
	if err != nil {
		t.Fatal(err)
	}
	return frame
}

const privateProductionCode = 0x64

var privateProductionPayload = []byte{0x04, 0x32, 0x02, 0x0a, 0x00}

func assertPrivateFenced(t *testing.T, e *RTUProductionEndpoint, stream *privateProductionStream, request PrivateFunctionRequest) {
	t.Helper()
	before := stream.writeCount()
	if _, _, err := e.ExchangePrivateFunction(context.Background(), 1, request, DefaultPrivateFunctionResponsePolicy(), nil); !errors.Is(err, errRTUSessionState) {
		t.Fatalf("fenced endpoint admitted successor exchange: %v", err)
	}
	if stream.writeCount() != before {
		t.Fatal("fenced endpoint wrote a successor request")
	}
}

func TestRTUProductionPrivateFunctionRetainsCorrelatedMultiFrameEvidence(t *testing.T) {
	request := privateProductionRequest(t, privateProductionCode, privateProductionPayload)
	echo := privateProductionFrame(t, 1, privateProductionCode, privateProductionPayload)
	terminal := privateProductionFrame(t, 1, privateProductionCode, []byte{0x06, 0x32, 0x04, 0x12, 0x02, 0x08, 0x01})
	stream := &privateProductionStream{}
	stream.queue(echo, terminal)
	admission := &privateProductionAdmission{admit: true, mutatePay: true}
	e := privateProductionEndpoint(t, stream, admission, 8)

	responses, evidence, err := e.ExchangePrivateFunction(context.Background(), 1, request, DefaultPrivateFunctionResponsePolicy(), echoThenTerminal(request))
	if err != nil {
		t.Fatal(err)
	}
	if len(responses) != 2 || !bytes.Equal(responses[0].Bytes(), echo) || !bytes.Equal(responses[1].Bytes(), terminal) {
		t.Fatalf("responses = %#v", responses)
	}
	wantRequest, err := EncodeRTUPrivateFunctionADU(1, request)
	if err != nil {
		t.Fatal(err)
	}
	if len(stream.writes) != 1 || !bytes.Equal(stream.writes[0], wantRequest) {
		t.Fatalf("writes = %x, want one %x", stream.writes, wantRequest)
	}
	if len(admission.requests) != 1 {
		t.Fatalf("admission calls = %d", len(admission.requests))
	}
	candidate := admission.requests[0]
	if candidate.Endpoint != "rtu-a" || candidate.Generation != 1 || candidate.UnitID != 1 || candidate.Function.Byte() != privateProductionCode {
		t.Fatalf("admission candidate = %#v", candidate)
	}
	if !evidence.Current || !evidence.IntegrityValid || evidence.TerminalOutcome != "success" || evidence.Generation != 1 || evidence.RequestID != 1 || evidence.UnitID != 1 || evidence.Function.Byte() != privateProductionCode || evidence.Endpoint != "rtu-a" || evidence.ClockEpoch != "system-monotonic-v1" {
		t.Fatalf("evidence = %#v", evidence)
	}
	if !bytes.Equal(evidence.RequestADU, wantRequest) || len(evidence.ResponseADUs) != 2 || !bytes.Equal(evidence.ResponseADUs[0], echo) || !bytes.Equal(evidence.ResponseADUs[1], terminal) {
		t.Fatalf("evidence ADUs = %x / %x", evidence.RequestADU, evidence.ResponseADUs)
	}
	if evidence.ReceiptWall.IsZero() || evidence.ReceivedAt <= evidence.SentAt {
		t.Fatalf("receipt bounds = wall %v sent %v received %v", evidence.ReceiptWall, evidence.SentAt, evidence.ReceivedAt)
	}
	evidence.RequestADU[0] = 9
	evidence.ResponseADUs[0][0] = 9
	evidence.ResponseADUs[1] = nil
	again, ok := e.LastPrivateFunctionEvidence()
	if !ok || again.RequestADU[0] == 9 || again.ResponseADUs[0][0] == 9 || again.ResponseADUs[1] == nil {
		t.Fatal("private-function evidence aliased endpoint state")
	}
	if _, ok := e.LastEvidence(); ok {
		t.Fatal("private-function exchange fabricated FC03/FC04 read evidence")
	}
}

func TestRTUProductionPrivateFunctionWithoutClassifierAcceptsExactlyOneFrame(t *testing.T) {
	request := privateProductionRequest(t, privateProductionCode, privateProductionPayload)
	terminal := privateProductionFrame(t, 1, privateProductionCode, []byte{0x01})
	stream := &privateProductionStream{}
	stream.queue(terminal)
	e := privateProductionEndpoint(t, stream, &privateProductionAdmission{admit: true}, 1)
	responses, evidence, err := e.ExchangePrivateFunction(context.Background(), 1, request, DefaultPrivateFunctionResponsePolicy(), nil)
	if err != nil || len(responses) != 1 || !bytes.Equal(responses[0].Payload(), []byte{0x01}) || !evidence.Current || len(evidence.ResponseADUs) != 1 {
		t.Fatalf("single frame = %v %#v %#v", err, responses, evidence)
	}
}

func TestRTUProductionPrivateFunctionRejectsUnadmittedOrUnqualifiedBeforeWrite(t *testing.T) {
	request := privateProductionRequest(t, privateProductionCode, privateProductionPayload)
	replayPolicy, err := NewPrivateFunctionResponsePolicy(2, true)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name      string
		admission RTUPrivateFunctionAdmission
		max       int
		unit      byte
		request   PrivateFunctionRequest
		policy    PrivateFunctionResponsePolicy
	}{
		{name: "disabled", unit: 1, request: request, policy: DefaultPrivateFunctionResponsePolicy()},
		{name: "denied", admission: &privateProductionAdmission{}, max: 1, unit: 1, request: request, policy: DefaultPrivateFunctionResponsePolicy()},
		{name: "standard read code", admission: &privateProductionAdmission{admit: true}, max: 1, unit: 1, request: privateProductionRequest(t, byte(FunctionReadHoldingRegisters), []byte{0, 0, 0, 1}), policy: DefaultPrivateFunctionResponsePolicy()},
		{name: "standard non-read code", admission: &privateProductionAdmission{admit: true}, max: 1, unit: 1, request: privateProductionRequest(t, 0x06, []byte{0, 0, 0, 1}), policy: DefaultPrivateFunctionResponsePolicy()},
		{name: "between user-defined ranges", admission: &privateProductionAdmission{admit: true}, max: 1, unit: 1, request: privateProductionRequest(t, 0x49, nil), policy: DefaultPrivateFunctionResponsePolicy()},
		{name: "above user-defined ranges", admission: &privateProductionAdmission{admit: true}, max: 1, unit: 1, request: privateProductionRequest(t, 0x6f, nil), policy: DefaultPrivateFunctionResponsePolicy()},
		{name: "replay policy", admission: &privateProductionAdmission{admit: true}, max: 1, unit: 1, request: request, policy: replayPolicy},
		{name: "zero policy", admission: &privateProductionAdmission{admit: true}, max: 1, unit: 1, request: request},
		{name: "broadcast unit", admission: &privateProductionAdmission{admit: true}, max: 1, unit: 0, request: request, policy: DefaultPrivateFunctionResponsePolicy()},
		{name: "zero request", admission: &privateProductionAdmission{admit: true}, max: 1, unit: 1, policy: DefaultPrivateFunctionResponsePolicy()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stream := &privateProductionStream{}
			e := privateProductionEndpoint(t, stream, tc.admission, tc.max)
			responses, evidence, err := e.ExchangePrivateFunction(context.Background(), tc.unit, tc.request, tc.policy, nil)
			if err == nil || responses != nil || evidence.RequestADU != nil {
				t.Fatalf("NO_SEND case = %v %#v %#v", err, responses, evidence)
			}
			if stream.writeCount() != 0 {
				t.Fatalf("writes = %d, want 0", stream.writeCount())
			}
			if _, ok := e.LastPrivateFunctionEvidence(); ok {
				t.Fatal("NO_SEND fabricated exchange evidence")
			}
			// A rejected exchange neither fences nor consumes the generation.
			readRequest := rtuReadRequest(t, FunctionReadHoldingRegisters)
			stream.queue(productionReadResponse(t, 1, readRequest, []uint16{1, 2, 3}))
			if _, ev, err := e.Read(context.Background(), 1, readRequest); err != nil || ev.Generation != 1 || !ev.Current {
				t.Fatalf("read after NO_SEND = %v %#v", err, ev)
			}
		})
	}
}

func TestRTUProductionPrivateFunctionRejectsInvalidOptInConfig(t *testing.T) {
	admission := &privateProductionAdmission{admit: true}
	for _, private := range []RTUPrivateFunctionConfig{
		{Admission: admission},
		{Admission: admission, MaxResponses: -1},
		{Admission: admission, MaxResponses: 9},
		{MaxResponses: 1},
	} {
		stream := &privateProductionStream{}
		if _, err := newRTUProductionEndpoint(privateProductionConfig(t, private), stream); err == nil {
			t.Fatalf("private-function config %#v accepted", private)
		}
		if stream.writeCount() != 0 {
			t.Fatal("invalid config wrote")
		}
	}
	for _, max := range []int{1, 8} {
		if _, err := newRTUProductionEndpoint(privateProductionConfig(t, RTUPrivateFunctionConfig{Admission: admission, MaxResponses: max}), &privateProductionStream{}); err != nil {
			t.Fatalf("bound %d rejected: %v", max, err)
		}
	}
}

func TestRTUProductionPrivateFunctionExceptionDoesNotFenceButShortWriteDoes(t *testing.T) {
	request := privateProductionRequest(t, privateProductionCode, privateProductionPayload)
	echo := privateProductionFrame(t, 1, privateProductionCode, privateProductionPayload)
	exception := privateProductionFrame(t, 1, privateProductionCode|0x80, []byte{0x04})
	stream := &privateProductionStream{}
	stream.queue(echo, exception)
	e := privateProductionEndpoint(t, stream, &privateProductionAdmission{admit: true}, 8)
	responses, evidence, err := e.ExchangePrivateFunction(context.Background(), 1, request, DefaultPrivateFunctionResponsePolicy(), echoThenTerminal(request))
	var pe *ProtocolError
	if !errors.As(err, &pe) || pe.Kind != ErrorExceptionResponse || pe.ExceptionCode != 0x04 || responses != nil {
		t.Fatalf("exception = %v %#v", err, responses)
	}
	if evidence.Current || !evidence.IntegrityValid || evidence.TerminalOutcome != "exception" || evidence.Generation != 1 || len(evidence.ResponseADUs) != 2 || !bytes.Equal(evidence.ResponseADUs[1], exception) || evidence.ReceiptWall.IsZero() {
		t.Fatalf("exception evidence = %#v", evidence)
	}

	stream.short = true
	_, evidence, err = e.ExchangePrivateFunction(context.Background(), 1, request, DefaultPrivateFunctionResponsePolicy(), nil)
	if !errors.Is(err, io.ErrShortWrite) || evidence.Generation != 1 || evidence.TerminalOutcome != "write_fault" || evidence.ResponseADUs != nil || !evidence.ReceiptWall.IsZero() || evidence.Current {
		t.Fatalf("short write = %v %#v", err, evidence)
	}
	assertPrivateFenced(t, e, stream, request)
	stream.short = false
	if err := e.Recover(context.Background()); err != nil {
		t.Fatalf("recover: %v", err)
	}
	stream.queue(privateProductionFrame(t, 1, privateProductionCode, []byte{0x01}))
	_, evidence, err = e.ExchangePrivateFunction(context.Background(), 1, request, DefaultPrivateFunctionResponsePolicy(), nil)
	if err != nil || evidence.Generation != 2 || !evidence.Current {
		t.Fatalf("successor = %v %#v", err, evidence)
	}
}

func TestRTUProductionPrivateFunctionMalformedAndCRCFramesRemainTerminalEvidence(t *testing.T) {
	request := privateProductionRequest(t, privateProductionCode, privateProductionPayload)
	badCRC := privateProductionFrame(t, 1, privateProductionCode, []byte{0x01})
	badCRC[len(badCRC)-1] ^= 0xff
	cases := map[string][]byte{
		"crc":                badCRC,
		"unit mismatch":      privateProductionFrame(t, 2, privateProductionCode, []byte{0x01}),
		"function mismatch":  privateProductionFrame(t, 1, 0x65, []byte{0x01}),
		"exception length":   privateProductionFrame(t, 1, privateProductionCode|0x80, []byte{0x04, 0x00}),
		"foreign exception":  privateProductionFrame(t, 1, 0x65|0x80, []byte{0x04}),
		"truncated frame":    {1, privateProductionCode},
		"standard read code": productionReadResponse(t, 1, rtuReadRequest(t, FunctionReadHoldingRegisters), []uint16{1, 2, 3}),
	}
	for name, frame := range cases {
		t.Run(name, func(t *testing.T) {
			stream := &privateProductionStream{}
			stream.queue(frame)
			e := privateProductionEndpoint(t, stream, &privateProductionAdmission{admit: true}, 1)
			responses, evidence, err := e.ExchangePrivateFunction(context.Background(), 1, request, DefaultPrivateFunctionResponsePolicy(), nil)
			if err == nil || responses != nil || evidence.Current || evidence.IntegrityValid || evidence.TerminalOutcome != "transport_fault" || evidence.ReceiptWall.IsZero() {
				t.Fatalf("terminal frame %x = %v %#v", frame, err, evidence)
			}
			if len(evidence.ResponseADUs) != 1 || !bytes.Equal(evidence.ResponseADUs[0], frame) {
				t.Fatalf("retained frame = %x, want %x", evidence.ResponseADUs, frame)
			}
			assertPrivateFenced(t, e, stream, request)
		})
	}
}

func TestRTUProductionPrivateFunctionCancellationFencesAndPartialFramesRetainEvidence(t *testing.T) {
	request := privateProductionRequest(t, privateProductionCode, privateProductionPayload)
	stream := &privateProductionStream{}
	stream.queue([]byte{1, privateProductionCode, 2})
	e := privateProductionEndpoint(t, stream, &privateProductionAdmission{admit: true}, 1)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	responses, evidence, err := e.ExchangePrivateFunction(ctx, 1, request, DefaultPrivateFunctionResponsePolicy(), nil)
	if !errors.Is(err, context.Canceled) || responses != nil || evidence.Current || len(evidence.ResponseADUs) != 1 || !bytes.Equal(evidence.ResponseADUs[0], []byte{1, privateProductionCode, 2}) {
		t.Fatalf("cancel = %v %#v", err, evidence)
	}
	assertPrivateFenced(t, e, stream, request)
}

func TestRTUProductionPrivateFunctionNoByteTimeoutFencesWithoutFabricatedReceipt(t *testing.T) {
	request := privateProductionRequest(t, privateProductionCode, privateProductionPayload)
	stream := &privateProductionStream{}
	e := privateProductionEndpoint(t, stream, &privateProductionAdmission{admit: true}, 1)
	responses, evidence, err := e.ExchangePrivateFunction(context.Background(), 1, request, DefaultPrivateFunctionResponsePolicy(), nil)
	if !errors.Is(err, context.DeadlineExceeded) || responses != nil || evidence.Current || evidence.ResponseADUs != nil || !evidence.ReceiptWall.IsZero() || evidence.TerminalOutcome != "transport_fault" {
		t.Fatalf("timeout = %v %#v", err, evidence)
	}
	assertPrivateFenced(t, e, stream, request)
}

func TestRTUProductionPrivateFunctionIntermediateTimeoutRetainsEarlierFrames(t *testing.T) {
	request := privateProductionRequest(t, privateProductionCode, privateProductionPayload)
	echo := privateProductionFrame(t, 1, privateProductionCode, privateProductionPayload)
	stream := &privateProductionStream{}
	stream.queue(echo)
	e := privateProductionEndpoint(t, stream, &privateProductionAdmission{admit: true}, 8)
	started := time.Now()
	responses, evidence, err := e.ExchangePrivateFunction(context.Background(), 1, request, DefaultPrivateFunctionResponsePolicy(), echoThenTerminal(request))
	if !errors.Is(err, context.DeadlineExceeded) || responses != nil || evidence.Current || !evidence.IntegrityValid || evidence.TerminalOutcome != "transport_fault" {
		t.Fatalf("intermediate timeout = %v %#v", err, evidence)
	}
	if len(evidence.ResponseADUs) != 1 || !bytes.Equal(evidence.ResponseADUs[0], echo) || evidence.ReceiptWall.IsZero() {
		t.Fatalf("intermediate evidence = %#v", evidence)
	}
	// Two frame windows of at most one response timeout each, plus scheduling slack.
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("intermediate timeout unbounded: %s", elapsed)
	}
	assertPrivateFenced(t, e, stream, request)
}

func TestRTUProductionPrivateFunctionResponseBoundFencesAndRecoveryDiscardsExcessFrame(t *testing.T) {
	request := privateProductionRequest(t, privateProductionCode, privateProductionPayload)
	echo := privateProductionFrame(t, 1, privateProductionCode, privateProductionPayload)
	stream := &privateProductionStream{}
	stream.queue(echo, echo, echo)
	e := privateProductionEndpoint(t, stream, &privateProductionAdmission{admit: true}, 2)
	responses, evidence, err := e.ExchangePrivateFunction(context.Background(), 1, request, DefaultPrivateFunctionResponsePolicy(), echoThenTerminal(request))
	var pe *ProtocolError
	if !errors.As(err, &pe) || pe.Kind != ErrorMalformedResponse || responses != nil || evidence.Current || evidence.TerminalOutcome != "response_bound" || len(evidence.ResponseADUs) != 2 {
		t.Fatalf("response bound = %v %#v", err, evidence)
	}
	assertPrivateFenced(t, e, stream, request)
	// The third same-shape frame belongs to the retired generation. Recovery
	// consumes it before the successor generation admits a request.
	if err := e.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	terminal := privateProductionFrame(t, 1, privateProductionCode, []byte{0x02})
	stream.queue(terminal)
	responses, evidence, err = e.ExchangePrivateFunction(context.Background(), 1, request, DefaultPrivateFunctionResponsePolicy(), echoThenTerminal(request))
	if err != nil || evidence.Generation != 2 || len(responses) != 1 || !bytes.Equal(responses[0].Bytes(), terminal) {
		t.Fatalf("successor = %v %#v %#v", err, responses, evidence)
	}
}

func TestRTUProductionPrivateFunctionClassifierFaultFences(t *testing.T) {
	request := privateProductionRequest(t, privateProductionCode, privateProductionPayload)
	classifierErr := errors.New("caller codec rejected frame")
	cases := map[string]privateClassifierFunc{
		"error": func(RTUPrivateFunctionResponseADU) (RTUPrivateFunctionDisposition, error) {
			return RTUPrivateFunctionTerminal, classifierErr
		},
		"invalid disposition": func(RTUPrivateFunctionResponseADU) (RTUPrivateFunctionDisposition, error) {
			return 0, nil
		},
		"panic": func(RTUPrivateFunctionResponseADU) (RTUPrivateFunctionDisposition, error) {
			panic("caller codec panic")
		},
	}
	for name, classifier := range cases {
		t.Run(name, func(t *testing.T) {
			frame := privateProductionFrame(t, 1, privateProductionCode, []byte{0x01})
			stream := &privateProductionStream{}
			stream.queue(frame)
			e := privateProductionEndpoint(t, stream, &privateProductionAdmission{admit: true}, 2)
			responses, evidence, err := e.ExchangePrivateFunction(context.Background(), 1, request, DefaultPrivateFunctionResponsePolicy(), classifier)
			if err == nil || responses != nil || evidence.Current || !evidence.IntegrityValid || evidence.TerminalOutcome != "classifier_fault" || len(evidence.ResponseADUs) != 1 {
				t.Fatalf("classifier fault = %v %#v", err, evidence)
			}
			if name == "error" && !errors.Is(err, classifierErr) {
				t.Fatalf("classifier error lost: %v", err)
			}
			e.mu.Lock()
			inflight := e.inflight
			e.mu.Unlock()
			if inflight {
				t.Fatal("classifier fault leaked single-flight ownership")
			}
			assertPrivateFenced(t, e, stream, request)
		})
	}
}

func TestRTUProductionPrivateFunctionSharesSingleFlightGenerationAndCorrelation(t *testing.T) {
	request := privateProductionRequest(t, privateProductionCode, privateProductionPayload)
	readRequest := rtuReadRequest(t, FunctionReadHoldingRegisters)
	stream := &privateProductionStream{}
	e := privateProductionEndpoint(t, stream, &privateProductionAdmission{admit: true}, 1)

	e.mu.Lock()
	e.inflight = true
	e.mu.Unlock()
	if _, _, err := e.ExchangePrivateFunction(context.Background(), 1, request, DefaultPrivateFunctionResponsePolicy(), nil); !errors.Is(err, errRTUSessionState) {
		t.Fatalf("exchange during in-flight read = %v", err)
	}
	if stream.writeCount() != 0 {
		t.Fatal("exchange wrote while another exchange owned the stream")
	}
	e.mu.Lock()
	e.inflight = false
	e.mu.Unlock()

	stream.queue(productionReadResponse(t, 1, readRequest, []uint16{7, 7, 7}))
	_, readEvidence, err := e.Read(context.Background(), 1, readRequest)
	if err != nil || readEvidence.RequestID != 1 {
		t.Fatalf("read = %v %#v", err, readEvidence)
	}
	stream.queue(privateProductionFrame(t, 1, privateProductionCode, []byte{0x01}))
	_, privateEvidence, err := e.ExchangePrivateFunction(context.Background(), 1, request, DefaultPrivateFunctionResponsePolicy(), nil)
	if err != nil || privateEvidence.RequestID != 2 || privateEvidence.Generation != 1 {
		t.Fatalf("private = %v %#v", err, privateEvidence)
	}
	lastRead, ok := e.LastEvidence()
	if !ok || lastRead.RequestID != 1 || lastRead.Words[0] != 7 {
		t.Fatalf("private exchange rewrote read evidence: %#v", lastRead)
	}

	// A private-function fault fences the shared generation for FC03/FC04 too.
	_, _, err = e.ExchangePrivateFunction(context.Background(), 1, request, DefaultPrivateFunctionResponsePolicy(), nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout = %v", err)
	}
	if _, _, err := e.Read(context.Background(), 1, readRequest); !errors.Is(err, errRTUSessionState) {
		t.Fatalf("read after private fence = %v", err)
	}
	if err := e.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	stream.queue(productionReadResponse(t, 1, readRequest, []uint16{8, 8, 8}))
	_, readEvidence, err = e.Read(context.Background(), 1, readRequest)
	if err != nil || readEvidence.Generation != 2 || !readEvidence.Current {
		t.Fatalf("read successor = %v %#v", err, readEvidence)
	}

	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.ExchangePrivateFunction(context.Background(), 1, request, DefaultPrivateFunctionResponsePolicy(), nil); !errors.Is(err, errRTUSessionState) {
		t.Fatalf("exchange after close = %v", err)
	}
}
