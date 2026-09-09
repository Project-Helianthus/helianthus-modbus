package modbus

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"
)

type productionStream struct {
	mu     sync.Mutex
	bytes  []byte
	offset time.Duration
	writes [][]byte
	short  bool
}
type productionAdmission bool

func (a productionAdmission) AdmitRTURead(RTUReadAdmissionRequest) bool { return bool(a) }

func productionReadResponse(t *testing.T, unit byte, request ReadRegistersRequest, words []uint16) []byte {
	t.Helper()
	pdu := []byte{byte(request.Function()), byte(len(words) * 2)}
	for _, word := range words {
		pdu = append(pdu, byte(word>>8), byte(word))
	}
	frame, err := encodeRTUADU(unit, pdu)
	if err != nil {
		t.Fatal(err)
	}
	return frame
}
func productionException(t *testing.T, unit byte, function FunctionCode) []byte {
	t.Helper()
	frame, err := encodeRTUADU(unit, []byte{byte(function) | 0x80, 2})
	if err != nil {
		t.Fatal(err)
	}
	return frame
}

func (s *productionStream) WriteRTU(_ context.Context, b []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.writes = append(s.writes, cloneBytes(b))
	if s.short {
		return 1, nil
	}
	return len(b), nil
}
func (s *productionStream) ReadRTUByte(ctx context.Context) (byte, time.Duration, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.bytes) > 0 {
		b := s.bytes[0]
		s.bytes = s.bytes[1:]
		s.offset += time.Millisecond
		return b, s.offset, nil
	}
	<-ctx.Done()
	s.offset += 10 * time.Millisecond
	return 0, s.offset, ctx.Err()
}
func (s *productionStream) RTUOffset() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.offset
}

func productionEndpoint(t *testing.T, stream RTUByteStream) *RTUProductionEndpoint {
	t.Helper()
	timing, err := NewRTUTiming(RTUTimingConfig{Baud: 9600, DataBits: 8, Parity: RTUParityEven, StopBits: 1, MaxResponseLatency: 20 * time.Millisecond, MaxQuiescence: 24 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	e, err := newRTUProductionEndpoint(RTUProductionConfig{Endpoint: "rtu-a", Serial: RTUSerialConfig{Path: "configured", Baud: 9600, DataBits: 8, Parity: RTUParityEven, StopBits: 1}, Timing: timing, ResponseTimeout: 20 * time.Millisecond, Enabled: true, Admission: productionAdmission(true)}, stream)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestRTUProductionReadRetainsImmutableCorrelatedEvidence(t *testing.T) {
	req := rtuReadRequest(t, FunctionReadHoldingRegisters)
	response := productionReadResponse(t, 1, req, []uint16{0x1234, 0x5678, 0x9abc})
	stream := &productionStream{bytes: response}
	e := productionEndpoint(t, stream)
	got, ev, err := e.Read(context.Background(), 1, req)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Words) != 3 || got.Words[0] != 0x1234 || !ev.Current || ev.Generation != 1 || ev.Function != FunctionReadHoldingRegisters {
		t.Fatalf("unexpected result %#v %#v", got, ev)
	}
	ev.RequestADU[0] = 9
	again, ok := e.LastEvidence()
	if !ok || again.RequestADU[0] == 9 {
		t.Fatal("evidence aliased")
	}
}

func TestRTUProductionExceptionDoesNotFenceButShortWriteDoes(t *testing.T) {
	req := rtuReadRequest(t, FunctionReadHoldingRegisters)
	exception := productionException(t, 1, req.Function())
	stream := &productionStream{bytes: exception}
	e := productionEndpoint(t, stream)
	_, ev, err := e.Read(context.Background(), 1, req)
	var pe *ProtocolError
	if !errors.As(err, &pe) || pe.Kind != ErrorExceptionResponse || ev.Generation != 1 {
		t.Fatalf("exception = %v evidence=%#v", err, ev)
	}
	stream.short = true
	_, ev, err = e.Read(context.Background(), 1, req)
	if !errors.Is(err, io.ErrShortWrite) || ev.Generation != 1 {
		t.Fatalf("short=%v %#v", err, ev)
	}
	if _, _, err = e.Read(context.Background(), 1, req); err == nil {
		t.Fatal("fenced successor accepted")
	}
	stream.short = false
	if err := e.Recover(context.Background()); err != nil {
		t.Fatalf("recover: %v", err)
	}
	stream.bytes = productionReadResponse(t, 1, req, []uint16{1, 2, 3})
	_, ev, err = e.Read(context.Background(), 1, req)
	if err != nil || ev.Generation != 2 || !ev.Current {
		t.Fatalf("successor: %v %#v", err, ev)
	}
}

func TestRTUProductionRejectsUnadmittedReadBeforeWrite(t *testing.T) {
	req := rtuReadRequest(t, FunctionReadHoldingRegisters)
	stream := &productionStream{}
	timing, err := NewRTUTiming(RTUTimingConfig{Baud: 9600, DataBits: 8, Parity: RTUParityEven, StopBits: 1, MaxResponseLatency: time.Millisecond, MaxQuiescence: 5 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	e, err := newRTUProductionEndpoint(RTUProductionConfig{Endpoint: "rtu-a", Serial: RTUSerialConfig{Path: "configured", Baud: 9600, DataBits: 8, Parity: RTUParityEven, StopBits: 1}, Timing: timing, ResponseTimeout: time.Millisecond, Enabled: true, Admission: productionAdmission(false)}, stream)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.Read(context.Background(), 1, req); err == nil {
		t.Fatal("unadmitted read accepted")
	}
	if len(stream.writes) != 0 {
		t.Fatalf("writes = %d, want 0", len(stream.writes))
	}
}

func TestRTUProductionRecoveryWaitsForRetiringReadOwnership(t *testing.T) {
	stream := &productionStream{}
	e := productionEndpoint(t, stream)

	// This is the observable lifecycle state after a failing Read has fenced
	// its generation but before that same call has released single-flight
	// ownership. Recovery must not create a successor in this state.
	e.mu.Lock()
	e.fenced = true
	e.inflight = true
	e.quarantineUntil = e.timing.MaxResponseLatency()
	e.mu.Unlock()

	if err := e.Recover(context.Background()); !errors.Is(err, errRTUSessionState) {
		t.Fatalf("recovery while retiring read owns stream = %v, want session-state rejection", err)
	}
	e.mu.Lock()
	if !e.fenced || !e.inflight || e.generation != 1 || e.recoveryAttempted {
		t.Fatalf("rejected recovery mutated lifecycle: fenced=%v inflight=%v generation=%d attempted=%v", e.fenced, e.inflight, e.generation, e.recoveryAttempted)
	}
	e.inflight = false
	e.mu.Unlock()

	if err := e.Recover(context.Background()); err != nil {
		t.Fatalf("recovery after retiring read released ownership: %v", err)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.fenced || e.inflight || e.generation != 2 {
		t.Fatalf("successor lifecycle: fenced=%v inflight=%v generation=%d", e.fenced, e.inflight, e.generation)
	}
}
