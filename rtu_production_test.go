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

// chunkedReadStream models host delivery, including a pending transfer that
// outlives a read deadline. The serial wire timing is deliberately unknown.
type chunkedReadStream struct {
	frame    []byte
	index    int
	gap      time.Duration
	chunk    int
	started  time.Time
	ready    time.Time
	lastByte time.Duration
}

func (s *chunkedReadStream) WriteRTU(_ context.Context, frame []byte) (int, error) {
	s.started = time.Now()
	return len(frame), nil
}

func (s *chunkedReadStream) RTUOffset() time.Duration {
	if s.started.IsZero() {
		return 0
	}
	return time.Since(s.started)
}

func (s *chunkedReadStream) ReadRTUByte(ctx context.Context) (byte, time.Duration, error) {
	if s.index == len(s.frame) {
		<-ctx.Done()
		return 0, s.RTUOffset(), ctx.Err()
	}
	if s.ready.IsZero() && s.index%s.chunk == 0 {
		s.ready = time.Now().Add(s.gap)
	}
	if !s.ready.IsZero() {
		timer := time.NewTimer(time.Until(s.ready))
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return 0, s.RTUOffset(), ctx.Err()
		case <-timer.C:
			s.ready = time.Time{}
		}
	}
	v := s.frame[s.index]
	s.index++
	s.lastByte = s.RTUOffset()
	return v, s.lastByte, nil
}

func chunkedReadEndpoint(t *testing.T, stream RTUByteStream, safety time.Duration) *RTUProductionEndpoint {
	t.Helper()
	config := RTUTimingConfig{Baud: 115200, DataBits: 8, Parity: RTUParityNone, StopBits: 1,
		MaxResponseLatency: time.Second, MaxQuiescence: time.Second + time.Millisecond}
	if safety != 0 {
		config.InterCharacterSafety = safety
		config.InterFrameSafety = safety + time.Millisecond
	}
	timing, err := NewRTUTiming(config)
	if err != nil {
		t.Fatal(err)
	}
	e, err := newRTUProductionEndpoint(RTUProductionConfig{Endpoint: "synthetic-rtu", Enabled: true,
		Serial: RTUSerialConfig{Path: "configured", Baud: 115200, DataBits: 8, Parity: RTUParityNone, StopBits: 1},
		Timing: timing, ResponseTimeout: time.Second, Admission: productionAdmission(true)}, stream)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestRTUProductionLengthFramingAcceptsHostTransferGaps(t *testing.T) {
	for _, function := range []FunctionCode{FunctionReadHoldingRegisters, FunctionReadInputRegisters} {
		for _, exception := range []bool{false, true} {
			req, err := NewReadRegistersRequest(function, 0, 125)
			if err != nil {
				t.Fatal(err)
			}
			words := make([]uint16, 125)
			for i := range words {
				words[i] = uint16(i + 1)
			}
			frame := productionReadResponse(t, 1, req, words)
			chunk := 64
			if exception {
				frame = productionException(t, 1, function)
				chunk = 1
			}
			s := &chunkedReadStream{frame: frame, chunk: chunk, gap: 4 * time.Millisecond}
			e := chunkedReadEndpoint(t, s, 0)
			response, ev, err := e.Read(context.Background(), 1, req)
			if exception {
				var pe *ProtocolError
				if !errors.As(err, &pe) || pe.Kind != ErrorExceptionResponse || !ev.IntegrityValid || e.fenced {
					t.Fatalf("exception: %v %#v", err, ev)
				}
			} else if err != nil || !ev.Current || len(response.Words) != 125 || response.Words[124] != 125 {
				t.Fatalf("long response: %v %#v", err, ev)
			}
			if !bytes.Equal(ev.ResponseADU, frame) {
				t.Fatal("raw evidence changed")
			}
			if s.RTUOffset()-s.lastByte < e.timing.InterFrame() {
				t.Fatal("completed before t3.5 guard")
			}
		}
	}
}

func TestRTUProductionLengthFramingRejectsCorruptionAndTruncation(t *testing.T) {
	req, err := NewReadRegistersRequest(FunctionReadHoldingRegisters, 0, 125)
	if err != nil {
		t.Fatal(err)
	}
	valid := productionReadResponse(t, 1, req, make([]uint16, 125))
	badCRC := cloneBytes(valid)
	badCRC[len(badCRC)-1] ^= 1
	shortWithCRC := rtuTestFrame(1, 3, 250, 0, 1)
	for name, frame := range map[string][]byte{
		"crc": badCRC, "truncated": valid[:len(valid)-1], "short with valid crc": shortWithCRC,
		"trailing": append(cloneBytes(valid), 0), "wrong function": rtuTestFrame(1, 4, 2, 0, 1),
		"wrong unit": rtuTestFrame(2, 3, 2, 0, 1), "wrong count": rtuTestFrame(1, 3, 2, 0, 1),
		"odd count": rtuTestFrame(1, 3, 1, 0), "zero count": rtuTestFrame(1, 3, 0),
		"oversized count": rtuTestFrame(1, 3, 252), "header only": {1, 3},
		"exception truncated": {1, 0x83, 2, 0},
		"concatenated":        append(cloneBytes(valid), valid...),
	} {
		t.Run(name, func(t *testing.T) {
			s := &chunkedReadStream{frame: frame, chunk: 64, gap: 4 * time.Millisecond}
			e := chunkedReadEndpoint(t, s, 0)
			_, ev, err := e.Read(context.Background(), 1, req)
			if err == nil || ev.Current || ev.IntegrityValid || !e.fenced || len(ev.ResponseADU) == 0 {
				t.Fatalf("accepted malformed frame: %v %#v", err, ev)
			}
			if !bytes.Equal(ev.ResponseADU, frame[:len(ev.ResponseADU)]) {
				t.Fatal("partial evidence changed")
			}
		})
	}
}

// configuredGapStream scripts receipt offsets, not OS timeout delivery.
// A synthetic timeout supplies the final idle guard without waiting.
type configuredGapStream struct {
	frame   []byte
	offsets []time.Duration
	index   int
	offset  time.Duration
}

func (s *configuredGapStream) WriteRTU(_ context.Context, frame []byte) (int, error) {
	return len(frame), nil
}

func (s *configuredGapStream) RTUOffset() time.Duration { return s.offset }

func (s *configuredGapStream) ReadRTUByte(_ context.Context) (byte, time.Duration, error) {
	if s.index == len(s.frame) {
		s.offset += 40 * time.Millisecond
		return 0, s.offset, context.DeadlineExceeded
	}
	value := s.frame[s.index]
	s.offset = s.offsets[s.index]
	s.index++
	return value, s.offset, nil
}

func TestRTUProductionLengthFramingHonorsConfiguredGap(t *testing.T) {
	req := rtuReadRequest(t, FunctionReadHoldingRegisters)
	words := []uint16{1, 2, 3}
	frame := productionReadResponse(t, 1, req, words)
	for _, tc := range []struct {
		name        string
		gap, safety time.Duration
		accepted    bool
	}{
		{"configured below", 30*time.Millisecond - time.Nanosecond, 30 * time.Millisecond, true},
		{"configured equal", 30 * time.Millisecond, 30 * time.Millisecond, true},
		{"configured above", 30*time.Millisecond + time.Nanosecond, 30 * time.Millisecond, false},
		{"default below", 20*time.Millisecond - time.Nanosecond, 0, true},
		{"default equal", 20 * time.Millisecond, 0, true},
		{"default above", 20*time.Millisecond + time.Nanosecond, 0, false},
		{"default host gap", 4 * time.Millisecond, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			offsets := make([]time.Duration, len(frame))
			for i := range offsets {
				offsets[i] = time.Duration(i+1) * 100 * time.Microsecond
				if i >= 3 {
					// Split once after the unit/function/byte-count header.
					offsets[i] += tc.gap - 100*time.Microsecond
				}
			}
			s := &configuredGapStream{frame: frame, offsets: offsets}
			e := chunkedReadEndpoint(t, s, tc.safety)
			response, ev, err := e.Read(context.Background(), 1, req)
			if tc.accepted {
				if err != nil || !ev.Current || !ev.IntegrityValid || e.fenced || ev.TerminalOutcome != "success" {
					t.Fatalf("gap=%s safety=%s: err=%v evidence=%#v fenced=%v", tc.gap, tc.safety, err, ev, e.fenced)
				}
				if len(response.Words) != len(words) || len(ev.Words) != len(words) {
					t.Fatalf("words: response=%v evidence=%v", response.Words, ev.Words)
				}
				for i, want := range words {
					if response.Words[i] != want || ev.Words[i] != want {
						t.Fatalf("word %d: response=%v evidence=%v want=%v", i, response.Words, ev.Words, words)
					}
				}
				if !bytes.Equal(ev.ResponseADU, frame) || s.index != len(frame) || s.RTUOffset()-offsets[len(frame)-1] <= e.timing.InterFrame() {
					t.Fatalf("incomplete frame evidence or final idle guard: %#v", ev)
				}
			} else {
				var pe *ProtocolError
				if !errors.As(err, &pe) || pe.Field != "rtu_inter_character_gap" || ev.Current || ev.IntegrityValid || !e.fenced || ev.TerminalOutcome != "transport_fault" {
					t.Fatalf("excessive gap: err=%v evidence=%#v fenced=%v", err, ev, e.fenced)
				}
				if len(response.Words) != 0 || len(ev.Words) != 0 || s.index != 4 || !bytes.Equal(ev.ResponseADU, frame[:4]) {
					t.Fatalf("excessive gap did not retain only the rejected prefix: response=%#v evidence=%#v", response, ev)
				}
			}
		})
	}
}

func TestRTUProductionReadResponseHeaderLengths(t *testing.T) {
	for _, function := range []FunctionCode{FunctionReadHoldingRegisters, FunctionReadInputRegisters} {
		for _, quantity := range []uint16{1, 125} {
			req, err := NewReadRegistersRequest(function, 0, quantity)
			if err != nil {
				t.Fatal(err)
			}
			for _, frame := range [][]byte{
				productionReadResponse(t, 1, req, make([]uint16, int(quantity))),
				productionException(t, 1, function),
			} {
				for end := 0; end <= len(frame); end++ {
					got, err := rtuReadResponseLength(req, frame[:end])
					want := len(frame)
					if end < 2 || (end < 3 && frame[1]&0x80 == 0) {
						want = 0
					}
					if err != nil || got != want {
						t.Fatalf("prefix %d: length=%d want=%d err=%v", end, got, want, err)
					}
				}
				if _, err := rtuReadResponseLength(req, append(cloneBytes(frame), 0)); err == nil {
					t.Fatal("trailing byte accepted")
				}
			}
			for _, header := range [][]byte{{1, 6}, {1, 0x86}, {1, byte(function), 0}, {1, byte(function), 251}} {
				if _, err := rtuReadResponseLength(req, header); err == nil {
					t.Fatalf("invalid header accepted: %x", header)
				}
			}
		}
	}
}

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
	e, err := newRTUProductionEndpoint(RTUProductionConfig{Endpoint: "rtu-a", Serial: RTUSerialConfig{Path: "configured", Baud: 9600, DataBits: 8, Parity: RTUParityEven, StopBits: 1}, Timing: timing, ResponseTimeout: productionTestContextBudget(timing.MaxResponseLatency(), timing), Enabled: true, Admission: productionAdmission(true)}, stream)
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
	if ev.ReceiptWall.IsZero() {
		t.Fatal("successful receipt has no wall time")
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
	if ev.ReceiptWall.IsZero() {
		t.Fatal("exception receipt has no wall time")
	}
	stream.short = true
	_, ev, err = e.Read(context.Background(), 1, req)
	if !errors.Is(err, io.ErrShortWrite) || ev.Generation != 1 {
		t.Fatalf("short=%v %#v", err, ev)
	}
	if !ev.ReceiptWall.IsZero() {
		t.Fatal("short write fabricated receipt wall")
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

func TestRTUProductionFourSequentialReadsRemainBounded(t *testing.T) {
	stream := &productionStream{}
	e := productionEndpoint(t, stream)
	for index := 0; index < 4; index++ {
		req, err := NewReadRegistersRequest(FunctionReadHoldingRegisters, uint16(index), 1)
		if err != nil {
			t.Fatal(err)
		}
		stream.bytes = productionReadResponse(t, 1, req, []uint16{uint16(index)})
		got, evidence, err := e.Read(context.Background(), 1, req)
		if err != nil || !evidence.Current || len(got.Words) != 1 || got.Words[0] != uint16(index) {
			t.Fatalf("read %d: %v %#v %#v", index, err, got, evidence)
		}
	}
	if len(stream.writes) != 4 {
		t.Fatalf("writes=%d", len(stream.writes))
	}
}

func TestRTUProductionCancellationFencesAndPartialFramesRetainEvidence(t *testing.T) {
	stream := &productionStream{bytes: []byte{1, byte(FunctionReadHoldingRegisters), 2}}
	e := productionEndpoint(t, stream)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, evidence, err := e.Read(ctx, 1, rtuReadRequest(t, FunctionReadHoldingRegisters))
	if err == nil || evidence.Current || len(evidence.ResponseADU) != 3 {
		t.Fatalf("cancel=%v %#v", err, evidence)
	}
	if _, _, err := e.Read(context.Background(), 1, rtuReadRequest(t, FunctionReadHoldingRegisters)); err == nil {
		t.Fatal("fenced cancellation admitted successor")
	}
}

func TestRTUProductionMalformedAndCRCFramesRemainTerminalEvidence(t *testing.T) {
	req := rtuReadRequest(t, FunctionReadHoldingRegisters)
	for _, frame := range [][]byte{{1, byte(req.Function()), 2}, func() []byte {
		b := productionReadResponse(t, 1, req, []uint16{1, 2, 3})
		b[len(b)-1] ^= 0xff
		return b
	}()} {
		stream := &productionStream{bytes: frame}
		e := productionEndpoint(t, stream)
		_, evidence, err := e.Read(context.Background(), 1, req)
		if err == nil || evidence.Current || len(evidence.ResponseADU) == 0 || evidence.ReceiptWall.IsZero() {
			t.Fatalf("terminal frame=%x err=%v evidence=%#v", frame, err, evidence)
		}
	}
}

func TestRTUProductionRejectsTimingAndRecoveryBoundMismatch(t *testing.T) {
	timing := rtuTestTiming(t, 9600)
	stream := &productionStream{}
	_, err := newRTUProductionEndpoint(RTUProductionConfig{Endpoint: "rtu-a", Serial: RTUSerialConfig{Path: "configured", Baud: 9600, DataBits: 8, Parity: RTUParityNone, StopBits: 1}, Timing: timing, ResponseTimeout: time.Millisecond, Enabled: true, Admission: productionAdmission(true)}, stream)
	if err == nil {
		t.Fatal("timing/recovery mismatch accepted")
	}
	if len(stream.writes) != 0 {
		t.Fatal("invalid config wrote")
	}
}

func TestRTUProductionRecoveryDiscardsDelayedOldGenerationFrame(t *testing.T) {
	req := rtuReadRequest(t, FunctionReadHoldingRegisters)
	stream := &productionStream{short: true}
	e := productionEndpoint(t, stream)
	_, _, err := e.Read(context.Background(), 1, req)
	if !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("fence=%v", err)
	}
	stream.short = false
	// This is a valid same-shape response for the retired generation. Recovery
	// must consume it before it creates generation two.
	stream.bytes = productionReadResponse(t, 1, req, []uint16{9, 9, 9})
	if err := e.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	stream.bytes = productionReadResponse(t, 1, req, []uint16{2, 2, 2})
	got, evidence, err := e.Read(context.Background(), 1, req)
	if err != nil || evidence.Generation != 2 || got.Words[0] != 2 {
		t.Fatalf("successor=%v %#v %#v", err, got, evidence)
	}
}

func TestRTUProductionRejectsRecoveryBoundsAndNoByteTimeout(t *testing.T) {
	serial := RTUSerialConfig{Path: "configured", Baud: 9600, DataBits: 8, Parity: RTUParityEven, StopBits: 1}
	for _, quiescence := range []time.Duration{30 * time.Millisecond, 61 * time.Second} {
		timing, err := NewRTUTiming(RTUTimingConfig{Baud: 9600, DataBits: 8, Parity: RTUParityEven, StopBits: 1, MaxResponseLatency: 20 * time.Millisecond, MaxQuiescence: quiescence})
		if err != nil {
			t.Fatal(err)
		}
		stream := &productionStream{}
		if _, err := newRTUProductionEndpoint(RTUProductionConfig{Endpoint: "rtu-a", Serial: serial, Timing: timing, ResponseTimeout: 20 * time.Millisecond, Enabled: true, Admission: productionAdmission(true)}, stream); err == nil {
			t.Fatalf("quiescence %s accepted", quiescence)
		}
		if len(stream.writes) != 0 {
			t.Fatal("invalid recovery bound wrote")
		}
	}
	stream := &productionStream{}
	e := productionEndpoint(t, stream)
	_, evidence, err := e.Read(context.Background(), 1, rtuReadRequest(t, FunctionReadHoldingRegisters))
	if err == nil || !evidence.ReceiptWall.IsZero() || evidence.Current {
		t.Fatalf("timeout=%v %#v", err, evidence)
	}
}

func TestRTUTimingProductionReadHostAllowance(t *testing.T) {
	for _, baud := range []uint32{300, 9600, 115200} {
		timing := rtuTestTiming(t, baud)
		want := 20 * time.Millisecond
		if timing.InterCharacter() > want {
			want = timing.InterCharacter()
		}
		if timing.readInterCharacter != want {
			t.Fatalf("baud=%d: host allowance=%s want=%s", baud, timing.readInterCharacter, want)
		}
	}
	config := RTUTimingConfig{Baud: 115200, DataBits: 8, Parity: RTUParityNone, StopBits: 1,
		InterCharacterSafety: 30 * time.Millisecond, InterFrameSafety: 40 * time.Millisecond,
		MaxResponseLatency: time.Second, MaxQuiescence: 2 * time.Second}
	timing, err := NewRTUTiming(config)
	if err != nil {
		t.Fatal(err)
	}
	if timing.readInterCharacter != config.InterCharacterSafety || timing.InterCharacter() != config.InterCharacterSafety || timing.InterFrame() != config.InterFrameSafety {
		t.Fatal("explicit timing overrides lost")
	}
}
