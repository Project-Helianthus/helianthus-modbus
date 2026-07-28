package modbus

import (
	"bytes"
	"context"
	"encoding/hex"
	"math"
	"sync"
	"testing"
	"time"
)

type recordingRTUEventSink struct {
	mu     sync.Mutex
	events []RTUEvent
}

type rtuEventSinkFunc func(RTUEvent)

func (sink rtuEventSinkFunc) RecordRTUEvent(event RTUEvent) {
	sink(event)
}

func (sink *recordingRTUEventSink) RecordRTUEvent(event RTUEvent) {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	sink.events = append(sink.events, event)
}

func (sink *recordingRTUEventSink) snapshot() []RTUEvent {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	return append([]RTUEvent(nil), sink.events...)
}

func newRTUTestEndpoint(
	t *testing.T,
) (*RTUFixtureEndpoint, *virtualTCPClock, *recordingRTUEventSink) {
	t.Helper()
	clock := &virtualTCPClock{}
	sink := &recordingRTUEventSink{}
	line, err := NewRTUFixtureLine("fixture-line-1")
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := NewRTUFixtureEndpoint(RTUFixtureEndpointConfig{
		Endpoint:           "fixture-endpoint-1",
		Line:               line,
		Timing:             rtuTestTiming(t, 9600),
		Clock:              clock,
		EventSink:          sink,
		FixtureOptIn:       true,
		MaxDiscardedFrames: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	return endpoint, clock, sink
}

func rtuTestPlan(t *testing.T) RTUReadPlan {
	t.Helper()
	return RTUReadPlan{
		UnitID:             1,
		AuthorizationScope: "scope-a",
		PollGeneration:     7,
		DeadlineIdentity:   9,
		LogicalViewID:      11,
		Timeout:            50 * time.Millisecond,
		Request:            rtuReadRequest(t, FunctionReadHoldingRegisters),
	}
}

func beginRTUTestRead(
	t *testing.T,
	endpoint *RTUFixtureEndpoint,
) RTURequestHandle {
	t.Helper()
	handle, frame, err := endpoint.BeginRead(context.Background(), rtuTestPlan(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(frame) == 0 {
		t.Fatal("fixture request frame is empty")
	}
	return handle
}

func observeRTUTestFrame(
	endpoint *RTUFixtureEndpoint,
	clock *virtualTCPClock,
	frame []byte,
) (RTUReadResult, error) {
	for index, value := range frame {
		if index != 0 {
			clock.Advance(endpoint.timing.CharacterTime())
		}
		if err := endpoint.FeedByte(value); err != nil {
			return RTUReadResult{}, err
		}
	}
	clock.Advance(endpoint.timing.InterFrame())
	return endpoint.EndFrame()
}

func TestRTUEndpointClaimsOneFixtureIdentity(t *testing.T) {
	clock := &virtualTCPClock{}
	line, err := NewRTUFixtureLine("claimed-line")
	if err != nil {
		t.Fatal(err)
	}
	config := RTUFixtureEndpointConfig{
		Endpoint:           "endpoint-a",
		Line:               line,
		Timing:             rtuTestTiming(t, 9600),
		Clock:              clock,
		FixtureOptIn:       true,
		MaxDiscardedFrames: 4,
	}
	first, err := NewRTUFixtureEndpoint(config)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = first.Close() }()
	config.Endpoint = "endpoint-b"
	if _, err := NewRTUFixtureEndpoint(config); err == nil {
		t.Fatal("duplicate fixture-line owner accepted")
	}
}

func TestRTUEndpointAllowsOnlyOneOutstandingExchange(t *testing.T) {
	endpoint, _, _ := newRTUTestEndpoint(t)
	defer func() { _ = endpoint.Close() }()
	beginRTUTestRead(t, endpoint)
	if _, _, err := endpoint.BeginRead(
		context.Background(),
		rtuTestPlan(t),
	); err == nil {
		t.Fatal("concurrent RTU exchange accepted")
	}
}

func TestRTUEndpointRejectsImpossibleQuiescenceWindow(t *testing.T) {
	timing, err := NewRTUTiming(RTUTimingConfig{
		Baud:               9600,
		DataBits:           8,
		Parity:             RTUParityEven,
		StopBits:           1,
		MaxResponseLatency: 20 * time.Millisecond,
		MaxQuiescence:      21 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	line, err := NewRTUFixtureLine("invalid-quiescence")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewRTUFixtureEndpoint(RTUFixtureEndpointConfig{
		Endpoint:           "invalid-quiescence",
		Line:               line,
		Timing:             timing,
		Clock:              &virtualTCPClock{},
		FixtureOptIn:       true,
		MaxDiscardedFrames: 1,
	}); err == nil {
		t.Fatal("quiescence shorter than latency plus t3.5 accepted")
	}
}

func TestRTUProvableZeroNoAbandonment(t *testing.T) {
	endpoint, _, _ := newRTUTestEndpoint(t)
	defer func() { _ = endpoint.Close() }()
	handle := beginRTUTestRead(t, endpoint)
	if err := endpoint.CompleteTransmit(handle, TransmitProvableZero); err != nil {
		t.Fatal(err)
	}
	if endpoint.Snapshot().State() != RTUStateIdle {
		t.Fatalf("state = %s", endpoint.Snapshot().State())
	}
	if _, _, err := endpoint.BeginRead(
		context.Background(),
		rtuTestPlan(t),
	); err != nil {
		t.Fatal(err)
	}
}

func TestRTUProvableZeroRetainsTerminalDeadlineCause(t *testing.T) {
	endpoint, clock, sink := newRTUTestEndpoint(t)
	defer func() { _ = endpoint.Close() }()
	plan := rtuTestPlan(t)
	plan.Timeout = time.Millisecond
	handle, _, err := endpoint.BeginRead(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	clock.Advance(plan.Timeout)
	if err := endpoint.CompleteTransmit(
		handle,
		TransmitProvableZero,
	); err != nil {
		t.Fatal(err)
	}
	events := sink.snapshot()
	if len(events) < 3 ||
		events[2].Kind != RTUEventWaiterResolved ||
		events[2].Detail != "timeout_before_provable_zero" {
		t.Fatalf("events = %#v", events)
	}
	if endpoint.Snapshot().State() != RTUStateIdle {
		t.Fatalf("state = %s", endpoint.Snapshot().State())
	}
}

func testRTUUnsafeTransmitResult(t *testing.T, result TransmitResult) {
	t.Helper()
	endpoint, _, sink := newRTUTestEndpoint(t)
	defer func() { _ = endpoint.Close() }()
	handle := beginRTUTestRead(t, endpoint)
	if err := endpoint.CompleteTransmit(handle, result); err != nil {
		t.Fatal(err)
	}
	if endpoint.Snapshot().State() != RTUStateQuarantine {
		t.Fatalf("state = %s", endpoint.Snapshot().State())
	}
	events := sink.snapshot()
	quarantine := -1
	resolved := -1
	for index, event := range events {
		switch event.Kind {
		case RTUEventQuarantineTransition:
			quarantine = index
		case RTUEventWaiterResolved:
			resolved = index
		}
	}
	if quarantine < 0 || resolved < 0 || quarantine >= resolved {
		t.Fatalf("event order = %#v", events)
	}
}

func TestRTUPartialWriteQuarantine(t *testing.T) {
	testRTUUnsafeTransmitResult(t, TransmitPartial)
}

func TestRTUIndeterminateErrorQuarantine(t *testing.T) {
	testRTUUnsafeTransmitResult(t, TransmitIndeterminate)
}

func TestRTUCancellationRaceQuarantine(t *testing.T) {
	testRTUUnsafeTransmitResult(t, TransmitCancellationRace)
}

func TestRTUAmbiguousCompletionQuarantine(t *testing.T) {
	testRTUUnsafeTransmitResult(t, TransmitAmbiguous)
}

func testRTUFullTransmitAbandonment(t *testing.T, reason AbandonReason) {
	t.Helper()
	endpoint, _, _ := newRTUTestEndpoint(t)
	defer func() { _ = endpoint.Close() }()
	handle := beginRTUTestRead(t, endpoint)
	if err := endpoint.CompleteTransmit(handle, TransmitComplete); err != nil {
		t.Fatal(err)
	}
	if err := endpoint.Abandon(handle, reason); err != nil {
		t.Fatal(err)
	}
	if endpoint.Snapshot().State() != RTUStateQuarantine {
		t.Fatalf("state = %s", endpoint.Snapshot().State())
	}
}

func TestRTUFullTransmitTimeoutQuarantine(t *testing.T) {
	testRTUFullTransmitAbandonment(t, AbandonTimeout)
}

func TestRTUFullTransmitCancellationQuarantine(t *testing.T) {
	testRTUFullTransmitAbandonment(t, AbandonCancellation)
}

func TestRTUTickOwnsCancellationDuringWrite(t *testing.T) {
	endpoint, _, sink := newRTUTestEndpoint(t)
	defer func() { _ = endpoint.Close() }()
	ctx, cancel := context.WithCancel(context.Background())
	handle, _, err := endpoint.BeginRead(ctx, rtuTestPlan(t))
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := endpoint.Tick(); err != nil {
		t.Fatal(err)
	}
	if endpoint.Snapshot().State() != RTUStateQuarantine {
		t.Fatalf("state = %s", endpoint.Snapshot().State())
	}
	events := sink.snapshot()
	if len(events) < 4 ||
		events[1].Kind != RTUEventTransmitResult ||
		events[1].TransmitResult != TransmitCancellationRace ||
		events[2].Kind != RTUEventQuarantineTransition ||
		events[3].Kind != RTUEventWaiterResolved {
		t.Fatalf("events = %#v", events)
	}
	if err := endpoint.CompleteTransmit(handle, TransmitComplete); err == nil {
		t.Fatal("late write completion escaped quarantine")
	}
}

func TestRTUTickOwnsDeadlineDuringWrite(t *testing.T) {
	endpoint, clock, sink := newRTUTestEndpoint(t)
	defer func() { _ = endpoint.Close() }()
	plan := rtuTestPlan(t)
	plan.Timeout = time.Millisecond
	if _, _, err := endpoint.BeginRead(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	clock.Advance(plan.Timeout)
	if err := endpoint.Tick(); err != nil {
		t.Fatal(err)
	}
	if endpoint.Snapshot().State() != RTUStateQuarantine {
		t.Fatalf("state = %s", endpoint.Snapshot().State())
	}
	events := sink.snapshot()
	if len(events) < 4 ||
		events[1].TransmitResult != TransmitAmbiguous ||
		events[1].Detail != "deadline_during_write" {
		t.Fatalf("events = %#v", events)
	}
}

func TestRTUTickOwnsTimeoutAfterFullTransmit(t *testing.T) {
	endpoint, clock, _ := newRTUTestEndpoint(t)
	defer func() { _ = endpoint.Close() }()
	plan := rtuTestPlan(t)
	plan.Timeout = 10 * time.Millisecond
	handle, _, err := endpoint.BeginRead(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := endpoint.CompleteTransmit(handle, TransmitComplete); err != nil {
		t.Fatal(err)
	}
	clock.Advance(plan.Timeout)
	if err := endpoint.Tick(); err != nil {
		t.Fatal(err)
	}
	if endpoint.Snapshot().State() != RTUStateQuarantine {
		t.Fatalf("state = %s", endpoint.Snapshot().State())
	}
}

func TestRTUTickOwnsCancellationAfterFullTransmit(t *testing.T) {
	endpoint, _, _ := newRTUTestEndpoint(t)
	defer func() { _ = endpoint.Close() }()
	ctx, cancel := context.WithCancel(context.Background())
	handle, _, err := endpoint.BeginRead(ctx, rtuTestPlan(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := endpoint.CompleteTransmit(handle, TransmitComplete); err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := endpoint.Tick(); err != nil {
		t.Fatal(err)
	}
	if endpoint.Snapshot().State() != RTUStateQuarantine {
		t.Fatalf("state = %s", endpoint.Snapshot().State())
	}
}

func TestRTUExpiredResponseCannotBeatTick(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		expire func(*virtualTCPClock, context.CancelFunc, time.Duration)
	}{
		{
			name: "deadline",
			expire: func(
				clock *virtualTCPClock,
				_ context.CancelFunc,
				timeout time.Duration,
			) {
				clock.Advance(timeout)
			},
		},
		{
			name: "cancellation",
			expire: func(
				_ *virtualTCPClock,
				cancel context.CancelFunc,
				_ time.Duration,
			) {
				cancel()
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			endpoint, clock, _ := newRTUTestEndpoint(t)
			defer func() { _ = endpoint.Close() }()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			plan := rtuTestPlan(t)
			plan.Timeout = 10 * time.Millisecond
			handle, _, err := endpoint.BeginRead(ctx, plan)
			if err != nil {
				t.Fatal(err)
			}
			if err := endpoint.CompleteTransmit(
				handle,
				TransmitComplete,
			); err != nil {
				t.Fatal(err)
			}
			testCase.expire(clock, cancel, plan.Timeout)
			result, err := observeRTUTestFrame(
				endpoint,
				clock,
				rtuTestFrame(1, 0x03, 0x06, 0, 1, 0, 2, 0, 3),
			)
			if !IsRTUFrameDiscarded(err) {
				t.Fatalf("error = %v", err)
			}
			if result.Deliverable() {
				t.Fatal("expired response became deliverable")
			}
			if endpoint.Snapshot().State() != RTUStateQuarantine {
				t.Fatalf("state = %s", endpoint.Snapshot().State())
			}
		})
	}
}

func TestRTUExpiredCompleteTransmitEntersQuarantine(t *testing.T) {
	endpoint, clock, _ := newRTUTestEndpoint(t)
	defer func() { _ = endpoint.Close() }()
	plan := rtuTestPlan(t)
	plan.Timeout = time.Millisecond
	handle, _, err := endpoint.BeginRead(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	clock.Advance(plan.Timeout)
	if err := endpoint.CompleteTransmit(handle, TransmitComplete); err != nil {
		t.Fatal(err)
	}
	if endpoint.Snapshot().State() != RTUStateQuarantine {
		t.Fatalf("state = %s", endpoint.Snapshot().State())
	}
}

func TestRTULateSameShapeFrameIsDiscarded(t *testing.T) {
	endpoint, clock, _ := newRTUTestEndpoint(t)
	defer func() { _ = endpoint.Close() }()
	handle := beginRTUTestRead(t, endpoint)
	if err := endpoint.CompleteTransmit(handle, TransmitComplete); err != nil {
		t.Fatal(err)
	}
	if err := endpoint.Abandon(handle, AbandonTimeout); err != nil {
		t.Fatal(err)
	}
	result, err := observeRTUTestFrame(
		endpoint,
		clock,
		rtuTestFrame(1, 0x03, 0x06, 0, 1, 0, 2, 0, 3),
	)
	if err == nil || !IsRTUFrameDiscarded(err) {
		t.Fatalf("discard error = %v", err)
	}
	if result.Deliverable() {
		t.Fatal("late same-shape frame became deliverable")
	}
	if endpoint.Snapshot().DiscardedFrames() != 1 {
		t.Fatalf("discard count = %d", endpoint.Snapshot().DiscardedFrames())
	}
}

func TestRTUQuarantineReleaseRequiresLatencyAndIdleProof(t *testing.T) {
	endpoint, clock, _ := newRTUTestEndpoint(t)
	defer func() { _ = endpoint.Close() }()
	handle := beginRTUTestRead(t, endpoint)
	if err := endpoint.CompleteTransmit(handle, TransmitComplete); err != nil {
		t.Fatal(err)
	}
	if err := endpoint.Abandon(handle, AbandonTimeout); err != nil {
		t.Fatal(err)
	}
	timing := rtuTestTiming(t, 9600)
	clock.Advance(timing.MaxResponseLatency())
	if err := endpoint.TryResynchronize(); err == nil {
		t.Fatal("latency alone released quarantine")
	}
	clock.Advance(timing.InterFrame())
	if err := endpoint.TryResynchronize(); err != nil {
		t.Fatal(err)
	}
	if endpoint.Snapshot().State() != RTUStateIdle {
		t.Fatalf("state = %s", endpoint.Snapshot().State())
	}
}

func TestRTULastDiscardedByteRestartsIdleProof(t *testing.T) {
	endpoint, clock, _ := newRTUTestEndpoint(t)
	defer func() { _ = endpoint.Close() }()
	handle := beginRTUTestRead(t, endpoint)
	if err := endpoint.CompleteTransmit(handle, TransmitComplete); err != nil {
		t.Fatal(err)
	}
	if err := endpoint.Abandon(handle, AbandonTimeout); err != nil {
		t.Fatal(err)
	}
	timing := rtuTestTiming(t, 9600)
	clock.Advance(timing.MaxResponseLatency())
	if err := endpoint.FeedByte(0xff); err != nil {
		t.Fatal(err)
	}
	clock.Advance(timing.InterFrame() - 1)
	if err := endpoint.TryResynchronize(); err == nil {
		t.Fatal("idle proof ignored last discarded byte")
	}
	clock.Advance(1)
	if err := endpoint.TryResynchronize(); err != nil {
		t.Fatal(err)
	}
}

func TestRTUBytesBufferedBeforeAbandonmentExtendIdleProof(t *testing.T) {
	endpoint, clock, _ := newRTUTestEndpoint(t)
	defer func() { _ = endpoint.Close() }()
	plan := rtuTestPlan(t)
	handle, _, err := endpoint.BeginRead(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := endpoint.CompleteTransmit(handle, TransmitComplete); err != nil {
		t.Fatal(err)
	}
	clock.Advance(plan.Timeout - time.Millisecond)
	if err := endpoint.FeedByte(1); err != nil {
		t.Fatal(err)
	}
	clock.Advance(time.Millisecond)
	if err := endpoint.Tick(); err != nil {
		t.Fatal(err)
	}
	if err := endpoint.TryResynchronize(); err == nil {
		t.Fatal("pre-abandonment byte did not extend idle proof")
	}
	clock.Advance(endpoint.timing.InterFrame())
	if err := endpoint.TryResynchronize(); err != nil {
		t.Fatal(err)
	}
}

func TestRTUMalformedBytesBeforeAbandonmentExtendIdleProof(t *testing.T) {
	endpoint, clock, _ := newRTUTestEndpoint(t)
	defer func() { _ = endpoint.Close() }()
	plan := rtuTestPlan(t)
	handle, _, err := endpoint.BeginRead(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := endpoint.CompleteTransmit(handle, TransmitComplete); err != nil {
		t.Fatal(err)
	}
	clock.Advance(plan.Timeout - 2*endpoint.timing.InterCharacter())
	if err := endpoint.FeedByte(1); err != nil {
		t.Fatal(err)
	}
	clock.Advance(endpoint.timing.InterCharacter() + 1)
	if err := endpoint.FeedByte(2); err == nil {
		t.Fatal("malformed inter-character gap accepted")
	}
	clock.Advance(endpoint.timing.InterCharacter() - 1)
	if err := endpoint.Tick(); err != nil {
		t.Fatal(err)
	}
	if err := endpoint.TryResynchronize(); err == nil {
		t.Fatal("malformed pre-abandonment bytes did not extend idle proof")
	}
	clock.Advance(endpoint.timing.InterFrame())
	if err := endpoint.TryResynchronize(); err != nil {
		t.Fatal(err)
	}
}

func TestRTUResponseWaitRequiresT35AfterDecoderRejection(t *testing.T) {
	endpoint, clock, _ := newRTUTestEndpoint(t)
	defer func() { _ = endpoint.Close() }()
	plan := rtuTestPlan(t)
	plan.Timeout = 500 * time.Millisecond
	handle, _, err := endpoint.BeginRead(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := endpoint.CompleteTransmit(handle, TransmitComplete); err != nil {
		t.Fatal(err)
	}
	if err := endpoint.FeedByte(1); err != nil {
		t.Fatal(err)
	}
	clock.Advance(endpoint.timing.InterCharacter() + 1)
	if err := endpoint.FeedByte(2); err == nil {
		t.Fatal("inter-character violation accepted")
	}
	frame := rtuTestFrame(1, 0x03, 0x06, 0, 1, 0, 2, 0, 3)
	for _, value := range frame {
		clock.Advance(endpoint.timing.CharacterTime())
		if err := endpoint.FeedByte(value); err == nil {
			t.Fatal("frame byte accepted before t3.5 resynchronization")
		}
	}
	clock.Advance(endpoint.timing.InterFrame())
	if result, err := endpoint.EndFrame(); err == nil ||
		result.WireResponse().WireResponseID() != 0 {
		t.Fatalf("poisoned result = %#v error = %v", result, err)
	}
	for index, value := range frame {
		if index != 0 {
			clock.Advance(endpoint.timing.CharacterTime())
		}
		if err := endpoint.FeedByte(value); err != nil {
			t.Fatal(err)
		}
	}
	clock.Advance(endpoint.timing.InterFrame())
	result, err := endpoint.EndFrame()
	if err != nil || !result.Deliverable() {
		t.Fatalf("resynchronized result = %#v error = %v", result, err)
	}
}

func TestRTUQuiescenceFailureRequiresExplicitRecovery(t *testing.T) {
	endpoint, _, _ := newRTUTestEndpoint(t)
	defer func() { _ = endpoint.Close() }()
	handle := beginRTUTestRead(t, endpoint)
	if err := endpoint.CompleteTransmit(handle, TransmitPartial); err != nil {
		t.Fatal(err)
	}
	if err := endpoint.FailQuiescence(); err != nil {
		t.Fatal(err)
	}
	before := endpoint.Snapshot().Generation()
	if endpoint.Snapshot().State() != RTUStateRecoveryRequired {
		t.Fatalf("state = %s", endpoint.Snapshot().State())
	}
	if _, _, err := endpoint.BeginRead(
		context.Background(),
		rtuTestPlan(t),
	); err == nil {
		t.Fatal("recovery-required endpoint admitted request")
	}
	if err := endpoint.Recover(); err != nil {
		t.Fatal(err)
	}
	after := endpoint.Snapshot().Generation()
	if after != before+1 {
		t.Fatalf("generation = %d, want %d", after, before+1)
	}
	if CurrentRTUCapability().Disposition() != RTUFixtureOnlyNoHardware {
		t.Fatal("recovery upgraded RTU disposition")
	}
}

func TestRTUQuiescenceBoundFailsClosed(t *testing.T) {
	endpoint, clock, _ := newRTUTestEndpoint(t)
	defer func() { _ = endpoint.Close() }()
	handle := beginRTUTestRead(t, endpoint)
	if err := endpoint.CompleteTransmit(handle, TransmitPartial); err != nil {
		t.Fatal(err)
	}
	timing := rtuTestTiming(t, 9600)
	horizon, err := timing.FrameTransmitHorizon(8)
	if err != nil {
		t.Fatal(err)
	}
	clock.Advance(horizon + timing.MaxQuiescence() + 1)
	if err := endpoint.TryResynchronize(); err == nil {
		t.Fatal("expired quiescence bound returned endpoint to service")
	}
	if endpoint.Snapshot().State() != RTUStateRecoveryRequired {
		t.Fatalf("state = %s", endpoint.Snapshot().State())
	}
}

func TestRTUTickOwnsQuiescenceExpiry(t *testing.T) {
	endpoint, clock, _ := newRTUTestEndpoint(t)
	defer func() { _ = endpoint.Close() }()
	handle := beginRTUTestRead(t, endpoint)
	if err := endpoint.CompleteTransmit(handle, TransmitPartial); err != nil {
		t.Fatal(err)
	}
	horizon, err := endpoint.timing.FrameTransmitHorizon(8)
	if err != nil {
		t.Fatal(err)
	}
	clock.Advance(horizon + endpoint.timing.MaxQuiescence() + 1)
	if err := endpoint.Tick(); err == nil {
		t.Fatal("expired quiescence remained in quarantine")
	}
	if endpoint.Snapshot().State() != RTUStateRecoveryRequired {
		t.Fatalf("state = %s", endpoint.Snapshot().State())
	}
}

func TestRTUReceiveOperationsCannotBeatQuiescenceExpiry(t *testing.T) {
	t.Run("feed_byte", func(t *testing.T) {
		endpoint, clock, _ := newRTUTestEndpoint(t)
		defer func() { _ = endpoint.Close() }()
		handle := beginRTUTestRead(t, endpoint)
		if err := endpoint.CompleteTransmit(handle, TransmitPartial); err != nil {
			t.Fatal(err)
		}
		horizon, err := endpoint.timing.FrameTransmitHorizon(8)
		if err != nil {
			t.Fatal(err)
		}
		clock.Advance(horizon + endpoint.timing.MaxQuiescence() + 1)
		if err := endpoint.FeedByte(1); err == nil {
			t.Fatal("byte accepted after quiescence expiry")
		}
		if endpoint.Snapshot().State() != RTUStateRecoveryRequired {
			t.Fatalf("state = %s", endpoint.Snapshot().State())
		}
	})
	t.Run("end_frame", func(t *testing.T) {
		endpoint, clock, _ := newRTUTestEndpoint(t)
		defer func() { _ = endpoint.Close() }()
		handle := beginRTUTestRead(t, endpoint)
		if err := endpoint.CompleteTransmit(handle, TransmitComplete); err != nil {
			t.Fatal(err)
		}
		if err := endpoint.Abandon(handle, AbandonTimeout); err != nil {
			t.Fatal(err)
		}
		if err := endpoint.FeedByte(1); err != nil {
			t.Fatal(err)
		}
		clock.Advance(endpoint.timing.MaxQuiescence() + 1)
		if _, err := endpoint.EndFrame(); err == nil {
			t.Fatal("frame ended after quiescence expiry")
		}
		if endpoint.Snapshot().State() != RTUStateRecoveryRequired {
			t.Fatalf("state = %s", endpoint.Snapshot().State())
		}
	})
}

func TestRTUQuiescenceBoundaryIsExact(t *testing.T) {
	t.Run("exact_bound_releases", func(t *testing.T) {
		endpoint, clock, _ := newRTUTestEndpoint(t)
		defer func() { _ = endpoint.Close() }()
		handle := beginRTUTestRead(t, endpoint)
		if err := endpoint.CompleteTransmit(handle, TransmitComplete); err != nil {
			t.Fatal(err)
		}
		if err := endpoint.Abandon(handle, AbandonTimeout); err != nil {
			t.Fatal(err)
		}
		clock.Advance(rtuTestTiming(t, 9600).MaxQuiescence())
		if err := endpoint.TryResynchronize(); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("after_bound_requires_recovery", func(t *testing.T) {
		endpoint, clock, _ := newRTUTestEndpoint(t)
		defer func() { _ = endpoint.Close() }()
		handle := beginRTUTestRead(t, endpoint)
		if err := endpoint.CompleteTransmit(handle, TransmitComplete); err != nil {
			t.Fatal(err)
		}
		if err := endpoint.Abandon(handle, AbandonTimeout); err != nil {
			t.Fatal(err)
		}
		clock.Advance(rtuTestTiming(t, 9600).MaxQuiescence() + 1)
		if err := endpoint.TryResynchronize(); err == nil {
			t.Fatal("expired quiescence bound released")
		}
		if endpoint.Snapshot().State() != RTUStateRecoveryRequired {
			t.Fatalf("state = %s", endpoint.Snapshot().State())
		}
	})
}

func TestRTUQuarantineDeadlineOverflowFailsClosed(t *testing.T) {
	endpoint, clock, sink := newRTUTestEndpoint(t)
	defer func() { _ = endpoint.Close() }()
	clock.mu.Lock()
	clock.now = time.Duration(math.MaxInt64) - 20*time.Millisecond
	clock.mu.Unlock()
	plan := rtuTestPlan(t)
	plan.Timeout = time.Millisecond
	handle, _, err := endpoint.BeginRead(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := endpoint.CompleteTransmit(handle, TransmitPartial); err == nil {
		t.Fatal("overflowing quarantine deadline accepted")
	}
	if endpoint.Snapshot().State() != RTUStateRecoveryRequired {
		t.Fatalf("state = %s", endpoint.Snapshot().State())
	}
	if err := endpoint.Recover(); err != nil {
		t.Fatal(err)
	}
	events := sink.snapshot()
	if len(events) != 3 ||
		events[0].Sequence != 1 ||
		events[1].Sequence != 2 ||
		events[1].Kind != RTUEventRecoveryRequired ||
		events[1].Detail != "latency_deadline" ||
		events[2].Sequence != 3 ||
		events[2].Kind != RTUEventRecovered {
		t.Fatalf("events = %#v", events)
	}
}

func TestRTUGuardOverflowDoesNotConsumeWireIdentity(t *testing.T) {
	endpoint, clock, _ := newRTUTestEndpoint(t)
	defer func() { _ = endpoint.Close() }()
	clock.mu.Lock()
	clock.now = time.Duration(math.MaxInt64) - 10*time.Millisecond
	clock.mu.Unlock()
	plan := rtuTestPlan(t)
	plan.Timeout = 9 * time.Millisecond
	handle, _, err := endpoint.BeginRead(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := endpoint.CompleteTransmit(handle, TransmitComplete); err != nil {
		t.Fatal(err)
	}
	if _, err := observeRTUTestFrame(
		endpoint,
		clock,
		rtuTestFrame(1, 0x83, 0x02),
	); err == nil {
		t.Fatal("overflowing inter-frame guard accepted")
	}
	if endpoint.Snapshot().State() != RTUStateRecoveryRequired {
		t.Fatalf("state = %s", endpoint.Snapshot().State())
	}
	endpoint.mu.Lock()
	nextWire := endpoint.nextWireResponseID
	endpoint.mu.Unlock()
	if nextWire != 1 {
		t.Fatalf("next wire response ID = %d", nextWire)
	}
}

func TestRTUUnsafeAnchorIncludesFullTransmitHorizon(t *testing.T) {
	endpoint, clock, _ := newRTUTestEndpoint(t)
	defer func() { _ = endpoint.Close() }()
	handle := beginRTUTestRead(t, endpoint)
	if err := endpoint.CompleteTransmit(handle, TransmitPartial); err != nil {
		t.Fatal(err)
	}
	timing := rtuTestTiming(t, 9600)
	clock.Advance(timing.MaxResponseLatency() + timing.InterFrame())
	if err := endpoint.TryResynchronize(); err == nil {
		t.Fatal("quarantine ignored conservative transmit horizon")
	}
	horizon, err := timing.FrameTransmitHorizon(8)
	if err != nil {
		t.Fatal(err)
	}
	clock.Advance(horizon)
	if err := endpoint.TryResynchronize(); err != nil {
		t.Fatal(err)
	}
}

func TestRTUNormalSuccessHonorsInterFrameGuard(t *testing.T) {
	endpoint, clock, _ := newRTUTestEndpoint(t)
	defer func() { _ = endpoint.Close() }()
	handle := beginRTUTestRead(t, endpoint)
	if err := endpoint.CompleteTransmit(handle, TransmitComplete); err != nil {
		t.Fatal(err)
	}
	result, err := observeRTUTestFrame(
		endpoint,
		clock,
		rtuTestFrame(1, 0x03, 0x06, 0, 1, 0, 2, 0, 3),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Deliverable() {
		t.Fatal("valid response not deliverable")
	}
	wire := result.WireResponse()
	if wire.Provenance().Transport != TransportRTU ||
		wire.PhysicalRequestID() != handle.RequestID() ||
		wire.WireResponseID() == 0 {
		t.Fatalf("wire provenance = %#v", wire)
	}
	view, ok := result.LogicalView()
	if !ok ||
		view.WireResponseID() != wire.WireResponseID() ||
		view.Provenance().Wire.Transport != TransportRTU {
		t.Fatalf("logical view = %#v", view)
	}
	if endpoint.Snapshot().State() != RTUStateInterFrameGuard {
		t.Fatalf("state = %s", endpoint.Snapshot().State())
	}
	if _, _, err := endpoint.BeginRead(
		context.Background(),
		rtuTestPlan(t),
	); err == nil {
		t.Fatal("successor admitted during t3.5 guard")
	}
	clock.Advance(rtuTestTiming(t, 9600).InterFrame())
	if err := endpoint.TryResynchronize(); err != nil {
		t.Fatal(err)
	}
}

func TestRTUInterFrameActivityRestartsGuard(t *testing.T) {
	endpoint, clock, sink := newRTUTestEndpoint(t)
	defer func() { _ = endpoint.Close() }()
	handle := beginRTUTestRead(t, endpoint)
	if err := endpoint.CompleteTransmit(handle, TransmitComplete); err != nil {
		t.Fatal(err)
	}
	if _, err := observeRTUTestFrame(
		endpoint,
		clock,
		rtuTestFrame(1, 0x03, 0x06, 0, 1, 0, 2, 0, 3),
	); err != nil {
		t.Fatal(err)
	}
	halfGuard := endpoint.timing.InterFrame() / 2
	clock.Advance(halfGuard)
	if err := endpoint.FeedByte(0xff); !IsRTUFrameDiscarded(err) {
		t.Fatalf("guard activity error = %v", err)
	}
	clock.Advance(endpoint.timing.InterFrame() - halfGuard)
	if err := endpoint.TryResynchronize(); err == nil {
		t.Fatal("guard activity did not restart t3.5")
	}
	clock.Advance(halfGuard)
	if err := endpoint.TryResynchronize(); err != nil {
		t.Fatal(err)
	}
	events := sink.snapshot()
	found := false
	for _, event := range events {
		if event.Kind == RTUEventFrameDiscarded &&
			event.RequestID == handle.RequestID() &&
			event.Detail == "inter_frame_guard_activity" {
			found = true
		}
	}
	if !found {
		t.Fatalf("events = %#v", events)
	}
}

func TestRTUCorrelatedCRCFailureRetainsWireIdentity(t *testing.T) {
	endpoint, clock, sink := newRTUTestEndpoint(t)
	defer func() { _ = endpoint.Close() }()
	handle := beginRTUTestRead(t, endpoint)
	if err := endpoint.CompleteTransmit(handle, TransmitComplete); err != nil {
		t.Fatal(err)
	}
	frame := rtuTestFrame(1, 0x03, 0x06, 0, 1, 0, 2, 0, 3)
	frame[len(frame)-1] ^= 0xff
	result, err := observeRTUTestFrame(endpoint, clock, frame)
	_ = requireProtocolError(t, err, ErrorMalformedResponse)
	wire := result.WireResponse()
	if result.Deliverable() ||
		wire.Outcome() != WireMalformedResponse ||
		wire.WireResponseID() == 0 ||
		wire.PhysicalRequestID() != handle.RequestID() ||
		!bytes.Equal(wire.Bytes(), frame) {
		t.Fatalf("result = %#v wire = %#v", result, wire)
	}
	if _, ok := result.LogicalView(); ok {
		t.Fatal("CRC-invalid response produced a logical view")
	}
	if endpoint.Snapshot().State() != RTUStateInterFrameGuard {
		t.Fatalf("state = %s", endpoint.Snapshot().State())
	}
	events := sink.snapshot()
	last := events[len(events)-1]
	if last.Kind != RTUEventResponseReceive ||
		last.WireResponseID != wire.WireResponseID() ||
		last.WireOutcome != WireMalformedResponse ||
		last.ResponseADUHex != hex.EncodeToString(frame) {
		t.Fatalf("event = %#v", last)
	}
}

func TestRTUUncorrelatedFramesRetainDiagnosticIdentity(t *testing.T) {
	endpoint, clock, sink := newRTUTestEndpoint(t)
	defer func() { _ = endpoint.Close() }()
	handle := beginRTUTestRead(t, endpoint)
	if err := endpoint.CompleteTransmit(handle, TransmitComplete); err != nil {
		t.Fatal(err)
	}
	frames := [][]byte{
		rtuTestFrame(2, 0x03, 0x02, 0, 1),
		rtuTestFrame(1, 0x04, 0x02, 0, 1),
	}
	var previousID uint64
	for _, frame := range frames {
		result, err := observeRTUTestFrame(endpoint, clock, frame)
		_ = requireProtocolError(t, err, ErrorMalformedResponse)
		wire := result.WireResponse()
		diagnostic := wire.DiagnosticProvenance()
		if result.Deliverable() ||
			wire.Outcome() != WireDroppedUncorrelated ||
			wire.WireResponseID() != 0 ||
			wire.PhysicalRequestID() != 0 ||
			wire.DiagnosticFrameID() == 0 ||
			wire.DiagnosticFrameID() == previousID ||
			!bytes.Equal(wire.Bytes(), frame) ||
			diagnostic.Endpoint != "fixture-endpoint-1" ||
			diagnostic.ReceivedTransportGeneration != handle.Generation() ||
			diagnostic.ActiveTransportGeneration != handle.Generation() {
			t.Fatalf("result = %#v wire = %#v", result, wire)
		}
		previousID = wire.DiagnosticFrameID()
		if endpoint.Snapshot().State() != RTUStateResponseWait {
			t.Fatalf("state = %s", endpoint.Snapshot().State())
		}
	}
	events := sink.snapshot()
	diagnostics := 0
	for _, event := range events {
		if event.Kind == RTUEventResponseReceive &&
			event.WireOutcome == WireDroppedUncorrelated {
			diagnostics++
			if event.DiagnosticFrameID == 0 ||
				event.RequestID != 0 ||
				event.ResponseADUHex == "" {
				t.Fatalf("event = %#v", event)
			}
		}
	}
	if diagnostics != len(frames) {
		t.Fatalf("events = %#v", events)
	}
}

func TestRTUExceptionAndMalformedResponsesTerminalizeWithWireIdentity(
	t *testing.T,
) {
	for _, testCase := range []struct {
		name    string
		frame   []byte
		outcome WireOutcome
		kind    ErrorKind
	}{
		{
			name:    "exception",
			frame:   rtuTestFrame(1, 0x83, 0x02),
			outcome: WireProtocolException,
			kind:    ErrorExceptionResponse,
		},
		{
			name:    "malformed",
			frame:   rtuTestFrame(1, 0x03, 0x04, 0x00, 0x01),
			outcome: WireMalformedResponse,
			kind:    ErrorMalformedResponse,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			endpoint, clock, _ := newRTUTestEndpoint(t)
			defer func() { _ = endpoint.Close() }()
			handle := beginRTUTestRead(t, endpoint)
			if err := endpoint.CompleteTransmit(
				handle,
				TransmitComplete,
			); err != nil {
				t.Fatal(err)
			}
			result, err := observeRTUTestFrame(
				endpoint,
				clock,
				testCase.frame,
			)
			protocolErr := requireProtocolError(t, err, testCase.kind)
			if protocolErr.RequestedFunction !=
				FunctionReadHoldingRegisters {
				t.Fatalf("protocol error = %#v", protocolErr)
			}
			wire := result.WireResponse()
			if result.Deliverable() ||
				wire.Outcome() != testCase.outcome ||
				wire.WireResponseID() == 0 ||
				wire.PhysicalRequestID() != handle.RequestID() ||
				!bytes.Equal(wire.Bytes(), testCase.frame) {
				t.Fatalf("result = %#v wire = %#v", result, wire)
			}
			if endpoint.Snapshot().State() != RTUStateInterFrameGuard {
				t.Fatalf("state = %s", endpoint.Snapshot().State())
			}
		})
	}
}

func TestRTUClockRegressionFailsClosedWithoutEventGap(t *testing.T) {
	endpoint, clock, sink := newRTUTestEndpoint(t)
	defer func() { _ = endpoint.Close() }()
	clock.mu.Lock()
	clock.now = 100 * time.Millisecond
	clock.mu.Unlock()
	handle := beginRTUTestRead(t, endpoint)
	clock.mu.Lock()
	clock.now = 0
	clock.mu.Unlock()
	if err := endpoint.CompleteTransmit(handle, TransmitComplete); err == nil {
		t.Fatal("clock regression accepted")
	}
	if endpoint.Snapshot().State() != RTUStateRecoveryRequired {
		t.Fatalf("state = %s", endpoint.Snapshot().State())
	}
	clock.mu.Lock()
	clock.now = 100 * time.Millisecond
	clock.mu.Unlock()
	if err := endpoint.Recover(); err != nil {
		t.Fatal(err)
	}
	events := sink.snapshot()
	if len(events) != 3 ||
		events[0].Sequence != 1 ||
		events[1].Sequence != 2 ||
		events[2].Sequence != 3 ||
		events[1].Kind != RTUEventRecoveryRequired ||
		events[1].Detail != "clock_regression" ||
		events[2].Kind != RTUEventRecovered ||
		events[2].MonotonicOffset < events[0].MonotonicOffset {
		t.Fatalf("events = %#v", events)
	}
}

func TestRTUBufferedQuarantineBytesCannotReachSuccessor(t *testing.T) {
	endpoint, clock, _ := newRTUTestEndpoint(t)
	defer func() { _ = endpoint.Close() }()
	handle := beginRTUTestRead(t, endpoint)
	if err := endpoint.CompleteTransmit(handle, TransmitComplete); err != nil {
		t.Fatal(err)
	}
	if err := endpoint.Abandon(handle, AbandonTimeout); err != nil {
		t.Fatal(err)
	}
	frame := rtuTestFrame(1, 0x03, 0x06, 0, 1, 0, 2, 0, 3)
	for index, value := range frame {
		if index != 0 {
			clock.Advance(endpoint.timing.CharacterTime())
		}
		if err := endpoint.FeedByte(value); err != nil {
			t.Fatal(err)
		}
	}
	clock.Advance(
		endpoint.timing.MaxResponseLatency() +
			endpoint.timing.InterFrame(),
	)
	if err := endpoint.TryResynchronize(); err != nil {
		t.Fatal(err)
	}
	successor := beginRTUTestRead(t, endpoint)
	if err := endpoint.CompleteTransmit(
		successor,
		TransmitComplete,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := endpoint.EndFrame(); err == nil {
		t.Fatal("buffered predecessor frame reached successor")
	}
	if endpoint.Snapshot().State() != RTUStateResponseWait {
		t.Fatalf("state = %s", endpoint.Snapshot().State())
	}
	if result, err := observeRTUTestFrame(
		endpoint,
		clock,
		frame,
	); err != nil || !result.Deliverable() {
		t.Fatalf("successor result = %#v error = %v", result, err)
	}
}

func TestRTUDiscardBudgetResetsPerQuarantineEpisode(t *testing.T) {
	clock := &virtualTCPClock{}
	line, err := NewRTUFixtureLine("discard-budget")
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := NewRTUFixtureEndpoint(RTUFixtureEndpointConfig{
		Endpoint:           "discard-budget",
		Line:               line,
		Timing:             rtuTestTiming(t, 9600),
		Clock:              clock,
		FixtureOptIn:       true,
		MaxDiscardedFrames: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = endpoint.Close() }()
	frame := rtuTestFrame(1, 0x03, 0x06, 0, 1, 0, 2, 0, 3)
	for cycle := 0; cycle < 2; cycle++ {
		handle := beginRTUTestRead(t, endpoint)
		if err := endpoint.CompleteTransmit(
			handle,
			TransmitComplete,
		); err != nil {
			t.Fatal(err)
		}
		if err := endpoint.Abandon(handle, AbandonTimeout); err != nil {
			t.Fatal(err)
		}
		if _, err := observeRTUTestFrame(
			endpoint,
			clock,
			frame,
		); !IsRTUFrameDiscarded(err) {
			t.Fatalf("cycle %d discard error = %v", cycle, err)
		}
		if endpoint.Snapshot().State() != RTUStateQuarantine {
			t.Fatalf(
				"cycle %d state = %s",
				cycle,
				endpoint.Snapshot().State(),
			)
		}
		clock.Advance(endpoint.timing.MaxResponseLatency())
		if err := endpoint.TryResynchronize(); err != nil {
			t.Fatal(err)
		}
	}
	if endpoint.Snapshot().DiscardedFrames() != 2 {
		t.Fatalf("discarded = %d", endpoint.Snapshot().DiscardedFrames())
	}
}
func TestRTUEqualOffsetRaceUsesOwnerCallOrder(t *testing.T) {
	t.Run("response_first", func(t *testing.T) {
		endpoint, clock, _ := newRTUTestEndpoint(t)
		defer func() { _ = endpoint.Close() }()
		handle := beginRTUTestRead(t, endpoint)
		if err := endpoint.CompleteTransmit(handle, TransmitComplete); err != nil {
			t.Fatal(err)
		}
		if _, err := observeRTUTestFrame(
			endpoint,
			clock,
			rtuTestFrame(1, 0x03, 0x06, 0, 1, 0, 2, 0, 3),
		); err != nil {
			t.Fatal(err)
		}
		if err := endpoint.Abandon(handle, AbandonCancellation); err == nil {
			t.Fatal("completed response was abandoned")
		}
	})
	t.Run("abandon_first", func(t *testing.T) {
		endpoint, clock, _ := newRTUTestEndpoint(t)
		defer func() { _ = endpoint.Close() }()
		handle := beginRTUTestRead(t, endpoint)
		if err := endpoint.CompleteTransmit(handle, TransmitComplete); err != nil {
			t.Fatal(err)
		}
		if err := endpoint.Abandon(handle, AbandonCancellation); err != nil {
			t.Fatal(err)
		}
		if _, err := observeRTUTestFrame(
			endpoint,
			clock,
			rtuTestFrame(1, 0x03, 0x06, 0, 1, 0, 2, 0, 3),
		); !IsRTUFrameDiscarded(err) {
			t.Fatalf("late frame error = %v", err)
		}
	})
}

func TestRTUEventSinkCanInspectSnapshotAndPanicIsContained(t *testing.T) {
	clock := &virtualTCPClock{}
	line, err := NewRTUFixtureLine("event-line")
	if err != nil {
		t.Fatal(err)
	}
	var endpoint *RTUFixtureEndpoint
	sink := rtuEventSinkFunc(func(RTUEvent) {
		_ = endpoint.Snapshot()
		panic("fixture sink")
	})
	endpoint, err = NewRTUFixtureEndpoint(RTUFixtureEndpointConfig{
		Endpoint:           "event-endpoint",
		Line:               line,
		Timing:             rtuTestTiming(t, 9600),
		Clock:              clock,
		EventSink:          sink,
		FixtureOptIn:       true,
		MaxDiscardedFrames: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = endpoint.Close() }()
	if _, _, err := endpoint.BeginRead(
		context.Background(),
		rtuTestPlan(t),
	); err != nil {
		t.Fatal(err)
	}
	if endpoint.Snapshot().EventSinkPanics() != 1 {
		t.Fatalf("sink panics = %d", endpoint.Snapshot().EventSinkPanics())
	}
}

func TestRTUEventSinkCannotReenterEmitter(t *testing.T) {
	clock := &virtualTCPClock{}
	line, err := NewRTUFixtureLine("reentry-line")
	if err != nil {
		t.Fatal(err)
	}
	var endpoint *RTUFixtureEndpoint
	var reentryErr error
	sink := rtuEventSinkFunc(func(RTUEvent) {
		reentryErr = endpoint.Tick()
	})
	endpoint, err = NewRTUFixtureEndpoint(RTUFixtureEndpointConfig{
		Endpoint:           "reentry-endpoint",
		Line:               line,
		Timing:             rtuTestTiming(t, 9600),
		Clock:              clock,
		EventSink:          sink,
		FixtureOptIn:       true,
		MaxDiscardedFrames: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = endpoint.Close() }()
	if _, _, err := endpoint.BeginRead(
		context.Background(),
		rtuTestPlan(t),
	); err != nil {
		t.Fatal(err)
	}
	if reentryErr != errRTUEventReentry {
		t.Fatalf("reentry error = %v", reentryErr)
	}
}

func TestRTUEventSequencesAreStrictlyOrdered(t *testing.T) {
	endpoint, _, sink := newRTUTestEndpoint(t)
	defer func() { _ = endpoint.Close() }()
	handle := beginRTUTestRead(t, endpoint)
	if err := endpoint.CompleteTransmit(handle, TransmitPartial); err != nil {
		t.Fatal(err)
	}
	events := sink.snapshot()
	for index, event := range events {
		want := uint64(index + 1)
		if event.Sequence != want {
			t.Fatalf("event[%d].sequence = %d, want %d", index, event.Sequence, want)
		}
	}
	begin := events[0]
	if begin.RequestedFunction != FunctionReadHoldingRegisters ||
		begin.Table != HoldingRegisters ||
		begin.Quantity != 3 ||
		begin.AuthorizationScope != "scope-a" ||
		begin.DeadlineIdentity != 9 ||
		begin.DeadlineOffset == 0 ||
		begin.RequestADUHex == "" {
		t.Fatalf("begin event = %#v", begin)
	}
}

func TestRTUEventSequenceExhaustionFailsBeforeAdmission(t *testing.T) {
	endpoint, _, sink := newRTUTestEndpoint(t)
	defer func() { _ = endpoint.Close() }()
	endpoint.mu.Lock()
	endpoint.nextSequence = math.MaxUint64
	endpoint.mu.Unlock()
	handle, frame, err := endpoint.BeginRead(
		context.Background(),
		rtuTestPlan(t),
	)
	if err == nil {
		t.Fatal("sequence exhaustion admitted request")
	}
	if handle.RequestID() != 0 || len(frame) != 0 {
		t.Fatalf("handle = %#v frame = %x", handle, frame)
	}
	if endpoint.Snapshot().State() != RTUStateRecoveryRequired {
		t.Fatalf("state = %s", endpoint.Snapshot().State())
	}
	if len(sink.snapshot()) != 0 {
		t.Fatalf("events = %#v", sink.snapshot())
	}
}

func TestRTURecoverResetsGenerationScopedAllocators(t *testing.T) {
	endpoint, clock, sink := newRTUTestEndpoint(t)
	defer func() { _ = endpoint.Close() }()
	endpoint.mu.Lock()
	endpoint.nextRequestID = math.MaxUint64
	endpoint.nextDiagnosticID = math.MaxUint64
	endpoint.mu.Unlock()
	if _, _, err := endpoint.BeginRead(
		context.Background(),
		rtuTestPlan(t),
	); err == nil {
		t.Fatal("request identity exhaustion accepted")
	}
	if err := endpoint.Recover(); err != nil {
		t.Fatal(err)
	}
	handle := beginRTUTestRead(t, endpoint)
	if handle.RequestID() != 1 || handle.Generation() != 2 {
		t.Fatalf("handle = %#v", handle)
	}
	if err := endpoint.CompleteTransmit(handle, TransmitComplete); err != nil {
		t.Fatal(err)
	}
	result, err := observeRTUTestFrame(
		endpoint,
		clock,
		rtuTestFrame(2, 0x03, 0x02, 0, 1),
	)
	if err == nil || result.WireResponse().DiagnosticFrameID() != 1 {
		t.Fatalf("result = %#v error = %v", result, err)
	}
	events := sink.snapshot()
	if len(events) != 5 ||
		events[0].Kind != RTUEventRecoveryRequired ||
		events[0].Detail != "request_identity_or_event_capacity" ||
		events[1].Kind != RTUEventRecovered ||
		events[2].Kind != RTUEventBeginRead ||
		events[3].Kind != RTUEventTransmitResult ||
		events[4].DiagnosticFrameID != 1 {
		t.Fatalf("events = %#v", events)
	}
}

func TestRTUCloseIsIdempotentAndReleasesFixtureLine(t *testing.T) {
	endpoint, _, _ := newRTUTestEndpoint(t)
	line := endpoint.FixtureLine()
	if err := endpoint.Close(); err != nil {
		t.Fatal(err)
	}
	if err := endpoint.Close(); err != nil {
		t.Fatal(err)
	}
	if endpoint.Snapshot().State() != RTUStateClosed {
		t.Fatalf("state = %s", endpoint.Snapshot().State())
	}
	replacement, err := NewRTUFixtureEndpoint(RTUFixtureEndpointConfig{
		Endpoint:           "replacement",
		Line:               line,
		Timing:             rtuTestTiming(t, 9600),
		Clock:              &virtualTCPClock{},
		FixtureOptIn:       true,
		MaxDiscardedFrames: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = replacement.Close() }()
}
