package modbus

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type recordingRTUEventSink struct {
	mu     sync.Mutex
	events []RTUEvent
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
	defer first.Close()
	config.Endpoint = "endpoint-b"
	if _, err := NewRTUFixtureEndpoint(config); err == nil {
		t.Fatal("duplicate fixture-line owner accepted")
	}
}

func TestRTUEndpointAllowsOnlyOneOutstandingExchange(t *testing.T) {
	endpoint, _, _ := newRTUTestEndpoint(t)
	defer endpoint.Close()
	beginRTUTestRead(t, endpoint)
	if _, _, err := endpoint.BeginRead(
		context.Background(),
		rtuTestPlan(t),
	); err == nil {
		t.Fatal("concurrent RTU exchange accepted")
	}
}

func TestRTUProvableZeroNoAbandonment(t *testing.T) {
	endpoint, _, _ := newRTUTestEndpoint(t)
	defer endpoint.Close()
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

func TestRTUUnsafeTransmitResultsEnterQuarantine(t *testing.T) {
	for _, result := range []TransmitResult{
		TransmitPartial,
		TransmitIndeterminate,
		TransmitCancellationRace,
		TransmitAmbiguous,
	} {
		t.Run(result.String(), func(t *testing.T) {
			endpoint, _, sink := newRTUTestEndpoint(t)
			defer endpoint.Close()
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
		})
	}
}

func TestRTUFullTransmitAbandonmentEntersQuarantine(t *testing.T) {
	for _, reason := range []AbandonReason{
		AbandonTimeout,
		AbandonCancellation,
	} {
		t.Run(string(rune(reason)), func(t *testing.T) {
			endpoint, _, _ := newRTUTestEndpoint(t)
			defer endpoint.Close()
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
		})
	}
}

func TestRTULateSameShapeFrameIsDiscarded(t *testing.T) {
	endpoint, _, _ := newRTUTestEndpoint(t)
	defer endpoint.Close()
	handle := beginRTUTestRead(t, endpoint)
	if err := endpoint.CompleteTransmit(handle, TransmitComplete); err != nil {
		t.Fatal(err)
	}
	if err := endpoint.Abandon(handle, AbandonTimeout); err != nil {
		t.Fatal(err)
	}
	result, err := endpoint.Receive(
		rtuTestFrame(1, 0x03, 0x06, 0, 1, 0, 2, 0, 3),
	)
	if err == nil || !errors.Is(err, ErrRTUFrameDiscarded) {
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
	defer endpoint.Close()
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
	defer endpoint.Close()
	handle := beginRTUTestRead(t, endpoint)
	if err := endpoint.CompleteTransmit(handle, TransmitComplete); err != nil {
		t.Fatal(err)
	}
	if err := endpoint.Abandon(handle, AbandonTimeout); err != nil {
		t.Fatal(err)
	}
	timing := rtuTestTiming(t, 9600)
	clock.Advance(timing.MaxResponseLatency())
	if _, err := endpoint.Receive([]byte{0xff}); !errors.Is(err, ErrRTUFrameDiscarded) {
		t.Fatalf("discard error = %v", err)
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

func TestRTUQuiescenceFailureRequiresExplicitRecovery(t *testing.T) {
	endpoint, _, _ := newRTUTestEndpoint(t)
	defer endpoint.Close()
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

func TestRTUNormalSuccessHonorsInterFrameGuard(t *testing.T) {
	endpoint, clock, _ := newRTUTestEndpoint(t)
	defer endpoint.Close()
	handle := beginRTUTestRead(t, endpoint)
	if err := endpoint.CompleteTransmit(handle, TransmitComplete); err != nil {
		t.Fatal(err)
	}
	result, err := endpoint.Receive(
		rtuTestFrame(1, 0x03, 0x06, 0, 1, 0, 2, 0, 3),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Deliverable() {
		t.Fatal("valid response not deliverable")
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
	defer replacement.Close()
}
