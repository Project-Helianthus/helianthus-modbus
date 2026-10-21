package modbus

import (
	"errors"
	"slices"
	"testing"
	"time"
)

type resetDuringJitterSource struct {
	callback func(time.Duration) time.Duration
}

func (source resetDuringJitterSource) Next(upper time.Duration) time.Duration {
	return source.callback(upper)
}

func TestBackoffResetDuringJitterRejectsStaleNonzeroAttempt(t *testing.T) {
	var backoff *ReconnectBackoff
	calls := 0
	source := resetDuringJitterSource{callback: func(upper time.Duration) time.Duration {
		calls++
		wantUpper := time.Duration(7)
		if calls == 2 {
			wantUpper = 6
			backoff.ValidCorrelatedResponse()
		}
		if upper != wantUpper {
			t.Errorf("jitter call %d upper = %v, want %v", calls, upper, wantUpper)
		}
		return 0
	}}
	var err error
	backoff, err = newReconnectBackoff(BackoffConfig{
		Floor:             1,
		Ceiling:           8,
		MaxAttempts:       4,
		Jitter:            source,
		JitterAlgorithmID: "reset-callback",
		JitterVersion:     "test",
		JitterEvidence:    "synthetic:reset-on-second-call",
	})
	if err != nil {
		t.Fatal(err)
	}
	if delay, err := backoff.NextDelay(); err != nil || delay != 1 {
		t.Fatalf("first delay = %v, error = %v; want 1ns and nil", delay, err)
	}
	prior := append([]time.Duration(nil), backoff.EmittedJitter()...)
	if !slices.Equal(prior, []time.Duration{0}) {
		t.Fatalf("first emitted history = %v, want [0]", prior)
	}

	delay, err := backoff.NextDelay()
	var protocolErr *ProtocolError
	if !errors.As(err, &protocolErr) || protocolErr.Kind != ErrorInvalidRequest ||
		protocolErr.Field != "backoff_attempt" {
		t.Errorf("stale calculation error = %v, want invalid-request backoff_attempt", err)
	}
	if delay != 0 {
		t.Errorf("stale calculation delay = %v, want zero", delay)
	}
	if got := backoff.EmittedJitter(); !slices.Equal(got, prior) {
		t.Errorf("history after stale calculation = %v, want %v", got, prior)
	}

	if delay, err := backoff.NextDelay(); err != nil || delay != 1 {
		t.Errorf("delay after reset = %v, error = %v; want 1ns and nil", delay, err)
	}
	if got := backoff.EmittedJitter(); !slices.Equal(got, []time.Duration{0, 0}) {
		t.Errorf("history after restart = %v, want [0 0]", got)
	}
	if calls != 3 {
		t.Errorf("jitter calls = %d, want 3", calls)
	}
}
