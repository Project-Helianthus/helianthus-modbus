package modbus

import (
	"errors"
	"reflect"
	"testing"
	"time"
)

type s22BudgetJitter struct {
	values []time.Duration
	uppers []time.Duration
}

func (source *s22BudgetJitter) Next(upper time.Duration) time.Duration {
	index := len(source.uppers)
	source.uppers = append(source.uppers, upper)
	if index >= len(source.values) {
		panic("unexpected S22 jitter call")
	}
	return source.values[index]
}

func TestS22RejectedBudgetPreservesRetryState(t *testing.T) {
	for _, test := range []struct {
		name      string
		remaining time.Duration
		jitter    time.Duration
		calls     bool
	}{
		{name: "base_equal_remaining", remaining: 20},
		{name: "base_above_remaining", remaining: 19},
		{name: "base_one_below_jitter_reaches_remaining", remaining: 21, jitter: 1, calls: true},
		{name: "jitter_reaches_remaining", remaining: 25, jitter: 5, calls: true},
		{name: "jitter_exceeds_remaining", remaining: 25, jitter: 6, calls: true},
		{name: "oversized_jitter_clamped_to_remaining", remaining: 80, jitter: time.Duration(1<<63 - 1), calls: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			values := []time.Duration{1}
			if test.calls {
				values = append(values, test.jitter)
			}
			values = append(values, 2, 0, 0)
			jitter := &s22BudgetJitter{values: values}
			backoff, err := newReconnectBackoff(BackoffConfig{
				Floor: 10, Ceiling: 80, MaxAttempts: 4, Jitter: jitter,
				JitterAlgorithmID: "s22-sequence", JitterVersion: "v1",
				JitterEvidence: "synthetic:budget-boundaries",
			})
			if err != nil {
				t.Fatal(err)
			}
			if delay, err := backoff.nextDelayBefore(1000); err != nil || delay != 11 {
				t.Fatalf("initial delay = %v, %v; want 11ns, nil", delay, err)
			}
			delay, err := backoff.nextDelayBefore(test.remaining)
			var protocolErr *ProtocolError
			if delay != 0 || !errors.As(err, &protocolErr) ||
				protocolErr.Kind != ErrorInvalidRange || protocolErr.Field != "operation_deadline" {
				t.Fatalf("rejected proposal = %v, %v; want zero, operation_deadline", delay, err)
			}
			if backoff.attempt != 1 || !reflect.DeepEqual(backoff.EmittedJitter(), []time.Duration{1}) {
				t.Fatalf("rejection changed state: attempt=%d, emitted=%v", backoff.attempt, backoff.EmittedJitter())
			}
			// Every rejected proposal must leave attempt 1 available, then
			// progress through exactly the three remaining accepted attempts.
			for index, want := range []time.Duration{22, 40, 80} {
				if delay, err := backoff.nextDelayBefore(1000); err != nil || delay != want {
					t.Fatalf("accepted delay %d = %v, %v; want %v, nil", index, delay, err, want)
				}
			}
			delay, err = backoff.nextDelayBefore(1000)
			if delay != 0 || !errors.As(err, &protocolErr) ||
				protocolErr.Kind != ErrorInvalidRange || protocolErr.Field != "backoff_attempts" {
				t.Fatalf("attempt cap = %v, %v; want zero, backoff_attempts", delay, err)
			}
			wantUppers := []time.Duration{70}
			if test.calls {
				wantUppers = append(wantUppers, 60)
			}
			wantUppers = append(wantUppers, 60, 40, 0)
			if !reflect.DeepEqual(jitter.uppers, wantUppers) {
				t.Fatalf("jitter inputs = %v; want %v", jitter.uppers, wantUppers)
			}
			if backoff.attempt != 4 || !reflect.DeepEqual(backoff.EmittedJitter(), []time.Duration{1, 2, 0, 0}) {
				t.Fatalf("final state: attempt=%d, emitted=%v", backoff.attempt, backoff.EmittedJitter())
			}
		})
	}
}

func TestS22AcceptedBudgetClampsJitter(t *testing.T) {
	for _, test := range []struct {
		name       string
		remaining  time.Duration
		jitter     time.Duration
		wantDelay  time.Duration
		wantJitter time.Duration
	}{
		{name: "base_one_below_remaining", remaining: 11, wantDelay: 10},
		{name: "negative_jitter", remaining: 11, jitter: time.Duration(-1 << 63), wantDelay: 10},
		{name: "oversized_jitter", remaining: 81, jitter: time.Duration(1<<63 - 1), wantDelay: 80, wantJitter: 70},
	} {
		t.Run(test.name, func(t *testing.T) {
			jitter := &s22BudgetJitter{values: []time.Duration{test.jitter}}
			backoff, err := newReconnectBackoff(BackoffConfig{
				Floor: 10, Ceiling: 80, MaxAttempts: 1, Jitter: jitter,
				JitterAlgorithmID: "s22-sequence", JitterVersion: "v1",
				JitterEvidence: "synthetic:clamping",
			})
			if err != nil {
				t.Fatal(err)
			}
			if delay, err := backoff.nextDelayBefore(test.remaining); err != nil || delay != test.wantDelay {
				t.Fatalf("delay = %v, %v; want %v, nil", delay, err, test.wantDelay)
			}
			if backoff.attempt != 1 || !reflect.DeepEqual(backoff.EmittedJitter(), []time.Duration{test.wantJitter}) {
				t.Fatalf("accepted state: attempt=%d, emitted=%v", backoff.attempt, backoff.EmittedJitter())
			}
			if !reflect.DeepEqual(jitter.uppers, []time.Duration{70}) {
				t.Fatalf("jitter inputs = %v; want [70ns]", jitter.uppers)
			}
		})
	}
}

func TestS22CorrelatedResetAndConnectedControl(t *testing.T) {
	jitter := &s22BudgetJitter{values: []time.Duration{1, 2, 3, 4, 5, 6}}
	backoff, err := newReconnectBackoff(BackoffConfig{
		Floor: 10, Ceiling: 80, MaxAttempts: 3, Jitter: jitter,
		JitterAlgorithmID: "s22-sequence", JitterVersion: "v1",
		JitterEvidence: "synthetic:reset-control",
	})
	if err != nil {
		t.Fatal(err)
	}
	for index, want := range []time.Duration{11, 22, 13, 24, 45, 16} {
		switch index {
		case 1, 3:
			backoff.Connected()
		case 2:
			backoff.ValidCorrelatedResponse()
		case 5:
			backoff.Connected()
			delay, err := backoff.nextDelayBefore(1000)
			var protocolErr *ProtocolError
			if delay != 0 || !errors.As(err, &protocolErr) ||
				protocolErr.Kind != ErrorInvalidRange || protocolErr.Field != "backoff_attempts" {
				t.Fatalf("Connected reset exhausted attempts: delay=%v, err=%v", delay, err)
			}
			backoff.ValidCorrelatedResponse()
		}
		if delay, err := backoff.nextDelayBefore(1000); err != nil || delay != want {
			t.Fatalf("delay %d = %v, %v; want %v, nil", index, delay, err, want)
		}
	}
	if backoff.attempt != 1 || !reflect.DeepEqual(backoff.EmittedJitter(), []time.Duration{4, 5, 6}) {
		t.Fatalf("reset/history state: attempt=%d, emitted=%v", backoff.attempt, backoff.EmittedJitter())
	}
	if !reflect.DeepEqual(jitter.uppers, []time.Duration{70, 60, 70, 60, 40, 70}) {
		t.Fatalf("jitter inputs = %v; want [70ns 60ns 70ns 60ns 40ns 70ns]", jitter.uppers)
	}
}
