package modbus

import (
	"bytes"
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// k17FakeTransport delivers an already-correlated view through a test callback.
// It owns completion; cancellation must not close its result channel.
type k17FakeTransport struct {
	result chan k17CallbackResult
	done   chan struct{}
}

type k17CallbackResult struct {
	acquisition RuntimeAcquisition
	err         error
}

func k17Deliver(callback func() (RuntimeAcquisition, error)) *k17FakeTransport {
	transport := &k17FakeTransport{
		result: make(chan k17CallbackResult, 1),
		done:   make(chan struct{}),
	}
	go func() {
		defer close(transport.done)
		acquisition, err := callback()
		transport.result <- k17CallbackResult{acquisition, err}
	}()
	return transport
}

func k17Wait(t *testing.T, done <-chan struct{}, operation string) {
	t.Helper()
	watchdog := time.NewTimer(5 * time.Second)
	defer watchdog.Stop()
	select {
	case <-done:
	case <-watchdog.C:
		t.Fatalf("watchdog: %s did not complete", operation)
	}
}

func TestK17RetiredAttemptRejectsPausedCallbackWithSameKeySuccessor(t *testing.T) {
	clock := &virtualTCPClock{}
	source := newRuntimeAcquisitionSourceForTest(t, clock)
	// Reuse the public, in-memory TCP fixture; no new framing or live transport.
	views := runtimeSuccessfulViewsForTest(t, source, clock, []runtimeReadForTest{
		{logicalViewID: 1701, offset: 10, quantity: 1},
		{logicalViewID: 1702, offset: 10, quantity: 1},
		{logicalViewID: 1703, offset: 10, quantity: 1},
	}, []uint16{0x1234})
	attempt, err := source.BeginAttempt("k17-same-key")
	if err != nil {
		t.Fatal(err)
	}
	original := issueRuntimeAcquisitionForTest(t, source, attempt, 0, views[0], "k17-original")
	provenance := original.Provenance()
	normalization := original.Normalization().Bytes()
	lateRecord := runtimeNormalizationForTest(t, source, RuntimeAcquisitionSourceRuntime,
		"k17-late", 10, 1, "")

	paused := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	var first atomic.Bool
	source.beforeMembership = func() {
		if first.CompareAndSwap(false, true) {
			close(paused)
			<-release
		}
	}
	transport := k17Deliver(func() (RuntimeAcquisition, error) {
		return source.Issue(attempt, 1, views[1], lateRecord)
	})
	t.Cleanup(func() {
		releaseOnce.Do(func() { close(release) })
		k17Wait(t, transport.done, "callback cleanup/join")
	})
	k17Wait(t, paused, "callback membership barrier")

	// Close freezes only registered members. CancelOpen drains that exact
	// instance; neither operation owns or waits for the transport callback.
	var instance RuntimeAttemptInstance
	var lifecycleErr error
	lifecycleDone := make(chan struct{})
	go func() {
		defer close(lifecycleDone)
		instance, lifecycleErr = attempt.Close([]RuntimeAcquisition{original})
		if lifecycleErr == nil {
			lifecycleErr = source.CancelOpen(instance)
		}
	}()
	t.Cleanup(func() {
		releaseOnce.Do(func() { close(release) })
		k17Wait(t, lifecycleDone, "close/cancel cleanup/join")
	})
	k17Wait(t, lifecycleDone, "close/cancel while callback is paused")
	if lifecycleErr != nil {
		t.Fatalf("close/cancel: %v", lifecycleErr)
	}

	successor, err := source.BeginAttempt(original.AttemptKey())
	if err != nil {
		t.Fatal(err)
	}
	current := issueRuntimeAcquisitionForTest(t, source, successor, 0, views[2], "k17-successor")
	assertSuccessorOpen := func() {
		t.Helper()
		source.mu.Lock()
		defer source.mu.Unlock()
		state := source.attempts[successor.token]
		if state == nil || state.phase != runtimeAttemptOpen {
			t.Fatal("successor must remain open while the stale callback resumes")
		}
	}
	before := source.Snapshot()
	if before.LiveCapabilities != 1 || before.ActiveAttempts != 1 {
		t.Fatalf("successor state before callback: %#v", before)
	}
	assertSuccessorOpen()
	releaseOnce.Do(func() { close(release) })
	k17Wait(t, transport.done, "late callback completion/join")
	assertSuccessorOpen()
	late := <-transport.result
	if late.acquisition.Valid() || !errors.Is(late.err, ErrRuntimeAttemptClosed) {
		t.Fatalf("retired callback issued=%v err=%v", late.acquisition.Valid(), late.err)
	}
	if after := source.Snapshot(); !reflect.DeepEqual(after, before) {
		t.Fatalf("late callback changed successor state: before=%#v after=%#v", before, after)
	}
	currentInstance, err := successor.Close([]RuntimeAcquisition{current})
	if err != nil {
		t.Fatal(err)
	}
	if original.AttemptKey() != current.AttemptKey() || instance.token == currentInstance.token {
		t.Fatal("fixture must reuse the documentary key with distinct opaque instances")
	}
	if original.Capability().token.attempt != instance.token ||
		!reflect.DeepEqual(original.Provenance(), provenance) ||
		!bytes.Equal(original.Normalization().Bytes(), normalization) {
		t.Fatal("original evidence or attempt provenance changed")
	}
	if result, err := original.Capability().Claim(currentInstance); !errors.Is(err, ErrRuntimeAttemptMembership) || result.Won {
		t.Fatalf("old evidence admitted to successor: result=%#v err=%v", result, err)
	}
	if result, err := original.Capability().Claim(instance); err != nil || result.Won || result.Outcome != RuntimeCapabilityCancelled {
		t.Fatalf("original terminal state: result=%#v err=%v", result, err)
	}
	if result, err := current.Capability().Claim(currentInstance); err != nil || !result.Won || result.Outcome != RuntimeCapabilityClaimed {
		t.Fatalf("successor claim: result=%#v err=%v", result, err)
	}
	if err := source.CancelOpen(currentInstance); err != nil {
		t.Fatalf("drain successor: %v", err)
	}
	if snapshot := source.Snapshot(); snapshot.LiveCapabilities != 0 || snapshot.ActiveAttempts != 0 {
		t.Fatalf("retained live ownership after cleanup: %#v", snapshot)
	}
}
