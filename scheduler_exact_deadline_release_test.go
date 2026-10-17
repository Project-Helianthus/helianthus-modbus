package modbus

import "testing"

func TestSchedulerDeadlineEqualityReleasesQueuedWeight(t *testing.T) {
	keys := []struct {
		name string
		peer AdmissionKey
	}{
		{"scope_only", AdmissionKey{AuthorizationScope: "beta", UnitID: 1}},
		{"unit_only", AdmissionKey{AuthorizationScope: "alpha", UnitID: 2}},
		{"scope_and_unit", AdmissionKey{AuthorizationScope: "beta", UnitID: 2}},
	}
	for _, identity := range keys {
		t.Run(identity.name, func(t *testing.T) {
			for _, offset := range []struct {
				name string
				now  int64
			}{
				{"before_deadline", 9},
				{"at_deadline", 10},
			} {
				t.Run(offset.name, func(t *testing.T) {
					scheduler, err := newEndpointScheduler(SchedulerLimits{
						MaxActiveAdmissionKeys:         2,
						ProtectedSlotsPerKey:           1,
						SharedBurstSlots:               1,
						TotalQueued:                    3,
						MaxQueuedPerKey:                2,
						MaxQueuedPerAuthorizationScope: 3,
						MaxCoalescedDependentsPerKey:   1,
						MaxRetryAttempts:               1,
						MaxInFlightRequests:            2,
					})
					if err != nil {
						t.Fatal(err)
					}
					first := ScheduledRequest{RequestID: 1,
						Key:            AdmissionKey{AuthorizationScope: "alpha", UnitID: 1},
						DeadlineOffset: 10}
					peer := ScheduledRequest{RequestID: 2, Key: identity.peer, DeadlineOffset: 20}
					// Two active keys require a minimum budget of three. Exercise
					// weighted queue accounting directly with exactly two entries.
					admit := func(request ScheduledRequest, weight int) error {
						scheduler.mu.Lock()
						defer scheduler.mu.Unlock()
						return scheduler.enqueueLocked(request, nil, weight)
					}
					if err := admit(first, 2); err != nil {
						t.Fatal(err)
					}
					if err := admit(peer, 1); err != nil {
						t.Fatal(err)
					}
					firstState := scheduler.keys[first.Key]
					if len(scheduler.entries) != 2 || len(scheduler.keys) != 2 ||
						firstState.queued != 2 || scheduler.keys[peer.Key].queued != 1 {
						t.Fatal("two independent keys did not fill the three-unit queue budget")
					}
					overflow := ScheduledRequest{RequestID: 3, Key: peer.Key, DeadlineOffset: 20}
					if got := requireProtocolError(t, scheduler.Enqueue(overflow), ErrorInvalidRange); got.Field != "queued_capacity" {
						t.Fatalf("full queue rejection field = %q", got.Field)
					}

					got, ok := scheduler.Dispatch(offset.now)
					want := first
					if offset.now == 10 {
						want = peer
					}
					if !ok || got != want {
						t.Fatalf("Dispatch(%d) = %+v, %v; want %+v", offset.now, got, ok, want)
					}
					if firstState.queued != 0 {
						t.Fatalf("released first queue weight = %d; want 0", firstState.queued)
					}
					if offset.now == 9 {
						if entry := scheduler.entries[first.RequestID]; entry == nil || entry.state != scheduledInFlight {
							t.Fatal("before deadline, first token must remain in flight")
						}
						wantMetadata := 3
						if first.Key.AuthorizationScope != peer.Key.AuthorizationScope {
							wantMetadata = 4
						}
						if len(scheduler.keys) != 2 || scheduler.OrderMetadataSize() != wantMetadata {
							t.Fatal("before deadline, both live keys must retain their order metadata")
						}
						if err := scheduler.Complete(first.RequestID); err != nil {
							t.Fatal(err)
						}
					} else {
						if _, exists := scheduler.entries[first.RequestID]; exists {
							t.Fatal("expired token retained at exact deadline")
						}
						if err := scheduler.Complete(first.RequestID); err == nil {
							t.Fatal("expired request must never be completable as dispatched work")
						}
					}
					if _, exists := scheduler.keys[first.Key]; exists {
						t.Fatal("released first key retained")
					}
					if scheduler.OrderMetadataSize() != 2 || len(scheduler.entries) != 1 {
						t.Fatal("only the peer token and its scope/unit metadata should remain")
					}

					// Reuse the released token on a new key to test token and key
					// capacity together, while retaining the original peer.
					replacement := ScheduledRequest{RequestID: 1,
						Key:            AdmissionKey{AuthorizationScope: "gamma", UnitID: 3},
						DeadlineOffset: 20}
					if err := admit(replacement, 2); err != nil {
						t.Fatalf("replacement could not reclaim token and capacity: %v", err)
					}
					if scheduler.keys[replacement.Key].queued != 2 || len(scheduler.entries) != 2 {
						t.Fatal("replacement accounting or token count incorrect")
					}
					if offset.now == 9 {
						if got := requireProtocolError(t, scheduler.Enqueue(overflow), ErrorInvalidRange); got.Field != "queued_capacity" {
							t.Fatalf("refilled queue rejection field = %q", got.Field)
						}
						got, ok := scheduler.Dispatch(offset.now)
						if !ok || got != peer {
							t.Fatalf("peer dispatch = %+v, %v", got, ok)
						}
					}
					// With the peer in flight, exactly one queue unit remains.
					if err := admit(overflow, 2); err == nil {
						t.Fatal("admitted two units into one remaining queue unit")
					}
					if err := scheduler.Enqueue(overflow); err != nil {
						t.Fatalf("exact remaining queue unit unavailable: %v", err)
					}
					if err := scheduler.Complete(peer.RequestID); err != nil {
						t.Fatal(err)
					}
					pending := map[uint64]ScheduledRequest{replacement.RequestID: replacement, overflow.RequestID: overflow}
					for range 2 {
						got, ok := scheduler.Dispatch(offset.now)
						want, exists := pending[got.RequestID]
						if !ok || !exists || got != want {
							t.Fatalf("remaining dispatch = %+v, %v; pending = %v", got, ok, pending)
						}
						delete(pending, got.RequestID)
						if err := scheduler.Complete(got.RequestID); err != nil {
							t.Fatal(err)
						}
					}
					if _, ok := scheduler.Dispatch(offset.now); ok {
						t.Fatal("dispatch after all work completed")
					}
					if len(scheduler.entries) != 0 || len(scheduler.coalesced) != 0 ||
						len(scheduler.keys) != 0 || len(scheduler.scopeOrder) != 0 ||
						len(scheduler.unitOrder) != 0 || len(scheduler.unitCursor) != 0 ||
						scheduler.scopeCursor != 0 || scheduler.inFlight != 0 {
						t.Fatal("completed scheduler retained tokens, capacity, or key/order metadata")
					}
				})
			}
		})
	}
}
