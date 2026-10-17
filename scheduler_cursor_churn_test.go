package modbus

import "testing"

func TestS21SchedulerCursorChurn(t *testing.T) {
	// IDs identify FIFO positions: 11/12 = first scope/unit, 21/22 =
	// first scope/second unit, then 31/32 through 61/62 for its peers.
	// Re-added keys receive 71/72 and (for whole scopes) 81/82.
	cases := []struct {
		name     string
		prefix   []uint64
		cancel   []uint64
		complete uint64
		readd    []int
		want     []uint64
	}{
		{
			name:   "scope_before_cursor_completion",
			prefix: []uint64{11}, cancel: []uint64{12, 21, 22}, complete: 11,
			readd: []int{0, 1},
			want:  []uint64{31, 51, 71, 41, 61, 81, 32, 52, 72, 42, 62, 82},
		},
		{
			name:   "scope_at_cursor_cancellation",
			prefix: []uint64{11}, cancel: []uint64{31, 32, 41, 42},
			readd: []int{2, 3},
			want:  []uint64{51, 71, 21, 61, 81, 12, 52, 72, 22, 62, 82},
		},
		{
			name:   "scope_after_cursor_cancellation",
			prefix: []uint64{11}, cancel: []uint64{51, 52, 61, 62},
			readd: []int{5, 4},
			want:  []uint64{31, 71, 21, 41, 81, 12, 32, 72, 22, 42, 82},
		},
		{
			name:   "unit_before_cursor_completion",
			prefix: []uint64{11}, cancel: []uint64{12}, complete: 11,
			readd: []int{0},
			want:  []uint64{31, 51, 21, 41, 61, 71, 32, 52, 22, 42, 62, 72},
		},
		{
			name:   "unit_at_cursor_cancellation",
			cancel: []uint64{11, 12}, readd: []int{0},
			want: []uint64{21, 31, 51, 71, 41, 61, 22, 32, 52, 72, 42, 62},
		},
		{
			name:   "unit_after_cursor_cancellation",
			cancel: []uint64{21, 22}, readd: []int{1},
			want: []uint64{11, 31, 51, 71, 41, 61, 12, 32, 52, 72, 42, 62},
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			scheduler, err := newEndpointScheduler(SchedulerLimits{
				MaxActiveAdmissionKeys: 12, ProtectedSlotsPerKey: 1,
				SharedBurstSlots: 52, TotalQueued: 64,
				MaxQueuedPerKey: 8, MaxQueuedPerAuthorizationScope: 64,
				MaxCoalescedDependentsPerKey: 8, MaxRetryAttempts: 2,
				MaxInFlightRequests: 16,
			})
			if err != nil {
				t.Fatal(err)
			}
			for cycle, scopes := range [][3]string{{"a", "b", "c"}, {"d", "e", "f"}} {
				base := uint64(cycle * 100)
				requests := make(map[uint64]ScheduledRequest)
				keys := make([]AdmissionKey, 0, 6)
				for _, scope := range scopes {
					for unit := byte(1); unit <= 2; unit++ {
						keys = append(keys, AdmissionKey{AuthorizationScope: scope, UnitID: unit})
					}
				}
				enqueue := func(id uint64, key AdmissionKey) {
					request := ScheduledRequest{RequestID: base + id, Key: key, DeadlineOffset: 1000 + int64(id)}
					if err := scheduler.Enqueue(request); err != nil {
						t.Fatalf("cycle %d enqueue %d: %v", cycle, id, err)
					}
					requests[base+id] = request
				}
				for index, key := range keys {
					enqueue(uint64(index*10+11), key)
					enqueue(uint64(index*10+12), key)
				}
				if size := scheduler.OrderMetadataSize(); size != 9 {
					t.Errorf("cycle %d initial metadata = %d, want 9", cycle, size)
				}
				dispatch := func(id uint64) ScheduledRequest {
					request, ok := scheduler.Dispatch(10)
					if !ok {
						t.Fatalf("cycle %d dispatch want %d returned empty", cycle, base+id)
					}
					if want := requests[base+id]; request != want {
						t.Errorf("cycle %d dispatch = %+v, want %+v", cycle, request, want)
					}
					return request
				}
				complete := func(id uint64) {
					if err := scheduler.Complete(id); err != nil {
						t.Fatalf("cycle %d complete %d: %v", cycle, id, err)
					}
				}
				for _, id := range test.prefix {
					request := dispatch(id)
					if id != test.complete {
						complete(request.RequestID)
					}
				}
				for _, id := range test.cancel {
					if !scheduler.CancelQueued(base + id) {
						t.Fatalf("cycle %d cancel %d failed", cycle, base+id)
					}
				}
				if test.complete != 0 {
					complete(base + test.complete)
				}
				for index, keyIndex := range test.readd {
					enqueue(uint64(71+index*10), keys[keyIndex])
					enqueue(uint64(72+index*10), keys[keyIndex])
				}
				for _, id := range test.want {
					complete(dispatch(id).RequestID)
				}
				if request, ok := scheduler.Dispatch(10); ok {
					t.Errorf("cycle %d extra dispatch: %+v", cycle, request)
				}
				if size := scheduler.OrderMetadataSize(); size != 0 {
					t.Errorf("cycle %d drained metadata = %d, want 0", cycle, size)
				}
				if got := scheduler.resourceSnapshot(); got != (endpointSchedulerResourceSnapshot{}) {
					t.Errorf("cycle %d drained resources = %+v, want zero", cycle, got)
				}
				if len(scheduler.entries) != 0 || len(scheduler.coalesced) != 0 ||
					len(scheduler.unitOrder) != 0 || len(scheduler.unitCursor) != 0 || scheduler.scopeCursor != 0 {
					t.Errorf("cycle %d retained entry or cursor metadata", cycle)
				}
			}
		})
	}
}
