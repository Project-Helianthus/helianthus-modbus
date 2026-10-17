package modbus

import (
	"errors"
	"fmt"
	"reflect"
	"testing"
)

func TestCoalescedRetryRelease(t *testing.T) {
	for _, exhaust := range []bool{false, true} {
		for cancelled := 0; cancelled < 3; cancelled++ {
			t.Run(fmt.Sprintf("exhaust_%t/cancel_%d", exhaust, cancelled), func(t *testing.T) {
				scheduler, err := newEndpointScheduler(SchedulerLimits{
					MaxActiveAdmissionKeys: 1, ProtectedSlotsPerKey: 1, SharedBurstSlots: 2,
					TotalQueued: 3, MaxQueuedPerKey: 3, MaxQueuedPerAuthorizationScope: 3,
					MaxCoalescedDependentsPerKey: 3, MaxRetryAttempts: 1, MaxInFlightRequests: 1,
				})
				if err != nil {
					t.Fatal(err)
				}
				key := AdmissionKey{AuthorizationScope: "synthetic-scope", UnitID: 1}
				request := ScheduledRequest{RequestID: 100, Key: key, DeadlineOffset: 50}
				peer := ScheduledRequest{RequestID: 200, Key: key, DeadlineOffset: 50}
				intents := make([]ReadIntent, 3)
				for i := range intents {
					read, err := NewReadRegistersRequest(FunctionReadHoldingRegisters, uint16(10+i), uint16(4-i))
					if err != nil {
						t.Fatal(err)
					}
					intents[i], err = NewReadIntent(ReadIntentSpec{
						LogicalViewID: uint64(11 + i), Endpoint: "synthetic-endpoint", Transport: TransportTCP,
						TransportGeneration: 7, UnitID: key.UnitID, AuthorizationScope: key.AuthorizationScope,
						PollGeneration: 9, DeadlineIdentity: 13, Request: read,
					})
					if err != nil {
						t.Fatal(err)
					}
				}
				admit := func() *CoalescedRead {
					t.Helper()
					group, err := scheduler.ScheduleCoalesced(request, intents)
					if err != nil {
						t.Fatal(err)
					}
					return group
				}
				snapshot := func(queued, inFlight, keys, dependents int) {
					t.Helper()
					want := endpointSchedulerResourceSnapshot{
						queuedRequests: queued, inFlightRequests: inFlight,
						activeAdmissionKeys: keys, coalescedDependents: dependents,
					}
					if got := scheduler.resourceSnapshot(); got != want {
						t.Fatalf("resources = %+v, want %+v", got, want)
					}
				}
				dispatch := func(want ScheduledRequest) {
					t.Helper()
					got, ok := scheduler.Dispatch(0)
					if !ok || got != want {
						t.Fatalf("dispatch = %+v, %t; want %+v", got, ok, want)
					}
				}
				group := admit()
				snapshot(1, 0, 1, 3)
				if err := scheduler.Enqueue(peer); err == nil {
					t.Fatal("full logical budget admitted peer")
				}
				cancelledID := uint64(11 + cancelled)
				transition, err := group.Cancel(cancelledID)
				if err != nil {
					t.Fatal(err)
				}
				if !transition.TransmitPhysical() || transition.AbandonTransport() {
					t.Fatalf("queued cancellation transition = %+v", transition)
				}
				snapshot(1, 0, 1, 2)
				wantStates := map[uint64]DependentTerminalState{11: DependentQueued, 12: DependentQueued, 13: DependentQueued}
				wantStates[cancelledID] = DependentCancelled
				checkStates := func() {
					t.Helper()
					if got := group.DependentStates(); !reflect.DeepEqual(got, wantStates) {
						t.Fatalf("dependent states = %v, want %v", got, wantStates)
					}
				}
				checkStates()
				if got := group.ActiveDependentCount(); got != 2 {
					t.Fatalf("active dependents = %d, want 2", got)
				}
				wantOffset, wantQuantity := uint16(10), uint16(4)
				if cancelled == 0 {
					wantOffset, wantQuantity = 11, 3
				}
				if physical := group.PhysicalRequest(); physical.Offset() != wantOffset || physical.Quantity() != wantQuantity {
					t.Fatalf("survivor union = %+v, want [%d,14)", physical, wantOffset)
				}
				if err := scheduler.Enqueue(peer); err != nil {
					t.Fatal("cancelled dependent did not release peer capacity:", err)
				}
				dispatch(request)
				snapshot(1, 1, 1, 2)
				if got, ok := scheduler.CoalescedGroup(request.RequestID); !ok || got != group {
					t.Fatal("physical token lost group")
				}
				if err := scheduler.RequireCoalescedDispatch(group); err != nil {
					t.Fatal(err)
				}
				if got, ok := scheduler.Dispatch(0); ok {
					t.Fatalf("second physical dispatch under one-slot limit: %+v", got)
				}
				if err := scheduler.RetryCoalesced(group); err != nil {
					t.Fatal(err)
				}
				snapshot(2, 0, 1, 2)
				checkStates()
				if err := scheduler.RequireCoalescedDispatch(group); err == nil {
					t.Fatal("retry retained dispatch permission")
				}
				dispatch(peer)
				if err := scheduler.Complete(peer.RequestID); err != nil {
					t.Fatal(err)
				}
				dispatch(request)
				snapshot(0, 1, 1, 2)
				if exhaust {
					err := scheduler.RetryCoalesced(group)
					var protocolErr *ProtocolError
					if !errors.As(err, &protocolErr) || protocolErr.Field != "retry_attempts" {
						t.Fatalf("second retry = %v, want retry_attempts", err)
					}
				} else if err := group.FailTransport(); err != nil {
					t.Fatal(err)
				}
				for id := range wantStates {
					if id != cancelledID {
						wantStates[id] = DependentFailed
					}
				}
				checkStates()
				if group.ActiveDependentCount() != 0 {
					t.Fatal("terminal group retained active dependents")
				}
				snapshot(0, 0, 0, 0)
				if _, ok := scheduler.CoalescedGroup(request.RequestID); ok {
					t.Fatal("terminal physical token remained live")
				}
				if scheduler.OrderMetadataSize() != 0 {
					t.Fatal("terminal group retained order metadata")
				}
				if err := scheduler.RetryCoalesced(group); err == nil {
					t.Fatal("terminal group retried again")
				}
				// Reuse the full logical budget and physical ID before repeating old cleanup.
				replacement := admit()
				if err := group.FailTransport(); err != nil {
					t.Fatal(err)
				}
				if err := scheduler.FinishCoalesced(group); err != nil {
					t.Fatal(err)
				}
				checkStates()
				snapshot(1, 0, 1, 3)
				if got, ok := scheduler.CoalescedGroup(request.RequestID); !ok || got != replacement {
					t.Fatal("old cleanup removed replacement token")
				}
				dispatch(request)
				if err := replacement.FailTransport(); err != nil {
					t.Fatal(err)
				}
				snapshot(0, 0, 0, 0)
				if got, ok := scheduler.Dispatch(0); ok {
					t.Fatalf("terminal work redispatched: %+v", got)
				}
			})
		}
	}
}
