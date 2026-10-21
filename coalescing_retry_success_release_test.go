package modbus

import (
	"fmt"
	"reflect"
	"testing"
)

func TestCoalescedRetrySuccessRelease(t *testing.T) {
	for _, schedulerFirst := range []bool{false, true} {
		t.Run(fmt.Sprintf("scheduler_first_%t", schedulerFirst), func(t *testing.T) {
			for cancelled := 0; cancelled < 3; cancelled++ {
				t.Run(fmt.Sprintf("cancel_%d", cancelled), func(t *testing.T) {
					scheduler, err := newEndpointScheduler(SchedulerLimits{
						MaxActiveAdmissionKeys: 1, ProtectedSlotsPerKey: 1, SharedBurstSlots: 2,
						TotalQueued: 3, MaxQueuedPerKey: 3, MaxQueuedPerAuthorizationScope: 3,
						MaxCoalescedDependentsPerKey: 3, MaxRetryAttempts: 1, MaxInFlightRequests: 1,
					})
					if err != nil {
						t.Fatal(err)
					}
					key := AdmissionKey{AuthorizationScope: "synthetic-scope", UnitID: 1}
					request := ScheduledRequest{RequestID: 1, Key: key, DeadlineOffset: 50}
					peer := ScheduledRequest{RequestID: 200, Key: key, DeadlineOffset: 50}
					intents := make([]ReadIntent, 3)
					for i := range intents {
						read, err := NewReadRegistersRequest(FunctionReadHoldingRegisters, uint16(10+i), uint16(4-i))
						if err != nil {
							t.Fatal(err)
						}
						intents[i], err = NewReadIntent(ReadIntentSpec{
							LogicalViewID: uint64(11 + i), Endpoint: "synthetic-endpoint", Transport: TransportTCP,
							TransportGeneration: 7, UnitID: 1, AuthorizationScope: "synthetic-scope",
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
					resources := func(queued, inFlight, keys, dependents, weight int) {
						t.Helper()
						want := endpointSchedulerResourceSnapshot{
							queuedRequests: queued, inFlightRequests: inFlight,
							activeAdmissionKeys: keys, coalescedDependents: dependents,
						}
						if got := scheduler.resourceSnapshot(); got != want {
							t.Fatalf("resources = %+v, want %+v", got, want)
						}
						actualWeight, keySlots := 0, 0
						for _, state := range scheduler.keys {
							actualWeight += state.queued
							keySlots += state.inFlight
						}
						if actualWeight != weight || keySlots != inFlight {
							t.Fatalf("queued weight/key slots = %d/%d, want %d/%d", actualWeight, keySlots, weight, inFlight)
						}
						if got := scheduler.OrderMetadataSize(); got != 2*keys {
							t.Fatalf("order metadata = %d, want %d", got, 2*keys)
						}
					}
					dispatch := func(want ScheduledRequest) {
						t.Helper()
						if got, ok := scheduler.Dispatch(0); !ok || got != want {
							t.Fatalf("dispatch = %+v, %t; want %+v", got, ok, want)
						}
					}
					group := admit()
					resources(1, 0, 1, 3, 0)
					if err := scheduler.Enqueue(peer); err == nil {
						t.Fatal("full logical capacity admitted peer")
					}
					cancelledID := uint64(11 + cancelled)
					transition, err := group.Cancel(cancelledID)
					if err != nil {
						t.Fatal(err)
					}
					if !transition.TransmitPhysical() || transition.AbandonTransport() {
						t.Fatalf("queued cancellation = %+v", transition)
					}
					wantStates := map[uint64]DependentTerminalState{11: DependentQueued, 12: DependentQueued, 13: DependentQueued}
					wantStates[cancelledID] = DependentCancelled
					states := func() {
						t.Helper()
						if got := group.DependentStates(); !reflect.DeepEqual(got, wantStates) {
							t.Fatalf("states = %v, want %v", got, wantStates)
						}
					}
					states()
					resources(1, 0, 1, 2, 0)
					if err := scheduler.Enqueue(peer); err != nil {
						t.Fatal(err)
					}
					resources(2, 0, 1, 2, 1)
					dispatch(request)
					resources(1, 1, 1, 2, 1)
					if err := scheduler.RetryCoalesced(group); err != nil {
						t.Fatal(err)
					}
					resources(2, 0, 1, 2, 1)
					states()
					if err := scheduler.RequireCoalescedDispatch(group); err == nil {
						t.Fatal("queued retry retained dispatch permission")
					}
					dispatch(peer)
					if err := scheduler.Complete(peer.RequestID); err != nil {
						t.Fatal(err)
					}
					resources(1, 0, 1, 2, 0)
					dispatch(request)
					resources(0, 1, 1, 2, 0)
					if err := scheduler.RequireCoalescedDispatch(group); err != nil {
						t.Fatal(err)
					}
					if got, ok := scheduler.Dispatch(0); ok {
						t.Fatalf("one-slot limit dispatched %+v", got)
					}

					// The response is correlated by the real owner without opening a socket.
					physicalWords := []uint16{101, 202, 303, 404}
					physicalOffset := uint16(10)
					if cancelled == 0 {
						physicalWords = []uint16{202, 303, 404}
						physicalOffset = 11
					}
					physical := group.PhysicalRequest()
					if physical.Offset() != physicalOffset || int(physical.Quantity()) != len(physicalWords) {
						t.Fatalf("survivor union = %+v", physical)
					}
					response := retrySuccessResponse(t, group, physicalWords)
					// Scheduler completion and logical delivery are separate production APIs.
					if schedulerFirst {
						if err := scheduler.CompleteCoalesced(group); err != nil {
							t.Fatal(err)
						}
						resources(0, 0, 1, 2, 0)
					}
					views, err := group.ReplaySuccessfulResponse(response)
					if err != nil {
						t.Fatal(err)
					}
					if len(views) != 2 {
						t.Fatalf("views = %d, want 2", len(views))
					}
					expectedWords := [][]uint16{{101, 202, 303, 404}, {202, 303, 404}, {303, 404}}
					next := 0
					for i := 0; i < 3; i++ {
						if i == cancelled {
							continue
						}
						view := views[next]
						next++
						if view.LogicalViewID() != uint64(11+i) || !reflect.DeepEqual(view.Words(), expectedWords[i]) ||
							view.LogicalOffset() != uint16(10+i) || view.LogicalWordCount() != uint16(4-i) ||
							view.SliceOffset() != uint16(10+i)-physicalOffset || view.SliceWordCount() != uint16(4-i) ||
							view.WireResponseID() != response.WireResponseID() {
							t.Fatalf("dependent %d: unexpected successful slice %+v words %v", i, view, view.Words())
						}
						wantStates[uint64(11+i)] = DependentDelivered
					}
					states()
					if !group.completed || group.ActiveDependentCount() != 0 {
						t.Fatal("successful group remained active")
					}
					resources(0, 0, 0, 0, 0)
					if _, ok := scheduler.CoalescedGroup(request.RequestID); ok {
						t.Fatal("old physical token remains")
					}
					if _, ok := scheduler.coalesced[group]; ok {
						t.Fatal("old group identity remains")
					}
					if len(scheduler.entries) != 0 || len(scheduler.unitCursor) != 0 {
						t.Fatal("terminal metadata remains")
					}

					replacement := admit()
					if replacement == group {
						t.Fatal("replacement reused group identity")
					}
					for repeat := 0; repeat < 2; repeat++ {
						if err := scheduler.FinishCoalesced(group); err != nil {
							t.Fatal(err)
						}
						if err := group.FailTransport(); err != nil {
							t.Fatal(err)
						}
						states()
						resources(1, 0, 1, 3, 0)
						if got, ok := scheduler.CoalescedGroup(request.RequestID); !ok || got != replacement {
							t.Fatal("stale cleanup removed same-ID replacement")
						}
						if id, ok := scheduler.coalesced[replacement]; !ok || id != request.RequestID {
							t.Fatal("replacement identity mapping lost")
						}
						if replacement.ActiveDependentCount() != 3 {
							t.Fatal("stale cleanup changed replacement dependents")
						}
					}
					if err := scheduler.Enqueue(peer); err == nil {
						t.Fatal("replacement did not fill logical capacity")
					}
					dispatch(request)
					resources(0, 1, 1, 3, 0)
					replacementResponse := retrySuccessResponse(t, replacement, []uint16{101, 202, 303, 404})
					if err := scheduler.CompleteCoalesced(replacement); err != nil {
						t.Fatal(err)
					}
					if got, err := replacement.ReplaySuccessfulResponse(replacementResponse); err != nil || len(got) != 3 {
						t.Fatalf("replacement delivery = %v, %v", got, err)
					}
					resources(0, 0, 0, 0, 0)
					if got, ok := scheduler.Dispatch(0); ok {
						t.Fatalf("terminal work redispatched: %+v", got)
					}
				})
			}
		})
	}
}

func retrySuccessResponse(t *testing.T, group *CoalescedRead, words []uint16) WireResponse {
	t.Helper()
	owner, err := newTCPConnectionOwner(group.endpoint, group.intentGeneration, ConnectionLimits{MaxInFlight: 1, MaxTombstones: 1})
	if err != nil {
		t.Fatal(err)
	}
	reservation, err := owner.ReserveRead(group.unitID, group.PhysicalRequest())
	if err != nil {
		t.Fatal(err)
	}
	if err := group.BindReservation(reservation); err != nil {
		t.Fatal(err)
	}
	if _, err := group.invokeWrite(nil, func(TCPReservation) (OwnerTransition, error) { return OwnerTransition{}, nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.RecordTransmit(reservation, TransmitComplete); err != nil {
		t.Fatal(err)
	}
	pdu := []byte{byte(FunctionReadHoldingRegisters), byte(2 * len(words))}
	for _, word := range words {
		pdu = append(pdu, byte(word>>8), byte(word))
	}
	raw, err := encodeTCPADU(reservation.TransactionID(), group.unitID, pdu)
	if err != nil {
		t.Fatal(err)
	}
	decoder, err := NewTCPStreamDecoder(260)
	if err != nil {
		t.Fatal(err)
	}
	frames, err := decoder.Feed(raw)
	if err != nil || len(frames) != 1 {
		t.Fatalf("response frames = %v, %v", frames, err)
	}
	response, err := owner.Correlate(reservation.Generation(), frames[0])
	if err != nil {
		t.Fatal(err)
	}
	return response
}
