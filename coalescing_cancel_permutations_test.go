package modbus

import (
	"fmt"
	"reflect"
	"testing"
)

func TestS20QueuedCancellationPermutations(t *testing.T) {
	// Half-open logical intervals share [14,18), with distinct outer bounds.
	ranges := [3]struct{ offset, quantity uint16 }{
		{10, 8},  // ID 1: [10,18)
		{12, 9},  // ID 2: [12,21)
		{14, 10}, // ID 3: [14,24)
	}
	// Each bit names a surviving ID. These are independent interval oracles,
	// not results from the implementation's union calculation.
	expected := map[uint8]struct {
		ids              []uint64
		offset, quantity uint16
	}{
		0: {ids: []uint64{}},
		1: {[]uint64{1}, 10, 8},
		2: {[]uint64{2}, 12, 9},
		3: {[]uint64{1, 2}, 10, 11},
		4: {[]uint64{3}, 14, 10},
		5: {[]uint64{1, 3}, 10, 14},
		6: {[]uint64{2, 3}, 12, 12},
		7: {[]uint64{1, 2, 3}, 10, 14},
	}
	orders := [][3]uint64{
		{1, 2, 3}, {1, 3, 2}, {2, 1, 3},
		{2, 3, 1}, {3, 1, 2}, {3, 2, 1},
	}
	for _, order := range orders {
		t.Run(fmt.Sprintf("%d_%d_%d", order[0], order[1], order[2]), func(t *testing.T) {
			intents := make([]ReadIntent, 0, 3)
			for index, interval := range ranges {
				request, err := NewReadRegistersRequest(
					FunctionReadHoldingRegisters, interval.offset, interval.quantity,
				)
				if err != nil {
					t.Fatal(err)
				}
				intent, err := NewReadIntent(ReadIntentSpec{
					LogicalViewID: uint64(index + 1), Endpoint: "synthetic-group",
					Transport: TransportTCP, TransportGeneration: 1, UnitID: 1,
					AuthorizationScope: "synthetic-scope", PollGeneration: 1,
					DeadlineIdentity: 1, Request: request,
				})
				if err != nil {
					t.Fatal(err)
				}
				intents = append(intents, intent)
			}
			group, err := coalesceReads(intents, 3)
			if err != nil {
				t.Fatal(err)
			}
			assertGroup := func(mask uint8, offset, quantity uint16) {
				t.Helper()
				states := group.DependentStates()
				if len(states) != 3 {
					t.Fatalf("survivors %03b: states = %v, want exactly three IDs", mask, states)
				}
				activeIDs := make([]uint64, 0, 3)
				for id := uint64(1); id <= 3; id++ {
					want := DependentCancelled
					if mask&(1<<(id-1)) != 0 {
						want = DependentQueued
					}
					if states[id] != want {
						t.Errorf("survivors %03b: ID %d state = %q, want %q", mask, id, states[id], want)
					}
					if states[id] == DependentQueued || states[id] == DependentAttached {
						activeIDs = append(activeIDs, id)
					}
				}
				if !reflect.DeepEqual(activeIDs, expected[mask].ids) {
					t.Errorf("survivors %03b: active IDs = %v, want %v", mask, activeIDs, expected[mask].ids)
				}
				if got := group.ActiveDependentCount(); got != len(expected[mask].ids) {
					t.Errorf("survivors %03b: active count = %d, want %d", mask, got, len(expected[mask].ids))
				}
				physical := group.PhysicalRequest()
				if physical.Function() != FunctionReadHoldingRegisters ||
					physical.Offset() != offset || physical.Quantity() != quantity {
					t.Errorf("survivors %03b: physical = %v, want FC03 offset=%d quantity=%d", mask, physical, offset, quantity)
				}
			}
			mask := uint8(7)
			assertGroup(mask, expected[mask].offset, expected[mask].quantity)
			terminalTransitions := 0
			for step, id := range order {
				mask &^= 1 << (id - 1)
				transition, err := group.Cancel(id)
				if err != nil {
					t.Fatalf("step %d cancel ID %d: %v", step, id, err)
				}
				if transition.TransmitPhysical() != (mask != 0) ||
					transition.AbandonTransport() || transition.CloseConnection() ||
					len(transition.FailedReservations()) != 0 {
					t.Fatalf("step %d cancel ID %d: transition = %#v", step, id, transition)
				}
				if !transition.TransmitPhysical() {
					terminalTransitions++
				}
				interval := expected[mask]
				if mask == 0 {
					// Completion suppresses transmission; the last physical value
					// remains the independently tabulated final singleton range.
					interval = expected[1<<(id-1)]
				}
				assertGroup(mask, interval.offset, interval.quantity)
				physicalBefore := group.PhysicalRequest()
				slicesBefore := group.Slices()
				for _, cancelledID := range order[:step+1] {
					duplicate, err := group.Cancel(cancelledID)
					if err == nil {
						t.Fatalf("duplicate cancel ID %d accepted", cancelledID)
					}
					if !reflect.DeepEqual(duplicate, CoalescedTransition{}) {
						t.Errorf("duplicate cancel ID %d emitted transition %#v", cancelledID, duplicate)
					}
					assertGroup(mask, interval.offset, interval.quantity)
					if !reflect.DeepEqual(group.PhysicalRequest(), physicalBefore) ||
						!reflect.DeepEqual(group.Slices(), slicesBefore) {
						t.Errorf("duplicate cancel ID %d changed physical request or slices", cancelledID)
					}
				}
			}
			if terminalTransitions != 1 {
				t.Fatalf("successful no-send transitions = %d, want 1", terminalTransitions)
			}
		})
	}
}
