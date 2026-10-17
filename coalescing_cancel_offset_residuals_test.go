package modbus

import (
	"errors"
	"testing"
)

func TestU10QueuedCancellationRecomputesOffsetsAndExtrema(t *testing.T) {
	for _, order := range []struct {
		name string
		ids  []uint64
	}{
		{"inner_then_middle", []uint64{2, 1, 3}},
		{"middle_then_inner", []uint64{3, 1, 2}},
	} {
		t.Run(order.name, func(t *testing.T) {
			group := u10QueuedGroup(t, order.ids)
			transition, err := group.Cancel(1)
			if err != nil {
				t.Fatalf("cancel outer range: %v", err)
			}
			if !transition.TransmitPhysical() || transition.AbandonTransport() {
				t.Fatalf("unexpected queued cancellation transition: %+v", transition)
			}
			u10AssertSurvivors(t, group)
		})
	}
}

func TestU10DuplicateCancelIdentifiesDependentOnLiveGroup(t *testing.T) {
	group := u10QueuedGroup(t, []uint64{2, 1, 3})
	if _, err := group.Cancel(1); err != nil {
		t.Fatalf("initial cancel: %v", err)
	}
	u10AssertSurvivors(t, group)

	transition, err := group.Cancel(1)
	var protocolErr *ProtocolError
	if !errors.As(err, &protocolErr) {
		t.Fatalf("duplicate cancel error = %v, want *ProtocolError", err)
	}
	if protocolErr.Field != "dependent_state" || protocolErr.Kind != ErrorInvalidRequest {
		t.Fatalf("duplicate cancel error = %+v, want invalid_request/dependent_state", protocolErr)
	}
	if transition.TransmitPhysical() || transition.AbandonTransport() || transition.CloseConnection() {
		t.Fatalf("duplicate cancel returned work: %+v", transition)
	}
	u10AssertSurvivors(t, group)
}

func u10QueuedGroup(t *testing.T, order []uint64) *CoalescedRead {
	t.Helper()
	// Synthetic common-overlap ranges: outer [10,30), inner [14,24), middle [12,28).
	ranges := map[uint64]struct{ start, words, initialOffset uint16 }{
		1: {10, 20, 0},
		2: {14, 10, 4},
		3: {12, 16, 2},
	}
	intents := make([]ReadIntent, 0, len(order))
	for _, id := range order {
		r := ranges[id]
		request, err := NewReadRegistersRequest(FunctionReadHoldingRegisters, r.start, r.words)
		if err != nil {
			t.Fatalf("request %d: %v", id, err)
		}
		intent, err := NewReadIntent(ReadIntentSpec{
			LogicalViewID: id, Endpoint: "u10-synthetic", Transport: TransportTCP,
			TransportGeneration: 1, UnitID: 1, AuthorizationScope: "u10-synthetic",
			PollGeneration: 1, DeadlineIdentity: 1, Request: request,
		})
		if err != nil {
			t.Fatalf("intent %d: %v", id, err)
		}
		intents = append(intents, intent)
	}
	group, err := coalesceReads(intents, 3)
	if err != nil {
		t.Fatalf("initial group: %v", err)
	}
	physical := group.PhysicalRequest()
	if physical.Offset() != 10 || physical.Quantity() != 20 || group.ActiveDependentCount() != 3 {
		t.Fatalf("initial control: physical=%+v active=%d", physical, group.ActiveDependentCount())
	}
	slices := group.Slices()
	if len(slices) != 3 {
		t.Fatalf("initial slices = %d, want 3", len(slices))
	}
	for index, slice := range slices {
		id := order[index]
		r := ranges[id]
		if slice.LogicalViewID() != id || slice.SliceOffset() != r.initialOffset || slice.SliceWordCount() != r.words {
			t.Fatalf("initial slice %d = %+v, want id=%d offset=%d width=%d", index, slice, id, r.initialOffset, r.words)
		}
		if group.DependentStates()[id] != DependentQueued {
			t.Fatalf("initial dependent %d is not queued", id)
		}
	}
	return group
}

func u10AssertSurvivors(t *testing.T, group *CoalescedRead) {
	t.Helper()
	// Hand-computed union [12,28), with inner [14,24) at 2 and middle [12,28) at 0.
	physical := group.PhysicalRequest()
	if physical.Offset() != 12 || physical.Quantity() != 16 {
		t.Errorf("surviving physical start/width = %d/%d, want 12/16", physical.Offset(), physical.Quantity())
	}
	if group.ActiveDependentCount() != 2 {
		t.Errorf("active dependents = %d, want 2", group.ActiveDependentCount())
	}
	states := group.DependentStates()
	if states[1] != DependentCancelled || states[2] != DependentQueued || states[3] != DependentQueued {
		t.Errorf("surviving states = %v, want outer cancelled and both survivors queued", states)
	}
	want := map[uint64]struct{ offset, words uint16 }{2: {2, 10}, 3: {0, 16}}
	for _, slice := range group.Slices() {
		expected, active := want[slice.LogicalViewID()]
		if !active {
			continue
		}
		if slice.SliceOffset() != expected.offset || slice.SliceWordCount() != expected.words {
			t.Errorf("survivor %d offset/width = %d/%d, want %d/%d", slice.LogicalViewID(), slice.SliceOffset(), slice.SliceWordCount(), expected.offset, expected.words)
		}
		delete(want, slice.LogicalViewID())
	}
	if len(want) != 0 {
		t.Errorf("missing surviving slices: %v", want)
	}
}
