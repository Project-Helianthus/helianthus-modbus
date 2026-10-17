package modbus

import (
	"errors"
	"fmt"
	"testing"
)

var u19IntentOrders = [][3]uint64{
	{101, 102, 103},
	{102, 101, 103},
	{101, 103, 102},
	{102, 103, 101},
	{103, 101, 102},
	{103, 102, 101},
}

func u19ReadIntents(t *testing.T, order [3]uint64, change func(*ReadIntentSpec)) []ReadIntent {
	t.Helper()
	intents := make([]ReadIntent, 0, len(order))
	for _, id := range order {
		request, err := NewReadRegistersRequest(FunctionReadHoldingRegisters, 10, 3)
		if err != nil {
			t.Fatal(err)
		}
		spec := ReadIntentSpec{
			LogicalViewID:       id,
			Endpoint:            "u19-endpoint-a",
			Transport:           TransportTCP,
			TransportGeneration: 7,
			UnitID:              1,
			AuthorizationScope:  "u19-scope-a",
			PollGeneration:      11,
			DeadlineIdentity:    13,
			Request:             request,
		}
		if id == 103 && change != nil {
			change(&spec)
		}
		intent, err := NewReadIntent(spec)
		if err != nil {
			t.Fatalf("individually valid intent %d: %v", id, err)
		}
		intents = append(intents, intent)
	}
	return intents
}

func TestU19LateIdentityMismatch(t *testing.T) {
	cases := []struct {
		name   string
		change func(*ReadIntentSpec)
	}{
		{"endpoint", func(spec *ReadIntentSpec) { spec.Endpoint = "u19-endpoint-b" }},
		{"transport_generation", func(spec *ReadIntentSpec) { spec.TransportGeneration = 8 }},
		{"unit", func(spec *ReadIntentSpec) { spec.UnitID = 2 }},
		{"scope_token", func(spec *ReadIntentSpec) { spec.AuthorizationScope = "u19-scope-b" }},
		{"poll_generation", func(spec *ReadIntentSpec) { spec.PollGeneration = 12 }},
		{"deadline_identity", func(spec *ReadIntentSpec) { spec.DeadlineIdentity = 14 }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			for _, order := range u19IntentOrders {
				t.Run(fmt.Sprintf("order_%d_%d_%d", order[0], order[1], order[2]), func(t *testing.T) {
					intents := u19ReadIntents(t, order, test.change)
					group, err := coalesceReads(intents, 3)
					var failure *ProtocolError
					if !errors.As(err, &failure) || failure.Kind != ErrorInvalidRequest || failure.Field != "coalescing_identity" {
						t.Errorf("error = %v, want invalid_request at coalescing_identity", err)
					}
					if group != nil {
						t.Errorf("mismatched identity admitted a group with %d dependents", len(group.Slices()))
					}
				})
			}
		})
	}
}

func TestU19MatchingIdentityControl(t *testing.T) {
	for _, order := range u19IntentOrders {
		t.Run(fmt.Sprintf("order_%d_%d_%d", order[0], order[1], order[2]), func(t *testing.T) {
			group, err := coalesceReads(u19ReadIntents(t, order, nil), 3)
			if err != nil || group == nil {
				t.Fatalf("matching identities: group=%v error=%v", group, err)
			}
			physical := group.PhysicalRequest()
			if physical.Function() != FunctionReadHoldingRegisters || physical.Offset() != 10 || physical.Quantity() != 3 {
				t.Errorf("physical request = %#v, want FC03 range [10,13)", physical)
			}
			slices := group.Slices()
			if len(slices) != 3 {
				t.Fatalf("dependents = %d, want exactly 3", len(slices))
			}
			states := group.DependentStates()
			if len(states) != 3 {
				t.Fatalf("dependent states = %v, want exactly 3", states)
			}
			for index, id := range order {
				if slices[index].LogicalViewID() != id || slices[index].SliceOffset() != 0 || slices[index].SliceWordCount() != 3 {
					t.Errorf("slice %d = %#v, want logical ID %d, offset 0, words 3", index, slices[index], id)
				}
				if states[id] != DependentQueued {
					t.Errorf("dependent %d state = %q, want queued", id, states[id])
				}
			}
		})
	}
}
