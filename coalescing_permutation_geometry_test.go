package modbus

import (
	"errors"
	"fmt"
	"testing"
)

func TestS19ThreeReadGeometry(t *testing.T) {
	type interval struct {
		id       uint64
		start    uint16
		quantity uint16
	}
	type viewSlice struct {
		offset uint16
		words  uint16
	}
	tests := []struct {
		name          string
		ranges        [3]interval
		physicalStart uint16
		physicalWords uint16
		slices        map[uint64]viewSlice
		errorField    string
	}{
		{
			name:          "unequal_common_intersection",
			ranges:        [3]interval{{101, 10, 10}, {205, 12, 7}, {309, 14, 3}},
			physicalStart: 10,
			physicalWords: 10,
			slices: map[uint64]viewSlice{
				101: {0, 10}, 205: {2, 7}, 309: {4, 3},
			},
		},
		{
			name:       "chain_without_common_intersection",
			ranges:     [3]interval{{101, 10, 5}, {205, 14, 6}, {309, 19, 7}},
			errorField: "non_overlapping_ranges",
		},
		{
			name:          "nearby_common_intersection",
			ranges:        [3]interval{{101, 10, 5}, {205, 14, 6}, {309, 14, 7}},
			physicalStart: 10,
			physicalWords: 11,
			slices: map[uint64]viewSlice{
				101: {0, 5}, 205: {4, 6}, 309: {4, 7},
			},
		},
		{
			name:          "union_125_words",
			ranges:        [3]interval{{101, 100, 60}, {205, 140, 70}, {309, 150, 75}},
			physicalStart: 100,
			physicalWords: 125,
			slices: map[uint64]viewSlice{
				101: {0, 60}, 205: {40, 70}, 309: {50, 75},
			},
		},
		{
			name:       "union_126_words",
			ranges:     [3]interval{{101, 100, 60}, {205, 140, 70}, {309, 150, 76}},
			errorField: "physical_union",
		},
	}
	permutations := [][3]int{
		{0, 1, 2}, {0, 2, 1}, {1, 0, 2},
		{1, 2, 0}, {2, 0, 1}, {2, 1, 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, permutation := range permutations {
				t.Run(fmt.Sprintf("order_%d%d%d", permutation[0], permutation[1], permutation[2]), func(t *testing.T) {
					intents := make([]ReadIntent, 0, 3)
					for _, index := range permutation {
						r := test.ranges[index]
						request, err := NewReadRegistersRequest(FunctionReadHoldingRegisters, r.start, r.quantity)
						if err != nil {
							t.Fatal(err)
						}
						intent, err := NewReadIntent(ReadIntentSpec{
							LogicalViewID:       r.id,
							Endpoint:            "synthetic-endpoint",
							Transport:           TransportTCP,
							TransportGeneration: 7,
							UnitID:              1,
							AuthorizationScope:  "synthetic-scope",
							PollGeneration:      11,
							DeadlineIdentity:    13,
							Request:             request,
						})
						if err != nil {
							t.Fatal(err)
						}
						intents = append(intents, intent)
					}
					group, err := CoalesceReads(intents, 3)
					if test.errorField != "" {
						var protocolErr *ProtocolError
						if !errors.As(err, &protocolErr) || protocolErr.Kind != ErrorInvalidRange || protocolErr.Field != test.errorField {
							t.Fatalf("error = %v, want invalid range field %q", err, test.errorField)
						}
						if group != nil {
							t.Fatal("rejected geometry returned a group")
						}
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					physical := group.PhysicalRequest()
					if physical.Function() != FunctionReadHoldingRegisters || physical.Offset() != test.physicalStart || physical.Quantity() != test.physicalWords {
						t.Fatalf("physical request = %v, want FC03 start=%d words=%d", physical, test.physicalStart, test.physicalWords)
					}
					slices := group.Slices()
					if len(slices) != len(test.slices) {
						t.Fatalf("slice count = %d, want %d", len(slices), len(test.slices))
					}
					seen := make(map[uint64]bool, len(slices))
					for _, slice := range slices {
						id := slice.LogicalViewID()
						want, ok := test.slices[id]
						if !ok || seen[id] {
							t.Fatalf("unexpected or duplicate logical view ID %d", id)
						}
						seen[id] = true
						if slice.SliceOffset() != want.offset || slice.SliceWordCount() != want.words {
							t.Errorf("view %d slice = (%d,%d), want (%d,%d)", id, slice.SliceOffset(), slice.SliceWordCount(), want.offset, want.words)
						}
					}
				})
			}
		})
	}
}
