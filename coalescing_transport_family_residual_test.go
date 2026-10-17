package modbus

import (
	"errors"
	"testing"
)

func TestCoalescingTransportResidualLateFamilyMismatch(t *testing.T) {
	for _, tc := range []struct {
		name     string
		matching TransportFamily
		late     TransportFamily
	}{
		{"tcp_tcp_rtu", TransportTCP, TransportRTU},
		{"rtu_rtu_tcp", TransportRTU, TransportTCP},
	} {
		t.Run(tc.name, func(t *testing.T) {
			makeIntents := func(last TransportFamily) []ReadIntent {
				t.Helper()
				intents := make([]ReadIntent, 3)
				for i := range intents {
					request, err := NewReadRegistersRequest(FunctionReadHoldingRegisters, uint16(10+i), uint16(3-i))
					if err != nil {
						t.Fatal(err)
					}
					family := tc.matching
					if i == 2 {
						family = last
					}
					intents[i], err = NewReadIntent(ReadIntentSpec{
						LogicalViewID:       uint64(i + 1),
						Endpoint:            "synthetic-endpoint",
						Transport:           family,
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
				}
				return intents
			}
			scheduler, err := newEndpointScheduler(SchedulerLimits{
				MaxActiveAdmissionKeys:         1,
				ProtectedSlotsPerKey:           1,
				SharedBurstSlots:               2,
				TotalQueued:                    3,
				MaxQueuedPerKey:                3,
				MaxQueuedPerAuthorizationScope: 3,
				MaxCoalescedDependentsPerKey:   3,
				MaxRetryAttempts:               1,
				MaxInFlightRequests:            1,
			})
			if err != nil {
				t.Fatal(err)
			}
			key := AdmissionKey{AuthorizationScope: "synthetic-scope", UnitID: 1}
			request := ScheduledRequest{RequestID: 100, Key: key, DeadlineOffset: 100}
			assertEmpty := func() {
				t.Helper()
				if got := scheduler.resourceSnapshot(); got != (endpointSchedulerResourceSnapshot{}) {
					t.Fatalf("scheduler resources = %+v, want zero occupancy and all three admission slots free", got)
				}
			}
			assertEmpty()
			group, err := scheduler.ScheduleCoalesced(request, makeIntents(tc.late))
			var protocolErr *ProtocolError
			if !errors.As(err, &protocolErr) || protocolErr.Kind != ErrorInvalidRequest || protocolErr.Field != "coalescing_identity" || group != nil {
				t.Fatalf("mixed-family admission = (%v, %v), want nil group and coalescing_identity rejection", group, err)
			}
			assertEmpty()
			group, err = scheduler.ScheduleCoalesced(request, makeIntents(tc.matching))
			if err != nil || group == nil {
				t.Fatalf("all-%s readmission = (%v, %v), want admitted group", tc.matching, group, err)
			}
			if got := scheduler.resourceSnapshot(); got != (endpointSchedulerResourceSnapshot{queuedRequests: 1, activeAdmissionKeys: 1, coalescedDependents: 3}) {
				t.Fatalf("readmission resources = %+v, want one queue entry, one key and three dependents", got)
			}
			if physical := group.PhysicalRequest(); physical.Offset() != 10 || physical.Quantity() != 3 {
				t.Fatalf("physical request = %+v, want [10,13)", physical)
			}
			if slices := group.Slices(); len(slices) != 3 {
				t.Fatalf("slices = %d, want three", len(slices))
			} else {
				for i, slice := range slices {
					if slice.LogicalViewID() != uint64(i+1) || slice.SliceOffset() != uint16(i) || slice.SliceWordCount() != uint16(3-i) {
						t.Fatalf("slice %d = %+v, want distinct logical ID and exact overlapping range", i, slice)
					}
				}
			}
			if err := scheduler.Enqueue(ScheduledRequest{RequestID: 101, Key: key, DeadlineOffset: 100}); err == nil {
				t.Fatal("fourth admission succeeded, want literal capacity of three")
			}
		})
	}
}
