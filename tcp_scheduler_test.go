package modbus

import (
	"context"
	"math"
	"testing"
	"time"
)

func testScheduler(t *testing.T) *EndpointScheduler {
	t.Helper()
	scheduler, err := newEndpointScheduler(SchedulerLimits{
		MaxActiveAdmissionKeys:         3,
		ProtectedSlotsPerKey:           2,
		SharedBurstSlots:               2,
		TotalQueued:                    8,
		MaxQueuedPerKey:                4,
		MaxQueuedPerAuthorizationScope: 8,
		MaxCoalescedDependentsPerKey:   4,
		MaxRetryAttempts:               2,
		MaxInFlightRequests:            4,
	})
	if err != nil {
		t.Fatal(err)
	}
	return scheduler
}

func scheduledRequest(
	id uint64,
	scope string,
	unitID byte,
	deadline int64,
) ScheduledRequest {
	return ScheduledRequest{
		RequestID: id,
		Key: AdmissionKey{
			AuthorizationScope: scope,
			UnitID:             unitID,
		},
		DeadlineOffset: deadline,
	}
}

func schedulerReadIntent(
	t *testing.T,
	logicalViewID uint64,
	offset uint16,
	quantity uint16,
	deadlineIdentity uint64,
) ReadIntent {
	t.Helper()
	request, err := NewReadRegistersRequest(
		FunctionReadHoldingRegisters,
		offset,
		quantity,
	)
	if err != nil {
		t.Fatal(err)
	}
	intent, err := NewReadIntent(ReadIntentSpec{
		LogicalViewID:       logicalViewID,
		Endpoint:            "tcp://192.0.2.10:502",
		Transport:           TransportTCP,
		TransportGeneration: 7,
		UnitID:              1,
		AuthorizationScope:  "site-a",
		PollGeneration:      11,
		DeadlineIdentity:    deadlineIdentity,
		Request:             request,
	})
	if err != nil {
		t.Fatal(err)
	}
	return intent
}

func TestSchedulerRejectsInvalidOverflowingAndInconsistentLimits(t *testing.T) {
	valid := SchedulerLimits{
		MaxActiveAdmissionKeys:         2,
		ProtectedSlotsPerKey:           2,
		SharedBurstSlots:               1,
		TotalQueued:                    5,
		MaxQueuedPerKey:                3,
		MaxQueuedPerAuthorizationScope: 5,
		MaxCoalescedDependentsPerKey:   2,
		MaxRetryAttempts:               2,
		MaxInFlightRequests:            2,
	}
	tests := []struct {
		name   string
		change func(*SchedulerLimits)
	}{
		{"zero", func(limits *SchedulerLimits) { limits.MaxActiveAdmissionKeys = 0 }},
		{"negative", func(limits *SchedulerLimits) { limits.SharedBurstSlots = -1 }},
		{"multiplication overflow", func(limits *SchedulerLimits) {
			limits.MaxActiveAdmissionKeys = math.MaxInt
			limits.ProtectedSlotsPerKey = 2
			limits.TotalQueued = math.MaxInt
		}},
		{"protected capacity absent", func(limits *SchedulerLimits) {
			limits.TotalQueued = 4
		}},
		{"per-key below protected", func(limits *SchedulerLimits) {
			limits.MaxQueuedPerKey = 1
		}},
		{"per-key above total", func(limits *SchedulerLimits) {
			limits.MaxQueuedPerKey = 6
		}},
		{"scope below protected", func(limits *SchedulerLimits) {
			limits.MaxQueuedPerAuthorizationScope = 1
		}},
		{"dependent below protected", func(limits *SchedulerLimits) {
			limits.MaxCoalescedDependentsPerKey = 1
		}},
		{"scope cannot protect all keys", func(limits *SchedulerLimits) {
			limits.MaxQueuedPerAuthorizationScope = 3
		}},
		{"retry attempts zero", func(limits *SchedulerLimits) {
			limits.MaxRetryAttempts = 0
		}},
		{"in-flight zero", func(limits *SchedulerLimits) {
			limits.MaxInFlightRequests = 0
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			limits := valid
			test.change(&limits)
			_, err := newEndpointScheduler(limits)
			_ = requireProtocolError(t, err, ErrorInvalidRequest)
		})
	}
}

func TestSchedulerAdmissionArithmeticFailsClosed(t *testing.T) {
	scheduler := testScheduler(t)
	request := scheduledRequest(1, "a", 1, 100)
	if err := scheduler.Enqueue(request); err != nil {
		t.Fatal(err)
	}
	key := request.Key
	scheduler.mu.Lock()
	state := scheduler.keys[key]
	state.queued = math.MaxInt
	state.dependents = 1
	scheduler.mu.Unlock()

	err := scheduler.Enqueue(scheduledRequest(2, "a", 1, 100))
	protocolErr := requireProtocolError(t, err, ErrorInvalidRange)
	if protocolErr.Field != "admission_accounting" {
		t.Fatalf("overflow field = %q", protocolErr.Field)
	}

	scheduler.mu.Lock()
	state.queued = scheduler.limits.MaxQueuedPerKey + 1
	state.dependents = 0
	scheduler.mu.Unlock()
	err = scheduler.Enqueue(scheduledRequest(3, "a", 1, 100))
	protocolErr = requireProtocolError(t, err, ErrorInvalidRange)
	if protocolErr.Field != "admission_accounting" {
		t.Fatalf("underflow field = %q", protocolErr.Field)
	}
}

func TestSchedulerPreservesCapacityForInactiveAdmissionKeys(t *testing.T) {
	scheduler, err := newEndpointScheduler(SchedulerLimits{
		MaxActiveAdmissionKeys:         2,
		ProtectedSlotsPerKey:           2,
		SharedBurstSlots:               1,
		TotalQueued:                    5,
		MaxQueuedPerKey:                3,
		MaxQueuedPerAuthorizationScope: 5,
		MaxCoalescedDependentsPerKey:   2,
		MaxRetryAttempts:               2,
		MaxInFlightRequests:            2,
	})
	if err != nil {
		t.Fatal(err)
	}
	for id := uint64(1); id <= 3; id++ {
		if err := scheduler.Enqueue(scheduledRequest(id, "a", 1, 100)); err != nil {
			t.Fatal(err)
		}
	}
	err = scheduler.Enqueue(scheduledRequest(4, "a", 1, 100))
	_ = requireProtocolError(t, err, ErrorInvalidRange)
	if err := scheduler.Enqueue(scheduledRequest(5, "b", 2, 100)); err != nil {
		t.Fatal("first protected request for second key was rejected:", err)
	}
	if err := scheduler.Enqueue(scheduledRequest(6, "b", 2, 100)); err != nil {
		t.Fatal("second protected request for second key was rejected:", err)
	}
	err = scheduler.Enqueue(scheduledRequest(7, "c", 3, 100))
	_ = requireProtocolError(t, err, ErrorInvalidRange)
}

func TestSchedulerPreservesProtectedDeficitForActiveKeys(t *testing.T) {
	scheduler, err := newEndpointScheduler(SchedulerLimits{
		MaxActiveAdmissionKeys:         2,
		ProtectedSlotsPerKey:           2,
		SharedBurstSlots:               1,
		TotalQueued:                    5,
		MaxQueuedPerKey:                5,
		MaxQueuedPerAuthorizationScope: 5,
		MaxCoalescedDependentsPerKey:   2,
		MaxRetryAttempts:               1,
		MaxInFlightRequests:            2,
	})
	if err != nil {
		t.Fatal(err)
	}
	for id := uint64(1); id <= 3; id++ {
		if err := scheduler.Enqueue(scheduledRequest(id, "a", 1, 100)); err != nil {
			t.Fatal(err)
		}
	}
	if err := scheduler.Enqueue(scheduledRequest(4, "b", 2, 100)); err != nil {
		t.Fatal(err)
	}
	err = scheduler.Enqueue(scheduledRequest(5, "a", 1, 100))
	_ = requireProtocolError(t, err, ErrorInvalidRange)
	if err := scheduler.Enqueue(scheduledRequest(6, "b", 2, 100)); err != nil {
		t.Fatal("active key could not claim protected deficit:", err)
	}
}

func TestSchedulerIsScopeThenUnitRoundRobinAndFIFOWithinKey(t *testing.T) {
	scheduler := testScheduler(t)
	requests := []ScheduledRequest{
		scheduledRequest(1, "a", 1, 100),
		scheduledRequest(2, "a", 1, 100),
		scheduledRequest(3, "a", 2, 100),
		scheduledRequest(4, "a", 2, 100),
		scheduledRequest(5, "b", 1, 100),
		scheduledRequest(6, "b", 1, 100),
	}
	for _, request := range requests {
		if err := scheduler.Enqueue(request); err != nil {
			t.Fatal(err)
		}
	}
	want := []uint64{1, 5, 3, 6, 2, 4}
	for index, requestID := range want {
		request, ok := scheduler.Dispatch(0)
		if !ok {
			t.Fatalf("dispatch %d returned empty", index)
		}
		if request.RequestID != requestID {
			t.Fatalf(
				"dispatch %d = %d, want %d",
				index,
				request.RequestID,
				requestID,
			)
		}
		if err := scheduler.Complete(request.RequestID); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSchedulerKeepsTCPUnitZeroAndUnitOneAdmissionKeysDistinct(t *testing.T) {
	scheduler := testScheduler(t)
	if err := scheduler.Enqueue(scheduledRequest(1, "site", 0, 100)); err != nil {
		t.Fatal(err)
	}
	if err := scheduler.Enqueue(scheduledRequest(2, "site", 1, 100)); err != nil {
		t.Fatal(err)
	}
	first, ok := scheduler.Dispatch(0)
	if !ok || first.Key.UnitID != 0 {
		t.Fatalf("first dispatch=%#v ok=%v", first, ok)
	}
	second, ok := scheduler.Dispatch(0)
	if !ok || second.Key.UnitID != 1 {
		t.Fatalf("second dispatch=%#v ok=%v", second, ok)
	}
}

func TestSchedulerSkipsExpirySupportsCancellationAndRetriesAtTail(t *testing.T) {
	scheduler := testScheduler(t)
	if err := scheduler.Enqueue(scheduledRequest(1, "a", 1, 5)); err != nil {
		t.Fatal(err)
	}
	if err := scheduler.Enqueue(scheduledRequest(2, "a", 1, 100)); err != nil {
		t.Fatal(err)
	}
	if err := scheduler.Enqueue(scheduledRequest(3, "a", 1, 100)); err != nil {
		t.Fatal(err)
	}
	if !scheduler.CancelQueued(3) {
		t.Fatal("queued cancellation did not remove request")
	}
	request, ok := scheduler.Dispatch(5)
	if !ok || request.RequestID != 2 {
		t.Fatalf("dispatch after expiry = %#v, %v", request, ok)
	}
	if err := scheduler.Enqueue(scheduledRequest(4, "a", 1, 100)); err != nil {
		t.Fatal(err)
	}
	if err := scheduler.Retry(request.RequestID); err != nil {
		t.Fatal(err)
	}
	request, ok = scheduler.Dispatch(5)
	if !ok || request.RequestID != 4 {
		t.Fatalf("retry jumped queue: %#v, %v", request, ok)
	}
	_ = scheduler.Complete(request.RequestID)
	request, ok = scheduler.Dispatch(5)
	if !ok || request.RequestID != 2 {
		t.Fatalf("retry did not re-enter at tail: %#v, %v", request, ok)
	}
}

func TestAdmissionKeyStaysActiveUntilQueueInflightAndDependentsEmpty(t *testing.T) {
	scheduler, err := newEndpointScheduler(SchedulerLimits{
		MaxActiveAdmissionKeys:         1,
		ProtectedSlotsPerKey:           1,
		SharedBurstSlots:               1,
		TotalQueued:                    2,
		MaxQueuedPerKey:                2,
		MaxQueuedPerAuthorizationScope: 2,
		MaxCoalescedDependentsPerKey:   2,
		MaxRetryAttempts:               2,
		MaxInFlightRequests:            1,
	})
	if err != nil {
		t.Fatal(err)
	}
	key := AdmissionKey{AuthorizationScope: "a", UnitID: 1}
	if err := scheduler.Enqueue(scheduledRequest(1, "a", 1, 100)); err != nil {
		t.Fatal(err)
	}
	if err := scheduler.attachDependent(key); err != nil {
		t.Fatal(err)
	}
	request, ok := scheduler.Dispatch(0)
	if !ok {
		t.Fatal("queued request not dispatched")
	}
	other := scheduledRequest(2, "b", 2, 100)
	err = scheduler.Enqueue(other)
	_ = requireProtocolError(t, err, ErrorInvalidRange)
	if err := scheduler.Complete(request.RequestID); err != nil {
		t.Fatal(err)
	}
	err = scheduler.Enqueue(other)
	_ = requireProtocolError(t, err, ErrorInvalidRange)
	if err := scheduler.detachDependent(key); err != nil {
		t.Fatal(err)
	}
	if err := scheduler.Enqueue(other); err != nil {
		t.Fatal("empty key did not release active position:", err)
	}
}

func TestSchedulerRetryLimitFailsAndReleasesRequest(t *testing.T) {
	scheduler := testScheduler(t)
	if err := scheduler.Enqueue(scheduledRequest(1, "a", 1, 100)); err != nil {
		t.Fatal(err)
	}
	for retry := 0; retry < 2; retry++ {
		request, ok := scheduler.Dispatch(0)
		if !ok || request.RequestID != 1 {
			t.Fatalf("retry dispatch = %#v, %v", request, ok)
		}
		if err := scheduler.Retry(request.RequestID); err != nil {
			t.Fatal(err)
		}
	}
	request, ok := scheduler.Dispatch(0)
	if !ok || request.RequestID != 1 {
		t.Fatalf("final dispatch = %#v, %v", request, ok)
	}
	err := scheduler.Retry(request.RequestID)
	_ = requireProtocolError(t, err, ErrorInvalidRange)
	if err := scheduler.Enqueue(scheduledRequest(2, "b", 2, 100)); err != nil {
		t.Fatal("retry exhaustion retained admission key:", err)
	}
}

func TestSchedulerRetryAdmissionFailureReleasesInFlightSlot(t *testing.T) {
	scheduler, err := newEndpointScheduler(SchedulerLimits{
		MaxActiveAdmissionKeys:         1,
		ProtectedSlotsPerKey:           1,
		SharedBurstSlots:               1,
		TotalQueued:                    2,
		MaxQueuedPerKey:                2,
		MaxQueuedPerAuthorizationScope: 2,
		MaxCoalescedDependentsPerKey:   2,
		MaxRetryAttempts:               2,
		MaxInFlightRequests:            1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := scheduler.Enqueue(scheduledRequest(1, "a", 1, 100)); err != nil {
		t.Fatal(err)
	}
	if err := scheduler.Enqueue(scheduledRequest(2, "a", 1, 100)); err != nil {
		t.Fatal(err)
	}
	request, ok := scheduler.Dispatch(0)
	if !ok || request.RequestID != 1 {
		t.Fatalf("dispatch = %#v, %v", request, ok)
	}
	if err := scheduler.Enqueue(scheduledRequest(3, "a", 1, 100)); err != nil {
		t.Fatal(err)
	}
	err = scheduler.Retry(1)
	_ = requireProtocolError(t, err, ErrorInvalidRange)
	request, ok = scheduler.Dispatch(0)
	if !ok || request.RequestID != 2 {
		t.Fatalf("retry rejection retained in-flight slot: %#v, %v", request, ok)
	}
}

func TestCoalescedDependentsConsumeTotalAndScopeAdmission(t *testing.T) {
	scheduler, err := newEndpointScheduler(SchedulerLimits{
		MaxActiveAdmissionKeys:         2,
		ProtectedSlotsPerKey:           1,
		SharedBurstSlots:               2,
		TotalQueued:                    4,
		MaxQueuedPerKey:                4,
		MaxQueuedPerAuthorizationScope: 4,
		MaxCoalescedDependentsPerKey:   4,
		MaxRetryAttempts:               1,
		MaxInFlightRequests:            1,
	})
	if err != nil {
		t.Fatal(err)
	}
	intents := []ReadIntent{
		schedulerReadIntent(t, 1, 10, 4, 13),
		schedulerReadIntent(t, 2, 11, 4, 13),
		schedulerReadIntent(t, 3, 12, 4, 13),
		schedulerReadIntent(t, 4, 13, 4, 13),
	}
	if _, err := scheduler.ScheduleCoalesced(
		scheduledRequest(100, "site-a", 1, 50),
		intents,
	); err == nil {
		t.Fatal("coalesced dependents bypassed protected capacity")
	}
	scheduler, _ = newEndpointScheduler(scheduler.limits)
	if _, err := scheduler.ScheduleCoalesced(
		scheduledRequest(100, "site-a", 1, 50),
		intents[:3],
	); err != nil {
		t.Fatal(err)
	}
	otherFirst := schedulerReadIntent(t, 5, 20, 2, 13)
	otherFirst.spec.UnitID = 2
	otherSecond := schedulerReadIntent(t, 6, 21, 2, 13)
	otherSecond.spec.UnitID = 2
	if _, err := scheduler.ScheduleCoalesced(
		scheduledRequest(101, "site-a", 2, 50),
		[]ReadIntent{otherFirst, otherSecond},
	); err == nil {
		t.Fatal("coalesced dependents bypassed total/scope admission")
	}
}

func TestScheduleCoalescedRequiresExplicitFiniteDeadlineOffset(t *testing.T) {
	intent := schedulerReadIntent(
		t,
		11,
		10,
		4,
		math.MaxUint64,
	)
	for _, deadline := range []int64{0, -1} {
		scheduler := testScheduler(t)
		_, err := scheduler.ScheduleCoalesced(
			scheduledRequest(100, "site-a", 1, deadline),
			[]ReadIntent{intent},
		)
		_ = requireProtocolError(t, err, ErrorInvalidRequest)
	}

	scheduler := testScheduler(t)
	group, err := scheduler.ScheduleCoalesced(
		scheduledRequest(100, "site-a", 1, 50),
		[]ReadIntent{intent},
	)
	if err != nil {
		t.Fatal(err)
	}
	request, ok := scheduler.Dispatch(49)
	if !ok || request.RequestID != 100 {
		t.Fatalf(
			"deadline identity was treated as offset: %#v, %v",
			request,
			ok,
		)
	}
	if err := scheduler.RequireCoalescedDispatch(group); err != nil {
		t.Fatal(err)
	}
}

func TestCoalescedPhysicalReadUsesSchedulerDispatchLifecycle(t *testing.T) {
	scheduler, err := newEndpointScheduler(SchedulerLimits{
		MaxActiveAdmissionKeys:         2,
		ProtectedSlotsPerKey:           1,
		SharedBurstSlots:               2,
		TotalQueued:                    4,
		MaxQueuedPerKey:                4,
		MaxQueuedPerAuthorizationScope: 4,
		MaxCoalescedDependentsPerKey:   4,
		MaxRetryAttempts:               1,
		MaxInFlightRequests:            1,
	})
	if err != nil {
		t.Fatal(err)
	}
	first := schedulerReadIntent(t, 11, 10, 4, 13)
	second := schedulerReadIntent(t, 12, 11, 4, 13)
	group, err := scheduler.ScheduleCoalesced(
		scheduledRequest(100, "site-a", 1, 50),
		[]ReadIntent{first, second},
	)
	if err != nil {
		t.Fatal(err)
	}
	other := scheduledRequest(200, "site-b", 2, 50)
	if err := scheduler.Enqueue(other); err != nil {
		t.Fatal(err)
	}
	if err := scheduler.RequireCoalescedDispatch(group); err == nil {
		t.Fatal("coalesced write admitted before scheduler dispatch")
	}

	dispatched, ok := scheduler.Dispatch(0)
	if !ok || dispatched.RequestID != 100 {
		t.Fatalf("coalesced dispatch = %#v, %v", dispatched, ok)
	}
	if got, ok := scheduler.CoalescedGroup(dispatched.RequestID); !ok ||
		got != group {
		t.Fatalf("coalesced token resolved to %p, %v", got, ok)
	}
	if err := scheduler.RequireCoalescedDispatch(group); err != nil {
		t.Fatal("dispatched coalesced write was rejected:", err)
	}
	if _, ok := scheduler.Dispatch(0); ok {
		t.Fatal("coalesced physical request bypassed in-flight bound")
	}
	if err := scheduler.RetryCoalesced(group); err != nil {
		t.Fatal(err)
	}
	if err := scheduler.RequireCoalescedDispatch(group); err == nil {
		t.Fatal("retried coalesced write admitted before redispatch")
	}

	dispatched, ok = scheduler.Dispatch(0)
	if !ok || dispatched.RequestID != 200 {
		t.Fatalf("retry jumped fair queue: %#v, %v", dispatched, ok)
	}
	if err := scheduler.Complete(dispatched.RequestID); err != nil {
		t.Fatal(err)
	}
	dispatched, ok = scheduler.Dispatch(0)
	if !ok || dispatched.RequestID != 100 {
		t.Fatalf("coalesced retry was not dispatched: %#v, %v", dispatched, ok)
	}
	if err := group.FailTransport(); err != nil {
		t.Fatal(err)
	}
	if err := scheduler.FinishCoalesced(group); err != nil {
		t.Fatal(err)
	}
	if scheduler.OrderMetadataSize() != 0 {
		t.Fatalf("terminal group retained scheduler metadata: %d", scheduler.OrderMetadataSize())
	}
}

func TestFinalQueuedCoalescedCancellationReleasesDispatchToken(t *testing.T) {
	scheduler := testScheduler(t)
	group, err := scheduler.ScheduleCoalesced(
		scheduledRequest(100, "site-a", 1, 50),
		[]ReadIntent{
			schedulerReadIntent(t, 11, 10, 4, 13),
			schedulerReadIntent(t, 12, 11, 4, 13),
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := group.Cancel(11); err != nil {
		t.Fatal(err)
	}
	if _, err := group.Cancel(12); err != nil {
		t.Fatal(err)
	}
	if err := scheduler.FinishCoalesced(group); err != nil {
		t.Fatal(err)
	}
	states := group.DependentStates()
	if states[11] != DependentCancelled ||
		states[12] != DependentCancelled {
		t.Fatalf("cancelled dependent states = %#v", states)
	}
	if request, ok := scheduler.Dispatch(0); ok {
		t.Fatalf("cancelled physical request dispatched: %#v", request)
	}
	if scheduler.OrderMetadataSize() != 0 {
		t.Fatalf("cancelled group retained scheduler metadata: %d", scheduler.OrderMetadataSize())
	}
}

func TestCoalescedPhysicalReadExpiresWithoutTransportWrite(t *testing.T) {
	scheduler := testScheduler(t)
	group, err := scheduler.ScheduleCoalesced(
		scheduledRequest(100, "site-a", 1, 10),
		[]ReadIntent{
			schedulerReadIntent(t, 11, 10, 4, math.MaxUint64),
			schedulerReadIntent(t, 12, 11, 4, math.MaxUint64),
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if request, ok := scheduler.Dispatch(10); ok {
		t.Fatalf("expired coalesced request dispatched: %#v", request)
	}
	states := group.DependentStates()
	if states[11] != DependentFailed || states[12] != DependentFailed {
		t.Fatalf("expired dependent states = %#v", states)
	}
	if _, ok := scheduler.CoalescedGroup(100); ok {
		t.Fatal("expired coalesced dispatch token remained live")
	}
	if scheduler.OrderMetadataSize() != 0 {
		t.Fatalf("expired group retained scheduler metadata: %d", scheduler.OrderMetadataSize())
	}
}

func TestSchedulerScopeRemovalPreservesNextRoundRobinPeer(t *testing.T) {
	scheduler := testScheduler(t)
	requests := []ScheduledRequest{
		scheduledRequest(1, "a", 1, 100),
		scheduledRequest(2, "a", 1, 100),
		scheduledRequest(3, "b", 1, 100),
	}
	for _, request := range requests {
		if err := scheduler.Enqueue(request); err != nil {
			t.Fatal(err)
		}
	}
	first, ok := scheduler.Dispatch(0)
	if !ok || first.RequestID != 1 {
		t.Fatalf("first dispatch = %#v, %v", first, ok)
	}
	if err := scheduler.Complete(first.RequestID); err != nil {
		t.Fatal(err)
	}
	for id := uint64(4); id < 68; id++ {
		if err := scheduler.Enqueue(scheduledRequest(id, "c", 1, 100)); err != nil {
			t.Fatal(err)
		}
		if !scheduler.CancelQueued(id) {
			t.Fatal("transient scope was not cancelled")
		}
	}
	next, ok := scheduler.Dispatch(0)
	if !ok || next.RequestID != 3 {
		t.Fatalf("transient scope reset cursor and starved b: %#v, %v", next, ok)
	}
}

func TestSchedulerUnitRemovalPreservesNextRoundRobinPeer(t *testing.T) {
	scheduler := testScheduler(t)
	requests := []ScheduledRequest{
		scheduledRequest(1, "a", 1, 100),
		scheduledRequest(2, "a", 1, 100),
		scheduledRequest(3, "a", 2, 100),
	}
	for _, request := range requests {
		if err := scheduler.Enqueue(request); err != nil {
			t.Fatal(err)
		}
	}
	first, ok := scheduler.Dispatch(0)
	if !ok || first.RequestID != 1 {
		t.Fatalf("first dispatch = %#v, %v", first, ok)
	}
	if err := scheduler.Complete(first.RequestID); err != nil {
		t.Fatal(err)
	}
	for id := uint64(4); id < 68; id++ {
		if err := scheduler.Enqueue(scheduledRequest(id, "a", 3, 100)); err != nil {
			t.Fatal(err)
		}
		if !scheduler.CancelQueued(id) {
			t.Fatal("transient unit was not cancelled")
		}
	}
	next, ok := scheduler.Dispatch(0)
	if !ok || next.RequestID != 3 {
		t.Fatalf("transient unit reset cursor and starved unit 2: %#v, %v", next, ok)
	}
}

func TestSchedulerBoundsInflightRequests(t *testing.T) {
	scheduler := testScheduler(t)
	for id := uint64(1); id <= 4; id++ {
		if err := scheduler.Enqueue(scheduledRequest(id, "a", 1, 100)); err != nil {
			t.Fatal(err)
		}
	}
	for count := 0; count < 4; count++ {
		if _, ok := scheduler.Dispatch(0); !ok {
			t.Fatalf("dispatch %d unexpectedly blocked", count)
		}
	}
	if err := scheduler.Enqueue(scheduledRequest(5, "a", 1, 100)); err != nil {
		t.Fatal(err)
	}
	if request, ok := scheduler.Dispatch(0); ok {
		t.Fatalf("in-flight overflow dispatched %#v", request)
	}
	if err := scheduler.Complete(1); err != nil {
		t.Fatal(err)
	}
	if request, ok := scheduler.Dispatch(0); !ok || request.RequestID != 5 {
		t.Fatalf("released in-flight slot dispatched %#v, %v", request, ok)
	}
}

func TestSchedulerPrunesHistoricalScopeAndUnitMetadata(t *testing.T) {
	scheduler, err := newEndpointScheduler(SchedulerLimits{
		MaxActiveAdmissionKeys:         1,
		ProtectedSlotsPerKey:           1,
		SharedBurstSlots:               1,
		TotalQueued:                    2,
		MaxQueuedPerKey:                2,
		MaxQueuedPerAuthorizationScope: 2,
		MaxCoalescedDependentsPerKey:   1,
		MaxRetryAttempts:               1,
		MaxInFlightRequests:            1,
	})
	if err != nil {
		t.Fatal(err)
	}
	for id := uint64(1); id <= 100; id++ {
		scope := string(rune('a' + id))
		if err := scheduler.Enqueue(scheduledRequest(id, scope, 1, 100)); err != nil {
			t.Fatal(err)
		}
		request, ok := scheduler.Dispatch(0)
		if !ok {
			t.Fatal("request not dispatched")
		}
		if err := scheduler.Complete(request.RequestID); err != nil {
			t.Fatal(err)
		}
		if scheduler.OrderMetadataSize() != 0 {
			t.Fatalf(
				"historical metadata after %d keys = %d",
				id,
				scheduler.OrderMetadataSize(),
			)
		}
	}
}

type sequenceJitter struct {
	values []time.Duration
	index  int
}

func (source *sequenceJitter) Next(upper time.Duration) time.Duration {
	value := source.values[source.index]
	source.index++
	if value > upper {
		return upper
	}
	return value
}

type blockingDelay struct {
	started chan time.Duration
}

type callbackJitter struct {
	callback func()
}

func (source callbackJitter) Next(time.Duration) time.Duration {
	source.callback()
	return 0
}

func (delay blockingDelay) Wait(
	ctx context.Context,
	duration time.Duration,
) error {
	delay.started <- duration
	<-ctx.Done()
	return ctx.Err()
}

func TestReconnectBackoffIsBoundedInjectedAndResetsOnlyOnValidResponse(t *testing.T) {
	jitter := &sequenceJitter{
		values: []time.Duration{10, 20, 30, 40},
	}
	backoff, err := newReconnectBackoff(BackoffConfig{
		Floor:             100 * time.Millisecond,
		Ceiling:           350 * time.Millisecond,
		MaxAttempts:       4,
		Jitter:            jitter,
		JitterAlgorithmID: "sequence",
		JitterVersion:     "v1",
		JitterEvidence:    "schedule:test-sequence",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := backoff.NextDelay(); err != nil ||
		got != 100*time.Millisecond+10 {
		t.Fatalf("first delay = %v", got)
	}
	backoff.Connected()
	if got, err := backoff.NextDelay(); err != nil ||
		got != 200*time.Millisecond+20 {
		t.Fatalf("connect reset backoff: %v", got)
	}
	if got, err := backoff.NextDelay(); err != nil ||
		got != 350*time.Millisecond {
		t.Fatalf("ceiling = %v", got)
	}
	backoff.ValidCorrelatedResponse()
	if got, err := backoff.NextDelay(); err != nil ||
		got != 100*time.Millisecond+40 {
		t.Fatalf("valid response did not reset backoff: %v", got)
	}
	if backoff.JitterAlgorithmID() != "sequence" ||
		backoff.JitterVersion() != "v1" ||
		backoff.JitterEvidence() != "schedule:test-sequence" {
		t.Fatal("traceable jitter identity was lost")
	}
	if len(backoff.EmittedJitter()) != 4 {
		t.Fatalf("emitted schedule = %#v", backoff.EmittedJitter())
	}
}

func TestReconnectBackoffWaitIsCancellationAware(t *testing.T) {
	backoff, err := newReconnectBackoff(BackoffConfig{
		Floor:             time.Second,
		Ceiling:           time.Second,
		MaxAttempts:       1,
		Jitter:            &sequenceJitter{values: []time.Duration{0}},
		JitterAlgorithmID: "zero",
		JitterVersion:     "v1",
		JitterEvidence:    "seed:0",
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	delay := blockingDelay{started: make(chan time.Duration, 1)}
	done := make(chan error, 1)
	go func() {
		done <- backoff.WaitUntil(ctx, delay, 0, 2*time.Second)
	}()
	if got := <-delay.started; got != time.Second {
		t.Fatalf("wait delay = %v", got)
	}
	cancel()
	if err := <-done; err != context.Canceled {
		t.Fatalf("wait error = %v", err)
	}
	if _, err := backoff.NextDelay(); err == nil {
		t.Fatal("backoff exceeded finite attempt limit")
	}
}

func TestReconnectBackoffDoesNotHoldStateLockAcrossJitter(t *testing.T) {
	var backoff *ReconnectBackoff
	source := callbackJitter{callback: func() {
		backoff.ValidCorrelatedResponse()
	}}
	var err error
	backoff, err = newReconnectBackoff(BackoffConfig{
		Floor:             time.Second,
		Ceiling:           2 * time.Second,
		MaxAttempts:       2,
		Jitter:            source,
		JitterAlgorithmID: "callback",
		JitterVersion:     "v1",
		JitterEvidence:    "schedule:zero",
	})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, nextErr := backoff.NextDelay()
		done <- nextErr
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("jitter callback deadlocked backoff state")
	}
}

func TestReconnectBackoffRefusesDelayPastAbsoluteDeadline(t *testing.T) {
	backoff, err := newReconnectBackoff(BackoffConfig{
		Floor:             time.Second,
		Ceiling:           time.Second,
		MaxAttempts:       1,
		Jitter:            &sequenceJitter{values: []time.Duration{0}},
		JitterAlgorithmID: "zero",
		JitterVersion:     "v1",
		JitterEvidence:    "seed:0",
	})
	if err != nil {
		t.Fatal(err)
	}
	delay := blockingDelay{started: make(chan time.Duration, 1)}
	err = backoff.WaitUntil(
		context.Background(),
		delay,
		500*time.Millisecond,
		time.Second,
	)
	_ = requireProtocolError(t, err, ErrorInvalidRange)
	select {
	case started := <-delay.started:
		t.Fatalf("waiter started past deadline with %v", started)
	default:
	}
}
