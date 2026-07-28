package modbus

import (
	"context"
	"math"
	"sync"
	"time"
)

// SchedulerLimits bounds endpoint admission and dependent state.
type SchedulerLimits struct {
	MaxActiveAdmissionKeys         int
	ProtectedSlotsPerKey           int
	SharedBurstSlots               int
	TotalQueued                    int
	MaxQueuedPerKey                int
	MaxQueuedPerAuthorizationScope int
	MaxCoalescedDependentsPerKey   int
	MaxRetryAttempts               int
	MaxInFlightRequests            int
}

// AdmissionKey isolates queue capacity by authorization scope and unit.
type AdmissionKey struct {
	AuthorizationScope string
	UnitID             byte
}

// ScheduledRequest is one scheduler-owned read request.
type ScheduledRequest struct {
	RequestID      uint64
	Key            AdmissionKey
	DeadlineOffset int64
}

type scheduledState byte

const (
	scheduledQueued scheduledState = iota + 1
	scheduledInFlight
)

type scheduledEntry struct {
	request         ScheduledRequest
	sequence        uint64
	state           scheduledState
	retries         int
	admissionWeight int
	coalesced       *CoalescedRead
}

type admissionState struct {
	queue      []*scheduledEntry
	queued     int
	inFlight   int
	dependents int
}

// EndpointScheduler owns bounded deterministic endpoint queue service.
type EndpointScheduler struct {
	mu           sync.Mutex
	limits       SchedulerLimits
	nextSequence uint64
	entries      map[uint64]*scheduledEntry
	coalesced    map[*CoalescedRead]uint64
	keys         map[AdmissionKey]*admissionState
	scopeOrder   []string
	unitOrder    map[string][]byte
	scopeCursor  int
	unitCursor   map[string]int
	inFlight     int
}

type endpointSchedulerResourceSnapshot struct {
	queuedRequests      int
	inFlightRequests    int
	activeAdmissionKeys int
	coalescedDependents int
}

func (scheduler *EndpointScheduler) resourceSnapshot() (
	snapshot endpointSchedulerResourceSnapshot,
) {
	if scheduler == nil {
		return snapshot
	}
	scheduler.mu.Lock()
	defer scheduler.mu.Unlock()
	snapshot.inFlightRequests = scheduler.inFlight
	snapshot.activeAdmissionKeys = len(scheduler.keys)
	for _, state := range scheduler.keys {
		snapshot.queuedRequests += len(state.queue)
		snapshot.coalescedDependents += state.dependents
	}
	return snapshot
}

// newEndpointScheduler validates limits with checked arithmetic.
func newEndpointScheduler(
	limits SchedulerLimits,
) (*EndpointScheduler, error) {
	if err := validateSchedulerLimits(limits); err != nil {
		return nil, err
	}
	return &EndpointScheduler{
		limits:     limits,
		entries:    make(map[uint64]*scheduledEntry),
		coalesced:  make(map[*CoalescedRead]uint64),
		keys:       make(map[AdmissionKey]*admissionState),
		unitOrder:  make(map[string][]byte),
		unitCursor: make(map[string]int),
	}, nil
}

func validateSchedulerLimits(limits SchedulerLimits) error {
	if limits.MaxActiveAdmissionKeys <= 0 ||
		limits.ProtectedSlotsPerKey <= 0 ||
		limits.SharedBurstSlots <= 0 ||
		limits.TotalQueued <= 0 ||
		limits.MaxQueuedPerKey <= 0 ||
		limits.MaxQueuedPerAuthorizationScope <= 0 ||
		limits.MaxCoalescedDependentsPerKey <= 0 ||
		limits.MaxRetryAttempts <= 0 ||
		limits.MaxInFlightRequests <= 0 {
		return invalidSchedulerLimits()
	}
	if limits.MaxActiveAdmissionKeys >
		math.MaxInt/limits.ProtectedSlotsPerKey {
		return invalidSchedulerLimits()
	}
	protected := limits.MaxActiveAdmissionKeys *
		limits.ProtectedSlotsPerKey
	if protected > math.MaxInt-limits.SharedBurstSlots {
		return invalidSchedulerLimits()
	}
	required := protected + limits.SharedBurstSlots
	if limits.TotalQueued < required ||
		limits.MaxQueuedPerKey < limits.ProtectedSlotsPerKey ||
		limits.MaxQueuedPerKey > limits.TotalQueued ||
		limits.MaxQueuedPerAuthorizationScope <
			protected ||
		limits.MaxQueuedPerAuthorizationScope > limits.TotalQueued ||
		limits.MaxCoalescedDependentsPerKey <
			limits.ProtectedSlotsPerKey ||
		limits.MaxCoalescedDependentsPerKey > maxCoalescedDependents ||
		limits.MaxCoalescedDependentsPerKey > limits.TotalQueued {
		return invalidSchedulerLimits()
	}
	return nil
}

func invalidSchedulerLimits() error {
	return protocolError(
		ErrorInvalidRequest,
		0,
		0,
		"scheduler_limits",
		-1,
	)
}

// Enqueue admits a new request without consuming future protected capacity.
func (scheduler *EndpointScheduler) Enqueue(request ScheduledRequest) error {
	if scheduler == nil || !validScheduledRequest(request) {
		return protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"scheduled_request",
			-1,
		)
	}
	scheduler.mu.Lock()
	defer scheduler.mu.Unlock()
	return scheduler.enqueueLocked(request, nil, 1)
}

func validScheduledRequest(request ScheduledRequest) bool {
	return request.RequestID != 0 &&
		request.Key.AuthorizationScope != "" &&
		request.Key.UnitID != 0 &&
		request.Key.UnitID <= 247 &&
		request.DeadlineOffset > 0
}

func (scheduler *EndpointScheduler) enqueueLocked(
	request ScheduledRequest,
	group *CoalescedRead,
	admissionWeight int,
) error {
	if _, exists := scheduler.entries[request.RequestID]; exists {
		return protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"request_id",
			-1,
		)
	}
	keyState, active := scheduler.keys[request.Key]
	if admissionWeight > 0 {
		if err := scheduler.checkAdmissionCount(
			request.Key,
			active,
			admissionWeight,
		); err != nil {
			return err
		}
	}
	if !active {
		keyState = &admissionState{}
		scheduler.keys[request.Key] = keyState
		scheduler.rememberOrder(request.Key)
	}
	scheduler.nextSequence++
	entry := &scheduledEntry{
		request:         request,
		sequence:        scheduler.nextSequence,
		state:           scheduledQueued,
		admissionWeight: admissionWeight,
		coalesced:       group,
	}
	keyState.queue = append(keyState.queue, entry)
	queued, ok := checkedAdmissionAdd(
		keyState.queued,
		admissionWeight,
	)
	if !ok {
		keyState.queue = keyState.queue[:len(keyState.queue)-1]
		scheduler.releaseIfEmpty(request.Key)
		return schedulerAdmissionError("admission_accounting")
	}
	keyState.queued = queued
	scheduler.entries[request.RequestID] = entry
	if group != nil {
		scheduler.coalesced[group] = request.RequestID
	}
	return nil
}

func (scheduler *EndpointScheduler) validateCoalescedRequest(
	request ScheduledRequest,
	intents []ReadIntent,
) error {
	if !validScheduledRequest(request) || len(intents) == 0 {
		return protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"scheduled_coalesced_request",
			-1,
		)
	}
	spec := intents[0].spec
	if request.Key.AuthorizationScope != spec.AuthorizationScope ||
		request.Key.UnitID != spec.UnitID {
		return protocolError(
			ErrorInvalidRequest,
			spec.Request.Function(),
			0,
			"scheduled_coalesced_identity",
			-1,
		)
	}
	return nil
}

// ScheduleCoalesced admits dependents and queues their physical union.
func (scheduler *EndpointScheduler) ScheduleCoalesced(
	request ScheduledRequest,
	intents []ReadIntent,
) (*CoalescedRead, error) {
	if scheduler == nil {
		return nil, protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"scheduler",
			-1,
		)
	}
	if err := scheduler.validateCoalescedRequest(request, intents); err != nil {
		return nil, err
	}
	group, err := coalesceReads(
		intents,
		scheduler.limits.MaxCoalescedDependentsPerKey,
	)
	if err != nil {
		return nil, err
	}
	scheduler.mu.Lock()
	defer scheduler.mu.Unlock()
	if err := scheduler.scheduleCoalescedLocked(
		request,
		intents,
		group,
	); err != nil {
		return nil, err
	}
	return group, nil
}

func (scheduler *EndpointScheduler) checkAdmissionCount(
	key AdmissionKey,
	active bool,
	count int,
) error {
	if count <= 0 {
		return schedulerAdmissionError("queued_capacity")
	}
	activeCount := len(scheduler.keys)
	if !active && activeCount >= scheduler.limits.MaxActiveAdmissionKeys {
		return schedulerAdmissionError("active_admission_keys")
	}
	keyState := scheduler.keys[key]
	keyQueued := 0
	if keyState != nil {
		var ok bool
		keyQueued, ok = checkedAdmissionAdd(
			keyState.queued,
			keyState.dependents,
		)
		if !ok {
			return schedulerAdmissionError("admission_accounting")
		}
	}
	keyRemaining, ok := checkedAdmissionRemaining(
		scheduler.limits.MaxQueuedPerKey,
		keyQueued,
	)
	if !ok {
		return schedulerAdmissionError("admission_accounting")
	}
	if count > keyRemaining {
		return schedulerAdmissionError("queued_per_key")
	}
	scopeQueued := 0
	totalQueued := 0
	for activeKey, state := range scheduler.keys {
		occupied, ok := checkedAdmissionAdd(
			state.queued,
			state.dependents,
		)
		if !ok {
			return schedulerAdmissionError("admission_accounting")
		}
		totalQueued, ok = checkedAdmissionAdd(totalQueued, occupied)
		if !ok {
			return schedulerAdmissionError("admission_accounting")
		}
		if activeKey.AuthorizationScope == key.AuthorizationScope {
			scopeQueued, ok = checkedAdmissionAdd(
				scopeQueued,
				occupied,
			)
			if !ok {
				return schedulerAdmissionError("admission_accounting")
			}
		}
	}
	totalRemaining, totalOK := checkedAdmissionRemaining(
		scheduler.limits.TotalQueued,
		totalQueued,
	)
	scopeRemaining, scopeOK := checkedAdmissionRemaining(
		scheduler.limits.MaxQueuedPerAuthorizationScope,
		scopeQueued,
	)
	if !totalOK || !scopeOK {
		return schedulerAdmissionError("admission_accounting")
	}
	if count > totalRemaining || count > scopeRemaining {
		return schedulerAdmissionError("queued_capacity")
	}
	resultingActive := activeCount
	if !active {
		resultingActive++
	}
	if resultingActive > scheduler.limits.MaxActiveAdmissionKeys {
		return schedulerAdmissionError("active_admission_keys")
	}
	inactivePositions := scheduler.limits.MaxActiveAdmissionKeys -
		resultingActive
	reservedCapacity := inactivePositions *
		scheduler.limits.ProtectedSlotsPerKey
	for activeKey, state := range scheduler.keys {
		if activeKey == key {
			continue
		}
		occupied, ok := checkedAdmissionAdd(
			state.queued,
			state.dependents,
		)
		if !ok {
			return schedulerAdmissionError("admission_accounting")
		}
		if occupied < scheduler.limits.ProtectedSlotsPerKey {
			deficit := scheduler.limits.ProtectedSlotsPerKey -
				occupied
			reservedCapacity, ok = checkedAdmissionAdd(
				reservedCapacity,
				deficit,
			)
			if !ok {
				return schedulerAdmissionError("admission_accounting")
			}
		}
	}
	usableNow, ok := checkedAdmissionRemaining(
		scheduler.limits.TotalQueued,
		reservedCapacity,
	)
	if !ok {
		return schedulerAdmissionError("admission_accounting")
	}
	usableRemaining, ok := checkedAdmissionRemaining(
		usableNow,
		totalQueued,
	)
	if !ok {
		return schedulerAdmissionError("protected_capacity")
	}
	if count > usableRemaining {
		return schedulerAdmissionError("protected_capacity")
	}
	return nil
}

func checkedAdmissionAdd(first, second int) (int, bool) {
	if first < 0 || second < 0 || first > math.MaxInt-second {
		return 0, false
	}
	return first + second, true
}

func checkedAdmissionRemaining(limit, used int) (int, bool) {
	if limit < 0 || used < 0 || used > limit {
		return 0, false
	}
	return limit - used, true
}

func schedulerAdmissionError(field string) error {
	return protocolError(
		ErrorInvalidRange,
		0,
		0,
		field,
		-1,
	)
}

func (scheduler *EndpointScheduler) scheduleCoalescedLocked(
	request ScheduledRequest,
	intents []ReadIntent,
	group *CoalescedRead,
) error {
	if _, exists := scheduler.entries[request.RequestID]; exists {
		return protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"request_id",
			-1,
		)
	}
	state := scheduler.keys[request.Key]
	active := state != nil
	if err := scheduler.checkAdmissionCount(
		request.Key,
		active,
		len(intents),
	); err != nil {
		return err
	}
	if state == nil {
		state = &admissionState{}
		scheduler.keys[request.Key] = state
		scheduler.rememberOrder(request.Key)
	}
	dependentRemaining, ok := checkedAdmissionRemaining(
		scheduler.limits.MaxCoalescedDependentsPerKey,
		state.dependents,
	)
	if !ok {
		scheduler.releaseIfEmpty(request.Key)
		return schedulerAdmissionError("admission_accounting")
	}
	if len(intents) > dependentRemaining {
		scheduler.releaseIfEmpty(request.Key)
		return schedulerAdmissionError("coalesced_dependents")
	}
	previousDependents := state.dependents
	dependents, ok := checkedAdmissionAdd(
		previousDependents,
		len(intents),
	)
	if !ok {
		scheduler.releaseIfEmpty(request.Key)
		return schedulerAdmissionError("admission_accounting")
	}
	state.dependents = dependents
	group.scheduler = scheduler
	group.admissionKey = request.Key
	if err := scheduler.enqueueLocked(request, group, 0); err != nil {
		state.dependents = previousDependents
		scheduler.releaseIfEmpty(request.Key)
		group.scheduler = nil
		group.admissionKey = AdmissionKey{}
		return err
	}
	return nil
}

// CoalescedGroup resolves one live scheduler token to its physical group.
func (scheduler *EndpointScheduler) CoalescedGroup(
	requestID uint64,
) (*CoalescedRead, bool) {
	if scheduler == nil || requestID == 0 {
		return nil, false
	}
	scheduler.mu.Lock()
	defer scheduler.mu.Unlock()
	entry := scheduler.entries[requestID]
	if entry == nil || entry.coalesced == nil {
		return nil, false
	}
	return entry.coalesced, true
}

// RequireCoalescedDispatch rejects a physical write before scheduler service.
func (scheduler *EndpointScheduler) RequireCoalescedDispatch(
	group *CoalescedRead,
) error {
	if scheduler == nil || group == nil {
		return protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"coalesced_dispatch",
			-1,
		)
	}
	scheduler.mu.Lock()
	defer scheduler.mu.Unlock()
	requestID, ok := scheduler.coalesced[group]
	if !ok {
		return protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"coalesced_dispatch",
			-1,
		)
	}
	entry := scheduler.entries[requestID]
	if entry == nil || entry.state != scheduledInFlight {
		return protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"coalesced_dispatch_state",
			-1,
		)
	}
	return nil
}

func (scheduler *EndpointScheduler) releaseCoalescedDependents(
	key AdmissionKey,
	count int,
) {
	scheduler.mu.Lock()
	defer scheduler.mu.Unlock()
	state := scheduler.keys[key]
	if state == nil || count <= 0 || count > state.dependents {
		return
	}
	dependents, ok := checkedAdmissionRemaining(
		state.dependents,
		count,
	)
	if !ok {
		return
	}
	state.dependents = dependents
	scheduler.releaseIfEmpty(key)
}

func (scheduler *EndpointScheduler) rememberOrder(key AdmissionKey) {
	scopeKnown := false
	for _, scope := range scheduler.scopeOrder {
		if scope == key.AuthorizationScope {
			scopeKnown = true
			break
		}
	}
	if !scopeKnown {
		scheduler.scopeOrder = append(
			scheduler.scopeOrder,
			key.AuthorizationScope,
		)
	}
	for _, unitID := range scheduler.unitOrder[key.AuthorizationScope] {
		if unitID == key.UnitID {
			return
		}
	}
	scheduler.unitOrder[key.AuthorizationScope] = append(
		scheduler.unitOrder[key.AuthorizationScope],
		key.UnitID,
	)
}

// Dispatch expires stale work and returns the next deterministic fair request.
func (scheduler *EndpointScheduler) Dispatch(
	nowOffset int64,
) (ScheduledRequest, bool) {
	if scheduler == nil {
		return ScheduledRequest{}, false
	}
	scheduler.mu.Lock()
	expired, accountingOK := scheduler.expireLocked(nowOffset)
	if !accountingOK {
		scheduler.mu.Unlock()
		failExpiredCoalesced(expired)
		return ScheduledRequest{}, false
	}
	if scheduler.inFlight >= scheduler.limits.MaxInFlightRequests {
		scheduler.mu.Unlock()
		failExpiredCoalesced(expired)
		return ScheduledRequest{}, false
	}
	scope, ok := scheduler.nextScope()
	if !ok {
		scheduler.mu.Unlock()
		failExpiredCoalesced(expired)
		return ScheduledRequest{}, false
	}
	key, ok := scheduler.nextUnit(scope)
	if !ok {
		scheduler.mu.Unlock()
		failExpiredCoalesced(expired)
		return ScheduledRequest{}, false
	}
	state := scheduler.keys[key]
	entry := state.queue[0]
	queued, queuedOK := checkedAdmissionRemaining(
		state.queued,
		entry.admissionWeight,
	)
	keyInFlight, keyOK := checkedAdmissionAdd(state.inFlight, 1)
	inFlight, inFlightOK := checkedAdmissionAdd(scheduler.inFlight, 1)
	if !queuedOK || !keyOK || !inFlightOK ||
		inFlight > scheduler.limits.MaxInFlightRequests {
		scheduler.mu.Unlock()
		failExpiredCoalesced(expired)
		return ScheduledRequest{}, false
	}
	state.queue = state.queue[1:]
	state.queued = queued
	state.inFlight = keyInFlight
	scheduler.inFlight = inFlight
	entry.state = scheduledInFlight
	request := entry.request
	scheduler.mu.Unlock()
	failExpiredCoalesced(expired)
	return request, true
}

func (scheduler *EndpointScheduler) expireLocked(
	nowOffset int64,
) ([]*CoalescedRead, bool) {
	var expired []*CoalescedRead
	accountingOK := true
	for key, state := range scheduler.keys {
		kept := state.queue[:0]
		for _, entry := range state.queue {
			if entry.request.DeadlineOffset <= nowOffset {
				queued, ok := checkedAdmissionRemaining(
					state.queued,
					entry.admissionWeight,
				)
				if !ok {
					accountingOK = false
					kept = append(kept, entry)
					continue
				}
				state.queued = queued
				scheduler.forgetEntryLocked(entry)
				if entry.coalesced != nil {
					expired = append(expired, entry.coalesced)
				}
				continue
			}
			kept = append(kept, entry)
		}
		state.queue = kept
		scheduler.releaseIfEmpty(key)
	}
	return expired, accountingOK
}

func failExpiredCoalesced(groups []*CoalescedRead) {
	for _, group := range groups {
		_ = group.FailTransport()
	}
}

func (scheduler *EndpointScheduler) nextScope() (string, bool) {
	if len(scheduler.scopeOrder) == 0 {
		return "", false
	}
	for checked := 0; checked < len(scheduler.scopeOrder); checked++ {
		index := (scheduler.scopeCursor + checked) %
			len(scheduler.scopeOrder)
		scope := scheduler.scopeOrder[index]
		if scheduler.scopeHasQueued(scope) {
			scheduler.scopeCursor = (index + 1) %
				len(scheduler.scopeOrder)
			return scope, true
		}
	}
	return "", false
}

func (scheduler *EndpointScheduler) scopeHasQueued(scope string) bool {
	for _, unitID := range scheduler.unitOrder[scope] {
		key := AdmissionKey{
			AuthorizationScope: scope,
			UnitID:             unitID,
		}
		if state := scheduler.keys[key]; state != nil &&
			len(state.queue) > 0 {
			return true
		}
	}
	return false
}

func (scheduler *EndpointScheduler) nextUnit(
	scope string,
) (AdmissionKey, bool) {
	units := scheduler.unitOrder[scope]
	if len(units) == 0 {
		return AdmissionKey{}, false
	}
	cursor := scheduler.unitCursor[scope]
	for checked := 0; checked < len(units); checked++ {
		index := (cursor + checked) % len(units)
		key := AdmissionKey{
			AuthorizationScope: scope,
			UnitID:             units[index],
		}
		if state := scheduler.keys[key]; state != nil &&
			len(state.queue) > 0 {
			scheduler.unitCursor[scope] = (index + 1) % len(units)
			return key, true
		}
	}
	return AdmissionKey{}, false
}

// CancelQueued removes one request only if transport has not begun.
func (scheduler *EndpointScheduler) CancelQueued(requestID uint64) bool {
	if scheduler == nil {
		return false
	}
	scheduler.mu.Lock()
	entry, ok := scheduler.entries[requestID]
	if !ok || entry.state != scheduledQueued {
		scheduler.mu.Unlock()
		return false
	}
	state := scheduler.keys[entry.request.Key]
	for index, queued := range state.queue {
		if queued != entry {
			continue
		}
		remaining, ok := checkedAdmissionRemaining(
			state.queued,
			entry.admissionWeight,
		)
		if !ok {
			scheduler.mu.Unlock()
			return false
		}
		copy(state.queue[index:], state.queue[index+1:])
		state.queue = state.queue[:len(state.queue)-1]
		state.queued = remaining
		scheduler.forgetEntryLocked(entry)
		scheduler.releaseIfEmpty(entry.request.Key)
		group := entry.coalesced
		scheduler.mu.Unlock()
		if group != nil {
			_ = group.FailTransport()
		}
		return true
	}
	scheduler.mu.Unlock()
	return false
}

// Retry re-enters one in-flight request at the tail under current bounds.
func (scheduler *EndpointScheduler) Retry(requestID uint64) error {
	if scheduler == nil {
		return protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"scheduler",
			-1,
		)
	}
	scheduler.mu.Lock()
	entry, ok := scheduler.entries[requestID]
	if !ok || entry.state != scheduledInFlight {
		scheduler.mu.Unlock()
		return protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"request_state",
			-1,
		)
	}
	if entry.retries >= scheduler.limits.MaxRetryAttempts {
		state := scheduler.keys[entry.request.Key]
		if !scheduler.releaseInFlightLocked(state) {
			scheduler.mu.Unlock()
			return schedulerAdmissionError("admission_accounting")
		}
		scheduler.forgetEntryLocked(entry)
		scheduler.releaseIfEmpty(entry.request.Key)
		group := entry.coalesced
		scheduler.mu.Unlock()
		if group != nil {
			_ = group.FailTransport()
		}
		return schedulerAdmissionError("retry_attempts")
	}
	if entry.admissionWeight > 0 {
		if err := scheduler.checkAdmissionCount(
			entry.request.Key,
			true,
			entry.admissionWeight,
		); err != nil {
			state := scheduler.keys[entry.request.Key]
			if !scheduler.releaseInFlightLocked(state) {
				scheduler.mu.Unlock()
				return schedulerAdmissionError("admission_accounting")
			}
			scheduler.forgetEntryLocked(entry)
			scheduler.releaseIfEmpty(entry.request.Key)
			group := entry.coalesced
			scheduler.mu.Unlock()
			if group != nil {
				_ = group.FailTransport()
			}
			return err
		}
	}
	state := scheduler.keys[entry.request.Key]
	if !scheduler.releaseInFlightLocked(state) {
		scheduler.mu.Unlock()
		return schedulerAdmissionError("admission_accounting")
	}
	entry.retries++
	scheduler.nextSequence++
	entry.sequence = scheduler.nextSequence
	entry.state = scheduledQueued
	state.queue = append(state.queue, entry)
	queued, ok := checkedAdmissionAdd(
		state.queued,
		entry.admissionWeight,
	)
	if !ok {
		state.queue = state.queue[:len(state.queue)-1]
		scheduler.forgetEntryLocked(entry)
		scheduler.releaseIfEmpty(entry.request.Key)
		group := entry.coalesced
		scheduler.mu.Unlock()
		if group != nil {
			_ = group.FailTransport()
		}
		return schedulerAdmissionError("admission_accounting")
	}
	state.queued = queued
	scheduler.mu.Unlock()
	return nil
}

// RetryCoalesced requeues one dispatched physical union through normal policy.
func (scheduler *EndpointScheduler) RetryCoalesced(
	group *CoalescedRead,
) error {
	requestID, ok := scheduler.coalescedRequestID(group)
	if !ok {
		return protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"coalesced_dispatch",
			-1,
		)
	}
	return scheduler.Retry(requestID)
}

func (scheduler *EndpointScheduler) coalescedRequestID(
	group *CoalescedRead,
) (uint64, bool) {
	if scheduler == nil || group == nil {
		return 0, false
	}
	scheduler.mu.Lock()
	defer scheduler.mu.Unlock()
	requestID, ok := scheduler.coalesced[group]
	return requestID, ok
}

// Complete releases one in-flight request and possibly its admission key.
func (scheduler *EndpointScheduler) Complete(requestID uint64) error {
	if scheduler == nil {
		return protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"scheduler",
			-1,
		)
	}
	scheduler.mu.Lock()
	defer scheduler.mu.Unlock()
	entry, ok := scheduler.entries[requestID]
	if !ok || entry.state != scheduledInFlight {
		return protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"request_state",
			-1,
		)
	}
	state := scheduler.keys[entry.request.Key]
	if !scheduler.releaseInFlightLocked(state) {
		return schedulerAdmissionError("admission_accounting")
	}
	scheduler.forgetEntryLocked(entry)
	scheduler.releaseIfEmpty(entry.request.Key)
	return nil
}

// CompleteCoalesced releases a dispatched physical union by group identity.
func (scheduler *EndpointScheduler) CompleteCoalesced(
	group *CoalescedRead,
) error {
	requestID, ok := scheduler.coalescedRequestID(group)
	if !ok {
		return protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"coalesced_dispatch",
			-1,
		)
	}
	return scheduler.Complete(requestID)
}

// FinishCoalesced releases a terminal physical union from either live state.
//
// The group lifecycle calls this after its dependents reach terminal states.
// It is idempotent because expiry removes the token before failing the group.
func (scheduler *EndpointScheduler) FinishCoalesced(
	group *CoalescedRead,
) error {
	if scheduler == nil || group == nil {
		return protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"coalesced_dispatch",
			-1,
		)
	}
	scheduler.mu.Lock()
	requestID, ok := scheduler.coalesced[group]
	if !ok {
		scheduler.mu.Unlock()
		return nil
	}
	entry := scheduler.entries[requestID]
	if entry == nil {
		delete(scheduler.coalesced, group)
		scheduler.mu.Unlock()
		return nil
	}
	state := scheduler.keys[entry.request.Key]
	switch entry.state {
	case scheduledQueued:
		for index, queued := range state.queue {
			if queued != entry {
				continue
			}
			remaining, ok := checkedAdmissionRemaining(
				state.queued,
				entry.admissionWeight,
			)
			if !ok {
				scheduler.mu.Unlock()
				return schedulerAdmissionError("admission_accounting")
			}
			copy(state.queue[index:], state.queue[index+1:])
			state.queue = state.queue[:len(state.queue)-1]
			state.queued = remaining
			break
		}
	case scheduledInFlight:
		if !scheduler.releaseInFlightLocked(state) {
			scheduler.mu.Unlock()
			return schedulerAdmissionError("admission_accounting")
		}
	default:
		scheduler.mu.Unlock()
		return protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"coalesced_dispatch_state",
			-1,
		)
	}
	scheduler.forgetEntryLocked(entry)
	scheduler.releaseIfEmpty(entry.request.Key)
	scheduler.mu.Unlock()
	return nil
}

// CancelCoalesced removes a physical union only while it remains queued.
func (scheduler *EndpointScheduler) CancelCoalesced(
	group *CoalescedRead,
) bool {
	requestID, ok := scheduler.coalescedRequestID(group)
	if !ok {
		return false
	}
	return scheduler.CancelQueued(requestID)
}

func (scheduler *EndpointScheduler) forgetEntryLocked(
	entry *scheduledEntry,
) {
	delete(scheduler.entries, entry.request.RequestID)
	if entry.coalesced != nil {
		delete(scheduler.coalesced, entry.coalesced)
	}
}

func (scheduler *EndpointScheduler) releaseInFlightLocked(
	state *admissionState,
) bool {
	if state == nil {
		return false
	}
	keyInFlight, keyOK := checkedAdmissionRemaining(state.inFlight, 1)
	inFlight, inFlightOK := checkedAdmissionRemaining(
		scheduler.inFlight,
		1,
	)
	if !keyOK || !inFlightOK {
		return false
	}
	state.inFlight = keyInFlight
	scheduler.inFlight = inFlight
	return true
}

func (scheduler *EndpointScheduler) attachDependent(
	key AdmissionKey,
) error {
	if scheduler == nil {
		return protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"scheduler",
			-1,
		)
	}
	scheduler.mu.Lock()
	defer scheduler.mu.Unlock()
	state := scheduler.keys[key]
	if state == nil {
		return protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"admission_key",
			-1,
		)
	}
	dependents, ok := checkedAdmissionAdd(state.dependents, 1)
	if !ok ||
		dependents > scheduler.limits.MaxCoalescedDependentsPerKey {
		return schedulerAdmissionError("coalesced_dependents")
	}
	state.dependents = dependents
	return nil
}

func (scheduler *EndpointScheduler) detachDependent(
	key AdmissionKey,
) error {
	if scheduler == nil {
		return protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"scheduler",
			-1,
		)
	}
	scheduler.mu.Lock()
	defer scheduler.mu.Unlock()
	state := scheduler.keys[key]
	if state == nil || state.dependents <= 0 {
		return protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"coalesced_dependents",
			-1,
		)
	}
	dependents, ok := checkedAdmissionRemaining(state.dependents, 1)
	if !ok {
		return schedulerAdmissionError("admission_accounting")
	}
	state.dependents = dependents
	scheduler.releaseIfEmpty(key)
	return nil
}

func (scheduler *EndpointScheduler) releaseIfEmpty(key AdmissionKey) {
	state := scheduler.keys[key]
	if state != nil &&
		len(state.queue) == 0 &&
		state.inFlight == 0 &&
		state.dependents == 0 {
		delete(scheduler.keys, key)
		scheduler.forgetOrder(key)
	}
}

func (scheduler *EndpointScheduler) forgetOrder(key AdmissionKey) {
	units := scheduler.unitOrder[key.AuthorizationScope]
	unitIndex := -1
	for index, unitID := range units {
		if unitID == key.UnitID {
			unitIndex = index
			break
		}
	}
	if unitIndex < 0 {
		return
	}
	units = append(units[:unitIndex], units[unitIndex+1:]...)
	if len(units) > 0 {
		scheduler.unitOrder[key.AuthorizationScope] = units
		scheduler.unitCursor[key.AuthorizationScope] = cursorAfterRemoval(
			scheduler.unitCursor[key.AuthorizationScope],
			unitIndex,
			len(units)+1,
		)
		return
	}
	delete(scheduler.unitOrder, key.AuthorizationScope)
	delete(scheduler.unitCursor, key.AuthorizationScope)
	scopeIndex := -1
	for index, scope := range scheduler.scopeOrder {
		if scope == key.AuthorizationScope {
			scopeIndex = index
			break
		}
	}
	if scopeIndex < 0 {
		return
	}
	oldLength := len(scheduler.scopeOrder)
	scheduler.scopeOrder = append(
		scheduler.scopeOrder[:scopeIndex],
		scheduler.scopeOrder[scopeIndex+1:]...,
	)
	scheduler.scopeCursor = cursorAfterRemoval(
		scheduler.scopeCursor,
		scopeIndex,
		oldLength,
	)
}

func cursorAfterRemoval(cursor, removedIndex, oldLength int) int {
	if oldLength <= 1 {
		return 0
	}
	if cursor > removedIndex {
		cursor--
	}
	newLength := oldLength - 1
	if cursor >= newLength {
		return 0
	}
	return cursor
}

// OrderMetadataSize reports bounded live scope and unit ordering entries.
func (scheduler *EndpointScheduler) OrderMetadataSize() int {
	if scheduler == nil {
		return 0
	}
	scheduler.mu.Lock()
	defer scheduler.mu.Unlock()
	size := len(scheduler.scopeOrder)
	for _, units := range scheduler.unitOrder {
		size += len(units)
	}
	return size
}

// JitterSource provides replayable bounded jitter.
type JitterSource interface {
	Next(upper time.Duration) time.Duration
}

// BackoffConfig declares bounded reconnect timing and trace identity.
type BackoffConfig struct {
	Floor             time.Duration
	Ceiling           time.Duration
	MaxAttempts       int
	Jitter            JitterSource
	JitterAlgorithmID string
	JitterVersion     string
	JitterEvidence    string
}

// DelayWaiter is an injected cancellation-aware timer.
type DelayWaiter interface {
	Wait(context.Context, time.Duration) error
}

// ReconnectBackoff owns bounded retry progression for one endpoint.
type ReconnectBackoff struct {
	mu      sync.Mutex
	nextMu  sync.Mutex
	config  BackoffConfig
	attempt uint
	emitted []time.Duration
}

// newReconnectBackoff validates one replayable backoff configuration.
func newReconnectBackoff(
	config BackoffConfig,
) (*ReconnectBackoff, error) {
	if config.Floor <= 0 ||
		config.Ceiling <= 0 ||
		config.Floor > config.Ceiling ||
		config.MaxAttempts <= 0 ||
		config.Jitter == nil ||
		config.JitterAlgorithmID == "" ||
		config.JitterVersion == "" ||
		config.JitterEvidence == "" {
		return nil, protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"backoff_config",
			-1,
		)
	}
	return &ReconnectBackoff{config: config}, nil
}

// NextDelay returns and advances one bounded deterministic retry delay.
func (backoff *ReconnectBackoff) NextDelay() (time.Duration, error) {
	return backoff.nextDelayBefore(0)
}

func (backoff *ReconnectBackoff) nextDelayBefore(
	remaining time.Duration,
) (time.Duration, error) {
	if backoff == nil {
		return 0, protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"backoff",
			-1,
		)
	}
	backoff.nextMu.Lock()
	defer backoff.nextMu.Unlock()
	backoff.mu.Lock()
	if backoff.attempt >= uint(backoff.config.MaxAttempts) {
		backoff.mu.Unlock()
		return 0, protocolError(
			ErrorInvalidRange,
			0,
			0,
			"backoff_attempts",
			-1,
		)
	}
	attempt := backoff.attempt
	base := backoff.config.Floor
	for step := uint(0); step < attempt; step++ {
		if base >= backoff.config.Ceiling/2 {
			base = backoff.config.Ceiling
			break
		}
		base *= 2
	}
	if base > backoff.config.Ceiling {
		base = backoff.config.Ceiling
	}
	if remaining > 0 && base >= remaining {
		backoff.mu.Unlock()
		return 0, protocolError(
			ErrorInvalidRange,
			0,
			0,
			"operation_deadline",
			-1,
		)
	}
	jitterUpper := backoff.config.Ceiling - base
	jitterSource := backoff.config.Jitter
	backoff.mu.Unlock()
	jitter := jitterSource.Next(jitterUpper)
	if jitter < 0 {
		jitter = 0
	}
	if jitter > jitterUpper {
		jitter = jitterUpper
	}
	delay := base + jitter
	if remaining > 0 && delay >= remaining {
		return 0, protocolError(
			ErrorInvalidRange,
			0,
			0,
			"operation_deadline",
			-1,
		)
	}
	backoff.mu.Lock()
	defer backoff.mu.Unlock()
	if backoff.attempt != attempt {
		return 0, protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"backoff_attempt",
			-1,
		)
	}
	backoff.attempt++
	if len(backoff.emitted) == backoff.config.MaxAttempts {
		copy(backoff.emitted, backoff.emitted[1:])
		backoff.emitted = backoff.emitted[:len(backoff.emitted)-1]
	}
	backoff.emitted = append(backoff.emitted, jitter)
	return delay, nil
}

// Connected deliberately does not reset retry progression.
func (backoff *ReconnectBackoff) Connected() {}

// ValidCorrelatedResponse resets progression after proven protocol success.
func (backoff *ReconnectBackoff) ValidCorrelatedResponse() {
	if backoff == nil {
		return
	}
	backoff.mu.Lock()
	backoff.attempt = 0
	backoff.mu.Unlock()
}

// WaitUntil enforces one absolute monotonic deadline across backoff.
func (backoff *ReconnectBackoff) WaitUntil(
	ctx context.Context,
	waiter DelayWaiter,
	nowOffset time.Duration,
	deadlineOffset time.Duration,
) error {
	if backoff == nil ||
		ctx == nil ||
		waiter == nil ||
		nowOffset < 0 ||
		deadlineOffset <= nowOffset {
		return protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"backoff_wait",
			-1,
		)
	}
	delay, err := backoff.NextDelay()
	if err != nil {
		return err
	}
	if delay > deadlineOffset-nowOffset {
		return protocolError(
			ErrorInvalidRange,
			0,
			0,
			"operation_deadline",
			-1,
		)
	}
	return waiter.Wait(ctx, delay)
}

// JitterAlgorithmID returns the recorded jitter algorithm identity.
func (backoff *ReconnectBackoff) JitterAlgorithmID() string {
	if backoff == nil {
		return ""
	}
	return backoff.config.JitterAlgorithmID
}

// JitterVersion returns the recorded jitter algorithm version.
func (backoff *ReconnectBackoff) JitterVersion() string {
	if backoff == nil {
		return ""
	}
	return backoff.config.JitterVersion
}

// JitterEvidence returns the configured replay seed or schedule identity.
func (backoff *ReconnectBackoff) JitterEvidence() string {
	if backoff == nil {
		return ""
	}
	return backoff.config.JitterEvidence
}

// EmittedJitter returns the bounded recent emitted jitter schedule.
func (backoff *ReconnectBackoff) EmittedJitter() []time.Duration {
	if backoff == nil {
		return nil
	}
	backoff.mu.Lock()
	defer backoff.mu.Unlock()
	return append([]time.Duration(nil), backoff.emitted...)
}
