package modbus

import (
	"errors"
	"sync"
	"time"
)

const maxCoalescedDependents = 4096

// TransportFamily distinguishes transport-generation identity.
type TransportFamily string

const (
	// TransportTCP identifies a Modbus TCP transport generation.
	TransportTCP TransportFamily = "tcp"
	// TransportRTU identifies a Modbus RTU transport generation.
	TransportRTU TransportFamily = "rtu"
)

// ReadIntentSpec contains every V1 read-coalescing identity field.
type ReadIntentSpec struct {
	LogicalViewID       uint64
	Endpoint            string
	Transport           TransportFamily
	TransportGeneration uint64
	UnitID              byte
	AuthorizationScope  string
	PollGeneration      uint64
	DeadlineIdentity    uint64
	Request             ReadRegistersRequest
}

// ReadIntent is an immutable validated logical read candidate.
type ReadIntent struct {
	spec ReadIntentSpec
}

// NewReadIntent validates one complete coalescing identity.
func NewReadIntent(spec ReadIntentSpec) (ReadIntent, error) {
	if spec.LogicalViewID == 0 ||
		spec.Endpoint == "" ||
		(spec.Transport != TransportTCP && spec.Transport != TransportRTU) ||
		spec.TransportGeneration == 0 ||
		spec.UnitID == 0 ||
		spec.UnitID > 247 ||
		spec.AuthorizationScope == "" ||
		spec.PollGeneration == 0 ||
		spec.DeadlineIdentity == 0 {
		return ReadIntent{}, protocolError(
			ErrorInvalidRequest,
			spec.Request.Function(),
			0,
			"read_intent",
			-1,
		)
	}
	if err := validateReadRegistersRequest(spec.Request); err != nil {
		return ReadIntent{}, err
	}
	return ReadIntent{spec: spec}, nil
}

// Spec returns an independent value copy of the immutable intent.
func (intent ReadIntent) Spec() ReadIntentSpec {
	return intent.spec
}

type dependentState byte

const (
	dependentQueued dependentState = iota + 1
	dependentAttached
	dependentCancelled
	dependentDelivered
	dependentFailed
)

// DependentTerminalState exposes exact dependent lifecycle state.
type DependentTerminalState string

const (
	DependentQueued    DependentTerminalState = "queued"
	DependentAttached  DependentTerminalState = "attached"
	DependentCancelled DependentTerminalState = "cancelled"
	DependentDelivered DependentTerminalState = "delivered"
	DependentFailed    DependentTerminalState = "failed"
)

// CoalescedSlice identifies one exact logical slice in a physical response.
type CoalescedSlice struct {
	logicalViewID  uint64
	logicalOffset  uint16
	logicalWords   uint16
	sliceOffset    uint16
	sliceWordCount uint16
}

// LogicalViewID returns the owner-assigned dependent identity.
func (slice CoalescedSlice) LogicalViewID() uint64 {
	return slice.logicalViewID
}

// SliceOffset returns the dependent start relative to the physical response.
func (slice CoalescedSlice) SliceOffset() uint16 {
	return slice.sliceOffset
}

// SliceWordCount returns the exact dependent word count.
func (slice CoalescedSlice) SliceWordCount() uint16 {
	return slice.sliceWordCount
}

type coalescedDependent struct {
	slice CoalescedSlice
	state dependentState
}

// CoalescedRead is one physical request plus its bounded logical dependents.
type CoalescedRead struct {
	mu                 sync.Mutex
	physical           ReadRegistersRequest
	dependents         []coalescedDependent
	endpoint           string
	transport          TransportFamily
	intentGeneration   uint64
	unitID             byte
	authorizationScope string
	pollGeneration     uint64
	deadlineIdentity   uint64
	operationDeadline  time.Duration
	owner              *TCPConnectionOwner
	reservation        TCPReservation
	physicalRequestID  uint64
	generation         uint64
	writeBegun         bool
	completed          bool
	scheduler          *EndpointScheduler
	admissionKey       AdmissionKey
	tcpTransport       *TCPTransport
}

func (group *CoalescedRead) setOperationDeadline(
	deadline time.Duration,
) {
	if group == nil {
		return
	}
	group.mu.Lock()
	if !group.writeBegun && !group.completed {
		group.operationDeadline = deadline
	}
	group.mu.Unlock()
}

func coalesceReads(
	intents []ReadIntent,
	maxDependents int,
) (*CoalescedRead, error) {
	if maxDependents <= 0 || maxDependents > maxCoalescedDependents {
		return nil, protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"max_coalesced_dependents",
			-1,
		)
	}
	if len(intents) == 0 || len(intents) > maxDependents {
		kind := ErrorInvalidRequest
		if len(intents) > maxDependents {
			kind = ErrorInvalidRange
		}
		return nil, protocolError(
			kind,
			0,
			0,
			"read_intents",
			-1,
		)
	}
	base := intents[0].spec
	if _, err := NewReadIntent(base); err != nil {
		return nil, err
	}
	minOffset := uint32(base.Request.Offset())
	maxEnd := minOffset + uint32(base.Request.Quantity())
	maxStart := minOffset
	minEnd := maxEnd
	seenIDs := make(map[uint64]struct{}, len(intents))
	for _, intent := range intents {
		spec := intent.spec
		if _, err := NewReadIntent(spec); err != nil {
			return nil, err
		}
		if _, exists := seenIDs[spec.LogicalViewID]; exists {
			return nil, protocolError(
				ErrorInvalidRequest,
				spec.Request.Function(),
				0,
				"logical_view_id",
				-1,
			)
		}
		seenIDs[spec.LogicalViewID] = struct{}{}
		if !sameCoalescingIdentity(base, spec) {
			return nil, protocolError(
				ErrorInvalidRequest,
				spec.Request.Function(),
				0,
				"coalescing_identity",
				-1,
			)
		}
		start := uint32(spec.Request.Offset())
		end := start + uint32(spec.Request.Quantity())
		if start < minOffset {
			minOffset = start
		}
		if end > maxEnd {
			maxEnd = end
		}
		if start > maxStart {
			maxStart = start
		}
		if end < minEnd {
			minEnd = end
		}
	}
	if len(intents) > 1 && maxStart >= minEnd {
		return nil, protocolError(
			ErrorInvalidRange,
			base.Request.Function(),
			0,
			"non_overlapping_ranges",
			-1,
		)
	}
	union := maxEnd - minOffset
	if union == 0 || union > MaxReadRegisters {
		return nil, protocolError(
			ErrorInvalidRange,
			base.Request.Function(),
			0,
			"physical_union",
			-1,
		)
	}
	physical, err := NewReadRegistersRequest(
		base.Request.Function(),
		uint16(minOffset),
		uint16(union),
	)
	if err != nil {
		return nil, err
	}
	dependents := make([]coalescedDependent, len(intents))
	for index, intent := range intents {
		spec := intent.spec
		dependents[index] = coalescedDependent{
			slice: CoalescedSlice{
				logicalViewID:  spec.LogicalViewID,
				logicalOffset:  spec.Request.Offset(),
				logicalWords:   spec.Request.Quantity(),
				sliceOffset:    spec.Request.Offset() - uint16(minOffset),
				sliceWordCount: spec.Request.Quantity(),
			},
			state: dependentQueued,
		}
	}
	return &CoalescedRead{
		physical:           physical,
		dependents:         dependents,
		endpoint:           base.Endpoint,
		transport:          base.Transport,
		intentGeneration:   base.TransportGeneration,
		unitID:             base.UnitID,
		authorizationScope: base.AuthorizationScope,
		pollGeneration:     base.PollGeneration,
		deadlineIdentity:   base.DeadlineIdentity,
	}, nil
}

func (group *CoalescedRead) releaseDependentCount(count int) {
	if group.scheduler != nil && count > 0 {
		group.scheduler.releaseCoalescedDependents(
			group.admissionKey,
			count,
		)
	}
}

func sameCoalescingIdentity(first, second ReadIntentSpec) bool {
	return first.Endpoint == second.Endpoint &&
		first.Transport == second.Transport &&
		first.TransportGeneration == second.TransportGeneration &&
		first.UnitID == second.UnitID &&
		first.Request.Function() == second.Request.Function() &&
		first.Request.Table() == second.Request.Table() &&
		first.AuthorizationScope == second.AuthorizationScope &&
		first.PollGeneration == second.PollGeneration &&
		first.DeadlineIdentity == second.DeadlineIdentity
}

// PhysicalRequest returns the exact minimal-union read request.
func (group *CoalescedRead) PhysicalRequest() ReadRegistersRequest {
	if group == nil {
		return ReadRegistersRequest{}
	}
	group.mu.Lock()
	defer group.mu.Unlock()
	return group.physical
}

// Slices returns independent logical-to-physical provenance values.
func (group *CoalescedRead) Slices() []CoalescedSlice {
	if group == nil {
		return nil
	}
	group.mu.Lock()
	defer group.mu.Unlock()
	slices := make([]CoalescedSlice, len(group.dependents))
	for index, dependent := range group.dependents {
		slices[index] = dependent.slice
	}
	return slices
}

// BindReservation binds the group to one owner-issued physical request.
func (group *CoalescedRead) BindReservation(
	reservation TCPReservation,
) error {
	if group == nil {
		return protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"coalesced_group",
			-1,
		)
	}
	group.mu.Lock()
	defer group.mu.Unlock()
	if group.completed ||
		group.writeBegun ||
		group.physicalRequestID != 0 ||
		reservation.owner == nil ||
		reservation.physicalRequestID == 0 ||
		reservation.generation == 0 {
		return protocolError(
			ErrorInvalidRequest,
			group.physical.Function(),
			0,
			"physical_reservation",
			-1,
		)
	}
	if group.transport != TransportTCP ||
		!reservation.owner.matchesReadReservation(
			reservation,
			group.endpoint,
			group.intentGeneration,
			group.unitID,
			group.physical,
		) {
		return protocolError(
			ErrorInvalidRequest,
			group.physical.Function(),
			0,
			"reservation_identity",
			-1,
		)
	}
	group.physicalRequestID = reservation.physicalRequestID
	group.generation = reservation.generation
	group.owner = reservation.owner
	group.reservation = reservation
	return nil
}

// CoalescedTransition reports whether transport work remains or must abandon.
type CoalescedTransition struct {
	transmitPhysical bool
	abandonTransport bool
	ownerTransition  OwnerTransition
}

// TransmitPhysical reports whether at least one queued dependent remains.
func (transition CoalescedTransition) TransmitPhysical() bool {
	return transition.transmitPhysical
}

// AbandonTransport reports that the final post-write dependent detached.
func (transition CoalescedTransition) AbandonTransport() bool {
	return transition.abandonTransport
}

// CloseConnection reports whether abandonment invalidated the current socket.
func (transition CoalescedTransition) CloseConnection() bool {
	return transition.ownerTransition.CloseConnection()
}

// FailedReservations returns sibling requests failed by socket abandonment.
func (transition CoalescedTransition) FailedReservations() []TCPReservation {
	return transition.ownerTransition.FailedReservations()
}

func (group *CoalescedRead) reservationForTransportLocked(
	owner *TCPConnectionOwner,
	generation uint64,
) (TCPReservation, error) {
	if group.writeBegun ||
		group.completed ||
		group.physicalRequestID == 0 ||
		group.owner != owner ||
		group.generation != generation {
		return TCPReservation{}, protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"coalesced_state",
			-1,
		)
	}
	if group.activeDependentCountLocked() == 0 {
		return TCPReservation{}, protocolError(
			ErrorInvalidRange,
			0,
			0,
			"active_dependents",
			-1,
		)
	}
	return group.reservation, nil
}

func (group *CoalescedRead) withWriteLock(
	prepare func() error,
) error {
	if group == nil || prepare == nil {
		return protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"coalesced_write_preparation",
			-1,
		)
	}
	group.mu.Lock()
	defer group.mu.Unlock()
	return prepare()
}

func (group *CoalescedRead) invokeWrite(
	transport *TCPTransport,
	invoke func(TCPReservation) (OwnerTransition, error),
) (OwnerTransition, error) {
	if group == nil {
		return OwnerTransition{}, protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"coalesced_group",
			-1,
		)
	}
	if invoke == nil {
		return OwnerTransition{}, protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"write_invocation",
			-1,
		)
	}
	reservation, err := group.beginWrite(transport)
	if err != nil {
		return OwnerTransition{}, err
	}
	transition, err := invoke(reservation)
	if err != nil {
		group.finishWriteFailure()
	}
	return transition, err
}

func (group *CoalescedRead) beginWrite(
	transport *TCPTransport,
) (TCPReservation, error) {
	group.mu.Lock()
	defer group.mu.Unlock()
	return group.beginWriteLocked(transport)
}

func (group *CoalescedRead) beginWriteLocked(
	transport *TCPTransport,
) (TCPReservation, error) {
	if group.writeBegun ||
		group.completed ||
		group.physicalRequestID == 0 ||
		group.activeDependentCountLocked() == 0 {
		return TCPReservation{}, protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"coalesced_state",
			-1,
		)
	}
	if transport != nil &&
		(transport.owner != group.owner ||
			transport.generation != group.generation) {
		return TCPReservation{}, protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"coalesced_transport",
			-1,
		)
	}
	if group.scheduler != nil {
		if err := group.scheduler.RequireCoalescedDispatch(group); err != nil {
			return TCPReservation{}, err
		}
	}
	if transport != nil {
		if err := transport.registerCoalescedLocked(
			group.reservation,
			group,
		); err != nil {
			return TCPReservation{}, err
		}
	}
	if err := group.owner.MarkWriteInvoked(group.reservation); err != nil {
		if transport != nil {
			transport.forgetCoalesced(group.physicalRequestID)
		}
		return TCPReservation{}, err
	}
	group.tcpTransport = transport
	group.writeBegun = true
	for index := range group.dependents {
		if group.dependents[index].state == dependentQueued {
			group.dependents[index].state = dependentAttached
		}
	}
	return group.reservation, nil
}

func (group *CoalescedRead) finishWriteFailure() {
	group.mu.Lock()
	if group.completed {
		group.mu.Unlock()
		return
	}
	failed := 0
	for index := range group.dependents {
		if group.dependents[index].state == dependentAttached {
			group.dependents[index].state = dependentFailed
			failed++
		}
	}
	group.releaseDependentCount(failed)
	group.completed = true
	transport := group.tcpTransport
	physicalRequestID := group.physicalRequestID
	group.mu.Unlock()
	if transport != nil {
		transport.forgetCoalesced(physicalRequestID)
	}
	_ = group.finishScheduling()
}

// Cancel moves one dependent to its sole cancelled terminal state.
func (group *CoalescedRead) Cancel(
	logicalViewID uint64,
) (CoalescedTransition, error) {
	if group == nil {
		return CoalescedTransition{}, protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"coalesced_group",
			-1,
		)
	}
	group.mu.Lock()
	transition, transport, completed, err := group.cancelLocked(logicalViewID)
	group.mu.Unlock()
	if completed && transport != nil {
		transport.forgetCoalesced(group.physicalRequestID)
	}
	if transition.ownerTransition.CloseConnection() && transport != nil {
		closeTransition, closeErr := transport.closeTerminal()
		transition.ownerTransition = mergeOwnerTransitions(
			transition.ownerTransition,
			closeTransition,
		)
		err = errors.Join(err, closeErr)
	}
	if completed {
		err = errors.Join(err, group.finishScheduling())
	}
	return transition, err
}

func (group *CoalescedRead) cancelLocked(
	logicalViewID uint64,
) (CoalescedTransition, *TCPTransport, bool, error) {
	if group.completed {
		return CoalescedTransition{}, nil, false, protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"coalesced_state",
			-1,
		)
	}
	for index := range group.dependents {
		dependent := &group.dependents[index]
		if dependent.slice.logicalViewID != logicalViewID {
			continue
		}
		if dependent.state != dependentQueued &&
			dependent.state != dependentAttached {
			return CoalescedTransition{}, nil, false, protocolError(
				ErrorInvalidRequest,
				group.physical.Function(),
				0,
				"dependent_state",
				-1,
			)
		}
		wasAttached := dependent.state == dependentAttached
		activeAfter := group.activeDependentCountLocked() - 1
		var ownerTransition OwnerTransition
		var ownerErr error
		var replacement ReadRegistersRequest
		haveReplacement := false
		if !group.writeBegun && activeAfter > 0 {
			replacement, ownerErr =
				group.physicalWithoutLogicalLocked(logicalViewID)
			if ownerErr == nil && group.owner != nil {
				ownerErr = group.owner.replaceReservedRead(
					group.reservation,
					replacement,
				)
			}
			if ownerErr != nil {
				return CoalescedTransition{}, nil, false, ownerErr
			}
			haveReplacement = true
		}
		if !group.writeBegun &&
			activeAfter == 0 &&
			group.owner != nil {
			ownerErr = group.owner.CancelBeforeWrite(group.reservation)
		}
		if wasAttached && activeAfter == 0 {
			ownerTransition, ownerErr = group.owner.AbandonAfterWrite(
				group.reservation,
				AbandonCancellation,
			)
		}
		if ownerErr != nil && !ownerTransition.CloseConnection() {
			return CoalescedTransition{}, nil, false, ownerErr
		}
		dependent.state = dependentCancelled
		group.releaseDependentCount(1)
		active := group.activeDependentCountLocked()
		if haveReplacement {
			group.applyPhysicalLocked(replacement)
		}
		if active == 0 {
			group.completed = true
		}
		transition := CoalescedTransition{
			transmitPhysical: !group.writeBegun && active > 0,
			abandonTransport: wasAttached && active == 0,
			ownerTransition:  ownerTransition,
		}
		return transition, group.tcpTransport, group.completed, ownerErr
	}
	return CoalescedTransition{}, nil, false, protocolError(
		ErrorInvalidRequest,
		group.physical.Function(),
		0,
		"logical_view_id",
		-1,
	)
}

func (group *CoalescedRead) physicalWithoutLogicalLocked(
	excludedLogicalViewID uint64,
) (ReadRegistersRequest, error) {
	var minOffset uint32
	var maxEnd uint32
	haveActive := false
	for _, dependent := range group.dependents {
		if dependent.state != dependentQueued &&
			dependent.state != dependentAttached {
			continue
		}
		if dependent.slice.logicalViewID == excludedLogicalViewID {
			continue
		}
		start := uint32(dependent.slice.logicalOffset)
		end := start + uint32(dependent.slice.logicalWords)
		if !haveActive || start < minOffset {
			minOffset = start
		}
		if !haveActive || end > maxEnd {
			maxEnd = end
		}
		haveActive = true
	}
	if !haveActive || maxEnd <= minOffset {
		return ReadRegistersRequest{}, protocolError(
			ErrorInvalidRequest,
			group.physical.Function(),
			0,
			"physical_union",
			-1,
		)
	}
	physical, err := NewReadRegistersRequest(
		group.physical.Function(),
		uint16(minOffset),
		uint16(maxEnd-minOffset),
	)
	if err != nil {
		return ReadRegistersRequest{}, err
	}
	return physical, nil
}

func (group *CoalescedRead) applyPhysicalLocked(
	physical ReadRegistersRequest,
) {
	group.physical = physical
	for index := range group.dependents {
		dependent := &group.dependents[index]
		if dependent.state != dependentQueued &&
			dependent.state != dependentAttached {
			continue
		}
		dependent.slice.sliceOffset =
			dependent.slice.logicalOffset - physical.Offset()
	}
}

// ActiveDependentCount returns queued or attached dependent count.
func (group *CoalescedRead) ActiveDependentCount() int {
	if group == nil {
		return 0
	}
	group.mu.Lock()
	defer group.mu.Unlock()
	return group.activeDependentCountLocked()
}

func (group *CoalescedRead) activeDependentCountLocked() int {
	count := 0
	for _, dependent := range group.dependents {
		if dependent.state == dependentQueued ||
			dependent.state == dependentAttached {
			count++
		}
	}
	return count
}

// LogicalReadView is one exact successful dependent observation.
type LogicalReadView struct {
	logicalViewID  uint64
	wireResponseID uint64
	logicalOffset  uint16
	logicalWords   uint16
	sliceOffset    uint16
	sliceWordCount uint16
	words          []uint16
	provenance     LogicalViewProvenance
}

// LogicalViewProvenance is the self-contained physical/logical source record.
type LogicalViewProvenance struct {
	PhysicalRequestID  uint64
	Wire               WireProvenance
	AuthorizationScope string
	PollGeneration     uint64
	DeadlineIdentity   uint64
	LogicalOffset      uint16
	LogicalWordCount   uint16
	SliceOffset        uint16
	SliceWordCount     uint16
}

// LogicalViewID returns the distinct dependent observation identity.
func (view LogicalReadView) LogicalViewID() uint64 {
	return view.logicalViewID
}

// WireResponseID returns the shared physical wire response identity.
func (view LogicalReadView) WireResponseID() uint64 {
	return view.wireResponseID
}

// LogicalOffset returns the exact requested zero-based PDU offset.
func (view LogicalReadView) LogicalOffset() uint16 {
	return view.logicalOffset
}

// LogicalWordCount returns the exact requested word count.
func (view LogicalReadView) LogicalWordCount() uint16 {
	return view.logicalWords
}

// SliceOffset returns the view start within the physical response.
func (view LogicalReadView) SliceOffset() uint16 {
	return view.sliceOffset
}

// SliceWordCount returns the view word count within the physical response.
func (view LogicalReadView) SliceWordCount() uint16 {
	return view.sliceWordCount
}

// Words returns an independent copy of the exact logical values.
func (view LogicalReadView) Words() []uint16 {
	return append([]uint16(nil), view.words...)
}

// Provenance returns the complete immutable source and logical slice binding.
func (view LogicalReadView) Provenance() LogicalViewProvenance {
	return view.provenance
}

// ReplaySuccessfulResponse creates views only for still-active dependents.
func (group *CoalescedRead) ReplaySuccessfulResponse(
	response WireResponse,
) (views []LogicalReadView, err error) {
	if group == nil {
		return nil, protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"coalesced_group",
			-1,
		)
	}
	group.mu.Lock()
	defer func() {
		completed := group.completed
		transport := group.tcpTransport
		physicalRequestID := group.physicalRequestID
		group.mu.Unlock()
		if completed && transport != nil {
			transport.forgetCoalesced(physicalRequestID)
		}
		if completed {
			err = errors.Join(err, group.finishScheduling())
		}
	}()
	provenance := response.provenance
	if group.completed ||
		!group.writeBegun ||
		response.wireResponseID == 0 ||
		response.owner != group.owner ||
		!response.deliverable ||
		response.outcome != WireSuccessfulData ||
		response.physicalRequestID != group.physicalRequestID ||
		provenance.Transport != TransportTCP ||
		provenance.TransportGeneration != group.generation ||
		provenance.RequestedFunction != group.physical.Function() ||
		provenance.Table != group.physical.Table() ||
		provenance.Offset != group.physical.Offset() ||
		provenance.Quantity != group.physical.Quantity() {
		return nil, protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"replay_identity",
			-1,
		)
	}
	physicalWords := response.words
	if len(physicalWords) != int(group.physical.Quantity()) {
		return nil, protocolError(
			ErrorInvalidRange,
			group.physical.Function(),
			0,
			"physical_words",
			-1,
		)
	}
	views = make(
		[]LogicalReadView,
		0,
		group.activeDependentCountLocked(),
	)
	for index := range group.dependents {
		dependent := &group.dependents[index]
		if dependent.state == dependentCancelled {
			continue
		}
		if dependent.state != dependentAttached {
			return nil, protocolError(
				ErrorInvalidRequest,
				group.physical.Function(),
				0,
				"dependent_state",
				-1,
			)
		}
		start := uint32(dependent.slice.sliceOffset)
		end := start + uint32(dependent.slice.sliceWordCount)
		if end > uint32(len(physicalWords)) {
			return nil, protocolError(
				ErrorInvalidRange,
				group.physical.Function(),
				0,
				"logical_slice",
				-1,
			)
		}
		views = append(views, LogicalReadView{
			logicalViewID:  dependent.slice.logicalViewID,
			wireResponseID: response.wireResponseID,
			logicalOffset:  dependent.slice.logicalOffset,
			logicalWords:   dependent.slice.logicalWords,
			sliceOffset:    dependent.slice.sliceOffset,
			sliceWordCount: dependent.slice.sliceWordCount,
			words: append(
				[]uint16(nil),
				physicalWords[int(start):int(end)]...,
			),
			provenance: LogicalViewProvenance{
				PhysicalRequestID:  response.physicalRequestID,
				Wire:               response.provenance,
				AuthorizationScope: group.authorizationScope,
				PollGeneration:     group.pollGeneration,
				DeadlineIdentity:   group.deadlineIdentity,
				LogicalOffset:      dependent.slice.logicalOffset,
				LogicalWordCount:   dependent.slice.logicalWords,
				SliceOffset:        dependent.slice.sliceOffset,
				SliceWordCount:     dependent.slice.sliceWordCount,
			},
		})
		dependent.state = dependentDelivered
	}
	group.releaseDependentCount(len(views))
	group.completed = true
	return views, nil
}

// Fail terminates all attached dependents for a correlated non-data response.
func (group *CoalescedRead) Fail(response WireResponse) (err error) {
	if group == nil {
		return protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"coalesced_group",
			-1,
		)
	}
	group.mu.Lock()
	defer func() {
		completed := group.completed
		transport := group.tcpTransport
		physicalRequestID := group.physicalRequestID
		group.mu.Unlock()
		if completed && transport != nil {
			transport.forgetCoalesced(physicalRequestID)
		}
		if completed {
			err = errors.Join(err, group.finishScheduling())
		}
	}()
	if group.completed ||
		!group.writeBegun ||
		response.wireResponseID == 0 ||
		response.owner != group.owner ||
		response.physicalRequestID != group.physicalRequestID ||
		response.deliverable ||
		(response.outcome != WireProtocolException &&
			response.outcome != WireMalformedResponse) {
		return protocolError(
			ErrorInvalidRequest,
			group.physical.Function(),
			0,
			"failed_response",
			-1,
		)
	}
	failed := 0
	for index := range group.dependents {
		if group.dependents[index].state == dependentAttached {
			group.dependents[index].state = dependentFailed
			failed++
		}
	}
	group.releaseDependentCount(failed)
	group.completed = true
	return nil
}

// FailTransport terminates all non-terminal dependents without a response.
func (group *CoalescedRead) FailTransport() error {
	if group == nil {
		return protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"coalesced_group",
			-1,
		)
	}
	group.mu.Lock()
	err := group.failTransportLocked()
	completed := group.completed
	transport := group.tcpTransport
	physicalRequestID := group.physicalRequestID
	group.mu.Unlock()
	if completed && transport != nil {
		transport.forgetCoalesced(physicalRequestID)
	}
	if completed {
		err = errors.Join(err, group.finishScheduling())
	}
	return err
}

func (group *CoalescedRead) failTransportLocked() error {
	if group.completed {
		return nil
	}
	var ownerErr error
	if group.owner != nil && !group.writeBegun {
		ownerErr = group.owner.CancelBeforeWrite(group.reservation)
	}
	failed := 0
	for index := range group.dependents {
		if group.dependents[index].state == dependentQueued ||
			group.dependents[index].state == dependentAttached {
			group.dependents[index].state = dependentFailed
			failed++
		}
	}
	group.releaseDependentCount(failed)
	group.completed = true
	return ownerErr
}

func (group *CoalescedRead) finishScheduling() error {
	if group == nil || group.scheduler == nil {
		return nil
	}
	return group.scheduler.FinishCoalesced(group)
}

// DependentStates returns an immutable lifecycle snapshot keyed by view ID.
func (group *CoalescedRead) DependentStates() map[uint64]DependentTerminalState {
	if group == nil {
		return nil
	}
	group.mu.Lock()
	defer group.mu.Unlock()
	states := make(
		map[uint64]DependentTerminalState,
		len(group.dependents),
	)
	for _, dependent := range group.dependents {
		states[dependent.slice.logicalViewID] =
			publicDependentState(dependent.state)
	}
	return states
}

func publicDependentState(state dependentState) DependentTerminalState {
	switch state {
	case dependentQueued:
		return DependentQueued
	case dependentAttached:
		return DependentAttached
	case dependentCancelled:
		return DependentCancelled
	case dependentDelivered:
		return DependentDelivered
	case dependentFailed:
		return DependentFailed
	default:
		return ""
	}
}
