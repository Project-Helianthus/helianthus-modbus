package modbus

import (
	"encoding/json"
	"math"
	"sort"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

// RuntimeAcquisitionError is a stable sentinel error from the source-owned
// runtime acquisition boundary.
type RuntimeAcquisitionError string

// Error implements error.
func (err RuntimeAcquisitionError) Error() string {
	return string(err)
}

const (
	// ErrRuntimeAcquisitionUnavailable marks a value that has no source-owned
	// runtime issuance authority.
	ErrRuntimeAcquisitionUnavailable RuntimeAcquisitionError = "runtime acquisition unavailable"
	// ErrRuntimeAcquisitionCapacity marks a configured live-state bound.
	ErrRuntimeAcquisitionCapacity RuntimeAcquisitionError = "runtime acquisition capacity exhausted"
	// ErrRuntimeTerminalSequenceExhausted marks permanent sequence exhaustion.
	ErrRuntimeTerminalSequenceExhausted RuntimeAcquisitionError = "runtime terminal sequence exhausted"
	// ErrRuntimeAttemptClosed marks an attempt that no longer admits membership.
	ErrRuntimeAttemptClosed RuntimeAcquisitionError = "runtime attempt is closed"
	// ErrRuntimeAttemptMembership marks an incomplete or inconsistent member set.
	ErrRuntimeAttemptMembership RuntimeAcquisitionError = "runtime attempt membership mismatch"
	// ErrRuntimeNormalization marks invalid or over-bound documentary input.
	ErrRuntimeNormalization RuntimeAcquisitionError = "runtime normalization invalid"
	// ErrOpaqueRuntimeState prevents private authority from entering encodings.
	ErrOpaqueRuntimeState RuntimeAcquisitionError = "opaque runtime state is not serializable"
)

const (
	maxRuntimeCapabilities       = 1 << 16
	maxRuntimeAttempts           = 1 << 16
	maxRuntimeMembersPerAttempt  = maxCoalescedDependents
	maxRuntimeNormalizationBytes = 4 << 20
	maxRuntimeNormalizationItems = 1 << 12
	maxRuntimeStringBytes        = 1 << 20
	maxRuntimeTombstones         = 1 << 16
)

func newRuntimeViewEligibility(
	source *RuntimeAcquisitionSource,
) *runtimeViewEligibility {
	if source == nil {
		return nil
	}
	return &runtimeViewEligibility{source: source}
}

// RuntimeAcquisitionClock supplies the source-owned monotonic claim time.
type RuntimeAcquisitionClock interface {
	Now() time.Duration
}

// RuntimeAcquisitionLimits closes every source-owned allocation dimension.
type RuntimeAcquisitionLimits struct {
	MaxLiveCapabilities                        int
	MaxAttempts                                int
	MaxMembersPerAttempt                       int
	AttemptKeyMaxUTF8Bytes                     int
	SourceEvidenceIDMaxUTF8Bytes               int
	NormalizationRecordMaxEncodedBytes         int
	NormalizationRequiredStringMaxUTF8Bytes    int
	NormalizationExtensionCountMax             int
	NormalizationExtensionKeyMaxUTF8Bytes      int
	NormalizationExtensionValueMaxEncodedBytes int
	RetainedDiagnosticCountPerObjectMax        int
	RetainedDiagnosticMaxUTF8Bytes             int
	CapabilityTombstoneLimit                   int
	CapabilityTombstoneMaxEncodedBytes         int
}

// RuntimeAcquisitionConfig activates one bounded source owner.
type RuntimeAcquisitionConfig struct {
	Limits        RuntimeAcquisitionLimits
	ClaimLifetime time.Duration
	Clock         RuntimeAcquisitionClock
	Restart       *RuntimeAcquisitionRestartState
}

// RuntimeCapabilityTerminalOutcome is the closed terminal capability enum.
type RuntimeCapabilityTerminalOutcome string

const (
	RuntimeCapabilityClaimed   RuntimeCapabilityTerminalOutcome = "claimed"
	RuntimeCapabilityCancelled RuntimeCapabilityTerminalOutcome = "cancelled"
	RuntimeCapabilityFailed    RuntimeCapabilityTerminalOutcome = "failed"
	RuntimeCapabilityExpired   RuntimeCapabilityTerminalOutcome = "expired"
)

// RuntimeCapabilityTombstone is the complete non-reconstructing audit record.
type RuntimeCapabilityTombstone struct {
	SchemaVersion    int                              `json:"schema_version"`
	TerminalSequence uint64                           `json:"terminal_sequence"`
	TerminalOutcome  RuntimeCapabilityTerminalOutcome `json:"terminal_outcome"`
}

// RuntimeAcquisitionRestartState is the bounded source restart metadata.
type RuntimeAcquisitionRestartState struct {
	SchemaVersion        int                          `json:"schema_version"`
	NextTerminalSequence uint64                       `json:"next_terminal_sequence"`
	SequenceExhausted    bool                         `json:"sequence_exhausted"`
	Tombstones           []RuntimeCapabilityTombstone `json:"tombstones"`
}

// RuntimeAcquisitionSnapshot reports bounded public resource state only.
type RuntimeAcquisitionSnapshot struct {
	LiveCapabilities     int
	ActiveAttempts       int
	NextTerminalSequence uint64
	SequenceExhausted    bool
	Tombstones           []RuntimeCapabilityTombstone
}

type runtimeAttemptPhase uint8

const (
	runtimeAttemptOpen runtimeAttemptPhase = iota + 1
	runtimeAttemptClosing
	runtimeAttemptClosed
)

type runtimeAttemptToken struct {
	source atomic.Pointer[RuntimeAcquisitionSource]
}

type runtimeCapabilityToken struct {
	source  atomic.Pointer[RuntimeAcquisitionSource]
	attempt *runtimeAttemptToken
	ordinal uint32
	outcome atomic.Uint32
}

type runtimeAttemptState struct {
	token      *runtimeAttemptToken
	key        string
	phase      runtimeAttemptPhase
	registered map[uint32]*runtimeCapabilityToken
	members    []*runtimeCapabilityToken
}

type runtimeCapabilityState struct {
	token            *runtimeCapabilityToken
	attempt          *runtimeAttemptToken
	terminalSequence uint64
	claimDeadline    time.Duration
}

// RuntimeAcquisitionSource owns issuance, claim state, cancellation, and
// deterministic reclamation. It contains no transport or consumer policy.
type RuntimeAcquisitionSource struct {
	mu                   sync.Mutex
	config               RuntimeAcquisitionConfig
	attempts             map[*runtimeAttemptToken]*runtimeAttemptState
	live                 map[*runtimeCapabilityToken]*runtimeCapabilityState
	tombstones           []RuntimeCapabilityTombstone
	nextTerminalSequence uint64
	sequenceExhausted    bool
	retired              bool
	beforeMembership     func()
}

// RuntimeAttempt is an opaque open membership handle.
type RuntimeAttempt struct {
	token *runtimeAttemptToken
}

// RuntimeAttemptInstance is the exact opaque identity of one closed attempt.
type RuntimeAttemptInstance struct {
	token *runtimeAttemptToken
}

// RuntimeAcquisitionCapability is one source-issued, copy-shared claim view.
type RuntimeAcquisitionCapability struct {
	token *runtimeCapabilityToken
}

// RuntimeCapabilityClaimResult distinguishes the one CAS winner from later
// immutable observations of the same terminal state.
type RuntimeCapabilityClaimResult struct {
	Won     bool
	Outcome RuntimeCapabilityTerminalOutcome
}

// RuntimeAcquisitionProvenance is the lossless successful logical-view source
// record. Slice fields are copied on every return.
type RuntimeAcquisitionProvenance struct {
	SourceKind          RuntimeAcquisitionSourceKind
	SourceEvidenceID    string
	LogicalViewID       uint64
	WireResponseID      uint64
	PhysicalRequestID   uint64
	Endpoint            string
	ConnectionID        uint64
	Transport           TransportFamily
	TransportGeneration uint64
	UnitID              byte
	RequestedFunction   FunctionCode
	ReceivedFunction    FunctionCode
	Table               LogicalTable
	PhysicalOffset      uint16
	PhysicalWordCount   uint16
	AuthorizationScope  string
	PollGeneration      uint64
	DeadlineIdentity    uint64
	LogicalOffset       uint16
	LogicalWordCount    uint16
	SliceOffset         uint16
	SliceWordCount      uint16
	Words               []uint16
	WireResponseBytes   []byte
}

// RuntimeAcquisition combines documentary provenance with an opaque claim.
type RuntimeAcquisition struct {
	attemptKey    string
	provenance    RuntimeAcquisitionProvenance
	normalization RuntimeNormalizationRecord
	capability    RuntimeAcquisitionCapability
}

type runtimeViewEligibility struct {
	source *RuntimeAcquisitionSource
	state  atomic.Uint32
}

const (
	runtimeViewAvailable uint32 = iota
	runtimeViewIssuing
	runtimeViewIssued
	runtimeViewRejected
)

// NewRuntimeAcquisitionSource validates all bounds before allocating an owner.
func NewRuntimeAcquisitionSource(
	config RuntimeAcquisitionConfig,
) (*RuntimeAcquisitionSource, error) {
	if err := validateRuntimeAcquisitionConfig(config); err != nil {
		return nil, err
	}
	restart := config.Restart
	config.Restart = nil
	source := &RuntimeAcquisitionSource{
		config:               config,
		attempts:             make(map[*runtimeAttemptToken]*runtimeAttemptState),
		live:                 make(map[*runtimeCapabilityToken]*runtimeCapabilityState),
		nextTerminalSequence: 1,
	}
	if restart != nil {
		source.nextTerminalSequence = restart.NextTerminalSequence
		source.sequenceExhausted = restart.SequenceExhausted
		source.tombstones = append(
			[]RuntimeCapabilityTombstone(nil),
			restart.Tombstones...,
		)
	}
	return source, nil
}

func validateRuntimeAcquisitionConfig(config RuntimeAcquisitionConfig) error {
	limits := config.Limits
	positiveBounded := []struct {
		value int
		max   int
	}{
		{limits.MaxLiveCapabilities, maxRuntimeCapabilities},
		{limits.MaxAttempts, maxRuntimeAttempts},
		{limits.MaxMembersPerAttempt, maxRuntimeMembersPerAttempt},
		{limits.AttemptKeyMaxUTF8Bytes, maxRuntimeStringBytes},
		{limits.SourceEvidenceIDMaxUTF8Bytes, maxRuntimeStringBytes},
		{limits.NormalizationRecordMaxEncodedBytes, maxRuntimeNormalizationBytes},
		{limits.NormalizationRequiredStringMaxUTF8Bytes, maxRuntimeStringBytes},
		{limits.NormalizationExtensionCountMax, maxRuntimeNormalizationItems},
		{limits.NormalizationExtensionKeyMaxUTF8Bytes, maxRuntimeStringBytes},
		{limits.NormalizationExtensionValueMaxEncodedBytes, maxRuntimeNormalizationBytes},
		{limits.RetainedDiagnosticCountPerObjectMax, maxRuntimeNormalizationItems},
		{limits.RetainedDiagnosticMaxUTF8Bytes, maxRuntimeStringBytes},
		{limits.CapabilityTombstoneLimit, maxRuntimeTombstones},
		{limits.CapabilityTombstoneMaxEncodedBytes, maxRuntimeNormalizationBytes},
	}
	for _, bound := range positiveBounded {
		if bound.value <= 0 || bound.value > bound.max {
			return ErrRuntimeAcquisitionUnavailable
		}
	}
	if limits.MaxMembersPerAttempt > limits.MaxLiveCapabilities ||
		config.Clock == nil || config.ClaimLifetime <= 0 ||
		config.Clock.Now() < 0 {
		return ErrRuntimeAcquisitionUnavailable
	}
	keyAndValue, ok := checkedRuntimeAdd(
		limits.NormalizationExtensionKeyMaxUTF8Bytes,
		limits.NormalizationExtensionValueMaxEncodedBytes,
	)
	if !ok {
		return ErrRuntimeAcquisitionUnavailable
	}
	if _, ok := checkedRuntimeAdd(
		len(runtimeNormalizationRequiredFields),
		limits.NormalizationExtensionCountMax,
	); !ok {
		return ErrRuntimeAcquisitionUnavailable
	}
	if _, ok := checkedRuntimeMultiply(
		limits.NormalizationExtensionCountMax,
		keyAndValue,
	); !ok {
		return ErrRuntimeAcquisitionUnavailable
	}
	largest, err := json.Marshal(RuntimeCapabilityTombstone{
		SchemaVersion:    1,
		TerminalSequence: math.MaxUint64,
		TerminalOutcome:  RuntimeCapabilityCancelled,
	})
	if err != nil || len(largest) > limits.CapabilityTombstoneMaxEncodedBytes {
		return ErrRuntimeAcquisitionUnavailable
	}
	return validateRuntimeRestart(config.Restart, limits)
}

func validateRuntimeRestart(
	restart *RuntimeAcquisitionRestartState,
	limits RuntimeAcquisitionLimits,
) error {
	if restart == nil {
		return nil
	}
	if restart.SchemaVersion != 1 ||
		len(restart.Tombstones) > limits.CapabilityTombstoneLimit ||
		(restart.SequenceExhausted && restart.NextTerminalSequence != 0) ||
		(!restart.SequenceExhausted && restart.NextTerminalSequence == 0) {
		return ErrRuntimeAcquisitionUnavailable
	}
	var previous uint64
	for index, tombstone := range restart.Tombstones {
		if !validRuntimeTombstone(tombstone) ||
			(index > 0 && tombstone.TerminalSequence <= previous) {
			return ErrRuntimeAcquisitionUnavailable
		}
		encoded, err := json.Marshal(tombstone)
		if err != nil || len(encoded) > limits.CapabilityTombstoneMaxEncodedBytes {
			return ErrRuntimeAcquisitionUnavailable
		}
		previous = tombstone.TerminalSequence
	}
	if !restart.SequenceExhausted && previous >= restart.NextTerminalSequence {
		return ErrRuntimeAcquisitionUnavailable
	}
	return nil
}

func checkedRuntimeAdd(first, second int) (int, bool) {
	if first < 0 || second < 0 || first > math.MaxInt-second {
		return 0, false
	}
	return first + second, true
}

func checkedRuntimeMultiply(first, second int) (int, bool) {
	if first < 0 || second < 0 || (first != 0 && second > math.MaxInt/first) {
		return 0, false
	}
	return first * second, true
}

func validRuntimeTombstone(tombstone RuntimeCapabilityTombstone) bool {
	return tombstone.SchemaVersion == 1 && tombstone.TerminalSequence != 0 &&
		validRuntimeTerminalOutcome(tombstone.TerminalOutcome)
}

func validRuntimeTerminalOutcome(outcome RuntimeCapabilityTerminalOutcome) bool {
	switch outcome {
	case RuntimeCapabilityClaimed,
		RuntimeCapabilityCancelled,
		RuntimeCapabilityFailed,
		RuntimeCapabilityExpired:
		return true
	default:
		return false
	}
}

// BeginAttempt creates a fresh opaque incarnation for one documentary key.
func (source *RuntimeAcquisitionSource) BeginAttempt(
	attemptKey string,
) (*RuntimeAttempt, error) {
	if source == nil || attemptKey == "" || !utf8.ValidString(attemptKey) ||
		len(attemptKey) > source.config.Limits.AttemptKeyMaxUTF8Bytes {
		return nil, ErrRuntimeAcquisitionUnavailable
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	if source.retired {
		return nil, ErrRuntimeAcquisitionUnavailable
	}
	if len(source.attempts) >= source.config.Limits.MaxAttempts {
		return nil, ErrRuntimeAcquisitionCapacity
	}
	token := &runtimeAttemptToken{}
	token.source.Store(source)
	source.attempts[token] = &runtimeAttemptState{
		token:      token,
		key:        attemptKey,
		phase:      runtimeAttemptOpen,
		registered: make(map[uint32]*runtimeCapabilityToken),
	}
	return &RuntimeAttempt{token: token}, nil
}

// Issue emits one capability only from an eligible successful runtime view.
func (source *RuntimeAcquisitionSource) Issue(
	attempt *RuntimeAttempt,
	dependencyOrdinal uint32,
	view LogicalReadView,
	normalization RuntimeNormalizationRecord,
) (RuntimeAcquisition, error) {
	if source == nil || attempt == nil || attempt.token == nil ||
		attempt.token.source.Load() != source || normalization.owner != source ||
		view.runtimeEligibility == nil ||
		view.runtimeEligibility.source != source ||
		normalization.fields.SourceKind != RuntimeAcquisitionSourceRuntime ||
		!normalizationMatchesView(normalization.fields, view) {
		return RuntimeAcquisition{}, ErrRuntimeAcquisitionUnavailable
	}
	if hook := source.beforeMembership; hook != nil {
		hook()
	}
	if !view.runtimeEligibility.state.CompareAndSwap(
		runtimeViewAvailable,
		runtimeViewIssuing,
	) {
		return RuntimeAcquisition{}, ErrRuntimeAcquisitionUnavailable
	}
	now := source.config.Clock.Now()
	if now < 0 || source.config.ClaimLifetime > time.Duration(math.MaxInt64)-now {
		view.runtimeEligibility.state.Store(runtimeViewRejected)
		return RuntimeAcquisition{}, ErrRuntimeAcquisitionUnavailable
	}
	source.mu.Lock()
	state := source.attempts[attempt.token]
	if source.retired || state == nil || state.phase != runtimeAttemptOpen {
		source.mu.Unlock()
		view.runtimeEligibility.state.Store(runtimeViewRejected)
		return RuntimeAcquisition{}, ErrRuntimeAttemptClosed
	}
	if uint64(dependencyOrdinal) >= uint64(source.config.Limits.MaxMembersPerAttempt) {
		source.mu.Unlock()
		view.runtimeEligibility.state.Store(runtimeViewRejected)
		return RuntimeAcquisition{}, ErrRuntimeAttemptMembership
	}
	if _, duplicate := state.registered[dependencyOrdinal]; duplicate {
		source.mu.Unlock()
		view.runtimeEligibility.state.Store(runtimeViewRejected)
		return RuntimeAcquisition{}, ErrRuntimeAttemptMembership
	}
	if len(state.registered) >= source.config.Limits.MaxMembersPerAttempt ||
		len(source.live) >= source.config.Limits.MaxLiveCapabilities {
		source.mu.Unlock()
		view.runtimeEligibility.state.Store(runtimeViewRejected)
		return RuntimeAcquisition{}, ErrRuntimeAcquisitionCapacity
	}
	sequence, err := source.reserveTerminalSequenceLocked()
	if err != nil {
		source.mu.Unlock()
		view.runtimeEligibility.state.Store(runtimeViewRejected)
		return RuntimeAcquisition{}, err
	}
	token := &runtimeCapabilityToken{
		attempt: attempt.token,
		ordinal: dependencyOrdinal,
	}
	token.source.Store(source)
	source.live[token] = &runtimeCapabilityState{
		token:            token,
		attempt:          attempt.token,
		terminalSequence: sequence,
		claimDeadline:    now + source.config.ClaimLifetime,
	}
	state.registered[dependencyOrdinal] = token
	source.mu.Unlock()
	view.runtimeEligibility.state.Store(runtimeViewIssued)
	return RuntimeAcquisition{
		attemptKey: state.key,
		provenance: runtimeProvenanceFromView(
			view,
			normalization.fields,
		),
		normalization: normalization,
		capability: RuntimeAcquisitionCapability{
			token: token,
		},
	}, nil
}

func normalizationMatchesView(
	fields RuntimeNormalizationFields,
	view LogicalReadView,
) bool {
	provenance := view.Provenance()
	return view.LogicalViewID() != 0 && view.WireResponseID() != 0 &&
		provenance.PhysicalRequestID != 0 &&
		provenance.Wire.Transport == TransportTCP &&
		provenance.Wire.RequestedFunction == fields.FunctionCode &&
		provenance.Wire.ReceivedFunction == fields.FunctionCode &&
		provenance.Wire.Table == fields.LogicalTable &&
		view.LogicalOffset() == fields.NormalizedZeroBasedPDUOffset &&
		view.LogicalWordCount() == fields.WordCount &&
		view.LogicalWordCount() == view.SliceWordCount() &&
		len(view.words) == int(view.LogicalWordCount()) &&
		len(view.wireBytes) != 0
}

func runtimeProvenanceFromView(
	view LogicalReadView,
	fields RuntimeNormalizationFields,
) RuntimeAcquisitionProvenance {
	provenance := view.Provenance()
	wire := provenance.Wire
	return RuntimeAcquisitionProvenance{
		SourceKind:          fields.SourceKind,
		SourceEvidenceID:    fields.SourceEvidenceID,
		LogicalViewID:       view.LogicalViewID(),
		WireResponseID:      view.WireResponseID(),
		PhysicalRequestID:   provenance.PhysicalRequestID,
		Endpoint:            wire.Endpoint,
		ConnectionID:        wire.ConnectionID,
		Transport:           wire.Transport,
		TransportGeneration: wire.TransportGeneration,
		UnitID:              wire.UnitID,
		RequestedFunction:   wire.RequestedFunction,
		ReceivedFunction:    wire.ReceivedFunction,
		Table:               wire.Table,
		PhysicalOffset:      wire.Offset,
		PhysicalWordCount:   wire.Quantity,
		AuthorizationScope:  provenance.AuthorizationScope,
		PollGeneration:      provenance.PollGeneration,
		DeadlineIdentity:    provenance.DeadlineIdentity,
		LogicalOffset:       view.LogicalOffset(),
		LogicalWordCount:    view.LogicalWordCount(),
		SliceOffset:         view.SliceOffset(),
		SliceWordCount:      view.SliceWordCount(),
		Words:               view.Words(),
		WireResponseBytes:   append([]byte(nil), view.wireBytes...),
	}
}

func (source *RuntimeAcquisitionSource) reserveTerminalSequenceLocked() (
	uint64,
	error,
) {
	if source.sequenceExhausted || source.nextTerminalSequence == 0 {
		return 0, ErrRuntimeTerminalSequenceExhausted
	}
	sequence := source.nextTerminalSequence
	if sequence == math.MaxUint64 {
		source.nextTerminalSequence = 0
		source.sequenceExhausted = true
	} else {
		source.nextTerminalSequence++
	}
	return sequence, nil
}

// Close atomically freezes and validates one exact ordered member set.
func (attempt *RuntimeAttempt) Close(
	members []RuntimeAcquisition,
) (RuntimeAttemptInstance, error) {
	if attempt == nil || attempt.token == nil {
		return RuntimeAttemptInstance{}, ErrRuntimeAcquisitionUnavailable
	}
	source := attempt.token.source.Load()
	if source == nil {
		return RuntimeAttemptInstance{}, ErrRuntimeAttemptClosed
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	state := source.attempts[attempt.token]
	if state == nil || state.phase != runtimeAttemptOpen {
		return RuntimeAttemptInstance{}, ErrRuntimeAttemptClosed
	}
	state.phase = runtimeAttemptClosing
	if !source.exactMembershipLocked(state, members) {
		source.cancelAttemptMembersLocked(state)
		delete(source.attempts, attempt.token)
		attempt.token.source.Store(nil)
		return RuntimeAttemptInstance{}, ErrRuntimeAttemptMembership
	}
	state.members = make([]*runtimeCapabilityToken, len(members))
	for index, member := range members {
		state.members[index] = member.capability.token
	}
	state.phase = runtimeAttemptClosed
	instance := RuntimeAttemptInstance{token: attempt.token}
	source.reclaimAttemptIfTerminalLocked(state)
	return instance, nil
}

func (source *RuntimeAcquisitionSource) exactMembershipLocked(
	state *runtimeAttemptState,
	members []RuntimeAcquisition,
) bool {
	if len(members) == 0 || len(members) != len(state.registered) ||
		len(members) > source.config.Limits.MaxMembersPerAttempt {
		return false
	}
	seen := make(map[*runtimeCapabilityToken]struct{}, len(members))
	for index, member := range members {
		token := member.capability.token
		capability := source.live[token]
		outcome := runtimeOutcomeOf(token)
		registered := state.registered[uint32(index)]
		if token == nil || token != registered || token.ordinal != uint32(index) ||
			(capability == nil && outcome == "") ||
			(capability != nil && capability.attempt != state.token) ||
			token.attempt != state.token || member.attemptKey != state.key {
			return false
		}
		if _, duplicate := seen[token]; duplicate {
			return false
		}
		seen[token] = struct{}{}
	}
	return true
}

func (source *RuntimeAcquisitionSource) cancelAttemptMembersLocked(
	state *runtimeAttemptState,
) {
	for _, token := range state.registered {
		if capability := source.live[token]; capability != nil {
			source.terminalizeLocked(capability, RuntimeCapabilityCancelled)
		}
	}
}

// Claim performs the source-owned one-shot CAS through an exact closed instance.
func (capability RuntimeAcquisitionCapability) Claim(
	instance RuntimeAttemptInstance,
) (RuntimeCapabilityClaimResult, error) {
	if capability.token == nil || instance.token == nil {
		return RuntimeCapabilityClaimResult{}, ErrRuntimeAcquisitionUnavailable
	}
	if capability.token.attempt != instance.token {
		return RuntimeCapabilityClaimResult{}, ErrRuntimeAttemptMembership
	}
	source := capability.token.source.Load()
	if source != nil {
		return source.claim(capability.token, instance.token)
	}
	if outcome := runtimeOutcomeOf(capability.token); outcome != "" {
		return RuntimeCapabilityClaimResult{Outcome: outcome}, nil
	}
	return RuntimeCapabilityClaimResult{}, ErrRuntimeAcquisitionUnavailable
}

func (source *RuntimeAcquisitionSource) claim(
	token *runtimeCapabilityToken,
	attemptToken *runtimeAttemptToken,
) (RuntimeCapabilityClaimResult, error) {
	source.mu.Lock()
	defer source.mu.Unlock()
	capability := source.live[token]
	attempt := source.attempts[attemptToken]
	if capability == nil {
		if outcome := runtimeOutcomeOf(token); outcome != "" {
			return RuntimeCapabilityClaimResult{Outcome: outcome}, nil
		}
		return RuntimeCapabilityClaimResult{}, ErrRuntimeAcquisitionUnavailable
	}
	if attempt == nil || attempt.phase != runtimeAttemptClosed ||
		capability.attempt != attemptToken ||
		!runtimeAttemptContains(attempt, token) {
		return RuntimeCapabilityClaimResult{}, ErrRuntimeAttemptMembership
	}
	if source.config.Clock.Now() >= capability.claimDeadline {
		source.terminalizeLocked(capability, RuntimeCapabilityExpired)
		source.reclaimAttemptIfTerminalLocked(attempt)
		return RuntimeCapabilityClaimResult{Outcome: RuntimeCapabilityExpired}, nil
	}
	source.terminalizeLocked(capability, RuntimeCapabilityClaimed)
	source.reclaimAttemptIfTerminalLocked(attempt)
	return RuntimeCapabilityClaimResult{
		Won:     true,
		Outcome: RuntimeCapabilityClaimed,
	}, nil
}

func runtimeAttemptContains(
	attempt *runtimeAttemptState,
	token *runtimeCapabilityToken,
) bool {
	for _, member := range attempt.members {
		if member == token {
			return true
		}
	}
	return false
}

// CancelOpen atomically cancels every still-open member of the exact instance.
func (source *RuntimeAcquisitionSource) CancelOpen(
	instance RuntimeAttemptInstance,
) error {
	if source == nil || instance.token == nil {
		return ErrRuntimeAcquisitionUnavailable
	}
	if instance.token.source.Load() != source {
		return ErrRuntimeAttemptClosed
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	attempt := source.attempts[instance.token]
	if attempt == nil || attempt.phase != runtimeAttemptClosed {
		return ErrRuntimeAttemptClosed
	}
	for _, member := range attempt.members {
		if capability := source.live[member]; capability != nil {
			source.terminalizeLocked(capability, RuntimeCapabilityCancelled)
		}
	}
	delete(source.attempts, instance.token)
	instance.token.source.Store(nil)
	return nil
}

// FailOpen records a source-owned terminal delivery failure when still open.
func (source *RuntimeAcquisitionSource) FailOpen(
	capability RuntimeAcquisitionCapability,
) (RuntimeCapabilityTerminalOutcome, error) {
	if source == nil || capability.token == nil {
		return "", ErrRuntimeAcquisitionUnavailable
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	state := source.live[capability.token]
	if state == nil {
		outcome := runtimeOutcomeOf(capability.token)
		if outcome != "" {
			return outcome, nil
		}
		return "", ErrRuntimeAcquisitionUnavailable
	}
	if capability.token.source.Load() != source {
		return "", ErrRuntimeAcquisitionUnavailable
	}
	attempt := source.attempts[state.attempt]
	source.terminalizeLocked(state, RuntimeCapabilityFailed)
	if attempt != nil {
		source.reclaimAttemptIfTerminalLocked(attempt)
	}
	return RuntimeCapabilityFailed, nil
}

// ExpireOpen synchronously expires all due capabilities in sequence order.
func (source *RuntimeAcquisitionSource) ExpireOpen() int {
	if source == nil || source.config.Clock == nil {
		return 0
	}
	now := source.config.Clock.Now()
	source.mu.Lock()
	defer source.mu.Unlock()
	expired := 0
	for {
		var candidate *runtimeCapabilityState
		for _, state := range source.live {
			if state.claimDeadline > now ||
				(candidate != nil && candidate.terminalSequence < state.terminalSequence) {
				continue
			}
			candidate = state
		}
		if candidate == nil {
			break
		}
		attempt := source.attempts[candidate.attempt]
		source.terminalizeLocked(candidate, RuntimeCapabilityExpired)
		if attempt != nil {
			source.reclaimAttemptIfTerminalLocked(attempt)
		}
		expired++
	}
	return expired
}

func (source *RuntimeAcquisitionSource) terminalizeLocked(
	capability *runtimeCapabilityState,
	outcome RuntimeCapabilityTerminalOutcome,
) {
	capability.token.outcome.Store(runtimeOutcomeCode(outcome))
	delete(source.live, capability.token)
	tombstone := RuntimeCapabilityTombstone{
		SchemaVersion:    1,
		TerminalSequence: capability.terminalSequence,
		TerminalOutcome:  outcome,
	}
	index := sort.Search(len(source.tombstones), func(index int) bool {
		return source.tombstones[index].TerminalSequence > tombstone.TerminalSequence
	})
	source.tombstones = append(source.tombstones, RuntimeCapabilityTombstone{})
	copy(source.tombstones[index+1:], source.tombstones[index:])
	source.tombstones[index] = tombstone
	if len(source.tombstones) > source.config.Limits.CapabilityTombstoneLimit {
		copy(source.tombstones, source.tombstones[1:])
		source.tombstones = source.tombstones[:len(source.tombstones)-1]
	}
	capability.token.source.Store(nil)
}

func (source *RuntimeAcquisitionSource) reclaimAttemptIfTerminalLocked(
	attempt *runtimeAttemptState,
) {
	if attempt == nil || attempt.phase != runtimeAttemptClosed {
		return
	}
	for _, member := range attempt.members {
		if runtimeOutcomeOf(member) == "" {
			return
		}
	}
	delete(source.attempts, attempt.token)
	attempt.token.source.Store(nil)
}

func runtimeOutcomeCode(outcome RuntimeCapabilityTerminalOutcome) uint32 {
	switch outcome {
	case RuntimeCapabilityClaimed:
		return 1
	case RuntimeCapabilityCancelled:
		return 2
	case RuntimeCapabilityFailed:
		return 3
	case RuntimeCapabilityExpired:
		return 4
	default:
		return 0
	}
}

func runtimeOutcomeOf(token *runtimeCapabilityToken) RuntimeCapabilityTerminalOutcome {
	if token == nil {
		return ""
	}
	switch token.outcome.Load() {
	case 1:
		return RuntimeCapabilityClaimed
	case 2:
		return RuntimeCapabilityCancelled
	case 3:
		return RuntimeCapabilityFailed
	case 4:
		return RuntimeCapabilityExpired
	default:
		return ""
	}
}

// Snapshot returns a copy with no capability or attempt representation.
func (source *RuntimeAcquisitionSource) Snapshot() RuntimeAcquisitionSnapshot {
	if source == nil {
		return RuntimeAcquisitionSnapshot{}
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	return RuntimeAcquisitionSnapshot{
		LiveCapabilities:     len(source.live),
		ActiveAttempts:       len(source.attempts),
		NextTerminalSequence: source.nextTerminalSequence,
		SequenceExhausted:    source.sequenceExhausted,
		Tombstones: append(
			[]RuntimeCapabilityTombstone(nil),
			source.tombstones...,
		),
	}
}

// ExportRestartState closes empty attempts and rejects any live authority.
func (source *RuntimeAcquisitionSource) ExportRestartState() (
	RuntimeAcquisitionRestartState,
	error,
) {
	if source == nil || source.config.Clock == nil {
		return RuntimeAcquisitionRestartState{}, ErrRuntimeAcquisitionUnavailable
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	if source.retired {
		return RuntimeAcquisitionRestartState{}, ErrRuntimeAcquisitionUnavailable
	}
	for token, attempt := range source.attempts {
		if len(attempt.registered) == 0 {
			delete(source.attempts, token)
			token.source.Store(nil)
		}
	}
	if len(source.live) != 0 || len(source.attempts) != 0 {
		return RuntimeAcquisitionRestartState{}, ErrRuntimeAcquisitionUnavailable
	}
	restart := RuntimeAcquisitionRestartState{
		SchemaVersion:        1,
		NextTerminalSequence: source.nextTerminalSequence,
		SequenceExhausted:    source.sequenceExhausted,
		Tombstones: append(
			[]RuntimeCapabilityTombstone(nil),
			source.tombstones...,
		),
	}
	source.retired = true
	return restart, nil
}

// Valid reports only whether an acquisition wrapper contains an issued token.
func (acquisition RuntimeAcquisition) Valid() bool {
	return acquisition.capability.token != nil
}

// AttemptKey returns the exact documentary key bound before issuance.
func (acquisition RuntimeAcquisition) AttemptKey() string {
	return acquisition.attemptKey
}

// Provenance returns an independent copy of the successful runtime source.
func (acquisition RuntimeAcquisition) Provenance() RuntimeAcquisitionProvenance {
	copy := acquisition.provenance
	copy.Words = append([]uint16(nil), copy.Words...)
	copy.WireResponseBytes = append([]byte(nil), copy.WireResponseBytes...)
	return copy
}

// Normalization returns the immutable lossless documentary record.
func (acquisition RuntimeAcquisition) Normalization() RuntimeNormalizationRecord {
	return acquisition.normalization
}

// Capability returns a copy sharing the one private source claim.
func (acquisition RuntimeAcquisition) Capability() RuntimeAcquisitionCapability {
	return acquisition.capability
}

func opaqueRuntimeMarshalError() ([]byte, error) {
	return nil, ErrOpaqueRuntimeState
}

// MarshalJSON rejects serialization of source authority.
func (*RuntimeAcquisitionSource) MarshalJSON() ([]byte, error) {
	return opaqueRuntimeMarshalError()
}

// UnmarshalJSON rejects reconstruction of source authority.
func (*RuntimeAcquisitionSource) UnmarshalJSON([]byte) error {
	return ErrOpaqueRuntimeState
}

// MarshalJSON rejects serialization of open attempt authority.
func (RuntimeAttempt) MarshalJSON() ([]byte, error) {
	return opaqueRuntimeMarshalError()
}

// UnmarshalJSON rejects reconstruction of open attempt authority.
func (*RuntimeAttempt) UnmarshalJSON([]byte) error {
	return ErrOpaqueRuntimeState
}

// MarshalJSON rejects serialization of exact attempt identity.
func (RuntimeAttemptInstance) MarshalJSON() ([]byte, error) {
	return opaqueRuntimeMarshalError()
}

// UnmarshalJSON rejects reconstruction of exact attempt identity.
func (*RuntimeAttemptInstance) UnmarshalJSON([]byte) error {
	return ErrOpaqueRuntimeState
}

// MarshalJSON rejects serialization of acquisition authority.
func (RuntimeAcquisition) MarshalJSON() ([]byte, error) {
	return opaqueRuntimeMarshalError()
}

// UnmarshalJSON rejects reconstruction of acquisition authority.
func (*RuntimeAcquisition) UnmarshalJSON([]byte) error {
	return ErrOpaqueRuntimeState
}

// MarshalJSON rejects serialization of capability authority.
func (RuntimeAcquisitionCapability) MarshalJSON() ([]byte, error) {
	return opaqueRuntimeMarshalError()
}

// UnmarshalJSON rejects reconstruction of capability authority.
func (*RuntimeAcquisitionCapability) UnmarshalJSON([]byte) error {
	return ErrOpaqueRuntimeState
}

// MarshalText rejects textual capability reconstruction.
func (RuntimeAcquisitionCapability) MarshalText() ([]byte, error) {
	return opaqueRuntimeMarshalError()
}

// UnmarshalText rejects textual capability reconstruction.
func (*RuntimeAcquisitionCapability) UnmarshalText([]byte) error {
	return ErrOpaqueRuntimeState
}

// MarshalBinary rejects binary capability reconstruction.
func (RuntimeAcquisitionCapability) MarshalBinary() ([]byte, error) {
	return opaqueRuntimeMarshalError()
}

// UnmarshalBinary rejects binary capability reconstruction.
func (*RuntimeAcquisitionCapability) UnmarshalBinary([]byte) error {
	return ErrOpaqueRuntimeState
}

// GobEncode rejects gob capability reconstruction.
func (RuntimeAcquisitionCapability) GobEncode() ([]byte, error) {
	return opaqueRuntimeMarshalError()
}

// GobDecode rejects gob capability reconstruction.
func (*RuntimeAcquisitionCapability) GobDecode([]byte) error {
	return ErrOpaqueRuntimeState
}

// MarshalText rejects textual attempt-instance reconstruction.
func (RuntimeAttemptInstance) MarshalText() ([]byte, error) {
	return opaqueRuntimeMarshalError()
}

// UnmarshalText rejects textual attempt-instance reconstruction.
func (*RuntimeAttemptInstance) UnmarshalText([]byte) error {
	return ErrOpaqueRuntimeState
}

// MarshalBinary rejects binary attempt-instance reconstruction.
func (RuntimeAttemptInstance) MarshalBinary() ([]byte, error) {
	return opaqueRuntimeMarshalError()
}

// UnmarshalBinary rejects binary attempt-instance reconstruction.
func (*RuntimeAttemptInstance) UnmarshalBinary([]byte) error {
	return ErrOpaqueRuntimeState
}

// GobEncode rejects gob attempt-instance reconstruction.
func (RuntimeAttemptInstance) GobEncode() ([]byte, error) {
	return opaqueRuntimeMarshalError()
}

// GobDecode rejects gob attempt-instance reconstruction.
func (*RuntimeAttemptInstance) GobDecode([]byte) error {
	return ErrOpaqueRuntimeState
}

// MarshalBinary rejects binary acquisition reconstruction.
func (RuntimeAcquisition) MarshalBinary() ([]byte, error) {
	return opaqueRuntimeMarshalError()
}

// UnmarshalBinary rejects binary acquisition reconstruction.
func (*RuntimeAcquisition) UnmarshalBinary([]byte) error {
	return ErrOpaqueRuntimeState
}

// GobEncode rejects gob acquisition reconstruction.
func (RuntimeAcquisition) GobEncode() ([]byte, error) {
	return opaqueRuntimeMarshalError()
}

// GobDecode rejects gob acquisition reconstruction.
func (*RuntimeAcquisition) GobDecode([]byte) error {
	return ErrOpaqueRuntimeState
}
