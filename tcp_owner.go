package modbus

import (
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// ConnectionLimits bounds one socket generation.
type ConnectionLimits struct {
	MaxInFlight   int
	MaxTombstones int
}

type requestKind byte

const (
	requestRead requestKind = iota + 1
	requestDeviceID
)

type requestState byte

const (
	requestReserved requestState = iota + 1
	requestWriteInvoked
	requestWaiting
)

type ownedRequest struct {
	transactionID     uint16
	physicalRequestID uint64
	generation        uint64
	unitID            byte
	kind              requestKind
	function          FunctionCode
	read              ReadRegistersRequest
	deviceID          DeviceIDRequest
	state             requestState
	deadlineOffset    time.Duration
}

// TCPReservation is an immutable handle issued by one connection owner.
type TCPReservation struct {
	owner             *TCPConnectionOwner
	transactionID     uint16
	physicalRequestID uint64
	generation        uint64
	deadlineOffset    time.Duration
}

type reservationWireIdentity struct {
	function FunctionCode
	table    LogicalTable
	offset   uint16
	quantity uint16
}

// TransactionID returns the allocated socket-lifetime transaction identifier.
func (reservation TCPReservation) TransactionID() uint16 {
	return reservation.transactionID
}

// PhysicalRequestID returns the owner-assigned physical request identity.
func (reservation TCPReservation) PhysicalRequestID() uint64 {
	return reservation.physicalRequestID
}

// Generation returns the socket generation in which the request was reserved.
func (reservation TCPReservation) Generation() uint64 {
	return reservation.generation
}

// DeadlineOffset returns the immutable absolute response deadline, or zero.
func (reservation TCPReservation) DeadlineOffset() time.Duration {
	return reservation.deadlineOffset
}

// TransmitResult classifies the result after transport write invocation.
type TransmitResult byte

const (
	TransmitProvableZero TransmitResult = iota + 1
	TransmitPartial
	TransmitIndeterminate
	TransmitCancellationRace
	TransmitAmbiguous
	TransmitComplete
)

// String returns the stable trace spelling for a transmit result.
func (result TransmitResult) String() string {
	switch result {
	case TransmitProvableZero:
		return "provable_zero"
	case TransmitPartial:
		return "partial_write"
	case TransmitIndeterminate:
		return "indeterminate_error"
	case TransmitCancellationRace:
		return "cancellation_race"
	case TransmitAmbiguous:
		return "ambiguous_completion"
	case TransmitComplete:
		return "complete"
	default:
		return fmt.Sprintf("transmit_result_%d", result)
	}
}

// AbandonReason identifies why a full-transmit response waiter was abandoned.
type AbandonReason byte

const (
	AbandonTimeout AbandonReason = iota + 1
	AbandonCancellation
)

// OwnerTransition describes transport action required by an owner transition.
type OwnerTransition struct {
	closeConnection bool
	failed          []TCPReservation
}

// CloseConnection reports whether the current socket must close.
func (transition OwnerTransition) CloseConnection() bool {
	return transition.closeConnection
}

// FailedReservations returns sibling requests terminalized by socket loss.
func (transition OwnerTransition) FailedReservations() []TCPReservation {
	return append([]TCPReservation(nil), transition.failed...)
}

// WireOutcome is the stable outcome attached to a received ADU.
type WireOutcome string

const (
	WireSuccessfulData       WireOutcome = "successful_data"
	WireProtocolException    WireOutcome = "protocol_exception"
	WireMalformedResponse    WireOutcome = "malformed_response"
	WireLateAfterAbandonment WireOutcome = "late_after_abandonment"
	WireDroppedUncorrelated  WireOutcome = "dropped_uncorrelated"
)

// WireResponse retains request-bound response identity and exact bytes.
type WireResponse struct {
	owner             *TCPConnectionOwner
	outcome           WireOutcome
	deliverable       bool
	wireResponseID    uint64
	diagnosticFrameID uint64
	physicalRequestID uint64
	provenance        WireProvenance
	diagnostic        DiagnosticFrameProvenance
	words             []uint16
	deviceIDSegment   *DeviceIDSegment
	bytes             []byte
}

// DiagnosticFrameProvenance identifies an uncorrelated received frame without
// attributing it to a request.
type DiagnosticFrameProvenance struct {
	Endpoint                    string
	ConnectionID                uint64
	ReceivedTransportGeneration uint64
	ActiveTransportGeneration   uint64
	UnitID                      byte
	ReceivedFunction            FunctionCode
}

// WireProvenance binds a wire response to its immutable physical request.
type WireProvenance struct {
	Endpoint            string
	ConnectionID        uint64
	Transport           TransportFamily
	TransportGeneration uint64
	UnitID              byte
	RequestedFunction   FunctionCode
	ReceivedFunction    FunctionCode
	Table               LogicalTable
	Offset              uint16
	Quantity            uint16
	DeviceIDAccess      DeviceIDAccess
	DeviceIDObjectID    byte
}

// Outcome returns the classified response outcome.
func (response WireResponse) Outcome() WireOutcome {
	return response.outcome
}

// Deliverable reports whether the response may satisfy the active waiter.
func (response WireResponse) Deliverable() bool {
	return response.deliverable
}

// WireResponseID returns the request-bound response identity, or zero.
func (response WireResponse) WireResponseID() uint64 {
	return response.wireResponseID
}

// DiagnosticFrameID returns the non-request-bound frame identity, or zero.
func (response WireResponse) DiagnosticFrameID() uint64 {
	return response.diagnosticFrameID
}

// PhysicalRequestID returns the associated physical request identity, or zero.
func (response WireResponse) PhysicalRequestID() uint64 {
	return response.physicalRequestID
}

// Provenance returns the immutable request/response binding.
func (response WireResponse) Provenance() WireProvenance {
	return response.provenance
}

// DiagnosticProvenance returns receipt identity for an uncorrelated frame.
func (response WireResponse) DiagnosticProvenance() DiagnosticFrameProvenance {
	return response.diagnostic
}

// Words returns an independent copy of a successful FC03/FC04 response.
func (response WireResponse) Words() []uint16 {
	return append([]uint16(nil), response.words...)
}

// DeviceIDSegment returns the decoded FC2B segment when applicable.
func (response WireResponse) DeviceIDSegment() (DeviceIDSegment, bool) {
	if response.deviceIDSegment == nil {
		return DeviceIDSegment{}, false
	}
	segment := *response.deviceIDSegment
	segment.objects = cloneDeviceIDObjects(segment.objects)
	return segment, true
}

// Bytes returns an independent copy of the exact received ADU.
func (response WireResponse) Bytes() []byte {
	return cloneBytes(response.bytes)
}

// TCPConnectionOwner owns all transaction state for one live TCP socket.
type TCPConnectionOwner struct {
	mu                    sync.Mutex
	endpoint              string
	connectionID          uint64
	generation            uint64
	limits                ConnectionLimits
	closed                bool
	retired               bool
	nextTransactionID     uint16
	nextPhysicalRequestID uint64
	nextWireResponseID    uint64
	nextDiagnosticFrameID uint64
	inFlight              map[uint16]*ownedRequest
	tombstones            map[uint16]ownedRequest
	closingTombstone      *ownedRequest
	earlyCompletions      map[uint64]uint16
	pendingFailures       []TCPReservation
	generationAllocator   func() uint64
	boundTransport        *TCPTransport
	pool                  *TCPEndpointPool
}

// newTCPConnectionOwner constructs one bounded socket-generation owner.
func newTCPConnectionOwner(
	endpoint string,
	generation uint64,
	limits ConnectionLimits,
) (*TCPConnectionOwner, error) {
	if endpoint == "" ||
		generation == 0 ||
		limits.MaxInFlight <= 0 ||
		limits.MaxInFlight > 1<<16 ||
		limits.MaxTombstones <= 0 ||
		limits.MaxTombstones > 1<<16 {
		return nil, protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"connection_limits",
			-1,
		)
	}
	return &TCPConnectionOwner{
		endpoint:              endpoint,
		generation:            generation,
		limits:                limits,
		nextPhysicalRequestID: 1,
		nextWireResponseID:    1,
		nextDiagnosticFrameID: 1,
		inFlight:              make(map[uint16]*ownedRequest),
		tombstones:            make(map[uint16]ownedRequest),
		earlyCompletions:      make(map[uint64]uint16),
	}, nil
}

// ReserveRead reserves one identifier for a validated FC03/FC04 request.
func (owner *TCPConnectionOwner) ReserveRead(
	unitID byte,
	request ReadRegistersRequest,
) (TCPReservation, error) {
	return owner.reserveReadUntil(unitID, request, 0)
}

func (owner *TCPConnectionOwner) reserveReadUntil(
	unitID byte,
	request ReadRegistersRequest,
	deadlineOffset time.Duration,
) (TCPReservation, error) {
	if err := validateReadRegistersRequest(request); err != nil {
		return TCPReservation{}, err
	}
	if owner == nil {
		return TCPReservation{}, invalidOwner()
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	return owner.reserve(
		unitID,
		requestRead,
		request,
		DeviceIDRequest{},
		deadlineOffset,
	)
}

// ReserveDeviceID reserves one identifier for a validated FC2B/MEI0E request.
func (owner *TCPConnectionOwner) ReserveDeviceID(
	unitID byte,
	request DeviceIDRequest,
) (TCPReservation, error) {
	return owner.reserveDeviceIDUntil(unitID, request, 0)
}

func (owner *TCPConnectionOwner) reserveDeviceIDUntil(
	unitID byte,
	request DeviceIDRequest,
	deadlineOffset time.Duration,
) (TCPReservation, error) {
	if err := validateDeviceIDRequest(request); err != nil {
		return TCPReservation{}, err
	}
	if owner == nil {
		return TCPReservation{}, invalidOwner()
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	return owner.reserve(
		unitID,
		requestDeviceID,
		ReadRegistersRequest{},
		request,
		deadlineOffset,
	)
}

func invalidOwner() error {
	return protocolError(
		ErrorInvalidRequest,
		0,
		0,
		"connection_owner",
		-1,
	)
}

func (owner *TCPConnectionOwner) reserve(
	unitID byte,
	kind requestKind,
	read ReadRegistersRequest,
	deviceID DeviceIDRequest,
	deadlineOffset time.Duration,
) (TCPReservation, error) {
	if owner == nil || owner.closed || owner.retired {
		return TCPReservation{}, protocolError(
			ErrorInvalidRange,
			0,
			0,
			"connection_closed",
			-1,
		)
	}
	if unitID == 0 || unitID > 247 {
		return TCPReservation{}, protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"unit_id",
			-1,
		)
	}
	if len(owner.inFlight)+len(owner.earlyCompletions) >=
		owner.limits.MaxInFlight {
		return TCPReservation{}, protocolError(
			ErrorInvalidRange,
			0,
			0,
			"in_flight",
			-1,
		)
	}
	transactionID, ok := owner.allocateTransactionID()
	if !ok {
		owner.closed = true
		return TCPReservation{}, protocolError(
			ErrorInvalidRange,
			0,
			0,
			"transaction_identifiers",
			-1,
		)
	}
	if owner.nextPhysicalRequestID == 0 {
		owner.closed = true
		return TCPReservation{}, protocolError(
			ErrorInvalidRange,
			0,
			0,
			"physical_request_id",
			-1,
		)
	}
	physicalRequestID := owner.nextPhysicalRequestID
	owner.nextPhysicalRequestID++
	function := read.Function()
	if kind == requestDeviceID {
		function = FunctionEncapsulatedInterface
	}
	owned := &ownedRequest{
		transactionID:     transactionID,
		physicalRequestID: physicalRequestID,
		generation:        owner.generation,
		unitID:            unitID,
		kind:              kind,
		function:          function,
		read:              read,
		deviceID:          deviceID,
		state:             requestReserved,
		deadlineOffset:    deadlineOffset,
	}
	owner.inFlight[transactionID] = owned
	return TCPReservation{
		owner:             owner,
		transactionID:     transactionID,
		physicalRequestID: physicalRequestID,
		generation:        owner.generation,
		deadlineOffset:    deadlineOffset,
	}, nil
}

func (owner *TCPConnectionOwner) allocateTransactionID() (uint16, bool) {
	for attempts := 0; attempts < 1<<16; attempts++ {
		candidate := owner.nextTransactionID
		owner.nextTransactionID++
		if _, exists := owner.inFlight[candidate]; exists {
			continue
		}
		if _, tombstoned := owner.tombstones[candidate]; tombstoned {
			continue
		}
		return candidate, true
	}
	return 0, false
}

// CancelBeforeWrite releases a reservation before transport invocation.
func (owner *TCPConnectionOwner) CancelBeforeWrite(
	reservation TCPReservation,
) error {
	if owner == nil {
		return invalidOwner()
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	request, err := owner.requestFor(reservation, requestReserved)
	if err != nil {
		return err
	}
	delete(owner.inFlight, request.transactionID)
	owner.rewindAllocator(request.transactionID)
	return nil
}

func (owner *TCPConnectionOwner) replaceReservedRead(
	reservation TCPReservation,
	request ReadRegistersRequest,
) error {
	if err := validateReadRegistersRequest(request); err != nil {
		return err
	}
	if owner == nil {
		return invalidOwner()
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	owned, err := owner.requestFor(reservation, requestReserved)
	if err != nil {
		return err
	}
	if owned.kind != requestRead ||
		owned.read.Function() != request.Function() {
		return protocolError(
			ErrorInvalidRequest,
			request.Function(),
			0,
			"reserved_read_identity",
			-1,
		)
	}
	owned.read = request
	return nil
}

// MarkWriteInvoked crosses the cancellation-safe write boundary.
func (owner *TCPConnectionOwner) MarkWriteInvoked(
	reservation TCPReservation,
) error {
	if owner == nil {
		return invalidOwner()
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	request, err := owner.requestFor(reservation, requestReserved)
	if err != nil {
		return err
	}
	request.state = requestWriteInvoked
	return nil
}

// RecordTransmit applies the exact result of an invoked transport write.
func (owner *TCPConnectionOwner) RecordTransmit(
	reservation TCPReservation,
	result TransmitResult,
) (OwnerTransition, error) {
	return owner.recordTransmitUntil(
		reservation,
		result,
		reservation.deadlineOffset,
	)
}

func (owner *TCPConnectionOwner) recordTransmitUntil(
	reservation TCPReservation,
	result TransmitResult,
	responseDeadlineOffset time.Duration,
) (OwnerTransition, error) {
	if owner == nil {
		return OwnerTransition{}, invalidOwner()
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	transactionID, completedEarly := owner.earlyCompletions[reservation.physicalRequestID]
	if completedEarly {
		if reservation.owner != owner ||
			reservation.generation != owner.generation ||
			reservation.transactionID != transactionID ||
			result != TransmitComplete {
			owner.closed = true
			return OwnerTransition{closeConnection: true}, protocolError(
				ErrorInvalidRequest,
				0,
				0,
				"early_response_transmit_result",
				-1,
			)
		}
		delete(owner.earlyCompletions, reservation.physicalRequestID)
		return OwnerTransition{}, nil
	}
	request, err := owner.requestFor(reservation, requestWriteInvoked)
	if err != nil {
		return OwnerTransition{}, err
	}
	switch result {
	case TransmitProvableZero:
		delete(owner.inFlight, request.transactionID)
		owner.rewindAllocator(request.transactionID)
		return OwnerTransition{}, nil
	case TransmitComplete:
		if responseDeadlineOffset > 0 {
			request.deadlineOffset = responseDeadlineOffset
		}
		request.state = requestWaiting
		return OwnerTransition{}, nil
	case TransmitPartial,
		TransmitIndeterminate,
		TransmitCancellationRace,
		TransmitAmbiguous:
		if !owner.addTombstone(*request) {
			copy := *request
			owner.closingTombstone = &copy
		}
		failed := owner.failAllExcept(request.transactionID)
		delete(owner.inFlight, request.transactionID)
		owner.closed = true
		return OwnerTransition{
			closeConnection: true,
			failed:          failed,
		}, nil
	default:
		return OwnerTransition{}, protocolError(
			ErrorInvalidRequest,
			request.function,
			0,
			"transmit_result",
			-1,
		)
	}
}

func (owner *TCPConnectionOwner) abandonExpired(
	nowOffset time.Duration,
) ([]TCPReservation, OwnerTransition, error) {
	if owner == nil || nowOffset < 0 {
		return nil, OwnerTransition{}, invalidOwner()
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	expired := make([]TCPReservation, 0)
	candidates := make([]*ownedRequest, 0)
	for _, request := range owner.inFlight {
		if request.state != requestWaiting ||
			request.deadlineOffset <= 0 ||
			request.deadlineOffset > nowOffset {
			continue
		}
		candidates = append(candidates, request)
	}
	sort.Slice(candidates, func(first, second int) bool {
		if candidates[first].deadlineOffset !=
			candidates[second].deadlineOffset {
			return candidates[first].deadlineOffset <
				candidates[second].deadlineOffset
		}
		if candidates[first].physicalRequestID !=
			candidates[second].physicalRequestID {
			return candidates[first].physicalRequestID <
				candidates[second].physicalRequestID
		}
		return candidates[first].transactionID <
			candidates[second].transactionID
	})
	for _, request := range candidates {
		transactionID := request.transactionID
		reservation := TCPReservation{
			owner:             owner,
			transactionID:     request.transactionID,
			physicalRequestID: request.physicalRequestID,
			generation:        request.generation,
			deadlineOffset:    request.deadlineOffset,
		}
		expired = append(expired, reservation)
		if len(owner.tombstones) >= owner.limits.MaxTombstones {
			copy := *request
			owner.closingTombstone = &copy
			delete(owner.inFlight, transactionID)
			failed := owner.failAll()
			owner.pendingFailures = append(
				owner.pendingFailures,
				failed...,
			)
			owner.closed = true
			return expired, OwnerTransition{
					closeConnection: true,
					failed:          failed,
				}, protocolError(
					ErrorInvalidRange,
					request.function,
					0,
					"tombstones",
					-1,
				)
		}
		owner.addTombstone(*request)
		delete(owner.inFlight, transactionID)
	}
	return expired, OwnerTransition{}, nil
}

func (owner *TCPConnectionOwner) responseDeadline(
	reservation TCPReservation,
) (time.Duration, bool) {
	if owner == nil || reservation.owner != owner {
		return 0, false
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	request := owner.inFlight[reservation.transactionID]
	if request == nil ||
		request.physicalRequestID != reservation.physicalRequestID ||
		request.generation != reservation.generation ||
		request.state != requestWaiting ||
		request.deadlineOffset <= 0 {
		return 0, false
	}
	return request.deadlineOffset, true
}

// AbandonResponseWait tombstones a fully transmitted request.
func (owner *TCPConnectionOwner) AbandonResponseWait(
	reservation TCPReservation,
	reason AbandonReason,
) error {
	transition, err := owner.AbandonAfterWrite(reservation, reason)
	if !transition.CloseConnection() {
		return err
	}
	return errors.Join(err, owner.closeBoundTransport())
}

// AbandonAfterWrite atomically handles cancellation after write invocation.
func (owner *TCPConnectionOwner) AbandonAfterWrite(
	reservation TCPReservation,
	reason AbandonReason,
) (OwnerTransition, error) {
	if owner == nil {
		return OwnerTransition{}, invalidOwner()
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if reason != AbandonTimeout && reason != AbandonCancellation {
		return OwnerTransition{}, protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"abandon_reason",
			-1,
		)
	}
	request, err := owner.requestFor(reservation, requestWaiting)
	if err == nil {
		if len(owner.tombstones) >= owner.limits.MaxTombstones {
			copy := *request
			owner.closingTombstone = &copy
			owner.pendingFailures = append(
				owner.pendingFailures,
				owner.failAllExcept(request.transactionID)...,
			)
			delete(owner.inFlight, request.transactionID)
			owner.closed = true
			return OwnerTransition{closeConnection: true}, protocolError(
				ErrorInvalidRange,
				request.function,
				0,
				"tombstones",
				-1,
			)
		}
		owner.addTombstone(*request)
		delete(owner.inFlight, request.transactionID)
		return OwnerTransition{}, nil
	}
	request, err = owner.requestFor(reservation, requestWriteInvoked)
	if err != nil {
		return OwnerTransition{}, err
	}
	if !owner.addTombstone(*request) {
		copy := *request
		owner.closingTombstone = &copy
	}
	failed := owner.failAllExcept(request.transactionID)
	delete(owner.inFlight, request.transactionID)
	owner.closed = true
	return OwnerTransition{
		closeConnection: true,
		failed:          failed,
	}, nil
}

func (owner *TCPConnectionOwner) failAllExcept(
	excludedTransactionID uint16,
) []TCPReservation {
	failed := make([]TCPReservation, 0, len(owner.inFlight))
	for _, transactionID := range owner.sortedInFlightTransactionIDs() {
		if transactionID == excludedTransactionID {
			continue
		}
		request := owner.inFlight[transactionID]
		failed = append(failed, TCPReservation{
			owner:             owner,
			transactionID:     transactionID,
			physicalRequestID: request.physicalRequestID,
			generation:        request.generation,
			deadlineOffset:    request.deadlineOffset,
		})
		delete(owner.inFlight, transactionID)
	}
	return failed
}

func (owner *TCPConnectionOwner) failAll() []TCPReservation {
	failed := make([]TCPReservation, 0, len(owner.inFlight))
	for _, transactionID := range owner.sortedInFlightTransactionIDs() {
		request := owner.inFlight[transactionID]
		failed = append(failed, TCPReservation{
			owner:             owner,
			transactionID:     transactionID,
			physicalRequestID: request.physicalRequestID,
			generation:        request.generation,
			deadlineOffset:    request.deadlineOffset,
		})
		delete(owner.inFlight, transactionID)
	}
	return failed
}

func (owner *TCPConnectionOwner) sortedInFlightTransactionIDs() []uint16 {
	transactionIDs := make([]uint16, 0, len(owner.inFlight))
	for transactionID := range owner.inFlight {
		transactionIDs = append(transactionIDs, transactionID)
	}
	sort.Slice(transactionIDs, func(first, second int) bool {
		firstRequest := owner.inFlight[transactionIDs[first]]
		secondRequest := owner.inFlight[transactionIDs[second]]
		if firstRequest.physicalRequestID !=
			secondRequest.physicalRequestID {
			return firstRequest.physicalRequestID <
				secondRequest.physicalRequestID
		}
		return transactionIDs[first] < transactionIDs[second]
	})
	return transactionIDs
}

// DrainFailedReservations returns failures caused by an error-only close path.
func (owner *TCPConnectionOwner) DrainFailedReservations() []TCPReservation {
	if owner == nil {
		return nil
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	failed := append([]TCPReservation(nil), owner.pendingFailures...)
	owner.pendingFailures = nil
	return failed
}

func (owner *TCPConnectionOwner) addTombstone(request ownedRequest) bool {
	if len(owner.tombstones) < owner.limits.MaxTombstones {
		owner.tombstones[request.transactionID] = request
		return true
	}
	return false
}

func (owner *TCPConnectionOwner) rewindAllocator(transactionID uint16) {
	if uint16(owner.nextTransactionID-1) == transactionID {
		owner.nextTransactionID = transactionID
	}
}

func (owner *TCPConnectionOwner) requestFor(
	reservation TCPReservation,
	state requestState,
) (*ownedRequest, error) {
	if owner == nil ||
		reservation.owner != owner ||
		reservation.generation != owner.generation {
		return nil, protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"reservation_owner",
			-1,
		)
	}
	request, ok := owner.inFlight[reservation.transactionID]
	if !ok ||
		request.physicalRequestID != reservation.physicalRequestID ||
		request.state != state {
		return nil, protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"reservation_state",
			-1,
		)
	}
	return request, nil
}

func (owner *TCPConnectionOwner) matchesReadReservation(
	reservation TCPReservation,
	endpoint string,
	generation uint64,
	unitID byte,
	request ReadRegistersRequest,
) bool {
	if owner == nil {
		return false
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	owned, err := owner.requestFor(reservation, requestReserved)
	return err == nil &&
		owner.endpoint == endpoint &&
		owner.generation == generation &&
		owned.unitID == unitID &&
		owned.kind == requestRead &&
		owned.read == request
}

func (owner *TCPConnectionOwner) encodeReservation(
	reservation TCPReservation,
) ([]byte, reservationWireIdentity, error) {
	if owner == nil {
		return nil, reservationWireIdentity{}, invalidOwner()
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	request, err := owner.requestFor(reservation, requestReserved)
	if err != nil {
		return nil, reservationWireIdentity{}, err
	}
	identity := reservationWireIdentity{function: request.function}
	if request.kind == requestRead {
		identity.table = request.read.Table()
		identity.offset = request.read.Offset()
		identity.quantity = request.read.Quantity()
		adu, encodeErr := EncodeTCPReadADU(
			request.transactionID,
			request.unitID,
			request.read,
		)
		return adu, identity, encodeErr
	}
	adu, encodeErr := EncodeTCPDeviceIDAccessADU(
		request.transactionID,
		request.unitID,
		request.deviceID,
	)
	return adu, identity, encodeErr
}

// Generation returns the current socket generation.
func (owner *TCPConnectionOwner) Generation() uint64 {
	if owner == nil {
		return 0
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	return owner.generation
}

func (owner *TCPConnectionOwner) bindTransport(
	transport *TCPTransport,
) (uint64, error) {
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.closed || owner.retired || owner.boundTransport != nil {
		return 0, protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"transport_binding",
			-1,
		)
	}
	owner.boundTransport = transport
	return owner.generation, nil
}

func (owner *TCPConnectionOwner) loseTransport(
	transport *TCPTransport,
) OwnerTransition {
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.boundTransport != transport {
		return OwnerTransition{}
	}
	owner.boundTransport = nil
	failed := owner.failAll()
	owner.closed = true
	if owner.pool != nil {
		owner.retired = true
	}
	owner.tombstones = make(map[uint16]ownedRequest)
	owner.closingTombstone = nil
	owner.earlyCompletions = make(map[uint64]uint16)
	return OwnerTransition{closeConnection: true, failed: failed}
}

func (owner *TCPConnectionOwner) transportCurrent(
	transport *TCPTransport,
	generation uint64,
) bool {
	owner.mu.Lock()
	defer owner.mu.Unlock()
	return !owner.closed &&
		!owner.retired &&
		owner.boundTransport == transport &&
		owner.generation == generation
}

// Correlate validates one received ADU against active or abandoned requests.
func (owner *TCPConnectionOwner) Correlate(
	generation uint64,
	adu TCPADU,
) (WireResponse, error) {
	if owner == nil {
		return WireResponse{outcome: WireDroppedUncorrelated}, nil
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if generation != owner.generation {
		return owner.newDiagnosticFrame(generation, adu)
	}
	if owner.nextWireResponseID == 0 {
		owner.closed = true
		response, diagnosticErr := owner.newDiagnosticFrame(generation, adu)
		return response, errors.Join(diagnosticErr, protocolError(
			ErrorInvalidRange,
			0,
			0,
			"wire_response_id",
			-1,
		))
	}
	request, active := owner.inFlight[adu.transactionID]
	if active && !owner.closed {
		if (request.state != requestWaiting &&
			request.state != requestWriteInvoked) ||
			!candidateMatches(*request, adu) {
			return owner.newDiagnosticFrame(generation, adu)
		}
		response, err := owner.correlateActive(request, adu)
		if request.state == requestWriteInvoked {
			owner.earlyCompletions[request.physicalRequestID] =
				request.transactionID
		}
		return response, err
	}
	tombstone, abandoned := owner.tombstones[adu.transactionID]
	if !abandoned &&
		owner.closingTombstone != nil &&
		owner.closingTombstone.transactionID == adu.transactionID {
		tombstone = *owner.closingTombstone
		abandoned = true
	}
	if !abandoned || !candidateMatches(tombstone, adu) {
		return owner.newDiagnosticFrame(generation, adu)
	}
	decoded, decodeErr := validateOwnedResponse(tombstone, adu.pdu)
	outcome := WireLateAfterAbandonment
	if protocolErr, ok := decodeErr.(*ProtocolError); ok &&
		protocolErr.Kind == ErrorMalformedResponse {
		outcome = WireMalformedResponse
	}
	response := owner.newWireResponse(
		outcome,
		false,
		tombstone,
		adu,
		decoded,
	)
	if outcome == WireMalformedResponse {
		return response, decodeErr
	}
	return response, nil
}

func candidateMatches(request ownedRequest, adu TCPADU) bool {
	if adu.unitID != request.unitID || len(adu.pdu) == 0 {
		return false
	}
	received := FunctionCode(adu.pdu[0])
	return received == request.function ||
		received == request.function|0x80
}

func (owner *TCPConnectionOwner) correlateActive(
	request *ownedRequest,
	adu TCPADU,
) (WireResponse, error) {
	decoded, decodeErr := validateOwnedResponse(*request, adu.pdu)
	delete(owner.inFlight, request.transactionID)
	if decodeErr == nil {
		return owner.newWireResponse(
			WireSuccessfulData,
			true,
			*request,
			adu,
			decoded,
		), nil
	}
	protocolErr, ok := decodeErr.(*ProtocolError)
	if ok && protocolErr.Kind == ErrorExceptionResponse {
		return owner.newWireResponse(
			WireProtocolException,
			false,
			*request,
			adu,
			decodedOwnedResponse{},
		), decodeErr
	}
	return owner.newWireResponse(
		WireMalformedResponse,
		false,
		*request,
		adu,
		decodedOwnedResponse{},
	), decodeErr
}

type decodedOwnedResponse struct {
	words   []uint16
	segment *DeviceIDSegment
}

func validateOwnedResponse(
	request ownedRequest,
	pdu []byte,
) (decodedOwnedResponse, error) {
	switch request.kind {
	case requestRead:
		response, err := DecodeReadRegistersResponse(request.read, pdu)
		return decodedOwnedResponse{words: response.Words}, err
	case requestDeviceID:
		segment, err := DecodeDeviceIDSegment(request.deviceID, pdu)
		if err != nil {
			return decodedOwnedResponse{}, err
		}
		return decodedOwnedResponse{segment: &segment}, nil
	default:
		return decodedOwnedResponse{}, protocolError(
			ErrorMalformedResponse,
			request.function,
			FunctionCode(pdu[0]),
			"request_kind",
			-1,
		)
	}
}

func (owner *TCPConnectionOwner) newWireResponse(
	outcome WireOutcome,
	deliverable bool,
	request ownedRequest,
	adu TCPADU,
	decoded decodedOwnedResponse,
) WireResponse {
	wireResponseID := owner.nextWireResponseID
	owner.nextWireResponseID++
	return WireResponse{
		owner:             owner,
		outcome:           outcome,
		deliverable:       deliverable,
		wireResponseID:    wireResponseID,
		physicalRequestID: request.physicalRequestID,
		provenance:        owner.wireProvenance(request, adu),
		words:             append([]uint16(nil), decoded.words...),
		deviceIDSegment:   cloneDeviceIDSegment(decoded.segment),
		bytes:             cloneBytes(adu.raw),
	}
}

func cloneDeviceIDSegment(segment *DeviceIDSegment) *DeviceIDSegment {
	if segment == nil {
		return nil
	}
	copy := *segment
	copy.objects = cloneDeviceIDObjects(copy.objects)
	return &copy
}

func (owner *TCPConnectionOwner) wireProvenance(
	request ownedRequest,
	adu TCPADU,
) WireProvenance {
	provenance := WireProvenance{
		Endpoint:            owner.endpoint,
		ConnectionID:        owner.connectionID,
		Transport:           TransportTCP,
		TransportGeneration: request.generation,
		UnitID:              request.unitID,
		RequestedFunction:   request.function,
	}
	if len(adu.pdu) > 0 {
		provenance.ReceivedFunction = FunctionCode(adu.pdu[0])
	}
	if request.kind == requestRead {
		provenance.Table = request.read.Table()
		provenance.Offset = request.read.Offset()
		provenance.Quantity = request.read.Quantity()
	} else {
		provenance.DeviceIDAccess = request.deviceID.Access()
		provenance.DeviceIDObjectID = request.deviceID.ObjectID()
	}
	return provenance
}

func (owner *TCPConnectionOwner) newDiagnosticFrame(
	receivedGeneration uint64,
	adu TCPADU,
) (WireResponse, error) {
	if owner.nextDiagnosticFrameID == 0 {
		owner.closed = true
		return WireResponse{outcome: WireDroppedUncorrelated}, protocolError(
			ErrorInvalidRange,
			0,
			0,
			"diagnostic_frame_id",
			-1,
		)
	}
	id := owner.nextDiagnosticFrameID
	owner.nextDiagnosticFrameID++
	provenance := DiagnosticFrameProvenance{
		Endpoint:                    owner.endpoint,
		ConnectionID:                owner.connectionID,
		ReceivedTransportGeneration: receivedGeneration,
		ActiveTransportGeneration:   owner.generation,
		UnitID:                      adu.unitID,
	}
	if len(adu.pdu) > 0 {
		provenance.ReceivedFunction = FunctionCode(adu.pdu[0])
	}
	return WireResponse{
		owner:             owner,
		outcome:           WireDroppedUncorrelated,
		diagnosticFrameID: id,
		diagnostic:        provenance,
		bytes:             cloneBytes(adu.raw),
	}, nil
}

// Closed reports whether the current generation must no longer be used.
func (owner *TCPConnectionOwner) Closed() bool {
	if owner == nil {
		return true
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	return owner.closed
}

func (owner *TCPConnectionOwner) hasTombstones() bool {
	if owner == nil {
		return false
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	return len(owner.tombstones) > 0 || owner.closingTombstone != nil
}

// Close invalidates the current socket generation and discards live state.
func (owner *TCPConnectionOwner) Close() {
	if owner == nil {
		return
	}
	owner.mu.Lock()
	transport := owner.boundTransport
	failed := owner.failAll()
	owner.closed = true
	owner.pendingFailures = append(owner.pendingFailures, failed...)
	owner.tombstones = make(map[uint16]ownedRequest)
	owner.closingTombstone = nil
	owner.earlyCompletions = make(map[uint64]uint16)
	owner.boundTransport = nil
	owner.mu.Unlock()
	if transport != nil {
		_ = transport.closeDetached()
	}
}

func (owner *TCPConnectionOwner) retire() {
	if owner == nil {
		return
	}
	owner.mu.Lock()
	transport := owner.boundTransport
	owner.boundTransport = nil
	owner.pool = nil
	owner.retired = true
	owner.closed = true
	owner.pendingFailures = append(owner.pendingFailures, owner.failAll()...)
	owner.tombstones = make(map[uint16]ownedRequest)
	owner.closingTombstone = nil
	owner.earlyCompletions = make(map[uint64]uint16)
	owner.mu.Unlock()
	if transport != nil {
		_ = transport.closeDetached()
	}
}

func (owner *TCPConnectionOwner) releasePoolSlot() {
	if owner == nil {
		return
	}
	owner.mu.Lock()
	pool := owner.pool
	connectionID := owner.connectionID
	owner.pool = nil
	owner.mu.Unlock()
	if pool != nil {
		pool.releaseLostConnection(connectionID, owner)
	}
}

func (owner *TCPConnectionOwner) closeBoundTransport() error {
	if owner == nil {
		return invalidOwner()
	}
	owner.mu.Lock()
	transport := owner.boundTransport
	owner.mu.Unlock()
	if transport == nil {
		return nil
	}
	_, err := transport.closeTerminal()
	return err
}

// Reconnect discards socket-scoped state and increments the generation.
func (owner *TCPConnectionOwner) Reconnect() uint64 {
	if owner == nil {
		return 0
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if !owner.closed || owner.retired || owner.boundTransport != nil {
		return owner.generation
	}
	nextGeneration := owner.generation + 1
	if owner.generationAllocator != nil {
		nextGeneration = owner.generationAllocator()
	}
	if nextGeneration == 0 {
		return owner.generation
	}
	owner.generation = nextGeneration
	owner.closed = false
	owner.nextTransactionID = 0
	owner.inFlight = make(map[uint16]*ownedRequest)
	owner.tombstones = make(map[uint16]ownedRequest)
	owner.closingTombstone = nil
	owner.earlyCompletions = make(map[uint64]uint16)
	return owner.generation
}
