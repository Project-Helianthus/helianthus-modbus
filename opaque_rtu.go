package modbus

import (
	"errors"
	"sync"
)

// The fixed vendor function family is deliberately opaque at this transport
// layer. Callers may select one of the admitted wire functions but cannot
// provide an unbounded caller-selected escape hatch.
const (
	FunctionVendor100 FunctionCode = 100
	FunctionVendor101 FunctionCode = 101
	FunctionVendor102 FunctionCode = 102
)

// OpaqueVendorRequest is one bounded, uninterpreted vendor PDU request.
type OpaqueVendorRequest struct {
	function FunctionCode
	payload  []byte
}

// NewOpaqueVendorRequest validates the fixed opaque vendor function family.
func NewOpaqueVendorRequest(
	function FunctionCode,
	payload []byte,
) (OpaqueVendorRequest, error) {
	if !isOpaqueVendorFunction(function) {
		return OpaqueVendorRequest{}, protocolError(
			ErrorUnsupportedOperation,
			function,
			0,
			"vendor_function",
			0,
		)
	}
	if len(payload) > MaxPDUSize-1 {
		return OpaqueVendorRequest{}, protocolError(
			ErrorInvalidRange,
			function,
			0,
			"vendor_payload_length",
			len(payload),
		)
	}
	return OpaqueVendorRequest{
		function: function,
		payload:  cloneBytes(payload),
	}, nil
}

// Function returns the fixed vendor function code.
func (request OpaqueVendorRequest) Function() FunctionCode {
	return request.function
}

// Payload returns an independent copy of opaque PDU bytes.
func (request OpaqueVendorRequest) Payload() []byte {
	return cloneBytes(request.payload)
}

// EncodePDU returns one exact opaque PDU after revalidating its bounds.
func (request OpaqueVendorRequest) EncodePDU() ([]byte, error) {
	if _, err := NewOpaqueVendorRequest(request.function, request.payload); err != nil {
		return nil, err
	}
	pdu := make([]byte, 1+len(request.payload))
	pdu[0] = byte(request.function)
	copy(pdu[1:], request.payload)
	return pdu, nil
}

// EncodeRTUOpaqueADU encodes one bounded opaque vendor RTU request.
func EncodeRTUOpaqueADU(
	unitID byte,
	request OpaqueVendorRequest,
) ([]byte, error) {
	pdu, err := request.EncodePDU()
	if err != nil {
		return nil, err
	}
	return encodeRTUADU(unitID, pdu)
}

// RTUOpaqueResponseADU retains an exact opaque response and validated framing.
type RTUOpaqueResponseADU struct {
	adu     RTUADU
	payload []byte
}

// Bytes returns an independent copy of the complete RTU response frame.
func (response RTUOpaqueResponseADU) Bytes() []byte {
	return response.adu.Bytes()
}

// Payload returns an independent copy of opaque response PDU bytes.
func (response RTUOpaqueResponseADU) Payload() []byte {
	return cloneBytes(response.payload)
}

// DecodeRTUOpaqueResponseADU validates unit, CRC, response function, and the
// exact exception shape without interpreting vendor payload bytes.
func DecodeRTUOpaqueResponseADU(
	expectedUnitID byte,
	request OpaqueVendorRequest,
	frame []byte,
) (RTUOpaqueResponseADU, error) {
	if expectedUnitID == 0 || expectedUnitID > 247 {
		return RTUOpaqueResponseADU{}, protocolError(
			ErrorInvalidRequest,
			request.function,
			0,
			"unit_id",
			0,
		)
	}
	if _, err := NewOpaqueVendorRequest(request.function, request.payload); err != nil {
		return RTUOpaqueResponseADU{}, err
	}
	adu, err := decodeRTUADU(frame)
	response := RTUOpaqueResponseADU{adu: adu}
	if err != nil {
		return response, err
	}
	if adu.unitID != expectedUnitID {
		return response, protocolError(
			ErrorMalformedResponse,
			request.function,
			0,
			"unit_id",
			0,
		)
	}
	if len(adu.pdu) == 0 {
		return response, protocolError(
			ErrorMalformedResponse,
			request.function,
			0,
			"function",
			0,
		)
	}
	received := FunctionCode(adu.pdu[0])
	if received == request.function|0x80 {
		if len(adu.pdu) != 2 {
			return response, protocolError(
				ErrorMalformedResponse,
				request.function,
				received,
				"exception_length",
				len(adu.pdu),
			)
		}
		exception := protocolError(
			ErrorExceptionResponse,
			request.function,
			received,
			"exception_code",
			1,
		)
		exception.ExceptionCode = adu.pdu[1]
		return response, exception
	}
	if received != request.function {
		return response, protocolError(
			ErrorMalformedResponse,
			request.function,
			received,
			"function_mismatch",
			0,
		)
	}
	response.payload = cloneBytes(adu.pdu[1:])
	return response, nil
}

func isOpaqueVendorFunction(function FunctionCode) bool {
	switch function {
	case FunctionVendor100, FunctionVendor101, FunctionVendor102:
		return true
	default:
		return false
	}
}

// OpaqueVendorRetryPolicy permits retries only after a higher layer explicitly
// declares the request replay-safe. Its default permits exactly one attempt.
type OpaqueVendorRetryPolicy struct {
	maxAttempts uint8
	replaySafe  bool
}

// DefaultOpaqueVendorRetryPolicy denies implicit retry of opaque requests.
func DefaultOpaqueVendorRetryPolicy() OpaqueVendorRetryPolicy {
	return OpaqueVendorRetryPolicy{maxAttempts: 1}
}

// NewOpaqueVendorRetryPolicy validates a bounded opt-in retry policy.
func NewOpaqueVendorRetryPolicy(
	maxAttempts uint8,
	replaySafe bool,
) (OpaqueVendorRetryPolicy, error) {
	if maxAttempts == 0 || maxAttempts > 3 || (maxAttempts > 1 && !replaySafe) {
		return OpaqueVendorRetryPolicy{}, protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"opaque_vendor_retry_policy",
			-1,
		)
	}
	return OpaqueVendorRetryPolicy{
		maxAttempts: maxAttempts,
		replaySafe:  replaySafe,
	}, nil
}

// MaxAttempts returns the bounded number of allowed attempts.
func (policy OpaqueVendorRetryPolicy) MaxAttempts() uint8 {
	return policy.maxAttempts
}

// ReplaySafe reports the explicit higher-layer replay declaration.
func (policy OpaqueVendorRetryPolicy) ReplaySafe() bool {
	return policy.replaySafe
}

var errOpaqueVendorTransactionState = errors.New("invalid opaque vendor transaction state")

// OpaqueVendorTransaction is an offline, generic single-flight RTU response
// owner. It delivers each matching framed response to a higher layer, which
// alone decides whether one is intermediate or terminal. It never interprets
// opaque payload bytes.
type OpaqueVendorTransaction struct {
	mu      sync.Mutex
	state   opaqueVendorTransactionState
	unitID  byte
	request OpaqueVendorRequest
}

type opaqueVendorTransactionState uint8

const (
	opaqueVendorIdle opaqueVendorTransactionState = iota
	opaqueVendorWaiting
	opaqueVendorQuarantine
)

// Begin validates and opens exactly one opaque transaction. A caller performs
// the actual bounded write only after receiving this locally validated frame.
func (transaction *OpaqueVendorTransaction) Begin(
	unitID byte,
	request OpaqueVendorRequest,
) ([]byte, error) {
	if transaction == nil {
		return nil, errOpaqueVendorTransactionState
	}
	frame, err := EncodeRTUOpaqueADU(unitID, request)
	if err != nil {
		return nil, err
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if transaction.state != opaqueVendorIdle {
		return nil, errOpaqueVendorTransactionState
	}
	transaction.state = opaqueVendorWaiting
	transaction.unitID = unitID
	transaction.request = request
	return cloneBytes(frame), nil
}

// Accept validates and delivers one matching response while retaining
// single-flight ownership. It accepts multiple frames so profile code can
// classify echo, intermediate, and terminal phases without transport semantics.
func (transaction *OpaqueVendorTransaction) Accept(
	frame []byte,
) (RTUOpaqueResponseADU, error) {
	if transaction == nil {
		return RTUOpaqueResponseADU{}, errOpaqueVendorTransactionState
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if transaction.state != opaqueVendorWaiting {
		return RTUOpaqueResponseADU{}, errOpaqueVendorTransactionState
	}
	return DecodeRTUOpaqueResponseADU(transaction.unitID, transaction.request, frame)
}

// Complete releases a profile-classified terminal transaction to idle.
func (transaction *OpaqueVendorTransaction) Complete() error {
	if transaction == nil {
		return errOpaqueVendorTransactionState
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if transaction.state != opaqueVendorWaiting {
		return errOpaqueVendorTransactionState
	}
	transaction.state = opaqueVendorIdle
	transaction.unitID = 0
	transaction.request = OpaqueVendorRequest{}
	return nil
}

// Timeout enters quarantine. The owner must discard late bytes and then call
// ReleaseQuarantine only after its bounded timing proof is complete.
func (transaction *OpaqueVendorTransaction) Timeout() error {
	if transaction == nil {
		return errOpaqueVendorTransactionState
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if transaction.state != opaqueVendorWaiting {
		return errOpaqueVendorTransactionState
	}
	transaction.state = opaqueVendorQuarantine
	return nil
}

// ReleaseQuarantine permits the next request after the owner discarded late
// frames and established the configured quiet interval.
func (transaction *OpaqueVendorTransaction) ReleaseQuarantine() error {
	if transaction == nil {
		return errOpaqueVendorTransactionState
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if transaction.state != opaqueVendorQuarantine {
		return errOpaqueVendorTransactionState
	}
	transaction.state = opaqueVendorIdle
	transaction.unitID = 0
	transaction.request = OpaqueVendorRequest{}
	return nil
}
