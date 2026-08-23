package modbus

import (
	"errors"
	"sync"
)

// PrivateFunctionCode is a transport-level private function-code value. It
// deliberately has no vendor, codec, or operation identity.
type PrivateFunctionCode byte

// NewPrivateFunctionCode validates one non-exception private function code.
// Codec selection belongs to the caller's endpoint-scoped registry, never to
// this transport package.
func NewPrivateFunctionCode(value byte) (PrivateFunctionCode, error) {
	if value == 0 || value&0x80 != 0 {
		return 0, protocolError(
			ErrorUnsupportedOperation,
			FunctionCode(value),
			0,
			"private_function_code",
			0,
		)
	}
	return PrivateFunctionCode(value), nil
}

// Byte returns the wire function-code byte.
func (code PrivateFunctionCode) Byte() byte {
	return byte(code)
}

// PrivateFunctionRequest is one bounded, uninterpreted private-function PDU.
type PrivateFunctionRequest struct {
	function PrivateFunctionCode
	payload  []byte
}

// NewPrivateFunctionRequest validates a generic private function-code request.
func NewPrivateFunctionRequest(
	function PrivateFunctionCode,
	payload []byte,
) (PrivateFunctionRequest, error) {
	if _, err := NewPrivateFunctionCode(byte(function)); err != nil {
		return PrivateFunctionRequest{}, err
	}
	if len(payload) > MaxPDUSize-1 {
		return PrivateFunctionRequest{}, protocolError(
			ErrorInvalidRange,
			FunctionCode(function),
			0,
			"private_function_payload_length",
			len(payload),
		)
	}
	return PrivateFunctionRequest{function: function, payload: cloneBytes(payload)}, nil
}

// FunctionCode returns the raw private function-code value.
func (request PrivateFunctionRequest) FunctionCode() PrivateFunctionCode {
	return request.function
}

// Payload returns an independent copy of raw request payload bytes.
func (request PrivateFunctionRequest) Payload() []byte {
	return cloneBytes(request.payload)
}

// EncodePDU returns one raw private-function PDU after revalidating bounds.
func (request PrivateFunctionRequest) EncodePDU() ([]byte, error) {
	if _, err := NewPrivateFunctionRequest(request.function, request.payload); err != nil {
		return nil, err
	}
	pdu := make([]byte, 1+len(request.payload))
	pdu[0] = byte(request.function)
	copy(pdu[1:], request.payload)
	return pdu, nil
}

// EncodeRTUPrivateFunctionADU encodes one bounded generic private-function RTU
// request. It assigns no semantic meaning to the function code or payload.
func EncodeRTUPrivateFunctionADU(
	unitID byte,
	request PrivateFunctionRequest,
) ([]byte, error) {
	pdu, err := request.EncodePDU()
	if err != nil {
		return nil, err
	}
	return encodeRTUADU(unitID, pdu)
}

// EncodeTCPPrivateFunctionADU encodes one bounded generic private-function
// MBAP request. It assigns no vendor or codec behavior.
func EncodeTCPPrivateFunctionADU(
	transactionID uint16,
	unitID byte,
	request PrivateFunctionRequest,
) ([]byte, error) {
	pdu, err := request.EncodePDU()
	if err != nil {
		return nil, err
	}
	return encodeTCPADU(transactionID, unitID, pdu)
}

// RTUPrivateFunctionResponseADU retains an exact raw normal response and
// validated framing. A registry-selected codec alone may decode its payload.
type RTUPrivateFunctionResponseADU struct {
	adu     RTUADU
	payload []byte
}

// Bytes returns an independent copy of the complete RTU response frame.
func (response RTUPrivateFunctionResponseADU) Bytes() []byte {
	return response.adu.Bytes()
}

// Payload returns an independent copy of raw normal-response payload bytes.
func (response RTUPrivateFunctionResponseADU) Payload() []byte {
	return cloneBytes(response.payload)
}

// TCPPrivateFunctionResponseADU retains an exact raw normal MBAP response.
// A registry-selected codec alone may decode its payload.
type TCPPrivateFunctionResponseADU struct {
	adu     TCPADU
	payload []byte
}

// Bytes returns an independent copy of the complete MBAP response frame.
func (response TCPPrivateFunctionResponseADU) Bytes() []byte {
	return response.adu.Bytes()
}

// Payload returns an independent copy of raw normal-response payload bytes.
func (response TCPPrivateFunctionResponseADU) Payload() []byte {
	return cloneBytes(response.payload)
}

// DecodeRTUPrivateFunctionResponseADU validates unit, CRC, in-flight function
// correlation, and the exact exception shape without interpreting payloads.
func DecodeRTUPrivateFunctionResponseADU(
	expectedUnitID byte,
	request PrivateFunctionRequest,
	frame []byte,
) (RTUPrivateFunctionResponseADU, error) {
	if expectedUnitID == 0 || expectedUnitID > 247 {
		return RTUPrivateFunctionResponseADU{}, protocolError(
			ErrorInvalidRequest,
			FunctionCode(request.function),
			0,
			"unit_id",
			0,
		)
	}
	if _, err := NewPrivateFunctionRequest(request.function, request.payload); err != nil {
		return RTUPrivateFunctionResponseADU{}, err
	}
	adu, err := decodeRTUADU(frame)
	response := RTUPrivateFunctionResponseADU{adu: adu}
	if err != nil {
		return response, err
	}
	if adu.unitID != expectedUnitID {
		return response, protocolError(
			ErrorMalformedResponse,
			FunctionCode(request.function),
			0,
			"unit_id",
			0,
		)
	}
	if len(adu.pdu) == 0 {
		return response, protocolError(
			ErrorMalformedResponse,
			FunctionCode(request.function),
			0,
			"function",
			0,
		)
	}
	received := FunctionCode(adu.pdu[0])
	if received == FunctionCode(byte(request.function)|0x80) {
		if len(adu.pdu) != 2 {
			return response, protocolError(
				ErrorMalformedResponse,
				FunctionCode(request.function),
				received,
				"exception_length",
				len(adu.pdu),
			)
		}
		exception := protocolError(
			ErrorExceptionResponse,
			FunctionCode(request.function),
			received,
			"exception_code",
			1,
		)
		exception.ExceptionCode = adu.pdu[1]
		return response, exception
	}
	if received != FunctionCode(request.function) {
		return response, protocolError(
			ErrorMalformedResponse,
			FunctionCode(request.function),
			received,
			"function_mismatch",
			0,
		)
	}
	response.payload = cloneBytes(adu.pdu[1:])
	return response, nil
}

// DecodeTCPPrivateFunctionResponseADU validates one exact MBAP frame against
// the in-flight transaction, unit, and private function code. It returns raw
// normal payload bytes or the generic exception error without vendor decoding.
func DecodeTCPPrivateFunctionResponseADU(
	expectedTransactionID uint16,
	expectedUnitID byte,
	request PrivateFunctionRequest,
	frame []byte,
) (TCPPrivateFunctionResponseADU, error) {
	if expectedUnitID > 247 {
		return TCPPrivateFunctionResponseADU{}, protocolError(
			ErrorInvalidRequest,
			FunctionCode(request.function),
			0,
			"unit_id",
			6,
		)
	}
	if _, err := NewPrivateFunctionRequest(request.function, request.payload); err != nil {
		return TCPPrivateFunctionResponseADU{}, err
	}
	decoder, err := NewTCPStreamDecoder(maxTCPADUSize)
	if err != nil {
		return TCPPrivateFunctionResponseADU{}, err
	}
	frames, err := decoder.Feed(frame)
	if err != nil {
		return TCPPrivateFunctionResponseADU{}, err
	}
	if err := decoder.Finish(); err != nil {
		return TCPPrivateFunctionResponseADU{}, err
	}
	if len(frames) != 1 {
		return TCPPrivateFunctionResponseADU{}, protocolError(
			ErrorMalformedResponse,
			FunctionCode(request.function),
			0,
			"tcp_adu_count",
			len(frames),
		)
	}
	adu := frames[0]
	response := TCPPrivateFunctionResponseADU{adu: adu}
	if adu.transactionID != expectedTransactionID {
		return response, protocolError(
			ErrorMalformedResponse,
			FunctionCode(request.function),
			0,
			"transaction_id",
			0,
		)
	}
	if adu.unitID != expectedUnitID {
		return response, protocolError(
			ErrorMalformedResponse,
			FunctionCode(request.function),
			0,
			"unit_id",
			6,
		)
	}
	if len(adu.pdu) == 0 {
		return response, protocolError(
			ErrorMalformedResponse,
			FunctionCode(request.function),
			0,
			"function",
			7,
		)
	}
	received := FunctionCode(adu.pdu[0])
	if received == FunctionCode(byte(request.function)|0x80) {
		if len(adu.pdu) != 2 {
			return response, protocolError(
				ErrorMalformedResponse,
				FunctionCode(request.function),
				received,
				"exception_length",
				len(adu.pdu),
			)
		}
		exception := protocolError(
			ErrorExceptionResponse,
			FunctionCode(request.function),
			received,
			"exception_code",
			8,
		)
		exception.ExceptionCode = adu.pdu[1]
		return response, exception
	}
	if received != FunctionCode(request.function) {
		return response, protocolError(
			ErrorMalformedResponse,
			FunctionCode(request.function),
			received,
			"function_mismatch",
			7,
		)
	}
	response.payload = cloneBytes(adu.pdu[1:])
	return response, nil
}

// PrivateFunctionResponsePolicy permits retries only after a higher layer
// explicitly declares the selected operation replay-safe. Its default permits
// exactly one attempt.
type PrivateFunctionResponsePolicy struct {
	maxAttempts uint8
	replaySafe  bool
}

// DefaultPrivateFunctionResponsePolicy denies implicit replay.
func DefaultPrivateFunctionResponsePolicy() PrivateFunctionResponsePolicy {
	return PrivateFunctionResponsePolicy{maxAttempts: 1}
}

// NewPrivateFunctionResponsePolicy validates bounded retry admission.
func NewPrivateFunctionResponsePolicy(
	maxAttempts uint8,
	replaySafe bool,
) (PrivateFunctionResponsePolicy, error) {
	if maxAttempts == 0 || maxAttempts > 3 || (maxAttempts > 1 && !replaySafe) {
		return PrivateFunctionResponsePolicy{}, protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"private_function_response_policy",
			-1,
		)
	}
	return PrivateFunctionResponsePolicy{maxAttempts: maxAttempts, replaySafe: replaySafe}, nil
}

// MaxAttempts returns the bounded number of permitted attempts.
func (policy PrivateFunctionResponsePolicy) MaxAttempts() uint8 {
	return policy.maxAttempts
}

// ReplaySafe reports the explicit higher-layer replay declaration.
func (policy PrivateFunctionResponsePolicy) ReplaySafe() bool {
	return policy.replaySafe
}

var errPrivateFunctionTransactionState = errors.New("invalid private function transaction state")

// PrivateFunctionTransaction is an offline generic single-flight RTU response
// owner. It returns raw matching responses to a higher layer and never selects
// or invokes a vendor codec.
type PrivateFunctionTransaction struct {
	mu      sync.Mutex
	state   privateFunctionTransactionState
	unitID  byte
	request PrivateFunctionRequest
}

type privateFunctionTransactionState uint8

const (
	privateFunctionIdle privateFunctionTransactionState = iota
	privateFunctionWaiting
	privateFunctionQuarantine
)

// Begin validates and opens one private-function transaction.
func (transaction *PrivateFunctionTransaction) Begin(
	unitID byte,
	request PrivateFunctionRequest,
) ([]byte, error) {
	if transaction == nil {
		return nil, errPrivateFunctionTransactionState
	}
	frame, err := EncodeRTUPrivateFunctionADU(unitID, request)
	if err != nil {
		return nil, err
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if transaction.state != privateFunctionIdle {
		return nil, errPrivateFunctionTransactionState
	}
	transaction.state = privateFunctionWaiting
	transaction.unitID = unitID
	transaction.request = request
	return cloneBytes(frame), nil
}

// Accept correlates one raw normal response or raw exception to the in-flight
// request. It accepts multiple normal frames for a selected higher-layer codec.
func (transaction *PrivateFunctionTransaction) Accept(
	frame []byte,
) (RTUPrivateFunctionResponseADU, error) {
	if transaction == nil {
		return RTUPrivateFunctionResponseADU{}, errPrivateFunctionTransactionState
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if transaction.state != privateFunctionWaiting {
		return RTUPrivateFunctionResponseADU{}, errPrivateFunctionTransactionState
	}
	return DecodeRTUPrivateFunctionResponseADU(transaction.unitID, transaction.request, frame)
}

// Complete releases a higher-layer-classified terminal transaction to idle.
func (transaction *PrivateFunctionTransaction) Complete() error {
	if transaction == nil {
		return errPrivateFunctionTransactionState
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if transaction.state != privateFunctionWaiting {
		return errPrivateFunctionTransactionState
	}
	transaction.state = privateFunctionIdle
	transaction.unitID = 0
	transaction.request = PrivateFunctionRequest{}
	return nil
}

// Timeout enters quarantine until the endpoint proves safe recovery.
func (transaction *PrivateFunctionTransaction) Timeout() error {
	if transaction == nil {
		return errPrivateFunctionTransactionState
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if transaction.state != privateFunctionWaiting {
		return errPrivateFunctionTransactionState
	}
	transaction.state = privateFunctionQuarantine
	return nil
}

// ReleaseQuarantine permits the next request after endpoint recovery.
func (transaction *PrivateFunctionTransaction) ReleaseQuarantine() error {
	if transaction == nil {
		return errPrivateFunctionTransactionState
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if transaction.state != privateFunctionQuarantine {
		return errPrivateFunctionTransactionState
	}
	transaction.state = privateFunctionIdle
	transaction.unitID = 0
	transaction.request = PrivateFunctionRequest{}
	return nil
}
