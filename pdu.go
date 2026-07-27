package modbus

import "fmt"

const (
	// MaxPDUSize is the maximum Modbus protocol data unit size in bytes.
	MaxPDUSize = 253
	// MaxReadRegisters is the maximum FC03/FC04 quantity.
	MaxReadRegisters = 125
)

// FunctionCode identifies a Modbus operation.
type FunctionCode byte

const (
	FunctionReadHoldingRegisters  FunctionCode = 0x03
	FunctionReadInputRegisters    FunctionCode = 0x04
	FunctionEncapsulatedInterface FunctionCode = 0x2b
)

// LogicalTable keeps numerically equal FC03 and FC04 ranges distinct.
type LogicalTable string

const (
	HoldingRegisters LogicalTable = "holding_registers"
	InputRegisters   LogicalTable = "input_registers"
)

// ErrorKind classifies local validation and remote protocol failures.
type ErrorKind string

const (
	ErrorUnsupportedOperation ErrorKind = "unsupported_operation"
	ErrorInvalidRequest       ErrorKind = "invalid_request"
	ErrorInvalidRange         ErrorKind = "invalid_range"
	ErrorMalformedResponse    ErrorKind = "malformed_response"
	ErrorExceptionResponse    ErrorKind = "exception_response"
)

// ProtocolError preserves protocol identity without profile interpretation.
type ProtocolError struct {
	Kind              ErrorKind
	RequestedFunction FunctionCode
	ReceivedFunction  FunctionCode
	ExceptionCode     byte
	Field             string
	Offset            int
}

func (err *ProtocolError) Error() string {
	if err == nil {
		return "<nil>"
	}
	message := string(err.Kind)
	if err.Field != "" {
		message += ": " + err.Field
	}
	if err.Offset >= 0 {
		message += fmt.Sprintf(" at byte %d", err.Offset)
	}
	return message
}

func protocolError(
	kind ErrorKind,
	requested FunctionCode,
	received FunctionCode,
	field string,
	offset int,
) *ProtocolError {
	return &ProtocolError{
		Kind:              kind,
		RequestedFunction: requested,
		ReceivedFunction:  received,
		Field:             field,
		Offset:            offset,
	}
}

// ReadRegistersRequest is a validated FC03 or FC04 request.
type ReadRegistersRequest struct {
	function FunctionCode
	table    LogicalTable
	offset   uint16
	quantity uint16
}

// ReadProvenance identifies the exact logical read represented by a response.
type ReadProvenance struct {
	Function FunctionCode
	Table    LogicalTable
	Offset   uint16
	Quantity uint16
}

// ReadRegistersResponse contains uninterpreted wire-order words.
type ReadRegistersResponse struct {
	Words      []uint16
	Provenance ReadProvenance
}

// NewReadRegistersRequest validates an FC03 or FC04 range.
func NewReadRegistersRequest(
	function FunctionCode,
	offset uint16,
	quantity uint16,
) (ReadRegistersRequest, error) {
	var table LogicalTable
	switch function {
	case FunctionReadHoldingRegisters:
		table = HoldingRegisters
	case FunctionReadInputRegisters:
		table = InputRegisters
	default:
		return ReadRegistersRequest{}, protocolError(
			ErrorUnsupportedOperation,
			function,
			0,
			"function",
			0,
		)
	}
	if quantity == 0 || quantity > MaxReadRegisters {
		return ReadRegistersRequest{}, protocolError(
			ErrorInvalidRange,
			function,
			0,
			"quantity",
			3,
		)
	}
	if uint32(offset)+uint32(quantity)-1 > 0xffff {
		return ReadRegistersRequest{}, protocolError(
			ErrorInvalidRange,
			function,
			0,
			"range_wrap",
			1,
		)
	}
	return ReadRegistersRequest{
		function: function,
		table:    table,
		offset:   offset,
		quantity: quantity,
	}, nil
}

// Function returns the validated request function.
func (request ReadRegistersRequest) Function() FunctionCode {
	return request.function
}

// Table returns the validated logical table.
func (request ReadRegistersRequest) Table() LogicalTable {
	return request.table
}

// Offset returns the zero-based PDU offset.
func (request ReadRegistersRequest) Offset() uint16 {
	return request.offset
}

// Quantity returns the requested register count.
func (request ReadRegistersRequest) Quantity() uint16 {
	return request.quantity
}

// EncodePDU validates the request again and returns a new exact PDU.
func (request ReadRegistersRequest) EncodePDU() ([]byte, error) {
	if err := validateReadRegistersRequest(request); err != nil {
		return nil, err
	}
	return []byte{
		byte(request.function),
		byte(request.offset >> 8),
		byte(request.offset),
		byte(request.quantity >> 8),
		byte(request.quantity),
	}, nil
}

// DecodeReadRegistersResponse validates and decodes one exact FC03/FC04 PDU.
func DecodeReadRegistersResponse(
	request ReadRegistersRequest,
	pdu []byte,
) (ReadRegistersResponse, error) {
	if err := validateReadRegistersRequest(request); err != nil {
		return ReadRegistersResponse{}, err
	}
	if len(pdu) == 0 {
		return ReadRegistersResponse{}, protocolError(
			ErrorMalformedResponse,
			request.function,
			0,
			"function",
			0,
		)
	}
	received := FunctionCode(pdu[0])
	if received == request.function|0x80 {
		if len(pdu) != 2 {
			return ReadRegistersResponse{}, protocolError(
				ErrorMalformedResponse,
				request.function,
				received,
				"exception_length",
				len(pdu),
			)
		}
		err := protocolError(
			ErrorExceptionResponse,
			request.function,
			received,
			"exception_code",
			1,
		)
		err.ExceptionCode = pdu[1]
		return ReadRegistersResponse{}, err
	}
	if received != request.function {
		return ReadRegistersResponse{}, protocolError(
			ErrorMalformedResponse,
			request.function,
			received,
			"function_mismatch",
			0,
		)
	}
	if len(pdu) < 2 {
		return ReadRegistersResponse{}, protocolError(
			ErrorMalformedResponse,
			request.function,
			received,
			"byte_count",
			1,
		)
	}
	expectedBytes := int(request.quantity) * 2
	if int(pdu[1]) != expectedBytes {
		return ReadRegistersResponse{}, protocolError(
			ErrorMalformedResponse,
			request.function,
			received,
			"byte_count",
			1,
		)
	}
	if len(pdu) != expectedBytes+2 || len(pdu) > MaxPDUSize {
		return ReadRegistersResponse{}, protocolError(
			ErrorMalformedResponse,
			request.function,
			received,
			"response_length",
			len(pdu),
		)
	}
	words := make([]uint16, request.quantity)
	for index := range words {
		offset := 2 + index*2
		words[index] = uint16(pdu[offset])<<8 | uint16(pdu[offset+1])
	}
	return ReadRegistersResponse{
		Words: words,
		Provenance: ReadProvenance{
			Function: request.function,
			Table:    request.table,
			Offset:   request.offset,
			Quantity: request.quantity,
		},
	}, nil
}

func validateReadRegistersRequest(request ReadRegistersRequest) error {
	var expectedTable LogicalTable
	switch request.function {
	case FunctionReadHoldingRegisters:
		expectedTable = HoldingRegisters
	case FunctionReadInputRegisters:
		expectedTable = InputRegisters
	default:
		return protocolError(
			ErrorUnsupportedOperation,
			request.function,
			0,
			"function",
			0,
		)
	}
	if request.table != expectedTable {
		return protocolError(
			ErrorInvalidRequest,
			request.function,
			0,
			"logical_table",
			-1,
		)
	}
	if request.quantity == 0 || request.quantity > MaxReadRegisters {
		return protocolError(
			ErrorInvalidRange,
			request.function,
			0,
			"quantity",
			3,
		)
	}
	if uint32(request.offset)+uint32(request.quantity)-1 > 0xffff {
		return protocolError(
			ErrorInvalidRange,
			request.function,
			0,
			"range_wrap",
			1,
		)
	}
	return nil
}
