package modbus

import (
	"errors"
	"reflect"
	"testing"
)

func requireProtocolError(t *testing.T, err error, kind ErrorKind) *ProtocolError {
	t.Helper()
	var protocolErr *ProtocolError
	if !errors.As(err, &protocolErr) {
		t.Fatalf("expected ProtocolError, got %T: %v", err, err)
	}
	if protocolErr.Kind != kind {
		t.Fatalf("error kind = %q, want %q", protocolErr.Kind, kind)
	}
	return protocolErr
}

func TestPhaseOneFunctionAllowlist(t *testing.T) {
	tests := []struct {
		function FunctionCode
		allowed  bool
	}{
		{FunctionReadHoldingRegisters, true},
		{FunctionReadInputRegisters, true},
		{FunctionEncapsulatedInterface, true},
		{FunctionCode(0x01), false},
		{FunctionCode(0x06), false},
		{FunctionCode(0x10), false},
		{FunctionCode(0x2c), false},
	}
	for _, test := range tests {
		if got := IsPhaseOneFunction(test.function); got != test.allowed {
			t.Errorf("IsPhaseOneFunction(0x%02x) = %v, want %v", test.function, got, test.allowed)
		}
	}
}

func TestNewReadRegistersRequestAndEncoding(t *testing.T) {
	tests := []struct {
		name     string
		function FunctionCode
		table    LogicalTable
		wantPDU  []byte
	}{
		{
			name:     "holding",
			function: FunctionReadHoldingRegisters,
			table:    HoldingRegisters,
			wantPDU:  []byte{0x03, 0x12, 0x34, 0x00, 0x02},
		},
		{
			name:     "input",
			function: FunctionReadInputRegisters,
			table:    InputRegisters,
			wantPDU:  []byte{0x04, 0x12, 0x34, 0x00, 0x02},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request, err := NewReadRegistersRequest(test.function, 0x1234, 2)
			if err != nil {
				t.Fatal(err)
			}
			if request.Table != test.table {
				t.Fatalf("table = %q, want %q", request.Table, test.table)
			}
			if got := request.EncodePDU(); !reflect.DeepEqual(got, test.wantPDU) {
				t.Fatalf("PDU = %x, want %x", got, test.wantPDU)
			}
		})
	}
}

func TestReadRegistersRequestBounds(t *testing.T) {
	tests := []struct {
		name     string
		function FunctionCode
		offset   uint16
		quantity uint16
		kind     ErrorKind
	}{
		{"function", FunctionCode(0x06), 0, 1, ErrorUnsupportedOperation},
		{"zero quantity", FunctionReadHoldingRegisters, 0, 0, ErrorInvalidRange},
		{"quantity too large", FunctionReadHoldingRegisters, 0, 126, ErrorInvalidRange},
		{"wrapped range", FunctionReadInputRegisters, 0xffff, 2, ErrorInvalidRange},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewReadRegistersRequest(test.function, test.offset, test.quantity)
			requireProtocolError(t, err, test.kind)
		})
	}
}

func TestDecodeReadRegistersResponsePreservesTableProvenance(t *testing.T) {
	holding, err := NewReadRegistersRequest(FunctionReadHoldingRegisters, 0x20, 2)
	if err != nil {
		t.Fatal(err)
	}
	input, err := NewReadRegistersRequest(FunctionReadInputRegisters, 0x20, 2)
	if err != nil {
		t.Fatal(err)
	}

	holdingResponse, err := DecodeReadRegistersResponse(
		holding,
		[]byte{0x03, 0x04, 0x12, 0x34, 0xab, 0xcd},
	)
	if err != nil {
		t.Fatal(err)
	}
	inputResponse, err := DecodeReadRegistersResponse(
		input,
		[]byte{0x04, 0x04, 0x12, 0x34, 0xab, 0xcd},
	)
	if err != nil {
		t.Fatal(err)
	}

	wantWords := []uint16{0x1234, 0xabcd}
	if !reflect.DeepEqual(holdingResponse.Words, wantWords) {
		t.Fatalf("holding words = %#v, want %#v", holdingResponse.Words, wantWords)
	}
	if !reflect.DeepEqual(inputResponse.Words, wantWords) {
		t.Fatalf("input words = %#v, want %#v", inputResponse.Words, wantWords)
	}
	if holdingResponse.Provenance.Table != HoldingRegisters {
		t.Fatalf("holding provenance table = %q", holdingResponse.Provenance.Table)
	}
	if inputResponse.Provenance.Table != InputRegisters {
		t.Fatalf("input provenance table = %q", inputResponse.Provenance.Table)
	}
	if holdingResponse.Provenance == inputResponse.Provenance {
		t.Fatal("FC03 and FC04 provenance must remain distinct")
	}
	if holdingResponse.Provenance.Offset != 0x20 || holdingResponse.Provenance.Quantity != 2 {
		t.Fatalf("unexpected provenance: %#v", holdingResponse.Provenance)
	}
}

func TestDecodeReadRegistersResponseRejectsMalformedShape(t *testing.T) {
	request, err := NewReadRegistersRequest(FunctionReadHoldingRegisters, 0, 2)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		pdu  []byte
	}{
		{"empty", nil},
		{"wrong function", []byte{0x04, 0x04, 0, 1, 0, 2}},
		{"missing byte count", []byte{0x03}},
		{"wrong byte count", []byte{0x03, 0x02, 0, 1}},
		{"odd byte count", []byte{0x03, 0x03, 0, 1, 2}},
		{"truncated", []byte{0x03, 0x04, 0, 1}},
		{"trailing bytes", []byte{0x03, 0x04, 0, 1, 0, 2, 0}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := DecodeReadRegistersResponse(request, test.pdu)
			requireProtocolError(t, err, ErrorMalformedResponse)
		})
	}
}

func TestDecodeReadRegistersExceptionPreservesUnknownCode(t *testing.T) {
	request, err := NewReadRegistersRequest(FunctionReadInputRegisters, 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	_, err = DecodeReadRegistersResponse(request, []byte{0x84, 0x7f})
	protocolErr := requireProtocolError(t, err, ErrorExceptionResponse)
	if protocolErr.RequestedFunction != FunctionReadInputRegisters {
		t.Fatalf("requested function = 0x%02x", protocolErr.RequestedFunction)
	}
	if protocolErr.ReceivedFunction != FunctionCode(0x84) {
		t.Fatalf("received function = 0x%02x", protocolErr.ReceivedFunction)
	}
	if protocolErr.ExceptionCode != 0x7f {
		t.Fatalf("exception code = 0x%02x", protocolErr.ExceptionCode)
	}
}

func TestExceptionResponseMustBeExactlyTwoBytes(t *testing.T) {
	request, err := NewReadRegistersRequest(FunctionReadHoldingRegisters, 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, pdu := range [][]byte{{0x83}, {0x83, 0x02, 0x00}} {
		_, err := DecodeReadRegistersResponse(request, pdu)
		requireProtocolError(t, err, ErrorMalformedResponse)
	}
}
