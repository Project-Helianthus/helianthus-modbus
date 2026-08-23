package modbus

import (
	"bytes"
	"testing"
)

func TestTCPPrivateFunctionPreservesMBAPIdentityAndRawPayload(t *testing.T) {
	code, err := NewPrivateFunctionCode(0x41)
	if err != nil {
		t.Fatal(err)
	}
	request, err := NewPrivateFunctionRequest(code, []byte{0x01})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := EncodeTCPPrivateFunctionADU(7, 0x10, request)
	if err != nil {
		t.Fatal(err)
	}
	response, err := DecodeTCPPrivateFunctionResponseADU(7, 0x10, request, wire)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := response.Payload(), []byte{0x01}; !bytes.Equal(got, want) {
		t.Fatalf("payload = %x, want %x", got, want)
	}
	if _, err := DecodeTCPPrivateFunctionResponseADU(8, 0x10, request, wire); err == nil {
		t.Fatal("transaction mismatch accepted")
	}
	if _, err := DecodeTCPPrivateFunctionResponseADU(7, 0x11, request, wire); err == nil {
		t.Fatal("unit mismatch accepted")
	}
}

func TestTCPPrivateFunctionExceptionBindsToInflightFunction(t *testing.T) {
	code, err := NewPrivateFunctionCode(0x64)
	if err != nil {
		t.Fatal(err)
	}
	request, err := NewPrivateFunctionRequest(code, nil)
	if err != nil {
		t.Fatal(err)
	}
	exceptionPDU := []byte{byte(code) | 0x80, 0x02}
	wire, err := encodeTCPADU(9, 0x10, exceptionPDU)
	if err != nil {
		t.Fatal(err)
	}
	_, err = DecodeTCPPrivateFunctionResponseADU(9, 0x10, request, wire)
	protocolErr, ok := err.(*ProtocolError)
	if !ok || protocolErr.Kind != ErrorExceptionResponse || protocolErr.ExceptionCode != 0x02 {
		t.Fatalf("exception = %#v", err)
	}
}
