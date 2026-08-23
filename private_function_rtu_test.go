package modbus

import (
	"bytes"
	"testing"
)

func TestPrivateFunctionCodeIsGenericAndResponseRemainsRaw(t *testing.T) {
	firstCode, err := NewPrivateFunctionCode(0x41)
	if err != nil {
		t.Fatal(err)
	}
	secondCode, err := NewPrivateFunctionCode(0x64)
	if err != nil {
		t.Fatal(err)
	}
	first, err := NewPrivateFunctionRequest(firstCode, []byte{0x01, 0x02})
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewPrivateFunctionRequest(secondCode, []byte{0x03})
	if err != nil {
		t.Fatal(err)
	}
	firstWire, err := EncodeRTUPrivateFunctionADU(0x10, first)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := firstWire[1], byte(firstCode); got != want {
		t.Fatalf("function = 0x%02x, want 0x%02x", got, want)
	}
	responseWire := makePrivateFunctionRTUFrame(t, 0x10, firstCode, []byte{0xff, 0x00})
	response, err := DecodeRTUPrivateFunctionResponseADU(0x10, first, responseWire)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := response.Payload(), []byte{0xff, 0x00}; !bytes.Equal(got, want) {
		t.Fatalf("payload = %x, want %x", got, want)
	}
	if _, err := DecodeRTUPrivateFunctionResponseADU(0x10, second, responseWire); err == nil {
		t.Fatal("response crossed private function-code policy")
	}
}

func TestPrivateFunctionCodeRejectsNonPrivateAndBindsExceptionsToInflightRequest(t *testing.T) {
	if _, err := NewPrivateFunctionCode(0x40); err == nil {
		t.Fatal("non-private function code accepted")
	}
	if _, err := NewPrivateFunctionCode(0x80); err == nil {
		t.Fatal("exception function code accepted")
	}
	code, err := NewPrivateFunctionCode(0x64)
	if err != nil {
		t.Fatal(err)
	}
	request, err := NewPrivateFunctionRequest(code, nil)
	if err != nil {
		t.Fatal(err)
	}
	exception := makePrivateFunctionRTUFrame(t, 0x10, PrivateFunctionCode(byte(code)|0x80), []byte{0x04})
	_, err = DecodeRTUPrivateFunctionResponseADU(0x10, request, exception)
	protocolErr, ok := err.(*ProtocolError)
	if !ok || protocolErr.Kind != ErrorExceptionResponse || protocolErr.ExceptionCode != 0x04 {
		t.Fatalf("exception = %#v", err)
	}
	otherCode, err := NewPrivateFunctionCode(0x41)
	if err != nil {
		t.Fatal(err)
	}
	otherException := makePrivateFunctionRTUFrame(t, 0x10, PrivateFunctionCode(byte(otherCode)|0x80), []byte{0x04})
	if _, err := DecodeRTUPrivateFunctionResponseADU(0x10, request, otherException); err == nil {
		t.Fatal("exception crossed in-flight private function code")
	}
}

func makePrivateFunctionRTUFrame(
	t *testing.T,
	unitID byte,
	function PrivateFunctionCode,
	payload []byte,
) []byte {
	t.Helper()
	body := append([]byte{unitID, byte(function)}, payload...)
	crc := rtuCRC16(body)
	return append(body, byte(crc), byte(crc>>8))
}
