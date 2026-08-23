package modbus

import (
	"bytes"
	"testing"
)

func TestPrivateFunctionRTUVectorsAndRetention(t *testing.T) {
	code, err := NewPrivateFunctionCode(0x64)
	if err != nil {
		t.Fatal(err)
	}
	request, err := NewPrivateFunctionRequest(code, []byte{0})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := EncodeRTUPrivateFunctionADU(0x10, request)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := wire, []byte{0x10, 0x64, 0x00, 0x5a, 0xc5}; !bytes.Equal(got, want) {
		t.Fatalf("wire = %x, want %x", got, want)
	}
	response, err := DecodeRTUPrivateFunctionResponseADU(0x10, request, wire)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := response.Payload(), []byte{0}; !bytes.Equal(got, want) {
		t.Fatalf("payload = %x, want %x", got, want)
	}
	retained := response.Payload()
	retained[0] = 0xff
	if got := response.Payload(); got[0] != 0 {
		t.Fatalf("payload alias = %x", got)
	}
}

func TestPrivateFunctionRTURejectsInvalidLocalRequestsWithoutWire(t *testing.T) {
	for _, test := range []struct {
		name    string
		code    byte
		payload []byte
	}{
		{name: "non_private", code: 0x40},
		{name: "oversized_payload", code: 0x65, payload: make([]byte, 253)},
	} {
		t.Run(test.name, func(t *testing.T) {
			code, err := NewPrivateFunctionCode(test.code)
			if test.name == "non_private" {
				if err == nil {
					t.Fatal("invalid private code accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := NewPrivateFunctionRequest(code, test.payload); err == nil {
				t.Fatal("oversized private payload accepted")
			}
		})
	}
}

func TestPrivateFunctionRTUResponseValidation(t *testing.T) {
	code, err := NewPrivateFunctionCode(0x66)
	if err != nil {
		t.Fatal(err)
	}
	request, err := NewPrivateFunctionRequest(code, []byte{0})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		body []byte
	}{
		{name: "node_mismatch", body: []byte{0x11, 0x66, 0x00}},
		{name: "function_mismatch", body: []byte{0x10, 0x65, 0x00}},
		{name: "exception_extra_status", body: []byte{0x10, 0xe6, 0x04, 0x00}},
	} {
		t.Run(test.name, func(t *testing.T) {
			crc := rtuCRC16(test.body)
			wire := append(test.body, byte(crc), byte(crc>>8))
			if _, err := DecodeRTUPrivateFunctionResponseADU(0x10, request, wire); err == nil {
				t.Fatal("malformed response accepted")
			}
		})
	}

	exceptionBody := []byte{0x10, 0xe6, 0x04}
	crc := rtuCRC16(exceptionBody)
	_, err = DecodeRTUPrivateFunctionResponseADU(0x10, request, append(exceptionBody, byte(crc), byte(crc>>8)))
	protocolErr, ok := err.(*ProtocolError)
	if !ok || protocolErr.Kind != ErrorExceptionResponse || protocolErr.ExceptionCode != 4 {
		t.Fatalf("exception error = %#v", err)
	}
}

func TestPrivateFunctionResponsePolicyIsFailClosed(t *testing.T) {
	if policy := DefaultPrivateFunctionResponsePolicy(); policy.MaxAttempts() != 1 {
		t.Fatalf("default max attempts = %d", policy.MaxAttempts())
	}
	if _, err := NewPrivateFunctionResponsePolicy(2, false); err == nil {
		t.Fatal("non-replay-safe retry accepted")
	}
	policy, err := NewPrivateFunctionResponsePolicy(2, true)
	if err != nil {
		t.Fatal(err)
	}
	if policy.MaxAttempts() != 2 || !policy.ReplaySafe() {
		t.Fatalf("policy = %#v", policy)
	}
}

func TestPrivateFunctionTransactionDeliversRawFramesAndQuarantinesLateData(t *testing.T) {
	code, err := NewPrivateFunctionCode(0x64)
	if err != nil {
		t.Fatal(err)
	}
	request, err := NewPrivateFunctionRequest(code, []byte{0})
	if err != nil {
		t.Fatal(err)
	}
	var transaction PrivateFunctionTransaction
	if _, err := transaction.Begin(0x10, request); err != nil {
		t.Fatal(err)
	}
	if _, err := transaction.Begin(0x10, request); err == nil {
		t.Fatal("second outstanding transaction accepted")
	}
	first := makePrivateFunctionRTUFrame(t, 0x10, code, []byte{0})
	if response, err := transaction.Accept(first); err != nil || !bytes.Equal(response.Payload(), []byte{0}) {
		t.Fatalf("first = %#v, %v", response, err)
	}
	second := makePrivateFunctionRTUFrame(t, 0x10, code, []byte{1, 2})
	if response, err := transaction.Accept(second); err != nil || !bytes.Equal(response.Payload(), []byte{1, 2}) {
		t.Fatalf("second = %#v, %v", response, err)
	}
	if err := transaction.Timeout(); err != nil {
		t.Fatal(err)
	}
	if _, err := transaction.Accept(second); err == nil {
		t.Fatal("late response escaped quarantine")
	}
	if _, err := transaction.Begin(0x10, request); err == nil {
		t.Fatal("request began before quarantine release")
	}
	if err := transaction.ReleaseQuarantine(); err != nil {
		t.Fatal(err)
	}
	if _, err := transaction.Begin(0x10, request); err != nil {
		t.Fatal(err)
	}
}
