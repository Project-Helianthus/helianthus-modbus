package modbus

import (
	"bytes"
	"testing"
)

func TestOpaqueVendorRTUVectorsAndRetention(t *testing.T) {
	request, err := NewOpaqueVendorRequest(FunctionVendor100, []byte{0})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := EncodeRTUOpaqueADU(0x10, request)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := wire, []byte{0x10, 0x64, 0x00, 0x5a, 0xc5}; !bytes.Equal(got, want) {
		t.Fatalf("wire = %x, want %x", got, want)
	}
	response, err := DecodeRTUOpaqueResponseADU(0x10, request, wire)
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

func TestOpaqueVendorRTURejectsInvalidLocalRequestsWithoutWire(t *testing.T) {
	for _, test := range []struct {
		name     string
		function FunctionCode
		payload  []byte
	}{
		{name: "unknown_function", function: FunctionCode(99)},
		{name: "oversized_payload", function: FunctionVendor101, payload: make([]byte, 253)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewOpaqueVendorRequest(test.function, test.payload); err == nil {
				t.Fatal("invalid opaque request accepted")
			}
		})
	}
}

func TestOpaqueVendorRTUResponseValidation(t *testing.T) {
	request, err := NewOpaqueVendorRequest(FunctionVendor102, []byte{0})
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
			if _, err := DecodeRTUOpaqueResponseADU(0x10, request, wire); err == nil {
				t.Fatal("malformed response accepted")
			}
		})
	}

	exceptionBody := []byte{0x10, 0xe6, 0x04}
	crc := rtuCRC16(exceptionBody)
	_, err = DecodeRTUOpaqueResponseADU(
		0x10,
		request,
		append(exceptionBody, byte(crc), byte(crc>>8)),
	)
	protocolErr, ok := err.(*ProtocolError)
	if !ok || protocolErr.Kind != ErrorExceptionResponse || protocolErr.ExceptionCode != 4 {
		t.Fatalf("exception error = %#v", err)
	}
}

func TestOpaqueVendorRetryPolicyIsFailClosed(t *testing.T) {
	if policy := DefaultOpaqueVendorRetryPolicy(); policy.MaxAttempts() != 1 {
		t.Fatalf("default max attempts = %d", policy.MaxAttempts())
	}
	if _, err := NewOpaqueVendorRetryPolicy(2, false); err == nil {
		t.Fatal("non-replay-safe retry accepted")
	}
	policy, err := NewOpaqueVendorRetryPolicy(2, true)
	if err != nil {
		t.Fatal(err)
	}
	if policy.MaxAttempts() != 2 || !policy.ReplaySafe() {
		t.Fatalf("policy = %#v", policy)
	}
}

func TestOpaqueVendorTransactionDeliversMultipleFramesAndQuarantinesLateData(t *testing.T) {
	request, err := NewOpaqueVendorRequest(FunctionVendor100, []byte{0})
	if err != nil {
		t.Fatal(err)
	}
	var transaction OpaqueVendorTransaction
	if _, err := transaction.Begin(0x10, request); err != nil {
		t.Fatal(err)
	}
	if _, err := transaction.Begin(0x10, request); err == nil {
		t.Fatal("second outstanding transaction accepted")
	}
	echo := makeOpaqueRTUFrame(t, 0x10, FunctionVendor100, []byte{0})
	if response, err := transaction.Accept(echo); err != nil || !bytes.Equal(response.Payload(), []byte{0}) {
		t.Fatalf("echo = %#v, %v", response, err)
	}
	result := makeOpaqueRTUFrame(t, 0x10, FunctionVendor100, []byte{1, 2})
	if response, err := transaction.Accept(result); err != nil || !bytes.Equal(response.Payload(), []byte{1, 2}) {
		t.Fatalf("result = %#v, %v", response, err)
	}
	if err := transaction.Timeout(); err != nil {
		t.Fatal(err)
	}
	if _, err := transaction.Accept(result); err == nil {
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

func makeOpaqueRTUFrame(
	t *testing.T,
	unitID byte,
	function FunctionCode,
	payload []byte,
) []byte {
	t.Helper()
	body := append([]byte{unitID, byte(function)}, payload...)
	crc := rtuCRC16(body)
	return append(body, byte(crc), byte(crc>>8))
}
