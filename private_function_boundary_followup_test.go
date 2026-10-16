package modbus

import (
	"bytes"
	"fmt"
	"testing"
)

func q01Error(t *testing.T, err error, kind ErrorKind, field string) {
	t.Helper()
	pe, ok := err.(*ProtocolError)
	if !ok || pe.Kind != kind || pe.Field != field {
		t.Fatalf("error = %#v, want %s / %s", err, kind, field)
	}
}

func q01Request(t *testing.T, value byte, payload []byte) PrivateFunctionRequest {
	t.Helper()
	code, err := NewPrivateFunctionCode(value)
	if err != nil {
		t.Fatal(err)
	}
	request, err := NewPrivateFunctionRequest(code, payload)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

// Build wire fixtures independently of the encoders, including over-limit frames.
func q01RTU(payload []byte) []byte {
	frame := append([]byte{1, 127}, payload...)
	crc := uint16(0xffff)
	for _, value := range frame {
		crc ^= uint16(value)
		for bit := 0; bit < 8; bit++ {
			low := crc & 1
			crc >>= 1
			if low != 0 {
				crc ^= 0xa001
			}
		}
	}
	return append(frame, byte(crc), byte(crc>>8))
}

func q01TCP(payload []byte, declared int) []byte {
	frame := []byte{0, 7, 0, 0, byte(declared >> 8), byte(declared), 1, 127}
	return append(frame, payload...)
}

func TestQ01PrivateCodeBoundaries(t *testing.T) {
	for _, value := range []byte{0, 1, 127, 128, 255} {
		t.Run(fmt.Sprint(value), func(t *testing.T) {
			code, err := NewPrivateFunctionCode(value)
			if value == 0 || value >= 128 {
				q01Error(t, err, ErrorUnsupportedOperation, "private_function_code")
				// A cast must not bypass constructor validation at the request boundary.
				_, err = NewPrivateFunctionRequest(PrivateFunctionCode(value), nil)
				q01Error(t, err, ErrorUnsupportedOperation, "private_function_code")
				control := byte(127)
				if value == 0 {
					control = 1
				}
				q01Request(t, control, nil)
				return
			}
			if err != nil || code.Byte() != value {
				t.Fatalf("code = %d, error = %v", code.Byte(), err)
			}
			q01Request(t, value, nil)
		})
	}
}

func TestQ01PrivatePayloadBoundaries(t *testing.T) {
	for _, value := range []byte{1, 127} {
		for _, size := range []int{0, 252} {
			t.Run(fmt.Sprintf("code_%d/size_%d", value, size), func(t *testing.T) {
				payload := bytes.Repeat([]byte{0xa5}, size)
				request := q01Request(t, value, payload)
				pdu, err := request.EncodePDU()
				want := append([]byte{value}, payload...)
				if err != nil || !bytes.Equal(pdu, want) {
					t.Fatalf("PDU = %x, error = %v", pdu, err)
				}
				rtu, err := EncodeRTUPrivateFunctionADU(1, request)
				if err != nil || len(rtu) != size+4 {
					t.Fatalf("RTU length = %d, error = %v", len(rtu), err)
				}
				rr, err := DecodeRTUPrivateFunctionResponseADU(1, request, rtu)
				if err != nil || !bytes.Equal(rr.Payload(), payload) {
					t.Fatalf("RTU payload = %x, error = %v", rr.Payload(), err)
				}
				tcp, err := EncodeTCPPrivateFunctionADU(7, 1, request)
				if err != nil || len(tcp) != size+8 {
					t.Fatalf("TCP length = %d, error = %v", len(tcp), err)
				}
				tr, err := DecodeTCPPrivateFunctionResponseADU(7, 1, request, tcp)
				if err != nil || !bytes.Equal(tr.Payload(), payload) {
					t.Fatalf("TCP payload = %x, error = %v", tr.Payload(), err)
				}
			})
		}
		_, err := NewPrivateFunctionRequest(PrivateFunctionCode(value), make([]byte, 253))
		q01Error(t, err, ErrorInvalidRange, "private_function_payload_length")
		q01Request(t, value, make([]byte, 252))
	}
}

func TestQ01NormalRTULengthBoundaries(t *testing.T) {
	request := q01Request(t, 127, make([]byte, 252))
	// Empty and one-byte replies are valid opaque responses to a longer request.
	for _, size := range []int{0, 1, 251, 252, 253} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			payload := bytes.Repeat([]byte{0xa5}, size)
			frame := q01RTU(payload)
			response, err := DecodeRTUPrivateFunctionResponseADU(1, request, frame)
			if size == 253 {
				q01Error(t, err, ErrorMalformedResponse, "rtu_adu_length")
				control, err := DecodeRTUPrivateFunctionResponseADU(1, request, q01RTU(payload[:252]))
				if err != nil || !bytes.Equal(control.Payload(), payload[:252]) {
					t.Fatalf("adjacent RTU control: %v", err)
				}
				return
			}
			if err != nil || !bytes.Equal(response.Payload(), payload) {
				t.Fatalf("payload = %x, error = %v", response.Payload(), err)
			}
		})
	}
}

func TestQ01NormalTCPLengthBoundaries(t *testing.T) {
	request := q01Request(t, 127, make([]byte, 252))
	for _, size := range []int{0, 1, 251, 252} {
		payload := bytes.Repeat([]byte{0xa5}, size)
		response, err := DecodeTCPPrivateFunctionResponseADU(7, 1, request, q01TCP(payload, size+2))
		if err != nil || !bytes.Equal(response.Payload(), payload) {
			t.Fatalf("valid size %d: payload = %x, error = %v", size, response.Payload(), err)
		}
	}
	for _, tc := range []struct {
		name     string
		payload  []byte
		declared int
		field    string
	}{
		{"oversized_normal", make([]byte, 253), 255, "length"},
		{"below_minimum", nil, 1, "length"},
		{"truncated_body", []byte{0xa5}, 4, "truncated_adu"},
		{"declared_too_long", []byte{0xa5}, 254, "truncated_adu"},
		{"declared_too_short", []byte{0xa5}, 2, "truncated_adu"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DecodeTCPPrivateFunctionResponseADU(7, 1, request, q01TCP(tc.payload, tc.declared))
			q01Error(t, err, ErrorMalformedResponse, tc.field)
			// Repair only the boundary under test, retaining matching identity.
			payload := tc.payload
			if len(payload) > 252 {
				payload = payload[:252]
			}
			control, err := DecodeTCPPrivateFunctionResponseADU(7, 1, request, q01TCP(payload, len(payload)+2))
			if err != nil || !bytes.Equal(control.Payload(), payload) {
				t.Fatalf("valid TCP control: %v", err)
			}
		})
	}
}
