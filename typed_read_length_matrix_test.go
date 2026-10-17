package modbus

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"
)

func TestQ24TypedReadLengthMatrix(t *testing.T) {
	for _, function := range []FunctionCode{FunctionReadHoldingRegisters, FunctionReadInputRegisters} {
		for _, quantity := range []uint16{1, MaxReadRegisters - 1, MaxReadRegisters} {
			t.Run(fmt.Sprintf("FC%02X/registers_%d", function, quantity), func(t *testing.T) {
				request, err := NewReadRegistersRequest(function, 0, quantity)
				if err != nil {
					t.Fatal(err)
				}
				// The wire fixture and expected words are independently specified.
				wirePattern := []byte{0x12, 0x34, 0xab, 0xcd, 0x00, 0xff, 0x80, 0x01}
				wordPattern := []uint16{0x1234, 0xabcd, 0x00ff, 0x8001}
				payload := make([]byte, int(quantity)*2)
				for i := range payload {
					payload[i] = wirePattern[i%len(wirePattern)]
				}
				wantWords := make([]uint16, quantity)
				for i := range wantWords {
					wantWords[i] = wordPattern[i%len(wordPattern)]
				}
				exact := append([]byte{byte(function), byte(len(payload))}, payload...)
				other := FunctionReadInputRegisters
				table := HoldingRegisters
				if function == FunctionReadInputRegisters {
					other = FunctionReadHoldingRegisters
					table = InputRegisters
				}
				type lengthVector struct {
					name     string
					data     []byte
					count    byte
					received FunctionCode
					field    string
				}
				cases := []lengthVector{
					{"exact", payload, byte(len(payload)), function, ""},
					{"too_few_even", payload[:len(payload)-2], byte(len(payload)), function, "response_length"},
					{"too_few_odd", payload[:len(payload)-1], byte(len(payload)), function, "response_length"},
					{"too_many_odd", append(append([]byte(nil), payload...), 0x55), byte(len(payload)), function, "response_length"},
					{"inconsistent_byte_count", payload, byte(len(payload) - 1), function, "byte_count"},
					{"self_consistent_short_even", payload[:len(payload)-2], byte(len(payload) - 2), function, "byte_count"},
					{"self_consistent_short_odd", payload[:len(payload)-1], byte(len(payload) - 1), function, "byte_count"},
					{"self_consistent_long_odd", append(append([]byte(nil), payload...), 0x55), byte(len(payload) + 1), function, "byte_count"},
					{"wrong_function", payload, byte(len(payload)), other, "function_mismatch"},
				}
				// Two extra bytes at the maximum would exceed RTU framing bounds.
				if quantity < MaxReadRegisters {
					cases = append(cases, lengthVector{
						"self_consistent_long_even", append(append([]byte(nil), payload...), 0x55, 0xaa), byte(len(payload) + 2), function, "byte_count",
					})
				}
				for _, vector := range cases {
					t.Run(vector.name, func(t *testing.T) {
						pdu := append([]byte{byte(vector.received), vector.count}, vector.data...)
						frame := rtuTestFrame(1, pdu...)
						// Prove every malformed frame reaches typed correlation, including at the size limit.
						framed, err := decodeRTUADU(frame)
						if err != nil {
							t.Fatalf("fixture framing: %v", err)
						}
						if framed.UnitID() != 1 || !bytes.Equal(framed.PDU(), pdu) {
							t.Fatal("fixture identity or PDU changed")
						}
						for _, transport := range []string{"PDU", "RTU"} {
							t.Run(transport, func(t *testing.T) {
								var response ReadRegistersResponse
								var err error
								if transport == "PDU" {
									response, err = DecodeReadRegistersResponse(request, pdu)
								} else {
									var adu RTUReadResponseADU
									adu, err = DecodeRTUReadResponseADU(1, request, frame)
									response = adu.Response()
									if !bytes.Equal(adu.Bytes(), frame) {
										t.Fatal("raw response evidence changed")
									}
								}
								if vector.field == "" {
									if err != nil {
										t.Fatal(err)
									}
									if !bytes.Equal(pdu, exact) || !reflect.DeepEqual(response.Words, wantWords) {
										t.Fatalf("words = %04x, want %04x", response.Words, wantWords)
									}
									want := ReadProvenance{Function: function, Table: table, Offset: 0, Quantity: quantity}
									if response.Provenance != want {
										t.Fatalf("provenance = %#v, want %#v", response.Provenance, want)
									}
									return
								}
								protocolErr := requireProtocolError(t, err, ErrorMalformedResponse)
								offset := 1
								if vector.field == "response_length" {
									offset = len(pdu)
								}
								if vector.field == "function_mismatch" {
									offset = 0
								}
								if protocolErr.Field != vector.field || protocolErr.Offset != offset || protocolErr.RequestedFunction != function || protocolErr.ReceivedFunction != vector.received || protocolErr.ExceptionCode != 0 {
									t.Fatalf("error = %#v; want field %s, offset %d, requested %02x, received %02x", protocolErr, vector.field, offset, function, vector.received)
								}
								if len(response.Words) != 0 || response.Provenance != (ReadProvenance{}) {
									t.Fatalf("invalid response returned decoded data: %#v", response)
								}
							})
						}
					})
				}
			})
		}
	}
}
