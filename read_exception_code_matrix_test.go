package modbus

import (
	"errors"
	"fmt"
	"testing"
)

func TestS18ReadExceptionOpaqueCodeMatrix(t *testing.T) {
	for _, function := range []FunctionCode{0x03, 0x04} {
		request, err := NewReadRegistersRequest(function, 0, 1)
		if err != nil {
			t.Fatal(err)
		}
		for code := 0; code < 256; code++ {
			t.Run(fmt.Sprintf("fc%02x/code%02x", function, code), func(t *testing.T) {
				received := function | 0x80
				response, err := DecodeReadRegistersResponse(request, []byte{byte(received), byte(code)})
				var protocolErr *ProtocolError
				if !errors.As(err, &protocolErr) {
					t.Fatalf("error = %v; want *ProtocolError", err)
				}
				want := ProtocolError{
					Kind:              ErrorExceptionResponse,
					RequestedFunction: function,
					ReceivedFunction:  received,
					ExceptionCode:     byte(code),
					Field:             "exception_code",
					Offset:            1,
				}
				if *protocolErr != want {
					t.Fatalf("error = %#v; want %#v", *protocolErr, want)
				}
				if response.Words != nil || response.Provenance != (ReadProvenance{}) {
					t.Fatalf("exception returned register data: %#v", response)
				}
			})
		}
	}
}

func TestS18ReadExceptionFunctionAndLengthMatrix(t *testing.T) {
	for _, function := range []FunctionCode{0x03, 0x04} {
		request, err := NewReadRegistersRequest(function, 0, 1)
		if err != nil {
			t.Fatal(err)
		}
		for _, received := range []FunctionCode{0x83, 0x84} {
			for _, code := range []byte{0x00, 0x02, 0x7f, 0xff} {
				for _, length := range []int{1, 2, 3, 4} {
					if received == function|0x80 && length == 2 {
						continue // Exact matching exceptions are covered by the exhaustive sweep.
					}
					t.Run(fmt.Sprintf("fc%02x/received%02x/code%02x/length%d", function, received, code, length), func(t *testing.T) {
						pdu := []byte{byte(received), code, 0x12, 0x34}[:length]
						response, err := DecodeReadRegistersResponse(request, pdu)
						var protocolErr *ProtocolError
						if !errors.As(err, &protocolErr) {
							t.Fatalf("error = %v; want *ProtocolError", err)
						}
						field, offset := "function_mismatch", 0
						if received == function|0x80 {
							field, offset = "exception_length", length
						}
						want := ProtocolError{
							Kind:              ErrorMalformedResponse,
							RequestedFunction: function,
							ReceivedFunction:  received,
							Field:             field,
							Offset:            offset,
						}
						if *protocolErr != want {
							t.Fatalf("error = %#v; want %#v", *protocolErr, want)
						}
						if response.Words != nil || response.Provenance != (ReadProvenance{}) {
							t.Fatalf("malformed exception returned register data: %#v", response)
						}
					})
				}
			}
		}
	}
}
