package modbus

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
)

func TestS17LastRegisterEveryReadWidth(t *testing.T) {
	for _, operation := range []struct {
		function FunctionCode
		table    LogicalTable
		wire     byte
	}{
		{FunctionReadHoldingRegisters, HoldingRegisters, 0x03},
		{FunctionReadInputRegisters, InputRegisters, 0x04},
	} {
		for quantity := 1; quantity <= 125; quantity++ {
			t.Run(fmt.Sprintf("FC%02x/quantity_%d", operation.wire, quantity), func(t *testing.T) {
				// Compute in int so the inclusive end cannot silently wrap.
				offset := 65536 - quantity
				if end := offset + quantity - 1; end != 65535 {
					t.Fatalf("fixture end = %d, want 65535", end)
				}
				request, err := NewReadRegistersRequest(operation.function, uint16(offset), uint16(quantity))
				if err != nil {
					t.Fatal(err)
				}
				if request.Function() != operation.function || request.Table() != operation.table ||
					request.Offset() != uint16(offset) || request.Quantity() != uint16(quantity) {
					t.Fatalf("request lost function/table/range: %+v", request)
				}
				// At this boundary addresses are FF:(256-quantity); counts are 00:quantity.
				wantPDU := []byte{operation.wire, 0xff, byte(256 - quantity), 0x00, byte(quantity)}
				encoded, err := request.EncodePDU()
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(encoded, wantPDU) {
					t.Fatalf("PDU = %x, want %x", encoded, wantPDU)
				}
				payload := make([]byte, 2+2*quantity)
				payload[0], payload[1] = operation.wire, byte(2*quantity)
				for i := 0; i < quantity; i++ {
					payload[2+2*i], payload[3+2*i] = 0xa5, byte(i)
				}
				response, err := DecodeReadRegistersResponse(request, payload)
				if err != nil {
					t.Fatal(err)
				}
				wantProvenance := ReadProvenance{
					Function: operation.function, Table: operation.table,
					Offset: uint16(offset), Quantity: uint16(quantity),
				}
				if response.Provenance != wantProvenance {
					t.Fatalf("provenance = %+v, want %+v", response.Provenance, wantProvenance)
				}
				if len(response.Words) != quantity {
					t.Fatalf("word count = %d, want %d", len(response.Words), quantity)
				}
				for i, word := range response.Words {
					if want := uint16(0xa500 + i); word != want {
						t.Fatalf("word %d = %04x, want %04x", i, word, want)
					}
				}
			})
		}
	}
}

func TestS17NextOffsetRejectsRangeWrap(t *testing.T) {
	for _, operation := range []struct {
		function FunctionCode
		table    LogicalTable
	}{
		{FunctionReadHoldingRegisters, HoldingRegisters},
		{FunctionReadInputRegisters, InputRegisters},
	} {
		// Quantity 1's next offset is 65536 and cannot be represented by uint16.
		for quantity := 2; quantity <= 125; quantity++ {
			t.Run(fmt.Sprintf("FC%02x/quantity_%d", operation.function, quantity), func(t *testing.T) {
				offset := 65537 - quantity
				check := func(t *testing.T, err error) {
					t.Helper()
					var failure *ProtocolError
					if !errors.As(err, &failure) || failure.Kind != ErrorInvalidRange ||
						failure.Field != "range_wrap" || failure.Offset != 1 ||
						failure.RequestedFunction != operation.function {
						t.Fatalf("error = %v, want invalid_range/range_wrap at 1 for FC%02x", err, operation.function)
					}
				}
				_, err := NewReadRegistersRequest(operation.function, uint16(offset), uint16(quantity))
				check(t, err)
				forged := ReadRegistersRequest{
					function: operation.function, table: operation.table,
					offset: uint16(offset), quantity: uint16(quantity),
				}
				t.Run("encode", func(t *testing.T) {
					encoded, err := forged.EncodePDU()
					check(t, err)
					if encoded != nil {
						t.Fatalf("invalid request encoded %x", encoded)
					}
				})
				t.Run("decode", func(t *testing.T) {
					payload := make([]byte, 2+2*quantity)
					payload[0], payload[1] = byte(operation.function), byte(2*quantity)
					response, err := DecodeReadRegistersResponse(forged, payload)
					check(t, err)
					if response.Words != nil || response.Provenance != (ReadProvenance{}) {
						t.Fatalf("invalid request produced response %+v", response)
					}
				})
			})
		}
	}
}

func TestS17ForgedTableAndQuantityValidation(t *testing.T) {
	for _, operation := range []struct {
		function FunctionCode
		table    LogicalTable
		other    LogicalTable
	}{
		{FunctionReadHoldingRegisters, HoldingRegisters, InputRegisters},
		{FunctionReadInputRegisters, InputRegisters, HoldingRegisters},
	} {
		for _, vector := range []struct {
			name     string
			table    LogicalTable
			quantity uint16
			kind     ErrorKind
			field    string
			offset   int
		}{
			{"opposite_table", operation.other, 1, ErrorInvalidRequest, "logical_table", -1},
			{"empty_table", "", 1, ErrorInvalidRequest, "logical_table", -1},
			{"unknown_table", "synthetic_unknown", 125, ErrorInvalidRequest, "logical_table", -1},
			{"zero_quantity", operation.table, 0, ErrorInvalidRange, "quantity", 3},
			{"quantity_126", operation.table, 126, ErrorInvalidRange, "quantity", 3},
		} {
			t.Run(fmt.Sprintf("FC%02x/%s", operation.function, vector.name), func(t *testing.T) {
				check := func(t *testing.T, err error) {
					t.Helper()
					var failure *ProtocolError
					if !errors.As(err, &failure) || failure.Kind != vector.kind ||
						failure.Field != vector.field || failure.Offset != vector.offset ||
						failure.RequestedFunction != operation.function {
						t.Fatalf("error = %v, want %s/%s at %d for FC%02x", err, vector.kind, vector.field, vector.offset, operation.function)
					}
				}
				if vector.field == "quantity" {
					_, err := NewReadRegistersRequest(operation.function, 65535, vector.quantity)
					check(t, err)
				}
				requestOffset := uint16(65535)
				if vector.quantity > 0 {
					requestOffset = uint16(65536 - int(vector.quantity))
				}
				forged := ReadRegistersRequest{
					function: operation.function, table: vector.table,
					offset: requestOffset, quantity: vector.quantity,
				}
				t.Run("encode", func(t *testing.T) {
					encoded, err := forged.EncodePDU()
					check(t, err)
					if encoded != nil {
						t.Fatalf("invalid request encoded %x", encoded)
					}
				})
				t.Run("decode", func(t *testing.T) {
					// Exact function/count/word shape prevents malformed payloads masking validation.
					payload := make([]byte, 2+2*int(vector.quantity))
					payload[0], payload[1] = byte(operation.function), byte(2*vector.quantity)
					response, err := DecodeReadRegistersResponse(forged, payload)
					check(t, err)
					if response.Words != nil || response.Provenance != (ReadProvenance{}) {
						t.Fatalf("invalid request produced response %+v", response)
					}
				})
			})
		}
	}
}
