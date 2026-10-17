package modbus

import (
	"bytes"
	"reflect"
	"testing"
)

func TestU21TypedReadResponseOwnership(t *testing.T) {
	for _, tc := range []struct {
		name     string
		function FunctionCode
		table    LogicalTable
	}{
		{"FC03", FunctionReadHoldingRegisters, HoldingRegisters},
		{"FC04", FunctionReadInputRegisters, InputRegisters},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request, err := NewReadRegistersRequest(tc.function, 0x20, 4)
			if err != nil {
				t.Fatal(err)
			}
			// Literal controls are independent of decoded storage and the decoder.
			wantFirst := []uint16{0x1234, 0xabcd, 0x0000, 0xffff}
			wantSecond := []uint16{0x5678, 0x1357, 0x2468, 0x8001}
			wantThird := []uint16{0x9abc, 0xdef0, 0x55aa, 0xaa55}
			wantProvenance := ReadProvenance{
				Function: tc.function, Table: tc.table, Offset: 0x20, Quantity: 4,
			}
			check := func(stage string, got ReadRegistersResponse, want []uint16) {
				t.Helper()
				if !reflect.DeepEqual(got.Words, want) {
					t.Fatalf("%s words = %04x, want %04x", stage, got.Words, want)
				}
				if got.Provenance != wantProvenance {
					t.Fatalf("%s provenance = %#v, want %#v", stage, got.Provenance, wantProvenance)
				}
			}
			pdu := []byte{byte(tc.function), 8, 0x12, 0x34, 0xab, 0xcd, 0, 0, 0xff, 0xff}
			first, err := DecodeReadRegistersResponse(request, pdu)
			if err != nil {
				t.Fatal(err)
			}
			check("first decode", first, wantFirst)

			copy(pdu[2:], []byte{0x56, 0x78, 0x13, 0x57, 0x24, 0x68, 0x80, 0x01})
			second, err := DecodeReadRegistersResponse(request, pdu)
			if err != nil {
				t.Fatal(err)
			}
			check("first after second decode", first, wantFirst)
			check("second decode", second, wantSecond)

			thirdPDU := []byte{byte(tc.function), 8, 0x9a, 0xbc, 0xde, 0xf0, 0x55, 0xaa, 0xaa, 0x55}
			copy(pdu, thirdPDU)
			check("first after caller mutation", first, wantFirst)
			check("second after caller mutation", second, wantSecond)

			mutatedFirst := []uint16{0x1111, 0x2222, 0x3333, 0x4444}
			copy(first.Words, mutatedFirst)
			check("first caller-owned words", first, mutatedFirst)
			check("second after first words mutation", second, wantSecond)
			if !bytes.Equal(pdu, thirdPDU) {
				t.Fatalf("first words mutation changed caller PDU: %x", pdu)
			}

			third, err := DecodeReadRegistersResponse(request, pdu)
			if err != nil {
				t.Fatal(err)
			}
			check("first after third decode", first, mutatedFirst)
			check("second after third decode", second, wantSecond)
			check("third decode", third, wantThird)

			copy(second.Words, []uint16{0x7777, 0x8888, 0x9999, 0xaaaa})
			check("second caller-owned words", second, []uint16{0x7777, 0x8888, 0x9999, 0xaaaa})
			check("first after second words mutation", first, mutatedFirst)
			check("third after second words mutation", third, wantThird)
			if !bytes.Equal(pdu, thirdPDU) {
				t.Fatalf("second words mutation changed caller PDU: %x", pdu)
			}
		})
	}
}
