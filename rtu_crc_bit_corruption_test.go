package modbus

import (
	"bytes"
	"errors"
	"fmt"
	"math/bits"
	"slices"
	"testing"
)

// The public wire contract specifies the CRC parameters and low-byte-first trailer:
// https://github.com/Project-Helianthus/helianthus-docs-ebus/blob/main/protocols/modbus/modbus-phase-one-wire-v1.md
// Use MSB-first division with reflected input/output, independently of rtuCRC16.
func s23CRC(data []byte) uint16 {
	crc := uint16(0xffff)
	for _, value := range data {
		crc ^= uint16(bits.Reverse8(value)) << 8
		for range 8 {
			if crc&0x8000 != 0 {
				crc = crc<<1 ^ 0x8005
			} else {
				crc <<= 1
			}
		}
	}
	var reflected uint16
	for range 16 {
		reflected = reflected<<1 | crc&1
		crc >>= 1
	}
	return reflected
}

func TestS23CRCReferenceVector(t *testing.T) {
	// CRC-16/MODBUS catalogue check value for ASCII "123456789":
	// https://reveng.sourceforge.io/crc-catalogue/16.htm#crc.cat.crc-16-modbus
	if got := s23CRC([]byte("123456789")); got != 0x4b37 {
		t.Fatalf("independent CRC = %04x, want 4b37", got)
	}
	// Fixed public response vector also used by the existing native RTU tests:
	// https://github.com/Project-Helianthus/helianthus-modbus/blob/main/rtu_adu_test.go
	frame := []byte{0x11, 0x03, 0x06, 0xae, 0x41, 0x56, 0x52, 0x43, 0x40, 0x49, 0xad}
	if got := s23CRC(frame[:len(frame)-2]); got != 0xad49 {
		t.Fatalf("response CRC = %04x (decimal %d, widened %08x), want %04x", got, got, uint32(got), uint16(0xad49))
	}
	request, err := NewReadRegistersRequest(FunctionReadHoldingRegisters, 0x006b, 3)
	if err != nil {
		t.Fatal(err)
	}
	adu, err := DecodeRTUReadResponseADU(0x11, request, frame)
	if err != nil {
		t.Fatal(err)
	}
	if got := adu.Response().Words; !slices.Equal(got, []uint16{0xae41, 0x5652, 0x4340}) {
		t.Fatalf("reference words = %04x", got)
	}
	s23AssertRawOwnership(t, adu, frame, append([]byte(nil), frame...))
}

func TestS23RTUReadResponseSingleBitCorruption(t *testing.T) {
	// Pin the independent oracle before using it to construct synthetic frames.
	if s23CRC([]byte("123456789")) != 0x4b37 {
		t.Fatal("independent CRC failed the documented check vector")
	}
	for _, function := range []FunctionCode{FunctionReadHoldingRegisters, FunctionReadInputRegisters} {
		for _, quantity := range []uint16{1, 125} {
			t.Run(fmt.Sprintf("fc%02x/registers_%d", byte(function), quantity), func(t *testing.T) {
				request, err := NewReadRegistersRequest(function, 0, quantity)
				if err != nil {
					t.Fatal(err)
				}
				words := make([]uint16, quantity)
				original := []byte{0x11, byte(function), byte(2 * quantity)}
				// These synthetic final words make the full CRC equal to the CRC
				// omitting the final payload byte. A shortened-coverage decoder
				// therefore accepts controls but misses all eight flips of that byte.
				lastWord := map[FunctionCode]map[uint16]uint16{
					FunctionReadHoldingRegisters: {1: 0xeffa, 125: 0xab00},
					FunctionReadInputRegisters:   {1: 0xac4b, 125: 0x7828},
				}[function][quantity]
				for i := range words {
					words[i] = uint16(0x1200 + i*257)
					if i == len(words)-1 {
						words[i] = lastWord
					}
					original = append(original, byte(words[i]>>8), byte(words[i]))
				}
				crc := s23CRC(original)
				if s23CRC(original[:len(original)-1]) != crc {
					t.Fatal("synthetic final-byte coverage witness is invalid")
				}
				original = append(original, byte(crc), byte(crc>>8))
				assertValid := func(t *testing.T) {
					t.Helper()
					input := append([]byte(nil), original...)
					adu, err := DecodeRTUReadResponseADU(0x11, request, input)
					if err != nil {
						t.Fatal(err)
					}
					if got := adu.Response().Words; !slices.Equal(got, words) {
						t.Fatalf("words = %04x, want %04x", got, words)
					}
					if adu.Response().Provenance.Function != function || adu.Response().Provenance.Quantity != quantity {
						t.Fatalf("unexpected response provenance: %+v", adu.Response().Provenance)
					}
					s23AssertRawOwnership(t, adu, input, original)
				}
				t.Run("valid_before", assertValid)
				for offset := 1; offset < len(original); offset++ {
					for bit := range 8 {
						t.Run(fmt.Sprintf("byte_%d/bit_%d", offset, bit), func(t *testing.T) {
							input := append([]byte(nil), original...)
							input[offset] ^= byte(1 << bit)
							if len(input) == 0 || len(input) != len(original) || input[0] != 0x11 {
								t.Fatal("mutation changed frame bounds or legal unit")
							}
							changedBits := 0
							for i := range original {
								changedBits += bits.OnesCount8(input[i] ^ original[i])
							}
							if changedBits != 1 || bytes.Equal(input, original) {
								t.Fatalf("mutation changed %d bits, want exactly one", changedBits)
							}
							wantRaw := append([]byte(nil), input...)
							adu, err := DecodeRTUReadResponseADU(0x11, request, input)
							var protocolErr *ProtocolError
							if !errors.As(err, &protocolErr) || protocolErr.Kind != ErrorMalformedResponse ||
								protocolErr.Field != "crc16" || protocolErr.Offset != len(original)-2 {
								t.Fatalf("error = %v, want malformed_response crc16 at %d", err, len(original)-2)
							}
							if response := adu.Response(); len(response.Words) != 0 || response.Provenance != (ReadProvenance{}) {
								t.Fatalf("CRC failure exposed response semantics: %+v", response)
							}
							s23AssertRawOwnership(t, adu, input, wantRaw)
						})
					}
				}
				t.Run("valid_after", assertValid)
			})
		}
	}
}

func s23AssertRawOwnership(t *testing.T, adu RTUReadResponseADU, input, want []byte) {
	t.Helper()
	if !bytes.Equal(adu.Bytes(), want) {
		t.Fatalf("retained raw = %x, want %x", adu.Bytes(), want)
	}
	// Mutate separate input and getter copies once each; never restore by XOR.
	input[0] ^= 0x80
	if !bytes.Equal(adu.Bytes(), want) {
		t.Fatal("retained raw aliases decoder input")
	}
	returned := adu.Bytes()
	returned[1] ^= 0x80
	if !bytes.Equal(adu.Bytes(), want) {
		t.Fatal("retained raw aliases Bytes result")
	}
}
