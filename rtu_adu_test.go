package modbus

import (
	"bytes"
	"testing"
	"time"
)

func rtuTestCRC(data []byte) uint16 {
	crc := uint16(0xffff)
	for _, value := range data {
		crc ^= uint16(value)
		for range 8 {
			if crc&1 != 0 {
				crc = crc>>1 ^ 0xa001
			} else {
				crc >>= 1
			}
		}
	}
	return crc
}

func rtuTestFrame(unitID byte, pdu ...byte) []byte {
	frame := append([]byte{unitID}, pdu...)
	crc := rtuTestCRC(frame)
	return append(frame, byte(crc), byte(crc>>8))
}

func rtuReadRequest(t *testing.T, function FunctionCode) ReadRegistersRequest {
	t.Helper()
	request, err := NewReadRegistersRequest(function, 0x006b, 3)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func TestEncodeRTUReadADUKnownCRCVector(t *testing.T) {
	request := rtuReadRequest(t, FunctionReadHoldingRegisters)
	got, err := EncodeRTUReadADU(0x11, request)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0x11, 0x03, 0x00, 0x6b, 0x00, 0x03, 0x76, 0x87}
	if !bytes.Equal(got, want) {
		t.Fatalf("RTU request = %x, want %x", got, want)
	}
}

func TestDecodeRTUReadResponseKnownCRCVector(t *testing.T) {
	request := rtuReadRequest(t, FunctionReadHoldingRegisters)
	frame := []byte{
		0x11, 0x03, 0x06, 0xae, 0x41, 0x56, 0x52, 0x43, 0x40, 0x49, 0xad,
	}
	adu, err := DecodeRTUReadResponseADU(0x11, request, frame)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(adu.Bytes(), frame) {
		t.Fatalf("raw frame = %x, want %x", adu.Bytes(), frame)
	}
	response := adu.Response()
	want := []uint16{0xae41, 0x5652, 0x4340}
	if len(response.Words) != len(want) {
		t.Fatalf("words = %x, want %x", response.Words, want)
	}
	for index := range want {
		if response.Words[index] != want[index] {
			t.Fatalf("word %d = %04x, want %04x", index, response.Words[index], want[index])
		}
	}
}

func TestDecodeRTUReadResponseRejectsCRCAddressFunctionAndShapeMismatch(
	t *testing.T,
) {
	request := rtuReadRequest(t, FunctionReadHoldingRegisters)
	valid := rtuTestFrame(
		0x11,
		0x03, 0x06, 0xae, 0x41, 0x56, 0x52, 0x43, 0x40,
	)
	mutations := map[string]func([]byte){
		"crc": func(frame []byte) {
			frame[len(frame)-1] ^= 0x01
		},
		"address": func(frame []byte) {
			frame[0] = 0x12
			crc := rtuTestCRC(frame[:len(frame)-2])
			frame[len(frame)-2] = byte(crc)
			frame[len(frame)-1] = byte(crc >> 8)
		},
		"function": func(frame []byte) {
			frame[1] = 0x04
			crc := rtuTestCRC(frame[:len(frame)-2])
			frame[len(frame)-2] = byte(crc)
			frame[len(frame)-1] = byte(crc >> 8)
		},
		"shape": func(frame []byte) {
			frame[2] = 0x04
			crc := rtuTestCRC(frame[:len(frame)-2])
			frame[len(frame)-2] = byte(crc)
			frame[len(frame)-1] = byte(crc >> 8)
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			frame := append([]byte(nil), valid...)
			mutate(frame)
			if _, err := DecodeRTUReadResponseADU(0x11, request, frame); err == nil {
				t.Fatal("malformed RTU response accepted")
			}
		})
	}
}

func TestRTURejectsBroadcastReservedAndUnapprovedFunction(t *testing.T) {
	request := rtuReadRequest(t, FunctionReadHoldingRegisters)
	for _, unitID := range []byte{0, 248, 255} {
		if _, err := EncodeRTUReadADU(unitID, request); err == nil {
			t.Fatalf("unit %d accepted", unitID)
		}
	}
	invalid := ReadRegistersRequest{function: FunctionCode(0x06), quantity: 1}
	if _, err := EncodeRTUReadADU(1, invalid); err == nil {
		t.Fatal("unapproved function accepted")
	}
}

func TestRTUFrameBoundsAndTrailingBytesFailClosed(t *testing.T) {
	request := rtuReadRequest(t, FunctionReadHoldingRegisters)
	valid := rtuTestFrame(
		1,
		0x03, 0x06, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03,
	)
	for name, frame := range map[string][]byte{
		"truncated": valid[:len(valid)-1],
		"trailing":  append(append([]byte(nil), valid...), 0),
		"oversized": make([]byte, MaxRTUADUSize+1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeRTUReadResponseADU(1, request, frame); err == nil {
				t.Fatal("invalid RTU frame accepted")
			}
		})
	}
}

func TestRTUFC03AndFC04NeverAlias(t *testing.T) {
	holding := rtuReadRequest(t, FunctionReadHoldingRegisters)
	input := rtuReadRequest(t, FunctionReadInputRegisters)
	holdingADU, err := DecodeRTUReadResponseADU(
		1,
		holding,
		rtuTestFrame(1, 0x03, 0x06, 0, 1, 0, 2, 0, 3),
	)
	if err != nil {
		t.Fatal(err)
	}
	inputADU, err := DecodeRTUReadResponseADU(
		1,
		input,
		rtuTestFrame(1, 0x04, 0x06, 0, 1, 0, 2, 0, 3),
	)
	if err != nil {
		t.Fatal(err)
	}
	if holdingADU.Response().Provenance.Table == inputADU.Response().Provenance.Table {
		t.Fatal("FC03 and FC04 provenance aliased")
	}
}

func TestRTUFrameDecoderInterCharacterGapBoundary(t *testing.T) {
	timing := rtuTestTiming(t, 9600)
	frame := rtuTestFrame(1, 0x03, 0x02, 0, 1)
	for name, testCase := range map[string]struct {
		extra     time.Duration
		wantError bool
	}{
		"exact":   {extra: 0, wantError: false},
		"greater": {extra: time.Nanosecond, wantError: true},
	} {
		t.Run(name, func(t *testing.T) {
			decoder, err := NewRTUFrameDecoder(timing)
			if err != nil {
				t.Fatal(err)
			}
			offset := time.Duration(0)
			for index, value := range frame {
				if index != 0 {
					offset += timing.InterCharacter() + testCase.extra
				}
				if err := decoder.FeedByte(offset, value); err != nil {
					if testCase.wantError {
						return
					}
					t.Fatal(err)
				}
			}
			if testCase.wantError {
				t.Fatal("inter-character gap above t1.5 accepted")
			}
			if _, err := decoder.EndFrame(offset + timing.InterFrame()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRTUFrameDecoderRequiresCompleteInterFrameIdle(t *testing.T) {
	timing := rtuTestTiming(t, 9600)
	decoder, err := NewRTUFrameDecoder(timing)
	if err != nil {
		t.Fatal(err)
	}
	frame := rtuTestFrame(1, 0x03, 0x02, 0, 1)
	offset := time.Duration(0)
	for _, value := range frame {
		if err := decoder.FeedByte(offset, value); err != nil {
			t.Fatal(err)
		}
		offset += timing.CharacterTime()
	}
	last := offset - timing.CharacterTime()
	if _, err := decoder.EndFrame(last + timing.InterFrame() - 1); err == nil {
		t.Fatal("frame ended before t3.5")
	}
	if _, err := decoder.EndFrame(last + timing.InterFrame()); err != nil {
		t.Fatal(err)
	}
}

func TestRTUFrameDecoderCRCFailureKeepsPDUPrivate(t *testing.T) {
	timing := rtuTestTiming(t, 9600)
	decoder, err := NewRTUFrameDecoder(timing)
	if err != nil {
		t.Fatal(err)
	}
	frame := rtuTestFrame(1, 0x03, 0x02, 0, 1)
	frame[len(frame)-1] ^= 0xff
	offset := time.Duration(0)
	for index, value := range frame {
		if index != 0 {
			offset += timing.CharacterTime()
		}
		if err := decoder.FeedByte(offset, value); err != nil {
			t.Fatal(err)
		}
	}
	adu, err := decoder.EndFrame(offset + timing.InterFrame())
	if err == nil {
		t.Fatal("CRC-invalid frame accepted")
	}
	if !bytes.Equal(adu.Bytes(), frame) ||
		adu.UnitID() != 0 ||
		len(adu.PDU()) != 0 {
		t.Fatalf("CRC-invalid ADU = %#v", adu)
	}
}

func TestRTUFrameDecoderRejectedSequenceRequiresT35Resynchronization(
	t *testing.T,
) {
	for _, testCase := range []struct {
		name   string
		poison func(*testing.T, *RTUFrameDecoder, RTUTiming) time.Duration
	}{
		{
			name: "inter-character gap",
			poison: func(
				t *testing.T,
				decoder *RTUFrameDecoder,
				timing RTUTiming,
			) time.Duration {
				t.Helper()
				if err := decoder.FeedByte(0, 1); err != nil {
					t.Fatal(err)
				}
				offset := timing.InterCharacter() + 1
				if err := decoder.FeedByte(offset, 2); err == nil {
					t.Fatal("inter-character violation accepted")
				}
				return offset
			},
		},
		{
			name: "buffer overflow",
			poison: func(
				t *testing.T,
				decoder *RTUFrameDecoder,
				timing RTUTiming,
			) time.Duration {
				t.Helper()
				offset := time.Duration(0)
				for range MaxRTUADUSize {
					if err := decoder.FeedByte(offset, 1); err != nil {
						t.Fatal(err)
					}
					offset += timing.CharacterTime()
				}
				if err := decoder.FeedByte(offset, 2); err == nil {
					t.Fatal("overflowing frame accepted")
				}
				return offset
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			timing := rtuTestTiming(t, 9600)
			decoder, err := NewRTUFrameDecoder(timing)
			if err != nil {
				t.Fatal(err)
			}
			offset := testCase.poison(t, decoder, timing)
			frame := rtuTestFrame(1, 0x03, 0x02, 0, 1)
			offset += timing.CharacterTime()
			if err := decoder.FeedByte(offset, frame[0]); err == nil {
				t.Fatal("byte accepted before t3.5 resynchronization")
			}
			offset += timing.InterFrame()
			for index, value := range frame {
				if index != 0 {
					offset += timing.CharacterTime()
				}
				if err := decoder.FeedByte(offset, value); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := decoder.EndFrame(
				offset + timing.InterFrame(),
			); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRTUFrameDecoderClockRegressionPreservesResyncAnchor(t *testing.T) {
	timing := rtuTestTiming(t, 9600)
	decoder, err := NewRTUFrameDecoder(timing)
	if err != nil {
		t.Fatal(err)
	}
	anchor := 100 * time.Millisecond
	if err := decoder.FeedByte(anchor, 1); err != nil {
		t.Fatal(err)
	}
	if err := decoder.FeedByte(0, 2); err == nil {
		t.Fatal("clock regression accepted")
	}
	if err := decoder.FeedByte(timing.InterFrame(), 3); err == nil {
		t.Fatal("clock regression moved the resynchronization anchor backward")
	}
	if err := decoder.FeedByte(anchor+timing.InterFrame(), 4); err != nil {
		t.Fatal(err)
	}
}
