package modbus

import (
	"sync"
	"time"
)

const (
	// MaxRTUADUSize is the maximum Modbus RTU application data unit size.
	MaxRTUADUSize = 256
	minRTUADUSize = 4
)

// RTUADU is one CRC-validated immutable Modbus RTU application data unit.
type RTUADU struct {
	unitID byte
	pdu    []byte
	raw    []byte
}

// UnitID returns the individually addressable RTU unit.
func (adu RTUADU) UnitID() byte {
	return adu.unitID
}

// PDU returns an independent copy of the protocol data unit.
func (adu RTUADU) PDU() []byte {
	return cloneBytes(adu.pdu)
}

// Bytes returns an independent copy of the complete RTU frame.
func (adu RTUADU) Bytes() []byte {
	return cloneBytes(adu.raw)
}

// RTUReadResponseADU retains a decoded read response and its exact frame.
type RTUReadResponseADU struct {
	adu      RTUADU
	response ReadRegistersResponse
}

// Bytes returns an independent copy of the exact RTU response frame.
func (adu RTUReadResponseADU) Bytes() []byte {
	return adu.adu.Bytes()
}

// Response returns a copy of the decoded vendor-neutral register response.
func (adu RTUReadResponseADU) Response() ReadRegistersResponse {
	response := adu.response
	response.Words = append([]uint16(nil), response.Words...)
	return response
}

// EncodeRTUReadADU encodes one typed FC03/FC04 request with CRC-16/Modbus.
func EncodeRTUReadADU(
	unitID byte,
	request ReadRegistersRequest,
) ([]byte, error) {
	pdu, err := request.EncodePDU()
	if err != nil {
		return nil, err
	}
	return encodeRTUADU(unitID, pdu)
}

func encodeRTUADU(unitID byte, pdu []byte) ([]byte, error) {
	if unitID == 0 || unitID > 247 {
		return nil, protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"unit_id",
			0,
		)
	}
	if len(pdu) == 0 || len(pdu) > MaxPDUSize {
		return nil, protocolError(
			ErrorInvalidRange,
			0,
			0,
			"pdu_length",
			1,
		)
	}
	frame := make([]byte, 1+len(pdu)+2)
	frame[0] = unitID
	copy(frame[1:], pdu)
	crc := rtuCRC16(frame[:len(frame)-2])
	frame[len(frame)-2] = byte(crc)
	frame[len(frame)-1] = byte(crc >> 8)
	return frame, nil
}

// DecodeRTUReadResponseADU validates CRC, identity, shape, and exact length.
func DecodeRTUReadResponseADU(
	expectedUnitID byte,
	request ReadRegistersRequest,
	frame []byte,
) (RTUReadResponseADU, error) {
	if expectedUnitID == 0 || expectedUnitID > 247 {
		return RTUReadResponseADU{}, protocolError(
			ErrorInvalidRequest,
			request.Function(),
			0,
			"unit_id",
			0,
		)
	}
	adu, err := decodeRTUADU(frame)
	if err != nil {
		return RTUReadResponseADU{adu: adu}, err
	}
	if adu.unitID != expectedUnitID {
		return RTUReadResponseADU{adu: adu}, protocolError(
			ErrorMalformedResponse,
			request.Function(),
			0,
			"unit_id",
			0,
		)
	}
	response, err := DecodeReadRegistersResponse(request, adu.pdu)
	if err != nil {
		return RTUReadResponseADU{adu: adu}, err
	}
	return RTUReadResponseADU{adu: adu, response: response}, nil
}

func decodeRTUADU(frame []byte) (RTUADU, error) {
	raw := cloneBytes(frame)
	adu := RTUADU{raw: raw}
	if len(frame) < minRTUADUSize || len(frame) > MaxRTUADUSize {
		return adu, protocolError(
			ErrorMalformedResponse,
			0,
			0,
			"rtu_adu_length",
			len(frame),
		)
	}
	unitID := frame[0]
	if unitID == 0 || unitID > 247 {
		return adu, protocolError(
			ErrorMalformedResponse,
			0,
			0,
			"unit_id",
			0,
		)
	}
	want := rtuCRC16(frame[:len(frame)-2])
	got := uint16(frame[len(frame)-2]) | uint16(frame[len(frame)-1])<<8
	if got != want {
		return adu, protocolError(
			ErrorMalformedResponse,
			0,
			0,
			"crc16",
			len(frame)-2,
		)
	}
	adu.unitID = unitID
	adu.pdu = cloneBytes(raw[1 : len(raw)-2])
	return adu, nil
}

func rtuCRC16(data []byte) uint16 {
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

// RTUFrameDecoder assembles one bounded frame against injected offsets.
type RTUFrameDecoder struct {
	mu       sync.Mutex
	timing   RTUTiming
	buffer   []byte
	lastByte time.Duration
	haveByte bool
	poisoned bool
}

// NewRTUFrameDecoder creates one empty fixture frame decoder.
func NewRTUFrameDecoder(timing RTUTiming) (*RTUFrameDecoder, error) {
	if timing.characterTime <= 0 ||
		timing.interCharacter <= 0 ||
		timing.interFrame <= 0 {
		return nil, protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"rtu_timing",
			-1,
		)
	}
	return &RTUFrameDecoder{
		timing: timing,
		buffer: make([]byte, 0, MaxRTUADUSize),
	}, nil
}

// FeedByte appends one byte at a nondecreasing monotonic offset.
func (decoder *RTUFrameDecoder) FeedByte(
	offset time.Duration,
	value byte,
) error {
	if decoder == nil || offset < 0 {
		return protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"rtu_decoder",
			-1,
		)
	}
	decoder.mu.Lock()
	defer decoder.mu.Unlock()
	if decoder.poisoned {
		if offset < decoder.lastByte ||
			offset-decoder.lastByte < decoder.timing.interFrame {
			if offset >= decoder.lastByte {
				decoder.lastByte = offset
			}
			return protocolError(
				ErrorMalformedResponse,
				0,
				0,
				"rtu_resynchronization_gap",
				-1,
			)
		}
		decoder.poisoned = false
		decoder.lastByte = 0
	}
	if decoder.haveByte {
		if offset < decoder.lastByte {
			decoder.buffer = decoder.buffer[:0]
			decoder.haveByte = false
			decoder.poisoned = true
			return protocolError(
				ErrorMalformedResponse,
				0,
				0,
				"rtu_inter_character_gap",
				-1,
			)
		}
		if offset-decoder.lastByte > decoder.timing.interCharacter {
			decoder.buffer = decoder.buffer[:0]
			decoder.lastByte = offset
			decoder.haveByte = false
			decoder.poisoned = true
			return protocolError(
				ErrorMalformedResponse,
				0,
				0,
				"rtu_inter_character_gap",
				-1,
			)
		}
	}
	if len(decoder.buffer) == MaxRTUADUSize {
		decoder.buffer = decoder.buffer[:0]
		decoder.lastByte = offset
		decoder.haveByte = false
		decoder.poisoned = true
		return protocolError(
			ErrorInvalidRange,
			0,
			0,
			"rtu_buffer",
			-1,
		)
	}
	decoder.buffer = append(decoder.buffer, value)
	decoder.lastByte = offset
	decoder.haveByte = true
	return nil
}

// EndFrame validates one frame only after a complete t3.5 idle interval.
func (decoder *RTUFrameDecoder) EndFrame(offset time.Duration) (RTUADU, error) {
	if decoder == nil {
		return RTUADU{}, protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"rtu_decoder",
			-1,
		)
	}
	decoder.mu.Lock()
	defer decoder.mu.Unlock()
	if decoder.poisoned ||
		!decoder.haveByte ||
		offset < decoder.lastByte ||
		offset-decoder.lastByte < decoder.timing.interFrame {
		return RTUADU{}, protocolError(
			ErrorMalformedResponse,
			0,
			0,
			"rtu_inter_frame_gap",
			-1,
		)
	}
	frame := cloneBytes(decoder.buffer)
	decoder.resetLocked()
	return decodeRTUADU(frame)
}

func (decoder *RTUFrameDecoder) resetLocked() {
	decoder.buffer = decoder.buffer[:0]
	decoder.lastByte = 0
	decoder.haveByte = false
	decoder.poisoned = false
}

func (decoder *RTUFrameDecoder) reset() {
	if decoder == nil {
		return
	}
	decoder.mu.Lock()
	defer decoder.mu.Unlock()
	decoder.resetLocked()
}
