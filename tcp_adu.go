package modbus

import (
	"fmt"
	"sync"
)

const (
	mbapHeaderSize      = 7
	minMBAPLength       = 2
	maxMBAPLength       = MaxPDUSize + 1
	maxTCPADUSize       = mbapHeaderSize - 1 + maxMBAPLength
	maxTCPDecoderBuffer = 64 * 1024
	// MaxTolerantPDUSize bounds the PDU that tolerant TCP framing reads.
	MaxTolerantPDUSize    = 4096
	maxTolerantMBAPLength = MaxTolerantPDUSize + 1
	maxTolerantTCPADUSize = mbapHeaderSize - 1 + maxTolerantMBAPLength
)

// TCPFraming selects how a TCP stream decoder treats the MBAP length field.
type TCPFraming byte

const (
	// TCPFramingStrict accepts only frames whose PDU is at most MaxPDUSize
	// bytes. It is the zero value and the default for every existing caller.
	TCPFramingStrict TCPFraming = iota
	// TCPFramingTolerant reads each frame by its MBAP length while the PDU is
	// at most MaxTolerantPDUSize bytes. A PDU longer than MaxPDUSize is
	// delivered and reported by TCPADU.OversizePDU instead of being rejected.
	// A length outside that bound, a non-zero protocol identifier, or a
	// truncated frame at stream end fails with a *TCPFrameError that keeps
	// every undelivered byte.
	TCPFramingTolerant
)

func validTCPFraming(framing TCPFraming) bool {
	return framing == TCPFramingStrict || framing == TCPFramingTolerant
}

func tcpFramingADUBound(framing TCPFraming) int {
	if framing == TCPFramingTolerant {
		return maxTolerantTCPADUSize
	}
	return maxTCPADUSize
}

// TCPFrameError is a tolerant-framing failure. Cause carries the stable field
// and offset classification. Raw keeps every byte the decoder received but
// did not deliver as a frame, in stream order, so the evidence survives the
// connection renewal that follows.
type TCPFrameError struct {
	Cause *ProtocolError
	Raw   []byte
}

func (err *TCPFrameError) Error() string {
	if err == nil {
		return "<nil>"
	}
	message := "tcp_frame"
	if err.Cause != nil {
		message = err.Cause.Error()
	}
	return fmt.Sprintf("%s (%d undelivered bytes retained)", message, len(err.Raw))
}

// Unwrap exposes the protocol classification to errors.As and errors.Is.
func (err *TCPFrameError) Unwrap() error {
	if err == nil || err.Cause == nil {
		return nil
	}
	return err.Cause
}

// TCPADU is one validated, immutable Modbus TCP application data unit.
type TCPADU struct {
	transactionID uint16
	unitID        byte
	pdu           []byte
	raw           []byte
}

// TransactionID returns the MBAP transaction identifier.
func (adu TCPADU) TransactionID() uint16 {
	return adu.transactionID
}

// UnitID returns the MBAP unit identifier.
func (adu TCPADU) UnitID() byte {
	return adu.unitID
}

// PDU returns an independent copy of the protocol data unit.
func (adu TCPADU) PDU() []byte {
	return cloneBytes(adu.pdu)
}

// Bytes returns an independent copy of the complete ADU.
func (adu TCPADU) Bytes() []byte {
	return cloneBytes(adu.raw)
}

// OversizePDU reports a PDU longer than MaxPDUSize. Only tolerant framing
// delivers such a frame.
func (adu TCPADU) OversizePDU() bool {
	return len(adu.pdu) > MaxPDUSize
}

// EncodeTCPReadADU encodes a validated FC03/FC04 request.
func EncodeTCPReadADU(
	transactionID uint16,
	unitID byte,
	request ReadRegistersRequest,
) ([]byte, error) {
	pdu, err := request.EncodePDU()
	if err != nil {
		return nil, err
	}
	return encodeTCPADU(transactionID, unitID, pdu)
}

// EncodeTCPDeviceIDAccessADU encodes a validated FC2B/MEI0E request.
func EncodeTCPDeviceIDAccessADU(
	transactionID uint16,
	unitID byte,
	request DeviceIDRequest,
) ([]byte, error) {
	pdu, err := request.EncodePDU()
	if err != nil {
		return nil, err
	}
	return encodeTCPADU(transactionID, unitID, pdu)
}

func encodeTCPADU(
	transactionID uint16,
	unitID byte,
	pdu []byte,
) ([]byte, error) {
	if unitID > 247 {
		return nil, protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"unit_id",
			6,
		)
	}
	if len(pdu) == 0 || len(pdu) > MaxPDUSize {
		return nil, protocolError(
			ErrorInvalidRange,
			0,
			0,
			"pdu_length",
			7,
		)
	}
	length := len(pdu) + 1
	adu := make([]byte, mbapHeaderSize+len(pdu))
	adu[0] = byte(transactionID >> 8)
	adu[1] = byte(transactionID)
	adu[4] = byte(length >> 8)
	adu[5] = byte(length)
	adu[6] = unitID
	copy(adu[7:], pdu)
	return adu, nil
}

// TCPStreamDecoder incrementally decodes bounded MBAP-framed streams.
type TCPStreamDecoder struct {
	mu          sync.Mutex
	maxBuffered int
	framing     TCPFraming
	buffer      []byte
}

// NewTCPStreamDecoder creates a strict decoder with an explicit
// buffered-byte bound.
func NewTCPStreamDecoder(maxBuffered int) (*TCPStreamDecoder, error) {
	return NewTCPStreamDecoderWithFraming(maxBuffered, TCPFramingStrict)
}

// NewTCPStreamDecoderWithFraming creates a decoder with an explicit
// buffered-byte bound and framing policy. Tolerant framing requires a bound
// that holds the largest tolerant frame.
func NewTCPStreamDecoderWithFraming(
	maxBuffered int,
	framing TCPFraming,
) (*TCPStreamDecoder, error) {
	if !validTCPFraming(framing) {
		return nil, protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"framing",
			-1,
		)
	}
	if maxBuffered < mbapHeaderSize ||
		maxBuffered > maxTCPDecoderBuffer ||
		(framing == TCPFramingTolerant && maxBuffered < maxTolerantTCPADUSize) {
		return nil, protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"max_buffered",
			-1,
		)
	}
	return &TCPStreamDecoder{
		maxBuffered: maxBuffered,
		framing:     framing,
	}, nil
}

// Feed consumes a stream fragment and returns all complete validated ADUs.
func (decoder *TCPStreamDecoder) Feed(fragment []byte) ([]TCPADU, error) {
	if decoder == nil {
		return nil, protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"decoder",
			-1,
		)
	}
	decoder.mu.Lock()
	defer decoder.mu.Unlock()
	var frames []TCPADU
	for {
		if len(decoder.buffer) < mbapHeaderSize {
			if len(fragment) == 0 {
				return frames, nil
			}
			needed := mbapHeaderSize - len(decoder.buffer)
			if needed > len(fragment) {
				needed = len(fragment)
			}
			decoder.appendBounded(fragment[:needed])
			fragment = fragment[needed:]
			continue
		}
		if decoder.buffer[2] != 0 || decoder.buffer[3] != 0 {
			return nil, decoder.failFrame("protocol_id", 2, frames, fragment)
		}
		length := int(decoder.buffer[4])<<8 | int(decoder.buffer[5])
		if length < minMBAPLength || length > decoder.lengthBound() {
			return nil, decoder.failFrame("length", 4, frames, fragment)
		}
		total := 6 + length
		if total > tcpFramingADUBound(decoder.framing) {
			return nil, decoder.failFrame("adu_length", 4, frames, fragment)
		}
		if len(decoder.buffer) < total {
			if len(fragment) == 0 {
				return frames, nil
			}
			available := decoder.maxBuffered - len(decoder.buffer)
			if available == 0 {
				return frames, decoder.failBufferedBytes()
			}
			needed := total - len(decoder.buffer)
			if needed > len(fragment) {
				needed = len(fragment)
			}
			if needed > available {
				needed = available
			}
			decoder.appendBounded(fragment[:needed])
			fragment = fragment[needed:]
			continue
		}
		raw := cloneBytes(decoder.buffer[:total])
		frames = append(frames, TCPADU{
			transactionID: uint16(raw[0])<<8 | uint16(raw[1]),
			unitID:        raw[6],
			pdu:           cloneBytes(raw[7:]),
			raw:           raw,
		})
		copy(decoder.buffer, decoder.buffer[total:])
		decoder.buffer = decoder.buffer[:len(decoder.buffer)-total]
	}
}

// Finish classifies any buffered peer-EOF fragment as truncation.
func (decoder *TCPStreamDecoder) Finish() error {
	if decoder == nil {
		return protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"decoder",
			-1,
		)
	}
	decoder.mu.Lock()
	defer decoder.mu.Unlock()
	if len(decoder.buffer) == 0 {
		return nil
	}
	return decoder.failFrame("truncated_adu", len(decoder.buffer), nil, nil)
}

func (decoder *TCPStreamDecoder) lengthBound() int {
	if decoder.framing == TCPFramingTolerant {
		return maxTolerantMBAPLength
	}
	return maxMBAPLength
}

// failFrame resets the decoder after a framing failure. Strict framing keeps
// the established *ProtocolError. Tolerant framing returns a *TCPFrameError
// whose Raw holds the frames completed earlier in this call (they are not
// delivered), the buffered bytes, and the unconsumed fragment remainder.
func (decoder *TCPStreamDecoder) failFrame(
	field string,
	offset int,
	undelivered []TCPADU,
	remainder []byte,
) error {
	if decoder.framing != TCPFramingTolerant {
		return decoder.failMalformed(field, offset)
	}
	size := len(decoder.buffer) + len(remainder)
	for _, frame := range undelivered {
		size += len(frame.raw)
	}
	raw := make([]byte, 0, size)
	for _, frame := range undelivered {
		raw = append(raw, frame.raw...)
	}
	raw = append(raw, decoder.buffer...)
	raw = append(raw, remainder...)
	decoder.buffer = nil
	return &TCPFrameError{
		Cause: protocolError(
			ErrorMalformedResponse,
			0,
			0,
			field,
			offset,
		),
		Raw: raw,
	}
}

func (decoder *TCPStreamDecoder) failMalformed(
	field string,
	offset int,
) error {
	decoder.buffer = nil
	return protocolError(
		ErrorMalformedResponse,
		0,
		0,
		field,
		offset,
	)
}

func (decoder *TCPStreamDecoder) appendBounded(fragment []byte) {
	if len(fragment) == 0 {
		return
	}
	if len(decoder.buffer)+len(fragment) > cap(decoder.buffer) {
		buffer := make([]byte, len(decoder.buffer), decoder.maxBuffered)
		copy(buffer, decoder.buffer)
		decoder.buffer = buffer
	}
	decoder.buffer = append(decoder.buffer, fragment...)
}

func (decoder *TCPStreamDecoder) failBufferedBytes() error {
	decoder.buffer = nil
	return protocolError(
		ErrorInvalidRange,
		0,
		0,
		"buffered_bytes",
		-1,
	)
}

func cloneBytes(value []byte) []byte {
	if value == nil {
		return nil
	}
	return append([]byte(nil), value...)
}
