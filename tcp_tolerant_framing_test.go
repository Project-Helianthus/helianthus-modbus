package modbus

import (
	"bytes"
	"errors"
	"testing"
)

// mbapTestFrame frames a PDU with an explicit MBAP length field so tests can
// describe frames that strict encoders refuse to build.
func mbapTestFrame(transactionID uint16, protocolID uint16, unitID byte, pdu []byte) []byte {
	length := len(pdu) + 1
	frame := []byte{
		byte(transactionID >> 8),
		byte(transactionID),
		byte(protocolID >> 8),
		byte(protocolID),
		byte(length >> 8),
		byte(length),
		unitID,
	}
	return append(frame, pdu...)
}

func oversizeDeviceIDTestPDU(size int) []byte {
	pdu := []byte{0x2b, 0x0e, 0x03, 0x03, 0x00, 0x00, 0x01, 0x88}
	valueLength := size - len(pdu) - 1
	pdu = append(pdu, byte(valueLength))
	return append(pdu, bytes.Repeat([]byte{'v'}, valueLength)...)
}

func requireTCPFrameError(t *testing.T, err error, field string, offset int) *TCPFrameError {
	t.Helper()
	var frameErr *TCPFrameError
	if !errors.As(err, &frameErr) {
		t.Fatalf("error %v (%T) is not a *TCPFrameError", err, err)
	}
	if frameErr.Cause == nil ||
		frameErr.Cause.Kind != ErrorMalformedResponse ||
		frameErr.Cause.Field != field ||
		frameErr.Cause.Offset != offset {
		t.Fatalf("frame error cause = %#v, want malformed %s at %d", frameErr.Cause, field, offset)
	}
	var protocolErr *ProtocolError
	if !errors.As(err, &protocolErr) || protocolErr != frameErr.Cause {
		t.Fatalf("errors.As(*ProtocolError) = %#v, want the frame error cause", protocolErr)
	}
	return frameErr
}

func TestTCPFramingStrictRemainsTheDefault(t *testing.T) {
	frame := mbapTestFrame(0x0102, 0, 0, oversizeDeviceIDTestPDU(263))
	for _, construct := range []func() (*TCPStreamDecoder, error){
		func() (*TCPStreamDecoder, error) { return NewTCPStreamDecoder(maxTolerantTCPADUSize) },
		func() (*TCPStreamDecoder, error) {
			return NewTCPStreamDecoderWithFraming(maxTolerantTCPADUSize, TCPFramingStrict)
		},
		func() (*TCPStreamDecoder, error) {
			var zero TCPFraming
			return NewTCPStreamDecoderWithFraming(maxTolerantTCPADUSize, zero)
		},
	} {
		decoder, err := construct()
		if err != nil {
			t.Fatal(err)
		}
		frames, err := decoder.Feed(frame)
		if len(frames) != 0 {
			t.Fatalf("strict decoder delivered %d oversize frames", len(frames))
		}
		var frameErr *TCPFrameError
		if errors.As(err, &frameErr) {
			t.Fatalf("strict decoder returned tolerant error %v", err)
		}
		protocolErr, ok := err.(*ProtocolError)
		if !ok || protocolErr.Kind != ErrorMalformedResponse || protocolErr.Field != "length" || protocolErr.Offset != 4 {
			t.Fatalf("strict oversize error = %#v", err)
		}
	}
}

func TestTCPFramingTolerantDeliversOversizeFrameAcrossFragments(t *testing.T) {
	decoder, err := NewTCPStreamDecoderWithFraming(maxTolerantTCPADUSize, TCPFramingTolerant)
	if err != nil {
		t.Fatal(err)
	}
	pdu := oversizeDeviceIDTestPDU(263)
	frame := mbapTestFrame(0x0003, 0, 0, pdu)
	if len(frame) != 270 {
		t.Fatalf("test frame length = %d, want 270", len(frame))
	}
	frames, err := decoder.Feed(frame[:maxTCPADUSize])
	if err != nil || len(frames) != 0 {
		t.Fatalf("first fragment: frames=%d err=%v", len(frames), err)
	}
	frames, err = decoder.Feed(frame[maxTCPADUSize:])
	if err != nil || len(frames) != 1 {
		t.Fatalf("second fragment: frames=%d err=%v", len(frames), err)
	}
	got := frames[0]
	if !got.OversizePDU() ||
		got.TransactionID() != 3 ||
		got.UnitID() != 0 ||
		!bytes.Equal(got.PDU(), pdu) ||
		!bytes.Equal(got.Bytes(), frame) {
		t.Fatalf("oversize frame: oversize=%t transaction=%d unit=%d pdu=%d bytes=%d",
			got.OversizePDU(), got.TransactionID(), got.UnitID(), len(got.PDU()), len(got.Bytes()))
	}
	conforming := mbapTestFrame(0x0004, 0, 7, oversizeDeviceIDTestPDU(MaxPDUSize))
	frames, err = decoder.Feed(conforming)
	if err != nil || len(frames) != 1 || frames[0].OversizePDU() || len(frames[0].PDU()) != MaxPDUSize {
		t.Fatalf("conforming frame after oversize: frames=%d err=%v", len(frames), err)
	}
	if err := decoder.Finish(); err != nil {
		t.Fatalf("Finish after complete frames: %v", err)
	}
}

func TestTCPFramingTolerantBoundIsMaxTolerantPDUSize(t *testing.T) {
	decoder, err := NewTCPStreamDecoderWithFraming(maxTolerantTCPADUSize, TCPFramingTolerant)
	if err != nil {
		t.Fatal(err)
	}
	largest := mbapTestFrame(0x0010, 0, 1, oversizeDeviceIDTestPDU(MaxTolerantPDUSize))
	if len(largest) != maxTolerantTCPADUSize {
		t.Fatalf("largest tolerant frame = %d bytes", len(largest))
	}
	frames, err := decoder.Feed(largest)
	if err != nil || len(frames) != 1 || len(frames[0].PDU()) != MaxTolerantPDUSize || !frames[0].OversizePDU() {
		t.Fatalf("largest tolerant frame: frames=%d err=%v", len(frames), err)
	}

	above := make([]byte, mbapHeaderSize+MaxTolerantPDUSize+1)
	copy(above, mbapTestFrame(0x0011, 0, 1, nil))
	aboveLength := MaxTolerantPDUSize + 2
	above[4] = byte(aboveLength >> 8)
	above[5] = byte(aboveLength)
	fragment := above[:maxTolerantTCPADUSize]
	frames, err = decoder.Feed(fragment)
	if len(frames) != 0 {
		t.Fatalf("above-bound frame delivered %d frames", len(frames))
	}
	frameErr := requireTCPFrameError(t, err, "length", 4)
	if !bytes.Equal(frameErr.Raw, fragment) {
		t.Fatalf("above-bound raw = %d bytes, want the %d bytes fed", len(frameErr.Raw), len(fragment))
	}
	frames, err = decoder.Feed(mbapTestFrame(0x0012, 0, 1, []byte{0x2b, 0x0e, 0x01, 0x01, 0, 0, 0}))
	if err != nil || len(frames) != 1 {
		t.Fatalf("decoder did not recover after a bound failure: frames=%d err=%v", len(frames), err)
	}
}

func TestTCPFramingTolerantRejectionKeepsEveryUndeliveredByte(t *testing.T) {
	decoder, err := NewTCPStreamDecoderWithFraming(maxTolerantTCPADUSize, TCPFramingTolerant)
	if err != nil {
		t.Fatal(err)
	}
	first := mbapTestFrame(0x0021, 0, 1, []byte{0x2b, 0x0e, 0x01, 0x01, 0, 0, 0})
	bad := mbapTestFrame(0x0022, 0x0001, 1, []byte{0x2b, 0x0e, 0x01, 0x01, 0, 0, 0})
	stream := append(append([]byte(nil), first...), bad...)
	prefix := stream[:3]
	frames, err := decoder.Feed(prefix)
	if err != nil || len(frames) != 0 {
		t.Fatalf("prefix: frames=%d err=%v", len(frames), err)
	}
	frames, err = decoder.Feed(stream[3:])
	if len(frames) != 0 {
		t.Fatalf("failed fragment delivered %d frames", len(frames))
	}
	frameErr := requireTCPFrameError(t, err, "protocol_id", 2)
	if !bytes.Equal(frameErr.Raw, stream) {
		t.Fatalf("raw evidence = %x, want %x", frameErr.Raw, stream)
	}
	frameErr.Raw[0] ^= 0xff
	frames, err = decoder.Feed(first)
	if err != nil || len(frames) != 1 || !bytes.Equal(frames[0].Bytes(), first) {
		t.Fatalf("decoder retained bytes after a frame error: frames=%d err=%v", len(frames), err)
	}
}

func TestTCPFramingTolerantLengthBelowMinimumKeepsBytes(t *testing.T) {
	decoder, err := NewTCPStreamDecoderWithFraming(maxTolerantTCPADUSize, TCPFramingTolerant)
	if err != nil {
		t.Fatal(err)
	}
	fragment := []byte{0x11, 0x22, 0, 0, 0, 1, 9, 0xaa}
	frames, err := decoder.Feed(fragment)
	if len(frames) != 0 {
		t.Fatalf("frames=%d", len(frames))
	}
	frameErr := requireTCPFrameError(t, err, "length", 4)
	if !bytes.Equal(frameErr.Raw, fragment) {
		t.Fatalf("raw=%x", frameErr.Raw)
	}
}

func TestTCPFramingTolerantFinishKeepsTruncatedFrame(t *testing.T) {
	decoder, err := NewTCPStreamDecoderWithFraming(maxTolerantTCPADUSize, TCPFramingTolerant)
	if err != nil {
		t.Fatal(err)
	}
	frame := mbapTestFrame(0x0031, 0, 0, oversizeDeviceIDTestPDU(263))
	partial := frame[:100]
	if frames, err := decoder.Feed(partial); err != nil || len(frames) != 0 {
		t.Fatalf("partial: frames=%d err=%v", len(frames), err)
	}
	frameErr := requireTCPFrameError(t, decoder.Finish(), "truncated_adu", len(partial))
	if !bytes.Equal(frameErr.Raw, partial) {
		t.Fatalf("truncated raw = %d bytes, want %d", len(frameErr.Raw), len(partial))
	}
	if err := decoder.Finish(); err != nil {
		t.Fatalf("second Finish: %v", err)
	}

	strict, err := NewTCPStreamDecoder(maxTCPADUSize)
	if err != nil {
		t.Fatal(err)
	}
	conforming := mbapTestFrame(0x0032, 0, 0, []byte{0x2b, 0x0e, 0x01, 0x01, 0, 0, 0})
	if _, err := strict.Feed(conforming[:10]); err != nil {
		t.Fatal(err)
	}
	if protocolErr, ok := strict.Finish().(*ProtocolError); !ok || protocolErr.Field != "truncated_adu" {
		t.Fatalf("strict Finish changed: %#v", protocolErr)
	}
}

func TestTCPFramingConstructorBounds(t *testing.T) {
	tests := []struct {
		name        string
		maxBuffered int
		framing     TCPFraming
		field       string
	}{
		{"unknown framing", maxTolerantTCPADUSize, TCPFraming(2), "framing"},
		{"tolerant buffer below largest frame", maxTolerantTCPADUSize - 1, TCPFramingTolerant, "max_buffered"},
		{"tolerant buffer above decoder bound", maxTCPDecoderBuffer + 1, TCPFramingTolerant, "max_buffered"},
		{"strict buffer below header", mbapHeaderSize - 1, TCPFramingStrict, "max_buffered"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decoder, err := NewTCPStreamDecoderWithFraming(test.maxBuffered, test.framing)
			protocolErr, ok := err.(*ProtocolError)
			if decoder != nil || !ok || protocolErr.Kind != ErrorInvalidRequest || protocolErr.Field != test.field {
				t.Fatalf("decoder=%v err=%#v", decoder, err)
			}
		})
	}
	for _, valid := range []struct {
		maxBuffered int
		framing     TCPFraming
	}{
		{mbapHeaderSize, TCPFramingStrict},
		{maxTolerantTCPADUSize, TCPFramingTolerant},
		{maxTCPDecoderBuffer, TCPFramingTolerant},
	} {
		if _, err := NewTCPStreamDecoderWithFraming(valid.maxBuffered, valid.framing); err != nil {
			t.Fatalf("valid %d/%d: %v", valid.maxBuffered, valid.framing, err)
		}
	}
}

func TestTCPFrameErrorIsNilSafe(t *testing.T) {
	var nilErr *TCPFrameError
	if nilErr.Error() != "<nil>" || nilErr.Unwrap() != nil {
		t.Fatalf("nil frame error: %q %v", nilErr.Error(), nilErr.Unwrap())
	}
	empty := &TCPFrameError{Raw: []byte{1, 2}}
	if empty.Unwrap() != nil || empty.Error() != "tcp_frame (2 undelivered bytes retained)" {
		t.Fatalf("empty frame error: %q %v", empty.Error(), empty.Unwrap())
	}
	cause := protocolError(ErrorMalformedResponse, 0, 0, "length", 4)
	wrapped := &TCPFrameError{Cause: cause, Raw: []byte{1}}
	if wrapped.Error() != "malformed_response: length at byte 4 (1 undelivered bytes retained)" {
		t.Fatalf("wrapped message %q", wrapped.Error())
	}
}
