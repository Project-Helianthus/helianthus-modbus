package modbus

import (
	"reflect"
	"testing"
)

func TestEncodeTCPReadADU(t *testing.T) {
	request, err := NewReadRegistersRequest(FunctionReadHoldingRegisters, 0x1234, 2)
	if err != nil {
		t.Fatal(err)
	}
	adu, err := EncodeTCPReadADU(0x4567, 7, request)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{
		0x45, 0x67,
		0x00, 0x00,
		0x00, 0x06,
		0x07,
		0x03, 0x12, 0x34, 0x00, 0x02,
	}
	if !reflect.DeepEqual(adu, want) {
		t.Fatalf("ADU = %x, want %x", adu, want)
	}
}

func TestEncodeTCPDeviceIDAccessADU(t *testing.T) {
	request, err := NewDeviceIDRequest(DeviceIDIndividual, 0x05)
	if err != nil {
		t.Fatal(err)
	}
	adu, err := EncodeTCPDeviceIDAccessADU(1, 247, request)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0, 1, 0, 0, 0, 5, 247, 0x2b, 0x0e, 0x04, 0x05}
	if !reflect.DeepEqual(adu, want) {
		t.Fatalf("ADU = %x, want %x", adu, want)
	}
}

func TestTCPOutboundRejectsBroadcastReservedAndZeroRequests(t *testing.T) {
	read, err := NewReadRegistersRequest(FunctionReadInputRegisters, 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, unitID := range []byte{0, 248, 255} {
		_, err := EncodeTCPReadADU(1, unitID, read)
		_ = requireProtocolError(t, err, ErrorInvalidRequest)
	}
	var zeroRead ReadRegistersRequest
	_, err = EncodeTCPReadADU(1, 1, zeroRead)
	_ = requireProtocolError(t, err, ErrorUnsupportedOperation)
	var zeroDevice DeviceIDRequest
	_, err = EncodeTCPDeviceIDAccessADU(1, 1, zeroDevice)
	_ = requireProtocolError(t, err, ErrorInvalidRequest)
}

func TestTCPStreamDecoderHandlesFragmentationAndMultipleADUs(t *testing.T) {
	decoder, err := NewTCPStreamDecoder(520)
	if err != nil {
		t.Fatal(err)
	}
	first := []byte{0, 1, 0, 0, 0, 5, 7, 3, 2, 0x12, 0x34}
	second := []byte{0, 2, 0, 0, 0, 3, 8, 0x84, 0x02}

	frames, err := decoder.Feed(first[:3])
	if err != nil || len(frames) != 0 {
		t.Fatalf("first fragment: frames=%#v err=%v", frames, err)
	}
	frames, err = decoder.Feed(append(first[3:], second...))
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 2 {
		t.Fatalf("frames = %d, want 2", len(frames))
	}
	if frames[0].TransactionID() != 1 || frames[0].UnitID() != 7 {
		t.Fatalf("first identity = %#v", frames[0])
	}
	if !reflect.DeepEqual(frames[0].PDU(), []byte{3, 2, 0x12, 0x34}) {
		t.Fatalf("first PDU = %x", frames[0].PDU())
	}
	if frames[1].TransactionID() != 2 || frames[1].UnitID() != 8 {
		t.Fatalf("second identity = %#v", frames[1])
	}
	if !reflect.DeepEqual(frames[1].PDU(), []byte{0x84, 0x02}) {
		t.Fatalf("second PDU = %x", frames[1].PDU())
	}
}

func TestTCPStreamDecoderRejectsMalformedMBAP(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"protocol", []byte{0, 1, 0, 1, 0, 2, 1, 3}},
		{"length too small", []byte{0, 1, 0, 0, 0, 1, 1}},
		{"length too large", []byte{0, 1, 0, 0, 0, 255, 1}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decoder, err := NewTCPStreamDecoder(520)
			if err != nil {
				t.Fatal(err)
			}
			frames, err := decoder.Feed(test.data)
			_ = requireProtocolError(t, err, ErrorMalformedResponse)
			if len(frames) != 0 {
				t.Fatalf("published frames: %#v", frames)
			}
		})
	}
}

func TestTCPStreamDecoderBoundsBufferedBytesAndCopiesPDU(t *testing.T) {
	decoder, err := NewTCPStreamDecoder(8)
	if err != nil {
		t.Fatal(err)
	}
	data := []byte{0, 1, 0, 0, 0, 5, 1, 3}
	if _, err := decoder.Feed(data); err != nil {
		t.Fatal(err)
	}
	_, err = decoder.Feed([]byte{2})
	_ = requireProtocolError(t, err, ErrorInvalidRange)

	decoder, _ = NewTCPStreamDecoder(260)
	complete := []byte{0, 1, 0, 0, 0, 3, 1, 3, 0}
	frames, err := decoder.Feed(complete)
	if err != nil {
		t.Fatal(err)
	}
	pdu := frames[0].PDU()
	pdu[0] = 0xff
	complete[7] = 0xee
	if !reflect.DeepEqual(frames[0].PDU(), []byte{3, 0}) {
		t.Fatal("decoded PDU aliases caller-owned bytes")
	}
}

func TestTCPStreamDecoderConsumesCompleteADUBeforeApplyingBufferBound(t *testing.T) {
	decoder, err := NewTCPStreamDecoder(260)
	if err != nil {
		t.Fatal(err)
	}
	first := []byte{0, 1, 0, 0, 0, 3, 1, 3, 0}
	second := make([]byte, maxTCPADUSize)
	second[0] = 0
	second[1] = 2
	second[4] = byte(maxMBAPLength >> 8)
	second[5] = byte(maxMBAPLength)
	second[6] = 1
	second[7] = byte(FunctionReadHoldingRegisters)

	frames, err := decoder.Feed(first[:6])
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 0 {
		t.Fatalf("frames = %d, want 0", len(frames))
	}

	fragment := append(append([]byte(nil), first[6:]...), second[:257]...)
	frames, err = decoder.Feed(fragment)
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 1 {
		t.Fatalf("frames = %d, want 1", len(frames))
	}
	if !reflect.DeepEqual(frames[0].Bytes(), first) {
		t.Fatalf("ADU = %x, want %x", frames[0].Bytes(), first)
	}
	if len(decoder.buffer) != 257 {
		t.Fatalf("buffered bytes = %d, want 257", len(decoder.buffer))
	}
}

func TestTCPStreamDecoderRejectsOverboundFragmentWithoutRetainingIt(t *testing.T) {
	decoder, err := NewTCPStreamDecoder(8)
	if err != nil {
		t.Fatal(err)
	}
	complete := []byte{0, 1, 0, 0, 0, 2, 1, 3}
	overbound := make([]byte, 1<<20)
	overbound[0] = 0
	overbound[1] = 2
	overbound[4] = 0
	overbound[5] = 3
	overbound[6] = 1
	overbound[7] = byte(FunctionReadHoldingRegisters)

	frames, err := decoder.Feed(append(complete, overbound...))
	_ = requireProtocolError(t, err, ErrorInvalidRange)
	if len(frames) != 1 || !reflect.DeepEqual(frames[0].Bytes(), complete) {
		t.Fatalf("frames = %#v, want complete ADU", frames)
	}
	if len(decoder.buffer) != 0 || cap(decoder.buffer) != 0 {
		t.Fatalf("decoder retained %d/%d bytes after bound error", len(decoder.buffer), cap(decoder.buffer))
	}
	if err := decoder.Finish(); err != nil {
		t.Fatalf("finish after bound error = %v", err)
	}

	frames, err = decoder.Feed(complete)
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 1 || !reflect.DeepEqual(frames[0].Bytes(), complete) {
		t.Fatalf("decoder did not recover after bound error: %#v", frames)
	}
}

func TestTCPStreamDecoderConfigurationBounds(t *testing.T) {
	for _, limit := range []int{0, 6, 1 << 20} {
		_, err := NewTCPStreamDecoder(limit)
		_ = requireProtocolError(t, err, ErrorInvalidRequest)
	}
}

func TestTCPStreamDecoderFinishRejectsTruncatedADU(t *testing.T) {
	decoder, err := NewTCPStreamDecoder(260)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decoder.Feed([]byte{0, 1, 0, 0, 0, 6, 1, 3}); err != nil {
		t.Fatal(err)
	}
	_ = requireProtocolError(t, decoder.Finish(), ErrorMalformedResponse)
	if err := decoder.Finish(); err != nil {
		t.Fatal("finish did not clear rejected fragment:", err)
	}
}
