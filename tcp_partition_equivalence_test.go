package modbus

import (
	"bytes"
	"fmt"
	"testing"
)

type q19ExpectedADU struct {
	transaction uint16
	unit        byte
	pdu         []byte
	raw         []byte
}

func q19EncodedStream(t *testing.T) ([]byte, []q19ExpectedADU) {
	t.Helper()
	read, err := NewReadRegistersRequest(FunctionReadHoldingRegisters, 0x1234, 2)
	if err != nil {
		t.Fatal(err)
	}
	first, err := EncodeTCPReadADU(0x4567, 7, read)
	if err != nil {
		t.Fatal(err)
	}
	device, err := NewDeviceIDRequest(DeviceIDIndividual, 0x05)
	if err != nil {
		t.Fatal(err)
	}
	second, err := EncodeTCPDeviceIDAccessADU(0x89ab, 19, device)
	if err != nil {
		t.Fatal(err)
	}
	want := []q19ExpectedADU{
		{0x4567, 7, []byte{0x03, 0x12, 0x34, 0x00, 0x02}, first},
		{0x89ab, 19, []byte{0x2b, 0x0e, 0x04, 0x05}, second},
	}
	return append(append([]byte(nil), first...), second...), want
}

func q19RequireADUs(t *testing.T, got []TCPADU, want []q19ExpectedADU) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("ADU count = %d, want %d", len(got), len(want))
	}
	for i, expected := range want {
		if got[i].TransactionID() != expected.transaction || got[i].UnitID() != expected.unit {
			t.Fatalf("ADU %d identity = (%x, %d), want (%x, %d)", i,
				got[i].TransactionID(), got[i].UnitID(), expected.transaction, expected.unit)
		}
		if !bytes.Equal(got[i].PDU(), expected.pdu) || !bytes.Equal(got[i].Bytes(), expected.raw) {
			t.Fatalf("ADU %d PDU/raw = %x/%x, want %x/%x", i,
				got[i].PDU(), got[i].Bytes(), expected.pdu, expected.raw)
		}
	}
}

func TestQ19TCPPartitionEquivalence(t *testing.T) {
	stream, want := q19EncodedStream(t)
	partitions := 0
	check := func(cuts ...int) {
		t.Helper()
		partitions++
		t.Run(fmt.Sprint(cuts), func(t *testing.T) {
			decoder, err := NewTCPStreamDecoder(260)
			if err != nil {
				t.Fatal(err)
			}
			var got []TCPADU
			start := 0
			for _, end := range append(append([]int(nil), cuts...), len(stream)) {
				for _, fragment := range [][]byte{nil, stream[start:end], {}} {
					frames, err := decoder.Feed(fragment)
					if err != nil {
						t.Fatalf("Feed at [%d:%d], fragment length %d: %v", start, end, len(fragment), err)
					}
					got = append(got, frames...)
				}
				start = end
			}
			q19RequireADUs(t, got, want)
			if err := decoder.Finish(); err != nil {
				t.Fatalf("Finish complete stream: %v", err)
			}
			frames, err := decoder.Feed(nil)
			if err != nil || len(frames) != 0 {
				t.Fatalf("post-Finish empty Feed: frames=%d err=%v", len(frames), err)
			}
			q19RequireADUs(t, got, want)
		})
	}
	for first := 0; first <= len(stream); first++ {
		check(first)
		for second := first; second <= len(stream); second++ {
			check(first, second)
		}
	}
	if partitions != 324 || partitions >= 1000 {
		t.Fatalf("partition count = %d, want 324 and fewer than 1000", partitions)
	}
}

func TestQ19TCPTruncatedSuffixPreservesFirstADU(t *testing.T) {
	stream, want := q19EncodedStream(t)
	firstEnd := len(want[0].raw)
	for suffix := 1; suffix < len(want[1].raw); suffix++ {
		t.Run(fmt.Sprint(suffix), func(t *testing.T) {
			decoder, err := NewTCPStreamDecoder(260)
			if err != nil {
				t.Fatal(err)
			}
			got, err := decoder.Feed(stream[:firstEnd+suffix])
			if err != nil {
				t.Fatal(err)
			}
			q19RequireADUs(t, got, want[:1])
			frames, err := decoder.Feed([]byte{})
			if err != nil || len(frames) != 0 {
				t.Fatalf("empty Feed with truncated suffix: frames=%d err=%v", len(frames), err)
			}
			protocolErr := requireProtocolError(t, decoder.Finish(), ErrorMalformedResponse)
			if protocolErr.Field != "truncated_adu" || protocolErr.Offset != suffix {
				t.Fatalf("truncation = %#v, want truncated_adu at %d", protocolErr, suffix)
			}
			q19RequireADUs(t, got, want[:1])
		})
	}
}
