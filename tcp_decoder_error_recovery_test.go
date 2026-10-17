package modbus

import (
	"bytes"
	"fmt"
	"testing"
)

func TestQ20TCPDecoderErrorRecovery(t *testing.T) {
	tests := []struct {
		name     string
		fragment []byte
		finish   bool
		kind     ErrorKind
		field    string
	}{
		{"protocol_low_byte", []byte{0x11, 0x22, 0, 1, 0, 5, 9}, false, ErrorMalformedResponse, "protocol_id"},
		{"protocol_high_byte", []byte{0x11, 0x22, 1, 0, 0, 5, 9}, false, ErrorMalformedResponse, "protocol_id"},
		{"length_below_minimum", []byte{0x11, 0x22, 0, 0, 0, 1, 9}, false, ErrorMalformedResponse, "length"},
		{"length_above_maximum", []byte{0x11, 0x22, 0, 0, 0, 255, 9}, false, ErrorMalformedResponse, "length"},
		{"truncated_header", []byte{0x11, 0x22, 0}, true, ErrorMalformedResponse, "truncated_adu"},
		{"truncated_body", []byte{0x11, 0x22, 0, 0, 0, 6, 9, 3}, true, ErrorMalformedResponse, "truncated_adu"},
		{"buffer_limit", []byte{0x11, 0x22, 0, 0, 0, 6, 9, 3, 4, 0xaa, 0xbb, 0xcc}, false, ErrorInvalidRange, "buffered_bytes"},
	}
	for _, test := range tests {
		for _, unit := range []byte{0, 7} {
			t.Run(fmt.Sprintf("%s/unit_%d", test.name, unit), func(t *testing.T) {
				decoder, err := NewTCPStreamDecoder(11)
				if err != nil {
					t.Fatal(err)
				}
				frames, err := decoder.Feed(test.fragment)
				if len(frames) != 0 {
					t.Fatalf("failure fragment returned %d frames", len(frames))
				}
				if test.finish {
					if err != nil {
						t.Fatalf("truncated fragment failed before Finish: %v", err)
					}
					err = decoder.Finish()
				}
				protocolErr := requireProtocolError(t, err, test.kind)
				if protocolErr.Field != test.field {
					t.Fatalf("error field = %q, want %q", protocolErr.Field, test.field)
				}

				// Reuse the failed decoder before any cleanup call can hide retained bytes.
				valid := []byte{0x45, 0x67, 0, 0, 0, 5, unit, 4, 2, 0x98, 0x76}
				frames, err = decoder.Feed(valid)
				if err != nil || len(frames) != 1 {
					t.Fatalf("valid frame after error: frames=%d err=%v", len(frames), err)
				}
				frame := frames[0]
				if frame.TransactionID() != 0x4567 || frame.UnitID() != unit ||
					!bytes.Equal(frame.PDU(), []byte{4, 2, 0x98, 0x76}) || !bytes.Equal(frame.Bytes(), valid) {
					t.Fatalf("recovered frame: transaction=%x unit=%d PDU=%x bytes=%x",
						frame.TransactionID(), frame.UnitID(), frame.PDU(), frame.Bytes())
				}
				frames, err = decoder.Feed(nil)
				if err != nil || len(frames) != 0 {
					t.Fatalf("recovery returned more than once: frames=%d err=%v", len(frames), err)
				}
				for attempt := 1; attempt <= 2; attempt++ {
					if err := decoder.Finish(); err != nil {
						t.Fatalf("Finish %d after recovery: %v", attempt, err)
					}
				}
			})
		}
	}
}
