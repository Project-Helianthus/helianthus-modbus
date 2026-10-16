package modbus

import (
	"fmt"
	"reflect"
	"testing"
)

func TestQ22ExtendedDeviceIDEveryWrapPartition(t *testing.T) {
	// Independent wire tuples and expected objects keep byte preservation observable.
	tuples := [][]byte{{0xfe, 2, 0x00, 0xff}, {0xff, 1, 0x81}, {0x00, 2, 0xc3, 0x28}, {0x01, 1, 0x20}}
	want := []DeviceIDObject{
		{ID: 0xfe, Value: []byte{0x00, 0xff}},
		{ID: 0xff, Value: []byte{0x81}},
		{ID: 0x00, Value: []byte{0xc3, 0x28}},
		{ID: 0x01, Value: []byte{0x20}},
	}
	for cuts := 0; cuts < 8; cuts++ {
		t.Run(fmt.Sprintf("cuts_%03b", cuts), func(t *testing.T) {
			first, err := NewExtendedDeviceIDStreamRequest(0xfe)
			if err != nil {
				t.Fatal(err)
			}
			request := first
			var segments []DeviceIDSegment
			start := 0
			for end := 1; end <= len(tuples); end++ {
				if end < len(tuples) && cuts&(1<<(end-1)) == 0 {
					continue
				}
				more, next := byte(0), byte(0)
				if end < len(tuples) {
					more, next = 0xff, tuples[end][0]
				}
				pdu := []byte{0x2b, 0x0e, 0x03, 0x83, more, next, byte(end - start)}
				for _, tuple := range tuples[start:end] {
					pdu = append(pdu, tuple...)
				}
				encoded, err := request.EncodePDU()
				if err != nil || !reflect.DeepEqual(encoded, []byte{0x2b, 0x0e, 0x03, tuples[start][0]}) {
					t.Fatalf("request PDU=%x err=%v", encoded, err)
				}
				segment, err := DecodeDeviceIDSegment(request, pdu)
				if err != nil {
					t.Fatalf("page starting at %d: %v", start, err)
				}
				if segment.Request() != request || segment.Request().Access() != DeviceIDExtended {
					t.Fatalf("request identity=%#v want=%#v", segment.Request(), request)
				}
				segments = append(segments, segment)
				if more != 0 {
					request, err = NextDeviceIDRequest(segment)
					if err != nil {
						t.Fatal(err)
					}
				}
				start = end
			}
			result, err := AggregateExtendedDeviceIDStream(first, segments, DefaultDeviceIDLimits())
			if err != nil {
				t.Fatal(err)
			}
			if result.Conformity != 0x83 || !reflect.DeepEqual(result.Objects, want) || !reflect.DeepEqual(result.Segments, segments) {
				t.Fatalf("aggregate=%#v want objects=%#v and exact segment provenance", result, want)
			}
		})
	}
}

func TestQ22ExtendedDeviceIDLateProgressMutations(t *testing.T) {
	for _, mutation := range []string{"second_wrap", "repeated_object_after_wrap"} {
		t.Run(mutation, func(t *testing.T) {
			first, err := NewExtendedDeviceIDStreamRequest(0xfe)
			if err != nil {
				t.Fatal(err)
			}
			lateCursor := byte(0x80)
			pages := [][]byte{
				{0x2b, 0x0e, 0x03, 0x83, 0xff, 0xff, 1, 0xfe, 1, 0xa1},
				{0x2b, 0x0e, 0x03, 0x83, 0xff, 0x00, 1, 0xff, 1, 0xb2},
				{0x2b, 0x0e, 0x03, 0x83, 0xff, lateCursor, 1, 0x00, 1, 0xc3},
			}
			request := first
			var segments []DeviceIDSegment
			for index, pdu := range pages {
				segment, err := DecodeDeviceIDSegment(request, pdu)
				if err != nil {
					t.Fatalf("valid prefix page %d: %v", index, err)
				}
				segments = append(segments, segment)
				request, err = NextDeviceIDRequest(segment)
				if err != nil {
					t.Fatalf("valid prefix continuation %d: %v", index, err)
				}
			}
			// Complete the same prefix successfully before introducing the late mutation.
			control, err := DecodeDeviceIDSegment(request, []byte{0x2b, 0x0e, 0x03, 0x83, 0, 0, 1, 0x80, 1, 0xd4})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := AggregateExtendedDeviceIDStream(first, append(segments, control), DefaultDeviceIDLimits()); err != nil {
				t.Fatalf("valid control: %v", err)
			}
			if mutation == "second_wrap" {
				_, err := DecodeDeviceIDSegment(request, []byte{0x2b, 0x0e, 0x03, 0x83, 0, 0, 3, 0x80, 1, 0xd4, 0xff, 1, 0xe5, 0, 1, 0xf6})
				protocolErr := requireProtocolError(t, err, ErrorMalformedResponse)
				if protocolErr.Field != "object_progress" || protocolErr.Offset != -1 {
					t.Fatalf("late wrap error=%#v", protocolErr)
				}
				return
			}
			duplicate, err := DecodeDeviceIDSegment(request, []byte{0x2b, 0x0e, 0x03, 0x83, 0, 0, 1, 0xfe, 1, 0x99})
			if err != nil {
				t.Fatalf("late repeated page must decode before aggregate progress rejection: %v", err)
			}
			result, err := AggregateExtendedDeviceIDStream(first, append(segments, duplicate), DefaultDeviceIDLimits())
			protocolErr := requireProtocolError(t, err, ErrorMalformedResponse)
			if protocolErr.Field != "object_progress" || protocolErr.Offset != -1 {
				t.Fatalf("late duplicate error=%#v", protocolErr)
			}
			if !reflect.DeepEqual(result, DeviceIDResult{}) {
				t.Fatalf("partial result published: %#v", result)
			}
		})
	}
}
