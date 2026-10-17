package modbus

import (
	"reflect"
	"testing"
)

func TestQ21DeviceIDDeepOwnership(t *testing.T) {
	for _, mutation := range []string{
		"original PDU buffers",
		"returned Objects slice",
		"returned Objects value bytes",
		"original segment slice",
		"original segment value bytes",
	} {
		t.Run(mutation, func(t *testing.T) {
			pdus := [][]byte{
				{0x2b, 0x0e, 0x02, 0x82, 0xff, 0x02, 0x02,
					0x00, 0x02, 0x10, 0x11, 0x01, 0x02, 0x20, 0x21},
				{0x2b, 0x0e, 0x02, 0x82, 0x00, 0x00, 0x02,
					0x02, 0x02, 0x30, 0x31, 0x04, 0x02, 0x40, 0x41},
			}
			// Independent allocations keep the oracle detached from every API result.
			wantSegments := [][]DeviceIDObject{
				{{ID: 0, Value: []byte{0x10, 0x11}}, {ID: 1, Value: []byte{0x20, 0x21}}},
				{{ID: 2, Value: []byte{0x30, 0x31}}, {ID: 4, Value: []byte{0x40, 0x41}}},
			}
			wantAggregate := []DeviceIDObject{
				{ID: 0, Value: []byte{0x10, 0x11}},
				{ID: 1, Value: []byte{0x20, 0x21}},
				{ID: 2, Value: []byte{0x30, 0x31}},
				{ID: 4, Value: []byte{0x40, 0x41}},
			}
			first, err := NewDeviceIDRequest(DeviceIDRegular, 0)
			if err != nil {
				t.Fatal(err)
			}
			var originals [2]DeviceIDSegment
			request := first
			for i := range pdus {
				originals[i], err = DecodeDeviceIDSegment(request, pdus[i])
				if err != nil {
					t.Fatal(err)
				}
				if i == 0 {
					request, err = NextDeviceIDRequest(originals[i])
					if err != nil {
						t.Fatal(err)
					}
				}
			}
			segments := []DeviceIDSegment{originals[0], originals[1]}
			result, err := AggregateDeviceID(first, segments, DefaultDeviceIDLimits())
			if err != nil {
				t.Fatal(err)
			}
			assertObjects := func(label string, got, want []DeviceIDObject) {
				t.Helper()
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("%s: got %#v, want %#v", label, got, want)
				}
			}
			assertState := func() {
				t.Helper()
				assertObjects("aggregate objects", result.Objects, wantAggregate)
				if len(result.Segments) != len(originals) {
					t.Fatalf("aggregate segments = %d, want %d", len(result.Segments), len(originals))
				}
				for i := range originals {
					assertObjects("decoded segment", originals[i].Objects(), wantSegments[i])
					assertObjects("aggregate segment", result.Segments[i].Objects(), wantAggregate[i*2:i*2+2])
				}
			}
			assertState()

			switch mutation {
			case "original PDU buffers":
				for _, pdu := range pdus {
					// Both nonempty object values in each segment are changed.
					for _, offset := range []int{9, 10, 13, 14} {
						pdu[offset] ^= 0xff
					}
				}
			case "returned Objects slice":
				for _, segment := range originals {
					objects := segment.Objects()
					for i := range objects {
						objects[i] = DeviceIDObject{ID: 0xff, Value: []byte{0xee}}
					}
				}
			case "returned Objects value bytes":
				for _, segment := range originals {
					for _, object := range segment.Objects() {
						for i := range object.Value {
							object.Value[i] ^= 0xff
						}
					}
				}
			case "original segment slice":
				for i := range segments {
					segments[i] = DeviceIDSegment{}
				}
			case "original segment value bytes":
				// Exercise aggregation's own deep copy independently of Objects().
				for i := range segments {
					for j := range segments[i].objects {
						for k := range segments[i].objects[j].Value {
							segments[i].objects[j].Value[k] ^= 0xff
							wantSegments[i][j].Value[k] ^= 0xff
						}
					}
				}
			}
			assertState()
		})
	}
}
