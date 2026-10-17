package modbus

import (
	"errors"
	"reflect"
	"testing"
)

func TestU20DeviceIDExactAggregateBudgets(t *testing.T) {
	first, err := NewDeviceIDRequest(DeviceIDBasic, 0)
	if err != nil {
		t.Fatal(err)
	}
	pageOne, err := DecodeDeviceIDSegment(first, []byte{
		0x2b, 0x0e, 0x01, 0x01, 0xff, 0x02, 0x02,
		0x00, 0x01, 'a',
		0x01, 0x02, 'b', 'c',
	})
	if err != nil {
		t.Fatalf("decode first page: %v", err)
	}
	second, err := NextDeviceIDRequest(pageOne)
	if err != nil {
		t.Fatalf("continue first page: %v", err)
	}
	pageTwo, err := DecodeDeviceIDSegment(second, []byte{
		0x2b, 0x0e, 0x01, 0x01, 0x00, 0x00, 0x01,
		0x02, 0x03, 'd', 'e', 'f',
	})
	if err != nil {
		t.Fatalf("decode second page: %v", err)
	}
	pages := []DeviceIDSegment{pageOne, pageTwo}
	wantObjects := []DeviceIDObject{
		{ID: 0, Value: []byte{'a'}},
		{ID: 1, Value: []byte{'b', 'c'}},
		{ID: 2, Value: []byte{'d', 'e', 'f'}},
	}
	// Two pages, three objects, and 1 + 2 + 3 = 6 value bytes.
	tests := []struct {
		name      string
		limits    DeviceIDLimits
		wantField string
	}{
		{"segments_exact", DeviceIDLimits{MaxSegments: 2, MaxObjects: 16, MaxValueBytes: 32}, ""},
		{"segments_one_less", DeviceIDLimits{MaxSegments: 1, MaxObjects: 16, MaxValueBytes: 32}, "segment_count"},
		{"objects_exact", DeviceIDLimits{MaxSegments: 16, MaxObjects: 3, MaxValueBytes: 32}, ""},
		{"objects_one_less", DeviceIDLimits{MaxSegments: 16, MaxObjects: 2, MaxValueBytes: 32}, "aggregate_limit"},
		{"value_bytes_exact", DeviceIDLimits{MaxSegments: 16, MaxObjects: 16, MaxValueBytes: 6}, ""},
		{"value_bytes_one_less", DeviceIDLimits{MaxSegments: 16, MaxObjects: 16, MaxValueBytes: 5}, "aggregate_limit"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := AggregateDeviceID(first, pages, test.limits)
			if test.wantField != "" {
				var protocolErr *ProtocolError
				if !errors.As(err, &protocolErr) {
					t.Fatalf("error = %v, want protocol error for %s", err, test.wantField)
				}
				if protocolErr.Kind != ErrorMalformedResponse || protocolErr.Field != test.wantField {
					t.Fatalf("error = %#v, want kind %s field %s", protocolErr, ErrorMalformedResponse, test.wantField)
				}
				if !reflect.DeepEqual(result, DeviceIDResult{}) {
					t.Fatalf("budget rejection published partial result: %#v", result)
				}
				return
			}
			if err != nil {
				t.Fatalf("exact budget rejected valid traversal: %v", err)
			}
			if !reflect.DeepEqual(result.Objects, wantObjects) {
				t.Fatalf("objects = %#v, want %#v", result.Objects, wantObjects)
			}
			valueBytes := 0
			for _, object := range result.Objects {
				valueBytes += len(object.Value)
			}
			if valueBytes != 6 || len(result.Segments) != 2 || result.Conformity != 0x01 {
				t.Fatalf("incomplete aggregate: bytes=%d segments=%d conformity=%x", valueBytes, len(result.Segments), result.Conformity)
			}
		})
	}
}
