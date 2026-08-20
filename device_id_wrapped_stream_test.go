package modbus

import (
	"reflect"
	"testing"
)

func TestExtendedDeviceIDStreamStartsAtArbitraryObjectAndWrapsOnce(t *testing.T) {
	first, err := NewExtendedDeviceIDStreamRequest(0x87)
	if err != nil {
		t.Fatal(err)
	}
	pdu, err := first.EncodePDU()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(pdu, []byte{0x2b, 0x0e, 0x03, 0x87}) {
		t.Fatalf("initial PDU=%x", pdu)
	}
	firstSegment := testDeviceIDSegment(
		first,
		0x83,
		true,
		0xff,
		[]DeviceIDObject{{ID: 0x87, Value: []byte("count")}, {ID: 0x88, Value: []byte("first")}},
	)
	atFF, err := NextDeviceIDRequest(firstSegment)
	if err != nil {
		t.Fatal(err)
	}
	wrapSegment := testDeviceIDSegment(
		atFF,
		0x83,
		true,
		0x00,
		[]DeviceIDObject{{ID: 0xff, Value: []byte("last-high")}},
	)
	atZero, err := NextDeviceIDRequest(wrapSegment)
	if err != nil {
		t.Fatal(err)
	}
	if atZero.Access() != DeviceIDExtended || atZero.ObjectID() != 0 {
		t.Fatalf("wrapped request=%#v", atZero)
	}
	finalSegment := testDeviceIDSegment(
		atZero,
		0x83,
		false,
		0,
		[]DeviceIDObject{{ID: 0x00, Value: []byte("first-low")}, {ID: 0x01, Value: []byte("second-low")}},
	)
	result, err := AggregateExtendedDeviceIDStream(
		first,
		[]DeviceIDSegment{firstSegment, wrapSegment, finalSegment},
		DefaultDeviceIDLimits(),
	)
	if err != nil {
		t.Fatal(err)
	}
	wantIDs := []byte{0x87, 0x88, 0xff, 0x00, 0x01}
	if len(result.Objects) != len(wantIDs) {
		t.Fatalf("objects=%d", len(result.Objects))
	}
	for index, object := range result.Objects {
		if object.ID != wantIDs[index] {
			t.Fatalf("object[%d]=0x%02x want=0x%02x", index, object.ID, wantIDs[index])
		}
	}
}

func TestExtendedDeviceIDStreamRejectsSecondWrapAndDuplicateAfterWrap(t *testing.T) {
	first, err := NewExtendedDeviceIDStreamRequest(0xff)
	if err != nil {
		t.Fatal(err)
	}
	wrap := testDeviceIDSegment(first, 0x83, true, 0, []DeviceIDObject{{ID: 0xff, Value: []byte{1}}})
	low, err := NextDeviceIDRequest(wrap)
	if err != nil {
		t.Fatal(err)
	}
	advance := testDeviceIDSegment(low, 0x83, true, 0xff, []DeviceIDObject{{ID: 0, Value: []byte{2}}})
	high, err := NextDeviceIDRequest(advance)
	if err != nil {
		t.Fatal(err)
	}
	secondWrap := testDeviceIDSegment(high, 0x83, true, 0, []DeviceIDObject{{ID: 0xff, Value: []byte{3}}})
	if _, err := NextDeviceIDRequest(secondWrap); err == nil {
		t.Fatal("second object-ID wrap accepted")
	}

	first, _ = NewExtendedDeviceIDStreamRequest(0x87)
	base := testDeviceIDSegment(first, 0x83, true, 0, []DeviceIDObject{{ID: 0x87, Value: []byte{1}}, {ID: 0xff, Value: []byte{2}}})
	low, _ = NextDeviceIDRequest(base)
	toDuplicate := testDeviceIDSegment(low, 0x83, true, 0x87, []DeviceIDObject{{ID: 0, Value: []byte{3}}})
	duplicateRequest, _ := NextDeviceIDRequest(toDuplicate)
	duplicate := testDeviceIDSegment(duplicateRequest, 0x83, false, 0, []DeviceIDObject{{ID: 0x87, Value: []byte{4}}})
	result, err := AggregateExtendedDeviceIDStream(first, []DeviceIDSegment{base, toDuplicate, duplicate}, DefaultDeviceIDLimits())
	if err == nil || len(result.Objects) != 0 || len(result.Segments) != 0 {
		t.Fatalf("duplicate published result=%#v err=%v", result, err)
	}
}

func TestExtendedDeviceIDStreamDecodesWrapInsideOneSegment(t *testing.T) {
	request, err := NewExtendedDeviceIDStreamRequest(0xff)
	if err != nil {
		t.Fatal(err)
	}
	segment, err := DecodeDeviceIDSegment(request, []byte{
		0x2b, 0x0e, 0x03, 0x83, 0x00, 0x00, 0x02,
		0xff, 0x01, 'a',
		0x00, 0x01, 'b',
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := AggregateExtendedDeviceIDStream(request, []DeviceIDSegment{segment}, DefaultDeviceIDLimits())
	if err != nil || len(result.Objects) != 2 || result.Objects[0].ID != 0xff || result.Objects[1].ID != 0 {
		t.Fatalf("result=%#v err=%v", result, err)
	}
}
