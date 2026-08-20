package modbus

import (
	"reflect"
	"testing"
)

func testDeviceIDSegment(
	request DeviceIDRequest,
	conformity DeviceIDConformity,
	moreFollows bool,
	nextObjectID byte,
	objects []DeviceIDObject,
) DeviceIDSegment {
	return DeviceIDSegment{
		request:      request,
		conformity:   conformity,
		moreFollows:  moreFollows,
		nextObjectID: nextObjectID,
		objects:      cloneDeviceIDObjects(objects),
		decoded:      true,
	}
}

func TestDeviceIDRequestEncoding(t *testing.T) {
	tests := []struct {
		access   DeviceIDAccess
		objectID byte
		want     []byte
	}{
		{DeviceIDBasic, 0x00, []byte{0x2b, 0x0e, 0x01, 0x00}},
		{DeviceIDRegular, 0x00, []byte{0x2b, 0x0e, 0x02, 0x00}},
		{DeviceIDExtended, 0x00, []byte{0x2b, 0x0e, 0x03, 0x00}},
		{DeviceIDIndividual, 0x05, []byte{0x2b, 0x0e, 0x04, 0x05}},
	}
	for _, test := range tests {
		request, err := NewDeviceIDRequest(test.access, test.objectID)
		if err != nil {
			t.Fatal(err)
		}
		got, err := request.EncodePDU()
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, test.want) {
			t.Errorf("PDU = %x, want %x", got, test.want)
		}
	}
}

func TestZeroDeviceIDRequestCannotEncodeOrDecode(t *testing.T) {
	var request DeviceIDRequest
	pdu, err := request.EncodePDU()
	_ = requireProtocolError(t, err, ErrorInvalidRequest)
	if pdu != nil {
		t.Fatalf("invalid request encoded bytes: %x", pdu)
	}
	_, err = DecodeDeviceIDSegment(
		request,
		[]byte{0x2b, 0x0e, 0x01, 0x01, 0, 0, 0},
	)
	_ = requireProtocolError(t, err, ErrorInvalidRequest)
}

func TestDeviceIDRequestRejectsUnknownAccess(t *testing.T) {
	_, err := NewDeviceIDRequest(DeviceIDAccess(0x00), 0)
	_ = requireProtocolError(t, err, ErrorInvalidRequest)
	_, err = NewDeviceIDRequest(DeviceIDAccess(0x05), 0)
	_ = requireProtocolError(t, err, ErrorInvalidRequest)
}

func TestDeviceIDStreamInitialRequestRejectsNonzeroCursor(t *testing.T) {
	for _, access := range []DeviceIDAccess{
		DeviceIDBasic,
		DeviceIDRegular,
		DeviceIDExtended,
	} {
		_, err := NewDeviceIDRequest(access, 1)
		_ = requireProtocolError(t, err, ErrorInvalidRequest)
	}
}

func TestNextDeviceIDRequestBindsPriorSegment(t *testing.T) {
	first, err := NewDeviceIDRequest(DeviceIDRegular, 0)
	if err != nil {
		t.Fatal(err)
	}
	segment := testDeviceIDSegment(
		first,
		0x82,
		true,
		3,
		[]DeviceIDObject{
			{ID: 0, Value: []byte{0}},
			{ID: 1, Value: []byte{1}},
			{ID: 2, Value: []byte{2}},
		},
	)
	next, err := NextDeviceIDRequest(segment)
	if err != nil {
		t.Fatal(err)
	}
	if next.Access() != DeviceIDRegular || next.ObjectID() != 3 {
		t.Fatalf("unexpected continuation request: %#v", next)
	}
	pdu, err := next.EncodePDU()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(pdu, []byte{0x2b, 0x0e, 0x02, 0x03}) {
		t.Fatalf("continuation PDU = %x", pdu)
	}
	segment.moreFollows = false
	segment.nextObjectID = 0
	_, err = NextDeviceIDRequest(segment)
	_ = requireProtocolError(t, err, ErrorInvalidRequest)
}

func TestNextDeviceIDRequestRejectsStructurallyForgedSegment(t *testing.T) {
	first, err := NewDeviceIDRequest(DeviceIDBasic, 0)
	if err != nil {
		t.Fatal(err)
	}
	forged := DeviceIDSegment{
		request:      first,
		conformity:   0x01,
		moreFollows:  true,
		nextObjectID: 2,
		objects: []DeviceIDObject{
			{ID: 0, Value: []byte{0}},
			{ID: 1, Value: []byte{1}},
		},
	}
	_, err = NextDeviceIDRequest(forged)
	protocolErr := requireProtocolError(t, err, ErrorMalformedResponse)
	if protocolErr.Field != "segment_identity" {
		t.Fatalf("field = %q", protocolErr.Field)
	}
}

func TestDeviceIDSegmentRejectsOutOfCategoryContinuationCursor(t *testing.T) {
	tests := []struct {
		access     DeviceIDAccess
		conformity byte
		next       byte
		objects    []byte
	}{
		{DeviceIDBasic, 0x01, 0xfe, []byte{0, 0, 1, 0, 2, 0}},
		{DeviceIDRegular, 0x02, 0x80, []byte{0, 0, 1, 0, 2, 0}},
		{DeviceIDExtended, 0x03, 0x07, []byte{0, 0, 1, 0, 2, 0}},
	}
	for _, test := range tests {
		request, err := NewDeviceIDRequest(test.access, 0)
		if err != nil {
			t.Fatal(err)
		}
		pdu := []byte{
			0x2b,
			0x0e,
			byte(test.access),
			test.conformity,
			0xff,
			test.next,
			0x03,
		}
		pdu = append(pdu, test.objects...)
		_, err = DecodeDeviceIDSegment(request, pdu)
		protocolErr := requireProtocolError(t, err, ErrorMalformedResponse)
		if protocolErr.Field != "next_object_id" {
			t.Fatalf("field = %q", protocolErr.Field)
		}
	}
}

func TestDecodeDeviceIDSegmentPreservesExactObjectBytes(t *testing.T) {
	request, err := NewDeviceIDRequest(DeviceIDBasic, 0)
	if err != nil {
		t.Fatal(err)
	}
	pdu := []byte{
		0x2b, 0x0e, 0x01, 0x81, 0x00, 0x00, 0x03,
		0x00, 0x03, 0xff, 0x00, 0x41,
		0x01, 0x02, 0xc3, 0x28,
		0x02, 0x01, 0x20,
	}
	segment, err := DecodeDeviceIDSegment(request, pdu)
	if err != nil {
		t.Fatal(err)
	}
	if segment.Request() != request {
		t.Fatalf("request identity lost: %#v", segment.Request())
	}
	if segment.Conformity() != DeviceIDConformity(0x81) {
		t.Fatalf("conformity = 0x%02x", segment.Conformity())
	}
	if segment.MoreFollows() || segment.NextObjectID() != 0 {
		t.Fatalf("unexpected completion fields: %#v", segment)
	}
	want := []DeviceIDObject{
		{ID: 0x00, Value: []byte{0xff, 0x00, 0x41}},
		{ID: 0x01, Value: []byte{0xc3, 0x28}},
		{ID: 0x02, Value: []byte{0x20}},
	}
	objects := segment.Objects()
	if !reflect.DeepEqual(objects, want) {
		t.Fatalf("objects = %#v, want %#v", objects, want)
	}
	pdu[9] = 0x42
	objects[0].Value[0] = 0x42
	if segment.Objects()[0].Value[0] != 0xff {
		t.Fatal("decoded object bytes alias input buffer")
	}
}

func TestDecodeDeviceIDSegmentRejectsMalformedHeader(t *testing.T) {
	request, err := NewDeviceIDRequest(DeviceIDRegular, 0)
	if err != nil {
		t.Fatal(err)
	}
	valid := []byte{0x2b, 0x0e, 0x02, 0x82, 0x00, 0x00, 0x00}
	tests := []struct {
		name string
		pdu  []byte
	}{
		{"truncated", valid[:6]},
		{"wrong function", []byte{0x2a, 0x0e, 0x02, 0x82, 0, 0, 0}},
		{"wrong mei", []byte{0x2b, 0x0d, 0x02, 0x82, 0, 0, 0}},
		{"wrong access echo", []byte{0x2b, 0x0e, 0x01, 0x82, 0, 0, 0}},
		{"invalid conformity", []byte{0x2b, 0x0e, 0x02, 0x04, 0, 0, 0}},
		{"invalid more follows", []byte{0x2b, 0x0e, 0x02, 0x82, 1, 0, 0}},
		{"terminal cursor", []byte{0x2b, 0x0e, 0x02, 0x82, 0, 3, 0}},
		{"nonterminal zero cursor", []byte{0x2b, 0x0e, 0x02, 0x82, 0xff, 0, 1, 3, 1, 1}},
		{"zero-object continuation", []byte{0x2b, 0x0e, 0x02, 0x82, 0xff, 3, 0}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := DecodeDeviceIDSegment(request, test.pdu)
			_ = requireProtocolError(t, err, ErrorMalformedResponse)
		})
	}
}

func TestDecodeDeviceIDSegmentRejectsMalformedObjects(t *testing.T) {
	request, err := NewDeviceIDRequest(DeviceIDExtended, 0)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		pdu  []byte
	}{
		{"missing tuple", []byte{0x2b, 0x0e, 0x03, 0x03, 0, 0, 1}},
		{"missing value", []byte{0x2b, 0x0e, 0x03, 0x03, 0, 0, 1, 0, 2, 1}},
		{"trailing", []byte{0x2b, 0x0e, 0x03, 0x03, 0, 0, 0, 1}},
		{"duplicate", []byte{0x2b, 0x0e, 0x03, 0x03, 0, 0, 2, 0, 1, 1, 0, 1, 2}},
		{"decreasing", []byte{0x2b, 0x0e, 0x03, 0x03, 0, 0, 2, 2, 1, 1, 1, 1, 2}},
		{"reserved object", []byte{0x2b, 0x0e, 0x03, 0x03, 0, 0, 1, 7, 1, 1}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := DecodeDeviceIDSegment(request, test.pdu)
			_ = requireProtocolError(t, err, ErrorMalformedResponse)
		})
	}
}

func TestDecodeDeviceIDSegmentEnforcesRequestedCategory(t *testing.T) {
	basic, err := NewDeviceIDRequest(DeviceIDBasic, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = DecodeDeviceIDSegment(
		basic,
		[]byte{0x2b, 0x0e, 0x01, 0x03, 0, 0, 1, 3, 1, 1},
	)
	_ = requireProtocolError(t, err, ErrorMalformedResponse)
}

func TestDecodeIndividualDeviceIDRules(t *testing.T) {
	request, err := NewDeviceIDRequest(DeviceIDIndividual, 0x05)
	if err != nil {
		t.Fatal(err)
	}
	valid := []byte{0x2b, 0x0e, 0x04, 0x82, 0, 0, 1, 0x05, 2, 0, 1}
	if _, err := DecodeDeviceIDSegment(request, valid); err != nil {
		t.Fatal(err)
	}
	tests := [][]byte{
		{0x2b, 0x0e, 0x04, 0x02, 0, 0, 1, 0x05, 1, 1},
		{0x2b, 0x0e, 0x04, 0x82, 0xff, 6, 1, 0x05, 1, 1},
		{0x2b, 0x0e, 0x04, 0x82, 0, 0, 0},
		{0x2b, 0x0e, 0x04, 0x82, 0, 0, 1, 0x04, 1, 1},
		{0x2b, 0x0e, 0x04, 0x82, 0, 0, 2, 0x05, 1, 1, 0x06, 1, 2},
	}
	for index, pdu := range tests {
		t.Run(string(rune('a'+index)), func(t *testing.T) {
			_, err := DecodeDeviceIDSegment(request, pdu)
			_ = requireProtocolError(t, err, ErrorMalformedResponse)
		})
	}
}

func TestDecodeDeviceIDException(t *testing.T) {
	request, err := NewDeviceIDRequest(DeviceIDIndividual, 0xfe)
	if err != nil {
		t.Fatal(err)
	}
	_, err = DecodeDeviceIDSegment(request, []byte{0xab, 0x02})
	protocolErr := requireProtocolError(t, err, ErrorExceptionResponse)
	if protocolErr.ExceptionCode != 0x02 {
		t.Fatalf("exception code = 0x%02x", protocolErr.ExceptionCode)
	}
	for _, pdu := range [][]byte{{0xab}, {0xab, 2, 0}} {
		_, err := DecodeDeviceIDSegment(request, pdu)
		_ = requireProtocolError(t, err, ErrorMalformedResponse)
	}
}

func TestAggregateDeviceIDSegments(t *testing.T) {
	first, _ := NewDeviceIDRequest(DeviceIDRegular, 0)
	base := testDeviceIDSegment(
		first,
		0x82,
		true,
		2,
		[]DeviceIDObject{
			{ID: 0, Value: []byte{0}},
			{ID: 1, Value: []byte{1}},
		},
	)
	second, err := NextDeviceIDRequest(base)
	if err != nil {
		t.Fatal(err)
	}
	segments := []DeviceIDSegment{
		base,
		testDeviceIDSegment(
			second,
			0x82,
			false,
			0,
			[]DeviceIDObject{
				{ID: 2, Value: []byte{2}},
				{ID: 4, Value: []byte{4}},
			},
		),
	}
	result, err := AggregateDeviceID(first, segments, DefaultDeviceIDLimits())
	if err != nil {
		t.Fatal(err)
	}
	if result.Conformity != DeviceIDConformity(0x82) {
		t.Fatalf("conformity = 0x%02x", result.Conformity)
	}
	if len(result.Segments) != 2 || len(result.Objects) != 4 {
		t.Fatalf("unexpected result: %#v", result)
	}
	segments[0].objects[0].Value[0] = 9
	if result.Objects[0].Value[0] != 0 {
		t.Fatal("aggregate aliases caller-owned object bytes")
	}
}

func TestAggregateDeviceIDRejectsPartialOrNonProgressingTraversal(t *testing.T) {
	first, _ := NewDeviceIDRequest(DeviceIDBasic, 0)
	base := testDeviceIDSegment(
		first,
		0x01,
		true,
		2,
		[]DeviceIDObject{
			{ID: 0, Value: []byte{0}},
			{ID: 1, Value: []byte{1}},
		},
	)
	cursorTwo, err := NextDeviceIDRequest(base)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name     string
		segments []DeviceIDSegment
		limits   DeviceIDLimits
	}{
		{"missing continuation", []DeviceIDSegment{base}, DefaultDeviceIDLimits()},
		{
			"wrong cursor",
			[]DeviceIDSegment{
				base,
				testDeviceIDSegment(
					first,
					0x01,
					false,
					0,
					[]DeviceIDObject{{ID: 2, Value: []byte{2}}},
				),
			},
			DefaultDeviceIDLimits(),
		},
		{
			"duplicate across segments",
			[]DeviceIDSegment{
				base,
				testDeviceIDSegment(
					cursorTwo,
					0x01,
					false,
					0,
					[]DeviceIDObject{{ID: 1, Value: []byte{2}}},
				),
			},
			DefaultDeviceIDLimits(),
		},
		{
			"conformity regression",
			[]DeviceIDSegment{
				base,
				testDeviceIDSegment(
					cursorTwo,
					0x81,
					false,
					0,
					[]DeviceIDObject{{ID: 2, Value: []byte{2}}},
				),
			},
			DefaultDeviceIDLimits(),
		},
		{
			"missing mandatory object",
			[]DeviceIDSegment{testDeviceIDSegment(
				first,
				0x01,
				false,
				0,
				[]DeviceIDObject{{ID: 0, Value: []byte{0}}},
			)},
			DefaultDeviceIDLimits(),
		},
		{
			"segment bound",
			[]DeviceIDSegment{
				base,
				testDeviceIDSegment(
					cursorTwo,
					0x01,
					false,
					0,
					[]DeviceIDObject{{ID: 2, Value: []byte{2}}},
				),
			},
			DeviceIDLimits{MaxSegments: 1, MaxObjects: 256, MaxValueBytes: 62464},
		},
		{
			"object bound",
			[]DeviceIDSegment{
				base,
				testDeviceIDSegment(
					cursorTwo,
					0x01,
					false,
					0,
					[]DeviceIDObject{{ID: 2, Value: []byte{2}}},
				),
			},
			DeviceIDLimits{MaxSegments: 256, MaxObjects: 2, MaxValueBytes: 62464},
		},
		{
			"value bound",
			[]DeviceIDSegment{
				base,
				testDeviceIDSegment(
					cursorTwo,
					0x01,
					false,
					0,
					[]DeviceIDObject{{ID: 2, Value: []byte{2}}},
				),
			},
			DeviceIDLimits{MaxSegments: 256, MaxObjects: 256, MaxValueBytes: 2},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := AggregateDeviceID(first, test.segments, test.limits)
			_ = requireProtocolError(t, err, ErrorMalformedResponse)
			if len(result.Objects) != 0 || len(result.Segments) != 0 {
				t.Fatalf("partial aggregate published on failure: %#v", result)
			}
		})
	}
}

func TestAggregateDeviceIDRejectsImpossibleDirectSegmentSizes(t *testing.T) {
	first, _ := NewDeviceIDRequest(DeviceIDBasic, 0)
	tests := []struct {
		name    string
		objects []DeviceIDObject
		field   string
	}{
		{
			name: "object exceeds wire maximum",
			objects: []DeviceIDObject{
				{ID: 0, Value: make([]byte, 245)},
				{ID: 1, Value: []byte{1}},
				{ID: 2, Value: []byte{2}},
			},
			field: "object_value_length",
		},
		{
			name: "reconstructed PDU exceeds maximum",
			objects: []DeviceIDObject{
				{ID: 0, Value: make([]byte, 81)},
				{ID: 1, Value: make([]byte, 81)},
				{ID: 2, Value: make([]byte, 81)},
			},
			field: "segment_pdu_length",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := AggregateDeviceID(
				first,
				[]DeviceIDSegment{testDeviceIDSegment(
					first,
					0x01,
					false,
					0,
					test.objects,
				)},
				DefaultDeviceIDLimits(),
			)
			protocolErr := requireProtocolError(t, err, ErrorMalformedResponse)
			if protocolErr.Field != test.field {
				t.Fatalf("field = %q, want %q", protocolErr.Field, test.field)
			}
			if len(result.Objects) != 0 || len(result.Segments) != 0 {
				t.Fatalf("partial aggregate published: %#v", result)
			}
		})
	}
}

func TestDeviceIDLimitsMustBePositiveAndBounded(t *testing.T) {
	first, _ := NewDeviceIDRequest(DeviceIDBasic, 0)
	segments := []DeviceIDSegment{testDeviceIDSegment(
		first,
		0x01,
		false,
		0,
		[]DeviceIDObject{
			{ID: 0, Value: []byte{0}},
			{ID: 1, Value: []byte{1}},
			{ID: 2, Value: []byte{2}},
		},
	)}
	for _, limits := range []DeviceIDLimits{
		{},
		{MaxSegments: 257, MaxObjects: 256, MaxValueBytes: 62464},
		{MaxSegments: 256, MaxObjects: 257, MaxValueBytes: 62464},
		{MaxSegments: 256, MaxObjects: 256, MaxValueBytes: 62465},
	} {
		_, err := AggregateDeviceID(first, segments, limits)
		_ = requireProtocolError(t, err, ErrorInvalidRequest)
	}
}

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
	if _, err := AggregateDeviceID(first, []DeviceIDSegment{firstSegment}, DefaultDeviceIDLimits()); err == nil {
		t.Fatal("standard aggregate accepted an extended stream request")
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
