package modbus

import (
	"reflect"
	"testing"
)

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
	segment := DeviceIDSegment{
		Request:      first,
		Conformity:   0x82,
		MoreFollows:  true,
		NextObjectID: 3,
		Objects: []DeviceIDObject{
			{ID: 0, Value: []byte{0}},
			{ID: 1, Value: []byte{1}},
			{ID: 2, Value: []byte{2}},
		},
	}
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
	segment.MoreFollows = false
	segment.NextObjectID = 0
	_, err = NextDeviceIDRequest(segment)
	_ = requireProtocolError(t, err, ErrorInvalidRequest)
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
	if segment.Request != request {
		t.Fatalf("request identity lost: %#v", segment.Request)
	}
	if segment.Conformity != DeviceIDConformity(0x81) {
		t.Fatalf("conformity = 0x%02x", segment.Conformity)
	}
	if segment.MoreFollows || segment.NextObjectID != 0 {
		t.Fatalf("unexpected completion fields: %#v", segment)
	}
	want := []DeviceIDObject{
		{ID: 0x00, Value: []byte{0xff, 0x00, 0x41}},
		{ID: 0x01, Value: []byte{0xc3, 0x28}},
		{ID: 0x02, Value: []byte{0x20}},
	}
	if !reflect.DeepEqual(segment.Objects, want) {
		t.Fatalf("objects = %#v, want %#v", segment.Objects, want)
	}
	pdu[9] = 0x42
	if segment.Objects[0].Value[0] != 0xff {
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
	base := DeviceIDSegment{
		Request:      first,
		Conformity:   0x82,
		MoreFollows:  true,
		NextObjectID: 2,
		Objects: []DeviceIDObject{
			{ID: 0, Value: []byte{0}},
			{ID: 1, Value: []byte{1}},
		},
	}
	second, err := NextDeviceIDRequest(base)
	if err != nil {
		t.Fatal(err)
	}
	segments := []DeviceIDSegment{
		base,
		{
			Request:    second,
			Conformity: 0x82,
			Objects: []DeviceIDObject{
				{ID: 2, Value: []byte{2}},
				{ID: 4, Value: []byte{4}},
			},
		},
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
	segments[0].Objects[0].Value[0] = 9
	if result.Objects[0].Value[0] != 0 {
		t.Fatal("aggregate aliases caller-owned object bytes")
	}
}

func TestAggregateDeviceIDRejectsPartialOrNonProgressingTraversal(t *testing.T) {
	first, _ := NewDeviceIDRequest(DeviceIDBasic, 0)
	base := DeviceIDSegment{
		Request:      first,
		Conformity:   0x01,
		MoreFollows:  true,
		NextObjectID: 2,
		Objects: []DeviceIDObject{
			{ID: 0, Value: []byte{0}},
			{ID: 1, Value: []byte{1}},
		},
	}
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
				{Request: first, Conformity: 0x01, Objects: []DeviceIDObject{{ID: 2, Value: []byte{2}}}},
			},
			DefaultDeviceIDLimits(),
		},
		{
			"duplicate across segments",
			[]DeviceIDSegment{
				base,
				{Request: cursorTwo, Conformity: 0x01, Objects: []DeviceIDObject{{ID: 1, Value: []byte{2}}}},
			},
			DefaultDeviceIDLimits(),
		},
		{
			"conformity regression",
			[]DeviceIDSegment{
				base,
				{Request: cursorTwo, Conformity: 0x81, Objects: []DeviceIDObject{{ID: 2, Value: []byte{2}}}},
			},
			DefaultDeviceIDLimits(),
		},
		{
			"missing mandatory object",
			[]DeviceIDSegment{{Request: first, Conformity: 0x01, Objects: []DeviceIDObject{{ID: 0, Value: []byte{0}}}}},
			DefaultDeviceIDLimits(),
		},
		{
			"segment bound",
			[]DeviceIDSegment{
				base,
				{Request: cursorTwo, Conformity: 0x01, Objects: []DeviceIDObject{{ID: 2, Value: []byte{2}}}},
			},
			DeviceIDLimits{MaxSegments: 1, MaxObjects: 256, MaxValueBytes: 62464},
		},
		{
			"object bound",
			[]DeviceIDSegment{
				base,
				{Request: cursorTwo, Conformity: 0x01, Objects: []DeviceIDObject{{ID: 2, Value: []byte{2}}}},
			},
			DeviceIDLimits{MaxSegments: 256, MaxObjects: 2, MaxValueBytes: 62464},
		},
		{
			"value bound",
			[]DeviceIDSegment{
				base,
				{Request: cursorTwo, Conformity: 0x01, Objects: []DeviceIDObject{{ID: 2, Value: []byte{2}}}},
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
				[]DeviceIDSegment{{
					Request:    first,
					Conformity: 0x01,
					Objects:    test.objects,
				}},
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
	segments := []DeviceIDSegment{{
		Request:    first,
		Conformity: 0x01,
		Objects: []DeviceIDObject{
			{ID: 0, Value: []byte{0}},
			{ID: 1, Value: []byte{1}},
			{ID: 2, Value: []byte{2}},
		},
	}}
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
