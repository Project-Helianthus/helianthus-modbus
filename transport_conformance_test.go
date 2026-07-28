package modbus

import (
	"bytes"
	"context"
	"testing"
	"time"
)

func rtuDeviceIDTestPlan(t *testing.T) RTUDeviceIDPlan {
	t.Helper()
	request, err := NewDeviceIDRequest(DeviceIDIndividual, 5)
	if err != nil {
		t.Fatal(err)
	}
	return RTUDeviceIDPlan{
		UnitID:             1,
		AuthorizationScope: "scope-device-id",
		PollGeneration:     8,
		DeadlineIdentity:   10,
		Timeout:            50 * time.Millisecond,
		Request:            request,
	}
}

func observeRTUDeviceIDFrame(
	endpoint *RTUFixtureEndpoint,
	clock *virtualTCPClock,
	frame []byte,
) (RTUDeviceIDResult, error) {
	for index, value := range frame {
		if index != 0 {
			clock.Advance(endpoint.timing.CharacterTime())
		}
		if err := endpoint.FeedByte(value); err != nil {
			return RTUDeviceIDResult{}, err
		}
	}
	clock.Advance(endpoint.timing.InterFrame())
	return endpoint.EndDeviceIDFrame()
}

func TestRTUDeviceIDAccessADUFramingAndSegmentDecode(t *testing.T) {
	request, err := NewDeviceIDRequest(DeviceIDRegular, 0)
	if err != nil {
		t.Fatal(err)
	}
	got, err := EncodeRTUDeviceIDAccessADU(0x11, request)
	if err != nil {
		t.Fatal(err)
	}
	want := rtuTestFrame(0x11, 0x2b, 0x0e, 0x02, 0x00)
	if !bytes.Equal(got, want) {
		t.Fatalf("RTU Device ID request = %x, want %x", got, want)
	}

	frame := rtuTestFrame(
		0x11,
		0x2b, 0x0e, 0x02, 0x82, 0x00, 0x00, 0x03,
		0x00, 0x01, 'v',
		0x01, 0x01, 'p',
		0x02, 0x01, 'r',
	)
	adu, err := DecodeRTUDeviceIDResponseADU(0x11, request, frame)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(adu.Bytes(), frame) {
		t.Fatalf("raw frame = %x, want %x", adu.Bytes(), frame)
	}
	segment := adu.Segment()
	if segment.Request().Access() != DeviceIDRegular ||
		segment.MoreFollows() ||
		segment.NextObjectID() != 0 ||
		len(segment.Objects()) != 3 {
		t.Fatalf("segment = %#v", segment)
	}
}

func TestRTUDeviceIDResponseRetainsExceptionAndMalformedRawFrame(
	t *testing.T,
) {
	request, err := NewDeviceIDRequest(DeviceIDIndividual, 5)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		pdu  []byte
		kind ErrorKind
	}{
		{
			name: "exception",
			pdu:  []byte{0xab, 0x02},
			kind: ErrorExceptionResponse,
		},
		{
			name: "wrong MEI",
			pdu:  []byte{0x2b, 0x0d, 0x04, 0x83, 0, 0, 1, 5, 1, 'x'},
			kind: ErrorMalformedResponse,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			frame := rtuTestFrame(0x11, test.pdu...)
			adu, err := DecodeRTUDeviceIDResponseADU(
				0x11,
				request,
				frame,
			)
			_ = requireProtocolError(t, err, test.kind)
			if !bytes.Equal(adu.Bytes(), frame) {
				t.Fatalf("raw frame = %x, want %x", adu.Bytes(), frame)
			}
		})
	}
}

func TestRTUDeviceIDEndpointDeliversSegmentWithWireProvenance(t *testing.T) {
	endpoint, clock, _ := newRTUTestEndpoint(t)
	plan := rtuDeviceIDTestPlan(t)
	handle, requestFrame, err := endpoint.BeginDeviceID(
		context.Background(),
		plan,
	)
	if err != nil {
		t.Fatal(err)
	}
	wantRequest := rtuTestFrame(1, 0x2b, 0x0e, 0x04, 0x05)
	if !bytes.Equal(requestFrame, wantRequest) {
		t.Fatalf("request frame = %x, want %x", requestFrame, wantRequest)
	}
	if err := endpoint.CompleteTransmit(handle, TransmitComplete); err != nil {
		t.Fatal(err)
	}
	frame := rtuTestFrame(
		1,
		0x2b, 0x0e, 0x04, 0x83, 0x00, 0x00, 0x01,
		0x05, 0x01, 'x',
	)
	result, err := observeRTUDeviceIDFrame(endpoint, clock, frame)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Deliverable() {
		t.Fatal("valid Device ID segment was not deliverable")
	}
	segment := result.Segment()
	if len(segment.Objects()) != 1 ||
		segment.Objects()[0].ID != 5 ||
		!bytes.Equal(segment.Objects()[0].Value, []byte{'x'}) {
		t.Fatalf("segment = %#v", segment)
	}
	wire := result.WireResponse()
	provenance := wire.Provenance()
	if wire.PhysicalRequestID() != handle.RequestID() ||
		provenance.Transport != TransportRTU ||
		provenance.RequestedFunction != FunctionEncapsulatedInterface ||
		provenance.ReceivedFunction != FunctionEncapsulatedInterface ||
		provenance.DeviceIDAccess != DeviceIDIndividual ||
		provenance.DeviceIDObjectID != 5 {
		t.Fatalf("wire/provenance = %#v / %#v", wire, provenance)
	}
	if !bytes.Equal(wire.Bytes(), frame) {
		t.Fatalf("wire bytes = %x, want %x", wire.Bytes(), frame)
	}
}

func TestRTUDeviceIDMalformedCandidateTerminalizesWithWireIdentity(
	t *testing.T,
) {
	endpoint, clock, _ := newRTUTestEndpoint(t)
	plan := rtuDeviceIDTestPlan(t)
	handle, _, err := endpoint.BeginDeviceID(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := endpoint.CompleteTransmit(handle, TransmitComplete); err != nil {
		t.Fatal(err)
	}
	frame := rtuTestFrame(
		1,
		0x2b, 0x0d, 0x04, 0x83, 0x00, 0x00, 0x01,
		0x05, 0x01, 'x',
	)
	result, err := observeRTUDeviceIDFrame(endpoint, clock, frame)
	_ = requireProtocolError(t, err, ErrorMalformedResponse)
	wire := result.WireResponse()
	if result.Deliverable() ||
		wire.Outcome() != WireMalformedResponse ||
		wire.PhysicalRequestID() != handle.RequestID() ||
		wire.WireResponseID() == 0 ||
		!bytes.Equal(wire.Bytes(), frame) {
		t.Fatalf("result/wire = %#v / %#v", result, wire)
	}
}

func TestRTUEndFrameOperationTypeMismatchDoesNotConsumeFrame(t *testing.T) {
	t.Run("Device ID frame through read API", func(t *testing.T) {
		endpoint, clock, _ := newRTUTestEndpoint(t)
		plan := rtuDeviceIDTestPlan(t)
		handle, _, err := endpoint.BeginDeviceID(context.Background(), plan)
		if err != nil {
			t.Fatal(err)
		}
		if err := endpoint.CompleteTransmit(
			handle,
			TransmitComplete,
		); err != nil {
			t.Fatal(err)
		}
		frame := rtuTestFrame(
			1,
			0x2b, 0x0e, 0x04, 0x83, 0x00, 0x00, 0x01,
			0x05, 0x01, 'x',
		)
		for index, value := range frame {
			if index != 0 {
				clock.Advance(endpoint.timing.CharacterTime())
			}
			if err := endpoint.FeedByte(value); err != nil {
				t.Fatal(err)
			}
		}
		clock.Advance(endpoint.timing.InterFrame())
		if _, err := endpoint.EndFrame(); err == nil {
			t.Fatal("read API consumed a Device ID frame")
		}
		result, err := endpoint.EndDeviceIDFrame()
		if err != nil || !result.Deliverable() {
			t.Fatalf("Device ID result/error = %#v / %v", result, err)
		}
	})

	t.Run("read frame through Device ID API", func(t *testing.T) {
		endpoint, clock, _ := newRTUTestEndpoint(t)
		handle := beginRTUTestRead(t, endpoint)
		if err := endpoint.CompleteTransmit(
			handle,
			TransmitComplete,
		); err != nil {
			t.Fatal(err)
		}
		frame := rtuTestFrame(1, 0x03, 0x06, 0, 1, 0, 2, 0, 3)
		for index, value := range frame {
			if index != 0 {
				clock.Advance(endpoint.timing.CharacterTime())
			}
			if err := endpoint.FeedByte(value); err != nil {
				t.Fatal(err)
			}
		}
		clock.Advance(endpoint.timing.InterFrame())
		if _, err := endpoint.EndDeviceIDFrame(); err == nil {
			t.Fatal("Device ID API consumed a read frame")
		}
		result, err := endpoint.EndFrame()
		if err != nil || !result.Deliverable() {
			t.Fatalf("read result/error = %#v / %v", result, err)
		}
	})
}

func deviceIDConformanceSegments() (DeviceIDRequest, [][]byte) {
	request, err := NewDeviceIDRequest(DeviceIDBasic, 0)
	if err != nil {
		panic(err)
	}
	return request, [][]byte{
		{
			0x2b, 0x0e, 0x01, 0x81, 0xff, 0x02, 0x02,
			0x00, 0x01, 'v',
			0x01, 0x01, 'p',
		},
		{
			0x2b, 0x0e, 0x01, 0x81, 0x00, 0x00, 0x01,
			0x02, 0x01, 'r',
		},
	}
}

func TestTCPDeviceIDTraversalAcrossTransportFrames(t *testing.T) {
	first, pdus := deviceIDConformanceSegments()
	owner := newTestConnectionOwner(t, 4, 4)
	request := first
	var segments []DeviceIDSegment
	for _, pdu := range pdus {
		reservation, err := owner.ReserveDeviceID(1, request)
		if err != nil {
			t.Fatal(err)
		}
		if err := owner.MarkWriteInvoked(reservation); err != nil {
			t.Fatal(err)
		}
		if _, err := owner.RecordTransmit(
			reservation,
			TransmitComplete,
		); err != nil {
			t.Fatal(err)
		}
		wire, err := owner.Correlate(
			1,
			testTCPFrame(t, reservation.TransactionID(), 1, pdu),
		)
		if err != nil {
			t.Fatal(err)
		}
		segment, ok := wire.DeviceIDSegment()
		if !ok || !wire.Deliverable() {
			t.Fatalf("wire = %#v", wire)
		}
		segments = append(segments, segment)
		if segment.MoreFollows() {
			request, err = NextDeviceIDRequest(segment)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	result, err := AggregateDeviceID(
		first,
		segments,
		DefaultDeviceIDLimits(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Segments) != 2 || len(result.Objects) != 3 {
		t.Fatalf("result = %#v", result)
	}
}

func TestRTUDeviceIDTraversalAcrossFixtureFrames(t *testing.T) {
	first, pdus := deviceIDConformanceSegments()
	endpoint, clock, _ := newRTUTestEndpoint(t)
	request := first
	var segments []DeviceIDSegment
	for index, pdu := range pdus {
		plan := rtuDeviceIDTestPlan(t)
		plan.Request = request
		handle, _, err := endpoint.BeginDeviceID(
			context.Background(),
			plan,
		)
		if err != nil {
			t.Fatal(err)
		}
		if err := endpoint.CompleteTransmit(
			handle,
			TransmitComplete,
		); err != nil {
			t.Fatal(err)
		}
		result, err := observeRTUDeviceIDFrame(
			endpoint,
			clock,
			rtuTestFrame(1, pdu...),
		)
		if err != nil {
			t.Fatal(err)
		}
		if !result.Deliverable() {
			t.Fatalf("result = %#v", result)
		}
		segment := result.Segment()
		segments = append(segments, segment)
		if !segment.MoreFollows() {
			continue
		}
		request, err = NextDeviceIDRequest(segment)
		if err != nil {
			t.Fatal(err)
		}
		if index != len(pdus)-1 {
			clock.Advance(endpoint.timing.InterFrame())
			if err := endpoint.TryResynchronize(); err != nil {
				t.Fatal(err)
			}
		}
	}
	result, err := AggregateDeviceID(
		first,
		segments,
		DefaultDeviceIDLimits(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Segments) != 2 || len(result.Objects) != 3 {
		t.Fatalf("result = %#v", result)
	}
}

func TestTCPDeviceIDExceptionAndMalformedTransportResponses(t *testing.T) {
	request, err := NewDeviceIDRequest(DeviceIDIndividual, 5)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		pdu     []byte
		kind    ErrorKind
		outcome WireOutcome
	}{
		{
			name:    "exception",
			pdu:     []byte{0xab, 0x02},
			kind:    ErrorExceptionResponse,
			outcome: WireProtocolException,
		},
		{
			name: "malformed",
			pdu: []byte{
				0x2b, 0x0d, 0x04, 0x83, 0x00, 0x00, 0x01,
				0x05, 0x01, 'x',
			},
			kind:    ErrorMalformedResponse,
			outcome: WireMalformedResponse,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			owner := newTestConnectionOwner(t, 1, 1)
			reservation, err := owner.ReserveDeviceID(1, request)
			if err != nil {
				t.Fatal(err)
			}
			if err := owner.MarkWriteInvoked(reservation); err != nil {
				t.Fatal(err)
			}
			if _, err := owner.RecordTransmit(
				reservation,
				TransmitComplete,
			); err != nil {
				t.Fatal(err)
			}
			frame := testTCPFrame(
				t,
				reservation.TransactionID(),
				1,
				test.pdu,
			)
			wire, err := owner.Correlate(1, frame)
			_ = requireProtocolError(t, err, test.kind)
			if wire.Deliverable() ||
				wire.Outcome() != test.outcome ||
				wire.PhysicalRequestID() != reservation.PhysicalRequestID() ||
				wire.WireResponseID() == 0 {
				t.Fatalf("wire = %#v", wire)
			}
		})
	}
}

func TestRTUDeviceIDExceptionTerminalizesWithWireIdentity(t *testing.T) {
	endpoint, clock, _ := newRTUTestEndpoint(t)
	plan := rtuDeviceIDTestPlan(t)
	handle, _, err := endpoint.BeginDeviceID(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := endpoint.CompleteTransmit(handle, TransmitComplete); err != nil {
		t.Fatal(err)
	}
	frame := rtuTestFrame(1, 0xab, 0x02)
	result, err := observeRTUDeviceIDFrame(endpoint, clock, frame)
	_ = requireProtocolError(t, err, ErrorExceptionResponse)
	wire := result.WireResponse()
	if result.Deliverable() ||
		wire.Outcome() != WireProtocolException ||
		wire.PhysicalRequestID() != handle.RequestID() ||
		wire.WireResponseID() == 0 {
		t.Fatalf("result/wire = %#v / %#v", result, wire)
	}
}

func TestTCPRemainsAvailableWhenRTUCapabilityIsDisabled(t *testing.T) {
	capability := CurrentRTUCapability()
	if capability.DefaultEnabled() ||
		capability.Supported() ||
		capability.HardwareQualified() {
		t.Fatal("RTU unexpectedly enabled or qualified")
	}
	request, err := NewReadRegistersRequest(
		FunctionReadHoldingRegisters,
		0,
		1,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := EncodeTCPReadADU(1, 1, request); err != nil {
		t.Fatalf("disabled RTU gated TCP: %v", err)
	}
}
