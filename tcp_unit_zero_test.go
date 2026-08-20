package modbus

import (
	"context"
	"net"
	"reflect"
	"testing"
	"time"
)

func TestTCPUnitZeroReadIsCorrelatedEndToEnd(t *testing.T) {
	clock := &virtualTCPClock{}
	endpoint, err := NewTCPEndpoint(endpointConfigForTest(clock, nil))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = endpoint.Close() }()
	client, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	connection, err := endpoint.openTestConnection(client)
	if err != nil {
		t.Fatal(err)
	}
	plan := endpointPlan(t, connection, time.Second, 91, 30000)
	plan.UnitID = 0
	handle, err := endpoint.EnqueueRead(plan)
	if err != nil {
		t.Fatal(err)
	}
	dispatch, ok := endpoint.Dispatch()
	if !ok {
		t.Fatal("unit-zero request not dispatched")
	}
	request := endpointWriteOne(t, endpoint, dispatch, peer)
	if request[6] != 0 {
		t.Fatalf("MBAP unit=%d", request[6])
	}
	sent := endpointSendFrame(peer, endpointResponse(request, 0, 0x1234))
	batch, err := endpoint.Read(context.Background(), connection)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-sent; err != nil {
		t.Fatal(err)
	}
	if len(batch.Responses) != 1 || batch.Responses[0].PhysicalRequestID() != handle.RequestID() || batch.Responses[0].Provenance().UnitID != 0 || !reflect.DeepEqual(batch.Responses[0].Words(), []uint16{0x1234}) {
		t.Fatalf("unit-zero batch=%#v", batch)
	}
}

func TestTCPUnitZeroIntentAndADUStayTCPOnly(t *testing.T) {
	read, err := NewReadRegistersRequest(FunctionReadHoldingRegisters, 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	adu, err := EncodeTCPReadADU(7, 0, read)
	if err != nil || adu[6] != 0 {
		t.Fatalf("TCP unit-zero ADU=%x err=%v", adu, err)
	}
	spec := ReadIntentSpec{
		LogicalViewID: 1, Endpoint: "tcp://192.0.2.10:502", Transport: TransportTCP,
		TransportGeneration: 1, UnitID: 0, AuthorizationScope: "unit-zero",
		PollGeneration: 1, DeadlineIdentity: 1, Request: read,
	}
	if _, err := NewReadIntent(spec); err != nil {
		t.Fatal(err)
	}
	spec.Transport = TransportRTU
	if _, err := NewReadIntent(spec); err == nil {
		t.Fatal("RTU unit-zero response-bearing intent accepted")
	}
	if _, err := EncodeRTUReadADU(0, read); err == nil {
		t.Fatal("RTU unit-zero read encoded")
	}
	for _, unitID := range []byte{248, 255} {
		if _, err := EncodeTCPReadADU(1, unitID, read); err == nil {
			t.Fatalf("reserved TCP unit %d accepted", unitID)
		}
	}
}

func TestTCPEndpointUnitZeroWrappedDeviceIDStream(t *testing.T) {
	clock := &virtualTCPClock{}
	endpoint, err := NewTCPEndpoint(endpointConfigForTest(clock, nil))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = endpoint.Close() }()
	client, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	connection, err := endpoint.openTestConnection(client)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := NewExtendedDeviceIDStreamRequest(0x87)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := endpoint.EnqueueDeviceID(TCPDeviceIDPlan{
		Connection: connection, UnitID: 0, AuthorizationScope: "unit-zero-device-id",
		PollGeneration: 1, DeadlineIdentity: 1, Timeout: time.Second,
		Request: initial, Limits: DefaultDeviceIDLimits(),
	})
	if err != nil {
		t.Fatal(err)
	}
	responses := []struct {
		wantObject byte
		pdu        []byte
	}{
		{0x87, []byte{0x2b, 0x0e, 0x03, 0x83, 0xff, 0xff, 1, 0x87, 1, 'c'}},
		{0xff, []byte{0x2b, 0x0e, 0x03, 0x83, 0xff, 0x00, 1, 0xff, 1, 'h'}},
		{0x00, []byte{0x2b, 0x0e, 0x03, 0x83, 0x00, 0x00, 1, 0x00, 1, 'l'}},
	}
	var completion TCPDeviceIDCompletion
	for index, step := range responses {
		dispatch, ok := endpoint.Dispatch()
		if !ok {
			t.Fatalf("dispatch %d absent", index)
		}
		request := endpointWriteDeviceID(t, endpoint, dispatch, peer)
		if request[6] != 0 || request[10] != step.wantObject {
			t.Fatalf("request %d=%x", index, request)
		}
		frame := testTCPFrame(t, uint16(request[0])<<8|uint16(request[1]), 0, step.pdu)
		sent := endpointSendFrame(peer, frame.Bytes())
		batch, readErr := endpoint.Read(context.Background(), connection)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if err := <-sent; err != nil {
			t.Fatal(err)
		}
		if index < len(responses)-1 && len(batch.DeviceIDs) != 0 {
			t.Fatalf("partial completion at %d: %#v", index, batch.DeviceIDs)
		}
		if index == len(responses)-1 {
			if len(batch.DeviceIDs) != 1 {
				t.Fatalf("completions=%d", len(batch.DeviceIDs))
			}
			completion = batch.DeviceIDs[0]
		}
	}
	if completion.RequestID != handle.RequestID() || len(completion.Result.Objects) != 3 {
		t.Fatalf("completion=%#v", completion)
	}
	want := []byte{0x87, 0xff, 0x00}
	for index, object := range completion.Result.Objects {
		if object.ID != want[index] {
			t.Fatalf("object[%d]=0x%02x", index, object.ID)
		}
	}
}
