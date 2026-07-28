package modbus

import (
	"context"
	"io"
	"net"
	"reflect"
	"testing"
	"time"
)

func endpointWriteDeviceID(
	t *testing.T,
	endpoint *TCPEndpoint,
	dispatch TCPDispatch,
	peer net.Conn,
) []byte {
	t.Helper()
	written := make(chan struct {
		bytes []byte
		err   error
	}, 1)
	go func() {
		bytes := make([]byte, 11)
		_, err := io.ReadFull(peer, bytes)
		written <- struct {
			bytes []byte
			err   error
		}{bytes: bytes, err: err}
	}()
	if _, err := endpoint.Write(context.Background(), dispatch); err != nil {
		t.Fatal(err)
	}
	result := <-written
	if result.err != nil {
		t.Fatal(result.err)
	}
	return result.bytes
}

func TestTCPEndpointDeviceIDTraversalPublishesOnlyCompleteAggregate(
	t *testing.T,
) {
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
	initial, err := NewDeviceIDRequest(DeviceIDRegular, 0)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := endpoint.EnqueueDeviceID(TCPDeviceIDPlan{
		Connection:         connection,
		UnitID:             1,
		AuthorizationScope: "endpoint-device-id-test",
		PollGeneration:     1,
		DeadlineIdentity:   1,
		Timeout:            time.Second,
		Request:            initial,
		Limits:             DefaultDeviceIDLimits(),
	})
	if err != nil {
		t.Fatal(err)
	}

	firstDispatch, ok := endpoint.Dispatch()
	if !ok {
		t.Fatal("first Device ID segment was not scheduled")
	}
	firstRequest := endpointWriteDeviceID(
		t,
		endpoint,
		firstDispatch,
		peer,
	)
	if got := firstRequest[7:]; !reflect.DeepEqual(
		got,
		[]byte{0x2b, 0x0e, 0x02, 0x00},
	) {
		t.Fatalf("first request PDU=%x", got)
	}
	firstResponse := testTCPFrame(
		t,
		uint16(firstRequest[0])<<8|uint16(firstRequest[1]),
		1,
		[]byte{
			0x2b, 0x0e, 0x02, 0x82, 0xff, 0x02, 0x02,
			0x00, 0x01, 'A',
			0x01, 0x01, 'B',
		},
	)
	firstSent := endpointSendFrame(peer, firstResponse.Bytes())
	firstBatch, err := endpoint.Read(context.Background(), connection)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-firstSent; err != nil {
		t.Fatal(err)
	}
	if len(firstBatch.DeviceIDs) != 0 {
		t.Fatalf("partial aggregate was published: %#v", firstBatch.DeviceIDs)
	}

	secondDispatch, ok := endpoint.Dispatch()
	if !ok {
		t.Fatal("continuation segment was not scheduled")
	}
	secondRequest := endpointWriteDeviceID(
		t,
		endpoint,
		secondDispatch,
		peer,
	)
	if got := secondRequest[7:]; !reflect.DeepEqual(
		got,
		[]byte{0x2b, 0x0e, 0x02, 0x02},
	) {
		t.Fatalf("continuation request PDU=%x", got)
	}
	secondResponse := testTCPFrame(
		t,
		uint16(secondRequest[0])<<8|uint16(secondRequest[1]),
		1,
		[]byte{
			0x2b, 0x0e, 0x02, 0x82, 0x00, 0x00, 0x01,
			0x02, 0x01, 'C',
		},
	)
	secondSent := endpointSendFrame(peer, secondResponse.Bytes())
	secondBatch, err := endpoint.Read(context.Background(), connection)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-secondSent; err != nil {
		t.Fatal(err)
	}
	if len(secondBatch.DeviceIDs) != 1 {
		t.Fatalf("complete aggregates=%d", len(secondBatch.DeviceIDs))
	}
	completion := secondBatch.DeviceIDs[0]
	if completion.RequestID != handle.RequestID() {
		t.Fatalf(
			"completion request=%d want=%d",
			completion.RequestID,
			handle.RequestID(),
		)
	}
	wantObjects := []DeviceIDObject{
		{ID: 0, Value: []byte{'A'}},
		{ID: 1, Value: []byte{'B'}},
		{ID: 2, Value: []byte{'C'}},
	}
	if !reflect.DeepEqual(completion.Result.Objects, wantObjects) {
		t.Fatalf(
			"aggregate objects=%#v want=%#v",
			completion.Result.Objects,
			wantObjects,
		)
	}
	if snapshot := endpoint.Snapshot(); snapshot.Resources.LiveRequests != 0 {
		t.Fatalf("completed traversal retained live state: %#v", snapshot)
	}
}
