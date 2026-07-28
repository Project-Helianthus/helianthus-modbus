package modbus

import (
	"context"
	"errors"
	"io"
	"net"
	"reflect"
	"sync"
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

func TestTCPEndpointDeviceIDExceptionAndMalformedAreTerminal(
	t *testing.T,
) {
	tests := []struct {
		name    string
		pdu     []byte
		outcome WireOutcome
	}{
		{
			name:    "exception",
			pdu:     []byte{0xab, 0x02},
			outcome: WireProtocolException,
		},
		{
			name: "wrong MEI",
			pdu: []byte{
				0x2b, 0x0d, 0x04, 0x83, 0x00, 0x00, 0x01,
				0x05, 0x01, 'x',
			},
			outcome: WireMalformedResponse,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clock := &virtualTCPClock{}
			endpoint, err := NewTCPEndpoint(
				endpointConfigForTest(clock, nil),
			)
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
			request, err := NewDeviceIDRequest(
				DeviceIDIndividual,
				5,
			)
			if err != nil {
				t.Fatal(err)
			}
			_, err = endpoint.EnqueueDeviceID(TCPDeviceIDPlan{
				Connection:         connection,
				UnitID:             1,
				AuthorizationScope: "endpoint-device-id-failure",
				PollGeneration:     1,
				DeadlineIdentity:   1,
				Timeout:            time.Second,
				Request:            request,
				Limits:             DefaultDeviceIDLimits(),
			})
			if err != nil {
				t.Fatal(err)
			}
			dispatch, ok := endpoint.Dispatch()
			if !ok {
				t.Fatal("Device ID request was not scheduled")
			}
			wire := endpointWriteDeviceID(t, endpoint, dispatch, peer)
			response := testTCPFrame(
				t,
				uint16(wire[0])<<8|uint16(wire[1]),
				1,
				test.pdu,
			)
			sent := endpointSendFrame(peer, response.Bytes())
			batch, readErr := endpoint.Read(
				context.Background(),
				connection,
			)
			if err := <-sent; err != nil {
				t.Fatal(err)
			}
			wantKind := ErrorMalformedResponse
			if test.outcome == WireProtocolException {
				wantKind = ErrorExceptionResponse
			}
			_ = requireProtocolError(t, readErr, wantKind)
			if len(batch.Responses) != 1 ||
				batch.Responses[0].Outcome() != test.outcome ||
				len(batch.DeviceIDs) != 0 {
				t.Fatalf("failure batch=%#v", batch)
			}
			if snapshot := endpoint.Snapshot(); snapshot.Resources.LiveRequests != 0 ||
				snapshot.Resources.InFlightRequests != 0 {
				t.Fatalf("failure retained state: %#v", snapshot)
			}
		})
	}
}

func TestTCPEndpointDeviceIDQueuedCancellationReleasesScheduler(
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
	request, err := NewDeviceIDRequest(DeviceIDBasic, 0)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := endpoint.EnqueueDeviceID(TCPDeviceIDPlan{
		Connection:         connection,
		UnitID:             1,
		AuthorizationScope: "endpoint-device-id-cancel",
		PollGeneration:     1,
		DeadlineIdentity:   1,
		Timeout:            time.Second,
		Request:            request,
		Limits:             DefaultDeviceIDLimits(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := endpoint.Cancel(handle); err != nil {
		t.Fatal(err)
	}
	if _, ok := endpoint.Dispatch(); ok {
		t.Fatal("cancelled Device ID request remained dispatchable")
	}
	snapshot := endpoint.Snapshot()
	if snapshot.Resources.LiveRequests != 0 ||
		snapshot.Resources.QueuedRequests != 0 ||
		snapshot.Resources.InFlightRequests != 0 {
		t.Fatalf("cancellation retained state: %#v", snapshot)
	}
}

func TestTCPEndpointDeviceIDCancellationOwnsWriteBoundary(
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
	writeStarted := make(chan struct{})
	connection, err := endpoint.openTestConnection(&writeStartedConn{
		Conn:    client,
		started: writeStarted,
	})
	if err != nil {
		t.Fatal(err)
	}
	request, err := NewDeviceIDRequest(DeviceIDIndividual, 5)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := endpoint.EnqueueDeviceID(TCPDeviceIDPlan{
		Connection:         connection,
		UnitID:             1,
		AuthorizationScope: "endpoint-device-id-write-cancel",
		PollGeneration:     1,
		DeadlineIdentity:   1,
		Timeout:            time.Second,
		Request:            request,
		Limits:             DefaultDeviceIDLimits(),
	})
	if err != nil {
		t.Fatal(err)
	}
	dispatch, ok := endpoint.Dispatch()
	if !ok {
		t.Fatal("Device ID dispatch missing")
	}
	writeDone := make(chan error, 1)
	go func() {
		_, writeErr := endpoint.Write(context.Background(), dispatch)
		writeDone <- writeErr
	}()
	select {
	case <-writeStarted:
	case <-time.After(time.Second):
		t.Fatal("Device ID write did not reach invocation boundary")
	}
	if err := endpoint.Cancel(handle); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-writeDone:
		if err == nil {
			t.Fatal("cancelled Device ID write succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("Device ID write ignored cancellation")
	}
	snapshot := endpoint.Snapshot()
	if snapshot.Resources.LiveRequests != 0 ||
		snapshot.Resources.InFlightRequests != 0 {
		t.Fatalf("write cancellation retained state: %#v", snapshot)
	}
}

func TestTCPEndpointDeviceIDCancellationAfterWriteBeforeWaitingTombstones(
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
	request, err := NewDeviceIDRequest(DeviceIDIndividual, 5)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := endpoint.EnqueueDeviceID(TCPDeviceIDPlan{
		Connection:         connection,
		UnitID:             1,
		AuthorizationScope: "endpoint-device-id-post-write-cancel",
		PollGeneration:     1,
		DeadlineIdentity:   1,
		Timeout:            time.Second,
		Request:            request,
		Limits:             DefaultDeviceIDLimits(),
	})
	if err != nil {
		t.Fatal(err)
	}
	dispatch, ok := endpoint.Dispatch()
	if !ok {
		t.Fatal("Device ID dispatch missing")
	}
	writeReturned := make(chan struct{})
	releaseWriter := make(chan struct{})
	endpoint.afterWrite = func() {
		close(writeReturned)
		<-releaseWriter
	}
	wireDone := make(chan struct {
		bytes []byte
		err   error
	}, 1)
	go func() {
		bytes := make([]byte, 11)
		_, readErr := io.ReadFull(peer, bytes)
		wireDone <- struct {
			bytes []byte
			err   error
		}{bytes: bytes, err: readErr}
	}()
	writeDone := make(chan error, 1)
	go func() {
		_, writeErr := endpoint.Write(context.Background(), dispatch)
		writeDone <- writeErr
	}()
	select {
	case <-writeReturned:
	case <-time.After(time.Second):
		t.Fatal("write did not reach pre-publication boundary")
	}
	wireResult := <-wireDone
	if wireResult.err != nil {
		t.Fatal(wireResult.err)
	}
	cancelDone := make(chan error, 1)
	go func() {
		cancelDone <- endpoint.Cancel(handle)
	}()
	deadline := time.Now().Add(time.Second)
	for {
		endpoint.mu.Lock()
		current := endpoint.requests[handle.RequestID()]
		pending := current != nil && current.cancelPending
		endpoint.mu.Unlock()
		if pending {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("cancellation did not claim the write boundary")
		}
		time.Sleep(time.Millisecond)
	}
	close(releaseWriter)
	if err := <-writeDone; err != nil {
		t.Fatalf("completed write returned error: %v", err)
	}
	if err := <-cancelDone; err != nil {
		t.Fatal(err)
	}

	late := testTCPFrame(
		t,
		uint16(wireResult.bytes[0])<<8|uint16(wireResult.bytes[1]),
		1,
		[]byte{
			0x2b, 0x0e, 0x04, 0x83, 0x00, 0x00, 0x01,
			0x05, 0x01, 'x',
		},
	)
	sent := endpointSendFrame(peer, late.Bytes())
	batch, err := endpoint.Read(context.Background(), connection)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-sent; err != nil {
		t.Fatal(err)
	}
	if len(batch.Responses) != 1 ||
		batch.Responses[0].Outcome() != WireLateAfterAbandonment ||
		len(batch.DeviceIDs) != 0 {
		t.Fatalf("post-write cancellation batch=%#v", batch)
	}
}

func TestTCPEndpointDeviceIDWaitingCancellationDropsLateResponse(
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
	request, err := NewDeviceIDRequest(DeviceIDIndividual, 5)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := endpoint.EnqueueDeviceID(TCPDeviceIDPlan{
		Connection:         connection,
		UnitID:             1,
		AuthorizationScope: "endpoint-device-id-late",
		PollGeneration:     1,
		DeadlineIdentity:   1,
		Timeout:            time.Second,
		Request:            request,
		Limits:             DefaultDeviceIDLimits(),
	})
	if err != nil {
		t.Fatal(err)
	}
	dispatch, ok := endpoint.Dispatch()
	if !ok {
		t.Fatal("Device ID dispatch missing")
	}
	wire := endpointWriteDeviceID(t, endpoint, dispatch, peer)
	if err := endpoint.Cancel(handle); err != nil {
		t.Fatal(err)
	}
	late := testTCPFrame(
		t,
		uint16(wire[0])<<8|uint16(wire[1]),
		1,
		[]byte{
			0x2b, 0x0e, 0x04, 0x83, 0x00, 0x00, 0x01,
			0x05, 0x01, 'x',
		},
	)
	sent := endpointSendFrame(peer, late.Bytes())
	batch, err := endpoint.Read(context.Background(), connection)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-sent; err != nil {
		t.Fatal(err)
	}
	if len(batch.Responses) != 1 ||
		batch.Responses[0].Outcome() != WireLateAfterAbandonment ||
		batch.Responses[0].Deliverable() ||
		len(batch.DeviceIDs) != 0 {
		t.Fatalf("late response batch=%#v", batch)
	}
	snapshot := endpoint.Snapshot()
	if snapshot.Resources.LiveRequests != 0 ||
		snapshot.Resources.InFlightRequests != 0 {
		t.Fatalf("late response retained state: %#v", snapshot)
	}
}

func TestTCPEndpointDeviceIDResponseAndCancellationLinearize(
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
	request, err := NewDeviceIDRequest(DeviceIDIndividual, 5)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := endpoint.EnqueueDeviceID(TCPDeviceIDPlan{
		Connection:         connection,
		UnitID:             1,
		AuthorizationScope: "endpoint-device-id-linearize",
		PollGeneration:     1,
		DeadlineIdentity:   1,
		Timeout:            time.Second,
		Request:            request,
		Limits:             DefaultDeviceIDLimits(),
	})
	if err != nil {
		t.Fatal(err)
	}
	dispatch, ok := endpoint.Dispatch()
	if !ok {
		t.Fatal("Device ID dispatch missing")
	}
	wire := endpointWriteDeviceID(t, endpoint, dispatch, peer)
	response := testTCPFrame(
		t,
		uint16(wire[0])<<8|uint16(wire[1]),
		1,
		[]byte{
			0x2b, 0x0e, 0x04, 0x83, 0x00, 0x00, 0x01,
			0x05, 0x01, 'x',
		},
	)
	beforeOutcome := make(chan struct{})
	releaseOutcome := make(chan struct{})
	var once sync.Once
	endpoint.beforeOutcome = func() {
		once.Do(func() {
			close(beforeOutcome)
			<-releaseOutcome
		})
	}
	readDone := make(chan struct {
		batch TCPReadBatch
		err   error
	}, 1)
	sent := endpointSendFrame(peer, response.Bytes())
	go func() {
		batch, readErr := endpoint.Read(
			context.Background(),
			connection,
		)
		readDone <- struct {
			batch TCPReadBatch
			err   error
		}{batch: batch, err: readErr}
	}()
	select {
	case <-beforeOutcome:
	case <-time.After(time.Second):
		t.Fatal("response did not reach the outcome boundary")
	}
	if err := endpoint.Cancel(handle); err != nil {
		t.Fatal(err)
	}
	close(releaseOutcome)
	result := <-readDone
	if err := <-sent; err != nil {
		t.Fatal(err)
	}
	if len(result.batch.DeviceIDs) != 0 {
		t.Fatalf(
			"response published after cancellation won: %#v",
			result.batch.DeviceIDs,
		)
	}
	if !errors.Is(result.err, context.Canceled) {
		t.Fatalf("losing response error=%v", result.err)
	}
}

func TestTCPEndpointDeviceIDProvableZeroRetryRestartsTraversal(
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
	connection, err := endpoint.openTestConnection(
		&endpointFailOnceConn{Conn: client},
	)
	if err != nil {
		t.Fatal(err)
	}
	request, err := NewDeviceIDRequest(DeviceIDIndividual, 5)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := endpoint.EnqueueDeviceID(TCPDeviceIDPlan{
		Connection:         connection,
		UnitID:             1,
		AuthorizationScope: "endpoint-device-id-retry",
		PollGeneration:     1,
		DeadlineIdentity:   1,
		Timeout:            time.Second,
		Request:            request,
		Limits:             DefaultDeviceIDLimits(),
	})
	if err != nil {
		t.Fatal(err)
	}
	dispatch, ok := endpoint.Dispatch()
	if !ok {
		t.Fatal("initial Device ID dispatch missing")
	}
	transition, err := endpoint.Write(context.Background(), dispatch)
	if err == nil || transition.CloseConnection() {
		t.Fatalf("provable-zero transition=%#v err=%v", transition, err)
	}
	if err := endpoint.Retry(handle, connection); err != nil {
		t.Fatal(err)
	}
	dispatch, ok = endpoint.Dispatch()
	if !ok {
		t.Fatal("retried Device ID dispatch missing")
	}
	wire := endpointWriteDeviceID(t, endpoint, dispatch, peer)
	response := testTCPFrame(
		t,
		uint16(wire[0])<<8|uint16(wire[1]),
		1,
		[]byte{
			0x2b, 0x0e, 0x04, 0x83, 0x00, 0x00, 0x01,
			0x05, 0x01, 'x',
		},
	)
	sent := endpointSendFrame(peer, response.Bytes())
	batch, err := endpoint.Read(context.Background(), connection)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-sent; err != nil {
		t.Fatal(err)
	}
	if len(batch.DeviceIDs) != 1 ||
		batch.DeviceIDs[0].RequestID != handle.RequestID() {
		t.Fatalf("retry result=%#v", batch.DeviceIDs)
	}
}

func TestTCPEndpointDeviceIDContinuationFailureRetryRestartsAtInitialCursor(
	t *testing.T,
) {
	clock := &virtualTCPClock{}
	endpoint, err := NewTCPEndpoint(endpointConfigForTest(clock, nil))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = endpoint.Close() }()
	oldClient, oldPeer := net.Pipe()
	defer func() { _ = oldPeer.Close() }()
	oldConnection, err := endpoint.openTestConnection(
		&endpointFullThenPartialConn{Conn: oldClient},
	)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := NewDeviceIDRequest(DeviceIDRegular, 0)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := endpoint.EnqueueDeviceID(TCPDeviceIDPlan{
		Connection:         oldConnection,
		UnitID:             1,
		AuthorizationScope: "endpoint-device-id-restart",
		PollGeneration:     1,
		DeadlineIdentity:   1,
		Timeout:            10 * time.Second,
		Request:            initial,
		Limits:             DefaultDeviceIDLimits(),
	})
	if err != nil {
		t.Fatal(err)
	}
	firstDispatch, ok := endpoint.Dispatch()
	if !ok {
		t.Fatal("initial Device ID dispatch missing")
	}
	firstWire := endpointWriteDeviceID(
		t,
		endpoint,
		firstDispatch,
		oldPeer,
	)
	firstResponse := testTCPFrame(
		t,
		uint16(firstWire[0])<<8|uint16(firstWire[1]),
		1,
		[]byte{
			0x2b, 0x0e, 0x02, 0x82, 0xff, 0x02, 0x02,
			0x00, 0x01, 'A',
			0x01, 0x01, 'B',
		},
	)
	firstSent := endpointSendFrame(oldPeer, firstResponse.Bytes())
	firstBatch, err := endpoint.Read(context.Background(), oldConnection)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-firstSent; err != nil {
		t.Fatal(err)
	}
	if len(firstBatch.DeviceIDs) != 0 {
		t.Fatal("partial traversal was published before retry")
	}
	continuationDispatch, ok := endpoint.Dispatch()
	if !ok {
		t.Fatal("continuation dispatch missing")
	}
	transition, err := endpoint.Write(
		context.Background(),
		continuationDispatch,
	)
	if err == nil || !transition.CloseConnection() {
		t.Fatalf(
			"continuation write transition=%#v err=%v",
			transition,
			err,
		)
	}
	if err := endpoint.WaitReconnect(
		context.Background(),
		handle,
		&endpointDelayWaiter{},
	); err != nil {
		t.Fatal(err)
	}

	newClient, newPeer := net.Pipe()
	defer func() { _ = newPeer.Close() }()
	newConnection, err := endpoint.openTestConnection(newClient)
	if err != nil {
		t.Fatal(err)
	}
	if err := endpoint.Retry(handle, newConnection); err != nil {
		t.Fatal(err)
	}
	retryDispatch, ok := endpoint.Dispatch()
	if !ok {
		t.Fatal("retry dispatch missing")
	}
	retryWire := endpointWriteDeviceID(
		t,
		endpoint,
		retryDispatch,
		newPeer,
	)
	if got := retryWire[7:]; !reflect.DeepEqual(
		got,
		[]byte{0x2b, 0x0e, 0x02, 0x00},
	) {
		t.Fatalf("retry resumed partial cursor: %x", got)
	}
	retryFirst := testTCPFrame(
		t,
		uint16(retryWire[0])<<8|uint16(retryWire[1]),
		1,
		[]byte{
			0x2b, 0x0e, 0x02, 0x82, 0xff, 0x02, 0x02,
			0x00, 0x01, 'A',
			0x01, 0x01, 'B',
		},
	)
	retryFirstSent := endpointSendFrame(newPeer, retryFirst.Bytes())
	retryFirstBatch, err := endpoint.Read(
		context.Background(),
		newConnection,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-retryFirstSent; err != nil {
		t.Fatal(err)
	}
	if len(retryFirstBatch.DeviceIDs) != 0 {
		t.Fatal("retry published a partial aggregate")
	}
	retryContinuation, ok := endpoint.Dispatch()
	if !ok {
		t.Fatal("retry continuation dispatch missing")
	}
	retrySecondWire := endpointWriteDeviceID(
		t,
		endpoint,
		retryContinuation,
		newPeer,
	)
	if got := retrySecondWire[7:]; !reflect.DeepEqual(
		got,
		[]byte{0x2b, 0x0e, 0x02, 0x02},
	) {
		t.Fatalf("retry continuation cursor=%x", got)
	}
	retrySecond := testTCPFrame(
		t,
		uint16(retrySecondWire[0])<<8|uint16(retrySecondWire[1]),
		1,
		[]byte{
			0x2b, 0x0e, 0x02, 0x82, 0x00, 0x00, 0x01,
			0x02, 0x01, 'C',
		},
	)
	retrySecondSent := endpointSendFrame(newPeer, retrySecond.Bytes())
	finalBatch, err := endpoint.Read(context.Background(), newConnection)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-retrySecondSent; err != nil {
		t.Fatal(err)
	}
	if len(finalBatch.DeviceIDs) != 1 ||
		len(finalBatch.DeviceIDs[0].Result.Segments) != 2 ||
		len(finalBatch.DeviceIDs[0].Result.Objects) != 3 {
		t.Fatalf("retry aggregate=%#v", finalBatch.DeviceIDs)
	}
}

func TestTCPEndpointDeviceIDMalformedContinuationReleasesCapacity(
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
	_, err = endpoint.EnqueueDeviceID(TCPDeviceIDPlan{
		Connection:         connection,
		UnitID:             1,
		AuthorizationScope: "endpoint-device-id-malformed-continuation",
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
		t.Fatal("initial dispatch missing")
	}
	firstWire := endpointWriteDeviceID(t, endpoint, firstDispatch, peer)
	first := testTCPFrame(
		t,
		uint16(firstWire[0])<<8|uint16(firstWire[1]),
		1,
		[]byte{
			0x2b, 0x0e, 0x02, 0x82, 0xff, 0x02, 0x02,
			0x00, 0x01, 'A',
			0x01, 0x01, 'B',
		},
	)
	firstSent := endpointSendFrame(peer, first.Bytes())
	if _, err := endpoint.Read(context.Background(), connection); err != nil {
		t.Fatal(err)
	}
	if err := <-firstSent; err != nil {
		t.Fatal(err)
	}
	secondDispatch, ok := endpoint.Dispatch()
	if !ok {
		t.Fatal("continuation dispatch missing")
	}
	secondWire := endpointWriteDeviceID(t, endpoint, secondDispatch, peer)
	malformed := testTCPFrame(
		t,
		uint16(secondWire[0])<<8|uint16(secondWire[1]),
		1,
		[]byte{
			0x2b, 0x0d, 0x02, 0x82, 0x00, 0x00, 0x01,
			0x02, 0x01, 'C',
		},
	)
	malformedSent := endpointSendFrame(peer, malformed.Bytes())
	batch, readErr := endpoint.Read(context.Background(), connection)
	_ = requireProtocolError(t, readErr, ErrorMalformedResponse)
	if err := <-malformedSent; err != nil {
		t.Fatal(err)
	}
	if len(batch.DeviceIDs) != 0 {
		t.Fatalf("malformed continuation published=%#v", batch.DeviceIDs)
	}
	snapshot := endpoint.Snapshot()
	if snapshot.Resources.LiveRequests != 0 ||
		snapshot.Resources.InFlightRequests != 0 {
		t.Fatalf("malformed continuation retained state: %#v", snapshot)
	}

	sibling, err := NewDeviceIDRequest(DeviceIDIndividual, 5)
	if err != nil {
		t.Fatal(err)
	}
	_, err = endpoint.EnqueueDeviceID(TCPDeviceIDPlan{
		Connection:         connection,
		UnitID:             1,
		AuthorizationScope: "endpoint-device-id-malformed-continuation",
		PollGeneration:     1,
		DeadlineIdentity:   2,
		Timeout:            time.Second,
		Request:            sibling,
		Limits:             DefaultDeviceIDLimits(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := endpoint.Dispatch(); !ok {
		t.Fatal("malformed continuation leaked scheduler capacity")
	}
}
