package modbus

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"reflect"
	"testing"
	"time"
)

// tolerantEndpointHarness drives one TCPEndpoint against an in-process fake
// logger-class peer. Every request the peer reads is recorded so the tests
// can prove that only FC2B/MEI0E requests reach the wire.
type tolerantEndpointHarness struct {
	t          *testing.T
	endpoint   *TCPEndpoint
	sink       *recordingTCPEventSink
	peer       net.Conn
	connection TCPConnectionHandle
	requests   [][]byte
}

func newTolerantEndpointHarness(t *testing.T, framing TCPFraming) *tolerantEndpointHarness {
	t.Helper()
	sink := &recordingTCPEventSink{}
	config := endpointConfigForTest(&virtualTCPClock{}, sink)
	config.Framing = framing
	if framing == TCPFramingTolerant {
		config.MaxBufferedBytes = 2 * maxTolerantTCPADUSize
	}
	endpoint, err := NewTCPEndpoint(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = endpoint.Close() })
	harness := &tolerantEndpointHarness{t: t, endpoint: endpoint, sink: sink}
	harness.connect()
	return harness
}

func (harness *tolerantEndpointHarness) connect() {
	harness.t.Helper()
	client, peer := net.Pipe()
	harness.t.Cleanup(func() { _ = peer.Close() })
	connection, err := harness.endpoint.openTestConnection(client)
	if err != nil {
		harness.t.Fatal(err)
	}
	harness.peer = peer
	harness.connection = connection
}

func (harness *tolerantEndpointHarness) plan(
	unitID byte,
	request DeviceIDRequest,
	decoding DeviceIDDecoding,
) TCPDeviceIDPlan {
	return TCPDeviceIDPlan{
		Connection:         harness.connection,
		UnitID:             unitID,
		AuthorizationScope: "logger-class-device-id",
		PollGeneration:     1,
		DeadlineIdentity:   uint64(unitID) + 1,
		Timeout:            10 * time.Second,
		Request:            request,
		Limits:             DefaultDeviceIDLimits(),
		Decoding:           decoding,
	}
}

func (harness *tolerantEndpointHarness) enqueue(plan TCPDeviceIDPlan) TCPRequestHandle {
	harness.t.Helper()
	handle, err := harness.endpoint.EnqueueDeviceID(plan)
	if err != nil {
		harness.t.Fatal(err)
	}
	return handle
}

// step serves the next dispatched page with reply and reads the endpoint
// batch. It reports false when nothing is queued.
func (harness *tolerantEndpointHarness) step(
	reply func(request []byte) []byte,
) (TCPReadBatch, error, bool) {
	harness.t.Helper()
	dispatch, ok := harness.endpoint.Dispatch()
	if !ok {
		return TCPReadBatch{}, nil, false
	}
	request := endpointWriteDeviceID(harness.t, harness.endpoint, dispatch, harness.peer)
	harness.requests = append(harness.requests, request)
	sent := endpointSendFrame(harness.peer, reply(request))
	batch, err := harness.endpoint.Read(context.Background(), harness.connection)
	<-sent
	return batch, err, true
}

func (harness *tolerantEndpointHarness) traverse(
	reply func(request []byte) []byte,
) ([]TCPReadBatch, []TCPDeviceIDCompletion) {
	harness.t.Helper()
	var batches []TCPReadBatch
	var completions []TCPDeviceIDCompletion
	for {
		batch, err, ok := harness.step(reply)
		if !ok {
			return batches, completions
		}
		if err != nil {
			harness.t.Fatalf("page %d: %v", len(batches)+1, err)
		}
		batches = append(batches, batch)
		completions = append(completions, batch.DeviceIDs...)
	}
}

// requireReadOnlyWire proves that every request was an FC2B/MEI0E read.
func (harness *tolerantEndpointHarness) requireReadOnlyWire() {
	harness.t.Helper()
	for index, request := range harness.requests {
		if len(request) != 11 || request[2] != 0 || request[3] != 0 || request[4] != 0 || request[5] != 5 ||
			request[7] != byte(FunctionEncapsulatedInterface) || request[8] != deviceIDMEIType ||
			request[9] < byte(DeviceIDBasic) || request[9] > byte(DeviceIDIndividual) {
			harness.t.Fatalf("request %d is not a read device identification: %x", index, request)
		}
	}
}

func (harness *tolerantEndpointHarness) cursors() []byte {
	cursors := make([]byte, 0, len(harness.requests))
	for _, request := range harness.requests {
		cursors = append(cursors, request[10])
	}
	return cursors
}

func reframeForRequest(adu []byte, request []byte) []byte {
	reply := append([]byte(nil), adu...)
	reply[0], reply[1] = request[0], request[1]
	return reply
}

// loggerFixtureReply answers like the recorded logger-class device: the
// over-full basic reply for any unit, and the paged extended inventory.
func loggerFixtureReply(t *testing.T, fixture loggerFixture) func([]byte) []byte {
	return func(request []byte) []byte {
		t.Helper()
		var exchange loggerFixtureExchange
		switch DeviceIDAccess(request[9]) {
		case DeviceIDBasic:
			exchange = fixture.exchange(t, fmt.Sprintf("basic_unit_%d", request[6]))
		case DeviceIDExtended:
			exchange = fixture.inventoryPage(t, request[10])
		default:
			t.Fatalf("unexpected request %x", request)
		}
		return reframeForRequest(exchange.adu(t), request)
	}
}

func TestTCPEndpointTolerantLoggerInventoryTraversal(t *testing.T) {
	fixture := loadLoggerFixture(t)
	harness := newTolerantEndpointHarness(t, TCPFramingTolerant)
	initial, err := NewExtendedDeviceIDStreamRequest(0x87)
	if err != nil {
		t.Fatal(err)
	}
	handle := harness.enqueue(harness.plan(0, initial, DeviceIDDecodingTolerant))
	batches, completions := harness.traverse(loggerFixtureReply(t, fixture))
	harness.requireReadOnlyWire()
	wantCursors := []byte{0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93}
	if !bytes.Equal(harness.cursors(), wantCursors) || len(batches) != 13 {
		t.Fatalf("cursors=%x batches=%d", harness.cursors(), len(batches))
	}
	if len(completions) != 1 || len(batches[12].DeviceIDs) != 1 {
		t.Fatalf("completions=%d", len(completions))
	}
	completion := completions[0]
	result := completion.Tolerant
	if completion.RequestID != handle.RequestID() ||
		completion.Decoding != DeviceIDDecodingTolerant ||
		!reflect.DeepEqual(completion.Result, DeviceIDResult{}) ||
		!result.Complete || len(result.Pages) != 13 || len(result.Objects) != 13 {
		t.Fatalf("completion=%+v", completion)
	}
	requireAnomalies(t, result.Anomalies,
		DeviceIDAnomalyObjectCountMismatch,
		DeviceIDAnomalyCountOnlyPage,
		DeviceIDAnomalyOversizePage,
		DeviceIDAnomalyOversizeObjectValue,
	)
	var units []int
	for _, object := range result.Objects[1:] {
		units = append(units, childUnitID(t, object.Value))
	}
	if want := []int{0, 2, 3, 4, 5, 6, 7, 8, 9, 1, 11, 19}; !reflect.DeepEqual(units, want) {
		t.Fatalf("child unit ids=%v", units)
	}
	oversize := 0
	for index, batch := range batches {
		if len(batch.Responses) != 1 {
			t.Fatalf("batch %d responses=%d", index, len(batch.Responses))
		}
		response := batch.Responses[0]
		fixturePage := fixture.inventoryPage(t, wantCursors[index])
		page, ok := response.DeviceIDPage()
		if _, strict := response.DeviceIDSegment(); strict || !ok ||
			response.Outcome() != WireSuccessfulData ||
			!bytes.Equal(response.Bytes()[2:], fixturePage.adu(t)[2:]) ||
			!bytes.Equal(page.PDU, fixturePage.pdu(t)) ||
			!bytes.Equal(result.Pages[index].PDU, fixturePage.pdu(t)) {
			t.Fatalf("batch %d lost the received page", index)
		}
		if response.OversizePDU() {
			oversize++
		}
		page.PDU[0] = 0
		page.Objects[0].Value[0] = 0
		again, _ := response.DeviceIDPage()
		if again.PDU[0] != byte(FunctionEncapsulatedInterface) || again.Objects[0].Value[0] == 0 {
			t.Fatal("WireResponse.DeviceIDPage shares memory")
		}
	}
	if oversize != 12 {
		t.Fatalf("oversize responses=%d", oversize)
	}
	observed := 0
	for _, event := range harness.sink.snapshot() {
		if event.Kind == TCPEventResponseReceive && event.Detail == tcpOversizePDUDetail {
			observed++
			if len(event.RawADUHex) != 2*270 {
				t.Fatalf("oversize event raw hex length %d", len(event.RawADUHex))
			}
		}
	}
	snapshot := harness.endpoint.Snapshot()
	if observed != 12 || snapshot.Metrics.OversizePDUResponses != 12 ||
		snapshot.Metrics.Responses.SuccessfulData != 13 || snapshot.ReconnectRequired {
		t.Fatalf("observed=%d metrics=%+v reconnect=%t", observed, snapshot.Metrics, snapshot.ReconnectRequired)
	}
}

func TestTCPEndpointTolerantBasicReplyForAnyUnit(t *testing.T) {
	fixture := loadLoggerFixture(t)
	harness := newTolerantEndpointHarness(t, TCPFramingStrict)
	request, err := NewDeviceIDRequest(DeviceIDBasic, 0)
	if err != nil {
		t.Fatal(err)
	}
	var reference []DeviceIDObject
	for _, unitID := range []byte{0, 1, 100} {
		harness.enqueue(harness.plan(unitID, request, DeviceIDDecodingTolerant))
		_, completions := harness.traverse(loggerFixtureReply(t, fixture))
		if len(completions) != 1 {
			t.Fatalf("unit %d completions=%d", unitID, len(completions))
		}
		result := completions[0].Tolerant
		requireAnomalies(t, result.Anomalies,
			DeviceIDAnomalyObjectOutsideCategory,
			DeviceIDAnomalyObjectOutsideConformity,
			DeviceIDAnomalyReservedObjectID,
		)
		if !result.Complete || len(result.Objects) != 12 || result.Conformity != 0x01 {
			t.Fatalf("unit %d result=%+v", unitID, result)
		}
		if reference == nil {
			reference = result.Objects
		} else if !reflect.DeepEqual(result.Objects, reference) {
			t.Fatalf("unit %d objects differ from unit 0", unitID)
		}
	}
	harness.requireReadOnlyWire()
	units := []byte{harness.requests[0][6], harness.requests[1][6], harness.requests[2][6]}
	if len(harness.requests) != 3 || !bytes.Equal(units, []byte{0, 1, 100}) {
		t.Fatalf("requests=%x", harness.requests)
	}
}

func TestTCPEndpointStrictDefaultsStillRejectLoggerClassPages(t *testing.T) {
	fixture := loadLoggerFixture(t)
	initial, err := NewExtendedDeviceIDStreamRequest(0x87)
	if err != nil {
		t.Fatal(err)
	}

	strict := newTolerantEndpointHarness(t, TCPFramingStrict)
	plan := strict.plan(0, initial, DeviceIDDecodingTolerant)
	plan.Decoding = DeviceIDDecoding(0)
	strict.enqueue(plan)
	batch, err, ok := strict.step(loggerFixtureReply(t, fixture))
	requireMalformedDeviceID(t, err, "object_header")
	if !ok || len(batch.Responses) != 1 || len(batch.DeviceIDs) != 0 ||
		batch.Responses[0].Outcome() != WireMalformedResponse ||
		!bytes.Equal(batch.Responses[0].Bytes()[7:], fixture.inventoryPage(t, 0x87).pdu(t)) {
		t.Fatalf("strict count-only page batch=%+v", batch)
	}
	if _, more := strict.endpoint.Dispatch(); more || strict.endpoint.Snapshot().ReconnectRequired {
		t.Fatal("strict malformed page did not terminate the traversal on a live socket")
	}

	mixed := newTolerantEndpointHarness(t, TCPFramingStrict)
	mixed.enqueue(mixed.plan(0, initial, DeviceIDDecodingTolerant))
	if _, err, _ := mixed.step(loggerFixtureReply(t, fixture)); err != nil {
		t.Fatalf("tolerant decoding of the count-only page: %v", err)
	}
	_, err, _ = mixed.step(loggerFixtureReply(t, fixture))
	var frameErr *TCPFrameError
	if errors.As(err, &frameErr) {
		t.Fatalf("strict framing returned a tolerant error: %v", err)
	}
	requireMalformedDeviceID(t, err, "length")
	if !mixed.endpoint.Snapshot().ReconnectRequired {
		t.Fatal("strict framing failure did not require a reconnect")
	}
	mixed.requireReadOnlyWire()
}

func TestTCPEndpointTolerantFramingRenewsConnectionAboveBound(t *testing.T) {
	fixture := loadLoggerFixture(t)
	harness := newTolerantEndpointHarness(t, TCPFramingTolerant)
	initial, err := NewExtendedDeviceIDStreamRequest(0x87)
	if err != nil {
		t.Fatal(err)
	}
	handle := harness.enqueue(harness.plan(0, initial, DeviceIDDecodingTolerant))
	reply := loggerFixtureReply(t, fixture)
	if _, err, _ := harness.step(reply); err != nil {
		t.Fatal(err)
	}
	var oversized []byte
	_, err, _ = harness.step(func(request []byte) []byte {
		oversized = mbapTestFrame(0, 0, 0, oversizeDeviceIDTestPDU(MaxTolerantPDUSize+1))
		return reframeForRequest(oversized, request)
	})
	frameErr := requireTCPFrameError(t, err, "length", 4)
	if len(frameErr.Raw) != maxTolerantTCPADUSize ||
		!bytes.Equal(frameErr.Raw[2:], oversized[2:maxTolerantTCPADUSize]) {
		t.Fatalf("raw evidence %d bytes", len(frameErr.Raw))
	}
	if !harness.endpoint.Snapshot().ReconnectRequired {
		t.Fatal("frame error did not require a reconnect")
	}
	if _, more := harness.endpoint.Dispatch(); more {
		t.Fatal("traversal continued on the failed socket")
	}
	if err := harness.endpoint.WaitReconnect(context.Background(), handle, &endpointDelayWaiter{}); err != nil {
		t.Fatal(err)
	}
	harness.connect()
	if err := harness.endpoint.Retry(handle, harness.connection); err != nil {
		t.Fatal(err)
	}
	harness.requests = nil
	_, completions := harness.traverse(reply)
	if harness.cursors()[0] != 0x87 || len(harness.requests) != 13 {
		t.Fatalf("retry cursors=%x", harness.cursors())
	}
	if len(completions) != 1 || completions[0].Decoding != DeviceIDDecodingTolerant ||
		!completions[0].Tolerant.Complete || len(completions[0].Tolerant.Pages) != 13 {
		t.Fatalf("retry completions=%+v", completions)
	}
	harness.requireReadOnlyWire()
}

func TestTCPEndpointTolerantFramingRenewsConnectionOnProtocolID(t *testing.T) {
	fixture := loadLoggerFixture(t)
	harness := newTolerantEndpointHarness(t, TCPFramingTolerant)
	initial, err := NewExtendedDeviceIDStreamRequest(0x87)
	if err != nil {
		t.Fatal(err)
	}
	harness.enqueue(harness.plan(0, initial, DeviceIDDecodingTolerant))
	var sent []byte
	_, err, _ = harness.step(func(request []byte) []byte {
		sent = reframeForRequest(fixture.inventoryPage(t, 0x87).adu(t), request)
		sent[3] = 0x01
		return sent
	})
	frameErr := requireTCPFrameError(t, err, "protocol_id", 2)
	if !bytes.Equal(frameErr.Raw, sent) {
		t.Fatalf("raw evidence=%x want %x", frameErr.Raw, sent)
	}
	if !harness.endpoint.Snapshot().ReconnectRequired {
		t.Fatal("protocol id failure did not require a reconnect")
	}
}

// loggerOversizeWorldReply mirrors the capture tool's oversize fake: the page
// at 0x89 packs three child objects into one 263-byte PDU and continues at
// 0x8c; every other page comes from the fixture.
func loggerOversizeWorldReply(t *testing.T, fixture loggerFixture) func([]byte) []byte {
	base := loggerFixtureReply(t, fixture)
	return func(request []byte) []byte {
		if DeviceIDAccess(request[9]) != DeviceIDExtended || request[10] != 0x89 {
			return base(request)
		}
		pdu := []byte{0x2b, 0x0e, 0x03, 0x03, 0xff, 0x8c, 12}
		for index, length := range []int{84, 84, 82} {
			text := fmt.Sprintf("1=INVERTER-MODEL-A;5=%d;9=0", 2+index)
			value := append([]byte(text), make([]byte, length-len(text))...)
			pdu = append(pdu, byte(0x89+index), byte(length))
			pdu = append(pdu, value...)
		}
		return mbapTestFrame(uint16(request[0])<<8|uint16(request[1]), 0, request[6], pdu)
	}
}

func TestTCPEndpointTolerantMultiObjectOversizePage(t *testing.T) {
	fixture := loadLoggerFixture(t)
	harness := newTolerantEndpointHarness(t, TCPFramingTolerant)
	initial, err := NewExtendedDeviceIDStreamRequest(0x87)
	if err != nil {
		t.Fatal(err)
	}
	harness.enqueue(harness.plan(0, initial, DeviceIDDecodingTolerant))
	_, completions := harness.traverse(loggerOversizeWorldReply(t, fixture))
	harness.requireReadOnlyWire()
	want := []byte{0x87, 0x88, 0x89, 0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93}
	if !bytes.Equal(harness.cursors(), want) || len(completions) != 1 {
		t.Fatalf("cursors=%x completions=%d", harness.cursors(), len(completions))
	}
	result := completions[0].Tolerant
	if !result.Complete || len(result.Pages) != 11 || len(result.Objects) != 13 ||
		len(result.Pages[2].PDU) != 263 || len(result.Pages[2].Objects) != 3 ||
		!result.Pages[2].HasAnomaly(DeviceIDAnomalyOversizePage) ||
		result.Pages[2].HasAnomaly(DeviceIDAnomalyOversizeObjectValue) {
		t.Fatalf("oversize world result=%+v", result)
	}
	var units []int
	for _, object := range result.Objects[1:] {
		units = append(units, childUnitID(t, object.Value))
	}
	if want := []int{0, 2, 3, 4, 5, 6, 7, 8, 9, 1, 11, 19}; !reflect.DeepEqual(units, want) {
		t.Fatalf("child unit ids=%v", units)
	}
}

func TestTCPEndpointTolerantFramingKeepsStrictRegisterDecoding(t *testing.T) {
	harness := newTolerantEndpointHarness(t, TCPFramingTolerant)
	plan := endpointPlan(t, harness.connection, time.Second, 7, 30000)
	if _, err := harness.endpoint.EnqueueRead(plan); err != nil {
		t.Fatal(err)
	}
	dispatch, ok := harness.endpoint.Dispatch()
	if !ok {
		t.Fatal("read not dispatched")
	}
	request := endpointWriteOne(t, harness.endpoint, dispatch, harness.peer)
	if request[7] != byte(FunctionReadHoldingRegisters) {
		t.Fatalf("request=%x", request)
	}
	pdu := append([]byte{byte(FunctionReadHoldingRegisters), 0xfe}, make([]byte, 254)...)
	sent := endpointSendFrame(harness.peer, mbapTestFrame(uint16(request[0])<<8|uint16(request[1]), 0, 1, pdu))
	batch, err := harness.endpoint.Read(context.Background(), harness.connection)
	if sendErr := <-sent; sendErr != nil {
		t.Fatal(sendErr)
	}
	requireMalformedDeviceID(t, err, "byte_count")
	if len(batch.Responses) != 1 || !batch.Responses[0].OversizePDU() ||
		batch.Responses[0].Outcome() != WireMalformedResponse || len(batch.Views) != 0 {
		t.Fatalf("oversize register batch=%+v", batch)
	}
	snapshot := harness.endpoint.Snapshot()
	if snapshot.ReconnectRequired || snapshot.Metrics.OversizePDUResponses != 1 {
		t.Fatalf("snapshot=%+v", snapshot)
	}
}

func TestTCPEndpointRejectsUnknownFramingAndDecoding(t *testing.T) {
	clock := &virtualTCPClock{}
	for _, test := range []struct {
		name        string
		framing     TCPFraming
		maxBuffered int
		valid       bool
	}{
		{"unknown framing", TCPFraming(5), 2 * maxTolerantTCPADUSize, false},
		{"tolerant buffer below largest frame", TCPFramingTolerant, maxTolerantTCPADUSize - 1, false},
		{"tolerant buffer holds largest frame", TCPFramingTolerant, maxTolerantTCPADUSize, true},
		{"strict default buffer", TCPFramingStrict, 260, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := endpointConfigForTest(clock, nil)
			config.Framing = test.framing
			config.MaxBufferedBytes = test.maxBuffered
			endpoint, err := NewTCPEndpoint(config)
			if test.valid != (err == nil) {
				t.Fatalf("endpoint=%v err=%v", endpoint, err)
			}
			if endpoint != nil {
				_ = endpoint.Close()
			}
		})
	}
	harness := newTolerantEndpointHarness(t, TCPFramingStrict)
	request, err := NewDeviceIDRequest(DeviceIDBasic, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = harness.endpoint.EnqueueDeviceID(harness.plan(1, request, DeviceIDDecoding(3)))
	var protocolErr *ProtocolError
	if !errors.As(err, &protocolErr) || protocolErr.Field != "device_id_decoding" {
		t.Fatalf("unknown decoding err=%#v", err)
	}
	if resources := harness.endpoint.Snapshot().Resources; resources.QueuedRequests != 0 || resources.LiveRequests != 0 {
		t.Fatalf("rejected plan was admitted: %+v", resources)
	}
}

func TestTCPEndpointTolerantStoppedTraversalPublishesIncompleteResult(t *testing.T) {
	harness := newTolerantEndpointHarness(t, TCPFramingStrict)
	request, err := NewDeviceIDRequest(DeviceIDBasic, 0)
	if err != nil {
		t.Fatal(err)
	}
	handle := harness.enqueue(harness.plan(1, request, DeviceIDDecodingTolerant))
	pdu := []byte{
		0x2b, 0x0e, 0x01, 0x01, 0xff, 0x00, 0x03,
		0x00, 0x01, 'V', 0x01, 0x01, 'P', 0x02, 0x01, 'R',
	}
	_, completions := harness.traverse(func(request []byte) []byte {
		return mbapTestFrame(uint16(request[0])<<8|uint16(request[1]), 0, request[6], pdu)
	})
	harness.requireReadOnlyWire()
	if len(harness.requests) != 1 || len(completions) != 1 || completions[0].RequestID != handle.RequestID() {
		t.Fatalf("requests=%d completions=%d", len(harness.requests), len(completions))
	}
	result := completions[0].Tolerant
	requireAnomalies(t, result.Anomalies,
		DeviceIDAnomalyMoreFollowsWithoutProgress,
		DeviceIDAnomalyContinuationUnavailable,
	)
	if result.Complete || len(result.Objects) != 3 || len(result.Pages) != 1 {
		t.Fatalf("stopped traversal=%+v", result)
	}
}

func TestTCPEndpointTolerantExceptionPageIsTerminal(t *testing.T) {
	fixture := loadLoggerFixture(t)
	harness := newTolerantEndpointHarness(t, TCPFramingTolerant)
	initial, err := NewExtendedDeviceIDStreamRequest(0x87)
	if err != nil {
		t.Fatal(err)
	}
	harness.enqueue(harness.plan(0, initial, DeviceIDDecodingTolerant))
	if _, err, _ := harness.step(loggerFixtureReply(t, fixture)); err != nil {
		t.Fatal(err)
	}
	batch, err, _ := harness.step(func(request []byte) []byte {
		return mbapTestFrame(uint16(request[0])<<8|uint16(request[1]), 0, request[6], []byte{0xab, 0x02})
	})
	var protocolErr *ProtocolError
	if !errors.As(err, &protocolErr) || protocolErr.Kind != ErrorExceptionResponse || protocolErr.ExceptionCode != 2 {
		t.Fatalf("exception err=%#v", err)
	}
	if len(batch.DeviceIDs) != 0 || len(batch.Responses) != 1 ||
		batch.Responses[0].Outcome() != WireProtocolException {
		t.Fatalf("exception batch=%+v", batch)
	}
	if _, page := batch.Responses[0].DeviceIDPage(); page {
		t.Fatal("exception response carried a decoded page")
	}
	if _, more := harness.endpoint.Dispatch(); more || harness.endpoint.Snapshot().ReconnectRequired {
		t.Fatal("exception did not terminate the traversal on a live socket")
	}
}
