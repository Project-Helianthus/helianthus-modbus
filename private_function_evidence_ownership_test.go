package modbus

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

func k18Equal(t *testing.T, label string, got, want []byte) {
	t.Helper()
	if !bytes.Equal(got, want) {
		t.Fatalf("%s = %x, want %x", label, got, want)
	}
}

func k18Mutate(b []byte) {
	for i := range b {
		b[i] += 0x55
	}
}

func TestK18BinaryExchangeEvidenceOwnership(t *testing.T) {
	// These bytes have no operation meaning; delimiter-like values remain data.
	nativeRequest := []byte{0, '\r', '\n', ':', ';', '|', 0x7e, 0x80, 0xff, 0}
	nativeReply := []byte{0xff, 0, '|', ':', '\n', '\r', 0x80, 0x7e, 0}
	callerRequest := bytes.Clone(nativeRequest)
	callerReply := bytes.Clone(nativeReply)
	request := privateProductionRequest(t, 0x64, callerRequest)
	reply := privateProductionFrame(t, 1, 0x64, callerReply)
	wantReply := bytes.Clone(reply)
	wantRequest := privateProductionFrame(t, 1, 0x64, nativeRequest)
	stream := &privateProductionStream{}
	stream.queue(reply)
	admission := &privateProductionAdmission{admit: true}
	endpoint := privateProductionEndpoint(t, stream, admission, 1)
	t.Cleanup(func() { _ = endpoint.Close() })
	responses, evidence, err := endpoint.ExchangePrivateFunction(context.Background(), 1, request, DefaultPrivateFunctionResponsePolicy(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(responses) != 1 || len(evidence.ResponseADUs) != 1 || !evidence.Current || !evidence.IntegrityValid || evidence.TerminalOutcome != "success" {
		t.Fatalf("exchange = %#v / %#v", responses, evidence)
	}
	k18Equal(t, "native request", request.Payload(), nativeRequest)
	k18Equal(t, "native reply", responses[0].Payload(), nativeReply)
	k18Equal(t, "framed reply", responses[0].Bytes(), wantReply)
	k18Equal(t, "evidence request", evidence.RequestADU, wantRequest)
	k18Equal(t, "evidence reply", evidence.ResponseADUs[0], wantReply)
	k18Equal(t, "native bytes inside request framing", evidence.RequestADU[2:len(wantRequest)-2], nativeRequest)
	k18Equal(t, "native bytes inside reply framing", evidence.ResponseADUs[0][2:len(wantReply)-2], nativeReply)
	if stream.writeCount() != 1 {
		t.Fatalf("writes = %d", stream.writeCount())
	}
	k18Equal(t, "wire request", stream.writes[0], wantRequest)

	// Mutate every caller-accessible buffer only after completion.
	k18Mutate(callerRequest)
	k18Mutate(callerReply)
	k18Mutate(reply)
	k18Mutate(request.Payload())
	k18Mutate(responses[0].Payload())
	k18Mutate(responses[0].Bytes())
	k18Mutate(admission.requests[0].Payload)
	k18Mutate(stream.writes[0])
	k18Equal(t, "retained request", request.Payload(), nativeRequest)
	k18Equal(t, "retained native reply", responses[0].Payload(), nativeReply)
	k18Equal(t, "retained framed reply", responses[0].Bytes(), wantReply)
	k18Equal(t, "returned evidence request", evidence.RequestADU, wantRequest)
	k18Equal(t, "returned evidence reply", evidence.ResponseADUs[0], wantReply)

	snapshot, ok := endpoint.LastPrivateFunctionEvidence()
	if !ok {
		t.Fatal("missing retained evidence")
	}
	k18Mutate(evidence.RequestADU)
	k18Mutate(evidence.ResponseADUs[0])
	evidence.ResponseADUs[0] = nil
	k18Mutate(snapshot.RequestADU)
	k18Mutate(snapshot.ResponseADUs[0])
	snapshot.ResponseADUs[0] = nil
	retained, ok := endpoint.LastPrivateFunctionEvidence()
	if !ok {
		t.Fatal("lost retained evidence")
	}
	k18Equal(t, "stored request", retained.RequestADU, wantRequest)
	k18Equal(t, "stored reply", retained.ResponseADUs[0], wantReply)

	nextPayload := []byte{0x80, 0, ';', 0xff}
	nextRequest := privateProductionRequest(t, 0x64, nextPayload)
	nextReply := privateProductionFrame(t, 1, 0x64, []byte{0, 0xff, ':'})
	stream.queue(nextReply)
	nextResponses, nextEvidence, err := endpoint.ExchangePrivateFunction(context.Background(), 1, nextRequest, DefaultPrivateFunctionResponsePolicy(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(nextResponses) != 1 || len(nextEvidence.ResponseADUs) != 1 || nextEvidence.RequestID != retained.RequestID+1 || nextEvidence.Generation != retained.Generation {
		t.Fatalf("successor evidence = %#v", nextEvidence)
	}
	k18Equal(t, "old request after successor", retained.RequestADU, wantRequest)
	k18Equal(t, "old reply after successor", retained.ResponseADUs[0], wantReply)
	k18Equal(t, "old response after successor", responses[0].Payload(), nativeReply)
	k18Mutate(retained.RequestADU)
	k18Mutate(retained.ResponseADUs[0])
	latest, ok := endpoint.LastPrivateFunctionEvidence()
	if !ok || latest.RequestID != nextEvidence.RequestID {
		t.Fatal("wrong successor receipt")
	}
	k18Equal(t, "successor request", latest.RequestADU, privateProductionFrame(t, 1, 0x64, nextPayload))
	k18Equal(t, "successor reply", latest.ResponseADUs[0], nextReply)
	k18Equal(t, "returned successor reply", nextResponses[0].Bytes(), nextReply)
	if _, ok := endpoint.LastEvidence(); ok {
		t.Fatal("private exchange fabricated typed read evidence")
	}
}

func TestK18MalformedBinaryExchangeRetainsDetachedPartialEvidence(t *testing.T) {
	request := privateProductionRequest(t, 0x64, []byte{0, 0xff, ':'})
	valid := privateProductionFrame(t, 1, 0x64, []byte{0, '|', 0x80})
	crc := privateProductionFrame(t, 1, 0x64, []byte{0, 0xff})
	crc[len(crc)-1] ^= 1
	cases := []struct {
		name  string
		frame []byte
	}{
		{"wrong_function", privateProductionFrame(t, 1, 0x65, []byte{0, 0xff})},
		{"wrong_unit", privateProductionFrame(t, 2, 0x64, []byte{0, 0xff})},
		{"foreign_exception", privateProductionFrame(t, 1, 0xe5, []byte{4})},
		{"exception_length", privateProductionFrame(t, 1, 0xe4, []byte{4, 0})},
		{"crc", crc},
		{"truncated", []byte{1, 0x64, 0}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stream := &privateProductionStream{}
			stream.queue(valid, tc.frame)
			endpoint := privateProductionEndpoint(t, stream, &privateProductionAdmission{admit: true}, 2)
			t.Cleanup(func() { _ = endpoint.Close() })
			classified := 0
			classifier := privateClassifierFunc(func(response RTUPrivateFunctionResponseADU) (RTUPrivateFunctionDisposition, error) {
				classified++
				k18Equal(t, "only correlated native bytes reach classifier", response.Payload(), []byte{0, '|', 0x80})
				return RTUPrivateFunctionContinue, nil
			})
			responses, evidence, err := endpoint.ExchangePrivateFunction(context.Background(), 1, request, DefaultPrivateFunctionResponsePolicy(), classifier)
			var pe *ProtocolError
			if !errors.As(err, &pe) || responses != nil || evidence.Current || evidence.IntegrityValid || evidence.TerminalOutcome != "transport_fault" || classified != 1 {
				t.Fatalf("malformed exchange = %v / %#v / classified %d", err, evidence, classified)
			}
			if len(evidence.ResponseADUs) != 2 {
				t.Fatalf("lost partial evidence: %x", evidence.ResponseADUs)
			}
			k18Equal(t, "earlier valid frame", evidence.ResponseADUs[0], valid)
			k18Equal(t, "exact malformed bytes", evidence.ResponseADUs[1], tc.frame)
			k18Mutate(evidence.ResponseADUs[0])
			k18Mutate(evidence.ResponseADUs[1])
			retained, ok := endpoint.LastPrivateFunctionEvidence()
			if !ok {
				t.Fatal("lost failure evidence")
			}
			k18Equal(t, "stored earlier valid frame", retained.ResponseADUs[0], valid)
			k18Equal(t, "stored malformed frame", retained.ResponseADUs[1], tc.frame)
			before := stream.writeCount()
			if _, _, err := endpoint.ExchangePrivateFunction(context.Background(), 1, request, DefaultPrivateFunctionResponsePolicy(), nil); !errors.Is(err, errRTUSessionState) {
				t.Fatalf("successor not fenced: %v", err)
			}
			if stream.writeCount() != before || before != 1 {
				t.Fatal("fault caused retry or successor write")
			}
		})
	}
}

func TestK18BinaryPayloadBoundsAndAdmission(t *testing.T) {
	payload := bytes.Repeat([]byte{0, ':', 0x80, 0xff}, (MaxPDUSize-1)/4)
	payload = append(payload, make([]byte, MaxPDUSize-1-len(payload))...)
	request := privateProductionRequest(t, 0x64, payload)
	if _, err := NewPrivateFunctionRequest(request.FunctionCode(), append(bytes.Clone(payload), 0)); err == nil {
		t.Fatal("over-bound request accepted")
	}
	frame := privateProductionFrame(t, 1, 0x64, payload)
	if len(frame) != MaxRTUADUSize {
		t.Fatalf("boundary frame length = %d", len(frame))
	}
	stream := &privateProductionStream{}
	stream.queue(frame)
	endpoint := privateProductionEndpoint(t, stream, &privateProductionAdmission{admit: true}, 1)
	t.Cleanup(func() { _ = endpoint.Close() })
	responses, _, err := endpoint.ExchangePrivateFunction(context.Background(), 1, request, DefaultPrivateFunctionResponsePolicy(), nil)
	if err != nil || len(responses) != 1 {
		t.Fatalf("boundary exchange: %v", err)
	}
	k18Equal(t, "maximum native payload", responses[0].Payload(), payload)
	stream.queue(append(bytes.Clone(frame), 0xff))
	responses, evidence, err := endpoint.ExchangePrivateFunction(context.Background(), 1, request, DefaultPrivateFunctionResponsePolicy(), nil)
	if err == nil || responses != nil || evidence.Current || evidence.IntegrityValid || evidence.TerminalOutcome != "transport_fault" || len(evidence.ResponseADUs) != 1 {
		t.Fatalf("over-bound response = %v / %#v", err, evidence)
	}
	k18Equal(t, "bounded overrun evidence", evidence.ResponseADUs[0], append(bytes.Clone(frame), 0xff))

	for _, admission := range []RTUPrivateFunctionAdmission{nil, &privateProductionAdmission{}} {
		deniedStream := &privateProductionStream{}
		maxResponses := 0
		if admission != nil {
			maxResponses = 1
		}
		denied := privateProductionEndpoint(t, deniedStream, admission, maxResponses)
		t.Cleanup(func() { _ = denied.Close() })
		if _, _, err := denied.ExchangePrivateFunction(context.Background(), 1, request, DefaultPrivateFunctionResponsePolicy(), nil); err == nil {
			t.Fatal("binary payload bypassed FC100 admission")
		}
		if deniedStream.writeCount() != 0 {
			t.Fatal("unadmitted binary request sent")
		}
		if _, ok := denied.LastPrivateFunctionEvidence(); ok {
			t.Fatal("unadmitted request fabricated evidence")
		}
	}
}
