package modbus

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"
)

func TestRTUProductionReadEvidenceRetiresWithLifecycle(t *testing.T) {
	for _, function := range []FunctionCode{FunctionReadHoldingRegisters, FunctionReadInputRegisters} {
		for _, transition := range []string{"close", "private fault and recover", "read timeout and recover"} {
			t.Run(fmt.Sprintf("FC%02d/%s", function, transition), func(t *testing.T) {
				request := rtuReadRequest(t, function)
				stream := &privateProductionStream{}
				stream.queue(productionReadResponse(t, 1, request, []uint16{7, 8, 9}))
				e := privateProductionEndpoint(t, stream, &privateProductionAdmission{admit: true}, 1)
				_, success, err := e.Read(context.Background(), 1, request)
				if err != nil || !success.Current {
					t.Fatalf("initial read = %v %#v", err, success)
				}
				assertEvidence := func(want RTUReadEvidence) {
					t.Helper()
					last, ok := e.LastEvidence()
					if !ok || !reflect.DeepEqual(last, want) {
						t.Errorf("last evidence = %#v, want %#v (present=%v)", last, want, ok)
					}
				}
				assertEvidence(success)
				retired := success.copy()
				retired.Current = false
				switch transition {
				case "close":
					if err := e.Close(); err != nil {
						t.Fatal(err)
					}
				case "private fault and recover":
					private := privateProductionRequest(t, privateProductionCode, privateProductionPayload)
					if _, _, err := e.ExchangePrivateFunction(context.Background(), 1, private, DefaultPrivateFunctionResponsePolicy(), nil); !errors.Is(err, context.DeadlineExceeded) {
						t.Fatalf("private timeout = %v", err)
					}
				case "read timeout and recover":
					_, retired, err = e.Read(context.Background(), 1, request)
					if !errors.Is(err, context.DeadlineExceeded) || retired.Current || retired.TerminalOutcome != "transport_fault" {
						t.Fatalf("read timeout = %v %#v", err, retired)
					}
				}
				assertEvidence(retired)
				if transition != "close" {
					if err := e.Recover(context.Background()); err != nil {
						t.Fatal(err)
					}
					assertEvidence(retired)
					// The successor lifecycle must not revive a historical receipt.
					e.mu.Lock()
					generation := e.generation
					e.mu.Unlock()
					if generation != success.Generation+1 {
						t.Fatalf("successor generation = %d", generation)
					}
				}
				// Historical ADUs and words remain independent copies.
				last, _ := e.LastEvidence()
				last.RequestADU[0] ^= 0xff
				if len(last.ResponseADU) > 0 {
					last.ResponseADU[0] ^= 0xff
				}
				if len(last.Words) > 0 {
					last.Words[0] ^= 0xffff
				}
				assertEvidence(retired)
			})
		}
	}
}

type productionAdmissionCallback func(uint64) bool

func (f productionAdmissionCallback) AdmitRTURead(request RTUReadAdmissionRequest) bool {
	return f(request.Generation)
}

func (f productionAdmissionCallback) AdmitRTUPrivateFunction(request RTUPrivateFunctionAdmissionRequest) bool {
	return f(request.Generation)
}

// Bound a broken callback/endpoint interaction so a regression reports a test
// failure instead of hanging the entire suite on a recursive mutex lock.
func productionAdmissionCall(t *testing.T, call func() error) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- call() }()
	select {
	case err := <-done:
		return err
	case <-time.After(time.Second):
		t.Fatal("admission callback blocked on endpoint lifecycle/evidence")
		return nil
	}
}

func TestRTUProductionAdmissionCanInspectEvidenceAndRechecksClose(t *testing.T) {
	for _, path := range []string{"read", "private"} {
		for _, action := range []string{"allow", "deny", "close"} {
			t.Run(path+"/"+action, func(t *testing.T) {
				stream := &privateProductionStream{}
				e := privateProductionEndpoint(t, stream, &privateProductionAdmission{admit: true}, 1)
				callback := productionAdmissionCallback(func(generation uint64) bool {
					if generation != 1 {
						return false
					}
					e.LastEvidence()
					e.LastPrivateFunctionEvidence()
					// The pending admission still owns single-flight across paths.
					if _, _, err := e.Read(context.Background(), 1, rtuReadRequest(t, FunctionReadHoldingRegisters)); !errors.Is(err, errRTUSessionState) {
						return false
					}
					private := privateProductionRequest(t, privateProductionCode, nil)
					if _, _, err := e.ExchangePrivateFunction(context.Background(), 1, private, DefaultPrivateFunctionResponsePolicy(), nil); !errors.Is(err, errRTUSessionState) {
						return false
					}
					if action == "close" {
						if err := e.Close(); err != nil {
							return false
						}
					}
					return action != "deny"
				})
				e.admission = callback
				e.private.Admission = callback
				request := rtuReadRequest(t, FunctionReadHoldingRegisters)
				var call func() error
				if path == "read" {
					stream.queue(productionReadResponse(t, 1, request, []uint16{1, 2, 3}))
					call = func() error { _, _, err := e.Read(context.Background(), 1, request); return err }
				} else {
					stream.queue(privateProductionFrame(t, 1, privateProductionCode, []byte{1}))
					private := privateProductionRequest(t, privateProductionCode, nil)
					call = func() error {
						_, _, err := e.ExchangePrivateFunction(context.Background(), 1, private, DefaultPrivateFunctionResponsePolicy(), nil)
						return err
					}
				}
				err := productionAdmissionCall(t, call)
				if action == "allow" {
					if err != nil || stream.writeCount() != 1 {
						t.Fatalf("admitted exchange = %v, writes=%d", err, stream.writeCount())
					}
				} else {
					if err == nil || stream.writeCount() != 0 {
						t.Fatalf("rejected exchange = %v, writes=%d", err, stream.writeCount())
					}
					if action == "close" && !errors.Is(err, errRTUSessionState) {
						t.Fatalf("closed during admission = %v", err)
					}
					if _, ok := e.LastEvidence(); ok {
						t.Fatal("rejected admission fabricated read evidence")
					}
					if _, ok := e.LastPrivateFunctionEvidence(); ok {
						t.Fatal("rejected admission fabricated private evidence")
					}
				}
				e.mu.Lock()
				defer e.mu.Unlock()
				if e.inflight || (action != "allow" && e.nextID != 0) {
					t.Fatalf("admission leaked ownership or consumed request ID: inflight=%v nextID=%d", e.inflight, e.nextID)
				}
			})
		}
	}
}
