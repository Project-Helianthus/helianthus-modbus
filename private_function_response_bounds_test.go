package modbus

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"
)

type responseBoundsStream struct {
	privateProductionStream
	reads int
}

func (s *responseBoundsStream) ReadRTUByte(ctx context.Context) (byte, time.Duration, error) {
	s.reads++
	return s.privateProductionStream.ReadRTUByte(ctx)
}

// Build CRC-valid synthetic frames without the encoder's request-size guard.
func responseBoundsFrame(unit, function byte, payloadSize int) []byte {
	frame := []byte{unit, function}
	frame = append(frame, bytes.Repeat([]byte{0xa5}, payloadSize)...)
	crc := rtuCRC16(frame)
	return append(frame, byte(crc), byte(crc>>8))
}

func responseBoundsError(t *testing.T, err error, kind ErrorKind, field string) {
	t.Helper()
	var pe *ProtocolError
	if !errors.As(err, &pe) || pe.Kind != kind || pe.Field != field {
		t.Fatalf("error = %v, want %v / %s", err, kind, field)
	}
}

func responseBoundsEvidence(t *testing.T, endpoint *RTUProductionEndpoint, evidence RTUPrivateFunctionEvidence, frames [][]byte, outcome string, integrity, current bool) {
	t.Helper()
	if evidence.TerminalOutcome != outcome || evidence.IntegrityValid != integrity || evidence.Current != current || !reflect.DeepEqual(evidence.ResponseADUs, frames) {
		t.Fatalf("receipt = %#v, want frames %x / %s / integrity %v / current %v", evidence, frames, outcome, integrity, current)
	}
	retained, ok := endpoint.LastPrivateFunctionEvidence()
	if !ok || !reflect.DeepEqual(retained, evidence) {
		t.Fatalf("retained receipt = %#v, present %v", retained, ok)
	}
}

func TestPrivateResponseBoundsCount(t *testing.T) {
	for _, limit := range []int{1, 3, 8} {
		for _, terminal := range []bool{false, true} {
			t.Run(fmt.Sprintf("limit_%d/terminal_%v", limit, terminal), func(t *testing.T) {
				frames := make([][]byte, limit+1)
				for i := range frames {
					frames[i] = responseBoundsFrame(1, 0x64, i+1)
				}
				stream := &responseBoundsStream{}
				stream.queue(frames...)
				endpoint := privateProductionEndpoint(t, stream, &privateProductionAdmission{admit: true}, limit)
				t.Cleanup(func() { _ = endpoint.Close() })
				calls := 0
				classifier := privateClassifierFunc(func(response RTUPrivateFunctionResponseADU) (RTUPrivateFunctionDisposition, error) {
					if calls >= limit {
						t.Fatalf("classified extra response %d", calls+1)
					}
					if !bytes.Equal(response.Bytes(), frames[calls]) {
						t.Fatalf("classifier frame %d = %x", calls, response.Bytes())
					}
					calls++
					if terminal && calls == limit {
						return RTUPrivateFunctionTerminal, nil
					}
					return RTUPrivateFunctionContinue, nil
				})
				request := privateProductionRequest(t, 0x64, []byte{0x55})
				responses, evidence, err := endpoint.ExchangePrivateFunction(context.Background(), 1, request, DefaultPrivateFunctionResponsePolicy(), classifier)
				wantReads := 0
				for _, frame := range frames[:limit] {
					wantReads += len(frame) + 1
				}
				if calls != limit || stream.reads != wantReads || stream.writeCount() != 1 {
					t.Fatalf("calls/reads/writes = %d/%d/%d, want %d/%d/1", calls, stream.reads, stream.writeCount(), limit, wantReads)
				}
				stream.mu.Lock()
				remaining := len(stream.segments) == 1 && bytes.Equal(stream.segments[0], frames[limit])
				stream.mu.Unlock()
				if !remaining {
					t.Fatal("extra queued response consumed")
				}
				if terminal {
					if err != nil || len(responses) != limit {
						t.Fatalf("completion = %v / %d responses", err, len(responses))
					}
					for i, response := range responses {
						if !bytes.Equal(response.Bytes(), frames[i]) {
							t.Fatalf("response %d differs", i)
						}
					}
					responseBoundsEvidence(t, endpoint, evidence, frames[:limit], "success", true, true)
				} else {
					responseBoundsError(t, err, ErrorMalformedResponse, "rtu_private_function_response_count")
					var pe *ProtocolError
					errors.As(err, &pe)
					if pe.Offset != limit || responses != nil {
						t.Fatalf("bound = %v / %#v", err, responses)
					}
					responseBoundsEvidence(t, endpoint, evidence, frames[:limit], "response_bound", true, false)
					assertPrivateFenced(t, endpoint, &stream.privateProductionStream, request)
				}
			})
		}
	}
}

func TestPrivateResponseBoundsSizes(t *testing.T) {
	// A three-byte CRC-valid ADU has only an address and CRC: no function slot.
	// Keep that malformed envelope separate from normal and exception frames.
	short := []byte{1}
	crc := rtuCRC16(short)
	short = append(short, byte(crc), byte(crc>>8))
	cases := []struct {
		name  string
		frame []byte
		field string
		kind  ErrorKind
		reads int
	}{
		{"minimum", responseBoundsFrame(1, 0x64, 0), "", "", 5},
		{"maximum", responseBoundsFrame(1, 0x64, 252), "", "", 257},
		{"below_minimum", short, "rtu_adu_length", ErrorMalformedResponse, 4},
		{"above_maximum", responseBoundsFrame(1, 0x64, 253), "rtu_buffer", ErrorInvalidRange, 257},
		{"wrong_unit", responseBoundsFrame(2, 0x64, 1), "unit_id", ErrorMalformedResponse, 6},
		{"wrong_function", responseBoundsFrame(1, 0x65, 1), "function_mismatch", ErrorMalformedResponse, 6},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got, want := rtuCRC16(tc.frame[:len(tc.frame)-2]), uint16(tc.frame[len(tc.frame)-2])|uint16(tc.frame[len(tc.frame)-1])<<8; got != want {
				t.Fatal("fixture CRC invalid")
			}
			prior := responseBoundsFrame(1, 0x64, 1)
			frames := [][]byte{prior, tc.frame}
			stream := &responseBoundsStream{}
			stream.queue(frames...)
			endpoint := privateProductionEndpoint(t, stream, &privateProductionAdmission{admit: true}, 2)
			t.Cleanup(func() { _ = endpoint.Close() })
			calls := 0
			classifier := privateClassifierFunc(func(response RTUPrivateFunctionResponseADU) (RTUPrivateFunctionDisposition, error) {
				if calls >= 2 || !bytes.Equal(response.Bytes(), frames[calls]) {
					t.Fatal("unexpected classified frame")
				}
				calls++
				if calls == 1 {
					return RTUPrivateFunctionContinue, nil
				}
				return RTUPrivateFunctionTerminal, nil
			})
			request := privateProductionRequest(t, 0x64, []byte{0x55})
			responses, evidence, err := endpoint.ExchangePrivateFunction(context.Background(), 1, request, DefaultPrivateFunctionResponsePolicy(), classifier)
			wantCalls := 1
			if tc.field == "" {
				wantCalls = 2
			}
			if calls != wantCalls || stream.reads != len(prior)+1+tc.reads || stream.writeCount() != 1 {
				t.Fatalf("calls/reads/writes = %d/%d/%d", calls, stream.reads, stream.writeCount())
			}
			if tc.field == "" {
				if err != nil || len(responses) != 2 || !bytes.Equal(responses[1].Bytes(), tc.frame) || !bytes.Equal(responses[1].Payload(), tc.frame[2:len(tc.frame)-2]) {
					t.Fatalf("normal response = %#v / %v", responses, err)
				}
				responseBoundsEvidence(t, endpoint, evidence, frames, "success", true, true)
			} else {
				responseBoundsError(t, err, tc.kind, tc.field)
				if responses != nil {
					t.Fatal("fault published responses")
				}
				responseBoundsEvidence(t, endpoint, evidence, frames, "transport_fault", false, false)
				assertPrivateFenced(t, endpoint, &stream.privateProductionStream, request)
			}
			// Exercise the complete-frame length guard independently of the stream cap.
			if tc.name == "above_maximum" {
				_, err = DecodeRTUPrivateFunctionResponseADU(1, request, tc.frame)
				responseBoundsError(t, err, ErrorMalformedResponse, "rtu_adu_length")
			}
		})
	}
}

func TestPrivateResponseBoundsExceptionSeparate(t *testing.T) {
	frame := privateProductionFrame(t, 1, 0xe4, []byte{4})
	stream := &responseBoundsStream{}
	stream.queue(frame)
	endpoint := privateProductionEndpoint(t, stream, &privateProductionAdmission{admit: true}, 1)
	t.Cleanup(func() { _ = endpoint.Close() })
	calls := 0
	classifier := privateClassifierFunc(func(RTUPrivateFunctionResponseADU) (RTUPrivateFunctionDisposition, error) {
		calls++
		return RTUPrivateFunctionContinue, nil
	})
	responses, evidence, err := endpoint.ExchangePrivateFunction(context.Background(), 1, privateProductionRequest(t, 0x64, []byte{0x55}), DefaultPrivateFunctionResponsePolicy(), classifier)
	responseBoundsError(t, err, ErrorExceptionResponse, "exception_code")
	var pe *ProtocolError
	errors.As(err, &pe)
	if pe.ExceptionCode != 4 || calls != 0 || responses != nil || stream.reads != len(frame)+1 || stream.writeCount() != 1 {
		t.Fatalf("exception = %v; calls/reads/writes = %d/%d/%d", err, calls, stream.reads, stream.writeCount())
	}
	responseBoundsEvidence(t, endpoint, evidence, [][]byte{frame}, "exception", true, false)
}
