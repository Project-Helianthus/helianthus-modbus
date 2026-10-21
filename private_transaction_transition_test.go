package modbus

import (
	"bytes"
	"errors"
	"testing"
)

func TestQ23PrivateTransactionTransitions(t *testing.T) {
	type state string
	const (
		idle       state = "idle"
		waiting    state = "waiting"
		quarantine state = "quarantine"
	)
	type operation string
	const (
		begin     operation = "begin"
		accept    operation = "accept"
		malformed operation = "malformed"
		complete  operation = "complete"
		timeout   operation = "timeout"
		release   operation = "release"
	)
	type transition struct {
		next        state
		badResponse bool
	}
	// Only these transitions are allowed. Every omitted pair must reject the
	// operation without changing the state or the in-flight correlation.
	oracle := map[state]map[operation]transition{
		idle: {begin: {next: waiting}},
		waiting: {
			accept: {next: waiting}, malformed: {next: waiting, badResponse: true},
			complete: {next: idle}, timeout: {next: quarantine},
		},
		quarantine: {release: {next: idle}},
	}
	prefix := map[state][]operation{
		idle: nil, waiting: {begin}, quarantine: {begin, timeout},
	}
	// Each witness starts with a valid operation specific to the preserved
	// state, then proves that a complete new transaction is still usable.
	witness := map[state][]operation{
		idle:       {begin, accept, complete},
		waiting:    {accept, complete, begin, accept, complete},
		quarantine: {release, begin, accept, complete},
	}
	type sequence struct {
		name  string
		steps []operation
	}
	sequences := []sequence{
		{"complete_and_rebegin", []operation{begin, accept, accept, complete, begin, accept, complete}},
		{"timeout_release_and_rebegin", []operation{begin, timeout, release, begin, accept, complete}},
		{"duplicate_complete", []operation{begin, complete, complete, begin, accept, complete}},
		{"duplicate_release", []operation{begin, timeout, release, release, begin, accept, complete}},
	}
	for _, start := range []state{idle, waiting, quarantine} {
		for _, op := range []operation{begin, accept, malformed, complete, timeout, release} {
			next := start
			if allowed, ok := oracle[start][op]; ok {
				next = allowed.next
			}
			steps := append([]operation(nil), prefix[start]...)
			steps = append(steps, op)
			steps = append(steps, witness[next]...)
			sequences = append(sequences, sequence{string(start) + "/" + string(op), steps})
		}
	}
	request, err := NewPrivateFunctionRequest(PrivateFunctionCode(0x64), []byte{0})
	if err != nil {
		t.Fatal(err)
	}
	replacement, err := NewPrivateFunctionRequest(PrivateFunctionCode(0x65), []byte{7})
	if err != nil {
		t.Fatal(err)
	}
	// Synthetic, independently specified normal response; framing vectors
	// remain in the existing private-function framing tests.
	responseFrame := []byte{0x10, 0x64, 0x00, 0x5a, 0xc5}
	for _, test := range sequences {
		t.Run(test.name, func(t *testing.T) {
			var transaction PrivateFunctionTransaction
			current := idle
			for i, op := range test.steps {
				expected, allowed := oracle[current][op]
				var err error
				switch op {
				case begin:
					unit, candidate := byte(0x10), request
					if current != idle {
						unit, candidate = 0x11, replacement
					}
					var frame []byte
					frame, err = transaction.Begin(unit, candidate)
					if err == nil && len(frame) == 0 {
						t.Fatalf("step %d: Begin returned no frame", i)
					}
				case accept, malformed:
					frame := responseFrame
					if op == malformed {
						frame = []byte{0x10}
					}
					var response RTUPrivateFunctionResponseADU
					response, err = transaction.Accept(frame)
					if err == nil && (!bytes.Equal(response.Bytes(), responseFrame) || !bytes.Equal(response.Payload(), []byte{0})) {
						t.Fatalf("step %d: raw response = %x, payload = %x", i, response.Bytes(), response.Payload())
					}
				case complete:
					err = transaction.Complete()
				case timeout:
					err = transaction.Timeout()
				case release:
					err = transaction.ReleaseQuarantine()
				default:
					t.Fatalf("unknown operation %q", op)
				}
				switch {
				case !allowed:
					if !errors.Is(err, errPrivateFunctionTransactionState) {
						t.Fatalf("step %d: %s in %s error = %v, want state rejection", i, op, current, err)
					}
				case expected.badResponse:
					var protocolErr *ProtocolError
					if !errors.As(err, &protocolErr) {
						t.Fatalf("step %d: malformed response error = %v, want protocol error", i, err)
					}
					current = expected.next
				default:
					if err != nil {
						t.Fatalf("step %d: %s in %s: %v", i, op, current, err)
					}
					current = expected.next
				}
			}
		})
	}
}
