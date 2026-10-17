package modbus

import (
	"errors"
	"fmt"
	"testing"
)

func u11ReadIntentSpec(request ReadRegistersRequest) ReadIntentSpec {
	return ReadIntentSpec{
		LogicalViewID: 1, Endpoint: "synthetic-u11", Transport: TransportTCP,
		TransportGeneration: 1, UnitID: 1, AuthorizationScope: "synthetic-read",
		PollGeneration: 1, DeadlineIdentity: 1, Request: request,
	}
}

func TestU11ReadIntentValidIdentity(t *testing.T) {
	request, err := NewReadRegistersRequest(FunctionReadHoldingRegisters, 16, 1)
	if err != nil {
		t.Fatal(err)
	}
	want := u11ReadIntentSpec(request)
	intent, err := NewReadIntent(want)
	if err != nil {
		t.Fatalf("independent interior-range identity control: %v", err)
	}
	if got := intent.Spec(); got != want {
		t.Fatalf("intent spec = %+v, want %+v", got, want)
	}
}

func TestU11ReadIntentFinalRegister(t *testing.T) {
	for _, operation := range []struct {
		function FunctionCode
		table    LogicalTable
	}{
		{FunctionReadHoldingRegisters, HoldingRegisters},
		{FunctionReadInputRegisters, InputRegisters},
	} {
		for _, quantity := range []int{1, 2, 125} {
			t.Run(fmt.Sprintf("FC%02x/quantity_%d", operation.function, quantity), func(t *testing.T) {
				// Construct directly so a constructor rejection cannot mask this seam.
				request := ReadRegistersRequest{
					function: operation.function, table: operation.table,
					offset: uint16(65536 - quantity), quantity: uint16(quantity),
				}
				want := u11ReadIntentSpec(request)
				intent, err := NewReadIntent(want)
				if err != nil {
					t.Fatalf("inclusive final register rejected: %v", err)
				}
				if got := intent.Spec(); got != want {
					t.Fatalf("intent spec = %+v, want %+v", got, want)
				}
			})
		}
	}
}

func TestU11ReadIntentRejectsForgedOverflow(t *testing.T) {
	for _, operation := range []struct {
		function FunctionCode
		table    LogicalTable
	}{
		{FunctionReadHoldingRegisters, HoldingRegisters},
		{FunctionReadInputRegisters, InputRegisters},
	} {
		for _, quantity := range []int{2, 125} {
			t.Run(fmt.Sprintf("FC%02x/quantity_%d", operation.function, quantity), func(t *testing.T) {
				// The inclusive end is 65536; all other request and identity fields are valid.
				request := ReadRegistersRequest{
					function: operation.function, table: operation.table,
					offset: uint16(65537 - quantity), quantity: uint16(quantity),
				}
				intent, err := NewReadIntent(u11ReadIntentSpec(request))
				var failure *ProtocolError
				if !errors.As(err, &failure) || failure.Kind != ErrorInvalidRange ||
					failure.Field != "range_wrap" || failure.Offset != 1 ||
					failure.RequestedFunction != operation.function {
					t.Fatalf("error = %v, want invalid_range/range_wrap at 1 for FC%02x", err, operation.function)
				}
				if intent != (ReadIntent{}) {
					t.Fatalf("invalid request produced intent %+v", intent)
				}
			})
		}
	}
}

func TestU11ReadIntentRejectsZeroRequest(t *testing.T) {
	intent, err := NewReadIntent(u11ReadIntentSpec(ReadRegistersRequest{}))
	var failure *ProtocolError
	if !errors.As(err, &failure) || failure.Kind != ErrorUnsupportedOperation ||
		failure.Field != "function" || failure.Offset != 0 || failure.RequestedFunction != 0 {
		t.Fatalf("error = %v, want unsupported_operation/function at 0 for zero request", err)
	}
	if intent != (ReadIntent{}) {
		t.Fatalf("zero request produced intent %+v", intent)
	}
}
