package modbus

import (
	"os"
	"strings"
	"testing"
)

func TestTCPEndpointRetryReconnectPhaseOrder(t *testing.T) {
	source, err := os.ReadFile("tcp_endpoint_retry.go")
	if err != nil {
		t.Fatalf("read retry/reconnect phase: %v", err)
	}
	text := string(source)

	last := -1
	for _, declaration := range []string{
		"func (endpoint *TCPEndpoint) finishRequestRetryable(",
		"func (endpoint *TCPEndpoint) Retry(",
		"func (endpoint *TCPEndpoint) WaitReconnect(",
		"func (endpoint *TCPEndpoint) completeReconnectBackoff(",
	} {
		next := strings.Index(text, declaration)
		if next < 0 || next < last {
			t.Fatalf("retry/reconnect phase %q is absent or out of order", declaration)
		}
		last = next
	}
}
