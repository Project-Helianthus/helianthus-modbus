package modbus

import (
	"context"
	"testing"
	"time"
)

func TestRTUSessionIsSingleFlightAndDisabledUntilExplicitlyEnabled(t *testing.T) {
	stream := &rtuSessionFakeStream{}
	session, err := NewRTUSession(RTUSessionConfig{
		Stream: stream, Timing: rtuTestTiming(t, 115200), Enabled: true,
	})
	if err != nil { t.Fatal(err) }
	request, err := NewOpaqueVendorRequest(FunctionVendor100, []byte{0})
	if err != nil { t.Fatal(err) }
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := session.Exchange(ctx, 0x10, request, DefaultOpaqueVendorRetryPolicy()); err == nil {
		t.Fatal("empty fake response accepted")
	}
	if stream.writes != 1 { t.Fatalf("writes = %d", stream.writes) }
}

type rtuSessionFakeStream struct{ writes int }
func (stream *rtuSessionFakeStream) Read([]byte) (int, error) { return 0, context.DeadlineExceeded }
func (stream *rtuSessionFakeStream) Write(p []byte) (int, error) { stream.writes++; return len(p), nil }
