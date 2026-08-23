package modbus

import (
	"bytes"
	"context"
	"io"
	"sync"
	"testing"
	"time"
)

func TestRTUSessionIsSingleFlightAndDisabledUntilExplicitlyEnabled(t *testing.T) {
	stream := &rtuSessionFakeStream{}
	session, err := NewRTUSession(RTUSessionConfig{
		Stream: stream, Timing: rtuTestTiming(t, 115200), Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	request, err := NewOpaqueVendorRequest(FunctionVendor100, []byte{0})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := session.Exchange(ctx, 0x10, request, DefaultOpaqueVendorRetryPolicy()); err == nil {
		t.Fatal("empty fake response accepted")
	}
	if stream.writes != 1 {
		t.Fatalf("writes = %d", stream.writes)
	}
	stream.writeN = 0
	stream.writeErr = nil
	if err := session.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := session.Exchange(context.Background(), 0x10, request, DefaultOpaqueVendorRetryPolicy()); err == nil {
		t.Fatal("empty successor response accepted")
	}
	if stream.writes != 2 {
		t.Fatalf("writes after recovery = %d", stream.writes)
	}
}

func TestRTUSessionRetriesOnlyProvenZeroByteReplaySafeWrite(t *testing.T) {
	stream := newRTUSessionFakeStream()
	stream.writeResults = []rtuSessionWriteResult{
		{err: io.ErrClosedPipe},
		{},
	}
	session, err := NewRTUSession(RTUSessionConfig{Stream: stream, Timing: rtuTestTiming(t, 115200), Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	request, err := NewOpaqueVendorRequest(FunctionVendor102, nil)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := NewOpaqueVendorRetryPolicy(2, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.Exchange(context.Background(), 0x10, request, policy); err == nil {
		t.Fatal("empty response accepted")
	}
	if stream.writes != 2 {
		t.Fatalf("writes = %d", stream.writes)
	}
}

func TestRTUSessionSerializesConcurrentExchanges(t *testing.T) {
	stream := &blockingRTUSessionStream{writeStarted: make(chan struct{}), release: make(chan struct{})}
	session, err := NewRTUSession(RTUSessionConfig{Stream: stream, Timing: rtuTestTiming(t, 115200), Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	request, err := NewOpaqueVendorRequest(FunctionVendor100, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	finished := make(chan error, 2)
	go func() {
		_, err := session.Exchange(ctx, 0x10, request, DefaultOpaqueVendorRetryPolicy())
		finished <- err
	}()
	<-stream.writeStarted
	go func() {
		_, err := session.Exchange(ctx, 0x10, request, DefaultOpaqueVendorRetryPolicy())
		finished <- err
	}()
	time.Sleep(5 * time.Millisecond)
	if writes := stream.WriteCount(); writes != 1 {
		t.Fatalf("concurrent writes = %d", writes)
	}
	close(stream.release)
	firstErr := <-finished
	secondErr := <-finished
	if firstErr == nil || secondErr == nil {
		t.Fatal("empty responses accepted")
	}
	if writes := stream.WriteCount(); writes != 1 {
		t.Fatalf("quarantined writes = %d", writes)
	}
}

func TestRTUSessionRetainsMultipleOpaqueFramesUntilResponseBound(t *testing.T) {
	request, err := NewOpaqueVendorRequest(FunctionVendor100, []byte{0})
	if err != nil {
		t.Fatal(err)
	}
	stream := newRTUSessionFakeStream(
		rtuSessionBytes(makeOpaqueRTUFrame(t, 0x10, FunctionVendor100, []byte{0}), 0),
		rtuSessionGap(3*time.Millisecond),
		rtuSessionBytes(makeOpaqueRTUFrame(t, 0x10, FunctionVendor100, []byte{1, 2}), 4*time.Millisecond),
		rtuSessionGap(7*time.Millisecond),
	)
	session, err := NewRTUSession(RTUSessionConfig{Stream: stream, Timing: rtuTestTiming(t, 115200), Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	responses, err := session.Exchange(context.Background(), 0x10, request, DefaultOpaqueVendorRetryPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if len(responses) != 2 || !bytes.Equal(responses[1].Payload(), []byte{1, 2}) {
		t.Fatalf("responses = %#v", responses)
	}
}

func TestRTUSessionQuarantinesResponseFrameOverflow(t *testing.T) {
	request, err := NewOpaqueVendorRequest(FunctionVendor100, []byte{0})
	if err != nil {
		t.Fatal(err)
	}
	stream := newRTUSessionFakeStream(
		rtuSessionBytes(makeOpaqueRTUFrame(t, 0x10, FunctionVendor100, []byte{0}), 0),
		rtuSessionGap(3*time.Millisecond),
		rtuSessionBytes(makeOpaqueRTUFrame(t, 0x10, FunctionVendor100, []byte{1}), 4*time.Millisecond),
		rtuSessionGap(7*time.Millisecond),
	)
	session, err := NewRTUSession(RTUSessionConfig{
		Stream: stream, Timing: rtuTestTiming(t, 115200), Enabled: true, MaxResponseFrames: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.Exchange(context.Background(), 0x10, request, DefaultOpaqueVendorRetryPolicy()); err == nil {
		t.Fatal("response frame overflow accepted")
	}
	if _, err := session.Exchange(context.Background(), 0x10, request, DefaultOpaqueVendorRetryPolicy()); err == nil {
		t.Fatal("overflow successor accepted")
	}
	if stream.writes != 1 {
		t.Fatalf("writes = %d", stream.writes)
	}
}

func TestRTUSessionRejectsDisabledAndLocalFailuresWithoutWrite(t *testing.T) {
	stream := newRTUSessionFakeStream()
	if _, err := NewRTUSession(RTUSessionConfig{Stream: stream, Timing: rtuTestTiming(t, 115200)}); err == nil {
		t.Fatal("disabled session accepted")
	}
	session, err := NewRTUSession(RTUSessionConfig{Stream: stream, Timing: rtuTestTiming(t, 115200), Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.Exchange(context.Background(), 0, OpaqueVendorRequest{}, DefaultOpaqueVendorRetryPolicy()); err == nil {
		t.Fatal("invalid local request accepted")
	}
	if stream.writes != 0 {
		t.Fatalf("writes = %d", stream.writes)
	}
}

func TestRTUSessionPartialWriteQuarantinesSuccessor(t *testing.T) {
	stream := newRTUSessionFakeStream()
	stream.writeN = 1
	stream.writeErr = io.ErrUnexpectedEOF
	session, err := NewRTUSession(RTUSessionConfig{Stream: stream, Timing: rtuTestTiming(t, 115200), Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	request, err := NewOpaqueVendorRequest(FunctionVendor101, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.Exchange(context.Background(), 0x10, request, DefaultOpaqueVendorRetryPolicy()); err == nil {
		t.Fatal("partial write accepted")
	}
	if _, err := session.Exchange(context.Background(), 0x10, request, DefaultOpaqueVendorRetryPolicy()); err == nil {
		t.Fatal("quarantined successor accepted")
	}
	if stream.writes != 1 {
		t.Fatalf("writes = %d", stream.writes)
	}
}

func TestRTUSessionRecoveryRequiresMonotonicQuietProof(t *testing.T) {
	stream := newRTUSessionFakeStream(rtuSessionGap(0))
	stream.writeN = 1
	stream.writeErr = io.ErrUnexpectedEOF
	session, err := NewRTUSession(RTUSessionConfig{Stream: stream, Timing: rtuTestTiming(t, 115200), Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	request, err := NewOpaqueVendorRequest(FunctionVendor101, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.Exchange(context.Background(), 0x10, request, DefaultOpaqueVendorRetryPolicy()); err == nil {
		t.Fatal("partial write accepted")
	}
	if err := session.Recover(context.Background()); err == nil {
		t.Fatal("unproven quiet interval accepted")
	}
	stream.writeN = 0
	stream.writeErr = nil
	if _, err := session.Exchange(context.Background(), 0x10, request, DefaultOpaqueVendorRetryPolicy()); err == nil {
		t.Fatal("unproven successor accepted")
	}
	if stream.writes != 1 {
		t.Fatalf("writes = %d", stream.writes)
	}
}

type rtuSessionAction struct {
	value  byte
	offset time.Duration
	err    error
}

func rtuSessionBytes(frame []byte, offset time.Duration) []rtuSessionAction {
	actions := make([]rtuSessionAction, len(frame))
	for index, value := range frame {
		actions[index] = rtuSessionAction{value: value, offset: offset + time.Duration(index)*100*time.Microsecond}
	}
	return actions
}

func rtuSessionGap(offset time.Duration) rtuSessionAction {
	return rtuSessionAction{offset: offset, err: context.DeadlineExceeded}
}

type rtuSessionFakeStream struct {
	actions      []rtuSessionAction
	writes       int
	writeN       int
	writeErr     error
	writeResults []rtuSessionWriteResult
	offset       time.Duration
}

type rtuSessionWriteResult struct {
	written int
	err     error
}

func newRTUSessionFakeStream(parts ...interface{}) *rtuSessionFakeStream {
	stream := &rtuSessionFakeStream{}
	for _, part := range parts {
		switch value := part.(type) {
		case []rtuSessionAction:
			stream.actions = append(stream.actions, value...)
		case rtuSessionAction:
			stream.actions = append(stream.actions, value)
		}
	}
	return stream
}

func (stream *rtuSessionFakeStream) ReadRTUByte(ctx context.Context) (byte, time.Duration, error) {
	if len(stream.actions) != 0 {
		action := stream.actions[0]
		stream.actions = stream.actions[1:]
		stream.offset = action.offset
		return action.value, action.offset, action.err
	}
	<-ctx.Done()
	stream.offset += 2 * time.Millisecond
	return 0, stream.offset, ctx.Err()
}

func (stream *rtuSessionFakeStream) WriteRTU(_ context.Context, frame []byte) (int, error) {
	stream.writes++
	if len(stream.writeResults) != 0 {
		result := stream.writeResults[0]
		stream.writeResults = stream.writeResults[1:]
		if result.written == 0 && result.err == nil {
			return len(frame), nil
		}
		return result.written, result.err
	}
	if stream.writeN != 0 || stream.writeErr != nil {
		return stream.writeN, stream.writeErr
	}
	return len(frame), nil
}

func (stream *rtuSessionFakeStream) RTUOffset() time.Duration { return stream.offset }

type blockingRTUSessionStream struct {
	mu           sync.Mutex
	writes       int
	writeStarted chan struct{}
	release      chan struct{}
}

func (stream *blockingRTUSessionStream) ReadRTUByte(ctx context.Context) (byte, time.Duration, error) {
	<-ctx.Done()
	return 0, 2 * time.Millisecond, ctx.Err()
}

func (stream *blockingRTUSessionStream) WriteRTU(ctx context.Context, frame []byte) (int, error) {
	stream.mu.Lock()
	stream.writes++
	first := stream.writes == 1
	stream.mu.Unlock()
	if first {
		close(stream.writeStarted)
	}
	select {
	case <-stream.release:
		return len(frame), nil
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}

func (stream *blockingRTUSessionStream) RTUOffset() time.Duration { return 2 * time.Millisecond }

func (stream *blockingRTUSessionStream) WriteCount() int {
	stream.mu.Lock()
	defer stream.mu.Unlock()
	return stream.writes
}
