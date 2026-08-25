package modbus

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"
)

func TestRTUSerialConfigRejectsImplicitOrInvalidFormats(t *testing.T) {
	valid := RTUSerialConfig{
		Path:     "/configured/rtu",
		Baud:     115200,
		DataBits: 8,
		Parity:   RTUParityNone,
		StopBits: 1,
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	for _, invalid := range []RTUSerialConfig{
		{},
		{Path: valid.Path, Baud: valid.Baud, DataBits: 7, Parity: valid.Parity, StopBits: valid.StopBits},
		{Path: valid.Path, Baud: valid.Baud, DataBits: valid.DataBits, Parity: RTUParity("invalid"), StopBits: valid.StopBits},
		{Path: valid.Path, Baud: valid.Baud, DataBits: valid.DataBits, Parity: valid.Parity, StopBits: 3},
	} {
		if err := invalid.Validate(); err == nil {
			t.Fatalf("invalid config accepted: %#v", invalid)
		}
	}
}

func TestRTUSerialStreamReportsOffsetsAndPreservesByteExchange(t *testing.T) {
	now := time.Unix(0, 0)
	backend := &fakeRTUSerialBackend{reads: []serialRead{{value: 0x7e}}}
	stream, err := newRTUSerialStream(backend, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(3 * time.Millisecond)
	value, offset, err := stream.ReadRTUByte(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if value != 0x7e || offset != 3*time.Millisecond {
		t.Fatalf("read = (%#x, %s), want (0x7e, 3ms)", value, offset)
	}
	if got := stream.RTUOffset(); got != 3*time.Millisecond {
		t.Fatalf("RTUOffset = %s, want 3ms", got)
	}
	if written, err := stream.WriteRTU(context.Background(), []byte{0x10, 0x64, 0, 0, 0}); err != nil || written != 5 {
		t.Fatalf("WriteRTU = (%d, %v), want (5, nil)", written, err)
	}
	if got := backend.writes; len(got) != 1 || string(got[0]) != string([]byte{0x10, 0x64, 0, 0, 0}) {
		t.Fatalf("writes = %#v", got)
	}
}

func TestRTUSerialStreamPassesCancellationAndClosesOnce(t *testing.T) {
	backend := &fakeRTUSerialBackend{readBlock: true}
	stream, err := newRTUSerialStream(backend, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := stream.ReadRTUByte(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("ReadRTUByte error = %v, want context cancellation", err)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	if backend.closes != 1 {
		t.Fatalf("Close calls = %d, want 1", backend.closes)
	}
	if _, err := stream.WriteRTU(context.Background(), []byte{1}); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("closed WriteRTU error = %v, want io.ErrClosedPipe", err)
	}
}

type serialRead struct {
	value byte
	err   error
}

type fakeRTUSerialBackend struct {
	mu        sync.Mutex
	reads     []serialRead
	readBlock bool
	writes    [][]byte
	closes    int
}

func (backend *fakeRTUSerialBackend) ReadByte(ctx context.Context) (byte, error) {
	backend.mu.Lock()
	if len(backend.reads) != 0 {
		read := backend.reads[0]
		backend.reads = backend.reads[1:]
		backend.mu.Unlock()
		return read.value, read.err
	}
	block := backend.readBlock
	backend.mu.Unlock()
	if block {
		<-ctx.Done()
		return 0, ctx.Err()
	}
	return 0, io.EOF
}

func (backend *fakeRTUSerialBackend) Write(ctx context.Context, frame []byte) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	backend.writes = append(backend.writes, append([]byte(nil), frame...))
	return len(frame), nil
}

func (backend *fakeRTUSerialBackend) Close() error {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	backend.closes++
	return nil
}
