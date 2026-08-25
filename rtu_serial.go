package modbus

import (
	"context"
	"io"
	"sync"
	"time"
)

// RTUSerialConfig identifies one explicitly configured local RTU serial endpoint.
// It does not select a vendor profile or admit a protocol operation.
type RTUSerialConfig struct {
	Path     string
	Baud     uint32
	DataBits uint8
	Parity   RTUParity
	StopBits uint8
}

// Validate rejects incomplete and unsupported serial formats before a device is opened.
func (config RTUSerialConfig) Validate() error {
	if config.Path == "" || !supportedRTUSerialBaud(config.Baud) ||
		config.DataBits != 8 ||
		(config.Parity != RTUParityNone && config.Parity != RTUParityEven && config.Parity != RTUParityOdd) ||
		(config.StopBits != 1 && config.StopBits != 2) {
		return protocolError(ErrorInvalidRequest, 0, 0, "rtu_serial_config", -1)
	}
	return nil
}

func supportedRTUSerialBaud(baud uint32) bool {
	switch baud {
	case 9600, 19200, 38400, 57600, 115200, 230400:
		return true
	default:
		return false
	}
}

type rtuSerialBackend interface {
	ReceiveByte(context.Context) (byte, error)
	Write(context.Context, []byte) (int, error)
	Close() error
}

// RTUSerialStream is a generic, bidirectional RTUByteStream backed by one
// configured serial endpoint. It preserves byte timing and leaves all PDU
// interpretation and operation admission to higher layers.
type RTUSerialStream struct {
	backend  rtuSerialBackend
	now      func() time.Time
	started  time.Time
	mu       sync.Mutex
	closed   bool
	closeErr error
}

func newRTUSerialStream(backend rtuSerialBackend, now func() time.Time) (*RTUSerialStream, error) {
	if backend == nil || now == nil {
		return nil, protocolError(ErrorInvalidRequest, 0, 0, "rtu_serial_stream", -1)
	}
	started := now()
	return &RTUSerialStream{backend: backend, now: now, started: started}, nil
}

// ReadRTUByte receives one byte and records its monotonic offset from opening.
func (stream *RTUSerialStream) ReadRTUByte(ctx context.Context) (byte, time.Duration, error) {
	if stream == nil || ctx == nil {
		return 0, 0, errRTUSessionState
	}
	if err := ctx.Err(); err != nil {
		return 0, stream.RTUOffset(), err
	}
	stream.mu.Lock()
	closed := stream.closed
	backend := stream.backend
	stream.mu.Unlock()
	if closed {
		return 0, stream.RTUOffset(), io.ErrClosedPipe
	}
	value, err := backend.ReceiveByte(ctx)
	return value, stream.RTUOffset(), err
}

// WriteRTU writes opaque bytes exactly as supplied. Short writes are returned
// unchanged so the session can quarantine uncertain transmission.
func (stream *RTUSerialStream) WriteRTU(ctx context.Context, frame []byte) (int, error) {
	if stream == nil || ctx == nil {
		return 0, errRTUSessionState
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	stream.mu.Lock()
	closed := stream.closed
	backend := stream.backend
	stream.mu.Unlock()
	if closed {
		return 0, io.ErrClosedPipe
	}
	return backend.Write(ctx, frame)
}

// RTUOffset returns the non-negative elapsed offset from stream opening.
func (stream *RTUSerialStream) RTUOffset() time.Duration {
	if stream == nil || stream.now == nil {
		return 0
	}
	offset := stream.now().Sub(stream.started)
	if offset < 0 {
		return 0
	}
	return offset
}

// Close releases the configured local endpoint once. In-flight operations are
// allowed to observe the underlying close error; later operations fail closed.
func (stream *RTUSerialStream) Close() error {
	if stream == nil {
		return errRTUSessionState
	}
	stream.mu.Lock()
	defer stream.mu.Unlock()
	if stream.closed {
		return stream.closeErr
	}
	stream.closed = true
	stream.closeErr = stream.backend.Close()
	return stream.closeErr
}
