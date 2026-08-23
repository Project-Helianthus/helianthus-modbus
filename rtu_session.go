package modbus

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"
)

const defaultRTUSessionMaxResponseFrames uint8 = 4

// RTUByteStream is the deliberately injected byte-level boundary for an RTU
// session. Implementations own physical-device access, cancellation, and the
// monotonic receipt timestamp for every byte; this package never opens a
// serial device itself.
type RTUByteStream interface {
	ReadRTUByte(context.Context) (byte, time.Duration, error)
	WriteRTU(context.Context, []byte) (int, error)
	RTUOffset() time.Duration
}

// RTUSessionConfig configures one default-denied, bounded RTU exchange owner.
type RTUSessionConfig struct {
	Stream            RTUByteStream
	Timing            RTUTiming
	Enabled           bool
	MaxResponseFrames uint8
}

// RTUSession serializes private-function RTU exchanges over one explicitly supplied
// stream. It retains no vendor semantics and never opens, discovers, or
// configures a physical device.
type RTUSession struct {
	mu                sync.Mutex
	stream            RTUByteStream
	timing            RTUTiming
	maxResponseFrames uint8
	quarantined       bool
	quarantineUntil   time.Duration
}

var errRTUSessionState = errors.New("invalid rtu session state")

// NewRTUSession validates one explicitly enabled injected stream. A false
// Enabled value is rejected rather than creating a latent outbound path.
func NewRTUSession(config RTUSessionConfig) (*RTUSession, error) {
	maxResponses := config.MaxResponseFrames
	if maxResponses == 0 {
		maxResponses = defaultRTUSessionMaxResponseFrames
	}
	if !config.Enabled || config.Stream == nil ||
		config.Timing.characterTime <= 0 ||
		config.Timing.interCharacter <= 0 ||
		config.Timing.interFrame <= 0 ||
		config.Timing.maxResponseLatency <= 0 ||
		config.Timing.maxQuiescence <= config.Timing.maxResponseLatency ||
		maxResponses > 8 {
		return nil, protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"rtu_session_config",
			-1,
		)
	}
	return &RTUSession{
		stream:            config.Stream,
		timing:            config.Timing,
		maxResponseFrames: maxResponses,
	}, nil
}

// Exchange writes one locally validated opaque request and retains every
// CRC-validated response frame received within the configured response bound.
// It never interprets a response payload: callers classify intermediate and
// terminal frames. A timed-out or malformed exchange remains quarantined until
// Recover proves a complete quiet interval.
func (session *RTUSession) Exchange(
	ctx context.Context,
	unitID byte,
	request PrivateFunctionRequest,
	policy PrivateFunctionResponsePolicy,
) ([]RTUPrivateFunctionResponseADU, error) {
	if session == nil || ctx == nil {
		return nil, errRTUSessionState
	}
	frame, err := EncodeRTUPrivateFunctionADU(unitID, request)
	if err != nil {
		return nil, err
	}
	if policy.maxAttempts == 0 ||
		policy.maxAttempts > 3 ||
		(policy.maxAttempts > 1 && !policy.replaySafe) {
		return nil, protocolError(
			ErrorInvalidRequest,
			FunctionCode(request.FunctionCode()),
			0,
			"private_function_response_policy",
			-1,
		)
	}

	session.mu.Lock()
	defer session.mu.Unlock()
	if session.quarantined {
		return nil, errRTUSessionState
	}
	for attempt := uint8(0); attempt < policy.maxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		written, writeErr := session.stream.WriteRTU(ctx, frame)
		if written == len(frame) && writeErr == nil {
			return session.receiveLocked(ctx, unitID, request)
		}
		if written != 0 {
			session.enterQuarantineLocked()
		}
		if writeErr == nil {
			writeErr = io.ErrShortWrite
		}
		if written == 0 && policy.replaySafe && attempt+1 < policy.maxAttempts && ctx.Err() == nil {
			continue
		}
		return nil, writeErr
	}
	return nil, errRTUSessionState
}

func (session *RTUSession) receiveLocked(
	ctx context.Context,
	unitID byte,
	request PrivateFunctionRequest,
) ([]RTUPrivateFunctionResponseADU, error) {
	decoder, err := NewRTUFrameDecoder(session.timing)
	if err != nil {
		return nil, err
	}
	var transaction PrivateFunctionTransaction
	if _, err := transaction.Begin(unitID, request); err != nil {
		return nil, err
	}
	responseCtx, cancel := context.WithTimeout(ctx, session.timing.MaxResponseLatency())
	defer cancel()
	responses := make([]RTUPrivateFunctionResponseADU, 0, session.maxResponseFrames)
	haveBytes := false
	for {
		readCtx, stopRead := context.WithTimeout(responseCtx, session.timing.InterFrame())
		value, offset, readErr := session.stream.ReadRTUByte(readCtx)
		stopRead()
		if readErr == nil {
			if err := decoder.FeedByte(offset, value); err != nil {
				session.enterQuarantineLocked()
				_ = transaction.Timeout()
				return nil, err
			}
			haveBytes = true
			continue
		}
		if !errors.Is(readErr, context.DeadlineExceeded) {
			session.enterQuarantineLocked()
			_ = transaction.Timeout()
			return nil, readErr
		}
		if haveBytes {
			frame, err := decoder.EndFrame(session.stream.RTUOffset())
			if err != nil {
				session.enterQuarantineLocked()
				_ = transaction.Timeout()
				return nil, err
			}
			if len(responses) == int(session.maxResponseFrames) {
				session.enterQuarantineLocked()
				_ = transaction.Timeout()
				return nil, protocolError(
					ErrorMalformedResponse,
					FunctionCode(request.FunctionCode()),
					0,
					"rtu_response_frame_count",
					len(responses),
				)
			}
			response, err := transaction.Accept(frame.Bytes())
			if err != nil {
				session.enterQuarantineLocked()
				_ = transaction.Timeout()
				return nil, err
			}
			responses = append(responses, response)
			haveBytes = false
			continue
		}
		if ctx.Err() != nil {
			session.enterQuarantineLocked()
			_ = transaction.Timeout()
			return nil, ctx.Err()
		}
		if responseCtx.Err() == nil {
			continue
		}
		if len(responses) != 0 {
			if err := transaction.Complete(); err != nil {
				return nil, err
			}
			return responses, nil
		}
		session.enterQuarantineLocked()
		_ = transaction.Timeout()
		return nil, responseCtx.Err()
	}
}

// enterQuarantineLocked preserves the entire response-latency horizon of a
// potentially transmitted request. Callers hold session.mu.
func (session *RTUSession) enterQuarantineLocked() {
	until := session.stream.RTUOffset() + session.timing.MaxResponseLatency()
	if until > session.quarantineUntil {
		session.quarantineUntil = until
	}
	session.quarantined = true
}

// Recover discards delayed bytes through the entire response-latency horizon,
// then requires a complete configured t3.5 quiet interval. It is the only way
// to admit a successor after a contaminated exchange.
func (session *RTUSession) Recover(ctx context.Context) error {
	if session == nil || ctx == nil {
		return errRTUSessionState
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if !session.quarantined {
		return errRTUSessionState
	}
	recoveryCtx, cancel := context.WithTimeout(ctx, session.timing.MaxQuiescence())
	defer cancel()
	quietAfter := session.stream.RTUOffset()
	for {
		readCtx, stopRead := context.WithTimeout(recoveryCtx, session.timing.InterFrame())
		_, offset, err := session.stream.ReadRTUByte(readCtx)
		stopRead()
		if err == nil {
			quietAfter = offset
			continue
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if recoveryCtx.Err() == nil {
			now := session.stream.RTUOffset()
			if now < quietAfter || now-quietAfter < session.timing.InterFrame() {
				return errRTUSessionState
			}
			if now < session.quarantineUntil {
				continue
			}
			session.quarantined = false
			session.quarantineUntil = 0
			return nil
		}
		return recoveryCtx.Err()
	}
}
