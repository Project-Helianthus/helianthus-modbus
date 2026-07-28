package modbus

import (
	"math"
	"time"
)

const (
	rtuFixedInterCharacter = 750 * time.Microsecond
	rtuFixedInterFrame     = 1750 * time.Microsecond
	rtuFixedTimerBaudFloor = 19200
)

// RTUParity identifies the parity bit in an RTU serial format.
type RTUParity string

const (
	RTUParityNone RTUParity = "none"
	RTUParityEven RTUParity = "even"
	RTUParityOdd  RTUParity = "odd"
)

// RTUTimingConfig defines fixture timing and finite quarantine bounds.
type RTUTimingConfig struct {
	Baud                 uint32
	DataBits             uint8
	Parity               RTUParity
	StopBits             uint8
	InterCharacterSafety time.Duration
	InterFrameSafety     time.Duration
	MaxResponseLatency   time.Duration
	MaxQuiescence        time.Duration
}

// RTUTiming is one validated immutable RTU timing contract.
type RTUTiming struct {
	baud               uint32
	bitsPerCharacter   uint8
	characterTime      time.Duration
	interCharacter     time.Duration
	interFrame         time.Duration
	maxResponseLatency time.Duration
	maxQuiescence      time.Duration
}

// NewRTUTiming validates one RTU serial format and its safety intervals.
func NewRTUTiming(config RTUTimingConfig) (RTUTiming, error) {
	if config.Baud == 0 ||
		config.DataBits != 8 ||
		(config.Parity != RTUParityNone &&
			config.Parity != RTUParityEven &&
			config.Parity != RTUParityOdd) ||
		(config.StopBits != 1 && config.StopBits != 2) ||
		config.MaxResponseLatency <= 0 ||
		config.MaxQuiescence <= config.MaxResponseLatency {
		return RTUTiming{}, protocolError(
			ErrorInvalidRequest,
			0,
			0,
			"rtu_timing",
			-1,
		)
	}
	parityBits := uint8(0)
	if config.Parity != RTUParityNone {
		parityBits = 1
	}
	bits := uint8(1) + config.DataBits + parityBits + config.StopBits
	character, ok := ceilRTUDuration(uint64(bits)*uint64(time.Second), uint64(config.Baud))
	if !ok {
		return RTUTiming{}, protocolError(
			ErrorInvalidRange,
			0,
			0,
			"rtu_character_time",
			-1,
		)
	}
	var interCharacter time.Duration
	var interFrame time.Duration
	if config.Baud > rtuFixedTimerBaudFloor {
		interCharacter = rtuFixedInterCharacter
		interFrame = rtuFixedInterFrame
	} else {
		var valid bool
		interCharacter, valid = ceilRTUDuration(
			uint64(bits)*3*uint64(time.Second),
			uint64(config.Baud)*2,
		)
		if !valid {
			return RTUTiming{}, protocolError(
				ErrorInvalidRange,
				0,
				0,
				"rtu_inter_character",
				-1,
			)
		}
		interFrame, valid = ceilRTUDuration(
			uint64(bits)*7*uint64(time.Second),
			uint64(config.Baud)*2,
		)
		if !valid {
			return RTUTiming{}, protocolError(
				ErrorInvalidRange,
				0,
				0,
				"rtu_inter_frame",
				-1,
			)
		}
	}
	if config.InterCharacterSafety != 0 {
		if config.InterCharacterSafety < interCharacter {
			return RTUTiming{}, protocolError(
				ErrorInvalidRange,
				0,
				0,
				"rtu_inter_character_safety",
				-1,
			)
		}
		interCharacter = config.InterCharacterSafety
	}
	if config.InterFrameSafety != 0 {
		if config.InterFrameSafety < interFrame {
			return RTUTiming{}, protocolError(
				ErrorInvalidRange,
				0,
				0,
				"rtu_inter_frame_safety",
				-1,
			)
		}
		interFrame = config.InterFrameSafety
	}
	if interCharacter >= interFrame {
		return RTUTiming{}, protocolError(
			ErrorInvalidRange,
			0,
			0,
			"rtu_silent_interval_order",
			-1,
		)
	}
	return RTUTiming{
		baud:               config.Baud,
		bitsPerCharacter:   bits,
		characterTime:      character,
		interCharacter:     interCharacter,
		interFrame:         interFrame,
		maxResponseLatency: config.MaxResponseLatency,
		maxQuiescence:      config.MaxQuiescence,
	}, nil
}

func ceilRTUDuration(numerator uint64, denominator uint64) (time.Duration, bool) {
	if denominator == 0 || numerator > math.MaxInt64 {
		return 0, false
	}
	value := numerator / denominator
	if numerator%denominator != 0 {
		value++
	}
	if value == 0 || value > math.MaxInt64 {
		return 0, false
	}
	return time.Duration(value), true
}

// CharacterTime returns the ceiling duration of one configured character.
func (timing RTUTiming) CharacterTime() time.Duration {
	return timing.characterTime
}

// InterCharacter returns the validated t1.5 safety interval.
func (timing RTUTiming) InterCharacter() time.Duration {
	return timing.interCharacter
}

// InterFrame returns the validated t3.5 safety interval.
func (timing RTUTiming) InterFrame() time.Duration {
	return timing.interFrame
}

// MaxResponseLatency returns the endpoint-declared quarantine latency bound.
func (timing RTUTiming) MaxResponseLatency() time.Duration {
	return timing.maxResponseLatency
}

// MaxQuiescence returns the finite bound before explicit recovery is required.
func (timing RTUTiming) MaxQuiescence() time.Duration {
	return timing.maxQuiescence
}

// FrameTransmitHorizon returns a conservative full-frame serialization time.
func (timing RTUTiming) FrameTransmitHorizon(frameBytes int) (time.Duration, error) {
	if frameBytes <= 0 ||
		frameBytes > MaxRTUADUSize ||
		timing.characterTime <= 0 ||
		int64(frameBytes) > math.MaxInt64/int64(timing.characterTime) {
		return 0, protocolError(
			ErrorInvalidRange,
			0,
			0,
			"rtu_frame_horizon",
			-1,
		)
	}
	return time.Duration(frameBytes) * timing.characterTime, nil
}
