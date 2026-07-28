package modbus

import (
	"math"
	"testing"
	"time"
)

func rtuTestTiming(t *testing.T, baud uint32) RTUTiming {
	t.Helper()
	timing, err := NewRTUTiming(RTUTimingConfig{
		Baud:               baud,
		DataBits:           8,
		Parity:             RTUParityEven,
		StopBits:           1,
		MaxResponseLatency: 20 * time.Millisecond,
		MaxQuiescence:      100 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	return timing
}

func TestRTUTimingAtOrBelow19200UsesCeilingCharacterMultiples(t *testing.T) {
	timing := rtuTestTiming(t, 9600)
	if got, want := timing.CharacterTime(), 1145834*time.Nanosecond; got != want {
		t.Fatalf("character time = %s, want %s", got, want)
	}
	if got, want := timing.InterCharacter(), 1718750*time.Nanosecond; got != want {
		t.Fatalf("t1.5 = %s, want %s", got, want)
	}
	if got, want := timing.InterFrame(), 4010417*time.Nanosecond; got != want {
		t.Fatalf("t3.5 = %s, want %s", got, want)
	}
}

func TestRTUTimingAbove19200UsesFixedTimers(t *testing.T) {
	timing := rtuTestTiming(t, 115200)
	if timing.InterCharacter() != 750*time.Microsecond {
		t.Fatalf("t1.5 = %s", timing.InterCharacter())
	}
	if timing.InterFrame() != 1750*time.Microsecond {
		t.Fatalf("t3.5 = %s", timing.InterFrame())
	}
}

func TestRTUTimingIncreaseAllowedButBaselineReductionRejected(t *testing.T) {
	base := rtuTestTiming(t, 9600)
	config := RTUTimingConfig{
		Baud:                 9600,
		DataBits:             8,
		Parity:               RTUParityEven,
		StopBits:             1,
		InterCharacterSafety: base.InterCharacter() + time.Millisecond,
		InterFrameSafety:     base.InterFrame() + time.Millisecond,
		MaxResponseLatency:   20 * time.Millisecond,
		MaxQuiescence:        100 * time.Millisecond,
	}
	increased, err := NewRTUTiming(config)
	if err != nil {
		t.Fatal(err)
	}
	if increased.InterCharacter() != config.InterCharacterSafety ||
		increased.InterFrame() != config.InterFrameSafety {
		t.Fatal("configured safety increase not retained")
	}
	config.InterFrameSafety = base.InterFrame() - 1
	if _, err := NewRTUTiming(config); err == nil {
		t.Fatal("t3.5 baseline reduction accepted")
	}
	config.InterFrameSafety = 0
	config.InterCharacterSafety = base.InterFrame() + time.Nanosecond
	if _, err := NewRTUTiming(config); err == nil {
		t.Fatal("t1.5 greater than t3.5 accepted")
	}
}

func TestRTUTimingOverflowAndInvalidFormatFailClosed(t *testing.T) {
	valid := RTUTimingConfig{
		Baud:               9600,
		DataBits:           8,
		Parity:             RTUParityNone,
		StopBits:           1,
		MaxResponseLatency: time.Second,
		MaxQuiescence:      2 * time.Second,
	}
	for name, mutate := range map[string]func(*RTUTimingConfig){
		"zero_baud": func(config *RTUTimingConfig) {
			config.Baud = 0
		},
		"data_bits": func(config *RTUTimingConfig) {
			config.DataBits = 9
		},
		"parity": func(config *RTUTimingConfig) {
			config.Parity = RTUParity("invalid")
		},
		"stop_bits": func(config *RTUTimingConfig) {
			config.StopBits = 3
		},
		"latency": func(config *RTUTimingConfig) {
			config.MaxResponseLatency = 0
		},
		"quiescence": func(config *RTUTimingConfig) {
			config.MaxQuiescence = config.MaxResponseLatency
		},
	} {
		t.Run(name, func(t *testing.T) {
			config := valid
			mutate(&config)
			if _, err := NewRTUTiming(config); err == nil {
				t.Fatal("invalid RTU timing accepted")
			}
		})
	}
	timing := rtuTestTiming(t, 300)
	if _, err := timing.FrameTransmitHorizon(math.MaxInt); err == nil {
		t.Fatal("frame horizon overflow accepted")
	}
}

func TestRTUTransmitHorizonUsesFullFrameLength(t *testing.T) {
	timing := rtuTestTiming(t, 9600)
	short, err := timing.FrameTransmitHorizon(4)
	if err != nil {
		t.Fatal(err)
	}
	full, err := timing.FrameTransmitHorizon(MaxRTUADUSize)
	if err != nil {
		t.Fatal(err)
	}
	if full <= short {
		t.Fatalf("full horizon %s <= short horizon %s", full, short)
	}
}
