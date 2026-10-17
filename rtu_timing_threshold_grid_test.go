package modbus

import (
	"fmt"
	"testing"
	"time"
)

func TestS24RTUTimingThresholdGrid(t *testing.T) {
	// Explicit nanosecond expectations use ceil(bits * 1e9 / baud),
	// ceil(bits * 3e9 / (2 * baud)), and ceil(bits * 7e9 / (2 * baud)).
	// Round each rational independently; do not multiply rounded character time.
	// Columns correspond to 10, 11, and 12 bits per character respectively.
	grid := []struct {
		baud      uint32
		character [3]time.Duration
		t15       [3]time.Duration
		t35       [3]time.Duration
	}{
		{19199, [3]time.Duration{520861, 572947, 625033},
			[3]time.Duration{781291, 859420, 937549},
			[3]time.Duration{1823012, 2005313, 2187614}},
		{19200, [3]time.Duration{520834, 572917, 625000},
			[3]time.Duration{781250, 859375, 937500},
			[3]time.Duration{1822917, 2005209, 2187500}},
		{19201, [3]time.Duration{520807, 572887, 624968},
			[3]time.Duration{750000, 750000, 750000},
			[3]time.Duration{1750000, 1750000, 1750000}},
	}
	formats := []struct {
		parity RTUParity
		stops  uint8
		column int
	}{
		{RTUParityNone, 1, 0},
		{RTUParityNone, 2, 1},
		{RTUParityEven, 1, 1},
		{RTUParityEven, 2, 2},
		{RTUParityOdd, 1, 1},
		{RTUParityOdd, 2, 2},
	}
	for _, row := range grid {
		for _, format := range formats {
			t.Run(fmt.Sprintf("baud_%d/%s/stop_%d", row.baud, format.parity, format.stops), func(t *testing.T) {
				timing, err := NewRTUTiming(RTUTimingConfig{
					Baud:               row.baud,
					DataBits:           8,
					Parity:             format.parity,
					StopBits:           format.stops,
					MaxResponseLatency: 20 * time.Millisecond,
					MaxQuiescence:      100 * time.Millisecond,
				})
				if err != nil {
					t.Fatal(err)
				}
				wantCharacter := row.character[format.column]
				if got := timing.CharacterTime(); got != wantCharacter {
					t.Errorf("character time = %s, want %s", got, wantCharacter)
				}
				if got, want := timing.InterCharacter(), row.t15[format.column]; got != want {
					t.Errorf("t1.5 = %s, want %s", got, want)
				}
				if got, want := timing.InterFrame(), row.t35[format.column]; got != want {
					t.Errorf("t3.5 = %s, want %s", got, want)
				}
				for _, length := range []int{1, MaxRTUADUSize} {
					t.Run(fmt.Sprintf("horizon_%d", length), func(t *testing.T) {
						got, err := timing.FrameTransmitHorizon(length)
						if err != nil {
							t.Fatal(err)
						}
						if want := time.Duration(length) * wantCharacter; got != want {
							t.Errorf("horizon = %s, want %s", got, want)
						}
					})
				}
				for _, length := range []int{-1, 0, MaxRTUADUSize + 1} {
					t.Run(fmt.Sprintf("invalid_horizon_%d", length), func(t *testing.T) {
						got, err := timing.FrameTransmitHorizon(length)
						if err == nil || got != 0 {
							t.Errorf("invalid horizon = (%s, %v), want zero and error", got, err)
						}
					})
				}
			})
		}
	}
}
