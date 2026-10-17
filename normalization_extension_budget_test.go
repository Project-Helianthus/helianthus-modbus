package modbus

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

type u16NormalizationClock struct{}

func (u16NormalizationClock) Now() time.Duration { return 0 }

func u16NormalizationConfig() RuntimeAcquisitionConfig {
	return RuntimeAcquisitionConfig{
		Limits: RuntimeAcquisitionLimits{
			MaxLiveCapabilities:                        1,
			MaxAttempts:                                1,
			MaxMembersPerAttempt:                       1,
			AttemptKeyMaxUTF8Bytes:                     8,
			SourceEvidenceIDMaxUTF8Bytes:               8,
			NormalizationRecordMaxEncodedBytes:         1024,
			NormalizationRequiredStringMaxUTF8Bytes:    32,
			NormalizationExtensionCountMax:             4,
			NormalizationExtensionKeyMaxUTF8Bytes:      16,
			NormalizationExtensionValueMaxEncodedBytes: 16,
			RetainedDiagnosticCountPerObjectMax:        1,
			RetainedDiagnosticMaxUTF8Bytes:             8,
			CapabilityTombstoneLimit:                   1,
			CapabilityTombstoneMaxEncodedBytes:         128,
		},
		ClaimLifetime: time.Second,
		Clock:         u16NormalizationClock{},
	}
}

func u16NormalizationJSON(extension string) []byte {
	return []byte(`{"schema_version":1,"source_kind":"offline_fixture",` +
		`"source_evidence_id":"fixture","documentary_notation":"4xxxx",` +
		`"documentary_address":40001,"documentary_address_base":"holding_reference_4xxxx",` +
		`"function_code":3,"logical_table":"holding_registers",` +
		`"normalized_zero_based_pdu_offset":0,"word_count":1,` + extension + `}`)
}

func u16NormalizationSource(t *testing.T, config RuntimeAcquisitionConfig) *RuntimeAcquisitionSource {
	t.Helper()
	source, err := NewRuntimeAcquisitionSource(config)
	if err != nil {
		t.Fatalf("NewRuntimeAcquisitionSource: %v", err)
	}
	return source
}

func u16CheckNormalization(t *testing.T, source *RuntimeAcquisitionSource, encoded []byte, accept bool) {
	t.Helper()
	if !json.Valid(encoded) {
		t.Fatal("fixture must remain valid JSON")
	}
	record, err := source.ParseNormalizationRecord(encoded)
	if accept {
		if err != nil || !record.Valid() {
			t.Fatalf("valid record rejected: valid=%v err=%v", record.Valid(), err)
		}
		if !bytes.Equal(record.Bytes(), encoded) {
			t.Fatalf("unknown extension encoding changed: got %q want %q", record.Bytes(), encoded)
		}
	} else if !errors.Is(err, ErrRuntimeNormalization) || record.Valid() || len(record.Bytes()) != 0 {
		t.Fatalf("over-budget record retained: valid=%v bytes=%q err=%v", record.Valid(), record.Bytes(), err)
	}
}

func TestU16NormalizationExtensionBudgets(t *testing.T) {
	for _, tc := range []struct {
		name     string
		exact    string
		over     string
		setLimit func(*RuntimeAcquisitionLimits, int)
		limit    int
	}{
		{
			name: "count", exact: `"a":0`, over: `"a":0,"b":0`, limit: 1,
			setLimit: func(l *RuntimeAcquisitionLimits, n int) { l.NormalizationExtensionCountMax = n },
		},
		{
			name: "utf8_key_bytes", exact: `"éa":0`, over: `"éab":0`, limit: 3,
			setLimit: func(l *RuntimeAcquisitionLimits, n int) { l.NormalizationExtensionKeyMaxUTF8Bytes = n },
		},
		{
			name: "encoded_value_bytes", exact: `"a":"a\n"`, over: `"a":"ab\n"`, limit: 5,
			setLimit: func(l *RuntimeAcquisitionLimits, n int) { l.NormalizationExtensionValueMaxEncodedBytes = n },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := u16NormalizationConfig()
			tc.setLimit(&config.Limits, tc.limit)
			source := u16NormalizationSource(t, config)
			for _, boundary := range []struct {
				name      string
				extension string
				accept    bool
			}{
				{"exact_limit", tc.exact, true},
				{"one_over", tc.over, false},
			} {
				t.Run(boundary.name, func(t *testing.T) {
					encoded := u16NormalizationJSON(boundary.extension)
					u16CheckNormalization(t, source, encoded, boundary.accept)
					// The public parser repeats the count guard. Check the decoder
					// independently so that repetition cannot mask its removal.
					_, _, err := source.decodeNormalizationObject(encoded)
					if boundary.accept && err != nil {
						t.Fatalf("decoder rejected exact limit: %v", err)
					}
					if !boundary.accept && !errors.Is(err, ErrRuntimeNormalization) {
						t.Fatalf("decoder accepted one-over extension: %v", err)
					}
				})
			}
			t.Run("one_over_with_only_target_cap_relaxed", func(t *testing.T) {
				tc.setLimit(&config.Limits, tc.limit+1)
				u16CheckNormalization(t, u16NormalizationSource(t, config), u16NormalizationJSON(tc.over), true)
			})
		})
	}
}

func TestU16NormalizationRecordByteBudget(t *testing.T) {
	encoded := append(u16NormalizationJSON(`"éa" : "a\n"`), []byte(" \n\t")...)
	config := u16NormalizationConfig()
	config.Limits.NormalizationRecordMaxEncodedBytes = len(encoded)
	source := u16NormalizationSource(t, config)
	t.Run("exact_limit", func(t *testing.T) {
		u16CheckNormalization(t, source, encoded, true)
	})
	over := append(bytes.Clone(encoded), ' ')
	t.Run("one_over", func(t *testing.T) {
		u16CheckNormalization(t, source, over, false)
	})
	t.Run("one_over_with_only_target_cap_relaxed", func(t *testing.T) {
		config.Limits.NormalizationRecordMaxEncodedBytes++
		u16CheckNormalization(t, u16NormalizationSource(t, config), over, true)
	})
}
