package modbus

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
)

const normalizationTrailingJunkDocument = `{"schema_version":1,"source_kind":"offline_fixture","source_evidence_id":"synthetic-trailing-junk","documentary_notation":"4xxxx","documentary_address":40001,"documentary_address_base":"holding_reference_4xxxx","function_code":3,"logical_table":"holding_registers","normalized_zero_based_pdu_offset":0,"word_count":1}`

func normalizationTrailingJunkFields() RuntimeNormalizationFields {
	return RuntimeNormalizationFields{
		SchemaVersion: 1, SourceKind: RuntimeAcquisitionSourceOfflineFixture,
		SourceEvidenceID: "synthetic-trailing-junk", DocumentaryNotation: "4xxxx",
		DocumentaryAddress: 40001, DocumentaryAddressBase: "holding_reference_4xxxx",
		FunctionCode: FunctionReadHoldingRegisters, LogicalTable: HoldingRegisters,
		NormalizedZeroBasedPDUOffset: 0, WordCount: 1,
	}
}

func TestNormalizationTrailingJunkControls(t *testing.T) {
	for _, control := range []struct {
		name   string
		suffix string
	}{
		{"original", ""},
		{"whitespace_only", " \t\r\n"},
	} {
		t.Run(control.name, func(t *testing.T) {
			source := newRuntimeAcquisitionSourceForTest(t, &virtualTCPClock{})
			input := []byte(normalizationTrailingJunkDocument + control.suffix)
			before := bytes.Clone(input)
			values, extensions, err := source.decodeNormalizationObject(input)
			if err != nil || len(values) != 10 || extensions != 0 {
				t.Fatalf("object control: fields=%d extensions=%d err=%v", len(values), extensions, err)
			}
			record, err := source.ParseNormalizationRecord(input)
			if err != nil {
				t.Fatalf("parse control: %v", err)
			}
			normalizationTrailingJunkAssertRecord(t, source, record, before)
			if !bytes.Equal(input, before) {
				t.Error("control changed caller input")
			}
		})
	}
}

func TestNormalizationTrailingJunkRejected(t *testing.T) {
	for _, suffix := range []struct {
		name  string
		bytes string
	}{
		{"invalid_token", "x"},
		{"unmatched_brace", "}"},
		{"truncated_json", `{"unfinished":`},
	} {
		for _, whitespace := range []struct {
			name  string
			bytes string
		}{
			{"adjacent", ""},
			{"after_whitespace", " \t\r\n"},
		} {
			for _, seam := range []string{"parse", "object_decoder"} {
				t.Run(suffix.name+"/"+whitespace.name+"/"+seam, func(t *testing.T) {
					source := newRuntimeAcquisitionSourceForTest(t, &virtualTCPClock{})
					priorBytes := []byte(normalizationTrailingJunkDocument)
					prior, err := source.ParseNormalizationRecord(bytes.Clone(priorBytes))
					if err != nil {
						t.Fatalf("prior record setup: %v", err)
					}
					attempt, err := source.BeginAttempt("synthetic-trailing-junk-open")
					if err != nil {
						t.Fatalf("open attempt setup: %v", err)
					}
					before := source.Snapshot()
					before.Tombstones = append([]RuntimeCapabilityTombstone(nil), before.Tombstones...)
					input := []byte(normalizationTrailingJunkDocument + whitespace.bytes + suffix.bytes)
					inputBefore := bytes.Clone(input)
					if seam == "parse" {
						record, err := source.ParseNormalizationRecord(input)
						if !errors.Is(err, ErrRuntimeNormalization) || !reflect.DeepEqual(record, RuntimeNormalizationRecord{}) {
							t.Errorf("malformed suffix: want normalization error and zero record, got record=%+v err=%v", record, err)
						}
					} else {
						values, extensions, err := source.decodeNormalizationObject(input)
						if !errors.Is(err, ErrRuntimeNormalization) || values != nil || extensions != 0 {
							t.Errorf("malformed suffix: want normalization error and empty object result, got fields=%d extensions=%d err=%v", len(values), extensions, err)
						}
					}
					if !bytes.Equal(input, inputBefore) {
						t.Error("rejection changed caller input")
					}
					if !reflect.DeepEqual(source.Snapshot(), before) {
						t.Error("rejection changed detached source snapshot")
					}
					state := source.attempts[attempt.token]
					if source.retired || attempt.token.source.Load() != source || state == nil || state.phase != runtimeAttemptOpen {
						t.Error("rejection retired source or invalidated the existing open attempt")
					}
					normalizationTrailingJunkAssertRecord(t, source, prior, priorBytes)
					successorBytes := []byte(normalizationTrailingJunkDocument + "\n")
					successor, err := source.ParseNormalizationRecord(bytes.Clone(successorBytes))
					if err != nil {
						t.Fatalf("valid successor after rejection: %v", err)
					}
					normalizationTrailingJunkAssertRecord(t, source, successor, successorBytes)
				})
			}
		}
	}
}

func normalizationTrailingJunkAssertRecord(t *testing.T, source *RuntimeAcquisitionSource, record RuntimeNormalizationRecord, wantBytes []byte) {
	t.Helper()
	if !record.Valid() || record.owner != source || !bytes.Equal(record.Bytes(), wantBytes) || record.Fields() != normalizationTrailingJunkFields() {
		t.Errorf("record lost native bytes or required fields: valid=%v fields=%+v", record.Valid(), record.Fields())
	}
	appended, err := record.AppendJSON(nil)
	if err != nil || !bytes.Equal(appended, wantBytes) {
		t.Errorf("record no longer readable through AppendJSON: err=%v", err)
	}
}
