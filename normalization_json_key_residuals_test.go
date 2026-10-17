package modbus

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// The complete synthetic core keeps rejection independent of missing fields.
const u17NormalizationCore = `"schema_version":1,"source_kind":"offline_fixture","source_evidence_id":"synthetic-u17","documentary_notation":"4xxxx","documentary_address":40001,"documentary_address_base":"holding_reference_4xxxx","function_code":3,"logical_table":"holding_registers","normalized_zero_based_pdu_offset":0,"word_count":1`

func TestU17EscapedDuplicateNormalizationKeys(t *testing.T) {
	members := strings.Split(u17NormalizationCore, ",")
	members = append(members, `"extension":{"note":"synthetic"}`)
	for _, member := range members {
		keyEnd := strings.Index(member[1:], `"`) + 1
		key := member[1:keyEnd]
		escaped := `"` + fmt.Sprintf(`\u%04x`, member[1]) + member[2:]
		core := u17NormalizationCore
		if key == "extension" {
			core += "," + member
		}
		for _, before := range []bool{true, false} {
			order := "escaped_after"
			replacement := member + "," + escaped
			if before {
				order = "escaped_before"
				replacement = escaped + "," + member
			}
			t.Run(key+"/"+order, func(t *testing.T) {
				source := newRuntimeAcquisitionSourceForTest(t, &virtualTCPClock{})
				// Admit the escaped spelling alone to exclude a malformed-key oracle.
				control := []byte("{" + strings.Replace(core, member, escaped, 1) + "}")
				if record, err := source.ParseNormalizationRecord(control); err != nil || !record.Valid() || !bytes.Equal(record.Bytes(), control) {
					t.Fatalf("single escaped key rejected or rewritten: record=%v err=%v", record.Valid(), err)
				}
				encoded := []byte("{" + strings.Replace(core, member, replacement, 1) + "}")
				u17AssertNormalizationRejected(t, source, encoded)
				// Extension-count consistency can also reject duplicate extensions;
				// check the object decoder itself to pin its decoded-key guard.
				if _, _, err := source.decodeNormalizationObject(encoded); !errors.Is(err, ErrRuntimeNormalization) {
					t.Fatalf("object decoder accepted duplicate decoded key: %v", err)
				}
			})
		}
	}
}

func TestU17NormalizationTrailingTokens(t *testing.T) {
	valid := "{" + u17NormalizationCore + "}"
	t.Run("trailing_whitespace", func(t *testing.T) {
		source := newRuntimeAcquisitionSourceForTest(t, &virtualTCPClock{})
		encoded := []byte(valid + " \t\r\n")
		record, err := source.ParseNormalizationRecord(encoded)
		want := RuntimeNormalizationFields{
			SchemaVersion: 1, SourceKind: RuntimeAcquisitionSourceOfflineFixture,
			SourceEvidenceID: "synthetic-u17", DocumentaryNotation: "4xxxx",
			DocumentaryAddress: 40001, DocumentaryAddressBase: "holding_reference_4xxxx",
			FunctionCode: FunctionReadHoldingRegisters, LogicalTable: HoldingRegisters,
			NormalizedZeroBasedPDUOffset: 0, WordCount: 1,
		}
		if err != nil || !record.Valid() || !bytes.Equal(record.Bytes(), encoded) || record.Fields() != want {
			t.Fatalf("whitespace control: valid=%v fields=%+v err=%v", record.Valid(), record.Fields(), err)
		}
	})
	t.Run("second_value_null", func(t *testing.T) {
		source := newRuntimeAcquisitionSourceForTest(t, &virtualTCPClock{})
		u17AssertNormalizationRejected(t, source, []byte(valid+" \nnull"))
	})
}

func u17AssertNormalizationRejected(t *testing.T, source *RuntimeAcquisitionSource, encoded []byte) {
	t.Helper()
	valid := []byte("{" + u17NormalizationCore + `,"retained":{"note":"last-known-good"}}`)
	retained, err := source.ParseNormalizationRecord(valid)
	if err != nil {
		t.Fatalf("retained record setup: %v", err)
	}
	fieldsBefore := retained.Fields()
	attempt, err := source.BeginAttempt("synthetic-u17-open")
	if err != nil {
		t.Fatalf("open attempt setup: %v", err)
	}
	before := source.Snapshot() // Snapshot copies its slice; no aliased before-state.
	inputBefore := append([]byte(nil), encoded...)
	rejected, err := source.ParseNormalizationRecord(encoded)
	if !errors.Is(err, ErrRuntimeNormalization) || !reflect.DeepEqual(rejected, RuntimeNormalizationRecord{}) {
		t.Errorf("expected normalization error and zero record: record=%+v err=%v", rejected, err)
	}
	if !bytes.Equal(encoded, inputBefore) {
		t.Error("rejection changed caller input")
	}
	if !reflect.DeepEqual(source.Snapshot(), before) {
		t.Error("rejection changed source resource state")
	}
	if source.retired || source.attempts[attempt.token] == nil || source.attempts[attempt.token].phase != runtimeAttemptOpen {
		t.Error("rejection retired source or changed the existing open attempt")
	}
	if !retained.Valid() || retained.owner != source || !bytes.Equal(retained.Bytes(), valid) || retained.Fields() != fieldsBefore {
		t.Error("rejection changed last-known-good normalization")
	}
	if record, err := source.ParseNormalizationRecord(valid); err != nil || !record.Valid() || !bytes.Equal(record.Bytes(), valid) {
		t.Errorf("source no longer admits valid normalization after rejection: %v", err)
	}
}
