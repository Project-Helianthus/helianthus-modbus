package modbus

import (
	"bytes"
	"testing"
)

func TestU18NormalizationBufferOwnership(t *testing.T) {
	const original = " \n" + `{
  "schema_version" : 1,
  "source_kind" : "offline_fixture",
  "source_evidence_id" : "synthetic\/ownership",
  "documentary_notation" : "4\u0078xxx",
  "documentary_address" : 40071,
  "documentary_address_base" : "holding_reference_4xxxx",
  "function_code" : 3,
  "logical_table" : "holding_registers",
  "normalized_zero_based_pdu_offset" : 70,
  "word_count" : 1,
  "extension" : { "text" : "<tag>\u0026\"quoted\"", "items" : [1, 2] }
}` + "\n\t "
	wantFields := RuntimeNormalizationFields{
		SchemaVersion:                1,
		SourceKind:                   RuntimeAcquisitionSourceOfflineFixture,
		SourceEvidenceID:             "synthetic/ownership",
		DocumentaryNotation:          "4xxxx",
		DocumentaryAddress:           40071,
		DocumentaryAddressBase:       "holding_reference_4xxxx",
		FunctionCode:                 FunctionReadHoldingRegisters,
		LogicalTable:                 HoldingRegisters,
		NormalizedZeroBasedPDUOffset: 70,
		WordCount:                    1,
	}
	for _, callerBuffer := range []string{"parse_input", "bytes_result", "append_json_result", "append_json_nil_destination"} {
		t.Run(callerBuffer, func(t *testing.T) {
			// The oracle is detached before parsing or mutating any caller buffer.
			wantEncoding := []byte(original)
			input := bytes.Clone(wantEncoding)
			source := newRuntimeAcquisitionSourceForTest(t, &virtualTCPClock{})
			record, err := source.ParseNormalizationRecord(input)
			if err != nil {
				t.Fatalf("ParseNormalizationRecord: %v", err)
			}
			assertU18NormalizationOriginal(t, record, wantEncoding, wantFields)

			var mutable []byte
			switch callerBuffer {
			case "parse_input":
				mutable = input
			case "bytes_result":
				mutable = record.Bytes()
				if !bytes.Equal(mutable, wantEncoding) {
					t.Fatalf("Bytes before mutation = %q, want %q", mutable, wantEncoding)
				}
			case "append_json_result":
				mutable = appendU18NormalizationWithPrefix(t, record, wantEncoding)
			case "append_json_nil_destination":
				// The common call shape: an empty destination must still get a copy.
				appended, err := record.AppendJSON(nil)
				if err != nil {
					t.Fatalf("AppendJSON(nil): %v", err)
				}
				if !bytes.Equal(appended, wantEncoding) {
					t.Fatalf("AppendJSON(nil) = %q, want %q", appended, wantEncoding)
				}
				mutable = appended
			}
			// Overwrite once; independent cases cannot restore an alias accidentally.
			for i := range mutable {
				mutable[i] = '!'
			}
			assertU18NormalizationOriginal(t, record, wantEncoding, wantFields)
		})
	}
}

func assertU18NormalizationOriginal(t *testing.T, record RuntimeNormalizationRecord, wantEncoding []byte, wantFields RuntimeNormalizationFields) {
	t.Helper()
	if !record.Valid() {
		t.Fatal("record became invalid")
	}
	if got := record.Fields(); got != wantFields {
		t.Fatalf("Fields = %#v, want %#v", got, wantFields)
	}
	if got := record.Bytes(); !bytes.Equal(got, wantEncoding) {
		t.Fatalf("Bytes = %q, want exact original %q", got, wantEncoding)
	}
	appendU18NormalizationWithPrefix(t, record, wantEncoding)
}

func appendU18NormalizationWithPrefix(t *testing.T, record RuntimeNormalizationRecord, wantEncoding []byte) []byte {
	t.Helper()
	const prefix = "U18-prefix:"
	destination := make([]byte, len(prefix), len(prefix)+len(wantEncoding)+16)
	copy(destination, prefix)
	got, err := record.AppendJSON(destination)
	if err != nil {
		t.Fatalf("AppendJSON: %v", err)
	}
	if len(got) != len(prefix)+len(wantEncoding) {
		t.Fatalf("AppendJSON length = %d, want %d", len(got), len(prefix)+len(wantEncoding))
	}
	if string(got[:len(prefix)]) != prefix || string(destination) != prefix {
		t.Fatalf("AppendJSON changed prefix: result=%q destination=%q", got[:len(prefix)], destination)
	}
	if !bytes.Equal(got[len(prefix):], wantEncoding) {
		t.Fatalf("AppendJSON payload = %q, want exact original %q", got[len(prefix):], wantEncoding)
	}
	return got
}
