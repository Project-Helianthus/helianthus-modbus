package modbus

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"
)

// RuntimeAcquisitionSourceKind is the closed V1 trust-source enum.
type RuntimeAcquisitionSourceKind string

const (
	RuntimeAcquisitionSourceRuntime        RuntimeAcquisitionSourceKind = "runtime"
	RuntimeAcquisitionSourceOfflineFixture RuntimeAcquisitionSourceKind = "offline_fixture"
)

// RuntimeNormalizationFields are the ten required V1 documentary fields.
type RuntimeNormalizationFields struct {
	SchemaVersion                int
	SourceKind                   RuntimeAcquisitionSourceKind
	SourceEvidenceID             string
	DocumentaryNotation          string
	DocumentaryAddress           uint32
	DocumentaryAddressBase       string
	FunctionCode                 FunctionCode
	LogicalTable                 LogicalTable
	NormalizedZeroBasedPDUOffset uint16
	WordCount                    uint16
}

// RuntimeNormalizationRecord retains the exact admitted JSON bytes. Unknown
// extension fields therefore round-trip without rewriting or truncation.
type RuntimeNormalizationRecord struct {
	owner   *RuntimeAcquisitionSource
	encoded []byte
	fields  RuntimeNormalizationFields
}

var runtimeNormalizationRequiredFields = map[string]struct{}{
	"schema_version":                   {},
	"source_kind":                      {},
	"source_evidence_id":               {},
	"documentary_notation":             {},
	"documentary_address":              {},
	"documentary_address_base":         {},
	"function_code":                    {},
	"logical_table":                    {},
	"normalized_zero_based_pdu_offset": {},
	"word_count":                       {},
}

// ParseNormalizationRecord validates before retaining any caller-owned tree.
func (source *RuntimeAcquisitionSource) ParseNormalizationRecord(
	encoded []byte,
) (RuntimeNormalizationRecord, error) {
	if source == nil {
		return RuntimeNormalizationRecord{}, ErrRuntimeNormalization
	}
	source.mu.Lock()
	retired := source.retired
	source.mu.Unlock()
	if retired {
		return RuntimeNormalizationRecord{}, ErrRuntimeAcquisitionUnavailable
	}
	if len(encoded) == 0 ||
		len(encoded) > source.config.Limits.NormalizationRecordMaxEncodedBytes ||
		!utf8.Valid(encoded) {
		return RuntimeNormalizationRecord{}, ErrRuntimeNormalization
	}
	values, extensionCount, err := source.decodeNormalizationObject(encoded)
	if err != nil {
		return RuntimeNormalizationRecord{}, err
	}
	if len(values) != len(runtimeNormalizationRequiredFields)+extensionCount ||
		extensionCount > source.config.Limits.NormalizationExtensionCountMax {
		return RuntimeNormalizationRecord{}, ErrRuntimeNormalization
	}
	fields, err := source.decodeNormalizationFields(values)
	if err != nil {
		return RuntimeNormalizationRecord{}, err
	}
	retained := append([]byte(nil), encoded...)
	if hook := source.beforeNormalizationPublish; hook != nil {
		hook()
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	if source.retired {
		return RuntimeNormalizationRecord{}, ErrRuntimeAcquisitionUnavailable
	}
	return RuntimeNormalizationRecord{
		owner:   source,
		encoded: retained,
		fields:  fields,
	}, nil
}

func (source *RuntimeAcquisitionSource) decodeNormalizationObject(
	encoded []byte,
) (map[string]json.RawMessage, int, error) {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	token, err := decoder.Token()
	if err != nil {
		return nil, 0, ErrRuntimeNormalization
	}
	delimiter, ok := token.(json.Delim)
	if !ok || delimiter != '{' {
		return nil, 0, ErrRuntimeNormalization
	}
	values := make(map[string]json.RawMessage)
	extensions := 0
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return nil, 0, ErrRuntimeNormalization
		}
		key, ok := keyToken.(string)
		if !ok || key == "" || !utf8.ValidString(key) {
			return nil, 0, ErrRuntimeNormalization
		}
		if _, duplicate := values[key]; duplicate {
			return nil, 0, ErrRuntimeNormalization
		}
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			return nil, 0, ErrRuntimeNormalization
		}
		if _, required := runtimeNormalizationRequiredFields[key]; !required {
			extensions++
			if extensions > source.config.Limits.NormalizationExtensionCountMax ||
				len(key) > source.config.Limits.NormalizationExtensionKeyMaxUTF8Bytes ||
				len(raw) > source.config.Limits.NormalizationExtensionValueMaxEncodedBytes {
				return nil, 0, ErrRuntimeNormalization
			}
		}
		values[key] = append(json.RawMessage(nil), raw...)
	}
	token, err = decoder.Token()
	if err != nil || token != json.Delim('}') {
		return nil, 0, ErrRuntimeNormalization
	}
	if token, err = decoder.Token(); !errors.Is(err, io.EOF) || token != nil {
		return nil, 0, ErrRuntimeNormalization
	}
	return values, extensions, nil
}

func (source *RuntimeAcquisitionSource) decodeNormalizationFields(
	values map[string]json.RawMessage,
) (RuntimeNormalizationFields, error) {
	for required := range runtimeNormalizationRequiredFields {
		if _, exists := values[required]; !exists {
			return RuntimeNormalizationFields{}, ErrRuntimeNormalization
		}
	}
	var fields RuntimeNormalizationFields
	if err := decodeRuntimeNormalizationNumber(
		values["schema_version"],
		&fields.SchemaVersion,
	); err != nil || fields.SchemaVersion != 1 {
		return RuntimeNormalizationFields{}, ErrRuntimeNormalization
	}
	if err := decodeRuntimeNormalizationString(
		values["source_kind"],
		&fields.SourceKind,
	); err != nil {
		return RuntimeNormalizationFields{}, ErrRuntimeNormalization
	}
	switch fields.SourceKind {
	case RuntimeAcquisitionSourceRuntime,
		RuntimeAcquisitionSourceOfflineFixture:
	default:
		return RuntimeNormalizationFields{}, ErrRuntimeNormalization
	}
	strings := []struct {
		raw         json.RawMessage
		destination *string
		max         int
	}{
		{
			raw:         values["source_evidence_id"],
			destination: &fields.SourceEvidenceID,
			max:         source.config.Limits.SourceEvidenceIDMaxUTF8Bytes,
		},
		{
			raw:         values["documentary_notation"],
			destination: &fields.DocumentaryNotation,
			max: source.config.Limits.
				NormalizationRequiredStringMaxUTF8Bytes,
		},
		{
			raw:         values["documentary_address_base"],
			destination: &fields.DocumentaryAddressBase,
			max: source.config.Limits.
				NormalizationRequiredStringMaxUTF8Bytes,
		},
	}
	for _, field := range strings {
		if err := decodeRuntimeNormalizationString(
			field.raw,
			field.destination,
		); err != nil || *field.destination == "" ||
			!utf8.ValidString(*field.destination) ||
			len(*field.destination) > field.max {
			return RuntimeNormalizationFields{}, ErrRuntimeNormalization
		}
	}
	if err := decodeRuntimeNormalizationNumber(
		values["documentary_address"],
		&fields.DocumentaryAddress,
	); err != nil {
		return RuntimeNormalizationFields{}, ErrRuntimeNormalization
	}
	var function uint8
	if err := decodeRuntimeNormalizationNumber(
		values["function_code"],
		&function,
	); err != nil {
		return RuntimeNormalizationFields{}, ErrRuntimeNormalization
	}
	fields.FunctionCode = FunctionCode(function)
	if err := decodeRuntimeNormalizationString(
		values["logical_table"],
		&fields.LogicalTable,
	); err != nil || !utf8.ValidString(string(fields.LogicalTable)) {
		return RuntimeNormalizationFields{}, ErrRuntimeNormalization
	}
	if err := decodeRuntimeNormalizationNumber(
		values["normalized_zero_based_pdu_offset"],
		&fields.NormalizedZeroBasedPDUOffset,
	); err != nil {
		return RuntimeNormalizationFields{}, ErrRuntimeNormalization
	}
	if err := decodeRuntimeNormalizationNumber(
		values["word_count"],
		&fields.WordCount,
	); err != nil || fields.WordCount == 0 ||
		fields.WordCount > MaxReadRegisters {
		return RuntimeNormalizationFields{}, ErrRuntimeNormalization
	}
	end := uint32(fields.NormalizedZeroBasedPDUOffset) +
		uint32(fields.WordCount)
	if end > 1<<16 {
		return RuntimeNormalizationFields{}, ErrRuntimeNormalization
	}
	switch fields.FunctionCode {
	case FunctionReadHoldingRegisters:
		if fields.LogicalTable != HoldingRegisters {
			return RuntimeNormalizationFields{}, ErrRuntimeNormalization
		}
	case FunctionReadInputRegisters:
		if fields.LogicalTable != InputRegisters {
			return RuntimeNormalizationFields{}, ErrRuntimeNormalization
		}
	default:
		return RuntimeNormalizationFields{}, ErrRuntimeNormalization
	}
	return fields, nil
}

func decodeRuntimeNormalizationString(
	raw json.RawMessage,
	destination any,
) error {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '"' {
		return ErrRuntimeNormalization
	}
	return decodeRuntimeNormalizationValue(trimmed, destination)
}

func decodeRuntimeNormalizationNumber(
	raw json.RawMessage,
	destination any,
) error {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 ||
		(trimmed[0] != '-' && (trimmed[0] < '0' || trimmed[0] > '9')) {
		return ErrRuntimeNormalization
	}
	return decodeRuntimeNormalizationValue(trimmed, destination)
}

func decodeRuntimeNormalizationValue(
	raw json.RawMessage,
	destination any,
) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(destination); err != nil {
		return ErrRuntimeNormalization
	}
	if token, err := decoder.Token(); !errors.Is(err, io.EOF) || token != nil {
		return ErrRuntimeNormalization
	}
	return nil
}

// Valid reports whether the record passed one source's bounded parser.
func (record RuntimeNormalizationRecord) Valid() bool {
	return record.owner != nil && len(record.encoded) != 0
}

// Bytes returns the exact admitted encoding.
func (record RuntimeNormalizationRecord) Bytes() []byte {
	return append([]byte(nil), record.encoded...)
}

// AppendJSON appends the exact admitted encoding without compaction, key
// reordering, escape rewriting, or HTML escaping.
func (record RuntimeNormalizationRecord) AppendJSON(destination []byte) (
	[]byte,
	error,
) {
	if !record.Valid() {
		return nil, ErrRuntimeNormalization
	}
	return append(destination, record.encoded...), nil
}

// Fields returns the parsed required fields without unknown-field loss.
func (record RuntimeNormalizationRecord) Fields() RuntimeNormalizationFields {
	return record.fields
}

// MarshalJSON rejects encoding/json because it compacts Marshaler output and
// may HTML-escape it. Call Bytes or AppendJSON for exact serialization.
func (record RuntimeNormalizationRecord) MarshalJSON() ([]byte, error) {
	return nil, ErrRuntimeNormalization
}
