package modbus

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"sync"
	"testing"
	"time"
)

func runtimeAcquisitionConfigForTest(
	clock RuntimeAcquisitionClock,
) RuntimeAcquisitionConfig {
	return RuntimeAcquisitionConfig{
		Limits: RuntimeAcquisitionLimits{
			MaxLiveCapabilities:                        8,
			MaxAttempts:                                8,
			MaxMembersPerAttempt:                       4,
			AttemptKeyMaxUTF8Bytes:                     64,
			SourceEvidenceIDMaxUTF8Bytes:               128,
			NormalizationRecordMaxEncodedBytes:         2048,
			NormalizationRequiredStringMaxUTF8Bytes:    128,
			NormalizationExtensionCountMax:             4,
			NormalizationExtensionKeyMaxUTF8Bytes:      64,
			NormalizationExtensionValueMaxEncodedBytes: 256,
			RetainedDiagnosticCountPerObjectMax:        4,
			RetainedDiagnosticMaxUTF8Bytes:             128,
			CapabilityTombstoneLimit:                   8,
			CapabilityTombstoneMaxEncodedBytes:         128,
		},
		ClaimLifetime: time.Minute,
		Clock:         clock,
	}
}

func newRuntimeAcquisitionSourceForTest(
	t *testing.T,
	clock RuntimeAcquisitionClock,
) *RuntimeAcquisitionSource {
	t.Helper()
	source, err := NewRuntimeAcquisitionSource(
		runtimeAcquisitionConfigForTest(clock),
	)
	if err != nil {
		t.Fatalf("NewRuntimeAcquisitionSource: %v", err)
	}
	return source
}

type runtimeReadForTest struct {
	logicalViewID uint64
	offset        uint16
	quantity      uint16
}

func runtimeSuccessfulViewsForTest(
	t *testing.T,
	source *RuntimeAcquisitionSource,
	clock *virtualTCPClock,
	reads []runtimeReadForTest,
	words []uint16,
) []LogicalReadView {
	t.Helper()
	config := endpointConfigForTest(clock, nil)
	config.RuntimeAcquisitionSource = source
	endpoint, err := NewTCPEndpoint(config)
	if err != nil {
		t.Fatalf("NewTCPEndpoint: %v", err)
	}
	defer func() {
		if err := endpoint.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	}()
	client, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	connection, err := endpoint.openTestConnection(client)
	if err != nil {
		t.Fatalf("openTestConnection: %v", err)
	}
	logicalReads := make([]TCPLogicalRead, 0, len(reads))
	for _, read := range reads {
		request, err := NewReadRegistersRequest(
			FunctionReadHoldingRegisters,
			read.offset,
			read.quantity,
		)
		if err != nil {
			t.Fatalf("NewReadRegistersRequest: %v", err)
		}
		logicalReads = append(logicalReads, TCPLogicalRead{
			LogicalViewID: read.logicalViewID,
			Request:       request,
		})
	}
	_, err = endpoint.EnqueueRead(TCPReadPlan{
		Connection:         connection,
		UnitID:             1,
		AuthorizationScope: "runtime-acquisition-test",
		PollGeneration:     7,
		DeadlineIdentity:   9,
		Timeout:            time.Second,
		Reads:              logicalReads,
	})
	if err != nil {
		t.Fatalf("EnqueueRead: %v", err)
	}
	dispatch, ok := endpoint.Dispatch()
	if !ok {
		t.Fatal("runtime read was not dispatched")
	}
	requestADU := endpointWriteOne(t, endpoint, dispatch, peer)
	responseADU := []byte{
		requestADU[0], requestADU[1], 0, 0,
		0, byte(3 + len(words)*2), 1,
		byte(FunctionReadHoldingRegisters), byte(len(words) * 2),
	}
	for _, word := range words {
		responseADU = append(responseADU, byte(word>>8), byte(word))
	}
	sent := endpointSendFrame(peer, responseADU)
	batch, err := endpoint.Read(t.Context(), connection)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if err := <-sent; err != nil {
		t.Fatalf("send response: %v", err)
	}
	if len(batch.Views) != len(reads) {
		t.Fatalf("runtime views=%d want=%d", len(batch.Views), len(reads))
	}
	return batch.Views
}

func runtimeNormalizationForTest(
	t *testing.T,
	source *RuntimeAcquisitionSource,
	sourceKind RuntimeAcquisitionSourceKind,
	evidenceID string,
	offset uint16,
	wordCount uint16,
	extension string,
) RuntimeNormalizationRecord {
	t.Helper()
	encoded := []byte(fmt.Sprintf(
		`{"schema_version":1,"source_kind":%q,"source_evidence_id":%q,`+
			`"documentary_notation":"4xxxx","documentary_address":%d,`+
			`"documentary_address_base":"holding_reference_4xxxx",`+
			`"function_code":3,"logical_table":"holding_registers",`+
			`"normalized_zero_based_pdu_offset":%d,"word_count":%d%s}`,
		sourceKind,
		evidenceID,
		40001+uint32(offset),
		offset,
		wordCount,
		extension,
	))
	record, err := source.ParseNormalizationRecord(encoded)
	if err != nil {
		t.Fatalf("ParseNormalizationRecord: %v\n%s", err, encoded)
	}
	if !bytes.Equal(record.Bytes(), encoded) {
		t.Fatalf("normalization bytes changed:\n got %s\nwant %s", record.Bytes(), encoded)
	}
	return record
}

func issueRuntimeAcquisitionForTest(
	t *testing.T,
	source *RuntimeAcquisitionSource,
	attempt *RuntimeAttempt,
	view LogicalReadView,
	evidenceID string,
) RuntimeAcquisition {
	t.Helper()
	record := runtimeNormalizationForTest(
		t,
		source,
		RuntimeAcquisitionSourceRuntime,
		evidenceID,
		view.LogicalOffset(),
		view.LogicalWordCount(),
		`,"future_extension":{"z":[3,2,1],"raw":"kept"}`,
	)
	acquisition, err := source.Issue(attempt, view, record)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return acquisition
}

func TestM106RuntimeOnlyIssuanceAndLosslessProvenance(t *testing.T) {
	clock := &virtualTCPClock{}
	source := newRuntimeAcquisitionSourceForTest(t, clock)
	view := runtimeSuccessfulViewsForTest(
		t,
		source,
		clock,
		[]runtimeReadForTest{{logicalViewID: 101, offset: 10, quantity: 2}},
		[]uint16{0x0102, 0x0304},
	)[0]
	attempt, err := source.BeginAttempt("attempt-runtime-1")
	if err != nil {
		t.Fatalf("BeginAttempt: %v", err)
	}
	normalization := runtimeNormalizationForTest(
		t,
		source,
		RuntimeAcquisitionSourceRuntime,
		"urn:helianthus:evidence:runtime-1",
		10,
		2,
		`,"unknown":{"preserve":[1,2,3]}`,
	)
	acquisition, err := source.Issue(attempt, view, normalization)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if acquisition.AttemptKey() != "attempt-runtime-1" {
		t.Fatalf("attempt key=%q", acquisition.AttemptKey())
	}
	provenance := acquisition.Provenance()
	if provenance.SourceKind != RuntimeAcquisitionSourceRuntime ||
		provenance.SourceEvidenceID != "urn:helianthus:evidence:runtime-1" ||
		provenance.LogicalViewID != 101 ||
		provenance.WireResponseID == 0 ||
		provenance.PhysicalRequestID == 0 ||
		provenance.Transport != TransportTCP ||
		provenance.LogicalOffset != 10 ||
		provenance.LogicalWordCount != 2 ||
		!bytes.Equal(provenance.WireResponseBytes, []byte{
			0, 0, 0, 0, 0, 7, 1, 3, 4, 1, 2, 3, 4,
		}) ||
		len(provenance.Words) != 2 ||
		provenance.Words[0] != 0x0102 || provenance.Words[1] != 0x0304 {
		t.Fatalf("provenance=%#v", provenance)
	}
	provenance.Words[0] = 0
	if acquisition.Provenance().Words[0] != 0x0102 {
		t.Fatal("caller mutated retained provenance")
	}
	encoded, err := json.Marshal(acquisition.Normalization())
	if err != nil {
		t.Fatalf("Marshal normalization: %v", err)
	}
	if !bytes.Equal(encoded, normalization.Bytes()) {
		t.Fatalf("normalization round trip changed:\n got %s\nwant %s", encoded, normalization.Bytes())
	}
	instance, err := attempt.Close([]RuntimeAcquisition{acquisition})
	if err != nil {
		t.Fatalf("Close: %v", err)
	}
	claim, err := acquisition.Capability().Claim(instance)
	if err != nil || !claim.Won || claim.Outcome != RuntimeCapabilityClaimed {
		t.Fatalf("claim=%#v err=%v", claim, err)
	}

	fixtureView := runtimeSuccessfulViewsForTest(
		t,
		source,
		clock,
		[]runtimeReadForTest{{logicalViewID: 102, offset: 20, quantity: 1}},
		[]uint16{0x9999},
	)[0]
	fixtureAttempt, err := source.BeginAttempt("attempt-fixture")
	if err != nil {
		t.Fatalf("BeginAttempt(fixture): %v", err)
	}
	fixtureRecord := runtimeNormalizationForTest(
		t,
		source,
		RuntimeAcquisitionSourceOfflineFixture,
		"fixture-1",
		20,
		1,
		"",
	)
	if issued, err := source.Issue(fixtureAttempt, fixtureView, fixtureRecord); !errors.Is(err, ErrRuntimeAcquisitionUnavailable) || issued.Valid() {
		t.Fatalf("fixture issued=%#v err=%v", issued, err)
	}
	if _, err := fixtureAttempt.Close(nil); !errors.Is(err, ErrRuntimeAttemptMembership) {
		t.Fatalf("fixture close err=%v", err)
	}

	missingAttempt, err := source.BeginAttempt("attempt-synthetic")
	if err != nil {
		t.Fatalf("BeginAttempt(synthetic): %v", err)
	}
	runtimeRecord := runtimeNormalizationForTest(
		t,
		source,
		RuntimeAcquisitionSourceRuntime,
		"runtime-synthetic",
		0,
		1,
		"",
	)
	if issued, err := source.Issue(missingAttempt, LogicalReadView{}, runtimeRecord); !errors.Is(err, ErrRuntimeAcquisitionUnavailable) || issued.Valid() {
		t.Fatalf("synthetic issued=%#v err=%v", issued, err)
	}
}

func TestM106CoalescedCapabilitiesAreIndependentAndCopiesShareOneClaim(t *testing.T) {
	clock := &virtualTCPClock{}
	source := newRuntimeAcquisitionSourceForTest(t, clock)
	views := runtimeSuccessfulViewsForTest(
		t,
		source,
		clock,
		[]runtimeReadForTest{
			{logicalViewID: 201, offset: 30, quantity: 2},
			{logicalViewID: 202, offset: 31, quantity: 1},
		},
		[]uint16{0x1111, 0x2222},
	)
	attempt, err := source.BeginAttempt("attempt-coalesced")
	if err != nil {
		t.Fatalf("BeginAttempt: %v", err)
	}
	first := issueRuntimeAcquisitionForTest(t, source, attempt, views[0], "coalesced-a")
	second := issueRuntimeAcquisitionForTest(t, source, attempt, views[1], "coalesced-b")
	instance, err := attempt.Close([]RuntimeAcquisition{first, second})
	if err != nil {
		t.Fatalf("Close: %v", err)
	}
	firstCapability := first.Capability()
	firstCopy := firstCapability
	results := make(chan RuntimeCapabilityClaimResult, 2)
	errorsSeen := make(chan error, 2)
	var start sync.WaitGroup
	start.Add(1)
	for _, capability := range []RuntimeAcquisitionCapability{firstCapability, firstCopy} {
		go func(candidate RuntimeAcquisitionCapability) {
			start.Wait()
			result, err := candidate.Claim(instance)
			results <- result
			errorsSeen <- err
		}(capability)
	}
	start.Done()
	winners := 0
	for range 2 {
		if err := <-errorsSeen; err != nil {
			t.Fatalf("concurrent Claim: %v", err)
		}
		result := <-results
		if result.Outcome != RuntimeCapabilityClaimed {
			t.Fatalf("first outcome=%#v", result)
		}
		if result.Won {
			winners++
		}
	}
	if winners != 1 {
		t.Fatalf("copied capability winners=%d", winners)
	}
	secondResult, err := second.Capability().Claim(instance)
	if err != nil || !secondResult.Won ||
		secondResult.Outcome != RuntimeCapabilityClaimed {
		t.Fatalf("independent second claim=%#v err=%v", secondResult, err)
	}
	if snapshot := source.Snapshot(); snapshot.LiveCapabilities != 0 ||
		snapshot.ActiveAttempts != 0 || len(snapshot.Tombstones) != 2 {
		t.Fatalf("terminal snapshot=%#v", snapshot)
	}
}

func TestM106MembershipCloseRejectsLateRegistration(t *testing.T) {
	clock := &virtualTCPClock{}
	source := newRuntimeAcquisitionSourceForTest(t, clock)
	view := runtimeSuccessfulViewsForTest(
		t,
		source,
		clock,
		[]runtimeReadForTest{{logicalViewID: 301, offset: 40, quantity: 1}},
		[]uint16{0x3333},
	)[0]
	attempt, err := source.BeginAttempt("attempt-close-race")
	if err != nil {
		t.Fatalf("BeginAttempt: %v", err)
	}
	record := runtimeNormalizationForTest(
		t,
		source,
		RuntimeAcquisitionSourceRuntime,
		"close-race",
		40,
		1,
		"",
	)
	paused := make(chan struct{})
	release := make(chan struct{})
	source.beforeMembership = func() {
		close(paused)
		<-release
	}
	issued := make(chan RuntimeAcquisition, 1)
	issueErr := make(chan error, 1)
	go func() {
		acquisition, err := source.Issue(attempt, view, record)
		issued <- acquisition
		issueErr <- err
	}()
	<-paused
	if _, err := attempt.Close(nil); !errors.Is(err, ErrRuntimeAttemptMembership) {
		t.Fatalf("Close(empty) err=%v", err)
	}
	close(release)
	if acquisition := <-issued; acquisition.Valid() {
		t.Fatalf("late registration exposed capability: %#v", acquisition)
	}
	if err := <-issueErr; !errors.Is(err, ErrRuntimeAttemptClosed) {
		t.Fatalf("late registration err=%v", err)
	}
	if snapshot := source.Snapshot(); snapshot.LiveCapabilities != 0 ||
		snapshot.ActiveAttempts != 0 {
		t.Fatalf("late registration retained source state: %#v", snapshot)
	}
}

func TestM106CancelOpenUsesExactInstanceAndDrainsMembers(t *testing.T) {
	clock := &virtualTCPClock{}
	source := newRuntimeAcquisitionSourceForTest(t, clock)
	views := runtimeSuccessfulViewsForTest(
		t,
		source,
		clock,
		[]runtimeReadForTest{
			{logicalViewID: 401, offset: 50, quantity: 1},
			{logicalViewID: 402, offset: 51, quantity: 1},
		},
		[]uint16{0x4444, 0x5555},
	)
	firstAttempt, err := source.BeginAttempt("same-key")
	if err != nil {
		t.Fatalf("BeginAttempt(first): %v", err)
	}
	first := issueRuntimeAcquisitionForTest(t, source, firstAttempt, views[0], "same-key-a")
	firstInstance, err := firstAttempt.Close([]RuntimeAcquisition{first})
	if err != nil {
		t.Fatalf("Close(first): %v", err)
	}
	secondAttempt, err := source.BeginAttempt("same-key")
	if err != nil {
		t.Fatalf("BeginAttempt(second): %v", err)
	}
	second := issueRuntimeAcquisitionForTest(t, source, secondAttempt, views[1], "same-key-b")
	secondInstance, err := secondAttempt.Close([]RuntimeAcquisition{second})
	if err != nil {
		t.Fatalf("Close(second): %v", err)
	}
	if err := source.CancelOpen(firstInstance); err != nil {
		t.Fatalf("CancelOpen(first): %v", err)
	}
	firstResult, err := first.Capability().Claim(firstInstance)
	if err != nil || firstResult.Won ||
		firstResult.Outcome != RuntimeCapabilityCancelled {
		t.Fatalf("first result=%#v err=%v", firstResult, err)
	}
	secondResult, err := second.Capability().Claim(secondInstance)
	if err != nil || !secondResult.Won ||
		secondResult.Outcome != RuntimeCapabilityClaimed {
		t.Fatalf("same-key second result=%#v err=%v", secondResult, err)
	}
	if err := source.CancelOpen(firstInstance); !errors.Is(err, ErrRuntimeAttemptClosed) {
		t.Fatalf("stale CancelOpen err=%v", err)
	}
}

func TestM106BoundsExhaustionAndDeterministicTombstones(t *testing.T) {
	clock := &virtualTCPClock{}
	config := runtimeAcquisitionConfigForTest(clock)
	config.Limits.MaxLiveCapabilities = 2
	config.Limits.CapabilityTombstoneLimit = 2
	source, err := NewRuntimeAcquisitionSource(config)
	if err != nil {
		t.Fatalf("NewRuntimeAcquisitionSource: %v", err)
	}
	views := runtimeSuccessfulViewsForTest(
		t,
		source,
		clock,
		[]runtimeReadForTest{
			{logicalViewID: 501, offset: 60, quantity: 1},
			{logicalViewID: 502, offset: 61, quantity: 1},
			{logicalViewID: 503, offset: 62, quantity: 1},
		},
		[]uint16{0x5001, 0x5002, 0x5003},
	)
	firstAttempt, _ := source.BeginAttempt("bounded-a")
	secondAttempt, _ := source.BeginAttempt("bounded-b")
	thirdAttempt, _ := source.BeginAttempt("bounded-c")
	first := issueRuntimeAcquisitionForTest(t, source, firstAttempt, views[0], "bounded-a")
	second := issueRuntimeAcquisitionForTest(t, source, secondAttempt, views[1], "bounded-b")
	thirdRecord := runtimeNormalizationForTest(
		t,
		source,
		RuntimeAcquisitionSourceRuntime,
		"bounded-c",
		62,
		1,
		"",
	)
	if third, err := source.Issue(thirdAttempt, views[2], thirdRecord); !errors.Is(err, ErrRuntimeAcquisitionCapacity) || third.Valid() {
		t.Fatalf("over-capacity issue=%#v err=%v", third, err)
	}
	firstInstance, err := firstAttempt.Close([]RuntimeAcquisition{first})
	if err != nil {
		t.Fatalf("Close(first): %v", err)
	}
	secondInstance, err := secondAttempt.Close([]RuntimeAcquisition{second})
	if err != nil {
		t.Fatalf("Close(second): %v", err)
	}
	if result, err := first.Capability().Claim(firstInstance); err != nil || !result.Won {
		t.Fatalf("Claim(first)=%#v err=%v", result, err)
	}
	if err := source.CancelOpen(secondInstance); err != nil {
		t.Fatalf("CancelOpen(second): %v", err)
	}
	fourthView := runtimeSuccessfulViewsForTest(
		t,
		source,
		clock,
		[]runtimeReadForTest{{logicalViewID: 504, offset: 63, quantity: 1}},
		[]uint16{0x5004},
	)[0]
	fourthAttempt, _ := source.BeginAttempt("bounded-d")
	fourth := issueRuntimeAcquisitionForTest(t, source, fourthAttempt, fourthView, "bounded-d")
	fourthInstance, err := fourthAttempt.Close([]RuntimeAcquisition{fourth})
	if err != nil {
		t.Fatalf("Close(fourth): %v", err)
	}
	if result, err := fourth.Capability().Claim(fourthInstance); err != nil || !result.Won {
		t.Fatalf("Claim(fourth)=%#v err=%v", result, err)
	}
	snapshot := source.Snapshot()
	if len(snapshot.Tombstones) != 2 ||
		snapshot.Tombstones[0].TerminalSequence != 2 ||
		snapshot.Tombstones[0].TerminalOutcome != RuntimeCapabilityCancelled ||
		snapshot.Tombstones[1].TerminalSequence != 3 ||
		snapshot.Tombstones[1].TerminalOutcome != RuntimeCapabilityClaimed {
		t.Fatalf("deterministic tombstones=%#v", snapshot.Tombstones)
	}
	restart, err := source.ExportRestartState()
	if err != nil {
		t.Fatalf("ExportRestartState: %v", err)
	}
	restoredConfig := config
	restoredConfig.Restart = &restart
	restored, err := NewRuntimeAcquisitionSource(restoredConfig)
	if err != nil {
		t.Fatalf("restore source: %v", err)
	}
	if got := restored.Snapshot().NextTerminalSequence; got != 4 {
		t.Fatalf("restored next sequence=%d", got)
	}

	exhaustedConfig := runtimeAcquisitionConfigForTest(clock)
	exhaustedConfig.Restart = &RuntimeAcquisitionRestartState{
		SchemaVersion:        1,
		NextTerminalSequence: math.MaxUint64,
	}
	exhausted, err := NewRuntimeAcquisitionSource(exhaustedConfig)
	if err != nil {
		t.Fatalf("NewRuntimeAcquisitionSource(exhaustion): %v", err)
	}
	exhaustedViews := runtimeSuccessfulViewsForTest(
		t,
		exhausted,
		clock,
		[]runtimeReadForTest{
			{logicalViewID: 505, offset: 64, quantity: 1},
			{logicalViewID: 506, offset: 65, quantity: 1},
		},
		[]uint16{0x5005, 0x5006},
	)
	lastAttempt, _ := exhausted.BeginAttempt("last-sequence")
	last := issueRuntimeAcquisitionForTest(t, exhausted, lastAttempt, exhaustedViews[0], "last")
	blockedAttempt, _ := exhausted.BeginAttempt("exhausted")
	blockedRecord := runtimeNormalizationForTest(
		t,
		exhausted,
		RuntimeAcquisitionSourceRuntime,
		"exhausted",
		65,
		1,
		"",
	)
	if blocked, err := exhausted.Issue(blockedAttempt, exhaustedViews[1], blockedRecord); !errors.Is(err, ErrRuntimeTerminalSequenceExhausted) || blocked.Valid() {
		t.Fatalf("exhausted issue=%#v err=%v", blocked, err)
	}
	lastInstance, err := lastAttempt.Close([]RuntimeAcquisition{last})
	if err != nil {
		t.Fatalf("Close(last): %v", err)
	}
	if result, err := last.Capability().Claim(lastInstance); err != nil || !result.Won {
		t.Fatalf("last Claim=%#v err=%v", result, err)
	}
	lastSnapshot := exhausted.Snapshot()
	if !lastSnapshot.SequenceExhausted ||
		len(lastSnapshot.Tombstones) != 1 ||
		lastSnapshot.Tombstones[0].TerminalSequence != math.MaxUint64 {
		t.Fatalf("exhausted snapshot=%#v", lastSnapshot)
	}
}

func TestM106PrivateCapabilityStateIsNotSerializableOrReconstructable(t *testing.T) {
	clock := &virtualTCPClock{}
	source := newRuntimeAcquisitionSourceForTest(t, clock)
	view := runtimeSuccessfulViewsForTest(
		t,
		source,
		clock,
		[]runtimeReadForTest{{logicalViewID: 601, offset: 70, quantity: 1}},
		[]uint16{0x6001},
	)[0]
	attempt, err := source.BeginAttempt("opaque-state")
	if err != nil {
		t.Fatalf("BeginAttempt: %v", err)
	}
	acquisition := issueRuntimeAcquisitionForTest(t, source, attempt, view, "opaque")
	instance, err := attempt.Close([]RuntimeAcquisition{acquisition})
	if err != nil {
		t.Fatalf("Close: %v", err)
	}
	values := []any{
		source,
		attempt,
		instance,
		acquisition,
		acquisition.Capability(),
	}
	for _, value := range values {
		if encoded, err := json.Marshal(value); !errors.Is(err, ErrOpaqueRuntimeState) {
			t.Fatalf("json.Marshal(%T)=%q err=%v", value, encoded, err)
		}
	}
	if _, err := (RuntimeAcquisitionCapability{}).Claim(instance); !errors.Is(err, ErrRuntimeAcquisitionUnavailable) {
		t.Fatalf("zero capability Claim err=%v", err)
	}
	if err := source.CancelOpen(RuntimeAttemptInstance{}); !errors.Is(err, ErrRuntimeAcquisitionUnavailable) {
		t.Fatalf("zero instance CancelOpen err=%v", err)
	}
	if err := source.CancelOpen(instance); err != nil {
		t.Fatalf("CancelOpen: %v", err)
	}
}

func TestM106NormalizationAndActivationBoundsFailClosed(t *testing.T) {
	clock := &virtualTCPClock{}
	valid := runtimeAcquisitionConfigForTest(clock)
	tests := []struct {
		name   string
		mutate func(*RuntimeAcquisitionConfig)
	}{
		{"live capabilities", func(config *RuntimeAcquisitionConfig) { config.Limits.MaxLiveCapabilities = 0 }},
		{"attempts", func(config *RuntimeAcquisitionConfig) { config.Limits.MaxAttempts = 0 }},
		{"members", func(config *RuntimeAcquisitionConfig) { config.Limits.MaxMembersPerAttempt = 0 }},
		{"attempt key bytes", func(config *RuntimeAcquisitionConfig) { config.Limits.AttemptKeyMaxUTF8Bytes = 0 }},
		{"normalization bytes", func(config *RuntimeAcquisitionConfig) { config.Limits.NormalizationRecordMaxEncodedBytes = 0 }},
		{"extension product", func(config *RuntimeAcquisitionConfig) {
			config.Limits.NormalizationExtensionCountMax = math.MaxInt
			config.Limits.NormalizationExtensionValueMaxEncodedBytes = math.MaxInt
		}},
		{"tombstones", func(config *RuntimeAcquisitionConfig) { config.Limits.CapabilityTombstoneLimit = 0 }},
		{"claim lifetime", func(config *RuntimeAcquisitionConfig) { config.ClaimLifetime = 0 }},
		{"clock", func(config *RuntimeAcquisitionConfig) { config.Clock = nil }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := valid
			test.mutate(&config)
			if source, err := NewRuntimeAcquisitionSource(config); err == nil || source != nil {
				t.Fatalf("source=%#v err=%v", source, err)
			}
		})
	}
	source := newRuntimeAcquisitionSourceForTest(t, clock)
	invalidRecords := [][]byte{
		[]byte(`{"schema_version":1,"source_kind":"runtime"}`),
		[]byte(`{"schema_version":1,"schema_version":1,"source_kind":"runtime"}`),
		[]byte(`{"schema_version":1,"source_kind":"runtime","source_evidence_id":"x","documentary_notation":"4xxxx","documentary_address":40001,"documentary_address_base":"holding_reference_4xxxx","function_code":3,"logical_table":"holding_registers","normalized_zero_based_pdu_offset":0,"word_count":1,"schema_version":1}`),
	}
	for _, encoded := range invalidRecords {
		if record, err := source.ParseNormalizationRecord(encoded); err == nil || record.Valid() {
			t.Fatalf("invalid normalization accepted: %s", encoded)
		}
	}
	overBound := bytes.Repeat([]byte{'x'}, valid.Limits.NormalizationRecordMaxEncodedBytes+1)
	if record, err := source.ParseNormalizationRecord(overBound); err == nil || record.Valid() {
		t.Fatal("over-bound normalization was decoded")
	}
}
