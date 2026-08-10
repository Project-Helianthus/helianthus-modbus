package modbus

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"strings"
	"sync"
	"sync/atomic"
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
	batch, err := endpoint.Read(context.Background(), connection)
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
	encoded := runtimeNormalizationBytesForTest(
		sourceKind,
		evidenceID,
		offset,
		wordCount,
		extension,
	)
	record, err := source.ParseNormalizationRecord(encoded)
	if err != nil {
		t.Fatalf("ParseNormalizationRecord: %v\n%s", err, encoded)
	}
	if !bytes.Equal(record.Bytes(), encoded) {
		t.Fatalf("normalization bytes changed:\n got %s\nwant %s", record.Bytes(), encoded)
	}
	return record
}

func runtimeNormalizationBytesForTest(
	sourceKind RuntimeAcquisitionSourceKind,
	evidenceID string,
	offset uint16,
	wordCount uint16,
	extension string,
) []byte {
	return []byte(fmt.Sprintf(
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
}

func issueRuntimeAcquisitionForTest(
	t *testing.T,
	source *RuntimeAcquisitionSource,
	attempt *RuntimeAttempt,
	dependencyOrdinal uint32,
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
	acquisition, err := source.Issue(attempt, dependencyOrdinal, view, record)
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
	acquisition, err := source.Issue(attempt, 0, view, normalization)
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
	encoded, err := acquisition.Normalization().AppendJSON(nil)
	if err != nil {
		t.Fatalf("AppendJSON normalization: %v", err)
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
	if issued, err := source.Issue(fixtureAttempt, 0, fixtureView, fixtureRecord); !errors.Is(err, ErrRuntimeAcquisitionUnavailable) || issued.Valid() {
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
	if issued, err := source.Issue(missingAttempt, 0, LogicalReadView{}, runtimeRecord); !errors.Is(err, ErrRuntimeAcquisitionUnavailable) || issued.Valid() {
		t.Fatalf("synthetic issued=%#v err=%v", issued, err)
	}
	if _, err := missingAttempt.Close(nil); !errors.Is(err, ErrRuntimeAttemptMembership) {
		t.Fatalf("synthetic close err=%v", err)
	}

	rtuEndpoint, rtuClock, _ := newRTUTestEndpoint(t)
	defer func() { _ = rtuEndpoint.Close() }()
	handle := beginRTUTestRead(t, rtuEndpoint)
	if err := rtuEndpoint.CompleteTransmit(handle, TransmitComplete); err != nil {
		t.Fatalf("RTU CompleteTransmit: %v", err)
	}
	rtuResult, err := observeRTUTestFrame(
		rtuEndpoint,
		rtuClock,
		rtuTestFrame(1, 0x03, 0x06, 0, 1, 0, 2, 0, 3),
	)
	if err != nil {
		t.Fatalf("RTU fixture response: %v", err)
	}
	rtuView, ok := rtuResult.LogicalView()
	if !ok {
		t.Fatal("RTU fixture did not produce its offline logical view")
	}
	rtuAttempt, err := source.BeginAttempt("attempt-rtu-fixture")
	if err != nil {
		t.Fatalf("BeginAttempt(RTU fixture): %v", err)
	}
	rtuRecord := runtimeNormalizationForTest(
		t,
		source,
		RuntimeAcquisitionSourceRuntime,
		"rtu-fixture",
		rtuView.LogicalOffset(),
		rtuView.LogicalWordCount(),
		"",
	)
	if issued, err := source.Issue(rtuAttempt, 0, rtuView, rtuRecord); !errors.Is(err, ErrRuntimeAcquisitionUnavailable) || issued.Valid() {
		t.Fatalf("RTU fixture issued=%#v err=%v", issued, err)
	}
	if _, err := rtuAttempt.Close(nil); !errors.Is(err, ErrRuntimeAttemptMembership) {
		t.Fatalf("RTU fixture close err=%v", err)
	}
}

func TestM106NonSuccessfulOutcomesNeverIssueCapabilities(t *testing.T) {
	newGroup := func(
		t *testing.T,
		source *RuntimeAcquisitionSource,
		logicalViewID uint64,
	) *CoalescedRead {
		t.Helper()
		group, err := CoalesceReads(
			[]ReadIntent{testReadIntent(t, logicalViewID, 10, 2)},
			1,
		)
		if err != nil {
			t.Fatalf("CoalesceReads: %v", err)
		}
		group.setRuntimeAcquisitionSource(source)
		return group
	}
	assertNoCapability := func(t *testing.T, source *RuntimeAcquisitionSource) {
		t.Helper()
		snapshot := source.Snapshot()
		if snapshot.LiveCapabilities != 0 || snapshot.ActiveAttempts != 0 ||
			len(snapshot.Tombstones) != 0 {
			t.Fatalf("non-success retained capability state: %#v", snapshot)
		}
	}

	for _, test := range []struct {
		name    string
		outcome WireOutcome
		pdu     []byte
	}{
		{
			name:    "protocol_exception",
			outcome: WireProtocolException,
			pdu:     []byte{0x83, 0x02},
		},
		{
			name:    "malformed_response",
			outcome: WireMalformedResponse,
			pdu:     []byte{3, 4, 0, 1},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			clock := &virtualTCPClock{}
			source := newRuntimeAcquisitionSourceForTest(t, clock)
			group := newGroup(t, source, 111)
			owner, reservation := bindCoalescedGroup(t, group)
			if _, err := owner.RecordTransmit(reservation, TransmitComplete); err != nil {
				t.Fatalf("RecordTransmit: %v", err)
			}
			response, _ := owner.Correlate(
				reservation.Generation(),
				testTCPFrame(
					t,
					reservation.TransactionID(),
					group.unitID,
					test.pdu,
				),
			)
			if response.Outcome() != test.outcome || response.Deliverable() {
				t.Fatalf("response=%#v", response)
			}
			if err := group.Fail(response); err != nil {
				t.Fatalf("Fail: %v", err)
			}
			assertNoCapability(t, source)
		})
	}

	t.Run("cancelled_dependent", func(t *testing.T) {
		clock := &virtualTCPClock{}
		source := newRuntimeAcquisitionSourceForTest(t, clock)
		group := newGroup(t, source, 112)
		if _, err := group.Cancel(112); err != nil {
			t.Fatalf("Cancel: %v", err)
		}
		assertNoCapability(t, source)
	})

	t.Run("transport_failure", func(t *testing.T) {
		clock := &virtualTCPClock{}
		source := newRuntimeAcquisitionSourceForTest(t, clock)
		group := newGroup(t, source, 113)
		if err := group.FailTransport(); err != nil {
			t.Fatalf("FailTransport: %v", err)
		}
		assertNoCapability(t, source)
	})

	for _, test := range []struct {
		name    string
		outcome WireOutcome
		prepare func(
			t *testing.T,
			owner *TCPConnectionOwner,
			reservation TCPReservation,
			group *CoalescedRead,
		) WireResponse
	}{
		{
			name:    "late_response",
			outcome: WireLateAfterAbandonment,
			prepare: func(
				t *testing.T,
				owner *TCPConnectionOwner,
				reservation TCPReservation,
				group *CoalescedRead,
			) WireResponse {
				t.Helper()
				if err := owner.AbandonResponseWait(reservation, AbandonTimeout); err != nil {
					t.Fatalf("AbandonResponseWait: %v", err)
				}
				response, err := owner.Correlate(
					reservation.Generation(),
					testTCPFrame(
						t,
						reservation.TransactionID(),
						group.unitID,
						[]byte{3, 4, 0, 1, 0, 2},
					),
				)
				if err != nil {
					t.Fatalf("Correlate(late): %v", err)
				}
				return response
			},
		},
		{
			name:    "uncorrelated_response",
			outcome: WireDroppedUncorrelated,
			prepare: func(
				t *testing.T,
				owner *TCPConnectionOwner,
				reservation TCPReservation,
				group *CoalescedRead,
			) WireResponse {
				t.Helper()
				response, err := owner.Correlate(
					reservation.Generation(),
					testTCPFrame(
						t,
						reservation.TransactionID(),
						group.unitID+1,
						[]byte{3, 4, 0, 1, 0, 2},
					),
				)
				if err != nil {
					t.Fatalf("Correlate(uncorrelated): %v", err)
				}
				return response
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			clock := &virtualTCPClock{}
			source := newRuntimeAcquisitionSourceForTest(t, clock)
			group := newGroup(t, source, 114)
			owner, reservation := bindCoalescedGroup(t, group)
			if _, err := owner.RecordTransmit(reservation, TransmitComplete); err != nil {
				t.Fatalf("RecordTransmit: %v", err)
			}
			response := test.prepare(t, owner, reservation, group)
			if response.Outcome() != test.outcome || response.Deliverable() {
				t.Fatalf("response=%#v", response)
			}
			if views, err := group.ReplaySuccessfulResponse(response); err == nil || len(views) != 0 {
				t.Fatalf("ReplaySuccessfulResponse views=%#v err=%v", views, err)
			}
			if err := group.FailTransport(); err != nil {
				t.Fatalf("FailTransport cleanup: %v", err)
			}
			assertNoCapability(t, source)
		})
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
	first := issueRuntimeAcquisitionForTest(t, source, attempt, 0, views[0], "coalesced-a")
	second := issueRuntimeAcquisitionForTest(t, source, attempt, 1, views[1], "coalesced-b")
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

func TestM106ConcurrentRegistrationUsesDeclaredOrdinals(t *testing.T) {
	clock := &virtualTCPClock{}
	source := newRuntimeAcquisitionSourceForTest(t, clock)
	views := runtimeSuccessfulViewsForTest(
		t,
		source,
		clock,
		[]runtimeReadForTest{
			{logicalViewID: 211, offset: 32, quantity: 1},
			{logicalViewID: 212, offset: 32, quantity: 1},
		},
		[]uint16{0x2111},
	)
	attempt, err := source.BeginAttempt("attempt-explicit-order")
	if err != nil {
		t.Fatalf("BeginAttempt: %v", err)
	}
	records := []RuntimeNormalizationRecord{
		runtimeNormalizationForTest(t, source, RuntimeAcquisitionSourceRuntime, "ordinal-a", 32, 1, ""),
		runtimeNormalizationForTest(t, source, RuntimeAcquisitionSourceRuntime, "ordinal-b", 32, 1, ""),
	}

	firstPaused := make(chan struct{})
	releaseFirst := make(chan struct{})
	var hookCalls atomic.Int32
	source.beforeMembership = func() {
		if hookCalls.Add(1) == 1 {
			close(firstPaused)
			<-releaseFirst
		}
	}
	type issueResult struct {
		acquisition RuntimeAcquisition
		err         error
	}
	firstResult := make(chan issueResult, 1)
	secondResult := make(chan issueResult, 1)
	go func() {
		acquisition, issueErr := source.Issue(attempt, 0, views[0], records[0])
		firstResult <- issueResult{acquisition: acquisition, err: issueErr}
	}()
	<-firstPaused
	go func() {
		acquisition, issueErr := source.Issue(attempt, 1, views[1], records[1])
		secondResult <- issueResult{acquisition: acquisition, err: issueErr}
	}()
	second := <-secondResult
	if second.err != nil {
		t.Fatalf("Issue(ordinal 1): %v", second.err)
	}
	close(releaseFirst)
	first := <-firstResult
	source.beforeMembership = nil
	if first.err != nil {
		t.Fatalf("Issue(ordinal 0): %v", first.err)
	}
	instance, err := attempt.Close([]RuntimeAcquisition{
		first.acquisition,
		second.acquisition,
	})
	if err != nil {
		t.Fatalf("Close declared [A,B] after reverse registration: %v", err)
	}
	for _, acquisition := range []RuntimeAcquisition{
		first.acquisition,
		second.acquisition,
	} {
		result, claimErr := acquisition.Capability().Claim(instance)
		if claimErr != nil || !result.Won {
			t.Fatalf("claim=%#v err=%v", result, claimErr)
		}
	}

	for _, test := range []struct {
		name    string
		members func(RuntimeAcquisition, RuntimeAcquisition) []RuntimeAcquisition
	}{
		{
			name: "duplicate",
			members: func(first, _ RuntimeAcquisition) []RuntimeAcquisition {
				return []RuntimeAcquisition{first, first}
			},
		},
		{
			name: "omission",
			members: func(first, _ RuntimeAcquisition) []RuntimeAcquisition {
				return []RuntimeAcquisition{first}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			localClock := &virtualTCPClock{}
			localSource := newRuntimeAcquisitionSourceForTest(t, localClock)
			localViews := runtimeSuccessfulViewsForTest(
				t,
				localSource,
				localClock,
				[]runtimeReadForTest{
					{logicalViewID: 213, offset: 34, quantity: 1},
					{logicalViewID: 214, offset: 34, quantity: 1},
				},
				[]uint16{0x2133},
			)
			localAttempt, beginErr := localSource.BeginAttempt("invalid-membership")
			if beginErr != nil {
				t.Fatalf("BeginAttempt: %v", beginErr)
			}
			firstMember := issueRuntimeAcquisitionForTest(
				t, localSource, localAttempt, 0, localViews[0], "member-a",
			)
			secondMember := issueRuntimeAcquisitionForTest(
				t, localSource, localAttempt, 1, localViews[1], "member-b",
			)
			if _, closeErr := localAttempt.Close(
				test.members(firstMember, secondMember),
			); !errors.Is(closeErr, ErrRuntimeAttemptMembership) {
				t.Fatalf("Close err=%v", closeErr)
			}
		})
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
		acquisition, err := source.Issue(attempt, 0, view, record)
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
	source.beforeMembership = nil
	if snapshot := source.Snapshot(); snapshot.LiveCapabilities != 0 ||
		snapshot.ActiveAttempts != 0 {
		t.Fatalf("late registration retained source state: %#v", snapshot)
	}

	orderedViews := runtimeSuccessfulViewsForTest(
		t,
		source,
		clock,
		[]runtimeReadForTest{
			{logicalViewID: 302, offset: 41, quantity: 1},
			{logicalViewID: 303, offset: 41, quantity: 1},
		},
		[]uint16{0x3334},
	)
	orderedAttempt, err := source.BeginAttempt("attempt-exact-order")
	if err != nil {
		t.Fatalf("BeginAttempt(order): %v", err)
	}
	first := issueRuntimeAcquisitionForTest(
		t,
		source,
		orderedAttempt,
		0,
		orderedViews[0],
		"ordered-first",
	)
	second := issueRuntimeAcquisitionForTest(
		t,
		source,
		orderedAttempt,
		1,
		orderedViews[1],
		"ordered-second",
	)
	if _, err := orderedAttempt.Close([]RuntimeAcquisition{second, first}); !errors.Is(err, ErrRuntimeAttemptMembership) {
		t.Fatalf("permuted membership close err=%v", err)
	}
	for _, acquisition := range []RuntimeAcquisition{first, second} {
		result, err := acquisition.Capability().Claim(RuntimeAttemptInstance{
			token: orderedAttempt.token,
		})
		if err != nil || result.Won ||
			result.Outcome != RuntimeCapabilityCancelled {
			t.Fatalf("permuted member result=%#v err=%v", result, err)
		}
	}
}

func TestM106CancelOpenUsesExactInstanceAndDrainsMembers(t *testing.T) {
	clock := &virtualTCPClock{}
	source := newRuntimeAcquisitionSourceForTest(t, clock)
	firstViews := runtimeSuccessfulViewsForTest(
		t,
		source,
		clock,
		[]runtimeReadForTest{
			{logicalViewID: 401, offset: 50, quantity: 1},
			{logicalViewID: 402, offset: 50, quantity: 1},
		},
		[]uint16{0x4444},
	)
	secondView := runtimeSuccessfulViewsForTest(
		t,
		source,
		clock,
		[]runtimeReadForTest{{logicalViewID: 403, offset: 50, quantity: 1}},
		[]uint16{0x4444},
	)[0]
	firstAttempt, err := source.BeginAttempt("same-key")
	if err != nil {
		t.Fatalf("BeginAttempt(first): %v", err)
	}
	first := issueRuntimeAcquisitionForTest(t, source, firstAttempt, 0, firstViews[0], "same-key-a")
	firstOpen := issueRuntimeAcquisitionForTest(t, source, firstAttempt, 1, firstViews[1], "same-key-open")
	firstInstance, err := firstAttempt.Close([]RuntimeAcquisition{first, firstOpen})
	if err != nil {
		t.Fatalf("Close(first): %v", err)
	}
	if result, err := first.Capability().Claim(firstInstance); err != nil ||
		!result.Won || result.Outcome != RuntimeCapabilityClaimed {
		t.Fatalf("Claim(first terminal member)=%#v err=%v", result, err)
	}
	secondAttempt, err := source.BeginAttempt("same-key")
	if err != nil {
		t.Fatalf("BeginAttempt(second): %v", err)
	}
	second := issueRuntimeAcquisitionForTest(t, source, secondAttempt, 0, secondView, "same-key-b")
	secondInstance, err := secondAttempt.Close([]RuntimeAcquisition{second})
	if err != nil {
		t.Fatalf("Close(second): %v", err)
	}
	if err := source.CancelOpen(firstInstance); err != nil {
		t.Fatalf("CancelOpen(first): %v", err)
	}
	firstResult, err := first.Capability().Claim(firstInstance)
	if err != nil || firstResult.Won ||
		firstResult.Outcome != RuntimeCapabilityClaimed {
		t.Fatalf("first result=%#v err=%v", firstResult, err)
	}
	firstOpenResult, err := firstOpen.Capability().Claim(firstInstance)
	if err != nil || firstOpenResult.Won ||
		firstOpenResult.Outcome != RuntimeCapabilityCancelled {
		t.Fatalf("first open result=%#v err=%v", firstOpenResult, err)
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
	config.Limits.MaxMembersPerAttempt = 2
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
			{logicalViewID: 502, offset: 60, quantity: 1},
			{logicalViewID: 503, offset: 60, quantity: 1},
		},
		[]uint16{0x5001},
	)
	firstAttempt, _ := source.BeginAttempt("bounded-a")
	secondAttempt, _ := source.BeginAttempt("bounded-b")
	thirdAttempt, _ := source.BeginAttempt("bounded-c")
	first := issueRuntimeAcquisitionForTest(t, source, firstAttempt, 0, views[0], "bounded-a")
	second := issueRuntimeAcquisitionForTest(t, source, secondAttempt, 0, views[1], "bounded-b")
	thirdRecord := runtimeNormalizationForTest(
		t,
		source,
		RuntimeAcquisitionSourceRuntime,
		"bounded-c",
		60,
		1,
		"",
	)
	if third, err := source.Issue(thirdAttempt, 0, views[2], thirdRecord); !errors.Is(err, ErrRuntimeAcquisitionCapacity) || third.Valid() {
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
	if err := source.CancelOpen(secondInstance); err != nil {
		t.Fatalf("CancelOpen(second): %v", err)
	}
	if result, err := first.Capability().Claim(firstInstance); err != nil || !result.Won {
		t.Fatalf("Claim(first)=%#v err=%v", result, err)
	}
	fourthView := runtimeSuccessfulViewsForTest(
		t,
		source,
		clock,
		[]runtimeReadForTest{{logicalViewID: 504, offset: 63, quantity: 1}},
		[]uint16{0x5004},
	)[0]
	fourthAttempt, _ := source.BeginAttempt("bounded-d")
	fourth := issueRuntimeAcquisitionForTest(t, source, fourthAttempt, 0, fourthView, "bounded-d")
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
			{logicalViewID: 506, offset: 64, quantity: 1},
		},
		[]uint16{0x5005},
	)
	lastAttempt, _ := exhausted.BeginAttempt("last-sequence")
	last := issueRuntimeAcquisitionForTest(t, exhausted, lastAttempt, 0, exhaustedViews[0], "last")
	blockedAttempt, _ := exhausted.BeginAttempt("exhausted")
	blockedRecord := runtimeNormalizationForTest(
		t,
		exhausted,
		RuntimeAcquisitionSourceRuntime,
		"exhausted",
		64,
		1,
		"",
	)
	if blocked, err := exhausted.Issue(blockedAttempt, 0, exhaustedViews[1], blockedRecord); !errors.Is(err, ErrRuntimeTerminalSequenceExhausted) || blocked.Valid() {
		t.Fatalf("exhausted issue=%#v err=%v", blocked, err)
	}
	if _, err := blockedAttempt.Close(nil); !errors.Is(err, ErrRuntimeAttemptMembership) {
		t.Fatalf("exhausted attempt close err=%v", err)
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
		lastSnapshot.ActiveAttempts != 0 ||
		len(lastSnapshot.Tombstones) != 1 ||
		lastSnapshot.Tombstones[0].TerminalSequence != math.MaxUint64 {
		t.Fatalf("exhausted snapshot=%#v", lastSnapshot)
	}
}

func TestM106RestartExportRetiresSourceAndPreservesSequenceUniqueness(t *testing.T) {
	clock := &virtualTCPClock{}
	config := runtimeAcquisitionConfigForTest(clock)
	source, err := NewRuntimeAcquisitionSource(config)
	if err != nil {
		t.Fatalf("NewRuntimeAcquisitionSource: %v", err)
	}
	views := runtimeSuccessfulViewsForTest(
		t,
		source,
		clock,
		[]runtimeReadForTest{
			{logicalViewID: 511, offset: 66, quantity: 1},
			{logicalViewID: 512, offset: 66, quantity: 1},
		},
		[]uint16{0x5111},
	)
	firstAttempt, err := source.BeginAttempt("before-export")
	if err != nil {
		t.Fatalf("BeginAttempt(first): %v", err)
	}
	first := issueRuntimeAcquisitionForTest(
		t, source, firstAttempt, 0, views[0], "before-export",
	)
	firstInstance, err := firstAttempt.Close([]RuntimeAcquisition{first})
	if err != nil {
		t.Fatalf("Close(first): %v", err)
	}
	if result, claimErr := first.Capability().Claim(firstInstance); claimErr != nil || !result.Won {
		t.Fatalf("Claim(first)=%#v err=%v", result, claimErr)
	}

	staleAttempt, err := source.BeginAttempt("stale-after-export")
	if err != nil {
		t.Fatalf("BeginAttempt(stale): %v", err)
	}
	staleRecord := runtimeNormalizationForTest(
		t,
		source,
		RuntimeAcquisitionSourceRuntime,
		"stale-view",
		views[1].LogicalOffset(),
		views[1].LogicalWordCount(),
		"",
	)
	restart, err := source.ExportRestartState()
	if err != nil {
		t.Fatalf("ExportRestartState: %v", err)
	}
	if _, err := source.ExportRestartState(); !errors.Is(err, ErrRuntimeAcquisitionUnavailable) {
		t.Fatalf("second export err=%v", err)
	}
	if attempt, err := source.BeginAttempt("retired-source"); !errors.Is(err, ErrRuntimeAcquisitionUnavailable) || attempt != nil {
		t.Fatalf("retired BeginAttempt=%#v err=%v", attempt, err)
	}
	if acquisition, err := source.Issue(staleAttempt, 0, views[1], staleRecord); !errors.Is(err, ErrRuntimeAcquisitionUnavailable) || acquisition.Valid() {
		t.Fatalf("retired stale Issue=%#v err=%v", acquisition, err)
	}

	restoredConfig := config
	restoredConfig.Restart = &restart
	restored, err := NewRuntimeAcquisitionSource(restoredConfig)
	if err != nil {
		t.Fatalf("restore source: %v", err)
	}
	if attempt, err := source.BeginAttempt("old-source-after-restore"); !errors.Is(err, ErrRuntimeAcquisitionUnavailable) || attempt != nil {
		t.Fatalf("old source BeginAttempt after restore=%#v err=%v", attempt, err)
	}
	restoredAttempt, err := restored.BeginAttempt("after-restore")
	if err != nil {
		t.Fatalf("BeginAttempt(restored): %v", err)
	}
	restoredStaleRecord := runtimeNormalizationForTest(
		t,
		restored,
		RuntimeAcquisitionSourceRuntime,
		"stale-view-restored-source",
		views[1].LogicalOffset(),
		views[1].LogicalWordCount(),
		"",
	)
	if acquisition, err := restored.Issue(
		restoredAttempt,
		0,
		views[1],
		restoredStaleRecord,
	); !errors.Is(err, ErrRuntimeAcquisitionUnavailable) || acquisition.Valid() {
		t.Fatalf("restored stale-view Issue=%#v err=%v", acquisition, err)
	}
	freshView := runtimeSuccessfulViewsForTest(
		t,
		restored,
		clock,
		[]runtimeReadForTest{{logicalViewID: 513, offset: 68, quantity: 1}},
		[]uint16{0x5133},
	)[0]
	second := issueRuntimeAcquisitionForTest(
		t, restored, restoredAttempt, 0, freshView, "after-restore",
	)
	secondInstance, err := restoredAttempt.Close([]RuntimeAcquisition{second})
	if err != nil {
		t.Fatalf("Close(second): %v", err)
	}
	if result, claimErr := second.Capability().Claim(secondInstance); claimErr != nil || !result.Won {
		t.Fatalf("Claim(second)=%#v err=%v", result, claimErr)
	}
	tombstones := restored.Snapshot().Tombstones
	if len(tombstones) != 2 ||
		tombstones[0].TerminalSequence != 1 ||
		tombstones[1].TerminalSequence != 2 {
		t.Fatalf("restored tombstones=%#v", tombstones)
	}
}

func TestM106FailureAndExpiryReclaimSynchronously(t *testing.T) {
	clock := &virtualTCPClock{}
	source := newRuntimeAcquisitionSourceForTest(t, clock)
	views := runtimeSuccessfulViewsForTest(
		t,
		source,
		clock,
		[]runtimeReadForTest{
			{logicalViewID: 551, offset: 66, quantity: 1},
			{logicalViewID: 552, offset: 66, quantity: 1},
		},
		[]uint16{0x5501},
	)
	attempt, err := source.BeginAttempt("failure-expiry")
	if err != nil {
		t.Fatalf("BeginAttempt: %v", err)
	}
	failed := issueRuntimeAcquisitionForTest(t, source, attempt, 0, views[0], "failed")
	expired := issueRuntimeAcquisitionForTest(t, source, attempt, 1, views[1], "expired")
	instance, err := attempt.Close([]RuntimeAcquisition{failed, expired})
	if err != nil {
		t.Fatalf("Close: %v", err)
	}
	if outcome, err := source.FailOpen(failed.Capability()); err != nil ||
		outcome != RuntimeCapabilityFailed {
		t.Fatalf("FailOpen outcome=%q err=%v", outcome, err)
	}
	clock.Advance(time.Minute)
	if count := source.ExpireOpen(); count != 1 {
		t.Fatalf("ExpireOpen count=%d", count)
	}
	failedClaim, err := failed.Capability().Claim(instance)
	if err != nil || failedClaim.Won ||
		failedClaim.Outcome != RuntimeCapabilityFailed {
		t.Fatalf("failed claim=%#v err=%v", failedClaim, err)
	}
	expiredClaim, err := expired.Capability().Claim(instance)
	if err != nil || expiredClaim.Won ||
		expiredClaim.Outcome != RuntimeCapabilityExpired {
		t.Fatalf("expired claim=%#v err=%v", expiredClaim, err)
	}
	if snapshot := source.Snapshot(); snapshot.LiveCapabilities != 0 ||
		snapshot.ActiveAttempts != 0 {
		t.Fatalf("failure/expiry retained live state: %#v", snapshot)
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
	acquisition := issueRuntimeAcquisitionForTest(t, source, attempt, 0, view, "opaque")
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
	jsonTargets := []any{
		&RuntimeAcquisitionSource{},
		&RuntimeAttempt{},
		&RuntimeAttemptInstance{},
		&RuntimeAcquisition{},
		&RuntimeAcquisitionCapability{},
	}
	for _, target := range jsonTargets {
		if err := json.Unmarshal([]byte(`{}`), target); !errors.Is(err, ErrOpaqueRuntimeState) {
			t.Fatalf("json.Unmarshal(%T) err=%v", target, err)
		}
	}
	capability := acquisition.Capability()
	if err := capability.UnmarshalText([]byte("forged")); !errors.Is(err, ErrOpaqueRuntimeState) {
		t.Fatalf("capability UnmarshalText err=%v", err)
	}
	if err := capability.UnmarshalBinary([]byte{1}); !errors.Is(err, ErrOpaqueRuntimeState) {
		t.Fatalf("capability UnmarshalBinary err=%v", err)
	}
	if err := capability.GobDecode([]byte{1}); !errors.Is(err, ErrOpaqueRuntimeState) {
		t.Fatalf("capability GobDecode err=%v", err)
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

func TestM106NormalizationRequiredFieldsRejectNullAndWrongTypes(t *testing.T) {
	clock := &virtualTCPClock{}
	source := newRuntimeAcquisitionSourceForTest(t, clock)
	view := runtimeSuccessfulViewsForTest(
		t,
		source,
		clock,
		[]runtimeReadForTest{{logicalViewID: 611, offset: 0, quantity: 1}},
		[]uint16{0x6111},
	)[0]
	valid := string(runtimeNormalizationBytesForTest(
		RuntimeAcquisitionSourceRuntime,
		"typed-fields",
		0,
		1,
		"",
	))
	tests := []struct {
		name      string
		token     string
		wrongType string
	}{
		{"schema_version", `"schema_version":1`, `"schema_version":"1"`},
		{"source_kind", `"source_kind":"runtime"`, `"source_kind":1`},
		{"source_evidence_id", `"source_evidence_id":"typed-fields"`, `"source_evidence_id":1`},
		{"documentary_notation", `"documentary_notation":"4xxxx"`, `"documentary_notation":1`},
		{"documentary_address", `"documentary_address":40001`, `"documentary_address":"40001"`},
		{"documentary_address_base", `"documentary_address_base":"holding_reference_4xxxx"`, `"documentary_address_base":1`},
		{"function_code", `"function_code":3`, `"function_code":"3"`},
		{"logical_table", `"logical_table":"holding_registers"`, `"logical_table":1`},
		{"normalized_zero_based_pdu_offset", `"normalized_zero_based_pdu_offset":0`, `"normalized_zero_based_pdu_offset":"0"`},
		{"word_count", `"word_count":1`, `"word_count":"1"`},
	}
	for index, test := range tests {
		for _, variant := range []struct {
			name        string
			replacement string
		}{
			{"null", strings.Split(test.token, ":")[0] + ":null"},
			{"wrong_type", test.wrongType},
		} {
			t.Run(test.name+"/"+variant.name, func(t *testing.T) {
				encoded := []byte(strings.Replace(valid, test.token, variant.replacement, 1))
				record, err := source.ParseNormalizationRecord(encoded)
				if !errors.Is(err, ErrRuntimeNormalization) || record.Valid() {
					t.Fatalf("ParseNormalizationRecord record=%#v err=%v\n%s", record, err, encoded)
				}
				attempt, err := source.BeginAttempt(fmt.Sprintf("invalid-type-%d-%s", index, variant.name))
				if err != nil {
					t.Fatalf("BeginAttempt: %v", err)
				}
				if acquisition, issueErr := source.Issue(attempt, 0, view, record); !errors.Is(issueErr, ErrRuntimeAcquisitionUnavailable) || acquisition.Valid() {
					t.Fatalf("Issue acquisition=%#v err=%v", acquisition, issueErr)
				}
				if _, closeErr := attempt.Close(nil); !errors.Is(closeErr, ErrRuntimeAttemptMembership) {
					t.Fatalf("Close err=%v", closeErr)
				}
				if snapshot := source.Snapshot(); snapshot.LiveCapabilities != 0 ||
					snapshot.ActiveAttempts != 0 || len(snapshot.Tombstones) != 0 {
					t.Fatalf("invalid field retained authority: %#v", snapshot)
				}
			})
		}
	}
}

func TestM106NormalizationParseLinearizesWithRestartExport(t *testing.T) {
	clock := &virtualTCPClock{}
	encoded := runtimeNormalizationBytesForTest(
		RuntimeAcquisitionSourceRuntime,
		"parse-export",
		70,
		1,
		` ,"future":{"exact":"<>&\\u003c"}`,
	)

	t.Run("pre_export_record", func(t *testing.T) {
		source := newRuntimeAcquisitionSourceForTest(t, clock)
		record, err := source.ParseNormalizationRecord(encoded)
		if err != nil || !record.Valid() {
			t.Fatalf("ParseNormalizationRecord record=%#v err=%v", record, err)
		}
		if _, err := source.ExportRestartState(); err != nil {
			t.Fatalf("ExportRestartState: %v", err)
		}
		if !record.Valid() || !bytes.Equal(record.Bytes(), encoded) {
			t.Fatalf("pre-export record changed: valid=%v bytes=%q", record.Valid(), record.Bytes())
		}
		if rejected, err := source.ParseNormalizationRecord(encoded); !errors.Is(err, ErrRuntimeAcquisitionUnavailable) || rejected.Valid() {
			t.Fatalf("post-export parse record=%#v err=%v", rejected, err)
		}
	})

	t.Run("export_wins_forced_race", func(t *testing.T) {
		source := newRuntimeAcquisitionSourceForTest(t, clock)
		beforePublish := make(chan struct{})
		release := make(chan struct{})
		source.beforeNormalizationPublish = func() {
			close(beforePublish)
			<-release
		}
		type parseResult struct {
			record RuntimeNormalizationRecord
			err    error
		}
		result := make(chan parseResult, 1)
		go func() {
			record, err := source.ParseNormalizationRecord(encoded)
			result <- parseResult{record: record, err: err}
		}()
		<-beforePublish
		if _, err := source.ExportRestartState(); err != nil {
			t.Fatalf("ExportRestartState: %v", err)
		}
		close(release)
		parsed := <-result
		source.beforeNormalizationPublish = nil
		if !errors.Is(parsed.err, ErrRuntimeAcquisitionUnavailable) || parsed.record.Valid() {
			t.Fatalf("racing parse record=%#v err=%v", parsed.record, parsed.err)
		}
		if rejected, err := source.ParseNormalizationRecord(encoded); !errors.Is(err, ErrRuntimeAcquisitionUnavailable) || rejected.Valid() {
			t.Fatalf("late parse record=%#v err=%v", rejected, err)
		}
	})
}

func TestM106NormalizationExactSerializationBoundary(t *testing.T) {
	clock := &virtualTCPClock{}
	source := newRuntimeAcquisitionSourceForTest(t, clock)
	encoded := []byte("{\n" +
		"  \"future_html\" : \"<script>&\\u003c/script>\",\n" +
		"  \"word_count\" : 1,\n" +
		"  \"logical_table\" : \"holding_registers\",\n" +
		"  \"function_code\" : 3,\n" +
		"  \"documentary_address_base\" : \"holding_reference_4xxxx\",\n" +
		"  \"documentary_address\" : 40071,\n" +
		"  \"documentary_notation\" : \"4\\u0078xxx\",\n" +
		"  \"source_evidence_id\" : \"evidence\\/escaped\",\n" +
		"  \"source_kind\" : \"\\u0072untime\",\n" +
		"  \"normalized_zero_based_pdu_offset\" : 70,\n" +
		"  \"schema_version\" : 1\n" +
		"}\n")
	record, err := source.ParseNormalizationRecord(encoded)
	if err != nil {
		t.Fatalf("ParseNormalizationRecord: %v", err)
	}
	prefix := []byte("prefix:")
	serialized, err := record.AppendJSON(append([]byte(nil), prefix...))
	if err != nil {
		t.Fatalf("AppendJSON: %v", err)
	}
	want := append(append([]byte(nil), prefix...), encoded...)
	if !bytes.Equal(serialized, want) {
		t.Fatalf("exact serialization changed:\n got %q\nwant %q", serialized, want)
	}
	if !bytes.Equal(record.Bytes(), encoded) {
		t.Fatalf("Bytes changed:\n got %q\nwant %q", record.Bytes(), encoded)
	}
	if marshaled, err := json.Marshal(record); !errors.Is(err, ErrRuntimeNormalization) || marshaled != nil {
		t.Fatalf("json.Marshal=%q err=%v", marshaled, err)
	}
}

func TestM106NormalizationAndActivationBoundsFailClosed(t *testing.T) {
	clock := &virtualTCPClock{}
	if count := (&RuntimeAcquisitionSource{}).ExpireOpen(); count != 0 {
		t.Fatalf("zero source expired capabilities=%d", count)
	}
	if _, err := (&RuntimeAcquisitionSource{}).ExportRestartState(); !errors.Is(err, ErrRuntimeAcquisitionUnavailable) {
		t.Fatalf("zero source restart err=%v", err)
	}
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
	invalidUTF8 := []byte(`{"schema_version":1,"source_kind":"runtime","source_evidence_id":"x","documentary_notation":"4xxxx","documentary_address":40001,"documentary_address_base":"holding_reference_4xxxx","function_code":3,"logical_table":"holding_registers","normalized_zero_based_pdu_offset":0,"word_count":1}`)
	invalidUTF8[bytes.Index(invalidUTF8, []byte(`"x"`))+1] = 0xff
	invalidRecords = append(invalidRecords, invalidUTF8)
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
