package modbus

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// loggerFixtureExchange is one sanitized FC2B/MEI0E response recorded from a
// logger-class Modbus TCP gateway. response_adu is the exact MBAP frame; the
// summary is the reviewable view that TestLoggerFixtureRawBytesMatchSummary
// proves against the raw bytes.
type loggerFixtureExchange struct {
	Name           string   `json:"name"`
	UnitID         byte     `json:"unit_id"`
	Access         byte     `json:"access"`
	ObjectID       string   `json:"object_id"`
	ExtendedStream bool     `json:"extended_stream"`
	ResponseADU    []string `json:"response_adu"`
	Summary        struct {
		PDULength       int    `json:"pdu_length"`
		Conformity      string `json:"conformity"`
		MoreFollows     string `json:"more_follows"`
		NextObjectID    string `json:"next_object_id"`
		DeclaredObjects int    `json:"declared_objects"`
		Objects         []struct {
			ID         string `json:"id"`
			Length     int    `json:"length"`
			Text       string `json:"text"`
			NULPadding int    `json:"nul_padding"`
			Hex        string `json:"hex"`
		} `json:"objects"`
	} `json:"summary"`
}

type loggerFixture struct {
	Schema       string                  `json:"schema"`
	DeviceClass  string                  `json:"device_class"`
	Provenance   string                  `json:"provenance"`
	Sanitization []string                `json:"sanitization"`
	Exchanges    []loggerFixtureExchange `json:"exchanges"`
}

func loadLoggerFixture(t *testing.T) loggerFixture {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "device_id_logger_class.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture loggerFixture
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Schema != "helianthus-modbus.device-id-fixture/v1" || len(fixture.Exchanges) != 16 {
		t.Fatalf("fixture schema=%q exchanges=%d", fixture.Schema, len(fixture.Exchanges))
	}
	return fixture
}

func (fixture loggerFixture) exchange(t *testing.T, name string) loggerFixtureExchange {
	t.Helper()
	for _, exchange := range fixture.Exchanges {
		if exchange.Name == name {
			return exchange
		}
	}
	t.Fatalf("fixture exchange %s missing", name)
	return loggerFixtureExchange{}
}

func (fixture loggerFixture) inventoryPage(t *testing.T, objectID byte) loggerFixtureExchange {
	t.Helper()
	for _, exchange := range fixture.Exchanges {
		if exchange.ExtendedStream && fixtureByte(t, exchange.ObjectID) == objectID {
			return exchange
		}
	}
	t.Fatalf("fixture inventory page for object 0x%02x missing", objectID)
	return loggerFixtureExchange{}
}

func (exchange loggerFixtureExchange) adu(t *testing.T) []byte {
	t.Helper()
	encoded := strings.ReplaceAll(strings.Join(exchange.ResponseADU, " "), " ", "")
	adu, err := hex.DecodeString(encoded)
	if err != nil {
		t.Fatalf("%s: %v", exchange.Name, err)
	}
	return adu
}

func (exchange loggerFixtureExchange) pdu(t *testing.T) []byte {
	t.Helper()
	return exchange.adu(t)[mbapHeaderSize:]
}

func fixtureByte(t *testing.T, text string) byte {
	t.Helper()
	value, err := strconv.ParseUint(strings.TrimPrefix(text, "0x"), 16, 8)
	if err != nil {
		t.Fatalf("fixture byte %q: %v", text, err)
	}
	return byte(value)
}

// loggerInventoryPages walks the fixture's extended inventory with the
// tolerant continuation API, as a gateway driver would.
func loggerInventoryPages(t *testing.T, fixture loggerFixture) (DeviceIDRequest, []DeviceIDPage) {
	t.Helper()
	first, err := NewExtendedDeviceIDStreamRequest(0x87)
	if err != nil {
		t.Fatal(err)
	}
	request := first
	var pages []DeviceIDPage
	for {
		page, err := DecodeDeviceIDPage(request, fixture.inventoryPage(t, request.ObjectID()).pdu(t))
		if err != nil {
			t.Fatal(err)
		}
		pages = append(pages, page)
		if !page.MoreFollows() {
			return first, pages
		}
		if request, err = NextDeviceIDPageRequest(page); err != nil {
			t.Fatal(err)
		}
	}
}

// childUnitID reads attribute 5 of an inventory attribute string. The
// transport keeps the value bytes; parsing them is a profile concern, done
// here only to prove that the bytes survive intact.
func childUnitID(t *testing.T, value []byte) int {
	t.Helper()
	text := string(bytes.TrimRight(value, "\x00"))
	for _, field := range strings.Split(text, ";") {
		key, attribute, found := strings.Cut(field, "=")
		if found && key == "5" {
			unit, err := strconv.Atoi(attribute)
			if err != nil {
				t.Fatalf("attribute 5 %q: %v", attribute, err)
			}
			return unit
		}
	}
	t.Fatalf("attribute 5 missing in %q", text)
	return -1
}

func requireAnomalies(t *testing.T, got []DeviceIDAnomaly, want ...DeviceIDAnomaly) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("anomalies = %v, want %v", got, want)
	}
}

func requireMalformedDeviceID(t *testing.T, err error, field string) {
	t.Helper()
	var protocolErr *ProtocolError
	if !errors.As(err, &protocolErr) || protocolErr.Kind != ErrorMalformedResponse || protocolErr.Field != field {
		t.Fatalf("error = %#v, want malformed %s", err, field)
	}
}

func TestLoggerFixtureRawBytesMatchSummary(t *testing.T) {
	fixture := loadLoggerFixture(t)
	var basics, inventory []loggerFixtureExchange
	for _, exchange := range fixture.Exchanges {
		adu := exchange.adu(t)
		pdu := adu[mbapHeaderSize:]
		summary := exchange.Summary
		if adu[2] != 0 || adu[3] != 0 ||
			int(adu[4])<<8|int(adu[5]) != len(pdu)+1 ||
			adu[6] != exchange.UnitID ||
			len(pdu) != summary.PDULength ||
			pdu[0] != byte(FunctionEncapsulatedInterface) ||
			pdu[1] != deviceIDMEIType ||
			pdu[2] != exchange.Access ||
			pdu[3] != fixtureByte(t, summary.Conformity) ||
			pdu[4] != fixtureByte(t, summary.MoreFollows) ||
			pdu[5] != fixtureByte(t, summary.NextObjectID) ||
			int(pdu[6]) != summary.DeclaredObjects {
			t.Fatalf("%s: header disagrees with summary: %x", exchange.Name, adu[:14])
		}
		cursor := 7
		for _, object := range summary.Objects {
			if cursor+2 > len(pdu) || pdu[cursor] != fixtureByte(t, object.ID) || int(pdu[cursor+1]) != object.Length {
				t.Fatalf("%s: object %s header mismatch at %d", exchange.Name, object.ID, cursor)
			}
			value := pdu[cursor+2 : cursor+2+object.Length]
			var want []byte
			if object.Hex != "" {
				decoded, err := hex.DecodeString(strings.ReplaceAll(object.Hex, " ", ""))
				if err != nil {
					t.Fatal(err)
				}
				want = decoded
			} else {
				want = append([]byte(object.Text), make([]byte, object.NULPadding)...)
			}
			if !bytes.Equal(value, want) {
				t.Fatalf("%s: object %s value differs from summary", exchange.Name, object.ID)
			}
			cursor += 2 + object.Length
		}
		if cursor != len(pdu) {
			t.Fatalf("%s: %d bytes not described by the summary", exchange.Name, len(pdu)-cursor)
		}
		if exchange.ExtendedStream {
			inventory = append(inventory, exchange)
		} else {
			basics = append(basics, exchange)
		}
	}
	if len(basics) != 3 || len(inventory) != 13 {
		t.Fatalf("basic=%d inventory=%d", len(basics), len(inventory))
	}
	for _, basic := range basics {
		if len(basic.Summary.Objects) != 12 || basic.Summary.DeclaredObjects != 12 ||
			!bytes.Equal(basic.pdu(t), basics[0].pdu(t)) {
			t.Fatalf("%s is not the shared over-full basic reply", basic.Name)
		}
	}
	if units := []byte{basics[0].UnitID, basics[1].UnitID, basics[2].UnitID}; !bytes.Equal(units, []byte{0, 1, 100}) {
		t.Fatalf("basic reply units = %v", units)
	}
	first := inventory[0]
	if fixtureByte(t, first.ObjectID) != 0x87 || len(first.Summary.Objects) != 1 ||
		first.Summary.Objects[0].Hex != "0c" || first.Summary.DeclaredObjects != 13 {
		t.Fatalf("first inventory page is not the count-only page: %+v", first.Summary)
	}
	for index, page := range inventory[1:] {
		objectID := byte(0x88 + index)
		if fixtureByte(t, page.ObjectID) != objectID ||
			len(page.adu(t)) != 270 || page.Summary.PDULength != 263 ||
			len(page.Summary.Objects) != 1 || fixtureByte(t, page.Summary.Objects[0].ID) != objectID ||
			page.Summary.Objects[0].Length != 254 || page.Summary.DeclaredObjects != 13 {
			t.Fatalf("inventory page %s shape changed", page.Name)
		}
		last := index == len(inventory)-2
		wantMore, wantNext := "0xff", objectID+1
		if last {
			wantMore, wantNext = "0x00", 0
		}
		if page.Summary.MoreFollows != wantMore || fixtureByte(t, page.Summary.NextObjectID) != wantNext {
			t.Fatalf("inventory page %s paging changed", page.Name)
		}
	}
}

func TestStrictDeviceIDDecoderStillRejectsLoggerClassPages(t *testing.T) {
	fixture := loadLoggerFixture(t)
	basic, err := NewDeviceIDRequest(DeviceIDBasic, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = DecodeDeviceIDSegment(basic, fixture.exchange(t, "basic_unit_0").pdu(t))
	requireMalformedDeviceID(t, err, "requested_category")
	stream, err := NewExtendedDeviceIDStreamRequest(0x87)
	if err != nil {
		t.Fatal(err)
	}
	_, err = DecodeDeviceIDSegment(stream, fixture.inventoryPage(t, 0x87).pdu(t))
	requireMalformedDeviceID(t, err, "object_header")
	strictDecoder, err := NewTCPStreamDecoder(maxTCPADUSize)
	if err != nil {
		t.Fatal(err)
	}
	_, err = strictDecoder.Feed(fixture.inventoryPage(t, 0x88).adu(t))
	requireMalformedDeviceID(t, err, "length")
}

func TestTolerantDeviceIDDecodesOverfullBasicReply(t *testing.T) {
	fixture := loadLoggerFixture(t)
	request, err := NewDeviceIDRequest(DeviceIDBasic, 0)
	if err != nil {
		t.Fatal(err)
	}
	pdu := fixture.exchange(t, "basic_unit_0").pdu(t)
	page, err := DecodeDeviceIDPage(request, pdu)
	if err != nil {
		t.Fatal(err)
	}
	requireAnomalies(t, page.Anomalies,
		DeviceIDAnomalyObjectOutsideCategory,
		DeviceIDAnomalyObjectOutsideConformity,
		DeviceIDAnomalyReservedObjectID,
	)
	outside := 0
	for _, object := range page.Objects {
		if object.ID > 0x02 {
			outside++
		}
	}
	if len(page.Objects) != 12 || outside != 9 || page.DeclaredObjects != 12 ||
		page.Conformity != 0x01 || page.AccessCode != DeviceIDBasic ||
		page.MoreFollows() || page.NextObjectID != 0 || page.OversizePDU() ||
		page.UndecodedOffset != len(pdu) || !bytes.Equal(page.PDU, pdu) {
		t.Fatalf("basic page: objects=%d outside=%d %+v", len(page.Objects), outside, page)
	}
	if string(page.Objects[0].Value) != "VENDOR" || string(page.Objects[1].Value) != "LOGGER-MODEL" {
		t.Fatalf("basic identity objects = %q %q", page.Objects[0].Value, page.Objects[1].Value)
	}
	result, err := AggregateTolerantDeviceID(request, []DeviceIDPage{page}, DefaultDeviceIDLimits())
	if err != nil {
		t.Fatal(err)
	}
	if !result.Complete || len(result.Objects) != 12 || result.HasAnomaly(DeviceIDAnomalyMandatoryObjectMissing) {
		t.Fatalf("basic aggregate = %+v", result)
	}
}

func TestTolerantDeviceIDBasicReplyIsDecodedPerUnit(t *testing.T) {
	fixture := loadLoggerFixture(t)
	request, err := NewDeviceIDRequest(DeviceIDBasic, 0)
	if err != nil {
		t.Fatal(err)
	}
	var reference DeviceIDPage
	for index, name := range []string{"basic_unit_0", "basic_unit_1", "basic_unit_100"} {
		page, err := DecodeDeviceIDPage(request, fixture.exchange(t, name).pdu(t))
		if err != nil {
			t.Fatal(err)
		}
		if index == 0 {
			reference = page
			continue
		}
		if !reflect.DeepEqual(page, reference) {
			t.Fatalf("%s decodes differently from unit 0", name)
		}
	}
}

func TestTolerantDeviceIDCountOnlyFirstPage(t *testing.T) {
	fixture := loadLoggerFixture(t)
	request, err := NewExtendedDeviceIDStreamRequest(0x87)
	if err != nil {
		t.Fatal(err)
	}
	pdu := fixture.inventoryPage(t, 0x87).pdu(t)
	page, err := DecodeDeviceIDPage(request, pdu)
	if err != nil {
		t.Fatal(err)
	}
	requireAnomalies(t, page.Anomalies,
		DeviceIDAnomalyObjectCountMismatch,
		DeviceIDAnomalyCountOnlyPage,
	)
	if !reflect.DeepEqual(page.Objects, []DeviceIDObject{{ID: 0x87, Value: []byte{12}}}) ||
		page.DeclaredObjects != 13 || !page.MoreFollows() || page.MoreFollowsValue != 0xff ||
		page.NextObjectID != 0x88 || page.Conformity != 0x03 || page.UndecodedOffset != len(pdu) {
		t.Fatalf("count-only page = %+v", page)
	}
	next, err := NextDeviceIDPageRequest(page)
	if err != nil || next.ObjectID() != 0x88 || next.Access() != DeviceIDExtended {
		t.Fatalf("continuation = %#v err=%v", next, err)
	}
}

func TestTolerantDeviceIDOversizeInventoryPage(t *testing.T) {
	fixture := loadLoggerFixture(t)
	first, err := NewExtendedDeviceIDStreamRequest(0x87)
	if err != nil {
		t.Fatal(err)
	}
	firstPage, err := DecodeDeviceIDPage(first, fixture.inventoryPage(t, 0x87).pdu(t))
	if err != nil {
		t.Fatal(err)
	}
	request, err := NextDeviceIDPageRequest(firstPage)
	if err != nil {
		t.Fatal(err)
	}
	pdu := fixture.inventoryPage(t, 0x88).pdu(t)
	page, err := DecodeDeviceIDPage(request, pdu)
	if err != nil {
		t.Fatal(err)
	}
	requireAnomalies(t, page.Anomalies,
		DeviceIDAnomalyOversizePage,
		DeviceIDAnomalyOversizeObjectValue,
		DeviceIDAnomalyObjectCountMismatch,
	)
	if !page.OversizePDU() || len(page.PDU) != 263 || !bytes.Equal(page.PDU, pdu) ||
		len(page.Objects) != 1 || page.Objects[0].ID != 0x88 || len(page.Objects[0].Value) != 254 ||
		page.UndecodedOffset != 263 || page.NextObjectID != 0x89 || childUnitID(t, page.Objects[0].Value) != 0 {
		t.Fatalf("oversize page = %+v", page)
	}
}

func TestTolerantDeviceIDAggregatesLoggerInventory(t *testing.T) {
	fixture := loadLoggerFixture(t)
	first, pages := loggerInventoryPages(t, fixture)
	result, err := AggregateTolerantDeviceID(first, pages, DefaultDeviceIDLimits())
	if err != nil {
		t.Fatal(err)
	}
	requireAnomalies(t, result.Anomalies,
		DeviceIDAnomalyObjectCountMismatch,
		DeviceIDAnomalyCountOnlyPage,
		DeviceIDAnomalyOversizePage,
		DeviceIDAnomalyOversizeObjectValue,
	)
	if !result.Complete || result.Conformity != 0x03 || len(result.Pages) != 13 || len(result.Objects) != 13 {
		t.Fatalf("inventory: complete=%t pages=%d objects=%d", result.Complete, len(result.Pages), len(result.Objects))
	}
	for index, page := range result.Pages {
		want := fixture.inventoryPage(t, byte(0x87+index)).pdu(t)
		if !bytes.Equal(page.PDU, want) || page.Request.ObjectID() != byte(0x87+index) {
			t.Fatalf("page %d lost bytes or cursor", index)
		}
	}
	if result.Objects[0].ID != 0x87 || !bytes.Equal(result.Objects[0].Value, []byte{12}) {
		t.Fatalf("count object = %+v", result.Objects[0])
	}
	var units []int
	for index, object := range result.Objects[1:] {
		if object.ID != byte(0x88+index) {
			t.Fatalf("object %d id 0x%02x", index, object.ID)
		}
		units = append(units, childUnitID(t, object.Value))
	}
	if want := []int{0, 2, 3, 4, 5, 6, 7, 8, 9, 1, 11, 19}; !reflect.DeepEqual(units, want) {
		t.Fatalf("child unit ids = %v, want %v", units, want)
	}
	if len(units) != int(result.Objects[0].Value[0]) {
		t.Fatalf("count object %d disagrees with %d children", result.Objects[0].Value[0], len(units))
	}
}

func TestTolerantDeviceIDMultiObjectOversizePage(t *testing.T) {
	request, err := NewExtendedDeviceIDStreamRequest(0x89)
	if err != nil {
		t.Fatal(err)
	}
	pdu := []byte{0x2b, 0x0e, 0x03, 0x03, 0xff, 0x8c, 12}
	for index, length := range []int{84, 84, 82} {
		pdu = append(pdu, byte(0x89+index), byte(length))
		pdu = append(pdu, bytes.Repeat([]byte{'a' + byte(index)}, length)...)
	}
	if len(pdu) != 263 {
		t.Fatalf("synthetic page length %d", len(pdu))
	}
	page, err := DecodeDeviceIDPage(request, pdu)
	if err != nil {
		t.Fatal(err)
	}
	requireAnomalies(t, page.Anomalies, DeviceIDAnomalyOversizePage, DeviceIDAnomalyObjectCountMismatch)
	if len(page.Objects) != 3 || page.Objects[2].ID != 0x8b || page.DeclaredObjects != 12 {
		t.Fatalf("multi-object oversize page = %+v", page)
	}
	next, err := NextDeviceIDPageRequest(page)
	if err != nil || next.ObjectID() != 0x8c {
		t.Fatalf("continuation after multi-object page = %#v err=%v", next, err)
	}
}

func TestTolerantDeviceIDOddMoreFollowsContinuesUntilZero(t *testing.T) {
	first, err := NewDeviceIDRequest(DeviceIDRegular, 0)
	if err != nil {
		t.Fatal(err)
	}
	pageOne, err := DecodeDeviceIDPage(first, []byte{
		0x2b, 0x0e, 0x02, 0x02, 0x01, 0x03, 0x03,
		0x00, 0x01, 'V', 0x01, 0x01, 'P', 0x02, 0x01, 'R',
	})
	if err != nil {
		t.Fatal(err)
	}
	requireAnomalies(t, pageOne.Anomalies, DeviceIDAnomalyMoreFollowsValue)
	if !pageOne.MoreFollows() || pageOne.MoreFollowsValue != 0x01 {
		t.Fatalf("odd more-follows page = %+v", pageOne)
	}
	second, err := NextDeviceIDPageRequest(pageOne)
	if err != nil || second.ObjectID() != 0x03 {
		t.Fatalf("odd more-follows continuation = %#v err=%v", second, err)
	}
	pageTwo, err := DecodeDeviceIDPage(second, []byte{
		0x2b, 0x0e, 0x02, 0x02, 0x00, 0x05, 0x01, 0x03, 0x01, 'U',
	})
	if err != nil {
		t.Fatal(err)
	}
	requireAnomalies(t, pageTwo.Anomalies, DeviceIDAnomalyNextObjectWithoutMoreFollows)
	result, err := AggregateTolerantDeviceID(first, []DeviceIDPage{pageOne, pageTwo}, DefaultDeviceIDLimits())
	if err != nil {
		t.Fatal(err)
	}
	requireAnomalies(t, result.Anomalies,
		DeviceIDAnomalyMoreFollowsValue,
		DeviceIDAnomalyNextObjectWithoutMoreFollows,
	)
	if !result.Complete || len(result.Objects) != 4 {
		t.Fatalf("odd more-follows aggregate = %+v", result)
	}
}

func TestTolerantDeviceIDMoreFollowsWithoutProgressStops(t *testing.T) {
	first, err := NewDeviceIDRequest(DeviceIDBasic, 0)
	if err != nil {
		t.Fatal(err)
	}
	page, err := DecodeDeviceIDPage(first, []byte{
		0x2b, 0x0e, 0x01, 0x01, 0xff, 0x00, 0x03,
		0x00, 0x01, 'V', 0x01, 0x01, 'P', 0x02, 0x01, 'R',
	})
	if err != nil {
		t.Fatal(err)
	}
	requireAnomalies(t, page.Anomalies, DeviceIDAnomalyMoreFollowsWithoutProgress)
	_, err = NextDeviceIDPageRequest(page)
	requireMalformedDeviceID(t, err, "next_object_id")
	result, err := AggregateTolerantDeviceID(first, []DeviceIDPage{page}, DefaultDeviceIDLimits())
	if err != nil {
		t.Fatal(err)
	}
	requireAnomalies(t, result.Anomalies,
		DeviceIDAnomalyMoreFollowsWithoutProgress,
		DeviceIDAnomalyContinuationUnavailable,
	)
	if result.Complete || len(result.Objects) != 3 {
		t.Fatalf("no-progress aggregate = %+v", result)
	}
}

func extendedTestPage(t *testing.T, request DeviceIDRequest, more byte, next byte, objectIDs ...byte) DeviceIDPage {
	t.Helper()
	pdu := []byte{0x2b, 0x0e, 0x03, 0x83, more, next, byte(len(objectIDs))}
	for _, objectID := range objectIDs {
		pdu = append(pdu, objectID, 1, objectID)
	}
	page, err := DecodeDeviceIDPage(request, pdu)
	if err != nil {
		t.Fatal(err)
	}
	return page
}

func TestTolerantDeviceIDPageLimitBoundsTraversal(t *testing.T) {
	first, err := NewExtendedDeviceIDStreamRequest(0x80)
	if err != nil {
		t.Fatal(err)
	}
	limits := DefaultDeviceIDLimits()
	limits.MaxSegments = 3
	var pages []DeviceIDPage
	request := first
	for index := 0; index < 4; index++ {
		objectID := byte(0x80 + index)
		page := extendedTestPage(t, request, 0xff, objectID+1, objectID)
		pages = append(pages, page)
		if request, err = NextDeviceIDPageRequest(page); err != nil {
			t.Fatal(err)
		}
	}
	result, err := AggregateTolerantDeviceID(first, pages[:3], limits)
	if err != nil {
		t.Fatal(err)
	}
	requireAnomalies(t, result.Anomalies, DeviceIDAnomalyPageLimitReached)
	if result.Complete || len(result.Pages) != 3 || len(result.Objects) != 3 {
		t.Fatalf("page-limited aggregate = %+v", result)
	}
	_, err = AggregateTolerantDeviceID(first, pages, limits)
	requireMalformedDeviceID(t, err, "segment_count")
	_, err = AggregateTolerantDeviceID(first, pages[:2], limits)
	requireMalformedDeviceID(t, err, "missing_continuation")
}

func TestTolerantDeviceIDAggregateLimitStopsTraversal(t *testing.T) {
	first, err := NewExtendedDeviceIDStreamRequest(0x80)
	if err != nil {
		t.Fatal(err)
	}
	page := extendedTestPage(t, first, 0xff, 0x83, 0x80, 0x81, 0x82)
	limits := DefaultDeviceIDLimits()
	limits.MaxObjects = 2
	result, err := AggregateTolerantDeviceID(first, []DeviceIDPage{page}, limits)
	if err != nil {
		t.Fatal(err)
	}
	requireAnomalies(t, result.Anomalies, DeviceIDAnomalyAggregateLimitReached)
	if result.Complete || len(result.Objects) != 2 || len(result.Pages[0].Objects) != 3 {
		t.Fatalf("object-limited aggregate = %+v", result)
	}
	limits = DefaultDeviceIDLimits()
	limits.MaxValueBytes = 2
	result, err = AggregateTolerantDeviceID(first, []DeviceIDPage{page}, limits)
	if err != nil {
		t.Fatal(err)
	}
	if !result.HasAnomaly(DeviceIDAnomalyAggregateLimitReached) || result.Complete || len(result.Objects) != 2 {
		t.Fatalf("value-limited aggregate = %+v", result)
	}
}

func TestTolerantDeviceIDDuplicateAcrossPagesKeepsFirst(t *testing.T) {
	first, err := NewExtendedDeviceIDStreamRequest(0x80)
	if err != nil {
		t.Fatal(err)
	}
	pageOne := extendedTestPage(t, first, 0xff, 0x81, 0x80)
	second, err := NextDeviceIDPageRequest(pageOne)
	if err != nil {
		t.Fatal(err)
	}
	pdu := []byte{0x2b, 0x0e, 0x03, 0x83, 0x00, 0x00, 0x02, 0x80, 0x01, 'x', 0x81, 0x01, 'y'}
	pageTwo, err := DecodeDeviceIDPage(second, pdu)
	if err != nil {
		t.Fatal(err)
	}
	result, err := AggregateTolerantDeviceID(first, []DeviceIDPage{pageOne, pageTwo}, DefaultDeviceIDLimits())
	if err != nil {
		t.Fatal(err)
	}
	requireAnomalies(t, result.Anomalies, DeviceIDAnomalyDuplicateObject)
	if !result.Complete || len(result.Objects) != 2 ||
		!bytes.Equal(result.Objects[0].Value, []byte{0x80}) || result.Objects[1].ID != 0x81 {
		t.Fatalf("duplicate aggregate = %+v", result)
	}
}

func TestTolerantDeviceIDTruncatedObjectKeepsUndecodedBytes(t *testing.T) {
	request, err := NewDeviceIDRequest(DeviceIDBasic, 0)
	if err != nil {
		t.Fatal(err)
	}
	pdu := []byte{
		0x2b, 0x0e, 0x01, 0x01, 0x00, 0x00, 0x03,
		0x00, 0x01, 'V', 0x01, 0x01, 'P',
		0x02, 0x0a, 'R', 'E', 'V',
	}
	page, err := DecodeDeviceIDPage(request, pdu)
	if err != nil {
		t.Fatal(err)
	}
	requireAnomalies(t, page.Anomalies, DeviceIDAnomalyTruncatedObject, DeviceIDAnomalyObjectCountMismatch)
	if len(page.Objects) != 2 || page.UndecodedOffset != 13 || !bytes.Equal(page.PDU[page.UndecodedOffset:], []byte{0x02, 0x0a, 'R', 'E', 'V'}) {
		t.Fatalf("truncated page = %+v", page)
	}
	oneByte, err := DecodeDeviceIDPage(request, append(pdu[:13:13], 0x02))
	if err != nil {
		t.Fatal(err)
	}
	if !oneByte.HasAnomaly(DeviceIDAnomalyTruncatedObject) || oneByte.UndecodedOffset != 13 {
		t.Fatalf("one trailing byte = %+v", oneByte)
	}
}

func TestTolerantDeviceIDHeaderDeviationsAreAnomalies(t *testing.T) {
	request, err := NewDeviceIDRequest(DeviceIDRegular, 0)
	if err != nil {
		t.Fatal(err)
	}
	page, err := DecodeDeviceIDPage(request, []byte{
		0x2b, 0x0e, 0x01, 0x07, 0x00, 0x00, 0x03,
		0x02, 0x01, 'R', 0x00, 0x01, 'V', 0x00, 0x01, 'W',
	})
	if err != nil {
		t.Fatal(err)
	}
	requireAnomalies(t, page.Anomalies,
		DeviceIDAnomalyAccessCodeMismatch,
		DeviceIDAnomalyConformityValue,
		DeviceIDAnomalyObjectOrder,
		DeviceIDAnomalyDuplicateObject,
	)
	individual, err := NewDeviceIDRequest(DeviceIDIndividual, 0x81)
	if err != nil {
		t.Fatal(err)
	}
	other, err := DecodeDeviceIDPage(individual, []byte{0x2b, 0x0e, 0x04, 0x83, 0xff, 0x83, 0x01, 0x82, 0x01, 'x'})
	if err != nil {
		t.Fatal(err)
	}
	requireAnomalies(t, other.Anomalies, DeviceIDAnomalyObjectOutsideCategory)
	result, err := AggregateTolerantDeviceID(individual, []DeviceIDPage{other}, DefaultDeviceIDLimits())
	if err != nil {
		t.Fatal(err)
	}
	if result.Complete || !result.HasAnomaly(DeviceIDAnomalyContinuationUnavailable) {
		t.Fatalf("individual more-follows aggregate = %+v", result)
	}
}

func TestTolerantDeviceIDExtendedStreamWrapsOnce(t *testing.T) {
	first, err := NewExtendedDeviceIDStreamRequest(0xfe)
	if err != nil {
		t.Fatal(err)
	}
	pageOne := extendedTestPage(t, first, 0xff, 0x00, 0xfe, 0xff)
	if len(pageOne.Anomalies) != 0 {
		t.Fatalf("0xff to 0x00 wrap flagged: %v", pageOne.Anomalies)
	}
	second, err := NextDeviceIDPageRequest(pageOne)
	if err != nil || second.ObjectID() != 0x00 {
		t.Fatalf("wrap continuation = %#v err=%v", second, err)
	}
	pageTwo := extendedTestPage(t, second, 0xff, 0x01, 0x00)
	third, err := NextDeviceIDPageRequest(pageTwo)
	if err != nil {
		t.Fatal(err)
	}
	pageThree := extendedTestPage(t, third, 0xff, 0x00, 0x01)
	if !pageThree.HasAnomaly(DeviceIDAnomalyMoreFollowsWithoutProgress) {
		t.Fatalf("backward cursor not flagged: %v", pageThree.Anomalies)
	}
	_, err = NextDeviceIDPageRequest(pageThree)
	requireMalformedDeviceID(t, err, "next_object_id")
	result, err := AggregateTolerantDeviceID(first, []DeviceIDPage{pageOne, pageTwo, pageThree}, DefaultDeviceIDLimits())
	if err != nil {
		t.Fatal(err)
	}
	if result.Complete || !result.HasAnomaly(DeviceIDAnomalyContinuationUnavailable) || len(result.Objects) != 4 {
		t.Fatalf("second wrap aggregate = %+v", result)
	}
}

func TestTolerantDeviceIDRejectedRepliesKeepBytes(t *testing.T) {
	request, err := NewDeviceIDRequest(DeviceIDBasic, 0)
	if err != nil {
		t.Fatal(err)
	}
	exception, err := DecodeDeviceIDPage(request, []byte{0xab, 0x02})
	var protocolErr *ProtocolError
	if !errors.As(err, &protocolErr) || protocolErr.Kind != ErrorExceptionResponse || protocolErr.ExceptionCode != 2 ||
		!bytes.Equal(exception.PDU, []byte{0xab, 0x02}) {
		t.Fatalf("exception page=%+v err=%#v", exception, err)
	}
	oversized := append([]byte{0x2b, 0x0e, 0x01, 0x01, 0, 0, 0}, make([]byte, MaxTolerantPDUSize)...)
	for _, test := range []struct {
		name  string
		pdu   []byte
		field string
	}{
		{"empty", nil, "function"},
		{"exception length", []byte{0xab, 0x02, 0x00}, "exception_length"},
		{"function", []byte{0x03, 0x02, 0x00, 0x01}, "function_mismatch"},
		{"short header", []byte{0x2b, 0x0e, 0x01, 0x01, 0x00}, "response_length"},
		{"above tolerant bound", oversized, "response_length"},
		{"mei type", []byte{0x2b, 0x0d, 0x01, 0x01, 0x00, 0x00, 0x00}, "mei_type"},
	} {
		t.Run(test.name, func(t *testing.T) {
			page, err := DecodeDeviceIDPage(request, test.pdu)
			requireMalformedDeviceID(t, err, test.field)
			if !bytes.Equal(page.PDU, test.pdu) || len(page.Objects) != 0 || page.Request != request {
				t.Fatalf("rejected page lost bytes: %+v", page)
			}
		})
	}
	if _, err := DecodeDeviceIDPage(DeviceIDRequest{}, []byte{0x2b}); err == nil {
		t.Fatal("invalid request decoded")
	}
}

func TestTolerantDeviceIDAggregationValidatesTheChain(t *testing.T) {
	fixture := loadLoggerFixture(t)
	first, pages := loggerInventoryPages(t, fixture)
	limits := DefaultDeviceIDLimits()
	swapped := append([]DeviceIDPage(nil), pages...)
	swapped[1], swapped[2] = swapped[2], swapped[1]
	_, err := AggregateTolerantDeviceID(first, swapped, limits)
	requireMalformedDeviceID(t, err, "continuation_request")
	basic, err := NewDeviceIDRequest(DeviceIDBasic, 0)
	if err != nil {
		t.Fatal(err)
	}
	basicPage, err := DecodeDeviceIDPage(basic, fixture.exchange(t, "basic_unit_0").pdu(t))
	if err != nil {
		t.Fatal(err)
	}
	_, err = AggregateTolerantDeviceID(basic, []DeviceIDPage{basicPage, basicPage}, limits)
	requireMalformedDeviceID(t, err, "trailing_segment")
	_, err = AggregateTolerantDeviceID(pages[1].Request, pages[1:], limits)
	var protocolErr *ProtocolError
	if !errors.As(err, &protocolErr) || protocolErr.Field != "initial_cursor" {
		t.Fatalf("continuation start err=%#v", err)
	}
	_, err = AggregateTolerantDeviceID(first, pages, DeviceIDLimits{})
	if !errors.As(err, &protocolErr) || protocolErr.Field != "aggregation_limits" {
		t.Fatalf("invalid limits err=%#v", err)
	}
	_, err = AggregateTolerantDeviceID(first, nil, limits)
	requireMalformedDeviceID(t, err, "segment_count")
	exception := pages[3]
	exception.PDU = []byte{0xab, 0x04}
	_, err = AggregateTolerantDeviceID(first, append(append([]DeviceIDPage(nil), pages[:3]...), exception), limits)
	if !errors.As(err, &protocolErr) || protocolErr.Kind != ErrorExceptionResponse {
		t.Fatalf("exception page err=%#v", err)
	}
}

func TestTolerantDeviceIDPagingFollowsBytesNotViews(t *testing.T) {
	fixture := loadLoggerFixture(t)
	first, pages := loggerInventoryPages(t, fixture)
	forged := make([]DeviceIDPage, len(pages))
	for index, page := range pages {
		page.MoreFollowsValue = 0
		page.NextObjectID = 0
		page.Objects = nil
		page.Anomalies = nil
		forged[index] = page
	}
	if _, err := NextDeviceIDPageRequest(forged[0]); err != nil {
		t.Fatalf("forged view changed paging: %v", err)
	}
	result, err := AggregateTolerantDeviceID(first, forged, DefaultDeviceIDLimits())
	if err != nil {
		t.Fatal(err)
	}
	reference, err := AggregateTolerantDeviceID(first, pages, DefaultDeviceIDLimits())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(result, reference) {
		t.Fatal("aggregation trusted forged page views")
	}
}

func TestTolerantDeviceIDResultsAreIndependentCopies(t *testing.T) {
	fixture := loadLoggerFixture(t)
	first, pages := loggerInventoryPages(t, fixture)
	result, err := AggregateTolerantDeviceID(first, pages, DefaultDeviceIDLimits())
	if err != nil {
		t.Fatal(err)
	}
	pages[1].PDU[9] = 0xee
	pages[1].Objects[0].Value[0] = 0xee
	if !bytes.Equal(result.Pages[1].PDU, fixture.inventoryPage(t, 0x88).pdu(t)) ||
		result.Objects[1].Value[0] == 0xee {
		t.Fatal("aggregate shares memory with its input pages")
	}
	again, err := AggregateTolerantDeviceID(first, pages, DefaultDeviceIDLimits())
	if err != nil {
		t.Fatal(err)
	}
	result.Pages[2].PDU[9] = 0xee
	result.Objects[2].Value[0] = 0xee
	result.Anomalies[0] = "mutated"
	if again.Pages[2].PDU[9] == 0xee || again.Objects[2].Value[0] == 0xee || again.Anomalies[0] == "mutated" {
		t.Fatal("aggregates share memory with each other")
	}
	if again.Pages[1].PDU[9] != 0xee || again.Objects[1].Value[0] != 0xee {
		t.Fatal("aggregation did not follow the received bytes")
	}
	page, err := DecodeDeviceIDPage(first, fixture.inventoryPage(t, 0x87).pdu(t))
	if err != nil {
		t.Fatal(err)
	}
	copied := cloneDeviceIDPage(page)
	copied.PDU[0] = 0
	copied.Objects[0].Value[0] = 0
	copied.Anomalies[0] = "mutated"
	if page.PDU[0] != byte(FunctionEncapsulatedInterface) || page.Objects[0].Value[0] != 12 ||
		page.Anomalies[0] != DeviceIDAnomalyObjectCountMismatch {
		t.Fatal("page clone shares memory")
	}
}

func TestStrictDeviceIDDecodingIsTheZeroValue(t *testing.T) {
	var decoding DeviceIDDecoding
	if decoding != DeviceIDDecodingStrict || !validDeviceIDDecoding(DeviceIDDecodingTolerant) ||
		validDeviceIDDecoding(DeviceIDDecoding(2)) {
		t.Fatal("device-id decoding values changed")
	}
	var framing TCPFraming
	if framing != TCPFramingStrict || validTCPFraming(TCPFraming(2)) {
		t.Fatal("tcp framing values changed")
	}
}
