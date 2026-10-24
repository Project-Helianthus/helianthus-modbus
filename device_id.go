package modbus

const (
	deviceIDMEIType             = 0x0e
	maxDeviceIDSegments         = 256
	maxDeviceIDObjects          = 256
	maxDeviceIDObjectValueBytes = 244
	maxDeviceIDAggregateBytes   = 62464
)

// DeviceIDAccess is a Read Device Identification access code.
type DeviceIDAccess byte

const (
	DeviceIDBasic      DeviceIDAccess = 0x01
	DeviceIDRegular    DeviceIDAccess = 0x02
	DeviceIDExtended   DeviceIDAccess = 0x03
	DeviceIDIndividual DeviceIDAccess = 0x04
)

// DeviceIDConformity is the exact conformity byte returned by the peer.
type DeviceIDConformity byte

// DeviceIDRequest is an exact FC2B/MEI0E request.
type DeviceIDRequest struct {
	access       DeviceIDAccess
	objectID     byte
	continuation bool
	extended     bool
	wrapped      bool
}

// DeviceIDObject retains an object's exact length-delimited bytes.
type DeviceIDObject struct {
	ID    byte
	Value []byte
}

// DeviceIDSegment is one validated response segment with request provenance.
type DeviceIDSegment struct {
	request      DeviceIDRequest
	conformity   DeviceIDConformity
	moreFollows  bool
	nextObjectID byte
	objects      []DeviceIDObject
	decoded      bool
}

// Request returns the exact request identity associated with the segment.
func (segment DeviceIDSegment) Request() DeviceIDRequest {
	return segment.request
}

// Conformity returns the exact peer conformity byte.
func (segment DeviceIDSegment) Conformity() DeviceIDConformity {
	return segment.conformity
}

// MoreFollows reports whether the peer supplied a continuation cursor.
func (segment DeviceIDSegment) MoreFollows() bool {
	return segment.moreFollows
}

// NextObjectID returns the peer-supplied continuation cursor.
func (segment DeviceIDSegment) NextObjectID() byte {
	return segment.nextObjectID
}

// Objects returns a deep copy of the exact object bytes.
func (segment DeviceIDSegment) Objects() []DeviceIDObject {
	return cloneDeviceIDObjects(segment.objects)
}

// DeviceIDLimits bounds traversal work and aggregate allocation.
type DeviceIDLimits struct {
	MaxSegments   int
	MaxObjects    int
	MaxValueBytes int
}

// DeviceIDResult is published only after a complete valid traversal.
type DeviceIDResult struct {
	Conformity DeviceIDConformity
	Objects    []DeviceIDObject
	Segments   []DeviceIDSegment
}

// DefaultDeviceIDLimits returns the closed V1 aggregation bounds.
func DefaultDeviceIDLimits() DeviceIDLimits {
	return DeviceIDLimits{
		MaxSegments:   maxDeviceIDSegments,
		MaxObjects:    maxDeviceIDObjects,
		MaxValueBytes: maxDeviceIDAggregateBytes,
	}
}

// NewDeviceIDRequest validates the Device Identification access code.
func NewDeviceIDRequest(
	access DeviceIDAccess,
	objectID byte,
) (DeviceIDRequest, error) {
	if !validDeviceIDAccess(access) {
		return DeviceIDRequest{}, protocolError(
			ErrorInvalidRequest,
			FunctionEncapsulatedInterface,
			0,
			"read_device_id_code",
			2,
		)
	}
	if access != DeviceIDIndividual && objectID != 0 {
		return DeviceIDRequest{}, protocolError(
			ErrorInvalidRequest,
			FunctionEncapsulatedInterface,
			0,
			"initial_cursor",
			3,
		)
	}
	return DeviceIDRequest{access: access, objectID: objectID}, nil
}

// NewExtendedDeviceIDStreamRequest starts an opaque code-03 object stream.
func NewExtendedDeviceIDStreamRequest(
	objectID byte,
) (DeviceIDRequest, error) {
	request := DeviceIDRequest{
		access:   DeviceIDExtended,
		objectID: objectID,
		extended: true,
	}
	if err := validateDeviceIDRequest(request); err != nil {
		return DeviceIDRequest{}, err
	}
	return request, nil
}

// NextDeviceIDRequest binds a continuation request to its prior segment.
func NextDeviceIDRequest(segment DeviceIDSegment) (DeviceIDRequest, error) {
	if err := validateDeviceIDSegment(segment); err != nil {
		return DeviceIDRequest{}, err
	}
	if segment.request.access == DeviceIDIndividual || !segment.moreFollows {
		return DeviceIDRequest{}, protocolError(
			ErrorInvalidRequest,
			FunctionEncapsulatedInterface,
			0,
			"continuation_unavailable",
			-1,
		)
	}
	wrapped := segment.request.wrapped
	if segment.request.extended {
		var err error
		wrapped, err = validateExtendedDeviceIDProgress(segment, wrapped)
		if err != nil {
			return DeviceIDRequest{}, err
		}
	}
	return DeviceIDRequest{
		access:       segment.request.access,
		objectID:     segment.nextObjectID,
		continuation: true,
		extended:     segment.request.extended,
		wrapped:      wrapped,
	}, nil
}

// Access returns the validated access code.
func (request DeviceIDRequest) Access() DeviceIDAccess {
	return request.access
}

// ObjectID returns the requested object or stream cursor.
func (request DeviceIDRequest) ObjectID() byte {
	return request.objectID
}

// EncodePDU validates the request again and returns a new exact PDU.
func (request DeviceIDRequest) EncodePDU() ([]byte, error) {
	if err := validateDeviceIDRequest(request); err != nil {
		return nil, err
	}
	return []byte{
		byte(FunctionEncapsulatedInterface),
		deviceIDMEIType,
		byte(request.access),
		request.objectID,
	}, nil
}

// DecodeDeviceIDSegment validates and decodes one exact response PDU.
func DecodeDeviceIDSegment(
	request DeviceIDRequest,
	pdu []byte,
) (DeviceIDSegment, error) {
	if err := validateDeviceIDRequest(request); err != nil {
		return DeviceIDSegment{}, err
	}
	if len(pdu) == 0 {
		return DeviceIDSegment{}, malformedDeviceID(
			request,
			0,
			"function",
			0,
		)
	}
	received := FunctionCode(pdu[0])
	if received == FunctionEncapsulatedInterface|0x80 {
		if len(pdu) != 2 {
			return DeviceIDSegment{}, malformedDeviceID(
				request,
				received,
				"exception_length",
				len(pdu),
			)
		}
		err := protocolError(
			ErrorExceptionResponse,
			FunctionEncapsulatedInterface,
			received,
			"exception_code",
			1,
		)
		err.ExceptionCode = pdu[1]
		return DeviceIDSegment{}, err
	}
	if len(pdu) < 7 || len(pdu) > MaxPDUSize {
		return DeviceIDSegment{}, malformedDeviceID(
			request,
			received,
			"response_length",
			len(pdu),
		)
	}
	if received != FunctionEncapsulatedInterface {
		return DeviceIDSegment{}, malformedDeviceID(
			request,
			received,
			"function_mismatch",
			0,
		)
	}
	if pdu[1] != deviceIDMEIType {
		return DeviceIDSegment{}, malformedDeviceID(
			request,
			received,
			"mei_type",
			1,
		)
	}
	if DeviceIDAccess(pdu[2]) != request.access {
		return DeviceIDSegment{}, malformedDeviceID(
			request,
			received,
			"read_device_id_code",
			2,
		)
	}
	conformity := DeviceIDConformity(pdu[3])
	if !validDeviceIDConformity(conformity) {
		return DeviceIDSegment{}, malformedDeviceID(
			request,
			received,
			"conformity_level",
			3,
		)
	}
	moreFollows, valid := decodeMoreFollows(pdu[4])
	if !valid {
		return DeviceIDSegment{}, malformedDeviceID(
			request,
			received,
			"more_follows",
			4,
		)
	}
	nextObjectID := pdu[5]
	if (!moreFollows && nextObjectID != 0) ||
		(moreFollows && nextObjectID == 0 && !request.extended) {
		return DeviceIDSegment{}, malformedDeviceID(
			request,
			received,
			"next_object_id",
			5,
		)
	}
	objectCount := int(pdu[6])
	if moreFollows && objectCount == 0 {
		return DeviceIDSegment{}, malformedDeviceID(
			request,
			received,
			"number_of_objects",
			6,
		)
	}
	objects := make([]DeviceIDObject, 0, objectCount)
	cursor := 7
	for index := 0; index < objectCount; index++ {
		if cursor+2 > len(pdu) {
			return DeviceIDSegment{}, malformedDeviceID(
				request,
				received,
				"object_header",
				cursor,
			)
		}
		objectID := pdu[cursor]
		valueLength := int(pdu[cursor+1])
		cursor += 2
		if valueLength > maxDeviceIDObjectValueBytes || cursor+valueLength > len(pdu) {
			return DeviceIDSegment{}, malformedDeviceID(
				request,
				received,
				"object_value",
				cursor,
			)
		}
		value := append([]byte(nil), pdu[cursor:cursor+valueLength]...)
		cursor += valueLength
		objects = append(objects, DeviceIDObject{ID: objectID, Value: value})
	}
	if cursor != len(pdu) {
		return DeviceIDSegment{}, malformedDeviceID(
			request,
			received,
			"trailing_bytes",
			cursor,
		)
	}
	segment := DeviceIDSegment{
		request:      request,
		conformity:   conformity,
		moreFollows:  moreFollows,
		nextObjectID: nextObjectID,
		objects:      objects,
		decoded:      true,
	}
	if err := validateDeviceIDSegment(segment); err != nil {
		return DeviceIDSegment{}, err
	}
	return segment, nil
}

// AggregateDeviceID validates a complete stream and returns no partial result.
func AggregateDeviceID(
	firstRequest DeviceIDRequest,
	segments []DeviceIDSegment,
	limits DeviceIDLimits,
) (DeviceIDResult, error) {
	return aggregateDeviceID(firstRequest, segments, limits, false)
}

// AggregateExtendedDeviceIDStream validates one complete arbitrary-start stream.
func AggregateExtendedDeviceIDStream(
	firstRequest DeviceIDRequest,
	segments []DeviceIDSegment,
	limits DeviceIDLimits,
) (DeviceIDResult, error) {
	return aggregateDeviceID(firstRequest, segments, limits, true)
}

func aggregateDeviceID(
	firstRequest DeviceIDRequest,
	segments []DeviceIDSegment,
	limits DeviceIDLimits,
	extended bool,
) (DeviceIDResult, error) {
	if err := validateDeviceIDLimits(limits); err != nil {
		return DeviceIDResult{}, err
	}
	standardInvalid := firstRequest.access == DeviceIDIndividual ||
		!validDeviceIDAccess(firstRequest.access) ||
		firstRequest.objectID != 0 ||
		firstRequest.extended
	extendedInvalid := firstRequest.access != DeviceIDExtended ||
		!firstRequest.extended ||
		firstRequest.continuation ||
		firstRequest.wrapped
	if (!extended && standardInvalid) || (extended && extendedInvalid) {
		return DeviceIDResult{}, protocolError(
			ErrorInvalidRequest,
			FunctionEncapsulatedInterface,
			0,
			"initial_cursor",
			3,
		)
	}
	if len(segments) == 0 || len(segments) > limits.MaxSegments {
		return DeviceIDResult{}, malformedDeviceID(
			firstRequest,
			0,
			"segment_count",
			-1,
		)
	}

	expectedRequest := firstRequest
	seen := make(map[byte]struct{}, len(segments))
	objects := make([]DeviceIDObject, 0)
	copiedSegments := make([]DeviceIDSegment, 0, len(segments))
	valueBytes := 0
	var conformity DeviceIDConformity
	var previousObjectID byte
	havePreviousObject := false
	wrapped := false

	for index, segment := range segments {
		if segment.request != expectedRequest {
			return DeviceIDResult{}, malformedDeviceID(
				expectedRequest,
				0,
				"continuation_request",
				-1,
			)
		}
		if err := validateDeviceIDSegment(segment); err != nil {
			return DeviceIDResult{}, err
		}
		if index == 0 {
			conformity = segment.conformity
		} else if segment.conformity != conformity {
			return DeviceIDResult{}, malformedDeviceID(
				expectedRequest,
				0,
				"conformity_change",
				3,
			)
		}
		copiedSegment := segment
		copiedSegment.objects = cloneDeviceIDObjects(segment.objects)
		copiedSegments = append(copiedSegments, copiedSegment)

		for _, object := range segment.objects {
			_, duplicate := seen[object.ID]
			progressValid := true
			if havePreviousObject {
				if extended {
					var nextWrapped bool
					nextWrapped, progressValid = advanceExtendedDeviceIDObject(
						previousObjectID,
						object.ID,
						wrapped,
					)
					wrapped = nextWrapped
				} else {
					progressValid = object.ID > previousObjectID
				}
			}
			if duplicate || !progressValid {
				return DeviceIDResult{}, malformedDeviceID(
					expectedRequest,
					0,
					"object_progress",
					-1,
				)
			}
			if len(objects) == limits.MaxObjects ||
				len(object.Value) > limits.MaxValueBytes-valueBytes {
				return DeviceIDResult{}, malformedDeviceID(
					expectedRequest,
					0,
					"aggregate_limit",
					-1,
				)
			}
			seen[object.ID] = struct{}{}
			previousObjectID = object.ID
			havePreviousObject = true
			valueBytes += len(object.Value)
			objects = append(objects, DeviceIDObject{
				ID:    object.ID,
				Value: append([]byte(nil), object.Value...),
			})
		}

		last := index == len(segments)-1
		if segment.moreFollows {
			if last {
				return DeviceIDResult{}, malformedDeviceID(
					expectedRequest,
					0,
					"missing_continuation",
					-1,
				)
			}
			nextRequest, err := NextDeviceIDRequest(segment)
			if err != nil {
				return DeviceIDResult{}, err
			}
			expectedRequest = nextRequest
		} else if !last {
			return DeviceIDResult{}, malformedDeviceID(
				expectedRequest,
				0,
				"trailing_segment",
				-1,
			)
		}
	}
	if !extended {
		for objectID := byte(0); objectID <= 2; objectID++ {
			if _, exists := seen[objectID]; !exists {
				return DeviceIDResult{}, malformedDeviceID(
					firstRequest,
					0,
					"mandatory_basic_object",
					-1,
				)
			}
		}
	}
	return DeviceIDResult{
		Conformity: conformity,
		Objects:    objects,
		Segments:   copiedSegments,
	}, nil
}

func validateDeviceIDLimits(limits DeviceIDLimits) error {
	if limits.MaxSegments < 1 ||
		limits.MaxSegments > maxDeviceIDSegments ||
		limits.MaxObjects < 1 ||
		limits.MaxObjects > maxDeviceIDObjects ||
		limits.MaxValueBytes < 1 ||
		limits.MaxValueBytes > maxDeviceIDAggregateBytes {
		return protocolError(
			ErrorInvalidRequest,
			FunctionEncapsulatedInterface,
			0,
			"aggregation_limits",
			-1,
		)
	}
	return nil
}

func validateDeviceIDSegment(segment DeviceIDSegment) error {
	request := segment.request
	if !segment.decoded ||
		validateDeviceIDRequest(request) != nil ||
		!validDeviceIDConformity(segment.conformity) {
		return malformedDeviceID(request, 0, "segment_identity", -1)
	}
	if len(segment.objects) > 0xff {
		return malformedDeviceID(request, 0, "number_of_objects", 6)
	}
	if (!segment.moreFollows && segment.nextObjectID != 0) ||
		(segment.moreFollows && segment.nextObjectID == 0 && !request.extended) ||
		(segment.moreFollows && len(segment.objects) == 0) {
		return malformedDeviceID(request, 0, "continuation", -1)
	}
	if request.access == DeviceIDIndividual {
		if segment.conformity&0x80 == 0 ||
			segment.moreFollows ||
			segment.nextObjectID != 0 ||
			len(segment.objects) != 1 ||
			segment.objects[0].ID != request.objectID {
			return malformedDeviceID(request, 0, "individual_response", -1)
		}
	}
	if request.extended {
		_, err := validateExtendedDeviceIDProgress(segment, request.wrapped)
		return err
	}
	var previous byte
	encodedSize := 7
	for index, object := range segment.objects {
		if len(object.Value) > maxDeviceIDObjectValueBytes {
			return malformedDeviceID(request, 0, "object_value_length", -1)
		}
		encodedSize += 2 + len(object.Value)
		if encodedSize > MaxPDUSize {
			return malformedDeviceID(request, 0, "segment_pdu_length", -1)
		}
		if index > 0 && object.ID <= previous {
			return malformedDeviceID(request, 0, "object_order", -1)
		}
		if object.ID >= 0x07 && object.ID < 0x80 {
			return malformedDeviceID(request, 0, "reserved_object_id", -1)
		}
		if request.access != DeviceIDIndividual &&
			(index == 0 && object.ID < request.objectID ||
				!objectAllowedByAccess(object.ID, request.access)) {
			return malformedDeviceID(request, 0, "requested_category", -1)
		}
		if !objectAllowedByConformity(object.ID, segment.conformity) {
			return malformedDeviceID(request, 0, "conformity_category", -1)
		}
		previous = object.ID
	}
	if segment.moreFollows {
		lastObjectID := segment.objects[len(segment.objects)-1].ID
		if segment.nextObjectID <= lastObjectID ||
			segment.nextObjectID >= 0x07 && segment.nextObjectID < 0x80 ||
			!objectAllowedByAccess(segment.nextObjectID, request.access) ||
			!objectAllowedByConformity(segment.nextObjectID, segment.conformity) {
			return malformedDeviceID(request, 0, "next_object_id", -1)
		}
	}
	return nil
}

func validateExtendedDeviceIDProgress(
	segment DeviceIDSegment,
	wrapped bool,
) (bool, error) {
	request := segment.request
	if !request.extended ||
		request.access != DeviceIDExtended ||
		segment.conformity&0x7f != DeviceIDConformity(DeviceIDExtended) {
		return wrapped, malformedDeviceID(
			request,
			0,
			"extended_stream_identity",
			-1,
		)
	}
	previous := request.objectID
	haveObject := false
	encodedSize := 7
	seen := make(map[byte]struct{}, len(segment.objects))
	for _, object := range segment.objects {
		if len(object.Value) > maxDeviceIDObjectValueBytes {
			return wrapped, malformedDeviceID(
				request,
				0,
				"object_value_length",
				-1,
			)
		}
		encodedSize += 2 + len(object.Value)
		if encodedSize > MaxPDUSize {
			return wrapped, malformedDeviceID(
				request,
				0,
				"segment_pdu_length",
				-1,
			)
		}
		if _, duplicate := seen[object.ID]; duplicate {
			return wrapped, malformedDeviceID(
				request,
				0,
				"object_progress",
				-1,
			)
		}
		seen[object.ID] = struct{}{}
		if !haveObject && object.ID == previous {
			haveObject = true
			continue
		}
		nextWrapped, valid := advanceExtendedDeviceIDObject(
			previous,
			object.ID,
			wrapped,
		)
		if !valid {
			return wrapped, malformedDeviceID(
				request,
				0,
				"object_progress",
				-1,
			)
		}
		wrapped = nextWrapped
		previous = object.ID
		haveObject = true
	}
	if segment.moreFollows {
		nextWrapped, valid := advanceExtendedDeviceIDObject(
			previous,
			segment.nextObjectID,
			wrapped,
		)
		if !valid {
			return wrapped, malformedDeviceID(
				request,
				0,
				"next_object_id",
				5,
			)
		}
		wrapped = nextWrapped
	}
	return wrapped, nil
}

func advanceExtendedDeviceIDObject(
	previous byte,
	next byte,
	wrapped bool,
) (bool, bool) {
	if next > previous {
		return wrapped, true
	}
	if previous == 0xff && next == 0 && !wrapped {
		return true, true
	}
	return wrapped, false
}

func cloneDeviceIDObjects(objects []DeviceIDObject) []DeviceIDObject {
	cloned := make([]DeviceIDObject, len(objects))
	for index, object := range objects {
		cloned[index] = DeviceIDObject{
			ID:    object.ID,
			Value: append([]byte(nil), object.Value...),
		}
	}
	return cloned
}

func malformedDeviceID(
	request DeviceIDRequest,
	received FunctionCode,
	field string,
	offset int,
) *ProtocolError {
	return protocolError(
		ErrorMalformedResponse,
		FunctionEncapsulatedInterface,
		received,
		field,
		offset,
	)
}

func validDeviceIDAccess(access DeviceIDAccess) bool {
	return access >= DeviceIDBasic && access <= DeviceIDIndividual
}

func validateDeviceIDRequest(request DeviceIDRequest) error {
	if !validDeviceIDAccess(request.access) {
		return protocolError(
			ErrorInvalidRequest,
			FunctionEncapsulatedInterface,
			0,
			"read_device_id_code",
			2,
		)
	}
	if request.access == DeviceIDIndividual {
		if request.continuation || request.extended || request.wrapped {
			return protocolError(
				ErrorInvalidRequest,
				FunctionEncapsulatedInterface,
				0,
				"individual_continuation",
				-1,
			)
		}
		return nil
	}
	if request.extended {
		if request.access != DeviceIDExtended ||
			(!request.continuation && request.wrapped) {
			return protocolError(
				ErrorInvalidRequest,
				FunctionEncapsulatedInterface,
				0,
				"extended_stream_cursor",
				3,
			)
		}
		return nil
	}
	if (!request.continuation && request.objectID != 0) ||
		(request.continuation && request.objectID == 0) {
		return protocolError(
			ErrorInvalidRequest,
			FunctionEncapsulatedInterface,
			0,
			"stream_cursor",
			3,
		)
	}
	return nil
}

func validDeviceIDConformity(conformity DeviceIDConformity) bool {
	switch conformity {
	case 0x01, 0x02, 0x03, 0x81, 0x82, 0x83:
		return true
	default:
		return false
	}
}

func decodeMoreFollows(value byte) (bool, bool) {
	switch value {
	case 0x00:
		return false, true
	case 0xff:
		return true, true
	default:
		return false, false
	}
}

func objectAllowedByAccess(objectID byte, access DeviceIDAccess) bool {
	switch access {
	case DeviceIDBasic:
		return objectID <= 0x02
	case DeviceIDRegular:
		return objectID <= 0x06
	case DeviceIDExtended:
		return objectID <= 0x06 || objectID >= 0x80
	default:
		return true
	}
}

func objectAllowedByConformity(
	objectID byte,
	conformity DeviceIDConformity,
) bool {
	switch conformity & 0x7f {
	case 0x01:
		return objectID <= 0x02
	case 0x02:
		return objectID <= 0x06
	case 0x03:
		return objectID <= 0x06 || objectID >= 0x80
	default:
		return false
	}
}

// DeviceIDDecoding selects how an FC2B/MEI0E traversal decodes its pages.
type DeviceIDDecoding byte

const (
	// DeviceIDDecodingStrict validates every page against the Modbus
	// specification and publishes only a complete validated aggregate. It is
	// the zero value and the default for every existing caller.
	DeviceIDDecodingStrict DeviceIDDecoding = iota
	// DeviceIDDecodingTolerant keeps every page byte, decodes what parses,
	// reports deviations as named anomalies, and pages until more-follows is
	// zero within the traversal limits.
	DeviceIDDecodingTolerant
)

func validDeviceIDDecoding(decoding DeviceIDDecoding) bool {
	return decoding == DeviceIDDecodingStrict ||
		decoding == DeviceIDDecodingTolerant
}

// DeviceIDAnomaly names one deviation observed by tolerant decoding. The
// names are stable; consumers key on them.
type DeviceIDAnomaly string

// Page anomalies describe one response PDU.
const (
	// DeviceIDAnomalyOversizePage marks a PDU longer than MaxPDUSize.
	DeviceIDAnomalyOversizePage DeviceIDAnomaly = "oversize_page"
	// DeviceIDAnomalyCountOnlyPage marks a page whose only object has a
	// one-byte value while its header announces more objects than the page
	// carries: the page carries a count, not the objects it announces.
	DeviceIDAnomalyCountOnlyPage DeviceIDAnomaly = "count_only_page"
	// DeviceIDAnomalyObjectCountMismatch marks a number-of-objects field that
	// differs from the objects present in the page.
	DeviceIDAnomalyObjectCountMismatch DeviceIDAnomaly = "object_count_mismatch"
	// DeviceIDAnomalyObjectOutsideCategory marks an object outside the
	// requested access category, for example non-basic objects in a basic
	// reply, or a different object in an individual reply.
	DeviceIDAnomalyObjectOutsideCategory DeviceIDAnomaly = "object_outside_requested_category"
	// DeviceIDAnomalyObjectOutsideConformity marks an object outside the
	// category that the page's own conformity level declares.
	DeviceIDAnomalyObjectOutsideConformity DeviceIDAnomaly = "object_outside_conformity"
	// DeviceIDAnomalyReservedObjectID marks an object id in 0x07 to 0x7f.
	DeviceIDAnomalyReservedObjectID DeviceIDAnomaly = "reserved_object_id"
	// DeviceIDAnomalyOversizeObjectValue marks an object value longer than a
	// conforming PDU can carry.
	DeviceIDAnomalyOversizeObjectValue DeviceIDAnomaly = "oversize_object_value"
	// DeviceIDAnomalyObjectOrder marks object ids that do not ascend within
	// the page, apart from one 0xff to 0x00 wrap on an extended stream.
	DeviceIDAnomalyObjectOrder DeviceIDAnomaly = "object_order"
	// DeviceIDAnomalyDuplicateObject marks an object id seen earlier in the
	// page or traversal. The first occurrence is aggregated.
	DeviceIDAnomalyDuplicateObject DeviceIDAnomaly = "duplicate_object"
	// DeviceIDAnomalyTruncatedObject marks an object header or value that
	// runs past the end of the PDU. The bytes from UndecodedOffset onward
	// stay in the page undecoded.
	DeviceIDAnomalyTruncatedObject DeviceIDAnomaly = "truncated_object"
	// DeviceIDAnomalyAccessCodeMismatch marks a reply whose read device id
	// code differs from the request.
	DeviceIDAnomalyAccessCodeMismatch DeviceIDAnomaly = "access_code_mismatch"
	// DeviceIDAnomalyConformityValue marks an unknown conformity level byte.
	DeviceIDAnomalyConformityValue DeviceIDAnomaly = "conformity_value"
	// DeviceIDAnomalyMoreFollowsValue marks a more-follows byte that is
	// neither 0x00 nor 0xff. Any non-zero value continues the stream.
	DeviceIDAnomalyMoreFollowsValue DeviceIDAnomaly = "more_follows_value"
	// DeviceIDAnomalyNextObjectWithoutMoreFollows marks a non-zero next
	// object id on a page whose more-follows byte is zero.
	DeviceIDAnomalyNextObjectWithoutMoreFollows DeviceIDAnomaly = "next_object_without_more_follows"
	// DeviceIDAnomalyMoreFollowsWithoutProgress marks a page that sets
	// more-follows but carries no object or a next object id that does not
	// advance past its last object.
	DeviceIDAnomalyMoreFollowsWithoutProgress DeviceIDAnomaly = "more_follows_without_progress"
)

// Traversal anomalies describe the page sequence.
const (
	// DeviceIDAnomalyConformityChange marks a conformity level that differs
	// from the first page.
	DeviceIDAnomalyConformityChange DeviceIDAnomaly = "conformity_change"
	// DeviceIDAnomalyMandatoryObjectMissing marks a standard stream without
	// all of the basic objects 0x00 to 0x02.
	DeviceIDAnomalyMandatoryObjectMissing DeviceIDAnomaly = "mandatory_object_missing"
	// DeviceIDAnomalyContinuationUnavailable marks a page that sets
	// more-follows although no bounded continuation exists: individual
	// access, a cursor that does not advance, or a second extended wrap.
	DeviceIDAnomalyContinuationUnavailable DeviceIDAnomaly = "continuation_unavailable"
	// DeviceIDAnomalyPageLimitReached marks a traversal stopped at the page
	// limit while more-follows was still set.
	DeviceIDAnomalyPageLimitReached DeviceIDAnomaly = "page_limit_reached"
	// DeviceIDAnomalyAggregateLimitReached marks a traversal stopped at the
	// object-count or value-byte limit.
	DeviceIDAnomalyAggregateLimitReached DeviceIDAnomaly = "aggregate_limit_reached"
)

// DeviceIDPage is one tolerantly decoded FC2B/MEI0E response page. PDU holds
// every received byte; the other fields are views decoded from it. Paging and
// aggregation decode PDU again, so only the received bytes decide them.
type DeviceIDPage struct {
	Request          DeviceIDRequest
	PDU              []byte
	AccessCode       DeviceIDAccess
	Conformity       DeviceIDConformity
	MoreFollowsValue byte
	NextObjectID     byte
	DeclaredObjects  int
	Objects          []DeviceIDObject
	UndecodedOffset  int
	Anomalies        []DeviceIDAnomaly
}

// MoreFollows reports a non-zero more-follows byte.
func (page DeviceIDPage) MoreFollows() bool {
	return page.MoreFollowsValue != 0
}

// OversizePDU reports a PDU longer than MaxPDUSize.
func (page DeviceIDPage) OversizePDU() bool {
	return len(page.PDU) > MaxPDUSize
}

// HasAnomaly reports whether the page carries the named anomaly.
func (page DeviceIDPage) HasAnomaly(anomaly DeviceIDAnomaly) bool {
	return containsDeviceIDAnomaly(page.Anomalies, anomaly)
}

// DeviceIDTolerantResult is the outcome of one tolerant traversal. Complete
// is true only when the last page carried more-follows zero. Objects holds
// the first occurrence of each object id in page order; Pages keeps every
// page with all of its bytes; Anomalies lists each page and traversal
// anomaly once, in first-seen order.
type DeviceIDTolerantResult struct {
	Complete   bool
	Conformity DeviceIDConformity
	Objects    []DeviceIDObject
	Pages      []DeviceIDPage
	Anomalies  []DeviceIDAnomaly
}

// HasAnomaly reports whether the traversal carries the named anomaly.
func (result DeviceIDTolerantResult) HasAnomaly(anomaly DeviceIDAnomaly) bool {
	return containsDeviceIDAnomaly(result.Anomalies, anomaly)
}

// DecodeDeviceIDPage tolerantly decodes one FC2B/MEI0E response PDU of at
// most MaxTolerantPDUSize bytes. Deviations from the specification become
// named anomalies on the returned page. An exception reply, a different
// function, a different MEI type, or a PDU too short for the seven header
// bytes returns an error together with a page that still holds every byte.
func DecodeDeviceIDPage(
	request DeviceIDRequest,
	pdu []byte,
) (DeviceIDPage, error) {
	if err := validateDeviceIDRequest(request); err != nil {
		return DeviceIDPage{}, err
	}
	page := DeviceIDPage{
		Request: request,
		PDU:     cloneBytes(pdu),
	}
	if len(pdu) == 0 {
		return page, malformedDeviceID(request, 0, "function", 0)
	}
	received := FunctionCode(pdu[0])
	if received == FunctionEncapsulatedInterface|0x80 {
		if len(pdu) != 2 {
			return page, malformedDeviceID(
				request,
				received,
				"exception_length",
				len(pdu),
			)
		}
		err := protocolError(
			ErrorExceptionResponse,
			FunctionEncapsulatedInterface,
			received,
			"exception_code",
			1,
		)
		err.ExceptionCode = pdu[1]
		return page, err
	}
	if received != FunctionEncapsulatedInterface {
		return page, malformedDeviceID(
			request,
			received,
			"function_mismatch",
			0,
		)
	}
	if len(pdu) < 7 || len(pdu) > MaxTolerantPDUSize {
		return page, malformedDeviceID(
			request,
			received,
			"response_length",
			len(pdu),
		)
	}
	if pdu[1] != deviceIDMEIType {
		return page, malformedDeviceID(request, received, "mei_type", 1)
	}
	page.AccessCode = DeviceIDAccess(pdu[2])
	page.Conformity = DeviceIDConformity(pdu[3])
	page.MoreFollowsValue = pdu[4]
	page.NextObjectID = pdu[5]
	page.DeclaredObjects = int(pdu[6])
	var anomalies deviceIDAnomalySet
	if len(pdu) > MaxPDUSize {
		anomalies.add(DeviceIDAnomalyOversizePage)
	}
	if page.AccessCode != request.access {
		anomalies.add(DeviceIDAnomalyAccessCodeMismatch)
	}
	conformityKnown := validDeviceIDConformity(page.Conformity)
	if !conformityKnown {
		anomalies.add(DeviceIDAnomalyConformityValue)
	}
	if page.MoreFollowsValue != 0x00 && page.MoreFollowsValue != 0xff {
		anomalies.add(DeviceIDAnomalyMoreFollowsValue)
	}
	if !page.MoreFollows() && page.NextObjectID != 0 {
		anomalies.add(DeviceIDAnomalyNextObjectWithoutMoreFollows)
	}
	cursor := 7
	seen := make(map[byte]struct{})
	for cursor < len(pdu) {
		if cursor+2 > len(pdu) {
			anomalies.add(DeviceIDAnomalyTruncatedObject)
			break
		}
		objectID := pdu[cursor]
		valueLength := int(pdu[cursor+1])
		if cursor+2+valueLength > len(pdu) {
			anomalies.add(DeviceIDAnomalyTruncatedObject)
			break
		}
		if valueLength > maxDeviceIDObjectValueBytes {
			anomalies.add(DeviceIDAnomalyOversizeObjectValue)
		}
		if _, duplicate := seen[objectID]; duplicate {
			anomalies.add(DeviceIDAnomalyDuplicateObject)
		}
		seen[objectID] = struct{}{}
		if count := len(page.Objects); count > 0 {
			previous := page.Objects[count-1].ID
			if !deviceIDPageCursorAdvances(previous, objectID, request.extended) {
				anomalies.add(DeviceIDAnomalyObjectOrder)
			}
		}
		if objectID >= 0x07 && objectID < 0x80 {
			anomalies.add(DeviceIDAnomalyReservedObjectID)
		}
		if (request.access == DeviceIDIndividual &&
			objectID != request.objectID) ||
			(request.access != DeviceIDIndividual &&
				!objectAllowedByAccess(objectID, request.access)) {
			anomalies.add(DeviceIDAnomalyObjectOutsideCategory)
		}
		if conformityKnown &&
			!objectAllowedByConformity(objectID, page.Conformity) {
			anomalies.add(DeviceIDAnomalyObjectOutsideConformity)
		}
		page.Objects = append(page.Objects, DeviceIDObject{
			ID:    objectID,
			Value: append([]byte(nil), pdu[cursor+2:cursor+2+valueLength]...),
		})
		cursor += 2 + valueLength
	}
	page.UndecodedOffset = cursor
	if page.DeclaredObjects != len(page.Objects) {
		anomalies.add(DeviceIDAnomalyObjectCountMismatch)
	}
	if len(page.Objects) == 1 &&
		len(page.Objects[0].Value) == 1 &&
		page.DeclaredObjects > len(page.Objects) {
		anomalies.add(DeviceIDAnomalyCountOnlyPage)
	}
	if page.MoreFollows() {
		count := len(page.Objects)
		if count == 0 || !deviceIDPageCursorAdvances(
			page.Objects[count-1].ID,
			page.NextObjectID,
			request.extended,
		) {
			anomalies.add(DeviceIDAnomalyMoreFollowsWithoutProgress)
		}
	}
	page.Anomalies = anomalies.list
	return page, nil
}

// NextDeviceIDPageRequest binds a tolerant continuation request to a page.
// The page is decoded again from its PDU. Any non-zero more-follows value
// continues a stream; the next cursor must advance past the requested
// cursor, with at most one backward wrap on an extended stream, so every
// traversal terminates.
func NextDeviceIDPageRequest(page DeviceIDPage) (DeviceIDRequest, error) {
	decoded, err := DecodeDeviceIDPage(page.Request, page.PDU)
	if err != nil {
		return DeviceIDRequest{}, err
	}
	return nextDeviceIDPageRequest(decoded)
}

// AggregateTolerantDeviceID folds a complete tolerant page sequence. The
// sequence must start at firstRequest and follow each page's continuation.
// It ends at the first page with more-follows zero, or where the traversal
// stopped at a limit or at an unavailable continuation; those stops publish
// the decoded objects with Complete false and a traversal anomaly.
func AggregateTolerantDeviceID(
	firstRequest DeviceIDRequest,
	pages []DeviceIDPage,
	limits DeviceIDLimits,
) (DeviceIDTolerantResult, error) {
	traversal, err := newDeviceIDTolerantTraversal(firstRequest, limits)
	if err != nil {
		return DeviceIDTolerantResult{}, err
	}
	if len(pages) == 0 || len(pages) > limits.MaxSegments {
		return DeviceIDTolerantResult{}, malformedDeviceID(
			firstRequest,
			0,
			"segment_count",
			-1,
		)
	}
	for _, page := range pages {
		if err := traversal.add(page); err != nil {
			return DeviceIDTolerantResult{}, err
		}
	}
	return traversal.finish()
}

type deviceIDTolerantTraversal struct {
	limits     DeviceIDLimits
	expected   DeviceIDRequest
	result     DeviceIDTolerantResult
	anomalies  deviceIDAnomalySet
	seen       map[byte]struct{}
	valueBytes int
	closed     bool
}

func newDeviceIDTolerantTraversal(
	firstRequest DeviceIDRequest,
	limits DeviceIDLimits,
) (*deviceIDTolerantTraversal, error) {
	if err := validateDeviceIDLimits(limits); err != nil {
		return nil, err
	}
	if validateDeviceIDRequest(firstRequest) != nil ||
		firstRequest.continuation ||
		firstRequest.wrapped {
		return nil, protocolError(
			ErrorInvalidRequest,
			FunctionEncapsulatedInterface,
			0,
			"initial_cursor",
			3,
		)
	}
	return &deviceIDTolerantTraversal{
		limits:   limits,
		expected: firstRequest,
		seen:     make(map[byte]struct{}),
	}, nil
}

// add folds the next page. After it returns nil, the traversal is either
// closed or expects traversal.expected as the next request.
func (traversal *deviceIDTolerantTraversal) add(page DeviceIDPage) error {
	if traversal.closed {
		return malformedDeviceID(page.Request, 0, "trailing_segment", -1)
	}
	if page.Request != traversal.expected {
		return malformedDeviceID(
			traversal.expected,
			0,
			"continuation_request",
			-1,
		)
	}
	decoded, err := DecodeDeviceIDPage(page.Request, page.PDU)
	if err != nil {
		return err
	}
	result := &traversal.result
	if len(result.Pages) == 0 {
		result.Conformity = decoded.Conformity
	} else if decoded.Conformity != result.Conformity {
		traversal.anomalies.add(DeviceIDAnomalyConformityChange)
	}
	result.Pages = append(result.Pages, cloneDeviceIDPage(decoded))
	for _, anomaly := range decoded.Anomalies {
		traversal.anomalies.add(anomaly)
	}
	for _, object := range decoded.Objects {
		if _, duplicate := traversal.seen[object.ID]; duplicate {
			traversal.anomalies.add(DeviceIDAnomalyDuplicateObject)
			continue
		}
		if len(result.Objects) == traversal.limits.MaxObjects ||
			len(object.Value) > traversal.limits.MaxValueBytes-traversal.valueBytes {
			traversal.anomalies.add(DeviceIDAnomalyAggregateLimitReached)
			traversal.close(false)
			return nil
		}
		traversal.seen[object.ID] = struct{}{}
		traversal.valueBytes += len(object.Value)
		result.Objects = append(result.Objects, DeviceIDObject{
			ID:    object.ID,
			Value: append([]byte(nil), object.Value...),
		})
	}
	if !decoded.MoreFollows() {
		traversal.close(true)
		return nil
	}
	next, err := nextDeviceIDPageRequest(decoded)
	if err != nil {
		traversal.anomalies.add(DeviceIDAnomalyContinuationUnavailable)
		traversal.close(false)
		return nil
	}
	if len(result.Pages) == traversal.limits.MaxSegments {
		traversal.anomalies.add(DeviceIDAnomalyPageLimitReached)
		traversal.close(false)
		return nil
	}
	traversal.expected = next
	return nil
}

func (traversal *deviceIDTolerantTraversal) close(complete bool) {
	traversal.closed = true
	traversal.result.Complete = complete
	first := traversal.result.Pages[0].Request
	if !first.extended && first.access != DeviceIDIndividual {
		for objectID := byte(0); objectID <= 2; objectID++ {
			if _, exists := traversal.seen[objectID]; !exists {
				traversal.anomalies.add(DeviceIDAnomalyMandatoryObjectMissing)
				break
			}
		}
	}
}

// finish publishes an independent copy of a closed traversal.
func (traversal *deviceIDTolerantTraversal) finish() (DeviceIDTolerantResult, error) {
	if !traversal.closed {
		return DeviceIDTolerantResult{}, malformedDeviceID(
			traversal.expected,
			0,
			"missing_continuation",
			-1,
		)
	}
	result := traversal.result
	result.Objects = cloneDeviceIDObjects(result.Objects)
	result.Pages = make([]DeviceIDPage, len(traversal.result.Pages))
	for index, page := range traversal.result.Pages {
		result.Pages[index] = cloneDeviceIDPage(page)
	}
	result.Anomalies = append([]DeviceIDAnomaly(nil), traversal.anomalies.list...)
	return result, nil
}

func nextDeviceIDPageRequest(page DeviceIDPage) (DeviceIDRequest, error) {
	request := page.Request
	if request.access == DeviceIDIndividual || !page.MoreFollows() {
		return DeviceIDRequest{}, protocolError(
			ErrorInvalidRequest,
			FunctionEncapsulatedInterface,
			0,
			"continuation_unavailable",
			-1,
		)
	}
	next := DeviceIDRequest{
		access:       request.access,
		objectID:     page.NextObjectID,
		continuation: true,
		extended:     request.extended,
		wrapped:      request.wrapped,
	}
	switch {
	case page.NextObjectID > request.objectID:
	case request.extended &&
		!request.wrapped &&
		page.NextObjectID < request.objectID:
		next.wrapped = true
	default:
		return DeviceIDRequest{}, malformedDeviceID(
			request,
			0,
			"next_object_id",
			5,
		)
	}
	if err := validateDeviceIDRequest(next); err != nil {
		return DeviceIDRequest{}, err
	}
	return next, nil
}

func deviceIDPageCursorAdvances(last byte, next byte, extended bool) bool {
	return next > last || (extended && last == 0xff && next == 0x00)
}

type deviceIDAnomalySet struct {
	list []DeviceIDAnomaly
}

func (set *deviceIDAnomalySet) add(anomaly DeviceIDAnomaly) {
	if !containsDeviceIDAnomaly(set.list, anomaly) {
		set.list = append(set.list, anomaly)
	}
}

func containsDeviceIDAnomaly(
	anomalies []DeviceIDAnomaly,
	anomaly DeviceIDAnomaly,
) bool {
	for _, current := range anomalies {
		if current == anomaly {
			return true
		}
	}
	return false
}

func cloneDeviceIDPage(page DeviceIDPage) DeviceIDPage {
	page.PDU = cloneBytes(page.PDU)
	page.Objects = cloneDeviceIDObjects(page.Objects)
	page.Anomalies = append([]DeviceIDAnomaly(nil), page.Anomalies...)
	return page
}
