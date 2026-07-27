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
}

// DeviceIDObject retains an object's exact length-delimited bytes.
type DeviceIDObject struct {
	ID    byte
	Value []byte
}

// DeviceIDSegment is one validated response segment with request provenance.
type DeviceIDSegment struct {
	Request      DeviceIDRequest
	Conformity   DeviceIDConformity
	MoreFollows  bool
	NextObjectID byte
	Objects      []DeviceIDObject
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

// NextDeviceIDRequest binds a continuation request to its prior segment.
func NextDeviceIDRequest(segment DeviceIDSegment) (DeviceIDRequest, error) {
	if err := validateDeviceIDSegment(segment); err != nil {
		return DeviceIDRequest{}, err
	}
	if segment.Request.access == DeviceIDIndividual || !segment.MoreFollows {
		return DeviceIDRequest{}, protocolError(
			ErrorInvalidRequest,
			FunctionEncapsulatedInterface,
			0,
			"continuation_unavailable",
			-1,
		)
	}
	return DeviceIDRequest{
		access:       segment.Request.access,
		objectID:     segment.NextObjectID,
		continuation: true,
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
	if (!moreFollows && nextObjectID != 0) || (moreFollows && nextObjectID == 0) {
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
		Request:      request,
		Conformity:   conformity,
		MoreFollows:  moreFollows,
		NextObjectID: nextObjectID,
		Objects:      objects,
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
	if err := validateDeviceIDLimits(limits); err != nil {
		return DeviceIDResult{}, err
	}
	if firstRequest.access == DeviceIDIndividual ||
		!validDeviceIDAccess(firstRequest.access) ||
		firstRequest.objectID != 0 {
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

	for index, segment := range segments {
		if segment.Request != expectedRequest {
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
			conformity = segment.Conformity
		} else if segment.Conformity != conformity {
			return DeviceIDResult{}, malformedDeviceID(
				expectedRequest,
				0,
				"conformity_change",
				3,
			)
		}
		copiedSegment := segment
		copiedSegment.Objects = cloneDeviceIDObjects(segment.Objects)
		copiedSegments = append(copiedSegments, copiedSegment)

		for _, object := range segment.Objects {
			if _, exists := seen[object.ID]; exists ||
				(havePreviousObject && object.ID <= previousObjectID) {
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
		if segment.MoreFollows {
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
	request := segment.Request
	if validateDeviceIDRequest(request) != nil ||
		!validDeviceIDConformity(segment.Conformity) {
		return malformedDeviceID(request, 0, "segment_identity", -1)
	}
	if len(segment.Objects) > 0xff {
		return malformedDeviceID(request, 0, "number_of_objects", 6)
	}
	if (!segment.MoreFollows && segment.NextObjectID != 0) ||
		(segment.MoreFollows && segment.NextObjectID == 0) ||
		(segment.MoreFollows && len(segment.Objects) == 0) {
		return malformedDeviceID(request, 0, "continuation", -1)
	}
	if request.access == DeviceIDIndividual {
		if segment.Conformity&0x80 == 0 ||
			segment.MoreFollows ||
			segment.NextObjectID != 0 ||
			len(segment.Objects) != 1 ||
			segment.Objects[0].ID != request.objectID {
			return malformedDeviceID(request, 0, "individual_response", -1)
		}
	}
	var previous byte
	encodedSize := 7
	for index, object := range segment.Objects {
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
		if !objectAllowedByConformity(object.ID, segment.Conformity) {
			return malformedDeviceID(request, 0, "conformity_category", -1)
		}
		previous = object.ID
	}
	if segment.MoreFollows &&
		len(segment.Objects) > 0 &&
		segment.NextObjectID <= segment.Objects[len(segment.Objects)-1].ID {
		return malformedDeviceID(request, 0, "next_object_id", -1)
	}
	return nil
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
		if request.continuation {
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
