package cose

import "github.com/fxamacker/cbor/v2"

// COSE Header labels registered in the IANA "COSE Header Parameters" registry.
//
// Reference: https://www.iana.org/assignments/cose/cose.xhtml#header-parameters
const (
	HeaderLabelAlgorithm         = 1
	HeaderLabelCritical          = 2
	HeaderLabelContentType       = 3
	HeaderLabelKeyID             = 4
	HeaderLabelCounterSignature  = 7
	HeaderLabelCounterSignature0 = 9
	HeaderLabelX5Bag             = 32
	HeaderLabelX5Chain           = 33
	HeaderLabelX5T               = 34
	HeaderLabelX5U               = 35
)

// ProtectedHeader contains parameters that are to be cryptographically
// protected.
type ProtectedHeader map[interface{}]interface{}

// MarshalCBOR encodes the protected header into a CBOR bstr object.
// A zero-length header is encoded as a zero-length string rather than as a
// zero-length map (encoded as h'a0').
func (h ProtectedHeader) MarshalCBOR() ([]byte, error) {
	var encoded []byte
	if len(h) == 0 {
		encoded = []byte{}
	} else {
		var err error
		encoded, err = encMode.Marshal(h)
		if err != nil {
			return nil, err
		}
	}
	return encMode.Marshal(encoded)
}

// UnmarshalCBOR decodes a CBOR bstr object into ProtectedHeader.
func (h *ProtectedHeader) UnmarshalCBOR(data []byte) error {
	var encoded []byte
	if err := decMode.Unmarshal(data, &encoded); err != nil {
		return err
	}
	if len(encoded) == 0 {
		(*h) = make(ProtectedHeader)
	} else {
		var header ProtectedHeader
		if err := decMode.Unmarshal(encoded, &header); err != nil {
			return err
		}
		(*h) = header
	}
	return nil
}

// SetAlgorithm sets the algorithm value to the algorithm header.
func (h ProtectedHeader) SetAlgorithm(alg Algorithm) {
	h[HeaderLabelAlgorithm] = int(alg)
}

// GetAlgorithm gets the algorithm value from the algorithm header.
func (h ProtectedHeader) GetAlgorithm() (Algorithm, error) {
	value, ok := h[HeaderLabelAlgorithm]
	if !ok {
		return 0, ErrAlgorithmNotFound
	}
	alg, ok := value.(int)
	if !ok {
		return 0, ErrInvalidAlgorithm
	}
	return Algorithm(alg), nil
}

// UnprotectedHeader contains parameters that are not cryptographically
// protected.
type UnprotectedHeader map[interface{}]interface{}

// Headers represents "two buckets of information that are not
// considered to be part of the payload itself, but are used for
// holding information about content, algorithms, keys, or evaluation
// hints for the processing of the layer."
//
// It is represented by CDDL fragments:
//
//   Headers = (
//       protected : empty_or_serialized_map,
//       unprotected : header_map
//   )
//
//   header_map = {
//       Generic_Headers,
//       * label => values
//   }
//
//   empty_or_serialized_map = bstr .cbor header_map / bstr .size 0
//
// See Also
//
// https://tools.ietf.org/html/rfc8152#section-3
type Headers struct {
	// RawProtected contains the raw CBOR encoded data for the protected header.
	// It is populated when decoding.
	// Applications can use this field for customized encoding / decoding of
	// the protected header in case the default decoder provided by this library
	// is not preferred.
	RawProtected cbor.RawMessage

	// Protected contains parameters that are to be cryptographically protected.
	// When encoding or signing, the protected header is encoded using the
	// default CBOR encoder if RawProtected is set to nil. Otherwise,
	// RawProtected will be used with Protected ignored.
	Protected ProtectedHeader

	// RawUnprotected contains the raw CBOR encoded data for the unprotected
	// header. It is populated when decoding.
	// Applications can use this field for customized encoding / decoding of
	// the unprotected header in case the default decoder provided by this
	// library is not preferred.
	RawUnprotected cbor.RawMessage

	// Unprotected contains parameters that are not cryptographically protected.
	// When encoding, the unprotected header is encoded using the default CBOR
	// encoder if RawUnprotected is set to nil. Otherwise, RawUnprotected will
	// be used with Unprotected ignored.
	Unprotected UnprotectedHeader
}
