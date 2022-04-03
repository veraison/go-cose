package cose

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// COSE Header labels registered in the IANA "COSE Header Parameters" registry.
//
// Reference: https://www.iana.org/assignments/cose/cose.xhtml#header-parameters
const (
	HeaderLabelAlgorithm         int64 = 1
	HeaderLabelCritical          int64 = 2
	HeaderLabelContentType       int64 = 3
	HeaderLabelKeyID             int64 = 4
	HeaderLabelCounterSignature  int64 = 7
	HeaderLabelCounterSignature0 int64 = 9
	HeaderLabelX5Bag             int64 = 32
	HeaderLabelX5Chain           int64 = 33
	HeaderLabelX5T               int64 = 34
	HeaderLabelX5U               int64 = 35
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
		encoded, err = encMode.Marshal(map[interface{}]interface{}(h))
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
		var header map[interface{}]interface{}
		if err := decMode.Unmarshal(encoded, &header); err != nil {
			return err
		}
		(*h) = header
	}
	return nil
}

// SetAlgorithm sets the algorithm value to the algorithm header.
func (h ProtectedHeader) SetAlgorithm(alg Algorithm) {
	h[HeaderLabelAlgorithm] = alg
}

// Algorithm gets the algorithm value from the algorithm header.
func (h ProtectedHeader) Algorithm() (Algorithm, error) {
	value, ok := h[HeaderLabelAlgorithm]
	if !ok {
		return 0, ErrAlgorithmNotFound
	}
	switch alg := value.(type) {
	case Algorithm:
		return alg, nil
	case int:
		return Algorithm(alg), nil
	case int8:
		return Algorithm(alg), nil
	case int16:
		return Algorithm(alg), nil
	case int32:
		return Algorithm(alg), nil
	case int64:
		return Algorithm(alg), nil
	default:
		return 0, ErrInvalidAlgorithm
	}
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

// MarshalProtected encodes the protected header.
// RawProtected is returned if it is not set to nil.
func (h *Headers) MarshalProtected() ([]byte, error) {
	if h.RawProtected == nil {
		return encMode.Marshal(h.Protected)
	}
	return h.RawProtected, nil
}

// MarshalUnprotected encodes the unprotected header.
// RawUnprotected is returned if it is not set to nil.
func (h *Headers) MarshalUnprotected() ([]byte, error) {
	if h.RawUnprotected == nil {
		return encMode.Marshal(h.Unprotected)
	}
	return h.RawUnprotected, nil
}

// UnmarshalFromRaw decodes Protected from RawProtected and Unprotected from
// RawUnprotected.
func (h *Headers) UnmarshalFromRaw() error {
	if err := decMode.Unmarshal(h.RawProtected, &h.Protected); err != nil {
		return fmt.Errorf("cbor: invalid protected header: %w", err)
	}
	if err := decMode.Unmarshal(h.RawUnprotected, &h.Unprotected); err != nil {
		return fmt.Errorf("cbor: invalid unprotected header: %w", err)
	}
	return nil
}
