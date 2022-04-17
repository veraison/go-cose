package cose

import (
	"bytes"
	"errors"

	"github.com/fxamacker/cbor/v2"
)

// CBOR Tags for COSE signatures registered in the IANA "CBOR Tags" registry.
//
// Reference: https://www.iana.org/assignments/cbor-tags/cbor-tags.xhtml#tags
const (
	CBORTagSignMessage  = 98
	CBORTagSign1Message = 18
)

// Pre-configured modes for CBOR encoding and decoding.
var (
	encMode                  cbor.EncMode
	decMode                  cbor.DecMode
	decModeWithTagsForbidden cbor.DecMode
)

func init() {
	var err error

	// init encode mode
	encOpts := cbor.EncOptions{
		Sort:        cbor.SortCanonical,        // sort map keys
		IndefLength: cbor.IndefLengthForbidden, // no streaming
	}
	encMode, err = encOpts.EncMode()
	if err != nil {
		panic(err)
	}

	// init decode mode
	decOpts := cbor.DecOptions{
		DupMapKey:   cbor.DupMapKeyEnforcedAPF, // duplicated key not allowed
		IndefLength: cbor.IndefLengthForbidden, // no streaming
		IntDec:      cbor.IntDecConvertSigned,  // decode CBOR uint/int to Go int64
	}
	decMode, err = decOpts.DecMode()
	if err != nil {
		panic(err)
	}
	decOpts.TagsMd = cbor.TagsForbidden
	decModeWithTagsForbidden, err = decOpts.DecMode()
	if err != nil {
		panic(err)
	}
}

// byteString represents a "bstr / nil" type.
type byteString []byte

// UnmarshalCBOR decodes data into a "bstr / nil" type.
//
// Note: `github.com/fxamacker/cbor/v2` considers the primitive value
// `undefined` (major type 7, value 23) as nil, which is not recognized by COSE.
//
// Related Code: https://github.com/fxamacker/cbor/blob/v2.4.0/decode.go#L709
//
// Reference: https://datatracker.ietf.org/doc/html/rfc8152#section-1.3
func (s *byteString) UnmarshalCBOR(data []byte) error {
	if s == nil {
		return errors.New("cbor: UnmarshalCBOR on nil byteString pointer")
	}
	var candidate []byte
	if err := decModeWithTagsForbidden.Unmarshal(data, &candidate); err != nil {
		return err
	}
	if candidate == nil && !bytes.Equal(data, []byte{0xf6}) {
		return errors.New("cbor: non-standard nil value")
	}
	*s = candidate
	return nil
}
