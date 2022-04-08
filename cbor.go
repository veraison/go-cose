package cose

import "github.com/fxamacker/cbor/v2"

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
