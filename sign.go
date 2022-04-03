package cose

import (
	"errors"

	"github.com/fxamacker/cbor/v2"
)

// signature represents a COSE_Signature CBOR object:
//
//   COSE_Signature =  [
//       Headers,
//       signature : bstr
//   ]
//
// Reference: https://tools.ietf.org/html/rfc8152#section-4.1
type signature struct {
	_           struct{} `cbor:",toarray"`
	Protected   cbor.RawMessage
	Unprotected cbor.RawMessage
	Signature   []byte
}

// Signature represents a decoded COSE_Signature.
//
// Reference: https://tools.ietf.org/html/rfc8152#section-4.1
type Signature struct {
	Headers   Headers
	External  []byte
	Signature []byte
}

// NewSignature returns a Signature with header initialized.
func NewSignature() *Signature {
	return &Signature{
		Headers: Headers{
			Protected:   ProtectedHeader{},
			Unprotected: UnprotectedHeader{},
		},
	}
}

// MarshalCBOR encodes Signature into a COSE_Signature object.
func (s *Signature) MarshalCBOR() ([]byte, error) {
	protected, err := s.Headers.MarshalProtected()
	if err != nil {
		return nil, err
	}
	unprotected, err := s.Headers.MarshalUnprotected()
	if err != nil {
		return nil, err
	}
	sig := signature{
		Protected:   protected,
		Unprotected: unprotected,
		Signature:   s.Signature,
	}
	return encMode.Marshal(sig)
}

// UnmarshalCBOR decodes a COSE_Signature object into Signature.
func (s *Signature) UnmarshalCBOR(data []byte) error {
	if s == nil {
		return errors.New("cbor: UnmarshalCBOR on nil Signature pointer")
	}

	// decode to signature and parse
	var raw signature
	if err := decMode.Unmarshal(data, &raw); err != nil {
		return err
	}
	sig := Signature{
		Headers: Headers{
			RawProtected:   raw.Protected,
			RawUnprotected: raw.Unprotected,
		},
		Signature: raw.Signature,
	}
	if err := sig.Headers.UnmarshalFromRaw(); err != nil {
		return err
	}

	*s = sig
	return nil
}
