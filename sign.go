package cose

import (
	"bytes"
	"errors"
	"fmt"
	"io"

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

// signMessage represents a COSE_Sign CBOR object:
//
//   COSE_Sign = [
//       Headers,
//       payload : bstr / nil,
//       signatures : [+ COSE_Signature]
//   ]
//
// Reference: https://tools.ietf.org/html/rfc8152#section-4.1
type signMessage struct {
	_           struct{} `cbor:",toarray"`
	Protected   cbor.RawMessage
	Unprotected cbor.RawMessage
	Payload     []byte
	Signatures  []cbor.RawMessage
}

// signMessagePrefix represents the fixed prefix of COSE_Sign_Tagged.
var signMessagePrefix = []byte{
	0xd8, 0x62, // #6.98
	0x84, // Array of length 4
}

// SignMessage represents a decoded COSE_Sign message.
//
// Reference: https://tools.ietf.org/html/rfc8152#section-4.1
type SignMessage struct {
	Headers    Headers
	Payload    []byte
	Signatures []*Signature
}

// NewSignMessage returns a SignMessage with header initialized.
func NewSignMessage() *SignMessage {
	return &SignMessage{
		Headers: Headers{
			Protected:   ProtectedHeader{},
			Unprotected: UnprotectedHeader{},
		},
	}
}

// MarshalCBOR encodes SignMessage into a COSE_Sign_Tagged object.
func (m *SignMessage) MarshalCBOR() ([]byte, error) {
	protected, err := m.Headers.MarshalProtected()
	if err != nil {
		return nil, err
	}
	unprotected, err := m.Headers.MarshalUnprotected()
	if err != nil {
		return nil, err
	}
	signatures := make([]cbor.RawMessage, 0, len(m.Signatures))
	for _, sig := range m.Signatures {
		sigCBOR, err := sig.MarshalCBOR()
		if err != nil {
			return nil, err
		}
		signatures = append(signatures, sigCBOR)
	}
	content := signMessage{
		Protected:   protected,
		Unprotected: unprotected,
		Payload:     m.Payload,
		Signatures:  signatures,
	}
	return encMode.Marshal(cbor.Tag{
		Number:  CBORTagSignMessage,
		Content: content,
	})
}

// UnmarshalCBOR decodes a COSE_Sign_Tagged object into SignMessage.
func (m *SignMessage) UnmarshalCBOR(data []byte) error {
	if m == nil {
		return errors.New("cbor: UnmarshalCBOR on nil SignMessage pointer")
	}

	// fast message check
	if !bytes.HasPrefix(data, signMessagePrefix) {
		return errors.New("cbor: invalid COSE_Sign_Tagged object")
	}

	// decode to sign1Message and parse
	var raw signMessage
	if err := decMode.Unmarshal(data[2:], &raw); err != nil {
		return err
	}
	signatures := make([]*Signature, 0, len(raw.Signatures))
	for _, sigCBOR := range raw.Signatures {
		sig := &Signature{}
		if err := sig.UnmarshalCBOR(sigCBOR); err != nil {
			return err
		}
		signatures = append(signatures, sig)
	}
	msg := SignMessage{
		Headers: Headers{
			RawProtected:   raw.Protected,
			RawUnprotected: raw.Unprotected,
		},
		Payload:    raw.Payload,
		Signatures: signatures,
	}
	if err := msg.Headers.UnmarshalFromRaw(); err != nil {
		return err
	}

	*m = msg
	return nil
}

// Sign signs a SignMessage using the provided signers corresponding to the
// signatures.
//
// Reference: https://datatracker.ietf.org/doc/html/rfc8152#section-4.4
func (m *SignMessage) Sign(rand io.Reader, signers ...Signer) error {
	switch len(m.Signatures) {
	case 0:
		return ErrNoSignatures
	case len(signers):
		// no ops
	default:
		return fmt.Errorf("%d signers for %d signatures", len(signers), len(m.Signatures))
	}
	panic("not implemented")
}

// Verify verifies the signatures on the SignMessage against the corresponding
// verifier, returning nil on success or a suitable error if verification fails.
//
// Reference: https://datatracker.ietf.org/doc/html/rfc8152#section-4.4
func (m *SignMessage) Verify(verifiers ...Verifier) error {
	switch len(m.Signatures) {
	case 0:
		return ErrNoSignatures
	case len(verifiers):
		// no ops
	default:
		return fmt.Errorf("%d verifiers for %d signatures", len(verifiers), len(m.Signatures))
	}
	panic("not implemented")
}
