package cose

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/fxamacker/cbor/v2"
)

// sign1Message represents a COSE_Sign1 CBOR object:
//
//   COSE_Sign1 = [
//       Headers,
//       payload : bstr / nil,
//       signature : bstr
//   ]
//
// Reference: https://tools.ietf.org/html/rfc8152#section-4.2
type sign1Message struct {
	_           struct{} `cbor:",toarray"`
	Protected   cbor.RawMessage
	Unprotected cbor.RawMessage
	Payload     []byte
	Signature   []byte
}

// sign1MessagePrefix represents the fixed prefix of COSE_Sign1_Tagged.
var sign1MessagePrefix = []byte{
	0xd2, // #6.18
	0x84, // Array of length 4
}

// Sign1Message represents a decoded COSE_Sign1 message.
//
// Reference: https://tools.ietf.org/html/rfc8152#section-4.2
type Sign1Message struct {
	Headers   Headers
	External  []byte
	Payload   []byte
	Signature []byte
}

// NewSign1Message returns a Sign1Message with header initialized.
func NewSign1Message() *Sign1Message {
	return &Sign1Message{
		Headers: Headers{
			Protected:   ProtectedHeader{},
			Unprotected: UnprotectedHeader{},
		},
	}
}

// MarshalCBOR encodes Sign1Message into a COSE_Sign1_Tagged object.
func (m *Sign1Message) MarshalCBOR() ([]byte, error) {
	content := sign1Message{
		Protected:   m.Headers.RawProtected,
		Unprotected: m.Headers.RawUnprotected,
		Payload:     m.Payload,
		Signature:   m.Signature,
	}
	if content.Protected == nil {
		header, err := encMode.Marshal(m.Headers.Protected)
		if err != nil {
			return nil, err
		}
		content.Protected = header
	}
	if content.Unprotected == nil {
		header, err := encMode.Marshal(m.Headers.Unprotected)
		if err != nil {
			return nil, err
		}
		content.Unprotected = header
	}
	return encMode.Marshal(cbor.Tag{
		Number:  CBORTagSign1Message,
		Content: m,
	})
}

// UnmarshalCBOR decodes a COSE_Sign1_Tagged object into Sign1Message.
func (m *Sign1Message) UnmarshalCBOR(data []byte) error {
	if m == nil {
		return errors.New("cbor: UnmarshalCBOR on nil Sign1Message pointer")
	}

	// fast message check
	if !bytes.HasPrefix(data, sign1MessagePrefix) {
		return errors.New("cbor: invalid COSE_Sign1_Tagged object")
	}

	// decode to sign1Message and parse
	var raw sign1Message
	if err := decMode.Unmarshal(data[1:], &raw); err != nil {
		return err
	}
	msg := Sign1Message{
		Headers: Headers{
			RawProtected:   raw.Protected,
			RawUnprotected: raw.Unprotected,
		},
		Payload:   raw.Payload,
		Signature: raw.Signature,
	}
	if err := decMode.Unmarshal(msg.Headers.RawProtected, &msg.Headers.Protected); err != nil {
		return fmt.Errorf("cbor: invalid protected header: %w", err)
	}
	if err := decMode.Unmarshal(msg.Headers.RawUnprotected, &msg.Headers.Unprotected); err != nil {
		return fmt.Errorf("cbor: invalid unprotected header: %w", err)
	}

	// write out
	*m = msg
	return nil
}

// Sign signs a Sign1Message using the provided Signer.
func (m *Sign1Message) Sign(rand io.Reader, signer Signer) error {
	if m.Signature != nil {
		return errors.New("Sign1Message signature already has signature bytes")
	}

	panic("not implemented")
}

func (m *Sign1Message) Verify(external []byte, verifier Verifier) error {
	panic("not implemented")
}
