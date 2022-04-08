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
	protected, err := m.Headers.MarshalProtected()
	if err != nil {
		return nil, err
	}
	unprotected, err := m.Headers.MarshalUnprotected()
	if err != nil {
		return nil, err
	}
	content := sign1Message{
		Protected:   protected,
		Unprotected: unprotected,
		Payload:     m.Payload,
		Signature:   m.Signature,
	}
	return encMode.Marshal(cbor.Tag{
		Number:  CBORTagSign1Message,
		Content: content,
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
	if raw.Signature == nil {
		return errors.New("cbor: nil signature")
	}
	msg := Sign1Message{
		Headers: Headers{
			RawProtected:   raw.Protected,
			RawUnprotected: raw.Unprotected,
		},
		Payload:   raw.Payload,
		Signature: raw.Signature,
	}
	if err := msg.Headers.UnmarshalFromRaw(); err != nil {
		return err
	}

	*m = msg
	return nil
}

// Sign signs a Sign1Message using the provided Signer.
//
// Reference: https://datatracker.ietf.org/doc/html/rfc8152#section-4.4
func (m *Sign1Message) Sign(rand io.Reader, signer Signer) error {
	if len(m.Signature) > 0 {
		return errors.New("Sign1Message signature already has signature bytes")
	}

	// check algorithm if present
	skAlg := signer.Algorithm()
	if alg, err := m.Headers.Protected.Algorithm(); err != nil {
		if err != ErrAlgorithmNotFound {
			return err
		}
		// `alg` header not present.
	} else if alg != skAlg {
		return fmt.Errorf("%w: signer %v: header %v", ErrAlgorithmMismatch, skAlg, alg)
	}

	// sign the message
	digest, err := m.digestToBeSigned(skAlg)
	if err != nil {
		return err
	}
	sig, err := signer.Sign(rand, digest)
	if err != nil {
		return err
	}

	m.Signature = sig
	return nil
}

// Verify verifies the signature on the Sign1Message returning nil on success or
// a suitable error if verification fails.
//
// Reference: https://datatracker.ietf.org/doc/html/rfc8152#section-4.4
func (m *Sign1Message) Verify(verifier Verifier) error {
	if len(m.Signature) == 0 {
		return errors.New("Sign1Message has no signature to verify")
	}

	// check algorithm if present
	vkAlg := verifier.Algorithm()
	if alg, err := m.Headers.Protected.Algorithm(); err != nil {
		if err != ErrAlgorithmNotFound {
			return err
		}
		// `alg` header not present.
	} else if alg != vkAlg {
		return fmt.Errorf("%w: verifier %v: header %v", ErrAlgorithmMismatch, vkAlg, alg)
	}

	// verify the message
	digest, err := m.digestToBeSigned(vkAlg)
	if err != nil {
		return err
	}
	return verifier.Verify(digest, m.Signature)
}

// digestToBeSigned constructs Sig_structure, computes ToBeSigned, and returns
// the digest of ToBeSigned.
// If the signing algorithm does not have a hash algorithm associated,
// ToBeSigned is returned instead.
//
// Reference: https://datatracker.ietf.org/doc/html/rfc8152#section-4.4
func (m *Sign1Message) digestToBeSigned(alg Algorithm) ([]byte, error) {
	// create a Sig_structure and populate it with the appropriate fields.
	var protected cbor.RawMessage
	protected, err := m.Headers.MarshalProtected()
	if err != nil {
		return nil, err
	}
	external := m.External
	if external == nil {
		external = []byte{}
	}
	payload := m.Payload
	if payload == nil {
		payload = []byte{}
	}
	sigStructure := []interface{}{
		"Signature1", // context
		protected,    // body_protected
		external,     // external_aad
		payload,      // payload
	}

	// create the value ToBeSigned by encoding the Sig_structure to a byte
	// string.
	toBeSigned, err := encMode.Marshal(sigStructure)
	if err != nil {
		return nil, err
	}

	// hash toBeSigned if there is a hash algorithm associated with the signing
	// algorithm.
	return alg.computeHash(toBeSigned)
}

// Sign1 signs a Sign1Message using the provided Signer.
//
// This method is a wrapper of `Sign1Message.Sign()`.
//
// Reference: https://datatracker.ietf.org/doc/html/rfc8152#section-4.4
func Sign1(rand io.Reader, signer Signer, protected ProtectedHeader, payload, external []byte) (*Sign1Message, error) {
	if protected == nil {
		protected = ProtectedHeader{}
	}
	msg := &Sign1Message{
		Headers: Headers{
			Protected:   protected,
			Unprotected: UnprotectedHeader{},
		},
		External: external,
		Payload:  payload,
	}
	err := msg.Sign(rand, signer)
	if err != nil {
		return nil, err
	}
	return msg, nil
}

// Verify1 verifies a Sign1Message returning nil on success or a suitable error
// if verification fails.
//
// This method is a wrapper of `Sign1Message.Verify()`.
//
// Reference: https://datatracker.ietf.org/doc/html/rfc8152#section-4.4
func Verify1(msg *Sign1Message, verifier Verifier) error {
	if msg == nil {
		return errors.New("nil Sign1Message")
	}
	return msg.Verify(verifier)
}
