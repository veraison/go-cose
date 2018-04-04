package cose

import (
	"crypto/ecdsa"
	"fmt"
	"io"
)

// Signature represents a COSE signature with CDDL fragment:
//
// COSE_Signature =  [
//        Headers,
//        signature : bstr
// ]
//
// https://tools.ietf.org/html/rfc8152#section-4.1
type Signature struct {
	Headers        *Headers
	SignatureBytes []byte
}

// NewSignature returns a new COSE Signature with empty headers and
// nil signature bytes
func NewSignature() (s *Signature) {
	return &Signature{
		Headers: &Headers{
			Protected:   map[interface{}]interface{}{},
			Unprotected: map[interface{}]interface{}{},
		},
		SignatureBytes: nil,
	}
}

// Decode updates the signature inplace from its COSE serialization
func (s *Signature) Decode(o interface{}) {
	array, ok := o.([]interface{})
	if !ok {
		panic(fmt.Sprintf("error decoding sigArray; got %T", array))
	}
	if len(array) != 3 {
		panic(fmt.Sprintf("can only decode Signature with 3 items; got %d", len(array)))
	}

	err := s.Headers.Decode(array[0:2])
	if err != nil {
		panic(fmt.Sprintf("error decoding signature header: %+v", err))
	}

	signatureBytes, ok := array[2].([]byte)
	if !ok {
		panic(fmt.Sprintf("unable to decode COSE signature expecting decode from interface{}; got %T", array[2]))
	}
	s.SignatureBytes = signatureBytes
}

// SignMessage represents a COSESignMessage with CDDL fragment:
//
// COSE_Sign = [
//        Headers,
//        payload : bstr / nil,
//        signatures : [+ COSE_Signature]
// ]
//
// https://tools.ietf.org/html/rfc8152#section-4.1
type SignMessage struct {
	Headers    *Headers
	Payload    []byte
	Signatures []Signature
}

// NewSignMessage takes a []byte payload and returns a new SignMessage
// with empty headers and signatures
func NewSignMessage(payload []byte) (msg SignMessage) {
	msg = SignMessage{
		Headers: &Headers{
			Protected:   map[interface{}]interface{}{},
			Unprotected: map[interface{}]interface{}{},
		},
		Payload:    payload,
		Signatures: []Signature{},
	}
	return msg
}

// AddSignature adds a signature to the message signatures creating an
// empty []Signature if necessary
func (m *SignMessage) AddSignature(s *Signature) {
	if m.Signatures == nil {
		m.Signatures = []Signature{}
	}
	m.Signatures = append(m.Signatures, *s)
}

// SigStructure returns the byte slice to be signed
func (m *SignMessage) SigStructure(external []byte, signature *Signature) (ToBeSigned []byte, err error) {
	// 1.  Create a Sig_structure and populate it with the appropriate fields.
	//
	// 2.  Create the value ToBeSigned by encoding the Sig_structure to a
	//     byte string, using the encoding described in Section 14.
	ToBeSigned, err = buildAndMarshalSigStructure(
		m.Headers.EncodeProtected(),
		signature.Headers.EncodeProtected(),
		external,
		m.Payload)
	return
}

// SignatureDigest takes an extra external byte slice and a Signature
// and returns the SigStructure (i.e. ToBeSigned) hashed using the
// algorithm from the signature parameter
//
// TODO: check that signature is in SignMessage?
func (m *SignMessage) SignatureDigest(external []byte, signature *Signature) (digest []byte, err error) {
	ToBeSigned, err := m.SigStructure(external, signature)
	if err != nil {
		return nil, err
	}

	alg, err := getAlg(signature.Headers)
	if err != nil {
		return nil, err
	}

	digest, err = hashSigStructure(ToBeSigned, alg.HashFunc)
	if err != nil {
		return nil, err
	}

	return digest, err
}

// Signing and Verification Process
// https://tools.ietf.org/html/rfc8152#section-4.4

// Sign signs a SignMessage populating signatures[].signature inplace
func (m *SignMessage) Sign(rand io.Reader, external []byte, opts SignOpts) (err error) {
	if m.Signatures == nil {
		return ErrNilSignatures
	} else if len(m.Signatures) < 1 {
		return ErrNoSignatures
	}

	for i, signature := range m.Signatures {
		if signature.Headers == nil {
			return ErrNilSigHeader
		} else if signature.Headers.Protected == nil {
			return ErrNilSigProtectedHeaders
		} else if signature.SignatureBytes != nil || len(signature.SignatureBytes) > 0 {
			return fmt.Errorf("SignMessage signature %d already has signature bytes", i)
		}
		// TODO: check if provided privateKey verify alg, bitsize, and supported key_ops in protected

		// TODO: dedup with alg in m.SignatureDigest()?
		alg, err := getAlg(signature.Headers)
		if err != nil {
			return err
		}
		if alg.Value > -1 { // Negative numbers are used for second layer objects (COSE_Signature and COSE_recipient)
			return ErrInvalidAlg
		}
		opts.HashFunc = alg.HashFunc

		digest, err := m.SignatureDigest(external, &signature)
		if err != nil {
			return err
		}

		signer, err := opts.GetSigner(i, signature)
		if err != nil {
			return fmt.Errorf("Error finding a Signer for signature %d", i)
		}

		// 3.  Call the signature creation algorithm passing in K (the key to
		//     sign with), alg (the algorithm to sign with), and ToBeSigned (the
		//     value to sign).
		signatureBytes, err := signer.Sign(rand, digest, opts)
		if err != nil {
			return err
		}

		// 4.  Place the resulting signature value in the 'signature' field of the array.
		m.Signatures[i].SignatureBytes = signatureBytes
	}
	return nil
}

// Verify verifies all signatures on the SignMessage returning nil for
// success or an error
func (m *SignMessage) Verify(external []byte, opts *VerifyOpts) (err error) {
	if m.Signatures == nil || len(m.Signatures) < 1 {
		return nil // Nothing to check
	}
	// TODO: take a func for a signature kid that returns a key or not?

	for i, signature := range m.Signatures {
		if signature.Headers == nil {
			return ErrNilSigHeader
		} else if signature.Headers.Protected == nil {
			return ErrNilSigProtectedHeaders
		} else if signature.SignatureBytes == nil || len(signature.SignatureBytes) < 1 {
			return fmt.Errorf("SignMessage signature %d missing signature bytes to verify", i)
		}
		// TODO: check if provided privateKey verify alg, bitsize, and supported key_ops in protected

		// TODO: dedup with alg in m.SignatureDigest()?
		alg, err := getAlg(signature.Headers)
		if err != nil {
			return err
		}
		if alg.Value > -1 { // Negative numbers are used for second layer objects (COSE_Signature and COSE_recipient)
			return ErrInvalidAlg
		}

		digest, err := m.SignatureDigest(external, &signature)
		if err != nil {
			return err
		}

		verifier, err := opts.GetVerifier(i, signature)
		if err != nil {
			return fmt.Errorf("Error finding a Verifier for signature %d", i)
		}
		if ecdsaKey, ok := verifier.publicKey.(ecdsa.PublicKey); ok {
			curveBits := ecdsaKey.Curve.Params().BitSize
			if alg.expectedKeyBitSize != curveBits {
				return fmt.Errorf("Error verifying signature %d expected %d bit key, got %d bits instead", i, alg.expectedKeyBitSize, curveBits)
			}
		}

		// 3.  Call the signature creation algorithm passing in K (the key to
		//     sign with), alg (the algorithm to sign with), and ToBeSigned (the
		//     value to sign).
		err = verifier.Verify(digest, signature.SignatureBytes)
		if err != nil {
			return err
		}
	}
	return
}
