package cose

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"io"
	"math/big"
)

const (
	// text strings identifying the context of the signature
	// https://tools.ietf.org/html/rfc8152#section-4.4

	// ContextSignature for signatures using the COSE_Signature structure
	ContextSignature = "Signature"

	// ContextSignature1 for signatures using the COSE_Sign1 structure
	ContextSignature1 = "Signature1"

	// ContextCounterSignature for signatures used as counter signature attributes
	ContextCounterSignature = "CounterSignature"
)

// Signer holds a private key for signing SignMessages implements
// crypto.Signer interface
type Signer struct {
	privateKey crypto.PrivateKey
}

// NewSigner checks whether the privateKey is supported and returns a
// new cose.Signer
func NewSigner(privateKey crypto.PrivateKey) (signer *Signer, err error) {
	switch privateKey.(type) {
	case *rsa.PrivateKey:
	case *ecdsa.PrivateKey:
	default:
		return nil, ErrUnknownPrivateKeyType
	}
	return &Signer{
		privateKey: privateKey,
	}, nil
}

// Public returns the crypto.PublicKey for the Signer's privateKey
func (s *Signer) Public() (publicKey crypto.PublicKey) {
	switch key := s.privateKey.(type) {
	case *rsa.PrivateKey:
		return key.Public()
	case *ecdsa.PrivateKey:
		return key.Public()
	default:
		panic("Could not return public key for Unrecognized private key type.")
	}
}

// SignOpts are options for Signer.Sign()
//
// HashFunc is the crypto.Hash to apply to the SigStructure
// func GetSigner returns the cose.Signer for the signature protected
// key ID or an error when one isn't found
type SignOpts struct {
	HashFunc  crypto.Hash
	GetSigner func(index int, signature Signature) (Signer, error)
}

// Sign returns the COSE signature as a byte slice
func (s *Signer) Sign(rand io.Reader, digest []byte, opts SignOpts) (signature []byte, err error) {
	switch key := s.privateKey.(type) {
	case *rsa.PrivateKey:
		sig, err := rsa.SignPSS(rand, key, opts.HashFunc, digest, &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       opts.HashFunc,
		})
		if err != nil {
			return nil, fmt.Errorf("rsa.SignPSS error %s", err)
		}
		return sig, nil
	case *ecdsa.PrivateKey:
		// https://tools.ietf.org/html/rfc8152#section-8.1
		r, s, err := ecdsa.Sign(rand, key, digest)
		if err != nil {
			return nil, fmt.Errorf("ecdsa.Sign error %s", err)
		}

		// TODO: assert r and s are the same length will be
		// the same length as the length of the key used for
		// the signature process

		// The signature is encoded by converting the integers into
		// byte strings of the same length as the key size.  The
		// length is rounded up to the nearest byte and is left padded
		// with zero bits to get to the correct length.  The two
		// integers are then concatenated together to form a byte
		// string that is the resulting signature.
		curveBits := key.Curve.Params().BitSize
		keyBytes := curveBits / 8
		if curveBits%8 > 0 {
			keyBytes++
		}

		n := keyBytes
		sig := make([]byte, 0)
		sig = append(sig, I2OSP(r, n)...)
		sig = append(sig, I2OSP(s, n)...)

		return sig, nil
	default:
		return nil, ErrUnknownPrivateKeyType
	}
}

// Verifier returns a Verifier using the Signer's public key and
// provided Algorithm
func (s *Signer) Verifier(alg *Algorithm) (verifier *Verifier) {
	return &Verifier{
		publicKey: s.Public(),
		alg:       alg,
	}
}

// Verifier holds a PublicKey and Algorithm to verify signatures
type Verifier struct {
	publicKey crypto.PublicKey
	alg       *Algorithm
}

// VerifyOpts are options to the Verifier.Verify requires a function
// that returns verifier or error for a given signature and message
// index
type VerifyOpts struct {
	GetVerifier func(index int, signature Signature) (Verifier, error)
}

// Verify verifies a signature returning nil for success or an error
func (v *Verifier) Verify(digest []byte, signature []byte) (err error) {
	if v.alg.Value > -1 { // Negative numbers are used for second layer objects (COSE_Signature and COSE_recipient)
		return ErrInvalidAlg
	}

	switch key := v.publicKey.(type) {
	case *rsa.PublicKey:
		hashFunc := v.alg.HashFunc

		err = rsa.VerifyPSS(key, hashFunc, digest, signature, &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       hashFunc,
		})
		if err != nil {
			return fmt.Errorf("verification failed rsa.VerifyPSS err %s", err)
		}
		return nil
	case *ecdsa.PublicKey:
		keySize := v.alg.keySize
		if keySize < 1 {
			return fmt.Errorf("Could not find a keySize for the ecdsa algorithm")
		}

		// r and s from sig
		if len(signature) != 2*keySize {
			return fmt.Errorf("invalid signature length: %d", len(signature))
		}

		r := big.NewInt(0).SetBytes(signature[:keySize])
		s := big.NewInt(0).SetBytes(signature[keySize:])

		ok := ecdsa.Verify(key, digest, r, s)
		if ok {
			return nil
		}
		return ErrECDSAVerification
	default:
		return ErrUnknownPublicKeyType
	}
}

// imperative functions on byte slices level

// buildAndMarshalSigStructure creates a Sig_structure, populates it
// with the appropriate fields, and marshals it to CBOR bytes
func buildAndMarshalSigStructure(
	bodyProtected []byte,
	signProtected []byte,
	external []byte,
	payload []byte,
) (ToBeSigned []byte, err error) {
	// 1.  Create a Sig_structure and populate it with the appropriate fields.
	//
	// Sig_structure = [
	//     context : "Signature" / "Signature1" / "CounterSignature",
	//     body_protected : empty_or_serialized_map,
	//     ? sign_protected : empty_or_serialized_map,
	//     external_aad : bstr,
	//     payload : bstr
	// ]
	sigStructure := []interface{}{
		ContextSignature,
		bodyProtected, // message.headers.EncodeProtected(),
		signProtected, // message.signatures[0].headers.EncodeProtected(),
		external,
		payload,
	}

	// 2.  Create the value ToBeSigned by encoding the Sig_structure to a
	//     byte string, using the encoding described in Section 14.
	ToBeSigned, err = Marshal(sigStructure)
	if err != nil {
		return nil, fmt.Errorf("Error marshaling Sig_structure: %s", err)
	}
	return ToBeSigned, nil
}

// hashSigStructure computes the crypto.Hash digest of a byte slice
func hashSigStructure(ToBeSigned []byte, hash crypto.Hash) (digest []byte, err error) {
	if !hash.Available() {
		return []byte(""), ErrUnavailableHashFunc
	}
	hasher := hash.New()
	_, _ = hasher.Write(ToBeSigned) // Write() on hash never fails
	digest = hasher.Sum(nil)
	return digest, nil
}

// I2OSP converts a nonnegative integer to an octet string of a specified length
// https://tools.ietf.org/html/rfc8017#section-4.1
//
// implementation from
// https://github.com/r2ishiguro/vrf/blob/69d5bfb37b72b7b932ffe34213778bdb319f0438/go/vrf_ed25519/vrf_ed25519.go#L206
// (Apache License 2.0)
func I2OSP(b *big.Int, n int) []byte {
	os := b.Bytes()
	if n > len(os) {
		var buf bytes.Buffer
		buf.Write(make([]byte, n-len(os))) // prepend 0s
		buf.Write(os)
		return buf.Bytes()
	}
	return os[:n]
}
