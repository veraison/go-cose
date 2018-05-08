package cose

import (
	"encoding/base64"
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
	"github.com/pkg/errors"
)

// ContextSignature identifies the context of the signature as a
// COSE_Signature structure per
// https://tools.ietf.org/html/rfc8152#section-4.4
const ContextSignature = "Signature"

// Supported Algorithms
var (
	// PS256 is RSASSA-PSS w/ SHA-256 from [RFC8230]
	PS256 = getAlgByNameOrPanic("PS256")

	// ES256 is ECDSA w/ SHA-256 from [RFC8152]
	ES256 = getAlgByNameOrPanic("ES256")

	// ES384 is ECDSA w/ SHA-384 from [RFC8152]
	ES384 = getAlgByNameOrPanic("ES384")

	// ES512 is ECDSA w/ SHA-512 from [RFC8152]
	ES512 = getAlgByNameOrPanic("ES512")
)

// Signer holds a COSE Algorithm and private key for signing messages
type Signer struct {
	privateKey crypto.PrivateKey
	alg        *Algorithm
}

type newSignerRSAOptions struct {
	size int
}

// NewSigner returns a Signer with a generated key
func NewSigner(alg *Algorithm, options interface{}) (signer *Signer, err error) {
	var privateKey crypto.PrivateKey

	if alg.privateKeyType == KeyTypeECDSA {
		privateKey, err = ecdsa.GenerateKey(alg.privateKeyECDSACurve, rand.Reader)
		if err != nil {
			err = errors.Wrapf(err, "error generating ecdsa signer private key")
			return nil, err
		}
	} else if alg.privateKeyType == KeyTypeRSA {
		opts, ok := options.(newSignerRSAOptions)
		if ok && opts.size > alg.minRSAKeyBitLen {
			privateKey, err = rsa.GenerateKey(rand.Reader, opts.size)
		} else {
			privateKey, err = rsa.GenerateKey(rand.Reader, alg.minRSAKeyBitLen)
		}
		if err != nil {
			err = errors.Wrapf(err, "error generating rsa signer private key")
			return nil, err
		}
	}

	return &Signer{
		privateKey: privateKey,
		alg: alg,
	}, nil
}

// NewSignerFromKey checks whether the privateKey is supported and
// returns a Signer using the provided key
func NewSignerFromKey(alg *Algorithm, privateKey crypto.PrivateKey) (signer *Signer, err error) {
	switch privateKey.(type) {
	case *rsa.PrivateKey:
	case *ecdsa.PrivateKey:
	default:
		return nil, ErrUnknownPrivateKeyType
	}
	return &Signer{
		privateKey: privateKey,
		alg: alg,
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

// Sign returns the COSE signature as a byte slice
func (s *Signer) Sign(rand io.Reader, digest []byte) (signature []byte, err error) {
	switch key := s.privateKey.(type) {
	case *rsa.PrivateKey:
		if s.alg.privateKeyType != KeyTypeRSA {
			return nil, fmt.Errorf("Key type must be RSA")
		}
		if key.N.BitLen() < s.alg.minRSAKeyBitLen {
			return nil, fmt.Errorf("RSA key must be at least %d bits long", s.alg.minRSAKeyBitLen)
		}

		sig, err := rsa.SignPSS(rand, key, s.alg.HashFunc, digest, &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       s.alg.HashFunc,
		})
		if err != nil {
			return nil, fmt.Errorf("rsa.SignPSS error %s", err)
		}
		return sig, nil
	case *ecdsa.PrivateKey:
		if s.alg.privateKeyType != KeyTypeECDSA {
			return nil, fmt.Errorf("Key type must be ECDSA")
		}

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
		curveBits := key.Curve.Params().BitSize
		if v.alg.expectedKeyBitSize != curveBits {
			return fmt.Errorf("Expected %d bit key, got %d bits instead", v.alg.expectedKeyBitSize, curveBits)
		}

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

// buildAndMarshalSigStructure creates a Sig_structure, populates it
// with the appropriate fields, and marshals it to CBOR bytes
func buildAndMarshalSigStructure(bodyProtected, signProtected, external, payload []byte) (ToBeSigned []byte, err error) {
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

// I2OSP "Integer-to-Octet-String" converts a nonnegative integer to
// an octet string of a specified length
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

// FromBase64Int decodes a base64-encoded string into a big.Int or panics
//
// from https://github.com/square/go-jose/blob/789a4c4bd4c118f7564954f441b29c153ccd6a96/utils_test.go#L45
// Apache License 2.0
func FromBase64Int(data string) *big.Int {
	val, err := base64.RawURLEncoding.DecodeString(data)
	if err != nil {
		panic("Invalid test data")
	}
	return new(big.Int).SetBytes(val)
}
