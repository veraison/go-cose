package cose

import (
	"crypto"
	"io"
)

// ed25519Signer is a Pure EdDsA based signer with a generic crypto.Signer.
type ed25519Signer struct {
	key crypto.Signer
}

// Algorithm returns the signing algorithm associated with the private key.
func (rs *ed25519Signer) Algorithm() Algorithm {
	return AlgorithmEd25519
}

// Sign signs digest with the private key, possibly using entropy from rand.
// The resulting signature should follow RFC 8152 section 8.2.
//
// Reference: https://datatracker.ietf.org/doc/html/rfc8152#section-8.2
func (rs *ed25519Signer) Sign(rand io.Reader, digest []byte) ([]byte, error) {
	// crypto.Hash(0) must be passed as an option.
	// Reference: https://pkg.go.dev/crypto/ed25519#PrivateKey.Sign
	return rs.key.Sign(rand, digest, crypto.Hash(0))
}
