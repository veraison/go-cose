package cose

import (
	"crypto"
	"crypto/rsa"
	"io"
)

// rsaSigner is a RSASSA-PSS based signer with a generic crypto.Signer.
//
// Reference: https://www.rfc-editor.org/rfc/rfc8230.html#section-2
type rsaSigner struct {
	alg Algorithm
	key crypto.Signer
}

// Algorithm returns the signing algorithm associated with the private key.
func (rs *rsaSigner) Algorithm() Algorithm {
	return rs.alg
}

// Sign signs digest with the private key, possibly using entropy from rand.
// The resulting signature should follow RFC 8152 section 8.
//
// Reference: https://datatracker.ietf.org/doc/html/rfc8152#section-8
func (rs *rsaSigner) Sign(rand io.Reader, digest []byte) ([]byte, error) {
	hash, _ := rs.alg.hashFunc()
	return rs.key.Sign(rand, digest, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash, // defined in RFC 8230 sec 2
		Hash:       hash,
	})
}
