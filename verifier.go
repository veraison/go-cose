package cose

import "crypto"

type Verifier interface {
	Algorithm() Algorithm
	Verify(digest, signature []byte) error
}

func NewVerifier(alg *Algorithm, key crypto.PublicKey) (Verifier, error) {
	panic("not implemented")
}
