package cose

import (
	"crypto"
	"io"
)

type Signer interface {
	Algorithm() Algorithm
	Sign(rand io.Reader, digest []byte) ([]byte, error)
}

func NewSigner(alg Algorithm, key crypto.Signer) (Signer, error) {
	panic("not implemented")
}

func NewSignerWithEphemeralKey(alg *Algorithm) (Signer, crypto.PrivateKey, error) {
	panic("not implemented")
}
