package cose

import (
	"crypto"
	"crypto/rand"
	"testing"
)

func signTestData(t *testing.T, alg Algorithm, key crypto.Signer) (digest, sig []byte) {
	signer, err := NewSigner(alg, key)
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}
	digest, err = alg.computeHash([]byte("hello world"))
	if err != nil {
		t.Fatalf("Algorithm.computeHash() error = %v", err)
	}
	sig, err = signer.Sign(rand.Reader, digest)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	return
}
