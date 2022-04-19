package cose

import (
	"crypto/rand"
	"crypto/rsa"
	"reflect"
	"testing"
)

func generateTestRSAKey(t *testing.T) *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	return key
}

func Test_rsaSigner(t *testing.T) {
	// generate key
	alg := AlgorithmPS256
	key := generateTestRSAKey(t)

	// set up signer
	signer, err := NewSigner(alg, key)
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}
	if _, ok := signer.(*rsaSigner); !ok {
		t.Fatalf("NewSigner() type = %v, want *rsaSigner", reflect.TypeOf(signer))
	}
	if got := signer.Algorithm(); got != alg {
		t.Fatalf("Algorithm() = %v, want %v", got, alg)
	}

	// sign / verify round trip
	// see also conformance_test.go for strict tests.
	digest, err := alg.computeHash([]byte("hello world"))
	if err != nil {
		t.Fatalf("Algorithm.computeHash() error = %v", err)
	}
	sig, err := signer.Sign(rand.Reader, digest)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	verifier, err := NewVerifier(alg, key.Public())
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	if err := verifier.Verify(digest, sig); err != nil {
		t.Fatalf("Verifier.Verify() error = %v", err)
	}
}

func Test_rsaVerifier_Verify_Success(t *testing.T) {
	// generate key
	alg := AlgorithmPS256
	key := generateTestRSAKey(t)

	// generate a valid signature
	digest, sig := signTestData(t, alg, key)

	// set up verifier
	verifier, err := NewVerifier(alg, key.Public())
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	if _, ok := verifier.(*rsaVerifier); !ok {
		t.Fatalf("NewVerifier() type = %v, want *rsaVerifier", reflect.TypeOf(verifier))
	}
	if got := verifier.Algorithm(); got != alg {
		t.Fatalf("Algorithm() = %v, want %v", got, alg)
	}

	// verify round trip
	if err := verifier.Verify(digest, sig); err != nil {
		t.Fatalf("rsaVerifier.Verify() error = %v", err)
	}
}

func Test_rsaVerifier_Verify_AlgorithmMismatch(t *testing.T) {
	// generate key
	alg := AlgorithmPS256
	key := generateTestRSAKey(t)

	// generate a valid signature
	digest, sig := signTestData(t, alg, key)

	// set up verifier with a different algorithm
	verifier := &rsaVerifier{
		alg: AlgorithmPS512,
		key: &key.PublicKey,
	}

	// verification should fail on algorithm mismatch
	if err := verifier.Verify(digest, sig); err != ErrVerification {
		t.Fatalf("rsaVerifier.Verify() error = %v, wantErr %v", err, ErrVerification)
	}
}

func Test_rsaVerifier_Verify_KeyMismatch(t *testing.T) {
	// generate key
	alg := AlgorithmPS256
	key := generateTestRSAKey(t)

	// generate a valid signature
	digest, sig := signTestData(t, alg, key)

	// set up verifier with a different key / new key
	key = generateTestRSAKey(t)
	verifier := &rsaVerifier{
		alg: alg,
		key: &key.PublicKey,
	}

	// verification should fail on key mismatch
	if err := verifier.Verify(digest, sig); err != ErrVerification {
		t.Fatalf("rsaVerifier.Verify() error = %v, wantErr %v", err, ErrVerification)
	}
}

func Test_rsaVerifier_Verify_InvalidSignature(t *testing.T) {
	// generate key
	alg := AlgorithmPS256
	key := generateTestRSAKey(t)

	// generate a valid signature with a tampered one
	digest, sig := signTestData(t, alg, key)
	tamperedSig := make([]byte, len(sig))
	copy(tamperedSig, sig)
	tamperedSig[0]++

	// set up verifier with a different algorithm
	verifier := &rsaVerifier{
		alg: alg,
		key: &key.PublicKey,
	}

	// verification should fail on invalid signature
	tests := []struct {
		name      string
		signature []byte
	}{
		{
			name:      "nil signature",
			signature: nil,
		},
		{
			name:      "empty signature",
			signature: []byte{},
		},
		{
			name:      "incomplete signature",
			signature: sig[:len(sig)-2],
		},
		{
			name:      "tampered signature",
			signature: tamperedSig,
		},
		{
			name:      "too many signature bytes",
			signature: append(sig, 0),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := verifier.Verify(digest, tt.signature); err != ErrVerification {
				t.Errorf("rsaVerifier.Verify() error = %v, wantErr %v", err, ErrVerification)
			}
		})
	}
}
