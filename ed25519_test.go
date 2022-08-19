package cose

import (
	"crypto/ed25519"
	"crypto/rand"
	"reflect"
	"testing"
)

func generateTestEd25519Key(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	vk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey() error = %v", err)
	}
	return vk, sk
}

func Test_ed25519Signer(t *testing.T) {
	// generate key
	alg := AlgorithmEd25519
	_, key := generateTestEd25519Key(t)

	// set up signer
	signer, err := NewSigner(alg, key)
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}
	if _, ok := signer.(*ed25519Signer); !ok {
		t.Fatalf("NewSigner() type = %v, want *ed25519Signer", reflect.TypeOf(signer))
	}
	if got := signer.Algorithm(); got != alg {
		t.Fatalf("Algorithm() = %v, want %v", got, alg)
	}

	// sign / verify round trip
	// see also conformance_test.go for strict tests.
	content := []byte("hello world")
	sig, err := signer.Sign(rand.Reader, content)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	verifier, err := NewVerifier(alg, key.Public())
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	if err := verifier.Verify(content, sig); err != nil {
		t.Fatalf("Verifier.Verify() error = %v", err)
	}
}

func Test_ed25519Verifier_Verify_Success(t *testing.T) {
	// generate key
	alg := AlgorithmEd25519
	_, key := generateTestEd25519Key(t)

	// generate a valid signature
	content, sig := signTestData(t, alg, key)

	// set up verifier
	verifier, err := NewVerifier(alg, key.Public())
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	if _, ok := verifier.(*ed25519Verifier); !ok {
		t.Fatalf("NewVerifier() type = %v, want *ed25519Verifier", reflect.TypeOf(verifier))
	}
	if got := verifier.Algorithm(); got != alg {
		t.Fatalf("Algorithm() = %v, want %v", got, alg)
	}

	// verify round trip
	if err := verifier.Verify(content, sig); err != nil {
		t.Fatalf("ed25519Verifier.Verify() error = %v", err)
	}
}

func Test_ed25519Verifier_Verify_KeyMismatch(t *testing.T) {
	// generate key
	alg := AlgorithmEd25519
	_, key := generateTestEd25519Key(t)

	// generate a valid signature
	content, sig := signTestData(t, alg, key)

	// set up verifier with a different key / new key
	vk, _ := generateTestEd25519Key(t)
	verifier := &ed25519Verifier{
		key: vk,
	}

	// verification should fail on key mismatch
	if err := verifier.Verify(content, sig); err != ErrVerification {
		t.Fatalf("ed25519Verifier.Verify() error = %v, wantErr %v", err, ErrVerification)
	}
}

func Test_ed25519Verifier_Verify_InvalidSignature(t *testing.T) {
	// generate key
	alg := AlgorithmEd25519
	vk, sk := generateTestEd25519Key(t)

	// generate a valid signature with a tampered one
	content, sig := signTestData(t, alg, sk)
	tamperedSig := make([]byte, len(sig))
	copy(tamperedSig, sig)
	tamperedSig[0]++

	// set up verifier with a different algorithm
	verifier := &ed25519Verifier{
		key: vk,
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
			if err := verifier.Verify(content, tt.signature); err != ErrVerification {
				t.Errorf("ed25519Verifier.Verify() error = %v, wantErr %v", err, ErrVerification)
			}
		})
	}
}
