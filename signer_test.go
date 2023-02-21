package cose

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"io"
	"reflect"
	"testing"
)

func signTestData(t *testing.T, alg Algorithm, key crypto.Signer) (content, sig []byte) {
	signer, err := NewSigner(alg, key)
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}
	content = []byte("hello world")
	sig, err = signer.Sign(rand.Reader, content)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	return
}

func TestNewSigner(t *testing.T) {
	// generate ecdsa key
	ecdsaKey := generateTestECDSAKey(t)
	ecdsaWrappedKey := struct {
		crypto.Signer
	}{
		Signer: ecdsaKey,
	}

	// generate ed25519 key
	_, ed25519Key := generateTestEd25519Key(t)

	// generate rsa keys
	rsaKey := generateTestRSAKey(t)
	rsaKeyLowEntropy, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}

	// run tests
	tests := []struct {
		name    string
		alg     Algorithm
		key     crypto.Signer
		want    Signer
		wantErr string
	}{
		{
			name: "ecdsa key signer",
			alg:  AlgorithmES256,
			key:  ecdsaKey,
			want: &ecdsaKeySigner{
				alg: AlgorithmES256,
				key: ecdsaKey,
			},
		},
		{
			name: "ecdsa crypto signer",
			alg:  AlgorithmES256,
			key:  ecdsaWrappedKey,
			want: &ecdsaCryptoSigner{
				alg:    AlgorithmES256,
				key:    &ecdsaKey.PublicKey,
				signer: ecdsaWrappedKey,
			},
		},
		{
			name:    "ecdsa key mismatch",
			alg:     AlgorithmES256,
			key:     rsaKey,
			wantErr: "ES256: invalid public key",
		},
		{
			name: "ed25519 signer",
			alg:  AlgorithmEd25519,
			key:  ed25519Key,
			want: &ed25519Signer{
				key: ed25519Key,
			},
		},
		{
			name:    "ed25519 key mismatch",
			alg:     AlgorithmEd25519,
			key:     rsaKey,
			wantErr: "EdDSA: invalid public key",
		},
		{
			name: "rsa signer",
			alg:  AlgorithmPS256,
			key:  rsaKey,
			want: &rsaSigner{
				alg: AlgorithmPS256,
				key: rsaKey,
			},
		},
		{
			name:    "rsa key mismatch",
			alg:     AlgorithmPS256,
			key:     ecdsaKey,
			wantErr: "PS256: invalid public key",
		},
		{
			name:    "rsa key under minimum entropy",
			alg:     AlgorithmPS256,
			key:     rsaKeyLowEntropy,
			wantErr: "RSA key must be at least 2048 bits long",
		},
		{
			name:    "unknown algorithm",
			alg:     0,
			wantErr: "algorithm not supported",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewSigner(tt.alg, tt.key)
			if err != nil && (err.Error() != tt.wantErr) {
				t.Errorf("NewSigner() error = %v, wantErr %v", err, tt.wantErr)
				return
			} else if err == nil && (tt.wantErr != "") {
				t.Errorf("NewSigner() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewSigner() = %v, want %v", got, tt.want)
			}
		})
	}
}

const algorithmMock Algorithm = -0x6d6f636b

type mockSigner struct {
	t *testing.T
	m map[string]string
}

func newMockSigner(t *testing.T) *mockSigner {
	return &mockSigner{
		t: t,
		m: make(map[string]string),
	}
}

func (m *mockSigner) setup(content, sig []byte) {
	m.m[hex.EncodeToString(content)] = hex.EncodeToString(sig) // deep copy
}

func (m *mockSigner) Algorithm() Algorithm {
	return algorithmMock
}

func (m *mockSigner) Sign(rand io.Reader, content []byte) ([]byte, error) {
	sigHex, ok := m.m[hex.EncodeToString(content)]
	if !ok {
		m.t.Fatalf("mockSigner: not setup: %v", content)
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		m.t.Fatalf("mockSigner: failed to decode: %v", sigHex)
	}
	return sig, nil
}
