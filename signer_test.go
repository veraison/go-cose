package cose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"reflect"
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

func TestNewSigner(t *testing.T) {
	// generate ecdsa key
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey() error = %v", err)
	}
	ecdsaWrappedKey := struct {
		crypto.Signer
	}{
		Signer: ecdsaKey,
	}

	// generate ed25519 key
	_, ed25519Key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey() error = %v", err)
	}

	// generate rsa keys
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
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
		wantErr bool
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
			wantErr: true,
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
			wantErr: true,
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
			wantErr: true,
		},
		{
			name:    "rsa key under minimum entropy",
			alg:     AlgorithmPS256,
			key:     rsaKeyLowEntropy,
			wantErr: true,
		},
		{
			name:    "unknown algorithm",
			alg:     0,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewSigner(tt.alg, tt.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewSigner() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewSigner() = %v, want %v", got, tt.want)
			}
		})
	}
}
