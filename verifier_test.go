package cose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"reflect"
	"testing"
)

func mustBase64ToBigInt(s string) *big.Int {
	val, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return new(big.Int).SetBytes(val)
}

func generateBogusECKey() *ecdsa.PublicKey {
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		// x-coord is not on curve p-256
		X: mustBase64ToBigInt("MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqx7D4"),
		Y: mustBase64ToBigInt("4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"),
	}
}

func TestNewVerifier(t *testing.T) {
	// generate ecdsa key
	ecdsaKey := generateTestECDSAKey(t).Public().(*ecdsa.PublicKey)

	// generate ed25519 key
	ed25519Key, _ := generateTestEd25519Key(t)

	// generate rsa keys
	rsaKey := generateTestRSAKey(t).Public().(*rsa.PublicKey)
	var rsaKeyLowEntropy *rsa.PublicKey
	if key, err := rsa.GenerateKey(rand.Reader, 1024); err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	} else {
		rsaKeyLowEntropy = &key.PublicKey
	}

	// craft an EC public key with the x-coord not on curve
	ecdsaKeyPointNotOnCurve := generateBogusECKey()

	// run tests
	tests := []struct {
		name    string
		alg     Algorithm
		key     crypto.PublicKey
		want    Verifier
		wantErr bool
	}{
		{
			name: "ecdsa key verifier",
			alg:  AlgorithmES256,
			key:  ecdsaKey,
			want: &ecdsaVerifier{
				alg: AlgorithmES256,
				key: ecdsaKey,
			},
		},
		{
			name:    "ecdsa key mismatch",
			alg:     AlgorithmES256,
			key:     rsaKey,
			wantErr: true,
		},
		{
			name: "ed25519 verifier",
			alg:  AlgorithmEd25519,
			key:  ed25519Key,
			want: &ed25519Verifier{
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
			name: "rsa verifier",
			alg:  AlgorithmPS256,
			key:  rsaKey,
			want: &rsaVerifier{
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
		{
			name:    "bogus ecdsa public key (point not on curve)",
			alg:     AlgorithmES256,
			key:     ecdsaKeyPointNotOnCurve,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewVerifier(tt.alg, tt.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewVerifier() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewVerifier() = %v, want %v", got, tt.want)
			}
		})
	}
}
