package cose

import (
	"bytes"
	"crypto/rand"
	"crypto/sha512"
	"maps"
	"reflect"
	"testing"
)

func TestSignHashEnvelope(t *testing.T) {
	// generate key and set up signer / verifier
	alg := AlgorithmES256
	key := generateTestECDSAKey(t)
	signer, err := NewSigner(alg, key)
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}
	verifier, err := NewVerifier(alg, key.Public())
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	payload := []byte("hello world")
	payloadAlg := AlgorithmSHA512
	payloadSHA512 := sha512.Sum512(payload)
	payloadHash := payloadSHA512[:]

	tests := []struct {
		name        string
		headers     Headers
		payload     HashEnvelopePayload
		wantHeaders Headers
		wantErr     string
	}{
		{
			name: "minimal signing",
			payload: HashEnvelopePayload{
				HashAlgorithm: payloadAlg,
				HashValue:     payloadHash,
			},
			wantHeaders: Headers{
				Protected: ProtectedHeader{
					HeaderLabelAlgorithm:            alg,
					HeaderLabelPayloadHashAlgorithm: payloadAlg,
				},
			},
		},
		{
			name: "with preimage content type (int)",
			payload: HashEnvelopePayload{
				HashAlgorithm:       payloadAlg,
				HashValue:           payloadHash,
				PreimageContentType: 0,
			},
			wantHeaders: Headers{
				Protected: ProtectedHeader{
					HeaderLabelAlgorithm:                  alg,
					HeaderLabelPayloadHashAlgorithm:       payloadAlg,
					HeaderLabelPayloadPreimageContentType: int64(0),
				},
			},
		},
		{
			name: "with preimage content type (tstr)",
			payload: HashEnvelopePayload{
				HashAlgorithm:       payloadAlg,
				HashValue:           payloadHash,
				PreimageContentType: "text/plain",
			},
			wantHeaders: Headers{
				Protected: ProtectedHeader{
					HeaderLabelAlgorithm:                  alg,
					HeaderLabelPayloadHashAlgorithm:       payloadAlg,
					HeaderLabelPayloadPreimageContentType: "text/plain",
				},
			},
		},
		{
			name: "with payload location",
			payload: HashEnvelopePayload{
				HashAlgorithm: payloadAlg,
				HashValue:     payloadHash,
				Location:      "urn:example:location",
			},
			wantHeaders: Headers{
				Protected: ProtectedHeader{
					HeaderLabelAlgorithm:            alg,
					HeaderLabelPayloadHashAlgorithm: payloadAlg,
					HeaderLabelPayloadLocation:      "urn:example:location",
				},
			},
		},
		{
			name: "full signing with base headers",
			headers: Headers{
				Protected: ProtectedHeader{
					HeaderLabelAlgorithm: AlgorithmES256,
				},
				Unprotected: UnprotectedHeader{
					HeaderLabelKeyID: []byte("42"),
				},
			},
			payload: HashEnvelopePayload{
				HashAlgorithm:       payloadAlg,
				HashValue:           payloadHash,
				PreimageContentType: "text/plain",
				Location:            "urn:example:location",
			},
			wantHeaders: Headers{
				Protected: ProtectedHeader{
					HeaderLabelAlgorithm:                  alg,
					HeaderLabelPayloadHashAlgorithm:       payloadAlg,
					HeaderLabelPayloadPreimageContentType: "text/plain",
					HeaderLabelPayloadLocation:            "urn:example:location",
				},
				Unprotected: UnprotectedHeader{
					HeaderLabelKeyID: []byte("42"),
				},
			},
		},
		{
			name: "bad hash algorithm",
			payload: HashEnvelopePayload{
				HashAlgorithm: AlgorithmReserved,
			},
			wantErr: "Reserved: algorithm not supported",
		},
		{
			name: "bad hash value",
			payload: HashEnvelopePayload{
				HashAlgorithm: payloadAlg,
			},
			wantErr: "SHA-512: size mismatch: expected 64, got 0",
		},
		{
			name: "invalid preimage content type",
			payload: HashEnvelopePayload{
				HashAlgorithm:       payloadAlg,
				HashValue:           payloadHash,
				PreimageContentType: -1,
			},
			wantErr: "protected header parameter: payload preimage content type: require uint / tstr type",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SignHashEnvelope(rand.Reader, signer, tt.headers, tt.payload)
			if err != nil {
				if tt.wantErr == "" || err.Error() != tt.wantErr {
					t.Fatalf("SignHashEnvelope() error = %v, wantErr %s", err, tt.wantErr)
				}
				return
			}
			if tt.wantErr != "" {
				t.Fatalf("SignHashEnvelope() error = %v, wantErr %s", err, tt.wantErr)
			}
			msg, err := VerifyHashEnvelope(verifier, got)
			if err != nil {
				t.Fatalf("VerifyHashEnvelope() error = %v", err)
			}
			if !maps.EqualFunc(msg.Headers.Protected, tt.wantHeaders.Protected, reflect.DeepEqual) {
				t.Errorf("SignHashEnvelope() Protected Header = %v, want %v", msg.Headers.Protected, tt.wantHeaders.Protected)
			}
			if !maps.EqualFunc(msg.Headers.Unprotected, tt.wantHeaders.Unprotected, reflect.DeepEqual) {
				t.Errorf("SignHashEnvelope() Unprotected Header = %v, want %v", msg.Headers.Unprotected, tt.wantHeaders.Unprotected)
			}
			if !bytes.Equal(msg.Payload, tt.payload.HashValue) {
				t.Errorf("SignHashEnvelope() Payload = %v, want %v", msg.Payload, tt.payload.HashValue)
			}
		})
	}
}
