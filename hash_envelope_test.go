package cose

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
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
	payloadAlg := AlgorithmSHA256
	payloadSHA256 := sha256.Sum256(payload)
	payloadHash := payloadSHA256[:]

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
					HeaderLabelAlgorithm: alg,
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
			name: "unsupported hash algorithm",
			payload: HashEnvelopePayload{
				HashAlgorithm: Algorithm(-15), // SHA-256/64
				HashValue:     payloadHash,
			},
			wantHeaders: Headers{
				Protected: ProtectedHeader{
					HeaderLabelAlgorithm:            alg,
					HeaderLabelPayloadHashAlgorithm: Algorithm(-15), // SHA-256/64
				},
			},
		},
		{
			name: "bad hash value",
			payload: HashEnvelopePayload{
				HashAlgorithm: payloadAlg,
			},
			wantErr: "SHA-256: size mismatch: expected 32, got 0",
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

func TestVerifyHashEnvelope(t *testing.T) {
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
	payloadAlg := AlgorithmSHA256
	payloadSHA256 := sha256.Sum256(payload)
	payloadHash := payloadSHA256[:]

	tests := []struct {
		name     string
		envelope []byte
		message  *Sign1Message
		wantErr  string
	}{
		{
			name: "valid envelope",
			message: &Sign1Message{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm:            alg,
						HeaderLabelPayloadHashAlgorithm: payloadAlg,
					},
				},
				Payload: payloadHash,
			},
		},
		{
			name:    "nil envelope",
			wantErr: "cbor: invalid COSE_Sign1_Tagged object",
		},
		{
			name:     "empty envelope",
			envelope: []byte{},
			wantErr:  "cbor: invalid COSE_Sign1_Tagged object",
		},
		{
			name: "not a Hash_Envelope object",
			message: &Sign1Message{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: alg,
					},
				},
				Payload: payloadHash,
			},
			wantErr: "protected header parameter: payload hash alg: required",
		},

		{
			name: "payload hash algorithm in the unprotected header",
			message: &Sign1Message{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelPayloadHashAlgorithm: payloadAlg,
						HeaderLabelAlgorithm:            alg,
					},
					Unprotected: UnprotectedHeader{
						HeaderLabelPayloadHashAlgorithm: payloadAlg,
					},
				},
				Payload: payloadHash,
			},
			wantErr: "unprotected header parameter: payload hash alg: not allowed",
		},
		{
			name: "invalid payload hash algorithm",
			message: &Sign1Message{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm:            alg,
						HeaderLabelPayloadHashAlgorithm: "SHA-256",
					},
				},
				Payload: payloadHash,
			},
			wantErr: "protected header parameter: payload hash alg: require int type",
		},
		{
			name: "invalid preimage content type in the protected header",
			message: &Sign1Message{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm:                  alg,
						HeaderLabelPayloadHashAlgorithm:       payloadAlg,
						HeaderLabelPayloadPreimageContentType: -1,
					},
				},
				Payload: payloadHash,
			},
			wantErr: "protected header parameter: payload preimage content type: require uint / tstr type",
		},
		{
			name: "invalid preimage content type in the unprotected header",
			message: &Sign1Message{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm:            alg,
						HeaderLabelPayloadHashAlgorithm: payloadAlg,
					},
					Unprotected: UnprotectedHeader{
						HeaderLabelPayloadPreimageContentType: -1,
					},
				},
				Payload: payloadHash,
			},
			wantErr: "unprotected header parameter: payload preimage content type: require uint / tstr type",
		},
		{
			name: "payload location present in the unprotected header",
			message: &Sign1Message{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm:            alg,
						HeaderLabelPayloadHashAlgorithm: payloadAlg,
					},
					Unprotected: UnprotectedHeader{
						HeaderLabelPayloadLocation: "urn:example:location",
					},
				},
				Payload: payloadHash,
			},
			wantErr: "unprotected header parameter: payload location: not allowed",
		},
		{
			name: "invalid payload location in the protected header",
			message: &Sign1Message{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm:            alg,
						HeaderLabelPayloadHashAlgorithm: payloadAlg,
						HeaderLabelPayloadLocation:      0,
					},
				},
				Payload: payloadHash,
			},
			wantErr: "protected header parameter: payload location: require tstr type",
		},
		{
			name: "content type present in the protected header",
			message: &Sign1Message{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm:            alg,
						HeaderLabelContentType:          "text/plain",
						HeaderLabelPayloadHashAlgorithm: payloadAlg,
					},
				},
				Payload: payloadHash,
			},
			wantErr: "protected header parameter: content type: not allowed",
		},
		{
			name: "content type present in the unprotected header",
			message: &Sign1Message{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm:            alg,
						HeaderLabelPayloadHashAlgorithm: payloadAlg,
					},
					Unprotected: UnprotectedHeader{
						HeaderLabelContentType: "text/plain",
					},
				},
				Payload: payloadHash,
			},
			wantErr: "unprotected header parameter: content type: not allowed",
		},
		{
			name: "bad signature",
			message: &Sign1Message{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm:            alg,
						HeaderLabelPayloadHashAlgorithm: payloadAlg,
					},
					Unprotected: UnprotectedHeader{
						HeaderLabelKeyID: []byte("42"),
					},
				},
				Payload:   payloadHash,
				Signature: []byte("bad signature"),
			},
			wantErr: "verification error",
		},
		{
			name: "bad hash value",
			message: &Sign1Message{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm:            alg,
						HeaderLabelPayloadHashAlgorithm: payloadAlg,
					},
					Unprotected: UnprotectedHeader{
						HeaderLabelKeyID: []byte("42"),
					},
				},
				Payload: []byte("bad hash value"),
			},
			wantErr: "SHA-256: size mismatch: expected 32, got 14",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			envelope := tt.envelope
			if tt.message != nil {
				message := tt.message
				if message.Signature == nil {
					if err := message.Sign(rand.Reader, nil, signer); err != nil {
						t.Fatalf("Sign1Message.Sign() error = %v", err)
					}
				}
				var err error
				envelope, err = message.MarshalCBOR()
				if err != nil {
					t.Fatalf("Sign1Message.MarshalCBOR() error = %v", err)
				}
			}
			msg, err := VerifyHashEnvelope(verifier, envelope)
			if err != nil {
				if tt.wantErr == "" || err.Error() != tt.wantErr {
					t.Fatalf("VerifyHashEnvelope() error = %v, wantErr %s", err, tt.wantErr)
				}
				return
			}
			if tt.wantErr != "" {
				t.Fatalf("VerifyHashEnvelope() error = %v, wantErr %s", err, tt.wantErr)
			}
			if msg == nil {
				t.Fatalf("VerifyHashEnvelope() message = nil, want not nil")
			}
		})
	}
}
