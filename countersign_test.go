package cose

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"reflect"
	"testing"
)

func TestCountersignature_MarshalCBOR(t *testing.T) {
	tests := []struct {
		name    string
		s       *Countersignature
		want    []byte
		wantErr string
	}{
		{
			name: "valid message",
			s: &Countersignature{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: AlgorithmES256,
					},
					Unprotected: UnprotectedHeader{
						HeaderLabelContentType: 42,
					},
				},
				Signature: []byte("bar"),
			},
			want: []byte{
				0x83,                   // array of size 3
				0x43, 0xa1, 0x01, 0x26, // protected
				0xa1, 0x03, 0x18, 0x2a, // unprotected
				0x43, 0x62, 0x61, 0x72, // signature
			},
		},
		{
			name:    "nil signature",
			s:       nil,
			wantErr: "cbor: MarshalCBOR on nil Countersignature pointer",
		},
		{
			name: "nil signature",
			s: &Countersignature{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: AlgorithmES256,
					},
					Unprotected: UnprotectedHeader{
						HeaderLabelContentType: 42,
					},
				},
				Signature: nil,
			},
			wantErr: "empty signature",
		},
		{
			name: "empty signature",
			s: &Countersignature{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: AlgorithmES256,
					},
					Unprotected: UnprotectedHeader{
						HeaderLabelContentType: 42,
					},
				},
				Signature: []byte{},
			},
			wantErr: "empty signature",
		},
		{
			name: "invalid protected header",
			s: &Countersignature{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: make(chan bool),
					},
					Unprotected: UnprotectedHeader{
						HeaderLabelContentType: 42,
					},
				},
				Signature: []byte("bar"),
			},
			wantErr: "protected header: header parameter: alg: require int / tstr type",
		},
		{
			name: "invalid unprotected header",
			s: &Countersignature{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: AlgorithmES256,
					},
					Unprotected: UnprotectedHeader{
						"foo": make(chan bool),
					},
				},
				Signature: []byte("bar"),
			},
			wantErr: "cbor: unsupported type: chan bool",
		},
		{
			name: "protected has IV and unprotected has PartialIV error",
			s: &Countersignature{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: AlgorithmES256,
						HeaderLabelIV:        []byte(""),
					},
					Unprotected: UnprotectedHeader{
						HeaderLabelPartialIV: []byte(""),
					},
				},
				Signature: []byte("bar"),
			},
			wantErr: "IV (protected) and PartialIV (unprotected) parameters must not both be present",
		},
		{
			name: "protected has PartialIV and unprotected has IV error",
			s: &Countersignature{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: AlgorithmES256,
						HeaderLabelPartialIV: []byte(""),
					},
					Unprotected: UnprotectedHeader{
						HeaderLabelIV: []byte(""),
					},
				},
				Signature: []byte("bar"),
			},
			wantErr: "IV (unprotected) and PartialIV (protected) parameters must not both be present",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.s.MarshalCBOR()
			if err != nil && (err.Error() != tt.wantErr) {
				t.Errorf("Countersignature.MarshalCBOR() error = %v, wantErr %v", err, tt.wantErr)
				return
			} else if err == nil && (tt.wantErr != "") {
				t.Errorf("Countersignature.MarshalCBOR() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Countersignature.MarshalCBOR() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCountersignature_UnmarshalCBOR(t *testing.T) {
	// test nil pointer
	t.Run("nil Countersignature pointer", func(t *testing.T) {
		var sig *Countersignature
		data := []byte{0x83, 0x40, 0xa0, 0x41, 0x00}
		if err := sig.UnmarshalCBOR(data); err == nil {
			t.Errorf("want error on nil *Countersignature")
		}
	})

	// test others
	tests := []struct {
		name    string
		data    []byte
		want    Countersignature
		wantErr string
	}{
		{
			name: "valid signature struct",
			data: []byte{
				0x83,
				0x43, 0xa1, 0x01, 0x26, // protected
				0xa1, 0x03, 0x18, 0x2a, // unprotected
				0x43, 0x62, 0x61, 0x72, // signature
			},
			want: Countersignature{
				Headers: Headers{
					RawProtected: []byte{0x43, 0xa1, 0x01, 0x26},
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: AlgorithmES256,
					},
					RawUnprotected: []byte{0xa1, 0x03, 0x18, 0x2a},
					Unprotected: UnprotectedHeader{
						HeaderLabelContentType: int64(42),
					},
				},
				Signature: []byte("bar"),
			},
		},
		{
			name:    "nil CBOR data",
			data:    nil,
			wantErr: "cbor: invalid Signature object",
		},
		{
			name:    "empty CBOR data",
			data:    []byte{},
			wantErr: "cbor: invalid Signature object",
		},
		{
			name: "tagged signature", // issue #30
			data: []byte{
				0x83,
				0x40, 0xa0, // empty headers
				0xcb, 0xa1, 0x00, // tagged signature
			},
			wantErr: "cbor: CBOR tag isn't allowed",
		},
		{
			name: "nil signature",
			data: []byte{
				0x83,
				0x40, 0xa0, // empty headers
				0xf6, // nil signature
			},
			wantErr: "empty signature",
		},
		{
			name: "empty signature",
			data: []byte{
				0x83,
				0x40, 0xa0, // empty headers
				0x40, // empty signature
			},
			wantErr: "empty signature",
		},
		{
			name: "mismatch type",
			data: []byte{
				0x40,
			},
			wantErr: "cbor: invalid Signature object",
		},
		{
			name: "smaller array size",
			data: []byte{
				0x82,
				0x40, 0xa0, // empty headers
			},
			wantErr: "cbor: invalid Signature object",
		},
		{
			name: "larger array size",
			data: []byte{
				0x84,
				0x40, 0xa0, // empty headers
				0x41, 0x00, // signature
				0x40,
			},
			wantErr: "cbor: invalid Signature object",
		},
		{
			name: "signature as a byte array",
			data: []byte{
				0x83,
				0x40, 0xa0, // empty headers
				0x81, 0x00, // signature
			},
			wantErr: "cbor: require bstr type",
		},
		{
			name: "protected has IV and unprotected has PartialIV",
			data: []byte{
				0x83,
				0x46, 0xa1, 0x5, 0x63, 0x66, 0x6f, 0x6f, // protected
				0xa1, 0x6, 0x63, 0x62, 0x61, 0x72, // unprotected
				0x43, 0x62, 0x61, 0x72, // signature
			},
			wantErr: "cbor: invalid protected header: protected header: header parameter: IV: require bstr type",
		},
		{
			name: "protected has PartialIV and unprotected has IV",
			data: []byte{
				0x83,
				0x46, 0xa1, 0x6, 0x63, 0x66, 0x6f, 0x6f, // protected
				0xa1, 0x5, 0x63, 0x62, 0x61, 0x72, // unprotected
				0x43, 0x62, 0x61, 0x72, // signature
			},
			wantErr: "cbor: invalid protected header: protected header: header parameter: Partial IV: require bstr type",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got Countersignature
			err := got.UnmarshalCBOR(tt.data)
			if err != nil && (err.Error() != tt.wantErr) {
				t.Errorf("Countersignature.UnmarshalCBOR() error = %v, wantErr %v", err, tt.wantErr)
				return
			} else if err == nil && (tt.wantErr != "") {
				t.Errorf("Countersignature.UnmarshalCBOR() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Countersignature.MarshalCBOR() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCountersignature_Sign(t *testing.T) {
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

	// sign / verify round trip
	type args struct {
		parent   any
		external []byte
	}
	tests := []struct {
		name     string
		sig      *Countersignature
		onSign   args
		onVerify args
		wantErr  string
		check    func(t *testing.T, s *Countersignature)
	}{
		{
			name: "valid message",
			sig: &Countersignature{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: AlgorithmES256,
					},
					Unprotected: UnprotectedHeader{
						HeaderLabelKeyID: []byte("11"),
					},
				},
			},
			onSign: args{
				parent: Signature{
					Headers: Headers{
						Protected: ProtectedHeader{
							HeaderLabelAlgorithm: AlgorithmES256,
						},
						Unprotected: UnprotectedHeader{
							HeaderLabelKeyID: []byte("42"),
						},
					},
					Signature: []byte{
						0x74, 0xc6, 0xac, 0xa6, 0x7d, 0x7a, 0x00, 0xea,
						0x0f, 0x9b, 0x86, 0xb3, 0x85, 0x7a, 0x7d, 0x36,
						0xd2, 0x77, 0x91, 0x73, 0x40, 0x09, 0x35, 0x4e,
						0x8c, 0x9f, 0xd6, 0x03, 0x37, 0xab, 0x43, 0xf5,
					},
				},
				external: []byte{},
			},
			onVerify: args{
				parent: Signature{
					Headers: Headers{
						Protected: ProtectedHeader{
							HeaderLabelAlgorithm: AlgorithmES256,
						},
						Unprotected: UnprotectedHeader{
							HeaderLabelKeyID: []byte("42"),
						},
					},
					Signature: []byte{
						0x74, 0xc6, 0xac, 0xa6, 0x7d, 0x7a, 0x00, 0xea,
						0x0f, 0x9b, 0x86, 0xb3, 0x85, 0x7a, 0x7d, 0x36,
						0xd2, 0x77, 0x91, 0x73, 0x40, 0x09, 0x35, 0x4e,
						0x8c, 0x9f, 0xd6, 0x03, 0x37, 0xab, 0x43, 0xf5,
					},
				},
				external: []byte{},
			},
		},
		{
			name: "valid message with external",
			sig: &Countersignature{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: AlgorithmES256,
					},
					Unprotected: UnprotectedHeader{
						HeaderLabelKeyID: []byte("11"),
					},
				},
			},
			onSign: args{
				parent: Signature{
					Headers: Headers{
						Protected: ProtectedHeader{
							HeaderLabelAlgorithm: AlgorithmES256,
						},
						Unprotected: UnprotectedHeader{
							HeaderLabelKeyID: []byte("42"),
						},
					},
					Signature: []byte{
						0x74, 0xc6, 0xac, 0xa6, 0x7d, 0x7a, 0x00, 0xea,
						0x0f, 0x9b, 0x86, 0xb3, 0x85, 0x7a, 0x7d, 0x36,
						0xd2, 0x77, 0x91, 0x73, 0x40, 0x09, 0x35, 0x4e,
						0x8c, 0x9f, 0xd6, 0x03, 0x37, 0xab, 0x43, 0xf5,
					},
				},
				external: []byte("foo"),
			},
			onVerify: args{
				parent: Signature{
					Headers: Headers{
						Protected: ProtectedHeader{
							HeaderLabelAlgorithm: AlgorithmES256,
						},
						Unprotected: UnprotectedHeader{
							HeaderLabelKeyID: []byte("42"),
						},
					},
					Signature: []byte{
						0x74, 0xc6, 0xac, 0xa6, 0x7d, 0x7a, 0x00, 0xea,
						0x0f, 0x9b, 0x86, 0xb3, 0x85, 0x7a, 0x7d, 0x36,
						0xd2, 0x77, 0x91, 0x73, 0x40, 0x09, 0x35, 0x4e,
						0x8c, 0x9f, 0xd6, 0x03, 0x37, 0xab, 0x43, 0xf5,
					},
				},
				external: []byte("foo"),
			},
		},
		{
			name: "nil external",
			sig: &Countersignature{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: AlgorithmES256,
					},
					Unprotected: UnprotectedHeader{
						HeaderLabelKeyID: []byte("11"),
					},
				},
			},
			onSign: args{
				parent: Signature{
					Headers: Headers{
						Protected: ProtectedHeader{
							HeaderLabelAlgorithm: AlgorithmES256,
						},
						Unprotected: UnprotectedHeader{
							HeaderLabelKeyID: []byte("42"),
						},
					},
					Signature: []byte{
						0x74, 0xc6, 0xac, 0xa6, 0x7d, 0x7a, 0x00, 0xea,
						0x0f, 0x9b, 0x86, 0xb3, 0x85, 0x7a, 0x7d, 0x36,
						0xd2, 0x77, 0x91, 0x73, 0x40, 0x09, 0x35, 0x4e,
						0x8c, 0x9f, 0xd6, 0x03, 0x37, 0xab, 0x43, 0xf5,
					},
				},
				external: nil,
			},
			onVerify: args{
				parent: Signature{
					Headers: Headers{
						Protected: ProtectedHeader{
							HeaderLabelAlgorithm: AlgorithmES256,
						},
						Unprotected: UnprotectedHeader{
							HeaderLabelKeyID: []byte("42"),
						},
					},
					Signature: []byte{
						0x74, 0xc6, 0xac, 0xa6, 0x7d, 0x7a, 0x00, 0xea,
						0x0f, 0x9b, 0x86, 0xb3, 0x85, 0x7a, 0x7d, 0x36,
						0xd2, 0x77, 0x91, 0x73, 0x40, 0x09, 0x35, 0x4e,
						0x8c, 0x9f, 0xd6, 0x03, 0x37, 0xab, 0x43, 0xf5,
					},
				},
				external: nil,
			},
		},
		{
			name: "mixed nil / empty external",
			sig: &Countersignature{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: AlgorithmES256,
					},
					Unprotected: UnprotectedHeader{
						HeaderLabelKeyID: []byte("11"),
					},
				},
			},
			onSign: args{
				parent: Signature{
					Headers: Headers{
						Protected: ProtectedHeader{
							HeaderLabelAlgorithm: AlgorithmES256,
						},
						Unprotected: UnprotectedHeader{
							HeaderLabelKeyID: []byte("42"),
						},
					},
					Signature: []byte{
						0x74, 0xc6, 0xac, 0xa6, 0x7d, 0x7a, 0x00, 0xea,
						0x0f, 0x9b, 0x86, 0xb3, 0x85, 0x7a, 0x7d, 0x36,
						0xd2, 0x77, 0x91, 0x73, 0x40, 0x09, 0x35, 0x4e,
						0x8c, 0x9f, 0xd6, 0x03, 0x37, 0xab, 0x43, 0xf5,
					},
				},
				external: []byte{},
			},
			onVerify: args{
				parent: Signature{
					Headers: Headers{
						Protected: ProtectedHeader{
							HeaderLabelAlgorithm: AlgorithmES256,
						},
						Unprotected: UnprotectedHeader{
							HeaderLabelKeyID: []byte("42"),
						},
					},
					Signature: []byte{
						0x74, 0xc6, 0xac, 0xa6, 0x7d, 0x7a, 0x00, 0xea,
						0x0f, 0x9b, 0x86, 0xb3, 0x85, 0x7a, 0x7d, 0x36,
						0xd2, 0x77, 0x91, 0x73, 0x40, 0x09, 0x35, 0x4e,
						0x8c, 0x9f, 0xd6, 0x03, 0x37, 0xab, 0x43, 0xf5,
					},
				},
				external: nil,
			},
		},
		{
			name: "nil payload", // payload is detached
			sig: &Countersignature{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: AlgorithmES256,
					},
				},
			},
			onSign: args{
				parent: Sign1Message{
					Headers: Headers{
						Protected: ProtectedHeader{
							HeaderLabelAlgorithm: AlgorithmES256,
						},
						Unprotected: UnprotectedHeader{
							HeaderLabelKeyID: []byte("42"),
						},
					},
					Payload: nil,
					Signature: []byte{
						0x74, 0xc6, 0xac, 0xa6, 0x7d, 0x7a, 0x00, 0xea,
						0x0f, 0x9b, 0x86, 0xb3, 0x85, 0x7a, 0x7d, 0x36,
						0xd2, 0x77, 0x91, 0x73, 0x40, 0x09, 0x35, 0x4e,
						0x8c, 0x9f, 0xd6, 0x03, 0x37, 0xab, 0x43, 0xf5,
					},
				},
			},
			onVerify: args{
				parent: Sign1Message{
					Headers: Headers{
						Protected: ProtectedHeader{
							HeaderLabelAlgorithm: AlgorithmES256,
						},
						Unprotected: UnprotectedHeader{
							HeaderLabelKeyID: []byte("42"),
						},
					},
					Payload: nil,
					Signature: []byte{
						0x74, 0xc6, 0xac, 0xa6, 0x7d, 0x7a, 0x00, 0xea,
						0x0f, 0x9b, 0x86, 0xb3, 0x85, 0x7a, 0x7d, 0x36,
						0xd2, 0x77, 0x91, 0x73, 0x40, 0x09, 0x35, 0x4e,
						0x8c, 0x9f, 0xd6, 0x03, 0x37, 0xab, 0x43, 0xf5,
					},
				},
			},
			wantErr: "missing payload",
		},
		{
			name: "mismatch algorithm",
			sig: &Countersignature{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: AlgorithmES512,
					},
				},
			},
			onSign: args{
				parent: Signature{
					Headers: Headers{
						Protected: ProtectedHeader{
							HeaderLabelAlgorithm: AlgorithmES256,
						},
						Unprotected: UnprotectedHeader{
							HeaderLabelKeyID: []byte("42"),
						},
					},
					Signature: []byte{
						0x74, 0xc6, 0xac, 0xa6, 0x7d, 0x7a, 0x00, 0xea,
						0x0f, 0x9b, 0x86, 0xb3, 0x85, 0x7a, 0x7d, 0x36,
						0xd2, 0x77, 0x91, 0x73, 0x40, 0x09, 0x35, 0x4e,
						0x8c, 0x9f, 0xd6, 0x03, 0x37, 0xab, 0x43, 0xf5,
					},
				},
			},
			onVerify: args{
				parent: Signature{
					Headers: Headers{
						Protected: ProtectedHeader{
							HeaderLabelAlgorithm: AlgorithmES256,
						},
						Unprotected: UnprotectedHeader{
							HeaderLabelKeyID: []byte("42"),
						},
					},
					Signature: []byte{
						0x74, 0xc6, 0xac, 0xa6, 0x7d, 0x7a, 0x00, 0xea,
						0x0f, 0x9b, 0x86, 0xb3, 0x85, 0x7a, 0x7d, 0x36,
						0xd2, 0x77, 0x91, 0x73, 0x40, 0x09, 0x35, 0x4e,
						0x8c, 0x9f, 0xd6, 0x03, 0x37, 0xab, 0x43, 0xf5,
					},
				},
			},
			wantErr: "algorithm mismatch: signer ES256: header ES512",
		},
		{
			name: "missing algorithm",
			sig:  &Countersignature{},
			onSign: args{
				parent: Signature{
					Headers: Headers{
						Protected: ProtectedHeader{
							HeaderLabelAlgorithm: AlgorithmES256,
						},
						Unprotected: UnprotectedHeader{
							HeaderLabelKeyID: []byte("42"),
						},
					},
					Signature: []byte{
						0x74, 0xc6, 0xac, 0xa6, 0x7d, 0x7a, 0x00, 0xea,
						0x0f, 0x9b, 0x86, 0xb3, 0x85, 0x7a, 0x7d, 0x36,
						0xd2, 0x77, 0x91, 0x73, 0x40, 0x09, 0x35, 0x4e,
						0x8c, 0x9f, 0xd6, 0x03, 0x37, 0xab, 0x43, 0xf5,
					},
				},
			},
			onVerify: args{
				parent: Signature{
					Headers: Headers{
						Protected: ProtectedHeader{
							HeaderLabelAlgorithm: AlgorithmES256,
						},
						Unprotected: UnprotectedHeader{
							HeaderLabelKeyID: []byte("42"),
						},
					},
					Signature: []byte{
						0x74, 0xc6, 0xac, 0xa6, 0x7d, 0x7a, 0x00, 0xea,
						0x0f, 0x9b, 0x86, 0xb3, 0x85, 0x7a, 0x7d, 0x36,
						0xd2, 0x77, 0x91, 0x73, 0x40, 0x09, 0x35, 0x4e,
						0x8c, 0x9f, 0xd6, 0x03, 0x37, 0xab, 0x43, 0xf5,
					},
				},
			},
			check: func(t *testing.T, s *Countersignature) {
				got, err := s.Headers.Protected.Algorithm()
				if err != nil {
					t.Errorf("Countersignature.Headers.Protected.Algorithm() error = %v", err)
				}
				if got != alg {
					t.Errorf("Countersignature.Headers.Protected.Algorithm() = %v, want %v", got, alg)
				}
			},
		},
		{
			name: "missing algorithm with raw protected",
			sig: &Countersignature{
				Headers: Headers{
					RawProtected: []byte{0x40},
				},
			},
			onSign: args{
				parent: Signature{
					Headers: Headers{
						Protected: ProtectedHeader{
							HeaderLabelAlgorithm: AlgorithmES256,
						},
						Unprotected: UnprotectedHeader{
							HeaderLabelKeyID: []byte("42"),
						},
					},
					Signature: []byte{
						0x74, 0xc6, 0xac, 0xa6, 0x7d, 0x7a, 0x00, 0xea,
						0x0f, 0x9b, 0x86, 0xb3, 0x85, 0x7a, 0x7d, 0x36,
						0xd2, 0x77, 0x91, 0x73, 0x40, 0x09, 0x35, 0x4e,
						0x8c, 0x9f, 0xd6, 0x03, 0x37, 0xab, 0x43, 0xf5,
					},
				},
			},
			onVerify: args{
				parent: Signature{
					Headers: Headers{
						Protected: ProtectedHeader{
							HeaderLabelAlgorithm: AlgorithmES256,
						},
						Unprotected: UnprotectedHeader{
							HeaderLabelKeyID: []byte("42"),
						},
					},
					Signature: []byte{
						0x74, 0xc6, 0xac, 0xa6, 0x7d, 0x7a, 0x00, 0xea,
						0x0f, 0x9b, 0x86, 0xb3, 0x85, 0x7a, 0x7d, 0x36,
						0xd2, 0x77, 0x91, 0x73, 0x40, 0x09, 0x35, 0x4e,
						0x8c, 0x9f, 0xd6, 0x03, 0x37, 0xab, 0x43, 0xf5,
					},
				},
			},
			wantErr: "algorithm not found",
		},
		{
			name: "missing algorithm with externally supplied data",
			sig:  &Countersignature{},
			onSign: args{
				parent: Signature{
					Headers: Headers{
						Protected: ProtectedHeader{
							HeaderLabelAlgorithm: AlgorithmES256,
						},
						Unprotected: UnprotectedHeader{
							HeaderLabelKeyID: []byte("42"),
						},
					},
					Signature: []byte{
						0x74, 0xc6, 0xac, 0xa6, 0x7d, 0x7a, 0x00, 0xea,
						0x0f, 0x9b, 0x86, 0xb3, 0x85, 0x7a, 0x7d, 0x36,
						0xd2, 0x77, 0x91, 0x73, 0x40, 0x09, 0x35, 0x4e,
						0x8c, 0x9f, 0xd6, 0x03, 0x37, 0xab, 0x43, 0xf5,
					},
				},
				external: []byte("foo"),
			},
			onVerify: args{
				parent: Signature{
					Headers: Headers{
						Protected: ProtectedHeader{
							HeaderLabelAlgorithm: AlgorithmES256,
						},
						Unprotected: UnprotectedHeader{
							HeaderLabelKeyID: []byte("42"),
						},
					},
					Signature: []byte{
						0x74, 0xc6, 0xac, 0xa6, 0x7d, 0x7a, 0x00, 0xea,
						0x0f, 0x9b, 0x86, 0xb3, 0x85, 0x7a, 0x7d, 0x36,
						0xd2, 0x77, 0x91, 0x73, 0x40, 0x09, 0x35, 0x4e,
						0x8c, 0x9f, 0xd6, 0x03, 0x37, 0xab, 0x43, 0xf5,
					},
				},
				external: []byte("foo"),
			},
			check: func(t *testing.T, s *Countersignature) {
				_, err := s.Headers.Protected.Algorithm()
				if want := ErrAlgorithmNotFound; err != want {
					t.Errorf("Countersignature.Headers.Protected.Algorithm() error = %v, wantErr %v", err, want)
				}
			},
		},
		{
			name: "double signing",
			sig: &Countersignature{
				Signature: []byte("foobar"),
			},
			onSign: args{
				parent: Signature{
					Headers: Headers{
						Protected: ProtectedHeader{
							HeaderLabelAlgorithm: AlgorithmES256,
						},
						Unprotected: UnprotectedHeader{
							HeaderLabelKeyID: []byte("42"),
						},
					},
					Signature: []byte{
						0x74, 0xc6, 0xac, 0xa6, 0x7d, 0x7a, 0x00, 0xea,
						0x0f, 0x9b, 0x86, 0xb3, 0x85, 0x7a, 0x7d, 0x36,
						0xd2, 0x77, 0x91, 0x73, 0x40, 0x09, 0x35, 0x4e,
						0x8c, 0x9f, 0xd6, 0x03, 0x37, 0xab, 0x43, 0xf5,
					},
				},
			},
			onVerify: args{
				parent: Signature{
					Headers: Headers{
						Protected: ProtectedHeader{
							HeaderLabelAlgorithm: AlgorithmES256,
						},
						Unprotected: UnprotectedHeader{
							HeaderLabelKeyID: []byte("42"),
						},
					},
					Signature: []byte{
						0x74, 0xc6, 0xac, 0xa6, 0x7d, 0x7a, 0x00, 0xea,
						0x0f, 0x9b, 0x86, 0xb3, 0x85, 0x7a, 0x7d, 0x36,
						0xd2, 0x77, 0x91, 0x73, 0x40, 0x09, 0x35, 0x4e,
						0x8c, 0x9f, 0xd6, 0x03, 0x37, 0xab, 0x43, 0xf5,
					},
				},
			},
			wantErr: "Countersignature already has signature bytes",
		},
		{
			name:     "nil countersignature",
			sig:      nil,
			onSign:   args{},
			onVerify: args{},
			wantErr:  "signing nil Countersignature",
		},
		{
			name: "empty body protected header, zero-length byte string is used",
			sig: &Countersignature{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: AlgorithmES256,
					},
					Unprotected: UnprotectedHeader{
						HeaderLabelKeyID: []byte("42"),
					},
				},
			},
			onSign: args{
				parent: Signature{
					Signature: []byte{
						0x74, 0xc6, 0xac, 0xa6, 0x7d, 0x7a, 0x00, 0xea,
						0x0f, 0x9b, 0x86, 0xb3, 0x85, 0x7a, 0x7d, 0x36,
						0xd2, 0x77, 0x91, 0x73, 0x40, 0x09, 0x35, 0x4e,
						0x8c, 0x9f, 0xd6, 0x03, 0x37, 0xab, 0x43, 0xf5,
					},
				},
			},
			onVerify: args{
				parent: Signature{
					Signature: []byte{
						0x74, 0xc6, 0xac, 0xa6, 0x7d, 0x7a, 0x00, 0xea,
						0x0f, 0x9b, 0x86, 0xb3, 0x85, 0x7a, 0x7d, 0x36,
						0xd2, 0x77, 0x91, 0x73, 0x40, 0x09, 0x35, 0x4e,
						0x8c, 0x9f, 0xd6, 0x03, 0x37, 0xab, 0x43, 0xf5,
					},
				},
			},
		},
		{
			name: "invalid protected header",
			sig: &Countersignature{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: AlgorithmES256,
					},
					Unprotected: UnprotectedHeader{
						HeaderLabelKeyID: []byte("42"),
					},
				},
			},
			onSign: args{
				parent: Signature{
					Headers: Headers{
						Protected: ProtectedHeader{
							HeaderLabelAlgorithm: AlgorithmES256,
							HeaderLabelCritical:  []any{},
						},
						Unprotected: UnprotectedHeader{
							HeaderLabelKeyID: []byte("42"),
						},
					},
					Signature: []byte{
						0x74, 0xc6, 0xac, 0xa6, 0x7d, 0x7a, 0x00, 0xea,
						0x0f, 0x9b, 0x86, 0xb3, 0x85, 0x7a, 0x7d, 0x36,
						0xd2, 0x77, 0x91, 0x73, 0x40, 0x09, 0x35, 0x4e,
						0x8c, 0x9f, 0xd6, 0x03, 0x37, 0xab, 0x43, 0xf5,
					},
				},
			},
			onVerify: args{
				parent: Signature{
					Headers: Headers{
						Protected: ProtectedHeader{
							HeaderLabelAlgorithm: AlgorithmES256,
							HeaderLabelCritical:  []any{},
						},
						Unprotected: UnprotectedHeader{
							HeaderLabelKeyID: []byte("42"),
						},
					},
					Signature: []byte{
						0x74, 0xc6, 0xac, 0xa6, 0x7d, 0x7a, 0x00, 0xea,
						0x0f, 0x9b, 0x86, 0xb3, 0x85, 0x7a, 0x7d, 0x36,
						0xd2, 0x77, 0x91, 0x73, 0x40, 0x09, 0x35, 0x4e,
						0x8c, 0x9f, 0xd6, 0x03, 0x37, 0xab, 0x43, 0xf5,
					},
				},
			},
			wantErr: "protected header: header parameter: crit: empty crit header",
		},
		{
			name: "countersign a Signature that was not signed is not allowed",
			sig: &Countersignature{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: AlgorithmES256,
					},
					Unprotected: UnprotectedHeader{
						HeaderLabelKeyID: []byte("11"),
					},
				},
			},
			onSign: args{
				parent: Signature{
					Headers: Headers{
						Protected: ProtectedHeader{
							HeaderLabelAlgorithm: AlgorithmES256,
						},
						Unprotected: UnprotectedHeader{
							HeaderLabelKeyID: []byte("42"),
						},
					},
				},
				external: []byte{},
			},
			onVerify: args{
				parent: Signature{
					Headers: Headers{
						Protected: ProtectedHeader{
							HeaderLabelAlgorithm: AlgorithmES256,
						},
						Unprotected: UnprotectedHeader{
							HeaderLabelKeyID: []byte("42"),
						},
					},
				},
				external: []byte{},
			},
			wantErr: "Signature was not signed yet",
		},
		{
			name: "countersign a valid SignMessage",
			sig: &Countersignature{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: AlgorithmES256,
					},
					Unprotected: UnprotectedHeader{
						HeaderLabelKeyID: []byte("11"),
					},
				},
			},
			onSign: args{
				parent: SignMessage{
					Headers: Headers{
						Protected:   ProtectedHeader{},
						Unprotected: UnprotectedHeader{},
					},
					Payload: []byte("hello world"),
					Signatures: []*Signature{
						{
							Headers: Headers{
								Protected: ProtectedHeader{
									HeaderLabelAlgorithm: AlgorithmES256,
								},
								Unprotected: UnprotectedHeader{
									HeaderLabelKeyID: []byte("42"),
								},
							},
							Signature: []byte{
								0x74, 0xc6, 0xac, 0xa6, 0x7d, 0x7a, 0x00, 0xea,
								0x0f, 0x9b, 0x86, 0xb3, 0x85, 0x7a, 0x7d, 0x36,
								0xd2, 0x77, 0x91, 0x73, 0x40, 0x09, 0x35, 0x4e,
								0x8c, 0x9f, 0xd6, 0x03, 0x37, 0xab, 0x43, 0xf5,
							},
						},
					},
				},
				external: []byte{},
			},
			onVerify: args{
				parent: SignMessage{
					Headers: Headers{
						Protected:   ProtectedHeader{},
						Unprotected: UnprotectedHeader{},
					},
					Payload: []byte("hello world"),
					Signatures: []*Signature{
						{
							Headers: Headers{
								Protected: ProtectedHeader{
									HeaderLabelAlgorithm: AlgorithmES256,
								},
								Unprotected: UnprotectedHeader{
									HeaderLabelKeyID: []byte("42"),
								},
							},
							Signature: []byte{
								0x74, 0xc6, 0xac, 0xa6, 0x7d, 0x7a, 0x00, 0xea,
								0x0f, 0x9b, 0x86, 0xb3, 0x85, 0x7a, 0x7d, 0x36,
								0xd2, 0x77, 0x91, 0x73, 0x40, 0x09, 0x35, 0x4e,
								0x8c, 0x9f, 0xd6, 0x03, 0x37, 0xab, 0x43, 0xf5,
							},
						},
					},
				},
				external: []byte{},
			},
		},
		{
			name: "countersign a SignMessage without signatures",
			sig: &Countersignature{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: AlgorithmES256,
					},
					Unprotected: UnprotectedHeader{
						HeaderLabelKeyID: []byte("11"),
					},
				},
			},
			onSign: args{
				parent: SignMessage{
					Headers: Headers{
						Protected:   ProtectedHeader{},
						Unprotected: UnprotectedHeader{},
					},
					Payload: []byte("hello world"),
				},
				external: []byte{},
			},
			onVerify: args{
				parent: SignMessage{
					Headers: Headers{
						Protected:   ProtectedHeader{},
						Unprotected: UnprotectedHeader{},
					},
					Payload: []byte("hello world"),
				},
				external: []byte{},
			},
			wantErr: "SignMessage has no signatures yet",
		},
		{
			name: "countersign a valid Sign1Message",
			sig: &Countersignature{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: AlgorithmES256,
					},
					Unprotected: UnprotectedHeader{
						HeaderLabelKeyID: []byte("11"),
					},
				},
			},
			onSign: args{
				parent: Sign1Message{
					Headers: Headers{
						Protected: ProtectedHeader{
							HeaderLabelAlgorithm: AlgorithmES256,
						},
						Unprotected: UnprotectedHeader{
							HeaderLabelKeyID: []byte("42"),
						},
					},
					Payload: []byte("hello world"),
					Signature: []byte{
						0x74, 0xc6, 0xac, 0xa6, 0x7d, 0x7a, 0x00, 0xea,
						0x0f, 0x9b, 0x86, 0xb3, 0x85, 0x7a, 0x7d, 0x36,
						0xd2, 0x77, 0x91, 0x73, 0x40, 0x09, 0x35, 0x4e,
						0x8c, 0x9f, 0xd6, 0x03, 0x37, 0xab, 0x43, 0xf5,
					},
				},
				external: []byte{},
			},
			onVerify: args{
				parent: Sign1Message{
					Headers: Headers{
						Protected: ProtectedHeader{
							HeaderLabelAlgorithm: AlgorithmES256,
						},
						Unprotected: UnprotectedHeader{
							HeaderLabelKeyID: []byte("42"),
						},
					},
					Payload: []byte("hello world"),
					Signature: []byte{
						0x74, 0xc6, 0xac, 0xa6, 0x7d, 0x7a, 0x00, 0xea,
						0x0f, 0x9b, 0x86, 0xb3, 0x85, 0x7a, 0x7d, 0x36,
						0xd2, 0x77, 0x91, 0x73, 0x40, 0x09, 0x35, 0x4e,
						0x8c, 0x9f, 0xd6, 0x03, 0x37, 0xab, 0x43, 0xf5,
					},
				},
				external: []byte{},
			},
		},
		{
			name: "countersign a Sign1Message without signature",
			sig: &Countersignature{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: AlgorithmES256,
					},
					Unprotected: UnprotectedHeader{
						HeaderLabelKeyID: []byte("11"),
					},
				},
			},
			onSign: args{
				parent: Sign1Message{
					Headers: Headers{
						Protected:   ProtectedHeader{},
						Unprotected: UnprotectedHeader{},
					},
					Payload: []byte("hello world"),
				},
				external: []byte{},
			},
			onVerify: args{
				parent: Sign1Message{
					Headers: Headers{
						Protected:   ProtectedHeader{},
						Unprotected: UnprotectedHeader{},
					},
					Payload: []byte("hello world"),
				},
				external: []byte{},
			},
			wantErr: "Sign1Message was not signed yet",
		},
		{
			name: "countersign a valid Countersignature",
			sig: &Countersignature{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: AlgorithmES256,
					},
					Unprotected: UnprotectedHeader{
						HeaderLabelKeyID: []byte("11"),
					},
				},
			},
			onSign: args{
				parent: Countersignature{
					Headers: Headers{
						Protected: ProtectedHeader{
							HeaderLabelAlgorithm: AlgorithmES256,
						},
						Unprotected: UnprotectedHeader{
							HeaderLabelKeyID: []byte("42"),
						},
					},
					Signature: []byte{
						0x74, 0xc6, 0xac, 0xa6, 0x7d, 0x7a, 0x00, 0xea,
						0x0f, 0x9b, 0x86, 0xb3, 0x85, 0x7a, 0x7d, 0x36,
						0xd2, 0x77, 0x91, 0x73, 0x40, 0x09, 0x35, 0x4e,
						0x8c, 0x9f, 0xd6, 0x03, 0x37, 0xab, 0x43, 0xf5,
					},
				},
				external: []byte{},
			},
			onVerify: args{
				parent: Countersignature{
					Headers: Headers{
						Protected: ProtectedHeader{
							HeaderLabelAlgorithm: AlgorithmES256,
						},
						Unprotected: UnprotectedHeader{
							HeaderLabelKeyID: []byte("42"),
						},
					},
					Signature: []byte{
						0x74, 0xc6, 0xac, 0xa6, 0x7d, 0x7a, 0x00, 0xea,
						0x0f, 0x9b, 0x86, 0xb3, 0x85, 0x7a, 0x7d, 0x36,
						0xd2, 0x77, 0x91, 0x73, 0x40, 0x09, 0x35, 0x4e,
						0x8c, 0x9f, 0xd6, 0x03, 0x37, 0xab, 0x43, 0xf5,
					},
				},
				external: []byte{},
			},
		},
		{
			name: "countersign a Countersignature without signature is not allowed",
			sig: &Countersignature{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: AlgorithmES256,
					},
					Unprotected: UnprotectedHeader{
						HeaderLabelKeyID: []byte("11"),
					},
				},
			},
			onSign: args{
				parent: Countersignature{
					Headers: Headers{
						Protected:   ProtectedHeader{},
						Unprotected: UnprotectedHeader{},
					},
				},
				external: []byte{},
			},
			onVerify: args{
				parent: Countersignature{
					Headers: Headers{
						Protected:   ProtectedHeader{},
						Unprotected: UnprotectedHeader{},
					},
				},
				external: []byte{},
			},
			wantErr: "Countersignature was not signed yet",
		},
		{
			name: "countersign an unsupported parent",
			sig: &Countersignature{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: AlgorithmES256,
					},
					Unprotected: UnprotectedHeader{
						HeaderLabelKeyID: []byte("11"),
					},
				},
			},
			onSign: args{
				parent:   struct{}{},
				external: []byte{},
			},
			onVerify: args{
				parent:   struct{}{},
				external: []byte{},
			},
			wantErr: "unsupported target struct {}",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.sig.Sign(rand.Reader, signer, tt.onSign.parent, tt.onSign.external)
			if err != nil {
				if err.Error() != tt.wantErr {
					t.Errorf("Countersignature.Sign() error = %v, wantErr %v", err, tt.wantErr)
				}
				return
			} else if tt.wantErr != "" {
				t.Errorf("Countersignature.Sign() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.check != nil {
				tt.check(t, tt.sig)
			}
			if err := tt.sig.Verify(verifier, tt.onVerify.parent, tt.onVerify.external); err != nil {
				t.Errorf("Countersignature.Verify() error = %v", err)
			}
		})
	}
}

func TestCountersign0(t *testing.T) {
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

	// sign / verify round trip
	type args struct {
		parent   any
		external []byte
	}
	tests := []struct {
		name     string
		onSign   args
		onVerify args
		wantErr  string
	}{
		{
			name: "valid message",
			onSign: args{
				parent: Signature{
					Headers: Headers{
						Protected: ProtectedHeader{
							HeaderLabelAlgorithm: AlgorithmES256,
						},
						Unprotected: UnprotectedHeader{
							HeaderLabelKeyID: []byte("42"),
						},
					},
					Signature: []byte{
						0x74, 0xc6, 0xac, 0xa6, 0x7d, 0x7a, 0x00, 0xea,
						0x0f, 0x9b, 0x86, 0xb3, 0x85, 0x7a, 0x7d, 0x36,
						0xd2, 0x77, 0x91, 0x73, 0x40, 0x09, 0x35, 0x4e,
						0x8c, 0x9f, 0xd6, 0x03, 0x37, 0xab, 0x43, 0xf5,
					},
				},
				external: []byte{},
			},
			onVerify: args{
				parent: Signature{
					Headers: Headers{
						Protected: ProtectedHeader{
							HeaderLabelAlgorithm: AlgorithmES256,
						},
						Unprotected: UnprotectedHeader{
							HeaderLabelKeyID: []byte("42"),
						},
					},
					Signature: []byte{
						0x74, 0xc6, 0xac, 0xa6, 0x7d, 0x7a, 0x00, 0xea,
						0x0f, 0x9b, 0x86, 0xb3, 0x85, 0x7a, 0x7d, 0x36,
						0xd2, 0x77, 0x91, 0x73, 0x40, 0x09, 0x35, 0x4e,
						0x8c, 0x9f, 0xd6, 0x03, 0x37, 0xab, 0x43, 0xf5,
					},
				},
				external: []byte{},
			},
		},
		{
			name: "valid message with external",
			onSign: args{
				parent: Signature{
					Headers: Headers{
						Protected: ProtectedHeader{
							HeaderLabelAlgorithm: AlgorithmES256,
						},
						Unprotected: UnprotectedHeader{
							HeaderLabelKeyID: []byte("42"),
						},
					},
					Signature: []byte{
						0x74, 0xc6, 0xac, 0xa6, 0x7d, 0x7a, 0x00, 0xea,
						0x0f, 0x9b, 0x86, 0xb3, 0x85, 0x7a, 0x7d, 0x36,
						0xd2, 0x77, 0x91, 0x73, 0x40, 0x09, 0x35, 0x4e,
						0x8c, 0x9f, 0xd6, 0x03, 0x37, 0xab, 0x43, 0xf5,
					},
				},
				external: []byte("foo"),
			},
			onVerify: args{
				parent: Signature{
					Headers: Headers{
						Protected: ProtectedHeader{
							HeaderLabelAlgorithm: AlgorithmES256,
						},
						Unprotected: UnprotectedHeader{
							HeaderLabelKeyID: []byte("42"),
						},
					},
					Signature: []byte{
						0x74, 0xc6, 0xac, 0xa6, 0x7d, 0x7a, 0x00, 0xea,
						0x0f, 0x9b, 0x86, 0xb3, 0x85, 0x7a, 0x7d, 0x36,
						0xd2, 0x77, 0x91, 0x73, 0x40, 0x09, 0x35, 0x4e,
						0x8c, 0x9f, 0xd6, 0x03, 0x37, 0xab, 0x43, 0xf5,
					},
				},
				external: []byte("foo"),
			},
		},
		{
			name: "nil external",
			onSign: args{
				parent: Signature{
					Headers: Headers{
						Protected: ProtectedHeader{
							HeaderLabelAlgorithm: AlgorithmES256,
						},
						Unprotected: UnprotectedHeader{
							HeaderLabelKeyID: []byte("42"),
						},
					},
					Signature: []byte{
						0x74, 0xc6, 0xac, 0xa6, 0x7d, 0x7a, 0x00, 0xea,
						0x0f, 0x9b, 0x86, 0xb3, 0x85, 0x7a, 0x7d, 0x36,
						0xd2, 0x77, 0x91, 0x73, 0x40, 0x09, 0x35, 0x4e,
						0x8c, 0x9f, 0xd6, 0x03, 0x37, 0xab, 0x43, 0xf5,
					},
				},
				external: nil,
			},
			onVerify: args{
				parent: Signature{
					Headers: Headers{
						Protected: ProtectedHeader{
							HeaderLabelAlgorithm: AlgorithmES256,
						},
						Unprotected: UnprotectedHeader{
							HeaderLabelKeyID: []byte("42"),
						},
					},
					Signature: []byte{
						0x74, 0xc6, 0xac, 0xa6, 0x7d, 0x7a, 0x00, 0xea,
						0x0f, 0x9b, 0x86, 0xb3, 0x85, 0x7a, 0x7d, 0x36,
						0xd2, 0x77, 0x91, 0x73, 0x40, 0x09, 0x35, 0x4e,
						0x8c, 0x9f, 0xd6, 0x03, 0x37, 0xab, 0x43, 0xf5,
					},
				},
				external: nil,
			},
		},
		{
			name: "mixed nil / empty external",
			onSign: args{
				parent: Signature{
					Headers: Headers{
						Protected: ProtectedHeader{
							HeaderLabelAlgorithm: AlgorithmES256,
						},
						Unprotected: UnprotectedHeader{
							HeaderLabelKeyID: []byte("42"),
						},
					},
					Signature: []byte{
						0x74, 0xc6, 0xac, 0xa6, 0x7d, 0x7a, 0x00, 0xea,
						0x0f, 0x9b, 0x86, 0xb3, 0x85, 0x7a, 0x7d, 0x36,
						0xd2, 0x77, 0x91, 0x73, 0x40, 0x09, 0x35, 0x4e,
						0x8c, 0x9f, 0xd6, 0x03, 0x37, 0xab, 0x43, 0xf5,
					},
				},
				external: []byte{},
			},
			onVerify: args{
				parent: Signature{
					Headers: Headers{
						Protected: ProtectedHeader{
							HeaderLabelAlgorithm: AlgorithmES256,
						},
						Unprotected: UnprotectedHeader{
							HeaderLabelKeyID: []byte("42"),
						},
					},
					Signature: []byte{
						0x74, 0xc6, 0xac, 0xa6, 0x7d, 0x7a, 0x00, 0xea,
						0x0f, 0x9b, 0x86, 0xb3, 0x85, 0x7a, 0x7d, 0x36,
						0xd2, 0x77, 0x91, 0x73, 0x40, 0x09, 0x35, 0x4e,
						0x8c, 0x9f, 0xd6, 0x03, 0x37, 0xab, 0x43, 0xf5,
					},
				},
				external: nil,
			},
		},
		{
			name: "nil payload", // payload is detached
			onSign: args{
				parent: Sign1Message{
					Headers: Headers{
						Protected: ProtectedHeader{
							HeaderLabelAlgorithm: AlgorithmES256,
						},
						Unprotected: UnprotectedHeader{
							HeaderLabelKeyID: []byte("42"),
						},
					},
					Payload: nil,
					Signature: []byte{
						0x74, 0xc6, 0xac, 0xa6, 0x7d, 0x7a, 0x00, 0xea,
						0x0f, 0x9b, 0x86, 0xb3, 0x85, 0x7a, 0x7d, 0x36,
						0xd2, 0x77, 0x91, 0x73, 0x40, 0x09, 0x35, 0x4e,
						0x8c, 0x9f, 0xd6, 0x03, 0x37, 0xab, 0x43, 0xf5,
					},
				},
			},
			onVerify: args{
				parent: Sign1Message{
					Headers: Headers{
						Protected: ProtectedHeader{
							HeaderLabelAlgorithm: AlgorithmES256,
						},
						Unprotected: UnprotectedHeader{
							HeaderLabelKeyID: []byte("42"),
						},
					},
					Payload: nil,
					Signature: []byte{
						0x74, 0xc6, 0xac, 0xa6, 0x7d, 0x7a, 0x00, 0xea,
						0x0f, 0x9b, 0x86, 0xb3, 0x85, 0x7a, 0x7d, 0x36,
						0xd2, 0x77, 0x91, 0x73, 0x40, 0x09, 0x35, 0x4e,
						0x8c, 0x9f, 0xd6, 0x03, 0x37, 0xab, 0x43, 0xf5,
					},
				},
			},
			wantErr: "missing payload",
		},
		{
			name: "empty body protected header, zero-length byte string is used",
			onSign: args{
				parent: Signature{
					Signature: []byte{
						0x74, 0xc6, 0xac, 0xa6, 0x7d, 0x7a, 0x00, 0xea,
						0x0f, 0x9b, 0x86, 0xb3, 0x85, 0x7a, 0x7d, 0x36,
						0xd2, 0x77, 0x91, 0x73, 0x40, 0x09, 0x35, 0x4e,
						0x8c, 0x9f, 0xd6, 0x03, 0x37, 0xab, 0x43, 0xf5,
					},
				},
			},
			onVerify: args{
				parent: Signature{
					Signature: []byte{
						0x74, 0xc6, 0xac, 0xa6, 0x7d, 0x7a, 0x00, 0xea,
						0x0f, 0x9b, 0x86, 0xb3, 0x85, 0x7a, 0x7d, 0x36,
						0xd2, 0x77, 0x91, 0x73, 0x40, 0x09, 0x35, 0x4e,
						0x8c, 0x9f, 0xd6, 0x03, 0x37, 0xab, 0x43, 0xf5,
					},
				},
			},
		},
		{
			name: "invalid protected header",
			onSign: args{
				parent: Signature{
					Headers: Headers{
						Protected: ProtectedHeader{
							HeaderLabelAlgorithm: AlgorithmES256,
							HeaderLabelCritical:  []any{},
						},
						Unprotected: UnprotectedHeader{
							HeaderLabelKeyID: []byte("42"),
						},
					},
					Signature: []byte{
						0x74, 0xc6, 0xac, 0xa6, 0x7d, 0x7a, 0x00, 0xea,
						0x0f, 0x9b, 0x86, 0xb3, 0x85, 0x7a, 0x7d, 0x36,
						0xd2, 0x77, 0x91, 0x73, 0x40, 0x09, 0x35, 0x4e,
						0x8c, 0x9f, 0xd6, 0x03, 0x37, 0xab, 0x43, 0xf5,
					},
				},
			},
			onVerify: args{
				parent: Signature{
					Headers: Headers{
						Protected: ProtectedHeader{
							HeaderLabelAlgorithm: AlgorithmES256,
							HeaderLabelCritical:  []any{},
						},
						Unprotected: UnprotectedHeader{
							HeaderLabelKeyID: []byte("42"),
						},
					},
					Signature: []byte{
						0x74, 0xc6, 0xac, 0xa6, 0x7d, 0x7a, 0x00, 0xea,
						0x0f, 0x9b, 0x86, 0xb3, 0x85, 0x7a, 0x7d, 0x36,
						0xd2, 0x77, 0x91, 0x73, 0x40, 0x09, 0x35, 0x4e,
						0x8c, 0x9f, 0xd6, 0x03, 0x37, 0xab, 0x43, 0xf5,
					},
				},
			},
			wantErr: "protected header: header parameter: crit: empty crit header",
		},
		{
			name: "countersign a Signature that was not signed is not allowed",
			onSign: args{
				parent: Signature{
					Headers: Headers{
						Protected: ProtectedHeader{
							HeaderLabelAlgorithm: AlgorithmES256,
						},
						Unprotected: UnprotectedHeader{
							HeaderLabelKeyID: []byte("42"),
						},
					},
				},
				external: []byte{},
			},
			onVerify: args{
				parent: Signature{
					Headers: Headers{
						Protected: ProtectedHeader{
							HeaderLabelAlgorithm: AlgorithmES256,
						},
						Unprotected: UnprotectedHeader{
							HeaderLabelKeyID: []byte("42"),
						},
					},
				},
				external: []byte{},
			},
			wantErr: "Signature was not signed yet",
		},
		{
			name: "countersign a valid SignMessage",
			onSign: args{
				parent: SignMessage{
					Headers: Headers{
						Protected:   ProtectedHeader{},
						Unprotected: UnprotectedHeader{},
					},
					Payload: []byte("hello world"),
					Signatures: []*Signature{
						{
							Headers: Headers{
								Protected: ProtectedHeader{
									HeaderLabelAlgorithm: AlgorithmES256,
								},
								Unprotected: UnprotectedHeader{
									HeaderLabelKeyID: []byte("42"),
								},
							},
							Signature: []byte{
								0x74, 0xc6, 0xac, 0xa6, 0x7d, 0x7a, 0x00, 0xea,
								0x0f, 0x9b, 0x86, 0xb3, 0x85, 0x7a, 0x7d, 0x36,
								0xd2, 0x77, 0x91, 0x73, 0x40, 0x09, 0x35, 0x4e,
								0x8c, 0x9f, 0xd6, 0x03, 0x37, 0xab, 0x43, 0xf5,
							},
						},
					},
				},
				external: []byte{},
			},
			onVerify: args{
				parent: SignMessage{
					Headers: Headers{
						Protected:   ProtectedHeader{},
						Unprotected: UnprotectedHeader{},
					},
					Payload: []byte("hello world"),
					Signatures: []*Signature{
						{
							Headers: Headers{
								Protected: ProtectedHeader{
									HeaderLabelAlgorithm: AlgorithmES256,
								},
								Unprotected: UnprotectedHeader{
									HeaderLabelKeyID: []byte("42"),
								},
							},
							Signature: []byte{
								0x74, 0xc6, 0xac, 0xa6, 0x7d, 0x7a, 0x00, 0xea,
								0x0f, 0x9b, 0x86, 0xb3, 0x85, 0x7a, 0x7d, 0x36,
								0xd2, 0x77, 0x91, 0x73, 0x40, 0x09, 0x35, 0x4e,
								0x8c, 0x9f, 0xd6, 0x03, 0x37, 0xab, 0x43, 0xf5,
							},
						},
					},
				},
				external: []byte{},
			},
		},
		{
			name: "countersign a SignMessage without signatures",
			onSign: args{
				parent: SignMessage{
					Headers: Headers{
						Protected:   ProtectedHeader{},
						Unprotected: UnprotectedHeader{},
					},
					Payload: []byte("hello world"),
				},
				external: []byte{},
			},
			onVerify: args{
				parent: SignMessage{
					Headers: Headers{
						Protected:   ProtectedHeader{},
						Unprotected: UnprotectedHeader{},
					},
					Payload: []byte("hello world"),
				},
				external: []byte{},
			},
			wantErr: "SignMessage has no signatures yet",
		},
		{
			name: "countersign a valid Sign1Message",
			onSign: args{
				parent: Sign1Message{
					Headers: Headers{
						Protected: ProtectedHeader{
							HeaderLabelAlgorithm: AlgorithmES256,
						},
						Unprotected: UnprotectedHeader{
							HeaderLabelKeyID: []byte("42"),
						},
					},
					Payload: []byte("hello world"),
					Signature: []byte{
						0x74, 0xc6, 0xac, 0xa6, 0x7d, 0x7a, 0x00, 0xea,
						0x0f, 0x9b, 0x86, 0xb3, 0x85, 0x7a, 0x7d, 0x36,
						0xd2, 0x77, 0x91, 0x73, 0x40, 0x09, 0x35, 0x4e,
						0x8c, 0x9f, 0xd6, 0x03, 0x37, 0xab, 0x43, 0xf5,
					},
				},
				external: []byte{},
			},
			onVerify: args{
				parent: Sign1Message{
					Headers: Headers{
						Protected: ProtectedHeader{
							HeaderLabelAlgorithm: AlgorithmES256,
						},
						Unprotected: UnprotectedHeader{
							HeaderLabelKeyID: []byte("42"),
						},
					},
					Payload: []byte("hello world"),
					Signature: []byte{
						0x74, 0xc6, 0xac, 0xa6, 0x7d, 0x7a, 0x00, 0xea,
						0x0f, 0x9b, 0x86, 0xb3, 0x85, 0x7a, 0x7d, 0x36,
						0xd2, 0x77, 0x91, 0x73, 0x40, 0x09, 0x35, 0x4e,
						0x8c, 0x9f, 0xd6, 0x03, 0x37, 0xab, 0x43, 0xf5,
					},
				},
				external: []byte{},
			},
		},
		{
			name: "countersign a Sign1Message without signature",
			onSign: args{
				parent: Sign1Message{
					Headers: Headers{
						Protected:   ProtectedHeader{},
						Unprotected: UnprotectedHeader{},
					},
					Payload: []byte("hello world"),
				},
				external: []byte{},
			},
			onVerify: args{
				parent: Sign1Message{
					Headers: Headers{
						Protected:   ProtectedHeader{},
						Unprotected: UnprotectedHeader{},
					},
					Payload: []byte("hello world"),
				},
				external: []byte{},
			},
			wantErr: "Sign1Message was not signed yet",
		},
		{
			name: "countersign a valid Countersignature",
			onSign: args{
				parent: Countersignature{
					Headers: Headers{
						Protected: ProtectedHeader{
							HeaderLabelAlgorithm: AlgorithmES256,
						},
						Unprotected: UnprotectedHeader{
							HeaderLabelKeyID: []byte("42"),
						},
					},
					Signature: []byte{
						0x74, 0xc6, 0xac, 0xa6, 0x7d, 0x7a, 0x00, 0xea,
						0x0f, 0x9b, 0x86, 0xb3, 0x85, 0x7a, 0x7d, 0x36,
						0xd2, 0x77, 0x91, 0x73, 0x40, 0x09, 0x35, 0x4e,
						0x8c, 0x9f, 0xd6, 0x03, 0x37, 0xab, 0x43, 0xf5,
					},
				},
				external: []byte{},
			},
			onVerify: args{
				parent: Countersignature{
					Headers: Headers{
						Protected: ProtectedHeader{
							HeaderLabelAlgorithm: AlgorithmES256,
						},
						Unprotected: UnprotectedHeader{
							HeaderLabelKeyID: []byte("42"),
						},
					},
					Signature: []byte{
						0x74, 0xc6, 0xac, 0xa6, 0x7d, 0x7a, 0x00, 0xea,
						0x0f, 0x9b, 0x86, 0xb3, 0x85, 0x7a, 0x7d, 0x36,
						0xd2, 0x77, 0x91, 0x73, 0x40, 0x09, 0x35, 0x4e,
						0x8c, 0x9f, 0xd6, 0x03, 0x37, 0xab, 0x43, 0xf5,
					},
				},
				external: []byte{},
			},
		},
		{
			name: "countersign a Countersignature without signature is not allowed",
			onSign: args{
				parent: Countersignature{
					Headers: Headers{
						Protected:   ProtectedHeader{},
						Unprotected: UnprotectedHeader{},
					},
				},
				external: []byte{},
			},
			onVerify: args{
				parent: Countersignature{
					Headers: Headers{
						Protected:   ProtectedHeader{},
						Unprotected: UnprotectedHeader{},
					},
				},
				external: []byte{},
			},
			wantErr: "Countersignature was not signed yet",
		},
		{
			name: "countersign an unsupported parent",
			onSign: args{
				parent:   struct{}{},
				external: []byte{},
			},
			onVerify: args{
				parent:   struct{}{},
				external: []byte{},
			},
			wantErr: "unsupported target struct {}",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sig, err := Countersign0(rand.Reader, signer, tt.onSign.parent, tt.onSign.external)
			if err != nil {
				if err.Error() != tt.wantErr {
					t.Errorf("Countersign0() error = %v, wantErr %v", err, tt.wantErr)
				}
				return
			} else if tt.wantErr != "" {
				t.Errorf("Countersign0() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err := VerifyCountersign0(verifier, tt.onVerify.parent, tt.onVerify.external, sig); err != nil {
				t.Errorf("VerifyCountersign0() error = %v", err)
			}
		})
	}
}

func TestCountersignature_Sign_Internal(t *testing.T) {
	tests := []struct {
		name       string
		sig        *Countersignature
		parent     any
		external   []byte
		toBeSigned []byte
	}{
		{
			// adapted from https://github.com/cose-wg/Examples/blob/master/countersign/signed1-01.json
			// by modifying the context to "CounterSignatureV2" (to adjust to RFC 9338), including the
			// signature as other_fields and altering the countersignature algorithm.
			name: "COSE_Sign1 countersignature conformance test",
			sig: &Countersignature{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: algorithmMock,
					},
					Unprotected: UnprotectedHeader{
						HeaderLabelKeyID: []byte("11"),
					},
				},
			},
			parent: Sign1Message{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm:   AlgorithmEdDSA,
						HeaderLabelContentType: 0,
					},
					Unprotected: UnprotectedHeader{
						HeaderLabelKeyID: []byte("11"),
					},
				},
				Payload: []byte("This is the content."),
				Signature: []byte{
					0x71, 0x42, 0xfd, 0x2f, 0xf9, 0x6d, 0x56, 0xdb,
					0x85, 0xbe, 0xe9, 0x05, 0xa7, 0x6b, 0xa1, 0xd0,
					0xb7, 0x32, 0x1a, 0x95, 0xc8, 0xc4, 0xd3, 0x60,
					0x7c, 0x57, 0x81, 0x93, 0x2b, 0x7a, 0xfb, 0x87,
					0x11, 0x49, 0x7d, 0xfa, 0x75, 0x1b, 0xf4, 0x0b,
					0x58, 0xb3, 0xbc, 0xc3, 0x23, 0x00, 0xb1, 0x48,
					0x7f, 0x3d, 0xb3, 0x40, 0x85, 0xee, 0xf0, 0x13,
					0xbf, 0x08, 0xf4, 0xa4, 0x4d, 0x6f, 0xef, 0x0d,
				},
			},
			toBeSigned: []byte{
				0x86, // array(6)
				0x72, // text(18) "CounterSignatureV2"
				0x43, 0x6f, 0x75, 0x6e, 0x74, 0x65, 0x72, 0x53,
				0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65,
				0x56, 0x32,
				0x45, // bytes(5)
				0xa2, 0x01, 0x27, 0x03, 0x00,
				0x47, // bytes(7)
				0xa1, 0x01, 0x3a, 0x6d, 0x6f, 0x63, 0x6a,
				0x40, // bytes(0)
				0x54, // bytes(20) "This is the content."
				0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20,
				0x74, 0x68, 0x65, 0x20, 0x63, 0x6f, 0x6e, 0x74,
				0x65, 0x6e, 0x74, 0x2e,
				0x81,       // array(1)
				0x58, 0x40, // bytes(64) signature:
				0x71, 0x42, 0xfd, 0x2f, 0xf9, 0x6d, 0x56, 0xdb,
				0x85, 0xbe, 0xe9, 0x05, 0xa7, 0x6b, 0xa1, 0xd0,
				0xb7, 0x32, 0x1a, 0x95, 0xc8, 0xc4, 0xd3, 0x60,
				0x7c, 0x57, 0x81, 0x93, 0x2b, 0x7a, 0xfb, 0x87,
				0x11, 0x49, 0x7d, 0xfa, 0x75, 0x1b, 0xf4, 0x0b,
				0x58, 0xb3, 0xbc, 0xc3, 0x23, 0x00, 0xb1, 0x48,
				0x7f, 0x3d, 0xb3, 0x40, 0x85, 0xee, 0xf0, 0x13,
				0xbf, 0x08, 0xf4, 0xa4, 0x4d, 0x6f, 0xef, 0x0d,
			},
		},
		{
			// adapted from https://github.com/cose-wg/Examples/blob/master/countersign/signed-01.json
			name: "COSE_Signature countersignature conformance test",
			sig: &Countersignature{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: algorithmMock,
					},
					Unprotected: UnprotectedHeader{
						HeaderLabelKeyID: []byte("11"),
					},
				},
			},
			parent: Signature{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: AlgorithmEdDSA,
					},
					Unprotected: UnprotectedHeader{
						HeaderLabelKeyID: []byte("11"),
					},
				},
				Signature: []byte{
					0x8e, 0x1b, 0xe2, 0xf9, 0x45, 0x3d, 0x26, 0x48,
					0x12, 0xe5, 0x90, 0x49, 0x91, 0x32, 0xbe, 0xf3,
					0xfb, 0xf9, 0xee, 0x9d, 0xb2, 0x7c, 0x2c, 0x16,
					0x87, 0x88, 0xe3, 0xb7, 0xeb, 0xe5, 0x06, 0xc0,
					0x4f, 0xd3, 0xd1, 0x9f, 0xaa, 0x9f, 0x51, 0x23,
					0x2a, 0xf5, 0xc9, 0x59, 0xe4, 0xef, 0x47, 0x92,
					0x88, 0x34, 0x64, 0x7f, 0x56, 0xdf, 0xbe, 0x93,
					0x91, 0x12, 0x88, 0x4d, 0x08, 0xef, 0x25, 0x05,
				},
			},
			toBeSigned: []byte{
				0x85, // array(5)
				0x70, // text(16) "CounterSignature"
				0x43, 0x6f, 0x75, 0x6e, 0x74, 0x65, 0x72, 0x53,
				0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65,
				0x43, // bytes(3)
				0xa1, 0x01, 0x27,
				0x47, // bytes(7)
				0xa1, 0x01, 0x3a, 0x6d, 0x6f, 0x63, 0x6a,
				0x40,       // bytes(0)
				0x58, 0x40, // bytes(64) signature:
				0x8e, 0x1b, 0xe2, 0xf9, 0x45, 0x3d, 0x26, 0x48,
				0x12, 0xe5, 0x90, 0x49, 0x91, 0x32, 0xbe, 0xf3,
				0xfb, 0xf9, 0xee, 0x9d, 0xb2, 0x7c, 0x2c, 0x16,
				0x87, 0x88, 0xe3, 0xb7, 0xeb, 0xe5, 0x06, 0xc0,
				0x4f, 0xd3, 0xd1, 0x9f, 0xaa, 0x9f, 0x51, 0x23,
				0x2a, 0xf5, 0xc9, 0x59, 0xe4, 0xef, 0x47, 0x92,
				0x88, 0x34, 0x64, 0x7f, 0x56, 0xdf, 0xbe, 0x93,
				0x91, 0x12, 0x88, 0x4d, 0x08, 0xef, 0x25, 0x05,
			},
		},
		{
			// adapted from https://github.com/cose-wg/Examples/blob/master/countersign/signed-03.json
			name: "COSE_Sign countersignature conformance test",
			sig: &Countersignature{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: algorithmMock,
					},
					Unprotected: UnprotectedHeader{
						HeaderLabelKeyID: []byte("11"),
					},
				},
			},
			parent: SignMessage{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelContentType: 0,
					},
					Unprotected: UnprotectedHeader{},
				},
				Payload: []byte("This is the content."),
				Signatures: []*Signature{
					{
						Headers: Headers{
							Protected: ProtectedHeader{
								HeaderLabelAlgorithm: AlgorithmEdDSA,
							},
							Unprotected: UnprotectedHeader{
								HeaderLabelKeyID: []byte("11"),
							},
						},
						Signature: []byte{
							0x77, 0xf3, 0xea, 0xcd, 0x11, 0x85, 0x2c, 0x4b,
							0xf9, 0xcb, 0x1d, 0x72, 0xfa, 0xbe, 0x6b, 0x26,
							0xfb, 0xa1, 0xd7, 0x60, 0x92, 0xb2, 0xb5, 0xb7,
							0xec, 0x83, 0xb8, 0x35, 0x57, 0x65, 0x22, 0x64,
							0xe6, 0x96, 0x90, 0xdb, 0xc1, 0x17, 0x2d, 0xdc,
							0x0b, 0xf8, 0x84, 0x11, 0xc0, 0xd2, 0x5a, 0x50,
							0x7f, 0xdb, 0x24, 0x7a, 0x20, 0xc4, 0x0d, 0x5e,
							0x24, 0x5f, 0xab, 0xd3, 0xfc, 0x9e, 0xc1, 0x06,
						},
					},
				},
			},
			toBeSigned: []byte{
				0x85, // array(5)
				0x70, // text(16) "CounterSignature"
				0x43, 0x6f, 0x75, 0x6e, 0x74, 0x65, 0x72, 0x53,
				0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65,
				0x43, // bytes(3)
				0xa1, 0x03, 0x00,
				0x47, // bytes(7)
				0xa1, 0x01, 0x3a, 0x6d, 0x6f, 0x63, 0x6a,
				0x40, // bytes(0)
				0x54, // bytes(20) "This is the content."
				0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20,
				0x74, 0x68, 0x65, 0x20, 0x63, 0x6f, 0x6e, 0x74,
				0x65, 0x6e, 0x74, 0x2e,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want := make([]byte, 64)
			_, err := rand.Read(want)
			if err != nil {
				t.Fatalf("rand.Read() error = %v", err)
			}
			signer := newMockSigner(t)
			signer.setup(tt.toBeSigned, want)

			sig := tt.sig
			if err := sig.Sign(rand.Reader, signer, tt.parent, tt.external); err != nil {
				t.Errorf("Countersignature.Sign() error = %v", err)
				return
			}
			if got := sig.Signature; !bytes.Equal(got, want) {
				t.Errorf("Countersignature.Sign() signature = %s, want %s",
					hex.EncodeToString(got),
					hex.EncodeToString(want))
			}
		})
	}
}
