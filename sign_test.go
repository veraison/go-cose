package cose

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"reflect"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

func TestSignature_MarshalCBOR(t *testing.T) {
	tests := []struct {
		name    string
		s       *Signature
		want    []byte
		wantErr bool
	}{
		{
			name: "valid message",
			s: &Signature{
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
			wantErr: true,
		},
		{
			name: "nil signature",
			s: &Signature{
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
			wantErr: true,
		},
		{
			name: "empty signature",
			s: &Signature{
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
			wantErr: true,
		},
		{
			name: "invalid protected header",
			s: &Signature{
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
			wantErr: true,
		},
		{
			name: "invalid unprotected header",
			s: &Signature{
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
			wantErr: true,
		},
		{
			name: "protected has IV and unprotected has PartialIV error",
			s: &Signature{
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
			wantErr: true,
		},
		{
			name: "protected has PartialIV and unprotected has IV error",
			s: &Signature{
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
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.s.MarshalCBOR()
			if (err != nil) != tt.wantErr {
				t.Errorf("Signature.MarshalCBOR() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Signature.MarshalCBOR() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSignature_UnmarshalCBOR(t *testing.T) {
	// test nil pointer
	t.Run("nil Signature pointer", func(t *testing.T) {
		var sig *Signature
		data := []byte{0x83, 0x40, 0xa0, 0x41, 0x00}
		if err := sig.UnmarshalCBOR(data); err == nil {
			t.Errorf("want error on nil *Signature")
		}
	})

	// test others
	tests := []struct {
		name    string
		data    []byte
		want    Signature
		wantErr bool
	}{
		{
			name: "valid signature struct",
			data: []byte{
				0x83,
				0x43, 0xa1, 0x01, 0x26, // protected
				0xa1, 0x03, 0x18, 0x2a, // unprotected
				0x43, 0x62, 0x61, 0x72, // signature
			},
			want: Signature{
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
			wantErr: true,
		},
		{
			name:    "empty CBOR data",
			data:    []byte{},
			wantErr: true,
		},
		{
			name: "tagged signature", // issue #30
			data: []byte{
				0x83,
				0x40, 0xa0, // empty headers
				0xcb, 0xa1, 0x00, // tagged signature
			},
			wantErr: true,
		},
		{
			name: "nil signature",
			data: []byte{
				0x83,
				0x40, 0xa0, // empty headers
				0xf6, // nil signature
			},
			wantErr: true,
		},
		{
			name: "empty signature",
			data: []byte{
				0x83,
				0x40, 0xa0, // empty headers
				0x40, // empty signature
			},
			wantErr: true,
		},
		{
			name: "mismatch type",
			data: []byte{
				0x40,
			},
			wantErr: true,
		},
		{
			name: "smaller array size",
			data: []byte{
				0x82,
				0x40, 0xa0, // empty headers
			},
			wantErr: true,
		},
		{
			name: "larger array size",
			data: []byte{
				0x84,
				0x40, 0xa0, // empty headers
				0x41, 0x00, // signature
				0x40,
			},
			wantErr: true,
		},
		{
			name: "signature as a byte array",
			data: []byte{
				0x83,
				0x40, 0xa0, // empty headers
				0x81, 0x00, // signature
			},
			wantErr: true,
		},
		{
			name: "protected has IV and unprotected has PartialIV",
			data: []byte{
				0x83,
				0x46, 0xa1, 0x5, 0x63, 0x66, 0x6f, 0x6f, // protected
				0xa1, 0x6, 0x63, 0x62, 0x61, 0x72, // unprotected
				0x43, 0x62, 0x61, 0x72, // signature
			},
			wantErr: true,
		},
		{
			name: "protected has PartialIV and unprotected has IV",
			data: []byte{
				0x83,
				0x46, 0xa1, 0x6, 0x63, 0x66, 0x6f, 0x6f, // protected
				0xa1, 0x5, 0x63, 0x62, 0x61, 0x72, // unprotected
				0x43, 0x62, 0x61, 0x72, // signature
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got Signature
			if err := got.UnmarshalCBOR(tt.data); (err != nil) != tt.wantErr {
				t.Errorf("Signature.UnmarshalCBOR() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Signature.MarshalCBOR() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSignature_Sign(t *testing.T) {
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
		protected cbor.RawMessage
		payload   []byte
		external  []byte
	}
	tests := []struct {
		name     string
		sig      *Signature
		onSign   args
		onVerify args
		wantErr  bool
		check    func(t *testing.T, s *Signature)
	}{
		{
			name: "valid message",
			sig: &Signature{
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
				protected: []byte{0x40},
				payload:   []byte("hello world"),
				external:  []byte{},
			},
			onVerify: args{
				protected: []byte{0x40},
				payload:   []byte("hello world"),
				external:  []byte{},
			},
		},
		{
			name: "valid message with external",
			sig: &Signature{
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
				protected: []byte{0x40},
				payload:   []byte("hello world"),
				external:  []byte("foo"),
			},
			onVerify: args{
				protected: []byte{0x40},
				payload:   []byte("hello world"),
				external:  []byte("foo"),
			},
		},
		{
			name: "nil external",
			sig: &Signature{
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
				protected: []byte{0x40},
				payload:   []byte("hello world"),
				external:  nil,
			},
			onVerify: args{
				protected: []byte{0x40},
				payload:   []byte("hello world"),
				external:  nil,
			},
		},
		{
			name: "mixed nil / empty external",
			sig: &Signature{
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
				protected: []byte{0x40},
				payload:   []byte("hello world"),
				external:  []byte{},
			},
			onVerify: args{
				protected: []byte{0x40},
				payload:   []byte("hello world"),
				external:  nil,
			},
		},
		{
			name: "nil payload", // payload is detached
			sig: &Signature{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: AlgorithmES256,
					},
				},
			},
			onSign: args{
				protected: []byte{0x40},
				payload:   nil,
			},
			onVerify: args{
				protected: []byte{0x40},
				payload:   nil,
			},
			wantErr: true,
		},
		{
			name: "mismatch algorithm",
			sig: &Signature{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: AlgorithmES512,
					},
				},
			},
			onSign: args{
				protected: []byte{0x40},
				payload:   []byte("hello world"),
			},
			onVerify: args{
				protected: []byte{0x40},
				payload:   []byte("hello world"),
			},
			wantErr: true,
		},
		{
			name: "missing algorithm",
			sig:  &Signature{},
			onSign: args{
				protected: []byte{0x40},
				payload:   []byte("hello world"),
			},
			onVerify: args{
				protected: []byte{0x40},
				payload:   []byte("hello world"),
			},
			check: func(t *testing.T, s *Signature) {
				got, err := s.Headers.Protected.Algorithm()
				if err != nil {
					t.Errorf("Signature.Headers.Protected.Algorithm() error = %v", err)
				}
				if got != alg {
					t.Errorf("Signature.Headers.Protected.Algorithm() = %v, want %v", got, alg)
				}
			},
		},
		{
			name: "missing algorithm with raw protected",
			sig: &Signature{
				Headers: Headers{
					RawProtected: []byte{0x40},
				},
			},
			onSign: args{
				protected: []byte{0x40},
				payload:   []byte("hello world"),
			},
			onVerify: args{
				protected: []byte{0x40},
				payload:   []byte("hello world"),
			},
			wantErr: true,
		},
		{
			name: "missing algorithm with externally supplied data",
			sig:  &Signature{},
			onSign: args{
				protected: []byte{0x40},
				payload:   []byte("hello world"),
				external:  []byte("foo"),
			},
			onVerify: args{
				protected: []byte{0x40},
				payload:   []byte("hello world"),
				external:  []byte("foo"),
			},
			check: func(t *testing.T, s *Signature) {
				_, err := s.Headers.Protected.Algorithm()
				if want := ErrAlgorithmNotFound; err != want {
					t.Errorf("Signature.Headers.Protected.Algorithm() error = %v, wantErr %v", err, want)
				}
			},
		},
		{
			name: "double signing",
			sig: &Signature{
				Signature: []byte("foobar"),
			},
			onSign: args{
				protected: []byte{0x40},
				payload:   []byte("hello world"),
			},
			onVerify: args{
				protected: []byte{0x40},
				payload:   []byte("hello world"),
			},
			wantErr: true,
		},
		{
			name: "nil signature",
			sig:  nil,
			onSign: args{
				protected: []byte{0x40},
				payload:   []byte("hello world"),
			},
			onVerify: args{
				protected: []byte{0x40},
				payload:   []byte("hello world"),
			},
			wantErr: true,
		},
		{
			name: "nil body protected header",
			sig: &Signature{
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
				protected: nil,
				payload:   []byte("hello world"),
			},
			onVerify: args{
				protected: nil,
				payload:   []byte("hello world"),
			},
			wantErr: true,
		},
		{
			name: "empty body protected header",
			sig: &Signature{
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
				protected: []byte{},
				payload:   []byte("hello world"),
			},
			onVerify: args{
				protected: []byte{},
				payload:   []byte("hello world"),
			},
			wantErr: true,
		},
		{
			name: "invalid protected header",
			sig: &Signature{
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
				protected: []byte{0xa0},
				payload:   []byte("hello world"),
			},
			onVerify: args{
				protected: []byte{0xa0},
				payload:   []byte("hello world"),
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.sig.Sign(rand.Reader, signer, tt.onSign.protected, tt.onSign.payload, tt.onSign.external)
			if (err != nil) != tt.wantErr {
				t.Errorf("Signature.Sign() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}
			if tt.check != nil {
				tt.check(t, tt.sig)
			}
			if err := tt.sig.Verify(verifier, tt.onVerify.protected, tt.onVerify.payload, tt.onVerify.external); err != nil {
				t.Errorf("Signature.Verify() error = %v", err)
			}
		})
	}
}

func TestSignature_Sign_Internal(t *testing.T) {
	tests := []struct {
		name       string
		sig        *Signature
		protected  cbor.RawMessage
		payload    []byte
		external   []byte
		toBeSigned []byte
	}{
		{
			name: "valid message",
			sig: &Signature{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: algorithmMock,
					},
					Unprotected: UnprotectedHeader{
						HeaderLabelKeyID: []byte("42"),
					},
				},
			},
			protected: []byte{0x40, 0xa1, 0x00, 0x00},
			payload:   []byte("hello world"),
			external:  []byte{},
			toBeSigned: []byte{
				0x85,                                                       // array type
				0x69, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, // context
				0x40, 0xa1, 0x00, 0x00, // body_protected
				0x47, 0xa1, 0x01, 0x3a, 0x6d, 0x6f, 0x63, 0x6a, // sign_protected
				0x40,                                                                   // external
				0x4b, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64, // payload
			},
		},
		{
			name: "valid message with empty parent protected header",
			sig: &Signature{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: algorithmMock,
					},
					Unprotected: UnprotectedHeader{
						HeaderLabelKeyID: []byte("42"),
					},
				},
			},
			protected: []byte{0x40},
			payload:   []byte("hello world"),
			external:  []byte{},
			toBeSigned: []byte{
				0x85,                                                       // array type
				0x69, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, // context
				0x40,                                           // body_protected
				0x47, 0xa1, 0x01, 0x3a, 0x6d, 0x6f, 0x63, 0x6a, // sign_protected
				0x40,                                                                   // external
				0x4b, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64, // payload
			},
		},
		{
			name: "valid message with external",
			sig: &Signature{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: algorithmMock,
					},
					Unprotected: UnprotectedHeader{
						HeaderLabelKeyID: []byte("42"),
					},
				},
			},
			protected: []byte{0x40},
			payload:   []byte("hello world"),
			external:  []byte("foo"),
			toBeSigned: []byte{
				0x85,                                                       // array type
				0x69, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, // context
				0x40,                                           // body_protected
				0x47, 0xa1, 0x01, 0x3a, 0x6d, 0x6f, 0x63, 0x6a, // sign_protected
				0x43, 0x66, 0x6f, 0x6f, // external
				0x4b, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64, // payload
			},
		},
		{
			name: "nil external",
			sig: &Signature{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: algorithmMock,
					},
					Unprotected: UnprotectedHeader{
						HeaderLabelKeyID: []byte("42"),
					},
				},
			},
			protected: []byte{0x40},
			payload:   []byte("hello world"),
			external:  nil,
			toBeSigned: []byte{
				0x85,                                                       // array type
				0x69, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, // context
				0x40,                                           // body_protected
				0x47, 0xa1, 0x01, 0x3a, 0x6d, 0x6f, 0x63, 0x6a, // sign_protected
				0x40,                                                                   // external
				0x4b, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64, // payload
			},
		},
		{
			name:      "nil protected header",
			sig:       &Signature{},
			protected: []byte{0x40},
			payload:   []byte("hello world"),
			external:  []byte("foo"),
			toBeSigned: []byte{
				0x85,                                                       // array type
				0x69, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, // context
				0x40,                   // body_protected
				0x40,                   // sign_protected
				0x43, 0x66, 0x6f, 0x6f, // external
				0x4b, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64, // payload
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash := crypto.SHA256
			RegisterAlgorithm(algorithmMock, "Mock", hash, nil)
			defer resetExtendedAlgorithm()

			want := make([]byte, 64)
			_, err := rand.Read(want)
			if err != nil {
				t.Fatalf("rand.Read() error = %v", err)
			}
			h := hash.New()
			h.Write(tt.toBeSigned)
			digest := h.Sum(nil)
			signer := newMockSigner(t)
			signer.setup(digest, want)

			sig := tt.sig
			if err := sig.Sign(rand.Reader, signer, tt.protected, tt.payload, tt.external); err != nil {
				t.Errorf("Signature.Sign() error = %v", err)
				return
			}
			if got := sig.Signature; !bytes.Equal(got, want) {
				t.Errorf("Signature.Sign() signature = %v, want %v", got, want)
			}
		})
	}
}

func TestSignature_Verify(t *testing.T) {
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
		protected cbor.RawMessage
		payload   []byte
		external  []byte
	}
	tests := []struct {
		name     string
		sig      *Signature
		onSign   args
		onVerify args
		tamper   func(s *Signature) *Signature
		wantErr  bool
	}{
		{
			name: "round trip on valid message",
			onSign: args{
				protected: []byte{0x40},
				payload:   []byte("hello world"),
				external:  []byte{},
			},
			onVerify: args{
				protected: []byte{0x40},
				payload:   []byte("hello world"),
				external:  []byte{},
			},
		},
		{
			name: "round trip on valid message with nil external data",
			onSign: args{
				protected: []byte{0x40},
				payload:   []byte("hello world"),
			},
			onVerify: args{
				protected: []byte{0x40},
				payload:   []byte("hello world"),
			},
		},
		{
			name: "mixed nil / empty external",
			onSign: args{
				protected: []byte{0x40},
				payload:   []byte("hello world"),
				external:  nil,
			},
			onVerify: args{
				protected: []byte{0x40},
				payload:   []byte("hello world"),
				external:  []byte{},
			},
		},
		{
			name: "nil body protected header",
			onSign: args{
				protected: []byte{0x40},
				payload:   []byte("hello world"),
			},
			onVerify: args{
				protected: nil,
				payload:   []byte("hello world"),
			},
			wantErr: true,
		},
		{
			name: "empty body protected header",
			onSign: args{
				protected: []byte{0x40},
				payload:   []byte("hello world"),
			},
			onVerify: args{
				protected: []byte{},
				payload:   []byte("hello world"),
			},
			wantErr: true,
		},
		{
			name: "invalid body protected header",
			onSign: args{
				protected: []byte{0x40},
				payload:   []byte("hello world"),
			},
			onVerify: args{
				protected: []byte{0xa0},
				payload:   []byte("hello world"),
			},
			wantErr: true,
		},
		{
			name: "body protected header mismatch",
			onSign: args{
				protected: []byte{0x43, 0xa1, 0x00, 0x00},
				payload:   []byte("hello world"),
			},
			onVerify: args{
				protected: []byte{0x43, 0xa1, 0x00, 0x01},
				payload:   []byte("hello world"),
			},
			wantErr: true,
		},
		{
			name: "nil payload",
			onSign: args{
				protected: []byte{0x40},
				payload:   []byte{},
			},
			onVerify: args{
				protected: []byte{0x40},
				payload:   nil,
			},
			wantErr: true,
		},
		{
			name: "payload mismatch",
			onSign: args{
				protected: []byte{0x40},
				payload:   []byte("hello world"),
			},
			onVerify: args{
				protected: []byte{0x40},
				payload:   []byte("foobar"),
			},
			wantErr: true,
		},
		{
			name: "external mismatch",
			onSign: args{
				protected: []byte{0x40},
				payload:   []byte("hello world"),
				external:  []byte("foo"),
			},
			onVerify: args{
				protected: []byte{0x40},
				payload:   []byte("hello world"),
				external:  []byte("bar"),
			},
			wantErr: true,
		},
		{
			name: "nil signature struct",
			onSign: args{
				protected: []byte{0x40},
				payload:   []byte("hello world"),
			},
			onVerify: args{
				protected: []byte{0x40},
				payload:   []byte("hello world"),
			},
			tamper: func(s *Signature) *Signature {
				return nil
			},
			wantErr: true,
		},
		{
			name: "strip signature",
			onSign: args{
				protected: []byte{0x40},
				payload:   []byte("hello world"),
			},
			onVerify: args{
				protected: []byte{0x40},
				payload:   []byte("hello world"),
			},
			tamper: func(s *Signature) *Signature {
				s.Signature = nil
				return s
			},
			wantErr: true,
		},
		{
			name: "empty signature",
			onSign: args{
				protected: []byte{0x40},
				payload:   []byte("hello world"),
			},
			onVerify: args{
				protected: []byte{0x40},
				payload:   []byte("hello world"),
			},
			tamper: func(s *Signature) *Signature {
				s.Signature = []byte{}
				return s
			},
			wantErr: true,
		},
		{
			name: "tamper protected header",
			onSign: args{
				protected: []byte{0x40},
				payload:   []byte("hello world"),
			},
			onVerify: args{
				protected: []byte{0x40},
				payload:   []byte("hello world"),
			},
			tamper: func(s *Signature) *Signature {
				s.Headers.Protected["foo"] = "bar"
				return s
			},
			wantErr: true,
		},
		{
			name: "tamper unprotected header",
			onSign: args{
				protected: []byte{0x40},
				payload:   []byte("hello world"),
			},
			onVerify: args{
				protected: []byte{0x40},
				payload:   []byte("hello world"),
			},
			tamper: func(s *Signature) *Signature {
				s.Headers.Unprotected["foo"] = "bar"
				return s
			},
			wantErr: false, // allowed
		},
		{
			name: "tamper signature",
			onSign: args{
				protected: []byte{0x40},
				payload:   []byte("hello world"),
			},
			onVerify: args{
				protected: []byte{0x40},
				payload:   []byte("hello world"),
			},
			tamper: func(s *Signature) *Signature {
				s.Signature[0]++
				return s
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// generate signature request and sign
			sig := &Signature{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: AlgorithmES256,
					},
					Unprotected: UnprotectedHeader{
						HeaderLabelKeyID: []byte("42"),
					},
				},
			}
			if err := sig.Sign(rand.Reader, signer, tt.onSign.protected, tt.onSign.payload, tt.onSign.external); err != nil {
				t.Errorf("Signature.Sign() error = %v", err)
				return
			}

			// tamper signature
			if tt.tamper != nil {
				sig = tt.tamper(sig)
			}

			// verify signature
			if err := sig.Verify(verifier, tt.onVerify.protected, tt.onVerify.payload, tt.onVerify.external); (err != nil) != tt.wantErr {
				t.Errorf("Signature.Verify() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSignMessage_MarshalCBOR(t *testing.T) {
	tests := []struct {
		name    string
		m       *SignMessage
		want    []byte
		wantErr bool
	}{
		{
			name: "valid message with multiple signatures",
			m: &SignMessage{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelContentType: "text/plain",
					},
					Unprotected: UnprotectedHeader{
						"extra": "test",
					},
				},
				Payload: []byte("hello world"),
				Signatures: []*Signature{
					{
						Headers: Headers{
							Protected: ProtectedHeader{
								HeaderLabelAlgorithm: AlgorithmES256,
							},
							Unprotected: UnprotectedHeader{
								HeaderLabelContentType: 42,
							},
						},
						Signature: []byte("foo"),
					},
					{
						Headers: Headers{
							Protected: ProtectedHeader{
								HeaderLabelAlgorithm: AlgorithmPS512,
							},
						},
						Signature: []byte("bar"),
					},
				},
			},
			want: []byte{
				0xd8, 0x62, // tag
				0x84,
				0x4d, 0xa1, // protected
				0x03,
				0x6a, 0x74, 0x65, 0x78, 0x74, 0x2f, 0x70, 0x6c, 0x61, 0x69, 0x6e,
				0xa1, // unprotected
				0x65, 0x65, 0x78, 0x74, 0x72, 0x61,
				0x64, 0x74, 0x65, 0x73, 0x74,
				0x4b, // payload
				0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64,
				0x82,                   // signatures
				0x83,                   // signature 0
				0x43, 0xa1, 0x01, 0x26, // protected
				0xa1, 0x03, 0x18, 0x2a, // unprotected
				0x43, 0x66, 0x6f, 0x6f, // signature
				0x83,                         // signature 1
				0x44, 0xa1, 0x01, 0x38, 0x26, // protected
				0xa0,                   // unprotected
				0x43, 0x62, 0x61, 0x72, // signature
			},
		},
		{
			name: "valid message with one signature",
			m: &SignMessage{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelContentType: "text/plain",
					},
					Unprotected: UnprotectedHeader{
						"extra": "test",
					},
				},
				Payload: []byte("hello world"),
				Signatures: []*Signature{
					{
						Headers: Headers{
							Protected: ProtectedHeader{
								HeaderLabelAlgorithm: AlgorithmES256,
							},
							Unprotected: UnprotectedHeader{
								HeaderLabelContentType: 42,
							},
						},
						Signature: []byte("foo"),
					},
				},
			},
			want: []byte{
				0xd8, 0x62, // tag
				0x84,
				0x4d, 0xa1, // protected
				0x03,
				0x6a, 0x74, 0x65, 0x78, 0x74, 0x2f, 0x70, 0x6c, 0x61, 0x69, 0x6e,
				0xa1, // unprotected
				0x65, 0x65, 0x78, 0x74, 0x72, 0x61,
				0x64, 0x74, 0x65, 0x73, 0x74,
				0x4b, // payload
				0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64,
				0x81,                   // signatures
				0x83,                   // signature 0
				0x43, 0xa1, 0x01, 0x26, // protected
				0xa1, 0x03, 0x18, 0x2a, // unprotected
				0x43, 0x66, 0x6f, 0x6f, // signature
			},
		},
		{
			name: "nil signatures",
			m: &SignMessage{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelContentType: "text/plain",
					},
					Unprotected: UnprotectedHeader{
						"extra": "test",
					},
				},
				Payload:    []byte("hello world"),
				Signatures: nil,
			},
			wantErr: true,
		},
		{
			name: "empty signatures",
			m: &SignMessage{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelContentType: "text/plain",
					},
					Unprotected: UnprotectedHeader{
						"extra": "test",
					},
				},
				Payload:    []byte("hello world"),
				Signatures: []*Signature{},
			},
			wantErr: true,
		},
		{
			name:    "nil message",
			m:       nil,
			wantErr: true,
		},
		{
			name: "nil payload",
			m: &SignMessage{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelContentType: "text/plain",
					},
					Unprotected: UnprotectedHeader{
						"extra": "test",
					},
				},
				Payload: nil,
				Signatures: []*Signature{
					{
						Headers: Headers{
							Protected: ProtectedHeader{
								HeaderLabelAlgorithm: AlgorithmES256,
							},
							Unprotected: UnprotectedHeader{
								HeaderLabelContentType: 42,
							},
						},
						Signature: []byte("foo"),
					},
				},
			},
			want: []byte{
				0xd8, 0x62, // tag
				0x84,
				0x4d, 0xa1, // protected
				0x03,
				0x6a, 0x74, 0x65, 0x78, 0x74, 0x2f, 0x70, 0x6c, 0x61, 0x69, 0x6e,
				0xa1, // unprotected
				0x65, 0x65, 0x78, 0x74, 0x72, 0x61,
				0x64, 0x74, 0x65, 0x73, 0x74,
				0xf6,                   // payload
				0x81,                   // signatures
				0x83,                   // signature 0
				0x43, 0xa1, 0x01, 0x26, // protected
				0xa1, 0x03, 0x18, 0x2a, // unprotected
				0x43, 0x66, 0x6f, 0x6f, // signature
			},
		},
		{
			name: "invalid protected header",
			m: &SignMessage{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: make(chan bool),
					},
					Unprotected: UnprotectedHeader{
						HeaderLabelKeyID: []byte("42"),
					},
				},
				Payload: []byte("foo"),
				Signatures: []*Signature{
					{
						Headers: Headers{
							Protected: ProtectedHeader{
								HeaderLabelAlgorithm: AlgorithmES256,
							},
						},
						Signature: []byte("foo"),
					},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid unprotected header",
			m: &SignMessage{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: AlgorithmES256,
					},
					Unprotected: UnprotectedHeader{
						"foo": make(chan bool),
					},
				},
				Payload: []byte("foo"),
				Signatures: []*Signature{
					{
						Headers: Headers{
							Protected: ProtectedHeader{
								HeaderLabelAlgorithm: AlgorithmES256,
							},
						},
						Signature: []byte("foo"),
					},
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.m.MarshalCBOR()
			if (err != nil) != tt.wantErr {
				t.Errorf("SignMessage.MarshalCBOR() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SignMessage.MarshalCBOR() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSignMessage_UnmarshalCBOR(t *testing.T) {
	// test nil pointer
	t.Run("nil SignMessage pointer", func(t *testing.T) {
		var msg *SignMessage
		data := []byte{
			0xd8, 0x62, 0x84, 0x40, 0xa0, 0xf6,
			0x81, 0x83, 0x40, 0xa0, 0x41, 0x00,
		}
		if err := msg.UnmarshalCBOR(data); err == nil {
			t.Errorf("want error on nil *SignMessage")
		}
	})

	// test others
	tests := []struct {
		name    string
		data    []byte
		want    SignMessage
		wantErr bool
	}{
		{
			name: "valid message with multiple signatures",
			data: []byte{
				0xd8, 0x62, // tag
				0x84,
				0x4d, 0xa1, // protected
				0x03,
				0x6a, 0x74, 0x65, 0x78, 0x74, 0x2f, 0x70, 0x6c, 0x61, 0x69, 0x6e,
				0xa1, // unprotected
				0x65, 0x65, 0x78, 0x74, 0x72, 0x61,
				0x64, 0x74, 0x65, 0x73, 0x74,
				0x4b, // payload
				0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64,
				0x82,                   // signatures
				0x83,                   // signature 0
				0x43, 0xa1, 0x01, 0x26, // protected
				0xa1, 0x03, 0x18, 0x2a, // unprotected
				0x43, 0x66, 0x6f, 0x6f, // signature
				0x83,                         // signature 1
				0x44, 0xa1, 0x01, 0x38, 0x26, // protected
				0xa0,                   // unprotected
				0x43, 0x62, 0x61, 0x72, // signature
			},
			want: SignMessage{
				Headers: Headers{
					RawProtected: []byte{
						0x4d, 0xa1,
						0x03,
						0x6a, 0x74, 0x65, 0x78, 0x74, 0x2f, 0x70, 0x6c, 0x61, 0x69, 0x6e,
					},
					Protected: ProtectedHeader{
						HeaderLabelContentType: "text/plain",
					},
					RawUnprotected: []byte{
						0xa1,
						0x65, 0x65, 0x78, 0x74, 0x72, 0x61,
						0x64, 0x74, 0x65, 0x73, 0x74,
					},
					Unprotected: UnprotectedHeader{
						"extra": "test",
					},
				},
				Payload: []byte("hello world"),
				Signatures: []*Signature{
					{
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
						Signature: []byte("foo"),
					},
					{
						Headers: Headers{
							RawProtected: []byte{0x44, 0xa1, 0x01, 0x38, 0x26},
							Protected: ProtectedHeader{
								HeaderLabelAlgorithm: AlgorithmPS512,
							},
							RawUnprotected: []byte{0xa0},
							Unprotected:    UnprotectedHeader{},
						},
						Signature: []byte("bar"),
					},
				},
			},
		},
		{
			name: "valid message with one signature",
			data: []byte{
				0xd8, 0x62, // tag
				0x84,
				0x4d, 0xa1, // protected
				0x03,
				0x6a, 0x74, 0x65, 0x78, 0x74, 0x2f, 0x70, 0x6c, 0x61, 0x69, 0x6e,
				0xa1, // unprotected
				0x65, 0x65, 0x78, 0x74, 0x72, 0x61,
				0x64, 0x74, 0x65, 0x73, 0x74,
				0x4b, // payload
				0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64,
				0x81,                   // signatures
				0x83,                   // signature 0
				0x43, 0xa1, 0x01, 0x26, // protected
				0xa1, 0x03, 0x18, 0x2a, // unprotected
				0x43, 0x66, 0x6f, 0x6f, // signature
			},
			want: SignMessage{
				Headers: Headers{
					RawProtected: []byte{
						0x4d, 0xa1,
						0x03,
						0x6a, 0x74, 0x65, 0x78, 0x74, 0x2f, 0x70, 0x6c, 0x61, 0x69, 0x6e,
					},
					Protected: ProtectedHeader{
						HeaderLabelContentType: "text/plain",
					},
					RawUnprotected: []byte{
						0xa1,
						0x65, 0x65, 0x78, 0x74, 0x72, 0x61,
						0x64, 0x74, 0x65, 0x73, 0x74,
					},
					Unprotected: UnprotectedHeader{
						"extra": "test",
					},
				},
				Payload: []byte("hello world"),
				Signatures: []*Signature{
					{
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
						Signature: []byte("foo"),
					},
				},
			},
		},
		{
			name: "valid message with nil payload",
			data: []byte{
				0xd8, 0x62, // tag
				0x84,
				0x4d, 0xa1, // protected
				0x03,
				0x6a, 0x74, 0x65, 0x78, 0x74, 0x2f, 0x70, 0x6c, 0x61, 0x69, 0x6e,
				0xa1, // unprotected
				0x65, 0x65, 0x78, 0x74, 0x72, 0x61,
				0x64, 0x74, 0x65, 0x73, 0x74,
				0xf6,                   // payload
				0x81,                   // signatures
				0x83,                   // signature 0
				0x43, 0xa1, 0x01, 0x26, // protected
				0xa1, 0x03, 0x18, 0x2a, // unprotected
				0x43, 0x66, 0x6f, 0x6f, // signature
			},
			want: SignMessage{
				Headers: Headers{
					RawProtected: []byte{
						0x4d, 0xa1,
						0x03,
						0x6a, 0x74, 0x65, 0x78, 0x74, 0x2f, 0x70, 0x6c, 0x61, 0x69, 0x6e,
					},
					Protected: ProtectedHeader{
						HeaderLabelContentType: "text/plain",
					},
					RawUnprotected: []byte{
						0xa1,
						0x65, 0x65, 0x78, 0x74, 0x72, 0x61,
						0x64, 0x74, 0x65, 0x73, 0x74,
					},
					Unprotected: UnprotectedHeader{
						"extra": "test",
					},
				},
				Payload: nil,
				Signatures: []*Signature{
					{
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
						Signature: []byte("foo"),
					},
				},
			},
		},
		{
			name: "nil signatures",
			data: []byte{
				0xd8, 0x62, // tag
				0x84,
				0x4d, 0xa1, // protected
				0x03,
				0x6a, 0x74, 0x65, 0x78, 0x74, 0x2f, 0x70, 0x6c, 0x61, 0x69, 0x6e,
				0xa1, // unprotected
				0x65, 0x65, 0x78, 0x74, 0x72, 0x61,
				0x64, 0x74, 0x65, 0x73, 0x74,
				0xf6, // nil payload
				0xf6, // signatures
			},
			wantErr: true,
		},
		{
			name: "empty signatures",
			data: []byte{
				0xd8, 0x62, // tag
				0x84,
				0x4d, 0xa1, // protected
				0x03,
				0x6a, 0x74, 0x65, 0x78, 0x74, 0x2f, 0x70, 0x6c, 0x61, 0x69, 0x6e,
				0xa1, // unprotected
				0x65, 0x65, 0x78, 0x74, 0x72, 0x61,
				0x64, 0x74, 0x65, 0x73, 0x74,
				0xf6, // nil payload
				0x80, // signatures
			},
			wantErr: true,
		},
		{
			name: "tagged signature", // issue #30
			data: []byte{
				0xd8, 0x62, // tag
				0x84,
				0x4d, 0xa1, // protected
				0x03,
				0x6a, 0x74, 0x65, 0x78, 0x74, 0x2f, 0x70, 0x6c, 0x61, 0x69, 0x6e,
				0xa1, // unprotected
				0x65, 0x65, 0x78, 0x74, 0x72, 0x61,
				0x64, 0x74, 0x65, 0x73, 0x74,
				0xf6,       // nil payload
				0x81,       // signatures
				0x83,       // signature 0
				0x40, 0xa0, // empty headers
				0xcb, 0xa1, 0x00, // tagged signature
			},
			wantErr: true,
		},
		{
			name:    "nil CBOR data",
			data:    nil,
			wantErr: true,
		},
		{
			name:    "empty CBOR data",
			data:    []byte{},
			wantErr: true,
		},
		{
			name: "mismatch tag",
			data: []byte{
				0xd2, 0x84, // tag
				0x40, 0xa0, // empty headers
				0xf6,       // nil payload
				0x81,       // signatures
				0x83,       // signature 0
				0x40, 0xa0, // empty headers
				0x41, 0x00, // signature
			},
			wantErr: true,
		},
		{
			name: "mismatch type",
			data: []byte{
				0xd8, 0x62, 0x40,
			},
			wantErr: true,
		},
		{
			name: "smaller array size",
			data: []byte{
				0xd8, 0x62, 0x83, // tag
				0x40, 0xa0, // empty headers
				0xf6, // nil payload
			},
			wantErr: true,
		},
		{
			name: "larger array size",
			data: []byte{
				0xd8, 0x62, 0x85, // tag
				0x40, 0xa0, // empty headers
				0xf6,       // nil payload
				0x81,       // signatures
				0x83,       // signature 0
				0x40, 0xa0, // empty headers
				0x41, 0x00, // signature
				0x40,
			},
			wantErr: true,
		},
		{
			name: "undefined payload",
			data: []byte{
				0xd8, 0x62, 0x84, // tag
				0x40, 0xa0, // empty headers
				0xf7,       // undefined payload
				0x81,       // signatures
				0x83,       // signature 0
				0x40, 0xa0, // empty headers
				0x41, 0x00, // signature
			},
			wantErr: true,
		},
		{
			name: "payload as a byte array",
			data: []byte{
				0xd8, 0x62, 0x84, // tag
				0x40, 0xa0, // empty headers
				0x80,       // payload
				0x81,       // signatures
				0x83,       // signature 0
				0x40, 0xa0, // empty headers
				0x41, 0x00, // signature
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got SignMessage
			if err := got.UnmarshalCBOR(tt.data); (err != nil) != tt.wantErr {
				t.Errorf("SignMessage.UnmarshalCBOR() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SignMessage.UnmarshalCBOR() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSignMessage_Sign(t *testing.T) {
	// generate key and set up signer / verifier
	gen := func(alg Algorithm) (Signer, Verifier) {
		key := generateTestECDSAKey(t)
		signer, err := NewSigner(alg, key)
		if err != nil {
			t.Fatalf("NewSigner() error = %v", err)
		}
		verifier, err := NewVerifier(alg, key.Public())
		if err != nil {
			t.Fatalf("NewVerifier() error = %v", err)
		}
		return signer, verifier
	}
	algorithms := []Algorithm{AlgorithmES256, AlgorithmES512}
	signers := make([]Signer, 2)
	verifiers := make([]Verifier, 2)
	for i, alg := range algorithms {
		signers[i], verifiers[i] = gen(alg)
	}

	// sign / verify round trip
	tests := []struct {
		name             string
		msg              *SignMessage
		externalOnSign   []byte
		externalOnVerify []byte
		wantErr          bool
		check            func(t *testing.T, m *SignMessage)
	}{
		{
			name: "valid message",
			msg: &SignMessage{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelContentType: "text/plain",
					},
					Unprotected: UnprotectedHeader{
						"extra": "test",
					},
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
					},
					{
						Headers: Headers{
							Protected: ProtectedHeader{
								HeaderLabelAlgorithm: AlgorithmES512,
							},
						},
					},
				},
			},
			externalOnSign:   []byte{},
			externalOnVerify: []byte{},
		},
		{
			name: "valid message with external",
			msg: &SignMessage{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelContentType: "text/plain",
					},
					Unprotected: UnprotectedHeader{
						"extra": "test",
					},
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
					},
					{
						Headers: Headers{
							Protected: ProtectedHeader{
								HeaderLabelAlgorithm: AlgorithmES512,
							},
						},
					},
				},
			},
			externalOnSign:   []byte("foo"),
			externalOnVerify: []byte("foo"),
		},
		{
			name: "nil external",
			msg: &SignMessage{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelContentType: "text/plain",
					},
					Unprotected: UnprotectedHeader{
						"extra": "test",
					},
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
					},
					{
						Headers: Headers{
							Protected: ProtectedHeader{
								HeaderLabelAlgorithm: AlgorithmES512,
							},
						},
					},
				},
			},
			externalOnSign:   nil,
			externalOnVerify: nil,
		},
		{
			name: "mixed nil / empty external",
			msg: &SignMessage{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelContentType: "text/plain",
					},
					Unprotected: UnprotectedHeader{
						"extra": "test",
					},
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
					},
					{
						Headers: Headers{
							Protected: ProtectedHeader{
								HeaderLabelAlgorithm: AlgorithmES512,
							},
						},
					},
				},
			},
			externalOnSign:   []byte{},
			externalOnVerify: nil,
		},
		{
			name: "nil payload", // payload is detached
			msg: &SignMessage{
				Payload: nil,
				Signatures: []*Signature{
					{
						Headers: Headers{
							Protected: ProtectedHeader{
								HeaderLabelAlgorithm: AlgorithmES256,
							},
						},
					},
					{
						Headers: Headers{
							Protected: ProtectedHeader{
								HeaderLabelAlgorithm: AlgorithmES512,
							},
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "mismatch algorithm",
			msg: &SignMessage{
				Payload: []byte("hello world"),
				Signatures: []*Signature{
					{
						Headers: Headers{
							Protected: ProtectedHeader{
								HeaderLabelAlgorithm: AlgorithmES512,
							},
						},
					},
					{
						Headers: Headers{
							Protected: ProtectedHeader{
								HeaderLabelAlgorithm: AlgorithmES256,
							},
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "plain message",
			msg: &SignMessage{
				Payload:    []byte("hello world"),
				Signatures: []*Signature{{}, {}},
			},
			check: func(t *testing.T, m *SignMessage) {
				for i, alg := range algorithms {
					got, err := m.Signatures[i].Headers.Protected.Algorithm()
					if err != nil {
						t.Errorf("SignMessage.Signatures[%d].Headers.Protected.Algorithm() error = %v", i, err)
					}
					if got != alg {
						t.Errorf("SignMessage.Signatures[%d].Headers.Protected.Algorithm() = %v, want %v", i, got, alg)
					}
				}
			},
		},
		{
			name: "double signing",
			msg: &SignMessage{
				Payload: []byte("hello world"),
				Signatures: []*Signature{
					{},
					{
						Signature: []byte("foobar"),
					},
				},
			},
			wantErr: true,
		},
		{
			name:    "nil message",
			msg:     nil,
			wantErr: true,
		},
		{
			name: "too few signers",
			msg: &SignMessage{
				Payload:    []byte("hello world"),
				Signatures: []*Signature{{}, {}, {}},
			},
			wantErr: true,
		},
		{
			name: "too many signers",
			msg: &SignMessage{
				Payload:    []byte("hello world"),
				Signatures: []*Signature{{}},
			},
			wantErr: true,
		},
		{
			name: "empty signatures",
			msg: &SignMessage{
				Payload:    []byte("hello world"),
				Signatures: []*Signature{},
			},
			wantErr: true,
		},
		{
			name: "nil signatures",
			msg: &SignMessage{
				Payload:    []byte("hello world"),
				Signatures: nil,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.msg.Sign(rand.Reader, tt.externalOnSign, signers...)
			if (err != nil) != tt.wantErr {
				t.Errorf("SignMessage.Sign() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}
			if tt.check != nil {
				tt.check(t, tt.msg)
			}
			if err := tt.msg.Verify(tt.externalOnVerify, verifiers...); err != nil {
				t.Errorf("SignMessage.Verify() error = %v", err)
			}
		})
	}

	// special cases
	t.Run("no signer", func(t *testing.T) {
		msg := &SignMessage{
			Payload:    []byte("hello world"),
			Signatures: []*Signature{{}},
		}
		if err := msg.Sign(rand.Reader, nil); err == nil {
			t.Error("SignMessage.Sign() error = nil, wantErr true")
		}
	})
}

func TestSignMessage_Verify(t *testing.T) {
	// generate key and set up signer / verifier
	gen := func(alg Algorithm) (Signer, Verifier) {
		key := generateTestECDSAKey(t)
		signer, err := NewSigner(alg, key)
		if err != nil {
			t.Fatalf("NewSigner() error = %v", err)
		}
		verifier, err := NewVerifier(alg, key.Public())
		if err != nil {
			t.Fatalf("NewVerifier() error = %v", err)
		}
		return signer, verifier
	}
	algorithms := []Algorithm{AlgorithmES256, AlgorithmES512}
	signers := make([]Signer, 2)
	verifiers := make([]Verifier, 2)
	for i, alg := range algorithms {
		signers[i], verifiers[i] = gen(alg)
	}

	// sign / verify round trip
	tests := []struct {
		name             string
		externalOnSign   []byte
		externalOnVerify []byte
		verifiers        []Verifier
		tamper           func(m *SignMessage) *SignMessage
		wantErr          bool
	}{
		{
			name:      "round trip on valid message",
			verifiers: verifiers,
		},
		{
			name:             "external mismatch",
			externalOnSign:   []byte("foo"),
			externalOnVerify: []byte("bar"),
			verifiers:        verifiers,
			wantErr:          true,
		},
		{
			name:             "mixed nil / empty external",
			externalOnSign:   nil,
			externalOnVerify: []byte{},
			verifiers:        verifiers,
		},
		{
			name:      "nil message",
			verifiers: verifiers,
			tamper: func(m *SignMessage) *SignMessage {
				return nil
			},
			wantErr: true,
		},
		{
			name:      "strip signatures",
			verifiers: verifiers,
			tamper: func(m *SignMessage) *SignMessage {
				m.Signatures = nil
				return m
			},
			wantErr: true,
		},
		{
			name:      "empty signatures",
			verifiers: verifiers,
			tamper: func(m *SignMessage) *SignMessage {
				m.Signatures = []*Signature{}
				return m
			},
			wantErr: true,
		},
		{
			name:      "tamper protected header",
			verifiers: verifiers,
			tamper: func(m *SignMessage) *SignMessage {
				m.Headers.Protected["foo"] = "bar"
				return m
			},
			wantErr: true,
		},
		{
			name:      "tamper unprotected header",
			verifiers: verifiers,
			tamper: func(m *SignMessage) *SignMessage {
				m.Headers.Unprotected["foo"] = "bar"
				return m
			},
			wantErr: false, // allowed
		},
		{
			name:      "tamper payload",
			verifiers: verifiers,
			tamper: func(m *SignMessage) *SignMessage {
				m.Payload = []byte("foobar")
				return m
			},
			wantErr: true,
		},
		{
			name:      "tamper signature",
			verifiers: verifiers,
			tamper: func(m *SignMessage) *SignMessage {
				m.Signatures[1].Signature[0]++
				return m
			},
			wantErr: true,
		},
		{
			name:      "no verifiers",
			verifiers: nil,
			wantErr:   true,
		},

		{
			name:      "too few verifiers",
			verifiers: verifiers[:1],
			wantErr:   true,
		},
		{
			name:      "too many verifiers",
			verifiers: verifiers,
			tamper: func(m *SignMessage) *SignMessage {
				m.Signatures = m.Signatures[:1]
				return m
			},
			wantErr: true,
		},
		{
			name:      "verifier mismatch",
			verifiers: []Verifier{verifiers[1], verifiers[0]},
			wantErr:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// generate message and sign
			msg := &SignMessage{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelContentType: "text/plain",
					},
					Unprotected: UnprotectedHeader{
						"extra": "test",
					},
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
					},
					{
						Headers: Headers{
							Protected: ProtectedHeader{
								HeaderLabelAlgorithm: AlgorithmES512,
							},
						},
					},
				},
			}
			if err := msg.Sign(rand.Reader, tt.externalOnSign, signers...); err != nil {
				t.Errorf("SignMessage.Sign() error = %v", err)
				return
			}

			// tamper message
			if tt.tamper != nil {
				msg = tt.tamper(msg)
			}

			// verify message
			if err := msg.Verify(tt.externalOnVerify, tt.verifiers...); (err != nil) != tt.wantErr {
				t.Errorf("SignMessage.Verify() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}

	// special cases
	t.Run("nil payload", func(t *testing.T) { // payload is detached
		msg := &SignMessage{
			Headers: Headers{
				Protected: ProtectedHeader{
					HeaderLabelContentType: "text/plain",
				},
				Unprotected: UnprotectedHeader{
					"extra": "test",
				},
			},
			Payload: []byte{},
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
				},
				{
					Headers: Headers{
						Protected: ProtectedHeader{
							HeaderLabelAlgorithm: AlgorithmES512,
						},
					},
				},
			},
		}
		if err := msg.Sign(rand.Reader, nil, signers...); err != nil {
			t.Errorf("SignMessage.Sign() error = %v", err)
			return
		}

		// make payload nil on verify
		msg.Payload = nil

		// verify message
		if err := msg.Verify(nil, verifiers...); err == nil {
			t.Error("SignMessage.Verify() error = nil, wantErr true")
		}
	})
}
