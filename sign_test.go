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
						HeaderLabelKeyID: 42,
					},
				},
				Signature: []byte("bar"),
			},
			want: []byte{
				0x83,                   // array of size 3
				0x43, 0xa1, 0x01, 0x26, // protected
				0xa1, 0x04, 0x18, 0x2a, // unprotected
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
						HeaderLabelKeyID: 42,
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
						HeaderLabelKeyID: 42,
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
						HeaderLabelKeyID: 42,
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
						HeaderLabelKeyID: make(chan bool),
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
				0xa1, 0x04, 0x18, 0x2a, // unprotected
				0x43, 0x62, 0x61, 0x72, // signature
			},
			want: Signature{
				Headers: Headers{
					RawProtected: []byte{0x43, 0xa1, 0x01, 0x26},
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: AlgorithmES256,
					},
					RawUnprotected: []byte{0xa1, 0x04, 0x18, 0x2a},
					Unprotected: UnprotectedHeader{
						HeaderLabelKeyID: int64(42),
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
						HeaderLabelKeyID: 42,
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
						HeaderLabelKeyID: 42,
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
						HeaderLabelKeyID: 42,
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
						HeaderLabelKeyID: 42,
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
						HeaderLabelKeyID: 42,
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
						HeaderLabelKeyID: 42,
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
						HeaderLabelKeyID: 42,
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
						HeaderLabelKeyID: 42,
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
						HeaderLabelKeyID: 42,
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
						HeaderLabelKeyID: 42,
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
						HeaderLabelKeyID: 42,
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
						HeaderLabelKeyID: 42,
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
								HeaderLabelKeyID: 42,
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
				0xa1, 0x04, 0x18, 0x2a, // unprotected
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
								HeaderLabelKeyID: 42,
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
				0xa1, 0x04, 0x18, 0x2a, // unprotected
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
								HeaderLabelKeyID: 42,
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
				0xa1, 0x04, 0x18, 0x2a, // unprotected
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
						HeaderLabelKeyID: 42,
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
						HeaderLabelKeyID: make(chan bool),
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
				0xa1, 0x04, 0x18, 0x2a, // unprotected
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
							RawUnprotected: []byte{0xa1, 0x04, 0x18, 0x2a},
							Unprotected: UnprotectedHeader{
								HeaderLabelKeyID: int64(42),
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
				0xa1, 0x04, 0x18, 0x2a, // unprotected
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
							RawUnprotected: []byte{0xa1, 0x04, 0x18, 0x2a},
							Unprotected: UnprotectedHeader{
								HeaderLabelKeyID: int64(42),
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
				0xa1, 0x04, 0x18, 0x2a, // unprotected
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
							RawUnprotected: []byte{0xa1, 0x04, 0x18, 0x2a},
							Unprotected: UnprotectedHeader{
								HeaderLabelKeyID: int64(42),
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
