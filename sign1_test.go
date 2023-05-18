package cose

import (
	"bytes"
	"crypto/rand"
	"reflect"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

func TestSign1Message_MarshalCBOR(t *testing.T) {
	tests := []struct {
		name    string
		m       *Sign1Message
		want    []byte
		wantErr string
	}{
		{
			name: "valid message",
			m: &Sign1Message{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: AlgorithmES256,
					},
					Unprotected: UnprotectedHeader{
						HeaderLabelContentType: 42,
					},
				},
				Payload:   []byte("foo"),
				Signature: []byte("bar"),
			},
			want: []byte{
				0xd2, // tag
				0x84,
				0x43, 0xa1, 0x01, 0x26, // protected
				0xa1, 0x03, 0x18, 0x2a, // unprotected
				0x43, 0x66, 0x6f, 0x6f, // payload
				0x43, 0x62, 0x61, 0x72, // signature
			},
		},
		{
			name:    "nil message",
			m:       nil,
			wantErr: "cbor: MarshalCBOR on nil Sign1Message pointer",
		},
		{
			name: "nil payload",
			m: &Sign1Message{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: AlgorithmES256,
					},
					Unprotected: UnprotectedHeader{
						HeaderLabelContentType: 42,
					},
				},
				Payload:   nil,
				Signature: []byte("bar"),
			},
			want: []byte{
				0xd2, // tag
				0x84,
				0x43, 0xa1, 0x01, 0x26, // protected
				0xa1, 0x03, 0x18, 0x2a, // unprotected
				0xf6,                   // payload
				0x43, 0x62, 0x61, 0x72, // signature
			},
		},
		{
			name: "nil signature",
			m: &Sign1Message{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: AlgorithmES256,
					},
					Unprotected: UnprotectedHeader{
						HeaderLabelKeyID: []byte("42"),
					},
				},
				Payload:   []byte("foo"),
				Signature: nil,
			},
			wantErr: "empty signature",
		},
		{
			name: "empty signature",
			m: &Sign1Message{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: AlgorithmES256,
					},
					Unprotected: UnprotectedHeader{
						HeaderLabelKeyID: []byte("42"),
					},
				},
				Payload:   nil,
				Signature: []byte{},
			},
			wantErr: "empty signature",
		},
		{
			name: "invalid protected header",
			m: &Sign1Message{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: make(chan bool),
					},
					Unprotected: UnprotectedHeader{
						HeaderLabelKeyID: []byte("42"),
					},
				},
				Payload:   []byte("foo"),
				Signature: []byte("bar"),
			},
			wantErr: "protected header: header parameter: alg: require int / tstr type",
		},
		{
			name: "invalid unprotected header",
			m: &Sign1Message{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: AlgorithmES256,
					},
					Unprotected: UnprotectedHeader{
						"foo": make(chan bool),
					},
				},
				Payload:   []byte("foo"),
				Signature: []byte("bar"),
			},
			wantErr: "cbor: unsupported type: chan bool",
		},
		{
			name: "protected has IV and unprotected has PartialIV error",
			m: &Sign1Message{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: AlgorithmES256,
						HeaderLabelIV:        []byte(""),
					},
					Unprotected: UnprotectedHeader{
						HeaderLabelPartialIV: []byte(""),
					},
				},
				Payload:   []byte("foo"),
				Signature: []byte("bar"),
			},
			wantErr: "IV (protected) and PartialIV (unprotected) parameters must not both be present",
		},
		{
			name: "protected has PartialIV and unprotected has IV error",
			m: &Sign1Message{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: AlgorithmES256,
						HeaderLabelPartialIV: []byte(""),
					},
					Unprotected: UnprotectedHeader{
						HeaderLabelIV: []byte(""),
					},
				},
				Payload:   []byte("foo"),
				Signature: []byte("bar"),
			},
			wantErr: "IV (unprotected) and PartialIV (protected) parameters must not both be present",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.m.MarshalCBOR()

			if err != nil && (err.Error() != tt.wantErr) {
				t.Errorf("Sign1Message.MarshalCBOR() error = %v, wantErr %v", err, tt.wantErr)
				return
			} else if err == nil && (tt.wantErr != "") {
				t.Errorf("Sign1Message.MarshalCBOR() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Sign1Message.MarshalCBOR() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSign1Message_UnmarshalCBOR(t *testing.T) {
	// test nil pointer
	t.Run("nil Sign1Message pointer", func(t *testing.T) {
		var msg *Sign1Message
		data := []byte{0xd2, 0x84, 0x40, 0xa0, 0xf6, 0x41, 0x00}
		if err := msg.UnmarshalCBOR(data); err == nil {
			t.Errorf("want error on nil *Sign1Message")
		}
	})

	// test others
	tests := []struct {
		name    string
		data    []byte
		want    Sign1Message
		wantErr string
	}{
		{
			name: "valid message",
			data: []byte{
				0xd2, // tag
				0x84,
				0x43, 0xa1, 0x01, 0x26, // protected
				0xa1, 0x03, 0x18, 0x2a, // unprotected
				0x43, 0x66, 0x6f, 0x6f, // payload
				0x43, 0x62, 0x61, 0x72, // signature
			},
			want: Sign1Message{
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
				Payload:   []byte("foo"),
				Signature: []byte("bar"),
			},
		},
		{
			name: "valid message with nil payload",
			data: []byte{
				0xd2, // tag
				0x84,
				0x43, 0xa1, 0x01, 0x26, // protected
				0xa1, 0x03, 0x18, 0x2a, // unprotected
				0xf6,                   // payload
				0x43, 0x62, 0x61, 0x72, // signature
			},
			want: Sign1Message{
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
				Payload:   nil,
				Signature: []byte("bar"),
			},
		},
		{
			name:    "nil CBOR data",
			data:    nil,
			wantErr: "cbor: invalid COSE_Sign1_Tagged object",
		},
		{
			name:    "empty CBOR data",
			data:    []byte{},
			wantErr: "cbor: invalid COSE_Sign1_Tagged object",
		},
		{
			name:    "invalid message with valid prefix", // issue #29
			data:    []byte{0xd2, 0x84, 0xf7, 0xf7, 0xf7, 0xf7},
			wantErr: "cbor: require bstr type",
		},
		{
			name: "tagged signature", // issue #30
			data: []byte{
				0xd2, 0x84, // prefix
				0x40, 0xa0, // empty headers
				0xf6,             // nil payload
				0xcb, 0xa1, 0x00, // tagged signature
			},
			wantErr: "cbor: CBOR tag isn't allowed",
		},
		{
			name: "nil signature",
			data: []byte{
				0xd2, 0x84, // prefix
				0x40, 0xa0, // empty headers
				0xf6, // payload
				0xf6, // nil signature
			},
			wantErr: "empty signature",
		},
		{
			name: "empty signature",
			data: []byte{
				0xd2, 0x84, // prefix
				0x40, 0xa0, // empty headers
				0xf6, // payload
				0x40, // empty signature
			},
			wantErr: "empty signature",
		},
		{
			name: "mismatch tag",
			data: []byte{
				0xd3, 0x84, // prefix
				0x40, 0xa0, // empty headers
				0xf6,       // payload
				0x41, 0x00, //  signature
			},
			wantErr: "cbor: invalid COSE_Sign1_Tagged object",
		},
		{
			name: "mismatch type",
			data: []byte{
				0xd2, 0x40,
			},
			wantErr: "cbor: invalid COSE_Sign1_Tagged object",
		},
		{
			name: "smaller array size",
			data: []byte{
				0xd2, 0x83, // prefix
				0x40, 0xa0, // empty headers
				0xf6, // payload
			},
			wantErr: "cbor: invalid COSE_Sign1_Tagged object",
		},
		{
			name: "larger array size",
			data: []byte{
				0xd2, 0x85, // prefix
				0x40, 0xa0, // empty headers
				0xf6,       // payload
				0x41, 0x00, // signature
				0x40,
			},
			wantErr: "cbor: invalid COSE_Sign1_Tagged object",
		},
		{
			name: "undefined payload",
			data: []byte{
				0xd2, 0x84, // prefix
				0x40, 0xa0, // empty headers
				0xf7,       // undefined payload
				0x41, 0x00, // signature
			},
			wantErr: "cbor: require bstr type",
		},
		{
			name: "payload as a byte array",
			data: []byte{
				0xd2, 0x84, // prefix
				0x40, 0xa0, // empty headers
				0x80,       // payload
				0x41, 0x00, // signature
			},
			wantErr: "cbor: require bstr type",
		},
		{
			name: "signature as a byte array",
			data: []byte{
				0xd2, 0x84, // prefix
				0x40, 0xa0, // empty headers
				0xf6,       // nil payload
				0x81, 0x00, // signature
			},
			wantErr: "cbor: require bstr type",
		},
		{
			name: "protected has IV and unprotected has PartialIV",
			data: []byte{
				0xd2, // tag
				0x84,
				0x46, 0xa1, 0x5, 0x63, 0x66, 0x6f, 0x6f, // protected
				0xa1, 0x6, 0x63, 0x62, 0x61, 0x72, // unprotected
				0xf6,                   // payload
				0x43, 0x62, 0x61, 0x72, // signature
			},
			wantErr: "cbor: invalid protected header: protected header: header parameter: IV: require bstr type",
		},
		{
			name: "protected has PartialIV and unprotected has IV",
			data: []byte{
				0xd2, // tag
				0x84,
				0x46, 0xa1, 0x6, 0x63, 0x66, 0x6f, 0x6f, // protected
				0xa1, 0x5, 0x63, 0x62, 0x61, 0x72, // unprotected
				0xf6,                   // payload
				0x43, 0x62, 0x61, 0x72, // signature
			},
			wantErr: "cbor: invalid protected header: protected header: header parameter: Partial IV: require bstr type",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got Sign1Message
			err := got.UnmarshalCBOR(tt.data)
			if (err != nil) && (err.Error() != tt.wantErr) {
				t.Errorf("Sign1Message.UnmarshalCBOR() error = %v, wantErr %v", err, tt.wantErr)
				return
			} else if err == nil && (tt.wantErr != "") {
				t.Errorf("Sign1Message.UnmarshalCBOR() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Sign1Message.UnmarshalCBOR() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSign1Message_Sign(t *testing.T) {
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
	// see also conformance_test.go for strict tests.
	tests := []struct {
		name             string
		msg              *Sign1Message
		externalOnSign   []byte
		externalOnVerify []byte
		wantErr          string
		check            func(t *testing.T, m *Sign1Message)
	}{
		{
			name: "valid message",
			msg: &Sign1Message{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: AlgorithmES256,
					},
					Unprotected: UnprotectedHeader{
						HeaderLabelKeyID: []byte("42"),
					},
				},
				Payload: []byte("hello world"),
			},
			externalOnSign:   []byte{},
			externalOnVerify: []byte{},
		},
		{
			name: "valid message with external",
			msg: &Sign1Message{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: AlgorithmES256,
					},
					Unprotected: UnprotectedHeader{
						HeaderLabelKeyID: []byte("42"),
					},
				},
				Payload: []byte("hello world"),
			},
			externalOnSign:   []byte("foo"),
			externalOnVerify: []byte("foo"),
		},
		{
			name: "nil external",
			msg: &Sign1Message{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: AlgorithmES256,
					},
					Unprotected: UnprotectedHeader{
						HeaderLabelKeyID: []byte("42"),
					},
				},
				Payload: []byte("hello world"),
			},
			externalOnSign:   nil,
			externalOnVerify: nil,
		},
		{
			name: "mixed nil / empty external",
			msg: &Sign1Message{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: AlgorithmES256,
					},
					Unprotected: UnprotectedHeader{
						HeaderLabelKeyID: []byte("42"),
					},
				},
				Payload: []byte("hello world"),
			},
			externalOnSign:   []byte{},
			externalOnVerify: nil,
		},
		{
			name: "nil payload", // payload is detached
			msg: &Sign1Message{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: AlgorithmES256,
					},
				},
				Payload: nil,
			},
			wantErr: "missing payload",
		},
		{
			name: "mismatch algorithm",
			msg: &Sign1Message{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: AlgorithmES512,
					},
				},
				Payload: []byte("hello world"),
			},
			wantErr: "algorithm mismatch: signer ES256: header ES512",
		},
		{
			name: "missing algorithm",
			msg: &Sign1Message{
				Payload: []byte("hello world"),
			},
			check: func(t *testing.T, m *Sign1Message) {
				got, err := m.Headers.Protected.Algorithm()
				if err != nil {
					t.Errorf("Sign1Message.Headers.Protected.Algorithm() error = %v", err)
				}
				if got != alg {
					t.Errorf("Sign1Message.Headers.Protected.Algorithm() = %v, want %v", got, alg)
				}
			},
		},
		{
			name: "missing algorithm with raw protected",
			msg: &Sign1Message{
				Headers: Headers{
					RawProtected: []byte{0x40},
				},
				Payload: []byte("hello world"),
			},
			wantErr: "algorithm not found",
		},
		{
			name: "missing algorithm with externally supplied data",
			msg: &Sign1Message{
				Payload: []byte("hello world"),
			},
			externalOnSign:   []byte("foo"),
			externalOnVerify: []byte("foo"),
			check: func(t *testing.T, m *Sign1Message) {
				_, err := m.Headers.Protected.Algorithm()
				if want := ErrAlgorithmNotFound; err != want {
					t.Errorf("Sign1Message.Headers.Protected.Algorithm() error = %v, wantErr %v", err, want)
				}
			},
		},
		{
			name: "double signing",
			msg: &Sign1Message{
				Payload:   []byte("hello world"),
				Signature: []byte("foobar"),
			},
			wantErr: "Sign1Message signature already has signature bytes",
		},
		{
			name:    "nil message",
			msg:     nil,
			wantErr: "signing nil Sign1Message",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.msg.Sign(rand.Reader, tt.externalOnSign, signer)

			if err != nil {
				if err.Error() != tt.wantErr {
					t.Errorf("Sign1Message.Sign() error = %v, wantErr %v", err, tt.wantErr)
				}
				return
			} else if tt.wantErr != "" {
				t.Errorf("Sign1Message.Sign() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.check != nil {
				tt.check(t, tt.msg)
			}
			if err := tt.msg.Verify(tt.externalOnVerify, verifier); err != nil {
				t.Errorf("Sign1Message.Verify() error = %v", err)
			}
		})
	}
}

func TestSign1Message_Sign_Internal(t *testing.T) {
	tests := []struct {
		name       string
		msg        *Sign1Message
		external   []byte
		toBeSigned []byte
	}{
		{
			name: "valid message",
			msg: &Sign1Message{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: algorithmMock,
					},
					Unprotected: UnprotectedHeader{
						HeaderLabelKeyID: []byte("42"),
					},
				},
				Payload: []byte("hello world"),
			},
			external: []byte{},
			toBeSigned: []byte{
				0x84,                                                             // array type
				0x6a, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x31, // context
				0x47, 0xa1, 0x01, 0x3a, 0x6d, 0x6f, 0x63, 0x6a, // protected
				0x40,                                                                   // external
				0x4b, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64, // payload
			},
		},
		{
			name: "valid message with external",
			msg: &Sign1Message{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: algorithmMock,
					},
					Unprotected: UnprotectedHeader{
						HeaderLabelKeyID: []byte("42"),
					},
				},
				Payload: []byte("hello world"),
			},
			external: []byte("foo"),
			toBeSigned: []byte{
				0x84,                                                             // array type
				0x6a, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x31, // context
				0x47, 0xa1, 0x01, 0x3a, 0x6d, 0x6f, 0x63, 0x6a, // protected
				0x43, 0x66, 0x6f, 0x6f, // external
				0x4b, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64, // payload
			},
		},
		{
			name: "nil external",
			msg: &Sign1Message{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: algorithmMock,
					},
					Unprotected: UnprotectedHeader{
						HeaderLabelKeyID: []byte("42"),
					},
				},
				Payload: []byte("hello world"),
			},
			external: nil,
			toBeSigned: []byte{
				0x84,                                                             // array type
				0x6a, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x31, // context
				0x47, 0xa1, 0x01, 0x3a, 0x6d, 0x6f, 0x63, 0x6a, // protected
				0x40,                                                                   // external
				0x4b, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64, // payload
			},
		},
		{
			name: "nil protected header",
			msg: &Sign1Message{
				Payload: []byte("hello world"),
			},
			external: []byte("foo"),
			toBeSigned: []byte{
				0x84,                                                             // array type
				0x6a, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x31, // context
				0x40,                   // protected
				0x43, 0x66, 0x6f, 0x6f, // external
				0x4b, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64, // payload
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sig := make([]byte, 64)
			_, err := rand.Read(sig)
			if err != nil {
				t.Fatalf("rand.Read() error = %v", err)
			}
			signer := newMockSigner(t)
			signer.setup(tt.toBeSigned, sig)

			msg := tt.msg
			if err := msg.Sign(rand.Reader, tt.external, signer); err != nil {
				t.Errorf("Sign1Message.Sign() error = %v", err)
				return
			}
			if got := msg.Signature; !bytes.Equal(got, sig) {
				t.Errorf("Sign1Message.Sign() signature = %v, want %v", got, sig)
			}
		})
	}
}

func TestSign1Message_Verify(t *testing.T) {
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
	// see also conformance_test.go for strict tests.
	tests := []struct {
		name             string
		externalOnSign   []byte
		externalOnVerify []byte
		tamper           func(m *Sign1Message) *Sign1Message
		wantErr          string
	}{
		{
			name: "round trip on valid message",
		},
		{
			name:             "external mismatch",
			externalOnSign:   []byte("foo"),
			externalOnVerify: []byte("bar"),
			wantErr:          "verification error",
		},
		{
			name:             "mixed nil / empty external",
			externalOnSign:   nil,
			externalOnVerify: []byte{},
		},
		{
			name: "nil message",
			tamper: func(m *Sign1Message) *Sign1Message {
				return nil
			},
			wantErr: "verifying nil Sign1Message",
		},
		{
			name: "strip signature",
			tamper: func(m *Sign1Message) *Sign1Message {
				m.Signature = nil
				return m
			},
			wantErr: "empty signature",
		},
		{
			name: "empty signature",
			tamper: func(m *Sign1Message) *Sign1Message {
				m.Signature = []byte{}
				return m
			},
			wantErr: "empty signature",
		},
		{
			name: "tamper protected header",
			tamper: func(m *Sign1Message) *Sign1Message {
				m.Headers.Protected["foo"] = "bar"
				return m
			},
			wantErr: "verification error",
		},
		{
			name: "tamper unprotected header",
			tamper: func(m *Sign1Message) *Sign1Message {
				m.Headers.Unprotected["foo"] = "bar"
				return m
			},
		},
		{
			name: "tamper payload",
			tamper: func(m *Sign1Message) *Sign1Message {
				m.Payload = []byte("foobar")
				return m
			},
			wantErr: "verification error",
		},
		{
			name: "tamper signature",
			tamper: func(m *Sign1Message) *Sign1Message {
				m.Signature[0]++
				return m
			},
			wantErr: "verification error",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// generate message and sign
			msg := &Sign1Message{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: AlgorithmES256,
					},
					Unprotected: UnprotectedHeader{
						HeaderLabelKeyID: []byte("42"),
					},
				},
				Payload: []byte("hello world"),
			}
			if err := msg.Sign(rand.Reader, tt.externalOnSign, signer); err != nil {
				t.Errorf("Sign1Message.Sign() error = %v", err)
				return
			}

			// tamper message
			if tt.tamper != nil {
				msg = tt.tamper(msg)
			}

			// verify message
			err := msg.Verify(tt.externalOnVerify, verifier)
			if err != nil && (err.Error() != tt.wantErr) {
				t.Errorf("Sign1Message.Verify() error = %v, wantErr %v", err, tt.wantErr)
			} else if err == nil && (tt.wantErr != "") {
				t.Errorf("Sign1Message.Verify() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}

	// special cases
	t.Run("nil payload", func(t *testing.T) { // payload is detached
		msg := &Sign1Message{
			Headers: Headers{
				Protected: ProtectedHeader{
					HeaderLabelAlgorithm: AlgorithmES256,
				},
			},
			Payload: []byte{},
		}
		if err := msg.Sign(rand.Reader, nil, signer); err != nil {
			t.Errorf("Sign1Message.Sign() error = %v", err)
			return
		}

		// make payload nil on verify
		msg.Payload = nil

		// verify message
		if err := msg.Verify(nil, verifier); err == nil {
			t.Error("Sign1Message.Verify() error = nil, wantErr true")
		}
	})
}

// TestSign1Message_Verify_issue119: non-minimal protected header length
func TestSign1Message_Verify_issue119(t *testing.T) {
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

	// generate message and sign
	msg := &Sign1Message{
		Headers: Headers{
			Protected: ProtectedHeader{
				HeaderLabelAlgorithm: AlgorithmES256,
			},
		},
		Payload: []byte("hello"),
	}
	if err := msg.Sign(rand.Reader, nil, signer); err != nil {
		t.Fatalf("Sign1Message.Sign() error = %v", err)
	}
	data, err := msg.MarshalCBOR()
	if err != nil {
		t.Fatalf("Sign1Message.MarshalCBOR() error = %v", err)
	}

	// decanonicalize protected header
	decanonicalize := func(data []byte) ([]byte, error) {
		var content sign1Message
		if err := decModeWithTagsForbidden.Unmarshal(data[1:], &content); err != nil {
			return nil, err
		}

		protected := make([]byte, len(content.Protected)+1)
		copy(protected[2:], content.Protected[1:])
		protected[0] = 0x58
		protected[1] = content.Protected[0] & 0x1f
		content.Protected = protected

		return encMode.Marshal(cbor.Tag{
			Number:  CBORTagSign1Message,
			Content: content,
		})
	}
	if data, err = decanonicalize(data); err != nil {
		t.Fatalf("fail to decanonicalize: %v", err)
	}

	// verify message
	var decoded Sign1Message
	if err = decoded.UnmarshalCBOR(data); err != nil {
		t.Fatalf("Sign1Message.UnmarshalCBOR() error = %v", err)
	}
	if err := decoded.Verify(nil, verifier); err != nil {
		t.Fatalf("Sign1Message.Verify() error = %v", err)
	}
}

func TestSign1Message_toBeSigned(t *testing.T) {
	tests := []struct {
		name     string
		m        *Sign1Message
		external []byte
		want     []byte
		wantErr  bool
	}{
		{
			name: "valid message",
			m: &Sign1Message{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: algorithmMock,
					},
				},
				Payload: []byte("hello world"),
			},
			want: []byte{
				0x84,                                                             // array type
				0x6a, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x31, // context
				0x47, 0xa1, 0x01, 0x3a, 0x6d, 0x6f, 0x63, 0x6a, // protected
				0x40,                                                                   // external
				0x4b, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64, // payload
			},
		},
		{
			name: "invalid protected header",
			m: &Sign1Message{
				Headers: Headers{
					Protected: ProtectedHeader{
						1.5: nil,
					},
				},
				Payload: []byte{},
			},
			wantErr: true,
		},
		{
			name: "invalid raw protected header",
			m: &Sign1Message{
				Headers: Headers{
					RawProtected: []byte{0x00},
				},
				Payload: []byte{},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.m.toBeSigned(tt.external)
			if (err != nil) != tt.wantErr {
				t.Errorf("Sign1Message.toBeSigned() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Sign1Message.toBeSigned() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUntaggedSign1Message_MarshalCBOR(t *testing.T) {
	tests := []struct {
		name    string
		m       *UntaggedSign1Message
		want    []byte
		wantErr string
	}{
		{
			name: "valid message",
			m: &UntaggedSign1Message{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: AlgorithmES256,
					},
					Unprotected: UnprotectedHeader{
						HeaderLabelContentType: 42,
					},
				},
				Payload:   []byte("foo"),
				Signature: []byte("bar"),
			},
			want: []byte{
				0x84,
				0x43, 0xa1, 0x01, 0x26, // protected
				0xa1, 0x03, 0x18, 0x2a, // unprotected
				0x43, 0x66, 0x6f, 0x6f, // payload
				0x43, 0x62, 0x61, 0x72, // signature
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.m.MarshalCBOR()

			if err != nil && (err.Error() != tt.wantErr) {
				t.Errorf("UntaggedSign1Message.MarshalCBOR() error = %v, wantErr %v", err, tt.wantErr)
				return
			} else if err == nil && (tt.wantErr != "") {
				t.Errorf("UntaggedSign1Message.MarshalCBOR() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("UntaggedSign1Message.MarshalCBOR() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUntaggedSign1Message_UnmarshalCBOR(t *testing.T) {
	// test others
	tests := []struct {
		name    string
		data    []byte
		want    UntaggedSign1Message
		wantErr string
	}{
		{
			name: "valid message",
			data: []byte{
				0x84,
				0x43, 0xa1, 0x01, 0x26, // protected
				0xa1, 0x03, 0x18, 0x2a, // unprotected
				0x43, 0x66, 0x6f, 0x6f, // payload
				0x43, 0x62, 0x61, 0x72, // signature
			},
			want: UntaggedSign1Message{
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
				Payload:   []byte("foo"),
				Signature: []byte("bar"),
			},
		},
		{
			name: "tagged message",
			data: []byte{
				0xd2, // tag
				0x84,
				0x43, 0xa1, 0x01, 0x26, // protected
				0xa1, 0x03, 0x18, 0x2a, // unprotected
				0x43, 0x66, 0x6f, 0x6f, // payload
				0x43, 0x62, 0x61, 0x72, // signature
			},
			wantErr: "cbor: invalid COSE_Sign1 object",
		},
		{
			name:    "empty data",
			data:    []byte{},
			wantErr: "cbor: zero length data",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got UntaggedSign1Message
			err := got.UnmarshalCBOR(tt.data)
			if (err != nil) && (err.Error() != tt.wantErr) {
				t.Errorf("Sign1Message.UnmarshalCBOR() error = %v, wantErr %v", err, tt.wantErr)
				return
			} else if err == nil && (tt.wantErr != "") {
				t.Errorf("Sign1Message.UnmarshalCBOR() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Sign1Message.UnmarshalCBOR() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUntaggedSign1Message_nil(t *testing.T) {
	var m *UntaggedSign1Message

	_, err := m.MarshalCBOR()
	if err.Error() != "cbor: MarshalCBOR on nil Sign1Message pointer" {
		t.Errorf("UntaggedSign1Message.MarshalCBOR unexpected err: %v", err)
	}

	err = m.UnmarshalCBOR([]byte{})
	if err.Error() != "cbor: UnmarshalCBOR on nil UntaggedSign1Message pointer" {
		t.Errorf("UntaggedSign1Message.UnmarshalCBOR unexpected err: %v", err)
	}

	err = m.Sign(nil, []byte{}, nil)
	if err.Error() != "signing nil Sign1Message" {
		t.Errorf("UntaggedSign1Message.Sign unexpected err: %v", err)
	}

	err = m.Verify([]byte{}, nil)
	if err.Error() != "verifying nil Sign1Message" {
		t.Errorf("UntaggedSign1Message.Sign unexpected err: %v", err)
	}
}
