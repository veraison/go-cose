package cose

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"reflect"
	"testing"
)

func TestSign1Message_MarshalCBOR(t *testing.T) {
	tests := []struct {
		name    string
		m       *Sign1Message
		want    []byte
		wantErr bool
	}{
		{
			name: "valid message",
			m: &Sign1Message{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: AlgorithmES256,
					},
					Unprotected: UnprotectedHeader{
						HeaderLabelKeyID: 42,
					},
				},
				Payload:   []byte("foo"),
				Signature: []byte("bar"),
			},
			want: []byte{
				0xd2, // tag
				0x84,
				0x43, 0xa1, 0x01, 0x26, // protected
				0xa1, 0x04, 0x18, 0x2a, // unprotected
				0x43, 0x66, 0x6f, 0x6f, // payload
				0x43, 0x62, 0x61, 0x72, // signature
			},
		},
		{
			name:    "nil message",
			m:       nil,
			wantErr: true,
		},
		{
			name: "nil payload",
			m: &Sign1Message{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: AlgorithmES256,
					},
					Unprotected: UnprotectedHeader{
						HeaderLabelKeyID: 42,
					},
				},
				Payload:   nil,
				Signature: []byte("bar"),
			},
			want: []byte{
				0xd2, // tag
				0x84,
				0x43, 0xa1, 0x01, 0x26, // protected
				0xa1, 0x04, 0x18, 0x2a, // unprotected
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
						HeaderLabelKeyID: 42,
					},
				},
				Payload:   []byte("foo"),
				Signature: nil,
			},
			wantErr: true,
		},
		{
			name: "empty signature",
			m: &Sign1Message{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: AlgorithmES256,
					},
					Unprotected: UnprotectedHeader{
						HeaderLabelKeyID: 42,
					},
				},
				Payload:   nil,
				Signature: []byte{},
			},
			wantErr: true,
		},
		{
			name: "invalid protected header",
			m: &Sign1Message{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: make(chan bool),
					},
					Unprotected: UnprotectedHeader{
						HeaderLabelKeyID: 42,
					},
				},
				Payload:   []byte("foo"),
				Signature: []byte("bar"),
			},
			wantErr: true,
		},
		{
			name: "invalid unprotected header",
			m: &Sign1Message{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: AlgorithmES256,
					},
					Unprotected: UnprotectedHeader{
						HeaderLabelKeyID: make(chan bool),
					},
				},
				Payload:   []byte("foo"),
				Signature: []byte("bar"),
			},
			wantErr: true,
		},
		{
			name: "protected has IV and unprotected has PartialIV error",
			m: &Sign1Message{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: AlgorithmES256,
						HeaderLabelIV:        "",
					},
					Unprotected: UnprotectedHeader{
						HeaderLabelPartialIV: "",
					},
				},
				Payload:   []byte("foo"),
				Signature: []byte("bar"),
			},
			wantErr: true,
		},
		{
			name: "protected has PartialIV and unprotected has IV error",
			m: &Sign1Message{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: AlgorithmES256,
						HeaderLabelPartialIV: "",
					},
					Unprotected: UnprotectedHeader{
						HeaderLabelIV: "",
					},
				},
				Payload:   []byte("foo"),
				Signature: []byte("bar"),
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.m.MarshalCBOR()
			if (err != nil) != tt.wantErr {
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
		wantErr bool
	}{
		{
			name: "valid message",
			data: []byte{
				0xd2, // tag
				0x84,
				0x43, 0xa1, 0x01, 0x26, // protected
				0xa1, 0x04, 0x18, 0x2a, // unprotected
				0x43, 0x66, 0x6f, 0x6f, // payload
				0x43, 0x62, 0x61, 0x72, // signature
			},
			want: Sign1Message{
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
				0xa1, 0x04, 0x18, 0x2a, // unprotected
				0xf6,                   // payload
				0x43, 0x62, 0x61, 0x72, // signature
			},
			want: Sign1Message{
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
				Payload:   nil,
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
			name:    "invalid message with valid prefix", // issue #29
			data:    []byte{0xd2, 0x84, 0xf7, 0xf7, 0xf7, 0xf7},
			wantErr: true,
		},
		{
			name: "tagged signature", // issue #30
			data: []byte{
				0xd2, 0x84, // prefix
				0x40, 0xa0, // empty headers
				0xf6,             // nil payload
				0xcb, 0xa1, 0x00, // tagged signature
			},
			wantErr: true,
		},
		{
			name: "nil signature",
			data: []byte{
				0xd2, 0x84, // prefix
				0x40, 0xa0, // empty headers
				0xf6, // payload
				0xf6, // nil signature
			},
			wantErr: true,
		},
		{
			name: "empty signature",
			data: []byte{
				0xd2, 0x84, // prefix
				0x40, 0xa0, // empty headers
				0xf6, // payload
				0x40, // empty signature
			},
			wantErr: true,
		},
		{
			name: "mismatch tag",
			data: []byte{
				0xd3, 0x84, // prefix
				0x40, 0xa0, // empty headers
				0xf6,       // payload
				0x41, 0x00, //  signature
			},
			wantErr: true,
		},
		{
			name: "mismatch type",
			data: []byte{
				0xd2, 0x40,
			},
			wantErr: true,
		},
		{
			name: "smaller array size",
			data: []byte{
				0xd2, 0x83, // prefix
				0x40, 0xa0, // empty headers
				0xf6, // payload
			},
			wantErr: true,
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
			wantErr: true,
		},
		{
			name: "undefined payload",
			data: []byte{
				0xd2, 0x84, // prefix
				0x40, 0xa0, // empty headers
				0xf7,       // undefined payload
				0x41, 0x00, // signature
			},
			wantErr: true,
		},
		{
			name: "payload as a byte array",
			data: []byte{
				0xd2, 0x84, // prefix
				0x40, 0xa0, // empty headers
				0x80,       // payload
				0x41, 0x00, // signature
			},
			wantErr: true,
		},
		{
			name: "signature as a byte array",
			data: []byte{
				0xd2, 0x84, // prefix
				0x40, 0xa0, // empty headers
				0xf6,       // nil payload
				0x81, 0x00, // signature
			},
			wantErr: true,
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
			wantErr: true,
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
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got Sign1Message
			if err := got.UnmarshalCBOR(tt.data); (err != nil) != tt.wantErr {
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
		wantErr          bool
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
						HeaderLabelKeyID: 42,
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
						HeaderLabelKeyID: 42,
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
						HeaderLabelKeyID: 42,
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
						HeaderLabelKeyID: 42,
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
			wantErr: true,
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
			wantErr: true,
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
			wantErr: true,
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
			wantErr: true,
		},
		{
			name:    "nil message",
			msg:     nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.msg.Sign(rand.Reader, tt.externalOnSign, signer)
			if (err != nil) != tt.wantErr {
				t.Errorf("Sign1Message.Sign() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
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
						HeaderLabelKeyID: 42,
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
						HeaderLabelKeyID: 42,
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
						HeaderLabelKeyID: 42,
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
			hash := crypto.SHA256
			RegisterAlgorithm(algorithmMock, "Mock", hash, nil)
			defer resetExtendedAlgorithm()

			sig := make([]byte, 64)
			_, err := rand.Read(sig)
			if err != nil {
				t.Fatalf("rand.Read() error = %v", err)
			}
			h := hash.New()
			h.Write(tt.toBeSigned)
			digest := h.Sum(nil)
			signer := newMockSigner(t)
			signer.setup(digest, sig)

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
		wantErr          bool
	}{
		{
			name: "round trip on valid message",
		},
		{
			name:             "external mismatch",
			externalOnSign:   []byte("foo"),
			externalOnVerify: []byte("bar"),
			wantErr:          true,
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
			wantErr: true,
		},
		{
			name: "strip signature",
			tamper: func(m *Sign1Message) *Sign1Message {
				m.Signature = nil
				return m
			},
			wantErr: true,
		},
		{
			name: "empty signature",
			tamper: func(m *Sign1Message) *Sign1Message {
				m.Signature = []byte{}
				return m
			},
			wantErr: true,
		},
		{
			name: "tamper protected header",
			tamper: func(m *Sign1Message) *Sign1Message {
				m.Headers.Protected["foo"] = "bar"
				return m
			},
			wantErr: true,
		},
		{
			name: "tamper unprotected header",
			tamper: func(m *Sign1Message) *Sign1Message {
				m.Headers.Unprotected["foo"] = "bar"
				return m
			},
			wantErr: false, // allowed
		},
		{
			name: "tamper payload",
			tamper: func(m *Sign1Message) *Sign1Message {
				m.Payload = []byte("foobar")
				return m
			},
			wantErr: true,
		},
		{
			name: "tamper signature",
			tamper: func(m *Sign1Message) *Sign1Message {
				m.Signature[0]++
				return m
			},
			wantErr: true,
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
						HeaderLabelKeyID: 42,
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
			if err := msg.Verify(tt.externalOnVerify, verifier); (err != nil) != tt.wantErr {
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
