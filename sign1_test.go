package cose

import (
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got Sign1Message
			if err := got.UnmarshalCBOR(tt.data); (err != nil) != tt.wantErr {
				t.Errorf("Sign1Message.UnmarshalCBOR() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Sign1Message.MarshalCBOR() = %v, want %v", got, tt.want)
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
			name: "nil payload",
			msg: &Sign1Message{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: AlgorithmES256,
					},
				},
				Payload: nil,
			},
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.msg.Sign(rand.Reader, tt.externalOnSign, signer)
			if (err != nil) != tt.wantErr {
				t.Errorf("Sign1Message.Sign() error = %v, wantErr %v", err, tt.wantErr)
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
