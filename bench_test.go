package cose_test

import (
	"io"
	"testing"

	"github.com/veraison/go-cose"
)

func newSign1Message() *cose.Sign1Message {
	return &cose.Sign1Message{
		Headers: cose.Headers{
			Protected: cose.ProtectedHeader{
				cose.HeaderLabelAlgorithm: cose.AlgorithmES256,
			},
			Unprotected: cose.UnprotectedHeader{
				cose.HeaderLabelKeyID: []byte{0x01},
			},
		},
		Payload:   make([]byte, 100),
		Signature: make([]byte, 32),
	}
}

type noSigner struct{}

func (noSigner) Algorithm() cose.Algorithm {
	return cose.AlgorithmES256
}

func (noSigner) Sign(_ io.Reader, digest []byte) ([]byte, error) {
	return digest, nil
}

func (noSigner) Verify(_, _ []byte) error {
	return nil
}

func BenchmarkSign1Message_MarshalCBOR(b *testing.B) {
	msg := newSign1Message()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := msg.MarshalCBOR()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSign1Message_UnmarshalCBOR(b *testing.B) {
	data, err := newSign1Message().MarshalCBOR()
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var m cose.Sign1Message
		err = m.UnmarshalCBOR(data)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSign1Message_Sign(b *testing.B) {
	msg := newSign1Message()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		msg.Signature = nil
		err := msg.Sign(zeroSource{}, nil, noSigner{})
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSign1Message_Verify(b *testing.B) {
	msg := newSign1Message()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := msg.Verify(nil, noSigner{})
		if err != nil {
			b.Fatal(err)
		}
	}
}
