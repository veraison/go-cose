package cose

import (
	"reflect"
	"testing"
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
