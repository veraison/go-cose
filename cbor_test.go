package cose

import (
	"bytes"
	"testing"
)

func Test_byteString_UnmarshalCBOR(t *testing.T) {
	// test nil pointer
	t.Run("nil byteString pointer", func(t *testing.T) {
		var s *byteString
		data := []byte{0x40}
		if err := s.UnmarshalCBOR(data); err == nil {
			t.Errorf("want error on nil *byteString")
		}
	})

	// test others
	tests := []struct {
		name    string
		data    []byte
		want    byteString
		wantErr bool
	}{
		{
			name: "valid string",
			data: []byte{0x43, 0x66, 0x6f, 0x6f},
			want: []byte{0x66, 0x6f, 0x6f},
		},
		{
			name: "empty string",
			data: []byte{0x40},
			want: []byte{},
		},
		{
			name: "nil string",
			data: []byte{0xf6},
			want: nil,
		},
		{
			name:    "undefined string",
			data:    []byte{0xf7},
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
			name:    "tagged string",
			data:    []byte{0xc2, 0x40},
			wantErr: true,
		},
		{
			name:    "array of bytes", // issue #46
			data:    []byte{0x82, 0x00, 0x1},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got byteString
			if err := got.UnmarshalCBOR(tt.data); (err != nil) != tt.wantErr {
				t.Errorf("byteString.UnmarshalCBOR() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !bytes.Equal(got, tt.want) {
				t.Errorf("byteString.UnmarshalCBOR() = %v, want %v", got, tt.want)
			}
		})
	}
}
