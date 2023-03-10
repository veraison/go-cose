package cose

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/fxamacker/cbor/v2"
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
		wantErr string
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
			wantErr: "cbor: require bstr type",
		},
		{
			name:    "nil CBOR data",
			data:    nil,
			wantErr: "EOF",
		},
		{
			name:    "empty CBOR data",
			data:    []byte{},
			wantErr: "EOF",
		},
		{
			name:    "tagged string",
			data:    []byte{0xc2, 0x40},
			wantErr: "cbor: require bstr type",
		},
		{
			name:    "array of bytes", // issue #46
			data:    []byte{0x82, 0x00, 0x1},
			wantErr: "cbor: require bstr type",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got byteString
			err := got.UnmarshalCBOR(tt.data)
			if err != nil && (err.Error() != tt.wantErr) {
				t.Errorf("byteString.UnmarshalCBOR() error = %v, wantErr %v", err, tt.wantErr)
			} else if err == nil && (tt.wantErr != "") {
				t.Errorf("byteString.UnmarshalCBOR() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !bytes.Equal(got, tt.want) {
				t.Errorf("byteString.UnmarshalCBOR() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_deterministicBinaryString(t *testing.T) {
	gen := func(initial []byte, size int) []byte {
		data := make([]byte, size+len(initial))
		copy(data, initial)
		return data
	}
	tests := []struct {
		name    string
		data    cbor.RawMessage
		want    cbor.RawMessage
		wantErr bool
	}{
		{
			name:    "empty input",
			data:    nil,
			wantErr: true,
		},
		{
			name:    "not bstr",
			data:    []byte{0x00},
			wantErr: true,
		},
		{
			name: "short length",
			data: gen([]byte{0x57}, 23),
			want: gen([]byte{0x57}, 23),
		},
		{
			name: "optimal uint8 length",
			data: gen([]byte{0x58, 0x18}, 24),
			want: gen([]byte{0x58, 0x18}, 24),
		},
		{
			name: "non-optimal uint8 length",
			data: gen([]byte{0x58, 0x17}, 23),
			want: gen([]byte{0x57}, 23),
		},
		{
			name: "optimal uint16 length",
			data: gen([]byte{0x59, 0x01, 0x00}, 256),
			want: gen([]byte{0x59, 0x01, 0x00}, 256),
		},
		{
			name: "non-optimal uint16 length, target short",
			data: gen([]byte{0x59, 0x00, 0x17}, 23),
			want: gen([]byte{0x57}, 23),
		},
		{
			name: "non-optimal uint16 length, target uint8",
			data: gen([]byte{0x59, 0x00, 0x18}, 24),
			want: gen([]byte{0x58, 0x18}, 24),
		},
		{
			name: "optimal uint32 length",
			data: gen([]byte{0x5a, 0x00, 0x01, 0x00, 0x00}, 65536),
			want: gen([]byte{0x5a, 0x00, 0x01, 0x00, 0x00}, 65536),
		},
		{
			name: "non-optimal uint32 length, target short",
			data: gen([]byte{0x5a, 0x00, 0x00, 0x00, 0x17}, 23),
			want: gen([]byte{0x57}, 23),
		},
		{
			name: "non-optimal uint32 length, target uint8",
			data: gen([]byte{0x5a, 0x00, 0x00, 0x00, 0x18}, 24),
			want: gen([]byte{0x58, 0x18}, 24),
		},
		{
			name: "non-optimal uint32 length, target uint16",
			data: gen([]byte{0x5a, 0x00, 0x00, 0x01, 0x00}, 256),
			want: gen([]byte{0x59, 0x01, 0x00}, 256),
		},
		{
			name: "non-optimal uint64 length, target short",
			data: gen([]byte{0x5b,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x17,
			}, 23),
			want: gen([]byte{0x57}, 23),
		},
		{
			name: "non-optimal uint64 length, target uint8",
			data: gen([]byte{0x5b,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x18,
			}, 24),
			want: gen([]byte{0x58, 0x18}, 24),
		},
		{
			name: "non-optimal uint64 length, target uint16",
			data: gen([]byte{0x5b,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x01, 0x00,
			}, 256),
			want: gen([]byte{0x59, 0x01, 0x00}, 256),
		},
		{
			name: "non-optimal uint64 length, target uint32",
			data: gen([]byte{0x5b,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x01, 0x00, 0x00,
			}, 65536),
			want: gen([]byte{0x5a, 0x00, 0x01, 0x00, 0x00}, 65536),
		},
		{
			name: "early EOF",
			data: gen([]byte{0x5b,
				0x01, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
			}, 42),
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := deterministicBinaryString(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("deterministicBinaryString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("deterministicBinaryString() = %v, want %v", got, tt.want)
			}
		})
	}
}
