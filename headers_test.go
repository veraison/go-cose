package cose

import (
	"reflect"
	"testing"
)

func TestProtectedHeader_MarshalCBOR(t *testing.T) {
	tests := []struct {
		name    string
		h       ProtectedHeader
		want    []byte
		wantErr bool
	}{
		{
			name: "valid header",
			h: ProtectedHeader{
				HeaderLabelAlgorithm: AlgorithmES256,
				HeaderLabelCritical: []interface{}{
					HeaderLabelContentType,
					"foo",
				},
				HeaderLabelContentType: "text/plain",
				"foo":                  "bar",
			},
			want: []byte{
				0x58, 0x1e, // bstr
				0xa4,       // map
				0x01, 0x26, // alg
				0x02, 0x82, 0x03, 0x63, 0x66, 0x6f, 0x6f, // crit
				0x03, 0x6a, 0x74, 0x65, 0x78, 0x74, 0x2f, 0x70, 0x6c, 0x61, 0x69, 0x6e, // cty
				0x63, 0x66, 0x6f, 0x6f, 0x63, 0x62, 0x61, 0x72, // foo: bar
			},
		},
		{
			name: "nil header",
			h:    nil,
			want: []byte{0x40},
		},
		{
			name: "empty header",
			h:    ProtectedHeader{},
			want: []byte{0x40},
		},
		{
			name: "various types of integer label",
			h: ProtectedHeader{
				uint(1):   0,
				uint8(2):  0,
				uint16(3): 0,
				uint32(4): 0,
				uint64(5): 0,
				int(-1):   0,
				int8(-2):  0,
				int16(-3): 0,
				int32(-4): 0,
				int64(-5): 0,
			},
			want: []byte{
				0x55, // bstr
				0xaa, // map
				0x01, 0x00,
				0x02, 0x00,
				0x03, 0x00,
				0x04, 0x00,
				0x05, 0x00,
				0x20, 0x00,
				0x21, 0x00,
				0x22, 0x00,
				0x23, 0x00,
				0x24, 0x00,
			},
		},
		{
			name: "invalid header label: struct type",
			h: ProtectedHeader{
				struct {
					value int
				}{}: 42,
			},
			wantErr: true,
		},
		{
			name: "empty critical",
			h: ProtectedHeader{
				HeaderLabelCritical: []interface{}{},
			},
			wantErr: true,
		},
		{
			name: "invalid critical",
			h: ProtectedHeader{
				HeaderLabelCritical: 42,
			},
			wantErr: true,
		},
		{
			name: "missing header marked as critical",
			h: ProtectedHeader{
				HeaderLabelCritical: []interface{}{
					HeaderLabelContentType,
				},
			},
			wantErr: true,
		},
		{
			name: "duplicated key",
			h: ProtectedHeader{
				int8(42):  "foo",
				int64(42): "bar",
			},
			wantErr: true,
		},
		{
			name: "un-marshalable content",
			h: ProtectedHeader{
				"foo": make(chan bool),
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.h.MarshalCBOR()
			if (err != nil) != tt.wantErr {
				t.Errorf("ProtectedHeader.MarshalCBOR() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ProtectedHeader.MarshalCBOR() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestProtectedHeader_UnmarshalCBOR(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    ProtectedHeader
		wantErr bool
	}{
		{
			name: "valid header",
			data: []byte{
				0x58, 0x1e, // bstr
				0xa4,       // map
				0x01, 0x26, // alg
				0x02, 0x82, 0x03, 0x63, 0x66, 0x6f, 0x6f, // crit
				0x03, 0x6a, 0x74, 0x65, 0x78, 0x74, 0x2f, 0x70, 0x6c, 0x61, 0x69, 0x6e, // cty
				0x63, 0x66, 0x6f, 0x6f, 0x63, 0x62, 0x61, 0x72, // foo: bar
			},
			want: ProtectedHeader{
				HeaderLabelAlgorithm: AlgorithmES256,
				HeaderLabelCritical: []interface{}{
					HeaderLabelContentType,
					"foo",
				},
				HeaderLabelContentType: "text/plain",
				"foo":                  "bar",
			},
		},
		{
			name: "empty header",
			data: []byte{0x40},
			want: ProtectedHeader{},
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
			name:    "bad CBOR data",
			data:    []byte{0x00, 0x01, 0x02, 0x04},
			wantErr: true,
		},
		{
			name:    "nil bstr",
			data:    []byte{0xf6},
			wantErr: true,
		},
		{
			name:    "non-map header",
			data:    []byte{0x41, 0x00},
			wantErr: true,
		},
		{
			name: "invalid header label type: bstr type",
			data: []byte{
				0x43, 0xa1, 0x40, 0x00,
			},
			wantErr: true,
		},
		{
			name: "empty critical",
			data: []byte{
				0x43, 0xa1, 0x02, 0x80,
			},
			wantErr: true,
		},
		{
			name: "invalid critical",
			data: []byte{
				0x43, 0xa1, 0x02, 0x00,
			},
			wantErr: true,
		},
		{
			name: "missing header marked as critical",
			data: []byte{
				0x44, 0xa1, 0x02, 0x81, 0x03,
			},
			wantErr: true,
		},
		{
			name: "duplicated key",
			data: []byte{
				0x45, 0xa2, 0x01, 0x00, 0x01, 0x00,
			},
			wantErr: true,
		},
		{
			name: "incomplete CBOR data",
			data: []byte{
				0x45,
			},
			wantErr: true,
		},
		{
			name: "invalid map value",
			data: []byte{
				0x46, 0xa1, 0x00, 0xa1, 0x00, 0x4f, 0x01,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		var got ProtectedHeader
		t.Run(tt.name, func(t *testing.T) {
			if err := got.UnmarshalCBOR(tt.data); (err != nil) != tt.wantErr {
				t.Errorf("ProtectedHeader.UnmarshalCBOR() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ProtectedHeader.UnmarshalCBOR() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestProtectedHeader_Algorithm(t *testing.T) {
	tests := []struct {
		name    string
		h       ProtectedHeader
		want    Algorithm
		wantErr error
	}{
		{
			name: "algorithm",
			h: ProtectedHeader{
				HeaderLabelAlgorithm: AlgorithmES256,
			},
			want: AlgorithmES256,
		},
		{
			name: "int",
			h: ProtectedHeader{
				HeaderLabelAlgorithm: int(AlgorithmES256),
			},
			want: AlgorithmES256,
		},
		{
			name: "int8",
			h: ProtectedHeader{
				HeaderLabelAlgorithm: int8(AlgorithmES256),
			},
			want: AlgorithmES256,
		},
		{
			name: "int16",
			h: ProtectedHeader{
				HeaderLabelAlgorithm: int16(AlgorithmES256),
			},
			want: AlgorithmES256,
		},
		{
			name: "int32",
			h: ProtectedHeader{
				HeaderLabelAlgorithm: int32(AlgorithmES256),
			},
			want: AlgorithmES256,
		},
		{
			name: "int64",
			h: ProtectedHeader{
				HeaderLabelAlgorithm: int64(AlgorithmES256),
			},
			want: AlgorithmES256,
		},
		{
			name:    "nil header",
			h:       nil,
			wantErr: ErrAlgorithmNotFound,
		},
		{
			name:    "empty header",
			h:       ProtectedHeader{},
			wantErr: ErrAlgorithmNotFound,
		},
		{
			name: "missing algorithm header",
			h: ProtectedHeader{
				"foo": "bar",
			},
			wantErr: ErrAlgorithmNotFound,
		},
		{
			name: "unknown algorithm",
			h: ProtectedHeader{
				HeaderLabelAlgorithm: "foo",
			},
			wantErr: ErrInvalidAlgorithm,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.h.Algorithm()
			if err != tt.wantErr {
				t.Errorf("ProtectedHeader.Algorithm() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ProtectedHeader.Algorithm() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestProtectedHeader_Critical(t *testing.T) {
	tests := []struct {
		name    string
		h       ProtectedHeader
		want    []interface{}
		wantErr bool
	}{
		{
			name: "valid header",
			h: ProtectedHeader{
				HeaderLabelAlgorithm: AlgorithmES256,
				HeaderLabelCritical: []interface{}{
					HeaderLabelContentType,
					"foo",
				},
				HeaderLabelContentType: "text/plain",
				"foo":                  "bar",
			},
			want: []interface{}{
				HeaderLabelContentType,
				"foo",
			},
		},
		{
			name: "nil header",
			h:    nil,
			want: nil,
		},
		{
			name: "empty header",
			h:    ProtectedHeader{},
			want: nil,
		},
		{
			name: "nothing critical",
			h: ProtectedHeader{
				HeaderLabelAlgorithm: AlgorithmES256,
			},
			want: nil,
		},
		{
			name: "empty critical",
			h: ProtectedHeader{
				HeaderLabelCritical: []interface{}{},
			},
			wantErr: true,
		},
		{
			name: "invalid critical",
			h: ProtectedHeader{
				HeaderLabelCritical: 42,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.h.Critical()
			if (err != nil) != tt.wantErr {
				t.Errorf("ProtectedHeader.Critical() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ProtectedHeader.Critical() = %v, want %v", got, tt.want)
			}
		})
	}
}
