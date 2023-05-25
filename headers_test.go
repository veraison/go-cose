package cose

import (
	"errors"
	"reflect"
	"testing"
)

func TestProtectedHeader_MarshalCBOR(t *testing.T) {
	tests := []struct {
		name    string
		h       ProtectedHeader
		want    []byte
		wantErr string
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
				uint(10):   0,
				uint8(11):  0,
				uint16(12): 0,
				uint32(13): 0,
				uint64(14): 0,
				int(-1):    0,
				int8(-2):   0,
				int16(-3):  0,
				int32(-4):  0,
				int64(-5):  0,
			},
			want: []byte{
				0x55, // bstr
				0xaa, // map
				0x0a, 0x00,
				0x0b, 0x00,
				0x0c, 0x00,
				0x0d, 0x00,
				0x0e, 0x00,
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
			wantErr: "protected header: header label: require int / tstr type",
		},
		{
			name: "empty critical",
			h: ProtectedHeader{
				HeaderLabelCritical: []interface{}{},
			},
			wantErr: "protected header: header parameter: crit: empty crit header",
		},
		{
			name: "invalid critical",
			h: ProtectedHeader{
				HeaderLabelCritical: 42,
			},
			wantErr: "protected header: header parameter: crit: invalid crit header",
		},
		{
			name: "missing header marked as critical",
			h: ProtectedHeader{
				HeaderLabelCritical: []interface{}{
					HeaderLabelContentType,
				},
			},
			wantErr: "protected header: header parameter: crit: missing critical header: 3",
		},
		{
			name: "critical header contains non-label element",
			h: ProtectedHeader{
				HeaderLabelCritical: []interface{}{[]uint8{}},
			},
			wantErr: "protected header: header parameter: crit: require int / tstr type, got '[]uint8': []",
		},
		{
			name: "duplicated key",
			h: ProtectedHeader{
				int8(42):  "foo",
				int64(42): "bar",
			},
			wantErr: "protected header: header label: duplicated label: 42",
		},
		{
			name: "un-marshalable content",
			h: ProtectedHeader{
				"foo": make(chan bool),
			},
			wantErr: "cbor: unsupported type: chan bool",
		},
		{
			name: "iv and partial iv present",
			h: ProtectedHeader{
				HeaderLabelIV:        []byte("foo"),
				HeaderLabelPartialIV: []byte("bar"),
			},
			wantErr: "protected header: header parameter: IV and PartialIV: parameters must not both be present",
		},
		{
			name: "content type is string",
			h: ProtectedHeader{
				HeaderLabelContentType: []byte("foo"),
			},
			wantErr: "protected header: header parameter: content type: require tstr / uint type",
		},
		{
			name: "content type is negative int8",
			h: ProtectedHeader{
				HeaderLabelContentType: int8(-1),
			},
			wantErr: "protected header: header parameter: content type: require tstr / uint type",
		},
		{
			name: "content type is negative int16",
			h: ProtectedHeader{
				HeaderLabelContentType: int16(-1),
			},
			wantErr: "protected header: header parameter: content type: require tstr / uint type",
		},
		{
			name: "content type is negative int32",
			h: ProtectedHeader{
				HeaderLabelContentType: int32(-1),
			},
			wantErr: "protected header: header parameter: content type: require tstr / uint type",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.h.MarshalCBOR()
			if err != nil && (err.Error() != tt.wantErr) {
				t.Errorf("ProtectedHeader.MarshalCBOR() error = %v, wantErr %v", err, tt.wantErr)
				return
			} else if err == nil && tt.wantErr != "" {
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
		wantErr string
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
			name: "empty map",
			data: []byte{0x41, 0xa0},
			want: ProtectedHeader{},
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
			name:    "bad CBOR data",
			data:    []byte{0x00, 0x01, 0x02, 0x04},
			wantErr: "cbor: require bstr type",
		},
		{
			name:    "nil bstr",
			data:    []byte{0xf6},
			wantErr: "cbor: nil protected header",
		},
		{
			name:    "non-map header",
			data:    []byte{0x41, 0x00},
			wantErr: "cbor: protected header: require map type",
		},
		{
			name: "invalid header label type: bstr type",
			data: []byte{
				0x43, 0xa1, 0x40, 0x00,
			},
			wantErr: "cbor: header label: require int / tstr type",
		},
		{
			name: "invalid header label type: major type 7: simple value", // issue #38
			data: []byte{
				0x43, 0xa1, 0xf3, 0x00,
			},
			wantErr: "cbor: header label: require int / tstr type",
		},
		{
			name: "empty critical",
			data: []byte{
				0x43, 0xa1, 0x02, 0x80,
			},
			wantErr: "protected header: header parameter: crit: empty crit header",
		},
		{
			name: "invalid critical",
			data: []byte{
				0x43, 0xa1, 0x02, 0x00,
			},
			wantErr: "protected header: header parameter: crit: invalid crit header",
		},
		{
			name: "missing header marked as critical",
			data: []byte{
				0x44, 0xa1, 0x02, 0x81, 0x03,
			},
			wantErr: "protected header: header parameter: crit: missing critical header: 3",
		},
		{
			name: "critical header contains non-label element",
			data: []byte{
				0x44, 0xa1, 0x2, 0x81, 0x40,
			},
			wantErr: "protected header: header parameter: crit: require int / tstr type, got '[]uint8': []",
		},
		{
			name: "duplicated key",
			data: []byte{
				0x45, 0xa2, 0x01, 0x00, 0x01, 0x00,
			},
			wantErr: "cbor: found duplicate map key \"1\" at map element index 1",
		},
		{
			name: "incomplete CBOR data",
			data: []byte{
				0x45,
			},
			wantErr: "unexpected EOF",
		},
		{
			name: "invalid map value",
			data: []byte{
				0x46, 0xa1, 0x00, 0xa1, 0x00, 0x4f, 0x01,
			},
			wantErr: "unexpected EOF",
		},
		{
			name: "int map key too large",
			data: []byte{
				0x4b, 0xa1, 0x3b, 0x83, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
			},
			wantErr: "cbor: header label: int key must not be higher than 1<<63 - 1",
		},
		{
			name: "header as a byte array",
			data: []byte{
				0x80,
			},
			wantErr: "cbor: require bstr type",
		},
		{
			name: "iv must be bstr",
			data: []byte{
				0x46, 0xa1, 0x5, 0x63, 0x66, 0x6f, 0x6f,
			},
			wantErr: "protected header: header parameter: IV: require bstr type",
		},
		{
			name: "partial iv must be bstr",
			data: []byte{
				0x46, 0xa1, 0x6, 0x63, 0x62, 0x61, 0x72,
			},
			wantErr: "protected header: header parameter: Partial IV: require bstr type",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got ProtectedHeader
			err := got.UnmarshalCBOR(tt.data)
			if err != nil && (err.Error() != tt.wantErr) {
				t.Errorf("ProtectedHeader.UnmarshalCBOR() error = %v, wantErr %v", err, tt.wantErr)
				return
			} else if err == nil && tt.wantErr != "" {
				t.Errorf("ProtectedHeader.UnmarshalCBOR() error = %v, wantErr %v", err, tt.wantErr)
				return
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
			wantErr: errors.New("unknown algorithm value \"foo\""),
		},
		{
			name: "invalid algorithm",
			h: ProtectedHeader{
				HeaderLabelAlgorithm: 2.5,
			},
			wantErr: ErrInvalidAlgorithm,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.h.Algorithm()
			if tt.wantErr != nil && err.Error() != tt.wantErr.Error() {
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
		wantErr string
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
			wantErr: "empty crit header",
		},
		{
			name: "invalid critical",
			h: ProtectedHeader{
				HeaderLabelCritical: 42,
			},
			wantErr: "invalid crit header",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.h.Critical()
			if err != nil && (err.Error() != tt.wantErr) {
				t.Errorf("ProtectedHeader.Critical() error = %v, wantErr %v", err, tt.wantErr)
				return
			} else if err == nil && tt.wantErr != "" {
				t.Errorf("ProtectedHeader.Critical() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ProtectedHeader.Critical() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUnprotectedHeader_MarshalCBOR(t *testing.T) {
	tests := []struct {
		name    string
		h       UnprotectedHeader
		want    []byte
		wantErr string
	}{
		{
			name: "valid header",
			h: UnprotectedHeader{
				HeaderLabelAlgorithm: "foobar",
			},
			want: []byte{
				0xa1,                                     // map
				0x01,                                     // alg
				0x66, 0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72, // foobar
			},
		},
		{
			name: "nil header",
			h:    nil,
			want: []byte{0xa0},
		},
		{
			name: "empty header",
			h:    UnprotectedHeader{},
			want: []byte{0xa0},
		},
		{
			name: "various types of integer label",
			h: UnprotectedHeader{
				uint(10):   0,
				uint8(11):  0,
				uint16(12): 0,
				uint32(13): 0,
				uint64(14): 0,
				int(-1):    0,
				int8(-2):   0,
				int16(-3):  0,
				int32(-4):  0,
				int64(-5):  0,
			},
			want: []byte{
				0xaa, // map
				0x0a, 0x00,
				0x0b, 0x00,
				0x0c, 0x00,
				0x0d, 0x00,
				0x0e, 0x00,
				0x20, 0x00,
				0x21, 0x00,
				0x22, 0x00,
				0x23, 0x00,
				0x24, 0x00,
			},
		},
		{
			name: "invalid header label: struct type",
			h: UnprotectedHeader{
				struct {
					value int
				}{}: 42,
			},
			wantErr: "unprotected header: header label: require int / tstr type",
		},
		{
			name: "duplicated key",
			h: UnprotectedHeader{
				int8(42):  "foo",
				int64(42): "bar",
			},
			wantErr: "unprotected header: header label: duplicated label: 42",
		},
		{
			name: "un-marshalable content",
			h: UnprotectedHeader{
				"foo": make(chan bool),
			},
			wantErr: "cbor: unsupported type: chan bool",
		},
		{
			name: "iv and partial iv present",
			h: UnprotectedHeader{
				HeaderLabelIV:        []byte("foo"),
				HeaderLabelPartialIV: []byte("bar"),
			},
			wantErr: "unprotected header: header parameter: IV and PartialIV: parameters must not both be present",
		},
		{
			name: "critical present",
			h: UnprotectedHeader{
				HeaderLabelCritical: []string{"foo"},
			},
			wantErr: "unprotected header: header parameter: crit: not allowed",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.h.MarshalCBOR()
			if err != nil && (err.Error() != tt.wantErr) {
				t.Errorf("UnprotectedHeader.MarshalCBOR() error = %v, wantErr %v", err, tt.wantErr)
				return
			} else if err == nil && tt.wantErr != "" {
				t.Errorf("UnprotectedHeader.MarshalCBOR() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("UnprotectedHeader.MarshalCBOR() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUnprotectedHeader_UnmarshalCBOR(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    UnprotectedHeader
		wantErr string
	}{
		{
			name: "valid header",
			data: []byte{
				0xa1,                                     // map
				0x01,                                     // alg
				0x66, 0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72, // foobar
			},
			want: UnprotectedHeader{
				HeaderLabelAlgorithm: "foobar",
			},
		},
		{
			name: "empty map",
			data: []byte{0xa0},
			want: UnprotectedHeader{},
		},
		{
			name:    "nil CBOR data",
			data:    nil,
			wantErr: "cbor: nil unprotected header",
		},
		{
			name:    "empty CBOR data",
			data:    []byte{},
			wantErr: "cbor: unprotected header: missing type",
		},
		{
			name:    "bad CBOR data",
			data:    []byte{0x00, 0x01, 0x02, 0x04},
			wantErr: "cbor: unprotected header: require map type",
		},
		{
			name:    "non-map header",
			data:    []byte{0x00},
			wantErr: "cbor: unprotected header: require map type",
		},
		{
			name: "invalid header label type: bstr type",
			data: []byte{
				0xa1, 0x40, 0x00,
			},
			wantErr: "cbor: header label: require int / tstr type",
		},
		{
			name: "invalid header label type: major type 7: simple value", // issue #38
			data: []byte{
				0xa1, 0xf3, 0x00,
			},
			wantErr: "cbor: header label: require int / tstr type",
		},
		{
			name: "duplicated key",
			data: []byte{
				0xa2, 0x01, 0x00, 0x01, 0x00,
			},
			wantErr: "cbor: found duplicate map key \"1\" at map element index 1",
		},
		{
			name: "incomplete CBOR data",
			data: []byte{
				0xa5,
			},
			wantErr: "unexpected EOF",
		},
		{
			name: "invalid map value",
			data: []byte{
				0xa1, 0x00, 0xa1, 0x00, 0x4f, 0x01,
			},
			wantErr: "unexpected EOF",
		},
		{
			name: "int map key too large",
			data: []byte{
				0xa1, 0x3b, 0x83, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
			},
			wantErr: "cbor: header label: int key must not be higher than 1<<63 - 1",
		},
		{
			name: "iv must be bstr",
			data: []byte{
				0xa1, 0x5, 0x63, 0x66, 0x6f, 0x6f,
			},
			wantErr: "unprotected header: header parameter: IV: require bstr type",
		},
		{
			name: "partial iv must be bstr",
			data: []byte{
				0xa1, 0x6, 0x63, 0x62, 0x61, 0x72,
			},
			wantErr: "unprotected header: header parameter: Partial IV: require bstr type",
		},
		{
			name: "critical present",
			data: []byte{
				0xa1,                                     // map
				0x02, 0x82, 0x03, 0x63, 0x66, 0x6f, 0x6f, // crit
			},
			wantErr: "unprotected header: header parameter: crit: not allowed",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got UnprotectedHeader
			err := got.UnmarshalCBOR(tt.data)
			if err != nil && (err.Error() != tt.wantErr) {
				t.Errorf("UnprotectedHeader.UnmarshalCBOR() error = %v, wantErr %v", err, tt.wantErr)
				return
			} else if err == nil && tt.wantErr != "" {
				t.Errorf("UnprotectedHeader.UnmarshalCBOR() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("UnprotectedHeader.UnmarshalCBOR() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHeaders_MarshalProtected(t *testing.T) {
	tests := []struct {
		name    string
		h       Headers
		want    []byte
		wantErr string
	}{
		{
			name: "pre-marshaled protected header",
			h: Headers{
				RawProtected: []byte{0x43, 0xa1, 0x01, 0x26},
				Unprotected: UnprotectedHeader{
					HeaderLabelKeyID: 42,
				},
			},
			want: []byte{0x43, 0xa1, 0x01, 0x26},
		},
		{
			name: "raw over protected",
			h: Headers{
				RawProtected: []byte{0x43, 0xa1, 0x01, 0x26},
				Protected: ProtectedHeader{
					HeaderLabelAlgorithm: AlgorithmPS512,
				},
				Unprotected: UnprotectedHeader{
					HeaderLabelKeyID: 42,
				},
			},
			want: []byte{0x43, 0xa1, 0x01, 0x26},
		},
		{
			name: "no pre-marshaled protected header",
			h: Headers{
				Protected: ProtectedHeader{
					HeaderLabelAlgorithm: AlgorithmES256,
				},
				Unprotected: UnprotectedHeader{
					HeaderLabelKeyID: 42,
				},
			},
			want: []byte{0x43, 0xa1, 0x01, 0x26},
		},
		{
			name: "invalid protected header",
			h: Headers{
				Protected: ProtectedHeader{
					HeaderLabelAlgorithm: make(chan bool),
				},
				Unprotected: UnprotectedHeader{
					HeaderLabelKeyID: 42,
				},
			},
			wantErr: "protected header: header parameter: alg: require int / tstr type",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.h.MarshalProtected()
			if err != nil && (err.Error() != tt.wantErr) {
				t.Errorf("Headers.MarshalProtected() error = %v, wantErr %v", err, tt.wantErr)
				return
			} else if err == nil && tt.wantErr != "" {
				t.Errorf("Headers.MarshalProtected() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Headers.MarshalProtected() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHeaders_MarshalUnprotected(t *testing.T) {
	tests := []struct {
		name    string
		h       Headers
		want    []byte
		wantErr string
	}{
		{
			name: "pre-marshaled protected header",
			h: Headers{
				Protected: ProtectedHeader{
					HeaderLabelAlgorithm: AlgorithmES256,
				},
				RawUnprotected: []byte{0xa1, 0x04, 0x18, 0x2a},
				Unprotected: UnprotectedHeader{
					HeaderLabelKeyID: 42,
				},
			},
			want: []byte{0xa1, 0x04, 0x18, 0x2a},
		},
		{
			name: "raw over protected",
			h: Headers{
				Protected: ProtectedHeader{
					HeaderLabelAlgorithm: AlgorithmES256,
				},
				RawUnprotected: []byte{0xa1, 0x04, 0x18, 0x2a},
				Unprotected: UnprotectedHeader{
					HeaderLabelKeyID: 43,
				},
			},
			want: []byte{0xa1, 0x04, 0x18, 0x2a},
		},
		{
			name: "no pre-marshaled protected header",
			h: Headers{
				Protected: ProtectedHeader{
					HeaderLabelAlgorithm: AlgorithmES256,
				},
				Unprotected: UnprotectedHeader{
					HeaderLabelContentType: uint8(42),
				},
			},
			want: []byte{0xa1, 0x03, 0x18, 0x2a},
		},
		{
			name: "invalid protected header",
			h: Headers{
				Protected: ProtectedHeader{
					HeaderLabelAlgorithm: AlgorithmES256,
				},
				Unprotected: UnprotectedHeader{
					HeaderLabelKeyID: make(chan bool),
				},
			},
			wantErr: "unprotected header: header parameter: kid: require bstr type",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.h.MarshalUnprotected()
			if err != nil && (err.Error() != tt.wantErr) {
				t.Errorf("Headers.MarshalUnprotected() error = %v, wantErr %v", err, tt.wantErr)
				return
			} else if err == nil && tt.wantErr != "" {
				t.Errorf("Headers.MarshalUnprotected() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Headers.MarshalUnprotected() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHeaders_UnmarshalFromRaw(t *testing.T) {
	tests := []struct {
		name    string
		h       Headers
		want    Headers
		wantErr string
	}{
		{
			name: "nil raw protected header",
			h: Headers{
				RawUnprotected: []byte{0xa1, 0x04, 0x18, 0x2a},
			},
			wantErr: "cbor: invalid protected header: EOF",
		},
		{
			name: "nil raw unprotected header",
			h: Headers{
				RawProtected: []byte{0x43, 0xa1, 0x01, 0x26},
			},
			wantErr: "cbor: invalid unprotected header: EOF",
		},
		{
			name: "valid raw header",
			h: Headers{
				RawProtected:   []byte{0x43, 0xa1, 0x01, 0x26},
				RawUnprotected: []byte{0xa1, 0x03, 0x18, 0x2a},
			},
			want: Headers{
				RawProtected: []byte{0x43, 0xa1, 0x01, 0x26},
				Protected: ProtectedHeader{
					HeaderLabelAlgorithm: AlgorithmES256,
				},
				RawUnprotected: []byte{0xa1, 0x04, 0x18, 0x2a},
				Unprotected: UnprotectedHeader{
					HeaderLabelContentType: int8(42),
				},
			},
		},
		{
			name: "replaced with raw header",
			h: Headers{
				RawProtected: []byte{0x43, 0xa1, 0x01, 0x26},
				Protected: ProtectedHeader{
					HeaderLabelAlgorithm: AlgorithmES512,
				},
				RawUnprotected: []byte{0xa1, 0x03, 0x18, 0x2a},
				Unprotected: UnprotectedHeader{
					HeaderLabelContentType: int16(43),
				},
			},
			want: Headers{
				RawProtected: []byte{0x43, 0xa1, 0x01, 0x26},
				Protected: ProtectedHeader{
					HeaderLabelAlgorithm: AlgorithmES256,
				},
				RawUnprotected: []byte{0xa1, 0x04, 0x18, 0x2a},
				Unprotected: UnprotectedHeader{
					HeaderLabelKeyID: 42,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.h
			err := got.UnmarshalFromRaw()
			if err != nil && (err.Error() != tt.wantErr) {
				t.Errorf("Headers.UnmarshalFromRaw() error = %v, wantErr %v", err, tt.wantErr)
				return
			} else if err == nil && tt.wantErr != "" {
				t.Errorf("Headers.UnmarshalFromRaw() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
