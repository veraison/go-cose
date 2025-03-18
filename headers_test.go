package cose

import (
	"errors"
	"math"
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
				HeaderLabelCritical: []any{
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
			name: "header with MinInt64 alg",
			h: ProtectedHeader{
				HeaderLabelAlgorithm: math.MinInt64,
			},
			want: []byte{
				0x4b,                                                       // bstr
				0xa1,                                                       // map
				0x01, 0x3b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // alg
			},
		},
		{
			name: "canonical ordering",
			h: ProtectedHeader{
				HeaderLabelAlgorithm:   1,
				HeaderLabelCritical:    []any{HeaderLabelAlgorithm},
				HeaderLabelContentType: 16,
				HeaderLabelKeyID:       []byte{1, 2, 3},
				HeaderLabelIV:          []byte{1, 2, 3},
				0x46:                   0x47,
				0x66:                   0x67,
			},
			want: []byte{
				0x58, 0x1a, // bstr
				0xa7,       // map
				0x01, 0x01, // alg
				0x02, 0x81, 0x01, // crit
				0x03, 0x10, // cty
				0x04, 0x43, 0x01, 0x02, 0x03, // kid
				0x05, 0x43, 0x01, 0x02, 0x03, // iv
				0x18, 0x46, 0x18, 0x47, // 0x46: 0x47
				0x18, 0x66, 0x18, 0x67, // 0x66: 0x67
			},
		}, {
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
				uint8(13):  0,
				uint16(14): 0,
				uint32(15): 0,
				uint64(16): 0,
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
				0x0d, 0x00,
				0x0e, 0x00,
				0x0f, 0x00,
				0x10, 0x00,
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
				HeaderLabelCritical: []any{},
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
				HeaderLabelCritical: []any{
					HeaderLabelContentType,
				},
			},
			wantErr: "protected header: header parameter: crit: missing critical header: 3",
		},
		{
			name: "critical header contains non-label element",
			h: ProtectedHeader{
				HeaderLabelCritical: []any{[]uint8{}},
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
		{
			name: "invalid counter signature",
			h: ProtectedHeader{
				HeaderLabelCounterSignature: &Countersignature{},
			},
			wantErr: "protected header: header parameter: counter signature: not allowed",
		},
		{
			name: "invalid counter signature version 2",
			h: ProtectedHeader{
				HeaderLabelCounterSignatureV2: &Countersignature{},
			},
			wantErr: "protected header: header parameter: Countersignature version 2: not allowed",
		},
		{
			name: "content type empty",
			h: ProtectedHeader{
				HeaderLabelContentType: "",
			},
			wantErr: "protected header: header parameter: content type: require non-empty string",
		},
		{
			name: "content type leading space",
			h: ProtectedHeader{
				HeaderLabelContentType: " a/b",
			},
			wantErr: "protected header: header parameter: content type: require no leading/trailing whitespace",
		},
		{
			name: "content type trailing space",
			h: ProtectedHeader{
				HeaderLabelContentType: "a/b ",
			},
			wantErr: "protected header: header parameter: content type: require no leading/trailing whitespace",
		},
		{
			name: "content type no slash",
			h: ProtectedHeader{
				HeaderLabelContentType: "ab",
			},
			wantErr: "protected header: header parameter: content type: require text of form type/subtype",
		},
		{
			name: "content type too many slashes",
			h: ProtectedHeader{
				HeaderLabelContentType: "a/b/c",
			},
			wantErr: "protected header: header parameter: content type: require text of form type/subtype",
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
				HeaderLabelCritical: []any{
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
		{
			name: "countersignature0 is not allowed",
			data: []byte{
				0x54, 0xa1, 0x09, 0x58, 0x10,
				0xb7, 0xca, 0xcb, 0xa2, 0x85, 0xc4, 0xcd, 0x3e,
				0xd2, 0xf0, 0x14, 0x6f, 0x41, 0x98, 0x86, 0x14,
			},
			wantErr: "protected header: header parameter: countersignature0: not allowed",
		},
		{
			name: "Countersignature0V2 is not allowed",
			data: []byte{
				0x54, 0xa1, 0x0c, 0x58, 0x10,
				0xb7, 0xca, 0xcb, 0xa2, 0x85, 0xc4, 0xcd, 0x3e,
				0xd2, 0xf0, 0x14, 0x6f, 0x41, 0x98, 0x86, 0x14,
			},
			wantErr: "protected header: header parameter: Countersignature0 version 2: not allowed",
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
			wantErr: errors.New(`Algorithm("foo"): algorithm not supported`),
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

func TestProtectedHeader_PayloadHashAlgorithm(t *testing.T) {
	tests := []struct {
		name    string
		h       ProtectedHeader
		want    Algorithm
		wantErr error
	}{
		{
			name: "algorithm",
			h: ProtectedHeader{
				HeaderLabelPayloadHashAlgorithm: AlgorithmES256,
			},
			want: AlgorithmES256,
		},
		{
			name: "int",
			h: ProtectedHeader{
				HeaderLabelPayloadHashAlgorithm: int(AlgorithmES256),
			},
			want: AlgorithmES256,
		},
		{
			name: "int8",
			h: ProtectedHeader{
				HeaderLabelPayloadHashAlgorithm: int8(AlgorithmES256),
			},
			want: AlgorithmES256,
		},
		{
			name: "int16",
			h: ProtectedHeader{
				HeaderLabelPayloadHashAlgorithm: int16(AlgorithmES256),
			},
			want: AlgorithmES256,
		},
		{
			name: "int32",
			h: ProtectedHeader{
				HeaderLabelPayloadHashAlgorithm: int32(AlgorithmES256),
			},
			want: AlgorithmES256,
		},
		{
			name: "int64",
			h: ProtectedHeader{
				HeaderLabelPayloadHashAlgorithm: int64(AlgorithmES256),
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
			name: "algorithm in string type is not allowed",
			h: ProtectedHeader{
				HeaderLabelPayloadHashAlgorithm: "foo",
			},
			wantErr: ErrInvalidAlgorithm,
		},
		{
			name: "invalid algorithm",
			h: ProtectedHeader{
				HeaderLabelPayloadHashAlgorithm: 2.5,
			},
			wantErr: ErrInvalidAlgorithm,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.h.PayloadHashAlgorithm()
			if tt.wantErr != nil && err.Error() != tt.wantErr.Error() {
				t.Errorf("ProtectedHeader.PayloadHashAlgorithm() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ProtectedHeader.PayloadHashAlgorithm() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestProtectedHeader_Critical(t *testing.T) {
	tests := []struct {
		name    string
		h       ProtectedHeader
		want    []any
		wantErr string
	}{
		{
			name: "valid header",
			h: ProtectedHeader{
				HeaderLabelAlgorithm: AlgorithmES256,
				HeaderLabelCritical: []any{
					HeaderLabelContentType,
					"foo",
				},
				HeaderLabelContentType: "text/plain",
				"foo":                  "bar",
			},
			want: []any{
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
				HeaderLabelCritical: []any{},
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
				uint8(13):  0,
				uint16(14): 0,
				uint32(15): 0,
				uint64(16): 0,
				int(-1):    0,
				int8(-2):   0,
				int16(-3):  0,
				int32(-4):  0,
				int64(-5):  0,
			},
			want: []byte{
				0xaa, // map
				0x0a, 0x00,
				0x0d, 0x00,
				0x0e, 0x00,
				0x0f, 0x00,
				0x10, 0x00,
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
		{
			name: "malformed counter signature",
			h: UnprotectedHeader{
				HeaderLabelCounterSignature: "",
			},
			wantErr: "unprotected header: header parameter: counter signature is not a Countersignature or a list",
		},
		{
			name: "counter signature without signature",
			h: UnprotectedHeader{
				HeaderLabelCounterSignature: []*Countersignature{
					{
						Headers: Headers{
							Protected: ProtectedHeader{
								HeaderLabelAlgorithm: AlgorithmEd25519,
							},
							Unprotected: UnprotectedHeader{
								HeaderLabelKeyID: []byte("11"),
							},
						},
					},
				},
			},
			wantErr: "empty signature",
		},
		{
			name: "complete counter signature",
			h: UnprotectedHeader{
				HeaderLabelCounterSignature: []*Countersignature{
					{
						Headers: Headers{
							Protected: ProtectedHeader{
								HeaderLabelAlgorithm: AlgorithmEd25519,
							},
							Unprotected: UnprotectedHeader{
								HeaderLabelKeyID: []byte("11"),
							},
						},
						Signature: []byte{
							0xb7, 0xca, 0xcb, 0xa2, 0x85, 0xc4, 0xcd, 0x3e,
							0xd2, 0xf0, 0x14, 0x6f, 0x41, 0x98, 0x86, 0x14,
							0x4c, 0xa6, 0x38, 0xd0, 0x87, 0xde, 0x12, 0x3d,
							0x40, 0x01, 0x67, 0x30, 0x8a, 0xce, 0xab, 0xc4,
							0xb5, 0xe5, 0xc6, 0xa4, 0x0c, 0x0d, 0xe0, 0xb7,
							0x11, 0x67, 0xa3, 0x91, 0x75, 0xea, 0x56, 0xc1,
							0xfe, 0x96, 0xc8, 0x9e, 0x5e, 0x7d, 0x30, 0xda,
							0xf2, 0x43, 0x8a, 0x45, 0x61, 0x59, 0xa2, 0x0a,
						},
					},
				},
			},
			want: []byte{
				0xa1, 0x07, 0x81, 0x83, 0x43, 0xa1, 0x01, 0x27, 0xa1,
				0x04, 0x42, 0x31, 0x31, 0x58, 0x40, 0xb7, 0xca, 0xcb,
				0xa2, 0x85, 0xc4, 0xcd, 0x3e, 0xd2, 0xf0, 0x14, 0x6f,
				0x41, 0x98, 0x86, 0x14, 0x4c, 0xa6, 0x38, 0xd0, 0x87,
				0xde, 0x12, 0x3d, 0x40, 0x01, 0x67, 0x30, 0x8a, 0xce,
				0xab, 0xc4, 0xb5, 0xe5, 0xc6, 0xa4, 0x0c, 0x0d, 0xe0,
				0xb7, 0x11, 0x67, 0xa3, 0x91, 0x75, 0xea, 0x56, 0xc1,
				0xfe, 0x96, 0xc8, 0x9e, 0x5e, 0x7d, 0x30, 0xda, 0xf2,
				0x43, 0x8a, 0x45, 0x61, 0x59, 0xa2, 0x0a,
			},
		},
		{
			name: "malformed Countersignature version 2",
			h: UnprotectedHeader{
				HeaderLabelCounterSignatureV2: "",
			},
			wantErr: "unprotected header: header parameter: Countersignature version 2 is not a Countersignature or a list",
		},
		{
			name: "Countersignature version 2 without signature",
			h: UnprotectedHeader{
				HeaderLabelCounterSignatureV2: &Countersignature{
					Headers: Headers{
						Protected: ProtectedHeader{
							HeaderLabelAlgorithm: AlgorithmEd25519,
						},
						Unprotected: UnprotectedHeader{
							HeaderLabelKeyID: []byte("11"),
						},
					},
				},
			},
			wantErr: "empty signature",
		},
		{
			name: "complete Countersignature version 2",
			h: UnprotectedHeader{
				HeaderLabelCounterSignatureV2: &Countersignature{
					Headers: Headers{
						Protected: ProtectedHeader{
							HeaderLabelAlgorithm: AlgorithmEd25519,
						},
						Unprotected: UnprotectedHeader{
							HeaderLabelKeyID: []byte("11"),
						},
					},
					Signature: []byte{
						0xb7, 0xca, 0xcb, 0xa2, 0x85, 0xc4, 0xcd, 0x3e,
						0xd2, 0xf0, 0x14, 0x6f, 0x41, 0x98, 0x86, 0x14,
						0x4c, 0xa6, 0x38, 0xd0, 0x87, 0xde, 0x12, 0x3d,
						0x40, 0x01, 0x67, 0x30, 0x8a, 0xce, 0xab, 0xc4,
						0xb5, 0xe5, 0xc6, 0xa4, 0x0c, 0x0d, 0xe0, 0xb7,
						0x11, 0x67, 0xa3, 0x91, 0x75, 0xea, 0x56, 0xc1,
						0xfe, 0x96, 0xc8, 0x9e, 0x5e, 0x7d, 0x30, 0xda,
						0xf2, 0x43, 0x8a, 0x45, 0x61, 0x59, 0xa2, 0x0a,
					},
				},
			},
			want: []byte{
				0xa1, 0x0b, 0x83, 0x43, 0xa1, 0x01, 0x27, 0xa1, 0x04,
				0x42, 0x31, 0x31, 0x58, 0x40, 0xb7, 0xca, 0xcb, 0xa2,
				0x85, 0xc4, 0xcd, 0x3e, 0xd2, 0xf0, 0x14, 0x6f, 0x41,
				0x98, 0x86, 0x14, 0x4c, 0xa6, 0x38, 0xd0, 0x87, 0xde,
				0x12, 0x3d, 0x40, 0x01, 0x67, 0x30, 0x8a, 0xce, 0xab,
				0xc4, 0xb5, 0xe5, 0xc6, 0xa4, 0x0c, 0x0d, 0xe0, 0xb7,
				0x11, 0x67, 0xa3, 0x91, 0x75, 0xea, 0x56, 0xc1, 0xfe,
				0x96, 0xc8, 0x9e, 0x5e, 0x7d, 0x30, 0xda, 0xf2, 0x43,
				0x8a, 0x45, 0x61, 0x59, 0xa2, 0x0a,
			},
		},
		{
			name: "complete countersignature0",
			h: UnprotectedHeader{
				HeaderLabelCounterSignature0: []byte{
					0xb7, 0xca, 0xcb, 0xa2, 0x85, 0xc4, 0xcd, 0x3e,
					0xd2, 0xf0, 0x14, 0x6f, 0x41, 0x98, 0x86, 0x14,
					0x4c, 0xa6, 0x38, 0xd0, 0x87, 0xde, 0x12, 0x3d,
					0x40, 0x01, 0x67, 0x30, 0x8a, 0xce, 0xab, 0xc4,
					0xb5, 0xe5, 0xc6, 0xa4, 0x0c, 0x0d, 0xe0, 0xb7,
					0x11, 0x67, 0xa3, 0x91, 0x75, 0xea, 0x56, 0xc1,
					0xfe, 0x96, 0xc8, 0x9e, 0x5e, 0x7d, 0x30, 0xda,
					0xf2, 0x43, 0x8a, 0x45, 0x61, 0x59, 0xa2, 0x0a,
				},
			},
			want: []byte{
				0xa1, 0x09, 0x58, 0x40,
				0xb7, 0xca, 0xcb, 0xa2, 0x85, 0xc4, 0xcd, 0x3e,
				0xd2, 0xf0, 0x14, 0x6f, 0x41, 0x98, 0x86, 0x14,
				0x4c, 0xa6, 0x38, 0xd0, 0x87, 0xde, 0x12, 0x3d,
				0x40, 0x01, 0x67, 0x30, 0x8a, 0xce, 0xab, 0xc4,
				0xb5, 0xe5, 0xc6, 0xa4, 0x0c, 0x0d, 0xe0, 0xb7,
				0x11, 0x67, 0xa3, 0x91, 0x75, 0xea, 0x56, 0xc1,
				0xfe, 0x96, 0xc8, 0x9e, 0x5e, 0x7d, 0x30, 0xda,
				0xf2, 0x43, 0x8a, 0x45, 0x61, 0x59, 0xa2, 0x0a,
			},
		},
		{
			name: "invalid countersignature0",
			h: UnprotectedHeader{
				HeaderLabelCounterSignature0: "11",
			},
			wantErr: "unprotected header: header parameter: countersignature0: require bstr type",
		},
		{
			name: "complete Countersignature0 version 2",
			h: UnprotectedHeader{
				HeaderLabelCounterSignature0V2: []byte{
					0xb7, 0xca, 0xcb, 0xa2, 0x85, 0xc4, 0xcd, 0x3e,
					0xd2, 0xf0, 0x14, 0x6f, 0x41, 0x98, 0x86, 0x14,
					0x4c, 0xa6, 0x38, 0xd0, 0x87, 0xde, 0x12, 0x3d,
					0x40, 0x01, 0x67, 0x30, 0x8a, 0xce, 0xab, 0xc4,
					0xb5, 0xe5, 0xc6, 0xa4, 0x0c, 0x0d, 0xe0, 0xb7,
					0x11, 0x67, 0xa3, 0x91, 0x75, 0xea, 0x56, 0xc1,
					0xfe, 0x96, 0xc8, 0x9e, 0x5e, 0x7d, 0x30, 0xda,
					0xf2, 0x43, 0x8a, 0x45, 0x61, 0x59, 0xa2, 0x0a,
				},
			},
			want: []byte{
				0xa1, 0x0c, 0x58, 0x40,
				0xb7, 0xca, 0xcb, 0xa2, 0x85, 0xc4, 0xcd, 0x3e,
				0xd2, 0xf0, 0x14, 0x6f, 0x41, 0x98, 0x86, 0x14,
				0x4c, 0xa6, 0x38, 0xd0, 0x87, 0xde, 0x12, 0x3d,
				0x40, 0x01, 0x67, 0x30, 0x8a, 0xce, 0xab, 0xc4,
				0xb5, 0xe5, 0xc6, 0xa4, 0x0c, 0x0d, 0xe0, 0xb7,
				0x11, 0x67, 0xa3, 0x91, 0x75, 0xea, 0x56, 0xc1,
				0xfe, 0x96, 0xc8, 0x9e, 0x5e, 0x7d, 0x30, 0xda,
				0xf2, 0x43, 0x8a, 0x45, 0x61, 0x59, 0xa2, 0x0a,
			},
		},
		{
			name: "invalid Countersignature0 version 2",
			h: UnprotectedHeader{
				HeaderLabelCounterSignature0V2: "11",
			},
			wantErr: "unprotected header: header parameter: Countersignature0 version 2: require bstr type",
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
		{
			name: "single counter signature present",
			data: []byte{
				0xa1,       // {
				0x07, 0x83, // / counter signature / 7: [
				0x43, 0xa1, 0x01, 0x27, // / protected h'a10127' / << { / alg / 1:-8 / EdDSA / } >>,
				0xa1, 0x04, 0x42, 0x31, 0x31, // / unprotected / { / kid / 4: '11' },
				0x58, 0x40, // bytes(64)
				0xb7, 0xca, 0xcb, 0xa2, 0x85, 0xc4, 0xcd, 0x3e,
				0xd2, 0xf0, 0x14, 0x6f, 0x41, 0x98, 0x86, 0x14,
				0x4c, 0xa6, 0x38, 0xd0, 0x87, 0xde, 0x12, 0x3d,
				0x40, 0x01, 0x67, 0x30, 0x8a, 0xce, 0xab, 0xc4,
				0xb5, 0xe5, 0xc6, 0xa4, 0x0c, 0x0d, 0xe0, 0xb7,
				0x11, 0x67, 0xa3, 0x91, 0x75, 0xea, 0x56, 0xc1,
				0xfe, 0x96, 0xc8, 0x9e, 0x5e, 0x7d, 0x30, 0xda,
				0xf2, 0x43, 0x8a, 0x45, 0x61, 0x59, 0xa2, 0x0a,
			},
			want: UnprotectedHeader{
				HeaderLabelCounterSignature: &Countersignature{
					Headers: Headers{
						RawProtected: []byte{0x43, 0xa1, 0x01, 0x27},
						Protected: ProtectedHeader{
							HeaderLabelAlgorithm: AlgorithmEd25519,
						},
						RawUnprotected: []byte{0xa1, 0x04, 0x42, 0x31, 0x31},
						Unprotected: UnprotectedHeader{
							HeaderLabelKeyID: []byte("11"),
						},
					},
					Signature: []byte{
						0xb7, 0xca, 0xcb, 0xa2, 0x85, 0xc4, 0xcd, 0x3e,
						0xd2, 0xf0, 0x14, 0x6f, 0x41, 0x98, 0x86, 0x14,
						0x4c, 0xa6, 0x38, 0xd0, 0x87, 0xde, 0x12, 0x3d,
						0x40, 0x01, 0x67, 0x30, 0x8a, 0xce, 0xab, 0xc4,
						0xb5, 0xe5, 0xc6, 0xa4, 0x0c, 0x0d, 0xe0, 0xb7,
						0x11, 0x67, 0xa3, 0x91, 0x75, 0xea, 0x56, 0xc1,
						0xfe, 0x96, 0xc8, 0x9e, 0x5e, 0x7d, 0x30, 0xda,
						0xf2, 0x43, 0x8a, 0x45, 0x61, 0x59, 0xa2, 0x0a,
					},
				},
			},
		},
		{
			name: "CountersignatureV2 in a list",
			data: []byte{
				0xa1,             // {
				0x0b, 0x81, 0x83, // / counter signature / 7: [ [
				0x43, 0xa1, 0x01, 0x27, // / protected h'a10127' / << { / alg / 1:-8 / EdDSA / } >>,
				0xa1, 0x04, 0x42, 0x31, 0x31, // / unprotected / { / kid / 4: '11' },
				0x58, 0x40, // bytes(64)
				0xb7, 0xca, 0xcb, 0xa2, 0x85, 0xc4, 0xcd, 0x3e,
				0xd2, 0xf0, 0x14, 0x6f, 0x41, 0x98, 0x86, 0x14,
				0x4c, 0xa6, 0x38, 0xd0, 0x87, 0xde, 0x12, 0x3d,
				0x40, 0x01, 0x67, 0x30, 0x8a, 0xce, 0xab, 0xc4,
				0xb5, 0xe5, 0xc6, 0xa4, 0x0c, 0x0d, 0xe0, 0xb7,
				0x11, 0x67, 0xa3, 0x91, 0x75, 0xea, 0x56, 0xc1,
				0xfe, 0x96, 0xc8, 0x9e, 0x5e, 0x7d, 0x30, 0xda,
				0xf2, 0x43, 0x8a, 0x45, 0x61, 0x59, 0xa2, 0x0a,
			},
			want: UnprotectedHeader{
				HeaderLabelCounterSignatureV2: []*Countersignature{
					{
						Headers: Headers{
							RawProtected: []byte{0x43, 0xa1, 0x01, 0x27},
							Protected: ProtectedHeader{
								HeaderLabelAlgorithm: AlgorithmEd25519,
							},
							RawUnprotected: []byte{0xa1, 0x04, 0x42, 0x31, 0x31},
							Unprotected: UnprotectedHeader{
								HeaderLabelKeyID: []byte("11"),
							},
						},
						Signature: []byte{
							0xb7, 0xca, 0xcb, 0xa2, 0x85, 0xc4, 0xcd, 0x3e,
							0xd2, 0xf0, 0x14, 0x6f, 0x41, 0x98, 0x86, 0x14,
							0x4c, 0xa6, 0x38, 0xd0, 0x87, 0xde, 0x12, 0x3d,
							0x40, 0x01, 0x67, 0x30, 0x8a, 0xce, 0xab, 0xc4,
							0xb5, 0xe5, 0xc6, 0xa4, 0x0c, 0x0d, 0xe0, 0xb7,
							0x11, 0x67, 0xa3, 0x91, 0x75, 0xea, 0x56, 0xc1,
							0xfe, 0x96, 0xc8, 0x9e, 0x5e, 0x7d, 0x30, 0xda,
							0xf2, 0x43, 0x8a, 0x45, 0x61, 0x59, 0xa2, 0x0a,
						},
					},
				},
			},
		},
		{
			name: "counter signature should be object or list",
			data: []byte{
				0xa1,                   // {
				0x07, 0x42, 0xf0, 0x0d, // / counter signature / 7: h'f00d'
			},
			wantErr: "invalid Countersignature object / list of objects",
		},
		{
			name: "CountersignatureV2 should be object or list",
			data: []byte{
				0xa1,                   // {
				0x0b, 0x42, 0xf0, 0x0d, // / counter signature / 11: h'f00d'
			},
			wantErr: "invalid Countersignature object / list of objects",
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
