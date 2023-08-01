package cose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"reflect"
	"strconv"
	"testing"
)

func TestKey_ParamBytes(t *testing.T) {
	key := &Key{
		Params: map[any]any{
			int64(-1): []byte{1},
			2:         []byte{2},
			uint16(3): []byte{3},
			"foo":     ed25519.PublicKey([]byte{4}),
			5:         5,
		},
	}
	tests := []struct {
		label any
		want  []byte
		want1 bool
	}{
		{int64(-1), []byte{1}, true},
		{2, []byte{2}, true},
		{uint16(3), []byte{3}, true},
		{3, nil, false},
		{5, nil, false},
		{"foo", []byte{4}, true},
		{"bar", nil, false},
	}
	for i, tt := range tests {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			got, got1 := key.ParamBytes(tt.label)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Key.ParamBytes() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("Key.ParamBytes() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestKey_ParamInt(t *testing.T) {
	type i16 int16
	type u16 uint16
	key := &Key{
		Params: map[any]any{
			int64(-1): 1,
			2:         int8(2),
			uint16(3): i16(3),
			uint16(6): u16(3),
			"foo":     -4,
			5:         []byte{5},
		},
	}
	tests := []struct {
		label any
		want  int64
		want1 bool
	}{
		{int64(-1), 1, true},
		{2, 2, true},
		{uint16(3), 3, true},
		{3, 0, false},
		{5, 0, false},
		{uint16(6), 0, false},
		{"foo", -4, true},
		{"bar", 0, false},
	}
	for i, tt := range tests {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			got, got1 := key.ParamInt(tt.label)
			if got != tt.want {
				t.Errorf("Key.ParamInt() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("Key.ParamInt() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestKey_ParamUint(t *testing.T) {
	type i16 int16
	type u16 uint16
	key := &Key{
		Params: map[any]any{
			int64(-1): 1,
			2:         int8(2),
			uint16(3): i16(3),
			4:         i16(-3),
			uint16(6): u16(3),
			"foo":     -4,
			5:         []byte{5},
		},
	}
	tests := []struct {
		label any
		want  uint64
		want1 bool
	}{
		{int64(-1), 1, true},
		{2, 2, true},
		{uint16(3), 3, true},
		{uint16(6), 3, true},
		{4, 0, false},
		{3, 0, false},
		{5, 0, false},
		{"foo", 0, false},
		{"bar", 0, false},
	}
	for i, tt := range tests {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			got, got1 := key.ParamUint(tt.label)
			if got != tt.want {
				t.Errorf("Key.ParamUint() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("Key.ParamUint() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestKey_ParamString(t *testing.T) {
	type str string
	key := &Key{
		Params: map[any]any{
			1:   "foo",
			"2": str("bar"),
			3:   []byte("baz"),
			4:   5,
		},
	}
	tests := []struct {
		label any
		want  string
		want1 bool
	}{
		{1, "foo", true},
		{"2", "bar", true},
		{3, "", false},
		{4, "", false},
	}
	for i, tt := range tests {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			got, got1 := key.ParamString(tt.label)
			if got != tt.want {
				t.Errorf("Key.ParamString() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("Key.ParamString() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestKey_ParamBool(t *testing.T) {
	type boo bool
	key := &Key{
		Params: map[any]any{
			1:   true,
			"2": boo(false),
			3:   []byte("baz"),
			4:   5,
		},
	}
	tests := []struct {
		label any
		want  bool
		want1 bool
	}{
		{1, true, true},
		{"2", false, true},
		{3, false, false},
		{4, false, false},
	}
	for i, tt := range tests {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			got, got1 := key.ParamBool(tt.label)
			if got != tt.want {
				t.Errorf("Key.ParamBool() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("Key.ParamBool() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestKeyOp_String(t *testing.T) {
	tests := []struct {
		op   KeyOp
		want string
	}{
		{KeyOpReserved, "Reserved"},
		{KeyOpSign, "sign"},
		{KeyOpVerify, "verify"},
		{KeyOpEncrypt, "encrypt"},
		{KeyOpDecrypt, "decrypt"},
		{KeyOpWrapKey, "wrapKey"},
		{KeyOpUnwrapKey, "unwrapKey"},
		{KeyOpDeriveKey, "deriveKey"},
		{KeyOpDeriveBits, "deriveBits"},
		{KeyOpMACCreate, "MAC create"},
		{KeyOpMACVerify, "MAC verify"},
		{42, "unknown key_op value 42"},
	}

	for _, tt := range tests {
		if got := tt.op.String(); got != tt.want {
			t.Errorf("KeyOp.String() = %v, want %v", got, tt.want)
		}
	}
}

func TestKey_UnmarshalCBOR(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    *Key
		wantErr string
	}{
		{
			name: "invalid COSE_Key CBOR type",
			data: []byte{
				0x82,       // array(2)
				0x01, 0x01, // kty: OKP
			},
			want:    nil,
			wantErr: "cbor: cannot unmarshal array into Go value of type map[interface {}]interface {}",
		}, {
			name: "invalid kty value",
			data: []byte{
				0xa2,             // map(2)
				0x01, 0x41, 0x01, // kty: bytes(1)
				0x02, 0x43, 0x01, 0x02, 0x03, // kdi: bytes(3)
			},
			want:    nil,
			wantErr: "kty: invalid type: expected int64, got []uint8",
		}, {
			name: "missing kty",
			data: []byte{
				0xa1,             // map(1)
				0x02, 0x41, 0x01, // kdi: bytes(1)
			},
			want:    nil,
			wantErr: "kty: missing",
		}, {
			name: "invalid key type",
			data: []byte{
				0xa1,       // map (2)
				0x01, 0x00, // kty: invalid
			},
			want:    nil,
			wantErr: "kty: invalid value 0",
		}, {
			name: "invalid kdi type",
			data: []byte{
				0xa2,       // map(2)
				0x01, 0x01, // kty: OKP
				0x02, 0x01, // kdi: int(1)
			},
			want:    nil,
			wantErr: "kid: invalid type: expected []uint8, got int64",
		}, {
			name: "invalid alg type",
			data: []byte{
				0xa2,       // map(2)
				0x01, 0x01, // kty: OKP
				0x03, 0x41, 0x01, // alg: bstr(1)
			},
			want:    nil,
			wantErr: "alg: invalid type: expected int64, got []uint8",
		}, {
			name: "invalid key_ops type",
			data: []byte{
				0xa2,       // map(2)
				0x01, 0x01, // kty: OKP
				0x04, 0x41, 0x01, // key_ops: bstr(1)
			},
			want:    nil,
			wantErr: "key_ops: invalid type: expected []any, got []uint8",
		}, {
			name: "unknown key_ops entry value",
			data: []byte{
				0xa2,       // map(2)
				0x01, 0x01, // kty: OKP
				0x04, 0x82, // key_ops: array (2)
				0x02,                   // verify
				0x63, 0x66, 0x6f, 0x6f, // tstr: foo
			},
			want:    nil,
			wantErr: `key_ops: unknown entry value "foo"`,
		}, {
			name: "invalid key_ops entry type",
			data: []byte{
				0xa2,       // map(2)
				0x01, 0x01, // kty: OKP
				0x04, 0x82, // key_ops: array (2)
				0x02, // verify
				0xf6, // nil
			},
			want:    nil,
			wantErr: `key_ops: invalid entry type <nil>`,
		}, {
			name: "invalid base_iv type",
			data: []byte{
				0xa2,       // map(2)
				0x01, 0x01, // kty: OKP
				0x05, 0x01, // base_iv: int(1)
			},
			want:    nil,
			wantErr: "base_iv: invalid type: expected []uint8, got int64",
		}, {
			name: "custom key invalid param type",
			data: []byte{
				0xa3,                               // map (3)
				0x01, 0x3a, 0x00, 0x01, 0x11, 0x6f, // kty: -70000
				0x20, 0x06, // 0x20: 0x06
				0xf6, 0xf6, // nil: nil
			},
			want:    nil,
			wantErr: "invalid label type <nil>",
		}, {
			name: "duplicated param",
			data: []byte{
				0xa3,       // map(3)
				0x01, 0x01, // kty: OKP
				0x18, 0x66, 0x18, 0x67, // 66: 67
				0x18, 0x66, 0x18, 0x47, // 66: 47
			},
			want:    nil,
			wantErr: `cbor: found duplicate map key "102" at map element index 2`,
		}, {
			name: "duplicated kty",
			data: []byte{
				0xa3,       // map(3)
				0x01, 0x01, // kty: OKP
				0x02, 0x41, 0x01, // kdi: bytes(1)
				0x01, 0x01, // kty: OKP (duplicated)
			},
			want:    nil,
			wantErr: `cbor: found duplicate map key "1" at map element index 2`,
		}, {
			name: "OKP missing curve",
			data: []byte{
				0xa1,       // map (2)
				0x01, 0x01, // kty: OKP
			},
			want:    nil,
			wantErr: "invalid key: required parameters missing",
		}, {
			name: "EC2 missing curve",
			data: []byte{
				0xa1,       // map (2)
				0x01, 0x02, // kty: EC2
			},
			want:    nil,
			wantErr: "invalid key: required parameters missing",
		}, {
			name: "OKP invalid curve",
			data: []byte{
				0xa3,       // map (3)
				0x01, 0x01, // kty: OKP
				0x20, 0x01, // curve: CurveP256
				0x21, 0x58, 0x20, //  x-coordinate: bytes(32)
				0x15, 0x52, 0x2e, 0xf1, 0x57, 0x29, 0xcc, 0xf3, // 32-byte value
				0x95, 0x09, 0xea, 0x5c, 0x15, 0xa2, 0x6b, 0xe9,
				0x49, 0xe3, 0x88, 0x07, 0xa5, 0xc2, 0x6e, 0xf9,
				0x28, 0x14, 0x87, 0xef, 0x4a, 0xe6, 0x7b, 0x46,
			},
			want:    nil,
			wantErr: "invalid key: curve not supported for the given key type",
		}, {
			name: "EC2 invalid curve",
			data: []byte{
				0xa4,       // map (4)
				0x01, 0x02, // kty: EC2
				0x20, 0x06, // curve: CurveEd25519
				0x21, 0x58, 0x20, //  x-coordinate: bytes(32)
				0x15, 0x52, 0x2e, 0xf1, 0x57, 0x29, 0xcc, 0xf3, // 32-byte value
				0x95, 0x09, 0xea, 0x5c, 0x15, 0xa2, 0x6b, 0xe9,
				0x49, 0xe3, 0x88, 0x07, 0xa5, 0xc2, 0x6e, 0xf9,
				0x28, 0x14, 0x87, 0xef, 0x4a, 0xe6, 0x7b, 0x46,
				0x22, 0x58, 0x20, //  y-coordinate: bytes(32)
				0x15, 0x52, 0x2e, 0xf1, 0x57, 0x29, 0xcc, 0xf3, // 32-byte value
				0x95, 0x09, 0xea, 0x5c, 0x15, 0xa2, 0x6b, 0xe9,
				0x49, 0xe3, 0x88, 0x07, 0xa5, 0xc2, 0x6e, 0xf9,
				0x28, 0x14, 0x87, 0xef, 0x4a, 0xe6, 0x7b, 0x46,
			},
			want:    nil,
			wantErr: "invalid key: curve not supported for the given key type",
		}, {
			name: "Symmetric missing K",
			data: []byte{
				0xa1,       // map (1)
				0x01, 0x04, // kty: Symmetric
			},
			want:    nil,
			wantErr: "invalid key: required parameters missing",
		}, {
			name: "EC2 invalid algorithm",
			data: []byte{
				0xa4,       // map (3)
				0x01, 0x01, // kty: OKP
				0x03, 0x26, // alg: ECDSA w/ SHA-256
				0x20, 0x06, // curve: Ed25519
				0x21, 0x58, 0x20, //  x-coordinate: bytes(32)
				0x15, 0x52, 0x2e, 0xf1, 0x57, 0x29, 0xcc, 0xf3, // 32-byte value
				0x95, 0x09, 0xea, 0x5c, 0x15, 0xa2, 0x6b, 0xe9,
				0x49, 0xe3, 0x88, 0x07, 0xa5, 0xc2, 0x6e, 0xf9,
				0x28, 0x14, 0x87, 0xef, 0x4a, 0xe6, 0x7b, 0x46,
			},
			want:    nil,
			wantErr: `found algorithm "ES256" (expected "EdDSA")`,
		}, {
			name: "custom key",
			data: []byte{
				0xa3,                               // map (3)
				0x01, 0x3a, 0x00, 0x01, 0x11, 0x6f, // kty: -70000
				0x20, 0x06, // 0x20: 0x06
				0x61, 0x66, 0x63, 0x66, 0x6f, 0x6f, // 0x21: foo
			},
			want: &Key{
				Type: -70000,
				Params: map[any]any{
					int64(-1): int64(6),
					"f":       "foo",
				},
			},
		}, {
			name: "OKP",
			data: []byte{
				0xa6,       // map (6)
				0x01, 0x01, // kty: OKP
				0x03, 0x27, //  alg: EdDSA w/ Ed25519
				0x04,                         // key ops
				0x82,                         // array (2)
				0x02,                         // verify
				0x64, 0x73, 0x69, 0x67, 0x6e, // tstr: sign
				0x05, 0x43, 0x03, 0x02, 0x01, // base_iv: bytes(5)
				0x20, 0x06, // curve: Ed25519
				0x21, 0x58, 0x20, //  x-coordinate: bytes(32)
				0x15, 0x52, 0x2e, 0xf1, 0x57, 0x29, 0xcc, 0xf3, // 32-byte value
				0x95, 0x09, 0xea, 0x5c, 0x15, 0xa2, 0x6b, 0xe9,
				0x49, 0xe3, 0x88, 0x07, 0xa5, 0xc2, 0x6e, 0xf9,
				0x28, 0x14, 0x87, 0xef, 0x4a, 0xe6, 0x7b, 0x46,
			},
			want: &Key{
				Type:      KeyTypeOKP,
				Algorithm: AlgorithmEdDSA,
				Ops:       []KeyOp{KeyOpVerify, KeyOpSign},
				BaseIV:    []byte{0x03, 0x02, 0x01},
				Params: map[any]any{
					KeyLabelOKPCurve: CurveEd25519,
					KeyLabelOKPX: []byte{
						0x15, 0x52, 0x2e, 0xf1, 0x57, 0x29, 0xcc, 0xf3,
						0x95, 0x09, 0xea, 0x5c, 0x15, 0xa2, 0x6b, 0xe9,
						0x49, 0xe3, 0x88, 0x07, 0xa5, 0xc2, 0x6e, 0xf9,
						0x28, 0x14, 0x87, 0xef, 0x4a, 0xe6, 0x7b, 0x46,
					},
				},
			},
			wantErr: "",
		}, {
			name: "Symmetric",
			data: []byte{
				0xa2,       // map (2)
				0x01, 0x04, // kty: Symmetric
				0x20, 0x58, 0x20, //  k: bytes(32)
				0x15, 0x52, 0x2e, 0xf1, 0x57, 0x29, 0xcc, 0xf3, // 32-byte value
				0x95, 0x09, 0xea, 0x5c, 0x15, 0xa2, 0x6b, 0xe9,
				0x49, 0xe3, 0x88, 0x07, 0xa5, 0xc2, 0x6e, 0xf9,
				0x28, 0x14, 0x87, 0xef, 0x4a, 0xe6, 0x7b, 0x46,
			},
			want: &Key{
				Type: KeyTypeSymmetric,
				Params: map[any]any{
					KeyLabelSymmetricK: []byte{
						0x15, 0x52, 0x2e, 0xf1, 0x57, 0x29, 0xcc, 0xf3,
						0x95, 0x09, 0xea, 0x5c, 0x15, 0xa2, 0x6b, 0xe9,
						0x49, 0xe3, 0x88, 0x07, 0xa5, 0xc2, 0x6e, 0xf9,
						0x28, 0x14, 0x87, 0xef, 0x4a, 0xe6, 0x7b, 0x46,
					},
				},
			},
			wantErr: "",
		},
		// The following samples are taken from RFC8152 C.7.1.
		{
			name: "EC2 P-256 public",
			data: mustHexToBytes("a5" +
				"0102" +
				"0258246d65726961646f632e6272616e64796275636b406275636b6c616e642e6578616d706c65" +
				"2001" +
				"21582065eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d" +
				"2258201e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c"),
			want: &Key{
				Type: KeyTypeEC2,
				ID:   []byte("meriadoc.brandybuck@buckland.example"),
				Params: map[any]any{
					KeyLabelEC2Curve: CurveP256,
					KeyLabelEC2X:     mustHexToBytes("65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d"),
					KeyLabelEC2Y:     mustHexToBytes("1e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c"),
				},
			},
		},
		{
			name: "EC2 P-521 public",
			data: mustHexToBytes("a5" +
				"0102" +
				"02581e62696c626f2e62616767696e7340686f626269746f6e2e6578616d706c65" +
				"2003" +
				"2158420072992cb3ac08ecf3e5c63dedec0d51a8c1f79ef2f82f94f3c737bf5de7986671eac625fe8257bbd0394644caaa3aaf8f27a4585fbbcad0f2457620085e5c8f42ad" +
				"22584201dca6947bce88bc5790485ac97427342bc35f887d86d65a089377e247e60baa55e4e8501e2ada5724ac51d6909008033ebc10ac999b9d7f5cc2519f3fe1ea1d9475"),
			want: &Key{
				Type: KeyTypeEC2,
				ID:   []byte("bilbo.baggins@hobbiton.example"),
				Params: map[any]any{
					KeyLabelEC2Curve: CurveP521,
					KeyLabelEC2X:     mustHexToBytes("0072992cb3ac08ecf3e5c63dedec0d51a8c1f79ef2f82f94f3c737bf5de7986671eac625fe8257bbd0394644caaa3aaf8f27a4585fbbcad0f2457620085e5c8f42ad"),
					KeyLabelEC2Y:     mustHexToBytes("01dca6947bce88bc5790485ac97427342bc35f887d86d65a089377e247e60baa55e4e8501e2ada5724ac51d6909008033ebc10ac999b9d7f5cc2519f3fe1ea1d9475"),
				},
			},
		},
		// The following samples are taken from RFC8152 C.7.2.
		{
			name: "EC2 P-256 private",
			data: mustHexToBytes("a6" +
				"0102" +
				"0258246d65726961646f632e6272616e64796275636b406275636b6c616e642e6578616d706c65" +
				"2001" +
				"21582065eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d" +
				"2258201e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c" +
				"235820aff907c99f9ad3aae6c4cdf21122bce2bd68b5283e6907154ad911840fa208cf"),
			want: &Key{
				Type: KeyTypeEC2,
				ID:   []byte("meriadoc.brandybuck@buckland.example"),
				Params: map[any]any{
					KeyLabelEC2Curve: CurveP256,
					KeyLabelEC2X:     mustHexToBytes("65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d"),
					KeyLabelEC2Y:     mustHexToBytes("1e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c"),
					KeyLabelEC2D:     mustHexToBytes("aff907c99f9ad3aae6c4cdf21122bce2bd68b5283e6907154ad911840fa208cf"),
				},
			},
		}, {
			name: "EC2 P-521 private",
			data: mustHexToBytes("a6" +
				"0102" +
				"02581e62696c626f2e62616767696e7340686f626269746f6e2e6578616d706c65" +
				"2003" +
				"2158420072992cb3ac08ecf3e5c63dedec0d51a8c1f79ef2f82f94f3c737bf5de7986671eac625fe8257bbd0394644caaa3aaf8f27a4585fbbcad0f2457620085e5c8f42ad" +
				"22584201dca6947bce88bc5790485ac97427342bc35f887d86d65a089377e247e60baa55e4e8501e2ada5724ac51d6909008033ebc10ac999b9d7f5cc2519f3fe1ea1d9475" +
				"23584200085138ddabf5ca975f5860f91a08e91d6d5f9a76ad4018766a476680b55cd339e8ab6c72b5facdb2a2a50ac25bd086647dd3e2e6e99e84ca2c3609fdf177feb26d"),
			want: &Key{
				Type: KeyTypeEC2,
				ID:   []byte("bilbo.baggins@hobbiton.example"),
				Params: map[any]any{
					KeyLabelEC2Curve: CurveP521,
					KeyLabelEC2X:     mustHexToBytes("0072992cb3ac08ecf3e5c63dedec0d51a8c1f79ef2f82f94f3c737bf5de7986671eac625fe8257bbd0394644caaa3aaf8f27a4585fbbcad0f2457620085e5c8f42ad"),
					KeyLabelEC2Y:     mustHexToBytes("01dca6947bce88bc5790485ac97427342bc35f887d86d65a089377e247e60baa55e4e8501e2ada5724ac51d6909008033ebc10ac999b9d7f5cc2519f3fe1ea1d9475"),
					KeyLabelEC2D:     mustHexToBytes("00085138ddabf5ca975f5860f91a08e91d6d5f9a76ad4018766a476680b55cd339e8ab6c72b5facdb2a2a50ac25bd086647dd3e2e6e99e84ca2c3609fdf177feb26d"),
				},
			},
		}, {
			name: "Symmetric",
			data: mustHexToBytes("a3" +
				"0104" +
				"024a6f75722d736563726574" +
				"205820849b57219dae48de646d07dbb533566e976686457c1491be3a76dcea6c427188"),
			want: &Key{
				Type: KeyTypeSymmetric,
				ID:   []byte("our-secret"),
				Params: map[any]any{
					KeyLabelSymmetricK: mustHexToBytes("849b57219dae48de646d07dbb533566e976686457c1491be3a76dcea6c427188"),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := new(Key)
			err := got.UnmarshalCBOR(tt.data)
			if (err != nil && err.Error() != tt.wantErr) || (err == nil && tt.wantErr != "") {
				t.Errorf("Key.UnmarshalCBOR() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Key.UnmarshalCBOR() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestKey_MarshalCBOR(t *testing.T) {
	tests := []struct {
		name    string
		key     *Key
		want    []byte
		wantErr string
	}{
		{
			name: "OKP with kty and kid",
			key: &Key{
				Type: KeyTypeOKP,
				ID:   []byte{1, 2, 3},
			},
			want: []byte{
				0xa2,       // map (2)
				0x01, 0x01, // kty: OKP
				0x02, 0x43, 0x01, 0x02, 0x03, // kid: bytes(3)
			},
		}, {
			name: "OKP with only kty",
			key: &Key{
				Type: KeyTypeOKP,
			},
			want: []byte{
				0xa1,       // map (1)
				0x01, 0x01, // kty: OKP
			},
		}, {
			name: "OKP with kty and base_iv",
			key: &Key{
				Type:   KeyTypeOKP,
				BaseIV: []byte{3, 2, 1},
			},
			want: []byte{
				0xa2,       // map (2)
				0x01, 0x01, // kty: OKP
				0x05, 0x43, 0x03, 0x02, 0x01, // base_iv: bytes(3)
			},
		}, {
			name: "OKP with kty and alg",
			key: &Key{
				Type:      KeyTypeOKP,
				Algorithm: AlgorithmEdDSA,
			},
			want: []byte{
				0xa2,       // map (2)
				0x01, 0x01, // kty: OKP
				0x03, 0x27, // alg: EdDSA
			},
		}, {
			name: "OKP with kty and private alg",
			key: &Key{
				Type:      KeyTypeOKP,
				Algorithm: -70_000,
			},
			want: []byte{
				0xa2,       // map (2)
				0x01, 0x01, // kty: OKP
				0x03, 0x3a, 0x00, 0x01, 0x11, 0x6f, // alg: -70000
			},
		}, {
			name: "OKP with kty and key_ops",
			key: &Key{
				Type: KeyTypeOKP,
				ID:   []byte{1, 2, 3},
				Ops:  []KeyOp{KeyOpEncrypt, KeyOpDecrypt, -70_000},
			},
			want: []byte{
				0xa3,       // map (3)
				0x01, 0x01, // kty: OKP
				0x02, 0x43, 0x01, 0x02, 0x03, // kid: bytes(3)
				0x04, 0x83, // key_ops: array(3)
				0x03, 0x04, 0x3a, 0x00, 0x01, 0x11, 0x6f, // -70000
			},
		}, {
			name: "OKP with kty and private int params",
			key: &Key{
				Type: KeyTypeOKP,
				Params: map[any]any{
					0x46: 0x47,
					0x66: 0x67,
				},
			},
			want: []byte{
				0xa3,       // map (3)
				0x01, 0x01, // kty: OKP
				0x18, 0x46, 0x18, 0x47, // 0x46: 0x47 (note canonical ordering)
				0x18, 0x66, 0x18, 0x67, // 0x66: 0x67
			},
		}, {
			name: "OKP with kty and private mixed params",
			key: &Key{
				Type: KeyTypeOKP,
				Params: map[any]any{
					0x1234: 0x47,
					"a":    0x67,
				},
			},
			want: []byte{
				0xa3,       // map (3)
				0x01, 0x01, // kty: OKP
				0x19, 0x12, 0x34, 0x18, 0x47, // 0x1234: 0x47 (note canonical lexicographic ordering)
				0x61, 0x61, 0x18, 0x67, // "a": 0x67
			},
		}, {
			name: "OKP duplicated params",
			key: &Key{
				Type: KeyTypeOKP,
				Params: map[any]any{
					int8(10):  0,
					int32(10): 1,
				},
			},
			wantErr: "duplicate label 10",
		}, {
			name: "OKP with invalid param label",
			key: &Key{
				Type: KeyTypeOKP,
				Params: map[any]any{
					int8(10): 0,
					-3.5:     1,
				},
			},
			wantErr: "invalid label type float64",
		}, {
			name: "OKP",
			key: &Key{
				Type:      KeyTypeOKP,
				Algorithm: AlgorithmEdDSA,
				Ops:       []KeyOp{KeyOpVerify, KeyOpEncrypt},
				Params: map[any]any{
					KeyLabelOKPCurve: CurveEd25519,
					KeyLabelOKPX: []byte{
						0x15, 0x52, 0x2e, 0xf1, 0x57, 0x29, 0xcc, 0xf3,
						0x95, 0x09, 0xea, 0x5c, 0x15, 0xa2, 0x6b, 0xe9,
						0x49, 0xe3, 0x88, 0x07, 0xa5, 0xc2, 0x6e, 0xf9,
						0x28, 0x14, 0x87, 0xef, 0x4a, 0xe6, 0x7b, 0x46,
					},
				},
			},
			want: []byte{
				0xa5,       // map (5)
				0x01, 0x01, // kty: OKP
				0x03, 0x27, //  alg: EdDSA w/ Ed25519
				0x04,       // key ops
				0x82,       // array (2)
				0x02, 0x03, // verify, encrypt
				0x20, 0x06, // curve: Ed25519
				0x21, 0x58, 0x20, //  x-coordinate: bytes(32)
				0x15, 0x52, 0x2e, 0xf1, 0x57, 0x29, 0xcc, 0xf3, // 32-byte value
				0x95, 0x09, 0xea, 0x5c, 0x15, 0xa2, 0x6b, 0xe9,
				0x49, 0xe3, 0x88, 0x07, 0xa5, 0xc2, 0x6e, 0xf9,
				0x28, 0x14, 0x87, 0xef, 0x4a, 0xe6, 0x7b, 0x46,
			},
			wantErr: "",
		}, {
			name: "EC2 with short x and y",
			key: &Key{
				Type:      KeyTypeEC2,
				Algorithm: AlgorithmES256,
				Params: map[any]any{
					KeyLabelEC2Curve: CurveP256,
					KeyLabelEC2X:     []byte{0x01},
					KeyLabelEC2Y:     []byte{0x02, 0x03},
				},
			},
			want: []byte{
				0xa5,       // map (4)
				0x01, 0x02, // kty: EC2
				0x03, 0x26, // alg: ES256
				0x20, 0x01, // curve: P256
				0x21, 0x58, 0x20, //  x-coordinate: bytes(32)
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 32-byte value
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
				0x22, 0x58, 0x20, //  y-coordinate: bytes(32)
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 32-byte value
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03,
			},
			wantErr: "",
		}, {
			name: "Symmetric",
			key: &Key{
				Type: KeyTypeSymmetric,
				Params: map[any]any{
					KeyLabelSymmetricK: []byte{
						0x15, 0x52, 0x2e, 0xf1, 0x57, 0x29, 0xcc, 0xf3,
						0x95, 0x09, 0xea, 0x5c, 0x15, 0xa2, 0x6b, 0xe9,
						0x49, 0xe3, 0x88, 0x07, 0xa5, 0xc2, 0x6e, 0xf9,
						0x28, 0x14, 0x87, 0xef, 0x4a, 0xe6, 0x7b, 0x46,
					},
				},
			},
			want: []byte{
				0xa2,       // map (2)
				0x01, 0x04, // kty: Symmetric
				0x20, 0x58, 0x20, //  K: bytes(32)
				0x15, 0x52, 0x2e, 0xf1, 0x57, 0x29, 0xcc, 0xf3, // 32-byte value
				0x95, 0x09, 0xea, 0x5c, 0x15, 0xa2, 0x6b, 0xe9,
				0x49, 0xe3, 0x88, 0x07, 0xa5, 0xc2, 0x6e, 0xf9,
				0x28, 0x14, 0x87, 0xef, 0x4a, 0xe6, 0x7b, 0x46,
			},
			wantErr: "",
		}, {
			name: "unknown key type",
			key:  &Key{Type: 42},
			want: []byte{
				0xa1,             // map (1)
				0x01, 0x18, 0x2a, // kty: 42
			},
			wantErr: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.key.MarshalCBOR()
			if (err != nil && err.Error() != tt.wantErr) || (err == nil && tt.wantErr != "") {
				t.Errorf("Key.MarshalCBOR() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Key.MarshalCBOR() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewKeyOKP(t *testing.T) {
	x, d := newEd25519(t)
	type args struct {
		alg Algorithm
		x   []byte
		d   []byte
	}
	tests := []struct {
		name    string
		args    args
		want    *Key
		wantErr string
	}{
		{
			name: "valid", args: args{AlgorithmEdDSA, x, d},
			want: &Key{
				Type:      KeyTypeOKP,
				Algorithm: AlgorithmEdDSA,
				Params: map[any]any{
					KeyLabelOKPCurve: CurveEd25519,
					KeyLabelOKPX:     x,
					KeyLabelOKPD:     d,
				},
			},
			wantErr: "",
		}, {
			name: "invalid alg", args: args{Algorithm(-100), x, d},
			want:    nil,
			wantErr: `unsupported algorithm "unknown algorithm value -100"`,
		}, {
			name: "x and d missing", args: args{AlgorithmEdDSA, nil, nil},
			want:    nil,
			wantErr: "invalid key: required parameters missing",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewKeyOKP(tt.args.alg, tt.args.x, tt.args.d)
			if (err != nil && err.Error() != tt.wantErr) || (err == nil && tt.wantErr != "") {
				t.Errorf("NewKeyOKP() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewKeyOKP() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewNewKeyEC2(t *testing.T) {
	ec256x, ec256y, ec256d := newEC2(t, elliptic.P256())
	ec384x, ec384y, ec384d := newEC2(t, elliptic.P384())
	ec521x, ec521y, ec521d := newEC2(t, elliptic.P521())
	type args struct {
		alg Algorithm
		x   []byte
		y   []byte
		d   []byte
	}
	tests := []struct {
		name    string
		args    args
		want    *Key
		wantErr string
	}{
		{
			name: "valid ES256", args: args{AlgorithmES256, ec256x, ec256y, ec256d},
			want: &Key{
				Type:      KeyTypeEC2,
				Algorithm: AlgorithmES256,
				Params: map[any]any{
					KeyLabelEC2Curve: CurveP256,
					KeyLabelEC2X:     ec256x,
					KeyLabelEC2Y:     ec256y,
					KeyLabelEC2D:     ec256d,
				},
			},
			wantErr: "",
		}, {
			name: "valid ES384", args: args{AlgorithmES384, ec384x, ec384y, ec384d},
			want: &Key{
				Type:      KeyTypeEC2,
				Algorithm: AlgorithmES384,
				Params: map[any]any{
					KeyLabelEC2Curve: CurveP384,
					KeyLabelEC2X:     ec384x,
					KeyLabelEC2Y:     ec384y,
					KeyLabelEC2D:     ec384d,
				},
			},
			wantErr: "",
		}, {
			name: "valid ES521", args: args{AlgorithmES512, ec521x, ec521y, ec521d},
			want: &Key{
				Type:      KeyTypeEC2,
				Algorithm: AlgorithmES512,
				Params: map[any]any{
					KeyLabelEC2Curve: CurveP521,
					KeyLabelEC2X:     ec521x,
					KeyLabelEC2Y:     ec521y,
					KeyLabelEC2D:     ec521d,
				},
			},
			wantErr: "",
		}, {
			name: "invalid alg", args: args{Algorithm(-100), ec256x, ec256y, ec256d},
			want:    nil,
			wantErr: `unsupported algorithm "unknown algorithm value -100"`,
		}, {
			name: "x, y and d missing", args: args{AlgorithmES512, nil, nil, nil},
			want:    nil,
			wantErr: "invalid key: required parameters missing",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewKeyEC2(tt.args.alg, tt.args.x, tt.args.y, tt.args.d)
			if (err != nil && err.Error() != tt.wantErr) || (err == nil && tt.wantErr != "") {
				t.Errorf("NewKeyEC2() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewKeyEC2() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewKeySymmetric(t *testing.T) {
	type args struct {
		k []byte
	}
	tests := []struct {
		name string
		args args
		want *Key
	}{
		{"valid", args{[]byte{1, 2, 3}}, &Key{
			Type: KeyTypeSymmetric,
			Params: map[any]any{
				KeyLabelSymmetricK: []byte{1, 2, 3},
			},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewKeySymmetric(tt.args.k); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewKeySymmetric() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestKey_SignRoundtrip(t *testing.T) {
	tests := []struct {
		name   string
		newKey func() (crypto.PrivateKey, error)
	}{
		{
			"P-256", func() (crypto.PrivateKey, error) {
				return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			},
		}, {
			"P-384", func() (crypto.PrivateKey, error) {
				return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
			},
		}, {
			"P-521", func() (crypto.PrivateKey, error) {
				return ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
			},
		}, {
			"Ed25519", func() (crypto.PrivateKey, error) {
				_, priv, err := ed25519.GenerateKey(rand.Reader)
				return priv, err
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			priv, err := tt.newKey()
			if err != nil {
				t.Fatal(err)
			}
			key, err := NewKeyFromPrivate(priv)
			if err != nil {
				t.Fatal(err)
			}
			signer, err := key.Signer()
			if err != nil {
				t.Fatal(err)
			}
			message := []byte("foo bar")
			sig, err := signer.Sign(rand.Reader, message)
			if err != nil {
				t.Fatal(err)
			}
			verifier, err := key.Verifier()
			if err != nil {
				t.Fatal(err)
			}
			err = verifier.Verify(message, sig)
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestKey_AlgorithmOrDefault(t *testing.T) {
	tests := []struct {
		name    string
		k       *Key
		want    Algorithm
		wantErr string
	}{
		{
			"custom",
			&Key{Algorithm: -1000},
			-1000,
			"",
		},
		{
			"OKP-Ed25519",
			&Key{
				Type: KeyTypeOKP,
				Params: map[any]any{
					KeyLabelOKPCurve: CurveEd25519,
				},
			},
			AlgorithmEdDSA,
			"",
		},
		{
			"OKP-P256",
			&Key{
				Type: KeyTypeOKP,
				Params: map[any]any{
					KeyLabelOKPCurve: CurveP256,
				},
			},
			AlgorithmReserved,
			`unsupported curve "P-256" for key type OKP`,
		},
		{
			"EC2-P256",
			&Key{
				Type: KeyTypeEC2,
				Params: map[any]any{
					KeyLabelEC2Curve: CurveP256,
				},
			},
			AlgorithmES256,
			"",
		},
		{
			"EC2-P384",
			&Key{
				Type: KeyTypeEC2,
				Params: map[any]any{
					KeyLabelEC2Curve: CurveP384,
				},
			},
			AlgorithmES384,
			"",
		},
		{
			"EC2-P521",
			&Key{
				Type: KeyTypeEC2,
				Params: map[any]any{
					KeyLabelEC2Curve: CurveP521,
				},
			},
			AlgorithmES512,
			"",
		},
		{
			"EC2-Ed25519",
			&Key{
				Type: KeyTypeEC2,
				Params: map[any]any{
					KeyLabelEC2Curve: CurveEd25519,
				},
			},
			AlgorithmReserved,
			`unsupported curve "Ed25519" for key type EC2`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.k.AlgorithmOrDefault()
			if (err != nil && err.Error() != tt.wantErr) || (err == nil && tt.wantErr != "") {
				t.Errorf("Key.AlgorithmOrDefault() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Key.AlgorithmOrDefault() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewKeyFromPrivate(t *testing.T) {
	x, y, d := newEC2(t, elliptic.P256())
	okpx, okpd := newEd25519(t)
	tests := []struct {
		name    string
		k       crypto.PrivateKey
		want    *Key
		wantErr string
	}{
		{
			"ecdsa", &ecdsa.PrivateKey{
				PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)},
				D:         new(big.Int).SetBytes(d),
			}, &Key{
				Algorithm: AlgorithmES256,
				Type:      KeyTypeEC2,
				Params: map[any]any{
					KeyLabelEC2Curve: CurveP256,
					KeyLabelEC2X:     x,
					KeyLabelEC2Y:     y,
					KeyLabelEC2D:     d,
				},
			},
			"",
		},
		{
			"ecdsa invalid", &ecdsa.PrivateKey{
				PublicKey: ecdsa.PublicKey{Curve: *new(elliptic.Curve), X: big.NewInt(1), Y: big.NewInt(2)},
				D:         big.NewInt(3),
			},
			nil,
			"unsupported curve: <nil>",
		},
		{
			"ed25519", ed25519.PrivateKey(append(okpd, okpx...)),
			&Key{
				Algorithm: AlgorithmEdDSA, Type: KeyTypeOKP,
				Params: map[any]any{
					KeyLabelOKPCurve: CurveEd25519,
					KeyLabelOKPX:     okpx,
					KeyLabelOKPD:     okpd,
				}},
			"",
		},
		{
			"invalid key", ed25519.PublicKey{1, 2, 3},
			nil,
			ErrInvalidPrivKey.Error(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewKeyFromPrivate(tt.k)
			if (err != nil && err.Error() != tt.wantErr) || (err == nil && tt.wantErr != "") {
				t.Errorf("NewKeyFromPrivate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewKeyFromPrivate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewKeyFromPublic(t *testing.T) {
	ecx, ecy, _ := newEC2(t, elliptic.P256())
	okpx, _ := newEd25519(t)
	tests := []struct {
		name    string
		k       crypto.PublicKey
		want    *Key
		wantErr string
	}{
		{
			"ecdsa", &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(ecx), Y: new(big.Int).SetBytes(ecy)},
			&Key{
				Algorithm: AlgorithmES256,
				Type:      KeyTypeEC2,
				Params: map[any]any{
					KeyLabelEC2Curve: CurveP256,
					KeyLabelEC2X:     ecx,
					KeyLabelEC2Y:     ecy,
				},
			},
			"",
		},
		{
			"ecdsa invalid", &ecdsa.PublicKey{Curve: *new(elliptic.Curve), X: big.NewInt(1), Y: big.NewInt(2)},
			nil,
			"unsupported curve: <nil>",
		},
		{
			"ed25519", ed25519.PublicKey(okpx),
			&Key{
				Algorithm: AlgorithmEdDSA,
				Type:      KeyTypeOKP,
				Params: map[any]any{
					KeyLabelOKPCurve: CurveEd25519,
					KeyLabelOKPX:     okpx,
				},
			},
			"",
		},
		{
			"invalid key", ed25519.PrivateKey{1, 2, 3, 1, 2, 3},
			nil,
			ErrInvalidPubKey.Error(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewKeyFromPublic(tt.k)
			if (err != nil && err.Error() != tt.wantErr) || (err == nil && tt.wantErr != "") {
				t.Errorf("NewKeyFromPublic() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewKeyFromPublic() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestKey_Signer(t *testing.T) {
	x, d := newEd25519(t)
	tests := []struct {
		name    string
		k       *Key
		wantAlg Algorithm
		wantErr string
	}{
		{
			"without algorithm", &Key{
				Type: KeyTypeOKP,
				Ops:  []KeyOp{KeyOpSign},
				Params: map[any]any{
					KeyLabelOKPCurve: CurveEd25519,
					KeyLabelOKPX:     x,
					KeyLabelOKPD:     d,
				},
			},
			AlgorithmEdDSA,
			"",
		},
		{
			"without key_ops", &Key{
				Type:      KeyTypeOKP,
				Algorithm: AlgorithmEdDSA,
				Params: map[any]any{
					KeyLabelOKPCurve: CurveEd25519,
					KeyLabelOKPX:     x,
					KeyLabelOKPD:     d,
				},
			},
			AlgorithmEdDSA,
			"",
		},
		{
			"invalid algorithm", &Key{
				Type: KeyTypeOKP,
				Params: map[any]any{
					KeyLabelOKPCurve: CurveP256,
					KeyLabelOKPX:     x,
					KeyLabelOKPD:     d,
				},
			},
			AlgorithmReserved,
			"invalid key: curve not supported for the given key type",
		},
		{
			"can't sign", &Key{
				Type: KeyTypeOKP,
				Ops:  []KeyOp{KeyOpVerify},
				Params: map[any]any{
					KeyLabelOKPCurve: CurveEd25519,
					KeyLabelOKPX:     x,
					KeyLabelOKPD:     d,
				},
			},
			AlgorithmReserved,
			ErrOpNotSupported.Error(),
		},
		{
			"unsupported key", &Key{
				Type: KeyTypeSymmetric,
				Ops:  []KeyOp{KeyOpSign},
				Params: map[any]any{
					KeyLabelSymmetricK: d,
				},
			},
			AlgorithmReserved,
			`unexpected key type "Symmetric"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, err := tt.k.Signer()
			if (err != nil && err.Error() != tt.wantErr) || (err == nil && tt.wantErr != "") {
				t.Errorf("Key.Signer() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil {
				if got := v.Algorithm(); got != tt.wantAlg {
					t.Errorf("Key.Signer().Algorithm() = %v, want %v", got, tt.wantAlg)
				}
			}
		})
	}
}

func TestKey_Verifier(t *testing.T) {
	x, _ := newEd25519(t)
	tests := []struct {
		name    string
		k       *Key
		wantAlg Algorithm
		wantErr string
	}{
		{
			"without algorithm", &Key{
				Type: KeyTypeOKP,
				Ops:  []KeyOp{KeyOpVerify},
				Params: map[any]any{
					KeyLabelOKPCurve: CurveEd25519,
					KeyLabelOKPX:     x,
				},
			},
			AlgorithmEdDSA,
			"",
		},
		{
			"without key_ops", &Key{
				Type:      KeyTypeOKP,
				Algorithm: AlgorithmEdDSA,
				Params: map[any]any{
					KeyLabelOKPCurve: CurveEd25519,
					KeyLabelOKPX:     x,
				},
			},
			AlgorithmEdDSA,
			"",
		},
		{
			"invalid algorithm", &Key{
				Type: KeyTypeOKP,
				Params: map[any]any{
					KeyLabelOKPCurve: CurveP256,
					KeyLabelOKPX:     x,
				},
			},
			AlgorithmReserved,
			"invalid key: curve not supported for the given key type",
		},
		{
			"can't verify", &Key{
				Type: KeyTypeOKP,
				Ops:  []KeyOp{KeyOpSign},
				Params: map[any]any{
					KeyLabelOKPCurve: CurveEd25519,
					KeyLabelOKPX:     x,
				},
			},
			AlgorithmReserved,
			ErrOpNotSupported.Error(),
		},
		{
			"unsupported key", &Key{
				Type: KeyTypeSymmetric,
				Ops:  []KeyOp{KeyOpVerify},
				Params: map[any]any{
					KeyLabelSymmetricK: x,
				},
			},
			AlgorithmReserved,
			`unexpected key type "Symmetric"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, err := tt.k.Verifier()
			if (err != nil && err.Error() != tt.wantErr) || (err == nil && tt.wantErr != "") {
				t.Errorf("Key.Verifier() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil {
				if got := v.Algorithm(); got != tt.wantAlg {
					t.Errorf("Key.Verifier().Algorithm() = %v, want %v", got, tt.wantAlg)
				}
			}
		})
	}
}

func TestKey_PrivateKey(t *testing.T) {
	ec256x, ec256y, ec256d := newEC2(t, elliptic.P256())
	ec384x, ec384y, ec384d := newEC2(t, elliptic.P384())
	ec521x, ec521y, ec521d := newEC2(t, elliptic.P521())
	okpx, okpd := newEd25519(t)
	tests := []struct {
		name    string
		k       *Key
		want    crypto.PrivateKey
		wantErr string
	}{
		{
			"CurveEd25519", &Key{
				Type: KeyTypeOKP,
				Params: map[any]any{
					KeyLabelOKPCurve: CurveEd25519,
					KeyLabelOKPX:     okpx,
					KeyLabelOKPD:     okpd,
				},
			},
			ed25519.PrivateKey(append(okpd, okpx...)),
			"",
		}, {
			"CurveEd25519 missing x", &Key{
				Type: KeyTypeOKP,
				Params: map[any]any{
					KeyLabelOKPCurve: CurveEd25519,
					KeyLabelOKPD:     okpd,
				},
			},
			ed25519.PrivateKey(append(okpd, okpx...)),
			"",
		}, {
			"CurveP256", &Key{
				Type: KeyTypeEC2,
				Params: map[any]any{
					KeyLabelEC2Curve: CurveP256,
					KeyLabelEC2X:     ec256x,
					KeyLabelEC2Y:     ec256y,
					KeyLabelEC2D:     ec256d,
				},
			},
			&ecdsa.PrivateKey{
				PublicKey: ecdsa.PublicKey{
					Curve: elliptic.P256(),
					X:     new(big.Int).SetBytes(ec256x),
					Y:     new(big.Int).SetBytes(ec256y),
				},
				D: new(big.Int).SetBytes(ec256d),
			},
			"",
		}, {
			"CurveP256 missing x and y", &Key{
				Type: KeyTypeEC2,
				Params: map[any]any{
					KeyLabelEC2Curve: CurveP256,
					KeyLabelEC2D:     ec256d,
				},
			},
			&ecdsa.PrivateKey{
				PublicKey: ecdsa.PublicKey{
					Curve: elliptic.P256(),
					X:     new(big.Int).SetBytes(ec256x),
					Y:     new(big.Int).SetBytes(ec256y),
				},
				D: new(big.Int).SetBytes(ec256d),
			},
			"",
		}, {
			"CurveP384", &Key{
				Type: KeyTypeEC2,
				Params: map[any]any{
					KeyLabelEC2Curve: CurveP384,
					KeyLabelEC2X:     ec384x,
					KeyLabelEC2Y:     ec384y,
					KeyLabelEC2D:     ec384d,
				},
			},
			&ecdsa.PrivateKey{
				PublicKey: ecdsa.PublicKey{
					Curve: elliptic.P384(),
					X:     new(big.Int).SetBytes(ec384x),
					Y:     new(big.Int).SetBytes(ec384y),
				},
				D: new(big.Int).SetBytes(ec384d),
			},
			"",
		}, {
			"CurveP521", &Key{
				Type: KeyTypeEC2,
				Params: map[any]any{
					KeyLabelEC2Curve: CurveP521,
					KeyLabelEC2X:     ec521x,
					KeyLabelEC2Y:     ec521y,
					KeyLabelEC2D:     ec521d,
				},
			},
			&ecdsa.PrivateKey{
				PublicKey: ecdsa.PublicKey{
					Curve: elliptic.P521(),
					X:     new(big.Int).SetBytes(ec521x),
					Y:     new(big.Int).SetBytes(ec521y),
				},
				D: new(big.Int).SetBytes(ec521d),
			},
			"",
		}, {
			"unknown key type", &Key{
				Type: KeyType(7),
			},
			nil,
			`unexpected key type "unknown key type value 7"`,
		}, {
			"OKP unknown curve", &Key{
				Type: KeyTypeOKP,
				Params: map[any]any{
					KeyLabelOKPCurve: 70,
					KeyLabelOKPX:     okpx,
					KeyLabelOKPD:     okpd,
				},
			},
			nil,
			`unsupported curve "unknown curve value 70" for key type OKP`,
		}, {
			"OKP missing d", &Key{
				Type: KeyTypeOKP,
				Params: map[any]any{
					KeyLabelOKPCurve: CurveEd25519,
					KeyLabelOKPX:     okpx,
				},
			},
			nil,
			ErrNotPrivKey.Error(),
		}, {
			"OKP incorrect x size", &Key{
				Type: KeyTypeOKP,
				Params: map[any]any{
					KeyLabelOKPCurve: CurveEd25519,
					KeyLabelOKPX:     make([]byte, 10),
					KeyLabelOKPD:     okpd,
				},
			},
			nil,
			"invalid key: overflowing coordinate",
		}, {
			"OKP incorrect d size", &Key{
				Type: KeyTypeOKP,
				Params: map[any]any{
					KeyLabelOKPCurve: CurveEd25519,
					KeyLabelOKPX:     okpx,
					KeyLabelOKPD:     make([]byte, 5),
				},
			},
			nil,
			"invalid key: overflowing coordinate",
		}, {
			"EC2 missing D", &Key{
				Type: KeyTypeEC2,
				Params: map[any]any{
					KeyLabelEC2Curve: CurveP256,
					KeyLabelEC2X:     ec256x,
					KeyLabelEC2Y:     ec256y,
				},
			},
			nil,
			ErrNotPrivKey.Error(),
		}, {
			"EC2 unknown curve", &Key{
				Type: KeyTypeEC2,
				Params: map[any]any{
					KeyLabelEC2Curve: 70,
					KeyLabelEC2X:     ec256x,
					KeyLabelEC2Y:     ec256y,
					KeyLabelEC2D:     ec256d,
				},
			},
			nil,
			`unsupported curve "unknown curve value 70" for key type EC2`,
		}, {
			"EC2 incorrect x size", &Key{
				Type: KeyTypeEC2,
				Params: map[any]any{
					KeyLabelEC2Curve: CurveP256,
					KeyLabelEC2X:     ec384x,
					KeyLabelEC2Y:     ec256y,
					KeyLabelEC2D:     ec256d,
				},
			},
			nil,
			"invalid key: overflowing coordinate",
		}, {
			"EC2 incorrect y size", &Key{
				Type: KeyTypeEC2,
				Params: map[any]any{
					KeyLabelEC2Curve: CurveP256,
					KeyLabelEC2X:     ec256x,
					KeyLabelEC2Y:     ec384y,
					KeyLabelEC2D:     ec256d,
				},
			},
			nil,
			"invalid key: overflowing coordinate",
		}, {
			"EC2 incorrect d size", &Key{
				Type: KeyTypeEC2,
				Params: map[any]any{
					KeyLabelEC2Curve: CurveP256,
					KeyLabelEC2X:     ec256x,
					KeyLabelEC2Y:     ec256y,
					KeyLabelEC2D:     ec384d,
				},
			},
			nil,
			"invalid key: overflowing coordinate",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.k.PrivateKey()
			if (err != nil && err.Error() != tt.wantErr) || (err == nil && tt.wantErr != "") {
				t.Errorf("Key.PrivateKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Key.PrivateKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestKey_PublicKey(t *testing.T) {
	ec256x, ec256y, _ := newEC2(t, elliptic.P256())
	ec384x, ec384y, _ := newEC2(t, elliptic.P384())
	ec521x, ec521y, _ := newEC2(t, elliptic.P521())
	okpx, _ := newEd25519(t)
	tests := []struct {
		name    string
		k       *Key
		want    crypto.PublicKey
		wantErr string
	}{
		{
			"CurveEd25519", &Key{
				Type: KeyTypeOKP,
				Params: map[any]any{
					KeyLabelOKPCurve: CurveEd25519,
					KeyLabelOKPX:     okpx,
				},
			},
			ed25519.PublicKey(okpx),
			"",
		}, {
			"CurveP256", &Key{
				Type: KeyTypeEC2,
				Params: map[any]any{
					KeyLabelEC2Curve: CurveP256,
					KeyLabelEC2X:     ec256x,
					KeyLabelEC2Y:     ec256y,
				},
			},
			&ecdsa.PublicKey{
				Curve: elliptic.P256(),
				X:     new(big.Int).SetBytes(ec256x),
				Y:     new(big.Int).SetBytes(ec256y),
			},
			"",
		}, {
			"CurveP384", &Key{
				Type: KeyTypeEC2,
				Params: map[any]any{
					KeyLabelEC2Curve: CurveP384,
					KeyLabelEC2X:     ec384x,
					KeyLabelEC2Y:     ec384y,
				},
			},
			&ecdsa.PublicKey{
				Curve: elliptic.P384(),
				X:     new(big.Int).SetBytes(ec384x),
				Y:     new(big.Int).SetBytes(ec384y),
			},
			"",
		}, {
			"CurveP521", &Key{
				Type: KeyTypeEC2,
				Params: map[any]any{
					KeyLabelEC2Curve: CurveP521,
					KeyLabelEC2X:     ec521x,
					KeyLabelEC2Y:     ec521y,
				},
			},
			&ecdsa.PublicKey{
				Curve: elliptic.P521(),
				X:     new(big.Int).SetBytes(ec521x),
				Y:     new(big.Int).SetBytes(ec521y),
			},
			"",
		}, {
			"unknown key type", &Key{
				Type: KeyType(7),
			},
			nil,
			`unexpected key type "unknown key type value 7"`,
		}, {
			"invalid key type", &Key{
				Type: KeyTypeReserved,
			},
			nil,
			`invalid key: kty value 0`,
		}, {
			"OKP missing X", &Key{
				Type: KeyTypeOKP,
				Params: map[any]any{
					KeyLabelOKPCurve: CurveEd25519,
				},
			},
			nil,
			ErrOKPNoPub.Error(),
		}, {
			"OKP unknown curve", &Key{
				Type: KeyTypeOKP,
				Params: map[any]any{
					KeyLabelOKPCurve: 70,
					KeyLabelOKPX:     okpx,
				},
			},
			nil,
			`unsupported curve "unknown curve value 70" for key type OKP`,
		}, {
			"EC2 missing X", &Key{
				Type: KeyTypeEC2,
				Params: map[any]any{
					KeyLabelEC2Curve: CurveP256,
					KeyLabelEC2Y:     ec256y,
				},
			},
			nil,
			ErrEC2NoPub.Error(),
		}, {
			"EC2 missing Y", &Key{
				Type: KeyTypeEC2,
				Params: map[any]any{
					KeyLabelEC2Curve: CurveP256,
					KeyLabelEC2X:     ec256x,
				},
			},
			nil,
			ErrEC2NoPub.Error(),
		}, {
			"EC2 unknown curve", &Key{
				Type: KeyTypeEC2,
				Params: map[any]any{
					KeyLabelEC2Curve: 70,
					KeyLabelEC2X:     ec256x,
					KeyLabelEC2Y:     ec256y,
				},
			},
			nil,
			`unsupported curve "unknown curve value 70" for key type EC2`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.k.PublicKey()
			if (err != nil && err.Error() != tt.wantErr) || (err == nil && tt.wantErr != "") {
				t.Errorf("Key.PublicKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Key.PublicKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestKeyType_String(t *testing.T) {
	tests := []struct {
		kt   KeyType
		want string
	}{
		{KeyTypeReserved, "Reserved"},
		{KeyTypeOKP, "OKP"},
		{KeyTypeEC2, "EC2"},
		{KeyTypeSymmetric, "Symmetric"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.kt.String(); got != tt.want {
				t.Errorf("KeyType.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCurve_String(t *testing.T) {
	tests := []struct {
		kt   Curve
		want string
	}{
		{CurveP256, "P-256"},
		{CurveP384, "P-384"},
		{CurveP521, "P-521"},
		{CurveX25519, "X25519"},
		{CurveX448, "X448"},
		{CurveEd25519, "Ed25519"},
		{CurveEd448, "Ed448"},
		{CurveReserved, "Reserved"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.kt.String(); got != tt.want {
				t.Errorf("Curve.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestKeyOpFromString(t *testing.T) {
	tests := []struct {
		val   string
		want  KeyOp
		want1 bool
	}{
		{"sign", KeyOpSign, true},
		{"verify", KeyOpVerify, true},
		{"encrypt", KeyOpEncrypt, true},
		{"decrypt", KeyOpDecrypt, true},
		{"wrapKey", KeyOpWrapKey, true},
		{"unwrapKey", KeyOpUnwrapKey, true},
		{"deriveKey", KeyOpDeriveKey, true},
		{"deriveBits", KeyOpDeriveBits, true},
		{"", KeyOp(0), false},
		{"foo", KeyOp(0), false},
	}
	for _, tt := range tests {
		t.Run(tt.val, func(t *testing.T) {
			got, got1 := KeyOpFromString(tt.val)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("KeyOpFromString() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("KeyOpFromString() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func mustHexToBytes(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func newEd25519(t *testing.T) (x, d []byte) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv[:32]
}

func newEC2(t *testing.T, crv elliptic.Curve) (x, y, d []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(crv, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv.X.Bytes(), priv.Y.Bytes(), priv.D.Bytes()
}
