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
	"testing"
)

func TestKeyOp_String(t *testing.T) {
	tests := []struct {
		op   KeyOp
		want string
	}{
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
			wantErr: "key_ops: invalid type: expected []interface{}, got []uint8",
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
			wantErr: ErrInvalidKey.Error(),
		}, {
			name: "EC2 missing curve",
			data: []byte{
				0xa1,       // map (2)
				0x01, 0x02, // kty: EC2
			},
			want:    nil,
			wantErr: ErrInvalidKey.Error(),
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
			wantErr: `Key type mismatch for curve "P-256" (must be EC2, found OKP)`,
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
			wantErr: `Key type mismatch for curve "Ed25519" (must be OKP, found EC2)`,
		}, {
			name: "Symmetric missing K",
			data: []byte{
				0xa1,       // map (1)
				0x01, 0x04, // kty: Symmetric
			},
			want:    nil,
			wantErr: ErrInvalidKey.Error(),
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
				KeyType: -70000,
				Params: map[interface{}]interface{}{
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
				KeyType:   KeyTypeOKP,
				Algorithm: AlgorithmEd25519,
				KeyOps:    []KeyOp{KeyOpVerify, KeyOpSign},
				BaseIV:    []byte{0x03, 0x02, 0x01},
				Params: map[interface{}]interface{}{
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
				KeyType: KeyTypeSymmetric,
				Params: map[interface{}]interface{}{
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
				KeyType: KeyTypeEC2,
				KeyID:   []byte("meriadoc.brandybuck@buckland.example"),
				Params: map[interface{}]interface{}{
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
				KeyType: KeyTypeEC2,
				KeyID:   []byte("bilbo.baggins@hobbiton.example"),
				Params: map[interface{}]interface{}{
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
				KeyType: KeyTypeEC2,
				KeyID:   []byte("meriadoc.brandybuck@buckland.example"),
				Params: map[interface{}]interface{}{
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
				KeyType: KeyTypeEC2,
				KeyID:   []byte("bilbo.baggins@hobbiton.example"),
				Params: map[interface{}]interface{}{
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
				KeyType: KeyTypeSymmetric,
				KeyID:   []byte("our-secret"),
				Params: map[interface{}]interface{}{
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
				KeyType: KeyTypeOKP,
				KeyID:   []byte{1, 2, 3},
			},
			want: []byte{
				0xa2,       // map (2)
				0x01, 0x01, // kty: OKP
				0x02, 0x43, 0x01, 0x02, 0x03, // kid: bytes(3)
			},
		}, {
			name: "OKP with only kty",
			key: &Key{
				KeyType: KeyTypeOKP,
			},
			want: []byte{
				0xa1,       // map (1)
				0x01, 0x01, // kty: OKP
			},
		}, {
			name: "OKP with kty and base_iv",
			key: &Key{
				KeyType: KeyTypeOKP,
				BaseIV:  []byte{3, 2, 1},
			},
			want: []byte{
				0xa2,       // map (2)
				0x01, 0x01, // kty: OKP
				0x05, 0x43, 0x03, 0x02, 0x01, // base_iv: bytes(3)
			},
		}, {
			name: "OKP with kty and alg",
			key: &Key{
				KeyType:   KeyTypeOKP,
				Algorithm: AlgorithmEd25519,
			},
			want: []byte{
				0xa2,       // map (2)
				0x01, 0x01, // kty: OKP
				0x03, 0x27, // alg: EdDSA
			},
		}, {
			name: "OKP with kty and private alg",
			key: &Key{
				KeyType:   KeyTypeOKP,
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
				KeyType: KeyTypeOKP,
				KeyID:   []byte{1, 2, 3},
				KeyOps:  []KeyOp{KeyOpEncrypt, KeyOpDecrypt, -70_000},
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
				KeyType: KeyTypeOKP,
				Params: map[interface{}]interface{}{
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
				KeyType: KeyTypeOKP,
				Params: map[interface{}]interface{}{
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
				KeyType: KeyTypeOKP,
				Params: map[interface{}]interface{}{
					int8(10):  0,
					int32(10): 1,
				},
			},
			wantErr: "duplicate label 10",
		}, {
			name: "OKP with invalid param label",
			key: &Key{
				KeyType: KeyTypeOKP,
				Params: map[interface{}]interface{}{
					int8(10): 0,
					-3.5:     1,
				},
			},
			wantErr: "invalid label type float64",
		}, {
			name: "OKP",
			key: &Key{
				KeyType:   KeyTypeOKP,
				Algorithm: AlgorithmEd25519,
				KeyOps:    []KeyOp{KeyOpVerify, KeyOpEncrypt},
				Params: map[interface{}]interface{}{
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
			name: "Symmetric",
			key: &Key{
				KeyType: KeyTypeSymmetric,
				Params: map[interface{}]interface{}{
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
			key:  &Key{KeyType: 42},
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

func TestNewOKPKey(t *testing.T) {
	x := []byte{
		0x30, 0xa0, 0x42, 0x4c, 0xd2, 0x1c, 0x29, 0x44,
		0x83, 0x8a, 0x2d, 0x75, 0xc9, 0x2b, 0x37, 0xe7,
		0x6e, 0xa2, 0x0d, 0x9f, 0x00, 0x89, 0x3a, 0x3b,
		0x4e, 0xee, 0x8a, 0x3c, 0x0a, 0xaf, 0xec, 0x3e,
	}
	d := []byte{
		0xe0, 0x4b, 0x65, 0xe9, 0x24, 0x56, 0xd9, 0x88,
		0x8b, 0x52, 0xb3, 0x79, 0xbd, 0xfb, 0xd5, 0x1e,
		0xe8, 0x69, 0xef, 0x1f, 0x0f, 0xc6, 0x5b, 0x66,
		0x59, 0x69, 0x5b, 0x6c, 0xce, 0x08, 0x17, 0x23,
	}
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
			name: "valid", args: args{AlgorithmEd25519, x, d},
			want: &Key{
				KeyType:   KeyTypeOKP,
				Algorithm: AlgorithmEd25519,
				Params: map[interface{}]interface{}{
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
			name: "x and d missing", args: args{AlgorithmEd25519, nil, nil},
			want:    nil,
			wantErr: ErrInvalidKey.Error(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewOKPKey(tt.args.alg, tt.args.x, tt.args.d)
			if (err != nil && err.Error() != tt.wantErr) || (err == nil && tt.wantErr != "") {
				t.Errorf("NewOKPKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewOKPKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewEC2Key(t *testing.T) {
	x := []byte{1, 2, 3}
	y := []byte{4, 5, 6}
	d := []byte{7, 8, 9}
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
			name: "valid ES256", args: args{AlgorithmES256, x, y, d},
			want: &Key{
				KeyType:   KeyTypeEC2,
				Algorithm: AlgorithmES256,
				Params: map[interface{}]interface{}{
					KeyLabelEC2Curve: CurveP256,
					KeyLabelEC2X:     x,
					KeyLabelEC2Y:     y,
					KeyLabelEC2D:     d,
				},
			},
			wantErr: "",
		}, {
			name: "valid ES384", args: args{AlgorithmES384, x, y, d},
			want: &Key{
				KeyType:   KeyTypeEC2,
				Algorithm: AlgorithmES384,
				Params: map[interface{}]interface{}{
					KeyLabelEC2Curve: CurveP384,
					KeyLabelEC2X:     x,
					KeyLabelEC2Y:     y,
					KeyLabelEC2D:     d,
				},
			},
			wantErr: "",
		}, {
			name: "valid ES521", args: args{AlgorithmES512, x, y, d},
			want: &Key{
				KeyType:   KeyTypeEC2,
				Algorithm: AlgorithmES512,
				Params: map[interface{}]interface{}{
					KeyLabelEC2Curve: CurveP521,
					KeyLabelEC2X:     x,
					KeyLabelEC2Y:     y,
					KeyLabelEC2D:     d,
				},
			},
			wantErr: "",
		}, {
			name: "invalid alg", args: args{Algorithm(-100), x, y, d},
			want:    nil,
			wantErr: `unsupported algorithm "unknown algorithm value -100"`,
		}, {
			name: "x, y and d missing", args: args{AlgorithmES512, nil, nil, nil},
			want:    nil,
			wantErr: ErrInvalidKey.Error(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewEC2Key(tt.args.alg, tt.args.x, tt.args.y, tt.args.d)
			if (err != nil && err.Error() != tt.wantErr) || (err == nil && tt.wantErr != "") {
				t.Errorf("NewEC2Key() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewEC2Key() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewSymmetricKey(t *testing.T) {
	type args struct {
		k []byte
	}
	tests := []struct {
		name string
		args args
		want *Key
	}{
		{"valid", args{[]byte{1, 2, 3}}, &Key{
			KeyType: KeyTypeSymmetric,
			Params: map[interface{}]interface{}{
				KeyLabelSymmetricK: []byte{1, 2, 3},
			},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewSymmetricKey(tt.args.k); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewSymmetricKey() = %v, want %v", got, tt.want)
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
				KeyType: KeyTypeOKP,
				Params: map[interface{}]interface{}{
					KeyLabelOKPCurve: CurveEd25519,
				},
			},
			AlgorithmEd25519,
			"",
		},
		{
			"OKP-P256",
			&Key{
				KeyType: KeyTypeOKP,
				Params: map[interface{}]interface{}{
					KeyLabelOKPCurve: CurveP256,
				},
			},
			AlgorithmInvalid,
			`unsupported curve "P-256" for key type OKP`,
		},
		{
			"EC2-P256",
			&Key{
				KeyType: KeyTypeEC2,
				Params: map[interface{}]interface{}{
					KeyLabelEC2Curve: CurveP256,
				},
			},
			AlgorithmES256,
			"",
		},
		{
			"EC2-P384",
			&Key{
				KeyType: KeyTypeEC2,
				Params: map[interface{}]interface{}{
					KeyLabelEC2Curve: CurveP384,
				},
			},
			AlgorithmES384,
			"",
		},
		{
			"EC2-P521",
			&Key{
				KeyType: KeyTypeEC2,
				Params: map[interface{}]interface{}{
					KeyLabelEC2Curve: CurveP521,
				},
			},
			AlgorithmES512,
			"",
		},
		{
			"EC2-Ed25519",
			&Key{
				KeyType: KeyTypeEC2,
				Params: map[interface{}]interface{}{
					KeyLabelEC2Curve: CurveEd25519,
				},
			},
			AlgorithmInvalid,
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
	tests := []struct {
		name    string
		k       crypto.PrivateKey
		want    *Key
		wantErr string
	}{
		{
			"ecdsa", &ecdsa.PrivateKey{
				PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: big.NewInt(1), Y: big.NewInt(2)},
				D:         big.NewInt(3),
			}, &Key{
				Algorithm: AlgorithmES256,
				KeyType:   KeyTypeEC2,
				Params: map[interface{}]interface{}{
					KeyLabelEC2Curve: CurveP256,
					KeyLabelEC2X:     big.NewInt(1).Bytes(),
					KeyLabelEC2Y:     big.NewInt(2).Bytes(),
					KeyLabelEC2D:     big.NewInt(3).Bytes(),
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
			"ed25519", ed25519.PrivateKey{
				1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				4, 5, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			},
			&Key{
				Algorithm: AlgorithmEd25519, KeyType: KeyTypeOKP,
				Params: map[interface{}]interface{}{
					KeyLabelOKPCurve: CurveEd25519,
					KeyLabelOKPX:     []byte{4, 5, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
					KeyLabelOKPD:     []byte{1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
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
	tests := []struct {
		name    string
		k       crypto.PublicKey
		want    *Key
		wantErr string
	}{
		{
			"ecdsa", &ecdsa.PublicKey{Curve: elliptic.P256(), X: big.NewInt(1), Y: big.NewInt(2)},
			&Key{
				Algorithm: AlgorithmES256,
				KeyType:   KeyTypeEC2,
				Params: map[interface{}]interface{}{
					KeyLabelEC2Curve: CurveP256,
					KeyLabelEC2X:     big.NewInt(1).Bytes(),
					KeyLabelEC2Y:     big.NewInt(2).Bytes(),
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
			"ed25519", ed25519.PublicKey{1, 2, 3},
			&Key{
				Algorithm: AlgorithmEd25519,
				KeyType:   KeyTypeOKP,
				Params: map[interface{}]interface{}{
					KeyLabelOKPCurve: CurveEd25519,
					KeyLabelOKPX:     []byte{1, 2, 3},
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
	x := []byte{0xde, 0xad, 0xbe, 0xef}
	d := []byte{0xde, 0xad, 0xbe, 0xef}
	tests := []struct {
		name    string
		k       *Key
		wantAlg Algorithm
		wantErr string
	}{
		{
			"without algorithm", &Key{
				KeyType: KeyTypeOKP,
				KeyOps:  []KeyOp{KeyOpSign},
				Params: map[interface{}]interface{}{
					KeyLabelOKPCurve: CurveEd25519,
					KeyLabelOKPX:     x,
					KeyLabelOKPD:     d,
				},
			},
			AlgorithmEd25519,
			"",
		},
		{
			"without key_ops", &Key{
				KeyType:   KeyTypeOKP,
				Algorithm: AlgorithmEd25519,
				Params: map[interface{}]interface{}{
					KeyLabelOKPCurve: CurveEd25519,
					KeyLabelOKPX:     x,
					KeyLabelOKPD:     d,
				},
			},
			AlgorithmEd25519,
			"",
		},
		{
			"invalid algorithm", &Key{
				KeyType: KeyTypeOKP,
				Params: map[interface{}]interface{}{
					KeyLabelOKPCurve: CurveP256,
					KeyLabelOKPX:     x,
					KeyLabelOKPD:     d,
				},
			},
			AlgorithmInvalid,
			`Key type mismatch for curve "P-256" (must be EC2, found OKP)`,
		},
		{
			"can't sign", &Key{
				KeyType: KeyTypeOKP,
				KeyOps:  []KeyOp{KeyOpVerify},
				Params: map[interface{}]interface{}{
					KeyLabelOKPCurve: CurveEd25519,
					KeyLabelOKPX:     x,
					KeyLabelOKPD:     d,
				},
			},
			AlgorithmInvalid,
			ErrOpNotSupported.Error(),
		},
		{
			"unsupported key", &Key{
				KeyType: KeyTypeSymmetric,
				KeyOps:  []KeyOp{KeyOpSign},
				Params: map[interface{}]interface{}{
					KeyLabelSymmetricK: d,
				},
			},
			AlgorithmInvalid,
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
	x := []byte{0xde, 0xad, 0xbe, 0xef}
	tests := []struct {
		name    string
		k       *Key
		wantAlg Algorithm
		wantErr string
	}{
		{
			"without algorithm", &Key{
				KeyType: KeyTypeOKP,
				KeyOps:  []KeyOp{KeyOpVerify},
				Params: map[interface{}]interface{}{
					KeyLabelOKPCurve: CurveEd25519,
					KeyLabelOKPX:     x,
				},
			},
			AlgorithmEd25519,
			"",
		},
		{
			"without key_ops", &Key{
				KeyType:   KeyTypeOKP,
				Algorithm: AlgorithmEd25519,
				Params: map[interface{}]interface{}{
					KeyLabelOKPCurve: CurveEd25519,
					KeyLabelOKPX:     x,
				},
			},
			AlgorithmEd25519,
			"",
		},
		{
			"invalid algorithm", &Key{
				KeyType: KeyTypeOKP,
				Params: map[interface{}]interface{}{
					KeyLabelOKPCurve: CurveP256,
					KeyLabelOKPX:     x,
				},
			},
			AlgorithmInvalid,
			`Key type mismatch for curve "P-256" (must be EC2, found OKP)`,
		},
		{
			"can't verify", &Key{
				KeyType: KeyTypeOKP,
				KeyOps:  []KeyOp{KeyOpSign},
				Params: map[interface{}]interface{}{
					KeyLabelOKPCurve: CurveEd25519,
					KeyLabelOKPX:     x,
				},
			},
			AlgorithmInvalid,
			ErrOpNotSupported.Error(),
		},
		{
			"unsupported key", &Key{
				KeyType: KeyTypeSymmetric,
				KeyOps:  []KeyOp{KeyOpVerify},
				Params: map[interface{}]interface{}{
					KeyLabelSymmetricK: x,
				},
			},
			AlgorithmInvalid,
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
	x := []byte{0xde, 0xad, 0xbe, 0xef}
	y := []byte{0xef, 0xbe, 0xad, 0xde}
	d := []byte{0xad, 0xde, 0xef, 0xbe}
	tests := []struct {
		name    string
		k       *Key
		want    crypto.PrivateKey
		wantErr string
	}{
		{
			"CurveEd25519", &Key{
				KeyType: KeyTypeOKP,
				Params: map[interface{}]interface{}{
					KeyLabelOKPCurve: CurveEd25519,
					KeyLabelOKPX:     x,
					KeyLabelOKPD:     d,
				},
			},
			ed25519.PrivateKey{
				d[0], d[1], d[2], d[3], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				x[0], x[1], x[2], x[3], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			},
			"",
		}, {
			"CurveP256", &Key{
				KeyType: KeyTypeEC2,
				Params: map[interface{}]interface{}{
					KeyLabelEC2Curve: CurveP256,
					KeyLabelEC2X:     x,
					KeyLabelEC2Y:     y,
					KeyLabelEC2D:     d,
				},
			},
			&ecdsa.PrivateKey{
				PublicKey: ecdsa.PublicKey{
					Curve: elliptic.P256(),
					X:     new(big.Int).SetBytes(x),
					Y:     new(big.Int).SetBytes(y),
				},
				D: new(big.Int).SetBytes(d),
			},
			"",
		}, {
			"CurveP384", &Key{
				KeyType: KeyTypeEC2,
				Params: map[interface{}]interface{}{
					KeyLabelEC2Curve: CurveP384,
					KeyLabelEC2X:     x,
					KeyLabelEC2Y:     y,
					KeyLabelEC2D:     d,
				},
			},
			&ecdsa.PrivateKey{
				PublicKey: ecdsa.PublicKey{
					Curve: elliptic.P384(),
					X:     new(big.Int).SetBytes(x),
					Y:     new(big.Int).SetBytes(y),
				},
				D: new(big.Int).SetBytes(d),
			},
			"",
		}, {
			"CurveP521", &Key{
				KeyType: KeyTypeEC2,
				Params: map[interface{}]interface{}{
					KeyLabelEC2Curve: CurveP521,
					KeyLabelEC2X:     x,
					KeyLabelEC2Y:     y,
					KeyLabelEC2D:     d,
				},
			},
			&ecdsa.PrivateKey{
				PublicKey: ecdsa.PublicKey{
					Curve: elliptic.P521(),
					X:     new(big.Int).SetBytes(x),
					Y:     new(big.Int).SetBytes(y),
				},
				D: new(big.Int).SetBytes(d),
			},
			"",
		}, {
			"unknown key type", &Key{
				KeyType: KeyType(7),
			},
			nil,
			`unexpected key type "unknown key type value 7"`,
		}, {
			"OKP missing X", &Key{
				KeyType: KeyTypeOKP,
				Params: map[interface{}]interface{}{
					KeyLabelOKPCurve: CurveEd25519,
					KeyLabelOKPD:     d,
				},
			},
			nil,
			ErrOKPNoPub.Error(),
		}, {
			"OKP missing D", &Key{
				KeyType: KeyTypeOKP,
				Params: map[interface{}]interface{}{
					KeyLabelOKPCurve: CurveEd25519,
					KeyLabelOKPX:     x,
				},
			},
			nil,
			ErrNotPrivKey.Error(),
		}, {
			"OKP unknown curve", &Key{
				KeyType: KeyTypeOKP,
				Params: map[interface{}]interface{}{
					KeyLabelOKPCurve: 70,
					KeyLabelOKPX:     x,
					KeyLabelOKPD:     d,
				},
			},
			nil,
			`unsupported curve "unknown curve value 70" for key type OKP`,
		}, {
			"EC2 missing X", &Key{
				KeyType: KeyTypeEC2,
				Params: map[interface{}]interface{}{
					KeyLabelEC2Curve: CurveP256,
					KeyLabelEC2Y:     y,
					KeyLabelEC2D:     d,
				},
			},
			nil,
			ErrEC2NoPub.Error(),
		}, {
			"EC2 missing Y", &Key{
				KeyType: KeyTypeEC2,
				Params: map[interface{}]interface{}{
					KeyLabelEC2Curve: CurveP256,
					KeyLabelEC2X:     x,
					KeyLabelEC2D:     d,
				},
			},
			nil,
			ErrEC2NoPub.Error(),
		}, {
			"EC2 missing D", &Key{
				KeyType: KeyTypeEC2,
				Params: map[interface{}]interface{}{
					KeyLabelEC2Curve: CurveP256,
					KeyLabelEC2X:     x,
					KeyLabelEC2Y:     y,
				},
			},
			nil,
			ErrNotPrivKey.Error(),
		}, {
			"EC2 unknown curve", &Key{
				KeyType: KeyTypeEC2,
				Params: map[interface{}]interface{}{
					KeyLabelEC2Curve: 70,
					KeyLabelEC2X:     x,
					KeyLabelEC2Y:     y,
					KeyLabelEC2D:     d,
				},
			},
			nil,
			`unsupported curve "unknown curve value 70" for key type EC2`,
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
	x := []byte{0xde, 0xad, 0xbe, 0xef}
	y := []byte{0xef, 0xbe, 0xad, 0xde}
	tests := []struct {
		name    string
		k       *Key
		want    crypto.PublicKey
		wantErr string
	}{
		{
			"CurveEd25519", &Key{
				KeyType: KeyTypeOKP,
				Params: map[interface{}]interface{}{
					KeyLabelOKPCurve: CurveEd25519,
					KeyLabelOKPX:     x,
				},
			},
			ed25519.PublicKey(x),
			"",
		}, {
			"CurveP256", &Key{
				KeyType: KeyTypeEC2,
				Params: map[interface{}]interface{}{
					KeyLabelEC2Curve: CurveP256,
					KeyLabelEC2X:     x,
					KeyLabelEC2Y:     y,
				},
			},
			&ecdsa.PublicKey{
				Curve: elliptic.P256(),
				X:     new(big.Int).SetBytes(x),
				Y:     new(big.Int).SetBytes(y),
			},
			"",
		}, {
			"CurveP384", &Key{
				KeyType: KeyTypeEC2,
				Params: map[interface{}]interface{}{
					KeyLabelEC2Curve: CurveP384,
					KeyLabelEC2X:     x,
					KeyLabelEC2Y:     y,
				},
			},
			&ecdsa.PublicKey{
				Curve: elliptic.P384(),
				X:     new(big.Int).SetBytes(x),
				Y:     new(big.Int).SetBytes(y),
			},
			"",
		}, {
			"CurveP521", &Key{
				KeyType: KeyTypeEC2,
				Params: map[interface{}]interface{}{
					KeyLabelEC2Curve: CurveP521,
					KeyLabelEC2X:     x,
					KeyLabelEC2Y:     y,
				},
			},
			&ecdsa.PublicKey{
				Curve: elliptic.P521(),
				X:     new(big.Int).SetBytes(x),
				Y:     new(big.Int).SetBytes(y),
			},
			"",
		}, {
			"unknown key type", &Key{
				KeyType: KeyType(7),
			},
			nil,
			`unexpected key type "unknown key type value 7"`,
		}, {
			"OKP missing X", &Key{
				KeyType: KeyTypeOKP,
				Params: map[interface{}]interface{}{
					KeyLabelOKPCurve: CurveEd25519,
				},
			},
			nil,
			ErrOKPNoPub.Error(),
		}, {
			"OKP unknown curve", &Key{
				KeyType: KeyTypeOKP,
				Params: map[interface{}]interface{}{
					KeyLabelOKPCurve: 70,
					KeyLabelOKPX:     x,
				},
			},
			nil,
			`unsupported curve "unknown curve value 70" for key type OKP`,
		}, {
			"EC2 missing X", &Key{
				KeyType: KeyTypeEC2,
				Params: map[interface{}]interface{}{
					KeyLabelEC2Curve: CurveP256,
					KeyLabelEC2Y:     y,
				},
			},
			nil,
			ErrEC2NoPub.Error(),
		}, {
			"EC2 missing Y", &Key{
				KeyType: KeyTypeEC2,
				Params: map[interface{}]interface{}{
					KeyLabelEC2Curve: CurveP256,
					KeyLabelEC2X:     x,
				},
			},
			nil,
			ErrEC2NoPub.Error(),
		}, {
			"EC2 unknown curve", &Key{
				KeyType: KeyTypeEC2,
				Params: map[interface{}]interface{}{
					KeyLabelEC2Curve: 70,
					KeyLabelEC2X:     x,
					KeyLabelEC2Y:     y,
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
	// test string conversions not exercised by other test cases
	tests := []struct {
		kt   KeyType
		want string
	}{
		{KeyTypeOKP, "OKP"},
		{KeyTypeEC2, "EC2"},
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
