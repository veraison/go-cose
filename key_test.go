package cose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"reflect"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

func Test_KeyOp(t *testing.T) {

	tvs := []struct {
		Name  string
		Value KeyOp
	}{
		{"sign", KeyOpSign},
		{"verify", KeyOpVerify},
		{"encrypt", KeyOpEncrypt},
		{"decrypt", KeyOpDecrypt},
		{"wrapKey", KeyOpWrapKey},
		{"unwrapKey", KeyOpUnwrapKey},
		{"deriveKey", KeyOpDeriveKey},
		{"deriveBits", KeyOpDeriveBits},
	}

	for _, tv := range tvs {
		if tv.Name != tv.Value.String() {
			t.Errorf(
				"String value mismatch: expected %q, got %q",
				tv.Name,
				tv.Value.String(),
			)
		}

		data, err := cbor.Marshal(tv.Name)
		if err != nil {
			t.Errorf("Unexpected error: %s", err)
			return
		}

		var ko KeyOp
		err = cbor.Unmarshal(data, &ko)
		if err != nil {
			t.Errorf("Unexpected error: %s", err)
			return
		}
		if tv.Value != ko {
			t.Errorf(
				"Value mismatch: want %v, got %v",
				tv.Value,
				ko,
			)
		}

		data, err = cbor.Marshal(int(tv.Value))
		if err != nil {
			t.Errorf("Unexpected error: %q", err)
			return
		}

		err = cbor.Unmarshal(data, &ko)
		if err != nil {
			t.Errorf("Unexpected error: %q", err)
			return
		}
		if tv.Value != ko {
			t.Errorf(
				"Value mismatch: want %v, got %v",
				tv.Value,
				ko,
			)
		}
	}

	var ko KeyOp

	data := []byte{0x63, 0x66, 0x6f, 0x6f}
	err := ko.UnmarshalCBOR(data)
	assertEqualError(t, err, `unknown key_ops value "foo"`)

	data = []byte{0x40}
	err = ko.UnmarshalCBOR(data)
	assertEqualError(t, err, "invalid key_ops value must be int or string, found []uint8")

	if KeyOpMACCreate.String() != "MAC create" {
		t.Errorf("Unexpected value: %q", KeyOpMACCreate.String())
	}

	if KeyOpMACVerify.String() != "MAC verify" {
		t.Errorf("Unexpected value: %q", KeyOpMACVerify.String())
	}

	if KeyOp(42).String() != "unknown key_op value 42" {
		t.Errorf("Unexpected value: %q", KeyOp(42).String())
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
			name: "ok OKP",
			data: []byte{
				0xa5,       // map (5)
				0x01, 0x01, // kty: OKP
				0x03, 0x27, //  alg: EdDSA w/ Ed25519
				0x04,       // key ops
				0x81,       // array (1)
				0x02,       // verify
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
				KeyOps:    []KeyOp{KeyOpVerify},
				Curve:     CurveEd25519,
				X: []byte{
					0x15, 0x52, 0x2e, 0xf1, 0x57, 0x29, 0xcc, 0xf3,
					0x95, 0x09, 0xea, 0x5c, 0x15, 0xa2, 0x6b, 0xe9,
					0x49, 0xe3, 0x88, 0x07, 0xa5, 0xc2, 0x6e, 0xf9,
					0x28, 0x14, 0x87, 0xef, 0x4a, 0xe6, 0x7b, 0x46,
				},
			},
			wantErr: "",
		},
		{
			name: "invalid key type",
			data: []byte{
				0xa1,       // map (2)
				0x01, 0x00, // kty: invalid
			},
			want:    nil,
			wantErr: "invalid key type value 0",
		},
		{
			name: "missing curve OKP",
			data: []byte{
				0xa1,       // map (2)
				0x01, 0x01, // kty: OKP
			},
			want:    nil,
			wantErr: "missing Curve parameter (required for OKP key type)",
		},
		{
			name: "missing curve EC2",
			data: []byte{
				0xa1,       // map (2)
				0x01, 0x02, // kty: EC2
			},
			want:    nil,
			wantErr: "missing Curve parameter (required for EC2 key type)",
		},
		{
			name: "invalid curve OKP",
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
		},
		{
			name: "invalid curve EC2",
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
		},
		{
			name: "ok Symmetric",
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
				K: []byte{
					0x15, 0x52, 0x2e, 0xf1, 0x57, 0x29, 0xcc, 0xf3,
					0x95, 0x09, 0xea, 0x5c, 0x15, 0xa2, 0x6b, 0xe9,
					0x49, 0xe3, 0x88, 0x07, 0xa5, 0xc2, 0x6e, 0xf9,
					0x28, 0x14, 0x87, 0xef, 0x4a, 0xe6, 0x7b, 0x46,
				},
			},
			wantErr: "",
		},
		{
			name: "missing K",
			data: []byte{
				0xa1,       // map (1)
				0x01, 0x04, // kty: Symmetric
			},
			want:    nil,
			wantErr: "missing K parameter (required for Symmetric key type)",
		},
		{
			name: "wrong algorithm",
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
			name: "OKP",
			key: &Key{
				KeyType: KeyTypeOKP,
				KeyOps:  []KeyOp{KeyOpVerify, KeyOpEncrypt},
				X: []byte{
					0x15, 0x52, 0x2e, 0xf1, 0x57, 0x29, 0xcc, 0xf3,
					0x95, 0x09, 0xea, 0x5c, 0x15, 0xa2, 0x6b, 0xe9,
					0x49, 0xe3, 0x88, 0x07, 0xa5, 0xc2, 0x6e, 0xf9,
					0x28, 0x14, 0x87, 0xef, 0x4a, 0xe6, 0x7b, 0x46,
				},
				Algorithm: AlgorithmEd25519,
				Curve:     CurveEd25519,
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
				K: []byte{
					0x15, 0x52, 0x2e, 0xf1, 0x57, 0x29, 0xcc, 0xf3,
					0x95, 0x09, 0xea, 0x5c, 0x15, 0xa2, 0x6b, 0xe9,
					0x49, 0xe3, 0x88, 0x07, 0xa5, 0xc2, 0x6e, 0xf9,
					0x28, 0x14, 0x87, 0xef, 0x4a, 0xe6, 0x7b, 0x46,
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
			name:    "unknown key type",
			key:     &Key{KeyType: 42},
			want:    nil,
			wantErr: `invalid key type: "unknown key type value 42"`,
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
				Curve:     CurveEd25519,
				X:         x,
				D:         d,
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
				Curve:     CurveP256,
				X:         x,
				Y:         y,
				D:         d,
			},
			wantErr: "",
		}, {
			name: "valid ES384", args: args{AlgorithmES384, x, y, d},
			want: &Key{
				KeyType:   KeyTypeEC2,
				Algorithm: AlgorithmES384,
				Curve:     CurveP384,
				X:         x,
				Y:         y,
				D:         d,
			},
			wantErr: "",
		}, {
			name: "valid ES521", args: args{AlgorithmES512, x, y, d},
			want: &Key{
				KeyType:   KeyTypeEC2,
				Algorithm: AlgorithmES512,
				Curve:     CurveP521,
				X:         x,
				Y:         y,
				D:         d,
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
			"ED25519", func() (crypto.PrivateKey, error) {
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
				Curve:   CurveEd25519,
			},
			AlgorithmEd25519,
			"",
		},
		{
			"OKP-P256",
			&Key{
				KeyType: KeyTypeOKP,
				Curve:   CurveP256,
			},
			AlgorithmInvalid,
			`unsupported curve "P-256" for key type OKP`,
		},
		{
			"EC2-P256",
			&Key{
				KeyType: KeyTypeEC2,
				Curve:   CurveP256,
			},
			AlgorithmES256,
			"",
		},
		{
			"EC2-P384",
			&Key{
				KeyType: KeyTypeEC2,
				Curve:   CurveP384,
			},
			AlgorithmES384,
			"",
		},
		{
			"EC2-P521",
			&Key{
				KeyType: KeyTypeEC2,
				Curve:   CurveP521,
			},
			AlgorithmES512,
			"",
		},
		{
			"EC2-Ed25519",
			&Key{
				KeyType: KeyTypeEC2,
				Curve:   CurveEd25519,
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
				Curve:     CurveP256,
				X:         big.NewInt(1).Bytes(),
				Y:         big.NewInt(2).Bytes(),
				D:         big.NewInt(3).Bytes(),
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
				Algorithm: AlgorithmEd25519, KeyType: KeyTypeOKP, Curve: CurveEd25519,
				X: []byte{4, 5, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				D: []byte{1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
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
				Curve:     CurveP256,
				X:         big.NewInt(1).Bytes(),
				Y:         big.NewInt(2).Bytes(),
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
			&Key{Algorithm: AlgorithmEd25519, KeyType: KeyTypeOKP, Curve: CurveEd25519, X: []byte{1, 2, 3}},
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
				Curve:   CurveEd25519,
				X:       x,
				D:       d,
			},
			AlgorithmEd25519,
			"",
		},
		{
			"without key_ops", &Key{
				KeyType:   KeyTypeOKP,
				Algorithm: AlgorithmEd25519,
				Curve:     CurveEd25519,
				X:         x,
				D:         d,
			},
			AlgorithmEd25519,
			"",
		},
		{
			"invalid algorithm", &Key{
				KeyType: KeyTypeOKP,
				Curve:   CurveP256,
				X:       x,
				D:       d,
			},
			AlgorithmInvalid,
			`Key type mismatch for curve "P-256" (must be EC2, found OKP)`,
		},
		{
			"can't sign", &Key{
				KeyType: KeyTypeOKP,
				Curve:   CurveEd25519,
				KeyOps:  []KeyOp{KeyOpVerify},
				X:       x,
				D:       d,
			},
			AlgorithmInvalid,
			ErrOpNotSupported.Error(),
		},
		{
			"unsupported key", &Key{
				KeyType: KeyTypeSymmetric,
				KeyOps:  []KeyOp{KeyOpSign},
				K:       x,
				D:       d,
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
				Curve:   CurveEd25519,
				X:       x,
			},
			AlgorithmEd25519,
			"",
		},
		{
			"without key_ops", &Key{
				KeyType:   KeyTypeOKP,
				Algorithm: AlgorithmEd25519,
				Curve:     CurveEd25519,
				X:         x,
			},
			AlgorithmEd25519,
			"",
		},
		{
			"invalid algorithm", &Key{
				KeyType: KeyTypeOKP,
				Curve:   CurveP256,
				X:       x,
			},
			AlgorithmInvalid,
			`Key type mismatch for curve "P-256" (must be EC2, found OKP)`,
		},
		{
			"can't verify", &Key{
				KeyType: KeyTypeOKP,
				Curve:   CurveEd25519,
				KeyOps:  []KeyOp{KeyOpSign},
				X:       x,
			},
			AlgorithmInvalid,
			ErrOpNotSupported.Error(),
		},
		{
			"unsupported key", &Key{
				KeyType: KeyTypeSymmetric,
				KeyOps:  []KeyOp{KeyOpVerify},
				K:       x,
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
				Curve:   CurveEd25519,
				X:       x,
				D:       d,
			},
			ed25519.PrivateKey{
				d[0], d[1], d[2], d[3], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				x[0], x[1], x[2], x[3], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			},
			"",
		}, {
			"CurveP256", &Key{
				KeyType: KeyTypeEC2,
				Curve:   CurveP256,
				X:       x,
				Y:       y,
				D:       d,
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
				Curve:   CurveP384,
				X:       x,
				Y:       y,
				D:       d,
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
				Curve:   CurveP521,
				X:       x,
				Y:       y,
				D:       d,
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
				Curve:   CurveEd25519,
				D:       d,
			},
			nil,
			ErrOKPNoPub.Error(),
		}, {
			"OKP missing D", &Key{
				KeyType: KeyTypeOKP,
				Curve:   CurveEd25519,
				X:       x,
			},
			nil,
			ErrNotPrivKey.Error(),
		}, {
			"OKP unknown curve", &Key{
				KeyType: KeyTypeOKP,
				Curve:   70,
				X:       x,
				D:       d,
			},
			nil,
			`unsupported curve "unknown curve value 70" for key type OKP`,
		}, {
			"EC2 missing X", &Key{
				KeyType: KeyTypeEC2,
				Curve:   CurveP256,
				Y:       y,
				D:       d,
			},
			nil,
			ErrEC2NoPub.Error(),
		}, {
			"EC2 missing Y", &Key{
				KeyType: KeyTypeEC2,
				Curve:   CurveP256,
				X:       x,
				D:       d,
			},
			nil,
			ErrEC2NoPub.Error(),
		}, {
			"EC2 missing D", &Key{
				KeyType: KeyTypeEC2,
				Curve:   CurveP256,
				X:       x,
				Y:       y,
			},
			nil,
			ErrNotPrivKey.Error(),
		}, {
			"EC2 unknown curve", &Key{
				KeyType: KeyTypeEC2,
				Curve:   70,
				X:       x,
				Y:       y,
				D:       d,
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
				Curve:   CurveEd25519,
				X:       x,
			},
			ed25519.PublicKey(x),
			"",
		}, {
			"CurveP256", &Key{
				KeyType: KeyTypeEC2,
				Curve:   CurveP256,
				X:       x,
				Y:       y,
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
				Curve:   CurveP384,
				X:       x,
				Y:       y,
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
				Curve:   CurveP521,
				X:       x,
				Y:       y,
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
				Curve:   CurveEd25519,
			},
			nil,
			ErrOKPNoPub.Error(),
		}, {
			"OKP unknown curve", &Key{
				KeyType: KeyTypeOKP,
				Curve:   70,
				X:       x,
				Y:       y,
			},
			nil,
			`unsupported curve "unknown curve value 70" for key type OKP`,
		}, {
			"EC2 missing X", &Key{
				KeyType: KeyTypeEC2,
				Curve:   CurveP256,
				Y:       y,
			},
			nil,
			ErrEC2NoPub.Error(),
		}, {
			"EC2 missing Y", &Key{
				KeyType: KeyTypeEC2,
				Curve:   CurveP256,
				X:       x,
			},
			nil,
			ErrEC2NoPub.Error(),
		}, {
			"EC2 unknown curve", &Key{
				KeyType: KeyTypeEC2,
				Curve:   70,
				X:       x,
				Y:       y,
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
	// test string conversions not exercised by other test cases
	tests := []struct {
		kt   Curve
		want string
	}{
		{CurveX25519, "X25519"},
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
