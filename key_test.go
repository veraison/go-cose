package cose

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
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

func Test_Key_UnmarshalCBOR(t *testing.T) {
	tvs := []struct {
		Name     string
		Value    []byte
		WantErr  string
		Validate func(k *Key)
	}{
		{
			Name: "ok OKP",
			Value: []byte{
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
			WantErr: "",
			Validate: func(k *Key) {
				assertEqual(t, KeyTypeOKP, k.KeyType)
				assertEqual(t, AlgorithmEd25519, k.Algorithm)
				assertEqual(t, CurveEd25519, k.Curve)
				assertEqual(t, []KeyOp{KeyOpVerify}, k.KeyOps)
				assertEqual(t, []byte{
					0x15, 0x52, 0x2e, 0xf1, 0x57, 0x29, 0xcc, 0xf3,
					0x95, 0x09, 0xea, 0x5c, 0x15, 0xa2, 0x6b, 0xe9,
					0x49, 0xe3, 0x88, 0x07, 0xa5, 0xc2, 0x6e, 0xf9,
					0x28, 0x14, 0x87, 0xef, 0x4a, 0xe6, 0x7b, 0x46,
				},
					k.X,
				)
				assertEqual(t, []byte(nil), k.K)
			},
		},
		{
			Name: "invalid key type",
			Value: []byte{
				0xa1,       // map (2)
				0x01, 0x00, // kty: invalid
			},
			WantErr:  "invalid key type value 0",
			Validate: nil,
		},
		{
			Name: "missing curve OKP",
			Value: []byte{
				0xa1,       // map (2)
				0x01, 0x01, // kty: OKP
			},
			WantErr:  "missing Curve parameter (required for OKP key type)",
			Validate: nil,
		},
		{
			Name: "missing curve EC2",
			Value: []byte{
				0xa1,       // map (2)
				0x01, 0x02, // kty: EC2
			},
			WantErr:  "missing Curve parameter (required for EC2 key type)",
			Validate: nil,
		},
		{
			Name: "invalid curve OKP",
			Value: []byte{
				0xa3,       // map (3)
				0x01, 0x01, // kty: OKP
				0x20, 0x01, // curve: CurveP256
				0x21, 0x58, 0x20, //  x-coordinate: bytes(32)
				0x15, 0x52, 0x2e, 0xf1, 0x57, 0x29, 0xcc, 0xf3, // 32-byte value
				0x95, 0x09, 0xea, 0x5c, 0x15, 0xa2, 0x6b, 0xe9,
				0x49, 0xe3, 0x88, 0x07, 0xa5, 0xc2, 0x6e, 0xf9,
				0x28, 0x14, 0x87, 0xef, 0x4a, 0xe6, 0x7b, 0x46,
			},
			WantErr:  `Key type mismatch for curve "P-256" (must be EC2, found OKP)`,
			Validate: nil,
		},
		{
			Name: "invalid curve EC2",
			Value: []byte{
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
			WantErr:  `Key type mismatch for curve "Ed25519" (must be OKP, found EC2)`,
			Validate: nil,
		},
		{
			Name: "ok Symmetric",
			Value: []byte{
				0xa4,       // map (4)
				0x01, 0x04, // kty: Symmetric
				0x03, 0x38, 0x24, //  alg: PS256
				0x04,             // key ops
				0x81,             // array (1)
				0x02,             // verify
				0x20, 0x58, 0x20, //  k: bytes(32)
				0x15, 0x52, 0x2e, 0xf1, 0x57, 0x29, 0xcc, 0xf3, // 32-byte value
				0x95, 0x09, 0xea, 0x5c, 0x15, 0xa2, 0x6b, 0xe9,
				0x49, 0xe3, 0x88, 0x07, 0xa5, 0xc2, 0x6e, 0xf9,
				0x28, 0x14, 0x87, 0xef, 0x4a, 0xe6, 0x7b, 0x46,
			},
			WantErr: "",
			Validate: func(k *Key) {
				assertEqual(t, KeyTypeSymmetric, k.KeyType)
				assertEqual(t, AlgorithmPS256, k.Algorithm)
				assertEqual(t, int64(0), int64(k.Curve))
				assertEqual(t, []KeyOp{KeyOpVerify}, k.KeyOps)
				assertEqual(t, []byte{
					0x15, 0x52, 0x2e, 0xf1, 0x57, 0x29, 0xcc, 0xf3,
					0x95, 0x09, 0xea, 0x5c, 0x15, 0xa2, 0x6b, 0xe9,
					0x49, 0xe3, 0x88, 0x07, 0xa5, 0xc2, 0x6e, 0xf9,
					0x28, 0x14, 0x87, 0xef, 0x4a, 0xe6, 0x7b, 0x46,
				},
					k.K,
				)
			},
		},
		{
			Name: "missing K",
			Value: []byte{
				0xa1,       // map (1)
				0x01, 0x04, // kty: Symmetric
			},
			WantErr:  "missing K parameter (required for Symmetric key type)",
			Validate: nil,
		},
		{
			Name: "wrong algorithm",
			Value: []byte{
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
			WantErr:  `found algorithm "ES256" (expected "EdDSA")`,
			Validate: nil,
		},
	}

	for _, tv := range tvs {
		t.Run(tv.Name, func(t *testing.T) {
			var k Key

			err := k.UnmarshalCBOR(tv.Value)
			if tv.WantErr != "" {
				if err == nil || err.Error() != tv.WantErr {
					t.Errorf("Unexpected error: want %q, got %q", tv.WantErr, err)
				}
			} else {
				tv.Validate(&k)
			}
		})
	}
}

func Test_Key_MarshalCBOR(t *testing.T) {
	k := Key{
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
	}

	data, err := k.MarshalCBOR()
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
		return
	}
	expected := []byte{
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
	}
	if !bytes.Equal(expected, data) {
		t.Errorf("Bad marshal: %v", data)
	}

	k = Key{
		KeyType: KeyTypeSymmetric,
		K: []byte{
			0x15, 0x52, 0x2e, 0xf1, 0x57, 0x29, 0xcc, 0xf3,
			0x95, 0x09, 0xea, 0x5c, 0x15, 0xa2, 0x6b, 0xe9,
			0x49, 0xe3, 0x88, 0x07, 0xa5, 0xc2, 0x6e, 0xf9,
			0x28, 0x14, 0x87, 0xef, 0x4a, 0xe6, 0x7b, 0x46,
		},
	}

	data, err = k.MarshalCBOR()
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
		return
	}
	expected = []byte{
		0xa2,       // map (2)
		0x01, 0x04, // kty: Symmetric
		0x20, 0x58, 0x20, //  K: bytes(32)
		0x15, 0x52, 0x2e, 0xf1, 0x57, 0x29, 0xcc, 0xf3, // 32-byte value
		0x95, 0x09, 0xea, 0x5c, 0x15, 0xa2, 0x6b, 0xe9,
		0x49, 0xe3, 0x88, 0x07, 0xa5, 0xc2, 0x6e, 0xf9,
		0x28, 0x14, 0x87, 0xef, 0x4a, 0xe6, 0x7b, 0x46,
	}
	if !bytes.Equal(expected, data) {
		t.Errorf("Bad marshal: %v", data)
	}

	k.KeyType = KeyType(42)
	_, err = k.MarshalCBOR()
	wantErr := `invalid key type: "unknown key type value 42"`
	if err == nil || err.Error() != wantErr {
		t.Errorf("Unexpected error: want %q, got %q", wantErr, err)
	}
}

func Test_Key_Create_and_Validate(t *testing.T) {
	x := []byte{
		0x30, 0xa0, 0x42, 0x4c, 0xd2, 0x1c, 0x29, 0x44,
		0x83, 0x8a, 0x2d, 0x75, 0xc9, 0x2b, 0x37, 0xe7,
		0x6e, 0xa2, 0x0d, 0x9f, 0x00, 0x89, 0x3a, 0x3b,
		0x4e, 0xee, 0x8a, 0x3c, 0x0a, 0xaf, 0xec, 0x3e,
	}

	y := []byte{
		0xe0, 0x4b, 0x65, 0xe9, 0x24, 0x56, 0xd9, 0x88,
		0x8b, 0x52, 0xb3, 0x79, 0xbd, 0xfb, 0xd5, 0x1e,
		0xe8, 0x69, 0xef, 0x1f, 0x0f, 0xc6, 0x5b, 0x66,
		0x59, 0x69, 0x5b, 0x6c, 0xce, 0x08, 0x17, 0x23,
	}

	key, err := NewOKPKey(AlgorithmEd25519, x, nil)
	requireNoError(t, err)
	assertEqual(t, KeyTypeOKP, key.KeyType)
	assertEqual(t, x, key.X)

	_, err = NewOKPKey(AlgorithmES256, x, nil)
	assertEqualError(t, err, `unsupported algorithm "ES256"`)

	_, err = NewEC2Key(AlgorithmEd25519, x, y, nil)
	assertEqualError(t, err, `unsupported algorithm "EdDSA"`)

	key, err = NewEC2Key(AlgorithmES256, x, y, nil)
	requireNoError(t, err)
	assertEqual(t, KeyTypeEC2, key.KeyType)
	assertEqual(t, x, key.X)
	assertEqual(t, y, key.Y)

	key = NewSymmetricKey(x)
	assertEqual(t, x, key.K)

	_, err = NewKeyFromPublic(crypto.PublicKey([]byte{0xde, 0xad, 0xbe, 0xef}))
	assertEqualError(t, err, "invalid public key")

	_, err = NewKeyFromPrivate(crypto.PublicKey([]byte{0xde, 0xad, 0xbe, 0xef}))
	assertEqualError(t, err, "invalid private key")
}

func Test_Key_ed25519_signature_round_trip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	requireNoError(t, err)

	key, err := NewKeyFromPrivate(priv)
	requireNoError(t, err)
	assertEqual(t, AlgorithmEd25519, key.Algorithm)
	assertEqual(t, CurveEd25519, key.Curve)
	assertEqual(t, pub, key.X)
	assertEqual(t, priv[:32], key.D)

	signer, err := key.Signer()
	requireNoError(t, err)

	message := []byte("foo bar")
	sig, err := signer.Sign(rand.Reader, message)
	requireNoError(t, err)

	key, err = NewKeyFromPublic(pub)
	requireNoError(t, err)

	assertEqual(t, AlgorithmEd25519, key.Algorithm)
	assertEqual(t, CurveEd25519, key.Curve)
	assertEqual(t, pub, key.X)

	verifier, err := key.Verifier()
	requireNoError(t, err)

	err = verifier.Verify(message, sig)
	requireNoError(t, err)
}

func Test_Key_ecdsa_signature_round_trip(t *testing.T) {
	for _, tv := range []struct {
		EC        elliptic.Curve
		Curve     Curve
		Algorithm Algorithm
	}{
		{elliptic.P256(), CurveP256, AlgorithmES256},
		{elliptic.P384(), CurveP384, AlgorithmES384},
		{elliptic.P521(), CurveP521, AlgorithmES512},
	} {
		t.Run(tv.Curve.String(), func(t *testing.T) {
			priv, err := ecdsa.GenerateKey(tv.EC, rand.Reader)
			requireNoError(t, err)

			key, err := NewKeyFromPrivate(priv)
			requireNoError(t, err)
			assertEqual(t, tv.Curve, key.Curve)
			assertEqual(t, priv.X.Bytes(), key.X)
			assertEqual(t, priv.Y.Bytes(), key.Y)
			assertEqual(t, priv.D.Bytes(), key.D)

			signer, err := key.Signer()
			requireNoError(t, err)

			message := []byte("foo bar")
			sig, err := signer.Sign(rand.Reader, message)
			requireNoError(t, err)

			pub := priv.Public()

			key, err = NewKeyFromPublic(pub)
			requireNoError(t, err)

			assertEqual(t, tv.Curve, key.Curve)
			assertEqual(t, priv.X.Bytes(), key.X)
			assertEqual(t, priv.Y.Bytes(), key.Y)

			verifier, err := key.Verifier()
			requireNoError(t, err)

			err = verifier.Verify(message, sig)
			requireNoError(t, err)
		})
	}
}

func Test_Key_derive_algorithm(t *testing.T) {
	k := Key{
		KeyType: KeyTypeEC2,
		Curve:   CurveEd25519,
	}

	_, err := k.AlgorithmOrDefault()
	assertEqualError(t, err, `unsupported curve "Ed25519" for key type EC2`)

	k = Key{
		KeyType: KeyTypeOKP,
		Curve:   CurveP256,
	}

	_, err = k.AlgorithmOrDefault()
	assertEqualError(t, err, `unsupported curve "P-256" for key type OKP`)

	k = Key{
		KeyType: KeyTypeOKP,
		Curve:   CurveX448,
	}

	_, err = k.AlgorithmOrDefault()
	assertEqualError(t, err, `unsupported curve "X448" for key type OKP`)

	k = Key{
		KeyType: KeyTypeOKP,
		Curve:   CurveEd25519,
	}

	alg, err := k.AlgorithmOrDefault()
	requireNoError(t, err)
	assertEqual(t, AlgorithmEd25519, alg)
}

func Test_NewKeyFrom(t *testing.T) {
	pub := ecdsa.PublicKey{Curve: *new(elliptic.Curve), X: new(big.Int), Y: new(big.Int)}
	_, err := NewKeyFromPublic(&pub)
	assertEqualError(t, err, "unsupported curve: <nil>")

	priv := ecdsa.PrivateKey{PublicKey: pub, D: new(big.Int)}
	_, err = NewKeyFromPrivate(&priv)
	assertEqualError(t, err, "unsupported curve: <nil>")
}

func Test_algorithmFromEllipticCurve(t *testing.T) {
	alg := algorithmFromEllipticCurve(*new(elliptic.Curve))
	assertEqual(t, alg, AlgorithmInvalid)
}

func Test_Key_signer_validation(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	requireNoError(t, err)

	key, err := NewKeyFromPublic(pub)
	requireNoError(t, err)

	_, err = key.Signer()
	assertEqualError(t, err, ErrNotPrivKey.Error())

	key, err = NewKeyFromPrivate(priv)
	requireNoError(t, err)

	key.KeyType = KeyTypeEC2
	_, err = key.Signer()
	assertEqualError(t, err, `Key type mismatch for curve "Ed25519" (must be OKP, found EC2)`)

	key.Curve = CurveP256
	_, err = key.Signer()
	assertEqualError(t, err, `found algorithm "EdDSA" (expected "ES256")`)

	key.KeyType = KeyTypeOKP
	key.Algorithm = AlgorithmEd25519
	key.Curve = CurveEd25519
	key.KeyOps = []KeyOp{}
	_, err = key.Signer()
	assertEqualError(t, err, ErrOpNotSupported.Error())

	key.KeyOps = []KeyOp{KeyOpSign}
	_, err = key.Signer()
	requireNoError(t, err)

	key.Algorithm = AlgorithmES256
	_, err = key.Signer()
	assertEqualError(t, err, `found algorithm "ES256" (expected "EdDSA")`)

	key.Curve = CurveX448
	_, err = key.Signer()
	assertEqualError(t, err, `unsupported curve "X448" for key type OKP`)
}

func TestKey_Verifier(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	requireNoError(t, err)

	key, err := NewKeyFromPublic(pub)
	requireNoError(t, err)

	_, err = key.Verifier()
	requireNoError(t, err)

	key.KeyType = KeyTypeEC2
	_, err = key.Verifier()
	assertEqualError(t, err, ErrEC2NoPub.Error())

	key.KeyType = KeyTypeOKP
	key.KeyOps = []KeyOp{}
	_, err = key.Verifier()
	assertEqualError(t, err, ErrOpNotSupported.Error())

	key.KeyOps = []KeyOp{KeyOpVerify}
	_, err = key.Verifier()
	requireNoError(t, err)
}

func TestKey_PrivateKey(t *testing.T) {
	x := []byte{0xde, 0xad, 0xbe, 0xef}
	y := []byte{0xef, 0xbe, 0xad, 0xde}
	d := []byte{0xad, 0xde, 0xef, 0xbe}
	tests := []struct {
		name    string
		k       *Key
		want    crypto.PrivateKey
		wantErr error
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
			nil,
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
			nil,
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
			nil,
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
			nil,
		}, {
			"unknown key type", &Key{
				KeyType: KeyType(7),
			},
			nil,
			errors.New(`unexpected key type "unknown key type value 7"`),
		}, {
			"OKP missing X", &Key{
				KeyType: KeyTypeOKP,
				Curve:   CurveEd25519,
				D:       d,
			},
			nil,
			ErrOKPNoPub,
		}, {
			"OKP missing D", &Key{
				KeyType: KeyTypeOKP,
				Curve:   CurveEd25519,
				X:       x,
			},
			nil,
			ErrNotPrivKey,
		}, {
			"OKP unknown curve", &Key{
				KeyType: KeyTypeOKP,
				Curve:   70,
				X:       x,
				D:       d,
			},
			nil,
			errors.New(`unsupported curve "unknown curve value 70" for key type OKP`),
		}, {
			"EC2 missing X", &Key{
				KeyType: KeyTypeEC2,
				Curve:   CurveP256,
				Y:       y,
				D:       d,
			},
			nil,
			ErrEC2NoPub,
		}, {
			"EC2 missing Y", &Key{
				KeyType: KeyTypeEC2,
				Curve:   CurveP256,
				X:       x,
				D:       d,
			},
			nil,
			ErrEC2NoPub,
		}, {
			"EC2 missing D", &Key{
				KeyType: KeyTypeEC2,
				Curve:   CurveP256,
				X:       x,
				Y:       y,
			},
			nil,
			ErrNotPrivKey,
		}, {
			"EC2 unknown curve", &Key{
				KeyType: KeyTypeEC2,
				Curve:   70,
				X:       x,
				Y:       y,
				D:       d,
			},
			nil,
			errors.New(`unsupported curve "unknown curve value 70" for key type EC2`),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.k.PrivateKey()
			if err != nil && err.Error() != tt.wantErr.Error() {
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
		wantErr error
	}{
		{
			"CurveEd25519", &Key{
				KeyType: KeyTypeOKP,
				Curve:   CurveEd25519,
				X:       x,
			},
			ed25519.PublicKey(x),
			nil,
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
			nil,
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
			nil,
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
			nil,
		}, {
			"unknown key type", &Key{
				KeyType: KeyType(7),
			},
			nil,
			errors.New(`unexpected key type "unknown key type value 7"`),
		}, {
			"OKP missing X", &Key{
				KeyType: KeyTypeOKP,
				Curve:   CurveEd25519,
			},
			nil,
			ErrOKPNoPub,
		}, {
			"OKP unknown curve", &Key{
				KeyType: KeyTypeOKP,
				Curve:   70,
				X:       x,
				Y:       y,
			},
			nil,
			errors.New(`unsupported curve "unknown curve value 70" for key type OKP`),
		}, {
			"EC2 missing X", &Key{
				KeyType: KeyTypeEC2,
				Curve:   CurveP256,
				Y:       y,
			},
			nil,
			ErrEC2NoPub,
		}, {
			"EC2 missing Y", &Key{
				KeyType: KeyTypeEC2,
				Curve:   CurveP256,
				X:       x,
			},
			nil,
			ErrEC2NoPub,
		}, {
			"EC2 unknown curve", &Key{
				KeyType: KeyTypeEC2,
				Curve:   70,
				X:       x,
				Y:       y,
			},
			nil,
			errors.New(`unsupported curve "unknown curve value 70" for key type EC2`),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.k.PublicKey()
			if err != nil && err.Error() != tt.wantErr.Error() {
				t.Errorf("Key.PublicKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Key.PublicKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_String(t *testing.T) {
	// test string conversions not exercised by other test cases
	assertEqual(t, "OKP", KeyTypeOKP.String())
	assertEqual(t, "EC2", KeyTypeEC2.String())
	assertEqual(t, "X25519", CurveX25519.String())
	assertEqual(t, "Ed448", CurveEd448.String())
}
