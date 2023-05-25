package cose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
		{"wrap key", KeyOpWrapKey},
		{"unwrap key", KeyOpUnwrapKey},
		{"derive key", KeyOpDeriveKey},
		{"derive bits", KeyOpDeriveBits},
		{"MAC create", KeyOpMacCreate},
		{"MAC verify", KeyOpMacVerify},
	}

	for _, tv := range tvs {
		assert.Equal(t, tv.Name, tv.Value.String())

		data, err := cbor.Marshal(tv.Name)
		require.NoError(t, err)

		var ko KeyOp
		err = cbor.Unmarshal(data, &ko)
		require.NoError(t, err)
		assert.Equal(t, tv.Value, ko)

		data, err = cbor.Marshal(int(tv.Value))
		require.NoError(t, err)

		err = cbor.Unmarshal(data, &ko)
		require.NoError(t, err)
		assert.Equal(t, tv.Value, ko)

	}

	var ko KeyOp

	data := []byte{0x20}
	err := ko.UnmarshalCBOR(data)
	assert.EqualError(t, err, "unknown key_ops value -1")

	data = []byte{0x18, 0xff}
	err = ko.UnmarshalCBOR(data)
	assert.EqualError(t, err, "unknown key_ops value 255")

	data = []byte{0x63, 0x66, 0x6f, 0x6f}
	err = ko.UnmarshalCBOR(data)
	assert.EqualError(t, err, "unknown key_ops value \"foo\"")

	data = []byte{0x40}
	err = ko.UnmarshalCBOR(data)
	assert.EqualError(t, err, "invalid key_ops value must be int or string, found []uint8")

	assert.Equal(t, "unknown key_op value 42", KeyOp(42).String())
}

func Test_KeyType(t *testing.T) {

	tvs := []struct {
		Name  string
		Value KeyType
	}{
		{"OKP", KeyTypeOkp},
		{"EC2", KeyTypeEc2},
		{"Symmetric", KeyTypeSymmetric},
	}

	for _, tv := range tvs {
		assert.Equal(t, tv.Name, tv.Value.String())

		data, err := cbor.Marshal(tv.Name)
		require.NoError(t, err)

		var ko KeyType
		err = cbor.Unmarshal(data, &ko)
		require.NoError(t, err)
		assert.Equal(t, tv.Value, ko)

		data, err = cbor.Marshal(int(tv.Value))
		require.NoError(t, err)

		err = cbor.Unmarshal(data, &ko)
		require.NoError(t, err)
		assert.Equal(t, tv.Value, ko)

	}

	var ko KeyType

	data := []byte{0x20}
	err := ko.UnmarshalCBOR(data)
	assert.EqualError(t, err, "unknown key type value -1")

	data = []byte{0x00}
	err = ko.UnmarshalCBOR(data)
	assert.EqualError(t, err, "invalid key type value 0")

	data = []byte{0x03}
	err = ko.UnmarshalCBOR(data)
	assert.EqualError(t, err, "unknown key type value 3")

	data = []byte{0x63, 0x66, 0x6f, 0x6f}
	err = ko.UnmarshalCBOR(data)
	assert.EqualError(t, err, "unknown key type value \"foo\"")

	data = []byte{0x40}
	err = ko.UnmarshalCBOR(data)
	assert.EqualError(t, err, "invalid key type value: must be int or string, found []uint8")
}

func Test_Curve(t *testing.T) {

	tvs := []struct {
		Name  string
		Value Curve
	}{
		{"P-256", CurveP256},
		{"P-384", CurveP384},
		{"P-521", CurveP521},
		{"X25519", CurveX25519},
		{"X448", CurveX448},
		{"Ed25519", CurveEd25519},
		{"Ed448", CurveEd448},
	}

	for _, tv := range tvs {
		assert.Equal(t, tv.Name, tv.Value.String())

		data, err := cbor.Marshal(tv.Name)
		require.NoError(t, err)

		var c Curve
		err = cbor.Unmarshal(data, &c)
		require.NoError(t, err)
		assert.Equal(t, tv.Value, c)

		data, err = cbor.Marshal(int(tv.Value))
		require.NoError(t, err)

		err = cbor.Unmarshal(data, &c)
		require.NoError(t, err)
		assert.Equal(t, tv.Value, c)

	}

	var c Curve

	data := []byte{0x20}
	err := c.UnmarshalCBOR(data)
	assert.EqualError(t, err, "unknown curve value -1")

	data = []byte{0x00}
	err = c.UnmarshalCBOR(data)
	assert.EqualError(t, err, "unknown curve value 0")

	data = []byte{0x63, 0x66, 0x6f, 0x6f}
	err = c.UnmarshalCBOR(data)
	assert.EqualError(t, err, "unknown curve value \"foo\"")

	data = []byte{0x40}
	err = c.UnmarshalCBOR(data)
	assert.EqualError(t, err, "invalid curve value: must be int or string, found []uint8")

	assert.Equal(t, "unknown curve value 42", Curve(42).String())
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
				assert.Equal(t, KeyTypeOkp, k.KeyType)
				assert.Equal(t, AlgorithmEd25519, k.Algorithm)
				assert.Equal(t, CurveEd25519, k.Curve)
				assert.Equal(t, []KeyOp{KeyOpVerify}, k.KeyOps)
				assert.Equal(t, []byte{
					0x15, 0x52, 0x2e, 0xf1, 0x57, 0x29, 0xcc, 0xf3,
					0x95, 0x09, 0xea, 0x5c, 0x15, 0xa2, 0x6b, 0xe9,
					0x49, 0xe3, 0x88, 0x07, 0xa5, 0xc2, 0x6e, 0xf9,
					0x28, 0x14, 0x87, 0xef, 0x4a, 0xe6, 0x7b, 0x46,
				},
					k.X,
				)
				assert.Equal(t, []byte(nil), k.K)
			},
		},
		{
			Name: "missing curve",
			Value: []byte{
				0xa1,       // map (2)
				0x01, 0x01, // kty: OKP
			},
			WantErr:  "missing Curve parameter (required for OKP key type)",
			Validate: nil,
		},
		{
			Name: "invalid curve",
			Value: []byte{
				0xa2,       // map (2)
				0x01, 0x01, // kty: OKP
				0x20, 0x01, // curve: CurveP256
			},
			WantErr:  "OKP curve must be X25519, X448, Ed25519, or Ed448; found \"P-256\"",
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
				assert.Equal(t, KeyTypeSymmetric, k.KeyType)
				assert.Equal(t, AlgorithmPS256, k.Algorithm)
				assert.EqualValues(t, 0, k.Curve)
				assert.Equal(t, []KeyOp{KeyOpVerify}, k.KeyOps)
				assert.Equal(t, []byte{
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
			WantErr:  "found algorithm \"ES256\" (expected \"EdDSA\")",
			Validate: nil,
		},
	}

	for _, tv := range tvs {
		t.Run(tv.Name, func(t *testing.T) {
			var k Key

			err := k.UnmarshalCBOR(tv.Value)
			if tv.WantErr != "" {
				assert.EqualError(t, err, tv.WantErr)
			} else {
				tv.Validate(&k)
			}
		})
	}
}

func Test_Key_MarshalCBOR(t *testing.T) {
	k := Key{
		keyStruct: keyStruct{
			KeyType:   KeyTypeOkp,
			Algorithm: AlgorithmEd25519,
			KeyOps:    []KeyOp{KeyOpVerify, KeyOpEncrypt},
			X: []byte{
				0x15, 0x52, 0x2e, 0xf1, 0x57, 0x29, 0xcc, 0xf3,
				0x95, 0x09, 0xea, 0x5c, 0x15, 0xa2, 0x6b, 0xe9,
				0x49, 0xe3, 0x88, 0x07, 0xa5, 0xc2, 0x6e, 0xf9,
				0x28, 0x14, 0x87, 0xef, 0x4a, 0xe6, 0x7b, 0x46,
			},
		},
		Curve: CurveEd25519,
	}

	data, err := k.MarshalCBOR()

	require.NoError(t, err)
	assert.Equal(t,
		[]byte{
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
		data,
	)
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

	key, err := NewOkpKey(CurveEd25519, x, nil)
	require.NoError(t, err)
	assert.Equal(t, KeyTypeOkp, key.KeyType)
	assert.Equal(t, x, key.X)

	_, err = NewEc2Key(CurveEd25519, x, y, nil)
	assert.EqualError(t, err, "EC2 curve must be P-256, P-384, or P-521; found \"Ed25519\"")

	key, err = NewEc2Key(CurveP256, x, y, nil)
	require.NoError(t, err)
	assert.Equal(t, KeyTypeEc2, key.KeyType)
	assert.Equal(t, x, key.X)
	assert.Equal(t, y, key.Y)

	key, err = NewSymmetricKey(x)
	require.NoError(t, err)
	assert.Equal(t, x, key.K)

	key.KeyType = KeyType(7)
	err = key.Validate()
	assert.EqualError(t, err, "unknown key type value 7")

	_, err = NewKeyFromPublic(AlgorithmES256,
		crypto.PublicKey([]byte{0xde, 0xad, 0xbe, 0xef}))
	assert.EqualError(t, err, "ES256: invalid public key")

	_, err = NewKeyFromPublic(AlgorithmEd25519,
		crypto.PublicKey([]byte{0xde, 0xad, 0xbe, 0xef}))
	assert.EqualError(t, err, "EdDSA: invalid public key")

	_, err = NewKeyFromPublic(AlgorithmInvalid,
		crypto.PublicKey([]byte{0xde, 0xad, 0xbe, 0xef}))
	assert.EqualError(t, err, "algorithm not supported")

	_, err = NewKeyFromPrivate(AlgorithmES256,
		crypto.PublicKey([]byte{0xde, 0xad, 0xbe, 0xef}))
	assert.EqualError(t, err, "ES256: invalid private key")

	_, err = NewKeyFromPrivate(AlgorithmEd25519,
		crypto.PublicKey([]byte{0xde, 0xad, 0xbe, 0xef}))
	assert.EqualError(t, err, "EdDSA: invalid private key")

	_, err = NewKeyFromPrivate(AlgorithmInvalid,
		crypto.PublicKey([]byte{0xde, 0xad, 0xbe, 0xef}))
	assert.EqualError(t, err, "algorithm not supported")
}

func Test_Key_ed25519_signature_round_trip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	key, err := NewKeyFromPrivate(AlgorithmEd25519, priv)
	require.NoError(t, err)
	assert.Equal(t, AlgorithmEd25519, key.Algorithm)
	assert.Equal(t, CurveEd25519, key.Curve)
	assert.EqualValues(t, pub, key.X)
	assert.EqualValues(t, priv[:32], key.D)

	signer, err := key.GetSigner()
	require.NoError(t, err)

	message := []byte("foo bar")
	sig, err := signer.Sign(rand.Reader, message)
	require.NoError(t, err)

	key, err = NewKeyFromPublic(AlgorithmEd25519, pub)
	require.NoError(t, err)

	assert.Equal(t, AlgorithmEd25519, key.Algorithm)
	assert.Equal(t, CurveEd25519, key.Curve)
	assert.EqualValues(t, pub, key.X)

	verifier, err := key.GetVerifier()
	require.NoError(t, err)

	err = verifier.Verify(message, sig)
	assert.NoError(t, err)
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
			require.NoError(t, err)

			key, err := NewKeyFromPrivate(tv.Algorithm, priv)
			require.NoError(t, err)
			assert.Equal(t, tv.Algorithm, key.Algorithm)
			assert.Equal(t, tv.Curve, key.Curve)
			assert.EqualValues(t, priv.X.Bytes(), key.X)
			assert.EqualValues(t, priv.Y.Bytes(), key.Y)
			assert.EqualValues(t, priv.D.Bytes(), key.D)

			signer, err := key.GetSigner()
			require.NoError(t, err)

			message := []byte("foo bar")
			sig, err := signer.Sign(rand.Reader, message)
			require.NoError(t, err)

			pub := priv.Public()

			key, err = NewKeyFromPublic(tv.Algorithm, pub)
			require.NoError(t, err)

			assert.Equal(t, tv.Algorithm, key.Algorithm)
			assert.Equal(t, tv.Curve, key.Curve)
			assert.EqualValues(t, priv.X.Bytes(), key.X)
			assert.EqualValues(t, priv.Y.Bytes(), key.Y)

			verifier, err := key.GetVerifier()
			require.NoError(t, err)

			err = verifier.Verify(message, sig)
			assert.NoError(t, err)
		})
	}
}

func Test_Key_derive_algorithm(t *testing.T) {
	k := Key{
		keyStruct: keyStruct{
			KeyType: KeyTypeOkp,
		},
		Curve: CurveX448,
	}

	_, err := k.GetAlgorithm()
	assert.EqualError(t, err, "unsupported curve \"X448\"")

	k = Key{
		keyStruct: keyStruct{
			KeyType: KeyTypeOkp,
		},
		Curve: CurveEd25519,
	}

	alg, err := k.GetAlgorithm()
	require.NoError(t, err)
	assert.Equal(t, AlgorithmEd25519, alg)
}
