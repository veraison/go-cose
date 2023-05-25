package cose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"errors"
	"fmt"
	"math/big"
	"strconv"

	cbor "github.com/fxamacker/cbor/v2"
)

const (
	// An inviald key_op value
	KeyOpInvalid KeyOp = -1

	// The key is used to create signatures. Requires private key fields.
	KeyOpSign KeyOp = 1

	// The key is used for verification of signatures.
	KeyOpVerify KeyOp = 2

	// The key is used for key transport encryption.
	KeyOpEncrypt KeyOp = 3

	// The key is used for key transport decryption. Requires private key fields.
	KeyOpDecrypt KeyOp = 4

	// The key is used for key wrap encryption.
	KeyOpWrapKey KeyOp = 5

	// The key is used for key wrap decryption.
	KeyOpUnwrapKey KeyOp = 6

	// The key is used for deriving keys. Requires private key fields.
	KeyOpDeriveKey KeyOp = 7

	// The key is used for deriving bits not to be used as a key. Requires
	// private key fields.
	KeyOpDeriveBits KeyOp = 8

	// The key is used for creating MACs.
	KeyOpMacCreate KeyOp = 9

	// The key is used for validating MACs.
	KeyOpMacVerify KeyOp = 10
)

// KeyOp represents a key_ops value used to restrict purposes for which a Key
// may be used.
type KeyOp int64

// KeyOpFromString returns the KeyOp corresponding to the specified name.
func KeyOpFromString(val string) KeyOp {
	switch val {
	case "sign":
		return KeyOpSign
	case "verify":
		return KeyOpVerify
	case "encrypt":
		return KeyOpEncrypt
	case "decrypt":
		return KeyOpDecrypt
	case "wrap key":
		return KeyOpWrapKey
	case "unwrap key":
		return KeyOpUnwrapKey
	case "derive key":
		return KeyOpDeriveKey
	case "derive bits":
		return KeyOpDeriveBits
	case "MAC create":
		return KeyOpMacCreate
	case "MAC verify":
		return KeyOpMacVerify
	default:
		return KeyOpInvalid
	}
}

func (ko KeyOp) String() string {
	switch ko {
	case KeyOpSign:
		return "sign"
	case KeyOpVerify:
		return "verify"
	case KeyOpEncrypt:
		return "encrypt"
	case KeyOpDecrypt:
		return "decrypt"
	case KeyOpWrapKey:
		return "wrap key"
	case KeyOpUnwrapKey:
		return "unwrap key"
	case KeyOpDeriveKey:
		return "derive key"
	case KeyOpDeriveBits:
		return "derive bits"
	case KeyOpMacCreate:
		return "MAC create"
	case KeyOpMacVerify:
		return "MAC verify"
	default:
		return "unknown key_op value " + strconv.Itoa(int(ko))
	}
}

func (ko KeyOp) IsSupported() bool {
	return ko >= 1 && ko <= 10
}

// MarshalCBOR marshals the KeyOp as a CBOR int.
func (ko KeyOp) MarshalCBOR() ([]byte, error) {
	return encMode.Marshal(int64(ko))
}

// UnmarshalCBOR populates the KeyOp from the provided CBOR value (must be int
// or tstr).
func (ko *KeyOp) UnmarshalCBOR(data []byte) error {
	var raw intOrStr

	if err := raw.UnmarshalCBOR(data); err != nil {
		return fmt.Errorf("invalid key_ops value %w", err)
	}

	if raw.IsString() {
		v := KeyOpFromString(raw.String())
		if v == KeyOpInvalid {
			return fmt.Errorf("unknown key_ops value %q", raw.String())
		}

		*ko = v
	} else {
		v := raw.Int()
		*ko = KeyOp(v)

		if !ko.IsSupported() {
			return fmt.Errorf("unknown key_ops value %d", v)
		}
	}

	return nil
}

const (
	// Octet Key Pair
	KeyTypeOkp KeyType = 1
	// Elliptic Curve Keys w/ x- and y-coordinate pair
	KeyTypeEc2 KeyType = 2
	// Symmetric Keys
	KeyTypeSymmetric KeyType = 4
)

type KeyType int64

// KeyTypeFromString returns the KeyType corresponding to the specified name.
func KeyTypeFromString(v string) (KeyType, error) {
	switch v {
	case "OKP":
		return KeyTypeOkp, nil
	case "EC2":
		return KeyTypeEc2, nil
	case "Symmetric":
		return KeyTypeSymmetric, nil
	default:
		return KeyType(0), fmt.Errorf("unknown key type value %q", v)
	}
}

func (kt KeyType) String() string {
	switch kt {
	case KeyTypeOkp:
		return "OKP"
	case KeyTypeEc2:
		return "EC2"
	case KeyTypeSymmetric:
		return "Symmetric"
	default:
		return "unknown key type value " + strconv.Itoa(int(kt))
	}
}

// MarshalCBOR marshals the KeyType as a CBOR int.
func (kt KeyType) MarshalCBOR() ([]byte, error) {
	return encMode.Marshal(int(kt))
}

// UnmarshalCBOR populates the KeyType form the provided CBOR value (must be
// int or tstr).
func (kt *KeyType) UnmarshalCBOR(data []byte) error {
	var raw intOrStr

	if err := raw.UnmarshalCBOR(data); err != nil {
		return fmt.Errorf("invalid key type value: %w", err)
	}

	if raw.IsString() {
		v, err := KeyTypeFromString(raw.String())

		if err != nil {
			return err
		}

		*kt = v
	} else {
		v := raw.Int()

		if v == 0 {
			// 0  is reserved, and so can never be valid
			return fmt.Errorf("invalid key type value 0")
		}

		if v > 4 || v < 0 || v == 3 {
			return fmt.Errorf("unknown key type value %d", v)
		}

		*kt = KeyType(v)
	}

	return nil
}

const (

	// Invalid/unrecognised curve
	CurveInvalid Curve = 0

	// NIST P-256 also known as secp256r1
	CurveP256 Curve = 1

	// NIST P-384 also known as secp384r1
	CurveP384 Curve = 2

	// NIST P-521 also known as secp521r1
	CurveP521 Curve = 3

	// X25519 for use w/ ECDH only
	CurveX25519 Curve = 4

	// X448 for use w/ ECDH only
	CurveX448 Curve = 5

	// Ed25519 for use /w EdDSA only
	CurveEd25519 Curve = 6

	// Ed448 for use /w EdDSA only
	CurveEd448 Curve = 7
)

// Curve reprsents the EC2/OKP key's curve. See:
// https://datatracker.ietf.org/doc/html/rfc8152#section-13.1
type Curve int64

func CurveFromString(v string) (Curve, error) {
	switch v {
	case "P-256":
		return CurveP256, nil
	case "P-384":
		return CurveP384, nil
	case "P-521":
		return CurveP521, nil
	case "X25519":
		return CurveX25519, nil
	case "X448":
		return CurveX448, nil
	case "Ed25519":
		return CurveEd25519, nil
	case "Ed448":
		return CurveEd448, nil
	default:
		return CurveInvalid, fmt.Errorf("unknown curve value %q", v)
	}
}

func (c Curve) String() string {
	switch c {
	case CurveP256:
		return "P-256"
	case CurveP384:
		return "P-384"
	case CurveP521:
		return "P-521"
	case CurveX25519:
		return "X25519"
	case CurveX448:
		return "X448"
	case CurveEd25519:
		return "Ed25519"
	case CurveEd448:
		return "Ed448"
	default:
		return "unknown curve value " + strconv.Itoa(int(c))
	}
}

// MarshalCBOR marshals the KeyType as a CBOR int.
func (c Curve) MarshalCBOR() ([]byte, error) {
	return encMode.Marshal(int(c))
}

// UnmarshalCBOR populates the KeyType form the provided CBOR value (must be
// int or tstr).
func (c *Curve) UnmarshalCBOR(data []byte) error {
	var raw intOrStr

	if err := raw.UnmarshalCBOR(data); err != nil {
		return fmt.Errorf("invalid curve value: %w", err)
	}

	if raw.IsString() {
		v, err := CurveFromString(raw.String())

		if err != nil {
			return err
		}

		*c = v
	} else {
		v := raw.Int()

		if v < 1 || v > 7 {
			return fmt.Errorf("unknown curve value %d", v)
		}

		*c = Curve(v)
	}

	return nil
}

// Key represents a COSE_Key structure, as defined by RFC8152.
// Note: currently, this does NOT support RFC8230 (RSA algorithms).
type Key struct {
	keyStruct
	// Curve is EC identifier -- taken form "COSE Elliptic Curves" IANA registry.
	// Populated from keyStruct.RawKeyParam when key type is EC2 or OKP.
	Curve Curve
	// K is the key value. Populated from keyStruct.RawKeyParam when key
	// type is Symmetric.
	K []byte
}

// keyStruct embedded inside Key to enable two-tier unmarshalling, of KeyType
// and parameter with label -1 (Curve or K, depending on key type).
type keyStruct struct {
	// Common parameters. These are independent of the key type. Only
	// KeyType common parameter MUST be set.

	// KeyType identifies the family of keys for this structure, and thus,
	// which of the key-type-specific parameters need to be set.
	KeyType KeyType `cbor:"1,keyasint" json:"kty"`
	// KeyId is the identification value matched to the kid in the message.
	KeyId []byte `cbor:"2,keyasint,omitempty" json:"kid,omitempty"`
	// Algorithm is used to restrict the algorithm that is used with the
	// key. If it is set, the application MUST verify that it matches the
	// algorithm for which the Key is being used.
	Algorithm Algorithm `cbor:"3,keyasint,omitempty" json:"alg,omitempty"`
	// KeyOps can be set to restrict the set of operations that the Key is used for.
	KeyOps []KeyOp `cbor:"4,keyasint,omitempty" json:"key_ops,omitempty"`
	// BaseIv is the Base IV to be xor-ed with Partial IVs.
	BaseIv []byte `cbor:"5,keyasint,omitempty" json:"base_iv,omitempty"`

	// Key-type-specific parameters. Which of these need to be set, and
	// what their values ought to be, is determined by the KeyType.

	// RawKeyParam contains the raw CBOR encoded data for the label -1.
	// Depending on the KeyType this is used to populate either Curve or K
	// below.
	RawKeyParam cbor.RawMessage `cbor:"-1,keyasint,omitempty"`

	// EC2/OKP params

	// X is the x-coordinate
	X []byte `cbor:"-2,keyasint,omitempty"`
	// Y is the y-coordinate (sign bits are not supported)
	Y []byte `cbor:"-3,keyasint,omitempty"`
	// D is the private key
	D []byte `cbor:"-4,keyasint,omitempty"`
}

// NewOkpKey returns a Key created using the provided Octet Key Pair data.
func NewOkpKey(curve Curve, x, d []byte) (*Key, error) {
	key := &Key{
		Curve: curve,
		keyStruct: keyStruct{
			KeyType: KeyTypeOkp,
			X:       x,
			D:       d,
		},
	}
	return key, key.Validate()
}

// NewEc2Key returns a Key created using the provided elliptic curve key
// data.
func NewEc2Key(curve Curve, x, y, d []byte) (*Key, error) {
	key := &Key{
		Curve: curve,
		keyStruct: keyStruct{
			KeyType: KeyTypeEc2,
			X:       x,
			Y:       y,
			D:       d,
		},
	}
	return key, key.Validate()

}

// NewSymmetricKey returns a Key created using the provided Symmetric key
// bytes.
func NewSymmetricKey(k []byte) (*Key, error) {
	key := &Key{
		K: k,
		keyStruct: keyStruct{
			KeyType: KeyTypeSymmetric,
		},
	}
	return key, key.Validate()
}

// NewKeyFromPublic returns a Key created using the provided crypto.PublicKey
// and Algorithm.
func NewKeyFromPublic(alg Algorithm, pub crypto.PublicKey) (*Key, error) {
	switch alg {
	case AlgorithmES256, AlgorithmES384, AlgorithmES512:
		vk, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("%v: %w", alg, ErrInvalidPubKey)
		}

		var curve Curve

		switch alg {
		case AlgorithmES256:
			curve = CurveP256
		case AlgorithmES384:
			curve = CurveP384
		case AlgorithmES512:
			curve = CurveP521
		}

		return &Key{
			Curve: curve,
			keyStruct: keyStruct{
				KeyType:   KeyTypeEc2,
				Algorithm: alg,
				X:         vk.X.Bytes(),
				Y:         vk.Y.Bytes(),
			},
		}, nil
	case AlgorithmEd25519:
		vk, ok := pub.(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("%v: %w", alg, ErrInvalidPubKey)
		}

		return &Key{
			Curve: CurveEd25519,
			keyStruct: keyStruct{
				KeyType:   KeyTypeOkp,
				Algorithm: alg,
				X:         []byte(vk),
			},
		}, nil
	default:
		return nil, ErrAlgorithmNotSupported
	}
}

// NewKeyFromPrivate returns a Key created using provided crypto.PrivateKey
// and Algorithm.
func NewKeyFromPrivate(alg Algorithm, pub crypto.PrivateKey) (*Key, error) {
	switch alg {
	case AlgorithmES256, AlgorithmES384, AlgorithmES512:
		sk, ok := pub.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%v: %w", alg, ErrInvalidPrivKey)
		}

		var curve Curve

		switch alg {
		case AlgorithmES256:
			curve = CurveP256
		case AlgorithmES384:
			curve = CurveP384
		case AlgorithmES512:
			curve = CurveP521
		}

		return &Key{
			Curve: curve,
			keyStruct: keyStruct{
				KeyType:   KeyTypeEc2,
				Algorithm: alg,
				X:         sk.X.Bytes(),
				Y:         sk.Y.Bytes(),
				D:         sk.D.Bytes(),
			},
		}, nil
	case AlgorithmEd25519:
		sk, ok := pub.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%v: %w", alg, ErrInvalidPrivKey)
		}
		return &Key{
			Curve: CurveEd25519,
			keyStruct: keyStruct{
				KeyType:   KeyTypeOkp,
				Algorithm: alg,
				X:         []byte(sk[32:]),
				D:         []byte(sk[:32]),
			},
		}, nil
	default:
		return nil, ErrAlgorithmNotSupported
	}
}

// Validate ensures that the parameters set inside the Key are internally
// consistent (e.g. that the key type is appropriate to the curve.
func (k Key) Validate() error {
	switch k.KeyType {
	case KeyTypeEc2:
		if k.Curve != CurveP256 && k.Curve != CurveP384 && k.Curve != CurveP521 {
			return fmt.Errorf(
				"EC2 curve must be P-256, P-384, or P-521; found %q",
				k.Curve.String(),
			)
		}
	case KeyTypeOkp:
		if k.Curve != CurveX25519 && k.Curve != CurveX448 &&
			k.Curve != CurveEd25519 && k.Curve != CurveEd448 {

			return fmt.Errorf(
				"OKP curve must be X25519, X448, Ed25519, or Ed448; found %q",
				k.Curve.String(),
			)
		}
	case KeyTypeSymmetric:
	default:
		return errors.New(k.KeyType.String())
	}

	// If Algorithm is set, it must match the specified key parameters.
	if k.Algorithm != AlgorithmInvalid {
		expectedAlg, err := k.deriveAlgorithm()
		if err != nil {
			return err
		}

		if k.Algorithm != expectedAlg {
			return fmt.Errorf(
				"found algorithm %q (expected %q)",
				k.Algorithm.String(),
				expectedAlg.String(),
			)
		}
	}

	return nil
}

// MarshalCBOR encodes Key into a COSE_Key object.
func (k Key) MarshalCBOR() ([]byte, error) {
	var err error

	if k.KeyType == KeyTypeSymmetric {
		if k.RawKeyParam, err = encMode.Marshal(k.K); err != nil {
			return nil, err
		}
	} else if k.KeyType == KeyTypeEc2 || k.KeyType == KeyTypeOkp {
		if k.RawKeyParam, err = encMode.Marshal(k.Curve); err != nil {
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("invalid key type: %q", k.KeyType.String())
	}

	return encMode.Marshal(k.keyStruct)
}

// UnmarshalCBOR decodes a COSE_Key object into Key.
func (k *Key) UnmarshalCBOR(data []byte) error {
	if err := decMode.Unmarshal(data, &k.keyStruct); err != nil {
		return err
	}

	switch k.KeyType {
	case KeyTypeEc2:
		if k.RawKeyParam == nil {
			return errors.New("missing Curve parameter (required for EC2 key type)")
		}

		if err := decMode.Unmarshal(k.RawKeyParam, &k.Curve); err != nil {
			return err
		}
	case KeyTypeOkp:
		if k.RawKeyParam == nil {
			return errors.New("missing Curve parameter (required for OKP key type)")
		}

		if err := decMode.Unmarshal(k.RawKeyParam, &k.Curve); err != nil {
			return err
		}
	case KeyTypeSymmetric:
		if k.RawKeyParam == nil {
			return errors.New("missing K parameter (required for Symmetric key type)")
		}

		if err := decMode.Unmarshal(k.RawKeyParam, &k.K); err != nil {
			return err
		}
	default:
		// this should not be reachable as KeyType.UnmarshalCBOR would
		// result in an error during decMode.Unmarshal() above, if the
		// value in the data doesn't correspond to one of the above
		// types.
		return fmt.Errorf("unexpected key type %q", k.KeyType.String())
	}

	return k.Validate()
}

// PublicKey returns a crypto.PublicKey generated using Key's parameters.
func (k *Key) PublicKey() (crypto.PublicKey, error) {
	alg, err := k.deriveAlgorithm()
	if err != nil {
		return nil, err
	}

	switch alg {
	case AlgorithmES256, AlgorithmES384, AlgorithmES512:
		var curve elliptic.Curve

		switch alg {
		case AlgorithmES256:
			curve = elliptic.P256()
		case AlgorithmES384:
			curve = elliptic.P384()
		case AlgorithmES512:
			curve = elliptic.P521()
		}

		pub := &ecdsa.PublicKey{Curve: curve, X: new(big.Int), Y: new(big.Int)}
		pub.X.SetBytes(k.X)
		pub.Y.SetBytes(k.Y)

		return pub, nil
	case AlgorithmEd25519:
		return ed25519.PublicKey(k.X), nil
	default:
		return nil, ErrAlgorithmNotSupported
	}
}

// PrivateKey returns a crypto.PrivateKey generated using Key's parameters.
func (k *Key) PrivateKey() (crypto.PrivateKey, error) {
	alg, err := k.deriveAlgorithm()
	if err != nil {
		return nil, err
	}

	switch alg {
	case AlgorithmES256, AlgorithmES384, AlgorithmES512:
		var curve elliptic.Curve

		switch alg {
		case AlgorithmES256:
			curve = elliptic.P256()
		case AlgorithmES384:
			curve = elliptic.P384()
		case AlgorithmES512:
			curve = elliptic.P521()
		}

		priv := &ecdsa.PrivateKey{
			PublicKey: ecdsa.PublicKey{Curve: curve, X: new(big.Int), Y: new(big.Int)},
			D:         new(big.Int),
		}
		priv.X.SetBytes(k.X)
		priv.Y.SetBytes(k.Y)
		priv.D.SetBytes(k.D)

		return priv, nil
	case AlgorithmEd25519:
		buf := make([]byte, ed25519.PrivateKeySize)

		copy(buf, k.D)
		copy(buf[32:], k.X)

		return ed25519.PrivateKey(buf), nil
	default:
		return nil, ErrAlgorithmNotSupported
	}
}

// GetAlgorithm returns the Algorithm assoicated with Key. If Key.Algorithm is
// set, that is what is returned. Otherwise, the algorithm is inferred using
// Key.Curve. This method does NOT validate that Key.Algorithm, if set, aligns
// with Key.Curve.
func (k *Key) GetAlgorithm() (Algorithm, error) {
	if k.Algorithm != AlgorithmInvalid {
		return k.Algorithm, nil
	}

	return k.deriveAlgorithm()
}

// GetSigner returns a Signer created using Key.
func (k *Key) GetSigner() (Signer, error) {
	priv, err := k.PrivateKey()
	if err != nil {
		return nil, err
	}

	alg, err := k.GetAlgorithm()
	if err != nil {
		return nil, err
	}

	var signer crypto.Signer
	var ok bool

	switch alg {
	case AlgorithmES256, AlgorithmES384, AlgorithmES512:
		signer, ok = priv.(*ecdsa.PrivateKey)
		if !ok {
			return nil, ErrInvalidPrivKey
		}
	case AlgorithmEd25519:
		signer, ok = priv.(ed25519.PrivateKey)
		if !ok {
			return nil, ErrInvalidPrivKey
		}
	default:
		return nil, ErrAlgorithmNotSupported
	}

	return NewSigner(alg, signer)
}

// GetVerifier returns a Verifier created using Key.
func (k *Key) GetVerifier() (Verifier, error) {
	pub, err := k.PublicKey()
	if err != nil {
		return nil, err
	}

	alg, err := k.GetAlgorithm()
	if err != nil {
		return nil, err
	}

	return NewVerifier(alg, pub)
}

// deriveAlgorithm derives the intended algorithm for the key from its curve.
func (k *Key) deriveAlgorithm() (Algorithm, error) {
	switch k.KeyType {
	case KeyTypeEc2, KeyTypeOkp:
		switch k.Curve {
		case CurveP256:
			return AlgorithmES256, nil
		case CurveP384:
			return AlgorithmES384, nil
		case CurveP521:
			return AlgorithmES512, nil
		case CurveEd25519:
			return AlgorithmEd25519, nil
		default:
			return AlgorithmInvalid, fmt.Errorf("unsupported curve %q", k.Curve.String())
		}
	default:
		// Symmetric algorithms are not supported in the current inmplementation.
		return AlgorithmInvalid, fmt.Errorf("unexpected key type %q", k.KeyType.String())
	}
}
