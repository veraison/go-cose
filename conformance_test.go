package cose_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

type TestCase struct {
	UUID        string   `json:"uuid"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Key         Key      `json:"key"`
	Alg         string   `json:"alg"`
	Sign1       *Sign1   `json:"sign1::sign"`
	Verify1     *Verify1 `json:"sign1::verify"`
}

type Key map[string]string

type Sign1 struct {
	Payload            string `json:"payload"`
	ProtectedHeaders   *CBOR  `json:"protectedHeaders"`
	UnprotectedHeaders *CBOR  `json:"unprotectedHeaders"`
	External           string `json:"external"`
	Detached           bool   `json:"detached"`
	TBS                CBOR   `json:"tbsHex"`
	Output             CBOR   `json:"expectedOutput"`
	OutputLength       int    `json:"fixedOutputLength"`
}

type Verify1 struct {
	TaggedCOSESign1 CBOR   `json:"taggedCOSESign1"`
	External        string `json:"external"`
	Verify          bool   `json:"shouldVerify"`
}

type CBOR struct {
	CBORHex  string `json:"cborHex"`
	CBORDiag string `json:"cborDiag"`
}

// Conformance samples are taken from
// https://github.com/gluecose/test-vectors.
var testCases = []struct {
	name          string
	deterministic bool
	err           string
	skip          bool
}{
	{name: "sign1-sign-0000"},
	{name: "sign1-sign-0001"},
	{name: "sign1-sign-0002"},
	{name: "sign1-sign-0003"},
	{name: "sign1-sign-0004", deterministic: true},
	{name: "sign1-sign-0005", deterministic: true},
	{name: "sign1-sign-0006", deterministic: true},
	{name: "sign1-verify-0000"},
	{name: "sign1-verify-0001"},
	{name: "sign1-verify-0002"},
	{name: "sign1-verify-0003"},
	{name: "sign1-verify-0004"},
	{name: "sign1-verify-0005"},
	{name: "sign1-verify-0006"},
	{name: "sign1-verify-negative-0000", err: "cbor: invalid protected header: cbor: require bstr type"},
	{name: "sign1-verify-negative-0001", err: "cbor: invalid protected header: cbor: protected header: require map type"},
	{name: "sign1-verify-negative-0002", err: "cbor: invalid protected header: cbor: found duplicate map key \"1\" at map element index 1"},
	{name: "sign1-verify-negative-0003", err: "cbor: invalid unprotected header: cbor: found duplicate map key \"4\" at map element index 1"},
}

func TestConformance(t *testing.T) {
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			if tt.skip {
				t.SkipNow()
			}
			data, err := os.ReadFile(filepath.Join("testdata", tt.name+".json"))
			if err != nil {
				t.Fatal(err)
			}
			var tc TestCase
			err = json.Unmarshal(data, &tc)
			if err != nil {
				t.Fatal(err)
			}
			if tc.Sign1 != nil {
				testSign1(t, &tc, tt.deterministic)
			} else if tc.Verify1 != nil {
				testVerify1(t, &tc, tt.err)
			} else {
				t.Fatal("test case not supported")
			}
		})
	}
}

func testVerify1(t *testing.T, tc *TestCase, wantErr string) {
	var err error
	defer func() {
		if tc.Verify1.Verify && err != nil {
			t.Fatal(err)
		} else if !tc.Verify1.Verify {
			if err == nil {
				t.Fatal("Verify1 should have failed")
			}
			if wantErr != "" {
				if got := err.Error(); !strings.Contains(got, wantErr) {
					t.Fatalf("error mismatch; want %q, got %q", wantErr, got)
				}
			}
		}
	}()
	var verifier cose.Verifier
	_, verifier, err = getSigner(tc, false)
	if err != nil {
		return
	}
	var sigMsg cose.Sign1Message
	err = sigMsg.UnmarshalCBOR(mustHexToBytes(tc.Verify1.TaggedCOSESign1.CBORHex))
	if err != nil {
		return
	}
	var external []byte
	if tc.Verify1.External != "" {
		external = mustHexToBytes(tc.Verify1.External)
	}
	err = sigMsg.Verify(external, verifier)
	if tc.Verify1.Verify && err != nil {
		t.Fatal(err)
	} else if !tc.Verify1.Verify && err == nil {
		t.Fatal("Verify1 should have failed")
	}
}

func testSign1(t *testing.T, tc *TestCase, deterministic bool) {
	signer, verifier, err := getSigner(tc, true)
	if err != nil {
		t.Fatal(err)
	}
	sig := tc.Sign1
	sigMsg := cose.NewSign1Message()
	sigMsg.Payload = mustHexToBytes(sig.Payload)
	sigMsg.Headers, err = decodeHeaders(mustHexToBytes(sig.ProtectedHeaders.CBORHex), mustHexToBytes(sig.UnprotectedHeaders.CBORHex))
	if err != nil {
		t.Fatal(err)
	}
	var external []byte
	if sig.External != "" {
		external = mustHexToBytes(sig.External)
	}
	err = sigMsg.Sign(new(zeroSource), external, signer)
	if err != nil {
		t.Fatal(err)
	}
	err = sigMsg.Verify(external, verifier)
	if err != nil {
		t.Fatal(err)
	}
	got, err := sigMsg.MarshalCBOR()
	if err != nil {
		t.Fatal(err)
	}
	want := mustHexToBytes(sig.Output.CBORHex)
	if !deterministic {
		got = got[:sig.OutputLength]
		want = want[:sig.OutputLength]
	}
	if !bytes.Equal(want, got) {
		t.Fatalf("unexpected output:\nwant: %x\n got: %x", want, got)
	}
}

func getSigner(tc *TestCase, private bool) (cose.Signer, cose.Verifier, error) {
	pkey, err := getKey(tc.Key, private)
	if err != nil {
		return nil, nil, err
	}
	alg := mustNameToAlg(tc.Alg)
	signer, err := cose.NewSigner(alg, pkey)
	if err != nil {
		return nil, nil, err
	}
	verifier, err := cose.NewVerifier(alg, pkey.Public())
	if err != nil {
		return nil, nil, err
	}
	return signer, verifier, nil
}

func getKey(key Key, private bool) (crypto.Signer, error) {
	switch key["kty"] {
	case "RSA":
		pkey := &rsa.PrivateKey{
			PublicKey: rsa.PublicKey{
				N: mustBase64ToBigInt(key["n"]),
				E: mustBase64ToInt(key["e"]),
			},
		}
		if private {
			pkey.D = mustBase64ToBigInt(key["d"])
			pkey.Primes = []*big.Int{mustBase64ToBigInt(key["p"]), mustBase64ToBigInt(key["q"])}
			pkey.Precomputed = rsa.PrecomputedValues{
				Dp:        mustBase64ToBigInt(key["dp"]),
				Dq:        mustBase64ToBigInt(key["dq"]),
				Qinv:      mustBase64ToBigInt(key["qi"]),
				CRTValues: make([]rsa.CRTValue, 0),
			}
		}
		return pkey, nil
	case "EC":
		var c elliptic.Curve
		switch key["crv"] {
		case "P-224":
			c = elliptic.P224()
		case "P-256":
			c = elliptic.P256()
		case "P-384":
			c = elliptic.P384()
		case "P-521":
			c = elliptic.P521()
		default:
			return nil, errors.New("unsupported EC curve: " + key["crv"])
		}
		pkey := &ecdsa.PrivateKey{
			PublicKey: ecdsa.PublicKey{
				X:     mustBase64ToBigInt(key["x"]),
				Y:     mustBase64ToBigInt(key["y"]),
				Curve: c,
			},
		}
		if private {
			pkey.D = mustBase64ToBigInt(key["d"])
		}
		return pkey, nil
	}
	return nil, errors.New("unsupported key type: " + key["kty"])
}

// zeroSource is an io.Reader that returns an unlimited number of zero bytes.
type zeroSource struct{}

func (zeroSource) Read(b []byte) (n int, err error) {
	for i := range b {
		b[i] = 0
	}

	return len(b), nil
}

var encMode, _ = cbor.CanonicalEncOptions().EncMode()

func decodeHeaders(protected, unprotected []byte) (hdr cose.Headers, err error) {
	// test-vectors encodes the protected header as a map instead of a map wrapped in a bstr.
	// UnmarshalFromRaw expects the former, so wrap the map here before passing it to UnmarshalFromRaw.
	hdr.RawProtected, err = encMode.Marshal(protected)
	if err != nil {
		return
	}
	hdr.RawUnprotected = unprotected
	err = hdr.UnmarshalFromRaw()
	return hdr, err
}

func mustBase64ToInt(s string) int {
	return int(mustBase64ToBigInt(s).Int64())
}

func mustHexToBytes(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func mustBase64ToBigInt(s string) *big.Int {
	val, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return new(big.Int).SetBytes(val)
}

// mustNameToAlg returns the algorithm associated to name.
// The content of name is not defined in any RFC,
// but it's what the test cases use to identify algorithms.
func mustNameToAlg(name string) cose.Algorithm {
	switch name {
	case "PS256":
		return cose.AlgorithmPS256
	case "PS384":
		return cose.AlgorithmPS384
	case "PS512":
		return cose.AlgorithmPS512
	case "ES256":
		return cose.AlgorithmES256
	case "ES384":
		return cose.AlgorithmES384
	case "ES512":
		return cose.AlgorithmES512
	}
	panic("algorithm name not found: " + name)
}
