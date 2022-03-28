package cose_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

type Example struct {
	Title         string         `json:"title"`
	Description   string         `json:"description"`
	Fail          bool           `json:"bool"`
	Input         Inputs         `json:"input"`
	Intermediates *Intermediates `json:"intermediates"`
	Output        Outputs        `json:"output"`
}

type Inputs struct {
	Plaintext  string     `json:"plaintext"`
	Detached   bool       `json:"detached"`
	Enveloped  *Enveloped `json:"enveloped"`
	Encrypt    *Encrypt   `json:"encrypt"`
	Mac        *Mac       `json:"mac"`
	Mac0       *Mac0      `json:"mac0"`
	Sign       *Sign      `json:"sign"`
	Sign0      *Signer    `json:"sign0"`
	Failures   Failures   `json:"failures"`
	RNG_desc   string     `json:"rng_description"`
	RNG_stream []string   `json:"rng_stream"`
}

type Sign struct {
	Headers
	Signers []Signer `json:"signers"`
}

type Headers struct {
	Protected   map[string]interface{} `json:"protected"`
	Unprotected map[string]interface{} `json:"unprotected"`
	Unsent      map[string]interface{} `json:"unsent"`
}

type Signer struct {
	Headers
	Alg      string `json:"alg"`
	Key      Key    `json:"key"`
	External string `json:"external"`
}

type HeaderItems struct {
	Alg           string `json:"alg"`
	KID           string `json:"kid"`
	KID_hex       string `json:"kid_hex"`
	EPK           Key    `json:"epk"`
	SPK           Key    `json:"spk"`
	SPK_KID       string `json:"spk_kid"`
	SPK_KID_hex   string `json:"spk_kid_hex"`
	APU_ID        string `json:"apu_id"`
	APU_Nonce_hex string `json:"apu_nonce_hex"`
	APV_ID        string `json:"apv_id"`
	PUB_other     string `json:"pub_other"`
	Salt          string `json:"salt"`
}
type Mac struct {
	Headers
	Alg        string      `json:"alg"`
	Recipients []Recipient `json:"recipients"`
}

type Mac0 struct {
	Headers
	Alg string `json:"alg"`
}

type Encrypt struct {
	Headers
	Alg string `json:"alg"`
}

type Enveloped struct {
	Headers
	Alg        string      `json:"alg"`
	Recipients []Recipient `json:"recipients"`
}

type Recipient struct {
	Headers
	Alg        string   `json:"alg"`
	Fail       bool     `json:"fail"`
	Key        Key      `json:"key"`
	Sender_key Key      `json:"sender_key"`
	Failures   Failures `json:"failures"`
}

type Key map[string]string

type Failures map[string]string

type Outputs struct {
	CBOR      string `json:"cbor"`
	CBOR_diag string `json:"cbor_diag"`
	Content   string `json:"content"`
}

type Intermediates struct {
	ToMax_hex  string `json:"ToMax_hex"`
	CEK_hex    string `json:"CEK_hex"`
	AAD_hex    string `json:"AAD_hex"`
	Recipients []struct {
		Context string `json:"Context_hex"`
		Secret  string `json:"Secret_hex"`
	} `json:"recipients"`
	Signers []struct {
		ToBeSign_hex string `json:"ToBeSign_hex"`
	} `json:"signers"`
}

// Conformance samples are taken from
// https://github.com/cose-wg/Examples.
var testCases = []struct {
	name          string
	compareResult bool
}{
	{"rsa-pss-examples/rsa-pss-01", true},
	// ECDSA test cases are not created with the same algorithm we use,
	// so the signature will be different.
	{"ecdsa-examples/ecdsa-01", false},
	{"ecdsa-examples/ecdsa-02", false},
	{"ecdsa-examples/ecdsa-03", false},
	{"ecdsa-examples/ecdsa-sig-01", false},
	{"ecdsa-examples/ecdsa-sig-02", false},
	{"ecdsa-examples/ecdsa-sig-03", false},
}

func TestExamples(t *testing.T) {
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("testdata", tt.name+".json"))
			if err != nil {
				t.Fatal(err)
			}
			var e Example
			err = json.Unmarshal(data, &e)
			if err != nil {
				t.Fatal(err)
			}
			processExample(t, &e, tt.compareResult)
		})
	}
}

func processExample(t *testing.T, e *Example, check bool) {
	rng := newStaticRnd(e.Input.RNG_stream)
	var result cbor.Marshaler
	if e.Input.Sign != nil {
		result = processSign(t, rng, e)
	} else if e.Input.Sign0 != nil {
		result = processSign0(t, rng, e)
	}
	got, err := result.MarshalCBOR()
	if err != nil {
		t.Fatal(err)
	}
	if check {
		want := mustHexToBytes(e.Output.CBOR)
		if !bytes.Equal(want, got) {
			t.Fatalf("unexpected output:\nwant: %x\n got: %x", want, got)
		}
	}
}

func processSign(t *testing.T, rng io.Reader, e *Example) cbor.Marshaler {
	sign := e.Input.Sign
	sigMsg := cose.SignMessage{
		Headers: &cose.Headers{
			Protected:   castMap(sign.Protected),
			Unprotected: castMap(sign.Unprotected),
		},
		Payload: []byte(e.Input.Plaintext),
	}
	external := []byte("")
	var signers []cose.Signer
	var verifiers []cose.Verifier
	for i, sig := range sign.Signers {
		signer, signature, err := getSigner(sig)
		if err != nil {
			t.Fatal(err)
		}
		// Check our Sig_structure is identical to the expected one.
		got, err := sigMsg.SigStructure(external, signature)
		if err != nil {
			t.Fatal(err)
		}
		want := mustHexToBytes(e.Intermediates.Signers[i].ToBeSign_hex)
		if !bytes.Equal(want, got) {
			t.Fatal("intermediate signature mismatch")
		}
		signers = append(signers, *signer)
		verifiers = append(verifiers, *signer.Verifier())
		sigMsg.Signatures = append(sigMsg.Signatures, *signature)
	}
	err := sigMsg.Sign(rng, external, signers)
	if err != nil {
		t.Fatal(err)
	}
	err = sigMsg.Verify(external, verifiers)
	if err != nil && !e.Fail {
		t.Fatal(err)
	} else if err == nil && e.Fail {
		t.Fatal("error expected")
	}
	return &sigMsg
}

func processSign0(t *testing.T, rng io.Reader, e *Example) cbor.Marshaler {
	sig := e.Input.Sign0
	sigMsg := cose.Sign1Message{
		Headers: &cose.Headers{
			Protected:   castMap(sig.Protected),
			Unprotected: castMap(sig.Unprotected),
		},
		Payload: []byte(e.Input.Plaintext),
	}
	external := []byte("")
	signer, _, err := getSigner(*sig)
	if err != nil {
		t.Fatal(err)
	}
	err = sigMsg.Sign(rng, external, *signer)
	if err != nil {
		t.Fatal(err)
	}
	err = sigMsg.Verify(external, *signer.Verifier())
	if err != nil && !e.Fail {
		t.Fatal(err)
	} else if err == nil && e.Fail {
		t.Fatal("error expected")
	}
	return &sigMsg
}

func getSigner(sig Signer) (*cose.Signer, *cose.Signature, error) {
	pkey, err := getKey(sig.Key)
	if err != nil {
		return nil, nil, err
	}
	alg := mustNameToAlg(sig.Protected["alg"].(string))
	signer, err := cose.NewSignerFromKey(alg, pkey)
	if err != nil {
		return nil, nil, err
	}
	signature := &cose.Signature{
		Headers: &cose.Headers{
			Protected:   castMap(sig.Protected),
			Unprotected: castMap(sig.Unprotected),
		},
	}
	return signer, signature, nil
}

func getKey(key Key) (crypto.PrivateKey, error) {
	switch key["kty"] {
	case "RSA":
		return &rsa.PrivateKey{
			PublicKey: rsa.PublicKey{
				N: mustHexToBigInt(key["n_hex"]),
				E: mustHexToInt(key["e_hex"]),
			},
			D:      mustHexToBigInt(key["d_hex"]),
			Primes: []*big.Int{mustHexToBigInt(key["p_hex"]), mustHexToBigInt(key["q_hex"])},
			Precomputed: rsa.PrecomputedValues{
				Dp:        mustHexToBigInt(key["dP_hex"]),
				Dq:        mustHexToBigInt(key["dQ_hex"]),
				Qinv:      mustHexToBigInt(key["qi_hex"]),
				CRTValues: make([]rsa.CRTValue, 0),
			},
		}, nil
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
		return &ecdsa.PrivateKey{
			PublicKey: ecdsa.PublicKey{
				X:     mustBase64ToBigInt(key["x"]),
				Y:     mustBase64ToBigInt(key["y"]),
				Curve: c,
			},
			D: mustBase64ToBigInt(key["d"]),
		}, nil
	}
	return nil, errors.New("unsupported key type: " + key["kty"])
}

type staticRnd struct {
	n    int
	data []byte
}

func newStaticRnd(s []string) *staticRnd {
	var r staticRnd
	for _, v := range s {
		r.data = append(r.data, mustHexToBytes(v)...)
	}
	return &r
}

func (r *staticRnd) Read(b []byte) (n int, err error) {
	if r.n+len(b) > len(r.data) {
		// If we reach here it means Go uses more
		// random bytes than provided in the test case.
		// If we are lucky providing zero numbers will be enough
		// to pass the test.
		r.data = append(r.data, make([]byte, len(b))...)
	}
	copy(b, r.data[r.n:])
	r.n += len(b)
	return len(b), nil
}

// castMap translated a map decoded from the test data into
// the naming convention and format expected by go-cose.
func castMap(m map[string]interface{}) map[interface{}]interface{} {
	ret := make(map[interface{}]interface{})
	for k, v := range m {
		switch v1 := v.(type) {
		case float64:
			// encoding/json uses float64 when it sees
			// an untyped number.
			v = int64(v1)
		}
		switch k {
		case "alg":
			v = mustNameToAlg(v.(string)).Name
		case "ctyp":
			k = "content type"
		case "kid":
			v = []byte(v.(string))
		}
		ret[k] = v
	}
	return ret
}

func mustHexToInt(s string) int {
	return int(mustHexToBigInt(s).Int64())
}

func mustHexToBytes(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func mustHexToBigInt(s string) *big.Int {
	return new(big.Int).SetBytes(mustHexToBytes(s))
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
func mustNameToAlg(name string) *cose.Algorithm {
	switch name {
	case "RSA-PSS-256":
		return cose.PS256
	case "ES256":
		return cose.ES256
	case "ES384":
		return cose.ES384
	case "ES512":
		return cose.ES512
	}
	panic("algorithm name not found: " + name)
}
