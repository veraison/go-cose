//go:build go1.18
// +build go1.18

package cose_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

var supportedAlgorithms = [...]cose.Algorithm{
	cose.AlgorithmPS256, cose.AlgorithmPS384, cose.AlgorithmPS512,
	cose.AlgorithmES256, cose.AlgorithmES384, cose.AlgorithmES512,
	cose.AlgorithmEd25519,
}

func FuzzSign1Message_UnmarshalCBOR(f *testing.F) {
	testdata, err := os.ReadDir("testdata")
	if err != nil {
		f.Fatalf("failed to read testdata directory: %s", err)
	}
	for _, de := range testdata {
		if de.IsDir() || !strings.HasPrefix(de.Name(), "sign1-") || !strings.HasSuffix(de.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join("testdata", de.Name()))
		if err != nil {
			f.Fatalf("failed to read testdata: %s", err)
		}
		type testCase struct {
			Sign1   *Sign1   `json:"sign1::sign"`
			Verify1 *Verify1 `json:"sign1::verify"`
		}
		var tc testCase
		err = json.Unmarshal(b, &tc)
		if err != nil {
			f.Fatal(err)
		}
		if tc.Sign1 != nil {
			f.Add(mustHexToBytes(tc.Sign1.Output.CBORHex))
		} else if tc.Verify1 != nil {
			f.Add(mustHexToBytes(tc.Verify1.TaggedCOSESign1.CBORHex))
		}
	}
	enc, _ := cbor.CanonicalEncOptions().EncMode()
	dec, _ := cbor.DecOptions{IntDec: cbor.IntDecConvertSigned}.DecMode()
	isCanonical := func(b []byte) bool {
		var tmp interface{}
		err := dec.Unmarshal(b, &tmp)
		if err != nil {
			return false
		}
		b1, err := enc.Marshal(tmp)
		if err != nil {
			return false
		}
		return bytes.Equal(b, b1)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		var msg cose.Sign1Message
		if err := msg.UnmarshalCBOR(b); err != nil {
			return
		}
		got, err := msg.MarshalCBOR()
		if err != nil {
			t.Fatalf("failed to marshal valid message: %s", err)
		}
		if !isCanonical(b) {
			return
		}
		if len(b) > len(got) {
			b = b[:len(got)]
		}
		if !bytes.Equal(b, got) {
			t.Fatalf("roundtripped message has changed, got: %v, want: %v", got, b)
		}
	})
}

func FuzzSign1(f *testing.F) {
	testdata, err := os.ReadDir("testdata")
	if err != nil {
		f.Fatalf("failed to read testdata directory: %s", err)
	}
	for _, de := range testdata {
		if de.IsDir() || !strings.HasPrefix(de.Name(), "sign1-sign") || !strings.HasSuffix(de.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join("testdata", de.Name()))
		if err != nil {
			f.Fatalf("failed to read testdata: %s", err)
		}
		type testCase struct {
			Sign1 *Sign1 `json:"sign1::sign"`
		}
		var tc testCase
		err = json.Unmarshal(b, &tc)
		if err != nil {
			f.Fatal(err)
		}
		if tc.Sign1 != nil {
			hdr, _ := encMode.Marshal(mustHexToBytes(tc.Sign1.ProtectedHeaders.CBORHex))
			f.Add(hdr, mustHexToBytes(tc.Sign1.Payload), mustHexToBytes(tc.Sign1.External))
		}
	}
	// Generating new keys consumes a lot of memory,
	// to the point that the host can decide to kill the fuzzing execution
	// when the memory is low.
	// We can avoid this by always reusing the same signer and verifier for a given algorithm.
	signverif := make(map[cose.Algorithm]signVerifier, len(supportedAlgorithms))
	for _, alg := range supportedAlgorithms {
		signverif[alg], err = newSignerWithEphemeralKey(alg)
		if err != nil {
			f.Fatal(err)
		}
	}

	f.Fuzz(func(t *testing.T, hdr_data, payload, external []byte) {
		hdr := make(cose.ProtectedHeader)
		err := hdr.UnmarshalCBOR(hdr_data)
		if err != nil {
			return
		}
		alg, err := hdr.Algorithm()
		if err != nil {
			return
		}
		sv, ok := signverif[alg]
		if !ok {
			return
		}
		msg := cose.Sign1Message{
			Headers: cose.Headers{Protected: hdr},
			Payload: payload,
		}
		err = msg.Sign(rand.Reader, external, sv.signer)
		if err != nil {
			t.Fatal(err)
		}
		err = msg.Verify(external, sv.verifier)
		if err != nil {
			t.Fatal(err)
		}
		err = msg.Verify(append(external, []byte{0}...), sv.verifier)
		if err == nil {
			t.Fatal("verification error expected")
		}
	})
}

type signVerifier struct {
	signer   cose.Signer
	verifier cose.Verifier
}

func newSignerWithEphemeralKey(alg cose.Algorithm) (sv signVerifier, err error) {
	var key crypto.Signer
	switch alg {
	case cose.AlgorithmPS256:
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	case cose.AlgorithmPS384:
		key, err = rsa.GenerateKey(rand.Reader, 3072)
	case cose.AlgorithmPS512:
		key, err = rsa.GenerateKey(rand.Reader, 4096)
	case cose.AlgorithmES256:
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case cose.AlgorithmES384:
		key, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case cose.AlgorithmES512:
		key, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	case cose.AlgorithmEd25519:
		_, key, err = ed25519.GenerateKey(rand.Reader)
	default:
		err = cose.ErrAlgorithmNotSupported
	}
	if err != nil {
		return
	}
	sv.signer, err = cose.NewSigner(alg, key)
	if err != nil {
		return
	}
	sv.verifier, err = cose.NewVerifier(alg, key.Public())
	return
}
