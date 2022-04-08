//go:build go1.18
// +build go1.18

package cose_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/veraison/go-cose"
)

func FuzzSign1_Encode(f *testing.F) {
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
	f.Fuzz(func(t *testing.T, b []byte) {
		var msg cose.Sign1Message
		if err := msg.UnmarshalCBOR(b); err != nil {
			return
		}
		_, err := msg.MarshalCBOR()
		if err != nil {
			t.Fatalf("failed to marshal valid message: %s", err)
		}
		// TODO: uncomment the roundtrip test once https://github.com/veraison/go-cose/pull/17 lands.
		// if !bytes.Equal(b, got) {
		// 	t.Fatalf("roundtripped message has changed, got: %v, want: %v", got, b)
		// }
	})
}
