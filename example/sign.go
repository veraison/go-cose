package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	cose "go.mozilla.org/cose"
	"math/rand"
	"time"
)

func main() {
	// create a private key
	ecdsaPrivateKey := ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     cose.FromBase64Int("usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8"),
			Y:     cose.FromBase64Int("IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4"),
		},
		D: cose.FromBase64Int("V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM"),
	}

	// create a signer
	signer, err := cose.NewSigner(&ecdsaPrivateKey, cose.GetAlgByNameOrPanic("ES256"))
	if err != nil {
		panic(fmt.Sprintf(fmt.Sprintf("Error creating signer %s", err)))
	}

	// create a signature
	sig := cose.NewSignature()
	sig.Headers.Unprotected["kid"] = 1
	sig.Headers.Protected["alg"] = "ES256"

	// create a message
	external := []byte("") // optional external data see https://tools.ietf.org/html/rfc8152#section-4.3

	msg := cose.NewSignMessage()
	msg.Payload = []byte("payload to sign")
	msg.AddSignature(sig)

	randReader := rand.New(rand.NewSource(time.Now().UnixNano()))
	err = msg.Sign(randReader, external, []cose.Signer{*signer})
	if err == nil {
		fmt.Println(fmt.Sprintf("Message signature (ES256): %x", msg.Signatures[0].SignatureBytes))
	} else {
		panic(fmt.Sprintf("Error signing the message %+v", err))
	}
}
