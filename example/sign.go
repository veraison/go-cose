package main

import (
	"crypto"
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
	signer, err := cose.NewSigner(&ecdsaPrivateKey)
	if err != nil {
		panic(fmt.Sprintf(fmt.Sprintf("Error creating signer %s", err)))
	}

	// create a signature
	sig := cose.NewSignature()
	sig.Headers.Unprotected["kid"] = 1
	sig.Headers.Protected["alg"] = "ES256"

	// create a message
	payload := []byte("payload to sign")
	external := []byte("") // optional external data see https://tools.ietf.org/html/rfc8152#section-4.3

	msg := cose.NewSignMessage(payload) // can update via .Payload later too
	msg.AddSignature(sig)

	randReader := rand.New(rand.NewSource(time.Now().UnixNano()))
	err = msg.Sign(randReader, external, cose.SignOpts{
		HashFunc: crypto.SHA256,
		GetSigner: func(index int, signature cose.Signature) (cose.Signer, error) {
			if signature.Headers.Unprotected["kid"] == 1 || signature.Headers.Unprotected[cose.GetCommonHeaderTagOrPanic("kid")] == 1 {
				return *signer, nil
			} else {
				return *signer, cose.ErrNoSignerFound
			}
		},
	})
	if err == nil {
		fmt.Println(fmt.Sprintf("Message signature (ES256): %x", msg.Signatures[0].SignatureBytes))
	} else {
		panic(fmt.Sprintf("Error signing the message %+v", err))
	}
}
