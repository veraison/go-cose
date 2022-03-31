package cose_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"

	"github.com/veraison/go-cose"
)

// This example demonstrates signing and verifying COSE_Sign1 signatures.
func ExampleSign1Message() {
	// create message to be signed
	msgToSign := cose.NewSign1Message()
	msgToSign.Payload = []byte("hello world")
	msgToSign.Headers.Protected.SetAlgorithm(cose.AlgorithmES512)
	msgToSign.Headers.Unprotected[cose.HeaderLabelKeyID] = 1

	// create a signer
	privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		panic(err)
	}
	signer, err := cose.NewSigner(cose.AlgorithmES512, privateKey)
	if err != nil {
		panic(err)
	}

	// sign message
	err = msgToSign.Sign(rand.Reader, signer)
	if err != nil {
		panic(err)
	}
	sig, err := msgToSign.MarshalCBOR()
	if err != nil {
		panic(err)
	}
	fmt.Println("message signed")

	// create a verifier from a trusted public key
	publicKey := privateKey.Public()
	verifier, err := cose.NewVerifier(cose.AlgorithmES512, publicKey)
	if err != nil {
		panic(err)
	}

	// verify message
	var msgToVerify cose.Sign1Message
	err = msgToVerify.UnmarshalCBOR(sig)
	if err != nil {
		panic(err)
	}
	err = msgToVerify.Verify(verifier)
	if err != nil {
		panic(err)
	}
	fmt.Println("message verified")

	// tamper the message and verification should fail
	msgToVerify.Payload = []byte("foobar")
	err = msgToVerify.Verify(verifier)
	if err != cose.ErrVerification {
		panic(err)
	}
	fmt.Println("verification error as expected")
	// Output:
	// message signed
	// message verified
	// verification error as expected
}