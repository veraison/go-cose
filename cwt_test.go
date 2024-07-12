package cose_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"

	"github.com/veraison/go-cose"
)

// This example demonstrates signing and verifying COSE_Sign1 signatures.
func ExampleCWTMessage() {
	// create message to be signed
	msgToSign := cose.NewSign1Message()
	msgToSign.Payload = []byte("hello world")
	msgToSign.Headers.Protected.SetAlgorithm(cose.AlgorithmES512)

	msgToSign.Headers.Protected.SetType("application/cwt")
	claims := cose.CWTClaims{
		cose.CWTClaimIssuer:  "issuer.example",
		cose.CWTClaimSubject: "subject.example",
	}
	msgToSign.Headers.Protected.SetCWTClaims(claims)

	msgToSign.Headers.Unprotected[cose.HeaderLabelKeyID] = []byte("1")

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
	err = msgToSign.Sign(rand.Reader, nil, signer)
	if err != nil {
		panic(err)
	}
	sig, err := msgToSign.MarshalCBOR()
	// uncomment to review EDN
	// coseSign1Diagnostic, err := cbor.Diagnose(sig)
	// fmt.Println(coseSign1Diagnostic)
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
	err = msgToVerify.Verify(nil, verifier)
	if err != nil {
		panic(err)
	}
	fmt.Println("message verified")

	// tamper the message and verification should fail
	msgToVerify.Payload = []byte("foobar")
	err = msgToVerify.Verify(nil, verifier)
	if err != cose.ErrVerification {
		panic(err)
	}
	fmt.Println("verification error as expected")
	// Output:
	// message signed
	// message verified
	// verification error as expected
}
