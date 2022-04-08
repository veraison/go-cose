package cose_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	_ "crypto/sha512"
	"fmt"

	"github.com/veraison/go-cose"
)

// This example demonstrates signing and verifying COSE_Sign signatures.
func ExampleSignMessage() {
	// create a signature holder
	sigHolder := cose.NewSignature()
	sigHolder.Headers.Protected.SetAlgorithm(cose.AlgorithmES512)
	sigHolder.Headers.Unprotected[cose.HeaderLabelKeyID] = 1

	// create message to be signed
	msgToSign := cose.NewSignMessage()
	msgToSign.Payload = []byte("hello world")
	msgToSign.Signatures = append(msgToSign.Signatures, sigHolder)

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
	var msgToVerify cose.SignMessage
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

// This example demonstrates signing COSE_Sign1 signatures using Sign1().
func ExampleSign1() {
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
	protected := cose.ProtectedHeader{}
	protected.SetAlgorithm(cose.AlgorithmES512)
	msg, err := cose.Sign1(rand.Reader, signer, protected, []byte("hello world"), nil)
	if err != nil {
		panic(err)
	}

	// update unprotected headers
	msg.Headers.Unprotected[cose.HeaderLabelKeyID] = 1

	// encode message
	sig, err := msg.MarshalCBOR()
	if err != nil {
		panic(err)
	}
	fmt.Println("message signed")
	_ = sig // futher process on sig
	// Output:
	// message signed
}

// This example demonstrates verifying COSE_Sign1 signatures using Verify1().
func ExampleVerify1() {
	// get a signed message and a trusted public key
	sig, publicKey := getSignatureAndPublicKey()

	// create a verifier from a trusted public key
	verifier, err := cose.NewVerifier(cose.AlgorithmES512, publicKey)
	if err != nil {
		panic(err)
	}

	// verify message
	var msg cose.Sign1Message
	err = msg.UnmarshalCBOR(sig)
	if err != nil {
		panic(err)
	}
	err = cose.Verify1(&msg, verifier)
	if err != nil {
		panic(err)
	}
	fmt.Println("message verified")

	// tamper the message and verification should fail
	msg.Payload = []byte("foobar")
	err = cose.Verify1(&msg, verifier)
	if err != cose.ErrVerification {
		panic(err)
	}
	fmt.Println("verification error as expected")
	// Output:
	// message verified
	// verification error as expected
}

// getSignatureAndPublicKey is a helping function for ExampleVerify1().
func getSignatureAndPublicKey() ([]byte, crypto.PublicKey) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		panic(err)
	}
	signer, err := cose.NewSigner(cose.AlgorithmES512, privateKey)
	if err != nil {
		panic(err)
	}
	msgToSign, err := cose.Sign1(rand.Reader, signer, nil, []byte("hello world"), nil)
	if err != nil {
		panic(err)
	}
	sig, err := msgToSign.MarshalCBOR()
	if err != nil {
		panic(err)
	}
	return sig, privateKey.Public()
}
