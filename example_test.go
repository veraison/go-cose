package cose_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"fmt"

	"github.com/veraison/go-cose"
)

// This example demonstrates signing and verifying COSE_Sign signatures.
//
// The COSE Sign API is EXPERIMENTAL and may be changed or removed in a later
// release.
func ExampleSignMessage() {
	// create a signature holder
	sigHolder := cose.NewSignature()
	sigHolder.Headers.Protected.SetAlgorithm(cose.AlgorithmES512)
	sigHolder.Headers.Unprotected[cose.HeaderLabelKeyID] = []byte("1")

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
	err = msgToSign.Sign(rand.Reader, nil, signer)
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

// This example demonstrates signing and verifying COSE_Sign1 signatures.
func ExampleSign1Message() {
	// create message to be signed
	msgToSign := cose.NewSign1Message()
	msgToSign.Payload = []byte("hello world")
	msgToSign.Headers.Protected.SetAlgorithm(cose.AlgorithmES512)
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

// This example demonstrates signing COSE_Sign1_Tagged signatures using Sign1().
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
	headers := cose.Headers{
		Protected: cose.ProtectedHeader{
			cose.HeaderLabelAlgorithm: cose.AlgorithmES512,
		},
		Unprotected: cose.UnprotectedHeader{
			cose.HeaderLabelKeyID: []byte("1"),
		},
	}
	sig, err := cose.Sign1(rand.Reader, signer, headers, []byte("hello world"), nil)
	if err != nil {
		panic(err)
	}

	fmt.Println("message signed")
	_ = sig // further process on sig
	// Output:
	// message signed
}

// This example demonstrates signing COSE_Sign1 signatures using Sign1Untagged().
func ExampleSign1Untagged() {
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
	headers := cose.Headers{
		Protected: cose.ProtectedHeader{
			cose.HeaderLabelAlgorithm: cose.AlgorithmES512,
		},
		Unprotected: cose.UnprotectedHeader{
			cose.HeaderLabelKeyID: []byte("1"),
		},
	}
	sig, err := cose.Sign1Untagged(rand.Reader, signer, headers, []byte("hello world"), nil)
	if err != nil {
		panic(err)
	}

	fmt.Println("message signed")
	_ = sig // further process on sig
	// Output:
	// message signed
}

func ExampleDigestSigner() {
	// create a signer
	privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		panic(err)
	}
	signer, err := cose.NewSigner(cose.AlgorithmES256, privateKey)
	if err != nil {
		panic(err)
	}
	digestSigner, ok := signer.(cose.DigestSigner)
	if !ok {
		panic("signer does not support digest signing")
	}

	// hash payload outside go-cose.
	payload := []byte("hello world")
	digested := sha512.Sum512(payload)
	sig, err := digestSigner.SignDigest(rand.Reader, digested[:])

	fmt.Println("digest signed")
	_ = sig // further process on sig
	// Output:
	// digest signed
}

// This example demonstrates signing and verifying countersignatures.
//
// The COSE Countersignature API is EXPERIMENTAL and may be changed or removed in a later
// release.
func ExampleCountersignature() {
	// create a signature holder
	sigHolder := cose.NewSignature()
	sigHolder.Headers.Protected.SetAlgorithm(cose.AlgorithmES512)
	sigHolder.Headers.Unprotected[cose.HeaderLabelKeyID] = []byte("1")

	// create message to be signed
	msgToSign := cose.NewSignMessage()
	msgToSign.Payload = []byte("hello world")
	msgToSign.Signatures = append(msgToSign.Signatures, sigHolder)

	// create a signer
	privateKey, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	signer, _ := cose.NewSigner(cose.AlgorithmES512, privateKey)

	// sign message
	msgToSign.Sign(rand.Reader, nil, signer)

	// create a countersignature holder for the message
	msgCountersig := cose.NewCountersignature()
	msgCountersig.Headers.Protected.SetAlgorithm(cose.AlgorithmES512)
	msgCountersig.Headers.Unprotected[cose.HeaderLabelKeyID] = []byte("11")

	// create a countersigner
	counterPrivateKey, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	countersigner, _ := cose.NewSigner(cose.AlgorithmES512, counterPrivateKey)

	// countersign message
	err := msgCountersig.Sign(rand.Reader, countersigner, msgToSign, nil)
	if err != nil {
		panic(err)
	}

	// add countersignature as message unprotected header; notice the
	// countersignature should be assigned as reference
	msgToSign.Headers.Unprotected[cose.HeaderLabelCounterSignatureV2] = msgCountersig

	// create a countersignature holder for the signature
	sigCountersig := cose.NewCountersignature()
	sigCountersig.Headers.Protected.SetAlgorithm(cose.AlgorithmES512)
	sigCountersig.Headers.Unprotected[cose.HeaderLabelKeyID] = []byte("11")

	// countersign signature
	err = sigCountersig.Sign(rand.Reader, countersigner, sigHolder, nil)
	if err != nil {
		panic(err)
	}

	// add countersignature as signature unprotected header; notice the
	// countersignature should be assigned as reference
	sigHolder.Headers.Unprotected[cose.HeaderLabelCounterSignatureV2] = sigCountersig

	sig, err := msgToSign.MarshalCBOR()
	if err != nil {
		panic(err)
	}
	fmt.Println("message signed and countersigned")

	// create a verifier from a trusted public key
	publicKey := counterPrivateKey.Public()
	verifier, err := cose.NewVerifier(cose.AlgorithmES512, publicKey)
	if err != nil {
		panic(err)
	}

	// decode COSE_Sign message containing countersignatures
	var msgToVerify cose.SignMessage
	err = msgToVerify.UnmarshalCBOR(sig)
	if err != nil {
		panic(err)
	}

	// unwrap the message countersignature; the example assumes the header is a
	// single countersignature, but real code would consider checking if it
	// consists in a slice of countersignatures too.
	msgCountersigHdr := msgToVerify.Headers.Unprotected[cose.HeaderLabelCounterSignatureV2]
	msgCountersigToVerify := msgCountersigHdr.(*cose.Countersignature)

	// verify message countersignature
	err = msgCountersigToVerify.Verify(verifier, msgToVerify, nil)
	if err != nil {
		panic(err)
	}
	fmt.Println("message countersignature verified")

	// unwrap the signature countersignature; the example assumes the header is a
	// single countersignature, but real code would consider checking if it
	// consists in a slice of countersignatures too.
	sig0 := msgToVerify.Signatures[0]
	sigCountersigHdr := sig0.Headers.Unprotected[cose.HeaderLabelCounterSignatureV2]
	sigCountersigToVerify := sigCountersigHdr.(*cose.Countersignature)

	// verify signature countersignature
	err = sigCountersigToVerify.Verify(verifier, sig0, nil)
	if err != nil {
		panic(err)
	}
	fmt.Println("signature countersignature verified")

	// tamper the message and verification should fail
	msgToVerify.Payload = []byte("foobar")
	err = msgCountersigToVerify.Verify(verifier, msgToVerify, nil)
	if err != cose.ErrVerification {
		panic(err)
	}
	fmt.Println("verification error as expected")
	// Output:
	// message signed and countersigned
	// message countersignature verified
	// signature countersignature verified
	// verification error as expected
}
