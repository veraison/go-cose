package cose_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"

	// "github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

// This example demonstrates signing and verifying COSE_Sign1 signatures.
func ExampleCWTMessage() {

	// create message to be signed
	msgToSign := cose.NewSign1Message()
	msgToSign.Payload = []byte("hello world")
	msgToSign.Headers.Protected.SetAlgorithm(cose.AlgorithmES512)

	claims := make(cose.CWTClaims)
	claims[cose.CWTClaimIssuer] = "issuer.example"
	claims[cose.CWTClaimSubject] = "subject.example"

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
	if err != nil {
		panic(err)
	}
	fmt.Println("message signed")

	// coseSign1Diagnostic, err := cbor.Diagnose(sig)
	// fmt.Println(coseSign1Diagnostic)
	// 18([h'a20138230fa2016e6973737565722e6578616d706c65026f7375626a6563742e6578616d706c65', {4: h'31'}, h'68656c6c6f20776f726c64', h'00528f74d41bae106bba113c3802d3ca69efac4e65e59e99e8d7b74a067adebc769c4982ef389cf21be044e7b5dbed86b20c94a70ce02a20693e04f6ee94669974030147db61af96137d415961a83ae0cde53d4fd4fc6cf224692e25067c0eb17e9f18717e88f64775f11d505b4cb6175e4f6a5c75897001ab480f59437ad52cf65bfcef'])

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
