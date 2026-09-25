package cose_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/veraison/go-cose"
	x509testdata "github.com/veraison/go-cose/testdata/x509"
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

// This example demonstrates signing and verifying COSE_Sign signatures with
// detached payload.
//
// The COSE Sign API is EXPERIMENTAL and may be changed or removed in a later
// release.
func ExampleSignMessage_detachedPayload() {
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
	msgToSign.Payload = nil // detach payload
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
	msgToVerify.Payload = []byte("hello world") // reattach payload
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

// This example demonstrates signing and verifying COSE_Sign1 signatures with
// detached payload.
func ExampleSign1Message_detachedPayload() {
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
	msgToSign.Payload = nil // detach payload
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
	msgToVerify.Payload = []byte("hello world") // reattach payload
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

// This example demonstrates signing and verifying COSE_Sign1 with a protected
// X.509 certificate chain. VerifyWithX5Chain returns the selected validated
// path so the application can apply its own certificate authorization policy.
func ExampleSign1Message_VerifyWithX5Chain() {
	leaf, err := x509.ParseCertificate(x509testdata.EndEntityDer)
	if err != nil {
		panic(err)
	}
	intermediate, err := x509.ParseCertificate(x509testdata.IntermediateCA)
	if err != nil {
		panic(err)
	}
	root, err := x509.ParseCertificate(x509testdata.RootCA)
	if err != nil {
		panic(err)
	}

	keyBlock, _ := pem.Decode(x509testdata.EndEntityKey)
	if keyBlock == nil {
		panic("invalid test signing key")
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		panic(err)
	}
	signer, err := cose.NewSigner(cose.AlgorithmES256, key)
	if err != nil {
		panic(err)
	}

	msg := cose.NewSign1Message()
	msg.Payload = []byte("hello world")
	msg.Headers.Protected.SetAlgorithm(cose.AlgorithmES256)
	if err := cose.SetX5Chain(msg.Headers.Protected, cose.X5Chain{
		Leaf:          leaf,
		Intermediates: []*x509.Certificate{intermediate},
	}); err != nil {
		panic(err)
	}
	if err := msg.Sign(rand.Reader, nil, signer); err != nil {
		panic(err)
	}
	wire, err := msg.MarshalCBOR()
	if err != nil {
		panic(err)
	}

	// A receiver verifies the decoded message, including its RawProtected header.
	var received cose.Sign1Message
	if err := received.UnmarshalCBOR(wire); err != nil {
		panic(err)
	}

	verifiedChain, err := received.VerifyWithX5Chain(nil, cose.TrustAnchors{
		Anchors:        []*x509.Certificate{root},
		RevocationMode: cose.RevocationDisabled, // This example supplies no CRLs.
	}, nil)
	if err != nil {
		panic(err)
	}
	if verifiedChain[0].Subject.CommonName != "Acme Gizmo CoRIM signer" {
		panic("unexpected signing certificate")
	}

	fmt.Printf("verified path length: %d\n", len(verifiedChain))
	fmt.Printf("authorized signer: %s\n", verifiedChain[0].Subject.CommonName)
	// Output:
	// verified path length: 3
	// authorized signer: Acme Gizmo CoRIM signer
}

// This example verifies a leaf-only x5chain by loading the root trust anchor and
// an omitted intermediate from files on disk.
func ExampleSign1Message_VerifyWithX5Chain_fromFiles() {
	leaf, err := x509.ParseCertificate(x509testdata.EndEntityDer)
	if err != nil {
		panic(err)
	}

	keyBlock, _ := pem.Decode(x509testdata.EndEntityKey)
	if keyBlock == nil {
		panic("invalid test signing key")
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		panic(err)
	}
	signer, err := cose.NewSigner(cose.AlgorithmES256, key)
	if err != nil {
		panic(err)
	}

	msg := cose.NewSign1Message()
	msg.Payload = []byte("hello world")
	msg.Headers.Protected.SetAlgorithm(cose.AlgorithmES256)
	// Present only the leaf; the verifier supplies the intermediate from disk.
	if err := cose.SetX5Chain(msg.Headers.Protected, cose.X5Chain{Leaf: leaf}); err != nil {
		panic(err)
	}
	if err := msg.Sign(rand.Reader, nil, signer); err != nil {
		panic(err)
	}
	wire, err := msg.MarshalCBOR()
	if err != nil {
		panic(err)
	}

	var received cose.Sign1Message
	if err := received.UnmarshalCBOR(wire); err != nil {
		panic(err)
	}

	anchors, err := cose.LoadTrustAnchors(os.ReadFile, []string{"testdata/x509/rootCA.der"}, nil)
	if err != nil {
		panic(err)
	}
	anchors.RevocationMode = cose.RevocationDisabled // This example supplies no CRLs.

	intermediateDER, err := os.ReadFile("testdata/x509/intermediateCA.der")
	if err != nil {
		panic(err)
	}
	intermediate, err := x509.ParseCertificate(intermediateDER)
	if err != nil {
		panic(err)
	}
	additional := x509.NewCertPool()
	additional.AddCert(intermediate)

	verifiedChain, err := received.VerifyWithX5Chain(nil, anchors, &cose.X5ChainVerifyOptions{
		AdditionalIntermediates: additional,
	})
	if err != nil {
		panic(err)
	}

	fmt.Printf("verified path length: %d\n", len(verifiedChain))
	fmt.Printf("authorized signer: %s\n", verifiedChain[0].Subject.CommonName)
	// Output:
	// verified path length: 3
	// authorized signer: Acme Gizmo CoRIM signer
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

// This example demonstrates signing and verifying COSE Hash Envelope.
//
// Reference: https://www.ietf.org/archive/id/draft-ietf-cose-hash-envelope-05.html
//
// Notice: The COSE Hash Envelope API is EXPERIMENTAL and may be changed or
// removed in a later release.
func Example_hashEnvelope() {
	// create message to be signed
	digested := sha512.Sum512([]byte("hello world"))
	payload := cose.HashEnvelopePayload{
		HashAlgorithm:       cose.AlgorithmSHA512,
		HashValue:           digested[:],
		PreimageContentType: "text/plain",
		Location:            "urn:example:location",
	}

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
	sig, err := cose.SignHashEnvelope(rand.Reader, signer, cose.Headers{
		Protected: cose.ProtectedHeader{
			cose.HeaderLabelAlgorithm: cose.AlgorithmES512,
		},
	}, payload)
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
	msg, err := cose.VerifyHashEnvelope(verifier, sig)
	if err != nil {
		panic(err)
	}
	fmt.Println("message verified")

	// check payload
	fmt.Printf("payload hash: %v: %x\n", msg.Headers.Protected[cose.HeaderLabelPayloadHashAlgorithm], msg.Payload)
	fmt.Println("payload content type:", msg.Headers.Protected[cose.HeaderLabelPayloadPreimageContentType])
	fmt.Println("payload location:", msg.Headers.Protected[cose.HeaderLabelPayloadLocation])
	// Output:
	// message signed
	// message verified
	// payload hash: SHA-512: 309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f
	// payload content type: text/plain
	// payload location: urn:example:location
}
