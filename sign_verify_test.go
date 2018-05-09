package cose

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestSignErrors(t *testing.T) {
	assert := assert.New(t)

	msg := NewSignMessage()
	msg.Payload = []byte("payload to sign")

	signer, err := NewSigner(ES256, nil)
	assert.Nil(err, fmt.Sprintf("Error creating signer %s", err))

	sig := NewSignature()
	sig.Headers.Protected[algTag] = -41 // RSAES-OAEP w/ SHA-256 from [RFC8230]
	sig.Headers.Protected[kidTag] = 1

	msg.Signatures = []Signature{}
	err = msg.Sign(rand.Reader, []byte(""), []Signer{*signer})
	assert.Equal(ErrNoSignatures, err)

	msg.Signatures = nil
	err = msg.Sign(rand.Reader, []byte(""), []Signer{*signer})
	assert.Equal(ErrNilSignatures, err)

	// check that it creates the signatures array from nil
	msg.AddSignature(sig)
	assert.Equal(len(msg.Signatures), 1)

	msg.Signatures[0].Headers = nil
	err = msg.Sign(rand.Reader, []byte(""), []Signer{*signer})
	assert.Equal(ErrNilSigHeader, err)

	msg.Signatures = nil
	msg.AddSignature(sig)
	msg.Signatures[0].Headers.Protected = nil
	err = msg.Sign(rand.Reader, []byte(""), []Signer{*signer})
	assert.Equal(ErrNilSigProtectedHeaders, err)

	msg.Signatures = nil
	sig.Headers.Protected = map[interface{}]interface{}{}
	sig.Headers.Protected[algTag] = -41 // RSAES-OAEP w/ SHA-256 from [RFC8230]
	sig.Headers.Protected[kidTag] = 1
	sig.SignatureBytes = []byte("already signed")

	msg.AddSignature(sig)
	assert.Equal(len(msg.Signatures), 1)
	assert.NotNil(msg.Signatures[0].Headers)

	err = msg.Sign(rand.Reader, []byte(""), []Signer{})
	assert.Equal(errors.New("0 signers for 1 signatures"), err)

	err = msg.Sign(rand.Reader, []byte(""), []Signer{*signer})
	assert.Equal(errors.New("SignMessage signature 0 already has signature bytes"), err)

	msg.Signatures[0].SignatureBytes = nil
	err = msg.Sign(rand.Reader, []byte(""), []Signer{*signer})
	assert.Equal(ErrUnavailableHashFunc, err)

	msg.Signatures[0].Headers.Protected[algTag] = ES256.Value
	signer.alg = ES256
	signer.privateKey = dsaPrivateKey
	err = msg.Sign(rand.Reader, []byte(""), []Signer{*signer})
	assert.Equal(ErrUnknownPrivateKeyType, err)

	signer.alg = PS256
	err = msg.Sign(rand.Reader, []byte(""), []Signer{*signer})
	assert.Equal(errors.New("Signer of type PS256 cannot generate a signature of type ES256"), err)

	msg.Signatures[0].Headers.Protected[algTag] = -9000
	err = msg.Sign(rand.Reader, []byte(""), []Signer{*signer})
	assert.Equal(errors.New("Algorithm with value -9000 not found"), err)

	msg.Signatures[0].Headers.Protected[algTag] = 1
	err = msg.Sign(rand.Reader, []byte(""), []Signer{*signer})
	assert.Equal(ErrInvalidAlg, err)

	delete(msg.Signatures[0].Headers.Protected, algTag)
	err = msg.Sign(rand.Reader, []byte(""), []Signer{*signer})
	assert.Equal(ErrAlgNotFound, err)

	// TODO: make Marshal fail
	// msg.Signatures[0].Headers.Protected[algTag] = -7
	// msg.Signatures[0].Headers.Unprotected = nil

	// err = msg.Sign(rand.Reader, []byte(""), []Signer{*signer})
	// assert.Equal(errors.New("Algorithm with value -9000 not found"), err)
}

func TestVerifyErrors(t *testing.T) {
	assert := assert.New(t)

	msg := NewSignMessage()
	msg.Payload = []byte("payload to sign")


	sig := NewSignature()
	sig.Headers.Protected[algTag] = -41 // RSAES-OAEP w/ SHA-256 from [RFC8230]
	sig.Headers.Protected[kidTag] = 1

	signer, err := NewSigner(ES256, nil)
	assert.Nil(err, "Error creating signer")

	verifier := signer.Verifier(ES256)
	assert.Nil(err, "Error creating verifier")

	verifiers := []Verifier{*verifier}
	payload := []byte("")

	msg.Signatures = []Signature{}
	assert.Nil(msg.Verify(payload, verifiers))

	msg.Signatures = nil
	assert.Nil(msg.Verify(payload, verifiers))

	msg.AddSignature(sig)
	msg.Signatures[0].Headers.Protected = nil
	assert.Equal(ErrNilSigProtectedHeaders, msg.Verify(payload, verifiers))

	msg.Signatures[0].Headers = nil
	assert.Equal(ErrNilSigHeader, msg.Verify(payload, verifiers))

	sig = NewSignature()
	sig.Headers.Protected[algTag] = -41 // RSAES-OAEP w/ SHA-256 from [RFC8230]
	sig.Headers.Protected[kidTag] = 1
	msg.Signatures[0] = *sig
	assert.Equal(errors.New("SignMessage signature 0 missing signature bytes to verify"), msg.Verify(payload, verifiers))

	msg.Signatures[0].Headers.Protected[algTag] = -41 // RSAES-OAEP w/ SHA-256 from [RFC8230]
	msg.Signatures[0].Headers.Protected[kidTag] = 1
	msg.Signatures[0].SignatureBytes = []byte("already signed")
	assert.Equal(ErrUnavailableHashFunc, msg.Verify(payload, verifiers))

	msg.Signatures[0].Headers.Protected[algTag] = 1
	assert.Equal(ErrInvalidAlg, msg.Verify(payload, verifiers))

	msg.Signatures[0].Headers.Protected[algTag] = -7 // ECDSA w/ SHA-256 from [RFC8152]
	assert.Equal(errors.New("Wrong number of signatures 1 and verifiers 0"), msg.Verify(payload, []Verifier{}))

	verifiers = []Verifier{
		Verifier{
			publicKey: &ecdsa.PublicKey{
				Curve: elliptic.P384(),
				X:     FromBase64Int("usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8"),
				Y:     FromBase64Int("IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4"),
			},
			alg: ES256,
		},
	}
	assert.Equal(errors.New("Expected 256 bit key, got 384 bits instead"), msg.Verify(payload, verifiers))

	verifiers = []Verifier{
		Verifier{
			publicKey: ecdsaPrivateKey.Public(),
			alg: ES256,
		},
	}
	assert.Equal(errors.New("invalid signature length: 14"), msg.Verify(payload, verifiers))
}
