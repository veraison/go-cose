package cose

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSign1Roundtrip(t *testing.T) {
	assert := assert.New(t)

	msg := NewSign1Message()
	msg.Payload = []byte("EAT token claims")

	signer, err := NewSigner(ES256, nil)
	assert.Nil(err, "signer creation failed")

	msg.Headers.Protected[algTag] = -7 // ECDSA w/ SHA-256

	external := []byte("")

	err = msg.Sign(rand.Reader, external, *signer)
	assert.Nil(err, "signature creation failed")
	assert.NotNil(msg.Signature, "nil signature")

	t.Logf("COSE signature: %x", msg.Signature)

	coseSig, err := Marshal(msg)
	assert.Nil(err, "COSE marshaling failed")

	t.Logf("COSE message: %x", coseSig)

	verifier := signer.Verifier()
	err = msg.Verify(external, *verifier)
	assert.Nil(err, "signature verification failed")
}
