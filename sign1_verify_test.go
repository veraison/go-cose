package cose

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSign1_Roundtrip(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	msg := NewSign1Message()
	msg.Payload = []byte("EAT token claims")

	signer, err := NewSigner(ES256, nil)
	require.Nil(err, "signer creation failed")

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

func TestSign1_SignErrors(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	signer, err := NewSigner(ES256, nil)
	require.Nil(err, "signer creation failed")

	external := []byte("")

	// empty Sign1 structure has nil Headers
	invalid := &Sign1Message{}

	err = invalid.Sign(rand.Reader, external, *signer)
	assert.Equal(err, ErrNilSign1Headers)

	// empty Headers structure has nil ProtectedHeaders
	invalid.Headers = &Headers{}

	err = invalid.Sign(rand.Reader, external, *signer)
	assert.Equal(err, ErrNilSign1ProtectedHeaders)

	// signature should be empty before signature is applied
	invalid.Signature = []byte("fake signature")

	err = invalid.Sign(rand.Reader, external, *signer)
	assert.EqualError(err, "Sign1Message signature already has signature bytes")

	// empty protected headers don't carry any signature alg
	invalid.Signature = nil
	invalid.Headers.Protected = map[interface{}]interface{}{}

	err = invalid.Sign(rand.Reader, external, *signer)
	assert.EqualError(err, "Error fetching alg")

	// an inconsistent algorithm
	invalid.Headers.Protected[algTag] = 1 // should be -7, i.e.: ECDSA w/ SHA-256

	err = invalid.Sign(rand.Reader, external, *signer)
	assert.EqualError(err, "Invalid algorithm")

	// an inconsistent signing key
	invalid.Headers.Protected[algTag] = -7 // ECDSA w/ SHA-256
	signer.PrivateKey = dsaPrivateKey

	err = invalid.Sign(rand.Reader, external, *signer)
	assert.EqualError(err, "Unrecognized private key type")

	// an inconsistent signer
	signer.alg = PS256

	err = invalid.Sign(rand.Reader, external, *signer)
	assert.EqualError(err, "Signer of type PS256 cannot generate a signature of type ES256")

	// unknown algorithm id
	invalid.Headers.Protected[algTag] = -9000

	err = invalid.Sign(rand.Reader, external, *signer)
	assert.EqualError(err, "Algorithm with value -9000 not found")
}

func TestSign1_VerifyErrors(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	invalid := &Sign1Message{}

	signer, err := NewSigner(ES256, nil)
	require.Nil(err)

	verifier := signer.Verifier()

	external := []byte("")

	err = invalid.Verify(external, *verifier)
	assert.EqualError(err, "Sign1Message has no signature to verify")

	invalid.Signature = []byte("fake signature")
	invalid.Headers = nil

	err = invalid.Verify(external, *verifier)
	assert.Equal(err, ErrNilSign1Headers)

	invalid.Headers = &Headers{}

	err = invalid.Verify(external, *verifier)
	assert.Equal(err, ErrNilSign1ProtectedHeaders)

	invalid.Headers.Protected = map[interface{}]interface{}{}

	invalid.Headers.Protected[algTag] = -9000

	err = invalid.Verify(external, *verifier)
	assert.EqualError(err, "Algorithm with value -9000 not found")

	invalid.Headers.Protected[algTag] = -41

	err = invalid.Verify(external, *verifier)
	assert.EqualError(err, "hash function is not available")

	invalid.Headers.Protected[algTag] = 1

	err = invalid.Verify(external, *verifier)
	assert.EqualError(err, "Invalid algorithm")

	invalid.Headers.Protected[algTag] = -7

	err = invalid.Verify(external, *verifier)
	assert.EqualError(err, "invalid signature length: 14")
}
