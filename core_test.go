package cose

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestVerifyInvalidAlgErrors(t *testing.T) {
	assert := assert.New(t)

	ecdsaPrivateKey := ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     FromBase64Int("usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8"),
			Y:     FromBase64Int("IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4"),
		},
		D: FromBase64Int("V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM"),
	}

	signer, err := NewSigner(&ecdsaPrivateKey)
	assert.Nil(err, "Error creating signer")

	verifier := signer.Verifier(GetAlgByNameOrPanic("A128GCM"))
	assert.Nil(err, "Error creating verifier")

	err = verifier.Verify([]byte(""), []byte(""))
	assert.Equal(ErrInvalidAlg, err)
}
