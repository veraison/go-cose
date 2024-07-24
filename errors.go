package cose

import "errors"

// Common errors
var (
	ErrAlgorithmMismatch     = errors.New("algorithm mismatch")
	ErrAlgorithmNotFound     = errors.New("algorithm not found")
	ErrAlgorithmNotSupported = errors.New("algorithm not supported")
	ErrEmptySignature        = errors.New("empty signature")
	ErrInvalidAlgorithm      = errors.New("invalid algorithm")
	ErrMissingPayload        = errors.New("missing payload")
	ErrMultiplePayloads      = errors.New("multiple payloads")
	ErrNoSignatures          = errors.New("no signatures attached")
	ErrUnavailableHashFunc   = errors.New("hash function is not available")
	ErrVerification          = errors.New("verification error")
	ErrEmptyTag              = errors.New("empty tag")
	ErrAuthentication        = errors.New("authentication error")
	ErrInvalidKey            = errors.New("invalid key")
	ErrInvalidPubKey         = errors.New("invalid public key")
	ErrInvalidPrivKey        = errors.New("invalid private key")
	ErrNotPrivKey            = errors.New("not a private key")
	ErrOpNotSupported        = errors.New("key_op not supported by key")
	ErrEC2NoPub              = errors.New("cannot create PrivateKey from EC2 key: missing x or y")
	ErrOKPNoPub              = errors.New("cannot create PrivateKey from OKP key: missing x")
)
