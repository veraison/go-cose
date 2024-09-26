package cose

import "errors"

// Authenticator is an interface for keys to authenticate COSE MACs.
type Authenticator interface {
	// Algorithm returns the MAC algorithm associated with the key.
	Algorithm() Algorithm

	// AuthenticateTag authenticates the message content with the key, returning
	// nil for success.
	// Otherwise, it returns ErrAuthentication.
	//
	// Reference: https://datatracker.ietf.org/doc/html/rfc8152#section-9
	AuthenticateTag(content, tag []byte) error
}

// NewAuthenticator returns an Authenticator with a given key.
// Only golang built-in HMAC is supported.
func NewAuthenticator(alg Algorithm, key []byte) (Authenticator, error) {
	switch alg {
	case AlgorithmHMAC256_256, AlgorithmHMAC384_384, AlgorithmHMAC512_512:
		// TODO key length? I can't find an concrete recommendation for this,
		//
		// len(key) == L where L is output length is usual.
		// Shorter keys are padded, longer keys are hashed.
		// HMAC 256 L = 32 bytes
		// HMAC 384 L = 48 bytes
		// HMAC 512 L = 64 bytes
		//
		// https://datatracker.ietf.org/doc/html/rfc8152#section-9.1:
		// Implementations creating and validating MAC values MUST validate that
		// the key type, key length, and algorithm are correct and appropriate
		// for the entities involved.
		//
		// https://datatracker.ietf.org/doc/html/rfc2104#section-3:
		// The key for HMAC can be of any length (keys longer than B bytes are
		// first hashed using H).  However, less than L bytes is strongly
		// discouraged as it would decrease the security strength of the
		// function.  Keys longer than L bytes are acceptable but the extra
		// length would not significantly increase the function strength. (A
		// longer key may be advisable if the randomness of the key is
		// considered weak.)
		if len(key) == 0 {
			return nil, errors.New("empty key")
		}
		return &hmacAuthenticator{
			alg: alg,
			key: key,
		}, nil
	default:
		return nil, ErrAlgorithmNotSupported
	}
}
