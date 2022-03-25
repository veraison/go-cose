package cose

import (
	"crypto"
	"hash"
)

// Algorithm represents an IANA algorithm entry in the COSE Algorithms registry.
//
// See Also
//
// COSE Algorithms: https://www.iana.org/assignments/cose/cose.xhtml#algorithms
//
// RFC 8152 16.4: https://datatracker.ietf.org/doc/html/rfc8152#section-16.4
type Algorithm struct {
	// Name of the algorithm.
	Name string

	// Value uniquely identified the algorithm.
	Value int

	// Hash is the hash algorithm associated with the algorithm.
	// If HashFunc presents, Hash is ignored.
	// If HashFunc does not present and Hash is set to 0, no hash is used.
	Hash crypto.Hash

	// HashFunc is the hash algorithm associated with the algorithm.
	// HashFunc is preferred in the case that the hash algorithm is not
	// supported by the golang build-in crypto hashes.
	// For regular scenarios, use Hash instead.
	HashFunc func() hash.Hash
}

// AlgorithmPS256 refers to RSASSA-PSS w/ SHA-256 by RFC 8230.
func AlgorithmPS256() Algorithm {
	return Algorithm{
		Name:  "PS256",
		Value: -37,
		Hash:  crypto.SHA256,
	}
}

// AlgorithmPS384 refers to RSASSA-PSS w/ SHA-384 by RFC 8230.
func AlgorithmPS384() Algorithm {
	return Algorithm{
		Name:  "PS384",
		Value: -38,
		Hash:  crypto.SHA384,
	}
}

// AlgorithmPS512 refers to RSASSA-PSS w/ SHA-512 by RFC 8230.
func AlgorithmPS512() Algorithm {
	return Algorithm{
		Name:  "PS512",
		Value: -39,
		Hash:  crypto.SHA512,
	}
}

// AlgorithmES256 refers to ECDSA w/ SHA-256 by RFC 8152.
func AlgorithmES256() Algorithm {
	return Algorithm{
		Name:  "ES256",
		Value: -7,
		Hash:  crypto.SHA256,
	}
}

// AlgorithmES384 refers to ECDSA w/ SHA-384 by RFC 8152.
func AlgorithmES384() Algorithm {
	return Algorithm{
		Name:  "ES384",
		Value: -35,
		Hash:  crypto.SHA384,
	}
}

// AlgorithmES512 refers to ECDSA w/ SHA-512 by RFC 8152.
func AlgorithmES512() Algorithm {
	return Algorithm{
		Name:  "ES512",
		Value: -36,
		Hash:  crypto.SHA512,
	}
}

// AlgorithmEd25519 refers to PureEdDSA by RFC 8152.
// As stated in RFC 8152 8.2, only the pure EdDSA version is used for COSE.
func AlgorithmEd25519() Algorithm {
	return Algorithm{
		Name:  "EdDSA",
		Value: -8,
	}
}
