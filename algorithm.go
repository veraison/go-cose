package cose

import (
	"crypto"
	"hash"
	"strconv"
)

// Algorithms supported by this library.
const (
	AlgorithmPS256   Algorithm = -37 // RSASSA-PSS w/ SHA-256 by RFC 8230
	AlgorithmPS384             = -38 // RSASSA-PSS w/ SHA-384 by RFC 8230
	AlgorithmPS512             = -39 // RSASSA-PSS w/ SHA-512 by RFC 8230
	AlgorithmES256             = -7  // ECDSA w/ SHA-256 by RFC 8152
	AlgorithmES384             = -35 // ECDSA w/ SHA-384 by RFC 8152
	AlgorithmES512             = -36 // ECDSA w/ SHA-512 by RFC 8152
	AlgorithmEd25519           = -8  // PureEdDSA by RFC 8152
)

// Algorithm represents an IANA algorithm entry in the COSE Algorithms registry.
// Algorithms with string values are not supported.
//
// See Also
//
// COSE Algorithms: https://www.iana.org/assignments/cose/cose.xhtml#algorithms
//
// RFC 8152 16.4: https://datatracker.ietf.org/doc/html/rfc8152#section-16.4
type Algorithm int

// extAlgorithm describes an extended algorithm, which is not implemented this
// library.
type extAlgorithm struct {
	// Name of the algorithm.
	Name string

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

// extAlgorithms contains extended algorithms.
var extAlgorithms map[Algorithm]extAlgorithm

// String returns the name of the algorithm
func (a Algorithm) String() string {
	switch a {
	case AlgorithmPS256:
		return "PS256"
	case AlgorithmPS384:
		return "PS384"
	case AlgorithmPS512:
		return "PS512"
	case AlgorithmES256:
		return "ES256"
	case AlgorithmES384:
		return "ES384"
	case AlgorithmES512:
		return "ES512"
	case AlgorithmEd25519:
		// As stated in RFC 8152 8.2, only the pure EdDSA version is used for
		// COSE.
		return "EdDSA"
	}
	if alg, ok := extAlgorithms[a]; ok {
		return alg.Name
	}
	return "unknown algorithm value " + strconv.Itoa(int(a))
}

// HashFunc returns the hash associated with the algorithm to implement
// crypto.SignerOpts.
func (a Algorithm) HashFunc() crypto.Hash {
	if h, ok := a.hashFunc(); ok {
		return h
	}
	if alg, ok := extAlgorithms[a]; ok {
		return alg.Hash
	}
	panic("cose: unknown algorithm value " + strconv.Itoa(int(a)))
}

// hashFunc returns the hash associated with the algorithm supported by this
// library.
func (a Algorithm) hashFunc() (crypto.Hash, bool) {
	switch a {
	case AlgorithmPS256, AlgorithmES256:
		return crypto.SHA256, true
	case AlgorithmPS384, AlgorithmES384:
		return crypto.SHA384, true
	case AlgorithmPS512, AlgorithmES512:
		return crypto.SHA512, true
	case AlgorithmEd25519:
		return 0, true
	}
	return 0, false
}

// NewHash returns a new hash instance for computing the digest specified in the
// algorithm.
// Returns nil if no hash is required for the message.
func (a Algorithm) NewHash() (hash.Hash, error) {
	h, ok := a.hashFunc()
	if !ok {
		alg, ok := extAlgorithms[a]
		if !ok {
			return nil, ErrUnknownAlgorithm
		}
		if alg.HashFunc != nil {
			return alg.HashFunc(), nil
		}
		h = alg.Hash
	}
	if h == 0 {
		// no hash required
		return nil, nil
	}
	if h.Available() {
		return h.New(), nil
	}
	return nil, ErrUnavailableHashFunc
}

// RegisterAlgorithm provides extensibility for the cose library to support
// private algorithms or algorithms not yet registered in IANA.
// The existing algorithms cannot be re-registered.
// The parameter `hash` is the hash algorithm associated with the algorithm. If
// hashFunc presents, hash is ignored. If hashFunc does not present and hash is
// set to 0, no hash is used for this algorithm.
// The parameter `hashFunc`` is preferred in the case that the hash algorithm is not
// supported by the golang build-in crypto hashes.
func RegisterAlgorithm(alg Algorithm, name string, hash crypto.Hash, hashFunc func() hash.Hash) error {
	if _, ok := alg.hashFunc(); ok {
		return ErrAlgorithmRegistered
	}
	if _, ok := extAlgorithms[alg]; ok {
		return ErrAlgorithmRegistered
	}
	extAlgorithms[alg] = extAlgorithm{
		Name:     name,
		Hash:     hash,
		HashFunc: hashFunc,
	}
	return nil
}
