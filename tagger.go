package cose

import "errors"

// TODO find a better verb
type Tagger interface {
	Algorithm() Algorithm

	CreateTag(content []byte) ([]byte, error)
}

func NewTagger(alg Algorithm, key []byte) (Tagger, error) {
	switch alg {
	case AlgorithmHMAC256_256, AlgorithmHMAC384_384, AlgorithmHMAC512_512:
		if len(key) == 0 {
			return nil, errors.New("empty key")
		}
		return &hmacTagger{
			alg: alg,
			key: key,
		}, nil
	default:
		return nil, ErrAlgorithmNotSupported
	}
}
