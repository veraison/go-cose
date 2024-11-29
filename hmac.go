package cose

import (
	"bytes"
	"crypto/hmac"
	"errors"
)

type hmacTagger struct {
	alg Algorithm
	key []byte
}

func (ht *hmacTagger) Algorithm() Algorithm {
	return ht.alg
}

func (ht *hmacTagger) CreateTag(content []byte) ([]byte, error) {
	h := ht.alg.hashFunc()
	if h == 0 {
		return nil, errors.New("TODO no hash")
	}

	hm := hmac.New(h.HashFunc().New, ht.key)

	_, err := hm.Write(content)
	if err != nil {
		return nil, err
	}

	return hm.Sum(nil), nil
}

type hmacAuthenticator hmacTagger

func (ha *hmacAuthenticator) Algorithm() Algorithm {
	return ha.alg
}

func (ha *hmacAuthenticator) AuthenticateTag(content, tag []byte) error {
	h := ha.alg.hashFunc()
	if h == 0 {
		return errors.New("TODO no hash")
	}

	hm := hmac.New(h.HashFunc().New, ha.key)

	_, err := hm.Write(content)
	if err != nil {
		return err
	}

	if !bytes.Equal(hm.Sum(nil), tag) {
		return ErrAuthentication
	}

	return nil
}
