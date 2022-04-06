package cose

import "errors"

// Common errors
var (
	ErrAlgorithmMismatch     = errors.New("algorithm mismatch")
	ErrAlgorithmNotFound     = errors.New("algorithm not found")
	ErrAlgorithmNotSupported = errors.New("algorithm not supported")
	ErrAlgorithmRegistered   = errors.New("algorithm registered")
	ErrInvalidAlgorithm      = errors.New("invalid algorithm")
	ErrNoSignatures          = errors.New("no signatures attached")
	ErrUnavailableHashFunc   = errors.New("hash function is not available")
	ErrUnknownAlgorithm      = errors.New("unknown algorithm")
	ErrVerification          = errors.New("verification error")
)
