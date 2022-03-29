package cose

import (
	"errors"
	"math/big"
)

// I2OSP - Integer-to-Octet-String primitive converts a nonnegative integer to
// an octet string of a specified length.
//
// Reference: https://datatracker.ietf.org/doc/html/rfc8017#section-4.1
func I2OSP(x *big.Int, xLen int) ([]byte, error) {
	if x.Sign() < 0 {
		return nil, errors.New("I2OSP: negative integer")
	}
	if len(x.Bits()) > xLen {
		return nil, errors.New("I2OSP: integer too large")
	}
	return x.FillBytes(make([]byte, xLen)), nil
}

// OS2IP - Octet-String-to-Integer primitive converts an octet string to a
// nonnegative integer.
//
// Reference: https://datatracker.ietf.org/doc/html/rfc8017#section-4.2
func OS2IP(x []byte) *big.Int {
	return new(big.Int).SetBytes(x)
}
