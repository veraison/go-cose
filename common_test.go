package cose

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

func Test_intOrStr(t *testing.T) {
	ios := newIntOrStr(3)
	assertEqual(t, true, ios.IsInt())
	assertEqual(t, false, ios.IsString())
	assertEqual(t, 3, ios.Int())
	assertEqual(t, "3", ios.String())

	ios = newIntOrStr("foo")
	assertEqual(t, false, ios.IsInt())
	assertEqual(t, true, ios.IsString())
	assertEqual(t, 0, ios.Int())
	assertEqual(t, "foo", ios.String())

	ios = newIntOrStr(3.5)
	if ios != nil {
		t.Errorf("Expected nil, got %v", ios)
	}
}

func Test_intOrStr_CBOR(t *testing.T) {
	ios := newIntOrStr(3)
	data, err := ios.MarshalCBOR()
	requireNoError(t, err)
	assertEqual(t, []byte{0x03}, data)

	ios = &intOrStr{}
	err = ios.UnmarshalCBOR(data)
	requireNoError(t, err)
	assertEqual(t, true, ios.IsInt())
	assertEqual(t, 3, ios.Int())

	ios = newIntOrStr("foo")
	data, err = ios.MarshalCBOR()
	requireNoError(t, err)
	assertEqual(t, []byte{0x63, 0x66, 0x6f, 0x6f}, data)

	ios = &intOrStr{}
	err = ios.UnmarshalCBOR(data)
	requireNoError(t, err)
	assertEqual(t, true, ios.IsString())
	assertEqual(t, "foo", ios.String())

	// empty value as field
	s := struct {
		Field1 intOrStr `cbor:"1,keyasint"`
		Field2 int      `cbor:"2,keyasint"`
	}{Field1: intOrStr{}, Field2: 7}

	data, err = cbor.Marshal(s)
	requireNoError(t, err)
	assertEqual(t, []byte{0xa2, 0x1, 0x00, 0x2, 0x7}, data)

	ios = &intOrStr{}
	data = []byte{0x22}
	err = ios.UnmarshalCBOR(data)
	requireNoError(t, err)
	assertEqual(t, true, ios.IsInt())
	assertEqual(t, -3, ios.Int())

	data = []byte{}
	err = ios.UnmarshalCBOR(data)
	assertEqualError(t, err, "zero length buffer")

	data = []byte{0x40}
	err = ios.UnmarshalCBOR(data)
	assertEqualError(t, err, "must be int or string, found []uint8")

	data = []byte{0xff, 0xff}
	err = ios.UnmarshalCBOR(data)
	assertEqualError(t, err, "cbor: unexpected \"break\" code")
}

func requireNoError(t *testing.T, err error) {
	if err != nil {
		t.Errorf("Unexpected error: %q", err)
		t.Fail()
	}
}

func assertEqualError(t *testing.T, err error, expected string) {
	if err == nil || err.Error() != expected {
		t.Errorf("Unexpected error: want %q, got %q", expected, err)
	}
}

func assertEqual(t *testing.T, expected, actual interface{}) {
	if !objectsAreEqualValues(expected, actual) {
		t.Errorf("Unexpected value: want %v, got %v", expected, actual)
	}
}

// taken from github.com/stretchr/testify
func objectsAreEqualValues(expected, actual interface{}) bool {
	if objectsAreEqual(expected, actual) {
		return true
	}

	actualType := reflect.TypeOf(actual)
	if actualType == nil {
		return false
	}
	expectedValue := reflect.ValueOf(expected)
	if expectedValue.IsValid() && expectedValue.Type().ConvertibleTo(actualType) {
		// Attempt comparison after type conversion
		return reflect.DeepEqual(expectedValue.Convert(actualType).Interface(), actual)
	}

	return false
}

// taken from github.com/stretchr/testify
func objectsAreEqual(expected, actual interface{}) bool {
	if expected == nil || actual == nil {
		return expected == actual
	}

	exp, ok := expected.([]byte)
	if !ok {
		return reflect.DeepEqual(expected, actual)
	}

	act, ok := actual.([]byte)
	if !ok {
		return false
	}
	if exp == nil || act == nil {
		return exp == nil && act == nil
	}
	return bytes.Equal(exp, act)
}
