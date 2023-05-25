package cose

import (
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_IntOrStr(t *testing.T) {
	ios := newIntOrStr(3)
	assert.True(t, ios.IsInt())
	assert.False(t, ios.IsString())
	assert.EqualValues(t, 3, ios.Int())
	assert.Equal(t, "3", ios.String())
	assert.NotPanics(t, func() { _ = ios.Value().(int64) })

	ios = newIntOrStr("foo")
	assert.False(t, ios.IsInt())
	assert.True(t, ios.IsString())
	assert.EqualValues(t, 0, ios.Int())
	assert.Equal(t, "foo", ios.String())
	assert.NotPanics(t, func() { _ = ios.Value().(string) })

	ios = newIntOrStr(3.5)
	assert.Nil(t, ios)
}

func Test_IntOrStr_CBOR(t *testing.T) {
	ios := newIntOrStr(3)
	data, err := ios.MarshalCBOR()
	require.NoError(t, err)
	assert.Equal(t, []byte{0x03}, data)

	ios = &intOrStr{}
	err = ios.UnmarshalCBOR(data)
	require.NoError(t, err)
	assert.True(t, ios.IsInt())
	assert.EqualValues(t, 3, ios.Int())

	ios = newIntOrStr("foo")
	data, err = ios.MarshalCBOR()
	require.NoError(t, err)
	assert.Equal(t, []byte{0x63, 0x66, 0x6f, 0x6f}, data)

	ios = &intOrStr{}
	err = ios.UnmarshalCBOR(data)
	require.NoError(t, err)
	assert.True(t, ios.IsString())
	assert.Equal(t, "foo", ios.String())

	// empty value as field
	s := struct {
		Field1 intOrStr `cbor:"1,keyasint"`
		Field2 int      `cbor:"2,keyasint"`
	}{Field1: intOrStr{}, Field2: 7}

	data, err = cbor.Marshal(s)
	require.NoError(t, err)
	assert.Equal(t, []byte{0xa2, 0x1, 0x00, 0x2, 0x7}, data)

	ios = &intOrStr{}
	data = []byte{0x22}
	err = ios.UnmarshalCBOR(data)
	require.NoError(t, err)
	assert.True(t, ios.IsInt())
	assert.EqualValues(t, -3, ios.Int())

	data = []byte{}
	err = ios.UnmarshalCBOR(data)
	assert.EqualError(t, err, "zero length buffer")

	data = []byte{0x40}
	err = ios.UnmarshalCBOR(data)
	assert.EqualError(t, err, "must be int or string, found []uint8")
}
