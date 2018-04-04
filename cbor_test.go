package cose

import (
	"errors"
	"fmt"
	"github.com/stretchr/testify/assert"
	codec "github.com/ugorji/go/codec"
	"reflect"
	"testing"
)

/// Tests for encoding and decoding go-cose objects to and from CBOR
// TODO: combine into a single test that: round trips and checks expected marshal / unmarshal results

type CBORTestCase struct {
	name  string
	obj   interface{}
	bytes []byte
}

var CBORTestCases = []CBORTestCase{
	// golang data structures
	{
		"empty bstr",
		[]byte(""),
		[]byte("\x40"), // bytes(0) i.e. ""
	},
	{
		"generic interface map",
		map[interface{}]interface{}{uint64(1): int64(-7)},
		HexToBytesOrDie("A10126"),
	},

	// Headers
	{
		"empty headers",
		Headers{
			Protected:   map[interface{}]interface{}{},
			Unprotected: map[interface{}]interface{}{},
		},
		[]byte("\x40"),
	},
	{
		"alg in protected header",
		Headers{
			Protected:   map[interface{}]interface{}{"alg": "ES256"},
			Unprotected: map[interface{}]interface{}{},
		},
		// 0x43 for bytes h'A10126'
		// decoding h'A10126' gives:
		//     A1    # map(1)
		//       01 # unsigned(1)
		//       26 # negative(7)
		[]byte("\x43\xA1\x01\x26"),
	},
	{
		"alg in unprotected header",
		Headers{
			Protected:   map[interface{}]interface{}{},
			Unprotected: map[interface{}]interface{}{"alg": "ES256"},
		},
		[]byte("\x40"),
	},
	{
		"duplicate key across protected and unprotected maps",
		// TODO: throw a duplicate key error?
		Headers{
			Protected: map[interface{}]interface{}{
				"alg": "ES256",
			},
			Unprotected: map[interface{}]interface{}{
				"alg": "PS256",
			},
		},
		HexToBytesOrDie("43a10126"), // see "alg in protected header" comment
	},
	// TODO: test this despite golang not allowing duplicate key "alg" in map literal
	// {
	// 	"duplicate key in protected",
	// 	[]byte(""),
	// 	Headers{
	// 		Protected: map[interface{}]interface{}{
	// 			"alg": "ES256",
	// 			"alg": "PS256",
	// 		},
	// 		Unprotected: map[interface{}]interface{}{},
	// 	},
	// },
	// {
	// 	"duplicate key in unprotected",
	// 	Headers{
	// 		Protected: map[interface{}]interface{}{},
	// 		Unprotected: map[interface{}]interface{}{
	// 			"alg": "ES256",
	// 			"alg": "PS256",
	// 		},
	// 	},
	// 	[]byte(""),
	// },
}

func MarshalsToExpectedBytes(t *testing.T, testCase CBORTestCase) {
	assert := assert.New(t)

	bytes, err := Marshal(testCase.obj)
	assert.Nil(err)

	assert.Equal(testCase.bytes, bytes)
}

func UnmarshalsToExpectedInterface(t *testing.T, testCase CBORTestCase) {
	assert := assert.New(t)

	_, err := Unmarshal(testCase.bytes)
	assert.Nil(err)

	// TODO: support untagged messages
	// assert.Equal(testCase.obj, obj)
}

func RoundtripsToExpectedBytes(t *testing.T, testCase CBORTestCase) {
	assert := assert.New(t)

	obj, err := Unmarshal(testCase.bytes)
	assert.Nil(err)

	bytes, err := Marshal(obj)
	assert.Nil(err)

	assert.Equal(testCase.bytes, bytes)
}

func TestCBOREncoding(t *testing.T) {
	for _, testCase := range CBORTestCases {
		t.Run(fmt.Sprintf("%s: MarshalsToExpectedBytes", testCase.name), func(t *testing.T) {
			MarshalsToExpectedBytes(t, testCase)
		})

		t.Run(fmt.Sprintf("%s: UnmarshalsToExpectedInterface", testCase.name), func(t *testing.T) {
			UnmarshalsToExpectedInterface(t, testCase)
		})

		t.Run(fmt.Sprintf("%s: RoundtripsToExpectedBytes", testCase.name), func(t *testing.T) {
			RoundtripsToExpectedBytes(t, testCase)
		})
	}
}

func TestCBOREncodingErrsOnUnexpectedType(t *testing.T) {
	assert := assert.New(t)

	type Flub struct {
		foo string
	}
	obj := Flub{
		foo: "not a SignMessage",
	}

	h := GetCOSEHandle()
	var cExt Ext
	h.SetInterfaceExt(reflect.TypeOf(obj), SignMessageCBORTag, cExt)

	var b []byte
	var enc *codec.Encoder = codec.NewEncoderBytes(&b, h)

	err := enc.Encode(obj)
	assert.Equal(errors.New("cbor encode error: unsupported format expecting to encode SignMessage; got *cose.Flub"), err)
}

func TestCBORDecodingErrors(t *testing.T) {
	assert := assert.New(t)

	type DecodeErrorTestCase struct {
		bytes        []byte
		errorMessage string
	}
	var cases = []DecodeErrorTestCase{
		{
			HexToBytesOrDie("D862" + "60"), // tag(98) + text(0)
			"cbor decode error [pos 3]: unsupported format expecting to decode from []interface{}; got string",
		},
		{
			HexToBytesOrDie("D862" + "80"), // tag(98) + array(0)
			"cbor decode error [pos 3]: can only decode SignMessage with 4 fields; got 0",
		},
		{
			// tag(98) + array(4) [ 4 * text(0) ]
			HexToBytesOrDie("D862" + "84" + "60" + "60" + "60" + "60"),
			"cbor decode error [pos 7]: error decoding header bytes; got error casting protected header bytes; got string",
		},
		{
			// tag(98) + array(4) [ bytes(0), map(0), 2 * text(0) ]
			HexToBytesOrDie("D862" + "84" + "40" + "A0" + "60" + "60"),
			"cbor decode error [pos 7]: error decoding msg payload decode from interface{} to []byte; got string",
		},
		{
			// tag(98) + array(4) [ bytes(0), map(0), bytes(0), text(0) ]
			HexToBytesOrDie("D862" + "84" + "40" + "A0" + "40" + "60"),
			"cbor decode error [pos 7]: error decoding sigs; got string",
		},
		// {
		// 	// tag(98) + array(4) [ bytes(0), map(0), bytes(0), array(0) ]
		// 	HexToBytesOrDie("D862" + "84" + "40" + "A0" + "40" + "80"),
		// 	"cbor decode error [pos 7]: error decoding sigs; got string",
		// },
	}

	for _, testCase := range cases {
		result, err := Unmarshal(testCase.bytes)
		assert.Nil(result)
		assert.Equal(errors.New(testCase.errorMessage), err)
	}

	// test decoding into the wrong dest type
	type Flub struct {
		foo string
	}
	obj := Flub{
		foo: "not a SignMessage",
	}

	h := GetCOSEHandle()
	var cExt Ext
	h.SetInterfaceExt(reflect.TypeOf(obj), SignMessageCBORTag, cExt)

	// tag(98) + array(4) [ bytes(0), map(0), bytes(0), array(0) ]
	var dec *codec.Decoder = codec.NewDecoderBytes(HexToBytesOrDie("D862"+"84"+"40"+"A0"+"40"+"80"), h)

	err := dec.Decode(&obj)
	assert.Equal(errors.New("cbor decode error [pos 7]: unsupported format expecting to decode into *SignMessage; got *cose.Flub"), err)
}
