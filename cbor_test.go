package cose

import (
	"errors"
	"fmt"
	"github.com/stretchr/testify/assert"
	codec "github.com/ugorji/go/codec"
	"reflect"
	"testing"
)

// Tests for encoding and decoding go-cose objects to and from CBOR

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

	// SignMessage Headers
	{
		"sign message with empty headers",
		SignMessage{
			Headers: &Headers{
				Protected:   map[interface{}]interface{}{},
				Unprotected: map[interface{}]interface{}{},
			},
			Payload:    nil,
			Signatures: nil,
		},
		// D8 62     # tag(98) COSE SignMessage tag
		//    84     # array(4)
		//       40  # bytes(0) empty protected headers
		//           # ""
		//       A0  # map(0) empty unprotectd headers
		//       F6  # primitive(22) nil / null payload
		//       80  # array(0) no signatures
		[]byte("\xd8\x62\x84\x40\xa0\xf6\x80"),
	},
	{
		"sign message with alg in protected header",
		SignMessage{
			Headers: &Headers{
				Protected:   map[interface{}]interface{}{"alg": "ES256"},
				Unprotected: map[interface{}]interface{}{},
			},
			Payload:    nil,
			Signatures: nil,
		},
		// D8 62           # tag(98) COSE SignMessage tag
		//    84           # array(4)
		//       43        # bytes(3) bstr protected header
		//          A10126 # "\xA1\x01&"
		//       A0        # map(0) empty unprotected headers
		//       F6        # primitive(22) nil / null payload
		//       80        # array(0) no signatures
		//
		// where bstr h'A10126' is:
		//     A1   # map(1)
		//       01 # unsigned(1) common header ID for alg
		//       26 # negative(7) ES256 alg ID
		[]byte("\xd8\x62\x84\x43\xa1\x01\x26\xa0\xf6\x80"),
	},
	{
		"sign message with alg in unprotected header",
		SignMessage{
			Headers: &Headers{
				Protected:   map[interface{}]interface{}{},
				Unprotected: map[interface{}]interface{}{"alg": "ES256"},
			},
			Payload:    nil,
			Signatures: nil,
		},
		// D8 62        # tag(98) COSE SignMessage tag
		//    84        # array(4)
		//       40     # bytes(0) empty protected headers
		//              # ""
		//       A1     # map(1) unprotected headers
		//          01  # unsigned(1) common header ID for alg
		//          26  # negative(7) ES256 alg ID
		//       F6     # primitive(22) nil / null payload
		//       80     # array(0) no signatures
		[]byte("\xd8\x62\x84\x40\xa1\x01\x26\xf6\x80"),
	},

	// {
	// 	"duplicate key across protected and unprotected maps",
	// 	// TODO: throw a duplicate key error?
	// 	Headers{
	// 		Protected: map[interface{}]interface{}{
	// 			"alg": "ES256",
	// 		},
	// 		Unprotected: map[interface{}]interface{}{
	// 			"alg": "PS256",
	// 		},
	// 	},
	// 	HexToBytesOrDie("43a10126"), // see "alg in protected header" comment
	// },
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

func UnmarshalsWithoutErr(t *testing.T, testCase CBORTestCase) {
	assert := assert.New(t)

	_, err := Unmarshal(testCase.bytes)
	assert.Nil(err)
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
			UnmarshalsWithoutErr(t, testCase)
		})

		t.Run(fmt.Sprintf("%s: RoundtripsToExpectedBytes", testCase.name), func(t *testing.T) {
			RoundtripsToExpectedBytes(t, testCase)
		})
	}
}

func TestCBORDecodeNilSignMessagePayload(t *testing.T) {
	assert := assert.New(t)

	msg := NewSignMessage()
	msg.Payload = nil

	// tag(98) + array(4) [ bytes(0), map(0), nil/null, array(0) ]
	b := HexToBytesOrDie("D862" + "84" + "40" + "A0" + "F6" + "80" )

	result, err := Unmarshal(b)
	assert.Nil(err)
	assert.Equal(result, msg)

	bytes, err := Marshal(result)
	assert.Nil(err)
	assert.Equal(bytes, b)
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
			"cbor decode error [pos 7]: error decoding msg payload decode from interface{} to []byte or nil; got type string",
		},
		{
			// tag(98) + array(4) [ bytes(0), map(0), bytes(0), text(0) ]
			HexToBytesOrDie("D862" + "84" + "40" + "A0" + "40" + "60"),
			"cbor decode error [pos 7]: error decoding sigs; got string",
		},
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
