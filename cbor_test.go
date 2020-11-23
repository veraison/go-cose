package cose

import (
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"

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
		map[interface{}]interface{}{1: -7},
		[]byte("\xA1\x01\x26"),
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
	{
		"Sign1 message with EAT token",
		Sign1Message{
			Headers: &Headers{
				Protected:   map[interface{}]interface{}{"alg": "ES256"},
				Unprotected: map[interface{}]interface{}{},
			},
			Payload: []byte{
				0xa2, 0x3a, 0x00, 0x01, 0x24, 0xff, 0x4b, 0x6e, 0x6f, 0x6e, 0x63, 0x65,
				0x5f, 0x6e, 0x6f, 0x6e, 0x63, 0x65, 0x3a, 0x00, 0x01, 0x25, 0x00, 0x49,
				0x75, 0x65, 0x69, 0x64, 0x5f, 0x75, 0x65, 0x69, 0x64,
			},
			Signature: []byte{
				0x28, 0x2d, 0xe0, 0xba, 0xe5, 0x10, 0xff, 0x04, 0xc3, 0x52, 0xd7, 0xa3,
				0xf7, 0x88, 0x46, 0x8a, 0xab, 0x0e, 0x04, 0x5c, 0xc4, 0x20, 0x38, 0x42,
				0xdf, 0x4b, 0x5e, 0x13, 0x0e, 0xba, 0xc1, 0xe0, 0x0a, 0x43, 0x2d, 0xe0,
				0x15, 0x3e, 0xf5, 0xb9, 0x8b, 0xb1, 0x8f, 0x76, 0x53, 0xab, 0x6d, 0xbb,
				0x37, 0x7b, 0x77, 0x51, 0x92, 0x1c, 0x99, 0x95, 0x1b, 0x20, 0x79, 0x9d,
				0x2e, 0xfb, 0xa6, 0xce,
			},
		},
		// D2                   # tag(18) COSE Sign1 tag
		//    84                # array(4)
		//       43             # bytes(3) protected headers
		//          A1          # map(1)
		//            01        # unsigned(1) common header ID for alg
		//            26        # negative(7) ES256 alg ID
		//       A0             # map(0) empty unprotected headers
		//       58 21          # bytes(33) payload
		//          A23A0001... # EAT token
		//       58 40          # bytes(64) signature
		//          282DE0BA... # 128 bytes ES256 signature
		[]byte{
			0xd2, 0x84, 0x43, 0xa1, 0x01, 0x26, 0xa0, 0x58, 0x21, 0xa2, 0x3a, 0x00,
			0x01, 0x24, 0xff, 0x4b, 0x6e, 0x6f, 0x6e, 0x63, 0x65, 0x5f, 0x6e, 0x6f,
			0x6e, 0x63, 0x65, 0x3a, 0x00, 0x01, 0x25, 0x00, 0x49, 0x75, 0x65, 0x69,
			0x64, 0x5f, 0x75, 0x65, 0x69, 0x64, 0x58, 0x40, 0x28, 0x2d, 0xe0, 0xba,
			0xe5, 0x10, 0xff, 0x04, 0xc3, 0x52, 0xd7, 0xa3, 0xf7, 0x88, 0x46, 0x8a,
			0xab, 0x0e, 0x04, 0x5c, 0xc4, 0x20, 0x38, 0x42, 0xdf, 0x4b, 0x5e, 0x13,
			0x0e, 0xba, 0xc1, 0xe0, 0x0a, 0x43, 0x2d, 0xe0, 0x15, 0x3e, 0xf5, 0xb9,
			0x8b, 0xb1, 0x8f, 0x76, 0x53, 0xab, 0x6d, 0xbb, 0x37, 0x7b, 0x77, 0x51,
			0x92, 0x1c, 0x99, 0x95, 0x1b, 0x20, 0x79, 0x9d, 0x2e, 0xfb, 0xa6, 0xce,
		},
	},
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

func TestCBORMarshalSignMessageWithNilHeadersErrors(t *testing.T) {
	assert := assert.New(t)

	msg := NewSignMessage()
	msg.Payload = nil
	msg.Headers = nil
	_, err := Marshal(msg)
	assert.Equal("cbor: SignMessage has nil Headers", err.Error())
}

func TestCBORMarshalDuplicateKeysErrs(t *testing.T) {
	assert := assert.New(t)

	// NB: golang does not allow duplicate keys in a map literal
	// so we don't test Marshalling duplicate entries both in
	// Protected or Unprotected

	// uncompressed one in each
	msg := NewSignMessage()
	msg.Payload = nil
	msg.Headers = &Headers{
		Protected: map[interface{}]interface{}{
			"alg": "ES256",
		},
		Unprotected: map[interface{}]interface{}{
			"alg": "PS256",
		},
	}
	_, err := Marshal(msg)
	assert.Equal(errors.New("cbor: Duplicate header 1 found"), err)

	// compressed one in each
	msg.Headers = &Headers{
		Protected: map[interface{}]interface{}{
			1: -7,
		},
		Unprotected: map[interface{}]interface{}{
			1: -37,
		},
	}
	_, err = Marshal(msg)
	assert.Equal(errors.New("cbor: Duplicate header 1 found"), err)

	// compressed and uncompressed both in Protected
	msg.Headers = &Headers{
		Protected: map[interface{}]interface{}{
			"alg": "ES256",
			1:     -37,
		},
		Unprotected: map[interface{}]interface{}{},
	}
	_, err = Marshal(msg)
	assert.Equal(errors.New("cbor: Duplicate compressed and uncompressed common header 1 found in headers"), err)

	// compressed and uncompressed both in Unprotected
	msg.Headers = &Headers{
		Protected: map[interface{}]interface{}{},
		Unprotected: map[interface{}]interface{}{
			"alg": "ES256",
			1:     -37,
		},
	}
	_, err = Marshal(msg)
	assert.Equal(errors.New("cbor: Duplicate compressed and uncompressed common header 1 found in headers"), err)

	// compressed and uncompressed one in each
	msg.Headers = &Headers{
		Protected: map[interface{}]interface{}{
			"alg": "ES256",
		},
		Unprotected: map[interface{}]interface{}{
			1: -37,
		},
	}
	_, err = Marshal(msg)
	assert.Equal(errors.New("cbor: Duplicate header 1 found"), err)

	msg.Headers = &Headers{
		Protected: map[interface{}]interface{}{
			1: -37,
		},
		Unprotected: map[interface{}]interface{}{
			"alg": "ES256",
		},
	}
	_, err = Marshal(msg)
	assert.Equal(errors.New("cbor: Duplicate header 1 found"), err)

	// duplicate headers in a SignMessage Signature
	msg.Headers = &Headers{
		Protected:   map[interface{}]interface{}{},
		Unprotected: map[interface{}]interface{}{},
	}
	msg.AddSignature(&Signature{
		Headers: &Headers{
			Protected: map[interface{}]interface{}{
				1: -37,
			},
			Unprotected: map[interface{}]interface{}{
				"alg": "ES256",
			},
		},
		SignatureBytes: []byte(""),
	})
	_, err = Marshal(msg)
	assert.Equal("cbor: Duplicate signature header 1 found", err.Error())
}

func TestCBORDecodeNilSignMessagePayload(t *testing.T) {
	assert := assert.New(t)

	msg := NewSignMessage()
	msg.Payload = nil

	// tag(98) + array(4) [ bytes(0), map(0), nil/null, array(0) ]
	b := HexToBytesOrDie("D862" + "84" + "40" + "A0" + "F6" + "80")

	result, err := Unmarshal(b)
	assert.Nil(err)
	assert.Equal(result, *msg)

	bytes, err := Marshal(result)
	assert.Nil(err)
	assert.Equal(bytes, b)
}

func TestCBORDecodingDuplicateKeys(t *testing.T) {
	assert := assert.New(t)

	type DecodeTestCase struct {
		bytes  []byte
		result SignMessage
	}
	var cases = []DecodeTestCase{
		{
			// duplicate compressed key in protected
			// tag(98) + array(4) [ bytes(5), map(0), bytes(0), array(0) ]
			//
			// where our bytes(5) is A201260128 or
			// A2    # map(2)
			//    01 # unsigned(1)
			//    26 # negative(6)
			//    01 # unsigned(1)
			//    29 # negative(10)
			//
			// and decodes to map[1:-10] so last/rightmost value wins
			HexToBytesOrDie("D862" + "84" + "45A201260129" + "A0" + "40" + "80"),
			SignMessage{
				Headers: &Headers{
					Protected:   map[interface{}]interface{}{1: -10},
					Unprotected: map[interface{}]interface{}{},
				},
				Payload:    []byte(""),
				Signatures: nil,
			},
		},
		{
			// duplicate compressed key in unprotected
			// tag(98) + array(4) [ bytes(0), map(2), bytes(0), array(0) ]
			//
			// where our map(2) is
			//    01 # unsigned(1)
			//    26 # negative(6)
			//    01 # unsigned(1)
			//    29 # negative(10)
			//
			// and decodes to map[1:-10] so last/rightmost value wins
			HexToBytesOrDie("D862" + "84" + "40" + "A201260129" + "40" + "80"),
			SignMessage{
				Headers: &Headers{
					Protected:   map[interface{}]interface{}{},
					Unprotected: map[interface{}]interface{}{1: -10},
				},
				Payload:    []byte(""),
				Signatures: nil,
			},
		},
		{
			// duplicate uncompressed key in protected
			// tag(98) + array(4) [ bytes(21), map(0), bytes(0), array(0) ]
			//
			// see next test for what bytes(21) represents
			HexToBytesOrDie("D862" + "84" + "55" + "A2" + "63" + "616C67" + "65" + "4553323536" + "63" + "616C67" + "65" + "5053323536" + "A0" + "40" + "80"),
			SignMessage{
				Headers: &Headers{
					Protected: map[interface{}]interface{}{
						1: -37, // decoding compresses to check for duplicate keys
					},
					Unprotected: map[interface{}]interface{}{},
				},
				Payload:    []byte(""),
				Signatures: nil,
			},
		},
		{
			// duplicate uncompressed key in unprotected
			// tag(98) + array(4) [ bytes(0), map(2), bytes(0), array(0) ]
			//
			// where our map(2) is
			//
			// A2               # map(2)
			//    63            # text(3)
			//       616C67     # "alg"
			//    65            # text(5)
			//       4553323536 # "ES256"
			//    63            # text(3)
			//       616C67     # "alg"
			//    65            # text(5)
			//       5053323536 # "PS256"
			//
			HexToBytesOrDie("D862" + "84" + "40" + "A2" + "63" + "616C67" + "65" + "4553323536" + "63" + "616C67" + "65" + "5053323536" + "40" + "80"),
			SignMessage{
				Headers: &Headers{
					Protected: map[interface{}]interface{}{},
					Unprotected: map[interface{}]interface{}{
						1: -37, // decoding compresses to check for duplicate keys
					},
				},
				Payload:    []byte(""),
				Signatures: nil,
			},
		},
	}

	for _, testCase := range cases {
		result, err := Unmarshal(testCase.bytes)
		assert.Nil(err)
		assert.Equal(testCase.result, result)
	}
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
			"cbor: cannot unmarshal UTF-8 text string into Go value of type cose.signMessage",
		},
		{
			HexToBytesOrDie("D862" + "80"), // tag(98) + array(0)
			"cbor: cannot unmarshal array into Go value of type cose.signMessage (cannot decode CBOR array to struct with different number of elements)",
		},
		{
			// tag(98) + array(4) [ 4 * text(0) ]
			HexToBytesOrDie("D862" + "84" + "60" + "60" + "60" + "60"),
			"cbor: cannot unmarshal UTF-8 text string into Go struct field cose.signMessage.Protected of type []uint8",
		},
		{
			// tag(98) + array(4) [ bytes(0), map(0), 2 * text(0) ]
			HexToBytesOrDie("D862" + "84" + "40" + "A0" + "60" + "60"),
			"cbor: cannot unmarshal UTF-8 text string into Go struct field cose.signMessage.Payload of type []uint8",
		},
		{
			// tag(98) + array(4) [ bytes(0), map(0), bytes(0), text(0) ]
			HexToBytesOrDie("D862" + "84" + "40" + "A0" + "40" + "60"),
			"cbor: cannot unmarshal UTF-8 text string into Go struct field cose.signMessage.Signatures of type []cose.signature",
		},
		{
			// wrong # of protected header bytes
			// tag(98) + array(4) [ bytes(2) (but actually 1), map(0), bytes(0), text(0) ]
			HexToBytesOrDie("D862" + "84" + "4263" + "A0" + "40" + "60"),
			"unexpected EOF",
		},
		{
			// protected header is serialized array
			// tag(98) + array(4) [ bytes(3), map(2), bytes(0), array(0) ]
			// protected header is bytes(3) is [2, -7]
			HexToBytesOrDie("D862" + "84" + "43820226" + "A10224" + "40" + "80"),
			"cbor: error casting protected to map; got []interface {}",
		},
		{
			// duplicate compressed key in protected and unprotected
			// tag(98) + array(4) [ bytes(3), map(2), bytes(0), array(0) ]
			// bytes(3) is protected {2: -7}
			// map(1) is {2: -5}
			HexToBytesOrDie("D862" + "84" + "43A10226" + "A10224" + "40" + "80"),
			"cbor: Duplicate header 2 found",
		},
		{
			// duplicate uncompressed key in protected and unprotected
			// tag(98) + array(4) [ bytes(11), map(1), bytes(0), array(0) ]
			// bytes(11) is protected {"alg": "ES256"}
			// map(1) is unprotected {"alg": "ES256"}
			HexToBytesOrDie("D862" + "84" + "4B" + "A1" + "63" + "616C67" + "65" + "4553323536" + "A1" + "63" + "616C67" + "65" + "4553323536" + "40" + "80"),
			"cbor: Duplicate header 1 found",
		},
		{
			// duplicate key compressed in protected and uncompressed in unprotected
			// tag(98) + array(4) [ bytes(3), map(1), bytes(0), array(0) ]
			// bytes(3) is protected {1: -7}
			// map(1) is unprotected {"alg": "PS256"}
			HexToBytesOrDie("D862" + "84" + "43" + "A10126" + "A1" + "63" + "616C67" + "65" + "4553323536" + "40" + "80"),
			"cbor: Duplicate header 1 found",
		},
		{
			// duplicate key uncompressed in protected and compressed in unprotected
			// tag(98) + array(4) [ bytes(11), map(1), bytes(0), array(0) ]
			// bytes(11) is protected {"alg": "ES256"}
			// map(1) is unprotected {1: -7}
			HexToBytesOrDie("D862" + "84" + "4B" + "A1" + "63" + "616C67" + "65" + "4553323536" + "A10126" + "40" + "80"),
			"cbor: Duplicate header 1 found",
		},
		{
			// Signature's protected header is serialized array
			// tag(98) + array(4) [ bytes(0), map(0), bytes(0), array(1) ]
			// Signature is array(3) [ bytes(3), map(0), bytes(0)]
			// Signature protected header is bytes(3) is [2, -7]
			HexToBytesOrDie("D862" + "84" + "40" + "A0" + "40" + "81" + "83" + "43820226" + "A0" + "40"),
			"cbor: error casting protected to map; got []interface {}",
		},
		{
			// Signature duplicate compressed key in protected and unprotected
			// tag(98) + array(4) [ bytes(0), map(0), bytes(0), array(1) ]
			// Signature is array(3) [ bytes(3), map(1), bytes(0)]
			// Signature bytes(3) is protected {2: -7}
			// Signature map(1) is {2: -5}
			HexToBytesOrDie("D862" + "84" + "40" + "A0" + "40" + "81" + "83" + "43A10226" + "A10224" + "40"),
			"cbor: Duplicate header 2 found",
		},
		{
			// Signature duplicate uncompressed key in protected and unprotected
			// tag(98) + array(4) [ bytes(0), map(0), bytes(0), array(1) ]
			// Signature is array(3) [ bytes(11), map(1), bytes(0)]
			// Signature bytes(11) is protected {"alg": "ES256"}
			// Signature map(1) is unprotected {"alg": "ES256"}
			//HexToBytesOrDie("D862" + "84" + "4B" + "A1" + "63" + "616C67" + "65" + "4553323536" + "A1" + "63" + "616C67" + "65" + "4553323536" + "40" + "80"),
			HexToBytesOrDie("D862" + "84" + "40" + "A0" + "40" + "81" + "83" + "4B" + "A1" + "63" + "616C67" + "65" + "4553323536" + "A1" + "63" + "616C67" + "65" + "4553323536" + "40"),
			"cbor: Duplicate header 1 found",
		},
		{
			// Signature duplicate key compressed in protected and uncompressed in unprotected
			// tag(98) + array(4) [ bytes(0), map(0), bytes(0), array(1) ]
			// Signature is array(3) [ bytes(3), map(1), bytes(0)]
			// Signature bytes(3) is protected {1: -7}
			// Signature map(1) is unprotected {"alg": "PS256"}
			//HexToBytesOrDie("D862" + "84" + "43" + "A10126" + "A1" + "63" + "616C67" + "65" + "4553323536" + "40" + "80"),
			HexToBytesOrDie("D862" + "84" + "40" + "A0" + "40" + "81" + "83" + "43" + "A10126" + "A1" + "63" + "616C67" + "65" + "4553323536" + "40"),
			"cbor: Duplicate header 1 found",
		},
		{
			// Signature duplicate key uncompressed in protected and compressed in unprotected
			// tag(98) + array(4) [ bytes(0), map(0), bytes(0), array(1) ]
			// Signature is array(3) [ bytes(11), map(1), bytes(0)]
			// Signature bytes(11) is protected {"alg": "ES256"}
			// Signature map(1) is unprotected {1: -7}
			//HexToBytesOrDie("D862" + "84" + "4B" + "A1" + "63" + "616C67" + "65" + "4553323536" + "A10126" + "40" + "80"),
			HexToBytesOrDie("D862" + "84" + "40" + "A0" + "40" + "81" + "83" + "4B" + "A1" + "63" + "616C67" + "65" + "4553323536" + "A10126" + "40"),
			"cbor: Duplicate header 1 found",
		},
	}

	for _, testCase := range cases {
		result, err := Unmarshal(testCase.bytes)
		assert.Nil(result)
		assert.Equal(testCase.errorMessage, err.Error())
	}
}

// TestCBORDecodingToSignMessageErrors tests unmarshaling COSE data to SignMessage,
// while TestCBORDecodingErrors tests unmarshaling COSE data to interface{}.
func TestCBORDecodingToSignMessageErrors(t *testing.T) {
	assert := assert.New(t)

	type DecodeErrorTestCase struct {
		name         string
		bytes        []byte
		errorMessage string
	}
	var cases = []DecodeErrorTestCase{
		{
			"missing tag number",
			HexToBytesOrDie("8440A0F680"), // array(4) [ bytes(0), map(0), nil, array(0)]
			"cbor: cannot unmarshal array into Go value of type cbor.RawTag",
		},
		{
			"wrong tag number",
			HexToBytesOrDie("D8638440A0F680"), // tag(99) + array(4) [ bytes(0), map(0), nil, array(0)]
			"cbor: wrong tag number 99",
		},
	}

	for _, testCase := range cases {
		var msg SignMessage
		err := cbor.Unmarshal(testCase.bytes, &msg)
		assert.Equal(testCase.errorMessage, err.Error())
	}
}

func TestIsSignMessage(t *testing.T) {
	assert := assert.New(t)

	assert.Equal(IsSignMessage([]byte("deadbeef")), false)

	msgBytes, err := Marshal(NewSignMessage())
	assert.Nil(err)
	assert.Equal(IsSignMessage(msgBytes), true)
}

func TestUnmarshalToNilSignMessage(t *testing.T) {
	assert := assert.New(t)

	b := []byte("\xd8\x62\x84\x40\xa0\xf6\x80")
	var msg *SignMessage
	err := msg.UnmarshalCBOR(b)
	assert.Equal("cbor: UnmarshalCBOR on nil SignMessage pointer", err.Error())
}
