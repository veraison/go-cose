package cose

import (
	"bytes"
	"fmt"
	"reflect"

	"github.com/fxamacker/cbor/v2"
	"github.com/pkg/errors"
)

const (
	// SignMessageCBORTag is the CBOR tag for a COSE SignMessage
	// from https://www.iana.org/assignments/cbor-tags/cbor-tags.xhtml#tags
	SignMessageCBORTag = 98

	// Sign1MessageCBORTag is the CBOR tag for COSE Single Signer Data Object
	Sign1MessageCBORTag = 18
)

var (
	signMessagePrefix = []byte{
		// 0b110_11000 major type 6 (tag) with additional information
		// length 24 bits / 3 bytes (since tags are always uints)
		//
		// per https://tools.ietf.org/html/rfc7049#section-2.4
		'\xd8',

		// uint8_t with the tag value
		SignMessageCBORTag,

		// 0b100_00100 major type 4 (array) with additional
		// information 4 for a 4-item array representing a COSE_Sign
		// message
		'\x84',
	}

	sign1MessagePrefix = []byte{
		// tag(18)
		'\xd2',

		// array(4)
		'\x84',
	}
)

// IsSignMessage checks whether the prefix is 0xd8 0x62 for a COSE
// SignMessage
func IsSignMessage(data []byte) bool {
	return bytes.HasPrefix(data, signMessagePrefix)
}

// IsSign1Message checks whether the prefix is 0xd2 0x84 for a COSE
// Sign1Message
func IsSign1Message(data []byte) bool {
	return bytes.HasPrefix(data, sign1MessagePrefix)
}

// Readonly CBOR encoding and decoding modes.
var (
	encMode, encModeError = initCBOREncMode()
	decMode, decModeError = initCBORDecMode()
)

func initCBOREncMode() (en cbor.EncMode, err error) {
	encOpt := cbor.EncOptions{
		IndefLength: cbor.IndefLengthForbidden, // no streaming
		Sort:        cbor.SortCanonical,        // sort map keys
	}
	return encOpt.EncMode()
}

func initCBORDecMode() (dm cbor.DecMode, err error) {
	// Create a tag with SignMessage and tag number 98.
	// When decoding CBOR data with tag number 98 to interface{}, cbor library returns SignMessage.
	tags := cbor.NewTagSet()
	err = tags.Add(
		cbor.TagOptions{EncTag: cbor.EncTagRequired, DecTag: cbor.DecTagRequired},
		reflect.TypeOf(SignMessage{}),
		SignMessageCBORTag,
	)
	if err != nil {
		return nil, err
	}

	decOpt := cbor.DecOptions{
		IndefLength: cbor.IndefLengthForbidden, // no streaming
		IntDec:      cbor.IntDecConvertSigned,  // decode CBOR uint/int to Go int64
	}
	return decOpt.DecModeWithTags(tags)
}

func init() {
	if encModeError != nil {
		panic(encModeError)
	}
	if decModeError != nil {
		panic(decModeError)
	}
}

// Marshal returns the CBOR []byte encoding of param o
func Marshal(o interface{}) (b []byte, err error) {
	defer func() {
		// Need to recover from panic because Headers.EncodeUnprotected()
		// and Headers.EncodeProtected() can panic.
		if r := recover(); r != nil {
			b = nil
			switch x := r.(type) {
			case error:
				err = fmt.Errorf("cbor: %s", x.Error())
			default:
				err = fmt.Errorf("cbor: %v", x)
			}
		}
	}()

	return encMode.Marshal(o)
}

// Unmarshal returns the CBOR decoding of a []byte into param o
func Unmarshal(b []byte) (o interface{}, err error) {
	err = decMode.Unmarshal(b, &o)
	return o, err
}

type signature struct {
	_              struct{} `cbor:",toarray"`
	Protected      []byte
	Unprotected    map[interface{}]interface{}
	SignatureBytes []byte
}

type signMessage struct {
	_           struct{} `cbor:",toarray"`
	Protected   []byte
	Unprotected map[interface{}]interface{}
	Payload     []byte
	Signatures  []signature
}

// MarshalCBOR encodes SignMessage.
func (message *SignMessage) MarshalCBOR() ([]byte, error) {
	// Verify SignMessage headers.
	if message.Headers == nil {
		return nil, errors.New("cbor: SignMessage has nil Headers")
	}
	dup := FindDuplicateHeader(message.Headers)
	if dup != nil {
		return nil, fmt.Errorf("cbor: Duplicate header %+v found", dup)
	}

	// Convert Signature to signature.
	sigs := make([]signature, len(message.Signatures))
	for i, s := range message.Signatures {
		dup := FindDuplicateHeader(s.Headers)
		if dup != nil {
			return nil, fmt.Errorf("cbor: Duplicate signature header %+v found", dup)
		}

		sigs[i] = signature{
			Protected:      s.Headers.EncodeProtected(),
			Unprotected:    s.Headers.EncodeUnprotected(),
			SignatureBytes: s.SignatureBytes,
		}
	}

	// Convert SignMessage to signMessage.
	m := signMessage{
		Protected:   message.Headers.EncodeProtected(),
		Unprotected: message.Headers.EncodeUnprotected(),
		Payload:     message.Payload,
		Signatures:  sigs,
	}

	// Marshal signMessage with tag number 98.
	return encMode.Marshal(cbor.Tag{Number: SignMessageCBORTag, Content: m})
}

// UnmarshalCBOR decodes data into SignMessage.
//
// Unpacks a SignMessage described by CDDL fragments:
//
// COSE_Sign = [
//     Headers,
//     payload : bstr / nil,
//     signatures : [+ COSE_Signature]
// ]
//
// COSE_Signature =  [
//     Headers,
//     signature : bstr
// ]
//
// Headers = (
//     protected : empty_or_serialized_map,
//     unprotected : header_map
// )
//
// header_map = {
//     Generic_Headers,
//     * label => values
// }
//
// empty_or_serialized_map = bstr .cbor header_map / bstr .size 0
//
// Generic_Headers = (
//        ? 1 => int / tstr,  ; algorithm identifier
//        ? 2 => [+label],    ; criticality
//        ? 3 => tstr / int,  ; content type
//        ? 4 => bstr,        ; key identifier
//        ? 5 => bstr,        ; IV
//        ? 6 => bstr,        ; Partial IV
//        ? 7 => COSE_Signature / [+COSE_Signature] ; Counter signature
// )
//
func (message *SignMessage) UnmarshalCBOR(data []byte) (err error) {
	if message == nil {
		return errors.New("cbor: UnmarshalCBOR on nil SignMessage pointer")
	}

	// Decode to cbor.RawTag to extract tag number and tag content as []byte.
	var raw cbor.RawTag
	err = decMode.Unmarshal(data, &raw)
	if err != nil {
		return err
	}

	// Verify tag number.
	if raw.Number != SignMessageCBORTag {
		return fmt.Errorf("cbor: wrong tag number %d", raw.Number)
	}

	// Decode tag content to signMessage.
	var m signMessage
	err = decMode.Unmarshal(raw.Content, &m)
	if err != nil {
		return err
	}

	// Create Headers from signMessage.
	msgHeaders := &Headers{}
	err = msgHeaders.Decode([]interface{}{m.Protected, m.Unprotected})
	if err != nil {
		return fmt.Errorf("cbor: %s", err.Error())
	}

	// Create Signature from signMessage.
	var sigs []Signature
	for _, s := range m.Signatures {
		sh := &Headers{}
		err = sh.Decode([]interface{}{s.Protected, s.Unprotected})
		if err != nil {
			return fmt.Errorf("cbor: %s", err.Error())
		}

		sigs = append(sigs, Signature{
			Headers:        sh,
			SignatureBytes: s.SignatureBytes,
		})
	}

	*message = SignMessage{
		Headers:    msgHeaders,
		Payload:    m.Payload,
		Signatures: sigs,
	}
	return nil
}

type sign1Message struct {
	_           struct{} `cbor:",toarray"`
	Protected   []byte
	Unprotected map[interface{}]interface{}
	Payload     []byte
	Signature   []byte
}

// MarshalCBOR encodes Sign1Message.
func (message *Sign1Message) MarshalCBOR() ([]byte, error) {
	// Verify Sign1Message headers.
	if message.Headers == nil {
		return nil, errors.New("cbor: Sign1Message has nil Headers")
	}
	dup := FindDuplicateHeader(message.Headers)
	if dup != nil {
		return nil, fmt.Errorf("cbor: Duplicate header %+v found", dup)
	}

	// Convert Sign1Message to sign1Message.
	m := sign1Message{
		Protected:   message.Headers.EncodeProtected(),
		Unprotected: message.Headers.EncodeUnprotected(),
		Payload:     message.Payload,
		Signature:   message.Signature,
	}

	// Marshal sign1Message with tag number 18.
	return encMode.Marshal(cbor.Tag{Number: Sign1MessageCBORTag, Content: m})
}

// UnmarshalCBOR decodes data into Sign1Message.
func (message *Sign1Message) UnmarshalCBOR(data []byte) (err error) {
	if message == nil {
		return errors.New("cbor: UnmarshalCBOR on nil Sign1Message pointer")
	}

	// Decode to cbor.RawTag to extract tag number and tag content as []byte.
	var raw cbor.RawTag
	err = decMode.Unmarshal(data, &raw)
	if err != nil {
		return err
	}

	// Verify tag number.
	if raw.Number != Sign1MessageCBORTag {
		return fmt.Errorf("cbor: wrong tag number %d", raw.Number)
	}

	// Decode tag content to sign1Message.
	var m sign1Message
	err = decMode.Unmarshal(raw.Content, &m)
	if err != nil {
		return err
	}

	// Create Headers from sign1Message.
	msgHeaders := &Headers{}
	err = msgHeaders.Decode([]interface{}{m.Protected, m.Unprotected})
	if err != nil {
		return fmt.Errorf("cbor: %s", err.Error())
	}

	*message = Sign1Message{
		Headers:   msgHeaders,
		Payload:   m.Payload,
		Signature: m.Signature,
	}

	return nil
}
