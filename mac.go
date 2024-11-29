package cose

import (
	"bytes"
	"errors"
	"github.com/fxamacker/cbor/v2"
)

// mac represents a COSE_Mac CBOR object:
//
//	COSE_Mac =  [
//	    Headers,
//	    payload : bstr / nil,
//	    tag : bstr,
//	    recipients :[+COSE_recipient]
//	]
//
// Reference: https://datatracker.ietf.org/doc/html/rfc8152#section-6.1
type mac struct {
	_           struct{} `cbor:",toarray"`
	Protected   cbor.RawMessage
	Unprotected cbor.RawMessage
	Payload     byteString
	Tag         byteString
	Recipients  []cbor.RawMessage
}

// macPrefix represents the fixed prefix of COSE_Mac
var macPrefix = []byte{
	0xd8, 0x61, // tag
	0x85, // array, len 5
}

// Mac represents a decoded COSE_Mac.
//
// Reference: https://datatracker.ietf.org/doc/html/rfc8152#section-6.1
//
// # Experimental
//
// Notice: The COSE Authenticate API is EXPERIMENTAL and may be changed or
// removed in a later release.
type Mac struct {
	Headers    Headers
	Payload    []byte
	Tag        []byte
	Recipients []Recipient
}

// NewMac returns a Mac with header initialised.
//
// # Experimental
//
// Notice: The COSE Authenticate API is EXPERIMENTAL and may be changed or
// removed ina later release.
func NewMac() *Mac {
	return &Mac{
		Headers: Headers{
			Protected:   ProtectedHeader{},
			Unprotected: UnprotectedHeader{},
		},
	}
}

// MarshalCBOR encodes Mac into a COSE_Mac object.
//
// # Experimental
//
// Notice: The COSE Authenticate API is EXPERIMENTAL and may be changed or
// removed in a later release.
func (m *Mac) MarshalCBOR() ([]byte, error) {
	if m == nil {
		return nil, errors.New("cbor: MarshalCBOR on nil Mac pointer")
	}
	if len(m.Tag) == 0 {
		return nil, ErrEmptyTag
	}
	protected, unprotected, err := m.Headers.marshal()
	if err != nil {
		return nil, err
	}

	recipients := make([]cbor.RawMessage, 0, len(m.Recipients))
	for _, rec := range m.Recipients {
		recCBOR, err := rec.MarshalCBOR()
		if err != nil {
			return nil, err
		}
		recipients = append(recipients, recCBOR)
	}

	mac := mac{
		Protected:   protected,
		Unprotected: unprotected,
		Payload:     m.Payload,
		Tag:         m.Tag,
		Recipients:  recipients,
	}
	return encMode.Marshal(cbor.Tag{
		Number:  CBORTagMacMessage,
		Content: mac,
	})
}

// UnmarshalCBOR decodes a COSE_Mac object to Mac.
//
// # Experimental
//
// Notice: The COSE Authenticate API is EXPERIMENTAL and may be changed or
// removed in a later release.
func (m *Mac) UnmarshalCBOR(data []byte) error {
	if m == nil {
		return errors.New("cbor: UnmarshalCBOR on nil Mac pointer")
	}

	if !bytes.HasPrefix(data, macPrefix) {
		return errors.New("cbor: invalid Mac object")
	}

	var raw mac
	if err := decModeWithTagsForbidden.Unmarshal(data[2:], &raw); err != nil {
		return err
	}
	if len(raw.Tag) == 0 {
		return ErrEmptyTag
	}

	recipients := make([]Recipient, 0, len(raw.Recipients))
	for _, recipientData := range raw.Recipients {
		rec := Recipient{}
		if err := rec.UnmarshalCBOR(recipientData); err != nil {
			return err
		}
		recipients = append(recipients, rec)
	}

	mac := Mac{
		Headers: Headers{
			RawProtected:   raw.Protected,
			RawUnprotected: raw.Unprotected,
		},
		Payload:    raw.Payload,
		Tag:        raw.Tag,
		Recipients: recipients,
	}

	if err := mac.Headers.UnmarshalFromRaw(); err != nil {
		return err
	}

	*m = mac
	return nil
}

// CreateTag creates a Mac using the provided AuthenticationCreator.
// Creating a COSE_Mac requires the encoded protected header and the payload
// of its parent message.
//
// Reference: https://datatracker.ietf.org/doc/html/rfc8152#section-6.3
//
// # Experimental
//
// Notice: The COSE Authenticate API is EXPERIMENTAL and may be changed
// or removed in a later release.
func (m *Mac) CreateTag(external []byte, tagger Tagger) error {
	return m.createTag(nil, external, tagger)
}

func (m *Mac) CreateTagDetached(detached, external []byte, tagger Tagger) error {
	if detached == nil {
		return ErrMissingPayload
	}
	return m.createTag(detached, external, tagger)
}

func (m *Mac) createTag(detached, external []byte, tagger Tagger) error {
	if m == nil {
		return errors.New("create tag on nil Mac")
	}
	if len(m.Tag) > 0 {
		return errors.New("Mac already has a tag")
	}
	if tagger == nil {
		return errors.New("no Tagger")
	}

	payload, err := checkPayload(m.Payload, detached)
	if err != nil {
		return err
	}

	var protected cbor.RawMessage
	protected, err = m.Headers.MarshalProtected()
	if err != nil {
		return err
	}
	if len(protected) == 0 || (protected[0]&cborMajorTypeMask) != cborMajorTypeByteString {
		return errors.New("invalid protected headers")
	}

	// check algorithm is present.
	alg := tagger.Algorithm()
	if err := m.Headers.ensureAuthenticationAlgorithm(alg, external); err != nil {
		return err
	}

	// create authentication tag
	toBeAuthenticated, err := m.toBeAuthenticated(protected, payload, external)
	if err != nil {
		return err
	}

	tag, err := tagger.CreateTag(toBeAuthenticated)
	if err != nil {
		return err
	}

	m.Tag = tag
	return nil
}

// AuthenticateTag authenticates the MAC tag, returning nil on success or a suitable
// error if authentication fails.
//
// Reference: https://datatracker.ietf.org/doc/html/rfc8152#section-6.3
//
// # Experimental
//
// Notice: The COSE Authenticate API is EXPERIMENTAL and may be changed
// or removed in a later release.
func (m *Mac) AuthenticateTag(external []byte, authenticator Authenticator) error {
	return m.authenticateTag(nil, external, authenticator)
}

func (m *Mac) AuthenticateTagDetached(detached, external []byte, authenticator Authenticator) error {
	if detached == nil {
		return ErrMissingPayload
	}
	return m.authenticateTag(detached, external, authenticator)
}

func (m *Mac) authenticateTag(detached, external []byte, authenticator Authenticator) error {
	if m == nil {
		return errors.New("authenticate tag on nil Mac")
	}
	if len(m.Tag) == 0 {
		return ErrEmptyTag
	}
	if authenticator == nil {
		return errors.New("no Authenticator")
	}

	payload, err := checkPayload(m.Payload, detached)
	if err != nil {
		return err
	}

	var protected cbor.RawMessage
	protected, err = m.Headers.MarshalProtected()
	if err != nil {
		return err
	}
	if len(protected) == 0 || (protected[0]&cborMajorTypeMask) != cborMajorTypeByteString {
		return errors.New("invalid protected headers")
	}

	alg := authenticator.Algorithm()
	err = m.Headers.ensureAuthenticationAlgorithm(alg, external)
	if err != nil {
		return err
	}

	toBeAuthenticated, err := m.toBeAuthenticated(protected, payload, external)
	if err != nil {
		return err
	}

	return authenticator.AuthenticateTag(toBeAuthenticated, m.Tag)
}

// toBeAuthenticated constructs Mac_structure, computes and returns ToBeMaced.
//
// Reference: https://datatracker.ietf.org/doc/html/rfc8152#section-6.3
func (m *Mac) toBeAuthenticated(protected cbor.RawMessage, payload, external []byte) ([]byte, error) {
	// create a Mac_structure and populate it with the appropriate fields
	//
	//  MAC_structure = [
	//    context : "MAC",
	//    protected : empty_or_serialized_map,
	//    external_aad : bstr,
	//    payload : bstr
	//  ]
	protected, err := deterministicBinaryString(protected)
	if err != nil {
		return nil, err
	}
	if external == nil {
		external = []byte{}
	}

	macStructure := []any{
		"MAC",
		protected,
		external,
		payload,
	}

	return encMode.Marshal(macStructure)
}

// recipient represents a COSE_recipient object.
//
//	 COSE_recipient =  [
//		    Headers,
//		    ciphertext : bstr / nil,
//		    ? recipients : [+COSE_recipient]
//	 ]
//
// Reference: https://datatracker.ietf.org/doc/html/rfc8152#section-5.1
type recipient struct {
	_           struct{} `cbor:",toarray"`
	Protected   cbor.RawMessage
	Unprotected cbor.RawMessage
	CipherText  byteString
	Recipients  []cbor.RawMessage
}

var recipientPrefix = []byte{
	0x84, // array, len 4
}

// Recipient represents a decoded COSE_recipient.
//
// Reference: https://datatracker.ietf.org/doc/html/rfc8152#section-5.1
//
// # Experimental
//
// Notice: The COSE Authenticate API is EXPERIMENTAL and may be changed or
// removed in a later release.
type Recipient struct {
	Headers    Headers
	CipherText []byte
	Recipients []Recipient
}

// NewRecipient returns a Recipient with header initialised.
//
// # Experimental
//
// Notice: The COSE Authenticate API is EXPERIMENTAL and may be changed or
// removed in a later release.
func NewRecipient() *Recipient {
	return &Recipient{
		Headers: Headers{
			Protected:   ProtectedHeader{},
			Unprotected: UnprotectedHeader{},
		},
	}
}

// MarshalCBOR encodes a Recipient into a CBOR_recipient object.
//
// # Experimental
//
// Notice: The COSE Authenticate API is EXPERIMENTAL and may be changed or
// removed in a later release.
func (r *Recipient) MarshalCBOR() ([]byte, error) {
	if r == nil {
		return nil, errors.New("cbor: MarshalCBOR on nil Recipient")
	}
	protected, unprotected, err := r.Headers.marshal()
	if err != nil {
		return nil, err
	}

	recipients := make([]cbor.RawMessage, 0, len(r.Recipients))
	for _, recipient := range r.Recipients {
		r, err := encMode.Marshal(&recipient)
		if err != nil {
			return nil, err
		}
		recipients = append(recipients, r)
	}

	rec := recipient{
		Protected:   protected,
		Unprotected: unprotected,
		CipherText:  r.CipherText,
		Recipients:  recipients,
	}
	return encMode.Marshal(rec)
}

// UnmarshalCBOR decodes a COSE_recipient object into Recipient.
//
// # Experimental
//
// Notice: The COSE Authenticate API is EXPERIMENTAL and may be changed or
// removed in a later release.
func (r *Recipient) UnmarshalCBOR(data []byte) error {
	if r == nil {
		return errors.New("cbor: UnmarshalCBOR on nil Recipient")
	}

	if !bytes.HasPrefix(data, recipientPrefix) {
		return errors.New("cbor: invalid Recipient object")
	}

	var raw recipient
	if err := decModeWithTagsForbidden.Unmarshal(data, &raw); err != nil {
		return err
	}

	recipients := make([]Recipient, 0, len(raw.Recipients))
	for _, recCBOR := range raw.Recipients {
		rec := Recipient{}
		if err := rec.UnmarshalCBOR(recCBOR); err != nil {
			return err
		}
		recipients = append(recipients, rec)
	}

	rec := Recipient{
		Headers: Headers{
			RawProtected:   raw.Protected,
			RawUnprotected: raw.Unprotected,
		},
		CipherText: raw.CipherText,
		Recipients: recipients,
	}
	if err := rec.Headers.UnmarshalFromRaw(); err != nil {
		return err
	}

	*r = rec
	return nil
}
