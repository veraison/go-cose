package cose

import (
	"errors"
	"fmt"
	"io"
	"maps"
)

// HashEnvelopePayload indicates the payload of a Hash_Envelope object.
// It is used by the [SignHashEnvelope] function.
//
// # Experimental
//
// Notice: The COSE Hash Envelope API is EXPERIMENTAL and may be changed or
// removed in a later release.
type HashEnvelopePayload struct {
	// HashAlgorithm is the hash algorithm used to produce the hash value.
	HashAlgorithm Algorithm

	// HashValue is the hash value of the payload.
	HashValue []byte

	// PreimageContentType is the content type of the data that has been hashed.
	// The value is either an unsigned integer (RFC 7252 Section 12.3) or a
	// string (RFC 9110 Section 8.3).
	// This field is optional.
	//
	// References:
	// - https://www.iana.org/assignments/core-parameters/core-parameters.xhtml
	// - https://www.iana.org/assignments/media-types/media-types.xhtml
	PreimageContentType any // uint / string

	// Location is the location of the hash value in the payload.
	// This field is optional.
	Location string
}

// SignHashEnvelope signs a [Sign1Message] using the provided [Signer] and
// produces a Hash_Envelope object.
//
//	Hash_Envelope_Protected_Header = {
//		? &(alg: 1) => int,
//		&(payload_hash_alg: 258) => int
//		&(payload_preimage_content_type: 259) => uint / tstr
//		? &(payload_location: 260) => tstr
//		* int / tstr => any
//	}
//
//	Hash_Envelope_Unprotected_Header = {
//		* int / tstr => any
//	}
//
//	Hash_Envelope_as_COSE_Sign1 = [
//		protected : bstr .cbor Hash_Envelope_Protected_Header,
//		unprotected : Hash_Envelope_Unprotected_Header,
//		payload: bstr / nil,
//		signature : bstr
//	]
//
//	Hash_Envelope = #6.18(Hash_Envelope_as_COSE_Sign1)
//
// Reference: https://www.ietf.org/archive/id/draft-ietf-cose-hash-envelope-03.html
//
// # Experimental
//
// Notice: The COSE Hash Envelope API is EXPERIMENTAL and may be changed or
// removed in a later release.
func SignHashEnvelope(rand io.Reader, signer Signer, headers Headers, payload HashEnvelopePayload) ([]byte, error) {
	if err := validateHash(payload.HashAlgorithm, payload.HashValue); err != nil {
		return nil, err
	}

	headers.Protected = setHashEnvelopeProtectedHeader(headers.Protected, &payload)
	headers.RawProtected = nil
	if err := validateHashEnvelopeHeaders(&headers); err != nil {
		return nil, err
	}

	return Sign1(rand, signer, headers, payload.HashValue, nil)
}

// VerifyHashEnvelope verifies a Hash_Envelope object using the provided
// [Verifier].
// It returns the decoded [Sign1Message] if the verification is successful.
//
// # Experimental
//
// Notice: The COSE Hash Envelope API is EXPERIMENTAL and may be changed or
// removed in a later release.
func VerifyHashEnvelope(verifier Verifier, envelope []byte) (*Sign1Message, error) {
	// parse and validate the Hash_Envelope object
	var message Sign1Message
	if err := message.UnmarshalCBOR(envelope); err != nil {
		return nil, err
	}
	if err := validateHashEnvelopeHeaders(&message.Headers); err != nil {
		return nil, err
	}

	// verify the Hash_Envelope object
	if err := message.Verify(nil, verifier); err != nil {
		return nil, err
	}

	// cast to type Algorithm
	hashAlgorithm, err := message.Headers.Protected.PayloadHashAlgorithm()
	if err != nil {
		return nil, err
	}
	message.Headers.Protected[HeaderLabelPayloadHashAlgorithm] = hashAlgorithm

	// validate the hash value
	if err := validateHash(hashAlgorithm, message.Payload); err != nil {
		return nil, err
	}

	return &message, nil
}

// validateHash checks the validity of the hash.
func validateHash(alg Algorithm, value []byte) error {
	hash := alg.hashFunc()
	if hash == 0 {
		return fmt.Errorf("%v: %w", alg, ErrAlgorithmNotSupported)
	}
	if size := hash.Size(); size != len(value) {
		return fmt.Errorf("%v: size mismatch: expected %d, got %d", alg, size, len(value))
	}
	return nil
}

// setHashEnvelopeProtectedHeader sets the protected header for a Hash_Envelope
// object.
func setHashEnvelopeProtectedHeader(base ProtectedHeader, payload *HashEnvelopePayload) ProtectedHeader {
	header := maps.Clone(base)
	if header == nil {
		header = make(ProtectedHeader)
	}
	header[HeaderLabelPayloadHashAlgorithm] = payload.HashAlgorithm
	if payload.PreimageContentType != nil {
		header[HeaderLabelPayloadPreimageContentType] = payload.PreimageContentType
	}
	if payload.Location != "" {
		header[HeaderLabelPayloadLocation] = payload.Location
	}
	return header
}

// validateHashEnvelopeHeaders validates the headers of a Hash_Envelope object.
// See https://www.ietf.org/archive/id/draft-ietf-cose-hash-envelope-03.html
// section 4 for more details.
func validateHashEnvelopeHeaders(headers *Headers) error {
	var foundPayloadHashAlgorithm bool
	for label, value := range headers.Protected {
		// Validate that all header labels are integers or strings.
		// Reference: https://datatracker.ietf.org/doc/html/rfc8152#section-1.4
		label, ok := normalizeLabel(label)
		if !ok {
			return errors.New("header label: require int / tstr type")
		}

		switch label {
		case HeaderLabelContentType:
			return errors.New("protected header parameter: content type: not allowed")
		case HeaderLabelPayloadHashAlgorithm:
			_, isAlg := value.(Algorithm)
			if !isAlg && !canInt(value) {
				return errors.New("protected header parameter: payload hash alg: require int type")
			}
			foundPayloadHashAlgorithm = true
		case HeaderLabelPayloadPreimageContentType:
			if !canUint(value) && !canTstr(value) {
				return errors.New("protected header parameter: payload preimage content type: require uint / tstr type")
			}
		case HeaderLabelPayloadLocation:
			if !canTstr(value) {
				return errors.New("protected header parameter: payload location: require tstr type")
			}
		}
	}
	if !foundPayloadHashAlgorithm {
		return errors.New("protected header parameter: payload hash alg: required")
	}

	for label, value := range headers.Unprotected {
		// Validate that all header labels are integers or strings.
		// Reference: https://datatracker.ietf.org/doc/html/rfc8152#section-1.4
		label, ok := normalizeLabel(label)
		if !ok {
			return errors.New("header label: require int / tstr type")
		}

		switch label {
		case HeaderLabelContentType:
			return errors.New("unprotected header parameter: content type: not allowed")
		case HeaderLabelPayloadHashAlgorithm:
			return errors.New("unprotected header parameter: payload hash alg: not allowed")
		case HeaderLabelPayloadPreimageContentType:
			if !canUint(value) && !canTstr(value) {
				return errors.New("unprotected header parameter: payload preimage content type: require uint / tstr type")
			}
		case HeaderLabelPayloadLocation:
			return errors.New("unprotected header parameter: payload location: not allowed")
		}
	}

	return nil
}
