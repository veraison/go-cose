package cose

import (
	"reflect"
	"testing"
)

func TestMac_MarshalCBOR(t *testing.T) {
	tests := []struct {
		name    string
		mac     *Mac
		want    []byte
		wantErr string
	}{
		{
			name: "valid mac",
			mac: &Mac{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: AlgorithmHMAC256_256,
					},
				},
				Payload: []byte{'p'},
				Tag:     []byte{'t'},
				Recipients: []Recipient{
					{
						Headers:    Headers{},
						CipherText: []byte("r"),
					},
				},
			},
			want: []byte{
				0xd8, 0x61, // tag COSE Mac
				0x85,                   // array, len 5
				0x43, 0xa1, 0x01, 0x05, // protected
				0xa0,      // unprotected
				0x41, 'p', // payload
				0x41, 't', // tag
				0x81,      // recipients, array, len 1
				0x84,      // array, len 4
				0x40,      // protected
				0xa0,      // unprotected
				0x41, 'r', // cipher text
				0x80, // recipients, empty array
			},
		},
		{
			name:    "nil mac",
			wantErr: "cbor: MarshalCBOR on nil Mac pointer",
		},
		{
			name: "nil tag",
			mac: &Mac{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: AlgorithmHMAC256_256,
					},
				},
				Payload: []byte{1, 2, 3, 4},
			},
			wantErr: ErrEmptyTag.Error(),
		},
		{
			name: "empty tag",
			mac: &Mac{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: AlgorithmHMAC256_256,
					},
				},
				Payload: []byte{1, 2, 3, 4},
				Tag:     []byte{},
			},
			wantErr: ErrEmptyTag.Error(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.mac.MarshalCBOR()
			if err != nil && (err.Error() != tt.wantErr) {
				t.Errorf("MarshalCBOR() error = %v, wantErr %v", err, tt.wantErr)
				return
			} else if err == nil && (tt.wantErr != "") {
				t.Errorf("MarshalCBOR() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("MarshalCBOR() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMac_UnmarshalCBOR(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    Mac
		wantErr string
	}{
		{
			name: "valid message with 1 recipient",
			data: []byte{
				0xd8, 0x61, // tag COSE Mac
				0x85,                   // array, len 5
				0x43, 0xa1, 0x01, 0x05, // protected
				0xa0,      // unprotected
				0x41, 'p', // payload
				0x41, 't', // tag
				0x81,      // recipients, array, len 1
				0x84,      // array, len 4
				0x40,      // protected
				0xa0,      // unprotected
				0x41, 'r', // cipher text
				0x80, // recipients, empty array
			},
			want: Mac{
				Headers: Headers{
					RawProtected: []byte{0x43, 0xa1, 0x01, 0x05},
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: AlgorithmHMAC256_256,
					},
					RawUnprotected: []byte{0xa0},
					Unprotected:    UnprotectedHeader{},
				},
				Payload: []byte("p"),
				Tag:     []byte("t"),
				Recipients: []Recipient{
					{
						Headers: Headers{
							RawProtected:   []byte{0x40},
							Protected:      ProtectedHeader{},
							RawUnprotected: []byte{0xa0},
							Unprotected:    UnprotectedHeader{},
						},
						CipherText: []byte("r"),
						Recipients: []Recipient{},
					},
				},
			},
		},
		{
			name: "valid message with multiple recipients",
			data: []byte{
				0xd8, 0x61, // tag COSE Mac
				0x85,                   // array, len 5
				0x43, 0xa1, 0x01, 0x05, // protected
				0xa0,      // unprotected
				0x41, 'p', // payload
				0x41, 't', // tag
				0x82,           // recipients, array, len 2
				0x84,           // array, len 4
				0x40,           // protected
				0xa0,           // unprotected
				0x42, 'r', '1', // cipher text
				0x80,           // recipients, empty array
				0x84,           // array, len 4
				0x40,           // protected
				0xa0,           // unprotected
				0x42, 'r', '2', // cipher text
				0x80, // recipients, empty array
			},
			want: Mac{
				Headers: Headers{
					RawProtected: []byte{0x43, 0xa1, 0x01, 0x05},
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: AlgorithmHMAC256_256,
					},
					RawUnprotected: []byte{0xa0},
					Unprotected:    UnprotectedHeader{},
				},
				Payload: []byte("p"),
				Tag:     []byte("t"),
				Recipients: []Recipient{
					{
						Headers: Headers{
							RawProtected:   []byte{0x40},
							Protected:      ProtectedHeader{},
							RawUnprotected: []byte{0xa0},
							Unprotected:    UnprotectedHeader{},
						},
						CipherText: []byte("r1"),
						Recipients: []Recipient{},
					},
					{
						Headers: Headers{
							RawProtected:   []byte{0x40},
							Protected:      ProtectedHeader{},
							RawUnprotected: []byte{0xa0},
							Unprotected:    UnprotectedHeader{},
						},
						CipherText: []byte("r2"),
						Recipients: []Recipient{},
					},
				},
			},
		},
		{
			name: "valid message with nested recipients",
			data: []byte{
				0xd8, 0x61, // tag COSE Mac
				0x85,                   // array, len 5
				0x43, 0xa1, 0x01, 0x05, // protected
				0xa0,      // unprotected
				0x41, 'p', // payload
				0x41, 't', // tag
				0x81,           // recipients, array, len 1
				0x84,           // array, len 4
				0x40,           // protected
				0xa0,           // unprotected
				0x42, 'r', '1', // cipher text
				0x81,           // recipients, array, len 1
				0x84,           // array, len 4
				0x40,           // protected
				0xa0,           // unprotected
				0x42, 'r', '2', // cipher text
				0x80, // recipients, empty array
			},
			want: Mac{
				Headers: Headers{
					RawProtected: []byte{0x43, 0xa1, 0x01, 0x05},
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: AlgorithmHMAC256_256,
					},
					RawUnprotected: []byte{0xa0},
					Unprotected:    UnprotectedHeader{},
				},
				Payload: []byte("p"),
				Tag:     []byte("t"),
				Recipients: []Recipient{
					{
						Headers: Headers{
							RawProtected:   []byte{0x40},
							Protected:      ProtectedHeader{},
							RawUnprotected: []byte{0xa0},
							Unprotected:    UnprotectedHeader{},
						},
						CipherText: []byte("r1"),
						Recipients: []Recipient{
							{
								Headers: Headers{
									RawProtected:   []byte{0x40},
									Protected:      ProtectedHeader{},
									RawUnprotected: []byte{0xa0},
									Unprotected:    UnprotectedHeader{},
								},
								CipherText: []byte("r2"),
								Recipients: []Recipient{},
							},
						},
					},
				},
			},
		},
		{
			name: "valid message with 0 recipients", // TODO should this fail
			data: []byte{
				0xd8, 0x61, // tag COSE Mac
				0x85,                   // array, len 5
				0x43, 0xa1, 0x01, 0x05, // protected
				0xa0,      // unprotected
				0x41, 'p', // payload
				0x41, 't', // tag
				0x80, // recipients, array, len 0
			},
			want: Mac{
				Headers: Headers{
					RawProtected: []byte{0x43, 0xa1, 0x01, 0x05},
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: AlgorithmHMAC256_256,
					},
					RawUnprotected: []byte{0xa0},
					Unprotected:    UnprotectedHeader{},
				},
				Payload:    []byte("p"),
				Tag:        []byte("t"),
				Recipients: []Recipient{},
			},
		},
		{
			name: "valid message with nil payload",
			data: []byte{
				0xd8, 0x61, // tag COSE Mac
				0x85,                   // array, len 5
				0x43, 0xa1, 0x01, 0x05, // protected
				0xa0,      // unprotected
				0xf6,      // payload
				0x41, 't', // tag
				0x81,      // recipients, array, len 1
				0x84,      // array, len 4
				0x40,      // protected
				0xa0,      // unprotected
				0x41, 'r', // cipher text
				0x80, // recipients, empty array
			},
			want: Mac{
				Headers: Headers{
					RawProtected: []byte{0x43, 0xa1, 0x01, 0x05},
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: AlgorithmHMAC256_256,
					},
					RawUnprotected: []byte{0xa0},
					Unprotected:    UnprotectedHeader{},
				},
				Payload: nil,
				Tag:     []byte("t"),
				Recipients: []Recipient{
					{
						Headers: Headers{
							RawProtected:   []byte{0x40},
							Protected:      ProtectedHeader{},
							RawUnprotected: []byte{0xa0},
							Unprotected:    UnprotectedHeader{},
						},
						CipherText: []byte("r"),
						Recipients: []Recipient{},
					},
				},
			},
		},
		{
			name: "nil tag",
			data: []byte{
				0xd8, 0x61, // tag COSE Mac
				0x85,                   // array, len 5
				0x43, 0xa1, 0x01, 0x05, // protected
				0xa0,      // unprotected
				0x41, 'p', // payload
				0xf6,      // tag
				0x81,      // recipients, array, len 1
				0x84,      // array, len 4
				0x40,      // protected
				0xa0,      // unprotected
				0x41, 'r', // cipher text
				0x80, // recipients, empty array
			},
			wantErr: "empty tag",
		},
		{
			name: "empty tag",
			data: []byte{
				0xd8, 0x61, // tag COSE Mac
				0x85,                   // array, len 5
				0x43, 0xa1, 0x01, 0x05, // protected
				0xa0,      // unprotected
				0x41, 'p', // payload
				0x40,      // tag
				0x81,      // recipients, array, len 1
				0x84,      // array, len 4
				0x40,      // protected
				0xa0,      // unprotected
				0x41, 'r', // cipher text
				0x80, // recipients, empty array
			},
			wantErr: "empty tag",
		},
		{
			name:    "nil CBOR data",
			data:    nil,
			wantErr: "cbor: invalid Mac object",
		},
		{
			name:    "empty CBOR data",
			data:    []byte{},
			wantErr: "cbor: invalid Mac object",
		},
		{
			name: "mismatch tag",
			data: []byte{
				0xd8, 0x60, // not tag COSE Mac
				0x00, // unread...
			},
			wantErr: "cbor: invalid Mac object",
		},
		{
			name: "mismatch type",
			data: []byte{
				0xd8, 0x61, // tag COSE Mac
				0xa0, // map, size 0
				0x00, // unread...
			},
			wantErr: "cbor: invalid Mac object",
		},
		{
			name: "mismatch size",
			data: []byte{
				0xd8, 0x61, // tag COSE Mac
				0x80, // array, len 0
				0x00, // unread...
			},
			wantErr: "cbor: invalid Mac object",
		},
		{
			name: "tag as byte array",
			data: []byte{
				0xd8, 0x61, // tag COSE Mac
				0x85,                   // array, len 5
				0x43, 0xa1, 0x01, 0x05, // protected
				0xa0,      // unprotected
				0x41, 'p', // payload
				0x81, 0x01, // tag, array, len 1
				0x81,      // recipients, array, len 1
				0x84,      // array, len 4
				0x40,      // protected
				0xa0,      // unprotected
				0x41, 'r', // cipher text
				0x80, // recipients, empty array
			},
			wantErr: "cbor: require bstr type",
		},
		{
			name: "payload as byte array",
			data: []byte{
				0xd8, 0x61, // tag COSE Mac
				0x85,                   // array, len 5
				0x43, 0xa1, 0x01, 0x05, // protected
				0xa0,       // unprotected
				0x81, 0x01, // payload, array, len 1
				0x41, 't', // tag
				0x81,      // recipients, array, len 1
				0x84,      // array, len 4
				0x40,      // protected
				0xa0,      // unprotected
				0x41, 'r', // cipher text
				0x80, // recipients, empty array
			},
			wantErr: "cbor: require bstr type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got Mac
			err := got.UnmarshalCBOR(tt.data)
			if err != nil && (err.Error() != tt.wantErr) {
				t.Errorf("UnmarshalCBOR() error = %v, wantErr %v", err, tt.wantErr)
				return
			} else if err == nil && (tt.wantErr != "") {
				t.Errorf("UnmarshalCBOR() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("UnmarshalCBOR() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestMac_CreateTag(t *testing.T) {
	algorithms := map[Algorithm]*struct {
		keySize       int
		tagger        Tagger
		authenticator Authenticator
	}{
		AlgorithmHMAC256_256: {
			keySize:       256,
			tagger:        nil,
			authenticator: nil,
		},
		AlgorithmHMAC384_384: {
			keySize:       384,
			tagger:        nil,
			authenticator: nil,
		},
		AlgorithmHMAC512_512: {
			keySize:       512,
			tagger:        nil,
			authenticator: nil,
		},
	}

	for algorithm, a := range algorithms {
		key := generateTestHMACKey(t, a.keySize)

		tagger, err := NewTagger(algorithm, key)
		if err != nil {
			t.Fatal(err)
		}
		authenticator, err := NewAuthenticator(algorithm, key)
		if err != nil {
			t.Fatal(err)
		}

		a.tagger = tagger
		a.authenticator = authenticator
	}

	tests := []struct {
		name                      string
		mac                       Mac
		externalOnCreateTag       []byte
		externalOnAuthenticateTag []byte
		tagger                    Tagger
		authenticator             Authenticator
		wantErr                   string
	}{
		{
			name: "valid message with external",
			mac: Mac{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: AlgorithmHMAC256_256,
					},
				},
				Payload: []byte("lorem ipsum"),
			},
			externalOnCreateTag:       []byte("external"),
			externalOnAuthenticateTag: []byte("external"),
			tagger:                    algorithms[AlgorithmHMAC256_256].tagger,
			authenticator:             algorithms[AlgorithmHMAC256_256].authenticator,
		},
		{
			name: "valid message with nil external",
			mac: Mac{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: AlgorithmHMAC384_384,
					},
				},
				Payload: []byte("lorem ipsum"),
			},
			externalOnCreateTag:       nil,
			externalOnAuthenticateTag: nil,
			tagger:                    algorithms[AlgorithmHMAC384_384].tagger,
			authenticator:             algorithms[AlgorithmHMAC384_384].authenticator,
		},
		{
			name: "valid message with empty external",
			mac: Mac{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: AlgorithmHMAC512_512,
					},
				},
				Payload: []byte("lorem ipsum"),
			},
			externalOnCreateTag:       []byte{},
			externalOnAuthenticateTag: []byte{},
			tagger:                    algorithms[AlgorithmHMAC512_512].tagger,
			authenticator:             algorithms[AlgorithmHMAC512_512].authenticator,
		},
		{
			name: "valid message with mixed external",
			mac: Mac{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: AlgorithmHMAC256_256,
					},
				},
				Payload: []byte("lorem ipsum"),
			},
			externalOnCreateTag:       []byte{},
			externalOnAuthenticateTag: nil,
			tagger:                    algorithms[AlgorithmHMAC256_256].tagger,
			authenticator:             algorithms[AlgorithmHMAC256_256].authenticator,
		},
		{
			name: "valid message empty payload",
			mac: Mac{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: AlgorithmHMAC256_256,
					},
				},
				Payload: []byte("lorem ipsum"),
			},
			tagger:        algorithms[AlgorithmHMAC256_256].tagger,
			authenticator: algorithms[AlgorithmHMAC256_256].authenticator,
		},
		{
			name: "nil payload",
			mac: Mac{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: AlgorithmHMAC256_256,
					},
				},
				Payload: nil,
			},
			tagger:  algorithms[AlgorithmHMAC256_256].tagger,
			wantErr: "missing payload",
		},
		{
			name: "double tagging",
			mac: Mac{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: AlgorithmHMAC256_256,
					},
				},
				Payload: []byte("lorem ipsum"),
				Tag:     []byte("ipsum lorem"),
			},
			tagger:  algorithms[AlgorithmHMAC256_256].tagger,
			wantErr: "Mac already has a tag",
		},
		{
			name: "header mismatch",
			mac: Mac{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: AlgorithmHMAC512_512,
					},
				},
				Payload: []byte("lorem ipsum"),
			},
			tagger:  algorithms[AlgorithmHMAC256_256].tagger,
			wantErr: "algorithm mismatch: authenticator HMAC256/256: header HMAC512/512",
		},
		{
			name: "no alg header, no external",
			mac: Mac{
				Payload: []byte("lorem ipsum"),
			},
			tagger:  algorithms[AlgorithmHMAC256_256].tagger,
			wantErr: "algorithm not found",
		},
		{
			name: "no tagger",
			mac: Mac{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: AlgorithmHMAC256_256,
					},
				},
				Payload: []byte("lorem ipsum"),
			},
			tagger:        nil,
			authenticator: algorithms[AlgorithmHMAC256_256].authenticator,
			wantErr:       "no Tagger",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.mac.CreateTag(tt.externalOnCreateTag, tt.tagger)
			if err != nil {
				if err.Error() != tt.wantErr {
					t.Errorf("Mac.CreateTag() error = %v, wantErr %v", err, tt.wantErr)
				}
				return
			} else if tt.wantErr != "" {
				t.Errorf("Mac.CreateTag() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err = tt.mac.AuthenticateTag(tt.externalOnAuthenticateTag, tt.authenticator); err != nil {
				t.Errorf("Mac.AuthenticateTag() error = %v", err)
			}
		})
	}

	// detached payloads
	detachedTests := []struct {
		name          string
		mac           Mac
		detached      []byte
		tagger        Tagger
		authenticator Authenticator
		wantErr       string
	}{
		{
			name: "valid message",
			mac: Mac{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: AlgorithmHMAC256_256,
					},
				},
			},
			detached:      []byte("lorem ipsum"),
			tagger:        algorithms[AlgorithmHMAC256_256].tagger,
			authenticator: algorithms[AlgorithmHMAC256_256].authenticator,
		},
		{
			name: "multiple payloads",
			mac: Mac{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: AlgorithmHMAC256_256,
					},
				},
				Payload: []byte("lorem ipsum"),
			},
			detached:      []byte("lorem ipsum"),
			tagger:        algorithms[AlgorithmHMAC256_256].tagger,
			authenticator: algorithms[AlgorithmHMAC256_256].authenticator,
			wantErr:       "multiple payloads",
		},
		{
			name: "missing payload",
			mac: Mac{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: AlgorithmHMAC256_256,
					},
				},
			},
			tagger:        algorithms[AlgorithmHMAC256_256].tagger,
			authenticator: algorithms[AlgorithmHMAC256_256].authenticator,
			wantErr:       "missing payload",
		},
	}

	for _, tt := range detachedTests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.mac.CreateTagDetached(tt.detached, nil, tt.tagger)
			if err != nil {
				if err.Error() != tt.wantErr {
					t.Errorf("Mac.CreateTagDetached() error = %v, wantErr %v", err, tt.wantErr)
				}
				return
			} else if tt.wantErr != "" {
				t.Errorf("Mac.CreateTagDetached() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err = tt.mac.AuthenticateTagDetached(tt.detached, nil, tt.authenticator); err != nil {
				t.Errorf("Mac.AuthenticateTagDetached() error = %v", err)
			}
		})
	}
}

func TestMac_AuthenticateTag(t *testing.T) {
	algorithms := map[Algorithm]*struct {
		keySize       int
		tagger        Tagger
		authenticator Authenticator
	}{
		AlgorithmHMAC256_256: {
			keySize:       256,
			tagger:        nil,
			authenticator: nil,
		},
		AlgorithmHMAC384_384: {
			keySize:       384,
			tagger:        nil,
			authenticator: nil,
		},
		AlgorithmHMAC512_512: {
			keySize:       512,
			tagger:        nil,
			authenticator: nil,
		},
	}

	for algorithm, a := range algorithms {
		key := generateTestHMACKey(t, a.keySize)

		tagger, err := NewTagger(algorithm, key)
		if err != nil {
			t.Fatal(err)
		}
		authenticator, err := NewAuthenticator(algorithm, key)
		if err != nil {
			t.Fatal(err)
		}

		a.tagger = tagger
		a.authenticator = authenticator
	}

	tests := []struct {
		name                      string
		tamper                    func(m *Mac) *Mac
		externalOnCreateTag       []byte
		externalOnAuthenticateTag []byte
		tagger                    Tagger
		authenticator             Authenticator
		wantErr                   string
	}{
		{
			name:                      "valid message with external",
			externalOnCreateTag:       []byte("external"),
			externalOnAuthenticateTag: []byte("external"),
			tagger:                    algorithms[AlgorithmHMAC256_256].tagger,
			authenticator:             algorithms[AlgorithmHMAC256_256].authenticator,
		},
		{
			name:                      "changed external",
			externalOnCreateTag:       []byte("external"),
			externalOnAuthenticateTag: []byte("external!"),
			tagger:                    algorithms[AlgorithmHMAC256_256].tagger,
			authenticator:             algorithms[AlgorithmHMAC256_256].authenticator,
			wantErr:                   "authentication error",
		},
		{
			name: "nil mac",
			tamper: func(m *Mac) *Mac {
				return nil
			},
			externalOnCreateTag:       []byte("external"),
			externalOnAuthenticateTag: []byte("external"),
			tagger:                    algorithms[AlgorithmHMAC256_256].tagger,
			authenticator:             algorithms[AlgorithmHMAC256_256].authenticator,
			wantErr:                   "authenticate tag on nil Mac",
		},
		{
			name: "nil tag",
			tamper: func(m *Mac) *Mac {
				m.Tag = nil
				return m
			},
			externalOnCreateTag:       []byte("external"),
			externalOnAuthenticateTag: []byte("external"),
			tagger:                    algorithms[AlgorithmHMAC256_256].tagger,
			authenticator:             algorithms[AlgorithmHMAC256_256].authenticator,
			wantErr:                   "empty tag",
		},
		{
			name: "empty tag",
			tamper: func(m *Mac) *Mac {
				m.Tag = []byte{}
				return m
			},
			externalOnCreateTag:       []byte("external"),
			externalOnAuthenticateTag: []byte("external"),
			tagger:                    algorithms[AlgorithmHMAC256_256].tagger,
			authenticator:             algorithms[AlgorithmHMAC256_256].authenticator,
			wantErr:                   "empty tag",
		},
		{
			name: "tamper protected header",
			tamper: func(m *Mac) *Mac {
				m.Headers.Protected[123] = "hello"
				return m
			},
			externalOnCreateTag:       []byte("external"),
			externalOnAuthenticateTag: []byte("external"),
			tagger:                    algorithms[AlgorithmHMAC256_256].tagger,
			authenticator:             algorithms[AlgorithmHMAC256_256].authenticator,
			wantErr:                   "authentication error",
		},
		{
			name: "tamper payload",
			tamper: func(m *Mac) *Mac {
				m.Payload[0]++
				return m
			},
			externalOnCreateTag:       []byte("external"),
			externalOnAuthenticateTag: []byte("external"),
			tagger:                    algorithms[AlgorithmHMAC256_256].tagger,
			authenticator:             algorithms[AlgorithmHMAC256_256].authenticator,
			wantErr:                   "authentication error",
		},
		{
			name: "tamper tag",
			tamper: func(m *Mac) *Mac {
				m.Tag[0]++
				return m
			},
			externalOnCreateTag:       []byte("external"),
			externalOnAuthenticateTag: []byte("external"),
			tagger:                    algorithms[AlgorithmHMAC256_256].tagger,
			authenticator:             algorithms[AlgorithmHMAC256_256].authenticator,
			wantErr:                   "authentication error",
		},
		{
			name:                      "nil authenticator",
			externalOnCreateTag:       []byte("external"),
			externalOnAuthenticateTag: []byte("external"),
			tagger:                    algorithms[AlgorithmHMAC256_256].tagger,
			authenticator:             nil,
			wantErr:                   "no Authenticator",
		},
		{
			name:                      "mismatched authenticator",
			externalOnCreateTag:       []byte("external"),
			externalOnAuthenticateTag: []byte("external"),
			tagger:                    algorithms[AlgorithmHMAC256_256].tagger,
			authenticator:             algorithms[AlgorithmHMAC512_512].authenticator,
			wantErr:                   "algorithm mismatch: authenticator HMAC512/512: header HMAC256/256",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// creat message and tag
			mac := &Mac{
				Headers: Headers{
					Protected: ProtectedHeader{
						HeaderLabelAlgorithm: tt.tagger.Algorithm(),
					},
				},
				Payload: []byte("lorem ipsum"),
			}

			if err := mac.CreateTag(tt.externalOnCreateTag, tt.tagger); err != nil {
				t.Errorf("Mac.CreateTag() error = %v", err)
				return
			}

			if tt.tamper != nil {
				mac = tt.tamper(mac)
			}

			// authenticate tag
			err := mac.AuthenticateTag(tt.externalOnAuthenticateTag, tt.authenticator)
			if err != nil && (err.Error() != tt.wantErr) {
				t.Errorf("Mac.AuthenticateTag() error = %v, wantErr %v", err, tt.wantErr)
			} else if err == nil && (tt.wantErr != "") {
				t.Errorf("Mac.AuthenticateTag() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRecipient_MarshalCBOR(t *testing.T) {
	tests := []struct {
		name      string
		recipient *Recipient
		want      []byte
		wantErr   string
	}{
		{
			name: "valid recipient",
			recipient: &Recipient{
				Headers: Headers{
					Protected:   ProtectedHeader{},
					Unprotected: UnprotectedHeader{},
				},
				CipherText: []byte{1, 2, 3, 4},
			},
			want: []byte{
				0x84,                         // array len 4
				0x40,                         // protected
				0xa0,                         // unprotected
				0x44, 0x01, 0x02, 0x03, 0x04, // cipher text
				0x80, // empty recipients
			},
		},
		{
			name: "empty recipients",
			recipient: &Recipient{
				Headers: Headers{
					Protected:   ProtectedHeader{},
					Unprotected: UnprotectedHeader{},
				},
				CipherText: []byte{1, 2, 3, 4},
				Recipients: []Recipient{},
			},
			want: []byte{
				0x84,                         // array len 4
				0x40,                         // protected
				0xa0,                         // unprotected
				0x44, 0x01, 0x02, 0x03, 0x04, // cipher text
				0x80, // empty recipients
			},
		},
		{
			name: "nested recipients",
			recipient: &Recipient{
				Headers: Headers{
					Protected:   ProtectedHeader{},
					Unprotected: UnprotectedHeader{},
				},
				CipherText: []byte{1, 2, 3, 4},
				Recipients: []Recipient{
					{
						Headers: Headers{
							Protected:   ProtectedHeader{},
							Unprotected: UnprotectedHeader{},
						},
						CipherText: []byte{5, 6, 7, 8},
					},
				},
			},
			want: []byte{
				0x84,                         // array len 4
				0x40,                         // protected
				0xa0,                         // unprotected
				0x44, 0x01, 0x02, 0x03, 0x04, // cipher text
				0x81,                         // recipients, array len 1
				0x84,                         // array len 4
				0x40,                         // protected
				0xa0,                         // unprotected
				0x44, 0x05, 0x06, 0x07, 0x08, // cipher text
				0x80, // array len 0
			},
		},
		{
			name:    "nil recipient",
			wantErr: "cbor: MarshalCBOR on nil Recipient",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.recipient.MarshalCBOR()
			if err != nil && (err.Error() != tt.wantErr) {
				t.Errorf("MarshalCBOR() error = %v, wantErr %v", err, tt.wantErr)
				return
			} else if err == nil && (tt.wantErr != "") {
				t.Errorf("MarshalCBOR() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("MarshalCBOR() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRecipient_UnmarshalCBOR(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    Recipient
		wantErr string
	}{
		{
			name: "valid recipient",
			data: []byte{
				0x84,                         // array len 4
				0x40,                         // protected
				0xa0,                         // unprotected
				0x44, 0x01, 0x02, 0x03, 0x04, // cipher text
				0x80, // empty recipients
			},
			want: Recipient{
				Headers: Headers{
					Protected:      ProtectedHeader{},
					RawProtected:   []byte{0x40},
					Unprotected:    UnprotectedHeader{},
					RawUnprotected: []byte{0xa0},
				},
				CipherText: []byte{1, 2, 3, 4},
				Recipients: []Recipient{},
			},
		},
		{
			name:    "nil CBOR data",
			data:    nil,
			wantErr: "cbor: invalid Recipient object",
		},
		{
			name:    "empty CBOR data",
			data:    []byte{},
			wantErr: "cbor: invalid Recipient object",
		},
		{
			name: "mismatch type",
			data: []byte{
				0xa0, // map, size 0
				0x00, // unread...
			},
			wantErr: "cbor: invalid Recipient object",
		},
		{
			name: "mismatch size",
			data: []byte{
				0x80, // array len 8
				0x00, // unread...
			},
			wantErr: "cbor: invalid Recipient object",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got Recipient
			err := got.UnmarshalCBOR(tt.data)
			if err != nil && (err.Error() != tt.wantErr) {
				t.Errorf("UnmarshalCBOR() error = %v, wantErr %v", err, tt.wantErr)
				return
			} else if err == nil && (tt.wantErr != "") {
				t.Errorf("UnmarshalCBOR() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("UnmarshalCBOR() = %#v, want %#v", got, tt.want)
			}
		})
	}
}
