package cose

import (
	"crypto/hmac"
	"crypto/sha256"
	"testing"
)

func TestHmacTagger(t *testing.T) {
	tests := []struct {
		name string
	}{
		{
			name: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// TODO
		})
	}
}

func TestHmacAuthenticator(t *testing.T) {
	key := generateTestHMACKey(t, 256)
	hm := hmac.New(sha256.New, key)

	authenticator := &hmacAuthenticator{
		alg: AlgorithmHMAC256_256,
		key: key,
	}

	content := []byte("lorem ipsum")

	hm.Reset()
	hm.Write(content)
	tag := hm.Sum(nil)

	tests := []struct {
		name    string
		content []byte
		tag     []byte
		wantErr string
	}{
		{
			name:    "valid tag",
			content: content,
			tag:     tag,
		},
		{
			name:    "invalid tag",
			content: content,
			tag:     []byte{1, 2, 3, 4},
			wantErr: "authentication error",
		},
		{
			name:    "invalid content",
			content: []byte{1, 2, 3, 4},
			tag:     tag,
			wantErr: "authentication error",
		},
		{
			name:    "nil tag",
			content: content,
			tag:     nil,
			wantErr: "authentication error",
		},
		{
			name:    "empty tag",
			content: content,
			tag:     []byte{},
			wantErr: "authentication error",
		},
		{
			name:    "nil content",
			content: nil,
			tag:     tag,
			wantErr: "authentication error",
		},
		{
			name:    "empty content",
			content: []byte{},
			tag:     tag,
			wantErr: "authentication error",
		},
		{
			name:    "nil content & tag",
			content: nil,
			tag:     nil,
			wantErr: "authentication error",
		},
		{
			name:    "empty content & tag",
			content: []byte{},
			tag:     []byte{},
			wantErr: "authentication error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := authenticator.AuthenticateTag(tt.content, tt.tag)
			if err != nil && (err.Error() != tt.wantErr) {
				t.Errorf("AuthenticateTag() error = %v, wantErr %v", err, tt.wantErr)
				return
			} else if err == nil && (tt.wantErr != "") {
				t.Errorf("AuthenticateTag() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func generateTestHMACKey(t *testing.T, lenBits int) []byte {
	if lenBits%8 != 0 {
		t.Fatal("bad key lenBits")
	}
	key := make([]byte, lenBits/8)
	for i := range key {
		key[i] = byte(i)
	}
	return key
}
