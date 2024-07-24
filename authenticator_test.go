package cose

import (
	"reflect"
	"testing"
)

func TestNewAuthenticator(t *testing.T) {
	tests := []struct {
		name    string
		alg     Algorithm
		key     []byte
		want    Authenticator
		wantErr string
	}{
		{
			name: "new HMAC-SHA256",
			alg:  AlgorithmHMAC256_256,
			key:  generateTestHMACKey(t, 256),
			want: &hmacAuthenticator{
				alg: AlgorithmHMAC256_256,
				key: generateTestHMACKey(t, 256),
			},
		},
		{
			name: "new HMAC-SHA384",
			alg:  AlgorithmHMAC384_384,
			key:  generateTestHMACKey(t, 384),
			want: &hmacAuthenticator{
				alg: AlgorithmHMAC384_384,
				key: generateTestHMACKey(t, 384),
			},
		},
		{
			name: "new HMAC-SHA512",
			alg:  AlgorithmHMAC512_512,
			key:  generateTestHMACKey(t, 512),
			want: &hmacAuthenticator{
				alg: AlgorithmHMAC512_512,
				key: generateTestHMACKey(t, 512),
			},
		},
		{
			name:    "new HMAC-SHA256/64",
			alg:     AlgorithmHMAC256_64,
			wantErr: ErrAlgorithmNotSupported.Error(),
		},
		{
			name:    "nil key",
			alg:     AlgorithmHMAC256_256,
			wantErr: "empty key",
		},
		{
			name:    "empty key",
			alg:     AlgorithmHMAC256_256,
			wantErr: "empty key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewAuthenticator(tt.alg, tt.key)
			if err != nil && (err.Error() != tt.wantErr) {
				t.Errorf("NewAuthenticator() error = %v, wantErr %v", err, tt.wantErr)
				return
			} else if err == nil && (tt.wantErr != "") {
				t.Errorf("NewAuthenticator() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewAuthenticator() = %v, want %v", got, tt.want)
			}
		})
	}
}
