package cose

import (
	"crypto"
	"crypto/sha256"
	"reflect"
	"sync"
	"testing"
)

// resetExtendedAlgorithm cleans up extended algorithms
func resetExtendedAlgorithm() {
	extMu.Lock()
	extAlgorithms = nil
	extMu.Unlock()
}

func TestAlgorithm_String(t *testing.T) {
	defer resetExtendedAlgorithm()

	// register extended algorithms
	algFoo := Algorithm(-102)
	if err := RegisterAlgorithm(algFoo, "foo", 0, nil); err != nil {
		t.Fatalf("RegisterAlgorithm() = %v", err)
	}
	algBar := Algorithm(-98)
	if err := RegisterAlgorithm(algBar, "bar", 0, nil); err != nil {
		t.Fatalf("RegisterAlgorithm() = %v", err)
	}

	// run tests
	tests := []struct {
		name string
		alg  Algorithm
		want string
	}{
		{
			name: "PS256",
			alg:  AlgorithmPS256,
			want: "PS256",
		},
		{
			name: "PS384",
			alg:  AlgorithmPS384,
			want: "PS384",
		},
		{
			name: "PS512",
			alg:  AlgorithmPS512,
			want: "PS512",
		},
		{
			name: "ES256",
			alg:  AlgorithmES256,
			want: "ES256",
		},
		{
			name: "ES384",
			alg:  AlgorithmES384,
			want: "ES384",
		},
		{
			name: "ES512",
			alg:  AlgorithmES512,
			want: "ES512",
		},
		{
			name: "Ed25519",
			alg:  AlgorithmEd25519,
			want: "EdDSA",
		},
		{
			name: "extended algorithm: foo",
			alg:  algFoo,
			want: "foo",
		},
		{
			name: "extended algorithm: bar",
			alg:  algBar,
			want: "bar",
		},
		{
			name: "unknown algorithm",
			alg:  0,
			want: "unknown algorithm value 0",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.alg.String(); got != tt.want {
				t.Errorf("Algorithm.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAlgorithm_computeHash(t *testing.T) {
	defer resetExtendedAlgorithm()

	// register extended algorithms
	algFoo := Algorithm(-102)
	if err := RegisterAlgorithm(algFoo, "foo", crypto.SHA256, nil); err != nil {
		t.Fatalf("RegisterAlgorithm() = %v", err)
	}
	algBar := Algorithm(-98)
	if err := RegisterAlgorithm(algBar, "bar", 0, sha256.New); err != nil {
		t.Fatalf("RegisterAlgorithm() = %v", err)
	}
	algPlain := Algorithm(-112)
	if err := RegisterAlgorithm(algPlain, "plain", 0, nil); err != nil {
		t.Fatalf("RegisterAlgorithm() = %v", err)
	}
	algUnavailableHash := Algorithm(-117)
	if err := RegisterAlgorithm(algUnavailableHash, "unknown hash", 42, nil); err != nil {
		t.Fatalf("RegisterAlgorithm() = %v", err)
	}

	// run tests
	data := []byte("hello world")
	tests := []struct {
		name    string
		alg     Algorithm
		want    []byte
		wantErr error
	}{
		{
			name: "PS256",
			alg:  AlgorithmPS256,
			want: []byte{
				0xb9, 0x4d, 0x27, 0xb9, 0x93, 0x4d, 0x3e, 0x08, 0xa5, 0x2e, 0x52, 0xd7, 0xda, 0x7d, 0xab, 0xfa,
				0xc4, 0x84, 0xef, 0xe3, 0x7a, 0x53, 0x80, 0xee, 0x90, 0x88, 0xf7, 0xac, 0xe2, 0xef, 0xcd, 0xe9,
			},
		},
		{
			name: "PS384",
			alg:  AlgorithmPS384,
			want: []byte{
				0xfd, 0xbd, 0x8e, 0x75, 0xa6, 0x7f, 0x29, 0xf7, 0x01, 0xa4, 0xe0, 0x40, 0x38, 0x5e, 0x2e, 0x23,
				0x98, 0x63, 0x03, 0xea, 0x10, 0x23, 0x92, 0x11, 0xaf, 0x90, 0x7f, 0xcb, 0xb8, 0x35, 0x78, 0xb3,
				0xe4, 0x17, 0xcb, 0x71, 0xce, 0x64, 0x6e, 0xfd, 0x08, 0x19, 0xdd, 0x8c, 0x08, 0x8d, 0xe1, 0xbd,
			},
		},
		{
			name: "PS512",
			alg:  AlgorithmPS512,
			want: []byte{
				0x30, 0x9e, 0xcc, 0x48, 0x9c, 0x12, 0xd6, 0xeb, 0x4c, 0xc4, 0x0f, 0x50, 0xc9, 0x02, 0xf2, 0xb4,
				0xd0, 0xed, 0x77, 0xee, 0x51, 0x1a, 0x7c, 0x7a, 0x9b, 0xcd, 0x3c, 0xa8, 0x6d, 0x4c, 0xd8, 0x6f,
				0x98, 0x9d, 0xd3, 0x5b, 0xc5, 0xff, 0x49, 0x96, 0x70, 0xda, 0x34, 0x25, 0x5b, 0x45, 0xb0, 0xcf,
				0xd8, 0x30, 0xe8, 0x1f, 0x60, 0x5d, 0xcf, 0x7d, 0xc5, 0x54, 0x2e, 0x93, 0xae, 0x9c, 0xd7, 0x6f,
			},
		},
		{
			name: "ES256",
			alg:  AlgorithmES256,
			want: []byte{
				0xb9, 0x4d, 0x27, 0xb9, 0x93, 0x4d, 0x3e, 0x08, 0xa5, 0x2e, 0x52, 0xd7, 0xda, 0x7d, 0xab, 0xfa,
				0xc4, 0x84, 0xef, 0xe3, 0x7a, 0x53, 0x80, 0xee, 0x90, 0x88, 0xf7, 0xac, 0xe2, 0xef, 0xcd, 0xe9,
			},
		},
		{
			name: "ES384",
			alg:  AlgorithmES384,
			want: []byte{
				0xfd, 0xbd, 0x8e, 0x75, 0xa6, 0x7f, 0x29, 0xf7, 0x01, 0xa4, 0xe0, 0x40, 0x38, 0x5e, 0x2e, 0x23,
				0x98, 0x63, 0x03, 0xea, 0x10, 0x23, 0x92, 0x11, 0xaf, 0x90, 0x7f, 0xcb, 0xb8, 0x35, 0x78, 0xb3,
				0xe4, 0x17, 0xcb, 0x71, 0xce, 0x64, 0x6e, 0xfd, 0x08, 0x19, 0xdd, 0x8c, 0x08, 0x8d, 0xe1, 0xbd,
			},
		},
		{
			name: "ES512",
			alg:  AlgorithmES512,
			want: []byte{
				0x30, 0x9e, 0xcc, 0x48, 0x9c, 0x12, 0xd6, 0xeb, 0x4c, 0xc4, 0x0f, 0x50, 0xc9, 0x02, 0xf2, 0xb4,
				0xd0, 0xed, 0x77, 0xee, 0x51, 0x1a, 0x7c, 0x7a, 0x9b, 0xcd, 0x3c, 0xa8, 0x6d, 0x4c, 0xd8, 0x6f,
				0x98, 0x9d, 0xd3, 0x5b, 0xc5, 0xff, 0x49, 0x96, 0x70, 0xda, 0x34, 0x25, 0x5b, 0x45, 0xb0, 0xcf,
				0xd8, 0x30, 0xe8, 0x1f, 0x60, 0x5d, 0xcf, 0x7d, 0xc5, 0x54, 0x2e, 0x93, 0xae, 0x9c, 0xd7, 0x6f,
			},
		},
		{
			name: "Ed25519",
			alg:  AlgorithmEd25519,
			want: data,
		},
		{
			name: "extended algorithm with crypto.Hash",
			alg:  algFoo,
			want: []byte{
				0xb9, 0x4d, 0x27, 0xb9, 0x93, 0x4d, 0x3e, 0x08, 0xa5, 0x2e, 0x52, 0xd7, 0xda, 0x7d, 0xab, 0xfa,
				0xc4, 0x84, 0xef, 0xe3, 0x7a, 0x53, 0x80, 0xee, 0x90, 0x88, 0xf7, 0xac, 0xe2, 0xef, 0xcd, 0xe9,
			},
		},
		{
			name: "extended algorithm with hashFunc",
			alg:  algBar,
			want: []byte{
				0xb9, 0x4d, 0x27, 0xb9, 0x93, 0x4d, 0x3e, 0x08, 0xa5, 0x2e, 0x52, 0xd7, 0xda, 0x7d, 0xab, 0xfa,
				0xc4, 0x84, 0xef, 0xe3, 0x7a, 0x53, 0x80, 0xee, 0x90, 0x88, 0xf7, 0xac, 0xe2, 0xef, 0xcd, 0xe9,
			},
		},
		{
			name: "extended algorithm without hash",
			alg:  algPlain,
			want: data,
		},
		{
			name:    "unknown algorithm",
			alg:     0,
			wantErr: ErrUnknownAlgorithm,
		},
		{
			name:    "unknown hash",
			alg:     algUnavailableHash,
			wantErr: ErrUnavailableHashFunc,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.alg.computeHash(data)
			if err != tt.wantErr {
				t.Errorf("Algorithm.computeHash() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Algorithm.computeHash() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRegisterAlgorithm(t *testing.T) {
	defer resetExtendedAlgorithm()

	// Register algorithms concurrently to ensure testing on race mode catches races.
	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		// register existing algorithm (should fail)
		if err := RegisterAlgorithm(AlgorithmES256, "ES256", crypto.SHA256, nil); err != ErrAlgorithmRegistered {
			t.Errorf("RegisterAlgorithm() error = %v, wantErr %v", err, ErrAlgorithmRegistered)
		}
	}()

	algFoo := Algorithm(-102)
	go func() {
		defer wg.Done()
		// register external algorithm
		if err := RegisterAlgorithm(algFoo, "foo", 0, nil); err != nil {
			t.Errorf("RegisterAlgorithm() error = %v, wantErr %v", err, false)
		}
	}()

	go func() {
		defer wg.Done()
		// double register external algorithm (should fail)
		if err := RegisterAlgorithm(algFoo, "foo", 0, nil); err != ErrAlgorithmRegistered {
			t.Errorf("RegisterAlgorithm() error = %v, wantErr %v", err, ErrAlgorithmRegistered)
		}
	}()
	wg.Wait()
}
