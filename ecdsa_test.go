package cose

import (
	"math/big"
	"reflect"
	"testing"
)

func TestI2OSP(t *testing.T) {
	tests := []struct {
		name    string
		x       *big.Int
		xLen    int
		want    []byte
		wantErr bool
	}{
		{
			name:    "negative int",
			x:       big.NewInt(-1),
			xLen:    2,
			wantErr: true,
		},
		{
			name:    "integer too large #1",
			x:       big.NewInt(1),
			xLen:    0,
			wantErr: true,
		},
		{
			name:    "integer too large #2",
			x:       big.NewInt(256),
			xLen:    0,
			wantErr: true,
		},
		{
			name: "zero length string",
			x:    big.NewInt(0),
			xLen: 0,
			want: []byte{},
		},
		{
			name: "I2OSP(0, 2)",
			x:    big.NewInt(0),
			xLen: 2,
			want: []byte{0x00, 0x00},
		},
		{
			name: "I2OSP(1, 2)",
			x:    big.NewInt(1),
			xLen: 2,
			want: []byte{0x00, 0x01},
		},
		{
			name: "I2OSP(255, 2)",
			x:    big.NewInt(255),
			xLen: 2,
			want: []byte{0x00, 0xff},
		},
		{
			name: "I2OSP(256, 2)",
			x:    big.NewInt(256),
			xLen: 2,
			want: []byte{0x01, 0x00},
		},
		{
			name: "I2OSP(65535, 2)",
			x:    big.NewInt(65535),
			xLen: 2,
			want: []byte{0xff, 0xff},
		},
		{
			name: "I2OSP(1234, 5)",
			x:    big.NewInt(1234),
			xLen: 5,
			want: []byte{0x00, 0x00, 0x00, 0x04, 0xd2},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := I2OSP(tt.x, tt.xLen)
			if (err != nil) != tt.wantErr {
				t.Errorf("I2OSP() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("I2OSP() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOS2IP(t *testing.T) {
	type args struct {
	}
	tests := []struct {
		name string
		x    []byte
		want *big.Int
	}{
		{
			name: "zero length string",
			x:    []byte{},
			want: big.NewInt(0),
		},
		{
			name: "OS2IP(I2OSP(0, 2))",
			x:    []byte{0x00, 0x00},
			want: big.NewInt(0),
		},
		{
			name: "OS2IP(I2OSP(1, 2))",
			x:    []byte{0x00, 0x01},
			want: big.NewInt(1),
		},
		{
			name: "OS2IP(I2OSP(255, 2))",
			x:    []byte{0x00, 0xff},
			want: big.NewInt(255),
		},
		{
			name: "OS2IP(I2OSP(256, 2))",
			x:    []byte{0x01, 0x00},
			want: big.NewInt(256),
		},
		{
			name: "OS2IP(I2OSP(65535, 2))",
			x:    []byte{0xff, 0xff},
			want: big.NewInt(65535),
		},
		{
			name: "OS2IP(I2OSP(1234, 5))",
			x:    []byte{0x00, 0x00, 0x00, 0x04, 0xd2},
			want: big.NewInt(1234),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := OS2IP(tt.x); tt.want.Cmp(got) != 0 {
				t.Errorf("OS2IP() = %v, want %v", got, tt.want)
			}
		})
	}
}
