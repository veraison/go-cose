package x509testdata

import (
	_ "embed"
)

var (
	//go:embed endEntity.der
	EndEntityDer []byte

	//go:embed intermediateCA.der
	IntermediateCA []byte

	//go:embed rootCA.der
	RootCA []byte

	//go:embed endEntity.key
	EndEntityKey []byte
)
