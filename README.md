# go-cose

[![go.dev](https://pkg.go.dev/badge/github.com/veraison/go-cose.svg)](https://pkg.go.dev/github.com/veraison/go-cose)
[![tests](https://github.com/veraison/go-cose/workflows/ci/badge.svg)](https://github.com/veraison/go-cose/actions?query=workflow%3Aci)
[![codecov](https://codecov.io/gh/veraison/go-cose/branch/main/graph/badge.svg?token=SL18TCTC03)](https://codecov.io/gh/veraison/go-cose)

A golang library for the [COSE specification][cose-spec]

## Project Status

The verasion/go-cose project is actively maintained.
See [current releases](https://github.com/veraison/go-cose/releases).

The project was *initially* forked from the  upstream [mozilla-services/go-cose][mozilla-go-cose] project, however the Veraison and Mozilla maintainers have agreed to retire the mozilla-services/go-cose project and focus on [veraison/go-cose][veraison-go-cose] as the active project.

We thank the [Mozilla maintainers and contributors][mozilla-contributors] for their great work that formed the base of the [veraison/go-cose][veraison-go-cose] project.

## Community

The [veraison/go-cose](https://github.com/veraison/go-cose) project is an open source community effort.

You can reach the go-cose community via::

- [Mailing List](veraison-project@confidentialcomputing.io)
- Bi-weekly meetings: 08:00-09:00 Pacific
  - [Zoom meeting link](https://us02web.zoom.us/j/81054434992?pwd=YjNBU21seU5VcGdtVXY3VHVjS251Zz09)
  - [Calendar ics link](https://zoom.us/meeting/tZUtcu2srT8jE9YFubXn-lC9upuwUiiev52G/ics)
- [Meeting Notes](https://veraison.zulipchat.com/#narrow/stream/317999-go-cose-meetings)
- [Meeting Recordings](https://www.youtube.com/@go-cose-community3000)

Participation in the go-cose community is governed by the Veraison [CODE_OF_CONDUCT.md](https://github.com/veraison/.github/blob/main/CODE_OF_CONDUCT.md) and [GOVERNANCE.md](https://github.com/veraison/community/blob/main/GOVERNANCE.md)

## Code of Conduct

This project has adopted the [Contributor Covenant Code of Conduct](https://github.com/veraison/.github/blob/main/CODE_OF_CONDUCT.md).

## Installation

go-cose is compatible with modern Go releases in module mode, with Go installed:

```bash
go get github.com/veraison/go-cose
```

will resolve and add the package to the current development module, along with its dependencies.

Alternatively the same can be achieved if you use import in a package:

```go
import "github.com/veraison/go-cose"
```

and run `go get` without parameters.

Finally, to use the top-of-trunk version of this repo, use the following command:

```bash
go get github.com/veraison/go-cose@main
```

## Usage

### Signing and Verification

```go
import "github.com/veraison/go-cose"
```

Construct a new COSE_Sign1_Tagged message, then sign it using ECDSA w/ SHA-256 and finally marshal it. For example:

```go
package main

import (
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    _ "crypto/sha256"

    "github.com/veraison/go-cose"
)

func SignP256(data []byte) ([]byte, error) {
    // create a signer
    privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    if err != nil {
        return nil, err
    }
    signer, err := cose.NewSigner(cose.AlgorithmES256, privateKey)
    if err != nil {
        return nil, err
    }

    // create message header
    headers := cose.Headers{
        Protected: cose.ProtectedHeader{
            cose.HeaderLabelAlgorithm: cose.AlgorithmES256,
        },
    }

    // sign and marshal message
    return cose.Sign1(rand.Reader, signer, headers, data, nil)
}
```

Verify a raw COSE_Sign1_Tagged message. For example:

```go
package main

import (
    "crypto"
    _ "crypto/sha256"

    "github.com/veraison/go-cose"
)

func VerifyP256(publicKey crypto.PublicKey, sig []byte) error {
    // create a verifier from a trusted private key
    verifier, err := cose.NewVerifier(cose.AlgorithmES256, publicKey)
    if err != nil {
        return err
    }

    // create a sign message from a raw COSE_Sign1 payload
    var msg cose.Sign1Message
    if err = msg.UnmarshalCBOR(sig); err != nil {
        return err
    }
    return msg.Verify(nil, verifier)
}
```

See [example_test.go](./example_test.go) for more examples.

#### Untagged Signing and Verification

Untagged COSE_Sign1 messages can be signed and verified as above, using
`cose.UntaggedSign1Message` instead of `cose.Sign1Message`.

#### Signing and Verification of payload digest

When `cose.NewSigner` is used with PS{256,384,512} or ES{256,384,512}, the returned signer
can be casted to the `cose.DigestSigner` interface, whose `SignDigest` method signs an
already digested message.

When `cose.NewVerifier` is used with PS{256,384,512} or ES{256,384,512}, the returned verifier
can be casted to the `cose.DigestVerifier` interface, whose `VerifyDigest` method verifies an
already digested message.

Please refer to [example_test.go](./example_test.go) for the API usage.

### About hashing

`go-cose` does not import any hash package by its own to avoid linking unnecessary algorithms to the final binary.
It is the the responsibility of the `go-cose` user to make the necessary hash functions available at runtime, i.e.,
by using a blank import:

```go
import (
    _ "crypto/sha256"
    _ "crypto/sha512"
)
```

These are the required packages for each built-in cose.Algorithm:

- cose.AlgorithmPS256, cose.AlgorithmES256: `crypto/sha256`
- cose.AlgorithmPS384, cose.AlgorithmPS512, cose.AlgorithmES384, cose.AlgorithmES512: `crypto/sha512`
- cose.AlgorithmEdDSA: none

### Countersigning

It is possible to countersign `cose.Sign1Message`, `cose.SignMessage`, `cose.Signature` and
`cose.Countersignature` objects and add them as unprotected headers. In order to do so, first create
a countersignature holder with `cose.NewCountersignature()` and call its `Sign` function passing
the parent object which is going to be countersigned. Then assign the countersignature as an
unprotected header `cose.HeaderLabelCounterSignatureV2` or, if preferred, maintain it as a
detached countersignature.

When verifying countersignatures, it is necessary to pass the parent object in the `Verify` function
of the countersignature holder.

See [example_test.go](./example_test.go) for examples.

## Features

### Signing and Verifying Objects

go-cose supports two different signature structures:
- [cose.Sign1Message](https://pkg.go.dev/github.com/veraison/go-cose#Sign1Message) implements [COSE_Sign1](https://datatracker.ietf.org/doc/html/rfc8152#section-4.2).
- [cose.SignMessage](https://pkg.go.dev/github.com/veraison/go-cose#SignMessage) implements [COSE_Sign](https://datatracker.ietf.org/doc/html/rfc8152#section-4.1).
> :warning: The COSE_Sign API is currently **EXPERIMENTAL** and may be changed or removed in a later release.  In addition, the amount of functional and security testing it has received so far is significantly lower than the COSE_Sign1 API.

### Countersignatures

go-cose supports [COSE_Countersignature](https://tools.ietf.org/html/rfc9338#section-3.1), check [cose.Countersignature](https://pkg.go.dev/github.com/veraison/go-cose#Countersignature).
> :warning: The COSE_Countersignature API is currently **EXPERIMENTAL** and may be changed or removed in a later release.

### Built-in Algorithms

go-cose has built-in supports the following algorithms:
- PS{256,384,512}: RSASSA-PSS w/ SHA as defined in RFC 8230.
- ES{256,384,512}: ECDSA w/ SHA as defined in RFC 8152.
- Ed25519: PureEdDSA as defined in RFC 8152.

### Custom Algorithms

It is possible to use custom algorithms with this library, for example:

```go
package cose_test

import (
	"errors"
	"io"
	"testing"

	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/schemes"
	"github.com/veraison/go-cose"
)

type customKeySigner struct {
	alg cose.Algorithm
	key sign.PrivateKey
}

func (ks *customKeySigner) Algorithm() cose.Algorithm {
	return ks.alg
}

func (ks *customKeySigner) Sign(rand io.Reader, content []byte) ([]byte, error) {
	suite := schemes.ByName("ML-DSA-44")
	return suite.Sign(ks.key, content, nil), nil
}

type customKeyVerifier struct {
	alg cose.Algorithm
	key sign.PublicKey
}

func (ks *customKeyVerifier) Algorithm() cose.Algorithm {
	return ks.alg
}

func (ks *customKeyVerifier) Verify(content []byte, signature []byte) error {
	suite := schemes.ByName("ML-DSA-44")
	valid := suite.Verify(ks.key, content, signature, nil)
	if !valid {
		return errors.New("Signature not from public key")
	}
	return nil
}

func TestCustomSigner(t *testing.T) {
	const (
		COSE_ALG_ML_DSA_44 = -48
	)
	suite := schemes.ByName("ML-DSA-44")
	var seed [32]byte // zero seed
	pub, priv := suite.DeriveKey(seed[:])
	var ks cose.Signer = &customKeySigner{
		alg: COSE_ALG_ML_DSA_44,
		key: priv,
	}
	var kv = customKeyVerifier{
		alg: COSE_ALG_ML_DSA_44,
		key: pub,
	}

	headers := cose.Headers{
		Protected: cose.ProtectedHeader{
			cose.HeaderLabelAlgorithm: COSE_ALG_ML_DSA_44,
			cose.HeaderLabelKeyID:     []byte("key-42"),
		},
	}
	var payload = []byte("hello post quantum signatures")
	signature, _ := cose.Sign1(nil, ks, headers, payload, nil)
	var sign1 cose.Sign1Message
	_ = sign1.UnmarshalCBOR(signature)

	var verifier cose.Verifier = &kv
	verifyError := sign1.Verify(nil, verifier)

	if verifyError != nil {
		t.Fatalf("Verification failed")
	} else {
		// fmt.Println(cbor.Diagnose(signature))
		// 18([
		// 	<<{
		//  / alg / 1: -48,
		//  / kid / 4: h'6B65792D3432'}
		//  >>,
		// 	{},
		// 	h'4974...722e',
		// 	h'cb5a...293b'
		// ])
	}
}
```

### Integer Ranges

CBOR supports integers in the range [-2<sup>64</sup>, -1] ∪ [0, 2<sup>64</sup> - 1].

This does not map onto a single Go integer type.

`go-cose` uses `int64` to encompass both positive and negative values to keep data sizes smaller and easy to use.

The main effect is that integer label values in the [-2<sup>64</sup>, -2<sup>63</sup> - 1] and the [2<sup>63</sup>, 2<sup>64</sup> - 1] ranges, which are nominally valid
per RFC 8152, are rejected by the go-cose library.

### Conformance Tests

`go-cose` runs the [GlueCOSE](https://github.com/gluecose/test-vectors) test suite on every local `go test` execution.
These are also executed on every CI job.

### Fuzz Tests

`go-cose` implements several fuzz tests using [Go's native fuzzing](https://go.dev/doc/fuzz).

Fuzzing requires Go 1.18 or higher, and can be executed as follows:

```bash
go test -fuzz=FuzzSign1
```

### Security Reviews

`go-cose` undergoes periodic security review. The security review reports are located [here](./reports)

[cose-spec]:            https://datatracker.ietf.org/doc/rfc9052/
[mozilla-contributors]: https://github.com/mozilla-services/go-cose/graphs/contributors
[mozilla-go-cose]:      http://github.com/mozilla-services/go-cose
[veraison-go-cose]:     https://github.com/veraison/go-cose
