# go-cose

[![go.dev](https://pkg.go.dev/badge/github.com/veraison/go-cose.svg)](https://pkg.go.dev/github.com/veraison/go-cose)
[![tests](https://github.com/veraison/go-cose/workflows/ci/badge.svg)](https://github.com/veraison/go-cose/actions?query=workflow%3Aci)
[![coverage](https://github.com/veraison/go-cose/workflows/cover%20%E2%89%A589%25/badge.svg)](https://github.com/veraison/go-cose/actions?query=workflow%3A%22cover%20%E2%89%A589%25%22)

A [COSE](https://tools.ietf.org/html/rfc8152) library for go.

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

```go
import "github.com/veraison/go-cose"
```

Construct a new COSE_Sign1 message, then sign it using ECDSA w/ 512 and finally marshal it. For example:

```go
// create a signer
privateKey, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
signer, _ := cose.NewSigner(cose.AlgorithmES512, privateKey)

// create message to be signed
msg := cose.NewSign1Message()
msgToSign.Payload = []byte("hello world")
msg.Headers.Protected.SetAlgorithm(cose.AlgorithmES512)

// sign message
_ = msg.Sign(rand.Reader, nil, signer)

// marshall message
data, _ := msg.MarshalCBOR()
```

Verify a raw COSE_Sign1 message. For example:

```go
// create a verifier from a trusted private key
publicKey := privateKey.Public()
verifier, _ := cose.NewVerifier(cose.AlgorithmES512, publicKey)

// create a sign message from a raw COSE_Sign1 payload
var msg cose.Sign1Message
_ = msg.UnmarshalCBOR(raw)
_ = msg.Verify(nil, verifier)
```

## Features

### Signing and Verifying Objects

go-cose supports two different signature structures:
- [cose.Sign1Message](https://pkg.go.dev/github.com/veraison/go-cose#Sign1Message) implements [COSE_Sign1](https://datatracker.ietf.org/doc/html/rfc8152#section-4.2).
- [cose.SignMessage](https://pkg.go.dev/github.com/veraison/go-cose#SignMessage) implements [COSE_Sign](https://datatracker.ietf.org/doc/html/rfc8152#section-4.1).

### Built-in Algorithms

go-cose has built-in supports the following algorithms:
- PS{256,384,512}: RSASSA-PSS w/ SHA as defined in RFC 8230.
- ES{256,384,512}: ECDSA w/ SHA as defined in RFC 8152.
- Ed25519: PureEdDSA as defined in RFC 8152.

### Custom Algorithms

The supported algorithms can be extended at runtime by using [cose.RegisterAlgorithm](https://pkg.go.dev/github.com/veraison/go-cose#RegisterAlgorithm).

[API docs](https://pkg.go.dev/github.com/veraison/go-cose)

### Conformance Tests

go-cose runs the [GlueCOSE](https://github.com/gluecose/test-vectors) test suite on every local `go test` execution.
These are also executed on every CI job.

### Fuzz Tests

go-cose implements several fuzz tests using [Go's native fuzzing](https://go.dev/doc/fuzz).

Fuzzing only requires Go 1.18 or higher, and can be executed as follows:

```bash
go test -fuzz=FuzzSign1
```
