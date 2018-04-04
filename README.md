# go-cose

[![Build Status](https://travis-ci.org/mozilla-services/go-cose.svg?branch=master)](https://travis-ci.org/mozilla-services/go-cose)
[![Coverage Status](https://coveralls.io/repos/github/mozilla-services/go-cose/badge.svg)](https://coveralls.io/github/mozilla-services/go-cose)

A [COSE](https://tools.ietf.org/html/rfc8152) library for go.

It currently supports signing and verifying the SignMessage type with the ES{256,384,512} and PS256 algorithms.

[API docs](https://godoc.org/go.mozilla.org/cose)

## Usage

### Install

```console
go get -u go.mozilla.org/cose
```

### Signing a message

From [example/sign.go](example/sign.go):

```golang
...
	// create a signer
	signer, err := cose.NewSigner(&ecdsaPrivateKey)
	if err != nil {
		panic(fmt.Sprintf(fmt.Sprintf("Error creating signer %s", err)))
	}

	// create a signature
	sig := cose.NewSignature()
	sig.Headers.Unprotected["kid"] = 1
	sig.Headers.Protected["alg"] = "ES256"

	// create a message
	payload := []byte("payload to sign")
	external := []byte("") // optional external data see https://tools.ietf.org/html/rfc8152#section-4.3

	msg := cose.NewSignMessage(payload) // can update via .Payload later too
	msg.AddSignature(sig)

	randReader := rand.New(rand.NewSource(time.Now().UnixNano()))
	err = msg.Sign(randReader, external, cose.SignOpts{
		HashFunc: crypto.SHA256,
		GetSigner: func(index int, signature cose.Signature) (cose.Signer, error) {
			if signature.Headers.Unprotected["kid"] == 1 || signature.Headers.Unprotected[cose.GetCommonHeaderTagOrPanic("kid")] == 1 {
				return *signer, nil
			} else {
				return *signer, cose.ErrNoSignerFound
			}
		},
	})
	if err == nil {
		fmt.Println(fmt.Sprintf("Message signature (ES256): %x", msg.Signatures[0].SignatureBytes))
	} else {
		fmt.Println(fmt.Sprintf("Error signing the message %+v", err))
	}
...
```

To run the full example (your signature will vary):

```console
$ go run example/sign.go
Message signature (ES256): 043685f99421f9e80c7c3c50d0fc8266161d3d614aaa3b63d2cdf581713fca62bb5d2e34d2352dbe41424b31d0b4a11d6b2d4764c18e2af04f4520fbe494d51c
```

### Verifying a message

Continuing from the signer example in [example/verify.go](example/verify.go):

```golang
...
	// derive a verifier from out signer's public key
	verifier := signer.Verifier(cose.GetAlgByNameOrPanic("ES256"))

	// Verify
	err = msg.Verify(external, &cose.VerifyOpts{
		GetVerifier: func(index int, signature cose.Signature) (cose.Verifier, error) {
			// or return cose.ErrNoVerifierFound
			return *verifier, nil
		},
	})
	if err == nil {
		fmt.Println("Message signature verified")
	} else {
		fmt.Println(fmt.Sprintf("Error verifying the message %+v", err))
	}
...
```

To run the full example (your signature will vary):

```console
$ go run example/verify.go
Message signature (ES256): 9411dc5200c1cb67ccd76424ade09ce89c4a8d8d2b66f2bbf70edf63beb2dc3cbde83250773e659b635d3715442a1efaa6b0c030ee8a2523c3e37a22ddb055fa
Message signature verified
```

## Development

Running tests:

```console
make godep golint  # skip if you already have them
make install
go test # note that the rust tests will fail
```

The [cose-rust](https://github.com/g-k/cose-rust) tests run in CI. To run them locally:

1. Install [rust and cargo](https://www.rustup.rs/)
1. On OSX, you might need to:
  1. `brew install nss` [nss](https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS)
  1. Add `NSS_LIB_DIR` to the cmd in `sign_verify_cose_rust_cli_test.go` e.g. `cmd.Env = append(os.Environ(), "NSS_LIB_DIR=/usr/local/opt/nss/lib", "RUSTFLAGS=-A dead_code -A unused_imports")`
1. It can also be helpful to add the following to print output from the cmd too:

	```golang
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	```
