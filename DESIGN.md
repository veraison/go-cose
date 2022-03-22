# COSE Golang Library

## Objectives

The objectives of the `go-cose` library of this doc are

- Implement `COSE_Sign` and `COSE_Sign1` as specified in [RFC8152](https://datatracker.ietf.org/doc/html/rfc8152).
- Make the implementation secure and efficient.
- Provide signing and verification based on golang built-in crypto libraries.
- Provide extensibility so that other implementation can be used for signing and verification.
  - This objective implies remote signing.
- Be golang native.
  - Write documentation and examples for `godoc`.
  - Test using `go test` with both positive and negative test cases.

## Implementation Gaps

Here are the gaps between the current implementation and the objectives:

- The current implementation implements `COSE_Sign` and `COSE_Sign1`. However, the verification process does not follow [RFC8152](https://datatracker.ietf.org/doc/html/rfc8152) and causes [issue #7](https://github.com/veraison/go-cose/issues/7). There are also implementation errors in signing and verification (see [issue #8](https://github.com/veraison/go-cose/issues/8)).
- The efficiency of the current implementation can be improved with crypto domain knowledge. For instances,
  - Remove the use of constant time copy in `I2OSP`.
  - Remove the check on `(r,s)` against `n`.
- The current implementation implements `PS256`, `ES256`, `ES384`, `ES512`, and misses other common algorithms like `PS384`, `PS512`, `EdDSA` (e.g. `Ed25519`).
  - All conventional signature schemes are _signature with appendix_.
  - `RS256`, `RS384`, `RS512`, `ES256K` are marked **NOT RECOMMENDED** by [RFC8812](https://datatracker.ietf.org/doc/html/rfc8812).
- The current implementation has solid `Signer` and `Verify` structures and can only sign or verify against certain algorithms (see [issue #9](https://github.com/veraison/go-cose/issues/9)). The implementation cannot be extended to have new algorithms or new implementation for existing algorithms.
- The current implementation is not golang native.
  - Relies on `cose-rust` for testing and development.
  - Examples are not shown in `godoc` and are not clear, especially for verification.

## Proposal

In order to bridge the gaps, the following items are proposed:

1. Refactor existing APIs for extensibility.
2. Code clean up.
3. Scan crypto implementation and patch vulnerabilities and improve code efficiency.
4. Implement support for more algorithms.
5. Write Go examples and tests.

### API Breaking Changes

The APIs of the current `go-cose` implementation are listed below. Details can be found in [godoc](https://pkg.go.dev/github.com/veraison/go-cose).

Constants:

```go
SignMessageCBORTag  = 98
Sign1MessageCBORTag = 18

ContextSignature  = "Signature"
ContextSignature1 = "Signature1"
```

Variables:

```go
PS256 = getAlgByNameOrPanic("PS256")
ES256 = getAlgByNameOrPanic("ES256")
ES384 = getAlgByNameOrPanic("ES384")
ES512 = getAlgByNameOrPanic("ES512")

ErrInvalidAlg               = errors.New("Invalid algorithm")
ErrAlgNotFound              = errors.New("Error fetching alg")
ErrECDSAVerification        = errors.New("verification failed ecdsa.Verify")
ErrRSAPSSVerification       = errors.New("verification failed rsa.VerifyPSS err crypto/rsa: verification error")
ErrMissingCOSETagForLabel   = errors.New("No common COSE tag for label")
ErrMissingCOSETagForTag     = errors.New("No common COSE label for tag")
ErrNilSigHeader             = errors.New("Signature.headers is nil")
ErrNilSigProtectedHeaders   = errors.New("Signature.headers.protected is nil")
ErrNilSignatures            = errors.New("SignMessage.signatures is nil. Use AddSignature to add one")
ErrNoSignatures             = errors.New("No signatures to sign the message. Use AddSignature to add them")
ErrNoSignerFound            = errors.New("No signer found")
ErrNoVerifierFound          = errors.New("No verifier found")
ErrUnavailableHashFunc      = errors.New("hash function is not available")
ErrUnknownPrivateKeyType    = errors.New("Unrecognized private key type")
ErrUnknownPublicKeyType     = errors.New("Unrecognized public key type")
ErrNilSign1Headers          = errors.New("Sign1Message.headers is nil")
ErrNilSign1ProtectedHeaders = errors.New("Sign1Message.headers.protected is nil")
```

Functions and types:

```go
func CompressHeaders(headers map[interface{}]interface{}) (compressed map[interface{}]interface{})
func DecompressHeaders(headers map[interface{}]interface{}) (decompressed map[interface{}]interface{})
func FindDuplicateHeader(headers *Headers) interface{}
func FromBase64Int(data string) *big.Int
func GetCommonHeaderLabel(tag int) (label string, err error)
func GetCommonHeaderTag(label string) (tag int, err error)
func GetCommonHeaderTagOrPanic(label string) (tag int)
func I2OSP(b *big.Int, n int) []byte
func IsSign1Message(data []byte) bool
func IsSignMessage(data []byte) bool
func Marshal(o interface{}) (b []byte, err error)
func Sign(rand io.Reader, digest []byte, signers []ByteSigner) (signatures [][]byte, err error)
func Unmarshal(b []byte) (o interface{}, err error)
func Verify(digest []byte, signatures [][]byte, verifiers []ByteVerifier) (err error)
type Algorithm
    func GetAlg(h *Headers) (alg *Algorithm, err error)
type ByteSigner
type ByteVerifier
type Headers
    func (h *Headers) Decode(o []interface{}) (err error)
    func (h *Headers) DecodeProtected(o interface{}) (err error)
    func (h *Headers) DecodeUnprotected(o interface{}) (err error)
    func (h *Headers) EncodeProtected() (bstr []byte)
    func (h *Headers) EncodeUnprotected() (encoded map[interface{}]interface{})
type KeyType
type RSAOptions
type Sign1Message
    func NewSign1Message() *Sign1Message
    func (message *Sign1Message) MarshalCBOR() ([]byte, error)
    func (m *Sign1Message) SigStructure(external []byte) ([]byte, error)
    func (m *Sign1Message) Sign(rand io.Reader, external []byte, signer Signer) (err error)
    func (message *Sign1Message) UnmarshalCBOR(data []byte) (err error)
    func (m Sign1Message) Verify(external []byte, verifier Verifier) (err error)
type SignMessage
    func NewSignMessage() *SignMessage
    func (m *SignMessage) AddSignature(s *Signature)
    func (message *SignMessage) MarshalCBOR() ([]byte, error)
    func (m *SignMessage) SigStructure(external []byte, signature *Signature) (ToBeSigned []byte, err error)
    func (m *SignMessage) Sign(rand io.Reader, external []byte, signers []Signer) (err error)
    func (message *SignMessage) UnmarshalCBOR(data []byte) (err error)
    func (m *SignMessage) Verify(external []byte, verifiers []Verifier) (err error)
type Signature
    func NewSignature() (s *Signature)
    func (s *Signature) Decode(o interface{})
    func (s *Signature) Equal(other *Signature) bool
type Signer
    func NewSigner(alg *Algorithm, options interface{}) (signer *Signer, err error)
    func NewSignerFromKey(alg *Algorithm, privateKey crypto.PrivateKey) (signer *Signer, err error)
    func (s Signer) GetAlg() *Algorithm
    func (s *Signer) Public() (publicKey crypto.PublicKey)
    func (s *Signer) Sign(rand io.Reader, digest []byte) (signature []byte, err error)
    func (s *Signer) Verifier() (verifier *Verifier)
type Verifier
    func (v *Verifier) Verify(digest []byte, signature []byte) (err error)
```

Here are the proposed APIs:

```go
const (
    HeaderLabelAlgorithm         = 1
    HeaderLabelCritical          = 2
    HeaderLabelContentType       = 3
    HeaderLabelKeyID             = 4
    HeaderLabelCounterSignature  = 7
    HeaderLabelCounterSignature0 = 9
    HeaderLabelX5Bag             = 32
    HeaderLabelX5Chain           = 33
    HeaderLabelX5T               = 34
    HeaderLabelX5U               = 35
)

const (
    CBORTagSignMessage  = 98
    CBORTagSign1Message = 18
)

const (
    ContextSignature  = "Signature"
    ContextSignature1 = "Signature1"
)

var (
    AlgorithmPS256   *Algorithm
    AlgorithmPS384   *Algorithm
    AlgorithmPS512   *Algorithm
    AlgorithmES256   *Algorithm
    AlgorithmES384   *Algorithm
    AlgorithmES512   *Algorithm
    AlgorithmEd25519 *Algorithm
)

type Algorithm struct {
    Name     string
    Value    int
    HashFunc crypto.Hash
}

func I2OSP(x *big.Int, n int) ([]byte, error)
func OS2IP(x []byte) *big.Int

type ProtectedHeader map[interface{}]interface{}
    func (h *ProtectedHeader) MarshalCBOR() ([]byte, error)
    func (h *ProtectedHeader) UnmarshalCBOR(data []byte) error
    func (h *ProtectedHeader) SetAlgorithm(alg *Algorithm)

type UnprotectedHeader map[interface{}]interface{}

type Headers struct {
    RawProtected   []byte
    RawUnprotected []byte
    Protected      ProtectedHeader
    Unprotected    UnprotectedHeader
}

type Signature struct {
    Headers   Headers
    Signature []byte
}
    func NewSignature() *Signature
    func (s *Signature) MarshalCBOR() ([]byte, error)
    func (s *Signature) UnmarshalCBOR(data []byte) error

type SignMessage struct {
    Headers    Headers
    Payload    []byte
    Signatures []*Signature
}
    func NewSignMessage() *SignMessage
    func ParseSignMessage(data []byte) (*SignMessage, error)
    func (m *SignMessage) MarshalCBOR() ([]byte, error)
    func (m *SignMessage) UnmarshalCBOR(data []byte) error
    func (m *SignMessage) Sign(ctx context.Context, external []byte, signers []Signer) error
    func (m *SignMessage) Verify(ctx context.Context, external []byte, verifier []Verifier) error

type Sign1Message struct {
    Headers   Headers
    Payload   []byte
    Signature []byte
}
    func NewSign1Message() *Sign1Message
    func ParseSign1Message(data []byte) (*Sign1Message, error)
    func (m *Sign1Message) MarshalCBOR() ([]byte, error)
    func (m *Sign1Message) UnmarshalCBOR(data []byte) error
    func (m *Sign1Message) Sign(ctx context.Context, external []byte, signer Signer) error
    func (m *Sign1Message) Verify(ctx context.Context, external []byte, verifier Verifier) error

type Signer interface {
    Algorithm() *Algorithm
    Sign(ctx context.Context, digest []byte) ([]byte, error)
}
    func NewSigner(alg *Algorithm, key crypto.Signer) (Signer, error)
    func NewSignerWithEphemeralKey(alg *Algorithm) (Signer, crypto.PrivateKey, error)

type Verifier interface {
    Algorithm() *Algorithm
    Verify(ctx context.Context, digest, signature []byte) error
}
    func NewVerifier(alg *Algorithm, key crypto.PublicKey) (Verifier, error)
```

Key changes:

- Header related functions are cleaned up.
  - String header labels are not registered in [IANA "COSE Header Parameters" Registry](https://www.iana.org/assignments/cose/cose.xhtml#header-parameters), and thus are cleaned.
- `Signer` is now an interface.
  - `Sign` takes `context.Context` as input with `rand io.Reader` removed since it is potentially a RPC call.
  - `NewSigner` takes `crypto.Signer` where `Public()` must output a public key of type `*rsa.PublicKey`, `*ecdsa.PublicKey`, or `ed25519.PublicKey`.
    - Note: `*rsa.PrivateKey`, `*ecdsa.PrivateKey`, and `ed25519.PrivateKey` implement `crypto.Signer`.
  - `NewSignerWithEphemeralKey` is added mainly for testing or example purposes, and can be moved in the final version.
    - `crypto.PublicKey` can be obtained from `crypto.PrivateKey` by casting
      ```go
      var publicKey crypto.PublicKey
      if key, ok := privateKey.(interface{
          Public() crypto.PublicKey
      }); ok {
          publicKey = key.Public()
      }
      ```
- `Verifier` is now an interface.
  - `Verify` takes `context.Context` as input since it is potentially a RPC call.
- Primitive signature service providers can have their own implementation implementing `Signer` and / or `Verifier`.
  - Remote signing a.k.a. KMS is one kind of primitive signature service providers.
- `Headers` now stores raw CBOR object to avoid re-serialization in verification.
  - The raw field enables advanced developers to marshal / unmarshal in their own way.
- `I2OSP` now returns error. `OS2IP` is added as a pair of `I2OSP`.
- `SignMessage.Verify` is kept but need to be updated as its verification policy is unclear.
- More algorithm are supported.
- `IsSign1Message` and `IsSignMessage` are removed since the motivation is unclear and cannot identify untagged messages.
- `SignMessageCBORTag` and `Sign1MessageCBORTag` are renamed to `CBORTagSignMessage` and `CBORTagSign1Message` accordingly.

### Examples

Here are the example usage after the API changes are done.

#### COSE_Sign1

Sign a message:

```go
// create message to be signed
msg := cose.NewSign1Message()
msg.Payload = []byte("hello world")
msg.Headers.Protected.SetAlgorithm(cose.AlgorithmES256)
msg.Headers.Unprotected[cose.HeaderLabelKeyID] = 1

// more efficient alternative
msg = &cose.Sign1Message{
    Headers: cose.Headers{
        Protected: map[interface{}]interface{}{
            cose.HeaderLabelAlgorithm: cose.AlgorithmES256.Value,
        },
        Unprotected: map[interface{}]interface{}{
            cose.HeaderLabelKeyID: 1,
        },
    },
    Payload: []byte("hello world"),
}

// sign message
signer, _, err := cose.NewSignerWithEphemeralKey(cose.AlgorithmES256)
check(err)
ctx := context.Background()
err = msg.Sign(ctx, nil, signer)
check(err)
sig, err := msg.MarshalCBOR()
check(err)
```

Verify a message:

```go
rawSig := getRawSignature()
key := getPublicKey()

verifier, err := cose.NewVerifier(cose.AlgorithmES256, key)
check(err)
sig, err := cose.ParseSign1Message(rawSig)
check(err)
ctx := context.Background()
err = msg.Verify(ctx, nil, verifier)
check(err)
```


#### COSE_Sign

Sign a message:

```go
// create signature holder
sig := cose.NewSignature()
sig.Headers.Protected.SetAlgorithm(cose.AlgorithmES256)
sig.Headers.Unprotected[cose.HeaderLabelKeyID] = 1

// more efficient alternative
sig = &cose.Signature{
    Headers: cose.Headers{
        Protected: map[interface{}]interface{}{
            cose.HeaderLabelAlgorithm: cose.AlgorithmES256.Value,
        },
        Unprotected: map[interface{}]interface{}{
            cose.HeaderLabelKeyID: 1,
        },
    },
}

// create message to be signed
msg := cose.NewSignMessage()
msg.Payload = []byte("hello world")
msg.Signatures = append(msg.Signatures, sig)

// more efficient alternative
msg = &cose.SignMessage{
    Payload: []byte("hello world"),
    Signatures: []*cose.Signature{
        sig,
    },
}

// sign message
signer, _, err := cose.NewSignerWithEphemeralKey(cose.AlgorithmES256)
check(err)
ctx := context.Background()
err = msg.Sign(ctx, nil, []cose.Signer{signer})
check(err)
finalSig, err := msg.MarshalCBOR()
check(err)
```

Verify a message:

```go
rawSig := getRawSignature()
key := getPublicKey()

verifier, err := cose.NewVerifier(cose.AlgorithmES256, key)
check(err)
sig, err := cose.ParseSignMessage(rawSig)
check(err)
ctx := context.Background()
err = msg.Verify(ctx, nil, []cose.Verifier{verifier})
check(err)
```
