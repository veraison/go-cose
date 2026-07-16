package cose

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// X5Chain represents a parsed x5chain header value.
//
// Reference: https://www.rfc-editor.org/rfc/rfc9360.html#section-2
type X5Chain struct {
	Leaf          *x509.Certificate
	Intermediates []*x509.Certificate
}

// TrustAnchors configures trust and revocation data for x5chain verification.
type TrustAnchors struct {
	// Pool contains custom trust anchors. If nil, UseSystemRoots must be true.
	Pool *x509.CertPool

	// UseSystemRoots enables the OS trust store as a fallback to Pool.
	UseSystemRoots bool

	// CRLs contains revocation data. An empty slice fails when revocation checks
	// are enabled.
	CRLs []*x509.RevocationList

	// RevocationMode controls which certificates are checked against CRLs. The
	// zero value is [RevocationFullChain], which checks every non-trust-anchor
	// certificate and fails if required CRLs are missing.
	RevocationMode RevocationMode
}

// RevocationMode controls the scope of certificate revocation checking.
type RevocationMode uint8

const (
	// RevocationFullChain checks every non-trust-anchor certificate in the
	// verified chain.
	RevocationFullChain RevocationMode = iota

	// RevocationLeafOnly checks only the signing certificate.
	RevocationLeafOnly

	// RevocationDisabled skips all CRL checks. Callers must explicitly select
	// this mode when revocation checking is not required.
	RevocationDisabled
)

// CRLPolicy controls whether missing issuer CRLs fail verification. Invalid
// matching CRLs always fail. The zero value is [CRLPolicyStrict].
type CRLPolicy int

const (
	// CRLPolicyStrict requires an applicable CRL for every certificate selected
	// by RevocationMode.
	CRLPolicyStrict CRLPolicy = iota

	// CRLPolicyPermissive allows a selected certificate to have no applicable CRL.
	CRLPolicyPermissive
)

// X5ChainVerifyOptions configures path building and verification behavior.
// PKIX verification accepts any extended key usage; callers that require a
// particular EKU must enforce it on the returned verified chain.
type X5ChainVerifyOptions struct {
	// AdditionalIntermediates contains path-building candidates, not trust anchors.
	AdditionalIntermediates *x509.CertPool

	// CRLPolicy controls missing issuer CRLs. The zero value is strict.
	CRLPolicy CRLPolicy

	// CurrentTime overrides the verification time. The zero value uses time.Now.
	CurrentTime time.Time
}

const (
	// MaxX5ChainCertificates is the maximum number of certificates in x5chain.
	MaxX5ChainCertificates = 16

	// MaxX5ChainCertDERBytes is the maximum DER size of an x5chain certificate.
	MaxX5ChainCertDERBytes = 65536
)

// ParseX5Chain decodes and validates an x5chain header value. It accepts the
// legacy one-element array form for interoperability. Multi-certificate values
// must form a contiguous path starting at the leaf.
//
// Reference: https://www.rfc-editor.org/rfc/rfc9360.html#section-2
func ParseX5Chain(x5chain any) (X5Chain, error) {
	var chain X5Chain
	var err error

	switch t := x5chain.(type) {
	case []byte:
		chain, err = parseX5ChainLeafDER(t)
	case []interface{}:
		chain, err = parseX5ChainArray(t)
	case [][]byte:
		chain, err = parseX5ChainByteSlices(t)
	default:
		return X5Chain{}, fmt.Errorf("decoding x5chain: got %T, want []interface{}, [][]byte, or []byte", t)
	}
	if err != nil {
		return X5Chain{}, err
	}
	if err := validateX5ChainCertificateOrder(chain); err != nil {
		return X5Chain{}, fmt.Errorf("decoding x5chain: %w", err)
	}

	return chain, nil
}

// parseX5ChainLeafDER parses a single-certificate x5chain value.
func parseX5ChainLeafDER(leafDER []byte) (X5Chain, error) {
	if leafDER == nil {
		return X5Chain{}, fmt.Errorf("decoding x5chain: nil signing cert")
	}
	if len(leafDER) == 0 {
		return X5Chain{}, fmt.Errorf("decoding x5chain: empty signing cert")
	}
	if len(leafDER) > MaxX5ChainCertDERBytes {
		return X5Chain{}, fmt.Errorf("decoding x5chain: certificate exceeds %d bytes", MaxX5ChainCertDERBytes)
	}

	parsed, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return X5Chain{}, fmt.Errorf("decoding x5chain: invalid signing certificate: %w", err)
	}

	return X5Chain{Leaf: parsed}, nil
}

// parseX5ChainArray parses an x5chain represented as generic CBOR array values.
func parseX5ChainArray(elems []interface{}) (X5Chain, error) {
	if len(elems) == 0 {
		return X5Chain{}, fmt.Errorf("decoding x5chain: empty certificate array")
	}
	if len(elems) > MaxX5ChainCertificates {
		return X5Chain{}, fmt.Errorf("decoding x5chain: too many certificates: %d (max %d)", len(elems), MaxX5ChainCertificates)
	}

	leafDER, ok := elems[0].([]byte)
	if !ok {
		return X5Chain{}, fmt.Errorf("accessing x5chain[0]: got %T, want []byte", elems[0])
	}

	parsed, err := parseX5ChainLeafDER(leafDER)
	if err != nil {
		return X5Chain{}, err
	}

	chain := parsed
	for i := 1; i < len(elems); i++ {
		certDER, ok := elems[i].([]byte)
		if !ok {
			return X5Chain{}, fmt.Errorf("accessing x5chain[%d]: got %T, want []byte", i, elems[i])
		}

		intermediates, err := parseIntermediateDER(certDER, i)
		if err != nil {
			return X5Chain{}, err
		}

		chain.Intermediates = append(chain.Intermediates, intermediates...)
	}

	return chain, nil
}

// parseX5ChainByteSlices parses an x5chain represented as DER byte strings.
func parseX5ChainByteSlices(elems [][]byte) (X5Chain, error) {
	if len(elems) == 0 {
		return X5Chain{}, fmt.Errorf("decoding x5chain: empty certificate array")
	}
	if len(elems) > MaxX5ChainCertificates {
		return X5Chain{}, fmt.Errorf("decoding x5chain: too many certificates: %d (max %d)", len(elems), MaxX5ChainCertificates)
	}

	parsed, err := parseX5ChainLeafDER(elems[0])
	if err != nil {
		return X5Chain{}, err
	}

	chain := parsed
	for i := 1; i < len(elems); i++ {
		intermediates, err := parseIntermediateDER(elems[i], i)
		if err != nil {
			return X5Chain{}, err
		}

		chain.Intermediates = append(chain.Intermediates, intermediates...)
	}

	return chain, nil
}

// parseIntermediateDER parses one x5chain array element as exactly one certificate.
func parseIntermediateDER(der []byte, index int) ([]*x509.Certificate, error) {
	if len(der) == 0 {
		return nil, fmt.Errorf("decoding x5chain: empty intermediate cert at index %d", index)
	}
	if len(der) > MaxX5ChainCertDERBytes {
		return nil, fmt.Errorf("decoding x5chain: certificate at index %d exceeds %d bytes", index, MaxX5ChainCertDERBytes)
	}

	certs, err := x509.ParseCertificates(der)
	if err != nil {
		return nil, fmt.Errorf("decoding x5chain: invalid intermediate certificate at index %d: %w", index, err)
	}

	if len(certs) != 1 {
		return nil, fmt.Errorf("decoding x5chain: expected 1 certificate at index %d, got %d", index, len(certs))
	}

	return certs, nil
}

// SetX5Chain encodes chain into the protected header x5chain field using the
// RFC 9360 form: bstr for a leaf-only chain and an array otherwise. Certificates
// must form a contiguous path starting at the leaf; the trust anchor is optional.
//
// Reference: https://www.rfc-editor.org/rfc/rfc9360.html#section-2
func SetX5Chain(h ProtectedHeader, chain X5Chain) error {
	if h == nil {
		return errors.New("nil protected header")
	}
	if chain.Leaf == nil {
		return errors.New("nil signing cert")
	}
	if len(chain.Leaf.Raw) == 0 {
		return errors.New("x5chain: leaf certificate has empty Raw bytes")
	}
	if len(chain.Leaf.Raw) > MaxX5ChainCertDERBytes {
		return fmt.Errorf("x5chain: leaf certificate exceeds %d bytes", MaxX5ChainCertDERBytes)
	}
	if 1+len(chain.Intermediates) > MaxX5ChainCertificates {
		return fmt.Errorf(
			"x5chain: too many certificates: %d (max %d)",
			1+len(chain.Intermediates), MaxX5ChainCertificates,
		)
	}

	if len(chain.Intermediates) == 0 {
		h[HeaderLabelX5Chain] = chain.Leaf.Raw
		return nil
	}

	certChain := make([][]byte, 1, 1+len(chain.Intermediates))
	certChain[0] = chain.Leaf.Raw
	for i, cert := range chain.Intermediates {
		if cert == nil || len(cert.Raw) == 0 {
			return fmt.Errorf("x5chain: intermediate[%d] has empty Raw bytes", i)
		}
		if len(cert.Raw) > MaxX5ChainCertDERBytes {
			return fmt.Errorf("x5chain: intermediate[%d] exceeds %d bytes", i, MaxX5ChainCertDERBytes)
		}
		certChain = append(certChain, cert.Raw)
	}
	if err := validateX5ChainCertificateOrder(chain); err != nil {
		return err
	}
	h[HeaderLabelX5Chain] = certChain

	return nil
}

// validateX5ChainCertificateOrder checks that each certificate signs its
// predecessor.
func validateX5ChainCertificateOrder(chain X5Chain) error {
	if chain.Leaf == nil {
		return errors.New("x5chain: header not set")
	}

	child := chain.Leaf
	for i, issuer := range chain.Intermediates {
		if issuer == nil {
			return fmt.Errorf("x5chain: intermediate[%d] is nil", i)
		}
		if !bytes.Equal(child.RawIssuer, issuer.RawSubject) {
			return fmt.Errorf("x5chain: certificate at index %d was not issued by certificate at index %d", i, i+1)
		}
		if err := child.CheckSignatureFrom(issuer); err != nil {
			return fmt.Errorf("x5chain: certificate at index %d was not signed by certificate at index %d: %w", i, i+1, err)
		}
		child = issuer
	}

	return nil
}

// verifyParsedX5Chain verifies a parsed, ordered x5chain against configured
// trust.
func verifyParsedX5Chain(chain X5Chain, anchors TrustAnchors, opts *X5ChainVerifyOptions) ([]*x509.Certificate, error) {
	if chain.Leaf == nil {
		return nil, errors.New("x5chain: header not set")
	}

	presented := make([]*x509.Certificate, 0, 1+len(chain.Intermediates))
	presented = append(presented, chain.Leaf)
	for i, cert := range chain.Intermediates {
		if cert == nil {
			return nil, fmt.Errorf("x5chain: intermediate[%d] is nil", i)
		}
		presented = append(presented, cert)
	}

	var now time.Time
	var crlPolicy CRLPolicy
	if opts != nil {
		now = opts.CurrentTime
		crlPolicy = opts.CRLPolicy
	}
	if now.IsZero() {
		now = time.Now()
	}

	if err := validateLeafSigningCert(chain.Leaf); err != nil {
		return nil, err
	}

	verifiedChains, err := verifyPKIXChains(presented, anchors, opts, now)
	if err != nil {
		return nil, err
	}

	return selectVerifiedChainWithRevocation(
		presented, verifiedChains, anchors.CRLs, anchors.RevocationMode, crlPolicy, now,
	)
}

// selectVerifiedChainWithRevocation returns the first verified path that passes
// CRL checks.
func selectVerifiedChainWithRevocation(
	presented []*x509.Certificate,
	verifiedChains [][]*x509.Certificate,
	crls []*x509.RevocationList,
	mode RevocationMode,
	policy CRLPolicy,
	now time.Time,
) ([]*x509.Certificate, error) {
	if len(verifiedChains) == 0 {
		return nil, fmt.Errorf("x5chain verification failed: %w", ErrX5ChainNoTrust)
	}

	var revocationErr error
	for _, verifiedChain := range orderVerifiedChains(presented, verifiedChains) {
		if err := checkChainRevocation(verifiedChain, crls, mode, policy, now); err != nil {
			if revocationErr == nil {
				revocationErr = err
			}
			continue
		}

		return verifiedChain, nil
	}

	return nil, revocationErr
}

// VerifyWithX5Chain verifies the x5chain and signature on the Sign1Message,
// returning the selected PKIX and CRL-validated certificate path on success.
//
// Only x5chain in the effective protected header is supported. PKIX and CRL
// validation run before the COSE signature check. The caller is responsible
// for certificate identity authorization, such as Subject, SAN, or EKU policy.
// PKIX verification does
// not constrain EKU. The leaf must not be a CA, and a non-zero KeyUsage must
// include digitalSignature. Revocation checking defaults to
// [RevocationFullChain] with [CRLPolicyStrict]; callers must provide CRLs for
// the checked issuers, or explicitly select [RevocationDisabled]. A nil opts
// supplies no additional intermediates and uses the default verification behavior.
//
// Reference: https://www.rfc-editor.org/rfc/rfc9360.html#section-2
func (m *Sign1Message) VerifyWithX5Chain(external []byte, anchors TrustAnchors, opts *X5ChainVerifyOptions) ([]*x509.Certificate, error) {
	if m == nil {
		return nil, errors.New("verifying nil Sign1Message")
	}

	protected, err := m.Headers.MarshalProtected()
	if err != nil {
		return nil, fmt.Errorf("x5chain: unable to encode protected header: %w", err)
	}

	// MarshalProtected applies the same RawProtected precedence as Sign1Message.Verify.
	// Decode that effective representation so certificate and algorithm selection
	// cannot diverge from the protected bytes covered by the COSE signature.
	var effectiveProtected ProtectedHeader
	if err := decMode.Unmarshal(protected, &effectiveProtected); err != nil {
		return nil, fmt.Errorf("x5chain: invalid protected header: %w", err)
	}

	v, protectedOK := effectiveProtected[HeaderLabelX5Chain]
	if !protectedOK {
		unprotected, err := m.Headers.MarshalUnprotected()
		if err != nil {
			return nil, fmt.Errorf("x5chain: unable to encode unprotected header: %w", err)
		}
		var effectiveUnprotected UnprotectedHeader
		if err := decMode.Unmarshal(unprotected, &effectiveUnprotected); err != nil {
			return nil, fmt.Errorf("x5chain: invalid unprotected header: %w", err)
		}
		if _, ok := effectiveUnprotected[HeaderLabelX5Chain]; ok {
			return nil, errors.New("x5chain: unprotected header not supported")
		}
		return nil, errors.New("x5chain: header not set")
	}

	chain, err := ParseX5Chain(v)
	if err != nil {
		return nil, err
	}

	// ParseX5Chain has already validated the contiguous certificate sequence
	// presented in the header.
	verifiedChain, err := verifyParsedX5Chain(chain, anchors, opts)
	if err != nil {
		return nil, err
	}
	if len(verifiedChain) == 0 {
		return nil, errors.New("x5chain verification failed: empty verified chain")
	}

	alg, err := effectiveProtected.Algorithm()
	if err != nil {
		return nil, fmt.Errorf("unable to get verification algorithm: %w", err)
	}

	verifier, err := NewVerifier(alg, verifiedChain[0].PublicKey)
	if err != nil {
		return nil, fmt.Errorf("unable to instantiate verifier: %w", err)
	}

	// Verify also checks the protected algorithm. Use a shallow message copy so
	// that check observes the same effective header without mutating caller state.
	verifiedMessage := *m
	verifiedMessage.Headers.Protected = effectiveProtected
	verifiedMessage.Headers.RawProtected = protected
	if err := verifiedMessage.Verify(external, verifier); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrX5ChainSignature, err)
	}

	return verifiedChain, nil
}

// LoadTrustAnchors loads trust anchors and CRLs from files into a [TrustAnchors] value.
// PEM trust-anchor and CRL files may bundle multiple blocks.
// Duplicate DER anchors in trustAnchorPaths are added once.
//
// Pool is always non-nil. When trustAnchorPaths is empty, it is empty and
// verification fails closed rather than implicitly trusting the OS trust store.
// RevocationMode defaults to [RevocationFullChain].
func LoadTrustAnchors(
	readFile func(string) ([]byte, error),
	trustAnchorPaths, crlPaths []string,
) (TrustAnchors, error) {
	anchors := TrustAnchors{
		Pool: x509.NewCertPool(),
		CRLs: make([]*x509.RevocationList, 0, len(crlPaths)),
	}

	if len(trustAnchorPaths) > 0 {
		addedAnchors := make(map[string]struct{})

		for _, path := range trustAnchorPaths {
			data, err := readFile(path)
			if err != nil {
				return TrustAnchors{}, fmt.Errorf("loading trust anchor from %s: %w", path, err)
			}

			if err := addTrustAnchorsFromDEROrPEM(anchors.Pool, addedAnchors, data); err != nil {
				return TrustAnchors{}, fmt.Errorf("parsing trust anchor from %s: %w", path, err)
			}
		}
	}

	for _, path := range crlPaths {
		data, err := readFile(path)
		if err != nil {
			return TrustAnchors{}, fmt.Errorf("loading CRL from %s: %w", path, err)
		}

		crls, err := crlsFromDEROrPEM(data)
		if err != nil {
			return TrustAnchors{}, fmt.Errorf("parsing CRL from %s: %w", path, err)
		}

		anchors.CRLs = append(anchors.CRLs, crls...)
	}

	return anchors, nil
}

// newSystemCertPool loads the platform trust store.
func newSystemCertPool() (*x509.CertPool, error) {
	pool, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("loading system cert pool: %w", err)
	}
	if pool == nil {
		pool = x509.NewCertPool()
	}

	return pool, nil
}

// intermediatesFromChain combines presented and locally configured intermediates.
func intermediatesFromChain(chain []*x509.Certificate, opts *X5ChainVerifyOptions) *x509.CertPool {
	pool := x509.NewCertPool()
	if opts != nil && opts.AdditionalIntermediates != nil {
		pool = opts.AdditionalIntermediates.Clone()
	}

	for i := 1; i < len(chain); i++ {
		pool.AddCert(chain[i])
	}

	return pool
}

var oidExtensionIssuingDistributionPoint = asn1.ObjectIdentifier{2, 5, 29, 28}

// crlScope identifies the supported issuingDistributionPoint scopes.
type crlScope uint8

const (
	crlScopeAll crlScope = iota
	crlScopeUser
	crlScopeCA
)

// scopedCRL associates a CRL with its supported scope.
type scopedCRL struct {
	crl   *x509.RevocationList
	scope crlScope
}

// filterCRLsForIssuer selects applicable, validly signed CRLs for an issuer.
func filterCRLsForIssuer(cert, issuer *x509.Certificate, crls []*x509.RevocationList) ([]scopedCRL, error) {
	matched := make([]scopedCRL, 0, len(crls))

	for _, crl := range crls {
		if crl == nil {
			continue
		}

		// A valid signature proves possession of the issuer key, but not that the
		// CRL was issued under this certificate identity. This matters when the
		// same key is reused by CAs with different distinguished names.
		if !bytes.Equal(crl.RawIssuer, issuer.RawSubject) {
			continue
		}
		scope, applies, err := crlScopeForCertificate(cert, crl)
		if err != nil {
			return nil, fmt.Errorf("x5chain verification failed: invalid certificate CRL scope: %w", err)
		}
		if !applies {
			continue
		}
		if crlHasUnsupportedCriticalExtension(crl) {
			return nil, errors.New("x5chain verification failed: invalid certificate CRL: unsupported critical extension")
		}

		if err := crl.CheckSignatureFrom(issuer); err != nil {
			return nil, fmt.Errorf("x5chain verification failed: invalid certificate CRL signature: %w", err)
		}
		matched = append(matched, scopedCRL{crl: crl, scope: scope})
	}

	return matched, nil
}

// crlHasUnsupportedCriticalExtension rejects critical CRL extensions other
// than issuingDistributionPoint, which is handled below. crypto/x509 does not
// expose unhandled critical extensions on [x509.RevocationList].
func crlHasUnsupportedCriticalExtension(crl *x509.RevocationList) bool {
	for _, ext := range crl.Extensions {
		if !ext.Critical {
			continue
		}
		if ext.Id.Equal(oidExtensionIssuingDistributionPoint) {
			continue
		}
		return true
	}
	return false
}

// crlScopeForCertificate returns the supported issuingDistributionPoint scope
// and whether it covers cert. Malformed IDP values and unsupported IDP profile
// fields fail closed so revocation cannot be bypassed by an uninterpreted CRL.
// Attribute-certificate-only CRLs (onlyContainsAttributeCerts) do not apply.
//
// Reference: https://www.rfc-editor.org/rfc/rfc5280.html#section-5.2.5
func crlScopeForCertificate(cert *x509.Certificate, crl *x509.RevocationList) (crlScope, bool, error) {
	scope := crlScopeAll

	for _, ext := range crl.Extensions {
		if !ext.Id.Equal(oidExtensionIssuingDistributionPoint) {
			continue
		}

		var sequence asn1.RawValue
		rest, err := asn1.Unmarshal(ext.Value, &sequence)
		if err != nil || len(rest) != 0 || sequence.Class != asn1.ClassUniversal ||
			sequence.Tag != asn1.TagSequence || !sequence.IsCompound {
			return 0, false, errors.New("malformed issuingDistributionPoint")
		}

		var onlyUserCerts, onlyCACerts bool
		fields := sequence.Bytes
		for len(fields) > 0 {
			var field asn1.RawValue
			fields, err = asn1.Unmarshal(fields, &field)
			if err != nil || field.Class != asn1.ClassContextSpecific {
				return 0, false, errors.New("malformed issuingDistributionPoint field")
			}

			switch field.Tag {
			case 1:
				onlyUserCerts, err = parseImplicitDERBoolean(field)
			case 2:
				onlyCACerts, err = parseImplicitDERBoolean(field)
			case 5:
				// Attribute-certificate CRLs never apply to public-key certificates.
				return crlScopeAll, false, nil
			default:
				// distributionPoint, onlySomeReasons, indirectCRL, and unknown
				// fields require semantics not implemented by this verifier.
				return 0, false, fmt.Errorf("unsupported issuingDistributionPoint field [%d]", field.Tag)
			}
			if err != nil {
				return 0, false, err
			}
		}

		if onlyUserCerts && onlyCACerts {
			return 0, false, errors.New("issuingDistributionPoint cannot contain both onlyUserCerts and onlyCACerts")
		}
		if onlyUserCerts {
			scope = crlScopeUser
			if cert.IsCA {
				return scope, false, nil
			}
		}
		if onlyCACerts {
			scope = crlScopeCA
			if !cert.IsCA {
				return scope, false, nil
			}
		}
	}

	return scope, true, nil
}

// parseImplicitDERBoolean parses the DER encoding used by IDP boolean fields.
func parseImplicitDERBoolean(value asn1.RawValue) (bool, error) {
	if value.IsCompound || len(value.Bytes) != 1 {
		return false, errors.New("invalid implicit DER boolean")
	}
	switch value.Bytes[0] {
	case 0:
		return false, nil
	case 0xff:
		return true, nil
	default:
		return false, errors.New("invalid implicit DER boolean")
	}
}

// latestCRLsByScope selects the CRL that supersedes older CRLs in each scope.
//
// Reference: https://www.rfc-editor.org/rfc/rfc5280.html#section-5.2.3
func latestCRLsByScope(crls []scopedCRL) []*x509.RevocationList {
	groups := make([][]*x509.RevocationList, 3)
	for _, crl := range crls {
		groups[crl.scope] = append(groups[crl.scope], crl.crl)
	}

	latest := make([]*x509.RevocationList, 0, len(groups))
	for _, group := range groups {
		if len(group) != 0 {
			latest = append(latest, latestCRL(group))
		}
	}

	return latest
}

// latestCRL selects by CRL Number when every candidate has one, falling back
// to ThisUpdate when their numbers cannot be compared.
func latestCRL(crls []*x509.RevocationList) *x509.RevocationList {
	useNumber := true
	for _, crl := range crls {
		if crl.Number == nil {
			useNumber = false
			break
		}
	}

	latest := crls[0]
	for _, crl := range crls[1:] {
		if useNumber {
			comparison := crl.Number.Cmp(latest.Number)
			if comparison > 0 || comparison == 0 && crl.ThisUpdate.After(latest.ThisUpdate) {
				latest = crl
			}
			continue
		}

		if crl.ThisUpdate.After(latest.ThisUpdate) {
			latest = crl
		}
	}

	return latest
}

// checkCRLValidity checks that a CRL is current at now.
func checkCRLValidity(crl *x509.RevocationList, now time.Time) error {
	issuer := crl.Issuer.String()

	// RFC 5280 requires thisUpdate and permits nextUpdate to be omitted. This
	// verifier requires both so every accepted CRL has a bounded lifetime.
	// Reference: https://www.rfc-editor.org/rfc/rfc5280.html#section-5.1.2.4
	// Reference: https://www.rfc-editor.org/rfc/rfc5280.html#section-5.1.2.5
	if crl.ThisUpdate.IsZero() {
		return fmt.Errorf("x5chain: CRL from %q has no ThisUpdate", issuer)
	}

	if now.Before(crl.ThisUpdate) {
		return fmt.Errorf("x5chain: CRL from %q is not yet valid", issuer)
	}

	if crl.NextUpdate.IsZero() {
		return fmt.Errorf("x5chain: CRL from %q has no NextUpdate", issuer)
	}

	if !now.Before(crl.NextUpdate) {
		return fmt.Errorf("x5chain: CRL from %q has expired", issuer)
	}

	return nil
}

// isSerialRevoked reports whether a serial is revoked at now.
func isSerialRevoked(serial *big.Int, crl *x509.RevocationList, now time.Time) bool {
	if serial == nil {
		return false
	}

	for _, entry := range crl.RevokedCertificateEntries {
		if entry.SerialNumber == nil {
			continue
		}
		if entry.SerialNumber.Cmp(serial) == 0 && !now.Before(entry.RevocationTime) {
			return true
		}
	}

	return false
}

// checkCertificateRevocation checks one certificate against its issuer's CRLs.
func checkCertificateRevocation(
	cert, issuer *x509.Certificate,
	crls []*x509.RevocationList,
	policy CRLPolicy,
	now time.Time,
) error {
	if issuer == nil {
		return fmt.Errorf("x5chain verification failed: %w", ErrX5ChainCRLMissing)
	}
	if cert == nil || cert.SerialNumber == nil {
		return errors.New("x5chain verification failed: certificate has nil serial number")
	}

	issuerCRLs, err := filterCRLsForIssuer(cert, issuer, crls)
	if err != nil {
		return err
	}
	if len(issuerCRLs) == 0 {
		if policy == CRLPolicyPermissive {
			return nil
		}

		return fmt.Errorf("x5chain verification failed: %w", ErrX5ChainCRLMissing)
	}

	for _, crl := range latestCRLsByScope(issuerCRLs) {
		if err := checkCRLValidity(crl, now); err != nil {
			return err
		}

		if isSerialRevoked(cert.SerialNumber, crl, now) {
			return fmt.Errorf("%w: certificate %q", ErrX5ChainRevoked, cert.Subject)
		}
	}

	return nil
}

// checkChainRevocation checks the verified path, excluding its trust anchor as
// specified by RFC 5280.
//
// Reference: https://www.rfc-editor.org/rfc/rfc5280.html#section-6.1.1
func checkChainRevocation(
	chain []*x509.Certificate,
	crls []*x509.RevocationList,
	mode RevocationMode,
	policy CRLPolicy,
	now time.Time,
) error {
	if mode == RevocationDisabled {
		return nil
	}

	end := len(chain) - 1 // Exclude the trust anchor.
	switch mode {
	case RevocationFullChain:
	case RevocationLeafOnly:
		if end > 1 {
			end = 1
		}
	default:
		return fmt.Errorf("x5chain verification failed: unknown revocation mode %d", mode)
	}
	if len(crls) == 0 {
		return fmt.Errorf("x5chain verification failed: %w", ErrX5ChainCRLMissing)
	}

	for i := 0; i < end; i++ {
		if err := checkCertificateRevocation(chain[i], chain[i+1], crls, policy, now); err != nil {
			return err
		}
	}

	return nil
}

// validateLeafSigningCert validates the end-entity signing certificate.
func validateLeafSigningCert(cert *x509.Certificate) error {
	if cert.IsCA {
		return fmt.Errorf("x5chain: signing certificate must not be a CA")
	}

	if cert.KeyUsage != 0 &&
		cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return fmt.Errorf("x5chain: signing certificate lacks digitalSignature key usage")
	}

	return nil
}

// orderVerifiedChains prefers paths containing more certificates from x5chain.
func orderVerifiedChains(presented []*x509.Certificate, verifiedChains [][]*x509.Certificate) [][]*x509.Certificate {
	ordered := append([][]*x509.Certificate(nil), verifiedChains...)
	// Keep the verifier's order for ties while preferring paths that contain
	// more of the certificates supplied in x5chain.
	for i := 1; i < len(ordered); i++ {
		candidate := ordered[i]
		candidateScore := countDEROverlap(presented, candidate)
		j := i
		for j > 0 && countDEROverlap(presented, ordered[j-1]) < candidateScore {
			ordered[j] = ordered[j-1]
			j--
		}
		ordered[j] = candidate
	}

	return ordered
}

// countDEROverlap counts certificates shared by the presented and verified paths.
func countDEROverlap(presented, verified []*x509.Certificate) int {
	presentedDER := make(map[string]struct{}, len(presented))
	for _, cert := range presented {
		presentedDER[string(cert.Raw)] = struct{}{}
	}

	score := 0
	for _, cert := range verified {
		if _, ok := presentedDER[string(cert.Raw)]; ok {
			score++
		}
	}

	return score
}

// verifyPKIXChains builds paths using configured custom or system roots.
func verifyPKIXChains(
	chain []*x509.Certificate,
	anchors TrustAnchors,
	opts *X5ChainVerifyOptions,
	now time.Time,
) ([][]*x509.Certificate, error) {
	return verifyPKIXChainsWithSystemPoolLoader(chain, anchors, opts, now, newSystemCertPool)
}

// verifyPKIXChainsWithSystemPoolLoader verifies paths with an injectable system
// pool loader.
func verifyPKIXChainsWithSystemPoolLoader(
	chain []*x509.Certificate,
	anchors TrustAnchors,
	opts *X5ChainVerifyOptions,
	now time.Time,
	loadSystemPool func() (*x509.CertPool, error),
) ([][]*x509.Certificate, error) {
	if anchors.Pool == nil && !anchors.UseSystemRoots {
		return nil, fmt.Errorf("x5chain verification failed: %w", ErrX5ChainNoTrust)
	}

	verifyOptions := x509.VerifyOptions{
		Intermediates: intermediatesFromChain(chain, opts),
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	var customErr error
	if anchors.Pool != nil {
		verifyOptions.Roots = anchors.Pool
		verifiedChains, err := chain[0].Verify(verifyOptions)
		if err == nil {
			if len(verifiedChains) == 0 {
				return nil, fmt.Errorf("x5chain verification failed: %w", ErrX5ChainNoTrust)
			}
			return verifiedChains, nil
		}
		customErr = err
	}

	if !anchors.UseSystemRoots {
		if customErr != nil {
			return nil, wrapPKIXVerificationError(customErr)
		}
		return nil, fmt.Errorf("x5chain verification failed: %w", ErrX5ChainNoTrust)
	}

	systemPool, err := loadSystemPool()
	if err != nil {
		return nil, fmt.Errorf("x5chain verification failed: loading system cert pool: %w", err)
	}
	verifyOptions.Roots = systemPool
	verifiedChains, err := chain[0].Verify(verifyOptions)
	if err != nil {
		return nil, wrapPKIXVerificationError(err)
	}
	if len(verifiedChains) == 0 {
		return nil, fmt.Errorf("x5chain verification failed: %w", ErrX5ChainNoTrust)
	}

	return verifiedChains, nil
}

// wrapPKIXVerificationError preserves PKIX errors while classifying an
// unknown authority as a missing configured trust anchor.
func wrapPKIXVerificationError(err error) error {
	var unknownAuthority x509.UnknownAuthorityError
	if errors.As(err, &unknownAuthority) {
		return fmt.Errorf("x5chain verification failed: %w: %w", ErrX5ChainNoTrust, err)
	}

	return fmt.Errorf("x5chain verification failed: %w", err)
}

// addTrustAnchorsFromDEROrPEM parses and adds trust anchors from strict DER or
// PEM input.
func addTrustAnchorsFromDEROrPEM(pool *x509.CertPool, addedAnchors map[string]struct{}, data []byte) error {
	const pemBegin = "-----BEGIN"

	firstPEM := bytes.Index(data, []byte(pemBegin))
	if firstPEM < 0 {
		cert, err := x509.ParseCertificate(data)
		if err != nil {
			return fmt.Errorf("parsing certificate: %w", err)
		}
		addTrustAnchor(pool, addedAnchors, cert)
		return nil
	}

	remaining := data
	for {
		pemStart := bytes.Index(remaining, []byte(pemBegin))
		if pemStart < 0 {
			if !isIgnorablePEMTrailing(remaining) {
				return errors.New("trailing data after PEM certificate blocks")
			}
			return nil
		}
		if !isIgnorablePEMTrailing(remaining[:pemStart]) {
			return errors.New("invalid data before PEM certificate block")
		}

		block, rest := pem.Decode(remaining[pemStart:])
		if block == nil {
			return errors.New("invalid PEM certificate block")
		}
		if block.Type != "CERTIFICATE" {
			return fmt.Errorf("invalid PEM block type %q", block.Type)
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("parsing certificate: %w", err)
		}
		addTrustAnchor(pool, addedAnchors, cert)
		remaining = rest
	}
}

// addTrustAnchor adds a certificate to pool unless its DER was already seen.
func addTrustAnchor(pool *x509.CertPool, addedAnchors map[string]struct{}, cert *x509.Certificate) {
	if _, seen := addedAnchors[string(cert.Raw)]; seen {
		return
	}

	addedAnchors[string(cert.Raw)] = struct{}{}
	pool.AddCert(cert)
}

// crlsFromDEROrPEM parses one DER CRL or a strict PEM CRL bundle.
func crlsFromDEROrPEM(data []byte) ([]*x509.RevocationList, error) {
	const pemBegin = "-----BEGIN"

	if bytes.Index(data, []byte(pemBegin)) < 0 {
		crl, err := x509.ParseRevocationList(data)
		if err != nil {
			return nil, fmt.Errorf("parsing CRL: %w", err)
		}

		return []*x509.RevocationList{crl}, nil
	}

	crls := make([]*x509.RevocationList, 0, 1)
	remaining := data

	for {
		pemStart := bytes.Index(remaining, []byte(pemBegin))
		if pemStart < 0 {
			if !isIgnorablePEMTrailing(remaining) {
				return nil, errors.New("trailing data after PEM CRL blocks")
			}
			return crls, nil
		}
		if !isIgnorablePEMTrailing(remaining[:pemStart]) {
			return nil, errors.New("invalid data before PEM CRL block")
		}

		block, rest := pem.Decode(remaining[pemStart:])
		if block == nil {
			return nil, errors.New("invalid PEM CRL block")
		}
		if block.Type != "X509 CRL" {
			return nil, fmt.Errorf("invalid PEM block type %q", block.Type)
		}

		crl, err := x509.ParseRevocationList(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing CRL: %w", err)
		}

		crls = append(crls, crl)
		remaining = rest
	}
}

// isIgnorablePEMTrailing reports whether trailing bytes are only whitespace or
// PEM comment lines (# ...), which pem.Decode does not consume after the last block.
func isIgnorablePEMTrailing(data []byte) bool {
	for len(data) > 0 {
		lineEnd := bytes.IndexByte(data, '\n')
		if lineEnd < 0 {
			lineEnd = len(data)
		}
		line := bytes.TrimSpace(data[:lineEnd])
		if len(line) > 0 && line[0] != '#' {
			return false
		}
		if lineEnd >= len(data)-1 {
			break
		}
		data = data[lineEnd+1:]
	}
	return true
}

// validateX5ChainHeaderValue checks the wire shape of an x5chain header value
// and enforces [MaxX5ChainCertificates] / [MaxX5ChainCertDERBytes].
func validateX5ChainHeaderValue(value any) error {
	switch v := value.(type) {
	case []byte:
		if len(v) == 0 {
			return errors.New("require non-empty bstr")
		}
		if len(v) > MaxX5ChainCertDERBytes {
			return fmt.Errorf("certificate exceeds %d bytes", MaxX5ChainCertDERBytes)
		}
		return nil
	case []interface{}:
		if len(v) == 0 {
			return errors.New("require non-empty array")
		}
		if len(v) > MaxX5ChainCertificates {
			return fmt.Errorf("too many certificates: %d (max %d)", len(v), MaxX5ChainCertificates)
		}
		for i, elem := range v {
			if !canBstr(elem) {
				return fmt.Errorf("element %d: require bstr type", i)
			}
			der := elem.([]byte)
			if len(der) == 0 {
				return fmt.Errorf("element %d: require non-empty bstr", i)
			}
			if len(der) > MaxX5ChainCertDERBytes {
				return fmt.Errorf("element %d: certificate exceeds %d bytes", i, MaxX5ChainCertDERBytes)
			}
		}
		return nil
	case [][]byte:
		if len(v) == 0 {
			return errors.New("require non-empty array")
		}
		if len(v) > MaxX5ChainCertificates {
			return fmt.Errorf("too many certificates: %d (max %d)", len(v), MaxX5ChainCertificates)
		}
		for i, elem := range v {
			if len(elem) == 0 {
				return fmt.Errorf("element %d: require non-empty bstr", i)
			}
			if len(elem) > MaxX5ChainCertDERBytes {
				return fmt.Errorf("element %d: certificate exceeds %d bytes", i, MaxX5ChainCertDERBytes)
			}
		}
		return nil
	default:
		return fmt.Errorf("got %T, want bstr or array of bstr", value)
	}
}

// validateX5ChainHeaderEncoding rejects the legacy one-certificate array form
// when generating COSE headers. Decoding continues to accept that form for
// interoperability, while RFC 9360 requires a bare bstr for one certificate.
func validateX5ChainHeaderEncoding(headers map[any]any) error {
	for label, value := range headers {
		normalized, ok := normalizeLabel(label)
		if !ok || normalized != HeaderLabelX5Chain {
			continue
		}

		switch chain := value.(type) {
		case []interface{}:
			if len(chain) == 1 {
				return errors.New("header parameter: x5chain: single certificate must use bstr")
			}
		case [][]byte:
			if len(chain) == 1 {
				return errors.New("header parameter: x5chain: single certificate must use bstr")
			}
		}

		_, err := ParseX5Chain(value)
		if err != nil {
			return fmt.Errorf("header parameter: x5chain: %w", err)
		}
	}

	return nil
}
