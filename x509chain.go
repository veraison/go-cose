package cose

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
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
	// Anchors are custom trust anchors added to the verification root store.
	// When UseSystemRoots is true they are combined with the OS trust store.
	Anchors []*x509.Certificate

	// UseSystemRoots, when true, adds the OS trust store as a trust source.
	// If the OS trust store cannot be loaded, verification can still succeed
	// when Anchors alone establish a valid path.
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

// CRLPolicy controls whether missing issuer CRLs fail verification when the
// configured CRL set is non-empty. Invalid matching CRLs always fail. The zero
// value is [CRLPolicyStrict].
type CRLPolicy int

const (
	// CRLPolicyStrict requires an applicable CRL for every certificate selected
	// by RevocationMode.
	CRLPolicyStrict CRLPolicy = iota

	// CRLPolicyPermissive allows a selected certificate to have no applicable CRL
	// when the configured CRL set is non-empty. A permissive missing-CRL path
	// never overrides an explicit revocation found on another verified path.
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

// ParseX5Chain decodes and validates an x5chain header value. Header unmarshal
// leaves the raw value opaque; callers validate here (or via VerifyWithX5Chain).
// It accepts the legacy one-element array form for interoperability.
// Multi-certificate values must form a contiguous path starting at the leaf.
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

// parseX5ChainArray checks the certificate count before allocation and element
// type checks, then normalizes a CBOR-decoded array and delegates parsing.
func parseX5ChainArray(elems []interface{}) (X5Chain, error) {
	if err := validateX5ChainArrayLength(len(elems)); err != nil {
		return X5Chain{}, err
	}

	ders := make([][]byte, len(elems))
	for i, elem := range elems {
		der, ok := elem.([]byte)
		if !ok {
			return X5Chain{}, fmt.Errorf("accessing x5chain[%d]: got %T, want []byte", i, elem)
		}
		ders[i] = der
	}
	return parseX5ChainByteSlices(ders)
}

// parseX5ChainByteSlices independently checks the certificate count for direct
// [][]byte callers, then parses the leaf at index 0 and intermediates after it.
func parseX5ChainByteSlices(elems [][]byte) (X5Chain, error) {
	if err := validateX5ChainArrayLength(len(elems)); err != nil {
		return X5Chain{}, err
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

func validateX5ChainArrayLength(length int) error {
	if length == 0 {
		return errors.New("decoding x5chain: empty certificate array")
	}
	if length > MaxX5ChainCertificates {
		return fmt.Errorf("decoding x5chain: too many certificates: %d (max %d)", length, MaxX5ChainCertificates)
	}
	return nil
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

// selectVerifiedChainWithRevocation returns the preferred verified path that
// passes CRL checks. A path with complete CRL coverage is preferred and wins
// even if another verified path reports revocation. When no CRL-complete path
// exists, an explicit revocation on any verified path fails verification so a
// permissive missing-CRL path cannot bypass known revocation.
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

	var (
		softSelected  []*x509.Certificate
		revokedErr    error
		revocationErr error
	)
	for _, verifiedChain := range orderVerifiedChains(presented, verifiedChains) {
		complete, err := checkChainRevocationStatus(verifiedChain, crls, mode, policy, now)
		if err != nil {
			if errors.Is(err, ErrX5ChainRevoked) {
				if revokedErr == nil {
					revokedErr = err
				}
				continue
			}
			if revocationErr == nil {
				revocationErr = err
			}
			continue
		}
		if complete {
			return verifiedChain, nil
		}
		if softSelected == nil {
			softSelected = verifiedChain
		}
	}

	if revokedErr != nil {
		return nil, revokedErr
	}
	if revocationErr != nil {
		return nil, revocationErr
	}
	if softSelected != nil {
		return softSelected, nil
	}

	return nil, errors.New("x5chain verification failed: no selectable verified chain")
}

// VerifyWithX5Chain verifies the x5chain and signature on the Sign1Message,
// returning the selected PKIX and CRL-validated certificate path on success.
//
// Only x5chain in the effective protected header is supported. PKIX and CRL
// validation run before the COSE signature check. The caller is responsible
// for certificate identity authorization, such as Subject, SAN, or EKU policy.
// PKIX verification does not constrain EKU. The leaf must not be a CA, and a
// non-zero KeyUsage must include digitalSignature. Revocation checking
// defaults to [RevocationFullChain] with [CRLPolicyStrict]; callers must provide CRLs for
// the checked issuers, or explicitly select [RevocationDisabled].
//
// external is optional externally supplied authenticated data (AAD) included in
// the COSE Sig_structure. A nil or empty slice means no AAD. It must match the
// value used when the message was signed.
//
// anchors is required and configures trust roots and CRL data. Verification
// fails unless Anchors is non-empty and/or UseSystemRoots is true. With the
// default [RevocationFullChain] mode, CRLs must cover the checked issuers
// unless RevocationMode is [RevocationDisabled].
//
// opts is optional. A nil value supplies no additional intermediates, uses
// [CRLPolicyStrict], and verifies at time.Now.
//
// Reference: https://www.rfc-editor.org/rfc/rfc9360.html#section-2
func (m *Sign1Message) VerifyWithX5Chain(external []byte, anchors TrustAnchors, opts *X5ChainVerifyOptions) ([]*x509.Certificate, error) {
	if m == nil {
		return nil, errors.New("verifying nil Sign1Message")
	}

	// MarshalProtected applies the same RawProtected precedence as Sign1Message.Verify.
	protected, err := m.Headers.MarshalProtected()
	if err != nil {
		return nil, fmt.Errorf("x5chain: unable to encode protected header: %w", err)
	}

	// Decode that effective representation so certificate and algorithm selection
	// cannot diverge from the protected bytes covered by the COSE signature.
	var effectiveProtected ProtectedHeader
	if err := decMode.Unmarshal(protected, &effectiveProtected); err != nil {
		return nil, fmt.Errorf("x5chain: invalid protected header: %w", err)
	}

	// MarshalUnprotected applies the same RawUnprotected precedence as encoding.
	// Decode that effective representation so an x5chain present only in the
	// unprotected header is rejected even when Headers.Unprotected and
	// RawUnprotected disagree.
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

	v, protectedOK := effectiveProtected[HeaderLabelX5Chain]
	if !protectedOK {
		return nil, errors.New("x5chain: header not set")
	}

	// ParseX5Chain also validates the contiguous certificate sequence
	// presented in the header.
	chain, err := ParseX5Chain(v)
	if err != nil {
		return nil, err
	}

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

// VerifyWithX5Chain verifies the x5chain and signature on an untagged
// COSE_Sign1 message. Parameters match [Sign1Message.VerifyWithX5Chain]:
// external is optional AAD, anchors is required trust/CRL configuration, and
// opts is optional verification options.
func (m *UntaggedSign1Message) VerifyWithX5Chain(external []byte, anchors TrustAnchors, opts *X5ChainVerifyOptions) ([]*x509.Certificate, error) {
	return (*Sign1Message)(m).VerifyWithX5Chain(external, anchors, opts)
}

// LoadTrustAnchors loads PEM or DER trust-anchor and CRL files into a
// [TrustAnchors] value. Duplicate DER anchors are added once.
// RevocationMode defaults to [RevocationFullChain].
//
// readFile reads each configured path and is required unless both path slices
// are empty.
//
// trustAnchorPaths is optional. Each path contains one DER certificate or a PEM
// certificate bundle. An empty slice leaves Anchors empty and does not
// implicitly enable system roots.
//
// crlPaths is optional. Each path contains one DER CRL or a PEM CRL bundle.
// With the default [RevocationFullChain] mode, verification fails if an
// applicable CRL is unavailable.
func LoadTrustAnchors(
	readFile func(string) ([]byte, error),
	trustAnchorPaths, crlPaths []string,
) (TrustAnchors, error) {
	if readFile == nil && (len(trustAnchorPaths) != 0 || len(crlPaths) != 0) {
		return TrustAnchors{}, errors.New("loading trust anchors: nil readFile")
	}

	anchors := TrustAnchors{
		CRLs: make([]*x509.RevocationList, 0, len(crlPaths)),
	}

	if len(trustAnchorPaths) > 0 {
		addedAnchors := make(map[string]struct{})

		for _, path := range trustAnchorPaths {
			data, err := readFile(path)
			if err != nil {
				return TrustAnchors{}, fmt.Errorf("loading trust anchor from %s: %w", path, err)
			}

			if err := addTrustAnchorsFromDEROrPEM(
				addedAnchors, &anchors.Anchors, data,
			); err != nil {
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

var (
	oidExtensionReasonCode               = asn1.ObjectIdentifier{2, 5, 29, 21}
	oidExtensionIssuingDistributionPoint = asn1.ObjectIdentifier{2, 5, 29, 28}
	oidExtensionAuthorityKeyIdentifier   = asn1.ObjectIdentifier{2, 5, 29, 35}
)

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
		// When both identifiers are present, require the CRL to identify the
		// issuer key. Distinguished names alone are not sufficient when a CA
		// rotates or reuses names across different keys.
		crlAKI, err := authorityKeyIDFromCRL(crl)
		if err != nil {
			return nil, fmt.Errorf("x5chain verification failed: invalid certificate CRL authority key identifier: %w", err)
		}
		if len(crlAKI) != 0 && len(issuer.SubjectKeyId) != 0 &&
			!bytes.Equal(crlAKI, issuer.SubjectKeyId) {
			continue
		}
		if crlHasUnsupportedCriticalExtension(crl) {
			return nil, errors.New("x5chain verification failed: invalid certificate CRL: unsupported critical extension")
		}
		scope, applies, err := crlScopeForCertificate(cert, crl)
		if err != nil {
			return nil, fmt.Errorf("x5chain verification failed: invalid certificate CRL scope: %w", err)
		}
		if !applies {
			continue
		}

		if err := crl.CheckSignatureFrom(issuer); err != nil {
			return nil, fmt.Errorf("x5chain verification failed: invalid certificate CRL signature: %w", err)
		}
		matched = append(matched, scopedCRL{crl: crl, scope: scope})
	}

	return matched, nil
}

// authorityKeyIDFromCRL handles AuthorityKeyId differences across Go versions.
func authorityKeyIDFromCRL(crl *x509.RevocationList) ([]byte, error) {
	for _, ext := range crl.Extensions {
		if !ext.Id.Equal(oidExtensionAuthorityKeyIdentifier) {
			continue
		}

		var value struct {
			ID []byte `asn1:"optional,tag:0"`
		}
		rest, err := asn1.Unmarshal(ext.Value, &value)
		if err != nil || len(rest) != 0 {
			return nil, errors.New("malformed authorityKeyIdentifier extension")
		}
		return value.ID, nil
	}

	return crl.AuthorityKeyId, nil
}

// crlHasUnsupportedCriticalExtension rejects unhandled critical CRL extensions
// other than issuingDistributionPoint, which is handled below, and any
// unhandled critical CRL entry extension. crypto/x509 does not expose
// unhandled critical extensions on [x509.RevocationList].
func crlHasUnsupportedCriticalExtension(crl *x509.RevocationList) bool {
	if hasUnsupportedCriticalExtension(
		crl.Extensions, oidExtensionIssuingDistributionPoint,
	) {
		return true
	}
	for _, entry := range crl.RevokedCertificateEntries {
		if crlEntryHasUnsupportedCriticalExtension(entry) {
			return true
		}
	}
	return false
}

// crlScopeForCertificate returns the supported issuingDistributionPoint scope
// and whether it covers cert. Unsupported fields fail closed.
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
				return 0, false, errors.New("unsupported issuingDistributionPoint field")
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

// latestCurrentCRLsByScope selects the current CRL for each scope without
// allowing fallback from an expired newer CRL.
func latestCurrentCRLsByScope(crls []scopedCRL, now time.Time) ([]*x509.RevocationList, error) {
	groups := make([][]*x509.RevocationList, crlScopeCA+1)
	for _, candidate := range crls {
		groups[candidate.scope] = append(groups[candidate.scope], candidate.crl)
	}

	selected := make([]*x509.RevocationList, 0, len(groups))
	for _, group := range groups {
		if len(group) == 0 {
			continue
		}
		issued := make([]*x509.RevocationList, 0, len(group))
		for _, crl := range group {
			if !crl.ThisUpdate.After(now) {
				issued = append(issued, crl)
			}
		}
		if len(issued) == 0 {
			// Preserve a not-yet-valid error when only future CRLs match.
			return nil, checkCRLValidity(latestCRL(group), now)
		}
		crl := latestCRL(issued)
		if err := checkCRLValidity(crl, now); err != nil {
			return nil, err
		}
		selected = append(selected, crl)
	}

	return selected, nil
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
			if comparison > 0 ||
				(comparison == 0 && crl.ThisUpdate.After(latest.ThisUpdate)) {
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

// checkCRLValidity checks that a CRL is current at now. Although nextUpdate is
// optional in the X.509 ASN.1 syntax, RFC 5280 requires it in conforming CRLs.
//
// Reference: https://www.rfc-editor.org/rfc/rfc5280.html#section-5.1.2.4
// Reference: https://www.rfc-editor.org/rfc/rfc5280.html#section-5.1.2.5
func checkCRLValidity(crl *x509.RevocationList, now time.Time) error {
	issuer := crl.Issuer.String()

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

// crlEntryHasUnsupportedCriticalExtension rejects unhandled critical CRL entry
// extensions. reasonCode is allowed because crypto/x509 parses it into
// [x509.RevocationListEntry.ReasonCode].
//
// Reference: https://www.rfc-editor.org/rfc/rfc5280.html#section-5.3
func crlEntryHasUnsupportedCriticalExtension(entry x509.RevocationListEntry) bool {
	return hasUnsupportedCriticalExtension(entry.Extensions, oidExtensionReasonCode)
}

// hasUnsupportedCriticalExtension reports whether extensions contains a
// critical extension other than allowed.
func hasUnsupportedCriticalExtension(extensions []pkix.Extension, allowed asn1.ObjectIdentifier) bool {
	for _, ext := range extensions {
		if !ext.Critical {
			continue
		}
		if ext.Id.Equal(allowed) {
			continue
		}
		return true
	}
	return false
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

// checkCertificateRevocationStatus reports whether an applicable CRL was
// checked. Under [CRLPolicyPermissive], a missing CRL yields checked=false and
// a nil error.
func checkCertificateRevocationStatus(
	cert, issuer *x509.Certificate,
	crls []*x509.RevocationList,
	policy CRLPolicy,
	now time.Time,
) (checked bool, err error) {
	if err := validateCRLPolicy(policy); err != nil {
		return false, err
	}
	if issuer == nil {
		return false, errors.New("x5chain verification failed: missing issuer certificate")
	}
	if cert == nil || cert.SerialNumber == nil {
		return false, errors.New("x5chain verification failed: certificate has nil serial number")
	}

	issuerCRLs, err := filterCRLsForIssuer(cert, issuer, crls)
	if err != nil {
		return false, err
	}
	if len(issuerCRLs) == 0 {
		if policy == CRLPolicyPermissive {
			return false, nil
		}

		return false, fmt.Errorf("x5chain verification failed: %w", ErrX5ChainCRLMissing)
	}

	selectedCRLs, err := latestCurrentCRLsByScope(issuerCRLs, now)
	if err != nil {
		return false, err
	}

	for _, crl := range selectedCRLs {
		if isSerialRevoked(cert.SerialNumber, crl, now) {
			return false, fmt.Errorf("%w: certificate %q", ErrX5ChainRevoked, cert.Subject)
		}
	}

	return true, nil
}

// checkChainRevocationStatus reports whether every selected certificate had an
// applicable CRL. Permissive missing-CRL results yield complete=false.
//
// Reference: https://www.rfc-editor.org/rfc/rfc5280.html#section-6.1.1
func checkChainRevocationStatus(
	chain []*x509.Certificate,
	crls []*x509.RevocationList,
	mode RevocationMode,
	policy CRLPolicy,
	now time.Time,
) (complete bool, err error) {
	if err := validateCRLPolicy(policy); err != nil {
		return false, err
	}
	if mode == RevocationDisabled {
		return true, nil
	}

	end := len(chain) - 1 // Exclude the trust anchor.
	switch mode {
	case RevocationFullChain:
	case RevocationLeafOnly:
		if end > 1 {
			end = 1
		}
	default:
		return false, fmt.Errorf("x5chain verification failed: unknown revocation mode %d", mode)
	}
	if end == 0 {
		return true, nil
	}
	if len(crls) == 0 {
		return false, fmt.Errorf("x5chain verification failed: %w", ErrX5ChainCRLMissing)
	}

	complete = true
	for i := 0; i < end; i++ {
		checked, err := checkCertificateRevocationStatus(chain[i], chain[i+1], crls, policy, now)
		if err != nil {
			return false, err
		}
		if !checked {
			complete = false
		}
	}

	return complete, nil
}

func validateCRLPolicy(policy CRLPolicy) error {
	switch policy {
	case CRLPolicyStrict, CRLPolicyPermissive:
		return nil
	default:
		return fmt.Errorf("x5chain verification failed: unknown CRL policy %d", policy)
	}
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
	presentedDER := make(map[string]struct{}, len(presented))
	for _, cert := range presented {
		presentedDER[string(cert.Raw)] = struct{}{}
	}

	type scoredChain struct {
		chain []*x509.Certificate
		score int
	}
	ordered := make([]scoredChain, len(verifiedChains))
	for i, chain := range verifiedChains {
		ordered[i] = scoredChain{chain: chain, score: countDEROverlap(presentedDER, chain)}
	}
	// Keep the verifier's order for ties while preferring paths that contain
	// more of the certificates supplied in x5chain.
	for i := 1; i < len(ordered); i++ {
		candidate := ordered[i]
		j := i
		for j > 0 && ordered[j-1].score < candidate.score {
			ordered[j] = ordered[j-1]
			j--
		}
		ordered[j] = candidate
	}

	chains := make([][]*x509.Certificate, len(ordered))
	for i, candidate := range ordered {
		chains[i] = candidate.chain
	}
	return chains
}

// countDEROverlap counts verified certificates in the presented DER set.
func countDEROverlap(presentedDER map[string]struct{}, verified []*x509.Certificate) int {
	score := 0
	for _, cert := range verified {
		if _, ok := presentedDER[string(cert.Raw)]; ok {
			score++
		}
	}

	return score
}

// verifyPKIXChains builds paths against one combined root store containing
// system roots when enabled and explicitly configured anchors.
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
	if len(anchors.Anchors) == 0 && !anchors.UseSystemRoots {
		return nil, fmt.Errorf("x5chain verification failed: %w", ErrX5ChainNoTrust)
	}

	roots := x509.NewCertPool()
	var systemPoolErr error
	if anchors.UseSystemRoots {
		systemPool, err := loadSystemPool()
		if err != nil {
			systemPoolErr = fmt.Errorf("x5chain verification failed: loading system cert pool: %w", err)
		} else if systemPool != nil {
			roots = systemPool.Clone()
		}
	}

	for i, cert := range anchors.Anchors {
		if cert == nil {
			return nil, fmt.Errorf("x5chain verification failed: trust anchor %d is nil", i)
		}
		roots.AddCert(cert)
	}

	if systemPoolErr != nil && len(anchors.Anchors) == 0 {
		return nil, systemPoolErr
	}

	chains, err := chain[0].Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediatesFromChain(chain, opts),
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err == nil {
		return chains, nil
	}
	pkixErr := wrapPKIXVerificationError(err)
	if systemPoolErr != nil {
		return nil, errors.Join(pkixErr, systemPoolErr)
	}
	return nil, pkixErr
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
func addTrustAnchorsFromDEROrPEM(
	addedAnchors map[string]struct{},
	certificates *[]*x509.Certificate,
	data []byte,
) error {
	return parseDEROrPEM(
		data,
		"CERTIFICATE",
		"certificate",
		x509.ParseCertificate,
		func(cert *x509.Certificate) {
			addTrustAnchor(addedAnchors, certificates, cert)
		},
	)
}

// addTrustAnchor retains a certificate in Anchors unless its DER was already
// seen.
func addTrustAnchor(
	addedAnchors map[string]struct{},
	certificates *[]*x509.Certificate,
	cert *x509.Certificate,
) {
	if _, seen := addedAnchors[string(cert.Raw)]; seen {
		return
	}

	addedAnchors[string(cert.Raw)] = struct{}{}
	*certificates = append(*certificates, cert)
}

// crlsFromDEROrPEM parses one DER CRL or a strict PEM CRL bundle.
func crlsFromDEROrPEM(data []byte) ([]*x509.RevocationList, error) {
	crls := make([]*x509.RevocationList, 0, 1)
	err := parseDEROrPEM(
		data,
		"X509 CRL",
		"CRL",
		x509.ParseRevocationList,
		func(crl *x509.RevocationList) {
			crls = append(crls, crl)
		},
	)
	if err != nil {
		return nil, err
	}
	return crls, nil
}

// parseDEROrPEM parses one DER object or a strict PEM bundle of pemType.
// parse converts each DER blob; accumulate retains the parsed object.
func parseDEROrPEM[T any](
	data []byte,
	pemType string,
	kind string,
	parse func([]byte) (T, error),
	accumulate func(T),
) error {
	const pemBegin = "-----BEGIN"

	apply := func(der []byte) error {
		obj, err := parse(der)
		if err != nil {
			return fmt.Errorf("parsing %s: %w", kind, err)
		}
		accumulate(obj)
		return nil
	}

	if bytes.Index(data, []byte(pemBegin)) < 0 {
		return apply(data)
	}

	remaining := data
	for {
		pemStart := bytes.Index(remaining, []byte(pemBegin))
		if pemStart < 0 {
			if !isIgnorablePEMTrailing(remaining) {
				return fmt.Errorf("trailing data after PEM %s blocks", kind)
			}
			return nil
		}
		if !isIgnorablePEMTrailing(remaining[:pemStart]) {
			return fmt.Errorf("invalid data before PEM %s block", kind)
		}

		block, rest := pem.Decode(remaining[pemStart:])
		if block == nil {
			return fmt.Errorf("invalid PEM %s block", kind)
		}
		if block.Type != pemType {
			return fmt.Errorf("invalid PEM block type %q", block.Type)
		}
		if err := apply(block.Bytes); err != nil {
			return err
		}
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
