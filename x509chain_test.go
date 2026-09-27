package cose

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	x509testdata "github.com/veraison/go-cose/testdata/x509"
)

// RFC 5280 §5.2.4 deltaCRLIndicator (always critical).
var oidExtensionDeltaCRLIndicator = asn1.ObjectIdentifier{2, 5, 29, 27}

// trustAnchorsWithoutRevocation returns a custom-root TrustAnchors with
// revocation checking disabled. Tests that exercise default FullChain CRL
// behavior must configure CRLs explicitly instead of using this helper.
func trustAnchorsWithoutRevocation(der []byte) (TrustAnchors, error) {
	anchor, err := x509.ParseCertificate(der)
	if err != nil {
		return TrustAnchors{}, err
	}

	return TrustAnchors{Anchors: []*x509.Certificate{anchor}, RevocationMode: RevocationDisabled}, nil
}

type testPKI struct {
	rootKey         *ecdsa.PrivateKey
	root            *x509.Certificate
	intermediateKey *ecdsa.PrivateKey
	intermediate    *x509.Certificate
	intermediateDER []byte
	leafKey         *ecdsa.PrivateKey
	leaf            *x509.Certificate
	leafDER         []byte
}

func buildTestPKI(t *testing.T) testPKI {
	t.Helper()

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	rootDER := mustCreateCA(t, rootKey, "Root CA")
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}

	intermediateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	intermediateTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Intermediate CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	intermediateDER, err := x509.CreateCertificate(
		rand.Reader, intermediateTemplate, root, &intermediateKey.PublicKey, rootKey,
	)
	if err != nil {
		t.Fatal(err)
	}

	intermediate, err := x509.ParseCertificate(intermediateDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	leafTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(3),
		Subject:               pkix.Name{CommonName: "Leaf"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	leafDER, err := x509.CreateCertificate(
		rand.Reader, leafTemplate, intermediate, &leafKey.PublicKey, intermediateKey,
	)
	if err != nil {
		t.Fatal(err)
	}

	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}

	return testPKI{
		rootKey:         rootKey,
		root:            root,
		intermediateKey: intermediateKey,
		intermediate:    intermediate,
		intermediateDER: intermediateDER,
		leafKey:         leafKey,
		leaf:            leaf,
		leafDER:         leafDER,
	}
}

func makeValidCRL(t *testing.T, issuer *x509.Certificate, issuerKey *ecdsa.PrivateKey) *x509.RevocationList {
	t.Helper()

	crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now().Add(-time.Minute),
		NextUpdate: time.Now().Add(time.Hour),
	}, issuer, issuerKey)
	if err != nil {
		t.Fatal(err)
	}

	crl, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		t.Fatal(err)
	}

	return crl
}

func makeValidChainCRLs(t *testing.T, pki *testPKI) []*x509.RevocationList {
	t.Helper()

	return []*x509.RevocationList{
		makeValidCRL(t, pki.intermediate, pki.intermediateKey),
		makeValidCRL(t, pki.root, pki.rootKey),
	}
}

func checkCertificateRevocation(
	cert, issuer *x509.Certificate,
	crls []*x509.RevocationList,
	policy CRLPolicy,
	now time.Time,
) error {
	_, err := checkCertificateRevocationStatus(cert, issuer, crls, policy, now)
	return err
}

func checkChainRevocation(
	chain []*x509.Certificate,
	crls []*x509.RevocationList,
	mode RevocationMode,
	policy CRLPolicy,
	now time.Time,
) error {
	_, err := checkChainRevocationStatus(chain, crls, mode, policy, now)
	return err
}

func mustCreateCA(t *testing.T, key *ecdsa.PrivateKey, commonName string) []byte {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	return der
}

func certChainBytes() []byte {
	return append(append([]byte{}, x509testdata.IntermediateCA...), x509testdata.RootCA...)
}

func parseEndEntityKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()

	block, _ := pem.Decode(x509testdata.EndEntityKey)
	if block == nil {
		t.Fatal("failed to decode end entity key PEM")
	}

	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	return key
}

func signSign1WithX5Chain(t *testing.T, leafDER, intermediates []byte, key *ecdsa.PrivateKey) *Sign1Message {
	t.Helper()

	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}

	chain := X5Chain{Leaf: leaf}
	if len(intermediates) > 0 {
		certs, err := x509.ParseCertificates(intermediates)
		if err != nil {
			t.Fatal(err)
		}
		chain.Intermediates = certs
	}

	msg := NewSign1Message()
	msg.Payload = []byte("test payload")
	msg.Headers.Protected.SetAlgorithm(AlgorithmES256)
	if err := SetX5Chain(msg.Headers.Protected, chain); err != nil {
		t.Fatal(err)
	}

	signer, err := NewSigner(AlgorithmES256, key)
	if err != nil {
		t.Fatal(err)
	}

	if err := msg.Sign(rand.Reader, []byte{}, signer); err != nil {
		t.Fatal(err)
	}

	return msg
}

func TestParseX5Chain_rejectsMultiCertInSingleSlot(t *testing.T) {
	concat := append(append([]byte(nil), x509testdata.IntermediateCA...), x509testdata.RootCA...)
	_, err := ParseX5Chain([]interface{}{x509testdata.EndEntityDer, concat})
	if err == nil || !strings.Contains(err.Error(), "expected 1 certificate at index 1") {
		t.Fatalf("got err %v", err)
	}

	_, err = ParseX5Chain([][]byte{x509testdata.EndEntityDer, concat})
	if err == nil || !strings.Contains(err.Error(), "expected 1 certificate at index 1") {
		t.Fatalf("got err %v", err)
	}
}

func TestParseX5Chain_arrayFormsSuccessParity(t *testing.T) {
	elems := [][]byte{x509testdata.EndEntityDer, x509testdata.IntermediateCA, x509testdata.RootCA}
	asInterface := make([]interface{}, len(elems))
	for i, der := range elems {
		asInterface[i] = der
	}

	fromInterfaces, err := ParseX5Chain(asInterface)
	if err != nil {
		t.Fatalf("ParseX5Chain([]interface{}) error = %v", err)
	}
	fromByteSlices, err := ParseX5Chain(elems)
	if err != nil {
		t.Fatalf("ParseX5Chain([][]byte) error = %v", err)
	}

	if !bytes.Equal(fromInterfaces.Leaf.Raw, fromByteSlices.Leaf.Raw) {
		t.Fatal("array forms produced different leaf certificates")
	}
	if len(fromInterfaces.Intermediates) != len(fromByteSlices.Intermediates) {
		t.Fatalf("array forms produced %d and %d intermediates", len(fromInterfaces.Intermediates), len(fromByteSlices.Intermediates))
	}
	for i := range fromInterfaces.Intermediates {
		if !bytes.Equal(fromInterfaces.Intermediates[i].Raw, fromByteSlices.Intermediates[i].Raw) {
			t.Fatalf("array forms produced different intermediate at index %d", i)
		}
	}
}

func TestParseX5Chain_rejectsTooManyBeforeElementTypes(t *testing.T) {
	tooMany := make([]interface{}, MaxX5ChainCertificates+1)
	_, err := ParseX5Chain(tooMany)
	if err == nil || !strings.Contains(err.Error(), "too many certificates") {
		t.Fatalf("certificate count must be checked before element types: got err %v", err)
	}
}

func TestVerifyParsedX5Chain_completesPartialChainWithAdditionalIntermediates(t *testing.T) {
	pki := buildTestPKI(t)

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootDER := mustCreateCA(t, rootKey, "Ultimate Root CA")
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}

	i2Template := &x509.Certificate{
		SerialNumber:          big.NewInt(4),
		Subject:               pki.root.Subject,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	i2DER, err := x509.CreateCertificate(
		rand.Reader, i2Template, root, &pki.rootKey.PublicKey, rootKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	i2, err := x509.ParseCertificate(i2DER)
	if err != nil {
		t.Fatal(err)
	}

	anchors := TrustAnchors{Anchors: []*x509.Certificate{root}, RevocationMode: RevocationDisabled}

	tests := []struct {
		name       string
		presented  X5Chain
		additional []*x509.Certificate
	}{
		{
			name:       "leaf and I1 presented; I2 available locally",
			presented:  X5Chain{Leaf: pki.leaf, Intermediates: []*x509.Certificate{pki.intermediate}},
			additional: []*x509.Certificate{i2},
		},
		{
			name:       "leaf presented; I1 and I2 available locally",
			presented:  X5Chain{Leaf: pki.leaf},
			additional: []*x509.Certificate{pki.intermediate, i2},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			additionalPool := x509.NewCertPool()
			for _, cert := range test.additional {
				additionalPool.AddCert(cert)
			}
			opts := &X5ChainVerifyOptions{
				AdditionalIntermediates: additionalPool,
			}

			verified, err := verifyParsedX5Chain(test.presented, anchors, opts)
			if err != nil {
				t.Fatal(err)
			}
			if len(verified) != 4 {
				t.Fatalf("verified chain length = %d, want 4", len(verified))
			}
			if !bytes.Equal(verified[1].Raw, pki.intermediate.Raw) || !bytes.Equal(verified[2].Raw, i2.Raw) {
				t.Fatal("verified chain did not use the locally available intermediates")
			}
		})
	}
}

func TestVerifyParsedX5Chain_additionalIntermediateIsNotTrustAnchor(t *testing.T) {
	leaf, err := x509.ParseCertificate(x509testdata.EndEntityDer)
	if err != nil {
		t.Fatal(err)
	}
	intermediate, err := x509.ParseCertificate(x509testdata.IntermediateCA)
	if err != nil {
		t.Fatal(err)
	}

	additional := x509.NewCertPool()
	additional.AddCert(intermediate)
	_, err = verifyParsedX5Chain(
		X5Chain{Leaf: leaf},
		TrustAnchors{},
		&X5ChainVerifyOptions{AdditionalIntermediates: additional},
	)
	if err == nil {
		t.Fatal("verification succeeded without a trust anchor")
	}
	if !errors.Is(err, ErrX5ChainNoTrust) {
		t.Fatalf("expected ErrX5ChainNoTrust, got %v", err)
	}
}

func TestValidateX5ChainLeafSigningCert_zeroKeyUsagePasses(t *testing.T) {
	cert := &x509.Certificate{IsCA: false}

	if err := validateLeafSigningCert(cert); err != nil {
		t.Fatal(err)
	}
}

func TestCheckChainRevocation_latestExpiredCRLFails(t *testing.T) {
	pki := buildTestPKI(t)

	validCRLDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now().Add(-time.Minute),
		NextUpdate: time.Now().Add(time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{
			{
				SerialNumber:   pki.leaf.SerialNumber,
				RevocationTime: time.Now().Add(-time.Minute),
			},
		},
	}, pki.intermediate, pki.intermediateKey)
	if err != nil {
		t.Fatal(err)
	}

	expiredCRLDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(2),
		ThisUpdate: time.Now().Add(-2 * time.Hour),
		NextUpdate: time.Now().Add(-time.Hour),
	}, pki.intermediate, pki.intermediateKey)
	if err != nil {
		t.Fatal(err)
	}

	validCRL, err := x509.ParseRevocationList(validCRLDER)
	if err != nil {
		t.Fatal(err)
	}

	expiredCRL, err := x509.ParseRevocationList(expiredCRLDER)
	if err != nil {
		t.Fatal(err)
	}

	chain := []*x509.Certificate{pki.leaf, pki.intermediate, pki.root}
	crls := makeValidChainCRLs(t, &pki)
	crls[0] = validCRL
	crls = append(crls, expiredCRL)

	err = checkChainRevocation(chain, crls, RevocationFullChain, CRLPolicyStrict, time.Now())
	if err == nil || !strings.Contains(err.Error(), "has expired") {
		t.Fatalf("got err %v", err)
	}
}

func TestCheckCertificateRevocation_usesLatestCRLNumber(t *testing.T) {
	pki := buildTestPKI(t)
	now := time.Now()

	oldDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: now.Add(-2 * time.Minute),
		NextUpdate: now.Add(time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{{
			SerialNumber:   pki.leaf.SerialNumber,
			RevocationTime: now.Add(-time.Minute),
			ReasonCode:     6, // certificateHold
		}},
	}, pki.intermediate, pki.intermediateKey)
	if err != nil {
		t.Fatal(err)
	}
	latestDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(2),
		ThisUpdate: now.Add(-time.Minute),
		NextUpdate: now.Add(time.Hour),
	}, pki.intermediate, pki.intermediateKey)
	if err != nil {
		t.Fatal(err)
	}

	oldCRL, err := x509.ParseRevocationList(oldDER)
	if err != nil {
		t.Fatal(err)
	}
	latestCRL, err := x509.ParseRevocationList(latestDER)
	if err != nil {
		t.Fatal(err)
	}

	if err := checkCertificateRevocation(
		pki.leaf, pki.intermediate, []*x509.RevocationList{oldCRL, latestCRL},
		CRLPolicyStrict, now,
	); err != nil {
		t.Fatalf("latest CRL removed the certificate from hold: %v", err)
	}
}

func TestLatestCRL_prefersNumber(t *testing.T) {
	newerTime := &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: time.Unix(2, 0)}
	newerNumber := &x509.RevocationList{Number: big.NewInt(2), ThisUpdate: time.Unix(1, 0)}

	if got := latestCRL([]*x509.RevocationList{newerTime, newerNumber}); got != newerNumber {
		t.Fatal("latestCRL did not prefer the greater CRL Number")
	}
}

func TestLatestCRL_fallsBackToThisUpdateWhenNumberMissing(t *testing.T) {
	older := &x509.RevocationList{Number: big.NewInt(2), ThisUpdate: time.Unix(1, 0)}
	newer := &x509.RevocationList{ThisUpdate: time.Unix(2, 0)}

	if got := latestCRL([]*x509.RevocationList{older, newer}); got != newer {
		t.Fatal("latestCRL did not fall back to the latest ThisUpdate")
	}
}

func TestLatestCRL_usesThisUpdateToBreakNumberTie(t *testing.T) {
	older := &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: time.Unix(1, 0)}
	newer := &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: time.Unix(2, 0)}

	if got := latestCRL([]*x509.RevocationList{older, newer}); got != newer {
		t.Fatal("latestCRL did not use ThisUpdate to break a CRL Number tie")
	}
}

func TestLatestCurrentCRLsByScope_ignoresCRLIssuedAfterVerificationTime(t *testing.T) {
	now := time.Unix(1000, 0)
	current := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: now.Add(-time.Hour),
		NextUpdate: now.Add(time.Hour),
	}
	future := &x509.RevocationList{
		Number:     big.NewInt(2),
		ThisUpdate: now.Add(time.Hour),
		NextUpdate: now.Add(2 * time.Hour),
	}

	selected, err := latestCurrentCRLsByScope([]scopedCRL{
		{crl: current, scope: crlScopeAll},
		{crl: future, scope: crlScopeAll},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(selected) != 1 || selected[0] != current {
		t.Fatal("future CRL superseded the CRL current at the verification time")
	}
}

func TestLatestCurrentCRLsByScope_doesNotRollBackExpiredNewerCRL(t *testing.T) {
	now := time.Unix(1000, 0)
	old := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: now.Add(-2 * time.Hour),
		NextUpdate: now.Add(time.Hour),
	}
	newerExpired := &x509.RevocationList{
		Number:     big.NewInt(2),
		ThisUpdate: now.Add(-time.Hour),
		NextUpdate: now,
	}

	_, err := latestCurrentCRLsByScope([]scopedCRL{
		{crl: old, scope: crlScopeAll},
		{crl: newerExpired, scope: crlScopeAll},
	}, now)
	if err == nil || !strings.Contains(err.Error(), "has expired") {
		t.Fatalf("got err %v", err)
	}
}

func TestCheckCertificateRevocation_differentScopesDoNotSupersede(t *testing.T) {
	pki := buildTestPKI(t)
	now := time.Now()

	allCertificatesDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: now.Add(-2 * time.Minute),
		NextUpdate: now.Add(time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{{
			SerialNumber:   pki.leaf.SerialNumber,
			RevocationTime: now.Add(-time.Minute),
		}},
	}, pki.intermediate, pki.intermediateKey)
	if err != nil {
		t.Fatal(err)
	}
	userCertificatesDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(2),
		ThisUpdate: now.Add(-time.Minute),
		NextUpdate: now.Add(time.Hour),
		ExtraExtensions: []pkix.Extension{{
			Id:       oidExtensionIssuingDistributionPoint,
			Critical: true,
			Value:    []byte{0x30, 0x03, 0x81, 0x01, 0xff},
		}},
	}, pki.intermediate, pki.intermediateKey)
	if err != nil {
		t.Fatal(err)
	}

	allCertificatesCRL, err := x509.ParseRevocationList(allCertificatesDER)
	if err != nil {
		t.Fatal(err)
	}
	userCertificatesCRL, err := x509.ParseRevocationList(userCertificatesDER)
	if err != nil {
		t.Fatal(err)
	}

	err = checkCertificateRevocation(
		pki.leaf, pki.intermediate,
		[]*x509.RevocationList{allCertificatesCRL, userCertificatesCRL},
		CRLPolicyStrict, now,
	)
	if !errors.Is(err, ErrX5ChainRevoked) {
		t.Fatalf("CRLs with different scopes must not supersede each other: %v", err)
	}
}

func TestCheckCertificateRevocation_rejectsUnsupportedExtensionOutsideScope(t *testing.T) {
	pki := buildTestPKI(t)
	now := time.Now()

	caOnlyDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: now.Add(-time.Minute),
		NextUpdate: now.Add(time.Hour),
		ExtraExtensions: []pkix.Extension{
			{
				Id:       oidExtensionIssuingDistributionPoint,
				Critical: true,
				Value:    []byte{0x30, 0x03, 0x82, 0x01, 0xff},
			},
			{
				Id:       oidExtensionDeltaCRLIndicator,
				Critical: true,
				Value:    []byte{0x02, 0x01, 0x01},
			},
		},
	}, pki.intermediate, pki.intermediateKey)
	if err != nil {
		t.Fatal(err)
	}
	caOnlyCRL, err := x509.ParseRevocationList(caOnlyDER)
	if err != nil {
		t.Fatal(err)
	}

	err = checkCertificateRevocation(
		pki.leaf, pki.intermediate,
		[]*x509.RevocationList{caOnlyCRL, makeValidCRL(t, pki.intermediate, pki.intermediateKey)},
		CRLPolicyStrict, now,
	)
	if err == nil || !strings.Contains(err.Error(), "unsupported critical extension") {
		t.Fatalf("out-of-scope CRL with unsupported critical extension must be rejected: %v", err)
	}
}

func TestCheckChainRevocation_revokedIntermediate(t *testing.T) {
	pki := buildTestPKI(t)

	rootCRLDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now().Add(-time.Minute),
		NextUpdate: time.Now().Add(time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{
			{
				SerialNumber:   pki.intermediate.SerialNumber,
				RevocationTime: time.Now().Add(-time.Minute),
			},
		},
	}, pki.root, pki.rootKey)
	if err != nil {
		t.Fatal(err)
	}
	rootCRL, err := x509.ParseRevocationList(rootCRLDER)
	if err != nil {
		t.Fatal(err)
	}

	chain := []*x509.Certificate{pki.leaf, pki.intermediate, pki.root}
	crls := []*x509.RevocationList{
		makeValidCRL(t, pki.intermediate, pki.intermediateKey),
		rootCRL,
	}

	err = checkChainRevocation(chain, crls, RevocationFullChain, CRLPolicyStrict, time.Now())
	if !errors.Is(err, ErrX5ChainRevoked) {
		t.Fatalf("got err %v", err)
	}

	if err := checkChainRevocation(chain, crls, RevocationLeafOnly, CRLPolicyStrict, time.Now()); err != nil {
		t.Fatalf("leaf-only revocation checking must not check an intermediate: %v", err)
	}
}

func TestCheckChainRevocation_missingApplicableCRL(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	chainCA, err := x509.ParseCertificate(mustCreateCA(t, caKey, "Chain CA"))
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	leafDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Test Leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}, chainCA, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}

	unrelatedKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	unrelatedCA, err := x509.ParseCertificate(mustCreateCA(t, unrelatedKey, "Unrelated CA"))
	if err != nil {
		t.Fatal(err)
	}
	unrelatedCRL := makeValidCRL(t, unrelatedCA, unrelatedKey)

	chain := []*x509.Certificate{leaf, chainCA}
	crls := []*x509.RevocationList{unrelatedCRL}

	for _, tt := range []struct {
		name string
		run  func(t *testing.T)
	}{
		{
			name: "strict checkChainRevocation",
			run: func(t *testing.T) {
				err := checkChainRevocation(chain, crls, RevocationFullChain, CRLPolicyStrict, time.Now())
				if !errors.Is(err, ErrX5ChainCRLMissing) {
					t.Fatalf("got err %v", err)
				}
			},
		},
		{
			name: "zero value CRLPolicy is strict",
			run: func(t *testing.T) {
				err := checkChainRevocation(chain, crls, RevocationFullChain, 0, time.Now())
				if !errors.Is(err, ErrX5ChainCRLMissing) {
					t.Fatalf("got err %v", err)
				}
			},
		},
		{
			name: "zero value options via verifyParsedX5Chain",
			run: func(t *testing.T) {
				_, err := verifyParsedX5Chain(X5Chain{Leaf: leaf}, TrustAnchors{
					Anchors: []*x509.Certificate{chainCA},
					CRLs:    crls,
				}, nil)
				if !errors.Is(err, ErrX5ChainCRLMissing) {
					t.Fatalf("got err %v", err)
				}
			},
		},
		{
			name: "permissive allows missing issuer CRL",
			run: func(t *testing.T) {
				_, err := verifyParsedX5Chain(
					X5Chain{Leaf: leaf},
					TrustAnchors{Anchors: []*x509.Certificate{chainCA}, CRLs: crls},
					&X5ChainVerifyOptions{CRLPolicy: CRLPolicyPermissive},
				)
				if err != nil {
					t.Fatalf("permissive CRLPolicy should allow a missing issuer CRL: %v", err)
				}
			},
		},
	} {
		t.Run(tt.name, tt.run)
	}
}

func TestCheckChainRevocation_rejectsUnknownCRLPolicy(t *testing.T) {
	pki := buildTestPKI(t)
	chain := []*x509.Certificate{pki.leaf, pki.intermediate, pki.root}
	unknown := CRLPolicy(99)

	tests := []struct {
		name string
		crls []*x509.RevocationList
		mode RevocationMode
	}{
		{name: "without CRLs", mode: RevocationFullChain},
		{name: "with CRLs", crls: makeValidChainCRLs(t, &pki), mode: RevocationFullChain},
		{name: "revocation disabled", mode: RevocationDisabled},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkChainRevocation(
				chain, tt.crls, tt.mode, unknown, time.Now(),
			)
			if err == nil || !strings.Contains(err.Error(), "unknown CRL policy 99") {
				t.Fatalf("got err %v", err)
			}
		})
	}
}

func TestCheckChainRevocation_rejectsCRLFromDifferentIssuerUsingSameKey(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	chainCA, err := x509.ParseCertificate(mustCreateCA(t, caKey, "Chain CA"))
	if err != nil {
		t.Fatal(err)
	}
	unrelatedCA, err := x509.ParseCertificate(mustCreateCA(t, caKey, "Unrelated CA"))
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Test Leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}, chainCA, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}

	// This CRL's signature verifies with chainCA because both CA certificates
	// use caKey, but its issuer name identifies unrelatedCA.
	unrelatedCRL := makeValidCRL(t, unrelatedCA, caKey)
	if err := unrelatedCRL.CheckSignatureFrom(chainCA); err != nil {
		t.Fatalf("test setup: shared-key signature should verify: %v", err)
	}

	err = checkChainRevocation(
		[]*x509.Certificate{leaf, chainCA},
		[]*x509.RevocationList{unrelatedCRL},
		RevocationFullChain,
		CRLPolicyStrict,
		time.Now(),
	)
	if !errors.Is(err, ErrX5ChainCRLMissing) {
		t.Fatalf("got err %v", err)
	}
}

func TestFilterCRLsForIssuer_handlesLegacyAuthorityKeyIDRepresentation(t *testing.T) {
	pki := buildTestPKI(t)
	crl := makeValidCRL(t, pki.intermediate, pki.intermediateKey)
	for _, ext := range crl.Extensions {
		if ext.Id.Equal(oidExtensionAuthorityKeyIdentifier) {
			crl.AuthorityKeyId = ext.Value
			break
		}
	}

	matched, err := filterCRLsForIssuer(
		pki.leaf, pki.intermediate, []*x509.RevocationList{crl},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(matched) != 1 {
		t.Fatalf("got %d matching CRLs, want 1", len(matched))
	}
}

func TestAuthorityKeyIDFromCRL_acceptsOptionalIssuerAndSerial(t *testing.T) {
	extensionValue, err := asn1.Marshal(struct {
		ID     []byte `asn1:"optional,tag:0"`
		Issuer asn1.RawValue
		Serial asn1.RawValue
	}{
		ID:     []byte{1, 2, 3},
		Issuer: asn1.RawValue{FullBytes: []byte{0xa1, 0x04, 0xa4, 0x02, 0x30, 0x00}},
		Serial: asn1.RawValue{FullBytes: []byte{0x82, 0x01, 0x01}},
	})
	if err != nil {
		t.Fatal(err)
	}

	got, err := authorityKeyIDFromCRL(&x509.RevocationList{
		Extensions: []pkix.Extension{{
			Id:    oidExtensionAuthorityKeyIdentifier,
			Value: extensionValue,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte{1, 2, 3}) {
		t.Fatalf("got key identifier %x", got)
	}
}

func TestFilterCRLsForIssuer_rejectsMalformedAuthorityKeyID(t *testing.T) {
	pki := buildTestPKI(t)
	crl := makeValidCRL(t, pki.intermediate, pki.intermediateKey)
	for i := range crl.Extensions {
		if crl.Extensions[i].Id.Equal(oidExtensionAuthorityKeyIdentifier) {
			crl.Extensions[i].Value = []byte{0x30, 0x01, 0xff}
			break
		}
	}

	_, err := filterCRLsForIssuer(
		pki.leaf, pki.intermediate, []*x509.RevocationList{crl},
	)
	if err == nil || !strings.Contains(err.Error(), "authority key identifier") {
		t.Fatalf("got err %v", err)
	}
}

func TestCheckCertificateRevocation_rejectsCRLForDifferentCertificateScope(t *testing.T) {
	pki := buildTestPKI(t)

	crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now().Add(-time.Minute),
		NextUpdate: time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{{
			Id:       oidExtensionIssuingDistributionPoint,
			Critical: true,
			// issuingDistributionPoint with onlyContainsCACerts = TRUE.
			Value: []byte{0x30, 0x03, 0x82, 0x01, 0xff},
		}},
	}, pki.intermediate, pki.intermediateKey)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		t.Fatal(err)
	}

	err = checkCertificateRevocation(
		pki.leaf, pki.intermediate, []*x509.RevocationList{crl},
		CRLPolicyStrict, time.Now(),
	)
	if !errors.Is(err, ErrX5ChainCRLMissing) {
		t.Fatalf("got err %v", err)
	}
}

func TestCheckCertificateRevocation_rejectsUnsupportedCriticalExtensionWhenScopeDoesNotApply(t *testing.T) {
	pki := buildTestPKI(t)
	crl := makeCRLWithExtensions(t, pki.intermediate, pki.intermediateKey, []pkix.Extension{
		{
			Id:       oidExtensionIssuingDistributionPoint,
			Critical: true,
			// onlyContainsCACerts = TRUE — does not apply to the leaf.
			Value: []byte{0x30, 0x03, 0x82, 0x01, 0xff},
		},
		{
			Id:       oidExtensionDeltaCRLIndicator,
			Critical: true,
			Value:    []byte{0x02, 0x01, 0x01},
		},
	})

	err := checkCertificateRevocation(
		pki.leaf, pki.intermediate, []*x509.RevocationList{crl},
		CRLPolicyPermissive, time.Now(),
	)
	if err == nil || !strings.Contains(err.Error(), "unsupported critical extension") {
		t.Fatalf("got err %v", err)
	}
}

func TestCheckCertificateRevocation_rejectsNilIssuerWithoutCRLMissing(t *testing.T) {
	pki := buildTestPKI(t)

	err := checkCertificateRevocation(
		pki.leaf, nil, []*x509.RevocationList{makeValidCRL(t, pki.intermediate, pki.intermediateKey)},
		CRLPolicyStrict, time.Now(),
	)
	if err == nil {
		t.Fatal("expected missing issuer error")
	}
	if errors.Is(err, ErrX5ChainCRLMissing) {
		t.Fatalf("nil issuer must not be reported as missing CRL: %v", err)
	}
	if !strings.Contains(err.Error(), "missing issuer certificate") {
		t.Fatalf("got err %v", err)
	}
}

func TestCheckCertificateRevocation_rejectsUnsupportedIDPProfile(t *testing.T) {
	pki := buildTestPKI(t)
	now := time.Now()

	// issuingDistributionPoint with distributionPoint [0] — unsupported profile.
	unsupportedIDPCRL := makeCRLWithExtensions(t, pki.intermediate, pki.intermediateKey, []pkix.Extension{{
		Id:       oidExtensionIssuingDistributionPoint,
		Critical: true,
		Value:    []byte{0x30, 0x02, 0x80, 0x00},
	}})
	validCRL := makeValidCRL(t, pki.intermediate, pki.intermediateKey)

	err := checkCertificateRevocation(
		pki.leaf, pki.intermediate, []*x509.RevocationList{unsupportedIDPCRL},
		CRLPolicyStrict, now,
	)
	if err == nil || !strings.Contains(err.Error(), "unsupported issuingDistributionPoint field") {
		t.Fatalf("got err %v", err)
	}

	err = checkCertificateRevocation(
		pki.leaf, pki.intermediate,
		[]*x509.RevocationList{unsupportedIDPCRL, validCRL},
		CRLPolicyStrict, now,
	)
	if err == nil || !strings.Contains(err.Error(), "unsupported issuingDistributionPoint field") {
		t.Fatalf("got err %v", err)
	}

	err = checkCertificateRevocation(
		pki.leaf, pki.intermediate, []*x509.RevocationList{unsupportedIDPCRL},
		CRLPolicyPermissive, now,
	)
	if err == nil || !strings.Contains(err.Error(), "unsupported issuingDistributionPoint field") {
		t.Fatalf("got err %v", err)
	}
}

func TestCheckCertificateRevocation_permissiveFailsWhenOnlyExpiredMatchingCRL(t *testing.T) {
	pki := buildTestPKI(t)

	expiredCRLDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now().Add(-2 * time.Hour),
		NextUpdate: time.Now().Add(-time.Hour),
	}, pki.intermediate, pki.intermediateKey)
	if err != nil {
		t.Fatal(err)
	}
	expiredCRL, err := x509.ParseRevocationList(expiredCRLDER)
	if err != nil {
		t.Fatal(err)
	}

	err = checkCertificateRevocation(
		pki.leaf, pki.intermediate, []*x509.RevocationList{expiredCRL},
		CRLPolicyPermissive, time.Now(),
	)
	if err == nil || !strings.Contains(err.Error(), "has expired") {
		t.Fatalf("got err %v", err)
	}
}

func TestCheckChainRevocation_excludesTrustAnchor(t *testing.T) {
	pki := buildTestPKI(t)
	chain := []*x509.Certificate{pki.leaf, pki.intermediate, pki.root}
	// CRLs cover every non-anchor certificate. No parent-of-root CRL is supplied;
	// success shows the trust anchor itself is not revocation-checked.
	crls := makeValidChainCRLs(t, &pki)
	if err := checkChainRevocation(chain, crls, RevocationFullChain, CRLPolicyStrict, time.Now()); err != nil {
		t.Fatalf("full-chain revocation must not require a CRL for the trust anchor: %v", err)
	}

	// leaf issued directly by root: only the leaf needs a CRL.
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(9),
		Subject:      pkix.Name{CommonName: "Direct Leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}, pki.root, &leafKey.PublicKey, pki.rootKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	short := []*x509.Certificate{leaf, pki.root}
	if err := checkChainRevocation(
		short,
		[]*x509.RevocationList{makeValidCRL(t, pki.root, pki.rootKey)},
		RevocationFullChain,
		CRLPolicyStrict,
		time.Now(),
	); err != nil {
		t.Fatalf("two-certificate path must check only the leaf: %v", err)
	}
}

func TestVerifyParsedX5Chain_directTrustAnchorRequiresNoCRL(t *testing.T) {
	pki := buildTestPKI(t)

	verified, err := verifyParsedX5Chain(
		X5Chain{Leaf: pki.leaf},
		TrustAnchors{Anchors: []*x509.Certificate{pki.leaf}},
		nil,
	)
	if err != nil {
		t.Fatalf("directly trusted signing certificate must not require a CRL: %v", err)
	}
	if len(verified) != 1 || !bytes.Equal(verified[0].Raw, pki.leaf.Raw) {
		t.Fatalf("unexpected verified chain: %#v", verified)
	}
}

func TestVerifyParsedX5Chain_revocationMode(t *testing.T) {
	pki := buildTestPKI(t)

	revokingCRLDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now().Add(-time.Minute),
		NextUpdate: time.Now().Add(time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{
			{
				SerialNumber:   pki.leaf.SerialNumber,
				RevocationTime: time.Now().Add(-time.Minute),
			},
		},
	}, pki.intermediate, pki.intermediateKey)
	if err != nil {
		t.Fatal(err)
	}
	revokingCRL, err := x509.ParseRevocationList(revokingCRLDER)
	if err != nil {
		t.Fatal(err)
	}

	presented := X5Chain{Leaf: pki.leaf, Intermediates: []*x509.Certificate{pki.intermediate}}

	_, err = verifyParsedX5Chain(presented, TrustAnchors{
		Anchors: []*x509.Certificate{pki.root},
		CRLs:    nil,
	}, nil)
	if !errors.Is(err, ErrX5ChainCRLMissing) {
		t.Fatalf("full-chain checking without CRLs must fail: %v", err)
	}

	for _, tt := range []struct {
		name string
		mode RevocationMode
	}{
		{name: "full chain", mode: RevocationFullChain},
		{name: "leaf only", mode: RevocationLeafOnly},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := verifyParsedX5Chain(presented, TrustAnchors{
				Anchors:        []*x509.Certificate{pki.root},
				RevocationMode: tt.mode,
			}, &X5ChainVerifyOptions{CRLPolicy: CRLPolicyPermissive})
			if !errors.Is(err, ErrX5ChainCRLMissing) {
				t.Fatalf("enabled revocation checking without CRLs must fail: %v", err)
			}
		})
	}

	verified, err := verifyParsedX5Chain(presented, TrustAnchors{
		Anchors:        []*x509.Certificate{pki.root},
		CRLs:           []*x509.RevocationList{},
		RevocationMode: RevocationDisabled,
	}, nil)
	if err != nil {
		t.Fatalf("explicitly disabled revocation must skip CRL checks: %v", err)
	}
	if len(verified) < 2 || !bytes.Equal(verified[0].Raw, pki.leaf.Raw) {
		t.Fatalf("unexpected verified chain with revocation disabled: len=%d", len(verified))
	}

	verified, err = verifyParsedX5Chain(presented, TrustAnchors{
		Anchors:        []*x509.Certificate{pki.root},
		CRLs:           []*x509.RevocationList{revokingCRL, makeValidCRL(t, pki.root, pki.rootKey)},
		RevocationMode: RevocationDisabled,
	}, nil)
	if err != nil || len(verified) < 2 {
		t.Fatalf("disabled revocation must ignore configured CRLs: chain=%d err=%v", len(verified), err)
	}

	_, err = verifyParsedX5Chain(presented, TrustAnchors{
		Anchors: []*x509.Certificate{pki.root},
		CRLs:    []*x509.RevocationList{revokingCRL, makeValidCRL(t, pki.root, pki.rootKey)},
	}, nil)
	if !errors.Is(err, ErrX5ChainRevoked) {
		t.Fatalf("matching CRL must revoke leaf: got err %v", err)
	}
}

func TestCheckCertificateRevocation_permissiveFailsWhenOnlyNotYetValidMatchingCRL(t *testing.T) {
	pki := buildTestPKI(t)

	futureCRLDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now().Add(time.Hour),
		NextUpdate: time.Now().Add(2 * time.Hour),
	}, pki.intermediate, pki.intermediateKey)
	if err != nil {
		t.Fatal(err)
	}
	futureCRL, err := x509.ParseRevocationList(futureCRLDER)
	if err != nil {
		t.Fatal(err)
	}

	err = checkCertificateRevocation(
		pki.leaf, pki.intermediate, []*x509.RevocationList{futureCRL},
		CRLPolicyPermissive, time.Now(),
	)
	if err == nil || !strings.Contains(err.Error(), "not yet valid") {
		t.Fatalf("got err %v", err)
	}
}

func TestCheckCertificateRevocation_honorsRevocationTime(t *testing.T) {
	pki := buildTestPKI(t)
	now := time.Now().Truncate(time.Second)
	revocationTime := now.Add(time.Hour)

	crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: now.Add(-time.Hour),
		NextUpdate: now.Add(2 * time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{
			{SerialNumber: pki.leaf.SerialNumber, RevocationTime: revocationTime},
		},
	}, pki.intermediate, pki.intermediateKey)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		t.Fatal(err)
	}

	if err := checkCertificateRevocation(
		pki.leaf, pki.intermediate, []*x509.RevocationList{crl}, CRLPolicyStrict, now,
	); err != nil {
		t.Fatalf("future revocation must not apply yet: %v", err)
	}
	if err := checkCertificateRevocation(
		pki.leaf, pki.intermediate, []*x509.RevocationList{crl}, CRLPolicyStrict, revocationTime,
	); !errors.Is(err, ErrX5ChainRevoked) {
		t.Fatalf("revocation must apply at its effective time: %v", err)
	}
}

func TestCheckCertificateRevocation_strictRejectsCriticalDeltaCRL(t *testing.T) {
	pki := buildTestPKI(t)

	// BaseCRLNumber INTEGER 1 — deltaCRLIndicator value (RFC 5280 §5.2.4).
	deltaCRLDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now().Add(-time.Minute),
		NextUpdate: time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{{
			Id:       oidExtensionDeltaCRLIndicator,
			Critical: true,
			Value:    []byte{0x02, 0x01, 0x01},
		}},
	}, pki.intermediate, pki.intermediateKey)
	if err != nil {
		t.Fatal(err)
	}
	deltaCRL, err := x509.ParseRevocationList(deltaCRLDER)
	if err != nil {
		t.Fatal(err)
	}

	err = checkCertificateRevocation(
		pki.leaf, pki.intermediate, []*x509.RevocationList{deltaCRL},
		CRLPolicyStrict, time.Now(),
	)
	if err == nil || !strings.Contains(err.Error(), "invalid certificate CRL") {
		t.Fatalf("got err %v", err)
	}
}

func TestCheckCertificateRevocation_permissiveRejectsInvalidMatchingCRL(t *testing.T) {
	pki := buildTestPKI(t)

	wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongIssuerDER := mustCreateCA(t, wrongKey, pki.intermediate.Subject.CommonName)
	wrongIssuer, err := x509.ParseCertificate(wrongIssuerDER)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		crl     *x509.RevocationList
		wantErr bool
	}{
		{
			name: "different authority key identifier",
			crl:  makeValidCRL(t, wrongIssuer, wrongKey),
		},
		{
			name:    "unsupported critical extension",
			wantErr: true,
			crl: makeCRLWithExtensions(t, pki.intermediate, pki.intermediateKey, []pkix.Extension{{
				Id:       oidExtensionDeltaCRLIndicator,
				Critical: true,
				Value:    []byte{0x02, 0x01, 0x01},
			}}),
		},
		{
			name:    "malformed scope",
			wantErr: true,
			crl: makeCRLWithExtensions(t, pki.intermediate, pki.intermediateKey, []pkix.Extension{{
				Id:       oidExtensionIssuingDistributionPoint,
				Critical: true,
				Value:    []byte{0x01, 0x01, 0xff},
			}}),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkCertificateRevocation(
				pki.leaf, pki.intermediate, []*x509.RevocationList{tt.crl},
				CRLPolicyPermissive, time.Now(),
			)
			if tt.wantErr && (err == nil || !strings.Contains(err.Error(), "invalid certificate CRL")) {
				t.Fatalf("got err %v", err)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("non-applicable CRL must be ignored in permissive mode: %v", err)
			}
		})
	}
}

func makeCRLWithExtensions(
	t *testing.T,
	issuer *x509.Certificate,
	issuerKey *ecdsa.PrivateKey,
	extensions []pkix.Extension,
) *x509.RevocationList {
	t.Helper()

	crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:          big.NewInt(1),
		ThisUpdate:      time.Now().Add(-time.Minute),
		NextUpdate:      time.Now().Add(time.Hour),
		ExtraExtensions: extensions,
	}, issuer, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		t.Fatal(err)
	}

	return crl
}

func TestCheckCertificateRevocation_rejectsInvalidMatchingCRLAlongsideValidCRL(t *testing.T) {
	pki := buildTestPKI(t)
	validCRL := makeValidCRL(t, pki.intermediate, pki.intermediateKey)
	invalidCRL := makeCRLWithExtensions(t, pki.intermediate, pki.intermediateKey, []pkix.Extension{{
		Id:       oidExtensionDeltaCRLIndicator,
		Critical: true,
		Value:    []byte{0x02, 0x01, 0x01},
	}})

	tests := []struct {
		name string
		crls []*x509.RevocationList
	}{
		{name: "invalid first", crls: []*x509.RevocationList{invalidCRL, validCRL}},
		{name: "valid first", crls: []*x509.RevocationList{validCRL, invalidCRL}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := checkCertificateRevocation(
				pki.leaf, pki.intermediate, test.crls, CRLPolicyPermissive, time.Now(),
			)
			if err == nil || !strings.Contains(err.Error(), "unsupported critical extension") {
				t.Fatalf("got err %v", err)
			}
		})
	}
}

func TestCheckChainRevocation_permissiveSkipsMissingIssuerCRL(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	chainCA, err := x509.ParseCertificate(mustCreateCA(t, caKey, "Chain CA"))
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Test Leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, chainCA, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}

	unrelatedKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	unrelatedCA, err := x509.ParseCertificate(mustCreateCA(t, unrelatedKey, "Unrelated CA"))
	if err != nil {
		t.Fatal(err)
	}

	crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now().Add(-time.Minute),
		NextUpdate: time.Now().Add(time.Hour),
	}, unrelatedCA, unrelatedKey)
	if err != nil {
		t.Fatal(err)
	}

	crl, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		t.Fatal(err)
	}

	err = checkChainRevocation(
		[]*x509.Certificate{leaf, chainCA},
		[]*x509.RevocationList{crl},
		RevocationFullChain,
		CRLPolicyPermissive,
		time.Now(),
	)
	if err != nil {
		t.Fatal(err)
	}
}

func TestOrderVerifiedChains_prefersPresentedOverlap(t *testing.T) {
	leaf := &x509.Certificate{Raw: []byte("leaf")}
	inter := &x509.Certificate{Raw: []byte("inter")}
	rootA := &x509.Certificate{Raw: []byte("root-a")}
	rootB := &x509.Certificate{Raw: []byte("root-b")}

	presented := []*x509.Certificate{leaf, inter, rootA}
	chains := [][]*x509.Certificate{
		{leaf, inter, rootB},
		{leaf, inter, rootA},
	}

	ordered := orderVerifiedChains(presented, chains)
	if len(ordered) == 0 || string(ordered[0][len(ordered[0])-1].Raw) != "root-a" {
		t.Fatalf("unexpected selected chain")
	}
}

func TestSelectVerifiedChainWithRevocation_triesEveryCandidatePath(t *testing.T) {
	pki := buildTestPKI(t)

	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherRoot, err := x509.ParseCertificate(mustCreateCA(t, otherKey, "Other Root"))
	if err != nil {
		t.Fatal(err)
	}

	badPath := []*x509.Certificate{pki.leaf, pki.intermediate, otherRoot}
	goodPath := []*x509.Certificate{pki.leaf, pki.intermediate, pki.root}
	selected, err := selectVerifiedChainWithRevocation(
		badPath,
		[][]*x509.Certificate{badPath, goodPath},
		makeValidChainCRLs(t, &pki),
		RevocationFullChain,
		CRLPolicyStrict,
		time.Now(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if selected[len(selected)-1] != pki.root {
		t.Fatal("expected the candidate path with complete CRL coverage")
	}
}

func TestSelectVerifiedChainWithRevocation_prefersCompleteOverSoftPath(t *testing.T) {
	pki := buildTestPKI(t)

	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherRoot, err := x509.ParseCertificate(mustCreateCA(t, otherKey, "Other Root"))
	if err != nil {
		t.Fatal(err)
	}

	softPath := []*x509.Certificate{pki.leaf, otherRoot}
	completePath := []*x509.Certificate{pki.leaf, pki.intermediate, pki.root}
	selected, err := selectVerifiedChainWithRevocation(
		softPath,
		[][]*x509.Certificate{softPath, completePath},
		[]*x509.RevocationList{makeValidCRL(t, pki.intermediate, pki.intermediateKey)},
		RevocationLeafOnly,
		CRLPolicyPermissive,
		time.Now(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if selected[len(selected)-1] != pki.root {
		t.Fatal("expected the CRL-complete path")
	}
}

func TestSelectVerifiedChainWithRevocation_revocationOnAnyPathFails(t *testing.T) {
	pki := buildTestPKI(t)
	now := time.Now()
	revokingDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: now.Add(-time.Minute),
		NextUpdate: now.Add(time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{{
			SerialNumber:   pki.leaf.SerialNumber,
			RevocationTime: now.Add(-time.Minute),
		}},
	}, pki.intermediate, pki.intermediateKey)
	if err != nil {
		t.Fatal(err)
	}
	revokingCRL, err := x509.ParseRevocationList(revokingDER)
	if err != nil {
		t.Fatal(err)
	}

	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherRoot, err := x509.ParseCertificate(mustCreateCA(t, otherKey, "Other Root"))
	if err != nil {
		t.Fatal(err)
	}

	revokedPath := []*x509.Certificate{pki.leaf, pki.intermediate, pki.root}
	missingCRLPath := []*x509.Certificate{pki.leaf, otherRoot}
	_, err = selectVerifiedChainWithRevocation(
		revokedPath,
		[][]*x509.Certificate{missingCRLPath, revokedPath},
		[]*x509.RevocationList{revokingCRL},
		RevocationLeafOnly,
		CRLPolicyPermissive,
		now,
	)
	if !errors.Is(err, ErrX5ChainRevoked) {
		t.Fatalf("known revocation must not be bypassed by a path with missing CRL data: %v", err)
	}
}

func TestSelectVerifiedChainWithRevocation_CRLErrorBeatsSoftPath(t *testing.T) {
	pki := buildTestPKI(t)
	now := time.Now()

	expiredDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: now.Add(-2 * time.Hour),
		NextUpdate: now.Add(-time.Hour),
	}, pki.intermediate, pki.intermediateKey)
	if err != nil {
		t.Fatal(err)
	}
	expiredCRL, err := x509.ParseRevocationList(expiredDER)
	if err != nil {
		t.Fatal(err)
	}

	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherRoot, err := x509.ParseCertificate(mustCreateCA(t, otherKey, "Other Root"))
	if err != nil {
		t.Fatal(err)
	}

	expiredPath := []*x509.Certificate{pki.leaf, pki.intermediate, pki.root}
	missingCRLPath := []*x509.Certificate{pki.leaf, otherRoot}
	_, err = selectVerifiedChainWithRevocation(
		expiredPath,
		[][]*x509.Certificate{missingCRLPath, expiredPath},
		[]*x509.RevocationList{expiredCRL},
		RevocationLeafOnly,
		CRLPolicyPermissive,
		now,
	)
	if err == nil || !strings.Contains(err.Error(), "has expired") {
		t.Fatalf("CRL error must not be bypassed by a soft path: %v", err)
	}
}

func TestSelectVerifiedChainWithRevocation_completePathIgnoresOtherRevokedPath(t *testing.T) {
	pki := buildTestPKI(t)
	now := time.Now()

	evilKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	evilCA, err := x509.ParseCertificate(mustCreateCA(t, evilKey, "Evil CA"))
	if err != nil {
		t.Fatal(err)
	}
	revokingDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: now.Add(-time.Minute),
		NextUpdate: now.Add(time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{{
			SerialNumber:   pki.leaf.SerialNumber,
			RevocationTime: now.Add(-time.Minute),
		}},
	}, evilCA, evilKey)
	if err != nil {
		t.Fatal(err)
	}
	revokingCRL, err := x509.ParseRevocationList(revokingDER)
	if err != nil {
		t.Fatal(err)
	}

	goodPath := []*x509.Certificate{pki.leaf, pki.intermediate, pki.root}
	revokedPath := []*x509.Certificate{pki.leaf, evilCA}
	crls := append(makeValidChainCRLs(t, &pki), revokingCRL)

	// Prefer the revoked candidate first so selection must keep scanning.
	selected, err := selectVerifiedChainWithRevocation(
		revokedPath,
		[][]*x509.Certificate{revokedPath, goodPath},
		crls,
		RevocationLeafOnly,
		CRLPolicyStrict,
		now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if selected[len(selected)-1] != pki.root {
		t.Fatal("expected the CRL-complete path even when another candidate is revoked")
	}
}

func TestLoadTrustAnchors_nilReadFile(t *testing.T) {
	tests := []struct {
		name        string
		anchorPaths []string
		crlPaths    []string
		wantErr     bool
	}{
		{name: "empty paths"},
		{name: "trust anchor path", anchorPaths: []string{"anchor.der"}, wantErr: true},
		{name: "CRL path", crlPaths: []string{"issuer.crl"}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := LoadTrustAnchors(nil, tt.anchorPaths, tt.crlPaths)
			if tt.wantErr && (err == nil || !strings.Contains(err.Error(), "nil readFile")) {
				t.Fatalf("got err %v", err)
			}
			if !tt.wantErr && err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestVerifyParsedX5Chain_requiresExplicitTrustSource(t *testing.T) {
	leaf, err := x509.ParseCertificate(x509testdata.EndEntityDer)
	if err != nil {
		t.Fatal(err)
	}

	_, err = verifyParsedX5Chain(X5Chain{Leaf: leaf}, TrustAnchors{}, nil)
	if !errors.Is(err, ErrX5ChainNoTrust) {
		t.Fatalf("empty TrustAnchors must fail closed: %v", err)
	}
}

func TestVerifyParsedX5Chain_combinesLoadedAndSystemRoots(t *testing.T) {
	leaf, err := x509.ParseCertificate(x509testdata.EndEntityDer)
	if err != nil {
		t.Fatal(err)
	}
	intermediates, err := x509.ParseCertificates(certChainBytes())
	if err != nil {
		t.Fatal(err)
	}
	anchors, err := trustAnchorsWithoutRevocation(x509testdata.RootCA)
	if err != nil {
		t.Fatal(err)
	}
	anchors.UseSystemRoots = true

	verified, err := verifyParsedX5Chain(
		X5Chain{Leaf: leaf, Intermediates: intermediates}, anchors, nil,
	)
	if err != nil {
		t.Fatalf("verification with loaded and system roots failed: %v", err)
	}
	if len(verified) == 0 || !bytes.Equal(verified[0].Raw, leaf.Raw) {
		t.Fatal("unexpected verified chain")
	}
}

func TestVerifyPKIXChains_mergesCustomAndSystemRoots(t *testing.T) {
	leaf, err := x509.ParseCertificate(x509testdata.EndEntityDer)
	if err != nil {
		t.Fatal(err)
	}
	intermediates, err := x509.ParseCertificates(certChainBytes())
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(x509testdata.RootCA)
	if err != nil {
		t.Fatal(err)
	}
	chain := append([]*x509.Certificate{leaf}, intermediates...)
	customPool := x509.NewCertPool()
	customPool.AddCert(root)

	systemLoadCalled := false
	verified, err := verifyPKIXChainsWithSystemPoolLoader(chain, TrustAnchors{
		Anchors:        []*x509.Certificate{root},
		UseSystemRoots: true,
	}, nil, time.Now(), func() (*x509.CertPool, error) {
		systemLoadCalled = true
		return customPool, nil
	})
	if err != nil {
		t.Fatalf("combined trust verification failed: %v", err)
	}
	if !systemLoadCalled {
		t.Fatal("system roots were not loaded alongside custom roots")
	}
	if len(verified) != 1 {
		t.Fatalf("duplicate verified paths were not removed: got %d", len(verified))
	}

	systemLoadCalled = false
	_, err = verifyPKIXChainsWithSystemPoolLoader(chain, TrustAnchors{
		UseSystemRoots: true,
	}, nil, time.Now(), func() (*x509.CertPool, error) {
		systemLoadCalled = true
		return customPool, nil
	})
	if err != nil {
		t.Fatalf("system-root verification failed: %v", err)
	}
	if !systemLoadCalled {
		t.Fatal("system roots were not loaded after custom-root verification failed")
	}
}

func TestVerifyPKIXChains_keepsCustomPathWhenSystemPoolLoadFails(t *testing.T) {
	pki := buildTestPKI(t)

	verified, err := verifyPKIXChainsWithSystemPoolLoader(
		[]*x509.Certificate{pki.leaf, pki.intermediate},
		TrustAnchors{Anchors: []*x509.Certificate{pki.root}, UseSystemRoots: true},
		nil,
		time.Now(),
		func() (*x509.CertPool, error) {
			return nil, errors.New("system pool unavailable")
		},
	)
	if err != nil {
		t.Fatalf("valid custom path was discarded: %v", err)
	}
	if len(verified) != 1 || verified[0][len(verified[0])-1] != pki.root {
		t.Fatal("custom path was not retained")
	}
}

func TestVerifyPKIXChains_preservesPKIXErrorWhenSystemPoolLoadFails(t *testing.T) {
	pki := buildTestPKI(t)

	_, err := verifyPKIXChainsWithSystemPoolLoader(
		[]*x509.Certificate{pki.leaf, pki.intermediate},
		TrustAnchors{Anchors: []*x509.Certificate{pki.root}, UseSystemRoots: true},
		nil,
		pki.leaf.NotAfter.Add(time.Second),
		func() (*x509.CertPool, error) {
			return nil, errors.New("system pool unavailable")
		},
	)
	var invalidErr x509.CertificateInvalidError
	if !errors.As(err, &invalidErr) {
		t.Fatalf("got err %v, want CertificateInvalidError", err)
	}
	if !strings.Contains(err.Error(), "system pool unavailable") {
		t.Fatalf("system pool error was lost: %v", err)
	}
}

func TestVerifyPKIXChains_rejectsNilCertificateTrustAnchor(t *testing.T) {
	pki := buildTestPKI(t)
	_, err := verifyPKIXChainsWithSystemPoolLoader(
		[]*x509.Certificate{pki.leaf, pki.intermediate},
		TrustAnchors{Anchors: []*x509.Certificate{nil}},
		nil,
		time.Now(),
		func() (*x509.CertPool, error) {
			t.Fatal("system pool loader must not be called")
			return nil, nil
		},
	)
	if err == nil || !strings.Contains(err.Error(), "trust anchor 0 is nil") {
		t.Fatalf("got err %v", err)
	}
}

func TestLoadTrustAnchors_loadsPemTrustAnchorBundle(t *testing.T) {
	bundle := append(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: x509testdata.RootCA}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: x509testdata.IntermediateCA})...,
	)

	anchors, err := LoadTrustAnchors(func(string) ([]byte, error) {
		return bundle, nil
	}, []string{"bundle.pem"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	anchors.RevocationMode = RevocationDisabled

	leaf, err := x509.ParseCertificate(x509testdata.EndEntityDer)
	if err != nil {
		t.Fatal(err)
	}
	intermediates, err := x509.ParseCertificates(certChainBytes())
	if err != nil {
		t.Fatal(err)
	}

	root, err := x509.ParseCertificate(x509testdata.RootCA)
	if err != nil {
		t.Fatal(err)
	}

	verified, err := verifyParsedX5Chain(X5Chain{Leaf: leaf, Intermediates: intermediates}, anchors, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(verified) < 2 {
		t.Fatalf("expected verified chain length >= 2, got %d", len(verified))
	}
	if !bytes.Equal(verified[0].Raw, leaf.Raw) {
		t.Fatal("verified chain leaf does not match presented leaf")
	}
	if !bytes.Equal(verified[len(verified)-1].Raw, root.Raw) {
		t.Fatal("verified chain trust anchor does not match RootCA")
	}
}

func TestLoadTrustAnchors_rejectsPartiallyMalformedPEMBundle(t *testing.T) {
	validCertificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: x509testdata.RootCA})

	tests := []struct {
		name   string
		suffix []byte
	}{
		{
			name:   "invalid block type",
			suffix: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("invalid")}),
		},
		{
			name:   "malformed certificate",
			suffix: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("invalid")}),
		},
		{
			name:   "trailing garbage",
			suffix: []byte("not PEM data"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bundle := append(append([]byte(nil), validCertificate...), tt.suffix...)
			_, err := LoadTrustAnchors(func(string) ([]byte, error) {
				return bundle, nil
			}, []string{"bundle.pem"}, nil)
			if err == nil || !strings.Contains(err.Error(), "parsing trust anchor from bundle.pem") {
				t.Fatalf("got err %v", err)
			}
		})
	}
}

func TestSign1Message_VerifyWithX5Chain_ok(t *testing.T) {
	key := parseEndEntityKey(t)
	msg := signSign1WithX5Chain(t, x509testdata.EndEntityDer, certChainBytes(), key)

	anchors, err := trustAnchorsWithoutRevocation(x509testdata.RootCA)
	if err != nil {
		t.Fatal(err)
	}

	verifiedChain, err := msg.VerifyWithX5Chain([]byte{}, anchors, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(verifiedChain) != 3 || !bytes.Equal(verifiedChain[0].Raw, x509testdata.EndEntityDer) ||
		!bytes.Equal(verifiedChain[len(verifiedChain)-1].Raw, x509testdata.RootCA) {
		t.Fatal("returned path is not the verified leaf-to-root chain")
	}
}

func TestUntaggedSign1Message_VerifyWithX5Chain_ok(t *testing.T) {
	key := parseEndEntityKey(t)
	msg := signSign1WithX5Chain(t, x509testdata.EndEntityDer, certChainBytes(), key)
	untagged := UntaggedSign1Message(*msg)

	anchors, err := trustAnchorsWithoutRevocation(x509testdata.RootCA)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := untagged.VerifyWithX5Chain([]byte{}, anchors, nil); err != nil {
		t.Fatal(err)
	}
}

func TestSign1Message_VerifyWithX5Chain_okWithCRLs(t *testing.T) {
	pki := buildTestPKI(t)
	msg := signSign1WithX5Chain(t, pki.leafDER, pki.intermediateDER, pki.leafKey)

	verifiedChain, err := msg.VerifyWithX5Chain([]byte{}, TrustAnchors{
		Anchors: []*x509.Certificate{pki.root},
		CRLs:    makeValidChainCRLs(t, &pki),
	}, nil)
	if err != nil {
		t.Fatalf("default full-chain revocation with applicable CRLs must succeed: %v", err)
	}
	if len(verifiedChain) != 3 ||
		!bytes.Equal(verifiedChain[0].Raw, pki.leaf.Raw) ||
		!bytes.Equal(verifiedChain[1].Raw, pki.intermediate.Raw) ||
		!bytes.Equal(verifiedChain[2].Raw, pki.root.Raw) {
		t.Fatal("returned path is not the verified leaf-to-root chain")
	}
}

func TestSign1Message_VerifyWithX5Chain_requiresCRLsByDefault(t *testing.T) {
	key := parseEndEntityKey(t)
	msg := signSign1WithX5Chain(t, x509testdata.EndEntityDer, certChainBytes(), key)

	root, err := x509.ParseCertificate(x509testdata.RootCA)
	if err != nil {
		t.Fatal(err)
	}

	verifiedChain, err := msg.VerifyWithX5Chain([]byte{}, TrustAnchors{Anchors: []*x509.Certificate{root}}, nil)
	if !errors.Is(err, ErrX5ChainCRLMissing) {
		t.Fatalf("default full-chain revocation checking must require CRLs: %v", err)
	}
	if verifiedChain != nil {
		t.Fatal("failed revocation checking must not return a verified chain")
	}
}

func TestSign1Message_VerifyWithX5Chain_usesAdditionalIntermediates(t *testing.T) {
	key := parseEndEntityKey(t)
	msg := signSign1WithX5Chain(t, x509testdata.EndEntityDer, nil, key)

	anchors, err := trustAnchorsWithoutRevocation(x509testdata.RootCA)
	if err != nil {
		t.Fatal(err)
	}
	intermediate, err := x509.ParseCertificate(x509testdata.IntermediateCA)
	if err != nil {
		t.Fatal(err)
	}
	additional := x509.NewCertPool()
	additional.AddCert(intermediate)
	opts := &X5ChainVerifyOptions{
		AdditionalIntermediates: additional,
	}

	verifiedChain, err := msg.VerifyWithX5Chain([]byte{}, anchors, opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(verifiedChain) != 3 || !bytes.Equal(verifiedChain[1].Raw, x509testdata.IntermediateCA) {
		t.Fatal("returned path did not include the selected additional intermediate")
	}
}

func TestSign1Message_VerifyWithX5Chain_loadsRootAndIntermediateFromFiles(t *testing.T) {
	key := parseEndEntityKey(t)
	// Leaf-only x5chain: root and intermediate must come from disk.
	msg := signSign1WithX5Chain(t, x509testdata.EndEntityDer, nil, key)

	rootPath := filepath.Join("testdata", "x509", "rootCA.der")
	intermediatePath := filepath.Join("testdata", "x509", "intermediateCA.der")

	anchors, err := LoadTrustAnchors(os.ReadFile, []string{rootPath}, nil)
	if err != nil {
		t.Fatal(err)
	}
	anchors.RevocationMode = RevocationDisabled

	verifiedChain, err := msg.VerifyWithX5Chain(nil, anchors, nil)
	if !errors.Is(err, ErrX5ChainNoTrust) {
		t.Fatalf("verification without the file-loaded intermediate error = %v, want ErrX5ChainNoTrust", err)
	}
	if verifiedChain != nil {
		t.Fatal("failed verification without the file-loaded intermediate returned a chain")
	}

	intermediateDER, err := os.ReadFile(intermediatePath)
	if err != nil {
		t.Fatal(err)
	}
	intermediate, err := x509.ParseCertificate(intermediateDER)
	if err != nil {
		t.Fatal(err)
	}
	additional := x509.NewCertPool()
	additional.AddCert(intermediate)

	verifiedChain, err = msg.VerifyWithX5Chain([]byte{}, anchors, &X5ChainVerifyOptions{
		AdditionalIntermediates: additional,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(verifiedChain) != 3 {
		t.Fatalf("verified path length = %d, want 3", len(verifiedChain))
	}
	if !bytes.Equal(verifiedChain[0].Raw, x509testdata.EndEntityDer) {
		t.Fatal("verified path leaf mismatch")
	}
	if !bytes.Equal(verifiedChain[1].Raw, x509testdata.IntermediateCA) {
		t.Fatal("verified path did not use the intermediate loaded from disk")
	}
	if !bytes.Equal(verifiedChain[2].Raw, x509testdata.RootCA) {
		t.Fatal("verified path did not use the root loaded from disk")
	}
}

func TestSign1Message_VerifyWithX5Chain_loadsRootFromFileWithPresentedIntermediate(t *testing.T) {
	key := parseEndEntityKey(t)
	// The x5chain presents the leaf and intermediate; only the root comes from disk.
	msg := signSign1WithX5Chain(
		t, x509testdata.EndEntityDer, x509testdata.IntermediateCA, key,
	)

	rootPath := filepath.Join("testdata", "x509", "rootCA.der")
	anchors, err := LoadTrustAnchors(os.ReadFile, []string{rootPath}, nil)
	if err != nil {
		t.Fatal(err)
	}
	anchors.RevocationMode = RevocationDisabled

	verifiedChain, err := msg.VerifyWithX5Chain(nil, anchors, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(verifiedChain) != 3 {
		t.Fatalf("verified path length = %d, want 3", len(verifiedChain))
	}
	if !bytes.Equal(verifiedChain[0].Raw, x509testdata.EndEntityDer) {
		t.Fatal("verified path leaf mismatch")
	}
	if !bytes.Equal(verifiedChain[1].Raw, x509testdata.IntermediateCA) {
		t.Fatal("verified path did not use the intermediate presented in x5chain")
	}
	if !bytes.Equal(verifiedChain[2].Raw, x509testdata.RootCA) {
		t.Fatal("verified path did not use the root loaded from disk")
	}
}

func TestSign1Message_VerifyWithX5Chain_rejectsDuplicateUnprotected(t *testing.T) {
	key := parseEndEntityKey(t)
	msg := signSign1WithX5Chain(t, x509testdata.EndEntityDer, certChainBytes(), key)
	msg.Headers.Unprotected[HeaderLabelX5Chain] = []byte("not a certificate")

	anchors, err := trustAnchorsWithoutRevocation(x509testdata.RootCA)
	if err != nil {
		t.Fatal(err)
	}
	_, err = msg.VerifyWithX5Chain([]byte{}, anchors, nil)
	if err == nil || err.Error() != "x5chain: unprotected header not supported" {
		t.Fatalf("got err %v", err)
	}
}

func TestSign1Message_VerifyWithX5Chain_wireRoundTrip(t *testing.T) {
	key := parseEndEntityKey(t)
	msg := signSign1WithX5Chain(t, x509testdata.EndEntityDer, certChainBytes(), key)

	wire, err := msg.MarshalCBOR()
	if err != nil {
		t.Fatal(err)
	}

	var decoded Sign1Message
	if err := decoded.UnmarshalCBOR(wire); err != nil {
		t.Fatal(err)
	}

	anchors, err := trustAnchorsWithoutRevocation(x509testdata.RootCA)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decoded.VerifyWithX5Chain([]byte{}, anchors, nil); err != nil {
		t.Fatal(err)
	}
}

func TestSign1Message_VerifyWithX5Chain_unprotectedNotSupported(t *testing.T) {
	leaf, err := x509.ParseCertificate(x509testdata.EndEntityDer)
	if err != nil {
		t.Fatal(err)
	}
	intermediates, err := x509.ParseCertificates(certChainBytes())
	if err != nil {
		t.Fatal(err)
	}

	encodedChain := ProtectedHeader{}
	if err := SetX5Chain(encodedChain, X5Chain{Leaf: leaf, Intermediates: intermediates}); err != nil {
		t.Fatal(err)
	}

	msg := NewSign1Message()
	msg.Payload = []byte("test payload")
	msg.Headers.Protected.SetAlgorithm(AlgorithmES256)
	msg.Headers.Unprotected[HeaderLabelX5Chain] = encodedChain[HeaderLabelX5Chain]

	signer, err := NewSigner(AlgorithmES256, parseEndEntityKey(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := msg.Sign(rand.Reader, []byte{}, signer); err != nil {
		t.Fatal(err)
	}

	anchors, err := trustAnchorsWithoutRevocation(x509testdata.RootCA)
	if err != nil {
		t.Fatal(err)
	}
	_, err = msg.VerifyWithX5Chain([]byte{}, anchors, nil)
	if err == nil || err.Error() != "x5chain: unprotected header not supported" {
		t.Fatalf("got err %v", err)
	}
}

func TestSign1Message_VerifyWithX5Chain_usesEffectiveRawProtected(t *testing.T) {
	key := parseEndEntityKey(t)
	msg := signSign1WithX5Chain(t, x509testdata.EndEntityDer, certChainBytes(), key)

	rawProtected, err := msg.Headers.MarshalProtected()
	if err != nil {
		t.Fatal(err)
	}
	msg.Headers.RawProtected = rawProtected

	// RawProtected has precedence and contains the values covered by the
	// signature. These conflicting structured values must not influence trust or
	// algorithm selection.
	msg.Headers.Protected[HeaderLabelX5Chain] = []byte("not a certificate")
	msg.Headers.Protected.SetAlgorithm(AlgorithmPS256)

	anchors, err := trustAnchorsWithoutRevocation(x509testdata.RootCA)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := msg.VerifyWithX5Chain([]byte{}, anchors, nil); err != nil {
		t.Fatalf("verification must use effective RawProtected: %v", err)
	}
}

func TestSign1Message_VerifyWithX5Chain_noHeader(t *testing.T) {
	msg := NewSign1Message()
	msg.Payload = []byte("payload")
	msg.Signature = []byte{1, 2, 3}
	msg.Headers.Protected.SetAlgorithm(AlgorithmES256)

	_, err := msg.VerifyWithX5Chain([]byte{}, TrustAnchors{}, nil)
	if err == nil || err.Error() != "x5chain: header not set" {
		t.Fatalf("got err %v", err)
	}
}

func TestSign1Message_VerifyWithX5Chain_tamperedPayload(t *testing.T) {
	key := parseEndEntityKey(t)
	msg := signSign1WithX5Chain(t, x509testdata.EndEntityDer, certChainBytes(), key)
	msg.Payload = []byte("tampered")

	anchors, err := trustAnchorsWithoutRevocation(x509testdata.RootCA)
	if err != nil {
		t.Fatal(err)
	}

	verifiedChain, err := msg.VerifyWithX5Chain([]byte{}, anchors, nil)
	if !errors.Is(err, ErrX5ChainSignature) {
		t.Fatalf("got err %v", err)
	}
	if verifiedChain != nil {
		t.Fatal("failed verification must not return a verified chain")
	}
}

func TestSign1Message_VerifyWithX5Chain_rejectsCALeaf(t *testing.T) {
	pki := buildTestPKI(t)
	msg := signSign1WithX5Chain(t, pki.intermediateDER, pki.root.Raw, pki.intermediateKey)

	anchors, err := trustAnchorsWithoutRevocation(pki.root.Raw)
	if err != nil {
		t.Fatal(err)
	}

	_, err = msg.VerifyWithX5Chain(nil, anchors, nil)
	if err == nil || err.Error() != "x5chain: signing certificate must not be a CA" {
		t.Fatalf("got err %v", err)
	}
}

func TestSign1Message_VerifyWithX5Chain_rejectsMissingDigitalSignature(t *testing.T) {
	pki := buildTestPKI(t)
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber:          big.NewInt(4),
		Subject:               pkix.Name{CommonName: "Leaf without digitalSignature"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
	}, pki.intermediate, &leafKey.PublicKey, pki.intermediateKey)
	if err != nil {
		t.Fatal(err)
	}

	chainDER := append(append([]byte{}, pki.intermediate.Raw...), pki.root.Raw...)
	msg := signSign1WithX5Chain(t, leafDER, chainDER, leafKey)
	anchors, err := trustAnchorsWithoutRevocation(pki.root.Raw)
	if err != nil {
		t.Fatal(err)
	}

	_, err = msg.VerifyWithX5Chain(nil, anchors, nil)
	if err == nil || err.Error() != "x5chain: signing certificate lacks digitalSignature key usage" {
		t.Fatalf("got err %v", err)
	}
}

func TestSetX5Chain_singleLeafUsesBstrForm(t *testing.T) {
	leaf, err := x509.ParseCertificate(x509testdata.EndEntityDer)
	if err != nil {
		t.Fatal(err)
	}

	h := ProtectedHeader{}
	if err := SetX5Chain(h, X5Chain{Leaf: leaf}); err != nil {
		t.Fatal(err)
	}

	wire, ok := h[HeaderLabelX5Chain].([]byte)
	if !ok {
		t.Fatalf("expected []byte wire form, got %T", h[HeaderLabelX5Chain])
	}
	if !bytes.Equal(wire, leaf.Raw) {
		t.Fatalf("unexpected single-leaf wire encoding: %+v", wire)
	}

	parsed, err := ParseX5Chain(wire)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Leaf == nil || len(parsed.Intermediates) != 0 {
		t.Fatal("round-trip single-leaf chain failed")
	}
}

func TestSetX5Chain_rejectsOutOfOrderCertificates(t *testing.T) {
	leaf, err := x509.ParseCertificate(x509testdata.EndEntityDer)
	if err != nil {
		t.Fatal(err)
	}
	intermediates, err := x509.ParseCertificates(certChainBytes())
	if err != nil {
		t.Fatal(err)
	}

	h := ProtectedHeader{}
	err = SetX5Chain(h, X5Chain{
		Leaf:          leaf,
		Intermediates: []*x509.Certificate{intermediates[1], intermediates[0]},
	})
	if err == nil || !strings.Contains(err.Error(), "was not issued by") {
		t.Fatalf("SetX5Chain() error = %v", err)
	}
	if _, ok := h[HeaderLabelX5Chain]; ok {
		t.Fatal("SetX5Chain must not modify the header after validation fails")
	}
}

func TestSetX5Chain_rejectsEmptyRaw(t *testing.T) {
	h := ProtectedHeader{}
	err := SetX5Chain(h, X5Chain{Leaf: &x509.Certificate{IsCA: false}})
	if err == nil || !strings.Contains(err.Error(), "leaf certificate has empty Raw bytes") {
		t.Fatalf("got err %v", err)
	}

	leaf, err := x509.ParseCertificate(x509testdata.EndEntityDer)
	if err != nil {
		t.Fatal(err)
	}
	err = SetX5Chain(h, X5Chain{
		Leaf:          leaf,
		Intermediates: []*x509.Certificate{{IsCA: true}},
	})
	if err == nil || !strings.Contains(err.Error(), "intermediate[0] has empty Raw bytes") {
		t.Fatalf("got err %v", err)
	}
}

func TestSetX5Chain_rejectsNilHeader(t *testing.T) {
	leaf, err := x509.ParseCertificate(x509testdata.EndEntityDer)
	if err != nil {
		t.Fatal(err)
	}

	var h ProtectedHeader
	err = SetX5Chain(h, X5Chain{Leaf: leaf})
	if err == nil || !strings.Contains(err.Error(), "nil protected header") {
		t.Fatalf("got err %v", err)
	}
}

func TestSetX5Chain_rejectsResourceLimitViolations(t *testing.T) {
	leaf, err := x509.ParseCertificate(x509testdata.EndEntityDer)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("too many certificates", func(t *testing.T) {
		h := ProtectedHeader{}
		intermediates := make([]*x509.Certificate, MaxX5ChainCertificates)
		for i := range intermediates {
			intermediates[i] = leaf
		}

		err := SetX5Chain(h, X5Chain{Leaf: leaf, Intermediates: intermediates})
		if err == nil || !strings.Contains(err.Error(), "too many certificates") {
			t.Fatalf("got err %v", err)
		}
		if _, ok := h[HeaderLabelX5Chain]; ok {
			t.Fatal("SetX5Chain must not modify the header after validation fails")
		}
	})

	t.Run("oversized certificate", func(t *testing.T) {
		h := ProtectedHeader{}
		oversizedLeaf := *leaf
		oversizedLeaf.Raw = make([]byte, MaxX5ChainCertDERBytes+1)

		err := SetX5Chain(h, X5Chain{Leaf: &oversizedLeaf})
		if err == nil || !strings.Contains(err.Error(), "exceeds") {
			t.Fatalf("got err %v", err)
		}
		if _, ok := h[HeaderLabelX5Chain]; ok {
			t.Fatal("SetX5Chain must not modify the header after validation fails")
		}
	})
}

func TestProtectedHeader_x5chainValidationDeferred(t *testing.T) {
	h := ProtectedHeader{
		HeaderLabelAlgorithm: AlgorithmES256,
		HeaderLabelX5Chain:   "not-a-cert-chain",
	}
	if _, err := h.MarshalCBOR(); err != nil {
		t.Fatalf("MarshalCBOR should preserve opaque x5chain values: %v", err)
	}
	if _, err := ParseX5Chain(h[HeaderLabelX5Chain]); err == nil {
		t.Fatal("ParseX5Chain() expected invalid x5chain type")
	}
}

func TestProtectedHeader_x5chainInvalidTypeUnmarshal(t *testing.T) {
	inner, err := encMode.Marshal(map[any]any{
		HeaderLabelAlgorithm: AlgorithmES256,
		HeaderLabelX5Chain:   "not-a-cert-chain",
	})
	if err != nil {
		t.Fatal(err)
	}
	data, err := encMode.Marshal(inner)
	if err != nil {
		t.Fatal(err)
	}

	var h ProtectedHeader
	if err := h.UnmarshalCBOR(data); err != nil {
		t.Fatalf("UnmarshalCBOR should defer x5chain checks: %v", err)
	}
	if _, err := ParseX5Chain(h[HeaderLabelX5Chain]); err == nil {
		t.Fatal("ParseX5Chain() expected invalid x5chain type")
	}
}

func TestX5ChainHeaderMarshal_preservesLegacyOneCertificateArray(t *testing.T) {
	tests := []struct {
		name  string
		value any
	}{
		{name: "interface slice", value: []interface{}{[]byte{1}}},
		{name: "byte slice", value: [][]byte{{1}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			protected := ProtectedHeader{HeaderLabelX5Chain: tt.value}
			if _, err := protected.MarshalCBOR(); err != nil {
				t.Fatalf("ProtectedHeader.MarshalCBOR() error = %v", err)
			}
		})
	}
}

func TestX5ChainHeaderMarshal_defersCertificateOrderValidation(t *testing.T) {
	value := [][]byte{
		x509testdata.EndEntityDer,
		x509testdata.RootCA,
		x509testdata.IntermediateCA,
	}

	protected := ProtectedHeader{HeaderLabelX5Chain: value}
	if _, err := protected.MarshalCBOR(); err != nil {
		t.Fatalf("ProtectedHeader.MarshalCBOR() error = %v", err)
	}

	if _, err := ParseX5Chain(value); err == nil || !strings.Contains(err.Error(), "was not issued by") {
		t.Fatalf("ParseX5Chain() error = %v", err)
	}
}

func TestParseX5Chain_rejectsOversize(t *testing.T) {
	oversized := make([]byte, MaxX5ChainCertDERBytes+1)
	oversized[0] = 0x30
	_, err := ParseX5Chain(oversized)
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("leaf size: got err %v", err)
	}

	tooMany := make([][]byte, MaxX5ChainCertificates+1)
	for i := range tooMany {
		tooMany[i] = x509testdata.EndEntityDer
	}
	_, err = ParseX5Chain(tooMany)
	if err == nil || !strings.Contains(err.Error(), "too many certificates") {
		t.Fatalf("count: got err %v", err)
	}

	_, err = ParseX5Chain([]interface{}{x509testdata.EndEntityDer, oversized})
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("intermediate size: got err %v", err)
	}
}

func TestParseX5Chain_emptyIntermediateElement(t *testing.T) {
	_, err := ParseX5Chain([]interface{}{x509testdata.EndEntityDer, []byte{}})
	if err == nil || !strings.Contains(err.Error(), "empty intermediate cert at index 1") {
		t.Fatalf("got err %v", err)
	}

	_, err = ParseX5Chain([][]byte{x509testdata.EndEntityDer, []byte{}})
	if err == nil || !strings.Contains(err.Error(), "empty intermediate cert at index 1") {
		t.Fatalf("got err %v", err)
	}
}

func TestLoadTrustAnchors_loadsCRL(t *testing.T) {
	pki := buildTestPKI(t)
	crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now().Add(-time.Minute),
		NextUpdate: time.Now().Add(time.Hour),
	}, pki.intermediate, pki.intermediateKey)
	if err != nil {
		t.Fatal(err)
	}

	anchors, err := LoadTrustAnchors(func(path string) ([]byte, error) {
		switch path {
		case "anchor.der":
			return x509testdata.RootCA, nil
		case "issuer.crl":
			return crlDER, nil
		default:
			t.Fatalf("unexpected path %q", path)
			return nil, nil
		}
	}, []string{"anchor.der"}, []string{"issuer.crl"})
	if err != nil {
		t.Fatal(err)
	}
	if len(anchors.CRLs) != 1 {
		t.Fatalf("expected 1 CRL, got %d", len(anchors.CRLs))
	}
}

func TestLoadTrustAnchors_pemCRLTrailingGarbage(t *testing.T) {
	pki := buildTestPKI(t)
	crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now().Add(-time.Minute),
		NextUpdate: time.Now().Add(time.Hour),
	}, pki.intermediate, pki.intermediateKey)
	if err != nil {
		t.Fatal(err)
	}

	bundle := append(
		pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDER}),
		[]byte("trailing-garbage")...,
	)

	_, err = LoadTrustAnchors(func(path string) ([]byte, error) {
		switch path {
		case "anchor.der":
			return x509testdata.RootCA, nil
		case "crls.pem":
			return bundle, nil
		default:
			t.Fatalf("unexpected path %q", path)
			return nil, nil
		}
	}, []string{"anchor.der"}, []string{"crls.pem"})
	if err == nil || !strings.Contains(err.Error(), "trailing data after PEM CRL blocks") {
		t.Fatalf("got err %v", err)
	}
}

func TestLoadTrustAnchors_rejectsGarbageAroundPEMCRLBlocks(t *testing.T) {
	pki := buildTestPKI(t)
	crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now().Add(-time.Minute),
		NextUpdate: time.Now().Add(time.Hour),
	}, pki.intermediate, pki.intermediateKey)
	if err != nil {
		t.Fatal(err)
	}
	encodedCRL := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDER})

	tests := []struct {
		name   string
		bundle []byte
	}{
		{
			name:   "before first block",
			bundle: append([]byte("garbage\n"), encodedCRL...),
		},
		{
			name: "between blocks",
			bundle: append(
				append(append([]byte(nil), encodedCRL...), []byte("garbage\n")...),
				encodedCRL...,
			),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := LoadTrustAnchors(func(path string) ([]byte, error) {
				switch path {
				case "anchor.der":
					return x509testdata.RootCA, nil
				case "crls.pem":
					return tt.bundle, nil
				default:
					t.Fatalf("unexpected path %q", path)
					return nil, nil
				}
			}, []string{"anchor.der"}, []string{"crls.pem"})
			if err == nil || !strings.Contains(err.Error(), "PEM CRL block") {
				t.Fatalf("got err %v", err)
			}
		})
	}
}

func TestSign1Message_VerifyWithX5Chain_algKeyMismatch(t *testing.T) {
	// After Sign, RawProtected is unset, so changing the structured alg affects
	// VerifyWithX5Chain before the COSE signature check (NewVerifier fails).
	key := parseEndEntityKey(t)
	msg := signSign1WithX5Chain(t, x509testdata.EndEntityDer, certChainBytes(), key)
	msg.Headers.Protected.SetAlgorithm(AlgorithmPS256)

	anchors, err := trustAnchorsWithoutRevocation(x509testdata.RootCA)
	if err != nil {
		t.Fatal(err)
	}

	_, err = msg.VerifyWithX5Chain([]byte{}, anchors, nil)
	if err == nil || !strings.Contains(err.Error(), "unable to instantiate verifier") {
		t.Fatalf("got err %v", err)
	}
}

func TestSign1Message_VerifyWithX5Chain_revokedLeaf(t *testing.T) {
	pki := buildTestPKI(t)

	crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now().Add(-time.Minute),
		NextUpdate: time.Now().Add(time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{
			{
				SerialNumber:   pki.leaf.SerialNumber,
				RevocationTime: time.Now().Add(-time.Minute),
			},
		},
	}, pki.intermediate, pki.intermediateKey)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		t.Fatal(err)
	}

	msg := signSign1WithX5Chain(t, pki.leafDER, pki.intermediateDER, pki.leafKey)

	_, err = msg.VerifyWithX5Chain([]byte{}, TrustAnchors{
		Anchors: []*x509.Certificate{pki.root},
		CRLs:    []*x509.RevocationList{crl, makeValidCRL(t, pki.root, pki.rootKey)},
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("got err %v", err)
	}
}

func TestVerifyParsedX5Chain_nilIntermediateNoPanic(t *testing.T) {
	leaf, err := x509.ParseCertificate(x509testdata.EndEntityDer)
	if err != nil {
		t.Fatal(err)
	}
	inter, err := x509.ParseCertificate(x509testdata.IntermediateCA)
	if err != nil {
		t.Fatal(err)
	}

	anchors, err := trustAnchorsWithoutRevocation(x509testdata.RootCA)
	if err != nil {
		t.Fatal(err)
	}

	_, err = verifyParsedX5Chain(
		X5Chain{Leaf: leaf, Intermediates: []*x509.Certificate{inter, nil}},
		anchors,
		nil,
	)
	if err == nil || !strings.Contains(err.Error(), "intermediate[1] is nil") {
		t.Fatalf("got err %v", err)
	}
}

func TestCheckCRLValidity_nextUpdateBoundary(t *testing.T) {
	nextUpdate := time.Now().Truncate(time.Second)
	crl := &x509.RevocationList{
		ThisUpdate: nextUpdate.Add(-time.Hour),
		NextUpdate: nextUpdate,
	}

	if err := checkCRLValidity(crl, nextUpdate.Add(-time.Second)); err != nil {
		t.Fatalf("CRL must be valid before NextUpdate: %v", err)
	}
	if err := checkCRLValidity(crl, nextUpdate); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("CRL must expire at NextUpdate: %v", err)
	}
	if err := checkCRLValidity(crl, nextUpdate.Add(time.Second)); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("CRL must remain expired after NextUpdate: %v", err)
	}
}

func TestCheckCertificateRevocation_rejectsNilSerial(t *testing.T) {
	pki := buildTestPKI(t)
	cert := *pki.leaf
	cert.SerialNumber = nil

	err := checkCertificateRevocation(
		&cert, pki.intermediate,
		[]*x509.RevocationList{makeValidCRL(t, pki.intermediate, pki.intermediateKey)},
		CRLPolicyStrict, time.Now(),
	)
	if err == nil || !strings.Contains(err.Error(), "nil serial number") {
		t.Fatalf("got err %v", err)
	}
}

func TestIsSerialRevoked_honorsRevocationTime(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	serial := big.NewInt(1)

	tests := []struct {
		name           string
		revocationTime time.Time
		want           bool
	}{
		{name: "before verification time", revocationTime: now.Add(-time.Second), want: true},
		{name: "at verification time", revocationTime: now, want: true},
		{name: "after verification time", revocationTime: now.Add(time.Second), want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			crl := &x509.RevocationList{
				RevokedCertificateEntries: []x509.RevocationListEntry{
					{SerialNumber: serial, RevocationTime: tt.revocationTime},
				},
			}
			got := isSerialRevoked(serial, crl, now)
			if got != tt.want {
				t.Fatalf("isSerialRevoked() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCRLEntryHasUnsupportedCriticalExtension(t *testing.T) {
	unknownOID := asn1.ObjectIdentifier{1, 2, 3, 4}

	tests := []struct {
		name  string
		entry x509.RevocationListEntry
		want  bool
	}{
		{
			name: "unsupported critical",
			entry: x509.RevocationListEntry{
				Extensions: []pkix.Extension{{
					Id:       unknownOID,
					Critical: true,
				}},
			},
			want: true,
		},
		{
			name: "non-critical unknown",
			entry: x509.RevocationListEntry{
				Extensions: []pkix.Extension{{
					Id: unknownOID,
				}},
			},
		},
		{
			name: "critical reasonCode policy",
			entry: x509.RevocationListEntry{
				Extensions: []pkix.Extension{{
					Id:       oidExtensionReasonCode,
					Critical: true,
				}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := crlEntryHasUnsupportedCriticalExtension(tt.entry)
			if got != tt.want {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCheckCertificateRevocation_rejectsUnsupportedCriticalEntryExtension(t *testing.T) {
	pki := buildTestPKI(t)
	now := time.Now().Truncate(time.Second)

	tests := []struct {
		name   string
		serial *big.Int
	}{
		{name: "matching entry", serial: pki.leaf.SerialNumber},
		{name: "unrelated entry", serial: big.NewInt(99)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
				Number:     big.NewInt(1),
				ThisUpdate: now.Add(-time.Minute),
				NextUpdate: now.Add(time.Hour),
				RevokedCertificateEntries: []x509.RevocationListEntry{{
					SerialNumber:   tt.serial,
					RevocationTime: now.Add(-time.Minute),
					ExtraExtensions: []pkix.Extension{{
						Id:       asn1.ObjectIdentifier{1, 2, 3, 4},
						Critical: true,
						Value:    []byte{0x05, 0x00},
					}},
				}},
			}, pki.intermediate, pki.intermediateKey)
			if err != nil {
				t.Fatal(err)
			}
			crl, err := x509.ParseRevocationList(crlDER)
			if err != nil {
				t.Fatal(err)
			}

			err = checkCertificateRevocation(
				pki.leaf, pki.intermediate, []*x509.RevocationList{crl},
				CRLPolicyStrict, now,
			)
			if err == nil || !strings.Contains(
				err.Error(),
				"invalid certificate CRL: unsupported critical extension",
			) {
				t.Fatalf("got err %v", err)
			}
		})
	}
}

func TestParseImplicitDERBoolean(t *testing.T) {
	tests := []struct {
		name    string
		value   asn1.RawValue
		want    bool
		wantErr bool
	}{
		{name: "false", value: asn1.RawValue{Bytes: []byte{0x00}}},
		{name: "true", value: asn1.RawValue{Bytes: []byte{0xff}}, want: true},
		{name: "compound", value: asn1.RawValue{IsCompound: true, Bytes: []byte{0xff}}, wantErr: true},
		{name: "wrong length", value: asn1.RawValue{Bytes: []byte{0x00, 0x00}}, wantErr: true},
		{name: "invalid byte", value: asn1.RawValue{Bytes: []byte{0x01}}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseImplicitDERBoolean(tt.value)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected invalid implicit DER boolean error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidateX5ChainCertificateOrder_rejectsNilIntermediate(t *testing.T) {
	leaf, err := x509.ParseCertificate(x509testdata.EndEntityDer)
	if err != nil {
		t.Fatal(err)
	}

	err = validateX5ChainCertificateOrder(X5Chain{
		Leaf:          leaf,
		Intermediates: []*x509.Certificate{nil},
	})
	if err == nil || !strings.Contains(err.Error(), "intermediate[0] is nil") {
		t.Fatalf("got err %v", err)
	}
}

func TestValidateX5ChainCertificateOrder_rejectsInvalidSignature(t *testing.T) {
	leaf, err := x509.ParseCertificate(x509testdata.EndEntityDer)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(x509testdata.RootCA)
	if err != nil {
		t.Fatal(err)
	}

	mutatedLeaf := *leaf
	mutatedLeaf.RawIssuer = append([]byte(nil), root.RawSubject...)
	err = validateX5ChainCertificateOrder(X5Chain{
		Leaf:          &mutatedLeaf,
		Intermediates: []*x509.Certificate{root},
	})
	if err == nil || !strings.Contains(err.Error(), "was not signed by") {
		t.Fatalf("got err %v", err)
	}
}

func TestParseX5Chain_rejectsInvalidInput(t *testing.T) {
	tooMany := make([]interface{}, MaxX5ChainCertificates+1)
	for i := range tooMany {
		tooMany[i] = []byte{0x01}
	}

	tests := []struct {
		name  string
		value any
	}{
		{name: "unsupported type", value: 42},
		{name: "invalid leaf DER", value: []byte{0x30, 0x03}},
		{name: "invalid leaf type", value: []interface{}{"leaf"}},
		{name: "invalid intermediate type", value: []interface{}{x509testdata.EndEntityDer, "intermediate"}},
		{name: "too many interface elements", value: tooMany},
		{name: "invalid intermediate DER", value: [][]byte{x509testdata.EndEntityDer, {0x30, 0x03}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseX5Chain(tt.value); err == nil {
				t.Fatal("expected ParseX5Chain to reject invalid input")
			}
		})
	}
}

func TestSetX5Chain_rejectsOversizedIntermediate(t *testing.T) {
	leaf, err := x509.ParseCertificate(x509testdata.EndEntityDer)
	if err != nil {
		t.Fatal(err)
	}
	intermediates, err := x509.ParseCertificates(certChainBytes())
	if err != nil {
		t.Fatal(err)
	}

	oversized := *intermediates[0]
	oversized.Raw = make([]byte, MaxX5ChainCertDERBytes+1)
	err = SetX5Chain(ProtectedHeader{}, X5Chain{
		Leaf:          leaf,
		Intermediates: []*x509.Certificate{&oversized},
	})
	if err == nil || !strings.Contains(err.Error(), "intermediate[0] exceeds") {
		t.Fatalf("got err %v", err)
	}
}

func TestParseX5Chain_rejectsInvalidArrays(t *testing.T) {
	oversized := make([]byte, MaxX5ChainCertDERBytes+1)
	tests := []struct {
		name  string
		value any
	}{
		{name: "empty interface slice", value: []interface{}{}},
		{name: "empty byte slice", value: [][]byte{}},
		{name: "non-byte element", value: []interface{}{"not bytes"}},
		{name: "oversized byte element", value: [][]byte{oversized}},
		{name: "empty leaf bstr", value: []byte{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseX5Chain(tt.value); err == nil {
				t.Fatal("expected ParseX5Chain to reject invalid input")
			}
		})
	}
}

func TestCRLScopeForCertificate_issuingDistributionPointEdges(t *testing.T) {
	pki := buildTestPKI(t)
	tests := []struct {
		name        string
		cert        *x509.Certificate
		value       []byte
		wantApplies bool
		wantErr     bool
	}{
		{
			name:  "attribute certificates only",
			cert:  pki.leaf,
			value: []byte{0x30, 0x02, 0x85, 0x00},
		},
		{
			name:    "user and CA certificates",
			cert:    pki.leaf,
			value:   []byte{0x30, 0x06, 0x81, 0x01, 0xff, 0x82, 0x01, 0xff},
			wantErr: true,
		},
		{
			name:  "user certificates only with CA",
			cert:  pki.intermediate,
			value: []byte{0x30, 0x03, 0x81, 0x01, 0xff},
		},
		{
			name:        "explicit false",
			cert:        pki.leaf,
			value:       []byte{0x30, 0x03, 0x81, 0x01, 0x00},
			wantApplies: true,
		},
		{
			name:    "invalid boolean",
			cert:    pki.leaf,
			value:   []byte{0x30, 0x03, 0x81, 0x01, 0x01},
			wantErr: true,
		},
		{
			name:    "malformed field",
			cert:    pki.leaf,
			value:   []byte{0x30, 0x03, 0x01, 0x01, 0xff},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			crl := &x509.RevocationList{Extensions: []pkix.Extension{{
				Id:    oidExtensionIssuingDistributionPoint,
				Value: tt.value,
			}}}
			_, applies, err := crlScopeForCertificate(tt.cert, crl)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected invalid issuingDistributionPoint error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if applies != tt.wantApplies {
				t.Fatalf("got applies=%v, want %v", applies, tt.wantApplies)
			}
		})
	}
}

func TestSign1Message_VerifyWithX5Chain_rejectsNilMessage(t *testing.T) {
	var msg *Sign1Message
	if _, err := msg.VerifyWithX5Chain(nil, TrustAnchors{}, nil); err == nil {
		t.Fatal("expected nil message error")
	}
}

func TestSign1Message_VerifyWithX5Chain_rejectsInvalidCertificate(t *testing.T) {
	msg := NewSign1Message()
	msg.Payload = []byte("payload")
	msg.Signature = []byte{1, 2, 3}
	msg.Headers.Protected.SetAlgorithm(AlgorithmES256)
	msg.Headers.Protected[HeaderLabelX5Chain] = []byte{0x30, 0x03}

	if _, err := msg.VerifyWithX5Chain(nil, TrustAnchors{}, nil); err == nil {
		t.Fatal("expected invalid signing certificate error")
	}
}
