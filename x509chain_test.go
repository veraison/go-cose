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

	pool := x509.NewCertPool()
	pool.AddCert(anchor)

	return TrustAnchors{Pool: pool, RevocationMode: RevocationDisabled}, nil
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

func TestParseX5Chain_arrayForm(t *testing.T) {
	chain, err := ParseX5Chain([]interface{}{
		x509testdata.EndEntityDer,
		x509testdata.IntermediateCA,
		x509testdata.RootCA,
	})
	if err != nil {
		t.Fatal(err)
	}
	if chain.Leaf == nil || len(chain.Intermediates) != 2 {
		t.Fatalf("unexpected chain: leaf=%v intermediates=%d", chain.Leaf, len(chain.Intermediates))
	}
}

func TestParseX5Chain_singleLeaf(t *testing.T) {
	// RFC 9360 registered form: bare leaf bstr.
	chain, err := ParseX5Chain(x509testdata.EndEntityDer)
	if err != nil {
		t.Fatal(err)
	}
	if chain.Leaf == nil || len(chain.Intermediates) != 0 {
		t.Fatal("expected leaf only")
	}
}

func TestParseX5Chain_legacyOneElementArray(t *testing.T) {
	chain, err := ParseX5Chain([]interface{}{x509testdata.EndEntityDer})
	if err != nil {
		t.Fatal(err)
	}
	if chain.Leaf == nil || len(chain.Intermediates) != 0 {
		t.Fatal("expected leaf only from []interface{} one-element array")
	}
	if !bytes.Equal(chain.Leaf.Raw, x509testdata.EndEntityDer) {
		t.Fatal("unexpected leaf DER from []interface{} one-element array")
	}

	chain, err = ParseX5Chain([][]byte{x509testdata.EndEntityDer})
	if err != nil {
		t.Fatal(err)
	}
	if chain.Leaf == nil || len(chain.Intermediates) != 0 {
		t.Fatal("expected leaf only from [][]byte one-element array")
	}
	if !bytes.Equal(chain.Leaf.Raw, x509testdata.EndEntityDer) {
		t.Fatal("unexpected leaf DER from [][]byte one-element array")
	}
}

func TestParseX5Chain_emptyLeaf(t *testing.T) {
	_, err := ParseX5Chain([]byte{})
	if err == nil || !strings.Contains(err.Error(), "empty signing cert") {
		t.Fatalf("got err %v", err)
	}
}

func TestParseX5Chain_emptyArray(t *testing.T) {
	_, err := ParseX5Chain([]interface{}{})
	if err == nil || !strings.Contains(err.Error(), "empty certificate array") {
		t.Fatalf("got err %v", err)
	}

	_, err = ParseX5Chain([][]byte{})
	if err == nil || !strings.Contains(err.Error(), "empty certificate array") {
		t.Fatalf("got err %v", err)
	}
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

func TestVerifyParsedX5Chain_ok(t *testing.T) {
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

	anchors, err := trustAnchorsWithoutRevocation(x509testdata.RootCA)
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

	rootPool := x509.NewCertPool()
	rootPool.AddCert(root)
	anchors := TrustAnchors{Pool: rootPool, RevocationMode: RevocationDisabled}

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
		TrustAnchors{Pool: x509.NewCertPool()},
		&X5ChainVerifyOptions{AdditionalIntermediates: additional},
	)
	if err == nil {
		t.Fatal("verification succeeded without a trust anchor")
	}
	if !errors.Is(err, ErrX5ChainNoTrust) {
		t.Fatalf("expected ErrX5ChainNoTrust, got %v", err)
	}
	var unknownAuthority x509.UnknownAuthorityError
	if !errors.As(err, &unknownAuthority) {
		t.Fatalf("expected UnknownAuthorityError, got %v", err)
	}
}

func TestValidateX5ChainCertificateOrder_rejectsOutOfOrderCertificates(t *testing.T) {
	leaf, err := x509.ParseCertificate(x509testdata.EndEntityDer)
	if err != nil {
		t.Fatal(err)
	}
	intermediates, err := x509.ParseCertificates(certChainBytes())
	if err != nil {
		t.Fatal(err)
	}
	err = validateX5ChainCertificateOrder(X5Chain{
		Leaf:          leaf,
		Intermediates: []*x509.Certificate{intermediates[1], intermediates[0]},
	})
	if err == nil || !strings.Contains(err.Error(), "was not issued by") {
		t.Fatalf("got err %v", err)
	}
}

func TestVerifyParsedX5Chain_untrustedAnchor(t *testing.T) {
	leaf, err := x509.ParseCertificate(x509testdata.EndEntityDer)
	if err != nil {
		t.Fatal(err)
	}
	intermediates, err := x509.ParseCertificates(certChainBytes())
	if err != nil {
		t.Fatal(err)
	}

	_, err = verifyParsedX5Chain(
		X5Chain{Leaf: leaf, Intermediates: intermediates},
		TrustAnchors{Pool: x509.NewCertPool()},
		nil,
	)
	if !errors.Is(err, ErrX5ChainNoTrust) {
		t.Fatalf("expected ErrX5ChainNoTrust, got %v", err)
	}
	var unknownAuthority x509.UnknownAuthorityError
	if !errors.As(err, &unknownAuthority) {
		t.Fatalf("expected UnknownAuthorityError, got %v", err)
	}
}

func TestValidateX5ChainLeafSigningCert_rejectsCA(t *testing.T) {
	cert, err := x509.ParseCertificate(x509testdata.RootCA)
	if err != nil {
		t.Fatal(err)
	}

	err = validateLeafSigningCert(cert)
	if err == nil || err.Error() != "x5chain: signing certificate must not be a CA" {
		t.Fatalf("got err %v", err)
	}
}

func TestValidateX5ChainLeafSigningCert_missingDigitalSignature(t *testing.T) {
	cert := &x509.Certificate{
		IsCA:     false,
		KeyUsage: x509.KeyUsageCertSign,
	}

	err := validateLeafSigningCert(cert)
	if err == nil || err.Error() != "x5chain: signing certificate lacks digitalSignature key usage" {
		t.Fatalf("got err %v", err)
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

func TestCheckCertificateRevocation_ignoresUnsupportedExtensionOutsideScope(t *testing.T) {
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
	if err != nil {
		t.Fatalf("out-of-scope CRL must not affect leaf revocation: %v", err)
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

	pool := x509.NewCertPool()
	pool.AddCert(chainCA)
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
					Pool: pool,
					CRLs: crls,
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
					TrustAnchors{Pool: pool, CRLs: crls},
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
		t.Fatalf("unsupported IDP-only CRL set: got err %v", err)
	}

	err = checkCertificateRevocation(
		pki.leaf, pki.intermediate,
		[]*x509.RevocationList{unsupportedIDPCRL, validCRL},
		CRLPolicyStrict, now,
	)
	if err == nil || !strings.Contains(err.Error(), "unsupported issuingDistributionPoint field") {
		t.Fatalf("unsupported IDP must fail closed even with a usable CRL: %v", err)
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

	pool := x509.NewCertPool()
	pool.AddCert(pki.root)
	presented := X5Chain{Leaf: pki.leaf, Intermediates: []*x509.Certificate{pki.intermediate}}

	_, err = verifyParsedX5Chain(presented, TrustAnchors{
		Pool: pool,
		CRLs: nil,
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
				Pool:           pool,
				RevocationMode: tt.mode,
			}, &X5ChainVerifyOptions{CRLPolicy: CRLPolicyPermissive})
			if !errors.Is(err, ErrX5ChainCRLMissing) {
				t.Fatalf("enabled revocation checking without CRLs must fail: %v", err)
			}
		})
	}

	verified, err := verifyParsedX5Chain(presented, TrustAnchors{
		Pool:           pool,
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
		Pool:           pool,
		CRLs:           []*x509.RevocationList{revokingCRL, makeValidCRL(t, pki.root, pki.rootKey)},
		RevocationMode: RevocationDisabled,
	}, nil)
	if err != nil || len(verified) < 2 {
		t.Fatalf("disabled revocation must ignore configured CRLs: chain=%d err=%v", len(verified), err)
	}

	_, err = verifyParsedX5Chain(presented, TrustAnchors{
		Pool: pool,
		CRLs: []*x509.RevocationList{revokingCRL, makeValidCRL(t, pki.root, pki.rootKey)},
	}, nil)
	if !errors.Is(err, ErrX5ChainRevoked) {
		t.Fatalf("matching CRL must revoke leaf: got err %v", err)
	}
}

func TestVerifyParsedX5Chain_currentTime(t *testing.T) {
	pki := buildTestPKI(t)
	pool := x509.NewCertPool()
	pool.AddCert(pki.root)
	presented := X5Chain{Leaf: pki.leaf, Intermediates: []*x509.Certificate{pki.intermediate}}

	verified, err := verifyParsedX5Chain(
		presented,
		TrustAnchors{Pool: pool, RevocationMode: RevocationDisabled},
		&X5ChainVerifyOptions{CurrentTime: time.Now()},
	)
	if err != nil {
		t.Fatalf("valid-at-custom-time: %v", err)
	}
	if len(verified) < 2 || !bytes.Equal(verified[0].Raw, pki.leaf.Raw) {
		t.Fatalf("unexpected verified chain: len=%d", len(verified))
	}

	_, err = verifyParsedX5Chain(
		presented,
		TrustAnchors{Pool: pool, RevocationMode: RevocationDisabled},
		&X5ChainVerifyOptions{CurrentTime: time.Now().Add(24 * time.Hour)},
	)
	if err == nil || !strings.Contains(err.Error(), "has expired or is not yet valid") {
		t.Fatalf("expected leaf expiry via CurrentTime, got %v", err)
	}
	var certInvalid x509.CertificateInvalidError
	if !errors.As(err, &certInvalid) || certInvalid.Reason != x509.Expired {
		t.Fatalf("expected CertificateInvalidError(Expired), got %v", err)
	}
	if errors.Is(err, ErrX5ChainNoTrust) {
		t.Fatalf("expired certificate must not match ErrX5ChainNoTrust: %v", err)
	}

	validCRL := makeValidCRL(t, pki.intermediate, pki.intermediateKey)
	rootCRL := makeValidCRL(t, pki.root, pki.rootKey)
	_, err = verifyParsedX5Chain(
		presented,
		TrustAnchors{Pool: pool, CRLs: []*x509.RevocationList{validCRL, rootCRL}},
		&X5ChainVerifyOptions{CurrentTime: validCRL.NextUpdate.Add(time.Minute)},
	)
	if err == nil || !strings.Contains(err.Error(), "has expired") {
		t.Fatalf("expected CRL expiry via CurrentTime, got %v", err)
	}

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
	_, err = verifyParsedX5Chain(
		presented,
		TrustAnchors{Pool: pool, CRLs: []*x509.RevocationList{futureCRL, rootCRL}},
		&X5ChainVerifyOptions{CurrentTime: time.Now()},
	)
	if err == nil || !strings.Contains(err.Error(), "not yet valid") {
		t.Fatalf("expected CRL not-yet-valid via CurrentTime, got %v", err)
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
		name string
		crl  *x509.RevocationList
	}{
		{
			name: "invalid signature",
			crl:  makeValidCRL(t, wrongIssuer, wrongKey),
		},
		{
			name: "unsupported critical extension",
			crl: makeCRLWithExtensions(t, pki.intermediate, pki.intermediateKey, []pkix.Extension{{
				Id:       oidExtensionDeltaCRLIndicator,
				Critical: true,
				Value:    []byte{0x02, 0x01, 0x01},
			}}),
		},
		{
			name: "malformed scope",
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
			if err == nil || !strings.Contains(err.Error(), "invalid certificate CRL") {
				t.Fatalf("got err %v", err)
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

func TestLoadTrustAnchors_readFileError(t *testing.T) {
	_, err := LoadTrustAnchors(func(string) ([]byte, error) {
		return nil, errors.New("read failed")
	}, []string{"missing.der"}, nil)
	if err == nil || !strings.Contains(err.Error(), "loading trust anchor from missing.der") {
		t.Fatalf("got err %v", err)
	}
}

func TestLoadTrustAnchors_invalidTrustAnchorParse(t *testing.T) {
	_, err := LoadTrustAnchors(func(string) ([]byte, error) {
		return []byte("not-a-cert"), nil
	}, []string{"bad.der"}, nil)
	if err == nil || !strings.Contains(err.Error(), "parsing trust anchor from bad.der") {
		t.Fatalf("got err %v", err)
	}
}

func TestLoadTrustAnchors_emptyPathsUsesEmptyPool(t *testing.T) {
	anchors, err := LoadTrustAnchors(func(string) ([]byte, error) {
		t.Fatal("readFile should not be called when trustAnchorPaths is empty")
		return nil, nil
	}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if anchors.Pool == nil {
		t.Fatal("expected non-nil empty pool")
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

func TestVerifyParsedX5Chain_prefersCustomRootsWhenSystemFallbackEnabled(t *testing.T) {
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
		t.Fatalf("custom roots must be tried before system fallback: %v", err)
	}
	if len(verified) == 0 || !bytes.Equal(verified[0].Raw, leaf.Raw) {
		t.Fatal("unexpected verified chain")
	}
}

func TestVerifyPKIXChains_systemRootsAreFallbackOnly(t *testing.T) {
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
	_, err = verifyPKIXChainsWithSystemPoolLoader(chain, TrustAnchors{
		Pool:           customPool,
		UseSystemRoots: true,
	}, nil, time.Now(), func() (*x509.CertPool, error) {
		systemLoadCalled = true
		return nil, errors.New("system roots must not be loaded")
	})
	if err != nil {
		t.Fatalf("custom-root verification failed: %v", err)
	}
	if systemLoadCalled {
		t.Fatal("system roots were loaded despite successful custom-root verification")
	}

	systemLoadCalled = false
	_, err = verifyPKIXChainsWithSystemPoolLoader(chain, TrustAnchors{
		Pool:           x509.NewCertPool(),
		UseSystemRoots: true,
	}, nil, time.Now(), func() (*x509.CertPool, error) {
		systemLoadCalled = true
		return customPool, nil
	})
	if err != nil {
		t.Fatalf("system-root fallback verification failed: %v", err)
	}
	if !systemLoadCalled {
		t.Fatal("system roots were not loaded after custom-root verification failed")
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

func TestSign1Message_VerifyWithX5Chain_okWithCRLs(t *testing.T) {
	pki := buildTestPKI(t)
	msg := signSign1WithX5Chain(t, pki.leafDER, pki.intermediateDER, pki.leafKey)

	pool := x509.NewCertPool()
	pool.AddCert(pki.root)
	verifiedChain, err := msg.VerifyWithX5Chain([]byte{}, TrustAnchors{
		Pool: pool,
		CRLs: makeValidChainCRLs(t, &pki),
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
	roots := x509.NewCertPool()
	roots.AddCert(root)

	verifiedChain, err := msg.VerifyWithX5Chain([]byte{}, TrustAnchors{Pool: roots}, nil)
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

func TestSign1Message_VerifyWithX5Chain_usesProtectedHeader(t *testing.T) {
	key := parseEndEntityKey(t)
	msg := signSign1WithX5Chain(t, x509testdata.EndEntityDer, certChainBytes(), key)
	msg.Headers.Unprotected[HeaderLabelX5Chain] = []byte("not a certificate")

	anchors, err := trustAnchorsWithoutRevocation(x509testdata.RootCA)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := msg.VerifyWithX5Chain([]byte{}, anchors, nil); err != nil {
		t.Fatalf("protected x5chain must be used: %v", err)
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

func TestSetX5Chain_roundTripMultiCert(t *testing.T) {
	leaf, err := x509.ParseCertificate(x509testdata.EndEntityDer)
	if err != nil {
		t.Fatal(err)
	}
	intermediates, err := x509.ParseCertificates(certChainBytes())
	if err != nil {
		t.Fatal(err)
	}

	h := ProtectedHeader{}
	if err := SetX5Chain(h, X5Chain{Leaf: leaf, Intermediates: intermediates}); err != nil {
		t.Fatal(err)
	}

	parsed, err := ParseX5Chain(h[HeaderLabelX5Chain])
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Leaf == nil || len(parsed.Intermediates) != 2 {
		t.Fatalf("unexpected parsed chain")
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

func TestProtectedHeader_x5chainInvalidType(t *testing.T) {
	h := ProtectedHeader{
		HeaderLabelAlgorithm: AlgorithmES256,
		HeaderLabelX5Chain:   "not-a-cert-chain",
	}
	_, err := h.MarshalCBOR()
	if err == nil || !strings.Contains(err.Error(), "header parameter: x5chain") {
		t.Fatalf("got err %v", err)
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
	err = h.UnmarshalCBOR(data)
	if err == nil || !strings.Contains(err.Error(), "header parameter: x5chain") {
		t.Fatalf("got err %v", err)
	}
}

func TestValidateX5ChainHeaderValue_rejectsEmptyBstr(t *testing.T) {
	if err := validateX5ChainHeaderValue([]byte{}); err == nil || !strings.Contains(err.Error(), "require non-empty bstr") {
		t.Fatalf("bare bstr: got err %v", err)
	}

	if err := validateX5ChainHeaderValue([]interface{}{[]byte{}}); err == nil || !strings.Contains(err.Error(), "element 0: require non-empty bstr") {
		t.Fatalf("array bstr: got err %v", err)
	}

	if err := validateX5ChainHeaderValue([][]byte{{}}); err == nil || !strings.Contains(err.Error(), "element 0: require non-empty bstr") {
		t.Fatalf("[][]byte: got err %v", err)
	}
}

func TestX5ChainHeaderMarshal_rejectsLegacyOneCertificateArray(t *testing.T) {
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
			if _, err := protected.MarshalCBOR(); err == nil || !strings.Contains(err.Error(), "single certificate must use bstr") {
				t.Fatalf("ProtectedHeader.MarshalCBOR() error = %v", err)
			}
		})
	}
}

func TestX5ChainHeaderMarshal_rejectsOutOfOrderCertificates(t *testing.T) {
	value := [][]byte{
		x509testdata.EndEntityDer,
		x509testdata.RootCA,
		x509testdata.IntermediateCA,
	}

	protected := ProtectedHeader{HeaderLabelX5Chain: value}
	if _, err := protected.MarshalCBOR(); err == nil || !strings.Contains(err.Error(), "was not issued by") {
		t.Fatalf("ProtectedHeader.MarshalCBOR() error = %v", err)
	}

	if _, err := ParseX5Chain(value); err == nil || !strings.Contains(err.Error(), "was not issued by") {
		t.Fatalf("ParseX5Chain() error = %v", err)
	}
}

func TestValidateX5ChainHeaderValue_rejectsOversize(t *testing.T) {
	oversized := make([]byte, MaxX5ChainCertDERBytes+1)
	oversized[0] = 0x30
	if err := validateX5ChainHeaderValue(oversized); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("bare bstr size: got err %v", err)
	}

	if err := validateX5ChainHeaderValue([]interface{}{oversized}); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("array element size: got err %v", err)
	}

	tooMany := make([]interface{}, MaxX5ChainCertificates+1)
	for i := range tooMany {
		tooMany[i] = []byte{0x30, 0x00}
	}
	if err := validateX5ChainHeaderValue(tooMany); err == nil || !strings.Contains(err.Error(), "too many certificates") {
		t.Fatalf("array count: got err %v", err)
	}

	tooManyBytes := make([][]byte, MaxX5ChainCertificates+1)
	for i := range tooManyBytes {
		tooManyBytes[i] = []byte{0x30, 0x00}
	}
	if err := validateX5ChainHeaderValue(tooManyBytes); err == nil || !strings.Contains(err.Error(), "too many certificates") {
		t.Fatalf("[][]byte count: got err %v", err)
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

func TestLoadTrustAnchors_pemCRLTrailingComment(t *testing.T) {
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
		[]byte("# EOF\n")...,
	)

	anchors, err := LoadTrustAnchors(func(path string) ([]byte, error) {
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
	if err != nil {
		t.Fatal(err)
	}
	if len(anchors.CRLs) != 1 {
		t.Fatalf("expected 1 CRL, got %d", len(anchors.CRLs))
	}
}

func TestLoadTrustAnchors_pemCRLLeadingCertificateBlock(t *testing.T) {
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
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: x509testdata.RootCA}),
		pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDER})...,
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
	if err == nil || !strings.Contains(err.Error(), `invalid PEM block type "CERTIFICATE"`) {
		t.Fatalf("got err %v", err)
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
	pool := x509.NewCertPool()
	pool.AddCert(pki.root)

	_, err = msg.VerifyWithX5Chain([]byte{}, TrustAnchors{
		Pool: pool,
		CRLs: []*x509.RevocationList{crl, makeValidCRL(t, pki.root, pki.rootKey)},
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

func TestCheckCRLValidity_missingNextUpdate(t *testing.T) {
	err := checkCRLValidity(&x509.RevocationList{
		ThisUpdate: time.Now().Add(-time.Hour),
	}, time.Now())
	if err == nil || !strings.Contains(err.Error(), "no NextUpdate") {
		t.Fatalf("got err %v", err)
	}
}

func TestCheckCRLValidity_missingThisUpdate(t *testing.T) {
	err := checkCRLValidity(&x509.RevocationList{
		NextUpdate: time.Now().Add(time.Hour),
	}, time.Now())
	if err == nil || !strings.Contains(err.Error(), "no ThisUpdate") {
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

func TestIsSerialRevoked_nilSerialNoPanic(t *testing.T) {
	now := time.Now()
	crl := &x509.RevocationList{
		RevokedCertificateEntries: []x509.RevocationListEntry{
			{SerialNumber: big.NewInt(1), RevocationTime: now.Add(-time.Minute)},
		},
	}
	if isSerialRevoked(nil, crl, now) {
		t.Fatal("nil serial should not match")
	}
	if !isSerialRevoked(big.NewInt(1), &x509.RevocationList{
		RevokedCertificateEntries: []x509.RevocationListEntry{
			{SerialNumber: nil},
			{SerialNumber: big.NewInt(1), RevocationTime: now},
		},
	}, now) {
		t.Fatal("expected match via non-nil entry")
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
			if got := isSerialRevoked(serial, crl, now); got != tt.want {
				t.Fatalf("isSerialRevoked() = %v, want %v", got, tt.want)
			}
		})
	}
}
