package pca

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// TS attest-intel-tdx.ts: each cert's issuer DN equals the next cert's subject DN, checked before the signature.
func TestK05X2bPckLinkNameCheckedFirst(t *testing.T) {
	child := &attCert{RawIssuer: []byte("a")}
	parent := &attCert{RawSubject: []byte("b")}
	want := "certificate at depth 0 issuer does not match its parent subject"
	if got := pckLinkFailure([]*attCert{child, parent}); got != want {
		t.Fatalf("got %q", got)
	}
	if got := pckLinkFailure([]*attCert{child}); got != "" {
		t.Fatalf("one certificate has no link: %q", got)
	}
}

// TS attest-intel-tdx.ts refuses a chain result that is not ok, or that lacks the leaf or its key.
func TestK05X2bTdxChainResultGuard(t *testing.T) {
	f := g08NewTdx(t)
	q := f.quote(t, nil)
	defer func() { pckChainVerify = verifyIntelPckChain }()
	key := &ecdsa.PublicKey{}
	leaf := &attCert{}
	for name, res := range map[string]pckChainResult{
		"not ok":  {reason: "r", leaf: leaf, leafKey: key},
		"no key":  {ok: true, reason: "r", leaf: leaf},
		"no leaf": {ok: true, reason: "r", leafKey: key},
	} {
		res := res
		pckChainVerify = func(string, string, int64) pckChainResult { return res }
		if r := verifyGenuineTdxQuote(q, f.pin, g08now, nil, false); r.ok || r.reason != "PCK chain invalid: r" {
			t.Fatalf("%s: %+v", name, r)
		}
	}
}

// The device key must be EC: a key that cannot be read and a non-EC key are refused, never handed to the verifier.
func TestK05X2bNvidiaReportNeedsAnEcKey(t *testing.T) {
	if nvidiaReportSigned(&attCert{}, []byte("m"), []byte("s!")) {
		t.Fatal("unreadable key accepted")
	}
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "x2b"}, NotBefore: time.Unix(0, 0), NotAfter: time.Unix(1<<31, 0)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, err := certFromPEM(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})))
	if err != nil {
		t.Fatal(err)
	}
	if nvidiaReportSigned(c, []byte("m"), []byte("s!")) {
		t.Fatal("non-EC key accepted")
	}
}
