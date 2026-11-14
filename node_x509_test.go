package pca

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// NodeCert is exercised end to end by the sigstore module's oracle; this pins each accessor here so the root package's own
// mutation run sees them.
func TestNodeCert(t *testing.T) {
	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	to := from.Add(time.Hour)
	mk := func(cn string, ca bool, parent *x509.Certificate, pk, signer *ecdsa.PrivateKey) []byte {
		tpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: cn}, NotBefore: from, NotAfter: to,
			BasicConstraintsValid: true, IsCA: ca, KeyUsage: x509.KeyUsageDigitalSignature}
		if ca {
			tpl.KeyUsage |= x509.KeyUsageCertSign
		}
		if parent == nil {
			parent = tpl
		}
		der, err := x509.CreateCertificate(rand.Reader, tpl, parent, &pk.PublicKey, signer)
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	rk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	lk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootDer := mk("root", true, nil, rk, rk)
	rootX, _ := x509.ParseCertificate(rootDer)
	leafDer := mk("leaf", false, rootX, lk, rk)
	root, err := ParseNodeCert(rootDer)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := ParseNodeCert(leafDer)
	if err != nil {
		t.Fatal(err)
	}
	// a Name value under a tag OpenSSL reads as B_ASN1_UNKNOWN (13, RELATIVE-OID) still parses; a UTCTime does not
	at := bytes.Index(leafDer, []byte{0x13, 4, 'l', 'e', 'a', 'f'})
	if at < 0 {
		t.Fatal("no PrintableString CN in the leaf")
	}
	for tag, ok := range map[byte]bool{0x0d: true, 0x17: false} {
		mut := append([]byte{}, leafDer...)
		mut[at] = tag
		if _, err := ParseNodeCert(mut); (err == nil) != ok {
			t.Errorf("name value tag %#x: err=%v", tag, err)
		}
	}
	if c, err := ParseNodeCert([]byte{0x30, 0x00}); err == nil || c != nil {
		t.Fatal("an empty SEQUENCE is not a certificate")
	}
	if !bytes.Equal(leaf.Issuer(), root.Subject()) || bytes.Equal(leaf.Subject(), root.Subject()) || !bytes.Equal(root.Issuer(), root.Subject()) {
		t.Fatal("names")
	}
	if spki, _ := x509.MarshalPKIXPublicKey(&lk.PublicKey); !bytes.Equal(leaf.SPKI(), spki) {
		t.Fatal("spki differs")
	}
	if k, err := leaf.PublicKey(); err != nil || !k.(*ecdsa.PublicKey).Equal(&lk.PublicKey) {
		t.Fatal("public key", err)
	}
	if !root.CA() || leaf.CA() {
		t.Fatal("ca")
	}
	if !leaf.SignedBy(root) || !root.SignedBy(root) || leaf.SignedBy(leaf) {
		t.Fatal("signatures")
	}
	f, e := from.UnixMilli(), to.UnixMilli()
	for at, want := range map[int64]bool{f - 1: false, f: true, e: true, e + 1: false} {
		if leaf.ValidAt(at) != want {
			t.Errorf("ValidAt(%d) != %v", at, want)
		}
	}
}
