package pca

// NVIDIA CRL coverage default (0.5): every non-root chain certificate that names a cRLDistributionPoints extension must be covered
// by a verified CRL from its own issuer; before, any one fresh CRL satisfied the check.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"testing"
	"time"
)

type r11Rig struct {
	rootK, icaK, leafK *ecdsa.PrivateKey
	root, ica, leaf    *x509.Certificate
	chain              []*attCert
}

// r11NewRig builds leaf <- ica <- root; cdp says which of leaf and ica carry a CRL distribution point.
func r11NewRig(t *testing.T, leafCDP, icaCDP bool) *r11Rig {
	t.Helper()
	gen := func() *ecdsa.PrivateKey {
		k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	r := &r11Rig{rootK: gen(), icaK: gen(), leafK: gen()}
	nb, na := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC)
	mk := func(tmpl, parent *x509.Certificate, pub *ecdsa.PublicKey, signer *ecdsa.PrivateKey) *x509.Certificate {
		tmpl.NotBefore, tmpl.NotAfter = nb, na
		if parent == nil {
			parent = tmpl
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
		if err != nil {
			t.Fatal(err)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	var cdp = func(on bool) []string {
		if on {
			return []string{"http://crl.example/ca.crl"}
		}
		return nil
	}
	ku := x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	r.root = mk(&x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "r11 root"}, BasicConstraintsValid: true, IsCA: true, KeyUsage: ku, SubjectKeyId: []byte{1}}, nil, &r.rootK.PublicKey, r.rootK)
	r.ica = mk(&x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "r11 ica"}, BasicConstraintsValid: true, IsCA: true, KeyUsage: ku, SubjectKeyId: []byte{2}, CRLDistributionPoints: cdp(icaCDP)}, r.root, &r.icaK.PublicKey, r.rootK)
	r.leaf = mk(&x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "r11 leaf"}, KeyUsage: x509.KeyUsageDigitalSignature, SubjectKeyId: []byte{3}, CRLDistributionPoints: cdp(leafCDP)}, r.ica, &r.leafK.PublicKey, r.icaK)
	for _, c := range []*x509.Certificate{r.leaf, r.ica, r.root} {
		a, err := parseCertDER(c.Raw)
		if err != nil {
			t.Fatal(err)
		}
		r.chain = append(r.chain, a)
	}
	return r
}

func (r *r11Rig) crl(t *testing.T, issuer *x509.Certificate, key *ecdsa.PrivateKey, revoked ...*big.Int) []byte {
	t.Helper()
	tmpl := &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), NextUpdate: time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC), SignatureAlgorithm: x509.ECDSAWithSHA256}
	for _, s := range revoked {
		tmpl.RevokedCertificateEntries = append(tmpl.RevokedCertificateEntries, x509.RevocationListEntry{SerialNumber: s, RevocationTime: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)})
	}
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, issuer, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestR11_CrlCoverage(t *testing.T) {
	r := r11NewRig(t, true, true)
	rootCrl, icaCrl := r.crl(t, r.root, r.rootK), r.crl(t, r.ica, r.icaK)
	leafMissing := "no verified CRL from the issuer of chain certificate '" + subjectLine(r.chain[0]) + "'"
	icaMissing := "no verified CRL from the issuer of chain certificate '" + subjectLine(r.chain[1]) + "'"
	check := func(crls [][]byte, rf ...any) string {
		return checkNvidiaChainRevocation(r.chain, crls, g12Now, nil, rf...)
	}
	// 1: only the root's CRL, both certificates name a CDP: the leaf has no CRL from its issuer (the ica)
	if got := check([][]byte{rootCrl}); got != leafMissing {
		t.Errorf("root CRL only: %q", got)
	}
	// the default is "cdp"
	if got := check([][]byte{rootCrl}, "cdp"); got != leafMissing {
		t.Errorf("explicit cdp: %q", got)
	}
	// 2: the ica's CRL (covers the leaf) plus the root's (covers the ica)
	if got := check([][]byte{icaCrl, rootCrl}); got != "" {
		t.Errorf("both CRLs: %q", got)
	}
	// the ica's CRL alone leaves the ica uncovered
	if got := check([][]byte{icaCrl}); got != icaMissing {
		t.Errorf("ica CRL only: %q", got)
	}
	// 3: a revoked leaf on the ica's CRL is still refused as revoked
	if got := check([][]byte{r.crl(t, r.ica, r.icaK, r.leaf.SerialNumber), rootCrl}); got != "chain certificate '"+subjectLine(r.chain[0])+"' is revoked" {
		t.Errorf("revoked leaf: %q", got)
	}
	// 6: CRLs supplied but not required: supplied ones are enforced, no coverage demand
	if got := check([][]byte{rootCrl}, "none"); got != "" {
		t.Errorf("none: %q", got)
	}
	// 5: an index outside 0 .. last-1 (the root is index 2)
	for _, i := range []int{-1, 2, 3} {
		want := "requireCrlFor index " + itoaR5N0(i) + " is not a non-root chain certificate"
		if i < 0 {
			want = "requireCrlFor index -1 is not a non-root chain certificate"
		}
		if got := check([][]byte{icaCrl, rootCrl}, []int{i}); got != want {
			t.Errorf("index %d: %q, want %q", i, got, want)
		}
	}
	// an explicit list demands exactly those indices
	if got := check([][]byte{rootCrl}, []int{1}); got != "" {
		t.Errorf("list [1] with the root CRL: %q", got)
	}
	if got := check([][]byte{rootCrl}, []int{0}); got != leafMissing {
		t.Errorf("list [0]: %q", got)
	}
	if got := check([][]byte{rootCrl}, []int{}); got != "" {
		t.Errorf("empty list: %q", got)
	}
}

func TestR11_CrlCoverageAllVersusCdp(t *testing.T) {
	// 4: the leaf names no CDP and has no CRL from its issuer: "cdp" passes, "all" fails
	r := r11NewRig(t, false, true)
	rootCrl := r.crl(t, r.root, r.rootK)
	if got := checkNvidiaChainRevocation(r.chain, [][]byte{rootCrl}, g12Now, nil); got != "" {
		t.Errorf("cdp, leaf without a CDP: %q", got)
	}
	want := "no verified CRL from the issuer of chain certificate '" + subjectLine(r.chain[0]) + "'"
	if got := checkNvidiaChainRevocation(r.chain, [][]byte{rootCrl}, g12Now, nil, "all"); got != want {
		t.Errorf("all: %q", got)
	}
	// no CDP anywhere: nothing is demanded beyond the existing checks
	n := r11NewRig(t, false, false)
	if got := checkNvidiaChainRevocation(n.chain, [][]byte{n.crl(t, n.root, n.rootK)}, g12Now, nil); got != "" {
		t.Errorf("no CDP anywhere: %q", got)
	}
}

func TestR11_CrlDistributionPointScan(t *testing.T) {
	r := r11NewRig(t, true, false)
	if !hasCrlDistributionPoint(r.chain[0]) || hasCrlDistributionPoint(r.chain[1]) || hasCrlDistributionPoint(r.chain[2]) {
		t.Errorf("leaf/ica/root: %v %v %v", hasCrlDistributionPoint(r.chain[0]), hasCrlDistributionPoint(r.chain[1]), hasCrlDistributionPoint(r.chain[2]))
	}
}

// The option is validated when the hook is built.
func TestR11_RequireCrlForOption(t *testing.T) {
	pins := []any{"0000000000000000000000000000000000000000000000000000000000000000"}
	build := func(v any, has bool) (*nvidiaHook, error) {
		col := map[string]any{"rimRootSpkiSha256": pins}
		if has {
			col["requireCrlFor"] = v
		}
		return newNvidiaHook(col)
	}
	for name, c := range map[string]struct {
		v    any
		has  bool
		want any
	}{
		"absent": {nil, false, "cdp"}, "null": {nil, true, "cdp"}, "cdp": {"cdp", true, "cdp"}, "all": {"all", true, "all"},
	} {
		h, err := build(c.v, c.has)
		if err != nil || h.requireCrlFor != c.want {
			t.Errorf("%s: %v %v", name, h, err)
		}
	}
	h, err := build([]any{jnum(0), jnum(1)}, true)
	if got, ok := h.requireCrlFor.([]int); err != nil || !ok || len(got) != 2 || got[0] != 0 || got[1] != 1 {
		t.Errorf("list: %+v %v", h, err)
	}
	for name, v := range map[string]any{
		"unknown word": "some", "none is not an option": "none", "number": jnum(1), "negative": []any{jnum(-1)}, "fraction": []any{json.Number("1.5")},
		"string element": []any{"0"}, "bool": true, "object": map[string]any{},
	} {
		if _, err := build(v, true); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
