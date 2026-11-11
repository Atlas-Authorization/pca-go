package pca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"math/big"
	"strings"
	"testing"
	"time"
)

// The strict chain profile (x509-strict.ts:266) at its sites: attest-azure-maa.ts:395,411, attest-gcp-confidential-space.ts:384,
// attest-nvidia-spdm.ts:224. Go has no attest-maa-keys.ts equivalent.

func scLeaf(c *x509.Certificate) {
	c.IsCA, c.KeyUsage = false, x509.KeyUsageDigitalSignature
}

func scCert(t *testing.T, cn string, key *ecdsa.PrivateKey, parent *x509.Certificate, signer *ecdsa.PrivateKey, muts ...func(*x509.Certificate)) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(11), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC),
		BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign}
	for _, m := range muts {
		m(tmpl)
	}
	if parent == nil {
		parent = tmpl
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// scChain builds leaf <- intermediate <- root over P-384, applying a mutation per position.
func scChain(t *testing.T, leaf, inter, root func(*x509.Certificate)) (l, i, r *x509.Certificate) {
	t.Helper()
	key := func() *ecdsa.PrivateKey {
		k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	nop := func(*x509.Certificate) {}
	if leaf == nil {
		leaf = nop
	}
	if inter == nil {
		inter = nop
	}
	if root == nil {
		root = nop
	}
	kr, ki, kl := key(), key(), key()
	r = scCert(t, "root", kr, nil, kr, root)
	i = scCert(t, "inter", ki, r, kr, inter)
	l = scCert(t, "leaf", kl, i, ki, scLeaf, leaf)
	return l, i, r
}

func scExt(oid asn1.ObjectIdentifier, critical bool, value []byte) func(*x509.Certificate) {
	return func(c *x509.Certificate) {
		c.ExtraExtensions = []pkix.Extension{{Id: oid, Critical: critical, Value: value}}
	}
}

var (
	scUnknownCritical = scExt(asn1.ObjectIdentifier{1, 2, 3, 4}, true, []byte{0x05, 0x00})
	scUnknownPlain    = scExt(asn1.ObjectIdentifier{1, 2, 3, 4}, false, []byte{0x05, 0x00})
	// id-ce-extKeyUsage, critical, serverAuth
	scEkuCritical = scExt(asn1.ObjectIdentifier{2, 5, 29, 37}, true, []byte{0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01})
)

type scRow struct {
	name              string
	leaf, inter, root func(*x509.Certificate)
	want              string // strictChainError; "" = fine
	early             string // the NVIDIA link loop refuses a non-CA issuer first
}

func scRows() []scRow {
	const notCA = "device chain cert #1 issues a certificate but is not a CA"
	return []scRow{
		{name: "control"},
		{name: "critical EKU on the leaf", leaf: scEkuCritical},
		{name: "critical EKU on the intermediate", inter: scEkuCritical},
		{name: "non-critical unknown extension", leaf: scUnknownPlain, inter: scUnknownPlain},
		{name: "leaf CA:TRUE", leaf: func(c *x509.Certificate) { c.IsCA = true },
			want: "leaf certificate asserts BasicConstraints CA:TRUE (an end-entity must not be a CA)"},
		{name: "issuer CA:FALSE", inter: func(c *x509.Certificate) { c.IsCA = false },
			want: "issuer certificate at depth 1 is not a CA (BasicConstraints CA:FALSE)", early: notCA},
		{name: "issuer without BasicConstraints", inter: func(c *x509.Certificate) { c.IsCA, c.BasicConstraintsValid = false, false },
			want: "issuer certificate at depth 1 has no BasicConstraints (not a CA)", early: notCA},
		{name: "issuer keyUsage without keyCertSign", inter: func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageDigitalSignature },
			want: "issuer certificate at depth 1 keyUsage lacks keyCertSign", early: notCA},
		{name: "pathLen exceeded", root: func(c *x509.Certificate) { c.MaxPathLen, c.MaxPathLenZero = 0, true },
			want: "issuer certificate at depth 2 pathLenConstraint 0 is exceeded (1 intermediate(s) below)"},
		{name: "critical 1.2.3.4 on the leaf", leaf: scUnknownCritical,
			want: "certificate at depth 0 has an unrecognised critical extension 1.2.3.4"},
		{name: "critical 1.2.3.4 on the intermediate", inter: scUnknownCritical,
			want: "certificate at depth 1 has an unrecognised critical extension 1.2.3.4"},
		{name: "critical 1.2.3.4 on the root", root: scUnknownCritical,
			want: "certificate at depth 2 has an unrecognised critical extension 1.2.3.4"},
	}
}

func scAtt(t *testing.T, cs ...*x509.Certificate) []*attCert {
	t.Helper()
	out := make([]*attCert, len(cs))
	for i, c := range cs {
		a, err := parseCertDER(c.Raw)
		if err != nil {
			t.Fatal(err)
		}
		out[i] = a
	}
	return out
}

func TestStrictChainError(t *testing.T) {
	for _, r := range scRows() {
		l, i, root := scChain(t, r.leaf, r.inter, r.root)
		if got := strictChainError(scAtt(t, l, i, root)); got != r.want {
			t.Errorf("%s: %q, want %q", r.name, got, r.want)
		}
	}
	if got := strictChainError([]*attCert{{Raw: []byte{0x30, 0x03, 1, 2, 3}}}); !strings.HasPrefix(got, "certificate extension parse failed: ") {
		t.Errorf("unreadable DER: %q", got)
	}
	// a lone certificate has no roles to check, its critical extensions still count
	_, _, lone := scChain(t, nil, nil, scUnknownCritical)
	if got := strictChainError(scAtt(t, lone)); got != "certificate at depth 0 has an unrecognised critical extension 1.2.3.4" {
		t.Errorf("lone: %q", got)
	}
}

func TestStrictChainAtMaaGcpNvidia(t *testing.T) {
	for _, r := range scRows() {
		l, i, root := scChain(t, r.leaf, r.inter, r.root)
		x5c := []any{g03b64(l.Raw), g03b64(i.Raw), g03b64(root.Raw)}
		pin := g10nvPin(root)
		want := func(prefix string) string {
			if r.want == "" {
				return ""
			}
			return prefix + r.want
		}
		// MAA, the anchor inside the chain
		leaf, why := maaAnchors{rootSpki: []string{pin}}.verifyX5cChain(x5c, tokNow, 0)
		if why != want("x5c chain profile: ") || (why == "") != (leaf != nil) {
			t.Errorf("MAA in-chain anchor, %s: %q", r.name, why)
		}
		// GCP
		v := &gcpVerifier{spkiPins: map[string]bool{pin: true}}
		if why := v.verifyJwkX5cChain(x5c, tokNow); why != want("x5c chain profile: ") {
			t.Errorf("GCP, %s: %q", r.name, why)
		}
		// NVIDIA (and the RIM signer chain, which goes through the same function)
		nv := want("device chain profile: ")
		if r.early != "" {
			nv = r.early
		}
		if c, why := verifyNvidiaDeviceChain(g10nvPEM(l, i, root), []string{pin}, tokNow); why != nv || (why == "") != (c != nil) {
			t.Errorf("NVIDIA, %s: %q, want %q", r.name, why, nv)
		}
	}
}

func TestStrictChainMaaSlicesAndOrder(t *testing.T) {
	// anchored at the intermediate: only leaf and intermediate are profiled, the certificate above is not read (azure:395)
	l, i, root := scChain(t, nil, nil, func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageDigitalSignature })
	x5c := []any{g03b64(l.Raw), g03b64(i.Raw), g03b64(root.Raw)}
	if c, why := (maaAnchors{rootSpki: []string{g10nvPin(i)}}).verifyX5cChain(x5c, tokNow, 0); c == nil || why != "" {
		t.Errorf("anchor at the intermediate: %q", why)
	}
	if _, why := (maaAnchors{rootSpki: []string{g10nvPin(root)}}).verifyX5cChain(x5c, tokNow, 0); why != "x5c chain profile: issuer certificate at depth 2 keyUsage lacks keyCertSign" {
		t.Errorf("anchor at the root: %q", why)
	}
	// anchored at the leaf: the slice is the leaf alone, whatever is above
	l, i, root = scChain(t, nil, func(c *x509.Certificate) { c.IsCA = false }, nil)
	if c, why := (maaAnchors{rootSpki: []string{g10nvPin(l)}}).verifyX5cChain([]any{g03b64(l.Raw), g03b64(i.Raw)}, tokNow, 0); c == nil || why != "" {
		t.Errorf("anchor at the leaf: %q", why)
	}
	// no anchor inside the chain: the whole x5c is profiled after the root check (azure:411)
	byRoot := maaAnchors{rootCertsPem: []string{g03pem(root.Raw)}}
	chain := []any{g03b64(l.Raw), g03b64(i.Raw)}
	if _, why := byRoot.verifyX5cChain(chain, tokNow, 0); why != "x5c chain profile: issuer certificate at depth 1 is not a CA (BasicConstraints CA:FALSE)" {
		t.Errorf("external root: %q", why)
	}
	lo, io, _ := scChain(t, nil, nil, nil)
	if c, why := byRoot.verifyX5cChain([]any{g03b64(lo.Raw), g03b64(io.Raw)}, tokNow, 0); c != nil || why != "x5c chain does not anchor in a configured MAA trust root" {
		t.Errorf("not anchored: %q", why)
	}
	// GCP profiles before the anchor lookup; NVIDIA before the pin
	if why := (&gcpVerifier{spkiPins: map[string]bool{}}).verifyJwkX5cChain(chain, tokNow); !strings.HasPrefix(why, "x5c chain profile: ") {
		t.Errorf("GCP order: %q", why)
	}
	l2, i2, r2 := scChain(t, scUnknownCritical, nil, nil)
	if _, why := verifyNvidiaDeviceChain(g10nvPEM(l2, i2, r2), []string{"00"}, tokNow); !strings.HasPrefix(why, "device chain profile: ") {
		t.Errorf("NVIDIA order: %q", why)
	}
}

// attest-nvidia-rim.ts `!fw`: an empty object IS a policy, an unparseable reported version is refused.
func TestEmptyFirmwarePolicyIsAPolicy(t *testing.T) {
	p, err := compileFirmwarePolicy(map[string]any{})
	if err != nil || p == nil {
		t.Fatalf("{}: %v %v", p, err)
	}
	if got := p.check(&nvidiaRimIDs{driverVersion: "x", vbiosVersion: "1"}); got != "driver version 'x' in the GPU report is not parseable" {
		t.Errorf("unparseable driver: %q", got)
	}
}

// packages/pca-grants/src/lease.ts:219,231-235,245.
func TestLeaseMaxTtlCeiling(t *testing.T) {
	k := newKey(t)
	ceil := func(n int64) *int64 { return &n }
	lease := func(id string, maxTTL int64) map[string]any {
		l := g04Lease()
		l["lease_id"], l["max_ttl"] = id, jnum(maxTTL)
		return g04SignLease(t, k, l)
	}
	for _, c := range []struct {
		name    string
		ceiling *int64
		maxTTL  int64
		want    string
	}{
		{"below", ceil(1000), 999, ""}, {"at", ceil(1000), 1000, ""}, {"above", ceil(1000), 1001, "ttl_ceiling"}, {"absent", nil, 1 << 40, ""},
	} {
		r := NewLeaseRegistry(LeasePolicy{Authorities: []string{k.id}, MaxTtlCeiling: c.ceiling}, MemoryLeaseKv()).Accept(lease("L1", c.maxTTL), nil)
		if r.Code != c.want || r.Ok != (c.want == "") {
			t.Errorf("%s: %+v, want %q", c.name, r, c.want)
		}
	}
	// after over_max_ttl: a record over both reports over_max_ttl
	over := g04Lease()
	over["max_ttl"], over["expires_at"] = jnum(50), jnum(500)
	if r := NewLeaseRegistry(LeasePolicy{Authorities: []string{k.id}, MaxTtlCeiling: ceil(10)}, MemoryLeaseKv()).Accept(g04SignLease(t, k, over), nil); r.Code != "over_max_ttl" {
		t.Errorf("order: %+v", r)
	}
	for _, bad := range []int64{0, -1, maxSafeInt + 1} {
		func() {
			defer func() {
				if x := recover(); x != "LeaseRegistry: maxTtlCeiling must be a positive integer" {
					t.Errorf("ceiling %d: %v", bad, x)
				}
			}()
			NewLeaseRegistry(LeasePolicy{MaxTtlCeiling: ceil(bad)}, MemoryLeaseKv())
		}()
	}
	for _, good := range []int64{1, maxSafeInt} {
		if NewLeaseRegistry(LeasePolicy{MaxTtlCeiling: ceil(good)}, MemoryLeaseKv()) == nil {
			t.Errorf("ceiling %d", good)
		}
	}

	// pruning: kept while revoked_at + ceiling >= now, on an accepted record and on a revocation
	rev := func(value string, at int64) map[string]any {
		return g04SignRev(t, k, map[string]any{"v": jnum(1), "target": "lease", "value": value, "revoked_at": jnum(at)})
	}
	reg := NewLeaseRegistryShards(LeasePolicy{Authorities: []string{k.id}, MaxTtlCeiling: ceil(1000)}, MemoryLeaseKv(), 1)
	now := int64(1500)
	reg.clock = func() int64 { return now }
	if code, _ := reg.Revoke(rev("X1", 500)); code != "" || len(reg.revocations) != 1 {
		t.Fatalf("at the boundary (500+1000 == now) it stays: %q %d", code, len(reg.revocations))
	}
	now = 1501
	if r := reg.Accept(lease("L2", 1000), nil); !r.Ok || len(reg.revocations) != 0 {
		t.Fatalf("past the boundary an accept prunes it: %+v %d", r, len(reg.revocations))
	}
	if code, _ := reg.Revoke(rev("X2", 1000)); code != "" || len(reg.revocations) != 1 {
		t.Fatalf("revoke: %q %d", code, len(reg.revocations))
	}
	now = 2001
	if code, _ := reg.Revoke(rev("X3", 2000)); code != "" || len(reg.revocations) != 1 || reg.revocations[0]["value"] != "X3" {
		t.Fatalf("a revoke prunes too: %q %v", code, reg.revocations)
	}
	// no ceiling: nothing is pruned
	all := NewLeaseRegistryShards(LeasePolicy{Authorities: []string{k.id}}, MemoryLeaseKv(), 1)
	all.clock = func() int64 { return 1 << 50 }
	all.Revoke(rev("X1", 1))
	all.Revoke(rev("X2", 2))
	if len(all.revocations) != 2 {
		t.Fatalf("no ceiling: %d", len(all.revocations))
	}
	// the production clock is wall time
	if got := NewLeaseRegistry(LeasePolicy{}, MemoryLeaseKv()).clock(); got < 1_700_000_000_000 {
		t.Fatalf("clock: %d", got)
	}
}

// attest-gcp-confidential-space.test.ts (TS 365d0e8ec): a genuine public chain must not vouch for a key beside it.
func TestGcpJwkKeyMustBeItsX5cLeaf(t *testing.T) {
	const notLeaf = "signing key not trusted: the JWK key is not the key of its x5c leaf"
	p := g09gNewPKI(t)
	x5c := []any{g09gB64(p.leaf), g09gB64(p.ca)}
	byRoot := &gcpVerifier{spkiPins: map[string]bool{}, rootCertsPem: []string{g09gPEM(p.ca)}}
	byPin := &gcpVerifier{spkiPins: map[string]bool{g09gSpki(t, p.ca): true}}
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	withChain := func(j map[string]any) any {
		j["x5c"] = x5c
		return map[string]any{"keys": []any{j}}
	}
	rsaJwk := map[string]any{"kid": "e1", "kty": "RSA", "n": base64.RawURLEncoding.EncodeToString(rk.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(rk.E)).Bytes())}
	tok := &jwtParsed{hasKid: true, kid: "e1"}
	leafSpki := g09gSpki(t, p.leaf)
	for name, v := range map[string]*gcpVerifier{"root": byRoot, "pin": byPin} {
		for form, ev := range map[string]any{"attacker x/y": withChain(jwkOf(p.otherKey, "e1")), "attacker n/e": withChain(rsaJwk)} {
			if k, why := v.signingKey(tok, ev, tokNow); why != notLeaf || k.pub != nil {
				t.Errorf("%s, %s: %q", name, form, why)
			}
		}
		// the honest leaf key as x/y beside its own chain, and the chain alone
		for form, ev := range map[string]any{"leaf x/y": withChain(jwkOf(p.leafKey, "e1")), "x5c only": withChain(map[string]any{"kid": "e1"})} {
			if k, why := v.signingKey(tok, ev, tokNow); why != "" || k.spkiSHA256() != leafSpki {
				t.Errorf("%s, %s: %q", name, form, why)
			}
		}
	}
	// a chain that does not verify reports that, not the key mismatch
	bad := map[string]any{"keys": []any{map[string]any{"kid": "e1", "x": "-", "x5c": []any{g09gB64(p.leaf), g09gB64(p.other)}}}}
	if _, why := byRoot.signingKey(tok, bad, tokNow); why != "signing key not trusted: x5c link 0 is not signed by the certificate above it" {
		t.Errorf("bad chain: %q", why)
	}
}
