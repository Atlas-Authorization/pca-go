package pca

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"
)

// r5n8: deadline kills. A mutant that stops a loop from advancing (or lets it append without bound) makes these calls spin
// forever. They run before every other caller of the same code (the a0_ prefix sorts first under -failfast), so the mutant
// is decided by a short deadline failure instead of a go-test timeout or an out-of-memory kill. The unmutated calls take
// microseconds; the append-without-bound mutants get the short deadline so they fail before memory runs out.

func r5n8Within(t *testing.T, what string, d time.Duration, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		f()
	}()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("%s did not finish within %v", what, d)
	}
}

const (
	r5n8Spin   = 2 * time.Second
	r5n8Append = 300 * time.Millisecond
)

// saferegex.go:39-47 (the binary search of charSet.has)
func TestR5N8CharSetHasTerminates(t *testing.T) {
	ranges := []charRange{{2, 3}, {10, 12}, {20, 20}, {30, 35}, {50, 60}, {70, 70}, {80, 90}}
	linear := func(u int) bool {
		for _, r := range ranges {
			if u >= r[0] && u <= r[1] {
				return true
			}
		}
		return false
	}
	for _, neg := range []bool{false, true} {
		cs := &charSet{ranges: ranges, negated: neg}
		var bad []int
		r5n8Within(t, "charSet.has", r5n8Spin, func() {
			for u := 0; u <= 100; u++ {
				if cs.has(u) != (linear(u) != neg) {
					bad = append(bad, u)
				}
			}
		})
		if len(bad) > 0 {
			t.Fatalf("negated=%v: wrong membership at %v", neg, bad)
		}
	}
	empty := &charSet{}
	r5n8Within(t, "charSet.has on no ranges", r5n8Spin, func() {
		if empty.has(5) {
			t.Error("an empty set has no member")
		}
	})
}

// saferegex.go:135, 136, 150 (alt and cat loops of the parser)
func TestR5N8RegexParserTerminates(t *testing.T) {
	for _, c := range []struct {
		src   string
		kind  int
		items int
	}{{"ab", nodeCat, 2}, {"a", nodeCat, 1}, {"a|b|c", nodeAlt, 3}, {"a|b", nodeAlt, 2}} {
		var n *reNode
		r5n8Within(t, "parse("+c.src+")", r5n8Append, func() { n = (&reParser{s: utf16Units(c.src)}).parse() })
		if n == nil || n.k != c.kind || len(n.items) != c.items {
			t.Fatalf("parse(%q): %+v, want kind %d with %d items", c.src, n, c.kind, c.items)
		}
	}
}

// saferegex.go:548 (the stack pop of the Pike simulation)
func TestR5N8RunSafeRegexTerminates(t *testing.T) {
	for _, c := range []struct {
		src, subject string
		want         bool
	}{{"ab", "ab", true}, {"a*b|c", "aab", true}, {"a*b|c", "c", true}, {"(?:a|b)+", "abba", true}, {"ab", "ac", false}} {
		prog := compileSafeRegex(utf16Units(c.src))
		if prog == nil {
			t.Fatalf("%q does not compile", c.src)
		}
		var m, ok bool
		r5n8Within(t, "runSafeRegex("+c.src+")", r5n8Spin, func() { m, ok = runSafeRegex(prog, utf16Units(c.subject)) })
		if !ok || m != c.want {
			t.Fatalf("runSafeRegex(%q, %q) = %v, %v; want %v", c.src, c.subject, m, ok, c.want)
		}
	}
}

// saferegex.go:619, 630, 636, 645, 663 (the source scanner advances over escapes, classes, groups)
func TestR5N8SafeRegexScannerTerminates(t *testing.T) {
	for _, c := range []struct {
		src    string
		d      time.Duration
		expect bool
	}{
		{`a\.b`, r5n8Spin, true}, {`[a\]b]`, r5n8Spin, true}, {`[ab]`, r5n8Spin, true}, {`[]`, r5n8Spin, true}, {`[^]`, r5n8Spin, true},
		{`(a)`, r5n8Spin, true}, {`(?:a)`, r5n8Append, true}, {`(?:a|b)c`, r5n8Append, true},
	} {
		var got bool
		r5n8Within(t, "isSafeRegexSource("+c.src+")", c.d, func() { got = isSafeRegexSource(utf16Units(c.src)) })
		if got != c.expect {
			t.Fatalf("isSafeRegexSource(%q) = %v, want %v", c.src, got, c.expect)
		}
	}
}

// attest_nvidia_rim.go:56 (the PEM line splitter advances 64 characters per line)
func TestR5N8PemOfDerB64Terminates(t *testing.T) {
	body := strings.Repeat("A", 130)
	var got string
	r5n8Within(t, "pemOfDerB64", r5n8Append, func() { got = pemOfDerB64(body) })
	want := "-----BEGIN CERTIFICATE-----\n" + strings.Repeat("A", 64) + "\n" + strings.Repeat("A", 64) + "\nAA\n-----END CERTIFICATE-----"
	if got != want {
		t.Fatalf("pemOfDerB64 = %q", got)
	}
}

// attest_nvidia_rim.go:376 (the revoked-serial walk over the chain steps forward)
func TestR5N8ChainRevocationWalkTerminates(t *testing.T) {
	r := g12NewRig(t)
	chain := r.chain(t)
	crl := r.crl(t, r.root, r.rootKey)
	var why string
	r5n8Within(t, "checkNvidiaChainRevocation", r5n8Spin, func() { why = checkNvidiaChainRevocation(chain, [][]byte{crl}, g12Now, nil) })
	if why != "" {
		t.Fatalf("clean CRL: %q", why)
	}
}

// attest_intel.go:312 (the PCK chain walk marks each certificate seen, so an issuer cycle ends)
func TestR5N8PckChainIssuerCycleTerminates(t *testing.T) {
	ka, kb := g08Key(t), g08Key(t)
	ta := &x509.Certificate{SerialNumber: big.NewInt(10), Subject: pkix.Name{CommonName: "r5n8 A"}, NotBefore: g08nb, NotAfter: g08na}
	tb := &x509.Certificate{SerialNumber: big.NewInt(11), Subject: pkix.Name{CommonName: "r5n8 B"}, NotBefore: g08nb, NotAfter: g08na}
	ca := g08MakeCert(t, ta, tb, &ka.PublicKey, kb)
	cb := g08MakeCert(t, tb, ta, &kb.PublicKey, ka)
	pem := g08PEM(ca.Raw, cb.Raw)
	var r pckChainResult
	r5n8Within(t, "verifyIntelPckChain", r5n8Append, func() { r = verifyIntelPckChain(pem, g08Pin(ca), g08now) })
	if r.ok || r.reason != "PCK chain does not terminate in a self-signed root" {
		t.Fatalf("issuer cycle: %+v", r)
	}
}

// attest_der.go:506 (a TLV whose content runs past the buffer is refused, not returned as an empty element)
func TestR5N8TlvAtTruncated(t *testing.T) {
	var el derTlv
	var err error
	r5n8Within(t, "tlvAt", r5n8Spin, func() { el, err = tlvAt([]byte{0x30, 0x05, 1}, 0) })
	if err == nil || err.Error() != "truncated" || el != (derTlv{}) {
		t.Fatalf("tlvAt over-long: %+v %v", el, err)
	}
}

// attest_der.go:111, 293 (the tbsCertificate element walks advance)
func TestR5N8CertWalksTerminate(t *testing.T) {
	cert := g09dRoleCert(g09dExt(g09dRaw(0x2a), false, nil))
	r5n8Within(t, "readCertRoleInfo", r5n8Spin, func() {
		if _, err := readCertRoleInfo(cert); err != nil {
			t.Errorf("readCertRoleInfo: %v", err)
		}
	})
	var tab *extTable
	var err error
	r5n8Within(t, "parseCertExtensions", r5n8Spin, func() { tab, err = parseCertExtensions(cert) })
	if err != nil || tab == nil || len(tab.oids) != 1 || tab.oids[0] != "1.2" {
		t.Fatalf("parseCertExtensions: %+v %v", tab, err)
	}
}

// workflow.go:316 (a step is marked in progress before its dependencies are visited, so a cycle ends)
func TestR5N8WorkflowAncestorsCycleTerminates(t *testing.T) {
	body := g09wBody("x", []any{g09wStep("a", "b"), g09wStep("b", "a")}, []any{})
	var anc map[string]map[string]bool
	var ok bool
	r5n8Within(t, "k5Ancestors", r5n8Append, func() { anc, ok = k5Ancestors(body) })
	if ok || anc != nil {
		t.Fatalf("a dependency cycle must be refused: %v %v", anc, ok)
	}
}
