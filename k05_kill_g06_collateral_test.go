package pca

// k05 mutation kills (group g06): the Intel PCS collateral path (attest_intel_collateral.go). Self-contained: the
// certificates, CRLs, signed PCS documents and the quote layout are generated here; the genuine-quote and issuer-chain
// verifiers are substituted (collateralQuoteCheck / collateralChainCheck) only where a test needs to reach a re-check that a
// genuine verified quote never trips.

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"reflect"
	"strings"
	"testing"
	"time"
)

var (
	g06nb  = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	g06na  = time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC)
	g06now = time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC).UnixMilli()
)

func g06key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// g06certDER issues a certificate (parent nil: self-issued, signed by signer).
func g06certDER(t *testing.T, cn string, serial int64, ca bool, nb, na time.Time, parent *x509.Certificate, pub any, signer *ecdsa.PrivateKey) []byte {
	t.Helper()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn}, NotBefore: nb, NotAfter: na}
	if ca {
		tmpl.BasicConstraintsValid, tmpl.IsCA, tmpl.KeyUsage = true, true, x509.KeyUsageCertSign|x509.KeyUsageCRLSign
	} else {
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature
	}
	if parent == nil {
		parent = tmpl
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func g06cert(t *testing.T, cn string, serial int64, ca bool, nb, na time.Time, parent *x509.Certificate, pub any, signer *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	c, err := x509.ParseCertificate(g06certDER(t, cn, serial, ca, nb, na, parent, pub, signer))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func g06pem(ders ...[]byte) string {
	var sb strings.Builder
	for _, d := range ders {
		sb.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: d}))
	}
	return sb.String()
}

func g06att(t *testing.T, der []byte) *attCert {
	t.Helper()
	c, err := parseCertDER(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// g06unreadableKey rewrites the SPKI algorithm of an EC certificate (id-ecPublicKey 1.2.840.10045.2.1 -> 1.2.840.10045.2.2):
// the certificate still parses, its key is of no type this verifier reads (its signature no longer verifies; unused here).
func g06unreadableKey(t *testing.T, der []byte) []byte {
	t.Helper()
	ecOID := []byte{0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01}
	if bytes.Count(der, ecOID) != 1 {
		t.Fatal("expected one id-ecPublicKey")
	}
	return bytes.Replace(der, ecOID, []byte{0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x02}, 1)
}

// ───────────────────────────────────────────────────────────── DER CRLs

var (
	g06alg = derTLV(0x30, derTLV(0x06, []byte{0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02}))
	g06ver = derTLV(0x02, []byte{1})
	g06iss = derTLV(0x30)
	g06tu  = derTLV(0x17, []byte("250101000000Z"))
	g06nu  = derTLV(0x17, []byte("300101000000Z"))
	g06sig = derTLV(0x03, []byte{0, 0xaa})
	g06TU  = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC).UnixMilli()
	g06NU  = time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC).UnixMilli()
)

func g06tbs(parts ...[]byte) []byte { return derTLV(0x30, parts...) }

func g06outer(tbs []byte) []byte { return derTLV(0x30, tbs, g06alg, g06sig) }

// g06crl is a CRL (thisUpdate 2025-01-01, nextUpdate 2030-01-01, no revoked entries) signed (ECDSA DER) by k.
func g06crl(t *testing.T, k *ecdsa.PrivateKey) []byte {
	t.Helper()
	tbs := g06tbs(g06ver, g06alg, g06iss, g06tu, g06nu)
	sig, err := ecdsa.SignASN1(rand.Reader, k, sha256Sum(tbs))
	if err != nil {
		t.Fatal(err)
	}
	return derTLV(0x30, tbs, g06alg, derTLV(0x03, append([]byte{0}, sig...)))
}

// ───────────────────────────────────────────────────────────── signed PCS documents

func g06signed(t *testing.T, k *ecdsa.PrivateKey, name, body string) string {
	t.Helper()
	r, s, err := ecdsa.Sign(rand.Reader, k, sha256Sum([]byte(body)))
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return `{"` + name + `":` + body + `,"signature":"` + hex.EncodeToString(sig) + `"}`
}

func g06comps(svn int) string {
	parts := make([]string, 16)
	for i := range parts {
		parts[i] = fmt.Sprintf(`{"svn":%d}`, svn)
	}
	return "[" + strings.Join(parts, ",") + "]"
}

func g06tcbInfo(eval string) string {
	return `{"id":"TDX","version":3,"issueDate":"2025-01-01T00:00:00Z","nextUpdate":"2030-01-01T00:00:00Z","fmspc":"00906ED50000","tcbEvaluationDataNumber":` + eval +
		`,"tdxModule":{"mrsigner":"` + strings.Repeat("11", 48) + `","attributes":"0000000000000000","attributesMask":"FFFFFFFFFFFFFFFF"},"tcbLevels":[{"tcb":{"sgxtcbcomponents":` +
		g06comps(2) + `,"pcesvn":10,"tdxtcbcomponents":` + g06comps(0) + `},"tcbStatus":"UpToDate","advisoryIDs":["INTEL-SA-00009"]}]}`
}

func g06qeIdent(eval string) string {
	return `{"id":"TD_QE","version":2,"issueDate":"2025-01-01T00:00:00Z","nextUpdate":"2030-01-01T00:00:00Z","tcbEvaluationDataNumber":` + eval +
		`,"miscselect":"00000000","miscselectMask":"FFFFFFFF","attributes":"` + strings.Repeat("00", 16) + `","attributesMask":"` + strings.Repeat("FF", 16) +
		`","mrsigner":"` + strings.Repeat("22", 32) + `","isvprodid":2,"tcbLevels":[{"tcb":{"isvsvn":8},"tcbStatus":"UpToDate","advisoryIDs":["INTEL-SA-00001"]}]}`
}

// ───────────────────────────────────────────────────────────── the quote layout (parseDcapQuote; signatures not checked here)

func g06body() []byte {
	b := make([]byte, dcapTdReportLen)
	copy(b[64:112], bytes.Repeat([]byte{0x11}, 48))
	return b
}

func g06qeBody() []byte {
	q := make([]byte, dcapSgxReport)
	copy(q[128:160], bytes.Repeat([]byte{0x22}, 32))
	q[256] = 2 // ISVPRODID 2
	q[258] = 8 // ISVSVN 8
	return q
}

func g06quote(body, qe []byte, chain string) []byte {
	le := binary.LittleEndian
	hdr := make([]byte, dcapHeaderLen)
	le.PutUint16(hdr[0:], 4)
	le.PutUint16(hdr[2:], 2)
	le.PutUint32(hdr[4:], 0x81)
	inner := make([]byte, 6)
	le.PutUint16(inner[0:], 5)
	le.PutUint32(inner[2:], uint32(len(chain)))
	inner = append(inner, chain...)
	ob := append(append([]byte{}, qe...), make([]byte, 64)...) // QE report + its signature
	ob = append(ob, 0, 0)                                      // QE auth-data size 0
	ob = append(ob, inner...)
	outer := make([]byte, 6)
	le.PutUint16(outer[0:], 6)
	le.PutUint32(outer[2:], uint32(len(ob)))
	outer = append(outer, ob...)
	sig := append(make([]byte, 128), outer...) // quote signature + attestation key
	sl := make([]byte, 4)
	le.PutUint32(sl, uint32(len(sig)))
	out := append(append([]byte{}, hdr...), body...)
	out = append(out, sl...)
	return append(out, sig...)
}

type g06fx struct {
	rootKey, caKey, tcbKey *ecdsa.PrivateKey
	root, ca, pck, tcb     *x509.Certificate
	pin                    string
	quote                  []byte
	col                    *intelCollateral
}

func g06newFx(t *testing.T) *g06fx {
	t.Helper()
	f := &g06fx{rootKey: g06key(t), caKey: g06key(t), tcbKey: g06key(t)}
	pckKey := g06key(t)
	f.root = g06cert(t, "g06 root", 1, true, g06nb, g06na, nil, &f.rootKey.PublicKey, f.rootKey)
	f.ca = g06cert(t, "g06 platform ca", 2, true, g06nb, g06na, f.root, &f.caKey.PublicKey, f.rootKey)
	f.pck = g06cert(t, "g06 pck", 3, false, g06nb, g06na, f.ca, &pckKey.PublicKey, f.caKey)
	f.tcb = g06cert(t, "g06 tcb signing", 4, false, g06nb, g06na, f.root, &f.tcbKey.PublicKey, f.rootKey)
	sum := sha256.Sum256(f.root.RawSubjectPublicKeyInfo)
	f.pin = hex.EncodeToString(sum[:])
	f.quote = g06quote(g06body(), g06qeBody(), g06pem(f.pck.Raw, f.ca.Raw, f.root.Raw))
	chain := g06pem(f.tcb.Raw, f.root.Raw)
	f.col = &intelCollateral{
		tcbInfoJSON: g06signed(t, f.tcbKey, "tcbInfo", g06tcbInfo("17")), tcbInfoChain: chain,
		qeIdentityJSON: g06signed(t, f.tcbKey, "enclaveIdentity", g06qeIdent("17")), qeIdentityChain: chain,
		pckCrl: g06crl(t, f.caKey), rootCrl: g06crl(t, f.rootKey),
	}
	return f
}

func g06okBase() tdxResult {
	return tdxResult{ok: true, fmspc: "00906ed50000", pck: &pckTcb{sgx: bytes.Repeat([]byte{2}, 16), pcesvn: 10}}
}

func g06withQuote(t *testing.T, base tdxResult) {
	t.Helper()
	old := collateralQuoteCheck
	collateralQuoteCheck = func([]byte, string, int64, *tdxQuotePolicy, bool) tdxResult { return base }
	t.Cleanup(func() { collateralQuoteCheck = old })
}

func g06withChain(t *testing.T, r pckChainResult) {
	t.Helper()
	old := collateralChainCheck
	collateralChainCheck = func(string, string, int64) pckChainResult { return r }
	t.Cleanup(func() { collateralChainCheck = old })
}

func g06wantFail(t *testing.T, res collateralResult, reason string) {
	t.Helper()
	if res.ok || res.reason != reason {
		t.Fatalf("got ok=%v reason %q, want reason %q", res.ok, res.reason, reason)
	}
}

const g06thrown = "collateral verification error (fail closed): "

func TestK05G06CollateralWhole(t *testing.T) {
	f := g06newFx(t)
	g06withQuote(t, g06okBase())
	res := verifyIntelTdxCollateral(f.quote, f.col, g06now, nil, f.pin, false)
	if !res.ok || res.reason != "" || res.status != "UpToDate" {
		t.Fatalf("got %+v", res)
	}
	// the TCB advisory (INTEL-SA-00009) is appended before the QE one (INTEL-SA-00001): the result is sorted
	if !reflect.DeepEqual(res.advisoryIDs, []string{"INTEL-SA-00001", "INTEL-SA-00009"}) {
		t.Fatalf("advisories %v", res.advisoryIDs)
	}
}

func TestK05G06CollateralQuoteResultGuards(t *testing.T) {
	f := g06newFx(t)
	bad := g06okBase()
	bad.ok, bad.reason = false, "r"
	noPck := g06okBase()
	noPck.pck = nil
	noFmspc := g06okBase()
	noFmspc.fmspc = ""
	for _, b := range []struct {
		base tdxResult
		want string
	}{{bad, "quote invalid: r"}, {noPck, "quote invalid: "}, {noFmspc, "quote invalid: "}} {
		g06withQuote(t, b.base)
		g06wantFail(t, verifyIntelTdxCollateral(f.quote, f.col, g06now, nil, f.pin, false), b.want)
	}
}

func TestK05G06CollateralQuoteReparse(t *testing.T) {
	f := g06newFx(t)
	g06withQuote(t, g06okBase())
	run := func(quote []byte, now int64) collateralResult {
		return verifyIntelTdxCollateral(quote, f.col, now, nil, f.pin, false)
	}
	g06wantFail(t, run([]byte("x"), g06now), g06thrown+"parseDcapQuote: too short for header + TD report + sig length")

	res := run(g06quote(g06body(), g06qeBody(), "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"), g06now)
	if res.ok || !strings.HasPrefix(res.reason, g06thrown) || strings.Contains(res.reason, "parseDcapQuote") {
		t.Fatalf("bad PEM block: %+v", res)
	}

	// a PCK leaf that expired exactly 1 ms before now (validity is checked with no skew)
	pckE := g06cert(t, "g06 pck", 3, false, g06nb, time.UnixMilli(g06now).UTC(), f.ca, &g06key(t).PublicKey, f.caKey)
	g06wantFail(t, run(g06quote(g06body(), g06qeBody(), g06pem(pckE.Raw, f.ca.Raw, f.root.Raw)), g06now+1), "PCK chain certificate outside its validity period")
	if r := run(g06quote(g06body(), g06qeBody(), g06pem(pckE.Raw, f.ca.Raw, f.root.Raw)), g06now); !r.ok {
		t.Fatalf("leaf valid at its notAfter: %+v", r)
	}

	g06wantFail(t, run(g06quote(g06body(), g06qeBody(), g06pem(f.root.Raw)), g06now), "PCK leaf not found")
	g06wantFail(t, run(g06quote(g06body(), g06qeBody(), g06pem(f.pck.Raw, f.root.Raw)), g06now), "PCK CA not found in the quote chain")
	g06wantFail(t, run(g06quote(g06body(), g06qeBody(), g06pem(f.pck.Raw, f.ca.Raw)), g06now), "Intel root not found in the quote chain")

	// a root / CA whose key this verifier cannot read: fail closed before any CRL is checked
	xk := g06key(t)
	xroot := g06unreadableKey(t, g06certDER(t, "g06 root", 1, true, g06nb, g06na, nil, &xk.PublicKey, xk))
	g06wantFail(t, run(g06quote(g06body(), g06qeBody(), g06pem(f.pck.Raw, f.ca.Raw, xroot)), g06now), g06thrown+"error:1E08010C:DECODER routines::unsupported")
	xca := g06unreadableKey(t, g06certDER(t, "g06 platform ca", 2, true, g06nb, g06na, f.root, &f.caKey.PublicKey, f.rootKey))
	g06wantFail(t, run(g06quote(g06body(), g06qeBody(), g06pem(f.pck.Raw, xca, f.root.Raw)), g06now), g06thrown+"error:1E08010C:DECODER routines::unsupported")
}

func TestK05G06CollateralQeIdentityChain(t *testing.T) {
	f := g06newFx(t)
	g06withQuote(t, g06okBase())
	ok2 := g06key(t)
	other := g06cert(t, "g06 other root", 9, true, g06nb, g06na, nil, &ok2.PublicKey, ok2)
	f.col.qeIdentityChain = g06pem(other.Raw)
	g06wantFail(t, verifyIntelTdxCollateral(f.quote, f.col, g06now, nil, f.pin, false), "QE identity: issuer chain invalid: Intel SGX Root CA does not match the pinned trust anchor")
}

func TestK05G06CollateralEvaluationNumbers(t *testing.T) {
	f := g06newFx(t)
	g06withQuote(t, g06okBase())
	for _, c := range []struct{ info, qe, want string }{{"0", "17", ""}, {"17", "0", ""}, {`"17"`, "17", "tcbEvaluationDataNumber missing"}, {"17", `"17"`, "tcbEvaluationDataNumber missing"}} {
		f.col.tcbInfoJSON = g06signed(t, f.tcbKey, "tcbInfo", g06tcbInfo(c.info))
		f.col.qeIdentityJSON = g06signed(t, f.tcbKey, "enclaveIdentity", g06qeIdent(c.qe))
		res := verifyIntelTdxCollateral(f.quote, f.col, g06now, nil, f.pin, false)
		if c.want == "" {
			if !res.ok || res.reason != "" {
				t.Fatalf("info %s qe %s: %+v", c.info, c.qe, res)
			}
			continue
		}
		g06wantFail(t, res, c.want)
	}
}

func TestK05G06CollateralSeamAttributesLastByte(t *testing.T) {
	f := g06newFx(t)
	g06withQuote(t, g06okBase())
	body := g06body()
	body[119] = 0x01 // the last SEAM attributes byte, under an all-ones mask
	g06wantFail(t, verifyIntelTdxCollateral(g06quote(body, g06qeBody(), g06pem(f.pck.Raw, f.ca.Raw, f.root.Raw)), f.col, g06now, nil, f.pin, false),
		"TCB evaluation: TD report SEAM attributes do not match the TDX module identity")
}

func TestK05G06SignerKeyFromChain(t *testing.T) {
	f := g06newFx(t)
	tcbAtt := g06att(t, f.tcb.Raw)

	g06withChain(t, pckChainResult{validity: true, reason: "v"})
	if _, why := signerKeyFromChain("", "", g06now, nil); why != "issuer chain certificate outside its validity period" {
		t.Fatalf("validity: %q", why)
	}
	g06withChain(t, pckChainResult{ok: true})
	if _, why := signerKeyFromChain("", "", g06now, nil); why != "issuer chain invalid: " {
		t.Fatalf("ok without leaf: %q", why)
	}
	g06withChain(t, pckChainResult{reason: "r", leaf: tcbAtt})
	if _, why := signerKeyFromChain("", "", g06now, nil); why != "issuer chain invalid: r" {
		t.Fatalf("not ok with leaf: %q", why)
	}

	g06withChain(t, pckChainResult{ok: true, leaf: tcbAtt})
	k, why := signerKeyFromChain(g06pem(f.tcb.Raw), "", g06now, nil)
	if pk, _ := k.pub.(*ecdsa.PublicKey); why != "" || pk == nil || !pk.Equal(&f.tcbKey.PublicKey) {
		t.Fatalf("valid: %q", why)
	}
	if _, why := signerKeyFromChain("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n", "", g06now, nil); !strings.HasPrefix(why, g06thrown) {
		t.Fatalf("bad PEM block: %q", why)
	}
	exp := g06cert(t, "g06 tcb signing", 4, false, g06nb, time.UnixMilli(g06now).UTC(), f.root, &f.tcbKey.PublicKey, f.rootKey)
	if _, why := signerKeyFromChain(g06pem(exp.Raw), "", g06now+1, nil); why != "issuer chain certificate outside its validity period" {
		t.Fatalf("expired 1 ms ago: %q", why)
	}
	if _, why := signerKeyFromChain(g06pem(exp.Raw), "", g06now, nil); why != "" {
		t.Fatalf("valid at notAfter: %q", why)
	}

	xleaf := g06unreadableKey(t, g06certDER(t, "g06 x leaf", 5, false, g06nb, g06na, f.root, &f.tcbKey.PublicKey, f.rootKey))
	g06withChain(t, pckChainResult{ok: true, leaf: g06att(t, xleaf)})
	if _, why := signerKeyFromChain("", "", g06now, nil); why != g06thrown+"error:1E08010C:DECODER routines::unsupported" {
		t.Fatalf("unreadable leaf key: %q", why)
	}
}

// ───────────────────────────────────────────────────────────── DER reading

func TestK05G06TlvLenient(t *testing.T) {
	for _, c := range []struct {
		b      []byte
		limit  int
		want   derTlv
		errMsg string
	}{
		{[]byte{0x30, 0x00}, 2, derTlv{tag: 0x30, start: 2, end: 2}, ""},
		{[]byte{0x30, 0x00, 0, 0}, 1, derTlv{}, "DER truncated"},
		{[]byte{0x30, 0x80}, 2, derTlv{}, "DER bad length"},
		{[]byte{0x30, 0x85, 0, 0, 0, 0, 0}, 7, derTlv{}, "DER bad length"},
		{[]byte{0x30, 0x84, 0, 0, 0, 1, 0xee}, 7, derTlv{tag: 0x30, start: 6, end: 7}, ""},
		{[]byte{0x30, 0x81, 0x00}, 3, derTlv{tag: 0x30, start: 3, end: 3}, ""},
		{[]byte{0x30, 0x82, 0x00, 0x05}, 3, derTlv{}, "DER bad length"},
		{[]byte{0x30, 0x05, 0}, 3, derTlv{}, "DER overrun"},
	} {
		got, err := tlvLenient(c.b, 0, c.limit)
		if c.errMsg != "" {
			if err == nil || err.Error() != c.errMsg || got != (derTlv{}) {
				t.Fatalf("%x/%d: %+v %v, want %s", c.b, c.limit, got, err, c.errMsg)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Fatalf("%x/%d: %+v %v, want %+v", c.b, c.limit, got, err, c.want)
		}
	}
}

func TestK05G06DateUTC(t *testing.T) {
	ms := func(y int) int64 { return time.Date(y, 1, 1, 0, 0, 0, 0, time.UTC).UnixMilli() }
	for _, c := range []struct {
		y    int
		want int64
	}{{0, ms(1900)}, {1, ms(1901)}, {98, ms(1998)}, {99, ms(1999)}, {100, ms(100)}, {-1, ms(-1)}, {2030, ms(2030)}} {
		if got := dateUTC(c.y, 1, 1, 0, 0, 0); got != c.want {
			t.Fatalf("dateUTC(%d) = %d, want %d", c.y, got, c.want)
		}
	}
}

func TestK05G06CrlTime(t *testing.T) {
	at := func(y, mo, d, h, mi, s int) int64 {
		return time.Date(y, time.Month(mo), d, h, mi, s, 0, time.UTC).UnixMilli()
	}
	for _, c := range []struct {
		tag    byte
		s      string
		want   int64
		errMsg string
	}{
		{0x17, "500203040506Z", at(1950, 2, 3, 4, 5, 6), ""},
		{0x17, "490203040506Z", at(2049, 2, 3, 4, 5, 6), ""},
		{0x17, "510203040506Z", at(1951, 2, 3, 4, 5, 6), ""},
		{0x17, "5002030405Z", 0, "bad UTCTime"},
		{0x18, "20500203040506Z", at(2050, 2, 3, 4, 5, 6), ""},
		{0x18, "205002030405Z", 0, "bad GeneralizedTime"},
		{0x02, "500203040506Z", 0, "not a DER time"},
	} {
		b := []byte(c.s)
		got, err := crlTime(b, derTlv{tag: c.tag, start: 0, end: len(b)})
		if c.errMsg != "" {
			if err == nil || err.Error() != c.errMsg || got != 0 {
				t.Fatalf("%x %s: %d %v, want %s", c.tag, c.s, got, err, c.errMsg)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Fatalf("%x %s: %d %v, want %d", c.tag, c.s, got, err, c.want)
		}
	}
}

func TestK05G06ParseCRLRefusals(t *testing.T) {
	tbsOK := g06tbs(g06ver, g06alg, g06iss, g06tu, g06nu)
	for _, c := range []struct {
		name, want string
		der        []byte
	}{
		{"tbs bad length", "DER bad length", derTLV(0x30, []byte{0x30, 0x80})},
		{"tbs not a SEQUENCE", "CRL: bad TBSCertList", derTLV(0x30, derTLV(0x31), g06alg, g06sig)},
		{"algorithm bad length", "DER bad length", derTLV(0x30, tbsOK, []byte{0x30, 0x80})},
		{"signature bad length", "DER bad length", derTLV(0x30, tbsOK, g06alg, []byte{0x03, 0x80})},
		{"signature not a BIT STRING", "CRL: bad signature", derTLV(0x30, tbsOK, g06alg, derTLV(0x04, []byte{0, 0xaa}))},
		{"bytes after the signature", "CRL: bad signature", derTLV(0x30, tbsOK, g06alg, g06sig, derTLV(0x05))},
		{"first tbs element bad length", "DER bad length", g06outer(g06tbs([]byte{0x02, 0x80}))},
		{"element after version bad length", "DER bad length", g06outer(g06tbs(g06ver, []byte{0x30, 0x80}))},
		{"issuer bad length", "DER bad length", g06outer(g06tbs(g06ver, g06alg, []byte{0x30, 0x80}))},
		{"issuer not a SEQUENCE", "CRL: bad issuer", g06outer(g06tbs(g06ver, g06alg, derTLV(0x31), g06tu, g06nu))},
		{"thisUpdate bad length", "DER bad length", g06outer(g06tbs(g06ver, g06alg, g06iss, []byte{0x17, 0x80}))},
		{"thisUpdate malformed", "bad UTCTime", g06outer(g06tbs(g06ver, g06alg, g06iss, derTLV(0x17, []byte("bad")), g06nu))},
		{"no nextUpdate", "CRL: missing nextUpdate", g06outer(g06tbs(g06ver, g06alg, g06iss, g06tu))},
		{"revoked list but no nextUpdate", "CRL: missing nextUpdate", g06outer(g06tbs(g06ver, g06alg, g06iss, g06tu, derTLV(0x30, derTLV(0x30, derTLV(0x02, []byte{1}), g06tu))))},
		{"nextUpdate malformed", "bad UTCTime", g06outer(g06tbs(g06ver, g06alg, g06iss, g06tu, derTLV(0x17, []byte("bad"))))},
		{"element after nextUpdate bad length", "DER bad length", g06outer(g06tbs(g06ver, g06alg, g06iss, g06tu, g06nu, []byte{0x30, 0x80}))},
		{"revoked entry bad length", "DER bad length", g06outer(g06tbs(g06ver, g06alg, g06iss, g06tu, g06nu, derTLV(0x30, []byte{0x30, 0x80})))},
		{"revoked serial bad length", "DER bad length", g06outer(g06tbs(g06ver, g06alg, g06iss, g06tu, g06nu, derTLV(0x30, derTLV(0x30, []byte{0x02, 0x80}))))},
		{"revoked serial not an INTEGER", "CRL: bad revoked entry", g06outer(g06tbs(g06ver, g06alg, g06iss, g06tu, g06nu, derTLV(0x30, derTLV(0x30, derTLV(0x04, []byte{1})))))},
	} {
		crl, err := parseCRL(c.der)
		if err == nil || err.Error() != c.want || crl != nil {
			t.Fatalf("%s: %v %v, want %s", c.name, crl, err, c.want)
		}
	}
}

func TestK05G06ParseCRLShapes(t *testing.T) {
	revoked := derTLV(0x30, derTLV(0x30, derTLV(0x02, []byte{0x01, 0x23}), g06tu), derTLV(0x30, derTLV(0x02, []byte{0x00, 0x45}), g06tu))
	full := g06tbs(g06ver, g06alg, g06iss, g06tu, g06nu, revoked)
	crl, err := parseCRL(g06outer(full))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(crl.tbs, full) || crl.thisUpdate != g06TU || crl.nextUpdate != g06NU || !crl.hasNext ||
		!reflect.DeepEqual(crl.revoked, map[string]bool{"123": true, "45": true}) || !bytes.Equal(crl.sigDer, []byte{0xaa}) {
		t.Fatalf("full CRL: %+v", crl)
	}

	for _, c := range []struct {
		name string
		tbs  []byte
	}{
		{"no revoked list", g06tbs(g06ver, g06alg, g06iss, g06tu, g06nu)},
		{"no version", g06tbs(g06alg, g06iss, g06tu, g06nu)},
	} {
		crl, err := parseCRL(g06outer(c.tbs))
		if err != nil || crl.thisUpdate != g06TU || crl.nextUpdate != g06NU || len(crl.revoked) != 0 {
			t.Fatalf("%s: %+v %v", c.name, crl, err)
		}
	}

	gen, err := parseCRL(g06outer(g06tbs(g06ver, g06alg, g06iss, g06tu, derTLV(0x18, []byte("20300101000000Z")))))
	if err != nil || !gen.hasNext || gen.nextUpdate != g06NU {
		t.Fatalf("GeneralizedTime nextUpdate: %+v %v", gen, err)
	}

	// the signature BIT STRING: empty (no unused-bits byte) gives no signature; the unused-bits byte alone an empty one
	empty, err := parseCRL(derTLV(0x30, g06tbs(g06ver, g06alg, g06iss, g06tu, g06nu), g06alg, derTLV(0x03)))
	if err != nil || empty.sigDer != nil {
		t.Fatalf("empty BIT STRING: %+v %v", empty, err)
	}
	zero, err := parseCRL(derTLV(0x30, g06tbs(g06ver, g06alg, g06iss, g06tu, g06nu), g06alg, derTLV(0x03, []byte{0})))
	if err != nil || zero.sigDer == nil || len(zero.sigDer) != 0 {
		t.Fatalf("unused-bits-only BIT STRING: %+v %v", zero, err)
	}
}

func TestK05G06CrlSignatureAndWindow(t *testing.T) {
	k := g06key(t)
	der := g06crl(t, k)
	key := certKey{pub: &k.PublicKey}
	for _, c := range []struct {
		now  int64
		want string
	}{
		{g06TU, ""}, {g06NU, ""}, {g06TU - 1, "CRL thisUpdate is in the future"}, {g06NU + 1, "CRL is stale (nextUpdate passed)"},
	} {
		rev, why := verifyCRL(der, key, c.now)
		if why != c.want || (c.want == "" && (rev == nil || len(rev) != 0)) {
			t.Fatalf("now %d: %v %q, want %q", c.now, rev, why, c.want)
		}
	}

	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tbs := []byte("g06 tbs")
	sig, err := rsa.SignPKCS1v15(rand.Reader, rk, crypto.SHA256, sha256Sum(tbs))
	if err != nil {
		t.Fatal(err)
	}
	if !crlSigOK(tbs, sig, certKey{pub: &rk.PublicKey}) {
		t.Fatal("RSA CRL signature refused")
	}
	if crlSigOK([]byte("other"), sig, certKey{pub: &rk.PublicKey}) {
		t.Fatal("RSA signature over other bytes accepted")
	}
	if crlSigOK(tbs, sig, certKey{}) {
		t.Fatal("a key of no known type accepted")
	}
}

// ───────────────────────────────────────────────────────────── signed JSON text

func TestK05G06RawJSONObject(t *testing.T) {
	for _, c := range []struct {
		text, want string
		ok         bool
	}{
		{`  {"tcbInfo":{"a":1}}`, `{"a":1}`, true},
		{``, ``, false},
		{`x"tcbInfo":{}`, ``, false},
		{`{"abcdefg":{"x":1}}`, ``, false},
		{`{"tcbInfo"x{}}`, ``, false},
		{`{"tcbInfo"`, ``, false},
		{`{"tcbInfo":x{}}`, ``, false},
		{`{"tcbInfo":`, ``, false},
		{`{"tcbInfo":{"a":"\"}"}}`, `{"a":"\"}"}`, true},
		{`{"tcbInfo":{"a":"}"}}`, `{"a":"}"}`, true},
		{`{"tcbInfo":{"a":1`, ``, false},
	} {
		got, ok := rawJSONObject(c.text, "tcbInfo")
		if got != c.want || ok != c.ok {
			t.Fatalf("%q: %q %v, want %q %v", c.text, got, ok, c.want, c.ok)
		}
	}
}

func TestK05G06HexAndDates(t *testing.T) {
	if b, ok := hexDecodeLoose("abc"); !ok || !bytes.Equal(b, []byte{0xab}) {
		t.Fatalf("odd length: %x %v", b, ok)
	}
	if b, ok := hexDecodeLoose("ag"); ok || b != nil {
		t.Fatalf("bad low nibble: %x %v", b, ok)
	}
	if b, ok := hexDecodeLoose("zz"); ok || b != nil {
		t.Fatalf("bad nibbles: %x %v", b, ok)
	}
	for _, c := range []struct {
		c    byte
		want byte
		ok   bool
	}{{'0', 0, true}, {'9', 9, true}, {'a', 10, true}, {'A', 10, true}, {'F', 15, true}, {'g', 0, false}, {'G', 0, false}} {
		if v, ok := hexNibble(c.c); v != c.want || ok != c.ok {
			t.Fatalf("hexNibble(%c) = %d %v", c.c, v, ok)
		}
	}
	if ms, ok := jsDateParse("nope"); ms != 0 || ok {
		t.Fatalf("jsDateParse(nope) = %d %v", ms, ok)
	}
	if ms, ok := jsDateParse("2025-01-01T00:00:00Z"); ms != g06TU || !ok {
		t.Fatalf("jsDateParse = %d %v", ms, ok)
	}
	issueOnly := map[string]any{"issueDate": "2025-01-01T00:00:00Z"}
	if got := checkFresh(issueOnly, "X", g06TU+1); got != "X: issueDate/nextUpdate missing" {
		t.Fatalf("issue only: %q", got)
	}
	both := map[string]any{"issueDate": "2025-01-01T00:00:00Z", "nextUpdate": "2030-01-01T00:00:00Z"}
	if got := checkFresh(both, "X", g06TU); got != "" {
		t.Fatalf("now == issueDate: %q", got)
	}
	if got := checkFresh(both, "X", g06TU-1); got != "X: issueDate is in the future" {
		t.Fatalf("before issueDate: %q", got)
	}
}

// ───────────────────────────────────────────────────────────── status units

func TestK05G06StatusUnits(t *testing.T) {
	if statusRank("nope") != -1 || statusRank("UpToDate") != 0 {
		t.Fatal("statusRank")
	}
	if worstStatus("x", "y") != "x" || worstStatus("UpToDate", "OutOfDate") != "OutOfDate" {
		t.Fatal("worstStatus")
	}
	if b, ok := hexBytesN("ab", 2); ok || b != nil {
		t.Fatalf("short hex: %x %v", b, ok)
	}
	if b, ok := hexBytesN("abcd", 2); !ok || !bytes.Equal(b, []byte{0xab, 0xcd}) {
		t.Fatalf("hex: %x %v", b, ok)
	}
	if out, ok := svnList(g06svns(1)[:15]); ok || out != nil {
		t.Fatalf("15 components: %v %v", out, ok)
	}
	notRec := g06svns(1)
	notRec[3] = "s"
	if out, ok := svnList(notRec); ok || out != nil {
		t.Fatalf("non-record component: %v %v", out, ok)
	}
	notNum := g06svns(1)
	notNum[5] = map[string]any{"svn": "x"}
	if out, ok := svnList(notNum); ok || out != nil {
		t.Fatalf("non-numeric svn: %v %v", out, ok)
	}
	if out, ok := svnList(g06svns(4)); !ok || len(out) != 16 || out[15] != 4 {
		t.Fatalf("16 components: %v %v", out, ok)
	}
}

func g06svns(v float64) []any {
	out := make([]any, 16)
	for i := range out {
		out[i] = map[string]any{"svn": v}
	}
	return out
}

func g06level(sgx, tdx []any, pce any, status string, adv ...string) map[string]any {
	advs := make([]any, len(adv))
	for i, a := range adv {
		advs[i] = a
	}
	return map[string]any{"tcb": map[string]any{"sgxtcbcomponents": sgx, "tdxtcbcomponents": tdx, "pcesvn": pce}, "tcbStatus": status, "advisoryIDs": advs}
}

func g06module(mr string) map[string]any {
	return map[string]any{"mrsigner": mr, "attributes": "0000000000000000", "attributesMask": "FFFFFFFFFFFFFFFF"}
}

var g06mr = strings.Repeat("11", 48)

type g06tdx struct {
	sgx      []byte
	pcesvn   int
	tee      []byte
	mrSigner []byte
	attr     []byte
}

func g06tdxIn() g06tdx {
	return g06tdx{sgx: bytes.Repeat([]byte{2}, 16), pcesvn: 10, tee: make([]byte, 16), mrSigner: bytes.Repeat([]byte{0x11}, 48), attr: make([]byte, 8)}
}

func (in g06tdx) eval(info map[string]any) tcbEval {
	return evaluateTcb(info, in.sgx, in.pcesvn, in.tee, in.mrSigner, in.attr)
}

func g06with(svns []any, i int, v float64) []any {
	out := append([]any{}, svns...)
	out[i] = map[string]any{"svn": v}
	return out
}

func TestK05G06EvaluateTcbComponents(t *testing.T) {
	in := g06tdxIn()
	// minor 0: every TDX component is compared, index 0 included
	info := map[string]any{"tdxModule": g06module(g06mr), "tcbLevels": []any{
		g06level(g06svns(2), g06with(g06svns(0), 0, 1), 10.0, "UpToDate"),
		g06level(g06svns(2), g06svns(0), 10.0, "OutOfDate"),
	}}
	if r := in.eval(info); r.err != "" || r.platform != "OutOfDate" || r.module != "UpToDate" {
		t.Fatalf("minor 0, component 0: %+v", r)
	}
	// SGX and TDX component 15 are compared
	info["tcbLevels"] = []any{g06level(g06with(g06svns(2), 15, 3), g06svns(0), 10.0, "UpToDate"), g06level(g06svns(0), g06svns(0), 10.0, "OutOfDate")}
	if r := in.eval(info); r.err != "" || r.platform != "OutOfDate" {
		t.Fatalf("SGX component 15: %+v", r)
	}
	info["tcbLevels"] = []any{g06level(g06svns(2), g06with(g06svns(0), 15, 1), 10.0, "UpToDate"), g06level(g06svns(0), g06svns(0), 10.0, "OutOfDate")}
	if r := in.eval(info); r.err != "" || r.platform != "OutOfDate" {
		t.Fatalf("TDX component 15: %+v", r)
	}
	// the level advisories come back sorted
	var adv []string
	for i := 11; i >= 0; i-- {
		adv = append(adv, fmt.Sprintf("INTEL-SA-%05d", i))
	}
	info["tcbLevels"] = []any{g06level(g06svns(2), g06svns(0), 10.0, "UpToDate", adv...)}
	r := in.eval(info)
	want := append([]string{}, adv...)
	for i, j := 0, len(want)-1; i < j; i, j = i+1, j-1 {
		want[i], want[j] = want[j], want[i]
	}
	if r.err != "" || !reflect.DeepEqual(r.advisories, want) {
		t.Fatalf("advisories: %+v", r)
	}
}

func TestK05G06EvaluateTcbModuleIdentity(t *testing.T) {
	in := g06tdxIn()
	in.tee[0], in.tee[1] = 3, 1 // module SVN 3, minor 1: TDX_01
	ident := func(id, mr string) map[string]any {
		m := g06module(mr)
		m["id"] = id
		m["tcbLevels"] = []any{map[string]any{"tcb": map[string]any{"isvsvn": 2.0}, "tcbStatus": "SWHardeningNeeded", "advisoryIDs": []any{"INTEL-SA-00100"}}}
		return m
	}
	ids := []any{ident("TDX_02", strings.Repeat("33", 48)), ident("TDX_01", g06mr)}
	// TDX components 0 and 1 (the module's) are skipped: a level demanding 5 there still matches
	tdx := g06with(g06with(g06svns(0), 0, 5), 1, 5)
	info := map[string]any{"tdxModuleIdentities": ids, "tcbLevels": []any{g06level(g06svns(2), tdx, 10.0, "UpToDate", "INTEL-SA-00200")}}
	r := in.eval(info)
	if r.err != "" || r.platform != "UpToDate" || r.module != "SWHardeningNeeded" || !reflect.DeepEqual(r.advisories, []string{"INTEL-SA-00100", "INTEL-SA-00200"}) {
		t.Fatalf("module identity: %+v", r)
	}
	// TDX component 2 is compared
	info["tcbLevels"] = []any{g06level(g06svns(2), g06with(g06svns(0), 2, 1), 10.0, "UpToDate"), g06level(g06svns(2), g06svns(0), 10.0, "OutOfDate")}
	if r := in.eval(info); r.err != "" || r.platform != "OutOfDate" {
		t.Fatalf("module path, component 2: %+v", r)
	}
}

func TestK05G06EvaluateTcbMalformed(t *testing.T) {
	in := g06tdxIn()
	for _, field := range []string{"mrsigner", "attributes", "attributesMask"} {
		m := g06module(g06mr)
		m[field] = "zz"
		info := map[string]any{"tdxModule": m, "tcbLevels": []any{g06level(g06svns(2), g06svns(0), 10.0, "UpToDate")}}
		if r := in.eval(info); r.err != "TDX module identity fields malformed" {
			t.Fatalf("%s: %+v", field, r)
		}
	}
	for _, lvl := range []any{"x", map[string]any{"tcb": "x"}} {
		if r := in.eval(map[string]any{"tdxModule": g06module(g06mr), "tcbLevels": []any{lvl}}); r.err != "malformed TCB level" {
			t.Fatalf("level %v: %+v", lvl, r)
		}
	}
	if l := findLevel([]any{"x", map[string]any{"tcb": "x"}, map[string]any{"tcb": map[string]any{"isvsvn": 1.0}}}, 1); l == nil || l["tcb"] == nil {
		t.Fatalf("findLevel skips non-records: %v", l)
	}
	for i, lvl := range []map[string]any{
		g06level(nil, g06svns(0), 10.0, "UpToDate"),
		g06level(g06svns(2), nil, 10.0, "UpToDate"),
		g06level(g06svns(2), g06svns(0), "x", "UpToDate"),
	} {
		info := map[string]any{"tdxModule": g06module(g06mr), "tcbLevels": []any{lvl}}
		if r := in.eval(info); r.err != "malformed TCB level components" {
			t.Fatalf("level %d: %+v", i, r)
		}
	}
}

func g06qlvl(svn float64, st string) map[string]any {
	return map[string]any{"tcb": map[string]any{"isvsvn": svn}, "tcbStatus": st}
}

func g06qeIdentMap() map[string]any {
	return map[string]any{"id": "TD_QE", "version": 2.0, "miscselect": "01020304", "miscselectMask": "FFFFFFFF",
		"attributes": strings.Repeat("00", 15) + "05", "attributesMask": strings.Repeat("FF", 16), "mrsigner": strings.Repeat("22", 32), "isvprodid": float64(0x0102),
		"tcbLevels": []any{g06qlvl(512, "SWHardeningNeeded"), g06qlvl(256, "UpToDate"), g06qlvl(128, "ConfigurationNeeded"), g06qlvl(0, "OutOfDate")}}
}

func g06qeReport() []byte {
	q := make([]byte, dcapSgxReport)
	copy(q[16:20], []byte{1, 2, 3, 4})
	q[63] = 5
	copy(q[128:160], bytes.Repeat([]byte{0x22}, 32))
	q[256], q[257] = 0x02, 0x01 // ISVPRODID 0x0102
	q[258], q[259] = 0x00, 0x01 // ISVSVN 0x0100
	return q
}

func TestK05G06EvaluateQe(t *testing.T) {
	if r := evaluateQe(g06qeIdentMap(), g06qeReport()); r.err != "" || r.status != "UpToDate" {
		t.Fatalf("whole: %+v", r)
	}
	for _, c := range []struct {
		name string
		edit func(q []byte) []byte
		want string
	}{
		{"short report", func(q []byte) []byte { return q[:383] }, "QE report has wrong length"},
		{"MISCSELECT byte 19", func(q []byte) []byte { q[19] = 9; return q }, "QE MISCSELECT does not match the QE identity"},
		{"ATTRIBUTES byte 63", func(q []byte) []byte { q[63] = 6; return q }, "QE ATTRIBUTES do not match the QE identity"},
	} {
		if r := evaluateQe(g06qeIdentMap(), c.edit(g06qeReport())); r.err != c.want {
			t.Fatalf("%s: %+v", c.name, r)
		}
	}
	for _, field := range []string{"miscselect", "miscselectMask", "attributes", "attributesMask", "mrsigner", "isvprodid"} {
		id := g06qeIdentMap()
		id[field] = "zz"
		if r := evaluateQe(id, g06qeReport()); r.err != "QE identity fields malformed" {
			t.Fatalf("%s: %+v", field, r)
		}
	}
}
