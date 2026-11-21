package pca

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

// g08: kills for attest_intel.go. The DCAP quote layout, the lenient DER reader and the SGX-extension byte scan are driven
// directly; a self-contained genuine TDX quote (generated root + PCK leaf carrying an SGX extension, QE report signed by the
// leaf, attestation key endorsed by the QE, quote signed by the AK) drives verifyGenuineTdxQuote / verifyIntelPckChain.

var (
	g08nb  = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	g08na  = time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC)
	g08now = time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC).UnixMilli()
)

// ---- DCAP quote layout ----------------------------------------------------------------------------------------------

func g08DcapQuote(sig []byte) []byte {
	le := binary.LittleEndian
	q := make([]byte, dcapHeaderLen+dcapTdReportLen+4)
	le.PutUint16(q[0:], 4)
	le.PutUint16(q[2:], 2)
	le.PutUint32(q[4:], 0x81)
	le.PutUint32(q[dcapHeaderLen+dcapTdReportLen:], uint32(len(sig)))
	return append(q, sig...)
}

// g08DcapSig is the signature data: quote sig + AK (128), outer header (6), QE report + sig (448), auth size 0 (2), inner
// header (6), inner bytes.
func g08DcapSig(outerSize uint32, inner []byte) []byte {
	le := binary.LittleEndian
	s := make([]byte, 128)
	h := make([]byte, 6)
	le.PutUint16(h, 6)
	le.PutUint32(h[2:], outerSize)
	s = append(s, h...)
	s = append(s, make([]byte, dcapSgxReport+64)...)
	s = append(s, 0, 0)
	h2 := make([]byte, 6)
	le.PutUint16(h2, 5)
	le.PutUint32(h2[2:], uint32(len(inner)))
	s = append(s, h2...)
	return append(s, inner...)
}

func TestK05KillG08DcapParse(t *testing.T) {
	errOf := func(q []byte) string {
		_, err := parseDcapQuote(q)
		if err == nil {
			return ""
		}
		return err.Error()
	}
	g08Eq(t, "635", errOf(g08DcapQuote(nil)[:635]), "parseDcapQuote: too short for header + TD report + sig length")
	g08Eq(t, "636", errOf(g08DcapQuote(nil)), "parseDcapQuote: truncated reading quote signature")
	z := g08DcapSig(0, nil)
	const tr = "parseDcapQuote: truncated reading "
	for _, c := range []struct {
		n    int
		what string
	}{
		{63, "quote signature"}, {127, "attestation public key"}, {128, "outer cert-data header"}, {133, "outer cert-data header"},
		{134, "QE report"}, {517, "QE report"}, {518, "QE report signature"}, {581, "QE report signature"},
		{582, "QE auth-data size"}, {583, "QE auth-data size"}, {584, "inner cert-data header"}, {589, "inner cert-data header"},
	} {
		g08Eq(t, "truncated", errOf(g08DcapQuote(z[:c.n])), tr+c.what)
	}
	q, err := parseDcapQuote(g08DcapQuote(g08DcapSig(dcapSgxReport+64+2+6+3, []byte("PEM"))))
	if err != nil || q.pckChainPem != "PEM" || len(q.qeReportBody) != dcapSgxReport || len(q.qeAuthData) != 0 {
		t.Fatalf("full parse: %v %+v", err, q)
	}
	q, err = parseDcapQuote(g08DcapQuote(g08DcapSig(dcapSgxReport+64+2+6, nil)))
	if err != nil || q.pckChainPem != "" {
		t.Fatalf("empty chain parse: %v", err)
	}
}

// ---- lenient DER / byte scan ----------------------------------------------------------------------------------------

func TestK05KillG08DerTlvLenient(t *testing.T) {
	long256 := append([]byte{0x04, 0x82, 0x01, 0x00}, make([]byte, 256)...)
	for _, c := range []struct {
		name       string
		buf        []byte
		off        int
		ok         bool
		start, end int
	}{
		{"neg off", []byte{0x04, 0x00}, -1, false, 0, 0},
		{"empty at 0", []byte{0x04, 0x00}, 0, true, 2, 2},
		{"off past", []byte{0x04, 0x00}, 1, false, 0, 0},
		{"one byte", []byte{0x04}, 0, false, 0, 0},
		{"short form fits", []byte{0x04, 0x01, 0xaa}, 0, true, 2, 3},
		{"short form overruns", []byte{0x04, 0x05, 0xaa}, 0, false, 0, 0},
		{"long 0x80", []byte{0x04, 0x80, 0xaa}, 0, false, 0, 0},
		{"long n=1", []byte{0x04, 0x81, 0x01, 0xaa}, 0, true, 3, 4},
		{"long n=1 exact", []byte{0x04, 0x81, 0x00}, 0, true, 3, 3},
		{"long n=2 truncated", []byte{0x04, 0x82, 0x01}, 0, false, 0, 0},
		{"long n=4", []byte{0x04, 0x84, 0, 0, 0, 1, 0xaa}, 0, true, 6, 7},
		{"long n=5", []byte{0x04, 0x85, 0, 0, 0, 0, 1, 0xaa}, 0, false, 0, 0},
		{"long 256", long256, 0, true, 4, 260},
	} {
		got, ok := readDerTlvLenient(c.buf, c.off)
		if ok != c.ok || (ok && (got.tag != 0x04 || got.start != c.start || got.end != c.end)) {
			t.Errorf("%s: got %+v ok=%v", c.name, got, ok)
		}
	}
	for _, c := range []struct {
		hay, needle string
		want        int
	}{{"abc", "c", 2}, {"abc", "a", 0}, {"abc", "abc", 0}, {"abc", "z", -1}, {"ab", "abc", -1}} {
		if got := indexOfBytes([]byte(c.hay), []byte(c.needle)); got != c.want {
			t.Errorf("indexOfBytes(%q, %q) = %d, want %d", c.hay, c.needle, got, c.want)
		}
	}
}

func g08Comp(k byte, val []byte) []byte {
	return derTLV(0x30, derTLV(0x06, []byte{0x2a, k}), derTLV(0x02, val))
}

var g08Fmspc = derTLV(0x04, []byte{1, 2, 3, 4, 5, 6})

func g08FmspcFirst(fmspc []byte, tcbTag byte, comps ...[]byte) []byte {
	out := append(append([]byte{}, oidSgxFmspc...), fmspc...)
	out = append(out, oidSgxTcb...)
	return append(out, derTLV(tcbTag, comps...)...)
}

func g08Fillers(n int) [][]byte {
	out := make([][]byte, n)
	for i := range out {
		out[i] = g08Comp(0x20, []byte{1})
	}
	return out
}

func TestK05KillG08SgxExtension(t *testing.T) {
	errOf := func(leaf []byte) string {
		_, err := extractPckFmspcAndTcb(leaf)
		if err == nil {
			return ""
		}
		return err.Error()
	}
	octet17 := derTLV(0x30, derTLV(0x06, []byte{0x2a, 17}), derTLV(0x04, []byte{9}))
	full := g08FmspcFirst(g08Fmspc, 0x30, g08Comp(1, []byte{7}), g08Comp(16, []byte{9}), g08Comp(0, []byte{3}),
		g08Comp(17, []byte{1, 2}), g08Comp(0x20, []byte{0x7f}), octet17)
	tcb, err := extractPckFmspcAndTcb(full)
	if err != nil {
		t.Fatalf("full: %v", err)
	}
	wantSgx := make([]byte, 16)
	wantSgx[0], wantSgx[15] = 7, 9
	if !bytes.Equal(tcb.fmspc, []byte{1, 2, 3, 4, 5, 6}) || !bytes.Equal(tcb.sgx, wantSgx) || tcb.pcesvn != 0x0102 {
		t.Fatalf("full: %+v", tcb)
	}
	// the TCB OID first, PCESVN 0.
	tcbFirst := append(append([]byte{}, oidSgxTcb...), derTLV(0x30, g08Comp(17, []byte{0}))...)
	tcbFirst = append(append(tcbFirst, oidSgxFmspc...), g08Fmspc...)
	if tcb, err := extractPckFmspcAndTcb(tcbFirst); err != nil || tcb.pcesvn != 0 {
		t.Fatalf("tcb first: %v %+v", err, tcb)
	}
	pce := g08Comp(17, []byte{5})
	const pre = "extractPckFmspcAndTcb: "
	g08Eq(t, "fmspc tag", errOf(g08FmspcFirst(derTLV(0x05, []byte{1, 2, 3, 4, 5, 6}), 0x30, pce)), pre+"malformed FMSPC OCTET STRING")
	g08Eq(t, "fmspc len", errOf(g08FmspcFirst(derTLV(0x04, []byte{1, 2, 3, 4, 5}), 0x30, pce)), pre+"malformed FMSPC OCTET STRING")
	g08Eq(t, "seq tag", errOf(g08FmspcFirst(g08Fmspc, 0x31, pce)), pre+"malformed TCB SEQUENCE")
	g08Eq(t, "pair tag", errOf(g08FmspcFirst(g08Fmspc, 0x30, derTLV(0x31, derTLV(0x06, []byte{0x2a, 17}), derTLV(0x02, []byte{5})))),
		pre+"malformed TCB component")
	g08Eq(t, "oid tag", errOf(g08FmspcFirst(g08Fmspc, 0x30, derTLV(0x30, derTLV(0x05, []byte{0x2a, 17}), derTLV(0x02, []byte{5})))),
		pre+"TCB component missing OID")
	g08Eq(t, "value missing", errOf(g08FmspcFirst(g08Fmspc, 0x30, pce, derTLV(0x30, derTLV(0x06, []byte{0x2a, 0x20})))),
		pre+"TCB component missing value")
	g08Eq(t, "no pcesvn", errOf(g08FmspcFirst(g08Fmspc, 0x30, g08Comp(1, []byte{1}))), pre+"PCESVN not found in TCB extension")
	// at most 65 components are read: PCESVN as the 65th is seen, as the 66th it is not.
	g08Eq(t, "pce 65th", errOf(g08FmspcFirst(g08Fmspc, 0x30, append(g08Fillers(64), pce)...)), "")
	g08Eq(t, "pce 66th", errOf(g08FmspcFirst(g08Fmspc, 0x30, append(g08Fillers(65), pce)...)), pre+"PCESVN not found in TCB extension")
}

// ---- generated certificates and a genuine quote ---------------------------------------------------------------------

func g08Key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func g08MakeCert(t *testing.T, tmpl, parent *x509.Certificate, pub any, signer *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
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

func g08CATmpl(cn string, serial int64) *x509.Certificate {
	return &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn}, NotBefore: g08nb, NotAfter: g08na,
		BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
}

func g08PEM(ders ...[]byte) string {
	var sb strings.Builder
	for _, d := range ders {
		sb.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: d}))
	}
	return sb.String()
}

func g08Pin(c *x509.Certificate) string {
	s := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(s[:])
}

func g08Compact(t *testing.T, k *ecdsa.PrivateKey, msg []byte) []byte {
	t.Helper()
	r, s, err := ecdsa.Sign(rand.Reader, k, sha256Sum(msg))
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return sig
}

type g08Tdx struct {
	pckKey, akKey *ecdsa.PrivateKey
	root, pck     *x509.Certificate
	pin           string
}

func g08NewTdx(t *testing.T) *g08Tdx {
	t.Helper()
	rootKey := g08Key(t)
	f := &g08Tdx{pckKey: g08Key(t), akKey: g08Key(t)}
	f.root = g08MakeCert(t, g08CATmpl("g08 root", 1), g08CATmpl("g08 root", 1), &rootKey.PublicKey, rootKey)
	ext := g08FmspcFirst(g08Fmspc, 0x30, g08Comp(1, []byte{2}), g08Comp(17, []byte{10}))
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "g08 pck"}, NotBefore: g08nb, NotAfter: g08na,
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 840, 113741, 1, 13, 1}, Value: ext}}}
	f.pck = g08MakeCert(t, leaf, f.root, &f.pckKey.PublicKey, rootKey)
	f.pin = g08Pin(f.root)
	return f
}

// quote builds a genuine quote; editQE edits the QE report before the PCK leaf signs it.
func (f *g08Tdx) quote(t *testing.T, editQE func(qe []byte)) []byte {
	t.Helper()
	le := binary.LittleEndian
	hdr := make([]byte, dcapHeaderLen)
	le.PutUint16(hdr[0:], 4)
	le.PutUint16(hdr[2:], 2)
	le.PutUint32(hdr[4:], 0x81)
	body := make([]byte, dcapTdReportLen)
	ak := make([]byte, 64)
	f.akKey.X.FillBytes(ak[:32])
	f.akKey.Y.FillBytes(ak[32:])
	qe := make([]byte, dcapSgxReport)
	copy(qe[dcapQeRdataOff:], sha256Sum(ak)) // empty QE auth data
	if editQE != nil {
		editQE(qe)
	}
	chain := g08PEM(f.pck.Raw, f.root.Raw)
	inner := make([]byte, 6)
	le.PutUint16(inner[0:], 5)
	le.PutUint32(inner[2:], uint32(len(chain)))
	inner = append(inner, chain...)
	ob := append(append(append([]byte{}, qe...), g08Compact(t, f.pckKey, qe)...), 0, 0)
	ob = append(ob, inner...)
	outer := make([]byte, 6)
	le.PutUint16(outer[0:], 6)
	le.PutUint32(outer[2:], uint32(len(ob)))
	sig := append(append(g08Compact(t, f.akKey, append(append([]byte{}, hdr...), body...)), ak...), outer...)
	sig = append(sig, ob...)
	sl := make([]byte, 4)
	le.PutUint32(sl, uint32(len(sig)))
	out := append(append(append([]byte{}, hdr...), body...), sl...)
	return append(out, sig...)
}

func TestK05KillG08GenuineTdxQuote(t *testing.T) {
	f := g08NewTdx(t)
	q := f.quote(t, nil)
	r := verifyGenuineTdxQuote(q, f.pin, g08now, nil, false)
	if !r.ok || r.fmspc != "010203040506" || r.pck == nil || r.pck.pcesvn != 10 {
		t.Fatalf("genuine quote refused: %+v", r)
	}
	// an empty MRTD allowlist does not filter.
	if r := verifyGenuineTdxQuote(q, f.pin, g08now, &tdxQuotePolicy{}, false); !r.ok {
		t.Fatalf("empty policy: %q", r.reason)
	}
	if r := verifyGenuineTdxQuote(q, f.pin, g08now, &tdxQuotePolicy{mrtds: []string{strings.Repeat("00", 48)}}, false); !r.ok {
		t.Fatalf("listed MRTD: %q", r.reason)
	}
	if r := verifyGenuineTdxQuote(q, f.pin, g08now, &tdxQuotePolicy{mrtds: []string{strings.Repeat("ff", 48)}}, false); r.ok || r.reason != "MRTD not in policy allowlist" {
		t.Fatalf("unlisted MRTD: %+v", r)
	}
	// the upper half of the QE report_data must be zero, from its first byte.
	bad := f.quote(t, func(qe []byte) { qe[dcapQeRdataOff+32] = 1 })
	if r := verifyGenuineTdxQuote(bad, f.pin, g08now, nil, false); r.ok || r.reason != "QE report_data does not bind the attestation key (AK not endorsed by this QE)" {
		t.Fatalf("non-zero report_data[32]: %+v", r)
	}
}

func TestK05KillG08P256Compact(t *testing.T) {
	k := g08Key(t)
	msg := []byte("g08 message")
	sig := g08Compact(t, k, msg)
	if !verifyP256Compact(msg, sig, &k.PublicKey) {
		t.Fatal("valid compact signature refused")
	}
	// the same (r, s) zero-padded to 66 bytes is a valid raw signature, but not a 64-byte compact one.
	padded := append(append(append([]byte{0}, sig[:32]...), 0), sig[32:]...)
	if !verifyRawECDSA(&k.PublicKey, sha256Sum(msg), padded) {
		t.Fatal("fixture: padded raw signature should verify")
	}
	if verifyP256Compact(msg, padded, &k.PublicKey) {
		t.Error("66-byte signature accepted")
	}
}

func TestK05KillG08PckChain(t *testing.T) {
	rootKey := g08Key(t)
	root := g08MakeCert(t, g08CATmpl("g08 lone root", 7), g08CATmpl("g08 lone root", 7), &rootKey.PublicKey, rootKey)
	pin := g08Pin(root)
	pemRoot := g08PEM(root.Raw)
	// validity: valid at NotAfter, not one millisecond later.
	if r := verifyIntelPckChain(pemRoot, pin, g08na.UnixMilli()); !r.ok {
		t.Fatalf("at NotAfter: %q", r.reason)
	}
	if r := verifyIntelPckChain(pemRoot, pin, g08na.UnixMilli()+1); r.ok || !r.validity || r.reason != "PCK chain certificate outside its validity period" {
		t.Fatalf("after NotAfter: %+v", r)
	}
	// a critical flag encoded 0x01 (BER, not DER) is a parse error of the critical-extension check.
	var c struct {
		TBS asn1.RawValue
		Alg asn1.RawValue
		Sig asn1.BitString
	}
	if _, err := asn1.Unmarshal(root.Raw, &c); err != nil {
		t.Fatal(err)
	}
	tbs := append([]byte{}, c.TBS.FullBytes...)
	bc := []byte{0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff}
	i := bytes.Index(tbs, bc)
	if i < 0 {
		t.Fatal("fixture: no critical BasicConstraints in the TBS")
	}
	tbs[i+len(bc)-1] = 0x01
	sig, err := ecdsa.SignASN1(rand.Reader, rootKey, sha256Sum(tbs))
	if err != nil {
		t.Fatal(err)
	}
	patched, err := asn1.Marshal(struct {
		TBS asn1.RawValue
		Alg asn1.RawValue
		Sig asn1.BitString
	}{asn1.RawValue{FullBytes: tbs}, c.Alg, asn1.BitString{Bytes: sig, BitLength: 8 * len(sig)}})
	if err != nil {
		t.Fatal(err)
	}
	r := verifyIntelPckChain(g08PEM(patched), pin, g08now)
	if r.ok || r.reason != "PCK chain X.509 verification error (fail closed): extension 2.5.29.19 has a non-DER critical flag" {
		t.Fatalf("BER critical flag: %+v", r)
	}
	// two certificates issuing each other: the walk stops at the repeat, no self-signed root.
	ka, kb := g08Key(t), g08Key(t)
	ta := &x509.Certificate{SerialNumber: big.NewInt(10), Subject: pkix.Name{CommonName: "g08 A"}, NotBefore: g08nb, NotAfter: g08na}
	tb := &x509.Certificate{SerialNumber: big.NewInt(11), Subject: pkix.Name{CommonName: "g08 B"}, NotBefore: g08nb, NotAfter: g08na}
	ca := g08MakeCert(t, ta, tb, &ka.PublicKey, kb)
	cb := g08MakeCert(t, tb, ta, &kb.PublicKey, ka)
	if r := verifyIntelPckChain(g08PEM(ca.Raw, cb.Raw), pin, g08now); r.ok || r.reason != "PCK chain does not terminate in a self-signed root" {
		t.Fatalf("issuer cycle: %+v", r)
	}
}

func TestK05KillG08DcapVerifierConfig(t *testing.T) {
	m96 := strings.Repeat("ab", 48)
	for _, entry := range []string{"aa", strings.Repeat("z", 96)} {
		_, err := newDcapVerifier(map[string]any{"binding": "report-data", "policy": map[string]any{"mrtds": []any{m96}, "mrSeams": []any{entry}}})
		if err == nil || err.Error() != "createIntelDcapVerifier: every mrSeams entry must be 96 hex chars (48 bytes)" {
			t.Errorf("mrSeams %q: %v", entry, err)
		}
	}
	if _, err := newDcapVerifier(map[string]any{"binding": "report-data", "policy": map[string]any{"mrtds": []any{m96}, "mrSeams": []any{m96}}}); err != nil {
		t.Errorf("valid mrSeams: %v", err)
	}
}
