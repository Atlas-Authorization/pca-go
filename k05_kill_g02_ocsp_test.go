package pca

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"strconv"
	"strings"
	"testing"
	"time"
)

// NVIDIA device-chain OCSP (attest_nvidia_ocsp.go): every response here is built byte by byte (RFC 6960 structure, signed
// with generated P-256 keys), so each row pins one rule of the verifier with its exact reason.

var (
	g02now     = time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	g02good    = []byte{0x80, 0x00}
	g02unknown = []byte{0x82, 0x00}
)

func g02oid(dotted string) []byte {
	var oid asn1.ObjectIdentifier
	for _, p := range strings.Split(dotted, ".") {
		n, err := strconv.Atoi(p)
		if err != nil {
			panic(err)
		}
		oid = append(oid, n)
	}
	b, err := asn1.Marshal(oid)
	if err != nil {
		panic(err)
	}
	return b
}

func g02gt(t time.Time) []byte { return derTLV(0x18, []byte(t.UTC().Format("20060102150405Z"))) }

func g02gts(s string) []byte { return derTLV(0x18, []byte(s)) }

func g02sha1(b []byte) []byte {
	s := sha1.Sum(b)
	return s[:]
}

func g02key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// g02bits is the subjectPublicKey BIT STRING content of a SubjectPublicKeyInfo, read with encoding/asn1 (independent of the SDK).
func g02bits(t *testing.T, spki []byte) []byte {
	t.Helper()
	var s struct {
		Algo asn1.RawValue
		Bits asn1.BitString
	}
	if _, err := asn1.Unmarshal(spki, &s); err != nil {
		t.Fatal(err)
	}
	return s.Bits.Bytes
}

func g02mk(t *testing.T, tmpl, parent *x509.Certificate, pub *ecdsa.PublicKey, signer *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	if tmpl.NotBefore.IsZero() {
		tmpl.NotBefore = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	if tmpl.NotAfter.IsZero() {
		tmpl.NotAfter = time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC)
	}
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

func g02att(t *testing.T, der []byte) *attCert {
	t.Helper()
	a, err := parseCertDER(der)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

type g02fx struct {
	rootK, interK, leafK, respK, otherK *ecdsa.PrivateKey
	root, inter, leaf                   *x509.Certificate
	rootA, interA, leafA                *attCert
	chain                               []*attCert
	nowMs                               int64
}

// g02newFx: root -> inter -> leaf (the leaf advertises an OCSP responder; inter does not).
func g02newFx(t *testing.T) *g02fx {
	t.Helper()
	f := &g02fx{rootK: g02key(t), interK: g02key(t), leafK: g02key(t), respK: g02key(t), otherK: g02key(t), nowMs: g02now.UnixMilli()}
	f.root = g02mk(t, &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "g02 root"}, BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign}, nil, &f.rootK.PublicKey, f.rootK)
	f.inter = g02mk(t, &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "g02 inter"}, BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign}, f.root, &f.interK.PublicKey, f.rootK)
	f.leaf = g02mk(t, &x509.Certificate{SerialNumber: big.NewInt(0x1234), Subject: pkix.Name{CommonName: "g02 leaf"}, OCSPServer: []string{"http://ocsp.example/"}}, f.inter, &f.leafK.PublicKey, f.interK)
	f.rootA, f.interA, f.leafA = g02att(t, f.root.Raw), g02att(t, f.inter.Raw), g02att(t, f.leaf.Raw)
	f.chain = []*attCert{f.leafA, f.interA, f.rootA}
	return f
}

// responder is a delegated OCSP responder certificate for respK (id-kp-OCSPSigning unless mod drops it).
func (f *g02fx) responder(t *testing.T, mod func(*x509.Certificate), parent *x509.Certificate, signer *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(77), Subject: pkix.Name{CommonName: "g02 ocsp responder"},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}, KeyUsage: x509.KeyUsageDigitalSignature}
	if mod != nil {
		mod(tmpl)
	}
	return g02mk(t, tmpl, parent, &f.respK.PublicKey, signer)
}

func g02certID(t *testing.T, issuer *attCert, serial *big.Int) []byte {
	t.Helper()
	ser, err := asn1.Marshal(serial)
	if err != nil {
		t.Fatal(err)
	}
	return derTLV(0x30, derTLV(0x30, g02oid("1.3.14.3.2.26"), []byte{0x05, 0x00}), derTLV(0x04, g02sha1(issuer.RawSubject)),
		derTLV(0x04, g02sha1(g02bits(t, issuer.RawSPKI))), ser)
}

func g02single(certID, status, this []byte, extra ...[]byte) []byte {
	return derTLV(0x30, append([][]byte{certID, status, this}, extra...)...)
}

func g02byName(c *attCert) []byte { return derTLV(0xa1, c.RawSubject) }

func g02byKey(t *testing.T, c *attCert) []byte {
	t.Helper()
	return derTLV(0xa2, derTLV(0x04, g02sha1(g02bits(t, c.RawSPKI))))
}

func g02certs(ders ...[]byte) []byte { return derTLV(0xa0, derTLV(0x30, ders...)) }

type g02rsp struct {
	version   bool
	rid       []byte
	produced  []byte
	singles   [][]byte
	responses []byte // overrides SEQUENCE OF singles when set
	signer    *ecdsa.PrivateKey
	certs     []byte
}

func (r g02rsp) basic(t *testing.T) []byte {
	t.Helper()
	var parts [][]byte
	if r.version {
		parts = append(parts, derTLV(0xa0, derTLV(0x02, []byte{0})))
	}
	responses := r.responses
	if responses == nil {
		responses = derTLV(0x30, r.singles...)
	}
	parts = append(parts, r.rid, r.produced, responses)
	tbs := derTLV(0x30, parts...)
	h := sha256.Sum256(tbs)
	sig, err := ecdsa.SignASN1(rand.Reader, r.signer, h[:])
	if err != nil {
		t.Fatal(err)
	}
	out := [][]byte{tbs, derTLV(0x30, g02oid("1.2.840.10045.4.3.2")), derTLV(0x03, append([]byte{0}, sig...))}
	if r.certs != nil {
		out = append(out, r.certs)
	}
	return derTLV(0x30, out...)
}

func g02outer(responseBytes []byte) []byte {
	return derTLV(0x30, derTLV(0x0a, []byte{0}), derTLV(0xa0, responseBytes))
}

func g02wrapBasic(basic []byte) []byte {
	return g02outer(derTLV(0x30, g02oid(oidOcspBasic), derTLV(0x04, basic)))
}

func (r g02rsp) der(t *testing.T) []byte {
	t.Helper()
	return g02wrapBasic(r.basic(t))
}

// base: a GOOD response for the leaf, signed by its issuer (inter), responderID byName, an hour old, no nextUpdate.
func (f *g02fx) base(t *testing.T) g02rsp {
	t.Helper()
	at := g02now.Add(-time.Hour)
	return g02rsp{rid: g02byName(f.interA), produced: g02gt(at), signer: f.interK,
		singles: [][]byte{g02single(g02certID(t, f.interA, f.leaf.SerialNumber), g02good, g02gt(at))}}
}

func (f *g02fx) mod(t *testing.T, m func(r *g02rsp)) []byte {
	t.Helper()
	r := f.base(t)
	m(&r)
	return r.der(t)
}

func (f *g02fx) fresh(t *testing.T, this, produced time.Time, next ...[]byte) []byte {
	t.Helper()
	return f.mod(t, func(r *g02rsp) {
		r.produced = g02gt(produced)
		r.singles = [][]byte{g02single(g02certID(t, f.interA, f.leaf.SerialNumber), g02good, g02gt(this), next...)}
	})
}

func (f *g02fx) withStatus(t *testing.T, status []byte) []byte {
	t.Helper()
	at := g02now.Add(-time.Hour)
	return f.mod(t, func(r *g02rsp) {
		r.singles = [][]byte{g02single(g02certID(t, f.interA, f.leaf.SerialNumber), status, g02gt(at))}
	})
}

// badNotBeforeResponder is a responder certificate (signed by inter) whose notBefore is UTCTime month 13: the certificate
// parser only checks the tag, the validity reader refuses the value.
func (f *g02fx) badNotBeforeResponder(t *testing.T) []byte {
	t.Helper()
	c := f.responder(t, nil, f.inter, f.interK)
	tbs := append([]byte{}, c.RawTBSCertificate...)
	i := bytes.Index(tbs, []byte("250101000000Z"))
	if i < 0 {
		t.Fatal("notBefore not found")
	}
	copy(tbs[i+2:], "13")
	h := sha256.Sum256(tbs)
	sig, err := ecdsa.SignASN1(rand.Reader, f.interK, h[:])
	if err != nil {
		t.Fatal(err)
	}
	return derTLV(0x30, tbs, derTLV(0x30, g02oid("1.2.840.10045.4.3.2")), derTLV(0x03, append([]byte{0}, sig...)))
}

func g02rej(m string) ocspResult { return ocspResult{reason: "OCSP response rejected: " + m} }

func g02no(m string) ocspResult { return ocspResult{reason: m} }

func g02ok(status string) ocspResult { return ocspResult{ok: true, status: status} }

func TestG02OcspTimeMs(t *testing.T) {
	ms := func(y, mo, d, h, mi, s int) int64 {
		return time.Date(y, time.Month(mo), d, h, mi, s, 0, time.UTC).UnixMilli()
	}
	rows := []struct {
		text string
		utc  bool
		ms   int64
		ok   bool
	}{
		{"260531000000Z", true, ms(2026, 5, 31, 0, 0, 0), true},
		{"490101000000Z", true, ms(2049, 1, 1, 0, 0, 0), true},
		{"500101000000Z", true, ms(1950, 1, 1, 0, 0, 0), true},
		{"20260531010203Z", false, ms(2026, 5, 31, 1, 2, 3), true},
		{"20260101000000Z", false, ms(2026, 1, 1, 0, 0, 0), true},
		{"20261231235959Z", false, ms(2026, 12, 31, 23, 59, 59), true},
		{"20260531000000.5Z", false, ms(2026, 5, 31, 0, 0, 0) + 500, true},
		{"20260531000007.25Z", false, ms(2026, 5, 31, 0, 0, 7) + 250, true},
		{"20260531006000Z", false, 0, false},
		{"20260531000060Z", false, 0, false},
		{"20260431000000Z", false, 0, false},
		{"20260230000000Z", false, 0, false},
		{"garbage", false, 0, false},
		{"260531000000Z", false, 0, false},
	}
	for _, r := range rows {
		got, ok := ocspTimeMs(r.text, r.utc)
		if got != r.ms || ok != r.ok {
			t.Errorf("ocspTimeMs(%q, %v) = %d, %v; want %d, %v", r.text, r.utc, got, ok, r.ms, r.ok)
		}
	}
}

func TestG02OcspDerHelpers(t *testing.T) {
	if _, err := readOcspNode([]byte{0x1f, 0x00}, 0, 2); err == nil || err.Error() != "multi-byte tags are not supported" {
		t.Errorf("multi-byte tag: %v", err)
	}
	if n, err := readOcspNode([]byte{0x30, 0x00}, 0, 2); err != nil || n != (ocspNode{tag: 0x30, hdr: 0, start: 2, end: 2}) {
		t.Errorf("empty SEQUENCE: %+v %v", n, err)
	}
	if _, err := readOcspNode([]byte{0x30}, 0, 1); err == nil || err.Error() != "not valid DER" {
		t.Errorf("truncated: %v", err)
	}
	b := []byte{0x30, 0x03, 0x04, 0x05, 0x00}
	n, err := readOcspNode(b, 0, len(b))
	if err != nil {
		t.Fatal(err)
	}
	if kids, err := ocspKids(b, n); err == nil || err.Error() != "not valid DER" || kids != nil {
		t.Errorf("child overrunning its parent: %v %v", kids, err)
	}

	if _, err := ocspOID([]byte{0x02, 0x01, 0x05}, ocspNode{tag: 0x02, hdr: 0, start: 2, end: 3}); err == nil || err.Error() != "expected an OBJECT IDENTIFIER" {
		t.Errorf("INTEGER as OID: %v", err)
	}
	if s, err := ocspOID([]byte{0x06, 0x00}, ocspNode{tag: 0x06, hdr: 0, start: 2, end: 2}); err == nil || s != "" {
		t.Errorf("empty OID: %q %v", s, err)
	}
	o := g02oid("1.2.3.4")
	if s, err := ocspOID(o, ocspNode{tag: 0x06, hdr: 0, start: 2, end: len(o)}); err != nil || s != "1.2.3.4" {
		t.Errorf("OID: %q %v", s, err)
	}

	wf := func(b []byte) bool {
		n, err := readOcspNode(b, 0, len(b))
		if err != nil {
			t.Fatal(err)
		}
		return ocspTimesWellFormed(b, n)
	}
	wfRows := []struct {
		name string
		b    []byte
		want bool
	}{
		{"UTCTime", derTLV(0x17, []byte("260531000000Z")), true},
		{"UTCTime month 13", derTLV(0x17, []byte("261301000000Z")), false},
		{"GeneralizedTime", derTLV(0x18, []byte("20260531000000Z")), true},
		{"GeneralizedTime month 13", derTLV(0x18, []byte("20261301000000Z")), false},
		{"SEQUENCE with a bad time", derTLV(0x30, derTLV(0x18, []byte("20261301000000Z"))), false},
		{"nested bad UTCTime", derTLV(0x30, derTLV(0x30, derTLV(0x17, []byte("261301000000Z")))), false},
		{"SEQUENCE of good members", derTLV(0x30, derTLV(0x02, []byte{1}), derTLV(0x18, []byte("20260531000000Z"))), true},
		{"constructed with an overrunning child", []byte{0x30, 0x02, 0x04, 0x05}, false},
	}
	for _, r := range wfRows {
		if got := wf(r.b); got != r.want {
			t.Errorf("ocspTimesWellFormed %s = %v, want %v", r.name, got, r.want)
		}
	}

	for _, r := range []struct{ in, want []byte }{
		{[]byte{5, 6}, []byte{5, 6}},
		{[]byte{0, 0}, []byte{0}},
		{[]byte{0, 5}, []byte{5}},
		{[]byte{0, 0, 7}, []byte{7}},
		{[]byte{5}, []byte{5}},
	} {
		if got := stripLeading0(r.in); !bytes.Equal(got, r.want) {
			t.Errorf("stripLeading0(%x) = %x, want %x", r.in, got, r.want)
		}
	}

	if _, err := spkiKeyBits(&attCert{RawSPKI: []byte{0x04, 0x00}}); err == nil || err.Error() != osslWrongTag {
		t.Errorf("SPKI not a SEQUENCE: %v", err)
	}
	if _, err := spkiKeyBits(&attCert{RawSPKI: []byte{0x30, 0x02, 0x05, 0x00}}); err == nil || err.Error() != "malformed SubjectPublicKeyInfo" {
		t.Errorf("SPKI with one member: %v", err)
	}
	f := g02newFx(t)
	if got, err := spkiKeyBits(f.interA); err != nil || !bytes.Equal(got, g02bits(t, f.inter.RawSubjectPublicKeyInfo)) {
		t.Errorf("SPKI bits: %x %v", got, err)
	}
}

func TestG02OcspSigOK(t *testing.T) {
	ek := g02key(t)
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tbs := []byte("g02 tbs")
	h := sha256.Sum256(tbs)
	esig, err := ecdsa.SignASN1(rand.Reader, ek, h[:])
	if err != nil {
		t.Fatal(err)
	}
	rsig, err := rsa.SignPKCS1v15(rand.Reader, rk, crypto.SHA256, h[:])
	if err != nil {
		t.Fatal(err)
	}
	ecK, rsaK, edK := certKey{pub: &ek.PublicKey}, certKey{pub: &rk.PublicKey, typ: "rsa"}, certKey{pub: edPub}
	rows := []struct {
		name string
		alg  string
		sig  []byte
		k    certKey
		want bool
	}{
		{"unknown algorithm", "1.2.3.4", esig, ecK, false},
		{"ecdsa", "1.2.840.10045.4.3.2", esig, ecK, true},
		{"EC key under an RSA algorithm", "1.2.840.113549.1.1.11", esig, ecK, false},
		{"rsa", "1.2.840.113549.1.1.11", rsig, rsaK, true},
		{"RSA key under an ECDSA algorithm", "1.2.840.10045.4.3.2", rsig, rsaK, false},
		{"ed25519 key", "1.2.840.10045.4.3.2", esig, edK, false},
	}
	for _, r := range rows {
		if got := ocspSigOK(r.alg, tbs, r.sig, r.k); got != r.want {
			t.Errorf("ocspSigOK %s = %v, want %v", r.name, got, r.want)
		}
	}
}

func TestG02OcspResponseStructure(t *testing.T) {
	f := g02newFx(t)
	at := g02now.Add(-time.Hour)
	alg := derTLV(0x30, g02oid("1.2.840.10045.4.3.2"))
	cid := g02certID(t, f.interA, f.leaf.SerialNumber)
	single := g02single(cid, g02good, g02gt(at))
	sha1Alg := derTLV(0x30, g02oid("1.3.14.3.2.26"), []byte{0x05, 0x00})
	nameHash, keyHash := derTLV(0x04, g02sha1(f.interA.RawSubject)), derTLV(0x04, g02sha1(g02bits(t, f.interA.RawSPKI)))
	serial, err := asn1.Marshal(f.leaf.SerialNumber)
	if err != nil {
		t.Fatal(err)
	}
	withSingles := func(s ...[]byte) []byte { return f.mod(t, func(r *g02rsp) { r.singles = s }) }
	noMatch := g02no("no SingleResponse matches the certificate (serial / issuer hashes differ)")

	rows := []struct {
		name string
		der  []byte
		want ocspResult
	}{
		{"good by name", f.base(t).der(t), g02ok("good")},
		{"good with a version", f.mod(t, func(r *g02rsp) { r.version = true }), g02ok("good")},
		{"good by key", f.mod(t, func(r *g02rsp) { r.rid = g02byKey(t, f.interA) }), g02ok("good")},

		{"truncated", []byte{0x30}, g02no("response is not valid DER")},
		{"trailing byte", append(f.base(t).der(t), 0x00), g02no("trailing bytes after OCSPResponse")},
		{"not a SEQUENCE", []byte{0x31, 0x00}, g02rej("OCSPResponse is not a SEQUENCE")},
		{"empty", []byte{0x30, 0x00}, g02rej("malformed OCSPResponse")},
		{"status not ENUMERATED", []byte{0x30, 0x03, 0x02, 0x01, 0x00}, g02rej("malformed OCSPResponse")},
		{"status of two octets", []byte{0x30, 0x04, 0x0a, 0x02, 0x00, 0x00}, g02rej("malformed OCSPResponse")},
		{"status 1", []byte{0x30, 0x03, 0x0a, 0x01, 0x01}, g02no("OCSP responseStatus is 1 (not successful)")},
		{"no responseBytes", []byte{0x30, 0x03, 0x0a, 0x01, 0x00}, g02no("successful response carries no responseBytes")},
		{"responseBytes [1]", []byte{0x30, 0x05, 0x0a, 0x01, 0x00, 0xa1, 0x00}, g02no("successful response carries no responseBytes")},
		{"responseBytes empty", g02outer(nil), g02rej("malformed responseBytes")},
		{"responseBytes not a SEQUENCE", g02outer(derTLV(0x04)), g02rej("malformed responseBytes")},
		{"responseBytes of one member", g02outer(derTLV(0x30, g02oid(oidOcspBasic))), g02rej("malformed responseBytes")},
		{"response not an OCTET STRING", g02outer(derTLV(0x30, g02oid(oidOcspBasic), derTLV(0x02, []byte{1}))), g02rej("malformed responseBytes")},
		{"responseType not an OID", g02outer(derTLV(0x30, derTLV(0x02, []byte{1}), derTLV(0x04))), g02rej("expected an OBJECT IDENTIFIER")},
		{"responseType other", g02outer(derTLV(0x30, g02oid("1.2.3.4"), derTLV(0x04))), g02no("responseType is not id-pkix-ocsp-basic")},
		{"basic not DER", g02wrapBasic([]byte{0x30}), g02no("BasicOCSPResponse is not valid DER")},
		{"basic not a SEQUENCE", g02wrapBasic([]byte{0x31, 0x00}), g02rej("BasicOCSPResponse is not a SEQUENCE")},
		{"basic empty", g02wrapBasic(derTLV(0x30)), g02rej("malformed BasicOCSPResponse")},
		{"basic of two members", g02wrapBasic(derTLV(0x30, derTLV(0x30), derTLV(0x30))), g02rej("malformed BasicOCSPResponse")},
		{"empty signatureAlgorithm", g02wrapBasic(derTLV(0x30, derTLV(0x30), derTLV(0x30), derTLV(0x03, []byte{0}))), g02rej("malformed signatureAlgorithm")},
		{"signatureAlgorithm not an OID", g02wrapBasic(derTLV(0x30, derTLV(0x30), derTLV(0x30, derTLV(0x02, []byte{1})), derTLV(0x03, []byte{0}))), g02rej("expected an OBJECT IDENTIFIER")},
		{"unsupported signatureAlgorithm", g02wrapBasic(derTLV(0x30, derTLV(0x30), derTLV(0x30, g02oid("1.2.840.10045.4.3.1")), derTLV(0x03, []byte{0}))), g02no("unsupported OCSP signature algorithm 1.2.840.10045.4.3.1")},
		{"empty signature BIT STRING", g02wrapBasic(derTLV(0x30, derTLV(0x30), alg, derTLV(0x03))), g02rej("malformed signature")},
		{"empty ResponseData", g02wrapBasic(derTLV(0x30, derTLV(0x30), alg, derTLV(0x03, []byte{0}))), g02rej("malformed ResponseData")},
		{"ResponseData of two members", g02wrapBasic(derTLV(0x30, derTLV(0x30, g02byName(f.interA), g02gt(at)), alg, derTLV(0x03, []byte{0}))), g02rej("malformed ResponseData")},
		{"producedAt UTCTime", f.mod(t, func(r *g02rsp) { r.produced = derTLV(0x17, []byte("260531230000Z")) }), g02rej("malformed ResponseData")},
		{"responses a SET", f.mod(t, func(r *g02rsp) { r.responses = derTLV(0x31, single) }), g02rej("malformed ResponseData")},
		{"responderID [3]", f.mod(t, func(r *g02rsp) { r.rid = derTLV(0xa3, f.interA.RawSubject) }), g02rej("malformed ResponseData")},
		{"producedAt April 31", f.mod(t, func(r *g02rsp) { r.produced = g02gts("20260431000000Z") }), g02no("response carries a malformed (out-of-range) ASN.1 time")},

		{"empty SingleResponse", withSingles(derTLV(0x30)), g02rej("malformed SingleResponse")},
		{"SingleResponse of two members", withSingles(derTLV(0x30, cid, g02good)), g02rej("malformed SingleResponse")},
		{"thisUpdate UTCTime", withSingles(derTLV(0x30, cid, g02good, derTLV(0x17, []byte("260531230000Z")))), g02rej("malformed SingleResponse")},
		{"empty CertID", withSingles(g02single(derTLV(0x30), g02good, g02gt(at))), g02rej("malformed CertID")},
		{"CertID keyHash an INTEGER", withSingles(g02single(derTLV(0x30, sha1Alg, nameHash, derTLV(0x02, []byte{1}), serial), g02good, g02gt(at))), g02rej("malformed CertID")},
		{"CertID empty hashAlgorithm", withSingles(g02single(derTLV(0x30, derTLV(0x30), nameHash, keyHash, serial), g02good, g02gt(at))), g02rej("malformed CertID hash algorithm")},
		{"CertID hashAlgorithm not an OID", withSingles(g02single(derTLV(0x30, derTLV(0x30, derTLV(0x02, []byte{1})), nameHash, keyHash, serial), g02good, g02gt(at))), g02rej("expected an OBJECT IDENTIFIER")},
		{"CertID unknown hash", withSingles(g02single(derTLV(0x30, derTLV(0x30, g02oid("1.2.3.4")), nameHash, keyHash, serial), g02good, g02gt(at))), noMatch},
		{"serial differs", withSingles(g02single(g02certID(t, f.interA, big.NewInt(0x1235)), g02good, g02gt(at))), noMatch},
		{"issuer differs", withSingles(g02single(g02certID(t, f.rootA, f.leaf.SerialNumber), g02good, g02gt(at))), noMatch},
		{"two matching SingleResponses", withSingles(single, single), g02no("ambiguous: multiple SingleResponses match the certificate")},

		{"empty responderID", f.mod(t, func(r *g02rsp) { r.rid = derTLV(0xa1) }), g02rej("malformed responderID")},
		{"responderID of two names", f.mod(t, func(r *g02rsp) { r.rid = derTLV(0xa1, f.interA.RawSubject, f.interA.RawSubject) }), g02rej("malformed responderID")},
		{"byKey not an OCTET STRING", f.mod(t, func(r *g02rsp) { r.rid = derTLV(0xa2, derTLV(0x02, g02sha1(g02bits(t, f.interA.RawSPKI)))) }), g02no("no embedded responder certificate verifies the response")},
		{"byName of another certificate", f.mod(t, func(r *g02rsp) { r.rid = g02byName(f.rootA) }), g02no("no embedded responder certificate verifies the response")},
		{"issuer named, signed by another key", f.mod(t, func(r *g02rsp) { r.signer = f.otherK }), g02no("OCSP response signature does not verify under the issuer key")},

		{"unknown", f.withStatus(t, g02unknown), g02ok("unknown")},
		{"revoked", f.withStatus(t, derTLV(0xa1, g02gts("20260101000000Z"))), g02ok("revoked")},
		{"revoked without a time", f.withStatus(t, derTLV(0xa1)), g02no("malformed revoked certStatus")},
		{"revoked with a fractional time", f.withStatus(t, derTLV(0xa1, g02gts("20260101000000.5Z"))), g02no("malformed revoked certStatus")},
		{"certStatus NULL", f.withStatus(t, []byte{0x05, 0x00}), g02no("malformed certStatus")},
		{"certStatus [3]", f.withStatus(t, []byte{0x83, 0x00}), g02no("unrecognised certStatus")},
	}
	for _, r := range rows {
		if got := verifyNvidiaOcspResponse(r.der, f.leafA, f.interA, f.chain, f.nowMs); got != r.want {
			t.Errorf("%s: got %+v, want %+v", r.name, got, r.want)
		}
	}
}

// The issuer's key is read only after the response structure: an unreadable one is an error, a malformed one a recovered panic.
func TestG02OcspIssuerKey(t *testing.T) {
	f := g02newFx(t)
	der := f.base(t).der(t)
	unreadable := &attCert{RawSubject: f.interA.RawSubject, RawSPKI: []byte{0x04, 0x00}}
	if got := verifyNvidiaOcspResponse(der, f.leafA, unreadable, f.chain, f.nowMs); got != g02rej(osslWrongTag) {
		t.Errorf("unreadable issuer SPKI: %+v", got)
	}
	unsupported := &attCert{RawSubject: f.interA.RawSubject, RawSPKI: derTLV(0x30, derTLV(0x30, g02oid("1.2.3.4")), derTLV(0x03, []byte{0, 0xaa}))}
	der2 := f.mod(t, func(r *g02rsp) {
		r.singles = [][]byte{g02single(g02certID(t, unsupported, f.leaf.SerialNumber), g02good, g02gt(g02now.Add(-time.Hour)))}
	})
	if got := verifyNvidiaOcspResponse(der2, f.leafA, unsupported, f.chain, f.nowMs); got != g02rej("error:1E08010C:DECODER routines::unsupported") {
		t.Errorf("unsupported issuer key: %+v", got)
	}
	emptyKey := &attCert{RawSubject: f.interA.RawSubject, RawSPKI: []byte{0x30, 0x04, 0x30, 0x00, 0x03, 0x00}}
	got := verifyNvidiaOcspResponse(der, f.leafA, emptyKey, f.chain, f.nowMs)
	if got.ok || got.status != "" || !strings.HasPrefix(got.reason, "OCSP response rejected: runtime error: slice bounds out of range") {
		t.Errorf("empty issuer key bits: %+v", got)
	}
}

func TestG02OcspDelegatedResponder(t *testing.T) {
	f := g02newFx(t)
	resp := f.responder(t, nil, f.inter, f.interK)
	respA := g02att(t, resp.Raw)
	delegated := func(c []byte, rid []byte, signer *ecdsa.PrivateKey) []byte {
		return f.mod(t, func(r *g02rsp) { r.rid, r.certs, r.signer = rid, c, signer })
	}
	viaResponder := func(c *x509.Certificate) []byte { return delegated(g02certs(c.Raw), g02byName(respA), f.respK) }
	noEmbedded := g02no("no embedded responder certificate verifies the response")
	notSigned := g02no("delegated responder certificate is not signed by the supplied NVIDIA chain")
	outside := g02no("delegated responder certificate is outside its validity window")
	forgedParent := &x509.Certificate{RawSubject: f.inter.RawSubject}

	rows := []struct {
		name string
		der  []byte
		want ocspResult
	}{
		{"delegated by name", viaResponder(resp), g02ok("good")},
		{"delegated by key", delegated(g02certs(resp.Raw), g02byKey(t, respA), f.respK), g02ok("good")},
		{"responder named, no certificates", delegated(nil, g02byName(respA), f.respK), noEmbedded},
		{"certs wrapper of two members", delegated(derTLV(0xa0, derTLV(0x30, resp.Raw), derTLV(0x30)), g02byName(respA), f.respK), g02no("OCSP response rejected: malformed certs")},
		{"embedded certificate not the responderID", delegated(g02certs(resp.Raw), g02byName(f.rootA), f.respK), g02no("embedded certificates do not match the responderID")},
		{"no OCSPSigning EKU", viaResponder(f.responder(t, func(c *x509.Certificate) { c.ExtKeyUsage = nil }, f.inter, f.interK)), g02no("delegated responder certificate lacks the id-kp-OCSPSigning EKU")},
		{"expired responder", viaResponder(f.responder(t, func(c *x509.Certificate) { c.NotAfter = g02now.Add(-time.Hour) }, f.inter, f.interK)), outside},
		{"responder not yet valid", viaResponder(f.responder(t, func(c *x509.Certificate) { c.NotBefore = g02now.Add(time.Hour) }, f.inter, f.interK)), outside},
		{"responder valid from now", viaResponder(f.responder(t, func(c *x509.Certificate) { c.NotBefore = g02now }, f.inter, f.interK)), g02ok("good")},
		{"responder valid until now", viaResponder(f.responder(t, func(c *x509.Certificate) { c.NotAfter = g02now }, f.inter, f.interK)), g02ok("good")},
		{"responder notBefore malformed", delegated(derTLV(0xa0, derTLV(0x04, f.badNotBeforeResponder(t))), g02byName(respA), f.respK), g02no("response carries a malformed (out-of-range) ASN.1 time")}, // asn1js parses the OCTET STRING, so the reference's time walk sees it
		{"responder signed above the issuer", viaResponder(f.responder(t, nil, f.root, f.rootK)), g02ok("good")},
		{"responder signed below the issuer", viaResponder(f.responder(t, nil, f.leaf, f.leafK)), notSigned},
		{"responder naming the issuer, signed by a stranger", viaResponder(f.responder(t, nil, forgedParent, f.otherK)), notSigned},
		{"response not signed by the responder", delegated(g02certs(resp.Raw), g02byName(respA), f.otherK), g02no("OCSP response signature does not verify under the delegated responder key")},
	}
	for _, r := range rows {
		if got := verifyNvidiaOcspResponse(r.der, f.leafA, f.interA, f.chain, f.nowMs); got != r.want {
			t.Errorf("%s: got %+v, want %+v", r.name, got, r.want)
		}
	}
}

func TestG02OcspFreshness(t *testing.T) {
	f := g02newFx(t)
	h := time.Hour
	week := 7 * 24 * h
	stale := g02no("response is stale (past nextUpdate)")
	next := func(at time.Time) []byte { return derTLV(0xa0, g02gt(at)) }
	rows := []struct {
		name  string
		der   []byte
		nowMs int64
		want  ocspResult
	}{
		{"thisUpdate now", f.fresh(t, g02now, g02now.Add(-h)), f.nowMs, g02ok("good")},
		{"thisUpdate in the future", f.fresh(t, g02now.Add(time.Second), g02now.Add(-h)), f.nowMs, g02no("response thisUpdate is in the future")},
		{"producedAt now", f.fresh(t, g02now.Add(-h), g02now), f.nowMs, g02ok("good")},
		{"producedAt in the future", f.fresh(t, g02now.Add(-h), g02now.Add(time.Second)), f.nowMs, g02no("response producedAt is in the future")},
		{"nextUpdate before thisUpdate", f.fresh(t, g02now.Add(-h), g02now.Add(-h), next(g02now.Add(-2*h))), f.nowMs, g02no("response nextUpdate is invalid")},
		{"nextUpdate equal to thisUpdate, past", f.fresh(t, g02now.Add(-h), g02now.Add(-h), next(g02now.Add(-h))), f.nowMs, stale},
		{"nextUpdate now", f.fresh(t, g02now.Add(-h), g02now.Add(-h), next(g02now)), f.nowMs, g02ok("good")},
		{"past nextUpdate", f.fresh(t, g02now.Add(-2*h), g02now.Add(-2*h), next(g02now.Add(-h))), f.nowMs, stale},
		{"nextUpdate ahead", f.fresh(t, g02now.Add(-h), g02now.Add(-h), next(g02now.Add(h))), f.nowMs, g02ok("good")},
		{"empty nextUpdate wrapper", f.fresh(t, g02now.Add(-h), g02now.Add(-h), derTLV(0xa0)), f.nowMs, g02no("OCSP response rejected: malformed nextUpdate")},
		{"exactly the maximum age", f.fresh(t, g02now.Add(-week), g02now.Add(-week)), f.nowMs, g02ok("good")},
		{"a millisecond past the maximum age", f.fresh(t, g02now.Add(-week), g02now.Add(-week)), f.nowMs + 1, g02no("response is older than the maximum accepted age")},
	}
	for _, r := range rows {
		if got := verifyNvidiaOcspResponse(r.der, f.leafA, f.interA, f.chain, r.nowMs); got != r.want {
			t.Errorf("%s: got %+v, want %+v", r.name, got, r.want)
		}
	}
}

func TestG02OcspChain(t *testing.T) {
	f := g02newFx(t)
	at := g02now.Add(-time.Hour)
	leafGood := f.base(t).der(t)
	interSingle := g02single(g02certID(t, f.rootA, f.inter.SerialNumber), g02good, g02gt(at))
	interGood := g02rsp{rid: g02byName(f.rootA), produced: g02gt(at), signer: f.rootK, singles: [][]byte{interSingle}}.der(t)
	resp := f.responder(t, nil, f.root, f.rootK)
	both := g02rsp{rid: g02byName(g02att(t, resp.Raw)), produced: g02gt(at), signer: f.respK, certs: g02certs(resp.Raw),
		singles: [][]byte{g02single(g02certID(t, f.interA, f.leaf.SerialNumber), g02good, g02gt(at)), interSingle}}.der(t)
	unrelated := f.mod(t, func(r *g02rsp) {
		r.singles = [][]byte{g02single(g02certID(t, f.interA, big.NewInt(999)), g02good, g02gt(at))}
	})
	leafSub := subjectLine(f.leafA)
	rows := []struct {
		name      string
		chain     []*attCert
		responses [][]byte
		want      string
	}{
		{"one certificate", []*attCert{f.leafA}, [][]byte{leafGood}, "chain too short for OCSP"},
		{"two certificates", []*attCert{f.leafA, f.interA}, [][]byte{leafGood}, ""},
		{"no responses", f.chain, nil, "no OCSP responses supplied"},
		{"leaf good", f.chain, [][]byte{leafGood}, ""},
		{"leaf and intermediate good", f.chain, [][]byte{leafGood, interGood}, ""},
		{"required leaf absent", f.chain, [][]byte{interGood}, "no GOOD OCSP response for required certificate '" + leafSub + "' (status: absent)"},
		{"required leaf unknown", f.chain, [][]byte{f.withStatus(t, g02unknown)}, "no GOOD OCSP response for required certificate '" + leafSub + "' (status: unknown)"},
		{"duplicate leaf responses", f.chain, [][]byte{leafGood, leafGood}, "duplicate OCSP responses for chain certificate #0"},
		{"leaf revoked", f.chain, [][]byte{f.withStatus(t, derTLV(0xa1, g02gts("20260101000000Z")))}, "chain certificate '" + leafSub + "' is revoked (OCSP)"},
		{"one response for two certificates", f.chain, [][]byte{both}, "OCSP response #0 matches more than one chain certificate"},
		{"a response for no chain certificate", f.chain, [][]byte{leafGood, unrelated}, "OCSP response #1 rejected: no SingleResponse matches the certificate (serial / issuer hashes differ)"},
		{"a malformed response", f.chain, [][]byte{{0x30}}, "OCSP response #0 for '" + leafSub + "' rejected: response is not valid DER"},
	}
	for _, r := range rows {
		if got := checkNvidiaChainOcsp(r.chain, r.responses, f.nowMs); got != r.want {
			t.Errorf("%s: got %q, want %q", r.name, got, r.want)
		}
	}
}
