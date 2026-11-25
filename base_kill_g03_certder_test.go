package pca

// g03: direct unit tests of the lenient certificate engine of attest_cert.go (readCertElem, certKids, validOID, algID,
// checkBitString, checkName, parseCertDER, derLengthHeader, certFromPEM, keyOfCert, pssParams, certSigOK, the extension
// helpers). Every row pins the exact OpenSSL-style message or the exact return value so the boundary mutants are observable.

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"reflect"
	"sync"
	"testing"
	"time"
)

var (
	g03oidEcdsaSha256 = []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02}
	g03oidEcKey       = []byte{0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01}
	g03oidP256        = []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}
	g03oidCN          = []byte{0x06, 0x03, 0x55, 0x04, 0x03}
	g03oidBasicC      = []byte{0x06, 0x03, 0x55, 0x1d, 0x13}
	g03oidKeyUsage    = []byte{0x06, 0x03, 0x55, 0x1d, 0x0f}
	g03oidOCSP        = []byte{0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01}
	g03oidCAIssuers   = []byte{0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02}
	g03oidOCSPSign    = []byte{0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09}
	g03oidServerAuth  = []byte{0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01}
	g03oidSha256      = []byte{0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01}
	g03oidMgf1        = []byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08}
	g03oidRsaPss      = []byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a}
	g03oidRsaEnc      = []byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01}
	g03oid123         = []byte{0x06, 0x02, 0x2a, 0x03}
	g03oidBad         = []byte{0x06, 0x01, 0x80}
)

const (
	g03notEnough = "error:0680007B:asn1 encoding routines::not enough data"
	g03zero      = "error:0688010A:asn1 encoding routines::illegal zero content"
	g03unsupp    = "error:1E08010C:DECODER routines::unsupported"
)

func g03name(value []byte) []byte {
	return derTLV(0x30, derTLV(0x31, derTLV(0x30, g03oidCN, value)))
}

// g03cert is a certificate as its raw DER parts; der() assembles it (nil parts are left out).
type g03cert struct {
	version, serial, tbsAlg, issuer, validity, subject, spki, tail []byte
	alg, sig, outerTail                                            []byte
}

func g03base() g03cert {
	return g03cert{
		version:  derTLV(0xa0, derTLV(0x02, []byte{0x02})),
		serial:   derTLV(0x02, []byte{0x01}),
		tbsAlg:   derTLV(0x30, g03oidEcdsaSha256),
		issuer:   g03name(derTLV(0x0c, []byte("x"))),
		validity: derTLV(0x30, derTLV(0x17, []byte("250101000000Z")), derTLV(0x17, []byte("350101000000Z"))),
		subject:  g03name(derTLV(0x0c, []byte("y"))),
		spki:     derTLV(0x30, derTLV(0x30, g03oidEcKey, g03oidP256), derTLV(0x03, []byte{0x00, 0x04, 0x01})),
		alg:      derTLV(0x30, g03oidEcdsaSha256),
		sig:      derTLV(0x03, []byte{0x00, 0x01, 0x02}),
	}
}

func (c g03cert) der() []byte {
	tbs := derTLV(0x30, c.version, c.serial, c.tbsAlg, c.issuer, c.validity, c.subject, c.spki, c.tail)
	return derTLV(0x30, tbs, c.alg, c.sig, c.outerTail)
}

func g03ext(parts ...[]byte) []byte { return derTLV(0x30, parts...) }
func g03exts(exts ...[]byte) []byte { return derTLV(0xa3, derTLV(0x30, exts...)) }

func g03errIs(t *testing.T, what string, err error, want string) {
	t.Helper()
	if err == nil || err.Error() != want {
		t.Errorf("%s: err %v, want %q", what, err, want)
	}
}

func TestG03ReadCertElemAndKids(t *testing.T) {
	if _, err := readCertElem([]byte{0x30, 0x00}, 2, 2, 0); err == nil || err.Error() != g03notEnough {
		t.Errorf("off == limit: %v", err)
	}
	if _, err := readCertElem([]byte{0x31, 0x00}, 0, 2, 0x30); err == nil || err.Error() != osslWrongTag {
		t.Errorf("wrong tag: %v", err)
	}
	if e, err := readCertElem([]byte{0x31, 0x00}, 0, 2, 0); err != nil || e.tag != 0x31 || e.start != 2 || e.end != 2 {
		t.Errorf("any tag: %+v %v", e, err)
	}
	b := []byte{0x30, 0x03, 0x02, 0x05, 0x00}
	e, err := readCertElem(b, 0, len(b), 0x30)
	if err != nil {
		t.Fatal(err)
	}
	if kids, err := certKids(b, e); err == nil || err.Error() != osslNested || kids != nil {
		t.Errorf("broken kid: %v %v", kids, err)
	}
}

func TestG03ValidOID(t *testing.T) {
	rows := []struct {
		b          []byte
		tag        byte
		start, end int
		want       bool
	}{
		{[]byte{0x2a}, 0x05, 0, 1, false},
		{[]byte{0x2a}, 0x06, 1, 1, false},
		{[]byte{0x2a, 0x81, 0x00}, 0x06, 0, 2, false},
		{[]byte{0x2a}, 0x06, 0, 1, true},
		{[]byte{0x2a, 0x80}, 0x06, 0, 1, true},
		{[]byte{0x80, 0x01}, 0x06, 0, 2, false},
		{[]byte{0x81, 0x80, 0x01}, 0x06, 1, 3, false},
		{[]byte{0x2a, 0x80, 0x01}, 0x06, 0, 3, false},
		{[]byte{0x2a, 0x80, 0x81, 0x01}, 0x06, 0, 4, false},
		{[]byte{0x81, 0x2a, 0x80, 0x01}, 0x06, 1, 4, false},
		{[]byte{0x2b, 0x80, 0x01}, 0x06, 0, 3, false},
		{[]byte{0x2a, 0x81, 0x01}, 0x06, 0, 3, true},
	}
	for i, r := range rows {
		if got := validOID(r.b, certElem{tag: r.tag, start: r.start, end: r.end}); got != r.want {
			t.Errorf("row %d: %v, want %v", i, got, r.want)
		}
	}
}

func TestG03AlgIDAndBitString(t *testing.T) {
	alg := func(b []byte) (string, []byte, error) {
		e, err := readCertElem(b, 0, len(b), 0x30)
		if err != nil {
			t.Fatal(err)
		}
		return algID(b, e)
	}
	if o, p, err := alg(derTLV(0x30, g03oidSha256, []byte{0x05, 0x00}, []byte{0x05, 0x00})); err == nil || err.Error() != osslNested || o != "" || p != nil {
		t.Errorf("three kids: %q %v %v", o, p, err)
	}
	if o, p, err := alg([]byte{0x30, 0x00}); err == nil || err.Error() != osslNested || o != "" {
		t.Errorf("empty: %q %v %v", o, p, err)
	}
	if o, p, err := alg(derTLV(0x30, g03oidBad)); err == nil || err.Error() != osslNested || o != "" {
		t.Errorf("bad oid: %q %v %v", o, p, err)
	}
	if o, p, err := alg(derTLV(0x30, g03oidSha256, []byte{0x05, 0x00})); err != nil || o != "2.16.840.1.101.3.4.2.1" || !bytes.Equal(p, []byte{0x05, 0x00}) {
		t.Errorf("with params: %q %v %v", o, p, err)
	}
	if o, p, err := alg(derTLV(0x30, g03oidSha256)); err != nil || o != "2.16.840.1.101.3.4.2.1" || p != nil {
		t.Errorf("without params: %q %v %v", o, p, err)
	}

	bits := []struct {
		b          []byte
		tag        byte
		start, end int
		want       string
	}{
		{[]byte{0x00, 0x00}, 0x03, 1, 1, osslWrongTag},
		{[]byte{0x00}, 0x04, 0, 1, osslWrongTag},
		{[]byte{0x00}, 0x03, 0, 1, ""},
		{[]byte{0x07}, 0x03, 0, 1, ""},
		{[]byte{0x08}, 0x03, 0, 1, osslBits},
		{[]byte{0x06, 0xff}, 0x03, 0, 2, ""},
	}
	for i, r := range bits {
		err := checkBitString(r.b, certElem{tag: r.tag, start: r.start, end: r.end})
		got := ""
		if err != nil {
			got = err.Error()
		}
		if got != r.want {
			t.Errorf("bits row %d: %q, want %q", i, got, r.want)
		}
	}
}

func TestG03CheckName(t *testing.T) {
	chk := func(b []byte) string {
		e, err := readCertElem(b, 0, len(b), 0x30)
		if err != nil {
			t.Fatal(err)
		}
		if err := checkName(b, e); err != nil {
			return err.Error()
		}
		return ""
	}
	rows := []struct {
		name string
		b    []byte
		want string
	}{
		{"broken rdn list", []byte{0x30, 0x02, 0x31, 0x05}, osslNested},
		{"rdn is a SEQUENCE", []byte{0x30, 0x02, 0x30, 0x00}, osslWrongTag},
		{"broken atv list", []byte{0x30, 0x04, 0x31, 0x02, 0x30, 0x05}, osslNested},
		{"atv is a SET", []byte{0x30, 0x04, 0x31, 0x02, 0x31, 0x00}, osslWrongTag},
		{"atv with one member", derTLV(0x30, derTLV(0x31, derTLV(0x30, g03oidCN))), osslNested},
		{"atv with a bad oid", derTLV(0x30, derTLV(0x31, derTLV(0x30, g03oidBad, derTLV(0x0c, []byte("x"))))), osslNested},
		{"value tag INTEGER", g03name(derTLV(0x02, []byte{1})), osslNested},
		{"empty name", []byte{0x30, 0x00}, ""},
	}
	for _, r := range rows {
		if got := chk(r.b); got != r.want {
			t.Errorf("%s: %q, want %q", r.name, got, r.want)
		}
	}
	for _, tag := range []byte{0x0c, 0x12, 0x13, 0x14, 0x16, 0x30, 0x07, 0x08, 0x09, 0x0b, 0x0d, 0x0e, 0x0f, 0x1d} {
		if got := chk(g03name(derTLV(tag, []byte("x")))); got != "" {
			t.Errorf("value tag %#x refused: %q", tag, got)
		}
	}
	// these three check their content too, so "x" alone would not do
	for tag, value := range map[byte][]byte{0x1c: {0, 0, 0, 'x'}, 0x1e: {0, 'x'}, 0x03: {0, 'x'}} {
		if got := chk(g03name(derTLV(tag, value))); got != "" {
			t.Errorf("value tag %#x refused: %q", tag, got)
		}
	}
	for _, tag := range []byte{0x15, 0x1f, 0x04, 0x31, 0x10, 0x01, 0x0a} {
		if got := chk(g03name(derTLV(tag, []byte("x")))); got != osslNested {
			t.Errorf("value tag %#x: %q", tag, got)
		}
	}
}

func TestG03ParseCertDERStructure(t *testing.T) {
	c, err := parseCertDER(g03base().der())
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	if c.SigOID != "1.2.840.10045.4.3.2" || c.SigParams != nil || !bytes.Equal(c.Signature, []byte{1, 2}) || !bytes.Equal(c.Serial, []byte{1}) || len(c.exts) != 0 {
		t.Fatalf("baseline fields: %+v", c)
	}
	mut := func(f func(c *g03cert)) []byte {
		b := g03base()
		f(&b)
		return b.der()
	}
	rows := []struct {
		name string
		der  []byte
		want string
	}{
		{"outer is a SET", []byte{0x31, 0x00}, osslWrongTag},
		{"tbs is a SET", []byte{0x30, 0x02, 0x31, 0x00}, osslWrongTag},
		{"no signature algorithm", []byte{0x30, 0x02, 0x30, 0x00}, g03notEnough},
		{"no signature", []byte{0x30, 0x04, 0x30, 0x00, 0x30, 0x00}, g03notEnough},
		{"trailing element inside the certificate", mut(func(c *g03cert) { c.outerTail = []byte{0x05, 0x00} }), osslNested},
		{"signature unused bits 8", mut(func(c *g03cert) { c.sig = []byte{0x03, 0x02, 0x08, 0x00} }), osslBits},
		{"outer algorithm bad oid", mut(func(c *g03cert) { c.alg = derTLV(0x30, g03oidBad) }), osslNested},
		{"version overruns", mut(func(c *g03cert) { c.version = []byte{0xa0, 0x7f} }), osslNested},
		{"version not an INTEGER", mut(func(c *g03cert) { c.version = derTLV(0xa0, []byte{0x01, 0x01, 0xff}) }), osslWrongTag},
		{"no serial", mut(func(c *g03cert) { c.serial = nil }), osslWrongTag},
		{"empty serial", mut(func(c *g03cert) { c.serial = []byte{0x02, 0x00} }), g03zero},
		{"tbs algorithm is a SET", mut(func(c *g03cert) { c.tbsAlg = []byte{0x31, 0x00} }), osslWrongTag},
		{"tbs algorithm bad oid", mut(func(c *g03cert) { c.tbsAlg = derTLV(0x30, g03oidBad) }), osslNested},
		{"issuer is a SET", mut(func(c *g03cert) { c.issuer = []byte{0x31, 0x00} }), osslWrongTag},
		{"issuer rdn is a SEQUENCE", mut(func(c *g03cert) {
			c.issuer = derTLV(0x30, derTLV(0x30, derTLV(0x30, g03oidCN, derTLV(0x0c, []byte("x")))))
		}), osslWrongTag},
		{"validity is a SET", mut(func(c *g03cert) { c.validity = []byte{0x31, 0x00} }), osslWrongTag},
		{"subject is a SET", mut(func(c *g03cert) { c.subject = []byte{0x31, 0x00} }), osslWrongTag},
		{"spki is a SET", mut(func(c *g03cert) { c.spki = []byte{0x31, 0x00} }), osslWrongTag},
		{"spki algorithm is a SET", mut(func(c *g03cert) { c.spki = derTLV(0x30, derTLV(0x31, g03oidEcKey), derTLV(0x03, []byte{0x00})) }), osslNested},
		{"spki with three members", mut(func(c *g03cert) {
			c.spki = derTLV(0x30, derTLV(0x30, g03oidEcKey), derTLV(0x03, []byte{0x00}), derTLV(0x03, []byte{0x00}))
		}), osslNested},
		{"spki with one member", mut(func(c *g03cert) { c.spki = derTLV(0x30, derTLV(0x30, g03oidEcKey)) }), osslNested},
		{"spki algorithm bad oid", mut(func(c *g03cert) { c.spki = derTLV(0x30, derTLV(0x30, g03oidBad), derTLV(0x03, []byte{0x00})) }), osslNested},
		{"spki key not a BIT STRING", mut(func(c *g03cert) { c.spki = derTLV(0x30, derTLV(0x30, g03oidEcKey), derTLV(0x04, []byte{0x00})) }), osslWrongTag},
		{"trailing garbage in tbs", mut(func(c *g03cert) { c.tail = []byte{0x05, 0x00} }), osslNested},
		{"extensions wrapper overruns", mut(func(c *g03cert) { c.tail = []byte{0xa3, 0x7f} }), osslNested},
		{"extensions not a SEQUENCE", mut(func(c *g03cert) { c.tail = []byte{0xa3, 0x02, 0x31, 0x00} }), osslWrongTag},
		{"bytes after the extensions SEQUENCE", mut(func(c *g03cert) { c.tail = []byte{0xa3, 0x04, 0x30, 0x00, 0x05, 0x00} }), osslNested},
		{"broken extension list", mut(func(c *g03cert) { c.tail = []byte{0xa3, 0x04, 0x30, 0x02, 0x30, 0x05} }), osslNested},
		{"extension is a SET", mut(func(c *g03cert) { c.tail = g03exts(derTLV(0x31, g03oidBasicC, derTLV(0x04, nil))) }), osslWrongTag},
		{"extension with four members", mut(func(c *g03cert) {
			c.tail = g03exts(g03ext(g03oidBasicC, derTLV(0x01, []byte{0xff}), derTLV(0x04, nil), derTLV(0x04, nil)))
		}), osslNested},
		{"critical is an INTEGER", mut(func(c *g03cert) {
			c.tail = g03exts(g03ext(g03oidBasicC, derTLV(0x02, []byte{0xff}), derTLV(0x04, nil)))
		}), osslNested},
		{"critical of two bytes", mut(func(c *g03cert) {
			c.tail = g03exts(g03ext(g03oidBasicC, derTLV(0x01, []byte{0xff, 0xff}), derTLV(0x04, nil)))
		}), osslNested},
		{"extension value not an OCTET STRING", mut(func(c *g03cert) { c.tail = g03exts(g03ext(g03oidBasicC, []byte{0x05, 0x00})) }), osslWrongTag},
	}
	for _, r := range rows {
		c, err := parseCertDER(r.der)
		if c != nil {
			t.Errorf("%s: parsed", r.name)
		}
		g03errIs(t, r.name, err, r.want)
	}
	// one-member extension: refused (nested), never an index panic
	func() {
		defer func() {
			if x := recover(); x != nil {
				t.Errorf("one-member extension panicked: %v", x)
			}
		}()
		_, err := parseCertDER(mut(func(c *g03cert) { c.tail = g03exts(g03ext(g03oidBasicC)) }))
		g03errIs(t, "one-member extension", err, osslNested)
	}()
}

func TestG03ParseCertDERValidityTimes(t *testing.T) {
	v := func(tags ...byte) []byte {
		var parts [][]byte
		for _, tg := range tags {
			txt := "250101000000Z"
			if tg == 0x18 {
				txt = "20250101000000Z"
			}
			parts = append(parts, derTLV(tg, []byte(txt)))
		}
		return derTLV(0x30, parts...)
	}
	for _, r := range []struct {
		tags []byte
		ok   bool
	}{
		{[]byte{0x17, 0x17}, true}, {[]byte{0x17, 0x18}, true}, {[]byte{0x18, 0x17}, true}, {[]byte{0x18, 0x18}, true},
		{[]byte{0x17, 0x02}, false}, {[]byte{0x18, 0x02}, false}, {[]byte{0x02, 0x17}, false}, {[]byte{0x02, 0x18}, false},
		{[]byte{0x17, 0x17, 0x17}, false}, {[]byte{0x17}, false},
	} {
		b := g03base()
		b.validity = v(r.tags...)
		c, err := parseCertDER(b.der())
		if r.ok && (err != nil || c == nil) {
			t.Errorf("validity %x: %v", r.tags, err)
		}
		if !r.ok {
			g03errIs(t, "validity", err, osslNested)
		}
	}
}

func TestG03ParseCertDEROptionalParts(t *testing.T) {
	// no version
	b := g03base()
	b.version = nil
	if c, err := parseCertDER(b.der()); err != nil || c == nil {
		t.Errorf("no version: %v", err)
	}
	// unique identifiers
	for _, tail := range [][]byte{{0x81, 0x01, 0x00}, {0x82, 0x01, 0x00}, {0x81, 0x01, 0x00, 0x82, 0x01, 0x00}} {
		b := g03base()
		b.tail = tail
		if c, err := parseCertDER(b.der()); err != nil || c == nil {
			t.Errorf("unique ids %x: %v %v", tail, c, err)
		}
	}
	// a uid overrunning the tbs
	b = g03base()
	b.tail = []byte{0x81, 0x7f}
	_, err := parseCertDER(b.der())
	g03errIs(t, "uid overrun", err, osslNested)
	// extensions: critical flag, value, order
	b = g03base()
	b.tail = g03exts(
		g03ext(g03oidBasicC, derTLV(0x01, []byte{0xff}), derTLV(0x04, []byte{0x00})),
		g03ext(g03oidKeyUsage, derTLV(0x01, []byte{0x00}), derTLV(0x04, []byte{0x05})),
		g03ext(g03oidCN, derTLV(0x04, []byte{0x07, 0x08})),
		g03ext(g03oidBasicC, derTLV(0x01, []byte{0x01}), derTLV(0x04, nil)),
	)
	c, err := parseCertDER(b.der())
	if err != nil {
		t.Fatalf("extensions: %v", err)
	}
	want := []lenientExt{
		{oid: "2.5.29.19", critical: true, value: []byte{0x00}},
		{oid: "2.5.29.15", critical: false, value: []byte{0x05}},
		{oid: "2.5.4.3", critical: false, value: []byte{0x07, 0x08}},
		{oid: "2.5.29.19", critical: true, value: []byte{}},
	}
	if !reflect.DeepEqual(c.exts, want) {
		t.Errorf("extensions: %+v, want %+v", c.exts, want)
	}
}

func TestG03DerLengthHeader(t *testing.T) {
	rows := []struct {
		n    int
		want []byte
	}{
		{0, []byte{0x30, 0x00}},
		{0x7f, []byte{0x30, 0x7f}},
		{0x80, []byte{0x30, 0x81, 0x80}},
		{0xff, []byte{0x30, 0x81, 0xff}},
		{0x100, []byte{0x30, 0x82, 0x01, 0x00}},
		{0x1234, []byte{0x30, 0x82, 0x12, 0x34}},
		{0xffff, []byte{0x30, 0x82, 0xff, 0xff}},
		{0x10000, []byte{0x30, 0x83, 0x01, 0x00, 0x00}},
		{0x100000, []byte{0x30, 0x83, 0x10, 0x00, 0x00}},
		{0x123456, []byte{0x30, 0x83, 0x12, 0x34, 0x56}},
		{0xffffff, []byte{0x30, 0x83, 0xff, 0xff, 0xff}},
		{0x1000000, []byte{0x30, 0x84, 0x01, 0x00, 0x00, 0x00}},
		{0x12345678, []byte{0x30, 0x84, 0x12, 0x34, 0x56, 0x78}},
	}
	for _, r := range rows {
		if got := derLengthHeader(0x30, r.n); !bytes.Equal(got, r.want) {
			t.Errorf("derLengthHeader(%#x) = %x, want %x", r.n, got, r.want)
		}
	}
}

func g03ecCert(t *testing.T) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key, selfSigned(t, key, "g03", time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC))
}

func TestG03CertFromPEM(t *testing.T) {
	_, cert := g03ecCert(t)
	text := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
	c, err := certFromPEM(text)
	if err != nil || !bytes.Equal(c.Raw, cert.Raw) {
		t.Fatalf("pem with line breaks: %v", err)
	}
	if c, err := certFromPEM("-----BEGIN CERTIFICATE-----\r\n\t " + text[len("-----BEGIN CERTIFICATE-----"):]); err != nil || !bytes.Equal(c.Raw, cert.Raw) {
		t.Errorf("pem with tabs/CR/spaces: %v", err)
	}
	func() {
		defer func() {
			if x := recover(); x != nil {
				t.Errorf("no pem panicked: %v", x)
			}
		}()
		_, err := certFromPEM("not a pem")
		g03errIs(t, "no pem", err, "error:0480006C:PEM routines::no start line")
	}()
	_, err = certFromPEM("-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----")
	g03errIs(t, "bad base64", err, g03unsupp)
}

var (
	g03rsaOnce sync.Once
	g03rsa     *rsa.PrivateKey
)

func g03rsaKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	g03rsaOnce.Do(func() { g03rsa, _ = rsa.GenerateKey(rand.Reader, 2048) })
	if g03rsa == nil {
		t.Fatal("rsa key generation failed")
	}
	return g03rsa
}

func TestG03KeyOfCert(t *testing.T) {
	key := func(spki []byte) (certKey, error) { return keyOfCert(&attCert{RawSPKI: spki}) }
	_, err := key([]byte{0x31, 0x00})
	g03errIs(t, "spki is a SET", err, osslWrongTag)
	_, err = key(derTLV(0x30, derTLV(0x30, g03oidEcKey, g03oidP256), derTLV(0x03, []byte{0x00, 0x04}), []byte{0x05, 0x00}))
	g03errIs(t, "three members", err, osslNested)
	_, err = key(derTLV(0x30, derTLV(0x30, g03oidBad), derTLV(0x03, []byte{0x00})))
	g03errIs(t, "bad algorithm oid", err, osslNested)
	_, err = key(derTLV(0x30, derTLV(0x30, g03oid123), derTLV(0x03, []byte{0x00})))
	g03errIs(t, "unknown algorithm", err, g03unsupp)

	rk := g03rsaKey(t)
	pk1 := x509.MarshalPKCS1PublicKey(&rk.PublicKey)
	pss := derTLV(0x30, derTLV(0x30, g03oidRsaPss), derTLV(0x03, append([]byte{0x00}, pk1...)))
	if k, err := key(pss); err != nil || k.typ != "rsa-pss" {
		t.Errorf("rsa-pss key: %+v %v", k, err)
	}
	enc := derTLV(0x30, derTLV(0x30, g03oidRsaEnc, []byte{0x05, 0x00}), derTLV(0x03, append([]byte{0x00}, pk1...)))
	if k, err := key(enc); err != nil || k.typ != "rsa" {
		t.Errorf("rsa key: %+v %v", k, err)
	}
}

func TestG03PSSParams(t *testing.T) {
	alg := func(oid []byte, params ...[]byte) []byte { return derTLV(0x30, append([][]byte{oid}, params...)...) }
	seq := func(kids ...[]byte) []byte { return derTLV(0x30, kids...) }
	sha256Alg := alg(g03oidSha256)
	rows := []struct {
		name string
		raw  []byte
		h    crypto.Hash
		salt int
		ok   bool
	}{
		{"absent", nil, crypto.SHA1, 20, true},
		{"not a SEQUENCE", []byte{0x31, 0x00}, 0, 0, false},
		{"broken members", []byte{0x30, 0x02, 0xa0, 0x05}, 0, 0, false},
		{"[0] with two members", seq(derTLV(0xa0, sha256Alg, sha256Alg)), 0, 0, false},
		{"[0] empty", seq(derTLV(0xa0)), 0, 0, false},
		{"[0] bad oid", seq(derTLV(0xa0, alg(g03oidBad))), 0, 0, false},
		{"[0] unknown hash", seq(derTLV(0xa0, alg(g03oid123))), 0, 0, false},
		{"[0] sha256 alone (mgf stays sha1)", seq(derTLV(0xa0, sha256Alg)), crypto.SHA256, 20, false},
		{"[1] not mgf1", seq(derTLV(0xa1, alg(g03oid123, sha256Alg))), 0, 0, false},
		{"[1] mgf1 params not a SEQUENCE", seq(derTLV(0xa1, alg(g03oidMgf1, []byte{0x31, 0x00}))), 0, 0, false},
		{"[1] mgf1 hash bad oid", seq(derTLV(0xa1, alg(g03oidMgf1, alg(g03oidBad)))), 0, 0, false},
		{"[1] mgf1 unknown hash", seq(derTLV(0xa1, alg(g03oidMgf1, alg(g03oid123)))), 0, 0, false},
		{"[2] not an INTEGER", seq(derTLV(0xa2, []byte{0x04, 0x01, 0x14})), 0, 0, false},
		{"[2] salt 2^20", seq(derTLV(0xa2, []byte{0x02, 0x03, 0x10, 0x00, 0x00})), crypto.SHA1, 1 << 20, true},
		{"[2] salt 2^20+1", seq(derTLV(0xa2, []byte{0x02, 0x03, 0x10, 0x00, 0x01})), 0, 0, false},
		{"[2] salt beyond int64", seq(derTLV(0xa2, []byte{0x02, 0x09, 0x01, 0, 0, 0, 0, 0, 0, 0, 0})), 0, 0, false},
		{"[3] trailer 2", seq(derTLV(0xa3, []byte{0x02, 0x01, 0x02})), 0, 0, false},
		{"[3] trailer 1", seq(derTLV(0xa3, []byte{0x02, 0x01, 0x01})), crypto.SHA1, 20, true},
		{"[4] unknown member", seq(derTLV(0xa4, []byte{0x02, 0x01, 0x01})), 0, 0, false},
		{"full sha256 profile", seq(derTLV(0xa0, sha256Alg), derTLV(0xa1, alg(g03oidMgf1, sha256Alg)), derTLV(0xa2, []byte{0x02, 0x01, 0x20}), derTLV(0xa3, []byte{0x02, 0x01, 0x01})), crypto.SHA256, 32, true},
	}
	for _, r := range rows {
		h, salt, ok := pssParams(r.raw)
		if h != r.h || salt != r.salt || ok != r.ok {
			t.Errorf("%s: (%v, %d, %v), want (%v, %d, %v)", r.name, h, salt, ok, r.h, r.salt, r.ok)
		}
	}
}

func g03x509(t *testing.T, cn string, pub any, parent *x509.Certificate, signer crypto.Signer, alg x509.SignatureAlgorithm) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC),
		BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		SignatureAlgorithm: alg,
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

func g03att(t *testing.T, c *x509.Certificate) (*attCert, certKey) {
	t.Helper()
	a, err := parseCertDER(c.Raw)
	if err != nil {
		t.Fatal(err)
	}
	k, err := keyOfCert(a)
	if err != nil {
		t.Fatal(err)
	}
	return a, k
}

func TestG03CertSigOK(t *testing.T) {
	edPub, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	edPub2, _, _ := ed25519.GenerateKey(rand.Reader)
	rk := g03rsaKey(t)
	_, ecCert := g03ecCert(t)

	edA, edK := g03att(t, g03x509(t, "ed", edPub, nil, edPriv, x509.PureEd25519))
	rsaA, rsaK := g03att(t, g03x509(t, "rsa", &rk.PublicKey, nil, rk, x509.SHA256WithRSA))
	pssA, _ := g03att(t, g03x509(t, "pss", &rk.PublicKey, nil, rk, x509.SHA256WithRSAPSS))
	ecA, ecK := g03att(t, ecCert)
	rsaKey := keyInfoOf(&rk.PublicKey, nil)

	tbs := []byte("g03 tbs")
	d := sha256.Sum256(tbs)
	pssSalt20, err := rsa.SignPSS(rand.Reader, rk, crypto.SHA256, d[:], &rsa.PSSOptions{SaltLength: 20})
	if err != nil {
		t.Fatal(err)
	}
	pkcs1, err := rsa.SignPKCS1v15(rand.Reader, rk, crypto.SHA256, d[:])
	if err != nil {
		t.Fatal(err)
	}
	// RSASSA-PSS whose params name sha256 but leave MGF1 at its sha1 default: an unchecked profile, refused even though the
	// signature itself verifies under (sha256, salt 20, MGF1-sha256)
	pssMismatch := &attCert{SigOID: "1.2.840.113549.1.1.10", SigParams: derTLV(0x30, derTLV(0xa0, derTLV(0x30, g03oidSha256))), RawTBS: tbs, Signature: pssSalt20}
	// a PKCS#1 v1.5 signature labelled ecdsa-with-SHA256
	mislabelled := &attCert{SigOID: "1.2.840.10045.4.3.2", RawTBS: tbs, Signature: pkcs1}

	rows := []struct {
		name  string
		child *attCert
		k     certKey
		want  bool
	}{
		{"ed25519 own key", edA, edK, true},
		{"ed25519 other key", edA, keyInfoOf(edPub2, nil), false},
		{"ed25519 cert under an ec key", edA, ecK, false},
		{"pss own key", pssA, rsaKey, true},
		{"pss under an ec key", pssA, ecK, false},
		{"pss unchecked profile", pssMismatch, rsaKey, false},
		{"rsa own key", rsaA, rsaK, true},
		{"pkcs1 signature labelled ecdsa", mislabelled, rsaKey, false},
		{"ecdsa own key", ecA, ecK, true},
		{"ecdsa oid under an ed25519 key", ecA, edK, false},
		{"unknown signature oid", &attCert{SigOID: "1.2.3", RawTBS: tbs}, ecK, false},
	}
	for _, r := range rows {
		got := func() (ok bool) {
			defer func() {
				if x := recover(); x != nil {
					t.Errorf("%s panicked: %v", r.name, x)
				}
			}()
			return certSigOK(r.child, r.k)
		}()
		if got != r.want {
			t.Errorf("%s: %v, want %v", r.name, got, r.want)
		}
	}
	if certSigOKBy(ecA, &attCert{RawSPKI: []byte{0x31, 0x00}}) {
		t.Error("certSigOKBy with an unreadable parent key")
	}
	if !certSigOKBy(ecA, ecA) {
		t.Error("certSigOKBy self-signed")
	}
}

func TestG03ExtensionHelpers(t *testing.T) {
	c := &attCert{exts: []lenientExt{{oid: "1.1", value: []byte{1}}, {oid: "1.2", value: []byte{2}}}}
	if v, ok := c.extValue("1.2"); !ok || !bytes.Equal(v, []byte{2}) {
		t.Errorf("second: %v %v", v, ok)
	}
	if v, ok := c.extValue("1.1"); !ok || !bytes.Equal(v, []byte{1}) {
		t.Errorf("first: %v %v", v, ok)
	}
	if v, ok := c.extValue("1.9"); ok || v != nil {
		t.Errorf("missing: %v %v", v, ok)
	}

	aia := derTLV(0x30,
		derTLV(0x30, g03oidOCSP, derTLV(0x86, []byte("http://a"))),
		derTLV(0x30, g03oidOCSP, derTLV(0x86, []byte("http://b")), derTLV(0x86, []byte("http://c"))),
		derTLV(0x30, derTLV(0x04, []byte("x")), derTLV(0x86, []byte("http://d"))),
		[]byte{0x30, 0x02, 0x06, 0x05},
		derTLV(0x30, g03oidCAIssuers, derTLV(0x86, []byte("http://e"))),
		derTLV(0x30, g03oidOCSP, derTLV(0x82, []byte("dns"))),
		derTLV(0x30, []byte{0x06, 0x00}, derTLV(0x86, []byte("http://g"))),
		derTLV(0x30, g03oidOCSP, derTLV(0x86, []byte("http://f"))),
	)
	withExt := func(oid string, v []byte) *attCert { return &attCert{exts: []lenientExt{{oid: oid, value: v}}} }
	if got := withExt("1.3.6.1.5.5.7.1.1", aia).ocspServers(); !reflect.DeepEqual(got, []string{"http://a", "http://f"}) {
		t.Errorf("ocspServers: %q", got)
	}
	if got := (&attCert{}).ocspServers(); got != nil {
		t.Errorf("no AIA: %q", got)
	}
	if got := withExt("1.3.6.1.5.5.7.1.1", []byte{0x31, 0x00}).ocspServers(); got != nil {
		t.Errorf("AIA not a SEQUENCE: %q", got)
	}

	eku := func(purposes ...[]byte) *attCert { return withExt("2.5.29.37", derTLV(0x30, purposes...)) }
	rows := []struct {
		name string
		c    *attCert
		want bool
	}{
		{"ocsp signing", eku(g03oidOCSPSign), true},
		{"server auth then ocsp signing", eku(g03oidServerAuth, g03oidOCSPSign), true},
		{"server auth only", eku(g03oidServerAuth), false},
		{"malformed purpose", eku([]byte{0x06, 0x00}), false},
		{"no EKU", &attCert{}, false},
		{"EKU not a SEQUENCE", withExt("2.5.29.37", []byte{0x31, 0x00}), false},
		{"EKU broken list", withExt("2.5.29.37", []byte{0x30, 0x02, 0x06, 0x05}), false},
	}
	for _, r := range rows {
		if got := r.c.hasOCSPSigningEKU(); got != r.want {
			t.Errorf("%s: %v, want %v", r.name, got, r.want)
		}
	}
}
