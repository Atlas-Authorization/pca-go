package pca

import (
	"testing"
	"time"
)

// g09 mutation kills for attest_der.go: exact errors from every strict DER read, CA-role fields, OID arcs at the 40/80
// boundaries, validity reading and the window edges.

func g09dTLV(tag byte, parts ...[]byte) []byte {
	var c []byte
	for _, p := range parts {
		c = append(c, p...)
	}
	n := len(c)
	var h []byte
	switch {
	case n < 0x80:
		h = []byte{tag, byte(n)}
	case n < 0x100:
		h = []byte{tag, 0x81, byte(n)}
	default:
		h = []byte{tag, 0x82, byte(n >> 8), byte(n)}
	}
	return append(h, c...)
}

func g09dRaw(b ...byte) []byte { return b }

// g09dRoleCert is Certificate{tbs{INTEGER 1 [, [3]{SEQUENCE exts}]}} (enough for the role and extension readers).
func g09dRoleCert(exts ...[]byte) []byte {
	if len(exts) == 0 {
		return g09dTLV(0x30, g09dTLV(0x30, g09dTLV(0x02, g09dRaw(1))))
	}
	return g09dTLV(0x30, g09dTLV(0x30, g09dTLV(0x02, g09dRaw(1)), g09dTLV(0xa3, g09dTLV(0x30, exts...))))
}

func g09dRoleCertRaw(a3content []byte) []byte {
	return g09dTLV(0x30, g09dTLV(0x30, g09dTLV(0x02, g09dRaw(1)), g09dTLV(0xa3, a3content)))
}

func g09dExt(oid []byte, critical bool, value []byte) []byte {
	if critical {
		return g09dTLV(0x30, g09dTLV(0x06, oid), g09dTLV(0x01, g09dRaw(0xff)), g09dTLV(0x04, value))
	}
	return g09dTLV(0x30, g09dTLV(0x06, oid), g09dTLV(0x04, value))
}

func g09dErr(t *testing.T, name string, err error, want string) {
	t.Helper()
	if err == nil || err.Error() != want {
		t.Errorf("%s: err %v, want %q", name, err, want)
	}
}

func TestG09DerReadTlvStrict(t *testing.T) {
	_, err := readTlvStrict(g09dRaw(0x04, 0x81, 0x00), 0, 3)
	g09dErr(t, "81 00", err, "DER: non-minimal length (long form below 128)")
	b := append(g09dRaw(0x04, 0x81, 0x80), make([]byte, 128)...)
	if el, err := readTlvStrict(b, 0, len(b)); err != nil || el != (derTlv{tag: 0x04, start: 3, end: 131}) {
		t.Errorf("81 80: %+v %v", el, err)
	}
	bc := []byte{0x55, 0x1d, 0x13}
	if oidEqualsDER(bc, derTlv{tag: 0x04, start: 0, end: 3}, oidBasicConstraintsDER) || !oidEqualsDER(bc, derTlv{tag: 0x06, start: 0, end: 3}, oidBasicConstraintsDER) {
		t.Error("oidEqualsDER must require tag 6")
	}
	long := []byte{0x55, 0x1d, 0x13, 0x00}
	if oidEqualsDER(long, derTlv{tag: 0x06, start: 0, end: 4}, oidBasicConstraintsDER) {
		t.Error("oidEqualsDER must require the exact length")
	}
}

func TestG09DerCertRoleInfo(t *testing.T) {
	bcOID := []byte{0x55, 0x1d, 0x13}
	kuOID := []byte{0x55, 0x1d, 0x0f}
	info, err := readCertRoleInfo(g09dRoleCert())
	if err != nil || info != (certRoleInfo{pathLen: -1}) {
		t.Errorf("no extensions: %+v %v", info, err)
	}
	cases := []struct {
		name string
		ext  []byte
		want certRoleInfo
	}{
		{"ca 01", g09dExt(bcOID, true, g09dTLV(0x30, g09dTLV(0x01, g09dRaw(0x01)))), certRoleInfo{hasBasicConstraints: true, ca: true, pathLen: -1}},
		{"ca 00", g09dExt(bcOID, true, g09dTLV(0x30, g09dTLV(0x01, g09dRaw(0x00)))), certRoleInfo{hasBasicConstraints: true, pathLen: -1}},
		{"pathLen only", g09dExt(bcOID, false, g09dTLV(0x30, g09dTLV(0x02, g09dRaw(0x03)))), certRoleInfo{hasBasicConstraints: true, pathLen: 3}},
		{"pathLen 256", g09dExt(bcOID, true, g09dTLV(0x30, g09dTLV(0x01, g09dRaw(0xff)), g09dTLV(0x02, g09dRaw(0x01, 0x00)))), certRoleInfo{hasBasicConstraints: true, ca: true, pathLen: 256}},
		{"ku 01", g09dExt(kuOID, true, g09dTLV(0x03, g09dRaw(0x00, 0x01))), certRoleInfo{pathLen: -1, hasKeyUsage: true}},
		{"ku 04", g09dExt(kuOID, true, g09dTLV(0x03, g09dRaw(0x00, 0x04))), certRoleInfo{pathLen: -1, hasKeyUsage: true, keyCertSign: true}},
	}
	for _, c := range cases {
		info, err := readCertRoleInfo(g09dRoleCert(c.ext))
		if err != nil || info != c.want {
			t.Errorf("%s: %+v %v, want %+v", c.name, info, err, c.want)
		}
	}
	malformed := "BasicConstraints pathLenConstraint malformed"
	errs := []struct {
		name string
		cert []byte
		want string
	}{
		{"pathLen empty", g09dRoleCert(g09dExt(bcOID, false, g09dTLV(0x30, g09dTLV(0x02)))), malformed},
		{"pathLen octet", g09dRoleCert(g09dExt(bcOID, false, g09dTLV(0x30, g09dTLV(0x04, g09dRaw(0x05))))), malformed},
		{"pathLen 3 bytes", g09dRoleCert(g09dExt(bcOID, false, g09dTLV(0x30, g09dTLV(0x02, g09dRaw(0x01, 0x00, 0x00))))), malformed},
		{"pathLen negative", g09dRoleCert(g09dExt(bcOID, false, g09dTLV(0x30, g09dTLV(0x02, g09dRaw(0x80))))), malformed},
		{"tbs overruns", g09dTLV(0x30, g09dRaw(0x30, 0x05, 0x00)), "DER: element overruns its parent"},
		{"tbs not seq", g09dTLV(0x30, g09dTLV(0x31)), "certificate has no tbsCertificate"},
		{"tbs element overruns", g09dTLV(0x30, g09dTLV(0x30, g09dRaw(0xa3, 0x05, 0x00, 0x00))), "DER: element overruns its parent"},
		{"extensions overrun", g09dRoleCertRaw(g09dRaw(0x30, 0x05, 0x00)), "DER: element overruns its parent"},
		{"extension overruns", g09dRoleCertRaw(g09dTLV(0x30, g09dRaw(0x30, 0x05, 0x00))), "DER: element overruns its parent"},
		{"oid truncated", g09dRoleCert(g09dTLV(0x30, g09dRaw(0x06))), "DER: truncated header"},
		{"no value after critical", g09dRoleCert(g09dTLV(0x30, g09dTLV(0x06, bcOID), g09dTLV(0x01, g09dRaw(0xff)))), "DER: truncated header"},
		{"pathLen overruns", g09dRoleCert(g09dExt(bcOID, false, g09dTLV(0x30, g09dTLV(0x01, g09dRaw(0xff)), g09dRaw(0x02, 0x05)))), "DER: element overruns its parent"},
		{"first overruns", g09dRoleCert(g09dExt(bcOID, false, g09dTLV(0x30, g09dRaw(0x01, 0x05)))), "DER: element overruns its parent"},
		{"ku overruns", g09dRoleCert(g09dExt(kuOID, false, g09dRaw(0x03, 0x05))), "DER: element overruns its parent"},
	}
	for _, c := range errs {
		_, err := readCertRoleInfo(c.cert)
		g09dErr(t, c.name, err, c.want)
	}
	if got := checkChainRoles([][]byte{g09dRoleCert()}); got != "" {
		t.Errorf("a lone self-signed certificate needs no CA role: %q", got)
	}
}

func TestG09DerOidToDotted(t *testing.T) {
	for _, c := range []struct {
		b    byte
		want string
	}{{0x27, "0.39"}, {0x28, "1.0"}, {0x4f, "1.39"}, {0x50, "2.0"}} {
		got, err := oidToDotted([]byte{c.b}, derTlv{tag: 0x06, start: 0, end: 1})
		if err != nil || got != c.want {
			t.Errorf("arc %d: %q %v, want %q", c.b, got, err, c.want)
		}
	}
}

func TestG09DerParseTbsExtensions(t *testing.T) {
	ok, err := parseTbsExtensions(g09dTLV(0x30, g09dTLV(0x02, g09dRaw(1)), g09dTLV(0xa3, g09dTLV(0x30, g09dExt(g09dRaw(0x2a), true, nil)))))
	if err != nil || len(ok.oids) != 1 || ok.oids[0] != "1.2" || !ok.m["1.2"].critical {
		t.Fatalf("valid: %+v %v", ok, err)
	}
	ext := func(content []byte) []byte {
		return g09dTLV(0x30, g09dTLV(0x02, g09dRaw(1)), g09dTLV(0xa3, g09dTLV(0x30, content)))
	}
	for _, c := range []struct {
		name string
		tbs  []byte
		want string
	}{
		{"tbs not seq", g09dTLV(0x31, g09dTLV(0x02, g09dRaw(1))), "tbsCertificate is not a SEQUENCE"},
		{"element overruns", g09dTLV(0x30, g09dRaw(0x04, 0x05)), "DER: element overruns its parent"},
		{"extensions overrun", g09dTLV(0x30, g09dTLV(0xa3, g09dRaw(0x30, 0x05, 0x00))), "DER: element overruns its parent"},
		{"extension overruns", ext(g09dRaw(0x30, 0x05, 0x00)), "DER: element overruns its parent"},
		{"extension not seq", ext(g09dTLV(0x31, g09dTLV(0x06, g09dRaw(0x2a)), g09dTLV(0x04))), "extension is not a SEQUENCE"},
		{"oid truncated", ext(g09dTLV(0x30, g09dRaw(0x06))), "DER: truncated header"},
		{"no value", ext(g09dTLV(0x30, g09dTLV(0x06, g09dRaw(0x2a)))), "DER: truncated header"},
		{"no value after critical", ext(g09dTLV(0x30, g09dTLV(0x06, g09dRaw(0x2a)), g09dTLV(0x01, g09dRaw(0xff)))), "DER: truncated header"},
	} {
		_, err := parseTbsExtensions(c.tbs)
		g09dErr(t, c.name, err, c.want)
	}
}

func TestG09DerTbsOfCertificate(t *testing.T) {
	for _, c := range []struct {
		name string
		cert []byte
		want string
	}{
		{"empty", []byte{}, "DER: truncated header"},
		{"not seq", g09dTLV(0x31, g09dTLV(0x30)), "certificate is not a DER SEQUENCE"},
		{"tbs overruns", g09dTLV(0x30, g09dRaw(0x30, 0x05, 0x00)), "DER: element overruns its parent"},
		{"tbs not seq", g09dTLV(0x30, g09dTLV(0x31)), "certificate has no tbsCertificate"},
	} {
		_, err := tbsOfCertificate(c.cert)
		g09dErr(t, c.name, err, c.want)
	}
	if oid, found, err := unrecognisedCriticalExtension([]byte{}, nil); oid != "" || found || err == nil {
		t.Errorf("malformed: %q %v %v", oid, found, err)
	}
	if oid, found, err := unrecognisedCriticalExtension(g09dRoleCert(g09dExt(g09dRaw(0x2a), true, nil)), nil); oid != "1.2" || !found || err != nil {
		t.Errorf("unknown critical: %q %v %v", oid, found, err)
	}
}

func TestG09DerTlvAtAndTime(t *testing.T) {
	for _, c := range []struct {
		b    []byte
		want derTlv
		err  string
	}{
		{g09dRaw(0x30, 0x80), derTlv{}, "bad length"},
		{g09dRaw(0x04, 0x84, 0, 0, 0, 1, 0xaa), derTlv{tag: 0x04, start: 6, end: 7}, ""},
		{g09dRaw(0x04, 0x85, 0, 0, 0, 0, 1, 0xaa), derTlv{}, "bad length"},
		{g09dRaw(0x04, 0x81, 0x00), derTlv{tag: 0x04, start: 3, end: 3}, ""},
		{g09dRaw(0x04, 0x82, 0x00), derTlv{}, "bad length"},
	} {
		el, err := tlvAt(c.b, 0)
		if c.err != "" {
			g09dErr(t, "tlvAt", err, c.err)
		} else if err != nil || el != c.want {
			t.Errorf("tlvAt % x: %+v %v", c.b, el, err)
		}
	}
	if allASCIIDigits("") || allASCIIDigits("a1") || !allASCIIDigits("01") {
		t.Error("allASCIIDigits")
	}
	ms := func(y, mo, d, h, mi, s int) int64 {
		return time.Date(y, time.Month(mo), d, h, mi, s, 0, time.UTC).UnixMilli()
	}
	for _, c := range []struct {
		tag  int
		text string
		ok   bool
		ms   int64
	}{
		{0x18, "20240105120000Z", true, ms(2024, 1, 5, 12, 0, 0)},
		{0x18, "20240105125959Z", true, ms(2024, 1, 5, 12, 59, 59)},
		{0x17, "500101000000Z", true, ms(1950, 1, 1, 0, 0, 0)},
		{0x18, "20240105240000Z", false, 0},
		{0x18, "20241305000000Z", false, 0},
		{0x18, "20240005000000Z", false, 0},
		{0x18, "20240100000000Z", false, 0},
		{0x18, "20240105126000Z", false, 0},
		{0x18, "20240105125960Z", false, 0},
		{0x18, "2024010512000aZ", false, 0},
		{0x18, "20240105120000X", false, 0},
	} {
		got := parseDerTime(c.tag, c.text)
		if got.ok != c.ok || got.ms != c.ms {
			t.Errorf("%s: %+v, want ok=%v ms=%d", c.text, got, c.ok, c.ms)
		}
	}
}

type g09dVParts struct {
	outer, tbsTag              byte
	ver, serial, sig, iss, val []byte
	valOutside                 bool
}

func g09dVCert(mut func(*g09dVParts)) []byte {
	p := g09dVParts{outer: 0x30, tbsTag: 0x30,
		ver:    g09dTLV(0xa0, g09dTLV(0x02, g09dRaw(2))),
		serial: g09dTLV(0x02, g09dRaw(1)),
		sig:    g09dTLV(0x30),
		iss:    g09dTLV(0x30),
		val:    g09dTLV(0x30, g09dTLV(0x17, []byte("250101000000Z")), g09dTLV(0x17, []byte("350101000000Z"))),
	}
	if mut != nil {
		mut(&p)
	}
	if p.valOutside {
		return g09dTLV(p.outer, g09dTLV(p.tbsTag, p.ver, p.serial, p.sig, p.iss), p.val)
	}
	return g09dTLV(p.outer, g09dTLV(p.tbsTag, p.ver, p.serial, p.sig, p.iss, p.val), g09dTLV(0x30), g09dTLV(0x03, g09dRaw(0)))
}

func TestG09DerValidity(t *testing.T) {
	from2025 := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC).UnixMilli()
	to2035 := time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC).UnixMilli()
	for _, c := range []struct {
		name string
		mut  func(*g09dVParts)
		ok   bool
	}{
		{"default", nil, true},
		{"no version", func(p *g09dVParts) { p.ver = nil }, true},
		{"outer not seq", func(p *g09dVParts) { p.outer = 0x31 }, false},
		{"tbs not seq", func(p *g09dVParts) { p.tbsTag = 0x31 }, false},
		{"serial not integer", func(p *g09dVParts) { p.serial = g09dTLV(0x04, g09dRaw(1)) }, false},
		{"sig not seq", func(p *g09dVParts) { p.sig = g09dTLV(0x31) }, false},
		{"issuer not seq", func(p *g09dVParts) { p.iss = g09dTLV(0x31) }, false},
		{"validity not seq", func(p *g09dVParts) {
			p.val = g09dTLV(0x31, g09dTLV(0x17, []byte("250101000000Z")), g09dTLV(0x17, []byte("350101000000Z")))
		}, false},
		{"validity outside tbs", func(p *g09dVParts) { p.valOutside = true }, false},
		{"validity trailing", func(p *g09dVParts) {
			p.val = g09dTLV(0x30, g09dTLV(0x17, []byte("250101000000Z")), g09dTLV(0x17, []byte("350101000000Z")), g09dTLV(0x05))
		}, false},
	} {
		from, to := derValidity(g09dVCert(c.mut))
		if c.ok && (from != derInstant{ms: from2025, ok: true} || to != derInstant{ms: to2035, ok: true}) {
			t.Errorf("%s: %+v %+v", c.name, from, to)
		}
		if !c.ok && (from.ok || to.ok) {
			t.Errorf("%s: must not read a validity: %+v %+v", c.name, from, to)
		}
	}
	now2030 := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC).UnixMilli()
	badFrom := g09dVCert(func(p *g09dVParts) {
		p.val = g09dTLV(0x30, g09dTLV(0x17, []byte("2501010000xxZ")), g09dTLV(0x17, []byte("350101000000Z")))
	})
	if derValidAt(badFrom, now2030, 0) || derValidAtF(badFrom, now2030, 0) {
		t.Error("an unparseable notBefore must fail closed")
	}
	good := g09dVCert(nil)
	if !derValidAtF(good, to2035+1000, 1000) || derValidAtF(good, to2035+1001, 1000) {
		t.Error("derValidAtF upper edge: now - skew <= notAfter")
	}
}
