package pcasigstore

// The reference's JavaScript semantics on inputs the k05 oracle does not reach (values checked against node 22): URL host
// extraction, Date.parse of RFC 3339, Number#toString, DER length forms, OID arcs, GeneralizedTime, base64, TextDecoder,
// JavaScript white space and crypto.verify's algorithm handling.

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"math"
	"testing"
)

func throws(f func()) bool { return catch(f) != nil }

func TestSigstoreHostname(t *testing.T) {
	for in, want := range map[string]string{
		"https://user@Host.EXAMPLE:443/p?q#f": "host.example",
		"https://[::1]:8080/":                 "[::1]",
		"http://h?x":                          "h",
		"http://h#x":                          "h",
		"http://a:b@h/x":                      "h",
		" \thttps://a.b\n ":                   "a.b",
		"https://a\tb.c":                      "ab.c",
		"https://a\nb.c/":                     "ab.c",
		"https://a\rb.c/":                     "ab.c",
		"noscheme":                            "",
		"":                                    "",
	} {
		if got := hostname(in); got != want {
			t.Errorf("hostname(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSigstoreRFC3339(t *testing.T) {
	const jan1 = 1767225600000 // 2026-01-01T00:00:00Z
	for in, want := range map[string]int64{
		"2026-01-01T00:00:00Z":           jan1,
		"2026-01-01T24:00:00Z":           jan1 + 86400000,
		"2026-01-01T24:00:00.000Z":       jan1 + 86400000,
		"2026-01-01T00:00:00.5Z":         jan1 + 500,
		"2026-01-01T00:00:00.123456789Z": jan1 + 123,
		"2026-01-01T00:00:00+05:30":      1767205800000,
		"2026-01-01T00:00:00-23:59":      1767311940000,
		"2024-02-29T00:00:00Z":           1709164800000,
		"0100-01-01T00:00:00Z":           -59011459200000,
		"2026-12-31T23:59:59Z":           1798761599000,
	} {
		if got, ok := rfc3339(in); !ok || got != want {
			t.Errorf("rfc3339(%q) = %d %v, want %d", in, got, ok, want)
		}
	}
	for _, in := range []string{"2026-01-01T24:00:01Z", "2026-01-01T24:01:00Z", "2026-01-01T24:00:00.0001Z", "2026-01-01T25:00:00Z",
		"2026-01-01T00:00:00+24:00", "2026-01-01T00:00:00+00:60", "2026-01-01T00:60:00Z", "2026-01-01T00:00:60Z", "2023-02-29T00:00:00Z",
		"2026-13-01T00:00:00Z", "2026-00-01T00:00:00Z", "2026-01-00T00:00:00Z", "2026-01-32T00:00:00Z", "0099-01-01T00:00:00Z",
		"2026-01-01t00:00:00Z", "2026-01-01T00:00:00z", "2026-01-01T00:00:00", "2026-01-01T00:00:00.Z", "2026-01-01T00:00:00.1234567890Z"} {
		if got, ok := rfc3339(in); ok {
			t.Errorf("rfc3339(%q) = %d, want refused", in, got)
		}
	}
}

func TestSigstoreValidity(t *testing.T) {
	v := readValidity(map[string]any{"start": "2026-01-01T00:00:00Z", "end": json.Number("5")})
	if v.end != forever || v.start != 1767225600000 {
		t.Fatalf("a non-string end is open: %+v", v)
	}
	if !v.has(v.start) || v.has(v.start-1) || !v.has(math.MaxInt64) {
		t.Fatal("has")
	}
	w := readValidity(map[string]any{"start": "2026-01-01T00:00:00Z", "end": "2026-01-01T00:00:01Z"})
	if !w.has(w.end) || w.has(w.end+1) || w.end != 1767225601000 {
		t.Fatalf("closed end: %+v", w)
	}
	for _, x := range []any{nil, map[string]any{}, map[string]any{"start": 5}, map[string]any{"start": "x"},
		map[string]any{"start": "2026-01-01T00:00:00Z", "end": "x"}} {
		if !throws(func() { readValidity(x) }) {
			t.Errorf("validity %v accepted", x)
		}
	}
}

func TestSigstoreJSNum(t *testing.T) {
	for _, c := range []struct {
		f    float64
		want string
	}{{0, "0"}, {math.Copysign(0, -1), "0"}, {5, "5"}, {-5, "-5"}, {1 << 60, "1152921504606847000"}, {1e21, "1e+21"},
		{1 << 70, "1.1805916207174113e+21"}, {999999999999999900000, "999999999999999900000"}, {123.456, "123.456"},
		{0.5, "0.5"}, {0.000001, "0.000001"}, {0.0000015, "0.0000015"}, {1e-7, "1e-7"}, {1.5e-7, "1.5e-7"}, {-2.5e-8, "-2.5e-8"},
		{1.5e300, "1.5e+300"}, {math.NaN(), "NaN"}, {math.Inf(1), "Infinity"}, {math.Inf(-1), "-Infinity"}} {
		if got := jsNum(c.f); got != c.want {
			t.Errorf("jsNum(%v) = %s, want %s", c.f, got, c.want)
		}
	}
	o := map[string]any{"n": nil, "t": true, "f": false, "s": "x", "z": json.Number("-0"), "i": json.Number("1e400"), "d": json.Number("1.50"),
		"e": []any{}, "a": []any{nil, "x", json.Number("2"), []any{"y", "z"}}, "o": map[string]any{"x": json.Number("1")}}
	for k, want := range map[string]string{"missing": "undefined", "n": "null", "t": "true", "f": "false", "s": "x", "z": "0", "i": "Infinity",
		"d": "1.5", "e": "", "a": ",x,2,y,z", "o": "[object Object]"} {
		if got := jsStr(o, k); got != want {
			t.Errorf("jsStr(%s) = %q, want %q", k, got, want)
		}
	}
}

func TestSigstoreDER(t *testing.T) {
	for n, head := range map[int][]byte{0: {4, 0}, 0x7f: {4, 0x7f}, 0x80: {4, 0x81, 0x80}, 0xff: {4, 0x81, 0xff}, 0x100: {4, 0x82, 1, 0},
		0xffff: {4, 0x82, 0xff, 0xff}, 0x10000: {4, 0x83, 1, 0, 0}} {
		got := enc(4, make([]byte, n))
		if !bytes.Equal(got[:len(head)], head) || len(got) != len(head)+n {
			t.Errorf("enc(%d) head %x", n, got[:min(len(got), 5)])
		}
		if n > 0 {
			if e := tlv(got, 0, len(got)); e.tag != 4 || e.body != len(head) || e.end != len(got) {
				t.Errorf("tlv(enc(%d)) = %+v", n, e)
			}
		}
	}
	if e := tlv([]byte{0x30, 0x81, 0x01, 0xaa, 0xbb}, 0, 5); e != (tlvT{0x30, 0, 3, 4}) {
		t.Errorf("non-minimal long form: %+v", e)
	}
	if e := tlv([]byte{0x30, 0x84, 0, 0, 0, 1, 7}, 0, 7); e.end != 7 {
		t.Errorf("4-byte length: %+v", e)
	}
	for _, b := range [][]byte{{0x30}, {0x1f, 0}, {0x3f, 0}, {0x30, 0x80}, {0x30, 0x85, 0, 0, 0, 0, 1}, {0x30, 0x82, 1}, {0x30, 2, 0}, {0x30, 0x81, 2, 0}} {
		if !throws(func() { tlv(b, 0, len(b)) }) {
			t.Errorf("tlv(%x) accepted", b)
		}
	}
	if !throws(func() { tlv([]byte{0x30, 1, 0, 0}, 0, 2) }) || throws(func() { tlv([]byte{0x30, 1, 0, 0}, 0, 3) }) {
		t.Error("tlv limit")
	}
	if k := kids([]byte{0x30, 4, 1, 0, 2, 0}, tlvT{0x30, 0, 2, 6}); len(k) != 2 || k[1].start != 4 {
		t.Errorf("kids %+v", k)
	}
	oid := func(b ...byte) string { return oidText(b, tlvT{6, 0, 0, len(b)}) }
	for want, b := range map[string][]byte{"1.2.840": {0x2a, 0x86, 0x48}, "0.39": {39}, "1.0": {40}, "2.0": {80}, "2.40": {120}, "2.100": {0x81, 0x34}, "1.3.6.1.4.1.57264.1.8": {0x2b, 6, 1, 4, 1, 0x83, 0xbf, 0x30, 1, 8}} {
		if got := oid(b...); got != want {
			t.Errorf("oid %x = %s, want %s", b, got, want)
		}
	}
	for _, b := range [][]byte{{0x80, 1}, {0x2a, 0x80, 1}, {0x81}, {0x2a, 0x86}} {
		if !throws(func() { oid(b...) }) {
			t.Errorf("oid %x accepted", b)
		}
	}
	if !throws(func() { oidText([]byte{4, 1, 1}, tlvT{4, 0, 2, 3}) }) || !throws(func() { oidText([]byte{6, 0}, tlvT{6, 0, 2, 2}) }) {
		t.Error("not an OID accepted")
	}
}

func TestSigstoreGeneralizedTime(t *testing.T) {
	gt := func(tag byte, s string) func() int64 {
		return func() int64 {
			b := append([]byte{tag, byte(len(s))}, s...)
			return generalizedTime(b, tlvT{int(tag), 0, 2, len(b)})
		}
	}
	for s, want := range map[string]int64{"20260601120030Z": 1780315230000, "20260601120030.5Z": 1780315230500, "20260601120030.123456789Z": 1780315230123, "20240229000000Z": 1709164800000} {
		var got int64
		if err := catch(func() { got = gt(0x18, s)() }); err != nil || got != want {
			t.Errorf("genTime %s = %d %v, want %d", s, got, err, want)
		}
	}
	for _, s := range []string{"20260601240000Z", "20230229000000Z", "20261301000000Z", "20260601126000Z", "20260601120060Z", "00500601120030Z",
		"2026060112003Z", "20260601120030", "20260601120030.Z", "20260601120030.1234567890Z", "20260601120030+0000"} {
		if !throws(func() { gt(0x18, s)() }) {
			t.Errorf("genTime %s accepted", s)
		}
	}
	if !throws(func() { gt(0x17, "260601120030Z")() }) {
		t.Error("a UTCTime genTime accepted")
	}
}

func TestSigstoreScalars(t *testing.T) {
	for in, want := range map[string]int64{"0": 0, "7": 7, "9007199254740991": maxSafe} {
		var got int64
		if err := catch(func() { got = decInt(in) }); err != nil || got != want {
			t.Errorf("decInt(%s) = %d %v", in, got, err)
		}
	}
	for _, in := range []any{"9007199254740992", "9999999999999999", "01", "-1", "1.0", "", "12345678901234567", json.Number("5"), nil} {
		if !throws(func() { decInt(in) }) {
			t.Errorf("decInt(%v) accepted", in)
		}
	}
	for in, want := range map[string][]byte{"": {}, "AA==": {0}, "AB==": {0}, "AAA=": {0, 0}, "AAAA": {0, 0, 0}, "+/+/": {0xfb, 0xff, 0xbf}} {
		var got []byte
		if err := catch(func() { got = b64(in) }); err != nil || !bytes.Equal(got, want) {
			t.Errorf("b64(%q) = %x %v", in, got, err)
		}
	}
	for _, in := range []any{"AA", "AA=A", "A===", "AAA", "AA==AA==", "-_-_", "AA== ", "AA\n==", nil, json.Number("1")} {
		if !throws(func() { b64(in) }) {
			t.Errorf("b64(%v) accepted", in)
		}
	}
	if utf8Strict([]byte("\xEF\xBB\xBFab")) != "ab" || utf8Strict([]byte("a\xEF\xBB\xBF")) != "a\uFEFF" || !throws(func() { utf8Strict([]byte{0xff}) }) ||
		!throws(func() { utf8Strict([]byte{0xed, 0xa0, 0x80}) }) {
		t.Error("utf8Strict")
	}
	if latin1([]byte{0x41, 0xe9, 0}) != "Aé\x00" {
		t.Error("latin1")
	}
	for _, r := range []rune{'\t', '\n', '\v', '\f', '\r', ' ', 0xa0, 0x1680, 0x2000, 0x2005, 0x200a, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff} {
		if !isJSSpace(r) {
			t.Errorf("%U is JavaScript white space", r)
		}
	}
	for _, r := range []rune{'a', 0x85, 0x1fff, 0x200b, 0x180e, 0x2027, 0x202a, 0x2060, 0xfffe, 0} {
		if isJSSpace(r) {
			t.Errorf("%U is not JavaScript white space", r)
		}
	}
	if string(DSSEPAE("é", []byte("x"))) != "DSSEv1 2 é 1 x" || string(DSSEPAE("", nil)) != "DSSEv1 0  0 " {
		t.Error("PAE")
	}
	pem := "-----BEGIN CERTIFICATE-----\nAAEC\nAw==\n-----END CERTIFICATE-----"
	if !bytes.Equal(pemDer([]byte(pem)), []byte{0, 1, 2, 3}) || !bytes.Equal(pemDer([]byte(pem+"\n")), []byte{0, 1, 2, 3}) ||
		pemDer([]byte(pem+"\n\n")) != nil || pemDer([]byte(" "+pem)) != nil || !throws(func() { pemDer([]byte("-----BEGIN CERTIFICATE-----\nAA\n-----END CERTIFICATE-----")) }) {
		t.Error("pemDer")
	}
}

func TestSigstoreNodeVerify(t *testing.T) {
	msg := []byte("checkpoint body\n")
	_, ep, _ := ed25519.GenerateKey(rand.Reader)
	esig := ed25519.Sign(ep, msg)
	if !nodeVerify(0, msg, ep.Public(), esig) || nodeVerify(crypto.SHA256, msg, ep.Public(), esig) || nodeVerify(0, msg[1:], ep.Public(), esig) {
		t.Error("Ed25519 verifies only with no digest")
	}
	h := sha256.Sum256(msg)
	ek, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	es, _ := ecdsa.SignASN1(rand.Reader, ek, h[:])
	if !nodeVerify(0, msg, &ek.PublicKey, es) || !nodeVerify(crypto.SHA256, msg, &ek.PublicKey, es) || nodeVerify(crypto.SHA384, msg, &ek.PublicKey, es) ||
		nodeVerify(crypto.SHA256, msg, &ek.PublicKey, append(es, 0)) {
		t.Error("ECDSA: default and explicit SHA-256 only")
	}
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	rs, _ := rsa.SignPKCS1v15(rand.Reader, rk, crypto.SHA256, h[:])
	if !nodeVerify(0, msg, &rk.PublicKey, rs) || !nodeVerify(crypto.SHA256, msg, &rk.PublicKey, rs) || nodeVerify(crypto.SHA512, msg, &rk.PublicKey, rs) {
		t.Error("RSA PKCS#1 v1.5: default and explicit SHA-256 only")
	}
	if nodeVerify(crypto.SHA256, msg, "not a key", es) || nodeVerify(0, msg, nil, esig) {
		t.Error("an unknown key verified")
	}
	k384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	k521, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if leafHashAlg(&ek.PublicKey) != crypto.SHA256 || leafHashAlg(&k384.PublicKey) != crypto.SHA384 || leafHashAlg(&k521.PublicKey) != 0 ||
		leafHashAlg(ep.Public()) != 0 || leafHashAlg(&rk.PublicKey) != 0 {
		t.Error("leafHashAlg")
	}
	if !bytes.Equal(digest(crypto.SHA256, msg), h[:]) || len(digest(crypto.SHA384, msg)) != 48 || len(digest(crypto.SHA512, msg)) != 64 {
		t.Error("digest")
	}
	if !bytes.Equal(sha256Of([]byte("a"), []byte("b")), digest(crypto.SHA256, []byte("ab"))) {
		t.Error("sha256Of")
	}
}
