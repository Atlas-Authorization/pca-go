package pca

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

// attest_nvidia_ocsp.go, the BER reader that mirrors asn1js (ocspBER) and its helpers, pinned through direct calls. Expected
// values follow the reader's rules line by line (the same rules the 592000-structure differential in k05_ocsp_inner_time_test.go
// agreed with the reference on).

type r5n0Want struct {
	end, kind int
	ok        bool
}

type r5n0Run struct {
	r5n0Want
	st    ocspBERState
	panic any
}

// r5n0BER runs ocspBER over all of b; a panic is reported, not propagated, so it is a plain assertion failure.
func r5n0BER(b []byte, depth int, pre ocspBERState) (o r5n0Run) {
	o.st = pre
	defer func() { o.panic = recover() }()
	o.end, o.kind, o.ok = ocspBER(b, 0, len(b), depth, &o.st)
	return
}

func r5n0Check(t *testing.T, name string, b []byte, want r5n0Want) r5n0Run {
	t.Helper()
	o := r5n0BER(b, 0, ocspBERState{})
	if o.panic != nil {
		t.Errorf("%s: panic %v", name, o.panic)
		return o
	}
	if o.r5n0Want != want {
		t.Errorf("%s: got %+v, want %+v", name, o.r5n0Want, want)
	}
	return o
}

func r5n0OK(end, kind int) r5n0Want { return r5n0Want{end, kind, true} }

func TestR5N0_BERShapes(t *testing.T) {
	fail := r5n0Want{}
	hex := func(s ...byte) []byte { return s }
	zeros := func(n int) []byte { return make([]byte, n) }
	cat := func(parts ...[]byte) []byte { return bytes.Join(parts, nil) }
	genGood, genBad := []byte("20260531000000Z"), []byte("20261301000000Z")
	utcGood, utcBad := []byte("260531000000Z"), []byte("261301000000Z")
	const (
		throwGen = "Wrong input string for conversion"
		throwBMP = "Offset is outside the bounds of the DataView"
		throwUni = "byte length of Uint32Array should be a multiple of 4"
	)
	rows := []struct {
		name  string
		b     []byte
		want  r5n0Want
		threw string
	}{
		// high tag numbers
		{"high tag 5", hex(0x1f, 0x05, 0x00), r5n0OK(3, 5), ""},
		{"high tag 129 is past 36", hex(0x1f, 0x81, 0x01, 0x00), fail, ""},
		{"high tag, 8 bytes after 1f, keeps its number", cat(hex(0x1f), bytes.Repeat(hex(0x80), 7), hex(0x05, 0x00)), r5n0OK(10, 5), ""},
		{"high tag, 9 bytes after 1f, has no number", cat(hex(0x1f), bytes.Repeat(hex(0x80), 8), hex(0x05, 0x00)), r5n0OK(11, -1), ""},
		{"high tag cut after one byte", hex(0x1f, 0x81), fail, ""},
		{"high tag, nothing after 1f", hex(0x1f), fail, ""},
		// lengths
		{"long length, exact fit", hex(0x04, 0x81, 0x00), r5n0OK(3, 4), ""},
		{"long length with content", hex(0x04, 0x81, 0x02, 0xaa, 0xbb), r5n0OK(5, 4), ""},
		{"long length cut", hex(0x04, 0x82, 0x00), fail, ""},
		{"long length byte missing", hex(0x04, 0x81), fail, ""},
		{"long length of 8 bytes", hex(0x04, 0x88, 0, 0, 0, 0, 0, 0, 0, 2, 0xaa, 0xbb), r5n0OK(12, 4), ""},
		{"long length of 9 bytes", hex(0x04, 0x89, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0xaa, 0xbb), fail, ""},
		{"length that overflows", hex(0x04, 0x88, 0x80, 0, 0, 0, 0, 0, 0, 0, 0xaa), fail, ""},
		{"indefinite SEQUENCE", hex(0x30, 0x80, 0x05, 0x00, 0x00, 0x00), r5n0OK(6, 16), ""},
		{"indefinite primitive", hex(0x04, 0x80, 0x00, 0x00), fail, ""},
		{"indefinite SEQUENCE without content", hex(0x30, 0x80), r5n0OK(2, 16), ""},
		{"container one byte short for a child", hex(0x30, 0x01, 0x00), fail, ""},
		{"container with a one byte tail", hex(0x30, 0x03, 0x05, 0x00, 0xff), fail, ""},
		{"truncated octet", hex(0x04, 0x05, 0x01), fail, ""},
		{"truncated container", hex(0x30, 0x05, 0x05, 0x00), fail, ""},
		// EndOfContent
		{"EOC primitive", hex(0x00, 0x00), r5n0OK(2, 0), ""},
		{"EOC constructed, empty", hex(0x20, 0x00), r5n0OK(2, 0), ""},
		{"EOC constructed with content", hex(0x20, 0x01, 0xaa), r5n0Want{2, 0, false}, ""},
		{"EOC constructed, indefinite", hex(0x20, 0x80, 0x00), r5n0OK(2, 0), ""},
		// other classes
		{"context primitive", hex(0x80, 0x00), r5n0OK(2, -2), ""},
		{"context [1] primitive", hex(0x81, 0x00), r5n0OK(2, -2), ""},
		{"application primitive", hex(0x40, 0x00), r5n0OK(2, -2), ""},
		{"private primitive with content", hex(0xc0, 0x01, 0xff), r5n0OK(3, -2), ""},
		{"context primitive, content that is no element", hex(0x80, 0x01, 0xff), r5n0OK(3, -2), ""},
		{"context constructed", hex(0xa0, 0x01, 0xff), fail, ""},
		{"application constructed", hex(0x60, 0x01, 0xff), fail, ""},
		{"private constructed", hex(0xe0, 0x01, 0xff), fail, ""},
		{"context constructed number 10", hex(0xaa, 0x01, 0xff), fail, ""},
		{"context constructed number 12", hex(0xac, 0x01, 0xff), fail, ""},
		{"context constructed number 18", hex(0xb2, 0x01, 0xff), fail, ""},
		{"context constructed number 30", hex(0xbe, 0x01, 0xff), fail, ""},
		// primitive tags that still hold elements
		{"primitive SEQUENCE has children", hex(0x10, 0x01, 0xff), fail, ""},
		{"primitive SET has children", hex(0x11, 0x01, 0xff), fail, ""},
		{"primitive 18 is opaque", hex(0x12, 0x01, 0xff), r5n0OK(3, 18), ""},
		// values
		{"GeneralizedTime good", cat(hex(0x18, 0x0f), genGood), r5n0OK(17, 24), ""},
		{"GeneralizedTime bad month", cat(hex(0x18, 0x0f), genBad), r5n0Want{17, 24, true}, ""},
		{"UTCTime good", cat(hex(0x17, 0x0d), utcGood), r5n0OK(15, 23), ""},
		{"UTCTime bad month", cat(hex(0x17, 0x0d), utcBad), r5n0Want{15, 23, true}, ""},
		{"GeneralizedTime that throws", hex(0x18, 0x03, 'a', 'b', 'c'), fail, throwGen},
		{"OID ends inside an arc", hex(0x06, 0x01, 0x81), fail, ""},
		{"relative OID ends inside an arc", hex(0x0d, 0x01, 0x81), fail, ""},
		{"empty OID", hex(0x06, 0x00), r5n0OK(2, 6), ""},
		{"OID", hex(0x06, 0x01, 0x2a), r5n0OK(3, 6), ""},
		{"empty relative OID", hex(0x0d, 0x00), r5n0OK(2, 13), ""},
		{"relative OID", hex(0x0d, 0x01, 0x2a), r5n0OK(3, 13), ""},
		{"BMPString of one byte", hex(0x1e, 0x01, 0x00), fail, throwBMP},
		{"BMPString of three bytes", hex(0x1e, 0x03, 0x00, 0x41, 0x00), fail, throwBMP},
		{"BMPString of two bytes", hex(0x1e, 0x02, 0x00, 0x41), r5n0OK(4, 30), ""},
		{"empty BMPString", hex(0x1e, 0x00), r5n0OK(2, 30), ""},
		{"UniversalString of one byte", hex(0x1c, 0x01, 0x00), fail, throwUni},
		{"UniversalString of two bytes", hex(0x1c, 0x02, 0x00, 0x00), fail, throwUni},
		{"UniversalString of five bytes", hex(0x1c, 0x05, 0, 0, 0, 0, 0), fail, throwUni},
		{"UniversalString of four bytes", hex(0x1c, 0x04, 0, 0, 0, 0x41), r5n0OK(6, 28), ""},
		{"UniversalString of eight bytes", cat(hex(0x1c, 0x08), zeros(8)), r5n0OK(10, 28), ""},
		{"BIT STRING unused 8", hex(0x03, 0x02, 0x08, 0x00), fail, ""},
		{"BIT STRING of one byte, unused 8", hex(0x03, 0x01, 0x08), fail, ""},
		{"BIT STRING of one byte", hex(0x03, 0x01, 0x05), r5n0OK(3, 3), ""},
		{"BIT STRING unused 7", hex(0x03, 0x02, 0x07, 0x00), r5n0OK(4, 3), ""},
		{"empty BIT STRING", hex(0x03, 0x00), r5n0OK(2, 3), ""},
		{"OCTET STRING holding a bad time", cat(hex(0x04, 0x11, 0x18, 0x0f), genBad), r5n0Want{19, 4, true}, ""},
		{"OCTET STRING holding a good time", cat(hex(0x04, 0x11, 0x18, 0x0f), genGood), r5n0OK(19, 4), ""},
		// constructed strings and mixed content
		{"constructed OCTET STRING holding an INTEGER", hex(0x24, 0x03, 0x02, 0x01, 0x00), fail, ""},
		{"constructed BIT STRING, two with unused bits", hex(0x23, 0x08, 3, 2, 1, 0, 3, 2, 1, 0), fail, ""},
		{"constructed BIT STRING, only the first with unused bits", hex(0x23, 0x08, 3, 2, 1, 0, 3, 2, 0, 0), r5n0OK(10, 3), ""},
		{"SEQUENCE of two BIT STRINGs with unused bits", hex(0x30, 0x08, 3, 2, 1, 0, 3, 2, 1, 0), r5n0OK(10, 16), ""},
	}
	for _, r := range rows {
		o := r5n0Check(t, r.name, r.b, r.want)
		if o.panic == nil && o.st.threw != r.threw {
			t.Errorf("%s: threw %q, want %q", r.name, o.st.threw, r.threw)
		}
	}

	// every constructed universal tag number: those the reader refuses, those it reads as a container, those it keeps opaque
	refused := map[int]bool{1: true, 2: true, 5: true, 6: true, 9: true, 13: true, 14: true, 15: true, 23: true, 24: true, 31: true, 32: true, 33: true, 34: true}
	for n := 0; n <= 40; n++ {
		var tag []byte
		if n < 31 {
			tag = hex(0x20 | byte(n))
		} else {
			tag = hex(0x3f, byte(n))
		}
		content := hex(0xff) // no element: a container fails on it, an opaque tag does not
		switch n {
		case 28:
			content = bytes.Repeat(hex(0xff), 4)
		case 30:
			content = bytes.Repeat(hex(0xff), 2)
		}
		b := cat(tag, hex(byte(len(content))), content)
		opaque := n == 10 || n == 12 || (n >= 18 && n <= 30)
		want := fail
		switch {
		case refused[n] || n >= 37:
		case n == 0:
			want = r5n0Want{len(tag) + 1, 0, false}
		case opaque:
			want = r5n0OK(len(b), n)
		}
		r5n0Check(t, "constructed universal #"+itoaR5N0(n), b, want)
	}
	// every primitive universal tag number, with empty content
	for n := 0; n <= 40; n++ {
		var b []byte
		if n < 31 {
			b = hex(byte(n), 0x00)
		} else {
			b = hex(0x1f, byte(n), 0x00)
		}
		want := r5n0OK(len(b), n)
		switch {
		case n == 15 || n >= 37 || n == 24:
			want = fail
		}
		r5n0Check(t, "primitive universal #"+itoaR5N0(n), b, want)
	}
}

func itoaR5N0(n int) string {
	if n == 0 {
		return "0"
	}
	var d []byte
	for ; n > 0; n /= 10 {
		d = append([]byte{byte('0' + n%10)}, d...)
	}
	return string(d)
}

// The unused-bit count and the node count are shared parse state.
func TestR5N0_BERState(t *testing.T) {
	hex := func(s ...byte) []byte { return s }
	rows := []struct {
		name   string
		b      []byte
		pre    int
		want   r5n0Want
		unused int
	}{
		{"empty BIT STRING resets the count", hex(0x03, 0x00), 5, r5n0OK(2, 3), 0},
		{"INTEGER keeps the count", hex(0x02, 0x01, 0x00), 5, r5n0OK(3, 2), 5},
		{"BIT STRING of one byte sets it", hex(0x03, 0x01, 0x05), 0, r5n0OK(3, 3), 5},
		{"SEQUENCE keeps its child's count", hex(0x30, 0x04, 0x03, 0x02, 0x05, 0x00), 0, r5n0OK(6, 16), 5},
		{"context [3] keeps its child's count", hex(0xa3, 0x04, 0x03, 0x02, 0x05, 0x00), 0, r5n0OK(6, -2), 5},
		{"constructed BIT STRING takes its child's count", hex(0x23, 0x04, 0x03, 0x02, 0x05, 0x00), 0, r5n0OK(6, 3), 5},
		{"empty constructed BIT STRING resets the count", hex(0x23, 0x00), 5, r5n0OK(2, 3), 0},
		{"constructed BIT STRING after one with unused bits", hex(0x23, 0x06, 0x03, 0x02, 0x05, 0x00, 0x23, 0x00), 0, r5n0OK(8, 3), 0},
		{"empty constructed OCTET STRING keeps the count", hex(0x24, 0x00), 5, r5n0OK(2, 4), 5},
	}
	for _, r := range rows {
		o := r5n0BER(r.b, 0, ocspBERState{unused: r.pre})
		if o.panic != nil {
			t.Errorf("%s: panic %v", r.name, o.panic)
			continue
		}
		if o.r5n0Want != r.want || o.st.unused != r.unused {
			t.Errorf("%s: got %+v unused %d, want %+v unused %d", r.name, o.r5n0Want, o.st.unused, r.want, r.unused)
		}
	}
	// the node counter counts an element that fails on its first byte, but not one handed no bytes
	st := &ocspBERState{}
	if e, k, ok := ocspBER([]byte{0x05}, 0, 1, 0, st); e != 0 || k != 0 || ok || st.nodes != 1 {
		t.Errorf("one byte: %d %d %v nodes %d", e, k, ok, st.nodes)
	}
	st = &ocspBERState{}
	if e, k, ok := ocspBER([]byte{0x05, 0x00}, 0, 0, 0, st); e != 0 || k != 0 || ok || st.nodes != 0 {
		t.Errorf("no bytes: %d %d %v nodes %d", e, k, ok, st.nodes)
	}
	// nesting: a container reads its children only below the limit
	seq := hex(0x30, 0x02, 0x05, 0x00)
	if o := r5n0BER(seq, ocspMaxNesting, ocspBERState{}); o.panic != nil || o.r5n0Want != (r5n0Want{}) {
		t.Errorf("at the limit: %+v", o)
	}
	if o := r5n0BER(seq, ocspMaxNesting-1, ocspBERState{}); o.panic != nil || o.r5n0Want != r5n0OK(4, 16) {
		t.Errorf("below the limit: %+v", o)
	}
}

// ocspMaxContent is 16 MiB, written out here so a change to the constant is seen.
func TestR5N0_BERContentLimit(t *testing.T) {
	const limit = 16777216
	at := k05DeepTLV(0x04, make([]byte, limit))
	if o := r5n0BER(at, 0, ocspBERState{}); o.panic != nil || o.r5n0Want != r5n0OK(len(at), 4) {
		t.Errorf("16 MiB: %+v", o)
	}
	over := k05DeepTLV(0x04, make([]byte, limit+1))
	if o := r5n0BER(over, 0, ocspBERState{}); o.panic != nil || o.r5n0Want != (r5n0Want{}) {
		t.Errorf("16 MiB + 1: %+v", o)
	}
	// a time element past the limit is not a well-formed time, and the walk says so without reading it as BER
	der := k05DeepTLV(0x17, make([]byte, limit+1))
	n, err := readOcspNode(der, 0, len(der))
	if err != nil {
		t.Fatal(err)
	}
	if ocspTimesWellFormed(der, n) {
		t.Error("an oversize UTCTime passed the walk")
	}
}

// ocspWrapped judges nothing; it only shares the parse state, and a failed read clears the exception on its way out.
func TestR5N0_Wrapped(t *testing.T) {
	bad := append([]byte{0x18, 0x0f}, "20261301000000Z"...)
	rows := []struct {
		name  string
		c     []byte
		depth int
		threw string // threw after the call, with "x" before it
		nodes int
	}{
		{"empty keeps the exception", nil, 0, "x", 0},
		{"one byte fails the parse and clears it", []byte{0x05}, 0, "", 1},
		{"a valid element keeps it", []byte{0x05, 0x00}, 0, "x", 1},
		{"a bad time is not judged", bad, 0, "x", 1},
		{"a bad time and a trailing byte", append(append([]byte{}, bad...), 0), 0, "x", 1},
		{"at the nesting limit nothing is read", bad, ocspMaxNesting, "x", 0},
		{"below the nesting limit it is read", bad, ocspMaxNesting - 1, "x", 1},
	}
	for _, r := range rows {
		st := &ocspBERState{threw: "x"}
		ocspWrapped(r.c, r.depth, st)
		if st.threw != r.threw || st.nodes != r.nodes {
			t.Errorf("%s: threw %q nodes %d, want threw %q nodes %d", r.name, st.threw, st.nodes, r.threw, r.nodes)
		}
	}
}

// ocspTimesWellFormed: the walk stops one level past the nesting limit, and a time is judged by its own text.
func TestR5N0_TimesWalk(t *testing.T) {
	bad := derTLV(0x18, []byte("20261301000000Z"))
	nest := func(n int, c []byte) []byte {
		for i := 0; i < n; i++ {
			c = derTLV(0x30, c)
		}
		return c
	}
	for _, r := range []struct {
		name string
		der  []byte
		want bool
	}{
		{"time at depth 100", nest(100, bad), false},
		{"time at depth 101", nest(101, bad), false},
		{"time at depth 102", nest(102, bad), true},
		{"bare GeneralizedTime that throws", derTLV(0x18, []byte("abc")), false},
		{"bare bad UTCTime", derTLV(0x17, []byte("261301000000Z")), false},
		{"bare good UTCTime", derTLV(0x17, []byte("260531000000Z")), true},
	} {
		n, err := readOcspNode(r.der, 0, len(r.der))
		if err != nil {
			t.Fatalf("%s: %v", r.name, err)
		}
		if got := ocspTimesWellFormed(r.der, n); got != r.want {
			t.Errorf("%s = %v, want %v", r.name, got, r.want)
		}
	}
}

func TestR5N0_OID(t *testing.T) {
	s, err := ocspOID([]byte{0x04, 0x00}, ocspNode{tag: 0x04, hdr: 0, start: 2, end: 2})
	if s != "" || err == nil || err.Error() != "expected an OBJECT IDENTIFIER" {
		t.Errorf("not an OID: %q %v", s, err)
	}
}

func TestR5N0_TextHelpers(t *testing.T) {
	safe := func(f func() bool) (v bool, p any) {
		defer func() { p = recover() }()
		return f(), nil
	}
	for c, want := range map[byte]bool{0: false, 8: false, 9: true, 10: true, 11: true, 12: true, 13: true, 14: false, 31: false,
		32: true, 33: false, 0x9f: false, 0xa0: true, 0xa1: false, 0xff: false} {
		if got := ocspJSSpace(c); got != want {
			t.Errorf("ocspJSSpace(%#x) = %v, want %v", c, got, want)
		}
	}
	for s, want := range map[string]bool{
		"": true, "5": false, " 5": false, "\xa05": false, "\t5": false, "+5": false, "-5": false, "x": true, "+": true, "+x": true,
		"  ": true, " +5": false, "+ 5": true, "5x": false, "\x085": true,
	} {
		s := s
		if got, p := safe(func() bool { return ocspParseIntNaN(s) }); p != nil || got != want {
			t.Errorf("ocspParseIntNaN(%q) = %v (panic %v), want %v", s, got, p, want)
		}
	}
	for s, want := range map[string]bool{
		",5": true, ".5": false, ".": false, ".5e3": false, ".5E3": false, ".5e": true, ".5e+3": false, ".5e-3": false, ".5e+": true,
		".5 ": false, ".5x": true, ".5e3 ": false, ".5\xa0": false, ".5e3x": true, ".5 x": true, ".e3": false, ".5e3\t": false,
	} {
		s := s
		if got, p := safe(func() bool { return ocspFractionNaN(s) }); p != nil || got != want {
			t.Errorf("ocspFractionNaN(%q) = %v (panic %v), want %v", s, got, p, want)
		}
	}
	for s, want := range map[string]bool{
		"20260531000000.5e+3Z": true, "20260531000000.5e-3Z": true, "20260531000000.": true,
		"20260531000000-01": false, "20260531000000+0130": false, "20260531000000+01": false, "20260531000000+013": true,
		"20260531000000+": true, "20260531000000+0": true, "20260531000000+01301": true, "20260531000000+xx": true,
		"20260531000000+01x0": true, "20260531000000+0x": true, "202605310000": false, "2026053100000": true,
		"20260531": false, "202605": true, "2026053100": false, "x0260531000000": true, "20260531000000x": true,
		"20260531000000": false, "20260531000000,5": true, "20260531000000.5": false, ",": true,
	} {
		s := s
		if got, p := safe(func() bool { return ocspGenTimeThrows(s) }); p != nil || got != want {
			t.Errorf("ocspGenTimeThrows(%q) = %v (panic %v), want %v", s, got, p, want)
		}
	}
}

// An algorithm the table does not know is refused for every key; an RSA key would otherwise verify a bare SHA-512 digest.
func TestR5N0_SigOKUnknownAlgorithm(t *testing.T) {
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tbs := []byte("r5n0 tbs")
	digest := sha512.Sum512(tbs)
	sig, err := rsa.SignPKCS1v15(rand.Reader, rk, crypto.Hash(0), digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if ocspSigOK("1.2.3.4", tbs, sig, certKey{pub: &rk.PublicKey, typ: "rsa"}) {
		t.Error("unknown algorithm verified under an RSA key")
	}
}

// Structure and responder-loop rows that need the signed fixtures.
func TestR5N0_OcspVerifyLoops(t *testing.T) {
	f := g02newFx(t)
	at := g02now.Add(-time.Hour)
	verify := func(der []byte, chain []*attCert) ocspResult {
		return verifyNvidiaOcspResponse(der, f.leafA, f.interA, chain, f.nowMs)
	}

	// a length the strict reader refuses (five length bytes) that the BER reader accepts: refused as not valid DER
	oddLen := []byte{0x30, 0x85, 0, 0, 0, 0, 0}
	if got, want := verify(oddLen, f.chain), g02no("response is not valid DER"); got != want {
		t.Errorf("outer odd length: %+v", got)
	}
	if got, want := verify(g02wrapBasic(oddLen), f.chain), g02no("BasicOCSPResponse is not valid DER"); got != want {
		t.Errorf("basic odd length: %+v", got)
	}

	// a CertID with a hash algorithm the verifier does not know is skipped, even when its hashes are SHA-512 of the right inputs
	ser, err := asn1.Marshal(f.leaf.SerialNumber)
	if err != nil {
		t.Fatal(err)
	}
	unknownID := derTLV(0x30, derTLV(0x30, g02oid("1.2.3.4")), derTLV(0x04, hashBytes(crypto.SHA512, f.interA.RawSubject)),
		derTLV(0x04, hashBytes(crypto.SHA512, g02bits(t, f.interA.RawSPKI))), ser)
	unknownSingle := g02single(unknownID, g02good, g02gt(at))
	goodSingle := g02single(g02certID(t, f.interA, f.leaf.SerialNumber), g02good, g02gt(at))
	withSingles := func(s ...[]byte) []byte { return f.mod(t, func(r *g02rsp) { r.singles = s }) }
	if got, want := verify(withSingles(unknownSingle), f.chain), g02no("no SingleResponse matches the certificate (serial / issuer hashes differ)"); got != want {
		t.Errorf("unknown hash alone: %+v", got)
	}
	if got := verify(withSingles(unknownSingle, goodSingle), f.chain); got != g02ok("good") {
		t.Errorf("unknown hash, then a match: %+v", got)
	}

	// embedded responder certificates: a certificate that fails any test is passed over for the next one
	respOK := f.responder(t, nil, f.inter, f.interK)
	respA := g02att(t, respOK.Raw)
	deleg := func(certs ...[]byte) []byte {
		return f.mod(t, func(r *g02rsp) { r.rid, r.certs, r.signer = g02byName(respA), g02certs(certs...), f.respK })
	}
	noEKU := f.responder(t, func(c *x509.Certificate) { c.ExtKeyUsage = nil }, f.inter, f.interK)
	expired := f.responder(t, func(c *x509.Certificate) { c.NotAfter = g02now.Add(-time.Hour) }, f.inter, f.interK)
	belowIssuer := f.responder(t, nil, f.leaf, f.leafK)
	wrongKey := g02mk(t, &x509.Certificate{SerialNumber: big.NewInt(78), Subject: pkix.Name{CommonName: "g02 ocsp responder"},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}, KeyUsage: x509.KeyUsageDigitalSignature}, f.inter, &f.otherK.PublicKey, f.interK)
	for name, der := range map[string][]byte{
		"not the responderID":     deleg(f.root.Raw, respOK.Raw),
		"no OCSPSigning EKU":      deleg(noEKU.Raw, respOK.Raw),
		"outside its validity":    deleg(expired.Raw, respOK.Raw),
		"not signed by the chain": deleg(belowIssuer.Raw, respOK.Raw),
		"signature under its key": deleg(wrongKey.Raw, respOK.Raw),
	} {
		if got := verify(der, f.chain); got != g02ok("good") {
			t.Errorf("%s, then a good certificate: %+v", name, got)
		}
	}

	// a validity bound the strict reader cannot read (GeneralizedTime with a fraction) is outside the window even though the
	// other bound is fine
	if got, want := verify(deleg(r5n0FracNotBefore(t, f)), f.chain), g02no("delegated responder certificate is outside its validity window"); got != want {
		t.Errorf("unreadable notBefore: %+v", got)
	}

	// the signer list runs from the first copy of the issuer in the chain
	rootSigned := f.responder(t, nil, f.root, f.rootK)
	chain4 := []*attCert{f.leafA, f.interA, f.rootA, f.interA}
	if got := verify(deleg(rootSigned.Raw), chain4); got != g02ok("good") {
		t.Errorf("issuer twice in the chain: %+v", got)
	}

	// the loop stops at the first certificate that verifies
	seen := 0
	old := ocspCandidateSeen
	ocspCandidateSeen = func(*attCert) { seen++ }
	t.Cleanup(func() { ocspCandidateSeen = old })
	if got := verify(deleg(respOK.Raw, f.root.Raw), f.chain); got != g02ok("good") {
		t.Errorf("good then another: %+v", got)
	}
	if seen != 1 {
		t.Errorf("candidates read: %d, want 1", seen)
	}
}

// r5n0FracNotBefore is a responder certificate whose notBefore is the GeneralizedTime 20250101000000.5Z: a well-formed time to the
// response walk, unreadable to the certificate validity reader.
func r5n0FracNotBefore(t *testing.T, f *g02fx) []byte {
	t.Helper()
	c := f.responder(t, nil, f.inter, f.interK)
	var tbs asn1.RawValue
	if _, err := asn1.Unmarshal(c.RawTBSCertificate, &tbs); err != nil {
		t.Fatal(err)
	}
	var kids [][]byte
	rest := tbs.Bytes
	for len(rest) > 0 {
		var rv asn1.RawValue
		var err error
		if rest, err = asn1.Unmarshal(rest, &rv); err != nil {
			t.Fatal(err)
		}
		kids = append(kids, rv.FullBytes)
	}
	if len(kids) < 5 || kids[0][0] != 0xa0 {
		t.Fatalf("unexpected TBSCertificate shape: %d members", len(kids))
	}
	var validity, notBefore, notAfter asn1.RawValue
	if _, err := asn1.Unmarshal(kids[4], &validity); err != nil {
		t.Fatal(err)
	}
	after, err := asn1.Unmarshal(validity.Bytes, &notBefore)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := asn1.Unmarshal(after, &notAfter); err != nil {
		t.Fatal(err)
	}
	kids[4] = derTLV(0x30, derTLV(0x18, []byte("20250101000000.5Z")), notAfter.FullBytes)
	newTBS := derTLV(0x30, kids...)
	h := sha256.Sum256(newTBS)
	sig, err := ecdsa.SignASN1(rand.Reader, f.interK, h[:])
	if err != nil {
		t.Fatal(err)
	}
	return derTLV(0x30, newTBS, derTLV(0x30, g02oid("1.2.840.10045.4.3.2")), derTLV(0x03, append([]byte{0}, sig...)))
}
