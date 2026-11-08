package pca

import (
	"bytes"
	"strings"
	"testing"
)

// Every row was measured through allAsn1TimesWellFormed over asn1js fromBER (Node 26, asn1js 3.0.10). A JS mirror of ocspBER agreed
// with the reference on all of 592000 generated structures, for the outer parse result and for the time walk.
func TestK05OcspInnerTimes(t *testing.T) {
	const badText, goodText = "20261301000000Z", "20260531000000Z"
	bad, good := derTLV(0x18, []byte(badText)), derTLV(0x18, []byte(goodText))
	badUTC := derTLV(0x17, []byte("261301000000Z"))
	octet := func(c ...[]byte) []byte { return derTLV(0x30, derTLV(0x04, c...)) }
	bits := func(unused byte, c ...[]byte) []byte {
		return derTLV(0x30, derTLV(0x03, append([][]byte{{unused}}, c...)...))
	}
	gen := func(s string) []byte { return derTLV(0x18, []byte(s)) }
	raw := func(hdr []byte, s string) []byte { return append(append([]byte{}, hdr...), s...) }
	for _, r := range []struct {
		name string
		der  []byte
		want bool
	}{
		{"octet: bad GeneralizedTime", octet(bad), false},
		{"octet: bad UTCTime", octet(badUTC), false},
		{"octet: good", octet(good), true},
		{"bit 0 unused: bad", bits(0, bad), false},
		{"bit 0 unused: good", bits(0, good), true},
		{"bit 1 unused: opaque", bits(1, bad), true},
		{"bit 7 unused: opaque", bits(7, bad), true},
		{"octet: trailing byte, opaque", octet(bad, []byte{0}), true},
		{"octet: two elements, opaque", octet(bad, good), true},
		{"bit: trailing byte, opaque", bits(0, bad, []byte{0}), true},
		{"octet: truncated, opaque", octet(bad[:10]), true},
		{"octet: non-minimal length", octet(raw([]byte{0x18, 0x81, 15}, badText)), false},
		{"octet: leading-zero length", octet(raw([]byte{0x18, 0x82, 0, 15}, badText)), false},
		{"octet: high tag form", octet(raw([]byte{0x1f, 0x18, 15}, badText)), false},
		{"octet: indefinite SEQUENCE", octet([]byte{0x30, 0x80}, bad, []byte{0, 0}), false},
		{"octet: indefinite without EndOfContent, opaque", octet([]byte{0x30, 0x80}, bad), true},
		{"octet: GeneralizedTime text that throws, opaque", octet(gen("abc")), true},
		{"octet: empty GeneralizedTime throws, opaque", octet(gen("")), true},
		{"octet: UTCTime garbage only records an error", octet(derTLV(0x17, []byte("abc"))), false},
		{"octet: empty UTCTime", octet(derTLV(0x17, nil)), false},
		{"octet: no Z, parses, not strict", octet(gen("20261301000000")), false},
		{"octet: a sibling that throws hides the bad time", octet(derTLV(0x30, bad, gen("abc"))), true},
		{"octet: constructed time fails the parse, opaque", octet(derTLV(0x38, bad)), true},
		{"octet: a child may overrun its parent", octet([]byte{0x30, 3}, bad), false},
		{"octet in octet", octet(derTLV(0x04, bad)), false},
		{"bit in octet", octet(derTLV(0x03, []byte{0}, bad)), false},
		{"octet in SEQUENCE in bit", bits(0, octet(bad)), false},
		{"octet: a bad BIT STRING fails the parse, opaque", octet(derTLV(0x30, derTLV(0x03, []byte{8, 1}), bad)), true},
		{"constructed octet holding a bad time", derTLV(0x30, derTLV(0x24, derTLV(0x04, bad))), false},
		{"octet: constructed octet with another child, opaque", octet(derTLV(0x24, bad)), true},
		{"context primitive: opaque", derTLV(0x30, derTLV(0x80, bad)), true},
		{"context constructed", derTLV(0x30, derTLV(0xa0, bad)), false},
		{"UTF8String: opaque", derTLV(0x30, derTLV(0x0c, bad)), true},
		{"primitive SEQUENCE tag still has children", derTLV(0x30, derTLV(0x10, bad)), false},
		{"empty octet", octet(), true},
		{"bit with only the unused count", bits(0), true},
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

// The depth is shared with the enclosing structure: past it the innermost string is opaque (a failed parse), and the walk stops.
func TestK05OcspInnerTimeDepth(t *testing.T) {
	bad := derTLV(0x18, []byte("20261301000000Z"))
	nest := func(tag byte, n int, c []byte) []byte {
		for i := 0; i < n; i++ {
			c = derTLV(tag, c)
		}
		return c
	}
	for _, r := range []struct {
		name string
		der  []byte
		want bool
	}{
		{"99 octets", nest(4, 99, bad), false},
		{"100 octets", nest(4, 100, bad), false},
		{"101 octets", nest(4, 101, bad), true},
		{"150 octets", nest(4, 150, bad), true},
		{"99 SEQUENCE, octet", nest(0x30, 99, derTLV(4, bad)), false},
		{"100 SEQUENCE, octet", nest(0x30, 100, derTLV(4, bad)), true},
		{"98 SEQUENCE, octet, SEQUENCE", nest(0x30, 98, derTLV(4, derTLV(0x30, bad))), false},
		{"99 SEQUENCE, octet, SEQUENCE", nest(0x30, 99, derTLV(4, derTLV(0x30, bad))), true},
		{"octet, 99 SEQUENCE", derTLV(4, nest(0x30, 99, bad)), false},
		{"octet, 100 SEQUENCE", derTLV(4, nest(0x30, 100, bad)), true},
	} {
		n, err := readOcspNode(r.der, 0, len(r.der))
		if err != nil {
			t.Fatalf("%s: %v", r.name, err)
		}
		if got := ocspTimesWellFormed(r.der, n); got != r.want {
			t.Errorf("%s = %v, want %v", r.name, got, r.want)
		}
	}
	// hostile depth inside a primitive string ends at the limit: a stack overflow would kill the test binary
	chain := k05DeepRetag(k05DeepDER(1<<20), 0x04)
	for name, content := range map[string][]byte{
		"nested SEQUENCE":   k05DeepDER(1 << 20),
		"nested OCTET":      chain,
		"indefinite":        []byte(strings.Repeat("\x30\x80", 4<<20)),
		"high tags":         []byte(strings.Repeat("\x3f\x10\x80", 2<<20)),
		"constructed octet": []byte(strings.Repeat("\x24\x80", 4<<20)),
	} {
		der := k05DeepTLV(0x30, k05DeepTLV(0x04, content))
		n, err := readOcspNode(der, 0, len(der))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !ocspTimesWellFormed(der, n) {
			t.Errorf("%s: opaque content refused", name)
		}
	}
}

// Through the verifier: the walk runs before the signature, with the reference's reason.
func TestK05OcspInnerTimeVerify(t *testing.T) {
	f := g02newFx(t)
	bad := derTLV(0x18, []byte("20261301000000Z"))
	alg, sig := derTLV(0x30, g02oid("1.2.840.10045.4.3.2")), derTLV(0x03, []byte{0})
	want := ocspFail("response carries a malformed (out-of-range) ASN.1 time")
	for name, basic := range map[string][]byte{
		"octet in tbs":     derTLV(0x30, derTLV(0x30, derTLV(0x04, bad)), alg, sig),
		"signature bits":   derTLV(0x30, derTLV(0x30), alg, derTLV(0x03, []byte{0}, bad)),
		"after the fields": derTLV(0x30, derTLV(0x30), alg, sig, derTLV(0x04, bad)),
	} {
		if got := verifyNvidiaOcspResponse(g02wrapBasic(basic), f.leafA, f.interA, f.chain, f.nowMs); got != want {
			t.Errorf("%s: %+v", name, got)
		}
	}
}

// The port of GeneralizedTime.fromString's throws, against the reference's outcome for each text.
func TestK05OcspGenTimeThrows(t *testing.T) {
	for s, want := range map[string]bool{
		"": true, "1": true, "abc": true, "20260531000000 ": true, "20260531000000\xa0": true,
		"20260531000000+  12": true, "20260531000000,5Z": true, "20260531.5Z": true, "20260531000000+0": true,
		"20260531000000-0100Z": true,
		"20260531000000+1x12":  false, "20260531000000.5e1Z": false, "20260531000000.Z": false,
		"2026053100.5Z": false, "20260531Z": false, "2026053100+01": false, "20260531000000Z": false, "20261301000000Z": false,
		"20261301000000": false,
	} {
		if got := ocspGenTimeThrows(s); got != want {
			t.Errorf("ocspGenTimeThrows(%q) = %v, want %v", s, got, want)
		}
	}
}

// What asn1js refuses or throws on while parsing the outer structure, wherever the element sits. Each row was measured through
// asn1js fromBER (Node 26, asn1js 3.0.10).
func TestK05OcspOuterParse(t *testing.T) {
	f := g02newFx(t)
	verify := func(der []byte) ocspResult {
		return verifyNvidiaOcspResponse(der, f.leafA, f.interA, f.chain, f.nowMs)
	}
	notDER, basicNotDER := ocspFail("response is not valid DER"), ocspFail("BasicOCSPResponse is not valid DER")
	null := derTLV(5)
	nulls := func(n int) []byte { return bytes.Repeat(null, n) }
	cases := []struct {
		name  string
		el    []byte
		threw string // "" with refused is `not valid DER`
		ref   bool   // refused
	}{
		{"BIT STRING unused 8", derTLV(3, []byte{8, 1}), "", true},
		{"BIT STRING unused 7", derTLV(3, []byte{7, 1}), "", false},
		{"empty BIT STRING", derTLV(3), "", false},
		{"constructed UTCTime", derTLV(0x37, derTLV(0x17, []byte("260531000000Z"))), "", true},
		{"constructed GeneralizedTime", derTLV(0x38, derTLV(0x18, []byte("20260531000000Z"))), "", true},
		{"constructed BOOLEAN", derTLV(0x21, []byte{1, 1, 0}), "", true},
		{"constructed INTEGER", derTLV(0x22, []byte{2, 1, 0}), "", true},
		{"tag 15", derTLV(0x0f), "", true},
		{"tag 37, high form", []byte{0x1f, 37, 0}, "", true},
		{"constructed tag 0 with content", derTLV(0x20, null), "", true},
		{"constructed OCTET STRING holding an INTEGER", derTLV(0x24, derTLV(2, []byte{1})), "", true},
		{"constructed BIT STRING holding an INTEGER", derTLV(0x23, derTLV(2, []byte{1})), "", true},
		{"constructed BIT STRING, two with unused bits", derTLV(0x23, []byte{3, 2, 1, 0, 3, 2, 1, 0}), "", true},
		{"constructed BIT STRING, first with unused bits", derTLV(0x23, []byte{3, 2, 1, 0, 3, 2, 0, 0}), "", false},
		{"constructed BIT STRING, last with unused bits", derTLV(0x23, []byte{3, 2, 0, 0, 3, 2, 1, 0}), "", false},
		{"OID ending inside an arc", derTLV(6, []byte{0x81}), "", true},
		{"empty OID", derTLV(6), "", false},
		{"GeneralizedTime text that throws", derTLV(0x18, []byte("abc")), "Wrong input string for conversion", true},
		{"odd BMPString", derTLV(30, []byte{1}), "Offset is outside the bounds of the DataView", true},
		{"UniversalString length 1", derTLV(28, []byte{1}), "byte length of Uint32Array should be a multiple of 4", true},
		{"UTCTime garbage only records an error", derTLV(0x17, []byte("abc")), "", false},
		{"UTF8String with a bad byte", derTLV(12, []byte{0xff}), "", false},
		{"non-empty NULL", derTLV(5, []byte{1}), "", false},
	}
	for _, c := range cases {
		top, basic := verify(k05DeepTLV(0x30, c.el)), verify(g02wrapBasic(k05DeepTLV(0x30, c.el)))
		switch {
		case c.threw != "":
			if want := g02rej(c.threw); top != want || basic != want {
				t.Errorf("%s: %+v / %+v, want %+v", c.name, top, basic, want)
			}
		case c.ref:
			if top != notDER || basic != basicNotDER {
				t.Errorf("%s: %+v / %+v", c.name, top, basic)
			}
		default:
			if top == notDER || basic == basicNotDER {
				t.Errorf("%s: refused as a parse failure: %+v / %+v", c.name, top, basic)
			}
		}
	}
	// a throw inside a primitive string is caught there, and a failed parse leaves it opaque
	if got := verify(k05DeepTLV(0x30, derTLV(4, derTLV(0x18, []byte("abc"))))); got == notDER || got == g02rej("Wrong input string for conversion") {
		t.Errorf("throw inside a string: %+v", got)
	}
	// node limit: the top element counts, so 10000 elements in all pass and 10001 do not
	if got := verify(k05DeepTLV(0x30, nulls(9999))); got == notDER {
		t.Errorf("10000 nodes: %+v", got)
	}
	if got := verify(k05DeepTLV(0x30, nulls(10000))); got != notDER {
		t.Errorf("10001 nodes: %+v", got)
	}
	if got := verify(g02wrapBasic(k05DeepTLV(0x30, nulls(10000)))); got != basicNotDER {
		t.Errorf("10001 nodes in the basic response: %+v", got)
	}
	// the limit inside a primitive string is caught there; only a later element outside it fails the parse
	over := derTLV(4, derTLV(0x30, null))
	if got := verify(k05DeepTLV(0x30, append(nulls(9998), over...))); got == notDER {
		t.Errorf("over the limit in the last string: %+v", got)
	}
	if got := verify(k05DeepTLV(0x30, append(append(nulls(9998), over...), null...))); got != notDER {
		t.Errorf("over the limit, then a sibling: %+v", got)
	}
	// content limit
	if got := verify(k05DeepTLV(4, make([]byte, ocspMaxContent))); got != g02rej("OCSPResponse is not a SEQUENCE") {
		t.Errorf("16 MiB: %+v", got)
	}
	if got := verify(k05DeepTLV(4, make([]byte, ocspMaxContent+1))); got != notDER {
		t.Errorf("16 MiB + 1: %+v", got)
	}
	if got := verify(k05DeepTLV(0x30, k05DeepTLV(4, make([]byte, ocspMaxContent+1)))); got != notDER {
		t.Errorf("16 MiB + 1 in a SEQUENCE: %+v", got)
	}
}
