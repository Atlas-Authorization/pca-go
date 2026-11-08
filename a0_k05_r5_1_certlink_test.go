package pca

import (
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

func r5n1hex(s string) []byte {
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		panic(err)
	}
	return b
}

func r5n1tlv(tag byte, parts ...[]byte) []byte {
	var c []byte
	for _, p := range parts {
		c = append(c, p...)
	}
	return append(derLengthHeader(tag, len(c)), c...)
}

// r5n1run decides a loop mutant by an ordinary assertion: a non-terminating or panicking body fails here within 2 seconds.
func r5n1run(f func() bool) (res bool, status string) {
	type out struct {
		res bool
		pan bool
	}
	ch := make(chan out, 1)
	go func() {
		defer func() {
			if recover() != nil {
				ch <- out{pan: true}
			}
		}()
		ch <- out{res: f()}
	}()
	select {
	case o := <-ch:
		if o.pan {
			return false, "panic"
		}
		return o.res, ""
	case <-time.After(2 * time.Second):
		return false, "timeout"
	}
}

func r5n1ext(oid string, v []byte) bool {
	got, st := r5n1run(func() bool { return certExtsDecode(&attCert{exts: []lenientExt{{oid: oid, value: v}}}) })
	if st != "" {
		return false
	}
	return got
}

func r5n1gn(der []byte) bool {
	got, _ := r5n1run(func() bool {
		e, err := readCertElem(der, 0, len(der), 0)
		if err != nil {
			return false
		}
		return generalNameDecodes(der, e)
	})
	return got
}

func TestR5N1_NameValueStrings(t *testing.T) {
	for _, r := range []struct {
		tag  byte
		hex  string
		want bool
	}{
		{0x1e, "0041 0042", true}, {0x1e, "00d8", true}, {0x1e, "d800", false}, {0x1e, "d900", false}, {0x1e, "dfff", false},
		{0x1e, "d7ff", true}, {0x1e, "e000", true}, {0x1e, "0041 d800", false}, {0x1e, "00", false}, {0x1e, "", true},
		{0x1c, "00000041", true}, {0x1c, "0010ffff", true}, {0x1c, "00100000", true}, {0x1c, "00110000", false},
		{0x1c, "01000000", false}, {0x1c, "80000000", false}, {0x1c, "0000d800", false}, {0x1c, "0000dfff", false},
		{0x1c, "0000d7ff", true}, {0x1c, "0000e000", true}, {0x1c, "00000041 00000042", true},
		{0x1c, "0010ffff 00000041", true}, {0x1c, "0010d800 00000041", true},
		{0x1c, "00000041 01000000 00000041", false}, {0x1c, "000000", false},
		{0x03, "00", true}, {0x03, "07 80", true}, {0x03, "08 80", false}, {0x03, "", false},
	} {
		b := r5n1tlv(r.tag, r5n1hex(r.hex))
		e := certElem{tag: r.tag, hdr: 0, start: len(b) - len(r5n1hex(r.hex)), end: len(b)}
		got, st := r5n1run(func() bool { return nameValueDecodes(b, e) })
		if st != "" || got != r.want {
			t.Errorf("tag %#x %q: got %v (%s), want %v", r.tag, r.hex, got, st, r.want)
		}
	}
}

func TestR5N1_GeneralNames(t *testing.T) {
	oid := r5n1hex("06032a0304")
	other := func(val []byte) []byte { return r5n1tlv(0xa0, oid, r5n1tlv(0xa0, val)) }
	for _, tag := range []byte{0x04, 0x0c, 0x13, 0x14, 0x16, 0x30} {
		if !r5n1gn(other([]byte{tag, 0})) {
			t.Errorf("otherName value tag %#x must decode", tag)
		}
	}
	for _, tag := range []byte{0x05, 0x0d, 0x15, 0x17, 0x31, 0x01} {
		if r5n1gn(other([]byte{tag, 0})) {
			t.Errorf("otherName value tag %#x must not decode", tag)
		}
	}
	s := func(tag byte) []byte { return r5n1tlv(tag, r5n1tlv(0x0c, []byte("x"))) }
	edi := func(parts ...[]byte) []byte { return r5n1tlv(0xa5, parts...) }
	a0, a1 := func() []byte { return s(0xa0) }, func() []byte { return s(0xa1) }
	for _, r := range []struct {
		name string
		der  []byte
		want bool
	}{
		{"party only", edi(a1()), true},
		{"assigner and party", edi(a0(), a1()), true},
		{"three kids", edi(a0(), a1(), a1()), false},
		{"two party kids", edi(a1(), a1()), false},
		{"assigner only", edi(a0()), false},
		{"empty", edi(), false},
		{"printable", edi(r5n1tlv(0xa1, r5n1tlv(0x13, []byte("x")))), true},
		{"teletex", edi(r5n1tlv(0xa1, r5n1tlv(0x14, []byte("x")))), true},
		{"0x15 not a directory string", edi(r5n1tlv(0xa1, r5n1tlv(0x15, []byte("x")))), false},
		{"universal", edi(r5n1tlv(0xa1, r5n1tlv(0x1c, r5n1hex("00000041")))), true},
		{"bmp", edi(r5n1tlv(0xa1, r5n1tlv(0x1e, r5n1hex("0041")))), true},
		{"bad bmp", edi(r5n1tlv(0xa1, r5n1tlv(0x1e, r5n1hex("d800")))), false},
		{"truncated child", r5n1hex("a5 03 a1 05 0c"), false},
		{"truncated registered-less tag", r5n1hex("a6 00"), false},
		{"truncated directory name", r5n1hex("a4 03 30 05 31"), false},
	} {
		if got := r5n1gn(r.der); got != r.want {
			t.Errorf("%s: %v, want %v", r.name, got, r.want)
		}
	}
}

func TestR5N1_ExtensionDecoders(t *testing.T) {
	dns := r5n1hex("82 01 61")
	high := r5n1hex("82 01 e9")
	dpName := func() []byte { return r5n1tlv(0xa0, r5n1tlv(0xa0, dns)) }
	for _, r := range []struct {
		name string
		oid  string
		v    []byte
		want bool
	}{
		// extKeyUsage
		{"eku ok", "2.5.29.37", r5n1tlv(0x30, r5n1hex("06032a0304")), true},
		{"eku truncated child", "2.5.29.37", r5n1hex("30 03 06 05 2a"), false},
		// subjectKeyIdentifier
		{"ski ok", "2.5.29.14", r5n1hex("04 01 aa"), true},
		{"ski trailing", "2.5.29.14", r5n1hex("04 01 aa ff"), false},
		{"ski empty", "2.5.29.14", nil, false},
		// authorityKeyIdentifier
		{"aki keyid", "2.5.29.35", r5n1tlv(0x30, r5n1hex("80 01 aa")), true},
		{"aki all", "2.5.29.35", r5n1tlv(0x30, r5n1tlv(0xa1, dns), r5n1hex("82 01 05")), true},
		{"aki trailing", "2.5.29.35", r5n1hex("30 00 ff"), false},
		{"aki empty", "2.5.29.35", nil, false},
		{"aki order", "2.5.29.35", r5n1tlv(0x30, r5n1hex("82 01 05 80 01 aa")), false},
		{"aki foreign tag", "2.5.29.35", r5n1tlv(0x30, r5n1hex("83 01 00")), false},
		{"aki padded serial", "2.5.29.35", r5n1tlv(0x30, r5n1hex("82 02 00 05")), false},
		{"aki truncated names", "2.5.29.35", r5n1tlv(0x30, r5n1hex("a1 03 82 05 61")), false},
		// nameConstraints
		{"nc ok", "2.5.29.30", r5n1tlv(0x30, r5n1tlv(0xa0, r5n1tlv(0x30, high))), true},
		{"nc bounds", "2.5.29.30", r5n1tlv(0x30, r5n1tlv(0xa0, r5n1tlv(0x30, dns, r5n1hex("80 01 00 81 01 02")))), true},
		{"nc negative bound", "2.5.29.30", r5n1tlv(0x30, r5n1tlv(0xa0, r5n1tlv(0x30, dns, r5n1hex("80 01 ff")))), false},
		{"nc subtree not a sequence", "2.5.29.30", r5n1tlv(0x30, r5n1tlv(0xa0, r5n1tlv(0x31, dns))), false},
		{"nc truncated list", "2.5.29.30", r5n1tlv(0x30, r5n1hex("a0 03 30 05 61")), false},
		// cRLDistributionPoints
		{"dp ok", "2.5.29.31", r5n1tlv(0x30, r5n1tlv(0x30, dpName())), true},
		{"dp wrong tag", "2.5.29.31", r5n1tlv(0x30, r5n1tlv(0x31, dpName())), false},
		{"dp reasons 7", "2.5.29.31", r5n1tlv(0x30, r5n1tlv(0x30, dpName(), r5n1hex("81 02 07 80"))), true},
		{"dp reasons 8", "2.5.29.31", r5n1tlv(0x30, r5n1tlv(0x30, dpName(), r5n1hex("81 02 08 80"))), false},
		{"dp reasons empty", "2.5.29.31", r5n1tlv(0x30, r5n1tlv(0x30, dpName(), r5n1hex("81 00"))), false},
		{"dp truncated list", "2.5.29.31", r5n1hex("30 03 30 05 a0"), false},
		// keyUsage
		{"ku ok", "2.5.29.15", r5n1hex("03 02 00 80"), true},
		{"ku 8 unused bits", "2.5.29.15", r5n1hex("03 03 08 ff ff"), false},
		{"ku nothing asserted", "2.5.29.15", r5n1hex("03 02 07 00"), false},
		{"ku short", "2.5.29.15", r5n1hex("03 01 00"), false},
	} {
		if got := r5n1ext(r.oid, r.v); got != r.want {
			t.Errorf("%s: %v, want %v", r.name, got, r.want)
		}
	}
	// An uncached extension is skipped, not the end of the table.
	c := &attCert{exts: []lenientExt{{oid: "1.2.3.4", value: []byte{1}}, {oid: "2.5.29.37", value: r5n1hex("30 03 06 05 2a")}}}
	if certExtsDecode(c) {
		t.Error("an extension after an uncached one must still be read")
	}
	c = &attCert{exts: []lenientExt{{oid: "2.5.29.14", value: r5n1hex("04 01 aa")}, {oid: "2.5.29.14", value: r5n1hex("04 01 aa")}}}
	if certExtsDecode(c) {
		t.Error("a repeated cached extension must be refused")
	}
}

func TestR5N1_CertMayIssue(t *testing.T) {
	ku := func(h string) *attCert {
		return &attCert{exts: []lenientExt{{oid: "2.5.29.15", value: r5n1hex(h)}}}
	}
	for _, r := range []struct {
		name string
		c    *attCert
		want bool
	}{
		{"no keyUsage", &attCert{}, true},
		{"keyCertSign", ku("03 02 01 04"), true},
		{"keyCertSign beside others", ku("03 02 00 84"), true},
		{"low bit only", ku("03 02 00 01"), false},
		{"digitalSignature only", ku("03 02 00 80"), false},
		{"undecodable", ku("03 01 00"), false},
		{"unused bits cleared", ku("03 02 02 07"), true},
	} {
		if got := certMayIssue(r.c); got != r.want {
			t.Errorf("%s: %v, want %v", r.name, got, r.want)
		}
	}
}
