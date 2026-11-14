package pca

import (
	"bytes"
	"math/rand"
	"testing"
)

// r and s are each a 72-byte little-endian field: r's top byte counts (non-zero puts r >= n), the byte after s does not.
func TestW1cSnpSignatureFieldWidths(t *testing.T) {
	key := g13amdP384(t)
	raw := g13amdReport(t, key, bytes.Repeat([]byte{0x3c}, 48))
	rep, err := parseSnpReport(raw)
	if err != nil || len(rep.sigR) != 72 || len(rep.sigS) != 72 {
		t.Fatalf("sig field widths: err=%v", err)
	}
	if !verifySnpReportSignature(rep, &key.PublicKey) {
		t.Fatal("genuine signature refused")
	}
	rTop := append([]byte{}, raw...)
	rTop[snpOffSigR+71] = 1
	if rep, err := parseSnpReport(rTop); err != nil || verifySnpReportSignature(rep, &key.PublicKey) {
		t.Fatalf("r with a non-zero 72nd byte accepted (err=%v)", err)
	}
	afterS := append([]byte{}, raw...)
	afterS[snpOffSigS+72] = 1
	if rep, err := parseSnpReport(afterS); err != nil || !verifySnpReportSignature(rep, &key.PublicKey) {
		t.Fatalf("the byte after s changed the signature (err=%v)", err)
	}
}

// algID drops oidToDotted's error because validOID refuses every OID content oidToDotted refuses: checked exhaustively
// for 1-2 content bytes and on a seeded sample of 3-8 bytes biased to the continuation edge values.
func TestW1cValidOIDImpliesDotted(t *testing.T) {
	check := func(c []byte) {
		b := append([]byte{0x06, byte(len(c))}, c...)
		if validOID(b, certElem{tag: 0x06, start: 2, end: len(b)}) {
			if _, err := oidToDotted(b, derTlv{tag: 0x06, start: 2, end: len(b)}); err != nil {
				t.Fatalf("validOID accepted % x but oidToDotted refused: %v", c, err)
			}
		}
	}
	for x := 0; x < 256; x++ {
		check([]byte{byte(x)})
		for y := 0; y < 256; y++ {
			check([]byte{byte(x), byte(y)})
		}
	}
	edge := []byte{0x00, 0x01, 0x7f, 0x80, 0x81, 0xff}
	rng := rand.New(rand.NewSource(5))
	for i := 0; i < 200000; i++ {
		c := make([]byte, 3+rng.Intn(6))
		for j := range c {
			if rng.Intn(2) == 0 {
				c[j] = edge[rng.Intn(len(edge))]
			} else {
				c[j] = byte(rng.Intn(256))
			}
		}
		check(c)
	}
}

func TestW1cFirmwarePolicyRefusesMalformedVersions(t *testing.T) {
	for _, c := range []struct {
		fw   map[string]any
		want string
	}{
		{map[string]any{"minVbiosVersion": "q"}, "nvidiaCollateralHook: malformed minVbiosVersion 'q'"},
		{map[string]any{"denyDriverVersions": []any{"535.86", "x"}}, "nvidiaCollateralHook: malformed denyDriverVersions entry 'x'"},
	} {
		if p, err := compileFirmwarePolicy(c.fw); p != nil || err == nil || err.Error() != c.want {
			t.Errorf("%v: p=%v err=%v", c.fw, p, err)
		}
	}
}
