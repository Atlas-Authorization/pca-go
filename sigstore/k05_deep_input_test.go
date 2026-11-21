package pcasigstore

import (
	"strings"
	"testing"
)

// Deep nesting: a Go stack overflow is fatal and recover (catch) cannot stop it, so a missing bound fails this file by killing the
// test binary. Bundle and root JSON go through encoding/json (10000 levels); the DER helpers read children, they never descend.
func TestK05DeepSigstoreJSON(t *testing.T) {
	for _, in := range []string{
		strings.Repeat("[", 100000),
		strings.Repeat("[", 100000) + strings.Repeat("]", 100000),
		strings.Repeat("[", 8<<20),
		strings.Repeat(`{"a":`, 1<<20),
	} {
		if _, ok := decodeOneJSON([]byte(in)); ok {
			t.Fatalf("decodeOneJSON accepted %d bytes", len(in))
		}
		if _, err := ParseTrustedRoot([]byte(in)); err == nil {
			t.Fatalf("ParseTrustedRoot accepted %d bytes", len(in))
		}
		if r := VerifySigstoreBundleCore([]byte(in), &PinnedRoots{}); r.OK || r.Code != "malformed" {
			t.Fatalf("bundle core(%d bytes): %+v", len(in), r)
		}
		if r := VerifySigstoreBundle([]byte(in), &PinnedRoots{}); r.Code != "malformed" {
			t.Fatalf("bundle(%d bytes): %+v", len(in), r)
		}
	}
	// jsVal, the one recursive walk over decoded JSON, at the deepest value the decoder lets through
	v, ok := decodeOneJSON([]byte(strings.Repeat("[", 10000) + strings.Repeat("]", 10000)))
	if !ok {
		t.Fatal("10000 levels did not decode")
	}
	if got := jsVal(v); got != "" {
		t.Fatalf("jsVal = %q", got)
	}
}

func TestK05DeepSigstoreDER(t *testing.T) {
	const levels = 1 << 20
	b := make([]byte, levels*6)
	p := len(b)
	for i := 0; i < levels; i++ {
		n := len(b) - p
		if n < 0x80 {
			p--
			b[p] = byte(n)
		} else {
			k := 0
			for m := n; m > 0; m >>= 8 {
				p--
				b[p] = byte(m)
				k++
			}
			p--
			b[p] = 0x80 | byte(k)
		}
		p--
		b[p] = 0x30
	}
	deep := b[p:]
	if _, err := parsedOrNil(deep); err == nil {
		t.Fatal("parseCert accepted nested SEQUENCEs")
	}
	if len(kids(deep, tlv(deep, 0, len(deep)))) != 1 {
		t.Fatal("kids must read one level")
	}
	if catch(func() { fullCert(deep) }) == nil {
		t.Fatal("fullCert accepted nested SEQUENCEs")
	}
	_ = catch(func() { hasEKU(deep, "1.2.3") })
	_ = catch(func() { sanDecodes(deep) })
}
