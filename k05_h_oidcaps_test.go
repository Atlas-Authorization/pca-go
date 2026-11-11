package pca

import (
	"bytes"
	"testing"
	"time"
)

// H2: OID content and arc caps, checked before any big-integer work.

func h2Dotted(content []byte) (string, error) {
	b := append([]byte{0x06, 0x00}, content...) // the length byte is not read by oidToDotted: it takes the element bounds
	return oidToDotted(b, derTlv{tag: 0x06, start: 2, end: len(b)})
}

func TestH2_OidToDottedCaps(t *testing.T) {
	// 1: ordinary OIDs decode
	if got, err := h2Dotted([]byte{0x55, 0x1d, 0x13}); err != nil || got != "2.5.29.19" {
		t.Errorf("2.5.29.19: %q %v", got, err)
	}
	// 4: 2.25.<UUID>: a 128-bit arc is 19 groups
	uuid := append([]byte{0x69}, append(bytes.Repeat([]byte{0xff}, 18), 0x7f)...)
	if got, err := h2Dotted(uuid); err != nil || len(got) < 10 || got[:5] != "2.25." {
		t.Errorf("2.25.<uuid>: %q %v", got, err)
	}
	// 2: 300 bytes of content: too long, even when it would be a valid arc
	long := append(bytes.Repeat([]byte{0x81}, 299), 0x01)
	if _, err := h2Dotted(long); err == nil || err.Error() != "extension OID is too long" {
		t.Errorf("300 bytes: %v", err)
	}
	// the content limit is 256 bytes: 256 passes the length check, 257 does not
	ok256 := append([]byte{0x2b}, bytes.Repeat([]byte{0x01}, 255)...) // 1.3 then 255 one-byte arcs
	if _, err := h2Dotted(ok256); err != nil {
		t.Errorf("256 bytes: %v", err)
	}
	if _, err := h2Dotted(append(ok256, 0x01)); err == nil || err.Error() != "extension OID is too long" {
		t.Errorf("257 bytes: %v", err)
	}
	// 3: an arc of 65 groups is oversized, 64 is not
	arc := func(n int) []byte { return append(append([]byte{0x2b}, bytes.Repeat([]byte{0x81}, n-1)...), 0x01) }
	if _, err := h2Dotted(arc(65)); err == nil || err.Error() != "extension OID has an oversized arc" {
		t.Errorf("65 groups: %v", err)
	}
	if _, err := h2Dotted(arc(64)); err != nil {
		t.Errorf("64 groups: %v", err)
	}
	// the group counter restarts for every arc
	two := append(append([]byte{0x2b}, arc(64)[1:]...), arc(64)[1:]...)
	if _, err := h2Dotted(two); err != nil {
		t.Errorf("two 64-group arcs: %v", err)
	}
	// the existing refusals keep their text
	if _, err := h2Dotted([]byte{0x2b, 0x80, 0x01}); err == nil || err.Error() != "extension OID has a non-minimal arc" {
		t.Errorf("non-minimal: %v", err)
	}
	if _, err := h2Dotted([]byte{0x2b, 0x81}); err == nil || err.Error() != "extension OID is truncated" {
		t.Errorf("truncated: %v", err)
	}
	// 5: a 100 KB single-arc OID is refused quickly, not after quadratic big-integer work
	start := time.Now()
	if _, err := h2Dotted(append(bytes.Repeat([]byte{0x81}, 100_000), 0x01)); err == nil {
		t.Error("100 KB OID accepted")
	}
	if d := time.Since(start); d > 50*time.Millisecond {
		t.Errorf("100 KB OID took %v", d)
	}
}
