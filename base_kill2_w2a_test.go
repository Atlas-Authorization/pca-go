package pca

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

// parseSnpReport reads committed_tcb at 0x1e0 and the 72-byte little-endian s at 0x2e8 (offsets written as literals so a
// changed constant is caught): a nonzero byte 71 of s must stay part of s, where it makes the signature fail.
func TestW2aSnpReportOffsets(t *testing.T) {
	b := make([]byte, 0x4a0)
	for i := range b {
		b[i] = byte(i*131 + 7)
	}
	r, err := parseSnpReport(b)
	if err != nil {
		t.Fatal(err)
	}
	if want := binary.LittleEndian.Uint64(b[0x1e0:]); r.committedTcb != want {
		t.Errorf("committedTcb = %#x, want %#x", r.committedTcb, want)
	}
	if !bytes.Equal(r.sigS, b[0x2e8:0x2e8+72]) {
		t.Errorf("sigS = %x, want %x", r.sigS, b[0x2e8:0x2e8+72])
	}
}

// A malformed denyVbiosVersions entry refuses the policy (not a nil version in the deny list).
func TestW2aFirmwarePolicyRefusesMalformedVbiosDeny(t *testing.T) {
	p, err := compileFirmwarePolicy(map[string]any{"denyVbiosVersions": []any{"96.00", "zz"}})
	if want := "nvidiaCollateralHook: malformed denyVbiosVersions entry 'zz'"; p != nil || err == nil || err.Error() != want {
		t.Errorf("p=%v err=%v", p, err)
	}
}

// An empty rimRootSpkiSha256 list pins nothing and is refused like an absent one.
func TestW2aNvidiaHookEmptyRimPins(t *testing.T) {
	for _, pins := range []any{[]any{}, nil, []any{"aa", 1}} {
		h, err := newNvidiaHook(map[string]any{"rimRootSpkiSha256": pins})
		if want := "nvidiaCollateralHook: rimRootSpkiSha256 must pin at least one root"; h != nil || err == nil || err.Error() != want {
			t.Errorf("%v: h=%v err=%v", pins, h, err)
		}
	}
	if h, err := newNvidiaHook(map[string]any{"rimRootSpkiSha256": []any{strings.Repeat("a", 64)}}); err != nil || h == nil {
		t.Errorf("one pin: h=%v err=%v", h, err)
	}
}

// A clause with an unknown kind or value makes the certificate inconsistent, even when the rest of it would follow.
func TestW2aForbidCertificateClauseKindAndValue(t *testing.T) {
	rows := []struct {
		name string
		cert any
		want bool
	}{
		{"unknown kind", g02cert("deny", "none", nil, []any{}, g02clause("a", "bogus", "true", "")), false},
		{"unknown value", g02cert("allow", "permit", "a", []any{}, g02clause("a", "permit", "maybe", "")), false},
		{"valid permit", g02cert("allow", "permit", "a", []any{}, g02clause("a", "permit", "unknown", "")), true},
	}
	for _, r := range rows {
		if got := ForbidCertificateConsistent(r.cert, nil); got != r.want {
			t.Errorf("%s: consistent = %v, want %v", r.name, got, r.want)
		}
	}
}
