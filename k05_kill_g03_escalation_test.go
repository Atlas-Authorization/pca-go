package pca

// g03: escalation request construction (TTL default and boundaries, digests that cannot be built), UTF-16 truncation at the
// first astral code point, the non-negative reader and the verifier-clock bounds.

import (
	"encoding/json"
	"testing"
)

func TestG03TruncUTF16AstralBoundary(t *testing.T) {
	if got := truncUTF16("\U00010000", 1); got != loneOpen+"d800"+loneClose {
		t.Errorf("U+10000 cut after one unit: %q", got)
	}
	if got := truncUTF16("a\U00010000", 2); got != "a"+loneOpen+"d800"+loneClose {
		t.Errorf("a U+10000 cut after two units: %q", got)
	}
	if got := truncUTF16("\U00010000", 2); got != "\U00010000" {
		t.Errorf("U+10000 kept whole: %q", got)
	}
	if got := truncUTF16("\U00010400", 1); got != loneOpen+"d801"+loneClose {
		t.Errorf("U+10400 cut after one unit: %q", got)
	}
}

func TestG03BuildEscalationRequestTTL(t *testing.T) {
	grant := map[string]any{"g": "x"}
	pcactn := map[string]any{"action": map[string]any{"verb": "read", "resource": "/r"}}
	for _, c := range []struct {
		ttl  int64
		want string
	}{{0, "3601000"}, {-5, "3601000"}, {1, "1001"}, {2, "1002"}} {
		req, err := BuildEscalationRequest("aud", grant, pcactn, nil, nil, 1000, c.ttl)
		if err != nil {
			t.Fatal(err)
		}
		if req["expires_at"] != json.Number(c.want) || req["v"] != json.Number("1") || req["verb"] != "read" || req["resource"] != "/r" {
			t.Errorf("ttl %d: %v", c.ttl, req)
		}
	}
	big := int64(1) << 60
	for _, c := range []struct {
		name          string
		grant, pcactn map[string]any
		last          *int64
	}{
		{"grant not canonical", map[string]any{"x": 1.5}, pcactn, nil},
		{"pcactn not canonical", grant, map[string]any{"x": 1.5}, nil},
		{"last counter beyond the safe range", grant, pcactn, &big},
	} {
		req, err := BuildEscalationRequest("aud", c.grant, c.pcactn, c.last, nil, 1000, 0)
		if err == nil || req != nil {
			t.Errorf("%s: %v %v", c.name, req, err)
			continue
		}
		want := "canonicalize: unsupported type float64"
		if c.last != nil {
			want = "canonicalize: integer outside the safe range"
		}
		if err.Error() != want {
			t.Errorf("%s: %q, want %q", c.name, err.Error(), want)
		}
	}
}

func TestG03NonNegSafeZero(t *testing.T) {
	if i, ok := nonNegSafe(json.Number("0")); !ok || i != 0 {
		t.Errorf("0: %d %v", i, ok)
	}
	if i, ok := nonNegSafe(json.Number("-1")); ok || i != -1 {
		t.Errorf("-1: %d %v", i, ok)
	}
}

func TestG03EscalationVerifierClockBounds(t *testing.T) {
	const malformed = "malformed escalation answer: not an object"
	const clock = "the verifier clock is not a safe integer (fail closed)"
	for _, c := range []struct {
		now  int64
		want string
	}{{maxSafeInt, malformed}, {-maxSafeInt, malformed}, {maxSafeInt + 1, clock}, {-maxSafeInt - 1, clock}} {
		if r := VerifyEscalationAnswer(nil, nil, EscalationBinding{}, c.now); r.OK || r.Reason != c.want {
			t.Errorf("now %d: %+v, want %q", c.now, r, c.want)
		}
	}
}
