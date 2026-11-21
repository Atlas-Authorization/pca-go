package pca

import (
	"encoding/json"
	"math"
	"testing"
)

// AuthorityDigest of anything that is not a well-formed authority is ("", false): the digest string is empty.
func TestR6N4_AuthorityDigestRefusalIsEmpty(t *testing.T) {
	if d, ok := AuthorityDigest("x"); ok || d != "" {
		t.Fatalf("non-object: %q %v", d, ok)
	}
	if d, ok := AuthorityDigest(map[string]any{"resources": []any{"r"}}); ok || d != "" {
		t.Fatalf("no verbs: %q %v", d, ok)
	}
}

// pca-grants grant-resource.ts:158: Math.max(v, d.limits?.[k] ?? v): a delta that omits the limit keeps the kept value
// exactly, including negative zero (a delta default of 0 would turn -0 into +0).
func TestR6N4_MergeKeepsLimitTheDeltaOmits(t *testing.T) {
	a, ok := parseAuthority(map[string]any{"verbs": []any{"a"}, "resources": []any{"r"}, "limits": map[string]any{"x": json.Number("-0")}})
	if !ok {
		t.Fatal("parse a")
	}
	d, ok := parseAuthority(map[string]any{"verbs": []any{"b"}, "resources": []any{"s"}})
	if !ok {
		t.Fatal("parse d")
	}
	lim, _ := k3Merge(a, d)["limits"].(map[string]any)
	if lim["x"] != jsNumber(math.Copysign(0, -1)) {
		t.Fatalf("limit changed by an omitting delta: %v", lim["x"])
	}
}

// capability.ts:513 caveatLimitExceeded: a non-object hop counts zero and the scan goes on to the later hops.
func TestR6N4_CaveatLimitScansPastNonObjectHop(t *testing.T) {
	hop := func(n int) any {
		cv := make([]any, n)
		for i := range cv {
			cv[i] = map[string]any{"type": "note"}
		}
		return map[string]any{"caveats": cv}
	}
	if !caveatLimitExceeded([]any{"x", hop(257)}) {
		t.Fatal("257 caveats after a non-object hop must trip the per-hop cap")
	}
	if !caveatLimitExceeded([]any{nil, hop(205), hop(205), hop(205), hop(205), hop(205)}) {
		t.Fatal("1025 caveats after a non-object hop must trip the per-chain cap")
	}
}

// attest-nvidia-spdm.ts:317 String(d): null prints "null", an array joins with commas.
func TestR6N4_JsAnyStringIsEcmaString(t *testing.T) {
	if got := jsAnyString(nil); got != "null" {
		t.Fatalf("nil: %q", got)
	}
	if got := jsAnyString([]any{json.Number("1"), "a"}); got != "1,a" {
		t.Fatalf("array: %q", got)
	}
}
