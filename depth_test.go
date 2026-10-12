package pca

import (
	"strings"
	"testing"
)

// Depth: the strict profile caps nesting at MaxJSONDepth (32, same counting as the reference); every entry point is a
// clean refusal on deeper input. The lenient fixture loader has a large safety cap so hostile depth is an error, never a
// fatal goroutine stack overflow (which recover() cannot catch).
func TestStrictDepthBoundaries(t *testing.T) {
	for _, c := range []struct {
		n  int
		ok bool
	}{{MaxJSONDepth - 1, true}, {MaxJSONDepth, true}, {MaxJSONDepth + 1, false}, {100000, false}} {
		_, err := StrictParse(strings.Repeat("[", c.n) + strings.Repeat("]", c.n))
		if (err == nil) != c.ok {
			t.Fatalf("depth %d: err=%v", c.n, err)
		}
		obj := strings.Repeat(`{"a":`, c.n) + "1" + strings.Repeat("}", c.n)
		if _, err := StrictParse(obj); (err == nil) != c.ok {
			t.Fatalf("object depth %d: err=%v", c.n, err)
		}
	}
}

func TestLenientDepthSafetyCap(t *testing.T) {
	if _, err := ParseJSONLenient([]byte(strings.Repeat("[", 100000) + strings.Repeat("]", 100000))); err != nil {
		t.Fatalf("100000-deep fixture must still load: %v", err)
	}
	n := MaxLenientDepth + 1
	if _, err := ParseJSONLenient([]byte(strings.Repeat("[", n) + strings.Repeat("]", n))); err == nil {
		t.Fatal("lenient depth above the safety cap accepted")
	}
	// 8M unbalanced '[': without the cap this recursed until the runtime aborted the process
	if _, err := ParseJSONLenient([]byte(strings.Repeat("[", 8<<20))); err == nil {
		t.Fatal("8M-deep input accepted")
	}
}

func TestCanonicalizeDepthBoundaries(t *testing.T) {
	nest := func(k int) any {
		var v any = json1()
		for i := 0; i < k; i++ {
			v = []any{v}
		}
		return v
	}
	for _, c := range []struct {
		k  int
		ok bool
	}{{MaxJSONDepth - 1, true}, {MaxJSONDepth, true}, {MaxJSONDepth + 1, false}, {100000, false}} {
		if _, err := Canonicalize(nest(c.k)); (err == nil) != c.ok {
			t.Fatalf("canonicalize depth %d: err=%v", c.k, err)
		}
	}
	deep := nest(100000)
	if _, ok := VerifyChain([]any{deep}, "", false); ok {
		t.Fatal("deep chain accepted")
	}
	if VerifyThresholdShare(map[string]any{"role": "agent", "t": 1, "signer_set": []any{deep}, "threshold_message": "AA", "share": deep}) {
		t.Fatal("deep share accepted")
	}
	if r := ValidateWireV2(map[string]any{"ver": deep}); r == "" {
		t.Fatal("deep wire accepted")
	}
}

func json1() any { v, _ := StrictParse("1"); return v }
