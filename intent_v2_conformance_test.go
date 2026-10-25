package pca

import (
	"strings"
	"testing"
)

// The Intent Layer v2 primitives of the shared corpus (conformance README rules 13-18): intent_schema (rule 14
// alone), intent_revocation (rule 13 step 7 alone), intent_world (16), intent_provenance (17), intent_classifier
// (18). A family the corpus does not carry yet (W-A primitives are written by the freeze job) is skipped, never
// silently passed: the test logs it.

func v2Primitives(t *testing.T, name string) []any {
	t.Helper()
	prim := load(t, "vectors.json")["primitives"].(map[string]any)
	xs, ok := prim[name].([]any)
	if !ok {
		t.Logf("primitives.%s not in the corpus yet (generated at freeze): skipped", name)
		return nil
	}
	return xs
}

// sameJSON compares two JSON values by value (numbers by binary64, objects as key sets).
func sameJSON(a, b any) bool {
	x, ok1 := canonicalLenient(normalizeJSON(a))
	y, ok2 := canonicalLenient(normalizeJSON(b))
	return ok1 && ok2 && x == y
}

// noReason adapts a primitive without a refusal reason.
func noReason(f func(any) map[string]any) func(any) (map[string]any, string) {
	return func(in any) (map[string]any, string) { return f(in), "" }
}

func runV2Primitive(t *testing.T, family string, fields func(exp map[string]any) []string, run func(input any) (map[string]any, string)) {
	xs := v2Primitives(t, family)
	for _, x := range xs {
		v := x.(map[string]any)
		rs, needs := v["requires_suite"].(string)
		mustRefuse := needs && !suiteSupported(rs, true)
		t.Run(v["name"].(string), func(t *testing.T) {
			exp := v["expect"].(map[string]any)
			// README "Raw JSON text members": `input_json` (raw text, keeps values plain JSON erases such as -0) is parsed
			// with the SDK's own parser and used INSTEAD of `input`.
			input := v["input"]
			if raw, ok := v["input_json"].(string); ok {
				parsed, err := ParseJSONLenient([]byte(raw))
				if err != nil {
					t.Fatalf("input_json: %v", err)
				}
				input = parsed
			}
			got, reason := run(input)
			if rc, ok := exp["reason_contains"].(string); ok && !strings.Contains(reason, rc) {
				t.Errorf("reason %q does not contain %q", reason, rc)
			}
			if mustRefuse {
				if !strings.Contains(reason, UnsupportedSuite) && family != "intent_schema" && family != "intent_revocation" {
					t.Errorf("requires_suite %q: reason %q lacks %s", rs, reason, UnsupportedSuite)
				}
				// README "suite capability": an unimplemented required suite fails closed (the primitive refuses)
				for _, k := range []string{"ok", "sig"} {
					if b, has := got[k]; has && b == true {
						t.Errorf("requires_suite %q: %s accepted", rs, k)
					}
				}
				return
			}
			for _, k := range fields(exp) {
				if !sameJSON(got[k], exp[k]) {
					t.Errorf("%s = %v, want %v", k, got[k], exp[k])
				}
			}
		})
	}
	if len(xs) > 0 {
		t.Logf("primitives.%s: %d entries", family, len(xs))
	}
}

func TestIntentWorldPrimitives(t *testing.T) {
	runV2Primitive(t, "intent_world", func(exp map[string]any) []string {
		if exp["ok"] == true {
			return []string{"ok", "world", "single_source"}
		}
		return []string{"ok"}
	}, IntentWorldPrimitive)
}

func TestIntentProvenancePrimitives(t *testing.T) {
	runV2Primitive(t, "intent_provenance", func(exp map[string]any) []string {
		switch exp["outcome"] {
		case "deny":
			return []string{"outcome"}
		case "question":
			return []string{"outcome", "labels", "classes", "friction"}
		}
		return []string{"outcome", "labels", "classes"}
	}, IntentProvenancePrimitive)
}

func TestIntentClassifierPrimitives(t *testing.T) {
	runV2Primitive(t, "intent_classifier", func(exp map[string]any) []string {
		if exp["ok"] == true {
			return []string{"ok", "classes"}
		}
		return []string{"ok"}
	}, IntentClassifierPrimitive)
}

func TestIntentSchemaPrimitives(t *testing.T) {
	runV2Primitive(t, "intent_schema", func(exp map[string]any) []string {
		if exp["sig"] == true {
			return []string{"sig", "digest", "conform"}
		}
		return []string{"sig", "conform"}
	}, noReason(IntentSchemaPrimitive))
}

func TestIntentRevocationPrimitives(t *testing.T) {
	runV2Primitive(t, "intent_revocation", func(map[string]any) []string { return []string{"ok"} }, noReason(func(input any) map[string]any {
		return map[string]any{"ok": IntentRevocationPrimitive(input)}
	}))
}

func TestIntentWBActivePrimitives(t *testing.T) {
	runV2Primitive(t, "intent_wb_active", func(map[string]any) []string { return []string{"facts", "provenance", "classes"} }, noReason(IntentWBActivePrimitive))
}

func TestIntentReadPurposePrimitives(t *testing.T) {
	runV2Primitive(t, "intent_read_purpose", func(map[string]any) []string { return []string{"outcome", "minimise", "uncovered"} }, noReason(IntentReadPurposePrimitive))
}

func TestIntentMapCommitPrimitives(t *testing.T) {
	runV2Primitive(t, "intent_map_commit", func(map[string]any) []string { return []string{"map_commit"} }, noReason(IntentMapCommitPrimitive))
}

func TestIntentMapPrimitives(t *testing.T) {
	runV2Primitive(t, "intent_map", func(exp map[string]any) []string {
		if exp["ok"] == true {
			return []string{"ok", "cell", "p_ppm"}
		}
		return []string{"ok"}
	}, IntentMapPrimitive)
}
