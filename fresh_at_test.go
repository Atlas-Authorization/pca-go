package pca

import (
	"strings"
	"testing"
)

// Replays packages/pca/conformance/fresh-at-vectors.json: the `fresh_at` PCActn member, its policy and its place in the check order.
func TestFreshAtMemberVectors(t *testing.T) {
	doc := load(t, "fresh-at-vectors.json")
	if num(doc["format"]) != 1 {
		t.Fatal("not a format-1 fresh_at vector file")
	}
	vs := doc["vectors"].([]any)
	if len(vs) == 0 {
		t.Fatal("no vectors")
	}
	for _, x := range vs {
		v := x.(map[string]any)
		t.Run(v["name"].(string), func(t *testing.T) {
			ctx := v["context"].(map[string]any)
			opts := VerifyOptions{FreshAt: FreshAtPolicyFromJSON(ctx["fresh_at"])}
			got, err := VerifyPCActnCoreWith(v["pcactn"].(map[string]any), v["grant"].(map[string]any), num(ctx["now"]), ctx["aud"].(string), opts)
			if err != nil {
				t.Fatal(err)
			}
			exp := v["expect"].(map[string]any)
			if got.Allow != exp["allow"].(bool) {
				t.Errorf("allow = %v, want %v (%s)", got.Allow, exp["allow"], got.Reason)
			}
			want := exp["checks"].(map[string]any)
			_, hasFA := got.Checks["fresh_at"]
			if n := len(want); hasFA && len(got.Checks) != n+1 || !hasFA && len(got.Checks) != n {
				t.Errorf("checks %v, want %v plus fresh_at", got.Checks, want)
			}
			for k, w := range want {
				if g, has := got.Checks[k]; !has || g != w.(bool) {
					t.Errorf("check %s = %v, want %v (%s)", k, g, w, got.Reason)
				}
			}
			status := "absent"
			if g, has := got.Checks["fresh_at"]; has {
				status = map[bool]string{true: "pass", false: "fail"}[g]
			}
			if status != exp["fresh_at"] {
				t.Errorf("fresh_at = %s, want %v", status, exp["fresh_at"])
			}
			checks := map[string]any{}
			for k, ok := range got.Checks {
				checks[k] = map[bool]string{true: "pass", false: "fail"}[ok]
			}
			reasons := []any{}
			for _, r := range got.Reasons {
				reasons = append(reasons, r)
			}
			if len(reasons) == 0 && got.Reason != "" {
				reasons = append(reasons, got.Reason)
			}
			if d := DecisionOf(map[string]any{"allow": got.Allow, "checks": checks, "reasons": reasons}); d != exp["decision"] {
				t.Errorf("decision = %s, want %v (%s)", d, exp["decision"], got.Reason)
			}
			// fresh_at and wire reasons are compared exactly; for another check's reason only the check name (its text is that check's own).
			if w, has := exp["reason"].(string); has {
				if strings.HasPrefix(w, "fresh_at:") || strings.HasPrefix(w, "wire:") {
					if got.Reason != w {
						t.Errorf("reason %q, want %q", got.Reason, w)
					}
				} else if name := w[:strings.Index(w, ":")+1]; !strings.HasPrefix(got.Reason, name) {
					t.Errorf("reason %q, want a %s reason", got.Reason, name)
				}
			} else if got.Reason != "" {
				t.Errorf("unexpected reason %q", got.Reason)
			}
		})
	}
}
