package pca

import "testing"

// Replays packages/pca/conformance/policy-classes-vectors.json (a missing file fails: load calls t.Fatal).
func TestPolicyClassesVectors(t *testing.T) {
	doc := load(t, "policy-classes-vectors.json")
	val, dec := doc["validate"].([]any), doc["decide"].([]any)
	if len(val) < 8 || len(dec) < 6 {
		t.Fatal("too few vectors")
	}
	for _, x := range val {
		v := x.(map[string]any)
		t.Run("validate/"+v["name"].(string), func(t *testing.T) {
			if got := ClassVerdictsError(v["input"]) == ""; got != v["expect"].(map[string]any)["ok"].(bool) {
				t.Fatalf("ok = %v", got)
			}
		})
	}
	for _, x := range dec {
		v := x.(map[string]any)
		t.Run("decide/"+v["name"].(string), func(t *testing.T) {
			want := v["expect"].(map[string]any)
			got := DecideClasses(v["input"])
			reason, _ := want["reason"].(string)
			if got.Decision != want["decision"] || got.Reason != reason {
				t.Fatalf("got %s %q, want %v", got.Decision, got.Reason, want)
			}
			wc := want["classes"].([]any)
			if len(got.Classes) != len(wc) {
				t.Fatalf("classes %v, want %v", got.Classes, wc)
			}
			for i, c := range got.Classes {
				w := wc[i].(map[string]any)
				if c.Class != w["class"] || c.Revision != num(w["revision"]) || c.Digest != w["digest"] || c.Decision != w["decision"] {
					t.Fatalf("class %d: %+v, want %v", i, c, w)
				}
			}
			for _, p := range []struct {
				got  []string
				want []any
			}{{got.DeniedBy, want["denied_by"].([]any)}, {got.EscalatedBy, want["escalated_by"].([]any)}} {
				if len(p.got) != len(p.want) {
					t.Fatalf("lists %v, want %v", p.got, p.want)
				}
				for i := range p.got {
					if p.got[i] != p.want[i] {
						t.Fatalf("lists %v, want %v", p.got, p.want)
					}
				}
			}
		})
	}
}
