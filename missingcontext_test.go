package pca

import (
	"reflect"
	"testing"
)

// Replays packages/pca/conformance/missing-context-vectors.json (a missing file fails: load calls t.Fatal).
func TestMissingContextVectors(t *testing.T) {
	doc := load(t, "missing-context-vectors.json")
	dec, bind := doc["decide"].([]any), doc["bind"].([]any)
	if len(dec) < 20 || len(bind) < 8 {
		t.Fatal("too few vectors")
	}
	for _, x := range dec {
		v := x.(map[string]any)
		t.Run("decide/"+v["name"].(string), func(t *testing.T) {
			want := v["expect"].(map[string]any)
			got := DecideWithMissing(v["where"], v["bound"], v["supplied"], v["suppliers"])
			reason, _ := want["reason"].(string)
			if got.Decision != want["decision"] || got.Reason != reason {
				t.Fatalf("got %s %q, want %v", got.Decision, got.Reason, want)
			}
			wm := want["missing"].([]any)
			if len(got.Missing) != len(wm) {
				t.Fatalf("missing %v, want %v", got.Missing, wm)
			}
			for i, m := range got.Missing {
				w := wm[i].(map[string]any)
				if m.Path != w["path"] || m.Supplier != w["supplier"] {
					t.Fatalf("missing %d: %+v, want %v", i, m, w)
				}
			}
		})
	}
	for _, x := range bind {
		v := x.(map[string]any)
		t.Run("bind/"+v["name"].(string), func(t *testing.T) {
			want := v["expect"].(map[string]any)
			bound, _ := v["bound"].(map[string]any)
			got := BindContext(bound, v["supplied"], supplierTable(v["suppliers"]))
			if !reflect.DeepEqual(got.Context, want["context"]) {
				t.Fatalf("context %v, want %v", got.Context, want["context"])
			}
			for _, p := range []struct {
				got  []string
				want []any
			}{{got.Conflicts, want["conflicts"].([]any)}, {got.Dropped, want["dropped"].([]any)}} {
				if len(p.got) != len(p.want) {
					t.Fatalf("list %v, want %v", p.got, p.want)
				}
				for i := range p.got {
					if p.got[i] != p.want[i] {
						t.Fatalf("list %v, want %v", p.got, p.want)
					}
				}
			}
		})
	}
}
