package pca

import (
	"reflect"
	"testing"
)

// Shared vectors for linked policy templates: packages/pca/conformance/policy-link-vectors.json.
func TestPolicyLinkVectors(t *testing.T) {
	doc := load(t, "policy-link-vectors.json")
	def := doc["template"].(map[string]any)["def"]
	if d, err := TemplateDigest(def); err != nil || d != doc["template"].(map[string]any)["digest"] {
		t.Fatalf("digest %q %v", d, err)
	}
	list := func(k string) []any { return doc[k].([]any) }
	for _, x := range list("def_errors") {
		v := x.(map[string]any)
		t.Run("def/"+v["name"].(string), func(t *testing.T) {
			want, _ := v["expect"].(string)
			if got := TemplateDefError(v["def"]); got != want {
				t.Fatalf("got %q, want %q", got, want)
			}
		})
	}
	if len(list("instantiate")) < 14 {
		t.Fatal("too few instantiate vectors")
	}
	for _, x := range list("instantiate") {
		v := x.(map[string]any)
		t.Run("instantiate/"+v["name"].(string), func(t *testing.T) {
			pol, why := InstantiateTemplate(def, v["slots"])
			want := v["expect"].(map[string]any)
			if want["ok"].(bool) {
				if why != "" || !reflect.DeepEqual(pol, want["policy"]) {
					t.Fatalf("got %v %q", pol, why)
				}
			} else if why != want["reason"] {
				t.Fatalf("reason %q, want %q", why, want["reason"])
			}
		})
	}
	for _, x := range list("verify") {
		v := x.(map[string]any)
		t.Run("verify/"+v["name"].(string), func(t *testing.T) {
			var trusted []string
			for _, k := range v["trusted"].([]any) {
				trusted = append(trusted, k.(string))
			}
			var why string
			var ok bool
			if v["kind"] == "template" {
				why, ok = VerifyTemplate(v["signed"], trusted)
			} else {
				why, ok = VerifyTighten(v["signed"], trusted)
			}
			want := v["expect"].(map[string]any)
			if ok != want["ok"].(bool) || (!ok && why != want["reason"]) {
				t.Fatalf("got %v %q, want %v", ok, why, want)
			}
		})
	}
	for _, x := range list("ref_errors") {
		v := x.(map[string]any)
		t.Run("ref/"+v["name"].(string), func(t *testing.T) {
			want, _ := v["expect"].(string)
			if got := TemplateRefError(v["ref"]); got != want {
				t.Fatalf("got %q, want %q", got, want)
			}
		})
	}
	for _, x := range list("resolve") {
		v := x.(map[string]any)
		t.Run("resolve/"+v["name"].(string), func(t *testing.T) {
			pol, n, why := ResolveLink(v["ref"], v["registry"].(map[string]any))
			want := v["expect"].(map[string]any)
			if want["ok"].(bool) {
				if why != "" || !reflect.DeepEqual(pol, want["policy"]) || int64(n) != num(want["overlays"]) {
					t.Fatalf("got %v %d %q", pol, n, why)
				}
			} else if why != want["reason"] {
				t.Fatalf("reason %q, want %q", why, want["reason"])
			}
		})
	}
}
