package pca

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

// Round-6 shared vectors (packages/pca/conformance/vectors.json, gen-conformance-r6.mjs): whole signer-set
// validation (R6-02, R6-03/R6-04), the signer-set hash (pq_pk:"" carried, UTF-8 byte order) and malformed input
// that must be a clean deny, never a panic (R6-05).

func r6Section(t *testing.T, k string) []map[string]any {
	t.Helper()
	prim := load(t, "vectors.json")["primitives"].(map[string]any)
	raw, ok := prim[k].([]any)
	if !ok {
		t.Fatalf("primitives.%s missing", k)
	}
	out := make([]map[string]any, 0, len(raw))
	for _, x := range raw {
		out = append(out, x.(map[string]any))
	}
	return out
}

// noPanic runs f and reports a recovered panic as an error string.
func noPanic(f func() bool) (got bool, panicked string) {
	defer func() {
		if r := recover(); r != nil {
			panicked = fmt.Sprint(r)
		}
	}()
	return f(), ""
}

func TestR6ThresholdSet(t *testing.T) {
	ran, skipped := 0, 0
	for _, e := range r6Section(t, "threshold_set") {
		name, _ := e["name"].(string)
		if req, ok := e["requires"].(string); ok && !supportedSuites[req] {
			skipped++
			continue
		}
		ran++
		want := e["valid"].(bool)
		got, p := noPanic(func() bool { return VerifyThresholdShare(e) })
		if p != "" {
			t.Errorf("%s: PANIC %s", name, p)
		} else if got != want {
			t.Errorf("%s: got %v want %v", name, got, want)
		}
	}
	if ran+skipped < 55 {
		t.Fatalf("threshold_set shrank: %d", ran+skipped)
	}
	t.Logf("threshold_set: ran %d, skipped %d", ran, skipped)
}

func TestR6SignerSetHash(t *testing.T) {
	for _, e := range r6Section(t, "signer_set_hash") {
		name, _ := e["name"].(string)
		set, _ := e["signer_set"].([]any)
		h, ok := SignerSetHash(set)
		got := ""
		if ok {
			got = base64.RawURLEncoding.EncodeToString(h)
		}
		if got != e["hash"].(string) {
			t.Errorf("%s: got %q want %q", name, got, e["hash"])
		}
	}
}

func TestR6Malformed(t *testing.T) {
	ms := r6Section(t, "malformed")
	if len(ms) < 80 {
		t.Fatalf("malformed shrank: %d", len(ms))
	}
	for _, m := range ms {
		name, _ := m["name"].(string)
		var f func() bool
		switch m["api"] {
		case "chain":
			in := m["input"].(map[string]any)
			chain, _ := in["chain"].([]any)
			iss, _ := in["expected_root_issuer"].(string)
			f = func() bool { _, ok := VerifyChain(chain, iss, true); return ok }
		case "threshold_share":
			in := m["input"]
			f = func() bool { return VerifyThresholdShare(in) }
		case "pcactn_json":
			in := m["input"].(map[string]any)
			grant, _ := in["grant"].(map[string]any)
			aud, _ := in["aud"].(string)
			now := num(in["now"])
			text, _ := in["text"].(string)
			f = func() bool {
				p, err := ParsePCActn(text)
				if err != nil {
					return false // parse failure == deny
				}
				v, _ := VerifyPCActnCore(p, grant, now, aud)
				return v.Allow
			}
		default:
			t.Errorf("%s: unknown api %v", name, m["api"])
			continue
		}
		got, p := noPanic(f)
		if p != "" {
			t.Errorf("%s: PANIC %s", name, p)
		} else if got {
			t.Errorf("%s: accepted", name)
		}
	}
}

// expandDepth applies a depth case's optional `expand` ({marker, levels, leaf}) ITERATIVELY, so the verifier (not the
// runner) faces the huge value: chain / threshold_share replace the string value equal to marker; pcactn_json /
// json_parse replace the substring marker of input.text.
func expandDepth(t *testing.T, e map[string]any) any {
	t.Helper()
	in := e["input"]
	x, ok := e["expand"].(map[string]any)
	if !ok {
		return in
	}
	marker, _ := x["marker"].(string)
	levels := int(num(x["levels"]))
	if api := e["api"]; api == "pcactn_json" || api == "json_parse" {
		leaf, err := Canonicalize(x["leaf"])
		if err != nil {
			t.Fatal(err)
		}
		m := in.(map[string]any)
		out := map[string]any{}
		for k, v := range m {
			out[k] = v
		}
		text, _ := m["text"].(string)
		out["text"] = strings.Replace(text, marker, strings.Repeat("[", levels)+leaf+strings.Repeat("]", levels), 1)
		return out
	}
	var v any = x["leaf"]
	for i := 0; i < levels; i++ {
		v = []any{v}
	}
	stack := []any{in}
	for len(stack) > 0 {
		c := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		switch n := c.(type) {
		case map[string]any:
			for k, val := range n {
				if s, isS := val.(string); isS && s == marker {
					n[k] = v
					return in
				}
				stack = append(stack, val)
			}
		case []any:
			for i, val := range n {
				if s, isS := val.(string); isS && s == marker {
					n[i] = v
					return in
				}
				stack = append(stack, val)
			}
		}
	}
	t.Fatalf("depth marker not found in %v", e["name"])
	return nil
}

// Depth limit-1 / limit / limit+1 / huge on every untrusted-input entry point (primitives.depth): the verdict equals the
// reference's and no panic escapes.
func TestDepthVectors(t *testing.T) {
	ds := r6Section(t, "depth")
	if len(ds) < 29 {
		t.Fatalf("depth shrank: %d", len(ds))
	}
	for _, e := range ds {
		name, _ := e["name"].(string)
		in := expandDepth(t, e)
		var f func() bool
		switch e["api"] {
		case "chain":
			m := in.(map[string]any)
			chain, _ := m["chain"].([]any)
			iss, _ := m["expected_root_issuer"].(string)
			f = func() bool { _, ok := VerifyChain(chain, iss, true); return ok }
		case "threshold_share":
			f = func() bool { return VerifyThresholdShare(in) }
		case "pcactn_json":
			m := in.(map[string]any)
			grant, _ := m["grant"].(map[string]any)
			aud, _ := m["aud"].(string)
			now := num(m["now"])
			text, _ := m["text"].(string)
			f = func() bool {
				p, err := ParsePCActn(text)
				if err != nil {
					return false
				}
				v, _ := VerifyPCActnCore(p, grant, now, aud)
				return v.Allow
			}
		case "json_parse":
			text, _ := in.(map[string]any)["text"].(string)
			f = func() bool { _, err := StrictParse(text); return err == nil }
		default:
			t.Errorf("%s: unknown api %v", name, e["api"])
			continue
		}
		got, p := noPanic(f)
		if p != "" {
			t.Errorf("%s: PANIC %s", name, p)
		} else if got != e["valid"] {
			t.Errorf("%s: got %v want %v", name, got, e["valid"])
		}
	}
}
