package pca

// Differential kill test for predicates.go / jsval.go against the TypeScript reference (packages/pca/src/predicates.ts +
// hash.ts + JavaScript number semantics). testdata/k042-predjs.json is produced by
// tools/pca-audit/java-mutate/k042-predjs-oracle.mjs (shared with the Java suite); every input is carried as JSON text so
// both sides parse identical lexemes (1e400, -0, lone surrogates).

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"strconv"
	"testing"
)

type k042PredJs struct {
	Tri []struct {
		Name, Ctx, Cond, Tri string
	} `json:"tri"`
	Preds []struct {
		Name, Ctx, Preds string
		Allowed          bool
		Each             []bool
	} `json:"preds"`
	Eq []struct {
		A, B string
		Eq   bool
	} `json:"eq"`
	Nums []struct {
		Raw, Js             string
		Safe, Finite, Plain bool
	} `json:"nums"`
	Ctx   map[string]string `json:"ctx"`
	Chain map[string]string `json:"chain"`
	Fan   map[string]string `json:"fan"`
}

func k042LoadPredJs(t *testing.T) *k042PredJs {
	b, err := os.ReadFile("testdata/k042-predjs.json")
	if err != nil {
		t.Fatal(err)
	}
	var g k042PredJs
	if err := json.Unmarshal(b, &g); err != nil {
		t.Fatal(err)
	}
	return &g
}

func k042Ctx(t *testing.T, s string) map[string]any {
	v, err := ParseJSONLenient([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	m, _ := v.(map[string]any)
	return m
}

func k042TriName(r int) string {
	switch r {
	case triTrue:
		return "true"
	case triFalse:
		return "false"
	}
	return "unknown"
}

func TestK042PredJsConditionsMatchTheReference(t *testing.T) {
	g := k042LoadPredJs(t)
	if len(g.Tri) < 400 {
		t.Fatalf("golden too small: %d", len(g.Tri))
	}
	var bad []string
	for _, c := range g.Tri {
		cond, err := ParseJSONLenient([]byte(c.Cond))
		if err != nil {
			t.Fatal(err)
		}
		got := k042TriName(evaluateConditionTri(cond, k042Ctx(t, g.Ctx[c.Ctx]), &regexBudget{}))
		if got != c.Tri {
			bad = append(bad, fmt.Sprintf("%s: want %s got %s", c.Name, c.Tri, got))
		}
	}
	if len(bad) > 0 {
		t.Fatalf("%d differences: %v", len(bad), bad)
	}
}

func TestK042PredJsPredicatesMatchTheReference(t *testing.T) {
	g := k042LoadPredJs(t)
	var bad []string
	for _, c := range g.Preds {
		preds, err := ParseJSONLenient([]byte(c.Preds))
		if err != nil {
			t.Fatal(err)
		}
		if got := evaluatePredicates(preds, k042Ctx(t, g.Ctx[c.Ctx])); got != c.Allowed {
			bad = append(bad, fmt.Sprintf("%s: allowed want %v got %v", c.Name, c.Allowed, got))
		}
		if ps, ok := preds.([]any); ok {
			if len(ps) != len(c.Each) {
				t.Fatalf("%s: each length", c.Name)
			}
			for i, p := range ps {
				if m := predicateMatches(p, k042Ctx(t, g.Ctx[c.Ctx]), &regexBudget{}); m != c.Each[i] {
					bad = append(bad, fmt.Sprintf("%s[%d]: want %v got %v", c.Name, i, c.Each[i], m))
				}
			}
		}
	}
	if len(bad) > 0 {
		t.Fatalf("%d differences: %v", len(bad), bad)
	}
}

func TestK042PredJsLenientCanonicalEquality(t *testing.T) {
	g := k042LoadPredJs(t)
	for _, c := range g.Eq {
		a, err := ParseJSONLenient([]byte(c.A))
		if err != nil {
			t.Fatal(err)
		}
		b, err := ParseJSONLenient([]byte(c.B))
		if err != nil {
			t.Fatal(err)
		}
		if got := deepEq(a, b); got != c.Eq {
			t.Errorf("%s == %s: want %v got %v", c.A, c.B, c.Eq, got)
		}
	}
}

func TestK042PredJsNumbersMatchJavaScript(t *testing.T) {
	g := k042LoadPredJs(t)
	for _, c := range g.Nums {
		n := json.Number(c.Raw)
		d, ok := parseJSNumberLexeme(c.Raw)
		if !ok {
			t.Errorf("%s: not parsed", c.Raw)
			continue
		}
		if jsIsSafeInteger(n) != c.Safe {
			t.Errorf("%s: isSafeInteger want %v", c.Raw, c.Safe)
		}
		if isFinite(d) != c.Finite {
			t.Errorf("%s: isFinite want %v", c.Raw, c.Finite)
		}
		if f, _ := jsNum(n); f != d && !(math.IsNaN(f) && math.IsNaN(d)) {
			t.Errorf("%s: jsNum %v want %v", c.Raw, f, d)
		}
		if c.Finite {
			if got := jsNumberString(d); got != c.Js {
				t.Errorf("%s: jsNumberString %q want %q", c.Raw, got, c.Js)
			}
			if nv, _ := normalizeJSON(n).(json.Number); string(nv) != c.Js {
				t.Errorf("%s: normalizeJSON %q want %q", c.Raw, nv, c.Js)
			}
			if nv, _ := normalizeJSON(d).(json.Number); string(nv) != c.Js {
				t.Errorf("%s: normalizeJSON(float64) %q want %q", c.Raw, nv, c.Js)
			}
			if want := strconv.FormatBool(c.Safe && d != math.Trunc(d)); want == "true" {
				t.Errorf("%s: a safe non-integer", c.Raw)
			}
		}
	}
}

func TestK042PredJsUtf8LengthsAndSurrogates(t *testing.T) {
	// the lenient parser keeps a lone surrogate (as WTF-8); encoding/json would turn it into U+FFFD
	b, err := os.ReadFile("testdata/k042-predjs.json")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := ParseJSONLenient(b)
	if err != nil {
		t.Fatal(err)
	}
	root := doc.(map[string]any)
	u8, cmp := root["u8"].([]any), root["cmp"].([]any)
	if len(u8) < 10 || len(cmp) < 5 {
		t.Fatal("golden too small")
	}
	for _, o := range u8 {
		c := o.(map[string]any)
		s := c["s"].(string)
		n, _ := strconv.Atoi(string(c["n"].(json.Number)))
		if got := utf8Len(s); got != n {
			t.Errorf("utf8Len %q: want %d got %d", s, n, got)
		}
		if got := hasLoneSurrogate(s); got != c["lone"].(bool) {
			t.Errorf("hasLoneSurrogate %q: want %v got %v", s, c["lone"], got)
		}
	}
	for _, o := range cmp {
		c := o.(map[string]any)
		a, bb := c["a"].(string), c["b"].(string)
		sign, _ := strconv.Atoi(string(c["sign"].(json.Number)))
		got := compareUtf8(a, bb)
		if (got > 0) != (sign > 0) || (got < 0) != (sign < 0) {
			t.Errorf("compareUtf8 %q %q: want sign %d got %d", a, bb, sign, got)
		}
	}
}

func k042ChainCtx(n int) map[string]any {
	g := map[string]any{}
	for i := 0; i < n; i++ {
		g[fmt.Sprintf("n%d", i)] = fmt.Sprintf("n%d", i+1)
	}
	return map[string]any{"action": map[string]any{"verb": "v", "resource": "r"}, "subject": map[string]any{"id": "n0", "g": g}}
}

func k042FanCtx() map[string]any {
	g := map[string]any{}
	s := []any{}
	cs := []any{}
	for j := 0; j < 100; j++ {
		cs = append(cs, fmt.Sprintf("c%d", j))
	}
	g["s"] = s
	for i := 0; i < 100; i++ {
		s = append(s, fmt.Sprintf("a%d", i))
		g[fmt.Sprintf("a%d", i)] = cs
	}
	g["s"] = s
	g["c0"] = "e"
	g["e"] = "t"
	return map[string]any{"action": map[string]any{"verb": "v", "resource": "r"}, "subject": map[string]any{"id": "s", "g": g}}
}

func k042Member(v string) map[string]any {
	return map[string]any{"field": "subject.id", "op": "member_of", "collection": "subject.g", "value": v}
}

func TestK042PredJsMemberClosureIsCappedLikeTheReference(t *testing.T) {
	g := k042LoadPredJs(t)
	cc, fc := k042ChainCtx(10005), k042FanCtx()
	for k, want := range g.Chain {
		if got := k042TriName(evaluateConditionTri(k042Member(k), cc, &regexBudget{})); got != want {
			t.Errorf("chain %s: want %s got %s", k, want, got)
		}
	}
	for k, want := range g.Fan {
		if got := k042TriName(evaluateConditionTri(k042Member(k), fc, &regexBudget{})); got != want {
			t.Errorf("fan %s: want %s got %s", k, want, got)
		}
	}
	if g.Chain["n10000"] != "true" || g.Chain["n10001"] != "false" {
		t.Fatal("chain golden")
	}
}
