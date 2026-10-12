package pca

// 0.4.1 runners for the new public helpers: primitives.caveat_eval (PolicyCaveats + EvaluateCaveats, the
// root-caveat security fix in the policy layer) and primitives.pca_header (DecodePCAHeader, strict unpadded
// base64url of UTF-8), plus unit tests for the edges the corpus does not pin.

import (
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func TestR041CaveatEval(t *testing.T) {
	prim := load(t, "vectors.json")["primitives"].(map[string]any)
	cases := prim["caveat_eval"].([]any)
	if len(cases) < 40 {
		t.Fatalf("caveat_eval: %d cases, want >= 40", len(cases))
	}
	byName := map[string]map[string]any{}
	for _, x := range cases {
		c := x.(map[string]any)
		byName[c["name"].(string)] = c
	}
	if e := byName["r041-root-max-spend-exceeded"]; e == nil || e["expect"].(map[string]any)["allow"] != false {
		t.Fatal("missing the root max_spend DENY vector")
	}
	if e := byName["r041-root-max-spend-within"]; e == nil || e["expect"].(map[string]any)["allow"] != true {
		t.Fatal("missing the root max_spend ALLOW vector")
	}
	for _, x := range cases {
		c := x.(map[string]any)
		t.Run(c["name"].(string), func(t *testing.T) {
			ok, failed := EvaluateCaveats(PolicyCaveats(c["grant"], c["chain"]), c["context"].(map[string]any))
			exp := c["expect"].(map[string]any)
			want := []string{}
			for _, f := range exp["failed"].([]any) {
				want = append(want, f.(string))
			}
			if ok != exp["allow"].(bool) || !reflect.DeepEqual(failed, want) {
				t.Errorf("got (%v, %q), want (%v, %q)", ok, failed, exp["allow"], want)
			}
		})
	}
}

func TestR041PcaHeader(t *testing.T) {
	prim := load(t, "vectors.json")["primitives"].(map[string]any)
	cases := prim["pca_header"].([]any)
	if len(cases) < 27 {
		t.Fatalf("pca_header: %d cases, want >= 27", len(cases))
	}
	for _, x := range cases {
		c := x.(map[string]any)
		t.Run(c["name"].(string), func(t *testing.T) {
			text, err := DecodePCAHeader(c["input"].(string))
			valid := err == nil
			if valid != c["valid"].(bool) {
				t.Fatalf("valid = %v, want %v (err %v)", valid, c["valid"], err)
			}
			if valid && text != c["text"].(string) {
				t.Fatalf("text = %q, want %q", text, c["text"])
			}
			if !valid && text != "" {
				t.Fatalf("text %q returned with an error", text)
			}
		})
	}
}

func TestR041DecodePCAHeaderEdges(t *testing.T) {
	bad := []string{"", "YQ==", "YQ=", "Y", "YR", " YQ", "YQ ", "Y Q", "YQ\r\n", "Y+", "Y/", "\uFEFFYQ", "7aCA" /* ED A0 80 */, "wK8" /* C0 AF */, "4oI" /* E2 82 */, "_w" /* FF */}
	for _, in := range bad {
		if s, err := DecodePCAHeader(in); err == nil {
			t.Errorf("%q: accepted as %q", in, s)
		}
	}
	good := map[string]string{"YQ": "a", "e30": "{}", "77u_": "\uFEFF", "8J-YgA": "\U0001F600"}
	for in, want := range good {
		if s, err := DecodePCAHeader(in); err != nil || s != want {
			t.Errorf("%q: got %q, %v; want %q", in, s, err, want)
		}
	}
}

// A padded / whitespace-carrying header takes the existing 401 "not valid base64url" path; the canonical
// spelling of the same PCActn still passes.
func TestR041MiddlewareStrictHeader(t *testing.T) {
	pcactn, _, _, _ := loadValidVector(t)
	good := headerFor(t, pcactn)
	do := func(h string) *httptest.ResponseRecorder {
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
		req := httptest.NewRequest(http.MethodGet, "/do", nil)
		req.Header[http.CanonicalHeaderKey(PCAHeader)] = []string{h}
		rec := httptest.NewRecorder()
		mw(t, "")(next).ServeHTTP(rec, req)
		return rec
	}
	for i, h := range []string{good + "=", good + "==", good + " ", "\t" + good, "eyJhIjoxfQ=="} {
		rec := do(h)
		if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), headerB64Reason) {
			t.Errorf("case %d: status %d body %s", i, rec.Code, rec.Body.String())
		}
	}
	if rec := do(good); rec.Code != http.StatusOK {
		t.Fatalf("canonical header: status %d body %s", rec.Code, rec.Body.String())
	}
}

func r041num(s string) json.Number { return json.Number(s) }

func ctxWith(params any) map[string]any {
	return map[string]any{"now": r041num("1000"), "action": map[string]any{"verb": "pay", "resource": "x", "params": params}}
}

func TestR041EvaluateCaveatsEdges(t *testing.T) {
	ms := func(usd any) map[string]any { return map[string]any{"type": "max_spend", "usd": usd} }
	cases := []struct {
		name    string
		caveats any
		ctx     map[string]any
		ok      bool
		failed  []string
	}{
		{"non-array", map[string]any{}, ctxWith(nil), false, []string{"<malformed caveats>"}},
		{"nil list", nil, ctxWith(nil), false, []string{"<malformed caveats>"}},
		{"empty list", []any{}, ctxWith(nil), true, []string{}},
		{"non-object caveat", []any{"max_spend"}, ctxWith(nil), false, []string{"<malformed>"}},
		{"array caveat", []any{[]any{}}, ctxWith(nil), false, []string{"<malformed>"}},
		{"non-string type", []any{map[string]any{"type": r041num("1")}}, ctxWith(nil), false, []string{"<malformed>"}},
		{"unknown type", []any{map[string]any{"type": "resource_prefix"}}, ctxWith(nil), false, []string{"resource_prefix"}},
		{"predicates fail closed", []any{map[string]any{"type": "predicates", "allow": []any{}}}, ctxWith(nil), false, []string{"predicates"}},
		{"max_spend ok float64", []any{ms(100.0)}, ctxWith(map[string]any{"amount": 99.5}), true, []string{}},
		{"max_spend ok int", []any{ms(100)}, ctxWith(map[string]any{"amount": 100}), true, []string{}},
		{"max_spend bool amount", []any{ms(r041num("100"))}, ctxWith(map[string]any{"amount": true}), false, []string{"max_spend"}},
		{"max_spend bool limit", []any{ms(true)}, ctxWith(map[string]any{"amount": r041num("0")}), false, []string{"max_spend"}},
		{"max_spend inf limit", []any{ms(r041num("1e400"))}, ctxWith(map[string]any{"amount": r041num("0")}), false, []string{"max_spend"}},
		{"max_spend NaN amount", []any{ms(r041num("10"))}, ctxWith(map[string]any{"amount": math.NaN()}), false, []string{"max_spend"}},
		{"max_spend no now needed", []any{ms(r041num("10"))}, map[string]any{"action": map[string]any{"params": map[string]any{"amount": r041num("1")}}}, true, []string{}},
		{"max_spend action not object", []any{ms(r041num("10"))}, map[string]any{"now": r041num("1"), "action": "pay"}, false, []string{"max_spend"}},
		{"max_spend no action", []any{ms(r041num("10"))}, map[string]any{"now": r041num("1")}, false, []string{"max_spend"}},
		{"max_spend currency number", []any{ms(r041num("10"))}, ctxWith(map[string]any{"amount": r041num("1"), "currency": r041num("1")}), false, []string{"max_spend"}},
		{"max_spend negative zero amount", []any{ms(r041num("0"))}, ctxWith(map[string]any{"amount": r041num("-0")}), true, []string{}},
		{"expires needs now", []any{map[string]any{"type": "expires", "at": r041num("5")}}, map[string]any{}, false, []string{"expires"}},
		{"expires string now", []any{map[string]any{"type": "expires", "at": r041num("5")}}, map[string]any{"now": "1"}, false, []string{"expires"}},
		{"budget_alloc needs now", []any{map[string]any{"type": "budget_alloc", "limit": r041num("1")}}, map[string]any{}, false, []string{"budget_alloc"}},
		{"budget_alloc negative", []any{map[string]any{"type": "budget_alloc", "limit": r041num("-1")}}, ctxWith(nil), false, []string{"budget_alloc"}},
		{"rate per_secs 0", []any{map[string]any{"type": "rate", "max": r041num("5"), "per_secs": r041num("0")}}, map[string]any{"now": r041num("1000"), "recent_action_times": []any{}}, false, []string{"rate"}},
		{"rate ignores non-numbers", []any{map[string]any{"type": "rate", "max": r041num("1"), "per_secs": r041num("1")}}, map[string]any{"now": r041num("1000"), "recent_action_times": []any{"999", true, nil, r041num("0")}}, true, []string{}},
		{"rate counts window", []any{map[string]any{"type": "rate", "max": r041num("1"), "per_secs": r041num("1")}}, map[string]any{"now": r041num("1000"), "recent_action_times": []any{r041num("1000")}}, false, []string{"rate"}},
		{"reversibility uses ctx class", []any{map[string]any{"type": "reversibility_max", "class": "reversible"}}, map[string]any{"now": r041num("1"), "action": map[string]any{"reversibility_class": "reversible"}}, false, []string{"reversibility_max"}},
		{"reversibility unknown class", []any{map[string]any{"type": "reversibility_max", "class": "bogus"}}, map[string]any{"now": r041num("1"), "reversibility_class": "reversible"}, false, []string{"reversibility_max"}},
		{"delegation_depth", []any{map[string]any{"type": "delegation_depth", "max": r041num("2")}}, map[string]any{"now": r041num("1"), "delegation_depth": r041num("2")}, true, []string{}},
		{"order kept", []any{map[string]any{"type": "note"}, ms(r041num("1")), "x"}, ctxWith(map[string]any{"amount": r041num("2")}), false, []string{"note", "max_spend", "<malformed>"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ok, failed := EvaluateCaveats(c.caveats, c.ctx)
			if ok != c.ok || !reflect.DeepEqual(failed, c.failed) {
				t.Errorf("got (%v, %q), want (%v, %q)", ok, failed, c.ok, c.failed)
			}
		})
	}
	// nil context: total, everything that needs a context is unsatisfied.
	if ok, f := EvaluateCaveats([]any{ms(r041num("1"))}, nil); ok || !reflect.DeepEqual(f, []string{"max_spend"}) {
		t.Errorf("nil ctx: %v %q", ok, f)
	}
}

func TestR041PolicyCaveatsEdges(t *testing.T) {
	env := map[string]any{"type": "envelope"}
	a := map[string]any{"type": "a"}
	b := map[string]any{"type": "b"}
	h := map[string]any{"type": "h"}
	grant := map[string]any{"caveats": []any{a, env, b, env}}
	leaf := map[string]any{"caveats": []any{a, env, b, env, h}}
	cases := []struct {
		name  string
		grant any
		chain any
		want  any
	}{
		{"first envelope removed, order kept, hop appended", grant, []any{grant, leaf}, []any{a, b, env, h}},
		{"empty chain", grant, []any{}, []any{a, b, env}},
		{"chain not array", grant, "x", []any{a, b, env}},
		{"leaf not object", grant, []any{r041num("5")}, []any{a, b, env}},
		{"leaf caveats not array", grant, []any{map[string]any{"caveats": "x"}}, []any{a, b, env}},
		{"leaf shorter than grant", grant, []any{map[string]any{"caveats": []any{a}}}, []any{a, b, env}},
		{"grant caveats not array", map[string]any{"caveats": "x"}, []any{leaf}, "x"},
		{"grant not object", "g", []any{leaf}, nil},
		{"no envelope", map[string]any{"caveats": []any{a}}, nil, []any{a}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := PolicyCaveats(c.grant, c.chain); !reflect.DeepEqual(got, c.want) {
				t.Errorf("got %v, want %v", got, c.want)
			}
		})
	}
	// The grant's own list is not mutated.
	_ = PolicyCaveats(grant, []any{leaf})
	if len(grant["caveats"].([]any)) != 4 {
		t.Fatal("grant caveats mutated")
	}
}

// The share wire rule, one violation at a time (unit level; the r041-share vectors cover it end to end).
func TestR041ShareWireUnit(t *testing.T) {
	pk := strings.Repeat("A", 43)
	sig := func(n int) string { return b64.EncodeToString(make([]byte, n)) }
	base := func(extra map[string]any) map[string]any {
		s := map[string]any{"role": "guardian", "publicKey": pk}
		for k, v := range extra {
			s[k] = v
		}
		return s
	}
	cases := []struct {
		name  string
		share map[string]any
		ok    bool
	}{
		{"ed25519 default", base(map[string]any{"sig": sig(64)}), true},
		{"ed25519 explicit", base(map[string]any{"alg": "ed25519", "sig": sig(64)}), true},
		{"ml-dsa-65", base(map[string]any{"alg": "ml-dsa-65", "sig": sig(3309)}), true},
		{"ml-dsa-65 with pq_pk echo of any shape", base(map[string]any{"alg": "ml-dsa-65", "sig": sig(3309), "pq_pk": r041num("1")}), true},
		{"hybrid", base(map[string]any{"alg": "hybrid-ed25519-ml-dsa-65", "sig": sig(64), "pq_sig": sig(3309)}), true},
		{"ed25519 3309", base(map[string]any{"sig": sig(3309)}), false},
		{"ed25519 stray pq_sig", base(map[string]any{"sig": sig(64), "pq_sig": sig(3309)}), false},
		{"ed25519 null pq_sig", base(map[string]any{"sig": sig(64), "pq_sig": nil}), false},
		{"ml-dsa-65 64", base(map[string]any{"alg": "ml-dsa-65", "sig": sig(64)}), false},
		{"ml-dsa-65 stray pq_sig", base(map[string]any{"alg": "ml-dsa-65", "sig": sig(3309), "pq_sig": sig(3309)}), false},
		{"hybrid no pq_sig", base(map[string]any{"alg": "hybrid-ed25519-ml-dsa-65", "sig": sig(64)}), false},
		{"hybrid sig 3309", base(map[string]any{"alg": "hybrid-ed25519-ml-dsa-65", "sig": sig(3309), "pq_sig": sig(3309)}), false},
		{"alg null", base(map[string]any{"alg": nil, "sig": sig(64)}), false},
		{"alg number", base(map[string]any{"alg": r041num("1"), "sig": sig(64)}), false},
		{"alg unknown", base(map[string]any{"alg": "ml-dsa-87", "sig": sig(4627)}), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := validateShareSignatureWire(c.share)
			if (got == "") != c.ok {
				t.Fatalf("validateShareSignatureWire = %q, want ok=%v", got, c.ok)
			}
		})
	}
}
