package pca

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// ---- B6: check names ---------------------------------------------------------------------------------------------

func firstFixtureStep(t *testing.T) (map[string]any, map[string]any, map[string]any) {
	d := authorizeFixtures(t)
	c := d["cases"].([]any)[0].(map[string]any)
	return d, c, c["steps"].([]any)[0].(map[string]any)
}

func TestCoreVerifierNamesTheFormatCheckCounterFormat(t *testing.T) {
	f := newFx(t)
	v, err := VerifyPCActnCore(f.p, f.grant, f.now, f.aud)
	if err != nil || !v.Allow {
		t.Fatalf("baseline: %+v %v", v, err)
	}
	if _, has := v.Checks["counter"]; has || !v.Checks["counter_format"] {
		t.Fatalf("checks must carry counter_format and not counter: %v", v.Checks)
	}
}

func TestAuthorizeRequiredListAndReplayCheck(t *testing.T) {
	want := "counter_format,replay,revocation,plan_root_authorized,audience,validity,grant_ref_bound,operation,params_digest,policy"
	if got := strings.Join(DefaultRequiredChecks(), ","); got != want {
		t.Fatalf("required list %s, want %s", got, want)
	}
	d, c, s := firstFixtureStep(t)
	revoked := false
	in := fixInput(d, c["grant"].(map[string]any), NewMemoryStateStore(), &revoked)
	in.Operation = fixOp(s["operation"].(map[string]any))
	r := Authorize(s["pcactn"], in)
	if !r.Allow || r.Checks["replay"] != "pass" || r.Checks["counter_format"] != "pass" {
		t.Fatalf("allowed: %+v", r)
	}
	if _, has := r.Checks["counter"]; has {
		t.Fatalf("counter must not be emitted: %v", r.Checks)
	}
	// the 0.4 name in Require is an alias of replay: it still passes and does not demand a check called counter
	in.StateStore = NewMemoryStateStore()
	in.Require = []string{"counter"}
	if r := Authorize(s["pcactn"], in); !r.Allow || r.Status != 200 {
		t.Fatalf("require counter alias: %+v", r)
	}
}

type fakeStore struct {
	res ClaimResult
	err error
}

func (f fakeStore) Claim(string, int64) (ClaimResult, error) { return f.res, f.err }

func TestAuthorizeReplayReasons(t *testing.T) {
	d, c, s := firstFixtureStep(t)
	n := fixNum(s["pcactn"].(map[string]any)["counter"])
	last := int64(7)
	for name, tc := range map[string]struct {
		store fakeStore
		want  string
	}{
		"older":  {fakeStore{res: ClaimResult{LastCounter: &last}}, fmt.Sprintf("replay: %d is not greater than last seen 7 (replay)", n)},
		"seen":   {fakeStore{}, fmt.Sprintf("replay: %d was already claimed (replay)", n)},
		"failed": {fakeStore{err: errors.New("db down")}, "replay: the replay store failed (fail closed)"},
	} {
		revoked := false
		in := fixInput(d, c["grant"].(map[string]any), tc.store, &revoked)
		in.Operation = fixOp(s["operation"].(map[string]any))
		r := Authorize(s["pcactn"], in)
		if r.Allow || r.Status != 403 || r.Reason != tc.want || r.Checks["replay"] != "fail" {
			t.Errorf("%s: %+v want reason %q", name, r, tc.want)
		}
		if _, has := r.Checks["counter"]; has {
			t.Errorf("%s: counter emitted", name)
		}
	}
}

// ---- B6: limit-naming reasons ------------------------------------------------------------------------------------

// limit-reasons.json: every case's reason is what the TypeScript evaluatePredicates returns.
func TestLimitNamingReasonsMatchTypeScript(t *testing.T) {
	b, err := os.ReadFile("testdata/limit-reasons.json")
	if err != nil {
		t.Fatal(err)
	}
	// plain decoder with json.Number: the file holds numbers the strict grant parser would refuse (beyond 2^53)
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.UseNumber()
	var d map[string]any
	if err := dec.Decode(&d); err != nil {
		t.Fatal(err)
	}
	cases := d["cases"].([]any)
	if len(cases) < 70 {
		t.Fatalf("only %d cases", len(cases))
	}
	for _, c := range cases {
		c := c.(map[string]any)
		ctx := map[string]any{"action": map[string]any{"verb": c["verb"], "resource": c["resource"], "params": c["params"]}}
		ok, reason := envelopePredicates(c["predicates"], ctx, &regexBudget{})
		if ok != (c["allowed"] == true) || reason != c["reason"] {
			t.Errorf("%v: got (%v, %q), want %q", c["name"], ok, reason, c["reason"])
		}
	}
}

func TestLimitNamingReasonsLiteral(t *testing.T) {
	mk := func(where ...any) []any {
		return []any{map[string]any{"verb": "stripe.refund", "resource": "charge:*", "where": where}}
	}
	leaf := func(op string, v any) map[string]any {
		return map[string]any{"field": "action.params.amount", "op": op, "value": v}
	}
	ctx := map[string]any{"action": map[string]any{"verb": "stripe.refund", "resource": "charge:ch_1",
		"params": map[string]any{"amount": jnum(900)}}}
	for _, tc := range []struct {
		name  string
		preds []any
		want  string
	}{
		{"scalar", mk(leaf("lte", jnum(500))), "amount <= 500 not satisfied for stripe.refund on charge:ch_1"},
		{"list", mk(map[string]any{"field": "action.params.currency", "op": "in", "value": []any{"usd", "eur"}}),
			`currency in ["usd", "eur"] not satisfied for stripe.refund on charge:ch_1`},
		{"scope", []any{map[string]any{"verb": "other", "where": []any{leaf("lte", jnum(1))}}},
			"no predicate permits stripe.refund on charge:ch_1"},
		{"empty", []any{}, "envelope grants no predicates"},
	} {
		if ok, reason := envelopePredicates(tc.preds, ctx, &regexBudget{}); ok || reason != tc.want {
			t.Errorf("%s: (%v, %q), want %q", tc.name, ok, reason, tc.want)
		}
	}
}

// ---- B3: the default guard is the full authorize path ---------------------------------------------------------------

type guardRun struct {
	code  int
	calls int
	body  map[string]any
}

func serve(t *testing.T, opts RequirePCAOptions, pcactn map[string]any) guardRun {
	t.Helper()
	var g guardRun
	h := RequirePCA(opts)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { g.calls++; w.WriteHeader(204) }))
	req := httptest.NewRequest(http.MethodPost, "/pay", strings.NewReader(`{"amount":50}`))
	req.Header.Set(PCAHeader, headerFor(t, pcactn))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	g.code = rec.Code
	_ = json.Unmarshal(rec.Body.Bytes(), &g.body)
	return g
}

// Every shared fixture step through the middleware with the DEFAULT guard (no opt-in flag): the same outcomes.
func TestDefaultGuardRunsEveryFixtureCase(t *testing.T) {
	d := authorizeFixtures(t)
	for _, c := range d["cases"].([]any) {
		c := c.(map[string]any)
		t.Run(c["name"].(string), func(t *testing.T) {
			grant := c["grant"].(map[string]any)
			store := NewMemoryStateStore()
			for i, s := range c["steps"].([]any) {
				s := s.(map[string]any)
				revoked := s["revoked"] == true
				op := fixOp(s["operation"].(map[string]any))
				g := serve(t, RequirePCAOptions{
					Audience: d["audience"].(string), Now: func() int64 { return fixNum(d["now"]) },
					ResolveGrant: func(string) (map[string]any, error) { return grant, nil },
					Authorize: &AuthorizeOptions{StateStore: store,
						IsRevoked: func(_, _ map[string]any) (bool, error) { return revoked, nil },
						Operation: func(*http.Request, []byte) (*Operation, error) { return op, nil }},
				}, s["pcactn"].(map[string]any))
				exp := s["expect"].(map[string]any)
				want, calls := int(fixNum(exp["status"])), 0
				if exp["allow"] == true {
					want, calls = 204, 1
				}
				if g.code != want || g.calls != calls {
					t.Fatalf("step %d: code %d calls %d, want %d/%d (%v)", i, g.code, g.calls, want, calls, g.body)
				}
				if r, has := exp["reason"].(string); has {
					if got, _ := g.body["reason"].(string); !strings.Contains(got, r) {
						t.Fatalf("step %d: reason %q does not contain %q", i, got, r)
					}
				}
			}
		})
	}
}

func guardCase(t *testing.T, name string) (map[string]any, map[string]any, map[string]any) {
	d := authorizeFixtures(t)
	for _, c := range d["cases"].([]any) {
		if c.(map[string]any)["name"] == name {
			c := c.(map[string]any)
			return d, c["grant"].(map[string]any), c["steps"].([]any)[0].(map[string]any)
		}
	}
	t.Fatalf("no fixture case %s", name)
	return nil, nil, nil
}

func TestDefaultGuardWithoutComponentsRefusesAuthorizeConfig(t *testing.T) {
	d, grant, s := guardCase(t, "envelope-predicate-within")
	g := serve(t, RequirePCAOptions{Audience: d["audience"].(string), Now: func() int64 { return fixNum(d["now"]) },
		ResolveGrant: func(string) (map[string]any, error) { return grant, nil }}, s["pcactn"].(map[string]any))
	if g.code != 403 || g.calls != 0 || g.body["checks"].(map[string]any)["authorize_config"] != "fail" {
		t.Fatalf("default without store: %+v", g)
	}
	missing, _ := json.Marshal(g.body["missing"])
	if string(missing) != `["StateStore","IsRevoked"]` {
		t.Fatalf("missing = %s", missing)
	}
	// an Authorize set with a store but no revocation source names only what is still absent
	g = serve(t, RequirePCAOptions{Audience: d["audience"].(string), Now: func() int64 { return fixNum(d["now"]) },
		ResolveGrant: func(string) (map[string]any, error) { return grant, nil },
		Authorize:    &AuthorizeOptions{StateStore: NewMemoryStateStore()}}, s["pcactn"].(map[string]any))
	missing, _ = json.Marshal(g.body["missing"])
	if g.code != 403 || g.calls != 0 || string(missing) != `["IsRevoked"]` {
		t.Fatalf("partial config: %+v %s", g, missing)
	}
}

func TestDefaultGuardWithoutOperationMappingRefuses(t *testing.T) {
	d, grant, s := guardCase(t, "envelope-predicate-within")
	g := serve(t, RequirePCAOptions{Audience: d["audience"].(string), Now: func() int64 { return fixNum(d["now"]) },
		ResolveGrant: func(string) (map[string]any, error) { return grant, nil },
		Authorize: &AuthorizeOptions{StateStore: NewMemoryStateStore(),
			IsRevoked: func(_, _ map[string]any) (bool, error) { return false, nil }}}, s["pcactn"].(map[string]any))
	if g.code != 403 || g.calls != 0 || g.body["checks"].(map[string]any)["operation"] != "fail" {
		t.Fatalf("no operation mapping: %+v", g)
	}
}

func TestSignatureOnlyIsAnExplicitOptInAndSkipsPolicy(t *testing.T) {
	d, grant, s := guardCase(t, "envelope-predicate-400-refused")
	opts := RequirePCAOptions{Audience: d["audience"].(string), Now: func() int64 { return fixNum(d["now"]) },
		ResolveGrant: func(string) (map[string]any, error) { return grant, nil }}
	if g := serve(t, opts, s["pcactn"].(map[string]any)); g.code != 403 || g.calls != 0 {
		t.Fatalf("default refuses: %+v", g)
	}
	opts.SignatureOnly = true
	if g := serve(t, opts, s["pcactn"].(map[string]any)); g.code != 204 || g.calls != 1 {
		t.Fatalf("signature-only verifies the signature only and the handler runs: %+v", g)
	}
}

func TestSignatureOnlyWithAuthorizeIsAConstructionError(t *testing.T) {
	defer func() {
		r := recover()
		if s, _ := r.(string); !strings.Contains(s, "mutually exclusive") {
			t.Fatalf("want a construction panic, got %v", r)
		}
	}()
	RequirePCA(RequirePCAOptions{SignatureOnly: true, Authorize: &AuthorizeOptions{}})
}
