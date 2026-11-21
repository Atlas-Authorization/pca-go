package pca

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/slhdsa"
)

// The agent facade pinned to the reference facade at its edges: catalog lookup and aliases, every limit period, the amount
// guard, the compiled caveats and risk policy (zero and sub-unit caps, reversible-only grants, duplicate grants), the risk
// claim, the agent defaults, the action options, the dry run, the provenance header cap and the sub-agent refusals; plus the
// key-material clearing of the post-quantum keygen and the revocation-epoch signer.

// fcCatalog: a reversible money-moving action with a resource matcher, an irreversible one with an alias, a rate-limited one
// with a one-letter connector and an alias, an action of the empty connector, and a verb without a dot.
func fcCatalog() *Catalog {
	return NewCatalog([]CatalogAction{
		{Connector: "pay", Action: "send", Verb: "pay.send", Reversibility: "reversible", BlastRadius: 0.3, AmountField: "amount", Resource: "acct:*"},
		{Connector: "pay", Action: "void", Verb: "pay.void", Reversibility: "irreversible", BlastRadius: 0.7, AmountField: "amount", Aliases: []string{"cancel"}},
		{Connector: "c", Action: "a", Verb: "c.a", Reversibility: "rate_limited", BlastRadius: 0.4, Aliases: []string{"z"}},
		{Connector: "", Action: "a", Verb: ".a", Reversibility: "reversible", BlastRadius: 0.1, Aliases: []string{"x"}},
		{Connector: "solo", Action: "solo", Verb: "solo", Reversibility: "reversible", BlastRadius: 0.1},
	})
}

func fcNum(t *testing.T, v any) float64 {
	t.Helper()
	f, ok := numOf(v)
	if !ok {
		t.Fatalf("not a JSON number: %#v", v)
	}
	return f
}

func fcZero(b []byte) bool { return len(b) > 0 && bytes.Equal(b, make([]byte, len(b))) }

func TestFacadeCatalogResolution(t *testing.T) {
	c := fcCatalog()
	if a, ok := c.Resolve("pay", "send"); !ok || a.Verb != "pay.send" {
		t.Fatalf("a catalogued verb resolves directly: %v %v", a.Verb, ok)
	}
	if a, ok := c.Resolve("pay", "cancel"); !ok || a.Verb != "pay.void" {
		t.Fatalf("alias: %v %v", a.Verb, ok)
	}
	if s := specFor(c, "solo"); s.Verb != "solo" || s.Reversibility != "reversible" || s.BlastRadius != 0.1 || s.Description != "" {
		t.Fatalf("a dot-less catalogued verb: %+v", s)
	}
	if s := specFor(c, "c.z"); s.Verb != "c.a" || s.Reversibility != "rate_limited" {
		t.Fatalf("an alias of a one-letter connector: %+v", s)
	}
	if s := specFor(DefaultCatalog(), "stripe.issue_refund"); s.Verb != "stripe.refund" {
		t.Fatalf("a built-in alias: %+v", s)
	}
	// a leading dot is no connector: never an alias lookup, as the reference (dot > 0)
	if s := specFor(c, ".x"); s.Connector != "" || s.Action != "x" || s.Verb != ".x" || s.Reversibility != "irreversible" || s.BlastRadius != 0.8 ||
		s.Description != "(uncatalogued) .x" || s.Aliases != nil {
		t.Fatalf("leading dot: %+v", s)
	}
	if s := specFor(c, "x.y.z"); s.Connector != "x" || s.Action != "y.z" || s.Reversibility != "irreversible" || s.BlastRadius != 0.8 {
		t.Fatalf("uncatalogued, two dots: %+v", s)
	}
	if s := specFor(c, "x."); s.Connector != "x" || s.Action != "x." {
		t.Fatalf("uncatalogued, empty action: %+v", s)
	}
}

func TestFacadeLimitPeriods(t *testing.T) {
	for ms, names := range map[int64][]string{
		1000: {"s", "sec", "second", "seconds"}, 60_000: {"m", "min", "minute", "minutes"}, 3_600_000: {"h", "hr", "hour", "hours"},
		86_400_000: {"d", "day", "days"}, 604_800_000: {"w", "week", "weeks"}, 2_592_000_000: {"mo", "month", "months"},
	} {
		for _, n := range names {
			for _, form := range []string{n, strings.ToUpper(n)} {
				if got, err := ParseLimit("$2/" + form); err != nil || got != (ParsedLimit{Amount: 2, Unit: "usd", PeriodMs: ms}) {
					t.Fatalf("$2/%s = %+v %v, want %d ms", form, got, err, ms)
				}
				if got, err := ParseLimit("7 / " + form); err != nil || got != (ParsedLimit{Amount: 7, Unit: "count", PeriodMs: ms}) {
					t.Fatalf("7 / %s = %+v %v", form, got, err)
				}
			}
		}
	}
	// the longest accepted amount (64 digits) is finite: the grammar never reaches the amount guard
	if got, err := ParseLimit(strings.Repeat("9", 64)); err != nil || got.Amount != 1e64 || got.Unit != "count" {
		t.Fatalf("64 nines: %+v %v", got, err)
	}
}

func TestFacadeLimitAmountGuard(t *testing.T) {
	for _, c := range []struct {
		in  float64
		err error
	}{{math.NaN(), nil}, {math.Inf(1), nil}, {math.Inf(-1), nil}, {-1, nil}, {-0.5, nil}, {3, errors.New("syntax")}} {
		got, err := limitAmount(c.in, c.err, "x")
		if got != 0 {
			t.Fatalf("limitAmount(%v, %v) = %v", c.in, c.err, got)
		}
		wantErr(t, err, "parseLimit: bad amount in 'x'")
	}
	for _, ok := range []float64{0, 0.5, 2.5, math.MaxFloat64} {
		if got, err := limitAmount(ok, nil, "x"); err != nil || got != ok {
			t.Fatalf("limitAmount(%v) = %v %v", ok, got, err)
		}
	}
}

func TestFacadeCompileCapsAndResources(t *testing.T) {
	weights := map[string]any{"alpha": 0, "beta": 0, "gamma": 1, "delta": 0, "epsilon": 0, "zeta": 0}
	// a $0 cap: kappa and bMax fall back to 1; nothing granted is irreversible, so within-cap actions auto-approve (theta 1, 1)
	pol, err := CompilePolicy(PolicyOptions{Permissions: map[string][]string{"pay": {"send"}}, Limits: map[string]string{"send": "$0"}, Catalog: fcCatalog(), Now: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(pol.Actions) != 1 || pol.Actions[0].Verb != "pay.send" || pol.Actions[0].Reversibility != "reversible" || pol.BudgetModel != "dollars" {
		t.Fatalf("the caller's catalog: %+v %s", pol.Actions, pol.BudgetModel)
	}
	assertSameJSON(t, "predicates", pol.Predicates, []any{map[string]any{"verb": "pay.send", "resource": "acct:*", "where": []any{
		map[string]any{"field": "action.params.amount", "op": "lte", "value": 0}, map[string]any{"field": "action.params.amount", "op": "gte", "value": 0}}}})
	assertSameJSON(t, "caveats", pol.Caveats, []any{map[string]any{"type": "reversibility_max", "class": "reversible"}})
	assertSameJSON(t, "risk policy $0", pol.RiskPolicy, map[string]any{"weights": weights, "theta1": 1, "theta2": 1, "kappa": 1, "lambda": 0, "rho": 0.5, "bMax": 1})
	// a cap below 1 is kept as is
	pol, err = CompilePolicy(PolicyOptions{Permissions: map[string][]string{"pay": {"send"}}, Limits: map[string]string{"pay.send": "$0.5"}, Catalog: fcCatalog(), Now: 1})
	if err != nil {
		t.Fatal(err)
	}
	assertSameJSON(t, "risk policy $0.5", pol.RiskPolicy, map[string]any{"weights": weights, "theta1": 1, "theta2": 1, "kappa": 0.5, "lambda": 0, "rho": 0.5, "bMax": 0.5})
	// an irreversible grant beside it keeps the default co-sign tiers
	pol, err = CompilePolicy(PolicyOptions{Permissions: map[string][]string{"pay": {"send", "cancel"}}, Limits: map[string]string{"send": "$4", "void": "$6"}, Catalog: fcCatalog(), Now: 1})
	if err != nil {
		t.Fatal(err)
	}
	assertSameJSON(t, "risk policy irreversible", pol.RiskPolicy, map[string]any{"weights": weights, "theta1": 0.25, "theta2": 0.6, "kappa": 6, "lambda": 0, "rho": 0.5, "bMax": 10})
	assertSameJSON(t, "caveats irreversible", pol.Caveats, []any{map[string]any{"type": "reversibility_max", "class": "irreversible"}})
}

func TestFacadeCompileWindowsAndRates(t *testing.T) {
	// Now 0 is the wall clock
	before := time.Now().UnixMilli()
	pol, err := CompilePolicy(PolicyOptions{Permissions: map[string][]string{"files": {"read"}}, Limits: map[string]string{"read": "1/day"}})
	after := time.Now().UnixMilli()
	if err != nil {
		t.Fatal(err)
	}
	if at := fcNum(t, pol.Caveats[1].(map[string]any)["at"]); at < float64(before+86_400_000) || at > float64(after+86_400_000) {
		t.Fatalf("expires at %v, want the wall clock plus a day (%d..%d)", at, before, after)
	}
	pol, err = CompilePolicy(PolicyOptions{Permissions: map[string][]string{"files": {"read"}}, Limits: map[string]string{"read": "1/s"}, Now: 1})
	if err != nil {
		t.Fatal(err)
	}
	assertSameJSON(t, "1/s", pol.Caveats, []any{map[string]any{"type": "reversibility_max", "class": "reversible"}, map[string]any{"type": "expires", "at": 1001},
		map[string]any{"type": "rate", "max": 1, "per_secs": 1}})
	// a count without a period is no rate
	pol, err = CompilePolicy(PolicyOptions{Permissions: map[string][]string{"files": {"read"}}, Limits: map[string]string{"read": "3"}, Now: 1})
	if err != nil {
		t.Fatal(err)
	}
	assertSameJSON(t, "3", pol.Caveats, []any{map[string]any{"type": "reversibility_max", "class": "reversible"}})
	if pol.Limits["files.read"] != (ParsedLimit{Amount: 3, Unit: "count"}) {
		t.Fatalf("limits: %+v", pol.Limits)
	}
	// the same verb granted twice (once by alias) is one limit and one rate caveat, as the reference's per-verb record
	pol, err = CompilePolicy(PolicyOptions{Permissions: map[string][]string{"c": {"a", "z"}}, Limits: map[string]string{"a": "10/hour"}, Catalog: fcCatalog(), Now: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(pol.Actions) != 2 || pol.Actions[1].Verb != "c.a" {
		t.Fatalf("actions: %+v", pol.Actions)
	}
	assertSameJSON(t, "twice", pol.Caveats, []any{map[string]any{"type": "reversibility_max", "class": "rate_limited"}, map[string]any{"type": "expires", "at": 1 + 3_600_000},
		map[string]any{"type": "rate", "max": 10, "per_secs": 3600}})
	// a sub-second period still gives a rate window of at least one second
	limitPeriods["ms"] = 1
	defer delete(limitPeriods, "ms")
	pol, err = CompilePolicy(PolicyOptions{Permissions: map[string][]string{"files": {"read"}}, Limits: map[string]string{"read": "5/ms"}, Now: 1})
	if err != nil {
		t.Fatal(err)
	}
	assertSameJSON(t, "5/ms", pol.Caveats, []any{map[string]any{"type": "reversibility_max", "class": "reversible"}, map[string]any{"type": "expires", "at": 2},
		map[string]any{"type": "rate", "max": 5, "per_secs": 1}})
}

func TestFacadeCompileRefusesNonJSON(t *testing.T) {
	_, err := CompilePolicy(PolicyOptions{Permissions: map[string][]string{"files": {"read"}}, RiskPolicy: map[string]any{"note": make(chan int)}, Now: 1})
	wantErr(t, err, "json: unsupported type: chan int")
	_, err = CompilePolicy(PolicyOptions{Permissions: map[string][]string{"files": {"\xff"}}, Now: 1})
	wantErr(t, err, "canonicalize: invalid UTF-8")
}

func TestFacadeRiskClaim(t *testing.T) {
	spec := CatalogAction{Verb: "pay.send", BlastRadius: 0.3, AmountField: "amount"}
	ag := func(model, kappa string) *FacadeAgent {
		return &FacadeAgent{Policy: &CompiledPolicy{BudgetModel: model, RiskPolicy: map[string]any{"kappa": json.Number(kappa)}}}
	}
	over := 1.5
	for i, c := range []struct {
		a      *FacadeAgent
		params map[string]any
		over   *float64
		want   float64
	}{
		{ag("risk", "1"), map[string]any{"amount": json.Number("100")}, nil, 0.3}, // the risk model ignores the amount
		{ag("dollars", "500"), map[string]any{"amount": json.Number("125")}, nil, 0.25},
		{ag("dollars", "500"), map[string]any{}, nil, 0.3},                          // no amount: Number(undefined) is NaN
		{ag("dollars", "500"), map[string]any{"amount": "abc"}, nil, 0.3},           // NaN
		{ag("dollars", "500"), map[string]any{"amount": "Infinity"}, nil, 0.3},      // not finite
		{ag("dollars", "500"), map[string]any{"amount": "-Infinity"}, nil, 0.3},     // not finite
		{ag("dollars", "500"), map[string]any{"amount": nil}, nil, 0},               // Number(null) is 0
		{ag("dollars", "500"), map[string]any{"amount": json.Number("-5")}, nil, 0}, // clamped
		{ag("dollars", "0.5"), map[string]any{"amount": json.Number("0.25")}, nil, 0.5},
		{ag("dollars", "0"), map[string]any{"amount": json.Number("5")}, nil, 0.3}, // kappa must be > 0
		{ag("dollars", "500"), map[string]any{"amount": json.Number("5")}, &over, 1},
	} {
		if got := c.a.riskFor(spec, c.params, c.over); got != c.want {
			t.Fatalf("case %d: riskFor = %v, want %v", i, got, c.want)
		}
	}
}

func TestFacadeJSToNumber(t *testing.T) {
	nan := math.NaN()
	for i, c := range []struct {
		in   any
		want float64
	}{
		{nil, 0}, {true, 1}, {false, 0}, {"12", 12}, {" ", 0}, {"abc", nan}, {[]any{}, 0}, {[]any{"7"}, 7}, {[]any{json.Number("3")}, 3},
		{[]any{json.Number("1"), json.Number("2")}, nan}, {map[string]any{}, nan}, {json.Number("5"), 5}, {math.Inf(1), math.Inf(1)},
		{int32(5), 5}, {map[string]string{}, nan},
	} {
		got := jsToNumber(c.in)
		if !(got == c.want || math.IsNaN(got) && math.IsNaN(c.want)) {
			t.Fatalf("case %d: jsToNumber(%#v) = %v, want %v", i, c.in, got, c.want)
		}
	}
}

func TestFacadeCreateAgentDefaults(t *testing.T) {
	principal := mustKey(t)
	ag, err := CreateAgent(AgentOptions{Principal: principal, Goal: "g", Permissions: map[string][]string{"pay": {"send"}}, Catalog: fcCatalog(), Aud: "rs", Now: 1,
		Provenance: &ProvenanceRecorderOptions{Mediator: "m2", Kid: "k9"}, AgentBinding: map[string]any{"model": "m"}})
	if err != nil {
		t.Fatal(err)
	}
	if ag.Budget.Tau != 1 || ag.Budget.AsOf != 1 || ag.Provenance.Pin.Mediator != "m2" || ag.Provenance.Pin.Kid != "k9" {
		t.Fatalf("agent: %+v %+v", ag.Budget, ag.Provenance.Pin)
	}
	env := ag.Grant["caveats"].([]any)[0].(map[string]any)
	assertSameJSON(t, "agent binding", env["agent_binding"], map[string]any{"model": "m"})
	r, err := ag.Act("pay.send", "acct:1", map[string]any{"amount": 1}, &ActOptions{Now: 1})
	if err != nil {
		t.Fatal(err)
	}
	if r.PCActn["action"].(map[string]any)["reversibility_class"] != "reversible" {
		t.Fatalf("the agent acts under the caller's catalog: %v", r.PCActn["action"])
	}
	// Now 0 is the wall clock; no binding is the empty one
	before := time.Now().UnixMilli()
	ag, err = CreateAgent(AgentOptions{Principal: principal, Goal: "g", Permissions: map[string][]string{"files": {"read"}}})
	after := time.Now().UnixMilli()
	if err != nil {
		t.Fatal(err)
	}
	if ag.Budget.Tau < float64(before) || ag.Budget.Tau > float64(after) || ag.Budget.AsOf != ag.Budget.Tau {
		t.Fatalf("budget clock %v, want %d..%d", ag.Budget.Tau, before, after)
	}
	assertSameJSON(t, "empty binding", ag.Grant["caveats"].([]any)[0].(map[string]any)["agent_binding"], map[string]any{})
	if ag.Provenance.Pin.Mediator != "agent-harness" || ag.Provenance.Pin.Kid != "k1" {
		t.Fatalf("default recorder: %+v", ag.Provenance.Pin)
	}

	_, err = CreateAgent(AgentOptions{Principal: principal, Goal: "g", Now: 1})
	wantErr(t, err, "compilePolicy: no permissions granted")
	_, err = CreateAgent(AgentOptions{Principal: principal, Permissions: map[string][]string{"files": {"read"}}, Now: 1})
	wantErr(t, err, "MintGrant: goal required")
	_, err = CreateAgent(AgentOptions{Principal: principal, Goal: "g", Permissions: map[string][]string{"files": {"read"}}, Now: 1,
		Provenance: &ProvenanceRecorderOptions{Session: "short"}})
	wantErr(t, err, "NewProvenanceRecorder: session must be canonical base64url of 32 bytes")
}

func TestFacadeActOptions(t *testing.T) {
	mk := func() *FacadeAgent {
		ag, err := CreateAgent(AgentOptions{Principal: mustKey(t), Goal: "g", Permissions: map[string][]string{"files": {"read"}}, Aud: "rs-test", Now: 1})
		if err != nil {
			t.Fatal(err)
		}
		return ag
	}
	ag := mk()
	caution := 0.3
	r, err := ag.Act("files.read", "f", nil, &ActOptions{Aud: "rs-other", Now: 1, Caution: &caution})
	if err != nil {
		t.Fatal(err)
	}
	empty, _ := ParamsDigest(nil)
	if r.PCActn["aud"] != "rs-other" || prodInt(t, r.PCActn["iat"]) != 1 || fcNum(t, r.PCActn["caution"]) != 0.3 ||
		r.PCActn["action"].(map[string]any)["params_digest"] != empty {
		t.Fatalf("options: %v", r.PCActn)
	}
	// params no action can carry are refused before anything is counted or recorded
	bad := map[string]any{"x": math.NaN()}
	_, want := ParamsDigest(bad)
	if want == nil {
		t.Fatal("a NaN param digested")
	}
	ag = mk()
	_, err = ag.Act("files.read", "f", bad, &ActOptions{Now: 1})
	wantErr(t, err, want.Error())
	if n := len(ag.Provenance.Receipts()); n != 0 {
		t.Fatalf("a refused action left %d receipts", n)
	}
	if r, err = ag.Act("files.read", "f", nil, &ActOptions{Now: 1}); err != nil || prodInt(t, r.PCActn["counter"]) != 1 {
		t.Fatalf("the refused action took a counter: %v", err)
	}
	// the signer's refusal and the recorder's refusal are returned
	_, err = (&FacadeAgent{Grant: ag.Grant, Chain: ag.Chain, Policy: ag.Policy, catalog: ag.catalog, aud: "rs-test", Provenance: ag.Provenance}).Act("files.read", "f", nil, &ActOptions{Now: 1})
	wantErr(t, err, "BuildPCActn: signer required")
	ag = mk()
	for i := 0; i < MaxProvReceipts; i++ {
		if _, err := ag.Provenance.Tool("t", "x"); err != nil {
			t.Fatal(err)
		}
	}
	r, err = ag.Act("files.read", "f", nil, &ActOptions{Now: 1})
	if r != nil {
		t.Fatal("an action without a provenance bundle was returned")
	}
	wantErr(t, err, "provenance: the session holds 256 receipts; start a new session with the principal's message")
}

func TestFacadeDryRunEdges(t *testing.T) {
	ag, err := CreateAgent(AgentOptions{Principal: mustKey(t), Goal: "g", Permissions: map[string][]string{"pay": {"send"}, "c": {"a"}}, Limits: map[string]string{"send": "$10/s"},
		Catalog: fcCatalog(), Aud: "rs", Now: 1})
	if err != nil {
		t.Fatal(err)
	}
	if dr := ag.DryRun("pay.send", "acct:1", map[string]any{"amount": 5}, 1); dr != (DryRunResult{Allowed: true, T: 1}) {
		t.Fatalf("within the cap: %+v", dr)
	}
	if dr := ag.DryRun("c.a", "r", nil, 1); dr != (DryRunResult{Allowed: true, T: 1}) {
		t.Fatalf("no params: %+v", dr)
	}
	// now 0 is the wall clock, long after the one-second window
	if dr := ag.DryRun("pay.send", "acct:1", map[string]any{"amount": 5}, 0); dr != (DryRunResult{Reason: "caveat(s) failed: expires"}) {
		t.Fatalf("wall clock: %+v", dr)
	}
	bad := map[string]any{"amount": 5, "memo": math.NaN()}
	_, e := normObj(bad)
	if e == nil {
		t.Fatal("a NaN param normalized")
	}
	if dr := ag.DryRun("pay.send", "acct:1", bad, 1); dr != (DryRunResult{Reason: "params are not JSON: " + e.Error()}) {
		t.Fatalf("non-JSON params: %+v", dr)
	}
	// the delegation depth the caveats see: 0 at the root, one more per hop
	pol := *ag.Policy
	pol.Caveats = append(append([]any{}, ag.Policy.Caveats...), map[string]any{"type": "delegation_depth", "max": json.Number("0")})
	ag.Policy = &pol
	if dr := ag.DryRun("c.a", "r", nil, 1); !dr.Allowed {
		t.Fatalf("depth 0: %+v", dr)
	}
	sub, err := ag.SubAgent(SubAgentOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if dr := sub.DryRun("c.a", "r", nil, 1); dr != (DryRunResult{Reason: "caveat(s) failed: delegation_depth"}) {
		t.Fatalf("depth 1: %+v", dr)
	}
}

func TestFacadeProvenanceHeaderCap(t *testing.T) {
	mk := func(text string) (*ActResult, string) {
		ag, err := CreateAgent(AgentOptions{Principal: mustKey(t), Goal: "g", Permissions: map[string][]string{"files": {"read"}}, Aud: "rs", Now: 5,
			Provenance: &ProvenanceRecorderOptions{Now: func() int64 { return 5 }}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ag.Provenance.Principal(text); err != nil {
			t.Fatal(err)
		}
		r, err := ag.Act("files.read", "f", nil, &ActOptions{Now: 5})
		if err != nil {
			t.Fatal(err)
		}
		c, err := Canonicalize(r.Provenance)
		if err != nil {
			t.Fatal(err)
		}
		return r, c
	}
	// every byte of an ASCII principal message is one byte of the bundle: size it to exactly 6144 bytes, 8192 base64url
	_, c := mk("a")
	fit := strings.Repeat("a", 1+6144-len(c))
	r, c := mk(fit)
	if len(c) != 6144 {
		t.Fatalf("bundle is %d bytes", len(c))
	}
	if v := r.Headers[ProvenanceHeader]; len(v) != 8192 || v != b64.EncodeToString([]byte(c)) {
		t.Fatalf("an 8192-character bundle is sent as a header (got %d characters)", len(v))
	}
	r, c = mk(fit + "a")
	if v, has := r.Headers[ProvenanceHeader]; has || len(c) != 6145 {
		t.Fatalf("an 8194-character bundle went in a header (%d)", len(v))
	}
	if r.Headers[PCAHeader] == "" || r.Provenance == nil {
		t.Fatal("the action header and the bundle stay")
	}
}

type fcBadReader struct{ err error }

func (r fcBadReader) Read([]byte) (int, error) { return 0, r.err }

type fcCaptureReader struct{ bufs [][]byte }

func (r *fcCaptureReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0x5a
	}
	r.bufs = append(r.bufs, p)
	return len(p), nil
}

func TestFacadeSubAgentRefusals(t *testing.T) {
	pq, err := GeneratePqKeyPair("ML-DSA-65")
	if err != nil {
		t.Fatal(err)
	}
	ag, err := CreateAgent(AgentOptions{Principal: mustKey(t), Goal: "g", Permissions: map[string][]string{"files": {"read"}}, Aud: "rs", Now: 1,
		Suite: &SuiteOpts{Alg: "hybrid-ed25519-ml-dsa-65", Pq: pq}})
	if err != nil {
		t.Fatal(err)
	}
	holder := mustKey(t)
	rngDown := errors.New("rng down")
	old := rand.Reader
	rand.Reader = fcBadReader{rngDown}
	sub, err := ag.SubAgent(SubAgentOptions{Holder: holder})
	rand.Reader = old
	if sub != nil || !errors.Is(err, rngDown) {
		t.Fatalf("a failed sub-agent keygen: %v %v", sub, err)
	}
	bad := []any{math.NaN()}
	_, want := normList(bad)
	if want == nil {
		t.Fatal("a NaN caveat normalized")
	}
	sub, err = ag.SubAgent(SubAgentOptions{Holder: holder, AddedCaveats: bad})
	if sub != nil {
		t.Fatal("a sub-agent without a hop")
	}
	wantErr(t, err, want.Error())
}

func TestFacadeKeygenClearsSeeds(t *testing.T) {
	// the drawn seed is cleared when GeneratePqKeyPair returns
	cr := &fcCaptureReader{}
	old := rand.Reader
	rand.Reader = cr
	kp, err := GeneratePqKeyPair("ML-DSA-65")
	rand.Reader = old
	if err != nil {
		t.Fatal(err)
	}
	want, _ := GeneratePqKeyPairFromSeed("ML-DSA-65", bytes.Repeat([]byte{0x5a}, 32))
	if kp.Public != want.Public || len(cr.bufs) != 1 || len(cr.bufs[0]) != 32 || !fcZero(cr.bufs[0]) {
		t.Fatalf("the drawn seed: %d reads, cleared %v", len(cr.bufs), len(cr.bufs) == 1 && fcZero(cr.bufs[0]))
	}
	// the transient ML-DSA seed copy is cleared; the caller's seed is not
	var seen, atSeam []byte
	oldSeam := pqSeedSeam
	pqSeedSeam = func(b []byte) { seen, atSeam = b, append([]byte(nil), b...) }
	defer func() { pqSeedSeam = oldSeam }()
	for _, fam := range []string{"ML-DSA-65", "ML-DSA-87"} {
		seen, atSeam = nil, nil
		seed := bytes.Repeat([]byte{7}, 32)
		if _, err := GeneratePqKeyPairFromSeed(fam, seed); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(atSeam, seed) || len(seen) != 32 || !fcZero(seen) || !bytes.Equal(seed, bytes.Repeat([]byte{7}, 32)) {
			t.Fatalf("%s: the seed copy was not cleared (seen %x)", fam, seen)
		}
	}
	// an SLH-DSA keygen failure is returned
	oldGen := slhGenerateKey
	short := errors.New("short read")
	slhGenerateKey = func(io.Reader, slhdsa.ID) (slhdsa.PublicKey, slhdsa.PrivateKey, error) {
		return slhdsa.PublicKey{}, slhdsa.PrivateKey{}, short
	}
	defer func() { slhGenerateKey = oldGen }()
	for fam, n := range map[string]int{"SLH-DSA-SHA2-128f": 48, "SLH-DSA-SHA2-256s": 96} {
		if kp, err := GeneratePqKeyPairFromSeed(fam, make([]byte, n)); kp != nil || err != short {
			t.Fatalf("%s: %v %v", fam, kp, err)
		}
	}
}

func TestFacadeRevocationEpochSuites(t *testing.T) {
	seed := bytes.Repeat([]byte{0x11}, 32)
	body := RevocationEpochBody{InstanceID: "i", GrantRef: "g", Epoch: 1, Root: "r", IssuedAt: 1, NotAfter: 2}
	_, err := SignRevocationEpoch(seed, body, nil, nil)
	wantErr(t, err, "SignRevocationEpoch: at most one suite")
	out, err := SignRevocationEpoch(seed, body, &SuiteOpts{Alg: "ml-dsa-65"})
	if out != nil {
		t.Fatal("an unsigned epoch was returned")
	}
	wantErr(t, err, "ml-dsa-65 needs a post-quantum key pair")

	var g *KeyPair
	oldSeam := guardianKeySeam
	guardianKeySeam = func(k *KeyPair) { g = k }
	defer func() { guardianKeySeam = oldSeam }()
	pq, err := GeneratePqKeyPair("ML-DSA-65")
	if err != nil {
		t.Fatal(err)
	}
	out, err = SignRevocationEpoch(seed, body, &SuiteOpts{Alg: "hybrid-ed25519-ml-dsa-65", Pq: pq})
	if err != nil {
		t.Fatal(err)
	}
	want, _ := KeyPairFromSeed(seed)
	if g == nil || out["guardian"] != want.Public || g.Public != want.Public || out["pq_sig"] == nil {
		t.Fatalf("hybrid epoch: %v", out)
	}
	if len(g.priv) != 64 || !fcZero(g.priv) {
		t.Fatal("the transient guardian key was not cleared")
	}
	if !bytes.Equal(seed, bytes.Repeat([]byte{0x11}, 32)) {
		t.Fatal("the caller's seed was changed")
	}
}

func TestFacadeSignersRefuseAnUnsignableSuite(t *testing.T) {
	k := mustKey(t)
	s := &SuiteOpts{Alg: "ml-dsa-65"}
	const msg = "ml-dsa-65 needs a post-quantum key pair"
	a, err := SignEscalationAnswer(k, map[string]any{"policy_digest": "p", "action_digest": "a", "history_head": "h"}, "allow", 1, 2, "", s)
	if a != nil {
		t.Fatal("escalation answer")
	}
	wantErr(t, err, msg)
	d, err := SignDischarge(k, DischargeInput{CaveatID: "c", IssuerLabel: "i", CapHash: "h", Claims: map[string]any{}, Iat: 1, NotAfter: 2}, s)
	if d != nil {
		t.Fatal("discharge")
	}
	wantErr(t, err, msg)
	n, err := SignNarrow(k, "h", []any{}, 1, 2, "", "", s)
	if n != nil {
		t.Fatal("narrow")
	}
	wantErr(t, err, msg)
}

func TestFacadeMintGrantKeepsValidPins(t *testing.T) {
	root, err := HashCanonical("pack")
	if err != nil {
		t.Fatal(err)
	}
	tr := map[string]any{"template_id": "tpl", "version_digest": "v1", "slots": map[string]any{}}
	ac := map[string]any{"pack": map[string]any{"ns": "acme", "root": root}, "on_new_action": "deny"}
	env := map[string]any{"predicates": []any{}, "caveats": []any{}, "risk_policy": DefaultRiskPolicy(), "template_ref": tr, "actions": ac}
	r, err := MintGrant(mustKey(t), "h", env, "goal", "salt", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	e := r.Grant["caveats"].([]any)[0].(map[string]any)
	assertSameJSON(t, "template_ref", e["template_ref"], tr)
	assertSameJSON(t, "actions", e["actions"], ac)
}

func TestFacadeDelegatePqRefusesAKeyOutsideTheSuite(t *testing.T) {
	principal, holder := mustKey(t), mustKey(t)
	r, err := MintGrant(principal, holder.Public, map[string]any{"predicates": []any{}, "caveats": []any{}, "risk_policy": DefaultRiskPolicy()}, "goal", "salt", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	a := &Agent{Key: holder, Grant: r.Grant, Chain: []map[string]any{r.Grant}, Aud: "rs"}
	// a zero PqKeyPair names no primitive: an Ed25519 agent has no PQ suite to hand down, whatever the key
	sub, err := a.DelegatePq(mustKey(t), &PqKeyPair{Public: "x"}, nil)
	if sub != nil {
		t.Fatal("delegated")
	}
	wantErr(t, err, "DelegatePq: the sub-agent's PQ key does not match the suite ed25519")
}
