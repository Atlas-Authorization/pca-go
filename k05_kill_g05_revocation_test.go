package pca

import (
	"bytes"
	"encoding/json"
	"math"
	"testing"
)

// g05: revocation_staleness.go and the denial-reason helpers of predicates.go: window validation bound, the rate_limited
// alias, unknown issue times, the epoch shape guard, the age cap followed by the rollback check, the gate with no root,
// and the "no state" wording by class.

func g05F(f float64) *float64 { return &f }

func g05RevWant(t *testing.T, label string, r RevocationAgeResult, ok bool, reason string) {
	t.Helper()
	if r.OK != ok || r.Reason != reason {
		t.Fatalf("%s: got %+v, want ok=%v %q", label, r, ok, reason)
	}
}

func TestG05RevocationPolicyParsing(t *testing.T) {
	if err := (RevocationStalenessPolicy{MaxRevocationAgeMs: g05F(1)}).Validate(); err != nil {
		t.Fatalf("1 ms is a positive window: %v", err)
	}
	if err := (RevocationStalenessPolicy{MaxRevocationAgeMs: g05F(0.5)}).Validate(); err != nil {
		t.Fatalf("0.5 ms is a positive window: %v", err)
	}
	if err := (RevocationStalenessPolicy{MaxRevocationAgeMs: g05F(0)}).Validate(); err == nil {
		t.Fatal("0 ms validated")
	}
	p := RevocationStalenessPolicyFromJSON(map[string]any{"staleness": map[string]any{"rate_limited": json.Number("5")}})
	if p.Staleness == nil || p.Staleness.Costly == nil || *p.Staleness.Costly != 5 {
		t.Fatalf("rate_limited not read: %+v", p.Staleness)
	}
	p = RevocationStalenessPolicyFromJSON(map[string]any{"staleness": map[string]any{"costly": json.Number("7")}})
	if p.Staleness == nil || p.Staleness.Costly == nil || *p.Staleness.Costly != 7 {
		t.Fatalf("costly not read: %+v", p.Staleness)
	}
}

func TestG05RevocationAgeUnknown(t *testing.T) {
	const unknown = "revocation state age is unknown (unverifiable revocation state)"
	g05RevWant(t, "nil", CheckRevocationAge(nil, 0, 1000, ""), false, unknown)
	g05RevWant(t, "NaN", CheckRevocationAge(g05F(math.NaN()), 0, 1000, ""), false, unknown)
	g05RevWant(t, "-Inf", CheckRevocationAge(g05F(math.Inf(-1)), 0, 1000, ""), false, unknown)
	g05RevWant(t, "+Inf", CheckRevocationAge(g05F(math.Inf(1)), 0, 1000, ""), false, unknown)
	g05RevWant(t, "fresh", CheckRevocationAge(g05F(0), 0, 1000, ""), true, "")
}

func g05Epoch(t *testing.T, seed []byte) map[string]any {
	t.Helper()
	ep, err := SignRevocationEpoch(seed, RevocationEpochBody{InstanceID: "ins", GrantRef: "g", Epoch: 5, SetSize: 2, Root: "root", IssuedAt: 1000, NotAfter: 100_000})
	if err != nil {
		t.Fatal(err)
	}
	return ep
}

func TestG05RevocationEpochChecks(t *testing.T) {
	seed := bytes.Repeat([]byte{0x71}, 32)
	ep := g05Epoch(t, seed)
	g := ep["guardian"].(string)
	base := func() EpochCheckOptions { return EpochCheckOptions{GuardianPublic: g, Now: 2000} }
	g05RevWant(t, "valid", CheckRevocationEpoch(ep, base()), true, "")

	noEpoch := copyMap(ep)
	delete(noEpoch, "epoch")
	g05RevWant(t, "no epoch", CheckRevocationEpoch(noEpoch, base()), false, "malformed revocation epoch")

	// within the age cap, the rollback check still runs
	o := base()
	o.MaxAgeMs = g05F(10_000)
	o.LastAcceptedEpoch = g05F(6)
	g05RevWant(t, "rollback", CheckRevocationEpoch(ep, o), false, "revocation epoch 5 is older than the last accepted 6 (rollback)")
	o.LastAcceptedEpoch = g05F(5)
	g05RevWant(t, "same epoch", CheckRevocationEpoch(ep, o), true, "")

	if out, err := SignRevocationEpoch(seed, RevocationEpochBody{InstanceID: "\xed\xa0\x80", GrantRef: "g", Root: "r"}); err == nil || out != nil {
		t.Fatalf("an uncanonicalizable epoch was signed: %v %v", out, err)
	}
}

func TestG05RevocationGateNoRoot(t *testing.T) {
	if r := RevocationGate(RevocationGateInput{}); r.OK || r.Reason != "no revocation root" {
		t.Fatalf("got %+v", r)
	}
	if r := RevocationGate(RevocationGateInput{Root: "r"}); !r.OK || r.Root != "r" {
		t.Fatalf("got %+v", r)
	}
}

func TestG05RevocationFreshnessNoState(t *testing.T) {
	in := AuthorizeInput{Risk: InsecureCalmRisk, RevocationStaleness: &RevocationStalenessPolicy{}}
	rev := map[string]any{"action": map[string]any{"reversibility_class": "reversible"}}
	if got := revocationFreshness(in, &AuthorizeContext{ReversibilityClass: "reversible"}, rev, nil, 0); got != "no signed revocation epoch" {
		t.Fatalf("reversible: %q", got)
	}
	irr := map[string]any{"action": map[string]any{"reversibility_class": "irreversible"}}
	if got := revocationFreshness(in, &AuthorizeContext{}, irr, nil, 0); got != "no verifiable (guardian-signed) revocation state for an irreversible action" {
		t.Fatalf("irreversible: %q", got)
	}
	in.RevocationStaleness = &RevocationStalenessPolicy{AllowUnsignedRootForIrreversible: true}
	if got := revocationFreshness(in, &AuthorizeContext{}, irr, nil, 0); got != "no signed revocation epoch" {
		t.Fatalf("irreversible, unsigned allowed: %q", got)
	}
}

func TestG05PredicatesShowValue(t *testing.T) {
	for _, c := range []struct {
		v    any
		want string
	}{
		{false, "false"}, {true, "true"}, {" ", `" "`}, {"\x1f", `"..."`}, {"!", `"!"`},
		{"￿", "\"￿\""}, {"\U00010000", `"..."`},
	} {
		if got := showValue(c.v, 0); got != c.want {
			t.Fatalf("showValue(%q) = %q, want %q", c.v, got, c.want)
		}
	}
}

func TestG05PredicatesFirstUnmetNeedsVerbAndResource(t *testing.T) {
	preds := []any{map[string]any{"verb": "x", "where": []any{map[string]any{"field": "action.params.amount", "op": "lte", "value": json.Number("5")}}}}
	for _, a := range []map[string]any{{"verb": "x"}, {"resource": "r"}} {
		if s, ok := firstUnmetLimit(preds, map[string]any{"action": a}, &regexBudget{}); ok || s != "" {
			t.Fatalf("action %v: got %q %v", a, s, ok)
		}
	}
	ctx := map[string]any{"action": map[string]any{"verb": "x", "resource": "r", "params": map[string]any{"amount": json.Number("10")}}}
	if s, ok := firstUnmetLimit(preds, ctx, &regexBudget{}); !ok || s != "amount <= 5" {
		t.Fatalf("got %q %v", s, ok)
	}
}
