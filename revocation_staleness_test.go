package pca

import (
	"bytes"
	"math"
	"strings"
	"testing"
)

// Revocation staleness (T9): replays staleness-vectors.json (max_age, effective_reversibility, age, epoch, gate), then
// the Authorize wiring. A missing vector file fails the test.

func stalenessDoc(t *testing.T) map[string]any {
	t.Helper()
	return load(t, "staleness-vectors.json")
}

func fptr(v any) *float64 {
	f, ok := jsNum(v)
	if !ok {
		return nil
	}
	return &f
}

// vecMs reads a vector number; the string "NaN" stands for NaN.
func vecMs(v any) float64 {
	if s, ok := v.(string); ok && s == "NaN" {
		return math.NaN()
	}
	f, _ := jsNum(v)
	return f
}

func wantResult(t *testing.T, label string, got RevocationAgeResult, v map[string]any) {
	t.Helper()
	exp := v["result"].(map[string]any)
	if got.OK != exp["ok"].(bool) {
		t.Errorf("%s: ok=%v (%q) want %v", label, got.OK, got.Reason, exp["ok"])
		return
	}
	if _, loose := v["ok_only"]; loose || got.OK {
		return
	}
	if got.Reason != exp["reason"] {
		t.Errorf("%s: reason %q want %q", label, got.Reason, exp["reason"])
	}
}

func TestStalenessConstants(t *testing.T) {
	c := stalenessDoc(t)["constants"].(map[string]any)
	if num(c["refresh_ms"]) != RevocationEpochRefreshMs || num(c["validity_ms"]) != RevocationEpochValidityMs ||
		num(c["irreversible_max_age_ms"]) != RevocationIrreversibleMaxAgeMs || num(c["skew_ms"]) != revSkewMs {
		t.Fatalf("constants differ from the corpus: %v", c)
	}
}

func TestStalenessMaxAgeVectors(t *testing.T) {
	rs := grows(t, stalenessDoc(t), "max_age")
	if len(rs) != 15 {
		t.Fatalf("max_age rows %d", len(rs))
	}
	for _, v := range rs {
		p := RevocationStalenessPolicyFromJSON(v["policy"])
		if got := RevocationMaxAgeMs(p, v["class"].(string)); got != vecMs(v["max_age_ms"]) {
			t.Errorf("%v/%v: %v want %v", v["policy"], v["class"], got, v["max_age_ms"])
		}
	}
}

func TestStalenessEffectiveReversibilityVectors(t *testing.T) {
	rs := grows(t, stalenessDoc(t), "effective_reversibility")
	if len(rs) != 14 {
		t.Fatalf("effective_reversibility rows %d", len(rs))
	}
	for _, v := range rs {
		server, _ := v["server_class"].(string)
		if got := EffectiveReversibility(server, v["signed_class"]); got != v["effective"] {
			t.Errorf("%v/%v: %s want %v", v["server_class"], v["signed_class"], got, v["effective"])
		}
	}
}

func TestStalenessAgeVectors(t *testing.T) {
	rs := grows(t, stalenessDoc(t), "age")
	if len(rs) != 13 {
		t.Fatalf("age rows %d", len(rs))
	}
	for i, v := range rs {
		what, _ := v["what"].(string)
		var issued *float64
		if _, isStr := v["issued_at"].(string); !isStr { // null, "NaN" and "x" are all an unknown age
			issued = fptr(v["issued_at"])
		}
		wantResult(t, "age#"+string(rune('a'+i)), CheckRevocationAge(issued, vecMs(v["now"]), vecMs(v["max_age_ms"]), what), v)
	}
}

func TestStalenessEpochVectors(t *testing.T) {
	doc := stalenessDoc(t)
	rs := grows(t, doc, "epoch")
	if len(rs) != 25 {
		t.Fatalf("epoch rows %d", len(rs))
	}
	for _, v := range rs {
		o := EpochCheckOptions{GuardianPublic: v["guardian_public"].(string), Now: vecMs(v["now"])}
		if g, ok := v["grant_ref"].(string); ok {
			o.GrantRef = &g
		}
		if x, has := v["last_accepted_epoch"]; has {
			o.LastAcceptedEpoch = fptr(x)
		}
		if x, has := v["pcactn_epoch"]; has {
			o.PCActnEpoch = fptr(x)
		}
		if x, has := v["max_age_ms"]; has {
			m := vecMs(x)
			o.MaxAgeMs = &m
		}
		wantResult(t, "epoch/"+v["name"].(string), CheckRevocationEpoch(v["epoch"], o), v)
	}
}

func TestStalenessGateVectors(t *testing.T) {
	doc := stalenessDoc(t)
	guardian := doc["guardian_public"].(string)
	rs := grows(t, doc, "gate")
	if len(rs) != 28 {
		t.Fatalf("gate rows %d", len(rs))
	}
	for _, v := range rs {
		in := RevocationGateInput{Policy: RevocationStalenessPolicyFromJSON(v["policy"]), GuardianPublic: guardian,
			GrantRef: "g1", Now: vecMs(v["now"])}
		in.PCActnEpoch = fptr(0)
		in.Policy.AllowUnsignedRootForIrreversible, _ = v["allow_unsigned_root_for_irreversible"].(bool)
		in.ServerClass, _ = v["server_class"].(string)
		if sc, has := v["signed_class"]; has {
			in.SignedClass = sc
		}
		switch v["mode"] {
		case "epoch":
			in.EpochSource, in.Epoch = true, v["epoch"]
			in.Root, _ = v["bare_root"].(string)
		case "root":
			in.Root = doc["revocation_root"].(string)
			in.RootIssuedAt = fptr(v["root_issued_at"])
		case "none":
			in.EpochSource = true
		default:
			t.Fatalf("mode %v", v["mode"])
		}
		r := RevocationGate(in)
		wantResult(t, "gate/"+v["name"].(string), RevocationAgeResult{OK: r.OK, Reason: r.Reason}, v)
	}
}

func TestStalenessInvalidPolicyRefused(t *testing.T) {
	for name, p := range map[string]RevocationStalenessPolicy{
		"zero":       {MaxRevocationAgeMs: fptr(float64(0))},
		"negative":   {Staleness: &StalenessWindows{Irreversible: fptr(float64(-1))}},
		"nan":        {Staleness: &StalenessWindows{Costly: fptr(math.NaN())}},
		"infinite":   {MaxRevocationAgeMs: fptr(math.Inf(1))},
		"not-number": RevocationStalenessPolicyFromJSON(map[string]any{"maxRevocationAgeMs": "300000"}),
	} {
		if p.Validate() == nil {
			t.Errorf("%s accepted", name)
		}
		if r := RevocationGate(RevocationGateInput{Policy: p, Now: 1, Root: "r", RootIssuedAt: fptr(1), SignedClass: "reversible"}); r.OK {
			t.Errorf("%s: the gate opened under an invalid policy", name)
		}
	}
	if (RevocationStalenessPolicy{}).On() {
		t.Error("the zero policy must be off")
	}
}

// A post-quantum epoch needs a pin for the guardian; no pin (or a different one) refuses it, and an unregistered suite is
// refused as not signed by the pinned guardian.
func TestStalenessEpochSuitesUnderPins(t *testing.T) {
	seed := bytes.Repeat([]byte{11}, 32)
	ep, err := SignRevocationEpoch(seed, RevocationEpochBody{InstanceID: "i", GrantRef: "g1", Root: "r", IssuedAt: 1000, NotAfter: 2000})
	if err != nil {
		t.Fatal(err)
	}
	o := EpochCheckOptions{GuardianPublic: ep["guardian"].(string), Now: 1500}
	if r := CheckRevocationEpoch(ep, o); !r.OK {
		t.Fatalf("signed epoch refused: %s", r.Reason)
	}
	mut := func(k string, v any) map[string]any {
		m := map[string]any{}
		for a, b := range ep {
			m[a] = b
		}
		m[k] = v
		return m
	}
	if r := CheckRevocationEpoch(mut("root", "other"), o); r.OK || r.Reason != "revocation epoch signature invalid" {
		t.Errorf("tampered root: %+v", r)
	}
	if r := CheckRevocationEpoch(mut("alg", "ml-dsa-65"), o); r.OK {
		t.Errorf("a PQ suite without a pin must be refused: %+v", r)
	}
	if r := CheckRevocationEpoch(mut("alg", "ml-dsa-65"), EpochCheckOptions{GuardianPublic: o.GuardianPublic, Now: 1500, Pins: map[string]string{o.GuardianPublic: "AAAA"}}); r.OK {
		t.Errorf("a PQ suite whose pq_pk is not the pinned key must be refused: %+v", r)
	}
	if r := CheckRevocationEpoch(mut("alg", "no-such-suite"), o); r.OK || r.Reason != "revocation epoch not signed by the pinned guardian" {
		t.Errorf("unregistered suite: %+v", r)
	}
	if _, err := SignRevocationEpoch([]byte{1}, RevocationEpochBody{}); err == nil {
		t.Error("a short seed must be refused")
	}
}

// ---- Authorize wiring

func stalenessAuthorize(t *testing.T, policy *RevocationStalenessPolicy, state func(ageMs int64, root string) *RevocationState, ageMs int64) AuthorizeResult {
	t.Helper()
	return stalenessAuthorizeWith(t, policy, state, ageMs, nil)
}

func stalenessAuthorizeWith(t *testing.T, policy *RevocationStalenessPolicy, state func(ageMs int64, root string) *RevocationState, ageMs int64, mod func(*AuthorizeInput)) AuthorizeResult {
	t.Helper()
	d := authorizeFixtures(t)
	c := d["cases"].([]any)[0].(map[string]any) // signed class irreversible
	s := c["steps"].([]any)[0].(map[string]any)
	revoked := false
	in := fixInput(d, c["grant"].(map[string]any), NewMemoryStateStore(), &revoked)
	in.Operation = fixOp(s["operation"].(map[string]any))
	in.RevocationStaleness = policy
	in.RevocationIds = func(map[string]any) []string { return nil } // freshness-only tests opt out of the per-capability proofs
	if mod != nil {
		mod(&in)
	}
	grantRef := s["pcactn"].(map[string]any)["grant_ref"].(string)
	seed := bytes.Repeat([]byte{11}, 32)
	probe, _ := SignRevocationEpoch(seed, RevocationEpochBody{})
	in.GuardianPublic = probe["guardian"].(string)
	if state != nil {
		in.RevocationState = func(_, _ map[string]any) (*RevocationState, error) {
			st := state(ageMs, "root")
			if st != nil && st.Epoch == nil && st.Root == "" {
				st = nil
			}
			if st != nil && st.Epoch != nil {
				ep, _ := SignRevocationEpoch(seed, RevocationEpochBody{InstanceID: "i", GrantRef: grantRef, Root: "root", IssuedAt: in.Now - ageMs, NotAfter: in.Now + 600000})
				st.Epoch = ep
			}
			return st, nil
		}
	}
	return Authorize(s["pcactn"], in)
}

func TestAuthorizeRevocationStalenessIrreversible(t *testing.T) {
	on := &RevocationStalenessPolicy{MaxRevocationAgeMs: fptr(300000.0)}
	epoch := func(int64, string) *RevocationState { return &RevocationState{Epoch: map[string]any{}} }
	if r := stalenessAuthorize(t, on, epoch, 30_000); !r.Allow || r.Checks["freshness"] != "pass" {
		t.Fatalf("a fresh signed epoch must allow: %+v", r)
	}
	if r := stalenessAuthorize(t, on, epoch, 180_000); r.Allow || r.Checks["freshness"] != "fail" ||
		!strings.Contains(r.Reason, "revocation epoch is 180000 ms old, over the verifier's maximum of 120000 ms") {
		t.Fatalf("an epoch over the irreversible cap must deny: %+v", r)
	}
	root := func(int64, string) *RevocationState { return &RevocationState{Root: "root", RootIssuedAt: fptr(1.0)} }
	if r := stalenessAuthorize(t, on, root, 0); r.Allow || r.Checks["freshness"] != "fail" ||
		!strings.Contains(r.Reason, "unsigned revocation root refused for an irreversible action") {
		t.Fatalf("an unsigned root must be refused for an irreversible action: %+v", r)
	}
	none := func(int64, string) *RevocationState { return nil }
	if r := stalenessAuthorize(t, on, none, 0); r.Allow || !strings.Contains(r.Reason, "no verifiable (guardian-signed) revocation state") {
		t.Fatalf("no state must deny an irreversible action: %+v", r)
	}
	// off (nil or empty policy): unchanged behaviour, no freshness check
	if r := stalenessAuthorize(t, nil, nil, 0); !r.Allow || r.Checks["freshness"] != "" {
		t.Fatalf("staleness off must not change the decision: %+v", r)
	}
	if r := stalenessAuthorize(t, &RevocationStalenessPolicy{}, nil, 0); !r.Allow {
		t.Fatalf("an empty policy is off: %+v", r)
	}
}

func TestAuthorizeRevocationStalenessMisconfigured(t *testing.T) {
	// a policy without a state source, or an invalid policy, denies and names what is wrong
	r := stalenessAuthorize(t, &RevocationStalenessPolicy{MaxRevocationAgeMs: fptr(300000.0)}, nil, 0)
	if r.Allow || r.Status != 403 || len(r.Missing) != 1 || !strings.HasPrefix(r.Missing[0], "RevocationState") {
		t.Fatalf("missing state source: %+v", r)
	}
	bad := stalenessAuthorize(t, &RevocationStalenessPolicy{MaxRevocationAgeMs: fptr(-1.0)}, func(int64, string) *RevocationState { return nil }, 0)
	if bad.Allow || len(bad.Missing) != 1 || !strings.HasPrefix(bad.Missing[0], "RevocationStaleness") {
		t.Fatalf("invalid policy: %+v", bad)
	}
}

func TestStalenessMembershipVectors(t *testing.T) {
	doc := stalenessDoc(t)
	set := doc["revocation_set"].(map[string]any)
	roots := map[string]string{"main": set["root"].(string), "one": set["single"].(map[string]any)["root"].(string), "empty": set["empty_root"].(string)}
	rs := grows(t, doc, "membership")
	if len(rs) != 27 {
		t.Fatalf("membership rows %d", len(rs))
	}
	for _, v := range rs {
		if got := VerifyNonMembership(v["root"].(string), v["proof"], v["id"].(string)); got != v["ok"].(bool) {
			t.Errorf("%s: %v want %v", v["name"], got, v["ok"])
		}
		if _, known := roots[v["set"].(string)]; !known && v["set"] != "wrong" {
			t.Errorf("%s: unknown set %v", v["name"], v["set"])
		}
	}
}

func TestStalenessGateIDsVectors(t *testing.T) {
	doc := stalenessDoc(t)
	rs := grows(t, doc, "gate_ids")
	if len(rs) != 10 {
		t.Fatalf("gate_ids rows %d", len(rs))
	}
	root := doc["revocation_set"].(map[string]any)["root"].(string)
	for _, v := range rs {
		issued := int64(vecMs(v["epoch_issued_at"]))
		ep, err := SignRevocationEpoch(bytes.Repeat([]byte{11}, 32), RevocationEpochBody{InstanceID: "i", GrantRef: "g1", Epoch: 0,
			SetSize: 6, Root: root, IssuedAt: issued, NotAfter: issued + 600_000})
		if err != nil {
			t.Fatal(err)
		}
		var ids []string
		for _, x := range v["ids"].([]any) {
			ids = append(ids, x.(string))
		}
		proofs := v["proofs"].(map[string]any)
		in := RevocationGateInput{Policy: RevocationStalenessPolicy{MaxRevocationAgeMs: fptr(float64(RevocationEpochValidityMs))},
			GuardianPublic: doc["guardian_public"].(string), GrantRef: "g1", PCActnEpoch: fptr(0), Now: vecMs(v["now"]),
			SignedClass: "costly", EpochSource: true, Epoch: ep, Ids: ids,
			Proof: func(id string) any { return proofs[id] }}
		r := RevocationGate(in)
		wantResult(t, "gate_ids/"+v["name"].(string), RevocationAgeResult{OK: r.OK, Reason: r.Reason}, v)
	}
}

// With RevocationProof set, Authorize needs a valid proof per cap_chain id: none supplied denies, fail closed.
func TestAuthorizeRevocationStalenessNonMembership(t *testing.T) {
	on := &RevocationStalenessPolicy{MaxRevocationAgeMs: fptr(300000.0)}
	epoch := func(int64, string) *RevocationState { return &RevocationState{Epoch: map[string]any{}} }
	r := stalenessAuthorizeWith(t, on, epoch, 30_000, func(in *AuthorizeInput) {
		in.RevocationIds = nil // the default: every cap_chain id
		in.RevocationProof = func(string, map[string]any) any { return nil }
	})
	if r.Allow || r.Checks["freshness"] != "fail" || !strings.Contains(r.Reason, "no non-membership proof for ") {
		t.Fatalf("a missing proof must deny: %+v", r)
	}
	r = stalenessAuthorizeWith(t, on, epoch, 30_000, func(in *AuthorizeInput) {
		in.RevocationProof = func(string, map[string]any) any { return map[string]any{"size": 1} }
		in.RevocationIds = func(map[string]any) []string { return []string{"x"} }
	})
	if r.Allow || !strings.Contains(r.Reason, "capability x is revoked or proof invalid") {
		t.Fatalf("an invalid proof must deny: %+v", r)
	}
}

// 0.5 default: with staleness on and no proof source at all, a request that carries a capability chain is denied.
func TestAuthorizeRevocationStalenessDefaultRequiresProofs(t *testing.T) {
	on := &RevocationStalenessPolicy{MaxRevocationAgeMs: fptr(300000.0)}
	epoch := func(int64, string) *RevocationState { return &RevocationState{Epoch: map[string]any{}} }
	r := stalenessAuthorizeWith(t, on, epoch, 30_000, func(in *AuthorizeInput) { in.RevocationIds = nil })
	if r.Allow || r.Checks["freshness"] != "fail" || !strings.Contains(r.Reason, "no non-membership proof for ") {
		t.Fatalf("no proof source must deny by default: %+v", r)
	}
	r = stalenessAuthorizeWith(t, on, epoch, 30_000, nil) // explicit empty ids: freshness only
	if !r.Allow {
		t.Fatalf("explicit empty ids must allow: %+v", r)
	}
}
