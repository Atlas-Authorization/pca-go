package pca

import (
	"encoding/json"
	"strings"
	"testing"
)

// r5-7: optimistic.go, forbid_certificate.go, passport.go and readvault.go survivors.

// ---- optimistic.go

// A body the lenient canonical form refuses (a number past the double range reads as Infinity) is malformed, not badly signed.
func TestR5N7_OptimisticUncanonicalBody(t *testing.T) {
	claim := map[string]any{"pcactn_digest": "D", "claimed_r": json.Number("0.5"), "issued_at": json.Number("1000"),
		"challenge_window_ms": json.Number("2000"), "sig": "x", "z": json.Number("1e400")}
	if got := ClaimCheck(claim, "D", "k", 1000, DefaultChallengeWindowPolicy); got != "malformed" {
		t.Fatalf("claim: %q", got)
	}
	record := map[string]any{"claimId": "c", "action": "open", "amount": json.Number("0.5"), "from": "f", "to": "t",
		"at": json.Number("1"), "evidenceDigest": "", "sig": "x", "z": json.Number("1e400")}
	if got := SettlementWireCheck(record, "k"); got != "malformed" {
		t.Fatalf("settlement: %q", got)
	}
	delete(record, "z")
	if got := SettlementWireCheck(record, "k"); got != "signature" {
		t.Fatalf("settlement without the extra member: %q", got)
	}
}

// JavaScript === on a member that is present as null in one object and absent in the other is false.
func TestR5N7_OptimisticNullIsNotAbsent(t *testing.T) {
	withNull := map[string]any{"a": nil}
	if extNumEq(withNull, map[string]any{}, "a") || extNumEq(map[string]any{}, withNull, "a") {
		t.Fatal("null equals absent")
	}
	if !extNumEq(withNull, map[string]any{"a": nil}, "a") {
		t.Fatal("null != null")
	}
}

// With no r_margin the default margin is 1e-9 (the reference's DEFAULT_R_MARGIN), not zero.
func TestR5N7_OptimisticDefaultRMargin(t *testing.T) {
	claim := map[string]any{"pcactn_digest": "D", "bond_ref": "B", "claimed_r": json.Number("0.5")}
	proof := func(r string) map[string]any {
		return map[string]any{"pcactn_digest": "D", "bond_ref": "B", "claimed_r": json.Number("0.5"), "reason": "x", "kind": "risk-understated",
			"decision": map[string]any{"releaseGuardianShare": true, "optimisticAllowed": true, "r": json.Number(r)}}
	}
	if got := FraudProofWireCheck(claim, proof("0.5000000005")); got != "consistency" {
		t.Fatalf("r within the default margin: %q", got)
	}
	if got := FraudProofWireCheck(claim, proof("0.5000000015")); got != "ok" {
		t.Fatalf("r past the default margin: %q", got)
	}
}

// ---- forbid_certificate.go

// A clause with no signer ranks last, even when the precedence list holds an empty string.
func TestR5N7_ForbidUnsignedClauseRanksLast(t *testing.T) {
	cert := map[string]any{"v": json.Number("1"), "kind": "forbid-wins", "decision": "deny",
		"clauses": []any{
			map[string]any{"id": "z-f", "kind": "forbid", "value": "true"},
			map[string]any{"id": "a-f", "kind": "forbid", "value": "true", "signer": "a"},
		},
		"winner": map[string]any{"kind": "forbid", "id": "a-f"}, "shadowed": []any{"z-f"}}
	if !ForbidCertificateConsistent(cert, []string{"", "a"}) {
		t.Fatal("the signed forbid clause wins over the unsigned one")
	}
}

// ---- passport.go

func TestR5N7_PassportRefusals(t *testing.T) {
	sp, iss := g05Passport(t, false, nil)
	odd := copyMap(sp)
	odd["x"] = 1.5 // a float64 is outside the strict profile: the body has no canonical form
	g05Want(t, "uncanonical body", VerifyPassport(odd, g05PassOpts(iss, g05Iat+1)), "malformed")

	hw, hwIss := g05Passport(t, true, map[string]any{"document": map[string]any{"nonce": "n"}, "at": "not a number"})
	g05Want(t, "evidence time", VerifyPassport(hw, g05PassOpts(hwIss, g05Iat)), "hardware_evidence_missing")
}

// ---- readvault.go

// A refusal hands back a copy of the input state, never the caller's map.
func TestR5N7_AggregateRefusalStateIsACopy(t *testing.T) {
	st := AggregateState{SpentMicro: 5, Queries: 2, Answered: map[string]int64{"q": 3}}
	r := AggregateRead(AggregateInput{Principal: "x", Now: jnum(1), State: st})
	if r.Code != "bad_request" || r.State.Answered["q"] != 3 {
		t.Fatalf("premise: %+v", r)
	}
	r.State.Answered["z"] = 9
	if _, has := st.Answered["z"]; has {
		t.Fatal("the refusal aliases the caller's state")
	}
}

// Of several matching rules the first decides.
func TestR5N7_AggregateFirstMatchingRuleDecides(t *testing.T) {
	k := newKey(t)
	body := g12AggBody(k.id, g12With(g12AggRule(), "min_group", jnum(3)), g12AggRule())
	g := map[string]any{"body": body, "sig": signDomain(t, k, k5AggregateDomain, body)}
	if r := AggregateRead(g12AggIn(k, g)); r.Decision != "deny" || r.Code != "group_too_small" {
		t.Fatalf("got %+v", r)
	}
}

// A salt that cannot be hashed (a lone surrogate) makes the seeded noise unavailable: the catch-all with an EMPTY state.
func TestR5N7_AggregateSeededNoiseNeedsAHashableSalt(t *testing.T) {
	k := newKey(t)
	rule := g12With(g12AggRule(), "dp", true)
	rule["epsilon_micro"] = jnum(1000000)
	body := g12AggBody(k.id, rule)
	body["epsilon_budget_micro"] = jnum(10000000)
	in := g12AggIn(k, map[string]any{"body": body, "sig": signDomain(t, k, k5AggregateDomain, body)})
	in.State = AggregateState{SpentMicro: 7, Queries: 1}
	in.Salt = "ok-salt-ok-salt-ok"
	if r := AggregateRead(in); r.Decision != "allow" {
		t.Fatalf("premise: %+v", r)
	}
	in.Salt = "\xed\xa0\x80" + strings.Repeat("a", 20)
	if r := AggregateRead(in); !g12IsEmptyFail(r) {
		t.Fatalf("lone surrogate salt: %+v", r)
	}
}

// The grant digest of a read grant is needed to record and to redeem a token; without one both refuse.
func TestR5N7_VaultNeedsTheReadGrantDigest(t *testing.T) {
	grant, in := g12VaultRead(t)
	defer func(old func(map[string]any) (string, bool)) { k5ReadDigestFn = old }(k5ReadDigestFn)
	k5ReadDigestFn = func(map[string]any) (string, bool) { return "", false }
	st := &g12VaultStore{}
	if r := RedactReadWithVault(in, st); r.Decision != "deny" || r.Code != "bad_request" || len(st.puts) != 0 {
		t.Fatalf("redact: %+v %v", r, st.puts)
	}
	now := int64(k5F(in.Now))
	store := &g12VaultStore{entry: VaultEntry{Cls: "ref", Value: "v", Grant: "", Exp: now + 1}, has: true}
	if r := Detokenize(DetokenizeInput{Grant: grant, Principal: in.Principal, Now: in.Now, Sink: "payments", Token: "tok", Store: store}); r.Decision != "deny" || r.Code != "bad_request" || r.Value != nil {
		t.Fatalf("detokenize: %+v", r)
	}
}
