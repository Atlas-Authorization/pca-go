package pca

import (
	"math"
	"sync/atomic"
	"testing"
)

// A constitution with exactly one problem is refused with that problem (the check is "any problem", not "more than one").
func TestSvVerifyConstitutionRefusesOnASingleProblem(t *testing.T) {
	c := goAJ(`{"version":2,"principal":"P","invariants":[]}`)
	if p := ValidateConstitution(c); len(p) != 1 {
		t.Fatalf("setup: %q", p)
	}
	r := VerifyConstitution(c, "")
	if r["ok"] != false || r["reason"] != "unsupported version 2" {
		t.Errorf("one problem: %v", r)
	}
}

// Every condition of an unless / approved list is validated, not only the first.
func TestSvValidateInvariantChecksEveryCondition(t *testing.T) {
	good := `{"field":"action.params.ok","op":"eq","value":true}`
	bad := `{"op":"eq"}`
	unless := goAJ(`{"id":"i1","kind":"never_unless","when":{"verb":"pay"},"unless":[` + good + `,` + bad + `]}`)
	if got := ValidateInvariant(unless); len(got) != 1 || got[0] != "i1: condition.field missing" {
		t.Errorf("unless: %q", got)
	}
	approved := goAJ(`{"id":"i1","kind":"require_approval_over","when":{"verb":"pay"},"amount":"action.params.n","threshold":100,"approved":[` + good + `,` + bad + `]}`)
	if got := ValidateInvariant(approved); len(got) != 1 || got[0] != "i1: condition.field missing" {
		t.Errorf("approved: %q", got)
	}
}

// An amount of zero (or a fraction) at or under the threshold needs no approval; only a negative one does.
func TestSvRequireApprovalOverSmallAmounts(t *testing.T) {
	ap := `{"id":"ap","kind":"require_approval_over","when":{"verb":"pay"},"amount":"action.params.n","threshold":100,"approved":[{"field":"subject.approved","op":"eq","value":true}]}`
	for _, n := range []string{"0", "0.5"} {
		got := goARes(CheckProhibitions(goAActSubj("pay", `"n":`+n, `"approved":false`), goAC(ap), goAGenesis("{}", "{}")))
		if got != "ok=true violated=[] reasons=[]" {
			t.Errorf("amount %s: %s", n, got)
		}
	}
}

// The binding id needs the three bound digests to be present, as the reference canonicalizer refuses an undefined member.
func TestSvSafetyBindingIDNeedsTheBoundMembers(t *testing.T) {
	f := goAFx(t)
	ev := f.evidence()
	if id, err := SafetyBindingID(ev, "s"); id == "" || err != nil {
		t.Fatalf("complete evidence: %q %v", id, err)
	}
	for _, k := range []string{"constitution", "action_digest", "state_digest"} {
		bad := goAMut(ev, func(m map[string]any) { delete(m, k) })
		id, err := SafetyBindingID(bad, "s")
		if id != "" || err == nil || err.Error() != "safetyBindingId: missing "+k {
			t.Errorf("without %s: %q %v", k, id, err)
		}
		signed := goAMut(f.sign(t, ev), func(m map[string]any) { delete(m["evidence"].(map[string]any), k) })
		if r := VerifySignedSafetyEvidence(signed, f.full()); r["ok"] != false || r["reason"] != "verification error (fail closed)" {
			t.Errorf("signed without %s: %v", k, r)
		}
		// a binding id that is not a string is judged first, as in the reference
		numeric := goAMut(signed, func(m map[string]any) { m["id"] = 5 })
		if r := VerifySignedSafetyEvidence(numeric, f.full()); r["ok"] != false || r["reason"] != "binding id mismatch" {
			t.Errorf("numeric id without %s: %v", k, r)
		}
	}
}

// The evidence version is exactly the number 1: not a string, a boolean, null or a list.
func TestSvEvidenceVersionIsExactlyTheNumberOne(t *testing.T) {
	f := goAFx(t)
	ev := f.evidence()
	signed := f.sign(t, ev)
	for name, v := range map[string]any{"string": "1", "true": true, "null": nil, "list": []any{goAN("1")}} {
		bad := goAMut(ev, func(m map[string]any) { m["v"] = v })
		if s, err := SignSafetyEvidence(bad, f.seed, f.kp.Public); s != nil || err == nil || err.Error() != "signSafetyEvidence: unsupported evidence" {
			t.Errorf("sign v=%s: %v %v", name, s, err)
		}
		sv := goAMut(signed, func(m map[string]any) { m["evidence"].(map[string]any)["v"] = v })
		if r := VerifySignedSafetyEvidence(sv, f.full()); r["ok"] != false || r["reason"] != "unsupported evidence version" {
			t.Errorf("verify v=%s: %v", name, r)
		}
	}
}

// A null pin, like a non-string one, never matches a constitution's principal: the pin is refused, not skipped.
func TestSvSignedEvidencePrincipalPinMustBeAString(t *testing.T) {
	f := goAFx(t)
	pseed := make([]byte, 32)
	pseed[0] = 34
	pkp, _ := KeyPairFromSeed(pseed)
	c := goAJ(`{"version":1,"principal":"` + pkp.Public + `","invariants":[{"id":"n","kind":"never","when":{"verb":"zzz"}}]}`)
	sc, err := SignConstitution(c, pseed)
	if err != nil {
		t.Fatal(err)
	}
	signed := f.sign(t, ProveSafety(f.act, sc, f.st))
	ad, _ := HashCanonical(f.act)
	sd, _ := StateDigest(f.st)
	for name, pin := range map[string]any{"null": nil, "true": true, "list": []any{pkp.Public}, "object": map[string]any{}} {
		exp := map[string]any{"signer": f.kp.Public, "actionDigest": ad, "constitution": sc, "stateDigest": sd, "principal": pin}
		if r := VerifySignedSafetyEvidence(signed, exp); r["ok"] != false || r["reason"] != "constitution not authentic: principal mismatch" {
			t.Errorf("pin %s: %v", name, r)
		}
	}
}

type svPlainStore struct{ closed *atomic.Int32 }

func (svPlainStore) Claim(string, int64) (ClaimResult, error) { return ClaimResult{}, nil }
func (s svPlainStore) Close() error                           { s.closed.Add(1); return nil }

// A store that lacks the budget seam is still closed.
func TestSvBudgetConformanceClosesAStoreWithoutTheSeam(t *testing.T) {
	var opened, closed atomic.Int32
	BudgetStoreConformance{Name: "plain", Open: func() (StateStore, error) {
		opened.Add(1)
		return svPlainStore{&closed}, nil
	}}.Run()
	if opened.Load() == 0 || opened.Load() != closed.Load() {
		t.Errorf("opened %d, closed %d", opened.Load(), closed.Load())
	}
}

// A use of a frozen holder is refused without writing anything; a review whose write is not acknowledged is not an acceptance.
func TestSvBreakGlassFrozenUseWritesNothingAndReviewFaultRefuses(t *testing.T) {
	auth, _ := NewKeyPair()
	rev, _ := NewKeyPair()
	kv := goCNewKV()
	reg := NewBreakGlassRegistry(BreakGlassPolicy{Authorities: []string{auth.Public}, Reviewers: []string{rev.Public}}, kv)
	if r := reg.Accept(goCBGRec(t, auth, "g1", "h", nil), 1000); !r.Ok {
		t.Fatalf("accept: %+v", r)
	}
	if d := reg.Use("g1", "h", "d", 1500, true); d.Decision != "allow" {
		t.Fatalf("use: %+v", d)
	}
	before := kv.writes[bgKey("h")]
	if d := reg.Use("g1", "h", "d2", 101500, true); d.Decision != "deny" || d.Code != "holder_frozen" || kv.writes[bgKey("h")] != before {
		t.Errorf("frozen use: %+v writes %d -> %d", d, before, kv.writes[bgKey("h")])
	}
	kv.errAfter = func(string) bool { return true }
	if r := reg.Review(goCBGRev(t, rev, "g1", "n", 1500), "h", 2000); r.Ok || r.Code != "store_unreachable" {
		t.Errorf("review with an unacknowledged write: %+v", r)
	}
}

func TestSvSignContractResetRefusesABadSeed(t *testing.T) {
	if s, err := SignContractReset([]byte("short"), "c", 1); s != "" || err == nil {
		t.Errorf("a bad seed must not sign: %q %v", s, err)
	}
}

// The highest epoch only moves up: an equal or lower epoch writes nothing.
func TestSvBlueprintMaxEpochWritesOnlyWhenRaised(t *testing.T) {
	kv := goCNewKV()
	reg := NewBlueprintRegistry(nil, kv)
	writes := func() int { return kv.writes[blueprintMaxEpochKey] }
	if err := reg.raiseMaxEpoch(5); err != nil || writes() != 1 {
		t.Fatalf("first raise: %v writes %d", err, writes())
	}
	for _, e := range []int64{5, 4} {
		if err := reg.raiseMaxEpoch(e); err != nil || writes() != 1 {
			t.Errorf("epoch %d: %v writes %d", e, err, writes())
		}
	}
	if err := reg.raiseMaxEpoch(6); err != nil || writes() != 2 {
		t.Errorf("epoch 6: %v writes %d", err, writes())
	}
}

func TestSvOIDContentOver256BytesIsRefusedWithNoText(t *testing.T) {
	b := make([]byte, 300)
	if s, err := oidToDotted(b, derTlv{tag: 0x06, start: 2, end: 2 + 257}); s != "" || err == nil || err.Error() != "extension OID is too long" {
		t.Errorf("257 bytes: %q %v", s, err)
	}
}

// A budget too low for a band-2 action reads as depleted (not as a plain step-up), as for band 1.
func TestSvDecideRiskDepletedBudgetAtBandTwo(t *testing.T) {
	alpha := goBDecidePolicy(RiskWeights{Alpha: 1})
	d := DecideRisk(goBGo(RiskStep{Policy: alpha, Risk: goBFullRisk(map[string]any{"semanticDistance": 0.5}), Budget: TrustBudget{B: 0}}))
	if len(d.Reasons) != 1 || d.Reasons[0] != "trust budget depleted: human recharge required" || !d.NeedStepUp {
		t.Errorf("band 2, no budget: %+v", d)
	}
}

// A negative-zero bound or scale is zero, not negative zero.
func TestSvRiskNegativeZeroScalesAreZero(t *testing.T) {
	negz := math.Copysign(0, -1)
	if b := RechargeFull(negz, 0); b.B != 0 || math.Signbit(b.B) {
		t.Errorf("recharge to -0: %v", b.B)
	}
	if c := RiskCost(0.5, negz); c != 0 || math.Signbit(c) {
		t.Errorf("cost at kappa -0: %v", c)
	}
}
