package pca

import (
	"crypto/ed25519"
	"os"
	"reflect"
	"strings"
	"testing"
)

// Escalation answers (vectors shared with TypeScript / Rust / Python) and the guard: escalate is surfaced distinctly, refused
// without an answer, admitted only by a bound principal answer spent by the replay counter, never upgraded from a deny.

func TestEscalationAnswerVectors(t *testing.T) {
	ran := map[string]bool{}
	for _, x := range decisionTable(t, "escalation_answer") {
		v := x.(map[string]any)
		t.Run(v["name"].(string), func(t *testing.T) {
			in := vectorInput(t, v)
			var pins []PinnedSigner
			for _, p := range in["principals"].([]any) {
				switch q := p.(type) {
				case string:
					pins = append(pins, PinnedSigner{PK: q})
				case map[string]any:
					pq, _ := q["pq_pk"].(string)
					pins = append(pins, PinnedSigner{PK: q["pk"].(string), PQPK: pq})
				}
			}
			b := in["bind"].(map[string]any)
			now, _ := jsNum(in["now"])
			if now != float64(int64(now)) {
				now = 1 << 62 // a non-integer clock is refused by the safe-integer check
			}
			r := VerifyEscalationAnswer(in["answer"], pins, EscalationBinding{PolicyDigest: b["policy_digest"].(string), ActionDigest: b["action_digest"].(string), HistoryHead: b["history_head"].(string)}, int64(now))
			e := v["expect"].(map[string]any)
			if need, has := v["requires_suite"].(string); has && !supportedSuites[need] {
				// a suite this build cannot run is refused, never accepted and never mistaken for a bad signature
				if r.OK || !strings.Contains(r.Reason, UnsupportedSuite) {
					t.Fatalf("suite %s is not built: want %s, got %+v", need, UnsupportedSuite, r)
				}
				return
			}
			if need, has := v["requires_suite"].(string); has && e["ok"].(bool) {
				ran[need] = true
			}
			if r.OK != e["ok"].(bool) {
				t.Fatalf("ok = %v (%s), want %v", r.OK, r.Reason, e["ok"])
			}
			if r.OK && (r.Principal != e["principal"] || r.Decision != e["decision"]) {
				t.Fatalf("got %+v, want %v", r, e)
			}
			if !r.OK && !strings.Contains(r.Reason, e["reason_contains"].(string)) {
				t.Fatalf("reason %q lacks %q", r.Reason, e["reason_contains"])
			}
		})
	}
	// every suite this build implements ran its positive vector (a runner that skipped them all would pass vacuously)
	for _, alg := range SupportedSuites() {
		if alg != "ed25519" && !strings.Contains(alg, "less") && !ran[alg] {
			t.Errorf("suite %s is built but no escalation_answer vector exercised it", alg)
		}
	}
}

func principalKey(t *testing.T) (ed25519.PrivateKey, string) {
	t.Helper()
	b, err := os.ReadFile(dir + "keys.json")
	if err != nil {
		t.Fatal(err)
	}
	k, _ := ParseJSONLenient(b)
	p := k.(map[string]any)["principal"].(map[string]any)
	seed, _ := DecodeB64uStrict(p["seed"].(string), 32)
	return ed25519.NewKeyFromSeed(seed), p["public"].(string)
}

func signAnswer(t *testing.T, sk ed25519.PrivateKey, pub string, grant, pcactn map[string]any, last *int64, over map[string]any) map[string]any {
	t.Helper()
	pd, _ := EscalationPolicyDigest(grant)
	ad, _ := EscalationActionDigest(pcactn)
	hh, _ := EscalationHistoryHead(last)
	now := fixNum(authorizeFixtures(t)["now"]) // the answer's window is relative to the fixture clock
	body := map[string]any{"v": jsonNumberOf(1), "kind": "pca-escalation-answer", "principal": pub, "policy_digest": pd, "action_digest": ad,
		"history_head": hh, "decision": "allow", "iat": jsonNumberOf(now), "expires_at": jsonNumberOf(now + 600_000),
		"nonce": "CQkJCQkJCQkJCQkJCQkJCQ"}
	for k, v := range over {
		body[k] = v
	}
	cb, err := Canonicalize(body)
	if err != nil {
		t.Fatal(err)
	}
	body["sig"] = b64.EncodeToString(ed25519.Sign(sk, []byte(EscalationAnswerDomain+cb)))
	return body
}

func escalateHook(checks ...string) func() {
	authorizeCoreHook = func(core *Verdict) {
		for _, c := range checks {
			core.Checks[c] = false
		}
		core.Allow = false
		core.Reason = "provenance: intent_required: a question is required"
	}
	return func() { authorizeCoreHook = nil }
}

// escalateHookReasons makes the core verdict fail `checks` with the full reason list `reasons` (the first is Reason), as the
// v2 pipeline's fold does for a multi-check verdict.
func escalateHookReasons(checks []string, reasons []string) func() {
	authorizeCoreHook = func(core *Verdict) {
		for _, c := range checks {
			core.Checks[c] = false
		}
		core.Allow = false
		core.Reason = reasons[0]
		core.Reasons = append([]string{}, reasons...)
	}
	return func() { authorizeCoreHook = nil }
}

func escalationSetup(t *testing.T) (fix map[string]any, grant, pcactn map[string]any, in func(store StateStore, answer any, principals []string) AuthorizeInput, step map[string]any) {
	t.Helper()
	d := authorizeFixtures(t)
	var c map[string]any
	for _, x := range d["cases"].([]any) {
		cc := x.(map[string]any)
		ss := cc["steps"].([]any)
		if len(ss) == 1 && ss[0].(map[string]any)["expect"].(map[string]any)["allow"] == true {
			c = cc
			break
		}
	}
	grant = c["grant"].(map[string]any)
	step = c["steps"].([]any)[0].(map[string]any)
	pcactn = step["pcactn"].(map[string]any)
	in = func(store StateStore, answer any, principals []string) AuthorizeInput {
		revoked := false
		i := fixInput(d, grant, store, &revoked)
		i.Operation = fixOp(step["operation"].(map[string]any))
		i.EscalationAnswer, i.EscalationPrincipals = answer, principals
		i.InsecureUnboundApproval = true // these tests cover the answer binding, not the render (see TestUnboundApprovalIsRefusedByDefault)
		return i
	}
	return d, grant, pcactn, in, step
}

func TestEscalateIsSurfacedAndRefusedWithoutAnAnswer(t *testing.T) {
	_, _, pcactn, in, _ := escalationSetup(t)
	defer escalateHook("provenance")()
	r := Authorize(pcactn, in(NewMemoryStateStore(), nil, nil))
	if r.Allow || r.Decision != "escalate" || r.Status != 403 || r.Escalation["kind"] != "pca-escalation-request" {
		t.Fatalf("got %+v", r)
	}
}

func TestHardFailureIsDenyNotEscalate(t *testing.T) {
	_, _, pcactn, in, _ := escalationSetup(t)
	defer escalateHook("provenance", "leaf_signature")()
	r := Authorize(pcactn, in(NewMemoryStateStore(), nil, nil))
	if r.Allow || r.Decision != "deny" || r.Escalation != nil {
		t.Fatalf("got %+v", r)
	}
}

func TestValidAnswerAdmitsOnceAndTheCounterSpendsIt(t *testing.T) {
	_, grant, pcactn, in, _ := escalationSetup(t)
	sk, pub := principalKey(t)
	defer escalateHook("provenance")()
	store := NewMemoryStateStore()
	a := signAnswer(t, sk, pub, grant, pcactn, nil, nil)
	r := Authorize(pcactn, in(store, a, []string{pub}))
	if !r.Allow || r.Decision != "allow" || r.Escalation["answered_by"] != pub {
		t.Fatalf("got %+v", r)
	}
	last, _ := store.Last(StateKey(grant["id"].(string), pcactn["cap_chain"].([]any)[len(pcactn["cap_chain"].([]any))-1].(map[string]any)["holder"].(string)))
	again := Authorize(pcactn, in(store, signAnswer(t, sk, pub, grant, pcactn, last, nil), []string{pub}))
	if again.Allow || again.Checks["replay"] != "fail" {
		t.Fatalf("replayed answer admitted: %+v", again)
	}
}

func TestBadAnswersStayEscalate(t *testing.T) {
	_, grant, pcactn, in, _ := escalationSetup(t)
	sk, pub := principalKey(t)
	defer escalateHook("provenance")()
	zero := b64.EncodeToString(make([]byte, 32))
	n99 := int64(99)
	for name, ans := range map[string]map[string]any{
		"deny":     signAnswer(t, sk, pub, grant, pcactn, nil, map[string]any{"decision": "deny"}),
		"policy":   signAnswer(t, sk, pub, grant, pcactn, nil, map[string]any{"policy_digest": zero}),
		"action":   signAnswer(t, sk, pub, grant, pcactn, nil, map[string]any{"action_digest": zero}),
		"history":  signAnswer(t, sk, pub, grant, pcactn, &n99, nil),
		"expired":  signAnswer(t, sk, pub, grant, pcactn, nil, map[string]any{"iat": jsonNumberOf(1), "expires_at": jsonNumberOf(2)}),
		"unsigned": {"junk": jsonNumberOf(1)},
	} {
		r := Authorize(pcactn, in(NewMemoryStateStore(), ans, []string{pub}))
		if r.Allow || r.Decision != "escalate" {
			t.Fatalf("%s: got %+v", name, r)
		}
	}
	if r := Authorize(pcactn, in(NewMemoryStateStore(), signAnswer(t, sk, pub, grant, pcactn, nil, nil), nil)); r.Allow {
		t.Fatal("no pinned principal admitted")
	}
}

func TestAnswerNeverUpgradesADeny(t *testing.T) {
	_, grant, pcactn, in, _ := escalationSetup(t)
	sk, pub := principalKey(t)
	defer escalateHook("provenance", "leaf_signature")()
	r := Authorize(pcactn, in(NewMemoryStateStore(), signAnswer(t, sk, pub, grant, pcactn, nil, nil), []string{pub}))
	if r.Allow || r.Decision != "deny" {
		t.Fatalf("got %+v", r)
	}
}

type bareStore struct{ m *MemoryStateStore }

func (b bareStore) Claim(k string, c int64) (ClaimResult, error) { return b.m.Claim(k, c) }

func TestStoreWithoutLastIsAConfigurationError(t *testing.T) {
	_, grant, pcactn, in, _ := escalationSetup(t)
	sk, pub := principalKey(t)
	defer escalateHook("provenance")()
	r := Authorize(pcactn, in(bareStore{NewMemoryStateStore()}, signAnswer(t, sk, pub, grant, pcactn, nil, nil), []string{pub}))
	if r.Allow || r.Decision != "deny" || r.Status != 403 || r.Checks["authorize_config"] != "fail" ||
		len(r.Missing) != 1 || r.Missing[0] != "StateStore.Last (required by EscalationPrincipals)" {
		t.Fatalf("got %+v", r)
	}
	// without escalation principals a store without Last is fine
	ok := Authorize(pcactn, in(bareStore{NewMemoryStateStore()}, nil, nil))
	if ok.Checks["authorize_config"] != "" {
		t.Fatalf("a store without Last must be accepted when no principal is pinned: %+v", ok)
	}
	// RequirePCA refuses the same configuration at construction
	defer func() {
		if recover() == nil {
			t.Fatal("RequirePCA must panic for escalation principals over a store without Last")
		}
	}()
	RequirePCA(RequirePCAOptions{Authorize: &AuthorizeOptions{StateStore: bareStore{NewMemoryStateStore()}, EscalationPrincipals: []string{pub}}})
}

func TestSQLStateStoreIsALastStore(t *testing.T) {
	var _ LastStore = (*SQLStateStore)(nil)
	var _ LastStore = (*MemoryStateStore)(nil)
}

// A multi-check escalation (every failing check escalate-class, each with its own reason) is ONE escalation that a single
// answer upgrades; one hard failure among them makes the whole decision a deny.
func TestMultiCheckEscalationIsAnEscalation(t *testing.T) {
	_, grant, pcactn, in, _ := escalationSetup(t)
	sk, pub := principalKey(t)
	rs := []string{"provenance: intent_required: q1", "facts: intent_required: q2", "classes: escalate: q3"}
	defer escalateHookReasons([]string{"provenance", "facts", "classes"}, rs)()
	r := Authorize(pcactn, in(NewMemoryStateStore(), nil, nil))
	if r.Allow || r.Decision != "escalate" || !reflect.DeepEqual(r.Reasons[:3], rs) {
		t.Fatalf("got %+v", r)
	}
	got, _ := r.Escalation["reasons"].([]any)
	if len(got) != 3 || got[0] != rs[0] || got[2] != rs[2] {
		t.Fatalf("the request must carry every reason: %v", r.Escalation["reasons"])
	}
	ok := Authorize(pcactn, in(NewMemoryStateStore(), signAnswer(t, sk, pub, grant, pcactn, nil, nil), []string{pub}))
	if !ok.Allow || ok.Decision != "allow" {
		t.Fatalf("one answer must upgrade every escalate-class failure: %+v", ok)
	}
	for n, st := range ok.Checks {
		if st == "fail" {
			t.Fatalf("check %s still fails after the answer", n)
		}
	}
}

func TestMultiCheckWithOneHardFailureIsADeny(t *testing.T) {
	_, grant, pcactn, in, _ := escalationSetup(t)
	sk, pub := principalKey(t)
	rs := []string{"provenance: intent_required: q1", "facts: intent_required: q2", "classes: class receipt does not verify"}
	defer escalateHookReasons([]string{"provenance", "facts", "classes"}, rs)()
	r := Authorize(pcactn, in(NewMemoryStateStore(), signAnswer(t, sk, pub, grant, pcactn, nil, nil), []string{pub}))
	if r.Allow || r.Decision != "deny" || r.Escalation != nil || !reflect.DeepEqual(r.Reasons[:3], rs) {
		t.Fatalf("got %+v", r)
	}
}

func TestAFailingCheckWithNoReasonOfItsOwnIsADeny(t *testing.T) {
	_, grant, pcactn, in, _ := escalationSetup(t)
	sk, pub := principalKey(t)
	defer escalateHookReasons([]string{"provenance", "facts"}, []string{"provenance: intent_required: q"})()
	r := Authorize(pcactn, in(NewMemoryStateStore(), signAnswer(t, sk, pub, grant, pcactn, nil, nil), []string{pub}))
	if r.Allow || r.Decision != "deny" {
		t.Fatalf("got %+v", r)
	}
}

func TestUnboundApprovalIsRefusedByDefault(t *testing.T) {
	_, grant, pcactn, in, _ := escalationSetup(t)
	sk, pub := principalKey(t)
	defer escalateHook("provenance")()
	a := signAnswer(t, sk, pub, grant, pcactn, nil, nil)
	secure := in(NewMemoryStateStore(), a, []string{pub})
	secure.InsecureUnboundApproval = false
	if r := Authorize(pcactn, secure); r.Allow {
		t.Fatalf("an answer with no recomputed render was admitted: %+v", r.Reasons)
	}
	loose := in(NewMemoryStateStore(), a, []string{pub})
	if r := Authorize(pcactn, loose); !r.Allow {
		t.Fatalf("the documented opt-out must admit: %+v", r.Reasons)
	}
}
