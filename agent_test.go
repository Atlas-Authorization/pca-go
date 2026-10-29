package pca

import (
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
)

// Replays packages/pca/conformance/producer-vectors.json against the Go producers byte for byte (fixed keys, nonces and
// timestamps; Ed25519 is deterministic), then round-trips what they produce through this package's own verifier, post-quantum
// suites included (their signatures are randomised: cross-verified, not compared).

type producerDoc struct {
	keys  map[string]*KeyPair
	cases []any
}

func loadProducer(t *testing.T) producerDoc {
	t.Helper()
	raw, err := os.ReadFile(dir + "producer-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	v, err := ParseJSONLenient(raw)
	if err != nil {
		t.Fatal(err)
	}
	doc := v.(map[string]any)
	d := producerDoc{keys: map[string]*KeyPair{}, cases: doc["cases"].([]any)}
	for name, k := range doc["keys"].(map[string]any) {
		kp, err := KeyPairFromSeedB64u(k.(map[string]any)["seed"].(string))
		if err != nil {
			t.Fatal(err)
		}
		if kp.Public != k.(map[string]any)["public"].(string) {
			t.Fatalf("key %s: public mismatch", name)
		}
		d.keys[name] = kp
	}
	return d
}

func prodStr(m map[string]any, k string) string { s, _ := m[k].(string); return s }
func prodInt(t *testing.T, v any) int64 {
	t.Helper()
	n, ok := safeInt(v)
	if !ok {
		t.Fatalf("not an integer: %v", v)
	}
	return n
}
func prodObjs(v any) []map[string]any {
	var out []map[string]any
	for _, x := range v.([]any) {
		out = append(out, x.(map[string]any))
	}
	return out
}

func runProducer(t *testing.T, d producerDoc, op string, a map[string]any) any {
	t.Helper()
	must := func(v map[string]any, err error) map[string]any {
		if err != nil {
			t.Fatalf("%s: %v", op, err)
		}
		return v
	}
	switch op {
	case "ed25519_sign":
		k, _ := KeyPairFromSeedB64u(prodStr(a, "seed"))
		return map[string]any{"public": k.Public, "sig": b64.EncodeToString(k.Sign([]byte(prodStr(a, "message_utf8"))))}
	case "goal_commit":
		c, err := GoalCommitOf(prodStr(a, "goal"), prodStr(a, "salt"))
		if err != nil {
			t.Fatal(err)
		}
		return map[string]any{"commit": c}
	case "params_digest":
		c, err := ParamsDigest(a["params"])
		if err != nil {
			t.Fatal(err)
		}
		return map[string]any{"digest": c}
	case "plan_commit":
		nodes := prodObjs(a["nodes"])
		pc, err := CommitPlan(nodes)
		if err != nil {
			t.Fatal(err)
		}
		proofs := map[string]any{}
		for _, n := range nodes {
			p, err := pc.ProofFor(prodStr(n, "id"))
			if err != nil {
				t.Fatal(err)
			}
			proofs[prodStr(n, "id")] = p
		}
		return map[string]any{"root": pc.Root, "proofs": proofs}
	case "mint_grant":
		r, err := MintGrant(d.keys[prodStr(a, "principal")], d.keys[prodStr(a, "holder")].Public, a["envelope"].(map[string]any), prodStr(a, "goal"), prodStr(a, "salt"), "", nil)
		if err != nil {
			t.Fatal(err)
		}
		return map[string]any{"grant": r.Grant, "goal_commit": r.GoalCommit, "goal_salt": r.GoalSalt}
	case "delegate":
		to := ""
		if s := prodStr(a, "to_holder"); s != "" {
			to = d.keys[s].Public
		}
		return must(Delegate(a["parent"].(map[string]any), d.keys[prodStr(a, "signer")], to, a["added_caveats"].([]any), "", nil))
	case "act":
		in := PCActnInput{Grant: a["grant"].(map[string]any), Chain: prodObjs(a["chain"]), Plan: prodObjs(a["plan"]), NodeID: prodStr(a, "node_id"),
			Params: a["params"], Counter: prodInt(t, a["counter"]), Signer: d.keys[prodStr(a, "signer")], Aud: prodStr(a, "aud"), Iat: prodInt(t, a["iat"]), Exp: prodInt(t, a["exp"]),
			Extra: map[string]any{}}
		for _, k := range []string{"nonce", "caution", "rationale_commitment", "tool_binding", "fresh_at"} {
			if v, ok := a[k]; ok {
				in.Extra[k] = v
			}
		}
		p := must(BuildPCActn(in))
		h, err := PCAHeaders(p, nil, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		return map[string]any{"pcactn": p, "header": h[PCAHeader]}
	case "fresh_at":
		return must(SignFreshAt(d.keys[prodStr(a, "signer")], prodStr(a, "scope"), a["state"].(map[string]any), prodInt(t, a["issued_at"])))
	case "escalation_digests":
		var last *int64
		if a["last_counter"] != nil {
			n := prodInt(t, a["last_counter"])
			last = &n
		}
		pd, _ := EscalationPolicyDigest(a["grant"].(map[string]any))
		ad, _ := EscalationActionDigest(a["pcactn"].(map[string]any))
		hh, _ := EscalationHistoryHead(last)
		return map[string]any{"policy_digest": pd, "action_digest": ad, "history_head": hh}
	case "sign_escalation_answer":
		b := a["body"].(map[string]any)
		return must(SignEscalationAnswer(d.keys[prodStr(a, "signer")], b, prodStr(b, "decision"), prodInt(t, b["iat"]), prodInt(t, b["expires_at"]), prodStr(b, "nonce"), nil))
	case "sign_discharge":
		b := a["body"].(map[string]any)
		return must(SignDischarge(d.keys[prodStr(a, "signer")], DischargeInput{CaveatID: prodStr(b, "caveat_id"), IssuerLabel: prodStr(b, "issuer"), CapHash: prodStr(b, "cap_hash"),
			Bind: prodStr(b, "bind"), ActionDigest: prodStr(b, "action_digest"), Claims: b["claims"].(map[string]any), Iat: prodInt(t, b["iat"]), NotAfter: prodInt(t, b["not_after"]), Nonce: prodStr(b, "nonce")}, nil))
	case "discharge_digest":
		x, err := DischargeDigest(a["discharge"])
		if err != nil {
			t.Fatal(err)
		}
		return map[string]any{"digest": x}
	case "sign_narrow":
		b := a["body"].(map[string]any)
		return must(SignNarrow(d.keys[prodStr(a, "signer")], prodStr(b, "cap_hash"), b["caveats"].([]any), prodInt(t, b["iat"]), prodInt(t, b["not_after"]), prodStr(b, "action_digest"), prodStr(b, "nonce"), nil))
	case "sign_passport":
		pp := must(IssuePassport(a["identity"].(map[string]any)))
		sp := must(SignPassport(pp, d.keys[prodStr(a, "issuer")], d.keys[prodStr(a, "subject")].Public, 0, 0, prodInt(t, a["exp"]), nil, nil))
		return map[string]any{"passport": pp, "signed": sp}
	case "sign_workflow":
		return must(SignWorkflow(d.keys[prodStr(a, "signer")], a["body"].(map[string]any)))
	case "sign_step_receipt":
		var prev map[string]any
		if p, ok := a["prev"].(map[string]any); ok {
			prev = p
		}
		return must(SignStepReceipt(d.keys[prodStr(a, "signer")], a["workflow"].(map[string]any), prodStr(a, "step"), prodStr(a, "outcome"), prodStr(a, "params_digest"),
			a["outputs"].(map[string]any), prodInt(t, a["issued_at"]), prev))
	case "sign_read_grant":
		return must(SignReadGrant(d.keys[prodStr(a, "signer")], a["body"].(map[string]any)))
	case "sign_aggregate_grant":
		return must(SignAggregateGrant(d.keys[prodStr(a, "signer")], a["body"].(map[string]any)))
	}
	t.Fatalf("unknown op %s", op)
	return nil
}

func TestProducerVectors(t *testing.T) {
	d := loadProducer(t)
	if len(d.cases) < 34 {
		t.Fatalf("only %d cases", len(d.cases))
	}
	for _, c := range d.cases {
		cm := c.(map[string]any)
		name, op := prodStr(cm, "name"), prodStr(cm, "op")
		got := runProducer(t, d, op, cm["args"].(map[string]any))
		want := cm["expect"]
		if op == "act" {
			delete(want.(map[string]any), "threshold_message")
		}
		g, err := NormalizeJSON(got)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		w, err := NormalizeJSON(want)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !reflect.DeepEqual(g, w) {
			gb, _ := json.Marshal(g)
			wb, _ := json.Marshal(w)
			t.Errorf("%s: producer output differs\n got  %s\n want %s", name, gb, wb)
		}
	}
}

func newGrant(t *testing.T, principal, agent *KeyPair, holderPq string, s *SuiteOpts) map[string]any {
	t.Helper()
	env := map[string]any{"predicates": []any{map[string]any{"verb": "refund", "resource": "orders/*"}}, "caveats": []any{}, "risk_policy": DefaultRiskPolicy()}
	r, err := MintGrant(principal, agent.Public, env, "refund an order", "", holderPq, s)
	if err != nil {
		t.Fatal(err)
	}
	return r.Grant
}

func coreOK(t *testing.T, p, grant map[string]any, label string) {
	t.Helper()
	v, err := VerifyPCActnCore(p, grant, prodInt(t, p["iat"]), "rs-test")
	if err != nil {
		t.Fatalf("%s: %v", label, err)
	}
	if !v.Allow {
		t.Fatalf("%s: refused: %s", label, v.Reason)
	}
}

func TestAgentRoundTrip(t *testing.T) {
	principal, _ := NewKeyPair()
	agentKey, _ := NewKeyPair()
	grant := newGrant(t, principal, agentKey, "", nil)
	agent := NewAgent(agentKey, grant, "rs-test", 0)
	a1, err := agent.Act("refund", "orders/1", map[string]any{"amount_cents": 500}, nil)
	if err != nil {
		t.Fatal(err)
	}
	a2, err := agent.Act("refund", "orders/1", map[string]any{"amount_cents": 500}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if prodInt(t, a1.PCActn["counter"]) != 1 || prodInt(t, a2.PCActn["counter"]) != 2 || a1.PCActn["nonce"] == a2.PCActn["nonce"] {
		t.Fatalf("counter/nonce: %v %v", a1.PCActn["counter"], a2.PCActn["counter"])
	}
	text, ok := DecodeB64uStrict(a1.Headers[PCAHeader], -1)
	if !ok {
		t.Fatal("header is not strict base64url")
	}
	parsed, err := ParsePCActn(string(text))
	if err != nil {
		t.Fatal(err)
	}
	coreOK(t, parsed, grant, "header round trip")

	tampered := copyMap(a1.PCActn)
	tampered["counter"] = 9
	if v, _ := VerifyPCActnCore(tampered, grant, prodInt(t, a1.PCActn["iat"]), "rs-test"); v.Allow {
		t.Fatal("a tampered counter verified")
	}
}

func TestAgentDelegateAndPlan(t *testing.T) {
	principal, _ := NewKeyPair()
	agentKey, _ := NewKeyPair()
	sub, _ := NewKeyPair()
	grant := newGrant(t, principal, agentKey, "", nil)
	child, err := NewAgent(agentKey, grant, "rs-test", 0).Delegate(sub, []any{SealedCaveat()})
	if err != nil {
		t.Fatal(err)
	}
	chain := make([]any, len(child.Chain))
	for i, c := range child.Chain {
		chain[i] = c
	}
	if why, ok := VerifyChain(chain, principal.Public, true); !ok {
		t.Fatalf("chain: %s", why)
	}
	a, err := child.Act("refund", "orders/2", map[string]any{"amount_cents": 1}, nil)
	if err != nil {
		t.Fatal(err)
	}
	coreOK(t, a.PCActn, grant, "sub-agent")

	agent := NewAgent(agentKey, grant, "rs-test", 0)
	agent.UsePlan([]map[string]any{{"id": "a", "verb": "read", "resource": "x"}, {"id": "b", "verb": "refund", "resource": "orders/1"}})
	pa, err := agent.Act("refund", "orders/1", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	coreOK(t, pa.PCActn, grant, "plan node")
	if _, err := agent.Act("delete", "everything", nil, nil); err == nil {
		t.Fatal("an action outside the committed plan was signed")
	}
}

func TestEscalationAndPassportRoundTrip(t *testing.T) {
	principal, _ := NewKeyPair()
	agentKey, _ := NewKeyPair()
	grant := newGrant(t, principal, agentKey, "", nil)
	act, err := NewAgent(agentKey, grant, "rs-test", 0).Act("refund", "orders/1", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	now := prodInt(t, act.PCActn["iat"])
	zero := int64(0)
	req, err := BuildEscalationRequest("rs-test", grant, act.PCActn, &zero, []string{"escalate: big refund"}, now, 0)
	if err != nil {
		t.Fatal(err)
	}
	ans, err := SignEscalationAnswer(principal, req, "allow", now, now+60_000, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	bind := EscalationBinding{PolicyDigest: prodStr(req, "policy_digest"), ActionDigest: prodStr(req, "action_digest"), HistoryHead: prodStr(req, "history_head")}
	if r := VerifyEscalationAnswer(ans, Ed25519Pins(principal.Public), bind, now); !r.OK || r.Decision != "allow" {
		t.Fatalf("answer refused: %s", r.Reason)
	}
	bad := copyMap(ans)
	bad["decision"] = "deny"
	if r := VerifyEscalationAnswer(bad, Ed25519Pins(principal.Public), bind, now); r.OK {
		t.Fatal("a tampered answer verified")
	}

	issuer, _ := NewKeyPair()
	pp, err := IssuePassport(map[string]any{"model_id": "m", "operator": "acme", "hardware_rooted": false, "issued_at": 1_800_000_000_000})
	if err != nil {
		t.Fatal(err)
	}
	sp, err := SignPassport(pp, issuer, agentKey.Public, 0, 0, 1_800_003_600_000, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if why := VerifyPassport(sp, PassportOptions{TrustedIssuers: []string{issuer.Public}, NowMs: 1_800_000_000_500, Revoked: func(string, string, string) (bool, error) { return false, nil }}); why != "" {
		t.Fatalf("passport refused: %s", why)
	}
	hw, _ := IssuePassport(map[string]any{"model_id": "m", "operator": "acme", "hardware_rooted": true, "issued_at": 1})
	if _, err := SignPassport(hw, issuer, agentKey.Public, 0, 0, 99, nil, nil); err == nil {
		t.Fatal("a hardware-rooted passport was signed without evidence")
	}
}

func TestProducerRefusesBadInput(t *testing.T) {
	principal, _ := NewKeyPair()
	agentKey, _ := NewKeyPair()
	env := map[string]any{"predicates": []any{}, "caveats": []any{}, "risk_policy": map[string]any{}}
	if _, err := MintGrant(principal, agentKey.Public, env, "g", "", "", nil); err == nil {
		t.Fatal("a grant with an empty risk policy was minted")
	}
	env["risk_policy"] = DefaultRiskPolicy()
	if _, err := MintGrant(principal, agentKey.Public, env, "", "", "", nil); err == nil {
		t.Fatal("a grant without a goal was minted")
	}
	if _, _, err := signWithSuite(&SuiteOpts{Alg: "fn-dsa-512"}, agentKey, []byte("m")); err == nil {
		t.Fatal("signed with a verify-only suite")
	}
}

func TestPostQuantumSuites(t *testing.T) {
	cases := []struct{ alg, family string }{
		{"hybrid-ed25519-ml-dsa-65", "ML-DSA-65"},
		{"hybrid-nested-ed25519-ml-dsa-65", "ML-DSA-65"},
		{"ml-dsa-87", "ML-DSA-87"},
		{"hybrid-ed25519-slh-dsa-sha2-128f", "SLH-DSA-SHA2-128f"},
	}
	for _, c := range cases {
		t.Run(c.alg, func(t *testing.T) {
			pq, err := GeneratePqKeyPair(c.family)
			if err != nil {
				t.Fatal(err)
			}
			principal, _ := NewKeyPair()
			agentKey, _ := NewKeyPair()
			s := &SuiteOpts{Alg: c.alg, Pq: pq}
			grant := newGrant(t, principal, agentKey, pq.Public, nil)
			agent := NewAgent(agentKey, grant, "rs-test", 0)
			agent.Suite = s
			a, err := agent.Act("refund", "orders/1", nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			if a.PCActn["alg"] != c.alg {
				t.Fatalf("alg = %v", a.PCActn["alg"])
			}
			coreOK(t, a.PCActn, grant, c.alg)
			// a signature from another key pair of the family must not verify under the committed holder_pq
			other, _ := GeneratePqKeyPair(c.family)
			agent2 := NewAgent(agentKey, grant, "rs-test", 0)
			agent2.Suite = &SuiteOpts{Alg: c.alg, Pq: other}
			f, err := agent2.Act("refund", "orders/1", nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			if v, _ := VerifyPCActnCore(f.PCActn, grant, prodInt(t, f.PCActn["iat"]), "rs-test"); v.Allow {
				t.Fatal("a PQ key the holder did not commit to verified")
			}
		})
	}
}

// ---- exact-outcome kill tests for the refusal paths, counters, nonces and header encoding (mutation-tested module) ----

func wantErr(t *testing.T, err error, msg string) {
	t.Helper()
	if err == nil || err.Error() != msg {
		t.Fatalf("error = %v, want %q", err, msg)
	}
}

func prodEnv() map[string]any {
	return map[string]any{"predicates": []any{map[string]any{"verb": "v", "resource": "r"}}, "caveats": []any{}, "risk_policy": DefaultRiskPolicy()}
}

func rpWith(k string, v any) map[string]any {
	rp := DefaultRiskPolicy()
	rp[k] = v
	e := prodEnv()
	e["risk_policy"] = rp
	return e
}

func TestProducerSeedsAndSuites(t *testing.T) {
	for _, n := range []int{0, 31, 33} {
		_, err := KeyPairFromSeed(make([]byte, n))
		wantErr(t, err, "an Ed25519 seed is 32 bytes")
	}
	seed := make([]byte, 32)
	seed[0] = 1
	k, err := KeyPairFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := KeyPairFromSeedB64u(b64.EncodeToString(seed))
	if err != nil || k2.Public != k.Public || len(k.Sign([]byte("m"))) != 64 || string(k.Seed()) != string(seed) {
		t.Fatalf("seed round trip: %v", err)
	}
	_, err = KeyPairFromSeedB64u("AAAA")
	wantErr(t, err, "an Ed25519 seed is 32 canonical base64url bytes")
	for _, alg := range []string{"fn-dsa-512", "fn-dsa-1024", "less-cat1", "hybrid-ed25519-less-cat1"} {
		_, _, err := signWithSuite(&SuiteOpts{Alg: alg}, k, []byte("m"))
		wantErr(t, err, "unsupported_suite: "+alg)
		if !errors.Is(err, ErrUnsupportedSigner) {
			t.Fatalf("%s: not ErrUnsupportedSigner", alg)
		}
	}
	_, _, err = signWithSuite(&SuiteOpts{Alg: "rot13"}, k, []byte("m"))
	wantErr(t, err, `unknown signature alg "rot13"`)
	_, _, err = signWithSuite(nil, nil, []byte("m"))
	wantErr(t, err, "ed25519 needs an Ed25519 key")
	_, _, err = signWithSuite(&SuiteOpts{Alg: "ml-dsa-65"}, k, []byte("m"))
	wantErr(t, err, "ml-dsa-65 needs a matching post-quantum key pair")
	_, err = SignArtifact("d", map[string]any{"v": 1}, k, &SuiteOpts{Alg: "ml-dsa-65"})
	wantErr(t, err, "ml-dsa-65 needs a post-quantum key pair")
	a, err := SignArtifact("d", map[string]any{"v": 1}, k, &SuiteOpts{Alg: "ed25519"})
	if err != nil || len(a) != 2 || a["sig"] == nil {
		t.Fatalf("ed25519 artifact: %v %v", a, err)
	}
	if _, err := GeneratePqKeyPair("FN-DSA-512"); err == nil || err.Error() != "unsupported_suite: FN-DSA-512" {
		t.Fatalf("GeneratePqKeyPair FN-DSA: %v", err)
	}
}

func TestProducerMintGrantRefusals(t *testing.T) {
	p, _ := NewKeyPair()
	h, _ := NewKeyPair()
	mg := func(env map[string]any, goal string) error {
		_, err := MintGrant(p, h.Public, env, goal, "", "", nil)
		return err
	}
	wantErr(t, mg(prodEnv(), ""), "MintGrant: goal required")
	for _, k := range []string{"predicates", "caveats", "risk_policy"} {
		e := prodEnv()
		delete(e, k)
		wantErr(t, mg(e, "g"), "MintGrant: envelope."+k+" required")
	}
	wantErr(t, mg(rpWith("weights", map[string]any{}), "g"), "MintGrant: risk_policy.weights.alpha must be finite and >= 0")
	e := prodEnv()
	e["risk_policy"] = map[string]any{}
	wantErr(t, mg(e, "g"), "MintGrant: risk_policy.weights missing")
	w := DefaultRiskPolicy()["weights"].(map[string]any)
	w["alpha"] = -1
	wantErr(t, mg(rpWith("weights", w), "g"), "MintGrant: risk_policy.weights.alpha must be finite and >= 0")
	wantErr(t, mg(rpWith("theta1", "x"), "g"), "MintGrant: risk_policy.theta1 must be finite")
	wantErr(t, mg(rpWith("theta1", 0.7), "g"), "MintGrant: risk_policy requires 0 <= theta1 <= theta2")
	wantErr(t, mg(rpWith("theta1", -0.1), "g"), "MintGrant: risk_policy requires 0 <= theta1 <= theta2")
	wantErr(t, mg(rpWith("kappa", 0), "g"), "MintGrant: risk_policy.kappa must be > 0")
	wantErr(t, mg(rpWith("rho", -1), "g"), "MintGrant: risk_policy lambda/rho/bMax must be >= 0")
	e = prodEnv()
	e["model_polarity"] = "strict"
	wantErr(t, mg(e, "g"), "MintGrant: model_polarity must be 'legacy' when present")
	r, err := MintGrant(p, h.Public, prodEnv(), "g", "abc", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := GoalCommitOf("g", "abc")
	if r.GoalSalt != "abc" || r.GoalCommit != want {
		t.Fatalf("salt/commit: %s %s", r.GoalSalt, r.GoalCommit)
	}
	r2, _ := MintGrant(p, h.Public, prodEnv(), "g", "", "", nil)
	if b, ok := DecodeB64uStrict(r2.GoalSalt, 16); !ok || len(b) != 16 {
		t.Fatal("random salt is not 16 bytes")
	}
	cav := r.Grant["caveats"].([]any)[0].(map[string]any)
	if cav["type"] != "envelope" || len(cav["agent_binding"].(map[string]any)) != 0 {
		t.Fatalf("envelope caveat: %v", cav)
	}
}

func TestProducerDelegationAndPlanRefusals(t *testing.T) {
	p, _ := NewKeyPair()
	k, _ := NewKeyPair()
	r, _ := MintGrant(p, k.Public, prodEnv(), "g", "", "", nil)
	grant := r.Grant
	add := map[string]any{"type": "budget_alloc", "limit": 5}
	child, err := Delegate(grant, k, "", []any{add}, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	pc := grant["caveats"].([]any)
	cc := child["caveats"].([]any)
	if len(cc) != len(pc)+1 || child["holder"] != k.Public || child["issuer"] != k.Public {
		t.Fatalf("append-only: %v", child)
	}
	if h, _ := CapHash(grant); child["parent"] != h {
		t.Fatal("parent link")
	}
	if _, has := child["holder_pq"]; has {
		t.Fatal("holder_pq appeared")
	}
	rpq, _ := MintGrant(p, k.Public, prodEnv(), "g", "", "PQKEY", nil)
	if rpq.Grant["holder_pq"] != holderPqCommitment("PQKEY") {
		t.Fatal("holder_pq commitment")
	}
	same, _ := Delegate(rpq.Grant, k, "", nil, "", nil)
	other, _ := NewKeyPair()
	moved, _ := Delegate(rpq.Grant, k, other.Public, nil, "", nil)
	withPq, _ := Delegate(rpq.Grant, k, other.Public, nil, "OTHER", nil)
	if same["holder_pq"] != rpq.Grant["holder_pq"] || moved["holder_pq"] != nil || withPq["holder_pq"] != holderPqCommitment("OTHER") {
		t.Fatal("holder_pq carry rules")
	}

	node := map[string]any{"id": "a", "verb": "v", "resource": "r"}
	base := PCActnInput{Grant: grant, Chain: []map[string]any{grant}, Plan: []map[string]any{node}, NodeID: "a", Counter: 1, Signer: k, Aud: "x", Iat: 1000}
	with := func(f func(*PCActnInput)) error {
		in := base
		f(&in)
		_, err := BuildPCActn(in)
		return err
	}
	wantErr(t, with(func(i *PCActnInput) { i.Aud = "" }), "BuildPCActn: aud (audience) is required")
	wantErr(t, with(func(i *PCActnInput) { i.Signer = nil }), "BuildPCActn: signer required")
	wantErr(t, with(func(i *PCActnInput) { i.NodeID = "zz" }), "BuildPCActn: unknown plan node zz")
	pd, _ := ParamsDigest(map[string]any{"x": 1})
	wantErr(t, with(func(i *PCActnInput) {
		i.Plan = []map[string]any{{"id": "a", "verb": "v", "resource": "r", "params_digest": pd}}
		i.Params = map[string]any{"x": 2}
	}), "BuildPCActn: params do not match plan node a's params_digest")
	_, err = CommitPlan([]map[string]any{node, node})
	wantErr(t, err, "CommitPlan: duplicate node id a")
	_, err = CommitPlan(nil)
	wantErr(t, err, "CommitPlan: empty plan")
	x, err := BuildPCActn(base)
	if err != nil {
		t.Fatal(err)
	}
	if prodInt(t, x["iat"]) != 1000 || prodInt(t, x["exp"]) != 1000+20*60000 || prodInt(t, x["ver"]) != 2 || prodInt(t, x["counter"]) != 1 ||
		x["action"].(map[string]any)["reversibility_class"] != "reversible" {
		t.Fatalf("defaults: %v", x)
	}
	in := base
	in.Exp = 5000
	e1, _ := BuildPCActn(in)
	in = base
	in.TtlMs = 7
	e2, _ := BuildPCActn(in)
	in = base
	in.Extra = map[string]any{"nonce": "n", "caution": nil}
	e3, _ := BuildPCActn(in)
	if prodInt(t, e1["exp"]) != 5000 || prodInt(t, e2["exp"]) != 1007 || e3["nonce"] != "n" || e3["caution"] != nil {
		t.Fatal("exp / ttl / extra")
	}
	if _, has := e3["caution"]; has {
		t.Fatal("a nil extra slot was signed")
	}
}

func TestProducerCounterNonceAndHeaders(t *testing.T) {
	p, _ := NewKeyPair()
	k, _ := NewKeyPair()
	r, _ := MintGrant(p, k.Public, prodEnv(), "g", "", "", nil)
	var seen []int64
	agent := NewAgent(k, r.Grant, "rs", 41)
	agent.OnCounter = func(n int64) { seen = append(seen, n) }
	agent.Clock = func() int64 { return 5000 }
	var acts []*Action
	for i := 0; i < 3; i++ {
		a, err := agent.Act("v", "r", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		acts = append(acts, a)
	}
	nonces := map[any]bool{}
	for i, a := range acts {
		if prodInt(t, a.PCActn["counter"]) != int64(42+i) || seen[i] != int64(42+i) {
			t.Fatalf("counter %d: %v / %v", i, a.PCActn["counter"], seen)
		}
		nonces[a.PCActn["nonce"]] = true
		if b, ok := DecodeB64uStrict(a.PCActn["nonce"].(string), 16); !ok || len(b) != 16 {
			t.Fatal("nonce is not 16 bytes")
		}
		if prodInt(t, a.PCActn["iat"]) != 5000 || prodInt(t, a.PCActn["exp"]) != 5000+20*60000 || a.PCActn["aud"] != "rs" || a.NodeID != "n1" {
			t.Fatalf("freshness: %v", a.PCActn)
		}
	}
	if len(nonces) != 3 || len(seen) != 3 {
		t.Fatal("nonces repeat or hook count")
	}
	sub, _ := NewKeyPair()
	child, err := agent.Delegate(sub, nil)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := child.Act("v", "r", nil, nil)
	if prodInt(t, ca.PCActn["counter"]) != 1 || len(child.Chain) != 2 || len(agent.Chain) != 1 {
		t.Fatal("sub-agent counter / chain")
	}
	fx, _ := NewAgent(k, r.Grant, "rs", 0).Act("v", "r", nil, map[string]any{"nonce": "fixed"})
	if fx.PCActn["nonce"] != "fixed" {
		t.Fatal("explicit nonce ignored")
	}
	planned := NewAgent(k, r.Grant, "rs", 0)
	planned.UsePlan([]map[string]any{{"id": "a", "verb": "v", "resource": "r"}})
	_, err = planned.Act("v", "nope", nil, nil)
	wantErr(t, err, "Act: no node of the committed plan matches v nope")

	// header encoding
	a := acts[0]
	if len(a.Headers) != 1 {
		t.Fatalf("headers: %v", a.Headers)
	}
	h := a.Headers[PCAHeader]
	raw, ok := DecodeB64uStrict(h, -1)
	want, _ := Canonicalize(a.PCActn)
	if !ok || string(raw) != want || strings.Contains(h, "=") {
		t.Fatal("PCA-Action is not strict unpadded base64url of the canonical JSON")
	}
	full, err := PCAHeaders(a.PCActn, []map[string]any{{"d": 1}}, map[string]any{"n": 2}, map[string]any{"a": 3})
	if err != nil || len(full) != 4 {
		t.Fatalf("full headers: %v %v", full, err)
	}
	for name, body := range map[string]string{"PCA-Discharges": `[{"d":1}]`, "PCA-Narrow": `{"n":2}`, "PCA-Escalation-Answer": `{"a":3}`} {
		raw, ok := DecodeB64uStrict(full[name], -1)
		if !ok || string(raw) != body {
			t.Fatalf("%s = %q", name, raw)
		}
	}
	only, _ := PCAHeaders(a.PCActn, []map[string]any{}, nil, nil)
	if len(only) != 1 {
		t.Fatal("empty discharges produced a header")
	}
}

func TestProducerSignerAnswerAndPassportRefusals(t *testing.T) {
	k, _ := NewKeyPair()
	o, _ := NewKeyPair()
	body := map[string]any{"principal": k.Public}
	_, err := SignWorkflow(o, body)
	wantErr(t, err, "SignWorkflow: principal is not the signer")
	_, err = SignReadGrant(o, body)
	wantErr(t, err, "SignReadGrant: principal is not the signer")
	_, err = SignAggregateGrant(o, body)
	wantErr(t, err, "SignAggregateGrant: principal is not the signer")
	_, err = SignEscalationAnswer(o, map[string]any{"policy_digest": "a", "action_digest": "b", "history_head": "c"}, "maybe", 1, 2, "", nil)
	wantErr(t, err, "decision must be 'allow' or 'deny'")
	pp, _ := IssuePassport(map[string]any{"model_id": "m", "operator": "o", "hardware_rooted": false, "issued_at": 10})
	hw, _ := IssuePassport(map[string]any{"model_id": "m", "operator": "o", "hardware_rooted": true, "issued_at": 10})
	_, err = SignPassport(pp, o, k.Public, 0, 0, 10, nil, nil)
	wantErr(t, err, "SignPassport: exp must be after nbf")
	forged := copyMap(pp)
	forged["model_id"] = "other"
	_, err = SignPassport(forged, o, k.Public, 0, 0, 99, nil, nil)
	wantErr(t, err, "SignPassport: passport.id is not the fingerprint of its identity (use IssuePassport)")
	_, err = SignPassport(hw, o, k.Public, 0, 0, 99, nil, nil)
	wantErr(t, err, "SignPassport: hardware_rooted requires attestation evidence (fail closed)")
	sp, err := SignPassport(pp, o, k.Public, 0, 0, 99, nil, nil)
	if err != nil || prodInt(t, sp["iat"]) != 10 || prodInt(t, sp["nbf"]) != 10 || prodInt(t, sp["exp"]) != 99 {
		t.Fatalf("passport window: %v %v", sp, err)
	}
	sp2, _ := SignPassport(pp, o, k.Public, 20, 30, 99, nil, nil)
	if prodInt(t, sp2["nbf"]) != 30 {
		t.Fatal("explicit nbf ignored")
	}
}
