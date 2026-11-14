package pca

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// The agent side beyond the grant / action core: replays the newer producer vectors (signers, recorder, facade), the
// deterministic post-quantum vectors byte for byte, and writes this SDK's post-quantum output for the reference to verify.

// vectorBody is a fresh copy of the first producer vector body of op, with principal as its principal.
func vectorBody(t *testing.T, op string, principal *KeyPair) map[string]any {
	t.Helper()
	for _, c := range loadProducer(t).cases {
		cm := c.(map[string]any)
		if cm["op"] == op {
			b := cm["args"].(map[string]any)["body"].(map[string]any)
			b["principal"] = principal.Public
			return b
		}
	}
	t.Fatalf("no %s vector", op)
	return nil
}

// producerErrorText are the ops whose refusal text must match the reference; every other refusal only has to refuse.
var producerErrorText = map[string]bool{"parse_limit": true, "compile_policy": true}

func prodStrs(v any) []string {
	out := []string{}
	l, _ := v.([]any)
	for _, x := range l {
		out = append(out, x.(string))
	}
	return out
}

// ---- deterministic post-quantum vectors ------------------------------------------------------------------------------------------

func TestProducerPqVectors(t *testing.T) {
	raw, err := os.ReadFile(dir + "producer-pq-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	v, err := ParseJSONLenient(raw)
	if err != nil {
		t.Fatal(err)
	}
	doc := v.(map[string]any)
	for n, k := range doc["ed_keys"].(map[string]any) {
		km := k.(map[string]any)
		kp, err := KeyPairFromSeedB64u(prodStr(km, "seed"))
		if err != nil || kp.Public != prodStr(km, "public") {
			t.Fatalf("ed key %s: %v", n, err)
		}
	}
	for n, k := range doc["pq_keys"].(map[string]any) {
		km := k.(map[string]any)
		fam, ok := pqVectorFamilies[prodStr(km, "family")]
		if !ok {
			continue // FN-DSA: neither signed nor verified here
		}
		seed, _ := DecodeB64uStrict(prodStr(km, "seed"), -1)
		kp, err := GeneratePqKeyPairFromSeed(fam, seed)
		if err != nil || kp.Public != prodStr(km, "public") {
			t.Fatalf("pq key %s: public key differs from the reference keygen (%v)", n, err)
		}
	}
	ran := 0
	for _, c := range doc["cases"].([]any) {
		cm := c.(map[string]any)
		if !contains(prodStrs(cm["exact"]), "go") {
			continue
		}
		name, a := prodStr(cm, "name"), cm["args"].(map[string]any)
		got, err := ProduceVector(prodStr(cm, "op"), a, doc["ed_keys"].(map[string]any), doc["pq_keys"].(map[string]any))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		assertSameJSON(t, name, got, cm["expect"])
		ran++
	}
	if ran < 60 {
		t.Fatalf("only %d post-quantum cases list go as exact", ran)
	}
}

func assertSameJSON(t *testing.T, name string, got, want any) {
	t.Helper()
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

func TestPqSeedKeygen(t *testing.T) {
	for fam, n := range map[string]int{"ML-DSA-65": 32, "ML-DSA-87": 32, "SLH-DSA-SHA2-128f": 48, "SLH-DSA-SHA2-256s": 96} {
		_, err := GeneratePqKeyPairFromSeed(fam, make([]byte, n-1))
		wantErr(t, err, "a "+fam+" seed is "+itoa(n)+" bytes")
		seed := make([]byte, n)
		seed[0] = 7
		k1, err := GeneratePqKeyPairFromSeed(fam, seed)
		if err != nil {
			t.Fatal(err)
		}
		k2, _ := GeneratePqKeyPairFromSeed(fam, seed)
		s1, _ := k1.sign([]byte("m"))
		s2, _ := k2.sign([]byte("m"))
		if k1.Public != k2.Public || string(s1) != string(s2) {
			t.Fatalf("%s: seeded keygen or signing is not deterministic", fam)
		}
		r, _ := GeneratePqKeyPair(fam)
		if r.Public == k1.Public {
			t.Fatalf("%s: a random key repeated a seeded one", fam)
		}
	}
	_, err := GeneratePqKeyPairFromSeed("fn-dsa-512", make([]byte, 32))
	wantErr(t, err, "unsupported_suite: fn-dsa-512")
	if !errors.Is(err, ErrUnsupportedSigner) {
		t.Fatal("not ErrUnsupportedSigner")
	}
}

// ---- the sub-agent keeps its own PQ key (it used to sign with its parent's) ----------------------------------------------------

func TestPqSubAgentSignsWithItsOwnKey(t *testing.T) {
	for _, c := range []struct{ alg, family string }{{"ml-dsa-65", "ML-DSA-65"}, {"hybrid-ed25519-ml-dsa-65", "ML-DSA-65"}, {"hybrid-ed25519-slh-dsa-sha2-128f", "SLH-DSA-SHA2-128f"}} {
		principal, _ := NewKeyPair()
		agentKey, _ := NewKeyPair()
		subKey, _ := NewKeyPair()
		agentPq, _ := GeneratePqKeyPair(c.family)
		subPq, _ := GeneratePqKeyPair(c.family)
		grant := newGrant(t, principal, agentKey, agentPq.Public, nil)
		parent := NewAgent(agentKey, grant, "rs-test", 0)
		parent.Suite = &SuiteOpts{Alg: c.alg, Pq: agentPq}
		child, err := parent.DelegatePq(subKey, subPq, nil)
		if err != nil {
			t.Fatal(err)
		}
		hop := child.Chain[1]
		if hop["holder_pq"] != holderPqCommitment(subPq.Public) || child.Suite.Pq != subPq || child.Suite.Alg != c.alg {
			t.Fatalf("%s: the hop does not commit the sub-agent's PQ key", c.alg)
		}
		a, err := child.Act("refund", "orders/1", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if a.PCActn["pq_pk"] != subPq.Public {
			t.Fatalf("%s: the sub-agent signed with %v", c.alg, a.PCActn["pq_pk"])
		}
		coreOK(t, a.PCActn, grant, c.alg+" sub-agent")
		// the old behaviour: the sub-agent signing with the parent's PQ key is refused
		old := &Agent{Key: subKey, Grant: grant, Chain: child.Chain, Aud: "rs-test", Suite: parent.Suite, Clock: child.Clock}
		f, err := old.Act("refund", "orders/1", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if v, _ := verifyCoreSkipPlan(f.PCActn, grant, prodInt(t, f.PCActn["iat"]), "rs-test"); v.Allow {
			t.Fatalf("%s: a sub-agent leaf under the parent's PQ key verified", c.alg)
		}
		// without its own PQ key the sub-agent is Ed25519 only
		ed, err := parent.Delegate(subKey, nil)
		if err != nil || ed.Suite != nil {
			t.Fatalf("%s: Delegate kept the PQ suite: %v", c.alg, err)
		}
		if _, has := ed.Chain[1]["holder_pq"]; has {
			t.Fatal("an Ed25519 sub-agent hop carries holder_pq")
		}
		other, _ := GeneratePqKeyPair("ML-DSA-87")
		_, err = parent.DelegatePq(subKey, other, nil)
		wantErr(t, err, "DelegatePq: the sub-agent's PQ key does not match the suite "+c.alg)
	}
	ed := NewAgent(mustKey(t), newGrant(t, mustKey(t), mustKey(t), "", nil), "rs", 0)
	pq, _ := GeneratePqKeyPair("ML-DSA-65")
	_, err := ed.DelegatePq(mustKey(t), pq, nil)
	wantErr(t, err, "DelegatePq: the sub-agent's PQ key does not match the suite ed25519")
}

func mustKey(t *testing.T) *KeyPair {
	t.Helper()
	k, err := NewKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// ---- MintGrant validates the optional envelope members like the reference -----------------------------------------------------

func TestMintGrantEnvelopeMembers(t *testing.T) {
	k := mustKey(t)
	with := func(member string, v any) map[string]any {
		e := prodEnv()
		e[member] = v
		return e
	}
	for _, c := range []struct {
		member string
		v      any
		msg    string
	}{
		{"units", nil, "MintGrant: units must be an object"},
		{"units", map[string]any{"amount": map[string]any{"kind": "money"}}, "MintGrant: units key 'amount' must be an action.params.<name> path"},
		{"tighten", nil, "MintGrant: tighten must be an array"},
		{"tighten", map[string]any{}, "MintGrant: tighten must be an array"},
		{"actions", nil, "MintGrant: actions must be an object"},
		{"provenance", nil, "MintGrant: " + ProvEnvelopeError(nil)},
		{"model_polarity", nil, "MintGrant: model_polarity must be 'legacy' when present"},
	} {
		_, err := MintGrant(k, k.Public, with(c.member, c.v), "g", "s", "", nil)
		wantErr(t, err, c.msg)
	}
	_, err := MintGrant(k, k.Public, with("template_ref", nil), "g", "s", "", nil)
	wantErr(t, err, "MintGrant: "+TemplateRefError(nil))
	// a present null of a member without a validator is signed as null, as the reference keeps it
	r, err := MintGrant(k, k.Public, with("objective_risk", nil), "g", "s", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	env := r.Grant["caveats"].([]any)[0].(map[string]any)
	if v, has := env["objective_risk"]; !has || v != nil {
		t.Fatalf("objective_risk: %v %v", v, has)
	}
	units := map[string]any{"action.params.amount": map[string]any{"kind": "money", "currency": "USD", "exponent": 2}}
	r, err = MintGrant(k, k.Public, with("units", units), "g", "s", "", nil)
	if err != nil || !reflect.DeepEqual(r.Grant["caveats"].([]any)[0].(map[string]any)["units"], mustNorm(t, units)) {
		t.Fatalf("valid units: %v", err)
	}
}

func mustNorm(t *testing.T, v any) any {
	t.Helper()
	n, err := NormalizeJSON(v)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// ---- the new signers: refusals and round trips ------------------------------------------------------------------------------

func TestMoreSignersRefuse(t *testing.T) {
	k := mustKey(t)
	_, err := SignPqBinding(k, "pk", 0, "aud")
	wantErr(t, err, "SignPqBinding: epoch must be a positive safe integer")
	_, err = SignPqBinding(k, "pk", 1<<53, "aud")
	wantErr(t, err, "SignPqBinding: epoch must be a positive safe integer")
	_, err = SignPqBinding(k, "pk", 1, "")
	wantErr(t, err, "SignPqBinding: aud (the instance/audience id) is required")
	b, err := SignPqBinding(k, "pk", 9007199254740991, "a")
	if err != nil || prodInt(t, mustNorm(t, b).(map[string]any)["epoch"]) != 9007199254740991 {
		t.Fatalf("max epoch: %v", err)
	}
	for _, c := range []struct {
		body map[string]any
		msg  string
	}{
		{map[string]any{"caution": 0.5, "holder": k.Public}, "action_digest required"},
		{map[string]any{"action_digest": "", "caution": 0.5, "holder": k.Public}, "action_digest required"},
		{map[string]any{"action_digest": "d", "caution": 0.5}, "holder required"},
		{map[string]any{"action_digest": "d", "caution": 1.5, "holder": k.Public}, "caution must be a finite number in [0,1]"},
		{map[string]any{"action_digest": "d", "caution": -0.1, "holder": k.Public}, "caution must be a finite number in [0,1]"},
		{map[string]any{"action_digest": "d", "caution": "0.5", "holder": k.Public}, "caution must be a finite number in [0,1]"},
		{map[string]any{"action_digest": "d", "caution": 0, "holder": k.Public, "reason": "has space"}, "invalid reason"},
		{map[string]any{"action_digest": "d", "caution": 0, "holder": k.Public, "reason": strings.Repeat("a", 65)}, "invalid reason"},
		{map[string]any{"action_digest": "d", "caution": 0, "holder": k.Public, "reason": 3}, "invalid reason"},
	} {
		_, err := SignCaution(k, c.body)
		wantErr(t, err, "SignCaution: "+c.msg)
	}
	cl, err := SignCaution(k, map[string]any{"action_digest": "d", "caution": 1, "holder": k.Public, "reason": strings.Repeat("a", 64), "extra": true})
	if err != nil || len(cl) != 5 || cl["extra"] != nil {
		t.Fatalf("caution clean body: %v %v", cl, err)
	}
	hb, err := SignHeartbeat(k, map[string]any{"cap_id": "c", "seq": 1, "at": 2, "holder": k.Public, "x": 1})
	if err != nil || len(hb) != 5 || hb["x"] != nil || hb["lease_issued_at"] != nil {
		t.Fatalf("heartbeat members: %v %v", hb, err)
	}
	set := []any{map[string]any{"role": "agent", "publicKey": k.Public}}
	for _, tt := range []int{0, 4} {
		_, err = ShareMessage("agent", []byte("m"), set, tt, "")
		wantErr(t, err, "ShareMessage: t must be 1, 2 or 3")
	}
	_, err = ShareMessage("agent", []byte("m"), []any{"x"}, 1, "")
	wantErr(t, err, "ShareMessage: malformed signer set")
	_, err = SignThresholdShare("agent", k, []byte("m"), set, 1, &SuiteOpts{Alg: "rot13"})
	wantErr(t, err, `unknown signature alg "rot13"`)
	_, err = SignPreparedShare("agent", k, []byte("m"), &SuiteOpts{Alg: "rot13"})
	wantErr(t, err, `unknown signature alg "rot13"`)
	_, err = SignPreparedShare("agent", nil, []byte("m"), nil)
	wantErr(t, err, "SignPreparedShare: a share needs the role's Ed25519 key")
	_, err = SignPreparedShare("agent", k, []byte("m"), &SuiteOpts{Alg: "fn-dsa-512"})
	wantErr(t, err, "unsupported_suite: fn-dsa-512")
	plain, _ := ShareMessage("agent", []byte("m"), set, 2, "ed25519")
	tagged, _ := ShareMessage("agent", []byte("m"), set, 2, "ml-dsa-65")
	if string(tagged) != string(plain)+"\x00atlas-pca/share-suite/v1\x00ml-dsa-65" || plain[len(plain)-1] != 2 {
		t.Fatal("share message suite tag")
	}
	_, err = SignMeshAction(nil, map[string]any{}, k)
	wantErr(t, err, "SignMeshAction: empty chain")
	_, err = SignTemplate(map[string]any{"v": 2}, k)
	wantErr(t, err, "SignTemplate: template v / kind mismatch")
	_, err = SignTighten(map[string]any{"v": 2}, k)
	wantErr(t, err, "SignTighten: overlay v / kind mismatch")
	_, _, err = MintSessionGrant(SessionGrantInput{Principal: k, Holder: k.Public, Session: "s"})
	wantErr(t, err, "MintSessionGrant: intent_session caveat: session and root must be canonical base64url (32 bytes)")
	dg := b64.EncodeToString(make([]byte, 32))
	_, _, err = MintSessionGrant(SessionGrantInput{Principal: k, Holder: k.Public, Session: dg, Root: dg, Seq: 1})
	wantErr(t, err, "MintSessionGrant: intent_session caveat: prev is present exactly when seq > 0")
	_, _, err = MintSessionGrant(SessionGrantInput{Principal: k, Holder: k.Public, Session: dg, Root: dg, MapDigest: "x"})
	wantErr(t, err, "MintSessionGrant: mapDigest must be canonical base64url (32 bytes)")
	g, salt, err := MintSessionGrant(SessionGrantInput{Principal: k, Holder: k.Public, Session: dg, Root: dg, MapDigest: dg})
	if err != nil || len(salt) != 22 || len(g["caveats"].([]any)) != 2 {
		t.Fatalf("session grant: %v", err)
	}
	env := g["caveats"].([]any)[0].(map[string]any)
	if !reflect.DeepEqual(env["risk_policy"], mustNorm(t, DefaultRiskPolicy())) || len(env["predicates"].([]any)) != 0 || len(env["agent_binding"].(map[string]any)) != 0 {
		t.Fatalf("session grant defaults: %v", env)
	}
	if want, _ := intentGoalCommitV2(dg, dg, salt, false); env["goal_commit"] != want {
		t.Fatal("session grant goal")
	}
}

func TestSessionRootRefusals(t *testing.T) {
	d := loadProducer(t)
	var body map[string]any
	for _, c := range d.cases {
		if cm := c.(map[string]any); cm["op"] == "sign_session_root" {
			body = cm["args"].(map[string]any)["body"].(map[string]any)
		}
	}
	if body == nil {
		t.Skip("the session root vector is not in producer-vectors.json yet")
	}
	k := mustKey(t)
	_, err := SignSessionRoot(k, body, nil)
	wantErr(t, err, "SignSessionRoot: the signer is not one of the session principals")
	x := copyMap(body)
	x["signer"] = k.Public
	_, err = SignSessionRoot(k, x, nil)
	wantErr(t, err, "SignSessionRoot: session root: unknown member 'signer'")
	y := copyMap(body)
	y["question_uri"] = ""
	_, err = SignSessionRoot(d.keys["principal"], y, nil)
	wantErr(t, err, "SignSessionRoot: question_uri must be a non-empty string")
	pq, _ := GeneratePqKeyPair("ML-DSA-65")
	r, err := SignSessionRoot(d.keys["principal"], body, &SuiteOpts{Alg: "ml-dsa-65", Pq: pq})
	if err != nil {
		t.Fatal(err)
	}
	if why := verifySessionRoot(mustNorm(t, r), map[string]any{d.keys["principal"].Public: pq.Public}); why != "" {
		t.Fatalf("a PQ session root does not verify: %s", why)
	}
}

func TestProducerPolicyAndLimits(t *testing.T) {
	for in, want := range map[string]ParsedLimit{
		"$500/day": {500, "usd", 86_400_000}, " $12.50 ": {12.5, "usd", 0}, "10 / Hours": {10, "count", 3_600_000}, "3": {3, "count", 0},
		"\u00a0$1/mo\ufeff": {1, "usd", 2_592_000_000}, "2/W": {2, "count", 604_800_000},
	} {
		got, err := ParseLimit(in)
		if err != nil || got != want {
			t.Fatalf("ParseLimit(%q) = %v %v", in, got, err)
		}
	}
	for in, msg := range map[string]string{
		"  ": "parseLimit: empty limit", "": "parseLimit: empty limit", strings.Repeat("1", 65): "parseLimit: limit is longer than 64 characters",
		"five dollars": "parseLimit: cannot parse limit 'five dollars'", "$5/fortnight": "parseLimit: unknown period 'fortnight' in '$5/fortnight'",
		"5/constructor": "parseLimit: unknown period 'constructor' in '5/constructor'", "$-5": "parseLimit: cannot parse limit '$-5'",
		"1\u0085": "parseLimit: cannot parse limit '1\u0085'", "5//day": "parseLimit: cannot parse limit '5//day'",
	} {
		_, err := ParseLimit(in)
		wantErr(t, err, msg)
	}
	if _, err := ParseLimit(strings.Repeat("1", 64)); err != nil {
		t.Fatal("64 characters is the limit, not over it")
	}
	pol, err := CompilePolicy(PolicyOptions{Permissions: map[string][]string{"stripe": {"refund", "charge"}, "gmail": {"draft"}, "slack": {"post_message"}},
		Limits: map[string]string{"issue_refund": "$500/day", "stripe.charge": "$200", "post_message": "10/hour"}, Now: 1000})
	if err != nil {
		t.Fatal(err)
	}
	wantPreds := []any{
		map[string]any{"verb": "gmail.draft", "resource": "*"},
		map[string]any{"verb": "slack.post_message", "resource": "*"},
		map[string]any{"verb": "stripe.refund", "resource": "*", "where": []any{map[string]any{"field": "action.params.amount", "op": "lte", "value": 500}, map[string]any{"field": "action.params.amount", "op": "gte", "value": 0}}},
		map[string]any{"verb": "stripe.charge", "resource": "*", "where": []any{map[string]any{"field": "action.params.amount", "op": "lte", "value": 200}, map[string]any{"field": "action.params.amount", "op": "gte", "value": 0}}},
	}
	wantCav := []any{map[string]any{"type": "reversibility_max", "class": "irreversible"}, map[string]any{"type": "expires", "at": 1000 + 3_600_000},
		map[string]any{"type": "rate", "max": 10, "per_secs": 3600}}
	wantRP := map[string]any{"weights": map[string]any{"alpha": 0, "beta": 0, "gamma": 1, "delta": 0, "epsilon": 0, "zeta": 0}, "theta1": 0.25, "theta2": 0.6,
		"kappa": 500, "lambda": 0, "rho": 0.5, "bMax": 700}
	assertSameJSON(t, "compile", pol.JSON(), map[string]any{"predicates": wantPreds, "caveats": wantCav, "riskPolicy": wantRP, "budgetModel": "dollars",
		"limits": map[string]any{"stripe.refund": map[string]any{"amount": 500, "unit": "usd", "periodMs": 86_400_000}, "slack.post_message": map[string]any{"amount": 10, "unit": "count", "periodMs": 3_600_000},
			"stripe.charge": map[string]any{"amount": 200, "unit": "usd"}},
		"approximations": []any{"stripe.refund: $500/period is a per-call ceiling plus a one-period grant lifetime, not a renewing window cap"}})
	// reversible only: within-cap actions auto-approve
	pol, _ = CompilePolicy(PolicyOptions{Permissions: map[string][]string{"files": {"read"}, "http": {"get"}}, Limits: map[string]string{"toString": "$1"}, Now: 1})
	if pol.BudgetModel != "risk" || len(pol.Caveats) != 1 || !reflect.DeepEqual(pol.RiskPolicy, mustNorm(t, DefaultRiskPolicy())) {
		t.Fatalf("no matching limit: %v", pol.JSON())
	}
	pol, _ = CompilePolicy(PolicyOptions{Permissions: map[string][]string{"gmail": {"draft"}, "stripe": {"create_customer"}, "x": {"y"}}, Now: 1,
		RiskPolicy: map[string]any{"theta2": 0.9, "weights": map[string]any{"zeta": 0.5}}, BudgetModel: "dollars"})
	rp := pol.RiskPolicy
	if pol.BudgetModel != "dollars" || pol.Actions[2].Verb != "x.y" || pol.Actions[2].Reversibility != "irreversible" || pol.Actions[2].BlastRadius != 0.8 ||
		rp["theta2"] != mustNorm(t, 0.9) || rp["weights"].(map[string]any)["zeta"] != mustNorm(t, 0.5) || rp["weights"].(map[string]any)["alpha"] != mustNorm(t, 0.25) {
		t.Fatalf("override / uncatalogued: %v", pol.JSON())
	}
	pol, _ = CompilePolicy(PolicyOptions{Permissions: map[string][]string{"gmail": {"draft"}}, Limits: map[string]string{"draft": "$5"}, Now: 1})
	if pol != nil {
		t.Fatal("a $ limit on a verb without an amount field compiled")
	}
	for _, c := range []struct {
		o   PolicyOptions
		msg string
	}{
		{PolicyOptions{Permissions: map[string][]string{"gmail": {"send"}}, Limits: map[string]string{"send": "$10"}}, "compilePolicy: '$' limit on 'gmail.send' but the catalog gives that verb no amount field, so the limit could not be enforced"},
		{PolicyOptions{Permissions: map[string][]string{}}, "compilePolicy: no permissions granted"},
		{PolicyOptions{}, "compilePolicy: no permissions granted"},
		{PolicyOptions{Permissions: map[string]any{"a": "b"}}, "compilePolicy: permissions.a must be an array"},
		{PolicyOptions{Permissions: []any{}}, "compilePolicy: permissions must be an object"},
		{PolicyOptions{Permissions: map[string][]string{"files": {"read"}}, Limits: map[string]string{"read": "x"}}, "parseLimit: cannot parse limit 'x'"},
		{PolicyOptions{Permissions: map[string][]string{"files": {"read"}}, RiskPolicy: map[string]any{"kappa": 0}}, "compilePolicy: derived risk policy invalid: risk_policy.kappa must be > 0"},
	} {
		_, err := CompilePolicy(c.o)
		wantErr(t, err, c.msg)
	}
	// parsed JSON keeps the reference's key order
	perms, _ := ParseJSONLenient([]byte(`{"stripe":["refund"],"gmail":["draft"]}`))
	pol, _ = CompilePolicy(PolicyOptions{Permissions: perms, Now: 1})
	if pol.Actions[0].Verb != "stripe.refund" || pol.Actions[1].Verb != "gmail.draft" {
		t.Fatal("permissions order")
	}
	c := DefaultCatalog()
	if a, ok := c.Resolve("stripe", "issue_refund"); !ok || a.Verb != "stripe.refund" {
		t.Fatal("alias")
	}
	twins := NewCatalog([]CatalogAction{{Connector: "c", Action: "a", Verb: "c.a", Aliases: []string{"z"}}, {Connector: "c", Action: "b", Verb: "c.b", Aliases: []string{"z"}}})
	if _, ok := twins.Resolve("c", "z"); ok {
		t.Fatal("an ambiguous alias resolved")
	}
	if s := specFor(c, "solo"); s.Connector != "solo" || s.Action != "solo" || s.Description != "(uncatalogued) solo" {
		t.Fatalf("uncatalogued: %v", s)
	}
}

func TestCatalogMatchesReference(t *testing.T) {
	src, err := os.ReadFile("../../packages/pca/src/catalog-builtin.generated.ts")
	if err != nil {
		t.Skip("the reference catalog source is not beside this SDK")
	}
	text := string(src)
	text = text[strings.Index(text, "= [")+2 : strings.LastIndex(text, "];")+1]
	v, err := ParseJSONLenient([]byte(regexp.MustCompile(`,\s*\]`).ReplaceAllString(quoteKeys(text), "]")))
	if err != nil {
		t.Fatal(err)
	}
	ref := v.([]any)
	if len(ref) != len(BuiltinActions) {
		t.Fatalf("%d reference actions, %d here", len(ref), len(BuiltinActions))
	}
	for i, x := range ref {
		r := x.(map[string]any)
		g := BuiltinActions[i]
		al, _ := r["aliases"].([]any)
		blast, _ := numOf(r["blastRadius"])
		if g.Connector != r["connector"] || g.Action != r["action"] || g.Verb != r["verb"] || g.Reversibility != r["reversibility"] || g.BlastRadius != blast ||
			g.AmountField != prodStr(r, "amountField") || g.Description != r["description"] || !reflect.DeepEqual(g.Aliases, nilIfEmpty(prodStrs(al))) ||
			!reflect.DeepEqual(g.Traits, prodStrs(r["traits"])) {
			t.Fatalf("catalog entry %d (%s) differs from the reference", i, g.Verb)
		}
	}
}

func nilIfEmpty(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	return s
}

// quoteKeys turns the generated TypeScript object literals ({ connector: "x", ... }) into JSON.
func quoteKeys(s string) string {
	var b strings.Builder
	inStr := false
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if inStr {
			b.WriteByte(ch)
			if ch == '\\' && i+1 < len(s) {
				i++
				b.WriteByte(s[i])
			} else if ch == '"' {
				inStr = false
			}
			continue
		}
		if ch == '"' {
			inStr = true
			b.WriteByte(ch)
			continue
		}
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') {
			j := i
			for j < len(s) && ((s[j] >= 'a' && s[j] <= 'z') || (s[j] >= 'A' && s[j] <= 'Z')) {
				j++
			}
			if j < len(s) && s[j] == ':' {
				b.WriteString(`"` + s[i:j] + `"`)
				i = j - 1
				continue
			}
		}
		b.WriteByte(ch)
	}
	return b.String()
}

// ---- the facade end to end ----------------------------------------------------------------------------------------------------

func TestFacadeActVerifies(t *testing.T) {
	principal, holder, rk := mustKey(t), mustKey(t), mustKey(t)
	ag, err := CreateAgent(AgentOptions{Principal: principal, Holder: holder, Goal: "refund order 1", Permissions: map[string][]string{"stripe": {"refund"}, "gmail": {"draft"}},
		Limits: map[string]string{"refund": "$500/day"}, Aud: "rs-test", Now: 1_000_000, Provenance: &ProvenanceRecorderOptions{Key: rk}})
	if err != nil {
		t.Fatal(err)
	}
	if ag.Budget.B != 500 || ag.AutonomyBound != 500 || ag.Provenance.Pin.Mediator != "agent-harness" || ag.Provenance.Pin.Kid != "k1" || ag.Provenance.Pin.PK != rk.Public {
		t.Fatalf("agent: %+v", ag.Budget)
	}
	env := ag.Grant["caveats"].([]any)[0].(map[string]any)
	if !reflect.DeepEqual(env["provenance"], mustNorm(t, map[string]any{"mediators": []any{ag.Provenance.Pin.JSON()}})) {
		t.Fatal("the recorder pin is not in the grant")
	}
	if c, _ := GoalCommitOf("refund order 1", ag.GoalSalt); env["goal_commit"] != c {
		t.Fatal("goal commitment")
	}
	if _, err := ag.Provenance.Principal("refund order 1"); err != nil {
		t.Fatal(err)
	}
	r, err := ag.Act("stripe.refund", "charge:ch_1", map[string]any{"amount": 125, "currency": "usd"}, &ActOptions{Now: 2_000_000})
	if err != nil {
		t.Fatal(err)
	}
	p := r.PCActn
	if _, has := p["nonce"]; has {
		t.Fatal("the facade signed a nonce nobody asked for")
	}
	if prodInt(t, p["counter"]) != 1 || p["plan"].(map[string]any)["node_id"] != "n0" || prodInt(t, p["exp"]) != 2_000_000+DefaultTTLMs {
		t.Fatalf("pcactn: %v", p)
	}
	if !reflect.DeepEqual(p["risk_claim"], mustNorm(t, map[string]any{"r": 0.25, "inputs": map[string]any{"blastRadius": 0.25}})) ||
		p["action"].(map[string]any)["reversibility_class"] != "irreversible" {
		t.Fatalf("risk claim / class: %v", p["risk_claim"])
	}
	if r.DryRun != (DryRunResult{Allowed: true, T: 1}) {
		t.Fatalf("dry run: %+v", r.DryRun)
	}
	enc, _ := Canonicalize(p)
	if lenient, _ := canonicalLenient(p); r.Encoded != lenient || r.Headers[PCAHeader] != b64.EncodeToString([]byte(enc)) {
		t.Fatal("encoding / PCA-Action header")
	}
	pt, _ := Canonicalize(r.Provenance)
	if r.Headers[ProvenanceHeader] != b64.EncodeToString([]byte(pt)) || len(r.Provenance["receipts"].([]any)) != 2 {
		t.Fatal("PCA-Provenance header / bundle")
	}
	v, err := verifyCoreSkipPlan(p, ag.Grant, 2_000_000, "rs-test")
	if err != nil || !v.Allow {
		t.Fatalf("the facade's action does not verify: %v %v", err, v.Reason)
	}
	// counters: auto increments, an explicit one raises the floor
	five := int64(5)
	r5, _ := ag.Act("gmail.draft", "t", nil, &ActOptions{Counter: &five, Now: 2_000_000, Nonce: "n"})
	r6, _ := ag.Act("gmail.draft", "t", nil, &ActOptions{Now: 2_000_000})
	if prodInt(t, r5.PCActn["counter"]) != 5 || prodInt(t, r6.PCActn["counter"]) != 6 || r5.PCActn["nonce"] != "n" {
		t.Fatal("counter semantics")
	}
	if dr := ag.DryRun("stripe.refund", "charge:ch_1", map[string]any{"amount": 600}, 2_000_000); dr.Allowed || !strings.HasSuffix(dr.Reason, " not satisfied for stripe.refund on charge:ch_1") {
		t.Fatalf("over the cap: %+v", dr)
	}
	if dr := ag.DryRun("stripe.refund", "charge:ch_1", map[string]any{"amount": 1}, 1_000_000+86_400_000+1); dr.Allowed || dr.Reason != "caveat(s) failed: expires" {
		t.Fatalf("after the window: %+v", dr)
	}
	if dr := ag.DryRun("github.read", "r", nil, 2_000_000); dr.Allowed || dr.Reason != "no predicate permits github.read on r" {
		t.Fatalf("ungranted: %+v", dr)
	}
	_, err = (&FacadeAgent{Policy: ag.Policy, catalog: ag.catalog}).Act("gmail.draft", "t", nil, nil)
	wantErr(t, err, "Act: aud (resource-server / instance id) is required (pass ActOptions.Aud or AgentOptions.Aud)")
	risk := 0.7
	rr, _ := ag.Act("stripe.refund", "c", map[string]any{"amount": 1}, &ActOptions{Risk: &risk, Now: 2_000_000})
	if !reflect.DeepEqual(rr.PCActn["risk_claim"].(map[string]any)["r"], mustNorm(t, 0.7)) {
		t.Fatal("risk override")
	}

	// sub-agent: generated key, one more hop, shared recorder
	sub, err := ag.SubAgent(SubAgentOptions{AddedCaveats: []any{SealedCaveat()}})
	if err != nil {
		t.Fatal(err)
	}
	if len(sub.Chain) != 2 || sub.Holder.Public == holder.Public || sub.Provenance != ag.Provenance || sub.Chain[1]["holder"] != sub.Holder.Public {
		t.Fatal("sub-agent shape")
	}
	sr, err := sub.Act("stripe.refund", "charge:ch_2", map[string]any{"amount": 10}, &ActOptions{Now: 2_000_000})
	if err != nil {
		t.Fatal(err)
	}
	if v, err := verifyCoreSkipPlan(sr.PCActn, sub.Grant, 2_000_000, "rs-test"); err != nil || !v.Allow {
		t.Fatalf("the sub-agent's action does not verify: %v %v", err, v.Reason)
	}
	if prodInt(t, sr.PCActn["counter"]) != 1 {
		t.Fatal("the sub-agent has its own counter")
	}
	if g, _ := ag.EncodeGrant(); g == "" {
		t.Fatal("EncodeGrant")
	}
	_, err = CreateAgent(AgentOptions{Goal: "g"})
	wantErr(t, err, "CreateAgent: principal required")
	_, err = CreateAgent(AgentOptions{Principal: principal, Goal: "g", Permissions: map[string][]string{"files": {"read"}}, Suite: &SuiteOpts{Alg: "ml-dsa-65"}})
	wantErr(t, err, "CreateAgent: the suite ml-dsa-65 needs a matching post-quantum key pair the agent can sign with")
}

func TestFacadePostQuantumSubAgent(t *testing.T) {
	pq, _ := GeneratePqKeyPair("ML-DSA-65")
	ag, err := CreateAgent(AgentOptions{Principal: mustKey(t), Goal: "g", Permissions: map[string][]string{"files": {"read"}}, Aud: "rs-test", Now: 5,
		Suite: &SuiteOpts{Alg: "hybrid-ed25519-ml-dsa-65", Pq: pq}})
	if err != nil {
		t.Fatal(err)
	}
	if ag.Grant["holder_pq"] != holderPqCommitment(pq.Public) {
		t.Fatal("the grant does not commit the holder's PQ key")
	}
	sub, err := ag.SubAgent(SubAgentOptions{})
	if err != nil {
		t.Fatal(err)
	}
	r, err := sub.Act("files.read", "f", nil, &ActOptions{Now: 10})
	if err != nil {
		t.Fatal(err)
	}
	if r.PCActn["pq_pk"] == pq.Public || sub.Chain[1]["holder_pq"] != holderPqCommitment(r.PCActn["pq_pk"].(string)) {
		t.Fatal("the PQ sub-agent did not get its own key")
	}
	if v, err := verifyCoreSkipPlan(r.PCActn, ag.Grant, 10, "rs-test"); err != nil || !v.Allow {
		t.Fatalf("PQ sub-agent action: %v %v", err, v.Reason)
	}
	other, _ := GeneratePqKeyPair("ML-DSA-87")
	_, err = ag.SubAgent(SubAgentOptions{HolderPq: other})
	wantErr(t, err, "SubAgent: the sub-agent's PQ key does not match the suite hybrid-ed25519-ml-dsa-65")
}

// ---- the reverse direction: this SDK's post-quantum output for the reference verifier -------------------------------------------

// vectorArgs is a fresh copy of the args of the first non-refusal producer vector of op.
func vectorArgs(t *testing.T, op string) map[string]any {
	t.Helper()
	for _, c := range loadProducer(t).cases {
		cm := c.(map[string]any)
		if e, _ := cm["expect"].(map[string]any); cm["op"] == op && e["error"] == nil {
			return cm["args"].(map[string]any)
		}
	}
	t.Fatalf("no %s vector", op)
	return nil
}

// nativeArtifacts signs one of each artifact kind the reference checks, over the vector bodies (their times bracket the output file's now) re-pointed at fresh keys: the escalation
// answer and the revocation epoch under a hybrid suite, the rest Ed25519.
func nativeArtifacts(t *testing.T, aud string) []any {
	t.Helper()
	pq, err := GeneratePqKeyPair("ML-DSA-65")
	if err != nil {
		t.Fatal(err)
	}
	const alg = "hybrid-ed25519-ml-dsa-65"
	hy := &SuiteOpts{Alg: alg, Pq: pq}
	must := func(a map[string]any, err error) map[string]any {
		t.Helper()
		if err != nil {
			t.Fatalf("native artifact: %v", err)
		}
		return a
	}
	out := []any{}
	add := func(kind, alg string, artifact, pins map[string]any) {
		out = append(out, map[string]any{"kind": kind, "alg": alg, "artifact": artifact, "pins": pins})
	}
	k := mustKey(t)
	b := vectorArgs(t, "sign_escalation_answer")["body"].(map[string]any)
	b["principal"] = k.Public
	add("escalation_answer", alg, must(SignEscalationAnswer(k, b, prodStr(b, "decision"), prodInt(t, b["iat"]), prodInt(t, b["expires_at"]),
		prodStr(b, "nonce"), hy)), map[string]any{"pk": k.Public, "pq_pk": pq.Public})
	k = mustKey(t)
	b = vectorArgs(t, "sign_revocation_epoch")["body"].(map[string]any)
	add("revocation_epoch", alg, must(SignRevocationEpoch(k.Seed(), RevocationEpochBody{InstanceID: prodStr(b, "instance_id"),
		GrantRef: prodStr(b, "grant_ref"), Epoch: prodInt(t, b["epoch"]), SetSize: prodInt(t, b["set_size"]), Root: prodStr(b, "root"),
		IssuedAt: prodInt(t, b["issued_at"]), NotAfter: prodInt(t, b["not_after"])}, hy)), map[string]any{"pk": k.Public, "pq_pk": pq.Public})
	k = mustKey(t)
	b = vectorArgs(t, "sign_session_root")["body"].(map[string]any)
	b["principals"] = []any{map[string]any{"key": k.Public}}
	add("session_root", "ed25519", must(SignSessionRoot(k, b, nil)), map[string]any{"pk": k.Public})
	k = mustKey(t)
	a := vectorArgs(t, "sign_action_schema")
	add("action_schema", "ed25519", must(SignActionSchema(a["doc"].(map[string]any), prodStr(a, "kid"), k, nil)),
		map[string]any{"pk": k.Public, "kid": prodStr(a, "kid"), "alg": "ed25519"})
	k = mustKey(t)
	b = vectorArgs(t, "sign_labels")["body"].(map[string]any)
	add("labels", "ed25519", must(SignLabels(b, k, nil)), map[string]any{"pk": k.Public, "kid": prodStr(b, "kid"), "site": prodStr(b, "site")})
	k = mustKey(t)
	a = vectorArgs(t, "sign_intent_required")
	add("intent_required", "ed25519", must(SignIntentRequired(a["body"].(map[string]any), prodStr(a, "kid"), k, nil)),
		map[string]any{"pk": k.Public, "kid": prodStr(a, "kid"), "alg": "ed25519"})
	k = mustKey(t)
	add("fact", "ed25519", must(SignFact(vectorArgs(t, "sign_fact")["body"].(map[string]any), k, nil)), map[string]any{"pk": k.Public})
	k = mustKey(t)
	b = vectorArgs(t, "sign_caution")["body"].(map[string]any)
	b["holder"] = k.Public
	add("caution", "ed25519", must(SignCaution(k, b)), map[string]any{"pk": k.Public})
	k = mustKey(t)
	add("pq_binding", "ed25519", must(SignPqBinding(k, pq.Public, 1, aud)), map[string]any{"pk": k.Public})
	return out
}

// coreOKAud is coreOK for a PCActn addressed to aud.
func coreOKAud(t *testing.T, p, grant map[string]any, aud, label string) {
	t.Helper()
	v, err := verifyCoreSkipPlan(p, grant, prodInt(t, p["iat"]), aud)
	if err != nil {
		t.Fatalf("%s: %v", label, err)
	}
	if !v.Allow {
		t.Fatalf("%s: refused: %s", label, v.Reason)
	}
}

// TestProducerNativeOutput signs one PCActn per suite this SDK signs, a post-quantum sub-agent's PCActn and a facade act with
// params, checks each under this package's verifier, and (PCA_PRODUCER_OUT set) writes them for the reference to verify.
func TestProducerNativeOutput(t *testing.T) {
	const aud, now = "ins_producer_test", int64(1_800_000_000_000)
	cases := []any{}
	for _, c := range []struct{ alg, family string }{
		{"ml-dsa-65", "ML-DSA-65"}, {"hybrid-ed25519-ml-dsa-65", "ML-DSA-65"}, {"hybrid-nested-ed25519-ml-dsa-65", "ML-DSA-65"},
		{"ml-dsa-87", "ML-DSA-87"}, {"hybrid-ed25519-ml-dsa-87", "ML-DSA-87"}, {"slh-dsa-sha2-128f", "SLH-DSA-SHA2-128f"},
		{"hybrid-ed25519-slh-dsa-sha2-128f", "SLH-DSA-SHA2-128f"}, {"slh-dsa-sha2-256s", "SLH-DSA-SHA2-256s"}, {"hybrid-ed25519-slh-dsa-sha2-256s", "SLH-DSA-SHA2-256s"},
	} {
		pq, _ := GeneratePqKeyPair(c.family)
		agentKey := mustKey(t)
		grant := newGrant(t, mustKey(t), agentKey, pq.Public, nil)
		ag := NewAgent(agentKey, grant, aud, 0)
		ag.Suite, ag.Clock = &SuiteOpts{Alg: c.alg, Pq: pq}, func() int64 { return now }
		a, err := ag.Act("refund", "orders/1", map[string]any{"amount": 5}, nil)
		if err != nil {
			t.Fatal(err)
		}
		coreOKAud(t, a.PCActn, grant, aud, c.alg)
		cases = append(cases, map[string]any{"kind": "pcactn", "alg": c.alg, "grant": grant, "pcactn": a.PCActn})
		if c.alg == "hybrid-ed25519-ml-dsa-65" || c.alg == "slh-dsa-sha2-128f" {
			subPq, _ := GeneratePqKeyPair(c.family)
			child, err := ag.DelegatePq(mustKey(t), subPq, []any{SealedCaveat()})
			if err != nil {
				t.Fatal(err)
			}
			sa, err := child.Act("refund", "orders/1", map[string]any{"amount": 5}, nil)
			if err != nil {
				t.Fatal(err)
			}
			coreOKAud(t, sa.PCActn, grant, aud, c.alg+" sub-agent")
			cases = append(cases, map[string]any{"kind": "pcactn", "alg": c.alg + " (sub-agent)", "grant": grant, "pcactn": sa.PCActn})
		}
	}
	fa, err := CreateAgent(AgentOptions{Principal: mustKey(t), Goal: "refund", Permissions: map[string][]string{"stripe": {"refund"}}, Limits: map[string]string{"refund": "$500"},
		Aud: aud, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	r, err := fa.Act("stripe.refund", "charge:ch_1", map[string]any{"amount": 42, "currency": "usd"}, &ActOptions{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	coreOKAud(t, r.PCActn, fa.Grant, aud, "facade act")
	cases = append(cases, map[string]any{"kind": "pcactn", "alg": "ed25519 (facade act)", "grant": fa.Grant, "pcactn": r.PCActn})
	cases = append(cases, nativeArtifacts(t, aud)...)
	out := os.Getenv("PCA_PRODUCER_OUT")
	if out == "" {
		return
	}
	// Go values (int64 and friends) go through encoding/json first: Canonicalize takes JSON-decoded values only
	raw, err := json.Marshal(map[string]any{"lang": "go", "aud": aud, "now": now, "cases": cases})
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		t.Fatal(err)
	}
	doc, err := Canonicalize(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, []byte(doc+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestIntentRequiredAndProgressStepRefusals(t *testing.T) {
	k := mustKey(t)
	base := func() map[string]any { return vectorArgs(t, "sign_intent_required")["body"].(map[string]any) }
	coords := func(b map[string]any) map[string]any { return b["cell"].(map[string]any)["coords"].(map[string]any) }
	for _, c := range []struct {
		edit func(map[string]any)
		want string
	}{
		{func(b map[string]any) { b["extra"] = true }, "unknown member 'extra'"},
		{func(b map[string]any) { b["kind"] = "pca-labels" }, "not a pca-intent-required v1"},
		{func(b map[string]any) { b["v"] = json.Number("2") }, "not a pca-intent-required v1"},
		{func(b map[string]any) { b["schema"] = "abc" }, "schema must be canonical base64url (32 bytes)"},
		{func(b map[string]any) { b["cell"] = map[string]any{"verb": "", "coords": map[string]any{}} }, "cell must be {verb, coords}"},
		{func(b map[string]any) { b["cell"].(map[string]any)["coords"] = map[string]any{} }, "coords must be an object of 1..64 dimensions"},
		{func(b map[string]any) {
			coords(b)["action.params.amount_cents"] = []any{json.Number("5"), json.Number("1")}
		}, "coords 'action.params.amount_cents': need 0 <= lo <= hi"},
		{func(b map[string]any) { coords(b)["action.params.currency"] = []any{"USD", "USD"} }, "coords 'action.params.currency': values must be distinct"},
		{func(b map[string]any) { coords(b)["action.params.currency"] = []any{} }, "coords 'action.params.currency': an index range [lo, hi] or a value set"},
		{func(b map[string]any) { coords(b)[strings.Repeat("x", 257)] = []any{"a"} }, "a coordinate path must be 1..256 characters"},
		{func(b map[string]any) { b["reason"] = "sure" }, "reason must be 'uncertain'"},
		{func(b map[string]any) { b["question_id"] = "q 1" }, "question_id must match [A-Za-z0-9_-]{1,64}"},
		{func(b map[string]any) { b["friction"] = "swipe" }, "unknown friction tier"},
		{func(b map[string]any) { b["delivered_to"] = "email" }, "delivered_to must be 'wallet' or 'agent'"},
		{func(b map[string]any) { b["expires_at"] = json.Number("-1") }, "expires_at must be a non-negative safe integer"},
		{func(b map[string]any) { b["sig"] = map[string]any{} }, "an unsigned body must not carry sig"},
	} {
		b := base()
		c.edit(b)
		_, err := SignIntentRequired(b, "site-k1", k, nil)
		wantErr(t, err, "SignIntentRequired: "+c.want)
	}
	// -0 fails the reference's isInt (the coordinate is then neither a range nor a value set); the signer refuses it even
	// earlier, at the strict JSON boundary every signer applies
	neg := base()
	coords(neg)["action.params.amount_cents"] = []any{json.Number("-0"), json.Number("1")}
	if got := IntentRequiredShapeError(neg); got != "coords 'action.params.amount_cents': an index range [lo, hi] or a value set" {
		t.Fatalf("-0 coordinate: %q", got)
	}
	_, err := SignIntentRequired(neg, "site-k1", k, nil)
	wantErr(t, err, "strict JSON: negative zero is not allowed (at offset 113)")
	// 2^53 likewise fails the shape check, and the signer refuses it first at the strict JSON boundary
	big := base()
	big["expires_at"] = json.Number("9007199254740992")
	if got := IntentRequiredShapeError(big); got != "expires_at must be a non-negative safe integer" {
		t.Fatalf("2^53 expires_at: %q", got)
	}
	_, err = SignIntentRequired(big, "site-k1", k, nil)
	wantErr(t, err, "strict JSON: integer outside the safe range (at offset 222)")
	_, err = SignIntentRequired(base(), "site-k1", k, &SuiteOpts{Alg: "rot13"})
	wantErr(t, err, `SignIntentRequired: unknown signature alg "rot13"`)
	step := vectorArgs(t, "sign_progress_step")["step"].(map[string]any)
	delete(step, "digest")
	_, err = SignProgressStep(step, k)
	wantErr(t, err, "SignProgressStep: step.digest is required")
}
