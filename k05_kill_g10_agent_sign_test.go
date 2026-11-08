package pca

import (
	"crypto/rand"
	"errors"
	"reflect"
	"testing"
	"time"
)

func g10agKey(t *testing.T, b byte) *KeyPair {
	t.Helper()
	seed := make([]byte, 32)
	seed[0] = b
	k, err := KeyPairFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// g10agFakePq is a PQ key pair whose signer answers a fixed signature (or err).
func g10agFakePq(prim pqPrim, pub string, err error) *PqKeyPair {
	return &PqKeyPair{prim: prim, Public: pub, sign: func([]byte) ([]byte, error) {
		if err != nil {
			return nil, err
		}
		return []byte("pq-sig"), nil
	}}
}

type g10agBadReader struct{}

func (g10agBadReader) Read([]byte) (int, error) { return 0, errors.New("g10 rng down") }

func TestG10AgentKeysAndRandomness(t *testing.T) {
	a, err := NewKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	zero := g10agKey(t, 0)
	if a.Public == b.Public || a.Public == zero.Public {
		t.Fatal("NewKeyPair must draw a random seed")
	}
	if n1, n2 := randNonce(), randNonce(); n1 == n2 || len(n1) != 22 || n1 == "AAAAAAAAAAAAAAAAAAAAAA" {
		t.Fatalf("randNonce: %q %q", n1, n2)
	}

	kp, err := GeneratePqKeyPair("SLH-DSA-SHA2-256s")
	if err != nil {
		t.Fatal(err)
	}
	if pk, ok := DecodeB64uStrict(kp.Public, -1); kp.prim != pqSlh256s || !ok || len(pk) != 64 {
		t.Fatalf("SLH-DSA-SHA2-256s key: prim %v, %d bytes", kp.prim, len(pk))
	}

	// a failing randomness source is an error from every PQ key generator (nothing else runs while it is installed)
	old := rand.Reader
	rand.Reader = g10agBadReader{}
	var errs []error
	for _, f := range []string{"ML-DSA-65", "ML-DSA-87", "SLH-DSA-SHA2-128f"} {
		kp, err := GeneratePqKeyPair(f)
		if kp != nil {
			err = errors.New(f + ": returned a key")
		}
		errs = append(errs, err)
	}
	rand.Reader = old
	for _, err := range errs {
		g10agErr(t, "keygen with a failing RNG", err, "g10 rng down")
	}
}

func TestG10AgentSignWithSuite(t *testing.T) {
	k := g10agKey(t, 1)
	boom := errors.New("pq signer down")
	_, _, err := signWithSuite(&SuiteOpts{Alg: "ml-dsa-65", Pq: g10agFakePq(pqMlDsa65, "P", boom)}, k, []byte("m"))
	g10agErr(t, "pure PQ signer error", err, "pq signer down")
	_, _, err = signWithSuite(&SuiteOpts{Alg: "hybrid-ed25519-ml-dsa-65", Pq: g10agFakePq(pqMlDsa65, "P", boom)}, k, []byte("m"))
	g10agErr(t, "hybrid PQ signer error", err, "pq signer down")
	_, _, err = signWithSuite(&SuiteOpts{Alg: "hybrid-ed25519-ml-dsa-65", Pq: g10agFakePq(pqMlDsa65, "P", nil)}, nil, []byte("m"))
	g10agErr(t, "hybrid without an Ed25519 key", err, "hybrid-ed25519-ml-dsa-65 needs an Ed25519 key")

	_, err = SignArtifact("d", map[string]any{"x": make(chan int)}, k, nil)
	g10agErr(t, "SignArtifact chan", err, g10agChanErr)
	_, err = SignArtifact("d", map[string]any{}, k, &SuiteOpts{Alg: "ml-dsa-65", Pq: g10agFakePq(pqMlDsa65, g10agLone, nil)})
	g10agErr(t, "SignArtifact non-canonical pq_pk", err, g10agLoneErr)
	_, err = SignArtifact("d", map[string]any{}, nil, nil)
	g10agErr(t, "SignArtifact without a key", err, "ed25519 needs an Ed25519 key")
	_, err = signBody(k, "d", map[string]any{"x": g10agLone})
	g10agErr(t, "signBody", err, g10agLoneErr)

	_, err = SignPCActn(map[string]any{}, k, &SuiteOpts{Alg: "ml-dsa-65"})
	g10agErr(t, "SignPCActn suite without PQ key", err, "ml-dsa-65 needs a post-quantum key pair")
	_, err = SignPCActn(map[string]any{"x": make(chan int)}, k, nil)
	g10agErr(t, "SignPCActn chan", err, "canonicalize: unsupported type chan int")
	_, err = SignPCActn(map[string]any{}, nil, nil)
	g10agErr(t, "SignPCActn without a key", err, "ed25519 needs an Ed25519 key")

	bad := map[string]any{"x": g10agLone}
	ok := map[string]any{"x": "y"}
	for name, f := range map[string]func() error{
		"pcactn":     func() error { _, err := PCAHeaders(bad, nil, nil, nil); return err },
		"discharges": func() error { _, err := PCAHeaders(ok, []map[string]any{bad}, nil, nil); return err },
		"narrow":     func() error { _, err := PCAHeaders(ok, nil, bad, nil); return err },
		"answer":     func() error { _, err := PCAHeaders(ok, nil, nil, bad); return err },
	} {
		g10agErr(t, "PCAHeaders "+name, f(), g10agLoneErr)
	}
}

func TestG10AgentCapabilities(t *testing.T) {
	k := g10agKey(t, 2)
	_, err := MintRoot(k, "h", []any{make(chan int)}, "", nil)
	g10agErr(t, "MintRoot chan caveat", err, g10agChanErr)
	_, err = MintRoot(k, g10agLone, nil, "", nil)
	g10agErr(t, "MintRoot holder", err, g10agLoneErr)
	_, err = MintRoot(k, "h", nil, "", &SuiteOpts{Alg: "ml-dsa-65"})
	g10agErr(t, "MintRoot suite without PQ key", err, "ml-dsa-65 needs a post-quantum key pair")
	_, err = seal("i", "h", []any{}, "", "", nil, nil)
	g10agErr(t, "seal without a key", err, "ed25519 needs an Ed25519 key")

	pure, err := MintRoot(k, "h", nil, "", &SuiteOpts{Alg: "ml-dsa-65", Pq: g10agFakePq(pqMlDsa65, "PQPK", nil)})
	if err != nil || pure["alg"] != "ml-dsa-65" || pure["pq_pk"] != "PQPK" {
		t.Fatalf("pure suite: %v %v", pure, err)
	}
	if _, has := pure["pq_sig"]; has {
		t.Fatalf("a pure suite carries no pq_sig: %v", pure)
	}
	hyb, err := MintRoot(k, "h", nil, "", &SuiteOpts{Alg: "hybrid-ed25519-ml-dsa-65", Pq: g10agFakePq(pqMlDsa65, "PQPK", nil)})
	if err != nil || hyb["alg"] != "hybrid-ed25519-ml-dsa-65" || hyb["pq_sig"] != b64.EncodeToString([]byte("pq-sig")) {
		t.Fatalf("hybrid suite: %v %v", hyb, err)
	}

	root, err := MintRoot(k, k.Public, nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Delegate(map[string]any{"holder": "h", "caveats": []any{make(chan int)}}, k, "", nil, "", nil)
	g10agErr(t, "Delegate parent caveats", err, g10agChanErr)
	_, err = Delegate(root, k, "", []any{make(chan int)}, "", nil)
	g10agErr(t, "Delegate added caveats", err, g10agChanErr)
	_, err = Delegate(map[string]any{"holder": "h", "caveats": []any{}, "issuer": g10agLone}, k, "", nil, "", nil)
	g10agErr(t, "Delegate parent hash", err, g10agLoneErr)

	ag := NewAgent(k, root, "aud", 0)
	_, err = ag.Delegate(g10agKey(t, 3), []any{make(chan int)})
	g10agErr(t, "Agent.Delegate", err, g10agChanErr)
}

func g10agEnvelope() map[string]any {
	return map[string]any{"predicates": []any{}, "caveats": []any{}, "risk_policy": DefaultRiskPolicy()}
}

func TestG10AgentMintGrant(t *testing.T) {
	k := g10agKey(t, 4)
	_, err := MintGrant(k, "h", map[string]any{"x": make(chan int)}, "goal", "salt", "", nil)
	g10agErr(t, "envelope chan", err, g10agChanErr)
	_, err = MintGrant(k, "h", g10agEnvelope(), g10agLone, "salt", "", nil)
	g10agErr(t, "goal", err, g10agLoneErr)
	_, err = MintGrant(k, g10agLone, g10agEnvelope(), "goal", "salt", "", nil)
	g10agErr(t, "holder", err, g10agLoneErr)

	env := g10agEnvelope()
	env["agent_binding"] = nil
	env["units"] = nil
	r, err := MintGrant(k, "h", env, "goal", "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.GoalSalt) != 22 || r.GoalSalt == "AAAAAAAAAAAAAAAAAAAAAA" {
		t.Fatalf("drawn salt %q", r.GoalSalt)
	}
	e := r.Grant["caveats"].([]any)[0].(map[string]any)
	if ab, ok := e["agent_binding"].(map[string]any); !ok || len(ab) != 0 {
		t.Fatalf("a null agent_binding becomes {}: %v", e["agent_binding"])
	}
	if _, has := e["units"]; has {
		t.Fatalf("a null optional member is dropped: %v", e)
	}
}

func TestG10AgentPlans(t *testing.T) {
	var nodes []map[string]any
	for _, id := range []string{"n0", "n1", "n2", "n3"} {
		nodes = append(nodes, map[string]any{"id": id, "verb": "v", "resource": "/r"})
	}
	pc, err := CommitPlan(nodes)
	if err != nil {
		t.Fatal(err)
	}
	h := func(i, j int) string { return b64.EncodeToString(build(pc.hs[i:j])) }
	for id, want := range map[string][]any{
		"n2": {map[string]any{"side": "R", "hash": h(3, 4)}, map[string]any{"side": "L", "hash": h(0, 2)}},
		"n3": {map[string]any{"side": "L", "hash": h(2, 3)}, map[string]any{"side": "L", "hash": h(0, 2)}},
	} {
		p, err := pc.ProofFor(id)
		if err != nil || !reflect.DeepEqual(p["path"], want) {
			t.Errorf("%s path: %v %v", id, p["path"], err)
		}
	}
	_, err = CommitPlan([]map[string]any{{"id": "a", "x": make(chan int)}})
	g10agErr(t, "CommitPlan chan", err, g10agChanErr)

	k := g10agKey(t, 5)
	in := func(plan []map[string]any, params any, extra map[string]any) PCActnInput {
		return PCActnInput{Grant: map[string]any{"id": "g"}, Plan: plan, NodeID: "n1", Params: params, Signer: k, Aud: "aud", Extra: extra}
	}
	one := []map[string]any{{"id": "n1", "verb": "v", "resource": "/r", "reversibility_class": ""}}
	_, err = BuildPCActn(in([]map[string]any{{"id": "n1", "x": make(chan int)}}, nil, nil))
	g10agErr(t, "BuildPCActn plan chan", err, g10agChanErr)
	_, err = BuildPCActn(in(one, map[string]any{"c": make(chan int)}, nil))
	g10agErr(t, "BuildPCActn params chan", err, "canonicalize: unsupported type chan int")
	_, err = BuildPCActn(in([]map[string]any{{"id": "n1", "verb": "v", "resource": "/r"}, {"id": "n1", "verb": "w", "resource": "/r"}}, nil, nil))
	g10agErr(t, "BuildPCActn duplicate node", err, "CommitPlan: duplicate node id n1")
	_, err = BuildPCActn(in(one, nil, map[string]any{"x": make(chan int)}))
	g10agErr(t, "BuildPCActn extra chan", err, g10agChanErr)

	before := time.Now().UnixMilli()
	p, err := BuildPCActn(in(one, map[string]any{"a": 1}, nil))
	if err != nil {
		t.Fatal(err)
	}
	if rc := p["action"].(map[string]any)["reversibility_class"]; rc != defaultRev {
		t.Fatalf("an empty reversibility_class is the default: %v", rc)
	}
	if iat, ok := safeInt(p["iat"]); !ok || iat < before || iat > time.Now().UnixMilli() {
		t.Fatalf("Iat 0 is now: %v", p["iat"])
	}
}

func TestG10AgentArtifacts(t *testing.T) {
	k := g10agKey(t, 6)
	for rd, want := range map[string]bool{"": false, "rd": true} {
		a, err := SignEscalationAnswer(k, map[string]any{"render_digest": rd}, "allow", 1, 2, "n", nil)
		if _, has := a["render_digest"]; err != nil || has != want {
			t.Errorf("render_digest %q: %v %v", rd, a, err)
		}
	}
	if c := NeedsDischargeCaveat("i", "is", "c", "", 1, nil); c["bind"] != "chain_hop" {
		t.Fatalf("default bind: %v", c["bind"])
	}
	if c := NeedsDischargeCaveat("i", "is", "c", "action", 1, nil); c["bind"] != "action" {
		t.Fatalf("bind action: %v", c["bind"])
	}
	d, err := SignDischarge(k, DischargeInput{CaveatID: "c", IssuerLabel: "l", CapHash: "h", Claims: map[string]any{}}, nil)
	if n, _ := d["nonce"].(string); err != nil || d["bind"] != "chain_hop" || len(n) != 22 {
		t.Fatalf("discharge defaults: %v %v", d, err)
	}
	if d, err := SignDischarge(k, DischargeInput{Bind: "action", Nonce: "n", Claims: map[string]any{}}, nil); err != nil || d["bind"] != "action" || d["nonce"] != "n" {
		t.Fatalf("discharge set: %v %v", d, err)
	}
	nw, err := SignNarrow(k, "h", []any{}, 1, 2, "ad", "", nil)
	if n, _ := nw["nonce"].(string); err != nil || nw["action_digest"] != "ad" || len(n) != 22 {
		t.Fatalf("narrow: %v %v", nw, err)
	}
	if nw, err := SignNarrow(k, "h", []any{}, 1, 2, "", "n", nil); err != nil || nw["nonce"] != "n" {
		t.Fatalf("narrow without action digest: %v %v", nw, err)
	} else if _, has := nw["action_digest"]; has {
		t.Fatalf("no action_digest: %v", nw)
	}

	_, err = IssuePassport(map[string]any{"x": make(chan int)})
	g10agErr(t, "IssuePassport chan", err, g10agChanErr)
	pp, err := IssuePassport(map[string]any{"model_id": "m", "issued_at": 7})
	if err != nil {
		t.Fatal(err)
	}
	_, err = SignPassport(map[string]any{"x": make(chan int)}, k, "sub", 5, 0, 100, nil, nil)
	g10agErr(t, "SignPassport chan", err, g10agChanErr)
	_, err = SignPassport(pp, k, "sub", 5, 0, 100, map[string]any{"x": make(chan int)}, nil)
	g10agErr(t, "SignPassport evidence chan", err, g10agChanErr)
	sp, err := SignPassport(pp, k, "sub", 5, 0, 100, map[string]any{"kind": "x"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ev, _ := sp["evidence"].(map[string]any)
	if iat, _ := safeInt(sp["iat"]); iat != 5 || ev == nil || ev["kind"] != "x" {
		t.Fatalf("iat given / evidence: %v", sp)
	}
	if at, _ := safeInt(ev["at"]); at != 5 {
		t.Fatalf("evidence.at defaults to iat: %v", ev)
	}
	sp, err = SignPassport(pp, k, "sub", 5, 0, 100, map[string]any{"at": 99}, nil)
	if at, _ := safeInt(sp["evidence"].(map[string]any)["at"]); err != nil || at != 99 {
		t.Fatalf("evidence.at kept: %v %v", sp, err)
	}
	if sp, err := SignPassport(pp, k, "sub", 0, 0, 100, nil, nil); err != nil {
		t.Fatal(err)
	} else if iat, _ := safeInt(sp["iat"]); iat != 7 {
		t.Fatalf("iat 0 is issued_at: %v", sp["iat"])
	} else if _, has := sp["evidence"]; has {
		t.Fatalf("no evidence: %v", sp)
	}

	_, err = SignWorkflow(k, map[string]any{"principal": k.Public, "x": make(chan int)})
	g10agErr(t, "SignWorkflow chan", err, g10agChanErr)
	wf := map[string]any{"a": 1}
	_, err = SignStepReceipt(k, map[string]any{"x": make(chan int)}, "s", "ok", "pd", map[string]any{}, 1, nil)
	g10agErr(t, "SignStepReceipt workflow chan", err, g10agChanErr)
	_, err = SignStepReceipt(k, wf, "s", "ok", "pd", map[string]any{}, 1, map[string]any{"x": make(chan int)})
	g10agErr(t, "SignStepReceipt prev chan", err, g10agChanErr)
	_, err = SignStepReceipt(k, wf, "s", "ok", "pd", map[string]any{"o": make(chan int)}, 1, nil)
	g10agErr(t, "SignStepReceipt outputs chan", err, g10agChanErr)
	_, err = SignFreshAt(k, "s", map[string]any{"revocation_epoch": make(chan int)}, 1)
	g10agErr(t, "SignFreshAt chan", err, g10agChanErr)
}

func TestG10AgentAct(t *testing.T) {
	k := g10agKey(t, 7)
	grant := map[string]any{"id": "g"}
	a := NewAgent(k, grant, "aud", 0)
	called := false
	a.OnCounter = func(int64) { called = true }
	_, err := a.Act("v", "/r", map[string]any{"c": make(chan int)}, nil)
	g10agErr(t, "Act params chan", err, "canonicalize: unsupported type chan int")
	if called || a.counter != 0 {
		t.Fatalf("a refused action spends no counter: called=%v counter=%d", called, a.counter)
	}
	_, err = NewAgent(k, grant, "", 0).Act("v", "/r", nil, nil)
	g10agErr(t, "Act without audience", err, "BuildPCActn: aud (audience) is required")
}
