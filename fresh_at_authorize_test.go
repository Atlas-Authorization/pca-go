package pca

import (
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// faRig: a PCActn whose single-node plan is exactly the operation, carrying (or not) a signed `fresh_at` member.
type faRig struct {
	f      *fx
	op     *Operation
	signer fxKey
}

func faToken(t *testing.T, signer fxKey, revEpoch int64) map[string]any {
	tok := map[string]any{"v": jnum(1), "scope": "inst_1", "revocation_epoch": jnum(revEpoch), "ledger_tree_size": jnum(10),
		"budget_version": jnum(1), "policy_revision": jnum(1), "policy_digest": "pd", "issued_at": jnum(1_700_000_000_000), "signer": signer.id}
	c, err := canonBytes(tok)
	if err != nil {
		t.Fatal(err)
	}
	tok["sig"] = b64.EncodeToString(ed25519.Sign(signer.priv, append([]byte(freshAtDomain), c...)))
	return tok
}

func newFaRig(t *testing.T, member bool) *faRig {
	env := map[string]any{"type": "envelope", "agent_binding": map[string]any{}, "caveats": []any{}, "goal_commit": b64.EncodeToString(sha([]byte("g"))),
		"predicates": []any{map[string]any{"verb": "pay", "resource": "acct:*", "where": []any{map[string]any{"field": "action.params.amount", "op": "lte", "value": jnum(100)}}}},
		"risk_policy": map[string]any{"bMax": jnum(1000), "kappa": jnum(1), "lambda": jnum(0), "rho": jnum(0), "theta1": json.Number("0.5"), "theta2": json.Number("0.8"),
			"weights": map[string]any{"alpha": jnum(0), "beta": jnum(0), "delta": jnum(0), "epsilon": jnum(0), "gamma": jnum(0), "zeta": jnum(0)}}}
	chain, keys := mkChain(t, 1, func(int) []any { return []any{env} })
	f := &fx{t: t, chain: chain, keys: keys, aud: "rs-1", now: 1_700_000_001_000, grant: chain[0].(map[string]any)}
	r := &faRig{f: f, op: &Operation{Verb: "pay", Resource: "acct:1", Params: map[string]any{"amount": jnum(5)}}, signer: newKey(t)}
	pd, err := ParamsDigest(r.op.Params)
	if err != nil {
		t.Fatal(err)
	}
	action := map[string]any{"verb": "pay", "resource": "acct:1", "params_digest": pd, "reversibility_class": "reversible"}
	node := map[string]any{"id": "n1", "verb": "pay", "resource": "acct:1", "params_digest": pd, "reversibility_class": "reversible"}
	root, ok := planRoot([]map[string]any{node})
	cond, _ := conditionsDigest(nil, nil)
	if !ok {
		t.Fatal("plan root")
	}
	f.p = map[string]any{
		"ver": jnum(2), "action": action, "grant_ref": f.grant["id"], "cap_chain": chain,
		"plan":        map[string]any{"root": root, "node_id": "n1", "conditions_digest": cond, "inclusion_proof": map[string]any{"index": jnum(0), "size": jnum(1), "path": []any{}}},
		"attestation": map[string]any{"epoch": jnum(1), "quote_digest": "q", "model_id": "m", "measurement": "x", "operator": "o"},
		"provenance":  map[string]any{"causal_hash": "h", "taint_level": jnum(0), "trusted_refs": []any{"r"}},
		"freshness":   map[string]any{"beacon_ref": "b", "accumulator_witness": "w", "epoch": jnum(1)},
		"counter":     jnum(0), "risk_claim": map[string]any{"r": json.Number("0.5"), "inputs": map[string]any{}},
		"aud": f.aud, "iat": jnum(1_700_000_000_000), "exp": jnum(1_700_000_600_000),
	}
	if member {
		f.p["fresh_at"] = faToken(t, r.signer, 5)
	}
	f.resign()
	return r
}

func (r *faRig) policy(local int64) *FreshAtPolicy {
	return &FreshAtPolicy{Signer: r.signer.id, Scope: "inst_1", Local: FreshAtState{RevocationEpoch: local, LedgerTreeSize: 10, BudgetVersion: 1, PolicyRevision: 1, PolicyDigest: "pd"}}
}

func (r *faRig) input(fp *FreshAtPolicy) AuthorizeInput {
	return AuthorizeInput{Operation: r.op, Audience: r.f.aud, Now: r.f.now, Plan: PlanSingleStep, StateStore: NewMemoryStateStore(), FreshAt: fp,
		ResolveGrant: func(string) (map[string]any, error) { return r.f.grant, nil },
		IsRevoked:    func(_, _ map[string]any) (bool, error) { return false, nil }, ArgProvenance: harnessProv()}
}

func TestAuthorizeFreshAt(t *testing.T) {
	r := newFaRig(t, true)
	if res := Authorize(r.f.norm(), r.input(r.policy(5))); !res.Allow || res.Checks["fresh_at"] != "pass" {
		t.Fatalf("fresh verifier: %+v", res)
	}
	res := Authorize(r.f.norm(), r.input(r.policy(4)))
	if res.Allow || res.Decision != "escalate" || res.Checks["fresh_at"] != "fail" {
		t.Fatalf("stale verifier must escalate: %+v", res)
	}
	if res := Authorize(r.f.norm(), r.input(nil)); res.Allow || res.Decision == "escalate" {
		t.Fatalf("no policy must refuse (not escalate): %+v", res)
	}
}

func faServer(r *faRig, fp *FreshAtPolicy) http.Handler {
	in := r.input(nil)
	return RequirePCA(RequirePCAOptions{Audience: r.f.aud, Now: func() int64 { return r.f.now }, ResolveGrant: in.ResolveGrant,
		FreshAt: func(*http.Request, map[string]any) *FreshAtPolicy {
			if fp == nil {
				return nil
			}
			c := *fp
			return &c
		},
		Authorize: &AuthorizeOptions{StateStore: in.StateStore, IsRevoked: in.IsRevoked, ArgProvenance: in.ArgProvenance,
			Operation: func(*http.Request, []byte) (*Operation, error) { return r.op, nil }}})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
}

func faCall(t *testing.T, h http.Handler, p map[string]any, side *string) *httptest.ResponseRecorder {
	b, _ := json.Marshal(p)
	req := httptest.NewRequest("POST", "/x", nil)
	req.Header.Set(PCAHeader, b64.EncodeToString(b))
	if side != nil {
		req.Header.Set("pca-fresh-at", *side)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func TestMiddlewareFreshAt(t *testing.T) {
	r := newFaRig(t, true)
	if w := faCall(t, faServer(r, r.policy(5)), r.f.p, nil); w.Code != 200 {
		t.Fatalf("member, fresh: %d %s", w.Code, w.Body)
	}
	w := faCall(t, faServer(r, r.policy(4)), r.f.p, nil)
	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if w.Code != 403 || body["decision"] != "escalate" {
		t.Fatalf("member, stale: %d %s", w.Code, w.Body)
	}
	if w := faCall(t, faServer(r, nil), r.f.p, nil); w.Code != 403 {
		t.Fatalf("member, no policy: %d", w.Code)
	}

	// side-carried: the PCActn has no member; the header token is read, the garbage header is a bad token
	n := newFaRig(t, false)
	tok, _ := json.Marshal(faToken(t, n.signer, 5))
	side := string(tok)
	if w := faCall(t, faServer(n, n.policy(5)), n.f.p, &side); w.Code != 200 {
		t.Fatalf("side-carried fresh: %d %s", w.Code, w.Body)
	}
	w = faCall(t, faServer(n, n.policy(4)), n.f.p, &side)
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if w.Code != 403 || body["decision"] != "escalate" {
		t.Fatalf("side-carried stale: %d %s", w.Code, w.Body)
	}
	bad := "{nope"
	w = faCall(t, faServer(n, n.policy(5)), n.f.p, &bad)
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if w.Code != 403 || body["decision"] == "escalate" || body["reason"] != "fresh_at: bad_token" {
		t.Fatalf("garbage header: %d %s", w.Code, w.Body)
	}
	if w := faCall(t, faServer(n, n.policy(5)), n.f.p, nil); w.Code != 200 {
		t.Fatalf("no token, not required: %d", w.Code)
	}
}
