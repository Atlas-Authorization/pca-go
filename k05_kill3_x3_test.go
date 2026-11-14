package pca

import (
	"strings"
	"testing"
)

// AggregateRead state bounds with the literal 2^53-1 (read-vault.ts: Number.isSafeInteger), not the Go constant under test.
func TestX3AggregateStateSafeIntegerLiteral(t *testing.T) {
	const safe, over = int64(9007199254740991), int64(9007199254740992)
	for name, st := range map[string]AggregateState{
		"spent":    {SpentMicro: safe, Queries: 1},
		"queries":  {SpentMicro: 1, Queries: safe},
		"answered": {SpentMicro: 1, Queries: 1, Answered: map[string]int64{"a": safe, "b": -safe}},
	} {
		r := AggregateRead(AggregateInput{Principal: "x", Now: jnum(1), State: st})
		if r.Decision != "deny" || r.Code != "bad_request" || r.State.SpentMicro != st.SpentMicro || r.State.Queries != st.Queries || len(r.State.Answered) != len(st.Answered) {
			t.Errorf("%s at 2^53-1 must be kept: %+v", name, r)
		}
	}
	for name, st := range map[string]AggregateState{
		"spent":        {SpentMicro: over, Queries: 1},
		"queries":      {SpentMicro: 1, Queries: over},
		"answered":     {SpentMicro: 1, Queries: 1, Answered: map[string]int64{"a": over}},
		"answered low": {SpentMicro: 1, Queries: 1, Answered: map[string]int64{"a": -over}},
	} {
		if r := AggregateRead(AggregateInput{Principal: "x", Now: jnum(1), State: st}); !g12IsEmptyFail(r) {
			t.Errorf("%s at 2^53 must be refused with an empty state: %+v", name, r)
		}
	}
}

// assurance.ts: (ZK_RANK[level] ?? 0) < ZK_NEED[req]: an unrecognised level ranks 0, below attested_vm_hardware's floor of 1.
func TestX3ZkHardwareFloorRefusesUnrecognisedLevel(t *testing.T) {
	rep := g07asRep([]string{"zk_compliance"}, []CheckAssurance{{Outcome: "pass", Level: "mystery"}})
	want := "assurance: zk compliance (attested_vm_hardware) required but the evidence is mystery"
	if got := UnmetAssurance(rep, AssuranceRequirement{Zk: "attested_vm_hardware"}); got != want {
		t.Fatalf("got %q", got)
	}
}

// ledger.ts verifyPinnedSuite: a PQ suite verifies only under a pin equal to the artifact's pq_pk, even when the signature is valid.
func TestX3ExtSuiteSignedNeedsTheExactPin(t *testing.T) {
	id, pq, other := newKey(t), newPq(t), newPq(t)
	body := map[string]any{"principal": "p", "size": jnum(1), "root": "r"}
	c, err := canonBytes(map[string]any{"principal": "p", "size": jnum(1), "root": "r", "alg": "ml-dsa-65", "pq_pk": pq.b64})
	if err != nil {
		t.Fatal(err)
	}
	signed := map[string]any{"alg": "ml-dsa-65", "pq_pk": pq.b64, "sig": pq.sign(t, append([]byte(ledgerHeadDomain), c...))}
	pin := func(v string) extPins { return extPins{map[string]string{id.id: v}, true} }
	for _, tc := range []struct {
		name string
		m    map[string]any
		pins extPins
		want bool
	}{
		{"pinned to its key", signed, pin(pq.b64), true},
		{"pinned to another key", signed, pin(other.b64), false},
		{"no pin for the identity", signed, extPins{map[string]string{}, true}, false},
		{"no pins at all", signed, extPins{}, false},
		{"empty key under an empty pin", map[string]any{"alg": "ml-dsa-65", "pq_pk": "", "sig": signed["sig"]}, pin(""), false},
		{"non-string key under an empty pin", map[string]any{"alg": "ml-dsa-65", "pq_pk": jnum(1), "sig": signed["sig"]}, pin(""), false},
	} {
		if got := extSuiteSigned(id.id, ledgerHeadDomain, body, tc.m, tc.pins); got != tc.want {
			t.Errorf("%s: %v", tc.name, got)
		}
	}
}

// x3MeshProof is a single-domain mesh proof over the given caveats per hop; only the chain verifier may object to them.
func x3MeshProof(t *testing.T, caveats func(i int) []any) (any, any) {
	t.Helper()
	const n = 2
	chain, keys := mkChain(t, n, caveats)
	dom, wit := newKey(t), newKey(t)
	now := int64(1_800_000_000_000)
	digests := make([]any, n)
	for i, c := range chain {
		d, err := CapHash(c.(map[string]any))
		if err != nil {
			t.Fatal(err)
		}
		digests[i] = d
	}
	hs := leafHashes(t, digests)
	emptyRev, _ := bindRevRoot(0, emptyRevTree())
	head := map[string]any{"domain": dom.id, "size": jnum(n), "root": b64.EncodeToString(rootOf(hs)),
		"rev_root": emptyRev, "rev_size": jnum(0), "timestamp": jnum(now)}
	ch := map[string]any{"head": head, "sig": signDomain(t, dom, meshHeadDomain, head),
		"cosigs": []any{map[string]any{"witness": wit.id, "sig": signDomain(t, wit, meshCosigDomain, head)}}}
	hops := make([]any, n)
	for i := range chain {
		sides, sib := treeProof(hs, i)
		ev := map[string]any{"domain": dom.id, "head": jnum(0), "inclusion": proofMap(sides, sib, i, n),
			"revocation": map[string]any{"cap": map[string]any{"size": jnum(0)}, "issuer_key": map[string]any{"size": jnum(0)}}}
		if i > 0 {
			b := map[string]any{"agent": keys[i].id, "domain": dom.id, "role": "agent"}
			ev["binding"] = map[string]any{"agent": keys[i].id, "domain": dom.id, "role": "agent", "sig": signDomain(t, dom, meshBindingDomain, b)}
		}
		hops[i] = ev
	}
	action := map[string]any{"type": "pay", "resource": "/r/1", "service_domain": dom.id, "nonce": "n1", "at": jnum(now)}
	tipHash, err := CapHash(chain[n-1].(map[string]any))
	if err != nil {
		t.Fatal(err)
	}
	proof := map[string]any{"chain": chain, "hops": hops, "heads": []any{ch}, "rev_leaves": []any{}, "action": action,
		"action_sig": signDomain(t, keys[n], meshActionDomain, map[string]any{"action": action, "tip": tipHash})}
	trust := map[string]any{"humanPrincipal": keys[0].id, "witnesses": []any{wit.id}, "threshold": jnum(1), "now": jnum(now),
		"allowedDomains": []any{dom.id}, "rootDomain": dom.id}
	return proof, trust
}

// mesh.ts: `if (prev && !narrows(eff, prev)) return fail('hop widens authority', i)`, reached by stubbing ONLY the chain verifier
// (as the reference's own narrows test does): a real chain is append-only, so a widening hop stops there first.
func TestX3MeshHopWidensAuthority(t *testing.T) {
	widening := func(i int) []any {
		if i == 0 {
			return []any{map[string]any{"type": "scope", "actions": []any{"pay"}}}
		}
		return nil // hop 1 drops the parent's scope caveat
	}

	proof, trust := x3MeshProof(t, widening)
	if v := VerifyMeshProof(proof, trust); v.OK || !strings.HasPrefix(v.Reason, "chain: ") || v.Hop != -1 {
		t.Fatalf("the real chain verifier must refuse first: %+v", v)
	}

	saved := meshChainPolicy
	defer func() { meshChainPolicy = saved }()
	meshChainPolicy = func(_ []any, _ string, _ bool, _ []string, _ map[string]string, _ map[string]any) (string, bool) {
		return "", true
	}
	if v := VerifyMeshProof(proof, trust); v != (MeshVerdict{Reason: "hop widens authority", Hop: 1}) {
		t.Fatalf("widening hop: %+v", v)
	}
	proof, trust = x3MeshProof(t, nil) // the stub alone refuses nothing
	if v := VerifyMeshProof(proof, trust); v != (MeshVerdict{OK: true, Hop: -1}) {
		t.Fatalf("no caveats at all: %+v", v)
	}
}
