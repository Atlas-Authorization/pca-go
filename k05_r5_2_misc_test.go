package pca

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"testing"
)

// ---- operations.go ----------------------------------------------------------------------------------------------------

func TestR5N2_OperationStoreTransitionStampsTheID(t *testing.T) {
	for name, st := range map[string]OperationStore{"memory": NewMemoryOperationStore(), "kv": NewKVOperationStore(NewMemoryAtomicKV(), "")} {
		if ok, _, err := st.Create(OperationRecord{ID: "a", State: OpPending}); err != nil || !ok {
			t.Fatalf("%s create: %v %v", name, ok, err)
		}
		// next carries no id: the stored record is still the one for "a"
		if ok, err := st.Transition("a", OpPending, OperationRecord{State: OpCommitted}); err != nil || !ok {
			t.Fatalf("%s transition: %v %v", name, ok, err)
		}
		cur, err := st.Get("a")
		if err != nil || cur == nil || cur.ID != "a" || cur.State != OpCommitted {
			t.Fatalf("%s get: %+v %v", name, cur, err)
		}
	}
}

func TestR5N2_KVOperationGetUndecodableIsNone(t *testing.T) {
	rec, err := NewKVOperationStore(&g02kv{getB: []byte("not json"), getOK: true}, "").Get("a")
	if rec != nil || err != nil {
		t.Fatalf("an undecodable record is no record: %+v %v", rec, err)
	}
}

// r5n2kv runs the update function against a stored value and then reports a failure.
type r5n2kv struct {
	prev []byte
	err  error
}

func (k *r5n2kv) Get(string) ([]byte, bool, error) { return k.prev, true, nil }

func (k *r5n2kv) Update(_ string, fn func([]byte) []byte) error {
	fn(k.prev)
	return k.err
}

func TestR5N2_KVOperationTransitionReportsUpdateError(t *testing.T) {
	st := NewKVOperationStore(&r5n2kv{prev: []byte(`{"id":"a","state":"pending"}`), err: g02boom}, "")
	done, err := st.Transition("a", OpPending, OperationRecord{State: OpCommitted})
	if done || err != g02boom {
		t.Fatalf("done %v err %v", done, err)
	}
}

func TestR5N2_ResolveOperationGetError(t *testing.T) {
	done, err := ResolveOperation(&g02store{get: g02boomGet}, "a", OperationResolution{State: OpCommitted}, nil)
	if done || err != g02boom {
		t.Fatalf("done %v err %v", done, err)
	}
}

func TestR5N2_ExecuteAuthorizedTransitionEdges(t *testing.T) {
	d, err := ParamsDigest(nil)
	if err != nil {
		t.Fatal(err)
	}
	az := func(id string) AuthorizeResult {
		return AuthorizeResult{Allow: true, Operation: &AuthorizedOperation{Verb: "read", Resource: "doc", ParamsDigest: d, ID: id}, PCActn: map[string]any{}}
	}
	clock := func() int64 { return 1000 }
	never := func(ExecutionHandle) (any, error) {
		t.Error("fn ran")
		return nil, nil
	}
	refuse := func(ExecutionHandle) (RecheckResult, error) { return RecheckResult{}, nil }
	pass := func(ExecutionHandle) (RecheckResult, error) { return RecheckResult{OK: true}, nil }
	gone := ExecuteOutcome{Status: "uncertain", OperationID: "op", Reason: "the operation record disappeared", Replayed: true}

	// the abort cannot be recorded because the record moved: the outcome is the record's, not an abort
	st := &g02store{trans: func(string, OperationState, OperationRecord) (bool, error) { return false, nil }}
	if out := ExecuteAuthorized(az("op"), never, ExecuteOptions{Store: st, RecheckFor: "always", Recheck: refuse, Now: clock}); out != gone {
		t.Errorf("abort lost the race: %+v", out)
	}

	// the executing marker fails: refused, fn never runs
	st = &g02store{trans: func(_ string, _ OperationState, next OperationRecord) (bool, error) {
		if next.State == OpExecuting {
			return false, g02boom
		}
		return true, nil
	}}
	if out := ExecuteAuthorized(az("op"), never, ExecuteOptions{Store: st, RecheckFor: "always", Recheck: pass, Now: clock}); out != (ExecuteOutcome{Status: "refused", Reason: g02storeFailed}) {
		t.Errorf("marker error: %+v", out)
	}

	// the executing marker loses to a concurrent settle: answered from the record, fn never runs
	st = &g02store{trans: func(_ string, _ OperationState, next OperationRecord) (bool, error) {
		return next.State != OpExecuting, nil
	}}
	if out := ExecuteAuthorized(az("op"), never, ExecuteOptions{Store: st, RecheckFor: "always", Recheck: pass, Now: clock}); out != gone {
		t.Errorf("marker lost the race: %+v", out)
	}
}

// ---- storeconformance.go ----------------------------------------------------------------------------------------------

func TestR5N2_ClaimBurstCatchesAnAdmittedReplay(t *testing.T) {
	b := g11NewBack()
	b.hook = g11At(26, true, nil)
	g11WantErr(t, b.conf(true).claimBurst(), "counter 25 was admitted twice (or an older counter was admitted after a newer one)")
}

// r5n2Applying applies every transition, whatever the state, and reports that it did not.
type r5n2Applying struct{ *MemoryOperationStore }

func (s r5n2Applying) Transition(id string, _ OperationState, next OperationRecord) (bool, error) {
	s.MemoryOperationStore.mu.Lock()
	s.MemoryOperationStore.m[id] = next
	s.MemoryOperationStore.mu.Unlock()
	return false, nil
}

func TestR5N2_WrongStateCheckSeesAChangedRecord(t *testing.T) {
	st := r5n2Applying{NewMemoryOperationStore()}
	r := RunOperationStoreConformance(OperationStoreConformance{Name: "applying", Open: func() (OperationStore, error) { return st, nil }, Shared: true})
	if got := checkStatus(r, "wrong-state"); got != "fail" {
		t.Fatalf("a refused transition that still changed the record must fail wrong-state, got %s:\n%s", got, r)
	}
}

// ---- allowlist_anchor.go ----------------------------------------------------------------------------------------------

func r5n2AnchorEvidence(l g11Log, root string, entries []any) map[string]any {
	return map[string]any{
		"head":    l.signed("ins", "p", root, emptyTreeRoot(), int64(len(entries)), g11Now),
		"entries": entries,
		"proof":   map[string]any{"index": json.Number("0"), "size": json.Number(anchorNum(int64(len(entries)))), "path": []any{}},
	}
}

func TestR5N2_AnchorRefusals(t *testing.T) {
	l := g11NewLog()
	opts := AnchorOptions{Trust: l.trust(), NowMs: g11Now}
	good := AnchorEntry{Issuer: "i", Version: 1, Digest: g11Digest("d")}
	// an issuer with a lone surrogate cannot be canonicalized
	bad := AnchorEntry{Issuer: "\xed\xa0\x80", Version: 1, Digest: g11Digest("b")}

	// an unreadable head is bad-head even when the zero head would match an empty trust
	empty := AnchorOptions{Trust: AnchorTrust{LogKey: l.key}, NowMs: 0}
	res := VerifyAllowlistAnchored(good, map[string]any{"head": "x", "entries": []any{}, "proof": map[string]any{}}, empty)
	g11WantAnchor(t, "unreadable head", res, false, "bad-head", 0)

	// a feed entry that is not an entry: the root over what it would decode to does not rescue it
	zero, err := anchorCommit(AnchorEntry{})
	if err != nil {
		t.Fatal(err)
	}
	rootZero, err := MerkleRoot([]any{zero})
	if err != nil {
		t.Fatal(err)
	}
	ev := r5n2AnchorEvidence(l, rootZero, []any{map[string]any{"x": json.Number("1")}})
	g11WantAnchor(t, "malformed entry", VerifyAllowlistAnchored(good, ev, opts), false, "feed-mismatch", 0)

	// a feed entry whose commitment cannot be computed: likewise
	rootEmpty, err := MerkleRoot([]any{""})
	if err != nil {
		t.Fatal(err)
	}
	ev = r5n2AnchorEvidence(l, rootEmpty, []any{g11EntryMap(bad)})
	g11WantAnchor(t, "uncommittable entry", VerifyAllowlistAnchored(good, ev, opts), false, "feed-mismatch", 0)

	// a manifest entry whose commitment cannot be computed is bad-proof, whatever the inclusion check says
	oldIncl := anchorVerifyInclusion
	anchorVerifyInclusion = func(string, map[string]any, any) bool { return true }
	defer func() { anchorVerifyInclusion = oldIncl }()
	ev = l.evidence([]AnchorEntry{good}, 0, g11Now)
	g11WantAnchor(t, "uncommittable manifest", VerifyAllowlistAnchored(bad, ev, opts), false, "bad-proof", 0)
	anchorVerifyInclusion = oldIncl

	// a Merkle root that cannot be computed: feed-mismatch, even for a head whose root is the empty string
	oldRoot := anchorMerkleRoot
	anchorMerkleRoot = func([]any) (string, error) { return "", errors.New("root") }
	defer func() { anchorMerkleRoot = oldRoot }()
	ev = r5n2AnchorEvidence(l, "", []any{g11EntryMap(good)})
	g11WantAnchor(t, "root error", VerifyAllowlistAnchored(good, ev, opts), false, "feed-mismatch", 0)
	anchorMerkleRoot = oldRoot
}

func TestR5N2_AnchorPanicIsBadHead(t *testing.T) {
	l := g11NewLog()
	good := AnchorEntry{Issuer: "i", Version: 1, Digest: g11Digest("d")}
	old := anchorVerifyInclusion
	anchorVerifyInclusion = func(string, map[string]any, any) bool { panic("inclusion") }
	defer func() { anchorVerifyInclusion = old }()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("VerifyAllowlistAnchored let a panic out: %v", r)
		}
	}()
	res := VerifyAllowlistAnchored(good, l.evidence([]AnchorEntry{good}, 0, g11Now), AnchorOptions{Trust: l.trust(), NowMs: g11Now})
	g11WantAnchor(t, "panic", res, false, "bad-head", 0)
}

// ---- revocation_staleness.go ------------------------------------------------------------------------------------------

func TestR5N2_RevocationPolicyFromJSON(t *testing.T) {
	p := RevocationStalenessPolicyFromJSON(map[string]any{"maxRevocationAgeMs": "soon", "allowUnsignedRootForIrreversible": true})
	if p.MaxRevocationAgeMs == nil || !math.IsNaN(*p.MaxRevocationAgeMs) {
		t.Fatalf("a non-number window must be NaN: %v", p.MaxRevocationAgeMs)
	}
	if !p.AllowUnsignedRootForIrreversible {
		t.Fatal("allowUnsignedRootForIrreversible not read")
	}
}

func TestR5N2_RevocationEpochEdges(t *testing.T) {
	seed := bytes.Repeat([]byte{0x71}, 32)
	ep := g05Epoch(t, seed)
	g := ep["guardian"].(string)
	const notGuardian = "revocation epoch not signed by the pinned guardian"
	// not an object: refused as unsigned, even when the pinned guardian is the empty string
	g05RevWant(t, "string", CheckRevocationEpoch("x", EpochCheckOptions{Now: 2000}), false, notGuardian)
	// a body member missing: a check error
	noRoot := copyMap(ep)
	delete(noRoot, "root")
	g05RevWant(t, "no root", CheckRevocationEpoch(noRoot, EpochCheckOptions{GuardianPublic: g, Now: 2000}), false, "revocation epoch check error")
}

func TestR5N2_RevocationFreshnessReadsThePCActnEpoch(t *testing.T) {
	seed := bytes.Repeat([]byte{0x71}, 32)
	ep := g05Epoch(t, seed) // epoch 5, grant "g"
	in := AuthorizeInput{RevocationStaleness: &RevocationStalenessPolicy{}, GuardianPublic: ep["guardian"].(string)}
	state := &RevocationState{Epoch: ep}
	p := func(fresh any, chain []any) map[string]any {
		return map[string]any{"grant_ref": "g", "action": map[string]any{"reversibility_class": "reversible"}, "freshness": fresh, "cap_chain": chain}
	}
	ctx := &AuthorizeContext{}
	if got := revocationFreshness(in, ctx, p(map[string]any{"epoch": json.Number("5")}, []any{}), state, 2000); got != "" {
		t.Fatalf("a current epoch: %q", got)
	}
	if got := revocationFreshness(in, ctx, p(map[string]any{"epoch": json.Number("1")}, []any{}), state, 2000); got != "PCActn freshness.epoch 1 predates the revocation epoch 5" {
		t.Fatalf("an older epoch: %q", got)
	}
	// no readable epoch in freshness: nothing to compare (the gate does not invent a zero)
	if got := revocationFreshness(in, ctx, p(map[string]any{}, []any{}), state, 2000); got != "" {
		t.Fatalf("no epoch member: %q", got)
	}
	if got := revocationFreshness(in, ctx, p(map[string]any{"epoch": "5"}, []any{}), state, 2000); got != "" {
		t.Fatalf("a non-number epoch member: %q", got)
	}
	if got := revocationFreshness(in, ctx, p(map[string]any{}, []any{map[string]any{}}), state, 2000); got != "capability chain entry has no readable id (fail closed)" {
		t.Fatalf("unreadable chain id: %q", got)
	}
}

// ---- pq.go ------------------------------------------------------------------------------------------------------------

func TestR5N2_ResolvePqVerifyKeyNonStringKey(t *testing.T) {
	// a trusted key of "" would accept a missing pq_pk if the type check were skipped
	if _, ok := resolvePqVerifyKey("ml-dsa-65", true, 5, pqAuthority{hasTrusted: true, trustedPk: ""}); ok {
		t.Fatal("a non-string pq_pk was authorised")
	}
	if _, ok := resolvePqVerifyKey("ml-dsa-65", true, "", pqAuthority{hasTrusted: true, trustedPk: ""}); !ok {
		t.Fatal("control: an equal string is authorised")
	}
}

func TestR5N2_PqVerifyRawChecksLengthsBeforeTheNativeVerifier(t *testing.T) {
	old := lessCat1Verify
	lessCat1Verify = func(pk, msg, sig []byte) bool { return true }
	defer func() { lessCat1Verify = old }()
	pk := make([]byte, lessPublicKeyBytes)
	sig := make([]byte, lessSignatureMaxBytes)
	if !pqVerifyRaw(pqLessCat1, pk, nil, sig) {
		t.Fatal("control: right lengths reach the verifier")
	}
	if pqVerifyRaw(pqLessCat1, pk[:10], nil, sig) {
		t.Error("a short public key reached the verifier")
	}
	if pqVerifyRaw(pqLessCat1, pk, nil, sig[:5]) {
		t.Error("a short signature reached the verifier")
	}
}

// ---- obligations.go ---------------------------------------------------------------------------------------------------

func TestR5N2_ObligationKeyOmitsAbsentDue(t *testing.T) {
	s, ok := ObligationKey(map[string]any{"kind": "log"})
	if !ok || s != `{"kind":"log","params":{}}` {
		t.Fatalf("%q %v", s, ok)
	}
	s, ok = ObligationKey(map[string]any{"kind": "log", "due": json.Number("5")})
	if !ok || s != `{"due":5,"kind":"log","params":{}}` {
		t.Fatalf("%q %v", s, ok)
	}
}

func TestR5N2_ObligationsErrorNotCanonicalizable(t *testing.T) {
	list := []any{map[string]any{"kind": "notify", "params": map[string]any{"to": "\xed\xa0\x80"}}}
	if got := ObligationsError(list); got != "an obligation is not canonicalizable" {
		t.Fatalf("%q", got)
	}
}

func TestR5N2_ObligationOutcomeBadFulfilledEntry(t *testing.T) {
	r := ObligationOutcome([]any{}, []any{"x"}, json.Number("5"))
	if r.Outcome != "escalate" || r.Status != "obligation_unmet" {
		t.Fatalf("a fulfilled list with a non-integer is malformed input: %+v", r)
	}
}

// ---- intent_session.go ------------------------------------------------------------------------------------------------

func TestR5N2_SessionPinForNotAnObject(t *testing.T) {
	for _, pins := range []any{nil, "x", []any{"p"}} {
		if v, ok := sessionPinFor(pins, "s"); v != "" || ok {
			t.Errorf("%v: %q %v", pins, v, ok)
		}
	}
}

func TestR5N2_SessionRootUnbindableSuiteIsInvalid(t *testing.T) {
	f := newV2Fx(t)
	if verifySessionRoot(deepM(t, f.S), nil) != "" {
		t.Fatal("control: the base root verifies")
	}
	old := sessionBindSuiteFields
	sessionBindSuiteFields = func(map[string]any, any, bool, any, bool) (map[string]any, bool) { return nil, false }
	defer func() { sessionBindSuiteFields = old }()
	if r := verifySessionRoot(deepM(t, f.S), nil); r != "session root signature invalid" {
		t.Fatalf("got %q", r)
	}
}
