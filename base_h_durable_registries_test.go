package pca

import (
	"errors"
	"sync"
	"testing"
)

// H15: lease, break-glass and blueprint registries keep their state in a durable kv. A second registry over the same kv sees it.

func TestH15_ConstructorsRequireAKv(t *testing.T) {
	for want, f := range map[string]func(){
		"LeaseRegistry: a durable key-value store is required (MemoryLeaseKv() is for tests and single-process use)":           func() { NewLeaseRegistry(LeasePolicy{}, nil) },
		"BreakGlassRegistry: a durable key-value store is required (MemoryBreakGlassKv() is for tests and single-process use)": func() { NewBreakGlassRegistry(BreakGlassPolicy{}, nil) },
		"BlueprintRegistry: a durable BlueprintStore is required (MemoryBlueprintKv() is for tests and single-process use)":    func() { NewBlueprintRegistry(nil, nil) },
	} {
		func() {
			defer func() {
				if got := recover(); got != want {
					t.Errorf("panic %v, want %q", got, want)
				}
			}()
			f()
		}()
	}
}

// brokenKv fails every call (or panics), like an unreachable database.
type brokenKv struct{ panics bool }

func (b brokenKv) Get(string) ([]byte, bool, error) {
	if b.panics {
		panic("down")
	}
	return nil, false, errors.New("down")
}
func (b brokenKv) Update(string, func([]byte) []byte) error {
	if b.panics {
		panic("down")
	}
	return errors.New("down")
}

func TestH15_LeaseSurvivesARestart(t *testing.T) {
	k := newKey(t)
	pol := LeasePolicy{Authorities: []string{k.id}}
	kv := MemoryLeaseKv()
	l1 := g04SignLease(t, k, g04Lease())
	reg := NewLeaseRegistry(pol, kv)
	if r := reg.Accept(l1, nil); !r.Ok || !r.Replaced {
		t.Fatalf("accept: %+v", r)
	}
	if code, n := reg.Revoke(g04SignRev(t, k, map[string]any{"v": jnum(1), "target": "lease", "value": "L1", "revoked_at": jnum(500)})); code != "" || n != 1 {
		t.Fatalf("revoke: %q %d", code, n)
	}
	// a new registry over the same kv (a restart or a second instance): the revocation is still there
	again := NewLeaseRegistry(pol, kv)
	if r := again.Accept(l1, nil); r.Ok || r.Code != "revoked" {
		t.Errorf("seq-1 replay after restart: %+v", r)
	}
	if d := CheckLease(l1, again, jnum(150)); d.Decision != "deny" || d.Code != "revoked" {
		t.Errorf("check after restart: %+v", d)
	}
	if got := again.Get("L1"); got == nil || got["lease_id"] != "L1" {
		t.Errorf("the stored lease is gone: %v", got)
	}
}

func TestH15_LeaseRenewalRacesHaveOneWinner(t *testing.T) {
	k := newKey(t)
	pol := LeasePolicy{Authorities: []string{k.id}}
	kv := MemoryLeaseKv()
	if r := NewLeaseRegistry(pol, kv).Accept(g04SignLease(t, k, g04Lease()), nil); !r.Ok {
		t.Fatal(r)
	}
	renew := func(j string, exp int64) map[string]any {
		l := g04Lease()
		l["seq"], l["renewed_at"], l["expires_at"], l["justification_digest"] = jnum(2), jnum(150), jnum(exp), j
		return g04SignLease(t, k, l)
	}
	a, b := renew("JA", 300), renew("JB", 310)
	var wg sync.WaitGroup
	out := make([]LeaseAcceptResult, 2)
	for i, rec := range []map[string]any{a, b} {
		wg.Add(1)
		go func(i int, rec map[string]any) {
			defer wg.Done()
			out[i] = NewLeaseRegistry(pol, kv).Accept(rec, nil) // two instances, one kv
		}(i, rec)
	}
	wg.Wait()
	wins, forks := 0, 0
	for _, r := range out {
		if r.Ok && r.Replaced {
			wins++
		}
		if r.Code == "lease_fork" {
			forks++
		}
	}
	if wins != 1 || forks != 1 {
		t.Errorf("results: %+v", out)
	}
}

func TestH15_BreakGlassBudgetIsSharedAcrossRegistries(t *testing.T) {
	auth, _ := NewKeyPair()
	rev, _ := NewKeyPair()
	pol := BreakGlassPolicy{Authorities: []string{auth.Public}, Reviewers: []string{rev.Public}}
	kv := MemoryBreakGlassKv()
	rec := g03bgRecord()
	rec["authority"], rec["max_uses"] = auth.Public, 1
	g03bgSign(t, auth, breakGlassDomain, rec, breakGlassBodyKeys)
	r1, r2 := NewBreakGlassRegistry(pol, kv), NewBreakGlassRegistry(pol, kv)
	if r := r1.Accept(rec, 1500); !r.Ok || !r.Replaced {
		t.Fatalf("accept: %+v", r)
	}
	if d := r1.Use("g1", "h", "d1", 2000, true); d.Decision != "allow" || d.Use != 1 || d.Remaining != 0 {
		t.Fatalf("first use: %+v", d)
	}
	if d := r2.Use("g1", "h", "d2", 2001, true); d.Decision != "deny" || d.Code != "budget_exhausted" {
		t.Errorf("second use on another registry over the same kv: %+v", d)
	}
	// the freeze (no review after review_within) is shared too
	if r2.Frozen("h", 2001+rec["review_within"].(int)) != true {
		t.Error("a holder past its review clock is frozen on the second registry")
	}
}

func TestH15_BlueprintDisabledStaysDisabled(t *testing.T) {
	op := newKey(t)
	kv := MemoryBlueprintKv()
	disabled := parityBlueprint(t, op, "K", "disabled", func(b map[string]any) { b["epoch"] = jnum(5); delete(b, "runtime_pins") })
	active4 := parityBlueprint(t, op, "K", "active", func(b map[string]any) { b["epoch"] = jnum(4); delete(b, "runtime_pins") })
	if code, replaced := NewBlueprintRegistry([]string{op.id}, kv).Accept(disabled); code != "" || !replaced {
		t.Fatalf("disable: %q %v", code, replaced)
	}
	again := NewBlueprintRegistry([]string{op.id}, kv)
	if code, _ := again.Accept(active4); code != "stale_epoch" {
		t.Errorf("replay of active epoch 4 after restart: %q", code)
	}
	if again.Epoch() != 5 {
		t.Errorf("epoch %d", again.Epoch())
	}
	chain := []any{map[string]any{"issuer": "root", "holder": "K"}, map[string]any{"issuer": "K", "holder": "inst"}}
	if d := CheckBlueprints(chain, again, jnum(2), "any", nil); d.Decision != "deny" || d.Code != "blueprint_disabled" {
		t.Errorf("check: %+v", d)
	}
}

func TestH15_AnUnreachableStoreIsStoreUnreachable(t *testing.T) {
	k := newKey(t)
	auth, _ := NewKeyPair()
	op := newKey(t)
	for name, kv := range map[string]brokenKv{"error": {}, "panic": {panics: true}} {
		lr := NewLeaseRegistry(LeasePolicy{Authorities: []string{k.id}}, kv)
		l1 := g04SignLease(t, k, g04Lease())
		if r := lr.Accept(l1, nil); r.Ok || r.Code != "store_unreachable" {
			t.Errorf("%s lease accept: %+v", name, r)
		}
		if code, _ := lr.Revoke(g04SignRev(t, k, g04Rev())); code != "store_unreachable" {
			t.Errorf("%s lease revoke: %q", name, code)
		}
		if d := CheckLease(l1, lr, jnum(150)); d.Decision != "deny" || d.Code != "store_unreachable" {
			t.Errorf("%s lease check: %+v", name, d)
		}
		if lr.Get("L1") != nil {
			t.Errorf("%s lease get", name)
		}
		bg := NewBreakGlassRegistry(BreakGlassPolicy{Authorities: []string{auth.Public}, Reviewers: []string{auth.Public}}, kv)
		rec := g03bgRecord()
		rec["authority"] = auth.Public
		g03bgSign(t, auth, breakGlassDomain, rec, breakGlassBodyKeys)
		if r := bg.Accept(rec, 1500); r.Ok || r.Code != "store_unreachable" {
			t.Errorf("%s bg accept: %+v", name, r)
		}
		if d := bg.Use("g1", "h", "d", 2000, true); d.Decision != "deny" || d.Code != "store_unreachable" {
			t.Errorf("%s bg use: %+v", name, d)
		}
		if !bg.Frozen("h", 2000) {
			t.Errorf("%s bg frozen must fail closed", name)
		}
		rv := g03bgReview()
		rv["reviewer"] = auth.Public
		g03bgSign(t, auth, breakGlassReviewDomain, rv, breakGlassReviewKeys)
		if r := bg.Review(rv, "h", 3000); r.Ok || r.Code != "store_unreachable" {
			t.Errorf("%s bg review: %+v", name, r)
		}
		br := NewBlueprintRegistry([]string{op.id}, kv)
		if code, _ := br.Accept(parityBlueprint(t, op, "K", "active", nil)); code != "store_unreachable" {
			t.Errorf("%s blueprint accept: %q", name, code)
		}
		chain := []any{map[string]any{"issuer": "root", "holder": "K"}, map[string]any{"issuer": "K", "holder": "inst"}}
		if d := CheckBlueprints(chain, br, jnum(2), "any", nil); d.Decision != "deny" || d.Code != "store_unreachable" {
			t.Errorf("%s blueprint check: %+v", name, d)
		}
		min := int64(1)
		if d := CheckBlueprints(chain, br, jnum(2), "any", &min); d.Decision != "deny" || d.Code != "store_unreachable" {
			t.Errorf("%s blueprint epoch check: %+v", name, d)
		}
	}
}

// A stored document that does not decode is treated as an unreachable store, never as "empty".
func TestH15_AGarbledDocumentFailsClosed(t *testing.T) {
	k := newKey(t)
	kv := MemoryLeaseKv()
	_ = kv.Update(leaseMetaKey, func([]byte) []byte { return []byte(`{"v":1,"shards":16}`) })
	_ = kv.Update(leaseShardKey(DefaultLeaseShards, leaseShardOf("L1", DefaultLeaseShards)), func([]byte) []byte { return []byte("{not json") })
	r := NewLeaseRegistry(LeasePolicy{Authorities: []string{k.id}}, kv).Accept(g04SignLease(t, k, g04Lease()), nil)
	if r.Ok || r.Code != "store_unreachable" {
		t.Errorf("garbled: %+v", r)
	}
	bkv := MemoryBlueprintKv()
	_ = bkv.Update(blueprintKeyDoc("K"), func([]byte) []byte { return []byte(`null`) })
	op := newKey(t)
	if code, _ := NewBlueprintRegistry([]string{op.id}, bkv).Accept(parityBlueprint(t, op, "K", "active", nil)); code != "store_unreachable" {
		t.Errorf("null entry: %q", code)
	}
}
