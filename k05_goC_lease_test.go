package pca

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// goCKV is a recording AtomicKV over a memory store with switchable faults.
type goCKV struct {
	inner      *MemoryAtomicKV
	writes     map[string]int
	calls      map[string]int
	failUpdate func(key string) bool // Update fails before running
	failGet    func(key string) bool
	skip       func(key string) bool // Update returns nil without running the callback
	retry      func(key string) bool // the callback runs once extra (discarded) before the real update
	errAfter   func(key string) bool // the update is applied, then an error is returned
}

func goCNewKV() *goCKV {
	return &goCKV{inner: NewMemoryAtomicKV(), writes: map[string]int{}, calls: map[string]int{}}
}

func (k *goCKV) Get(key string) ([]byte, bool, error) {
	if k.failGet != nil && k.failGet(key) {
		return nil, false, errors.New("down")
	}
	return k.inner.Get(key)
}

func (k *goCKV) Update(key string, fn func(prev []byte) []byte) error {
	k.calls[key]++
	if k.failUpdate != nil && k.failUpdate(key) {
		return errors.New("down")
	}
	if k.skip != nil && k.skip(key) {
		return nil
	}
	if k.retry != nil && k.retry(key) {
		prev, ok, _ := k.inner.Get(key)
		if !ok {
			prev = nil
		}
		fn(prev)
	}
	err := k.inner.Update(key, func(prev []byte) []byte {
		out := fn(prev)
		if out != nil {
			k.writes[key]++
		}
		return out
	})
	if err == nil && k.errAfter != nil && k.errAfter(key) {
		return errors.New("late")
	}
	return err
}

func goCSum(m map[string]int, prefix string) (total, distinct int) {
	for k, v := range m {
		if strings.HasPrefix(k, prefix) && v > 0 {
			total += v
			distinct++
		}
	}
	return
}

func goCPanicMsg(f func()) (msg string) {
	defer func() {
		if r := recover(); r != nil {
			msg = fmt.Sprint(r)
		}
	}()
	f()
	return ""
}

func goCNotMeta(key string) bool { return key != leaseMetaKey }

func TestGoCLeaseShardBounds(t *testing.T) {
	if MaxLeaseShards != 4096 || DefaultLeaseShards != 16 {
		t.Fatal("shard constants changed")
	}
	want := "LeaseRegistry: shards must be an integer from 1 to 4096"
	for _, n := range []int{0, -1, 4097} {
		n := n
		if got := goCPanicMsg(func() { NewLeaseRegistryShards(LeasePolicy{}, NewMemoryAtomicKV(), n) }); got != want {
			t.Errorf("shards %d: %q", n, got)
		}
	}
	for _, n := range []int{1, 4096} {
		if r := NewLeaseRegistryShards(LeasePolicy{}, NewMemoryAtomicKV(), n); r == nil || r.shards != n {
			t.Errorf("shards %d must be accepted", n)
		}
	}
}

func TestGoCLeaseShardOf(t *testing.T) {
	for i := 0; i < 64; i++ {
		id := fmt.Sprintf("lease-%d", i)
		h := sha256.Sum256([]byte(id))
		for _, n := range []int{1, 3, 16, 1000, 4093, 4096} {
			if got, want := leaseShardOf(id, n), int(binary.BigEndian.Uint32(h[:4])%uint32(n)); got != want {
				t.Fatalf("%s/%d: got %d want %d", id, n, got, want)
			}
		}
	}
}

func TestGoCLeaseLoadDump(t *testing.T) {
	r := &LeaseRegistry{}
	if err := r.load([]byte(`{"leases":{"a":{"current":null,"history":[]}},"revocations":[]}`)); err != errStoreState {
		t.Errorf("a stored lease with no current record: %v", err)
	}
	if err := r.load([]byte(`{"leases":{"a":{"current":{"seq":1},"history":[]}},"revocations":[]}`)); err != nil || r.leases["a"] == nil {
		t.Errorf("valid doc: %v", err)
	}
	d := &LeaseRegistry{leases: map[string]*leaseState{}}
	if got := string(d.dump()); got != `{"leases":{},"revocations":[]}` {
		t.Errorf("dump: %s", got)
	}
}

func TestGoCLeaseReady(t *testing.T) {
	kv := goCNewKV()
	r1 := NewLeaseRegistryShards(LeasePolicy{}, kv, 16)
	if err := r1.ready(); err != nil {
		t.Fatal(err)
	}
	if got, _, _ := kv.inner.Get(leaseMetaKey); string(got) != `{"shards":16,"v":1}` {
		t.Errorf("meta: %s", got)
	}
	calls := kv.calls[leaseMetaKey]
	if err := r1.ready(); err != nil || kv.calls[leaseMetaKey] != calls {
		t.Errorf("a pinned registry must not touch the store again: %v", err)
	}
	r2 := NewLeaseRegistryShards(LeasePolicy{}, kv, 16)
	if err := r2.ready(); err != nil || kv.writes[leaseMetaKey] != 1 || !r2.metaOK {
		t.Errorf("same count: err=%v writes=%d", err, kv.writes[leaseMetaKey])
	}
	r3 := NewLeaseRegistryShards(LeasePolicy{}, kv, 8)
	if err := r3.ready(); err == nil || err.Error() != "pca: the lease store was opened with another shard count" || r3.metaOK {
		t.Errorf("other count: %v", err)
	}
	if kv.writes[leaseMetaKey] != 1 {
		t.Error("a refused count must not rewrite the pin")
	}
	// an unreadable pin is refused and left alone
	bad := goCNewKV()
	_ = bad.inner.Update(leaseMetaKey, func([]byte) []byte { return []byte("not json") })
	if err := NewLeaseRegistryShards(LeasePolicy{}, bad, 16).ready(); err != errStoreState {
		t.Errorf("garbage pin: %v", err)
	}
	if got, _, _ := bad.inner.Get(leaseMetaKey); string(got) != "not json" {
		t.Errorf("garbage pin was overwritten: %s", got)
	}
	// store failure surfaces its own error
	if err := NewLeaseRegistryShards(LeasePolicy{}, brokenKv{}, 16).ready(); err == nil || err.Error() != "down" {
		t.Errorf("broken store: %v", err)
	}
	// a retried callback starts clean
	retry := goCBeaconKV{func(_ string, fn func([]byte) []byte) error {
		fn([]byte(`{"v":1,"shards":8}`))
		fn(nil)
		return nil
	}}
	if err := NewLeaseRegistryShards(LeasePolicy{}, retry, 16).ready(); err != nil {
		t.Errorf("stored count leaked across a retry: %v", err)
	}
}

func TestGoCLeaseRegistryRejectionsDoNotWrite(t *testing.T) {
	k := newKey(t)
	kv := goCNewKV()
	reg := NewLeaseRegistry(LeasePolicy{Authorities: []string{k.id}}, kv)
	mk := func(mut func(l map[string]any)) map[string]any {
		l := g04Lease()
		l["seq"], l["renewed_at"], l["expires_at"], l["justification_digest"] = jnum(2), jnum(150), jnum(300), "J2"
		if mut != nil {
			mut(l)
		}
		return g04SignLease(t, k, l)
	}
	mk3 := func(mut func(l map[string]any)) map[string]any {
		return mk(func(l map[string]any) {
			l["seq"], l["renewed_at"], l["expires_at"], l["justification_digest"] = jnum(3), jnum(160), jnum(310), "J3"
			if mut != nil {
				mut(l)
			}
		})
	}
	writes := func() int { n, _ := goCSum(kv.writes, "lease/16/"); return n }
	if r := reg.Accept(g04SignLease(t, k, g04Lease()), nil); !r.Ok || !r.Replaced || r.Seq != 1 {
		t.Fatalf("issue: %+v", r)
	}
	if writes() != 1 {
		t.Fatalf("issue writes: %d", writes())
	}
	reject := func(name string, rec map[string]any, code, reason string) {
		t.Helper()
		before := writes()
		r := reg.Accept(rec, nil)
		if r.Ok || r.Code != code || r.Reason != reason || writes() != before {
			t.Errorf("%s: %+v (wrote %d)", name, r, writes()-before)
		}
	}
	reject("new lease at seq 2", mk(func(l map[string]any) { l["lease_id"] = "L2" }), "bad_seq", "a new lease starts at seq 1")
	if r := reg.Accept(mk(nil), nil); !r.Ok || !r.Replaced || r.Seq != 2 || writes() != 2 {
		t.Fatalf("renew: %+v", r)
	}
	reject("stale", g04SignLease(t, k, g04Lease()), "stale_seq", "")
	before := writes()
	if r := reg.Accept(mk(nil), nil); !r.Ok || r.Replaced || r.Seq != 2 || writes() != before {
		t.Errorf("idempotent resend: %+v", r)
	}
	reject("fork", mk(func(l map[string]any) { l["justification_digest"] = "JZ" }), "lease_fork", "")
	reject("skip a seq", mk(func(l map[string]any) { l["seq"] = jnum(4) }), "bad_seq", "renewals advance seq by exactly 1")
	reject("holder", mk3(func(l map[string]any) { l["holder"] = "H2" }), "renewal_mismatch", "")
	reject("max_ttl", mk3(func(l map[string]any) { l["max_ttl"] = jnum(2000) }), "renewal_mismatch", "")
	reject("issued_at", mk3(func(l map[string]any) { l["issued_at"] = jnum(90) }), "renewal_mismatch", "")
	reject("expired", mk3(func(l map[string]any) { l["renewed_at"], l["expires_at"] = jnum(300), jnum(400) }), "expired_lease", "an expired lease cannot be renewed")
	reject("renewed_at backwards", mk3(func(l map[string]any) { l["renewed_at"], l["expires_at"] = jnum(140), jnum(400) }), "not_extending", "")
	reject("expires_at not later", mk3(func(l map[string]any) { l["expires_at"] = jnum(300) }), "not_extending", "")
	reject("same justification", mk3(func(l map[string]any) { l["justification_digest"] = "J2" }), "stale_justification", "")
	// a revoked lease is refused without a write
	if code, n := reg.Revoke(g04SignRev(t, k, map[string]any{"v": jnum(1), "target": "lease", "value": "L1", "revoked_at": jnum(500)})); code != "" || n != 1 {
		t.Fatalf("revoke: %q %d", code, n)
	}
	reject("revoked", mk3(nil), "revoked", "")
}

func TestGoCLeaseFreshJustificationOptOut(t *testing.T) {
	k := newKey(t)
	f := false
	reg := NewLeaseRegistry(LeasePolicy{Authorities: []string{k.id}, FreshJustification: &f}, NewMemoryAtomicKV())
	if r := reg.Accept(g04SignLease(t, k, g04Lease()), nil); !r.Ok {
		t.Fatal(r)
	}
	l := g04Lease()
	l["seq"], l["renewed_at"], l["expires_at"] = jnum(2), jnum(150), jnum(300)
	if r := reg.Accept(g04SignLease(t, k, l), nil); !r.Ok || r.Seq != 2 {
		t.Errorf("same justification must be allowed when freshness is off: %+v", r)
	}
	tr := true
	reg2 := NewLeaseRegistry(LeasePolicy{Authorities: []string{k.id}, FreshJustification: &tr}, NewMemoryAtomicKV())
	reg2.Accept(g04SignLease(t, k, g04Lease()), nil)
	l2 := g04Lease()
	l2["seq"], l2["renewed_at"], l2["expires_at"] = jnum(2), jnum(150), jnum(300)
	if r := reg2.Accept(g04SignLease(t, k, l2), nil); r.Ok || r.Code != "stale_justification" {
		t.Errorf("explicit freshness: %+v", r)
	}
}

func TestGoCLeaseStoreFaultsAndMismatch(t *testing.T) {
	k := newKey(t)
	pol := LeasePolicy{Authorities: []string{k.id}}
	rec := g04SignLease(t, k, g04Lease())
	rev := g04SignRev(t, k, map[string]any{"v": jnum(1), "target": "lease", "value": "L1", "revoked_at": jnum(500)})
	kv := goCNewKV()
	a := NewLeaseRegistry(pol, kv)
	if r := a.Accept(rec, nil); !r.Ok {
		t.Fatal(r)
	}
	// a registry opened with another shard count over the same store is refused everywhere
	b := NewLeaseRegistryShards(pol, kv, 8)
	if r := b.Accept(rec, nil); r.Ok || r.Code != "store_unreachable" {
		t.Errorf("accept: %+v", r)
	}
	if code, n := b.Revoke(rev); code != "store_unreachable" || n != 0 {
		t.Errorf("revoke: %q %d", code, n)
	}
	if d := CheckLease(rec, b, jnum(150)); d.Decision != "deny" || d.Code != "store_unreachable" || d.LeaseID != "L1" {
		t.Errorf("check: %+v", d)
	}
	if cur, revoked, err := b.lookup("L1"); cur != nil || revoked || err == nil {
		t.Errorf("lookup: %v %v %v", cur, revoked, err)
	}
	if b.Get("L1") != nil {
		t.Error("get through a mismatched registry")
	}
	if n, _ := goCSum(kv.writes, "lease/8/"); n != 0 {
		t.Errorf("the refused registry wrote %d shard documents", n)
	}

	// a lookup of an unknown id is a clean miss
	if cur, revoked, err := a.lookup("nope"); cur != nil || revoked || err != nil {
		t.Errorf("unknown: %v %v %v", cur, revoked, err)
	}

	// shard read failure
	kv.failGet = goCNotMeta
	if cur, revoked, err := a.lookup("L1"); cur != nil || revoked || err == nil {
		t.Errorf("read fault: %v %v %v", cur, revoked, err)
	}
	if d := CheckLease(rec, a, jnum(150)); d.Decision != "deny" || d.Code != "store_unreachable" {
		t.Errorf("check on read fault: %+v", d)
	}
	kv.failGet = nil

	// shard write failure
	kv.failUpdate = goCNotMeta
	if code, n := a.Revoke(rev); code != "store_unreachable" || n != 0 {
		t.Errorf("revoke on write fault: %q %d", code, n)
	}
	l2 := g04Lease()
	l2["seq"], l2["renewed_at"], l2["expires_at"], l2["justification_digest"] = jnum(2), jnum(150), jnum(300), "J2"
	if r := a.Accept(g04SignLease(t, k, l2), nil); r.Ok || r.Code != "store_unreachable" {
		t.Errorf("accept on write fault: %+v", r)
	}
	kv.failUpdate = nil

	// the update is applied but its acknowledgement fails: never an allow
	kv.errAfter = goCNotMeta
	if r := a.Accept(g04SignLease(t, k, l2), nil); r.Ok || r.Code != "store_unreachable" || r.Seq != 0 {
		t.Errorf("accept on late fault: %+v", r)
	}
	kv.errAfter = nil
}

func TestGoCLeaseRevokeFanOutAndCount(t *testing.T) {
	k := newKey(t)
	pol := LeasePolicy{Authorities: []string{k.id}}
	kv := goCNewKV()
	reg := NewLeaseRegistry(pol, kv)
	if r := reg.Accept(g04SignLease(t, k, g04Lease()), nil); !r.Ok {
		t.Fatal(r)
	}
	// a revocation of one lease touches one shard; a prefix revocation touches all of them
	for k2 := range kv.writes {
		delete(kv.writes, k2)
	}
	if code, n := reg.Revoke(g04SignRev(t, k, map[string]any{"v": jnum(1), "target": "lease", "value": "L1", "revoked_at": jnum(500)})); code != "" || n != 1 {
		t.Fatalf("lease revoke: %q %d", code, n)
	}
	if _, distinct := goCSum(kv.writes, "lease/16/"); distinct != 1 {
		t.Errorf("a lease revocation wrote %d shards", distinct)
	}
	if code, n := reg.Revoke(g04SignRev(t, k, map[string]any{"v": jnum(1), "target": "prefix", "value": "db", "revoked_at": jnum(600)})); code != "" || n != 1 {
		t.Fatalf("prefix revoke: %q %d", code, n)
	}
	if _, distinct := goCSum(kv.writes, "lease/16/"); distinct != 16 {
		t.Errorf("a prefix revocation wrote %d shards", distinct)
	}
	// a callback retried by an optimistic store counts each lease once
	kv.retry = goCNotMeta
	if code, n := reg.Revoke(g04SignRev(t, k, map[string]any{"v": jnum(1), "target": "grant", "value": "G1", "revoked_at": jnum(700)})); code != "" || n != 1 {
		t.Errorf("retried revoke: %q %d", code, n)
	}
	// a store that never runs the callback covered nothing
	kv2 := goCNewKV()
	kv2.skip = goCNotMeta
	reg2 := NewLeaseRegistry(pol, kv2)
	if code, n := reg2.Revoke(g04SignRev(t, k, map[string]any{"v": jnum(1), "target": "lease", "value": "L1", "revoked_at": jnum(500)})); code != "" || n != 0 {
		t.Errorf("skipped callback: %q %d", code, n)
	}
}

func TestGoCLeaseRegistryUnknownBrokenStore(t *testing.T) {
	k := newKey(t)
	reg := NewLeaseRegistry(LeasePolicy{Authorities: []string{k.id}}, brokenKv{})
	if code, n := reg.Revoke(g04SignRev(t, k, map[string]any{"v": jnum(1), "target": "lease", "value": "L1", "revoked_at": jnum(500)})); code != "store_unreachable" || n != 0 {
		t.Errorf("revoke: %q %d", code, n)
	}
}
