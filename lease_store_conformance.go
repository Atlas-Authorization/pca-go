package pca

import (
	"encoding/json"
	"fmt"
	"sync"
)

// The conformance kit for lease storage. Run it against any AtomicKV (the in-memory one, an opened durable state, or your own
// database adapter) before trusting that store with leases:
//
//	passed, err := pca.RunLeaseStoreConformance(pca.LeaseStoreKit{Open: freshEmptyKv, Reopen: sameStoreOpenedAgain})
//
// It stops at the first failure with an error `lease store conformance: <check>: <detail>` and returns the checks passed. What it
// proves: leases spread over the shards; an update is atomic (of many concurrent renewals of one lease exactly one wins and the rest
// are forks); different leases do not interfere; a prefix revocation lands in every shard and a lease revocation only in its own; a
// store opened with another shard count is refused rather than silently empty; state survives a reopen (pass Reopen); a lease issued
// under a revoked prefix is a new lease; with a TTL ceiling, old revocations are pruned from every shard and a longer max_ttl is refused.

// LeaseStoreKit is what RunLeaseStoreConformance needs from a store.
type LeaseStoreKit struct {
	// Open returns a fresh, empty store.
	Open func() (AtomicKV, error)
	// Reopen returns the same store opened again as a restarted process would (state kept). Nil skips the restart check.
	Reopen func(kv AtomicKV) (AtomicKV, error)
	// Shards is the shard count (0: DefaultLeaseShards).
	Shards int
}

const (
	lscT0  int64 = 1_800_000_000_000
	lscDay int64 = 86_400_000
)

func lscMk(id string, over map[string]any) map[string]any {
	n := func(x int64) json.Number { return jsNumber(float64(x)) }
	rec := map[string]any{
		"lease_id": id, "path": fmt.Sprintf("svc/%d/%s", len(id)%3, id), "grant_ref": "g-" + id, "holder": "agent", "requester": "alice",
		"approvers": []any{"bob"}, "justification_digest": "j1", "seq": n(1), "issued_at": n(lscT0), "renewed_at": n(lscT0),
		"expires_at": n(lscT0 + 600_000), "max_ttl": n(3_600_000),
	}
	for k, v := range over {
		rec[k] = v
	}
	return rec
}

func lscErr(check, detail string, a ...any) error {
	return fmt.Errorf("lease store conformance: %s: %s", check, fmt.Sprintf(detail, a...))
}

func lscEq(check string, got, want any) error {
	g, _ := json.Marshal(got)
	w, _ := json.Marshal(want)
	if string(g) != string(w) {
		return lscErr(check, "got %s, want %s", g, w)
	}
	return nil
}

func lscSeqs(h []LeaseHistoryEntry, err error) []int64 {
	out := []int64{}
	if err != nil {
		return out
	}
	for _, e := range h {
		out = append(out, e.Seq)
	}
	return out
}

// RunLeaseStoreConformance runs the lease store checks (see above) and returns the names of the checks that passed.
func RunLeaseStoreConformance(kit LeaseStoreKit) (passed []string, err error) {
	shards := kit.Shards
	if shards == 0 {
		shards = DefaultLeaseShards
	}
	sk, err := KeyPairFromSeed(func() []byte {
		b := make([]byte, 32)
		for i := range b {
			b[i] = 61
		}
		return b
	}())
	if err != nil {
		return nil, err
	}
	policy := LeasePolicy{Authorities: []string{sk.Public}}
	sign := func(over map[string]any, id string) map[string]any {
		r, serr := SignLease(sk, lscMk(id, over))
		if serr != nil {
			panic(serr)
		}
		return r
	}
	signRev := func(target, value string, at int64) map[string]any {
		r, serr := SignLeaseRevocation(sk, map[string]any{"target": target, "value": value, "revoked_at": jsNumber(float64(at))})
		if serr != nil {
			panic(serr)
		}
		return r
	}
	num := func(x int64) json.Number { return jsNumber(float64(x)) }
	open := func() AtomicKV {
		kv, oerr := kit.Open()
		if oerr != nil {
			panic(oerr)
		}
		return kv
	}
	ok := func(name string) { passed = append(passed, name) }
	defer func() {
		if r := recover(); r != nil {
			if e, isErr := r.(error); isErr {
				err = e
			} else {
				err = fmt.Errorf("lease store conformance: %v", r)
			}
		}
	}()

	// 1. spread
	{
		reg := NewLeaseRegistryShards(policy, open(), shards)
		ids := make([]string, 256)
		for i := range ids {
			ids[i] = fmt.Sprintf("lease-%d", i)
		}
		for _, id := range ids {
			if e := lscEq("spread: issue "+id, reg.Accept(sign(nil, id), nil).Ok, true); e != nil {
				return passed, e
			}
		}
		per := make([]int, shards)
		for _, id := range ids {
			per[leaseShardOf(id, shards)]++
		}
		hi, used := 0, 0
		for _, n := range per {
			if n > hi {
				hi = n
			}
			if n > 0 {
				used++
			}
		}
		if hi > len(ids)/4 || used < shards/2 {
			return passed, lscErr("spread", "256 leases landed %v", per)
		}
		for _, id := range ids {
			if cur := reg.Get(id); cur == nil || cur["lease_id"] != id {
				return passed, lscErr("spread", "%s not found after issue", id)
			}
		}
		ok("spread")
	}

	// 2. atomic update
	{
		reg := NewLeaseRegistryShards(policy, open(), shards)
		reg.Accept(sign(nil, "hot"), nil)
		results := make([]LeaseAcceptResult, 8)
		var wg sync.WaitGroup
		for i := range results {
			rival := sign(map[string]any{"seq": num(2), "renewed_at": num(lscT0 + 1000), "expires_at": num(lscT0 + 700_000 + int64(i)), "justification_digest": fmt.Sprintf("r%d", i)}, "hot")
			wg.Add(1)
			go func(i int, rival map[string]any) {
				defer wg.Done()
				results[i] = reg.Accept(rival, nil)
			}(i, rival)
		}
		wg.Wait()
		won, forks := 0, 0
		for _, r := range results {
			if r.Ok {
				won++
			} else if r.Code == "lease_fork" {
				forks++
			}
		}
		for _, e := range []error{lscEq("atomic: one winner", won, 1), lscEq("atomic: the rest are forks", forks, 7), lscEq("atomic: ledger length", lscSeqs(reg.History("hot")), []int64{1, 2})} {
			if e != nil {
				return passed, e
			}
		}
		ok("atomic update")
	}

	// 3. independence
	{
		reg := NewLeaseRegistryShards(policy, open(), shards)
		ids := make([]string, 32)
		for i := range ids {
			ids[i] = fmt.Sprintf("ind-%d", i)
		}
		var wg sync.WaitGroup
		for _, id := range ids {
			rec := sign(nil, id)
			wg.Add(1)
			go func() { defer wg.Done(); reg.Accept(rec, nil) }()
		}
		wg.Wait()
		renewed := make([]bool, len(ids))
		for i, id := range ids {
			rec := sign(map[string]any{"seq": num(2), "renewed_at": num(lscT0 + 10), "expires_at": num(lscT0 + 900_000), "justification_digest": "j2"}, id)
			wg.Add(1)
			go func(i int) { defer wg.Done(); renewed[i] = reg.Accept(rec, nil).Ok }(i)
		}
		wg.Wait()
		all := true
		for _, r := range renewed {
			all = all && r
		}
		if e := lscEq("independence", all, true); e != nil {
			return passed, e
		}
		ok("independent leases")
	}

	// 4 + 5. revocation placement
	{
		reg := NewLeaseRegistryShards(policy, open(), shards)
		ids := make([]string, 64)
		for i := range ids {
			ids[i] = fmt.Sprintf("rv-%d", i)
			reg.Accept(sign(map[string]any{"path": "db/prod/ro"}, ids[i]), nil)
		}
		lone := sign(map[string]any{"path": "other/x"}, "lone")
		reg.Accept(lone, nil)
		byLease := signRev("lease", "lone", lscT0+5)
		code, n := reg.Revoke(byLease)
		if e := lscEq("revoke by lease", []any{code, n}, []any{"", 1}); e != nil {
			return passed, e
		}
		holders := 0
		for i := 0; i < shards; i++ {
			if l, _ := reg.ShardRevocations(i); len(l) > 0 {
				holders++
			}
		}
		if e := lscEq("lease revocation lands in exactly one shard", holders, 1); e != nil {
			return passed, e
		}
		if e := lscEq("revoked lease is dead", CheckLease(lone, reg, num(lscT0+6)).Decision, "deny"); e != nil {
			return passed, e
		}
		byPrefix := signRev("prefix", "db/prod", lscT0+10)
		code, n = reg.Revoke(byPrefix)
		if e := lscEq("revoke by prefix covers every lease in every shard", []any{code, n}, []any{"", 64}); e != nil {
			return passed, e
		}
		code, n = reg.Revoke(byPrefix)
		if e := lscEq("revoke twice is idempotent", []any{code, n}, []any{"", 64}); e != nil {
			return passed, e
		}
		for i := 0; i < shards; i++ {
			list, _ := reg.ShardRevocations(i)
			have := 0
			for _, r := range list {
				if r["sig"] == byPrefix["sig"] {
					have++
				}
			}
			if have == 0 {
				return passed, lscErr("prefix revocation in every shard", "shard %d lacks it", i)
			}
			if e := lscEq(fmt.Sprintf("no duplicate in shard %d", i), have, 1); e != nil {
				return passed, e
			}
		}
		for _, id := range ids {
			cur := reg.Get(id)
			if e := lscEq("check "+id, CheckLease(cur, reg, num(lscT0+11)).Decision, "deny"); e != nil {
				return passed, e
			}
			renewal := sign(map[string]any{"path": "db/prod/ro", "seq": num(2), "renewed_at": num(lscT0 + 20), "expires_at": num(lscT0 + 700_000), "justification_digest": "x"}, id)
			if e := lscEq("renewal of "+id+" refused", reg.Accept(renewal, nil).Ok, false); e != nil {
				return passed, e
			}
		}
		fresh := sign(map[string]any{"path": "db/prod/ro", "issued_at": num(lscT0 + 100), "renewed_at": num(lscT0 + 100), "expires_at": num(lscT0 + 900_000)}, "after")
		if e := lscEq("a lease issued after the revocation is new", reg.Accept(fresh, nil).Ok, true); e != nil {
			return passed, e
		}
		ok("revocation placement")
	}

	// 6. shard-count mismatch
	{
		kv := open()
		NewLeaseRegistryShards(policy, kv, shards).Accept(sign(nil, "m1"), nil)
		other := NewLeaseRegistryShards(policy, kv, shards*2)
		r := other.Accept(sign(nil, "m2"), nil)
		if e := lscEq("shard mismatch accept", []any{r.Ok, r.Code}, []any{false, "store_unreachable"}); e != nil {
			return passed, e
		}
		if e := lscEq("shard mismatch check", CheckLease(sign(nil, "m1"), other, num(lscT0+1)).Decision, "deny"); e != nil {
			return passed, e
		}
		ok("shard count is pinned")
	}

	// 7. restart
	if kit.Reopen != nil {
		kv := open()
		reg := NewLeaseRegistryShards(policy, kv, shards)
		l := sign(nil, "persist")
		reg.Accept(l, nil)
		reg.Accept(sign(map[string]any{"seq": num(2), "renewed_at": num(lscT0 + 5), "expires_at": num(lscT0 + 800_000), "justification_digest": "j2"}, "persist"), nil)
		reg.Revoke(signRev("prefix", "gone", lscT0+50))
		kv2, rerr := kit.Reopen(kv)
		if rerr != nil {
			return passed, lscErr("restart", "reopen failed: %v", rerr)
		}
		again := NewLeaseRegistryShards(policy, kv2, shards)
		revs, _ := again.ShardRevocations(0)
		for _, e := range []error{lscEq("restart: renewal ledger", lscSeqs(again.History("persist")), []int64{1, 2}), lscEq("restart: revocation kept", len(revs), 1),
			lscEq("restart: old record still superseded", CheckLease(l, again, num(lscT0+6)).Decision, "deny")} {
			if e != nil {
				return passed, e
			}
		}
		ok("state survives a restart")
	}

	// 8. ceiling and pruning
	{
		now := lscT0
		ceiling := lscDay
		reg := NewLeaseRegistryShards(LeasePolicy{Authorities: []string{sk.Public}, MaxTtlCeiling: &ceiling}, open(), shards)
		reg.clock = func() int64 { return now }
		r := reg.Accept(sign(map[string]any{"max_ttl": num(lscDay + 1), "expires_at": num(lscT0 + 1000)}, "big"), nil)
		if e := lscEq("ceiling refuses a longer max_ttl", []any{r.Ok, r.Code}, []any{false, "ttl_ceiling"}); e != nil {
			return passed, e
		}
		reg.Accept(sign(map[string]any{"max_ttl": num(lscDay)}, "small"), nil)
		reg.Revoke(signRev("prefix", "svc", lscT0))
		for i := 0; i < shards; i++ {
			l, _ := reg.ShardRevocations(i)
			if e := lscEq(fmt.Sprintf("kept before the ceiling passes (shard %d)", i), len(l), 1); e != nil {
				return passed, e
			}
		}
		now = lscT0 + lscDay + 1
		reg.Accept(sign(map[string]any{"issued_at": num(now), "renewed_at": num(now), "expires_at": num(now + 1000), "max_ttl": num(5000)}, "trigger"), nil)
		reg.Revoke(signRev("prefix", "zzz", now))
		for i := 0; i < shards; i++ {
			l, _ := reg.ShardRevocations(i)
			hasSvc, hasZzz := false, false
			for _, rv := range l {
				hasSvc = hasSvc || rv["value"] == "svc"
				hasZzz = hasZzz || rv["value"] == "zzz"
			}
			if hasSvc {
				return passed, lscErr("pruning", "shard %d still holds the expired revocation", i)
			}
			if !hasZzz {
				return passed, lscErr("pruning", "shard %d lost the fresh revocation", i)
			}
		}
		ok("pruning bounds revocations")
	}
	return passed, nil
}
