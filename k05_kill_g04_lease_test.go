package pca

// g04 mutation kills for lease.go: every leaseWellFormed / leaseRevWellFormed refusal observed directly (bool AND map), the
// separation-of-duties bounds, and the registry's renewal / revocation bookkeeping with natively signed records.

import (
	"strings"
	"testing"
)

func g04Lease() map[string]any {
	return map[string]any{"v": jnum(1), "lease_id": "L1", "path": "db/main", "grant_ref": "G1", "holder": "H", "requester": "R",
		"approvers": []any{"A1"}, "justification_digest": "J1", "seq": jnum(1), "issued_at": jnum(100), "renewed_at": jnum(100),
		"expires_at": jnum(200), "max_ttl": jnum(1000), "authority": "AUTH"}
}

func g04Many(n int) []any {
	out := make([]any, n)
	for i := range out {
		out[i] = "A" + strings.Repeat("x", i)
	}
	return out
}

func TestG04LeaseWellFormed(t *testing.T) {
	if m, ok := leaseWellFormed(g04Lease()); !ok || m["lease_id"] != "L1" {
		t.Fatal("base lease must be well formed")
	}
	if m, ok := leaseWellFormed("x"); ok || m != nil {
		t.Fatal("a non-object")
	}
	s := strings.Repeat
	for _, c := range []struct {
		name string
		mut  func(l map[string]any)
		ok   bool
	}{
		{"v 2", func(l map[string]any) { l["v"] = jnum(2) }, false},
		{"v absent", func(l map[string]any) { delete(l, "v") }, false},
		{"lease_id 128", func(l map[string]any) { l["lease_id"] = s("a", 128) }, true},
		{"lease_id 129", func(l map[string]any) { l["lease_id"] = s("a", 129) }, false},
		{"grant_ref 256", func(l map[string]any) { l["grant_ref"] = s("a", 256) }, true},
		{"grant_ref 257", func(l map[string]any) { l["grant_ref"] = s("a", 257) }, false},
		{"holder 128", func(l map[string]any) { l["holder"] = s("a", 128) }, true},
		{"holder 129", func(l map[string]any) { l["holder"] = s("a", 129) }, false},
		{"requester 128", func(l map[string]any) { l["requester"] = s("a", 128) }, true},
		{"requester 129", func(l map[string]any) { l["requester"] = s("a", 129) }, false},
		{"authority 128", func(l map[string]any) { l["authority"] = s("a", 128) }, true},
		{"authority 129", func(l map[string]any) { l["authority"] = s("a", 129) }, false},
		{"justification 128", func(l map[string]any) { l["justification_digest"] = s("a", 128) }, true},
		{"justification 129", func(l map[string]any) { l["justification_digest"] = s("a", 129) }, false},
		{"path not a string", func(l map[string]any) { l["path"] = jnum(1) }, false},
		{"path bad", func(l map[string]any) { l["path"] = "DB" }, false},
		{"seq not an int", func(l map[string]any) { l["seq"] = "1" }, false},
		{"seq 0", func(l map[string]any) { l["seq"] = jnum(0) }, false},
		{"max_ttl 0", func(l map[string]any) { l["max_ttl"] = jnum(0) }, false},
		{"max_ttl 1", func(l map[string]any) { l["max_ttl"] = jnum(1) }, true},
		{"renewed < issued", func(l map[string]any) { l["seq"], l["renewed_at"] = jnum(2), jnum(99) }, false},
		{"seq 2 renewed == issued", func(l map[string]any) { l["seq"] = jnum(2) }, true},
		{"seq 2 renewed > issued", func(l map[string]any) { l["seq"], l["renewed_at"] = jnum(2), jnum(101) }, true},
		{"seq 1 renewed != issued", func(l map[string]any) { l["renewed_at"] = jnum(101) }, false},
		{"expires == renewed", func(l map[string]any) { l["expires_at"] = jnum(100) }, false},
		{"expires == renewed + 1", func(l map[string]any) { l["expires_at"] = jnum(101) }, true},
		{"approvers absent", func(l map[string]any) { delete(l, "approvers") }, false},
		{"approvers 16", func(l map[string]any) { l["approvers"] = g04Many(16) }, true},
		{"approvers 17", func(l map[string]any) { l["approvers"] = g04Many(17) }, false},
		{"approver 128", func(l map[string]any) { l["approvers"] = []any{s("a", 128)} }, true},
		{"approver 129", func(l map[string]any) { l["approvers"] = []any{s("a", 129)} }, false},
	} {
		l := g04Lease()
		c.mut(l)
		m, ok := leaseWellFormed(l)
		if ok != c.ok || (ok && m == nil) || (!ok && m != nil) {
			t.Errorf("%s: %v %v, want %v", c.name, m != nil, ok, c.ok)
		}
	}
}

func g04Rev() map[string]any {
	return map[string]any{"v": jnum(1), "target": "lease", "value": "L1", "revoked_at": jnum(10), "authority": "AUTH"}
}

func TestG04LeaseRevWellFormed(t *testing.T) {
	if m, ok := leaseRevWellFormed(g04Rev()); !ok || m == nil {
		t.Fatal("base revocation")
	}
	if m, ok := leaseRevWellFormed(jnum(1)); ok || m != nil {
		t.Fatal("a non-object")
	}
	s := strings.Repeat
	for _, c := range []struct {
		name  string
		mut   func(r map[string]any)
		ok    bool
		isNil bool
	}{
		{"v 2", func(r map[string]any) { r["v"] = jnum(2) }, false, true},
		{"v absent", func(r map[string]any) { delete(r, "v") }, false, true},
		{"value 256", func(r map[string]any) { r["value"] = s("a", 256) }, true, false},
		{"value 257", func(r map[string]any) { r["value"] = s("a", 257) }, false, true},
		{"authority 128", func(r map[string]any) { r["authority"] = s("a", 128) }, true, false},
		{"authority 129", func(r map[string]any) { r["authority"] = s("a", 129) }, false, true},
		{"revoked_at bad", func(r map[string]any) { r["revoked_at"] = "x" }, false, true},
		{"target bad", func(r map[string]any) { r["target"] = "x" }, false, true},
		{"target grant", func(r map[string]any) { r["target"] = "grant" }, true, false},
		{"prefix ok", func(r map[string]any) { r["target"], r["value"] = "prefix", "db" }, true, false},
		{"prefix bad path", func(r map[string]any) { r["target"], r["value"] = "prefix", "DB" }, false, false},
	} {
		r := g04Rev()
		c.mut(r)
		m, ok := leaseRevWellFormed(r)
		if ok != c.ok || (m == nil) != c.isNil {
			t.Errorf("%s: map %v ok %v, want ok %v nil %v", c.name, m != nil, ok, c.ok, c.isNil)
		}
	}
}

func TestG04LeaseHelpers(t *testing.T) {
	for _, c := range []struct {
		path, prefix string
		want         bool
	}{{"a/b", "a", true}, {"ab", "a", false}, {"a", "a", true}, {"a", "a/b", false}, {"b", "a", false}} {
		if LeasePathUnder(c.path, c.prefix) != c.want {
			t.Errorf("LeasePathUnder(%q, %q)", c.path, c.prefix)
		}
	}
	l := map[string]any{"issued_at": jnum(5), "lease_id": "L", "grant_ref": "G", "path": "a/b"}
	if !leaseCovers(map[string]any{"revoked_at": jnum(5), "target": "lease", "value": "L"}, l) {
		t.Error("issued_at == revoked_at is covered")
	}
	if leaseCovers(map[string]any{"revoked_at": jnum(4), "target": "lease", "value": "L"}, l) {
		t.Error("issued after the revocation is not covered")
	}
	if r := leaseFail("c", "why"); r.Code != "c" || r.Reason != "why" || r.Ok {
		t.Errorf("leaseFail with reason: %+v", r)
	}
	if r := leaseFail("c"); r.Code != "c" || r.Reason != "" {
		t.Errorf("leaseFail: %+v", r)
	}
	sod := func(k int64) string {
		return LeaseSodError(map[string]any{"approvers": []any{"A1"}, "requester": "R", "holder": "H"}, LeasePolicy{MinApprovals: &k}, nil)
	}
	const pos = "minApprovals must be a positive integer"
	for k, want := range map[int64]string{0: pos, -1: pos, 1: "", 2: "too few approvers", 1<<53 - 1: "too few approvers", 1 << 53: pos} {
		if got := sod(k); got != want {
			t.Errorf("minApprovals %d: %q, want %q", k, got, want)
		}
	}
}

// g04SignLease signs a lease record with k (authority = k).
func g04SignLease(t *testing.T, k fxKey, l map[string]any) map[string]any {
	l["authority"] = k.id
	l["sig"] = signDomain(t, k, leaseDomain, leasePick(l, leaseBodyKeys))
	return l
}

func g04SignRev(t *testing.T, k fxKey, r map[string]any) map[string]any {
	r["authority"] = k.id
	r["sig"] = signDomain(t, k, leaseRevokeDomain, leasePick(r, leaseRevKeys))
	return r
}

func TestG04LeaseRegistryRenewal(t *testing.T) {
	k := newKey(t)
	pol := LeasePolicy{Authorities: []string{k.id}}
	issue := g04SignLease(t, k, g04Lease())
	renew := func(mut func(l map[string]any)) map[string]any {
		l := g04Lease()
		l["seq"], l["renewed_at"], l["expires_at"], l["justification_digest"] = jnum(2), jnum(150), jnum(300), "J2"
		if mut != nil {
			mut(l)
		}
		return g04SignLease(t, k, l)
	}
	reg := NewLeaseRegistry(pol, MemoryLeaseKv())
	if r := reg.Accept(issue, nil); !r.Ok || !r.Replaced || r.Seq != 1 {
		t.Fatalf("issue: %+v", r)
	}
	if r := reg.Accept(renew(nil), nil); !r.Ok || !r.Replaced || r.Seq != 2 {
		t.Fatalf("renew: %+v", r)
	}
	if h := reg.leases["L1"].history; len(h) != 2 || h[0].Seq != 1 || h[1].Seq != 2 || h[1].JustificationDigest != "J2" {
		t.Fatalf("history: %+v", h)
	}
	for name, c := range map[string]struct {
		mut  func(l map[string]any)
		code string
	}{
		"max_ttl changed":        {func(l map[string]any) { l["max_ttl"] = jnum(2000) }, "renewal_mismatch"},
		"issued_at changed":      {func(l map[string]any) { l["issued_at"] = jnum(90) }, "renewal_mismatch"},
		"renewed_at == previous": {func(l map[string]any) { l["renewed_at"] = jnum(100) }, ""},
	} {
		reg := NewLeaseRegistry(pol, MemoryLeaseKv())
		if r := reg.Accept(issue, nil); !r.Ok {
			t.Fatalf("%s: issue %+v", name, r)
		}
		r := reg.Accept(renew(c.mut), nil)
		if c.code == "" {
			if !r.Ok || r.Seq != 2 {
				t.Errorf("%s: %+v, want ok", name, r)
			}
		} else if r.Ok || r.Code != c.code {
			t.Errorf("%s: %+v, want %s", name, r, c.code)
		}
	}
}

func TestG04LeaseRegistryRevoke(t *testing.T) {
	k, other := newKey(t), newKey(t)
	reg := NewLeaseRegistryShards(LeasePolicy{Authorities: []string{k.id}}, MemoryLeaseKv(), 1)
	if code, n := reg.Revoke(nil); code != "bad_record" || n != 0 {
		t.Fatalf("bad record: %q %d", code, n)
	}
	if code, n := reg.Revoke(g04SignRev(t, other, map[string]any{"v": jnum(1), "target": "lease", "value": "L1", "revoked_at": jnum(500)})); code != "unknown_authority" || n != 0 {
		t.Fatalf("unknown authority: %q %d", code, n)
	}
	if len(reg.revocations) != 0 {
		t.Fatal("a refused revocation is not stored")
	}
	if r := reg.Accept(g04SignLease(t, k, g04Lease()), nil); !r.Ok {
		t.Fatalf("issue: %+v", r)
	}
	a := g04SignRev(t, k, map[string]any{"v": jnum(1), "target": "lease", "value": "L1", "revoked_at": jnum(500)})
	b := g04SignRev(t, k, map[string]any{"v": jnum(1), "target": "grant", "value": "G9", "revoked_at": jnum(500)})
	if code, n := reg.Revoke(a); code != "" || n != 1 || len(reg.revocations) != 1 {
		t.Fatalf("revoke a: %q %d %d", code, n, len(reg.revocations))
	}
	if code, n := reg.Revoke(a); code != "" || n != 1 || len(reg.revocations) != 1 {
		t.Fatalf("revoke a again (idempotent): %q %d %d", code, n, len(reg.revocations))
	}
	if code, n := reg.Revoke(b); code != "" || n != 0 || len(reg.revocations) != 2 {
		t.Fatalf("revoke b: %q %d %d", code, n, len(reg.revocations))
	}
}
