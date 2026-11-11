package pca

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"regexp"
	"sync"
	"time"
)

// Leases (verification side): a time-boxed grant that must be renewed, has a hard max_ttl cap, and dies when revoked. Records and
// revocations are Ed25519-signed under a domain string over strict-canonical JSON. LeaseRegistry keeps the newest record per
// lease_id (in memory) plus the revocations; CheckLease gates a presented record. Total: nothing here panics on hostile input.

const leaseDomain = "atlas-pca/lease/v1\x00"
const leaseRevokeDomain = "atlas-pca/lease-revoke/v1\x00"

var leasePathRe = regexp.MustCompile(`^[a-z0-9_.-]{1,64}(/[a-z0-9_.-]{1,64}){0,7}$`)
var leaseBodyKeys = []string{"v", "lease_id", "path", "grant_ref", "holder", "requester", "approvers", "justification_digest", "seq", "issued_at", "renewed_at", "expires_at", "max_ttl", "authority"}
var leaseRevKeys = []string{"v", "target", "value", "revoked_at", "authority"}

func leaseInt(v any) int64                       { f, _ := jsNum(v); return int64(f) }
func leaseStr(m map[string]any, k string) string { s, _ := m[k].(string); return s }
func leaseHas(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func leaseCap(l map[string]any) int64 { return leaseInt(l["issued_at"]) + leaseInt(l["max_ttl"]) }

func leaseWellFormed(v any) (map[string]any, bool) {
	l, _ := v.(map[string]any) // a non-object is a nil map here and fails the "v" check below
	if f, ok := jsNum(l["v"]); !ok || f != 1 {
		return nil, false
	}
	if !k3Str(l["lease_id"], 128) || !k3Str(l["grant_ref"], 256) || !k3Str(l["holder"], 128) || !k3Str(l["requester"], 128) {
		return nil, false
	}
	p, isStr := l["path"].(string)
	if !k3Str(l["authority"], 128) || !k3Str(l["justification_digest"], 128) || !isStr || !leasePathRe.MatchString(p) {
		return nil, false
	}
	for _, k := range []string{"seq", "issued_at", "renewed_at", "expires_at", "max_ttl"} {
		if !k3Int(l[k]) {
			return nil, false
		}
	}
	seq, issued, renewed, expires := leaseInt(l["seq"]), leaseInt(l["issued_at"]), leaseInt(l["renewed_at"]), leaseInt(l["expires_at"])
	if seq < 1 || leaseInt(l["max_ttl"]) < 1 || renewed < issued || expires <= renewed || (seq == 1 && renewed != issued) {
		return nil, false
	}
	a, ok := l["approvers"].([]any)
	if !ok || len(a) > 16 {
		return nil, false
	}
	for _, x := range a {
		if !k3Str(x, 128) {
			return nil, false
		}
	}
	return l, true
}

func leasePick(m map[string]any, keys []string) map[string]any {
	body := map[string]any{}
	for _, k := range keys {
		if x, has := m[k]; has {
			body[k] = x
		}
	}
	return body
}

// VerifyLease: well formed and signed by its authority over exactly its content. Does NOT check the cap.
func VerifyLease(v any) bool {
	l, ok := leaseWellFormed(v)
	return ok && extSigned(leaseStr(l, "authority"), leaseDomain, leasePick(l, leaseBodyKeys), l["sig"])
}

func leaseRevWellFormed(v any) (map[string]any, bool) {
	r, ok := v.(map[string]any)
	if !ok {
		return nil, false
	}
	if f, ok := jsNum(r["v"]); !ok || f != 1 || !k3Str(r["value"], 256) || !k3Str(r["authority"], 128) || !k3Int(r["revoked_at"]) {
		return nil, false
	}
	t := leaseStr(r, "target")
	if t != "lease" && t != "prefix" && t != "grant" {
		return nil, false
	}
	return r, t != "prefix" || leasePathRe.MatchString(leaseStr(r, "value"))
}

func VerifyLeaseRevocation(v any) bool {
	r, ok := leaseRevWellFormed(v)
	return ok && extSigned(leaseStr(r, "authority"), leaseRevokeDomain, leasePick(r, leaseRevKeys), r["sig"])
}

// LeasePathUnder: prefix covers path iff equal or path continues it at a segment boundary.
func LeasePathUnder(path, prefix string) bool {
	return path == prefix || (len(path) > len(prefix) && path[:len(prefix)] == prefix && path[len(prefix)] == '/')
}

func leaseCovers(r, l map[string]any) bool {
	if leaseInt(l["issued_at"]) > leaseInt(r["revoked_at"]) {
		return false
	}
	switch leaseStr(r, "target") {
	case "lease":
		return l["lease_id"] == r["value"]
	case "grant":
		return l["grant_ref"] == r["value"]
	}
	return LeasePathUnder(leaseStr(l, "path"), leaseStr(r, "value"))
}

// LeasePolicy: Authorities pin who may sign; MinApprovals nil = 1; Eligible nil = any approver; FreshJustification nil = true.
type LeasePolicy struct {
	Authorities        []string
	MinApprovals       *int64
	Eligible           []string
	FreshJustification *bool
	// MaxTtlCeiling: the longest max_ttl (ms) this registry accepts (ttl_ceiling). When set, a revocation is pruned once
	// revoked_at + ceiling is past (every lease it could cover is then beyond its own cap). nil: no ceiling, nothing is pruned.
	MaxTtlCeiling *int64
}

// LeaseSodError is separation of duties over one record ("" = fine). chain is every key in the holder's delegation chain.
func LeaseSodError(l map[string]any, p LeasePolicy, chain []string) string {
	k := int64(1)
	if p.MinApprovals != nil {
		k = *p.MinApprovals
	}
	if k < 1 || k > 1<<53-1 {
		return "minApprovals must be a positive integer"
	}
	appr, _ := l["approvers"].([]any)
	seen := map[string]bool{}
	for _, x := range appr {
		a, _ := x.(string)
		if seen[a] {
			return "an approver is listed twice"
		}
		seen[a] = true
		if a == l["requester"] {
			return "the requester may not approve their own request"
		}
		if a == l["holder"] {
			return "the holder may not approve its own lease"
		}
		if leaseHas(chain, a) {
			return "an approver appears in the holder's delegation chain"
		}
		if p.Eligible != nil && !leaseHas(p.Eligible, a) {
			return "an approver is not eligible"
		}
	}
	if int64(len(appr)) < k {
		return "too few approvers"
	}
	return ""
}

type LeaseHistoryEntry struct {
	Seq, RenewedAt, ExpiresAt int64
	JustificationDigest       string
}
type leaseState struct {
	current map[string]any
	history []LeaseHistoryEntry
}

// LeaseAcceptResult: Ok with Replaced/Seq, else Code (and Reason for some).
type LeaseAcceptResult struct {
	Ok       bool
	Replaced bool
	Seq      int64
	Code     string
	Reason   string
}

// LeaseRegistry keeps each lease in the shard its id hashes to, in a durable AtomicKV, as the reference does: an issue, a renewal and a
// check read and write one small document, and unrelated leases never contend for one value. A path-prefix or grant revocation is
// written to EVERY shard (it can cover leases anywhere); a revocation of one lease id only to that lease's shard. Within a shard
// each operation is one atomic kv.Update. A fan-out revocation is complete when Revoke returns; a renewal racing it in a shard not
// yet written succeeds and is then covered by the revocation when it lands (the check applies revocations to the stored lease).
type LeaseRegistry struct {
	mu          sync.Mutex // serialises the working copy below within this process; the kv makes the update atomic across processes
	policy      LeasePolicy
	kv          AtomicKV
	shards      int
	metaOK      bool                   // the shard count was pinned in the store (and matches)
	leases      map[string]*leaseState // the working copy of the shard document loaded last
	revocations []map[string]any
	clock       func() int64 // epoch ms
}

// DefaultLeaseShards and MaxLeaseShards bound the shard count of a LeaseRegistry (fixed for the life of the store).
const (
	DefaultLeaseShards = 16
	MaxLeaseShards     = 4096
	leaseMetaKey       = "lease/meta"
)

func leaseShardKey(n, i int) string { return fmt.Sprintf("lease/%d/%d", n, i) }

// leaseShardOf is the shard a lease id lives in: the first four bytes of SHA-256 of the id (big endian), modulo the shard count.
// Stable across processes.
func leaseShardOf(id string, shards int) int {
	h := sha256.Sum256([]byte(id))
	return int((uint32(h[0])<<24 | uint32(h[1])<<16 | uint32(h[2])<<8 | uint32(h[3])) % uint32(shards))
}

type leaseHistoryJSON struct {
	Seq                 int64  `json:"seq"`
	RenewedAt           int64  `json:"renewed_at"`
	ExpiresAt           int64  `json:"expires_at"`
	JustificationDigest string `json:"justification_digest"`
}
type leaseStateJSON struct {
	Current map[string]any     `json:"current"`
	History []leaseHistoryJSON `json:"history"`
}
type leaseDocJSON struct {
	Leases      map[string]leaseStateJSON `json:"leases"`
	Revocations []map[string]any          `json:"revocations"`
}

func (r *LeaseRegistry) load(prev []byte) error {
	r.leases, r.revocations = map[string]*leaseState{}, nil
	if prev == nil {
		return nil
	}
	var d leaseDocJSON
	if err := kvDecode(prev, &d); err != nil {
		return err
	}
	for id, st := range d.Leases {
		if st.Current == nil {
			return errStoreState
		}
		ls := &leaseState{current: st.Current}
		for _, h := range st.History {
			ls.history = append(ls.history, LeaseHistoryEntry{h.Seq, h.RenewedAt, h.ExpiresAt, h.JustificationDigest})
		}
		r.leases[id] = ls
	}
	r.revocations = d.Revocations
	return nil
}

func (r *LeaseRegistry) dump() []byte {
	d := leaseDocJSON{Leases: map[string]leaseStateJSON{}, Revocations: r.revocations}
	if d.Revocations == nil {
		d.Revocations = []map[string]any{}
	}
	for id, st := range r.leases {
		j := leaseStateJSON{Current: st.current, History: []leaseHistoryJSON{}}
		for _, h := range st.history {
			j.History = append(j.History, leaseHistoryJSON{h.Seq, h.RenewedAt, h.ExpiresAt, h.JustificationDigest})
		}
		d.Leases[id] = j
	}
	return kvEncode(d)
}

// NewLeaseRegistry panics on a malformed MaxTtlCeiling (not a positive safe integer) and on a missing kv, as the reference
// constructor throws: the registry holds revocations, so the store is required (MemoryLeaseKv() is for tests and single-process use).
func NewLeaseRegistry(p LeasePolicy, kv AtomicKV) *LeaseRegistry {
	return NewLeaseRegistryShards(p, kv, DefaultLeaseShards)
}

// NewLeaseRegistryShards is NewLeaseRegistry with an explicit shard count (1 to MaxLeaseShards). The count is pinned in the store on
// first use; a store opened with another count is refused (`store_unreachable`), because existing leases would become invisible.
func NewLeaseRegistryShards(p LeasePolicy, kv AtomicKV, shards int) *LeaseRegistry {
	if kv == nil {
		panic("LeaseRegistry: a durable key-value store is required (MemoryLeaseKv() is for tests and single-process use)")
	}
	if c := p.MaxTtlCeiling; c != nil && (*c < 1 || *c > maxSafeInt) {
		panic("LeaseRegistry: maxTtlCeiling must be a positive integer")
	}
	if shards < 1 || shards > MaxLeaseShards {
		panic("LeaseRegistry: shards must be an integer from 1 to 4096")
	}
	return &LeaseRegistry{policy: p, kv: kv, shards: shards, leases: map[string]*leaseState{}, clock: func() int64 { return time.Now().UnixMilli() }}
}

// ready pins the shard count in the store on first use and reports whether it matches (a different count would make the stored
// leases invisible, so it is refused).
func (r *LeaseRegistry) ready() error {
	if r.metaOK {
		return nil
	}
	var stored int
	err := kvTxn(r.kv, leaseMetaKey, func(prev []byte) error {
		stored = 0
		if prev == nil {
			return nil
		}
		var m struct {
			V      int `json:"v"`
			Shards int `json:"shards"`
		}
		if err := kvDecode(prev, &m); err != nil {
			return err
		}
		stored = m.Shards
		return nil
	}, func() bool {
		if stored == 0 {
			stored = r.shards
			return true
		}
		return false
	}, func() []byte { return kvEncode(map[string]any{"v": 1, "shards": stored}) })
	if err != nil {
		return err
	}
	if stored != r.shards {
		return errors.New("pca: the lease store was opened with another shard count")
	}
	r.metaOK = true
	return nil
}

func (r *LeaseRegistry) prune() {
	c := r.policy.MaxTtlCeiling
	if c == nil {
		return
	}
	now := r.clock()
	kept := r.revocations[:0]
	for _, rv := range r.revocations {
		if leaseInt(rv["revoked_at"])+*c >= now {
			kept = append(kept, rv)
		}
	}
	r.revocations = kept
}

func leaseFail(code string, reason ...string) LeaseAcceptResult {
	r := LeaseAcceptResult{Code: code}
	if len(reason) > 0 {
		r.Reason = reason[0]
	}
	return r
}

// Accept takes an issue (seq 1) or a renewal (seq = current + 1). chain: the keys in the holder's delegation chain.
func (r *LeaseRegistry) Accept(rec any, chain []string) LeaseAcceptResult {
	if !VerifyLease(rec) {
		return leaseFail("bad_record")
	}
	l := rec.(map[string]any)
	if !leaseHas(r.policy.Authorities, leaseStr(l, "authority")) {
		return leaseFail("unknown_authority")
	}
	if s := LeaseSodError(l, r.policy, chain); s != "" {
		return leaseFail("sod", s)
	}
	if leaseInt(l["expires_at"]) > leaseCap(l) {
		return leaseFail("over_max_ttl")
	}
	if c := r.policy.MaxTtlCeiling; c != nil && leaseInt(l["max_ttl"]) > *c {
		return leaseFail("ttl_ceiling")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	out := leaseFail("store_unreachable")
	if r.ready() != nil {
		return out
	}
	if err := kvTxn(r.kv, leaseShardKey(r.shards, leaseShardOf(leaseStr(l, "lease_id"), r.shards)), r.load, func() bool {
		var changed bool
		out, changed = r.acceptLocked(l)
		return changed
	}, r.dump); err != nil {
		return leaseFail("store_unreachable")
	}
	return out
}

// acceptLocked decides one record against the loaded state; changed says the state was modified.
func (r *LeaseRegistry) acceptLocked(l map[string]any) (LeaseAcceptResult, bool) {
	for _, rv := range r.revocations {
		if leaseCovers(rv, l) {
			return leaseFail("revoked"), false
		}
	}
	id := leaseStr(l, "lease_id")
	st := r.leases[id]
	seq := leaseInt(l["seq"])
	if st == nil {
		if seq != 1 {
			return leaseFail("bad_seq", "a new lease starts at seq 1"), false
		}
	} else {
		cur := st.current
		cseq := leaseInt(cur["seq"])
		if seq < cseq {
			return leaseFail("stale_seq"), false
		}
		if seq == cseq {
			if cur["sig"] == l["sig"] {
				return LeaseAcceptResult{Ok: true, Seq: seq}, false
			}
			return leaseFail("lease_fork"), false
		}
		if seq != cseq+1 {
			return leaseFail("bad_seq", "renewals advance seq by exactly 1"), false
		}
		for _, k := range []string{"authority", "path", "grant_ref", "holder", "requester"} {
			if l[k] != cur[k] {
				return leaseFail("renewal_mismatch"), false
			}
		}
		if leaseInt(l["max_ttl"]) != leaseInt(cur["max_ttl"]) || leaseInt(l["issued_at"]) != leaseInt(cur["issued_at"]) {
			return leaseFail("renewal_mismatch"), false
		}
		if leaseInt(l["renewed_at"]) >= leaseInt(cur["expires_at"]) {
			return leaseFail("expired_lease", "an expired lease cannot be renewed"), false
		}
		if leaseInt(l["renewed_at"]) < leaseInt(cur["renewed_at"]) || leaseInt(l["expires_at"]) <= leaseInt(cur["expires_at"]) {
			return leaseFail("not_extending"), false
		}
		if (r.policy.FreshJustification == nil || *r.policy.FreshJustification) && l["justification_digest"] == cur["justification_digest"] {
			return leaseFail("stale_justification"), false
		}
	}
	e := LeaseHistoryEntry{seq, leaseInt(l["renewed_at"]), leaseInt(l["expires_at"]), leaseStr(l, "justification_digest")}
	if st == nil {
		st = &leaseState{}
		r.leases[id] = st
	}
	st.current, st.history = l, append(st.history, e)
	r.prune()
	return LeaseAcceptResult{Ok: true, Replaced: true, Seq: seq}, true
}

// Revoke takes a signed revocation (idempotent): ("", n) with n leases covered, else the refusal code (`store_unreachable`
// when the kv cannot decide).
func (r *LeaseRegistry) Revoke(rec any) (string, int) {
	if !VerifyLeaseRevocation(rec) {
		return "bad_record", 0
	}
	rv := rec.(map[string]any)
	if !leaseHas(r.policy.Authorities, leaseStr(rv, "authority")) {
		return "unknown_authority", 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ready() != nil {
		return "store_unreachable", 0
	}
	targets := make([]int, 0, r.shards)
	if leaseStr(rv, "target") == "lease" {
		targets = append(targets, leaseShardOf(leaseStr(rv, "value"), r.shards))
	} else { // a prefix or grant revocation can cover leases anywhere
		for i := 0; i < r.shards; i++ {
			targets = append(targets, i)
		}
	}
	n := 0
	for _, i := range targets {
		shardN := 0
		if err := kvTxn(r.kv, leaseShardKey(r.shards, i), r.load, func() bool {
			shardN = 0
			known := false
			for _, x := range r.revocations {
				known = known || x["sig"] == rv["sig"]
			}
			if !known {
				r.revocations = append(r.revocations, rv)
			}
			for _, st := range r.leases {
				if leaseCovers(rv, st.current) {
					shardN++
				}
			}
			r.prune()
			return true
		}, r.dump); err != nil {
			return "store_unreachable", 0
		}
		n += shardN
	}
	return "", n
}

// lookup reads the newest record of a lease and whether a stored revocation covers it (cur nil: unknown). A store error is
// returned, never read as "unknown" or "not revoked".
func (r *LeaseRegistry) lookup(id string) (cur map[string]any, revoked bool, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err = r.ready(); err != nil {
		return nil, false, err
	}
	if err = kvRead(r.kv, leaseShardKey(r.shards, leaseShardOf(id, r.shards)), r.load); err != nil {
		return nil, false, err
	}
	st := r.leases[id]
	if st == nil {
		return nil, false, nil
	}
	for _, rv := range r.revocations {
		if leaseCovers(rv, st.current) {
			return st.current, true, nil
		}
	}
	return st.current, false, nil
}

// Get returns the newest accepted record of a lease (nil when unknown or when the store cannot be read).
func (r *LeaseRegistry) Get(id string) map[string]any {
	cur, _, err := r.lookup(id)
	if err != nil {
		return nil
	}
	return cur
}

// LeaseDecision: Decision "allow" (LeaseID, ExpiresAt) or "deny" (Code, LeaseID when known).
type LeaseDecision struct {
	Decision  string
	Code      string
	LeaseID   string
	ExpiresAt int64
}

// CheckLease: is presented a live lease? It must verify, be the newest record, be inside its window and cap, and not be revoked.
func CheckLease(presented any, r *LeaseRegistry, now any) LeaseDecision {
	deny := func(code, id string) LeaseDecision { return LeaseDecision{Decision: "deny", Code: code, LeaseID: id} }
	if !k3Int(now) {
		return deny("bad_input", "")
	}
	if !VerifyLease(presented) {
		return deny("bad_record", "")
	}
	p := presented.(map[string]any)
	id := leaseStr(p, "lease_id")
	cur, revoked, err := r.lookup(id)
	if err != nil {
		return deny("store_unreachable", id)
	}
	if cur == nil {
		return deny("unknown_lease", id)
	}
	if cur["sig"] != p["sig"] {
		return deny("superseded", id)
	}
	if revoked {
		return deny("revoked", id)
	}
	n := leaseInt(now)
	switch {
	case n < leaseInt(cur["renewed_at"]):
		return deny("not_yet_valid", id)
	case n >= leaseCap(cur):
		return deny("past_max_ttl", id)
	case n >= leaseInt(cur["expires_at"]):
		return deny("expired", id)
	}
	return LeaseDecision{Decision: "allow", LeaseID: id, ExpiresAt: leaseInt(cur["expires_at"])}
}
