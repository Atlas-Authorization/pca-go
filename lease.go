package pca

import "regexp"

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
	l, ok := v.(map[string]any)
	if !ok {
		return nil, false
	}
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

type LeaseRegistry struct {
	policy      LeasePolicy
	leases      map[string]*leaseState
	revocations []map[string]any
}

func NewLeaseRegistry(p LeasePolicy) *LeaseRegistry {
	return &LeaseRegistry{policy: p, leases: map[string]*leaseState{}}
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
	for _, rv := range r.revocations {
		if leaseCovers(rv, l) {
			return leaseFail("revoked")
		}
	}
	id := leaseStr(l, "lease_id")
	st := r.leases[id]
	seq := leaseInt(l["seq"])
	if st == nil {
		if seq != 1 {
			return leaseFail("bad_seq", "a new lease starts at seq 1")
		}
	} else {
		cur := st.current
		cseq := leaseInt(cur["seq"])
		if seq < cseq {
			return leaseFail("stale_seq")
		}
		if seq == cseq {
			if cur["sig"] == l["sig"] {
				return LeaseAcceptResult{Ok: true, Seq: seq}
			}
			return leaseFail("lease_fork")
		}
		if seq != cseq+1 {
			return leaseFail("bad_seq", "renewals advance seq by exactly 1")
		}
		for _, k := range []string{"authority", "path", "grant_ref", "holder", "requester"} {
			if l[k] != cur[k] {
				return leaseFail("renewal_mismatch")
			}
		}
		if leaseInt(l["max_ttl"]) != leaseInt(cur["max_ttl"]) || leaseInt(l["issued_at"]) != leaseInt(cur["issued_at"]) {
			return leaseFail("renewal_mismatch")
		}
		if leaseInt(l["renewed_at"]) >= leaseInt(cur["expires_at"]) {
			return leaseFail("expired_lease", "an expired lease cannot be renewed")
		}
		if leaseInt(l["renewed_at"]) < leaseInt(cur["renewed_at"]) || leaseInt(l["expires_at"]) <= leaseInt(cur["expires_at"]) {
			return leaseFail("not_extending")
		}
		if (r.policy.FreshJustification == nil || *r.policy.FreshJustification) && l["justification_digest"] == cur["justification_digest"] {
			return leaseFail("stale_justification")
		}
	}
	e := LeaseHistoryEntry{seq, leaseInt(l["renewed_at"]), leaseInt(l["expires_at"]), leaseStr(l, "justification_digest")}
	if st == nil {
		st = &leaseState{}
		r.leases[id] = st
	}
	st.current, st.history = l, append(st.history, e)
	return LeaseAcceptResult{Ok: true, Replaced: true, Seq: seq}
}

// Revoke takes a signed revocation (idempotent): ("", n) with n leases covered, else the refusal code.
func (r *LeaseRegistry) Revoke(rec any) (string, int) {
	if !VerifyLeaseRevocation(rec) {
		return "bad_record", 0
	}
	rv := rec.(map[string]any)
	if !leaseHas(r.policy.Authorities, leaseStr(rv, "authority")) {
		return "unknown_authority", 0
	}
	known := false
	for _, x := range r.revocations {
		known = known || x["sig"] == rv["sig"]
	}
	if !known {
		r.revocations = append(r.revocations, rv)
	}
	n := 0
	for _, st := range r.leases {
		if leaseCovers(rv, st.current) {
			n++
		}
	}
	return "", n
}

// Get returns the newest accepted record of a lease (nil when unknown).
func (r *LeaseRegistry) Get(id string) map[string]any {
	if st := r.leases[id]; st != nil {
		return st.current
	}
	return nil
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
	cur := r.Get(id)
	if cur == nil {
		return deny("unknown_lease", id)
	}
	if cur["sig"] != p["sig"] {
		return deny("superseded", id)
	}
	for _, rv := range r.revocations {
		if leaseCovers(rv, cur) {
			return deny("revoked", id)
		}
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
