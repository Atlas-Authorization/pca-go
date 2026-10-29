package pca

import "sync"

// Break-glass grants (verification side): a time-boxed, small-budget, loud emergency grant with a mandatory signed review after the
// fact. Records and reviews are Ed25519-signed under a domain string over strict-canonical JSON. BreakGlassRegistry keeps each
// holder's grants, numbered uses, reviews and freeze status in memory (one document per holder). Total: nothing here panics on
// hostile input. Port of packages/pca-grants/src/breakglass.ts; replays break-glass-vectors.json.

const breakGlassDomain = "atlas-pca/break-glass/v1\x00"
const breakGlassReviewDomain = "atlas-pca/break-glass-review/v1\x00"

const (
	maxBreakGlassWindowMs = 86_400_000
	maxBreakGlassUses     = 16
	maxReviewWithinMs     = 30 * 86_400_000
)

var breakGlassBodyKeys = []string{"v", "id", "holder", "grant_ref", "reason_digest", "max_uses", "issued_at", "expires_at", "review_within", "notify_to", "authority"}
var breakGlassReviewKeys = []string{"v", "id", "outcome", "notes_digest", "at", "reviewer"}

func bgWellFormed(v any) (map[string]any, bool) {
	b, ok := v.(map[string]any)
	if !ok {
		return nil, false
	}
	if f, ok := jsNum(b["v"]); !ok || f != 1 {
		return nil, false
	}
	if !k3Str(b["id"], 128) || !k3Str(b["holder"], 128) || !k3Str(b["grant_ref"], 256) || !k3Str(b["reason_digest"], 128) || !k3Str(b["notify_to"], 256) || !k3Str(b["authority"], 128) {
		return nil, false
	}
	for _, k := range []string{"max_uses", "issued_at", "expires_at", "review_within"} {
		if !k3Int(b[k]) {
			return nil, false
		}
	}
	uses, issued, expires, within := leaseInt(b["max_uses"]), leaseInt(b["issued_at"]), leaseInt(b["expires_at"]), leaseInt(b["review_within"])
	if uses < 1 || uses > maxBreakGlassUses || expires <= issued || expires-issued > maxBreakGlassWindowMs || within < 1 || within > maxReviewWithinMs {
		return nil, false
	}
	return b, true
}

// VerifyBreakGlass: well formed and signed by its authority over exactly its content.
func VerifyBreakGlass(v any) bool {
	b, ok := bgWellFormed(v)
	return ok && extSigned(leaseStr(b, "authority"), breakGlassDomain, leasePick(b, breakGlassBodyKeys), b["sig"])
}

func bgReviewWellFormed(v any) (map[string]any, bool) {
	r, ok := v.(map[string]any)
	if !ok {
		return nil, false
	}
	if f, ok := jsNum(r["v"]); !ok || f != 1 {
		return nil, false
	}
	o, _ := r["outcome"].(string)
	if !k3Str(r["id"], 128) || (o != "justified" && o != "unjustified") || !k3Str(r["notes_digest"], 128) || !k3Int(r["at"]) || !k3Str(r["reviewer"], 128) {
		return nil, false
	}
	return r, true
}

func VerifyBreakGlassReview(v any) bool {
	r, ok := bgReviewWellFormed(v)
	return ok && extSigned(leaseStr(r, "reviewer"), breakGlassReviewDomain, leasePick(r, breakGlassReviewKeys), r["sig"])
}

type BreakGlassPolicy struct{ Authorities, Reviewers []string }

// BgResult is the outcome of Accept and Review: Ok with Replaced, else Code.
type BgResult struct {
	Ok       bool
	Replaced bool
	Code     string
}

// BgUseDecision: "allow" (ID, Use, Remaining, ReviewDue) or "deny" (Code, ID when known).
type BgUseDecision struct {
	Decision, Code, ID        string
	Use, Remaining, ReviewDue int64
}

type bgUse struct {
	n, at  int64
	digest string
}
type bgEntry struct {
	rec    map[string]any
	uses   []bgUse
	review map[string]any
}

type BreakGlassRegistry struct {
	mu      sync.Mutex
	policy  BreakGlassPolicy
	holders map[string]map[string]*bgEntry
}

func NewBreakGlassRegistry(p BreakGlassPolicy) *BreakGlassRegistry {
	return &BreakGlassRegistry{policy: p, holders: map[string]map[string]*bgEntry{}}
}

// bgFrozenIn: a grant was judged unjustified, or has uses, no review and a review clock that has run out.
func bgFrozenIn(grants map[string]*bgEntry, now int64) bool {
	for _, e := range grants {
		if e.review != nil && e.review["outcome"] == "unjustified" {
			return true
		}
		if e.review == nil && len(e.uses) > 0 && now >= e.uses[0].at+leaseInt(e.rec["review_within"]) {
			return true
		}
	}
	return false
}

func bgFail(code string) BgResult { return BgResult{Code: code} }

// Accept registers an issued record. A frozen holder gets no new one.
func (r *BreakGlassRegistry) Accept(rec any, now any) BgResult {
	if !VerifyBreakGlass(rec) || !k3Int(now) {
		return bgFail("bad_record")
	}
	b := rec.(map[string]any)
	if !leaseHas(r.policy.Authorities, leaseStr(b, "authority")) {
		return bgFail("unknown_authority")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	holder := leaseStr(b, "holder")
	grants := r.holders[holder]
	if grants == nil {
		grants = map[string]*bgEntry{}
		r.holders[holder] = grants
	}
	if cur := grants[leaseStr(b, "id")]; cur != nil {
		if cur.rec["sig"] == b["sig"] {
			return BgResult{Ok: true}
		}
		return bgFail("id_conflict")
	}
	if bgFrozenIn(grants, leaseInt(now)) {
		return bgFail("holder_frozen")
	}
	grants[leaseStr(b, "id")] = &bgEntry{rec: b}
	return BgResult{Ok: true, Replaced: true}
}

// Use records one use; notified must be true. Checks in order: input, existence, freeze, revocation, window, budget, notification.
func (r *BreakGlassRegistry) Use(id, holder, actionDigest string, now, notified any) BgUseDecision {
	nt, isBool := notified.(bool)
	if !k3Str(id, 128) || !k3Str(holder, 128) || !k3Str(actionDigest, 128) || !k3Int(now) || !isBool {
		return BgUseDecision{Decision: "deny", Code: "bad_input"}
	}
	deny := func(code string) BgUseDecision { return BgUseDecision{Decision: "deny", Code: code, ID: id} }
	n := leaseInt(now)
	r.mu.Lock()
	defer r.mu.Unlock()
	grants := r.holders[holder]
	e := grants[id]
	if e == nil {
		return deny("unknown_break_glass")
	}
	if bgFrozenIn(grants, n) {
		return deny("holder_frozen")
	}
	if e.review != nil && e.review["outcome"] == "unjustified" {
		return deny("revoked")
	}
	if n < leaseInt(e.rec["issued_at"]) {
		return deny("not_yet_valid")
	}
	if n >= leaseInt(e.rec["expires_at"]) {
		return deny("expired")
	}
	if int64(len(e.uses)) >= leaseInt(e.rec["max_uses"]) {
		return deny("budget_exhausted")
	}
	if !nt {
		return deny("not_notified")
	}
	e.uses = append(e.uses, bgUse{n: int64(len(e.uses)) + 1, at: n, digest: actionDigest})
	used := int64(len(e.uses))
	return BgUseDecision{Decision: "allow", ID: id, Use: used, Remaining: leaseInt(e.rec["max_uses"]) - used, ReviewDue: e.uses[0].at + leaseInt(e.rec["review_within"])}
}

// Review records the signed review. The first review of a grant is final; a late review lifts an overdue freeze.
func (r *BreakGlassRegistry) Review(rec any, holder string, now any) BgResult {
	if !VerifyBreakGlassReview(rec) || !k3Str(holder, 128) || !k3Int(now) {
		return bgFail("bad_record")
	}
	rv := rec.(map[string]any)
	reviewer := leaseStr(rv, "reviewer")
	if !leaseHas(r.policy.Reviewers, reviewer) {
		return bgFail("unknown_reviewer")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	e := r.holders[holder][leaseStr(rv, "id")]
	if e == nil {
		return bgFail("unknown_break_glass")
	}
	if reviewer == leaseStr(e.rec, "holder") || reviewer == leaseStr(e.rec, "authority") {
		return bgFail("sod")
	}
	if e.review != nil {
		if e.review["sig"] == rv["sig"] {
			return BgResult{Ok: true}
		}
		return bgFail("already_reviewed")
	}
	if len(e.uses) == 0 {
		return bgFail("nothing_to_review")
	}
	if at := leaseInt(rv["at"]); at < e.uses[0].at || at > leaseInt(now) {
		return bgFail("bad_time")
	}
	e.review = rv
	return BgResult{Ok: true, Replaced: true}
}

// Frozen: fails closed (true) on bad input.
func (r *BreakGlassRegistry) Frozen(holder string, now any) bool {
	if !k3Str(holder, 128) || !k3Int(now) {
		return true
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return bgFrozenIn(r.holders[holder], leaseInt(now))
}
