package pca

// The producing side of the operational plane: domain-separated Ed25519 signing, the signers of leases, revocations, blueprints and
// break-glass records, policy bundle signing and assembly, the decision log (hash chain, Merkle commitment, signed heads, inclusion
// proofs, streaming batches), replay tooling and consistency-token issuing. The verification side lives in lease.go, blueprint.go,
// breakglass.go, fresh_at.go and k3.go. Records are parsed JSON values (map[string]any with json.Number numbers); a signer refuses
// (returns an error) exactly where the reference throws. Secrets are *KeyPair values (KeyPairFromSeed).

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
)

// ---- shared value helpers -------------------------------------------------------------------------------------------

// grantsNum is the JSON value of a binary64 (a NaN or infinite result is null, as JSON.stringify writes it).
func grantsNum(f float64) any {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return nil
	}
	return jsNumber(f)
}

func grantsU16Less(a, b string) bool { return compareUnits(utf16Units(a), utf16Units(b)) < 0 }

// grantsClone deep-copies a parsed JSON value.
func grantsClone(v any) any {
	switch t := v.(type) {
	case map[string]any:
		m := make(map[string]any, len(t))
		for k, x := range t {
			m[k] = grantsClone(x)
		}
		return m
	case []any:
		a := make([]any, len(t))
		for i, x := range t {
			a[i] = grantsClone(x)
		}
		return a
	}
	return v
}

func grantsCloneMap(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	return grantsClone(m).(map[string]any)
}

// grantsEq is JavaScript === over parsed JSON values (an object or array is never equal to another value).
func grantsEq(a, b any) bool {
	switch x := a.(type) {
	case nil:
		return b == nil
	case string:
		y, ok := b.(string)
		return ok && x == y
	case bool:
		y, ok := b.(bool)
		return ok && x == y
	case map[string]any, []any:
		return false
	}
	fa, oka := jsNum(a)
	fb, okb := jsNum(b)
	return oka && okb && fa == fb
}

// grantsKV is one Object.entries pair.
type grantsKV struct {
	K string
	V any
}

// grantsEntries is Object.entries for the shapes a JSON value can take (an object, an array or a string; anything else has none).
func grantsEntries(v any) []grantsKV {
	switch t := v.(type) {
	case map[string]any:
		out := make([]grantsKV, 0, len(t))
		for _, k := range jsKeys(t) {
			out = append(out, grantsKV{k, t[k]})
		}
		return out
	case []any:
		out := make([]grantsKV, len(t))
		for i, x := range t {
			out[i] = grantsKV{fmt.Sprint(i), x}
		}
		return out
	case string:
		u := utf16Units(t)
		out := make([]grantsKV, len(u))
		for i := range u {
			out[i] = grantsKV{fmt.Sprint(i), string(rune(u[i]))}
		}
		return out
	}
	return nil
}

// grantsGet reads member k of an object (or index k of an array): the value and whether it exists.
func grantsGet(v any, k string) (any, bool) {
	switch t := v.(type) {
	case map[string]any:
		x, ok := t[k]
		return x, ok
	case []any:
		for i := range t {
			if fmt.Sprint(i) == k {
				return t[i], true
			}
		}
	}
	return nil, false
}

// ---- sig.ts ---------------------------------------------------------------------------------------------------------

// GrantsSignBody is the domain-separated Ed25519 signature over the strict-canonical JSON of body (an error when the body is
// outside the strict profile).
func GrantsSignBody(domain string, body any, k *KeyPair) (string, error) {
	return signBody(k, domain, body)
}

// GrantsVerifyBody is true iff sig is a canonical 64-byte base64url signature by signer over exactly body. Never panics.
func GrantsVerifyBody(domain string, body any, signer string, sig any) bool {
	s, ok := sig.(string)
	if !ok {
		return false
	}
	cb, err := canonBytes(body)
	if err != nil {
		return false
	}
	return verifyB64u(signer, append([]byte(domain), cb...), s)
}

// ---- signers --------------------------------------------------------------------------------------------------------

// grantsSignRecord is the shared shape of the record signers: base = {v: 1, ...rec, <who>: signer}; it must be well formed (and
// pass extra); the signature covers the body members picked by keys under domain.
func grantsSignRecord(k *KeyPair, fn string, rec any, who, domain string, keys []string, wf func(any) bool, extra func(map[string]any) bool) (map[string]any, error) {
	base := map[string]any{"v": json.Number("1")}
	if m, ok := rec.(map[string]any); ok {
		for kk, vv := range m {
			base[kk] = vv
		}
	}
	base[who] = k.Public
	if !wf(base) || (extra != nil && !extra(base)) {
		return nil, fmt.Errorf("%s: malformed", fn)
	}
	sig, err := signBody(k, domain, leasePick(base, keys))
	if err != nil {
		return nil, err
	}
	out := grantsCloneMap(base)
	out["sig"] = sig
	return out, nil
}

func grantsLeaseWF(v any) bool  { _, ok := leaseWellFormed(v); return ok }
func grantsRevWF(v any) bool    { _, ok := leaseRevWellFormed(v); return ok }
func grantsBpWF(v any) bool     { _, ok := blueprintWellFormed(v); return ok }
func grantsBgWF(v any) bool     { _, ok := bgWellFormed(v); return ok }
func grantsReviewWF(v any) bool { _, ok := bgReviewWellFormed(v); return ok }

// SignLease signs a lease record. An error on a malformed record or one that outlives issued_at + max_ttl.
func SignLease(k *KeyPair, rec any) (map[string]any, error) {
	return grantsSignRecord(k, "signLease", rec, "authority", leaseDomain, leaseBodyKeys, grantsLeaseWF, func(b map[string]any) bool { return leaseInt(b["expires_at"]) <= leaseCap(b) })
}

// SignLeaseUnsafeOverCap signs a record that outlives its cap, to prove verifiers refuse it (conformance builder; never in production).
func SignLeaseUnsafeOverCap(k *KeyPair, rec any) (map[string]any, error) {
	return grantsSignRecord(k, "signLeaseUnsafeOverCap", rec, "authority", leaseDomain, leaseBodyKeys, grantsLeaseWF, nil)
}

// SignLeaseRevocation signs a lease revocation ({target, value, revoked_at}).
func SignLeaseRevocation(k *KeyPair, rec any) (map[string]any, error) {
	return grantsSignRecord(k, "signLeaseRevocation", rec, "authority", leaseRevokeDomain, leaseRevKeys, grantsRevWF, nil)
}

// SignBlueprint signs a blueprint record with the operator's key.
func SignBlueprint(k *KeyPair, rec any) (map[string]any, error) {
	return grantsSignRecord(k, "signBlueprint", rec, "operator", agentBlueprintDomain, blueprintBodyKeys, grantsBpWF, nil)
}

// SignBreakGlass signs a break-glass record (window at most 24 hours, budget 1 to 16).
func SignBreakGlass(k *KeyPair, rec any) (map[string]any, error) {
	return grantsSignRecord(k, "signBreakGlass", rec, "authority", breakGlassDomain, breakGlassBodyKeys, grantsBgWF, nil)
}

// SignBreakGlassReview signs a break-glass review.
func SignBreakGlassReview(k *KeyPair, rec any) (map[string]any, error) {
	return grantsSignRecord(k, "signBreakGlassReview", rec, "reviewer", breakGlassReviewDomain, breakGlassReviewKeys, grantsReviewWF, nil)
}

// ---- policy bundles -------------------------------------------------------------------------------------------------

func grantsShadowError(b any) string {
	m, ok := b.(map[string]any)
	if !ok {
		return ""
	}
	s, has := m["shadow"]
	if !has {
		return ""
	}
	l, isArr := s.([]any)
	if !isArr || len(l) == 0 || len(l) > 16 {
		return "bad shadow"
	}
	seen := map[string]bool{}
	for _, g := range l {
		if !k3Str(g, 128) {
			return "bad shadow"
		}
		seen[g.(string)] = true
	}
	if len(seen) != len(l) {
		return "bad shadow"
	}
	return ""
}

// BundleShapeErrorFull is the complete shape check of a policy bundle (the verifier's check plus the shadow member: 1 to 16
// distinct digests). "" when well formed.
func BundleShapeErrorFull(b any) string {
	if e := bundleShapeError(b); e != "" {
		return e
	}
	return grantsShadowError(b)
}

// VerifyBundleFull is VerifyBundle with the shadow member checked too (a malformed one is `malformed`).
func VerifyBundleFull(b any, o BundleVerifyOptions) BundleVerdict {
	if e := grantsShadowError(b); e != "" && bundleShapeError(b) == "" {
		return BundleVerdict{Code: "malformed", Reason: e}
	}
	return VerifyBundle(b, o)
}

// SignBundle is one signer's signature over the bundle body: {signer, sig}. Collect k of them and call AssembleBundle.
func SignBundle(body any, k *KeyPair) (map[string]any, error) {
	if e := BundleShapeErrorFull(body); e != "" {
		return nil, errors.New("signBundle: " + e)
	}
	m := body.(map[string]any)
	sig, err := signBody(k, bundleDomain, k3Sub(m, "sigs"))
	if err != nil {
		return nil, err
	}
	return map[string]any{"signer": k.Public, "sig": sig}, nil
}

// AssembleBundle is the bundle body (without any stale signatures) carrying sigs.
func AssembleBundle(body any, sigs any) map[string]any {
	m, _ := body.(map[string]any)
	out := withoutKeys(m, "sigs")
	out["sigs"] = sigs
	return out
}

// ---- decision records -----------------------------------------------------------------------------------------------

// MaskRecord masks by data CLASS: every detail field whose class is in maskClasses becomes a commitment. A record without detail
// or classes is returned as is. An error when a masked value is outside the strict profile.
func MaskRecord(r map[string]any, maskClasses []string) (map[string]any, error) {
	if !jsTruthy(r["detail"]) || !jsTruthy(r["classes"]) {
		return r, nil
	}
	detail := map[string]any{}
	for _, e := range grantsEntries(r["detail"]) {
		cls, has := grantsGet(r["classes"], e.K)
		c, isStr := cls.(string)
		if has && isStr && containsStr(maskClasses, c) {
			h, err := HashCanonical(map[string]any{"d": "atlas-pca/mask/v1", "k": e.K, "v": e.V})
			if err != nil {
				return nil, err
			}
			detail[e.K] = "masked:" + c + ":" + h
		} else {
			detail[e.K] = e.V
		}
	}
	out := make(map[string]any, len(r))
	for k, v := range r {
		out[k] = v
	}
	out["detail"] = detail
	return out, nil
}

// GrantsMerkleProof is the RFC 6962 audit path of leaf index: {index, size, path: [{side, hash}]} (bottom up). An error for an
// index outside the leaves. Leaves are commit strings.
func GrantsMerkleProof(leaves []string, index int) (map[string]any, error) {
	if index < 0 || index >= len(leaves) {
		return nil, errors.New("merkleProof: index out of range")
	}
	hs := make([][]byte, len(leaves))
	for i, l := range leaves {
		h, err := leafHash(l)
		if err != nil {
			return nil, err
		}
		hs[i] = h
	}
	path := []any{}
	var prove func(hs [][]byte, idx int)
	prove = func(hs [][]byte, idx int) {
		if len(hs) == 1 {
			return
		}
		k := split(len(hs))
		if idx < k {
			prove(hs[:k], idx)
			path = append(path, map[string]any{"side": "R", "hash": b64.EncodeToString(build(hs[k:]))})
		} else {
			prove(hs[k:], idx-k)
			path = append(path, map[string]any{"side": "L", "hash": b64.EncodeToString(build(hs[:k]))})
		}
	}
	prove(hs, index)
	return map[string]any{"index": jsNumber(float64(index)), "size": jsNumber(float64(len(leaves))), "path": path}, nil
}

// DecisionLog is the append-only decision log: hash-chained, Merkle-committed, with signed heads and inclusion proofs.
type DecisionLog struct {
	key  *KeyPair
	mask []string
	recs []map[string]any
}

// NewDecisionLog opens an empty log signed by k; maskClasses are the data classes masked on append.
func NewDecisionLog(k *KeyPair, maskClasses []string) *DecisionLog {
	return &DecisionLog{key: k, mask: maskClasses}
}

// Size is the number of records.
func (l *DecisionLog) Size() int { return len(l.recs) }

// Signer is the b64u key that signs the log's heads.
func (l *DecisionLog) Signer() string { return l.key.Public }

// Append masks r, numbers it and chains it to its predecessor; the stored record is returned.
func (l *DecisionLog) Append(r map[string]any) (map[string]any, error) {
	masked, err := MaskRecord(r, l.mask)
	if err != nil {
		return nil, err
	}
	rec := map[string]any{"v": json.Number("1")}
	for k, v := range masked {
		rec[k] = v
	}
	prev := ""
	if n := len(l.recs); n > 0 {
		c, ok := RecordCommit(l.recs[n-1])
		if !ok {
			return nil, errors.New("recordCommit: not canonicalizable")
		}
		prev = c
	}
	rec["seq"] = jsNumber(float64(len(l.recs)))
	rec["prev"] = prev
	l.recs = append(l.recs, rec)
	return rec, nil
}

func (l *DecisionLog) commits() ([]string, error) {
	out := make([]string, len(l.recs))
	for i, r := range l.recs {
		c, ok := RecordCommit(r)
		if !ok {
			return nil, errors.New("recordCommit: not canonicalizable")
		}
		out[i] = c
	}
	return out, nil
}

// Head is the signed log head at time now ({v, size, root, last_commit, issued_at, signer, sig}). An error on an empty log (the
// Merkle root of no leaves is undefined).
func (l *DecisionLog) Head(now any) (map[string]any, error) {
	cs, err := l.commits()
	if err != nil {
		return nil, err
	}
	leaves := make([]any, len(cs))
	for i, c := range cs {
		leaves[i] = c
	}
	root, err := MerkleRoot(leaves)
	if err != nil {
		return nil, errors.New("merkleRoot: " + err.Error())
	}
	last := ""
	if len(cs) > 0 {
		last = cs[len(cs)-1]
	}
	base := map[string]any{"v": json.Number("1"), "size": jsNumber(float64(len(l.recs))), "root": root, "last_commit": last, "issued_at": now, "signer": l.key.Public}
	sig, err := signBody(l.key, logHeadDomain, base)
	if err != nil {
		return nil, err
	}
	base["sig"] = sig
	return base, nil
}

// Proof is the inclusion proof of record seq.
func (l *DecisionLog) Proof(seq int) (map[string]any, error) {
	cs, err := l.commits()
	if err != nil {
		return nil, err
	}
	return GrantsMerkleProof(cs, seq)
}

// Slice is the records in [from, to) (clamped like Array.prototype.slice).
func (l *DecisionLog) Slice(from, to int) []map[string]any {
	n := len(l.recs)
	if from > n {
		from = n
	}
	if to > n {
		to = n
	}
	if from >= to {
		return []map[string]any{}
	}
	return append([]map[string]any{}, l.recs[from:to]...)
}

// NextBatch is the next batch of at most max records starting at from (the stream cursor) with a freshly signed head.
func NextBatch(l *DecisionLog, from, max int64, now any) (map[string]any, error) {
	if from < 0 || from > maxSafeInt || max < 1 || max > maxSafeInt {
		return nil, errors.New("nextBatch: bad cursor or size")
	}
	hi := from + max
	if hi > int64(len(l.recs)) {
		hi = int64(len(l.recs))
	}
	recs := []any{}
	for _, r := range l.Slice(int(minInt64(from, int64(len(l.recs)))), int(hi)) {
		recs = append(recs, r)
	}
	head, err := l.Head(now)
	if err != nil {
		return nil, err
	}
	return map[string]any{"from": jsNumber(float64(from)), "records": recs, "head": head}, nil
}

func minInt64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

// ---- replay ---------------------------------------------------------------------------------------------------------

func grantsRank(x any) (int, bool) {
	s, ok := x.(string)
	if !ok {
		return 0, false
	}
	switch s {
	case "deny":
		return 0, true
	case "escalate":
		return 1, true
	case "allow":
		return 2, true
	}
	return 0, false
}

func grantsRankGt(a, b any) bool {
	ra, oka := grantsRank(a)
	rb, okb := grantsRank(b)
	return oka && okb && ra > rb
}

// SemanticDiff is "what would have changed": the pure decision function re-run over recorded cases ({action_digest, input}) under
// two revisions. A decision that is absent (nil) is omitted from the change, as an undefined member is in JSON. Analysis tooling.
func SemanticDiff(cases []map[string]any, oldDecide, newDecide func(input any) any) []map[string]any {
	out := []map[string]any{}
	for _, c := range cases {
		before, after := oldDecide(c["input"]), newDecide(c["input"])
		if grantsEq(before, after) {
			continue
		}
		dir := "tightened"
		if grantsRankGt(after, before) {
			dir = "widened"
		}
		ch := map[string]any{"action_digest": c["action_digest"], "direction": dir}
		if before != nil {
			ch["before"] = before
		}
		if after != nil {
			ch["after"] = after
		}
		out = append(out, ch)
	}
	return out
}

// AuditReplay returns the records whose logged decision differs from a replay under their own revision's decide function.
func AuditReplay(records, cases []map[string]any, decide func(input any, rev any) any) []map[string]any {
	by := map[string]any{}
	for _, c := range cases {
		if s, ok := c["action_digest"].(string); ok {
			by[s] = c["input"]
		}
	}
	out := []map[string]any{}
	for _, r := range records {
		s, ok := r["action_digest"].(string)
		if !ok {
			continue
		}
		in, has := by[s]
		if has && !grantsEq(decide(in, r["bundle_revision"]), r["decision"]) {
			out = append(out, r)
		}
	}
	return out
}

// ---- consistency tokens (issuing side) -------------------------------------------------------------------------------

var grantsFreshBodyKeys = []string{"v", "scope", "revocation_epoch", "ledger_tree_size", "budget_version", "policy_revision", "policy_digest", "issued_at", "signer"}

func grantsSignFreshAt(k *KeyPair, scope string, state map[string]any, issuedAt any) (map[string]any, error) {
	ok := k3Str(scope, 256) && k3Str(state["policy_digest"], 128) && k3Int(issuedAt)
	for _, c := range freshAtCounters {
		ok = ok && k3Int(state[c])
	}
	if !ok {
		return nil, errors.New("signFreshAt: a malformed state")
	}
	base := map[string]any{"v": json.Number("1"), "scope": scope}
	for kk, v := range state {
		base[kk] = v
	}
	base["issued_at"], base["signer"] = issuedAt, k.Public
	sig, err := signBody(k, freshAtDomain, leasePick(base, grantsFreshBodyKeys))
	if err != nil {
		return nil, err
	}
	out := grantsCloneMap(base)
	out["sig"] = sig
	return out, nil
}

func grantsMax(a, b any) any { return grantsNum(math.Max(jsF(a), jsF(b))) }

// MergeFreshAt is the field-wise maximum of two states (the client-side fold). Equal revisions with different digests keep a's
// digest. A missing counter makes the result null (Math.max with undefined is NaN).
func MergeFreshAt(a, b map[string]any) map[string]any {
	out := map[string]any{}
	for _, c := range freshAtCounters {
		out[c] = grantsMax(a[c], b[c])
	}
	src := a
	if jsF(b["policy_revision"]) > jsF(a["policy_revision"]) {
		src = b
	}
	if v, has := src["policy_digest"]; has {
		out["policy_digest"] = v
	}
	return out
}

// GateDecision composes a freshness verdict into a decision: it can only tighten (allow to escalate or deny), never loosen.
func GateDecision(decision string, v map[string]any) string {
	if decision == "deny" || v["decision"] == "deny" {
		return "deny"
	}
	if v["decision"] == "escalate" {
		return "escalate"
	}
	return decision
}

// FreshAtIssuer is the verifier-side state holder: advance on every write, mint the token for the write, check incoming tokens.
type FreshAtIssuer struct {
	key   *KeyPair
	Scope string
	state map[string]any
}

// NewFreshAtIssuer starts from the initial state ({revocation_epoch, ledger_tree_size, budget_version, policy_revision, policy_digest}).
func NewFreshAtIssuer(k *KeyPair, scope string, initial map[string]any) *FreshAtIssuer {
	return &FreshAtIssuer{key: k, Scope: scope, state: grantsCloneMap(initial)}
}

// Current is a copy of the issuer's state.
func (f *FreshAtIssuer) Current() map[string]any { return grantsCloneMap(f.state) }

// Advance applies a write (any subset of counters; each only moves forward) and returns its token. As in the reference the
// state moves before the token is signed: a refused token leaves the advanced state in place.
func (f *FreshAtIssuer) Advance(patch map[string]any, now any) (map[string]any, error) {
	next := map[string]any{}
	for k, v := range f.state {
		next[k] = v
	}
	for k, v := range patch {
		next[k] = v
	}
	f.state = MergeFreshAt(f.state, next)
	return grantsSignFreshAt(f.key, f.Scope, f.state, now)
}

// Check is the verifier's freshness check against the issuer's own state: signature and shape, scope, issued in the future
// (more than 60 s), token age (maxAge nil: not checked), policy fork, then any counter behind the token is an escalation.
func (f *FreshAtIssuer) Check(token any, now any, maxAge any) map[string]any {
	deny := func(code string) map[string]any { return map[string]any{"decision": "deny", "code": code} }
	if !VerifyFreshAt(token, f.key.Public) {
		return deny("bad_token")
	}
	m := token.(map[string]any)
	if m["scope"] != f.Scope {
		return deny("wrong_scope")
	}
	n, issued := jsF(now), jsF(m["issued_at"])
	if !(issued <= n+freshAtSkewMs) {
		return deny("token_from_the_future")
	}
	if maxAge != nil && !(n-issued <= jsF(maxAge)) {
		return deny("token_too_old")
	}
	if jsF(m["policy_revision"]) == jsF(f.state["policy_revision"]) && !grantsEq(m["policy_digest"], f.state["policy_digest"]) {
		return deny("policy_fork")
	}
	behind := []any{}
	for _, c := range freshAtCounters {
		if !(jsF(f.state[c]) >= jsF(m[c])) {
			behind = append(behind, c)
		}
	}
	if len(behind) == 0 {
		return map[string]any{"decision": "ok"}
	}
	return map[string]any{"decision": "escalate", "code": "stale_state", "behind": behind}
}

// grantsSortU16 sorts strings in UTF-16 code unit order (JavaScript's default string order).
func grantsSortU16(l []string) {
	sort.SliceStable(l, func(i, j int) bool { return grantsU16Less(l[i], l[j]) })
}
