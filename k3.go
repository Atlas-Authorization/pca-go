package pca

// K3 artifacts, verification side: signed policy bundles, decision records with their Merkle log (signed heads, inclusion,
// batches), list-authorized receipts and cursors, and the grant-management verifications (amend, revoke, needs approval).
// Every function takes parsed JSON values (StrictParse / ParseJSONLenient) and is TOTAL: malformed input yields the failure
// value, never a panic. Signatures are Ed25519 (strict) over a domain prefix followed by the strict canonical JSON of the body.

import (
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	bundleDomain      = "atlas-pca/policy-bundle/v1\x00"
	bundleRefDomain   = "atlas-pca/policy-bundle-ref/v1"
	recordDomain      = "atlas-pca/decision-record/v1"
	logHeadDomain     = "atlas-pca/decision-log-head/v1\x00"
	listReceiptDomain = "atlas-pca/list-receipt/v1\x00"
	listCursorDomain  = "atlas-pca/list-cursor/v1\x00"
	listObjectsDomain = "atlas-pca/list-objects/v1"
	grantAmendDomain  = "atlas-pca/grant-amend/v1\x00"
	grantRevokeDomain = "atlas-pca/grant-revoke/v1\x00"
	needApproveDomain = "atlas-pca/need-approve/v1\x00"
	authorityDomain   = "atlas-pca/authority/v1"
	k3MaxList         = 4096
)

func k3Sub(m map[string]any, drop ...string) map[string]any { return withoutKeys(m, drop...) }

// ---- policy bundles ----------------------------------------------------------------------------------------------------

// BundleDigest is the content address of a bundle: its body without the signatures.
func BundleDigest(b any) (string, bool) {
	m, ok := b.(map[string]any)
	if !ok {
		return "", false
	}
	return hashCanonicalV(map[string]any{"d": bundleRefDomain, "b": k3Sub(m, "sigs")})
}

var bundleVersionRe = regexp.MustCompile(`^[0-9]{1,6}(\.[0-9]{1,6}){0,3}$`)

func k3Num(s string) float64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return math.NaN()
	}
	return f
}

// compareVersion compares dotted numeric versions (missing parts are 0; a non-numeric part compares as NaN, i.e. greater).
func compareVersion(a, b string) int {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(pa) || i < len(pb); i++ {
		var x, y float64
		if i < len(pa) {
			x = k3Num(pa[i])
		}
		if i < len(pb) {
			y = k3Num(pb[i])
		}
		if d := x - y; d != 0 {
			if d < 0 {
				return -1
			}
			return 1
		}
	}
	return 0
}

func k3StrList(v any, max, each int) bool {
	l, ok := v.([]any)
	if !ok || len(l) > max {
		return false
	}
	for _, g := range l {
		if !k3Str(g, each) {
			return false
		}
	}
	return true
}

func bundleShapeError(b any) string {
	m, ok := b.(map[string]any)
	if !ok {
		return "not a policy bundle"
	}
	if f, ok := jsNum(m["v"]); !ok || f != 1 || m["kind"] != "pca-policy-bundle" {
		return "not a policy bundle"
	}
	rev, _ := jsNum(m["revision"])
	if !k3Int(m["revision"]) || rev < 1 || !k3Int(m["issued_at"]) {
		return "bad revision or time"
	}
	_, hasPrev := m["prev"]
	if rev == 1 && hasPrev || rev != 1 && !k3Str(m["prev"], 128) {
		return "prev must be absent at revision 1 and present after"
	}
	if !k3StrList(m["grants"], k3MaxList, 128) {
		return "bad grants"
	}
	if !k3StrList(m["template_digests"], k3MaxList, 128) {
		return "bad template_digests"
	}
	for _, k := range []string{"schema_digest", "constitution_digest", "flow_rules_digest"} {
		if v, has := m[k]; has && !k3Str(v, 128) {
			return "bad " + k
		}
	}
	if s, ok := m["min_verifier_version"].(string); !ok || !bundleVersionRe.MatchString(s) {
		return "bad min_verifier_version"
	}
	return ""
}

// BundleLast is the newest accepted bundle: a lower revision is a rollback, the next one must chain by `prev`.
type BundleLast struct {
	Revision int64
	Digest   string
}

// BundleVerifyOptions: Signers is the pinned signer set (b64u public keys); signatures by anyone else are ignored.
type BundleVerifyOptions struct {
	Signers         []string
	Threshold       int64
	VerifierVersion string
	Last            *BundleLast
}

// BundleVerdict: OK with Revision, Digest and the valid pinned Signers, else Code (malformed, below_threshold, rollback,
// broken_chain, verifier_too_old) and Reason.
type BundleVerdict struct {
	OK       bool
	Revision int64
	Digest   string
	Signers  []string
	Code     string
	Reason   string
}

// VerifyBundle checks a bundle against k-of-n pinned signers, this verifier's version and the accepted history.
func VerifyBundle(b any, o BundleVerifyOptions) BundleVerdict {
	bad := func(code, why string) BundleVerdict { return BundleVerdict{Code: code, Reason: why} }
	if e := bundleShapeError(b); e != "" {
		return bad("malformed", e)
	}
	m := b.(map[string]any)
	sigs, isArr := m["sigs"].([]any)
	if !isArr || len(sigs) > 64 || o.Threshold < 1 {
		return bad("malformed", "bad sigs or threshold")
	}
	pinned := map[string]bool{}
	for _, s := range o.Signers {
		pinned[s] = true
	}
	body := k3Sub(m, "sigs")
	good := []string{}
	seen := map[string]bool{}
	for _, sv := range sigs {
		s, ok := sv.(map[string]any)
		if !ok {
			continue
		}
		signer, ok := s["signer"].(string)
		if ok && pinned[signer] && extSigned(signer, bundleDomain, body, s["sig"]) && !seen[signer] {
			seen[signer] = true
			good = append(good, signer)
		}
	}
	if int64(len(good)) < o.Threshold {
		return bad("below_threshold", strconv.Itoa(len(good))+" valid pinned signature(s), need "+strconv.FormatInt(o.Threshold, 10))
	}
	min := m["min_verifier_version"].(string)
	if !bundleVersionRe.MatchString(o.VerifierVersion) || compareVersion(o.VerifierVersion, min) < 0 { // an unparseable verifier version is too old
		return bad("verifier_too_old", "needs verifier >= "+min)
	}
	rev, _ := jsNum(m["revision"])
	digest, ok := BundleDigest(b)
	if !ok {
		return bad("malformed", "bundle is not canonicalizable")
	}
	if l := o.Last; l != nil {
		last := float64(l.Revision)
		prev, _ := m["prev"].(string)
		switch {
		case rev < last:
			return bad("rollback", "revision "+jsNumberString(rev)+" < accepted "+strconv.FormatInt(l.Revision, 10))
		case rev == last && digest != l.Digest:
			return bad("broken_chain", "same revision, different content")
		case rev == last+1 && prev != l.Digest:
			return bad("broken_chain", "prev does not chain to the accepted revision")
		}
	}
	return BundleVerdict{OK: true, Revision: int64(rev), Digest: digest, Signers: good}
}

// ---- decision records and their log -------------------------------------------------------------------------------------

// RecordCommit is the hash-chain commit of a decision record.
func RecordCommit(r any) (string, bool) {
	return hashCanonicalV(map[string]any{"d": recordDomain, "r": r})
}

// VerifyLogHead: the signed log head is well formed and signed by `signer`.
func VerifyLogHead(h any, signer string) bool {
	m, ok := h.(map[string]any)
	if !ok {
		return false
	}
	if f, ok := jsNum(m["v"]); !ok || f != 1 {
		return false
	}
	if s, ok := m["signer"].(string); !ok || s != signer || !k3Int(m["size"]) || !k3Int(m["issued_at"]) {
		return false
	}
	if _, ok := m["root"].(string); !ok {
		return false
	}
	if _, ok := m["last_commit"].(string); !ok {
		return false
	}
	return extSigned(signer, logHeadDomain, k3Sub(m, "sig"), m["sig"])
}

// VerifyRecordInclusion: offline, this record is in the log the signed head commits to, and the head is by `signer`.
func VerifyRecordInclusion(rec, proof, head any, signer string) bool {
	if !VerifyLogHead(head, signer) {
		return false
	}
	c, ok := RecordCommit(rec)
	root, _ := head.(map[string]any)["root"].(string)
	return ok && VerifyLedgerInclusion(root, proof, c)
}

// BatchVerdict: OK with the new cursor (Next, LastCommit), else Reason.
type BatchVerdict struct {
	OK         bool
	Next       int64
	LastCommit string
	Reason     string
}

// VerifyDecisionBatch is the receiver side of the decision stream: contiguous sequence, intact hash chain from the receiver's
// state (next, lastCommit) and, when the batch reaches the head, the head's last commit and size match.
func VerifyDecisionBatch(b any, next int64, lastCommit string, signer string) BatchVerdict {
	malformed := BatchVerdict{Reason: "malformed batch"}
	m, ok := b.(map[string]any)
	if !ok {
		return malformed
	}
	if f, ok := jsNum(m["from"]); !ok || f != float64(next) {
		return BatchVerdict{Reason: "gap or replay: batch starts at " + jsMemberString(m, "from") + ", expected " + strconv.FormatInt(next, 10)}
	}
	if !VerifyLogHead(m["head"], signer) {
		return BatchVerdict{Reason: "head not signed by the pinned log signer"}
	}
	recs, ok := m["records"].([]any)
	if !ok {
		return malformed
	}
	last, n := lastCommit, next
	for _, rv := range recs {
		r, ok := rv.(map[string]any)
		if !ok {
			return malformed
		}
		seq, isNum := jsNum(r["seq"])
		if prev, isStr := r["prev"].(string); !isNum || seq != float64(n) || !isStr || prev != last {
			return BatchVerdict{Reason: "chain broken at seq " + jsMemberString(r, "seq")}
		}
		c, ok := RecordCommit(r)
		if !ok {
			return malformed
		}
		last = c
		n++
	}
	head := m["head"].(map[string]any)
	size, _ := jsNum(head["size"])
	if float64(n) > size {
		return BatchVerdict{Reason: "batch is longer than the signed head"}
	}
	if float64(n) == size && last != head["last_commit"] {
		return BatchVerdict{Reason: "batch end does not match the signed head"}
	}
	return BatchVerdict{OK: true, Next: n, LastCommit: last}
}

// ---- list-authorized ----------------------------------------------------------------------------------------------------

// ObjectsDigest is the digest of the returned object ids, in order.
func ObjectsDigest(objects []string) (string, bool) {
	o := make([]any, len(objects))
	for i, s := range objects {
		o[i] = s
	}
	return hashCanonicalV(map[string]any{"d": listObjectsDomain, "o": o})
}

// VerifyListReceipt: the receipt is well formed and signed by `signer`; when `objects` is non-nil it also commits to exactly
// those ids (count and digest).
func VerifyListReceipt(r any, signer string, objects []string) bool {
	m, ok := r.(map[string]any)
	if !ok {
		return false
	}
	if f, ok := jsNum(m["v"]); !ok || f != 1 {
		return false
	}
	if s, ok := m["signer"].(string); !ok || s != signer || !k3Str(m["subject"], 512) || !k3Str(m["resource_type"], 512) || !k3Int(m["count"]) || !k3Int(m["issued_at"]) {
		return false
	}
	if !extSigned(signer, listReceiptDomain, k3Sub(m, "sig"), m["sig"]) {
		return false
	}
	if objects == nil {
		return true
	}
	d, ok := ObjectsDigest(objects)
	return ok && jsF(m["count"]) == float64(len(objects)) && m["objects_digest"] == d
}

// ListBindInputs are what a page cursor is bound to. Relation nil: no relation filter.
type ListBindInputs struct {
	Subject      string
	ResourceType string
	FilterID     string
	PolicyDigest string
	Relation     *string
	Limit        int
}

// ListBind is the digest a cursor is bound to: changing any input between pages is refused.
func ListBind(a ListBindInputs) (string, bool) {
	var rel any
	if a.Relation != nil {
		rel = *a.Relation
	}
	return hashCanonicalV(map[string]any{"s": a.Subject, "t": a.ResourceType, "f": a.FilterID, "p": a.PolicyDigest, "r": rel, "l": a.Limit})
}

// CursorVerdict: OK with the inner candidate cursor (HasInner) and Skip, else Reason (malformed, signature, bind).
type CursorVerdict struct {
	OK       bool
	Inner    string
	HasInner bool
	Skip     int64
	Reason   string
}

// VerifyListCursor: shape, signature by `signer` and, when bind is non-nil, that it was issued for exactly those inputs.
func VerifyListCursor(tok any, signer string, bind *ListBindInputs) CursorVerdict {
	bad := func(r string) CursorVerdict { return CursorVerdict{Reason: r} }
	s, ok := tok.(string)
	if !ok {
		return bad("malformed")
	}
	parts := strings.Split(s, ".")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return bad("malformed")
	}
	raw, ok := DecodeB64uStrict(parts[0], -1)
	if !ok {
		return bad("malformed")
	}
	v, err := ParseJSONLenient([]byte(string([]rune(string(raw))))) // TextDecoder: invalid bytes become U+FFFD
	if err != nil {
		return bad("malformed")
	}
	c, ok := v.(map[string]any)
	if !ok {
		return bad("malformed")
	}
	if f, ok := jsNum(c["v"]); !ok || f != 1 {
		return bad("malformed")
	}
	cb, isStr := c["bind"].(string)
	inner, hasInner := c["inner"]
	_, innerIsStr := inner.(string)
	if !isStr || !k3Int(c["skip"]) || hasInner && !innerIsStr {
		return bad("malformed")
	}
	if sg, ok := c["signer"].(string); !ok || sg != signer || !extSigned(signer, listCursorDomain, c, parts[1]) {
		return bad("signature")
	}
	if bind != nil {
		if want, ok := ListBind(*bind); !ok || cb != want {
			return bad("bind")
		}
	}
	skip, _ := jsNum(c["skip"])
	out := CursorVerdict{OK: true, Skip: int64(skip)}
	if hasInner {
		out.Inner, out.HasInner = inner.(string), true
	}
	return out
}

// ---- grant authority ----------------------------------------------------------------------------------------------------

type k3Authority struct {
	verbs, resources []string
	limits           map[string]float64
	exp              float64
	hasExp           bool
	src              map[string]any
}

func k3Strings(v any, max, each int) ([]string, bool) {
	l, ok := v.([]any)
	if !ok || len(l) > max {
		return nil, false
	}
	out := make([]string, len(l))
	for i, x := range l {
		if !k3Str(x, each) {
			return nil, false
		}
		out[i] = x.(string)
	}
	return out, true
}

// parseAuthority is the reference checkAuthority.
func parseAuthority(a any) (*k3Authority, bool) {
	m, ok := a.(map[string]any)
	if !ok {
		return nil, false
	}
	out := &k3Authority{exp: math.Inf(1), src: m}
	if out.verbs, ok = k3Strings(m["verbs"], 256, 128); !ok {
		return nil, false
	}
	if out.resources, ok = k3Strings(m["resources"], 1024, 512); !ok {
		return nil, false
	}
	if lv, has := m["limits"]; has {
		lm, ok := lv.(map[string]any)
		if !ok {
			return nil, false
		}
		out.limits = map[string]float64{}
		for k, v := range lm {
			f, ok := jsNum(v)
			if !ok || math.IsInf(f, 0) || math.IsNaN(f) || f < 0 {
				return nil, false
			}
			out.limits[k] = f
		}
	}
	if ev, has := m["expires_at"]; has {
		if !k3Int(ev) {
			return nil, false
		}
		out.exp, out.hasExp = jsF(ev), true
	}
	return out, true
}

func k3Covers(p, r string) bool {
	if strings.HasSuffix(p, "*") {
		return strings.HasPrefix(r, p[:len(p)-1])
	}
	return p == r
}

func k3ResSubset(small, big []string) bool {
	for _, s := range small {
		ok := false
		for _, b := range big {
			if k3Covers(b, s) && (!strings.HasSuffix(s, "*") || strings.HasSuffix(b, "*") || b == s) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

func k3VerbSubset(small, big []string) bool {
	for _, s := range small {
		if !containsStr(big, s) {
			return false
		}
	}
	return true
}

// k3Le: everything a allows, b allows.
func k3Le(a, b *k3Authority) bool {
	if !k3VerbSubset(a.verbs, b.verbs) || !k3ResSubset(a.resources, b.resources) {
		return false
	}
	for k, v := range a.limits {
		if bv, has := b.limits[k]; has && !(v <= bv) {
			return false
		}
	}
	for k := range b.limits {
		if _, has := a.limits[k]; !has {
			return false
		}
	}
	return a.exp <= b.exp
}

func k3Compare(o, n *k3Authority) string {
	nle, ole := k3Le(n, o), k3Le(o, n)
	switch {
	case nle && ole:
		return "equal"
	case nle:
		return "narrower"
	case ole:
		return "wider"
	}
	return "incomparable"
}

// CompareAuthority orders two authorities: "narrower", "equal", "wider" or "incomparable" (ok false when either is malformed).
func CompareAuthority(oldA, newA any) (string, bool) {
	o, ok1 := parseAuthority(oldA)
	n, ok2 := parseAuthority(newA)
	if !ok1 || !ok2 {
		return "", false
	}
	return k3Compare(o, n), true
}

func k3SortedAny(l []string) []any {
	s := append([]string{}, l...)
	sort.SliceStable(s, func(i, j int) bool { return compareUnits(utf16Units(s[i]), utf16Units(s[j])) < 0 })
	out := make([]any, len(s))
	for i, x := range s {
		out[i] = x
	}
	return out
}

// AuthorityDigest: verbs and resources are sorted (UTF-16 order) first, so their order does not matter.
func AuthorityDigest(a any) (string, bool) {
	m, ok := a.(map[string]any)
	if !ok {
		return "", false
	}
	verbs, ok1 := k3Strings(m["verbs"], math.MaxInt32, math.MaxInt32)
	res, ok2 := k3Strings(m["resources"], math.MaxInt32, math.MaxInt32)
	if !ok1 || !ok2 {
		return "", false
	}
	c := k3Sub(m)
	c["verbs"], c["resources"] = k3SortedAny(verbs), k3SortedAny(res)
	return hashCanonicalV(map[string]any{"d": authorityDomain, "a": c})
}

func k3Union(a, b []string) []any {
	seen := map[string]bool{}
	out := []any{}
	for _, l := range [][]string{a, b} {
		for _, s := range l {
			if !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	return out
}

// k3Merge unions verbs and resources; a ceiling or expiry is only ever RAISED by the delta, one the delta omits is kept.
func k3Merge(a, d *k3Authority) map[string]any {
	out := map[string]any{"verbs": k3Union(a.verbs, d.verbs), "resources": k3Union(a.resources, d.resources)}
	if len(a.limits) > 0 {
		lim := map[string]any{}
		for k, v := range a.limits {
			if dv, has := d.limits[k]; has {
				v = math.Max(v, dv)
			}
			lim[k] = jsNumber(v)
		}
		out["limits"] = lim
	}
	if a.hasExp {
		e := a.exp
		if d.hasExp {
			e = math.Max(e, d.exp)
		}
		out["expires_at"] = jsNumber(e)
	}
	return out
}

// ---- grant management ---------------------------------------------------------------------------------------------------

// AmendVerdict: OK with Widens, Next (the resulting authority) and its digest, else Code.
type AmendVerdict struct {
	OK         bool
	Widens     bool
	Next       map[string]any
	NextDigest string
	Code       string
}

// VerifyAmendment decides an amendment against the current grant facts {id, rev, principal, agent, status, authority}. Check
// order is normative: request shape, authority shape, grant active, classification (`narrow` that changes nothing or widens is
// not_narrower), signature (signature_required, then bad_signature; widening needs the PRINCIPAL), step-up for a widening.
// stepUpOk is the already evaluated step-up verdict.
func VerifyAmendment(cur, req any, stepUpOk bool) AmendVerdict {
	fail := func(c string) AmendVerdict { return AmendVerdict{Code: c} }
	r, ok := req.(map[string]any)
	action, _ := r["action"].(string)
	if !ok || action != "narrow" && action != "merge" && action != "replace" {
		return fail("bad_request")
	}
	delta, ok := parseAuthority(r["authority"])
	c, ok2 := cur.(map[string]any)
	if !ok || !ok2 {
		return fail("bad_request")
	}
	curAuth, ok := parseAuthority(c["authority"])
	if !ok {
		return fail("bad_request")
	}
	if c["status"] != "active" {
		return fail("not_active")
	}
	next := delta.src
	if action == "merge" {
		next = k3Merge(curAuth, delta)
	}
	nextAuth, _ := parseAuthority(next)
	order := k3Compare(curAuth, nextAuth)
	widens := order == "wider" || order == "incomparable"
	if !widens && action == "narrow" && order == "equal" || widens && action == "narrow" {
		return fail("not_narrower")
	}
	sig, isStr := r["sig"].(string)
	by, _ := r["signed_by"].(string)
	if !isStr || by != "holder" && by != "principal" || widens && by != "principal" {
		return fail("signature_required")
	}
	who := "agent"
	if by == "principal" {
		who = "principal"
	}
	signer, _ := c[who].(string)
	dd, ok := AuthorityDigest(r["authority"])
	if !ok || !extSigned(signer, grantAmendDomain, map[string]any{"grant": c["id"], "rev": c["rev"], "action": action, "authority": dd}, sig) {
		return fail("bad_signature")
	}
	if widens && !stepUpOk {
		return fail("step_up_required")
	}
	nd, _ := AuthorityDigest(next)
	return AmendVerdict{OK: true, Widens: widens, Next: next, NextDigest: nd}
}

// RevokeVerdict: OK with Scope ("grant", "agent" or "subtree"), else Code.
type RevokeVerdict struct {
	OK    bool
	Scope string
	Code  string
}

// VerifyRevokeSignature decides a revocation's authority: the principal's signature over (grant id, scope) for root {id, principal}.
func VerifyRevokeSignature(root, scope, sig any) RevokeVerdict {
	sc, _ := scope.(string)
	if sc != "grant" && sc != "agent" && sc != "subtree" {
		return RevokeVerdict{Code: "bad_request"}
	}
	r, _ := root.(map[string]any)
	principal, _ := r["principal"].(string)
	if !extSigned(principal, grantRevokeDomain, map[string]any{"grant": r["id"], "scope": sc}, sig) {
		return RevokeVerdict{Code: "bad_signature"}
	}
	return RevokeVerdict{OK: true, Scope: sc}
}

// NeedVerdict: OK with the merged Authority and its digest, else Code.
type NeedVerdict struct {
	OK              bool
	Authority       map[string]any
	AuthorityDigest string
	Code            string
}

// VerifyNeedApproval decides a needs approval: principal signature over (need, grant, rev, approved), same count, each approved
// need names the same verb and resource with amounts only LOWERED and only when `adjustable`, then the step-up. Yields the
// merged authority.
func VerifyNeedApproval(needRequest, grant, approved, sig any, stepUpOk bool) NeedVerdict {
	fail := func(c string) NeedVerdict { return NeedVerdict{Code: c} }
	nr, ok1 := needRequest.(map[string]any)
	g, ok2 := grant.(map[string]any)
	if !ok1 || !ok2 {
		return fail("bad_request")
	}
	if nr["status"] != "pending" {
		return fail("conflict")
	}
	principal, _ := g["principal"].(string)
	msg := map[string]any{"need": nr["id"], "grant": nr["grant_id"], "rev": g["rev"], "approved": approved}
	if !extSigned(principal, needApproveDomain, msg, sig) {
		return fail("bad_signature")
	}
	appr, isArr := approved.([]any)
	needs, _ := nr["needs"].([]any)
	if !isArr || len(appr) != len(needs) {
		return fail("need_not_lowered_only")
	}
	delta := &k3Authority{limits: map[string]float64{}}
	for i := range appr {
		a, ok1 := appr[i].(map[string]any)
		want, ok2 := needs[i].(map[string]any)
		verb, vok := a["verb"].(string)
		res, rok := a["resource"].(string)
		if !ok1 || !ok2 || !vok || !rok || a["verb"] != want["verb"] || a["resource"] != want["resource"] {
			return fail("need_not_lowered_only")
		}
		al, _ := a["limits"].(map[string]any)
		wl, _ := want["limits"].(map[string]any)
		for _, k := range jsKeys(al) {
			v, vnum := jsNum(al[k])
			wv, has := wl[k]
			w, wnum := jsNum(wv)
			if !vnum || !has || !wnum || v > w {
				return fail("need_not_lowered_only")
			}
			if v < w && want["adjustable"] != true {
				return fail("need_not_adjustable")
			}
			if cur, ok := delta.limits[k]; !ok || v > cur {
				delta.limits[k] = math.Max(v, 0)
			}
		}
		delta.verbs, delta.resources = append(delta.verbs, verb), append(delta.resources, res)
	}
	if !stepUpOk {
		return fail("step_up_required")
	}
	cur, ok := parseAuthority(g["authority"])
	if !ok {
		return fail("bad_request")
	}
	merged := k3Merge(cur, delta)
	d, _ := AuthorityDigest(merged)
	return NeedVerdict{OK: true, Authority: merged, AuthorityDigest: d}
}
