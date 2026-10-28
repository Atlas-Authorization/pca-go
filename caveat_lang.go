package pca

// Caveat language v2 (track K1): a port of packages/pca/src/caveat-lang.ts (security contracts C-220 to C-229).
//
// Six verifier-side features, every one of them a RESTRICTION (a caveat only removes authority, and a verifier that does not
// know a type refuses the chain):
//
//   - needs_discharge: a third-party caveat, valid only with a signed discharge from a key THE VERIFIER pinned
//   - sealed: no hop may be appended below the hop that carries it
//   - narrow: a holder-signed per-action or short-lived self-attenuation that rides beside the PCActn (no new hop)
//   - max_uses: a lifetime use count backed by the verifier's replay store (n atomic first-use slots)
//   - derive: a bounded, stratified, non-recursive derived-fact check in Kleene three-valued logic
//   - spiffe_bound: the presenting workload's verified SPIFFE ID must match
//
// Everything is total: a malformed caveat, discharge, narrow block or context is a refusal, never a panic and never an allow.
// Values are parsed JSON (map[string]any, []any, string, bool, nil, json.Number). A clock (now) is a float64 so that a
// non-integer clock can be refused exactly like the reference; a "...Error" function returns "" when the value is valid.

import (
	"sort"
	"strconv"
	"strings"
)

// Caveat types this module evaluates.
const (
	CaveatNeedsDischarge = "needs_discharge"
	CaveatSealed         = "sealed"
	CaveatMaxUses        = "max_uses"
	CaveatDerive         = "derive"
	CaveatSpiffeBound    = "spiffe_bound"
)

// Signature and digest domains.
const (
	DischargeDomain       = "atlas-pca/discharge/v1\x00"
	DischargeRefDomain    = "atlas-pca/discharge-ref/v1"
	DischargeActionDomain = "atlas-pca/discharge-action/v1"
	NarrowDomain          = "atlas-pca/narrow/v1\x00"
	MaxUsesDomain         = "atlas-pca/max-uses/v1\x00"
)

// Limits.
const (
	// K1MaxLifetimeMs is the longest life of a discharge or a narrow block (24 h).
	K1MaxLifetimeMs   = 86_400_000
	MaxUsesLimit      = 256
	NarrowMaxCaveats  = 16
	DeriveMaxDefs     = 8
	DeriveMaxNodes    = 32
	DeriveMaxDepth    = 4
	DeriveMaxWindowMs = 30 * 86_400_000
	DeriveMaxHistory  = 10_000
	SpiffeMaxIDBytes  = 2048
)

var k1Types = []string{CaveatNeedsDischarge, CaveatSealed, CaveatMaxUses, CaveatDerive, CaveatSpiffeBound}
var k1IssuerClasses = []string{"human", "org", "workload", "model", "artifact"}
var k1Ops = []string{"eq", "neq", "gte", "lte", "in"}

// IsK1Caveat is true for a caveat object whose type this module evaluates (the stock evaluators refuse these).
func IsK1Caveat(c any) bool {
	m, ok := c.(map[string]any)
	if !ok {
		return false
	}
	t, ok := m["type"].(string)
	return ok && contains(k1Types, t)
}

// ---- small helpers -------------------------------------------------------------------------------------------------

// clSafeF is isSafeInt for a verifier clock: integral, |n| <= 2^53-1, not -0.
func clSafeF(f float64) bool {
	return f == f && f == float64(int64(f)) && f <= maxSafeInt && f >= -maxSafeInt && !(f == 0 && 1/f < 0)
}

func clStrIn(v any, xs []string) bool {
	s, ok := v.(string)
	return ok && contains(xs, s)
}

// clID is ^[a-z0-9][a-z0-9_.-]{0,63}$ (anchored: no trailing newline).
func clID(v any) bool {
	s, ok := v.(string)
	if !ok || len(s) < 1 || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		base := c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
		if i == 0 && !base {
			return false
		}
		if !base && c != '_' && c != '.' && c != '-' {
			return false
		}
	}
	return true
}

// clName is ^[a-z][a-z0-9_]{0,63}$.
func clName(v any) bool {
	s, ok := v.(string)
	return ok && matchName(s)
}

// clScalar is isScalarClaim: a string of 1..256 UTF-8 bytes, a boolean or a safe integer that is not -0.
func clScalar(v any) bool {
	if _, isStr := v.(string); isStr {
		return boundedStr(v, 256)
	}
	return isScalarV(v)
}

func clSortedKeys(m map[string]any) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// clSortUTF16 sorts like Array.prototype.sort() on strings (UTF-16 code unit order).
func clSortUTF16(xs []string) {
	sort.Slice(xs, func(i, j int) bool { return compareUnits(utf16Units(xs[i]), utf16Units(xs[j])) < 0 })
}

func clStrings(xs []any) []string {
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// ---- SPIFFE ID syntax -------------------------------------------------------------------------------------------------

// SpiffeIDError is "" when s is a valid SPIFFE ID: spiffe:// + a trust domain over [a-z0-9._-] (1..255 bytes) + an optional
// path of non-empty segments over [A-Za-z0-9._-] that are not "." or "..", no trailing slash, at most 2048 bytes.
func SpiffeIDError(v any) string {
	s, ok := v.(string)
	if !ok || s == "" {
		return "SPIFFE ID must be a non-empty string"
	}
	if len(s) > SpiffeMaxIDBytes {
		return "SPIFFE ID is too long"
	}
	if !strings.HasPrefix(s, "spiffe://") {
		return "SPIFFE ID must begin with spiffe://"
	}
	rest := s[len("spiffe://"):]
	slash := strings.IndexByte(rest, '/')
	td, path := rest, ""
	if slash >= 0 {
		td, path = rest[:slash], rest[slash:]
	}
	if len(td) == 0 || len(td) > 255 || !clSpiffeChars(td, false) {
		return "invalid trust domain"
	}
	if path == "" {
		return ""
	}
	if strings.HasSuffix(path, "/") {
		return "path must not end with a slash"
	}
	for _, seg := range strings.Split(path, "/")[1:] {
		if seg == "" || seg == "." || seg == ".." || !clSpiffeChars(seg, true) {
			return "invalid path segment"
		}
	}
	return ""
}

func clSpiffeChars(s string, upper bool) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_' || upper && c >= 'A' && c <= 'Z') {
			return false
		}
	}
	return true
}

// ---- hop analysis -----------------------------------------------------------------------------------------------------

// BoundCaveat is a caveat of the leaf hop with the hop that introduced it.
type BoundCaveat struct {
	Caveat any
	// Hop is the index of the introducing hop (0 = the root grant).
	Hop int
	// CapHash is CapHash() of that hop.
	CapHash string
}

// clHops is the hops the policy layer sees: the chain (root first), else the grant alone.
func clHops(grant, chain any) []any {
	if ch, ok := chain.([]any); ok && len(ch) > 0 {
		return ch
	}
	return []any{grant}
}

// BoundCaveats lists every caveat of the leaf hop with the hop that introduced it. Caveat lists are cumulative and
// append-only, so the caveat at position p was introduced by the first hop whose list is longer than p. ok is false for a
// malformed chain.
func BoundCaveats(grant, chain any) (out []BoundCaveat, ok bool) {
	defer func() {
		if recover() != nil {
			out, ok = nil, false
		}
	}()
	hops := clHops(normalizeJSON(grant), normalizeJSON(chain))
	leaf, _ := hops[len(hops)-1].(map[string]any)
	lc, isArr := leaf["caveats"].([]any)
	if !isArr {
		return nil, false
	}
	hashes := map[int]string{}
	out = make([]BoundCaveat, 0, len(lc))
	for p, cv := range lc {
		h := -1
		for i, x := range hops {
			if m, isObj := x.(map[string]any); isObj {
				if cs, isList := m["caveats"].([]any); isList && len(cs) > p {
					h = i
					break
				}
			}
		}
		if h < 0 {
			h = len(hops) - 1
		}
		hash, has := hashes[h]
		if !has {
			hm, isObj := hops[h].(map[string]any)
			if !isObj {
				return nil, false
			}
			var err error
			if hash, err = CapHash(hm); err != nil {
				return nil, false
			}
			hashes[h] = hash
		}
		out = append(out, BoundCaveat{Caveat: cv, Hop: h, CapHash: hash})
	}
	return out, true
}

// ---- needs_discharge ----------------------------------------------------------------------------------------------------

func clRequireError(r any) string {
	m, ok := r.(map[string]any)
	if !ok {
		return "requirement must be an object"
	}
	if e := closedMembersMsg(m, "require", []string{"claim", "op", "value"}); e != "" {
		return e
	}
	if !clName(m["claim"]) {
		return "claim name is malformed"
	}
	if !clStrIn(m["op"], k1Ops) {
		return "op must be eq, neq, gte, lte or in"
	}
	op := m["op"].(string)
	switch op {
	case "in":
		vs, isArr := m["value"].([]any)
		if !isArr || len(vs) == 0 || len(vs) > 16 {
			return "'in' needs 1..16 scalar values"
		}
		for _, x := range vs {
			if !clScalar(x) {
				return "'in' needs 1..16 scalar values"
			}
		}
	case "gte", "lte":
		if !jsIsInt(m["value"]) {
			return "'" + op + "' needs a safe integer"
		}
	default:
		if !clScalar(m["value"]) {
			return "value must be a scalar"
		}
	}
	return ""
}

// NeedsDischargeError is "" when the caveat is well-formed: closed members, canonical names, bounded sizes.
func NeedsDischargeError(c any) string {
	m, ok := c.(map[string]any)
	if !ok {
		return "caveat must be an object"
	}
	if e := closedMembersMsg(m, "needs_discharge", []string{"type", "id", "issuer", "issuer_class", "bind", "ttl_ms", "require"}, "issuer_spiffe"); e != "" {
		return e
	}
	if m["type"] != CaveatNeedsDischarge {
		return "not a needs_discharge caveat"
	}
	if !clID(m["id"]) {
		return "id is malformed"
	}
	if !clID(m["issuer"]) {
		return "issuer label is malformed"
	}
	if !clStrIn(m["issuer_class"], k1IssuerClasses) {
		return "issuer_class must be human, org, workload, model or artifact"
	}
	if m["bind"] != "chain_hop" && m["bind"] != "action" {
		return "bind must be 'chain_hop' or 'action'"
	}
	if !jsIsInt(m["ttl_ms"]) || jsF(m["ttl_ms"]) < 1 || jsF(m["ttl_ms"]) > K1MaxLifetimeMs {
		return "ttl_ms must be 1..86400000"
	}
	reqs, isArr := m["require"].([]any)
	if !isArr || len(reqs) > 16 {
		return "require must be an array of at most 16 requirements"
	}
	for _, r := range reqs {
		if e := clRequireError(r); e != "" {
			return e
		}
	}
	if sp, has := m["issuer_spiffe"]; has {
		if e := SpiffeIDError(sp); e != "" {
			return "issuer_spiffe: " + e
		}
	}
	return ""
}

// DischargePin is a verifier-side pin for a discharge issuer. Label is what caveats name; the keys never appear in a token.
// PinnedSigner.PQPK pins the post-quantum key a PQ or hybrid discharge must carry (empty: none, such discharges are refused).
type DischargePin struct {
	PinnedSigner
	Label string
	// Class is human, org, workload, model or artifact; it must equal the caveat's issuer_class.
	Class string
	// SpiffeID is the SPIFFE ID the pin carries ("" = none).
	SpiffeID string
}

// DischargeActionDigest is the digest of the exact PCActn (counter and signature included): a bind-action discharge
// authorises that one action.
func DischargeActionDigest(pcactn map[string]any) (string, error) {
	return HashCanonical(map[string]any{"d": DischargeActionDomain, "pcactn": normalizeJSON(pcactn)})
}

// DischargeDigest is the content address of a discharge (signature included); what a revocation list names.
func DischargeDigest(d any) (string, error) {
	return HashCanonical(map[string]any{"d": DischargeRefDomain, "discharge": normalizeJSON(d)})
}

// DischargeShapeError is "" for a well-formed discharge.
func DischargeShapeError(a any) string {
	m, ok := a.(map[string]any)
	if !ok {
		return "not an object"
	}
	required := []string{"v", "kind", "caveat_id", "issuer", "cap_hash", "bind", "claims", "iat", "not_after", "nonce", "sig"}
	if e := closedMembersMsg(m, "discharge", required, "action_digest", "alg", "pq_pk", "pq_sig"); e != "" {
		return e
	}
	if v, isNum := jsNum(m["v"]); !isNum || v != 1 || m["kind"] != "pca-discharge" {
		return "not a pca-discharge v1"
	}
	if !clID(m["caveat_id"]) {
		return "caveat_id is malformed"
	}
	if !clID(m["issuer"]) {
		return "issuer label is malformed"
	}
	if !isDigestV(m["cap_hash"]) {
		return "cap_hash must be canonical base64url (32 bytes)"
	}
	if m["bind"] != "chain_hop" && m["bind"] != "action" {
		return "bind must be 'chain_hop' or 'action'"
	}
	ad, hasAD := m["action_digest"]
	if m["bind"] == "action" {
		if !isDigestV(ad) {
			return "action_digest is required for bind action and forbidden for chain_hop"
		}
	} else if hasAD {
		return "action_digest is required for bind action and forbidden for chain_hop"
	}
	claims, isObj := m["claims"].(map[string]any)
	if !isObj || len(claims) > 16 {
		return "claims must be an object of at most 16 members"
	}
	for _, k := range clSortedKeys(claims) {
		if !clName(k) || !clScalar(claims[k]) {
			return "claim '" + k + "' is malformed"
		}
	}
	if e := clWindowError(m, "a discharge"); e != "" {
		return e
	}
	if e := clNonceError(m); e != "" {
		return e
	}
	if _, isStr := m["sig"].(string); !isStr {
		return "sig must be a string"
	}
	return artifactSuiteError(m)
}

func clWindowError(m map[string]any, what string) string {
	if !(jsIsInt(m["iat"]) && jsF(m["iat"]) >= 0) || !(jsIsInt(m["not_after"]) && jsF(m["not_after"]) >= 0) {
		return "iat and not_after must be non-negative safe integers"
	}
	if !(jsF(m["not_after"]) > jsF(m["iat"])) {
		return "not_after must be greater than iat"
	}
	if jsF(m["not_after"])-jsF(m["iat"]) > K1MaxLifetimeMs {
		return what + " lives at most " + strconv.Itoa(K1MaxLifetimeMs) + " ms"
	}
	return ""
}

func clNonceError(m map[string]any) string {
	ns, isStr := m["nonce"].(string)
	if !isStr {
		return "nonce must be canonical base64url of at least 16 bytes"
	}
	nb, okn := DecodeB64uStrict(ns, -1)
	if !okn || len(nb) < 16 {
		return "nonce must be canonical base64url of at least 16 bytes"
	}
	return ""
}

func clClaimHolds(r map[string]any, claims map[string]any) bool {
	name, _ := r["claim"].(string)
	v, has := claims[name]
	if !has {
		return false
	}
	switch r["op"] {
	case "eq":
		return scalarEqV(v, r["value"])
	case "neq":
		return !scalarEqV(v, r["value"])
	case "gte":
		return jsIsInt(v) && jsF(v) >= jsF(r["value"])
	case "lte":
		return jsIsInt(v) && jsF(v) <= jsF(r["value"])
	case "in":
		vs, _ := r["value"].([]any)
		for _, x := range vs {
			if scalarEqV(v, x) {
				return true
			}
		}
	}
	return false
}

// DischargeBinding is what a discharge must be bound to.
type DischargeBinding struct {
	// CapHash is CapHash() of the hop that carries the caveat.
	CapHash string
	// ActionDigest is DischargeActionDigest of the PCActn being decided (needed for bind action; "" = none).
	ActionDigest string
	Pins         []DischargePin
	Now          float64
	// Revoked lists the DischargeDigest values the verifier has revoked.
	Revoked []string
}

// DischargeVerdict is the result of VerifyDischarge.
type DischargeVerdict struct {
	OK     bool
	Digest string
	Claims map[string]any
	Reason string
}

// VerifyDischarge verifies one discharge against one caveat. The verifier's own pins decide the key; the discharge is bound
// to the hop carrying the caveat (and for bind action to the PCActn); it must be inside its window and within the caveat's
// ttl_ms; and its claims must satisfy every requirement. Total.
func VerifyDischarge(discharge, caveat any, bind DischargeBinding) (res DischargeVerdict) {
	no := func(r string) DischargeVerdict { return DischargeVerdict{Reason: r} }
	defer func() {
		if r := recover(); r != nil {
			res = no("discharge error (fail closed): " + clPanicText(r))
		}
	}()
	if !clSafeF(bind.Now) {
		return no("the verifier clock is not a safe integer (fail closed)")
	}
	cv := normalizeJSON(caveat)
	if e := NeedsDischargeError(cv); e != "" {
		return no("malformed needs_discharge caveat: " + e)
	}
	c := cv.(map[string]any)
	dv := normalizeJSON(discharge)
	if e := DischargeShapeError(dv); e != "" {
		return no("malformed discharge: " + e)
	}
	d := dv.(map[string]any)
	if d["caveat_id"] != c["id"] {
		return no("the discharge is for another caveat")
	}
	if d["issuer"] != c["issuer"] {
		return no("the discharge names another issuer")
	}
	var pins []DischargePin
	for _, p := range bind.Pins {
		if p.Label == c["issuer"] {
			pins = append(pins, p)
		}
	}
	if len(pins) == 0 {
		return no("the issuer is not pinned by this verifier")
	}
	if len(pins) > 1 {
		return no("the issuer label is pinned more than once (ambiguous)")
	}
	pin := pins[0]
	if pin.Class != c["issuer_class"] {
		return no("the pinned issuer is not of the class the caveat requires")
	}
	if sp, has := c["issuer_spiffe"]; has && pin.SpiffeID != sp {
		return no("the pinned issuer does not carry the SPIFFE ID the caveat requires")
	}
	var pinPq any
	if pin.PQPK != "" {
		pinPq = pin.PQPK
	}
	if !verifyArtifactSig(DischargeDomain, d, pin.PK, pinPq) {
		return no("discharge signature invalid")
	}
	if d["bind"] != c["bind"] {
		return no("the discharge binds differently than the caveat requires")
	}
	if d["cap_hash"] != bind.CapHash {
		return no("the discharge is bound to another hop")
	}
	if c["bind"] == "action" && d["action_digest"] != bind.ActionDigest {
		return no("the discharge is bound to another action")
	}
	iat, notAfter := jsF(d["iat"]), jsF(d["not_after"])
	if bind.Now < iat {
		return no("the discharge is from the future")
	}
	if bind.Now > notAfter {
		return no("the discharge has expired")
	}
	if notAfter-iat > jsF(c["ttl_ms"]) {
		return no("the discharge lives longer than the caveat allows")
	}
	digest, err := DischargeDigest(d)
	if err != nil {
		return no("discharge error (fail closed): " + err.Error())
	}
	if contains(bind.Revoked, digest) {
		return no("the discharge is revoked")
	}
	claims := d["claims"].(map[string]any)
	reqs, _ := c["require"].([]any)
	for _, r := range reqs {
		rm := r.(map[string]any)
		if !clClaimHolds(rm, claims) {
			return no("claim '" + rm["claim"].(string) + "' does not satisfy the caveat")
		}
	}
	return DischargeVerdict{OK: true, Digest: digest, Claims: claims}
}

func clPanicText(r any) string {
	switch t := r.(type) {
	case error:
		return t.Error()
	case string:
		return t
	}
	return "unknown"
}

// ---- narrow --------------------------------------------------------------------------------------------------------------

// narrowForbidden are the types a narrow block must not carry: structure only a real hop can introduce, and nested narrowing.
var narrowForbidden = []string{"envelope", CaveatSealed, "budget_alloc", "intent_session"}

// NarrowShapeError is "" for a well-formed narrow block.
func NarrowShapeError(a any) string {
	m, ok := a.(map[string]any)
	if !ok {
		return "not an object"
	}
	required := []string{"v", "kind", "cap_hash", "holder", "caveats", "iat", "not_after", "nonce", "sig"}
	if e := closedMembersMsg(m, "narrow", required, "action_digest", "alg", "pq_pk", "pq_sig"); e != "" {
		return e
	}
	if v, isNum := jsNum(m["v"]); !isNum || v != 1 || m["kind"] != "pca-narrow" {
		return "not a pca-narrow v1"
	}
	if !isDigestV(m["cap_hash"]) {
		return "cap_hash must be canonical base64url (32 bytes)"
	}
	if !boundedStr(m["holder"], 64) || !b64uOK(m["holder"], 32) {
		return "holder must be canonical base64url (32 bytes)"
	}
	cs, isArr := m["caveats"].([]any)
	if !isArr || len(cs) < 1 || len(cs) > NarrowMaxCaveats {
		return "caveats must be 1..16 caveats"
	}
	for _, c := range cs {
		cm, isObj := c.(map[string]any)
		t, isStr := cm["type"].(string)
		if !isObj || !isStr {
			return "every caveat must be an object with a string type"
		}
		if contains(narrowForbidden, t) {
			return "a narrow block cannot carry a '" + t + "' caveat"
		}
	}
	if ad, has := m["action_digest"]; has && !isDigestV(ad) {
		return "action_digest must be canonical base64url (32 bytes)"
	}
	if e := clWindowError(m, "a narrow block"); e != "" {
		return e
	}
	if e := clNonceError(m); e != "" {
		return e
	}
	if _, isStr := m["sig"].(string); !isStr {
		return "sig must be a string"
	}
	return artifactSuiteError(m)
}

// NarrowBinding is what a narrow block must be bound to.
type NarrowBinding struct {
	Now float64
	// ActionDigest is DischargeActionDigest of the PCActn being decided ("" = none).
	ActionDigest string
}

// NarrowVerdict is the result of VerifyNarrow; Caveats are the block's caveats when OK.
type NarrowVerdict struct {
	OK      bool
	Caveats []any
	Reason  string
}

// VerifyNarrow verifies a narrow block against the chain's leaf: signed by the leaf holder (a post-quantum suite only under
// the PQ key the leaf's holder_pq commits to), bound to the leaf hop and, when it names one, to this PCActn, inside its
// window. The caveats it carries then join the chain's. Total.
func VerifyNarrow(narrow, grant, chain any, bind NarrowBinding) (res NarrowVerdict) {
	no := func(r string) NarrowVerdict { return NarrowVerdict{Reason: r} }
	defer func() {
		if r := recover(); r != nil {
			res = no("narrow error (fail closed): " + clPanicText(r))
		}
	}()
	if !clSafeF(bind.Now) {
		return no("the verifier clock is not a safe integer (fail closed)")
	}
	nv := normalizeJSON(narrow)
	if e := NarrowShapeError(nv); e != "" {
		return no("malformed narrow block: " + e)
	}
	n := nv.(map[string]any)
	hops := clHops(normalizeJSON(grant), normalizeJSON(chain))
	leaf, _ := hops[len(hops)-1].(map[string]any)
	if n["holder"] != leaf["holder"] {
		return no("the narrow block is not signed by the leaf holder")
	}
	leafHash, err := CapHash(leaf)
	if err != nil {
		return no("narrow error (fail closed): " + err.Error())
	}
	if n["cap_hash"] != leafHash {
		return no("the narrow block is bound to another hop")
	}
	var pinPq any
	if pq, isStr := n["pq_pk"].(string); isStr {
		if hp, hasHP := leaf["holder_pq"].(string); hasHP && holderPqCommitment(pq) == hp {
			pinPq = pq
		}
	}
	if !verifyArtifactSig(NarrowDomain, n, n["holder"], pinPq) {
		return no("narrow signature invalid")
	}
	if ad, has := n["action_digest"]; has && ad != bind.ActionDigest {
		return no("the narrow block is bound to another action")
	}
	if bind.Now < jsF(n["iat"]) {
		return no("the narrow block is from the future")
	}
	if bind.Now > jsF(n["not_after"]) {
		return no("the narrow block has expired")
	}
	cs, _ := n["caveats"].([]any)
	return NarrowVerdict{OK: true, Caveats: cs}
}

// ---- max_uses ------------------------------------------------------------------------------------------------------------

// MaxUsesError is "" when the caveat is well-formed.
func MaxUsesError(c any) string {
	m, ok := c.(map[string]any)
	if !ok {
		return "caveat must be an object"
	}
	if e := closedMembersMsg(m, "max_uses", []string{"type", "id", "n", "until"}); e != "" {
		return e
	}
	if m["type"] != CaveatMaxUses {
		return "not a max_uses caveat"
	}
	if !clID(m["id"]) {
		return "id is malformed"
	}
	if !jsIsInt(m["n"]) || jsF(m["n"]) < 1 || jsF(m["n"]) > MaxUsesLimit {
		return "n must be 1..256"
	}
	if !jsIsInt(m["until"]) || jsF(m["until"]) < 0 {
		return "until must be a non-negative safe integer"
	}
	return ""
}

// MaxUsesSlotKey is the store key of use slot i of caveat id carried by the hop with CapHash capHashOfHop:
// b64u(sha256(domain NUL cap NUL id NUL i)).
func MaxUsesSlotKey(capHashOfHop, id string, i int) string {
	return b64.EncodeToString(sha([]byte(MaxUsesDomain + capHashOfHop + "\x00" + id + "\x00" + strconv.Itoa(i))))
}

// UsesVerdict is the result of ReserveMaxUses.
type UsesVerdict struct {
	OK     bool
	Spent  int
	Reason string
}

// ReserveMaxUses spends one use of every max_uses caveat in bound, in order, after the rest of the decision allows. Each
// caveat takes the first free slot of its n: slot i is the stream MaxUsesSlotKey(...) of the StateStore, claimed once with
// a TTL'd ConsumeOnce held until the caveat's `until` (a store without OnceStore falls back to Claim(slot, 1), which never
// expires; either is atomic, so concurrent actions never share a slot, across processes when the store is durable and shared).
// The first exhausted, expired or malformed caveat refuses; slots already taken stay spent (a refusal after that cannot give
// a use back: fail closed).
func ReserveMaxUses(store StateStore, bound []BoundCaveat, now float64) (res UsesVerdict) {
	no := func(r string) UsesVerdict { return UsesVerdict{Reason: r} }
	defer func() {
		if r := recover(); r != nil {
			res = no("max_uses error (fail closed): " + clPanicText(r))
		}
	}()
	if !clSafeF(now) {
		return no("the verifier clock is not a safe integer (fail closed)")
	}
	spent := 0
	ids := map[string]bool{}
	for _, b := range bound {
		cm, isObj := b.Caveat.(map[string]any)
		if !isObj || cm["type"] != CaveatMaxUses {
			continue
		}
		if e := MaxUsesError(cm); e != "" {
			return no("malformed max_uses caveat: " + e)
		}
		id := cm["id"].(string)
		if ids[b.CapHash+"\x00"+id] {
			return no("duplicate max_uses id '" + id + "'")
		}
		ids[b.CapHash+"\x00"+id] = true
		if now >= jsF(cm["until"]) {
			return no("max_uses '" + id + "' has expired")
		}
		if store == nil {
			return no("max_uses error (fail closed): no replay store")
		}
		took := false
		n := int(jsF(cm["n"]))
		for i := 0; i < n && !took; i++ {
			slot := MaxUsesSlotKey(b.CapHash, id, i)
			if os, isOnce := store.(OnceStore); isOnce {
				// the slot is remembered until the caveat's own `until`, then the store may forget it
				got, err := os.ConsumeOnce(slot, int64(jsF(cm["until"])), int64(now))
				if err != nil {
					return no("max_uses error (fail closed): " + err.Error())
				}
				took = got
				continue
			}
			r, err := store.Claim(slot, 1)
			if err != nil {
				return no("max_uses error (fail closed): " + err.Error())
			}
			took = r.OK
		}
		if !took {
			return no("max_uses '" + id + "' is exhausted")
		}
		spent++
	}
	return UsesVerdict{OK: true, Spent: spent}
}

// ---- derive --------------------------------------------------------------------------------------------------------------

func clExprError(x any, names map[string]bool, depth int, count *int) string {
	if depth > DeriveMaxDepth {
		return "expression nests deeper than 4"
	}
	*count++
	if *count > DeriveMaxNodes {
		return "more than 32 expression nodes"
	}
	m, ok := x.(map[string]any)
	if !ok {
		return "expression must be an object"
	}
	if ref, has := m["ref"]; has {
		if e := closedMembersMsg(m, "ref", []string{"ref"}); e != "" {
			return e
		}
		if s, isStr := ref.(string); isStr && names[s] {
			return ""
		}
		return "ref names no earlier def"
	}
	if cv, has := m["const"]; has {
		if e := closedMembersMsg(m, "const", []string{"const"}); e != "" {
			return e
		}
		if clScalar(cv) {
			return ""
		}
		return "const must be a scalar"
	}
	op, _ := m["op"].(string)
	switch op {
	case "and", "or":
		if e := closedMembersMsg(m, op, []string{"op", "args"}); e != "" {
			return e
		}
		args, isArr := m["args"].([]any)
		if !isArr || len(args) < 1 || len(args) > 8 {
			return op + " needs 1..8 arguments"
		}
		for _, a := range args {
			if e := clExprError(a, names, depth+1, count); e != "" {
				return e
			}
		}
		return ""
	case "not":
		if e := closedMembersMsg(m, "not", []string{"op", "arg"}); e != "" {
			return e
		}
		return clExprError(m["arg"], names, depth+1, count)
	case "eq", "neq", "lt", "lte", "gt", "gte":
		if e := closedMembersMsg(m, op, []string{"op", "a", "b"}); e != "" {
			return e
		}
		if e := clExprError(m["a"], names, depth+1, count); e != "" {
			return e
		}
		return clExprError(m["b"], names, depth+1, count)
	}
	return "unknown expression"
}

// DeriveError is "" when the caveat is well-formed: bounded, closed and non-recursive (a def refers only to defs before it).
func DeriveError(c any) string {
	m, ok := c.(map[string]any)
	if !ok {
		return "caveat must be an object"
	}
	if e := closedMembersMsg(m, "derive", []string{"type", "id", "defs", "check"}); e != "" {
		return e
	}
	if m["type"] != CaveatDerive {
		return "not a derive caveat"
	}
	if !clID(m["id"]) {
		return "id is malformed"
	}
	defs, isArr := m["defs"].([]any)
	if !isArr || len(defs) > DeriveMaxDefs {
		return "defs must be an array of at most 8"
	}
	names := map[string]bool{}
	count := 0
	for _, dv := range defs {
		d, isObj := dv.(map[string]any)
		if !isObj || !clName(d["name"]) {
			return "def name is malformed"
		}
		name := d["name"].(string)
		if names[name] {
			return "def '" + name + "' is defined twice"
		}
		de := ""
		kind, _ := d["kind"].(string)
		switch kind {
		case "count":
			de = closedMembersMsg(d, "count", []string{"name", "kind", "window_ms"}, "verb", "resource_prefix")
			if de == "" && !(jsIsInt(d["window_ms"]) && jsF(d["window_ms"]) >= 1 && jsF(d["window_ms"]) <= DeriveMaxWindowMs) {
				de = "window_ms out of range"
			}
			if v, has := d["verb"]; de == "" && has && !boundedStr(v, 256) {
				de = "verb must be a non-empty string"
			}
			if v, has := d["resource_prefix"]; de == "" && has && !boundedStr(v, 256) {
				de = "resource_prefix must be a non-empty string"
			}
		case "param":
			de = closedMembersMsg(d, "param", []string{"name", "kind", "path"})
			if de == "" {
				p, isStr := d["path"].(string)
				segs := strings.Split(p, ".")
				good := isStr && len(segs) <= 4
				for _, s := range segs {
					good = good && isPathSegment(s)
				}
				if !good {
					de = "param path is malformed"
				}
			}
		case "action":
			de = closedMembersMsg(d, "action", []string{"name", "kind", "field"})
			if de == "" && d["field"] != "verb" && d["field"] != "resource" {
				de = "field must be 'verb' or 'resource'"
			}
		case "claim":
			de = closedMembersMsg(d, "claim", []string{"name", "kind", "caveat_id", "claim"})
			if de == "" && !(clID(d["caveat_id"]) && clName(d["claim"])) {
				de = "claim reference is malformed"
			}
		case "expr":
			de = closedMembersMsg(d, "expr", []string{"name", "kind", "expr"})
			if de == "" {
				de = clExprError(d["expr"], names, 1, &count)
			}
		default:
			de = "unknown def kind"
		}
		if de != "" {
			return "def '" + name + "': " + de
		}
		names[name] = true
	}
	return clExprError(m["check"], names, 1, &count)
}

// clEval evaluates an expression; nil is unknown.
func clEval(x any, env map[string]any) any {
	m, ok := x.(map[string]any)
	if !ok {
		return nil
	}
	if ref, has := m["ref"]; has {
		s, _ := ref.(string)
		return env[s]
	}
	if cv, has := m["const"]; has {
		return cv
	}
	op, _ := m["op"].(string)
	switch op {
	case "not":
		if b, isBool := clEval(m["arg"], env).(bool); isBool {
			return !b
		}
		return nil
	case "and", "or":
		stop := op == "or"
		unknown := false
		args, _ := m["args"].([]any)
		for _, a := range args {
			b, isBool := clEval(a, env).(bool)
			if !isBool {
				unknown = true
			} else if b == stop {
				return stop
			}
		}
		if unknown {
			return nil
		}
		return !stop
	case "eq", "neq", "lt", "lte", "gt", "gte":
		a, b := clEval(m["a"], env), clEval(m["b"], env)
		if a == nil || b == nil {
			return nil
		}
		if op == "eq" {
			return scalarEqV(a, b)
		}
		if op == "neq" {
			return !scalarEqV(a, b)
		}
		if !jsIsInt(a) || !jsIsInt(b) {
			return nil
		}
		fa, fb := jsF(a), jsF(b)
		switch op {
		case "lt":
			return fa < fb
		case "lte":
			return fa <= fb
		case "gt":
			return fa > fb
		}
		return fa >= fb
	}
	return nil
}

// DeriveInput is what a derive caveat reads.
type DeriveInput struct {
	Now float64
	// Action is {verb, resource, params} (nil: none).
	Action map[string]any
	// History is the verifier's own record of the holder's admitted actions ({t, verb, resource}); nil = none.
	History []any
	// Claims maps a caveat id to the claims of the discharge that VERIFIED in this evaluation: the only claim source.
	Claims map[string]map[string]any
}

// EvaluateDerive evaluates a well-formed derive caveat in Kleene three-valued logic. known is false for unknown; the check
// passes only when known && result (false and unknown both refuse).
func EvaluateDerive(c map[string]any, inp DeriveInput) (result bool, known bool) {
	defer func() {
		if recover() != nil {
			result, known = false, false
		}
	}()
	env := map[string]any{}
	defs, _ := c["defs"].([]any)
	for _, dv := range defs {
		d, _ := dv.(map[string]any)
		var v any
		switch d["kind"] {
		case "count":
			v = clCount(d, inp)
		case "param":
			p, _ := d["path"].(string)
			if r, found := resolveParamPath(inp.Action["params"], "action.params."+p); found && clScalar(r) {
				v = r
			}
		case "action":
			f, _ := d["field"].(string)
			if s := inp.Action[f]; boundedStr(s, 256) {
				v = s
			}
		case "claim":
			cid, _ := d["caveat_id"].(string)
			cl, _ := d["claim"].(string)
			if claims, has := inp.Claims[cid]; has {
				v = claims[cl]
			}
		case "expr":
			v = clEval(d["expr"], env)
		}
		name, _ := d["name"].(string)
		env[name] = v
	}
	b, isBool := clEval(c["check"], env).(bool)
	return b, isBool
}

// clCount counts the history events inside the window that match the def; nil (unknown) when the history is absent, too
// long or malformed.
func clCount(d map[string]any, inp DeriveInput) any {
	if inp.History == nil || len(inp.History) > DeriveMaxHistory {
		return nil
	}
	window := jsF(d["window_ms"])
	n := 0
	for _, ev := range inp.History {
		e, isObj := ev.(map[string]any)
		verb, vok := e["verb"].(string)
		res, rok := e["resource"].(string)
		if !isObj || !jsIsInt(e["t"]) || !vok || !rok {
			return nil
		}
		t := jsF(e["t"])
		if !(t > inp.Now-window && t <= inp.Now) {
			continue
		}
		if want, has := d["verb"]; has && verb != want {
			continue
		}
		if pre, has := d["resource_prefix"]; has && !strings.HasPrefix(res, pre.(string)) {
			continue
		}
		n++
	}
	return float64(n)
}

// ---- spiffe_bound --------------------------------------------------------------------------------------------------------

// SpiffeBoundError is "" when the caveat is well-formed (exactly one of spiffe_id and spiffe_prefix).
func SpiffeBoundError(c any) string {
	m, ok := c.(map[string]any)
	if !ok {
		return "caveat must be an object"
	}
	if e := closedMembersMsg(m, "spiffe_bound", []string{"type"}, "spiffe_id", "spiffe_prefix"); e != "" {
		return e
	}
	if m["type"] != CaveatSpiffeBound {
		return "not a spiffe_bound caveat"
	}
	id, hasID := m["spiffe_id"]
	pre, hasPre := m["spiffe_prefix"]
	if hasID == hasPre {
		return "exactly one of spiffe_id and spiffe_prefix"
	}
	if hasID {
		return SpiffeIDError(id)
	}
	return SpiffeIDError(pre)
}

// clSpiffeSatisfied: spiffe_id means the peer equals it; spiffe_prefix means the peer equals it or lies below it (prefix + "/").
func clSpiffeSatisfied(c map[string]any, peer string) bool {
	if SpiffeBoundError(c) != "" || SpiffeIDError(peer) != "" {
		return false
	}
	if id, has := c["spiffe_id"]; has {
		return peer == id
	}
	pre := c["spiffe_prefix"].(string)
	return peer == pre || strings.HasPrefix(peer, pre+"/")
}

// ---- the K1 evaluator ------------------------------------------------------------------------------------------------

// K1Input is the verifier-side input of the caveat language.
type K1Input struct {
	// Pins are the verifier's pins for discharge issuers (never taken from the request).
	Pins []DischargePin
	// Discharges are presented with the action.
	Discharges []any
	// Narrow is a narrow block presented with the action; HasNarrow says whether one was presented (a JSON null is presented).
	Narrow    any
	HasNarrow bool
	// ActionDigest is DischargeActionDigest of the PCActn being decided ("" = none).
	ActionDigest string
	// RevokedDischarges are the DischargeDigest values the verifier has revoked.
	RevokedDischarges []string
	// SpiffeID is the presenting workload's SPIFFE ID from an SVID the verifier verified (never from the request).
	SpiffeID string
	// History is the verifier's own record of this holder's admitted actions ({t, verb, resource}); nil = none.
	History []any
}

// K1Context is the per-decision context: the verifier clock and the action ({verb, resource, params}).
type K1Context struct {
	Now    float64
	Action map[string]any
}

// K1Result is the result of EvaluateK1.
type K1Result struct {
	OK bool
	// Failed holds the types of the unsatisfied caveats, in order ("<malformed>" for one without a string type).
	Failed []string
	// Reasons holds one reason per failure (same order).
	Reasons []string
	// Plain holds the verified narrow-block caveats that are NOT K1 types: the caller evaluates them with its stock evaluator.
	Plain []any
	// Bound holds the K1 caveats evaluated with their hops: hand them to ReserveMaxUses once everything allowed.
	Bound []BoundCaveat
}

// EvaluateK1 evaluates the K1 caveat types of the leaf hop (and of a verified narrow block); non-K1 caveats are left to the
// stock evaluators. needs_discharge, sealed (not checked), max_uses and derive ids must be unique per type over the chain and
// narrow block: a duplicate fails every caveat sharing it. max_uses is only checked for well-formedness and expiry here;
// ReserveMaxUses spends it. Total.
//
// k1p == nil (no K1 input at all) refuses EVERY K1 caveat, whatever its type, with "the caveat language is not configured (no
// k1 input)": a verifier that was never configured for the language must not let `sealed` or a constant derive pass. An empty
// but present &K1Input{} IS configured.
func EvaluateK1(grant, chain any, k1p *K1Input, ctx K1Context) (res K1Result) {
	failed := []string{}
	reasons := []string{}
	fail := func(c any, why string) {
		name := "<malformed>"
		if m, isObj := c.(map[string]any); isObj {
			if t, isStr := m["type"].(string); isStr {
				name = t
			}
		}
		failed = append(failed, name)
		reasons = append(reasons, why)
	}
	result := func(plain []any, bound []BoundCaveat) K1Result {
		return K1Result{OK: len(failed) == 0, Failed: failed, Reasons: reasons, Plain: plain, Bound: bound}
	}
	defer func() {
		if r := recover(); r != nil {
			fail(map[string]any{"type": "<malformed>"}, "caveat language error (fail closed): "+clPanicText(r))
			res = result([]any{}, []BoundCaveat{})
		}
	}()
	base, ok := BoundCaveats(grant, chain)
	if !ok || !clSafeF(ctx.Now) {
		why := "the verifier clock is not a safe integer (fail closed)"
		if !ok {
			why = "malformed capability chain"
		}
		fail(map[string]any{"type": "<malformed>"}, why)
		return result([]any{}, []BoundCaveat{})
	}
	if k1p == nil {
		mine := clK1Only(base)
		for _, b := range mine {
			fail(b.Caveat, "the caveat language is not configured (no k1 input)")
		}
		return result([]any{}, mine)
	}
	k1 := *k1p
	hops := clHops(normalizeJSON(grant), normalizeJSON(chain))
	leafIndex := len(hops) - 1
	now := ctx.Now
	action, _ := normalizeJSON(ctx.Action).(map[string]any)
	bound := base
	plain := []any{}
	if k1.HasNarrow {
		nv := VerifyNarrow(k1.Narrow, grant, chain, NarrowBinding{Now: now, ActionDigest: k1.ActionDigest})
		if !nv.OK {
			fail(map[string]any{"type": "narrow"}, nv.Reason)
			return result([]any{}, clK1Only(bound))
		}
		leafHash, err := CapHash(hops[leafIndex].(map[string]any))
		if err != nil {
			fail(map[string]any{"type": "narrow"}, "narrow error (fail closed): "+err.Error())
			return result([]any{}, clK1Only(bound))
		}
		bound = append([]BoundCaveat{}, bound...)
		for _, c := range nv.Caveats {
			bound = append(bound, BoundCaveat{Caveat: c, Hop: leafIndex, CapHash: leafHash})
			if !IsK1Caveat(c) {
				plain = append(plain, c)
			}
		}
	}
	k1Bound := clK1Only(bound)
	// ids are unique per type across the chain and narrow block
	seen := map[string]int{}
	for _, b := range k1Bound {
		cm := b.Caveat.(map[string]any)
		if id, isStr := cm["id"].(string); isStr {
			seen[cm["type"].(string)+"\x00"+id]++
		}
	}
	dup := func(cm map[string]any) bool { return seen[cm["type"].(string)+"\x00"+cm["id"].(string)] > 1 }
	claims := map[string]map[string]any{}
	// pass 1: discharges (derive reads their claims)
	for _, b := range k1Bound {
		cm := b.Caveat.(map[string]any)
		if cm["type"] != CaveatNeedsDischarge {
			continue
		}
		if bad := NeedsDischargeError(cm); bad != "" {
			fail(cm, bad)
			continue
		}
		if dup(cm) {
			fail(cm, "duplicate needs_discharge id '"+cm["id"].(string)+"'")
			continue
		}
		why := "no discharge presented"
		var okd *DischargeVerdict
		for _, dv := range k1.Discharges {
			dm, isObj := normalizeJSON(dv).(map[string]any)
			if !isObj || dm["caveat_id"] != cm["id"] {
				continue
			}
			v := VerifyDischarge(dm, cm, DischargeBinding{CapHash: b.CapHash, ActionDigest: k1.ActionDigest, Pins: k1.Pins, Now: now, Revoked: k1.RevokedDischarges})
			if v.OK {
				okd = &v
				break
			}
			why = v.Reason
		}
		if okd != nil {
			claims[cm["id"].(string)] = okd.Claims
		} else {
			fail(cm, why)
		}
	}
	// pass 2: everything else, in order
	for _, b := range k1Bound {
		cm := b.Caveat.(map[string]any)
		switch cm["type"] {
		case CaveatSealed:
			if e := closedMembersMsg(cm, "sealed", []string{"type"}); e != "" {
				fail(cm, e)
			} else if b.Hop != leafIndex {
				fail(cm, "a hop was appended below a sealed hop")
			}
		case CaveatMaxUses:
			if e := MaxUsesError(cm); e != "" {
				fail(cm, e)
			} else if dup(cm) {
				fail(cm, "duplicate max_uses id '"+cm["id"].(string)+"'")
			} else if now >= jsF(cm["until"]) {
				fail(cm, "max_uses '"+cm["id"].(string)+"' has expired")
			}
		case CaveatDerive:
			if e := DeriveError(cm); e != "" {
				fail(cm, e)
			} else if dup(cm) {
				fail(cm, "duplicate derive id '"+cm["id"].(string)+"'")
			} else if r, known := EvaluateDerive(cm, DeriveInput{Now: now, Action: action, History: k1.History, Claims: claims}); !known {
				fail(cm, "derive check is unknown (a fact is missing)")
			} else if !r {
				fail(cm, "derive check is false")
			}
		case CaveatSpiffeBound:
			if !clSpiffeSatisfied(cm, k1.SpiffeID) {
				fail(cm, "the presenting workload does not carry the required SPIFFE ID")
			}
		}
	}
	return result(plain, k1Bound)
}

func clK1Only(bound []BoundCaveat) []BoundCaveat {
	out := []BoundCaveat{}
	for _, b := range bound {
		if IsK1Caveat(b.Caveat) {
			out = append(out, b)
		}
	}
	return out
}

// EvaluateCaveatsK1 evaluates every caveat of PolicyCaveats(grant, chain): the K1 types by EvaluateK1, all the others (plus
// the verified narrow block's plain caveats) by EvaluateCaveats over context (the conformance-vector field names: now,
// delegation_depth, action{verb, resource, params}, ...). failed is the stock failures plus the K1 failures, sorted.
func EvaluateCaveatsK1(grant, chain any, k1 *K1Input, context map[string]any) (allow bool, failed []string) {
	now := 0.5 // not a safe integer: EvaluateK1 refuses when the context carries no clock
	if f, ok := jsNum(context["now"]); ok {
		now = f
	}
	action, _ := context["action"].(map[string]any)
	k := EvaluateK1(grant, chain, k1, K1Context{Now: now, Action: action})
	var stockFailed []string
	if list, isArr := PolicyCaveats(grant, chain).([]any); isArr {
		stock := make([]any, 0, len(list)+len(k.Plain))
		for _, c := range list {
			if !IsK1Caveat(c) {
				stock = append(stock, c)
			}
		}
		_, stockFailed = EvaluateCaveats(append(stock, k.Plain...), context)
	} else {
		_, stockFailed = EvaluateCaveats(PolicyCaveats(grant, chain), context)
	}
	failed = append(append([]string{}, stockFailed...), k.Failed...)
	clSortUTF16(failed)
	return len(failed) == 0, failed
}
