package pca

// Intent Layer v2 session revocation (rule 13 step 7; packages/pca/src/intent-revocation.ts over the sorted-Merkle
// revocation set and the signed epoch format of packages/pca/src/revocation.ts): the epoch is signed by a session
// principal (or the root's revocation.key; a PQ epoch only under the PQ key S pins), scoped to
// "pca-intent-session:<session>", fresh within the T22 bound, and proves NON-MEMBERSHIP of every id the action relies on.
// The epoch and every proof are strictly typed before any comparison (README "strict values"): no coercion.

import (
	"crypto/sha256"
	"math"
)

const (
	revEpochDomain     = "atlas-pca/revepoch/v1\x00"
	revSetRootPrefix   = "pca-revset/v1\x00"
	revocationSkewMs   = 60_000
	sessionScopePrefix = "pca-intent-session:"
)

func sessionRevocationID(session string) string { return "pca-intent:session:" + session }
func mapRevocationID(mapDigest string) string   { return "pca-intent:map:" + mapDigest }
func deltaRevocationID(grantID string) string   { return "pca-intent:delta:" + grantID }
func profileRevocationID(p string, version float64) string {
	return "pca-intent:profile:" + p + "@" + jsNumberString(version)
}
func sessionRevocationScope(session string) string { return sessionScopePrefix + session }

func isSafeNonNegV(v any) bool { return jsIsNonNeg(v) }

func revNodeHash(l, r []byte) []byte {
	b := append([]byte{0x01}, l...)
	b = append(b, r...)
	return sha(b)
}

func bindRevRoot(size float64, tree string) (string, bool) {
	if !(size == math.Trunc(size) && math.Abs(size) <= maxSafeInt) {
		return "", false
	}
	tail, ok := strictBytes(map[string]any{"size": jsNumber(size), "tree": tree})
	if !ok {
		return "", false
	}
	h := sha256.Sum256(append([]byte(revSetRootPrefix), tail...))
	return b64.EncodeToString(h[:]), true
}

func emptyRevTree() string {
	h := sha256.Sum256(nil)
	return b64.EncodeToString(h[:])
}

// revocationEpochShape: "" when the epoch is strictly typed (strings, non-negative safe integers, a string alg this
// verifier implements, string pq_pk / pq_sig when present), else the reason.
func revocationEpochShape(v any) string {
	ep, ok := v.(map[string]any)
	if !ok {
		return "the revocation epoch must be an object"
	}
	for _, k := range []string{"instance_id", "grant_ref", "root", "guardian", "sig"} {
		if _, ok := ep[k].(string); !ok {
			return "revocation epoch " + k + " must be a string"
		}
	}
	for _, k := range []string{"epoch", "set_size", "issued_at", "not_after"} {
		if !isSafeNonNegV(ep[k]) {
			return "revocation epoch " + k + " must be a non-negative safe integer"
		}
	}
	if g, has := ep["guardian_epoch"]; has && !isSafeNonNegV(g) {
		return "revocation epoch guardian_epoch must be a non-negative safe integer"
	}
	alg, algP := ep["alg"]
	if e := suiteCapability(alg, algP); e != "" {
		return "revocation epoch alg: " + e
	}
	for _, k := range []string{"pq_pk", "pq_sig"} {
		if x, has := ep[k]; has {
			if _, ok := x.(string); !ok {
				return "revocation epoch " + k + " must be a string"
			}
		}
	}
	return ""
}

// checkRevocationEpoch (revocation.ts) on a shape-checked epoch: signed by the pinned guardian (a PQ suite only under
// pins[guardian]), the session scope, now <= not_after, issued_at <= now + 60 s.
func checkRevocationEpoch(ep map[string]any, guardian string, now float64, grantRef string, pins map[string]string) string {
	if ep["guardian"] != guardian {
		return "revocation epoch not signed by the pinned guardian"
	}
	body := map[string]any{}
	for _, k := range []string{"instance_id", "grant_ref", "epoch", "set_size", "root", "issued_at", "not_after"} {
		body[k] = ep[k]
	}
	alg, algP := ep["alg"]
	pq, pqP := ep["pq_pk"]
	bound, ok := bindSuiteFields(body, alg, algP, pq, pqP)
	if !ok {
		return "revocation epoch signature invalid"
	}
	msg, ok := domainMessage(revEpochDomain, bound)
	if !ok || !verifyPinnedSuite(alg, algP, guardian, pq, msg, ep["sig"], ep["pq_sig"], pins) {
		return "revocation epoch signature invalid"
	}
	if ep["grant_ref"] != grantRef {
		return "revocation epoch is for a different grant"
	}
	if !(now <= jsF(ep["not_after"])) {
		return "revocation epoch expired (stale revocation root)"
	}
	if !(jsF(ep["issued_at"]) <= now+revocationSkewMs) {
		return "revocation epoch issued in the future"
	}
	return ""
}

// revsetRoot is the sorted-set root of a revoked list: base64url(SHA-256("pca-revset/v1\0" || canonical({size, tree})))
// with the RFC 6962 tree (leaf SHA-256(0x00 || canonical(id)), node SHA-256(0x01 || l || r)) over the list in order.
func revsetRoot(list []string) (string, bool) {
	tree := emptyRevTree()
	if len(list) > 0 {
		leaves := make([]any, len(list))
		for i, id := range list {
			leaves[i] = id
		}
		t, err := MerkleRoot(leaves)
		if err != nil {
			return "", false
		}
		tree = t
	}
	return bindRevRoot(float64(len(list)), tree)
}

// revokedList checks that the evidence's `revoked` is exactly the signed set (strings, strictly ascending in UTF-8
// byte order, length == set_size == epoch, revset root == root) and returns it.
func revokedList(ev map[string]any) ([]string, string) {
	r, ok := ev["revoked"].([]any)
	if !ok {
		return nil, "revoked must be an array of ids"
	}
	out := make([]string, len(r))
	for i, x := range r {
		s, ok := x.(string)
		if !ok {
			return nil, "revoked must be an array of ids"
		}
		out[i] = s
	}
	for i := 1; i < len(out); i++ {
		if !(compareUtf8(out[i-1], out[i]) < 0) {
			return nil, "revoked must be sorted by UTF-8 bytes and distinct"
		}
	}
	ep := ev["epoch"].(map[string]any)
	if float64(len(out)) != jsF(ep["set_size"]) || jsF(ep["epoch"]) != jsF(ep["set_size"]) {
		return nil, "the epoch must be numbered by its set size and list exactly set_size ids"
	}
	if root, ok := revsetRoot(out); !ok || root != ep["root"] {
		return nil, "the revoked list is not the signed set (root mismatch)"
	}
	return out, ""
}

// checkSessionRevocation is rule 13 step 7 (steps a-g): the epoch is signed by the dedicated authority (a PQ epoch only
// under pins[authority]), scoped to the session, fresh within maxAgeMs, carries its full revoked list, extends the
// tracked last epoch (no rollback, no drop, no equivocation) and revokes none of ids. "" when it holds.
func checkSessionRevocation(ev any, session any, authority any, ids any, now any, maxAgeMs any, last any, lastP bool, pins map[string]string) string {
	if !jsIsNonNeg(maxAgeMs) {
		return "revocation max age misconfigured (fail closed)"
	}
	if !jsIsInt(now) {
		return "the verifier clock is not a safe integer (fail closed)"
	}
	idList, ok := ids.([]any)
	auth, ok2 := authority.(string)
	if !ok || !ok2 {
		return "ids must be an array and the authority a key"
	}
	e, ok := ev.(map[string]any)
	if !ok {
		return "no session revocation epoch supplied"
	}
	if !closedMembers(e, []string{"epoch", "revoked"}) {
		return "the revocation evidence must be exactly {epoch, revoked}"
	}
	if r := revocationEpochShape(e["epoch"]); r != "" {
		return r
	}
	ep := e["epoch"].(map[string]any)
	if ep["guardian"] != auth {
		return "the revocation epoch is not signed by the session revocation authority"
	}
	sess, _ := session.(string)
	nowF := jsF(now)
	if r := checkRevocationEpoch(ep, auth, nowF, sessionRevocationScope(sess), pins); r != "" {
		return r
	}
	if !(nowF-jsF(ep["issued_at"]) <= jsF(maxAgeMs)) {
		return "the session revocation epoch is older than the maximum age"
	}
	revoked, why := revokedList(e)
	if why != "" {
		return why
	}
	if lastP {
		L, ok := last.(map[string]any)
		if !ok || !closedMembers(L, []string{"epoch", "revoked"}) || revocationEpochShape(L["epoch"]) != "" {
			return "the tracked last epoch is malformed (fail closed)"
		}
		lastList, why := revokedList(L)
		if why != "" {
			return "the tracked last epoch is malformed (fail closed)"
		}
		le := L["epoch"].(map[string]any)
		if jsF(ep["epoch"]) < jsF(le["epoch"]) {
			return "revocation epoch rollback (older than the last accepted)"
		}
		have := map[string]bool{}
		for _, id := range revoked {
			have[id] = true
		}
		for _, id := range lastList {
			if !have[id] {
				return "the epoch drops '" + id + "', revoked in the last accepted epoch (not append-only)"
			}
		}
		if jsF(ep["epoch"]) == jsF(le["epoch"]) && ep["root"] != le["root"] {
			return "two different revocation sets under one epoch number (equivocation)"
		}
	}
	set := map[string]bool{}
	for _, id := range revoked {
		set[id] = true
	}
	for _, x := range idList {
		id, ok := x.(string)
		if !ok || set[id] {
			return "an id the action relies on is revoked"
		}
	}
	return ""
}

// IntentRevocationPrimitive runs primitives.intent_revocation (rule 13 step 7 alone) on its `input`:
// {epoch, revoked, session, authority, ids, now, max_age_ms, last?: {epoch, revoked}} -> ok; any other input member is
// an evidence member (refused: the evidence is exactly {epoch, revoked}).
func IntentRevocationPrimitive(input any) bool {
	in, ok := normalizeJSON(input).(map[string]any)
	if !ok {
		return false
	}
	// the evidence is every input member except the check's own inputs (so an extra member reaches the closed check)
	ev := withoutKeys(in, "session", "authority", "ids", "now", "max_age_ms", "last")
	last, lastP := in["last"]
	return checkSessionRevocation(ev, in["session"], in["authority"], in["ids"], in["now"], in["max_age_ms"], last, lastP, nil) == ""
}
