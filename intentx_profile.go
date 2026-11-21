package pca

// Portable, revocable intent profiles: the principal's signed, versioned record of standing rules and prior answers,
// append-only succession, scoped use (deny wins, permit is explicit, negative observations veto). Signing is Ed25519; a
// suite-agile profile verifies under the verifier's pin.

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
)

const (
	ixProfileKind          = "pca-intent-profile"
	ixProfileSigDomain     = "atlas-pca/intent-profile/v1\x00"
	ixProfileRefDomain     = "atlas-pca/intent-profile-ref/v1"
	ixMaxProfileRules      = 256
	ixMaxProfileObsrvation = 2000
)

var (
	ixProfileKeys = []string{"v", "kind", "profile_id", "version", "owner", "scope", "standing", "prior", "expires_at", "revocation", "prev", "alg", "pq_pk", "sig", "pq_sig"}
	ixProfileIDRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)
)

func ixStrListOK(v any, mx int) bool {
	l, ok := v.([]any)
	if !ok || len(l) > mx {
		return false
	}
	for _, x := range l {
		if s, ok := x.(string); !ok || s == "" {
			return false
		}
	}
	return true
}

func ixPredOK(p any) bool {
	m, ok := p.(map[string]any)
	if !ok {
		return false
	}
	switch v := m["verb"].(type) {
	case string:
		return true
	case []any:
		for _, x := range v {
			if !ixIsStr(x) {
				return false
			}
		}
		return true
	}
	return false
}

func ixSortedKeyList(o map[string]any) string { return strings.Join(ixKeysSorted(o), ",") }

func ixIsB32(x any) bool {
	s, ok := x.(string)
	if !ok {
		return false
	}
	_, ok = DecodeB64uStrict(s, 32)
	return ok
}

func ixProfileBody(p map[string]any) map[string]any {
	b := map[string]any{}
	for _, k := range []string{"v", "kind", "profile_id", "version", "owner", "scope", "standing", "prior", "expires_at", "revocation", "prev"} {
		if v, ok := p[k]; ok {
			b[k] = v
		}
	}
	return b
}

func ixProfileMessage(body map[string]any) ([]byte, bool) {
	b, ok := ixStrictCanon(body)
	if !ok {
		return nil, false
	}
	return append([]byte(ixProfileSigDomain), b...), true
}

// ixProfileShapeError is "" when the profile is well-formed (closed, strictly typed); else the first problem.
func ixProfileShapeError(pv any, signed bool) (msg string) {
	defer func() {
		if r := recover(); r != nil {
			msg = fmt.Sprintf("malformed profile: %v", r)
		}
	}()
	p, ok := pv.(map[string]any)
	if !ok {
		return "profile is not an object"
	}
	for _, k := range ixKeysSorted(p) {
		if ixIndexOf(ixProfileKeys, k) < 0 {
			return "profile: unknown member '" + k + "'"
		}
	}
	if !jsStrictEq(p["v"], 1.0) || p["kind"] != ixProfileKind {
		return "not a pca-intent-profile v1"
	}
	if pid, ok := p["profile_id"].(string); !ok || !ixProfileIDRe.MatchString(pid) {
		return "profile_id must match [A-Za-z0-9_.-]{1,128}"
	}
	ver, _ := jsNum(p["version"])
	if !jsIsSafeInteger(p["version"]) || ver < 1 {
		return "version must be a safe integer >= 1"
	}
	if !ixIsB32(p["owner"]) {
		return "owner must be canonical base64url (32 bytes)"
	}
	scope, ok := p["scope"].(map[string]any)
	if ok {
		for k := range scope {
			if k != "sites" && k != "verbs" && k != "semantic_types" {
				ok = false
			}
		}
	}
	if !ok {
		return "scope must be {sites?, verbs?, semantic_types?}"
	}
	for _, k := range []string{"sites", "verbs", "semantic_types"} {
		if v, has := scope[k]; has && !ixStrListOK(v, 256) {
			return "scope." + k + " must be a list of strings"
		}
	}
	standing, ok := p["standing"].(map[string]any)
	if !ok || ixSortedKeyList(standing) != "deny,permit" {
		return "standing must be {deny, permit}"
	}
	for _, k := range []string{"deny", "permit"} {
		r, ok := standing[k].([]any)
		good := ok && len(r) <= ixMaxProfileRules
		for _, x := range r {
			if !ixPredOK(x) {
				good = false
			}
		}
		if !good {
			return fmt.Sprintf("standing.%s must be at most %d predicates", k, ixMaxProfileRules)
		}
	}
	prior, ok := p["prior"].(map[string]any)
	if !ok || ixSortedKeyList(prior) != "maps,observations" {
		return "prior must be {observations, maps}"
	}
	obs, ok := prior["observations"].([]any)
	if !ok || len(obs) > ixMaxProfileObsrvation {
		return fmt.Sprintf("prior.observations must be at most %d", ixMaxProfileObsrvation)
	}
	for _, ov := range obs {
		o, ok := ov.(map[string]any)
		if !ok || ixSortedKeyList(o) != "at,values,verb,y" || !ixIsStr(o["verb"]) || !ixIsObj(o["values"]) ||
			!(jsStrictEq(o["y"], 0.0) || jsStrictEq(o["y"], 1.0)) || !jsIsSafeInteger(o["at"]) || ixF(o["at"]) < 0 {
			return "prior.observations entries are {verb, values, y, at}"
		}
	}
	maps, ok := prior["maps"].([]any)
	good := ok
	for _, m := range maps {
		if !ixIsB32(m) {
			good = false
		}
	}
	if !good {
		return "prior.maps must be 32-byte digests"
	}
	if ea, _ := jsNum(p["expires_at"]); !jsIsSafeInteger(p["expires_at"]) || ea < 0 {
		return "expires_at must be a non-negative safe integer"
	}
	rev, ok := p["revocation"].(map[string]any)
	if ok {
		for k := range rev {
			if k != "epoch_uri" && k != "key" {
				ok = false
			}
		}
		if uri, isS := rev["epoch_uri"].(string); !isS || uri == "" {
			ok = false
		}
	}
	if !ok {
		return "revocation must be {epoch_uri, key?}"
	}
	if k, has := rev["key"]; has && !ixIsB32(k) {
		return "revocation.key (the revocation authority; absent = the owner) must be canonical base64url (32 bytes)"
	}
	prev, hasPrev := p["prev"]
	if jsStrictEq(p["version"], 1.0) == hasPrev {
		return "prev is required exactly when version > 1"
	}
	if hasPrev && !ixIsB32(prev) {
		return "prev must be canonical base64url (32 bytes)"
	}
	if signed {
		alg, algP := p["alg"]
		if algP && !ixIsStr(alg) {
			return "alg must be a string"
		}
		if se := suiteCapability(alg, algP); se != "" {
			return "alg: " + se
		}
		_, hasPk := p["pq_pk"]
		_, hasPs := p["pq_sig"]
		if (!algP || alg == "ed25519") && (hasPk || hasPs) {
			return "an ed25519 profile must not carry pq_pk / pq_sig"
		}
		if !ixIsStr(p["sig"]) {
			return "sig must be a string"
		}
	}
	if _, ok := ixStrictCanon(ixProfileBody(p)); !ok {
		return "malformed profile: the profile is not canonicalizable"
	}
	return ""
}

func ixSignIntentProfile(body map[string]any, seedB64 string) map[string]any {
	seed, ok := DecodeB64uStrict(seedB64, 32)
	if !ok {
		ixFail("secret key must be a 32-byte seed")
	}
	priv := ed25519.NewKeyFromSeed(seed)
	owner := base64.RawURLEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
	if o, has := body["owner"]; has && o != owner {
		ixFail("signIntentProfile: owner does not match the signing key")
	}
	withOwner := ixCopyMap(body)
	withOwner["owner"] = owner
	b := ixProfileBody(withOwner)
	if bad := ixProfileShapeError(b, false); bad != "" {
		ixFail("signIntentProfile: %s", bad)
	}
	msg, ok := ixProfileMessage(b)
	if !ok {
		ixFail("profile is not canonicalizable")
	}
	out := ixCopyMap(b)
	out["sig"] = base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, msg))
	return out
}

func ixPqPins(pin any) map[string]string {
	pm, ok := ixM(pin)["pqPins"].(map[string]any)
	if !ok {
		return nil
	}
	out := map[string]string{}
	for k, v := range pm {
		out[k], _ = v.(string)
	}
	return out
}

func ixVerifyIntentProfile(pv, pin any) map[string]any {
	fail := func(r string) map[string]any { return map[string]any{"ok": false, "reason": r} }
	if bad := ixProfileShapeError(pv, true); bad != "" {
		return fail(bad)
	}
	p := pv.(map[string]any)
	alg, algP := p["alg"]
	pk, pkP := p["pq_pk"]
	body, ok := bindSuiteFields(ixProfileBody(p), alg, algP, pk, pkP)
	if !ok {
		return fail("malformed profile: canonicalize: unsupported type undefined")
	}
	msg, ok := ixProfileMessage(body)
	if !ok {
		return fail("malformed profile: the profile is not canonicalizable")
	}
	if !verifyPinnedSuite(alg, algP, ixS(p["owner"]), pk, msg, p["sig"], p["pq_sig"], ixPqPins(pin)) {
		return fail("profile signature invalid")
	}
	return map[string]any{"ok": true}
}

func ixIntentProfileDigest(p map[string]any) string {
	return ixHashCanon(map[string]any{"d": ixProfileRefDomain, "p": p})
}

func ixVerifyProfileSuccession(prevV, nextV any) map[string]any {
	for _, x := range []struct {
		p any
		n string
	}{{prevV, "previous"}, {nextV, "next"}} {
		if v := ixVerifyIntentProfile(x.p, nil); v["ok"] != true {
			return map[string]any{"ok": false, "reason": x.n + " version: " + ixS(v["reason"])}
		}
	}
	prev, next := prevV.(map[string]any), nextV.(map[string]any) // both verified as objects
	if next["profile_id"] != prev["profile_id"] || next["owner"] != prev["owner"] {
		return map[string]any{"ok": false, "reason": "a profile version cannot change its id or owner"}
	}
	if ixF(next["version"]) != ixF(prev["version"])+1 {
		return map[string]any{"ok": false, "reason": "versions are append-only: next.version must be previous + 1"}
	}
	if next["prev"] != ixIntentProfileDigest(prev) {
		return map[string]any{"ok": false, "reason": "next.prev is not the digest of the previous version"}
	}
	return map[string]any{"ok": true}
}

func ixProfileApplies(p, u map[string]any) bool {
	now, ok1 := u["now"].(float64)
	exp, ok2 := p["expires_at"].(float64)
	if !(ok1 && ok2 && finite(now) && finite(exp) && now < exp) {
		return false
	}
	scope := ixM(ixReq(p, "scope"))
	present := func(k string) ([]any, bool) {
		v, ok := scope[k]
		if !ok || v == nil {
			return nil, false
		}
		l, isL := v.([]any)
		if !isL {
			ixFail("scope.%s is not iterable", k)
		}
		return l, true
	}
	anyEq := func(l []any, v any) bool {
		for _, x := range l {
			if jsStrictEq(x, v) {
				return true
			}
		}
		return false
	}
	if sites, ok := present("sites"); ok && !anyEq(sites, u["aud"]) {
		return false
	}
	if verbs, ok := present("verbs"); ok && !anyEq(verbs, u["verb"]) {
		return false
	}
	if sem, ok := present("semantic_types"); ok {
		found := false
		for _, s := range ixL(u["semantics"]) {
			if anyEq(sem, s) {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func ixStandingMatch(p map[string]any, which string, action any) bool {
	ctx, _ := action.(map[string]any)
	for _, r := range ixL(ixM(ixReq(p, "standing"))[which]) {
		if predicateMatches(r, ctx, &regexBudget{}) {
			return true
		}
	}
	return false
}

// ixStandingAdmits is G^std membership: an in-scope action is outside the standing layer iff a deny rule matches it (deny wins).
func ixStandingAdmits(p, u map[string]any, action any) bool {
	if !ixProfileApplies(p, u) {
		return true
	}
	return !ixStandingMatch(p, "deny", action)
}

// ixStandingPermits is the explicit standing-permission layer: an in-scope permit rule matches (the only positive import).
func ixStandingPermits(p, u map[string]any, action any) bool {
	return ixProfileApplies(p, u) && ixStandingMatch(p, "permit", action)
}

// ixProfileVetoCells are the cells that the profile's negative observations veto.
func ixProfileVetoCells(p, omega map[string]any) []any {
	out := []any{}
	seen := map[string]bool{}
	for _, ov := range ixL(ixM(ixReq(p, "prior"))["observations"]) {
		o := ixM(ov)
		if !jsStrictEq(o["y"], 0.0) { // only a refused outcome (y = 0) is vetoed
			continue
		}
		vs := ixFindVerb(omega, o["verb"])
		if vs == nil {
			continue
		}
		cell := ixCellOf(vs, map[string]any{"verb": o["verb"], "values": o["values"]})
		if cell == nil {
			continue
		}
		k := ixS(o["verb"]) + "|" + ixCellKeyJoin(cell)
		if !seen[k] {
			seen[k] = true
			out = append(out, map[string]any{"verb": o["verb"], "cell": cell})
		}
	}
	return out
}

// ixProfileCeiling is a ceiling function (for a visit decision) from the profile's standing deny rules over outcomes.
func ixProfileCeiling(p, u, vs, o map[string]any) bool {
	a := ixOutcomeToAction(vs, o)
	ctx := map[string]any{"action": map[string]any{"verb": a["verb"], "resource": a["resource"], "params": a["params"]}}
	if a["env"] != nil {
		ctx["env"] = a["env"]
	}
	if a["subject"] != nil {
		ctx["subject"] = a["subject"]
	}
	uu := ixCopyMap(u)
	uu["verb"] = o["verb"]
	return ixStandingAdmits(p, uu, ctx)
}
