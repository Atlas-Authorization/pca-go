package pca

// Action-kit registry layer (native port): signed evolution records, principal re-approvals, the grant pin decision, signed packs
// (with shards), the rollback tracker and rule 22 over a whole v2 document. Natives verify signatures, digests and pins; they do
// NOT recompute the semantic diff (the tracker checks chain, version and signatures only). Pure and total: malformed input is a
// refusal. The shared vectors pin every output.

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

const (
	actionPackKind      = "pca-action-pack"
	evolutionRecordKind = "pca-evolution-record"
	reapprovalKind      = "pca-reapproval"
	evolutionDomain     = "atlas-pca/action-evolution/v1\x00"
	evolutionDiffDomain = "atlas-pca/action-evolution-diff/v1"
	reapprovalDomain    = "atlas-pca/action-reapproval/v1\x00"
	packSigDomain       = "atlas-pca/action-pack/v1\x00"
	packRefDomain       = "atlas-pca/action-pack-ref/v1"
	packShardDomain     = "atlas-pca/action-pack-shard/v1"
	rulesDigestDomain   = "atlas-pca/action-rules/v1"
	packShardKind       = "pca-action-pack-shard"
	maxEvolutionSteps   = 32
	maxEvolutionRecords = 65536
)

var (
	evolutionClasses = []string{"equal", "narrow", "widen", "incomparable", "added", "removed"}
	stabilities      = []string{"draft", "beta", "stable"}
	reB64u43         = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	reNS             = regexp.MustCompile(`^[a-z0-9_]+(?:\.[a-z0-9_]+){0,5}$`)
	reRegVerb        = regexp.MustCompile(`^[a-z0-9_]+(?:\.[a-z0-9_]+){1,5}$`)
	reSemver3        = regexp.MustCompile(`^(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})$`)
	reShardName      = regexp.MustCompile(`^[a-z0-9_]+(?:[.-][a-z0-9_]+){0,7}$`)
)

func isSha(v any) bool { s, ok := v.(string); return ok && reB64u43.MatchString(s) }

const maxEscTier = 3

func isTier(v any) bool {
	if !jsIsInt(v) { // strict profile: -0 is never a tier
		return false
	}
	f := jsF(v)
	return f >= 0 && f <= maxEscTier
}

func closedErr(o map[string]any, allowed []string) string {
	for _, k := range sortedKeysStd(o) {
		if !contains(allowed, k) {
			return "unknown member '" + k + "'"
		}
	}
	return ""
}

// failClosed is a deferred call (the reference's try/catch around a total function): a panic becomes *res = onPanic(r).
func failClosed[T any](res *T, onPanic func(any) T) {
	if r := recover(); r != nil {
		*res = onPanic(r)
	}
}

// registryFault is a test seam (nil in production): it runs inside the failClosed recover scopes of this file (verifyRegistrySig
// "sig", reapprovalValid "reapproval", decidePin "pin", packShapeError "pack"), which no input is known to reach, so a test can pin
// that a panic becomes the refusal.
var registryFault func(scope string)

// panicFalse is failClosed's refusal for a predicate.
func panicFalse(any) bool { return false }

func u16Less(a, b string) bool {
	x, y := utf16Units(a), utf16Units(b)
	for i := 0; i < len(x) && i < len(y); i++ {
		if x[i] != y[i] {
			return x[i] < y[i]
		}
	}
	return len(x) < len(y)
}

// ---- evolution records --------------------------------------------------------------------------------------------------

func evolutionRecordError(xv any, signed bool) string {
	x, ok := isObj(xv)
	if !ok {
		return "evolution record must be an object"
	}
	allowed := []string{"v", "kind", "ns", "verb", "from", "to", "class", "reasons"}
	if signed {
		allowed = append(allowed, "sig")
	}
	if u := closedErr(x, allowed); u != "" {
		return "evolution record: " + u
	}
	if !jsStrictEq(x["v"], jsNumber(1)) || x["kind"] != evolutionRecordKind {
		return "evolution record: bad v/kind"
	}
	if s, ok := x["ns"].(string); !ok || !reNS.MatchString(s) {
		return "evolution record: bad ns"
	}
	if s, ok := x["verb"].(string); !ok || !reRegVerb.MatchString(s) {
		return "evolution record: bad verb"
	}
	// an endpoint must be present: null or a digest (absent is not null)
	if f, has := x["from"]; !has || (f != nil && !isSha(f)) {
		return "evolution record: bad from"
	}
	if t, has := x["to"]; !has || (t != nil && !isSha(t)) {
		return "evolution record: bad to"
	}
	c, ok := x["class"].(string)
	if !ok || !contains(evolutionClasses, c) {
		return "evolution record: bad class"
	}
	if (c == "added") != (x["from"] == nil) || (c == "removed") != (x["to"] == nil) {
		return "evolution record: endpoints do not match the class"
	}
	r, ok := x["reasons"].([]any)
	if !ok || len(r) > 64 {
		return "evolution record: bad reasons"
	}
	for _, e := range r {
		if s, ok := e.(string); !ok || utf16Len(s) > 512 {
			return "evolution record: bad reasons"
		}
	}
	if signed {
		s, ok := x["sig"].(map[string]any)
		if !ok || closedErr(s, []string{"alg", "kid", "value", "pq_value"}) != "" {
			return "evolution record: bad sig"
		}
		kid, kok := s["kid"].(string)
		_, vok := s["value"].(string)
		_, aok := s["alg"].(string)
		if !kok || utf16Len(kid) == 0 || utf16Len(kid) > 128 || !vok || !aok {
			return "evolution record: bad sig"
		}
		if pv, has := s["pq_value"]; has {
			if _, isS := pv.(string); !isS {
				return "evolution record: bad sig"
			}
		}
	}
	if _, err := canonBytes(withoutKeys(x, "sig")); err != nil {
		return "evolution record: " + err.Error()
	}
	return ""
}

// evolutionDiffDigest is the digest of ONE record's diff; ok is false when a member is absent or out of profile.
func evolutionDiffDigest(r map[string]any) (string, bool) {
	for _, k := range []string{"ns", "verb", "from", "to", "class", "reasons"} {
		if _, has := r[k]; !has {
			return "", false
		}
	}
	d, err := HashCanonical(map[string]any{"d": evolutionDiffDomain, "ns": r["ns"], "verb": r["verb"], "from": r["from"], "to": r["to"], "class": r["class"], "reasons": r["reasons"]})
	return d, err == nil
}

// verifyRegistrySig verifies a registry-signed body under domain against the pinned registry keys (suite from the KEY entry). "" = ok.
func verifyRegistrySig(domain string, body any, sig map[string]any, keysV any) (res string) {
	defer failClosed(&res, func(r any) string { return fmt.Sprint("verification error: ", r) })
	if registryFault != nil {
		registryFault("sig")
	}
	keys, ok := keysV.([]any)
	if !ok {
		return "the registry keys must be an array"
	}
	var key map[string]any
	for _, k := range keys {
		if m, ok := k.(map[string]any); ok && m["kid"] != nil && jsStrictEq(m["kid"], sig["kid"]) { // a missing kid matches nothing
			key = m
			break
		}
	}
	if key == nil {
		return "no registry key with kid '" + jsMemberString(sig, "kid") + "'" // an absent kid prints 'undefined'
	}
	pq, pqP := key["pq_pk"]
	if pqP {
		if _, isS := pq.(string); !isS {
			return "the registry key pq_pk must be a string"
		}
	}
	pk, ok := key["pk"].(string)
	if !ok || !b64uOK(pk, b32) {
		return "registry key pk is not canonical base64url (32 bytes)"
	}
	ka, kaP := key["alg"]
	kn := suiteAlgName(ka, kaP)
	sa, saP := sig["alg"]
	if kn == "" || kn != suiteAlgName(sa, saP) {
		return "sig.alg does not match the pinned key suite"
	}
	cb, err := canonBytes(body)
	if err != nil {
		return "verification error: " + err.Error()
	}
	msg := append([]byte(domain), cb...)
	pv := sig["pq_value"]
	if !verifyPinnedSuite(kn, true, pk, pq, msg, sig["value"], pv, pinOf(pk, pq, pqP)) {
		return "signature invalid"
	}
	return ""
}

// verifyEvolutionRecord: shape and signature against the pinned registry keys. "" = ok.
func verifyEvolutionRecord(rec any, keys any) string {
	if bad := evolutionRecordError(rec, true); bad != "" {
		return bad
	}
	r := rec.(map[string]any)
	return verifyRegistrySig(evolutionDomain, withoutKeys(r, "sig"), r["sig"].(map[string]any), keys)
}

func reapprovalValid(rv any, grantID, issuer, verb, diff any) (res bool) {
	defer failClosed(&res, panicFalse)
	if registryFault != nil {
		registryFault("reapproval")
	}
	r, ok := isObj(rv)
	if !ok || closedErr(r, []string{"v", "kind", "grant", "verb", "diff", "sig"}) != "" {
		return false
	}
	if !jsStrictEq(r["v"], jsNumber(1)) || r["kind"] != reapprovalKind || !jsStrictEq(r["grant"], grantID) || !jsStrictEq(r["verb"], verb) || !jsStrictEq(r["diff"], diff) {
		return false
	}
	s, ok := r["sig"].(map[string]any)
	if !ok || closedErr(s, []string{"alg", "value"}) != "" || s["alg"] != "ed25519" {
		return false
	}
	if _, isS := s["value"].(string); !isS {
		return false
	}
	is, ok := issuer.(string)
	if !ok {
		return false
	}
	msg, ok := domainMessage(reapprovalDomain, withoutKeys(r, "sig"))
	if !ok {
		return false
	}
	return verifyPinnedSuite("ed25519", true, is, nil, msg, s["value"], nil, nil)
}

// ---- the pin --------------------------------------------------------------------------------------------------------------

func actionPinError(xv any) string {
	x, ok := isObj(xv)
	if !ok {
		return "actions must be an object"
	}
	if u := closedErr(x, []string{"pack", "defs", "on_new_action", "max_esc", "preauth_esc", "caveats"}); u != "" {
		return "actions: " + u
	}
	p, ok := x["pack"].(map[string]any)
	if !ok || closedErr(p, []string{"ns", "root"}) != "" {
		return "actions.pack must be {ns, root}"
	}
	if s, ok := p["ns"].(string); !ok || !reNS.MatchString(s) {
		return "actions.pack.ns is not a namespace"
	}
	if !isSha(p["root"]) {
		return "actions.pack.root must be a base64url digest"
	}
	if s, ok := x["on_new_action"].(string); !ok || (s != "deny" && s != "escalate") {
		return "actions.on_new_action must be 'deny' or 'escalate'"
	}
	if v, has := x["max_esc"]; has && !isTier(v) {
		return "actions.max_esc must be an integer tier 0..3"
	}
	if v, has := x["preauth_esc"]; has && !isTier(v) {
		return "actions.preauth_esc must be an integer tier 0..3"
	}
	if isTier(x["max_esc"]) && isTier(x["preauth_esc"]) && jsF(x["preauth_esc"]) > jsF(x["max_esc"]) {
		return "actions.preauth_esc exceeds actions.max_esc"
	}
	if cv, has := x["caveats"]; has {
		c, ok := cv.([]any)
		bad := !ok
		seen := map[string]bool{}
		for _, k := range c {
			s, isS := k.(string)
			if !isS || !contains(caveatKinds, s) || seen[s] {
				bad = true
				break
			}
			seen[s] = true
		}
		if bad {
			return "actions.caveats must be distinct caveat kinds"
		}
	}
	if dv, has := x["defs"]; has {
		d, ok := dv.(map[string]any)
		if !ok {
			return "actions.defs must be an object"
		}
		for _, verb := range sortedKeysStd(d) {
			if !reRegVerb.MatchString(verb) {
				return "actions.defs: '" + verb + "' is not a verb"
			}
			if !isSha(d[verb]) {
				return "actions.defs." + verb + " must be a base64url digest"
			}
		}
	}
	return ""
}

func pinDeny(code, reason string, escalate bool, needs string) map[string]any {
	o := map[string]any{"ok": false, "code": code, "escalate": escalate, "reason": reason}
	if needs != "" {
		o["needs_reapproval"] = needs
	}
	return o
}

type pinEdge struct {
	to      string
	blocked string // "" = usable
}

// decidePin decides the pin for one verb: exact digest, pack root, or a chain of verified equal/narrow (or principal-approved) steps.
func decidePin(in map[string]any) (res map[string]any) {
	defer failClosed(&res, func(r any) map[string]any {
		return pinDeny("bad_pin", fmt.Sprint("pin evaluation error (fail closed): ", r), false, "")
	})
	if registryFault != nil {
		registryFault("pin")
	}
	if pe := actionPinError(in["pin"]); pe != "" {
		return pinDeny("bad_pin", pe, false, "")
	}
	pin := in["pin"].(map[string]any)
	pinPack := pin["pack"].(map[string]any)
	verb, _ := in["verb"].(string)
	doc, _ := isObj(in["doc"])
	var v map[string]any
	if verbs, ok := doc["verbs"].([]any); ok {
		for _, e := range verbs {
			if m, ok := e.(map[string]any); ok && jsStrictEq(m["verb"], verb) {
				v = m
				break
			}
		}
	}
	if v == nil {
		return pinDeny("unknown_verb", "the accepted schema does not declare '"+verb+"'", false, "")
	}
	pk, ok := doc["pack"].(map[string]any)
	if !ok || !jsStrictEq(pk["ns"], pinPack["ns"]) {
		return pinDeny("pack_mismatch", fmt.Sprint("the schema does not come from the pinned pack '", pinPack["ns"], "'"), false, "")
	}
	defs, hasDefs := pin["defs"].(map[string]any)
	if !hasDefs {
		if jsStrictEq(pk["root"], pinPack["root"]) {
			return map[string]any{"ok": true, "via": "pack"}
		}
		return pinDeny("pack_mismatch", "the pack root differs from the pinned root (the grant pins the pack as a whole)", false, "")
	}
	pinnedV, named := defs[verb]
	if !named {
		return pinDeny("new_action", fmt.Sprint("the grant does not name '", verb, "' (on_new_action: ", pin["on_new_action"], ")"), pin["on_new_action"] == "escalate", "")
	}
	pinned := pinnedV.(string)
	presented, isS := v["def"].(string)
	if !isS {
		return pinDeny("def_changed", "the schema verb carries no definition digest", false, "")
	}
	if presented == pinned {
		return map[string]any{"ok": true, "via": "exact"}
	}
	grant, _ := isObj(in["grant"])
	// inputs the reference cannot evaluate (its `for of` / `.some` / `i.grant.id` throw) refuse the pin, fail closed
	evalErr := func(what string) map[string]any {
		return pinDeny("bad_pin", "pin evaluation error (fail closed): "+what, false, "")
	}
	var recs []any
	switch rv := in["records"].(type) {
	case nil, string: // absent / null: none; a string iterates as characters, none of which verifies
	case []any:
		recs = rv
	default:
		return evalErr("records is not a list")
	}
	apprs, apprsOK := in["reapprovals"].([]any)
	if in["reapprovals"] == nil {
		apprsOK = true
	}
	edges := map[string][]pinEdge{}
	for _, rv := range recs {
		if verifyEvolutionRecord(rv, in["keys"]) != "" {
			continue
		}
		r := rv.(map[string]any)
		if !jsStrictEq(r["ns"], pinPack["ns"]) || r["verb"] != verb || r["from"] == nil || r["to"] == nil {
			continue
		}
		diff, _ := evolutionDiffDigest(r)
		approved := r["class"] == "equal" || r["class"] == "narrow"
		if !approved && !apprsOK {
			return evalErr("reapprovals is not a list")
		}
		if !approved && len(apprs) > 0 && in["grant"] == nil {
			return evalErr("no grant to check the re-approvals against")
		}
		for _, a := range apprs {
			if approved {
				break
			}
			approved = reapprovalValid(a, grant["id"], grant["issuer"], verb, diff)
		}
		e := pinEdge{to: r["to"].(string)}
		if !approved {
			e.blocked = diff
		}
		from := r["from"].(string)
		edges[from] = append(edges[from], e)
	}
	type par struct{ from, blocked string }
	search := func(usableOnly bool) map[string]par {
		parent := map[string]par{}
		seen := map[string]bool{pinned: true}
		frontier := []string{pinned}
		for step := 0; step < maxEvolutionSteps && len(frontier) > 0; step++ {
			if _, done := parent[presented]; done {
				break
			}
			var next []string
			for _, f := range frontier {
				for _, e := range edges[f] {
					if seen[e.to] || (usableOnly && e.blocked != "") {
						continue
					}
					seen[e.to] = true
					parent[e.to] = par{f, e.blocked}
					next = append(next, e.to)
				}
			}
			frontier = next
		}
		return parent
	}
	if _, ok := search(true)[presented]; ok {
		return map[string]any{"ok": true, "via": "chain"}
	}
	all := search(false)
	if _, ok := all[presented]; ok {
		first := ""
		for cur := presented; cur != pinned; {
			p := all[cur]
			if p.blocked != "" {
				first = p.blocked
			}
			cur = p.from
		}
		return pinDeny("def_changed", "the definition widened (or changed incomparably) since the grant pinned it: the principal must re-approve", false, first)
	}
	return pinDeny("def_changed", "the definition differs from the pinned digest and no signed evolution record chains to it", false, "")
}

// ---- signed packs ---------------------------------------------------------------------------------------------------------

func compareVersions(a, b string) (int, error) {
	pa, pb := reSemver3.FindStringSubmatch(a), reSemver3.FindStringSubmatch(b)
	if pa == nil || pb == nil {
		bad := a
		if pa != nil {
			bad = b
		}
		return 0, fmt.Errorf("bad_version: '%s' is not MAJOR.MINOR.PATCH", bad)
	}
	for i := 1; i <= 3; i++ {
		var x, y int
		fmt.Sscan(pa[i], &x)
		fmt.Sscan(pb[i], &y)
		if x != y {
			return x - y, nil
		}
	}
	return 0, nil
}

func rulesDigest() (string, error) {
	return HashCanonical(map[string]any{"d": rulesDigestDomain, "prules": anyStrs(paramRuleIDs), "caveats": anyStrs(caveatKinds), "context": anyStrs(contextKeys)})
}

func packDigest(p map[string]any) (string, error) {
	return HashCanonical(map[string]any{"d": packRefDomain, "p": p})
}

func shardDigest(s any) (string, error) {
	return HashCanonical(map[string]any{"d": packShardDomain, "s": s})
}

func sortedUniqueDefsError(defs []any) string {
	for i, d := range defs {
		if e := validateDef(d); e != "" {
			return fmt.Sprintf("def %d: %s", i, e)
		}
		if i > 0 {
			prev := defs[i-1].(map[string]any)["verb"].(string)
			cur := d.(map[string]any)["verb"].(string)
			if !u16Less(prev, cur) {
				return "defs must be sorted by verb and unique (at '" + cur + "')"
			}
		}
	}
	return ""
}

func packShapeError(xv any, signed bool) (res string) {
	defer failClosed(&res, func(r any) string { return fmt.Sprint("pack: ", r) })
	if registryFault != nil {
		registryFault("pack")
	}
	x, ok := isObj(xv)
	if !ok {
		return "pack must be an object"
	}
	allowed := []string{"v", "kind", "ns", "version", "stability", "traits_digest", "roles_digest", "rules_digest", "root", "defs", "source", "prev", "evolution"}
	if signed {
		allowed = append(allowed, "sig")
	}
	if e := closedErr(x, allowed); e != "" {
		return "pack: " + e
	}
	if !jsStrictEq(x["v"], jsNumber(1)) || x["kind"] != actionPackKind {
		return "pack: bad v/kind"
	}
	if s, ok := x["ns"].(string); !ok || !reNS.MatchString(s) {
		return "pack: bad ns"
	}
	if s, ok := x["version"].(string); !ok || !reSemver3.MatchString(s) {
		return "pack: version must be MAJOR.MINOR.PATCH"
	}
	if s, ok := x["stability"].(string); !ok || !contains(stabilities, s) {
		return "pack: bad stability"
	}
	for _, k := range []string{"traits_digest", "roles_digest", "rules_digest", "root"} {
		if !isSha(x[k]) {
			return "pack: " + k + " must be a base64url digest"
		}
	}
	if pv, has := x["prev"]; !has || (pv != nil && !isSha(pv)) { // absent is not null
		return "pack: bad prev"
	}
	s, ok := x["source"].(map[string]any)
	sk := []string{"kind", "uri", "spec_digest", "licence", "licence_notes"}
	if !ok || closedErr(s, sk) != "" {
		return "pack: source must be {kind, uri, spec_digest, licence, licence_notes}"
	}
	for _, k := range sk {
		v, isS := s[k].(string)
		if !isS || (k != "licence_notes" && len(v) == 0) || utf16Len(v) > 2048 {
			return "pack: source." + k + " is not a string of 1..2048 characters"
		}
	}
	if d, isL := x["defs"].([]any); isL {
		if len(d) == 0 || len(d) > 4096 {
			return "pack: inline defs must number 1..4096 (larger packs are sharded)"
		}
		if de := sortedUniqueDefsError(d); de != "" {
			return "pack: " + de
		}
	} else {
		dm, ok := x["defs"].(map[string]any)
		shards, _ := dm["shards"].([]any) // a non-object defs is a nil map here: no shards
		if !ok || closedErr(dm, []string{"shards"}) != "" || len(shards) == 0 || len(shards) > 4096 {
			return "pack: defs must be a list of defs or {shards}"
		}
		names := map[string]bool{}
		for _, rv := range shards {
			r, ok := rv.(map[string]any)
			if !ok || closedErr(r, []string{"name", "digest", "uri"}) != "" {
				return "pack: bad shard ref"
			}
			n, isS := r["name"].(string)
			if !isS || !reShardName.MatchString(n) || names[n] {
				return "pack: shard names must be distinct simple names"
			}
			names[n] = true
			u, uok := r["uri"].(string)
			if !isSha(r["digest"]) || !uok || len(u) == 0 || utf16Len(u) > 2048 {
				return "pack: bad shard digest or uri"
			}
		}
	}
	ev, ok := x["evolution"].([]any)
	if !ok || len(ev) > maxEvolutionRecords {
		return "pack: evolution must be a list of records"
	}
	for _, r := range ev {
		if e := evolutionRecordError(r, true); e != "" {
			return "pack: " + e
		}
	}
	if signed {
		g, ok := x["sig"].(map[string]any)
		_, kok := g["kid"].(string)
		_, vok := g["value"].(string)
		_, aok := g["alg"].(string)
		if !ok || closedErr(g, []string{"alg", "kid", "value", "pq_value"}) != "" || !kok || !vok || !aok {
			return "pack: bad sig"
		}
	}
	if _, err := HashCanonical(withoutKeys(x, "sig")); err != nil {
		return "pack: " + err.Error()
	}
	return ""
}

func packDefs(pack map[string]any, shards map[string]any) ([]any, error) {
	if d, ok := pack["defs"].([]any); ok {
		return append([]any{}, d...), nil
	}
	var all []any
	for _, rv := range pack["defs"].(map[string]any)["shards"].([]any) {
		r := rv.(map[string]any)
		name := r["name"].(string)
		sv, has := shards[name]
		if !has {
			return nil, fmt.Errorf("missing_shard: shard '%s' was not supplied", name)
		}
		// any supplied value (null included) is digested: a value outside the strict profile is the canonicalizer's error
		d, err := shardDigest(sv)
		if err != nil {
			return nil, err
		}
		if d != r["digest"] {
			return nil, fmt.Errorf("shard_digest_mismatch: shard '%s' does not match its digest", name)
		}
		s, isM := sv.(map[string]any)
		defs, isL := s["defs"].([]any)
		if !isM || !jsStrictEq(s["v"], jsNumber(1)) || s["kind"] != packShardKind || s["ns"] != pack["ns"] || s["version"] != pack["version"] || s["name"] != name || !isL {
			return nil, fmt.Errorf("bad_shard: shard '%s' is not a shard of this pack", name)
		}
		all = append(all, defs...)
	}
	sort.SliceStable(all, func(i, j int) bool {
		return u16Less(all[i].(map[string]any)["verb"].(string), all[j].(map[string]any)["verb"].(string))
	})
	return all, nil
}

// packDefDigest is defDigest; a var only so a test can reach verifyPack's digest failure: every def already canonicalised under the pack or shard digest.
var packDefDigest = defDigest

// verifyPack: shape, signature under the pinned keys, vocabulary digests, shards, defs, the recomputed Merkle root, and every evolution
// record. ok is true with the pack digest and def count, else a reason.
func verifyPack(packV any, keys any, shards map[string]any) (digest string, defCount int, reason string) {
	defer func() {
		if r := recover(); r != nil {
			digest, defCount, reason = "", 0, fmt.Sprint("pack verification error: ", r)
		}
	}()
	if se := packShapeError(packV, true); se != "" {
		return "", 0, se
	}
	pack := packV.(map[string]any)
	if v := verifyRegistrySig(packSigDomain, withoutKeys(pack, "sig"), pack["sig"].(map[string]any), keys); v != "" {
		return "", 0, "pack signature: " + v
	}
	if d, _ := traitsDigest(coreRegistry); pack["traits_digest"] != d {
		return "", 0, "traits_digest does not match the trait registry"
	}
	if d, _ := tablesDigest(); pack["roles_digest"] != d {
		return "", 0, "roles_digest does not match the vocabulary tables"
	}
	if d, _ := rulesDigest(); pack["rules_digest"] != d {
		return "", 0, "rules_digest does not match the rule tables"
	}
	defs, err := packDefs(pack, shards)
	if err != nil {
		e := err.Error()
		for _, code := range []string{"missing_shard: ", "shard_digest_mismatch: ", "bad_shard: "} {
			e = strings.TrimPrefix(e, code) // the reason is the error's message, without its code (as the reference)
		}
		return "", 0, e
	}
	if de := sortedUniqueDefsError(defs); de != "" {
		return "", 0, de
	}
	if packDefsOutOfRange(len(defs)) {
		return "", 0, "the pack lists no defs or too many"
	}
	digests := make([]string, len(defs))
	have := map[string]bool{}
	for i, d := range defs {
		dg, err := packDefDigest(d.(map[string]any))
		if err != nil {
			return "", 0, "pack verification error: " + err.Error() // the reference's outer catch
		}
		digests[i] = dg
		have[dg] = true
	}
	if root, err := packRoot(digests); err != nil || root != pack["root"] {
		return "", 0, "the Merkle root does not match the defs"
	}
	for _, rv := range pack["evolution"].([]any) {
		if e := verifyEvolutionRecord(rv, keys); e != "" {
			return "", 0, "evolution record: " + e
		}
		r := rv.(map[string]any)
		if r["ns"] != pack["ns"] {
			return "", 0, "evolution record of another namespace"
		}
		if to, ok := r["to"].(string); ok && !have[to] {
			return "", 0, fmt.Sprint("evolution record for '", r["verb"], "' names a definition that is not in the pack")
		}
	}
	pd, err := packDigest(pack)
	if err != nil {
		return "", 0, err.Error()
	}
	return pd, len(defs), ""
}

// packDefsOutOfRange: a verified pack lists 1..1000000 defs.
func packDefsOutOfRange(n int) bool { return n == 0 || n > 1000000 }

// PackTracker is the verifier's view of a registry: it refuses rollback, fork and chain gap.
type PackTracker struct {
	keys any
	seen map[string][2]string // ns -> {version, digest}
}

func newPackTracker(keys any) *PackTracker {
	return &PackTracker{keys: keys, seen: map[string][2]string{}}
}

func (t *PackTracker) accept(packV any, shards map[string]any) map[string]any {
	digest, _, reason := verifyPack(packV, t.keys, shards)
	if reason != "" {
		return map[string]any{"ok": false, "code": "bad_pack", "reason": reason}
	}
	pack := packV.(map[string]any)
	ns, version := pack["ns"].(string), pack["version"].(string)
	cur, has := t.seen[ns]
	if !has {
		t.seen[ns] = [2]string{version, digest}
		return map[string]any{"ok": true, "status": "first"}
	}
	if cur[1] == digest {
		return map[string]any{"ok": true, "status": "same"}
	}
	c, _ := compareVersions(version, cur[0])
	if c < 0 {
		return map[string]any{"ok": false, "code": "rollback", "reason": "version " + version + " is older than the accepted " + cur[0]}
	}
	if c == 0 {
		return map[string]any{"ok": false, "code": "fork", "reason": "two different packs claim version " + version}
	}
	if pack["prev"] != cur[1] {
		return map[string]any{"ok": false, "code": "chain_gap", "reason": "prev does not name the accepted pack"}
	}
	t.seen[ns] = [2]string{version, digest}
	return map[string]any{"ok": true, "status": "upgrade"}
}

// ---- rule 22 over a whole document -----------------------------------------------------------------------------------------

var rule22Codes = []string{"schema_floor_forged", "schema_traits_forged", "unknown_trait", "traits_digest_mismatch", "bad_registry"}

func rule22Integrity(doc map[string]any, pins any) map[string]any {
	e := schemaFloorError(doc, pins)
	if e == "" {
		return map[string]any{"ok": true}
	}
	for _, c := range rule22Codes {
		if strings.Contains(e, c) {
			return map[string]any{"ok": false, "code": c}
		}
	}
	return map[string]any{"ok": false, "code": "unknown"}
}

func rule22Decide(doc map[string]any, verb string, grant map[string]any, context []any) (res string) {
	defer func() {
		if recover() != nil {
			res = "deny"
		}
	}()
	var v map[string]any
	for _, e := range doc["verbs"].([]any) {
		if m, ok := e.(map[string]any); ok && m["verb"] == verb {
			v = m
			break
		}
	}
	if v == nil || profileErrorRaw(v["floors"]) != "" {
		return "deny"
	}
	var kinds, ctx []string
	for _, k := range grant["caveats"].([]any) {
		if s, ok := k.(string); ok && contains(caveatKinds, s) {
			kinds = append(kinds, s)
		}
	}
	for _, k := range context {
		if s, ok := k.(string); ok && isContextKey(s) {
			ctx = append(ctx, s)
		}
	}
	// a grant whose tiers are not non-negative safe integers (not -0) decides nothing: deny, before int() could truncate 2.5
	if !jsIsNonNeg(grant["max_esc"]) || !jsIsNonNeg(grant["preauth_esc"]) {
		return "deny"
	}
	return floorDecision(GrantFacts{Caveats: kinds, MaxEsc: int(jsF(grant["max_esc"])), PreauthEsc: int(jsF(grant["preauth_esc"]))}, ctx, profileFromRaw(v["floors"]))
}
