package pca

// The hosted action registry of one instance: the publish gate (what a new version of a namespace may change without a reviewer)
// and the verifier's view of the active versions (provenance facts, trait floors for rule 22, undo eligibility, the server
// reversibility class, compiled business rules). Pure: storage, keys and time are the caller's. Fail closed everywhere: an action
// the view does not know, that no pinned reviewer key confirmed, or that is deprecated gets the top of the trait registry, no
// provenance facts, is irreversible and never undoable. Versions and documents are JSON objects (map[string]any).

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

const (
	ActionRulesDocKind        = "pca-action-rules"
	ActionHostedVersionDomain = "atlas-pca/hosted-action-version/v1"
)

var (
	hostedPlainSemver  = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
	hostedEffectiveDim = []string{"confirmation", "effective.traits", "effective.profile"}
	hostedServerClass  = map[string]string{"reversible": "reversible", "rate_limited": "costly", "irreversible": "irreversible"}
)

// ActionRegistryOfTraits is the trait registry of a version: core plus its custom traits (an error with code bad_registry when a
// custom trait does not extend its implies).
func ActionRegistryOfTraits(traits []any) (Registry, error) {
	if len(traits) == 0 {
		return coreRegistry, nil
	}
	reg, err := extendRegistry(coreRegistry, traits)
	if err != nil {
		if m, ok := strings.CutPrefix(err.Error(), "bad_registry: "); ok {
			return nil, &CodedError{Code: "bad_registry", Msg: m}
		}
		return nil, err
	}
	return reg, nil
}

func hostedReviewOf(pins any, reg Registry) ActionDiffConfirmed {
	return ActionUndoConfirmedFrom(pins, reg)
}

func hostedList(v any) []any { l, _ := v.([]any); return l }

// ActionRulesDocError is "" iff x is a rules document for ns whose every verb is in defs and whose rules lint without errors.
func ActionRulesDocError(xv any, ns string, defs []any) string {
	x, ok := xv.(map[string]any)
	if !ok {
		return "rules must be a pca-action-rules document"
	}
	for _, k := range jsKeys(x) {
		if !contains([]string{"v", "kind", "ns", "rules", "reviews"}, k) {
			return "rules: unknown member '" + k + "'"
		}
	}
	if v, isNum := jsNum(x["v"]); !isNum || v != 1 || x["kind"] != ActionRulesDocKind {
		return "rules: not a " + ActionRulesDocKind + " v1 document"
	}
	if got, _ := x["ns"].(string); x["ns"] == nil || got != ns {
		return fmt.Sprintf("rules: ns '%s' is not the pack's '%s'", jsValueString(x["ns"]), ns)
	}
	rules, ok := x["rules"].(map[string]any)
	if !ok {
		return "rules.rules must map verbs to rules blocks"
	}
	reviews, hasReviews := x["reviews"]
	revM, revIsObj := reviews.(map[string]any)
	if hasReviews && !revIsObj {
		return "rules.reviews must map verbs to rules reviews"
	}
	byVerb := map[string]map[string]any{}
	for _, dv := range defs {
		if d, ok := dv.(map[string]any); ok {
			byVerb[jsAnyString(d["verb"])] = d
		}
	}
	for _, verb := range jsKeys(rules) {
		d := byVerb[verb]
		if d == nil {
			return "rules: '" + verb + "' is not an action of the pack"
		}
		var msgs []string
		for _, fv := range ActionLintBusinessRules(d, rules[verb]) {
			if f, _ := fv.(map[string]any); f["severity"] == "error" {
				msgs = append(msgs, jsAnyString(f["message"]))
			}
		}
		if len(msgs) > 0 {
			return "rules for '" + verb + "': " + strings.Join(msgs, "; ")
		}
	}
	for _, verb := range jsKeys(revM) {
		if byVerb[verb] == nil {
			return "rules.reviews: '" + verb + "' is not an action of the pack"
		}
	}
	return ""
}

func hostedSortedStrs(v any) []any {
	var ss []string
	for _, x := range hostedList(v) {
		ss = append(ss, jsAnyString(x))
	}
	sort.Slice(ss, func(i, j int) bool { return u16Less(ss[i], ss[j]) })
	return anyStrs(ss)
}

// ActionHostedVersionDigest is the content address of a stored version: {pack, rules, traits, deprecated}.
func ActionHostedVersionDigest(v map[string]any) (string, error) {
	for _, k := range []string{"pack", "rules", "traits", "deprecated"} {
		if _, has := v[k]; !has {
			return "", fmt.Errorf("the hosted version has no %s", k)
		}
	}
	return HashCanonical(map[string]any{"d": ActionHostedVersionDomain, "pack": v["pack"], "rules": v["rules"], "traits": v["traits"], "deprecated": hostedSortedStrs(v["deprecated"])})
}

func hostedFail(code, reason string, verbs []string) map[string]any {
	out := map[string]any{"ok": false, "code": code, "reason": reason}
	if len(verbs) > 0 {
		out["verbs"] = anyStrs(verbs)
	}
	return out
}

func hostedSafeConfirmed(d map[string]any, review ActionDiffConfirmed) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	return review != nil && review(d)
}

// hostedDiffAcross is ActionDiffDefs with each side under its own registry and review (a trait registry change shows up in the
// effective dimensions); same = both sides use one registry.
func hostedDiffAcross(o, n map[string]any, oReg, nReg Registry, oRev, nRev ActionDiffConfirmed, same bool) (map[string]any, error) {
	base, err := ActionDiffDefs(o, n, nReg, nRev)
	if err != nil || same {
		return base, err
	}
	eo, err := adEffective(o, oReg, oRev)
	if err != nil {
		return nil, err
	}
	en, err := adEffective(n, nReg, nRev)
	if err != nil {
		return nil, err
	}
	var rel string
	if leqProfile(eo.eff, en.eff) {
		if leqProfile(en.eff, eo.eff) {
			return base, nil
		}
		rel = "narrow"
	} else if leqProfile(en.eff, eo.eff) {
		rel = "widen"
	} else {
		rel = "incomparable"
	}
	var reasons []string
	for _, r := range hostedList(base["reasons"]) {
		if s := jsAnyString(r); !strings.HasPrefix(s, "effective.profile") {
			reasons = append(reasons, s)
		}
	}
	reasons = append(reasons, "effective.profile: "+rel)
	adSortU16(reasons)
	bc := jsAnyString(base["class"])
	cls := "narrow"
	switch {
	case rel == "incomparable" || bc == "incomparable" || (rel == "widen" && bc == "narrow") || (rel == "narrow" && bc == "widen"):
		cls = "incomparable"
	case rel == "widen" || bc == "widen":
		cls = "widen"
	}
	return map[string]any{"class": cls, "reasons": anyStrs(reasons)}, nil
}

func hostedRulesBlock(doc map[string]any, verb string) any {
	r, _ := doc["rules"].(map[string]any)
	return r[verb]
}

// ActionPublishGate decides whether a version may become the active one of its namespace and computes what it changes. in:
// {current?, pack, rules?, traits?, publisherKeys, pins, pin?}. Refused (ok false): bad_pack, bad_traits, bad_rules, ns_mismatch,
// bad_version / not_newer, widen_unreviewed (an action whose effective authority or business rules widen without a reviewer
// signature). Removed actions become deprecated. A non-nil error is a malformed stored `current` or an internal failure.
func ActionPublishGate(in map[string]any) (map[string]any, error) {
	traits := []any{}
	if tv, has := in["traits"]; has {
		l, ok := tv.([]any)
		if !ok {
			return hostedFail("bad_traits", "traits must be a list of trait definitions", nil), nil
		}
		traits = l
	}
	reg, err := ActionRegistryOfTraits(traits)
	if err != nil {
		msg := err.Error()
		if ce, ok := err.(*CodedError); ok {
			msg = ce.Msg
		}
		return hostedFail("bad_traits", msg, nil), nil
	}
	keys := hostedList(in["publisherKeys"])
	if pv := ActionBuildVerifyPack(in["pack"], keys, reg); pv["ok"] != true {
		return hostedFail("bad_pack", jsAnyString(pv["reason"]), nil), nil
	}
	pack := in["pack"].(map[string]any)
	pver, _ := pack["version"].(string)
	pns, _ := pack["ns"].(string)
	if !hostedPlainSemver.MatchString(pver) {
		return hostedFail("bad_version", fmt.Sprintf("version '%s' must be MAJOR.MINOR.PATCH", pver), nil), nil
	}
	cur, _ := in["current"].(map[string]any)
	if len(cur) == 0 {
		cur = nil
	}
	if cur != nil {
		if cns, _ := cur["ns"].(string); cns != pns {
			return hostedFail("ns_mismatch", fmt.Sprintf("the active namespace is '%s', the pack is '%s'", jsAnyString(cur["ns"]), pns), nil), nil
		}
		if !rbTruthy(in["pin"]) {
			cmp, err := compareVersions(pver, jsAnyString(cur["version"]))
			if err != nil {
				return nil, err
			}
			if cmp <= 0 {
				return hostedFail("not_newer", fmt.Sprintf("version %s is not above the active %s", pver, jsAnyString(cur["version"])), nil), nil
			}
		}
	}
	var rulesV any = map[string]any{"v": jsNumber(1), "kind": ActionRulesDocKind, "ns": pns, "rules": map[string]any{}}
	if rv, has := in["rules"]; has {
		rulesV = rv
	}
	packDefs := hostedList(pack["defs"])
	if e := ActionRulesDocError(rulesV, pns, packDefs); e != "" {
		return hostedFail("bad_rules", e, nil), nil
	}
	rules := rulesV.(map[string]any)

	pins := in["pins"]
	review := hostedReviewOf(pins, reg)
	prevReg, same := reg, len(traits) == 0
	if cur != nil {
		if pr, err := ActionRegistryOfTraits(hostedList(cur["traits"])); err != nil {
			prevReg, same = reg, true
		} else {
			prevReg, same = pr, len(traits) == 0 && len(hostedList(cur["traits"])) == 0
		}
	}
	prevReview := hostedReviewOf(pins, prevReg)

	oldDefs := map[string]map[string]any{}
	oldDep := map[string]bool{}
	if cur != nil {
		if cp, _ := cur["pack"].(map[string]any); cp != nil {
			for _, dv := range hostedList(cp["defs"]) {
				if d, _ := dv.(map[string]any); d != nil {
					oldDefs[jsAnyString(d["verb"])] = d
				}
			}
		}
		for _, x := range hostedList(cur["deprecated"]) {
			oldDep[jsAnyString(x)] = true
		}
	}
	newVerbs := map[string]bool{}
	for _, dv := range packDefs {
		d, _ := dv.(map[string]any)
		newVerbs[jsAnyString(d["verb"])] = true
	}
	var changes []map[string]any
	var blocked, reasons []string
	for _, dv := range packDefs {
		n, _ := dv.(map[string]any)
		verb := jsAnyString(n["verb"])
		o := oldDefs[verb]
		newRules := hostedRulesBlock(rules, verb)
		confirmed := hostedSafeConfirmed(n, review)
		var change map[string]any
		isNew := o == nil || oldDep[verb]
		if isNew {
			change = map[string]any{"verb": verb, "class": "added", "reasons": []any{}}
			if confirmed {
				change["reviewed"] = true
			}
		} else {
			d, err := hostedDiffAcross(o, n, prevReg, reg, prevReview, review, same)
			if err != nil {
				return nil, err
			}
			change = map[string]any{"verb": verb, "class": d["class"], "reasons": d["reasons"]}
			effWide := false
			for _, rv := range hostedList(d["reasons"]) {
				r := jsAnyString(rv)
				for _, dim := range hostedEffectiveDim {
					if strings.HasPrefix(r, dim+": widen") || strings.HasPrefix(r, dim+": incomparable") {
						effWide = true
					}
				}
			}
			if effWide {
				if confirmed {
					change["reviewed"] = true
				} else {
					blocked = append(blocked, verb)
					reasons = append(reasons, verb+": its effective authority widens without a valid confirmation of the new definition")
				}
			}
		}
		var oldRules any
		if !isNew {
			cr, _ := cur["rules"].(map[string]any)
			oldRules = hostedRulesBlock(cr, verb)
		}
		if oldRules != nil || newRules != nil {
			om, _ := oldRules.(map[string]any)
			nm, _ := newRules.(map[string]any)
			rd, err := ActionDiffBusinessRules(n, om, nm)
			if err != nil {
				rd = map[string]any{"class": "incomparable", "reasons": []any{"rules: " + err.Error()}}
			}
			if rd["class"] != "equal" {
				change["rules"] = rd
			}
			if rd["class"] == "widen" || rd["class"] == "incomparable" {
				if nm == nil {
					nm = map[string]any{}
				}
				revs, _ := rules["reviews"].(map[string]any)
				if e := ActionRulesReviewError(revs[verb], n, nm, pins); e == "" {
					change["reviewed"] = true
				} else {
					var rs []string
					for _, r := range hostedList(rd["reasons"]) {
						rs = append(rs, jsAnyString(r))
					}
					blocked = append(blocked, verb)
					reasons = append(reasons, fmt.Sprintf("%s: its business rules widen (%s) without a valid rules review: %s", verb, strings.Join(rs, ", "), e))
				}
			}
		}
		if change["class"] != "equal" || change["rules"] != nil {
			changes = append(changes, change)
		}
	}
	deprecated := map[string]bool{}
	for v := range oldDep {
		if !newVerbs[v] {
			deprecated[v] = true
		}
	}
	for v := range oldDefs {
		if newVerbs[v] || oldDep[v] {
			continue
		}
		deprecated[v] = true
		changes = append(changes, map[string]any{"verb": v, "class": "deprecated", "reasons": []any{"removed from the namespace: treated as unknown"}})
	}
	sort.Slice(changes, func(i, j int) bool { return u16Less(changes[i]["verb"].(string), changes[j]["verb"].(string)) })
	changeList := make([]any, 0, len(changes))
	for _, c := range changes {
		changeList = append(changeList, c)
	}
	if len(blocked) > 0 {
		seen := map[string]bool{}
		var uniq []string
		for _, b := range blocked {
			if !seen[b] {
				seen[b] = true
				uniq = append(uniq, b)
			}
		}
		sort.Slice(uniq, func(i, j int) bool { return u16Less(uniq[i], uniq[j]) })
		out := hostedFail("widen_unreviewed", strings.Join(reasons, "\n"), uniq)
		out["changes"] = changeList
		return out, nil
	}
	var depList []string
	for v := range deprecated {
		depList = append(depList, v)
	}
	sort.Slice(depList, func(i, j int) bool { return u16Less(depList[i], depList[j]) })
	body := map[string]any{"pack": pack, "rules": rules, "traits": traits, "deprecated": anyStrs(depList)}
	if depList == nil {
		body["deprecated"] = []any{}
	}
	digest, err := ActionHostedVersionDigest(body)
	if err != nil {
		return nil, err
	}
	var prev any
	if cur != nil {
		prev = cur["digest"]
	}
	ver := map[string]any{"ns": pns, "version": pver, "digest": digest, "prev": prev, "changes": changeList}
	for k, v := range body {
		ver[k] = v
	}
	return map[string]any{"ok": true, "version": ver}, nil
}

// ---- the verifier's view ----------------------------------------------------------------------------------------------------

// ActionGrantFactsOf is the grant facts for rule 22 from a stored grant: envelope caveat types plus the pin block's caveats and
// escalation tiers (a missing or invalid tier takes the strict default: max 3, preauth 0).
func ActionGrantFactsOf(grant any) GrantFacts {
	env := ReadEnvelope(grant)
	a, _ := env["actions"].(map[string]any)
	tier := func(v any, d int) int {
		if jsIsInt(v) {
			if f, _ := jsNum(v); f >= 0 && f <= 3 {
				return int(f)
			}
		}
		return d
	}
	caveats := []string{}
	for _, c := range hostedList(env["caveats"]) {
		if m, ok := c.(map[string]any); ok {
			if s, ok := m["type"].(string); ok {
				caveats = append(caveats, s)
			}
		}
	}
	for _, c := range hostedList(a["caveats"]) {
		if s, ok := c.(string); ok {
			caveats = append(caveats, s)
		}
	}
	return GrantFacts{Caveats: caveats, MaxEsc: tier(a["max_esc"], 3), PreauthEsc: tier(a["preauth_esc"], 0)}
}

func hostedBrokenRules(verb string) map[string]any {
	return map[string]any{"v": jsNumber(1), "verb": verb, "rules_digest": "", "def_digest": "", "accumulators": []any{},
		"tighten": []any{map[string]any{"id": "rules_broken", "when": map[string]any{"field": "action.verb", "op": "eq", "value": verb}, "signal": "deny",
			"reason": "the business rules of this action no longer compile"}}}
}

type hostedEntry struct {
	def     map[string]any
	reg     Registry
	regID   int
	review  ActionDiffConfirmed
	rules   any
	hasRule bool
}

type hostedLookup struct {
	out  map[string]any
	prof Profile
}

// ActionHostedView is the verifier's view of the active versions of an instance.
type ActionHostedView struct {
	// Versions is "ns@version" per input version.
	Versions   []string
	pins       any
	byVerb     map[string]*hostedEntry
	deprecated map[string]bool
	broken     map[string]bool
	top        Profile
	topIDs     []string
	cache      map[string]hostedLookup
	prov       map[string]map[string]any
	undoDefs   map[int][]any
}

// NewActionHostedView builds the view of versions (as stored by ActionPublishGate) under the instance's reviewer pins.
func NewActionHostedView(versions []any, pins any) *ActionHostedView {
	v := &ActionHostedView{pins: pins, byVerb: map[string]*hostedEntry{}, deprecated: map[string]bool{}, broken: map[string]bool{}, cache: map[string]hostedLookup{},
		prov: map[string]map[string]any{}, undoDefs: map[int][]any{}}
	type regRef struct {
		reg Registry
		id  int
	}
	var regs []regRef
	for i, xv := range versions {
		x, _ := xv.(map[string]any)
		v.Versions = append(v.Versions, jsAnyString(x["ns"])+"@"+jsAnyString(x["version"]))
		tl := hostedList(x["traits"])
		reg, err := ActionRegistryOfTraits(tl)
		if err != nil {
			pk, _ := x["pack"].(map[string]any)
			for _, dv := range hostedList(pk["defs"]) {
				if d, _ := dv.(map[string]any); d != nil {
					if s, ok := d["verb"].(string); ok {
						v.broken[s] = true
					}
				}
			}
			continue
		}
		id := i + 1 // the core registry is shared by every version without custom traits (as one object in the reference)
		if len(tl) == 0 {
			id = 0
		}
		regs = append(regs, regRef{reg, id})
		review := hostedReviewOf(pins, reg)
		pk, _ := x["pack"].(map[string]any)
		rl, _ := x["rules"].(map[string]any)
		rm, _ := rl["rules"].(map[string]any)
		for _, dv := range hostedList(pk["defs"]) {
			d, _ := dv.(map[string]any)
			verb := jsAnyString(d["verb"])
			if _, has := v.byVerb[verb]; has {
				continue
			}
			e := &hostedEntry{def: d, reg: reg, regID: id, review: review}
			if r := rm[verb]; rbTruthy(r) { // a JS object is truthy even when empty
				e.rules, e.hasRule = r, true
			}
			v.byVerb[verb] = e
		}
		for _, dp := range hostedList(x["deprecated"]) {
			v.deprecated[jsAnyString(dp)] = true
		}
	}
	for x := range v.deprecated {
		delete(v.byVerb, x)
	}
	for x := range v.broken {
		delete(v.byVerb, x)
	}
	if len(regs) == 0 {
		regs = []regRef{{coreRegistry, 0}}
		v.top, _ = coreRegistry.floorOf(topTraits(coreRegistry))
	} else {
		for i, r := range regs {
			f, _ := r.reg.floorOf(topTraits(r.reg))
			switch {
			case i == 0:
				v.top = f
			case leqProfile(v.top, f):
				v.top = f
			case leqProfile(f, v.top):
			default:
				v.top = joinProfile(v.top, f)
			}
		}
	}
	seen := map[string]bool{}
	for _, r := range regs {
		for _, t := range topTraits(r.reg) {
			seen[t] = true
		}
	}
	for t := range seen {
		v.topIDs = append(v.topIDs, t)
	}
	sort.Slice(v.topIDs, func(i, j int) bool { return u16Less(v.topIDs[i], v.topIDs[j]) })
	for verb, e := range v.byVerb {
		if !hostedSafeConfirmed(e.def, e.review) {
			continue
		}
		if p, err := ActionProvenanceInfoOf(e.def, e.reg, e.review); err == nil {
			v.prov[verb] = p // an error leaves the action unknown: sensitive
		}
	}
	verbs := make([]string, 0, len(v.byVerb))
	for verb := range v.byVerb {
		verbs = append(verbs, verb)
	}
	sort.Strings(verbs)
	for _, verb := range verbs {
		e := v.byVerb[verb]
		v.undoDefs[e.regID] = append(v.undoDefs[e.regID], e.def)
	}
	return v
}

func (v *ActionHostedView) topIDsAny() []any { return anyStrs(v.topIDs) }

func (v *ActionHostedView) lookup(verb string) hostedLookup {
	if hit, ok := v.cache[verb]; ok {
		return hit
	}
	e := v.byVerb[verb]
	out := map[string]any{"verb": verb, "confirmed": false, "known": e != nil, "deprecated": v.deprecated[verb], "profile": v.top.raw(),
		"traits": v.topIDsAny(), "serverClass": "irreversible"}
	prof := v.top
	if e == nil && v.broken[verb] && !v.deprecated[verb] {
		out["known"] = true
		out["rules"] = hostedBrokenRules(verb)
	}
	if e != nil {
		if nxt, p, ok := v.lookupEntry(verb, e, out); ok {
			out, prof = nxt, p
		} else { // a def or rules block that no longer compiles: unknown-strict, and its rules cannot be dropped silently
			out["confirmed"], out["profile"], out["traits"], out["serverClass"] = false, v.top.raw(), v.topIDsAny(), "irreversible"
			out["rules"] = hostedBrokenRules(verb)
		}
	}
	h := hostedLookup{out, prof}
	v.cache[verb] = h
	return h
}

func (v *ActionHostedView) lookupEntry(verb string, e *hostedEntry, base map[string]any) (out map[string]any, prof Profile, ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	eff, err := adEffective(e.def, e.reg, e.review)
	if err != nil {
		return nil, Profile{}, false
	}
	dg, err := defDigest(e.def)
	if err != nil {
		return nil, Profile{}, false
	}
	out = map[string]any{}
	for k, x := range base {
		out[k] = x
	}
	prof = v.top
	out["def_digest"], out["confirmed"] = dg, eff.confirmed
	if idem, _ := e.def["idempotency"].(map[string]any); idem["mode"] == "key_param" {
		out["idempotency_param"] = idem["param"]
	}
	if eff.confirmed {
		sc, has := hostedServerClass[eff.eff.Rev]
		if !has {
			return nil, Profile{}, false
		}
		prof = eff.eff
		out["profile"], out["traits"], out["serverClass"] = eff.eff.raw(), anyStrs(eff.traits), sc
	}
	if e.hasRule {
		c, err := ActionCompileBusinessRules(e.def, e.rules)
		if err != nil {
			return nil, Profile{}, false
		}
		out["rules"] = c
	}
	return out, prof, true
}

// Lookup is what the hosted adjudication path reads for a verb (never nil; unknown / unconfirmed / deprecated verbs get the top).
func (v *ActionHostedView) Lookup(verb string) map[string]any { return v.lookup(verb).out }

// Provenance is the provenance facts of a confirmed action, or nil (unknown: sensitive).
func (v *ActionHostedView) Provenance(op map[string]any) map[string]any {
	return v.prov[jsAnyString(op["verb"])]
}

// UndoPlan is the undo plan of op {verb, params}, or nil.
func (v *ActionHostedView) UndoPlan(op map[string]any) map[string]any {
	e := v.byVerb[jsAnyString(op["verb"])]
	if e == nil {
		return nil
	}
	return actionUndoPlanIn(v.undoDefs[e.regID], v.pins, op, e.reg)
}

// Floor is the rule 22 decision (allow / escalate / deny) of a call to verb under a grant and the call's context; deny on any failure.
func (v *ActionHostedView) Floor(verb string, grant GrantFacts, callContext []string) (res string) {
	defer func() {
		if recover() != nil {
			res = "deny"
		}
	}()
	kinds := []string{}
	for _, c := range grant.Caveats {
		if contains(caveatKinds, c) {
			kinds = append(kinds, c)
		}
	}
	return floorDecision(GrantFacts{Caveats: kinds, MaxEsc: grant.MaxEsc, PreauthEsc: grant.PreauthEsc}, callContext, v.lookup(verb).prof)
}

// ActionHostedCallContext is the context keys the hosted server itself establishes for a call: fresh revocation always; an
// idempotency key when the action names one and the call carries a non-empty string for it.
func ActionHostedCallContext(l, params map[string]any) []string {
	out := []string{"fresh_revocation"}
	if k, ok := l["idempotency_param"].(string); ok {
		if s, ok := params[k].(string); ok && len(s) > 0 {
			out = append(out, "idempotency")
		}
	}
	return out
}

// ActionRateKeysOf is the event keys of a compiled rules block's rate limits: verb, window and scope id (never a rule index or the
// rules digest). who = {principal?, org?}.
func ActionRateKeysOf(c, who map[string]any) []any {
	out := []any{}
	for _, av := range hostedList(c["accumulators"]) {
		a, _ := av.(map[string]any)
		scope, who2 := "principal", who["principal"]
		if a["scope"] == "org" {
			scope, who2 = "org", who["org"]
		}
		var ms float64
		if w, _ := a["win"].(map[string]any); w["kind"] != "task" {
			ms, _ = jsNum(w["ms"])
		}
		e := map[string]any{"id": a["id"], "ms": jsNumber(ms)}
		if id, ok := who2.(string); ok && len(id) > 0 && ms > 0 {
			e["key"] = fmt.Sprintf("%s|%s|%s:%s", jsAnyString(c["verb"]), jsNumberString(ms), scope, id)
		}
		out = append(out, e)
	}
	return out
}
