package pca

// The intent-fidelity ontology: the signed authoring vocabulary (aliases, templates, units), its projection onto the IR ontology, its
// well-formedness checker, template instantiation, slot typing and locale-aware amount parsing (the TypeScript reference is
// @atlasauth/pca-goal `ontology`). Ontologies, goals and slot values are the parsed-JSON trees of the reference. The goal*
// functions panic like a JavaScript throw; the exported Goal* wrappers return errors.

import (
	"math"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
	"golang.org/x/text/unicode/norm"
)

// goalEffectClasses is EFFECT_CLASSES.
var goalEffectClasses = []any{"read", "reversible", "external_send", "irreversible"}

const goalOntologyForever = 9007199254740991

var goalOntologyIDRE = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// goalOntologyInvis is the invisible-character class of the reference: U+200B..U+200F, U+2060, U+FEFF.
func goalOntologyInvisRune(r rune) bool {
	return (r >= 0x200b && r <= 0x200f) || r == 0x2060 || r == 0xfeff
}

func goalOntologyHasInvis(s string) bool { return strings.IndexFunc(s, goalOntologyInvisRune) >= 0 }

type goalOntologyPtr struct {
	p uintptr
	n int
}

// goalOntologyKey is a map key with JavaScript Set semantics: objects and arrays by identity, numbers by value.
func goalOntologyKey(x any) any {
	switch t := x.(type) {
	case map[string]any:
		return goalOntologyPtr{reflect.ValueOf(t).Pointer(), -1}
	case []any:
		return goalOntologyPtr{reflect.ValueOf(t).Pointer(), len(t)}
	}
	if f, ok := jsNum(x); ok {
		if f == 0 {
			f = 0
		}
		return f
	}
	return x
}

type goalOntologySet struct{ m map[any]bool }

func goalOntologyNewSet() *goalOntologySet { return &goalOntologySet{m: map[any]bool{}} }

func (s *goalOntologySet) add(x any)      { s.m[goalOntologyKey(x)] = true }
func (s *goalOntologySet) has(x any) bool { return s.m[goalOntologyKey(x)] }
func (s *goalOntologySet) size() int      { return len(s.m) }

// goalOntologyIs is `v === "lit"` for a string literal.
func goalOntologyIs(v any, lit string) bool { s, ok := v.(string); return ok && s == lit }

func goalOntologyNorm(s string) string {
	l := cases.Lower(language.Und).String(norm.NFKC.String(s))
	return strings.Map(func(r rune) rune {
		if goalOntologyInvisRune(r) {
			return -1
		}
		return r
	}, l)
}

type goalOntologyEntry struct {
	k string
	v any
}

// goalOntologyEntries is Object.entries(o): an object's members in JavaScript key order; null throws; other primitives have none.
func goalOntologyEntries(o any) []goalOntologyEntry {
	if o == nil || anlIsUndef(o) {
		anlFail("cannot convert undefined or null to object")
	}
	var out []goalOntologyEntry
	switch t := o.(type) {
	case map[string]any:
		for _, k := range jsKeys(t) {
			out = append(out, goalOntologyEntry{k, t[k]})
		}
	case []any:
		for i, x := range t {
			out = append(out, goalOntologyEntry{strconv.Itoa(i), x})
		}
	case string:
		for i, u := range utf16.Encode([]rune(t)) {
			out = append(out, goalOntologyEntry{strconv.Itoa(i), string(utf16.Decode([]uint16{u}))})
		}
	}
	return out
}

func goalOntologyValues(o any) []any {
	es := goalOntologyEntries(o)
	out := make([]any, len(es))
	for i, e := range es {
		out[i] = e.v
	}
	return out
}

// goalOntologyIter is `for (const e of x)`: an array's elements or a string's code points; anything else throws.
func goalOntologyIter(x any) []any {
	switch t := x.(type) {
	case []any:
		return t
	case string:
		var out []any // code points; a lone surrogate stays one element (its WTF-8 form)
		us := utf16Units(t)
		for i := 0; i < len(us); i++ {
			if us[i] >= 0xD800 && us[i] < 0xDC00 && i+1 < len(us) && us[i+1] >= 0xDC00 && us[i+1] <= 0xDFFF {
				out = append(out, string(rune(0x10000+(rune(us[i])-0xD800)<<10+rune(us[i+1])-0xDC00)))
				i++
				continue
			}
			out = append(out, acpUnitString(us[i]))
		}
		return out
	}
	anlFail("not iterable")
	return nil
}

func goalOntologyFind(xs any, pred func(any) bool) any {
	for _, x := range anlReqList(xs) {
		if pred(x) {
			return x
		}
	}
	return anlUndef
}

// goalOntologyOwn is o[k] for an own member of a plain object, else undefined (a null object throws).
func goalOntologyOwn(o any, k any) any {
	if o == nil || anlIsUndef(o) {
		anlFail("cannot read properties of null")
	}
	ks, ok := k.(string)
	if !ok {
		return anlUndef
	}
	return anlOwn(o, ks)
}

// goalOntologyLenPos is `!!x?.length`: a non-empty array or string.
func goalOntologyLenPos(x any) bool {
	switch t := x.(type) {
	case []any:
		return len(t) > 0
	case string:
		return len(t) > 0
	}
	return false
}

// goalOntologyStartsWith is x.startsWith(pre); a non-string either side throws.
func goalOntologyStartsWith(x, pre any) bool {
	xs, ok := x.(string)
	if !ok {
		anlFail("x.startsWith is not a function")
	}
	ps, ok := pre.(string)
	if !ok {
		anlFail("startswith first arg must be str")
	}
	return strings.HasPrefix(xs, ps)
}

func goalOntologyIsInteger(x any) bool {
	f, ok := jsNum(x)
	return ok && !math.IsInf(f, 0) && !math.IsNaN(f) && f == math.Trunc(f)
}

func goalOntologyDigest(o any) string {
	h, err := HashCanonical(map[string]any{"d": "atlas-pca/goal-intent-ontology/v1", "ontology": o})
	if err != nil {
		anlFail("%s", err.Error())
	}
	return h
}

func goalSignOntology(o any, secret any, rest ...any) map[string]any {
	return goalSignPayload("ontology", o, secret, rest...)
}

func goalVerifyOntology(s any, pins []any) bool { return goalVerifyPayload(s, "ontology", pins) }

func goalResolveVerb(o any, word any) any {
	ws, ok := word.(string)
	if !ok {
		anlFail("word.trim is not a function")
	}
	w := jsTrim(ws)
	for _, v := range anlReqList(anlGet(o, "verbs")) {
		if anlStrictEq(anlGet(v, "id"), w) {
			return w
		}
	}
	hit := goalOntologyOwn(anlGet(o, "aliases"), w)
	if anlIsUndef(hit) {
		return nil
	}
	return hit
}

// goalGoalCcy is the currency a goal is written in: the first money quantity in its conditions or bound caps (nil without money).
func goalGoalCcy(g any) any {
	found := anlUndef
	t := func(x any) {
		if !goalOntologyIs(anlGet(x, "k"), "lit") {
			return
		}
		v := anlGet(x, "v")
		items := []any{v}
		if goalOntologyIs(anlGet(v, "k"), "set") {
			items = anlReqList(anlGet(v, "items"))
		}
		for _, i := range items {
			if anlIsUndef(found) && goalOntologyIs(anlGet(i, "k"), "q") && goalOntologyIs(anlGet(anlGet(anlGet(i, "q"), "u"), "k"), "money") {
				found = anlGet(anlGet(anlGet(i, "q"), "u"), "ccy")
			}
		}
	}
	var c func(x any)
	c = func(x any) {
		switch k := anlGet(x, "k"); {
		case goalOntologyIs(k, "cmp"):
			t(anlGet(x, "l"))
			t(anlGet(x, "r"))
		case goalOntologyIs(k, "and") || goalOntologyIs(k, "or"):
			c(anlGet(x, "a"))
			c(anlGet(x, "b"))
		case goalOntologyIs(k, "not"):
			c(anlGet(x, "c"))
		}
	}
	for _, gr := range anlReqList(anlGet(g, "grants")) {
		c(anlGet(gr, "cond"))
	}
	for _, p := range anlReqList(anlGet(g, "prohibits")) {
		c(anlGet(p, "cond"))
	}
	for _, x := range anlReqList(anlGet(g, "escalateOn")) {
		c(x)
	}
	for _, b := range anlReqList(anlGet(g, "bounds")) {
		cp := anlGet(b, "cap")
		if anlIsUndef(found) && goalOntologyIs(anlGet(anlGet(cp, "u"), "k"), "money") {
			found = anlGet(anlGet(cp, "u"), "ccy")
		}
	}
	if anlIsUndef(found) {
		return nil
	}
	return found
}

func goalOntologyParamTy(p any, ccy any) map[string]any {
	kind := anlGet(p, "kind")
	if goalOntologyIs(kind, "id") || goalOntologyIs(kind, "enum") || goalOntologyIs(kind, "text") {
		return map[string]any{"k": "s"}
	}
	if goalOntologyIs(kind, "money") {
		ccys := anlGet(p, "ccys")
		var c any
		if ccy != nil && !anlIsUndef(ccy) && !anlIsUndef(ccys) && anlIncludes(ccys, ccy) {
			c = ccy
		} else if !anlIsUndef(ccys) && anlIncludes(ccys, "USD") {
			c = "USD"
		} else if l := anlReqList(ccys); len(l) > 0 {
			c = l[0]
		} else {
			c = anlUndef
		}
		return map[string]any{"k": "q", "u": map[string]any{"k": "money", "ccy": c}}
	}
	return map[string]any{"k": "q", "u": map[string]any{"k": kind}}
}

// goalToIrOntology is T1's Ontology (verbs with effect class and typed parameters, relation tables) for an intent ontology.
// opts: {ccy?, rels?}.
func goalToIrOntology(o any, opts any) map[string]any {
	om, _ := opts.(map[string]any)
	if opts != nil && om == nil {
		if l, ok := opts.([]any); !ok || len(l) > 0 {
			anlFail("opts.get is not a function")
		}
	}
	var ccy any
	if v, ok := om["ccy"]; ok {
		ccy = v
	}
	verbs := []any{}
	for _, v := range anlReqList(anlGet(o, "verbs")) {
		params := anlGet(v, "params")
		var paths []string
		for _, e := range goalOntologyEntries(params) {
			paths = append(paths, e.k)
		}
		ps := []any{}
		for _, path := range goalSortU16(paths) {
			ps = append(ps, map[string]any{"path": path, "ty": goalOntologyParamTy(goalOntologyOwn(params, path), ccy)})
		}
		verbs = append(verbs, map[string]any{"verb": anlGet(v, "id"), "cls": anlGet(v, "effect"), "params": ps})
	}
	rels := any([]any{})
	if r, ok := om["rels"]; ok && r != nil {
		rels = r
	}
	return map[string]any{"verbs": verbs, "rels": rels}
}

// goalOntologyForGoal is the IR ontology a goal is typed and decided against: money parameters in the goal's own currency.
func goalOntologyForGoal(o any, g any, rels any) map[string]any {
	ccy := goalGoalCcy(g)
	if rels == nil {
		rels = []any{}
	}
	opts := map[string]any{"rels": rels}
	if ccy != nil {
		opts["ccy"] = ccy
	}
	return goalToIrOntology(o, opts)
}

// goalGoalAnchors are the relation anchors a goal mentions, declared with no members (typing needs them; facts come per case).
func goalGoalAnchors(g any) []any {
	out := map[string]map[string]any{}
	var sel func(s any)
	sel = func(s any) {
		k := anlGet(s, "k")
		if goalOntologyIs(k, "related") {
			rel, anchor := anlGet(s, "rel"), anlGet(s, "anchor")
			out[anlJS(rel)+"\x00"+anlJS(anchor)] = map[string]any{"rel": rel, "anchor": anchor, "members": []any{}}
		} else if goalOntologyIs(k, "all_of") {
			for _, p := range anlReqList(anlGet(s, "parts")) {
				sel(p)
			}
		}
	}
	for _, gr := range anlReqList(anlGet(g, "grants")) {
		sel(anlGet(gr, "res"))
	}
	for _, p := range anlReqList(anlGet(g, "prohibits")) {
		sel(anlGet(p, "res"))
	}
	keys := make([]string, 0, len(out))
	for k := range out {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return utf16Less(keys[i], keys[j]) })
	res := make([]any, len(keys))
	for i, k := range keys {
		res[i] = out[k]
	}
	return res
}

func goalOntologyDollar(x any) []any {
	if goalOntologyStartsWith(x, "$") {
		return []any{x.(string)[1:]}
	}
	return nil
}

func goalOntologyRefsRes(s any) []any {
	switch k := anlGet(s, "k"); {
	case goalOntologyIs(k, "exact"):
		return goalOntologyDollar(anlGet(s, "id"))
	case goalOntologyIs(k, "oneof"):
		var out []any
		for _, i := range anlReqList(anlGet(s, "ids")) {
			out = append(out, goalOntologyDollar(i)...)
		}
		return out
	case goalOntologyIs(k, "related"):
		return goalOntologyDollar(anlGet(s, "anchor"))
	case goalOntologyIs(k, "all_of"):
		var out []any
		for _, p := range anlReqList(anlGet(s, "parts")) {
			out = append(out, goalOntologyRefsRes(p)...)
		}
		return out
	}
	return nil
}

func goalOntologyRefsTerm(x any) []any {
	if goalOntologyIs(anlGet(x, "k"), "slot") {
		return []any{anlGet(x, "slot")}
	}
	return nil
}

func goalOntologyRefsCond(c any) []any {
	switch k := anlGet(c, "k"); {
	case goalOntologyIs(k, "cmp"):
		return append(goalOntologyRefsTerm(anlGet(c, "l")), goalOntologyRefsTerm(anlGet(c, "r"))...)
	case goalOntologyIs(k, "and") || goalOntologyIs(k, "or"):
		return append(goalOntologyRefsCond(anlGet(c, "a")), goalOntologyRefsCond(anlGet(c, "b"))...)
	case goalOntologyIs(k, "not"):
		return goalOntologyRefsCond(anlGet(c, "c"))
	}
	return nil
}

func goalOntologyRefsGrant(g any) []any {
	return append(goalOntologyRefsRes(anlGet(g, "res")), goalOntologyRefsCond(anlGet(g, "cond"))...)
}

func goalOntologyRefsBound(b any) []any {
	if anlTruthy(anlGet(b, "cap_slot")) {
		return []any{anlGet(b, "cap_slot")}
	}
	return nil
}

func goalOntologySlotRefs(t any) []any {
	var out []any
	for _, g := range anlReqList(anlGet(t, "grants")) {
		out = append(out, goalOntologyRefsGrant(g)...)
	}
	for _, p := range anlReqList(anlGet(t, "prohibits")) {
		out = append(out, goalOntologyRefsGrant(p)...)
	}
	for _, b := range anlReqList(anlGet(t, "bounds")) {
		out = append(out, goalOntologyRefsBound(b)...)
	}
	return out
}

type goalOntologyBad func(code string, where any, msg string)

// goalCheckOntology is the well-formedness checker: every defect as {code, where, msg}; an empty list means well formed.
func goalCheckOntology(o any) []any {
	issues := []any{}
	bad := func(code string, where any, msg string) {
		m := map[string]any{"code": code, "msg": msg}
		if !anlIsUndef(where) {
			m["where"] = where
		}
		issues = append(issues, m)
	}
	typeIDs, prefixes := goalOntologyNewSet(), goalOntologyNewSet()
	for _, t := range goalOntologyIter(anlGet(o, "types")) {
		tid := anlGet(t, "id")
		if typeIDs.has(tid) {
			bad("dup_type", tid, "duplicate type id")
		}
		typeIDs.add(tid)
		pre := anlGet(t, "id_prefix")
		if !anlTruthy(pre) || prefixes.has(pre) {
			bad("dup_prefix", tid, "id prefix empty or reused")
		}
		prefixes.add(pre)
	}
	units := anlGet(o, "units")
	for _, e := range goalOntologyEntries(units) {
		d := e.v
		exp := anlGet(d, "exponent")
		if goalOntologyIs(anlGet(d, "kind"), "money") {
			f, _ := jsNum(exp)
			if !(goalOntologyIsInteger(exp) && f >= 0 && f <= 4) {
				bad("unit_exponent", e.k, "money unit needs an integer exponent 0..4")
			}
		}
		if !goalOntologyIs(anlGet(d, "kind"), "money") && !anlIsUndef(exp) {
			bad("unit_exponent", e.k, "only money units carry an exponent")
		}
	}
	relIDs := goalOntologyNewSet()
	for _, r := range goalOntologyIter(anlGet(o, "relations")) {
		rid := anlGet(r, "id")
		if relIDs.has(rid) {
			bad("dup_relation", rid, "duplicate relation")
		}
		relIDs.add(rid)
		if !typeIDs.has(anlGet(r, "from")) || !typeIDs.has(anlGet(r, "to")) {
			bad("relation_type", rid, "relation endpoint type is not declared")
		}
	}
	verbIDs := goalOntologyNewSet()
	verbs := map[any]any{}
	for _, v := range goalOntologyIter(anlGet(o, "verbs")) {
		vid := anlGet(v, "id")
		if verbIDs.has(vid) {
			bad("dup_verb", vid, "duplicate verb")
		}
		verbIDs.add(vid)
		verbs[goalOntologyKey(vid)] = v
		if !anlIncludes(goalEffectClasses, anlGet(v, "effect")) {
			bad("no_effect_class", vid, "verb has no valid effect class")
		}
		if !typeIDs.has(anlGet(v, "resource_type")) {
			bad("verb_resource_type", vid, "resource type is not declared")
		}
		for _, pe := range goalOntologyEntries(anlGet(v, "params")) {
			pt, kind := pe.v, anlGet(pe.v, "kind")
			w := anlJS(vid) + "." + pe.k
			switch {
			case goalOntologyIs(kind, "money"):
				ccys := anlGet(pt, "ccys")
				if !goalOntologyLenPos(ccys) {
					bad("param_ccy", w, "money parameter lists no currency")
				}
				if !(anlIsUndef(ccys) || ccys == nil) {
					for _, c := range goalOntologyIter(ccys) {
						var u any = anlUndef
						if _, ok := c.(string); ok {
							u = goalOntologyOwn(units, c)
						}
						if !goalOntologyIs(anlOget(u, "kind"), "money") {
							bad("unit_unknown", w, "currency "+anlJS(c)+" is not a declared money unit")
						}
					}
				}
			case goalOntologyIs(kind, "enum"):
				if !goalOntologyLenPos(anlGet(pt, "values")) {
					bad("param_enum", w, "enum parameter has no values")
				}
			case goalOntologyIs(kind, "id"):
				of := anlGet(pt, "of")
				if !anlTruthy(of) || !typeIDs.has(of) {
					bad("param_type", w, "id parameter type is not declared")
				}
			case !goalOntologyIs(kind, "text"):
				any_ := false
				for _, u := range goalOntologyValues(units) {
					if anlStrictEq(anlGet(u, "kind"), kind) {
						any_ = true
						break
					}
				}
				if !any_ {
					bad("unit_unknown", w, "no declared unit of kind "+anlJS(kind))
				}
			}
		}
	}
	seen := map[string]string{}
	aliases := anlGet(o, "aliases")
	for _, e := range goalOntologyEntries(aliases) {
		k, target := e.k, e.v
		nonPrintable := strings.IndexFunc(k, func(r rune) bool { return r < 0x20 || r > 0x7e }) >= 0
		if k != goalOntologyNorm(k) || (nonPrintable && k != norm.NFKC.String(k)) {
			bad("alias_key", k, "alias key is not in normalized form")
		}
		if goalOntologyHasInvis(k) {
			bad("alias_key", k, "alias key contains invisible characters")
		}
		n := goalOntologyNorm(k)
		if prev, ok := seen[n]; ok && prev != k {
			bad("alias_collision", k, "collides with "+prev+" after normalization")
		}
		seen[n] = k
		if !verbIDs.has(target) {
			bad("alias_target", k, "alias target is not a canonical verb")
		}
		if ts, ok := target.(string); ok {
			if am, ok := aliases.(map[string]any); ok {
				if _, has := am[ts]; has {
					bad("alias_chain", k, "alias target is itself an alias (chain or cycle)")
				}
			}
		}
		if verbIDs.has(k) && !goalOntologyIs(target, k) {
			bad("alias_shadow", k, "alias shadows a canonical verb")
		}
	}
	tids := goalOntologyNewSet()
	for _, t := range anlReqList(anlGet(o, "templates")) {
		tid := anlGet(t, "id")
		w := "template:" + anlJS(tid)
		if tids.has(tid) {
			bad("dup_template", w, "duplicate template id")
		}
		tids.add(tid)
		slots := anlReqList(anlGet(t, "slots"))
		slotNames := goalOntologyNewSet()
		for _, s := range slots {
			slotNames.add(anlGet(s, "name"))
		}
		if slotNames.size() != len(slots) {
			bad("dup_slot", w, "duplicate slot")
		}
		for _, r := range goalOntologySlotRefs(t) {
			if !slotNames.has(r) {
				bad("slot_undeclared", w, "slot "+anlJS(r)+" is used but not declared")
			}
		}
		for _, s := range slots {
			sw := w + "." + anlJS(anlGet(s, "name"))
			sk := anlGet(s, "kind")
			if goalOntologyIs(sk, "id") || goalOntologyIs(sk, "id_list") {
				of := anlGet(s, "of")
				if !anlTruthy(of) || !typeIDs.has(of) {
					bad("slot_type", sw, "id slot type is not declared")
				}
			}
			if goalOntologyIs(sk, "money") {
				ccy := anlGet(s, "ccy")
				var u any = anlUndef
				if anlIsUndef(ccy) {
					u = goalOntologyOwn(units, "")
				} else if _, ok := ccy.(string); ok {
					u = goalOntologyOwn(units, ccy)
				}
				if !goalOntologyIs(anlOget(u, "kind"), "money") {
					bad("slot_ccy", sw, "money slot currency is not a declared unit")
				}
			}
			if (goalOntologyIs(sk, "enum") || goalOntologyIs(sk, "enum_list")) && !goalOntologyLenPos(anlGet(s, "values")) {
				bad("slot_enum", sw, "enum slot has no values")
			}
			if !anlTruthy(anlGet(s, "mandatory")) && anlIsUndef(anlGet(s, "default")) {
				bad("slot_default", sw, "optional slot needs a default (an unfilled slot must be a hole or a default)")
			}
			if !anlIncludes(goalOntologySlotRefs(t), anlGet(s, "name")) {
				bad("slot_unused", sw, "declared slot is never used")
			}
		}
		tgrants := anlReqList(anlGet(t, "grants"))
		tbounds := anlReqList(anlGet(t, "bounds"))
		if len(tgrants) == 0 {
			bad("empty_allow", w, "template has no grant (empty Allow set)")
		}
		gids := goalOntologyNewSet()
		for _, g := range tgrants {
			gids.add(anlGet(g, "gid"))
		}
		if gids.size() != len(tgrants) {
			bad("dup_gid", w, "duplicate grant id")
		}
		for _, g := range tgrants {
			v, ok := verbs[goalOntologyKey(anlGet(g, "verb"))]
			gw := w + "." + anlJS(anlGet(g, "gid"))
			if !ok {
				bad("grant_verb", gw, "grant verb is not in the ontology")
				continue
			}
			goalOntologyCheckResource(o, anlGet(g, "res"), v, gw, bad)
			goalOntologyCheckCond(anlGet(g, "cond"), v, t, gw, bad)
			res := anlGet(g, "res")
			if goalOntologyIs(anlGet(res, "k"), "any") && !(goalOntologyIs(anlGet(v, "effect"), "read") && len(tbounds) > 0) {
				bad("unbounded", gw, "wildcard resource in a template")
			}
			if !goalOntologyIs(anlGet(v, "effect"), "read") && goalOntologyIs(anlGet(res, "k"), "related") && len(tbounds) == 0 {
				bad("unbounded", gw, "non-read grant on a related set needs an aggregate bound")
			}
		}
		for _, p := range anlReqList(anlGet(t, "prohibits")) {
			tg := anlGet(p, "target")
			pw := w + "." + anlJS(anlGet(p, "pid"))
			if goalOntologyIs(anlGet(tg, "k"), "verb") {
				if _, ok := verbs[goalOntologyKey(anlGet(tg, "verb"))]; !ok {
					bad("prohibit_verb", pw, "prohibit verb is not in the ontology")
				}
			}
			if goalOntologyIs(anlGet(tg, "k"), "effect") && !anlIncludes(goalEffectClasses, anlGet(tg, "cls")) {
				bad("prohibit_effect", pw, "unknown effect class")
			}
		}
		for _, b := range tbounds {
			bw := w + "." + anlJS(anlGet(b, "bid"))
			over := anlGet(b, "over")
			if !anlStrictEq(over, "all") {
				unknown := false
				for _, x := range anlReqList(over) {
					if !gids.has(x) {
						unknown = true
						break
					}
				}
				if unknown {
					bad("bound_over", bw, "bound selects an unknown grant")
				}
			}
			csName := anlGet(b, "cap_slot")
			if anlTruthy(csName) && !slotNames.has(csName) {
				bad("slot_undeclared", w, "cap slot "+anlJS(csName)+" is not declared")
			}
			if anlTruthy(csName) {
				cs := goalOntologyFind(slots, func(x any) bool { return anlStrictEq(anlGet(x, "name"), csName) })
				if !anlIsUndef(cs) {
					csk, agg := anlGet(cs, "kind"), anlGet(b, "agg")
					if !(goalOntologyIs(csk, "money") || goalOntologyIs(csk, "count")) {
						bad("bound_cap", bw, "cap slot must be money or count")
					}
					if goalOntologyIs(agg, "count") && !goalOntologyIs(csk, "count") {
						bad("bound_cap", bw, "count bound needs a count slot")
					}
					if goalOntologyIs(agg, "sum") && !goalOntologyIs(csk, "money") {
						bad("bound_cap", bw, "sum bound over money needs a money slot")
					}
				}
			}
			if goalOntologyIs(anlGet(b, "agg"), "sum") && !anlTruthy(anlGet(b, "param")) {
				bad("bound_value", bw, "sum bound has no value parameter")
			}
		}
		// non-empty and bounded after instantiation with the declared example
		g := goalInstantiateTemplate(o, tid, anlGet(t, "example"), map[string]any{"principal": "p", "nl": ""})
		holes := g["holes"].([]any)
		switch {
		case len(holes) > 0:
			ids := make([]string, len(holes))
			for i, h := range holes {
				s, ok := h.(map[string]any)["hid"].(string)
				if !ok {
					anlFail("sequence item: expected str instance")
				}
				ids[i] = s
			}
			bad("example_holes", w, "example leaves holes: "+strings.Join(ids, ","))
		case len(g["grants"].([]any)) != len(tgrants):
			bad("empty_allow", w, "example instantiation dropped a grant")
		case !goalOntologyHasAllowWitness(o, g):
			bad("empty_allow", w, "instantiated template has an empty Allow set")
		}
	}
	return issues
}

func goalOntologyCheckResource(o any, s any, v any, w string, bad goalOntologyBad) {
	rt := anlGet(v, "resource_type")
	ty := goalOntologyFind(anlGet(o, "types"), func(t any) bool { return anlStrictEq(anlGet(t, "id"), rt) })
	prefix := anlOget(ty, "id_prefix")
	idOK := func(i any, pre any) bool {
		return goalOntologyStartsWith(i, "$") || (!anlIsUndef(pre) && goalOntologyStartsWith(i, pre))
	}
	switch k := anlGet(s, "k"); {
	case goalOntologyIs(k, "exact") && !idOK(anlGet(s, "id"), prefix):
		bad("resource_type", w, "exact resource id has the wrong type prefix")
	case goalOntologyIs(k, "oneof"):
		ids := anlReqList(anlGet(s, "ids"))
		if len(ids) == 0 {
			bad("resource_empty", w, "one_of is empty")
		}
		for _, i := range ids {
			if !idOK(i, prefix) {
				bad("resource_type", w, "one_of member has the wrong type prefix")
			}
		}
	case goalOntologyIs(k, "related"):
		rel := anlGet(s, "rel")
		r := goalOntologyFind(anlGet(o, "relations"), func(x any) bool { return anlStrictEq(anlGet(x, "id"), rel) })
		if anlIsUndef(r) {
			bad("relation_unknown", w, "relation "+anlJS(rel)+" is not declared")
		} else {
			if !anlStrictEq(anlGet(r, "to"), rt) {
				bad("relation_type", w, "relation target type differs from the verb resource type")
			}
			rf := anlGet(r, "from")
			anchorPre := anlOget(goalOntologyFind(anlGet(o, "types"), func(t any) bool { return anlStrictEq(anlGet(t, "id"), rf) }), "id_prefix")
			if !idOK(anlGet(s, "anchor"), anchorPre) {
				bad("resource_type", w, "relation anchor has the wrong type prefix")
			}
		}
	case goalOntologyIs(k, "all_of"):
		parts := anlReqList(anlGet(s, "parts"))
		if len(parts) < 2 {
			bad("all_of_arity", w, "all_of needs at least two parts")
		}
		for _, x := range parts {
			goalOntologyCheckResource(o, x, v, w, bad)
		}
	}
}

func goalOntologyCheckCond(c any, v any, t any, w string, bad goalOntologyBad) {
	k := anlGet(c, "k")
	if goalOntologyIs(k, "and") || goalOntologyIs(k, "or") {
		goalOntologyCheckCond(anlGet(c, "a"), v, t, w, bad)
		goalOntologyCheckCond(anlGet(c, "b"), v, t, w, bad)
		return
	}
	if goalOntologyIs(k, "not") {
		goalOntologyCheckCond(anlGet(c, "c"), v, t, w, bad)
		return
	}
	if !goalOntologyIs(k, "cmp") {
		return
	}
	l := anlGet(c, "l")
	var p any = anlUndef
	if goalOntologyIs(anlGet(l, "k"), "param") {
		p = goalOntologyOwn(anlGet(v, "params"), anlGet(l, "path"))
	}
	if !goalOntologyIs(anlGet(l, "k"), "param") || !anlTruthy(p) {
		bad("cond_param", w, "left side of a comparison must be a declared parameter of the verb")
		return
	}
	op := anlGet(c, "op")
	pk := anlGet(p, "kind")
	if (goalOntologyIs(op, "lt") || goalOntologyIs(op, "lte") || goalOntologyIs(op, "gt") || goalOntologyIs(op, "gte")) &&
		(goalOntologyIs(pk, "text") || goalOntologyIs(pk, "enum") || goalOntologyIs(pk, "id")) {
		bad("cond_order", w, "ordering on a text/enum/id parameter")
	}
	isIn := goalOntologyIs(op, "in") || goalOntologyIs(op, "nin")
	x := anlGet(c, "r")
	switch xk := anlGet(x, "k"); {
	case goalOntologyIs(xk, "slot"):
		sn := anlGet(x, "slot")
		s := goalOntologyFind(anlGet(t, "slots"), func(q any) bool { return anlStrictEq(anlGet(q, "name"), sn) })
		if anlIsUndef(s) {
			return
		}
		sk := anlGet(s, "kind")
		var okKind bool
		if goalOntologyIs(pk, "money") {
			okKind = goalOntologyIs(sk, "money")
		} else {
			okKind = anlStrictEq(pk, sk) || (goalOntologyIs(pk, "enum") && (goalOntologyIs(sk, "enum") || goalOntologyIs(sk, "enum_list"))) ||
				(goalOntologyIs(pk, "id") && (goalOntologyIs(sk, "id") || goalOntologyIs(sk, "id_list"))) ||
				(goalOntologyIs(pk, "text") && goalOntologyIs(sk, "text_list"))
		}
		if !okKind {
			bad("cond_type", w, "slot "+anlJS(anlGet(s, "name"))+" ("+anlJS(sk)+") does not type-check against parameter kind "+anlJS(pk))
		}
		ccys := anlGet(p, "ccys")
		scc := anlGet(s, "ccy")
		if goalOntologyIs(pk, "money") && goalOntologyIs(sk, "money") {
			var probe any = scc
			if anlIsUndef(scc) {
				probe = ""
			}
			if !(!anlIsUndef(ccys) && anlIncludes(ccys, probe)) {
				bad("cond_unit", w, "slot currency is not accepted by the parameter")
			}
		}
		lst := goalOntologyIs(sk, "id_list") || goalOntologyIs(sk, "enum_list") || goalOntologyIs(sk, "text_list")
		if lst != isIn {
			bad("cond_type", w, "list slots pair with in/nin and scalar slots with the other operators")
		}
	case goalOntologyIs(xk, "lit"):
		lv := anlGet(x, "v")
		if goalOntologyIs(anlGet(lv, "k"), "set") {
			items := anlReqList(anlGet(lv, "items"))
			if len(items) == 0 {
				bad("cond_type", w, "empty literal list")
			}
			for _, i := range items {
				goalOntologyLitCheck(i, p, w, bad)
			}
			if !isIn {
				bad("cond_type", w, "a literal set pairs with in/nin")
			}
		} else {
			goalOntologyLitCheck(lv, p, w, bad)
			if isIn {
				bad("cond_type", w, "in/nin needs a list")
			}
		}
	default:
		bad("cond_term", w, "unsupported right-hand term")
	}
}

func goalOntologyLitCheck(l any, p any, w string, bad goalOntologyBad) {
	pk := anlGet(p, "kind")
	switch k := anlGet(l, "k"); {
	case goalOntologyIs(k, "q"):
		u := anlGet(anlGet(l, "q"), "u")
		if !anlStrictEq(anlGet(u, "k"), pk) {
			bad("cond_type", w, "literal kind differs from the parameter kind")
		}
		ccys := anlGet(p, "ccys")
		if goalOntologyIs(anlGet(u, "k"), "money") && !(!anlIsUndef(ccys) && anlIncludes(ccys, anlGet(u, "ccy"))) {
			bad("cond_unit", w, "literal currency is not accepted by the parameter")
		}
	case goalOntologyIs(k, "s"):
		if !goalOntologyIs(pk, "enum") && !goalOntologyIs(pk, "id") && !goalOntologyIs(pk, "text") {
			bad("cond_type", w, "literal kind differs from the parameter kind")
		}
		vals := anlGet(p, "values")
		if goalOntologyIs(pk, "enum") && !(!anlIsUndef(vals) && anlIncludes(vals, anlGet(l, "s"))) {
			bad("cond_enum", w, "enum literal is not a member")
		}
	default:
		bad("cond_type", w, "nested literal set")
	}
}

// goalOntologyHasAllowWitness is a cheap Allow witness for the checker: every grant admits some case.
func goalOntologyHasAllowWitness(o any, g map[string]any) bool {
	ont := goalOntologyForGoal(o, g, nil)
	for _, gr := range g["grants"].([]any) {
		w := reflect.ValueOf(goalAllowWitness(g, gr, ont))
		if !w.IsValid() || ((w.Kind() == reflect.Map || w.Kind() == reflect.Pointer || w.Kind() == reflect.Slice || w.Kind() == reflect.Interface) && w.IsNil()) {
			return false
		}
	}
	return true
}

// goalOntologyQuantityOf is the typed quantity of a slot value, or nil.
func goalOntologyQuantityOf(s any, v any) map[string]any {
	switch v.(type) {
	case string, []any:
		return nil
	}
	m, ok := v.(map[string]any)
	if !ok {
		anlFail("cannot use 'in' operator on a non-object")
	}
	kind := anlGet(s, "kind")
	okN := func(n any, signed bool) bool {
		f, _ := jsNum(n)
		return jsIsInt(n) && (signed || f >= 0)
	}
	if n, has := m["minor"]; has && goalOntologyIs(kind, "money") && anlStrictEq(anlOwn(m, "ccy"), anlGet(s, "ccy")) && okN(n, false) {
		return map[string]any{"u": map[string]any{"k": "money", "ccy": m["ccy"]}, "n": n}
	}
	if n, has := m["n"]; has && goalOntologyIs(kind, "count") && okN(n, false) {
		return map[string]any{"u": map[string]any{"k": "count"}, "n": n}
	}
	if n, has := m["ms"]; has && goalOntologyIs(kind, "duration") && okN(n, false) {
		return map[string]any{"u": map[string]any{"k": "duration"}, "n": n}
	}
	if n, has := m["epoch_ms"]; has && goalOntologyIs(kind, "instant") && okN(n, true) {
		return map[string]any{"u": map[string]any{"k": "instant"}, "n": n}
	}
	return nil
}

func goalOntologySv(s any) map[string]any { return map[string]any{"k": "s", "s": s} }

func goalOntologyIDOK(x any, pre any) bool {
	return goalOntologyStartsWith(x, pre) && goalOntologyIDRE.MatchString(x.(string))
}

// goalSlotLits are the typed value(s) of a slot ([]any), or a reason string when it is missing / invalid (the slot then becomes a
// Hole), or nil for a kind the reference switch does not handle.
func goalSlotLits(o any, s any, v any) any {
	if anlIsUndef(v) {
		return "missing"
	}
	kind := anlGet(s, "kind")
	if goalOntologyIs(kind, "money") || goalOntologyIs(kind, "count") || goalOntologyIs(kind, "duration") || goalOntologyIs(kind, "instant") {
		q := goalOntologyQuantityOf(s, v)
		if q == nil {
			return "ill-typed"
		}
		if mx := anlGet(s, "max"); !anlIsUndef(mx) {
			var n any = q["n"]
			if goalOntologyIs(kind, "instant") {
				n = goalNum(0)
			}
			if anlGt(n, mx) {
				return "above the template maximum"
			}
		}
		return []any{map[string]any{"k": "q", "q": q}}
	}
	if goalOntologyIs(kind, "id") || goalOntologyIs(kind, "id_list") {
		of := anlGet(s, "of")
		pre := anlOget(goalOntologyFind(anlGet(o, "types"), func(t any) bool { return anlStrictEq(anlGet(t, "id"), of) }), "id_prefix")
		if goalOntologyIs(kind, "id") {
			if vs, ok := v.(string); ok && anlTruthy(pre) && goalOntologyStartsWith(vs, pre) && jsLen(vs) > jsLen(pre.(string)) && goalOntologyIDRE.MatchString(vs) {
				return []any{goalOntologySv(vs)}
			}
			return "ill-typed"
		}
		if l, ok := v.([]any); ok && len(l) > 0 {
			all := true
			for _, x := range l {
				if !(anlTruthy(pre) && goalOntologyIDOK(x, pre)) {
					all = false
					break
				}
			}
			if all {
				out := make([]any, len(l))
				for i, x := range l {
					out[i] = goalOntologySv(x)
				}
				return out
			}
		}
		return "ill-typed"
	}
	vals := anlGet(s, "values")
	if goalOntologyIs(kind, "enum") {
		if vs, ok := v.(string); ok && !anlIsUndef(vals) && anlIncludes(vals, vs) {
			return []any{goalOntologySv(vs)}
		}
		return "ill-typed"
	}
	if goalOntologyIs(kind, "enum_list") || goalOntologyIs(kind, "text_list") {
		l, ok := v.([]any)
		if !ok || len(l) == 0 {
			return "ill-typed"
		}
		for _, x := range l {
			if goalOntologyIs(kind, "enum_list") {
				if anlIsUndef(vals) || !anlIncludes(vals, x) {
					return "ill-typed"
				}
			} else if xs, isStr := x.(string); !isStr || len(xs) == 0 || xs != norm.NFKC.String(xs) || goalOntologyHasInvis(xs) {
				return "ill-typed"
			}
		}
		out := make([]any, len(l))
		for i, x := range l {
			out[i] = goalOntologySv(x)
		}
		return out
	}
	return nil // the reference switch has no default
}

func goalOntologyIsListSlot(t any, name any) bool {
	s := goalOntologyFind(anlGet(t, "slots"), func(x any) bool { return anlStrictEq(anlGet(x, "name"), name) })
	var k any = ""
	if !anlIsUndef(s) && !anlIsUndef(anlGet(s, "kind")) {
		k = anlGet(s, "kind")
	}
	ks, ok := k.(string)
	return ok && strings.HasSuffix(ks, "_list")
}

// goalOntologyIdx is d[k] of a dict (a missing key throws, as KeyError).
func goalOntologyIdx(d any, k string) any {
	m, ok := d.(map[string]any)
	if ok {
		if v, has := m[k]; has {
			return v
		}
	}
	anlFail("KeyError: %s", k)
	return nil
}

// goalInstantiateTemplate: Template -> Goal (IR, canonical order). Mandatory slots that are missing or ill-typed become Holes; every
// clause depending on a hole is dropped (the most restrictive completion); a prohibition that depends on a hole widens to every
// resource. Limits become IR bounds over the surviving grants (admitting grant, lifetime window, session scope).
func goalInstantiateTemplate(o any, templateID any, values any, opts any) map[string]any {
	t := goalOntologyFind(anlGet(o, "templates"), func(x any) bool { return anlStrictEq(anlGet(x, "id"), templateID) })
	if anlIsUndef(t) {
		anlFail("unknown template %s", anlJS(templateID))
	}
	bound := map[any]any{}
	holes := []any{}
	for _, s := range anlReqList(anlGet(t, "slots")) {
		name := anlGet(s, "name")
		v := goalOntologyOwn(values, name)
		if v == nil || anlIsUndef(v) {
			v = anlGet(s, "default")
		}
		r := goalSlotLits(o, s, v)
		if reason, ok := r.(string); ok {
			ccy := anlGet(s, "ccy")
			extra := ""
			if anlTruthy(ccy) {
				extra = " " + anlJS(ccy)
			}
			holes = append(holes, map[string]any{
				"hid":    name,
				"q":      "What is the " + strings.ReplaceAll(anlJS(name), "_", " ") + " (" + anlJS(anlGet(s, "kind")) + extra + ")? (" + reason + ")",
				"domain": []any{}, "affects": []any{}, "global": false})
		} else {
			bound[goalOntologyKey(name)] = r
		}
	}
	deps := func(refs []any) bool {
		for _, r := range refs {
			if _, ok := bound[goalOntologyKey(r)]; !ok {
				return false
			}
		}
		return true
	}
	single := func(name any) any {
		l, ok := bound[goalOntologyKey(name)].([]any)
		if !ok || len(l) == 0 {
			anlFail("single: no slot value")
		}
		return l[0]
	}
	sub := func(i any) any {
		if goalOntologyStartsWith(i, "$") {
			return goalOntologyIdx(single(i.(string)[1:]), "s")
		}
		return i
	}
	subPart := func(r any) any {
		switch k := anlGet(r, "k"); {
		case goalOntologyIs(k, "exact"):
			return map[string]any{"k": "exact", "id": sub(anlGet(r, "id"))}
		case goalOntologyIs(k, "oneof"):
			ids := []any{}
			for _, i := range anlReqList(anlGet(r, "ids")) {
				ids = append(ids, sub(i))
			}
			return map[string]any{"k": "oneof", "ids": ids}
		}
		a := sub(anlGet(r, "anchor"))
		m, ok := r.(map[string]any)
		if !ok {
			anlFail("dict() argument is not a mapping")
		}
		c := anlCopy(m)
		c["anchor"] = a
		return c
	}
	subRes := func(r any) any {
		switch k := anlGet(r, "k"); {
		case goalOntologyIs(k, "any"):
			return r
		case goalOntologyIs(k, "all_of"):
			parts := []any{}
			for _, p := range anlReqList(anlGet(r, "parts")) {
				parts = append(parts, subPart(p))
			}
			return map[string]any{"k": "all_of", "parts": parts}
		}
		return subPart(r)
	}
	verbOf := map[any]any{}
	for _, v := range anlReqList(anlGet(o, "verbs")) {
		if _, ok := verbOf[goalOntologyKey(anlGet(v, "id"))]; !ok {
			verbOf[goalOntologyKey(anlGet(v, "id"))] = v
		}
	}
	tyOf := func(verb any, path any, ccy any) any {
		var p any = anlUndef
		if verb != nil {
			if vv, ok := verbOf[goalOntologyKey(verb)]; ok {
				p = goalOntologyOwn(anlGet(vv, "params"), path)
			}
		}
		if anlIsUndef(p) {
			for _, v := range anlReqList(anlGet(o, "verbs")) {
				if x := goalOntologyOwn(anlGet(v, "params"), path); !anlIsUndef(x) {
					p = x
					break
				}
			}
		}
		if anlIsUndef(p) {
			anlFail("parameter %s is not declared by any verb", anlJS(path))
		}
		return goalOntologyParamTy(p, ccy)
	}
	lit := func(x any) any {
		k := anlGet(x, "k")
		if goalOntologyIs(k, "slot") {
			l, ok := bound[goalOntologyKey(anlGet(x, "slot"))].([]any)
			if !ok || len(l) == 0 {
				anlFail("KeyError: slot")
			}
			if goalOntologyIsListSlot(t, anlGet(x, "slot")) {
				return map[string]any{"k": "lit", "v": map[string]any{"k": "set", "items": l}}
			}
			return map[string]any{"k": "lit", "v": l[0]}
		}
		if goalOntologyIs(k, "lit") {
			return map[string]any{"k": "lit", "v": anlGet(x, "v")}
		}
		return nil
	}
	ccyOf := func(x any) any {
		if x != nil && goalOntologyIs(anlGet(x, "k"), "lit") && goalOntologyIs(anlGet(anlGet(x, "v"), "k"), "q") &&
			goalOntologyIs(anlGet(anlGet(anlGet(anlGet(x, "v"), "q"), "u"), "k"), "money") {
			return anlGet(anlGet(anlGet(anlGet(x, "v"), "q"), "u"), "ccy")
		}
		return nil
	}
	var subCond func(c any, verb any) any
	subCond = func(c any, verb any) any {
		k := anlGet(c, "k")
		switch {
		case goalOntologyIs(k, "true"):
			return c
		case goalOntologyIs(k, "and") || goalOntologyIs(k, "or"):
			return map[string]any{"k": k, "a": subCond(anlGet(c, "a"), verb), "b": subCond(anlGet(c, "b"), verb)}
		case goalOntologyIs(k, "not"):
			return map[string]any{"k": "not", "c": subCond(anlGet(c, "c"), verb)}
		}
		lv, rv := lit(anlGet(c, "l")), lit(anlGet(c, "r"))
		hint := ccyOf(lv)
		if hint == nil {
			hint = ccyOf(rv)
		}
		term := func(x any, v any) any {
			if v != nil {
				return v
			}
			path := anlGet(x, "path")
			return map[string]any{"k": "param", "path": path, "ty": tyOf(verb, path, hint)}
		}
		op := anlGet(c, "op")
		l := term(anlGet(c, "l"), lv)
		r := term(anlGet(c, "r"), rv)
		return map[string]any{"k": "cmp", "op": op, "l": l, "r": r}
	}
	dropped := goalOntologyNewSet()
	grants := []any{}
	tBounds := anlReqList(anlGet(t, "bounds"))
	tGrants := anlReqList(anlGet(t, "grants"))
	keepBound := []any{}
	for _, b := range tBounds {
		if deps(goalOntologyRefsBound(b)) {
			keepBound = append(keepBound, b)
		}
	}
	for _, b := range tBounds {
		if !deps(goalOntologyRefsBound(b)) {
			for _, g := range tGrants {
				over := anlGet(b, "over")
				if anlStrictEq(over, "all") || anlIncludes(over, anlGet(g, "gid")) {
					dropped.add(anlGet(g, "gid"))
				}
			}
		}
	}
	for _, g := range tGrants {
		if dropped.has(anlGet(g, "gid")) || !deps(goalOntologyRefsGrant(g)) {
			dropped.add(anlGet(g, "gid"))
		} else {
			grants = append(grants, map[string]any{"gid": anlGet(g, "gid"), "verb": anlGet(g, "verb"), "res": subRes(anlGet(g, "res")), "cond": subCond(anlGet(g, "cond"), anlGet(g, "verb"))})
		}
	}
	prohibits := []any{}
	for _, p := range anlReqList(anlGet(t, "prohibits")) {
		tg := anlGet(p, "target")
		var verb any
		if goalOntologyIs(anlGet(tg, "k"), "verb") {
			verb = anlGet(tg, "verb")
		} else {
			cls := anlGet(tg, "cls")
			fv := goalOntologyFind(anlGet(o, "verbs"), func(v any) bool { return anlStrictEq(anlGet(v, "effect"), cls) })
			verb = anlOget(fv, "id")
			if anlIsUndef(verb) {
				verb = nil
			}
		}
		if deps(goalOntologyRefsGrant(p)) {
			prohibits = append(prohibits, map[string]any{"pid": anlGet(p, "pid"), "target": tg, "res": subRes(anlGet(p, "res")), "cond": subCond(anlGet(p, "cond"), verb)})
		} else {
			prohibits = append(prohibits, map[string]any{"pid": anlGet(p, "pid"), "target": tg, "res": map[string]any{"k": "any", "reason": "hole"}, "cond": map[string]any{"k": "true"}})
		}
	}
	kept := goalOntologyNewSet()
	for _, g := range grants {
		kept.add(g.(map[string]any)["gid"])
	}
	bounds := []any{}
	for _, b := range keepBound {
		over := anlGet(b, "over")
		gids := []any{}
		if anlStrictEq(over, "all") {
			for _, g := range grants {
				gids = append(gids, g.(map[string]any)["gid"])
			}
		} else {
			for _, x := range anlReqList(over) {
				if kept.has(x) {
					gids = append(gids, x)
				}
			}
		}
		if len(gids) == 0 {
			continue
		}
		cs := anlGet(b, "cap_slot")
		var capLit any
		if anlTruthy(cs) {
			capLit = single(cs)
		}
		var capV any
		if capLit != nil && goalOntologyIs(anlGet(capLit, "k"), "q") {
			capV = anlGet(capLit, "q")
		} else {
			capV = anlGet(b, "cap")
		}
		var verb any
		found := false
		for _, g := range grants {
			if gm := g.(map[string]any); anlStrictEq(gm["gid"], gids[0]) {
				verb, found = gm["verb"], true
				break
			}
		}
		if !found {
			anlFail("StopIteration")
		}
		agg := anlGet(b, "agg")
		capu := anlGet(capV, "u")
		var value any
		if goalOntologyIs(agg, "sum") {
			var ccy any
			if goalOntologyIs(anlGet(capu, "k"), "money") {
				ccy = anlGet(capu, "ccy")
			}
			value = map[string]any{"k": "param", "path": anlGet(b, "param"), "ty": tyOf(verb, anlGet(b, "param"), ccy)}
		} else {
			value = map[string]any{"k": "lit", "v": map[string]any{"k": "q", "q": map[string]any{"u": map[string]any{"k": "count"}, "n": goalNum(1)}}}
		}
		bounds = append(bounds, map[string]any{
			"bid": anlGet(b, "bid"), "sel": map[string]any{"k": "gids", "gids": gids}, "agg": agg, "value": value,
			"key": "", "window": map[string]any{"k": "lifetime"}, "scope": map[string]any{"k": "session"}, "cap": capV, "onExceed": anlGet(b, "onExceed")})
	}
	sources := []any{}
	if srcs := anlGet(opts, "sources"); !anlIsUndef(srcs) && srcs != nil {
		sources = append(sources, anlReqList(srcs)...)
	}
	return goalCanonicalizeGoal(map[string]any{
		"v": goalNum(1), "principal": anlGet(opts, "principal"), "ontDigest": goalOntologyDigest(o), "nlDigest": goalNlDigest(anlGet(opts, "nl")),
		"sources": sources, "grants": grants, "prohibits": prohibits, "bounds": bounds,
		"validity":   map[string]any{"notBefore": goalNum(0), "notAfter": goalNum(goalOntologyForever), "maxIdle": goalNum(0)},
		"deleg":      map[string]any{"maxDepth": goalNum(0), "narrowOnly": true, "mayTouch": []any{}},
		"escalateOn": []any{}, "wildcardAck": []any{}, "holes": holes})
}

// ---- locale-aware human number parsing (interpreter front end only; the IR has no locale) ---------------------------------

func goalOntologyIsNum(t string) bool {
	if t == "" || t[0] < '0' || t[0] > '9' {
		return false
	}
	for i := 0; i < len(t); i++ {
		if (t[i] < '0' || t[i] > '9') && t[i] != '.' && t[i] != ',' {
			return false
		}
	}
	return true
}

func goalOntologyFail(reason string) map[string]any {
	return map[string]any{"ok": false, "reason": reason}
}

// goalParseHumanAmount reads "1,000.50", "1.000,50", "$20", "20 dollars". Ambiguous literals ("1,000" with no locale hint, "1.000") are
// NOT guessed: they yield a failure and become a Hole. locale 'en' reads ',' as thousands, 'de' reads '.' as thousands.
func goalParseHumanAmount(text any, exponent int, locale any) map[string]any {
	ts, ok := text.(string)
	if !ok {
		anlFail("text.normalize is not a function")
	}
	var sb strings.Builder
	for _, c := range []byte(jsTrim(norm.NFKC.String(ts))) {
		if (c >= '0' && c <= '9') || c == '.' || c == ',' {
			sb.WriteByte(c)
		}
	}
	t := sb.String()
	if !goalOntologyIsNum(t) || strings.Contains(t, "..") || strings.Contains(t, ",,") || strings.Contains(t, ".,") || strings.Contains(t, ",.") {
		return goalOntologyFail("not a number")
	}
	lastDot, lastComma := strings.LastIndex(t, "."), strings.LastIndex(t, ",")
	dec, thou := "", ""
	if lastDot >= 0 && lastComma >= 0 {
		if lastDot > lastComma {
			dec, thou = ".", ","
		} else {
			dec, thou = ",", "."
		}
	} else if lastDot >= 0 || lastComma >= 0 {
		sep := ","
		if lastDot >= 0 {
			sep = "."
		}
		parts := strings.Split(t, sep)
		groupLike := len(parts) > 2 || len(parts[len(parts)-1]) == 3
		switch {
		case !groupLike:
			dec = sep
		case len(parts) > 2:
			thou = sep
		case anlTruthy(locale):
			if goalOntologyIs(locale, "en") == (sep == ",") {
				thou = sep
			} else {
				dec = sep
			}
		default:
			return goalOntologyFail("ambiguous separator")
		}
	}
	intPart, frac := t, ""
	if dec != "" {
		i := strings.LastIndex(t, dec)
		intPart, frac = t[:i], t[i+1:]
	}
	if thou != "" {
		groups := strings.Split(intPart, thou)
		bad := len(groups[0]) == 0 || len(groups[0]) > 3
		for _, g := range groups[1:] {
			if len(g) != 3 {
				bad = true
			}
		}
		if bad {
			return goalOntologyFail("malformed grouping")
		}
		intPart = strings.Join(groups, "")
	}
	if len(frac) > exponent {
		return goalOntologyFail("more decimals than the currency allows")
	}
	digits := intPart + frac
	if exponent > len(frac) {
		digits += strings.Repeat("0", exponent-len(frac))
	}
	if digits == "" || strings.Trim(digits, "0123456789") != "" {
		anlFail("invalid literal for int()")
	}
	digits = strings.TrimLeft(digits, "0")
	if len(digits) > 16 {
		return goalOntologyFail("out of range")
	}
	minor := int64(0)
	if digits != "" {
		minor, _ = strconv.ParseInt(digits, 10, 64)
	}
	if minor > goalOntologyForever {
		return goalOntologyFail("out of range")
	}
	return map[string]any{"ok": true, "minor": goalNum(minor)}
}

// goalParseMoney is the strict front-end contract over goalParseHumanAmount: only digits, '.' and ',' after one optional leading
// currency symbol; with a locale, a decimal separator that contradicts it is refused; without one, a repeated or ambiguous separator
// is a Hole, not a guess.
func goalParseMoney(text any, exponent int, locale any) map[string]any {
	t := jsTrim(anlJS(text))
	if r := []rune(t); len(r) > 0 && (r[0] == '$' || r[0] == '€' || r[0] == '£') {
		t = strings.TrimLeftFunc(string(r[1:]), isJSSpace)
	}
	if !goalOntologyIsNum(t) {
		return map[string]any{"error": "BAD_NUMBER"}
	}
	both := strings.Contains(t, ".") && strings.Contains(t, ",")
	if locale != nil && both {
		want := ","
		if goalOntologyIs(locale, "en") {
			want = "."
		}
		i := strings.LastIndex(t, ".")
		if j := strings.LastIndex(t, ","); j > i {
			i = j
		}
		if t[i:i+1] != want {
			return map[string]any{"error": "BAD_NUMBER"}
		}
	}
	if locale == nil && !both && strings.Count(t, ".")+strings.Count(t, ",") > 1 {
		return map[string]any{"hole": "AMBIGUOUS_NUMBER"}
	}
	r := goalParseHumanAmount(t, exponent, locale)
	if r["ok"] == true {
		return map[string]any{"minor": r["minor"]}
	}
	if r["reason"] == "ambiguous separator" {
		return map[string]any{"hole": "AMBIGUOUS_NUMBER"}
	}
	return map[string]any{"error": "BAD_NUMBER"}
}

// ---- exported, error-returning wrappers -----------------------------------------------------------------------------------

func GoalOntologyDigest(o any) (r string, err error) {
	_, err = anlTry(func() any { r = goalOntologyDigest(o); return nil })
	return
}

// GoalSignOntology signs an intent ontology (secret is a *KeyPair; the optional suite is a *SuiteOpts).
func GoalSignOntology(o any, kp *KeyPair, s *SuiteOpts) (r map[string]any, err error) {
	_, err = anlTry(func() any { r = goalSignOntology(o, kp, s); return nil })
	return
}

// GoalVerifyOntology verifies a signed intent ontology against the pinned signers.
func GoalVerifyOntology(s any, pins []any) bool { return goalVerifyOntology(s, pins) }

func GoalResolveVerb(o any, word any) (r any, err error) {
	_, err = anlTry(func() any { r = goalResolveVerb(o, word); return nil })
	return
}

func GoalCcy(g any) (r any, err error) {
	_, err = anlTry(func() any { r = goalGoalCcy(g); return nil })
	return
}

func GoalAnchors(g any) (r []any, err error) {
	_, err = anlTry(func() any { r = goalGoalAnchors(g); return nil })
	return
}

func GoalToIrOntology(o any, opts any) (r map[string]any, err error) {
	_, err = anlTry(func() any { r = goalToIrOntology(o, opts); return nil })
	return
}

func GoalOntologyForGoal(o any, g any, rels any) (r map[string]any, err error) {
	_, err = anlTry(func() any { r = goalOntologyForGoal(o, g, rels); return nil })
	return
}

func GoalCheckOntology(o any) (r []any, err error) {
	_, err = anlTry(func() any { r = goalCheckOntology(o); return nil })
	return
}

func GoalSlotLits(o any, s any, v any) (r any, err error) {
	_, err = anlTry(func() any { r = goalSlotLits(o, s, v); return nil })
	return
}

func GoalInstantiateTemplate(o any, templateID any, values any, opts any) (r map[string]any, err error) {
	_, err = anlTry(func() any { r = goalInstantiateTemplate(o, templateID, values, opts); return nil })
	return
}

func GoalParseHumanAmount(text any, exponent int, locale any) (r map[string]any, err error) {
	_, err = anlTry(func() any { r = goalParseHumanAmount(text, exponent, locale); return nil })
	return
}

func GoalParseMoney(text any, exponent int, locale any) (r map[string]any, err error) {
	_, err = anlTry(func() any { r = goalParseMoney(text, exponent, locale); return nil })
	return
}
