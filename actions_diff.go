package pca

// Action-def id patterns and semantic diffs: whether one resource id pattern contains another, how a new version of an action
// definition relates to the old one (equal / narrow / widen / incomparable, per dimension), the authoring diff that flags breaking
// changes, and the per-verb diff of two packs. Definitions are JSON objects (map[string]any); both versions must have passed
// validation.

import (
	"errors"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
)

var actionsUUIDRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func adIDParts(p any) (prefix, class string, lo, hi int) {
	m, _ := p.(map[string]any)
	prefix, _ = m["prefix"].(string)
	class, _ = m["class"].(string)
	if ln, ok := m["len"].([]any); ok && len(ln) == 2 {
		lo, hi = int(jsF(ln[0])), int(jsF(ln[1]))
	}
	return
}

func adExact(p any) (string, bool) {
	m, ok := p.(map[string]any)
	if !ok {
		return "", false
	}
	e, has := m["exact"]
	s, _ := e.(string)
	return s, has
}

// ActionIDMatches is whether id is a member of the id pattern p ("*", {exact} or {prefix, class, len}).
func ActionIDMatches(p any, id string) bool {
	if s, ok := p.(string); ok && s == "*" {
		return len(id) > 0 && len(id) <= 128 && inIDClass(id, "any_safe")
	}
	if e, ok := adExact(p); ok {
		return id == e
	}
	prefix, class, lo, hi := adIDParts(p)
	if !strings.HasPrefix(id, prefix) {
		return false
	}
	rest := id[len(prefix):]
	if len(rest) < lo || len(rest) > hi {
		return false
	}
	if class == "uuid" {
		return actionsUUIDRe.MatchString(rest)
	}
	return inIDClass(rest, class)
}

func adClassSubset(a, b string) bool {
	for _, r := range idClassChars[a] {
		if !strings.ContainsRune(idClassChars[b], r) {
			return false
		}
	}
	return true
}

// ActionIDPatternContains is whether every id of inner is also an id of outer. Sound, not complete.
func ActionIDPatternContains(outer, inner any) bool {
	if s, ok := outer.(string); ok && s == "*" {
		return true
	}
	if s, ok := inner.(string); ok && s == "*" {
		return false
	}
	if oe, ok := adExact(outer); ok {
		ie, iok := adExact(inner)
		return iok && ie == oe
	}
	if ie, ok := adExact(inner); ok {
		return ActionIDMatches(outer, ie)
	}
	op, oc, olo, ohi := adIDParts(outer)
	ip, ic, ilo, ihi := adIDParts(inner)
	if !strings.HasPrefix(ip, op) {
		return false
	}
	r := ip[len(op):]
	if !inIDClass(r, oc) {
		return false
	}
	if oc == "uuid" {
		return ic == "uuid" && r == ""
	}
	if !adClassSubset(ic, oc) {
		return false
	}
	return len(r)+ilo >= olo && len(r)+ihi <= ohi
}

// ---- semantic diff (relation of the NEW value to the OLD one, per dimension) -----------------------------------------------------------

type adRel string

const (
	relEq     adRel = "eq"
	relNarrow adRel = "narrow"
	relWiden  adRel = "widen"
	relInc    adRel = "inc"
)

func adSetRel(oldS, newS []string) adRel {
	o, n := map[string]bool{}, map[string]bool{}
	for _, x := range oldS {
		o[x] = true
	}
	for _, x := range newS {
		n[x] = true
	}
	added, removed := false, false
	for x := range n {
		added = added || !o[x]
	}
	for x := range o {
		removed = removed || !n[x]
	}
	switch {
	case added && removed:
		return relInc
	case added:
		return relNarrow
	case removed:
		return relWiden
	}
	return relEq
}

// adRankRel: more restrictive = larger.
func adRankRel(o, n int) adRel {
	switch {
	case n == o:
		return relEq
	case n > o:
		return relNarrow
	}
	return relWiden
}

// adSameJSON is the reference's sameJson: JSON.stringify of both values with every object's keys sorted first (recursively), so
// key order is not meaning (absent === absent). The sorted object a JavaScript object literal builds puts array-index keys first,
// ascending, then the others in code unit order; arrays keep their order.
func adSameJSON(a any, aHas bool, b any, bHas bool) bool {
	if !aHas || !bHas {
		return aHas == bHas
	}
	var x, y strings.Builder
	if adStringifySorted(&x, a) != nil || adStringifySorted(&y, b) != nil {
		return false
	}
	return x.String() == y.String()
}

func adStringifySorted(sb *strings.Builder, v any) error {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		var idx, rest []string
		for _, k := range keys {
			if _, ok := jsArrayIndex(k); ok {
				idx = append(idx, k)
			} else {
				rest = append(rest, k)
			}
		}
		sort.Slice(idx, func(i, j int) bool { a, _ := jsArrayIndex(idx[i]); b, _ := jsArrayIndex(idx[j]); return a < b })
		keys = append(idx, jsSortStrings(rest)...)
		sb.WriteByte('{')
		first := true
		for _, k := range keys {
			if anlIsUndef(t[k]) { // JSON.stringify drops an undefined member
				continue
			}
			if !first {
				sb.WriteByte(',')
			}
			first = false
			ks, _ := canonicalLenient(k)
			sb.WriteString(ks + ":")
			if err := adStringifySorted(sb, t[k]); err != nil {
				return err
			}
		}
		sb.WriteByte('}')
	case eatOrdered:
		m := make(map[string]any, len(t))
		for _, kv := range t {
			m[kv.k] = kv.v
		}
		return adStringifySorted(sb, m)
	case []any:
		sb.WriteByte('[')
		for i, x := range t {
			if i > 0 {
				sb.WriteByte(',')
			}
			if err := adStringifySorted(sb, x); err != nil {
				return err
			}
		}
		sb.WriteByte(']')
	default:
		return eatStringify(sb, v)
	}
	return nil
}

func adOpt(m map[string]any, k string) (any, bool) {
	v, has := m[k]
	return v, has
}

// adNum is `m[k] ?? def` over a number member.
func adNum(m map[string]any, k string, def float64) float64 {
	if v, has := m[k]; has && v != nil {
		if f, ok := jsNum(v); ok {
			return f
		}
	}
	return def
}

func adStrs(m map[string]any, k string) []string {
	s, _ := strsOf(m[k])
	return s
}

func adStrEq(m map[string]any, k string, n map[string]any) bool {
	a, ah := m[k]
	b, bh := n[k]
	return adSameJSON(a, ah, b, bh)
}

func adDomainContains(outer, inner map[string]any) bool {
	ot, _ := outer["type"].(string)
	it, _ := inner["type"].(string)
	if ot != it {
		return false
	}
	inf := math.Inf(1)
	switch ot {
	case "string", "object_ref":
		if adNum(inner, "max_len", 1024) > adNum(outer, "max_len", 1024) {
			return false
		}
		if ov, has := outer["values"]; has && ov != nil {
			iv, ihas := inner["values"]
			if !ihas || iv == nil {
				return false
			}
			os, _ := strsOf(ov)
			is, _ := strsOf(iv)
			for _, v := range is {
				if !contains(os, v) {
					return false
				}
			}
		}
		of, has := outer["format"]
		if !has {
			return true
		}
		inf2, ihas := inner["format"]
		return ihas && jsStrictEq(inf2, of)
	case "integer":
		return adNum(inner, "min", -inf) >= adNum(outer, "min", -inf) && adNum(inner, "max", inf) <= adNum(outer, "max", inf)
	case "duration":
		return math.Max(adNum(inner, "min", 0), 0) >= math.Max(adNum(outer, "min", 0), 0) && adNum(inner, "max", inf) <= adNum(outer, "max", inf)
	case "set":
		ov, iv := adStrs(outer, "values"), adStrs(inner, "values")
		for _, v := range iv {
			if !contains(ov, v) {
				return false
			}
		}
		oMax := math.Min(adNum(outer, "max_items", float64(len(ov))), float64(len(ov)))
		iMax := math.Min(adNum(inner, "max_items", float64(len(iv))), float64(len(iv)))
		return adNum(inner, "min_items", 0) >= adNum(outer, "min_items", 0) && iMax <= oMax
	case "array":
		oi, ii := "string", "string"
		if s, ok := outer["items"].(string); ok {
			oi = s
		}
		if s, ok := inner["items"].(string); ok {
			ii = s
		}
		if oi != ii {
			return false
		}
		if adNum(inner, "min_items", 0) < adNum(outer, "min_items", 0) || adNum(inner, "max_items", 64) > adNum(outer, "max_items", 64) {
			return false
		}
		if outer["items"] == "integer" {
			return adNum(inner, "min", -inf) >= adNum(outer, "min", -inf) && adNum(inner, "max", inf) <= adNum(outer, "max", inf)
		}
		return adNum(inner, "max_len", 1024) <= adNum(outer, "max_len", 1024)
	}
	return true // boolean, date, datetime: no domain members
}

// adCallsContained: is every call conforming to inner also conforming to outer (closed world, required members, domains)?
func adCallsContained(outer, inner map[string]any) bool {
	for name, ipv := range inner {
		opv, has := outer[name]
		if !has {
			return false
		}
		op, _ := opv.(map[string]any)
		ip, _ := ipv.(map[string]any)
		if !adDomainContains(op, ip) {
			return false
		}
	}
	for name, opv := range outer {
		op, _ := opv.(map[string]any)
		if op["required"] != true {
			continue
		}
		ipv, has := inner[name]
		ip, _ := ipv.(map[string]any)
		if !has || ip["required"] != true {
			return false
		}
	}
	return true
}

func adCallSetRel(oldP, newP map[string]any) adRel {
	sub := adCallsContained(oldP, newP)
	sup := adCallsContained(newP, oldP)
	switch {
	case sub && sup:
		return relEq
	case sub:
		return relNarrow
	case sup:
		return relWiden
	}
	return relInc
}

func adProvRank(p map[string]any) int {
	v, has := p["provenance_min"]
	if !has {
		return len(provenanceLevels) - 1
	}
	for i, l := range provenanceLevels {
		if v == l {
			return i
		}
	}
	return -1
}

var (
	adScopeRank = map[string]int{"one": 0, "set": 1, "tenant": 2, "global": 3}
	adIdemRank  = map[string]int{"none": 0, "natural": 1, "key_param": 2}
)

type adAttr struct {
	k string
	r adRel
}

func adParamAttrRels(o, n map[string]any) []adAttr {
	var out []adAttr
	if !adStrEq(o, "role", n) {
		out = append(out, adAttr{"role", relInc})
	}
	os, _ := o["sensitivity"].(string)
	ns, _ := n["sensitivity"].(string)
	out = append(out, adAttr{"sensitivity", adRankRel(sensitivityRank[os], sensitivityRank[ns])})
	out = append(out, adAttr{"tags", adSetRel(adStrs(o, "tags"), adStrs(n, "tags"))})
	out = append(out, adAttr{"provenance_min", adRankRel(-adProvRank(o), -adProvRank(n))})
	if !adStrEq(o, "unit", n) {
		out = append(out, adAttr{"unit", relInc})
	}
	out = append(out, adAttr{"accumulates", adSetRel(adStrs(o, "accumulates"), adStrs(n, "accumulates"))})
	if !adStrEq(o, "default", n) || !adStrEq(o, "principal_neutral_default", n) {
		out = append(out, adAttr{"default", relInc})
	}
	return out
}

// ActionDiffConfirmed says whether a definition's attestation is valid for exactly that definition (ReviewOpts.attestationVerified);
// nil = never (an unconfirmed def has the top of the registry as its effective traits).
type ActionDiffConfirmed func(def map[string]any) bool

type adEff struct {
	confirmed bool
	traits    []string // T(d): the hint traits when confirmed, else every trait of the registry
	closure   []string
	eff       Profile
	hintCl    []string
	hintEff   Profile
}

func adEffective(d map[string]any, reg Registry, confirmed ActionDiffConfirmed) (adEff, error) {
	hint := hintTraits(d)
	hintCl, err := reg.closure(hint)
	if err != nil {
		return adEff{}, err
	}
	hfl, _ := reg.floorOf(hint)
	hintEff := joinProfile(declProfile(d), hfl)
	ok := confirmed != nil && confirmed(d)
	tr := topTraits(reg)
	if ok {
		tr = hint
	}
	cl, err := reg.closure(tr)
	if err != nil {
		return adEff{}, err
	}
	fl, _ := reg.floorOf(tr)
	return adEff{confirmed: ok, traits: tr, closure: cl, eff: joinProfile(declProfile(d), fl), hintCl: hintCl, hintEff: hintEff}, nil
}

func adProfRel(a, b Profile) adRel {
	if leqProfile(a, b) {
		if leqProfile(b, a) {
			return relEq
		}
		return relNarrow
	}
	if leqProfile(b, a) {
		return relWiden
	}
	return relInc
}

func adSortU16(xs []string) { sort.Slice(xs, func(i, j int) bool { return u16Less(xs[i], xs[j]) }) }

// ActionDiffDefs is the semantic diff of next against prev (two versions of one verb): {class, reasons} with one reason line per
// differing dimension (`<dimension>: <narrow|widen|incomparable|text>`). Two different verbs are a `diff_verb` error.
func ActionDiffDefs(prev, next map[string]any, reg Registry, confirmed ActionDiffConfirmed) (map[string]any, error) {
	if prev["verb"] != next["verb"] {
		return nil, &CodedError{Code: "diff_verb", Msg: fmt.Sprintf("diff compares two versions of one verb, not '%s' and '%s'", jsAnyString(prev["verb"]), jsAnyString(next["verb"]))}
	}
	o, n := normalizeDef(prev), normalizeDef(next)
	op, _ := o["params"].(map[string]any)
	np, _ := n["params"].(map[string]any)
	var rels []adAttr
	text := !adStrEq(o, "title", n) || !adStrEq(o, "description", n) || !adStrEq(o, "compensates", n)
	rels = append(rels, adAttr{"effects", adSetRel(adStrs(o, "effects"), adStrs(n, "effects"))})
	rels = append(rels, adAttr{"params.accepted_calls", adCallSetRel(op, np)})
	for _, name := range sortedKeysStd(op) {
		if nv, has := np[name]; has {
			ov, _ := op[name].(map[string]any)
			nm, _ := nv.(map[string]any)
			for _, a := range adParamAttrRels(ov, nm) {
				rels = append(rels, adAttr{"params." + name + "." + a.k, a.r})
			}
		}
	}
	eo, err := adEffective(prev, reg, confirmed)
	if err != nil {
		return nil, err
	}
	en, err := adEffective(next, reg, confirmed)
	if err != nil {
		return nil, err
	}
	rels = append(rels, adAttr{"traits", adSetRel(eo.hintCl, en.hintCl)})
	rels = append(rels, adAttr{"profile", adProfRel(eo.hintEff, en.hintEff)})
	b2i := func(b bool) int {
		if b {
			return 0
		}
		return 1
	}
	rels = append(rels, adAttr{"confirmation", adRankRel(b2i(eo.confirmed), b2i(en.confirmed))})
	rels = append(rels, adAttr{"effective.traits", adSetRel(eo.closure, en.closure)})
	rels = append(rels, adAttr{"effective.profile", adProfRel(eo.eff, en.eff)})
	rels = append(rels, adAttr{"reversibility", adRankRel(revRank[worstReversibility(o["reversibility"], op)], revRank[worstReversibility(n["reversibility"], np)])})
	ob, _ := o["blast"].(map[string]any)
	nb, _ := n["blast"].(map[string]any)
	rels = append(rels, adAttr{"blast", adRankRel(int(jsF(ob["ppm"])), int(jsF(nb["ppm"])))})
	oi, _ := o["idempotency"].(map[string]any)
	ni, _ := n["idempotency"].(map[string]any)
	idem := adRankRel(adIdemRank[jsAnyString(oi["mode"])], adIdemRank[jsAnyString(ni["mode"])])
	if oi["mode"] == "key_param" && ni["mode"] == "key_param" && !adStrEq(oi, "param", ni) {
		idem = relInc
	}
	rels = append(rels, adAttr{"idempotency", idem})
	rels = append(rels, adAttr{"context", adSetRel(adStrs(o, "context"), adStrs(n, "context"))})
	seKeys := func(m map[string]any) []string {
		var out []string
		l, _ := m["side_effects"].([]any)
		for _, e := range l {
			em, _ := e.(map[string]any)
			out = append(out, jsAnyString(em["target"])+"|"+jsAnyString(em["kind"]))
		}
		return out
	}
	rels = append(rels, adAttr{"side_effects", adSetRel(seKeys(o), seKeys(n))})
	ores, _ := o["resource"].(map[string]any)
	nres, _ := n["resource"].(map[string]any)
	var resID adRel
	switch {
	case adStrEq(ores, "id", nres):
		resID = relEq
	case ActionIDPatternContains(ores["id"], nres["id"]):
		resID = relNarrow
	case ActionIDPatternContains(nres["id"], ores["id"]):
		resID = relWiden
	default:
		resID = relInc
	}
	if ores["type"] != nres["type"] {
		resID = relInc
	}
	rels = append(rels, adAttr{"resource.id", resID})
	rels = append(rels, adAttr{"resource.scope", adRankRel(-adScopeRank[jsAnyString(ores["scope"])], -adScopeRank[jsAnyString(nres["scope"])])})
	al := adSetRel(adStrs(o, "aliases"), adStrs(n, "aliases"))
	switch al {
	case relNarrow:
		al = relWiden
	case relWiden:
		al = relNarrow
	}
	rels = append(rels, adAttr{"aliases", al})
	ob2, obh := o["bindings"], true
	nb2, nbh := n["bindings"], true
	if adSameJSON(ob2, obh, nb2, nbh) {
		rels = append(rels, adAttr{"bindings", relEq})
	} else {
		rels = append(rels, adAttr{"bindings", relInc})
	}
	has := map[adRel]bool{}
	reasons := []string{}
	for _, a := range rels {
		if a.r == relEq {
			continue
		}
		has[a.r] = true
		r := string(a.r)
		if a.r == relInc {
			r = "incomparable"
		}
		reasons = append(reasons, a.k+": "+r)
	}
	if text {
		reasons = append(reasons, "text: title, description or compensates changed")
	}
	adSortU16(reasons)
	cls := "equal"
	switch {
	case has[relInc] || (has[relNarrow] && has[relWiden]):
		cls = "incomparable"
	case has[relWiden]:
		cls = "widen"
	case has[relNarrow]:
		cls = "narrow"
	}
	return map[string]any{"class": cls, "reasons": anyStrs(reasons)}, nil
}

// ActionDiffIsFree is whether a pin follows this change on its own (no principal).
func ActionDiffIsFree(class string) bool { return class == "equal" || class == "narrow" }

// ---- authoring diff (flags breaking changes) -------------------------------------------------------------------------------------------

func adNumStr(m map[string]any, k string) string {
	v, has := m[k]
	if !has || v == nil {
		return "undefined"
	}
	f, _ := jsNum(v)
	return jsLenientNumber(f)
}

func adParamDiff(k string, x, y map[string]any, wide, narrow, incomp *[]string) {
	num := func(f string, lowerIsWider bool) {
		o, oh := x[f]
		n, nh := y[f]
		if oh == nh && (!oh || jsStrictEq(o, n)) {
			return
		}
		rank := func(v any, has bool) float64 {
			if !has || v == nil {
				if lowerIsWider {
					return math.Inf(-1)
				}
				return math.Inf(1)
			}
			f, _ := jsNum(v)
			return f
		}
		var widerNew bool
		if lowerIsWider {
			widerNew = rank(n, nh) < rank(o, oh)
		} else {
			widerNew = rank(n, nh) > rank(o, oh)
		}
		line := fmt.Sprintf("param %s: %s %s to %s", k, f, adNumStr(x, f), adNumStr(y, f))
		if widerNew {
			*wide = append(*wide, line)
		} else {
			*narrow = append(*narrow, line)
		}
	}
	if x["type"] != y["type"] {
		*incomp = append(*incomp, "param "+k+": type changed")
	}
	num("min", true)
	num("max", false)
	num("max_len", false)
	num("max_items", false)
	num("min_items", true)
	if !adSameJSON(x["unit"], true, y["unit"], true) { // JSON.stringify(unit ?? null)
		*incomp = append(*incomp, "param "+k+": unit changed")
	}
	vo, voh := x["values"]
	vn, vnh := y["values"]
	if voh || vnh {
		switch {
		case !voh:
			*narrow = append(*narrow, "param "+k+": values restricted")
		case !vnh:
			*wide = append(*wide, "param "+k+": values unrestricted")
		default:
			a, _ := strsOf(vo)
			b, _ := strsOf(vn)
			var added, removed []string
			for _, v := range b {
				if !contains(a, v) {
					added = append(added, v)
				}
			}
			for _, v := range a {
				if !contains(b, v) {
					removed = append(removed, v)
				}
			}
			if len(added) > 0 {
				*wide = append(*wide, "param "+k+": values added ("+strings.Join(added, ", ")+")")
			}
			if len(removed) > 0 {
				*narrow = append(*narrow, "param "+k+": values removed ("+strings.Join(removed, ", ")+")")
			}
		}
	}
	if x["required"] == true && y["required"] == false {
		*wide = append(*wide, "param "+k+": required to optional")
	}
	if x["required"] == false && y["required"] == true {
		*narrow = append(*narrow, "param "+k+": optional to required")
	}
	pl := func(m map[string]any) int {
		v, has := m["provenance_min"]
		if !has {
			return len(provenanceLevels)
		}
		for i, l := range provenanceLevels {
			if v == l {
				return i
			}
		}
		return -1
	}
	if pl(y) > pl(x) {
		*wide = append(*wide, "param "+k+": provenance_min loosened")
	} else if pl(y) < pl(x) {
		*narrow = append(*narrow, "param "+k+": provenance_min tightened")
	}
	sx, sy := sensitivityRank[effectiveParamSensitivity(x)], sensitivityRank[effectiveParamSensitivity(y)]
	if sy < sx {
		*wide = append(*wide, "param "+k+": sensitivity lowered")
	} else if sy > sx {
		*narrow = append(*narrow, "param "+k+": sensitivity raised")
	}
	if !adStrEq(x, "role", y) {
		f := func(m map[string]any) int {
			if r, ok := m["role"].(string); ok {
				if s, has := roleSensitivityFloor[r]; has {
					return sensitivityRank[s]
				}
			}
			return 0
		}
		switch {
		case f(y) < f(x):
			*wide = append(*wide, "param "+k+": role changed to a lower-floor role")
		case f(y) > f(x):
			*narrow = append(*narrow, "param "+k+": role changed to a higher-floor role")
		default:
			*incomp = append(*incomp, "param "+k+": role changed")
		}
	}
}

// ActionDiffDefsAuthoring is the authoring diff of two versions of a def: {class, breaking, reasons}. A verb rename is a
// breaking widen (grants on the old verb do not follow).
func ActionDiffDefsAuthoring(a, b map[string]any, reg Registry) (map[string]any, error) {
	if a["verb"] != b["verb"] {
		return map[string]any{"class": "widen", "breaking": true,
			"reasons": []any{"verb renamed: removed + added (grants on the old verb do not follow)"}}, nil
	}
	var wide, narrow, incomp []string
	breaking := false
	na, nb := normalizeDef(a), normalizeDef(b)
	ea, err := adEffective(a, reg, nil)
	if err != nil {
		return nil, err
	}
	eb, err := adEffective(b, reg, nil)
	if err != nil {
		return nil, err
	}
	if !leqProfile(ea.hintEff, eb.hintEff) {
		wide = append(wide, "the effective profile is not at least the old one")
	} else if !(leqProfile(eb.hintEff, ea.hintEff)) {
		narrow = append(narrow, "the effective profile rose")
	}
	ae, be := adStrs(na, "effects"), adStrs(nb, "effects")
	for _, e := range ae {
		if !contains(be, e) {
			wide = append(wide, "effect "+e+" removed")
		}
	}
	for _, e := range be {
		if !contains(ae, e) {
			narrow = append(narrow, "effect "+e+" added")
		}
	}
	at, bt := adStrs(na, "traits"), adStrs(nb, "traits")
	for _, t := range at {
		if !contains(bt, t) {
			wide = append(wide, "declared trait "+t+" removed")
		}
	}
	for _, t := range bt {
		if !contains(at, t) {
			narrow = append(narrow, "declared trait "+t+" added")
		}
	}
	npa, _ := na["params"].(map[string]any)
	npb, _ := nb["params"].(map[string]any)
	ra, rb := worstReversibility(na["reversibility"], npa), worstReversibility(nb["reversibility"], npb)
	if revRank[rb] < revRank[ra] {
		wide = append(wide, fmt.Sprintf("reversibility lowered (%s to %s)", ra, rb))
	} else if revRank[rb] > revRank[ra] {
		narrow = append(narrow, fmt.Sprintf("reversibility raised (%s to %s)", ra, rb))
	}
	ba, _ := na["blast"].(map[string]any)
	bb, _ := nb["blast"].(map[string]any)
	if jsF(bb["ppm"]) < jsF(ba["ppm"]) {
		wide = append(wide, "blast lowered")
	} else if jsF(bb["ppm"]) > jsF(ba["ppm"]) {
		narrow = append(narrow, "blast raised")
	}
	idem := func(m map[string]any) int {
		i, _ := m["idempotency"].(map[string]any)
		if i["mode"] == "none" {
			return 0
		}
		return 1
	}
	if idem(nb) < idem(na) {
		wide = append(wide, "idempotency loosened")
	} else if idem(nb) > idem(na) {
		narrow = append(narrow, "idempotency added")
	}
	resA, _ := na["resource"].(map[string]any)
	resB, _ := nb["resource"].(map[string]any)
	if resA["type"] != resB["type"] {
		incomp = append(incomp, "resource type changed")
	}
	sa, sb := adScopeRank[jsAnyString(resA["scope"])], adScopeRank[jsAnyString(resB["scope"])]
	if sb > sa {
		wide = append(wide, "resource scope widened")
	} else if sb < sa {
		narrow = append(narrow, "resource scope narrowed")
	}
	if !ActionIDPatternContains(resA["id"], resB["id"]) {
		wide = append(wide, "the resource id pattern is not contained in the old one")
	} else if !ActionIDPatternContains(resB["id"], resA["id"]) {
		narrow = append(narrow, "the resource id pattern is narrower")
	}
	for _, k := range sortedKeysStd(npa) {
		x, _ := npa[k].(map[string]any)
		yv, has := npb[k]
		if !has {
			narrow = append(narrow, "param "+k+" removed")
			breaking = true
			continue
		}
		y, _ := yv.(map[string]any)
		adParamDiff(k, x, y, &wide, &narrow, &incomp)
		if x["required"] == false && y["required"] == true {
			breaking = true
		}
	}
	for _, k := range sortedKeysStd(npb) {
		if _, has := npa[k]; has {
			continue
		}
		if y, _ := npb[k].(map[string]any); y["required"] == true {
			narrow = append(narrow, "required param "+k+" added")
			breaking = true
		} else {
			wide = append(wide, "optional param "+k+" added")
		}
	}
	if ra2, _ := a["review"].(map[string]any); ra2["state"] == "confirmed" {
		if rb2, _ := b["review"].(map[string]any); rb2["state"] != "confirmed" {
			narrow = append(narrow, "review state left confirmed")
		}
	}
	cls := "equal"
	switch {
	case len(incomp) > 0 || (len(wide) > 0 && len(narrow) > 0):
		cls = "incomparable"
	case len(wide) > 0:
		cls = "widen"
	case len(narrow) > 0:
		cls = "narrow"
	}
	reasons := []string{}
	for _, r := range wide {
		reasons = append(reasons, "widen: "+r)
	}
	for _, r := range narrow {
		reasons = append(reasons, "narrow: "+r)
	}
	for _, r := range incomp {
		reasons = append(reasons, "incomparable: "+r)
	}
	if cls == "equal" {
		da, e1 := defDigest(a)
		db, e2 := defDigest(b)
		if e1 != nil || e2 != nil {
			return nil, errors.New("defDigest failed")
		}
		if da != db {
			reasons = append(reasons, "equal: only title or description changed")
		}
	}
	return map[string]any{"class": cls, "breaking": breaking, "reasons": anyStrs(reasons)}, nil
}

// ActionDiffPacks is the per-verb diff of two sets of defs, sorted by verb: a removed verb is `removed` (breaking), a new verb is
// `added`.
func ActionDiffPacks(olds, news []any, reg Registry) ([]any, error) {
	o, n := map[string]map[string]any{}, map[string]map[string]any{}
	verbs := map[string]bool{}
	for _, x := range olds {
		m, _ := x.(map[string]any)
		v, _ := m["verb"].(string)
		o[v], verbs[v] = m, true
	}
	for _, x := range news {
		m, _ := x.(map[string]any)
		v, _ := m["verb"].(string)
		n[v], verbs[v] = m, true
	}
	list := make([]string, 0, len(verbs))
	for v := range verbs {
		list = append(list, v)
	}
	adSortU16(list)
	out := []any{}
	for _, v := range list {
		x, y := o[v], n[v]
		switch {
		case x == nil:
			out = append(out, map[string]any{"verb": v, "class": "added", "breaking": false, "reasons": []any{}})
		case y == nil:
			out = append(out, map[string]any{"verb": v, "class": "removed", "breaking": true, "reasons": []any{"verb removed"}})
		default:
			d, err := ActionDiffDefsAuthoring(x, y, reg)
			if err != nil {
				return nil, err
			}
			d["verb"] = v
			out = append(out, d)
		}
	}
	return out, nil
}
