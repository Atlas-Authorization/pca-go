package pca

// The deterministic suggestion layer of the action importers. A versioned rule set proposes traits, param roles and param tags for a
// draft def. Union only: a suggestion can ADD a trait, a role (to a param that has none) or a tag, never remove or replace anything,
// and it never marks a def confirmed. A suggested def is still `pca.unreviewed` for floor purposes; suggestions only improve the
// card and the review queue. `path_re` is a JavaScript regular expression (see actions_import_jsre.go). Rule sets, defs and
// suggestions are JSON values (map[string]any / []any).

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

const (
	// ActionSuggestRulesKind is the `kind` member of a suggestion rule set.
	ActionSuggestRulesKind   = "pca-suggest-rules"
	actionSuggestRulesDomain = "atlas-pca/suggest-rules/v1"
	aisMaxRules              = 1024
	aisMaxList               = 64
)

var (
	reAisRuleID  = regexp.MustCompile(`^SR-[0-9]{3,4}$`)
	reAisVersion = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
	// a group that holds a quantifier or an alternation, followed by another quantifier: the shapes that backtrack exponentially
	reAisNested    = regexp.MustCompile(`\([^)]*[+*][^)]*\)[+*{]|\([^)]*\|[^)]*\)[+*{]`)
	reAisBackref   = regexp.MustCompile(`\\[1-9]`)
	reAisLookahead = regexp.MustCompile(`\(\?[<=!]`)

	aisMatchKeys  = []string{"methods", "path_re", "name_tokens", "name_tokens_strict", "param_names", "param_names_all", "param_types", "param_formats", "roles", "effects"}
	aisParamTypes = []string{"string", "integer", "boolean", "date", "datetime", "duration", "set", "array", "object_ref"}
	aisIntRoles   = []string{"money.amount", "money.fee", "count.limit", "bytes.size"}
)

func aisUpper(s string) string { return cases.Upper(language.Und).String(s) }

func aisMap(v any) map[string]any { m, _ := v.(map[string]any); return m }

func aisList(v any) []any { l, _ := v.([]any); return l }

func aisIsOne(v any) bool {
	switch v.(type) {
	case bool, string, nil:
		return false
	}
	f, ok := jsNum(v)
	return ok && f == 1
}

func aisIsStrList(v any, mx int) bool {
	l, ok := v.([]any)
	if !ok || len(l) == 0 || len(l) > mx {
		return false
	}
	for _, x := range l {
		s, ok := x.(string)
		if !ok {
			return false
		}
		if n := jsLen(s); n == 0 || n > 64 {
			return false
		}
	}
	return true
}

// ActionSuggestRulesError is "" iff the rule set is well formed: closed members, unique ids, safe regular expressions, known
// trait/role/tag names. known (when not nil) is the set of trait ids a rule may add.
func ActionSuggestRulesError(rv any, known map[string]bool) string {
	r, ok := rv.(map[string]any)
	if !ok {
		return "rules must be an object"
	}
	if k, bad := unknownMember(r, []string{"v", "kind", "version", "rules", "digest", "sig"}); bad {
		return "unknown member '" + k + "'"
	}
	if !aisIsOne(r["v"]) || r["kind"] != ActionSuggestRulesKind {
		return "not a suggest-rules document (v 1)"
	}
	if ver, ok := r["version"].(string); !ok || !reAisVersion.MatchString(ver) {
		return "version must be semver"
	}
	rules, ok := r["rules"].([]any)
	if !ok || len(rules) == 0 || len(rules) > aisMaxRules {
		return fmt.Sprintf("rules must be 1..%d entries", aisMaxRules)
	}
	ids := map[string]bool{}
	for _, rl := range rules {
		rule, ok := rl.(map[string]any)
		if !ok {
			return "a rule must be an object"
		}
		if k, bad := unknownMember(rule, []string{"id", "match", "adds", "note"}); bad {
			return "rule: unknown member '" + k + "'"
		}
		rid, ok := rule["id"].(string)
		if !ok || !reAisRuleID.MatchString(rid) || ids[rid] {
			return "rule ids must be unique SR-nnn"
		}
		ids[rid] = true
		w := rid
		note, ok := rule["note"].(string)
		if !ok || jsLen(note) == 0 || jsLen(note) > 200 {
			return w + ": note must be 1..200 characters"
		}
		m, ok := rule["match"].(map[string]any)
		if !ok || len(m) == 0 {
			return w + ": match must be a non-empty object"
		}
		if k, bad := unknownMember(m, aisMatchKeys); bad {
			return w + ": unknown match member '" + k + "'"
		}
		for _, k := range []string{"methods", "name_tokens", "name_tokens_strict", "param_names", "param_names_all", "param_formats", "roles"} {
			if v, has := m[k]; has && !aisIsStrList(v, aisMaxList) {
				return fmt.Sprintf("%s: match.%s must be 1..%d short strings", w, k, aisMaxList)
			}
		}
		if v, has := m["methods"]; has {
			for _, s := range aisList(v) {
				if x := s.(string); x != aisUpper(x) {
					return w + ": methods are uppercase"
				}
			}
		}
		if v, has := m["param_types"]; has {
			bad := !aisIsStrList(v, aisMaxList)
			if !bad {
				for _, t := range aisList(v) {
					if !contains(aisParamTypes, t.(string)) {
						bad = true
					}
				}
			}
			if bad {
				return w + ": match.param_types is not a list of param types"
			}
		}
		if v, has := m["effects"]; has && !aisIsStrList(v, 12) {
			return w + ": match.effects must be a list of effects"
		}
		if v, has := m["path_re"]; has {
			p, ok := v.(string)
			if !ok || jsLen(p) == 0 || jsLen(p) > 128 {
				return w + ": path_re must be 1..128 characters"
			}
			if reAisNested.MatchString(p) || reAisBackref.MatchString(p) || reAisLookahead.MatchString(p) {
				return w + ": path_re uses a construct outside the bounded subset (nested quantifiers, backreferences, lookaround)"
			}
			if _, err := jsrCompile(p); err != nil {
				return w + ": path_re is not a regular expression"
			}
		}
		_, a := m["param_names"]
		_, b := m["param_names_all"]
		_, c := m["param_formats"]
		_, d := m["roles"]
		hasParam := a || b || c || d
		if _, has := m["param_types"]; has && !a && !c && !b {
			return w + ": param_types needs param_names, param_names_all or param_formats"
		}
		if !aisIsStrList(rule["adds"], 16) {
			return w + ": adds must be 1..16 entries"
		}
		for _, av := range aisList(rule["adds"]) {
			add := av.(string)
			switch {
			case strings.HasPrefix(add, "tag:"):
				if !contains(paramTags, add[4:]) {
					return w + ": unknown tag '" + add + "'"
				}
				if !hasParam {
					return w + ": a tag needs a param matcher"
				}
			case isRole(add):
				if !hasParam {
					return w + ": a role needs a param matcher"
				}
			case reTraitID.MatchString(add):
				if known != nil && !known[add] {
					return w + ": unknown trait '" + add + "'"
				}
			default:
				return w + ": '" + add + "' is not a trait, role or tag:"
			}
		}
	}
	return ""
}

func aisRulesBody(r map[string]any) map[string]any {
	return map[string]any{"v": r["v"], "kind": r["kind"], "version": r["version"], "rules": r["rules"]}
}

// ActionRulesDigest is the b64u sha256 of the strict canonical rule set (without digest and sig).
func ActionRulesDigest(rv any) (string, error) {
	r, ok := rv.(map[string]any)
	if !ok {
		return "", &CodedError{Code: "bad_rules", Msg: "rules must be an object"}
	}
	return HashCanonical(map[string]any{"d": actionSuggestRulesDomain, "rules": aisRulesBody(r)})
}

// ActionSealRules is the rule set with its digest.
func ActionSealRules(rv any) (map[string]any, error) {
	d, err := ActionRulesDigest(rv)
	if err != nil {
		return nil, err
	}
	out := map[string]any{}
	for k, v := range rv.(map[string]any) {
		out[k] = v
	}
	out["digest"] = d
	return out, nil
}

func aisRulesMessage(digest string) ([]byte, error) {
	m, ok := domainMessage(actionSuggestRulesDomain+"\x00", map[string]any{"digest": digest})
	if !ok {
		return nil, errors.New("the rules digest is not canonical")
	}
	return m, nil
}

// ActionSignRules signs a rule set as the rules publisher (a release step; the signature covers the digest). seed is an Ed25519 seed.
func ActionSignRules(rv any, kid string, seed []byte) (map[string]any, error) {
	if bad := ActionSuggestRulesError(rv, nil); bad != "" {
		return nil, &CodedError{Code: "bad_rules", Msg: bad}
	}
	sealed, err := ActionSealRules(rv)
	if err != nil {
		return nil, err
	}
	kp, err := KeyPairFromSeed(seed)
	if err != nil {
		return nil, err
	}
	msg, err := aisRulesMessage(sealed["digest"].(string))
	if err != nil {
		return nil, err
	}
	sealed["sig"] = map[string]any{"alg": "ed25519", "kid": kid, "value": b64.EncodeToString(kp.Sign(msg))}
	return sealed, nil
}

// ActionVerifyRules verifies a signed rule set against pinned publisher keys ([{kid, pk}]): shape, digest, signature. Never panics.
func ActionVerifyRules(doc any, pins any) (res map[string]any) {
	defer func() {
		if r := recover(); r != nil {
			res = map[string]any{"ok": false, "reason": fmt.Sprintf("rules verification error: %v", r)}
		}
	}()
	if bad := ActionSuggestRulesError(doc, nil); bad != "" {
		return map[string]any{"ok": false, "reason": bad}
	}
	d := doc.(map[string]any)
	want, err := ActionRulesDigest(d)
	if err != nil {
		return map[string]any{"ok": false, "reason": "rules verification error: " + err.Error()}
	}
	if dg, _ := d["digest"].(string); dg != want {
		return map[string]any{"ok": false, "reason": "digest does not match the rules"}
	}
	sig, has := d["sig"]
	if !has || !aimTruthy(sig) {
		return map[string]any{"ok": false, "reason": "the rule set is not signed"}
	}
	sm := aisMap(sig)
	kidV, kidHas := sm["kid"]
	var key map[string]any
	if kidHas {
		for _, p := range aisList(pins) {
			if pm := aisMap(p); pm != nil {
				if pk, ok := pm["kid"]; ok && pk == kidV {
					key = pm
					break
				}
			}
		}
	}
	if key == nil {
		name := "undefined"
		if kidHas {
			name = jsValueString(kidV)
		}
		return map[string]any{"ok": false, "reason": "no pinned rules key '" + name + "'"}
	}
	msg, err := aisRulesMessage(want)
	if err != nil {
		return map[string]any{"ok": false, "reason": "rules verification error: " + err.Error()}
	}
	pk, ok1 := key["pk"].(string)
	val, ok2 := sm["value"].(string)
	if ok1 && ok2 && verifyB64u(pk, msg, val) {
		return map[string]any{"ok": true}
	}
	return map[string]any{"ok": false, "reason": "rules signature invalid"}
}

// ---- facts -------------------------------------------------------------------------------------------------------------------

// ActionSuggestStem is a light stemmer: plural, -ing, -ed and a trailing -e fold together (`charges`, `charged`, `charging` -> `charg`).
func ActionSuggestStem(t string) string {
	s := t
	n := jsLen(s)
	switch {
	case n > 4 && strings.HasSuffix(s, "ies"):
		s = s[:len(s)-3] + "y"
	case n > 4 && (strings.HasSuffix(s, "sses") || strings.HasSuffix(s, "xes") || strings.HasSuffix(s, "zes") || strings.HasSuffix(s, "ches") || strings.HasSuffix(s, "shes")):
		s = s[:len(s)-2]
	case n > 3 && strings.HasSuffix(s, "s") && !strings.HasSuffix(s, "ss"):
		s = s[:len(s)-1]
	}
	n = jsLen(s)
	switch {
	case n > 5 && strings.HasSuffix(s, "ing"):
		s = s[:len(s)-3]
	case n > 4 && strings.HasSuffix(s, "ed"):
		s = s[:len(s)-2]
	}
	if jsLen(s) > 3 && strings.HasSuffix(s, "e") {
		s = s[:len(s)-1]
	}
	return s
}

const aisSep = "|"

func aisStemAll(xs []string) []string {
	out := make([]string, len(xs))
	for i, x := range xs {
		out[i] = ActionSuggestStem(x)
	}
	return out
}

func aisPathTokens(p string) []string {
	out := []string{}
	for _, s := range strings.Split(p, "/") {
		if len(s) > 0 && !strings.Contains(s, "{") && !strings.Contains(s, "}") {
			out = append(out, aimTokensOf(s)...)
		}
	}
	return out
}

// aisU16Prefix is the first n UTF-16 units of s (a cut surrogate pair stays as a lone surrogate, as in the reference).
func aisU16Prefix(s string, n int) string {
	u := utf16Units(s)
	if len(u) <= n {
		return s
	}
	var sb strings.Builder
	for i := 0; i < n; i++ {
		c := rune(u[i])
		switch {
		case c >= 0xD800 && c <= 0xDBFF && i+1 < n && u[i+1] >= 0xDC00 && u[i+1] <= 0xDFFF:
			sb.WriteRune(0x10000 + (c-0xD800)<<10 + rune(u[i+1]) - 0xDC00)
			i++
		case c >= 0xD800 && c <= 0xDFFF: // a lone surrogate, as its WTF-8 form
			sb.WriteByte(byte(0xE0 | c>>12))
			sb.WriteByte(byte(0x80 | (c>>6)&0x3F))
			sb.WriteByte(byte(0x80 | c&0x3F))
		default:
			sb.WriteRune(c)
		}
	}
	return sb.String()
}

type aisParam struct {
	name      string
	tokens    []string
	typ       string
	format    string
	hasFormat bool
	role      string
	hasRole   bool
}

type aisFacts struct {
	methods, locs, tokens, strict []string
	params                        []aisParam
	effects                       []string
}

func (f aisFacts) toMap() map[string]any {
	ps := make([]any, len(f.params))
	for i, p := range f.params {
		e := map[string]any{"name": p.name, "tokens": anyStrs(p.tokens), "type": p.typ}
		if p.hasFormat {
			e["format"] = p.format
		}
		if p.hasRole {
			e["role"] = p.role
		}
		ps[i] = e
	}
	return map[string]any{"methods": anyStrs(f.methods), "locs": anyStrs(f.locs), "tokens": anyStrs(f.tokens), "strict": anyStrs(f.strict), "params": ps, "effects": anyStrs(f.effects)}
}

func aisStr(m map[string]any, k string) string { return jsMemberString(m, k) }

func aisUniq(xs []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, x := range xs {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

func aisFactsOf(d map[string]any) aisFacts {
	b := aisMap(d["bindings"])
	var methods, locs []string
	var src [][]string
	pathSrc := map[int]bool{}
	verbParts := strings.Split(aisStr(d, "verb"), ".")
	vt := []string{}
	for _, s := range verbParts[1:] {
		vt = append(vt, aimTokensOf(s)...)
	}
	src = append(src, vt)
	for _, a := range aisList(d["aliases"]) {
		src = append(src, aimTokensOf(a))
	}
	src = append(src, aimTokensOf(d["title"]))
	if o := aisMap(b["openapi"]); aimTruthy(b["openapi"]) {
		src = append(src, aimTokensOf(o["operationId"]))
		if aimTruthy(o["method"]) {
			methods = append(methods, aisUpper(aisStr(o, "method")))
		}
		if aimTruthy(o["path"]) {
			p := aisStr(o, "path")
			locs = append(locs, p)
			pathSrc[len(src)] = true
			src = append(src, aisPathTokens(p))
		}
	}
	if h := aisMap(b["http"]); aimTruthy(b["http"]) {
		methods = append(methods, aisUpper(aisStr(h, "method")))
		p := aisStr(h, "path")
		locs = append(locs, p)
		pathSrc[len(src)] = true
		src = append(src, aisPathTokens(p))
	}
	if m := aisMap(b["mcp"]); aimTruthy(b["mcp"]) {
		locs = append(locs, aisStr(m, "tool"))
		src = append(src, aimTokensOf(m["tool"]))
	}
	if g := aisMap(b["graphql"]); aimTruthy(b["graphql"]) {
		methods = append(methods, aisUpper(aisStr(g, "op")))
		locs = append(locs, aisStr(g, "field"))
		src = append(src, aimTokensOf(g["field"]))
	}
	if g := aisMap(b["grpc"]); aimTruthy(b["grpc"]) {
		locs = append(locs, aisStr(g, "service")+"/"+aisStr(g, "method"))
		src = append(src, aimTokensOf(g["service"]), aimTokensOf(g["method"]))
	}
	if a := aisMap(b["asyncapi"]); aimTruthy(b["asyncapi"]) {
		methods = append(methods, aisUpper(aisStr(a, "op")))
		locs = append(locs, aisStr(a, "channel"))
		src = append(src, aimTokensOf(a["channel"]))
	}
	tokens, strict := []string{}, []string{}
	for i, s := range src {
		if len(tokens) > 0 {
			tokens = append(tokens, aisSep)
		}
		tokens = append(tokens, aisStemAll(s)...)
		if !pathSrc[i] {
			if len(strict) > 0 {
				strict = append(strict, aisSep)
			}
			strict = append(strict, aisStemAll(s)...)
		}
	}
	pm := aisMap(d["params"])
	names := sortedKeysStd(pm)
	adSortU16(names)
	params := make([]aisParam, 0, len(names))
	for _, name := range names {
		p := aisMap(pm[name])
		e := aisParam{name: name, tokens: aisStemAll(aimTokensOf(name)), typ: aisStr(p, "type")}
		if aimTruthy(p["format"]) {
			e.format, e.hasFormat = aisStr(p, "format"), true
		}
		if aimTruthy(p["role"]) {
			e.role, e.hasRole = aisStr(p, "role"), true
		}
		params = append(params, e)
	}
	ls := make([]string, len(locs))
	for i, x := range locs {
		ls[i] = aisU16Prefix(x, 512)
	}
	eff := []string{}
	for _, e := range aisList(d["effects"]) {
		eff = append(eff, jsValueString(e))
	}
	return aisFacts{methods: aisUniq(methods), locs: ls, tokens: tokens, strict: strict, params: params, effects: aisUniq(eff)}
}

// ActionSuggestFactsOf is the facts the rules match against: HTTP methods, locations, stemmed tokens (with and without the path),
// params and effects.
func ActionSuggestFactsOf(d map[string]any) map[string]any { return aisFactsOf(d).toMap() }

func aisHasSeq(hay, pat []string) bool {
	if len(pat) == 0 {
		return false
	}
	for i := 0; i+len(pat) <= len(hay); i++ {
		ok := true
		for j := range pat {
			if hay[i+j] != pat[j] {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

func aisPatOf(s string) []string { return aisStemAll(aimTokensOf(s)) }

func aisRoleFits(role, typ string) bool {
	switch {
	case contains(aisIntRoles, role):
		return typ == "integer"
	case strings.HasPrefix(role, "time."):
		return typ == "date" || typ == "datetime" || typ == "integer"
	}
	return typ == "string"
}

func aisSortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	adSortU16(out)
	return out
}

func aisStrList(v any) []string {
	out := []string{}
	for _, x := range aisList(v) {
		s, _ := x.(string)
		out = append(out, s)
	}
	return out
}

func aisHas(xs []string, s string) bool { return contains(xs, s) }

// ActionSuggestWithRules runs the rules over a def: {traits, roles, tags, fired}. Only trait ids in reg (when not nil) can be
// suggested. Pure and deterministic.
func ActionSuggestWithRules(d map[string]any, rulesV any, reg Registry) (res map[string]any, err error) {
	defer func() {
		if r := recover(); r != nil {
			res, err = nil, fmt.Errorf("suggest: %v", r)
		}
	}()
	rules := aisMap(rulesV)
	f := aisFactsOf(d)
	traits := map[string]bool{}
	roles := map[string]string{}
	tags := map[string]map[string]bool{}
	fired := []string{}
	for _, rl := range aisList(rules["rules"]) {
		rule := aisMap(rl)
		m := aisMap(rule["match"])
		if aimTruthy(m["methods"]) {
			any1 := false
			for _, x := range aisStrList(m["methods"]) {
				if aisHas(f.methods, x) {
					any1 = true
				}
			}
			if !any1 {
				continue
			}
		}
		if aimTruthy(m["effects"]) {
			any1 := false
			for _, x := range aisStrList(m["effects"]) {
				if aisHas(f.effects, x) {
					any1 = true
				}
			}
			if !any1 {
				continue
			}
		}
		if aimTruthy(m["name_tokens"]) {
			any1 := false
			for _, x := range aisStrList(m["name_tokens"]) {
				if aisHasSeq(f.tokens, aisPatOf(x)) {
					any1 = true
				}
			}
			if !any1 {
				continue
			}
		}
		if aimTruthy(m["name_tokens_strict"]) {
			any1 := false
			for _, x := range aisStrList(m["name_tokens_strict"]) {
				if aisHasSeq(f.strict, aisPatOf(x)) {
					any1 = true
				}
			}
			if !any1 {
				continue
			}
		}
		if aimTruthy(m["path_re"]) {
			rx, err := jsrCompile(aisStr(m, "path_re"))
			if err != nil {
				return nil, err
			}
			any1 := false
			for _, loc := range f.locs {
				if jsrTest(rx, loc) {
					any1 = true
					break
				}
			}
			if !any1 {
				continue
			}
		}
		if aimTruthy(m["roles"]) {
			rs := aisStrList(m["roles"])
			any1 := false
			for _, p := range f.params {
				if p.hasRole && aisHas(rs, p.role) {
					any1 = true
				}
			}
			if !any1 {
				continue
			}
		}
		var matched []aisParam
		if m["param_names"] != nil || m["param_formats"] != nil {
			var pats [][]string
			for _, x := range aisStrList(m["param_names"]) {
				pats = append(pats, aisPatOf(x))
			}
			for _, p := range f.params {
				if aimTruthy(m["param_types"]) && !aisHas(aisStrList(m["param_types"]), p.typ) {
					continue
				}
				if aimTruthy(m["param_names"]) {
					hit := false
					for _, q := range pats {
						if aisHasSeq(p.tokens, q) {
							hit = true
						}
					}
					if !hit {
						continue
					}
				}
				if aimTruthy(m["param_formats"]) && (!p.hasFormat || !aisHas(aisStrList(m["param_formats"]), p.format)) {
					continue
				}
				matched = append(matched, p)
			}
			if len(matched) == 0 {
				continue
			}
		}
		if aimTruthy(m["param_names_all"]) {
			ok := true
			for _, n := range aisStrList(m["param_names_all"]) {
				q := aisPatOf(n)
				hit := false
				for _, p := range f.params {
					if aisHasSeq(p.tokens, q) && (!aimTruthy(m["param_types"]) || aisHas(aisStrList(m["param_types"]), p.typ) || p.typ == "string") {
						hit = true
						break
					}
				}
				if !hit {
					ok = false
					break
				}
			}
			if !ok {
				continue
			}
		}
		fired = append(fired, aisStr(rule, "id"))
		for _, a := range aisStrList(rule["adds"]) {
			switch {
			case strings.HasPrefix(a, "tag:"):
				for _, p := range matched {
					if tags[p.name] == nil {
						tags[p.name] = map[string]bool{}
					}
					tags[p.name][a[4:]] = true
				}
			case !isRole(a):
				if reg == nil {
					traits[a] = true
				} else if _, in := reg[a]; in {
					traits[a] = true
				}
			default:
				for _, p := range matched {
					if _, set := roles[p.name]; !p.hasRole && !set && aisRoleFits(a, p.typ) {
						roles[p.name] = a
					}
				}
			}
		}
	}
	delete(traits, "pca.unreviewed")
	return aisSuggestion(aisSortedKeys(traits), roles, tags, fired), nil
}

func aisSuggestion(traits []string, roles map[string]string, tags map[string]map[string]bool, fired []string) map[string]any {
	rm := map[string]any{}
	for k, v := range roles {
		rm[k] = v
	}
	tm := map[string]any{}
	for k, v := range tags {
		tm[k] = anyStrs(aisSortedKeys(v))
	}
	return map[string]any{"traits": anyStrs(traits), "roles": rm, "tags": tm, "fired": anyStrs(fired)}
}

func aisSortUniq(xs []string) []string {
	out := aisUniq(xs)
	adSortU16(out)
	return out
}

// ActionUnionSuggestions unions two suggestions (the restrictive direction, so no intersection is needed); a wins a role clash.
func ActionUnionSuggestions(a, b map[string]any) map[string]any {
	tags := map[string]any{}
	at, bt := aisMap(a["tags"]), aisMap(b["tags"])
	for _, k := range append(sortedKeysStd(at), sortedKeysStd(bt)...) {
		tags[k] = anyStrs(aisSortUniq(append(aisStrList(at[k]), aisStrList(bt[k])...)))
	}
	roles := map[string]any{}
	for k, v := range aisMap(b["roles"]) {
		roles[k] = v
	}
	for k, v := range aisMap(a["roles"]) {
		roles[k] = v
	}
	fired := append(append([]any{}, aisList(a["fired"])...), aisList(b["fired"])...)
	return map[string]any{"traits": anyStrs(aisSortUniq(append(aisStrList(a["traits"]), aisStrList(b["traits"])...))), "roles": roles, "tags": tags, "fired": fired}
}

func aisShallow(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// ActionApplySuggestion applies a suggestion to a def. UNION ONLY: traits are added, a role is set only on a param without one,
// tags are added; nothing is removed or replaced, no attestation is created, and `review.state` goes from `unreviewed` to
// `suggested`. by is {rules?, models?}.
func ActionApplySuggestion(d, s, by map[string]any) (res map[string]any, err error) {
	defer func() {
		if r := recover(); r != nil {
			res, err = nil, fmt.Errorf("apply suggestion: %v", r)
		}
	}()
	params := map[string]any{}
	addedRoles := map[string]any{}
	addedTags := map[string][]string{}
	sroles, stags := aisMap(s["roles"]), aisMap(s["tags"])
	for name, pv := range aisMap(d["params"]) {
		p := aisMap(pv)
		q := p
		if role, has := sroles[name]; has && role != nil {
			if _, hasRole := p["role"]; !hasRole && aisRoleFits(jsValueString(role), aisStr(p, "type")) {
				q = aisShallow(q)
				q["role"] = role
				addedRoles[name] = role
			}
		}
		if tv, has := stags[name]; has && tv != nil {
			have := aisStrList(p["tags"])
			fresh := []string{}
			for _, x := range aisStrList(tv) {
				if !aisHas(have, x) {
					fresh = append(fresh, x)
				}
			}
			if len(fresh) > 0 {
				q = aisShallow(q)
				q["tags"] = anyStrs(aisSortUniq(append(append([]string{}, have...), fresh...)))
				addedTags[name] = fresh
			}
		}
		params[name] = q
	}
	declared := aisStrList(d["traits"])
	strs := aisStrList(s["traits"])
	fresh := []string{}
	for _, t := range strs {
		if !aisHas(declared, t) {
			fresh = append(fresh, t)
		}
	}
	// a money-moving action must be safe to repeat (lint LD-004): add the optional idempotency key the pack generator adds
	idem := d["idempotency"]
	if aisHas(strs, "pca.money_moving") && (idem == nil || aisMap(idem)["mode"] == "none") {
		idem = map[string]any{"mode": "key_param", "param": "idempotency_key"}
		if _, has := params["idempotency_key"]; !has {
			params["idempotency_key"] = map[string]any{"type": "string", "max_len": jsNumber(64), "required": false}
		}
	}
	review := aisMap(d["review"])
	prev := aisMap(review["suggested_by"])
	prevAdded := aisMap(prev["added"])
	if !aimTruthy(prev["added"]) {
		prevAdded = map[string]any{"traits": []any{}, "roles": map[string]any{}, "tags": map[string]any{}}
	}
	tags := map[string]any{}
	pat := aisMap(prevAdded["tags"])
	keys := map[string]bool{}
	for k := range pat {
		keys[k] = true
	}
	for k := range addedTags {
		keys[k] = true
	}
	for _, k := range aisSortedKeys(keys) {
		tags[k] = anyStrs(aisSortUniq(append(aisStrList(pat[k]), addedTags[k]...)))
	}
	roles := map[string]any{}
	for k, v := range aisMap(prevAdded["roles"]) {
		roles[k] = v
	}
	for k, v := range addedRoles {
		roles[k] = v
	}
	added := map[string]any{"traits": anyStrs(aisSortUniq(append(aisStrList(prevAdded["traits"]), fresh...))), "roles": roles, "tags": tags}
	rules := by["rules"]
	if !aimTruthy(rules) {
		rules = prev["rules"]
	}
	models := append(append([]any{}, aisList(prev["models"])...), aisList(by["models"])...)
	sb := map[string]any{"added": added}
	if aimTruthy(rules) {
		sb["rules"] = rules
	}
	if len(models) > 0 {
		sb["models"] = models
	}
	state := review["state"]
	if state == "unreviewed" || state == "suggested" {
		state = "suggested"
	}
	out := aisShallow(d)
	out["params"] = params
	if idem != nil {
		out["idempotency"] = idem
	}
	if len(fresh) > 0 || len(declared) > 0 {
		out["traits"] = anyStrs(aisSortUniq(append(append([]string{}, declared...), strs...)))
	}
	nr := aisShallow(review)
	nr["state"] = state
	nr["suggested_by"] = sb
	out["review"] = nr
	return out, nil
}

var (
	aisRulesOnce   sync.Once
	aisRulesParsed map[string]any
)

// ActionDefaultRules is the shipped suggestion rules (shared and read-only).
func ActionDefaultRules() map[string]any {
	aisRulesOnce.Do(func() {
		v, err := ActionImportDefaultRules()
		if err != nil {
			panic(err)
		}
		aisRulesParsed = map[string]any{}
		for k, x := range v.(map[string]any) {
			if k != "digest" { // the shipped file carries its digest; the rule set itself does not (ActionDefaultRulesSealed adds it)
				aisRulesParsed[k] = x
			}
		}
		recordKeyOrder(aisRulesParsed, func() []string {
			var ks []string
			for _, k := range jsKeys(v.(map[string]any)) {
				if k != "digest" {
					ks = append(ks, k)
				}
			}
			return ks
		}())
	})
	return aisRulesParsed
}

// ActionDefaultRulesSealed is the shipped rules with their digest.
func ActionDefaultRulesSealed() (map[string]any, error) { return ActionSealRules(ActionDefaultRules()) }
