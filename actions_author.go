package pca

// Authoring forms of an ActionDef (native port of the author module of the TypeScript reference): the param and resource
// shorthands, the entry expansion, the document loader over a parsed value, the text loader (YAML 1.2 core or JSON, with source
// positions: actions_yaml_load.go) and the typed param constructors (ActionP*). One action has one digest whichever way it was
// written; every expanded def is checked by validateDef. A malformed shorthand or entry is a *CodedError (bad_shorthand /
// bad_action); the loaders never fail, they report errors in their result.

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

const (
	authorMaxBytes  = 1 << 20
	authorIdemParam = "idempotency_key"
)

var (
	authorAutoIdemEffects = []string{"send", "pay", "create", "provision", "publish"}
	authorDefaultIDLen    = [2]int{8, 32}
	authorFileKeys        = []string{"ns", "since", "actions"}
	reAuShorthand         = regexp.MustCompile(`^([a-z_]+(?::[a-z0-9_]+(?:\.[a-z0-9_]+){0,3})?)(?:\(([^\n\r\x{2028}\x{2029}]*)\))?(\?)?$`)
	reAuIntArg            = regexp.MustCompile(`^-?[0-9]{1,15}$`)
	reAuIntRange          = regexp.MustCompile(`^(-?[0-9]{1,15})\.\.(-?[0-9]{1,15})$`)
	reAuAt                = regexp.MustCompile(`(?s)^.*@([a-z]+)$`)
	reAuIDRest            = regexp.MustCompile(`^\{([a-z_]+),([0-9]{1,3})\.\.([0-9]{1,3})\}$`)
	reAuNS                = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
)

func auErr(code, format string, a ...any) error {
	return &CodedError{Code: code, Msg: fmt.Sprintf(format, a...)}
}

func auN(n int) json.Number { return json.Number(strconv.Itoa(n)) }

func auSplitArgs(s string) (pos []string, named map[string]string, order []string) {
	named = map[string]string{}
	for _, raw := range strings.Split(s, ",") {
		a := jsTrim(raw)
		if a == "" {
			continue
		}
		if eq := strings.Index(a, "="); eq > 0 {
			k := jsTrim(a[:eq])
			if _, dup := named[k]; !dup {
				order = append(order, k)
			}
			named[k] = jsTrim(a[eq+1:])
		} else {
			pos = append(pos, a)
		}
	}
	return pos, named, order
}

// auIntArg reads an optional integer option (up to 15 digits, an optional minus).
func auIntArg(s string, has bool, what string) (int, bool, error) {
	if !has {
		return 0, false, nil
	}
	if !reAuIntArg.MatchString(s) {
		return 0, false, auErr("bad_shorthand", "%s must be an integer, got '%s'", what, s)
	}
	n, _ := strconv.Atoi(s)
	return n, true, nil
}

func auFirst(pos []string) (string, bool) {
	if len(pos) == 0 {
		return "", false
	}
	return pos[0], true
}

func auOnly(pos []string, named map[string]string, order []string, n int, names []string, shorthand string) error {
	if len(pos) > n {
		return auErr("bad_shorthand", "'%s' takes at most %d positional argument(s)", shorthand, n)
	}
	for _, k := range order {
		if !contains(names, k) {
			return auErr("bad_shorthand", "'%s' has no option '%s'", shorthand, k)
		}
	}
	return nil
}

func auListArg(s, shorthand string) ([]any, error) {
	parts := strings.Split(s, "|")
	out := make([]any, len(parts))
	for i, x := range parts {
		x = jsTrim(x)
		if x == "" {
			return nil, auErr("bad_shorthand", "'%s' needs values separated by |", shorthand)
		}
		out[i] = x
	}
	return out, nil
}

// ActionParseParamShorthand expands one param shorthand (email phone url uuid ccy country secret bool date datetime duration
// text(N) string(N) message(N) int(MIN..MAX) count(MAX) money(CCY|@param, max=, min=, exp=, provenance=) id:<type> enum(a|b)
// set(a|b) array(items, max=, min=)); a trailing `?` makes it optional.
func ActionParseParamShorthand(src string) (map[string]any, error) {
	s := jsTrim(src)
	m := reAuShorthand.FindStringSubmatchIndex(s)
	if m == nil {
		return nil, auErr("bad_shorthand", "unknown param shorthand '%s'", src)
	}
	name := s[m[2]:m[3]]
	hasInner := m[4] >= 0
	inner := ""
	if hasInner {
		inner = s[m[4]:m[5]]
	}
	optional := m[6] >= 0
	pos, named, order := auSplitArgs(inner)
	bare := func() error {
		if hasInner {
			return auErr("bad_shorthand", "'%s' takes no arguments", name)
		}
		return nil
	}
	var p map[string]any
	switch {
	case name == "email":
		if err := bare(); err != nil {
			return nil, err
		}
		p = map[string]any{"type": "string", "role": "contact.email", "format": "email", "tags": []any{"pii"}, "max_len": auN(254)}
	case name == "phone":
		if err := bare(); err != nil {
			return nil, err
		}
		p = map[string]any{"type": "string", "role": "contact.phone", "format": "phone_e164", "tags": []any{"pii"}, "max_len": auN(16)}
	case name == "url":
		if err := bare(); err != nil {
			return nil, err
		}
		p = map[string]any{"type": "string", "role": "url.target", "format": "url", "max_len": auN(2048)}
	case name == "uuid":
		if err := bare(); err != nil {
			return nil, err
		}
		p = map[string]any{"type": "string", "format": "uuid", "max_len": auN(36)}
	case name == "ccy":
		if err := bare(); err != nil {
			return nil, err
		}
		p = map[string]any{"type": "string", "role": "money.currency", "format": "iso_currency", "max_len": auN(3)}
	case name == "country":
		if err := bare(); err != nil {
			return nil, err
		}
		p = map[string]any{"type": "string", "format": "iso_country", "max_len": auN(2)}
	case name == "secret":
		if err := bare(); err != nil {
			return nil, err
		}
		p = map[string]any{"type": "string", "role": "credential.secret", "tags": []any{"secret"}, "max_len": auN(512)}
	case name == "bool":
		if err := bare(); err != nil {
			return nil, err
		}
		p = map[string]any{"type": "boolean"}
	case name == "date":
		if err := bare(); err != nil {
			return nil, err
		}
		p = map[string]any{"type": "date"}
	case name == "datetime":
		if err := bare(); err != nil {
			return nil, err
		}
		p = map[string]any{"type": "datetime"}
	case name == "duration":
		if err := auOnly(pos, named, order, 1, nil, "duration"); err != nil {
			return nil, err
		}
		a, has := auFirst(pos)
		mx, hasMx, err := auIntArg(a, has, "duration max (ms)")
		if err != nil {
			return nil, err
		}
		p = map[string]any{"type": "duration"}
		if hasMx {
			p["min"], p["max"] = auN(0), auN(mx)
		}
	case name == "text" || name == "string":
		if err := auOnly(pos, named, order, 1, nil, name); err != nil {
			return nil, err
		}
		a, has := auFirst(pos)
		n, hasN, err := auIntArg(a, has, name+" length")
		if err != nil {
			return nil, err
		}
		p = map[string]any{"type": "string"}
		if hasN {
			p["max_len"] = auN(n)
		}
	case name == "message":
		if err := auOnly(pos, named, order, 1, nil, "message"); err != nil {
			return nil, err
		}
		a, has := auFirst(pos)
		ml, hasMl, err := auIntArg(a, has, "message length")
		if err != nil {
			return nil, err
		}
		if !hasMl {
			ml = 1024
		}
		p = map[string]any{"type": "string", "role": "text.message", "tags": []any{"free_text_outbound"}, "max_len": auN(ml)}
	case name == "int":
		if err := auOnly(pos, named, order, 1, nil, "int"); err != nil {
			return nil, err
		}
		var r []string
		if len(pos) > 0 {
			r = reAuIntRange.FindStringSubmatch(pos[0])
			if r == nil {
				return nil, auErr("bad_shorthand", "int takes MIN..MAX, for example int(0..100)")
			}
		}
		p = map[string]any{"type": "integer"}
		if r != nil {
			lo, _ := strconv.Atoi(r[1])
			hi, _ := strconv.Atoi(r[2])
			p["min"], p["max"] = auN(lo), auN(hi)
		}
	case name == "count":
		if err := auOnly(pos, named, order, 1, nil, "count"); err != nil {
			return nil, err
		}
		a, has := auFirst(pos)
		mx, hasMx, err := auIntArg(a, has, "count max")
		if err != nil {
			return nil, err
		}
		p = map[string]any{"type": "integer", "role": "count.limit", "min": auN(1)}
		if hasMx {
			p["max"] = auN(mx)
		}
		p["unit"] = map[string]any{"kind": "count"}
	case name == "money":
		if err := auOnly(pos, named, order, 1, []string{"max", "min", "exp", "provenance"}, "money"); err != nil {
			return nil, err
		}
		c, has := auFirst(pos)
		if !has {
			return nil, auErr("bad_shorthand", "money needs a currency: money(USD) or money(@currency_param)")
		}
		var ccy any = c
		if strings.HasPrefix(c, "@") {
			ccy = map[string]any{"from": c[1:]}
		}
		mxs, hasMxs := named["max"]
		mx, hasMx, err := auIntArg(mxs, hasMxs, "money max")
		if err != nil {
			return nil, err
		}
		prov, hasProv := named["provenance"]
		if !hasProv {
			prov = "first_party" // an amount defaults to provenance first_party
		}
		if !contains(provenanceLevels, prov) {
			return nil, auErr("bad_shorthand", "money provenance must be one of %s", strings.Join(provenanceLevels, ", "))
		}
		mns, hasMns := named["min"]
		mn, hasMn, err := auIntArg(mns, hasMns, "money min")
		if err != nil {
			return nil, err
		}
		exs, hasExs := named["exp"]
		ex, hasEx, err := auIntArg(exs, hasExs, "money exp")
		if err != nil {
			return nil, err
		}
		if !hasMn {
			mn = 1
		}
		if !hasEx {
			ex = 2
		}
		p = map[string]any{"type": "integer", "role": "money.amount", "min": auN(mn)}
		if hasMx {
			p["max"] = auN(mx)
		}
		p["unit"] = map[string]any{"kind": "money", "ccy": ccy, "exp": auN(ex)}
		p["provenance_min"] = prov
	case name == "enum" || name == "set":
		if !hasInner {
			return nil, auErr("bad_shorthand", "%s needs values: %s(a|b|c)", name, name)
		}
		vals, err := auListArg(inner, name)
		if err != nil {
			return nil, err
		}
		typ := "string"
		if name == "set" {
			typ = "set"
		}
		p = map[string]any{"type": typ, "values": vals}
	case name == "array":
		if err := auOnly(pos, named, order, 1, []string{"max", "min"}, "array"); err != nil {
			return nil, err
		}
		items, _ := auFirst(pos)
		if items != "string" && items != "integer" {
			return nil, auErr("bad_shorthand", "array(items): items is string or integer")
		}
		mxs, hasMxs := named["max"]
		mx, hasMx, err := auIntArg(mxs, hasMxs, "array max")
		if err != nil {
			return nil, err
		}
		mns, hasMns := named["min"]
		mn, hasMn, err := auIntArg(mns, hasMns, "array min")
		if err != nil {
			return nil, err
		}
		p = map[string]any{"type": "array", "items": items}
		if hasMn {
			p["min_items"] = auN(mn)
		}
		if hasMx {
			p["max_items"] = auN(mx)
		}
	case strings.HasPrefix(name, "id:"):
		if err := bare(); err != nil {
			return nil, err
		}
		p = map[string]any{"type": "string", "role": "id." + name[3:], "max_len": auN(64)}
	default:
		return nil, auErr("bad_shorthand", "unknown param shorthand '%s'", name)
	}
	if optional {
		p["required"] = false
	}
	return p, nil
}

// ActionParseResourceShorthand expands `type`, `type:*`, `type:exact`, `type:prefix*` or `type:prefix*{class,min..max}`, with an
// optional `@one|set|tenant|global`.
func ActionParseResourceShorthand(src string) (map[string]any, error) {
	s := jsTrim(src)
	scope := ""
	if at := reAuAt.FindStringSubmatchIndex(s); at != nil {
		name := s[at[2]:at[3]]
		if !contains(defScopes, name) {
			return nil, auErr("bad_shorthand", "unknown resource scope '@%s'", name)
		}
		scope = name
		s = s[:at[2]-1]
	}
	or := func(def string) string {
		if scope != "" {
			return scope
		}
		return def
	}
	colon := strings.Index(s, ":")
	if colon < 0 {
		return map[string]any{"type": s, "id": "*", "scope": or("tenant")}, nil
	}
	typ, idsrc := s[:colon], s[colon+1:]
	if idsrc == "*" {
		return map[string]any{"type": typ, "id": "*", "scope": or("set")}, nil
	}
	star := strings.Index(idsrc, "*")
	if star < 0 {
		return map[string]any{"type": typ, "id": map[string]any{"exact": idsrc}, "scope": or("one")}, nil
	}
	prefix, rest := idsrc[:star], idsrc[star+1:]
	cls, ln := "alnum", authorDefaultIDLen
	if rest != "" {
		r := reAuIDRest.FindStringSubmatch(rest)
		if r == nil || !contains(idClasses, r[1]) {
			return nil, auErr("bad_shorthand", "resource id '%s': expected prefix*{class,min..max}", idsrc)
		}
		lo, _ := strconv.Atoi(r[2])
		hi, _ := strconv.Atoi(r[3])
		cls, ln = r[1], [2]int{lo, hi}
	}
	return map[string]any{"type": typ, "id": map[string]any{"prefix": prefix, "class": cls, "len": []any{auN(ln[0]), auN(ln[1])}}, "scope": or("one")}, nil
}

// ActionDefaultTitle is the title an action gets when it names none: "acme.invoice.send" -> "Send invoice".
func ActionDefaultTitle(verb string) string {
	parts := strings.Split(verb, ".")
	seg := parts[1:]
	act := verb
	if len(seg) > 0 {
		act = seg[len(seg)-1]
	}
	words := []string{act}
	if len(seg) > 0 {
		words = append(words, seg[:len(seg)-1]...)
	}
	t := strings.ReplaceAll(strings.Join(words, " "), "_", " ")
	r, w := utf8.DecodeRuneInString(t)
	if w == 0 || (r == utf8.RuneError && w <= 1) || r > 0xFFFF { // the reference upper-cases one UTF-16 unit: an astral character stays
		return t
	}
	return cases.Upper(language.Und).String(string(r)) + t[w:]
}

func auAsList(v any) any {
	if s, ok := v.(string); ok {
		return []any{s}
	}
	return v
}

// auProvided is `entry.get(k) is not None`.
func auProvided(entry map[string]any, k string) (any, bool) {
	v, ok := entry[k]
	return v, ok && v != nil
}

// ActionExpansion is the result of expanding one authoring entry: the def and the notes about what was added for the author.
type ActionExpansion struct {
	Def   map[string]any
	Notes []any
}

// ActionExpand expands one authoring entry (shorthands or full def members); since (nil for none) is the file-level default.
func ActionExpand(entry any, since any) (*ActionExpansion, error) {
	em, ok := entry.(map[string]any)
	if !ok {
		return nil, auErr("bad_action", "an action must be an object")
	}
	for _, k := range jsKeys(em) {
		if !contains(defKeys, k) {
			return nil, auErr("bad_action", "unknown member '%s'", k)
		}
	}
	if v, has := em["v"]; has {
		if f, isNum := jsNum(v); !isNum || f != 1 {
			return nil, auErr("bad_action", "unsupported def version")
		}
	}
	if k, has := em["kind"]; has {
		if s, isStr := k.(string); !isStr || s != actionDefKind {
			return nil, auErr("bad_action", "kind must be '%s'", actionDefKind)
		}
	}
	verb, isStr := em["verb"].(string)
	if !isStr {
		return nil, auErr("bad_action", "verb is required")
	}
	notes := []any{}
	if _, has := em["kind"]; has {
		full := make(map[string]any, len(em)+1) // the full form is taken exactly as written: validateDef decides
		full["v"] = auN(1)
		for k, v := range em {
			full[k] = v
		}
		if je := defJSONProfileError(full, 0); je != "" {
			return nil, auErr("bad_action", "not strict JSON: %s", je)
		}
		return &ActionExpansion{full, notes}, nil
	}
	out := map[string]any{"v": auN(1), "kind": actionDefKind, "verb": verb}
	if v, has := em["aliases"]; has {
		out["aliases"] = auAsList(v)
	}
	if t, ok := auProvided(em, "title"); ok {
		out["title"] = t
	} else {
		out["title"] = ActionDefaultTitle(verb)
	}
	if v, has := em["description"]; has {
		out["description"] = v
	}
	if v, has := em["effects"]; has {
		out["effects"] = auAsList(v)
	}
	if res, has := em["resource"]; has {
		if rs, isS := res.(string); isS {
			r, err := ActionParseResourceShorthand(rs)
			if err != nil {
				return nil, err
			}
			out["resource"] = r
		} else {
			out["resource"] = res
		}
	}
	params := map[string]any{}
	if pv, has := em["params"]; has {
		pm, isMap := pv.(map[string]any)
		if !isMap {
			return nil, auErr("bad_action", "params must be an object")
		}
		for _, k := range jsKeys(pm) {
			if s, isS := pm[k].(string); isS {
				p, err := ActionParseParamShorthand(s)
				if err != nil {
					return nil, err
				}
				params[k] = p
			} else {
				params[k] = pm[k]
			}
		}
	}
	if v, has := em["reversibility"]; has {
		out["reversibility"] = v
	}
	if b, has := em["blast"]; has {
		if bs, isS := b.(string); isS {
			out["blast"] = map[string]any{"radius": bs}
		} else {
			out["blast"] = b
		}
	}
	if bs, isS := em["blast"].(string); isS && !contains(defBlastRadii, bs) {
		return nil, auErr("bad_action", "unknown blast radius '%s'", bs)
	}
	if v, has := em["side_effects"]; has {
		out["side_effects"] = v
	}
	var effects []any
	if l, isList := out["effects"].([]any); isList {
		effects = l
	}
	idem, hasIdem := em["idempotency"]
	if is, isS := idem.(string); isS && hasIdem {
		if is == "key_param" {
			idem = map[string]any{"mode": "key_param", "param": authorIdemParam}
		} else {
			idem = map[string]any{"mode": is}
		}
	}
	if !hasIdem {
		for _, e := range effects {
			if s, isS := e.(string); isS && contains(authorAutoIdemEffects, s) {
				idem, hasIdem = map[string]any{"mode": "key_param", "param": authorIdemParam}, true
				notes = append(notes, map[string]any{"verb": verb, "message": authorIdemParam + " auto-added"})
				break
			}
		}
	}
	if im, isMap := idem.(map[string]any); isMap && im["mode"] == "key_param" && im["param"] == authorIdemParam {
		if _, exists := params[authorIdemParam]; !exists {
			params[authorIdemParam] = map[string]any{"type": "string", "max_len": auN(64)}
		}
	}
	if hasIdem {
		out["idempotency"] = idem
	}
	out["params"] = params
	for _, k := range []string{"context", "traits"} {
		if v, has := em[k]; has {
			out[k] = auAsList(v)
		}
	}
	for _, k := range []string{"audience", "compensates", "bindings", "examples", "source"} {
		if v, has := em[k]; has {
			out[k] = v
		}
	}
	if rv, ok := auProvided(em, "review"); ok {
		out["review"] = rv
	} else {
		out["review"] = map[string]any{"state": "authored"}
	}
	if sn, ok := auProvided(em, "since"); ok {
		out["since"] = sn
	} else if since != nil {
		out["since"] = since
	}
	if _, hasEff := em["effects"]; !hasEff { // the reference keeps the member as undefined, which has no strict JSON form
		return nil, auErr("bad_action", "not strict JSON: only JSON values are allowed")
	}
	if _, hasRes := em["resource"]; !hasRes {
		return nil, auErr("bad_action", "not strict JSON: only JSON values are allowed")
	}
	if je := defJSONProfileError(out, 0); je != "" {
		return nil, auErr("bad_action", "not strict JSON: %s", je)
	}
	return &ActionExpansion{out, notes}, nil
}

func auHasProtoKey(v any, depth int) bool {
	if depth > 40 {
		return true
	}
	switch t := v.(type) {
	case []any:
		for _, x := range t {
			if auHasProtoKey(x, depth+1) {
				return true
			}
		}
	case map[string]any:
		for k, x := range t {
			if k == "__proto__" || auHasProtoKey(x, depth+1) {
				return true
			}
		}
	}
	return false
}

func auNewResult() map[string]any {
	return map[string]any{"defs": []any{}, "notes": []any{}, "errors": []any{}, "locs": map[string]any{}, "rules": map[string]any{}}
}

// ActionLoadValue expands an already parsed document ({ns, since?, actions: [...]}, or one raw def) to {defs, notes, errors,
// locs, rules[, ns]}. It never fails: every problem is an entry of `errors`.
func ActionLoadValue(doc any) map[string]any {
	res := auNewResult()
	fail := func(msg string) map[string]any {
		out := make(map[string]any, len(res))
		for k, v := range res {
			out[k] = v
		}
		out["errors"] = []any{map[string]any{"message": msg}}
		return out
	}
	if auHasProtoKey(doc, 0) {
		return fail("the document contains a '__proto__' member or nests deeper than 40")
	}
	dm, isMap := doc.(map[string]any)
	if !isMap {
		return fail("the document must be an object")
	}
	var since any
	var entries []any
	if k, _ := dm["kind"].(string); k == actionDefKind {
		entries = []any{doc}
	} else {
		for _, k := range jsKeys(dm) {
			if !contains(authorFileKeys, k) {
				return fail(fmt.Sprintf("unknown top-level member '%s' (expected ns, since, actions)", k))
			}
		}
		ns, isStr := dm["ns"].(string)
		if !isStr || !reAuNS.MatchString(ns) {
			return fail("ns must be a lowercase identifier")
		}
		res["ns"] = ns
		if s, isS := dm["since"].(string); isS {
			since = s
		} else if _, has := dm["since"]; has {
			return fail("since must be a string")
		}
		l, isList := dm["actions"].([]any)
		if !isList {
			return fail("actions must be a list")
		}
		entries = l
	}
	errs := res["errors"].([]any)
	for index, e := range entries {
		verb := ""
		if em, ok := e.(map[string]any); ok {
			verb, _ = em["verb"].(string)
		}
		report := func(message string) {
			x := map[string]any{"index": index}
			if verb != "" {
				x["verb"] = verb
			}
			x["message"] = message
			errs = append(errs, x)
		}
		func() {
			defer func() {
				if r := recover(); r != nil {
					report(fmt.Sprintf("malformed action: %v", r))
				}
			}()
			var rules any
			hasRules := false
			entry := e
			if em, ok := e.(map[string]any); ok {
				if rv, has := em["rules"]; has {
					rules, hasRules = rv, true
					stripped := make(map[string]any, len(em))
					var keys []string
					for _, k := range jsKeys(em) {
						if k != "rules" {
							stripped[k] = em[k]
							keys = append(keys, k)
						}
					}
					recordKeyOrder(stripped, keys)
					entry = stripped
				}
			}
			ex, err := ActionExpand(entry, since)
			if err != nil {
				var ce *CodedError
				if errors.As(err, &ce) {
					report(ce.Msg)
				} else {
					report("malformed action: " + err.Error())
				}
				return
			}
			d := ex.Def
			if bad := validateDef(d); bad != "" {
				report(bad)
				return
			}
			if hasRules {
				if re := ActionBusinessRulesError(d, rules); re != "" {
					report(re)
					return
				}
				res["rules"].(map[string]any)[d["verb"].(string)] = rules
			}
			res["defs"] = append(res["defs"].([]any), d)
			res["notes"] = append(res["notes"].([]any), ex.Notes...)
		}()
	}
	res["errors"] = errs
	return res
}

// ActionLoadText loads an authoring file (YAML 1.2 core, or JSON when format is "json") with source positions. Input above 1 MiB
// is refused; see actions_yaml_load.go for what the YAML reader refuses beyond the reference.
func ActionLoadText(text, format string) map[string]any {
	fail := func(message string, line, col int) map[string]any {
		res := auNewResult()
		res["errors"] = []any{map[string]any{"message": message, "line": line, "column": col}}
		return res
	}
	if len(text) > authorMaxBytes {
		return fail(fmt.Sprintf("the file is larger than %d bytes", authorMaxBytes), 1, 1)
	}
	var root *ydNode
	var err error
	prefix := "not YAML: "
	if format == "json" {
		prefix = "not JSON: "
		root, err = yamlParseJSON(text)
	} else {
		root, err = yamlParseDocument(text, true)
	}
	var value any
	if err == nil {
		value, err = yamlToValue(root)
	}
	if err != nil {
		var le *YamlLoadError
		if errors.As(err, &le) {
			return fail(prefix+le.Message, le.Line, le.Column)
		}
		return fail(prefix+err.Error(), 1, 1)
	}
	res := ActionLoadValue(value)
	if pos := yamlPositionsOf(root); pos != nil {
		yamlAttachPositions(res, pos)
	}
	return res
}

// ActionAuthor is the constructor over the JSON form: the same expansion as the loader (so the same digest). It fails with
// bad_action on a malformed spec.
func ActionAuthor(verb string, spec map[string]any) (map[string]any, error) {
	entry := map[string]any{"verb": verb}
	for k, v := range spec {
		entry[k] = v
	}
	ex, err := ActionExpand(entry, nil)
	if err != nil {
		return nil, err
	}
	if bad := validateDef(ex.Def); bad != "" {
		return nil, auErr("bad_action", "%s: %s", verb, bad)
	}
	return ex.Def, nil
}

// ---- the typed param constructors -----------------------------------------------------------------------------------------
// Each returns the same param the matching shorthand expands to. A trailing `x` adds or overrides members.

func auExtra(p, x map[string]any) map[string]any {
	if len(x) == 0 {
		return p
	}
	out := make(map[string]any, len(p)+len(x))
	for k, v := range p {
		out[k] = v
	}
	for k, v := range x {
		out[k] = v
	}
	return out
}

func auFixed(src string, x map[string]any) map[string]any {
	p, err := ActionParseParamShorthand(src)
	if err != nil {
		panic(err) // the fixed shorthands are well formed
	}
	return auExtra(p, x)
}

func auOptInt(src string, n *int, x map[string]any) (map[string]any, error) {
	if n != nil {
		src += "(" + strconv.Itoa(*n) + ")"
	}
	p, err := ActionParseParamShorthand(src)
	if err != nil {
		return nil, err
	}
	return auExtra(p, x), nil
}

func ActionPEmail(x map[string]any) map[string]any    { return auFixed("email", x) }
func ActionPPhone(x map[string]any) map[string]any    { return auFixed("phone", x) }
func ActionPURL(x map[string]any) map[string]any      { return auFixed("url", x) }
func ActionPUUID(x map[string]any) map[string]any     { return auFixed("uuid", x) }
func ActionPCcy(x map[string]any) map[string]any      { return auFixed("ccy", x) }
func ActionPCountry(x map[string]any) map[string]any  { return auFixed("country", x) }
func ActionPSecret(x map[string]any) map[string]any   { return auFixed("secret", x) }
func ActionPBool(x map[string]any) map[string]any     { return auFixed("bool", x) }
func ActionPDate(x map[string]any) map[string]any     { return auFixed("date", x) }
func ActionPDatetime(x map[string]any) map[string]any { return auFixed("datetime", x) }

// ActionPDuration: maxMs nil for no bound.
func ActionPDuration(maxMs *int, x map[string]any) (map[string]any, error) {
	return auOptInt("duration", maxMs, x)
}

// ActionPMessage: maxLen nil for the default length.
func ActionPMessage(maxLen *int, x map[string]any) (map[string]any, error) {
	return auOptInt("message", maxLen, x)
}

// ActionPText: maxLen nil for no bound.
func ActionPText(maxLen *int, x map[string]any) (map[string]any, error) {
	return auOptInt("text", maxLen, x)
}

// ActionPInt: a range needs both bounds, otherwise the unbounded integer.
func ActionPInt(min, max *int, x map[string]any) (map[string]any, error) {
	src := "int"
	if min != nil && max != nil {
		src = fmt.Sprintf("int(%d..%d)", *min, *max)
	}
	p, err := ActionParseParamShorthand(src)
	if err != nil {
		return nil, err
	}
	return auExtra(p, x), nil
}

// ActionPCount: max nil for no bound.
func ActionPCount(max *int, x map[string]any) (map[string]any, error) {
	return auOptInt("count", max, x)
}

// ActionPMoney: ccy is a literal ISO code, or {"from": "param"} naming the currency param; o holds max / min / exp.
func ActionPMoney(ccy any, o, x map[string]any) (map[string]any, error) {
	var c string
	switch t := ccy.(type) {
	case string:
		c = t
	case map[string]any:
		c = "@" + jsValueString(t["from"])
	default:
		return nil, auErr("bad_shorthand", "money needs a currency: money(USD) or money(@currency_param)")
	}
	opts := ""
	for _, k := range []string{"max", "min", "exp"} {
		if v, ok := o[k]; ok && v != nil {
			opts += ", " + k + "=" + jsValueString(v)
		}
	}
	p, err := ActionParseParamShorthand("money(" + c + opts + ")")
	if err != nil {
		return nil, err
	}
	return auExtra(p, x), nil
}

func ActionPID(typ string, x map[string]any) (map[string]any, error) {
	p, err := ActionParseParamShorthand("id:" + typ)
	if err != nil {
		return nil, err
	}
	return auExtra(p, x), nil
}

func ActionPEnum(values []string, x map[string]any) (map[string]any, error) {
	p, err := ActionParseParamShorthand("enum(" + strings.Join(values, "|") + ")")
	if err != nil {
		return nil, err
	}
	return auExtra(p, x), nil
}

func ActionPSet(values []string, x map[string]any) (map[string]any, error) {
	p, err := ActionParseParamShorthand("set(" + strings.Join(values, "|") + ")")
	if err != nil {
		return nil, err
	}
	return auExtra(p, x), nil
}

// ActionPArray: max nil for no bound.
func ActionPArray(items string, max *int, x map[string]any) (map[string]any, error) {
	src := "array(" + items + ")"
	if max != nil {
		src = fmt.Sprintf("array(%s, max=%d)", items, *max)
	}
	p, err := ActionParseParamShorthand(src)
	if err != nil {
		return nil, err
	}
	return auExtra(p, x), nil
}

// ActionPOptional marks a param as not required.
func ActionPOptional(d map[string]any) map[string]any {
	out := make(map[string]any, len(d)+1)
	for k, v := range d {
		out[k] = v
	}
	out["required"] = false
	return out
}
