package pca

// The action-definition linter: structural and semantic findings (errors and warnings) over a set of defs, the report renderers
// (text, SARIF) and the structural half of the undo engine the linter needs (the reversibility a call can have, whether a def can
// be reversible, and whether a compensating action can undo another).

import (
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// ActionLintRules is the lint rule table as {id, severity, title} rows.
func ActionLintRules() []any {
	out := make([]any, len(actionLintRules))
	for i, r := range actionLintRules {
		out[i] = []any{r.id, r.severity, r.title}
	}
	return out
}

var (
	lintDestroyRe = regexp.MustCompile(`^(delete|destroy|remove|purge|drop|erase|wipe|revoke|terminate|truncate)(_|$)`)
	lintSendRe    = regexp.MustCompile(`^(send|email|notify|sms|message|post_to|broadcast|invite)(_|$)`)
	lintExportRe  = regexp.MustCompile(`^(export|download|dump|backup|extract)(_|$)`)
	lintIngEdRe   = regexp.MustCompile(`(ing|ed)$`)
	lintPluralRe  = regexp.MustCompile(`[^s]s$`)
	lintUsIsRe    = regexp.MustCompile(`(us|is)$`)
)

func lintLastSeg(verb string) string {
	if i := strings.LastIndex(verb, "."); i >= 0 {
		return verb[i+1:]
	}
	return verb
}

func lintBindingKeys(d map[string]any) []string {
	b, _ := d["bindings"].(map[string]any)
	var out []string
	str := func(m map[string]any, k string) string { return jsAnyString(m[k]) }
	if m, ok := b["mcp"].(map[string]any); ok && m != nil {
		out = append(out, "mcp:"+str(m, "tool"))
	}
	if m, ok := b["openapi"].(map[string]any); ok && m != nil {
		out = append(out, "openapi:"+str(m, "operationId"))
	}
	if m, ok := b["http"].(map[string]any); ok && m != nil {
		out = append(out, "http:"+strings.ToUpper(str(m, "method"))+" "+str(m, "path"))
	}
	if m, ok := b["graphql"].(map[string]any); ok && m != nil {
		out = append(out, "graphql:"+str(m, "op")+"."+str(m, "field"))
	}
	if m, ok := b["grpc"].(map[string]any); ok && m != nil {
		out = append(out, "grpc:"+str(m, "service")+"/"+str(m, "method"))
	}
	if m, ok := b["asyncapi"].(map[string]any); ok && m != nil {
		out = append(out, "asyncapi:"+str(m, "op")+" "+str(m, "channel"))
	}
	return out
}

var lintNameGroups = [][]string{{"create_", "new_", "add_", "make_"}, {"delete_", "remove_", "destroy_"}}

func lintVocabularyIssues(x any, reg Registry) []string {
	m, ok := x.(map[string]any)
	if !ok {
		return nil
	}
	var out []string
	if ef, ok := m["effects"].([]any); ok {
		for _, e := range ef {
			if s, isS := e.(string); !isS || !contains(defEffects, s) {
				out = append(out, "unknown effect '"+jsAnyString(e)+"'")
			}
		}
	}
	if ps, ok := m["params"].(map[string]any); ok {
		for _, n := range jsKeys(ps) {
			q, ok := ps[n].(map[string]any)
			if !ok {
				continue
			}
			if r, has := q["role"]; has && !isRole(r) {
				out = append(out, n+": unknown role '"+jsAnyString(r)+"'")
			}
			if f, has := q["format"]; has && !isFormat(f) {
				out = append(out, n+": unknown format '"+jsAnyString(f)+"'")
			}
		}
	}
	if cs, ok := m["context"].([]any); ok {
		for _, c := range cs {
			if s, isS := c.(string); !isS || !isContextKey(s) {
				out = append(out, "unknown context key '"+jsAnyString(c)+"' (known: "+strings.Join(contextKeys, ", ")+", session_taint_max:<level>)")
			}
		}
	}
	if ts, ok := m["traits"].([]any); ok {
		for _, t := range ts {
			if s, isS := t.(string); isS {
				if _, in := reg[s]; !in {
					out = append(out, "unknown trait '"+s+"'")
				}
			}
		}
	}
	return out
}

// ActionPrulesViolations is the structural param rules the def violates among ids (nil = all rules).
func ActionPrulesViolations(d map[string]any, ids []string) []string {
	if ids == nil {
		ids = paramRuleIDs
	}
	n := normalizeDef(d)
	ps := adParamsOf(n)
	names := make([]string, 0, len(ps))
	for k := range ps {
		names = append(names, k)
	}
	adSortU16(names)
	withRole := func(pred func(string) bool) []map[string]any {
		var out []map[string]any
		for _, k := range names {
			p, _ := ps[k].(map[string]any)
			if r, ok := p["role"].(string); ok && pred(r) {
				out = append(out, p)
			}
		}
		return out
	}
	allP := func(pred func(map[string]any) bool, list []map[string]any) bool {
		for _, p := range list {
			if !pred(p) {
				return false
			}
		}
		return true
	}
	res, _ := n["resource"].(map[string]any)
	var bad []string
	for _, id := range ids {
		ok := true
		switch id {
		case "money_has_currency":
			ok = allP(func(p map[string]any) bool {
				u, isU := p["unit"].(map[string]any)
				if !isU || u["kind"] != "money" {
					return false
				}
				if _, isS := u["ccy"].(string); isS {
					return true
				}
				from := ""
				if cm, isM := u["ccy"].(map[string]any); isM {
					from = jsAnyString(cm["from"])
				}
				c, has := ps[from].(map[string]any)
				return has && c["role"] == "money.currency" && c["format"] == "iso_currency"
			}, withRole(func(r string) bool { return r == "money.amount" || r == "money.fee" }))
		case "money_amount_bounded":
			ok = allP(func(p map[string]any) bool {
				_, hasMin := p["min"]
				_, hasMax := p["max"]
				return p["type"] == "integer" && hasMin && hasMax
			}, withRole(func(r string) bool { return r == "money.amount" }))
		case "id_not_wildcard":
			ok = !(res["id"] == "*" && res["scope"] == "one")
		case "recipient_param_declared":
			ok = n["audience"] == "resource" || len(withRole(func(r string) bool { return r == "party.payee" || strings.HasPrefix(r, "contact.") })) > 0
		case "array_bounded":
			ok = true
			for _, k := range names {
				p, _ := ps[k].(map[string]any)
				if p["type"] == "array" && p["max_items"] == nil {
					ok = false
				}
			}
		case "export_bounded":
			ok = res["scope"] == "one"
			if !ok {
				for _, p := range withRole(func(r string) bool { return r == "count.limit" }) {
					if _, has := p["max"]; has {
						ok = true
					}
				}
			}
		case "secret_not_logged":
			ok = allP(func(p map[string]any) bool { tg, _ := strsOf(p["tags"]); return contains(tg, "secret") },
				withRole(func(r string) bool { return strings.HasPrefix(r, "credential.") }))
		case "pay_has_idempotency":
			im, _ := n["idempotency"].(map[string]any)
			ok = !contains(adStrs(n, "effects"), "pay") || im["mode"] != "none"
		}
		if !ok {
			bad = append(bad, id)
		}
	}
	return bad
}

func undoReversibilityFor(d, params map[string]any) string {
	n := normalizeDef(d)
	r := n["reversibility"]
	if s, ok := r.(string); ok {
		return s
	}
	rm, _ := r.(map[string]any)
	by := jsAnyString(rm["by"])
	k, hasK := "", false
	if v, has := params[by]; has {
		switch t := v.(type) {
		case string:
			k, hasK = t, true
		case bool:
			k, hasK = strconv.FormatBool(t), true
		default:
			if f, ok := jsNum(v); ok && f == math.Trunc(f) && math.Abs(f) <= 9007199254740991 && !(f == 0 && math.Signbit(f)) {
				k, hasK = jsLenientNumber(f), true
			}
		}
	}
	m, _ := rm["map"].(map[string]any)
	if hasK {
		if v, has := m[k]; has {
			return jsAnyString(v)
		}
	}
	if dv, has := rm["default"]; has && dv != nil {
		return jsAnyString(dv)
	}
	return "irreversible"
}

// ActionReversibilityFor is the reversibility class a call with these params has.
func ActionReversibilityFor(d, params map[string]any) string { return undoReversibilityFor(d, params) }

// ActionMayBeReversible is whether a def can be reversible for some call (a declared reversible class).
func ActionMayBeReversible(d map[string]any) bool {
	r, has := d["reversibility"]
	if !has {
		return false
	}
	if s, ok := r.(string); ok {
		return s == "reversible"
	}
	rm, _ := r.(map[string]any)
	m, _ := rm["map"].(map[string]any)
	for _, v := range m {
		if v == "reversible" {
			return true
		}
	}
	return rm["default"] == "reversible"
}

// ActionCompensationShape says whether comp can undo orig: which parameters it copies from the original call and which one names
// the target. Returns {ok: true, shape: {copied, target?}} or {ok: false, reason}.
func ActionCompensationShape(orig, comp map[string]any) map[string]any {
	no := func(r string) map[string]any { return map[string]any{"ok": false, "reason": r} }
	cverb := jsAnyString(comp["verb"])
	if isReadOnlyEffects(adStrs(comp, "effects")) {
		return no("the compensating action " + cverb + " only reads")
	}
	cres, _ := comp["resource"].(map[string]any)
	ores, _ := orig["resource"].(map[string]any)
	if cres["type"] != ores["type"] {
		return no(fmt.Sprintf("the compensating action %s acts on %s, not %s", cverb, jsAnyString(cres["type"]), jsAnyString(ores["type"])))
	}
	nc := normalizeDef(comp)
	ncp := adParamsOf(nc)
	op := adParamsOf(orig)
	idem := ""
	if im, _ := nc["idempotency"].(map[string]any); im["mode"] == "key_param" {
		idem = jsAnyString(im["param"])
	}
	names := make([]string, 0, len(ncp))
	for k := range ncp {
		names = append(names, k)
	}
	adSortU16(names)
	copied := []string{}
	target := ""
	hasTarget := false
	for _, name := range names {
		if idem != "" && name == idem {
			continue
		}
		p, _ := ncp[name].(map[string]any)
		if a, ok := op[name].(map[string]any); ok && a["type"] == p["type"] && jsStrictEq(lintItems(a), lintItems(p)) {
			copied = append(copied, name)
			continue
		}
		if p["required"] != true {
			continue
		}
		if p["role"] == "id."+jsAnyString(cres["type"]) && !hasTarget {
			target, hasTarget = name, true
			continue
		}
		return no(fmt.Sprintf("the compensating action %s needs '%s', which neither the original call nor its result supplies", cverb, name))
	}
	shape := map[string]any{"copied": anyStrs(copied)}
	if hasTarget {
		shape["target"] = target
	}
	return map[string]any{"ok": true, "shape": shape}
}

func lintItems(p map[string]any) any {
	if v, has := p["items"]; has && v != nil {
		return v
	}
	return nil
}

func lintSortFindings(out []map[string]any) {
	str := func(m map[string]any, k string) string { s, _ := m[k].(string); return s }
	sort.SliceStable(out, func(i, j int) bool {
		for _, k := range []string{"verb", "rule", "param", "message"} {
			a, b := str(out[i], k), str(out[j], k)
			if a != b {
				return u16Less(a, b)
			}
		}
		return false
	})
}

// ActionLintDefs lints raw defs. opts: customTraits (extra trait defs), stability ("draft"|"beta"|"stable"), ns, and att (nil =
// no attestation check; else the constant the check answers).
func ActionLintDefs(raw []any, opts map[string]any) ([]any, error) {
	var out []map[string]any
	add := func(rule string, verb any, message string, param ...string) {
		sev := "error"
		for _, r := range actionLintRules {
			if r.id == rule {
				sev = r.severity
			}
		}
		f := map[string]any{"rule": rule, "severity": sev, "message": message}
		if v, ok := verb.(string); ok {
			f["verb"] = v
		}
		if len(param) > 0 {
			f["param"] = param[0]
		}
		out = append(out, f)
	}
	var attest ActionDiffConfirmed
	if c, ok := opts["att"].(bool); ok {
		attest = func(map[string]any) bool { return c }
	}
	reg := coreRegistry
	if ct, ok := opts["customTraits"].([]any); ok && len(ct) > 0 {
		if r, err := extendRegistry(coreRegistry, ct); err != nil {
			add("LD-007", nil, "invalid custom traits: "+strings.TrimPrefix(err.Error(), "bad_registry: "))
		} else {
			reg = r
		}
	}
	var defs []map[string]any
	for _, x := range raw {
		var verb any
		if m, ok := x.(map[string]any); ok {
			if v, isS := m["verb"].(string); isS {
				verb = v
			}
		}
		if vocab := lintVocabularyIssues(x, reg); len(vocab) > 0 {
			for _, v := range vocab {
				add("LD-007", verb, v)
			}
			continue
		}
		if bad := validateDef(x); bad != "" {
			add("LD-000", verb, bad)
			continue
		}
		defs = append(defs, x.(map[string]any))
	}
	byVerb := map[string]map[string]any{}
	names := map[string]string{}
	for _, d := range defs {
		v := jsAnyString(d["verb"])
		if _, dup := byVerb[v]; dup {
			add("LD-009", v, "verb '"+v+"' is defined twice")
		}
		byVerb[v] = d
	}
	for _, d := range defs {
		v := jsAnyString(d["verb"])
		al, _ := strsOf(d["aliases"])
		for _, n := range append([]string{v}, al...) {
			if owner, has := names[n]; has && owner != v {
				add("LD-009", v, "'"+n+"' is also a name of '"+owner+"'")
			} else if !has {
				names[n] = v
			}
		}
	}
	bound := map[string]string{}
	for _, d := range defs {
		v := jsAnyString(d["verb"])
		for _, k := range lintBindingKeys(d) {
			if owner, has := bound[k]; has && owner != v {
				add("LD-014", v, "binding "+k+" is also bound by '"+owner+"'")
			} else if !has {
				bound[k] = v
			}
		}
	}
	for _, grp := range lintNameGroups {
		used := map[string]int{}
		groupOf := func(d map[string]any) string {
			seg := lintLastSeg(jsAnyString(d["verb"]))
			for _, pfx := range grp {
				if strings.HasPrefix(seg, pfx) {
					return pfx
				}
			}
			return ""
		}
		for _, d := range defs {
			if g := groupOf(d); g != "" {
				used[g]++
			}
		}
		if len(used) > 1 {
			win, best := "", -1
			for g, c := range used {
				if c > best || (c == best && u16Less(g, win)) {
					win, best = g, c
				}
			}
			for _, d := range defs {
				if g := groupOf(d); g != "" && g != win {
					add("LW-008", d["verb"], "uses '"+g+"' where its siblings use '"+win+"'")
				}
			}
		}
	}
	if ns, ok := opts["ns"].(string); ok {
		for _, d := range defs {
			if first, _, _ := strings.Cut(jsAnyString(d["verb"]), "."); first != ns {
				add("LW-008", d["verb"], "verb namespace '"+first+"' differs from the file namespace '"+ns+"'")
			}
		}
	}
	for _, d := range defs {
		if err := lintOne(d, reg, opts, attest, byVerb, add); err != nil {
			return nil, err
		}
	}
	lintSortFindings(out)
	res := make([]any, len(out))
	for i, f := range out {
		res[i] = f
	}
	return res, nil
}

func lintOne(d map[string]any, reg Registry, opts map[string]any, attest ActionDiffConfirmed, byVerb map[string]map[string]any,
	add func(rule string, verb any, message string, param ...string)) error {
	n := normalizeDef(d)
	np := adParamsOf(n)
	pnames := make([]string, 0, len(np))
	for k := range np {
		pnames = append(pnames, k)
	}
	adSortU16(pnames)
	hint := hintTraits(d)
	hintCl, err := reg.closure(hint)
	if err != nil {
		return err
	}
	hfl, _ := reg.floorOf(hint)
	decl := declProfile(d)
	hintEff := joinProfile(decl, hfl)
	tset, cl := map[string]bool{}, map[string]bool{}
	for _, t := range hint {
		tset[t] = true
	}
	for _, t := range hintCl {
		cl[t] = true
	}
	verb := jsAnyString(d["verb"])
	effects := adStrs(d, "effects")
	params := func(pred func(map[string]any) bool) []string {
		var out []string
		for _, k := range pnames {
			if q, _ := np[k].(map[string]any); pred(q) {
				out = append(out, k)
			}
		}
		return out
	}
	role := func(q map[string]any) string { r, _ := q["role"].(string); return r }
	has := func(q map[string]any, k string) bool { _, h := q[k]; return h }
	tagsOf := func(q map[string]any) []string { t, _ := strsOf(q["tags"]); return t }

	if lintDestroyRe.MatchString(lintLastSeg(verb)) && !contains(effects, "delete") {
		add("LD-001", verb, "the verb says '"+lintLastSeg(verb)+"' but effects do not include delete")
	}
	for _, k := range params(func(q map[string]any) bool { return role(q) == "money.amount" || role(q) == "money.fee" }) {
		q, _ := np[k].(map[string]any)
		u, isU := q["unit"].(map[string]any)
		if !isU || u["kind"] != "money" {
			add("LD-002", verb, "a money parameter needs a unit of kind money with a currency", k)
		} else if _, isS := u["ccy"].(string); !isS {
			from := ""
			if cm, ok := u["ccy"].(map[string]any); ok {
				from = jsAnyString(cm["from"])
			}
			if c, ok := np[from].(map[string]any); !ok || c["role"] != "money.currency" || c["format"] != "iso_currency" {
				add("LD-002", verb, "the currency parameter '"+from+"' needs role money.currency and format iso_currency", k)
			}
		}
	}
	for _, k := range params(func(q map[string]any) bool { return role(q) == "money.currency" }) {
		if q, _ := np[k].(map[string]any); q["format"] != "iso_currency" {
			add("LD-002", verb, "a currency parameter needs the iso_currency format", k)
		}
	}
	for _, k := range params(func(q map[string]any) bool { return q["type"] == "integer" || q["type"] == "duration" }) {
		q, _ := np[k].(map[string]any)
		if strings.HasPrefix(role(q), "id.") || (role(q) == "count.limit" && has(q, "max")) {
			continue
		}
		if !has(q, "min") || !has(q, "max") {
			a, b := "min", "max"
			if !has(q, "min") {
				a = "no min"
			}
			if !has(q, "max") {
				b = "no max"
			}
			add("LD-003", verb, "a numeric parameter needs both min and max (has "+a+", "+b+")", k)
		}
	}
	idem, _ := n["idempotency"].(map[string]any)
	if (contains(effects, "pay") || tset["pca.money_moving"]) && idem["mode"] == "none" {
		add("LD-004", verb, "a money-moving action needs idempotency key_param or natural")
	}
	pii := params(func(q map[string]any) bool {
		r := role(q)
		return contains(tagsOf(q), "pii") || strings.HasPrefix(r, "contact.") || strings.HasPrefix(r, "person.")
	})
	if len(pii) > 0 {
		expected := map[string]bool{}
		if se, ok := d["side_effects"].([]any); ok {
			for _, s := range se {
				if sm, _ := s.(map[string]any); sm["kind"] == "send" || sm["kind"] == "export" {
					expected[jsAnyString(sm["kind"])] = true
				}
			}
		}
		if lintSendRe.MatchString(lintLastSeg(verb)) {
			expected["send"] = true
		}
		if lintExportRe.MatchString(lintLastSeg(verb)) {
			expected["export"] = true
		}
		var es []string
		for e := range expected {
			es = append(es, e)
		}
		adSortU16(es)
		for _, e := range es {
			if !contains(effects, e) {
				what := "be exported"
				if e == "send" {
					what = "be sent"
				}
				add("LD-005", verb, "personal data can "+what+" ("+strings.Join(pii, ", ")+") but effects do not include "+e)
			}
		}
	}
	if _, hasRev := d["reversibility"]; hasRev && revRank[decl.Rev] < revRank[hfl.Rev] {
		add("LD-006", verb, "declared reversibility "+decl.Rev+" is below the floor "+hfl.Rev)
	}
	if _, hasBlast := d["blast"]; hasBlast && decl.Blast < hfl.Blast {
		add("LD-006", verb, fmt.Sprintf("declared blast %d is below the floor %d", decl.Blast, hfl.Blast))
	}
	res, _ := n["resource"].(map[string]any)
	if res["id"] == "*" && res["scope"] == "one" {
		add("LD-008", verb, "resource id '*' with scope one names every resource at once")
	}
	if !isReadOnlyEffects(effects) && ActionMayBeReversible(d) {
		comp, hasComp := d["compensates"]
		cv := jsAnyString(comp)
		switch {
		case !hasComp:
			add("LD-010", verb, "a write declared reversible must name its compensating action (compensates)")
		case byVerb[cv] == nil:
			add("LD-010", verb, "compensates '"+cv+"', which is not in the pack")
		default:
			if s := ActionCompensationShape(d, byVerb[cv]); s["ok"] != true {
				add("LD-010", verb, "compensates '"+cv+"', which cannot undo it: "+s["reason"].(string))
			}
		}
	}
	review, _ := d["review"].(map[string]any)
	if review["state"] == "confirmed" {
		a, _ := review["attestation"].(map[string]any)
		dg, _ := defDigest(d)
		td, _ := traitsDigest(reg)
		_, signed := a["sig"]
		switch {
		case a == nil:
			add("LD-011", verb, "confirmed without an attestation")
		case a["def_digest"] != dg:
			add("LD-011", verb, "the attestation covers a different digest of this def")
		case a["traits_digest"] != td:
			add("LD-011", verb, "the attestation was made against a different trait registry")
		case (attest != nil && !attest(d)) || (attest == nil && !signed):
			add("LD-011", verb, "the attestation is not signed by a pinned reviewer")
		}
	}
	dismissed := map[string]bool{}
	var dismissedList []any
	if a, ok := review["attestation"].(map[string]any); ok {
		dismissedList, _ = a["dismissed"].([]any)
	}
	if review["state"] == "confirmed" {
		for _, x := range dismissedList {
			if m, _ := x.(map[string]any); m != nil {
				dismissed[jsAnyString(m["trait"])] = true
			}
		}
	}
	if prov, ok := review["provenance"].(map[string]any); ok {
		if un, _ := strsOf(prov["union"]); un != nil {
			for _, t := range un {
				if !cl[t] && !dismissed[t] {
					add("LD-011", verb, "the union-added trait "+t+" was removed without a signed dismissal")
				}
			}
		}
	}
	for _, r := range ActionPrulesViolations(d, hintEff.Prules) {
		if r != "money_has_currency" && r != "money_amount_bounded" && r != "pay_has_idempotency" {
			add("LD-012", verb, "structural rule "+r+" is required by the action's traits and violated")
		}
	}
	if isReadOnlyEffects(effects) {
		enforced := contains(adStrs(d, "context"), "sandbox_attested")
		for _, k := range params(func(q map[string]any) bool { return role(q) == "code.command" || role(q) == "query.sql" }) {
			if !enforced {
				add("LD-013", verb, "a read-only action takes code or a query it cannot prove read-only (declare context sandbox_attested)", k)
			}
		}
		for _, k := range params(func(q map[string]any) bool { return contains(tagsOf(q), "credential") }) {
			add("LD-013", verb, "a read-only action handles a credential", k)
		}
	}
	// warnings
	desc, hasDesc := d["description"]
	if !hasDesc {
		add("LW-001", verb, "description is missing")
	} else if ds, _ := desc.(string); len(ds) > 400 { // UTF-8 bytes
		add("LW-001", verb, "description is longer than 400 bytes")
	}
	title := jsAnyString(d["title"])
	first := ""
	for i, r := range title {
		if isJSSpace(r) {
			first = title[:i]
			break
		}
		first = title
	}
	first = strings.ToLower(first)
	if lintIngEdRe.MatchString(first) || (lintPluralRe.MatchString(first) && !lintUsIsRe.MatchString(first)) || first == "a" || first == "an" || first == "the" {
		add("LW-001", verb, "title '"+title+"' is not imperative")
	}
	for _, k := range params(func(q map[string]any) bool { return q["type"] == "string" && !has(q, "max_len") && !has(q, "values") }) {
		add("LW-002", verb, "a string parameter without max_len (the default is 1024; say it)", k)
	}
	if cl["pca.external_communication"] {
		ip, _ := idem["param"].(string)
		for _, k := range params(func(q map[string]any) bool {
			r, hasR := q["role"].(string)
			return q["type"] == "string" && !has(q, "values") && !has(q, "format") && (!hasR || strings.HasPrefix(r, "text.")) && !contains(tagsOf(q), "free_text_outbound")
		}) {
			if k != ip {
				add("LW-003", verb, "free text flows into an outbound action without tags: [free_text_outbound]", k)
			}
		}
	}
	if opts["stability"] == "stable" && (review["state"] == "unreviewed" || review["state"] == "suggested") {
		add("LW-004", verb, "a "+jsAnyString(review["state"])+" def in a stable pack")
	}
	if a, ok := review["attestation"].(map[string]any); ok {
		dl, _ := a["dismissed"].([]any)
		for _, x := range dl {
			m, _ := x.(map[string]any)
			if utf16Len(jsTrim(jsAnyString(m["reason"]))) < 5 {
				add("LW-005", verb, "dismissed trait "+jsAnyString(m["trait"])+" has no reason")
			}
		}
	}
	for _, k := range params(func(q map[string]any) bool { return q["type"] == "array" && q["max_items"] == nil }) {
		add("LW-006", verb, "an array parameter without max_items", k)
	}
	for _, k := range params(func(q map[string]any) bool {
		return sensitivityRank[effectiveParamSensitivity(q)] >= sensitivityRank["critical"] && !has(q, "provenance_min")
	}) {
		add("LW-007", verb, "a critical parameter without provenance_min", k)
	}
	if ex, _ := d["examples"].([]any); (tset["pca.money_moving"] || tset["pca.destructive"] || tset["pca.privilege_change"]) && len(ex) == 0 {
		add("LW-009", verb, "no example for a money-moving, destructive or privilege-changing action")
	}
	if _, has := d["since"]; !has {
		add("LW-010", verb, "since is missing")
	}
	return nil
}

// ActionLintFails is whether any finding is an error (or, strict, a warning).
func ActionLintFails(fs []any, strict bool) bool {
	for _, f := range fs {
		m, _ := f.(map[string]any)
		if m["severity"] == "error" || (strict && m["severity"] == "warning") {
			return true
		}
	}
	return false
}

// ActionLintText renders findings as text lines and a summary.
func ActionLintText(fs []any) string {
	if len(fs) == 0 {
		return "0 errors, 0 warnings"
	}
	e, w := 0, 0
	lines := make([]string, len(fs))
	for i, x := range fs {
		f, _ := x.(map[string]any)
		sev := jsAnyString(f["severity"])
		switch sev {
		case "error":
			e++
		case "warning":
			w++
		}
		loc := ""
		if file, ok := f["file"].(string); ok && file != "" {
			loc = file
			if line, has := f["line"]; has {
				col := any(jsNumber(1))
				if c, hc := f["column"]; hc && c != nil {
					col = c
				}
				loc += ":" + jsAnyString(line) + ":" + jsAnyString(col)
			}
			loc += ": "
		}
		v, _ := f["verb"].(string)
		p, _ := f["param"].(string)
		pp := ""
		if p != "" {
			pp = " [" + p + "]"
		}
		sep := ""
		if v != "" || p != "" {
			sep = ": "
		}
		pad := sev + strings.Repeat(" ", max(0, 7-len(sev)))
		lines[i] = pad + " " + jsAnyString(f["rule"]) + "  " + loc + v + pp + sep + jsAnyString(f["message"])
	}
	plural := func(n int) string {
		if n == 1 {
			return ""
		}
		return "s"
	}
	s := strings.Join(lines, "\n") + fmt.Sprintf("\n%d error%s, %d warning%s", e, plural(e), w, plural(w))
	if notes := len(fs) - e - w; notes > 0 {
		s += fmt.Sprintf(", %d note%s", notes, plural(notes))
	}
	return s
}

// ActionToSarif renders findings as a SARIF 2.1.0 log; tool is {name?, version?}.
func ActionToSarif(fs []any, tool map[string]any) map[string]any {
	level := func(s string) string {
		if s == "error" || s == "warning" {
			return s
		}
		return "note"
	}
	type rr struct{ id, sev, title string }
	rules := []rr{{"LD-000", "error", "the def is not well formed and cannot be loaded"}, {"LN-001", "note", "an informational note from the loader"}}
	for _, r := range actionLintRules {
		rules = append(rules, rr{r.id, r.severity, r.title})
	}
	rs := make([]any, len(rules))
	for i, r := range rules {
		rs[i] = map[string]any{"id": r.id, "shortDescription": map[string]any{"text": r.title}, "defaultConfiguration": map[string]any{"level": level(r.sev)}}
	}
	name := any("pca actions lint")
	if n, ok := tool["name"]; ok && n != nil {
		name = n
	}
	driver := map[string]any{"name": name}
	if v, ok := tool["version"]; ok && eatTruthy(v) {
		driver["version"] = v
	}
	driver["rules"] = rs
	results := make([]any, len(fs))
	for i, x := range fs {
		f, _ := x.(map[string]any)
		v, _ := f["verb"].(string)
		p, _ := f["param"].(string)
		prefix := ""
		if v != "" {
			prefix = v
			if p != "" {
				prefix += " [" + p + "]"
			}
			prefix += ": "
		}
		loc := map[string]any{}
		if file, ok := f["file"].(string); ok && file != "" {
			pl := map[string]any{"artifactLocation": map[string]any{"uri": file}}
			if line, has := f["line"]; has {
				col := any(jsNumber(1))
				if c, hc := f["column"]; hc && c != nil {
					col = c
				}
				pl["region"] = map[string]any{"startLine": line, "startColumn": col}
			}
			loc["physicalLocation"] = pl
		}
		if v != "" {
			loc["logicalLocations"] = []any{map[string]any{"name": v, "kind": "member"}}
		}
		results[i] = map[string]any{"ruleId": f["rule"], "level": level(jsAnyString(f["severity"])),
			"message": map[string]any{"text": prefix + jsAnyString(f["message"])}, "locations": []any{loc}}
	}
	return map[string]any{"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
		"runs": []any{map[string]any{"tool": map[string]any{"driver": driver}, "results": results}}}
}
