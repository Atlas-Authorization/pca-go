package pca

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode/utf16"
)

// Ternary decision, tighten-only model rule (rule 21) and units check (rule 20): a port of
// packages/pca/src/decision.ts (the TypeScript is authoritative; goal-to-decision track T2, contracts C-50..C-55).
// deny < escalate < allow; Meet (the minimum) is the only combinator, so escalate never becomes allow. Every function is
// total; anything malformed fails closed (deny / ok false).

var decisionRank = map[string]int{"deny": 0, "escalate": 1, "allow": 2}

// Meet is the lower of two decisions; an unknown value is deny.
func Meet(a, b string) string {
	x, ok1 := decisionRank[a]
	y, ok2 := decisionRank[b]
	if !ok1 || !ok2 {
		return "deny"
	}
	if x <= y {
		return a
	}
	return b
}

// MeetAll is the meet over a list (allow for the empty list, the neutral element).
func MeetAll(ds ...string) string {
	acc := "allow"
	for _, d := range ds {
		acc = Meet(acc, d)
	}
	return acc
}

// SignalCeiling is the highest decision a model signal permits (anything but ok / escalate is deny).
func SignalCeiling(s any) string {
	switch s {
	case "ok":
		return "allow"
	case "escalate":
		return "escalate"
	}
	return "deny"
}

// TightenDecision is G-T9: a model can only move a decision down.
func TightenDecision(base string, signal any) string { return Meet(base, SignalCeiling(signal)) }

// PepDecision is `d === 'escalate' && answered === true ? 'allow' : d`: anything but an answered escalate is returned UNCHANGED,
// whatever d is (as the reference does).
func PepDecision(d string, answered bool) string {
	if d == "escalate" && answered {
		return "allow"
	}
	return d
}

var escalateReasonPrefixes = []string{"intent_required:", "escalate:"}

// DecisionOf is the ternary decision of a verdict {allow, checks, reasons}.
func DecisionOf(v map[string]any) string {
	if v["allow"] == true {
		return "allow"
	}
	checks, ok := v["checks"].(map[string]any)
	if !ok {
		return "deny"
	}
	reasons, _ := v["reasons"].([]any)
	names := make([]string, 0, len(checks))
	for n := range checks {
		names = append(names, n)
	}
	sort.Strings(names)
	failing := 0
	for _, name := range names {
		if checks[name] != "fail" {
			continue
		}
		failing++
		head := name + ": "
		own := 0
		for _, r := range reasons {
			s, ok := r.(string)
			if !ok || !strings.HasPrefix(s, head) {
				continue
			}
			own++
			body := s[len(head):]
			esc := false
			for _, p := range escalateReasonPrefixes {
				if strings.HasPrefix(body, p) {
					esc = true
				}
			}
			if !esc {
				return "deny"
			}
		}
		if own == 0 {
			return "deny"
		}
	}
	if failing > 0 {
		return "escalate"
	}
	return "deny"
}

var (
	modelNameRe  = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	paramPathRe  = regexp.MustCompile(`^action\.params\.[A-Za-z0-9_-]{1,64}$`)
	modelEnvRoot = map[string]bool{"class": true, "prov": true, "judge": true, "detect": true}
)

// modelNameSource is the pattern the reference prints in its reasons (NAME_RE.source).
const modelNameSource = "^[a-z][a-z0-9_]{0,63}$"

// maxTightenRules is MAX_TIGHTEN_RULES.
const maxTightenRules = 64

// utf16Len is the JavaScript `.length` of a string: UTF-16 code units.
func utf16Len(s string) int { return len(utf16.Encode([]rune(s))) }

func isModelDerivedPath(path string, single []string) bool {
	seg := strings.Split(path, ".")
	if seg[0] != "env" || len(seg) < 2 {
		return false
	}
	if modelEnvRoot[seg[1]] {
		return true
	}
	if seg[1] == "world" {
		if len(seg) == 2 {
			return len(single) > 0
		}
		for _, s := range single {
			if s == seg[2] {
				return true
			}
		}
	}
	return false
}

func collectCondPaths(c any, out map[string]bool, depth int) {
	o, ok := c.(map[string]any)
	if !ok || depth > 64 {
		return
	}
	for _, k := range []string{"all_of", "any_of"} {
		if xs, ok := o[k].([]any); ok {
			for _, x := range xs {
				collectCondPaths(x, out, depth+1)
			}
		}
	}
	if n, has := o["not"]; has && n != nil {
		collectCondPaths(n, out, depth+1)
	}
	for _, k := range []string{"field", "ref", "collection"} {
		if s, ok := o[k].(string); ok {
			out[s] = true
		}
	}
}

func collectPredicatePaths(lists []any, inScope func(any) bool, out map[string]bool) {
	for _, l := range lists {
		arr, ok := l.([]any)
		if !ok {
			continue
		}
		for _, p := range arr {
			if inScope != nil && !inScope(p) {
				continue
			}
			po, _ := p.(map[string]any)
			if w, ok := po["where"].([]any); ok {
				for _, c := range w {
					collectCondPaths(c, out, 0)
				}
			}
		}
	}
}

// ModelPathsRead is every model-derived env path a list of predicate lists reads (`field`, `ref` or `collection` of any nested
// condition), sorted by UTF-8 byte order and de-duplicated; single names the worlds decided by one oracle.
func ModelPathsRead(predicateLists []any, single []string) []string {
	found := map[string]bool{}
	collectPredicatePaths(predicateLists, nil, found)
	return sortedUTF8(found, func(p string) bool { return isModelDerivedPath(p, single) })
}

func sortedUTF8(set map[string]bool, keep func(string) bool) []string {
	out := []string{}
	for k := range set {
		if keep(k) {
			out = append(out, k)
		}
	}
	sort.Strings(out) // Go strings compare by UTF-8 bytes
	return out
}

func sortedMapKeys(o map[string]any) []string {
	ks := make([]string, 0, len(o))
	for k := range o {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// closedMemberError is the reference closedMembers: the first unknown member, then the first missing required one, named
// `<where>.<member>`, members visited in `Object.keys` order (jsKeys: the parsed text order, see keyorder.go).
func closedMemberError(o map[string]any, required, optional []string, where string) string {
	known := map[string]bool{}
	for _, k := range required {
		known[k] = true
	}
	for _, k := range optional {
		known[k] = true
	}
	for _, k := range jsKeys(o) {
		if !known[k] {
			return "unknown member '" + where + "." + k + "'"
		}
	}
	for _, k := range required {
		if _, ok := o[k]; !ok {
			return "missing member '" + where + "." + k + "'"
		}
	}
	return ""
}

// tightenListError is the reference tightenListError; present is false for an ABSENT member (well-formed). A JSON null is
// present and is not an array.
func tightenListError(t any, present bool) string {
	if !present {
		return ""
	}
	arr, ok := t.([]any)
	if !ok {
		return "tighten must be an array"
	}
	if len(arr) > maxTightenRules {
		return fmt.Sprintf("tighten has more than %d rules", maxTightenRules)
	}
	ids := map[string]bool{}
	for i, x := range arr {
		r, ok := x.(map[string]any)
		if !ok {
			return fmt.Sprintf("tighten[%d] must be an object", i)
		}
		if e := closedMemberError(r, []string{"id", "when", "signal"}, []string{"reason"}, fmt.Sprintf("tighten[%d]", i)); e != "" {
			return e
		}
		id, ok := r["id"].(string)
		if !ok || !modelNameRe.MatchString(id) {
			return fmt.Sprintf("tighten[%d].id must match %s", i, modelNameSource)
		}
		if ids[id] {
			return fmt.Sprintf("tighten[%d].id '%s' is a duplicate", i, id)
		}
		ids[id] = true
		if _, ok := r["when"].(map[string]any); !ok {
			return fmt.Sprintf("tighten[%d].when must be a condition object", i)
		}
		if r["signal"] != "escalate" && r["signal"] != "deny" {
			return fmt.Sprintf("tighten[%d].signal must be 'escalate' or 'deny'", i)
		}
		if rs, has := r["reason"]; has {
			s, ok := rs.(string)
			if !ok || utf16Len(s) > 256 {
				return fmt.Sprintf("tighten[%d].reason must be a string of at most 256 characters", i)
			}
		}
	}
	return ""
}

// TightenResult is the outcome of rule 21.
type TightenResult struct {
	Outcome   string
	Legacy    bool
	Offending []string
	Reason    string
}

// DecideTighten is rule 21 over {predicates, tighten, polarity, single_source, context}. Reasons are the reference's, byte
// for byte. A JSON null `tighten` or `polarity` is PRESENT (malformed), never read as absent.
func DecideTighten(in map[string]any) (res TightenResult) {
	defer func() {
		if r := recover(); r != nil {
			res = TightenResult{Outcome: "deny", Offending: []string{}, Reason: fmt.Sprint("evaluation error (fail closed): ", r)}
		}
	}()
	deny := func(why string, off []string) TightenResult {
		return TightenResult{Outcome: "deny", Offending: off, Reason: why}
	}
	single := []string{}
	if ss, ok := in["single_source"].([]any); ok {
		for _, s := range ss {
			if x, ok := s.(string); ok {
				single = append(single, x)
			}
		}
	}
	pol, hasPol := in["polarity"]
	if hasPol && pol != "legacy" {
		return deny("model_polarity must be 'legacy' when present", []string{})
	}
	tl, hasTl := in["tighten"]
	if e := tightenListError(tl, hasTl); e != "" {
		return deny("malformed tighten list: "+e, []string{})
	}
	var offending []string
	if ps, ok := in["predicates"].([]any); ok {
		offending = ModelPathsRead(ps, single)
	} else {
		offending = []string{}
	}
	legacy := hasPol && len(offending) > 0
	if len(offending) > 0 && !legacy {
		return deny("a grant's where reads model-derived path(s) "+strings.Join(offending, ", ")+
			": a model may only tighten (move them into tighten[]) (rule 21)", offending)
	}
	out := "ok"
	reason := ""
	ctx, _ := in["context"].(map[string]any)
	if ctx == nil {
		ctx = map[string]any{}
	}
	rules, _ := tl.([]any)
	for _, x := range rules {
		r := x.(map[string]any)
		sig, why := "", ""
		switch evaluateConditionTri(r["when"], ctx, &regexBudget{}) {
		case triTrue:
			sig = r["signal"].(string)
			if sig == "deny" {
				why = "denied by"
			} else {
				why = "escalate: asked by"
			}
			why += " tighten rule '" + r["id"].(string) + "'"
			if rs, has := r["reason"]; has {
				why += " (" + rs.(string) + ")"
			}
		case triUnknown:
			sig = "escalate"
			why = "escalate: rule '" + r["id"].(string) + "' could not be decided (a value it reads is missing or ill-typed)"
		}
		if sig != "" && decisionRank[SignalCeiling(sig)] < decisionRank[SignalCeiling(out)] {
			out = sig
			reason = why
		}
	}
	return TightenResult{Outcome: out, Legacy: legacy, Offending: offending, Reason: reason}
}

// unitTagsError is the reference unitTagsError (keys are visited in `Object.keys` order, see keyorder.go).
func unitTagsError(u any) string {
	m, ok := u.(map[string]any)
	if !ok {
		return "units must be an object"
	}
	if len(m) > 64 {
		return "units has more than 64 entries"
	}
	for _, k := range jsKeys(m) {
		if !paramPathRe.MatchString(k) {
			return "units key '" + k + "' must be an action.params.<name> path"
		}
		t, ok := m[k].(map[string]any)
		if !ok {
			return "units['" + k + "'] must be an object"
		}
		if e := closedMemberError(t, []string{"kind"}, []string{"currency", "exponent"}, "units['"+k+"']"); e != "" {
			return e
		}
		if s, ok := t["kind"].(string); !ok || utf16Len(s) == 0 || utf16Len(s) > 64 {
			return "units['" + k + "'].kind must be a string of 1..64 characters"
		}
		if c, has := t["currency"]; has {
			if s, ok := c.(string); !ok || utf16Len(s) == 0 || utf16Len(s) > 16 {
				return "units['" + k + "'].currency must be a string of 1..16 characters"
			}
		}
		if e, has := t["exponent"]; has {
			f, _ := jsNum(e)
			if !jsIsInt(e) || f < 0 || f > 18 {
				return "units['" + k + "'].exponent must be an integer in [0, 18]"
			}
		}
	}
	return ""
}

// sameUnitTag is `a.kind === b.kind && a.currency === b.currency && a.exponent === b.exponent` (an absent member equals only an
// absent member).
func sameUnitTag(a, b map[string]any) bool {
	for _, k := range []string{"kind", "currency", "exponent"} {
		x, h1 := a[k]
		y, h2 := b[k]
		if h1 != h2 || (h1 && !jsStrictEq(x, y)) {
			return false
		}
	}
	return true
}

// unitTagText is the reference tagText: `<kind ?? '?'>[/<currency>][/e<exponent>]`, or `no unit` for no tag.
func unitTagText(t map[string]any) string {
	if t == nil {
		return "no unit"
	}
	s := "?"
	if k, has := t["kind"]; has && k != nil {
		s = jsValueString(k)
	}
	if c, has := t["currency"]; has {
		s += "/" + jsValueString(c)
	}
	if e, has := t["exponent"]; has {
		s += "/e" + jsValueString(e)
	}
	return s
}

// DecideUnits is rule 20: the policy's unit tags must equal the unit the action schema declares for each parameter.
// reason is the reference's, byte for byte.
func DecideUnits(in map[string]any) (ok bool, reason string) {
	defer func() {
		if r := recover(); r != nil {
			ok, reason = false, fmt.Sprint("evaluation error (fail closed): ", r)
		}
	}()
	if e := unitTagsError(in["units"]); e != "" {
		return false, e
	}
	tags := in["units"].(map[string]any)
	verb, isStr := in["verb"].(string)
	if !isStr || verb == "" {
		return false, "the verb is missing"
	}
	su := map[string]any{}
	if v, has := in["schema_units"]; has { // an explicit null is NOT absent
		m, isMap := v.(map[string]any)
		if !isMap {
			return false, "the schema units table must be an object"
		}
		su = m
	}
	params, isMap := in["verb_params"].(map[string]any)
	if !isMap {
		return false, "the schema does not declare verb '" + verb + "'"
	}
	declared := func(path string) (bool, map[string]any) {
		d, isObj := params[path].(map[string]any)
		if !isObj {
			return false, nil
		}
		var tag map[string]any
		if id, isID := d["unit"].(string); isID {
			tag, _ = su[id].(map[string]any)
		}
		return true, tag
	}
	for _, p := range sortedMapKeys(tags) {
		has, tag := declared(p)
		if !has {
			continue
		}
		if tag == nil || !sameUnitTag(tag, tags[p].(map[string]any)) {
			return false, "'" + p + "' is declared as " + unitTagText(tag) + " by the action schema but the policy term is tagged " +
				unitTagText(tags[p].(map[string]any)) + " (unit confusion)"
		}
	}
	read := map[string]bool{}
	if ps, isArr := in["predicates"].([]any); isArr {
		collectPredicatePaths(ps, func(p any) bool {
			po, _ := p.(map[string]any)
			switch v := po["verb"].(type) {
			case string:
				return v == "*" || v == verb
			case []any:
				for _, x := range v {
					if x == verb {
						return true
					}
				}
			}
			return false
		}, read)
	}
	for _, p := range sortedUTF8(read, func(s string) bool { return paramPathRe.MatchString(s) }) {
		has, tag := declared(p)
		if _, tagged := tags[p]; has && tag != nil && !tagged {
			return false, "a policy term reads '" + p + "' (" + unitTagText(tag) + ") without a unit tag"
		}
	}
	return true, ""
}

// V2CheckResult is one reported intent-v2 check: its name, whether it passed and (a failing one) its reason, if it has one.
type V2CheckResult struct {
	Name      string
	OK        bool
	Reason    string
	HasReason bool
}

// FoldV2Reasons is the ordered reason list of a verdict (decision.ts foldV2Reasons): base (the core's own reasons), then one
// `<check>: <reason>` for EVERY failing intent-v2 check not already listed, in pipeline order. A failing check with no reason
// adds nothing (DecisionOf then reads it as a hard failure). The core keeps only its first failure, so without this fold a
// multi-check escalation would look like a deny.
func FoldV2Reasons(base []string, v2 []V2CheckResult) []string {
	out := append([]string{}, base...)
	for _, c := range v2 {
		if c.OK || !c.HasReason {
			continue
		}
		r := c.Name + ": " + c.Reason
		seen := false
		for _, x := range out {
			if x == r {
				seen = true
				break
			}
		}
		if !seen {
			out = append(out, r)
		}
	}
	return out
}
