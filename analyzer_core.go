package pca

// Static analyzability of authority: the bounded decision engine and its relational queries (reachability, vacuity, totality,
// subsumption, disjointness, equivalence, intent conformance). Policies are plain JSON trees; a model, a probe set, a
// representative and every result are plain maps / lists. The engine enumerates a finite distinguishing grid of representative
// actions and evaluates the real predicate evaluator at each, so a verdict is exact over the decided fragment and fails safe
// (`approximate`) outside it. Every entry point may panic with *anlThrow where the reference throws; the exported wrappers
// (analyzer.go) turn that into an error.

import (
	"math"
	"sort"
	"strings"
)

const (
	anlDefaultMaxCombinations = 200000.0
	anlFreshString            = "\x00atlas-analyzer::fresh-unmatched\x00"
	anlFreshVerb              = "\x00atlas-analyzer::fresh-verb\x00"
	anlFreshResource          = "\x00atlas-analyzer::fresh-resource\x00"
)

// ---- caveats ----------------------------------------------------------------------------------------------------------------

func anlUnsat(reason string) map[string]any { return map[string]any{"sat": false, "reason": reason} }

// anlAnalyzeCaveats is the static satisfiability of an envelope caveat set: {sat, reason?, revCap?}.
func anlAnalyzeCaveats(caveats any) map[string]any {
	list, ok := caveats.([]any)
	if !ok {
		return anlUnsat("caveats are not an array")
	}
	notBeforeMax := math.Inf(-1)
	expiresMin := math.Inf(1)
	revCap := -1
	for _, cvv := range list {
		cv, ok := cvv.(map[string]any)
		if !ok {
			return anlUnsat("malformed caveat (not an object with a string type)")
		}
		t, ok := cv["type"].(string)
		if !ok {
			return anlUnsat("malformed caveat (not an object with a string type)")
		}
		switch t {
		case "expires":
			at, ok := anlFin(anlOwn(cv, "at"))
			if !ok {
				return anlUnsat("expires.at is not a finite number")
			}
			expiresMin = math.Min(expiresMin, at)
		case "not_before":
			at, ok := anlFin(anlOwn(cv, "at"))
			if !ok {
				return anlUnsat("not_before.at is not a finite number")
			}
			notBeforeMax = math.Max(notBeforeMax, at)
		case "rate":
			mx, ok1 := anlFin(anlOwn(cv, "max"))
			per, ok2 := anlFin(anlOwn(cv, "per_secs"))
			if !ok1 || !ok2 || per <= 0 {
				return anlUnsat("rate caveat requires finite max and per_secs > 0")
			}
			if mx < 1 {
				return anlUnsat("rate.max " + anlNumStr(mx) + " < 1 forbids every action")
			}
		case "max_blast_radius":
			mx, ok := anlFin(anlOwn(cv, "max"))
			if !ok {
				return anlUnsat("max_blast_radius.max is not a finite number")
			}
			if mx < 0 {
				return anlUnsat("max_blast_radius.max < 0 forbids every action")
			}
		case "reversibility_max":
			cls := anlJS(anlOwn(cv, "class"))
			idx := -1
			for i, r := range anlRevOrder {
				if r == cls {
					idx = i
				}
			}
			if idx < 0 {
				return anlUnsat("reversibility_max.class '" + cls + "' is unknown")
			}
			if revCap < 0 || idx < revCap {
				revCap = idx
			}
		case "delegation_depth":
			mx, ok := anlFin(anlOwn(cv, "max"))
			if !ok {
				return anlUnsat("delegation_depth.max is not a finite number")
			}
			if mx < 0 {
				return anlUnsat("delegation_depth.max < 0 forbids every action")
			}
		case "budget_alloc":
			lim, ok := anlFin(anlOwn(cv, "limit"))
			if !ok || lim < 0 {
				return anlUnsat("budget_alloc.limit must be a finite number >= 0")
			}
		default:
			return anlUnsat("unknown caveat type '" + t + "' (fail closed)")
		}
	}
	if !math.IsInf(notBeforeMax, -1) && !math.IsInf(expiresMin, 1) && notBeforeMax >= expiresMin {
		return anlUnsat("not_before (" + anlNumStr(notBeforeMax) + ") >= expires (" + anlNumStr(expiresMin) + "): the validity window is empty")
	}
	out := map[string]any{"sat": true}
	if revCap >= 0 {
		out["revCap"] = revCap
	}
	return out
}

// ---- constitution -----------------------------------------------------------------------------------------------------------

// anlVetoesFromConstitution maps a constitution's stateless invariants to analyzer vetoes; the rest are reported in `unmodeled`.
func anlVetoesFromConstitution(c any) map[string]any {
	vetoes := []any{}
	unmodeled := []any{}
	invs := anlOwn(c, "invariants")
	list, _ := invs.([]any)
	for _, inv := range list {
		kind := anlGet(inv, "kind")
		iid := anlGet(inv, "id")
		switch kind {
		case "never":
			vetoes = append(vetoes, anlU(map[string]any{"id": iid, "kind": "deny", "when": anlGet(inv, "when")}))
		case "never_unless":
			vetoes = append(vetoes, anlU(map[string]any{"id": iid, "kind": "deny", "when": anlGet(inv, "when"), "unless": anlGet(inv, "unless")}))
		case "require_approval_over":
			vetoes = append(vetoes, anlU(map[string]any{
				"id": iid, "kind": "approval", "when": anlGet(inv, "when"),
				"over":   anlU(map[string]any{"path": anlGet(inv, "amount"), "threshold": anlGet(inv, "threshold")}),
				"unless": anlGet(inv, "approved"),
			}))
		case "cap", "rate":
			unmodeled = append(unmodeled, anlU(map[string]any{"id": iid, "kind": kind, "reason": "windowed total: bounded by maxExposure, not by a per-action veto"}))
		default:
			unmodeled = append(unmodeled, anlU(map[string]any{"id": iid, "kind": kind, "reason": "needs action history"}))
		}
	}
	return map[string]any{"vetoes": vetoes, "unmodeled": unmodeled}
}

// ---- single-field interval / finite-set engine ------------------------------------------------------------------------------

// anlIv is a numeric interval.
type anlIv struct {
	lo, hi       float64
	loInc, hiInc bool
}

var anlFullInterval = anlIv{lo: math.Inf(-1), hi: math.Inf(1)}

func (v anlIv) toJSON() map[string]any {
	return map[string]any{"lo": v.lo, "loInclusive": v.loInc, "hi": v.hi, "hiInclusive": v.hiInc}
}

func anlNumericCellReps(thresholds []float64) []float64 {
	seen := map[float64]bool{}
	var s []float64
	for _, t := range thresholds {
		if !seen[t] {
			seen[t] = true
			if !math.IsInf(t, 0) && !math.IsNaN(t) {
				s = append(s, t)
			}
		}
	}
	if len(s) == 0 {
		return nil
	}
	sort.Float64s(s)
	out := []float64{s[0] - 1}
	for i, ti := range s {
		out = append(out, ti)
		if i+1 < len(s) {
			out = append(out, (ti+s[i+1])/2)
		}
	}
	return append(out, s[len(s)-1]+1)
}

func anlValueKey(x any) string {
	if s, ok := x.(string); ok && s == anlFreshString {
		return "s:__fresh__"
	}
	t := "object"
	switch {
	case anlIsNum(x):
		t = "number"
	case anlIsUndef(x):
		t = "undefined"
	default:
		switch x.(type) {
		case string:
			t = "string"
		case bool:
			t = "boolean"
		}
	}
	if anlIsUndef(x) {
		return t + ":undefined"
	}
	return t + ":" + anlJSON(x)
}

// anlFieldProbes is the representative probe values for one field from the conjunction of `where` conditions on it.
func anlFieldProbes(conditions any) []any {
	var literals []any
	var thresholds []float64
	var prefixes []string
	for _, cc := range anlReqList(conditions) {
		c, ok := anlLeaf(cc)
		if !ok || anlHas(c, "ref") {
			continue
		}
		v := anlOwn(c, "value")
		switch op := anlOwn(c, "op"); op {
		case "eq", "ne":
			literals = append(literals, v)
			if f, ok := anlFin(v); ok {
				thresholds = append(thresholds, f)
			}
		case "in", "nin":
			if xs, ok := v.([]any); ok {
				for _, x := range xs {
					literals = append(literals, x)
					if f, ok := anlFin(x); ok {
						thresholds = append(thresholds, f)
					}
				}
			}
		case "lt", "lte", "gt", "gte":
			if f, ok := anlFin(v); ok {
				thresholds = append(thresholds, f)
			}
		case "prefix", "like", "matches", "is_a":
			if s, ok := v.(string); ok {
				literals = append(literals, s)
				if op == "prefix" {
					prefixes = append(prefixes, s)
				}
			}
		case "member_of":
			if s, ok := v.(string); ok {
				literals = append(literals, s)
			} else if xs, ok := v.([]any); ok {
				for _, x := range xs {
					if s, ok := x.(string); ok {
						literals = append(literals, s)
					}
				}
			}
		}
	}
	out := []any{}
	seen := map[string]bool{}
	add := func(x any) {
		k := anlValueKey(x)
		if !seen[k] {
			seen[k] = true
			out = append(out, x)
		}
	}
	for _, l := range literals {
		add(l)
	}
	for _, n := range anlNumericCellReps(thresholds) {
		add(n)
	}
	for _, p := range prefixes {
		add(p)
		add(p + "x")
	}
	add(anlFreshString)
	return out
}

// anlTighten tightens an interval by one numeric condition (a non-numeric operand returns it as is).
func anlTighten(iv anlIv, op, value any) anlIv {
	v, ok := anlFin(value)
	if !ok {
		return iv
	}
	n := iv
	switch op {
	case "eq":
		if v > n.lo || (v == n.lo && !n.loInc) {
			n.lo, n.loInc = v, true
		}
		if v < n.hi || (v == n.hi && !n.hiInc) {
			n.hi, n.hiInc = v, true
		}
	case "gte":
		if v > n.lo {
			n.lo, n.loInc = v, true
		}
	case "gt":
		if v > n.lo || (v == n.lo && n.loInc) {
			n.lo, n.loInc = v, false
		}
	case "lte":
		if v < n.hi {
			n.hi, n.hiInc = v, true
		}
	case "lt":
		if v < n.hi || (v == n.hi && n.hiInc) {
			n.hi, n.hiInc = v, false
		}
	}
	return n
}

func anlIntervalEmpty(iv anlIv) bool {
	if iv.lo > iv.hi {
		return true
	}
	if iv.lo == iv.hi {
		return !(iv.loInc && iv.hiInc)
	}
	return false
}

// anlNumericConjunctionSatisfiable: is the numeric part of a field's `where` conjunction satisfiable?
func anlNumericConjunctionSatisfiable(conditions any) bool {
	byField := map[string]anlIv{}
	for _, cc := range anlReqList(conditions) {
		c, ok := anlLeaf(cc)
		if !ok || anlHas(c, "ref") {
			continue
		}
		f := c["field"].(string)
		iv, has := byField[f]
		if !has {
			iv = anlFullInterval
		}
		byField[f] = anlTighten(iv, anlOwn(c, "op"), anlOwn(c, "value"))
	}
	for _, iv := range byField {
		if anlIntervalEmpty(iv) {
			return false
		}
	}
	return true
}

func anlPredicateNumericSatisfiable(where any) bool {
	if _, ok := where.([]any); !ok {
		return true
	}
	return anlNumericConjunctionSatisfiable(where)
}

// ---- model ------------------------------------------------------------------------------------------------------------------

// anlNormalizePolicy: a value that is not a policy is an empty policy (the verifier admits nothing under it).
func anlNormalizePolicy(p any) map[string]any {
	pm, ok := p.(map[string]any)
	arr := func(k string) any {
		if ok {
			if l, ok := pm[k].([]any); ok {
				return l
			}
		}
		return []any{}
	}
	return map[string]any{"predicates": arr("predicates"), "caveats": arr("caveats"), "vetoes": arr("vetoes"), "tighten": arr("tighten")}
}

// anlProbeSet is the predicates whose literals shape the grid: the permits plus every veto and tighten trigger.
func anlProbeSet(m map[string]any) []any {
	out := append([]any{}, m["predicates"].([]any)...)
	for _, v := range m["vetoes"].([]any) {
		out = append(out, anlGet(v, "when"))
		if unless, ok := anlGet(v, "unless").([]any); ok && len(unless) > 0 {
			out = append(out, map[string]any{"verb": "*", "where": unless})
		}
		if over := anlGet(v, "over"); anlTruthy(over) {
			out = append(out, map[string]any{"verb": "*", "where": []any{map[string]any{"field": anlGet(over, "path"), "op": "gt", "value": anlGet(over, "threshold")}}})
		}
	}
	for _, t := range m["tighten"].([]any) {
		out = append(out, map[string]any{"verb": "*", "where": []any{anlGet(t, "when")}})
	}
	for _, x := range m["meets"].([]any) {
		out = append(out, anlProbeSet(x.(map[string]any))...)
	}
	return out
}

func anlConditionUndecidable(cc any, reasons *anlSet) {
	c, ok := cc.(map[string]any)
	if !ok {
		return
	}
	if anlIsGroup(c) {
		if xs, ok := c["all_of"].([]any); ok {
			for _, x := range xs {
				anlConditionUndecidable(x, reasons)
			}
		} else if xs, ok := c["any_of"].([]any); ok {
			for _, x := range xs {
				anlConditionUndecidable(x, reasons)
			}
		} else if n, has := c["not"]; has {
			anlConditionUndecidable(n, reasons)
		}
		return
	}
	if _, ok := anlLeaf(c); !ok {
		return
	}
	if anlHas(c, "ref") {
		reasons.add("cross-field `ref` condition — the relation between two fields is not resolved")
	}
	if c["field"] == "action.params" {
		reasons.add("condition on the whole `action.params` object is not enumerated precisely")
	}
	op := anlOwn(c, "op")
	switch op {
	case "lt", "lte", "gt", "gte":
		if !anlIsFin(anlOwn(c, "value")) {
			reasons.add("`" + op.(string) + "` against a non-numeric operand — string ordering is not enumerated exactly")
		}
	case "like", "matches", "is_a", "member_of":
		reasons.add("`" + op.(string) + "` condition — matched by over-approximation, not enumerated exactly")
	}
}

func anlDetectUndecidable(predicates []any) []any {
	reasons := &anlSet{}
	for _, p := range predicates {
		pm, ok := p.(map[string]any)
		if !ok {
			continue
		}
		if r, ok := pm["resource"].(string); ok && strings.HasPrefix(r, "re:") {
			reasons.add("re: regex resource matcher — resource dimension cannot be soundly enumerated")
		}
		if w, ok := pm["where"].([]any); ok {
			for _, c := range w {
				anlConditionUndecidable(c, reasons)
			}
		}
	}
	return reasons.list()
}

// anlToModel is the analyzable model of a policy: {predicates, caveats, vetoes, tighten, meets, caveatSat, caveatReason?, revCap?, undecidable}.
func anlToModel(p any) map[string]any {
	n := anlNormalizePolicy(p)
	ca := anlAnalyzeCaveats(n["caveats"])
	meets := []any{}
	if pm, ok := p.(map[string]any); ok {
		if ms, ok := pm["meet"].([]any); ok {
			for _, x := range ms {
				meets = append(meets, anlToModel(x))
			}
		}
	}
	allSat := true
	for _, x := range meets {
		if x.(map[string]any)["caveatSat"] != true {
			allSat = false
		}
	}
	var reason any
	if ca["sat"] == true {
		for _, x := range meets {
			if xm := x.(map[string]any); xm["caveatSat"] != true {
				reason = xm["caveatReason"]
				break
			}
		}
	} else {
		reason = ca["reason"]
	}
	m := map[string]any{
		"predicates": n["predicates"], "caveats": n["caveats"], "vetoes": n["vetoes"], "tighten": n["tighten"], "meets": meets,
		"caveatSat": ca["sat"] == true && allSat,
	}
	if reason != nil {
		m["caveatReason"] = reason
	}
	capv := -1
	if c, ok := ca["revCap"].(int); ok {
		capv = c
	}
	for _, x := range meets {
		if c, ok := x.(map[string]any)["revCap"].(int); ok && (capv < 0 || c < capv) {
			capv = c
		}
	}
	if capv >= 0 {
		m["revCap"] = capv
	}
	seen := &anlSet{}
	for _, r := range anlDetectUndecidable(anlProbeSet(m)) {
		seen.add(r.(string))
	}
	for _, x := range meets {
		for _, r := range x.(map[string]any)["undecidable"].([]any) {
			seen.add(r.(string))
		}
	}
	m["undecidable"] = seen.list()
	return m
}

// ---- probe collection --------------------------------------------------------------------------------------------------------

type anlField struct {
	path   string
	values []any
}

type anlProbes struct {
	verbs, resources, revClasses []any
	fields                       []anlField
}

func (pr *anlProbes) toJSON() map[string]any {
	fs := []any{}
	for _, f := range pr.fields {
		vs := make([]any, len(f.values))
		for i, v := range f.values {
			if anlIsAbsent(v) {
				vs[i] = map[string]any{"$absent": true}
			} else {
				vs[i] = v
			}
		}
		fs = append(fs, map[string]any{"path": f.path, "values": vs})
	}
	return map[string]any{"verbs": pr.verbs, "resources": pr.resources, "revClasses": pr.revClasses, "fields": fs}
}

// anlOrd is an insertion-ordered set of JSON values.
type anlOrd struct {
	vals []any
	seen map[string]bool
}

func (o *anlOrd) add(v any) {
	if o.seen == nil {
		o.seen = map[string]bool{}
	}
	k := anlValueKey(v)
	if !o.seen[k] {
		o.seen[k] = true
		o.vals = append(o.vals, v)
	}
}

func anlAddVerbLiterals(c map[string]any, into *anlOrd) {
	v := anlOwn(c, "value")
	switch anlOwn(c, "op") {
	case "eq", "ne", "prefix", "like", "is_a":
		if s, ok := v.(string); ok {
			into.add(s)
		}
	case "in", "nin":
		if xs, ok := v.([]any); ok {
			for _, x := range xs {
				if s, ok := x.(string); ok {
					into.add(s)
				}
			}
		}
	}
}

// anlCollectProbes is the grid dimensions of a set of predicate sets
// ({predicateSets, extraVerbs?, extraResources?, extraFieldConditions?, varyReversibility}); an absent value is anlAbsent.
func anlCollectProbes(inputs map[string]any) *anlProbes {
	verbs := &anlOrd{}
	for _, v := range anlReqListOpt(anlOwn(inputs, "extraVerbs")) {
		verbs.add(v)
	}
	resources := &anlSet{}
	var fieldOrder []string
	fieldConds := map[string][]any{}

	classifyResource := func(r any) {
		if anlIsUndef(r) {
			return
		}
		s, ok := r.(string)
		if !ok {
			anlFail("resource matcher is not a string")
		}
		if s == "*" || strings.HasPrefix(s, "re:") {
			return
		}
		if strings.HasSuffix(s, "*") {
			body := s[:len(s)-1]
			resources.add(body)
			resources.add(body + "x")
			return
		}
		resources.add(s)
	}
	var handleCond func(cc any)
	handleCond = func(cc any) {
		c, ok := cc.(map[string]any)
		if !ok {
			return
		}
		if anlIsGroup(c) {
			if xs, ok := c["all_of"].([]any); ok {
				for _, x := range xs {
					handleCond(x)
				}
			} else if xs, ok := c["any_of"].([]any); ok {
				for _, x := range xs {
					handleCond(x)
				}
			} else if n, has := c["not"]; has {
				handleCond(n)
			}
			return
		}
		if _, ok := anlLeaf(c); !ok {
			return
		}
		field := c["field"].(string)
		switch field {
		case "action.verb":
			anlAddVerbLiterals(c, verbs)
			return
		case "action.resource":
			v := anlOwn(c, "value")
			if s, ok := v.(string); ok {
				if anlOwn(c, "op") == "prefix" {
					classifyResource(s + "*")
				} else {
					classifyResource(s)
				}
			} else if xs, ok := v.([]any); ok {
				for _, x := range xs {
					if s, ok := x.(string); ok {
						classifyResource(s)
					}
				}
			}
			return
		}
		if _, has := fieldConds[field]; !has {
			fieldOrder = append(fieldOrder, field)
		}
		fieldConds[field] = append(fieldConds[field], c)
	}

	for _, lst := range anlReqList(inputs["predicateSets"]) {
		for _, p := range anlReqList(lst) {
			pm, ok := p.(map[string]any)
			if !ok {
				continue
			}
			switch verb := pm["verb"].(type) {
			case string:
				if verb != "*" {
					verbs.add(verb)
				}
			case []any:
				for _, v := range verb {
					if s, ok := v.(string); ok && s != "*" {
						verbs.add(s)
					}
				}
			}
			classifyResource(anlOwn(pm, "resource"))
			if w, ok := pm["where"].([]any); ok {
				for _, c := range w {
					handleCond(c)
				}
			}
		}
	}
	for _, r := range anlReqListOpt(anlOwn(inputs, "extraResources")) {
		classifyResource(r)
	}
	for _, ec := range anlReqListOpt(anlOwn(inputs, "extraFieldConditions")) {
		cond := anlCopy(anlGet(ec, "cond").(map[string]any))
		cond["field"] = anlGet(ec, "path")
		handleCond(cond)
	}
	pr := &anlProbes{}
	for _, path := range fieldOrder {
		pr.fields = append(pr.fields, anlField{path: path, values: append(anlFieldProbes(fieldConds[path]), anlAbsent)})
	}
	pr.verbs = append(append([]any{}, verbs.vals...), anlFreshVerb)
	pr.resources = append(resources.list(), anlFreshResource)
	if anlTruthy(anlOwn(inputs, "varyReversibility")) {
		for _, r := range anlRevOrder {
			pr.revClasses = append(pr.revClasses, r)
		}
	} else {
		pr.revClasses = []any{nil}
	}
	return pr
}

// anlReqListOpt is `nn(v, [])` iterated as a list (a non-array throws).
func anlReqListOpt(v any) []any {
	return anlReqList(anlNN(v, []any{}))
}

func anlProductSize(pr *anlProbes) float64 {
	n := float64(len(pr.verbs)) * float64(len(pr.resources)) * float64(len(pr.revClasses))
	for _, f := range pr.fields {
		n *= float64(len(f.values))
	}
	return n
}

// ---- representatives --------------------------------------------------------------------------------------------------------

// anlAsg is an insertion-ordered path -> value assignment.
type anlAsg struct {
	keys []string
	m    map[string]any
}

func (a *anlAsg) set(k string, v any) {
	if _, has := a.m[k]; !has {
		a.keys = append(a.keys, k)
	}
	a.m[k] = v
}

func (a *anlAsg) pop(k string) {
	if _, has := a.m[k]; !has {
		return
	}
	delete(a.m, k)
	for i, x := range a.keys {
		if x == k {
			a.keys = append(a.keys[:i:i], a.keys[i+1:]...)
			return
		}
	}
}

func (a *anlAsg) clone() *anlAsg {
	c := &anlAsg{keys: append([]string{}, a.keys...), m: make(map[string]any, len(a.m))}
	for k, v := range a.m {
		c.m[k] = v
	}
	return c
}

func (a *anlAsg) toJSON() map[string]any {
	out := make(map[string]any, len(a.m))
	for k, v := range a.m {
		out[k] = v
	}
	return out
}

// anlRep is a grid point {verb, resource, revClass (nil = no class), assignments}.
type anlRep struct {
	verb, resource, revClass any
	asg                      *anlAsg
}

func anlEnumFields(fields []anlField, i int, acc *anlAsg, yield func(*anlAsg) bool) bool {
	if i >= len(fields) {
		return yield(acc.clone())
	}
	f := fields[i]
	for _, v := range f.values {
		if anlIsAbsent(v) {
			acc.pop(f.path)
		} else {
			acc.set(f.path, v)
		}
		if anlEnumFields(fields, i+1, acc, yield) {
			return true
		}
	}
	return false
}

// anlEachRep walks every grid point; yield returns true to stop.
func anlEachRep(pr *anlProbes, yield func(*anlRep) bool) {
	for _, verb := range pr.verbs {
		for _, res := range pr.resources {
			for _, rev := range pr.revClasses {
				stop := anlEnumFields(pr.fields, 0, &anlAsg{m: map[string]any{}}, func(a *anlAsg) bool {
					return yield(&anlRep{verb: verb, resource: res, revClass: rev, asg: a})
				})
				if stop {
					return
				}
			}
		}
	}
}

type anlLeafNode struct{ v any }

func anlInsert(root map[string]any, segs []string, value any) {
	node := root
	for _, key := range segs[:len(segs)-1] {
		nxt, has := node[key]
		m, isMap := nxt.(map[string]any)
		if !has || nxt == nil || !isMap {
			created := map[string]any{}
			anlPutKey(node, key, created)
			node = created
		} else {
			node = m
		}
	}
	anlPutKey(node, segs[len(segs)-1], &anlLeafNode{v: value})
}

func anlMaterialize(x any) any {
	switch t := x.(type) {
	case *anlLeafNode:
		return t.v
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, c := range t {
			out[k] = anlMaterialize(c)
		}
		recordKeyOrder(out, jsKeys(t))
		return out
	}
	return x
}

func anlBuildRoots(rep *anlRep) map[string]any {
	roots := map[string]map[string]any{"action": {}, "subject": {}, "env": {}}
	for _, path := range rep.asg.keys {
		segs := strings.Split(path, ".")
		r, ok := roots[segs[0]]
		if len(segs) < 2 || !ok {
			continue
		}
		anlInsert(r, segs[1:], rep.asg.m[path])
	}
	action := map[string]any{"params": map[string]any{}}
	if !anlIsUndef(rep.verb) {
		action["verb"] = rep.verb
	}
	if !anlIsUndef(rep.resource) {
		action["resource"] = rep.resource
	}
	for key, child := range roots["action"] {
		switch key {
		case "verb", "resource":
		case "params":
			if _, leaf := child.(*anlLeafNode); !leaf {
				action["params"] = anlMaterialize(child)
			}
		default:
			action[key] = anlMaterialize(child)
		}
	}
	if rep.revClass != nil && !anlIsUndef(rep.revClass) {
		action["reversibility_class"] = rep.revClass
	}
	return map[string]any{"action": action, "subject": anlMaterialize(roots["subject"]), "env": anlMaterialize(roots["env"])}
}

func anlRevIndex(rev any) int {
	s, ok := rev.(string)
	if !ok {
		return -1
	}
	for i, r := range anlRevOrder {
		if r == s {
			return i
		}
	}
	return -1
}

func anlReversibilityOK(model map[string]any, rev any) bool {
	c, has := model["revCap"].(int)
	if !has {
		return true
	}
	if rev == nil || anlIsUndef(rev) {
		return false // a reversibility_max caveat denies an action with no class
	}
	i := anlRevIndex(rev)
	return i >= 0 && i <= c
}

// anlVetoApplies: does a veto apply at this context? Veto polarity: whatever cannot be decided counts as applying.
func anlVetoApplies(v any, ctx map[string]any) bool {
	w := anlGet(v, "when")
	if anlIsUndef(w) {
		w = nil
	}
	if !whenMatchesB(w, ctx, &regexBudget{}) {
		return false
	}
	if over := anlGet(v, "over"); anlTruthy(over) {
		val, found := resolvePath(ctx, anlGet(over, "path"))
		isOver := !found || !anlIsFin(val)
		if !isOver {
			f, _ := anlFin(val)
			isOver = f < 0 || anlGt(val, anlGet(over, "threshold"))
		}
		if !isOver {
			return false
		}
	}
	unless := anlGet(v, "unless")
	if anlGet(v, "kind") != "approval" && anlTruthy(unless) {
		ul, ok := unless.([]any)
		if !ok {
			anlFail("unless.every is not a function")
		}
		all := true
		for _, c := range ul {
			if evaluateConditionTri(c, ctx, &regexBudget{}) != triTrue {
				all = false
				break
			}
		}
		if all {
			return false
		}
	}
	return true
}

// anlDecisionAtContext is the ternary decision 'allow' | 'escalate' | 'deny' of the permission layer at a concrete context.
func anlDecisionAtContext(model map[string]any, ctx map[string]any) string {
	if !evaluatePredicates(model["predicates"], ctx) {
		return "deny"
	}
	escalate := false
	for _, v := range model["vetoes"].([]any) {
		if !anlVetoApplies(v, ctx) {
			continue
		}
		if anlGet(v, "kind") == "deny" {
			return "deny"
		}
		escalate = true
	}
	for _, t := range model["tighten"].([]any) {
		w := anlGet(t, "when")
		if anlIsUndef(w) {
			w = nil
		}
		if evaluateConditionTri(w, ctx, &regexBudget{}) == triFalse {
			continue
		}
		if anlGet(t, "signal") == "deny" {
			return "deny"
		}
		escalate = true
	}
	own := "allow"
	if escalate {
		own = "escalate"
	}
	for _, x := range model["meets"].([]any) {
		d := anlDecisionAtContext(x.(map[string]any), ctx)
		if d == "deny" {
			return "deny"
		}
		if d == "escalate" {
			own = "escalate"
		}
	}
	return own
}

// anlDecide is the ternary decision of a representative (the static caveat gate first).
func anlDecide(model map[string]any, rep *anlRep) string {
	if model["caveatSat"] != true || !anlReversibilityOK(model, rep.revClass) {
		return "deny"
	}
	return anlDecisionAtContext(model, anlBuildRoots(rep))
}

func anlAdmits(model map[string]any, rep *anlRep) bool { return anlDecide(model, rep) != "deny" }

func anlContextOfAction(action any) map[string]any {
	act := map[string]any{}
	if v := anlGet(action, "verb"); !anlIsUndef(v) {
		act["verb"] = v
	}
	if v := anlGet(action, "resource"); !anlIsUndef(v) {
		act["resource"] = v
	}
	act["params"] = anlSpread(anlUndefToNil(anlGet(action, "params")))
	if v := anlGet(action, "reversibilityClass"); !anlIsUndef(v) {
		act["reversibility_class"] = v
	}
	return map[string]any{
		"action":  act,
		"subject": anlSpread(anlUndefToNil(anlGet(action, "subject"))),
		"env":     anlSpread(anlUndefToNil(anlGet(action, "env"))),
	}
}

func anlUndefToNil(v any) any {
	if anlIsUndef(v) {
		return nil
	}
	return v
}

// anlDecideAction is the ternary decision of a fully-specified action.
func anlDecideAction(model map[string]any, action any) string {
	if model["caveatSat"] != true {
		return "deny"
	}
	if !anlReversibilityOK(model, anlGet(action, "reversibilityClass")) {
		return "deny"
	}
	return anlDecisionAtContext(model, anlContextOfAction(action))
}

func anlAdmitsAction(model map[string]any, action any) bool {
	return anlDecideAction(model, action) != "deny"
}

func anlRepToAction(rep *anlRep) map[string]any {
	roots := anlBuildRoots(rep)
	params := anlCopy(roots["action"].(map[string]any)["params"].(map[string]any))
	action := map[string]any{"verb": rep.verb, "resource": rep.resource, "params": params}
	if rep.revClass != nil {
		action["reversibilityClass"] = rep.revClass
	}
	if s := roots["subject"].(map[string]any); len(s) > 0 {
		action["subject"] = s
	}
	if e := roots["env"].(map[string]any); len(e) > 0 {
		action["env"] = e
	}
	order := []string{"verb", "resource", "params"} // the reference builds the object in this order (a message prints it so)
	for _, k := range []string{"reversibilityClass", "subject", "env"} {
		if _, has := action[k]; has {
			order = append(order, k)
		}
	}
	recordKeyOrder(action, order)
	return action
}

// anlSearch walks the grid to the first representative the predicate accepts.
func anlSearch(pr *anlProbes, pred func(*anlRep) bool, mx float64) (hit *anlRep, overflow bool) {
	if anlProductSize(pr) > mx {
		return nil, true
	}
	anlEachRep(pr, func(r *anlRep) bool {
		if pred(r) {
			hit = r
			return true
		}
		return false
	})
	return hit, false
}

// anlCollect is anlSearch collecting up to limit accepted representatives.
func anlCollect(pr *anlProbes, pred func(*anlRep) bool, mx float64, limit int) (hits []*anlRep, overflow bool) {
	if anlProductSize(pr) > mx {
		return nil, true
	}
	anlEachRep(pr, func(r *anlRep) bool {
		if pred(r) {
			hits = append(hits, r)
			if len(hits) >= limit {
				return true
			}
		}
		return false
	})
	return hits, false
}

// ---- queries ----------------------------------------------------------------------------------------------------------------

// anlBound is the grid bound; anything but a non-negative finite number falls back to the default.
func anlBound(opts any) float64 {
	if f, ok := anlFin(anlOwn(opts, "maxCombinations")); ok && f >= 0 {
		return f
	}
	return anlDefaultMaxCombinations
}

func anlMergeWitness(witness map[string]any, provided any) map[string]any {
	params := map[string]any{}
	if wp, ok := witness["params"].(map[string]any); ok {
		params = anlCopy(wp)
	}
	for k, v := range anlSpread(anlUndefToNil(anlGet(provided, "params"))) {
		params[k] = v
	}
	out := anlU(map[string]any{"verb": anlGet(provided, "verb"), "resource": anlGet(provided, "resource"), "params": params})
	rc := anlGet(provided, "reversibilityClass")
	if anlIsUndef(rc) || rc == nil {
		if w, has := witness["reversibilityClass"]; has {
			rc = w
		} else {
			rc = anlUndef
		}
	}
	if !anlIsUndef(rc) {
		out["reversibilityClass"] = rc
	}
	if s, has := witness["subject"]; has {
		out["subject"] = s
	}
	if e, has := witness["env"]; has {
		out["env"] = e
	}
	return out
}

func anlReasonOf(model map[string]any) any {
	if r, has := model["caveatReason"]; has {
		return r
	}
	return "unknown"
}

func anlRevList() []any {
	out := []any{}
	for _, r := range anlRevOrder {
		out = append(out, r)
	}
	return out
}

// anlReachable: can any input complete `action` into one the policy admits?
func anlReachable(policy, action, opts any) map[string]any {
	model := anlToModel(policy)
	mx := anlBound(opts)
	if model["caveatSat"] != true {
		return map[string]any{"reachable": false, "reason": "caveats unsatisfiable: " + anlJS(anlReasonOf(model))}
	}
	rc := anlGet(action, "reversibilityClass")
	capv, hasCap := model["revCap"].(int)
	if !anlIsUndef(rc) && hasCap {
		if idx := anlRevIndex(rc); idx < 0 || idx > capv {
			return map[string]any{"reachable": false, "reason": "reversibility class '" + anlJS(rc) + "' exceeds the caveat cap"}
		}
	}
	if anlAdmitsAction(model, action) {
		return map[string]any{"reachable": true, "witness": action}
	}
	base := anlCollectProbes(map[string]any{"predicateSets": []any{anlProbeSet(model)}, "varyReversibility": hasCap})
	provided := anlNN(anlGet(action, "params"), map[string]any{})
	pm, _ := provided.(map[string]any)
	var fields []anlField
	for _, f := range base.fields {
		if strings.HasPrefix(f.path, "action.params.") {
			key := f.path[len("action.params."):]
			if v, has := pm[key]; has {
				fields = append(fields, anlField{path: f.path, values: []any{v}})
				continue
			}
		}
		fields = append(fields, f)
	}
	var revClasses []any
	switch {
	case !anlIsUndef(rc):
		revClasses = []any{rc}
	case hasCap:
		revClasses = anlRevList()
	default:
		revClasses = []any{nil}
	}
	pr := &anlProbes{verbs: []any{anlGet(action, "verb")}, resources: []any{anlGet(action, "resource")}, revClasses: revClasses, fields: fields}
	hit, overflow := anlSearch(pr, func(rep *anlRep) bool { return anlAdmits(model, rep) }, mx)
	if hit != nil {
		return map[string]any{"reachable": true, "witness": anlMergeWitness(anlRepToAction(hit), action)}
	}
	if overflow {
		return map[string]any{"reachable": true, "approximate": true, "reason": "representative grid exceeded the bound; could not prove unreachable"}
	}
	if u := model["undecidable"].([]any); len(u) > 0 {
		return map[string]any{"reachable": true, "approximate": true,
			"reason": "over-approximated (" + anlJoin(u, "; ") + "); could not construct a witness but cannot prove unreachable"}
	}
	return map[string]any{"reachable": false, "reason": "no predicate admits this action for any input (proven over the decided fragment)"}
}

func anlProbesFor(models []map[string]any, verb any) *anlProbes {
	sets := []any{}
	vary := false
	for _, m := range models {
		sets = append(sets, anlProbeSet(m))
		if _, has := m["revCap"]; has {
			vary = true
		}
	}
	pr := anlCollectProbes(map[string]any{"predicateSets": sets, "varyReversibility": vary})
	if verb != nil && !anlIsUndef(verb) {
		pr.verbs = []any{verb}
	}
	return pr
}

// anlAlwaysDenies: does the policy deny everything (optionally restricted to `verb`)?
func anlAlwaysDenies(policy, verb, opts any) map[string]any {
	model := anlToModel(policy)
	mx := anlBound(opts)
	if model["caveatSat"] != true {
		return map[string]any{"alwaysDenies": true, "reason": "caveats unsatisfiable: " + anlJS(anlReasonOf(model))}
	}
	hit, overflow := anlSearch(anlProbesFor([]map[string]any{model}, verb), func(rep *anlRep) bool { return anlAdmits(model, rep) }, mx)
	if hit != nil {
		return map[string]any{"alwaysDenies": false, "witness": anlRepToAction(hit)}
	}
	if overflow {
		return map[string]any{"alwaysDenies": false, "approximate": true, "reason": "grid exceeded the bound; cannot prove vacuity"}
	}
	if u := model["undecidable"].([]any); len(u) > 0 {
		return map[string]any{"alwaysDenies": false, "approximate": true, "reason": "over-approximated (" + anlJoin(u, "; ") + "); cannot prove vacuity"}
	}
	return map[string]any{"alwaysDenies": true}
}

// anlAlwaysAllows: does the policy admit EVERY action of `verb`?
func anlAlwaysAllows(policy, verb, opts any) map[string]any {
	model := anlToModel(policy)
	mx := anlBound(opts)
	if model["caveatSat"] != true {
		return map[string]any{"alwaysAllows": false, "reason": "caveats unsatisfiable: " + anlJS(anlReasonOf(model))}
	}
	hit, overflow := anlSearch(anlProbesFor([]map[string]any{model}, verb), func(rep *anlRep) bool { return !anlAdmits(model, rep) }, mx)
	if hit != nil {
		return map[string]any{"alwaysAllows": false, "counterexample": anlRepToAction(hit)}
	}
	if overflow {
		return map[string]any{"alwaysAllows": false, "approximate": true, "reason": "grid exceeded the bound; cannot prove totality"}
	}
	if u := model["undecidable"].([]any); len(u) > 0 {
		return map[string]any{"alwaysAllows": false, "approximate": true, "reason": "over-approximated (" + anlJoin(u, "; ") + "); cannot prove totality"}
	}
	return map[string]any{"alwaysAllows": true}
}

func anlApproxNote(models []map[string]any, overflow bool) (string, bool) {
	if overflow {
		return "representative grid exceeded the bound; cannot prove the relation", true
	}
	reasons := &anlSet{}
	for _, m := range models {
		for _, r := range m["undecidable"].([]any) {
			reasons.add(r.(string))
		}
	}
	if len(reasons.keys) > 0 {
		return "over-approximated (" + strings.Join(reasons.keys, "; ") + "); cannot prove the relation", true
	}
	return "", false
}

func anlRelation(a, b, opts any, pred func(ma, mb map[string]any, r *anlRep) bool, key, witnessKey string) map[string]any {
	ma, mb := anlToModel(a), anlToModel(b)
	mx := anlBound(opts)
	hit, overflow := anlSearch(anlProbesFor([]map[string]any{ma, mb}, nil), func(rep *anlRep) bool { return pred(ma, mb, rep) }, mx)
	if hit != nil {
		return map[string]any{key: false, witnessKey: anlRepToAction(hit)}
	}
	if note, ok := anlApproxNote([]map[string]any{ma, mb}, overflow); ok {
		return map[string]any{key: false, "approximate": true, "reason": note}
	}
	return map[string]any{key: true}
}

// anlSubsumes: does `a` permit everything `b` permits? A counterexample is an action `b` admits that `a` denies.
func anlSubsumes(a, b, opts any) map[string]any {
	return anlRelation(a, b, opts, func(ma, mb map[string]any, r *anlRep) bool { return anlAdmits(mb, r) && !anlAdmits(ma, r) }, "subsumes", "counterexample")
}

// anlDisjoint: is there no action both policies admit?
func anlDisjoint(a, b, opts any) map[string]any {
	return anlRelation(a, b, opts, func(ma, mb map[string]any, r *anlRep) bool { return anlAdmits(ma, r) && anlAdmits(mb, r) }, "disjoint", "witness")
}

// anlEquivalent: do the policies admit exactly the same actions?
func anlEquivalent(a, b, opts any) map[string]any {
	return anlRelation(a, b, opts, func(ma, mb map[string]any, r *anlRep) bool { return anlAdmits(ma, r) != anlAdmits(mb, r) }, "equivalent", "counterexample")
}

func anlScopeMatches(scope any, resource any) bool {
	s, ok := scope.(string)
	if !ok {
		anlFail("scope.startsWith is not a function")
	}
	if s == "*" {
		return true
	}
	if strings.HasPrefix(s, "re:") {
		src := s[3:]
		res := anlStr(resource, "resource")
		if jsLen(src) > 200 || jsLen(res) > maxREResourceLen || !isSafeRegexSource(utf16Units(src)) {
			return false
		}
		m, ok := safeRegexFullMatch(utf16Units(src), utf16Units(res))
		return ok && m
	}
	if strings.HasSuffix(s, "*") {
		return jsStartsWith(anlStr(resource, "resource"), s[:len(s)-1])
	}
	return s == resource
}

func anlIntentViolationKinds(action map[string]any, intent any, amountField, minAmount any) []any {
	kinds := []any{}
	verbs := anlGet(intent, "verbs")
	if !(anlIncludes(verbs, "*") || anlIncludes(verbs, action["verb"])) {
		kinds = append(kinds, "off-verb")
	}
	scopes := anlReqList(anlNN(anlGet(intent, "resourceScopes"), []any{}))
	if len(scopes) > 0 {
		any1 := false
		for _, s := range scopes {
			if anlScopeMatches(s, action["resource"]) {
				any1 = true
				break
			}
		}
		if !any1 {
			kinds = append(kinds, "off-scope")
		}
	}
	if maxAmount := anlGet(intent, "maxAmount"); !anlIsUndef(maxAmount) {
		af, _ := amountField.(string)
		amt := anlOwn(anlNN(action["params"], map[string]any{}), af)
		if anlIsFin(amt) {
			if anlGt(amt, maxAmount) {
				kinds = append(kinds, "over-amount")
			} else if anlLt(amt, minAmount) {
				kinds = append(kinds, "under-amount")
			}
		}
	}
	return kinds
}

func anlScopeStartsRe(s any) bool {
	str, ok := s.(string)
	if !ok {
		anlFail("s.startsWith is not a function")
	}
	return strings.HasPrefix(str, "re:")
}

// anlIntentConformance: does the policy admit ONLY actions inside the declared intent envelope?
func anlIntentConformance(policy, intent, opts any) map[string]any {
	model := anlToModel(policy)
	mx := anlBound(opts)
	amountField := anlNN(anlGet(intent, "amountField"), "amount")
	minAmount := anlNN(anlGet(intent, "minAmount"), float64(0))
	if model["caveatSat"] != true {
		return map[string]any{"conforms": true, "violations": []any{}}
	}
	extra := []any{}
	if maxAmount := anlGet(intent, "maxAmount"); !anlIsUndef(maxAmount) {
		path := "action.params." + anlJS(amountField)
		extra = append(extra,
			map[string]any{"path": path, "cond": map[string]any{"field": path, "op": "lte", "value": maxAmount}},
			map[string]any{"path": path, "cond": map[string]any{"field": path, "op": "gte", "value": minAmount}})
	}
	verbs := anlReqList(anlGet(intent, "verbs"))
	extraVerbs := []any{}
	for _, v := range verbs {
		if v != "*" {
			extraVerbs = append(extraVerbs, v)
		}
	}
	_, hasCap := model["revCap"]
	pr := anlCollectProbes(map[string]any{
		"predicateSets":        []any{anlProbeSet(model)},
		"extraVerbs":           extraVerbs,
		"extraResources":       anlNN(anlGet(intent, "resourceScopes"), []any{}),
		"extraFieldConditions": extra,
		"varyReversibility":    hasCap,
	})
	fp := 1.0
	for _, f := range pr.fields {
		fp *= float64(len(f.values))
	}
	if float64(len(pr.verbs))*float64(len(pr.resources))*float64(len(pr.revClasses))*fp > mx {
		return map[string]any{"conforms": false, "approximate": true, "violations": []any{}, "reason": "grid exceeded the bound; cannot prove conformance"}
	}
	violations := []any{}
	anlEachRep(pr, func(rep *anlRep) bool {
		if !anlAdmits(model, rep) {
			return false
		}
		action := anlRepToAction(rep)
		if kinds := anlIntentViolationKinds(action, intent, amountField, minAmount); len(kinds) > 0 {
			violations = append(violations, map[string]any{"action": action, "kinds": kinds})
			if len(violations) >= 16 {
				return true
			}
		}
		return false
	})
	if len(violations) > 0 {
		return map[string]any{"conforms": false, "violations": violations}
	}
	intentRegex := false
	for _, s := range anlReqList(anlNN(anlGet(intent, "resourceScopes"), []any{})) {
		if anlScopeStartsRe(s) {
			intentRegex = true
			break
		}
	}
	und := model["undecidable"].([]any)
	if len(und) > 0 || intentRegex {
		reasons := append([]any{}, und...)
		if intentRegex {
			reasons = append(reasons, "re: intent resource scope not enumerated soundly")
		}
		return map[string]any{"conforms": false, "approximate": true, "violations": []any{}, "reason": "over-approximated (" + anlJoin(reasons, "; ") + "); cannot prove conformance"}
	}
	return map[string]any{"conforms": true, "violations": []any{}}
}

// anlAdmitsConcrete is the exact admission of a fully-specified action (no existential search).
func anlAdmitsConcrete(policy, action any) bool { return anlAdmitsAction(anlToModel(policy), action) }
