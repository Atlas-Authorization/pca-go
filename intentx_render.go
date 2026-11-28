package pca

// Deterministic plain-language rendering and the back-translation diff. Every sentence is a fixed template over the grant's
// own data (no language model anywhere); anything the templates do not know is rendered as an explicit "not understood" line.

import (
	"fmt"
	"math"
	"sort"
	"strings"
)

// ixCatalogGet finds the catalog entry of a verb (a later spec with the same verb replaces an earlier one).
func ixCatalogGet(catalog any, verb string) map[string]any {
	var found map[string]any
	for _, s := range ixCatalogAll(catalog) {
		if ixS(s["verb"]) == verb {
			found = s
		}
	}
	return found
}

func ixLabelOf(path string) string {
	if path == "action.resource" {
		return "resource"
	}
	parts := strings.Split(path, ".")
	return strings.ReplaceAll(parts[len(parts)-1], "_", " ")
}

func ixFmtVal(v any, present bool) string {
	if !present {
		return "undefined"
	}
	switch t := v.(type) {
	case string:
		return `"` + t + `"`
	case []any:
		parts := make([]string, len(t))
		for i, x := range t {
			parts[i] = ixFmtVal(x, true)
		}
		return strings.Join(parts, ", ")
	}
	return jsValueString(v)
}

// ixArr is the list of a member that may be absent / null (empty) but must otherwise be an array.
func ixArr(x any) []any {
	if x == nil {
		return nil
	}
	l, ok := x.([]any)
	if !ok {
		ixFail("map is not a function")
	}
	return l
}

var ixOpTemplates = map[string]string{
	"eq": "%s is %s", "ne": "%s is not %s", "in": "%s is one of %s", "nin": "%s is none of %s", "lt": "%s is less than %s",
	"lte": "%s is at most %s", "gt": "%s is more than %s", "gte": "%s is at least %s", "prefix": "%s starts with %s",
	"like": "%s matches the pattern %s", "matches": "%s matches the regular expression %s", "is_a": "%s is of type %s",
	"member_of": "%s belongs to %s",
}

func ixRenderCondition(cv any) string {
	c, ok := cv.(map[string]any)
	if !ok {
		return "an unreadable condition (not understood)"
	}
	if ixIsGroupCond(c) {
		if ixHas(c, "all_of") {
			var parts []string
			for _, x := range ixArr(c["all_of"]) {
				parts = append(parts, "("+ixRenderCondition(x)+")")
			}
			return "all of: " + strings.Join(parts, " and ")
		}
		if ixHas(c, "any_of") {
			var parts []string
			for _, x := range ixArr(c["any_of"]) {
				parts = append(parts, "("+ixRenderCondition(x)+")")
			}
			return "either " + strings.Join(parts, " or ")
		}
		return "it is not the case that " + ixRenderCondition(c["not"])
	}
	field, ok := c["field"].(string)
	if !ok {
		return "an unreadable condition (not understood)"
	}
	L := "the " + ixLabelOf(field)
	var V string
	if ref, has := c["ref"]; has {
		rs, ok := ref.(string)
		if !ok {
			ixFail("path.split is not a function")
		}
		V = "the " + ixLabelOf(rs)
	} else {
		val, has := c["value"]
		V = ixFmtVal(val, has)
	}
	opv, hasOp := c["op"]
	if op, ok := opv.(string); ok {
		if t, ok := ixOpTemplates[op]; ok {
			return fmt.Sprintf(t, L, V)
		}
	}
	if opv == "exists" {
		if c["value"] == false {
			return L + " is absent"
		}
		return L + " is present"
	}
	opText := "undefined"
	if hasOp {
		opText = jsValueString(opv)
	}
	return L + ` has an unrecognised test "` + opText + `" (not understood)`
}

func ixRenderResource(r any, present bool) string {
	if !present || r == "*" {
		return "on any resource"
	}
	s, ok := r.(string)
	if !ok {
		return "on an unreadable resource matcher (not understood)"
	}
	if strings.HasPrefix(s, "re:") {
		return `on resources matching the regular expression "` + s[3:] + `"`
	}
	if strings.HasSuffix(s, "*") {
		return `on resources under "` + s[:len(s)-1] + `"`
	}
	return `only on resource "` + s + `"`
}

func ixLowerFirst(s string) string {
	if s == "" || s[0] == '\n' {
		return s
	}
	r := []rune(s)
	return strings.ToLower(string(r[0])) + string(r[1:])
}

func ixDesc(s map[string]any) string {
	d := ixS(ixReq(s, "description"))
	return strings.TrimSuffix(d, ".")
}

func ixRev(s string) string { return strings.Replace(s, "_", "-", 1) }

func ixRenderVerb(v any, present bool, catalog any) string {
	one := func(x string) string {
		if x == "*" {
			return "ANY action of any connector"
		}
		if s := ixCatalogGet(catalog, x); s != nil {
			return ixLowerFirst(ixDesc(s)) + " [" + x + ", " + ixRev(ixS(ixReq(s, "reversibility"))) + "]"
		}
		return `"` + x + `" [uncatalogued: treated as irreversible]`
	}
	str := func(x any, has bool) string {
		if !has {
			return "undefined"
		}
		return jsValueString(x)
	}
	if l, ok := v.([]any); ok {
		parts := make([]string, len(l))
		for i, x := range l {
			parts[i] = one(str(x, true))
		}
		return strings.Join(parts, "; or ")
	}
	return one(str(v, present))
}

func ixFloorDiv(a, b int64) int64 {
	q := a / b
	if (a%b != 0) && ((a < 0) != (b < 0)) {
		q--
	}
	return q
}

// ixIso is new Date(Number(t)).toISOString(); an invalid date is a throw.
func ixIso(tv any, present bool) string {
	if !present {
		ixFail("Invalid time value") // Number(undefined) is NaN
	}
	t := jsToNumber(tv) // new Date(Number(x))
	if t != t || math.Abs(t) > 8.64e15 {
		ixFail("Invalid time value")
	}
	ms := int64(t)
	days := ixFloorDiv(ms, 86400000)
	rem := ms - days*86400000
	z := days + 719468
	era := ixFloorDiv(z, 146097)
	doe := z - era*146097
	yoe := (doe - doe/1460 + doe/36524 - doe/146096) / 365
	y := yoe + era*400
	doy := doe - (365*yoe + yoe/4 - yoe/100)
	mp := (5*doy + 2) / 153
	d := doy - (153*mp+2)/5 + 1
	m := mp - 9
	if mp < 10 {
		m = mp + 3
	}
	if m <= 2 {
		y++
	}
	var ys string
	switch {
	case y >= 0 && y <= 9999:
		ys = fmt.Sprintf("%04d", y)
	case y > 0:
		ys = fmt.Sprintf("+%06d", y)
	default:
		ys = fmt.Sprintf("-%06d", -y)
	}
	h := rem / 3600000
	rem -= h * 3600000
	mi := rem / 60000
	rem -= mi * 60000
	return fmt.Sprintf("%s-%02d-%02dT%02d:%02d:%02d.%03dZ", ys, m, d, h, mi, rem/1000, rem%1000)
}

func ixRenderCaveat(cv any) string {
	c, _ := cv.(map[string]any)
	g := func(k string) string {
		v, ok := c[k]
		if !ok {
			return "undefined"
		}
		return jsValueString(v)
	}
	t, hasT := c["type"]
	switch t {
	case "expires":
		at, has := c["at"]
		return "The grant expires at " + ixIso(at, has) + "."
	case "not_before":
		at, has := c["at"]
		return "The grant is not valid before " + ixIso(at, has) + "."
	case "rate":
		return "At most " + g("max") + " actions in any " + g("per_secs") + " seconds."
	case "max_blast_radius":
		return "No action whose blast radius exceeds " + g("max") + " (on a 0–1 scale)."
	case "reversibility_max":
		return `Nothing more severe than "` + ixRev(g("class")) + `" (reversible < rate-limited < irreversible).`
	case "delegation_depth":
		return "It may be re-delegated at most " + g("max") + " level(s) deep."
	case "budget_alloc":
		return "A trust-budget allocation of " + g("limit") + " is carried for sub-delegation."
	}
	tt := "undefined"
	if hasT {
		tt = jsValueString(t)
	}
	return `An unrecognised constraint of type "` + tt + `" (NOT UNDERSTOOD: do not rely on this grant until it is explained).`
}

func ixRenderGrant(policy, catalog any) string {
	n := ixNormalizePolicy(policy)
	preds, caveats := n["predicates"].([]any), n["caveats"].([]any)
	if len(preds) == 0 {
		return "This grant allows nothing."
	}
	lines := []string{"The agent may do the following, and nothing else:"}
	for i, pv := range preds {
		if pv == nil {
			ixFail("cannot read properties of null (reading 'where')")
		}
		p, _ := pv.(map[string]any)
		var conds []string
		for _, x := range ixArr(p["where"]) {
			conds = append(conds, ixRenderCondition(x))
		}
		verb, hasVerb := p["verb"]
		res, hasRes := p["resource"]
		tail := ""
		if len(conds) > 0 {
			tail = ", only when " + strings.Join(conds, ", and ")
		}
		lines = append(lines, fmt.Sprintf("%d. %s, %s%s.", i+1, ixRenderVerb(verb, hasVerb, catalog), ixRenderResource(res, hasRes), tail))
	}
	if len(caveats) > 0 {
		lines = append(lines, "Limits that apply to everything above:")
		for _, c := range caveats {
			lines = append(lines, "- "+ixRenderCaveat(c))
		}
	}
	return strings.Join(lines, "\n")
}

func ixRenderDimCell(d map[string]any, i int) string {
	L := ixLabelOf(ixS(d["path"]))
	if d["kind"] == "num" {
		c := ixCellAt(ixNumCells(d), i)
		if c.lo == c.hi {
			return L + " exactly " + jsValueString(c.lo)
		}
		rep := c.hi
		if i > 0 {
			rep = c.lo
		}
		return "any " + L + " from " + jsValueString(c.lo) + " to " + jsValueString(c.hi) + " (e.g. " + jsValueString(rep) + ")"
	}
	vals := ixL(d["values"])
	if i < 0 || i >= len(vals) {
		ixFail("cell index out of range")
	}
	v := ixM(vals[i])
	switch v["kind"] {
	case "exact":
		return L + ` "` + ixS(v["value"]) + `"`
	case "prefix":
		return "a " + L + ` under "` + ixS(v["value"]) + `" (not otherwise named)`
	}
	return "a " + L + " not named anywhere in the grant or your request"
}

func ixRenderQuestion(vs map[string]any, cell []any, catalog any) string {
	verb := ixS(vs["verb"])
	what := `perform "` + verb + `"`
	if s := ixCatalogGet(catalog, verb); s != nil {
		what = ixDesc(s) + " [" + verb + "]"
	}
	var parts []string
	for k, dv := range ixL(vs["dims"]) {
		if k >= len(cell) {
			ixFail("cell index missing")
		}
		parts = append(parts, ixRenderDimCell(ixM(dv), ixIdx(cell[k])))
	}
	tail := ""
	if len(parts) > 0 {
		tail = ", with " + strings.Join(parts, ", ")
	}
	return "Should the agent be allowed to: " + what + tail + "?"
}

// ---- back-translation diff ----

// ixClaimsOf is the claim IR of a policy over the outcome space: verb by verb and dimension by dimension.
func ixClaimsOf(policy any, omega map[string]any) []any {
	a := ixAdmitter(policy)
	out := []any{}
	for _, vv := range ixL(omega["verbs"]) {
		vs := ixM(vv)
		n := int(ixVerbCellCount(vs))
		dimsV := ixL(vs["dims"])
		var acc [][]any
		for c := 0; c < n; c++ {
			idx := ixDecodeCell(vs, float64(c))
			if a.admits(vs, ixCellRep(vs, idx)) {
				acc = append(acc, idx)
			}
		}
		proj := make([]map[int]bool, len(dimsV))
		boxCount := 1
		for k := range dimsV {
			proj[k] = map[int]bool{}
			for _, x := range acc {
				proj[k][ixIdx(x[k])] = true
			}
			boxCount *= len(proj[k])
		}
		dims := []any{}
		for k, dv := range dimsV {
			d := ixM(dv)
			s := proj[k]
			total := ixCellCount(d)
			ids := make([]int, 0, len(s))
			for i := range s {
				ids = append(ids, i)
			}
			sort.Ints(ids)
			if d["kind"] == "num" {
				cells := ixNumCells(d)
				dc := map[string]any{"path": d["path"], "any": len(s) == total}
				if len(ids) > 0 {
					dc["range"] = []any{cells[ids[0]].lo, cells[ids[len(ids)-1]].hi}
				}
				dims = append(dims, dc)
			} else {
				vals := ixL(d["values"])
				vs2 := []any{}
				for _, i := range ids {
					v := ixM(vals[i])
					if v["kind"] == "prefix" {
						vs2 = append(vs2, ixS(v["value"])+"*")
					} else {
						vs2 = append(vs2, v["value"])
					}
				}
				dims = append(dims, map[string]any{"path": d["path"], "any": len(s) == total, "values": vs2})
			}
		}
		out = append(out, map[string]any{"verb": vs["verb"], "allowed": len(acc) > 0, "boxShaped": len(acc) == boxCount, "dims": dims})
	}
	return out
}

func ixDimText(c map[string]any) string {
	if len(c) == 0 {
		return "anything"
	}
	if c["any"] == true {
		return "any value"
	}
	if r, ok := c["range"].([]any); ok {
		return jsValueString(r[0]) + " to " + jsValueString(r[1])
	}
	if vals := ixL(c["values"]); len(vals) > 0 {
		parts := make([]string, len(vals))
		for i, v := range vals {
			parts[i] = ixS(v)
		}
		return strings.Join(parts, ", ")
	}
	return "nothing"
}

func ixContainsAll(hay, needles []any) bool {
	for _, n := range needles {
		found := false
		for _, h := range hay {
			if h == n {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}

type ixDiffWords struct {
	extra, missing, shape func(v string) string
	dim                   func(v, path, a, b string) string
}

func ixDiffClaims(g, s []any, w ixDiffWords) []any {
	out := []any{}
	for i, gv := range g {
		gc, sc := ixM(gv), ixM(s[i])
		verb := ixS(gc["verb"])
		ga, sa := gc["allowed"] == true, sc["allowed"] == true
		if ga && !sa {
			out = append(out, map[string]any{"verb": verb, "kind": "extra-verb", "text": w.extra(verb)})
			continue
		}
		if !ga && sa {
			out = append(out, map[string]any{"verb": verb, "kind": "missing-verb", "text": w.missing(verb)})
			continue
		}
		if !ga {
			continue
		}
		gb, sb := gc["boxShaped"] == true, sc["boxShaped"] == true
		if (!gb || !sb) && gb != sb {
			out = append(out, map[string]any{"verb": verb, "kind": "shape", "text": w.shape(verb)})
		}
		for k, gdv := range ixL(gc["dims"]) {
			gd, sd := ixM(gdv), ixM(ixL(sc["dims"])[k])
			a, _ := canonicalLenient(gd)
			b, _ := canonicalLenient(sd)
			if a == b {
				continue
			}
			kind := "different"
			gr, gHasR := gd["range"].([]any)
			sr, sHasR := sd["range"].([]any)
			gvals, gHasV := gd["values"].([]any)
			svals, sHasV := sd["values"].([]any)
			switch {
			case gHasR && sHasR:
				switch {
				case ixF(gr[0]) <= ixF(sr[0]) && ixF(gr[1]) >= ixF(sr[1]):
					kind = "looser"
				case ixF(gr[0]) >= ixF(sr[0]) && ixF(gr[1]) <= ixF(sr[1]):
					kind = "tighter"
				}
			case gHasV && sHasV:
				switch {
				case ixContainsAll(gvals, svals):
					kind = "looser"
				case ixContainsAll(svals, gvals):
					kind = "tighter"
				}
			case gd["any"] == true && sd["any"] != true:
				kind = "looser"
			}
			path := ixS(gd["path"])
			out = append(out, map[string]any{"verb": verb, "kind": kind, "path": path, "text": w.dim(verb, path, ixDimText(gd), ixDimText(sd))})
		}
	}
	return out
}

// ixBackTranslationDiff renders the grant and the intent slots into the same claim IR and lists every difference.
func ixBackTranslationDiff(grant any, slots, omega map[string]any) []any {
	return ixDiffClaims(ixClaimsOf(grant, omega), ixClaimsOf(ixSlotsToPolicy(slots), omega), ixDiffWords{
		extra:   func(v string) string { return "The grant allows " + v + ", which your request did not mention." },
		missing: func(v string) string { return "Your request mentions " + v + ", but the grant does not allow it." },
		shape: func(v string) string {
			return "The grant's rule for " + v + " is a combination of cases that your request did not describe."
		},
		dim: func(v, path, a, b string) string {
			return "For " + v + ", the grant allows " + ixLabelOf(path) + " " + a + "; your request said " + b + "."
		},
	})
}

// ixClaimDiff is the same claim diff between two grants (two readings); kind is from a's point of view.
func ixClaimDiff(a, b any, omega map[string]any, n0, n1 string) []any {
	return ixDiffClaims(ixClaimsOf(a, omega), ixClaimsOf(b, omega), ixDiffWords{
		extra:   func(v string) string { return n0 + " allows " + v + "; " + n1 + " does not." },
		missing: func(v string) string { return n1 + " allows " + v + "; " + n0 + " does not." },
		shape:   func(v string) string { return n0 + " and " + n1 + " describe " + v + " with differently shaped rules." },
		dim: func(v, path, x, y string) string {
			return "For " + v + ", " + n0 + " allows " + ixLabelOf(path) + " " + x + "; " + n1 + " allows " + y + "."
		},
	})
}

// ixRenderAction is a concrete action in plain language; values are printed verbatim so nothing is hidden.
func ixRenderAction(vs, values map[string]any, catalog any) string {
	verb := ixS(vs["verb"])
	revText := "undefined"
	if r, ok := vs["reversibility"]; ok {
		revText = jsValueString(r)
	}
	what := `perform "` + verb + `" [uncatalogued: treated as irreversible]`
	if s := ixCatalogGet(catalog, verb); s != nil {
		what = ixDesc(s) + " [" + verb + ", " + ixRev(revText) + "]"
	}
	var parts []string
	for _, k := range ixKeysSorted(values) {
		v := values[k]
		if s, ok := v.(string); ok {
			parts = append(parts, ixLabelOf(k)+` "`+s+`"`)
		} else {
			parts = append(parts, ixLabelOf(k)+" "+jsValueString(v))
		}
	}
	tail := ""
	if len(parts) > 0 {
		tail = ", with " + strings.Join(parts, ", ")
	}
	return "The agent wants to: " + what + tail + "."
}
