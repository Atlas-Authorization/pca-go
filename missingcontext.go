package pca

import (
	"regexp"
	"sort"
	"strings"
)

// Typed missing context and the stored-wins merge. When a permit condition cannot be decided because a value is absent the
// verifier names what is missing and who may supply it (principal | discharge_issuer | rs_observation | agent_declared_untrusted);
// a supplied value never replaces a bound one. Total: nothing here panics, every malformed input is a deny. Port of
// packages/pca/src/missing-context.ts; replays missing-context-vectors.json. Contexts are decoded JSON (map[string]any).

var missingSuppliers = []string{"principal", "discharge_issuer", "rs_observation", "agent_declared_untrusted"}
var supplierKeyRe = regexp.MustCompile(`^(action\.params|subject|env)(\.[A-Za-z_][A-Za-z0-9_]*)*$`)

// MissingContext names one absent value and who may supply it.
type MissingContext struct{ Path, Supplier string }

// TypedDecision: Reason is "" when not set; Missing is never nil.
type TypedDecision struct {
	Decision string
	Reason   string
	Missing  []MissingContext
}

// BoundContext is the merged context plus the refused (conflicts) and dropped paths, both sorted.
type BoundContext struct {
	Context   map[string]any
	Conflicts []string
	Dropped   []string
}

// SupplierOf: the longest table key equal to path or a segment-boundary prefix of it; unmatched is principal.
func SupplierOf(path string, table map[string]string) string {
	best, found := "", false
	for k := range table {
		if (path == k || strings.HasPrefix(path, k+".")) && (!found || len(k) > len(best)) {
			best, found = k, true
		}
	}
	if !found {
		return "principal"
	}
	return table[best]
}

// SupplierTableError: "" = a well-formed table (an object of allowed paths to known suppliers).
func SupplierTableError(t any) string {
	m, ok := t.(map[string]any)
	if !ok {
		return "the supplier table must be an object"
	}
	for _, k := range jsKeys(m) {
		bad := !supplierKeyRe.MatchString(k)
		for _, s := range strings.Split(k, ".") {
			bad = bad || forbiddenSegments[s]
		}
		if bad {
			return "bad supplier path '" + k + "'"
		}
		if v, isStr := m[k].(string); !isStr || !leaseHas(missingSuppliers, v) {
			return "bad supplier for '" + k + "'"
		}
	}
	return ""
}

func supplierTable(t any) map[string]string {
	out := map[string]string{}
	if m, ok := t.(map[string]any); ok {
		for k, v := range m {
			s, _ := v.(string)
			out[k] = s
		}
	}
	return out
}

func sortU16(s []string) []string {
	sort.Slice(s, func(i, j int) bool { return u16Less(s[i], s[j]) })
	return s
}

// mcLeaves flattens a plain-object tree into dotted leaf paths. Arrays and non-plain values are leaves.
func mcLeaves(v any, prefix string, out map[string]any, depth int) {
	if m, ok := v.(map[string]any); ok && len(m) > 0 && depth <= 16 {
		for k, x := range m {
			if !forbiddenSegments[k] {
				mcLeaves(x, prefix+"."+k, out, depth+1)
			}
		}
		return
	}
	out[prefix] = v
}

func mcDigest(v any) (string, bool) { return hashCanonicalV(map[string]any{"v": v}) }

// BindContext merges request-supplied context into the bound context. Bound wins; a differing supplied value is a conflict.
func BindContext(bound map[string]any, supplied any, table map[string]string) (out BoundContext) {
	ctx, _ := deepCopy(bound).(map[string]any)
	if ctx == nil {
		ctx = map[string]any{}
	}
	out = BoundContext{Context: ctx, Conflicts: []string{}, Dropped: []string{}}
	sup, ok := supplied.(map[string]any)
	if !ok {
		return out
	}
	flat := map[string]any{}
	defer func() {
		if recover() != nil { // fail closed: the call is refused
			out.Conflicts = []string{"?"}
			for p := range flat {
				out.Conflicts = append(out.Conflicts, p)
			}
			sortU16(out.Conflicts)
		}
	}()
	if a, ok := sup["action"].(map[string]any); ok {
		if p, ok := a["params"].(map[string]any); ok {
			mcLeaves(p, "action.params", flat, 0)
		}
	}
	for _, root := range []string{"subject", "env"} {
		if m, ok := sup[root].(map[string]any); ok {
			mcLeaves(m, root, flat, 0)
		}
	}
	paths := make([]string, 0, len(flat))
	for p := range flat {
		paths = append(paths, p)
	}
	for _, path := range sortU16(paths) {
		value := flat[path]
		if SupplierOf(path, table) == "agent_declared_untrusted" {
			out.Dropped = append(out.Dropped, path)
			continue
		}
		if cur, found := resolvePath(ctx, path); found {
			a, ok1 := mcDigest(cur)
			b, ok2 := mcDigest(value)
			if !ok1 || !ok2 || a != b {
				out.Conflicts = append(out.Conflicts, path)
			}
			continue
		}
		segs := strings.Split(path, ".")
		blocked := false
		for i := 2; i < len(segs); i++ {
			if v, found := resolvePath(ctx, strings.Join(segs[:i], ".")); found {
				if _, isObj := v.(map[string]any); !isObj {
					blocked = true // a bound leaf sits above the supplied path: writing it would replace the bound value
				}
			}
		}
		if blocked {
			out.Conflicts = append(out.Conflicts, path)
			continue
		}
		if strings.HasPrefix(path, "action.params") {
			act, has := ctx["action"]
			if !has || act == nil {
				act = map[string]any{"verb": "", "resource": ""}
			}
			am, isMap := act.(map[string]any)
			if !isMap {
				out.Conflicts = append(out.Conflicts, path) // the reference throws here; refused
				continue
			}
			if _, isObj := am["params"].(map[string]any); !isObj {
				am["params"] = map[string]any{}
			}
			ctx["action"] = am
		}
		cur := ctx
		for _, s := range segs[:len(segs)-1] {
			next, isObj := cur[s].(map[string]any)
			if !isObj {
				next = map[string]any{}
				cur[s] = next
			}
			cur = next
		}
		cur[segs[len(segs)-1]] = deepCopy(value)
	}
	return out
}

func mcCollect(c any, ctx map[string]any, out map[string]bool, ill *bool, depth int) {
	var m map[string]any
	switch t := c.(type) {
	case map[string]any:
		m = t
	case []any:
	default:
		*ill = true
		return
	}
	if depth > 64 {
		*ill = true
		return
	}
	if m != nil && isGroupCond(m) {
		var kids any
		if x, has := m["all_of"]; has {
			kids = x
		} else if x, has := m["any_of"]; has {
			kids = x
		} else {
			kids = []any{m["not"]}
		}
		arr, ok := kids.([]any)
		if !ok || len(arr) == 0 {
			*ill = true
			return
		}
		for _, k := range arr {
			mcCollect(k, ctx, out, ill, depth+1)
		}
		return
	}
	if evaluateConditionTri(c, ctx, &regexBudget{}) != triUnknown {
		return
	}
	field, _ := m["field"].(string)
	ref, _ := m["ref"].(string)
	absent := false
	for _, p := range []string{field, ref} {
		if p == "" {
			continue
		}
		if _, found := resolvePath(ctx, p); !found {
			out[p] = true
			absent = true
		}
	}
	if field != "" && paramsRooted(field) && !paramsAvailable(ctx) {
		out[field] = true
		absent = true
	}
	if !absent {
		*ill = true
	}
}

func mcDeny(reason string, missing []MissingContext) TypedDecision {
	if missing == nil {
		missing = []MissingContext{}
	}
	return TypedDecision{Decision: "deny", Reason: reason, Missing: missing}
}

// DecideWithMissing decides a permit condition list (implicit AND) over the bound context plus whatever the request supplied.
// bound must be an object with an action object (else bad_context); suppliers is the supplier table (nil = empty).
func DecideWithMissing(where, bound, supplied, suppliers any) (res TypedDecision) {
	defer func() {
		if recover() != nil {
			res = mcDeny("evaluation error (fail closed)", nil)
		}
	}()
	bm, ok := bound.(map[string]any)
	if !ok {
		return mcDeny("bad_context", nil)
	}
	if _, ok := bm["action"].(map[string]any); !ok {
		return mcDeny("bad_context", nil)
	}
	if suppliers == nil {
		suppliers = map[string]any{}
	}
	if te := SupplierTableError(suppliers); te != "" {
		return mcDeny("bad supplier table: "+te, nil)
	}
	table := supplierTable(suppliers)
	list, ok := where.([]any)
	if !ok || len(list) == 0 {
		return mcDeny("condition_false", nil)
	}
	b := BindContext(bm, supplied, table)
	if len(b.Conflicts) > 0 {
		return mcDeny("context_shadow: "+strings.Join(b.Conflicts, ","), nil)
	}
	switch evaluateConditionTri(map[string]any{"all_of": list}, b.Context, &regexBudget{}) {
	case triTrue:
		return TypedDecision{Decision: "allow", Missing: []MissingContext{}}
	case triFalse:
		return mcDeny("condition_false", nil)
	}
	set := map[string]bool{}
	ill := false
	for _, c := range list {
		mcCollect(c, b.Context, set, &ill, 0)
	}
	if len(set) == 0 || ill {
		return mcDeny("ill_typed_context", nil)
	}
	paths := make([]string, 0, len(set))
	for p := range set {
		paths = append(paths, p)
	}
	missing := make([]MissingContext, 0, len(paths))
	var untrusted, typed []string
	for _, p := range sortU16(paths) {
		s := SupplierOf(p, table)
		missing = append(missing, MissingContext{p, s})
		typed = append(typed, s+":"+p)
		if s == "agent_declared_untrusted" {
			untrusted = append(untrusted, p)
		}
	}
	if len(untrusted) > 0 {
		return mcDeny("missing_context_untrusted: "+strings.Join(untrusted, ","), missing)
	}
	return TypedDecision{Decision: "escalate", Reason: "escalate: missing_context " + strings.Join(typed, ","), Missing: missing}
}
