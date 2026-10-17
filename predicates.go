package pca

// The predicate DSL of packages/pca/src/predicates.ts (evaluatePredicates and everything it calls): the ONE predicate
// evaluator the Intent Layer v2 `layers` check (intent-layers.ts decideLayerCeilings) runs each ceiling through.
// Total and panic-free: anything malformed, unknown or missing fails closed (condition 'unknown', predicate not
// matched). Strings are compared and measured in UTF-16 code units where JavaScript does (`length`, `startsWith`,
// globs, regex subjects) and ordered by UTF-8 bytes (the normative string order of lt/lte/gt/gte).

import "strings"

const (
	triTrue = iota
	triFalse
	triUnknown
)

const (
	maxPatternSubjectLen  = 512
	maxLikePatternLen     = 512
	maxMatchesPatternLen  = 200
	maxMemberClosureNodes = 10_000
	maxREResourceLen      = 512
)

var predicateRoots = setOf("action", "subject", "env")
var forbiddenSegments = setOf("__proto__", "constructor", "prototype")

// resolvePath: a dotted path into the context; own properties only; arrays by canonical index.
func resolvePath(ctx map[string]any, path any) (any, bool) {
	p, ok := path.(string)
	if !ok || p == "" {
		return nil, false
	}
	segs := strings.Split(p, ".")
	if !predicateRoots[segs[0]] {
		return nil, false
	}
	cur, ok := ctx[segs[0]]
	if !ok {
		return nil, false
	}
	for _, s := range segs[1:] {
		if forbiddenSegments[s] {
			return nil, false
		}
		switch t := cur.(type) {
		case []any:
			i, ok := arrayIndex(s)
			if !ok || (len(s) > 1 && s[0] == '0') || i >= len(t) {
				return nil, false
			}
			cur = t[i]
		case map[string]any:
			v, ok := t[s]
			if !ok {
				return nil, false
			}
			cur = v
		default:
			return nil, false
		}
	}
	return cur, true
}

func deepEq(a, b any) bool {
	x, ok1 := canonicalLenient(a)
	y, ok2 := canonicalLenient(b)
	return ok1 && ok2 && x == y
}

// ordered: -1/0/1, or ok false when the pair has no order (mixed types, a lone surrogate, a non-finite number).
func ordered(a, b any) (int, bool) {
	fa, na := jsNum(a)
	fb, nb := jsNum(b)
	if na && nb {
		if isFinite(fa) && isFinite(fb) {
			switch {
			case fa < fb:
				return -1, true
			case fa > fb:
				return 1, true
			}
			return 0, true
		}
		return 0, false
	}
	sa, sok := a.(string)
	sb, tok := b.(string)
	if sok && tok {
		if hasLoneSurrogate(sa) || hasLoneSurrogate(sb) {
			return 0, false
		}
		c := compareUtf8(sa, sb)
		switch {
		case c < 0:
			return -1, true
		case c > 0:
			return 1, true
		}
		return 0, true
	}
	return 0, false
}

func isFinite(f float64) bool { return f-f == 0 }

// jsStartsWith is String.prototype.startsWith over UTF-16 code units.
func jsStartsWith(s, prefix string) bool {
	u, p := utf16Units(s), utf16Units(prefix)
	if len(p) > len(u) {
		return false
	}
	for i := range p {
		if u[i] != p[i] {
			return false
		}
	}
	return true
}

type globTok struct {
	kind int // 0 lit, 1 one, 2 star
	ch   uint16
}

func parseGlob(g []uint16) ([]globTok, bool) {
	out := []globTok{}
	for i := 0; i < len(g); i++ {
		ch := g[i]
		switch ch {
		case '\\':
			if i+1 >= len(g) {
				return nil, false
			}
			out = append(out, globTok{0, g[i+1]})
			i++
		case '*':
			if len(out) == 0 || out[len(out)-1].kind != 2 {
				out = append(out, globTok{kind: 2})
			}
		case '?':
			out = append(out, globTok{kind: 1})
		default:
			out = append(out, globTok{0, ch})
		}
	}
	return out, true
}

func globMatch(glob, s []uint16) (bool, bool) {
	toks, ok := parseGlob(glob)
	if !ok {
		return false, false
	}
	ti, si, starTi, starSi := 0, 0, -1, 0
	for si < len(s) {
		if ti < len(toks) && toks[ti].kind == 2 {
			ti++
			starTi = ti
			starSi = si
		} else if ti < len(toks) && (toks[ti].kind == 1 || s[si] == toks[ti].ch) {
			ti++
			si++
		} else if starTi >= 0 {
			ti = starTi
			starSi++
			si = starSi
		} else {
			return false, true
		}
	}
	for ti < len(toks) && toks[ti].kind == 2 {
		ti++
	}
	return ti == len(toks), true
}

// typeTagMatch: (match, decidable).
func typeTagMatch(v any, t string) (bool, bool) {
	if s, ok := v.(string); ok {
		return s == t || strings.HasPrefix(s, t+"::"), true
	}
	m, ok := v.(map[string]any)
	if !ok {
		return false, false
	}
	decidable, matched := false, false
	if ty, has := m["type"]; has {
		if s, ok := ty.(string); ok {
			decidable = true
			if s == t || strings.HasPrefix(s, t+"::") {
				matched = true
			}
		}
	}
	if tags, has := m["tags"]; has {
		if arr, ok := tags.([]any); ok {
			decidable = true
			for _, x := range arr {
				if s, ok := x.(string); ok && s == t {
					matched = true
				}
			}
		}
	}
	return matched, decidable
}

func neighboursOf(adj map[string]any, node string) []string {
	if forbiddenSegments[node] {
		return nil
	}
	raw, ok := adj[node]
	if !ok {
		return nil
	}
	switch t := raw.(type) {
	case string:
		return []string{t}
	case []any:
		out := []string{}
		for _, x := range t {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func memberClosure(start string, adj map[string]any) map[string]bool {
	seen := map[string]bool{start: true}
	queue := []string{start}
	visited := 0
	for len(queue) > 0 && visited < maxMemberClosureNodes {
		visited++
		node := queue[0]
		queue = queue[1:]
		for _, n := range neighboursOf(adj, node) {
			if !seen[n] {
				seen[n] = true
				queue = append(queue, n)
			}
		}
	}
	return seen
}

func paramsRooted(p string) bool {
	return p == "action.params" || strings.HasPrefix(p, "action.params.")
}

func paramsAvailable(ctx map[string]any) bool {
	a, _ := ctx["action"].(map[string]any)
	switch a["params"].(type) {
	case map[string]any, []any:
		return true
	}
	return false
}

func triLeaf(c map[string]any, ctx map[string]any, b *regexBudget) int {
	field, ok := c["field"].(string)
	if !ok || field == "" {
		return triUnknown
	}
	op, ok := c["op"].(string)
	if !ok {
		return triUnknown
	}
	if paramsRooted(field) && !paramsAvailable(ctx) {
		return triUnknown
	}
	if r, ok := c["ref"].(string); ok && paramsRooted(r) && !paramsAvailable(ctx) {
		return triUnknown
	}
	v, found := resolvePath(ctx, field)
	if op == "exists" {
		want := found
		if b, ok := c["value"].(bool); ok && !b {
			want = !found
		}
		if want {
			return triTrue
		}
		return triFalse
	}
	if !found {
		return triUnknown
	}
	ref, hasRef := c["ref"]
	if op == "member_of" {
		s, ok := v.(string)
		if !ok {
			return triUnknown
		}
		coll, ok := c["collection"].(string)
		if !ok || coll == "" {
			return triUnknown
		}
		cv, found := resolvePath(ctx, coll)
		adj, isMap := cv.(map[string]any)
		if !found || !isMap {
			return triUnknown
		}
		var target any
		if hasRef {
			r, ok := resolvePath(ctx, ref)
			if !ok {
				return triUnknown
			}
			target = r
		} else {
			t, has := c["value"]
			if !has {
				return triUnknown
			}
			target = t
		}
		targets := []string{}
		switch t := target.(type) {
		case []any:
			for _, x := range t {
				if s, ok := x.(string); ok {
					targets = append(targets, s)
				}
			}
		case string:
			targets = append(targets, t)
		}
		if len(targets) == 0 {
			return triUnknown
		}
		reach := memberClosure(s, adj)
		for _, t := range targets {
			if reach[t] {
				return triTrue
			}
		}
		return triFalse
	}
	var operand any
	if hasRef {
		r, ok := resolvePath(ctx, ref)
		if !ok {
			return triUnknown
		}
		operand = r
	} else {
		o, has := c["value"]
		if !has {
			return triUnknown
		}
		operand = o
	}
	tri := func(b bool) int {
		if b {
			return triTrue
		}
		return triFalse
	}
	switch op {
	case "eq":
		return tri(deepEq(v, operand))
	case "ne":
		return tri(!deepEq(v, operand))
	case "in", "nin":
		arr, ok := operand.([]any)
		if !ok {
			return triUnknown
		}
		hit := false
		for _, x := range arr {
			if deepEq(v, x) {
				hit = true
				break
			}
		}
		return tri(hit == (op == "in"))
	case "lt", "lte", "gt", "gte":
		o, ok := ordered(v, operand)
		if !ok {
			return triUnknown
		}
		switch op {
		case "lt":
			return tri(o < 0)
		case "lte":
			return tri(o <= 0)
		case "gt":
			return tri(o > 0)
		}
		return tri(o >= 0)
	case "prefix":
		s, ok1 := v.(string)
		p, ok2 := operand.(string)
		if !ok1 || !ok2 {
			return triUnknown
		}
		return tri(jsStartsWith(s, p))
	case "like":
		s, ok1 := v.(string)
		p, ok2 := operand.(string)
		if !ok1 || !ok2 {
			return triUnknown
		}
		su, pu := utf16Units(s), utf16Units(p)
		if len(pu) > maxLikePatternLen || len(su) > maxPatternSubjectLen {
			return triUnknown
		}
		m, ok := globMatch(pu, su)
		if !ok {
			return triUnknown
		}
		return tri(m)
	case "matches":
		s, ok1 := v.(string)
		p, ok2 := operand.(string)
		if !ok1 || !ok2 {
			return triUnknown
		}
		su, pu := utf16Units(s), utf16Units(p)
		if len(pu) > maxMatchesPatternLen || len(su) > maxPatternSubjectLen {
			return triUnknown
		}
		if !isSafeRegexSource(pu) || !b.charge(pu, len(su)) {
			return triUnknown
		}
		m, ok := safeRegexFullMatch(pu, su)
		if !ok {
			return triUnknown
		}
		return tri(m)
	case "is_a":
		t, ok := operand.(string)
		if !ok || t == "" {
			return triUnknown
		}
		m, dec := typeTagMatch(v, t)
		if !dec {
			return triUnknown
		}
		return tri(m)
	}
	return triUnknown
}

func evaluateConditionTri(cv any, ctx map[string]any, b *regexBudget) int {
	c, ok := cv.(map[string]any)
	if !ok {
		return triUnknown // null, a primitive, or an array (no `field`)
	}
	if x, has := c["all_of"]; has {
		arr, ok := x.([]any)
		if !ok || len(arr) == 0 {
			return triUnknown
		}
		unk := false
		for _, y := range arr {
			switch evaluateConditionTri(y, ctx, b) {
			case triFalse:
				return triFalse
			case triUnknown:
				unk = true
			}
		}
		if unk {
			return triUnknown
		}
		return triTrue
	}
	if x, has := c["any_of"]; has {
		arr, ok := x.([]any)
		if !ok || len(arr) == 0 {
			return triUnknown
		}
		unk := false
		for _, y := range arr {
			switch evaluateConditionTri(y, ctx, b) {
			case triTrue:
				return triTrue
			case triUnknown:
				unk = true
			}
		}
		if unk {
			return triUnknown
		}
		return triFalse
	}
	if x, has := c["not"]; has {
		switch evaluateConditionTri(x, ctx, b) {
		case triTrue:
			return triFalse
		case triFalse:
			return triTrue
		}
		return triUnknown
	}
	return triLeaf(c, ctx, b)
}

func verbMatches(p any, verb string) bool {
	switch t := p.(type) {
	case string:
		return t == "*" || t == verb
	case []any:
		for _, x := range t {
			if s, ok := x.(string); ok && (s == "*" || s == verb) {
				return true
			}
		}
	}
	return false
}

func resourceMatches(pattern any, present bool, resource string, b *regexBudget) bool {
	if !present {
		return true
	}
	p, ok := pattern.(string)
	if !ok {
		return false
	}
	if p == "*" {
		return true
	}
	if strings.HasPrefix(p, "re:") {
		src := utf16Units(p[3:])
		ru := utf16Units(resource)
		if len(src) > 200 || len(ru) > maxREResourceLen {
			return false
		}
		if !isSafeRegexSource(src) || !b.charge(src, len(ru)) {
			return false
		}
		m, ok := safeRegexFullMatch(src, ru)
		return ok && m
	}
	if strings.HasSuffix(p, "*") {
		return jsStartsWith(resource, p[:len(p)-1])
	}
	return p == resource
}

func predicateMatches(pv any, ctx map[string]any, b *regexBudget) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	p, isMap := pv.(map[string]any)
	if !isMap {
		return false
	}
	a, _ := ctx["action"].(map[string]any)
	verb, ok1 := a["verb"].(string)
	resource, ok2 := a["resource"].(string)
	if !ok1 || !ok2 {
		return false
	}
	if !verbMatches(p["verb"], verb) {
		return false
	}
	rp, has := p["resource"]
	if !resourceMatches(rp, has, resource, b) {
		return false
	}
	if w, has := p["where"]; has {
		arr, ok := w.([]any)
		if !ok {
			return false
		}
		for _, c := range arr {
			if evaluateConditionTri(c, ctx, b) != triTrue {
				return false
			}
		}
	}
	return true
}

// evaluatePredicates: an action is allowed iff it matches at least one predicate (one document regex budget).
func evaluatePredicates(predicates any, ctx map[string]any) bool {
	arr, ok := predicates.([]any)
	if !ok || len(arr) == 0 {
		return false
	}
	b := &regexBudget{}
	for _, p := range arr {
		if predicateMatches(p, ctx, b) {
			return true
		}
	}
	return false
}
