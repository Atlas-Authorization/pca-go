package pca

// Data filters: a residual compiled to a parameterized SQL filter and to a UCAST tree, and their evaluation over a row.

import (
	"fmt"
	"regexp"
	"strings"
)

// anlUnsupported marks an expression the filter cannot express exactly (the caller falls back to per-row authorization).
type anlUnsupported struct{ msg string }

func (e *anlUnsupported) Error() string { return e.msg }

func anlUnsup(format string, a ...any) { panic(&anlUnsupported{fmt.Sprintf(format, a...)}) }

var anlColRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,62}(\.[A-Za-z_][A-Za-z0-9_]{0,62})?$`)

func anlScalar(v any) bool {
	switch v.(type) {
	case bool, string:
		return true
	}
	return anlIsFin(v)
}

func anlColOf(path any, cols any) string {
	cm, ok := cols.(map[string]any)
	if !ok {
		anlFail("columns is not an object")
	}
	var c any = anlUndef
	if p, ok := path.(string); ok {
		if v, has := cm[p]; has {
			c = v
		}
	}
	s, ok := c.(string)
	if !ok || !anlColRe.MatchString(s) {
		anlUnsup("field '%s' has no usable column", anlJS(path))
	}
	return s
}

func anlFAnd(xs []any) map[string]any {
	switch len(xs) {
	case 0:
		return map[string]any{"t": "true"}
	case 1:
		return xs[0].(map[string]any)
	}
	return map[string]any{"t": "and", "xs": xs}
}

func anlFOr(xs []any) map[string]any {
	switch len(xs) {
	case 0:
		return map[string]any{"t": "false"}
	case 1:
		return xs[0].(map[string]any)
	}
	return map[string]any{"t": "or", "xs": xs}
}

func anlFCoalesce(x map[string]any, def bool) map[string]any {
	return map[string]any{"t": "coalesce", "x": x, "def": def}
}

func anlFCond(c any, cols any) map[string]any {
	m, ok := c.(map[string]any)
	if !ok {
		anlUnsup("malformed condition")
	}
	if anlIsGroup(m) {
		if xs, ok := m["all_of"].([]any); ok && len(xs) > 0 {
			out := make([]any, len(xs))
			for i, x := range xs {
				out[i] = anlFCond(x, cols)
			}
			return anlFAnd(out)
		}
		if xs, ok := m["any_of"].([]any); ok && len(xs) > 0 {
			out := make([]any, len(xs))
			for i, x := range xs {
				out[i] = anlFCond(x, cols)
			}
			return anlFOr(out)
		}
		if n, has := m["not"]; has {
			return map[string]any{"t": "not", "x": anlFCond(n, cols)}
		}
		anlUnsup("empty condition group")
	}
	leaf, ok := anlLeaf(m)
	if !ok {
		anlUnsup("malformed condition")
	}
	if anlHas(leaf, "ref") {
		anlUnsup("cross-field ref")
	}
	col := anlColOf(leaf["field"], cols)
	v, op := anlOwn(leaf, "value"), anlOwn(leaf, "op")
	switch op {
	case "eq", "ne":
		if !anlScalar(v) {
			anlUnsup("%s against a non-scalar", op)
		}
		return map[string]any{"t": "cmp", "col": col, "op": op, "v": v}
	case "lt", "lte", "gt", "gte":
		if !anlIsFin(v) {
			anlUnsup("string ordering follows UTF-8 byte order, which SQL collations do not guarantee")
		}
		return map[string]any{"t": "cmp", "col": col, "op": op, "v": v}
	case "in", "nin":
		l, ok := v.([]any)
		if !ok || len(l) == 0 {
			anlUnsup("%s needs a non-empty list of scalars", op)
		}
		for _, x := range l {
			if !anlScalar(x) {
				anlUnsup("%s needs a non-empty list of scalars", op)
			}
		}
		return map[string]any{"t": "in", "col": col, "vs": l, "neg": op == "nin"}
	case "prefix":
		s, ok := v.(string)
		if !ok {
			anlUnsup("prefix needs a string")
		}
		return map[string]any{"t": "prefix", "col": col, "prefix": s}
	case "exists":
		return map[string]any{"t": "null", "col": col, "isNull": v == false}
	}
	anlUnsup("operator '%s' has no exact SQL form", anlJS(op))
	return nil
}

func anlResourceExpr(p any, cols any) map[string]any {
	r := anlGet(p, "resource")
	if anlIsUndef(r) || anlStrictEq(r, "*") {
		return map[string]any{"t": "true"}
	}
	col := anlColOf("action.resource", cols)
	s, ok := r.(string)
	if !ok {
		anlFail("resource.startsWith is not a function")
	}
	if strings.HasPrefix(s, "re:") {
		anlUnsup("regex resource matcher")
	}
	if strings.HasSuffix(s, "*") {
		return map[string]any{"t": "prefix", "col": col, "prefix": s[:len(s)-1]}
	}
	return map[string]any{"t": "cmp", "col": col, "op": "eq", "v": s}
}

func anlVetoExpr(v any, cols any) map[string]any {
	wh := anlGet(v, "when")
	xs := []any{}
	if !anlIsUndef(anlGet(wh, "resource")) {
		xs = append(xs, anlFCoalesce(anlResourceExpr(wh, cols), true))
	}
	for _, c := range anlReqList(anlNN(anlGet(wh, "where"), []any{})) {
		xs = append(xs, anlFCoalesce(anlFCond(c, cols), true))
	}
	parts := []any{anlFAnd(xs)}
	if over := anlGet(v, "over"); anlTruthy(over) {
		col := anlColOf(anlGet(over, "path"), cols)
		parts = append(parts, anlFOr([]any{
			map[string]any{"t": "null", "col": col, "isNull": true},
			map[string]any{"t": "cmp", "col": col, "op": "lt", "v": 0},
			anlU(map[string]any{"t": "cmp", "col": col, "op": "gt", "v": anlGet(over, "threshold")}),
		}))
	}
	unless := anlGet(v, "unless")
	if anlGet(v, "kind") != "approval" && anlTruthy(unless) && anlLen(unless) > 0 {
		var us []any
		for _, c := range anlReqList(unless) {
			us = append(us, anlFCoalesce(anlFCond(c, cols), false))
		}
		parts = append(parts, map[string]any{"t": "not", "x": anlFAnd(us)})
	}
	return anlFAnd(parts)
}

func anlPartExpr(p any, cols any, include any) map[string]any {
	permits := []any{}
	for _, x := range anlReqList(anlGet(p, "predicates")) {
		xs := []any{anlResourceExpr(x, cols)}
		for _, c := range anlReqList(anlNN(anlGet(x, "where"), []any{})) {
			xs = append(xs, anlFCond(c, cols))
		}
		permits = append(permits, anlFAnd(xs))
	}
	gates := []any{anlFOr(permits)}
	for _, v := range anlReqList(anlGet(p, "vetoes")) {
		e := anlVetoExpr(v, cols)
		// an approval veto sends the row to a human: it leaves the autonomous set but stays in the admitted set
		if anlGet(v, "kind") == "deny" || include == "autonomous" {
			gates = append(gates, map[string]any{"t": "not", "x": e})
		}
	}
	for _, t := range anlReqList(anlGet(p, "tighten")) {
		if include == "autonomous" || anlGet(t, "signal") == "deny" {
			gates = append(gates, map[string]any{"t": "not", "x": anlFCoalesce(anlFCond(anlGet(t, "when"), cols), true)})
		}
	}
	return anlFAnd(gates)
}

var anlSQLOps = map[string]string{"eq": "=", "ne": "<>", "lt": "<", "lte": "<=", "gt": ">", "gte": ">="}

var anlLikeEscape = strings.NewReplacer("!", "!!", "%", "!%", "_", "!_")

func anlRender(e map[string]any, dialect any, params *[]any) string {
	ph := func(v any) string {
		*params = append(*params, v)
		if dialect == "postgres" {
			return fmt.Sprintf("$%d", len(*params))
		}
		return "?"
	}
	var R func(x map[string]any) string
	join := func(xs any, sep string) string {
		var parts []string
		for _, y := range xs.([]any) {
			parts = append(parts, R(y.(map[string]any)))
		}
		return "(" + strings.Join(parts, sep) + ")"
	}
	R = func(x map[string]any) string {
		switch x["t"] {
		case "true":
			return "TRUE"
		case "false":
			return "FALSE"
		case "cmp":
			return fmt.Sprintf("%s %s %s", x["col"], anlSQLOps[x["op"].(string)], ph(x["v"]))
		case "in":
			var ps []string
			for _, v := range x["vs"].([]any) {
				ps = append(ps, ph(v))
			}
			neg := "IN"
			if x["neg"] == true {
				neg = "NOT IN"
			}
			return fmt.Sprintf("%s %s (%s)", x["col"], neg, strings.Join(ps, ", "))
		case "prefix":
			return fmt.Sprintf("%s LIKE %s ESCAPE '!'", x["col"], ph(anlLikeEscape.Replace(x["prefix"].(string))+"%"))
		case "null":
			if x["isNull"] == true {
				return fmt.Sprintf("%s IS NULL", x["col"])
			}
			return fmt.Sprintf("%s IS NOT NULL", x["col"])
		case "and":
			return join(x["xs"], " AND ")
		case "or":
			return join(x["xs"], " OR ")
		case "not":
			return "NOT (" + R(x["x"].(map[string]any)) + ")"
		}
		def := "FALSE"
		if x["def"] == true {
			def = "TRUE"
		}
		return fmt.Sprintf("COALESCE(%s, %s)", R(x["x"].(map[string]any)), def)
	}
	return R(e)
}

// anlToFilter compiles a residual to a parameterized SQL filter ({ok, expr, sql, params, ucast}), or {ok: false, reason} when it cannot
// be done exactly (the caller then falls back to per-row authorization).
func anlToFilter(res, o any) (out map[string]any) {
	defer func() {
		if r := recover(); r != nil {
			if u, ok := r.(*anlUnsupported); ok {
				out = map[string]any{"ok": false, "reason": u.msg}
			} else {
				out = map[string]any{"ok": false, "reason": "filter compilation error"}
			}
		}
	}()
	if anlGet(res, "decision") == "never" {
		f := map[string]any{"t": "false"}
		return map[string]any{"ok": true, "expr": f, "sql": "FALSE", "params": []any{}, "ucast": anlToUcast(f)}
	}
	include := anlNN(anlGet(o, "include"), "autonomous")
	pol, ok := anlGet(res, "policy").(map[string]any)
	if !ok {
		anlFail("policy is not an object")
	}
	own := anlCopy(pol)
	delete(own, "meet")
	cols := anlGet(o, "columns")
	xs := []any{anlPartExpr(own, cols, include)}
	for _, p := range anlReqList(anlNN(pol["meet"], []any{})) {
		xs = append(xs, anlPartExpr(p, cols, include))
	}
	expr := anlFAnd(xs)
	params := []any{}
	sql := anlRender(expr, anlNN(anlGet(o, "dialect"), "postgres"), &params)
	return map[string]any{"ok": true, "expr": expr, "sql": sql, "params": params, "ucast": anlToUcast(expr)}
}

func anlTypeof(x any) string {
	switch x.(type) {
	case bool:
		return "boolean"
	case string:
		return "string"
	case anlUndefT:
		return "undefined"
	}
	if anlIsNum(x) {
		return "number"
	}
	return "object"
}

func anlRowGet(row any, c string) any {
	if m, ok := row.(map[string]any); ok {
		if v, has := m[c]; has {
			return v
		}
	}
	return nil
}

// anlOrd2 compares two values of the same type as `a OP b`.
func anlOrd2(op string, a, b any) bool {
	var x, y any = a, b
	if anlTypeof(a) == "number" {
		x, y = anlToNumber(a), anlToNumber(b)
	}
	less := func() bool { return anlLt(x, y) }
	greater := func() bool { return anlGt(x, y) }
	switch op {
	case "lt":
		return less()
	case "lte":
		return !greater()
	case "gt":
		return greater()
	}
	return !less()
}

// anlEvalFilter evaluates a filter expression over one row with SQL's three-valued logic: true, false or nil (NULL).
func anlEvalFilter(e any, row any) any {
	var K func(x map[string]any) any
	K = func(x map[string]any) any {
		t, _ := x["t"].(string)
		switch t {
		case "true":
			return true
		case "false":
			return false
		case "cmp":
			a, b := anlRowGet(row, x["col"].(string)), x["v"]
			if a == nil || anlTypeof(a) != anlTypeof(b) {
				return nil
			}
			op := x["op"].(string)
			if op == "eq" {
				return anlStrictEq(a, b)
			}
			if op == "ne" {
				return !anlStrictEq(a, b)
			}
			if anlTypeof(a) == "object" {
				return false
			}
			return anlOrd2(op, a, b)
		case "in":
			a := anlRowGet(row, x["col"].(string))
			if a == nil {
				return nil
			}
			hit := false
			for _, v := range anlReqList(x["vs"]) {
				if anlStrictEq(v, a) {
					hit = true
				}
			}
			if x["neg"] == true {
				return !hit
			}
			return hit
		case "prefix":
			if s, ok := anlRowGet(row, x["col"].(string)).(string); ok {
				return strings.HasPrefix(s, anlStr(x["prefix"], "prefix"))
			}
			return nil
		case "null":
			return (anlRowGet(row, x["col"].(string)) == nil) == (x["isNull"] == true)
		case "and", "or":
			stop, unk := t == "or", false
			for _, y := range anlReqList(x["xs"]) {
				v := K(y.(map[string]any))
				if b, ok := v.(bool); ok && b == stop {
					return stop
				}
				if v == nil {
					unk = true
				}
			}
			if unk {
				return nil
			}
			return !stop
		case "not":
			v := K(x["x"].(map[string]any))
			if v == nil {
				return nil
			}
			return !v.(bool)
		}
		v := K(x["x"].(map[string]any))
		if v == nil {
			return x["def"] == true
		}
		return v
	}
	m, ok := e.(map[string]any)
	if !ok {
		anlFail("expression is not an object")
	}
	return K(m)
}

// ---- UCAST ------------------------------------------------------------------------------------------------------------------

func anlUEmpty(u map[string]any, op string) bool {
	return u["type"] == "compound" && u["operator"] == op && len(u["value"].([]any)) == 0
}

func anlUJoin(op string, xs []any) map[string]any {
	other := "and"
	if op == "and" {
		other = "or"
	}
	flat := []any{}
	for _, xv := range xs {
		x := xv.(map[string]any)
		if x["type"] == "compound" && x["operator"] == op {
			flat = append(flat, x["value"].([]any)...)
		} else {
			flat = append(flat, x)
		}
	}
	for _, x := range flat {
		if anlUEmpty(x.(map[string]any), other) {
			return map[string]any{"type": "compound", "operator": other, "value": []any{}}
		}
	}
	kept := []any{}
	for _, x := range flat {
		if !anlUEmpty(x.(map[string]any), op) {
			kept = append(kept, x)
		}
	}
	if len(kept) == 1 {
		return kept[0].(map[string]any)
	}
	return map[string]any{"type": "compound", "operator": op, "value": kept}
}

func anlUNot(x map[string]any) map[string]any {
	return map[string]any{"type": "compound", "operator": "not", "value": []any{x}}
}

func anlUF(field, operator string, value any) map[string]any {
	return map[string]any{"type": "field", "field": field, "operator": operator, "value": value}
}

func anlUNotNull(c string) map[string]any { return anlUF(c, "ne", nil) }

var anlInvOp = map[string]string{"eq": "ne", "ne": "eq", "lt": "gte", "lte": "gt", "gt": "lte", "gte": "lt"}

func anlUList(xs any, f func(map[string]any) map[string]any) []any {
	out := []any{}
	for _, y := range anlReqList(xs) {
		out = append(out, f(y.(map[string]any)))
	}
	return out
}

func anlUT(x map[string]any) map[string]any {
	col, _ := x["col"].(string)
	switch x["t"] {
	case "true":
		return anlUJoin("and", nil)
	case "false":
		return anlUJoin("or", nil)
	case "cmp":
		if x["op"] == "ne" {
			return anlUJoin("and", []any{anlUNotNull(col), anlUF(col, "ne", x["v"])})
		}
		return anlUF(col, x["op"].(string), x["v"])
	case "in":
		if x["neg"] == true {
			return anlUJoin("and", []any{anlUNotNull(col), anlUF(col, "nin", x["vs"])})
		}
		return anlUF(col, "in", x["vs"])
	case "prefix":
		return anlUF(col, "startswith", x["prefix"])
	case "null":
		if x["isNull"] == true {
			return anlUF(col, "eq", nil)
		}
		return anlUNotNull(col)
	case "and":
		return anlUJoin("and", anlUList(x["xs"], anlUT))
	case "or":
		return anlUJoin("or", anlUList(x["xs"], anlUT))
	case "not":
		return anlUFl(x["x"].(map[string]any))
	}
	if x["def"] == true {
		return anlUNot(anlUFl(x["x"].(map[string]any)))
	}
	return anlUT(x["x"].(map[string]any))
}

func anlUFl(x map[string]any) map[string]any {
	col, _ := x["col"].(string)
	switch x["t"] {
	case "true":
		return anlUJoin("or", nil)
	case "false":
		return anlUJoin("and", nil)
	case "cmp":
		return anlUJoin("and", []any{anlUNotNull(col), anlUF(col, anlInvOp[x["op"].(string)], x["v"])})
	case "in":
		if x["neg"] == true {
			return anlUF(col, "in", x["vs"])
		}
		return anlUJoin("and", []any{anlUNotNull(col), anlUF(col, "nin", x["vs"])})
	case "prefix":
		return anlUJoin("and", []any{anlUNotNull(col), anlUNot(anlUF(col, "startswith", x["prefix"]))})
	case "null":
		if x["isNull"] == true {
			return anlUNotNull(col)
		}
		return anlUF(col, "eq", nil)
	case "and":
		return anlUJoin("or", anlUList(x["xs"], anlUFl))
	case "or":
		return anlUJoin("and", anlUList(x["xs"], anlUFl))
	case "not":
		return anlUT(x["x"].(map[string]any))
	}
	if x["def"] == true {
		return anlUFl(x["x"].(map[string]any))
	}
	return anlUNot(anlUT(x["x"].(map[string]any)))
}

// anlToUcast is the filter as a UCAST tree whose rows are exactly those the SQL form selects.
func anlToUcast(e any) map[string]any {
	m, ok := e.(map[string]any)
	if !ok {
		anlFail("expression is not an object")
	}
	return anlUT(m)
}

// anlEvalUcast evaluates a UCAST tree over one row (two-valued; a comparison with NULL is false).
func anlEvalUcast(uv any, row any) bool {
	u, ok := uv.(map[string]any)
	if !ok {
		anlFail("node is not an object")
	}
	if u["type"] == "compound" {
		kids := anlReqList(u["value"])
		switch u["operator"] {
		case "and":
			for _, c := range kids {
				if !anlEvalUcast(c, row) {
					return false
				}
			}
			return true
		case "or":
			for _, c := range kids {
				if anlEvalUcast(c, row) {
					return true
				}
			}
			return false
		}
		if len(kids) == 0 {
			anlFail("cannot read properties of undefined")
		}
		return !anlEvalUcast(kids[0], row)
	}
	field, _ := u["field"].(string)
	a := anlRowGet(row, field)
	v, _ := u["value"]
	op, _ := u["operator"].(string)
	if op == "eq" && v == nil {
		return a == nil
	}
	if op == "ne" && v == nil {
		return a != nil
	}
	if a == nil {
		return false
	}
	switch op {
	case "eq":
		return anlStrictEq(a, v)
	case "ne", "lt", "lte", "gt", "gte":
		if anlTypeof(a) != anlTypeof(v) {
			return false
		}
		if op == "ne" {
			return !anlStrictEq(a, v)
		}
		if anlTypeof(a) == "object" {
			return false
		}
		return anlOrd2(op, a, v)
	case "in":
		for _, e := range anlReqList(v) {
			if anlStrictEq(e, a) {
				return true
			}
		}
		return false
	case "nin":
		for _, e := range anlReqList(v) {
			if anlStrictEq(e, a) {
				return false
			}
		}
		return true
	case "startswith":
		if s, ok := a.(string); ok {
			return strings.HasPrefix(s, anlStr(v, "prefix"))
		}
	}
	return false
}
