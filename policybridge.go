package pca

// Import external authorization policy into PCA predicates: Cedar permit / forbid policies, OPA / Rego allow rules and an
// OpenFGA model with its relationship tuples. Every translator returns {predicates, denies, caveats, report: {source,
// translated, skipped, errors}}; whatever is not modeled fails closed. Text is read the way JavaScript reads it (the
// JavaScript whitespace set, ASCII word characters, UTF-16 lengths) so messages agree with the reference. PolicyBridgeDecide
// applies deny-overrides-permit over a translation. The strict CEL translator is in policybridge_cel.go.

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

const pbWSChars = "\t\n\u000b\f\r \u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000\ufeff"
const pbSClass = `[\t\n\x0b\f\r \x{a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}\x{feff}]`
const pbNotSClass = `[^\t\n\x0b\f\r \x{a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}\x{feff}]`
const pbDotClass = `[^\n\r\x{2028}\x{2029}]`

// pbRe compiles a pattern where § is the JavaScript whitespace class, ¶ its negation and ¤ the dot class.
func pbRe(p string) *regexp.Regexp {
	p = strings.NewReplacer("§", pbSClass, "¶", pbNotSClass, "¤", pbDotClass).Replace(p)
	return regexp.MustCompile(p)
}

func pbTrim(s string) string { return strings.Trim(s, pbWSChars) }

// pbInner is s[1:-1] (drops the first and the last character).
func pbInner(s string) string {
	if utf8.RuneCountInString(s) < 2 {
		return ""
	}
	_, n := utf8.DecodeRuneInString(s)
	_, m := utf8.DecodeLastRuneInString(s)
	return s[n : len(s)-m]
}

func pbTrimmedNonEmpty(parts []string) []string {
	out := []string{}
	for _, p := range parts {
		if t := pbTrim(p); len(t) > 0 {
			out = append(out, t)
		}
	}
	return out
}

var pbWSRun = pbRe(`§+`)

func pbTruncate(s string) string {
	one := pbTrim(pbWSRun.ReplaceAllString(s, " "))
	if jsLen(one) > 80 {
		return truncUnits(one, 77) + "..."
	}
	return one
}

func pbJstr(s string) string {
	var sb strings.Builder
	lenientString(&sb, s)
	return sb.String()
}

func pbJverb(v any) string {
	if s, ok := v.(string); ok {
		return pbJstr(s)
	}
	l, _ := v.([]any)
	parts := make([]string, len(l))
	for i, x := range l {
		s, _ := x.(string)
		parts[i] = pbJstr(s)
	}
	return "[" + strings.Join(parts, ",") + "]"
}

// pbNumber is Number(s) of a decimal literal.
func pbNumber(s string) float64 {
	f, _ := strconv.ParseFloat(s, 64)
	return f
}

func pbLess(a, b string) bool { return compareUnits(utf16Units(a), utf16Units(b)) < 0 }

func pbSortUnits(xs []string) { sort.Slice(xs, func(i, j int) bool { return pbLess(xs[i], xs[j]) }) }

type pbKV struct {
	k string
	v any
}

// pbEntries is Object.entries of an object or array value (ok false for anything else).
func pbEntries(o any) ([]pbKV, bool) {
	switch t := o.(type) {
	case map[string]any:
		out := []pbKV{}
		for _, k := range jsKeys(t) {
			out = append(out, pbKV{k, t[k]})
		}
		return out, true
	case []any:
		out := []pbKV{}
		for i, x := range t {
			out = append(out, pbKV{strconv.Itoa(i), x})
		}
		return out, true
	}
	return nil, false
}

// ---- bracket and quote aware scanning ----

func pbIndexTop(text, token string) int {
	depth := 0
	inStr := false
	for i := 0; i < len(text); i++ {
		ch := text[i]
		if inStr {
			if ch == '"' {
				inStr = false
			}
			continue
		}
		if ch == '"' {
			inStr = true
			continue
		}
		if ch == '(' || ch == '[' || ch == '{' {
			depth++
		} else if ch == ')' || ch == ']' || ch == '}' {
			depth--
		} else if depth == 0 && strings.HasPrefix(text[i:], token) {
			return i
		}
	}
	return -1
}

func pbSplitTop(text, delim string) []string {
	out := []string{}
	depth := 0
	inStr := false
	start := 0
	for i := 0; i < len(text); i++ {
		ch := text[i]
		if inStr {
			if ch == '"' {
				inStr = false
			}
			continue
		}
		if ch == '"' {
			inStr = true
			continue
		}
		if ch == '(' || ch == '[' || ch == '{' {
			depth++
		} else if ch == ')' || ch == ']' || ch == '}' {
			depth--
		}
		if depth == 0 && strings.HasPrefix(text[i:], delim) {
			out = append(out, text[start:i])
			i += len(delim) - 1
			start = i + 1
		}
	}
	return append(out, text[start:])
}

func pbMatchDelim(text string, open int, o, c byte) int {
	depth := 0
	inStr := false
	for i := open; i < len(text); i++ {
		ch := text[i]
		if inStr {
			if ch == '"' {
				inStr = false
			}
			continue
		}
		if ch == '"' {
			inStr = true
		} else if ch == o {
			depth++
		} else if ch == c {
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

type pbReport struct {
	source                      string
	translated, skipped, errors []any
}

func pbNewReport(source string) *pbReport {
	return &pbReport{source: source, translated: []any{}, skipped: []any{}, errors: []any{}}
}

func (r *pbReport) m() map[string]any {
	return map[string]any{"source": r.source, "translated": r.translated, "skipped": r.skipped, "errors": r.errors}
}

func pbResult(predicates, denies []any, r *pbReport) map[string]any {
	return map[string]any{"predicates": predicates, "denies": denies, "caveats": []any{}, "report": r.m()}
}

// ---- Cedar ----

const pbEntityParents = "env.entity_parents"

type pbCedarError string

func (e pbCedarError) Error() string { return string(e) }

// CedarToPca translates Cedar `permit` / `forbid` policies as permit predicates and deny predicates (consume with
// PolicyBridgeDecide).
func CedarToPca(policyText string) map[string]any { return TranslateCedar(policyText, true) }

var pbLineComment = regexp.MustCompile(`//[^\n]*`)

// TranslateCedar with errorGuards false omits the trailing "no attribute was missing" guard (bare structure; not exact).
func TranslateCedar(policyText string, errorGuards bool) map[string]any {
	report := pbNewReport("cedar")
	predicates, denies := []any{}, []any{}
	cleaned := pbLineComment.ReplaceAllString(policyText, "")
	for _, stmt := range pbTrimmedNonEmpty(pbSplitTop(cleaned, ";")) {
		if err := pbCedarStatement(stmt, &predicates, &denies, report, errorGuards); err != nil {
			report.errors = append(report.errors, fmt.Sprintf(`policy "%s": %s`, pbTruncate(stmt), err.Error()))
		}
	}
	return pbResult(predicates, denies, report)
}

var (
	pbAnnot   = pbRe(`^§*(?:@[A-Za-z_]\w*§*\([^)]*\)§*)+`)
	pbHead    = pbRe(`^§*([pP][eE][rR][mM][iI][tT]|[fF][oO][rR][bB][iI][dD])§*\(`)
	pbScopeRe = pbRe(`^(principal|action|resource)\b§*(?:(==|in|is)§*)?((?s:.*))$`)
	pbBlockRe = pbRe(`\b(when|unless)\b§*\{`)
)

func pbCedarStatement(stmt string, permits, denies *[]any, report *pbReport, errorGuards bool) error {
	body := stmt
	if loc := pbAnnot.FindStringIndex(body); loc != nil {
		body = body[loc[1]:]
	}
	head := pbHead.FindStringSubmatchIndex(body)
	if head == nil {
		report.skipped = append(report.skipped, fmt.Sprintf(`unrecognized statement: "%s"`, pbTruncate(stmt)))
		return nil
	}
	effect := "permit"
	if strings.ToLower(body[head[2]:head[3]]) == "forbid" {
		effect = "forbid"
	}
	openIdx := head[0] + strings.Index(body[head[0]:], "(")
	closeIdx := pbMatchDelim(body, openIdx, '(', ')')
	if closeIdx < 0 {
		return pbCedarError("unterminated scope parentheses")
	}
	scopeText := body[openIdx+1 : closeIdx]
	rest := body[closeIdx+1:]
	verb, resource, hasRes, scopeConds, err := pbParseScope(scopeText)
	if err != nil {
		return err
	}
	where := append([]any{}, scopeConds...)
	guards := []any{}
	blocks, err := pbConditionBlocks(rest)
	if err != nil {
		return err
	}
	for _, b := range blocks {
		parsed := pbParseExpr(b[1])
		if parsed == nil {
			report.skipped = append(report.skipped, fmt.Sprintf(`unmodeled %s-condition "%s" — policy dropped (fail closed)`, b[0], pbTruncate(b[1])))
			if effect == "forbid" {
				report.errors = append(report.errors, fmt.Sprintf(`forbid could not be fully modeled and was dropped — treat result as fail-closed: "%s"`, pbTruncate(stmt)))
			}
			return nil
		}
		if b[0] == "when" {
			where = append(where, parsed)
		} else {
			where = append(where, map[string]any{"not": parsed})
		}
		if g := pbNoError(parsed); g != nil {
			guards = append(guards, g)
		}
	}
	conditionCount := len(where)
	if errorGuards && len(guards) > 0 {
		if len(guards) == 1 {
			where = append(where, guards[0])
		} else {
			where = append(where, map[string]any{"all_of": guards})
		}
	}
	predicate := map[string]any{"verb": verb}
	if hasRes {
		predicate["resource"] = resource
	}
	if len(where) > 0 {
		predicate["where"] = where
	}
	on := ""
	if hasRes && resource != "" {
		on = " on " + resource
	}
	if effect == "permit" {
		*permits = append(*permits, predicate)
		report.translated = append(report.translated, fmt.Sprintf("permit → verb %s%s (%d condition(s))", pbJverb(verb), on, conditionCount))
	} else {
		*denies = append(*denies, predicate)
		report.translated = append(report.translated, fmt.Sprintf("forbid → deny verb %s%s (%d condition(s))", pbJverb(verb), on, conditionCount))
	}
	return nil
}

func pbParseScope(scopeText string) (verb any, resource string, hasRes bool, conds []any, err error) {
	verb = "*"
	conds = []any{}
	for _, clause := range pbTrimmedNonEmpty(pbSplitTop(scopeText, ",")) {
		m := pbScopeRe.FindStringSubmatch(clause)
		if m == nil {
			return nil, "", false, nil, pbCedarError(fmt.Sprintf(`unparseable scope clause "%s"`, pbTruncate(clause)))
		}
		variable, op, operand := m[1], m[2], pbTrim(m[3])
		if op == "" {
			continue
		}
		if variable == "action" {
			if op == "==" {
				eid, ok := pbEntityID(operand)
				if !ok {
					return nil, "", false, nil, pbCedarError(fmt.Sprintf(`action == expects an Action entity, got "%s"`, pbTruncate(operand)))
				}
				verb = eid
			} else if op == "in" && strings.HasPrefix(operand, "[") {
				verbs := []any{}
				for _, it := range pbTrimmedNonEmpty(pbSplitTop(pbInner(operand), ",")) {
					eid, ok := pbEntityID(it)
					if !ok {
						return nil, "", false, nil, pbCedarError(fmt.Sprintf(`action in [...] expects Action entities, got "%s"`, pbTruncate(it)))
					}
					verbs = append(verbs, eid)
				}
				verb = verbs
			} else {
				return nil, "", false, nil, pbCedarError(fmt.Sprintf(`unsupported action scope operator "%s"`, op))
			}
			continue
		}
		field := "subject.id"
		if variable == "resource" {
			field = "action.resource"
		}
		switch op {
		case "==":
			uid, ok := pbEntityUID(operand)
			if variable == "resource" {
				if !ok {
					return nil, "", false, nil, pbCedarError(fmt.Sprintf(`resource == expects an entity, got "%s"`, pbTruncate(operand)))
				}
				resource, hasRes = uid, true
			} else {
				if !ok {
					return nil, "", false, nil, pbCedarError(fmt.Sprintf(`principal == expects an entity, got "%s"`, pbTruncate(operand)))
				}
				conds = append(conds, map[string]any{"field": field, "op": "eq", "value": uid})
			}
		case "is":
			t, ok := pbTypeName(operand)
			if !ok {
				return nil, "", false, nil, pbCedarError(fmt.Sprintf(`%s is expects a type, got "%s"`, variable, pbTruncate(operand)))
			}
			conds = append(conds, map[string]any{"field": field, "op": "is_a", "value": t})
		default:
			mem := pbMemberOf(field, operand)
			if mem == nil {
				return nil, "", false, nil, pbCedarError(fmt.Sprintf(`%s in expects an entity (hierarchy), got "%s"`, variable, pbTruncate(operand)))
			}
			conds = append(conds, mem)
		}
	}
	return verb, resource, hasRes, conds, nil
}

// pbConditionBlocks returns the (kind, text) of every `when {..}` / `unless {..}` block.
func pbConditionBlocks(rest string) ([][2]string, error) {
	blocks := [][2]string{}
	pos := 0
	for pos <= len(rest) {
		m := pbBlockRe.FindStringSubmatchIndex(rest[pos:])
		if m == nil {
			break
		}
		kind := "when"
		if rest[pos+m[2]:pos+m[3]] == "unless" {
			kind = "unless"
		}
		open := pos + m[0] + strings.Index(rest[pos+m[0]:], "{")
		cl := pbMatchDelim(rest, open, '{', '}')
		if cl < 0 {
			return nil, pbCedarError("unterminated " + kind + " block")
		}
		blocks = append(blocks, [2]string{kind, rest[open+1 : cl]})
		pos = cl + 1
	}
	return blocks, nil
}

func pbParseExpr(text string) map[string]any {
	t := pbTrim(text)
	if len(t) == 0 {
		return nil
	}
	for _, d := range [][2]string{{"||", "any_of"}, {"&&", "all_of"}} {
		parts := pbTrimmedNonEmpty(pbSplitTop(t, d[0]))
		if len(parts) > 1 {
			subs := []any{}
			for _, s := range parts {
				p := pbParseExpr(s)
				if p == nil {
					return nil
				}
				subs = append(subs, p)
			}
			return map[string]any{d[1]: subs}
		}
	}
	if strings.HasPrefix(t, "(") && pbMatchDelim(t, 0, '(', ')') == len(t)-1 {
		return pbParseExpr(pbInner(t))
	}
	return pbParseAtom(t)
}

var pbCmpTokens = [][2]string{{"==", "eq"}, {"!=", "ne"}, {"<=", "lte"}, {">=", "gte"}, {"<", "lt"}, {">", "gt"}}
var pbWordOp = pbRe(`^((?s:.*?)¶)§+(in|is|like|has)§+((?s:.+))$`)

func pbParseAtom(text string) map[string]any {
	t := pbTrim(text)
	for _, c := range pbCmpTokens {
		if idx := pbIndexTop(t, c[0]); idx >= 0 {
			return pbBuildComparison(pbTrim(t[:idx]), c[1], pbTrim(t[idx+len(c[0]):]))
		}
	}
	if wm := pbWordOp.FindStringSubmatch(t); wm != nil {
		return pbBuildWordOp(pbTrim(wm[1]), wm[2], pbTrim(wm[3]))
	}
	return nil
}

func pbBuildComparison(lhs, op, rhs string) map[string]any {
	field, ok := pbFieldPath(lhs)
	if !ok {
		return nil
	}
	if field == "action.verb" {
		if op != "eq" && op != "ne" {
			return nil
		}
		eid, ok := pbEntityID(rhs)
		if !ok {
			return nil
		}
		return map[string]any{"field": field, "op": op, "value": eid}
	}
	if pbIsPathExpr(rhs) {
		if ref, ok := pbFieldPath(rhs); ok {
			return map[string]any{"field": field, "op": op, "ref": ref}
		}
	}
	v, ok := pbLiteral(rhs)
	if !ok {
		return nil
	}
	return map[string]any{"field": field, "op": op, "value": v}
}

var (
	pbIdent    = pbRe(`^[A-Za-z_]\w*$`)
	pbLikeStr  = pbRe(`^"((?s:.*))"$`)
	pbPathHead = pbRe(`^(principal|resource|action|context)\b`)
	pbPPrin    = pbRe(`^principal\.([A-Za-z_][\w.]*)$`)
	pbPRes     = pbRe(`^resource\.([A-Za-z_][\w.]*)$`)
	pbPCtx     = pbRe(`^context\.([A-Za-z_][\w.]*)$`)
	pbTypeRe   = pbRe(`^[A-Za-z_]\w*(::[A-Za-z_]\w*)*$`)
	pbEntID    = pbRe(`^¤+::"([^"]*)"$`)
	pbEntUID   = pbRe(`^(¤+)::"([^"]*)"$`)
	pbStrLit   = pbRe(`^"([^"]*)"$`)
	pbNumLit   = pbRe(`^-?\d+(\.\d+)?$`)
)

func pbBuildWordOp(lhs, kind, rhs string) map[string]any {
	if kind == "has" {
		if !pbIdent.MatchString(rhs) {
			return nil
		}
		field, ok := pbFieldPath(lhs + "." + rhs)
		if !ok {
			return nil
		}
		return map[string]any{"field": field, "op": "exists"}
	}
	field, ok := pbFieldPath(lhs)
	if !ok {
		return nil
	}
	if field == "action.verb" {
		if kind != "in" {
			return nil
		}
		inner := rhs
		if strings.HasPrefix(rhs, "[") && strings.HasSuffix(rhs, "]") {
			inner = pbInner(rhs)
		}
		ids := []any{}
		for _, x := range pbTrimmedNonEmpty(pbSplitTop(inner, ",")) {
			eid, ok := pbEntityID(x)
			if !ok {
				return nil
			}
			ids = append(ids, eid)
		}
		if len(ids) == 0 {
			return nil
		}
		return map[string]any{"field": field, "op": "in", "value": ids}
	}
	if kind == "is" {
		t, ok := pbTypeName(rhs)
		if !ok {
			return nil
		}
		return map[string]any{"field": field, "op": "is_a", "value": t}
	}
	if kind == "like" {
		sm := pbLikeStr.FindStringSubmatch(rhs)
		if sm == nil {
			return nil
		}
		return map[string]any{"field": field, "op": "like", "value": pbCedarLikeToGlob(sm[1])}
	}
	if strings.HasPrefix(rhs, "[") {
		inner := rhs[1:]
		if strings.HasSuffix(rhs, "]") {
			inner = pbInner(rhs)
		}
		items := pbTrimmedNonEmpty(pbSplitTop(inner, ","))
		allUID := len(items) > 0
		uids := []any{}
		for _, it := range items {
			u, ok := pbEntityUID(it)
			if !ok {
				allUID = false
				break
			}
			uids = append(uids, u)
		}
		if allUID {
			return map[string]any{"field": field, "op": "member_of", "value": uids, "collection": pbEntityParents}
		}
		values := []any{}
		for _, it := range items {
			v, ok := pbLiteral(it)
			if !ok {
				return nil
			}
			values = append(values, v)
		}
		return map[string]any{"field": field, "op": "in", "value": values}
	}
	return pbMemberOf(field, rhs)
}

func pbMemberOf(field, operand string) map[string]any {
	if uid, ok := pbEntityUID(operand); ok {
		return map[string]any{"field": field, "op": "member_of", "value": uid, "collection": pbEntityParents}
	}
	if pbIsPathExpr(operand) {
		if ref, ok := pbFieldPath(operand); ok {
			return map[string]any{"field": field, "op": "member_of", "ref": ref, "collection": pbEntityParents}
		}
	}
	return nil
}

func pbIsPathExpr(e string) bool { return pbPathHead.MatchString(e) }

func pbFieldPath(e string) (string, bool) {
	switch e {
	case "principal":
		return "subject.id", true
	case "resource":
		return "action.resource", true
	case "action":
		return "action.verb", true
	case "context":
		return "env", true
	}
	if m := pbPPrin.FindStringSubmatch(e); m != nil {
		return "subject." + m[1], true
	}
	if m := pbPRes.FindStringSubmatch(e); m != nil {
		return "env.resource." + m[1], true
	}
	if m := pbPCtx.FindStringSubmatch(e); m != nil {
		return "env." + m[1], true
	}
	return "", false
}

func pbTypeName(e string) (string, bool) {
	s := pbTrim(e)
	return s, pbTypeRe.MatchString(s)
}

func pbEntityID(e string) (string, bool) {
	if m := pbEntID.FindStringSubmatch(pbTrim(e)); m != nil {
		return m[1], true
	}
	return "", false
}

func pbEntityUID(e string) (string, bool) {
	if m := pbEntUID.FindStringSubmatch(pbTrim(e)); m != nil {
		return m[1] + "::" + m[2], true
	}
	return "", false
}

func pbLiteral(e string) (any, bool) {
	s := pbTrim(e)
	if m := pbStrLit.FindStringSubmatch(s); m != nil {
		return m[1], true
	}
	if s == "true" {
		return true, true
	}
	if s == "false" {
		return false, true
	}
	if pbNumLit.MatchString(s) {
		return pbNumber(s), true
	}
	if u, ok := pbEntityUID(s); ok {
		return u, true
	}
	return nil, false
}

func pbEscGlob(ch byte) []byte {
	if ch == '*' || ch == '?' || ch == '\\' {
		return []byte{'\\', ch}
	}
	return []byte{ch}
}

func pbCedarLikeToGlob(inner string) string {
	out := []byte{}
	n := len(inner)
	for i := 0; i < n; {
		ch := inner[i]
		if ch == '\\' {
			if i+1 < n {
				if inner[i+1] == '*' {
					out = append(out, '\\', '*')
				} else {
					out = append(out, pbEscGlob(inner[i+1])...)
				}
				i += 2
				continue
			}
			out = append(out, '\\', '\\')
			i++
			continue
		}
		if ch == '*' {
			out = append(out, '*')
		} else {
			out = append(out, pbEscGlob(ch)...)
		}
		i++
	}
	return string(out)
}

// Cedar evaluation-error semantics: the guard that makes a policy apply only when no absent attribute is read.

func pbGuardedPaths(field string, has bool) []string {
	if !has || field == "subject.id" || field == "action.verb" || field == "action.resource" || field == "env" || strings.HasPrefix(field, "env.entity_parents") {
		return nil
	}
	if strings.HasPrefix(field, "subject.") || strings.HasPrefix(field, "env.") {
		return []string{field}
	}
	return nil
}

func pbExists(field string) any { return map[string]any{"field": field, "op": "exists"} }

func pbAllOf(xs []any) any {
	if len(xs) == 1 {
		return xs[0]
	}
	return map[string]any{"all_of": xs}
}

func pbAnyOf(xs []any) any {
	if len(xs) == 1 {
		return xs[0]
	}
	return map[string]any{"any_of": xs}
}

var pbLastSeg = regexp.MustCompile(`\.[^.]+$`)

func pbAsMap(v any) map[string]any { m, _ := v.(map[string]any); return m }

// pbNoError is "evaluating this expression raises no Cedar error", as a condition (nil = it cannot).
func pbNoError(c map[string]any) any {
	if inner, ok := c["not"]; ok {
		return pbNoErrorAny(inner)
	}
	_, isAnd := c["all_of"]
	_, isOr := c["any_of"]
	if isAnd || isOr {
		var kids []any
		if isAnd {
			kids, _ = c["all_of"].([]any)
		} else {
			kids, _ = c["any_of"].([]any)
		}
		var acc any
		for i := len(kids) - 1; i >= 0; i-- {
			kid := kids[i]
			n := pbNoErrorAny(kid)
			var cont any
			if acc != nil {
				first := kid
				if isAnd {
					first = map[string]any{"not": kid}
				}
				cont = pbAnyOf([]any{first, acc})
			}
			switch {
			case n == nil:
				acc = cont
			case cont == nil:
				acc = n
			default:
				acc = pbAllOf([]any{n, cont})
			}
		}
		return acc
	}
	field, hasF := c["field"].(string)
	if op, _ := c["op"].(string); op == "exists" && hasF {
		base := pbLastSeg.ReplaceAllString(field, "")
		min := 2
		if strings.HasPrefix(base, "env.resource") {
			min = 3
		}
		if len(strings.Split(base, ".")) >= min {
			needs := []any{}
			for _, p := range pbGuardedPaths(base, true) {
				needs = append(needs, pbExists(p))
			}
			if len(needs) > 0 {
				return pbAllOf(needs)
			}
		}
		return nil
	}
	needs := []any{}
	for _, p := range pbGuardedPaths(field, hasF) {
		needs = append(needs, pbExists(p))
	}
	ref, hasR := c["ref"].(string)
	for _, p := range pbGuardedPaths(ref, hasR) {
		needs = append(needs, pbExists(p))
	}
	if len(needs) == 0 {
		return nil
	}
	return pbAllOf(needs)
}

func pbNoErrorAny(v any) any {
	m := pbAsMap(v)
	if m == nil {
		return nil
	}
	return pbNoError(m)
}

// ---- Rego ----

var (
	pbPkgRe       = pbRe(`\bpackage§+([A-Za-z_][\w.]*)`)
	pbDefaultRe   = pbRe(`\bdefault§+allow§*(?::?=)§*(true|false)\b`)
	pbAllowRe     = pbRe(`\ballow\b§*(?:(?::?=§*true\b|=§*true\b|\bif\b)§*)?\{`)
	pbNotRe       = pbRe(`^not§+((?s:.+))$`)
	pbUnmodeledA  = pbRe(`:=|\bsome\b|\bevery\b|\[¤*\|¤*\]`)
	pbUnmodeledIx = pbRe(`\binput\.[\w.]*\[`)
	pbRegoCmp     = pbRe(`^(input\.[\w.]+)§*(==|!=|<=|>=|<|>|\bin\b)§*((?s:.+))$`)
	pbInputPath   = pbRe(`^input\.[\w.]+$`)
	pbStartsWith  = pbRe(`^startswith\(§*(input\.[\w.]+)§*,§*"([^"]*)"§*\)$`)
	pbGlobRe      = pbRe(`^glob\.match\(§*"([^"]*)"§*,§*(\[§*\]|null)§*,§*(input\.[\w.]+)§*\)$`)
	pbHashComment = regexp.MustCompile(`#[^\n]*`)
	pbRuleSplit   = regexp.MustCompile(`[\n;]`)
)

// RegoToPca translates OPA / Rego `allow` rules (a conjunction of input comparisons per rule) as permit predicates;
// anything else drops its rule.
func RegoToPca(moduleText string) map[string]any {
	report := pbNewReport("rego")
	predicates := []any{}
	src := pbHashComment.ReplaceAllString(moduleText, "")
	if m := pbPkgRe.FindStringSubmatch(src); m != nil {
		report.translated = append(report.translated, "package "+m[1])
	}
	d := pbDefaultRe.FindStringSubmatch(src)
	if d != nil && d[1] == "true" {
		report.skipped = append(report.skipped, "`default allow = true` is not modeled (cannot express allow-unless); treated as default-deny")
	} else if d == nil {
		report.skipped = append(report.skipped, "no `default allow = false` found; assuming default-deny")
	}
	pos := 0
	for pos <= len(src) {
		m := pbAllowRe.FindStringIndex(src[pos:])
		if m == nil {
			break
		}
		open := pos + m[0] + strings.Index(src[pos+m[0]:], "{")
		cl := pbMatchDelim(src, open, '{', '}')
		if cl < 0 {
			report.errors = append(report.errors, "unterminated `allow { ... }` block")
			break
		}
		pbRegoRule(src[open+1:cl], &predicates, report)
		pos = cl + 1
	}
	return pbResult(predicates, []any{}, report)
}

type pbStmt struct {
	kind string
	v    any
}

func pbRegoRule(body string, predicates *[]any, report *pbReport) {
	var verb any = "*"
	resource, hasRes := "", false
	where := []any{}
	for _, raw := range pbRuleSplit.Split(body, -1) {
		stmt := pbTrim(raw)
		if len(stmt) == 0 {
			continue
		}
		p := pbRegoStatement(stmt)
		switch p.kind {
		case "unmodeled":
			report.skipped = append(report.skipped, fmt.Sprintf(`unmodeled statement "%s" — rule dropped (fail closed)`, pbTruncate(stmt)))
			return
		case "verb":
			if vs, isStr := verb.(string); isStr && vs == "*" {
				verb = p.v
			} else {
				have := pbAsList(verb)
				nxt := pbAsList(p.v)
				both := []any{}
				for _, h := range have {
					for _, x := range nxt {
						if h == x {
							both = append(both, h)
							break
						}
					}
				}
				if len(both) == 0 {
					report.translated = append(report.translated, "rule can never match (contradictory action selectors), nothing emitted")
					return
				}
				if len(both) == 1 {
					verb = both[0]
				} else {
					verb = both
				}
			}
		case "resource":
			if hasRes && resource != p.v.(string) {
				report.translated = append(report.translated, "rule can never match (contradictory resource selectors), nothing emitted")
				return
			}
			resource, hasRes = p.v.(string), true
		default:
			where = append(where, p.v)
		}
	}
	predicate := map[string]any{"verb": verb}
	if hasRes {
		predicate["resource"] = resource
	}
	if len(where) > 0 {
		predicate["where"] = where
	}
	*predicates = append(*predicates, predicate)
	on := ""
	if hasRes && resource != "" {
		on = " on " + resource
	}
	report.translated = append(report.translated, fmt.Sprintf("allow → verb %s%s (%d condition(s))", pbJverb(verb), on, len(where)))
}

func pbAsList(v any) []any {
	if l, ok := v.([]any); ok {
		return l
	}
	return []any{v}
}

var pbUnmodeled = pbStmt{kind: "unmodeled"}

func pbRegoStatement(stmt string) pbStmt {
	s := pbTrim(stmt)
	if nm := pbNotRe.FindStringSubmatch(s); nm != nil {
		inner := pbRegoStatement(pbTrim(nm[1]))
		if inner.kind != "condition" {
			return pbUnmodeled
		}
		c := inner.v.(map[string]any)
		if op, _ := c["op"].(string); op == "eq" {
			if f, isStr := c["field"].(string); isStr {
				needs := []any{pbExists(f)}
				if r, ok := c["ref"].(string); ok {
					needs = append(needs, pbExists(r))
				}
				needs = append(needs, c)
				return pbStmt{"condition", map[string]any{"not": map[string]any{"all_of": needs}}}
			}
		}
		return pbStmt{"condition", map[string]any{"not": c}}
	}
	if b, ok := pbRegoBuiltin(s); ok {
		return b
	}
	if pbUnmodeledA.MatchString(s) || strings.Contains(s, "(") || pbUnmodeledIx.MatchString(s) {
		return pbUnmodeled
	}
	m := pbRegoCmp.FindStringSubmatch(s)
	if m == nil {
		return pbUnmodeled
	}
	path, opTok, rhs := m[1], m[2], pbTrim(m[3])
	sub := path[len("input."):]
	if opTok == "in" {
		values, ok := pbSetLiteral(rhs)
		if !ok {
			return pbUnmodeled
		}
		if sub == "action" {
			for _, v := range values {
				if _, isStr := v.(string); !isStr {
					return pbUnmodeled
				}
			}
			return pbStmt{"verb", values}
		}
		return pbStmt{"condition", map[string]any{"field": "env." + sub, "op": "in", "value": values}}
	}
	if (opTok == "==" || opTok == "!=") && pbInputPath.MatchString(rhs) {
		op := "eq"
		if opTok == "!=" {
			op = "ne"
		}
		return pbStmt{"condition", map[string]any{"field": "env." + sub, "op": op, "ref": "env." + rhs[len("input."):]}}
	}
	value, ok := pbRegoLiteral(rhs)
	if !ok {
		return pbUnmodeled
	}
	if opTok == "==" {
		if str, isStr := value.(string); isStr && sub == "action" {
			return pbStmt{"verb", str}
		}
		if str, isStr := value.(string); isStr && sub == "resource" {
			return pbStmt{"resource", str}
		}
		return pbStmt{"condition", map[string]any{"field": "env." + sub, "op": "eq", "value": value}}
	}
	if opTok == "!=" {
		return pbStmt{"condition", map[string]any{"field": "env." + sub, "op": "ne", "value": value}}
	}
	if _, isNum := value.(float64); !isNum {
		return pbUnmodeled
	}
	cmp := map[string]string{"<": "lt", "<=": "lte", ">": "gt", ">=": "gte"}[opTok]
	return pbStmt{"condition", map[string]any{"field": "env." + sub, "op": cmp, "value": value}}
}

func pbRegoBuiltin(s string) (pbStmt, bool) {
	if sw := pbStartsWith.FindStringSubmatch(s); sw != nil {
		return pbStmt{"condition", map[string]any{"field": "env." + sw[1][len("input."):], "op": "prefix", "value": sw[2]}}, true
	}
	if gm := pbGlobRe.FindStringSubmatch(s); gm != nil {
		pattern := gm[1]
		if strings.ContainsAny(pattern, "[]{}") {
			return pbUnmodeled, true
		}
		if strings.HasPrefix(gm[2], "[") && strings.ContainsAny(pattern, "*?\\") {
			return pbUnmodeled, true
		}
		return pbStmt{"condition", map[string]any{"field": "env." + gm[3][len("input."):], "op": "like", "value": pattern}}, true
	}
	return pbStmt{}, false
}

var pbRegoStr = pbRe(`^"([^"]*)"$`)

func pbRegoLiteral(e string) (any, bool) {
	s := pbTrim(e)
	if m := pbRegoStr.FindStringSubmatch(s); m != nil {
		return m[1], true
	}
	if s == "true" {
		return true, true
	}
	if s == "false" {
		return false, true
	}
	if pbNumLit.MatchString(s) {
		return pbNumber(s), true
	}
	return nil, false
}

func pbSetLiteral(e string) ([]any, bool) {
	s := pbTrim(e)
	isSet := strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}")
	isArr := strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]")
	if !isSet && !isArr {
		return nil, false
	}
	values := []any{}
	for _, it := range pbTrimmedNonEmpty(pbSplitTop(pbInner(s), ",")) {
		v, ok := pbRegoLiteral(it)
		if !ok {
			return nil, false
		}
		values = append(values, v)
	}
	return values, true
}

// ---- OpenFGA ----

const pbMaxDepth = 32

type pbPlan struct {
	kind              string // direct computed union intersection difference ttu
	relation          string
	children          []*pbPlan
	base, subtract    *pbPlan
	tupleset, compute string
}

type pbBuilt struct {
	ok, partial bool
	plan        *pbPlan
	reason      string
}

type pbRelSet struct {
	order []string
	nodes map[string]any
}

type pbOrdered struct {
	keys []string
	m    map[string]*pbRelSet
}

// OpenfgaToPca translates an OpenFGA / Zanzibar model plus relationship tuples into one permit per (user, object,
// relation) triple that holds (this, computedUserset, union, intersection, difference, tupleToUserset; bounded and
// cycle-guarded). Omitting tuples is no error; a non-array tuples value is reported.
func OpenfgaToPca(model any, tuples ...any) map[string]any {
	report := pbNewReport("openfga")
	predicates := []any{}
	typeRelations := pbParseModel(model, report)
	var tupleList []map[string]string
	if len(tuples) > 0 {
		tupleList = pbParseTuples(tuples[0], report, true)
	}
	if typeRelations == nil {
		return pbResult(predicates, []any{}, report)
	}
	direct := map[string]map[string]bool{}
	usersSeen := map[string]bool{}
	wildcardTypes := map[string]bool{}
	objectsSeen := map[string]bool{}
	usersetTuples := 0
	for _, t := range tupleList {
		objectsSeen[t["object"]] = true
		k := t["object"] + "\x00" + t["relation"]
		if direct[k] == nil {
			direct[k] = map[string]bool{}
		}
		direct[k][t["user"]] = true
		if strings.Contains(t["user"], "#") {
			usersetTuples++
		} else if pbIsWildcard(t["user"]) {
			wildcardTypes[t["user"][:len(t["user"])-2]] = true
		} else {
			usersSeen[t["user"]] = true
		}
	}
	if usersetTuples > 0 {
		report.skipped = append(report.skipped, fmt.Sprintf("%d userset-valued tuple(s) (user contains '#') not expanded to concrete users", usersetTuples))
	}
	plans := map[string]*pbPlan{}
	for _, typ := range typeRelations.keys {
		rels := typeRelations.m[typ]
		for _, relation := range rels.order {
			built := pbBuildPlan(rels.nodes[relation])
			if !built.ok || built.plan == nil {
				reason := built.reason
				if reason == "" {
					reason = "unsupported rewrite"
				}
				report.skipped = append(report.skipped, fmt.Sprintf("relation %s#%s: %s — skipped", typ, relation, reason))
				continue
			}
			if built.partial {
				report.skipped = append(report.skipped, fmt.Sprintf("relation %s#%s: some union children unsupported and dropped (under-approximated)", typ, relation))
			}
			plans[typ+"\x00"+relation] = built.plan
			report.translated = append(report.translated, fmt.Sprintf("relation %s#%s (%s)", typ, relation, pbDescribePlan(built.plan)))
		}
	}
	typeOf := func(obj string) string {
		if i := strings.Index(obj, ":"); i >= 0 {
			return obj[:i]
		}
		return obj
	}
	objectOfUserset := func(p string) string {
		if i := strings.Index(p, "#"); i >= 0 {
			return p[:i]
		}
		return p
	}
	var holdsRel func(user, obj, relation string, depth int, visited []string) bool
	var evalPlan func(user, obj, relation string, plan *pbPlan, depth int, visited []string) bool
	holdsRel = func(user, obj, relation string, depth int, visited []string) bool {
		key := obj + "\x00" + relation
		if depth > pbMaxDepth {
			return false
		}
		for _, v := range visited {
			if v == key {
				return false
			}
		}
		plan := plans[typeOf(obj)+"\x00"+relation]
		if plan == nil {
			return false
		}
		next := append(append([]string{}, visited...), key)
		return evalPlan(user, obj, relation, plan, depth, next)
	}
	evalPlan = func(user, obj, relation string, plan *pbPlan, depth int, visited []string) bool {
		switch plan.kind {
		case "direct":
			s := direct[obj+"\x00"+relation]
			return s != nil && (s[user] || s[typeOf(user)+":*"])
		case "computed":
			return holdsRel(user, obj, plan.relation, depth+1, visited)
		case "union":
			for _, c := range plan.children {
				if evalPlan(user, obj, relation, c, depth, visited) {
					return true
				}
			}
			return false
		case "intersection":
			for _, c := range plan.children {
				if !evalPlan(user, obj, relation, c, depth, visited) {
					return false
				}
			}
			return true
		case "difference":
			return evalPlan(user, obj, relation, plan.base, depth, visited) && !evalPlan(user, obj, relation, plan.subtract, depth, visited)
		}
		related := direct[obj+"\x00"+plan.tupleset]
		if related == nil {
			return false
		}
		// Python dict (insertion) order only matters for short-circuiting a pure predicate: any() is order-free.
		for p := range related {
			if holdsRel(user, objectOfUserset(p), plan.compute, depth+1, visited) {
				return true
			}
		}
		return false
	}
	sortedUsers := pbSortedKeys(usersSeen)
	for _, obj := range pbSortedKeys(objectsSeen) {
		typ := typeOf(obj)
		rels, has := typeRelations.m[typ]
		if !has {
			report.skipped = append(report.skipped, fmt.Sprintf(`object %s: type "%s" not defined in model — ignored`, obj, typ))
			continue
		}
		relNames := append([]string{}, rels.order...)
		pbSortUnits(relNames)
		for _, relation := range relNames {
			if plans[typ+"\x00"+relation] == nil {
				continue
			}
			for _, user := range sortedUsers {
				if holdsRel(user, obj, relation, 0, nil) {
					predicates = append(predicates, map[string]any{"verb": relation, "resource": obj, "where": []any{map[string]any{"field": "subject.id", "op": "eq", "value": user}}})
				}
			}
			// a public tuple (`type:*`) grants every subject of that type, including ones no tuple names
			for _, wtype := range pbSortedKeys(wildcardTypes) {
				if !holdsRel(wtype+":\x00anyone", obj, relation, 0, nil) {
					continue
				}
				named := []any{}
				for _, u := range sortedUsers {
					if typeOf(u) == wtype {
						named = append(named, u)
					}
				}
				where := []any{map[string]any{"field": "subject.id", "op": "like", "value": pbEscapeGlob(wtype) + ":*"}}
				if len(named) > 0 {
					where = append(where, map[string]any{"not": map[string]any{"field": "subject.id", "op": "in", "value": named}})
				}
				predicates = append(predicates, map[string]any{"verb": relation, "resource": obj, "where": where})
			}
		}
	}
	return pbResult(predicates, []any{}, report)
}

func pbSortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	pbSortUnits(out)
	return out
}

func pbIsWildcard(user string) bool {
	return strings.HasSuffix(user, ":*") && jsLen(user) > 2 && !strings.Contains(user, "#")
}

func pbEscapeGlob(t string) string {
	var sb strings.Builder
	for i := 0; i < len(t); i++ {
		if t[i] == '*' || t[i] == '?' || t[i] == '\\' {
			sb.WriteByte('\\')
		}
		sb.WriteByte(t[i])
	}
	return sb.String()
}

func pbDescribePlan(p *pbPlan) string {
	switch p.kind {
	case "direct":
		return "direct"
	case "computed":
		return "computed " + p.relation
	case "union", "intersection":
		parts := make([]string, len(p.children))
		for i, c := range p.children {
			parts[i] = pbDescribePlan(c)
		}
		return p.kind + "[" + strings.Join(parts, ", ") + "]"
	case "difference":
		return "difference(" + pbDescribePlan(p.base) + " - " + pbDescribePlan(p.subtract) + ")"
	}
	return p.compute + " from " + p.tupleset
}

func pbIsRewrite(v any) bool {
	switch v.(type) {
	case map[string]any, []any:
		return true
	}
	return false
}

func pbHasOwn(o any, k string) bool {
	m, ok := o.(map[string]any)
	if !ok {
		return false
	}
	_, has := m[k]
	return has
}

func pbGetMember(o any, k string) any {
	m, _ := o.(map[string]any)
	return m[k]
}

func pbChildNodes(container any) ([]any, bool) {
	l, ok := pbGetMember(container, "child").([]any)
	return l, ok
}

func pbRelationOf(v any) (string, bool) {
	rel, ok := pbGetMember(v, "relation").(string)
	return rel, ok && len(rel) > 0
}

func pbFail(reason string) pbBuilt { return pbBuilt{reason: reason} }

func pbBuildPlan(node any) pbBuilt {
	switch {
	case pbHasOwn(node, "this"):
		return pbBuilt{ok: true, plan: &pbPlan{kind: "direct"}}
	case pbHasOwn(node, "computedUserset"):
		rel, ok := pbGetMember(pbGetMember(node, "computedUserset"), "relation").(string)
		if !ok || len(rel) == 0 {
			return pbFail("computedUserset without a relation")
		}
		return pbBuilt{ok: true, plan: &pbPlan{kind: "computed", relation: rel}}
	case pbHasOwn(node, "union"):
		children, ok := pbChildNodes(pbGetMember(node, "union"))
		if !ok {
			return pbFail("union without children")
		}
		subs := []*pbPlan{}
		partial := false
		for _, child := range children {
			if !pbIsRewrite(child) {
				partial = true
				continue
			}
			sub := pbBuildPlan(child)
			if !sub.ok || sub.plan == nil {
				partial = true // OR under-approximates safely: drop the unmodeled child
				continue
			}
			if sub.partial {
				partial = true
			}
			subs = append(subs, sub.plan)
		}
		if len(subs) == 0 {
			return pbBuilt{partial: partial, reason: "union with no modeled children"}
		}
		return pbBuilt{ok: true, partial: partial, plan: &pbPlan{kind: "union", children: subs}}
	case pbHasOwn(node, "intersection"):
		children, ok := pbChildNodes(pbGetMember(node, "intersection"))
		if !ok {
			return pbFail("intersection without children")
		}
		subs := []*pbPlan{}
		for _, child := range children {
			if !pbIsRewrite(child) {
				return pbFail("intersection child is not a rewrite")
			}
			sub := pbBuildPlan(child)
			if !sub.ok || sub.plan == nil {
				r := sub.reason
				if r == "" {
					r = "unsupported"
				}
				return pbFail("intersection child unmodeled (" + r + ")")
			}
			subs = append(subs, sub.plan)
		}
		if len(subs) == 0 {
			return pbFail("intersection with no children")
		}
		return pbBuilt{ok: true, plan: &pbPlan{kind: "intersection", children: subs}}
	case pbHasOwn(node, "difference"):
		diff := pbGetMember(node, "difference")
		if !pbIsRewrite(diff) {
			return pbFail("malformed difference")
		}
		baseNode, subNode := pbGetMember(diff, "base"), pbGetMember(diff, "subtract")
		if !pbIsRewrite(baseNode) || !pbIsRewrite(subNode) {
			return pbFail("difference needs both base and subtract")
		}
		base, subtract := pbBuildPlan(baseNode), pbBuildPlan(subNode)
		if !base.ok || base.plan == nil {
			r := base.reason
			if r == "" {
				r = "?"
			}
			return pbFail("difference base unmodeled (" + r + ")")
		}
		if !subtract.ok || subtract.plan == nil {
			r := subtract.reason
			if r == "" {
				r = "?"
			}
			return pbFail("difference subtract unmodeled (" + r + ")")
		}
		return pbBuilt{ok: true, partial: base.partial || subtract.partial, plan: &pbPlan{kind: "difference", base: base.plan, subtract: subtract.plan}}
	case pbHasOwn(node, "tupleToUserset"):
		ttu := pbGetMember(node, "tupleToUserset")
		if !pbIsRewrite(ttu) {
			return pbFail("malformed tupleToUserset")
		}
		tupleset, ok1 := pbRelationOf(pbGetMember(ttu, "tupleset"))
		computed, ok2 := pbRelationOf(pbGetMember(ttu, "computedUserset"))
		if !ok1 {
			return pbFail("tupleToUserset without a tupleset relation")
		}
		if !ok2 {
			return pbFail("tupleToUserset without a computedUserset relation")
		}
		return pbBuilt{ok: true, plan: &pbPlan{kind: "ttu", tupleset: tupleset, compute: computed}}
	}
	return pbFail("unknown rewrite node")
}

// pbParseModel returns the ordered type -> relations map, or nil when the model is unusable (the report says why).
func pbParseModel(model any, report *pbReport) *pbOrdered {
	if !pbIsRewrite(model) {
		report.errors = append(report.errors, "model is not an object")
		return nil
	}
	defs, ok := pbGetMember(model, "type_definitions").([]any)
	if !ok {
		report.errors = append(report.errors, "model.type_definitions is missing or not an array")
		return nil
	}
	out := &pbOrdered{m: map[string]*pbRelSet{}}
	for _, d := range defs {
		if !pbIsRewrite(d) {
			continue
		}
		t, ok := pbGetMember(d, "type").(string)
		if !ok || len(t) == 0 {
			continue
		}
		rs := &pbRelSet{nodes: map[string]any{}}
		if entries, ok := pbEntries(pbGetMember(d, "relations")); ok {
			for _, e := range entries {
				if pbIsRewrite(e.v) {
					rs.nodes[e.k] = e.v
					rs.order = append(rs.order, e.k)
				}
			}
		}
		if _, seen := out.m[t]; !seen {
			out.keys = append(out.keys, t)
		}
		out.m[t] = rs
	}
	return out
}

func pbParseTuples(tuples any, report *pbReport, given bool) []map[string]string {
	l, ok := tuples.([]any)
	if !ok {
		if given {
			report.errors = append(report.errors, "tuples is not an array")
		}
		return nil
	}
	out := []map[string]string{}
	for _, t := range l {
		m, isMap := t.(map[string]any)
		if !isMap {
			continue
		}
		user, ok1 := m["user"].(string)
		relation, ok2 := m["relation"].(string)
		obj, ok3 := m["object"].(string)
		if ok1 && ok2 && ok3 {
			out = append(out, map[string]string{"user": user, "relation": relation, "object": obj})
		}
	}
	return out
}

// ---- decide ----

func pbEvaluate(predicates any, ctx map[string]any) (res map[string]any) {
	defer func() {
		if recover() != nil {
			res = map[string]any{"allowed": false, "reason": "predicate evaluation error (fail closed)"}
		}
	}()
	arr, ok := predicates.([]any)
	if !ok || len(arr) == 0 {
		return map[string]any{"allowed": false, "reason": "envelope grants no predicates"}
	}
	b := &regexBudget{}
	for _, p := range arr {
		if predicateMatches(p, ctx, b) {
			return map[string]any{"allowed": true, "matched": p}
		}
	}
	a, _ := ctx["action"].(map[string]any)
	tail := " for " + jsMemberString(a, "verb") + " on " + jsMemberString(a, "resource")
	if limit, found := firstUnmetLimit(arr, ctx, b); found {
		return map[string]any{"allowed": false, "reason": limit + " not satisfied" + tail}
	}
	return map[string]any{"allowed": false, "reason": "no predicate permits " + jsMemberString(a, "verb") + " on " + jsMemberString(a, "resource")}
}

// pbLength is `x.length` of an array or string; ok false for anything else, an error for null (a TypeError).
func pbLength(x any) (n int, ok bool, err error) {
	switch t := x.(type) {
	case nil:
		return 0, false, fmt.Errorf("cannot read properties of null (reading 'length')")
	case []any:
		return len(t), true, nil
	case string:
		return jsLen(t), true, nil
	}
	return 0, false, nil
}

func pbTruthy(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case bool:
		return t
	case string:
		return t != ""
	}
	if f, ok := jsNum(v); ok {
		return f != 0 && f == f
	}
	return true
}

// PolicyBridgeDecide decides one action under a translation with deny-overrides-permit (Cedar's combining rule). An
// incomplete translation (report.errors non-empty) denies everything.
func PolicyBridgeDecide(result map[string]any, ctx map[string]any) (map[string]any, error) {
	if report := result["report"]; pbTruthy(report) {
		rm, isMap := report.(map[string]any)
		if !isMap {
			return nil, fmt.Errorf("cannot read properties of undefined (reading 'length')")
		}
		errs, has := rm["errors"]
		if !has {
			return nil, fmt.Errorf("cannot read properties of undefined (reading 'length')")
		}
		n, ok, err := pbLength(errs)
		if err != nil {
			return nil, err
		}
		if ok && n > 0 {
			return map[string]any{"allowed": false, "reason": "translation incomplete (fail closed)"}, nil
		}
	}
	denies, has := result["denies"]
	if !has {
		return nil, fmt.Errorf("cannot read properties of undefined (reading 'length')")
	}
	n, ok, err := pbLength(denies)
	if err != nil {
		return nil, err
	}
	if ok && n > 0 {
		denied := pbEvaluate(denies, ctx)
		if denied["allowed"] == true {
			return map[string]any{"allowed": false, "matched": denied["matched"], "reason": "forbidden by deny policy"}, nil
		}
	}
	return pbEvaluate(result["predicates"], ctx), nil
}
