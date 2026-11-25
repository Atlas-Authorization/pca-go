package pca

// Stable JSON and canonical Goal order (the TypeScript reference is @atlasauth/pca-goal `normalize`).

import (
	"sort"
	"strings"
	"unicode/utf16"
)

// goalNormalizeU16Cmp orders strings by UTF-16 code units (a lone surrogate kept as WTF-8 is one unit).
func goalNormalizeU16Cmp(a, b string) int { return compareUnits(utf16Units(a), utf16Units(b)) }

// goalJq is JSON.stringify of a value; a string's lone surrogates are escaped (well-formed JSON.stringify).
func goalJq(v any) string {
	s, ok := v.(string)
	if !ok {
		return anlJSON(v)
	}
	const hexd = "0123456789abcdef"
	u := utf16Units(s)
	var sb strings.Builder
	sb.WriteByte('"')
	for i := 0; i < len(u); i++ {
		c := u[i]
		switch {
		case c == '"':
			sb.WriteString(`\"`)
		case c == '\\':
			sb.WriteString(`\\`)
		case c == '\b':
			sb.WriteString(`\b`)
		case c == '\f':
			sb.WriteString(`\f`)
		case c == '\n':
			sb.WriteString(`\n`)
		case c == '\r':
			sb.WriteString(`\r`)
		case c == '\t':
			sb.WriteString(`\t`)
		case c < 0x20:
			sb.WriteString(`\u00`)
			sb.WriteByte(hexd[c>>4])
			sb.WriteByte(hexd[c&15])
		case c >= 0xD800 && c <= 0xDBFF && i+1 < len(u) && u[i+1] >= 0xDC00 && u[i+1] <= 0xDFFF:
			sb.WriteRune(utf16.DecodeRune(rune(c), rune(u[i+1])))
			i++
		case c >= 0xD800 && c <= 0xDFFF:
			sb.WriteString(`\u`)
			sb.WriteByte(hexd[c>>12])
			sb.WriteByte(hexd[(c>>8)&15])
			sb.WriteByte(hexd[(c>>4)&15])
			sb.WriteByte(hexd[c&15])
		default:
			sb.WriteRune(rune(c))
		}
	}
	sb.WriteByte('"')
	return sb.String()
}

// goalStable is sorted-key JSON, undefined members dropped: an in-memory key for maps and sets, NOT a signed encoding.
func goalStable(v any) string {
	switch t := v.(type) {
	case []any:
		parts := make([]string, len(t))
		for i, x := range t {
			if !anlIsUndef(x) {
				parts[i] = goalStable(x)
			}
		}
		return "[" + strings.Join(parts, ",") + "]"
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k, x := range t {
			if !anlIsUndef(x) {
				keys = append(keys, k)
			}
		}
		sort.Slice(keys, func(i, j int) bool { return goalNormalizeU16Cmp(keys[i], keys[j]) < 0 })
		parts := make([]string, len(keys))
		for i, k := range keys {
			parts[i] = goalJq(k) + ":" + goalStable(t[k])
		}
		return "{" + strings.Join(parts, ",") + "}"
	}
	return goalJq(v)
}

// goalNormalizeSortBy is a stable sort of an array by the string member `field` (code-unit order); non-strings compare equal.
func goalNormalizeSortBy(xs any, field string) []any {
	out := append([]any(nil), anlReqList(xs)...)
	sort.SliceStable(out, func(i, j int) bool {
		x, y := anlGet(out[i], field), anlGet(out[j], field)
		xs, xok := x.(string)
		ys, yok := y.(string)
		return xok && yok && goalNormalizeU16Cmp(xs, ys) < 0
	})
	return out
}

// goalNormalizeSortedUnique is [...new Set(xs)].sort(): de-duplicated, ordered by the string form in code-unit order.
func goalNormalizeSortedUnique(xs any) []any {
	l, ok := xs.([]any)
	if !ok {
		anlFail("not iterable")
	}
	u := []any{}
	for _, x := range l {
		switch x.(type) {
		case map[string]any, []any:
			anlFail("unhashable member")
		}
		dup := false
		for _, y := range u {
			if anlStrictEq(x, y) {
				dup = true
				break
			}
		}
		if !dup {
			u = append(u, x)
		}
	}
	sort.SliceStable(u, func(i, j int) bool { return goalNormalizeU16Cmp(anlJS(u[i]), anlJS(u[j])) < 0 })
	return u
}

// goalCanonicalizeGoal puts grants, prohibits, bounds and holes strictly increasing by id (code-unit order) and wildcardAck /
// mayTouch sorted and de-duplicated. Duplicated ids are NOT merged: they stay and the typechecker refuses them.
func goalCanonicalizeGoal(g any) map[string]any {
	out := anlSpread(g)
	out["grants"] = goalNormalizeSortBy(anlGet(g, "grants"), "gid")
	out["prohibits"] = goalNormalizeSortBy(anlGet(g, "prohibits"), "pid")
	out["bounds"] = goalNormalizeSortBy(anlGet(g, "bounds"), "bid")
	out["holes"] = goalNormalizeSortBy(anlGet(g, "holes"), "hid")
	out["wildcardAck"] = goalNormalizeSortedUnique(anlGet(g, "wildcardAck"))
	d := anlSpread(anlGet(g, "deleg"))
	d["mayTouch"] = goalNormalizeSortedUnique(anlGet(anlGet(g, "deleg"), "mayTouch"))
	out["deleg"] = d
	return out
}

// GoalStable is the stable JSON of a value.
func GoalStable(v any) string { return goalStable(v) }

// GoalCanonicalizeGoal is the canonical form of a Goal.
func GoalCanonicalizeGoal(g any) (r map[string]any, err error) {
	_, err = anlTry(func() any { r = goalCanonicalizeGoal(g); return nil })
	return
}
