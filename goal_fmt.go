package pca

// Rendering helpers for quantities, values and actions (the TypeScript reference is @atlasauth/pca-goal `fmt`).

import (
	"fmt"
	"strings"
	"unicode/utf16"
)

// goalCcyExponent: an unknown currency is shown in raw minor units, never guessed.
var goalCcyExponent = map[string]int{"USD": 2, "EUR": 2, "GBP": 2, "CAD": 2, "AUD": 2, "CHF": 2, "JPY": 0, "KRW": 0}

func goalFmtMoney(ccy, minor any) string {
	e, known := 0, false
	if s, ok := ccy.(string); ok {
		e, known = goalCcyExponent[s]
	}
	if !known {
		return fmt.Sprintf("%s %s (minor units)", anlJS(ccy), anlJS(minor))
	}
	if e == 0 {
		return fmt.Sprintf("%s %s", anlJS(ccy), anlJS(minor))
	}
	u := utf16Units(anlJS(minor))
	for len(u) < e+1 {
		u = append([]uint16{'0'}, u...)
	}
	cut := len(u) - e
	return fmt.Sprintf("%s %s.%s", anlJS(ccy), string(utf16.Decode(u[:cut])), string(utf16.Decode(u[cut:])))
}

// goalFmtQuantity is the rendered text; anlUndef (JavaScript undefined) for an unknown unit tag.
func goalFmtQuantity(q any) any {
	u := anlGet(q, "u")
	k := anlGet(u, "k")
	n := anlGet(q, "n")
	switch k {
	case "money":
		return goalFmtMoney(anlGet(u, "ccy"), n)
	case "count":
		return anlJS(n)
	case "duration":
		return anlJS(n) + "ms"
	case "instant":
		return "@" + anlJS(n)
	case "bytes":
		return anlJS(n) + "B"
	case "ratio":
		return anlJS(n) + "ppm"
	}
	return anlUndef
}

func goalFmtValue(v any) any {
	switch anlGet(v, "k") {
	case "q":
		return goalFmtQuantity(anlGet(v, "q"))
	case "s":
		s := anlGet(v, "s")
		if anlIsUndef(s) {
			return anlUndef
		}
		return goalJq(s)
	}
	items := anlReqList(anlGet(v, "items"))
	parts := make([]string, len(items))
	for i, it := range items {
		if s, ok := goalFmtValue(it).(string); ok {
			parts[i] = s
		}
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

func goalFmtAct(a any) string {
	params := anlGet(a, "params")
	keys := goalSortU16(goalOkeys(params))
	ps := make([]string, len(keys))
	for i, k := range keys {
		ps[i] = k + "=" + anlJS(goalFmtValue(goalOget(params, k)))
	}
	suffix := ""
	if len(ps) > 0 {
		suffix = " (" + strings.Join(ps, ", ") + ")"
	}
	return fmt.Sprintf("%s on %s%s", anlJS(anlGet(a, "verb")), anlJS(anlGet(a, "res")), suffix)
}
