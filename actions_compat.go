package pca

// Bridges from the legacy action catalog (reversibility classes, a float blast radius, an amount field) to action definitions.

import (
	"math"
	"regexp"
	"unicode/utf16"
)

// ActionNormalizeReversibility maps a legacy or current reversibility class to the current three; anything else is irreversible.
func ActionNormalizeReversibility(x any) string {
	switch x {
	case "reversible", "read":
		return "reversible"
	case "rate_limited", "costly":
		return "rate_limited"
	}
	return "irreversible"
}

// ActionLegacyOperationsClass is the legacy operations name of a class (rate_limited = costly).
func ActionLegacyOperationsClass(r string) string {
	if r == "rate_limited" {
		return "costly"
	}
	return r
}

// ActionMaxRev is the worse of two classes (an unknown class never wins a tie, as in the reference).
func ActionMaxRev(a, b string) string {
	ra, oka := revRank[a]
	rb, okb := revRank[b]
	if oka && okb && ra >= rb {
		return a
	}
	return b
}

// ActionUnitTag is the legacy unit tag of a unit declaration; nil for a money unit without a string currency.
func ActionUnitTag(u map[string]any) map[string]any {
	if u["kind"] != "money" {
		return map[string]any{"kind": u["kind"]}
	}
	ccy, ok := u["ccy"].(string)
	if !ok {
		return nil
	}
	out := map[string]any{"kind": "money", "currency": ccy}
	if e, has := u["exp"]; has {
		out["exponent"] = e
	}
	return out
}

var actionBlastRadii = []string{"one", "bounded", "tenant", "global"}

func compatPPM(x any) int {
	f := 1.0
	if v, ok := jsNum(x); ok && !math.IsNaN(v) && !math.IsInf(v, 0) {
		f = v
	}
	p := f * 1_000_000
	r := math.Floor(p)
	if p-r >= 0.5 { // Math.round: halves round up
		r++
	}
	return int(math.Min(ppmMax, math.Max(0, r)))
}

// ActionBlastOfFloat is the smallest radius whose ppm covers the float blast (a non-finite blast is 1).
func ActionBlastOfFloat(x any) map[string]any {
	ppm := compatPPM(x)
	radius := "global"
	for _, r := range actionBlastRadii {
		if blastPPM[r] >= ppm {
			radius = r
			break
		}
	}
	return map[string]any{"radius": radius, "ppm": jsNumber(float64(ppm))}
}

// ActionBlastExactOfFloat is the largest radius whose ppm the float blast reaches.
func ActionBlastExactOfFloat(x any) map[string]any {
	ppm := compatPPM(x)
	radius := "one"
	for i := len(actionBlastRadii) - 1; i >= 0; i-- {
		if blastPPM[actionBlastRadii[i]] <= ppm {
			radius = actionBlastRadii[i]
			break
		}
	}
	return map[string]any{"radius": radius, "ppm": jsNumber(float64(ppm))}
}

var (
	compatReadRe   = regexp.MustCompile(`^(read|get|list|view|search|fetch|head)(_|$)`)
	compatDeleteRe = regexp.MustCompile(`(^|_)(delete|remove|destroy|drop|purge)(_|$)`)
	compatSendRe   = regexp.MustCompile(`(^|_)(send|post|publish|notify|email|sms)(_|$)`)
)

// ActionFromCatalogSpec is the action definition of a legacy catalog spec {connector, action, verb, reversibility, blastRadius,
// amountField?, resource?, description}; o carries ccy (USD), exp (2) and maxAmount (1e11) for the amount parameter.
func ActionFromCatalogSpec(s, o map[string]any) map[string]any {
	action := jsAnyString(s["action"])
	av, hasAmount := s["amountField"] // any present value counts as declared (null included)
	amountField := jsAnyString(av)
	effects := []any{}
	if hasAmount {
		effects = append(effects, "pay")
	}
	if compatReadRe.MatchString(action) {
		effects = append(effects, "read")
	}
	if compatDeleteRe.MatchString(action) {
		effects = append(effects, "delete")
	}
	if compatSendRe.MatchString(action) {
		effects = append(effects, "send")
	}
	if len(effects) == 0 {
		effects = append(effects, "update")
	}
	params := map[string]any{}
	if hasAmount {
		maxAmount := any(jsNumber(100_000_000_000))
		if v, has := o["maxAmount"]; has && v != nil {
			maxAmount = v
		}
		ccy, exp := any("USD"), any(jsNumber(2))
		if v, has := o["ccy"]; has && v != nil {
			ccy = v
		}
		if v, has := o["exp"]; has && v != nil {
			exp = v
		}
		params[amountField] = map[string]any{"type": "integer", "role": "money.amount", "min": jsNumber(0), "max": maxAmount,
			"unit": map[string]any{"kind": "money", "ccy": ccy, "exp": exp}}
		params["idempotency_key"] = map[string]any{"type": "string", "max_len": jsNumber(128)}
	}
	b := ActionBlastOfFloat(s["blastRadius"])
	res, hasRes := s["resource"]
	wildcard := !hasRes || res == nil || res == "*"
	desc := jsAnyString(s["description"])
	title := desc
	if u := utf16.Encode([]rune(desc)); len(u) > 120 {
		title = string(utf16.Decode(u[:117])) + "..."
	}
	var id any = "*"
	scope := "set"
	if !wildcard {
		id = map[string]any{"prefix": "", "class": "any_safe", "len": []any{jsNumber(1), jsNumber(128)}}
		scope = "one"
	}
	out := map[string]any{
		"v": jsNumber(1), "kind": "pca-action-def", "verb": s["verb"], "title": title, "description": s["description"], "effects": effects,
		"resource":      map[string]any{"type": s["connector"], "id": id, "scope": scope},
		"params":        params,
		"reversibility": ActionNormalizeReversibility(s["reversibility"]),
		"blast":         map[string]any{"radius": b["radius"], "ppm": b["ppm"]},
		"review":        map[string]any{"state": "authored"},
	}
	if hasAmount {
		out["idempotency"] = map[string]any{"mode": "key_param", "param": "idempotency_key"}
	}
	return out
}
