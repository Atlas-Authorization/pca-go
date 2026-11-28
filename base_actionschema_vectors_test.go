package pca

import (
	"strings"
	"testing"
)

// Replay of the rule-14 action schema corpus against the reference (base-actionschema, 16139 cases): the v1 and v2 shape of signed
// and unsigned documents, the confirmation and floors shapes, the value check of every declared parameter type and format, and the
// format checkers. Reasons compare exactly, except where the corpus records the same refusal with another wording: the
// canonicalizer's own refusals (compared by their family) and the four parameter refusals that carry the bound in the reference only.

func TestBaseActionSchemaMatchesTheReference(t *testing.T) {
	const canonFamily = "malformed schema: canonicalize: "
	shapeCmp := func(want, got any) bool {
		if w, ok := want.(string); ok && strings.HasPrefix(w, canonFamily) {
			g, _ := got.(string)
			return strings.HasPrefix(g, canonFamily)
		}
		return baseCanon(want) == baseCanon(got)
	}
	fns := map[string]vecFn{
		"shape":         func(a []any) (any, error) { return killReason(ActionSchemaShapeError(vecArg(a, 0), true)), nil },
		"shapeUnsigned": func(a []any) (any, error) { return killReason(ActionSchemaShapeError(vecArg(a, 0), false)), nil },
		"confirmation":  func(a []any) (any, error) { return killReason(ConfirmationShapeError(vecArg(a, 0))), nil },
		"floors":        func(a []any) (any, error) { return killReason(SchemaFloorsError(vecArg(a, 0))), nil },
		"pvv": func(a []any) (any, error) {
			d, _ := vecArg(a, 0).(map[string]any)
			code, reason := paramValueViolationReason(d, vecArg(a, 1))
			if code == "" {
				return nil, nil
			}
			return map[string]any{"code": code, "reason": reason}, nil
		},
		"format": func(a []any) (any, error) {
			f := FormatCheck(rsStr(vecArg(a, 0)))
			if f == nil {
				return "unknown", nil
			}
			return f(rsStr(vecArg(a, 1))), nil
		},
	}
	cmp := map[string]func(want, got any) bool{
		"shape":         shapeCmp,
		"shapeUnsigned": shapeCmp,
		"pvv": func(want, got any) bool {
			w, g := vecObj(want), vecObj(got)
			if w == nil || g == nil {
				return baseCanon(want) == baseCanon(got)
			}
			return w["code"] == g["code"] && killBoundless(rsStr(w["reason"])) == killBoundless(rsStr(g["reason"]))
		},
	}
	replayAll(t, "base-actionschema.json.gz", 16139, fns, cmp, nil)
}
