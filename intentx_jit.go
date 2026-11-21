package pca

// Lazy just-in-time elicitation, the pure parts: the cell coordinates carried by a signed `pca-intent-required` notice and
// its site-side body.

const ixIntentActionDomain = "atlas-pca/intent-action/v1"

// ixCellCoords is the coordinates of one cell (numeric: [i, i]; categorical: the cell's value). Never text about the value.
func ixCellCoords(vs map[string]any, cell []any) map[string]any {
	out := map[string]any{}
	for k, dv := range ixL(vs["dims"]) {
		d := ixM(dv)
		if k >= len(cell) {
			ixFail("cell index missing")
		}
		if ixS(d["kind"]) == "num" {
			out[ixS(d["path"])] = []any{cell[k], cell[k]}
		} else {
			vals := ixL(d["values"])
			i := ixIdx(cell[k])
			if i < 0 || i >= len(vals) {
				ixFail("cell index out of range")
			}
			out[ixS(d["path"])] = []any{ixM(vals[i])["value"]}
		}
	}
	return out
}

// ixCellFromCoords is the inverse of ixCellCoords for one cell; nil when the coordinates do not name one.
func ixCellFromCoords(vs map[string]any, coordsV any) any {
	coords, ok := coordsV.(map[string]any)
	dims := ixL(vs["dims"])
	if !ok || len(coords) != len(dims) {
		return nil
	}
	out := []any{}
	for _, dv := range dims {
		d := ixM(dv)
		c, ok := coords[ixS(d["path"])].([]any)
		if !ok {
			return nil
		}
		if ixS(d["kind"]) == "num" {
			if len(c) < 2 {
				return nil
			}
			f, isNum := jsNum(c[0]) // a coordinate is a JS number, whether it was decoded as a float or kept as a JSON number
			if !isNum || !jsStrictEq(c[0], c[1]) {
				return nil
			}
			out = append(out, f)
			continue
		}
		s, ok := ixArg(c, 0).(string)
		if len(c) != 1 || !ok {
			return nil
		}
		i := -1
		for k, v := range ixL(d["values"]) {
			if ixM(v)["value"] == s {
				i = k
				break
			}
		}
		if i < 0 {
			return nil
		}
		out = append(out, float64(i))
	}
	return out
}

// ixIntentActionDigest is the action digest a JIT consent is bound to.
func ixIntentActionDigest(action map[string]any) string {
	a := map[string]any{}
	for _, k := range []string{"verb", "resource", "params_digest", "reversibility_class"} {
		a[k] = ixReq(action, k)
	}
	return ixHashCanon(map[string]any{"d": ixIntentActionDomain, "action": a})
}

// ixIntentRequiredBody is the site's `pca-intent-required` body for a visited uncertain cell (sign it with the core).
func ixIntentRequiredBody(i map[string]any) map[string]any {
	pcactn := ixM(ixReq(i, "pcactn"))
	vs := ixM(ixReq(i, "vs"))
	return map[string]any{"v": 1.0, "kind": "pca-intent-required", "session": ixReq(i, "session"), "map_digest": ixReq(i, "mapDigest"),
		"schema": ixReq(i, "schemaDigest"), "pcactn_digest": ixHashCanon(pcactn),
		"action_digest": ixIntentActionDigest(ixM(ixReq(pcactn, "action"))),
		"cell":          map[string]any{"verb": vs["verb"], "coords": ixCellCoords(vs, ixL(ixReq(i, "cell")))},
		"reason":        "uncertain", "question_id": ixReq(i, "questionId"), "friction": ixReq(i, "friction"),
		"delivered_to": ixReq(i, "deliveredTo"), "expires_at": ixReq(i, "expiresAt")}
}
