package pca

// The undo engine: for a confirmed, reversible write whose confirmed compensating action can undo it, the plan that names the
// compensating call (verb, copied parameters, the parameter that names the target), the approval render of the original call and
// its digest. Anything unconfirmed, read-only, irreversible for this call or without a fitting compensation has no plan.

// ActionUndoConfirmedFrom is the attestation check over pinned reviewer keys (nil pins = nothing is confirmed).
func ActionUndoConfirmedFrom(pins any, reg Registry) ActionDiffConfirmed {
	if pins == nil {
		return nil
	}
	return func(d map[string]any) bool { return defConfirmed(d, reg, pins) }
}

// ActionUndoPlan is the undo plan for op {verb, params} over defs, or nil. It never panics: any failure is "no plan".
func ActionUndoPlan(defs []any, pins any, op map[string]any) map[string]any {
	return actionUndoPlanIn(defs, pins, op, coreRegistry)
}

// actionUndoPlanIn is ActionUndoPlan over a given trait registry.
func actionUndoPlanIn(defs []any, pins any, op map[string]any, reg Registry) (plan map[string]any) {
	defer func() {
		if recover() != nil {
			plan = nil
		}
	}()
	byVerb := map[string]map[string]any{}
	for _, x := range defs {
		d, _ := x.(map[string]any)
		v := jsAnyString(d["verb"])
		if _, has := byVerb[v]; !has {
			byVerb[v] = d
		}
	}
	review := ActionUndoConfirmedFrom(pins, reg)
	confirmed := func(d map[string]any) (ok bool) {
		defer func() {
			if recover() != nil {
				ok = false
			}
		}()
		return review != nil && review(d)
	}
	d := byVerb[jsAnyString(op["verb"])]
	params, _ := op["params"].(map[string]any)
	if params == nil {
		params = map[string]any{}
	}
	if d == nil || !confirmed(d) || isReadOnlyEffects(adStrs(d, "effects")) {
		return nil
	}
	compVerb, hasComp := d["compensates"]
	if !hasComp {
		return nil
	}
	eff, err := adEffective(d, reg, review)
	if err != nil || eff.eff.Rev != "reversible" || undoReversibilityFor(d, params) != "reversible" {
		return nil
	}
	c := byVerb[jsAnyString(compVerb)]
	if c == nil || !confirmed(c) {
		return nil
	}
	s := ActionCompensationShape(d, c)
	if s["ok"] != true {
		return nil
	}
	shape := s["shape"].(map[string]any)
	cparams := map[string]any{}
	ncp := adParamsOf(normalizeDef(c))
	copied, _ := strsOf(shape["copied"])
	for _, k := range copied {
		if v, has := params[k]; has {
			cparams[k] = deepCopy(v)
		} else if p, _ := ncp[k].(map[string]any); p["required"] == true {
			return nil // the call left out what the undo needs
		}
	}
	render, err := ActionRenderApproval(d, params, review)
	if err != nil {
		return nil
	}
	dg, err := defDigest(d)
	if err != nil {
		return nil
	}
	cdg, err := defDigest(c)
	if err != nil {
		return nil
	}
	rd, err := ApprovalRenderDigest(render)
	if err != nil {
		return nil
	}
	comp := map[string]any{"verb": c["verb"], "params": cparams, "def_digest": cdg}
	if t, has := shape["target"]; has {
		comp["target_param"] = t
	}
	return map[string]any{"def_digest": dg, "compensation": comp, "render": render, "render_digest": rd}
}
