package pca

// The lattice of a task learner under ceiling layers: effective, uncertain and ceiling cells, the layered decision for one outcome,
// and the org layer built from the org approvers' maps.

// IntentLatticeView is the lattice of a task learner under ceiling admitters (see ixCeilingAdmitters): {effective, uncertain, ceiling}.
func IntentLatticeView(task *IntentLearner, ceilings map[string]*IntentAdmitter) (map[string]any, error) {
	r, err := ixTry(func() any {
		eff, unc, ceil := []any{}, []any{}, []any{}
		for _, cv := range task.Cells() {
			c := ixM(cv)
			vs := ixMaFindVerb(task.omega, c["verb"])
			if vs == nil {
				ixFail("no verb space")
			}
			if layer := ixCeilingOf(ceilings, vs, ixCellRep(vs, ixL(c["cell"]))); layer != nil {
				ceil = append(ceil, map[string]any{"verb": c["verb"], "cell": c["cell"], "layer": layer})
				continue
			}
			if c["vetoed"] == true {
				continue
			}
			p := ixF(c["p"])
			if c["inGrant"] == true {
				eff = append(eff, map[string]any{"verb": c["verb"], "cell": c["cell"]})
			} else if p > 1e-12 && p < task.tau-1e-12 {
				unc = append(unc, map[string]any{"verb": c["verb"], "cell": c["cell"]})
			}
		}
		return map[string]any{"effective": eff, "uncertain": unc, "ceiling": ceil}
	})
	if err != nil {
		return nil, err
	}
	return r.(map[string]any), nil
}

// IntentDecideOutcomeLayers is the layered decision for one outcome of a task learner.
func IntentDecideOutcomeLayers(task *IntentLearner, ceilings map[string]*IntentAdmitter, o map[string]any) map[string]any {
	vs := ixMaFindVerb(task.omega, o["verb"])
	if vs == nil {
		return map[string]any{"decision": "intent_denied"}
	}
	if layer := ixCeilingOf(ceilings, vs, o); layer != nil {
		return map[string]any{"decision": "ceiling", "layer": layer}
	}
	if task.IsVetoed(o) || task.Acceptance(o) <= 1e-12 {
		return map[string]any{"decision": "intent_denied"}
	}
	if task.AdmitsOutcome(o) {
		return map[string]any{"decision": "admit", "by": 0.0}
	}
	return map[string]any{"decision": "intent_required"}
}

// IntentOrgLayerFromMaps is the joint grant of the org approvers' maps under the org's rule: {map, policy}.
func IntentOrgLayerFromMaps(maps []any, rule any) (map[string]any, error) {
	m, err := IntentAggregateMaps(maps, rule, nil)
	if err != nil {
		return nil, err
	}
	return map[string]any{"map": m, "policy": m["grant"]}, nil
}

// IntentCeilingAdmitters compiles ceiling layers into admitters; a malformed ceiling is an error.
func IntentCeilingAdmitters(layers any) (c map[string]*IntentAdmitter, err error) {
	r, err := ixTry(func() any { return ixCeilingAdmitters(layers) })
	if err != nil {
		return nil, err
	}
	return r.(map[string]*IntentAdmitter), nil
}
