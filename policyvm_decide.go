package pca

// The policy decision engine over a policy model: the exact admission check of a fully-specified action (the ternary decision
// 'allow' | 'escalate' | 'deny') that AuthZEN evaluation takes as its default `admitsConcrete`. The engine evaluates the real
// predicate evaluator, the vetoes (deny / approval), the tighten rules and the `meet` chain over a policy given as a plain JSON
// tree ({predicates, caveats?, vetoes?, tighten?, meet?}); a value that is not a policy admits nothing.

// PolicyVMModel is the analyzable model of a policy: {predicates, caveats, vetoes, tighten, meets, caveatSat, caveatReason?, revCap?,
// undecidable}. A malformed policy tree yields an error rather than a model.
func PolicyVMModel(policy any) (model map[string]any, err error) {
	r, err := anlTry(func() any { return anlToModel(policy) })
	if err != nil {
		return nil, err
	}
	return r.(map[string]any), nil
}

// PolicyVMDecide is the ternary decision of an action {verb, resource, params?, reversibilityClass?, subject?, env?} under a
// policy ("deny" when the caveats are unsatisfiable, the reversibility cap is exceeded, no predicate permits, or a veto denies).
func PolicyVMDecide(policy any, action any) (string, error) {
	r, err := anlTry(func() any { return anlDecideAction(anlToModel(policy), action) })
	if err != nil {
		return "deny", err
	}
	return r.(string), nil
}

// PolicyVMAdmitsConcrete reports whether the policy admits the fully-specified action (anything but a deny); an error means the
// reference would have thrown, and callers must treat it as a refusal.
func PolicyVMAdmitsConcrete(policy any, action any) (bool, error) {
	r, err := anlTry(func() any { return anlAdmitsConcrete(policy, action) })
	if err != nil {
		return false, err
	}
	return r.(bool), nil
}
