package pca

import (
	"strings"
)

// The native Policy VM decision `decide(input)`: the release decision of one party's own policy (envelope predicates, caveats over
// the delegation chain, risk score, trust budget, threshold band). Steps 3-5 are DecideRisk; this file is the glue the reference
// runs before them. Total: any internal error is a fail-closed denial.

func decideDenied(reason string, budget any) map[string]any {
	return map[string]any{
		"releaseGuardianShare": false,
		"requiredThreshold":    map[string]any{"t": jsNumber(3), "proof": "strong", "optimisticAllowed": false},
		"r":                    jsNumber(1),
		"admit":                false,
		"needStepUp":           true,
		"reasons":              []any{reason},
		"budget":               budget,
	}
}

func decideFin(v any) (float64, bool) {
	f, ok := jsNum(v)
	return f, ok && riskFinite(f)
}

// DecideNative is the Policy VM `decide` over a parsed JSON input: grant, chain?, action, plan?, risk, budget, now, nodeId?,
// goalNodeId?, caveatContext?, rFloor?, ageHorizonMs?, chainVerified?, pqPins?, trustedRoot?. k1 is the caveat-language input
// (nil = none: a chain carrying a caveat-language type is then refused). The result has releaseGuardianShare, requiredThreshold,
// r, admit, needStepUp, reasons and budget (and k1Bound when the caveat language ran). Never panics.
func DecideNative(input map[string]any, k1 *K1Input) (out map[string]any) {
	fallback, has := input["budget"]
	if !has || fallback == nil {
		fallback = map[string]any{"B": jsNumber(0), "tau": jsNumber(0)}
	}
	defer func() {
		if r := recover(); r != nil {
			msg := "unknown"
			if e, ok := r.(error); ok && e.Error() != "" {
				msg = e.Error()
			} else if s, ok := r.(string); ok && s != "" {
				msg = s
			}
			out = decideDenied("policy evaluation error (fail closed): "+msg, fallback)
		}
	}()
	return decideInner(input, k1, fallback)
}

func decideInner(in map[string]any, k1in *K1Input, fallback any) map[string]any {
	budgetIn := in["budget"]
	grant, _ := in["grant"].(map[string]any)
	env := ReadEnvelope(in["grant"])
	if env == nil {
		return decideDenied("grant carries no valid envelope", budgetIn)
	}
	now, ok := decideFin(in["now"])
	if !ok {
		return decideDenied("invalid decision time", budgetIn)
	}
	chainV, hasChain := in["chain"]
	chain, chainIsList := chainV.([]any)

	// an unverified capability chain is denied here: unless the caller vouches it was verified, decide re-verifies it
	if in["chainVerified"] != true {
		toVerify := []any{in["grant"]}
		if chainIsList && len(chain) > 0 {
			toVerify = chain
		}
		issuer, isStr := grant["issuer"].(string)
		var pins map[string]string
		if pm, ok := in["pqPins"].(map[string]any); ok {
			pins = map[string]string{}
			for k, v := range pm {
				s, _ := v.(string)
				pins[k] = s
			}
		}
		trusted, _ := in["trustedRoot"].(map[string]any)
		if why, ok := VerifyChainPolicy(toVerify, issuer, isStr, nil, pins, trusted); !ok {
			return decideDenied("capability chain unverified: "+why, budgetIn)
		}
	}

	pol, ok := RiskPolicyOf(env["risk_policy"])
	if !ok {
		return decideDenied("grant carries no valid envelope", budgetIn)
	}
	b := &regexBudget{} // one regex budget for the whole decision
	var reasons []any
	actionCtx, _ := in["action"].(map[string]any)
	if actionCtx == nil {
		actionCtx = map[string]any{}
	}
	inner, _ := actionCtx["action"].(map[string]any)

	// 1. semantic predicates (default deny)
	prOK, why := envelopePredicates(env["predicates"], actionCtx, b)
	if !prOK {
		reasons = append(reasons, why)
	}

	nodeID, hasNode := in["nodeId"].(string)
	var plan []map[string]any
	if pl, ok := in["plan"].([]any); ok {
		plan = make([]map[string]any, len(pl))
		for i, n := range pl {
			plan[i], _ = n.(map[string]any)
		}
	}
	risk, _ := in["risk"].(map[string]any)

	// the class the action is bound to: its own, else the plan node it names, else unknown (fail closed)
	var revClass any
	if inner != nil {
		revClass = inner["reversibility_class"]
	}
	if revClass == nil && hasNode && plan != nil {
		for _, n := range plan {
			if n != nil && n["id"] == any(nodeID) {
				revClass = n["reversibility_class"]
				break
			}
		}
	}

	// 2. envelope caveats
	cctx := map[string]any{"now": now, "action": inner}
	if v := risk["blastRadius"]; v != nil {
		cctx["blast_radius"] = v
	}
	if revClass != nil {
		cctx["reversibility_class"] = revClass
	}
	over, _ := in["caveatContext"].(map[string]any)
	for _, kv := range [][2]string{{"blastRadius", "blast_radius"}, {"reversibilityClass", "reversibility_class"}, {"delegationDepth", "delegation_depth"}, {"recentActionTimes", "recent_action_times"}} {
		if v, has := over[kv[0]]; has {
			cctx[kv[1]] = v
		}
	}
	tc := &ToolCall{Tool: "", Args: map[string]any{}}
	if verb, ok := inner["verb"].(string); ok {
		tc.Tool = verb
	}
	if params, ok := inner["params"].(map[string]any); ok {
		tc.Args = params
	}
	if tb, ok := actionCtx["toolBinding"].(string); ok {
		tc.ToolSignatureDigest = &tb
	}

	chainOK := true
	var extra []any
	gcs, _ := grant["caveats"].([]any)
	if hasChain {
		if !chainIsList || len(chain) == 0 {
			chainOK = false
			reasons = append(reasons, "delegation chain is empty or malformed")
		} else {
			cctx["delegation_depth"] = jsNumber(float64(len(chain) - 1))
			leaf, _ := chain[len(chain)-1].(map[string]any)
			lcs, _ := leaf["caveats"].([]any) // a leaf without a caveat list throws in the reference: nothing is extra here and the chain check refused it above
			if len(lcs) > len(gcs) {
				extra = lcs[len(gcs):]
			}
		}
	}
	ecvOK, failed := evaluateAgentCaveats(env["caveats"], cctx, actionCtx, tc, b)
	if !ecvOK {
		reasons = append(reasons, "caveat(s) not satisfied: "+strings.Join(failed, ", "))
	}

	// root caveats outside the envelope are signed authority too; the caveat-language types are evaluated over the whole chain
	leafCaveats := any(grant["caveats"])
	if chainIsList && len(chain) > 0 {
		if leaf, ok := chain[len(chain)-1].(map[string]any); ok {
			leafCaveats = leaf["caveats"]
		} else {
			leafCaveats = nil
		}
	}
	useK1 := k1in != nil && k1in.HasNarrow
	if lc, ok := leafCaveats.([]any); ok {
		for _, c := range lc {
			if IsK1Caveat(c) {
				useK1 = true
			}
		}
	}
	var k1r *K1Result
	if useK1 {
		r := EvaluateK1(in["grant"], chainV, k1in, K1Context{Now: now, Action: inner})
		k1r = &r
	}
	rcvOK, failed := evaluateAgentCaveats(k1StockList(RootCaveats(in["grant"]), nil), cctx, actionCtx, tc, b)
	if !rcvOK {
		reasons = append(reasons, "root caveat(s) not satisfied: "+strings.Join(failed, ", "))
	}
	var plain []any
	if k1r != nil {
		plain = k1r.Plain
	}
	dcvOK, failed := evaluateAgentCaveats(k1StockList(append([]any{}, extra...), plain), cctx, actionCtx, tc, b)
	if !dcvOK {
		reasons = append(reasons, "delegated caveat(s) not satisfied: "+strings.Join(failed, ", "))
	}
	if k1r != nil && !k1r.OK {
		dcvOK = false
		for i, r := range k1r.Reasons {
			reasons = append(reasons, "caveat language: "+k1r.Failed[i]+": "+r)
		}
	}

	// 3-5. risk, threshold band, budget admission, release
	bm, _ := budgetIn.(map[string]any)
	budget, ok := parseBudget(bm)
	if !ok {
		panic("budget is not a trust budget")
	}
	step := RiskStep{Policy: pol, Risk: risk, Plan: plan, NodeID: nodeID, HasNodeID: hasNode, Budget: budget, Now: now,
		PrOK: prOK, CvOK: ecvOK && rcvOK, DcvOK: dcvOK, ChainOK: chainOK}
	if g, ok := in["goalNodeId"].(string); ok {
		step.GoalNodeID = g
	}
	// the reference's default horizon applies only to an absent member: a present one that is not a positive number (zero, a
	// negative, NaN, null, a string) makes the age 1, and an infinite one makes it 0
	if hv, has := in["ageHorizonMs"]; has {
		if h, ok := jsNum(hv); ok && h > 0 {
			step.AgeHorizonMs = h
		} else {
			step.AgeHorizonMs = -1
		}
	}
	if rf, ok := decideFin(in["rFloor"]); ok {
		step.RFloor, step.HasRFloor = rf, true
	}
	step.ReversibilityClass, _ = cctx["reversibility_class"].(string)
	dec := DecideRisk(step)
	for _, r := range dec.Reasons {
		reasons = append(reasons, r)
	}
	if reasons == nil {
		reasons = []any{}
	}
	bud := map[string]any{"B": payNum(dec.Budget.B), "tau": payNum(dec.Budget.Tau)}
	if dec.Budget.HasAsOf {
		bud["asOf"] = payNum(dec.Budget.AsOf)
	} else {
		bud["asOf"] = nil
	}
	rt := dec.RequiredThreshold
	res := map[string]any{
		"releaseGuardianShare": dec.ReleaseGuardianShare,
		"requiredThreshold":    map[string]any{"t": jsNumber(float64(rt.T)), "proof": rt.Proof, "optimisticAllowed": rt.OptimisticAllowed},
		"r":                    payNum(dec.R),
		"admit":                dec.Admit,
		"needStepUp":           dec.NeedStepUp,
		"reasons":              reasons,
		"budget":               bud,
	}
	if k1r != nil {
		bound := make([]any, 0, len(k1r.Bound))
		for _, x := range k1r.Bound {
			bound = append(bound, map[string]any{"caveat": x.Caveat, "hop": jsNumber(float64(x.Hop)), "capHash": x.CapHash})
		}
		res["k1Bound"] = bound
	}
	return res
}

// NativeChargeDecider is the default ChargeDecider: the native Policy VM (DecideNative) with no caveat-language input.
func NativeChargeDecider(input map[string]any) (map[string]any, error) {
	return DecideNative(input, nil), nil
}

// DecideInputGrantRequired is the error DeriveDecideInputNative returns without ctx.grant (the grant from the verifier's OWN
// store); the presented chain root is never used as the grant.
var DecideInputGrantRequired = &CodedError{Code: "grant_required", Msg: "deriveDecideInput: ctx.grant (the grant from your own store) is required; the presented chain root is never used as the grant"}

// DeriveDecideInputNative assembles a DecideNative input from a PCActn plus the verifier's context (grant REQUIRED and stored,
// params, risk, budget, now, chain?, plan?, subject?, env?, goalNodeId?, pqPins?, caveatContext?, ageHorizonMs?), so the caller and
// the verifier derive action / nodeId / chain identically.
func DeriveDecideInputNative(p map[string]any, ctx map[string]any) (map[string]any, error) {
	var grant any
	switch g := ctx["grant"].(type) {
	case map[string]any:
		grant = g
	case []any: // typeof [] is "object": the reference takes it as the grant and the decision then finds no valid envelope
		grant = g
	default:
		return nil, DecideInputGrantRequired
	}
	in := map[string]any{"grant": grant, "trustedRoot": grant}
	if v, has := ctx["pqPins"]; has { // `!== undefined`: a null pin set is carried and refused downstream
		in["pqPins"] = v
	}
	chain := ctx["chain"]
	hasChain := chain != nil
	if !hasChain { // `ctx.chain ?? pcactn.cap_chain`: a null cap_chain is still a member of the input
		chain, hasChain = p["cap_chain"]
	}
	if hasChain {
		in["chain"] = chain
	}
	pa, _ := p["action"].(map[string]any)
	params := ctx["params"]
	if params == nil {
		params = map[string]any{}
	}
	inner := map[string]any{"params": params}
	for _, k := range []string{"verb", "resource", "reversibility_class"} {
		if v, has := pa[k]; has { // `!== undefined`: a null member is kept
			inner[k] = v
		}
	}
	action := map[string]any{"action": inner}
	for _, k := range []string{"subject", "env"} {
		if v := ctx[k]; jsTruthy(v) { // `ctx.subject ? {subject} : {}`: any truthy value is carried as it is (a string subject included)
			action[k] = v
		}
	}
	in["action"] = action
	if v, has := ctx["plan"]; has { // `!== undefined` members: a null one stays in the input
		in["plan"] = v
	}
	if pl, ok := p["plan"].(map[string]any); ok {
		if n, has := pl["node_id"]; has {
			in["nodeId"] = n
		}
	}
	for _, k := range []string{"goalNodeId", "risk", "budget", "now", "caveatContext", "ageHorizonMs"} {
		if v, has := ctx[k]; has {
			in[k] = v
		}
	}
	return in, nil
}

// AuthzenNativeDecide is DecideNative in the shape the AuthZEN PDP takes (its default Decide).
func AuthzenNativeDecide(input any) (*AuthzenDecision, error) {
	in, _ := input.(map[string]any)
	d := DecideNative(in, nil)
	reasons, _ := d["reasons"].([]any)
	rt, _ := d["requiredThreshold"].(map[string]any)
	rel, _ := d["releaseGuardianShare"].(bool)
	adm, _ := d["admit"].(bool)
	return &AuthzenDecision{ReleaseGuardianShare: rel, Admit: adm, R: d["r"], RequiredThreshold: rt, Reasons: reasons}, nil
}

// AuthzenNativeDeriveDecideInput is DeriveDecideInputNative in the shape the AuthZEN PDP takes (its default DeriveDecideInput).
func AuthzenNativeDeriveDecideInput(pc map[string]any, dctx map[string]any) (any, error) {
	return DeriveDecideInputNative(pc, dctx)
}
