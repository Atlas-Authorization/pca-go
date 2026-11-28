package pca

import (
	"fmt"
)

// Binding of the objective-risk functional to the decision path, without touching the signed PCActn. The facts live in the
// signed grant envelope as an optional `objective_risk` member (covered by the root signature); the registry, resource graph and
// calibration set are INSTANCE-held configuration whose digests must equal the committed ones, or the result is a mismatch.

func obMap(v any) (map[string]any, bool) { m, ok := v.(map[string]any); return m, ok }

func obStr(v any) bool { s, ok := v.(string); return ok && s != "" }

// ReadObjectiveCommitment reads the committed `objective_risk` off a grant's envelope. It returns (nil, "") when nothing is
// committed, (commitment, "") when it is well-formed and (nil, reason) when it is malformed. Pure and total.
func ReadObjectiveCommitment(grant any) (commitment map[string]any, malformed string) {
	env := ReadEnvelope(grant)
	raw, has := env["objective_risk"]
	if env == nil || !has {
		return nil, ""
	}
	r, ok := obMap(raw)
	if v, isNum := jsNum(r["v"]); !ok || !isNum || v != 1 {
		return nil, "objective_risk: unsupported shape/version"
	}
	emb, ok := obMap(r["embedder"])
	if _, cfgOK := obMap(emb["config"]); !ok || emb["scheme"] != "native" || !obStr(emb["model_id"]) || !cfgOK {
		return nil, `objective_risk.embedder must be { scheme: "native", model_id, config }`
	}
	if g, ok := obMap(r["goal"]); !ok || !obStr(g["commit"]) {
		return nil, "objective_risk.goal must be a goal commitment"
	}
	if !obStr(r["registry_digest"]) || !obStr(r["graph_digest"]) {
		return nil, "objective_risk needs registry_digest and graph_digest"
	}
	if cd, has := r["calibration_digest"]; has && !obStr(cd) {
		return nil, "objective_risk.calibration_digest must be a string"
	}
	kinds, isList := r["authorized_kinds"].([]any)
	if !isList {
		return nil, "objective_risk.authorized_kinds must be string[]"
	}
	for _, k := range kinds {
		if _, isStr := k.(string); !isStr {
			return nil, "objective_risk.authorized_kinds must be string[]"
		}
	}
	if d, has := r["denominations"]; has {
		if _, isList := d.([]any); !isList {
			return nil, "objective_risk.denominations must be an array"
		}
	}
	if m, has := r["on_mismatch"]; has && m != "deny" && m != "heuristic" {
		return nil, `objective_risk.on_mismatch must be "deny" or "heuristic"`
	}
	return r, ""
}

func obStrings(v any) []string {
	l, _ := v.([]any)
	out := make([]string, 0, len(l))
	for _, x := range l {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func obFloat(v any) float64 { f, _ := jsNum(v); return f }

func obBuildRegistry(cfgV any) *InMemoryInverseRegistry {
	cfg, _ := obMap(cfgV)
	reg := NewInMemoryInverseRegistry(obStrings(cfg["trusted_verifiers"])...)
	entries, _ := cfg["entries"].([]any)
	for _, ev := range entries {
		e, _ := obMap(ev)
		verb, _ := e["verb"].(string)
		kind, _ := e["inverse_kind"].(string)
		fid, _ := e["fidelity"].(string)
		ent := InverseEntry{InverseKind: kind, Fidelity: fid}
		if vm, ok := obMap(e["verification"]); ok {
			id, _ := vm["verifier_id"].(string)
			ed, _ := vm["evidence_digest"].(string)
			ent.Verification = &InverseVerification{VerifierID: id, EvidenceDigest: ed}
		}
		reg.Register(verb, ent)
	}
	return reg
}

func obBuildGraph(cfgV any) (*ObjResourceGraph, error) {
	cfg, _ := obMap(cfgV)
	g := NewObjResourceGraph()
	nodes, _ := cfg["nodes"].([]any)
	for _, nv := range nodes {
		n, _ := obMap(nv)
		id, _ := n["id"].(string)
		harm := map[string]float64{}
		if hm, ok := obMap(n["harm"]); ok {
			for k, v := range hm {
				harm[k] = obFloat(v)
			}
		}
		g.AddNode(ResourceNode{ID: id, Harm: harm})
	}
	edges, _ := cfg["edges"].([]any)
	for _, ev := range edges {
		e, _ := obMap(ev)
		from, _ := e["from"].(string)
		to, _ := e["to"].(string)
		kind, _ := e["kind"].(string)
		if err := g.AddEdge(ResourceEdge{From: from, To: to, Kind: kind}); err != nil {
			return nil, err
		}
	}
	return g, nil
}

// ResolveObjectiveRisk resolves the objective risk inputs for action under grant. Total (it never errors or panics).
//   - nothing committed: {mode: "none"} (the heuristic, unchanged)
//   - committed and reproduced: {mode: "objective", inputs: {reversibility, blastRadius, semanticDistance}, r, evidenceDigest}
//   - committed but not reproducible or invalid: {mode: "mismatch", reasons, onMismatch}; onMismatch is "deny" unless the verifier's
//     own instance config sets allow_heuristic_fallback and the grant asked for "heuristic" (a grant cannot downgrade the verifier).
//
// instance is the instance-held config ({registry, graph, calibration, allow_heuristic_fallback}); taint and age are
// verifier-supplied and nil means 1, the worst case.
func ResolveObjectiveRisk(grant, action, instance any, taint, age *float64) (res map[string]any) {
	com, malformed := ReadObjectiveCommitment(grant)
	if malformed != "" {
		return map[string]any{"mode": "mismatch", "reasons": []any{malformed}, "onMismatch": "deny"}
	}
	if com == nil {
		return map[string]any{"mode": "none"}
	}
	inst, instOK := obMap(instance)
	onMismatch := "deny"
	if com["on_mismatch"] == "heuristic" && instOK && inst["allow_heuristic_fallback"] == true {
		onMismatch = "heuristic"
	}
	miss := func(reasons ...string) map[string]any {
		rs := make([]any, len(reasons))
		for i, r := range reasons {
			rs[i] = r
		}
		return map[string]any{"mode": "mismatch", "reasons": rs, "onMismatch": onMismatch}
	}
	defer func() {
		if r := recover(); r != nil {
			res = miss(fmt.Sprintf("objective risk evaluation error (fail closed): %v", r))
		}
	}()
	env := ReadEnvelope(grant)
	if env == nil {
		return miss("grant carries no valid envelope")
	}
	if !instOK || inst == nil {
		return miss("the grant commits objective-risk facts but the instance holds no objective-risk config")
	}
	registry := obBuildRegistry(inst["registry"])
	graph, err := obBuildGraph(inst["graph"])
	if err != nil {
		return miss("objective risk evaluation error (fail closed): " + err.Error())
	}
	emb, _ := obMap(com["embedder"])
	cfg, _ := obMap(emb["config"])
	embedder, err := NativeHashEmbedder(cfg)
	if err != nil {
		return miss("objective risk evaluation error (fail closed): " + err.Error())
	}
	if want, _ := emb["model_id"].(string); embedder.ModelID() != want {
		return miss("embedder model_id does not match the committed one")
	}
	var calibration []float64
	if cl, isList := inst["calibration"].([]any); isList {
		calibration = make([]float64, len(cl))
		for i, v := range cl {
			calibration[i] = obFloat(v)
		}
	}
	commitments := RiskCommitments{RegistryDigest: com["registry_digest"].(string), GraphDigest: com["graph_digest"].(string)}
	if cd, has := com["calibration_digest"].(string); has {
		d, derr := CalibrationDigest(calibration)
		if calibration == nil || derr != nil || d != cd {
			return miss("calibration set does not match the committed digest")
		}
		commitments.CalibrationDigest = &cd
	}
	policy, ok := RiskPolicyOf(env["risk_policy"])
	if !ok {
		return miss("grant carries no valid envelope")
	}
	ctx := &ObjectiveRiskContext{
		Registry: registry, AuthorizedKinds: obStrings(com["authorized_kinds"]), Graph: graph, Embedder: embedder,
		Goal: com["goal"].(map[string]any), Commitments: commitments, Weights: policy.Weights, Taint: 1, Age: 1,
	}
	if taint != nil {
		ctx.Taint = *taint
	}
	if age != nil {
		ctx.Age = *age
	}
	if sc, ok := obMap(com["scope"]); ok {
		s := &ObjScope{}
		if ek, has := sc["edgeKinds"].([]any); has {
			s.EdgeKinds = obStrings(ek)
		}
		if md, has := jsNum(sc["maxDepth"]); has {
			s.MaxDepth = &md
		}
		ctx.Scope = s
	}
	if dl, isList := com["denominations"].([]any); isList {
		for _, dv := range dl {
			d, _ := obMap(dv)
			id, _ := d["id"].(string)
			ctx.Denominations = append(ctx.Denominations, Denomination{ID: id, Ceiling: obFloat(d["ceiling"]), Weight: obFloat(d["weight"])})
		}
	}
	if commitments.CalibrationDigest != nil && calibration != nil {
		ctx.Calibration = calibration
	}
	out, err := ObjectiveRisk(action, ctx)
	if err != nil {
		return miss("objective risk evaluation error (fail closed): " + err.Error())
	}
	if !out.Valid {
		return miss(out.Reasons...)
	}
	return map[string]any{
		"mode":           "objective",
		"inputs":         map[string]any{"reversibility": out.Inputs.Reversibility, "blastRadius": out.Inputs.BlastRadius, "semanticDistance": out.Inputs.SemanticDistance},
		"r":              out.R,
		"evidenceDigest": out.EvidenceDigest,
	}
}
