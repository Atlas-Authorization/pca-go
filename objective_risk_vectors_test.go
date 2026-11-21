package pca

import (
	"errors"
	"fmt"
	"math"
	"testing"
)

// Replay of the objective risk functional against the reference (ref-objective-risk), every case: the canonical action, the inverse
// registry and reversibility, the resource graph and blast radius, the native and customer embedders, the goal commitment and
// distance, split-conformal calibration, the harm currency, the composed risk and the dispute-game oracle. A reference refusal
// requires a refusal. Non-finite numbers travel in the corpus form {"$num": ...}.

// orOut makes a result JSON-able: a non-finite number in its corpus form, Go slices as lists.
func orOut(v any) any {
	switch t := v.(type) {
	case float64:
		return scNumOut(t)
	case map[string]any:
		m := make(map[string]any, len(t))
		for k, x := range t {
			m[k] = orOut(x)
		}
		recordKeyOrder(m, jsKeys(t))
		return m
	case map[string]float64:
		m := make(map[string]any, len(t))
		for k, x := range t {
			m[k] = scNumOut(x)
		}
		return m
	case []any:
		a := make([]any, len(t))
		for i, x := range t {
			a[i] = orOut(x)
		}
		return a
	case []string:
		a := make([]any, len(t))
		for i, x := range t {
			a[i] = x
		}
		return a
	case []float64:
		a := make([]any, len(t))
		for i, x := range t {
			a[i] = scNumOut(x)
		}
		return a
	}
	return v
}

func orStrs(v any) []string {
	l, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(l))
	for _, x := range l {
		s, _ := x.(string)
		out = append(out, s)
	}
	return out
}

// orFloats reads a JSON vector: a component that is no number is NaN (no safe integer), a non-list is refused.
func orFloats(v any) ([]float64, bool) {
	l, ok := v.([]any)
	if !ok {
		return nil, false
	}
	out := make([]float64, len(l))
	for i, x := range l {
		out[i] = jsF(x)
	}
	return out, true
}

func orRegistry(spec any) *InMemoryInverseRegistry {
	s, _ := spec.(map[string]any)
	r := NewInMemoryInverseRegistry(orStrs(s["trusted"])...)
	entries, _ := s["entries"].([]any)
	for _, en := range entries {
		pair, _ := en.([]any)
		verb, _ := pair[0].(string)
		e, _ := pair[1].(map[string]any)
		ie := InverseEntry{InverseKind: vecStr(e, "inverseKind"), Fidelity: vecStr(e, "fidelity")}
		if v, ok := e["verification"].(map[string]any); ok {
			ie.Verification = &InverseVerification{VerifierID: vecStr(v, "verifierId"), EvidenceDigest: vecStr(v, "evidenceDigest")}
		}
		r.Register(verb, ie)
	}
	return r
}

func orEntryOut(e InverseEntry) map[string]any {
	m := map[string]any{"inverseKind": e.InverseKind, "fidelity": e.Fidelity}
	if e.Verification != nil {
		m["verification"] = map[string]any{"verifierId": e.Verification.VerifierID, "evidenceDigest": e.Verification.EvidenceDigest}
	}
	return m
}

func orGraph(spec any) (*ObjResourceGraph, error) {
	s, _ := spec.(map[string]any)
	g := NewObjResourceGraph()
	nodes, _ := s["nodes"].([]any)
	for _, n := range nodes {
		m, _ := n.(map[string]any)
		rn := ResourceNode{ID: vecStr(m, "id")}
		if h, ok := m["harm"].(map[string]any); ok {
			rn.Harm = make(map[string]float64, len(h))
			for k, x := range h {
				rn.Harm[k] = jsF(x)
			}
		}
		g.AddNode(rn)
	}
	edges, _ := s["edges"].([]any)
	for _, e := range edges {
		m, _ := e.(map[string]any)
		if err := g.AddEdge(ResourceEdge{From: vecStr(m, "from"), To: vecStr(m, "to"), Kind: vecStr(m, "kind")}); err != nil {
			return nil, err
		}
	}
	return g, nil
}

func orScope(v any) *ObjScope {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	s := &ObjScope{}
	if l, ok := m["edgeKinds"].([]any); ok {
		s.EdgeKinds = make([]string, 0, len(l))
		for _, x := range l {
			k, _ := x.(string)
			s.EdgeKinds = append(s.EdgeKinds, k)
		}
	}
	if d, ok := m["maxDepth"]; ok && d != nil {
		f := jsF(d)
		s.MaxDepth = &f
	}
	return s
}

func orBlast(b BlastRadiusResult) map[string]any {
	return map[string]any{"count": b.Count, "reachable": b.Reachable, "normalized": b.Normalized, "harm": b.Harm}
}

// fixed is a custom embedder returning its vector verbatim, valid or not.
type orFixed struct {
	id     string
	dims   int
	config any
	vector any
}

func (f *orFixed) ModelID() string { return f.id }
func (f *orFixed) Config() any     { return f.config }
func (f *orFixed) Dims() int       { return f.dims }
func (f *orFixed) Embed(CanonicalAction) ([]float64, error) {
	v, ok := orFloats(f.vector)
	if !ok {
		return nil, &EmbeddingError{fmt.Sprintf("vector must have exactly %d components", f.dims)}
	}
	return v, nil
}

func orInfer(spec any, dims int) func(string) ([]float64, error) {
	m, _ := spec.(map[string]any)
	return func(j string) ([]float64, error) {
		switch {
		case m["throws"] == true:
			return nil, errors.New("infer boom")
		case m["notArray"] == true:
			return nil, &EmbeddingError{fmt.Sprintf("vector must have exactly %d components", dims)}
		case m["byLen"] == true:
			n := len(utf16Units(j))
			out := make([]float64, dims)
			for k := range out {
				out[k] = float64(n + k)
			}
			return out, nil
		}
		v, _ := orFloats(m["vector"])
		return v, nil
	}
}

func orEmbedder(spec any) (Embedder, error) {
	s, _ := spec.(map[string]any)
	switch s["scheme"] {
	case "native":
		cfg, _ := s["config"].(map[string]any)
		return NativeHashEmbedder(cfg)
	case "fixed":
		dims, _ := jsNum(s["dims"])
		return &orFixed{id: vecStr(s, "modelId"), dims: int(dims), config: s["config"], vector: s["vector"]}, nil
	}
	d, _ := s["descriptor"].(map[string]any)
	dims, _ := jsNum(d["dims"])
	var claimed *string
	if c, ok := s["claimedModelId"].(string); ok {
		claimed = &c
	}
	return NewByoEmbedder(d, orInfer(s["infer"], int(dims)), claimed)
}

func orCtx(spec any) (*ObjectiveRiskContext, error) {
	c, _ := spec.(map[string]any)
	g, err := orGraph(c["graph"])
	if err != nil {
		return nil, err
	}
	e, err := orEmbedder(c["embedder"])
	if err != nil {
		return nil, err
	}
	goal, _ := c["goal"].(map[string]any)
	cm, _ := c["commitments"].(map[string]any)
	ctx := &ObjectiveRiskContext{
		Registry: orRegistry(c["registry"]), AuthorizedKinds: orStrs(c["authorizedKinds"]), Graph: g, Scope: orScope(c["scope"]),
		Embedder: e, Goal: goal, Commitments: RiskCommitments{RegistryDigest: vecStr(cm, "registryDigest"), GraphDigest: vecStr(cm, "graphDigest")},
		Taint: jsF(c["taint"]), Age: jsF(c["age"]),
	}
	if d, ok := cm["calibrationDigest"].(string); ok {
		ctx.Commitments.CalibrationDigest = &d
	}
	for _, d := range c["denominations"].([]any) {
		m, _ := d.(map[string]any)
		ctx.Denominations = append(ctx.Denominations, Denomination{ID: vecStr(m, "id"), Ceiling: jsF(m["ceiling"]), Weight: jsF(m["weight"])})
	}
	w, _ := c["weights"].(map[string]any)
	ctx.Weights = RiskWeights{Alpha: jsF(w["alpha"]), Beta: jsF(w["beta"]), Gamma: jsF(w["gamma"]), Delta: jsF(w["delta"]), Epsilon: jsF(w["epsilon"]), Zeta: jsF(w["zeta"])}
	if u, ok := c["attestedUncertainty"]; ok {
		f := jsF(u)
		ctx.AttestedUncertainty = &f
	}
	if l, ok := orFloats(c["calibration"]); ok {
		ctx.Calibration = l
	}
	return ctx, nil
}

func orResult(r ObjectiveRiskResult) map[string]any {
	rev := map[string]any{"class": r.Reversibility.Class, "value": r.Reversibility.Value}
	if r.Reversibility.InverseKind != "" {
		rev["inverseKind"] = r.Reversibility.InverseKind
	}
	return map[string]any{
		"r": r.R, "valid": r.Valid, "reasons": r.Reasons, "raw": r.Raw,
		"inputs": map[string]any{
			"semanticDistance": r.Inputs.SemanticDistance, "reversibility": r.Inputs.Reversibility, "blastRadius": r.Inputs.BlastRadius,
			"taint": r.Inputs.Taint, "confidence": r.Inputs.Confidence, "age": r.Inputs.Age,
		},
		"reversibility": rev, "blast": orBlast(r.Blast), "harm": map[string]any{"units": r.Harm.Units, "normalized": r.Harm.Normalized},
		"evidenceDigest": r.EvidenceDigest,
	}
}

// orCanonical reads a canonical action; a hand-made object lacking a member has no typed form (ok false).
func orCanonical(v any) (CanonicalAction, bool) {
	m, isMap := v.(map[string]any)
	if !isMap {
		return CanonicalAction{}, false
	}
	verb, a := m["verb"].(string)
	res, b := m["resource"].(string)
	p, c := m["params"].(map[string]any)
	if !a || !b || !c {
		return CanonicalAction{}, false
	}
	return CanonicalAction{Verb: verb, Resource: res, Params: p}, true
}

func orEps(v any) []float64 {
	if v == nil {
		return nil
	}
	return []float64{jsF(v)}
}

func TestObjectiveRiskMatchesTheReference(t *testing.T) {
	dec := func(a []any, i int) any { return scDecode(vecArg(a, i)) }
	str := func(s string, err error) (any, error) { return s, err }
	fns := map[string]vecFn{
		"constants": func([]any) (any, error) {
			return map[string]any{"METRIC": ObjMetric, "DEFAULT_EPSILON": scNumOut(ObjDefaultEpsilon), "NATIVE_SCHEME": NativeScheme,
				"DEFAULT_MAX_PARAM_LEAVES": jsNumber(DefaultMaxParamLeaves), "DEFAULT_NATIVE_CONFIG": DefaultNativeConfig()}, nil
		},
		"canonicalAction": func(a []any) (any, error) {
			c, err := CanonicalizeAction(dec(a, 0))
			if err != nil {
				return nil, err
			}
			return c.Value(), nil
		},
		"canonicalActionJson": func(a []any) (any, error) {
			if c, ok := orCanonical(dec(a, 0)); ok {
				return str(CanonicalActionJSON(c))
			}
			return str(objCanon(dec(a, 0))) // hand-made object without a typed form: the canonical text of the object itself
		},
		"canonicalActionDigest": func(a []any) (any, error) {
			if c, ok := orCanonical(dec(a, 0)); ok {
				return str(CanonicalActionDigest(c))
			}
			return str(objHash(dec(a, 0)))
		},
		"registryOps": func(a []any) (any, error) {
			r := NewInMemoryInverseRegistry(orStrs(vecArg(a, 0))...)
			ops, _ := vecArg(a, 1).([]any)
			out := []any{}
			for _, o := range ops {
				op := o.([]any)
				switch op[0] {
				case "register":
					r2 := orRegistry(map[string]any{"trusted": []any{}, "entries": []any{[]any{op[1], op[2]}}})
					e, _ := r2.Lookup(op[1].(string))
					r.Register(op[1].(string), e)
					out = append(out, nil)
				case "lookup":
					if e, ok := r.Lookup(op[1].(string)); ok {
						out = append(out, orEntryOut(e))
					} else {
						out = append(out, nil)
					}
				case "trustedVerifiers":
					out = append(out, r.TrustedVerifiers())
				default:
					out = append(out, r.Digest())
				}
			}
			return orOut(out), nil
		},
		"registryDigest": func(a []any) (any, error) { return orRegistry(vecArg(a, 0)).Digest(), nil },
		"reversibility": func(a []any) (any, error) {
			act, _ := vecArg(a, 0).(map[string]any)
			r := ObjectiveReversibility(vecStr(act, "verb"), orRegistry(vecArg(a, 1)), orStrs(vecArg(a, 2)))
			m := map[string]any{"class": r.Class, "value": r.Value}
			if r.InverseKind != "" {
				m["inverseKind"] = r.InverseKind
			}
			return m, nil
		},
		"graphBuild": func(a []any) (any, error) {
			g, err := orGraph(dec(a, 0))
			if err != nil {
				return nil, err
			}
			d, err := g.Digest()
			if err != nil {
				return nil, err
			}
			return map[string]any{"size": g.Size(), "digest": d}, nil
		},
		"graphReachable": func(a []any) (any, error) {
			g, err := orGraph(dec(a, 0))
			if err != nil {
				return nil, err
			}
			return g.Reachable(vecStr(map[string]any{"s": vecArg(a, 1)}, "s"), orScope(dec(a, 2))), nil
		},
		"graphNode": func(a []any) (any, error) {
			g, err := orGraph(dec(a, 0))
			if err != nil {
				return nil, err
			}
			n, ok := g.Node(vecStr(map[string]any{"s": vecArg(a, 1)}, "s"))
			if !ok {
				return nil, nil
			}
			m := map[string]any{"id": n.ID}
			if n.Harm != nil {
				m["harm"] = n.Harm
			}
			return orOut(m), nil
		},
		"blastRadius": func(a []any) (any, error) {
			g, err := orGraph(dec(a, 1))
			if err != nil {
				return nil, err
			}
			act, _ := vecArg(a, 0).(map[string]any)
			return orOut(orBlast(ComputeBlastRadius(vecStr(act, "resource"), g, orScope(dec(a, 2))))), nil
		},
		"nativeEmbed": func(a []any) (any, error) {
			cfg, _ := dec(a, 0).(map[string]any)
			e, err := NativeHashEmbedder(cfg)
			if err != nil {
				return nil, err
			}
			c, ok := orCanonical(dec(a, 1))
			if !ok {
				return nil, errors.New("not a canonical action")
			}
			v, err := e.Embed(c)
			if err != nil {
				return nil, err
			}
			return map[string]any{"modelId": e.ModelID(), "dims": e.Dims(), "config": e.Config(), "vector": orOut(v)}, nil
		},
		"byoModelId": func(a []any) (any, error) {
			d, _ := dec(a, 0).(map[string]any)
			return str(ByoModelID(d))
		},
		"byoEmbed": func(a []any) (any, error) {
			d, _ := dec(a, 0).(map[string]any)
			dims, _ := jsNum(d["dims"])
			var claimed *string
			if c, ok := vecArg(a, 1).(string); ok {
				claimed = &c
			}
			e, err := NewByoEmbedder(d, orInfer(vecArg(a, 2), int(dims)), claimed)
			if err != nil {
				return nil, err
			}
			c, ok := orCanonical(dec(a, 3))
			if !ok {
				return nil, errors.New("not a canonical action")
			}
			v, err := e.Embed(c)
			if err != nil {
				return nil, err
			}
			return map[string]any{"modelId": e.ModelID(), "dims": e.Dims(), "vector": orOut(v)}, nil
		},
		"validateVector": func(a []any) (any, error) {
			v, ok := orFloats(dec(a, 0))
			if !ok {
				return nil, errors.New("not an array")
			}
			out, err := ValidateVector(v, int(jsF(dec(a, 1))))
			if err != nil {
				return nil, err
			}
			return orOut(out), nil
		},
		"conformanceCheck": func(a []any) (any, error) {
			e, err := orEmbedder(dec(a, 0))
			if err != nil {
				return nil, err
			}
			var cases []ConformanceCase
			l, _ := vecArg(a, 1).([]any)
			for _, x := range l {
				m, _ := x.(map[string]any)
				v, _ := orFloats(dec([]any{m["vector"]}, 0))
				cases = append(cases, ConformanceCase{Action: m["action"], Vector: v})
			}
			return EmbedderConformanceCheck(e, cases), nil
		},
		"commitGoal": func(a []any) (any, error) {
			e, err := orEmbedder(dec(a, 0))
			if err != nil {
				return nil, err
			}
			g, err := CommitGoal(e, dec(a, 1), orEps(dec(a, 2))...)
			if err != nil {
				return nil, err
			}
			return g, nil
		},
		"verifyGoalCommitment": func(a []any) (any, error) {
			e, err := orEmbedder(dec(a, 1))
			if err != nil {
				return nil, err
			}
			if r := VerifyGoalCommitment(dec(a, 0), e); r != "" {
				return r, nil
			}
			return nil, nil
		},
		"vectorDistance": func(a []any) (any, error) {
			x, _ := orFloats(dec(a, 0))
			y, _ := orFloats(dec(a, 1))
			return orOut(VectorDistance(x, y, orEps(dec(a, 2))...)), nil
		},
		"committedDistanceChecked": func(a []any) (any, error) {
			e, err := orEmbedder(dec(a, 2))
			if err != nil {
				return nil, err
			}
			c, ok := orCanonical(dec(a, 0))
			if !ok {
				return nil, errors.New("not a canonical action")
			}
			r := CommittedDistanceChecked(c, dec(a, 1), e)
			if !r.OK {
				return map[string]any{"ok": false, "reason": r.Reason}, nil
			}
			return map[string]any{"ok": true, "value": orOut(r.Value)}, nil
		},
		"committedDistance": func(a []any) (any, error) {
			e, err := orEmbedder(dec(a, 2))
			if err != nil {
				return nil, err
			}
			return orOut(CommittedDistance(dec(a, 0), dec(a, 1), e)), nil
		},
		"calibrate": func(a []any) (any, error) {
			s, _ := orFloats(dec(a, 1))
			return orOut(Calibrate(jsF(dec(a, 0)), s)), nil
		},
		"conformalThreshold": func(a []any) (any, error) {
			s, _ := orFloats(dec(a, 0))
			q, ok := ConformalThreshold(s, jsF(dec(a, 1)))
			if !ok {
				return nil, nil
			}
			return orOut(q), nil
		},
		"calibrationDigest": func(a []any) (any, error) {
			s, _ := orFloats(dec(a, 0))
			return str(CalibrationDigest(s))
		},
		"harmReport": func(a []any) (any, error) {
			units, _ := dec(a, 0).(map[string]any)
			var ds []Denomination
			l, _ := dec(a, 1).([]any)
			for _, d := range l {
				m, _ := d.(map[string]any)
				ds = append(ds, Denomination{ID: vecStr(m, "id"), Ceiling: jsF(m["ceiling"]), Weight: jsF(m["weight"])})
			}
			r := ComputeHarmReport(units, ds)
			return orOut(map[string]any{"units": r.Units, "normalized": r.Normalized}), nil
		},
		"objectiveRisk": func(a []any) (any, error) {
			ctx, err := orCtx(dec(a, 1))
			if err != nil {
				return nil, err
			}
			r, err := ObjectiveRisk(dec(a, 0), ctx)
			if err != nil {
				return nil, err
			}
			return orOut(orResult(r)), nil
		},
		"objectiveRiskOracle": func(a []any) (any, error) {
			ctx, err := orCtx(dec(a, 0))
			if err != nil {
				return nil, err
			}
			return orOut(ObjectiveRiskResolve(ctx, dec(a, 1), dec(a, 2))), nil
		},
	}
	cmp := map[string]func(want, got any) bool{
		// the reference's engine message for a null goal is only compared as "a reason"
		"verifyGoalCommitment": func(want, got any) bool {
			if w, ok := want.(string); ok && len(w) > 21 && w[:21] == "Cannot read propertie" {
				_, isStr := got.(string)
				return isStr
			}
			return baseCanon(want) == baseCanon(got)
		},
		"committedDistanceChecked": func(want, got any) bool {
			w, _ := want.(map[string]any)
			g, _ := got.(map[string]any)
			if r, ok := w["reason"].(string); ok && len(r) > 21 && r[:21] == "Cannot read propertie" {
				_, isStr := g["reason"].(string)
				return isStr && g["ok"] == false
			}
			return baseCanon(want) == baseCanon(got)
		},
	}
	replayAll(t, "ref-objective-risk.json.gz", 4052, fns, cmp, nil)
}

// the native embedder is the shared hash of its n-gram features: pin the final-sigma and dotted-capital-I lower-casing it relies on
func TestObjLowerIsTheFullUnicodeMapping(t *testing.T) {
	for in, want := range map[string]string{"İX": "i̇x", "ΟΔΥΣΣΕΥΣ": "οδυσσευς", "Σ": "σ", "AΣ": "aς", "AΣB": "aσb", "STRAßE": "straße"} {
		if got := objLower(in); got != want {
			t.Errorf("objLower(%q) = %q, want %q", in, got, want)
		}
	}
	if math.Floor(objMaxComponent(1)) != objMaxComponent(1) {
		t.Fatal("max component is an integer")
	}
}
