package pca

// Replays the policy analyzer reference corpus. Policies and results are plain JSON trees; a number that is not finite comes back
// as {"$num": "Infinity"}.

import (
	"crypto/sha256"
	"math"
	"strings"
	"testing"
)

// anlTestKey is the key pair of a seed label: the seed is sha256("atlas-pca-conformance/" + label).
func anlTestKey(label string) *KeyPair {
	d := sha256.Sum256([]byte("atlas-pca-conformance/" + label))
	kp, err := KeyPairFromSeed(d[:])
	if err != nil {
		panic(err)
	}
	return kp
}

// anlTestKeyed replaces "$key:LABEL" with the public key of the label.
func anlTestKeyed(v any) any {
	switch t := v.(type) {
	case string:
		if strings.HasPrefix(t, "$key:") {
			return anlTestKey(t[len("$key:"):]).Public
		}
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, x := range t {
			out[k] = anlTestKeyed(x)
		}
		recordKeyOrder(out, jsKeys(t))
		return out
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = anlTestKeyed(x)
		}
		return out
	}
	return v
}

func anlTestAt(a []any, i int) any {
	if i < len(a) {
		return a[i]
	}
	return nil
}

// anlTestOut spells a non-finite number as the reference does.
func anlTestOut(v any) any {
	switch t := v.(type) {
	case float64:
		if math.IsNaN(t) {
			return map[string]any{"$num": "NaN"}
		}
		if math.IsInf(t, 0) {
			if t > 0 {
				return map[string]any{"$num": "Infinity"}
			}
			return map[string]any{"$num": "-Infinity"}
		}
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, x := range t {
			out[k] = anlTestOut(x)
		}
		recordKeyOrder(out, jsKeys(t))
		return out
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = anlTestOut(x)
		}
		return out
	}
	return v
}

// anlTestRevive is the inverse: {"$num": "Infinity"} back to the number.
func anlTestRevive(v any) any {
	switch t := v.(type) {
	case map[string]any:
		if s, ok := t["$num"].(string); ok && len(t) == 1 {
			switch s {
			case "Infinity":
				return math.Inf(1)
			case "-Infinity":
				return math.Inf(-1)
			}
			return math.NaN()
		}
		out := make(map[string]any, len(t))
		for k, x := range t {
			out[k] = anlTestRevive(x)
		}
		recordKeyOrder(out, jsKeys(t))
		return out
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = anlTestRevive(x)
		}
		return out
	}
	return v
}

func anlTestIv(v any) anlIv {
	m, ok := v.(map[string]any)
	if !ok {
		return anlFullInterval
	}
	lo, _ := jsNum(m["lo"])
	hi, _ := jsNum(m["hi"])
	li, _ := m["loInclusive"].(bool)
	hiI, _ := m["hiInclusive"].(bool)
	return anlIv{lo: lo, hi: hi, loInc: li, hiInc: hiI}
}

func anlTestWrap(f func(a []any) any) vecFn {
	return func(a []any) (any, error) {
		r, err := anlTry(func() any { return anlTestOut(f(anlTestRevive(a).([]any))) })
		return r, err
	}
}

func anlTestProbes(in any) *anlProbes {
	m, ok := in.(map[string]any)
	if !ok {
		anlFail("probe inputs are not an object")
	}
	return anlCollectProbes(m)
}

func TestAnalyzerVectors(t *testing.T) {
	fns := map[string]vecFn{
		"analyzeCaveats":                anlTestWrap(func(a []any) any { return anlAnalyzeCaveats(a[0]) }),
		"numericConjunctionSatisfiable": anlTestWrap(func(a []any) any { return anlNumericConjunctionSatisfiable(a[0]) }),
		"predicateNumericSatisfiable":   anlTestWrap(func(a []any) any { return anlPredicateNumericSatisfiable(a[0]) }),
		"tightenInterval": anlTestWrap(func(a []any) any {
			return anlTighten(anlTestIv(a[0]), anlTestAt(a, 1), anlTestAt(a, 2)).toJSON()
		}),
		"intervalEmpty":          anlTestWrap(func(a []any) any { return anlIntervalEmpty(anlTestIv(a[0])) }),
		"fieldProbes":            anlTestWrap(func(a []any) any { return anlFieldProbes(a[0]) }),
		"vetoesFromConstitution": anlTestWrap(func(a []any) any { return anlVetoesFromConstitution(a[0]) }),
		"toModel":                anlTestWrap(func(a []any) any { return anlToModel(a[0]) }),
		"collectProbes":          anlTestWrap(func(a []any) any { return anlTestProbes(a[0]).toJSON() }),
		"representatives": anlTestWrap(func(a []any) any {
			pr := anlTestProbes(a[0])
			if anlProductSize(pr) > 400 {
				anlFail("grid too large for the corpus")
			}
			out := []any{}
			anlEachRep(pr, func(r *anlRep) bool {
				rep := map[string]any{"verb": r.verb, "resource": r.resource, "assignments": r.asg.toJSON(), "action": anlRepToAction(r)}
				if r.revClass != nil {
					rep["revClass"] = r.revClass
				}
				out = append(out, rep)
				return false
			})
			return out
		}),
		"witnessOf":      anlTestWrap(func(a []any) any { return anlWitnessOf(anlToModel(a[0]), a[1]) }),
		"decideAction":   anlTestWrap(func(a []any) any { return anlDecideAction(anlToModel(a[0]), a[1]) }),
		"admitsConcrete": anlTestWrap(func(a []any) any { return anlAdmitsConcrete(a[0], a[1]) }),
		"vetoApplies": anlTestWrap(func(a []any) any {
			src, _ := a[1].(map[string]any)
			x := anlCopy(src)
			if _, has := x["params"]; !has {
				x["params"] = map[string]any{}
			}
			ctx := map[string]any{"action": x, "subject": anlNN(src["subject"], map[string]any{}), "env": anlNN(src["env"], map[string]any{})}
			return anlVetoApplies(a[0], ctx)
		}),
		"reachable":         anlTestWrap(func(a []any) any { return anlReachable(a[0], anlTestAt(a, 1), anlTestAt(a, 2)) }),
		"alwaysDenies":      anlTestWrap(func(a []any) any { return anlAlwaysDenies(a[0], anlTestAt(a, 1), anlTestAt(a, 2)) }),
		"alwaysAllows":      anlTestWrap(func(a []any) any { return anlAlwaysAllows(a[0], anlTestAt(a, 1), anlTestAt(a, 2)) }),
		"subsumes":          anlTestWrap(func(a []any) any { return anlSubsumes(a[0], a[1], anlTestAt(a, 2)) }),
		"disjoint":          anlTestWrap(func(a []any) any { return anlDisjoint(a[0], a[1], anlTestAt(a, 2)) }),
		"equivalent":        anlTestWrap(func(a []any) any { return anlEquivalent(a[0], a[1], anlTestAt(a, 2)) }),
		"intentConformance": anlTestWrap(func(a []any) any { return anlIntentConformance(a[0], anlTestAt(a, 1), anlTestAt(a, 2)) }),
	}
	fns["thresholdsOf"] = anlTestWrap(func(a []any) any {
		out := anlThresholdsOf(anlToModel(a[0]), anlStr(a[1], "path"))
		return out
	})
	fns["maxExposure"] = anlTestWrap(func(a []any) any { return anlMaxExposure(a[0], anlTestAt(a, 1)) })
	fns["escalationSurface"] = anlTestWrap(func(a []any) any { return anlEscalationSurface(a[0], anlTestAt(a, 1)) })
	fns["delegationEnvelope"] = anlTestWrap(func(a []any) any { return anlDelegationEnvelope(a[0], anlTestAt(a, 1)) })
	fns["diffPolicies"] = anlTestWrap(func(a []any) any { return anlDiffPolicies(a[0], a[1], anlTestAt(a, 2)) })
	fns["diffGate"] = anlTestWrap(func(a []any) any { return anlDiffGate(a[0], anlTestAt(a, 1)) })
	fns["findWithBackend"] = anlTestWrap(func(a []any) any {
		return anlFindWithBackend(a[0], anlGet(a[1], "name"), anlGet(a[1], "result"))
	})
	fns["dagExposure"] = anlTestWrap(func(a []any) any { return anlDagExposure(a[0]) })
	fns["residual"] = anlTestWrap(func(a []any) any { return anlResidual(a[0], a[1], anlTestAt(a, 2)) })
	fns["residualPolicy"] = anlTestWrap(func(a []any) any { return anlResidualPolicy(a[0]) })
	fns["evaluateResidual"] = anlTestWrap(func(a []any) any { return anlEvaluateResidual(a[0], a[1]) })
	fns["whatMayIDo"] = anlTestWrap(func(a []any) any { return anlWhatMayIDo(a[0], a[1], anlTestAt(a, 2), anlTestAt(a, 3)) })
	fns["toFilter"] = anlTestWrap(func(a []any) any {
		return anlToFilter(anlResidual(a[0], a[1], anlTestAt(a, 2)), anlTestAt(a, 3))
	})
	fns["evalFilter"] = anlTestWrap(func(a []any) any { return anlEvalFilter(a[0], a[1]) })
	fns["toUcast"] = anlTestWrap(func(a []any) any { return anlToUcast(a[0]) })
	fns["evalUcast"] = anlTestWrap(func(a []any) any { return anlEvalUcast(a[0], a[1]) })
	fns["suggestNarrowing"] = anlTestWrap(func(a []any) any { return anlSuggestNarrowing(a[0], a[1], anlTestAt(a, 2)) })
	fns["signAccessRequest"] = anlTestWrap(func(a []any) any { return anlSignAccessRequest(a[0], anlTestKey(a[1].(string))) })
	fns["verifyAccessRequest"] = anlTestWrap(func(a []any) any { return anlVerifyAccessRequest(a[0], anlTestKeyed(anlTestAt(a, 1))) })
	fns["coverage"] = anlTestWrap(func(a []any) any { return anlCoverage(a[0], a[1], anlTestAt(a, 2)) })
	fns["coverageGate"] = anlTestWrap(func(a []any) any { return anlCoverageGate(a[0], anlTestAt(a, 1)) })
	fns["verbShapesFromActionDefs"] = anlTestWrap(func(a []any) any { return anlVerbShapesFromActionDefs(a[0]) })
	fns["verbShapes"] = anlTestWrap(func(a []any) any { return anlVerbShapes(a[0]) })
	fns["validatePolicyAgainstSchema"] = anlTestWrap(func(a []any) any { return anlValidatePolicyAgainstSchema(a[0], a[1], anlTestAt(a, 2)) })
	fns["policyTestsDoc"] = anlTestWrap(func(a []any) any { return anlPolicyTestsDoc(a[0], a[1]) })
	fns["runPolicyTests"] = anlTestWrap(func(a []any) any { return anlRunPolicyTests(a[0], a[1], anlTestAt(a, 2)) })
	fns["generateBoundaryTests"] = anlTestWrap(func(a []any) any { return anlGenerateBoundaryTests(a[0], anlTestAt(a, 1)) })
	fns["decideAll"] = anlTestWrap(func(a []any) any { return anlDecideAll(a[0], a[1]) })
	fns["signPolicyTests"] = anlTestWrap(func(a []any) any { return anlSignPolicyTests(a[0], anlTestKey(a[1].(string))) })
	fns["verifyPolicyTests"] = anlTestWrap(func(a []any) any { return anlVerifyPolicyTests(a[0], anlTestKeyed(anlTestAt(a, 1))) })
	fns["minimalFlip"] = anlTestWrap(func(a []any) any { return anlMinimalFlip(a[0], a[1], anlTestAt(a, 2)) })
	replayVectors(t, "ref-analyzer.json.gz", fns)
}
