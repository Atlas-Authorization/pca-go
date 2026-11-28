package pca

import (
	"math"
	"testing"
)

// Replay of the policy debugger against the reference (ref-policy-debug): explainRisk, explainDecision, applyDelta, counterfactual
// and auditPCActn. In the vectors a non-finite number is the object {"$num": "NaN" | "Infinity" | "-Infinity"}.

// pdvIn replaces every {"$num": ...} object by its float64, in place (the maps keep their recorded member order).
func pdvIn(v any) any {
	switch t := v.(type) {
	case map[string]any:
		if _, is := t["$num"]; is && len(t) == 1 {
			return stoNum(t)
		}
		for k, x := range t {
			t[k] = pdvIn(x)
		}
	case []any:
		for i, x := range t {
			t[i] = pdvIn(x)
		}
	}
	return v
}

// pdvOut is the JSON tree of a result with every non-finite float64 written as {"$num": ...}.
func pdvOut(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, x := range t {
			out[k] = pdvOut(x)
		}
		recordKeyOrder(out, jsKeys(t))
		return out
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = pdvOut(x)
		}
		return out
	case float64:
		switch {
		case math.IsNaN(t):
			return map[string]any{"$num": "NaN"}
		case math.IsInf(t, 1):
			return map[string]any{"$num": "Infinity"}
		case math.IsInf(t, -1):
			return map[string]any{"$num": "-Infinity"}
		}
	}
	return v
}

func pdvDelta(v any) CounterfactualDelta {
	m := vecObj(v)
	d := CounterfactualDelta{Label: vecStr(m, "label"), Risk: vecObj(m["risk"]), Budget: vecObj(m["budget"]), CaveatContext: vecObj(m["caveatContext"]),
		RFloor: bvOptNum(m["rFloor"]), Now: bvOptNum(m["now"])}
	d.HumanCosign = jsTruthy(m["humanCosign"])
	if hm, ok := m["humanCosign"].(map[string]any); ok {
		d.HumanCosign, d.HumanCosignFull = true, hm["full"] == true
	}
	return d
}

func TestPolicyDebugMatchesTheReference(t *testing.T) {
	count := 0
	num := func(m map[string]any, k string) float64 {
		if f, ok := m[k].(float64); ok {
			return f
		}
		return jsF(m[k])
	}
	wrap := func(f func(a []any) (any, error)) vecFn {
		return func(a []any) (any, error) {
			count++
			for i := range a {
				a[i] = pdvIn(a[i])
			}
			v, err := f(a)
			return pdvOut(v), err
		}
	}
	replayVectorsCmp(t, "ref-policy-debug.json.gz", map[string]vecFn{
		"explainRisk": wrap(func(a []any) (any, error) {
			i, w := vecObj(a[0]), vecObj(a[1])
			floor := math.NaN()
			if f, ok := vecArg(a, 2).(float64); ok {
				floor = f
			} else if f, ok := jsNum(vecArg(a, 2)); ok {
				floor = f
			}
			return ExplainRisk(RiskInputs{SemanticDistance: num(i, "semanticDistance"), Reversibility: num(i, "reversibility"), BlastRadius: num(i, "blastRadius"),
				Taint: num(i, "taint"), Confidence: num(i, "confidence"), Age: num(i, "age")},
				RiskWeights{Alpha: num(w, "alpha"), Beta: num(w, "beta"), Gamma: num(w, "gamma"), Delta: num(w, "delta"), Epsilon: num(w, "epsilon"), Zeta: num(w, "zeta")},
				floor).JSON(), nil
		}),
		"explainDecision": wrap(func(a []any) (any, error) { return ExplainPolicyDecision(vecObj(a[0])).JSON(), nil }),
		"applyDelta":      wrap(func(a []any) (any, error) { return ApplyDelta(vecObj(a[0]), pdvDelta(vecArg(a, 1))), nil }),
		"counterfactual": wrap(func(a []any) (any, error) {
			raw, _ := vecArg(a, 1).([]any)
			deltas := make([]CounterfactualDelta, len(raw))
			for i, d := range raw {
				deltas[i] = pdvDelta(d)
			}
			out := Counterfactual(vecObj(a[0]), deltas).JSON()
			for i, o := range out["outcomes"].([]any) {
				o.(map[string]any)["delta"] = raw[i] // the reference echoes the delta object it was given
			}
			return out, nil
		}),
		"auditPCActn": wrap(func(a []any) (any, error) {
			o := vecObj(a[2])
			aud, hasAud := o["audience"].(string)
			_, audNamed := o["audience"]
			if audNamed && !hasAud { // audience null accepts any audience: verified here under the PCActn's own, the audience check is then set aside
				aud, _ = vecObj(a[0])["aud"].(string)
			}
			audit, err := AuditPCActn(vecObj(a[0]), vecObj(a[1]), vecObj(o["grant"]), int64(jsF(o["nowEpoch"])), aud,
				VerifyOptions{InsecureSkipPlanRootCheck: o["insecureSkipPlanRootCheck"] == true})
			if err != nil {
				return nil, err
			}
			checks := map[string]string{"wire": "fail"} // a wire failure reports nothing else
			if audit.Verify.Checks["wire"] {
				checks = gwStatuses(audit.Verify, "not-enforced")
			}
			verify := map[string]any{"allow": audit.Verify.Allow, "checks": checks}
			if audit.Verify.Reason != "" {
				verify["reason"] = audit.Verify.Reason
			}
			return map[string]any{"explanation": audit.Explanation.JSON(), "verify": verify, "audience": map[string]any{"named": audNamed, "given": hasAud}}, nil
		}),
	}, map[string]func(want, got any) bool{
		// the verdict (allow, reason, the whole per-check map) and the explanation must be the reference's. The typed audience has no
		// form for "accept any" (the reference reports the audience check as not enforced: compared without that one check) nor for
		// "none given" (same verdict and checks; the reference words the refusal for its optional argument)
		"auditPCActn": func(want, got any) bool {
			w, g := vecObj(want), vecObj(got)
			wv, gv, aud := vecObj(w["verify"]), vecObj(g["verify"]), vecObj(g["audience"])
			if baseCanon(w["explanation"]) != baseCanon(g["explanation"]) || wv["allow"] != gv["allow"] {
				return false
			}
			wc, gc := vecObj(wv["checks"]), vecObj(gv["checks"])
			switch {
			case aud["given"] == true:
				return baseCanon(wv) == baseCanon(gv)
			case aud["named"] == true:
				if wc["audience"] != "not-enforced" || gc["audience"] != "pass" {
					return false
				}
				delete(wc, "audience")
				delete(gc, "audience")
				return baseCanon(wv) == baseCanon(gv)
			}
			return baseCanon(wc) == baseCanon(gc)
		},
	})
	if count != 553 {
		t.Fatalf("replayed %d cases, the corpus has 553", count)
	}
}
