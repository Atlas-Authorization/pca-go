package pca

// Replays the harness reference corpus: the self-measurement, the allowlisting attestation verifier and harness scenarios (plan
// inclusion, taint fold, trust budget, signing). The agent key is the Ed25519 seed sha256("atlas-pca-conformance/" + label); the
// nonce of the k-th build attempt is "n<k>"; the clock is constant between steps.

import (
	"errors"
	"fmt"
	"testing"
)

func hrnMapList(v any) []map[string]any {
	l, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]map[string]any, len(l))
	for i, x := range l {
		out[i], _ = x.(map[string]any)
	}
	return out
}

func hrnScenario(spec map[string]any) any {
	op := vecObj(spec["opts"])
	// scenario input, not the generator clock: the reference oracle injects this fixed T0 into its own clock and bakes it into the case data (token iat/exp, budget tau, grant times), so it must not follow the header clockMs (the Date.now default 1.7e12).
	t := connTestFloat(spec["t0"], 1_800_000_000_000)
	k := 0
	o := HarnessOptions{Grant: vecObj(op["grant"]), Plan: hrnMapList(op["plan"]), Budget: vecObj(op["budget"]), Now: func() float64 { return t },
		Nonce: func() string { n := fmt.Sprintf("n%d", k); k++; return n }}
	label, _ := op["label"].(string)
	o.AgentSeed = sbxTestSeed(label)
	o.Audience, _ = op["audience"].(string)
	if _, has := op["chain"]; has {
		o.Chain = hrnMapList(op["chain"])
		if o.Chain == nil {
			o.Chain = []map[string]any{}
		}
	}
	if p, ok := op["policy"].(map[string]any); ok {
		o.Policy = p
	}
	if b, ok := op["baseRisk"].(map[string]any); ok {
		o.BaseRisk = b
	}
	if _, has := op["ttlMs"]; has {
		x := int64(connTestFloat(op["ttlMs"], 0))
		o.TtlMs = &x
	}
	if m, ok := op["manifest"].([]any); ok {
		o.MeasurementManifest = append([]string{}, connStrListOrNil(m)...)
	}
	if a, ok := op["attestation"].(map[string]any); ok {
		o.Attestation = a
	}
	// the clock starts at the scenario's fixed time; steps move it
	t = 1_800_000_000_000
	h, err := NewHarness(o)
	if err != nil {
		return map[string]any{"$err": true}
	}
	outs := []any{}
	for _, si := range sliceOf(spec["steps"]) {
		st := vecObj(si)
		if st["op"] == "now" {
			t = connTestFloat(st["t"], t)
			outs = append(outs, nil)
			continue
		}
		orc := vecObj(st["oracle"])
		outs = append(outs, h.Step(func() (any, error) {
			switch orc["kind"] {
			case "throw":
				msg, _ := orc["msg"].(string)
				return nil, errors.New(msg)
			case "bad":
				return orc["v"], nil
			}
			return orc["c"], nil
		}))
	}
	meas, err := h.HarnessMeasurement()
	if err != nil {
		return map[string]any{"$err": true}
	}
	return map[string]any{"steps": outs, "budget": h.Budget(), "counter": jsNumber(float64(h.Counter())), "planRoot": h.PlanRoot(), "measurement": meas}
}

func TestHarnessReferenceVectors(t *testing.T) {
	replayVectors(t, "ref-harness.json.gz", map[string]vecFn{
		"consts": func(args []any) (any, error) {
			return map[string]any{"HARNESS_VERSION": HarnessVersion, "HARNESS_MODEL_ID": HarnessModelID, "ENFORCED_CHECKS": connAnyList(HarnessEnforcedChecks)}, nil
		},
		"computeHarnessMeasurement": func(args []any) (any, error) {
			return ComputeHarnessMeasurement(vecArg(args, 0), vecArg(args, 1), vecArg(args, 2))
		},
		"harnessAttest": func(args []any) (any, error) {
			hook, err := CreateHarnessAttestationVerifier(vecArg(args, 0))
			if err != nil {
				return nil, err
			}
			return hook(vecArg(args, 1)), nil
		},
		"harness": func(args []any) (any, error) { return hrnScenario(vecObj(vecArg(args, 0))), nil },
	})
}
