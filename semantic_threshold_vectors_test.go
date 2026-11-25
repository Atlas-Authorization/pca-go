package pca

import (
	"math"
	"testing"
)

// Replay of the semantic judge threshold against the reference (ref-semantic-threshold), every case: the judge statement and its
// signed message, verdict signing under ed25519, ml-dsa-65 and the hybrid (deterministic), the verdict digest and verification,
// the judge attestation gate, the k-of-n threshold with the attestation gate and key pins, the verifier hook and the risk
// contribution. A reference throw requires a refusal.
//
// The reference's legacy option that accepts an unpinned post-quantum key (allowUnboundPq) is NOT ported: the cases that the
// reference accepts only through it are asserted REFUSED here, with the count asserted.

// semHardware reads a hardware attestation result from its JSON form {ok, bound, measured?, reason?}.
func semHardware(v any) *HardwareResult {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	r := &HardwareResult{OK: m["ok"] == true, Bound: m["bound"] == true}
	r.Reason, _ = m["reason"].(string)
	r.Measured, _ = m["measured"].(map[string]any)
	return r
}

// semAttestation reads the gate {require, approved?, byJudge: {<judge key>: result}}: it resolves by the verdict's judge.
func semAttestation(v any) *SemanticAttestation {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	by, _ := m["byJudge"].(map[string]any)
	approved, _ := m["approved"].(map[string]any)
	return &SemanticAttestation{Require: m["require"] == true, Approved: approved, Resolve: func(verdict map[string]any) *HardwareResult {
		j, _ := verdict["judge"].(string)
		return semHardware(by[j])
	}}
}

func semOut(want, got any, ruled *int) bool {
	g := vecObj(got)
	if inner, has := g["ruled"]; has {
		if baseCanon(want) == baseCanon(inner) {
			return true
		}
		w := vecObj(want)
		if want == true || w["ok"] == true { // accepted by the reference only through the legacy option
			*ruled++
			return true
		}
		return false
	}
	return baseCanon(want) == baseCanon(got)
}

func TestSemanticThresholdMatchesTheReference(t *testing.T) {
	ruled := 0
	must := func(v any, err error) any {
		if err != nil {
			ixFail("%v", err)
		}
		return v
	}
	// a verdict check whose option accepts an unpinned key: report the Go answer and let the comparison apply the ruling
	ruling := func(pins any, got any) any {
		if ixM(pins)["allowUnboundPq"] == true {
			return map[string]any{"ruled": got}
		}
		return got
	}
	fns := map[string]vecFn{
		"constants": ixWrap(func(a []any) any {
			return map[string]any{"SEMANTIC_JUDGE_DOMAIN": ixSemanticJudgeDomain, "SCORE_SCALE": ixScoreScale}
		}),
		"quantizeScore": ixWrap(func(a []any) any { return IntentQuantizeScore(semNum(a[0])) }),
		"statementOf":   ixWrap(func(a []any) any { return must(StatementOf(ixM(a[0]))) }),
		"semanticJudgeMessage": ixWrap(func(a []any) any {
			if a[0] == nil { // the reference canonicalizes null itself
				return vecBytesOut(append([]byte(ixSemanticJudgeDomain), "null"...))
			}
			b, ok := SemanticJudgeMessage(ixM(a[0]))
			if !ok {
				ixFail("not canonicalizable")
			}
			return vecBytesOut(b)
		}),
		"verdictDigest": ixWrap(func(a []any) any { return must(VerdictDigest(a[0])) }),
		"signJudgeVerdict": ixWrap(func(a []any) any {
			secret, ok := qvBytes(a[0])
			if !ok {
				ixFail("secret is bytes")
			}
			key := must(KeyPairFromSeed(secret)).(*KeyPair)
			var suite *SuiteOpts
			if sm := ixM(ixArg(a, 2)); sm != nil {
				suite = &SuiteOpts{Alg: ixS(sm["alg"])}
				if seed, ok := qvBytes(sm["pqSeed"]); ok {
					suite.Pq = must(GeneratePqKeyPairFromSeed("ML-DSA-65", seed)).(*PqKeyPair)
				}
			}
			return must(SignJudgeVerdict(key, ixM(a[1]), suite))
		}),
		"verifyJudgeVerdict": ixWrap(func(a []any) any {
			return ruling(ixArg(a, 2), IntentVerifyJudgeVerdict(a[0], ixM(a[1]), ixM(ixArg(a, 2))))
		}),
		"verifyJudgeAttestation": ixWrap(func(a []any) any {
			return VerifyJudgeAttestation(ixS(a[0]), semHardware(ixArg(a, 1)), ixM(ixArg(a, 2)))
		}),
		"verifySemanticThreshold": ixWrap(func(a []any) any {
			opts := ixM(a[1])
			att := semAttestation(opts["attestation"])
			plain := map[string]any{}
			for k, v := range opts {
				if k != "attestation" {
					plain[k] = v
				}
			}
			r := VerifySemanticThreshold(a[0], plain, att)
			return ruling(opts, r) // an infinite cutoff is written in the {"$num"} form by the replay adapter
		}),
		"semanticVerifier": func(args []any) (any, error) {
			o := ixM(ixIn(vecArg(args, 0)))
			var keys []string
			for _, k := range ixL(o["judgeKeys"]) {
				keys = append(keys, ixS(k))
			}
			digestMode, _ := o["actionDigestMode"].(string)
			opts := SemanticVerifierOpts{JudgeKeys: keys, K: int(ixF(o["k"])), OptionalWhenAbsent: o["optionalWhenAbsent"] == true,
				Verdicts: func(ctx map[string]any) ([]any, bool) {
					l, ok := ctx["verdicts"].([]any)
					return l, ok
				},
				GoalCommitment: func(ctx map[string]any) (string, bool) {
					s, ok := ctx["goal"].(string)
					return s, ok
				},
				Attestation: func(ctx map[string]any) *SemanticAttestation { return semAttestation(ctx["attestation"]) }}
			if cal, ok := o["calibration"].(map[string]any); ok {
				opts.Calibration = cal
			}
			if len(digestMode) > 6 && digestMode[:6] == "fixed:" {
				d := digestMode[6:]
				opts.ActionDigest = func(map[string]any) string { return d }
			}
			hook := CreateSemanticVerifier(opts)
			var out []any
			for _, c := range ixL(vecArg(args, 1)) {
				raw := vecObj(c)
				ctx := map[string]any{"pcactn": raw["pcactn"]} // the action keeps its JSON numbers: it is hashed
				for _, k := range []string{"verdicts", "goal", "attestation"} {
					if v, has := raw[k]; has {
						ctx[k] = ixIn(v)
					}
				}
				r := hook(ctx)
				row := map[string]any{"enforced": r.Enforced}
				if r.Enforced {
					row["ok"] = r.OK
					if r.Reason != "" {
						row["reason"] = r.Reason
					}
				}
				out = append(out, row)
			}
			return out, nil
		},
		"semanticRiskContribution": ixWrap(func(a []any) any { return SemanticRiskContribution(semNum(a[0])) }),
	}
	cmp := map[string]func(want, got any) bool{}
	for _, name := range []string{"verifyJudgeVerdict", "verifySemanticThreshold"} {
		cmp[name] = func(want, got any) bool { return semOut(want, got, &ruled) }
	}
	replayAll(t, "ref-semantic-threshold.json.gz", 186, vecSeeded(fns), cmp, nil)
	if ruled != 2 {
		t.Fatalf("%d unpinned-key cases were refused, 2 are expected", ruled)
	}
}

// semNum is a JavaScript number argument: anything that is not a number is not finite (Number.isFinite does not coerce).
func semNum(v any) float64 {
	if f, ok := jsNum(v); ok {
		return f
	}
	return math.NaN()
}
