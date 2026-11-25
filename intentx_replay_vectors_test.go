package pca

// Replays the corpora of the intent modules that are native without a learner: the schema-derived outcome space, signed statements,
// provenance and regret, classifier calibration and risk, the compiler pipeline, frame constraints, trajectory intent and the JIT
// coordinates. Cases that need the learner-bound entry points are replayed by their own files.

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"math"
	"strings"
	"testing"
)

var ixRpAmountPath = "action.params.amount"

func ixRpAmt(x any) float64 {
	if f, ok := ixM(ixM(x)["values"])[ixRpAmountPath].(float64); ok {
		return f
	}
	return 0
}

func ixRpCase(c map[string]any) IntentRegretCase {
	adm := map[string]func(any) bool{
		"all": func(any) bool { return true }, "none": func(any) bool { return false },
		"amountLe50": func(x any) bool { return ixRpAmt(x) <= 50 },
		"verbRefund": func(x any) bool { return ixM(x)["verb"] == "stripe.refund" },
	}
	util := map[string]func(any) float64{
		"amount": ixRpAmt, "negAmount": func(x any) float64 { return -ixRpAmt(x) }, "zero": func(any) float64 { return 0 },
		"nan": func(any) float64 { return math.NaN() },
		"amountPlusPrefer": func(x any) float64 {
			if ixM(ixM(x)["values"])["action.params.recipient"] == "bob" {
				return ixRpAmt(x) + 1000
			}
			return ixRpAmt(x)
		},
	}
	return IntentRegretCase{Feasible: ixL(c["feasible"]), Chosen: c["chosen"], Admits: adm[ixS(c["admits"])], Utility: util[ixS(c["utility"])]}
}

func TestIntentSchemaReferenceVectors(t *testing.T) {
	replayVectors(t, "ref-intent-schema.json.gz", map[string]vecFn{
		"deriveSchemaOmega":    ixWrap(func(a []any) any { return ixDeriveOmegaFromSchema(ixM(a[0])) }),
		"canonValue":           ixWrap(func(a []any) any { return ixCanonValue(ixM(a[0]), a[1]) }),
		"effectiveSensitivity": ixWrap(func(a []any) any { return ixEffectiveSensitivity(ixM(a[0]), ixM(ixArg(a, 1))) }),
		"verbReversibility":    ixWrap(func(a []any) any { return ixVerbReversibility(ixM(a[0])) }),
		"walletFloorOverrides": ixWrap(func(a []any) any { return ixWalletFloorOverrides(ixL(a[0]), ixM(ixArg(a, 1))) }),
	})
}

func TestIntentStatementReferenceVectors(t *testing.T) {
	replayVectorsSeeded(t, "ref-intent-statement.json.gz", map[string]vecFn{
		"signIntent":   ixWrap(func(a []any) any { return ixSignIntent(ixM(a[0]), ixS(a[1])) }),
		"verifyIntent": ixWrap(func(a []any) any { return ixVerifyIntent(a[0], ixM(ixArg(a, 1))) }),
		"intentRef":    ixWrap(func(a []any) any { return ixIntentRef(ixM(a[0])) }),
		"intentGoal": ixWrap(func(a []any) any {
			m, _ := ixArg(a, 1).(string)
			return IntentGoal(ixS(a[0]), m)
		}),
		"parseIntentGoal": ixWrap(func(a []any) any {
			g, ok := a[0].(string)
			if !ok {
				return nil
			}
			ref, mapDigest, ok := ParseIntentGoal(g)
			if !ok {
				return nil
			}
			if mapDigest != "" {
				return map[string]any{"intentRef": ref, "mapDigest": mapDigest}
			}
			return map[string]any{"intentRef": ref}
		}),
	})
}

func TestIntentProvenanceReferenceVectors(t *testing.T) {
	replayVectors(t, "ref-intent-provenance.json.gz", map[string]vecFn{
		"provenanceBanner": ixWrap(func(a []any) any {
			what := "value"
			if len(a) > 1 {
				what = ixS(a[1])
			}
			return ixProvenanceBanner(a[0], what)
		}),
		"isTainted":          ixWrap(func(a []any) any { return ixIsTainted(a[0]) }),
		"provenanceFriction": ixWrap(func(a []any) any { return ixProvenanceFriction(a[0], a[1], a[2]) }),
		"regret": ixWrap(func(a []any) any {
			c := ixRpCase(ixM(a[0]))
			admitted := c.Admits(c.Chosen)
			var best any
			bestU, found := math.Inf(-1), false
			for _, o := range c.Feasible {
				if !c.Admits(o) {
					continue
				}
				if u := c.Utility(o); u > bestU {
					bestU, best, found = u, o, true
				}
			}
			if !admitted || !found {
				return map[string]any{"regret": 0.0, "best": best, "admitted": admitted}
			}
			r, _ := ixWithinGrantRegret(c)
			return map[string]any{"regret": r, "best": best, "admitted": admitted}
		}),
		"report": ixWrap(func(a []any) any {
			var cases []IntentRegretCase
			for _, cv := range ixL(a[0]) {
				cases = append(cases, ixRpCase(ixM(cv)))
			}
			scale := 1.0
			if len(a) > 1 {
				scale = ixF(a[1])
			}
			return IntentRegretReport(cases, scale)
		}),
	})
}

func TestIntentClassifierReferenceVectors(t *testing.T) {
	replayVectors(t, "ref-intent-classifier.json.gz", map[string]vecFn{
		"calibrate": ixWrap(func(a []any) any {
			d := 0.05
			if len(a) > 2 {
				d = ixF(a[2])
			}
			return ixCalibrateConfusion(ixL(a[0]), ixL(a[1]), d)
		}),
		"confusionDigest":    ixWrap(func(a []any) any { return ixConfusionDigest(ixM(a[0])) }),
		"publishedErrorRate": ixWrap(func(a []any) any { return ixPublishedErrorRate(ixM(a[0])) }),
		"classifierCardNote": ixWrap(func(a []any) any { return ixClassifierCardNote(ixS(a[0]), ixM(a[1])) }),
		"riskArrays": ixWrap(func(a []any) any {
			switch a[0] {
			case "risk":
				return ixClassifierRisk(ixM(a[1]))
			case "sound":
				return ixLabelSound(ixM(a[1]))
			}
			return ixLabelSoundBound(ixM(a[1]), ixF(ixArg(a, 2)))
		}),
		"awareScenario": ixWrap(func(a []any) any {
			return ixMkMust(IntentClassifierAwareResidualRisk(ixRfMk(ixM(a[0]), ixM(a[1]), ixL(a[2])), ixL(a[3])))
		}),
		"jitScenario": ixWrap(func(a []any) any {
			return ixMkMust(IntentClassifierJitCells(ixRfMk(ixM(a[0]), ixM(a[1]), ixL(a[2])), ixM(a[3]), ixF(a[4])))
		}),
	})
}

func ixRpCompilers(specs []any) []IntentCompiler {
	var cs []IntentCompiler
	for _, sv := range specs {
		s := ixM(sv)
		id, fam := ixS(s["id"]), ixS(s["family"])
		switch s["kind"] {
		case "captured":
			if id == "" {
				id = "captured-slots"
			}
			cs = append(cs, IntentCapturedSlotsCompiler(id))
		case "fixed":
			pol := s["policy"]
			cs = append(cs, IntentFixedCompiler(id, fam, func(map[string]any) any { return pol }))
		case "throws":
			cs = append(cs, IntentCompiler{ID: id, Family: fam, Compile: func(map[string]any) (map[string]any, error) { return nil, errors.New("boom") }})
		default:
			raw, down := ixS(s["raw"]), s["kind"] == "slotsThrows"
			cs = append(cs, IntentCompiler{ID: id, Family: fam, Compile: func(in map[string]any) (map[string]any, error) {
				return ixTryMap(func() map[string]any {
					if down {
						ixFail("llm down")
					}
					r := ixParseSlotsJSON(raw, in["catalog"])
					return map[string]any{"compiler": id, "family": fam, "policy": ixSlotsToPolicy(ixM(r["slots"])), "slots": r["slots"], "notes": r["notes"], "raw": raw}
				})
			}})
		}
	}
	return cs
}

func TestIntentCompilersReferenceVectors(t *testing.T) {
	replayVectors(t, "ref-intent-compilers.json.gz", map[string]vecFn{
		"slotsPrompt":    ixWrap(func(a []any) any { return ixSlotsPrompt(ixS(a[0]), nil) }),
		"parseSlotsJSON": ixWrap(func(a []any) any { return ixParseSlotsJSON(ixS(a[0]), nil) }),
		"runScenario":    ixWrap(func(a []any) any { return IntentRunCompilers(ixM(a[0]), ixRpCompilers(ixL(a[1]))) }),
		"analyze":        ixWrap(func(a []any) any { return ixAnalyzeDisagreement(ixL(a[0]), ixM(ixArg(a, 1))) }),
		"flags":          ixWrap(func(a []any) any { return ixPanelFlags(ixAnalyzeDisagreement(ixL(a[0]), ixM(ixArg(a, 1)))) }),
		"anchors":        ixWrap(func(a []any) any { return ixCommitteeAnchors(ixL(a[0]), a[1]) }),
		"compareScenario": ixWrap(func(a []any) any {
			in := ixM(a[0])
			outs := IntentRunCompilers(in, ixRpCompilers(ixL(a[1])))
			o := ixCopyMap(ixM(ixArg(a, 2)))
			if ixTruthy(in["slots"]) {
				o["slots"] = in["slots"]
			}
			return ixAnalyzeDisagreement(outs, o)
		}),
	})
}

func TestIntentFramesReferenceVectors(t *testing.T) {
	replayVectors(t, "ref-intent-frames.json.gz", map[string]vecFn{
		"stateDigest": ixWrap(func(a []any) any { return ixStateDigest(ixArg(a, 0)) }),
		"snapshotState": ixWrap(func(a []any) any {
			keep := true
			if len(a) > 1 {
				keep = ixTruthy(a[1])
			}
			return ixSnapshotState(ixM(a[0]), keep)
		}),
		"checkFrame": ixWrap(func(a []any) any {
			r := ixCheckFrame(a[0], a[1], a[2], a[3], ixM(ixArg(a, 4)))
			ms := []any{}
			for _, m := range ixL(r["missing"]) {
				s := ixS(m)
				if len(s) >= 7 && s[:7] == "error: " && !(strings.HasPrefix(s, "error: spec, action")) {
					s = "error: error"
				}
				ms = append(ms, s)
			}
			r = ixCopyMap(r)
			r["missing"] = ms
			return r
		}),
		"applyScenario": ixWrap(func(a []any) any {
			l := ixRfMk(ixM(a[0]), ixM(a[1]), ixL(a[2]))
			res := ixMkMust(IntentApplyFrameReport(l, ixM(a[3]), a[4]))
			return map[string]any{"result": res, "metrics": l.Metrics()}
		}),
	})
}

func TestIntentTrajectoryReferenceVectors(t *testing.T) {
	grant := func(name any) func(string, []any) bool {
		return func(_ string, cell []any) bool {
			switch name {
			case "all":
				return true
			case "none":
				return false
			case "cell0":
				for _, c := range cell {
					if ixF(c) != 0 {
						return false
					}
				}
				return true
			}
			return len(cell) > 0 && ixF(cell[0]) <= 1
		}
	}
	replayVectors(t, "ref-intent-trajectory.json.gz", map[string]vecFn{
		"dimKindOf":           ixWrap(func(a []any) any { return ixDimKindOf(ixS(a[0])) }),
		"accDimPath":          ixWrap(func(a []any) any { return ixAccDimPath(ixS(a[0])) }),
		"monDimPath":          ixWrap(func(a []any) any { return ixMonDimPath(ixS(a[0])) }),
		"trajectoryHarmRange": ixWrap(func(a []any) any { return ixTrajectoryHarmRange(a[0], a[1]) }),
		"augment":             ixWrap(func(a []any) any { return ixAugmentOmega(ixM(a[0]), ixM(a[1]), ixM(ixArg(a, 2))) }),
		"liftScenario": ixWrap(func(a []any) any {
			tilde := ixAugmentOmega(ixM(a[0]), ixM(a[1]), ixM(a[2]))
			lifted := ixLiftAction(tilde, ixM(a[1]), ixL(a[3]), ixM(a[4]), ixM(ixArg(a, 5)))
			var cell any
			if lifted != nil {
				if vs := ixFindVerb(tilde, lifted["verb"]); vs != nil {
					if c := ixCellOf(vs, lifted); c != nil {
						cell = map[string]any{"verb": vs["verb"], "cell": c}
					}
				}
			}
			var out any // a nil lifted action is null, not {}
			if lifted != nil {
				out = lifted
			}
			return map[string]any{"lifted": out, "cell": cell}
		}),
		"stepScenario": ixWrap(func(a []any) any {
			tilde := ixAugmentOmega(ixM(a[0]), ixM(a[1]), ixM(a[2]))
			return ixStepTrajectory(tilde, ixM(a[1]), ixL(a[3]), ixM(a[4]), grant(a[5]), ixM(ixArg(a, 6)))
		}),
		"defaultAccumulators": ixWrap(func(a []any) any { return ixDefaultAccumulators(ixM(a[0]), ixM(a[1])) }),
		"describeAccCell": func(args []any) (any, error) {
			if len(args) > 4 && args[4] == "bracket" {
				return nil, vecSkip("custom number formatter is not a native option")
			}
			return ixWrap(func(a []any) any { return ixDescribeAccCell(ixM(a[0]), ixIdx(a[1]), ixS(a[2]), ixArg(a, 3)) })(args)
		},
	})
}

// ixJitLearner builds the learner the reference scenarios build: omega, learner options, then each observation in order.
func ixJitLearner(omega, mapOpts map[string]any, obs []any) *IntentLearner {
	l, err := NewIntentLearner(omega, mapOpts, nil)
	if err != nil {
		panic(err)
	}
	for _, x := range obs {
		o := ixM(x)
		if _, err := l.Observe(map[string]any{"verb": o["verb"], "values": o["values"]}, ixF(o["y"]), ixS(o["source"]), nil); err != nil {
			panic(err)
		}
	}
	return l
}

func ixJitCeilings(names []any) []func(vs, o map[string]any) bool {
	var out []func(vs, o map[string]any) bool
	for _, n := range names {
		switch n {
		case "all":
			out = append(out, func(vs, o map[string]any) bool { return true })
		case "none":
			out = append(out, func(vs, o map[string]any) bool { return false })
		case "amountLe60":
			out = append(out, func(vs, o map[string]any) bool {
				a, isNum := ixM(o["values"])["action.params.amount"].(float64)
				return !isNum || a <= 60
			})
		case "notGmail":
			out = append(out, func(vs, o map[string]any) bool { return o["verb"] != "gmail.send" })
		default:
			panic("unknown ceiling " + ixS(n))
		}
	}
	return out
}

func ixJitDeltaOf(a []any) (*IntentLearner, *IntentLearner) {
	prev := ixJitLearner(ixM(a[0]), ixM(a[1]), ixL(a[2]))
	next := ixJitLearner(ixM(a[0]), ixM(a[1]), append(append([]any{}, ixL(a[2])...), ixL(a[3])...))
	return prev, next
}

func TestIntentJitCoordsReferenceVectors(t *testing.T) {
	replayVectorsSeeded(t, "ref-intent-jit.json.gz", map[string]vecFn{
		"cellCoords":     ixWrap(func(a []any) any { return ixCellCoords(ixM(a[0]), ixL(a[1])) }),
		"cellFromCoords": ixWrap(func(a []any) any { return ixCellFromCoords(ixM(a[0]), a[1]) }),
		"visitScenario": ixWrap(func(a []any) any {
			l := ixJitLearner(ixM(a[0]), ixM(a[1]), ixL(a[2]))
			r, err := IntentDecideVisit(l, ixM(a[3]), ixM(a[4]), ixJitCeilings(ixL(a[5])), a[6] == true)
			if err != nil {
				panic(err)
			}
			return r
		}),
		"deltaScenario": ixWrap(func(a []any) any {
			prev, next := ixJitDeltaOf(a)
			d, err := IntentDeltaCells(prev, next)
			if err != nil {
				panic(err)
			}
			cells := map[string]any{}
			for k, v := range d {
				row := make([]any, len(v))
				for i, x := range v {
					row[i] = float64(x)
				}
				cells[k] = row
			}
			return map[string]any{"cells": cells, "predicates": IntentDeltaPredicates(next.omega, d)}
		}),
		"requiredScenario": ixWrap(func(a []any) any {
			omega, inp := ixM(a[0]), ixM(a[3])
			vs := IntentVsOf(omega, map[string]any{"verb": a[1]})
			in := map[string]any{"vs": vs, "cell": a[2]}
			for k, v := range inp {
				in[k] = v
			}
			site, err := KeyPairFromSeedB64u(ixS(a[4]))
			if err != nil {
				panic(err)
			}
			signed, err := IntentSignedIntentRequired(in, "site-1", site, nil)
			if err != nil {
				panic(err)
			}
			return map[string]any{"body": IntentRequiredBody(in), "signed": signed}
		}),
		"walletScenario": ixWrap(func(a []any) any {
			omega, inp, mutation := ixM(a[0]), ixM(a[1]), ixS(a[2])
			in := map[string]any{"vs": IntentVsOf(omega, map[string]any{"verb": "stripe.refund"}), "cell": []any{1.0, 0.0}}
			for k, v := range inp {
				in[k] = v
			}
			site, err := KeyPairFromSeedB64u(ixS(a[7]))
			if err != nil {
				panic(err)
			}
			signed, err := IntentSignedIntentRequired(in, "site-1", site, nil)
			if err != nil {
				panic(err)
			}
			body := ixM(vecJSON(signed)) // numbers stay JSON numbers, the form the wallet verifier reads
			dig := func(x string) string {
				h := sha256.Sum256([]byte(x))
				return base64.RawURLEncoding.EncodeToString(h[:])
			}
			var b any = body
			switch mutation {
			case "coords":
				ixM(body["cell"])["coords"].(map[string]any)["action.params.amount"] = []any{jsNumber(2), jsNumber(2)}
			case "verb":
				ixM(body["cell"])["verb"] = "gmail.send"
			case "sig":
				v := ixS(ixM(body["sig"])["value"])
				ixM(body["sig"])["value"] = v[:len(v)-2] + "AA"
			case "kid":
				ixM(body["sig"])["kid"] = "other"
			case "session":
				body["session"] = dig("other")
			case "action":
				body["action_digest"] = dig("other")
			case "null":
				b = nil
			}
			keys := []any{map[string]any{"kid": "site-1", "alg": "ed25519", "pk": site.Public}}
			return IntentWalletCheckIntentRequired(b, keys, a[3], ixS(a[5]), ixS(a[6]), omega, ixM(a[4]), ixM(inp["pcactn"]))
		}),
		"mintScenario": ixWrap(func(a []any) any {
			prev, next := ixJitDeltaOf(a)
			args := ixM(a[4])
			princ, err := KeyPairFromSeedB64u(ixS(a[5]))
			if err != nil {
				panic(err)
			}
			prevGrant := ixM(args["prevGrant"])
			in := SessionGrantInput{Principal: princ, Holder: ixS(args["holder"]), Session: ixS(args["session"]), Seq: int64(ixF(args["seq"])),
				Root: ixS(args["root"]), MapDigest: ixS(args["mapDigest"]), Salt: ixS(args["salt"])}
			if v, has := args["prev"]; has {
				in.Prev = ixS(v)
			}
			if v, has := args["mapForm"]; has {
				in.MapForm = ixS(v)
			}
			if v, has := args["caveats"]; has {
				in.Caveats = ixL(v)
			}
			grant, salt, cells, ok, err := IntentMintDelta(prev, next, in, prevGrant)
			if err != nil {
				panic(err)
			}
			if !ok {
				return nil
			}
			return map[string]any{"grant": grant, "goalSalt": salt, "cells": float64(cells)}
		}),
	})
}
