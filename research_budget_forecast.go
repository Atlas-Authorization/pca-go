package pca

import (
	"errors"
	"math"
)

// Budget forecaster and policy recommender (planning): forecast how the trust budget drains for a planned sequence of actions, and,
// inversely, recommend kappa/bMax to hit a target level of autonomy. Composes the simulator and the budget algebra. Pure.

// ForecastBudget forecasts a plan against a compiled policy: {steps, firstStepUpAt?, autonomousRisk, forcesCosign, cosignsNeeded,
// endBudget}. start is the clock the budget starts at; catalog may be nil (the built-in one).
func ForecastBudget(policy *CompiledPolicy, plan []map[string]any, catalog *Catalog, start float64) map[string]any {
	rep := SimulatePolicy(policy, plan, catalog, start)
	results, _ := rep["results"].([]any)
	steps := make([]any, 0, len(results))
	first := -1
	for i, ro := range results {
		r := rsMap(ro)
		a := rsMap(r["action"])
		steps = append(steps, map[string]any{"verb": a["verb"], "resource": a["resource"], "outcome": r["outcome"], "r": r["r"], "budgetAfter": r["budgetAfter"]})
		if first < 0 && r["outcome"] == "step_up" {
			first = i
		}
	}
	out := map[string]any{"steps": steps, "autonomousRisk": rep["autonomousRisk"], "forcesCosign": jsF(rep["stepUp"]) > 0,
		"cosignsNeeded": rep["stepUp"], "endBudget": rep["endBudget"]}
	if first >= 0 {
		out["firstStepUpAt"] = jsNumber(float64(first))
	}
	return out
}

// RecommendPolicy recommends the smallest trust budget bMax = n * r * kappa that lets an agent run targetActions actions of per-action
// risk perActionRisk (clamped to [1e-6, 1]) before a human co-sign is needed. kappa nil is 1. It errors on a non-positive kappa or a
// non-finite count or risk.
func RecommendPolicy(targetActions, perActionRisk float64, kappa *float64) (map[string]any, error) {
	k := 1.0
	if kappa != nil {
		k = *kappa
	}
	if math.IsNaN(k) || math.IsInf(k, 0) || k <= 0 {
		return nil, errors.New("recommendPolicy: kappa must be a positive finite number")
	}
	if math.IsNaN(targetActions) || math.IsInf(targetActions, 0) || math.IsNaN(perActionRisk) || math.IsInf(perActionRisk, 0) {
		return nil, errors.New("recommendPolicy: targetActions and perActionRisk must be finite numbers")
	}
	r := math.Max(1e-6, math.Min(1, perActionRisk))
	n := math.Max(0, targetActions)
	bMax := n * r * k
	return map[string]any{"kappa": rsN(k), "bMax": rsN(bMax), "autonomousBound": rsN(bMax / k),
		"rationale": "Σr ≤ bMax/κ = " + rsToFixed(bMax/k, 3) + " ≥ " + rsNumStr(n) + "×" + rsToFixed(r, 3) + " actions before a human co-sign"}, nil
}

// AutonomyBoundOf is the autonomy bound of a risk policy {bMax, kappa}: the total risk an agent can accrue autonomously,
// max(0, bMax) / kappa (0 when kappa is not positive; NaN for an absent bMax, as in the reference).
func AutonomyBoundOf(policy map[string]any) float64 {
	kappa, bMax := jsF(policy["kappa"]), jsF(policy["bMax"])
	if !(kappa > 0) {
		return 0
	}
	return math.Max(0, bMax) / kappa
}
