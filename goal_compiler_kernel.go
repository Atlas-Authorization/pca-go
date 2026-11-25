//go:build pcagoalkernel

package pca

import (
	"github.com/Atlas-Authorization/pca-go/goalkernel"
)

func goalToKernel(t GoalTape) goalkernel.Tape {
	out := make(goalkernel.Tape, len(t))
	for i, x := range t {
		out[i] = goalkernel.Tok{Tag: x.Tag, Int: x.Int, Str: x.Str}
	}
	return out
}

func goalFromKernel(t goalkernel.Tape) GoalTape {
	out := make(GoalTape, len(t))
	for i, x := range t {
		out[i] = GoalTok{Tag: x.Tag, Int: x.Int, Str: x.Str}
	}
	return out
}

func goalMust[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func goalStrsAny(xs []string) []any {
	out := make([]any, len(xs))
	for i, s := range xs {
		out[i] = s
	}
	return out
}

// goalTypecheck: type reasons of a goal against an ontology; [] = well typed.
func goalTypecheck(goal, ont any) []any {
	return goalStrsAny(goalMust(goalkernel.Typecheck(goalToKernel(goalEncodeGoal(goal)), goalToKernel(goalEncodeOntology(ont)))))
}

// goalCompileGoal: {ok: true, policy} or {ok: false, reasons}. Ill-typed goals are rejected, never coerced.
func goalCompileGoal(goal, ont any) map[string]any {
	r := goalMust(goalkernel.CompileGoal(goalToKernel(goalEncodeGoal(goal)), goalToKernel(goalEncodeOntology(ont))))
	if r.OK {
		return map[string]any{"ok": true, "policy": goalDecodePolicy(goalFromKernel(r.Policy))}
	}
	return map[string]any{"ok": false, "reasons": goalStrsAny(r.Reasons)}
}

func goalDecideGoal(goal, ont, act, hist any) string {
	return goalMust(goalkernel.DecideGoal(goalToKernel(goalEncodeGoal(goal)), goalToKernel(goalEncodeOntology(ont)),
		goalToKernel(goalEncodeAct(act)), goalToKernel(goalEncodeHist(hist))))
}

// goalDecidePolicy: {ok:false, reasons} or {ok:true, decision, witness (nil unless allow), witnessChecked}.
func goalDecidePolicy(goal, ont, act, hist any) map[string]any {
	d := goalMust(goalkernel.DecidePolicy(goalToKernel(goalEncodeGoal(goal)), goalToKernel(goalEncodeOntology(ont)),
		goalToKernel(goalEncodeAct(act)), goalToKernel(goalEncodeHist(hist))))
	if !d.OK {
		return map[string]any{"ok": false, "reasons": goalStrsAny(d.Reasons)}
	}
	var w any
	if d.Witness != nil {
		w = map[string]any{"gid": d.Witness.Gid, "bids": goalStrsAny(d.Witness.Bids)}
	}
	return map[string]any{"ok": true, "decision": d.Decision, "witness": w, "witnessChecked": d.WitnessChecked}
}

// goalRenderTape: the card as a token tape (lossless: goalDecodeGoal(goalRenderTape(g)) equals g).
func goalRenderTape(goal any) GoalTape {
	return goalFromKernel(goalMust(goalkernel.RenderTape(goalToKernel(goalEncodeGoal(goal)))))
}
