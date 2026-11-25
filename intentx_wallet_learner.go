package pca

// The wallet over an intent learner: the grant view a question channel reads, and the mass a released population prior admits.

import "fmt"

// IntentLearnerView is a grant view over a learner, with an optional ceiling predicate (true = inside every ceiling).
type IntentLearnerView struct {
	l      *IntentLearner
	inside func(verb string, idx []int) bool
}

// NewIntentLearnerView builds the view; inside may be nil (no ceiling).
func NewIntentLearnerView(l *IntentLearner, inside func(verb string, idx []int) bool) *IntentLearnerView {
	return &IntentLearnerView{l: l, inside: inside}
}

func (v *IntentLearnerView) outcome(verb string, idx []int) map[string]any {
	vs := ixMaFindVerb(v.l.omega, verb)
	if vs == nil {
		ixFail("learnerView: unknown verb %s", verb)
	}
	cell := make([]any, len(idx))
	for i, x := range idx {
		cell[i] = float64(x)
	}
	return ixCellRep(vs, cell)
}

// P is the posterior acceptance of a cell.
func (v *IntentLearnerView) P(verb string, idx []int) (p float64, err error) {
	r, err := ixTry(func() any { return v.l.Acceptance(v.outcome(verb, idx)) })
	if err != nil {
		return 0, err
	}
	return r.(float64), nil
}

// Vetoed reports whether the cell was refused at run time.
func (v *IntentLearnerView) Vetoed(verb string, idx []int) (bool, error) {
	r, err := ixTry(func() any { return v.l.IsVetoed(v.outcome(verb, idx)) })
	if err != nil {
		return false, err
	}
	return r.(bool), nil
}

// OutsideCeiling reports whether a ceiling excludes the cell (false without a ceiling predicate).
func (v *IntentLearnerView) OutsideCeiling(verb string, idx []int) bool {
	return v.inside != nil && !v.inside(verb, idx)
}

// Confirmed are the cells inside the learner's grant.
func (v *IntentLearnerView) Confirmed() []any {
	out := []any{}
	for _, cv := range v.l.Cells() {
		if c := ixM(cv); c["inGrant"] == true {
			out = append(out, map[string]any{"verb": c["verb"], "idx": c["cell"]})
		}
	}
	return out
}

// WalletPriorAdmittedPpm is the mass (ppm) of cells admitted only because of the population prior: in the grant with the prior,
// not without it, after the same observations. Zero at tau = 1 under noise-free answers. base are plain learner options.
func WalletPriorAdmittedPpm(omega, base map[string]any, observations []map[string]any, prior *WalletPopulationPrior) (float64, error) {
	r, err := ixTry(func() any {
		wom, err := WalletOmegaFromJSON(omega)
		if err != nil {
			panic(err)
		}
		rest := ixCopyMap(base)
		delete(rest, "priorMix")
		without, err := ReplayIntentLearner(omega, rest, nil, observations)
		if err != nil {
			panic(err)
		}
		withOpts := ixCopyMap(rest)
		withOpts["priorMix"] = map[string]any{"beta": prior.Beta}
		hooks := &IntentLearnerHooks{PriorMixWeight: func(vs map[string]any, has func(int) bool) float64 {
			wv := wom.Verb(ixS(vs["verb"]))
			if wv == nil {
				panic(fmt.Errorf("unknown verb %s", ixS(vs["verb"])))
			}
			w, err := prior.Weight(wv, has)
			if err != nil {
				panic(err)
			}
			return w
		}}
		with, err := ReplayIntentLearner(omega, withOpts, hooks, observations)
		if err != nil {
			panic(err)
		}
		a, b := without.Cells(), with.Cells()
		mass := 0.0
		for i, cv := range b {
			c := ixM(cv)
			if c["inGrant"] == true && ixM(a[i])["inGrant"] != true {
				mass += ixF(c["mass"])
			}
		}
		return ixMkRound(mass * ixPPM)
	})
	if err != nil {
		return 0, err
	}
	return r.(float64), nil
}
