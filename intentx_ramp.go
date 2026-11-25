package pca

// Trust ramp and drift, the learner-free parts: the signal labels, the narrow starting configuration of a learner that will
// be ramped, and a one-sided Bernoulli CUSUM that freezes widening on drift.

import (
	"errors"
	"math"
)

// IntentSignalLabel is 1 for a confirming runtime signal, else 0.
func IntentSignalLabel(s string) int {
	if s == "jit-approve" || s == "principal-confirm" {
		return 1
	}
	return 0
}

func ixNarrowStart(omega, slots, opts map[string]any) map[string]any {
	inSlots := map[string]bool{}
	for _, v := range ixL(slots["verbs"]) {
		inSlots[ixS(v)] = true
	}
	slotMass, otherMass := 0.5, 0.95
	if opts["slotNullMass"] != nil {
		slotMass = ixF(opts["slotNullMass"])
	}
	if opts["otherNullMass"] != nil {
		otherMass = ixF(opts["otherNullMass"])
	}
	nm := map[string]any{}
	for _, vv := range ixL(omega["verbs"]) {
		v := ixS(ixM(vv)["verb"])
		if inSlots[v] {
			nm[v] = slotMass
		} else {
			nm[v] = otherMass
		}
	}
	return map[string]any{"eta": 0.0, "tau": 1.0, "nullMass": nm}
}

// IntentDriftState is the state of a drift detector.
type IntentDriftState struct {
	Statistic   float64
	Alarm       bool
	Informative int
	Divergences int
}

// IntentDriftDetector is a one-sided Bernoulli CUSUM over negative signals about actions inside the grant.
type IntentDriftDetector struct {
	rho0, rho1, h float64
	s             IntentDriftState
}

// NewIntentDriftDetector builds a detector; zero rho0 / rho1 / h take the defaults (0.02, 0.25, ln 100).
func NewIntentDriftDetector(rho0, rho1, h float64) (*IntentDriftDetector, error) {
	o := map[string]any{}
	if rho0 != 0 {
		o["rho0"] = rho0
	}
	if rho1 != 0 {
		o["rho1"] = rho1
	}
	if h != 0 {
		o["h"] = h
	}
	return ixNewDrift(o)
}

func ixNewDrift(o map[string]any) (*IntentDriftDetector, error) {
	d := &IntentDriftDetector{rho0: ixFOr(o["rho0"], 0.02), rho1: ixFOr(o["rho1"], 0.25), h: ixFOr(o["h"], DetLn(100))}
	if !(0 < d.rho0 && d.rho0 < d.rho1 && d.rho1 < 1) {
		return nil, errors.New("DriftDetector: need 0 < rho0 < rho1 < 1")
	}
	if !(d.h > 0) {
		return nil, errors.New("DriftDetector: h must be positive")
	}
	return d, nil
}

// Update feeds one signal about an action that was inside the grant: diverged is true for a negative signal.
func (d *IntentDriftDetector) Update(diverged bool) IntentDriftState {
	var inc float64
	if diverged {
		inc = DetLn(d.rho1 / d.rho0)
	} else {
		inc = DetLn((1 - d.rho1) / (1 - d.rho0))
	}
	st := math.Max(0, d.s.Statistic+inc)
	n := d.s
	n.Statistic = st
	n.Alarm = d.s.Alarm || st >= d.h
	n.Informative++
	if diverged {
		n.Divergences++
	}
	d.s = n
	return n
}

// State is the current state.
func (d *IntentDriftDetector) State() IntentDriftState { return d.s }

// Reset clears the statistic and the alarm.
func (d *IntentDriftDetector) Reset() { d.s = IntentDriftState{} }

func (s IntentDriftState) toJSON() map[string]any {
	return map[string]any{"statistic": s.Statistic, "alarm": s.Alarm, "informative": float64(s.Informative), "divergences": float64(s.Divergences)}
}
