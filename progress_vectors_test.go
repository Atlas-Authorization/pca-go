package pca

import (
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"testing"
)

// Replay of proof of progress against the reference (ref-progress), every case: the potentials and the registry, the goal commitment,
// state, step and anchor digests, the tracker (self-reported and observed steps, guards, budget), step and trajectory verification
// (every denial), the attested state source and its verifier hook, state attestations and signed steps. A reference refusal
// requires a refusal (a tracker refusal with its denial code). A reference "$err" list entry only requires an operation refusal.
//
// The reference's legacy option that accepts an unpinned post-quantum key (allowUnboundPq) is NOT ported: the cases the reference
// accepts only through it are asserted REFUSED here, with the count asserted.

// progKind is the potential a spec names.
func progKind(k string) (PotentialFn, error) {
	switch {
	case k == "l1-feature-v1":
		return L1FeaturePotential, nil
	case k == "dag-remaining-v1":
		return DagRemainingPotential, nil
	case k == "dag-weighted-v1":
		return DagWeightedPotential, nil
	case strings.HasPrefix(k, "const:"):
		n, _ := strconv.ParseFloat(k[6:], 64)
		return func(any, any) (float64, error) { return n, nil }, nil
	case k == "v":
		return func(_, s any) (float64, error) { return jsF(progMember(s, "v")), nil }, nil
	case k == "throws":
		return func(any, any) (float64, error) { return 0, errors.New("potential boom") }, nil
	case k == "negative":
		return func(any, any) (float64, error) { return -1, nil }, nil
	case k == "frac":
		return func(any, any) (float64, error) { return 0.5, nil }, nil
	case k == "nan":
		return func(any, any) (float64, error) { return math.NaN(), nil }, nil
	case k == "big":
		return func(any, any) (float64, error) { return 9007199254740992, nil }, nil
	}
	return nil, errors.New("bad potential kind " + k)
}

func progRegistrySpec(spec any) (*PotentialRegistry, error) {
	s, _ := spec.(map[string]any)
	if s == nil {
		return nil, nil
	}
	pots, _ := s["potentials"].([]any)
	if s["mode"] == "record" {
		rec := map[string]PotentialSpec{}
		for _, p := range pots {
			e := p.([]any)
			fn, err := progKind(e[1].(string))
			if err != nil {
				return nil, err
			}
			emb := ""
			if len(e) > 2 {
				emb, _ = e[2].(string)
			}
			rec[e[0].(string)] = PotentialSpec{Fn: fn, Embedder: emb}
		}
		return PotentialRegistryFrom(rec)
	}
	r := NewPotentialRegistry()
	for _, p := range pots {
		e := p.([]any)
		fn, err := progKind(e[1].(string))
		if err != nil {
			return nil, err
		}
		emb := ""
		if len(e) > 2 {
			emb, _ = e[2].(string)
		}
		if err := r.Register(e[0].(string), fn, emb); err != nil {
			return nil, err
		}
	}
	return r, nil
}

func progGuardSpec(g any) StepGuard {
	s, ok := g.(string)
	if !ok {
		return nil
	}
	switch {
	case s == "allow":
		return func(StepTransition) bool { return true }
	case s == "throws":
		return func(StepTransition) bool { panic("guard boom") }
	case s == "deny", s == "truthy": // the reference allows only the value true, a truthy string is a denial
		return func(StepTransition) bool { return false }
	case strings.HasPrefix(s, "action:"):
		return func(t StepTransition) bool { return t.ActionDigest != s[7:] }
	case strings.HasPrefix(s, "seq:"):
		n, _ := strconv.Atoi(s[4:])
		return func(t StepTransition) bool { return t.Seq != n }
	case strings.HasPrefix(s, "after-v:"):
		n, _ := strconv.ParseFloat(s[8:], 64)
		return func(t StepTransition) bool {
			v, isNum := jsNum(progMember(t.After, "v"))
			return !(isNum && v == n)
		}
	}
	return nil
}

func progPins(v any) map[string]string {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	out := map[string]string{}
	for k, x := range m {
		out[k], _ = x.(string)
	}
	return out
}

func progAVOpts(v any) AttestedStateVerifierOpts {
	m, _ := v.(map[string]any)
	o := AttestedStateVerifierOpts{PqPins: progPins(m["pqPins"])}
	if tk, ok := m["trustedKeys"].(map[string]any); ok {
		o.TrustedKeys = map[string]string{}
		for k, x := range tk {
			o.TrustedKeys[k], _ = x.(string)
		}
	}
	o.Attestations, _ = m["attestations"].([]any)
	return o
}

func progAttSpec(a any) StateAttestationVerifier {
	if s, ok := a.(string); ok {
		switch s {
		case "allow":
			return func(map[string]any) bool { return true }
		case "throws":
			return func(map[string]any) bool { panic("att boom") }
		}
		return func(map[string]any) bool { return false } // deny, and the truthy string the reference does not accept
	}
	if m, ok := a.(map[string]any); ok {
		return AttestedStateVerifier(progAVOpts(m["attested"]))
	}
	return nil
}

type progOpts struct {
	step   VerifyStepOptions
	traj   VerifyTrajectoryOptions
	holder *string
}

func progStrPtr(m map[string]any, k string) *string {
	if s, ok := m[k].(string); ok {
		return &s
	}
	return nil
}

func progParseOpts(v any) (progOpts, error) {
	var o progOpts
	m, _ := v.(map[string]any)
	if m == nil {
		return o, nil
	}
	if x, has := m["expectedSeq"]; has {
		f := jsF(x)
		o.step.ExpectedSeq = &f
	}
	o.step.ExpectedPrev = progStrPtr(m, "expectedPrev")
	o.step.ExpectedActionDigest = progStrPtr(m, "expectedActionDigest")
	o.step.ExpectedBeforeDigest = progStrPtr(m, "expectedBeforeDigest")
	o.step.ExpectedAfterDigest = progStrPtr(m, "expectedAfterDigest")
	o.holder = progStrPtr(m, "expectedHolder")
	reg, err := progRegistrySpec(m["registry"])
	if err != nil {
		return o, err
	}
	o.step.Registry, o.traj.Registry = reg, reg
	o.step.Guard, o.traj.Guard = progGuardSpec(m["guard"]), progGuardSpec(m["guard"])
	if l, ok := m["trustedStateSources"].([]any); ok {
		ts := make([]string, 0, len(l))
		for _, x := range l {
			s, _ := x.(string)
			ts = append(ts, s)
		}
		o.step.TrustedStateSources, o.traj.TrustedStateSources = ts, ts
	}
	if b, ok := m["requireAttestedState"].(bool); ok {
		o.step.RequireAttestedState, o.traj.RequireAttestedState = &b, &b
	}
	o.step.Attestation, o.traj.Attestation = progAttSpec(m["attestation"]), progAttSpec(m["attestation"])
	if x, has := m["initial"]; has {
		o.traj.Initial, o.traj.HasInitial = x, true
	}
	o.traj.InitialDigest = progStrPtr(m, "initialDigest")
	if l, ok := m["expectedActionDigests"].([]any); ok {
		o.traj.ExpectedActionDigests = make([]string, 0, len(l))
		for _, x := range l {
			s, _ := x.(string)
			o.traj.ExpectedActionDigests = append(o.traj.ExpectedActionDigests, s)
		}
	}
	return o, nil
}

func progStepOut(r VerifyStepResult) map[string]any {
	if r.OK {
		return map[string]any{"ok": true, "charge": jsNumber(r.Charge)}
	}
	return map[string]any{"ok": false, "reason": r.Reason}
}

func progTrajOut(r TrajectoryResult) map[string]any {
	if r.OK {
		return map[string]any{"ok": true, "spent": jsNumber(r.Spent), "remaining": jsNumber(r.Remaining), "reached": r.Reached,
			"finalPotential": jsNumber(r.FinalPotential), "steps": jsNumber(float64(r.Steps)), "head": r.Head}
	}
	return map[string]any{"ok": false, "reason": r.Reason, "at": jsNumber(float64(r.At))}
}

func progProveOut(r ProveResult) map[string]any {
	if r.OK {
		return map[string]any{"ok": true, "step": r.Step, "spent": jsNumber(r.Spent), "remaining": jsNumber(r.Remaining)}
	}
	return map[string]any{"ok": false, "reason": r.Reason, "stepUp": r.StepUp}
}

func progErrOut(err error) map[string]any { return map[string]any{"$err": err.Error()} }

// progNormErr makes every {"$err": text} entry compare by presence only.
func progNormErr(v any) any {
	switch t := v.(type) {
	case map[string]any:
		if _, ok := t["$err"]; ok && len(t) == 1 {
			return map[string]any{"$err": "x"}
		}
		m := make(map[string]any, len(t))
		for k, x := range t {
			m[k] = progNormErr(x)
		}
		recordKeyOrder(m, jsKeys(t))
		return m
	case []any:
		a := make([]any, len(t))
		for i, x := range t {
			a[i] = progNormErr(x)
		}
		return a
	}
	return v
}

func progCmpErrs(want, got any) bool {
	return baseCanon(progNormErr(want)) == baseCanon(progNormErr(got))
}

// progSource is a StateSource built from a spec, with a way to change its world.
type progSource struct {
	StateSource
	set func(any) error
}

type progLiar struct {
	mem  *InMemoryStateSource
	kind string
}

func (l *progLiar) ID() string { return l.mem.ID() }
func (l *progLiar) Observe(r StateObservationRequest) (*StateObservation, error) {
	switch l.kind {
	case "throws":
		return nil, errors.New("source boom")
	case "null":
		return nil, nil
	}
	ob, err := l.mem.Observe(r)
	if err != nil {
		return nil, err
	}
	switch l.kind {
	case "liar-digest":
		ob.StateDigest = strings.Repeat("x", 43)
	case "liar-source":
		ob.Source = "someone-else"
	}
	return ob, nil
}

func progSeedKey(v any) []byte {
	s, ok := v.(string)
	if !ok {
		return nil
	}
	b, _ := base64.RawURLEncoding.DecodeString(s)
	return b
}

func progMakeSource(spec any) (*progSource, error) {
	s, _ := spec.(map[string]any)
	id, _ := s["id"].(string)
	kind, _ := s["kind"].(string)
	initial := s["initial"]
	if kind == "attested" {
		world, err := progSnapshot(initial)
		if err != nil {
			return nil, err
		}
		o := AttestedStateSourceOpts{ID: id, SignerSecret: progSeedKey(s["signerSecret"]),
			ObserveState: func(StateObservationRequest) (any, error) { return world, nil }}
		if alg, ok := s["alg"].(string); ok {
			o.Suite = &SuiteOpts{Alg: alg}
		}
		a, err := NewAttestedStateSource(o)
		if err != nil {
			return nil, err
		}
		return &progSource{StateSource: a, set: func(n any) error { w, err := progSnapshot(n); world = w; return err }}, nil
	}
	mem, err := NewInMemoryStateSource(initial, id)
	if err != nil {
		return nil, err
	}
	if kind == "memory" {
		return &progSource{StateSource: mem, set: mem.Apply}, nil
	}
	return &progSource{StateSource: &progLiar{mem: mem, kind: kind}, set: mem.Apply}, nil
}

func progUnbound(att any, pin any) bool {
	pm, _ := pin.(map[string]any)
	a, _ := att.(map[string]any)
	alg, has := a["alg"]
	return pm["allowUnboundPq"] == true && has && alg != "ed25519"
}

func TestProgressMatchesTheReference(t *testing.T) {
	dec := func(a []any, i int) any { return scDecode(vecArg(a, i)) }
	str := func(s string, err error) (any, error) { return s, err }
	commitOf := func(a []any, i int) string { s, _ := vecArg(a, i).(string); return s }
	unbound, lastUnbound := 0, false
	fns := map[string]vecFn{
		"constants": func([]any) (any, error) {
			return map[string]any{"PROGRESS_VERSION": jsNumber(ProgressVersion), "PROGRESS_SIG_DOMAIN": ProgressSigDomain,
				"TRAJECTORY_ANCHOR_DOMAIN": TrajectoryAnchorDomain, "STATE_ATTESTATION_DOMAIN": StateAttestationDomain}, nil
		},
		"l1FeaturePotential": func(a []any) (any, error) {
			f, err := L1FeaturePotential(dec(a, 0), dec(a, 1))
			return jsNumber(f), err
		},
		"dagRemainingPotential": func(a []any) (any, error) {
			f, err := DagRemainingPotential(dec(a, 0), dec(a, 1))
			return jsNumber(f), err
		},
		"dagWeightedPotential": func(a []any) (any, error) {
			f, err := DagWeightedPotential(dec(a, 0), dec(a, 1))
			return jsNumber(f), err
		},
		"registryOps": func(a []any) (any, error) {
			ops, _ := vecArg(a, 0).([]any)
			var r *PotentialRegistry
			out := []any{}
			for _, o := range ops {
				op := o.([]any)
				res := any(nil)
				var err error
				switch op[0] {
				case "new":
					r = NewPotentialRegistry()
				case "defaults":
					r = NewDefaultPotentialRegistry()
				case "default-frozen":
					r = DefaultPotentials
				case "from":
					rec := map[string]PotentialSpec{}
					for id, v := range op[1].(map[string]any) {
						var spec PotentialSpec
						if k, isStr := v.(string); isStr {
							spec.Fn, err = progKind(k)
						} else {
							vm := v.(map[string]any)
							spec.Fn, err = progKind(vm["fn"].(string))
							spec.Embedder, _ = vm["embedder"].(string)
						}
						rec[id] = spec
					}
					if err == nil {
						r, err = PotentialRegistryFrom(rec)
					}
				case "register":
					id, isStr := op[1].(string)
					fn, kerr := progKind(op[2].(string))
					emb, embOK := "", true
					if len(op) > 3 && op[3] != nil {
						emb, embOK = op[3].(string)
					}
					switch {
					case r != nil && r.frozen:
						err = errors.New("registry is frozen")
					case !isStr:
						err = errors.New("potential id: 1..128 chars")
					case kerr != nil:
						err = kerr
					case !embOK:
						err = errors.New("embedder must be a string")
					default:
						err = r.Register(id, fn, emb)
					}
				case "get":
					id, _ := op[1].(string)
					if s, ok := r.Get(id); ok {
						res = map[string]any{"embedder": s.Embedder}
					}
				case "has":
					id, _ := op[1].(string)
					res = r.Has(id)
				case "ids":
					res = orOut(r.IDs())
				case "freeze":
					r.Freeze()
				}
				if err != nil {
					out = append(out, progErrOut(err))
				} else {
					out = append(out, res)
				}
			}
			return out, nil
		},
		"goalDigest": func(a []any) (any, error) { return str(ProgressGoalDigest(dec(a, 0))) },
		"commitGoal": func(a []any) (any, error) { return ProgressCommitGoal(dec(a, 0)) },
		"verifyGoalCommitment": func(a []any) (any, error) {
			return ProgressVerifyGoalCommitment(dec(a, 0), dec(a, 1)), nil
		},
		"stateDigest": func(a []any) (any, error) { return str(ProgressStateDigest(dec(a, 0))) },
		"trajectoryHead": func(a []any) (any, error) {
			l, _ := vecArg(a, 0).([]any)
			return ProgressTrajectoryHead(l), nil
		},
		"progressStepDigest": func(a []any) (any, error) { return ProgressStepDigest(vecArg(a, 0)) },
		"trajectoryAnchorCommit": func(a []any) (any, error) {
			s, ok1 := vecArg(a, 0).(string)
			h, ok2 := vecArg(a, 1).(string)
			if !ok1 || !ok2 {
				return nil, errors.New("trajectoryAnchorCommit: salt and head must be non-empty strings")
			}
			return str(TrajectoryAnchorCommit(s, h))
		},
		"verifyTrajectoryAnchor": func(a []any) (any, error) {
			c, ok0 := vecArg(a, 0).(string)
			s, ok1 := vecArg(a, 1).(string)
			h, ok2 := vecArg(a, 2).(string)
			return ok0 && ok1 && ok2 && VerifyTrajectoryAnchor(c, s, h), nil
		},
		"anchorTrajectoryHead": func(a []any) (any, error) {
			steps, _ := vecArg(a, 0).([]any)
			salt, _ := vecArg(a, 1).(string)
			prior, _ := vecArg(a, 2).([]any)
			log := NewMerkleLog()
			for _, c := range prior {
				s, _ := c.(string)
				if _, err := log.AppendCommitment(s); err != nil {
					return nil, err
				}
			}
			an, err := AnchorTrajectoryHead(log, steps, &salt)
			if err != nil {
				return nil, err
			}
			return map[string]any{"head": an.Head, "salt": an.Salt, "commit": an.Commit, "index": jsNumber(float64(an.Index)), "ledgerHead": an.LedgerHead}, nil
		},
		"verifyStateAttestation": func(a []any) (any, error) {
			pin, _ := vecArg(a, 2).(map[string]any)
			lastUnbound = progUnbound(vecArg(a, 0), pin)
			return VerifyStateAttestation(vecArg(a, 0), vecArg(a, 1), progPins(pin["pqPins"])), nil
		},
		"attestedStateVerifier": func(a []any) (any, error) {
			step, ok := vecArg(a, 1).(map[string]any)
			if !ok {
				return false, nil
			}
			return AttestedStateVerifier(progAVOpts(vecArg(a, 0)))(step), nil
		},
		"attestedSource": func(a []any) (any, error) {
			src, err := progMakeSource(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			obs := []any{}
			reqs, _ := vecArg(a, 1).([]any)
			for _, r := range reqs {
				rm, _ := r.(map[string]any)
				ob, err := src.Observe(StateObservationRequest{ActionDigest: vecStr(rm, "action_digest"), GoalCommitment: vecStr(rm, "goal_commitment"), PriorDigest: vecStr(rm, "prior_digest")})
				if err != nil {
					obs = append(obs, progErrOut(err))
					continue
				}
				obs = append(obs, map[string]any{"state": ob.State, "state_digest": ob.StateDigest, "source": ob.Source, "evidence": ob.Evidence})
			}
			var atts any
			if as, ok := src.StateSource.(*AttestedStateSource); ok {
				l := []any{}
				for _, x := range as.Attestations() {
					l = append(l, x)
				}
				atts = l
			}
			return map[string]any{"observations": obs, "attestations": atts}, nil
		},
		"tracker": func(a []any) (any, error) {
			goal := dec(a, 0)
			commitment, isStr := vecArg(a, 1).(string)
			if !isStr {
				d, err := ProgressGoalDigest(goal)
				if err != nil {
					return nil, err
				}
				commitment = d
			}
			reg, err := progRegistrySpec(vecArg(a, 3))
			if err != nil {
				return nil, err
			}
			var srcs []*progSource
			sl, _ := vecArg(a, 5).([]any)
			for _, s := range sl {
				ps, err := progMakeSource(s)
				if err != nil {
					return nil, err
				}
				srcs = append(srcs, ps)
			}
			tr, err := NewProgressTracker(goal, commitment, dec(a, 2), reg, TrackerOptions{Guard: progGuardSpec(vecArg(a, 4))})
			if err != nil {
				return nil, err
			}
			out := []any{}
			ops, _ := vecArg(a, 6).([]any)
			for _, o := range ops {
				op := o.([]any)
				switch op[0] {
				case "step":
					act, isStr := op[2].(string)
					if !isStr {
						out = append(out, progProveOut(ProveResult{Reason: DenyMalformed}))
					} else {
						out = append(out, progProveOut(tr.Step(scDecode(op[1]), act)))
					}
				case "stepObserved":
					idx, _ := jsNum(op[1])
					act, isStr := op[2].(string)
					if !isStr {
						out = append(out, progProveOut(ProveResult{Reason: DenyMalformed}))
					} else {
						out = append(out, progProveOut(tr.StepObserved(srcs[int(idx)], act)))
					}
				case "apply":
					idx, _ := jsNum(op[1])
					if err := srcs[int(idx)].set(op[2]); err != nil {
						out = append(out, progErrOut(err))
					} else {
						out = append(out, nil)
					}
				case "steps":
					l := []any{}
					for _, s := range tr.Steps() {
						l = append(l, s)
					}
					out = append(out, l)
				case "state":
					out = append(out, tr.State())
				case "currentStateDigest":
					out = append(out, tr.CurrentStateDigest())
				case "spent":
					out = append(out, jsNumber(tr.Spent()))
				case "remaining":
					out = append(out, jsNumber(tr.Remaining()))
				case "reached":
					if r, err := tr.Reached(); err != nil {
						out = append(out, progErrOut(err))
					} else {
						out = append(out, r)
					}
				default:
					return nil, fmt.Errorf("unknown tracker op %v", op[0])
				}
			}
			return out, nil
		},
		"verifyProgressStep": func(a []any) (any, error) {
			o, err := progParseOpts(vecArg(a, 3))
			if err != nil {
				return nil, err
			}
			return progStepOut(VerifyProgressStep(dec(a, 0), commitOf(a, 1), dec(a, 2), o.step)), nil
		},
		"verifyTrajectory": func(a []any) (any, error) {
			o, err := progParseOpts(vecArg(a, 3))
			if err != nil {
				return nil, err
			}
			return progTrajOut(VerifyTrajectory(dec(a, 0), commitOf(a, 1), dec(a, 2), o.traj)), nil
		},
		"verifySignedProgressStep": func(a []any) (any, error) {
			o, err := progParseOpts(vecArg(a, 3))
			if err != nil {
				return nil, err
			}
			return progStepOut(VerifySignedProgressStep(dec(a, 0), commitOf(a, 1), dec(a, 2), VerifySignedStepOptions{VerifyStepOptions: o.step, ExpectedHolder: o.holder})), nil
		},
		"verifySignedTrajectory": func(a []any) (any, error) {
			o, err := progParseOpts(vecArg(a, 3))
			if err != nil {
				return nil, err
			}
			return progTrajOut(VerifySignedTrajectory(dec(a, 0), commitOf(a, 1), dec(a, 2), VerifySignedTrajectoryOptions{VerifyTrajectoryOptions: o.traj, ExpectedHolder: o.holder})), nil
		},
		"signProgressStep": func(a []any) (any, error) {
			var seed []byte
			if m, ok := vecArg(a, 1).(map[string]any); ok {
				seed = progSeedKey(m["$bytes"])
			}
			kp, err := KeyPairFromSeed(seed)
			if err != nil {
				return nil, err
			}
			step, _ := vecArg(a, 0).(map[string]any)
			holder, _ := vecArg(a, 2).(string)
			return SignProgressStepAs(step, kp, holder)
		},
	}
	cmp := map[string]func(want, got any) bool{
		"registryOps": progCmpErrs,
		"tracker":     progCmpErrs,
		"verifyStateAttestation": func(want, got any) bool {
			if lastUnbound && want == true {
				unbound++
				return got == false // accepted by the reference only through the unpinned-key opt-out: refused here
			}
			return baseCanon(want) == baseCanon(got)
		},
	}
	replayAll(t, "ref-progress.json.gz", 723, vecSeeded(fns), cmp, nil)
	if unbound != 2 {
		t.Fatalf("expected the 2 corpus cases accepted only through the unpinned post-quantum key opt-out, saw %d", unbound)
	}
}
