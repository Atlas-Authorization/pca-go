package pca

// Replays the ratchet reference corpus: deterministic functions compare exactly; the provers draw fresh randomness, so recorded
// proofs (valid, out of range, over budget, tampered) must reach the reference verdict, and prover refusals the reference code.

import (
	"encoding/base64"
	"errors"
	"math"
	"math/big"
	"testing"
)

// ratchetRevive turns {"$bytes"} into []byte and {"$bigint"} into *big.Int, recursively.
func ratchetRevive(v any) any {
	switch x := v.(type) {
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = ratchetRevive(e)
		}
		return out
	case map[string]any:
		if len(x) == 1 {
			if s, ok := x["$bytes"].(string); ok {
				if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
					return b
				}
			}
			if s, ok := x["$bigint"].(string); ok {
				if n, ok := new(big.Int).SetString(s, 10); ok {
					return n
				}
			}
		}
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[k] = ratchetRevive(e)
		}
		return out
	}
	return v
}

func ratchetBig(n *big.Int) any { return map[string]any{"$bigint": n.String()} }

// ratchetNum is a JS number argument; anything else is NaN (which every numeric check refuses, as Number.isInteger does).
func ratchetNum(v any) float64 {
	if _, b := v.(bool); b {
		return math.NaN()
	}
	if f, ok := jsNum(v); ok {
		return f
	}
	return math.NaN()
}

func ratchetBlind(v any) (*big.Int, error) {
	if b, ok := v.(*big.Int); ok {
		return b, nil
	}
	return nil, errors.New("Cannot mix BigInt and other types, use explicit conversions")
}

type ratchetThrowingStore struct{}

func (ratchetThrowingStore) Claim(string, string) (bool, string, error) {
	return false, "", errors.New("boom")
}

// ratchetSetPath is the corpus clonePath: a deep copy with path set to value ("__DEL__" deletes); an empty path names the
// member "undefined", as path[path.length - 1] does in JavaScript.
func ratchetSetPath(v any, path []any, value any) any {
	c := vecJSON(v)
	key := func(k any) string { return jsValueString(k) }
	last := any("undefined")
	var t any = c
	if len(path) > 0 {
		for _, k := range path[:len(path)-1] {
			switch x := t.(type) {
			case map[string]any:
				t = x[key(k)]
			case []any:
				i, ok := jsNum(k)
				if ok && i >= 0 && int(i) < len(x) {
					t = x[int(i)]
				} else {
					t = nil
				}
			default:
				t = nil
			}
		}
		last = path[len(path)-1]
	}
	switch x := t.(type) {
	case map[string]any:
		if value == "__DEL__" {
			delete(x, key(last))
		} else {
			x[key(last)] = value
		}
	case []any:
		if i, ok := jsNum(last); ok && i >= 0 && int(i) < len(x) && value != "__DEL__" {
			x[int(i)] = value
		}
	}
	return c
}

func ratchetScenario(spec map[string]any) []any {
	var state *RatchetState
	root := ""
	var sigs []any
	var store SpentLeafStore = &MemorySpentLeafStore{}
	if spec["store"] == "throws" {
		store = ratchetThrowingStore{}
	}
	out := []any{}
	ops, _ := spec["ops"].([]any)
	for _, o := range ops {
		s := vecObj(o)
		res, err := func() (any, error) {
			msg, _ := s["msg"].([]byte)
			switch s["op"] {
			case "derive":
				seed, _ := s["seed"].([]byte)
				d, err := DeriveRatchetRoot(seed, ratchetNum(s["depth"]))
				if err != nil {
					return nil, err
				}
				state, root = d, d.RootCommitment
				return map[string]any{"root": d.RootCommitment, "leafPubKeys": d.LeafPubKeys, "available": AvailableLeaves(d)}, nil
			case "sign":
				sig, next, err := SignAtLeaf(state, ratchetNum(s["leaf"]), msg)
				if err != nil {
					return nil, err
				}
				state = next
				sigs = append(sigs, sig)
				return map[string]any{"signature": sig}, nil
			case "avail":
				if state == nil {
					return nil, errors.New("no state")
				}
				return AvailableLeaves(state), nil
			case "isAvail":
				if state == nil {
					return nil, errors.New("no state")
				}
				return IsLeafAvailable(state, ratchetNum(s["leaf"])), nil
			case "verify", "once":
				ref, _ := jsNum(s["sigRef"])
				var sig any
				if int(ref) < len(sigs) {
					sig = sigs[int(ref)]
				}
				sets, _ := s["set"].([]any)
				for _, pv := range sets {
					p, _ := pv.([]any)
					path, _ := vecArg(p, 0).([]any)
					sig = ratchetSetPath(sig, path, vecArg(p, 1))
				}
				rc := root
				if s["root"] == "other" {
					rc = "other-root"
				}
				if s["op"] == "verify" {
					return VerifyLeafSignature(rc, s["leaf"], msg, sig), nil
				}
				return VerifyLeafSignatureOnce(rc, s["leaf"], msg, sig, store), nil
			}
			return nil, errors.New("bad op")
		}()
		if err != nil {
			var ce *CodedError
			if errors.As(err, &ce) && ce.Code != "" {
				out = append(out, map[string]any{"$err": ce.Code})
			} else {
				out = append(out, map[string]any{"$err": true})
			}
			continue
		}
		out = append(out, res)
	}
	return out
}

func TestRatchetVectors(t *testing.T) {
	authority := make([]byte, 32) // the recorded issueRiskCommitment cases are refusals: any 32-byte key reaches them
	big1 := func(f func(a []any) (*big.Int, error)) vecFn {
		return func(a []any) (any, error) {
			n, err := f(a)
			if err != nil {
				return nil, err
			}
			return ratchetBig(n), nil
		}
	}
	fns := map[string]vecFn{
		"leafNullifier": func(a []any) (any, error) {
			r, _ := vecArg(a, 0).(string)
			return LeafNullifier(r, vecArg(a, 1))
		},
		"counterToLeafIndex": func(a []any) (any, error) {
			return CounterToLeafIndex(ratchetNum(vecArg(a, 0)), ratchetNum(vecArg(a, 1)))
		},
		"leafIndexToCounter": func(a []any) (any, error) { return LeafIndexToCounter(ratchetNum(vecArg(a, 0))) },
		"leafIndexForAction": func(a []any) (any, error) {
			m, ok := vecArg(a, 0).(map[string]any)
			if !ok {
				return nil, errors.New("Cannot read properties of null (reading 'counter')")
			}
			return LeafIndexForAction(m, ratchetNum(vecArg(a, 1)))
		},
		"riskToUnits": big1(func(a []any) (*big.Int, error) { return RiskToUnits(ratchetNum(vecArg(a, 0))) }),
		"budgetCeilingUnits": big1(func(a []any) (*big.Int, error) {
			m, _ := vecArg(a, 0).(map[string]any)
			return BudgetCeilingUnits(m)
		}),
		"quantizer": func(a []any) (any, error) {
			var q RiskQuantizer
			out := []any{}
			l, _ := vecArg(a, 0).([]any)
			for _, r := range l {
				n, err := q.Next(ratchetNum(r))
				if err != nil {
					out = append(out, map[string]any{"$err": true})
				} else {
					out = append(out, ratchetBig(n))
				}
			}
			return append(out, ratchetBig(q.TotalUnits())), nil
		},
		"ratchet": func(a []any) (any, error) { return ratchetScenario(vecObj(vecArg(a, 0))), nil },
		"commitRisk": func(a []any) (any, error) {
			b, err := ratchetBlind(vecArg(a, 1))
			if err != nil { // the reference reads the risk first (nil here would mean a fresh blinding)
				if _, rerr := ratchetUnits(vecArg(a, 0)); rerr != nil {
					return nil, rerr
				}
				return nil, err
			}
			c, err := CommitRisk(vecArg(a, 0), b)
			if err != nil {
				return nil, err
			}
			return map[string]any{"commitment": c.Commitment, "blinding": ratchetBig(c.Blinding)}, nil
		},
		"addCommitments": func(a []any) (any, error) {
			l, ok := vecArg(a, 0).([]any)
			if !ok {
				return nil, errors.New("commitments is not iterable")
			}
			return AddCommitments(l)
		},
		"openCommitment": func(a []any) (any, error) {
			b, _ := vecArg(a, 2).(*big.Int)
			return OpenCommitment(vecArg(a, 0), vecArg(a, 1), b), nil
		},
		"verifyRiskRange": func(a []any) (any, error) { return VerifyRiskRange(vecArg(a, 0), vecArg(a, 1)), nil },
		"verifyBudget":    func(a []any) (any, error) { return VerifyBudget(vecArg(a, 0), vecArg(a, 1), vecArg(a, 2)), nil },
		"verifyBoundedBudget": func(a []any) (any, error) {
			return VerifyBoundedBudget(vecArg(a, 0), vecArg(a, 1), vecArg(a, 2), vecArg(a, 3)), nil
		},
		"proveBudget": func(a []any) (any, error) {
			risks, _ := vecArg(a, 0).([]any)
			bl, _ := vecArg(a, 1).([]any)
			blinds := make([]*big.Int, len(bl))
			for i, b := range bl {
				blinds[i], _ = b.(*big.Int)
			}
			return ProveBudget(risks, blinds, vecArg(a, 2))
		},
		"proveRiskRange": func(a []any) (any, error) {
			b, _ := vecArg(a, 1).(*big.Int) // nil: refused after the risk, as the reference orders it
			return ProveRiskRange(vecArg(a, 0), b)
		},
		"issueRiskCommitment": func(a []any) (any, error) {
			d, _ := vecArg(a, 1).(string)
			k := authority
			if vecArg(a, 2) == "short" {
				k = make([]byte, 3)
			}
			return IssueRiskCommitment(vecArg(a, 0), d, k)
		},
		"verifyRiskAttestation": func(a []any) (any, error) {
			return VerifyRiskAttestation(vecArg(a, 0), vecArg(a, 1), vecArg(a, 2)), nil
		},
		"verifyAttestedBudget": func(a []any) (any, error) {
			return VerifyAttestedBudget(vecArg(a, 0), vecArg(a, 1), vecArg(a, 2), vecArg(a, 3), vecArg(a, 4)), nil
		},
	}
	revived := make(map[string]vecFn, len(fns))
	for name, f := range fns {
		f := f
		revived[name] = func(a []any) (any, error) { return f(ratchetRevive(a).([]any)) }
	}
	replayVectors(t, "ref-ratchet.json.gz", vecSeeded(revived))
}
