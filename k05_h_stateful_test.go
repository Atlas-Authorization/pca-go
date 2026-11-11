package pca

import (
	"sort"
	"testing"
)

// The shared stateful layer (conformance/stateful-vectors.json): ordered sequences against ONE store: replay, counter ordering,
// revocation mid-sequence and trust-budget depletion, checked against the TypeScript reference.

// statefulStore gives every counter stream the sequence's initial budget (absent: B = 0, deny-metered) the first time it is read.
type statefulStore struct {
	*MemoryStateStore
	initial map[string]any // nil: none
	now     *int64
}

func (s statefulStore) Budget(key string) (map[string]any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if b, has := s.budgets[key]; has {
		return cloneBudget(b), nil
	}
	init := s.initial
	if init == nil {
		init = map[string]any{"B": 0.0, "tau": float64(*s.now), "asOf": float64(*s.now)}
	}
	if s.budgets == nil {
		s.budgets = map[string]map[string]any{}
	}
	s.budgets[key] = cloneBudget(init)
	return cloneBudget(init), nil
}

func TestStatefulVectors(t *testing.T) {
	doc := load(t, "stateful-vectors.json")
	seqs := doc["stateful"].([]any)
	if len(seqs) == 0 {
		t.Fatal("no sequences")
	}
	for _, x := range seqs {
		seq := x.(map[string]any)
		t.Run(seq["name"].(string), func(t *testing.T) {
			setup := seq["setup"].(map[string]any)
			grants := map[string]map[string]any{}
			for _, g := range setup["grants"].([]any) {
				gm := g.(map[string]any)
				grants[gm["id"].(string)] = gm
			}
			var plan []map[string]any
			for _, n := range setup["plan_nodes"].([]any) {
				plan = append(plan, n.(map[string]any))
			}
			risk, _ := setup["risk"].(map[string]any)
			revoked := map[string]bool{}
			var now int64
			store := statefulStore{MemoryStateStore: NewMemoryStateStore(), now: &now}
			if b, has := setup["initial_budget"].(map[string]any); has {
				store.initial = b
			}
			for i, y := range seq["steps"].([]any) {
				st := y.(map[string]any)
				if st["op"] == "revoke" {
					revoked[st["id"].(string)] = true
					continue
				}
				now = num(st["now"])
				p := st["pcactn"].(map[string]any)
				action := p["action"].(map[string]any)
				stParams, _ := st["params"].(map[string]any)
				in := AuthorizeInput{
					Operation:    &Operation{Verb: action["verb"].(string), Resource: action["resource"].(string), Params: stParams},
					Audience:     setup["audience"].(string),
					ResolveGrant: func(ref string) (map[string]any, error) { return grants[ref], nil },
					StateStore:   store,
					IsRevoked: func(pc, _ map[string]any) (bool, error) {
						chain, _ := pc["cap_chain"].([]any)
						for _, c := range chain {
							if id, _ := c.(map[string]any)["id"].(string); revoked[id] {
								return true, nil
							}
						}
						return false, nil
					},
					Now:  now,
					Risk: func(*Operation, map[string]any, map[string]any) (map[string]any, error) { return risk, nil },
					Context: func(map[string]any) (*AuthorizeContext, error) {
						return &AuthorizeContext{Plan: plan, PlanAuthorized: true}, nil
					},
					ArgProvenance: harnessProv(),
				}
				got := Authorize(p, in)
				var failed []string
				for name, status := range got.Checks {
					if status == "fail" {
						failed = append(failed, name)
					}
				}
				sort.Strings(failed)
				exp := st["expect"].(map[string]any)
				want := []string{}
				for _, f := range exp["failed"].([]any) {
					want = append(want, f.(string))
				}
				sort.Strings(want)
				if got.Allow != exp["allow"].(bool) || len(failed) != len(want) || (len(want) > 0 && failed[0] != want[0]) {
					t.Errorf("step %d: allow=%v failed=%v (%v), want allow=%v failed=%v", i, got.Allow, failed, got.Reasons, exp["allow"], want)
				}
			}
		})
	}
}
