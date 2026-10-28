package pca

import (
	"encoding/json"
	"errors"
	"math"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// Plan lifecycle (T10): replays plan-vectors.json scenario by scenario (the roots are Merkle roots of the plan-node leaves,
// so a match proves the commitment equals the reference's), then concurrency and the Authorize wiring.

func nodesOf(v any) []map[string]any {
	arr, _ := v.([]any)
	out := make([]map[string]any, len(arr))
	for i, n := range arr {
		out[i], _ = n.(map[string]any)
	}
	return out
}

func transitionJSON(t *testing.T, r PlanTransition) any {
	if r.OK {
		return map[string]any{"ok": true, "record": jsonOf(t, r.Record)}
	}
	return map[string]any{"ok": false, "state": string(r.State), "reason": r.Reason}
}

func approvalOf(v any) *PlanApproval {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	a := &PlanApproval{}
	a.By, _ = m["by"].(string)
	if x, has := m["expiresAt"]; has {
		f := math.NaN() // a present non-number (null) is not a time
		if g, ok := jsNum(x); ok {
			f = g
		}
		a.ExpiresAt = &f
	}
	return a
}

func TestPlanVectors(t *testing.T) {
	doc := load(t, "plan-vectors.json")
	scs := grows(t, doc, "scenarios")
	if len(scs) != 12 {
		t.Fatalf("scenarios %d", len(scs))
	}
	for _, sc := range scs {
		t.Run(sc["name"].(string), func(t *testing.T) {
			var now int64
			opts := PlanRegistryOptions{Now: func() int64 { return now }}
			switch sc["validator"] {
			case "accept":
				opts.Validator = func(PlanRecord) (PlanValidation, error) { return PlanValidation{OK: true}, nil }
			case "refuse":
				opts.Validator = func(PlanRecord) (PlanValidation, error) { return PlanValidation{Reason: "node outside the grant"}, nil }
			case "throw":
				opts.Validator = func(PlanRecord) (PlanValidation, error) { return PlanValidation{}, errors.New("policy down") }
			}
			reg := NewPlanRegistry(opts)
			steps, expect := sc["steps"].([]any), sc["expect"].([]any)
			if len(steps) != len(expect) {
				t.Fatalf("steps %d expect %d", len(steps), len(expect))
			}
			for i, st := range steps {
				s := st.(map[string]any)
				now = num(s["at"])
				grant, _ := s["grant"].(string)
				root, _ := s["root"].(string)
				var got any
				switch s["op"] {
				case "draft":
					got = transitionJSON(t, reg.Draft(grant, nodesOf(s["nodes"])))
				case "validate":
					got = transitionJSON(t, reg.Validate(grant, root))
				case "commit":
					got = transitionJSON(t, reg.Commit(grant, root))
				case "authorize":
					got = transitionJSON(t, reg.Authorize(grant, root, approvalOf(s["approval"])))
				case "revoke":
					got = transitionJSON(t, reg.Revoke(grant, root, s["reason"].(string)))
				case "status":
					got = jsonOf(t, reg.Status(grant, root, now))
				case "check":
					o := PlanCheckOptions{Now: now}
					o.NodeID, _ = s["node_id"].(string)
					if op, ok := s["operation"].(map[string]any); ok {
						o.Operation = &Operation{Verb: op["verb"].(string), Resource: op["resource"].(string)}
						o.Operation.Params, _ = op["params"].(map[string]any)
					}
					got = jsonOf(t, reg.Check(grant, root, o))
				case "is_plan_authorized":
					got = reg.IsPlanAuthorized(grant, root)
				case "context":
					if pc := reg.Context(grant, root, now); pc != nil {
						got = jsonOf(t, pc)
					}
				default:
					t.Fatalf("op %v", s["op"])
				}
				if g, w := canonOf(t, got), canonOf(t, expect[i]); g != w {
					t.Fatalf("step %d (%v):\n got %s\nwant %s", i, s["op"], g, w)
				}
			}
		})
	}
}

func demoNodes() []map[string]any {
	return []map[string]any{{"id": "n1", "verb": "orders.read", "resource": "/orders/1"}}
}

// Of N concurrent claims of one transition exactly one wins; the rest see the new state.
func TestPlanRegistryConcurrentClaimsOneWinner(t *testing.T) {
	for name, kv := range map[string]AtomicKV{"memory": NewMemoryAtomicKV()} {
		t.Run(name, func(t *testing.T) {
			reg := NewPlanRegistry(PlanRegistryOptions{KV: kv, Now: func() int64 { return 1000 }})
			d := reg.Draft("g", demoNodes())
			if !d.OK {
				t.Fatal(d.Reason)
			}
			root := d.Record.Root
			if v := reg.Validate("g", root); !v.OK {
				t.Fatal(v.Reason)
			}
			if c := reg.Commit("g", root); !c.OK {
				t.Fatal(c.Reason)
			}
			for _, step := range []struct {
				name string
				do   func() PlanTransition
			}{
				{"authorize", func() PlanTransition { return reg.Authorize("g", root, &PlanApproval{By: "p"}) }},
				{"revoke", func() PlanTransition { return reg.Revoke("g", root, "x") }},
			} {
				var wins int32
				var wg sync.WaitGroup
				start := make(chan struct{})
				for i := 0; i < 64; i++ {
					wg.Add(1)
					go func() {
						defer wg.Done()
						<-start
						if step.do().OK {
							atomic.AddInt32(&wins, 1)
						}
					}()
				}
				close(start)
				wg.Wait()
				if wins != 1 {
					t.Fatalf("%s: %d winners, want exactly 1", step.name, wins)
				}
			}
			if s := reg.Status("g", root, 0); s.State != PlanRevoked || s.Executable {
				t.Fatalf("%+v", s)
			}
		})
	}
}

func TestPlanRegistryDraftConcurrentOneWinner(t *testing.T) {
	reg := NewPlanRegistry(PlanRegistryOptions{})
	var wins int32
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if reg.Draft("g", demoNodes()).OK {
				atomic.AddInt32(&wins, 1)
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("%d drafts won", wins)
	}
}

// A tampered stored plan is never executable: the nodes must still hash to the root.
func TestPlanStatusDetectsTamperedNodes(t *testing.T) {
	kv := NewMemoryAtomicKV()
	reg := NewPlanRegistry(PlanRegistryOptions{KV: kv, Now: func() int64 { return 5 }})
	d := reg.Draft("g", demoNodes())
	root := d.Record.Root
	reg.Validate("g", root)
	reg.Commit("g", root)
	reg.Authorize("g", root, &PlanApproval{By: "p"})
	if !reg.Status("g", root, 0).Executable {
		t.Fatal("authorized plan must be executable")
	}
	_ = kv.Update(reg.key("g", root), func(prev []byte) []byte {
		rec, _ := decodePlanRecord(prev)
		rec.Nodes[0]["resource"] = "/orders/2"
		b, _ := json.Marshal(rec)
		return b
	})
	if s := reg.Status("g", root, 0); s.Executable || s.Reason != "plan "+root+": the stored nodes no longer hash to the root" {
		t.Fatalf("%+v", s)
	}
}

// ---- Authorize wiring

func planAuthorizeFixture(t *testing.T) (AuthorizeInput, any, map[string]any) {
	t.Helper()
	d := authorizeFixtures(t)
	c := d["cases"].([]any)[0].(map[string]any)
	s := c["steps"].([]any)[0].(map[string]any)
	revoked := false
	in := fixInput(d, c["grant"].(map[string]any), NewMemoryStateStore(), &revoked)
	in.Operation = fixOp(s["operation"].(map[string]any))
	return in, s["pcactn"], s["pcactn"].(map[string]any)
}

func planNodeOf(p map[string]any) map[string]any {
	action := p["action"].(map[string]any)
	pl := p["plan"].(map[string]any)
	return map[string]any{"id": pl["node_id"], "verb": action["verb"], "resource": action["resource"],
		"params_digest": action["params_digest"], "reversibility_class": action["reversibility_class"]}
}

func TestAuthorizeFeedsFromPlanRegistry(t *testing.T) {
	in, pcactn, p := planAuthorizeFixture(t)
	reg := NewPlanRegistry(PlanRegistryOptions{Now: func() int64 { return in.Now }})
	in.Plan, in.Plans = "", reg

	// unknown root: denied, naming the registry
	if r := Authorize(pcactn, in); r.Allow || r.Checks["plan_state"] != "fail" || r.Checks["plan_root_authorized"] != "fail" {
		t.Fatalf("unknown plan must deny: %+v", r)
	}
	d := reg.Draft(p["grant_ref"].(string), []map[string]any{planNodeOf(p)})
	if !d.OK || d.Record.Root != p["plan"].(map[string]any)["root"] {
		t.Fatalf("the registry's root must equal the PCActn's plan root: %+v %v", d, p["plan"])
	}
	root := d.Record.Root
	grant := p["grant_ref"].(string)
	// committed but not authorized: denied with the state in the reason
	reg.Validate(grant, root)
	reg.Commit(grant, root)
	in.StateStore = NewMemoryStateStore()
	if r := Authorize(pcactn, in); r.Allow || r.Checks["plan_state"] != "fail" {
		t.Fatalf("a committed plan must not execute: %+v", r)
	}
	reg.Authorize(grant, root, &PlanApproval{By: "principal"})
	in.StateStore = NewMemoryStateStore()
	if r := Authorize(pcactn, in); !r.Allow || r.Checks["plan_state"] != "pass" {
		t.Fatalf("an authorized plan must execute: %+v", r)
	}
	// revoked: terminal
	reg.Revoke(grant, root, "changed my mind")
	in.StateStore = NewMemoryStateStore()
	if r := Authorize(pcactn, in); r.Allow || r.Checks["plan_state"] != "fail" {
		t.Fatalf("a revoked plan must not execute: %+v", r)
	}
}

// K5 default-deny trio: no plan configured fails with the exact reason; single-step and a configured authorized plan pass.
func TestPlanRootAuthorizedDefaultDeny(t *testing.T) {
	in, pcactn, p := planAuthorizeFixture(t)
	in.Plan = ""
	r := Authorize(pcactn, in)
	want := "plan_root_authorized: default-deny: no authorized plan is configured for this verifier (supply the plan and its authorization, or set InsecureSkipPlanRootCheck)"
	if r.Allow || r.Checks["plan_root_authorized"] != "fail" || !strings.Contains(r.Reason, want) {
		t.Fatalf("default must deny with the exact reason: %+v", r)
	}
	for _, c := range r.Checks {
		if c == "not-enforced" {
			t.Fatalf("plan_root_authorized must never be not-enforced: %+v", r.Checks)
		}
	}
	in.Plan = PlanSingleStep
	if r := Authorize(pcactn, in); !r.Allow || r.Checks["plan_root_authorized"] != "pass" {
		t.Fatalf("single-step must pass: %+v", r)
	}
	in.Plan, in.StateStore = "", NewMemoryStateStore()
	in.Context = func(_ map[string]any) (*AuthorizeContext, error) {
		return &AuthorizeContext{Plan: []map[string]any{planNodeOf(p)}, PlanAuthorized: true}, nil
	}
	if r := Authorize(pcactn, in); !r.Allow || r.Checks["plan_root_authorized"] != "pass" {
		t.Fatalf("configured authorized plan must pass: %+v", r)
	}
}
