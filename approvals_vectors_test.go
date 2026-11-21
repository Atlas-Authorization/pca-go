package pca

import (
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
)

// Replay of the approvals corpus (review, goal lineage, batch review, time-boxing) against the reference.

func apvKey(t *testing.T, label string) *KeyPair {
	t.Helper()
	h := sha256.Sum256([]byte("atlas-pca-conformance/approvals/" + label))
	k, err := KeyPairFromSeed(h[:])
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func apvInt(v any) *int64 {
	f, ok := jsNum(v)
	if !ok {
		return nil
	}
	n := int64(f)
	return &n
}

func apvAgent(t *testing.T, spec map[string]any) *FacadeAgent {
	t.Helper()
	o := AgentOptions{
		Principal:   apvKey(t, vecStr(spec, "principal")),
		Goal:        vecStr(spec, "goal"),
		Permissions: spec["permissions"],
		Holder:      apvKey(t, vecStr(spec, "holder")),
		GoalSalt:    vecStr(spec, "goalSalt"),
		BudgetModel: vecStr(spec, "budgetModel"),
		Aud:         vecStr(spec, "aud"),
	}
	if l, ok := spec["limits"].(map[string]any); ok {
		o.Limits = map[string]string{}
		for k, v := range l {
			o.Limits[k], _ = v.(string)
		}
	}
	if rp, ok := spec["riskPolicy"].(map[string]any); ok {
		o.RiskPolicy = rp
	}
	if n := apvInt(spec["now"]); n != nil {
		o.At = n // an explicit clock: now 0 is time 0, not the wall clock
	}
	a, err := CreateAgent(o)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func apvRender(mode, verb, resource string) (map[string]any, error) {
	switch mode {
	case "throw":
		return nil, errors.New("boom")
	case "badshape":
		return map[string]any{"v": jsNumber(2)}, nil
	}
	return map[string]any{"v": jsNumber(1), "kind": "pca-approval-render", "verb": verb, "def_digest": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "unreviewed": true,
		"fields": []any{map[string]any{"id": "resource", "class": "param", "value": resource}}}, nil
}

func apvOpts(o map[string]any) ReviewOptions {
	ro := ReviewOptions{Now: apvInt(o["now"]), InsecureUnboundApproval: o["insecure"] == true}
	if g, ok := o["goal"].(string); ok {
		ro.Goal = &g
	}
	if mode, ok := o["renderer"].(string); ok {
		ro.Renderer = func(verb, resource string, _ map[string]any) (map[string]any, error) {
			return apvRender(mode, verb, resource)
		}
	}
	if st, ok := o["standing"].([]any); ok {
		for _, x := range st {
			m := vecObj(x)
			c := ClassApproval{ID: vecStr(m, "id"), Verbs: vecStrs(m, "verbs"), By: vecStr(m, "by")}
			if g := apvInt(m["grantedAt"]); g != nil {
				c.GrantedAt = *g
			}
			if g := apvInt(m["ttlMs"]); g != nil {
				c.TTLMs = *g
			}
			if r, ok := m["resource"].(string); ok {
				c.Resource = &r
			}
			ro.Standing = append(ro.Standing, c)
		}
	}
	return ro
}

// apvFailClosed is the native's fail-closed deny for params the canonicalizer cannot take: the reference lets that refusal throw.
func apvFailClosed(r Review) error {
	if r.Kind == "deny" && (strings.HasPrefix(r.Reason, "params are not JSON: ") || strings.HasPrefix(r.Reason, "approval request failed (fail closed): ")) {
		return errors.New(r.Reason)
	}
	return nil
}

func TestApprovalsMatchTheReference(t *testing.T) {
	replayVectors(t, "ref-core-approvals-java.json.gz", map[string]vecFn{
		"reviewAction": func(a []any) (any, error) {
			r := ReviewAction(apvAgent(t, vecObj(a[0])), a[1].(string), a[2].(string), vecObj(a[3]), apvOpts(vecObj(a[4])))
			if err := apvFailClosed(r); err != nil {
				return nil, err
			}
			return r, nil
		},
		"batchReview": func(a []any) (any, error) {
			var calls []IntendedCall
			for _, x := range a[1].([]any) {
				m := vecObj(x)
				calls = append(calls, IntendedCall{Verb: vecStr(m, "verb"), Resource: vecStr(m, "resource"), Params: vecObj(m["params"])})
			}
			rs := BatchReview(apvAgent(t, vecObj(a[0])), calls, apvOpts(vecObj(a[2])))
			for _, r := range rs {
				if err := apvFailClosed(r); err != nil {
					return nil, err
				}
			}
			return rs, nil
		},
		"buildGoalLineage": func(a []any) (any, error) {
			var goal *string
			if g, ok := vecObj(a[4])["goal"].(string); ok {
				goal = &g
			}
			return BuildGoalLineage(apvAgent(t, vecObj(a[0])), a[1].(string), a[2].(string), vecObj(a[3]), goal), nil
		},
		"describeGoalLineage": func(a []any) (any, error) {
			// the reference maps the raw members, so a missing or non-string label / detail is whatever JavaScript makes of it
			return anlTry(func() any {
				chain, ok := anlGet(vecArg(a, 0), "chain").([]any)
				if !ok {
					anlFail("lineage.chain.map is not a function")
				}
				out := make([]any, len(chain))
				for i, n := range chain {
					lab := anlGet(n, "label")
					if det := anlGet(n, "detail"); anlTruthy(det) {
						out[i] = anlJS(lab) + " — " + anlJS(det)
					} else if !anlIsUndef(lab) {
						out[i] = lab
					}
				}
				return out
			})
		},
		"timeBox": func(a []any) (any, error) {
			ttl, _ := jsNum(a[2])
			var now *float64
			if f, ok := jsNum(vecArg(a, 3)); ok {
				now = &f
			}
			return TimeBox(vecObj(a[0]), apvKey(t, a[1].(string)), ttl, now)
		},
	})
}

func TestStandingClassApprovalsAndDecisions(t *testing.T) {
	now, res := int64(1000), "acct:*"
	a, err := ApproveClass([]string{"stripe.refund", "gmail.send"}, ApproveClassOptions{TTLMs: 3_600_000, By: "ops", Now: &now, Resource: &res})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		verb, res string
		at        int64
		want      bool
	}{
		{"stripe.refund", "acct:42", 1000, true}, {"gmail.send", "acct:", 3_599_999, true}, {"stripe.refund", "acct:42", 3_601_000, false},
		{"stripe.refund", "acct:42", 999, false}, {"stripe.payout", "acct:42", 1000, false}, {"stripe.refund", "other", 1000, false},
	} {
		if got := ClassApprovalCovers(a, c.verb, c.res, c.at); got != c.want {
			t.Errorf("covers(%s,%s,%d)=%v want %v", c.verb, c.res, c.at, got, c.want)
		}
	}
	zero := int64(0)
	x, _ := ApproveClass([]string{"b", "a"}, ApproveClassOptions{TTLMs: 1, By: "m", Now: &zero})
	y, _ := ApproveClass([]string{"a", "b"}, ApproveClassOptions{TTLMs: 1, By: "m", Now: &zero})
	if x.ID != y.ID {
		t.Error("the id depends on verb order")
	}
	seven := int64(7)
	if d := RecordDecision(StepUpRequest{ID: "req-1"}, "approve", "ops", &seven); d != (ApprovalDecision{RequestID: "req-1", Decision: "approve", By: "ops", At: 7}) {
		t.Errorf("decision %+v", d)
	}
	reqs := PendingRequests([]Review{{Kind: "auto"}, {Kind: "step_up", Request: &StepUpRequest{ID: "r"}}, {Kind: "deny", Reason: "x"}})
	if len(reqs) != 1 || reqs[0].ID != "r" {
		t.Errorf("pending %+v", reqs)
	}
}

func TestACosignRechargesTheBudget(t *testing.T) {
	p := RiskPolicy{Theta1: 0.3, Theta2: 0.6, Kappa: 1, Rho: 0.1, BMax: 1}
	low := TrustBudget{B: 0, Tau: 0, AsOf: 0, HasAsOf: true}
	if part := ApplyCosign(low, p, 5, false); !(part.B > 0 && part.B <= p.BMax && part.Tau == 5) {
		t.Errorf("partial recharge %+v", part)
	}
	if full := ApplyCosign(low, p, 9, true); full.B != p.BMax || full.Tau != 9 {
		t.Errorf("full recharge %+v", full)
	}
}
