package pca

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// ---- jsonValue: the typed-number cases each have their own result (the generic marshal path differs) ----------------

func TestR5N2_JSONValueNumberTypes(t *testing.T) {
	// float32 widens to float64 (the shortest float32 text, 0.1, would be a different number)
	got, ok := jsonValue(float32(0.1), 1)
	if !ok || got != jsNumber(float64(float32(0.1))) || got == any(json.Number("0.1")) {
		t.Fatalf("float32 0.1 -> %v %v", got, ok)
	}
	over := int64(maxSafeInt) + 1
	// a Go int / int64 outside the safe-integer range is refused, never rounded into a float
	for name, v := range map[string]any{"int+": int(over), "int-": int(-over), "int64+": over, "int64-": -over} {
		if g, ok := jsonValue(v, 1); ok || g != nil {
			t.Errorf("%s: %v %v", name, g, ok)
		}
	}
	for name, v := range map[string]any{"int": int(maxSafeInt), "int64": int64(maxSafeInt)} {
		if g, ok := jsonValue(v, 1); !ok || g != json.Number("9007199254740991") {
			t.Errorf("%s max: %v %v", name, g, ok)
		}
	}
}

func TestR5N2_RootCaveatsNonArray(t *testing.T) {
	if got := RootCaveats(map[string]any{"caveats": "x"}); got != "x" {
		t.Fatalf("non-array caveats are returned as they are: %#v", got)
	}
	if got := RootCaveats(map[string]any{}); got != nil {
		t.Fatalf("absent caveats stay absent: %#v", got)
	}
}

func TestR5N2_OrderedChecksSetKeepsFirstPosition(t *testing.T) {
	c := &orderedChecks{st: map[string]string{}}
	c.set("a", "pass")
	c.set("b", "pass")
	c.set("a", "fail")
	if !reflect.DeepEqual(c.order, []string{"a", "b"}) || c.st["a"] != "fail" {
		t.Fatalf("order %v st %v", c.order, c.st)
	}
}

func TestR5N2_CoercePCActnReasons(t *testing.T) {
	m := map[string]any{"a": json.Number("1")}
	if p, why := coercePCActn(m); why != "" || !reflect.DeepEqual(p, m) {
		t.Fatalf("object: %v %q", p, why)
	}
	for name, in := range map[string]any{
		"oversized bytes": make([]byte, MaxArtifactBytes+1),
		"invalid utf-8":   []byte{0xff},
		"other type":      5,
	} {
		if p, why := coercePCActn(in); p != nil || why != "undecodable" {
			t.Errorf("%s: %v %q", name, p, why)
		}
	}
}

func TestR5N2_LiftFailed(t *testing.T) {
	st := map[string]string{"a": "fail", "b": "not-enforced", "c": "pass", "d": "unsupported"}
	liftFailed(st)
	if !reflect.DeepEqual(st, map[string]string{"a": "pass", "b": "not-enforced", "c": "pass", "d": "unsupported"}) {
		t.Fatalf("%v", st)
	}
}

func TestR5N2_EnvelopePredicatesMatchHasNoReason(t *testing.T) {
	preds := []any{map[string]any{"verb": "x", "resource": "r",
		"where": []any{map[string]any{"field": "action.params.amount", "op": "lte", "value": json.Number("5")}}}}
	ctx := map[string]any{"action": map[string]any{"verb": "x", "resource": "r", "params": map[string]any{"amount": json.Number("3")}}}
	if ok, why := envelopePredicates(preds, ctx, &regexBudget{}); !ok || why != "" {
		t.Fatalf("a matching predicate: %v %q", ok, why)
	}
}

func TestR5N2_IsAuthorizedForPanicIsFalse(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("IsAuthorizedFor let a panic out: %v", r)
		}
	}()
	res := AuthorizeResult{Allow: true, Operation: &AuthorizedOperation{Verb: "v", Resource: "r", ParamsDigest: "d"}}
	op := &Operation{Verb: "v", Resource: "r", Params: map[string]any{"x": g01PanicJSON{}}}
	if IsAuthorizedFor(res, op) {
		t.Fatal("a panicking params value authorized")
	}
}

func TestR5N2_CallK1PanicIsNoInput(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("callK1 let a panic out: %v", r)
		}
	}()
	if ki := callK1(func(map[string]any) (*K1Input, error) { panic("k1") }, nil); ki != nil {
		t.Fatalf("a panicking K1 callback produced input %+v", ki)
	}
}

// ---- Authorize: the escalation stage ----------------------------------------------------------------------------------

type r5n2NoLast struct{ StateStore }

type r5n2ErrLast struct{ *MemoryStateStore }

func (r5n2ErrLast) Last(string) (*int64, error) { return nil, errors.New("down") }

func TestR5N2_EscalationStoreWithoutLast(t *testing.T) {
	_, _, pcactn, in, _ := escalationSetup(t)
	defer escalateHook("provenance")()
	r := Authorize(pcactn, in(r5n2NoLast{NewMemoryStateStore()}, nil, nil))
	if r.Allow || r.Decision != "escalate" || r.Escalation == nil {
		t.Fatalf("a store with no Last still escalates: %+v", r)
	}
}

func TestR5N2_EscalationLastErrorMeansUnknownHead(t *testing.T) {
	_, grant, pcactn, in, _ := escalationSetup(t)
	sk, pub := principalKey(t)
	defer escalateHook("provenance")()
	// an answer signed for the empty history: it must not be verified when the head cannot be read
	a := signAnswer(t, sk, pub, grant, pcactn, nil, nil)
	r := Authorize(pcactn, in(r5n2ErrLast{NewMemoryStateStore()}, a, []string{pub}))
	if r.Allow || r.Decision != "escalate" {
		t.Fatalf("an unreadable head admitted an answer: %+v", r)
	}
}

func TestR5N2_EscalationRenderPanicIsNoRender(t *testing.T) {
	_, _, pcactn, in, _ := escalationSetup(t)
	defer escalateHook("provenance")()
	i := in(NewMemoryStateStore(), nil, nil)
	i.EscalationRender = func(map[string]any) string { panic("render") }
	r := Authorize(pcactn, i)
	if r.Allow || r.Decision != "escalate" || r.Escalation == nil {
		t.Fatalf("a panicking render must be no render: %+v", r)
	}
}

func TestR5N2_EscalationBuildFailureDenies(t *testing.T) {
	_, grant, pcactn, in, _ := escalationSetup(t)
	defer escalateHook("provenance")()
	old := authorizeEscBuild
	authorizeEscBuild = func(string, map[string]any, map[string]any, *int64, []string, int64, int64, string) (map[string]any, error) {
		return nil, errors.New("build")
	}
	defer func() { authorizeEscBuild = old }()
	store := NewMemoryStateStore()
	r := Authorize(pcactn, in(store, nil, nil))
	if r.Allow || r.Decision != "deny" || r.Escalation != nil {
		t.Fatalf("got %+v", r)
	}
	chain := pcactn["cap_chain"].([]any)
	holder := chain[len(chain)-1].(map[string]any)["holder"].(string)
	if last, _ := store.Last(StateKey(grant["id"].(string), holder)); last != nil {
		t.Fatalf("a refused escalation spent the counter: %d", *last)
	}
}

// ---- the K5 workflow stage reads plan.root only when it is a string -------------------------------------------------

func TestR5N2_WorkflowPlanRootNotAString(t *testing.T) {
	F := load(t, "authorize-workflow-fixtures.json")
	var plan []map[string]any
	for _, n := range F["plan"].([]any) {
		plan = append(plan, n.(map[string]any))
	}
	grant := F["grant"].(map[string]any)
	c := F["cases"].([]any)[0].(map[string]any)
	s := c["steps"].([]any)[0].(map[string]any)
	op := s["operation"].(map[string]any)
	w := s["workflow"].(map[string]any)
	in := AuthorizeInput{Risk: InsecureCalmRisk,
		Operation: &Operation{Verb: op["verb"].(string), Resource: op["resource"].(string), Params: op["params"].(map[string]any)},
		Audience:  F["audience"].(string),
		ResolveGrant: func(ref string) (map[string]any, error) {
			if ref == grant["id"] {
				return grant, nil
			}
			return nil, nil
		},
		StateStore: NewMemoryStateStore(),
		IsRevoked:  func(_, _ map[string]any) (bool, error) { return false, nil },
		Now:        num(F["now"]),
		Context: func(map[string]any) (*AuthorizeContext, error) {
			return &AuthorizeContext{Plan: plan, PlanAuthorized: true}, nil
		},
		Workflow:      &WorkflowOption{Principal: F["principal"].(string), RsSigner: F["rs_signer"].(string)},
		ArgProvenance: harnessProv(),
		WorkflowStep:  &WorkflowCall{Commitment: w["commitment"], Receipts: w["receipts"], Step: w["step"].(string), Units: w["units"], GoalDigest: w["goal_digest"]},
	}
	pc := deepCopy(s["pcactn"]).(map[string]any)
	pc["plan"].(map[string]any)["root"] = json.Number("5")
	r := Authorize(pc, in)
	// a non-string plan.root is no root (null) for the workflow, which pins a root: a mismatch, not a malformed request
	if r.Allow || !strings.HasPrefix(r.Reason, "workflow: plan_root_mismatch") {
		t.Fatalf("got allow=%v reason=%q", r.Allow, r.Reason)
	}
}
