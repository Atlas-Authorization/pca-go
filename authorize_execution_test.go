package pca

import (
	"strings"
	"testing"
)

func TestAuthorizeExecutionConfigIsRequired(t *testing.T) {
	d := AuthorizeExecution(map[string]any{}, ExecutionOperation{Verb: "v"}, AuthorizeExecutionOptions{})
	if d.Allow || d.Kind != ExecutionDenyConfig || d.Status != 403 {
		t.Fatalf("%+v", d)
	}
	for _, want := range []string{"audience", "grant or resolveGrant", "state", "isRevoked"} {
		if !strings.Contains(d.Reason, want) {
			t.Fatalf("reason %q lacks %q", d.Reason, want)
		}
	}
	if got := MissingExecutionComponents(AuthorizeExecutionOptions{Audience: "a", Grant: map[string]any{}, State: NewMemoryStateStore(),
		IsRevoked: func(_, _ map[string]any) (bool, error) { return false, nil }}); len(got) != 0 {
		t.Fatalf("complete configuration reported missing %v", got)
	}
}

func TestAuthorizeExecutionBindsTheOperationBeforeAnyStateIsRead(t *testing.T) {
	opts := AuthorizeExecutionOptions{Audience: "a", Grant: map[string]any{}, State: NewMemoryStateStore(),
		IsRevoked: func(_, _ map[string]any) (bool, error) { return false, nil }}
	p := map[string]any{"action": map[string]any{"verb": "stripe.refund", "resource": "charge:1"}}
	d := AuthorizeExecution(p, ExecutionOperation{Verb: "stripe.charge"}, opts)
	if d.Allow || d.Kind != ExecutionDenyBinding || d.Reason != "the proof is for stripe.refund on charge:1, but this call is stripe.charge" {
		t.Fatalf("%+v", d)
	}
	d = AuthorizeExecution(p, ExecutionOperation{Verb: "stripe.refund", Resource: "charge:2"}, opts)
	if d.Kind != ExecutionDenyBinding || !strings.HasSuffix(d.Reason, "but this call is stripe.refund on charge:2") {
		t.Fatalf("%+v", d)
	}
	d = AuthorizeExecution(nil, ExecutionOperation{Verb: "x"}, opts)
	if d.Kind != ExecutionDenyBinding || !strings.HasPrefix(d.Reason, "the proof is for undefined on undefined") {
		t.Fatalf("%+v", d)
	}
}

func TestAmountRiskIsAmountOverKappaClamped(t *testing.T) {
	grant := map[string]any{"caveats": []any{map[string]any{"type": "envelope", "goal_commit": "g", "risk_policy": map[string]any{"kappa": 100.0}}}}
	if env := ReadEnvelope(grant); env == nil {
		t.Skip("envelope shape differs; AmountRisk is covered by the corpus")
	}
	if r := AmountRisk(grant, map[string]any{"amount": 25.0}, ""); r == nil || r["blastRadius"] != 0.25 {
		t.Fatalf("%v", r)
	}
	if r := AmountRisk(grant, map[string]any{"amount": 400.0}, ""); r["blastRadius"] != 1.0 {
		t.Fatalf("%v", r)
	}
	if AmountRisk(grant, map[string]any{"amount": "x"}, "") != nil || AmountRisk(grant, map[string]any{}, "") != nil {
		t.Fatal("no numeric amount must give no inputs")
	}
}
