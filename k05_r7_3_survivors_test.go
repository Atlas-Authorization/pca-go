package pca

import (
	"errors"
	"testing"
)

// agent.go signBody: a fault hook that reports no error for a domain must leave signing untouched, and a reported
// error is returned as is with an empty signature.
func TestR7N3_SignBodyFaultHook(t *testing.T) {
	k, err := NewKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	old := signBodyFault
	defer func() { signBodyFault = old }()
	body := map[string]any{"a": "b"}
	signBodyFault = func(string) error { return nil }
	sig, err := signBody(k, "r7n3/ok\x00", body)
	if err != nil || sig == "" {
		t.Fatalf("a hook with no error must not stop signing: %q %v", sig, err)
	}
	want := errors.New("r7n3 canon fault")
	signBodyFault = func(d string) error {
		if d == "r7n3/bad\x00" {
			return want
		}
		return nil
	}
	sig, err = signBody(k, "r7n3/bad\x00", body)
	if err != want || sig != "" {
		t.Fatalf("a hook error must come back unchanged with an empty signature: %q %v", sig, err)
	}
	if sig, err = signBody(k, "r7n3/other\x00", body); err != nil || sig == "" {
		t.Fatalf("the hook error is per domain: %q %v", sig, err)
	}
	// the public signers hand back the empty signature beside the error
	signBodyFault = func(string) error { return want }
	out, err := SignWorkflow(k, map[string]any{"principal": k.Public})
	if err == nil || out["sig"] != "" {
		t.Fatalf("SignWorkflow under a signing fault: sig %v err %v", out["sig"], err)
	}
}

// actions_registry.go reapprovalValid: a VALID re-approval must be refused when the fault hook raises in scope
// "reapproval" (an empty record would be refused anyway), and accepted when the hook is not set.
func TestR7N3_ReapprovalFaultOnAValidRecord(t *testing.T) {
	defer func() { registryFault = nil }()
	k := newKey(t)
	diff := dg("r7n3-diff")
	r := map[string]any{"v": jnum(1), "kind": reapprovalKind, "grant": "g1", "verb": "stripe.charge", "diff": diff}
	r["sig"] = map[string]any{"alg": "ed25519", "value": signDomain(t, k, reapprovalDomain, withoutKeys(r, "sig"))}
	registryFault = nil
	if !reapprovalValid(r, "g1", k.id, "stripe.charge", diff) {
		t.Fatal("precondition: the record is a valid re-approval")
	}
	registryFault = func(s string) {
		if s == "reapproval" {
			panic("boom")
		}
	}
	got := true
	func() {
		defer func() {
			if x := recover(); x != nil {
				t.Fatalf("a panic escaped reapprovalValid: %v", x)
			}
		}()
		got = reapprovalValid(r, "g1", k.id, "stripe.charge", diff)
	}()
	if got {
		t.Fatal("a fault inside reapprovalValid must refuse even a valid re-approval")
	}
}

// decision.go DecisionOf (TS decision.ts:75): only a check whose STATUS is "unsupported" denies by its
// "<check>: unsupported:" reason; the same reason beside a passing check is ignored.
func TestR7N3_DecisionUnsupportedReasonOnNonUnsupportedStatus(t *testing.T) {
	v := map[string]any{
		"allow":   false,
		"checks":  map[string]any{"c": "pass", "d": "fail"},
		"reasons": []any{"c: unsupported: ignored, c passed", "d: escalate: needs a human"},
	}
	if got := DecisionOf(v); got != "escalate" {
		t.Fatalf("got %q, want escalate", got)
	}
}
