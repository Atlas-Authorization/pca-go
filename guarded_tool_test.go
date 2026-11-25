package pca

import (
	"context"
	"testing"
)

type fakeRefundTool struct{ ran map[string]any }

func (f *fakeRefundTool) Metadata() ToolMetadata {
	return ToolMetadata{Name: "refund", Description: "Refund a charge", Parameters: map[string]any{"type": "object"}}
}

func (f *fakeRefundTool) Call(_ context.Context, args map[string]any) (any, error) {
	f.ran = args
	return map[string]any{"ok": true}, nil
}

func TestGuardedTool(t *testing.T) {
	mk := func() *FacadeAgent {
		ag, err := CreateAgent(AgentOptions{Principal: mustKey(t), Goal: "refunds", Permissions: map[string][]string{"stripe": {"refund"}}, Limits: map[string]string{"refund": "$500/day"}, Aud: "ins_test"})
		if err != nil {
			t.Fatal(err)
		}
		return ag
	}
	args := map[string]any{"amount": float64(20), "currency": "usd", "charge": "ch_1"}
	resource := func(a map[string]any) string { return "charge:" + adapterJsString(a["charge"]) }

	// emits a proof, forwards it, then runs the original call; metadata is preserved
	ag, inner := mk(), &fakeRefundTool{}
	var proof *PcaCall
	tool, err := GuardedTool(ag, GuardToolSpec{Verb: "stripe.refund", ResourceFn: resource, OnProof: func(c *PcaCall, _ map[string]any) { proof = c }}, inner)
	if err != nil {
		t.Fatal(err)
	}
	out, err := tool.Call(context.Background(), args)
	if err != nil || out.(map[string]any)["ok"] != true || inner.ran == nil {
		t.Fatalf("call: %v %v ran=%v", out, err, inner.ran)
	}
	if proof == nil {
		t.Fatal("no proof was forwarded")
	}
	if raw, derr := DecodePCAHeader(proof.Headers[PCAHeader]); derr != nil || raw != proof.Encoded {
		t.Fatalf("header does not carry the encoded proof: %v", derr)
	}
	if act := proof.PCActn["action"].(map[string]any); act["verb"] != "stripe.refund" || act["resource"] != "charge:ch_1" {
		t.Fatalf("proof not bound to the call: %v", act)
	}
	if m := tool.Metadata(); m.Name != "refund" || m.Description != "Refund a charge" {
		t.Fatalf("metadata: %+v", m)
	}
	if rs := ag.Provenance.Receipts(); rs[len(rs)-1]["origin"] != "tool" {
		t.Fatalf("result not recorded as tool output: %v", rs[len(rs)-1])
	}

	// an over-cap call fails fast and never runs the original call
	inner2 := &fakeRefundTool{}
	tool2, _ := GuardedTool(mk(), GuardToolSpec{Verb: "stripe.refund", Resource: "charge:ch_1"}, inner2)
	if _, err := tool2.Call(context.Background(), map[string]any{"amount": float64(9999), "currency": "usd", "charge": "ch_1"}); err == nil || inner2.ran != nil {
		t.Fatalf("over-cap call ran (err %v)", err)
	}

	// construction guards
	if _, err := GuardedTool(nil, GuardToolSpec{Verb: "v"}, inner); err == nil {
		t.Fatal("nil agent accepted")
	}
	if _, err := GuardedTool(mk(), GuardToolSpec{}, inner); err == nil {
		t.Fatal("empty verb accepted")
	}
}

func TestGuardedEngineRecordsPrincipal(t *testing.T) {
	ag, err := CreateAgent(AgentOptions{Principal: mustKey(t), Goal: "g", Permissions: map[string][]string{"files": {"read"}}, Aud: "rs"})
	if err != nil {
		t.Fatal(err)
	}
	ran := false
	chat := GuardedEngine(ag, func(any) (any, error) { ran = true; return "ok", nil })
	if _, err := chat(map[string]any{"message": "read the file", "chatHistory": []any{map[string]any{"role": "user", "content": "hi"}}}); err != nil || !ran {
		t.Fatalf("engine call: %v ran=%v", err, ran)
	}
	rs := ag.Provenance.Receipts()
	if len(rs) == 0 || rs[0]["origin"] != "principal" {
		t.Fatalf("the principal's request was not recorded: %v", rs)
	}
}
