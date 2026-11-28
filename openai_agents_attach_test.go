package pca

import "testing"

func TestOAAttachPCATextFormCarriesProofAndRefusesNonObject(t *testing.T) {
	agent, err := TestAgent(TestAgentOverrides{})
	if err != nil {
		t.Fatal(err)
	}
	ran := 0
	tool := &OATool{Name: "refund", OnInvokeTool: func(any, any) (any, error) { ran++; return "ok", nil }}
	var proof *PcaCall
	w, err := OAAttachPCA(agent, "refund", func(map[string]any) string { return "stripe" }, tool,
		func(c *PcaCall, _ map[string]any) error { proof = c; return nil }, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.OnInvokeTool(nil, `{"amount":10}`); err != nil || proof == nil || ran != 1 {
		t.Fatalf("a call must carry a proof and run: err=%v proof=%v ran=%d", err, proof, ran)
	}
	for _, bad := range []any{`[1]`, `not json`, nil} {
		if _, err := w.OnInvokeTool(nil, bad); err == nil || ran != 1 {
			t.Fatalf("non-object arguments %v must be refused without running", bad)
		}
	}
}
