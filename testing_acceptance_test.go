package pca

import "testing"

// The native net/http guard passes the shared adapter acceptance matrix.
func TestNetHTTPAdapterAcceptance(t *testing.T) {
	got, err := RunAdapterAcceptance(NetHTTPAcceptanceHarness)
	if err != nil {
		t.Fatal(err)
	}
	if bad := AcceptanceDiff(got); len(bad) > 0 {
		t.Fatalf("scenarios that differ from the expected matrix: %v (got %v)", bad, got)
	}
}

func TestTestAgentMakesAVerifiableAction(t *testing.T) {
	a, err := TestAgent(TestAgentOverrides{})
	if err != nil {
		t.Fatal(err)
	}
	p, _, err := MakePCActn(a, "refund", "stripe", map[string]any{"amount": jsNumber(10)}, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ExpectVerifies(p, FakeVerifyOptions{}); err != nil {
		t.Fatal(err)
	}
}
