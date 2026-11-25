package pcaadk

import (
	"iter"
	"testing"

	"google.golang.org/adk/v2/agent"
	"google.golang.org/genai"

	pca "github.com/Atlas-Authorization/pca-go"
)

type fakeRun struct {
	name string
	ran  int
}

func (f *fakeRun) Name() string        { return f.name }
func (f *fakeRun) Description() string { return "refund a charge" }
func (f *fakeRun) IsLongRunning() bool { return false }
func (f *fakeRun) Declaration() *genai.FunctionDeclaration {
	return &genai.FunctionDeclaration{Name: f.name}
}
func (f *fakeRun) Run(agent.Context, any) (map[string]any, error) {
	f.ran++
	return map[string]any{"ok": true}, nil
}

type fakeStream struct{ fakeRun }

func (f *fakeStream) RunStream(agent.Context, any) iter.Seq2[string, error] {
	return func(yield func(string, error) bool) {
		f.ran++
		if yield("a", nil) {
			yield("b", nil)
		}
	}
}

// modelSide is a tool the flow cannot execute: no Run, no RunStream.
type modelSide struct{ fakeRun }

func (modelSide) Run() {}

func mapping(name string, _ map[string]any) (string, string, bool) {
	return "refund", "stripe", name == "refund"
}

func TestRunToolCarriesAProofAndRefusesUnmapped(t *testing.T) {
	ag, err := pca.TestAgent(pca.TestAgentOverrides{})
	if err != nil {
		t.Fatal(err)
	}
	var proof *pca.PcaCall
	inner := &fakeRun{name: "refund"}
	w, err := WithPCA(ag, Spec{Mapping: mapping, OnProof: func(c *pca.PcaCall, _ map[string]any) { proof = c }}, inner)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := w.(runnableTool).Run(nil, map[string]any{"amount": 10}); err != nil || out["ok"] != true || proof == nil || inner.ran != 1 {
		t.Fatalf("a mapped call must carry a proof and run: %v %v proof=%v ran=%d", out, err, proof, inner.ran)
	}
	other := &fakeRun{name: "other"}
	r, _ := WithPCA(ag, Spec{Mapping: mapping}, other)
	if _, err := r.(runnableTool).Run(nil, map[string]any{}); err == nil || other.ran != 0 {
		t.Fatal("an unmapped tool must be refused and must not run")
	}
	if _, err := WithPCA(ag, Spec{Mapping: mapping}, &modelSide{fakeRun{name: "refund"}}); err == nil {
		t.Fatal("a tool without an execution surface was wrapped")
	}
}

func TestStreamToolIsGuarded(t *testing.T) {
	ag, _ := pca.TestAgent(pca.TestAgentOverrides{})
	inner := &fakeStream{fakeRun{name: "refund"}}
	w, err := WithPCA(ag, Spec{Mapping: mapping}, inner)
	if err != nil {
		t.Fatal(err)
	}
	if _, isRun := w.(runnableTool); isRun {
		t.Fatal("a streaming wrapper must not expose Run")
	}
	var got string
	for c, err := range w.(streamingTool).RunStream(nil, map[string]any{}) {
		if err != nil {
			t.Fatal(err)
		}
		got += c
	}
	if got != "ab" || inner.ran != 1 {
		t.Fatalf("stream %q ran %d", got, inner.ran)
	}
	denied := &fakeStream{fakeRun{name: "other"}}
	w2, _ := WithPCA(ag, Spec{Mapping: mapping}, denied)
	for _, err := range w2.(streamingTool).RunStream(nil, map[string]any{}) {
		if err == nil {
			t.Fatal("an unmapped stream produced output")
		}
	}
	if denied.ran != 0 {
		t.Fatal("an unmapped stream ran")
	}
}
