package pcalangchaingo

import (
	"context"
	"testing"

	"github.com/tmc/langchaingo/schema"

	pca "github.com/Atlas-Authorization/pca-go"
)

type echoTool struct{ ran bool }

func (e *echoTool) Name() string        { return "refund" }
func (e *echoTool) Description() string { return "refund a charge" }
func (e *echoTool) Call(_ context.Context, in string) (string, error) {
	e.ran = true
	return in, nil
}

func TestWithPCAAttachesAProofAndRefusesUnmapped(t *testing.T) {
	agent, err := pca.TestAgent(pca.TestAgentOverrides{})
	if err != nil {
		t.Fatal(err)
	}
	inner := &echoTool{}
	var proof *pca.PcaCall
	tool, err := WithPCA(agent, Spec{
		Mapping: func(name string, _ map[string]any) (string, string, bool) {
			return "refund", "stripe", name == "refund"
		},
		OnProof: func(c *pca.PcaCall, _ map[string]any) { proof = c },
	}, inner)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tool.Call(context.Background(), `{"amount":10}`); err != nil || proof == nil || !inner.ran {
		t.Fatalf("a mapped call must carry a proof and run: err=%v proof=%v ran=%v", err, proof, inner.ran)
	}
	refused, _ := WithPCA(agent, Spec{Mapping: func(string, map[string]any) (string, string, bool) { return "", "", false }}, &echoTool{})
	if _, err := refused.Call(context.Background(), "x"); err == nil {
		t.Fatal("an unmapped tool must be refused")
	}
}

type fixedRetriever []schema.Document

func (f fixedRetriever) GetRelevantDocuments(context.Context, string) ([]schema.Document, error) {
	return f, nil
}

func TestWithPCAFilterDropsUnreadableDocuments(t *testing.T) {
	policy := []any{} // no predicates: nothing is admitted
	docs := fixedRetriever{{PageContent: "a", Metadata: map[string]any{"id": "a"}}}
	r, err := WithPCAFilter(docs, "alice", policy, nil)
	if err != nil {
		t.Fatal(err)
	}
	out, err := r.GetRelevantDocuments(context.Background(), "q")
	if err != nil || len(out) != 0 {
		t.Fatalf("a document with no ACL must be dropped: out=%v err=%v", out, err)
	}
	if r.LastDecision() == nil {
		t.Fatal("a decision must be recorded")
	}
}
