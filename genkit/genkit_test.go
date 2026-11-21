package pcagenkit

import (
	"testing"

	"github.com/firebase/genkit/go/ai"

	pca "github.com/Atlas-Authorization/pca-go"
)

type refundIn struct {
	Amount int `json:"amount"`
}

func TestWithPCAAttachesAProofAndRefusesUnmapped(t *testing.T) {
	agent, err := pca.TestAgent(pca.TestAgentOverrides{})
	if err != nil {
		t.Fatal(err)
	}
	ran := false
	fn := func(_ *ai.ToolContext, in refundIn) (string, error) { ran = true; return "refunded", nil }
	var proof *pca.PcaCall
	wrapped, err := WithPCA(agent, Spec{
		Mapping: func(name string, _ map[string]any) (string, string, bool) {
			return "refund", "stripe", name == "refund"
		},
		OnProof: func(c *pca.PcaCall, _ map[string]any) { proof = c },
	}, "refund", fn)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := wrapped(&ai.ToolContext{}, refundIn{Amount: 10}); err != nil || out != "refunded" || proof == nil || !ran {
		t.Fatalf("a mapped call must carry a proof and run: out=%q err=%v proof=%v ran=%v", out, err, proof, ran)
	}
	ran = false
	refused, _ := WithPCA(agent, Spec{Mapping: func(string, map[string]any) (string, string, bool) { return "", "", false }}, "refund", fn)
	if _, err := refused(&ai.ToolContext{}, refundIn{Amount: 1}); err == nil || ran {
		t.Fatal("an unmapped tool must be refused and must not run")
	}
}
