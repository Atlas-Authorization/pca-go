package pcaeino

import (
	"context"
	"testing"

	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/schema"

	pca "github.com/Atlas-Authorization/pca-go"
)

type fakeTool struct {
	name string
	ran  int
}

func (f *fakeTool) Info(context.Context) (*schema.ToolInfo, error) {
	return &schema.ToolInfo{Name: f.name, Desc: "refund a charge"}, nil
}

func (f *fakeTool) InvokableRun(_ context.Context, _ string, _ ...tool.Option) (string, error) {
	f.ran++
	return "refunded", nil
}

func TestWithPCAAttachesAProofAndRefusesUnmapped(t *testing.T) {
	agent, err := pca.TestAgent(pca.TestAgentOverrides{})
	if err != nil {
		t.Fatal(err)
	}
	inner := &fakeTool{name: "refund"}
	var proof *pca.PcaCall
	spec := Spec{
		Mapping: func(name string, _ map[string]any) (string, string, bool) {
			return "refund", "stripe", name == "refund"
		},
		OnProof: func(c *pca.PcaCall, _ map[string]any) { proof = c },
	}
	wrapped, err := WithPCA(agent, spec, inner)
	if err != nil {
		t.Fatal(err)
	}
	if info, err := wrapped.Info(context.Background()); err != nil || info.Name != "refund" {
		t.Fatalf("info: %v %v", info, err)
	}
	if out, err := wrapped.InvokableRun(context.Background(), `{"amount":10}`); err != nil || out != "refunded" || proof == nil || inner.ran != 1 {
		t.Fatalf("a mapped call must carry a proof and run: out=%q err=%v proof=%v ran=%d", out, err, proof, inner.ran)
	}
	if _, err := wrapped.InvokableRun(context.Background(), `[1]`); err == nil || inner.ran != 1 {
		t.Fatal("arguments that are not an object must be refused before the tool runs")
	}
	other := &fakeTool{name: "other"}
	refused, _ := WithPCA(agent, spec, other)
	if _, err := refused.InvokableRun(context.Background(), ""); err == nil || other.ran != 0 {
		t.Fatal("an unmapped tool must be refused and must not run")
	}
	if _, err := WithPCA(nil, spec, inner); err == nil {
		t.Fatal("a nil agent was accepted")
	}
}
