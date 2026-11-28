package pcagenkit

import (
	"errors"
	"strings"
	"testing"

	"github.com/firebase/genkit/go/ai"

	pca "github.com/Atlas-Authorization/pca-go"
)

func killMapping(name string, _ map[string]any) (string, string, bool) {
	return "refund", "stripe", name == "refund"
}

func killAgent(t *testing.T) *pca.FacadeAgent {
	t.Helper()
	agent, err := pca.TestAgent(pca.TestAgentOverrides{})
	if err != nil {
		t.Fatal(err)
	}
	return agent
}

// fillReceipts brings the recorder to the receipt cap so the next Act (which records its action) fails.
func fillReceipts(t *testing.T, agent *pca.FacadeAgent) {
	t.Helper()
	for n := len(agent.Provenance.Receipts()); n < pca.MaxProvReceipts; n++ {
		if _, err := agent.Provenance.Tool("x", "y"); err != nil {
			t.Fatal(err)
		}
	}
}

func TestKillWithPCARequiresEveryArgument(t *testing.T) {
	agent := killAgent(t)
	fn := func(_ *ai.ToolContext, in refundIn) (string, error) { return "ok", nil }
	spec := Spec{Mapping: killMapping}
	if w, err := WithPCA(agent, spec, "refund", fn); err != nil || w == nil {
		t.Fatalf("complete arguments must wrap: err=%v", err)
	}
	if w, err := WithPCA(nil, spec, "refund", fn); err == nil || w != nil {
		t.Fatal("a nil agent must be refused")
	}
	if w, err := WithPCA[refundIn, string](agent, spec, "refund", nil); err == nil || w != nil {
		t.Fatal("a nil function must be refused")
	}
	if w, err := WithPCA(agent, Spec{}, "refund", fn); err == nil || w != nil {
		t.Fatal("a nil mapping must be refused")
	}
	if w, err := WithPCA(agent, spec, "", fn); err == nil || w != nil {
		t.Fatal("an empty name must be refused")
	}
}

func TestKillInputConversion(t *testing.T) {
	agent := killAgent(t)
	var got []map[string]any
	spec := Spec{Mapping: killMapping, OnProof: func(_ *pca.PcaCall, a map[string]any) { got = append(got, a) }}

	// an object input carries its members
	ran := 0
	w, _ := WithPCA(agent, spec, "refund", func(_ *ai.ToolContext, in refundIn) (string, error) { ran++; return "ok", nil })
	if _, err := w(&ai.ToolContext{}, refundIn{Amount: 7}); err != nil || ran != 1 || len(got) != 1 {
		t.Fatalf("object input: err=%v ran=%d got=%v", err, ran, got)
	}
	if _, ok := got[0]["amount"]; !ok || len(got[0]) != 1 {
		t.Fatalf("the args must be the input object, got %v", got[0])
	}

	// a nil pointer is JSON null: an empty object, not an error
	got, ran = nil, 0
	wn, _ := WithPCA(agent, spec, "refund", func(_ *ai.ToolContext, in *refundIn) (string, error) { ran++; return "ok", nil })
	if _, err := wn(&ai.ToolContext{}, nil); err != nil || ran != 1 || len(got) != 1 || got[0] == nil || len(got[0]) != 0 {
		t.Fatalf("null input: err=%v ran=%d got=%#v", err, ran, got)
	}

	// a non-object input is refused, nothing runs, no proof is handed out
	got, ran = nil, 0
	ws, _ := WithPCA(agent, spec, "refund", func(_ *ai.ToolContext, in string) (string, error) { ran++; return "ok", nil })
	out, err := ws(&ai.ToolContext{}, "plain")
	if err == nil || !strings.Contains(err.Error(), "not a JSON object") || out != "" || ran != 0 || len(got) != 0 {
		t.Fatalf("string input: out=%q err=%v ran=%d got=%v", out, err, ran, got)
	}

	// an input that cannot be marshalled is refused with the marshal error
	type bad struct{ C chan int }
	wb, _ := WithPCA(agent, spec, "refund", func(_ *ai.ToolContext, in bad) (string, error) { ran++; return "ok", nil })
	out, err = wb(&ai.ToolContext{}, bad{C: make(chan int)})
	if err == nil || strings.Contains(err.Error(), "not a JSON object") || out != "" || ran != 0 || len(got) != 0 {
		t.Fatalf("unmarshalable input: out=%q err=%v ran=%d got=%v", out, err, ran, got)
	}
}

func TestKillSuccessRecordsActionAndOutput(t *testing.T) {
	agent := killAgent(t)
	n0 := len(agent.Provenance.Receipts())
	w, _ := WithPCA(agent, Spec{Mapping: killMapping}, "refund", func(_ *ai.ToolContext, in refundIn) (string, error) { return "done", nil }) // no OnProof
	out, err := w(&ai.ToolContext{}, refundIn{Amount: 1})
	if err != nil || out != "done" {
		t.Fatalf("out=%q err=%v", out, err)
	}
	rs := agent.Provenance.Receipts()
	if len(rs) != n0+2 || rs[n0]["origin"] != "action" || rs[n0+1]["origin"] != "tool" || rs[n0+1]["source"] != "refund" {
		t.Fatalf("an action then a tool receipt must be recorded: %v", rs)
	}
}

func TestKillOnProofReceivesTheProof(t *testing.T) {
	agent := killAgent(t)
	var proof *pca.PcaCall
	w, _ := WithPCA(agent, Spec{Mapping: killMapping, OnProof: func(c *pca.PcaCall, _ map[string]any) { proof = c }}, "refund",
		func(_ *ai.ToolContext, in refundIn) (string, error) { return "ok", nil })
	if _, err := w(&ai.ToolContext{}, refundIn{Amount: 1}); err != nil || proof == nil || proof.Encoded == "" {
		t.Fatalf("OnProof must get a signed proof: err=%v proof=%v", err, proof)
	}
}

func TestKillUnmappedToolReportsAndDoesNotRun(t *testing.T) {
	agent := killAgent(t)
	ran, proofs := false, 0
	w, _ := WithPCA(agent, Spec{Mapping: killMapping, OnProof: func(*pca.PcaCall, map[string]any) { proofs++ }}, "other",
		func(_ *ai.ToolContext, in refundIn) (string, error) { ran = true; return "ok", nil })
	out, err := w(&ai.ToolContext{}, refundIn{})
	if err == nil || !strings.Contains(err.Error(), "unmapped") || out != "" || ran || proofs != 0 {
		t.Fatalf("out=%q err=%v ran=%v proofs=%d", out, err, ran, proofs)
	}
}

func TestKillActFailureIsReturned(t *testing.T) {
	agent := killAgent(t)
	fillReceipts(t, agent)
	ran, proofs := false, 0
	w, _ := WithPCA(agent, Spec{Mapping: killMapping, OnProof: func(*pca.PcaCall, map[string]any) { proofs++ }}, "refund",
		func(_ *ai.ToolContext, in refundIn) (string, error) { ran = true; return "ok", nil })
	out, err := w(&ai.ToolContext{}, refundIn{Amount: 1})
	if err == nil || !strings.Contains(err.Error(), "session holds") || out != "" || ran || proofs != 0 {
		t.Fatalf("a signing failure must surface: out=%q err=%v ran=%v proofs=%d", out, err, ran, proofs)
	}
}

func TestKillToolErrorIsReturnedAndNotRecorded(t *testing.T) {
	agent := killAgent(t)
	n0 := len(agent.Provenance.Receipts())
	boom := errors.New("boom")
	w, _ := WithPCA(agent, Spec{Mapping: killMapping}, "refund", func(_ *ai.ToolContext, in refundIn) (string, error) { return "partial", boom })
	out, err := w(&ai.ToolContext{}, refundIn{Amount: 1})
	if !errors.Is(err, boom) || out != "" {
		t.Fatalf("out=%q err=%v", out, err)
	}
	if n := len(agent.Provenance.Receipts()); n != n0+1 {
		t.Fatalf("a failed tool must record no output (receipts %d -> %d)", n0, n)
	}
}

func TestKillUnrecordableOutputIsAnError(t *testing.T) {
	agent := killAgent(t)
	w, _ := WithPCA(agent, Spec{Mapping: killMapping}, "refund", func(_ *ai.ToolContext, in refundIn) (string, error) { return "\xed\xa0\x80", nil }) // a lone surrogate
	out, err := w(&ai.ToolContext{}, refundIn{Amount: 1})
	if err == nil || out != "" {
		t.Fatalf("an output that cannot be recorded must not reach the model: out=%q err=%v", out, err)
	}
}

func TestKillRecordInput(t *testing.T) {
	if err := RecordInput(nil, "hi"); err == nil {
		t.Fatal("a nil agent must be refused")
	}
	agent := killAgent(t)
	n0 := len(agent.Provenance.Receipts())
	if err := RecordInput(agent, "hello"); err != nil {
		t.Fatal(err)
	}
	rs := agent.Provenance.Receipts()
	if len(rs) != n0+1 || rs[n0]["origin"] != "principal" {
		t.Fatalf("the principal input must be recorded: %v", rs)
	}
}
