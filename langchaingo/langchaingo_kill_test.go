package pcalangchaingo

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/tmc/langchaingo/schema"

	pca "github.com/Atlas-Authorization/pca-go"
)

type killTool struct {
	ran int
	out string
	err error
}

func (k *killTool) Name() string        { return "refund" }
func (k *killTool) Description() string { return "refund a charge" }
func (k *killTool) Call(context.Context, string) (string, error) {
	k.ran++
	return k.out, k.err
}

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
	spec := Spec{Mapping: killMapping}
	if w, err := WithPCA(agent, spec, &killTool{}); err != nil || w == nil {
		t.Fatalf("complete arguments must wrap: %v", err)
	}
	if w, err := WithPCA(nil, spec, &killTool{}); err == nil || w != nil {
		t.Fatal("a nil agent must be refused")
	}
	if w, err := WithPCA(agent, spec, nil); err == nil || w != nil {
		t.Fatal("a nil tool must be refused")
	}
	if w, err := WithPCA(agent, Spec{}, &killTool{}); err == nil || w != nil {
		t.Fatal("a nil mapping must be refused")
	}
}

func TestKillInputParsing(t *testing.T) {
	agent := killAgent(t)
	var got []map[string]any
	spec := Spec{Mapping: killMapping, OnProof: func(_ *pca.PcaCall, a map[string]any) { got = append(got, a) }}
	inner := &killTool{out: "ok"}
	w, _ := WithPCA(agent, spec, inner)

	if _, err := w.Call(context.Background(), "hello"); err != nil || len(got) != 1 || got[0]["input"] != "hello" || len(got[0]) != 1 {
		t.Fatalf("plain text becomes {input}: err=%v got=%v", err, got)
	}
	got = nil
	if _, err := w.Call(context.Background(), "  {\"amount\": 10}  "); err != nil || len(got) != 1 {
		t.Fatalf("object input: err=%v got=%v", err, got)
	}
	if _, ok := got[0]["amount"]; !ok || len(got[0]) != 1 {
		t.Fatalf("a JSON object is the args, not wrapped in {input}: %v", got[0])
	}

	got = nil
	ran := inner.ran
	out, err := w.Call(context.Background(), "{bad")
	if err == nil || !strings.Contains(err.Error(), "not valid JSON") || out != "" || inner.ran != ran || len(got) != 0 {
		t.Fatalf("invalid JSON: out=%q err=%v ran=%d got=%v", out, err, inner.ran-ran, got)
	}
}

func TestKillSuccessRecordsActionAndOutput(t *testing.T) {
	agent := killAgent(t)
	n0 := len(agent.Provenance.Receipts())
	w, _ := WithPCA(agent, Spec{Mapping: killMapping}, &killTool{out: "done"}) // no OnProof
	out, err := w.Call(context.Background(), "x")
	if err != nil || out != "done" {
		t.Fatalf("out=%q err=%v", out, err)
	}
	if w.Name() != "refund" || w.Description() != "refund a charge" {
		t.Fatal("the wrapper keeps the tool's name and description")
	}
	rs := agent.Provenance.Receipts()
	if len(rs) != n0+2 || rs[n0]["origin"] != "action" || rs[n0+1]["origin"] != "tool" || rs[n0+1]["source"] != "refund" {
		t.Fatalf("an action then a tool receipt must be recorded: %v", rs)
	}
}

func TestKillOnProofReceivesTheProof(t *testing.T) {
	agent := killAgent(t)
	var proof *pca.PcaCall
	w, _ := WithPCA(agent, Spec{Mapping: killMapping, OnProof: func(c *pca.PcaCall, _ map[string]any) { proof = c }}, &killTool{out: "ok"})
	if _, err := w.Call(context.Background(), "x"); err != nil || proof == nil || proof.Encoded == "" {
		t.Fatalf("OnProof must get a signed proof: err=%v proof=%v", err, proof)
	}
}

func TestKillUnmappedToolReportsAndDoesNotRun(t *testing.T) {
	agent := killAgent(t)
	proofs := 0
	inner := &killTool{out: "ok"}
	w, _ := WithPCA(agent, Spec{Mapping: func(string, map[string]any) (string, string, bool) { return "", "", false },
		OnProof: func(*pca.PcaCall, map[string]any) { proofs++ }}, inner)
	out, err := w.Call(context.Background(), "x")
	if err == nil || !strings.Contains(err.Error(), "unmapped") || out != "" || inner.ran != 0 || proofs != 0 {
		t.Fatalf("out=%q err=%v ran=%d proofs=%d", out, err, inner.ran, proofs)
	}
}

func TestKillActFailureIsReturned(t *testing.T) {
	agent := killAgent(t)
	fillReceipts(t, agent)
	proofs := 0
	inner := &killTool{out: "ok"}
	w, _ := WithPCA(agent, Spec{Mapping: killMapping, OnProof: func(*pca.PcaCall, map[string]any) { proofs++ }}, inner)
	out, err := w.Call(context.Background(), "x")
	if err == nil || !strings.Contains(err.Error(), "session holds") || out != "" || inner.ran != 0 || proofs != 0 {
		t.Fatalf("a signing failure must surface: out=%q err=%v ran=%d proofs=%d", out, err, inner.ran, proofs)
	}
}

func TestKillToolErrorIsReturnedAndNotRecorded(t *testing.T) {
	agent := killAgent(t)
	n0 := len(agent.Provenance.Receipts())
	boom := errors.New("boom")
	w, _ := WithPCA(agent, Spec{Mapping: killMapping}, &killTool{out: "partial", err: boom})
	out, err := w.Call(context.Background(), "x")
	if !errors.Is(err, boom) || out != "" {
		t.Fatalf("out=%q err=%v", out, err)
	}
	if n := len(agent.Provenance.Receipts()); n != n0+1 {
		t.Fatalf("a failed tool must record no output (receipts %d -> %d)", n0, n)
	}
}

func TestKillUnrecordableOutputIsAnError(t *testing.T) {
	agent := killAgent(t)
	inner := &killTool{out: "\xed\xa0\x80"} // a lone surrogate cannot be digested
	w, _ := WithPCA(agent, Spec{Mapping: killMapping}, inner)
	out, err := w.Call(context.Background(), "x")
	if err == nil || out != "" || inner.ran != 1 {
		t.Fatalf("an output that cannot be recorded must not reach the model: out=%q err=%v ran=%d", out, err, inner.ran)
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

// ---- retriever ----

type errRetriever struct{ err error }

func (e errRetriever) GetRelevantDocuments(context.Context, string) ([]schema.Document, error) {
	return nil, e.err
}

var killPolicy = []any{map[string]any{"verb": "viewer", "resource": "doc1"}}

func TestKillWithPCAFilterConstructionErrors(t *testing.T) {
	if r, err := WithPCAFilter(nil, "alice", killPolicy, nil); err == nil || r != nil {
		t.Fatal("a nil retriever must be refused")
	}
	badPolicy := map[string]any{"predicates": []any{}, "report": map[string]any{}} // report without errors
	if r, err := WithPCAFilter(fixedRetriever{}, "alice", badPolicy, nil); err == nil || r != nil {
		t.Fatal("a policy that does not compile must be refused at construction")
	}
}

func TestKillRetrieverErrorsAreReturned(t *testing.T) {
	boom := errors.New("boom")
	r, err := WithPCAFilter(errRetriever{boom}, "alice", killPolicy, nil)
	if err != nil {
		t.Fatal(err)
	}
	if docs, err := r.GetRelevantDocuments(context.Background(), "q"); !errors.Is(err, boom) || docs != nil {
		t.Fatalf("the inner error must surface: docs=%v err=%v", docs, err)
	}
	if r.LastDecision() != nil {
		t.Fatal("no decision before a successful retrieval")
	}

	// an admitted document whose id cannot be digested makes the filter itself fail
	bad := fixedRetriever{{PageContent: "p", Metadata: map[string]any{"id": "\xed\xa0\x80", "tags": []string{"viewer:doc1"}}}}
	r2, err := WithPCAFilter(bad, "alice", killPolicy, nil)
	if err != nil {
		t.Fatal(err)
	}
	if docs, err := r2.GetRelevantDocuments(context.Background(), "q"); err == nil || docs != nil {
		t.Fatalf("a filter failure must surface: docs=%v err=%v", docs, err)
	}
}

func TestKillMetadataShapesAndIDs(t *testing.T) {
	acl := func(rel, obj string) map[string]any { return map[string]any{"relation": rel, "object": obj} }
	docs := fixedRetriever{
		{PageContent: "0", Metadata: map[string]any{"id": "a", "source": "ignored", "tags": []string{"viewer:doc1"}}},
		{PageContent: "1", Metadata: map[string]any{"id": "", "source": "src", "acl": map[string]string{"relation": "viewer", "object": "doc1"}}},
		{PageContent: "2", Metadata: map[string]any{"source": "src2", "acl": []map[string]any{acl("viewer", "doc1")}}},
		{PageContent: "3", Metadata: map[string]any{"acl": []map[string]string{{"relation": "viewer", "object": "doc1"}}}},
		{PageContent: "4", Metadata: map[string]any{"id": 5, "source": "s4", "acl": []any{acl("viewer", "doc1")}}},
		{PageContent: "5", Metadata: map[string]any{"id": "x", "acl": "viewer:doc1"}},                               // not an ACL shape: dropped
		{PageContent: "6", Metadata: map[string]any{"id": "y", "tags": []string{"editor:doc1"}}},                    // wrong relation: dropped
		{PageContent: "7", Metadata: map[string]any{"id": "z", "acl": []map[string]string{{"relation": "viewer"}}}}, // incomplete entry: dropped
		{PageContent: "8"}, // no metadata at all: dropped
	}
	agent := killAgent(t)
	n0 := len(agent.Provenance.Receipts())
	r, err := WithPCAFilter(docs, "alice", killPolicy, agent.Provenance)
	if err != nil {
		t.Fatal(err)
	}
	out, err := r.GetRelevantDocuments(context.Background(), "q")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, d := range out {
		got = append(got, d.PageContent)
	}
	if fmt.Sprint(got) != "[0 1 2 3 4]" {
		t.Fatalf("admitted documents (candidate order): %v", got)
	}
	dec := r.LastDecision()
	if dec == nil {
		t.Fatal("a decision must be recorded")
	}
	if s := fmt.Sprint(dec["allowedIds"]); s != "[a src src2 doc#3 s4]" {
		t.Fatalf("ids come from id, then source, else doc#i: %s", s)
	}
	if s := fmt.Sprint(dec["droppedIds"]); s != "[x y z doc#8]" {
		t.Fatalf("dropped ids: %s", s)
	}
	rs := agent.Provenance.Receipts()
	if len(rs) != n0+5 || rs[n0]["origin"] != "retrieval" || rs[n0]["source"] != "a" || rs[n0+3]["source"] != "doc#3" {
		t.Fatalf("every admitted document is recorded as retrieval content: %v", rs)
	}
}
