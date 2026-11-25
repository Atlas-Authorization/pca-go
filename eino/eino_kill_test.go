package pcaeino

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/schema"

	pca "github.com/Atlas-Authorization/pca-go"
)

const loneSurrogate = "\xed\xa0\x80" // a string the provenance recorder refuses to hash

var errBoom = errors.New("boom")

// scriptedTool is a tool with a scripted Info and result.
type scriptedTool struct {
	name    string
	infoErr error
	out     string
	runErr  error
	ran     int
	gotArgs string
}

func (s *scriptedTool) Info(context.Context) (*schema.ToolInfo, error) {
	if s.infoErr != nil {
		return nil, s.infoErr
	}
	return &schema.ToolInfo{Name: s.name}, nil
}

func (s *scriptedTool) InvokableRun(_ context.Context, a string, _ ...tool.Option) (string, error) {
	s.ran++
	s.gotArgs = a
	return s.out, s.runErr
}

func refundOnly(name string, _ map[string]any) (string, string, bool) {
	return "refund", "stripe", name == "refund"
}

func newAgent(t *testing.T) *pca.FacadeAgent {
	t.Helper()
	ag, err := pca.TestAgent(pca.TestAgentOverrides{})
	if err != nil {
		t.Fatal(err)
	}
	return ag
}

func digestOf(s string) string {
	d, err := pca.HashCanonical(s)
	if err != nil {
		panic(err)
	}
	return d
}

func TestKillWithPCARequiresEachArgument(t *testing.T) {
	ag := newAgent(t)
	good := &scriptedTool{name: "refund"}
	if _, err := WithPCA(nil, Spec{Mapping: refundOnly}, good); err == nil || !strings.Contains(err.Error(), "required") {
		t.Fatalf("nil agent: %v", err)
	}
	if _, err := WithPCA(ag, Spec{Mapping: refundOnly}, nil); err == nil || !strings.Contains(err.Error(), "required") {
		t.Fatalf("nil tool: %v", err)
	}
	if _, err := WithPCA(ag, Spec{}, good); err == nil || !strings.Contains(err.Error(), "required") {
		t.Fatalf("nil mapping: %v", err)
	}
}

func TestKillInfoErrorPropagates(t *testing.T) {
	ag := newAgent(t)
	inner := &scriptedTool{name: "refund", infoErr: errBoom}
	w, _ := WithPCA(ag, Spec{Mapping: refundOnly}, inner)
	if _, err := w.Info(context.Background()); !errors.Is(err, errBoom) {
		t.Fatalf("info: %v", err)
	}
	out, err := w.InvokableRun(context.Background(), `{}`)
	if !errors.Is(err, errBoom) || out != "" || inner.ran != 0 {
		t.Fatalf("run: %q %v ran=%d", out, err, inner.ran)
	}
}

func TestKillMappedCallProofArgsAndProvenance(t *testing.T) {
	ag := newAgent(t)
	inner := &scriptedTool{name: "refund", out: "refunded"}
	var got map[string]any
	calls := 0
	w, _ := WithPCA(ag, Spec{Mapping: refundOnly, OnProof: func(c *pca.PcaCall, a map[string]any) {
		calls++
		got = a
		if c == nil || c.Encoded == "" {
			t.Error("empty proof")
		}
	}}, inner)
	before := len(ag.Provenance.Receipts())
	out, err := w.InvokableRun(context.Background(), `{"amount":10}`)
	if err != nil || out != "refunded" || calls != 1 || inner.ran != 1 || inner.gotArgs != `{"amount":10}` {
		t.Fatalf("%q %v calls=%d ran=%d args=%q", out, err, calls, inner.ran, inner.gotArgs)
	}
	if fmt.Sprint(got["amount"]) != "10" || len(got) != 1 {
		t.Fatalf("OnProof args: %v", got)
	}
	r := ag.Provenance.Receipts()
	if len(r) != before+2 { // the action, then the tool result
		t.Fatalf("receipts %d -> %d", before, len(r))
	}
	if last := r[len(r)-1]; last["origin"] != "tool" || last["source"] != "refund" || last["content_digest"] != digestOf("refunded") {
		t.Fatalf("tool receipt: %v", last)
	}
}

func TestKillEmptyArgumentsMeanNoArguments(t *testing.T) {
	for _, in := range []string{"", "   ", "\n\t"} {
		ag := newAgent(t)
		inner := &scriptedTool{name: "refund", out: "ok"}
		var got map[string]any
		called := false
		w, _ := WithPCA(ag, Spec{Mapping: refundOnly, OnProof: func(_ *pca.PcaCall, a map[string]any) { called = true; got = a }}, inner)
		out, err := w.InvokableRun(context.Background(), in)
		if err != nil || out != "ok" || !called || got == nil || len(got) != 0 || inner.ran != 1 {
			t.Fatalf("%q: out=%q err=%v called=%v got=%v ran=%d", in, out, err, called, got, inner.ran)
		}
	}
}

func TestKillWithoutOnProofStillRuns(t *testing.T) {
	ag := newAgent(t)
	inner := &scriptedTool{name: "refund", out: "ok"}
	w, _ := WithPCA(ag, Spec{Mapping: refundOnly}, inner)
	if out, err := w.InvokableRun(context.Background(), `{}`); err != nil || out != "ok" || inner.ran != 1 {
		t.Fatalf("%q %v ran=%d", out, err, inner.ran)
	}
}

func TestKillBadArgumentsAreRefusedBeforeTheToolRuns(t *testing.T) {
	cases := []struct{ name, in, msg string }{
		{"invalid json", `{`, "not valid JSON"},
		{"duplicate key", `{"a":1,"a":2}`, "not valid JSON"},
		{"array", `[1]`, "not a JSON object"},
		{"string", `"x"`, "not a JSON object"},
		{"null", `null`, "not a JSON object"},
		{"exponent number", `{"n":1e5}`, ""},
	}
	for _, c := range cases {
		ag := newAgent(t)
		inner := &scriptedTool{name: "refund", out: "ok"}
		proofs := 0
		w, _ := WithPCA(ag, Spec{Mapping: refundOnly, OnProof: func(*pca.PcaCall, map[string]any) { proofs++ }}, inner)
		out, err := w.InvokableRun(context.Background(), c.in)
		if err == nil || out != "" || inner.ran != 0 || proofs != 0 {
			t.Fatalf("%s: out=%q err=%v ran=%d proofs=%d", c.name, out, err, inner.ran, proofs)
		}
		if c.msg != "" && !strings.Contains(err.Error(), c.msg) {
			t.Fatalf("%s: %v", c.name, err)
		}
		if len(ag.Provenance.Receipts()) != 0 {
			t.Fatalf("%s: a refused call recorded provenance", c.name)
		}
	}
}

func TestKillUnmappedToolIsNamedAndNotRun(t *testing.T) {
	ag := newAgent(t)
	other := &scriptedTool{name: "other", out: "ok"}
	w, _ := WithPCA(ag, Spec{Mapping: refundOnly}, other)
	out, err := w.InvokableRun(context.Background(), `{}`)
	if err == nil || out != "" || other.ran != 0 || !strings.Contains(err.Error(), `"other"`) || !strings.Contains(err.Error(), "declined") {
		t.Fatalf("%q %v ran=%d", out, err, other.ran)
	}
}

func TestKillInnerErrorIsReturnedAndNotRecorded(t *testing.T) {
	ag := newAgent(t)
	inner := &scriptedTool{name: "refund", out: "partial", runErr: errBoom}
	w, _ := WithPCA(ag, Spec{Mapping: refundOnly}, inner)
	before := len(ag.Provenance.Receipts())
	out, err := w.InvokableRun(context.Background(), `{}`)
	if !errors.Is(err, errBoom) || out != "" || inner.ran != 1 {
		t.Fatalf("%q %v", out, err)
	}
	if n := len(ag.Provenance.Receipts()); n != before+1 { // the action only, no tool result
		t.Fatalf("receipts %d -> %d", before, n)
	}
}

func TestKillUnrecordableOutputIsRefused(t *testing.T) {
	ag := newAgent(t)
	inner := &scriptedTool{name: "refund", out: loneSurrogate}
	w, _ := WithPCA(ag, Spec{Mapping: refundOnly}, inner)
	out, err := w.InvokableRun(context.Background(), `{}`)
	if err == nil || out != "" {
		t.Fatalf("an unrecordable output reached the model: %q %v", out, err)
	}
}

func TestKillRecordInput(t *testing.T) {
	if err := RecordInput(nil, "hi"); err == nil || !strings.Contains(err.Error(), "agent is required") {
		t.Fatalf("nil agent: %v", err)
	}
	ag := newAgent(t)
	if err := RecordInput(ag, "hello"); err != nil {
		t.Fatal(err)
	}
	r := ag.Provenance.Receipts()
	if len(r) != 1 || r[0]["origin"] != "principal" || r[0]["content_digest"] != digestOf("hello") {
		t.Fatalf("receipts: %v", r)
	}
}
