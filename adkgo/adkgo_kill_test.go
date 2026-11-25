package pcaadk

import (
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"strings"
	"testing"

	"google.golang.org/adk/v2/agent"
	"google.golang.org/adk/v2/model"
	"google.golang.org/genai"

	pca "github.com/Atlas-Authorization/pca-go"
)

const loneSurrogate = "\xed\xa0\x80" // a string the provenance recorder refuses to hash

var errBoom = errors.New("boom")

// killRun is a runnable tool with a scripted result.
type killRun struct {
	fakeRun
	out map[string]any
	err error
}

func (k *killRun) Run(agent.Context, any) (map[string]any, error) {
	k.ran++
	return k.out, k.err
}

// killProc also implements the request-processor surface.
type killProc struct {
	killRun
	calls int
	fn    func(*model.LLMRequest) error
}

func (k *killProc) ProcessRequest(_ agent.Context, req *model.LLMRequest) error {
	k.calls++
	if k.fn != nil {
		return k.fn(req)
	}
	return nil
}

// killStream yields three chunks and counts how many it handed out.
type killStream struct {
	fakeRun
	delivered int
}

func (k *killStream) RunStream(agent.Context, any) iter.Seq2[string, error] {
	return func(yield func(string, error) bool) {
		k.ran++
		for _, c := range []string{"a", "b", "c"} {
			k.delivered++
			if !yield(c, nil) {
				return
			}
		}
	}
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

func lastReceipt(t *testing.T, ag *pca.FacadeAgent) map[string]any {
	t.Helper()
	r := ag.Provenance.Receipts()
	if len(r) == 0 {
		t.Fatal("no receipts")
	}
	return r[len(r)-1]
}

func TestKillWithPCARequiresEachArgument(t *testing.T) {
	ag := newAgent(t)
	good := &fakeRun{name: "refund"}
	if _, err := WithPCA(nil, Spec{Mapping: mapping}, good); err == nil || !strings.Contains(err.Error(), "required") {
		t.Fatalf("nil agent: %v", err)
	}
	if _, err := WithPCA(ag, Spec{Mapping: mapping}, nil); err == nil || !strings.Contains(err.Error(), "required") {
		t.Fatalf("nil tool: %v", err)
	}
	if _, err := WithPCA(ag, Spec{}, good); err == nil || !strings.Contains(err.Error(), "required") {
		t.Fatalf("nil mapping: %v", err)
	}
	_, err := WithPCA(ag, Spec{Mapping: mapping}, &modelSide{fakeRun{name: "refund"}})
	if err == nil || !strings.Contains(err.Error(), "not executable") {
		t.Fatalf("model-side tool: %v", err)
	}
}

func TestKillRunProofArgsAndProvenance(t *testing.T) {
	ag := newAgent(t)
	inner := &fakeRun{name: "refund"}
	var got map[string]any
	var calls int
	w, err := WithPCA(ag, Spec{Mapping: mapping, OnProof: func(c *pca.PcaCall, a map[string]any) {
		calls++
		got = a
		if c == nil || c.Encoded == "" {
			t.Error("empty proof")
		}
	}}, inner)
	if err != nil {
		t.Fatal(err)
	}
	if d := w.(runnableTool).Declaration(); d == nil || d.Name != "refund" {
		t.Fatalf("declaration: %v", d)
	}
	before := len(ag.Provenance.Receipts())
	out, err := w.(runnableTool).Run(nil, map[string]any{"amount": 10})
	if err != nil || out["ok"] != true || calls != 1 || inner.ran != 1 {
		t.Fatalf("run: %v %v calls=%d ran=%d", out, err, calls, inner.ran)
	}
	if fmt.Sprint(got["amount"]) != "10" || len(got) != 1 {
		t.Fatalf("OnProof args: %v", got)
	}
	if n := len(ag.Provenance.Receipts()); n != before+2 { // the action, then the tool result
		t.Fatalf("receipts %d -> %d", before, n)
	}
	r := lastReceipt(t, ag)
	if r["origin"] != "tool" || r["source"] != "refund" || r["content_digest"] != digestOf(`{"ok":true}`) {
		t.Fatalf("tool receipt: %v", r)
	}
}

func TestKillRunNilArgsBecomeEmptyObject(t *testing.T) {
	ag := newAgent(t)
	inner := &fakeRun{name: "refund"}
	var got map[string]any
	called := false
	w, _ := WithPCA(ag, Spec{Mapping: mapping, OnProof: func(_ *pca.PcaCall, a map[string]any) { called = true; got = a }}, inner)
	if _, err := w.(runnableTool).Run(nil, nil); err != nil || !called || got == nil || len(got) != 0 || inner.ran != 1 {
		t.Fatalf("nil args: err=%v called=%v got=%v ran=%d", err, called, got, inner.ran)
	}
}

func TestKillRunWithoutOnProofStillRuns(t *testing.T) {
	ag := newAgent(t)
	inner := &fakeRun{name: "refund"}
	w, _ := WithPCA(ag, Spec{Mapping: mapping}, inner)
	if _, err := w.(runnableTool).Run(nil, map[string]any{}); err != nil || inner.ran != 1 {
		t.Fatalf("%v ran=%d", err, inner.ran)
	}
}

func TestKillBadArgumentsAreRefusedBeforeTheToolRuns(t *testing.T) {
	cases := map[string]any{
		"unmarshalable": make(chan int),
		"not an object": []any{1},
		"a string":      "x",
		"a number":      5,
		"duplicate key": json.RawMessage(`{"a":1,"a":2}`),
		"exponent":      json.RawMessage(`{"n":1e5}`),
	}
	for name, in := range cases {
		ag := newAgent(t)
		inner := &fakeRun{name: "refund"}
		proofs := 0
		w, _ := WithPCA(ag, Spec{Mapping: mapping, OnProof: func(*pca.PcaCall, map[string]any) { proofs++ }}, inner)
		out, err := w.(runnableTool).Run(nil, in)
		if err == nil || out != nil || inner.ran != 0 || proofs != 0 {
			t.Fatalf("%s: out=%v err=%v ran=%d proofs=%d", name, out, err, inner.ran, proofs)
		}
		if name == "not an object" || name == "a string" || name == "a number" {
			if !strings.Contains(err.Error(), "not a JSON object") {
				t.Fatalf("%s: %v", name, err)
			}
		}
		if len(ag.Provenance.Receipts()) != 0 {
			t.Fatalf("%s: a refused call recorded provenance", name)
		}
		// the streaming surface refuses the same way, with exactly one error and no output
		sinner := &fakeStream{fakeRun{name: "refund"}}
		sw, _ := WithPCA(ag, Spec{Mapping: mapping}, sinner)
		errs, chunks := 0, 0
		for c, serr := range sw.(streamingTool).RunStream(nil, in) {
			if serr != nil {
				errs++
			}
			if c != "" {
				chunks++
			}
		}
		if errs != 1 || chunks != 0 || sinner.ran != 0 {
			t.Fatalf("%s stream: errs=%d chunks=%d ran=%d", name, errs, chunks, sinner.ran)
		}
	}
}

func TestKillUnmappedRunNamesTheTool(t *testing.T) {
	ag := newAgent(t)
	other := &fakeRun{name: "other"}
	w, _ := WithPCA(ag, Spec{Mapping: mapping}, other)
	out, err := w.(runnableTool).Run(nil, map[string]any{})
	if err == nil || out != nil || !strings.Contains(err.Error(), `"other"`) || other.ran != 0 {
		t.Fatalf("%v %v ran=%d", out, err, other.ran)
	}
}

func TestKillRunInnerErrorIsReturnedAndNotRecorded(t *testing.T) {
	ag := newAgent(t)
	inner := &killRun{fakeRun: fakeRun{name: "refund"}, out: map[string]any{"ok": true}, err: errBoom}
	w, _ := WithPCA(ag, Spec{Mapping: mapping}, inner)
	before := len(ag.Provenance.Receipts())
	out, err := w.(runnableTool).Run(nil, map[string]any{})
	if !errors.Is(err, errBoom) || out != nil || inner.ran != 1 {
		t.Fatalf("%v %v", out, err)
	}
	if n := len(ag.Provenance.Receipts()); n != before+1 { // the action only, no tool result
		t.Fatalf("receipts %d -> %d", before, n)
	}
}

func TestKillRunRefusesAResultThatCannotBeRecorded(t *testing.T) {
	ag := newAgent(t)
	// the chan makes the lenient canonical form fail, so the recorder hashes the Sprint text, which holds the lone surrogate
	inner := &killRun{fakeRun: fakeRun{name: "refund"}, out: map[string]any{"a": loneSurrogate, "b": make(chan int)}}
	w, _ := WithPCA(ag, Spec{Mapping: mapping}, inner)
	out, err := w.(runnableTool).Run(nil, map[string]any{})
	if err == nil || out != nil {
		t.Fatalf("an unrecordable result reached the model: %v %v", out, err)
	}
}

func TestKillStreamProofProvenanceAndEarlyStop(t *testing.T) {
	ag := newAgent(t)
	inner := &killStream{fakeRun: fakeRun{name: "refund"}}
	var got map[string]any
	w, _ := WithPCA(ag, Spec{Mapping: mapping, OnProof: func(_ *pca.PcaCall, a map[string]any) { got = a }}, inner)
	if d := w.(streamingTool).Declaration(); d == nil || d.Name != "refund" {
		t.Fatalf("declaration: %v", d)
	}
	var all string
	for c, err := range w.(streamingTool).RunStream(nil, map[string]any{"amount": 3}) {
		if err != nil {
			t.Fatal(err)
		}
		all += c
	}
	if all != "abc" || fmt.Sprint(got["amount"]) != "3" {
		t.Fatalf("%q %v", all, got)
	}
	r := lastReceipt(t, ag)
	if r["origin"] != "tool" || r["source"] != "refund" || r["content_digest"] != digestOf("abc") {
		t.Fatalf("tool receipt: %v", r)
	}

	// a reader that stops early: the inner stream stops too and only what was delivered is recorded
	ag2 := newAgent(t)
	inner2 := &killStream{fakeRun: fakeRun{name: "refund"}}
	w2, _ := WithPCA(ag2, Spec{Mapping: mapping}, inner2)
	before := len(ag2.Provenance.Receipts())
	for c := range w2.(streamingTool).RunStream(nil, map[string]any{}) {
		if c != "a" {
			t.Fatalf("chunk %q", c)
		}
		break
	}
	if inner2.delivered != 1 {
		t.Fatalf("the inner stream kept going after the reader stopped: %d", inner2.delivered)
	}
	if n := len(ag2.Provenance.Receipts()); n != before+2 {
		t.Fatalf("receipts %d -> %d", before, n)
	}
	if r := lastReceipt(t, ag2); r["origin"] != "tool" || r["content_digest"] != digestOf("a") {
		t.Fatalf("early-stop receipt: %v", r)
	}
}

func TestKillPackPutsTheWrapperIntoTheRequest(t *testing.T) {
	// the inner processor registers itself: the wrapper replaces it, and the inner processor ran once
	ag := newAgent(t)
	inner := &killProc{killRun: killRun{fakeRun: fakeRun{name: "refund"}}}
	inner.fn = func(req *model.LLMRequest) error {
		if req.Tools == nil {
			req.Tools = map[string]any{}
		}
		req.Tools["refund"] = inner
		return nil
	}
	w, _ := WithPCA(ag, Spec{Mapping: mapping}, inner)
	req := &model.LLMRequest{}
	if err := w.(requestProcessor).ProcessRequest(nil, req); err != nil {
		t.Fatal(err)
	}
	if inner.calls != 1 || req.Tools["refund"] != w {
		t.Fatalf("calls=%d registered=%v", inner.calls, req.Tools["refund"])
	}
	// the same through the streaming wrapper
	sinner := &killProc{killRun: killRun{fakeRun: fakeRun{name: "refund"}}}
	sinner.fn = func(req *model.LLMRequest) error { req.Tools = map[string]any{"refund": sinner}; return nil }
	sw, _ := WithPCA(ag, Spec{Mapping: mapping}, &killStreamProc{killProc: sinner})
	sreq := &model.LLMRequest{}
	if err := sw.(requestProcessor).ProcessRequest(nil, sreq); err != nil || sreq.Tools["refund"] != sw {
		t.Fatalf("stream: %v %v", err, sreq.Tools["refund"])
	}
}

// killStreamProc is a streaming tool that also processes requests.
type killStreamProc struct{ *killProc }

func (k *killStreamProc) RunStream(agent.Context, any) iter.Seq2[string, error] {
	return func(yield func(string, error) bool) { yield("a", nil) }
}

func TestKillPackReturnsTheInnerProcessorError(t *testing.T) {
	ag := newAgent(t)
	inner := &killProc{killRun: killRun{fakeRun: fakeRun{name: "refund"}}, fn: func(req *model.LLMRequest) error { return errBoom }}
	w, _ := WithPCA(ag, Spec{Mapping: mapping}, inner)
	req := &model.LLMRequest{Tools: map[string]any{}}
	if err := w.(requestProcessor).ProcessRequest(nil, req); err != errBoom {
		t.Fatalf("got %v", err)
	}
	if len(req.Tools) != 0 {
		t.Fatalf("the wrapper was registered despite the error: %v", req.Tools)
	}
}

func TestKillPackDoesNotOverwriteAnExistingTool(t *testing.T) {
	ag := newAgent(t)
	inner := &killProc{killRun: killRun{fakeRun: fakeRun{name: "refund"}}}
	w, _ := WithPCA(ag, Spec{Mapping: mapping}, inner)
	existing := &fakeRun{name: "refund"}
	req := &model.LLMRequest{Tools: map[string]any{"refund": existing}}
	// a tool of that name was already there: the wrapper must not take its slot on the fast path (the shared packer refuses a duplicate)
	if err := w.(requestProcessor).ProcessRequest(nil, req); err == nil {
		t.Fatal("a duplicate tool name was accepted")
	}
	if req.Tools["refund"] != existing {
		t.Fatalf("the existing tool was replaced: %v", req.Tools["refund"])
	}
	if inner.calls != 1 {
		t.Fatalf("calls=%d", inner.calls)
	}
}

func TestKillPackPacksAToolWithoutAProcessor(t *testing.T) {
	ag := newAgent(t)
	w, _ := WithPCA(ag, Spec{Mapping: mapping}, &fakeRun{name: "refund"})
	req := &model.LLMRequest{}
	if err := w.(requestProcessor).ProcessRequest(nil, req); err != nil || req.Tools["refund"] != w {
		t.Fatalf("%v %v", err, req.Tools["refund"])
	}
	// a processor that registers nothing falls through to the shared packer, which also declares the tool
	inner := &killProc{killRun: killRun{fakeRun: fakeRun{name: "refund"}}}
	w2, _ := WithPCA(ag, Spec{Mapping: mapping}, inner)
	req2 := &model.LLMRequest{Tools: map[string]any{}}
	if err := w2.(requestProcessor).ProcessRequest(nil, req2); err != nil || req2.Tools["refund"] != w2 || inner.calls != 1 {
		t.Fatalf("%v %v calls=%d", err, req2.Tools["refund"], inner.calls)
	}
	if req2.Config == nil || len(req2.Config.Tools) == 0 {
		t.Fatalf("the shared packer did not declare the tool: %+v", req2.Config)
	}
	_ = genai.Tool{}
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
