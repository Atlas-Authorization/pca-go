package pcaopenai

import (
	"encoding/json"
	"testing"

	pca "github.com/Atlas-Authorization/pca-go"
)

func refundOnly(name string, _ map[string]any) (string, string, bool) {
	return "refund", "stripe", name == "refund"
}

func call(id, name, args string) map[string]any {
	return map[string]any{"id": id, "type": "function", "function": map[string]any{"name": name, "arguments": args}}
}

func TestToolMessagesRunsMappedToolsWithAProof(t *testing.T) {
	ag, err := pca.TestAgent(pca.TestAgentOverrides{})
	if err != nil {
		t.Fatal(err)
	}
	var got []*pca.PcaCall
	handlers := map[string]pca.AdapterToolHandler{"refund": func(_ any, c *pca.PcaCall) (any, error) {
		got = append(got, c)
		return map[string]any{"ok": true}, nil
	}}
	msg := map[string]any{"role": "assistant", "tool_calls": []any{call("c1", "refund", `{"amount":10}`), call("c2", "refund", ``)}}
	out, err := ToolMessages(ag, msg, refundOnly, handlers)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 || len(got) != 2 || got[0] == nil || got[0].Encoded == "" {
		t.Fatalf("messages=%d runs=%d", len(out), len(got))
	}
	for i, id := range []string{"c1", "c2"} {
		raw, err := json.Marshal(out[i])
		if err != nil {
			t.Fatal(err)
		}
		var w struct {
			Role       string
			ToolCallID string `json:"tool_call_id"`
			Content    string
		}
		if err := json.Unmarshal(raw, &w); err != nil || w.Role != "tool" || w.ToolCallID != id || w.Content != `{"ok":true}` {
			t.Fatalf("message %d: %s (%v)", i, raw, err)
		}
	}
}

func TestToolMessagesRefusals(t *testing.T) {
	ag, _ := pca.TestAgent(pca.TestAgentOverrides{})
	ran := 0
	handlers := map[string]pca.AdapterToolHandler{"other": func(any, *pca.PcaCall) (any, error) { ran++; return nil, nil }}
	for name, c := range map[string]any{
		"an unmapped tool":               call("c1", "other", `{}`),
		"an unparseable argument string": call("c1", "refund", `{nope`),
		"a call that is not an object":   "refund",
	} {
		if _, err := ToolMessages(ag, map[string]any{"tool_calls": []any{c}}, refundOnly, handlers); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
	if ran != 0 {
		t.Fatal("a tool ran without a proof")
	}
	if _, err := ToolMessages(nil, map[string]any{}, refundOnly, nil); err == nil {
		t.Fatal("a nil agent was accepted")
	}
	if out, err := ToolMessages(ag, map[string]any{"role": "assistant"}, refundOnly, nil); err != nil || len(out) != 0 {
		t.Fatalf("a message without tool calls: %v %v", out, err)
	}
}

func TestRecordMessagesRecordsOncePerMessage(t *testing.T) {
	ag, _ := pca.TestAgent(pca.TestAgentOverrides{})
	if err := RecordMessages(nil, nil); err == nil {
		t.Fatal("a nil agent was accepted")
	}
	msgs := []any{map[string]any{"role": "user", "content": "refund alice ten dollars"}}
	before := len(ag.Provenance.Receipts())
	if err := RecordMessages(ag, msgs); err != nil {
		t.Fatal(err)
	}
	after := len(ag.Provenance.Receipts())
	if after <= before {
		t.Fatalf("the user turn was not recorded: %d -> %d", before, after)
	}
	if err := RecordMessages(ag, msgs); err != nil || len(ag.Provenance.Receipts()) != after {
		t.Fatal("an already recorded message was recorded again")
	}
}
