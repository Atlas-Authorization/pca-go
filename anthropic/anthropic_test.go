package pcaanthropic

import (
	"encoding/json"
	"testing"

	"github.com/anthropics/anthropic-sdk-go"

	pca "github.com/Atlas-Authorization/pca-go"
)

func refundOnly(name string, _ map[string]any) (string, string, bool) {
	return "refund", "stripe", name == "refund"
}

func assistant(t *testing.T, blocks string) *anthropic.Message {
	t.Helper()
	var m anthropic.Message
	if err := json.Unmarshal([]byte(`{"role":"assistant","content":`+blocks+`}`), &m); err != nil {
		t.Fatal(err)
	}
	return &m
}

// result decodes the single tool_result block of the returned user message.
func result(t *testing.T, p anthropic.MessageParam) (id, text string, isErr bool) {
	t.Helper()
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var w struct {
		Role    string
		Content []struct {
			Type      string
			ToolUseID string `json:"tool_use_id"`
			IsError   bool   `json:"is_error"`
			Content   []struct{ Text string }
		}
	}
	if err := json.Unmarshal(raw, &w); err != nil {
		t.Fatal(err)
	}
	if w.Role != "user" || len(w.Content) != 1 || w.Content[0].Type != "tool_result" || len(w.Content[0].Content) != 1 {
		t.Fatalf("not one tool_result in a user message: %s", raw)
	}
	b := w.Content[0]
	return b.ToolUseID, b.Content[0].Text, b.IsError
}

func TestToolResultMessageRunsMappedToolWithAProof(t *testing.T) {
	ag, err := pca.TestAgent(pca.TestAgentOverrides{})
	if err != nil {
		t.Fatal(err)
	}
	var proof *pca.PcaCall
	ran := 0
	handlers := map[string]pca.AdapterToolHandler{"refund": func(_ any, c *pca.PcaCall) (any, error) {
		ran++
		proof = c
		return map[string]any{"ok": true}, nil
	}}
	msg := assistant(t, `[{"type":"text","text":"refunding"},{"type":"tool_use","id":"tu1","name":"refund","input":{"amount":10}}]`)
	out, ok, err := ToolResultMessage(ag, msg, refundOnly, handlers)
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	id, text, isErr := result(t, out)
	if id != "tu1" || text != `{"ok":true}` || isErr || ran != 1 || proof == nil || proof.Encoded == "" {
		t.Fatalf("id=%q text=%q isErr=%v ran=%d proof=%v", id, text, isErr, ran, proof)
	}
}

func TestToolResultMessageRefusesWithoutAProof(t *testing.T) {
	ag, _ := pca.TestAgent(pca.TestAgentOverrides{})
	ran := 0
	handlers := map[string]pca.AdapterToolHandler{"other": func(any, *pca.PcaCall) (any, error) { ran++; return nil, nil }}
	out, ok, err := ToolResultMessage(ag, assistant(t, `[{"type":"tool_use","id":"tu2","name":"other","input":{}}]`), refundOnly, handlers)
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if id, _, isErr := result(t, out); id != "tu2" || !isErr || ran != 0 {
		t.Fatalf("an unmapped tool must be an is_error result and must not run: id=%q isErr=%v ran=%d", id, isErr, ran)
	}
	// mapped but no handler: still an is_error result
	out, _, _ = ToolResultMessage(ag, assistant(t, `[{"type":"tool_use","id":"tu3","name":"refund","input":{}}]`), refundOnly, nil)
	if _, _, isErr := result(t, out); !isErr {
		t.Fatal("a tool without a handler produced a success result")
	}
}

func TestToolResultMessageEdges(t *testing.T) {
	ag, _ := pca.TestAgent(pca.TestAgentOverrides{})
	if _, ok, err := ToolResultMessage(nil, assistant(t, `[]`), refundOnly, nil); ok || err == nil {
		t.Fatal("a nil agent was accepted")
	}
	if _, ok, err := ToolResultMessage(ag, nil, refundOnly, nil); ok || err == nil {
		t.Fatal("a nil message was accepted")
	}
	if _, ok, err := ToolResultMessage(ag, assistant(t, `[{"type":"text","text":"hi"}]`), refundOnly, nil); ok || err != nil {
		t.Fatalf("a message without a tool_use block: ok=%v err=%v", ok, err)
	}
}

func TestRecordMessagesRecordsOncePerMessage(t *testing.T) {
	ag, _ := pca.TestAgent(pca.TestAgentOverrides{})
	if err := RecordMessages(nil, nil); err == nil {
		t.Fatal("a nil agent was accepted")
	}
	msgs := []anthropic.MessageParam{anthropic.NewUserMessage(anthropic.NewTextBlock("refund alice ten dollars"))}
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
