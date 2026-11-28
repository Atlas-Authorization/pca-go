package pca

// Batch and recording-wrapper forms of the chat-API adapters: handle every tool call of one model turn in order, and wrap a model
// call so the conversation's messages are recorded into the agent's provenance before the call runs.

// AnthropicHandleToolUses handles many tool_use blocks (all of them from one assistant turn), preserving order; blocks that are not
// tool_use are skipped.
func AnthropicHandleToolUses(agent *FacadeAgent, blocks []map[string]any, mapping AdapterToolMapping, handlers map[string]AdapterToolHandler) []map[string]any {
	out := []map[string]any{}
	for _, b := range blocks {
		if b["type"] == "tool_use" {
			out = append(out, AnthropicHandleToolUse(agent, b, mapping, handlers))
		}
	}
	return out
}

// OpenAIDispatchToolCalls dispatches an array of tool calls sequentially (a model turn may return several) and stops at the first
// error, as the single-call form does.
func OpenAIDispatchToolCalls(agent *FacadeAgent, calls []map[string]any, mapping AdapterToolMapping, handlers map[string]AdapterToolHandler) ([]map[string]any, error) {
	out := make([]map[string]any, 0, len(calls))
	for _, c := range calls {
		m, err := OpenAIDispatchToolCall(agent, c, mapping, handlers)
		if err != nil {
			return out, err
		}
		out = append(out, m)
	}
	return out, nil
}

// WithPCAMessages wraps a model call taking {messages} (Anthropic messages.create) so every turn first records the conversation's new
// messages (user text is the principal; tool_result blocks are untrusted). Provenance by default.
func WithPCAMessages[R any](agent *FacadeAgent, create func(params map[string]any) R) func(params map[string]any) R {
	return func(params map[string]any) R {
		if agent != nil {
			_ = AdapterRecordMessages(agent.Provenance, params["messages"])
		}
		return create(params)
	}
}

// WithPCACompletions wraps a model call taking {messages} (OpenAI chat.completions.create) so every turn first records the
// conversation's new messages (user turns are the principal, tool turns untrusted). Provenance by default.
func WithPCACompletions[R any](agent *FacadeAgent, create func(params map[string]any) R) func(params map[string]any) R {
	return WithPCAMessages(agent, create)
}
