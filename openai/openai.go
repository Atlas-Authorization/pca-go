// Package pcaopenai is the typed OpenAI SDK adapter for Proof-Carrying Authority: it answers a chat completion's tool calls with
// tool messages, building and signing a PCActn for every call first and recording what enters the model's context for
// provenance. It authorizes nothing: the resource server's verifier decides. It lives in its own module so the core stays
// dependency-light.
package pcaopenai

import (
	"encoding/json"
	"errors"

	"github.com/openai/openai-go"

	pca "github.com/Atlas-Authorization/pca-go"
)

func toJSONValue(v any) (any, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return pca.ParseJSONLenient(raw)
}

// ToolMessages dispatches every tool call of the assistant message (a chat completion message, e.g. Choices[0].Message) through
// the proof-carrying bridge and returns the tool messages to append. A call the mapping declines, an unparseable argument string
// or a failing handler is an error: no tool runs without a proof.
func ToolMessages(agent *pca.FacadeAgent, assistantMessage any, mapping pca.AdapterToolMapping, handlers map[string]pca.AdapterToolHandler) ([]openai.ChatCompletionMessageParamUnion, error) {
	if agent == nil {
		return nil, errors.New("pcaopenai: agent is required")
	}
	v, err := toJSONValue(assistantMessage)
	if err != nil {
		return nil, err
	}
	msg, _ := v.(map[string]any)
	calls, _ := msg["tool_calls"].([]any)
	var out []openai.ChatCompletionMessageParamUnion
	for _, c := range calls {
		call, ok := c.(map[string]any)
		if !ok {
			return nil, errors.New("pcaopenai: a tool call is not an object")
		}
		res, err := pca.OpenAIDispatchToolCall(agent, call, mapping, handlers)
		if err != nil {
			return nil, err
		}
		id, _ := res["tool_call_id"].(string)
		content, _ := res["content"].(string)
		out = append(out, openai.ToolMessage(content, id))
	}
	return out, nil
}

// RecordMessages feeds the conversation (the request's messages) to the agent's provenance recorder; call it with the whole list
// before each model turn: messages already recorded are skipped.
func RecordMessages(agent *pca.FacadeAgent, messages any) error {
	if agent == nil {
		return errors.New("pcaopenai: agent is required")
	}
	v, err := toJSONValue(messages)
	if err != nil {
		return err
	}
	return pca.AdapterRecordMessages(agent.Provenance, v)
}
