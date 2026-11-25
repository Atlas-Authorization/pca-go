// Package pcaanthropic is the typed Anthropic SDK adapter for Proof-Carrying Authority: it answers a model's tool_use blocks with
// tool_result blocks, building and signing a PCActn for every tool call first and recording what enters the model's context for
// provenance. It authorizes nothing: the resource server's verifier decides. It lives in its own module so the core stays
// dependency-light.
package pcaanthropic

import (
	"encoding/json"
	"errors"

	"github.com/anthropics/anthropic-sdk-go"

	pca "github.com/Atlas-Authorization/pca-go"
)

func toJSONValue(v any) (any, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return pca.ParseJSONLenient(raw)
}

// ToolResultMessage runs every tool_use block of the assistant message through the proof-carrying bridge (a PCActn per call,
// handlers[name] runs with its proof) and returns the user message of tool_result blocks to send back. An unmapped tool, a
// missing handler or a failing handler is an is_error result the model sees; nothing runs without a proof. It reports false
// when the message holds no tool_use block.
func ToolResultMessage(agent *pca.FacadeAgent, msg *anthropic.Message, mapping pca.AdapterToolMapping, handlers map[string]pca.AdapterToolHandler) (anthropic.MessageParam, bool, error) {
	if agent == nil || msg == nil {
		return anthropic.MessageParam{}, false, errors.New("pcaanthropic: agent and message are required")
	}
	content, err := toJSONValue(msg.Content)
	if err != nil {
		return anthropic.MessageParam{}, false, err
	}
	list, _ := content.([]any)
	var blocks []anthropic.ContentBlockParamUnion
	for _, use := range pca.AnthropicExtractToolUses(list) {
		res := pca.AnthropicHandleToolUse(agent, use, mapping, handlers)
		id, _ := res["tool_use_id"].(string)
		text, _ := res["content"].(string)
		isErr, _ := res["is_error"].(bool)
		blocks = append(blocks, anthropic.NewToolResultBlock(id, text, isErr))
	}
	if len(blocks) == 0 {
		return anthropic.MessageParam{}, false, nil
	}
	return anthropic.NewUserMessage(blocks...), true, nil
}

// RecordMessages feeds the conversation to the agent's provenance recorder (the principal's turns are trusted, tool output is
// not); call it with the whole list before each model turn: messages already recorded are skipped.
func RecordMessages(agent *pca.FacadeAgent, messages []anthropic.MessageParam) error {
	if agent == nil {
		return errors.New("pcaanthropic: agent is required")
	}
	v, err := toJSONValue(messages)
	if err != nil {
		return err
	}
	return pca.AdapterRecordMessages(agent.Provenance, v)
}
