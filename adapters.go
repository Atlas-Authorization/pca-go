package pca

// Agent-side tool-call bridge for AI frameworks: build a signed PCActn for each tool call a model asks for, hand the tool the
// proof, and feed the provenance recorder the way the reference does (the principal's turns are TRUSTED, tool output UNTRUSTED).
// Nothing here authorizes: the resource server's verifier decides. Model messages and tool calls are duck-typed parsed-JSON
// values (map[string]any / []any / string / json.Number), so no vendor SDK is imported; the OpenAI and Anthropic helpers below
// take the wire shapes of those APIs.

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
)

// AdapterProvHeaderMax is the largest bundle carried as a header (base64url characters); a larger one goes in the request body as
// the pca_provenance member.
const AdapterProvHeaderMax = 8192

// PcaCall is what a guarded dispatch receives: the encoded PCActn JSON, the PCActn and the headers that carry it. Provenance is the
// action's provenance bundle (send it as the body member pca_provenance when it is not in Headers).
type PcaCall struct {
	Encoded    string
	PCActn     map[string]any
	Headers    map[string]string
	Provenance map[string]any
}

// AdapterToolMapping maps a tool call to the verb and resource it acts on; ok false declines the call (an unmapped tool).
type AdapterToolMapping func(name string, args map[string]any) (verb, resource string, ok bool)

// AdapterToolHandler runs a tool with its arguments and proof; a nil result sends the encoded PCActn back as the output.
type AdapterToolHandler func(args any, pca *PcaCall) (any, error)

// AdapterBridgeToolCall turns a tool call into a PCActn using mapping; nil when the mapping declines the call. No dry run here:
// an out-of-policy call still yields a signed PCActn and is refused server-side.
func AdapterBridgeToolCall(agent *FacadeAgent, name string, args map[string]any, mapping AdapterToolMapping) (*PcaCall, error) {
	verb, resource, ok := mapping(name, args)
	if !ok {
		return nil, nil
	}
	res, err := agent.Act(verb, resource, args, nil)
	if err != nil {
		return nil, err
	}
	return &PcaCall{Encoded: res.Encoded, PCActn: res.PCActn, Headers: res.Headers, Provenance: res.Provenance}, nil
}

// AdapterProvenanceHeaders is PCA-Provenance: <base64url canonical JSON> for a bundle that fits AdapterProvHeaderMax; empty
// otherwise (send it in the body). A bundle that is not strict canonical JSON is an error.
func AdapterProvenanceHeaders(bundle any) (map[string]string, error) {
	if bundle == nil {
		return map[string]string{}, nil
	}
	c, err := Canonicalize(bundle)
	if err != nil {
		return nil, err
	}
	v := b64.EncodeToString([]byte(c))
	if len(v) <= AdapterProvHeaderMax {
		return map[string]string{ProvenanceHeader: v}, nil
	}
	return map[string]string{}, nil
}

// adapterJsString is JavaScript String(v) for JSON values.
func adapterJsString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case nil:
		return "null"
	case bool:
		if t {
			return "true"
		}
		return "false"
	case []any:
		parts := make([]string, len(t))
		for i, x := range t {
			if x != nil {
				parts[i] = adapterJsString(x)
			}
		}
		return strings.Join(parts, ",")
	case map[string]any:
		return "[object Object]"
	}
	if f, ok := jsNum(v); ok {
		return jsNumberString(f)
	}
	return fmt.Sprint(v)
}

func adapterJsJSON(v any) (string, error) {
	var sb strings.Builder
	if err := siemStringify(&sb, v); err != nil {
		return "", err
	}
	return sb.String(), nil
}

func adapterGet(o any, k string) any {
	if m, ok := o.(map[string]any); ok {
		return m[k]
	}
	return nil
}

func adapterFirst(vals ...any) any {
	for _, v := range vals {
		if v != nil {
			return v
		}
	}
	return nil
}

func adapterRole(m any) string {
	for _, k := range []string{"role", "type"} {
		if s, ok := adapterGet(m, k).(string); ok {
			return s
		}
	}
	return ""
}

// AdapterMessageSegments are the context segments a chat message adds, by the conversation's own roles: a user / human turn is the
// PRINCIPAL; a tool_result / tool-result / function_call_output part inside any turn, a tool / function turn and a turn of an
// unknown role are UNTRUSTED tool output; assistant / system / developer turns add nothing. Each segment is
// {origin, source, content}.
func AdapterMessageSegments(m any) []map[string]any {
	switch m.(type) {
	case nil, string, bool, json.Number, float64, int, int64:
		return []map[string]any{}
	}
	role := strings.ToLower(adapterRole(m))
	switch role {
	case "assistant", "ai", "model", "system", "developer":
		return []map[string]any{}
	}
	content := adapterGet(m, "content")
	toolName := func(x any) string {
		return adapterJsString(adapterFirst(adapterGet(x, "toolName"), adapterGet(x, "name"), adapterGet(x, "tool_use_id"),
			adapterGet(x, "toolCallId"), adapterGet(x, "tool_call_id"), adapterGet(m, "name"), adapterGet(m, "tool_call_id"), "tool"))
	}
	if role != "user" && role != "human" {
		return []map[string]any{{"origin": "tool", "source": toolName(m), "content": adapterFirst(content, m)}}
	}
	parts, isList := content.([]any)
	if !isList {
		if content == nil {
			content = ""
		}
		return []map[string]any{{"origin": "principal", "source": "user", "content": content}}
	}
	out := []map[string]any{}
	var text []string
	for _, part := range parts {
		pt := part
		switch part.(type) {
		case map[string]any, []any:
		default:
			pt = map[string]any{"type": "text", "text": adapterJsString(part)}
		}
		t, _ := adapterGet(pt, "type").(string)
		if t == "tool_result" || t == "tool-result" || t == "function_call_output" {
			out = append(out, map[string]any{"origin": "tool", "source": toolName(pt),
				"content": adapterFirst(adapterGet(pt, "content"), adapterGet(pt, "result"), adapterGet(pt, "output"), pt)})
		} else if s, ok := adapterGet(pt, "text").(string); ok {
			text = append(text, s)
		} else {
			out = append(out, map[string]any{"origin": "principal", "source": "user", "content": pt})
		}
	}
	if len(text) > 0 {
		out = append([]map[string]any{{"origin": "principal", "source": "user", "content": strings.Join(text, "\n")}}, out...)
	}
	return out
}

var (
	adapterSeenMu sync.Mutex
	adapterSeen   = map[*ProvenanceRecorder]int{} // shortcut: one entry per recorder for the process lifetime, bounded by the sessions
)

// AdapterRecordPrincipal records the principal's own message (TRUSTED); a nil recorder records nothing.
func AdapterRecordPrincipal(rec *ProvenanceRecorder, text string) error {
	if rec == nil {
		return nil
	}
	_, err := rec.Principal(text)
	return err
}

// AdapterRecordToolResult records a tool result entering the model's context (UNTRUSTED).
func AdapterRecordToolResult(rec *ProvenanceRecorder, tool string, output any) error {
	if rec == nil {
		return nil
	}
	_, err := rec.Tool(tool, output)
	return err
}

// AdapterRecordMessages records a conversation's new messages (call it with the whole list before each model turn: messages
// already recorded are skipped, a shorter list starts over).
func AdapterRecordMessages(rec *ProvenanceRecorder, messages any) error {
	list, ok := messages.([]any)
	if rec == nil || !ok {
		return nil
	}
	adapterSeenMu.Lock()
	seen := adapterSeen[rec]
	adapterSeenMu.Unlock()
	start := seen
	if len(list) < seen {
		start = 0
	}
	for i := start; i < len(list); i++ {
		for _, seg := range AdapterMessageSegments(list[i]) {
			content := seg["content"]
			var err error
			if seg["origin"] == "principal" {
				text, isStr := content.(string)
				if !isStr {
					if text, err = adapterJsJSON(content); err != nil {
						return err
					}
				}
				_, err = rec.Principal(text)
			} else {
				_, err = rec.Tool(seg["source"].(string), content)
			}
			if err != nil {
				return err
			}
		}
	}
	adapterSeenMu.Lock()
	adapterSeen[rec] = len(list)
	adapterSeenMu.Unlock()
	return nil
}

// AdapterRecordInput records what the principal asked for: a string is the principal's message; a message list (or
// {"messages": [...]}) goes through AdapterRecordMessages; an object's input / prompt / query / question / message / text string
// (or message list) is the principal's message. Anything else records nothing (the gate then keeps the context at agent: fail
// closed).
func AdapterRecordInput(rec *ProvenanceRecorder, input any) error {
	if rec == nil {
		return nil
	}
	switch t := input.(type) {
	case string:
		return AdapterRecordPrincipal(rec, t)
	case []any:
		return AdapterRecordMessages(rec, t)
	case map[string]any:
		if l, ok := t["messages"].([]any); ok {
			if err := AdapterRecordMessages(rec, l); err != nil {
				return err
			}
		}
		for _, k := range []string{"input", "prompt", "query", "question", "message", "text"} {
			switch v := t[k].(type) {
			case string:
				if err := AdapterRecordPrincipal(rec, v); err != nil {
					return err
				}
			case []any:
				if err := AdapterRecordMessages(rec, v); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func adapterToolOutput(agent *FacadeAgent, name string, pca *PcaCall, result any) (string, error) {
	var content string
	var err error
	if result == nil {
		content, err = adapterJsJSON(map[string]any{"pca": pca.Encoded})
	} else {
		content, err = adapterJsJSON(result)
	}
	if err != nil {
		return "", err
	}
	if rerr := AdapterRecordToolResult(agent.Provenance, name, content); rerr != nil { // the output re-enters the model's context
		return "", rerr
	}
	return content, nil
}

func adapterRun(h AdapterToolHandler, args any, pca *PcaCall) (res any, err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("%v", p)
		}
	}()
	return h(args, pca)
}

// AnthropicHandleToolUse builds the PCActn for one tool_use block, runs handlers[name](input, pca) and returns the tool_result
// block. A declined tool, a missing handler or a failing handler yields an is_error result; the model sees the refusal text.
func AnthropicHandleToolUse(agent *FacadeAgent, block map[string]any, mapping AdapterToolMapping, handlers map[string]AdapterToolHandler) map[string]any {
	name, _ := block["name"].(string)
	id := block["id"]
	fail := func(msg string) map[string]any {
		return map[string]any{"type": "tool_result", "tool_use_id": id, "content": msg, "is_error": true}
	}
	in, _ := block["input"].(map[string]any)
	pca, err := AdapterBridgeToolCall(agent, name, in, mapping)
	if err != nil {
		return fail(err.Error())
	}
	if pca == nil {
		return fail(fmt.Sprintf("No proof-carrying authority is mapped for tool %q.", name))
	}
	h := handlers[name]
	if h == nil {
		return fail(fmt.Sprintf("No handler registered for tool %q.", name))
	}
	result, err := adapterRun(h, block["input"], pca)
	if err != nil {
		_ = AdapterRecordToolResult(agent.Provenance, name, err.Error()) // a tool's error text reaches the model too
		return fail(err.Error())
	}
	content, err := adapterToolOutput(agent, name, pca, result)
	if err != nil {
		return fail(err.Error())
	}
	return map[string]any{"type": "tool_result", "tool_use_id": id, "content": content}
}

// AnthropicExtractToolUses are the tool_use blocks of an assistant message's content.
func AnthropicExtractToolUses(content []any) []map[string]any {
	var out []map[string]any
	for _, b := range content {
		if m, ok := b.(map[string]any); ok && m["type"] == "tool_use" {
			out = append(out, m)
		}
	}
	return out
}

// OpenAIDispatchToolCall builds and signs a PCActn for one chat tool_call, runs handlers[name](args, pca) and returns the tool
// message. An unmapped tool is an error: no tool runs without a proof.
func OpenAIDispatchToolCall(agent *FacadeAgent, call map[string]any, mapping AdapterToolMapping, handlers map[string]AdapterToolHandler) (map[string]any, error) {
	fn, _ := call["function"].(map[string]any)
	name, _ := fn["name"].(string)
	args := map[string]any{}
	if raw, ok := fn["arguments"].(string); ok && strings.TrimSpace(raw) != "" {
		parsed, err := ParseJSONLenient([]byte(strings.TrimSpace(raw)))
		if err != nil {
			return nil, err
		}
		m, isObj := parsed.(map[string]any)
		if !isObj {
			return nil, errors.New("dispatchToolCall: tool_call arguments must be a JSON object")
		}
		args = m
	}
	pca, err := AdapterBridgeToolCall(agent, name, args, mapping)
	if err != nil {
		return nil, err
	}
	if pca == nil {
		return nil, fmt.Errorf("dispatchToolCall: no PCActn for unmapped tool %q (the mapping declined)", name)
	}
	var result any
	if h := handlers[name]; h != nil {
		if result, err = h(args, pca); err != nil {
			return nil, err
		}
	}
	content, err := adapterToolOutput(agent, name, pca, result)
	if err != nil {
		return nil, err
	}
	return map[string]any{"role": "tool", "tool_call_id": call["id"], "content": content}, nil
}
