package pca

// The agent side of an MCP server that requires a PCActn per tool call, as an http.RoundTripper for the MCP client transport. For
// every JSON-RPC tools/call request it builds a fresh PCActn for that call (verb and resource from the mapping, the tool arguments
// committed by digest, a new counter) and adds its headers; every other request passes through unchanged. It decides nothing: the
// server's verifier does. The agent's provenance bundle rides with the proof and each tools/call response is recorded in the agent's
// chain as UNTRUSTED tool output before it is returned.

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"strings"
)

// McpToolCall is the tools/call request a body carries; nil when the body is anything else.
type mcpToolCall struct {
	name string
	args map[string]any
}

func mcpToolCallOf(body []byte) *mcpToolCall {
	v, err := ParseJSONLenient(body)
	msg, ok := v.(map[string]any)
	if err != nil || !ok || msg["method"] != "tools/call" {
		return nil
	}
	params, _ := msg["params"].(map[string]any)
	name, ok := params["name"].(string)
	if !ok {
		return nil
	}
	args, ok := params["arguments"].(map[string]any)
	if !ok {
		args = map[string]any{}
	}
	return &mcpToolCall{name: name, args: args}
}

type mcpFetchTransport struct {
	agent   *FacadeAgent
	mapping AdapterToolMapping
	aud     string
	next    http.RoundTripper
}

// McpPcaFetch wraps next (nil: http.DefaultTransport). aud overrides the proofs' audience ("" keeps the agent's).
func McpPcaFetch(agent *FacadeAgent, mapping AdapterToolMapping, aud string, next http.RoundTripper) (http.RoundTripper, error) {
	if agent == nil || mapping == nil {
		return nil, errors.New("McpPcaFetch: agent and mapping are required")
	}
	if next == nil {
		next = http.DefaultTransport
	}
	return &mcpFetchTransport{agent: agent, mapping: mapping, aud: aud, next: next}, nil
}

func (t *mcpFetchTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Body == nil || req.Body == http.NoBody {
		return t.next.RoundTrip(req)
	}
	raw, err := io.ReadAll(req.Body)
	_ = req.Body.Close()
	if err != nil {
		return nil, err
	}
	restored := req.Clone(req.Context())
	restored.Body = io.NopCloser(bytes.NewReader(raw))
	restored.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(raw)), nil }
	call := mcpToolCallOf(raw)
	if call == nil {
		return t.next.RoundTrip(restored)
	}
	verb, resource, ok := t.mapping(call.name, call.args)
	if !ok {
		return t.next.RoundTrip(restored)
	}
	act, err := t.agent.Act(verb, resource, call.args, &ActOptions{Aud: t.aud})
	if err != nil {
		return nil, err
	}
	for k, v := range act.Headers {
		restored.Header.Set(k, v)
	}
	res, err := t.next.RoundTrip(restored)
	if err != nil {
		return nil, err
	}
	// the tool result enters the model's context: record it (untrusted) before the caller can act on it. A JSON body is recorded by
	// its bytes; a stream is recorded at once by its origin.
	var content any = map[string]any{"tool": call.name, "stream": req.URL.String()}
	if !strings.Contains(strings.ToLower(res.Header.Get("Content-Type")), "event-stream") && res.Body != nil {
		b, rerr := io.ReadAll(res.Body)
		_ = res.Body.Close()
		if rerr != nil {
			return nil, rerr
		}
		res.Body = io.NopCloser(bytes.NewReader(b))
		content = string(b)
	}
	if rerr := AdapterRecordToolResult(t.agent.Provenance, call.name, content); rerr != nil {
		return nil, rerr
	}
	return res, nil
}
