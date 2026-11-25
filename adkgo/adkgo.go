// Package pcaadk wraps a Google ADK-Go tool so every call first builds and signs a PCActn (handing the proof to your callback so it
// can forward it to the resource server), then runs the original tool and records its output for provenance. It authorizes
// nothing: the resource server's verifier decides; a bypassed wrapper just means the action lacks a valid PCActn and fails
// server-side. Both execution surfaces of ADK are wrapped (Run, and RunStream, which the flow dispatches on first); the wrapper
// embeds only the surface it wraps, so a tool that also has the other method never reaches the flow through it unguarded. A tool the
// flow cannot execute itself (a model-side built-in) has nothing to guard and is refused. It lives in its own module so the core
// stays dependency-light.
package pcaadk

import (
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"strings"

	"google.golang.org/adk/v2/agent"
	"google.golang.org/adk/v2/model"
	"google.golang.org/adk/v2/tool"
	"google.golang.org/adk/v2/tool/toolutils"
	"google.golang.org/genai"

	pca "github.com/Atlas-Authorization/pca-go"
)

// Spec says how a tool call becomes a proof-carrying action.
type Spec struct {
	// Mapping maps the tool call to the verb and resource it acts on; a call it declines is refused (no tool runs without a proof).
	Mapping pca.AdapterToolMapping
	// OnProof receives the PCActn so you can forward it (e.g. as request headers) to the resource server.
	OnProof func(call *pca.PcaCall, args map[string]any)
}

// runnableTool and streamingTool mirror the executable tool surfaces of the ADK flow (declared here: the originals are internal).
type runnableTool interface {
	tool.Tool
	Declaration() *genai.FunctionDeclaration
	Run(ctx agent.Context, args any) (map[string]any, error)
}

type streamingTool interface {
	tool.Tool
	Declaration() *genai.FunctionDeclaration
	RunStream(ctx agent.Context, args any) iter.Seq2[string, error]
}

type requestProcessor interface {
	ProcessRequest(ctx agent.Context, req *model.LLMRequest) error
}

// WithPCA wraps t, which must be an executable tool (a function tool or a streaming function tool).
func WithPCA(ag *pca.FacadeAgent, spec Spec, t tool.Tool) (tool.Tool, error) {
	if ag == nil || t == nil || spec.Mapping == nil {
		return nil, errors.New("pcaadk: agent, tool and a mapping are required")
	}
	g := guard{agent: ag, spec: spec}
	switch rt := t.(type) { // the flow dispatches on the streaming surface first
	case streamingTool:
		return &guardedStream{streamingTool: rt, guard: g}, nil
	case runnableTool:
		return &guardedRun{runnableTool: rt, guard: g}, nil
	}
	return nil, fmt.Errorf("pcaadk: tool %q is not executable by the flow (no Run or RunStream): nothing to guard", t.Name())
}

type guard struct {
	agent *pca.FacadeAgent
	spec  Spec
}

// toArgs turns the call's arguments into the JSON object the action carries (numbers keep their lexeme).
func toArgs(in any) (map[string]any, error) {
	raw, err := json.Marshal(in)
	if err != nil {
		return nil, err
	}
	v, err := pca.ParseJSONLenient(raw)
	if err != nil {
		return nil, err
	}
	if v == nil {
		return map[string]any{}, nil
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("pcaadk: the tool arguments are not a JSON object")
	}
	return m, nil
}

// prove builds the PCActn for the call and hands it to OnProof; a declined mapping is an error.
func (g guard) prove(name string, in any) (map[string]any, error) {
	args, err := toArgs(in)
	if err != nil {
		return nil, err
	}
	call, err := pca.AdapterBridgeToolCall(g.agent, name, args, g.spec.Mapping)
	if err != nil {
		return nil, err
	}
	if call == nil {
		return nil, fmt.Errorf("pcaadk: no PCActn for unmapped tool %q (the mapping declined)", name)
	}
	if g.spec.OnProof != nil {
		g.spec.OnProof(call, args)
	}
	return args, nil
}

// pack puts the guarded wrapper (not the inner tool) into the request, so the flow calls the wrapper.
func pack(inner any, self toolutils.Tool, name string, ctx agent.Context, req *model.LLMRequest) error {
	if rp, ok := inner.(requestProcessor); ok {
		_, existedBefore := req.Tools[name]
		if err := rp.ProcessRequest(ctx, req); err != nil {
			return err
		}
		if !existedBefore && req.Tools != nil && req.Tools[name] != nil {
			req.Tools[name] = self
			return nil
		}
	}
	return toolutils.PackTool(req, self)
}

type guardedRun struct {
	runnableTool
	guard
}

func (t *guardedRun) Declaration() *genai.FunctionDeclaration { return t.runnableTool.Declaration() }

func (t *guardedRun) ProcessRequest(ctx agent.Context, req *model.LLMRequest) error {
	return pack(t.runnableTool, t, t.Name(), ctx, req)
}

func (t *guardedRun) Run(ctx agent.Context, args any) (map[string]any, error) {
	if _, err := t.prove(t.Name(), args); err != nil {
		return nil, err
	}
	out, err := t.runnableTool.Run(ctx, args)
	if err != nil {
		return nil, err
	}
	if rerr := pca.AdapterRecordToolResult(t.agent.Provenance, t.Name(), out); rerr != nil { // the result re-enters the model's context
		return nil, rerr
	}
	return out, nil
}

type guardedStream struct {
	streamingTool
	guard
}

func (t *guardedStream) Declaration() *genai.FunctionDeclaration {
	return t.streamingTool.Declaration()
}

func (t *guardedStream) ProcessRequest(ctx agent.Context, req *model.LLMRequest) error {
	return pack(t.streamingTool, t, t.Name(), ctx, req)
}

func (t *guardedStream) RunStream(ctx agent.Context, args any) iter.Seq2[string, error] {
	return func(yield func(string, error) bool) {
		if _, err := t.prove(t.Name(), args); err != nil {
			yield("", err)
			return
		}
		var all strings.Builder
		defer func() { _ = pca.AdapterRecordToolResult(t.agent.Provenance, t.Name(), all.String()) }() // whatever reached the model, even when the reader stops early
		for chunk, err := range t.streamingTool.RunStream(ctx, args) {
			all.WriteString(chunk)
			if !yield(chunk, err) {
				return
			}
		}
	}
}

// RecordInput records the principal's input (a string, {"input"} or {"messages"}) before running the agent.
func RecordInput(ag *pca.FacadeAgent, input any) error {
	if ag == nil {
		return errors.New("pcaadk: agent is required")
	}
	return pca.AdapterRecordInput(ag.Provenance, input)
}
