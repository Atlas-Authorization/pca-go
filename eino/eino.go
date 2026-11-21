// Package pcaeino wraps an Eino InvokableTool so every call first builds and signs a PCActn (handing the proof to your callback so it
// can forward it to the resource server), then runs the original tool and records its output for provenance. It authorizes
// nothing: the resource server's verifier decides; a bypassed wrapper just means the action lacks a valid PCActn and fails
// server-side. The wrapper exposes ONLY the invokable surface (Info, InvokableRun): a tool that also streams does not reach the
// ToolsNode through it unguarded. It lives in its own module so the core stays dependency-light.
package pcaeino

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/schema"

	pca "github.com/Atlas-Authorization/pca-go"
)

// Spec says how a tool call becomes a proof-carrying action.
type Spec struct {
	// Mapping maps the tool call to the verb and resource it acts on; a call it declines is refused (no tool runs without a proof).
	Mapping pca.AdapterToolMapping
	// OnProof receives the PCActn so you can forward it (e.g. as request headers) to the resource server.
	OnProof func(call *pca.PcaCall, args map[string]any)
}

type guarded struct {
	inner tool.InvokableTool
	agent *pca.FacadeAgent
	spec  Spec
}

// WithPCA wraps t: the returned tool keeps its Info and builds a PCActn before every InvokableRun. The arguments are the model's JSON
// object (empty means no arguments).
func WithPCA(agent *pca.FacadeAgent, spec Spec, t tool.InvokableTool) (tool.InvokableTool, error) {
	if agent == nil || t == nil || spec.Mapping == nil {
		return nil, errors.New("pcaeino: agent, tool and a mapping are required")
	}
	return &guarded{inner: t, agent: agent, spec: spec}, nil
}

func (g *guarded) Info(ctx context.Context) (*schema.ToolInfo, error) { return g.inner.Info(ctx) }

func (g *guarded) InvokableRun(ctx context.Context, argumentsInJSON string, opts ...tool.Option) (string, error) {
	info, err := g.inner.Info(ctx)
	if err != nil {
		return "", err
	}
	args := map[string]any{}
	if t := strings.TrimSpace(argumentsInJSON); t != "" {
		v, perr := pca.ParseJSONLenient([]byte(t))
		if perr != nil {
			return "", fmt.Errorf("pcaeino: tool arguments are not valid JSON: %w", perr)
		}
		m, ok := v.(map[string]any)
		if !ok {
			return "", errors.New("pcaeino: tool arguments are not a JSON object")
		}
		args = m
	}
	call, err := pca.AdapterBridgeToolCall(g.agent, info.Name, args, g.spec.Mapping)
	if err != nil {
		return "", err
	}
	if call == nil {
		return "", fmt.Errorf("pcaeino: no PCActn for unmapped tool %q (the mapping declined)", info.Name)
	}
	if g.spec.OnProof != nil {
		g.spec.OnProof(call, args)
	}
	out, err := g.inner.InvokableRun(ctx, argumentsInJSON, opts...)
	if err != nil {
		return "", err
	}
	if rerr := pca.AdapterRecordToolResult(g.agent.Provenance, info.Name, out); rerr != nil { // the output re-enters the model's context
		return "", rerr
	}
	return out, nil
}

// RecordInput records the principal's input (a string, {"input"} or {"messages"}) before running a graph or agent.
func RecordInput(agent *pca.FacadeAgent, input any) error {
	if agent == nil {
		return errors.New("pcaeino: agent is required")
	}
	return pca.AdapterRecordInput(agent.Provenance, input)
}
