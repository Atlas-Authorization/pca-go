package pca

// A framework-neutral guarded tool, for agent frameworks whose tool is "metadata plus a call method" (the LlamaIndex shape and its
// many look-alikes). GuardedTool wraps one so every call first builds a PCActn through the agent (failing fast on the agent's local
// dry run and handing the proof to OnProof so it can be forwarded to the resource server), then runs the original tool and records
// its result as untrusted tool output in the agent's provenance. The wrapped tool has the same shape and keeps its metadata.
//
// HONEST: this does not authorize. It attaches a proof-carrying action; the resource server's verifier decides, and a bypassed
// wrapper just yields an action without a valid PCActn that fails server-side. The local dry run is a fast-fail, not a grant.

import (
	"context"
	"errors"
	"fmt"
)

// ToolMetadata is a tool's name, description and parameter schema.
type ToolMetadata struct {
	Name        string
	Description string
	Parameters  any
}

// Tool is the structural tool shape: metadata and a call over the model's arguments.
type Tool interface {
	Metadata() ToolMetadata
	Call(ctx context.Context, args map[string]any) (any, error)
}

// GuardToolSpec says how a tool call becomes a proof-carrying action. Resource is fixed, or ResourceFn derives it from the
// arguments (ResourceFn wins). Aud overrides the agent's audience for this tool; NoFailFast skips the local dry run.
type GuardToolSpec struct {
	Verb       string
	Resource   string
	ResourceFn func(args map[string]any) string
	Aud        string
	NoFailFast bool
	OnProof    func(call *PcaCall, args map[string]any)
}

type guardedTool struct {
	Tool
	agent *FacadeAgent
	spec  GuardToolSpec
}

// GuardedTool wraps tool; see the file comment.
func GuardedTool(agent *FacadeAgent, spec GuardToolSpec, tool Tool) (Tool, error) {
	if agent == nil || tool == nil {
		return nil, errors.New("GuardedTool: agent and tool are required")
	}
	if spec.Verb == "" {
		return nil, errors.New("GuardedTool: verb is required")
	}
	return &guardedTool{Tool: tool, agent: agent, spec: spec}, nil
}

func (g *guardedTool) Call(ctx context.Context, args map[string]any) (any, error) {
	resource := g.spec.Resource
	if g.spec.ResourceFn != nil {
		resource = g.spec.ResourceFn(args)
	}
	act, err := g.agent.Act(g.spec.Verb, resource, args, &ActOptions{Aud: g.spec.Aud})
	if err != nil {
		return nil, err
	}
	if !g.spec.NoFailFast && !act.DryRun.Allowed {
		return nil, fmt.Errorf("PCA denied %s on %s: %s", g.spec.Verb, resource, act.DryRun.Reason)
	}
	if g.spec.OnProof != nil {
		g.spec.OnProof(&PcaCall{Encoded: act.Encoded, PCActn: act.PCActn, Headers: act.Headers, Provenance: act.Provenance}, args)
	}
	out, err := g.Tool.Call(ctx, args)
	if err != nil {
		return nil, err
	}
	if rerr := AdapterRecordToolResult(g.agent.Provenance, g.spec.Verb, out); rerr != nil { // the result re-enters the model's context
		return nil, rerr
	}
	return out, nil
}

// GuardedEngine wraps a chat or query function of an engine or agent: each call first records the principal's request (the
// message, the query or a string; user turns of a chatHistory are the principal, tool turns untrusted), then runs fn.
func GuardedEngine(agent *FacadeAgent, fn func(params any) (any, error)) func(params any) (any, error) {
	return func(params any) (any, error) {
		if m, ok := params.(map[string]any); ok {
			if h, isList := m["chatHistory"].([]any); isList {
				if err := AdapterRecordMessages(agent.Provenance, h); err != nil {
					return nil, err
				}
			}
		}
		if err := AdapterRecordInput(agent.Provenance, params); err != nil {
			return nil, err
		}
		return fn(params)
	}
}
