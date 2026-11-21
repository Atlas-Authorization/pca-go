package pca

// withPCA for a Model Context Protocol tool handler, over plain values: every call first builds a PCActn through the agent
// (failing fast on the agent's local dry run and handing the proof to OnProof so it can be forwarded to the resource server),
// then runs the original handler and records its result as untrusted tool output in the agent's provenance.
//
// HONEST: this does not authorize. It attaches a proof-carrying action; the resource server's verifier decides, and a bypassed
// wrapper just yields an action without a valid PCActn that fails server-side. The local dry run is a fast-fail, not a grant.
// The per-request transport wrapper is McpPcaFetch (mcp_fetch.go).

import (
	"errors"
	"fmt"
)

// McpToolHandler is an MCP tool handler: (arguments, extra) -> a result object {content: [...], isError?, _meta?}.
type McpToolHandler func(args map[string]any, extra any) (map[string]any, error)

// McpGuardSpec describes the tool: Verb is the catalog verb, Resource a fixed resource or ResourceFn derives it from the arguments
// (ResourceFn wins). NoFailFast skips the local dry run. A per-call audience is not supported (set it on the agent): Aud is refused.
type McpGuardSpec struct {
	Verb       string
	Resource   string
	ResourceFn func(args map[string]any) string
	NoFailFast bool
	Aud        string
	OnProof    func(pca *PcaCall, args map[string]any)
}

// McpDeniedToolResult is the in-band tool error returned when the local dry run denies a call, as the reference does.
func McpDeniedToolResult(text string) map[string]any {
	return map[string]any{"content": []any{map[string]any{"type": "text", "text": text}}, "isError": true}
}

// McpWithPCA wraps handler so each call emits a PCActn before the handler runs. A local denial returns the MCP error result
// (not an error); an agent that cannot build the action returns the error and the handler never runs.
func McpWithPCA(agent *FacadeAgent, spec McpGuardSpec, handler McpToolHandler) (McpToolHandler, error) {
	if agent == nil || handler == nil {
		return nil, errors.New("McpWithPCA: agent and handler are required")
	}
	if spec.Aud != "" {
		return nil, errors.New("McpWithPCA: a per-call audience is not supported; set it on the agent")
	}
	if spec.Verb == "" {
		return nil, errors.New("McpWithPCA: verb is required")
	}
	return func(args map[string]any, extra any) (map[string]any, error) {
		resource := spec.Resource
		if spec.ResourceFn != nil {
			resource = spec.ResourceFn(args)
		}
		act, err := agent.Act(spec.Verb, resource, args, nil)
		if err != nil {
			return nil, err
		}
		if !spec.NoFailFast && !act.DryRun.Allowed {
			return McpDeniedToolResult(fmt.Sprintf("PCA denied %s on %s: %s", spec.Verb, resource, act.DryRun.Reason)), nil
		}
		call := &PcaCall{Encoded: act.Encoded, PCActn: act.PCActn, Headers: act.Headers, Provenance: act.Provenance}
		if spec.OnProof != nil {
			spec.OnProof(call, args)
		}
		out, err := handler(args, extra)
		if err != nil {
			return nil, err
		}
		if rerr := AdapterRecordToolResult(agent.Provenance, spec.Verb, out); rerr != nil { // the result re-enters the model's context
			return nil, rerr
		}
		return out, nil
	}, nil
}
