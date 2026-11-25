package pca

import (
	"errors"
	"fmt"
)

// OAPcaDenied is the agent-side refusal: the local dry run says the grant does not permit the call (no tool ran).
type OAPcaDenied struct{ Reason, Verb, Resource string }

func (e *OAPcaDenied) Error() string { return e.Reason }

// OAAttachPCA is the agent side of a tool: a copy whose every call first builds a signed PCActn from its JSON object arguments
// (refused with *OAPcaDenied on a failing dry run unless failFast is false), hands it to onProof (nil: none) and runs the original,
// then records the output as untrusted tool output. It authorizes nothing; the resource server's verifier decides. resource maps the
// arguments to the resource the call acts on. Arguments that are not a JSON object are refused. Both the Execute and the
// OnInvokeTool (raw JSON text) forms are wrapped.
func OAAttachPCA(agent *FacadeAgent, verb string, resource func(params map[string]any) string, tool *OATool, onProof func(*PcaCall, map[string]any) error, failFast bool) (*OATool, error) {
	if agent == nil || tool == nil || resource == nil {
		return nil, errors.New("attach_pca: agent, tool and resource are required")
	}
	guarded := func(args any, run func() (any, error)) (any, error) {
		params, ok := args.(map[string]any)
		if !ok {
			return nil, errors.New("attach_pca: tool arguments must be a JSON object")
		}
		res := resource(params)
		act, err := agent.Act(verb, res, params, nil)
		if err != nil {
			return nil, err
		}
		if failFast && !act.DryRun.Allowed {
			reason := act.DryRun.Reason
			if reason == "" {
				reason = "denied"
			}
			return nil, &OAPcaDenied{Reason: reason, Verb: verb, Resource: res}
		}
		if onProof != nil {
			call := &PcaCall{Encoded: act.Encoded, PCActn: act.PCActn, Headers: act.Headers, Provenance: act.Provenance}
			if err := onProof(call, params); err != nil {
				return nil, err
			}
		}
		out, err := run()
		if err != nil {
			return nil, err
		}
		if err := AdapterRecordToolResult(agent.Provenance, verb, out); err != nil {
			return nil, fmt.Errorf("attach_pca: %w", err)
		}
		return out, nil
	}
	cp := *tool
	if tool.OnInvokeTool != nil {
		cp.OnInvokeTool = func(ctx any, raw any) (any, error) {
			return guarded(oaParseArgs(raw), func() (any, error) { return tool.OnInvokeTool(ctx, raw) })
		}
	}
	if tool.Execute != nil {
		cp.Execute = func(input any, ctx any) (any, error) {
			return guarded(input, func() (any, error) { return tool.Execute(input, ctx) })
		}
	}
	return &cp, nil
}
