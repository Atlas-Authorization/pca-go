// Package pcagenkit wraps a Genkit tool function so every call first builds and signs a PCActn (handing the proof to your callback
// so it can forward it to the resource server), then runs the original function and records its output for provenance. It
// authorizes nothing: the resource server's verifier decides; a bypassed wrapper just means the action lacks a valid PCActn and
// fails server-side. Wrap the function you pass to genkit.DefineTool, so the tool keeps its name, schema and description.
// It lives in its own module so the core stays dependency-light.
package pcagenkit

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/firebase/genkit/go/ai"

	pca "github.com/Atlas-Authorization/pca-go"
)

// Spec says how a tool call becomes a proof-carrying action.
type Spec struct {
	// Mapping maps the tool call to the verb and resource it acts on; a call it declines is refused (no tool runs without a proof).
	Mapping pca.AdapterToolMapping
	// OnProof receives the PCActn so you can forward it (e.g. as request headers) to the resource server.
	OnProof func(call *pca.PcaCall, args map[string]any)
}

// toArgs turns the typed tool input into the JSON object the action carries (numbers keep their lexeme).
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
		return nil, errors.New("pcagenkit: the tool input is not a JSON object")
	}
	return m, nil
}

// WithPCA wraps fn: the returned function builds a PCActn before every call, so a tool without a proof never runs, and records the
// output (it re-enters the model's context) before returning it. name is the tool's name as registered with Genkit.
func WithPCA[In, Out any](agent *pca.FacadeAgent, spec Spec, name string, fn func(*ai.ToolContext, In) (Out, error)) (func(*ai.ToolContext, In) (Out, error), error) {
	if agent == nil || fn == nil || spec.Mapping == nil || name == "" {
		return nil, errors.New("pcagenkit: agent, a tool name, a function and a mapping are required")
	}
	return func(tc *ai.ToolContext, in In) (Out, error) {
		var zero Out
		args, err := toArgs(in)
		if err != nil {
			return zero, err
		}
		call, err := pca.AdapterBridgeToolCall(agent, name, args, spec.Mapping)
		if err != nil {
			return zero, err
		}
		if call == nil {
			return zero, fmt.Errorf("pcagenkit: no PCActn for unmapped tool %q (the mapping declined)", name)
		}
		if spec.OnProof != nil {
			spec.OnProof(call, args)
		}
		out, err := fn(tc, in)
		if err != nil {
			return zero, err
		}
		if rerr := pca.AdapterRecordToolResult(agent.Provenance, name, out); rerr != nil {
			return zero, rerr
		}
		return out, nil
	}, nil
}

// RecordInput records the principal's input (a string, {"input"} or {"messages"}) before generating.
func RecordInput(agent *pca.FacadeAgent, input any) error {
	if agent == nil {
		return errors.New("pcagenkit: agent is required")
	}
	return pca.AdapterRecordInput(agent.Provenance, input)
}
