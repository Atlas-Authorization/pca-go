// Package pcalangchaingo wraps a langchaingo tool so every call first builds and signs a PCActn (handing the proof to your
// callback so it can forward it to the resource server), then runs the original tool and records its output for provenance.
// It authorizes nothing: the resource server's verifier decides; a bypassed wrapper just means the action lacks a valid PCActn
// and fails server-side. It lives in its own module so the core stays dependency-light.
package pcalangchaingo

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/tmc/langchaingo/schema"
	"github.com/tmc/langchaingo/tools"

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
	tools.Tool
	agent *pca.FacadeAgent
	spec  Spec
}

// WithPCA wraps tool: the returned tool keeps its name and description and builds a PCActn before every Call. The tool input is a
// JSON object (the model's arguments) or plain text, which becomes {"input": text}.
func WithPCA(agent *pca.FacadeAgent, spec Spec, tool tools.Tool) (tools.Tool, error) {
	if agent == nil || tool == nil || spec.Mapping == nil {
		return nil, errors.New("pcalangchaingo: agent, tool and a mapping are required")
	}
	return &guarded{Tool: tool, agent: agent, spec: spec}, nil
}

func (g *guarded) Call(ctx context.Context, input string) (string, error) {
	args := map[string]any{"input": input}
	if t := strings.TrimSpace(input); strings.HasPrefix(t, "{") {
		v, err := pca.ParseJSONLenient([]byte(t))
		if err != nil {
			return "", fmt.Errorf("pcalangchaingo: tool input is not valid JSON: %w", err)
		}
		args, _ = v.(map[string]any)
	}
	call, err := pca.AdapterBridgeToolCall(g.agent, g.Name(), args, g.spec.Mapping)
	if err != nil {
		return "", err
	}
	if call == nil {
		return "", fmt.Errorf("pcalangchaingo: no PCActn for unmapped tool %q (the mapping declined)", g.Name())
	}
	if g.spec.OnProof != nil {
		g.spec.OnProof(call, args)
	}
	out, err := g.Tool.Call(ctx, input)
	if err != nil {
		return "", err
	}
	if rerr := pca.AdapterRecordToolResult(g.agent.Provenance, g.Name(), out); rerr != nil { // the output re-enters the model's context
		return "", rerr
	}
	return out, nil
}

// RecordInput records the principal's input (a string, {"input"} or {"messages"}) before running a chain or agent.
func RecordInput(agent *pca.FacadeAgent, input any) error {
	if agent == nil {
		return errors.New("pcalangchaingo: agent is required")
	}
	return pca.AdapterRecordInput(agent.Provenance, input)
}

// metaAny normalises Go-typed metadata ([]string, []map[string]string ...) to the JSON shapes the policy reads.
func metaAny(v any) any {
	switch x := v.(type) {
	case []string:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = e
		}
		return out
	case []map[string]any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = e
		}
		return out
	case map[string]string:
		out := map[string]any{}
		for k, e := range x {
			out[k] = e
		}
		return out
	case []map[string]string:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = metaAny(e)
		}
		return out
	}
	return v
}

type filteredRetriever struct {
	inner  schema.Retriever
	filter *pca.RagFilteredRetriever
}

// WithPCAFilter wraps a langchaingo retriever so its documents are filtered to what the principal may see under the policy
// before they reach the model. ACLs come from each document's Metadata ("acl" and "tags"); the id from Metadata "id", then
// "source", else doc#i. Pass agent.Provenance (or nil) as recorder to record admitted documents as untrusted retrieval content.
func WithPCAFilter(inner schema.Retriever, principal, policy any, recorder *pca.ProvenanceRecorder) (*filteredRetriever, error) {
	if inner == nil {
		return nil, errors.New("pcalangchaingo: a retriever is required")
	}
	fr := &filteredRetriever{inner: inner}
	meta := func(doc any) map[string]any {
		d, _ := doc.(schema.Document)
		return d.Metadata
	}
	opts := &pca.RagFilterOptions{
		Recorder: recorder,
		GetID: func(doc any, _ int) (any, error) {
			for _, k := range []string{"id", "source"} {
				if s, ok := meta(doc)[k].(string); ok && s != "" {
					return s, nil
				}
			}
			return "", nil
		},
		GetAcls: func(doc any) (any, error) {
			m := meta(doc)
			return pca.RagAclsFromMetadata(metaAny(m["acl"]), metaAny(m["tags"])), nil
		},
	}
	f, err := pca.RagWithPcaFilter(func(string, int) ([]any, error) { return nil, nil }, principal, policy, opts)
	if err != nil {
		return nil, err
	}
	fr.filter = f
	return fr, nil
}

// GetRelevantDocuments implements schema.Retriever.
func (r *filteredRetriever) GetRelevantDocuments(ctx context.Context, query string) ([]schema.Document, error) {
	docs, err := r.inner.GetRelevantDocuments(ctx, query)
	if err != nil {
		return nil, err
	}
	cands := make([]any, len(docs))
	for i, d := range docs {
		cands[i] = d
	}
	out, err := r.filter.FilterCandidates(cands)
	if err != nil {
		return nil, err
	}
	res := make([]schema.Document, 0, len(out))
	for _, o := range out {
		res = append(res, o.(schema.Document))
	}
	return res, nil
}

// LastDecision is the proof trace of the most recent retrieval (nil before the first).
func (r *filteredRetriever) LastDecision() map[string]any { return r.filter.LastDecision() }
