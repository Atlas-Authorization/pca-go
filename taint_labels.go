package pca

import (
	"errors"
	"fmt"
	"math"
)

// The labelled side of L4 taint: the trust lattice trusted < first_party < tool < web < agent as values, the trusted-input registry,
// per-ref classification and ComputeTaint with its per-ref audit list (the gate in taint.go keeps only the rank). A label is its
// decoded JSON object ({kind, id?}); the agent's own label is never read: every declared ref is re-classified from facts the SERVER
// holds, and what it cannot vouch for is `agent`, the worst case. Pure and deterministic; ComputeTaint never fails with an error.

// TaintLevels are the five levels, least trusted last.
var TaintLevels = []string{"trusted", "first_party", "tool", "web", "agent"}

// TaintBottom is the most trusted label (the identity of the join); TaintTop the least trusted (the fail-closed worst case).
func TaintBottom() map[string]any { return map[string]any{"kind": "trusted"} }
func TaintTop() map[string]any    { return map[string]any{"kind": "agent"} }

// IsTaintLevel is true only for the five level names (an own-name test: "constructor", "__proto__" and "toString" are no levels).
func IsTaintLevel(kind any) bool { return isTaintLevel(kind) }

// TaintLabelRank is the rank of a label (trusted 0 .. agent 4); an unknown, missing or non-string kind, and a label that is no
// object, are the worst rank.
func TaintLabelRank(l any) int {
	if m, ok := l.(map[string]any); ok {
		if k, isStr := m["kind"].(string); isStr {
			if r, known := taintRanks[k]; known {
				return r
			}
		}
	}
	return taintMaxRank
}

// TaintValueOf is the normalized taint of a label in [0, 1]: trusted 0, first_party 0.25, tool 0.5, web 0.75, agent 1.
func TaintValueOf(l any) float64 { return float64(TaintLabelRank(l)) / taintMaxRank }

// JoinTaintLabel is the least upper bound of two labels: the higher rank wins and keeps its label as it is; at equal rank the id
// is kept only when both agree, else the label is the bare kind. A null label at equal rank is an error.
func JoinTaintLabel(a, b any) (any, error) {
	ra, rb := TaintLabelRank(a), TaintLabelRank(b)
	if ra > rb {
		return a, nil
	}
	if rb > ra {
		return b, nil
	}
	if a == nil || b == nil {
		return nil, errors.New("Cannot convert undefined or null to object")
	}
	am, _ := a.(map[string]any)
	bm, _ := b.(map[string]any)
	ia, hasA := am["id"]
	ib, hasB := bm["id"]
	if (!hasA && !hasB) || (hasA && hasB && jsStrictEq(ia, ib)) {
		return a, nil
	}
	out := map[string]any{}
	if k, has := am["kind"]; has {
		out["kind"] = k
	}
	return out, nil
}

// JoinTaintLabels joins a list of labels. The EMPTY lineage joins to the top label: "no verifiable trusted input" is not "trusted".
// A value that is not a list is an error.
func JoinTaintLabels(labels any) (any, error) {
	l, ok := labels.([]any)
	if !ok {
		return nil, errors.New("labels.reduce is not a function")
	}
	if len(l) == 0 {
		return TaintTop(), nil
	}
	acc := l[0]
	for _, x := range l[1:] {
		var err error
		if acc, err = JoinTaintLabel(acc, x); err != nil {
			return nil, err
		}
	}
	return acc, nil
}

// TaintLabelRegistry is the server's registry of what it vouches for, by content digest: the label (any value; only an object whose
// kind is a level counts) or nil when it vouches for none. An error is a registry fault.
type TaintLabelRegistry interface {
	LookupLabel(digest string) (any, error)
}

// InMemoryTrustedInputRegistry is the in-memory registry. Only the server records into it; nothing an agent sends reaches it.
type InMemoryTrustedInputRegistry struct{ m map[string]map[string]any }

// NewInMemoryTrustedInputRegistry returns an empty registry.
func NewInMemoryTrustedInputRegistry() *InMemoryTrustedInputRegistry {
	return &InMemoryTrustedInputRegistry{m: map[string]map[string]any{}}
}

func taintCopy(l map[string]any) map[string]any {
	out := make(map[string]any, len(l))
	for k, v := range l {
		out[k] = v
	}
	return out
}

// Record records that digest is an input the server verified at label. An empty digest, and a label that is no object with a level
// kind, are ignored; the registry keeps a copy.
func (r *InMemoryTrustedInputRegistry) Record(digest string, label any) *InMemoryTrustedInputRegistry {
	if m, ok := label.(map[string]any); ok && digest != "" && isTaintLevel(m["kind"]) {
		r.m[digest] = taintCopy(m)
	}
	return r
}

// RecordTrusted records a verified principal utterance or fully trusted first-party input (the bottom of the lattice).
func (r *InMemoryTrustedInputRegistry) RecordTrusted(digest string) *InMemoryTrustedInputRegistry {
	return r.Record(digest, map[string]any{"kind": "trusted"})
}

// RecordFirstParty records a server-owned first-party resource.
func (r *InMemoryTrustedInputRegistry) RecordFirstParty(digest string) *InMemoryTrustedInputRegistry {
	return r.Record(digest, map[string]any{"kind": "first_party"})
}

// RecordTool records the attested output of a known tool.
func (r *InMemoryTrustedInputRegistry) RecordTool(digest, id string) *InMemoryTrustedInputRegistry {
	return r.Record(digest, map[string]any{"kind": "tool", "id": id})
}

// RecordWeb records content the server itself fetched from the open web.
func (r *InMemoryTrustedInputRegistry) RecordWeb(digest string) *InMemoryTrustedInputRegistry {
	return r.Record(digest, map[string]any{"kind": "web"})
}

// LookupLabel implements TaintLabelRegistry (a copy of the recorded label, nil when none).
func (r *InMemoryTrustedInputRegistry) LookupLabel(digest string) (any, error) {
	if l, ok := r.m[digest]; ok {
		return taintCopy(l), nil
	}
	return nil, nil
}

// Size is the number of digests recorded.
func (r *InMemoryTrustedInputRegistry) Size() int { return len(r.m) }

// Lookup implements TrustedInputRegistry (the taint gate): the level name of the recorded label, "" when none.
func (r *InMemoryTrustedInputRegistry) Lookup(digest string) string {
	k, _ := r.m[digest]["kind"].(string)
	return k
}

type emptyTaintRegistry struct{}

func (emptyTaintRegistry) LookupLabel(string) (any, error) { return nil, nil }

// EmptyTaintRegistry vouches for nothing: every ref falls through to the resource graph, then the worst case.
var EmptyTaintRegistry TaintLabelRegistry = emptyTaintRegistry{}

// TaintContext is what classification reads: the digests the server verified, and (optionally) its committed resource graph (only
// Node is called; a graph that panics is treated as having no such node).
type TaintContext struct {
	Registry TaintLabelRegistry
	Graph    ResourceGraph
}

// ClassifyTaintRef classifies ONE declared provenance ref independently: the registered label when the server vouches for it, else
// first_party when it names a resource-graph node, else `agent` (carrying the ref as id when it is at most 128 UTF-16 units). A
// non-string or empty ref is `agent`. A registry fault (or no registry for a real ref) is an error.
func ClassifyTaintRef(ref any, ctx TaintContext) (map[string]any, error) {
	s, ok := ref.(string)
	if !ok || s == "" {
		return TaintTop(), nil
	}
	if ctx.Registry == nil {
		return nil, errors.New("Cannot read properties of undefined (reading 'lookup')")
	}
	vouched, err := ctx.Registry.LookupLabel(s)
	if err != nil {
		return nil, err
	}
	if m, isObj := vouched.(map[string]any); isObj && isTaintLevel(m["kind"]) {
		return m, nil
	}
	if ctx.Graph != nil && taintGraphHas(ctx.Graph, s) {
		return map[string]any{"kind": "first_party"}, nil
	}
	out := map[string]any{"kind": "agent"}
	if len(utf16Units(s)) <= 128 {
		out["id"] = s
	}
	return out, nil
}

func taintGraphHas(g ResourceGraph, ref string) (has bool) {
	defer func() {
		if recover() != nil {
			has = false
		}
	}()
	return g.Node(ref)
}

// TaintResult is the outcome of ComputeTaint: the normalized taint of the join in [0, 1] (exactly 1 when fail-closed), the join
// label, the per-ref classification and whether the provenance was usable (Valid false: Reason says why and taint is 1).
type TaintResult struct {
	Taint  float64
	Label  map[string]any
	Refs   []map[string]any // {ref, label}
	Valid  bool
	Reason string
}

// JSON is the reference's result object.
func (r TaintResult) JSON() map[string]any {
	refs := make([]any, len(r.Refs))
	for i, x := range r.Refs {
		refs[i] = x
	}
	out := map[string]any{"taint": jsNumber(r.Taint), "label": r.Label, "refs": refs, "valid": r.Valid}
	if r.Reason != "" {
		out["reason"] = r.Reason
	}
	return out
}

func taintInvalid(reason string) TaintResult {
	return TaintResult{Taint: 1, Label: TaintTop(), Refs: []map[string]any{}, Reason: reason}
}

// ComputeTaint computes the information-flow taint of a PCActn's provenance: taintValue(join over the independently classified
// declared input refs). All-verified-trusted lineage is 0; anything unverifiable, web or agent is high; an empty lineage is 1.
// It fails closed (taint 1, Valid false) on a missing registry, absent or malformed provenance, a non-array `trusted_refs`, a
// non-string or empty ref and a registry fault. The agent's own `taint_level` and `causal_hash` are never read. It never panics.
func ComputeTaint(provenance any, ctx TaintContext) (res TaintResult) {
	defer func() {
		if r := recover(); r != nil {
			res = taintInvalid(fmt.Sprintf("taint: evaluation error (fail closed): %v", r))
		}
	}()
	if ctx.Registry == nil {
		return taintInvalid("taint: no trusted-input registry")
	}
	prov, ok := provenance.(map[string]any)
	if !ok {
		return taintInvalid("taint: provenance is absent or malformed")
	}
	var refs []string
	if raw, has := prov["trusted_refs"]; has {
		l, isList := raw.([]any)
		if !isList {
			return taintInvalid("taint: trusted_refs must be an array")
		}
		for _, x := range l {
			s, isStr := x.(string)
			if !isStr || s == "" {
				return taintInvalid("taint: trusted_refs must be non-empty strings")
			}
			refs = append(refs, s)
		}
	}
	rows := make([]map[string]any, 0, len(refs))
	labels := make([]any, 0, len(refs))
	for _, ref := range refs {
		l, err := ClassifyTaintRef(ref, ctx)
		if err != nil {
			return taintInvalid("taint: evaluation error (fail closed): " + err.Error())
		}
		rows = append(rows, map[string]any{"ref": ref, "label": l})
		labels = append(labels, l)
	}
	joined, err := JoinTaintLabels(labels)
	if err != nil {
		return taintInvalid("taint: evaluation error (fail closed): " + err.Error())
	}
	label, _ := joined.(map[string]any)
	return TaintResult{Taint: math.Min(1, TaintValueOf(label)), Label: label, Refs: rows, Valid: true}
}
