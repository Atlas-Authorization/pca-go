package pca

import (
	"errors"
	"testing"
)

// Replay of the labelled taint module against the reference (ref-taint), every case: the lattice functions, the registry, ref
// classification and ComputeTaint over registries that record, always throw or answer a fixed value, and resource graphs that
// list nodes or throw. A reference throw requires a refusal.

type taintFixedRegistry struct{ v any }

func (r taintFixedRegistry) LookupLabel(string) (any, error) { return r.v, nil }

type taintThrowingRegistry struct{}

func (taintThrowingRegistry) LookupLabel(string) (any, error) {
	return nil, errors.New("registry boom")
}

type taintSpecGraph struct {
	nodes  map[string]bool
	throws bool
}

func (g taintSpecGraph) Node(ref string) bool {
	if g.throws {
		panic("graph boom")
	}
	return g.nodes[ref]
}

// taintCtx builds a context from the corpus spec: {registry: RS, graph?: GS} (registry null = none).
func taintCtx(v any) TaintContext {
	spec, _ := v.(map[string]any)
	var ctx TaintContext
	if rs, ok := spec["registry"].(map[string]any); ok {
		switch rs["mode"] {
		case "throws":
			ctx.Registry = taintThrowingRegistry{}
		case "fixed":
			ctx.Registry = taintFixedRegistry{rs["fixed"]}
		default:
			r := NewInMemoryTrustedInputRegistry()
			for _, rec := range rsList(rs["records"]) {
				pair := rsList(rec)
				if d, ok := vecArg(pair, 0).(string); ok {
					r.Record(d, vecArg(pair, 1))
				}
			}
			ctx.Registry = r
		}
	}
	if gs, ok := spec["graph"].(map[string]any); ok {
		g := taintSpecGraph{nodes: map[string]bool{}, throws: gs["throws"] == true}
		for _, n := range rsList(gs["nodes"]) {
			s, _ := n.(string)
			g.nodes[s] = true
		}
		ctx.Graph = g
	}
	return ctx
}

func TestTaintMatchesTheReference(t *testing.T) {
	fns := map[string]vecFn{
		"constants": func([]any) (any, error) {
			return map[string]any{"TAINT_LEVELS": rsStringsOut(TaintLevels), "BOTTOM": TaintBottom(), "TOP": TaintTop()}, nil
		},
		"isTaintLevel": func(a []any) (any, error) { return IsTaintLevel(vecArg(a, 0)), nil },
		"labelRank":    func(a []any) (any, error) { return jsNumber(float64(TaintLabelRank(vecArg(a, 0)))), nil },
		"taintValue":   func(a []any) (any, error) { return jsNumber(TaintValueOf(vecArg(a, 0))), nil },
		"joinLabel":    func(a []any) (any, error) { return JoinTaintLabel(vecArg(a, 0), vecArg(a, 1)) },
		"joinLabels":   func(a []any) (any, error) { return JoinTaintLabels(vecArg(a, 0)) },
		"registry": func(a []any) (any, error) {
			r := NewInMemoryTrustedInputRegistry()
			ops := rsList(vecArg(a, 0))
			out := make([]any, len(ops))
			for i, o := range ops {
				op := rsList(o)
				d, _ := vecArg(op, 1).(string) // a non-string digest records nothing and finds nothing
				switch name, _ := vecArg(op, 0).(string); name {
				case "record":
					if _, isStr := vecArg(op, 1).(string); isStr {
						r.Record(d, vecArg(op, 2))
					}
				case "recordTrusted":
					r.RecordTrusted(d)
				case "recordFirstParty":
					r.RecordFirstParty(d)
				case "recordTool":
					r.RecordTool(d, rsStr(vecArg(op, 2)))
				case "recordWeb":
					r.RecordWeb(d)
				case "lookup":
					out[i], _ = r.LookupLabel(d)
				case "size":
					out[i] = jsNumber(float64(r.Size()))
				case "emptyLookup":
					out[i], _ = EmptyTaintRegistry.LookupLabel(d)
				default:
					return nil, errors.New("unknown registry op " + name)
				}
			}
			return out, nil
		},
		"classifyRef": func(a []any) (any, error) { return ClassifyTaintRef(vecArg(a, 0), taintCtx(vecArg(a, 1))) },
		"computeTaint": func(a []any) (any, error) {
			return ComputeTaint(vecArg(a, 0), taintCtx(vecArg(a, 1))).JSON(), nil
		},
	}
	replayAll(t, "ref-taint.json.gz", 2344, fns, nil, nil)
}
