package pca

// Replays the data-flow reference corpus: the capability-tagged flow model, the trace rules (parse / compile / lethal-trifecta lint)
// and the detector adapters. A tagged value crosses as {"$t": value, "cap": {...}}; {"$raw": v} is an UNtagged value; a null
// argument item is an omitted optional argument and {"$hole": true} an argument nobody tagged. The detector gateway key is
// re-derived from the seed label (the committed corpus carries no key material).

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strconv"
	"testing"
)

func dfMalformed() error { return errors.New("malformed spec") }

func dfCap(spec any) (Capability, error) {
	m, ok := spec.(map[string]any)
	if !ok {
		return Capability{}, errors.New("tag: a capability needs a set of sources and a boolean isTrusted")
	}
	src, ok := m["sources"].([]any)
	trusted, ok2 := m["isTrusted"].(bool)
	if !ok || !ok2 {
		return Capability{}, errors.New("tag: a capability needs a set of sources and a boolean isTrusted")
	}
	sources := []string{}
	for _, s := range src {
		str, ok := s.(string)
		if !ok {
			return Capability{}, dfMalformed()
		}
		sources = append(sources, str)
	}
	var readers []string
	if r, has := m["readers"]; has {
		l, ok := r.([]any)
		if !ok {
			return Capability{}, errors.New("tag: readers must be a Set when given")
		}
		readers = []string{}
		for _, s := range l {
			str, ok := s.(string)
			if !ok {
				return Capability{}, dfMalformed()
			}
			readers = append(readers, str)
		}
	}
	return NewCapability(sources, trusted, readers), nil
}

// dfVal builds a value from a spec: {$raw} -> an untagged value, {$t, cap} -> Tag, anything else is a malformed spec.
func dfVal(spec any) (*Tagged, error) {
	m, ok := spec.(map[string]any)
	if !ok {
		return nil, dfMalformed()
	}
	if raw, has := m["$raw"]; has {
		return &Tagged{value: raw}, nil
	}
	if _, has := m["$t"]; has {
		c, err := dfCap(m["cap"])
		if err != nil {
			return nil, err
		}
		return Tag(m["$t"], c)
	}
	return nil, dfMalformed()
}

func dfSink(spec any) *Sink {
	m, ok := spec.(map[string]any)
	if !ok {
		return nil
	}
	s := &Sink{}
	s.ID, _ = m["id"].(string)
	if a, ok := m["accepts"].(map[string]any); ok {
		p := &FlowPolicy{}
		p.External, _ = a["external"].(bool)
		p.RequireTrusted, _ = a["requireTrusted"].(bool)
		p.AllowedSources = vecStrs(a, "allowedSources")
		p.DeniedSources = vecStrs(a, "deniedSources")
		s.Accepts = p
	}
	return s
}

type dfGovernor struct {
	sink   *Sink
	throws bool
}

func (g dfGovernor) SinkFor(PcaStyleAction) (*Sink, error) {
	if g.throws {
		return nil, errors.New("governor failed")
	}
	return g.sink, nil
}

func dfTraceSel(v any) (TraceSelector, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return TraceSelector{}, dfMalformed()
	}
	any_, _ := m["any"].(bool)
	return TraceSelector{Tools: nonNilStrs(vecStrs(m, "tools")), Traits: nonNilStrs(vecStrs(m, "traits")), Resources: nonNilStrs(vecStrs(m, "resources")), Any: any_}, nil
}

// dfRules converts the reference's rule list; shapes the reference refuses by a runtime TypeError are plain errors, an absent
// within_ms is the coded window refusal (an absent id reads as the string "undefined" in the reference).
func dfRules(v any) ([]TraceRule, error) {
	if s, ok := v.(string); ok && s != "" {
		return nil, &CodedError{Code: "window", Msg: "within_ms must be 1..30 days"}
	}
	l, ok := v.([]any)
	if !ok {
		return nil, errors.New("rules is not iterable")
	}
	out := make([]TraceRule, 0, len(l))
	for _, x := range l {
		switch m := x.(type) {
		case nil:
			return nil, errors.New("null rule")
		case map[string]any:
			id := "undefined"
			if s, has := m["id"]; has {
				str, ok := s.(string)
				if !ok {
					return nil, dfMalformed()
				}
				id = str
			}
			n, isNum := m["within_ms"].(json.Number)
			w, err := strconv.ParseInt(string(n), 10, 64)
			if !isNum || err != nil {
				return nil, &CodedError{Code: "window", Msg: "within_ms must be 1..30 days"}
			}
			nv, err := dfTraceSel(m["never"])
			if err != nil {
				return nil, err
			}
			af, err := dfTraceSel(m["after"])
			if err != nil {
				return nil, err
			}
			r := TraceRule{ID: id, Never: nv, After: af, WithinMs: w}
			if s, ok := m["reason"].(string); ok {
				r.Reason = &s
			}
			out = append(out, r)
		default:
			return nil, &CodedError{Code: "window", Msg: "within_ms must be 1..30 days"}
		}
	}
	return out, nil
}

func dfTable(v any) VerbTable {
	t := VerbTable{}
	m, _ := v.(map[string]any)
	for k, d := range m {
		dm, _ := d.(map[string]any)
		def := VerbDef{Traits: nonNilStrs(vecStrs(dm, "traits"))}
		if e := vecStrs(dm, "effects"); e != nil {
			def.Effects = e
		}
		t[k] = def
	}
	return t
}

func dfCtx(a any, seedLabel string) (DetectorAdapterContext, error) {
	m, ok := a.(map[string]any)
	if !ok {
		return DetectorAdapterContext{}, dfMalformed()
	}
	var c DetectorAdapterContext
	c.Detector, _ = m["detector"].(string)
	c.Version, _ = m["version"].(string)
	c.Content = m["content"]
	if sk, ok := m["secretKey"].(map[string]any); ok {
		if sm, isMap := sk["$bytes"].(map[string]any); isMap { // {"$bytes": {"$seed": label}}
			sk = sm
		}
		if label, _ := sk["$seed"].(string); label != "" {
			h := sha256.Sum256([]byte("atlas-pca-conformance/" + label))
			k, err := KeyPairFromSeed(h[:])
			if err != nil {
				return c, err
			}
			c.Key = k
		}
	}
	if c.Key == nil {
		return c, errors.New("no gateway key")
	}
	n, isNum := m["now"].(json.Number)
	if !isNum || n == "-0" {
		return c, errors.New("iat must be a non-negative integer")
	}
	now, err := strconv.ParseInt(string(n), 10, 64)
	if err != nil {
		return c, errors.New("iat must be a non-negative integer")
	}
	c.Now = now
	for _, f := range []struct {
		k string
		p **string
	}{{"session", &c.Session}, {"calibration_ref", &c.CalibrationRef}} {
		if v, has := m[f.k]; has {
			s, ok := v.(string)
			if !ok {
				return c, errors.New(f.k + " must be a string")
			}
			*f.p = &s
		}
	}
	return c, nil
}

func TestDataflowVectors(t *testing.T) {
	flow := func(args []any) (*Tagged, *Sink, error) {
		v, err := dfVal(vecArg(args, 0))
		return v, dfSink(vecArg(args, 1)), err
	}
	capsOf := func(a any) ([]Capability, error) {
		l, ok := a.([]any)
		if !ok {
			return nil, dfMalformed()
		}
		out := make([]Capability, 0, len(l))
		for _, x := range l {
			c, err := dfCap(x)
			if err != nil {
				return nil, err
			}
			out = append(out, c)
		}
		return out, nil
	}
	readersOf := func(o any) []string { return vecStrs(vecObj(o), "readers") }
	checkAction := func(args []any) (any, error) {
		am := vecObj(vecArg(args, 0))
		action := PcaStyleAction{Verb: vecStr(am, "verb"), Resource: vecStr(am, "resource")}
		items, _ := vecArg(args, 1).([]any)
		list := make([]*Tagged, len(items))
		for i, it := range items {
			if it == nil {
				list[i] = AbsentArg
			} else if m := vecObj(it); m != nil && m["$hole"] == true {
				list[i] = nil
			} else {
				v, err := dfVal(it)
				if err != nil {
					return nil, err
				}
				list[i] = v
			}
		}
		g := vecObj(vecArg(args, 2))
		gov := dfGovernor{sink: dfSink(g["sink"])}
		gov.throws, _ = g["throws"].(bool)
		var expected *int
		if e, has := vecObj(vecArg(args, 3))["expectedArgs"]; has {
			f, ok := jsNum(e)
			if !ok || f != float64(int(f)) || f > 1e15 || f < -1e15 {
				return nil, vecSkip("expectedArgs outside the integer range")
			}
			n := int(f)
			expected = &n
		}
		return CheckAction(action, list, gov, expected), nil
	}
	dual := func(args []any) (any, error) {
		spec := vecObj(vecArg(args, 0))
		q, err := dfVal(spec["query"])
		if err != nil {
			return nil, err
		}
		plan := func(p any) (any, error) {
			switch spec["plan"] {
			case "identity":
				return p, nil
			case "wrap":
				return map[string]any{"planned": p}, nil
			}
			return nil, errors.New("planner failed")
		}
		quarantine := func(p any) (*Tagged, error) {
			switch spec["quarantine"] {
			case "tagged_untrusted":
				return FromToolOutput("quarantine", p, nil), nil
			case "trusted":
				return FromTrustedQuery(p, nil), nil
			case "raw":
				return &Tagged{value: p}, nil
			}
			return nil, errors.New("q failed")
		}
		p, r, err := DualContext(q, plan, quarantine)
		if err != nil {
			return nil, err
		}
		return map[string]any{"plan": p, "result": r}, nil
	}
	receipt := func(f func(any, DetectorAdapterContext) (map[string]any, error)) vecFn {
		return func(args []any) (any, error) {
			c, err := dfCtx(vecArg(args, 1), "")
			if err != nil {
				return nil, err
			}
			return f(vecArg(args, 0), c)
		}
	}
	replayVectors(t, "ref-dataflow.json.gz", map[string]vecFn{
		"classifyFlow": func(args []any) (any, error) {
			v, s, err := flow(args)
			if err != nil {
				return nil, err
			}
			return ClassifyFlow(v, s), nil
		},
		"canFlow": func(args []any) (any, error) {
			v, s, err := flow(args)
			if err != nil {
				return nil, err
			}
			return CanFlow(v, s), nil
		},
		"tag": func(args []any) (any, error) {
			c, err := dfCap(vecArg(args, 1))
			if err != nil {
				return nil, err
			}
			return Tag(vecArg(args, 0), c)
		},
		"fromTrustedQuery": func(args []any) (any, error) {
			return FromTrustedQuery(vecArg(args, 0), readersOf(vecArg(args, 1))), nil
		},
		"fromToolOutput": func(args []any) (any, error) {
			name, _ := vecArg(args, 0).(string)
			return FromToolOutput(name, vecArg(args, 1), readersOf(vecArg(args, 2))), nil
		},
		"fromSource": func(args []any) (any, error) {
			src, _ := vecArg(args, 0).(string)
			o := vecObj(vecArg(args, 2))
			trusted, _ := o["isTrusted"].(bool)
			return FromSource(src, vecArg(args, 1), trusted, vecStrs(o, "readers"))
		},
		"unionSources": func(args []any) (any, error) {
			cs, err := capsOf(vecArg(args, 0))
			if err != nil {
				return nil, err
			}
			return nonNilStrs(UnionSources(cs)), nil
		},
		"combineCaps": func(args []any) (any, error) {
			cs, err := capsOf(vecArg(args, 0))
			if err != nil {
				return nil, err
			}
			return CombineCaps(cs), nil
		},
		"derive": func(args []any) (any, error) {
			items, _ := vecArg(args, 0).([]any)
			ins := make([]*Tagged, len(items))
			for i, it := range items {
				v, err := dfVal(it)
				if err != nil {
					return nil, err
				}
				ins[i] = v
			}
			name, _ := vecArg(args, 1).(string)
			return Derive(ins, func(vals ...any) (any, error) {
				switch name {
				case "count":
					return len(vals), nil
				case "pair":
					return vals, nil
				case "first":
					if len(vals) == 0 {
						return nil, vecSkip("first of no inputs is undefined")
					}
					return vals[0], nil
				}
				return nil, errors.New("combiner failed")
			})
		},
		"checkAction": checkAction,
		"dualContext": dual,
		"externalSendSink": func(args []any) (any, error) {
			s, _ := vecArg(args, 0).(string)
			return ExternalSendSink(s), nil
		},
		"sensitiveSink": func(args []any) (any, error) {
			s, _ := vecArg(args, 0).(string)
			return SensitiveSink(s), nil
		},
		"levelOf": func(args []any) (any, error) {
			v, err := dfVal(vecArg(args, 0))
			if err != nil {
				return nil, err
			}
			return LevelOf(v), nil
		},
		"consts": func([]any) (any, error) {
			return map[string]any{"TRUSTED_QUERY": TrustedQuery, "tool": ToolProvenance("x"), "tool2": ToolProvenance("")}, nil
		},
		"parseTraceRule": func(args []any) (any, error) {
			id, _ := vecArg(args, 0).(string)
			text, ok := vecArg(args, 1).(string)
			if !ok {
				return nil, vecSkip("non-string rule text")
			}
			var reason *string
			if len(args) > 2 {
				r, ok := args[2].(string)
				if !ok {
					return nil, vecSkip("a null reason is kept as null by the reference; Go has no null reason")
				}
				reason = &r
			}
			return ParseTraceRule(id, text, reason)
		},
		"parseInvariantRule": func(args []any) (any, error) {
			id, _ := vecArg(args, 0).(string)
			text, _ := vecArg(args, 1).(string)
			o := vecObj(vecArg(args, 2))
			h, _ := o["horizon"].(string)
			return ParseInvariantRule(id, text, InvariantOptions{Horizon: h, DropUnsupported: o["dropUnsupported"] == true})
		},
		"compileTraceRules": func(args []any) (any, error) {
			rules, err := dfRules(vecArg(args, 0))
			if err != nil {
				return nil, err
			}
			return CompileTraceRules(rules, dfTable(vecArg(args, 1)))
		},
		"lethalTrifecta": func(args []any) (any, error) {
			var edges []TraceEdge
			b, err := json.Marshal(vecArg(args, 1))
			if err == nil {
				err = json.Unmarshal(b, &edges)
			}
			if err != nil {
				return nil, err
			}
			if len(args) > 2 && args[2] == nil { // opts.untrusted on null throws
				return nil, errors.New("Cannot read properties of null (reading 'untrusted')")
			}
			o := vecObj(vecArg(args, 2))
			return LethalTrifecta(dfTable(vecArg(args, 0)), edges, TrifectaOptions{Untrusted: vecStrs(o, "untrusted"), UntrustedTraits: vecStrs(o, "untrusted_traits")}), nil
		},
		"traceConsts": func([]any) (any, error) {
			return map[string]any{"MAX_TRACE_CAVEATS": jsNumber(MaxTraceCaveats), "PRIVATE_READ_TRAITS": PrivateReadTraits, "EXTERNAL_SEND_TRAITS": ExternalSendTraits}, nil
		},
		"categoryId":            func(args []any) (any, error) { return DetectorCategoryID(vecArg(args, 0)), nil },
		"lakeraReceipt":         receipt(LakeraReceipt),
		"promptSecurityReceipt": receipt(PromptSecurityReceipt),
		"genericReceipt":        receipt(GenericReceipt),
	})
}
