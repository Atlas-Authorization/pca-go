package pca

import (
	"math"
	"strings"
	"testing"
)

type goATaintPanicGraph struct{}

func (goATaintPanicGraph) Node(string) bool { panic("graph fault") }

func TestGoATaintGate(t *testing.T) {
	reg := MapTrustedInputRegistry{"t": "trusted", "w": "web", "o": "tool", "a": "agent", "f": "first_party"}
	prov := func(refs ...any) any { return map[string]any{"trusted_refs": refs} }
	cases := []struct {
		name string
		g    TaintGate
		p    any
		why  string
	}{
		{"tool is 0.5", TaintGate{Registry: reg, MaxTaint: 0.25}, prov("o"), "information-flow taint 0.5 exceeds policy max 0.25"},
		{"tool within 0.5", TaintGate{Registry: reg, MaxTaint: 0.5}, prov("o"), ""},
		{"web is 0.75", TaintGate{Registry: reg, MaxTaint: 0.5}, prov("w"), "information-flow taint 0.75 exceeds policy max 0.5"},
		{"web within 0.75", TaintGate{Registry: reg, MaxTaint: 0.75}, prov("w"), ""},
		{"agent is 1", TaintGate{Registry: reg, MaxTaint: 0.9}, prov("a"), "information-flow taint 1 exceeds policy max 0.9"},
		{"agent within 1", TaintGate{Registry: reg, MaxTaint: 1}, prov("a"), ""},
		{"worst ref wins whatever the order", TaintGate{Registry: reg, MaxTaint: 0.5}, prov("w", "t", "f"), "information-flow taint 0.75 exceeds policy max 0.5"},
		{"first ref lower", TaintGate{Registry: reg, MaxTaint: 0.25}, prov("t", "w"), "information-flow taint 0.75 exceeds policy max 0.25"},
		{"missing key is worst", TaintGate{Registry: reg, MaxTaint: 0.9}, map[string]any{}, "information-flow taint 1 exceeds policy max 0.9"},
		{"nan bound", TaintGate{Registry: reg, MaxTaint: math.NaN()}, prov("t"), "taint gate misconfigured: maxTaint must be a non-negative number (fail closed)"},
		{"+inf bound", TaintGate{Registry: reg, MaxTaint: math.Inf(1)}, prov("t"), "taint gate misconfigured: maxTaint must be a non-negative number (fail closed)"},
		{"-inf bound", TaintGate{Registry: reg, MaxTaint: math.Inf(-1)}, prov("t"), "taint gate misconfigured: maxTaint must be a non-negative number (fail closed)"},
		{"small negative bound", TaintGate{Registry: reg, MaxTaint: -0.5}, prov("t"), "taint gate misconfigured: maxTaint must be a non-negative number (fail closed)"},
		{"zero bound is fine", TaintGate{Registry: reg, MaxTaint: 0}, prov("t"), ""},
		{"graph node first_party over 0", TaintGate{Registry: reg, Graph: taintNodeSet{"n": true}, MaxTaint: 0}, prov("n"), "information-flow taint 0.25 exceeds policy max 0"},
		{"graph non-node is worst", TaintGate{Registry: reg, Graph: taintNodeSet{"n": true}, MaxTaint: 0.9}, prov("zz"), "information-flow taint 1 exceeds policy max 0.9"},
		{"graph fault is worst", TaintGate{Registry: reg, Graph: goATaintPanicGraph{}, MaxTaint: 0.9}, prov("zz"), "information-flow taint 1 exceeds policy max 0.9"},
	}
	for _, c := range cases {
		g := c.g
		if why := taintGateReason(&g, c.p); why != c.why {
			t.Errorf("%s: got %q want %q", c.name, why, c.why)
		}
	}
}

func TestGoATaintGateInternalFaultFailsClosed(t *testing.T) {
	why := taintGateReason(nil, map[string]any{"trusted_refs": []any{"t"}})
	if !strings.HasPrefix(why, "taint gate error (fail closed): ") || len(why) <= len("taint gate error (fail closed): ") {
		t.Fatalf("got %q", why)
	}
}
