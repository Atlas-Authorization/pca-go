package pca

import "testing"

type taintNodeSet map[string]bool

func (n taintNodeSet) Node(r string) bool { return n[r] }

type panicReg struct{}

func (panicReg) Lookup(string) string { panic("boom") }

func TestF3_TaintGate(t *testing.T) {
	reg := MapTrustedInputRegistry{"t": "trusted", "f": "first_party", "w": "web", "x": "bogus"}
	prov := func(refs ...any) any { return map[string]any{"trusted_refs": refs} }
	cases := []struct {
		name string
		g    TaintGate
		p    any
		ok   bool
		why  string
	}{
		{"trusted passes 0", TaintGate{Registry: reg, MaxTaint: 0}, prov("t"), true, ""},
		{"first_party over 0", TaintGate{Registry: reg, MaxTaint: 0}, prov("t", "f"), false, "information-flow taint 0.25 exceeds policy max 0"},
		{"first_party within .25", TaintGate{Registry: reg, MaxTaint: 0.25}, prov("t", "f"), true, ""},
		{"web over .5", TaintGate{Registry: reg, MaxTaint: 0.5}, prov("f", "w"), false, "information-flow taint 0.75 exceeds policy max 0.5"},
		{"unknown ref is agent", TaintGate{Registry: reg, MaxTaint: 0.75}, prov("nope"), false, "information-flow taint 1 exceeds policy max 0.75"},
		{"bogus level is unvouched", TaintGate{Registry: reg, MaxTaint: 0.9}, prov("x"), false, "information-flow taint 1 exceeds policy max 0.9"},
		{"graph node is first_party", TaintGate{Registry: reg, Graph: taintNodeSet{"n": true}, MaxTaint: 0.25}, prov("n"), true, ""},
		{"empty lineage is worst", TaintGate{Registry: reg, MaxTaint: 0.9}, prov(), false, "information-flow taint 1 exceeds policy max 0.9"},
		{"empty lineage at 1", TaintGate{Registry: reg, MaxTaint: 1}, prov(), true, ""},
		{"negative bound", TaintGate{Registry: reg, MaxTaint: -1}, prov("t"), false, "taint gate misconfigured: maxTaint must be a non-negative number (fail closed)"},
		{"no registry", TaintGate{MaxTaint: 1}, prov("t"), false, "taint: no trusted-input registry"},
		{"absent provenance", TaintGate{Registry: reg, MaxTaint: 1}, nil, false, "taint: provenance is absent or malformed"},
		{"refs not array", TaintGate{Registry: reg, MaxTaint: 1}, map[string]any{"trusted_refs": "t"}, false, "taint: trusted_refs must be an array"},
		{"empty string ref", TaintGate{Registry: reg, MaxTaint: 1}, prov(""), false, "taint: trusted_refs must be non-empty strings"},
		{"non-string ref", TaintGate{Registry: reg, MaxTaint: 1}, prov(3.0), false, "taint: trusted_refs must be non-empty strings"},
		{"registry panic is worst", TaintGate{Registry: panicReg{}, MaxTaint: 0.9}, prov("t"), false, "information-flow taint 1 exceeds policy max 0.9"},
	}
	for _, c := range cases {
		g := c.g
		why := taintGateReason(&g, c.p)
		if (why == "") != c.ok || why != c.why {
			t.Errorf("%s: got %q want ok=%v %q", c.name, why, c.ok, c.why)
		}
	}
}
