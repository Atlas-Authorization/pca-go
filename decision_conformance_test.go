package pca

import (
	"reflect"
	"testing"
)

// Shared vectors for rules 20, 21 and the ternary decision: packages/pca/conformance/decision-vectors.json.
func decisionTable(t *testing.T, name string) []any {
	t.Helper()
	return load(t, "decision-vectors.json")["primitives"].(map[string]any)[name].([]any)
}

// vectorInput is the vector's input: `input_text` is raw JSON text each runner parses itself (key order is part of the input;
// ParseJSONLenient records it), else `input`.
func vectorInput(t *testing.T, v map[string]any) map[string]any {
	t.Helper()
	if txt, ok := v["input_text"].(string); ok {
		x, err := ParseJSONLenient([]byte(txt))
		if err != nil {
			t.Fatal(err)
		}
		return x.(map[string]any)
	}
	return v["input"].(map[string]any)
}

// Request reasons are cut at 512 UTF-16 units like String(r).slice(0, 512); a cut inside a surrogate pair keeps the lone high
// surrogate, which the wire text writes as \udXXXX.
func TestEscalationTruncateVectors(t *testing.T) {
	for _, x := range decisionTable(t, "escalation_truncate") {
		v := x.(map[string]any)
		t.Run(v["name"].(string), func(t *testing.T) {
			rs := []string{}
			for _, r := range v["input"].(map[string]any)["reasons"].([]any) {
				rs = append(rs, r.(string))
			}
			req, err := BuildEscalationRequest("a", map[string]any{"id": "g"}, map[string]any{"action": map[string]any{"verb": "v", "resource": "r"}}, nil, rs, 1, 0)
			if err != nil {
				t.Fatal(err)
			}
			if got, want := EscalationReasonsWire(req), v["expect"].(map[string]any)["wire"].(string); got != want {
				t.Fatalf("wire %q, want %q", got, want)
			}
		})
	}
}

func TestDecisionUnitsVectors(t *testing.T) {
	for _, x := range decisionTable(t, "intent_units") {
		v := x.(map[string]any)
		t.Run(v["name"].(string), func(t *testing.T) {
			ok, why := DecideUnits(vectorInput(t, v))
			e := v["expect"].(map[string]any)
			if want := e["ok"].(bool); ok != want {
				t.Fatalf("ok = %v (%s), want %v", ok, why, want)
			}
			if want, has := e["reason"]; has && why != want {
				t.Fatalf("reason %q, want %q", why, want)
			}
		})
	}
}

func TestDecisionTightenVectors(t *testing.T) {
	for _, x := range decisionTable(t, "intent_tighten") {
		v := x.(map[string]any)
		t.Run(v["name"].(string), func(t *testing.T) {
			r := DecideTighten(vectorInput(t, v))
			e := v["expect"].(map[string]any)
			if r.Outcome != e["outcome"] || r.Legacy != e["legacy"].(bool) {
				t.Fatalf("got %+v, want %v", r, e)
			}
			want := e["offending"].([]any)
			if len(r.Offending) != len(want) {
				t.Fatalf("offending %v, want %v", r.Offending, want)
			}
			for i := range want {
				if r.Offending[i] != want[i] {
					t.Fatalf("offending %v, want %v", r.Offending, want)
				}
			}
			// the reason is part of the contract, byte for byte (an ok outcome has none)
			wantReason, _ := e["reason"].(string)
			if r.Reason != wantReason {
				t.Fatalf("reason %q, want %q", r.Reason, wantReason)
			}
		})
	}
}

// The ordered reason list and the decision of a verdict whose intent-v2 pipeline reported several failing checks.
func TestEscalationFoldVectors(t *testing.T) {
	for _, x := range decisionTable(t, "escalation_fold") {
		v := x.(map[string]any)
		t.Run(v["name"].(string), func(t *testing.T) {
			in := v["input"].(map[string]any)
			base := []string{}
			for _, r := range in["core_reasons"].([]any) {
				base = append(base, r.(string))
			}
			var v2 []V2CheckResult
			for _, c := range in["v2"].([]any) {
				m := c.(map[string]any)
				r, has := m["reason"].(string)
				v2 = append(v2, V2CheckResult{Name: m["name"].(string), OK: m["ok"] == true, Reason: r, HasReason: has})
			}
			got := FoldV2Reasons(base, v2)
			want := []string{}
			for _, r := range v["expect"].(map[string]any)["reasons"].([]any) {
				want = append(want, r.(string))
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("reasons %q, want %q", got, want)
			}
			checks := in["checks"].(map[string]any)
			allow := true
			for _, st := range checks {
				if st == "fail" {
					allow = false
				}
			}
			rs := make([]any, len(got))
			for i, r := range got {
				rs[i] = r
			}
			if d := DecisionOf(map[string]any{"allow": allow, "checks": checks, "reasons": rs}); d != v["expect"].(map[string]any)["decision"] {
				t.Fatalf("decision %s, want %v", d, v["expect"].(map[string]any)["decision"])
			}
		})
	}
}

func TestDecisionOfVectors(t *testing.T) {
	for _, x := range decisionTable(t, "decision_of") {
		v := x.(map[string]any)
		t.Run(v["name"].(string), func(t *testing.T) {
			if got := DecisionOf(v["input"].(map[string]any)); got != v["expect"].(map[string]any)["decision"] {
				t.Fatalf("got %s", got)
			}
		})
	}
}

func TestDecisionLatticeVectors(t *testing.T) {
	for _, x := range decisionTable(t, "decision_lattice") {
		v := x.(map[string]any)
		n, in := v["name"].(string), v["input"].(map[string]any)
		t.Run(n, func(t *testing.T) {
			var got string
			switch n[:3] {
			case "mee":
				got = Meet(in["a"].(string), in["b"].(string))
			case "pep":
				got = PepDecision(in["decision"].(string), in["answered"] == true)
			default:
				got = TightenDecision(in["decision"].(string), in["signal"])
			}
			if got != v["expect"].(map[string]any)["decision"] {
				t.Fatalf("got %s", got)
			}
		})
	}
}
