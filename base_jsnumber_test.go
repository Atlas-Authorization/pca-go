package pca

import (
	"math"
	"strings"
	"testing"
)

// The sweep table (spec: ECMAScript StringToNumber, same as node -p 'Number(x)').
var jsNumberNaN = []string{
	"+-Infinity", "-+Infinity", "+0x1", "-0x1", "0x+1", "0x-1", "0x1_0", "0x 1", "0x", "0b2", "0o8", "1_000",
	"\u0661", "\uff11", "infinity", "INFINITY", "inf", "+Inf", "nan", "NaN", "1e", ".", "+", "1f", "1d", "1L",
	"0x1p4", "0x1p3", "1\x00", "\x00", "1\u0085", "\u0085", "1\u180e", "\u180e", "1 2", "0b", "0o", "0xg", "e1", "1e+", "--1",
}

func TestJsStringToNumberNaN(t *testing.T) {
	for _, s := range jsNumberNaN {
		if f := jsStringToNumber(s); !math.IsNaN(f) {
			t.Errorf("Number(%q) = %v, want NaN", s, f)
		}
		if f, ok := jsNumberFromString(s); ok || f != 0 {
			t.Errorf("jsNumberFromString(%q) = %v %v, want 0 false", s, f, ok)
		}
	}
}

func TestJsStringToNumberParses(t *testing.T) {
	inf := math.Inf(1)
	for _, c := range []struct {
		s string
		f float64
	}{
		{"", 0}, {" \t\n", 0}, {"\ufeff\u00a0", 0}, {" 12 ", 12}, {"\ufeff12\u00a0", 12}, {"Infinity", inf}, {"+Infinity", inf}, {"-Infinity", -inf},
		{"0x10", 16}, {"0X1f", 31}, {"0o7", 7}, {"0O17", 15}, {"0b1", 1}, {"0B101", 5}, {"1.", 1}, {".5", 0.5}, {"1e3", 1000}, {"+1.5", 1.5},
		{"1.e1", 10}, {".5E+1", 5}, {"010", 10}, {"0x" + strings.Repeat("f", 300), inf}, {"1e999", inf}, {"-1e999", -inf}, {"1e-999", 0},
		{"0x20000000000001", 9007199254740992}, {"0x20000000000003", 9007199254740996}, // 2^53+1, 2^53+3: nearest, ties to even
	} {
		if f := jsStringToNumber(c.s); f != c.f {
			t.Errorf("Number(%q) = %v, want %v", c.s, f, c.f)
		}
	}
	if f := jsStringToNumber("-0"); f != 0 || !math.Signbit(f) {
		t.Errorf("Number(\"-0\") = %v, want -0", f)
	}
	if f := jsStringToNumber("0"); f != 0 || math.Signbit(f) {
		t.Errorf("Number(\"0\") = %v, want +0", f)
	}
}

// A floor that is any string, Number() NaN or not, is refused: Go reads floors as JSON numbers only, stricter than the
// reference's coercing comparison, and a forged "+-Infinity" floor can never pass.
func TestSchemaVerbFloorRefusesStringFloors(t *testing.T) {
	honest := actionVectorByID(t, "schema-verb-adv-honest")["verb"].(map[string]any)
	for _, field := range []string{"risk", "blast_ppm", "esc"} {
		for _, s := range append([]string{"Infinity", "3"}, jsNumberNaN...) {
			v := deepCopy(honest).(map[string]any)
			v["floors"].(map[string]any)[field] = s
			if e := schemaVerbFloorError(v, coreRegistry, nil); !strings.HasPrefix(e, "schema_floor_forged: ") {
				t.Errorf("floors.%s = %q: %q, want schema_floor_forged", field, s, e)
			}
		}
	}
}

// Reference: intent-history.ts responds_within, Number(q.slice('pending:'.length)); an event matching neither p nor q.
func TestMonitorPendingStateIsNumberOfTheTail(t *testing.T) {
	m := map[string]any{"id": "m", "kind": "responds_within", "within": jnum(3), "p": map[string]any{"verb": "a"}, "q": map[string]any{"verb": "b"}}
	e := map[string]any{"status": "committed", "verb": "other", "resource": "r", "params": map[string]any{}}
	for tail, want := range map[string]string{
		"": "missed", " ": "missed", "1": "missed", " 5 ": "pending:4", "0x10": "pending:15", "Infinity": "pending:Infinity",
		"inf": "pending:NaN", "+-Infinity": "pending:NaN", "1_0": "pending:NaN", "0x1p3": "pending:NaN", "x": "pending:NaN",
	} {
		if got := monitorStep(m, "pending:"+tail, e); got != want {
			t.Errorf("pending:%q: %q, want %q", tail, got, want)
		}
	}
}
