package pca

import (
	"strings"
	"testing"
)

// The corpus header's clockMs is the replay clock; a corpus without it (committed before the member existed) uses the fallback.
func TestCorpusHeaderClockCases(t *testing.T) {
	doc := `{"about":"a","generator":"g.mts","count":2,"clockMs":1700000000000,"clockCases":["aged","dated"],"cases":[{"fn":"f","name":"aged","args":[],"out":null},{"fn":"f","name":"plain","args":[],"out":null}]}`
	got := map[string]bool{}
	baseEachStream(t, "cases", strings.NewReader(doc), normalizeJSON, func(c *baseCase) { got[c.Name] = vecIsClockCase(c.Name) })
	if !got["aged"] || got["plain"] || !vecIsClockCase("dated") {
		t.Errorf("clock cases: %v", got)
	}
}

func TestCorpusHeaderClock(t *testing.T) {
	doc := func(clock string) string {
		return `{"about":"a","generator":"g.mts","count":1` + clock + `,"cases":[{"fn":"f","name":"n","args":[],"out":null}]}`
	}
	for _, tc := range []struct {
		name, clock string
		want        float64
	}{
		{"header clock", `,"clockMs":1700000000000`, 1_700_000_000_000},
		{"pinned generator clock", `,"clockMs":1800000000123`, 1_800_000_000_123},
		{"no member", ``, 1_700_000_000_000}, // the contract's default
	} {
		seen := 0
		baseEachStream(t, tc.name, strings.NewReader(doc(tc.clock)), normalizeJSON, func(c *baseCase) {
			seen++
			if got := vecOracleNow(); got != tc.want {
				t.Errorf("%s: clock %v, want %v", tc.name, got, tc.want)
			}
		})
		if seen != 1 {
			t.Errorf("%s: %d cases replayed", tc.name, seen)
		}
	}
}
