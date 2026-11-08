package pca

import (
	"fmt"
	"testing"
)

// actions_traits.go extendRegistry: a custom trait that is an object whose id is not a string is refused by the pre-check
// (not by registryErrorRaw, whose message differs).
func TestW2bExtendRegistryObjectWithoutStringID(t *testing.T) {
	for _, c := range []map[string]any{{}, {"id": 7}, {"id": nil}} {
		_, err := extendRegistry(coreRegistry, []any{c})
		if err == nil || err.Error() != "bad_registry: custom trait may not redefine a core trait" {
			t.Fatalf("%v: got %v", c, err)
		}
	}
}

// intent_wb.go decideParamProvenance: the critical-cap deny names the first offending parameter in sorted path order.
func TestW2bProvenanceCriticalCapNamesFirstSortedPath(t *testing.T) {
	params := map[string]any{}
	pol := map[string]any{}
	for i := 9; i >= 0; i-- {
		params[fmt.Sprintf("k%d", i)] = "x"
		pol[fmt.Sprintf("action.params.k%d", i)] = "critical"
	}
	policy := map[string]any{"params": pol, "critical_max": "trusted"}
	action := map[string]any{"params": params}
	want := "provenance: critical parameter 'action.params.k0' has provenance 'agent', above the policy maximum 'trusted'"
	for i := 0; i < 64; i++ { // map order is random per range: an unsorted walk names another path almost surely
		d := decideParamProvenance("site", "s", action, nil, false, nil, false, nil, false, policy)
		if d.outcome != "deny" || d.reason != want {
			t.Fatalf("got %q %q", d.outcome, d.reason)
		}
	}
}
