package pca

import (
	"strings"
	"testing"
)

func TestOmegaFromJSONRefusesACategoricalWithoutValues(t *testing.T) {
	mk := func(extra map[string]any) map[string]any {
		d := map[string]any{"kind": "cat", "path": "action.params.to"}
		for k, v := range extra {
			d[k] = v
		}
		return map[string]any{"approximate": []any{}, "verbs": []any{map[string]any{"verb": "x.a", "reversibility": "reversible", "w": 1.0, "dims": []any{d}}}}
	}
	for name, j := range map[string]map[string]any{"absent": mk(nil), "empty": mk(map[string]any{"values": []any{}})} {
		if _, err := IntentOmegaFromJSON(j); err == nil || !strings.Contains(err.Error(), "no values") {
			t.Errorf("%s: %v", name, err)
		}
	}
	ok := mk(map[string]any{"values": []any{map[string]any{"kind": "exact", "value": "a"}}})
	if _, err := IntentOmegaFromJSON(ok); err != nil {
		t.Errorf("one value: %v", err)
	}
}

func TestRequireAttestedFactRefusesAStringPath(t *testing.T) {
	if _, err := RequireAttestedFact(RequireAttestedFactOpts{Notary: "x", Path: "id", Equals: 1.0}); err == nil || !strings.Contains(err.Error(), "array of segments") {
		t.Errorf("string path: %v", err)
	}
}
