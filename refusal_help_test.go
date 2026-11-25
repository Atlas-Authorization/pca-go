package pca

import (
	"strings"
	"testing"
)

func TestExplainRefusal(t *testing.T) {
	h := ExplainRefusal("audience: signed aud ins_a is not ins_b")
	if h.Check != "audience" || !strings.HasPrefix(h.Docs, "https://") || h.Docs != refusalsDoc+"#audience" {
		t.Fatalf("audience: %+v", h)
	}
	if h := ExplainRefusal("authorize: missing required component(s): budgetStore (fail closed)"); h.Check != "authorize" || !strings.Contains(h.Fix, "protect()") {
		t.Fatalf("authorize: %+v", h)
	}
	// leading token wins; a longer check name is not shadowed by its prefix
	if h := ExplainRefusal("grant_ref_bound: x"); h.Check != "grant_ref_bound" {
		t.Fatalf("grant_ref_bound: %+v", h)
	}
	if h := ExplainRefusal("plan_root_authorized: x"); h.Check != "plan_root_authorized" {
		t.Fatalf("plan_root_authorized: %+v", h)
	}
	// no leading token: found by "<check>:" anywhere
	if h := ExplainRefusal("Replay: replay: 3 was already claimed"); h.Check != "replay" {
		t.Fatalf("contains: %+v", h)
	}
}

func TestExplainRefusalNeverPanicsAndFallsBack(t *testing.T) {
	for _, r := range []string{"", "x", "42", "_", "\xff\xfe", "REPLAY: x", "audience", strings.Repeat("a", 10000)} {
		h := ExplainRefusal(r)
		if h.Docs == "" || h.Meaning == "" || h.Fix == "" || h.Check == "" {
			t.Fatalf("%q: empty field in %+v", r, h)
		}
	}
	if h := ExplainRefusal(""); h.Check != "unknown" || h.Docs != refusalsDoc {
		t.Fatalf("empty: %+v", h)
	}
	if h := ExplainRefusal("audience"); h.Check != "audience" { // bare token, no colon
		t.Fatalf("bare: %+v", h)
	}
}

// The 0.5 rows: provenance by default and undo windows.
func TestExplainRefusalProvenanceAndUndo(t *testing.T) {
	if h := ExplainRefusal("provenance_flow: escalate: the choice of payments.send derives from untrusted content"); h.Check != "provenance_flow" || h.Docs != PCADocs+"/guides/prompt-injection-provenance.md" || !strings.Contains(h.Fix, "PCA-Provenance") {
		t.Fatalf("provenance_flow: %+v", h)
	}
	if h := ExplainRefusal("undo_window: runs now under a veto window until 1 (compensation payments.refund)"); h.Check != "undo_window" || h.Docs != PCADocs+"/guides/undo-windows.md" || !strings.Contains(h.Fix, "undo coordinator") {
		t.Fatalf("undo_window: %+v", h)
	}
}

// Every table row is complete and its docs link is an absolute https URL under the published docs.
func TestRefusalTableComplete(t *testing.T) {
	seen := map[string]bool{}
	for _, h := range refusalTable {
		if h.Check == "" || h.Meaning == "" || h.Fix == "" || !strings.HasPrefix(h.Docs, PCADocs+"/") || seen[h.Check] {
			t.Fatalf("bad row %+v", h)
		}
		seen[h.Check] = true
	}
	if len(refusalTable) != 24 {
		t.Fatalf("rows %d", len(refusalTable))
	}
}
