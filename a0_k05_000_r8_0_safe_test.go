package pca

import "testing"

// Runs first (file name a0_k05_000_): a mutant that makes the code under test PANIC (index out of range, nil result) is decided
// here by an ordinary failure, before any later test dereferences the broken result and kills the whole test binary.
func r8Guard(t *testing.T, name string, fn func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("%s panicked: %v", name, r)
		}
	}()
	fn()
}

// attest_intel.go:310 (the walk from the leaf must run at least once: a lone self-signed root is its own chain).
func TestR8N0_PckChainLoneRootWalks(t *testing.T) {
	rootKey := g08Key(t)
	root := g08MakeCert(t, g08CATmpl("r8n0 lone root", 7), g08CATmpl("r8n0 lone root", 7), &rootKey.PublicKey, rootKey)
	var r pckChainResult
	r8Guard(t, "verifyIntelPckChain", func() { r = verifyIntelPckChain(g08PEM(root.Raw), g08Pin(root), g08now) })
	if !r.ok {
		t.Fatalf("lone root: %q", r.reason)
	}
}

// k3.go:49 (the version loop advances: every part is compared).
func TestR8N0_CompareVersionAdvances(t *testing.T) {
	var a, b, c int
	r8Guard(t, "compareVersion", func() {
		a = compareVersion("1.2", "1.2")
		b = compareVersion("1", "1.0")
		c = compareVersion("1.2", "1.10")
	})
	if a != 0 || b != 0 || c != -1 {
		t.Fatalf("compareVersion: %d %d %d", a, b, c)
	}
}

// agent.go:587 (a plan node that normalizes is committed: no error and a plan back).
func TestR8N0_CommitPlanValidNodeCommits(t *testing.T) {
	var pc *PlanCommit
	var err error
	r8Guard(t, "CommitPlan", func() {
		pc, err = CommitPlan([]map[string]any{{"id": "n1", "verb": "v", "resource": "r"}})
	})
	if err != nil || pc == nil {
		t.Fatalf("CommitPlan: %v %v", pc, err)
	}
}

// actions.go:1047 (the proof walk stops at a one-leaf segment: a single-def pack has an empty path, and a bigger one never
// slices an empty segment).
func TestR8N0_PackProofWalkStopsAtOneLeaf(t *testing.T) {
	var one, many map[string]any
	var err1, err2 error
	r8Guard(t, "packProof", func() {
		one, err1 = packProof([]string{"a"}, "a")
		many, err2 = packProof([]string{"a", "b", "c", "d", "e", "f", "g", "h"}, "a")
	})
	if err1 != nil || err2 != nil {
		t.Fatalf("packProof: %v %v", err1, err2)
	}
	if p, _ := one["path"].([]any); len(p) != 0 {
		t.Fatalf("single-def path: %v", one["path"])
	}
	if p, _ := many["path"].([]any); len(p) != 3 {
		t.Fatalf("eight-def path: %v", many["path"])
	}
}
