package pca

// r0: guards that sort before every other test file (a0_k05_000_r0 < a0_k05_000_r7), so a mutant that makes the code loop,
// allocate without bound, panic in a goroutine or crash on a nil result is decided here by an ordinary assertion failure under
// -failfast, before a later test hangs or kills the binary. Every call runs on its own goroutine under a recover and a deadline.
// The order inside the file matters: split first (a recursive caller would overflow the stack under a wrong split), then the
// loops, then the goroutine-spawning conformance checks.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"
)

func r0within(t *testing.T, d time.Duration, what string, f func()) {
	t.Helper()
	done := make(chan any, 1)
	go func() {
		defer func() { done <- recover() }()
		f()
	}()
	select {
	case p := <-done:
		if p != nil {
			t.Fatalf("%s panicked: %v", what, p)
		}
	case <-time.After(d):
		t.Fatalf("%s did not return within %v", what, d)
	}
}

// pca.go build: the recursion ends at one leaf. A mutant that never reaches the base case grows the stack to the 1 GB limit in
// about a second (a run error that no test decides), so the deadline (300 ms; the unmutated call costs microseconds, ~1000x headroom) is far shorter and the failure comes first.
func TestR0_BuildEndsAtOneLeaf(t *testing.T) {
	leaves := func(n int) [][]byte {
		out := make([][]byte, n)
		for i := range out {
			out[i] = []byte{byte(i + 1)}
		}
		return out
	}
	for _, n := range []int{1, 2, 3, 5, 8} {
		var root []byte
		r0within(t, 300*time.Millisecond, fmt.Sprintf("build(%d leaves)", n), func() { root = build(leaves(n)) })
		if len(root) == 0 {
			t.Errorf("build(%d leaves) is empty", n)
		}
	}
}

// pca.go split: the largest power of two below n (1 for n <= 2).
func TestR0_SplitIsTheLargestPowerOfTwoBelowN(t *testing.T) {
	want := map[int]int{1: 1, 2: 1, 3: 2, 4: 2, 5: 4, 8: 4, 9: 8, 16: 8, 17: 16}
	got := map[int]int{}
	r0within(t, time.Second, "split", func() {
		for n := range want {
			got[n] = split(n)
		}
	})
	for n, w := range want {
		if got[n] != w {
			t.Errorf("split(%d) = %d, want %d", n, got[n], w)
		}
	}
}

// k3.go compareVersion: the loop advances over every part.
func TestR0_CompareVersionTerminates(t *testing.T) {
	var a, b, c int
	r0within(t, time.Second, "compareVersion", func() {
		a = compareVersion("1.2", "1.2")
		b = compareVersion("1", "1.0")
		c = compareVersion("1.2", "1.10")
	})
	if a != 0 || b != 0 || c != -1 {
		t.Fatalf("compareVersion: %d %d %d", a, b, c)
	}
}

// actions.go packProof: the walk stops at one leaf, shrinks its segment, and the reversal loop ends.
func TestR0_PackProofTerminates(t *testing.T) {
	for _, c := range []struct {
		digests []string
		digest  string
		path    int
	}{
		{[]string{"a"}, "a", 0},
		{[]string{"a", "b", "c", "d", "e", "f", "g", "h"}, "a", 3},
		{[]string{"a", "b", "c", "d", "e"}, "a", 3},
		{[]string{"a", "b", "c", "d", "e"}, "e", 1},
	} {
		var proof map[string]any
		var err error
		r0within(t, 300*time.Millisecond, "packProof", func() { proof, err = packProof(c.digests, c.digest) })
		if err != nil {
			t.Fatalf("packProof(%v, %s): %v", c.digests, c.digest, err)
		}
		if p, _ := proof["path"].([]any); len(p) != c.path {
			t.Fatalf("packProof(%v, %s) path %v, want %d hashes", c.digests, c.digest, proof["path"], c.path)
		}
	}
}

// attest_der.go readCertRoleInfo and parseTbsExtensions: the element walk moves past every element.
func TestR0_DERWalksTerminate(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := selfSigned(t, key, "r0", time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC))
	r0within(t, 2*time.Second, "readCertRoleInfo", func() {
		if _, err := readCertRoleInfo(cert.Raw); err != nil {
			t.Errorf("readCertRoleInfo: %v", err)
		}
	})
	var tbl *extTable
	r0within(t, 2*time.Second, "parseTbsExtensions", func() { tbl, err = parseTbsExtensions(cert.RawTBSCertificate) })
	if err != nil || tbl == nil {
		t.Fatalf("parseTbsExtensions: %v %v", tbl, err)
	}
}

// attest_nvidia.go parseNvidiaSpdmEvidence: after the blocks the nonce is skipped forward.
func TestR0_NvidiaSpdmParseDoesNotPanic(t *testing.T) {
	var rep *spdmReport
	var err error
	r0within(t, 2*time.Second, "parseNvidiaSpdmEvidence", func() { rep, err = parseNvidiaSpdmEvidence(g10nvRaw(nil, 0, nil, []byte{3, 0, 0, 0})) })
	if err != nil || rep == nil || len(rep.opaque) != 1 {
		t.Fatalf("parseNvidiaSpdmEvidence: %v %v", rep, err)
	}
}

// agent.go CommitPlan: a committed plan answers ProofFor (the closure is set).
func TestR0_CommitPlanProofFor(t *testing.T) {
	var pc *PlanCommit
	var err error
	var proof map[string]any
	r0within(t, 300*time.Millisecond, "CommitPlan", func() {
		pc, err = CommitPlan([]map[string]any{{"id": "n1", "verb": "v", "resource": "r"}})
		if err == nil && pc != nil {
			proof, err = pc.ProofFor("n1")
		}
	})
	if err != nil || pc == nil || proof == nil {
		t.Fatalf("CommitPlan / ProofFor: %v %v %v", pc, proof, err)
	}
}

// blueprint.go: every method that takes the registry lock gives it back (the next call would block for ever).
func TestR0_BlueprintRegistryReleasesItsLock(t *testing.T) {
	op := newKey(t)
	reg := NewBlueprintRegistry([]string{op.id}, MemoryBlueprintKv())
	b := parityBlueprint(t, op, "K", "active", func(b map[string]any) { delete(b, "runtime_pins") })
	var c1, c2 string
	r0within(t, 2*time.Second, "Accept twice", func() {
		c1, _ = reg.Accept(b)
		c2, _ = reg.Accept(b)
	})
	if c1 != "" || c2 != "" {
		t.Fatalf("accept: %q %q", c1, c2)
	}
	chain := []any{map[string]any{"issuer": "root", "holder": "K"}, map[string]any{"issuer": "K", "holder": "inst"}}
	var d1, d2 BlueprintDecision
	r0within(t, 2*time.Second, "CheckBlueprints twice", func() {
		d1 = CheckBlueprints(chain, reg, jnum(2), "any", nil)
		d2 = CheckBlueprints(chain, reg, jnum(2), "any", nil)
	})
	if d1.Decision != "allow" || d2.Decision != "allow" {
		t.Fatalf("check: %+v %+v", d1, d2)
	}
	var e1, e2 int64
	r0within(t, 2*time.Second, "Epoch twice", func() {
		e1 = reg.Epoch()
		e2 = reg.Epoch()
	})
	if e1 != 1 || e2 != 1 {
		t.Fatalf("epoch %d %d", e1, e2)
	}
}

// attest_xml.go c14nElement: the in-scope bindings are visited in map order, so a `continue` turned into `break` ends the
// scan at a random point. With 30 skipped bindings (the xml prefix and undeclared prefixes) mixed with 30 rendered ones, the
// chance that every rendered binding comes before the first skipped one is below 1e-17.
func TestR0_C14NSkippedBindingsDoNotEndTheScan(t *testing.T) {
	parent := map[string]string{"xml": "http://www.w3.org/XML/1998/namespace"}
	var want []string
	for i := 0; i < 30; i++ {
		parent[fmt.Sprintf("u%02d", i)] = ""
		parent[fmt.Sprintf("q%02d", i)] = "w"
		want = append(want, fmt.Sprintf(` xmlns:q%02d="w"`, i))
	}
	sort.Strings(want)
	if got := canonicalize(&xmlNode{elem: true, name: "a"}, parent, nil); got != "<a"+strings.Join(want, "")+"></a>" {
		t.Errorf("canonicalize: %q", got)
	}
}
