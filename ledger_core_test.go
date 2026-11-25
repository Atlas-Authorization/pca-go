package pca

import (
	"bytes"
	"testing"
)

func TestTransparencyLedgerRoundTrip(t *testing.T) {
	l := NewTransparencyLedger("pr")
	if r, _ := LedgerRootOf(nil); r != l.log.Root() {
		t.Fatal("empty root")
	}
	p1 := map[string]any{"v": jsNumber(1), "a": "x"}
	p2 := map[string]any{"v": jsNumber(1), "a": "y"}
	_, c1, err := l.Append(p1, "s1")
	if err != nil {
		t.Fatal(err)
	}
	if want, _ := EntryCommit("s1", p1); c1 != want {
		t.Fatal("commit")
	}
	if _, _, err := l.Append(p2, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := l.AppendCommitment("opaque"); err != nil {
		t.Fatal(err)
	}
	if _, err := l.AppendCommitment(""); err == nil {
		t.Fatal("empty commit accepted")
	}
	root, _ := LedgerRootOf(l.Commits())
	if root != l.Head()["root"] {
		t.Fatal("root differs")
	}
	pr, _ := l.InclusionProof(1)
	if !l.VerifyInclusion(root, pr, l.Commits()[1]) {
		t.Fatal("inclusion")
	}
	old, _ := l.RootAt(1)
	cp, _ := l.ConsistencyProof(1, -1)
	if !l.VerifyConsistency(old, root, cp) {
		t.Fatal("consistency")
	}
	if len(l.AuditOpenings()) != 0 {
		t.Fatal("audit")
	}
	e, _ := l.Entry(0)
	if !VerifyOpening(e.Commit, *e.Opening) || VerifyOpening(e.Commit, LedgerOpening{Salt: "z", Pcactn: p1}) {
		t.Fatal("opening")
	}
	if had, _ := l.Shred(0); !had {
		t.Fatal("shred")
	}
	if had, _ := l.Shred(0); had {
		t.Fatal("double shred")
	}
	if had, _ := l.Shred(2); had {
		t.Fatal("shred of a commitment-only entry")
	}
	if now, _ := LedgerRootOf(l.Commits()); now != root {
		t.Fatal("shred changed the root")
	}
	// tamper: a stored opening that no longer matches
	cp2, _ := TransparencyLedgerFromEntries([]LedgerEntry{{Commit: c1, Opening: &LedgerOpening{Salt: "bad", Pcactn: p1}}}, "pr")
	if a := cp2.AuditOpenings(); len(a) != 1 || a[0] != 0 {
		t.Fatalf("audit tamper: %v", a)
	}
	if _, err := l.Entry(9); err == nil {
		t.Fatal("entry range")
	}
}

func TestTransparencyLedgerWitnessAndEquivocation(t *testing.T) {
	g, err := KeyPairFromSeed(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	l := NewTransparencyLedger("pr")
	if _, err := l.AppendCommitment("a"); err != nil {
		t.Fatal(err)
	}
	wh, err := l.WitnessHead(g, nil)
	if err != nil || !VerifyWitnessedHead(wh, g.Public) {
		t.Fatalf("witnessed head: %v", err)
	}
	mk := func(root string) map[string]any {
		s, err := SignTreeHead(g, map[string]any{"instance_id": "i", "principal": "pr", "size": jsNumber(1), "root": root, "prev_root": "p", "timestamp": jsNumber(5)}, nil)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	a, b := mk("r1"), mk("r2")
	if !DetectTreeHeadEquivocation(a, b, g.Public) || DetectTreeHeadEquivocation(a, a, g.Public) {
		t.Fatal("equivocation")
	}
	b["sig"] = a["sig"]
	if DetectTreeHeadEquivocation(a, b, g.Public) {
		t.Fatal("forged head counted as evidence")
	}
}
