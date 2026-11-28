//go:build pcagoalkernel

package goalkernel

import (
	"compress/gzip"
	"encoding/json"
	"os"
	"testing"
)

// The kernel tape corpus (the goal-kernel corpus in ../testdata): the reference's extracted JavaScript kernel on every goal
// conformance vector. Every op's output tape must be identical.
type kcase struct {
	Name string            `json:"name"`
	Args []json.RawMessage `json:"args"`
	Out  struct {
		Typecheck string      `json:"typecheck"`
		Compile   string      `json:"compile"`
		Render    string      `json:"render"`
		Probes    [][2]string `json:"probes"`
	} `json:"out"`
}

func loadCorpus(t *testing.T) []kcase {
	t.Helper()
	f, err := os.Open("../testdata/ref-goal-kernel.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Count int     `json:"count"`
		Cases []kcase `json:"cases"`
	}
	if err := json.NewDecoder(z).Decode(&doc); err != nil {
		t.Fatal(err)
	}
	if doc.Count != len(doc.Cases) || doc.Count != 203 {
		t.Fatalf("corpus has %d of %d cases", len(doc.Cases), doc.Count)
	}
	return doc.Cases
}

func mustTape(t *testing.T, s string) Tape {
	t.Helper()
	x, err := TapeFromText(s)
	if err != nil {
		t.Fatal(err)
	}
	if TapeToText(x) != s {
		t.Fatalf("tape text does not round-trip: %.80s", s)
	}
	return x
}

func TestGoalKernelTapes(t *testing.T) {
	bad := 0
	report := func(format string, a ...interface{}) {
		if bad++; bad <= 25 {
			t.Errorf(format, a...)
		}
	}
	for _, c := range loadCorpus(t) {
		var gs, os_ string
		var probes [][2]string
		if len(c.Args) != 3 || json.Unmarshal(c.Args[0], &gs) != nil || json.Unmarshal(c.Args[1], &os_) != nil || json.Unmarshal(c.Args[2], &probes) != nil {
			t.Fatalf("%s: bad args", c.Name)
		}
		g, o := mustTape(t, gs), mustTape(t, os_)
		for _, w := range []struct{ op, want string }{{"typecheck", c.Out.Typecheck}, {"compile", c.Out.Compile}, {"render", c.Out.Render}} {
			got, err := Call(w.op, g, o, nil, nil)
			if err != nil || TapeToText(got) != w.want {
				report("%s %s: %v %.120s != %.120s", c.Name, w.op, err, TapeToText(got), w.want)
			}
		}
		if len(probes) != len(c.Out.Probes) {
			t.Fatalf("%s: %d probes, %d outputs", c.Name, len(probes), len(c.Out.Probes))
		}
		for i, p := range probes {
			a, h := mustTape(t, p[0]), mustTape(t, p[1])
			for j, op := range []string{"decideg", "decidep"} {
				got, err := Call(op, g, o, a, h)
				if err != nil || TapeToText(got) != c.Out.Probes[i][j] {
					report("%s#%d %s: %v %s != %s", c.Name, i, op, err, TapeToText(got), c.Out.Probes[i][j])
				}
			}
			// the typed front door agrees with the tapes, and D_G equals the compiled policy's decision
			// With holes the compiler lowers Strip(g) (grants a hole depends on dropped, holes emptied): the proof gives
			// D_P(Lower(Strip g)) == D_G(Strip g) exactly, and D_P is never more permissive than D_G(g). Without holes Strip(g) is g.
			d, err := DecidePolicy(g, o, a, h)
			dg, err2 := DecideGoal(g, o, a, h)
			sg, err3 := stripGoalTape(g)
			dgs := ""
			if err3 == nil {
				dgs, err3 = DecideGoal(sg, o, a, h)
			}
			rank := map[string]int{"deny": 0, "escalate": 1, "allow": 2}
			if err != nil || err2 != nil || err3 != nil || !d.OK || d.Decision != dgs || rank[d.Decision] > rank[dg] || (d.Decision == "allow") != (d.Witness != nil) || (d.Witness != nil && !d.WitnessChecked) {
				report("%s#%d typed: %v %v %v %+v goal=%s stripped=%s", c.Name, i, err, err2, err3, d, dg, dgs)
			}
		}
		if r, err := CompileGoal(g, o); err != nil || r.OK != (c.Out.Compile[:2] == "i0") {
			report("%s CompileGoal: %v %+v", c.Name, err, r)
		}
		if rs, err := Typecheck(g, o); err != nil || (len(rs) == 0) != (c.Out.Typecheck == "i0") {
			report("%s Typecheck: %v %v", c.Name, err, rs)
		}
		if r, err := RenderTape(g); err != nil || "i0 "+TapeToText(r) != c.Out.Render {
			report("%s RenderTape: %v", c.Name, err)
		}
	}
	if bad > 0 {
		t.Fatalf("%d divergence(s)", bad)
	}
}

func TestGoalKernelRefusesMalformed(t *testing.T) {
	out, err := Call("typecheck", Tape{I(7)}, Tape{}, nil, nil)
	if err != nil || TapeToText(out) != "i9" {
		t.Fatalf("malformed goal: %v %v", err, out)
	}
	if _, err := Typecheck(Tape{I(7)}, Tape{}); err != ErrRejected {
		t.Fatalf("Typecheck of a malformed tape: %v", err)
	}
	if _, err := Call("typecheck", Tape{K(maxSafe + 1)}, Tape{}, nil, nil); err == nil {
		t.Fatal("an unsafe integer must be refused")
	}
	if _, err := Call("nope", Tape{}, Tape{}, nil, nil); err == nil {
		t.Fatal("an unknown op must be refused")
	}
}

func TestTapeText(t *testing.T) {
	x, err := TapeFromText("k5 i-3 s s68.1f600")
	if err != nil || len(x) != 4 || x[0] != K(5) || x[1] != I(-3) || x[2] != S("") || x[3] != S("h\U0001F600") {
		t.Fatalf("%v %v", x, err)
	}
	for _, bad := range []string{"x1", "kz", "s1g"} {
		if _, err := TapeFromText(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}
