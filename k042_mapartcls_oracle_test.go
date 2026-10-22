package pca

// Differential kill test for intent_map.go (rule 19), the classifier (rule 18, intent_wb.go) and the shared artifact helpers
// (intent_artifacts.go) against the TypeScript reference: testdata/k042-mapartcls.json.gz comes from
// tools/pca-audit/java-mutate/k042-mapartcls-oracle.mjs (shared with the Java suite). Go reports verdicts rather than the
// reference's reason strings for the leaf validators, so those compare null vs refused; the decisions compare the verdict and
// every result member, and the reason texts of refused decisions are counted, not failed.

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
)

type k042MapCase struct {
	Fn, Name string
	Args     []any
	Out      any
}

var k042MapCases []k042MapCase

func k042MapLoad(t *testing.T) []k042MapCase {
	if k042MapCases == nil {
		f, err := os.Open("testdata/k042-mapartcls.json.gz")
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		zr, err := gzip.NewReader(f)
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(zr)
		if err != nil {
			t.Fatal(err)
		}
		doc, err := ParseJSONLenient(b)
		if err != nil {
			t.Fatal(err)
		}
		for _, o := range doc.([]any) {
			m := o.(map[string]any)
			k042MapCases = append(k042MapCases, k042MapCase{Fn: m["fn"].(string), Name: m["name"].(string), Args: normalizeJSON(m["args"]).([]any), Out: normalizeJSON(m["out"])})
		}
	}
	return k042MapCases
}

func k042MapOf(t *testing.T, fn string) []k042MapCase {
	var out []k042MapCase
	for _, c := range k042MapLoad(t) {
		if c.Fn == fn {
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		t.Fatalf("no oracle cases for %s", fn)
	}
	return out
}

func k042MapReport(t *testing.T, bad []string, n int) {
	t.Helper()
	if len(bad) > 0 {
		if len(bad) > 30 {
			bad = bad[:30]
		}
		t.Fatalf("%d/%d divergent:\n%s", len(bad), n, strings.Join(bad, "\n"))
	}
}

func k042MapValidators(t *testing.T, fn string, ok func(any) bool) {
	cs := k042MapOf(t, fn)
	var bad []string
	for _, c := range cs {
		want := c.Out == nil
		var got bool
		func() {
			defer func() {
				if r := recover(); r != nil {
					bad = append(bad, fmt.Sprintf("%s: threw %v", c.Name, r))
					got = want
				}
			}()
			got = ok(c.Args[0])
		}()
		if got != want {
			bad = append(bad, fmt.Sprintf("%s: want ok=%v got %v (reference reason %v)", c.Name, want, got, c.Out))
		}
	}
	k042MapReport(t, bad, len(cs))
}

func TestK042MapLeafValidators(t *testing.T) {
	k042MapValidators(t, "header", mapHeaderOK)
	k042MapValidators(t, "cell", mapCellOK)
	k042MapValidators(t, "metrics", mapMetricsOK)
	k042MapValidators(t, "learner", mapLearnerOK)
	k042MapValidators(t, "disclosure", mapDisclosureOK)
	k042MapValidators(t, "verdictwire", validateClassifierVerdictWire)
	k042MapValidators(t, "policy", validateClassifierPolicy)
}

func TestK042MapNumericCells(t *testing.T) {
	cs := k042MapOf(t, "numcells")
	var bad []string
	for _, c := range cs {
		got := mapNumCells(k042M(c.Args[0]))
		want := c.Out.([]any)
		same := len(got) == len(want)
		for i := 0; same && i < len(got); i++ {
			w := want[i].([]any)
			wl, _ := jsNum(w[0])
			wh, _ := jsNum(w[1])
			same = got[i][0] == wl && got[i][1] == wh
		}
		if !same {
			bad = append(bad, fmt.Sprintf("%s: want %v got %v", c.Name, want, got))
		}
	}
	k042MapReport(t, bad, len(cs))
}

func TestK042MapCellOfTheAction(t *testing.T) {
	cs := k042MapOf(t, "cellof")
	var bad []string
	for _, c := range cs {
		var params any
		if len(c.Args) > 2 {
			params = c.Args[2]
		}
		cell, flat, cerr := mapCellOf(k042M(c.Args[0]), c.Args[1], params)
		ok := cerr == ""
		if c.Out == nil {
			if ok {
				bad = append(bad, fmt.Sprintf("%s: want outside, got %v %d", c.Name, cell, flat))
			}
			continue
		}
		w := c.Out.(map[string]any)
		wf, _ := jsNum(w["flat"])
		wc := w["cell"].([]any)
		same := ok && float64(flat) == wf && len(cell) == len(wc)
		for i := 0; same && i < len(cell); i++ {
			x, _ := jsNum(wc[i])
			same = float64(cell[i]) == x
		}
		if !same {
			bad = append(bad, fmt.Sprintf("%s: want %v got %v %d %v", c.Name, w, cell, flat, ok))
		}
	}
	k042MapReport(t, bad, len(cs))
}

func TestK042MapCommitment(t *testing.T) {
	cs := k042MapOf(t, "commit")
	var bad []string
	for _, c := range cs {
		r := IntentMapCommitPrimitive(map[string]any{"leaves": c.Args[0]})
		if got, _ := r["map_commit"].(string); got != c.Out {
			bad = append(bad, fmt.Sprintf("%s: want %v got %v", c.Name, c.Out, got))
		}
	}
	k042MapReport(t, bad, len(cs))
}

func TestK042MapDecisions(t *testing.T) {
	cs := k042MapOf(t, "decide")
	var bad []string
	var td textDiffs
	for _, c := range cs {
		o := c.Out.(map[string]any)
		got, reason := IntentMapPrimitive(c.Args[0])
		if o["ok"] == true {
			wc, _ := canonicalLenient(o["cell"])
			gc, _ := canonicalLenient(got["cell"])
			wp, _ := jsNum(o["p_ppm"])
			gp, _ := jsNum(got["p_ppm"])
			if got["ok"] != true || wc != gc || wp != gp {
				bad = append(bad, fmt.Sprintf("%s: want %v got %v (%s)", c.Name, o, got, reason))
			}
			continue
		}
		if got["ok"] != false {
			bad = append(bad, fmt.Sprintf("%s: want refused (%v), got %v", c.Name, o["reason"], got))
			continue
		}
		if reason != o["reason"] {
			td.add(fmt.Sprint(o["reason"]), reason)
		}
	}
	td.finish(t)
	k042MapReport(t, bad, len(cs))
}

func TestK042ClassifierDecisions(t *testing.T) {
	cs := k042MapOf(t, "classify")
	var bad []string
	var td textDiffs
	for _, c := range cs {
		in, isMap := c.Args[0].(map[string]any)
		o := c.Out.(map[string]any)
		var d classDecision
		if !isMap {
			d = classDecision{reason: "classes: input must be an object"}
		} else {
			action, _ := in["action"].(map[string]any)
			committed, cP := in["committed"]
			verdicts, vP := in["verdicts"]
			d = decideClassifierDimensions(in["session"], action, committed, cP, verdicts, vP, in["policy"])
		}
		if d.ok != (o["ok"] == true) {
			bad = append(bad, fmt.Sprintf("%s: want ok=%v got %v (%s) ref %v", c.Name, o["ok"], d.ok, d.reason, o["reason"]))
			continue
		}
		if d.ok {
			w, _ := canonicalLenient(o["classes"])
			g, _ := canonicalLenient(d.classes)
			if w != g {
				bad = append(bad, fmt.Sprintf("%s: classes want %s got %s", c.Name, w, g))
			}
		} else if d.reason != o["reason"] {
			td.add(fmt.Sprint(o["reason"]), d.reason)
		}
	}
	td.finish(t)
	k042MapReport(t, bad, len(cs))
}

func TestK042ArtifactSignature(t *testing.T) {
	a := k042MapOf(t, "sigfixture")[0].Args
	v, pk, other := k042M(a[0]), a[1], a[2]
	dom := classifierDomain
	if !verifyArtifactSig(dom, v, pk, nil) {
		t.Fatal("the fixture signature must verify under the pinned key")
	}
	if verifyArtifactSig(dom, v, other, nil) {
		t.Error("another key verified")
	}
	if verifyArtifactSig(dom+"x", v, pk, nil) {
		t.Error("another domain verified")
	}
	cp := func() map[string]any {
		m := map[string]any{}
		for k, x := range v {
			m[k] = x
		}
		return m
	}
	noSig := cp()
	delete(noSig, "sig")
	numSig := cp()
	numSig["sig"] = jsNumber(5)
	lone := cp()
	lone["label"] = "a\xed\xa0\x80"
	dbl := cp()
	dbl["v"] = json.Number("1.0")
	for name, m := range map[string]map[string]any{"no sig": noSig, "numeric sig": numSig, "lone surrogate": lone, "1.0": dbl} {
		if verifyArtifactSig(dom, m, pk, nil) {
			t.Errorf("%s verified", name)
		}
	}
	if verifyArtifactSig(dom, v, nil, nil) || verifyArtifactSig(dom, v, jsNumber(5), nil) {
		t.Error("a missing / non-string pinned key verified")
	}
}
