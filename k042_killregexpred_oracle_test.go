package pca

// Differential kill tests of saferegex.go and predicates.go against the TypeScript reference: testdata/killRegex.json.gz
// (safe-regex.ts, predicates.ts isSafeRegexSource, regex-budget.ts: compiled sizes, full-match results over a pattern corpus
// crossed with boundary-probing subjects, the step boundary, the safe-source guard, the per-document budget) and
// testdata/killPred.json.gz (predicates.ts: path resolution over many contexts, every leaf operator over fields x operands,
// `like` globs, `matches`, `member_of` closures, groupings, predicates and predicate lists). Both are produced by
// tools/pca-audit/kotlin-mutate/kill{Regex,Pred}-oracle-gen.mjs (shared with the Kotlin suite).

import (
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
)

func k042LoadGz(t *testing.T, path string) map[string]any {
	f, err := os.Open(path)
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
	return doc.(map[string]any)
}

// k042RequireCovers: under mutation (tools/pca-audit/go-mutate exports GOMUT_FILE = the mutated source) a heavy oracle runs only
// when it covers that file; an ordinary `go test` (variable unset) always runs it.
func k042RequireCovers(t *testing.T, files ...string) {
	t.Helper()
	f := os.Getenv("GOMUT_FILE")
	if f == "" {
		return
	}
	for _, c := range files {
		if c == f {
			return
		}
	}
	t.Skipf("this oracle does not cover %s", f)
}

func k042Sec(g map[string]any, k string) []any { return g[k].([]any) }

func k042Int(v any) int { f, _ := jsNum(v); return int(f) }

func k042Fail(t *testing.T, bad []string) {
	t.Helper()
	if len(bad) > 0 {
		if len(bad) > 30 {
			bad = bad[:30]
		}
		t.Fatalf("%d divergences, first:\n%s", len(bad), strings.Join(bad, "\n"))
	}
}

func TestK042KillRegexFullMatchCorpus(t *testing.T) {
	k042RequireCovers(t, "saferegex.go")
	g := k042LoadGz(t, "testdata/killRegex.json.gz")
	var bad []string
	n := 0
	for _, eo := range k042Sec(g, "fm") {
		e := eo.([]any)
		p := u16(e[0].(string))
		subs := e[1].([]any)
		rs := e[2].(string)
		if len(subs) != len(rs) {
			t.Fatalf("corpus shape for %q", e[0])
		}
		prog := compileSafeRegex(p)
		for i, so := range subs {
			want := "N"
			switch rs[i] {
			case '1':
				want = "T"
			case '0':
				want = "F"
			}
			got := "N"
			if prog != nil {
				if m, ok := runSafeRegex(prog, u16(so.(string))); ok {
					got = "F"
					if m {
						got = "T"
					}
				}
			}
			if m, ok := safeRegexFullMatch(p, u16(so.(string))); (ok && got == "N") || (!ok && got != "N") || (ok && m != (got == "T")) {
				bad = append(bad, fmt.Sprintf("safeRegexFullMatch disagrees with compile+run for /%q/", e[0]))
			}
			if want != got {
				bad = append(bad, fmt.Sprintf("/%q/ on %q: want %s got %s", e[0], so, want, got))
			}
			n++
		}
	}
	if n < 100000 {
		t.Fatalf("only %d matches", n)
	}
	k042Fail(t, bad)
}

func u16(s string) []uint16 { return utf16Units(s) }

func TestK042KillRegexSizesStepsAndSafeSource(t *testing.T) {
	g := k042LoadGz(t, "testdata/killRegex.json.gz")
	var bad []string
	for _, eo := range k042Sec(g, "size") {
		e := eo.([]any)
		want := k042Int(e[1])
		prog := compileSafeRegex(u16(e[0].(string)))
		if want < 0 {
			if prog != nil {
				bad = append(bad, fmt.Sprintf("size /%q/: want refused got %d", e[0], len(prog)))
			}
		} else if prog == nil || len(prog) != want {
			bad = append(bad, fmt.Sprintf("size /%q/: want %d got %d", e[0], want, len(prog)))
		}
	}
	for _, eo := range k042Sec(g, "steps") {
		e := eo.([]any)
		n := k042Int(e[1])
		want := map[int]string{1: "T", 0: "F"}[k042Int(e[2])]
		if want == "" {
			want = "N"
		}
		got := "N"
		if m, ok := safeRegexFullMatch(u16(e[0].(string)), u16(strings.Repeat("a", n))); ok {
			got = "F"
			if m {
				got = "T"
			}
		}
		if got != want {
			bad = append(bad, fmt.Sprintf("steps /%.20s/ n=%d: want %s got %s", e[0], n, want, got))
		}
	}
	for _, eo := range k042Sec(g, "safe") {
		e := eo.([]any)
		if got := isSafeRegexSource(u16(e[0].(string))); got != e[1].(bool) {
			bad = append(bad, fmt.Sprintf("safe /%q/: want %v got %v", e[0], e[1], got))
		}
	}
	k042Fail(t, bad)
}

func TestK042KillRegexBudgetSequences(t *testing.T) {
	g := k042LoadGz(t, "testdata/killRegex.json.gz")
	var bad []string
	for k, bo := range k042Sec(g, "budgets") {
		b := bo.(map[string]any)
		budget := &regexBudget{}
		ops, res := b["ops"].([]any), b["res"].([]any)
		for i, oo := range ops {
			op := oo.([]any)
			if got := budget.charge(u16(op[0].(string)), k042Int(op[1])); got != res[i].(bool) {
				bad = append(bad, fmt.Sprintf("budget #%d op %d: want %v got %v", k, i, res[i], got))
			}
		}
		fin := b["fin"].([]any)
		// a refused charge poisons the Go budget differently from the reference's counters (evaluations / chars / steps stay
		// the reference's only while nothing was refused)
		if k042Int(fin[3]) == 0 {
			if budget.evaluations != k042Int(fin[0]) || budget.chars != k042Int(fin[1]) || budget.steps != k042Int(fin[2]) {
				bad = append(bad, fmt.Sprintf("budget #%d totals: want %v got %d/%d/%d", k, fin, budget.evaluations, budget.chars, budget.steps))
			}
		}
	}
	k042Fail(t, bad)
}

func k042KillTri(s any) int {
	switch s.(string) {
	case "T":
		return triTrue
	case "F":
		return triFalse
	}
	return triUnknown
}

func TestK042KillPredResolvePathAndConditions(t *testing.T) {
	k042RequireCovers(t, "predicates.go", "saferegex.go", "jsval.go", "strictjson.go")
	g := k042LoadGz(t, "testdata/killPred.json.gz")
	ctxs := k042Sec(g, "ctxs")
	ctx := func(i any) map[string]any { m, _ := ctxs[k042Int(i)].(map[string]any); return m }
	var bad []string
	for _, eo := range k042Sec(g, "rp") {
		e := eo.([]any)
		v, found := resolvePath(ctx(e[1]), e[0])
		if found != e[2].(bool) {
			bad = append(bad, fmt.Sprintf("resolvePath %q @ctx%d: want found=%v got %v", e[0], k042Int(e[1]), e[2], found))
			continue
		}
		if found {
			w, _ := canonicalLenient(e[3])
			gt, _ := canonicalLenient(v)
			if w != gt {
				bad = append(bad, fmt.Sprintf("resolvePath %q @ctx%d: want %s got %s", e[0], k042Int(e[1]), w, gt))
			}
		}
	}
	conds := k042Sec(g, "cond")
	if len(conds) < 100000 {
		t.Fatalf("only %d conditions", len(conds))
	}
	for _, eo := range conds {
		e := eo.([]any)
		if got := evaluateConditionTri(e[0], ctx(e[1]), &regexBudget{}); got != k042KillTri(e[2]) {
			s, _ := canonicalLenient(e[0])
			bad = append(bad, fmt.Sprintf("condition %.160s @ctx%d: want %v got %d", s, k042Int(e[1]), e[2], got))
		}
	}
	k042Fail(t, bad)
}

func TestK042KillPredPredicatesAndLists(t *testing.T) {
	g := k042LoadGz(t, "testdata/killPred.json.gz")
	ctxs := k042Sec(g, "ctxs")
	ctx := func(i any) map[string]any { m, _ := ctxs[k042Int(i)].(map[string]any); return m }
	var bad []string
	for _, eo := range k042Sec(g, "pred") {
		e := eo.([]any)
		if got := predicateMatches(e[0], ctx(e[1]), &regexBudget{}); got != e[2].(bool) {
			s, _ := canonicalLenient(e[0])
			bad = append(bad, fmt.Sprintf("predicate %.160s @ctx%d: want %v got %v", s, k042Int(e[1]), e[2], got))
		}
	}
	for _, eo := range k042Sec(g, "preds") {
		e := eo.([]any)
		if got := evaluatePredicates(e[0], ctx(e[1])); got != e[2].(bool) {
			s, _ := canonicalLenient(e[0])
			bad = append(bad, fmt.Sprintf("predicates %.160s @ctx%d: want %v got %v", s, k042Int(e[1]), e[2], got))
		}
	}
	k042Fail(t, bad)
}
