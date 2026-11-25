package pca

// Replays the policy-ci reference corpus: normalization, the lint rules over the analyzer, summary and exit codes, the pinned
// lint-rule digest, the authoring gates and the command line (files are written into a fresh directory per case).

import (
	"os"
	"path/filepath"
	"testing"
)

func policyciReplay(t *testing.T, file string, total int, fns map[string]func(c *baseCase) (any, error)) {
	t.Helper()
	var k baseTally
	n := 0
	siemEach(t, file, func(c *baseCase) {
		n++
		f, ok := fns[c.Fn]
		if !ok {
			k.fail(c, "no Go entry point for %s", c.Fn)
			return
		}
		k.run(c.Fn)
		var got any
		var err error
		if p := baseCall(func() { got, err = f(c) }); p != "" {
			k.fail(c, "panic: %s", p)
			return
		}
		if throws, _ := baseThrows(c.Out); throws {
			if err == nil && !(vecEngineCrash(c.Out) && vecRefusalValue(normalizeJSON(got))) {
				k.fail(c, "reference refuses (%v), Go returned %s", c.Out, baseCanon(normalizeJSON(got)))
			}
			return
		}
		if err != nil {
			k.fail(c, "Go refuses (%v), reference returned %s", err, baseCanon(c.Out))
			return
		}
		if w, g := baseCanon(c.Out), baseCanon(normalizeJSON(got)); w != g {
			k.fail(c, "want %s got %s", w, g)
		}
	})
	k.finish(t)
	if n != total {
		t.Fatalf("%s: the corpus holds %d cases, %d are expected", file, n, total)
	}
}

func TestPolicyCiVectors(t *testing.T) {
	arg := vecArg
	over := func(f func(a []any) (any, error)) func(c *baseCase) (any, error) {
		return func(c *baseCase) (any, error) { return f(c.Args) }
	}
	list := func(r []any, err error) (any, error) { return r, err }
	smap := func(r map[string]any, err error) (any, error) { return r, err }
	strs := func(v any) []string {
		out := []string{}
		l, _ := v.([]any)
		for _, x := range l {
			s, _ := x.(string)
			out = append(out, s)
		}
		return out
	}
	fns := map[string]func(c *baseCase) (any, error){
		"normalizePolicyInput": over(func(a []any) (any, error) { return PolicyCiNormalizePolicyInput(arg(a, 0)), nil }),
		"normalizeChain":       over(func(a []any) (any, error) { return smap(PolicyCiNormalizeChain(arg(a, 0))) }),
		"isCapability":         over(func(a []any) (any, error) { return PolicyCiIsCapability(arg(a, 0)), nil }),
		"isEnvelope":           over(func(a []any) (any, error) { return PolicyCiIsEnvelope(arg(a, 0)), nil }),
		"lintPolicy":           over(func(a []any) (any, error) { return list(PolicyCiLintPolicy(arg(a, 0), arg(a, 1))) }),
		"lintChain":            over(func(a []any) (any, error) { return list(PolicyCiLintChain(arg(a, 0), arg(a, 1))) }),
		"lint":                 over(func(a []any) (any, error) { return list(PolicyCiLint(arg(a, 0), arg(a, 1))) }),
		"lintPolicies":         over(func(a []any) (any, error) { return smap(PolicyCiLintPolicies(arg(a, 0), arg(a, 1))) }),
		"summarize":            over(func(a []any) (any, error) { return smap(PolicyCiSummarize(arg(a, 0), arg(a, 1))) }),
		"checkLintRulesPin": over(func(a []any) (any, error) {
			pin, _ := arg(a, 0).(string)
			if len(a) > 1 {
				actual, _ := arg(a, 1).(string)
				return PolicyCiCheckLintRulesPin(pin, actual), nil
			}
			return PolicyCiCheckLintRulesPin(pin), nil
		}),
		"toAnalyzerPolicy": over(func(a []any) (any, error) { return PolicyCiToAnalyzerPolicy(arg(a, 0)), nil }),
		"diffCommand":      over(func(a []any) (any, error) { return smap(PolicyCiDiffCommand(arg(a, 0), arg(a, 1), arg(a, 2))) }),
		"testCommand":      over(func(a []any) (any, error) { return smap(PolicyCiTestCommand(arg(a, 0), arg(a, 1), arg(a, 2))) }),
		"coverageCommand":  over(func(a []any) (any, error) { return smap(PolicyCiCoverageCommand(arg(a, 0), arg(a, 1), arg(a, 2))) }),
		"parseArgs":        over(func(a []any) (any, error) { return PolicyCiParseArgs(strs(arg(a, 0))), nil }),
		"run": func(c *baseCase) (any, error) {
			spec, _ := c.C["args"].(map[string]any)
			dir := t.TempDir()
			files, _ := spec["files"].(map[string]any)
			for name, body := range files {
				s, _ := body.(string)
				if err := os.WriteFile(filepath.Join(dir, name), []byte(s), 0o600); err != nil {
					return nil, err
				}
			}
			lines := []any{}
			code, err := pciRun(strs(spec["argv"]), func(s string) { lines = append(lines, s) }, dir)
			if err != nil {
				return nil, err
			}
			return map[string]any{"code": code, "lines": lines}, nil
		},
	}
	policyciReplay(t, "ref-policy-ci.json.gz", 2060, fns)
	policyciReplay(t, "ref-policy-ci-java-extra.json.gz", 162, fns)
}
