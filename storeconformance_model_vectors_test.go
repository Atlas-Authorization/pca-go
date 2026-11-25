package pca

// Replays the shared corpus of the store conformance kit: the register model, the reductions, the linearizability search, the per-key
// and per-history checkers, and the check inventories of the five profiles. In the vectors a non-finite number is the object
// {"$num": "Infinity" | "-Infinity"}.

import (
	"math"
	"strings"
	"testing"
)

func stoNum(v any) float64 {
	if m, ok := v.(map[string]any); ok {
		switch m["$num"] {
		case "Infinity":
			return math.Inf(1)
		case "-Infinity":
			return math.Inf(-1)
		}
		return math.NaN()
	}
	return jsF(v)
}

func stoOps(v any) []*StoreOp {
	l, _ := v.([]any)
	out := make([]*StoreOp, 0, len(l))
	for _, x := range l {
		m := vecObj(x)
		out = append(out, &StoreOp{Client: vecStr(m, "client"), Kind: vecStr(m, "kind"), Key: vecStr(m, "key"), Res: vecStr(m, "res"),
			Lo: stoNum(m["lo"]), W: stoNum(m["w"]), Call: stoNum(m["call"]), Ret: stoNum(m["ret"])})
	}
	return out
}

func stoOut(f float64) any {
	switch {
	case math.IsInf(f, 1):
		return map[string]any{"$num": "Infinity"}
	case math.IsInf(f, -1):
		return map[string]any{"$num": "-Infinity"}
	}
	return jsNumber(f)
}

func stoOpOut(o *StoreOp) map[string]any {
	return map[string]any{"client": o.Client, "kind": o.Kind, "key": o.Key, "lo": stoOut(o.Lo), "w": stoOut(o.W), "call": stoOut(o.Call), "ret": stoOut(o.Ret), "res": o.Res}
}

func stoOpsOut(ops []*StoreOp) any {
	if ops == nil {
		return nil
	}
	out := make([]any, len(ops))
	for i, o := range ops {
		out[i] = stoOpOut(o)
	}
	return out
}

func stoKeyOut(r StoreKeyResult) map[string]any {
	m := map[string]any{"key": r.Key, "kind": r.Kind, "ops": r.Ops, "searched": r.Searched, "verdict": r.Verdict, "method": r.Method}
	if r.Verdict == "violation" {
		m["counterexample"], m["minimized"] = stoOpsOut(r.Counterexample), r.Minimized
	}
	return m
}

func stoOptions(v any) StoreCheckOptions {
	m := vecObj(v)
	o := StoreCheckOptions{}
	if b, ok := jsNum(m["budget"]); ok {
		o.Budget = int(b)
	}
	if m["minimize"] == false {
		o.NoMinimize = true
	}
	if l, ok := jsNum(m["minimizeLimit"]); ok {
		o.MinimizeLimit = int(l)
	}
	return o
}

func stoBudget(a []any, i int) int {
	if b, ok := jsNum(vecArg(a, i)); ok {
		return int(b)
	}
	return 0
}

func stoInventory(profile string) any {
	keep := func(names []string, claims []string, needs []string) any {
		out := make([]any, len(names))
		for i := range names {
			var n any
			if needs[i] != "" {
				n = needs[i]
			}
			out[i] = map[string]any{"name": names[i], "claim": claims[i], "needs": n}
		}
		return out
	}
	switch profile {
	case "lease":
		return stoInv(GuardianLeaseChecks, keep)
	case "ledger":
		return stoInv(LedgerChecks, keep)
	case "budget":
		return stoInv(BudgetChecks, keep)
	case "bond":
		return stoInv(BondChecks, keep)
	}
	a := MeshWitnessStoreAdapter{Name: "x"}
	if strings.Contains(profile, "+reopen") {
		a.Reopen = func(p MeshWitnessStateStore) (MeshWitnessStateStore, error) { return p, nil }
	}
	if strings.Contains(profile, "+damage") {
		a.Damage = func(MeshWitnessStateStore) error { return nil }
	}
	var names []any
	for _, c := range MeshWitnessStoreCases(a, nil) {
		names = append(names, c.Name)
	}
	return names
}

func stoInv[S any](checks []ProfileCheck[S], keep func(n, c, nd []string) any) any {
	var n, c, nd []string
	for _, k := range checks {
		n, c, nd = append(n, k.Name), append(c, k.Claim), append(nd, k.Needs)
	}
	return keep(n, c, nd)
}

func TestStoreConformanceModelVectors(t *testing.T) {
	report := func(v any) StoreSuiteReport {
		m := vecObj(v)
		r := StoreSuiteReport{Adapter: vecStr(m, "adapter"), Status: vecStr(m, "status")}
		tests, _ := m["tests"].([]any)
		for _, x := range tests {
			tm := vecObj(x)
			n := func(k string) int { f, _ := jsNum(tm[k]); return int(f) }
			tr := StoreTestReport{Test: vecStr(tm, "test"), Kind: vecStr(tm, "kind"), Status: vecStr(tm, "status"), Ops: n("ops"), Keys: n("keys"),
				Errors: n("errors"), Unresolved: n("unresolved"), Note: vecStr(tm, "note"), Violations: []StoreKeyResult{}}
			viol, _ := tm["violations"].([]any)
			for _, y := range viol {
				vm := vecObj(y)
				vn := func(k string) int { f, _ := jsNum(vm[k]); return int(f) }
				kr := StoreKeyResult{Key: vecStr(vm, "key"), Kind: vecStr(vm, "kind"), Ops: vn("ops"), Searched: vn("searched"), Verdict: vecStr(vm, "verdict"),
					Method: vecStr(vm, "method"), Minimized: vm["minimized"] == true}
				if ce, has := vm["counterexample"]; has {
					kr.Counterexample = stoOps(ce)
				}
				tr.Violations = append(tr.Violations, kr)
			}
			r.Tests = append(r.Tests, tr)
		}
		return r
	}
	replayVectors(t, "ref-store-conformance.json.gz", map[string]vecFn{
		"step": func(a []any) (any, error) {
			var out []any
			for _, s := range StoreRegisterStep(stoNum(vecArg(a, 0)), stoOps([]any{vecArg(a, 1)})[0]) {
				out = append(out, stoOut(s))
			}
			if out == nil {
				out = []any{}
			}
			return out, nil
		},
		"overlappingTrues": func(a []any) (any, error) { return stoOpsOut(StoreOverlappingTrues(stoOps(vecArg(a, 0)))), nil },
		"prune":            func(a []any) (any, error) { return stoOpsOut(StorePrune(stoOps(vecArg(a, 0)))), nil },
		"fastCheck": func(a []any) (any, error) {
			ok, known := StoreFastCheck(stoOps(vecArg(a, 0)))
			if !known {
				return nil, nil
			}
			return ok, nil
		},
		"search": func(a []any) (any, error) { return StoreSearchLinearizable(stoOps(vecArg(a, 0)), stoBudget(a, 1)), nil },
		"decideKey": func(a []any) (any, error) {
			d := StoreDecideKey(stoOps(vecArg(a, 0)), stoBudget(a, 1))
			return map[string]any{"verdict": d.Verdict, "method": d.Method, "kept": stoOpsOut(d.Kept)}, nil
		},
		"minimize": func(a []any) (any, error) {
			return stoOpsOut(StoreMinimize(stoOps(vecArg(a, 0)), stoBudget(a, 1))), nil
		},
		"deletion": func(a []any) (any, error) {
			ops := stoOps(vecArg(a, 0))
			i, _ := jsNum(vecArg(a, 1))
			return stoOpsOut(StoreDeletion(ops, ops[int(i)])), nil
		},
		"checkKey": func(a []any) (any, error) {
			return stoKeyOut(StoreCheckKey(stoOps(vecArg(a, 0)), stoOptions(vecArg(a, 1)))), nil
		},
		"checkHistory": func(a []any) (any, error) {
			r := StoreCheckHistory(stoOps(vecArg(a, 0)), stoOptions(vecArg(a, 1)))
			viol, unres := []any{}, []any{}
			for _, v := range r.Violations {
				viol = append(viol, stoKeyOut(v))
			}
			for _, v := range r.Unresolved {
				unres = append(unres, stoKeyOut(v))
			}
			return map[string]any{"ops": r.Ops, "keys": r.Keys, "ok": r.OK, "outcomes": map[string]any{"true": r.Outcomes["true"], "false": r.Outcomes["false"], "unknown": r.Outcomes["unknown"]},
				"violations": viol, "unresolved": unres}, nil
		},
		"inventory": func(a []any) (any, error) { s, _ := vecArg(a, 0).(string); return stoInventory(s), nil },
		"formatOps": func(a []any) (any, error) { return StoreFormatOps(stoOps(vecArg(a, 0))), nil },
		"parseHistory": func(a []any) (any, error) {
			text, _ := vecArg(a, 0).(string)
			ops, torn, pending := StoreParseHistory(text)
			return map[string]any{"ops": stoOpsOut(ops), "torn": torn, "pending": pending}, nil
		},
		"prng": func(a []any) (any, error) {
			seed, _ := jsNum(vecArg(a, 0))
			rand := StorePrng(uint32(int64(math.Mod(math.Trunc(seed), 4294967296)))) // ToUint32
			out := []any{}
			for _, n := range vecArg(a, 1).([]any) {
				f, _ := jsNum(n)
				out = append(out, rand(f))
			}
			return out, nil
		},
		"overall": func(a []any) (any, error) {
			if statuses, ok := vecArg(a, 0).([]any); ok { // a bare list of statuses
				var tests []StoreTestReport
				for _, st := range statuses {
					s, _ := st.(string)
					tests = append(tests, StoreTestReport{Status: s})
				}
				return StoreOverall(tests), nil
			}
			return StoreOverall(report(vecArg(a, 0)).Tests), nil
		},
		"formatReport": func(a []any) (any, error) {
			maxKeys := 3
			if f, ok := jsNum(vecArg(a, 1)); ok {
				maxKeys = int(f)
			}
			return StoreFormatReport(report(vecArg(a, 0)), maxKeys), nil
		},
		"reportJson": func(a []any) (any, error) { return StoreReportJSON(report(vecArg(a, 0))), nil },
	})
}
