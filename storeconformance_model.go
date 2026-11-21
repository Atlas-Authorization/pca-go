package pca

// The pure logic of the store conformance kit: the sequential register specification both store operations share, the verdict
// preserving reductions, the budgeted linearizability search, the per-key checker with minimal counterexamples.
//
// ONE MODEL FOR BOTH OPERATIONS. An operation is a StoreOp: Kind is "consume" or "advance"; each carries a threshold Lo and a write
// value W (consume: Lo = now, W = retainUntil; advance: Lo = W = the counter); Call and Ret bound the interval (Ret is +Inf when the
// outcome is unknown); Res is "true", "false" or "unknown". The register starts at -Inf. A TRUE answer is legal iff s < Lo and then
// s = max(s, W); a FALSE answer is legal iff s >= Lo and leaves s; an UNKNOWN outcome may or may not have taken effect. Operation
// identity matters (StoreDeletion removes the very pointer it is given).
//
// A PASS is evidence, not proof; a violation is a recorded history no sequential order explains.

import (
	"fmt"
	"math"
	"sort"
)

// DefaultStoreSearchBudget bounds the states the linearizability search visits per key.
const DefaultStoreSearchBudget = 200_000

// StoreOp is one recorded operation of a history.
type StoreOp struct {
	Client, Kind, Key string
	Lo, W, Call, Ret  float64
	Res               string
}

// StoreRegisterStep is the register's successor states after op from s (empty: the answer is impossible from s).
func StoreRegisterStep(s float64, op *StoreOp) []float64 {
	fresh := s < op.Lo
	switch op.Res {
	case "true":
		if fresh {
			return []float64{math.Max(s, op.W)}
		}
		return nil
	case "false":
		if fresh {
			return nil
		}
		return []float64{s}
	}
	if fresh {
		return []float64{s, math.Max(s, op.W)}
	}
	return []float64{s}
}

func storeTrues(ops []*StoreOp, less func(a, b *StoreOp) bool) []*StoreOp {
	var ts []*StoreOp
	for _, o := range ops {
		if o.Res == "true" {
			ts = append(ts, o)
		}
	}
	sort.SliceStable(ts, func(i, j int) bool { return less(ts[i], ts[j]) })
	return ts
}

// StoreOverlappingTrues: two definite TRUE answers whose [Lo, W] intervals overlap can never both linearize. It returns the minimal
// counterexample, or nil.
func StoreOverlappingTrues(ops []*StoreOp) []*StoreOp {
	ts := storeTrues(ops, func(a, b *StoreOp) bool { return a.Lo < b.Lo })
	for i := 1; i < len(ts); i++ {
		if ts[i-1].W >= ts[i].Lo {
			return []*StoreOp{ts[i-1], ts[i]}
		}
	}
	return nil
}

// StorePrune drops every definite FALSE that a definite TRUE explains (a TRUE with W >= Lo that returned before the FALSE was invoked).
func StorePrune(ops []*StoreOp) []*StoreOp {
	ts := storeTrues(ops, func(a, b *StoreOp) bool { return a.Ret < b.Ret })
	pm := make([]float64, 0, len(ts))
	for _, t := range ts {
		p := t.W
		if len(pm) > 0 && pm[len(pm)-1] > p {
			p = pm[len(pm)-1]
		}
		pm = append(pm, p)
	}
	out := []*StoreOp{}
	for _, o := range ops {
		if o.Res != "false" {
			out = append(out, o)
			continue
		}
		n := 0
		for n < len(ts) && ts[n].Ret < o.Call {
			n++
		}
		if !(n > 0 && pm[n-1] >= o.Lo) {
			out = append(out, o)
		}
	}
	return out
}

// StoreFastCheck is the EXACT decision for a history with no unknown operation, in O(n log n); known is false when one is unknown.
func StoreFastCheck(ops []*StoreOp) (ok, known bool) {
	for _, o := range ops {
		if o.Res == "unknown" {
			return false, false
		}
	}
	ts := storeTrues(ops, func(a, b *StoreOp) bool { return a.Lo < b.Lo })
	t := make([]float64, 0, len(ts))
	prev := math.Inf(-1)
	for i, o := range ts {
		if i > 0 && ts[i-1].W >= o.Lo {
			return false, true
		}
		ti := math.Max(o.Call, prev)
		if ti > o.Ret {
			return false, true
		}
		t = append(t, ti)
		prev = ti
	}
	for _, f := range ops {
		if f.Res != "false" {
			continue
		}
		j := -1
		for k, x := range ts {
			if x.W >= f.Lo {
				j = k
				break
			}
		}
		if j < 0 || t[j] > f.Ret {
			return false, true
		}
	}
	return true, true
}

type storeSearchState struct {
	done []uint64
	s    float64
}

func (st storeSearchState) key() string { return fmt.Sprintf("%v|%v", st.done, st.s) }

// StoreSearchLinearizable is the Wing-Gong / Lowe search for ONE key's history: "ok", "violation" or "unresolved" (a key over the
// budget is never a pass). A budget of 0 means DefaultStoreSearchBudget.
func StoreSearchLinearizable(ops []*StoreOp, budget int) string {
	if budget == 0 {
		budget = DefaultStoreSearchBudget
	}
	order := append([]*StoreOp(nil), ops...)
	sort.SliceStable(order, func(i, j int) bool { return order[i].Call < order[j].Call })
	n := len(order)
	words := (n + 63) / 64
	isDone := func(d []uint64, i int) bool { return d[i/64]&(1<<(uint(i)%64)) != 0 }
	full := func(d []uint64) bool {
		for i := 0; i < n; i++ {
			if !isDone(d, i) {
				return false
			}
		}
		return true
	}
	seen := map[string]bool{}
	stack := []storeSearchState{{make([]uint64, words), math.Inf(-1)}}
	for len(stack) > 0 {
		st := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if full(st.done) {
			return "ok"
		}
		id := st.key()
		if seen[id] {
			continue
		}
		if len(seen) >= budget {
			return "unresolved"
		}
		seen[id] = true
		minRet := math.Inf(1)
		for i := 0; i < n; i++ {
			if !isDone(st.done, i) && order[i].Ret < minRet {
				minRet = order[i].Ret
			}
		}
		// sorted by invocation: once one starts after the earliest pending return, all later ones do too
		for i := 0; i < n && order[i].Call <= minRet; i++ {
			if isDone(st.done, i) {
				continue
			}
			for _, s2 := range StoreRegisterStep(st.s, order[i]) {
				nd := append([]uint64(nil), st.done...)
				nd[i/64] |= 1 << (uint(i) % 64)
				stack = append(stack, storeSearchState{nd, s2})
			}
		}
	}
	return "violation"
}

// StoreKeyDecision is the verdict of one key: Verdict ("ok", "violation", "unresolved"), Method ("overlap", "exact", "search") and the
// operations kept after pruning.
type StoreKeyDecision struct {
	Verdict, Method string
	Kept            []*StoreOp
}

// StoreDecideKey decides one key's history: overlap, then prune, then the exact check, then the budgeted search.
func StoreDecideKey(ops []*StoreOp, budget int) StoreKeyDecision {
	if StoreOverlappingTrues(ops) != nil {
		return StoreKeyDecision{"violation", "overlap", append([]*StoreOp(nil), ops...)}
	}
	kept := StorePrune(ops)
	if ok, known := StoreFastCheck(kept); known {
		v := "violation"
		if ok {
			v = "ok"
		}
		return StoreKeyDecision{v, "exact", kept}
	}
	return StoreKeyDecision{StoreSearchLinearizable(kept, budget), "search", kept}
}

// StoreDeletion is the SOUND deletion step for op: deleting a FALSE never helps it; deleting a writer also removes the FALSEs it may
// have explained.
func StoreDeletion(ops []*StoreOp, op *StoreOp) []*StoreOp {
	out := []*StoreOp{}
	for _, o := range ops {
		if o == op || (op.Res != "false" && o.Res == "false" && o.Lo <= op.W) {
			continue
		}
		out = append(out, o)
	}
	return out
}

// StoreMinimize is greedy sound deletion to a 1-minimal violating history.
func StoreMinimize(ops []*StoreOp, budget int) []*StoreOp {
	cur := append([]*StoreOp(nil), ops...)
	for changed := true; changed; {
		changed = false
		for _, op := range cur {
			nxt := StoreDeletion(cur, op)
			if StoreDecideKey(nxt, budget).Verdict == "violation" {
				cur, changed = nxt, true
				break
			}
		}
	}
	return cur
}

// StoreCheckOptions are the options of StoreCheckKey and StoreCheckHistory: Budget (0: the default), NoMinimize and MinimizeLimit
// (0: 200).
type StoreCheckOptions struct {
	Budget        int
	NoMinimize    bool
	MinimizeLimit int
}

// StoreKeyResult is the check of one key; the counterexample is set only for a violation.
type StoreKeyResult struct {
	Key, Kind       string
	Ops, Searched   int
	Verdict, Method string
	Counterexample  []*StoreOp
	Minimized       bool
}

// StoreCheckKey checks one key's history (all operations share Kind and Key).
func StoreCheckKey(ops []*StoreOp, o StoreCheckOptions) StoreKeyResult {
	budget := o.Budget
	if budget == 0 {
		budget = DefaultStoreSearchBudget
	}
	d := StoreDecideKey(ops, budget)
	r := StoreKeyResult{Key: ops[0].Key, Kind: ops[0].Kind, Ops: len(ops), Searched: len(d.Kept), Verdict: d.Verdict, Method: d.Method}
	if d.Verdict != "violation" {
		return r
	}
	limit := o.MinimizeLimit
	if limit == 0 {
		limit = 200
	}
	if pair := StoreOverlappingTrues(ops); pair != nil {
		sort.SliceStable(pair, func(i, j int) bool { return pair[i].Call < pair[j].Call })
		r.Counterexample, r.Minimized = pair, true
	} else if !o.NoMinimize && len(d.Kept) <= limit {
		r.Counterexample, r.Minimized = StoreMinimize(d.Kept, budget), true
	} else {
		r.Counterexample = d.Kept
	}
	return r
}

// StoreHistoryReport is the check of a whole history.
type StoreHistoryReport struct {
	Ops, Keys  int
	OK         bool
	Outcomes   map[string]int
	Violations []StoreKeyResult
	Unresolved []StoreKeyResult
}

// StoreCheckHistory splits a history by (kind, key) and checks every key (P-compositionality).
func StoreCheckHistory(ops []*StoreOp, o StoreCheckOptions) StoreHistoryReport {
	byKey := map[[2]string][]*StoreOp{}
	var order [][2]string
	out := map[string]int{"true": 0, "false": 0, "unknown": 0}
	for _, op := range ops {
		out[op.Res]++
		k := [2]string{op.Kind, op.Key}
		if _, has := byKey[k]; !has {
			order = append(order, k)
		}
		byKey[k] = append(byKey[k], op)
	}
	rep := StoreHistoryReport{Ops: len(ops), Keys: len(byKey), Outcomes: out, Violations: []StoreKeyResult{}, Unresolved: []StoreKeyResult{}}
	for _, k := range order {
		switch r := StoreCheckKey(byKey[k], o); r.Verdict {
		case "violation":
			rep.Violations = append(rep.Violations, r)
		case "unresolved":
			rep.Unresolved = append(rep.Unresolved, r)
		}
	}
	rep.OK = len(rep.Violations) == 0 && len(rep.Unresolved) == 0
	return rep
}
