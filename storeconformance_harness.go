package pca

// The harness side of the store conformance kit: recording a concurrent history (in memory, or to an append-only file that
// survives the death of the process that wrote it), reading such a file back, the deterministic generator the workloads draw from,
// and the report of a run as text and as JSON.

import (
	"encoding/json"
	"math"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// StoreClock is the recorder's clock in milliseconds (wall clock with sub-millisecond resolution).
func StoreClock() float64 { return float64(time.Now().UnixNano()) / 1e6 }

// StoreRecorder records the invocation and the completion of every operation of a workload.
type StoreRecorder interface {
	// Invoke records that client is about to call the store and returns the operation to complete.
	Invoke(client, kind, key string, lo, w float64) *StoreOp
	// Complete records the answer: "true", "false", or "unknown" (the call failed or timed out, so it may or may not have
	// taken effect).
	Complete(op *StoreOp, result string)
}

func storeNewOp(client, kind, key string, lo, w float64) *StoreOp {
	return &StoreOp{Client: client, Kind: kind, Key: key, Lo: lo, W: w, Call: StoreClock(), Ret: math.Inf(1), Res: "unknown"}
}

// StoreMemoryRecorder keeps the history in memory. It is safe for concurrent use.
type StoreMemoryRecorder struct {
	mu  sync.Mutex
	ops []*StoreOp
}

// Invoke implements StoreRecorder.
func (r *StoreMemoryRecorder) Invoke(client, kind, key string, lo, w float64) *StoreOp {
	r.mu.Lock()
	defer r.mu.Unlock()
	op := storeNewOp(client, kind, key, lo, w)
	r.ops = append(r.ops, op)
	return op
}

// Complete implements StoreRecorder: an unknown answer leaves the operation open.
func (r *StoreMemoryRecorder) Complete(op *StoreOp, result string) {
	if result != "true" && result != "false" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	op.Ret, op.Res = StoreClock(), result
}

// Ops returns the recorded operations in invocation order.
func (r *StoreMemoryRecorder) Ops() []*StoreOp {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]*StoreOp(nil), r.ops...)
}

// StoreFileRecorder appends every invocation and completion as one JSON line to a file, so the history of a process that is
// killed mid-call is still readable (StoreParseHistory): the crash test runs the store in child processes. It is safe for
// concurrent use.
type StoreFileRecorder struct {
	mu   sync.Mutex
	f    *os.File
	proc string
	seq  int
	ids  map[*StoreOp]int
}

// NewStoreFileRecorder opens path for appending; proc names this process in the file.
func NewStoreFileRecorder(path, proc string) (*StoreFileRecorder, error) {
	f, err := CreateOwnerOnly(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY)
	if err != nil {
		return nil, err
	}
	return &StoreFileRecorder{f: f, proc: proc, ids: map[*StoreOp]int{}}, nil
}

func (r *StoreFileRecorder) line(v []any) {
	b, err := json.Marshal(v)
	if err == nil {
		_, _ = r.f.Write(append(b, '\n')) // one write per line: a torn line is counted, never mistaken for an operation
	}
}

// Invoke implements StoreRecorder.
func (r *StoreFileRecorder) Invoke(client, kind, key string, lo, w float64) *StoreOp {
	r.mu.Lock()
	defer r.mu.Unlock()
	op := storeNewOp(client, kind, key, lo, w)
	r.seq++
	r.ids[op] = r.seq
	r.line([]any{"i", r.proc, r.seq, op.Call, client, kind, key, lo, w})
	return op
}

// Complete implements StoreRecorder.
func (r *StoreFileRecorder) Complete(op *StoreOp, result string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if result != "true" && result != "false" {
		result = "unknown"
	}
	r.line([]any{"r", r.proc, r.ids[op], StoreClock(), result})
	delete(r.ids, op)
}

// Close closes the file.
func (r *StoreFileRecorder) Close() error { return r.f.Close() }

// storeJSString is String(value) of a decoded JSON value.
func storeJSString(v any) string {
	switch t := v.(type) {
	case nil:
		return "null"
	case string:
		return t
	case bool:
		if t {
			return "true"
		}
		return "false"
	case map[string]any:
		return "[object Object]"
	case []any:
		parts := make([]string, len(t))
		for i, x := range t {
			if x != nil {
				parts[i] = storeJSString(x)
			}
		}
		return strings.Join(parts, ",")
	}
	if f, ok := jsNum(v); ok {
		return rsNumStr(f)
	}
	return ""
}

// storeJSNumber is Number(value) of a decoded JSON value.
func storeJSNumber(v any) float64 {
	switch t := v.(type) {
	case nil:
		return 0
	case bool:
		if t {
			return 1
		}
		return 0
	case string:
		s := strings.TrimSpace(t)
		if s == "" {
			return 0
		}
		if f, ok := parseJSNumberLexeme(s); ok {
			return f
		}
		return math.NaN()
	}
	if f, ok := jsNum(v); ok {
		return f
	}
	return math.NaN()
}

// StoreParseHistory reads a history file written by StoreFileRecorder (several processes may have appended to it). It returns the
// operations in invocation order, the number of torn or unusable lines (a process died while writing, or a completion without its
// invocation) and the number of invocations that never completed: those stay open with an unknown answer, as does one whose
// recorded answer is unknown.
func StoreParseHistory(text string) (ops []*StoreOp, torn, pending int) {
	open := map[string]*StoreOp{}
	ops = []*StoreOp{}
	for _, line := range strings.Split(text, "\n") {
		if line == "" {
			continue
		}
		v, err := ParseJSONLenient([]byte(line))
		e, isList := v.([]any)
		if err != nil || !isList {
			torn++
			continue
		}
		id := ""
		if len(e) > 2 {
			id = storeJSString(e[1]) + "/" + storeJSString(e[2])
		}
		switch {
		case len(e) == 9 && e[0] == any("i"):
			kind, _ := e[5].(string)
			op := &StoreOp{Client: storeJSString(e[4]), Kind: kind, Key: storeJSString(e[6]), Lo: storeJSNumber(e[7]), W: storeJSNumber(e[8]),
				Call: storeJSNumber(e[3]), Ret: math.Inf(1), Res: "unknown"}
			open[id] = op
			ops = append(ops, op)
		case len(e) == 5 && e[0] == any("r") && open[id] != nil:
			op := open[id]
			delete(open, id)
			if e[4] != any("unknown") {
				op.Ret, op.Res = storeJSNumber(e[3]), "false"
				if e[4] == any("true") {
					op.Res = "true"
				}
			}
		default:
			torn++
		}
	}
	return ops, torn, len(open)
}

// StoreFormatOps renders one line per operation, ordered by invocation, with times relative to the first invocation.
func StoreFormatOps(ops []*StoreOp) []string {
	base := math.Inf(1)
	for _, o := range ops {
		base = math.Min(base, o.Call)
	}
	sorted := append([]*StoreOp(nil), ops...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Call < sorted[j].Call })
	at := func(t float64) string {
		if math.IsInf(t, 1) {
			return "open"
		}
		return "+" + rsToFixed(t-base, 3) + "ms"
	}
	out := make([]string, len(sorted))
	for i, o := range sorted {
		what := "advance(" + rsNumStr(o.Lo) + ")"
		if o.Kind == "consume" {
			what = "consumeOnce(now=" + rsNumStr(o.Lo) + ", retainUntil=" + rsNumStr(o.W) + ")"
		}
		res := "unknown"
		switch o.Res {
		case "true":
			res = "TRUE"
		case "false":
			res = "false"
		}
		out[i] = o.Client + ": " + what + " [" + at(o.Call) + " .. " + at(o.Ret) + "] -> " + res
	}
	return out
}

// StorePrng is the deterministic generator of the workloads (mulberry32): the returned function gives an integer in [0, n).
func StorePrng(seed uint32) func(n float64) float64 {
	a := seed
	return func(n float64) float64 {
		a += 0x6d2b79f5
		t := a
		t = (t ^ (t >> 15)) * (t | 1)
		t ^= t + (t^(t>>7))*(t|61)
		return math.Floor(float64(t^(t>>14)) / 4294967296 * n)
	}
}

// StoreTestReport is the outcome of one test of a conformance run for one operation kind: Status is pass, fail, unresolved or
// skip.
type StoreTestReport struct {
	Test, Kind, Status string
	Ops, Keys, Errors  int
	Violations         []StoreKeyResult
	Unresolved         int
	Note               string
}

// StoreSuiteReport is the outcome of a conformance run of one adapter.
type StoreSuiteReport struct {
	Adapter, Status string
	Tests           []StoreTestReport
}

// StoreOverall is the status of a run: fail if any test failed, else unresolved if any is unresolved, else pass.
func StoreOverall(tests []StoreTestReport) string {
	status := "pass"
	for _, t := range tests {
		if t.Status == "fail" {
			return "fail"
		}
		if t.Status == "unresolved" {
			status = "unresolved"
		}
	}
	return status
}

var storeOpNames = map[string]string{"consume": "consumeOnce", "advance": "advance"}

func storeItoa(n int) string { return rsNumStr(float64(n)) }

// StoreFormatReport renders a run as text, with the counterexample of at most maxKeys violating keys per test.
func StoreFormatReport(r StoreSuiteReport, maxKeys int) string {
	out := []string{"pca-store-conformance: " + r.Adapter + " -> " + strings.ToUpper(r.Status)}
	for _, t := range r.Tests {
		name := t.Test + "/" + storeOpNames[t.Kind]
		if _, known := storeOpNames[t.Kind]; !known {
			name = t.Test + "/undefined"
		}
		for len(name) < 24 {
			name += " "
		}
		var parts, extra []string
		if t.Status != "skip" {
			parts = append(parts, storeItoa(t.Ops)+" ops, "+storeItoa(t.Keys)+" keys, "+storeItoa(t.Errors)+" errors/timeouts")
		}
		if len(t.Violations) > 0 {
			extra = append(extra, storeItoa(len(t.Violations))+" NON-LINEARIZABLE key(s)")
		}
		if t.Unresolved != 0 {
			extra = append(extra, storeItoa(t.Unresolved)+" unresolved key(s) (over the search budget)")
		}
		if t.Note != "" {
			extra = append(extra, t.Note)
		}
		if len(extra) > 0 {
			parts = append(parts, strings.Join(extra, "; "))
		}
		out = append(out, "  ["+strings.ToUpper(t.Status)+"] "+name+" "+strings.Join(parts, "; "))
		for i, v := range t.Violations {
			if i >= maxKeys {
				break
			}
			how := "violating history (not shrunk)"
			if v.Minimized {
				how = "minimal counterexample"
			}
			out = append(out, "      key "+v.Key+" ("+storeItoa(v.Ops)+" ops, decided by "+v.Method+"): "+how+":")
			for _, line := range StoreFormatOps(v.Counterexample) {
				out = append(out, "        "+line)
			}
		}
	}
	return strings.Join(out, "\n")
}

// storeKV is one member of an ordered JSON object.
type storeKV struct {
	k string
	v any
}

func storeWriteJSON(b *strings.Builder, v any, indent string) {
	switch t := v.(type) {
	case []storeKV:
		if len(t) == 0 {
			b.WriteString("{}")
			return
		}
		b.WriteString("{\n")
		for i, kv := range t {
			b.WriteString(indent + "  " + bsQuote(kv.k) + ": ")
			storeWriteJSON(b, kv.v, indent+"  ")
			if i < len(t)-1 {
				b.WriteString(",")
			}
			b.WriteString("\n")
		}
		b.WriteString(indent + "}")
	case []any:
		if len(t) == 0 {
			b.WriteString("[]")
			return
		}
		b.WriteString("[\n")
		for i, x := range t {
			b.WriteString(indent + "  ")
			storeWriteJSON(b, x, indent+"  ")
			if i < len(t)-1 {
				b.WriteString(",")
			}
			b.WriteString("\n")
		}
		b.WriteString(indent + "]")
	case string:
		b.WriteString(bsQuote(t))
	case bool:
		if t {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case int:
		b.WriteString(storeItoa(t))
	case float64:
		if math.IsNaN(t) || math.IsInf(t, 0) {
			b.WriteString("null") // an open operation's return time
		} else {
			b.WriteString(rsNumStr(t))
		}
	default:
		b.WriteString("null")
	}
}

// StoreReportJSON is the run as JSON with two-space indentation and the reference's member order (an open operation's return
// time is null).
func StoreReportJSON(r StoreSuiteReport) string {
	tests := make([]any, len(r.Tests))
	for i, t := range r.Tests {
		viol := make([]any, len(t.Violations))
		for j, v := range t.Violations {
			kv := []storeKV{{"key", v.Key}, {"kind", v.Kind}, {"ops", v.Ops}, {"searched", v.Searched}, {"verdict", v.Verdict}, {"method", v.Method}}
			if v.Counterexample != nil {
				ce := make([]any, len(v.Counterexample))
				for k, o := range v.Counterexample {
					ce[k] = []storeKV{{"client", o.Client}, {"kind", o.Kind}, {"key", o.Key}, {"lo", o.Lo}, {"w", o.W}, {"call", o.Call}, {"ret", o.Ret}, {"res", o.Res}}
				}
				kv = append(kv, storeKV{"counterexample", ce}, storeKV{"minimized", v.Minimized})
			}
			viol[j] = kv
		}
		kv := []storeKV{{"test", t.Test}, {"kind", t.Kind}, {"status", t.Status}, {"ops", t.Ops}, {"keys", t.Keys}, {"errors", t.Errors},
			{"violations", viol}, {"unresolved", t.Unresolved}}
		if t.Note != "" {
			kv = append(kv, storeKV{"note", t.Note})
		}
		tests[i] = kv
	}
	var b strings.Builder
	storeWriteJSON(&b, []storeKV{{"adapter", r.Adapter}, {"status", r.Status}, {"tests", tests}}, "")
	return b.String()
}
