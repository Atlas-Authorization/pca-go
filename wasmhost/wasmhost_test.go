package pcawasm

import (
	"errors"
	"testing"
	"time"

	pca "github.com/Atlas-Authorization/pca-go"
)

const fuel = 1_000_000

func mintOp(t *testing.T, table *pca.HandleTable, verb, url string) {
	t.Helper()
	params := map[string]any{"url": url}
	d, err := pca.HashCanonical(params)
	if err != nil {
		t.Fatal(err)
	}
	op := map[string]any{"verb": verb, "resource": "r", "params": params}
	res := map[string]any{"allow": true, "operation": map[string]any{"verb": verb, "resource": "r", "params_digest": d, "id": "op1"}}
	if _, err := table.Mint(res, op, map[string]any{"uses": 5}); err != nil {
		t.Fatal(err)
	}
}

func newTable(t *testing.T, ex map[string]pca.HandleExecutor, verbs ...string) (*pca.HandleTable, *pca.SandboxReceiptLog) {
	t.Helper()
	log := pca.NewSandboxReceiptLog(func() float64 { return 0 }, nil)
	table := pca.NewHandleTable("wasi_no_ambient", log, ex, func() float64 { return 0 })
	if len(verbs) == 0 {
		verbs = []string{"fetch"}
	}
	for _, v := range verbs {
		mintOp(t, table, v, "https://example.com/a")
	}
	return table, log
}

func tool(extra map[string]any) []byte {
	spec := map[string]any{"calls": []any{map[string]any{"handle": 1, "ptr": 0, "cap": 16}}, "returns": "byte0"}
	for k, v := range extra {
		spec[k] = v
	}
	return pca.BuildTool(spec)
}

func call(handle, ptr, cap int) []byte {
	return pca.BuildTool(map[string]any{"calls": []any{map[string]any{"handle": handle, "ptr": ptr, "cap": cap}}})
}

func run(table *pca.HandleTable, w []byte, o CoreOptions) pca.SandboxRunResult {
	if o.Fuel == 0 {
		o.Fuel = fuel
	}
	return RunCoreModule(table, w, "run", o)
}

func want(t *testing.T, got pca.SandboxRunResult, ok bool, value int64, reason string) {
	t.Helper()
	if got.OK != ok || got.Value != value || got.Reason != reason {
		t.Fatalf("got %+v, want ok=%v value=%d reason=%q", got, ok, value, reason)
	}
}

func fixed(b ...byte) map[string]pca.HandleExecutor {
	return map[string]pca.HandleExecutor{"fetch": func(map[string]any) ([]byte, error) { return b, nil }}
}

func TestFuelIsRequired(t *testing.T) {
	table, _ := newTable(t, nil)
	for _, f := range []int64{0, -1, 1 << 53} {
		want(t, RunCoreModule(table, tool(nil), "run", CoreOptions{Fuel: f}), false, 0, "bad_fuel")
	}
}

func TestModuleSizeAndMalformed(t *testing.T) {
	table, _ := newTable(t, nil)
	want(t, run(table, nil, CoreOptions{}), false, 0, "module_size")
	want(t, run(table, tool(nil), CoreOptions{MaxModuleBytes: 10}), false, 0, "module_size")
	want(t, run(table, []byte("not wasm at all"), CoreOptions{}), false, 0, "malformed_module")
	want(t, run(table, []byte("\x00asm\x01\x00\x00\x00\x01\x09\x00"), CoreOptions{}), false, 0, "malformed_module") // section overruns the module
	want(t, run(table, []byte("\x00asm\x01\x00\x00\x00\x01\x01\xff"), CoreOptions{}), false, 0, "malformed_module") // the engine rejects it
}

func TestMemoryLimitsAreRefusedBeforeAnythingRuns(t *testing.T) {
	table, _ := newTable(t, nil)
	for _, m := range []map[string]any{{"min": 1, "max": nil}, {"min": 1, "max": 257}, {"min": 300, "max": 300}} {
		want(t, run(table, tool(map[string]any{"memory": m}), CoreOptions{}), false, 0, "memory_limits")
	}
	for _, flag := range []byte{3, 5} { // shared; memory64 and newer
		b := tool(nil)
		for i := range b {
			if b[i] == 5 && b[i+1] == 4 && b[i+2] == 1 && b[i+3] == 1 { // memory section: size 4, count 1, flag 1
				b[i+3] = flag
				break
			}
		}
		want(t, run(table, b, CoreOptions{}), false, 0, "memory_limits")
	}
}

func TestHappyPathWritesResultIntoMemoryAndLogsAReceipt(t *testing.T) {
	table, log := newTable(t, fixed(42, 1, 2, 3))
	want(t, run(table, tool(nil), CoreOptions{}), true, 42, "")
	if len(log.Entries) != 1 || log.Entries[0]["outcome"] != "ok" || log.Entries[0]["reason"] != "used" {
		t.Fatalf("receipts: %v", log.Entries)
	}
	entries := make([]any, len(log.Entries))
	for i, e := range log.Entries {
		entries[i] = e
	}
	if r, err := pca.VerifyReceiptChain(entries, nil); err != nil || r["ok"] != true {
		t.Fatalf("chain: %v %v", r, err)
	}
}

func TestProbeToolReadsHandleCountAndVerb(t *testing.T) {
	table, _ := newTable(t, nil, "fetch", "send")
	want(t, run(table, pca.BuildProbeTool(16), CoreOptions{}), true, 2*256+'f', "")
	want(t, run(table, pca.BuildProbeTool(3), CoreOptions{}), true, 2*256, "") // "fetch" > cap: -3 ignored, byte 0 of memory
}

func TestBadWindowSpendsNoUseAndSmallCapIsRefused(t *testing.T) {
	table, log := newTable(t, fixed('a', 'b', 'c', 'd'))
	want(t, run(table, call(1, 65530, 100), CoreOptions{}), true, -4, "")
	if len(log.Entries) != 0 {
		t.Fatal("a bad window must not spend a use")
	}
	want(t, run(table, call(1, 0, 2), CoreOptions{}), true, -3, "")
	want(t, run(table, call(9, 0, 8), CoreOptions{}), true, -1, "")   // unknown handle
	want(t, run(table, call(1, -8, 16), CoreOptions{}), true, -4, "") // ptr+len must not wrap in unsigned 32-bit math
}

func TestResultOverMaxResultBytesIsOutTooSmall(t *testing.T) {
	table, _ := newTable(t, fixed(make([]byte, 10)...))
	want(t, run(table, call(1, 0, 16), CoreOptions{MaxResultBytes: 4}), true, -3, "")
}

func TestNoEntry(t *testing.T) {
	table, _ := newTable(t, fixed(7))
	want(t, RunCoreModule(table, tool(nil), "missing", CoreOptions{Fuel: fuel}), false, 0, "no_entry")
	want(t, RunCoreModule(table, tool(nil), "memory", CoreOptions{Fuel: fuel}), false, 0, "no_entry") // exported, but a memory
}

func TestForbiddenImportsAreRefused(t *testing.T) {
	for _, e := range [][2]string{{"wasi_snapshot_preview1", "fd_write"}, {"env", "x"}, {"pca:act", "other"}} {
		table, log := newTable(t, fixed(1))
		got := run(table, tool(map[string]any{"extraImports": []any{map[string]any{"module": e[0], "name": e[1]}}}), CoreOptions{})
		want(t, got, false, 0, "ambient_import:"+e[0]+"."+e[1])
		if len(log.Entries) != 0 {
			t.Fatal("a refused module must not touch the table")
		}
	}
}

func TestInfiniteLoopStopsOnFuel(t *testing.T) {
	table, _ := newTable(t, fixed(1))
	want(t, run(table, tool(map[string]any{"spin": true}), CoreOptions{Fuel: 50_000}), false, 0, "fuel_exhausted")
}

func TestInfiniteLoopStopsOnTheWallClockEvenWithHugeFuel(t *testing.T) {
	table, _ := newTable(t, fixed(1))
	t0 := time.Now()
	want(t, run(table, tool(map[string]any{"spin": true}), CoreOptions{Fuel: 1 << 52, TimeoutMs: 200}), false, 0, "timeout")
	if time.Since(t0) > 10*time.Second {
		t.Fatal("the deadline did not stop the guest promptly")
	}
}

// growModule is `run: memory.grow(delta)` over one memory with min 1 and the given declared max.
func growModule(delta, max byte) []byte {
	return []byte{0, 0x61, 0x73, 0x6D, 1, 0, 0, 0, 1, 5, 1, 0x60, 0, 1, 0x7F, 3, 2, 1, 0, 5, 4, 1, 1, 1, max,
		7, 7, 1, 3, 'r', 'u', 'n', 0, 0, 10, 8, 1, 6, 0, 0x41, delta, 0x40, 0, 0x0B}
}

func TestRuntimeGrowthPastTheDeclaredMaximumIsStopped(t *testing.T) {
	table, _ := newTable(t, nil)
	want(t, run(table, growModule(1, 2), CoreOptions{}), true, 1, "")  // within the cap: the old size in pages
	want(t, run(table, growModule(5, 2), CoreOptions{}), true, -1, "") // past the max: memory.grow fails
	// a cap below the declared module is a static refusal, so growth can never be asked for past the cap
	want(t, run(table, growModule(1, 2), CoreOptions{MaxMemoryPages: 1}), false, 0, "memory_limits")
}

func TestEgressPolicyAdmitsInPolicyAndRefusesOutOfPolicy(t *testing.T) {
	policy := pca.NewEgressPolicy(func() float64 { return 0 })
	params := map[string]any{"url": "https://example.com/a"}
	d, _ := pca.HashCanonical(params)
	op := map[string]any{"verb": "fetch", "resource": "r", "params": params}
	res := map[string]any{"allow": true, "operation": map[string]any{"verb": "fetch", "resource": "r", "params_digest": d, "id": "o"}}
	tmpl := map[string]any{"method": "GET", "scheme": "https", "host": "example.com", "path": "/a"}
	if err := policy.Admit(res, op, func(any) any { return tmpl }, nil); err != nil {
		t.Fatal(err)
	}
	fetch := func(op map[string]any) ([]byte, error) {
		url := op["params"].(map[string]any)["url"].(string)
		if c := policy.Claim("GET", url, nil); c["allow"] != true {
			return nil, errors.New("egress denied: " + c["reason"].(string))
		}
		return []byte{0x2a}, nil
	}
	log := pca.NewSandboxReceiptLog(func() float64 { return 0 }, nil)
	table := pca.NewHandleTable("egress_default_deny", log, map[string]pca.HandleExecutor{"fetch": fetch}, func() float64 { return 0 })
	for _, url := range []string{"https://example.com/a", "https://evil.example/a"} {
		p := map[string]any{"url": url}
		pd, _ := pca.HashCanonical(p)
		o := map[string]any{"verb": "fetch", "resource": "r", "params": p}
		if _, err := table.Mint(map[string]any{"allow": true, "operation": map[string]any{"verb": "fetch", "resource": "r", "params_digest": pd, "id": "o"}}, o, nil); err != nil {
			t.Fatal(err)
		}
	}
	want(t, run(table, call(1, 0, 8), CoreOptions{}), true, 1, "")                                          // one byte written
	want(t, run(table, call(2, 0, 8), CoreOptions{}), true, int64(pca.SandboxUseErr["executor_error"]), "") // out of policy: -5
	if len(log.Entries) != 2 || log.Entries[0]["outcome"] != "ok" || log.Entries[1]["outcome"] != "error" {
		t.Fatalf("receipts: %v", log.Entries)
	}
}
