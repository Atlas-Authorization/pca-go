// Package pcawasm is the in-process WebAssembly host of the PCA sandbox handle table (opt-in module: it needs cgo and wasmtime-go, so
// the core pca package carries neither). RunCoreModule runs a core module under wasmtime with an instruction budget (fuel), a
// wall-clock deadline (epoch interruption), a hard linear-memory cap and no ambient authority: no WASI is configured or linked, the
// only imports are pca:act.{invoke,handle_count,handle_verb}, and every use is decided by the HandleTable.
package pcawasm

import (
	"errors"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/bytecodealliance/wasmtime-go/v50"

	pca "github.com/Atlas-Authorization/pca-go"
)

// CoreOptions configures RunCoreModule. Fuel is required (positive): a budget is a decision. Zero values take the defaults.
type CoreOptions struct {
	Fuel           int64
	TimeoutMs      int // 5000
	MaxModuleBytes int // 1 MiB
	MaxMemoryPages int // 256
	MaxResultBytes int // 1 MiB
}

func pick(v, def int) int {
	if v <= 0 {
		return def
	}
	return v
}

func fail(reason string) pca.SandboxRunResult { return pca.SandboxRunFail(reason) }

// RunCoreModule runs the `entry` export of wasm (default "run"). It refuses to run, failing closed, when the engine cannot enforce
// fuel. Runtime memory.grow past the cap makes the guest see -1 (wasmtime's store limiter) instead of a trap; the declared-maximum
// check catches the static cases, so the cap holds either way.
func RunCoreModule(table *pca.HandleTable, wasm []byte, entry string, o CoreOptions) pca.SandboxRunResult {
	if entry == "" {
		entry = "run"
	}
	if pca.SandboxBadFuel(o.Fuel) {
		return fail("bad_fuel")
	}
	maxModule, maxPages, maxResult := pick(o.MaxModuleBytes, 1<<20), pick(o.MaxMemoryPages, 256), pick(o.MaxResultBytes, 1<<20)
	if len(wasm) == 0 || len(wasm) > maxModule {
		return fail("module_size")
	}
	mem, ok := pca.SandboxMemoryLimits(wasm)
	if !ok {
		return fail("malformed_module")
	}
	if mem != nil && (mem.Count > 1 || !mem.HasMax || mem.Shared || mem.Min > int64(maxPages) || mem.Max > int64(maxPages)) {
		return fail("memory_limits")
	}

	cfg := wasmtime.NewConfig()
	cfg.SetConsumeFuel(true)
	cfg.SetEpochInterruption(true)
	engine := wasmtime.NewEngineWithConfig(cfg)
	defer engine.Close()
	module, err := wasmtime.NewModule(engine, wasm)
	if err != nil {
		return fail("malformed_module")
	}
	defer module.Close()
	for _, imp := range module.Imports() {
		name := ""
		if n := imp.Name(); n != nil {
			name = *n
		}
		allowed := false
		for _, a := range pca.SandboxAllowedImports {
			allowed = allowed || a == name
		}
		if imp.Module() != pca.SandboxImportModule || imp.Type().FuncType() == nil || !allowed {
			return fail("ambient_import:" + imp.Module() + "." + name)
		}
	}

	store := wasmtime.NewStore(engine)
	defer store.Close()
	store.Limiter(int64(maxPages)*65536, -1, 1, -1, 1) // memory bytes, table elements, instances, tables, memories
	if store.SetFuel(uint64(o.Fuel)) != nil {
		return fail("limit_unenforceable:fuel")
	}
	store.SetEpochDeadline(1)

	// window is the guest memory range [ptr, ptr+n) in unsigned 32-bit math (no wrap), or nil. Valid only until the callback returns.
	window := func(c *wasmtime.Caller, ptr, n int32) []byte {
		ext := c.GetExport("memory")
		if ext == nil || ext.Memory() == nil {
			return nil
		}
		data := ext.Memory().UnsafeData(c)
		p, l := uint64(uint32(ptr)), uint64(uint32(n))
		if p+l > uint64(len(data)) {
			return nil
		}
		return data[p : p+l]
	}
	i32 := func() *wasmtime.ValType { return wasmtime.NewValType(wasmtime.KindI32) }
	ret := func(v int) ([]wasmtime.Val, *wasmtime.Trap) { return []wasmtime.Val{wasmtime.ValI32(int32(v))}, nil }
	code := func(reason string) int { return pca.SandboxUseErr[reason] }

	linker := wasmtime.NewLinker(engine) // no WASI: the guest has no ambient authority
	defer linker.Close()
	define := func(name string, params int, f func(*wasmtime.Caller, []wasmtime.Val) ([]wasmtime.Val, *wasmtime.Trap)) {
		ps := make([]*wasmtime.ValType, params)
		for i := range ps {
			ps[i] = i32()
		}
		if err == nil {
			err = linker.FuncNew(pca.SandboxImportModule, name, wasmtime.NewFuncType(ps, []*wasmtime.ValType{i32()}), f)
		}
	}
	define("handle_count", 0, func(*wasmtime.Caller, []wasmtime.Val) ([]wasmtime.Val, *wasmtime.Trap) { return ret(table.Size()) })
	define("handle_verb", 3, func(c *wasmtime.Caller, a []wasmtime.Val) ([]wasmtime.Val, *wasmtime.Trap) {
		verb, known := table.VerbOf(int(a[0].I32()))
		if !known {
			return ret(code("unknown_handle"))
		}
		win := window(c, a[1].I32(), a[2].I32())
		switch {
		case win == nil:
			return ret(code("bad_memory"))
		case len(verb) > len(win):
			return ret(code("out_too_small"))
		}
		copy(win, verb)
		return ret(len(verb))
	})
	define("invoke", 3, func(c *wasmtime.Caller, a []wasmtime.Val) ([]wasmtime.Val, *wasmtime.Trap) {
		if window(c, a[1].I32(), a[2].I32()) == nil { // validate the output window before a use is spent
			return ret(code("bad_memory"))
		}
		r, uerr := table.Use(int(a[0].I32()))
		if uerr != nil {
			return nil, wasmtime.NewTrap("receipt log: " + uerr.Error())
		}
		if r["ok"] != true {
			return ret(code(r["reason"].(string)))
		}
		res, _ := r["result"].([]byte)
		win := window(c, a[1].I32(), a[2].I32())
		if len(res) > maxResult || len(res) > len(win) {
			return ret(code("out_too_small"))
		}
		copy(win, res)
		return ret(len(res))
	})
	if err != nil {
		return fail("trap:LinkError")
	}

	var mu sync.Mutex
	closed := false
	timer := time.AfterFunc(time.Duration(pick(o.TimeoutMs, 5000))*time.Millisecond, func() {
		mu.Lock()
		defer mu.Unlock()
		if !closed {
			engine.IncrementEpoch()
		}
	})
	defer func() { timer.Stop(); mu.Lock(); closed = true; mu.Unlock() }() // runs before engine.Close

	inst, err := linker.Instantiate(store, module)
	if err != nil {
		return classify(err, true)
	}
	fn := inst.GetFunc(store, entry)
	if fn == nil {
		return fail("no_entry")
	}
	v, err := fn.Call(store)
	runtime.KeepAlive(inst)
	if err != nil {
		return classify(err, false)
	}
	switch n := v.(type) {
	case int32:
		return pca.SandboxRunResult{OK: true, Value: int64(n)}
	case int64:
		return pca.SandboxRunResult{OK: true, Value: n}
	case float32:
		return pca.SandboxRunResult{OK: true, Value: int64(n)}
	case float64:
		return pca.SandboxRunResult{OK: true, Value: int64(n)}
	}
	return pca.SandboxRunResult{OK: true}
}

func classify(err error, instantiating bool) pca.SandboxRunResult {
	var tr *wasmtime.Trap
	if errors.As(err, &tr) {
		if c := tr.Code(); c != nil {
			switch *c {
			case wasmtime.OutOfFuel:
				return fail("fuel_exhausted")
			case wasmtime.Interrupt:
				return fail("timeout")
			}
		}
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "all fuel consumed"), strings.Contains(msg, "out of fuel"):
		return fail("fuel_exhausted")
	case strings.Contains(msg, "interrupt"):
		return fail("timeout")
	case strings.Contains(msg, "memory") && (strings.Contains(msg, "minimum") || strings.Contains(msg, "limit") || strings.Contains(msg, "exceed")):
		return fail("memory_limits")
	case instantiating && tr == nil:
		return fail("trap:LinkError")
	}
	return fail("trap:RuntimeError")
}
