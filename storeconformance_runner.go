package pca

// The conformance run against a replay / counter store. Implement a StoreAdapter, then call RunStoreConformance: every test for every
// operation the adapter implements, each recorded history checked for linearizability. A PASS is evidence, not proof (the kit checks
// the histories it observed); a FAIL is a proof of a contract violation (the counterexample is a recorded history that no
// sequential order explains), unless the adapter itself is mis-wired.
//
// The contract under test is the one of the replay and counter stores: ConsumeOnce(key, retainUntilMs, nowMs) answers true iff
// there is no live record for key (live: its stored horizon is >= nowMs) and then records retainUntilMs; Advance(stream, counter)
// answers true iff counter is strictly greater than the stored value and then stores it. Both are atomic across every client of the
// same backend, durable, and fail closed (an error when they cannot decide).

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// StoreConsumer is the consume-once operation of a client.
type StoreConsumer interface {
	ConsumeOnce(key string, retainUntilMs, nowMs float64) (bool, error)
}

// StoreAdvancer is the counter operation of a client.
type StoreAdvancer interface {
	Advance(streamKey string, counter float64) (bool, error)
}

// StoreClient is one connection or verifier instance talking to the shared backend. It implements StoreConsumer, StoreAdvancer or
// both. Close releases the connection; the backend's state must survive it.
type StoreClient interface{ Close() error }

// StoreCapabilities declare what an adapter implements. A nil member is detected (the operations) or defaulted (Durable: true).
type StoreCapabilities struct {
	ConsumeOnce, Advance, Durable *bool
}

// StoreAdapter is what a store author implements to run the kit against their store.
type StoreAdapter interface {
	// Name is shown in reports.
	Name() string
	Capabilities() StoreCapabilities
	// Open opens one client against the shared backend (once per simulated verifier instance).
	Open() (StoreClient, error)
}

// StoreRestarter restarts the BACKEND after every client was closed; StoreCrasher crashes it abruptly (followed by Restart);
// StoreTeardowner releases everything the adapter holds (never shared data).
type StoreRestarter interface{ Restart() error }

// StoreCrasher crashes the backend abruptly.
type StoreCrasher interface{ Crash() error }

// StoreTeardowner releases everything the adapter holds.
type StoreTeardowner interface{ Teardown() error }

func storeBoolp(b bool) *bool { return &b }

// StoreWorkloadOptions tune the workloads; a zero member is its default.
type StoreWorkloadOptions struct {
	Clients     int     // concurrent clients, default 16
	DurationMs  float64 // concurrent run length, default 2000
	WindowMs    float64 // contention window, default 5
	Spread      int     // keys per window, default 3
	Values      int     // counter values are drawn from [0, Values), default 20
	RetentionMs float64 // consumeOnce horizon, default 10 minutes
	OpTimeoutMs float64 // a call not settled after this long is recorded unknown, default 5000
	Rounds      int     // same-key burst rounds, default 20
	RevisitKeys int     // retention run: distinct keys written then revisited, default 500
	Namespace   string  // key prefix; default random per run
	Seed        uint32  // PRNG seed; default random
}

// StoreWorkloadResult is a recorded history.
type StoreWorkloadResult struct {
	Ops    []*StoreOp
	Errors int // calls that failed, timed out or answered no boolean (recorded unknown)
	Note   string
}

type storeDefaults struct {
	clients, spread, values, rounds, revisitKeys int
	durationMs, windowMs, retentionMs, opTimeout float64
	namespace                                    string
	seed                                         uint32
}

// StoreRandomNamespace is a fresh key prefix, so runs never collide with each other or with real data.
func StoreRandomNamespace() string {
	return fmt.Sprintf("pcasc-%s-%06x", strings.ToLower(fmtBase36(uint64(time.Now().UnixMilli()))), uint32(time.Now().UnixNano())&0xffffff)
}

func fmtBase36(n uint64) string {
	const d = "0123456789abcdefghijklmnopqrstuvwxyz"
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 36 {
		b = append([]byte{d[n%36]}, b...)
	}
	return string(b)
}

func storeDefaultsOf(o StoreWorkloadOptions) storeDefaults {
	d := storeDefaults{clients: o.Clients, spread: o.Spread, values: o.Values, rounds: o.Rounds, revisitKeys: o.RevisitKeys,
		durationMs: o.DurationMs, windowMs: o.WindowMs, retentionMs: o.RetentionMs, opTimeout: o.OpTimeoutMs, namespace: o.Namespace, seed: o.Seed}
	if d.clients <= 0 {
		d.clients = 16
	}
	if d.spread <= 0 {
		d.spread = 3
	}
	if d.values <= 0 {
		d.values = 20
	}
	if d.rounds <= 0 {
		d.rounds = 20
	}
	if d.revisitKeys <= 0 {
		d.revisitKeys = 500
	}
	if d.durationMs <= 0 {
		d.durationMs = 2000
	}
	if d.windowMs <= 0 {
		d.windowMs = 5
	}
	if d.retentionMs <= 0 {
		d.retentionMs = 600_000
	}
	if d.opTimeout <= 0 {
		d.opTimeout = 5000
	}
	if d.namespace == "" {
		d.namespace = StoreRandomNamespace()
	}
	if d.seed == 0 {
		d.seed = uint32(time.Now().UnixNano())
	}
	return d
}

// StoreOpContext is what one operation needs: where to record, the retention horizon and the call timeout.
type StoreOpContext struct {
	Rec         StoreRecorder
	RetentionMs float64
	OpTimeoutMs float64
}

// StoreSettle runs fn and settles it as a definite boolean, or "unknown" on an error, a panic or a timeout.
func StoreSettle(fn func() (bool, error), timeoutMs float64) string {
	type res struct {
		ok  bool
		err error
	}
	ch := make(chan res, 1)
	go func() {
		defer func() {
			if recover() != nil {
				ch <- res{err: errors.New("panic")}
			}
		}()
		ok, err := fn()
		ch <- res{ok, err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			return "unknown"
		}
		if r.ok {
			return "true"
		}
		return "false"
	case <-time.After(time.Duration(timeoutMs * float64(time.Millisecond))):
		return "unknown"
	}
}

// StorePerform records and performs one operation. For advance, value is the counter; for consume it is ignored.
func StorePerform(c StoreClient, client, kind, key string, value float64, ctx StoreOpContext) string {
	now := float64(time.Now().UnixMilli())
	lo, w := value, value
	if kind == "consume" {
		lo, w = now, now+ctx.RetentionMs
	}
	op := ctx.Rec.Invoke(client, kind, key, lo, w)
	r := StoreSettle(func() (bool, error) {
		if kind == "consume" {
			cc, ok := c.(StoreConsumer)
			if !ok {
				return false, errors.New("client has no consumeOnce")
			}
			return cc.ConsumeOnce(key, w, now)
		}
		ac, ok := c.(StoreAdvancer)
		if !ok {
			return false, errors.New("client has no advance")
		}
		return ac.Advance(key, value)
	}, ctx.OpTimeoutMs)
	ctx.Rec.Complete(op, r)
	return r
}

// StoreOpenClients opens n clients; on an error it closes those already open.
func StoreOpenClients(a StoreAdapter, n int) ([]StoreClient, error) {
	cs := make([]StoreClient, 0, n)
	for i := 0; i < n; i++ {
		c, err := a.Open()
		if err != nil {
			StoreCloseClients(cs)
			return nil, err
		}
		cs = append(cs, c)
	}
	return cs, nil
}

// StoreCloseClients closes every client.
func StoreCloseClients(cs []StoreClient) {
	for _, c := range cs {
		_ = c.Close()
	}
}

func storeCountUnknown(ops []*StoreOp) int {
	n := 0
	for _, o := range ops {
		if o.Res == "unknown" {
			n++
		}
	}
	return n
}

// StoreWindowedLoop is the client loop of the concurrent run, shared with the multi-process crash harness: until deadline, pick
// one of the spread keys of the current window (all clients and processes compute the same window from origin) and operate on it.
func StoreWindowedLoop(c StoreClient, client, kind string, ctx StoreOpContext, namespace string, windowMs float64, spread, values int, origin, deadline float64, rand func(n float64) float64) {
	for StoreClock() < deadline {
		win := math.Floor((StoreClock() - origin) / windowMs)
		key := fmt.Sprintf("%s:%s:%s:%s", namespace, kind, rsNumStr(win), rsNumStr(rand(float64(spread))))
		StorePerform(c, client, kind, key, rand(float64(values)), ctx)
	}
}

func storeWorkload(a StoreAdapter, o StoreWorkloadOptions) (storeDefaults, *StoreMemoryRecorder, StoreOpContext, []StoreClient, error) {
	d := storeDefaultsOf(o)
	rec := &StoreMemoryRecorder{}
	ctx := StoreOpContext{Rec: rec, RetentionMs: d.retentionMs, OpTimeoutMs: d.opTimeout}
	cs, err := StoreOpenClients(a, d.clients)
	return d, rec, ctx, cs, err
}

func storeParallel(n int, fn func(i int)) {
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) { defer wg.Done(); fn(i) }(i)
	}
	wg.Wait()
}

// RunStoreBurst: rounds times, every client fires one operation at the SAME fresh key at once.
func RunStoreBurst(a StoreAdapter, kind string, o StoreWorkloadOptions) (StoreWorkloadResult, error) {
	d, rec, ctx, cs, err := storeWorkload(a, o)
	if err != nil {
		return StoreWorkloadResult{}, err
	}
	defer StoreCloseClients(cs)
	rnd := StorePrng(d.seed)
	for r := 0; r < d.rounds; r++ {
		key := fmt.Sprintf("%s:%s:burst:%d", d.namespace, kind, r)
		vals := make([]float64, len(cs))
		for i := range cs {
			vals[i] = rnd(float64(d.values))
		}
		storeParallel(len(cs), func(i int) { StorePerform(cs[i], fmt.Sprintf("c%d", i), kind, key, vals[i], ctx) })
	}
	ops := rec.Ops()
	return StoreWorkloadResult{Ops: ops, Errors: storeCountUnknown(ops)}, nil
}

// RunStoreConcurrent: every client loops on the windowed keys for the run length.
func RunStoreConcurrent(a StoreAdapter, kind string, o StoreWorkloadOptions) (StoreWorkloadResult, error) {
	d, rec, ctx, cs, err := storeWorkload(a, o)
	if err != nil {
		return StoreWorkloadResult{}, err
	}
	defer StoreCloseClients(cs)
	origin := StoreClock()
	storeParallel(len(cs), func(i int) {
		StoreWindowedLoop(cs[i], fmt.Sprintf("c%d", i), kind, ctx, d.namespace, d.windowMs, d.spread, d.values, origin, origin+d.durationMs, StorePrng(d.seed+uint32(i)))
	})
	ops := rec.Ops()
	return StoreWorkloadResult{Ops: ops, Errors: storeCountUnknown(ops)}, nil
}

// RunStoreRetention writes RevisitKeys distinct keys (consume once / advance to 1), then revisits every one while it is still live
// (same counter): each revisit must answer false. It catches early pruning and capacity eviction of live records.
func RunStoreRetention(a StoreAdapter, kind string, o StoreWorkloadOptions) (StoreWorkloadResult, error) {
	d, rec, ctx, cs, err := storeWorkload(a, o)
	if err != nil {
		return StoreWorkloadResult{}, err
	}
	defer StoreCloseClients(cs)
	keys := make([]string, d.revisitKeys)
	for i := range keys {
		keys[i] = fmt.Sprintf("%s:%s:keep:%d", d.namespace, kind, i)
	}
	for _, pass := range []string{"write", "revisit"} {
		for i := 0; i < len(keys); i += len(cs) {
			i := i
			storeParallel(len(cs), func(j int) {
				if i+j < len(keys) {
					StorePerform(cs[j], fmt.Sprintf("%s-c%d", pass, j), kind, keys[i+j], 1, ctx)
				}
			})
		}
	}
	ops := rec.Ops()
	return StoreWorkloadResult{Ops: ops, Errors: storeCountUnknown(ops)}, nil
}

// RunStoreDurability consumes a key / advances a stream to 7, closes the client, restarts the backend when the adapter can, opens a
// new client and reads back: the key must stay consumed and the counter must not go backwards (7 refused, 8 accepted).
func RunStoreDurability(a StoreAdapter, kind string, o StoreWorkloadOptions) (StoreWorkloadResult, error) {
	d := storeDefaultsOf(o)
	rec := &StoreMemoryRecorder{}
	ctx := StoreOpContext{Rec: rec, RetentionMs: d.retentionMs, OpTimeoutMs: d.opTimeout}
	key := fmt.Sprintf("%s:%s:durable", d.namespace, kind)
	before, err := a.Open()
	if err != nil {
		return StoreWorkloadResult{}, err
	}
	StorePerform(before, "before-restart", kind, key, 7, ctx)
	_ = before.Close()
	rs, canRestart := a.(StoreRestarter)
	if canRestart {
		if err := rs.Restart(); err != nil {
			return StoreWorkloadResult{}, err
		}
	}
	after, err := a.Open()
	if err != nil {
		return StoreWorkloadResult{}, err
	}
	StorePerform(after, "after-restart", kind, key, 7, ctx)
	if kind == "advance" {
		StorePerform(after, "after-restart", kind, key, 8, ctx)
	}
	_ = after.Close()
	note := "no Restart hook: clients closed and re-opened only"
	if canRestart {
		note = "backend restarted between write and read"
	}
	ops := rec.Ops()
	return StoreWorkloadResult{Ops: ops, Errors: storeCountUnknown(ops), Note: note}, nil
}

// ---- reference adapters -----------------------------------------------------------------------------------------------------------

type storeFuncClient struct {
	consume func(k string, r, n float64) (bool, error)
	advance func(k string, c float64) (bool, error)
}

func (c *storeFuncClient) Close() error { return nil }

type storeConsumeClient struct{ *storeFuncClient }

func (c storeConsumeClient) ConsumeOnce(k string, r, n float64) (bool, error) {
	return c.consume(k, r, n)
}

type storeAdvanceClient struct{ *storeFuncClient }

func (c storeAdvanceClient) Advance(k string, v float64) (bool, error) { return c.advance(k, v) }

type storeBothClient struct{ *storeFuncClient }

func (c storeBothClient) ConsumeOnce(k string, r, n float64) (bool, error) { return c.consume(k, r, n) }
func (c storeBothClient) Advance(k string, v float64) (bool, error)        { return c.advance(k, v) }

func storeMakeClient(consume func(string, float64, float64) (bool, error), advance func(string, float64) (bool, error)) StoreClient {
	f := &storeFuncClient{consume, advance}
	switch {
	case consume != nil && advance != nil:
		return storeBothClient{f}
	case consume != nil:
		return storeConsumeClient{f}
	}
	return storeAdvanceClient{f}
}

type storeRefAdapter struct {
	name    string
	caps    StoreCapabilities
	open    func() (StoreClient, error)
	restart func() error
}

func (a *storeRefAdapter) Name() string                    { return a.name }
func (a *storeRefAdapter) Capabilities() StoreCapabilities { return a.caps }
func (a *storeRefAdapter) Open() (StoreClient, error)      { return a.open() }

type storeRestartableRef struct{ *storeRefAdapter }

func (a storeRestartableRef) Restart() error { return a.restart() }

func storeRef(name string, caps StoreCapabilities, open func() (StoreClient, error), restart func() error) StoreAdapter {
	a := &storeRefAdapter{name: name, caps: caps, open: open, restart: restart}
	if restart != nil {
		return storeRestartableRef{a}
	}
	return a
}

// StoreInMemoryAdapter is GOOD for ONE process: the library's in-memory store. Not durable (declared), not shared between processes.
func StoreInMemoryAdapter() StoreAdapter {
	var mu sync.Mutex
	st := NewInMemoryPcactnReplayStore(1_000_000)
	return storeRef("in-memory (InMemoryPcactnReplayStore)", StoreCapabilities{Durable: storeBoolp(false)}, func() (StoreClient, error) {
		return storeMakeClient(
			func(k string, r, n float64) (bool, error) {
				mu.Lock()
				defer mu.Unlock()
				return st.ConsumeOnce(k, r, n)
			},
			func(k string, c float64) (bool, error) { mu.Lock(); defer mu.Unlock(); return st.Advance(k, c) }), nil
	}, nil)
}

func storeNumOf(prev any) (float64, bool) {
	switch v := prev.(type) {
	case json.Number:
		f, err := v.Float64()
		return f, err == nil
	case float64:
		return v, true
	}
	return 0, false
}

// StoreDurableFileAdapter is GOOD: the crash-safe, multi-process file store (OpenDurableState), one handle per client, atomic
// Update. An empty dir makes a fresh temporary directory.
func StoreDurableFileAdapter(dir string) (StoreAdapter, error) {
	if dir == "" {
		var err error
		if dir, err = os.MkdirTemp("", "pcasc-durable-"); err != nil {
			return nil, err
		}
	}
	return storeRef("durable-state file store ("+dir+")", StoreCapabilities{Durable: storeBoolp(true)}, func() (StoreClient, error) {
		st, err := OpenDurableState(DurableStateOptions{Dir: dir})
		if err != nil {
			return nil, err
		}
		return storeMakeClient(
			func(key string, retain, now float64) (bool, error) {
				if !(finite(now) && retain >= now) {
					return false, errors.New("consumeOnce: retainUntilMs is before nowMs")
				}
				first := false
				_, _, err := st.Update("n:"+key, func(prev any, ok bool) (any, bool) {
					if p, isNum := storeNumOf(prev); ok && isNum && !(finite(now) && p < now) {
						return nil, false
					}
					first = true
					return jsNumber(retain), true // any old horizon is < now <= retain here, so the new horizon is the larger one
				})
				return first, err
			},
			func(key string, counter float64) (bool, error) {
				okAdv := false
				_, _, err := st.Update("c:"+key, func(prev any, ok bool) (any, bool) {
					if p, isNum := storeNumOf(prev); ok && isNum && !(counter > p) {
						return nil, false
					}
					okAdv = true
					return jsNumber(counter), true
				})
				return okAdv, err
			}), nil
	}, func() error { return nil }), nil // everything is on disk and every client re-opens the directory: a restart loses nothing
}

// StoreReadThenWriteAdapter is BAD: read, then write after a yield (no transaction, no compare-and-set). Two clients both read "absent".
func StoreReadThenWriteAdapter() StoreAdapter {
	var mu sync.Mutex
	seen, counters := map[string]float64{}, map[string]float64{}
	return storeRef("BAD read-then-write (a yield between check and set)", StoreCapabilities{Durable: storeBoolp(false)}, func() (StoreClient, error) {
		return storeMakeClient(
			func(k string, r, now float64) (bool, error) {
				mu.Lock()
				until, had := seen[k]
				mu.Unlock()
				time.Sleep(time.Millisecond)
				if had && until >= now {
					return false, nil
				}
				mu.Lock()
				seen[k] = r
				mu.Unlock()
				return true, nil
			},
			func(k string, c float64) (bool, error) {
				mu.Lock()
				last, had := counters[k]
				mu.Unlock()
				time.Sleep(time.Millisecond)
				if had && !(c > last) {
					return false, nil
				}
				mu.Lock()
				counters[k] = c
				mu.Unlock()
				return true, nil
			}), nil
	}, nil)
}

// StoreVolatileAdapter is BAD: claims durability but keeps state in process memory, so a restart forgets every consumed key and counter.
func StoreVolatileAdapter() StoreAdapter {
	var mu sync.Mutex
	st := NewInMemoryPcactnReplayStore(0)
	return storeRef("BAD volatile (state lost on restart)", StoreCapabilities{Durable: storeBoolp(true)}, func() (StoreClient, error) {
		return storeMakeClient(
			func(k string, r, n float64) (bool, error) {
				mu.Lock()
				defer mu.Unlock()
				return st.ConsumeOnce(k, r, n)
			},
			func(k string, c float64) (bool, error) { mu.Lock(); defer mu.Unlock(); return st.Advance(k, c) }), nil
	}, func() error { mu.Lock(); defer mu.Unlock(); st = NewInMemoryPcactnReplayStore(0); return nil })
}

// storeOrderedMap is an insertion-ordered map for the evicting adapter.
type storeOrderedMap struct {
	m     map[string]float64
	order []string
}

func (o *storeOrderedMap) set(k string, v float64, capacity int) {
	if _, had := o.m[k]; !had {
		o.order = append(o.order, k)
	}
	o.m[k] = v
	for len(o.m) > capacity {
		oldest := o.order[0]
		o.order = o.order[1:]
		delete(o.m, oldest)
	}
}

// StoreEvictingAdapter is BAD: a bounded cache that evicts the oldest record when full, live or not (capacity eviction, early prune).
func StoreEvictingAdapter(capacity int) StoreAdapter {
	if capacity <= 0 {
		capacity = 64
	}
	var mu sync.Mutex
	seen, counters := &storeOrderedMap{m: map[string]float64{}}, &storeOrderedMap{m: map[string]float64{}}
	return storeRef(fmt.Sprintf("BAD evicting cache (capacity %d, evicts live records)", capacity), StoreCapabilities{Durable: storeBoolp(false)}, func() (StoreClient, error) {
		return storeMakeClient(
			func(k string, r, now float64) (bool, error) {
				mu.Lock()
				defer mu.Unlock()
				if until, had := seen.m[k]; had && until >= now {
					return false, nil
				}
				seen.set(k, r, capacity)
				return true, nil
			},
			func(k string, c float64) (bool, error) {
				mu.Lock()
				defer mu.Unlock()
				if last, had := counters.m[k]; had && !(c > last) {
					return false, nil
				}
				counters.set(k, c, capacity)
				return true, nil
			}), nil
	}, nil)
}

// StoreNonStrictCounterAdapter is BAD: a counter that accepts a value EQUAL to the last one (>= instead of >), so one counter is
// accepted twice.
func StoreNonStrictCounterAdapter() StoreAdapter {
	var mu sync.Mutex
	counters := map[string]float64{}
	return storeRef("BAD non-strict counter (accepts an equal value)", StoreCapabilities{Durable: storeBoolp(false), ConsumeOnce: storeBoolp(false)}, func() (StoreClient, error) {
		return storeMakeClient(nil, func(k string, c float64) (bool, error) {
			mu.Lock()
			defer mu.Unlock()
			if last, had := counters[k]; had && c < last {
				return false, nil
			}
			counters[k] = c
			return true, nil
		}), nil
	}, nil)
}

// StoreReferenceAdapters are the built-in adapters by name (builtin:<name>); each takes the option pairs.
var StoreReferenceAdapters = map[string]func(options map[string]string) (StoreAdapter, error){
	"in-memory":              func(map[string]string) (StoreAdapter, error) { return StoreInMemoryAdapter(), nil },
	"durable-file":           func(o map[string]string) (StoreAdapter, error) { return StoreDurableFileAdapter(o["dir"]) },
	"bad-read-then-write":    func(map[string]string) (StoreAdapter, error) { return StoreReadThenWriteAdapter(), nil },
	"bad-volatile":           func(map[string]string) (StoreAdapter, error) { return StoreVolatileAdapter(), nil },
	"bad-non-strict-counter": func(map[string]string) (StoreAdapter, error) { return StoreNonStrictCounterAdapter(), nil },
	"bad-evicting": func(o map[string]string) (StoreAdapter, error) {
		n := 64
		if s, ok := o["capacity"]; ok {
			if _, err := fmt.Sscanf(s, "%d", &n); err != nil {
				return nil, errors.New("capacity must be an integer")
			}
		}
		return StoreEvictingAdapter(n), nil
	},
}

// StoreLoadAdapter resolves an adapter spec: builtin:<name> for a reference adapter, or a name registered with
// StoreRegisterAdapter. (A Go program links its adapters in; there is no run-time module import.)
func StoreLoadAdapter(spec string, options map[string]string) (StoreAdapter, error) {
	if options == nil {
		options = map[string]string{}
	}
	if name, ok := strings.CutPrefix(spec, "builtin:"); ok {
		f, known := StoreReferenceAdapters[name]
		if !known {
			names := make([]string, 0, len(StoreReferenceAdapters))
			for k := range StoreReferenceAdapters {
				names = append(names, k)
			}
			sort.Strings(names)
			return nil, fmt.Errorf("unknown built-in adapter '%s' (known: %s)", name, strings.Join(names, ", "))
		}
		return f(options)
	}
	storeRegMu.Lock()
	f, ok := storeRegistered[spec]
	storeRegMu.Unlock()
	if !ok {
		return nil, fmt.Errorf("%s: no store adapter registered under this name (StoreRegisterAdapter)", spec)
	}
	return f(options)
}

var (
	storeRegMu      sync.Mutex
	storeRegistered = map[string]func(map[string]string) (StoreAdapter, error){}
)

// StoreRegisterAdapter makes an adapter factory loadable by name (the crash test loads it in every child process).
func StoreRegisterAdapter(name string, factory func(options map[string]string) (StoreAdapter, error)) {
	storeRegMu.Lock()
	defer storeRegMu.Unlock()
	storeRegistered[name] = factory
}

// ---- the run ---------------------------------------------------------------------------------------------------------------------

// StoreTests are every test of a run, in order.
var StoreTests = []string{"burst", "concurrent", "retention", "durability", "crash"}

// StoreConformanceOptions are the workload and check options of a run, which tests to run (nil: all) and the crash setup.
type StoreConformanceOptions struct {
	StoreWorkloadOptions
	StoreCheckOptions
	Tests []string
	// Crash configures the crash test, which runs the adapter in child processes; nil skips it.
	Crash *StoreCrashOptions
}

// StoreDetectKinds are the operations the adapter implements: declared capabilities win, else what its first client exposes.
func StoreDetectKinds(a StoreAdapter) ([]string, error) {
	caps := a.Capabilities()
	c, err := a.Open()
	if err != nil {
		return nil, err
	}
	defer c.Close()
	_, hasConsume := c.(StoreConsumer)
	_, hasAdvance := c.(StoreAdvancer)
	if caps.ConsumeOnce != nil {
		hasConsume = *caps.ConsumeOnce
	}
	if caps.Advance != nil {
		hasAdvance = *caps.Advance
	}
	var kinds []string
	if hasConsume {
		kinds = append(kinds, "consume")
	}
	if hasAdvance {
		kinds = append(kinds, "advance")
	}
	return kinds, nil
}

func storeJudge(test, kind string, w StoreWorkloadResult, o StoreCheckOptions) StoreTestReport {
	h := StoreCheckHistory(w.Ops, o)
	definite := h.Outcomes["true"] + h.Outcomes["false"]
	status := "pass"
	if len(h.Violations) > 0 {
		status = "fail"
	} else if len(h.Unresolved) > 0 || definite == 0 {
		status = "unresolved"
	}
	var notes []string
	if w.Note != "" {
		notes = append(notes, w.Note)
	}
	if definite == 0 {
		notes = append(notes, "no definite answer was observed (every call failed or timed out)")
	}
	return StoreTestReport{Test: test, Kind: kind, Status: status, Ops: h.Ops, Keys: h.Keys, Errors: w.Errors, Violations: h.Violations,
		Unresolved: len(h.Unresolved), Note: strings.Join(notes, "; ")}
}

func storeSkip(test, kind, note string) StoreTestReport {
	return StoreTestReport{Test: test, Kind: kind, Status: "skip", Note: note}
}

// RunStoreTest runs one test for one operation kind and judges its history.
func RunStoreTest(a StoreAdapter, test, kind string, o StoreConformanceOptions) (StoreTestReport, error) {
	if d := a.Capabilities().Durable; test == "durability" && d != nil && !*d {
		return storeSkip(test, kind, "the adapter declares durable: false (only correct for one process whose lifetime covers the action lifetime)"), nil
	}
	if test == "crash" && (o.Crash == nil || len(o.Crash.Worker) == 0) {
		return storeSkip(test, kind, "needs the worker command (the crash test runs the adapter in child processes)"), nil
	}
	var w StoreWorkloadResult
	var err error
	switch test {
	case "burst":
		w, err = RunStoreBurst(a, kind, o.StoreWorkloadOptions)
	case "concurrent":
		w, err = RunStoreConcurrent(a, kind, o.StoreWorkloadOptions)
	case "retention":
		w, err = RunStoreRetention(a, kind, o.StoreWorkloadOptions)
	case "durability":
		w, err = RunStoreDurability(a, kind, o.StoreWorkloadOptions)
	case "crash":
		c := *o.Crash
		c.StoreWorkloadOptions = o.StoreWorkloadOptions
		var cr StoreCrashResult
		cr, err = RunStoreCrash(kind, c)
		w = cr.StoreWorkloadResult
	default:
		return StoreTestReport{}, fmt.Errorf("unknown test %q", test)
	}
	if err != nil {
		return StoreTestReport{}, err
	}
	return storeJudge(test, kind, w, o.StoreCheckOptions), nil
}

// RunStoreConformance runs every test for every operation the adapter implements.
func RunStoreConformance(a StoreAdapter, o StoreConformanceOptions) (StoreSuiteReport, error) {
	kinds, err := StoreDetectKinds(a)
	if err != nil {
		return StoreSuiteReport{}, err
	}
	if len(kinds) == 0 {
		return StoreSuiteReport{}, fmt.Errorf("%s: the client implements neither consumeOnce nor advance", a.Name())
	}
	tests := o.Tests
	if tests == nil {
		tests = StoreTests
	}
	var out []StoreTestReport
	for _, t := range tests {
		for _, k := range kinds {
			r, err := RunStoreTest(a, t, k, o)
			if err != nil {
				return StoreSuiteReport{}, err
			}
			out = append(out, r)
		}
	}
	return StoreSuiteReport{Adapter: a.Name(), Status: StoreOverall(out), Tests: out}, nil
}

// ---- the crash harness ----------------------------------------------------------------------------------------------------------

// StoreCrashOptions configure the multi-process crash test. Several client PROCESSES (each with several clients) run the windowed
// workload against the same backend and append their histories to per-process files; every KillEveryMs a random client process is
// killed and a replacement starts under a new identity, so the killed ones leave PENDING operations. When the adapter has Crash,
// the backend is crashed and restarted once mid-run. All writers are awaited before the histories are read (a partial history can
// make a false look unexplained).
type StoreCrashOptions struct {
	StoreWorkloadOptions
	// Worker is the command of one client process; the JSON StoreWorkerConfig is appended as its last argument. The program must
	// call StoreWorkerMain.
	Worker []string
	// Adapter and Options are the adapter spec every process loads (StoreLoadAdapter).
	Adapter        string
	Options        map[string]string
	Processes      int     // client processes alive at once, default 3; Clients is per process, default 4
	KillEvery      float64 // ms; default 400; negative: never
	NoBackendCrash bool
	Dir            string // history directory; default a fresh temporary directory
}

// StoreWorkerConfig is what one worker process is told to do (serialized as the last command-line argument).
type StoreWorkerConfig struct {
	Adapter     string            `json:"module"`
	Options     map[string]string `json:"options"`
	Kind        string            `json:"kind"`
	Proc        string            `json:"proc"`
	File        string            `json:"file"`
	Clients     int               `json:"clients"`
	Namespace   string            `json:"namespace"`
	WindowMs    float64           `json:"windowMs"`
	Spread      int               `json:"spread"`
	Values      int               `json:"values"`
	RetentionMs float64           `json:"retentionMs"`
	OpTimeoutMs float64           `json:"opTimeoutMs"`
	Origin      float64           `json:"origin"`
	Deadline    float64           `json:"deadline"`
	Seed        uint32            `json:"seed"`
}

// StoreCrashResult is a crash run: the history and what was done to the system.
type StoreCrashResult struct {
	StoreWorkloadResult
	Kills, BackendCrashes, Torn, Pending, Processes int
}

// StoreWorkerMain is the body of one client process of the crash harness: load the adapter, run the windowed workload, record to the
// file.
func StoreWorkerMain(cfg StoreWorkerConfig) error {
	a, err := StoreLoadAdapter(cfg.Adapter, cfg.Options)
	if err != nil {
		return err
	}
	rec, err := NewStoreFileRecorder(cfg.File, cfg.Proc)
	if err != nil {
		return err
	}
	cs, err := StoreOpenClients(a, cfg.Clients)
	if err != nil {
		return err
	}
	ctx := StoreOpContext{Rec: rec, RetentionMs: cfg.RetentionMs, OpTimeoutMs: cfg.OpTimeoutMs}
	storeParallel(len(cs), func(i int) {
		StoreWindowedLoop(cs[i], fmt.Sprintf("%sc%d", cfg.Proc, i), cfg.Kind, ctx, cfg.Namespace, cfg.WindowMs, cfg.Spread, cfg.Values, cfg.Origin, cfg.Deadline, StorePrng(cfg.Seed+uint32(i)))
	})
	StoreCloseClients(cs)
	err = rec.Close()
	if td, ok := a.(StoreTeardowner); ok {
		_ = td.Teardown()
	}
	return err
}

// RunStoreCrash runs the crash harness for one operation kind.
func RunStoreCrash(kind string, o StoreCrashOptions) (StoreCrashResult, error) {
	if len(o.Worker) == 0 {
		return StoreCrashResult{}, errors.New("RunStoreCrash: a worker command is required")
	}
	dir := o.Dir
	if dir == "" {
		var err error
		if dir, err = os.MkdirTemp("", "pcasc-hist-"); err != nil {
			return StoreCrashResult{}, err
		}
	}
	d := storeDefaultsOf(o.StoreWorkloadOptions)
	durationMs := o.DurationMs
	if durationMs <= 0 {
		durationMs = 3000
	}
	killEvery := o.KillEvery
	if killEvery == 0 {
		killEvery = 400
	}
	clients := o.Clients
	if clients <= 0 {
		clients = 4
	}
	procs := o.Processes
	if procs <= 0 {
		procs = 3
	}
	rnd := StorePrng(d.seed)
	origin := StoreClock()
	deadline := origin + durationMs
	var (
		live  []*exec.Cmd
		exits sync.WaitGroup
		mu    sync.Mutex
		n     int
	)
	spawn := func() error {
		proc := fmt.Sprintf("p%d", n)
		cfg := StoreWorkerConfig{Adapter: o.Adapter, Options: o.Options, Kind: kind, Proc: proc, File: filepath.Join(dir, "h-"+proc+".jsonl"), Clients: clients,
			Namespace: d.namespace, WindowMs: d.windowMs, Spread: d.spread, Values: d.values, RetentionMs: d.retentionMs, OpTimeoutMs: d.opTimeout,
			Origin: origin, Deadline: deadline, Seed: d.seed + uint32(7919*n)}
		n++
		js, _ := json.Marshal(cfg)
		cmd := exec.Command(o.Worker[0], append(append([]string{}, o.Worker[1:]...), string(js))...)
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			return err
		}
		mu.Lock()
		live = append(live, cmd)
		mu.Unlock()
		exits.Add(1)
		go func() {
			_ = cmd.Wait()
			mu.Lock()
			for i, c := range live {
				if c == cmd {
					live = append(live[:i], live[i+1:]...)
					break
				}
			}
			mu.Unlock()
			exits.Done()
		}()
		return nil
	}
	for i := 0; i < procs; i++ {
		if err := spawn(); err != nil {
			return StoreCrashResult{}, err
		}
	}
	var control StoreAdapter
	if !o.NoBackendCrash {
		var err error
		if control, err = StoreLoadAdapter(o.Adapter, o.Options); err != nil {
			return StoreCrashResult{}, err
		}
	}
	kills, backendCrashes := 0, 0
	half := origin + durationMs/2
	for killEvery > 0 && StoreClock()+killEvery < deadline {
		time.Sleep(time.Duration(killEvery * float64(time.Millisecond)))
		mu.Lock()
		victims := append([]*exec.Cmd(nil), live...)
		mu.Unlock()
		if len(victims) > 0 {
			_ = victims[int(rnd(float64(len(victims))))].Process.Kill()
			kills++
			if err := spawn(); err != nil {
				return StoreCrashResult{}, err
			}
		}
		if cr, ok := control.(StoreCrasher); ok && backendCrashes == 0 && StoreClock() >= half {
			if err := cr.Crash(); err != nil {
				return StoreCrashResult{}, err
			}
			if rs, ok := control.(StoreRestarter); ok {
				if err := rs.Restart(); err != nil {
					return StoreCrashResult{}, err
				}
			}
			backendCrashes++
		}
	}
	exits.Wait()
	if td, ok := control.(StoreTeardowner); ok {
		_ = td.Teardown()
	}
	files, err := filepath.Glob(filepath.Join(dir, "h-*.jsonl"))
	if err != nil {
		return StoreCrashResult{}, err
	}
	sort.Strings(files)
	var text []string
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return StoreCrashResult{}, err
		}
		text = append(text, string(b))
	}
	ops, torn, pending := StoreParseHistory(strings.Join(text, "\n"))
	return StoreCrashResult{StoreWorkloadResult: StoreWorkloadResult{Ops: ops, Errors: storeCountUnknown(ops)}, Kills: kills, BackendCrashes: backendCrashes,
		Torn: torn, Pending: pending, Processes: n}, nil
}
