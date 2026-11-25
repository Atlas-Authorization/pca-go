package pca

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"
)

// The adapters and the command-line side of the pca-state profile (store-conformance --profile pca-state): the replay store behind
// the real guard, with real signed PCActns (RunPcaStateConformance).

// PcaStateAdapter is what a store author implements to run the pca-state profile against their store. Durable says state survives
// closing every handle and a Restart; Shared says several handles share one backend. An adapter that also implements StoreRestarter
// (restart the backend) and StoreTeardowner (release everything it holds) is driven through them.
type PcaStateAdapter interface {
	Name() string
	Durable() bool
	Shared() bool
	// Open opens one handle onto the backend (one verifier instance's connection).
	Open() (StateStore, error)
}

type pcaStateRef struct {
	name            string
	durable, shared bool
	open            func() (StateStore, error)
	restart         func() error
}

func (a *pcaStateRef) Name() string              { return a.name }
func (a *pcaStateRef) Durable() bool             { return a.durable }
func (a *pcaStateRef) Shared() bool              { return a.shared }
func (a *pcaStateRef) Open() (StateStore, error) { return a.open() }
func (a *pcaStateRef) Restart() error {
	if a.restart == nil {
		return nil
	}
	return a.restart()
}

// pcaStateSharedScope declares a process store shared (a control for the profile's multi-instance checks).
type pcaStateSharedScope struct{ *MemoryStateStore }

func (pcaStateSharedScope) Scope() string { return ScopeShared }

// PcaStateInMemoryAdapter is GOOD for ONE process: the atomic in-memory store (not durable, not shared: the multi-instance checks are skipped).
func PcaStateInMemoryAdapter() PcaStateAdapter {
	st := NewMemoryStateStore()
	return &pcaStateRef{name: "in-memory atomic (MemoryStateStore)", open: func() (StateStore, error) { return st, nil }}
}

// PcaStateDurableFileAdapter is GOOD: the replay store over the crash-safe, multi-process file store, one OpenDurableState per
// handle. An empty dir is a fresh temporary directory.
func PcaStateDurableFileAdapter(dir string) (PcaStateAdapter, error) {
	if dir == "" {
		var err error
		if dir, err = os.MkdirTemp("", "pcasc-pstate-durable-"); err != nil {
			return nil, err
		}
	}
	return &pcaStateRef{name: "durable-state file store, atomic claim (" + dir + ")", durable: true, shared: true, open: func() (StateStore, error) {
		ds, err := OpenDurableState(DurableStateOptions{Dir: dir})
		if err != nil {
			return nil, err
		}
		return NewKvStateStore(NewDurableAtomicKV(ds), "", "")
	}}, nil
}

// pcaStateRacy is BAD: a claim that reads, yields, then writes: two instances both read "fresh" and both admit.
type pcaStateRacy struct {
	mu sync.Mutex
	m  map[string]int64
}

func (s *pcaStateRacy) Scope() string { return ScopeShared }

func (s *pcaStateRacy) Claim(key string, counter int64) (ClaimResult, error) {
	s.mu.Lock()
	last, has := s.m[key]
	s.mu.Unlock()
	time.Sleep(200 * time.Microsecond) // the yield between the read and the write
	if has && counter <= last {
		return ClaimResult{OK: false, LastCounter: &last}, nil
	}
	s.mu.Lock()
	s.m[key] = counter
	s.mu.Unlock()
	return ClaimResult{OK: true}, nil
}

// PcaStateReadThenWriteClaimAdapter is BAD: the claim is a read, a yield and a write (no compare-and-set).
func PcaStateReadThenWriteClaimAdapter() PcaStateAdapter {
	st := &pcaStateRacy{m: map[string]int64{}}
	return &pcaStateRef{name: "BAD claim as read, yield, write", shared: true, open: func() (StateStore, error) { return st, nil }}
}

// PcaStateVolatileAdapter is BAD: atomic and "durable", but a restart forgets every claim (state in process memory).
func PcaStateVolatileAdapter() PcaStateAdapter {
	var mu sync.Mutex
	st := NewMemoryStateStore()
	return &pcaStateRef{name: "BAD volatile atomic store (claims lost on restart)", durable: true, shared: true,
		open: func() (StateStore, error) {
			mu.Lock()
			defer mu.Unlock()
			return pcaStateSharedScope{st}, nil
		},
		restart: func() error {
			mu.Lock()
			defer mu.Unlock()
			st = NewMemoryStateStore()
			return nil
		}}
}

// PcaStateUnsharedAdapter is BAD: every handle gets its own atomic state while the adapter claims `shared`.
func PcaStateUnsharedAdapter() PcaStateAdapter {
	return &pcaStateRef{name: "BAD per-handle state passed off as shared", shared: true, open: func() (StateStore, error) { return pcaStateSharedScope{NewMemoryStateStore()}, nil }}
}

// PcaStateReferenceAdapters are the built-in adapters (--adapter builtin:<name>): the GOOD ones and the BAD controls the profile must reject.
var PcaStateReferenceAdapters = map[string]func(options map[string]string) (PcaStateAdapter, error){
	"in-memory":                 func(map[string]string) (PcaStateAdapter, error) { return PcaStateInMemoryAdapter(), nil },
	"durable-file":              func(o map[string]string) (PcaStateAdapter, error) { return PcaStateDurableFileAdapter(o["dir"]) },
	"bad-read-then-write-claim": func(map[string]string) (PcaStateAdapter, error) { return PcaStateReadThenWriteClaimAdapter(), nil },
	"bad-volatile":              func(map[string]string) (PcaStateAdapter, error) { return PcaStateVolatileAdapter(), nil },
	"bad-unshared":              func(map[string]string) (PcaStateAdapter, error) { return PcaStateUnsharedAdapter(), nil },
}

var (
	pcaStateRegMu      sync.Mutex
	pcaStateRegistered = map[string]func(map[string]string) (PcaStateAdapter, error){}
)

// PcaStateRegisterAdapter makes an adapter factory loadable by name (the child processes of the run load it too: the program that
// calls StoreCliMain must register the same adapters before it does).
func PcaStateRegisterAdapter(name string, factory func(options map[string]string) (PcaStateAdapter, error)) {
	pcaStateRegMu.Lock()
	defer pcaStateRegMu.Unlock()
	pcaStateRegistered[name] = factory
}

// PcaStateLoadAdapter resolves an adapter spec: builtin:<name> for a reference adapter, or a name registered with PcaStateRegisterAdapter.
func PcaStateLoadAdapter(spec string, options map[string]string) (PcaStateAdapter, error) {
	if options == nil {
		options = map[string]string{}
	}
	if name, ok := strings.CutPrefix(spec, "builtin:"); ok {
		f, known := PcaStateReferenceAdapters[name]
		if !known {
			names := make([]string, 0, len(PcaStateReferenceAdapters))
			for k := range PcaStateReferenceAdapters {
				names = append(names, k)
			}
			sort.Strings(names)
			return nil, fmt.Errorf("unknown built-in pca-state adapter '%s' (known: %s)", name, strings.Join(names, ", "))
		}
		return f(options)
	}
	pcaStateRegMu.Lock()
	f, ok := pcaStateRegistered[spec]
	pcaStateRegMu.Unlock()
	if !ok {
		return nil, fmt.Errorf("%s: no pca-state adapter registered under this name (PcaStateRegisterAdapter)", spec)
	}
	return f(options)
}

// PcaStateWorkerFlag is the hidden first argument with which the command re-runs itself as a child process of the processes and
// crash checks: PcaStateWorkerFlag <config file> <adapter spec> <adapter options as JSON>.
const PcaStateWorkerFlag = "--pca-state-worker"

// PcaStateReportJSON is the report as JSON: {adapter, status, tests: [{test, status, note?}]}.
func PcaStateReportJSON(r ConformanceReport) string {
	tests := []any{}
	for _, c := range r.Checks {
		m := map[string]any{"test": c.Name, "status": c.Status}
		if c.Note != "" {
			m["note"] = c.Note
		}
		tests = append(tests, m)
	}
	status := "pass"
	if !r.OK() {
		status = "fail"
	}
	b, _ := json.MarshalIndent(map[string]any{"adapter": r.Name, "status": status, "tests": tests}, "", "  ")
	return string(b)
}

func pcaStateWorker(argv []string, errOut io.Writer) int {
	var opts map[string]string
	if len(argv) != 4 || json.Unmarshal([]byte(argv[3]), &opts) != nil {
		fmt.Fprintln(errOut, "pca-state worker: bad arguments")
		return 1
	}
	adapter, err := PcaStateLoadAdapter(argv[2], opts)
	if err == nil {
		err = PcaStateWorkerMain(argv[1], adapter.Open)
	}
	if err != nil {
		fmt.Fprintf(errOut, "pca-state worker failed: %s\n", err.Error())
		return 1
	}
	return 0
}

// pcaStateCliMain runs `store-conformance --profile pca-state`: exit 0 pass, 1 a check failed, 2 usage or adapter error.
func pcaStateCliMain(args StoreCliArgs, out, errOut io.Writer) int {
	opts := map[string]string{}
	for k, v := range args.Options {
		opts[k] = v
	}
	if args.Adapter == "builtin:durable-file" && opts["dir"] == "" {
		// the child processes must reach the SAME directory: it is made here and handed to them as an option
		dir, err := os.MkdirTemp("", "pcasc-pstate-durable-")
		if err != nil {
			fmt.Fprintf(errOut, "cannot load adapter: %s\n", err.Error())
			return 2
		}
		defer os.RemoveAll(dir)
		opts["dir"] = dir
	}
	adapter, err := PcaStateLoadAdapter(args.Adapter, opts)
	if err != nil {
		fmt.Fprintf(errOut, "cannot load adapter: %s\n", err.Error())
		return 2
	}
	defer func() {
		if td, ok := adapter.(StoreTeardowner); ok {
			_ = td.Teardown()
		}
	}()
	conf := PcaStateConformance{
		StateStoreConformance: StateStoreConformance{Name: adapter.Name(), Open: adapter.Open, Durable: adapter.Durable(), Shared: adapter.Shared(),
			Rounds: args.Conf.Rounds, Copies: args.Conf.Clients},
		Processes: args.Processes, Tests: args.PcaStateTests,
	}
	if r, ok := adapter.(StoreRestarter); ok {
		conf.Restart = r.Restart
	}
	if exe, err := os.Executable(); err == nil {
		optJSON, _ := json.Marshal(opts)
		conf.Worker = func(cfgPath string) *exec.Cmd {
			cmd := exec.Command(exe, PcaStateWorkerFlag, cfgPath, args.Adapter, string(optJSON))
			cmd.Stderr = os.Stderr
			return cmd
		}
	}
	rep := RunPcaStateConformance(conf)
	if args.JSON {
		fmt.Fprintln(out, PcaStateReportJSON(rep))
	} else {
		fmt.Fprint(out, rep.String())
	}
	if rep.OK() {
		return 0
	}
	return 1
}
