package pca

// The pca-state conformance profile: the replay store behind the REAL guard (RequirePCA in authorize mode), with real signed
// PCActns, checking the replay-state invariant: one action id (grant, leaf holder, counter) goes from unconsumed to consumed at most
// once, however many copies arrive, on however many instances or processes, across crashes after the claim and retries after a
// timeout.
//
//	claim-burst / claim-concurrent / claim-durability  the store's claim on its own (RunStateStoreConformance)
//	one-instance       N concurrent copies of one proof to one guard: exactly one admitted, every round
//	instances          the copies spread over K guards on separate Open() handles, built with MultiInstance (a store that declares
//	                   itself process-scoped is refused there, which fails the check)
//	processes          the same race across K child processes (needs Worker)
//	crash-after-claim  admitted, then the instance dies before its handler runs (and the backend restarts when it can): the same
//	                   proof is denied afterwards, the next counter admitted; with Worker the instance is a child process that
//	                   kills itself right after the admission
//	retry-after-timeout the commit lands but its answer is lost (the guard fails closed) and the retry is denied; and a retry on
//	                   another instance while the first commit is still in flight: exactly one admitted

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// PcaStateWorkerEnv names the environment variable that carries a child process's config file path.
const PcaStateWorkerEnv = "PCA_STATE_WORKER_CONFIG"

const pcaStateAudience = "pca-store-conformance"

// PcaStateConformance configures RunPcaStateConformance. The embedded fields are those of StateStoreConformance.
type PcaStateConformance struct {
	StateStoreConformance
	// Processes is the number of child processes of the processes check (default 3).
	Processes int
	// Worker builds the command of one child process for a config file. The child must call PcaStateWorkerMain with an Open that
	// reaches the SAME backend (PcaStateSelfReexec re-runs the test binary). Nil skips the process checks.
	Worker func(cfgPath string) *exec.Cmd
	// Tests selects checks by name (PcaStateTests); empty runs them all.
	Tests []string
}

// PcaStateTests are the checks of the profile, in order.
var PcaStateTests = []string{"claim-burst", "claim-concurrent", "claim-durability", "one-instance", "instances", "processes", "crash-after-claim", "retry-after-timeout"}

// PcaStateSelfReexec returns a Worker that re-runs the current test binary on the named test. That test must start with
//
//	if p := os.Getenv(pca.PcaStateWorkerEnv); p != "" { if err := pca.PcaStateWorkerMain(p, open); err != nil { t.Fatal(err) }; return }
func PcaStateSelfReexec(testName string) func(cfgPath string) *exec.Cmd {
	return func(cfgPath string) *exec.Cmd {
		cmd := exec.Command(os.Args[0], "-test.run=^"+testName+"$")
		cmd.Env = append(os.Environ(), PcaStateWorkerEnv+"="+cfgPath)
		cmd.Stderr = os.Stderr
		return cmd
	}
}

// ---- fixture ------------------------------------------------------------------------------------------------------------

// pcaStateFixture is a grant plus pre-signed PCActns (counters 1..n) from one agent, as JSON so child processes share it.
type pcaStateFixture struct {
	Grant   json.RawMessage `json:"grant"`
	Headers []string        `json:"headers"`
	// Provenance is the PCA-Provenance header of each action (the guard always runs the provenance gate; an action without the agent's
	// bundle is unlabelled and escalates).
	Provenance []string `json:"provenance"`
	grant      map[string]any
	denied     atomic.Value // the first refusal that was neither admitted nor a replay: status and body, for the failure report
}

func makePcaStateFixture(n int) (*pcaStateFixture, error) {
	principal, err := NewKeyPair()
	if err != nil {
		return nil, err
	}
	now := time.Now().UnixMilli()
	ag, err := CreateAgent(AgentOptions{Principal: principal, Goal: "store conformance", Permissions: map[string][]string{"files": {"read"}}, Aud: pcaStateAudience, Now: now})
	if err != nil {
		return nil, err
	}
	gj, err := Canonicalize(ag.Grant)
	if err != nil {
		return nil, err
	}
	fx := &pcaStateFixture{Grant: json.RawMessage(gj)}
	for i := 1; i <= n; i++ {
		c := int64(i)
		act, err := ag.Act("files.read", "doc:1", map[string]any{}, &ActOptions{Counter: &c, Now: now})
		if err != nil {
			return nil, err
		}
		fx.Headers = append(fx.Headers, act.Headers[PCAHeader])
		fx.Provenance = append(fx.Provenance, act.Headers[ProvenanceHeader])
	}
	return fx, fx.parse()
}

func (fx *pcaStateFixture) parse() error {
	v, err := ParseJSONLenient(fx.Grant)
	g, ok := v.(map[string]any)
	if err != nil || !ok {
		return errors.New("pca-state fixture: unreadable grant")
	}
	fx.grant = g
	return nil
}

// guard is the real RequirePCA over the store; the handler answers 204. multi declares several instances over the store.
func (fx *pcaStateFixture) guard(st StateStore, multi bool) (h http.Handler, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%v", r)
		}
	}()
	grantID, _ := fx.grant["id"].(string)
	op := &Operation{Verb: "files.read", Resource: "doc:1", Params: map[string]any{}}
	return RequirePCA(RequirePCAOptions{
		Audience: pcaStateAudience,
		ResolveGrant: func(ref string) (map[string]any, error) {
			if ref == grantID {
				return fx.grant, nil
			}
			return nil, errors.New("unknown grant")
		},
		Authorize: &AuthorizeOptions{StateStore: st, MultiInstance: &multi, IsRevoked: func(_, _ map[string]any) (bool, error) { return false, nil },
			Plan: PlanSingleStep, Risk: InsecureCalmRisk,
			// the fixture's action is a read: declared so, the provenance gate does not escalate it for lack of a principal-typed choice
			ArgProvenance: &ArgProvenanceOptions{Actions: func(Operation) map[string]any { return map[string]any{"effects": []any{"read"}} }},
			Operation:     func(*http.Request, []byte) (*Operation, error) { return op, nil }},
	})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })), nil
}

type pcaStateOutcome string

const (
	psAdmitted pcaStateOutcome = "admitted"
	psReplay   pcaStateOutcome = "replay"
	psError    pcaStateOutcome = "error"
)

// present sends proof counter (1-based) to the guard: admitted, denied as a replay (the counter check failed), or any other denial
// (fail closed, e.g. a store error).
func (fx *pcaStateFixture) present(h http.Handler, counter int64) pcaStateOutcome {
	req := httptest.NewRequest(http.MethodPost, "/docs/1", bytes.NewReader(nil))
	req.Header.Set(PCAHeader, fx.Headers[counter-1])
	if counter-1 < int64(len(fx.Provenance)) && fx.Provenance[counter-1] != "" {
		req.Header.Set(ProvenanceHeader, fx.Provenance[counter-1])
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code == http.StatusNoContent {
		return psAdmitted
	}
	var body struct {
		Checks map[string]string `json:"checks"`
		Reason string            `json:"reason"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body.Checks["replay"] == "fail" && !strings.Contains(body.Reason, "store failed") {
		return psReplay
	}
	if txt := rec.Body.String(); len(txt) > 600 {
		fx.denied.CompareAndSwap(nil, fmt.Sprintf("%d %s...", rec.Code, txt[:600]))
	} else {
		fx.denied.CompareAndSwap(nil, fmt.Sprintf("%d %s", rec.Code, txt))
	}
	return psError
}

// race presents copies of one proof round-robin over the guards at once and counts the admitted.
func (fx *pcaStateFixture) race(guards []http.Handler, counter int64, copies int) (admitted, replays, errs int) {
	out := make([]pcaStateOutcome, copies)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < copies; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			out[i] = fx.present(guards[i%len(guards)], counter)
		}(i)
	}
	close(start)
	wg.Wait()
	for _, o := range out {
		switch o {
		case psAdmitted:
			admitted++
		case psReplay:
			replays++
		default:
			errs++
		}
	}
	return
}

// ---- the run ------------------------------------------------------------------------------------------------------------

// RunPcaStateConformance runs the pca-state profile. Open is required (a missing one is a failed report).
func RunPcaStateConformance(c PcaStateConformance) ConformanceReport {
	rep := ConformanceReport{Name: c.Name}
	if c.Open == nil {
		rep.add("configuration", errors.New("Open is required"), "")
		return rep
	}
	c.defaults()
	if c.Processes <= 0 {
		c.Processes = 3
	}
	want := func(name string) bool {
		if len(c.Tests) == 0 {
			return true
		}
		for _, t := range c.Tests {
			if t == name {
				return true
			}
		}
		return false
	}
	if want("claim-burst") {
		rep.add("claim-burst", c.claimBurst(), "")
	}
	if want("claim-concurrent") {
		rep.add("claim-concurrent", c.claimConcurrent(), fmt.Sprintf("%d rounds x %d copies over %d handle(s)", c.Rounds, c.Copies, c.Handles))
	}
	if want("claim-durability") {
		if c.Durable {
			rep.add("claim-durability", c.claimDurability(), "")
		} else {
			rep.skip("claim-durability", "Durable is false (state dies with the process)")
		}
	}
	if want("one-instance") {
		rep.add("one-instance", c.psOneInstance(), "")
	}
	if want("instances") {
		if c.Shared {
			rep.add("instances", c.psInstances(), fmt.Sprintf("%d instances", c.Handles))
		} else {
			rep.skip("instances", "Shared is false (one instance only)")
		}
	}
	if want("processes") {
		switch {
		case !c.Shared:
			rep.skip("processes", "Shared is false (one instance only)")
		case c.Worker == nil:
			rep.skip("processes", "needs Worker (the guards run in child processes)")
		default:
			rep.add("processes", c.psProcesses(), fmt.Sprintf("%d processes x 2 instances x %d copies per round", c.Processes, c.Copies))
		}
	}
	if want("crash-after-claim") {
		if c.Durable {
			rep.add("crash-after-claim", c.psCrashAfterClaim(), "")
		} else {
			rep.skip("crash-after-claim", "Durable is false (state dies with the process)")
		}
	}
	if want("retry-after-timeout") {
		rep.add("retry-after-timeout", c.psRetryAfterTimeout(), "")
	}
	return rep
}

func (c PcaStateConformance) psRounds(fx *pcaStateFixture, guards []http.Handler) error {
	for r := int64(1); r <= int64(c.Rounds); r++ {
		if a, rp, e := fx.race(guards, r, c.Copies); a != 1 {
			return fmt.Errorf("round %d: %d of %d copies of one proof were admitted (want exactly 1; %d replays, %d fail-closed errors; first refusal: %v)", r, a, c.Copies, rp, e, fx.denied.Load())
		}
	}
	return nil
}

func (c PcaStateConformance) psOneInstance() error {
	fx, err := makePcaStateFixture(c.Rounds)
	if err != nil {
		return err
	}
	hs, err := c.openN(1)
	if err != nil {
		return err
	}
	defer closeAll(hs)
	g, err := fx.guard(hs[0], false)
	if err != nil {
		return err
	}
	return c.psRounds(fx, []http.Handler{g})
}

func (c PcaStateConformance) psInstances() error {
	fx, err := makePcaStateFixture(c.Rounds)
	if err != nil {
		return err
	}
	hs, err := c.openN(c.Handles)
	if err != nil {
		return err
	}
	defer closeAll(hs)
	guards := make([]http.Handler, len(hs))
	for i, h := range hs {
		if guards[i], err = fx.guard(h, true); err != nil {
			return fmt.Errorf("refused in multi-instance mode: %w", err)
		}
	}
	return c.psRounds(fx, guards)
}

// ---- child processes ----------------------------------------------------------------------------------------------------

type pcaStateWorkerCfg struct {
	Fixture   string `json:"fixture"`
	Out       string `json:"out"`
	Mode      string `json:"mode"` // "race" or "admit-then-die"
	Counter   int64  `json:"counter"`
	Rounds    int    `json:"rounds"`
	Origin    int64  `json:"origin"`
	RoundMs   int64  `json:"roundMs"`
	Copies    int    `json:"copies"`
	Instances int    `json:"instances"`
}

type pcaStateWorkerLine struct {
	Counter  int64 `json:"counter"`
	Admitted int   `json:"admitted"`
	Replays  int   `json:"replays"`
	Errors   int   `json:"errors"`
}

// PcaStateWorkerMain is the body of one child process of the process checks: open reaches the shared backend. In "admit-then-die"
// mode the process kills itself right after the admission, before any handler would run.
func PcaStateWorkerMain(cfgPath string, open func() (StateStore, error)) error {
	var cfg pcaStateWorkerCfg
	var fx pcaStateFixture
	raw, err := os.ReadFile(cfgPath)
	if err == nil {
		err = json.Unmarshal(raw, &cfg)
	}
	if err != nil {
		return err
	}
	raw, err = os.ReadFile(cfg.Fixture)
	if err == nil {
		err = json.Unmarshal(raw, &fx)
	}
	if err == nil {
		err = fx.parse()
	}
	if err != nil {
		return err
	}
	var stores []StateStore
	var guards []http.Handler
	for i := 0; i < max(cfg.Instances, 1); i++ {
		st, err := open()
		if err != nil {
			return err
		}
		stores = append(stores, st)
		g, err := fx.guard(st, cfg.Instances > 1 || cfg.Mode == "race")
		if err != nil {
			return err
		}
		guards = append(guards, g)
	}
	out, err := CreateOwnerOnly(cfg.Out, os.O_CREATE|os.O_APPEND|os.O_WRONLY)
	if err != nil {
		return err
	}
	record := func(counter int64, a, rp, e int) error {
		b, _ := json.Marshal(pcaStateWorkerLine{Counter: counter, Admitted: a, Replays: rp, Errors: e})
		_, err := out.Write(append(b, '\n'))
		if err == nil {
			err = out.Sync()
		}
		return err
	}
	if cfg.Mode == "admit-then-die" {
		a, rp, e := fx.race(guards[:1], cfg.Counter, 1)
		if err := record(cfg.Counter, a, rp, e); err != nil {
			return err
		}
		self, _ := os.FindProcess(os.Getpid())
		_ = self.Kill() // the instance dies after the claim committed and before any handler ran
		time.Sleep(time.Second)
		os.Exit(137) // Kill is not available: exit without cleanup
	}
	for r := 0; r < max(cfg.Rounds, 1); r++ {
		counter := cfg.Counter
		if counter == 0 {
			counter = int64(r + 1)
		}
		if d := time.Until(time.UnixMilli(cfg.Origin + int64(r)*cfg.RoundMs)); d > 0 {
			time.Sleep(d)
		}
		a, rp, e := fx.race(guards, counter, cfg.Copies)
		if err := record(counter, a, rp, e); err != nil {
			return err
		}
	}
	_ = out.Close()
	closeAll(stores)
	return nil
}

type pcaStateRun struct {
	lines  []pcaStateWorkerLine
	killed bool
}

func (c PcaStateConformance) psRunWorker(dir string, name string, cfg pcaStateWorkerCfg) (pcaStateRun, error) {
	cfg.Out = dir + "/" + name + ".jsonl"
	cfgPath := dir + "/" + name + ".cfg.json"
	b, _ := json.Marshal(cfg)
	if err := WriteFileOwnerOnly(cfgPath, b); err != nil {
		return pcaStateRun{}, err
	}
	cmd := c.Worker(cfgPath)
	runErr := cmd.Run()
	var run pcaStateRun
	if cmd.ProcessState != nil {
		code := cmd.ProcessState.ExitCode()
		// terminated by a signal; Windows has no signals: its forced termination exits 1 (the worker's own fallback exit is 137)
		run.killed = code == -1 || (runtime.GOOS == "windows" && (code == 1 || code == 137))
	}
	if runErr != nil && !run.killed && cmd.ProcessState == nil {
		return run, runErr
	}
	if raw, err := os.ReadFile(cfg.Out); err == nil {
		for _, l := range strings.Split(string(raw), "\n") {
			var ln pcaStateWorkerLine
			if l != "" && json.Unmarshal([]byte(l), &ln) == nil {
				run.lines = append(run.lines, ln)
			}
		}
	}
	return run, nil
}

func (r pcaStateRun) sum() (admitted, replays int) {
	for _, l := range r.lines {
		admitted += l.Admitted
		replays += l.Replays
	}
	return
}

func (c PcaStateConformance) psFixtureFile(n int) (dir, file string, err error) {
	fx, err := makePcaStateFixture(n)
	if err != nil {
		return "", "", err
	}
	if dir, err = os.MkdirTemp("", "pcasc-pstate-"); err != nil {
		return "", "", err
	}
	b, _ := json.Marshal(fx)
	file = dir + "/fixture.json"
	return dir, file, WriteFileOwnerOnly(file, b)
}

func (c PcaStateConformance) psProcesses() error {
	dir, fxFile, err := c.psFixtureFile(c.Rounds)
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	origin := time.Now().UnixMilli() + 1500 // time for every process to start and open its handles
	runs := make([]pcaStateRun, c.Processes)
	errs := make([]error, c.Processes)
	var wg sync.WaitGroup
	for p := 0; p < c.Processes; p++ {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			runs[p], errs[p] = c.psRunWorker(dir, fmt.Sprintf("p%d", p), pcaStateWorkerCfg{Fixture: fxFile, Mode: "race", Rounds: c.Rounds, Origin: origin, RoundMs: 150, Copies: c.Copies, Instances: 2})
		}(p)
	}
	wg.Wait()
	for p, e := range errs {
		if e != nil {
			return fmt.Errorf("process %d: %w", p, e)
		}
		if runs[p].killed || len(runs[p].lines) != c.Rounds {
			return fmt.Errorf("process %d did not finish its %d rounds (%d recorded)", p, c.Rounds, len(runs[p].lines))
		}
	}
	for r := int64(1); r <= int64(c.Rounds); r++ {
		n := 0
		for _, run := range runs {
			for _, l := range run.lines {
				if l.Counter == r {
					n += l.Admitted
				}
			}
		}
		if n != 1 {
			return fmt.Errorf("round %d: %d admissions across %d processes (want exactly 1)", r, n, c.Processes)
		}
	}
	return nil
}

// ---- crash and retry ----------------------------------------------------------------------------------------------------

func (c PcaStateConformance) psCrashAfterClaim() error {
	fx, err := makePcaStateFixture(4)
	if err != nil {
		return err
	}
	// in process: admitted on handle A, which is then abandoned (no close); the backend restarts when it can
	h1, err := c.openN(1)
	if err != nil {
		return err
	}
	g1, err := fx.guard(h1[0], false)
	if err != nil {
		closeAll(h1)
		return err
	}
	first := fx.present(g1, 1)
	if c.Restart != nil {
		if err := c.Restart(); err != nil {
			closeAll(h1)
			return fmt.Errorf("Restart: %w", err)
		}
	}
	hs, err := c.openN(1)
	if err != nil {
		closeAll(h1)
		return err
	}
	g, err := fx.guard(hs[0], false)
	if err != nil {
		closeAll(h1)
		closeAll(hs)
		return err
	}
	again, next := fx.present(g, 1), fx.present(g, 2)
	closeAll(hs)
	closeAll(h1)
	if first != psAdmitted || again != psReplay || next != psAdmitted {
		return fmt.Errorf("in process: admitted=%s, same proof after the instance died=%s, next counter=%s", first, again, next)
	}
	if c.Worker == nil {
		return nil
	}
	// child process: killed right after the admission, before its handler; a new process retries
	dir, fxFile, err := c.psFixtureFile(4)
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	killed, err := c.psRunWorker(dir, "a", pcaStateWorkerCfg{Fixture: fxFile, Mode: "admit-then-die", Counter: 3, Copies: 1, Instances: 1})
	if err != nil {
		return err
	}
	if c.Restart != nil {
		if err := c.Restart(); err != nil {
			return fmt.Errorf("Restart: %w", err)
		}
	}
	retried, err := c.psRunWorker(dir, "b", pcaStateWorkerCfg{Fixture: fxFile, Mode: "race", Counter: 3, Rounds: 1, Copies: 1, Instances: 1})
	if err != nil {
		return err
	}
	fresh, err := c.psRunWorker(dir, "c", pcaStateWorkerCfg{Fixture: fxFile, Mode: "race", Counter: 4, Rounds: 1, Copies: 1, Instances: 1})
	if err != nil {
		return err
	}
	ka, _ := killed.sum()
	ra, rr := retried.sum()
	fa, _ := fresh.sum()
	if !killed.killed || ka != 1 || ra != 0 || rr != 1 || fa != 1 {
		return fmt.Errorf("child process: killed=%v admitted before death=%d, retry admitted %d (replays %d), next counter admitted %d", killed.killed, ka, ra, rr, fa)
	}
	return nil
}

// slowClaimStore holds its claim at a gate before committing, so a second instance can race the in-flight first commit.
type slowClaimStore struct {
	StateStore
	entered chan struct{}
	gate    chan struct{}
	once    atomic.Bool
}

// ClaimHold is implemented by a store double that sequences racing claimers (a rendezvous that pairs them off). The harness calls
// HoldClaim before it keeps a claim back from the store at a gate and ReleaseClaim when it lets that claim go, so the double can tell
// a claimer the harness is withholding (which cannot arrive until the harness lets it, and must not be waited for) from one that is
// merely late.
type ClaimHold interface {
	HoldClaim(key string)
	ReleaseClaim(key string)
}

func (s *slowClaimStore) Claim(key string, counter int64) (ClaimResult, error) {
	if s.once.CompareAndSwap(false, true) {
		h, _ := s.StateStore.(ClaimHold)
		if h != nil {
			h.HoldClaim(key) // before `entered`, which lets the retry run
		}
		close(s.entered)
		<-s.gate
		if h != nil {
			h.ReleaseClaim(key)
		}
	}
	return s.StateStore.Claim(key, counter)
}

func (c PcaStateConformance) psRetryAfterTimeout() error {
	fx, err := makePcaStateFixture(4)
	if err != nil {
		return err
	}
	hs, err := c.openN(2)
	if err != nil {
		return err
	}
	defer closeAll(hs)
	first, other := hs[0], hs[len(hs)-1]
	if !c.Shared {
		other = first
	}
	guardOf := func(st StateStore) (http.Handler, error) { return fx.guard(st, false) }
	// 1. the commit lands, its answer is lost: the guard fails closed, the retry (another instance when shared) is a replay
	lossy := &lossyStore{StateStore: first}
	lossy.lose.Store(true)
	gl, err := guardOf(lossy)
	if err != nil {
		return err
	}
	go1, err := guardOf(other)
	if err != nil {
		return err
	}
	lost, retry, next := fx.present(gl, 1), fx.present(go1, 1), fx.present(go1, 2)
	if lost != psError || retry != psReplay || next != psAdmitted {
		return fmt.Errorf("lost answer: first=%s (want error), retry=%s (want replay), next counter=%s (want admitted)", lost, retry, next)
	}
	// 2. the first commit is still in flight when the caller retries elsewhere: exactly one of the two is admitted
	slow := &slowClaimStore{StateStore: first, entered: make(chan struct{}), gate: make(chan struct{})}
	gs, err := guardOf(slow)
	if err != nil {
		return err
	}
	inflight := make(chan pcaStateOutcome, 1)
	go func() { inflight <- fx.present(gs, 3) }()
	select {
	case <-slow.entered:
	case o := <-inflight:
		inflight <- o // refused before it reached the store: nothing is in flight
	}
	retried := fx.present(go1, 3)
	close(slow.gate)
	pair := 0
	for _, o := range []pcaStateOutcome{<-inflight, retried} {
		if o == psAdmitted {
			pair++
		}
	}
	if pair != 1 {
		return fmt.Errorf("in-flight retry: %d admitted of 2 (want exactly 1)", pair)
	}
	return nil
}
