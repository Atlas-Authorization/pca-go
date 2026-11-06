package pca

import (
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// ---- a recording StateStore backend: every Open, Claim, Close and Restart is logged in order --------------------------

type g11Back struct {
	mu         sync.Mutex
	mem        *MemoryStateStore
	log        []string
	calls      int
	opens      int
	openFail   int
	restartErr error
	// hook(k, prefix, n): k is the 1-based global claim index; override true replaces the store's answer with (ok, err)
	hook func(k int, prefix string, n int64) (override, ok bool, err error)
}

func g11NewBack() *g11Back { return &g11Back{mem: NewMemoryStateStore()} }

func g11Prefix(key string) string { return key[strings.LastIndex(key, ":")+1:] }

func (b *g11Back) logf(format string, a ...any) {
	b.mu.Lock()
	b.log = append(b.log, fmt.Sprintf(format, a...))
	b.mu.Unlock()
}

func (b *g11Back) snapshot() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.log...)
}

type g11H struct {
	b  *g11Back
	id int
}

func (h *g11H) Claim(key string, n int64) (ClaimResult, error) {
	b := h.b
	b.mu.Lock()
	b.calls++
	k := b.calls
	hook := b.hook
	b.mu.Unlock()
	var r ClaimResult
	var err error
	done := false
	if hook != nil {
		if over, ok, herr := hook(k, g11Prefix(key), n); over {
			r, err, done = ClaimResult{OK: ok}, herr, true
		}
	}
	if !done {
		r, err = b.mem.Claim(key, n)
	}
	b.logf("h%d %s %d %v", h.id, g11Prefix(key), n, r.OK && err == nil)
	return r, err
}

func (h *g11H) Close() error {
	h.b.logf("close h%d", h.id)
	return nil
}

func (b *g11Back) open() (StateStore, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.opens++
	if b.opens == b.openFail {
		b.log = append(b.log, "open-fail")
		return nil, errors.New("boom")
	}
	b.log = append(b.log, fmt.Sprintf("open h%d", b.opens))
	return &g11H{b: b, id: b.opens}, nil
}

func (b *g11Back) restart() error {
	b.logf("restart")
	return b.restartErr
}

func (b *g11Back) conf(shared bool) StateStoreConformance {
	return StateStoreConformance{Name: "g11", Open: b.open, Restart: b.restart, Shared: shared, Durable: true, Rounds: 2, Copies: 3, Handles: 2}
}

func g11ErrStr(err error) string {
	if err == nil {
		return "<nil>"
	}
	return err.Error()
}

func g11WantLog(t *testing.T, got, want []string) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("log:\n got %q\nwant %q", got, want)
	}
}

func g11WantErr(t *testing.T, err error, want string) {
	t.Helper()
	if g11ErrStr(err) != want {
		t.Fatalf("err %q want %q", g11ErrStr(err), want)
	}
}

func g11At(at int, ok bool, err error) func(int, string, int64) (bool, bool, error) {
	return func(k int, _ string, _ int64) (bool, bool, error) {
		if k == at {
			return true, ok, err
		}
		return false, false, nil
	}
}

// ---- report rendering, defaults, keys, helpers ------------------------------------------------------------------------

func TestG11ConformanceReportString(t *testing.T) {
	pass := ConformanceReport{Name: "n", Checks: []ConformanceCheck{{Name: "a", Status: "pass", Note: "x"}, {Name: "b", Status: "skip"}}}
	if got, want := pass.String(), "store conformance: n -> PASS\n"+fmt.Sprintf("  [PASS] %-20s %s\n", "a", "x")+fmt.Sprintf("  [SKIP] %-20s %s\n", "b", ""); got != want {
		t.Fatalf("%q want %q", got, want)
	}
	fail := ConformanceReport{Name: "n", Checks: []ConformanceCheck{{Name: "a", Status: "fail", Note: "y"}}}
	if got := fail.String(); !strings.HasPrefix(got, "store conformance: n -> FAIL\n") {
		t.Fatalf("%q", got)
	}
}

func TestG11StateConformanceDefaults(t *testing.T) {
	for i, tc := range []struct {
		in      StateStoreConformance
		r, c, h int
	}{
		{StateStoreConformance{Shared: true}, 10, 16, 4},
		{StateStoreConformance{Shared: true, Rounds: -1, Copies: -1, Handles: -1}, 10, 16, 4},
		{StateStoreConformance{Shared: true, Rounds: 1, Copies: 1, Handles: 1}, 1, 1, 1},
		{StateStoreConformance{Shared: true, Rounds: 5, Copies: 7, Handles: 3}, 5, 7, 3},
		{StateStoreConformance{Shared: false, Handles: 3}, 10, 16, 1},
		{StateStoreConformance{Shared: false}, 10, 16, 1},
	} {
		c := tc.in
		c.defaults()
		if c.Rounds != tc.r || c.Copies != tc.c || c.Handles != tc.h {
			t.Errorf("case %d: %d/%d/%d want %d/%d/%d", i, c.Rounds, c.Copies, c.Handles, tc.r, tc.c, tc.h)
		}
	}
}

func TestG11ConfKeySequence(t *testing.T) {
	seq := func(k string) uint64 {
		p := strings.Split(k, ":")
		if len(p) != 4 || p[0] != "conf" || p[3] != "x" {
			t.Fatalf("key %q", k)
		}
		n, err := strconv.ParseUint(p[2], 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	a, b := seq(confKey("x")), seq(confKey("x"))
	if b != a+1 {
		t.Fatalf("sequence %d then %d, want +1", a, b)
	}
}

func TestG11OpenNAndCloseHelpers(t *testing.T) {
	b := g11NewBack()
	hs, err := b.conf(true).openN(2)
	if err != nil || len(hs) != 2 {
		t.Fatalf("%v %d", err, len(hs))
	}
	g11WantLog(t, b.snapshot(), []string{"open h1", "open h2"})
	closeAll(hs)
	g11WantLog(t, b.snapshot(), []string{"open h1", "open h2", "close h1", "close h2"})

	// a failing Open closes what it already opened
	b = g11NewBack()
	b.openFail = 3
	hs, err = b.conf(true).openN(3)
	if hs != nil {
		t.Fatal("handles returned on failure")
	}
	g11WantErr(t, err, "Open: boom")
	g11WantLog(t, b.snapshot(), []string{"open h1", "open h2", "open-fail", "close h1", "close h2"})

	ob := &g11OB{mem: NewMemoryOperationStore()}
	x, y := &g11OH{b: ob, id: 1}, &g11OH{b: ob, id: 2}
	closeBoth(x, x)
	g11WantLog(t, ob.snapshot(), []string{"close h1"})
	closeBoth(x, y)
	g11WantLog(t, ob.snapshot(), []string{"close h1", "close h1", "close h2"})
}

func TestG11LossyStoreLosesOnce(t *testing.T) {
	l := &lossyStore{StateStore: NewMemoryStateStore()}
	l.lose.Store(true)
	r, err := l.Claim("k", 1)
	g11WantErr(t, err, "timeout (answer lost after commit)")
	if r.OK || l.lose.Load() {
		t.Fatal("the lost answer must be refused and the flag cleared")
	}
	if r, err := l.Claim("k", 1); err != nil || r.OK {
		t.Fatalf("the committed counter must be refused: %v %v", r.OK, err)
	}
	if r, err := l.Claim("k", 2); err != nil || !r.OK {
		t.Fatalf("the next counter must be admitted: %v %v", r.OK, err)
	}
}

// ---- claim-burst ------------------------------------------------------------------------------------------------------

func TestG11ClaimBurst(t *testing.T) {
	b := g11NewBack()
	g11WantErr(t, b.conf(true).claimBurst(), "<nil>")
	want := []string{"open h1"}
	for i := 1; i <= 25; i++ {
		want = append(want, fmt.Sprintf("h1 burst %d true", i))
	}
	for i := 25; i >= 1; i-- {
		want = append(want, fmt.Sprintf("h1 burst %d false", i))
	}
	want = append(want, "h1 burst 26 true", "h1 burst-other 1 true", "close h1")
	g11WantLog(t, b.snapshot(), want)

	b = g11NewBack()
	b.openFail = 1
	g11WantErr(t, b.conf(true).claimBurst(), "Open: boom")
	g11WantLog(t, b.snapshot(), []string{"open-fail"})

	for _, tc := range []struct {
		at   int
		err  error
		want string
	}{
		{5, nil, "counter 5 was not admitted on first use (err <nil>)"},
		{26, errors.New("x"), "replay of counter 25 errored: x"},
		{51, nil, "the next counter after refusals was not admitted (err <nil>)"},
		{52, nil, "a fresh key refused counter 1 (err <nil>)"},
	} {
		b := g11NewBack()
		b.hook = g11At(tc.at, false, tc.err)
		g11WantErr(t, b.conf(true).claimBurst(), tc.want)
	}
}

// ---- claim-concurrent -------------------------------------------------------------------------------------------------

func TestG11ClaimConcurrent(t *testing.T) {
	b := g11NewBack()
	g11WantErr(t, b.conf(true).claimConcurrent(), "<nil>")
	got := b.snapshot()
	// the sequential post-race check: on the first handle, every racing counter is refused again
	if n := len(got); n < 5 || !reflect.DeepEqual(got[n-5:], []string{"h1 concurrent-distinct 3 false", "h1 concurrent-distinct 4 false", "h1 concurrent-distinct 5 false", "close h1", "close h2"}) {
		t.Fatalf("tail %q", got)
	}
	strip := make([]string, 0, len(got))
	wins := map[string]int{}
	for _, e := range got {
		if strings.HasSuffix(e, " true") {
			wins[strings.TrimSuffix(e, " true")]++
		}
		strip = append(strip, strings.TrimSuffix(strings.TrimSuffix(e, " true"), " false"))
	}
	sort.Strings(strip)
	want := []string{"close h1", "close h2",
		"h1 concurrent 1", "h1 concurrent 1", "h1 concurrent 2", "h1 concurrent 2",
		"h1 concurrent-distinct 3", "h1 concurrent-distinct 4", "h1 concurrent-distinct 4", "h1 concurrent-distinct 5",
		"h2 concurrent 1", "h2 concurrent 2", "h2 concurrent-distinct 3", "h2 concurrent-distinct 5",
		"open h1", "open h2"}
	g11WantLog(t, strip, want)
	if wins["h2 concurrent-distinct 5"] != 1 {
		t.Fatalf("the highest racing counter must be admitted: %q", got)
	}

	b = g11NewBack()
	b.openFail = 1
	g11WantErr(t, b.conf(true).claimConcurrent(), "Open: boom")

	b = g11NewBack()
	b.hook = func(k int, _ string, _ int64) (bool, bool, error) { return k <= 3, false, errors.New("x") }
	g11WantErr(t, b.conf(true).claimConcurrent(), "round 1: 0 of 3 copies of one counter were admitted (want exactly 1; 3 errors)")

	b = g11NewBack()
	b.hook = func(k int, _ string, _ int64) (bool, bool, error) { return k <= 3, true, nil }
	g11WantErr(t, b.conf(true).claimConcurrent(), "round 1: 3 of 3 copies of one counter were admitted (want exactly 1; 0 errors)")

	b = g11NewBack()
	var highest atomic.Int32
	b.hook = func(_ int, prefix string, n int64) (bool, bool, error) {
		if prefix == "concurrent-distinct" && n == 5 && highest.Add(1) == 1 {
			return true, false, nil
		}
		return false, false, nil
	}
	g11WantErr(t, b.conf(true).claimConcurrent(), "the highest of 3 racing counters was not admitted")

	b = g11NewBack()
	b.hook = g11At(10, false, errors.New("x"))
	g11WantErr(t, b.conf(true).claimConcurrent(), "counter 3 is admitted again after the race (err x)")
}

// ---- claim-durability, crash-after-claim ------------------------------------------------------------------------------

func TestG11ClaimDurability(t *testing.T) {
	b := g11NewBack()
	g11WantErr(t, b.conf(true).claimDurability(), "<nil>")
	g11WantLog(t, b.snapshot(), []string{"open h1", "h1 durability 1 true", "h1 durability 2 true", "h1 durability 3 true", "close h1",
		"restart", "open h2", "h2 durability 3 false", "h2 durability 4 true", "close h2"})

	b = g11NewBack()
	b.openFail = 1
	g11WantErr(t, b.conf(true).claimDurability(), "Open: boom")

	b = g11NewBack()
	b.hook = g11At(2, false, nil)
	g11WantErr(t, b.conf(true).claimDurability(), "counter 2 was not admitted (err <nil>)")
	g11WantLog(t, b.snapshot(), []string{"open h1", "h1 durability 1 true", "h1 durability 2 false", "close h1"})

	b = g11NewBack()
	b.restartErr = errors.New("boom2")
	g11WantErr(t, b.conf(true).claimDurability(), "Restart: boom2")

	b = g11NewBack()
	b.openFail = 2
	g11WantErr(t, b.conf(true).claimDurability(), "Open: boom")

	b = g11NewBack()
	b.hook = g11At(5, false, nil)
	g11WantErr(t, b.conf(true).claimDurability(), "counter 4 was not admitted after closing every handle (err <nil>)")
}

func TestG11CrashAfterClaim(t *testing.T) {
	b := g11NewBack()
	g11WantErr(t, b.conf(true).crashAfterClaim(), "<nil>")
	g11WantLog(t, b.snapshot(), []string{"open h1", "h1 crash 1 true", "restart", "open h2", "h2 crash 1 false", "h2 crash 2 true", "close h2", "close h1"})

	b = g11NewBack()
	b.openFail = 1
	g11WantErr(t, b.conf(true).crashAfterClaim(), "Open: boom")

	b = g11NewBack()
	b.hook = g11At(1, false, nil)
	g11WantErr(t, b.conf(true).crashAfterClaim(), "counter 1 was not admitted (err <nil>)")

	b = g11NewBack()
	b.restartErr = errors.New("boom2")
	g11WantErr(t, b.conf(true).crashAfterClaim(), "Restart: boom2")
}

// ---- retry-after-timeout ----------------------------------------------------------------------------------------------

func TestG11RetryAfterTimeout(t *testing.T) {
	b := g11NewBack()
	g11WantErr(t, b.conf(true).retryAfterTimeout(), "<nil>")
	g11WantLog(t, b.snapshot(), []string{"open h1", "open h2", "h1 retry 1 true", "h2 retry 1 false", "h2 retry 2 true", "close h1", "close h2"})

	// not shared: the retry goes to the same handle
	b = g11NewBack()
	g11WantErr(t, b.conf(false).retryAfterTimeout(), "<nil>")
	g11WantLog(t, b.snapshot(), []string{"open h1", "open h2", "h1 retry 1 true", "h1 retry 1 false", "h1 retry 2 true", "close h1", "close h2"})

	b = g11NewBack()
	b.openFail = 1
	g11WantErr(t, b.conf(true).retryAfterTimeout(), "Open: boom")

	b = g11NewBack()
	b.hook = g11At(2, true, nil)
	g11WantErr(t, b.conf(true).retryAfterTimeout(), "the retry of a claim whose answer was lost was admitted (err <nil>): the commit had already landed")

	b = g11NewBack()
	b.hook = g11At(3, false, nil)
	g11WantErr(t, b.conf(true).retryAfterTimeout(), "the next counter after the retry was not admitted (err <nil>)")
}

// ---- a recording OperationStore backend -------------------------------------------------------------------------------

type g11Ret struct {
	ok  bool
	rec *OperationRecord
	err error
}

type g11OB struct {
	mu         sync.Mutex
	mem        *MemoryOperationStore
	log        []string
	opens      int
	openFail   int
	failAll    bool
	restartErr error
	// loser 1: a Create that loses returns an error; 2: it returns no existing record and no error
	loser int
	hook  func(op, prefix string) *g11Ret
}

func g11NewOB() *g11OB { return &g11OB{mem: NewMemoryOperationStore()} }

func (b *g11OB) logf(format string, a ...any) {
	b.mu.Lock()
	b.log = append(b.log, fmt.Sprintf(format, a...))
	b.mu.Unlock()
}

func (b *g11OB) snapshot() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.log...)
}

func (b *g11OB) call(op, id string) *g11Ret {
	if b.hook == nil {
		return nil
	}
	return b.hook(op, g11Prefix(id))
}

type g11OH struct {
	b  *g11OB
	id int
}

func (h *g11OH) Create(rec OperationRecord) (bool, OperationRecord, error) {
	h.b.logf("h%d create %s", h.id, g11Prefix(rec.ID))
	if r := h.b.call("create", rec.ID); r != nil {
		var ex OperationRecord
		if r.rec != nil {
			ex = *r.rec
		}
		return r.ok, ex, r.err
	}
	ok, ex, err := h.b.mem.Create(rec)
	if !ok && h.b.loser == 1 {
		return false, OperationRecord{}, errors.New("busy")
	}
	if !ok && h.b.loser == 2 {
		return false, OperationRecord{}, nil
	}
	return ok, ex, err
}

func (h *g11OH) Get(id string) (*OperationRecord, error) {
	h.b.logf("h%d get %s", h.id, g11Prefix(id))
	if r := h.b.call("get", id); r != nil {
		return r.rec, r.err
	}
	return h.b.mem.Get(id)
}

func (h *g11OH) Transition(id string, from OperationState, next OperationRecord) (bool, error) {
	h.b.logf("h%d transition %s %s", h.id, g11Prefix(id), from)
	if r := h.b.call("transition", id); r != nil {
		return r.ok, r.err
	}
	return h.b.mem.Transition(id, from, next)
}

func (h *g11OH) Close() error {
	h.b.logf("close h%d", h.id)
	return nil
}

func (b *g11OB) open() (OperationStore, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.opens++
	if b.failAll || b.opens == b.openFail {
		return nil, errors.New("boom")
	}
	b.log = append(b.log, fmt.Sprintf("open h%d", b.opens))
	return &g11OH{b: b, id: b.opens}, nil
}

func (b *g11OB) conf(shared, durable bool, copies int) OperationStoreConformance {
	return OperationStoreConformance{Name: "g11", Open: b.open, Shared: shared, Durable: durable, Copies: copies,
		Restart: func() error { b.logf("restart"); return b.restartErr }}
}

func g11Check(r ConformanceReport, name string) string {
	for _, c := range r.Checks {
		if c.Name == name {
			return c.Status + ": " + c.Note
		}
	}
	return "absent"
}

func g11Count(log []string, entry string) int {
	n := 0
	for _, e := range log {
		if e == entry {
			n++
		}
	}
	return n
}

// ---- OperationStore conformance ---------------------------------------------------------------------------------------

func TestG11OpRecord(t *testing.T) {
	want := OperationRecord{ID: "x", State: OpPending, Verb: "v", Resource: "/r", ParamsDigest: "d", Reversibility: "reversible", StartedAt: 1}
	if got := opRecord("x"); !reflect.DeepEqual(got, want) {
		t.Fatalf("%+v", got)
	}
}

func TestG11OpConformanceSharedDurableLog(t *testing.T) {
	b := g11NewOB()
	r := RunOperationStoreConformance(b.conf(true, true, 2))
	want := []ConformanceCheck{{"create-once", "pass", ""}, {"transition-once", "pass", ""}, {"wrong-state", "pass", ""},
		{"get-missing", "pass", ""}, {"shared", "pass", ""}, {"durability", "pass", ""}}
	if !reflect.DeepEqual(r.Checks, want) {
		t.Fatalf("%+v", r.Checks)
	}
	got := b.snapshot()
	if len(got) < 11 {
		t.Fatalf("%q", got)
	}
	sort.Strings(got[2:4])
	sort.Strings(got[9:11])
	g11WantLog(t, got, []string{
		"open h1", "open h2", "h1 create create", "h2 create create", "close h1", "close h2",
		"open h3", "open h4", "h3 create transition", "h3 transition transition pending", "h4 transition transition pending", "close h3", "close h4",
		"open h5", "h5 create wrong", "h5 transition wrong executing", "h5 get wrong", "h5 transition missing pending", "close h5",
		"open h6", "h6 get never", "close h6",
		"open h7", "open h8", "h7 create shared", "h8 get shared", "close h7", "close h8",
		"open h9", "h9 create durable", "close h9", "restart", "open h10", "h10 get durable", "close h10",
	})
}

func TestG11OpConformanceUnsharedSkipsAndCopies(t *testing.T) {
	b := g11NewOB()
	r := RunOperationStoreConformance(b.conf(false, false, 0))
	want := []ConformanceCheck{{"create-once", "pass", ""}, {"transition-once", "pass", ""}, {"wrong-state", "pass", ""},
		{"get-missing", "pass", ""}, {"shared", "skip", "Shared is false"}, {"durability", "skip", "Durable is false"}}
	if !reflect.DeepEqual(r.Checks, want) {
		t.Fatalf("%+v", r.Checks)
	}
	got := b.snapshot()
	if c := g11Count(got, "h1 create create"); c != 16 {
		t.Fatalf("default copies: %d creates", c)
	}
	if c := g11Count(got, "h2 transition transition pending"); c != 16 {
		t.Fatalf("default copies: %d transitions", c)
	}
	if b.opens != 4 {
		t.Fatalf("an unshared store opens one handle per check: %d", b.opens)
	}
	for _, copies := range []int{1, 3} {
		b := g11NewOB()
		RunOperationStoreConformance(b.conf(false, false, copies))
		if c := g11Count(b.snapshot(), "h1 create create"); c != copies {
			t.Fatalf("copies %d: %d creates", copies, c)
		}
	}
}

func TestG11OpConformanceOpenFailures(t *testing.T) {
	b := g11NewOB()
	b.failAll = true
	r := RunOperationStoreConformance(b.conf(true, true, 2))
	want := []ConformanceCheck{{"create-once", "fail", "boom"}, {"transition-once", "fail", "boom"}, {"wrong-state", "fail", "boom"},
		{"get-missing", "fail", "boom"}, {"shared", "fail", "boom"}, {"durability", "fail", "boom"}}
	if !reflect.DeepEqual(r.Checks, want) {
		t.Fatalf("%+v", r.Checks)
	}

	// unshared: a failed Open must stop each check before it uses the missing handle
	b = g11NewOB()
	b.failAll = true
	r = RunOperationStoreConformance(b.conf(false, true, 2))
	want = []ConformanceCheck{{"create-once", "fail", "boom"}, {"transition-once", "fail", "boom"}, {"wrong-state", "fail", "boom"},
		{"get-missing", "fail", "boom"}, {"shared", "skip", "Shared is false"}, {"durability", "fail", "boom"}}
	if !reflect.DeepEqual(r.Checks, want) {
		t.Fatalf("%+v", r.Checks)
	}

	// the durability check's reopen fails (unshared: opens 1-4 are the first four checks, 5 and 6 the durability check)
	b = g11NewOB()
	b.openFail = 6
	r = RunOperationStoreConformance(b.conf(false, true, 2))
	if got := g11Check(r, "durability"); got != "fail: boom" {
		t.Fatal(got)
	}

	b = g11NewOB()
	b.restartErr = errors.New("boom2")
	r = RunOperationStoreConformance(b.conf(false, true, 2))
	if got := g11Check(r, "durability"); got != "fail: Restart: boom2" {
		t.Fatal(got)
	}

	r = RunOperationStoreConformance(OperationStoreConformance{Name: "none"})
	if !reflect.DeepEqual(r.Checks, []ConformanceCheck{{"configuration", "fail", "Open is required"}}) {
		t.Fatalf("%+v", r.Checks)
	}
}

func TestG11OpConformanceCreateLosers(t *testing.T) {
	// a losing create that errors is neither a win nor a missing record
	b := g11NewOB()
	b.loser = 1
	if r := RunOperationStoreConformance(b.conf(true, true, 4)); !r.OK() {
		t.Fatal(r)
	}
	b = g11NewOB()
	b.loser = 2
	r := RunOperationStoreConformance(b.conf(true, true, 2))
	if got := g11Check(r, "create-once"); got != "fail: 101 concurrent creates of one id reported created (want exactly 1; >=100 means a loser got no existing record)" {
		t.Fatal(got)
	}
}

func TestG11OpConformanceHooks(t *testing.T) {
	committed := opRecord("w")
	committed.State = OpCommitted
	pending := opRecord("w")
	for _, tc := range []struct {
		op, prefix string
		ret        g11Ret
		check      string
		want       string // exact "status: note", or a prefix when it ends in "*"
	}{
		{"create", "transition", g11Ret{}, "transition-once", "fail: create failed (err <nil>)"},
		{"transition", "transition", g11Ret{ok: true}, "transition-once", "fail: 2 concurrent transitions out of pending won (want exactly 1)"},
		{"create", "wrong", g11Ret{}, "wrong-state", "fail: create failed (err <nil>)"},
		{"transition", "wrong", g11Ret{ok: true}, "wrong-state", "fail: a transition from the wrong state applied (err <nil>)"},
		{"get", "wrong", g11Ret{rec: &committed}, "wrong-state", "fail: the record changed after a refused transition: &{ID:w State:committed*"},
		{"get", "wrong", g11Ret{rec: &pending, err: errors.New("boom")}, "wrong-state", "fail: the record changed after a refused transition: &{ID:w State:pending*"},
		{"transition", "missing", g11Ret{ok: true}, "wrong-state", "fail: a transition of an unknown id applied (err <nil>)"},
		{"get", "never", g11Ret{rec: &pending}, "get-missing", "fail: an unknown id returned &{ID:w*"},
		{"get", "never", g11Ret{err: errors.New("boom")}, "get-missing", "fail: an unknown id returned <nil> (err boom)"},
		{"create", "shared", g11Ret{}, "shared", "fail: create failed (err <nil>)"},
		{"create", "durable", g11Ret{}, "durability", "fail: create failed (err <nil>)"},
	} {
		b := g11NewOB()
		tc := tc
		b.hook = func(op, prefix string) *g11Ret {
			if op == tc.op && prefix == tc.prefix {
				r := tc.ret
				return &r
			}
			return nil
		}
		r := RunOperationStoreConformance(b.conf(true, true, 2))
		got := g11Check(r, tc.check)
		if p, isPrefix := strings.CutSuffix(tc.want, "*"); isPrefix {
			if !strings.HasPrefix(got, p) {
				t.Errorf("%s %s: %q want prefix %q", tc.op, tc.prefix, got, p)
			}
		} else if got != tc.want {
			t.Errorf("%s %s: %q want %q", tc.op, tc.prefix, got, tc.want)
		}
		if tc.ret.err != nil && tc.prefix == "wrong" && !strings.HasSuffix(got, "(err boom)") {
			t.Errorf("%q", got)
		}
		if tc.prefix == "durable" {
			log := b.snapshot()
			for i, e := range log {
				if strings.HasSuffix(e, " create durable") {
					if i+1 >= len(log) || log[i+1] != "close "+strings.Fields(e)[0] {
						t.Errorf("the failed durability create must close its handle: %q", log)
					}
				}
			}
		}
	}
}
