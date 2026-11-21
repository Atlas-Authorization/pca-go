package pca

// Conformance profiles for the stores behind the operational plane: guardian lease stores, transparency-log ledger stores,
// aggregate budget ledgers, bond-settlement stores and mesh-witness state stores. Each profile is a list of checks, each one a single
// claim driven against YOUR store through an adapter; a failing check names the exact mismatch and the run reports it.
//
// An adapter is a ProfileAdapter: Name, Create (a fresh, empty, isolated backend as a ProfileHandle) and an optional Durable flag
// (nil means true: declare false ONLY for an in-process store; the durability checks are then skipped and reported). A handle has the
// Store (the client), Reopen (another client on the SAME backend; after a restart this is how state is read back), optionally Crash
// (kill the backend abruptly, then return a client on whatever survived) and Close. Records, plans and outcomes are JSON-shaped maps
// with the reference's member names. Concurrency is real goroutines.
//
//	rep := pca.RunGuardianLeaseStoreConformance(pca.ProfileAdapter[pca.LeaseStore]{Name: "redis", Create: open}, nil)
//	if !rep.OK() { t.Fatal(rep) }

import (
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"strings"
	"sync"
)

// ProfileHandle is one fresh, empty, isolated backend for a profile run.
type ProfileHandle[S any] struct {
	// Store is the client under test.
	Store S
	// Reopen returns another client on the SAME backend (the first stays usable).
	Reopen func() (S, error)
	// Crash kills the backend abruptly and returns a client on whatever survived; nil when the adapter cannot.
	Crash func() (S, error)
	// Close releases the backend after the check.
	Close func() error

	adapterDurable *bool
}

// ProfileAdapter creates the backends a profile is run against.
type ProfileAdapter[S any] struct {
	Name string
	// Create makes a fresh, empty backend.
	Create func() (*ProfileHandle[S], error)
	// Durable defaults to true; declare false ONLY for an in-process store (the durability checks are then skipped and reported).
	Durable *bool
}

// ProfileCheck is one claim about a store. Needs is "", "durable" or "crash".
type ProfileCheck[S any] struct {
	Name  string
	Claim string
	Needs string
	Run   func(h *ProfileHandle[S])
}

// ---- assertions (a failed one panics with a profileFailure the runner turns into a failed check) -----------------------------------

type profileFailure struct{ msg string }

func pFail(format string, a ...any) { panic(profileFailure{fmt.Sprintf(format, a...)}) }

// profNorm is the JSON-normalised form of v (numbers as float64), so that maps from a store compare by value.
func profNorm(v any) any {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	var out any
	_ = json.Unmarshal(b, &out)
	return out
}

func pEq(got, want any, msg ...string) {
	if reflect.DeepEqual(profNorm(got), profNorm(want)) {
		return
	}
	prefix := ""
	if len(msg) > 0 {
		prefix = msg[0] + ": "
	}
	g, _ := json.Marshal(got)
	w, _ := json.Marshal(want)
	pFail("%sexpected %s, got %s", prefix, w, g)
}

func pOK(cond bool, msg string) {
	if !cond {
		pFail("%s", msg)
	}
}

func pNoErr(err error) {
	if err != nil {
		pFail("unexpected error: %v", err)
	}
}

// pMust is v, or a failed check when the store returned an error.
func pMust[T any](v T, err error) T {
	pNoErr(err)
	return v
}

// pRejects expects the store to refuse: err must be non-nil.
func pRejects[T any](_ T, err error) {
	if err == nil {
		pFail("expected an error, none was returned")
	}
}

// pRace runs every function at once in its own goroutine and returns their results; a panic is re-raised after all have finished.
func pRace(fns ...func() any) []any {
	out := make([]any, len(fns))
	panics := make([]any, len(fns))
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i, f := range fns {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { panics[i] = recover() }()
			<-start
			out[i] = f()
		}()
	}
	close(start)
	wg.Wait()
	for _, p := range panics {
		if p != nil {
			panic(p)
		}
	}
	return out
}

// pBackground starts fn without waiting for it; whatever it does is dropped (an operation in flight at a crash).
func pBackground(fn func()) {
	go func() {
		defer func() { _ = recover() }()
		fn()
	}()
}

func pOutcome(v any) string {
	m, _ := v.(map[string]any)
	s, _ := m["outcome"].(string)
	return s
}

func pCount(rs []any, outcome string) int {
	n := 0
	for _, r := range rs {
		if pOutcome(r) == outcome {
			n++
		}
	}
	return n
}

// ---- running a profile ------------------------------------------------------------------------------------------------------------

func runProfile[S any](label string, checks []ProfileCheck[S], a ProfileAdapter[S], only []string) ConformanceReport {
	rep := ConformanceReport{Name: label + ": " + a.Name}
	for _, c := range checks {
		if only != nil {
			found := false
			for _, n := range only {
				found = found || n == c.Name
			}
			if !found {
				continue
			}
		}
		if c.Needs == "durable" && a.Durable != nil && !*a.Durable {
			rep.skip(c.Name, "the adapter declares durable: false")
			continue
		}
		if a.Create == nil {
			rep.add(c.Name, fmt.Errorf("Create is required"), "")
			continue
		}
		h, err := a.Create()
		if err != nil {
			rep.add(c.Name, fmt.Errorf("create: %w", err), "")
			continue
		}
		h.adapterDurable = a.Durable
		if c.Needs == "crash" && h.Crash == nil {
			rep.skip(c.Name, "the adapter has no Crash")
		} else {
			rep.add(c.Name, runCheck(c, h), "")
		}
		if h.Close != nil {
			_ = h.Close()
		}
	}
	return rep
}

func runCheck[S any](c ProfileCheck[S], h *ProfileHandle[S]) (err error) {
	defer func() {
		if r := recover(); r != nil {
			if f, ok := r.(profileFailure); ok {
				err = fmt.Errorf("%s", f.msg)
				return
			}
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	c.Run(h)
	return nil
}

// ProfileCheckNames lists the names of a profile's checks.
func ProfileCheckNames[S any](checks []ProfileCheck[S]) []string {
	out := make([]string, len(checks))
	for i, c := range checks {
		out[i] = c.Name
	}
	return out
}

// ---- guardian lease stores --------------------------------------------------------------------------------------------------------

// LeaseStore is a guardian lease store: the one record that says who the guardian leader is. A record is
// {holder, epoch, expiresAt}; Read is nil when none was ever written; Now is the store clock (epoch ms, finite); Cas replaces the
// stored record iff it equals expected (nil: no record), atomically, and never lets the epoch go down.
type LeaseStore interface {
	Read() (map[string]any, error)
	Now() (float64, error)
	Cas(expected, next map[string]any) (bool, error)
}

const (
	// DefaultGuardianLeaseSkewMs is the default clock-skew allowance of a lease.
	DefaultGuardianLeaseSkewMs = 1000
	// MaxGuardianLeaseTtlMs bounds a lease lifetime.
	MaxGuardianLeaseTtlMs = 3_600_000
	maxLeaseHolder        = 256
)

func leaseNum(v any) (float64, bool) {
	if _, isBool := v.(bool); isBool {
		return 0, false
	}
	f, ok := jsNum(v)
	return f, ok && !math.IsNaN(f) && !math.IsInf(f, 0)
}

func leaseValid(r map[string]any) bool {
	if r == nil {
		return false
	}
	if _, ok := r["holder"].(string); !ok {
		return false
	}
	e, ok := leaseNum(r["epoch"])
	if !ok || e != math.Trunc(e) || e < 1 || e > maxSafeInt {
		return false
	}
	x, ok := leaseNum(r["expiresAt"])
	return ok && x >= 0
}

func leaseOpts(holder string, ttl, skew float64) bool {
	if n := len(utf16Units(holder)); n == 0 || n > maxLeaseHolder { // the reference counts UTF-16 code units
		return false
	}
	return ttl == math.Trunc(ttl) && ttl >= 2 && ttl <= MaxGuardianLeaseTtlMs && skew >= 0 && skew < ttl
}

func guardLeaseFail(reason string, detail ...string) map[string]any {
	m := map[string]any{"ok": false, "reason": reason}
	if len(detail) > 0 {
		m["detail"] = detail[0]
	}
	return m
}

func leaseSnapshot(s LeaseStore) (cur map[string]any, now float64, err error) {
	if cur, err = s.Read(); err != nil {
		return nil, 0, err
	}
	n, err := s.Now()
	if err != nil {
		return nil, 0, err
	}
	if math.IsNaN(n) || math.IsInf(n, 0) || (cur != nil && !leaseValid(cur)) {
		return nil, 0, fmt.Errorf("corrupt lease state")
	}
	return cur, n, nil
}

func leaseApply(s LeaseStore, cur, nxt map[string]any) map[string]any {
	ok, err := s.Cas(cur, nxt)
	if err != nil {
		return guardLeaseFail("store-error", err.Error())
	}
	if !ok {
		return guardLeaseFail("lost-race")
	}
	return map[string]any{"ok": true, "lease": nxt}
}

// GuardianAcquireLease takes the lease if it is free (never held, released, or expired past the skew). The epoch increments on every takeover.
func GuardianAcquireLease(s LeaseStore, holder string, ttlMs, skewMs float64) map[string]any {
	if !leaseOpts(holder, ttlMs, skewMs) {
		return guardLeaseFail("invalid")
	}
	cur, now, err := leaseSnapshot(s)
	if err != nil {
		return guardLeaseFail("store-error", err.Error())
	}
	epoch := 0.0
	if cur != nil {
		exp, _ := leaseNum(cur["expiresAt"])
		if exp+skewMs > now && exp != 0 {
			return guardLeaseFail("held")
		}
		epoch, _ = leaseNum(cur["epoch"])
	}
	return leaseApply(s, cur, map[string]any{"holder": holder, "epoch": epoch + 1, "expiresAt": now + ttlMs})
}

// GuardianRenewLease extends a lease the caller still holds; it is refused once the holder's own safe window has passed, or after any takeover.
func GuardianRenewLease(s LeaseStore, lease map[string]any, ttlMs, skewMs float64) map[string]any {
	holder, _ := lease["holder"].(string)
	if !leaseValid(lease) || !leaseOpts(holder, ttlMs, skewMs) {
		return guardLeaseFail("invalid")
	}
	cur, now, err := leaseSnapshot(s)
	if err != nil {
		return guardLeaseFail("store-error", err.Error())
	}
	if cur == nil || cur["holder"] != lease["holder"] || !leaseSameEpoch(cur, lease) {
		return guardLeaseFail("stale")
	}
	if exp, _ := leaseNum(cur["expiresAt"]); exp-skewMs <= now {
		return guardLeaseFail("expired")
	}
	return leaseApply(s, cur, map[string]any{"holder": cur["holder"], "epoch": cur["epoch"], "expiresAt": now + ttlMs})
}

// GuardianReleaseLease gives the lease up early (expiresAt 0, epoch kept). Only the current holder at the current epoch can.
func GuardianReleaseLease(s LeaseStore, lease map[string]any) map[string]any {
	if !leaseValid(lease) {
		return guardLeaseFail("invalid")
	}
	cur, _, err := leaseSnapshot(s)
	if err != nil {
		return guardLeaseFail("store-error", err.Error())
	}
	if exp, _ := leaseNum(cur["expiresAt"]); cur == nil || cur["holder"] != lease["holder"] || !leaseSameEpoch(cur, lease) || exp == 0 {
		return guardLeaseFail("stale")
	}
	return leaseApply(s, cur, map[string]any{"holder": cur["holder"], "epoch": cur["epoch"], "expiresAt": 0})
}

func leaseSameEpoch(a, b map[string]any) bool {
	x, _ := leaseNum(a["epoch"])
	y, _ := leaseNum(b["epoch"])
	return x == y
}

func leaseWon(s LeaseStore, who string) map[string]any {
	r := GuardianAcquireLease(s, who, 600_000, 1_000)
	pOK(r["ok"] == true, fmt.Sprintf("acquire for %s failed: %v", who, r["reason"]))
	return r["lease"].(map[string]any)
}

func leaseEpoch(s LeaseStore) any {
	r := pMust(s.Read())
	if r == nil {
		return nil
	}
	return r["epoch"]
}

func leaseEmpty(h *ProfileHandle[LeaseStore]) {
	pEq(pMust(h.Store.Read()), nil)
	_, ok := leaseNum(pMust(h.Store.Now()))
	pOK(ok, "the store clock must be a finite number")
}

func leaseFirst(h *ProfileHandle[LeaseStore]) {
	l := leaseWon(h.Store, "a")
	pEq(l["epoch"], 1)
	pEq(pMust(h.Store.Read()), l)
	pOK(l["expiresAt"].(float64) > pMust(h.Store.Now()), "the lease must expire after the store clock")
}

func leaseWrongExpected(h *ProfileHandle[LeaseStore]) {
	s := h.Store
	pEq(pMust(s.Cas(map[string]any{"holder": "x", "epoch": 1, "expiresAt": 5}, map[string]any{"holder": "y", "epoch": 2, "expiresAt": 9})), false)
	pEq(pMust(s.Read()), nil)
	l := leaseWon(s, "a")
	pEq(pMust(s.Cas(nil, map[string]any{"holder": "y", "epoch": 2, "expiresAt": 9})), false)
	pEq(pMust(s.Read()), l)
}

func leaseRace(h *ProfileHandle[LeaseStore]) {
	clients := []LeaseStore{h.Store, pMust(h.Reopen()), pMust(h.Reopen()), pMust(h.Reopen())}
	var fns []func() any
	for i, c := range clients {
		fns = append(fns, func() any { return GuardianAcquireLease(c, fmt.Sprintf("h%da", i), 600_000, 1_000) },
			func() any { return GuardianAcquireLease(c, fmt.Sprintf("h%db", i), 600_000, 1_000) })
	}
	won := 0
	for _, r := range pRace(fns...) {
		if r.(map[string]any)["ok"] == true {
			won++
		}
	}
	pEq(won, 1)
	pEq(leaseEpoch(h.Store), 1)
}

func leaseTakeover(h *ProfileHandle[LeaseStore]) {
	a := leaseWon(h.Store, "a")
	pOK(GuardianReleaseLease(h.Store, a)["ok"] == true, "the holder must be able to release")
	pEq(leaseWon(h.Store, "b")["epoch"], 2)
}

func leaseEpochDown(h *ProfileHandle[LeaseStore]) {
	s := h.Store
	a := leaseWon(s, "a")
	GuardianReleaseLease(s, a)
	b := leaseWon(s, "b")
	ok, err := s.Cas(b, map[string]any{"holder": "z", "epoch": 1, "expiresAt": b["expiresAt"]})
	if err != nil {
		ok = false
	}
	pEq(ok, false)
	pEq(pMust(s.Read()), b)
}

func leaseStale(h *ProfileHandle[LeaseStore]) {
	s := h.Store
	a := leaseWon(s, "a")
	GuardianReleaseLease(s, a)
	b := leaseWon(s, "b")
	pEq(GuardianRenewLease(s, a, 600_000, 1_000), map[string]any{"ok": false, "reason": "stale"})
	pEq(GuardianReleaseLease(s, a), map[string]any{"ok": false, "reason": "stale"})
	pEq(pMust(s.Read()), b)
}

func leaseReopen(h *ProfileHandle[LeaseStore]) {
	l := leaseWon(h.Store, "a")
	pEq(pMust(pMust(h.Reopen()).Read()), l)
}

func leaseCrash(h *ProfileHandle[LeaseStore]) {
	a := leaseWon(h.Store, "a")
	GuardianReleaseLease(h.Store, a)
	back := pMust(h.Crash())
	pEq(leaseEpoch(back), 1)
	pEq(leaseWon(back, "b")["epoch"], 2)
}

// GuardianLeaseChecks is the guardian lease store profile.
var GuardianLeaseChecks = []ProfileCheck[LeaseStore]{
	{"empty-store-has-no-lease", "a new store has no lease and a finite clock", "", leaseEmpty},
	{"first-acquire-is-epoch-1", "the first holder gets epoch 1 and an expiry from the store clock", "", leaseFirst},
	{"wrong-expected-record-never-writes", "cas with an expected record that is not the stored one returns false and changes nothing", "", leaseWrongExpected},
	{"racing-acquirers-have-one-winner", "many contenders at once: exactly one acquires, at epoch 1", "", leaseRace},
	{"takeover-after-release-bumps-the-epoch", "a released lease is free at once and the next holder gets a strictly higher epoch", "", leaseTakeover},
	{"epoch-never-goes-down", "cas refuses a record with a lower epoch even when the expected record matches", "", leaseEpochDown},
	{"stale-holder-cannot-renew-or-release", "after a takeover the old (holder, epoch) is refused as stale for renew and release", "", leaseStale},
	{"state-survives-reopen", "an acknowledged lease is there when another client opens the same backend", "durable", leaseReopen},
	{"acknowledged-lease-survives-a-crash", "after an abrupt backend kill the lease and its epoch are still there, and the next epoch is higher", "crash", leaseCrash},
}

// RunGuardianLeaseStoreConformance runs GuardianLeaseChecks against a guardian lease store; only (nil: all) names the checks to run.
func RunGuardianLeaseStoreConformance(a ProfileAdapter[LeaseStore], only []string) ConformanceReport {
	return runProfile("lease store", GuardianLeaseChecks, a, only)
}

// ---- ledger stores ----------------------------------------------------------------------------------------------------------------

// LedgerStore is a transparency-log ledger store. Append and AppendCheckpoint return {outcome, size} and {outcome, count}; the
// outcome is "appended", "replayed" or "conflict". Invalid input (an empty batch, an empty commit, a negative expected length, a read
// range outside the log) is an error that writes nothing.
type LedgerStore interface {
	Size() (int, error)
	Read(from, to int) ([]string, error)
	Append(expected int, commits []string) (map[string]any, error)
	Checkpoints(from int) ([]map[string]any, error)
	CheckpointCount() (int, error)
	AppendCheckpoint(expected int, checkpoint map[string]any) (map[string]any, error)
}

func ledCm(i int) string { return fmt.Sprintf("commit-%d-%s", i, strings.Repeat("x", 30)) }

func ledCp(size int, rootAndPrev ...string) map[string]any {
	root, prev := fmt.Sprintf("root-%d", size), ""
	if len(rootAndPrev) > 0 {
		root = rootAndPrev[0]
	}
	if len(rootAndPrev) > 1 {
		prev = rootAndPrev[1]
	}
	return map[string]any{"sth": map[string]any{"instance_id": "i", "principal": "p", "size": size, "root": root, "prev_root": prev, "timestamp": 1, "guardian": "g", "sig": "s"}}
}

func ledRange(a, b int) []string {
	out := make([]string, 0, b-a)
	for i := a; i < b; i++ {
		out = append(out, ledCm(i))
	}
	return out
}

func ledAll(s LedgerStore) []string { return pMust(s.Read(0, pMust(s.Size()))) }

func ledApp(s LedgerStore, expected int, commits []string) map[string]any {
	return pMust(s.Append(expected, commits))
}

func ledCpApp(s LedgerStore, expected int, cp map[string]any) map[string]any {
	return pMust(s.AppendCheckpoint(expected, cp))
}

func ledAppendRetrying(s LedgerStore, commit string) int {
	for {
		size := pMust(s.Size())
		r := ledApp(s, size, []string{commit})
		if o := pOutcome(r); o == "appended" || o == "replayed" {
			return size
		}
	}
}

func ledEmpty(h *ProfileHandle[LedgerStore]) {
	s := h.Store
	pEq(pMust(s.Size()), 0)
	pEq(len(pMust(s.Read(0, 0))), 0)
	pEq(pMust(s.CheckpointCount()), 0)
	pEq(len(pMust(s.Checkpoints(0))), 0)
}

func ledNextPosition(h *ProfileHandle[LedgerStore]) {
	s := h.Store
	pEq(ledApp(s, 0, []string{ledCm(0)}), map[string]any{"outcome": "appended", "size": 1})
	pEq(ledApp(s, 1, []string{ledCm(1), ledCm(2)}), map[string]any{"outcome": "appended", "size": 3})
	pEq(pMust(s.Read(0, 3)), ledRange(0, 3))
	pEq(pMust(s.Read(1, 3)), ledRange(1, 3))
	pEq(len(pMust(s.Read(3, 3))), 0)
}

func ledConflict(h *ProfileHandle[LedgerStore]) {
	s := h.Store
	ledApp(s, 0, ledRange(0, 3))
	pEq(ledApp(s, 5, []string{ledCm(9)}), map[string]any{"outcome": "conflict", "size": 3})
	pEq(ledApp(s, 2, []string{ledCm(9)}), map[string]any{"outcome": "conflict", "size": 3})
	pEq(ledAll(s), ledRange(0, 3))
}

func ledReplay(h *ProfileHandle[LedgerStore]) {
	s := h.Store
	ledApp(s, 0, ledRange(0, 3))
	pEq(ledApp(s, 0, ledRange(0, 3)), map[string]any{"outcome": "replayed", "size": 3})
	pEq(ledApp(s, 1, ledRange(1, 3)), map[string]any{"outcome": "replayed", "size": 3})
	pEq(ledApp(s, 0, []string{ledCm(0), "other"}), map[string]any{"outcome": "conflict", "size": 3})
	pEq(ledApp(s, 2, []string{ledCm(2), ledCm(3)}), map[string]any{"outcome": "conflict", "size": 3})
	pEq(ledAll(s), ledRange(0, 3))
}

func ledInvalid(h *ProfileHandle[LedgerStore]) {
	s := h.Store
	ledApp(s, 0, []string{ledCm(0)})
	for _, bad := range [][]string{{}, {""}, {ledCm(1), ""}} {
		pRejects(s.Append(1, bad))
	}
	pRejects(s.Append(-1, []string{ledCm(1)}))
	pEq(ledAll(s), []string{ledCm(0)})
	for _, r := range [][2]int{{-1, 1}, {1, 0}, {0, 2}} {
		pRejects(s.Read(r[0], r[1]))
	}
}

func ledExact(h *ProfileHandle[LedgerStore]) {
	odd := []string{"a\"b\\c", "gränt-\U0001F512- -\x01", strings.Repeat("x", 5000), "__proto__", " leading and trailing "}
	ledApp(h.Store, 0, odd)
	pEq(ledAll(h.Store), odd)
}

func ledRaceOne(h *ProfileHandle[LedgerStore]) {
	clients := []LedgerStore{h.Store, pMust(h.Reopen()), pMust(h.Reopen()), pMust(h.Reopen())}
	var fns []func() any
	for i := 0; i < 8; i++ {
		fns = append(fns, func() any { return ledApp(clients[i%4], 0, []string{ledCm(100 + i)}) })
	}
	r := pRace(fns...)
	pEq(pCount(r, "appended"), 1)
	pEq(pCount(r, "conflict"), 7)
	log := ledAll(h.Store)
	pEq(len(log), 1)
	pOK(strings.Contains(strings.Join(ledRange(100, 108), "|"), log[0]), "the winning commit must be one of the racers")
}

func ledRaceRetry(h *ProfileHandle[LedgerStore]) {
	clients := []LedgerStore{h.Store, pMust(h.Reopen()), pMust(h.Reopen())}
	var fns []func() any
	for i := 0; i < 16; i++ {
		fns = append(fns, func() any { return ledAppendRetrying(clients[i%3], ledCm(200+i)) })
	}
	idx := pRace(fns...)
	seen := map[int]bool{}
	for _, p := range idx {
		seen[p.(int)] = true
	}
	pEq(len(seen), 16)
	log := ledAll(h.Store)
	pEq(len(log), 16)
	for i, p := range idx {
		pOK(p.(int) >= 0 && p.(int) < len(log) && log[p.(int)] == ledCm(200+i), fmt.Sprintf("commit %d is not at its reported position %d", i, p))
	}
}

func ledBatch(h *ProfileHandle[LedgerStore]) {
	s := h.Store
	ledApp(s, 0, ledRange(0, 2))
	pEq(pOutcome(ledApp(s, 5, ledRange(10, 14))), "conflict")
	pEq(ledAll(s), ledRange(0, 2))
	pEq(ledApp(s, 2, ledRange(10, 14)), map[string]any{"outcome": "appended", "size": 6})
	pEq(ledAll(s), append(ledRange(0, 2), ledRange(10, 14)...))
}

func ledCpCount(h *ProfileHandle[LedgerStore]) {
	s := h.Store
	ledApp(s, 0, ledRange(0, 6))
	pEq(ledCpApp(s, 0, ledCp(2)), map[string]any{"outcome": "appended", "count": 1})
	pEq(ledCpApp(s, 0, ledCp(2)), map[string]any{"outcome": "replayed", "count": 1})
	pEq(pOutcome(ledCpApp(s, 0, ledCp(3))), "conflict")
	pEq(pOutcome(ledCpApp(s, 2, ledCp(3))), "conflict")
	pEq(ledCpApp(s, 1, ledCp(5, "root-5", "root-2")), map[string]any{"outcome": "appended", "count": 2})
	sizes := func(from int) []any {
		var out []any
		for _, c := range pMust(s.Checkpoints(from)) {
			out = append(out, c["sth"].(map[string]any)["size"])
		}
		return out
	}
	pEq(sizes(0), []any{2, 5})
	pEq(sizes(1), []any{5})
	pEq(pMust(s.CheckpointCount()), 2)
}

func ledCpInside(h *ProfileHandle[LedgerStore]) {
	s := h.Store
	ledApp(s, 0, ledRange(0, 4))
	pEq(pOutcome(ledCpApp(s, 0, ledCp(5))), "conflict")
	pEq(pOutcome(ledCpApp(s, 0, ledCp(3))), "appended")
	pEq(pOutcome(ledCpApp(s, 1, ledCp(2))), "conflict")
	pEq(pOutcome(ledCpApp(s, 1, ledCp(3, "other-root"))), "conflict")
	pEq(pOutcome(ledCpApp(s, 1, ledCp(3))), "appended") // equal size, same root: allowed
	pEq(pOutcome(ledCpApp(s, 2, nil)), "conflict")
	pEq(pMust(s.CheckpointCount()), 2)
}

func ledCpRace(h *ProfileHandle[LedgerStore]) {
	ledApp(h.Store, 0, ledRange(0, 6))
	other := pMust(h.Reopen())
	r := pRace(func() any { return ledCpApp(h.Store, 0, ledCp(2)) }, func() any { return ledCpApp(other, 0, ledCp(3)) },
		func() any { return ledCpApp(h.Store, 0, ledCp(4)) }, func() any { return ledCpApp(other, 0, ledCp(5)) })
	pEq(pCount(r, "appended"), 1)
	pEq(pMust(h.Store.CheckpointCount()), 1)
}

func ledSnapshots(h *ProfileHandle[LedgerStore]) {
	s := h.Store
	ledApp(s, 0, ledRange(0, 3))
	ledCpApp(s, 0, ledCp(2))
	pMust(s.Read(0, 3))[0] = "mutated"
	c := pMust(s.Checkpoints(0))
	c[0]["sth"].(map[string]any)["size"] = 99
	pEq(ledAll(s), ledRange(0, 3))
	pEq(pMust(s.Checkpoints(0))[0]["sth"].(map[string]any)["size"], 2)
}

func ledReopen(h *ProfileHandle[LedgerStore]) {
	ledApp(h.Store, 0, ledRange(0, 5))
	ledCpApp(h.Store, 0, ledCp(3))
	ledApp(h.Store, 5, ledRange(5, 7))
	back := pMust(h.Reopen())
	pEq(ledAll(back), ledRange(0, 7))
	pEq(pMust(back.Checkpoints(0)), []map[string]any{ledCp(3)})
	pEq(ledApp(back, 7, []string{ledCm(7)}), map[string]any{"outcome": "appended", "size": 8})
}

func ledCrash(h *ProfileHandle[LedgerStore]) {
	ledApp(h.Store, 0, ledRange(0, 3))
	ledCpApp(h.Store, 0, ledCp(2))
	pBackground(func() { _, _ = h.Store.Append(3, ledRange(3, 7)) })
	back := pMust(h.Crash())
	log := ledAll(back)
	pOK(len(log) == 3 || len(log) == 7, fmt.Sprintf("log has %d entries", len(log))) // the batch of four is whole or absent
	pEq(log, ledRange(0, len(log)))
	pEq(pMust(back.Checkpoints(0)), []map[string]any{ledCp(2)})
	want := "replayed"
	if len(log) == 3 {
		want = "appended"
	}
	pEq(ledApp(back, 3, ledRange(3, 7)), map[string]any{"outcome": want, "size": 7})
	pEq(ledAll(back), ledRange(0, 7))
}

// LedgerChecks is the transparency-log ledger store profile. Inputs the Go types cannot express (a non-string commit, a fractional or
// NaN position) are not part of this port of the profile; the empty batch, the empty commit, a negative position and a bad range are.
var LedgerChecks = []ProfileCheck[LedgerStore]{
	{"empty-store-is-empty", "a new store has no entries and no checkpoints, and reads of the empty range succeed", "", ledEmpty},
	{"append-assigns-the-next-position", "an append at the current length adds its commits in order at exactly those positions", "", ledNextPosition},
	{"append-at-another-position-conflicts-without-trace", "an append whose expected length is not the current length conflicts, reports the real length, and writes nothing", "", ledConflict},
	{"append-retry-is-a-replay", "repeating a batch already stored at that position is a replay (a prefix of it too); a different batch there conflicts", "", ledReplay},
	{"invalid-input-is-refused", "empty batches, empty or non-string commits and a bad expected length throw and write nothing", "", ledInvalid},
	{"commit-strings-are-stored-exactly", "unicode, quotes, separators and long commits come back byte for byte", "", ledExact},
	{"racing-appends-at-one-position-have-one-winner", "clients appending at the same expected length: exactly one is appended, none is lost or duplicated, the log is the winner batch", "", ledRaceOne},
	{"racing-writers-with-retry-fill-every-position-once", "sixteen writers each retrying until their commit is in: positions are unique, there are no holes, every commit is present exactly once", "", ledRaceRetry},
	{"a-batch-is-all-or-nothing", "a batch that conflicts leaves none of its commits behind, and a batch that lands lands every commit", "", ledBatch},
	{"checkpoints-append-by-count-and-replay", "a checkpoint appends at the exact count; the same one again is a replay; another at that position conflicts", "", ledCpCount},
	{"checkpoints-stay-inside-the-log-and-never-go-back", "a checkpoint beyond the end of the log, below the previous one, or equal in size with another root is refused", "", ledCpInside},
	{"racing-checkpoints-have-one-winner", "checkpoints racing for one position: exactly one lands", "", ledCpRace},
	{"reads-are-snapshots", "mutating what a read returned cannot change the store", "", ledSnapshots},
	{"state-survives-reopen", "every acknowledged append and checkpoint is visible to a new client after the backend restarts", "durable", ledReopen},
	{"acknowledged-writes-survive-a-crash", "after an abrupt kill every acknowledged write is present and the log is a prefix of what was written: no holes, no partial batch", "crash", ledCrash},
}

// RunLedgerStoreConformance runs LedgerChecks against a transparency-log ledger store.
func RunLedgerStoreConformance(a ProfileAdapter[LedgerStore], only []string) ConformanceReport {
	return runProfile("ledger store", LedgerChecks, a, only)
}
