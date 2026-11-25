package pca

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"
)

// memLease and memLedger are tiny in-process reference stores: the profile must pass them and fail a store that breaks a guarantee.

type memLease struct {
	mu       sync.Mutex
	rec      map[string]any
	unsafe   bool // a cas that never checks its expected record
	downward bool // a cas that lets the epoch go down
}

func (m *memLease) Read() (map[string]any, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.rec == nil {
		return nil, nil
	}
	c := map[string]any{}
	for k, v := range m.rec {
		c[k] = v
	}
	return c, nil
}

func (m *memLease) Now() (float64, error) { return float64(time.Now().UnixMilli()), nil }

func (m *memLease) Cas(expected, next map[string]any) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.unsafe && !reflect.DeepEqual(profNorm(m.rec), profNorm(expected)) {
		return false, nil
	}
	if !m.downward && m.rec != nil && jsF(next["epoch"]) < jsF(m.rec["epoch"]) {
		return false, nil
	}
	m.rec = next
	return true, nil
}

func leaseAdapter(m *memLease) ProfileAdapter[LeaseStore] {
	no := false
	return ProfileAdapter[LeaseStore]{Name: "memory", Durable: &no, Create: func() (*ProfileHandle[LeaseStore], error) {
		fresh := &memLease{unsafe: m.unsafe, downward: m.downward}
		return &ProfileHandle[LeaseStore]{Store: fresh, Reopen: func() (LeaseStore, error) { return fresh, nil }}, nil
	}}
}

func TestLeaseProfileAgainstAMemoryStore(t *testing.T) {
	rep := RunGuardianLeaseStoreConformance(leaseAdapter(&memLease{}), nil)
	if !rep.OK() {
		t.Fatal(rep)
	}
	for _, c := range rep.Checks {
		if c.Name == "state-survives-reopen" && c.Status != "skip" {
			t.Fatalf("a non-durable adapter must skip the durability check, got %s", c.Status)
		}
	}
	if rep := RunGuardianLeaseStoreConformance(leaseAdapter(&memLease{unsafe: true}), []string{"wrong-expected-record-never-writes", "racing-acquirers-have-one-winner"}); rep.OK() {
		t.Fatal("a cas that ignores its expected record must fail the profile")
	}
	if rep := RunGuardianLeaseStoreConformance(leaseAdapter(&memLease{downward: true}), []string{"epoch-never-goes-down"}); rep.OK() {
		t.Fatal("a cas that lets the epoch go down must fail the profile")
	}
}

type memLedger struct {
	mu      sync.Mutex
	log     []string
	cps     []map[string]any
	lossy   bool // an append that always reports appended, even at the wrong position
	drained bool
}

func (m *memLedger) Size() (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.log), nil
}

func (m *memLedger) Read(from, to int) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if from < 0 || to < from || to > len(m.log) {
		return nil, errors.New("bad range")
	}
	return append([]string{}, m.log[from:to]...), nil
}

func (m *memLedger) Append(expected int, commits []string) (map[string]any, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(commits) == 0 || expected < 0 {
		return nil, errors.New("invalid")
	}
	for _, c := range commits {
		if c == "" {
			return nil, errors.New("invalid")
		}
	}
	n := len(m.log)
	switch {
	case expected == n || m.lossy:
		m.log = append(m.log, commits...)
		return map[string]any{"outcome": "appended", "size": len(m.log)}, nil
	case expected+len(commits) <= n && reflect.DeepEqual(m.log[expected:expected+len(commits)], commits):
		return map[string]any{"outcome": "replayed", "size": n}, nil
	}
	return map[string]any{"outcome": "conflict", "size": n}, nil
}

func (m *memLedger) Checkpoints(from int) ([]map[string]any, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []map[string]any{}
	for _, c := range m.cps[min(from, len(m.cps)):] {
		out = append(out, profNorm(c).(map[string]any))
	}
	return out, nil
}

func (m *memLedger) CheckpointCount() (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.cps), nil
}

func (m *memLedger) AppendCheckpoint(expected int, cp map[string]any) (map[string]any, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := len(m.cps)
	conflict := map[string]any{"outcome": "conflict", "count": n}
	if cp == nil || expected < 0 || expected > n {
		return conflict, nil
	}
	if expected < n {
		if reflect.DeepEqual(profNorm(m.cps[expected]), profNorm(cp)) {
			return map[string]any{"outcome": "replayed", "count": n}, nil
		}
		return conflict, nil
	}
	sth := cp["sth"].(map[string]any)
	size := int(jsF(sth["size"]))
	if size > len(m.log) {
		return conflict, nil
	}
	if n > 0 {
		last := m.cps[n-1]["sth"].(map[string]any)
		ls := int(jsF(last["size"]))
		if size < ls || (size == ls && sth["root"] != last["root"]) {
			return conflict, nil
		}
	}
	m.cps = append(m.cps, profNorm(cp).(map[string]any))
	return map[string]any{"outcome": "appended", "count": len(m.cps)}, nil
}

func ledgerAdapter(lossy bool) ProfileAdapter[LedgerStore] {
	no := false
	return ProfileAdapter[LedgerStore]{Name: "memory", Durable: &no, Create: func() (*ProfileHandle[LedgerStore], error) {
		m := &memLedger{lossy: lossy}
		return &ProfileHandle[LedgerStore]{Store: m, Reopen: func() (LedgerStore, error) { return m, nil }}, nil
	}}
}

func TestLedgerProfileAgainstAMemoryStore(t *testing.T) {
	if rep := RunLedgerStoreConformance(ledgerAdapter(false), nil); !rep.OK() {
		t.Fatal(rep)
	}
	if rep := RunLedgerStoreConformance(ledgerAdapter(true), []string{"append-at-another-position-conflicts-without-trace"}); rep.OK() {
		t.Fatal("an append that ignores the expected length must fail the profile")
	}
}

func TestProfileInventories(t *testing.T) {
	if n := len(GuardianLeaseChecks); n != 9 {
		t.Fatalf("lease checks: %d", n)
	}
	if n := len(LedgerChecks); n != 15 {
		t.Fatalf("ledger checks: %d", n)
	}
	if n := len(BudgetChecks); n != 22 {
		t.Fatalf("budget checks: %d", n)
	}
	if n := len(BondChecks); n != 20 {
		t.Fatalf("bond checks: %d", n)
	}
	seen := map[string]bool{}
	for _, name := range ProfileCheckNames(BudgetChecks) {
		if seen[name] {
			t.Fatalf("duplicate check name %s", name)
		}
		seen[name] = true
	}
}

type memMeshStore struct{ st map[string]any }

func (m *memMeshStore) Load() (map[string]any, error) {
	if m.st == nil {
		return nil, nil
	}
	return profNorm(m.st).(map[string]any), nil
}
func (m *memMeshStore) Save(s map[string]any) error { m.st = profNorm(s).(map[string]any); return nil }

func TestMeshWitnessStoreCasesWithoutAnEngine(t *testing.T) {
	a := MeshWitnessStoreAdapter{Name: "memory", Make: func() (MeshWitnessStateStore, error) { return &memMeshStore{}, nil }}
	rep := RunMeshWitnessStoreConformance(a, nil)
	if !rep.OK() {
		t.Fatal(rep)
	}
	skipped := 0
	for _, c := range rep.Checks {
		if c.Status == "skip" {
			skipped++
		}
	}
	if skipped != 2 {
		t.Fatalf("the two engine-driven cases must be skipped without an engine, skipped %d", skipped)
	}
}

// The mesh-witness profile over the file store, driving the real witness: every case runs, none is skipped.
func TestMeshWitnessStoreCasesWithTheRealWitness(t *testing.T) {
	dir := t.TempDir()
	n := 0
	a := MeshWitnessStoreAdapter{Name: "file",
		Make: func() (MeshWitnessStateStore, error) {
			n++
			return NewFileMeshWitnessStore(filepath.Join(dir, fmt.Sprintf("witness-%d.json", n))), nil
		},
		Reopen: func(previous MeshWitnessStateStore) (MeshWitnessStateStore, error) {
			return NewFileMeshWitnessStore(previous.(*FileMeshWitnessStore).path), nil
		},
		Damage: func(store MeshWitnessStateStore) error {
			return os.WriteFile(store.(*FileMeshWitnessStore).path, []byte("{not json"), 0o600)
		}}
	rep := RunMeshWitnessStoreConformance(a, NewMeshWitnessEngine())
	if !rep.OK() {
		t.Fatal(rep)
	}
	driven := 0
	for _, c := range MeshWitnessStoreCases(a, NewMeshWitnessEngine()) {
		if c.NeedsEngine {
			driven++
		}
	}
	for _, c := range rep.Checks {
		if c.Status != "pass" {
			t.Fatalf("%s: %s %s", c.Name, c.Status, c.Note)
		}
	}
	if driven < 3 {
		t.Fatalf("only %d cases drive the witness", driven)
	}
}
