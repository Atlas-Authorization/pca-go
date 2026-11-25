package pca

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// fileClaimStore is a durable, multi-process replay store: one file per key, a lock file taken with O_EXCL around the read-modify-write.
type fileClaimStore struct{ dir string }

func (s *fileClaimStore) Scope() string { return ScopeShared }

func (s *fileClaimStore) Claim(key string, counter int64) (ClaimResult, error) {
	name := filepath.Join(s.dir, strings.NewReplacer("/", "_", ":", "_").Replace(key))
	var lock *os.File
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(time.Millisecond) {
		f, err := os.OpenFile(name+".lock", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			lock = f
			break
		}
		if !os.IsExist(err) || time.Now().After(deadline) {
			return ClaimResult{}, err
		}
	}
	defer func() { lock.Close(); os.Remove(name + ".lock") }()
	if raw, err := os.ReadFile(name); err == nil {
		if last, perr := strconv.ParseInt(string(raw), 10, 64); perr == nil && counter <= last {
			return ClaimResult{OK: false, LastCounter: &last}, nil
		}
	}
	if err := os.WriteFile(name, []byte(strconv.FormatInt(counter, 10)), 0o600); err != nil {
		return ClaimResult{}, err
	}
	return ClaimResult{OK: true}, nil
}

func TestPcaStateConformanceFileStoreAcrossProcesses(t *testing.T) {
	dir := os.Getenv("PCA_TEST_STORE_DIR")
	open := func() (StateStore, error) { return &fileClaimStore{dir: dir}, nil }
	if p := os.Getenv(PcaStateWorkerEnv); p != "" { // a child process of the run below
		if err := PcaStateWorkerMain(p, open); err != nil {
			t.Fatal(err)
		}
		return
	}
	dir = t.TempDir()
	reexec := PcaStateSelfReexec("TestPcaStateConformanceFileStoreAcrossProcesses")
	rep := RunPcaStateConformance(PcaStateConformance{
		StateStoreConformance: StateStoreConformance{Name: "file", Open: open, Shared: true, Durable: true, Rounds: 4, Copies: 8},
		Processes:             2,
		Worker: func(cfg string) *exec.Cmd {
			cmd := reexec(cfg)
			cmd.Env = append(cmd.Env, "PCA_TEST_STORE_DIR="+dir)
			return cmd
		},
	})
	if !rep.OK() {
		t.Fatal(rep)
	}
	for _, name := range []string{"one-instance", "instances", "processes", "crash-after-claim", "retry-after-timeout"} {
		if got := checkStatus(rep, name); got != "pass" {
			t.Errorf("%s: %s\n%s", name, got, rep)
		}
	}
}

func TestPcaStateConformanceMemoryStoreOneInstance(t *testing.T) {
	st := NewMemoryStateStore()
	rep := RunPcaStateConformance(PcaStateConformance{StateStoreConformance: StateStoreConformance{Name: "memory", Open: func() (StateStore, error) { return st, nil }, Shared: false, Durable: false}})
	if !rep.OK() {
		t.Fatal(rep)
	}
	for name, want := range map[string]string{"one-instance": "pass", "retry-after-timeout": "pass", "instances": "skip", "processes": "skip", "crash-after-claim": "skip"} {
		if got := checkStatus(rep, name); got != want {
			t.Errorf("%s: %s want %s\n%s", name, got, want, rep)
		}
	}
	// a process-scoped store declared shared is refused by the multi-instance guard
	bad := RunPcaStateConformance(PcaStateConformance{StateStoreConformance: StateStoreConformance{Name: "memory-as-shared", Open: func() (StateStore, error) { return st, nil }, Shared: true}})
	if checkStatus(bad, "instances") != "fail" {
		t.Fatalf("a process-scoped store passed as shared:\n%s", bad)
	}
}

func TestPcaStateConformanceCatchesRacyClaim(t *testing.T) {
	st := &racyStore{meet: newRendezvous()} // the racers meet between the read and the write, so the lost update never depends on timing
	rep := RunPcaStateConformance(PcaStateConformance{StateStoreConformance: StateStoreConformance{Name: "racy", Open: func() (StateStore, error) { return st, nil }, Shared: false, Rounds: 3, Copies: 8}})
	if err := st.meet.err(); err != nil {
		t.Fatalf("the racers failed to rendezvous: %v", err)
	}
	if checkStatus(rep, "one-instance") != "fail" {
		t.Fatalf("a racy claim passed one-instance:\n%s", rep)
	}
}

// A claimer the harness withholds from the store is not waited for, and one it released arrives alone; two racers that are both
// in the store still wait for each other (strict pairing).
func TestRendezvousDoesNotWaitForAClaimerTheHarnessHolds(t *testing.T) {
	r := newRendezvous()
	within := func(what string, f func()) {
		t.Helper()
		done := make(chan struct{})
		go func() { f(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("%s blocked", what)
		}
	}
	r.HoldClaim("k")
	within("a claimer while another is withheld", func() { _ = r.wait("k") })
	r.ReleaseClaim("k")
	within("the released claimer", func() { _ = r.wait("k") })
	// no hold is left: two racers pair, and neither finishes before the other has arrived
	arrived := make(chan struct{})
	first := make(chan struct{})
	go func() { _ = r.wait("p"); close(first) }()
	select {
	case <-first:
		t.Fatal("a lone racer returned without a partner")
	case <-time.After(200 * time.Millisecond):
	}
	go func() { close(arrived); _ = r.wait("p") }()
	<-arrived
	within("the pair", func() { <-first })
	if err := r.err(); err != nil {
		t.Fatal(err)
	}
}
