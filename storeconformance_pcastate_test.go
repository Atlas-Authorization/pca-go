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
	st := &racyStore{}
	rep := RunPcaStateConformance(PcaStateConformance{StateStoreConformance: StateStoreConformance{Name: "racy", Open: func() (StateStore, error) { return st, nil }, Shared: false, Rounds: 3, Copies: 8}})
	if checkStatus(rep, "one-instance") != "fail" {
		t.Fatalf("a racy claim passed one-instance:\n%s", rep)
	}
}
