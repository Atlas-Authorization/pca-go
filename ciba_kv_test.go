package pca

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func kvTestStore(t *testing.T, timeout time.Duration) (ApprovalStore, string) {
	t.Helper()
	dir := t.TempDir()
	kv, err := NewDirectoryKv(dir, timeout)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewKvApprovalStore(kv)
	if err != nil {
		t.Fatal(err)
	}
	return s, dir
}

func TestKvApprovalStoreVersionsAndCas(t *testing.T) {
	s, _ := kvTestStore(t, 0)
	if v, err := s.Get("k"); v != nil || err != nil {
		t.Fatalf("absent key: %v %v", v, err)
	}
	if ok, err := s.Cas("k", 1, "x"); ok || err != nil {
		t.Fatalf("a stale expected version won: %v %v", ok, err)
	}
	if ok, err := s.Cas("k", 0, map[string]any{"a": 1.0}); !ok || err != nil {
		t.Fatalf("first write: %v %v", ok, err)
	}
	if ok, _ := s.Cas("k", 0, "again"); ok {
		t.Fatal("the same expected version won twice")
	}
	if ok, _ := s.Cas("k", 1, "two"); !ok {
		t.Fatal("the next version was refused")
	}
	if v, err := s.Get("k"); err != nil || v.Version != 2 || v.Value != "two" {
		t.Fatalf("get: %+v %v", v, err)
	}
}

func TestKvApprovalStoreRaceHasOneWinner(t *testing.T) {
	s, _ := kvTestStore(t, 0)
	var wins int32
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ok, err := s.Cas("race", 0, "v"); err == nil && ok {
				atomic.AddInt32(&wins, 1)
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("%d writers won", wins)
	}
}

func TestKvApprovalStoreFailsClosed(t *testing.T) {
	s, dir := kvTestStore(t, 20*time.Millisecond)
	code := func(err error) string {
		var ce *CodedError
		if errors.As(err, &ce) {
			return ce.Code
		}
		return ""
	}
	if _, err := s.Get(""); code(err) != ApprovalBadKey {
		t.Fatalf("empty key: %v", err)
	}
	if ok, _ := s.Cas("k", 0, "x"); !ok {
		t.Fatal("seed write")
	}
	// a corrupt record is an error, never a missing one
	for _, raw := range []string{"not json", `{"version":0,"value":1}`, `{"version":1.5,"value":1}`, `{"version":1}`} {
		entries, _ := os.ReadDir(dir)
		for _, e := range entries {
			os.WriteFile(filepath.Join(dir, e.Name()), []byte(raw), 0o600)
		}
		if _, err := s.Get("k"); code(err) != ApprovalCorruptRecord {
			t.Fatalf("%q: %v", raw, err)
		}
		if _, err := s.Cas("k", 1, "y"); code(err) != ApprovalCorruptRecord {
			t.Fatalf("cas over %q: %v", raw, err)
		}
	}
	// a lock left behind by a dead process fails every swap closed
	entries, _ := os.ReadDir(dir)
	os.WriteFile(filepath.Join(dir, entries[0].Name()), []byte(`{"version":1,"value":"x"}`), 0o600) // a valid record: the lock is what fails
	os.WriteFile(filepath.Join(dir, entries[0].Name()+".lock"), nil, 0o600)
	if _, err := s.Cas("k", 1, "z"); code(err) != ApprovalLockTimeout {
		t.Fatalf("stale lock: %v", err)
	}
	if _, err := NewDirectoryKv(dir, -1); err == nil {
		t.Fatal("a negative timeout was accepted")
	}
}
