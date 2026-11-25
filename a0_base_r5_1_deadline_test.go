package pca

import (
	"fmt"
	"testing"
	"time"
)

// This file sorts first in the package so that, for a mutant that stops a lock being released or a loop ending, the deadline
// below fails the run before any other covering test can block on it. r5n1within decides such a mutant by an ordinary
// assertion within two seconds.

func r5n1within(t *testing.T, what string, f func()) {
	t.Helper()
	done := make(chan bool, 1)
	go func() {
		defer func() { done <- recover() == nil }()
		f()
	}()
	select {
	case ok := <-done:
		if !ok {
			t.Fatalf("%s panicked", what)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("%s did not return: a lock is still held or a loop does not end", what)
	}
}

// Every method that takes the lock must give it back, a panic aside: a second call would block for ever otherwise.
func TestR5N1_MemorySecretStoreReleasesItsLock(t *testing.T) {
	s := &MemorySecretStore{}
	var got []byte
	r5n1within(t, "MemorySecretStore", func() {
		_ = s.Save([]byte{1})
		_ = s.Save([]byte{2})
		got, _ = s.Load()
		got, _ = s.Load()
		_ = s.Delete()
		_ = s.Delete()
	})
	if len(got) != 1 || got[0] != 2 {
		t.Fatalf("Load after two Saves: %v", got)
	}
	if v, _ := s.Load(); len(v) != 0 {
		t.Fatalf("Load after Delete: %v", v)
	}
}

func TestR5N1_ProtectedReleasesItsLock(t *testing.T) {
	p := Protect(ProtectOptions{})
	r5n1within(t, "Protected", func() {
		p.Revoke("a")
		p.Revoke("b")
		_ = p.isRevoked("a")
		_ = p.isRevoked("a")
	})
	if !p.isRevoked("a") || !p.isRevoked("b") || p.isRevoked("c") {
		t.Fatal("Revoke must refuse exactly the revoked grants")
	}
}

func TestR5N1_ProvenanceRecorderReleasesItsLock(t *testing.T) {
	rec, err := harnessRecorder()
	if err != nil {
		t.Fatal(err)
	}
	op := Operation{Verb: "v", Resource: "r", Params: map[string]any{}}
	var rs []map[string]any
	r5n1within(t, "ProvenanceRecorder", func() {
		_, _ = rec.Principal("a")
		_, _ = rec.Principal("b")
		rs = rec.Receipts()
		rs = rec.Receipts()
		_, _ = rec.ForAction(op)
		_, _ = rec.ForAction(op)
		rs = rec.Receipts()
	})
	if len(rs) != 4 {
		t.Fatalf("two principal receipts and two action receipts, got %d", len(rs))
	}
}

// The consistency walk must end and agree for every pair of small trees (the loops shift both indices to zero).
func TestR5N1_LedgerConsistencyTerminates(t *testing.T) {
	for n := 2; n <= 20; n++ {
		for m := 1; m < n; m++ {
			var got bool
			r5n1within(t, fmt.Sprintf("consistency %d -> %d", m, n), func() {
				got = VerifyLedgerConsistency(g05Root(m), g05Root(n), g05Cons(m, n))
			})
			if !got {
				t.Fatalf("a genuine %d -> %d consistency proof was refused", m, n)
			}
		}
	}
}
