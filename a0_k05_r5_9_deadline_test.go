package pca

import (
	"reflect"
	"testing"
	"time"
)

// This file sorts first in the package so that, for a mutant that stops a loop ending or a lock being released, the deadline
// below fails the run before any other covering test can spin or block on it. r5n9within decides such a mutant by an ordinary
// assertion within two seconds.

func r5n9within(t *testing.T, what string, f func()) {
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
		t.Fatalf("%s did not return: a loop does not end or a lock is still held", what)
	}
}

// The insertion sort must end and order the keys (its index walks up).
func TestR5N9_SortUtf8Terminates(t *testing.T) {
	var got []string
	r5n9within(t, "sortedKeysUtf8", func() {
		got = sortedKeysUtf8(map[string]any{"b": 1, "c": 2, "a": 3})
	})
	if !reflect.DeepEqual(got, []string{"a", "b", "c"}) {
		t.Fatalf("sortedKeysUtf8: %v", got)
	}
}

// The closure walk pops what it visits: without the pop it re-reads the same entry for ever.
func TestR5N9_ClosureTerminates(t *testing.T) {
	var got []string
	var err error
	r5n9within(t, "closure", func() { got, err = coreRegistry.closure([]string{"pca.impersonation"}) })
	if want := []string{"pca.external_communication", "pca.impersonation"}; err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("closure: %v %v", got, err)
	}
	r5n9within(t, "closure of a trait without implies", func() { got, err = coreRegistry.closure([]string{"pca.bulk"}) })
	if want := []string{"pca.bulk"}; err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("closure: %v %v", got, err)
	}
}

// Every method that takes the lock must give it back: a second call would block for ever otherwise.
func TestR5N9_MemoryAtomicKVReleasesItsLock(t *testing.T) {
	s := NewMemoryAtomicKV()
	var v []byte
	var ok bool
	first := []byte{9}
	r5n9within(t, "MemoryAtomicKV", func() {
		_ = s.Update("k", func(prev []byte) []byte { first = prev; return []byte("1") })
		_ = s.Update("k", func(prev []byte) []byte { return append(prev, '2') })
		v, ok, _ = s.Get("k")
		v, ok, _ = s.Get("k")
	})
	if first != nil {
		t.Fatalf("an absent key reaches fn as nil, got %v", first)
	}
	if !ok || string(v) != "12" {
		t.Fatalf("Get: %q %v", v, ok)
	}
	if got, has, _ := s.Get("missing"); has || len(got) != 0 {
		t.Fatalf("Get of a missing key: %q %v", got, has)
	}
}

// A widened step names the step to re-approve; an unreachable definition names none. Both walks must end (the path walk from the
// presented digest back to the pinned one steps to the parent each time).
func TestR5N9_DecidePinTerminates(t *testing.T) {
	k := newKey(t)
	p0, p3, rt := dg("r5n9p0"), dg("r5n9p3"), g04Sha('R')
	w := g04Evo(t, k, "stripe", "stripe.charge", p0, p3, "widen")
	diff, ok := evolutionDiffDigest(w)
	if !ok {
		t.Fatal("diff digest")
	}
	pin := func(recs ...any) map[string]any {
		return decidePin(map[string]any{
			"pin":     map[string]any{"pack": map[string]any{"ns": "stripe", "root": rt}, "defs": map[string]any{"stripe.charge": p0}, "on_new_action": "deny"},
			"verb":    "stripe.charge",
			"doc":     map[string]any{"verbs": []any{map[string]any{"verb": "stripe.charge", "def": p3}}, "pack": map[string]any{"ns": "stripe", "root": rt}},
			"records": recs, "keys": g04RegKeys(k),
		})
	}
	var none, widened map[string]any
	r5n9within(t, "decidePin", func() {
		none = pin()
		widened = pin(w)
	})
	if none["ok"] != false || none["code"] != "def_changed" || none["reason"] != "the definition differs from the pinned digest and no signed evolution record chains to it" {
		t.Fatalf("no record: %v", none)
	}
	if _, has := none["needs_reapproval"]; has {
		t.Fatalf("no record must name no step: %v", none)
	}
	if widened["ok"] != false || widened["code"] != "def_changed" || widened["needs_reapproval"] != diff {
		t.Fatalf("widened: %v (diff %s)", widened, diff)
	}
}
