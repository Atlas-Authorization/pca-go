package pcasigstore

import (
	"bytes"
	"testing"
	"time"
)

// This file sorts first so that a mutant that stops a loop from ending fails here, within two seconds, by an ordinary assertion.
func r5n7within(t *testing.T, what string, f func()) {
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
		t.Fatalf("%s did not return: a loop does not end", what)
	}
}

// The SCT list walk advances past an entry it skips (an unpinned log).
func TestR5N7_SCTListWalkEnds(t *testing.T) {
	f := newSCTFixture(t)
	issuer := fullCert(f.ca.Raw)
	other := bytes.Repeat([]byte{7}, 32)
	leaf, _ := f.leaf(func(tbs []byte) []byte {
		return list(append(entry(f.sct(tbs, other, nil, nil)), entry(f.sct(tbs, other, nil, nil))...))
	})
	var got string
	r5n7within(t, "verifySCT", func() { got = verifySCT(leaf, issuer, f.roots) })
	if got != "no SCT from a pinned CT log" {
		t.Fatalf("got %q", got)
	}
}
