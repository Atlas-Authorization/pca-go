package pca

import (
	"bytes"
	"errors"
	"sync"
	"testing"
)

// H13: the revocation-epoch rollback pin lives in the state store; the host does not have to supply it.

func TestH13_MemoryPinStoreIsMonotone(t *testing.T) {
	s := NewMemoryStateStore()
	if v, err := s.Pin("g:epoch"); v != nil || err != nil {
		t.Fatalf("empty: %v %v", v, err)
	}
	for _, c := range []struct{ raise, want float64 }{{5, 5}, {4, 5}, {5, 5}, {7, 7}, {6, 7}} {
		if err := s.RaisePin("g:epoch", c.raise); err != nil {
			t.Fatal(err)
		}
		if v, _ := s.Pin("g:epoch"); v == nil || *v != c.want {
			t.Fatalf("after raising %v: %v, want %v", c.raise, v, c.want)
		}
	}
	// another key is independent
	if v, _ := s.Pin("h:epoch"); v != nil {
		t.Errorf("other key: %v", *v)
	}
	// concurrent raises end at the maximum
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n float64) {
			defer wg.Done()
			_ = s.RaisePin("c:epoch", n)
		}(float64(i))
	}
	wg.Wait()
	if v, _ := s.Pin("c:epoch"); v == nil || *v != 49 {
		t.Errorf("concurrent: %v", v)
	}
}

type pinFault struct {
	*MemoryStateStore
	failRead, failRaise, panicRead bool
}

func (p pinFault) Pin(k string) (*float64, error) {
	if p.panicRead {
		panic("boom")
	}
	if p.failRead {
		return nil, errors.New("down")
	}
	return p.MemoryStateStore.Pin(k)
}

func (p pinFault) RaisePin(k string, v float64) error {
	if p.failRaise {
		return errors.New("down")
	}
	return p.MemoryStateStore.RaisePin(k, v)
}

func TestH13_WithRollbackPin(t *testing.T) {
	mem := NewMemoryStateStore()
	grant := map[string]any{"id": "g"}
	epoch := map[string]any{"epoch": 5}
	five := 5.0
	// no stored pin: the host's value stays
	st, key, why := withRollbackPin(mem, &RevocationState{Epoch: epoch, LastAcceptedEpoch: &five}, grant)
	if why != "" || key != "g:epoch" || st.LastAcceptedEpoch == nil || *st.LastAcceptedEpoch != 5 {
		t.Fatalf("host only: %+v %q %q", st, key, why)
	}
	_ = mem.RaisePin("g:epoch", 7)
	// the stored pin wins over a lower host value, and over none
	st, _, _ = withRollbackPin(mem, &RevocationState{Epoch: epoch, LastAcceptedEpoch: &five}, grant)
	if *st.LastAcceptedEpoch != 7 {
		t.Errorf("pin over host: %v", *st.LastAcceptedEpoch)
	}
	st, _, _ = withRollbackPin(mem, &RevocationState{Epoch: epoch}, grant)
	if st.LastAcceptedEpoch == nil || *st.LastAcceptedEpoch != 7 {
		t.Errorf("pin, no host value: %v", st.LastAcceptedEpoch)
	}
	// a higher host value is kept
	nine := 9.0
	st, _, _ = withRollbackPin(mem, &RevocationState{Epoch: epoch, LastAcceptedEpoch: &nine}, grant)
	if *st.LastAcceptedEpoch != 9 {
		t.Errorf("host over pin: %v", *st.LastAcceptedEpoch)
	}
	// the caller's state is not modified
	orig := &RevocationState{Epoch: epoch}
	withRollbackPin(mem, orig, grant)
	if orig.LastAcceptedEpoch != nil {
		t.Error("the state was modified in place")
	}
	// no signed epoch (a bare root), no state: nothing to pin
	for _, s := range []*RevocationState{nil, {Root: "r"}} {
		if got, key, why := withRollbackPin(mem, s, grant); got != s || key != "" || why != "" {
			t.Errorf("no epoch: %v %q %q", got, key, why)
		}
	}
	// fail closed: a grant without a readable id, a store without pins, a failing or panicking read
	if _, _, why := withRollbackPin(mem, &RevocationState{Epoch: epoch}, map[string]any{}); why == "" {
		t.Error("no grant id")
	}
	if _, _, why := withRollbackPin(mem, &RevocationState{Epoch: epoch}, map[string]any{"id": ""}); why == "" {
		t.Error("empty grant id")
	}
	if _, _, why := withRollbackPin(unscopedStore{}, &RevocationState{Epoch: epoch}, grant); why == "" {
		t.Error("store without pins")
	}
	for name, f := range map[string]pinFault{"error": {MemoryStateStore: mem, failRead: true}, "panic": {MemoryStateStore: mem, panicRead: true}} {
		if _, _, why := withRollbackPin(f, &RevocationState{Epoch: epoch}, grant); why != "the revocation pin store failed (fail closed)" {
			t.Errorf("%s read: %q", name, why)
		}
	}
	if !raisePin(pinFault{MemoryStateStore: mem, failRaise: true}, "g:epoch", 8) || raisePin(mem, "g:epoch", 8) {
		t.Error("raisePin failure reporting")
	}
}

// With a pin of 7, a replayed epoch 5 is a rollback although the host gave no lastAcceptedEpoch; a newer one passes.
func TestH13_PinTurnsAReplayedEpochIntoARollback(t *testing.T) {
	seed := bytes.Repeat([]byte{0x71}, 32)
	ep := g05Epoch(t, seed) // epoch 5, grant "g"
	in := AuthorizeInput{Risk: InsecureCalmRisk, RevocationStaleness: &RevocationStalenessPolicy{}, GuardianPublic: ep["guardian"].(string)}
	p := map[string]any{"grant_ref": "g", "action": map[string]any{"reversibility_class": "reversible"}, "cap_chain": []any{}}
	mem := NewMemoryStateStore()
	grant := map[string]any{"id": "g"}
	run := func() string {
		st, _, why := withRollbackPin(mem, &RevocationState{Epoch: ep}, grant)
		if why != "" {
			return why
		}
		return revocationFreshness(in, &AuthorizeContext{}, p, st, 2000)
	}
	if got := run(); got != "" {
		t.Fatalf("no pin: %q", got)
	}
	_ = mem.RaisePin("g:epoch", 5)
	if got := run(); got != "" {
		t.Fatalf("pin equal to the epoch: %q", got)
	}
	_ = mem.RaisePin("g:epoch", 7)
	if got := run(); got != "revocation epoch 5 is older than the last accepted 7 (rollback)" {
		t.Fatalf("pin 7: %q", got)
	}
	if got := verifiedEpoch(&RevocationState{Epoch: ep}); got == nil || *got != 5 {
		t.Errorf("verifiedEpoch: %v", got)
	}
	if verifiedEpoch(nil) != nil || verifiedEpoch(&RevocationState{Root: "r"}) != nil || verifiedEpoch(&RevocationState{Epoch: map[string]any{"epoch": "5"}}) != nil {
		t.Error("verifiedEpoch of a non-epoch")
	}
}

// Staleness with a store that cannot hold pins is a configuration error.
func TestH13_StalenessNeedsAPinStore(t *testing.T) {
	maxAge := 60000.0
	in := AuthorizeInput{Risk: InsecureCalmRisk, Audience: "a", ResolveGrant: func(string) (map[string]any, error) { return nil, nil },
		IsRevoked: func(_, _ map[string]any) (bool, error) { return false, nil }, StateStore: unscopedStore{},
		RevocationStaleness: &RevocationStalenessPolicy{MaxRevocationAgeMs: &maxAge}, RevocationState: func(_, _ map[string]any) (*RevocationState, error) { return nil, nil }}
	want := "revocation staleness needs a state store that implements pins (rollback protection)"
	found := false
	for _, m := range MissingAuthorizeComponents(in) {
		found = found || m == want
	}
	if !found {
		t.Errorf("missing: %v", MissingAuthorizeComponents(in))
	}
	in.StateStore = NewMemoryStateStore()
	for _, m := range MissingAuthorizeComponents(in) {
		if m == want {
			t.Error("a pin store was refused")
		}
	}
}
