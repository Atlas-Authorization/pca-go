package pca

// Durable round-1 nonce persistence for a FROST signer, built so a restart can neither lose a session nor reuse a nonce. The rule that
// prevents reuse across restarts is ORDER: the nonce is durably marked spent BEFORE the signature share is computed. A crash after
// the mark loses that session (the coordinator opens a new one); a crash before it leaves an unspent nonce that can still be used
// exactly once. The store never has to be trusted to forget a nonce: Spend removes the secret bytes and keeps only the marker.
//
// The contract every implementation must meet (AssertFrostNonceStoreContract checks it): Create is durable before it returns and fails
// if the session id exists in ANY state; Load returns the live record (a copy) or nil; Spend is atomic and durable, fails unless the
// session is live, deletes the secret nonces and records the id as spent forever, and a second Spend fails; IsSpent is true for every
// spent id, also after a restart; every method returns an error on failure and the signer treats any error as a refusal (fail closed).
// The records hold SECRET nonces: a durable store must encrypt them at rest.

import (
	"errors"
	"sync"
)

// FrostNonceRecord is the round-1 state of one session: the secret 32-byte little-endian hiding and binding nonce scalars, the public
// commitments emitted in round 1 and the wall-clock ms at which round 1 opened the session.
type FrostNonceRecord struct {
	Hiding, Binding, HidingCommitment, BindingCommitment []byte
	CreatedAt                                            float64
}

func (r FrostNonceRecord) clone() FrostNonceRecord {
	return FrostNonceRecord{Hiding: append([]byte{}, r.Hiding...), Binding: append([]byte{}, r.Binding...),
		HidingCommitment: append([]byte{}, r.HidingCommitment...), BindingCommitment: append([]byte{}, r.BindingCommitment...), CreatedAt: r.CreatedAt}
}

// FrostNonceStore persists round-1 nonces (see the contract above).
type FrostNonceStore interface {
	Create(sessionID string, r FrostNonceRecord) error
	// Load returns a copy of the live record, or nil when the id is spent, dropped or unknown.
	Load(sessionID string) (*FrostNonceRecord, error)
	Spend(sessionID string) error
	Drop(sessionID string) error
	IsSpent(sessionID string) (bool, error)
}

// MemoryFrostNonceStore is the reference implementation: correct, not durable (a process restart loses it, which fails closed).
type MemoryFrostNonceStore struct {
	mu    sync.Mutex
	live  map[string]FrostNonceRecord
	spent map[string]bool
}

// NewMemoryFrostNonceStore returns an empty store.
func NewMemoryFrostNonceStore() *MemoryFrostNonceStore {
	return &MemoryFrostNonceStore{live: map[string]FrostNonceRecord{}, spent: map[string]bool{}}
}

// Create implements FrostNonceStore.
func (s *MemoryFrostNonceStore) Create(id string, r FrostNonceRecord) error {
	if id == "" {
		return errors.New("nonce-store: session id must be a non-empty string")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, has := s.live[id]; has || s.spent[id] {
		return errors.New("nonce-store: session already exists")
	}
	s.live[id] = r.clone()
	return nil
}

// Load implements FrostNonceStore.
func (s *MemoryFrostNonceStore) Load(id string) (*FrostNonceRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.live[id]
	if !ok {
		return nil, nil
	}
	c := r.clone()
	return &c, nil
}

// Spend implements FrostNonceStore.
func (s *MemoryFrostNonceStore) Spend(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.live[id]
	if !ok {
		return errors.New("nonce-store: cannot spend a session that is not live")
	}
	clear(r.Hiding)
	clear(r.Binding)
	delete(s.live, id)
	s.spent[id] = true
	return nil
}

// Drop implements FrostNonceStore.
func (s *MemoryFrostNonceStore) Drop(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r, ok := s.live[id]; ok {
		clear(r.Hiding)
		clear(r.Binding)
		delete(s.live, id)
	}
	return nil
}

// IsSpent implements FrostNonceStore.
func (s *MemoryFrostNonceStore) IsSpent(id string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.spent[id], nil
}

// AssertFrostNonceStoreContract checks a store against the contract. reopen must return a store over the SAME durable state (a
// simulated restart); nil means the same instance. The first violation is returned as an error that starts "nonce-store contract: ".
func AssertFrostNonceStoreContract(mk func() FrostNonceStore, reopen func(FrostNonceStore) FrostNonceStore) error {
	if reopen == nil {
		reopen = func(s FrostNonceStore) FrostNonceStore { return s }
	}
	rec := func(n byte) FrostNonceRecord {
		fill := func(v byte) []byte {
			b := make([]byte, 32)
			for i := range b {
				b[i] = v
			}
			return b
		}
		return FrostNonceRecord{Hiding: fill(n), Binding: fill(n + 1), HidingCommitment: fill(n + 2), BindingCommitment: fill(n + 3), CreatedAt: float64(n)}
	}
	must := func(ok bool, what string) error {
		if !ok {
			return errors.New("nonce-store contract: " + what)
		}
		return nil
	}
	fails := func(err error) bool { return err != nil }
	s := mk()
	live := func(id string) *FrostNonceRecord { r, _ := s.Load(id); return r }
	spent := func(id string) bool { b, _ := s.IsSpent(id); return b }
	checks := []func() error{
		func() error { return must(live("a") == nil && !spent("a"), "an unknown id is neither live nor spent") },
		func() error { _ = s.Create("a", rec(1)); return nil },
		func() error { return must(fails(s.Create("a", rec(9))), "create must refuse an existing live id") },
		func() error { _ = s.Create("b", rec(5)); s = reopen(s); return nil },
		func() error {
			got := live("a")
			return must(got != nil && got.Hiding[0] == 1 && got.CreatedAt == 1, "a live record survives a restart")
		},
		func() error {
			if got := live("a"); got != nil {
				for i := range got.Hiding {
					got.Hiding[i] = 0xee
				}
			}
			again := live("a")
			return must(again != nil && again.Hiding[0] == 1, "load returns a copy")
		},
		func() error {
			_ = s.Spend("a")
			return must(live("a") == nil && spent("a"), "spend removes the secret and records the marker")
		},
		func() error { return must(fails(s.Spend("a")), "a second spend must throw") },
		func() error { return must(fails(s.Create("a", rec(2))), "create must refuse a spent id") },
		func() error { return must(fails(s.Spend("zzz")), "spend of an unknown id must throw") },
		func() error {
			s = reopen(s)
			return must(spent("a") && live("a") == nil, "a spent marker survives a restart")
		},
		func() error { return must(live("b") != nil, "the other live record survives") },
		func() error {
			_ = s.Drop("b")
			return must(live("b") == nil && !spent("b"), "drop removes a live record without marking it spent")
		},
		func() error { _ = s.Drop("never-existed"); return nil },
	}
	for _, c := range checks {
		if err := c(); err != nil {
			return err
		}
	}
	return nil
}
