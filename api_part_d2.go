package pca

import (
	"errors"
	"fmt"
	"sync"
)

// ProvLevels are the provenance levels of an argument, from most to least trusted.
var ProvLevels = []string{"trusted", "first_party", "tool", "web", "agent"}

// ActionUnitTagOf is the envelope unit tag of a def's unit declaration ({kind, currency?, exponent?}); nil for a money unit
// without a currency (it has no tag).
func ActionUnitTagOf(u map[string]any) map[string]any {
	kind, _ := u["kind"].(string)
	if kind != "money" {
		return map[string]any{"kind": u["kind"]}
	}
	ccy, ok := u["ccy"].(string)
	if !ok {
		return nil
	}
	t := map[string]any{"kind": "money", "currency": ccy}
	if e, has := u["exp"]; has {
		t["exponent"] = e
	}
	return t
}

// ScittRegisterStatement registers a signed statement with a transparency service.
func ScittRegisterStatement(statement []byte, svc *ScittTransparencyService) (*ScittRegistration, error) {
	return svc.Register(statement)
}

// MemoryIntentSessionStore is the in-process IntentSessionStore: one lock per session, history forgotten on restart (Durable is
// false, so a deployment that needs the caps to survive a restart must bring its own store).
type MemoryIntentSessionStore struct {
	mu    sync.Mutex
	logs  map[string][]map[string]any
	locks map[string]*sync.Mutex
}

// NewMemoryIntentSessionStore returns an empty store.
func NewMemoryIntentSessionStore() *MemoryIntentSessionStore {
	return &MemoryIntentSessionStore{logs: map[string][]map[string]any{}, locks: map[string]*sync.Mutex{}}
}

// Durable is false: the history does not survive the process.
func (s *MemoryIntentSessionStore) Durable() bool { return false }

type memIntentTx struct {
	s       *MemoryIntentSessionStore
	session string
}

// WithSession runs fn under the session's exclusive lock.
func (s *MemoryIntentSessionStore) WithSession(session string, fn func(tx SessionTx) error) error {
	s.mu.Lock()
	l := s.locks[session]
	if l == nil {
		l = &sync.Mutex{}
		s.locks[session] = l
	}
	s.mu.Unlock()
	l.Lock()
	defer l.Unlock()
	return fn(memIntentTx{s, session})
}

func (t memIntentTx) Events() ([]any, error) {
	t.s.mu.Lock()
	defer t.s.mu.Unlock()
	out := make([]any, 0, len(t.s.logs[t.session]))
	for _, e := range t.s.logs[t.session] {
		out = append(out, ixCopyMap(e))
	}
	return out, nil
}

func (t memIntentTx) Append(e map[string]any) error {
	t.s.mu.Lock()
	defer t.s.mu.Unlock()
	for _, x := range t.s.logs[t.session] {
		if x["id"] == e["id"] {
			return errors.New("duplicate event id")
		}
	}
	t.s.logs[t.session] = append(t.s.logs[t.session], ixCopyMap(e))
	return nil
}

func (t memIntentTx) SetStatus(id, status string) (bool, error) {
	t.s.mu.Lock()
	defer t.s.mu.Unlock()
	for _, e := range t.s.logs[t.session] {
		if e["id"] == any(id) {
			e["status"] = status
			return true, nil
		}
	}
	return false, nil
}

// Snapshot is a copy of the session's events.
func (s *MemoryIntentSessionStore) Snapshot(session string) []map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]map[string]any, 0, len(s.logs[session]))
	for _, e := range s.logs[session] {
		out = append(out, ixCopyMap(e))
	}
	return out
}

// BondAccount is the funds side a bond ledger moves money on.
type BondAccount interface {
	BalanceOf(account string) float64
	Debit(account string, amount float64) error
	Credit(account string, amount float64) error
}

// InMemoryBondAccount is the in-memory BondAccount (tests and reference). Balances move in exact micro-units when on that grid.
type InMemoryBondAccount struct {
	mu       sync.Mutex
	balances map[string]float64
}

// NewInMemoryBondAccount seeds the balances.
func NewInMemoryBondAccount(initial map[string]float64) *InMemoryBondAccount {
	b := &InMemoryBondAccount{balances: map[string]float64{}}
	for k, v := range initial {
		b.balances[k] = v
	}
	return b
}

// BalanceOf is the balance of an account (0 for an unknown one).
func (b *InMemoryBondAccount) BalanceOf(account string) float64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.balances[account]
}

func bondAmountOK(a float64) bool { return a >= 0 && a-a == 0 }

// Debit removes amount; it refuses a negative or non-finite amount and an overdraft.
func (b *InMemoryBondAccount) Debit(account string, amount float64) error {
	if !bondAmountOK(amount) {
		return errors.New("debit: invalid amount")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.balances[account] < amount {
		return fmt.Errorf("debit: insufficient balance for %s", account)
	}
	b.balances[account] = ExactAdd(b.balances[account], amount, -1)
	return nil
}

// Credit adds amount; it refuses a negative or non-finite amount.
func (b *InMemoryBondAccount) Credit(account string, amount float64) error {
	if !bondAmountOK(amount) {
		return errors.New("credit: invalid amount")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.balances[account] = ExactAdd(b.balances[account], amount, 1)
	return nil
}
