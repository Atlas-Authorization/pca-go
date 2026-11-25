package pca

import "errors"

// KvStateStore is the durable replay store over any AtomicKV (the reference's durablePcaStateStore): one JSON record per counter
// stream holding the last admitted counter and the stored trust budget, every operation one atomic read-modify-write, so a
// crash-safe, multi-process-safe AtomicKV (NewDurableAtomicKV over OpenDurableState on one host, NewSQLAtomicKV across nodes) makes
// it a shared store. It implements StateStore, BudgetStore, PinStore, LastStore, OnceStore and StoreScope. Over MemoryAtomicKV it
// must be declared ScopeProcess.
type KvStateStore struct {
	kv     AtomicKV
	prefix string
	scope  string
}

// DefaultKvStatePrefix namespaces the keys of a KvStateStore.
const DefaultKvStatePrefix = "pca-state:"

// NewKvStateStore builds the store. An empty prefix is DefaultKvStatePrefix; an empty scope is ScopeShared (declare ScopeProcess
// for an in-memory kv, which Authorize with a multi-instance deployment then refuses).
func NewKvStateStore(kv AtomicKV, prefix, scope string) (*KvStateStore, error) {
	if kv == nil {
		return nil, errors.New("pca: KvStateStore needs an AtomicKV")
	}
	if prefix == "" {
		prefix = DefaultKvStatePrefix
	}
	if scope == "" {
		scope = ScopeShared
	}
	return &KvStateStore{kv: kv, prefix: prefix, scope: scope}, nil
}

// Scope implements StoreScope.
func (s *KvStateStore) Scope() string { return s.scope }

// IsAtomicPcaStateStore is true when st can claim a counter and raise a pin atomically (StateStore and PinStore).
func IsAtomicPcaStateStore(st any) bool {
	_, claims := st.(StateStore)
	_, pins := st.(PinStore)
	return claims && pins
}

type kvStateDoc struct {
	LastCounter *int64         `json:"lastCounter,omitempty"`
	Budget      map[string]any `json:"budget,omitempty"`
}

func (s *KvStateStore) read(prev []byte) kvStateDoc {
	var d kvStateDoc
	if prev != nil {
		if err := kvDecode(prev, &d); err != nil {
			panic(err) // a corrupt record is never an empty one: the claim fails closed (kv Update surfaces the panic as an error)
		}
	}
	return d
}

func (s *KvStateStore) update(key string, fn func(d *kvStateDoc) bool) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errStoreState
		}
	}()
	return s.kv.Update(s.prefix+key, func(prev []byte) []byte {
		d := s.read(prev)
		if !fn(&d) {
			return nil
		}
		return kvEncode(d)
	})
}

// Claim implements StateStore: the counter is consumed iff it is strictly greater than the stored one.
func (s *KvStateStore) Claim(key string, counter int64) (ClaimResult, error) {
	res := ClaimResult{}
	err := s.update(key, func(d *kvStateDoc) bool {
		if d.LastCounter != nil && !(counter > *d.LastCounter) {
			last := *d.LastCounter
			res = ClaimResult{OK: false, LastCounter: &last}
			return false
		}
		c := counter
		d.LastCounter = &c
		res = ClaimResult{OK: true}
		return true
	})
	if err != nil {
		return ClaimResult{}, err
	}
	return res, nil
}

// Last implements LastStore.
func (s *KvStateStore) Last(key string) (last *int64, err error) {
	defer func() {
		if r := recover(); r != nil {
			last, err = nil, errStoreState
		}
	}()
	raw, ok, gerr := s.kv.Get(s.prefix + key)
	if gerr != nil {
		return nil, gerr
	}
	if !ok {
		return nil, nil
	}
	return s.read(raw).LastCounter, nil
}

// Budget implements BudgetStore.
func (s *KvStateStore) Budget(key string) (map[string]any, error) {
	raw, ok, err := s.kv.Get(s.prefix + key)
	if err != nil || !ok {
		return nil, err
	}
	var d kvStateDoc
	if derr := kvDecode(raw, &d); derr != nil {
		return nil, derr
	}
	if d.Budget == nil {
		return nil, nil
	}
	return cloneBudget(d.Budget), nil
}

// ClaimBudgeted implements BudgetStore in one atomic step: the counter and the budget move together.
func (s *KvStateStore) ClaimBudgeted(key string, counter int64, before, after map[string]any) (BudgetClaim, ClaimResult, error) {
	claim, res := BudgetClaimed, ClaimResult{}
	err := s.update(key, func(d *kvStateDoc) bool {
		if d.LastCounter != nil && !(counter > *d.LastCounter) {
			last := *d.LastCounter
			claim, res = BudgetReplay, ClaimResult{OK: false, LastCounter: &last}
			return false
		}
		if !budgetEqual(d.Budget, d.Budget != nil, before) {
			claim, res = BudgetConflict, ClaimResult{}
			return false
		}
		c := counter
		d.LastCounter = &c
		if after != nil {
			d.Budget = cloneBudget(after)
		}
		claim, res = BudgetClaimed, ClaimResult{OK: true}
		return true
	})
	if err != nil {
		return 0, ClaimResult{}, err
	}
	return claim, res, nil
}

// Pin implements PinStore.
func (s *KvStateStore) Pin(key string) (*float64, error) {
	raw, ok, err := s.kv.Get(s.prefix + "pin:" + key)
	if err != nil || !ok {
		return nil, err
	}
	var v float64
	if derr := kvDecode(raw, &v); derr != nil {
		return nil, derr
	}
	return &v, nil
}

// RaisePin implements PinStore: the pin only ever rises.
func (s *KvStateStore) RaisePin(key string, v float64) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errStoreState
		}
	}()
	return s.kv.Update(s.prefix+"pin:"+key, func(prev []byte) []byte {
		if prev != nil {
			var old float64
			if derr := kvDecode(prev, &old); derr != nil {
				panic(derr)
			}
			if !(v > old) {
				return nil
			}
		}
		return kvEncode(v)
	})
}

// ConsumeOnce implements OnceStore: true iff key has no live record (retainUntil >= now); a live record is never shortened.
func (s *KvStateStore) ConsumeOnce(key string, retainUntilMs, nowMs int64) (bool, error) {
	if key == "" || retainUntilMs < nowMs {
		return false, ErrConsumeOnce
	}
	first := false
	err := func() (err error) {
		defer func() {
			if r := recover(); r != nil {
				err = errStoreState
			}
		}()
		return s.kv.Update(s.prefix+"once:"+key, func(prev []byte) []byte {
			if prev != nil {
				var r int64
				if derr := kvDecode(prev, &r); derr != nil {
					panic(derr)
				}
				if r >= nowMs {
					first = false
					if retainUntilMs > r {
						return kvEncode(retainUntilMs)
					}
					return nil
				}
			}
			first = true
			return kvEncode(retainUntilMs)
		})
	}()
	if err != nil {
		return false, err
	}
	return first, nil
}
