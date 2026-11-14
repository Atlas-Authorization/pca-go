package pca

import (
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
)

// The atomic budget seam of the replay store: the trust budget of a counter stream is stored next to its counter, and a metered
// action's debit is written in the SAME atomic step as the replay claim (the reference atomic claim with budgetBefore / budgetAfter).

// BudgetClaim is what BudgetStore.ClaimBudgeted returns.
type BudgetClaim int

const (
	// BudgetClaimed: the counter was consumed and the budget stored.
	BudgetClaimed BudgetClaim = iota
	// BudgetReplay: the counter was not consumed (the result carries the stored counter when known).
	BudgetReplay
	// BudgetConflict: the stored budget changed since it was read; nothing was written.
	BudgetConflict
)

// BudgetStore is the optional budget side of a StateStore. Budget(key) is the stored budget of a stream ({"B","tau","asOf"} as
// decoded JSON; nil: none). ClaimBudgeted(key, counter, before, after) is ONE atomic operation: if the counter is not greater than
// the stored one it returns BudgetReplay (writing nothing); else if the stored budget is not equal to `before` (nil = none stored)
// it returns BudgetConflict (writing nothing); else it stores the counter and `after` and returns BudgetClaimed. A store without it
// cannot admit a metered action: the call is refused (a spend must never be forgotten).
type BudgetStore interface {
	Budget(key string) (map[string]any, error)
	ClaimBudgeted(key string, counter int64, before, after map[string]any) (BudgetClaim, ClaimResult, error)
}

// Budget implements BudgetStore.
func (s *MemoryStateStore) Budget(key string) (map[string]any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if b, has := s.budgets[key]; has {
		return cloneBudget(b), nil
	}
	return nil, nil
}

// ClaimBudgeted implements BudgetStore: the counter and the budget move together under one lock.
func (s *MemoryStateStore) ClaimBudgeted(key string, counter int64, before, after map[string]any) (BudgetClaim, ClaimResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if last, has := s.last[key]; has && !(counter > last) {
		return BudgetReplay, ClaimResult{OK: false, LastCounter: &last}, nil
	}
	cur, has := s.budgets[key]
	if !budgetEqual(cur, has, before) {
		return BudgetConflict, ClaimResult{}, nil
	}
	if s.last == nil {
		s.last = map[string]int64{}
	}
	s.last[key] = counter
	if after != nil {
		if s.budgets == nil {
			s.budgets = map[string]map[string]any{}
		}
		s.budgets[key] = cloneBudget(after)
	}
	return BudgetClaimed, ClaimResult{OK: true}, nil
}

func cloneBudget(b map[string]any) map[string]any {
	out := make(map[string]any, len(b))
	for k, v := range b {
		out[k] = v
	}
	return out
}

// budgetEqual compares a stored budget with the one a decision read (nil = none).
func budgetEqual(cur map[string]any, has bool, before map[string]any) bool {
	if !has || cur == nil {
		return before == nil
	}
	if before == nil {
		return false
	}
	return reflect.DeepEqual(canonBudget(cur), canonBudget(before))
}

// canonBudget normalizes numbers so a budget that went through JSON compares equal to the one that did not.
func canonBudget(b map[string]any) map[string]float64 {
	out := map[string]float64{}
	for k, v := range b {
		if f, ok := jsNum(v); ok {
			out[k] = f
		}
	}
	return out
}

// ---- SQL ----------------------------------------------------------------------------------------------------------------

// Budget implements BudgetStore over the `<table>_budget` table.
func (s *SQLStateStore) Budget(key string) (map[string]any, error) {
	var raw string
	switch err := s.db.QueryRow(s.budgetReadSQL, key).Scan(&raw); {
	case errors.Is(err, sql.ErrNoRows):
		return nil, nil
	case err != nil:
		return nil, err
	}
	return decodeBudget(raw)
}

func decodeBudget(raw string) (map[string]any, error) {
	var m map[string]any
	if err := kvDecode([]byte(raw), &m); err != nil || m == nil {
		return nil, errStoreState
	}
	return m, nil
}

// ClaimBudgeted implements BudgetStore in one transaction: the counter upsert, then the budget compare-and-set. The budget row is
// created or replaced only when the stored value still equals `before`; otherwise the transaction is rolled back (the counter too).
func (s *SQLStateStore) ClaimBudgeted(key string, counter int64, before, after map[string]any) (BudgetClaim, ClaimResult, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, ClaimResult{}, err
	}
	defer tx.Rollback() //nolint:errcheck // a committed transaction ignores it
	res, err := tx.Exec(s.claimSQL, key, counter)
	if err != nil {
		return 0, ClaimResult{}, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, ClaimResult{}, err
	}
	if n != 1 {
		var last int64
		if tx.QueryRow(s.readSQL, key).Scan(&last) != nil {
			return BudgetReplay, ClaimResult{}, nil
		}
		return BudgetReplay, ClaimResult{OK: false, LastCounter: &last}, nil
	}
	if after != nil {
		enc, err := json.Marshal(after)
		if err != nil {
			return 0, ClaimResult{}, err
		}
		var raw string
		qerr := tx.QueryRow(s.budgetReadSQL, key).Scan(&raw)
		switch {
		case errors.Is(qerr, sql.ErrNoRows):
			if before != nil {
				return BudgetConflict, ClaimResult{}, nil
			}
			if _, err := tx.Exec(s.budgetInsertSQL, key, string(enc)); err != nil {
				return BudgetConflict, ClaimResult{}, nil // a concurrent insert of the same row: the budget changed under us
			}
		case qerr != nil:
			return 0, ClaimResult{}, qerr
		default:
			cur, derr := decodeBudget(raw)
			if derr != nil || !budgetEqual(cur, true, before) {
				return BudgetConflict, ClaimResult{}, nil
			}
			if _, err := tx.Exec(s.budgetUpdateSQL, string(enc), key, raw); err != nil {
				return 0, ClaimResult{}, err
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, ClaimResult{}, err
	}
	return BudgetClaimed, ClaimResult{OK: true}, nil
}
