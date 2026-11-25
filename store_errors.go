package pca

import (
	"errors"
	"math"
)

// Typed failures shared by the durable stores: the coded LedgerStoreError and BondStoreError (the budget ledger has its own
// BudgetLedgerError) and StoreRangeError for an argument outside its range (the reference's RangeError: the caller's bug, never a
// store state). Code is stable; the message is "<code>: <text>" for the coded errors.

// LedgerStoreError is the typed failure of every store-backed ledger operation. Code is one of store_missing, guardian_key_missing,
// pin_missing, rollback, tamper, forged_checkpoint, inconsistent, store_corrupt, store_unavailable, invalid_commit, clock_invalid,
// conflict.
type LedgerStoreError struct {
	Code    string
	Message string
}

// Error implements error: "<code>: <message>".
func (e *LedgerStoreError) Error() string { return e.Code + ": " + e.Message }

// BondStoreError is the typed failure of every store-backed bond operation. Code is one of store_missing, guardian_key_missing,
// clock_invalid, store_unavailable, store_corrupt, invalid_claim, window_open, window_closed, unregistered, claim_mismatch, conflict.
type BondStoreError struct {
	Code    string
	Message string
}

// Error implements error: "<code>: <message>".
func (e *BondStoreError) Error() string { return e.Code + ": " + e.Message }

// StoreRangeError is an argument a store refuses; nothing was written.
type StoreRangeError struct{ Message string }

// Error implements error.
func (e *StoreRangeError) Error() string { return e.Message }

func storeRange(msg string) error { return &StoreRangeError{msg} }

// StoreErrorCode is the stable code of a store error: its Code for a coded error (ledger, bond or budget), "RangeError" for an
// argument error, "Error" for anything else.
func StoreErrorCode(err error) string {
	var le *LedgerStoreError
	var be *BondStoreError
	var bg *BudgetLedgerError
	var sr *StoreRangeError
	var br *BudgetRangeError
	switch {
	case errors.As(err, &le):
		return le.Code
	case errors.As(err, &be):
		return be.Code
	case errors.As(err, &bg):
		return bg.Code
	case errors.As(err, &sr), errors.As(err, &br):
		return "RangeError"
	}
	return "Error"
}

// storeKvTxn runs one atomic read-modify-write of key: fn gets the stored bytes (nil when absent) and returns the new bytes, or nil
// to leave the key untouched. fn may run more than once (an optimistic kv retries); its last error is the one returned.
func storeKvTxn(kv AtomicKV, key string, fn func(prev []byte) ([]byte, error)) error {
	var ferr error
	err := kv.Update(key, func(prev []byte) []byte {
		ferr = nil
		out, e := fn(prev)
		if e != nil {
			ferr = e
			return nil
		}
		return out
	})
	if err != nil {
		return err
	}
	return ferr
}

// storeSafeInt reads a JSON number that is a safe integer (JavaScript Number.isSafeInteger, -0 included).
func storeSafeInt(v any) (int64, bool) {
	f, ok := jsNum(v)
	if !ok || f != math.Trunc(f) || math.Abs(f) > 9007199254740991 {
		return 0, false
	}
	return int64(f), true
}

// storeFinite reads a finite JSON number (not NaN, not infinite).
func storeFinite(v any) (float64, bool) {
	f, ok := jsNum(v)
	return f, ok && !math.IsNaN(f) && !math.IsInf(f, 0)
}
