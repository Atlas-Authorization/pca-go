package pca

// Public form of the pure budget-document transitions (the reference's emptyBudgetDoc / reserveInDoc / startInDoc /
// commitInDoc / releaseInDoc / expireInDoc) and openDurableBudgetLedger. Each transition mutates the document in place and
// returns the outcome map ({outcome, version, status?}); a malformed request is an error, never a partial write.

// BudgetDoc is one ledger key's document: reservations and their version.
type BudgetDoc = budgetDoc

// EmptyBudgetDoc is a fresh document (version 0, no events).
func EmptyBudgetDoc() *BudgetDoc { return &budgetDoc{} }

// ReserveInDoc reserves request in doc.
func ReserveInDoc(doc *BudgetDoc, request map[string]any) (map[string]any, error) {
	return doc.reserve(request)
}

// StartInDoc marks reservation id started (its effect is now in flight and no longer expires).
func StartInDoc(doc *BudgetDoc, id string) map[string]any { return doc.start(id) }

// CommitInDoc settles reservation id as committed.
func CommitInDoc(doc *BudgetDoc, id string) map[string]any { return doc.commit(id) }

// ReleaseInDoc releases reservation id of key, with optional signed evidence.
func ReleaseInDoc(doc *BudgetDoc, key, id string, evidence map[string]any) (map[string]any, error) {
	return doc.release(key, id, evidence)
}

// ExpireInDoc releases every unstarted reservation whose expiry is at or before now (a safe integer).
func ExpireInDoc(doc *BudgetDoc, now float64) (map[string]any, error) { return doc.expire(now) }

// OpenDurableBudgetLedger opens the file-backed durable state under dir and returns the ledger over it, declared durable.
func OpenDurableBudgetLedger(dir string, lockTimeoutMs int64) (*KvBudgetLedger, error) {
	st, err := OpenDurableState(DurableStateOptions{Dir: dir, LockTimeoutMs: lockTimeoutMs})
	if err != nil {
		return nil, err
	}
	return NewKvBudgetLedger(NewDurableAtomicKV(st), true)
}
