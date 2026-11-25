package pca

// Public form of the pure store-document transitions the reference stores are built on: the ledger document
// (emptyLedgerDoc / appendToLedgerDoc / checkpointToLedgerDoc) and the bond document (emptyBondDoc / commitBondPlan /
// snapshotOf), plus isBondStore. A transition mutates the document in place and returns the outcome map; a malformed
// argument is an error and writes nothing.

// LedgerDoc is the ledger store document: the commit sequence and the checkpoints.
type LedgerDoc = ledgerDoc

// EmptyLedgerDoc is a fresh document.
func EmptyLedgerDoc() *LedgerDoc { return &ledgerDoc{} }

// AppendToLedgerDoc appends commits iff doc holds exactly expectedSize entries (all or none; a batch already stored there is a replay).
func AppendToLedgerDoc(doc *LedgerDoc, expectedSize any, commits any) (map[string]any, error) {
	return ledgerDocAppend(doc, expectedSize, commits)
}

// CheckpointToLedgerDoc appends a checkpoint at position expectedCount; it must lie inside the log and extend the previous one.
func CheckpointToLedgerDoc(doc *LedgerDoc, expectedCount any, checkpoint any) (map[string]any, error) {
	return ledgerDocCheckpoint(doc, expectedCount, checkpoint)
}

// BondDoc is the bond store document: balances, bonds and the observation high-water mark.
type BondDoc = bdoc

// EmptyBondDoc is a fresh document.
func EmptyBondDoc() *BondDoc { return bdocEmpty() }

// CommitBondPlan applies a settlement plan to doc atomically (or reports the conflict) as observed at observedAt.
func CommitBondPlan(doc *BondDoc, plan map[string]any, observedAt float64) (map[string]any, error) {
	return bdocCommit(doc, plan, observedAt)
}

// SnapshotOf is the read-scoped view of doc: the balances and bonds the query names.
func SnapshotOf(doc *BondDoc, query map[string]any) map[string]any { return doc.snapshot(query) }

// IsBondStore is true when s has the BondStore methods (read, commit, deposit).
func IsBondStore(s any) bool { _, ok := s.(BondStore); return ok }
