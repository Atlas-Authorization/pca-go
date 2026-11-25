package pca

import (
	"crypto/rand"
	"errors"
)

// The transparency ledger itself: salted commitments of PCActns in an append-only Merkle log (RFC 9162), with
// crypto-shredding of the openings, storage-tamper audit and the witnessed head. Inclusion / consistency verification and the
// signed tree heads are in ledger.go and ledger_store.go; the proofs are MerkleLog's.

// LedgerOpening is the salt and PCActn that reproduce a commitment.
type LedgerOpening struct {
	Salt   string
	Pcactn map[string]any
}

// LedgerEntry is one log entry: the commitment and, until shredded, its opening.
type LedgerEntry struct {
	Commit  string
	Opening *LedgerOpening
}

// EntryCommit is the salted commitment of a PCActn: hashCanonical({salt, pcactn_digest}).
func EntryCommit(salt string, pcactn map[string]any) (string, error) {
	d, err := PCActnDigest(pcactn)
	if err != nil {
		return "", err
	}
	return HashCanonical(map[string]any{"salt": salt, "pcactn_digest": d})
}

// VerifyOpening is true when the opening reproduces the commit; it never errors.
func VerifyOpening(commit string, opening LedgerOpening) bool {
	c, err := EntryCommit(opening.Salt, opening.Pcactn)
	return err == nil && c == commit
}

// LedgerRootOf is the root of an arbitrary commit sequence (the empty log is SHA-256 of the empty string), base64url.
func LedgerRootOf(commits []string) (string, error) {
	hs := make([][]byte, len(commits))
	for i, c := range commits {
		h, err := leafHash(c)
		if err != nil {
			return "", err
		}
		hs[i] = h
	}
	return b64.EncodeToString(merkleMTH(hs)), nil
}

// TransparencyLedger is an append-only commitment log for one principal. Not safe for concurrent use.
type TransparencyLedger struct {
	Principal string
	log       *MerkleLog
	openings  []*LedgerOpening
}

// NewTransparencyLedger returns an empty log for principal.
func NewTransparencyLedger(principal string) *TransparencyLedger {
	return &TransparencyLedger{Principal: principal, log: NewMerkleLog()}
}

// TransparencyLedgerFromEntries rebuilds a log from stored entries (after persistence, or to model tampering).
func TransparencyLedgerFromEntries(entries []LedgerEntry, principal string) (*TransparencyLedger, error) {
	l := NewTransparencyLedger(principal)
	for _, e := range entries {
		if _, err := l.log.AppendCommitment(e.Commit); err != nil {
			return nil, err
		}
		var op *LedgerOpening
		if e.Opening != nil {
			o := *e.Opening
			op = &o
		}
		l.openings = append(l.openings, op)
	}
	return l, nil
}

// Size is the number of entries.
func (l *TransparencyLedger) Size() int { return l.log.Size() }

// Append appends a PCActn as a salted commitment. An empty salt draws 16 random bytes; pass one for deterministic output.
func (l *TransparencyLedger) Append(pcactn map[string]any, salt string) (index int, commit string, err error) {
	if salt == "" {
		b := make([]byte, 16)
		if _, err = rand.Read(b); err != nil {
			return 0, "", err
		}
		salt = b64.EncodeToString(b)
	}
	if commit, err = EntryCommit(salt, pcactn); err != nil {
		return 0, "", err
	}
	if index, err = l.log.AppendCommitment(commit); err != nil {
		return 0, "", err
	}
	l.openings = append(l.openings, &LedgerOpening{Salt: salt, Pcactn: pcactn})
	return index, commit, nil
}

// AppendCommitment appends a PRECOMPUTED opaque commitment leaf (the opening is held off-log, so the entry is already
// shredded and AuditOpenings ignores it). A non-string or empty commit is refused.
func (l *TransparencyLedger) AppendCommitment(commit string) (int, error) {
	i, err := l.log.AppendCommitment(commit)
	if err != nil {
		return 0, err
	}
	l.openings = append(l.openings, nil)
	return i, nil
}

// Head is {size, root}.
func (l *TransparencyLedger) Head() map[string]any { return l.log.Head() }

// RootAt is the root the log had when it held only the first size entries.
func (l *TransparencyLedger) RootAt(size int) (string, error) { return l.log.RootAt(size) }

// Commits returns the commitments in order.
func (l *TransparencyLedger) Commits() []string { return l.log.Commits() }

// Entry returns entry index (a copy).
func (l *TransparencyLedger) Entry(index int) (LedgerEntry, error) {
	if index < 0 || index >= l.Size() {
		return LedgerEntry{}, errors.New("entry: index out of range")
	}
	e := LedgerEntry{Commit: l.log.commits[index]}
	if o := l.openings[index]; o != nil {
		c := *o
		e.Opening = &c
	}
	return e, nil
}

// AuditOpenings lists the indices whose stored opening no longer matches its commit (storage tamper detection).
func (l *TransparencyLedger) AuditOpenings() []int {
	bad := []int{}
	for i, o := range l.openings {
		if o != nil && !VerifyOpening(l.log.commits[i], *o) {
			bad = append(bad, i)
		}
	}
	return bad
}

// InclusionProof is the proof of entry index.
func (l *TransparencyLedger) InclusionProof(index int) (map[string]any, error) {
	return l.log.InclusionProof(index)
}

// VerifyInclusion checks an inclusion proof against root.
func (l *TransparencyLedger) VerifyInclusion(root string, proof any, commit string) bool {
	return VerifyLedgerInclusion(root, proof, commit)
}

// ConsistencyProof is the RFC 9162 SUBPROOF between two sizes; newSize < 0 means the current size.
func (l *TransparencyLedger) ConsistencyProof(oldSize, newSize int) (map[string]any, error) {
	if newSize < 0 {
		newSize = l.Size()
	}
	return l.log.ConsistencyProof(oldSize, newSize)
}

// VerifyConsistency checks a consistency proof between two roots.
func (l *TransparencyLedger) VerifyConsistency(oldRoot, newRoot string, proof any) bool {
	return VerifyLedgerConsistency(oldRoot, newRoot, proof)
}

// Shred destroys the opening of entry index (the commit, leaf, root and every proof are unchanged) and reports whether an
// opening was actually removed.
func (l *TransparencyLedger) Shred(index int) (bool, error) {
	if index < 0 || index >= l.Size() {
		return false, errors.New("shred: index out of range")
	}
	had := l.openings[index] != nil
	l.openings[index] = nil
	return had, nil
}

// WitnessHead signs the current head for third-party witnessing / anti-equivocation. suite nil = Ed25519.
func (l *TransparencyLedger) WitnessHead(guardian *KeyPair, suite *SuiteOpts) (map[string]any, error) {
	h := l.Head()
	wh, err := SignArtifact(ledgerHeadDomain, map[string]any{"principal": l.Principal, "size": h["size"], "root": h["root"]}, guardian, suite)
	if err != nil {
		return nil, err
	}
	wh["witness"] = guardian.Public
	return wh, nil
}

// DetectTreeHeadEquivocation is true when a and b are both genuine guardian-signed tree heads of the same instance and
// principal and size but carry different roots: a self-contained, attributable split view. It never errors.
func DetectTreeHeadEquivocation(a, b any, guardianPublic string, pins ...map[string]string) bool {
	am, ok1 := extMap(a)
	bm, ok2 := extMap(b)
	if !ok1 || !ok2 || !VerifyTreeHead(a, guardianPublic, nil, pins...) || !VerifyTreeHead(b, guardianPublic, nil, pins...) {
		return false
	}
	as, _ := jsNum(am["size"])
	bs, _ := jsNum(bm["size"])
	ar, _ := am["root"].(string)
	br, _ := bm["root"].(string)
	return extSame(am["instance_id"], bm["instance_id"]) && extSame(am["principal"], bm["principal"]) && as == bs && ar != br
}
