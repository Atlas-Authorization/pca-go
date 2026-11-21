package pca

// Anchoring an action pack in a transparency log: the registry signs a statement over the pack's reference (digest, root,
// previous), the log registers it and returns a receipt; a verifier checks the receipt, the registry's statement signature and
// that the statement is for exactly this pack.

import (
	"bytes"
	"crypto"
)

// ActionPackStatementContentType is the content type of a pack statement.
const ActionPackStatementContentType = "application/pca-action-pack+json"

// ActionPackLogEntry is what appending a pack to a log yields.
type ActionPackLogEntry struct {
	Statement []byte
	Receipt   []byte
	Index     int64
	Root      string
}

// ActionAppendPackToLog signs the pack's statement as the registry (signer: alg, key, issuer) and registers it with the log.
func ActionAppendPackToLog(pack map[string]any, svc *ScittTransparencyService, alg string, key crypto.PrivateKey, issuer string) (*ActionPackLogEntry, error) {
	payload, err := ActionPackStatementPayload(pack)
	if err != nil {
		return nil, err
	}
	subject := jsAnyString(pack["ns"]) + "@" + jsAnyString(pack["version"])
	ct := ActionPackStatementContentType
	statement, err := ScittSignStatement(payload, ScittSignStatementOpts{Alg: alg, Key: key, Issuer: issuer, Subject: &subject, ContentType: &ct})
	if err != nil {
		return nil, err
	}
	r, err := svc.Register(statement)
	if err != nil {
		return nil, err
	}
	return &ActionPackLogEntry{Statement: statement, Receipt: r.Receipt, Index: r.Index, Root: r.Root}, nil
}

// ActionVerifyPackLogEntry is true only when the receipt verifies under the log key (anchored at treeRoot when given), the
// statement verifies under the registry key, and the statement's payload is exactly the canonical statement of this pack.
func ActionVerifyPackLogEntry(pack map[string]any, statement, receipt []byte, registryKey, logKey crypto.PublicKey, treeRoot *string) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	if !ScittVerifyReceipt(receipt, statement, ScittVerifyReceiptOpts{TreeRoot: treeRoot, VerificationKey: logKey, StatementKey: registryKey}) {
		return false
	}
	got, err := ScittStatementPayload(statement)
	if err != nil {
		return false
	}
	payload, err := ActionPackStatementPayload(pack)
	if err != nil {
		return false
	}
	want, err := Canonicalize(payload)
	if err != nil {
		return false
	}
	return bytes.Equal(got, []byte(want))
}
