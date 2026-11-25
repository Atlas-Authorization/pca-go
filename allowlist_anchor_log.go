package pca

// The operator side of the allowlist transparency anchor: the anchor log (a Merkle log of anchor commitments plus the plain
// entries behind them), anchoring a manifest with a re-signed tree head, the liveness refresh, and the evidence a verifier
// reads (VerifyAllowlistAnchored takes it as returned here).

import (
	"errors"
	"fmt"
)

// AllowlistAnchorCommit is the leaf the log stores for an entry: deterministic and public.
func AllowlistAnchorCommit(e AnchorEntry) (string, error) { return anchorCommit(e) }

// AllowlistAnchorLog is the operator's anchor log. Not safe for concurrent use.
type AllowlistAnchorLog struct {
	ledger     *MerkleLog
	instanceID string
	principal  string
	entries    []AnchorEntry
	latest     map[string]any
}

// CreateAllowlistAnchorLog returns an empty anchor log. principal is the log id the verifier pins; instanceID the deployment.
func CreateAllowlistAnchorLog(instanceID, principal string) *AllowlistAnchorLog {
	return &AllowlistAnchorLog{ledger: NewMerkleLog(), instanceID: instanceID, principal: principal}
}

// Ledger is the Merkle log of anchor commitments.
func (l *AllowlistAnchorLog) Ledger() *MerkleLog { return l.ledger }

// InstanceID is the deployment the log belongs to.
func (l *AllowlistAnchorLog) InstanceID() string { return l.instanceID }

// Principal is the log id.
func (l *AllowlistAnchorLog) Principal() string { return l.principal }

// Entries returns a copy of the anchored entries, in log order.
func (l *AllowlistAnchorLog) Entries() []AnchorEntry { return append([]AnchorEntry{}, l.entries...) }

// Latest is the latest signed tree head, or nil when nothing was ever anchored.
func (l *AllowlistAnchorLog) Latest() map[string]any { return l.latest }

// AnchorSignOptions are the guardian key, the head timestamp (epoch ms) and the optional signature suite of a head signature.
type AnchorSignOptions struct {
	Guardian *KeyPair
	NowMs    int64
	Suite    *SuiteOpts
}

func (l *AllowlistAnchorLog) signHead(o AnchorSignOptions) (map[string]any, error) {
	prev := ""
	if l.latest != nil {
		prev, _ = l.latest["root"].(string)
	}
	ts, ok := safeIntNumber(o.NowMs)
	if !ok {
		return nil, errors.New("signTreeHead: the timestamp is not a safe integer")
	}
	sth, err := SignTreeHead(o.Guardian, map[string]any{"instance_id": l.instanceID, "principal": l.principal, "size": jsNumber(float64(l.ledger.Size())),
		"root": l.ledger.Root(), "prev_root": prev, "timestamp": ts}, o.Suite)
	if err != nil {
		return nil, err
	}
	l.latest = sth
	return sth, nil
}

// anchorEntryOfWhat reads what AnchorAllowlistHead accepts: an AnchorEntry, a verified AllowlistResult, or the decoded JSON form of
// either (an object with a `body` member is a verified result; any other object must be exactly {issuer, version, digest}).
func anchorEntryOfWhat(what any) (AnchorEntry, bool) {
	var e AnchorEntry
	switch t := what.(type) {
	case AnchorEntry:
		e = t
	case *AnchorEntry:
		if t == nil {
			return e, false
		}
		e = *t
	case AllowlistResult:
		if !t.OK {
			return e, false
		}
		e = AnchorEntry{Issuer: t.Issuer, Version: t.Version, Digest: t.Digest}
	case map[string]any:
		m := t
		if _, has := t["body"]; has {
			m = map[string]any{"issuer": t["issuer"], "version": t["version"], "digest": t["digest"]}
		}
		return anchorEntryOf(m)
	default:
		return e, false
	}
	if n := jsLen(e.Issuer); n == 0 || n > 200 || e.Version < 1 || e.Version > maxSafeInt || !anchorDigestRe.MatchString(e.Digest) {
		return e, false
	}
	return e, true
}

// AnchorAllowlistHead anchors a verified manifest (or a bare entry) in the log, re-signs the head and returns the evidence for its
// leaf. It refuses an entry that would lower the issuer's highest anchored version or give an anchored version a second digest;
// anchoring the identical entry again changes nothing and returns the evidence for the existing leaf.
func AnchorAllowlistHead(log *AllowlistAnchorLog, what any, opts AnchorSignOptions) (map[string]any, error) {
	entry, ok := anchorEntryOfWhat(what)
	if !ok {
		return nil, errors.New("anchorAllowlistHead: malformed entry")
	}
	index, highest := -1, int64(0)
	for i, e := range log.entries {
		if e.Issuer != entry.Issuer {
			continue
		}
		if e.Version == entry.Version && index < 0 {
			index = i
		}
		highest = max(highest, e.Version)
	}
	if index >= 0 {
		if log.entries[index].Digest != entry.Digest {
			return nil, errors.New("anchorAllowlistHead: this version is already anchored with a different digest")
		}
	} else {
		if entry.Version < highest {
			return nil, fmt.Errorf("anchorAllowlistHead: version %d is lower than the anchored %d", entry.Version, highest)
		}
		commit, err := anchorCommit(entry)
		if err != nil {
			return nil, err
		}
		// The head is signed over the log with the new leaf; a signing failure must not leave an anchored leaf without a head.
		if opts.Guardian == nil || opts.Guardian.Public == "" {
			return nil, errors.New("signTreeHead: a guardian key is required")
		}
		if index, err = log.ledger.AppendCommitment(commit); err != nil {
			return nil, err
		}
		log.entries = append(log.entries, entry)
		if _, err = log.signHead(opts); err != nil {
			return nil, err
		}
	}
	if log.latest == nil {
		if _, err := log.signHead(opts); err != nil {
			return nil, err
		}
	}
	return EvidenceFor(log, index, nil)
}

// RefreshAnchorHead re-signs the current head with a fresh timestamp (a liveness heartbeat; no new entry). An empty log is refused.
func RefreshAnchorHead(log *AllowlistAnchorLog, opts AnchorSignOptions) (map[string]any, error) {
	if log.ledger.Size() == 0 {
		return nil, errors.New("refreshAnchorHead: nothing anchored yet")
	}
	return log.signHead(opts)
}

// EvidenceFor is the evidence for the leaf at index under the log's latest head: {head, entries, proof}, plus `consistency` from a
// verifier's cached head size when cachedSize is given, positive and below the head size.
func EvidenceFor(log *AllowlistAnchorLog, index int, cachedSize *int) (map[string]any, error) {
	if log.latest == nil {
		return nil, errors.New("evidenceFor: log has no signed head")
	}
	proof, err := log.ledger.InclusionProof(index)
	if err != nil {
		return nil, err
	}
	entries := make([]any, len(log.entries))
	for i, e := range log.entries {
		entries[i] = map[string]any{"issuer": e.Issuer, "version": jsNumber(float64(e.Version)), "digest": e.Digest}
	}
	out := map[string]any{"head": log.latest, "entries": entries, "proof": proof}
	size, _ := anySafeInt(log.latest["size"])
	if cachedSize != nil && *cachedSize > 0 && int64(*cachedSize) < size {
		c, err := log.ledger.ConsistencyProof(*cachedSize, int(size))
		if err != nil {
			return nil, err
		}
		out["consistency"] = c
	}
	return out, nil
}
