package pca

// Transparency-anchored allowlist verification (wire level), the native counterpart of verifyAllowlistAnchored in
// @atlasauth/pca. It checks the log evidence for a manifest that has ALREADY been signature-verified elsewhere: an Ed25519
// signed tree head, the RFC 6962 root over the supplied anchor entries, the manifest's inclusion proof, the RFC 9162
// consistency proof from a cached head, head freshness and the per-issuer version rules. Same outcome codes as the
// reference; the reason text is not part of the contract. Heads must use the default Ed25519 suite (a head naming a
// post-quantum suite is reported as bad-head here; the TypeScript verifier handles those).

import (
	"encoding/json"
	"math/bits"
	"regexp"
)

// sthDomain (the signed tree head domain) is declared once, in ledger.go.
const (
	anchorDomain      = "pca-attest-allowlist-anchor/v1"
	anchorMaxFeed     = 100_000
	anchorDefaultSkew = int64(60_000)
	anchorDefaultAge  = int64(86_400_000)
)

var anchorDigestRe = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

// AnchorEntry is what the operator publishes per manifest.
type AnchorEntry struct {
	Issuer  string
	Version int64
	Digest  string
}

// AnchorTrust is the pinned identity of the log.
type AnchorTrust struct {
	LogKey     string // b64u Ed25519 public key of the log guardian
	InstanceID string
	Principal  string
}

// AnchorOptions configures one verification. Nil pointers mean "use the default".
type AnchorOptions struct {
	Trust        AnchorTrust
	NowMs        int64
	MaxHeadAgeMs *int64
	ClockSkewMs  *int64
	CachedHead   map[string]any // a previously accepted signed tree head, or nil
}

// AnchorResult is the outcome: Ok with HighestAnchoredVersion, or a Code (see the conformance corpus).
type AnchorResult struct {
	Ok                     bool
	Code                   string
	HighestAnchoredVersion int64
}

func anchorNo(code string) AnchorResult { return AnchorResult{Code: code} }

func anchorCommit(e AnchorEntry) (string, error) {
	return HashCanonical(map[string]any{"domain": anchorDomain, "issuer": e.Issuer, "version": json.Number(anchorNum(e.Version)), "digest": e.Digest})
}

func anchorNum(n int64) string { b, _ := json.Marshal(n); return string(b) }

type sth struct {
	instanceID, principal, root, prevRoot, guardian string
	size, timestamp                                 int64
}

// readHead verifies a signed tree head under the pinned key and returns it. ok=false on any problem.
func readHead(v any, logKey string) (sth, bool) {
	m, ok := v.(map[string]any)
	if !ok {
		return sth{}, false
	}
	if _, has := m["alg"]; has { // only the default Ed25519 suite is supported natively
		return sth{}, false
	}
	str := func(k string) (string, bool) { s, ok := m[k].(string); return s, ok }
	var h sth
	var ok1, ok2, ok3, ok4, ok5 bool
	h.instanceID, ok1 = str("instance_id")
	h.principal, ok2 = str("principal")
	h.root, ok3 = str("root")
	h.prevRoot, ok4 = str("prev_root")
	h.guardian, ok5 = str("guardian")
	size, ok6 := safeInt(m["size"])
	ts, ok7 := safeInt(m["timestamp"])
	sigS, ok8 := str("sig")
	if !(ok1 && ok2 && ok3 && ok4 && ok5 && ok6 && ok7 && ok8) || size < 0 || h.guardian != logKey {
		return sth{}, false
	}
	h.size, h.timestamp = size, ts
	pub, okp := DecodeB64uStrict(logKey, 32)
	sig, oks := DecodeB64uStrict(sigS, 64)
	if !okp || !oks {
		return sth{}, false
	}
	body, err := Canonicalize(map[string]any{
		"instance_id": h.instanceID, "principal": h.principal, "size": json.Number(anchorNum(size)),
		"root": h.root, "prev_root": h.prevRoot, "timestamp": json.Number(anchorNum(ts)),
	})
	if err != nil || !VerifyStrict(pub, append([]byte(sthDomain), body...), sig) {
		return sth{}, false
	}
	return h, true
}

func emptyTreeRoot() string { return b64.EncodeToString(sha(nil)) }

// verifyConsistency is RFC 9162 section 2.1.4.2 over the base64url roots and path.
func verifyConsistency(oldRoot, newRoot string, oldSize, newSize int64, path []any) bool {
	if oldSize < 0 || oldSize > newSize || len(path) > 2*53+2 {
		return false
	}
	if oldSize == 0 {
		if len(path) != 0 || oldRoot != emptyTreeRoot() {
			return false
		}
		if newSize == 0 {
			return newRoot == emptyTreeRoot()
		}
		return true
	}
	if oldSize == newSize {
		return len(path) == 0 && oldRoot == newRoot
	}
	nodes := make([][]byte, 0, len(path)+1)
	for _, p := range path {
		s, ok := p.(string)
		if !ok {
			return false
		}
		b, ok := DecodeB64uStrict(s, 32)
		if !ok {
			return false
		}
		nodes = append(nodes, b)
	}
	if bits.OnesCount64(uint64(oldSize)) == 1 {
		o, ok := DecodeB64uStrict(oldRoot, 32)
		if !ok {
			return false
		}
		nodes = append([][]byte{o}, nodes...)
	}
	if len(nodes) == 0 {
		return false
	}
	fn, sn := uint64(oldSize-1), uint64(newSize-1)
	for fn&1 == 1 {
		fn >>= 1
		sn >>= 1
	}
	fr, sr := nodes[0], nodes[0]
	for _, c := range nodes[1:] {
		if sn == 0 {
			return false
		}
		if fn&1 == 1 || fn == sn {
			fr = nodeHash(c, fr)
			sr = nodeHash(c, sr)
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			sr = nodeHash(sr, c)
		}
		fn >>= 1
		sn >>= 1
	}
	return sn == 0 && b64.EncodeToString(fr) == oldRoot && b64.EncodeToString(sr) == newRoot
}

func anchorEntryOf(v any) (AnchorEntry, bool) {
	m, ok := v.(map[string]any)
	if !ok || len(m) != 3 {
		return AnchorEntry{}, false
	}
	iss, ok1 := m["issuer"].(string)
	dig, ok2 := m["digest"].(string)
	ver, ok3 := safeInt(m["version"])
	if !ok1 || !ok2 || !ok3 || len(iss) == 0 || len(iss) > 200 || ver < 1 || !anchorDigestRe.MatchString(dig) {
		return AnchorEntry{}, false
	}
	return AnchorEntry{Issuer: iss, Version: ver, Digest: dig}, true
}

// VerifyAllowlistAnchored checks `mine` (a signature-verified manifest's issuer, version and digest) against the log
// evidence: {head, entries, proof, consistency?} decoded with json.Number. Never panics.
func VerifyAllowlistAnchored(mine AnchorEntry, evidence map[string]any, opts AnchorOptions) (res AnchorResult) {
	defer func() {
		if recover() != nil {
			res = anchorNo("bad-head")
		}
	}()
	proof, okp := evidence["proof"].(map[string]any)
	entriesAny, oke := evidence["entries"].([]any)
	if evidence == nil || !okp || evidence["head"] == nil || !oke {
		return anchorNo("missing-proof")
	}
	t := opts.Trust
	head, ok := readHead(evidence["head"], t.LogKey)
	if !ok {
		return anchorNo("bad-head")
	}
	if head.instanceID != t.InstanceID || head.principal != t.Principal {
		return anchorNo("bad-head")
	}
	skew, maxAge := anchorDefaultSkew, anchorDefaultAge
	if opts.ClockSkewMs != nil {
		skew = *opts.ClockSkewMs
	}
	if opts.MaxHeadAgeMs != nil {
		maxAge = *opts.MaxHeadAgeMs
	}
	if skew < 0 {
		skew = 0
	}
	if head.timestamp > opts.NowMs+skew || opts.NowMs-head.timestamp > maxAge {
		return anchorNo("stale-head")
	}

	if opts.CachedHead != nil {
		cached, ok := readHead(opts.CachedHead, t.LogKey)
		if !ok || cached.instanceID != t.InstanceID || cached.principal != t.Principal {
			return anchorNo("bad-cache")
		}
		switch {
		case head.size < cached.size:
			return anchorNo("log-rollback")
		case head.size == cached.size && head.root != cached.root:
			return anchorNo("split-view")
		case head.size > cached.size:
			c, okc := evidence["consistency"].(map[string]any)
			if !okc {
				return anchorNo("inconsistent-with-cache")
			}
			oldS, ok1 := safeInt(c["oldSize"])
			newS, ok2 := safeInt(c["newSize"])
			path, ok3 := c["path"].([]any)
			if !ok1 || !ok2 || !ok3 || oldS != cached.size || newS != head.size ||
				(head.size == cached.size+1 && head.prevRoot != cached.root) ||
				!verifyConsistency(cached.root, head.root, oldS, newS, path) {
				return anchorNo("inconsistent-with-cache")
			}
		}
	}

	if len(entriesAny) > anchorMaxFeed || int64(len(entriesAny)) != head.size {
		return anchorNo("feed-mismatch")
	}
	entries := make([]AnchorEntry, len(entriesAny))
	commits := make([]any, len(entriesAny))
	for i, e := range entriesAny {
		ae, ok := anchorEntryOf(e)
		if !ok {
			return anchorNo("feed-mismatch")
		}
		c, err := anchorCommit(ae)
		if err != nil {
			return anchorNo("feed-mismatch")
		}
		entries[i], commits[i] = ae, c
	}
	root := emptyTreeRoot()
	if len(commits) > 0 {
		r, err := MerkleRoot(commits)
		if err != nil {
			return anchorNo("feed-mismatch")
		}
		root = r
	}
	if root != head.root {
		return anchorNo("feed-mismatch")
	}

	digests := map[int64]string{}
	var highest int64
	for _, e := range entries {
		if e.Issuer != mine.Issuer {
			continue
		}
		if d, seen := digests[e.Version]; seen && d != e.Digest {
			return anchorNo("log-conflict")
		}
		digests[e.Version] = e.Digest
		if e.Version > highest {
			highest = e.Version
		}
	}
	myCommit, err := anchorCommit(mine)
	if err != nil {
		return anchorNo("bad-proof")
	}
	if ps, ok := safeInt(proof["size"]); !ok || ps != head.size {
		return anchorNo("bad-proof")
	}
	if !VerifyInclusion(head.root, proof, myCommit) {
		return anchorNo("bad-proof")
	}
	if mine.Version < highest {
		return anchorNo("anchored-rollback")
	}
	if digests[mine.Version] != mine.Digest {
		return anchorNo("not-anchored")
	}
	return AnchorResult{Ok: true, HighestAnchoredVersion: highest}
}
