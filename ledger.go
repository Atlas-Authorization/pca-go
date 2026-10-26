package pca

// Transparency-ledger verification (extension layer): RFC 6962 inclusion of ledger commits, RFC 9162 consistency,
// guardian-signed tree heads, witness cosignatures, head-to-head consistency, checkpoint chains and legacy witnessed
// heads. Inputs are parsed JSON values (StrictParse / ParseJSONLenient) so a hostile wire object cannot panic any
// function here: every verifier returns false on malformed input. Only Ed25519 (alg absent or "ed25519") is
// implemented; any other suite is refused (false).

import (
	"math"
)

const (
	sthWitnessDomain = "atlas-pca/sth-witness/v2\x00"
	ledgerHeadDomain = "atlas-pca/ledger-head/v1\x00"
	// longest consistency path any tree of fewer than 2^53 leaves can need (2*53+1), plus one of slack as the reference
	maxConsistencyPath = 2*53 + 2
)

// EmptyTreeRoot is the root of the empty tree (RFC 9162 2.1.1: SHA-256 of the empty string), base64url.
var EmptyTreeRoot = b64.EncodeToString(sha(nil))

func extMap(v any) (map[string]any, bool) { m, ok := v.(map[string]any); return m, ok }

func extStr(m map[string]any, k string) (string, bool) { s, ok := m[k].(string); return s, ok }

// extSafeInt reads a JavaScript safe integer (JSON number, integral, |n| <= 2^53-1).
func extSafeInt(v any) (float64, bool) {
	f, ok := jsNum(v)
	return f, ok && jsIsSafeInteger(v)
}

// extEd25519 is true when the artifact's `alg` is absent or "ed25519" (the only suite implemented).
func extEd25519(m map[string]any) bool {
	a, has := m["alg"]
	if !has {
		return true
	}
	s, ok := a.(string)
	return ok && s == "ed25519"
}

// extSigned verifies sig over domain || strict-canonical(body) with an Ed25519 public key (b64u).
func extSigned(pub string, domain string, body map[string]any, sig any) bool {
	s, ok := sig.(string)
	if !ok {
		return false
	}
	c, err := canonBytes(body)
	if err != nil {
		return false
	}
	return verifyB64u(pub, append([]byte(domain), c...), s)
}

// extPick copies the named members; ok is false when one is absent (the reference throws on undefined).
func extPick(m map[string]any, keys ...string) (map[string]any, bool) {
	out := make(map[string]any, len(keys))
	for _, k := range keys {
		v, has := m[k]
		if !has {
			return nil, false
		}
		out[k] = v
	}
	return out, true
}

// VerifyLedgerInclusion checks a ledger commit (string leaf) against a root with an RFC 6962 inclusion proof.
func VerifyLedgerInclusion(root string, proof any, commit any) bool {
	p, ok := extMap(proof)
	return ok && VerifyInclusion(root, p, commit)
}

// VerifyLedgerConsistency is RFC 9162 2.1.4.2 consistency verification. Sizes are JSON safe integers; the index
// arithmetic is done in uint64 so sizes 3 and 3+2^32 never collide. Size 0 pins oldRoot to the empty-tree root and
// requires an empty path. Never panics.
func VerifyLedgerConsistency(oldRoot, newRoot, proof any) bool {
	or, ok1 := oldRoot.(string)
	nr, ok2 := newRoot.(string)
	p, ok3 := extMap(proof)
	if !ok1 || !ok2 || !ok3 {
		return false
	}
	ff, ok1 := extSafeInt(p["oldSize"])
	sf, ok2 := extSafeInt(p["newSize"])
	rawPath, ok3 := p["path"].([]any)
	if !ok1 || !ok2 || !ok3 || ff < 0 || ff > sf || len(rawPath) > maxConsistencyPath {
		return false
	}
	first, second := uint64(ff), uint64(sf)
	if first == 0 {
		if len(rawPath) != 0 || or != EmptyTreeRoot {
			return false
		}
		if second == 0 {
			return nr == EmptyTreeRoot
		}
		return true // vacuous for a non-empty new tree
	}
	if first == second {
		return len(rawPath) == 0 && or == nr
	}
	path := make([][]byte, 0, len(rawPath)+1)
	if first&(first-1) == 0 {
		h, ok := DecodeB64uStrict(or, -1)
		if !ok {
			return false
		}
		path = append(path, h)
	}
	for _, e := range rawPath {
		s, ok := e.(string)
		if !ok {
			return false
		}
		h, ok := DecodeB64uStrict(s, -1)
		if !ok {
			return false
		}
		path = append(path, h)
	}
	if len(path) == 0 {
		return false
	}
	fn, sn := first-1, second-1
	for fn&1 == 1 {
		fn >>= 1
		sn >>= 1
	}
	fr, sr := path[0], path[0]
	for _, c := range path[1:] {
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
	return sn == 0 && b64.EncodeToString(fr) == or && b64.EncodeToString(sr) == nr
}

// VerifyWitnessedHead verifies a legacy witnessed head {principal,size,root,witness,sig} against the witness key.
func VerifyWitnessedHead(wh any, witnessPublic string) bool {
	m, ok := extMap(wh)
	if !ok {
		return false
	}
	if w, _ := extStr(m, "witness"); w != witnessPublic || !extEd25519(m) {
		return false
	}
	body, ok := extPick(m, "principal", "size", "root")
	return ok && extSigned(witnessPublic, ledgerHeadDomain, body, m["sig"])
}

// DetectEquivocation is true when a and b are both validly witnessed by the witness for the same principal and size
// but carry different roots (a split view).
func DetectEquivocation(a, b any, witnessPublic string) bool {
	am, ok1 := extMap(a)
	bm, ok2 := extMap(b)
	if !ok1 || !ok2 || !VerifyWitnessedHead(a, witnessPublic) || !VerifyWitnessedHead(b, witnessPublic) {
		return false
	}
	as, _ := jsNum(am["size"])
	bs, _ := jsNum(bm["size"])
	ar, _ := am["root"].(string)
	br, _ := bm["root"].(string)
	return extSame(am["principal"], bm["principal"]) && as == bs && ar != br
}

// VerifyWitnessCosignature verifies one cosignature of a tree head under a trusted witness key, bound to the head's
// {instance_id, principal, size, root, prev_root, guardian_epoch (absent or null = 0)}.
func VerifyWitnessCosignature(sth, cosig any, witnessPublic string) bool {
	sm, ok1 := extMap(sth)
	cm, ok2 := extMap(cosig)
	if !ok1 || !ok2 {
		return false
	}
	if k, _ := extStr(cm, "key"); k != witnessPublic || !extEd25519(cm) {
		return false
	}
	body, ok := extPick(sm, "instance_id", "principal", "size", "root", "prev_root")
	if !ok {
		return false
	}
	if e, has := sm["guardian_epoch"]; has && e != nil {
		body["guardian_epoch"] = e
	} else {
		body["guardian_epoch"] = 0
	}
	return extSigned(witnessPublic, sthWitnessDomain, body, cm["sig"])
}

// VerifyWitnessCosignatures is the k-of-n check: at least policy.threshold DISTINCT trusted witnesses (policy
// witnessKeys) carry a valid cosignature over this exact head. Unknown, duplicate and mis-bound cosignatures do not
// count; threshold 0 is vacuously met; a non-integer or negative threshold fails.
func VerifyWitnessCosignatures(sth any, policy map[string]any) bool {
	sm, ok := extMap(sth)
	if !ok || policy == nil {
		return false
	}
	tf, ok := jsNum(policy["threshold"])
	if !ok || tf != math.Trunc(tf) || tf < 0 {
		return false
	}
	if tf == 0 {
		return true
	}
	trusted := map[string]bool{}
	if ks, ok := policy["witnessKeys"].([]any); ok {
		for _, k := range ks {
			if s, ok := k.(string); ok {
				trusted[s] = true
			}
		}
	}
	if len(trusted) == 0 {
		return false
	}
	ws, ok := sm["witnesses"].([]any)
	if !ok {
		return false
	}
	counted := map[string]bool{}
	for _, w := range ws {
		wm, ok := extMap(w)
		if !ok {
			continue
		}
		key, ok1 := extStr(wm, "key")
		_, ok2 := extStr(wm, "sig")
		if !ok1 || !ok2 || !trusted[key] || counted[key] {
			continue
		}
		if !VerifyWitnessCosignature(sth, w, key) {
			continue
		}
		counted[key] = true
		if float64(len(counted)) >= tf {
			return true
		}
	}
	return float64(len(counted)) >= tf
}

// VerifyTreeHead verifies a guardian-signed tree head against the pinned guardian key: the head names that guardian,
// its size is a non-negative safe integer, the signature covers {instance_id, principal, size, root, prev_root,
// timestamp}, and, when policy is non-nil, enough trusted witnesses cosigned it.
func VerifyTreeHead(sth any, guardianPublic string, policy map[string]any) bool {
	m, ok := extMap(sth)
	if !ok {
		return false
	}
	if g, _ := extStr(m, "guardian"); g != guardianPublic || !extEd25519(m) {
		return false
	}
	if f, ok := extSafeInt(m["size"]); !ok || f < 0 {
		return false
	}
	body, ok := extPick(m, "instance_id", "principal", "size", "root", "prev_root", "timestamp")
	if !ok || !extSigned(guardianPublic, sthDomain, body, m["sig"]) {
		return false
	}
	return policy == nil || VerifyWitnessCosignatures(sth, policy)
}

// VerifyHeadConsistency: both heads are genuine for the pinned guardian, belong to the same instance and log, the
// proof connects exactly their sizes, the signed prev_root equals older.root when the heads are adjacent
// (newer.size == older.size+1), and the RFC 9162 path verifies.
func VerifyHeadConsistency(older, newer, proof any, guardianPublic string, policy map[string]any) bool {
	if !VerifyTreeHead(older, guardianPublic, policy) || !VerifyTreeHead(newer, guardianPublic, policy) {
		return false
	}
	om, nm, pm := older.(map[string]any), newer.(map[string]any), mapOrNil(proof)
	if pm == nil || !extSame(om["instance_id"], nm["instance_id"]) || !extSame(om["principal"], nm["principal"]) {
		return false
	}
	os, _ := jsNum(om["size"])
	ns, _ := jsNum(nm["size"])
	ps, ok1 := jsNum(pm["oldSize"])
	pn, ok2 := jsNum(pm["newSize"])
	if !ok1 || !ok2 || ps != os || pn != ns {
		return false
	}
	if ns == os+1 && !extSame(nm["prev_root"], om["root"]) {
		return false
	}
	return VerifyLedgerConsistency(om["root"], nm["root"], proof)
}

// extSame is JavaScript === on JSON values (compared through their canonical form; both must be canonicalizable).
func extSame(a, b any) bool {
	x, e1 := canonBytes(a)
	y, e2 := canonBytes(b)
	return e1 == nil && e2 == nil && string(x) == string(y)
}

func mapOrNil(v any) map[string]any { m, _ := v.(map[string]any); return m }

// CheckpointVerdict is the result of VerifyCheckpointChain: OK, or At = index of the first checkpoint that fails.
type CheckpointVerdict struct {
	OK bool
	At int
}

// VerifyCheckpointChain verifies pinned checkpoints end to end: every head is genuine (and witnessed when policy is
// non-nil), the first needs no proof, every later one carries a consistency proof from the checkpoint before. An empty
// or non-array chain fails at 0.
func VerifyCheckpointChain(chain any, guardianPublic string, policy map[string]any) CheckpointVerdict {
	cs, ok := chain.([]any)
	if !ok || len(cs) == 0 {
		return CheckpointVerdict{false, 0}
	}
	var prev any
	for i, c := range cs {
		cm, ok := extMap(c)
		if !ok || !VerifyTreeHead(cm["sth"], guardianPublic, policy) {
			return CheckpointVerdict{false, i}
		}
		if i > 0 {
			if cm["proof"] == nil || cm["proof"] == false {
				return CheckpointVerdict{false, i}
			}
			if !VerifyHeadConsistency(prev, cm["sth"], cm["proof"], guardianPublic, policy) {
				return CheckpointVerdict{false, i}
			}
		}
		prev = cm["sth"]
	}
	return CheckpointVerdict{true, 0}
}
