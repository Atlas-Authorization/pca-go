package pca

import (
	"bytes"
	"encoding/json"
	"sort"
)

// ---- v2.1 threshold-share binding, signer-set pinned (R5-A1), whole-set validated (R6-02/03/04) ----

const (
	shareDomainPrefix = "atlas-pca/share/"
	signersetDomain   = "atlas-pca/signerset/v1\x00"
	shareSuiteTag     = "\x00atlas-pca/share-suite/v1\x00"
)

// signerRoles are the only roles a signer set may register (case-sensitive), like the reference.
var signerRoles = map[string]bool{"agent": true, "guardian": true, "principal": true}

// pqPkLengths are the registered PQ public-key lengths of EVERY suite (ml-dsa-65/87, slh-dsa-128f/256s,
// fn-dsa-512/1024, less-cat1), whether or not Go implements the suite: a set is validated exactly like the reference.
var pqPkLengths = map[int]bool{1952: true, 2592: true, 32: true, 64: true, 897: true, 1793: true, 97484: true}

// SignerSetHash = sha256("atlas-pca/signerset/v1\0" || canonical(sort_by(role, publicKey)[{publicKey, role[, pq_pk]}])).
// Rows are sorted by the UTF-8 bytes of role then publicKey (Go string comparison is bytewise), and carry pq_pk
// whenever it is a string, INCLUDING "" (R6-04: the reference hashes pq_pk:"" too). (_, false) when an entry is not
// an object or its role / publicKey is not a string; never panics.
func SignerSetHash(signerSet []any) ([]byte, bool) {
	type ent struct {
		role, pk, pq string
		hasPq        bool
	}
	ents := make([]ent, 0, len(signerSet))
	for _, e := range signerSet {
		o, ok := e.(map[string]any)
		if !ok {
			return nil, false
		}
		role, ok := o["role"].(string)
		if !ok {
			return nil, false
		}
		pk, ok := o["publicKey"].(string)
		if !ok {
			return nil, false
		}
		pq, hasPq := o["pq_pk"].(string)
		ents = append(ents, ent{role, pk, pq, hasPq})
	}
	sort.SliceStable(ents, func(i, j int) bool {
		if ents[i].role != ents[j].role {
			return ents[i].role < ents[j].role
		}
		return ents[i].pk < ents[j].pk
	})
	arr := make([]any, len(ents))
	for i, e := range ents {
		row := map[string]any{"publicKey": e.pk, "role": e.role}
		if e.hasPq {
			row["pq_pk"] = e.pq
		}
		arr[i] = row
	}
	canon, err := Canonicalize(arr)
	if err != nil {
		return nil, false
	}
	return sha(append([]byte(signersetDomain), canon...)), true
}

type registered struct {
	pk    string
	pq    string
	hasPq bool
}

// validateSignerSet validates the WHOLE signer set like the reference (decideThreshold BuildReg): every entry is an
// object with a known role and a canonical 32-byte publicKey; a present pq_pk (JSON null IS present) is canonical
// base64url of a registered PQ key length; one key per role; one role per key; a duplicate (role, key) entry only
// with the same pq_pk (or none on both). Returns role -> registration, or (nil, false).
func validateSignerSet(signerSet []any) (map[string]registered, bool) {
	reg := map[string]registered{}
	for _, e := range signerSet {
		o, ok := e.(map[string]any)
		if !ok {
			return nil, false
		}
		role, ok := o["role"].(string)
		if !ok || !signerRoles[role] {
			return nil, false
		}
		pk, ok := o["publicKey"].(string)
		if !ok {
			return nil, false
		}
		if _, ok := DecodeB64uStrict(pk, 32); !ok {
			return nil, false
		}
		r := registered{pk: pk}
		if pv, has := o["pq_pk"]; has {
			ps, ok := pv.(string)
			if !ok {
				return nil, false
			}
			b, ok := DecodeB64uStrict(ps, -1)
			if !ok || !pqPkLengths[len(b)] {
				return nil, false
			}
			r.pq, r.hasPq = ps, true
		}
		if prev, seen := reg[role]; seen {
			if prev != r { // two keys for one role, or the same (role, key) with a conflicting pq_pk
				return nil, false
			}
			continue
		}
		for _, other := range reg {
			if other.pk == pk {
				return nil, false // one key under two roles
			}
		}
		reg[role] = r
	}
	return reg, true
}

// thresholdT reads t, which must be exactly 1, 2 or 3 (R6-04). Accepts a JSON number or a Go integer/float.
func thresholdT(v any) (byte, bool) {
	var f float64
	switch x := v.(type) {
	case json.Number:
		i, ok := safeInt(x)
		if !ok {
			return 0, false
		}
		f = float64(i)
	case float64:
		f = x
	case int:
		f = float64(x)
	case int64:
		f = float64(x)
	default:
		return 0, false
	}
	if f == 1 || f == 2 || f == 3 {
		return byte(f), true
	}
	return 0, false
}

// VerifyThresholdShare verifies ONE threshold share `{role, t, signer_set, threshold_message, share}` (the
// conformance `threshold_share` / `threshold_set` entry shape) the way the reference verifyThreshold counts it:
//
//	"atlas-pca/share/<role>\0" || sha256(thresholdMessage) || SignerSetHash(signer_set) || t(1 byte) [|| suite tag]
//
// The WHOLE signer set is validated first (R6-03), t must be 1, 2 or 3 (R6-04), share.role must equal role, the share
// must be for the one key the set registers for role, a role registering pq_pk needs a PQ / hybrid share (R6-02),
// and a PQ share verifies only under the set's registered pq_pk. TOTAL: false on ANY malformed input, never panics.
func VerifyThresholdShare(entry any) (ok bool) {
	defer func() {
		if r := recover(); r != nil {
			ok = false
		}
	}()
	e, isMap := entry.(map[string]any)
	if !isMap {
		return false
	}
	role, isStr := e["role"].(string)
	if !isStr {
		return false
	}
	t, tOK := thresholdT(e["t"])
	if !tOK {
		return false
	}
	signerSet, isList := e["signer_set"].([]any)
	if !isList {
		return false
	}
	tmStr, isStr := e["threshold_message"].(string)
	if !isStr {
		return false
	}
	tm, b64 := DecodeB64uStrict(tmStr, -1)
	if !b64 {
		return false
	}
	reg, valid := validateSignerSet(signerSet)
	if !valid {
		return false
	}
	ssh, hashed := SignerSetHash(signerSet)
	if !hashed {
		return false
	}
	share, isMap := e["share"].(map[string]any)
	if !isMap {
		return false
	}
	pk, isStr := share["publicKey"].(string)
	if !isStr {
		return false
	}
	if sr, isStr := share["role"].(string); !isStr || sr != role {
		return false
	}
	r, found := reg[role]
	if !found || r.pk != pk {
		return false
	}
	algV, algPresent := share["alg"]
	suite, known := resolveSigAlg(algV, algPresent)
	if !known {
		return false
	}
	// A share that NAMES a pq_pk must name exactly its role's registered one (any suite; a role registering none has
	// nothing it could equal). The key used is always the registered one.
	if sp, has := share["pq_pk"]; has {
		if s, ok := sp.(string); !ok || !r.hasPq || s != r.pq {
			return false
		}
	}
	// R6-02: a role that registers a pq_pk REQUIRES a PQ (pure or hybrid) share; an ed25519-only share for it is
	// refused (otherwise an Ed25519 break would still forge the role).
	if r.hasPq && suite.alg == "ed25519" {
		return false
	}
	var tag []byte
	pqKey := callerVouchedPqKey(nil)
	if suite.alg != "ed25519" {
		// PQ key = the signer set's registered pq_pk, never the share's own.
		if !r.hasPq {
			return false
		}
		pqKey = callerVouchedPqKey(r.pq)
		tag = []byte(shareSuiteTag + suite.alg)
	}
	var msg bytes.Buffer
	msg.WriteString(shareDomainPrefix)
	msg.WriteString(role)
	msg.WriteByte(0)
	msg.Write(sha(tm))
	msg.Write(ssh)
	msg.WriteByte(t)
	msg.Write(tag)
	return verifyLeafSuite(algV, algPresent, pk, pqKey, msg.Bytes(), share["sig"], share["pq_sig"])
}
