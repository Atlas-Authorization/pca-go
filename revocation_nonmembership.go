package pca

// Per-capability revocation non-membership (T9): a proof that a capability id is NOT in the guardian's sorted revocation
// set, checked against the (signed-epoch or bare) root. Mirrors the reference VerifyNonMembership: the set is sorted by
// UTF-8 bytes, the tree is the RFC 6962 shape and the root is bound to the set size. Proofs are parsed JSON values;
// nothing here panics on a hostile proof.

// revLeafOK checks one neighbour proof {index, size, path:[{side, hash}]} for id against the bound root: the index and
// size are what the path shape says and every sibling is canonical base64url of exactly 32 bytes.
func revLeafOK(root string, size float64, id string, proof any) bool {
	m, ok := proof.(map[string]any)
	if !ok {
		return false
	}
	idx, ok1 := extSafeInt(m["index"])
	psize, ok2 := extSafeInt(m["size"])
	path, ok3 := m["path"].([]any)
	if !ok1 || !ok2 || !ok3 || psize != size || idx < 0 || idx >= size {
		return false
	}
	shape := pathShape(int(idx), int(size))
	if len(shape) != len(path) {
		return false
	}
	h, err := leafHash(id)
	if err != nil {
		return false
	}
	for i, s := range path {
		step, ok := s.(map[string]any)
		if !ok {
			return false
		}
		side, _ := step["side"].(string)
		hs, _ := step["hash"].(string)
		sib, ok := DecodeB64uStrict(hs, b32)
		if side != shape[i] || !ok {
			return false
		}
		if side == "L" {
			h = revNodeHash(sib, h)
		} else {
			h = revNodeHash(h, sib)
		}
	}
	bound, ok := bindRevRoot(size, b64.EncodeToString(h))
	return ok && bound == root
}

// revNeighbour reads an optional {id, proof} member: present reports whether it is set (null counts as absent).
func revNeighbour(m map[string]any, k string) (id string, proof any, present, ok bool) {
	v, has := m[k]
	if !has || v == nil {
		return "", nil, false, true
	}
	n, isMap := v.(map[string]any)
	if !isMap {
		return "", nil, true, false
	}
	id, isStr := n["id"].(string)
	return id, n["proof"], true, isStr
}

// VerifyNonMembership reports whether proof shows id is NOT in the set the root commits to. proof is parsed JSON:
// {size, lo?: {id, proof}, hi?: {id, proof}} (lo = the largest revoked id below id, hi = the smallest above).
func VerifyNonMembership(root string, proof any, id string) bool {
	m, ok := proof.(map[string]any)
	if !ok {
		return false
	}
	size, ok := extSafeInt(m["size"])
	if !ok || size < 0 {
		return false
	}
	loID, loProof, hasLo, okLo := revNeighbour(m, "lo")
	hiID, hiProof, hasHi, okHi := revNeighbour(m, "hi")
	if !okLo || !okHi {
		return false
	}
	if size == 0 {
		want, _ := bindRevRoot(0, emptyRevTree())
		return !hasLo && !hasHi && root == want
	}
	if !hasLo && !hasHi {
		return false
	}
	var loIdx, hiIdx float64
	if hasLo {
		if !(compareUtf8(loID, id) < 0) || !revLeafOK(root, size, loID, loProof) {
			return false
		}
		loIdx, _ = extSafeInt(loProof.(map[string]any)["index"])
		if !hasHi && loIdx != size-1 {
			return false // id above the maximum
		}
	}
	if hasHi {
		if !(compareUtf8(id, hiID) < 0) || !revLeafOK(root, size, hiID, hiProof) {
			return false
		}
		hiIdx, _ = extSafeInt(hiProof.(map[string]any)["index"])
		if !hasLo && hiIdx != 0 {
			return false // id below the minimum
		}
	}
	return !(hasLo && hasHi && hiIdx != loIdx+1)
}
