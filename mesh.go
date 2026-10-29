package pca

import (
	"fmt"
	"math"
	"sort"
)

// Cross-domain mesh proofs (the agent mesh, mesh.ts `verifyMeshProof`). A MeshProof carries a capability chain, one
// witnessed head per issuing domain, per-hop log inclusion and revocation non-membership proofs, and a signed leaf
// action. VerifyMeshProof checks all of it offline and returns the reference's reason and failing hop.
//
// Scope: everything verifyMeshProof does, including RFC 9162 consistency proofs from a pinned head. The witness side
// (cosigning, heads publication) is not here: a verifier only needs to check what they produced.

const (
	meshHeadDomain    = "atlas-pca/mesh-head/v1\x00"
	meshCosigDomain   = "atlas-pca/mesh-cosig/v1\x00"
	meshBindingDomain = "atlas-pca/mesh-binding/v1\x00"
	meshActionDomain  = "atlas-pca/mesh-action/v1\x00"

	meshDefaultMaxHeadAgeMs = 5 * 60_000
	meshDefaultMaxSkewMs    = 60_000
	meshDefaultMaxChain     = 64
	meshMaxCosigs           = 256
	meshMaxPath             = 128
)

// MeshVerdict is the result of VerifyMeshProof. Hop is -1 when no hop is named.
type MeshVerdict struct {
	OK     bool
	Reason string
	Hop    int
}

func meshFail(reason string, hop int) MeshVerdict { return MeshVerdict{Reason: reason, Hop: hop} }

func mRec(x any) (map[string]any, bool) { m, ok := x.(map[string]any); return m, ok }
func mStr(x any) (string, bool)         { s, ok := x.(string); return s, ok }
func mNat(x any) bool                   { _, ok := safeInt(x); return ok && jsIsNonNeg(x) }
func mNum(x any) bool                   { f, ok := jsNum(x); return ok && !math.IsInf(f, 0) && !math.IsNaN(f) }
func mNatV(x any) int64                 { v, _ := safeInt(x); return v }

func meshMsg(domain string, body any) ([]byte, bool) {
	b, ok := strictBytes(body)
	if !ok {
		return nil, false
	}
	return append([]byte(domain), b...), true
}

func meshValidHead(h any) (map[string]any, bool) {
	m, ok := mRec(h)
	if !ok {
		return nil, false
	}
	if _, ok := mStr(m["domain"]); !ok {
		return nil, false
	}
	root, ok := mStr(m["root"])
	if !ok {
		return nil, false
	}
	if _, ok := mStr(m["rev_root"]); !ok {
		return nil, false
	}
	if !mNat(m["size"]) || !mNat(m["rev_size"]) || !mNum(m["timestamp"]) {
		return nil, false
	}
	return m, (mNatV(m["size"]) == 0) == (root == "")
}

func meshValidConsistency(c any) (map[string]any, bool) {
	m, ok := mRec(c)
	if !ok || !mNat(m["oldSize"]) || !mNat(m["newSize"]) {
		return nil, false
	}
	path, ok := m["path"].([]any)
	if !ok || len(path) > meshMaxPath {
		return nil, false
	}
	for _, p := range path {
		if _, ok := mStr(p); !ok {
			return nil, false
		}
	}
	return m, true
}

func meshValidInclusion(i any) (map[string]any, bool) {
	m, ok := mRec(i)
	if !ok || !mNat(m["index"]) || !mNat(m["size"]) {
		return nil, false
	}
	path, ok := m["path"].([]any)
	return m, ok && len(path) <= meshMaxPath
}

func meshValidAction(a any) (map[string]any, bool) {
	m, ok := mRec(a)
	if !ok {
		return nil, false
	}
	for _, k := range []string{"type", "resource", "service_domain", "nonce"} {
		if _, ok := mStr(m[k]); !ok {
			return nil, false
		}
	}
	if !mNum(m["at"]) {
		return nil, false
	}
	if v, has := m["amount"]; has && !mNum(v) {
		return nil, false
	}
	return m, true
}

// ---- effective authority --------------------------------------------------------------------------------------

type meshAuthority struct {
	actions   []string
	hasAct    bool
	prefixes  []string
	maxAmount float64
	hasAmount bool
	expiresAt float64
	hasExp    bool
	audience  []string
	hasAud    bool
	maxHops   float64
	hasHops   bool
}

func meshIntersect(have bool, a []string, b []string) []string {
	if !have {
		seen := map[string]bool{}
		out := []string{}
		for _, x := range b {
			if !seen[x] {
				seen[x] = true
				out = append(out, x)
			}
		}
		sort.SliceStable(out, func(i, j int) bool { return compareUtf8(out[i], out[j]) < 0 })
		return out
	}
	out := []string{}
	for _, x := range a {
		for _, y := range b {
			if x == y {
				out = append(out, x)
				break
			}
		}
	}
	return out
}

func meshStrings(v any) ([]string, bool) {
	arr, ok := v.([]any)
	if !ok {
		return nil, false
	}
	out := make([]string, len(arr))
	for i, x := range arr {
		s, ok := mStr(x)
		if !ok {
			return nil, false
		}
		out[i] = s
	}
	return out, true
}

func meshMin(have bool, cur, v float64) float64 {
	if !have {
		return v
	}
	return math.Min(cur, v)
}

// meshEffective is effectiveAuthority: the conjunction of the caveats; an unknown or malformed caveat is an error.
func meshEffective(caveats any) (meshAuthority, string) {
	e := meshAuthority{prefixes: []string{}}
	arr, ok := caveats.([]any)
	if !ok {
		return e, "malformed proof"
	}
	for _, cv := range arr {
		c, ok := mRec(cv)
		if !ok {
			return e, "malformed proof"
		}
		t, _ := c["type"].(string)
		switch t {
		case "scope":
			a, ok := meshStrings(c["actions"])
			if !ok {
				return e, "malformed scope caveat"
			}
			e.actions, e.hasAct = meshIntersect(e.hasAct, e.actions, a), true
		case "resource":
			p, ok := mStr(c["prefix"])
			if !ok {
				return e, "malformed resource caveat"
			}
			e.prefixes = append(e.prefixes, p)
		case "max_amount":
			if !mNum(c["max"]) {
				return e, "malformed max_amount caveat"
			}
			e.maxAmount, e.hasAmount = meshMin(e.hasAmount, e.maxAmount, jsF(c["max"])), true
		case "expires":
			if !mNum(c["at"]) {
				return e, "malformed expires caveat"
			}
			e.expiresAt, e.hasExp = meshMin(e.hasExp, e.expiresAt, jsF(c["at"])), true
		case "audience":
			d, ok := meshStrings(c["domains"])
			if !ok {
				return e, "malformed audience caveat"
			}
			e.audience, e.hasAud = meshIntersect(e.hasAud, e.audience, d), true
		case "max_hops":
			if !mNum(c["n"]) {
				return e, "malformed max_hops caveat"
			}
			e.maxHops, e.hasHops = meshMin(e.hasHops, e.maxHops, jsF(c["n"])), true
		default:
			return e, fmt.Sprintf("unknown caveat type \"%s\" (fail closed)", jsMemberString(c, "type"))
		}
	}
	return e, ""
}

func meshSubset(child, parent []string) bool {
	for _, c := range child {
		found := false
		for _, p := range parent {
			if c == p {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func meshNarrows(child, parent meshAuthority) bool {
	if parent.hasAct && (!child.hasAct || !meshSubset(child.actions, parent.actions)) {
		return false
	}
	if parent.hasAud && (!child.hasAud || !meshSubset(child.audience, parent.audience)) {
		return false
	}
	if parent.hasAmount && (!child.hasAmount || child.maxAmount > parent.maxAmount) {
		return false
	}
	if parent.hasExp && (!child.hasExp || child.expiresAt > parent.expiresAt) {
		return false
	}
	if parent.hasHops && (!child.hasHops || child.maxHops > parent.maxHops) {
		return false
	}
	return meshSubset(parent.prefixes, child.prefixes)
}

func meshAdmits(e meshAuthority, a map[string]any, now float64, chainLen int) string {
	typ, _ := a["type"].(string)
	res, _ := a["resource"].(string)
	svc, _ := a["service_domain"].(string)
	if e.hasAct && !meshSubset([]string{typ}, e.actions) {
		return fmt.Sprintf("action \"%s\" not in scope", typ)
	}
	for _, p := range e.prefixes {
		if len(res) < len(p) || res[:len(p)] != p {
			return fmt.Sprintf("resource \"%s\" outside prefix \"%s\"", res, p)
		}
	}
	if e.hasAmount {
		amt, has := a["amount"]
		if !has || jsF(amt) > e.maxAmount {
			return fmt.Sprintf("amount exceeds ceiling %s", jsNumberString(e.maxAmount))
		}
	}
	if e.hasExp && now > e.expiresAt {
		return "capability expired"
	}
	if e.hasAud && !meshSubset([]string{svc}, e.audience) {
		return "service domain not in audience"
	}
	if e.hasHops && float64(chainLen) > e.maxHops {
		return fmt.Sprintf("chain exceeds max_hops %s", jsNumberString(e.maxHops))
	}
	return ""
}

// ---- revocation sets and Merkle proofs ----------------------------------------------------------------------

func meshLeafOK(root string, size int64, id string, proof map[string]any) bool {
	psize, ok := safeInt(proof["size"])
	index, ok2 := safeInt(proof["index"])
	if !ok || !ok2 || psize != size || index < 0 || index >= size {
		return false
	}
	sides := pathShape(int(index), int(size))
	path, ok := proof["path"].([]any)
	if !ok || len(path) != len(sides) {
		return false
	}
	h, err := leafHash(id)
	if err != nil {
		return false
	}
	for i, s := range path {
		step, ok := mRec(s)
		if !ok {
			return false
		}
		side, _ := step["side"].(string)
		hs, _ := step["hash"].(string)
		if side != sides[i] {
			return false
		}
		sib, ok := DecodeB64uStrict(hs, b32)
		if !ok {
			return false
		}
		if side == "L" {
			h = revNodeHash(sib, h)
		} else {
			h = revNodeHash(h, sib)
		}
	}
	bound, ok := bindRevRoot(float64(size), b64.EncodeToString(h))
	return ok && bound == root
}

// meshNonMembership is verifyNonMembership over an expanded proof {size, lo?, hi?}.
func meshNonMembership(root string, nm map[string]any, id string) bool {
	size, ok := safeInt(nm["size"])
	if !ok || size < 0 {
		return false
	}
	lo, hasLo := mRec(nm["lo"])
	hi, hasHi := mRec(nm["hi"])
	if size == 0 {
		bound, ok := bindRevRoot(0, emptyRevTree())
		return !hasLo && !hasHi && ok && bound == root
	}
	if !hasLo && !hasHi {
		return false
	}
	var loIdx, hiIdx int64
	if hasLo {
		loID, _ := lo["id"].(string)
		lp, ok := mRec(lo["proof"])
		if !ok || !(compareUtf8(loID, id) < 0) || !meshLeafOK(root, size, loID, lp) {
			return false
		}
		loIdx, _ = safeInt(lp["index"])
		if !hasHi && loIdx != size-1 {
			return false
		}
	}
	if hasHi {
		hiID, _ := hi["id"].(string)
		hp, ok := mRec(hi["proof"])
		if !ok || !(compareUtf8(id, hiID) < 0) || !meshLeafOK(root, size, hiID, hp) {
			return false
		}
		hiIdx, _ = safeInt(hp["index"])
		if !hasLo && hiIdx != 0 {
			return false
		}
	}
	if hasLo && hasHi && hiIdx != loIdx+1 {
		return false
	}
	return true
}

// meshConsistency is verifyLedgerConsistency (RFC 9162 section 2.1.4.2), with strict 32-byte base64url hashes.
func meshConsistency(oldRoot, newRoot string, proof map[string]any) bool {
	first, ok1 := safeInt(proof["oldSize"])
	second, ok2 := safeInt(proof["newSize"])
	if !ok1 || !ok2 || first < 0 || first > second {
		return false
	}
	raw, _ := proof["path"].([]any)
	if len(raw) > meshMaxPath {
		return false
	}
	empty := emptyRevTree()
	if first == 0 {
		if len(raw) != 0 || oldRoot != empty {
			return false
		}
		if second == 0 {
			return newRoot == empty
		}
		return true
	}
	if first == second {
		return len(raw) == 0 && oldRoot == newRoot
	}
	path := make([][]byte, 0, len(raw)+1)
	if first&(first-1) == 0 {
		o, ok := DecodeB64uStrict(oldRoot, b32)
		if !ok {
			return false
		}
		path = append(path, o)
	}
	for _, p := range raw {
		s, _ := p.(string)
		b, ok := DecodeB64uStrict(s, b32)
		if !ok {
			return false
		}
		path = append(path, b)
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
	return sn == 0 && b64.EncodeToString(fr) == oldRoot && b64.EncodeToString(sr) == newRoot
}

// ---- heads --------------------------------------------------------------------------------------------------

func meshCheckHeadAdvance(prev, next any, proof any) string {
	p, ok := meshValidHead(prev)
	if !ok {
		return "malformed head"
	}
	n, ok := meshValidHead(next)
	if !ok {
		return "malformed head"
	}
	if p["domain"] != n["domain"] {
		return "head is for a different domain"
	}
	if mNatV(n["size"]) < mNatV(p["size"]) || mNatV(n["rev_size"]) < mNatV(p["rev_size"]) {
		return "head rolls back"
	}
	if mNatV(n["size"]) == mNatV(p["size"]) {
		if n["root"] != p["root"] {
			return "equivocation (same size, different log)"
		}
	} else {
		c, ok := meshValidConsistency(proof)
		if !ok || mNatV(c["oldSize"]) != mNatV(p["size"]) || mNatV(c["newSize"]) != mNatV(n["size"]) {
			return "consistency proof required for a larger head"
		}
		if !meshConsistency(p["root"].(string), n["root"].(string), c) {
			return "head is not consistent with the previous head (fork or rewrite)"
		}
	}
	if mNatV(n["rev_size"]) == mNatV(p["rev_size"]) && n["rev_root"] != p["rev_root"] {
		return "equivocation (revocation set)"
	}
	return ""
}

type meshTrustCfg struct {
	human        string
	witnesses    map[string]bool
	threshold    int64
	now          float64
	maxHeadAge   float64
	maxSkew      float64
	maxActionAge float64
	hasActionAge bool
	maxChain     int64
	allowed      []string
	rootDomain   string
	issuerDoms   map[string]any
	pinned       map[string]any
	pqPins       map[string]string
}

func meshOpt(t map[string]any, k string, def float64) (float64, bool) {
	v, has := t[k]
	if !has {
		return def, true
	}
	if !mNum(v) || jsF(v) < 0 {
		return 0, false
	}
	return jsF(v), true
}

func meshValidTrust(traw any) (meshTrustCfg, string) {
	var c meshTrustCfg
	t, ok := mRec(traw)
	if !ok {
		return c, "invalid trust configuration"
	}
	human, ok := mStr(t["humanPrincipal"])
	ws, ok2 := meshStrings(t["witnesses"])
	if !ok || !ok2 {
		return c, "invalid trust configuration"
	}
	c.human = human
	c.witnesses = map[string]bool{}
	for _, w := range ws {
		c.witnesses[w] = true
	}
	if !mNat(t["threshold"]) || mNatV(t["threshold"]) < 1 || mNatV(t["threshold"]) > int64(len(c.witnesses)) {
		return c, "invalid trust configuration: threshold"
	}
	c.threshold = mNatV(t["threshold"])
	if !mNum(t["now"]) {
		return c, "invalid trust configuration: now"
	}
	c.now = jsF(t["now"])
	var okk bool
	if c.maxHeadAge, okk = meshOpt(t, "maxHeadAgeMs", meshDefaultMaxHeadAgeMs); !okk {
		return c, "invalid trust configuration: maxHeadAgeMs"
	}
	if c.maxSkew, okk = meshOpt(t, "maxClockSkewMs", meshDefaultMaxSkewMs); !okk {
		return c, "invalid trust configuration: maxClockSkewMs"
	}
	if _, has := t["maxActionAgeMs"]; has {
		if c.maxActionAge, okk = meshOpt(t, "maxActionAgeMs", 0); !okk {
			return c, "invalid trust configuration: maxActionAgeMs"
		}
		c.hasActionAge = true
	}
	c.maxChain = meshDefaultMaxChain
	if v, has := t["maxChainLength"]; has {
		if !mNat(v) || mNatV(v) < 1 {
			return c, "invalid trust configuration: maxChainLength"
		}
		c.maxChain = mNatV(v)
	}
	ad, ok := meshStrings(t["allowedDomains"])
	if !ok || len(ad) == 0 {
		return c, "invalid trust configuration: allowedDomains is required"
	}
	c.allowed = ad
	rd, ok := mStr(t["rootDomain"])
	if !ok || !meshSubset([]string{rd}, ad) {
		return c, "invalid trust configuration: rootDomain is required and must be in allowedDomains"
	}
	c.rootDomain = rd
	if v, has := t["issuerDomains"]; has {
		m, ok := mRec(v)
		if !ok {
			return c, "invalid trust configuration: issuerDomains"
		}
		for _, x := range m {
			if _, ok := mStr(x); !ok {
				return c, "invalid trust configuration: issuerDomains"
			}
		}
		c.issuerDoms = m
	}
	if v, has := t["pinnedHeads"]; has {
		m, ok := mRec(v)
		if !ok {
			return c, "invalid trust configuration: pinnedHeads"
		}
		c.pinned = m
	}
	if v, has := t["pqPins"]; has {
		if m, ok := mRec(v); ok {
			c.pqPins = map[string]string{}
			for k, x := range m {
				if s, ok := mStr(x); ok {
					c.pqPins[k] = s
				}
			}
		}
	}
	return c, ""
}

func meshCheckCosignedHead(ch any, expectedDomain string, t meshTrustCfg, pinProof any) string {
	chm, _ := mRec(ch)
	h, ok := mRec(chm["head"])
	if !ok || h["domain"] != expectedDomain {
		return "head is for a different domain"
	}
	if _, ok := meshValidHead(h); !ok {
		return "malformed head"
	}
	sig, ok := mStr(chm["sig"])
	if !ok {
		return "malformed head"
	}
	domain, _ := h["domain"].(string)
	m, ok := meshMsg(meshHeadDomain, h)
	if !ok || !verifyB64u(domain, m, sig) {
		return "head not signed by its domain key"
	}
	cosigs, ok := chm["cosigs"].([]any)
	if !ok || len(cosigs) > meshMaxCosigs {
		return "malformed head"
	}
	good := map[string]bool{}
	cm, _ := meshMsg(meshCosigDomain, h)
	for _, c := range cosigs {
		cr, ok := mRec(c)
		if !ok {
			continue
		}
		w, ok1 := mStr(cr["witness"])
		s, ok2 := mStr(cr["sig"])
		if ok1 && ok2 && t.witnesses[w] && !good[w] && verifyB64u(w, cm, s) {
			good[w] = true
		}
	}
	if int64(len(good)) < t.threshold {
		return fmt.Sprintf("head has %d/%d trusted witness cosignatures", len(good), t.threshold)
	}
	ts := jsF(h["timestamp"])
	if ts > t.now+t.maxSkew {
		return "head timestamp is in the future"
	}
	if t.now-ts > t.maxHeadAge {
		return "head is stale"
	}
	if t.pinned != nil {
		if pin, has := t.pinned[domain]; has && meshTruthy(pin) {
			if why := meshCheckHeadAdvance(pin, h, pinProof); why != "" {
				return why + " (vs pinned head)"
			}
		}
	}
	return ""
}

// meshTruthy is JavaScript truthiness for a decoded JSON value.
func meshTruthy(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case bool:
		return t
	case string:
		return t != ""
	}
	if f, ok := jsNum(v); ok {
		return f != 0 && !math.IsNaN(f)
	}
	return true
}

func meshExpandNM(c any, leaves []any) map[string]any {
	m, ok := mRec(c)
	if !ok || !mNat(m["size"]) {
		return nil
	}
	out := map[string]any{"size": m["size"]}
	for _, side := range []string{"lo", "hi"} {
		ix, has := m[side]
		if !has {
			continue
		}
		if !mNat(ix) || mNatV(ix) >= int64(len(leaves)) {
			return nil
		}
		out[side] = leaves[mNatV(ix)]
	}
	return out
}

// VerifyMeshProof verifies a mesh proof end to end, offline. Both arguments are parsed JSON (ParseJSONLenient /
// StrictParse values). It is total: any malformed input is a verdict, never a panic.
func VerifyMeshProof(proof any, trust any) (verdict MeshVerdict) {
	defer func() {
		if r := recover(); r != nil {
			verdict = meshFail("malformed proof", -1)
		}
	}()
	t, bad := meshValidTrust(trust)
	if bad != "" {
		return meshFail(bad, -1)
	}
	p, ok := mRec(proof)
	if !ok {
		return meshFail("malformed proof", -1)
	}
	chain, ok1 := p["chain"].([]any)
	hops, ok2 := p["hops"].([]any)
	heads, ok3 := p["heads"].([]any)
	revLeaves, ok4 := p["rev_leaves"].([]any)
	if !ok1 || !ok2 || !ok3 || !ok4 {
		return meshFail("malformed proof", -1)
	}
	actionSig, okSig := mStr(p["action_sig"])
	action, okAct := meshValidAction(p["action"])
	if !okSig || !okAct {
		return meshFail("malformed action", -1)
	}
	if pp, has := p["pin_proofs"]; has {
		arr, ok := pp.([]any)
		if !ok || len(arr) > meshMaxCosigs {
			return meshFail("malformed pin proofs", -1)
		}
		for _, x := range arr {
			xm, ok := mRec(x)
			if !ok {
				return meshFail("malformed pin proofs", -1)
			}
			if _, ok := mStr(xm["domain"]); !ok {
				return meshFail("malformed pin proofs", -1)
			}
			if _, ok := meshValidConsistency(xm["proof"]); !ok {
				return meshFail("malformed pin proofs", -1)
			}
		}
	}
	if len(chain) < 1 || int64(len(chain)) > t.maxChain {
		return meshFail("chain length out of bounds", -1)
	}
	if len(heads) > len(chain) || len(revLeaves) > 2*len(chain) {
		return meshFail("evidence tables exceed chain size", -1)
	}
	if why, ok := VerifyChainPolicy(chain, t.human, true, nil, t.pqPins, nil); !ok {
		return meshFail("chain: "+why, -1)
	}
	if len(hops) != len(chain) {
		return meshFail("hop evidence count does not match chain length", -1)
	}
	for _, l := range revLeaves {
		lm, ok := mRec(l)
		if !ok {
			return meshFail("malformed revocation leaves", -1)
		}
		if _, ok := mStr(lm["id"]); !ok {
			return meshFail("malformed revocation leaves", -1)
		}
		if _, ok := meshValidInclusion(lm["proof"]); !ok {
			return meshFail("malformed revocation leaves", -1)
		}
	}
	used := map[int64]bool{}
	for _, h := range hops {
		if ev, ok := mRec(h); ok && mNat(ev["head"]) {
			used[mNatV(ev["head"])] = true
		}
	}
	if len(used) != len(heads) {
		return meshFail("unreferenced or missing head in evidence table", -1)
	}

	headErrs := map[int64]string{}
	headDone := map[int64]bool{}
	var prev meshAuthority
	havePrev := false
	for i := range chain {
		cap, _ := mRec(chain[i])
		ev, ok := mRec(hops[i])
		if !ok {
			return meshFail("malformed hop evidence", i)
		}
		domain, okd := mStr(ev["domain"])
		_, revOK := mRec(ev["revocation"])
		if !okd || !mNat(ev["head"]) || mNatV(ev["head"]) >= int64(len(heads)) || !revOK {
			return meshFail("malformed hop evidence", i)
		}
		if !meshSubset([]string{domain}, t.allowed) {
			return meshFail("issuing domain not allowed by policy", i)
		}
		if i == 0 && domain != t.rootDomain {
			return meshFail("root capability must be anchored in the pinned root domain", i)
		}
		issuer, _ := cap["issuer"].(string)
		if i > 0 && t.issuerDoms != nil {
			if pin, has := t.issuerDoms[issuer]; has && pin != domain {
				return meshFail("issuer key is pinned to a different domain", i)
			}
		}
		hi := mNatV(ev["head"])
		ch := heads[hi]
		if !headDone[hi] {
			chm, _ := mRec(ch)
			headM, headIsRec := mRec(chm["head"])
			dom := ""
			if headIsRec {
				if d, ok := mStr(headM["domain"]); ok {
					dom = d
				}
			}
			var pinProof any
			if pps, ok := p["pin_proofs"].([]any); ok {
				for _, x := range pps {
					xm, _ := mRec(x)
					if xm["domain"] == dom {
						pinProof = xm["proof"]
						break
					}
				}
			}
			headErrs[hi] = meshCheckCosignedHead(ch, dom, t, pinProof)
			headDone[hi] = true
		}
		chm, chIsRec := mRec(ch)
		hv, hasHead := chm["head"]
		if !chIsRec || hv == nil || !hasHead {
			return meshFail("malformed proof", -1) // `ch.head.domain` throws in the reference
		}
		headM, headIsRec := mRec(hv)
		if !headIsRec || headM["domain"] != domain {
			return meshFail("source-domain anchor: head is for a different domain", i)
		}
		if e := headErrs[hi]; e != "" {
			return meshFail("source-domain anchor: "+e, i)
		}

		incl, okInc := meshValidInclusion(ev["inclusion"])
		if !okInc || mNatV(incl["size"]) != mNatV(headM["size"]) {
			return meshFail("hop not included in the issuing domain log", i)
		}
		capDigest, err := CapHash(cap)
		root, _ := headM["root"].(string)
		if err != nil || !VerifyInclusion(root, incl, capDigest) {
			return meshFail("hop not included in the issuing domain log", i)
		}

		if i > 0 {
			b, okb := mRec(ev["binding"])
			role, okr := mStr(b["role"])
			bsig, oks := mStr(b["sig"])
			if !okb || !okr || !oks || b["agent"] != cap["issuer"] || b["domain"] != ev["domain"] {
				return meshFail("missing or mismatched domain binding for issuer", i)
			}
			m, okm := meshMsg(meshBindingDomain, map[string]any{"agent": b["agent"], "domain": b["domain"], "role": role})
			if !okm || !verifyB64u(domain, m, bsig) {
				return meshFail("domain binding signature invalid", i)
			}
		}

		rev, _ := mRec(ev["revocation"])
		revRoot, _ := headM["rev_root"].(string)
		id, _ := cap["id"].(string)
		nmCap := meshExpandNM(rev["cap"], revLeaves)
		if nmCap == nil || !meshNonMembership(revRoot, nmCap, id) {
			return meshFail("capability revoked (or revocation proof invalid)", i)
		}
		nmKey := meshExpandNM(rev["issuer_key"], revLeaves)
		if nmKey == nil || !meshNonMembership(revRoot, nmKey, "key:"+issuer) {
			return meshFail("issuer key revoked (or revocation proof invalid)", i)
		}

		eff, why := meshEffective(cap["caveats"])
		if why != "" {
			return meshFail(why, i)
		}
		if havePrev && !meshNarrows(eff, prev) {
			return meshFail("hop widens authority", i)
		}
		prev, havePrev = eff, true
	}

	at := jsF(action["at"])
	if at > t.now+t.maxSkew {
		return meshFail("action timestamp is in the future", -1)
	}
	if t.hasActionAge && t.now-at > t.maxActionAge {
		return meshFail("action is stale", -1)
	}
	tip, _ := mRec(chain[len(chain)-1])
	tipHash, err := CapHash(tip)
	holder, _ := tip["holder"].(string)
	am, okm := meshMsg(meshActionDomain, map[string]any{"action": action, "tip": tipHash})
	if err != nil || !okm || !verifyB64u(holder, am, actionSig) {
		return meshFail("action not signed by the chain tip holder", -1)
	}
	if denied := meshAdmits(prev, action, t.now, len(chain)); denied != "" {
		return meshFail("action not admitted: "+denied, -1)
	}
	return MeshVerdict{OK: true, Hop: -1}
}
