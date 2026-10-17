package pca

// Shared plumbing of the Intent Layer v2 artifacts (packages/pca/src/intent-artifacts.ts and the pinned-suite seam of
// pq.ts): suite-agile signatures under a verifier-pinned identity (session roots, action schemas, accumulator
// receipts, sequencer key sets, revocation epochs) and the Ed25519 W-B artifacts (facts, offer sets, label receipts,
// classifier verdicts) with their content references.

import "strings"

// suiteAlgName is resolveSigAlg(alg)?.alg ("" when unknown). Only the suites this verifier implements resolve; an
// artifact under another registered suite fails closed here (see sigSuites).
func suiteAlgName(alg any, present bool) string {
	s, ok := resolveSigAlg(alg, present)
	if !ok {
		return ""
	}
	return s.alg
}

// bindSuiteFields: for a non-ed25519 suite the signed body also carries `alg` and `pq_pk` (pq_pk absent makes the
// body unserialisable in the reference: undefined is refused, so ok is false).
func bindSuiteFields(base map[string]any, alg any, algPresent bool, pqPk any, pqPresent bool) (map[string]any, bool) {
	s, ok := resolveSigAlg(alg, algPresent)
	if !ok || s.alg == "ed25519" {
		return base, true
	}
	if !pqPresent {
		return nil, false
	}
	out := make(map[string]any, len(base)+2)
	for k, v := range base {
		out[k] = v
	}
	out["alg"] = s.alg
	out["pq_pk"] = pqPk
	return out, true
}

// suiteSupported: the artifact's `alg` (absent = ed25519) resolves in the SDK's suite dispatch.
func suiteSupported(alg any, present bool) bool {
	_, ok := resolveSigAlg(alg, present)
	return ok
}

// verifyPinnedSuite mirrors pq.ts verifyPinnedSuite through the SDK's ONE suite dispatch (verifyLeafSuite): a suite
// without a PQ key verifies under `identity`; a suite with one only under a PQ key pinned for `identity`
// (pins[identity] must equal the artifact's pq_pk; no pin => refused). No suite is named here.
func verifyPinnedSuite(alg any, algPresent bool, identity string, artifactPqPk any, msg []byte, sig, pqSig any, pins map[string]string) bool {
	s, ok := resolveSigAlg(alg, algPresent)
	if !ok {
		return false
	}
	key := pqVerifyKey{}
	if s.needsPqPk {
		pk, ok := artifactPqPk.(string)
		if !ok || pk == "" {
			return false
		}
		if pin, has := pins[identity]; !has || pin != pk {
			return false
		}
		key = pqVerifyKey{pk}
	}
	return verifyLeafSuite(alg, algPresent, identity, key, msg, sig, pqSig)
}

func pinOf(identity string, pq any, present bool) map[string]string {
	if !present {
		return nil
	}
	s, _ := pq.(string)
	return map[string]string{identity: s}
}

// domainMessage = utf8(domain) || strictCanonical(body).
func domainMessage(domain string, body any) ([]byte, bool) {
	b, ok := strictBytes(body)
	if !ok {
		return nil, false
	}
	return append([]byte(domain), b...), true
}

func withoutKeys(m map[string]any, drop ...string) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	for _, k := range drop {
		delete(out, k)
	}
	return out
}

// suiteMembers are the optional suite members every W-B artifact may carry.
var suiteMembers = []string{"alg", "pq_pk", "pq_sig"}

// artifactSuiteError is the reference artifactSuiteError: "" when usable; a non-string alg / pq_pk / pq_sig is
// malformed; an alg the suite dispatch does not implement is "unsupported_suite: ..."; an ed25519 artifact (alg
// absent or "ed25519") carries neither pq_pk nor pq_sig.
func artifactSuiteError(a map[string]any) string {
	alg, algP := a["alg"]
	if e := suiteCapability(alg, algP); e != "" {
		return e
	}
	for _, k := range []string{"pq_pk", "pq_sig"} {
		if v, has := a[k]; has {
			if _, ok := v.(string); !ok {
				return k + " must be a string"
			}
		}
	}
	_, hasPq := a["pq_pk"]
	_, hasPqSig := a["pq_sig"]
	if suiteAlgName(alg, algP) == "ed25519" && (hasPq || hasPqSig) {
		return "an ed25519 artifact must not carry pq_pk / pq_sig"
	}
	return ""
}

// pinPqOK: a pin entry's optional pq_pk is absent or a non-empty string (JSON null is malformed).
func pinPqOK(pin map[string]any) bool {
	v, has := pin["pq_pk"]
	if !has {
		return true
	}
	s, ok := v.(string)
	return ok && s != ""
}

// verifyArtifactSig verifies a W-B artifact (suite checked by artifactSuiteError) under a PINNED signer: the suite's
// signature over domain || strictCanonical(artifact without sig / pq_sig), Ed25519 under pk, a PQ suite only when the
// artifact's pq_pk equals the pinned pq_pk (pinPq: the pin entry's pq_pk, or nil).
func verifyArtifactSig(domain string, artifact map[string]any, pk any, pinPq any) bool {
	sig, ok := artifact["sig"].(string)
	pks, ok2 := pk.(string)
	if !ok || !ok2 {
		return false
	}
	msg, ok := domainMessage(domain, withoutKeys(artifact, "sig", "pq_sig"))
	if !ok {
		return false
	}
	var pins map[string]string
	if q, ok := pinPq.(string); ok {
		pins = map[string]string{pks: q}
	}
	alg, algP := artifact["alg"]
	return verifyPinnedSuite(alg, algP, pks, artifact["pq_pk"], msg, sig, artifact["pq_sig"], pins)
}

// artifactRef = b64u(sha256(strictCanonical({d: refDomain, [slot]: artifact}))); ok false when not canonical.
func artifactRef(refDomain, slot string, artifact any) (string, bool) {
	return hashCanonicalV(map[string]any{"d": refDomain, slot: artifact})
}

// closedMembers: exactly `required` plus any of `optional`.
func closedMembers(o map[string]any, required []string, optional ...string) bool {
	for k := range o {
		if !contains(required, k) && !contains(optional, k) {
			return false
		}
	}
	for _, k := range required {
		if _, ok := o[k]; !ok {
			return false
		}
	}
	return true
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// containsV is Array.prototype.includes over JSON values (SameValueZero: numbers by value).
func containsV(xs []any, v any) bool {
	for _, x := range xs {
		if jsStrictEq(x, v) {
			return true
		}
	}
	return false
}

// isPathSegment: [A-Za-z0-9_-]{1,64} and not __proto__ / constructor / prototype.
func isPathSegment(s string) bool { return matchIdent(s, 64, true) && !forbiddenSegments[s] }

// resolveParamPath resolves `action.params.<a>.<b>…` inside params (own members of plain objects only).
func resolveParamPath(params any, path any) (any, bool) {
	p, ok := path.(string)
	const pre = "action.params."
	if !ok || !strings.HasPrefix(p, pre) {
		return nil, false
	}
	cur := params
	for _, s := range strings.Split(p[len(pre):], ".") {
		m, ok := cur.(map[string]any)
		if !isPathSegment(s) || !ok {
			return nil, false
		}
		v, has := m[s]
		if !has {
			return nil, false
		}
		cur = v
	}
	return cur, true
}

// isParamPath: a well-formed `action.params.*` path of 1..8 segments.
func isParamPath(path any) bool {
	p, ok := path.(string)
	const pre = "action.params."
	if !ok || !strings.HasPrefix(p, pre) {
		return false
	}
	segs := strings.Split(p[len(pre):], ".")
	if len(segs) < 1 || len(segs) > 8 {
		return false
	}
	for _, s := range segs {
		if !isPathSegment(s) {
			return false
		}
	}
	return true
}

// setNested sets value at the dotted path under root; false when the path collides with a leaf or a subtree.
func setNested(root map[string]any, path string, value any) bool {
	segs := strings.Split(path, ".")
	cur := root
	for _, k := range segs[:len(segs)-1] {
		if _, ok := cur[k]; !ok {
			cur[k] = map[string]any{}
		}
		next, ok := cur[k].(map[string]any)
		if !ok {
			return false
		}
		cur = next
	}
	last := segs[len(segs)-1]
	if _, ok := cur[last]; ok {
		return false
	}
	cur[last] = value
	return true
}

// arrayOf reads an optional list member: absent is empty; present it must be an array (JSON null is MALFORMED: ok
// false, the caller fails closed).
func arrayOf(v any, present bool) ([]any, bool) {
	if !present {
		return nil, true
	}
	a, ok := v.([]any)
	return a, ok
}

// paramsOK: an action's optional `params` member is absent (empty) or an object; JSON null is malformed.
func paramsOK(action map[string]any) bool {
	p, has := action["params"]
	if !has {
		return true
	}
	_, ok := p.(map[string]any)
	return ok
}

// suiteCapability is the reference suiteCapabilityError: "" for an absent alg (ed25519) or one the SDK suite dispatch
// implements; "alg must be a string" for a non-string; "unsupported_suite: '<alg>'" for a string it does not implement.
func suiteCapability(alg any, present bool) string {
	if !present {
		return ""
	}
	s, ok := alg.(string)
	if !ok {
		return "alg must be a string"
	}
	if !suiteSupported(s, true) {
		return UnsupportedSuite + ": '" + s + "'"
	}
	return ""
}

// algUnsupported: the object carries a STRING `alg` member the suite dispatch does not implement.
func algUnsupported(v any, member string) bool {
	m, ok := v.(map[string]any)
	if !ok {
		return false
	}
	a, has := m[member]
	_, isS := a.(string)
	return has && isS && !suiteSupported(a, true)
}

// actionSchemaSuiteReason: "unsupported_suite" when the schema's sig.alg or the pinned key entry's alg is refused.
func actionSchemaSuiteReason(dv any, keysV any) string {
	sig, _ := member(dv, "sig")
	if algUnsupported(sig, "alg") {
		return UnsupportedSuite
	}
	kid, _ := member(sig, "kid")
	keys, _ := keysV.([]any)
	for _, k := range keys {
		if m, ok := k.(map[string]any); ok && jsStrictEq(m["kid"], kid) {
			if algUnsupported(m, "alg") {
				return UnsupportedSuite
			}
			break
		}
	}
	return ""
}

// receiptSuiteReason: "unsupported_suite" when the receipt, a presented key set or one of its entries names a refused
// suite (reported only when no presented set verified the receipt).
func receiptSuiteReason(r any, keySets []any) string {
	if algUnsupported(r, "alg") {
		return UnsupportedSuite
	}
	for _, k := range keySets {
		if algUnsupported(k, "alg") {
			return UnsupportedSuite
		}
		es, _ := member(k, "keys")
		arr, _ := es.([]any)
		for _, e := range arr {
			if algUnsupported(e, "alg") {
				return UnsupportedSuite
			}
		}
	}
	return ""
}
