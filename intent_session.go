package pca

// Intent Layer v2 sessions (rule 13; packages/pca/src/intent-session.ts, intent-session-caveat.ts): the signed PCActn
// member `intent_session` (closed wire), the session grant caveat {type: "intent_session", session, seq, root, prev?},
// and the principal-signed session root S (`pca-intent-session` v1) with its digest. The accumulator / monitor
// declarations S carries are intent_acc.go.

import (
	"sort"
	"strings"
)

const (
	intentSessionKind      = "pca-intent-session"
	intentSessionSigDomain = "atlas-pca/intent-session/v1\x00"
	intentSessionRefDomain = "atlas-pca/intent-session-ref/v1"
	intentSessionCaveat    = "intent_session"
	maxSessionSeq          = 2_147_483_647
	maxISAcc               = 16
	maxISFacts             = 16
	maxISProvPaths         = 32
	maxISProvRefs          = 8
	maxISClasses           = 8
	maxISLabels            = 16
	maxISStringBytes       = 256
	maxSessionPrincipals   = 16
	intentGoalV2Prefix     = "pca-intent:v2:"
)

var intentSessionFields = []string{"session", "root", "seq", "schema", "acc", "facts", "offer_set", "prov", "classes", "labels", "map_form"}

func digestList(v any, max int) bool {
	a, ok := v.([]any)
	if !ok || len(a) > max {
		return false
	}
	seen := map[string]bool{}
	for _, x := range a {
		if !isDigestV(x) {
			return false
		}
		s := x.(string)
		if seen[s] {
			return false
		}
		seen[s] = true
	}
	return true
}

// validateIntentSessionWire returns "" when `intent_session` is well-formed (rule 13 wire), else the reason.
func validateIntentSessionWire(v any) string {
	m, ok := v.(map[string]any)
	if !ok {
		return "'intent_session' must be an object"
	}
	if k, ok := closedKeys(m, intentSessionFields...); !ok {
		return "unknown field 'intent_session." + k + "'"
	}
	for _, k := range []string{"session", "root", "seq", "schema"} {
		if _, has := m[k]; !has {
			return "missing field 'intent_session." + k + "'"
		}
	}
	for _, k := range []string{"session", "root", "schema"} {
		if !isDigestV(m[k]) {
			return "'intent_session." + k + "' is not canonical base64url (32 bytes)"
		}
	}
	if !jsIsNonNeg(m["seq"]) || jsF(m["seq"]) > maxSessionSeq {
		return "'intent_session.seq' must be a safe integer in [0, 2147483647]"
	}
	if accV, has := m["acc"]; has {
		acc, ok := accV.([]any)
		if !ok || len(acc) > maxISAcc {
			return "'intent_session.acc' must be an array of at most 16 entries"
		}
		ids := map[string]bool{}
		for _, av := range acc {
			a, ok := av.(map[string]any)
			if !ok {
				return "'intent_session.acc[]' must be an object"
			}
			if _, ok := closedKeys(a, "id", "post", "receipt"); !ok {
				return "unknown field in 'intent_session.acc[]'"
			}
			id, ok := a["id"].(string)
			if !ok || !matchIdent(id, 64, false) {
				return "'intent_session.acc[].id' must match [A-Za-z0-9_]{1,64}"
			}
			if ids[id] {
				return "'intent_session.acc' ids must be distinct"
			}
			ids[id] = true
			if !jsIsNonNeg(a["post"]) {
				return "'intent_session.acc[].post' must be a non-negative safe integer"
			}
			if r, has := a["receipt"]; has && !isDigestV(r) {
				return "'intent_session.acc[].receipt' is not canonical base64url (32 bytes)"
			}
		}
	}
	if f, has := m["facts"]; has && !digestList(f, maxISFacts) {
		return "'intent_session.facts' must be an array of at most 16 distinct digests"
	}
	if o, has := m["offer_set"]; has && !isDigestV(o) {
		return "'intent_session.offer_set' is not canonical base64url (32 bytes)"
	}
	if pv, has := m["prov"]; has {
		prov, ok := pv.(map[string]any)
		if !ok || len(prov) > maxISProvPaths {
			return "'intent_session.prov' must be an object of at most 32 entries"
		}
		for path, rv := range prov {
			if !matchParamPath(path) {
				return "'intent_session.prov' key is not action.params.<name>"
			}
			refs, ok := rv.([]any)
			if !ok || len(refs) == 0 || len(refs) > maxISProvRefs {
				return "'intent_session.prov' entries must be 1..8 strings"
			}
			for _, r := range refs {
				s, ok := r.(string)
				if !ok || s == "" || hasLoneSurrogate(s) || utf8Len(s) > maxISStringBytes {
					return "'intent_session.prov' refs must be non-empty strings of at most 256 UTF-8 bytes"
				}
			}
		}
	}
	if c, has := m["classes"]; has && !digestList(c, maxISClasses) {
		return "'intent_session.classes' must be an array of at most 8 distinct digests"
	}
	if l, has := m["labels"]; has && !digestList(l, maxISLabels) {
		return "'intent_session.labels' must be an array of at most 16 distinct digests"
	}
	if f, has := m["map_form"]; has && f != mapFormCommit {
		return "'intent_session.map_form' must be \"commit\" when present"
	}
	return ""
}

// intentSessionCaveatError: "" for a well-formed {type: "intent_session", session, seq, root, prev?} (prev present
// exactly when seq > 0).
func intentSessionCaveatError(cv any) string {
	c, ok := cv.(map[string]any)
	if !ok || c["type"] != intentSessionCaveat {
		return "not an intent_session caveat"
	}
	if _, ok := closedKeys(c, "type", "session", "seq", "root", "prev"); !ok {
		return "intent_session caveat: unknown member"
	}
	if !isDigestV(c["session"]) || !isDigestV(c["root"]) {
		return "intent_session caveat: session and root must be canonical base64url (32 bytes)"
	}
	if !jsIsNonNeg(c["seq"]) || jsF(c["seq"]) > maxSessionSeq {
		return "intent_session caveat: seq must be a safe integer in [0, 2147483647]"
	}
	prev, hasPrev := c["prev"]
	if (jsF(c["seq"]) == 0) != !hasPrev {
		return "intent_session caveat: prev is present exactly when seq > 0"
	}
	if hasPrev && !isDigestV(prev) {
		return "intent_session caveat: prev must be canonical base64url (32 bytes)"
	}
	return ""
}

// grantSessionCaveat: the FIRST caveat of the grant whose type is intent_session.
func grantSessionCaveat(grant any) (map[string]any, bool) {
	g, ok := grant.(map[string]any)
	if !ok {
		return nil, false
	}
	cav, ok := g["caveats"].([]any)
	if !ok {
		return nil, false
	}
	for _, c := range cav {
		if m, ok := c.(map[string]any); ok && m["type"] == intentSessionCaveat {
			return m, true
		}
	}
	return nil, false
}

var sessionRootKeys = []string{"v", "kind", "session", "principals", "intent_ref", "schema", "layers", "accumulators", "monitors",
	"question_uri", "revocation", "flows", "expires_at", "signer", "alg", "pq_pk", "sig", "pq_sig"}

func sortedKeyList(m map[string]any) string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return strings.Join(ks, ",")
}

func sessionRootBody(s map[string]any) map[string]any {
	out := map[string]any{}
	for _, k := range []string{"v", "kind", "session", "principals", "intent_ref", "schema", "layers", "accumulators", "monitors", "question_uri", "expires_at"} {
		out[k] = s[k]
	}
	for _, k := range []string{"revocation", "flows"} {
		if v, has := s[k]; has {
			out[k] = v
		}
	}
	return out
}

// sessionRootShape is sessionRootShapeError for a signed root: "" when well-formed, else the reason (a suite this
// verifier does not implement is "unsupported_suite: ..."). An absent layers.org / std means no such layer; null is
// malformed.
func sessionRootShape(sv any) string {
	s, ok := sv.(map[string]any)
	if !ok {
		return "session root is not an object"
	}
	if !keysWithin(s, sessionRootKeys) {
		return "session root: unknown member"
	}
	if !jsStrictEq(s["v"], jsNumber(1)) || s["kind"] != intentSessionKind {
		return "not a pca-intent-session v1"
	}
	if !isDigestV(s["session"]) || !isDigestV(s["intent_ref"]) {
		return "session and intent_ref must be canonical base64url (32 bytes)"
	}
	principals, ok := s["principals"].([]any)
	if !ok || len(principals) == 0 || len(principals) > maxSessionPrincipals {
		return "principals must be 1..16 keys"
	}
	keys := map[string]bool{}
	for _, pv := range principals {
		p, ok := pv.(map[string]any)
		if !ok || !keysWithin(p, []string{"key", "alg", "pq_pk"}) || !isDigestV(p["key"]) {
			return "principals entries are {key, alg?, pq_pk?} with a 32-byte key"
		}
		a, aP := p["alg"]
		if e := suiteCapability(a, aP); e != "" {
			return "principal alg: " + e
		}
		if q, has := p["pq_pk"]; has && !b64uOK(q, -1) {
			return "principal pq_pk is not canonical base64url"
		}
		k := p["key"].(string)
		if keys[k] {
			return "principal keys must be distinct"
		}
		keys[k] = true
	}
	sch, ok := s["schema"].(map[string]any)
	if !ok || sortedKeyList(sch) != "aud,digest" {
		return "schema must be {aud, digest}"
	}
	if aud, ok := sch["aud"].(string); !ok || aud == "" || !isDigestV(sch["digest"]) {
		return "schema must be {aud, digest}"
	}
	L, ok := s["layers"].(map[string]any)
	if !ok || !keysWithin(L, []string{"org", "std", "task"}) {
		return "layers must be {org?, std?, task}"
	}
	task, ok := L["task"].(map[string]any)
	if !ok || len(task) != 1 || !hasKey(task, "map_digest") || !isDigestV(task["map_digest"]) {
		return "layers.task must be {map_digest}"
	}
	if org, has := L["org"]; has {
		om, ok := org.(map[string]any)
		if !ok || !isDigestV(om["digest"]) {
			return "layers.org must be an object with a 32-byte digest (absent = no org layer; null is malformed)"
		}
	}
	if std, has := L["std"]; has {
		d, ok := std.(map[string]any)
		if !ok || sortedKeyList(d) != "digest,profile,version" {
			return "layers.std must be {profile, version >= 1, digest} (null is malformed)"
		}
		prof, ok := d["profile"].(string)
		if !ok || prof == "" || utf8Len(prof) > 128 || !(jsIsInt(d["version"]) && jsF(d["version"]) >= 1) || !isDigestV(d["digest"]) {
			return "layers.std must be {profile, version >= 1, digest} (null is malformed)"
		}
	}
	accs, ok := s["accumulators"].([]any)
	if !ok || len(accs) > maxSessionAccumulators {
		return "accumulators must be an array of at most 16"
	}
	ids := map[string]bool{}
	for _, a := range accs {
		if e := accumulatorDeclError(a); e != "" {
			return e
		}
		id := a.(map[string]any)["id"].(string)
		if ids[id] {
			return "accumulator ids must be distinct"
		}
		ids[id] = true
	}
	mons, ok := s["monitors"].([]any)
	if !ok || len(mons) > maxSessionMonitors {
		return "monitors must be an array of at most 16"
	}
	mids := map[string]bool{}
	for _, m := range mons {
		if e := monitorDeclError(m); e != "" {
			return e
		}
		id := m.(map[string]any)["id"].(string)
		if mids[id] {
			return "monitor ids must be distinct"
		}
		mids[id] = true
	}
	if q, ok := s["question_uri"].(string); !ok || q == "" || utf8Len(q) > 2048 {
		return "question_uri must be a non-empty string"
	}
	if rv, has := s["revocation"]; has {
		r, ok := rv.(map[string]any)
		if !ok || !keysWithin(r, []string{"epoch_uri", "max_age_s", "key", "pq_pk"}) {
			return "revocation must be {epoch_uri, max_age_s, key, pq_pk?}"
		}
		if e, ok := r["epoch_uri"].(string); !ok || e == "" {
			return "revocation.epoch_uri must be a non-empty string"
		}
		if !jsIsNonNeg(r["max_age_s"]) {
			return "revocation.max_age_s must be a non-negative safe integer"
		}
		if !isDigestV(r["key"]) {
			return "revocation.key (the dedicated revocation authority) is required: canonical base64url (32 bytes)"
		}
		if keys[r["key"].(string)] {
			return "revocation.key must not be a session principal (a dedicated revocation authority)"
		}
		if q, has := r["pq_pk"]; has && !b64uOK(q, -1) {
			return "revocation.pq_pk must be canonical base64url"
		}
	}
	if f, has := s["flows"]; has {
		if _, ok := f.(map[string]any); !ok {
			return "flows must be an object"
		}
	}
	if !jsIsNonNeg(s["expires_at"]) {
		return "expires_at must be a non-negative safe integer (epoch ms)"
	}
	if !isDigestV(s["signer"]) || !keys[s["signer"].(string)] {
		return "signer is not one of the session principals"
	}
	alg, algP := s["alg"]
	if e := suiteCapability(alg, algP); e != "" {
		return "alg: " + e
	}
	_, hasPq := s["pq_pk"]
	_, hasPqSig := s["pq_sig"]
	if suiteAlgName(alg, algP) == "ed25519" && (hasPq || hasPqSig) {
		return "an ed25519 session root must not carry pq_pk / pq_sig"
	}
	if _, ok := s["sig"].(string); !ok {
		return "sig must be a string"
	}
	if _, ok := strictBytes(sessionRootBody(s)); !ok {
		return "malformed session root: not strictly canonical"
	}
	return ""
}

// sessionPinFor: the verifier's own PQ pin for signer, an OWN member of pq_pins (context session.pq_pins) whose value is
// a string; ("", false) otherwise (absent, not an object, not a string).
func sessionPinFor(pins any, signer string) (string, bool) {
	m, ok := pins.(map[string]any)
	if !ok {
		return "", false
	}
	v, ok := m[signer].(string)
	return v, ok
}

// verifySessionRoot: shape, signer listed, suite signature; "" when it verifies, else the reason. R3-01 (fail closed): a
// non-ed25519 root verifies only under the VERIFIER's pin for its signer (pins = context session.pq_pins), never under
// the root's own principals[].pq_pk (part of the presented artifact); the signer's own entry, when it declares a pq_pk,
// must agree. An ed25519 root never consults the pins.
func verifySessionRoot(sv any, pins any) string {
	if r := sessionRootShape(sv); r != "" {
		return r
	}
	s := sv.(map[string]any)
	signer := s["signer"].(string)
	alg, algP := s["alg"]
	pq, pqP := s["pq_pk"]
	suite, _ := resolveSigAlg(alg, algP)
	var pin map[string]string
	if suite.needsPqPk {
		pinned, ok := sessionPinFor(pins, signer)
		if !ok {
			return "session root suite '" + suite.alg + "' needs the signer's PQ key pinned by the verifier (pq_pins); the root's own principals entry proves nothing about who signed it"
		}
		if pqS, isS := pq.(string); !pqP || !isS || pqS != pinned {
			return "session root pq_pk does not match the verifier's pin for the signer"
		}
		for _, pv := range s["principals"].([]any) {
			p := pv.(map[string]any)
			if p["key"] == signer {
				if e, has := p["pq_pk"]; has && e != pq {
					return "session root pq_pk does not match the signer's principals entry"
				}
				break
			}
		}
		pin = map[string]string{signer: pinned}
	}
	base := sessionRootBody(s)
	base["signer"] = signer
	bound, ok := bindSuiteFields(base, alg, algP, pq, pqP)
	if !ok {
		return "session root signature invalid"
	}
	msg, ok := domainMessage(intentSessionSigDomain, bound)
	if !ok || !verifyPinnedSuite(alg, algP, signer, pq, msg, s["sig"], s["pq_sig"], pin) {
		return "session root signature invalid"
	}
	return ""
}

// sessionRootDigest = hashCanonical({d: "atlas-pca/intent-session-ref/v1", s: S}).
func sessionRootDigest(s any) (string, bool) {
	return hashCanonicalV(map[string]any{"d": intentSessionRefDomain, "s": s})
}
