package pca

// Accumulators, monitors, sequencer reservation receipts and the sequencer's root-signed key sets (rule 15;
// packages/pca/src/intent-acc.ts). The verifier recomputes every post-action value from state it holds (site-local
// pre-state) or from a receipt whose signing key a root-signed `pca-sequencer-keys` set lists for the receipt's issue
// time; the agent's claim must equal it.

import "math"

const (
	maxSessionAccumulators = 16
	maxSessionMonitors     = 16
	maxMonitorWithin       = 64
	accReceiptDomain       = "atlas-pca/acc-receipt/v1\x00"
	accReceiptRefDomain    = "atlas-pca/acc-receipt-ref/v1"
	accReserveDomain       = "atlas-pca/acc-reserve/v1"
	sequencerKeysDomain    = "atlas-pca/sequencer-keys/v1\x00"
	receiptSkewMs          = 60_000
	// maxReceiptLifetimeMs bounds a receipt: issued_at <= expires_at <= issued_at + 15 min.
	maxReceiptLifetimeMs = 900_000
	// defaultMaxReceiptAgeMs / defaultMaxKeySetAgeMs: policy acc.max_receipt_age_s / max_keyset_age_s defaults.
	defaultMaxReceiptAgeMs = 900_000
	defaultMaxKeySetAgeMs  = 3_600_000
)

var (
	accAggs      = []string{"sum", "count", "distinct", "max"}
	monitorKinds = []string{"requires_prior", "precedes", "never", "always", "responds_within"}
)

// matchKid is ^[A-Za-z0-9_.:-]{1,64}$.
func matchKid(s string) bool {
	if len(s) < 1 || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == ':' || c == '-') {
			return false
		}
	}
	return true
}

func predicateShapeOK(p any) bool {
	m, ok := p.(map[string]any)
	if !ok {
		return false
	}
	switch v := m["verb"].(type) {
	case string:
		return true
	case []any:
		if len(v) == 0 {
			return false
		}
		for _, x := range v {
			if _, ok := x.(string); !ok {
				return false
			}
		}
		return true
	}
	return false
}

// accumulatorDeclError: "" for a well-formed accumulator declaration of S.
func accumulatorDeclError(av any) string {
	a, ok := av.(map[string]any)
	if !ok || !keysWithin(a, []string{"id", "agg", "val", "unit", "sel", "win", "key", "domain_max", "cap", "holder"}) {
		return "accumulator: not an object / unknown member"
	}
	if id, ok := a["id"].(string); !ok || !matchIdent(id, 64, false) || forbiddenSegments[id] {
		return "accumulator id must match [A-Za-z0-9_]{1,64} and not be __proto__ / constructor / prototype"
	}
	if !strIn(a["agg"], accAggs) {
		return "accumulator agg"
	}
	val, hasVal := a["val"]
	if hasVal {
		if s, ok := val.(string); !ok || !matchParamPath(s) {
			return "accumulator val"
		}
	}
	if u, has := a["unit"]; has {
		if s, ok := u.(string); !ok || jsLen(s) > 64 || !matchUnitID(s) {
			return "accumulator unit"
		}
	}
	sel, ok := a["sel"].(map[string]any)
	if !ok || !keysWithin(sel, []string{"verbs", "accumulates_into", "event"}) {
		return "accumulator sel"
	}
	if vs, has := sel["verbs"]; has {
		arr, ok := vs.([]any)
		if !ok || len(arr) == 0 || len(arr) > 64 {
			return "accumulator sel.verbs"
		}
		for _, x := range arr {
			if s, ok := x.(string); !ok || s == "" {
				return "accumulator sel.verbs"
			}
		}
	}
	ai, hasAI := sel["accumulates_into"]
	if hasAI {
		if s, ok := ai.(string); !ok || !matchUnitID(s) {
			return "accumulator sel.accumulates_into"
		}
	}
	ev, hasEv := sel["event"]
	if hasEv && !strIn(ev, []string{"intent_required", "question", "clarification"}) {
		return "accumulator sel.event"
	}
	_, hasVerbs := sel["verbs"]
	if (hasVerbs || hasAI) == hasEv {
		return "accumulator sel kind"
	}
	w, ok := a["win"].(map[string]any)
	if !ok {
		return "accumulator win"
	}
	switch w["kind"] {
	case "task":
		if len(w) != 1 {
			return "accumulator win task"
		}
	case "sliding":
		if sortedKeyList(w) != "kind,ms" || !(jsIsInt(w["ms"]) && jsF(w["ms"]) > 0) {
			return "accumulator win sliding"
		}
	case "period":
		if sortedKeyList(w) != "kind,ms,t0" || !(jsIsInt(w["ms"]) && jsF(w["ms"]) > 0) || !jsIsNonNeg(w["t0"]) {
			return "accumulator win period"
		}
	default:
		return "accumulator win kind"
	}
	key, hasKeyM := a["key"]
	if !hasKeyM || key != nil {
		if s, ok := key.(string); !ok || !matchParamPath(s) {
			return "accumulator key"
		}
	}
	if d, has := a["domain_max"]; has && !jsIsNonNeg(d) {
		return "accumulator domain_max"
	}
	if c, has := a["cap"]; has && !jsIsNonNeg(c) {
		return "accumulator cap"
	}
	h, ok := a["holder"].(map[string]any)
	if !ok {
		return "accumulator holder"
	}
	switch h["kind"] {
	case "site_local", "wallet":
		if len(h) != 1 {
			return "accumulator holder members"
		}
	case "sequenced":
		if !keysWithin(h, []string{"kind", "uri", "root", "root_alg", "root_pq_pk", "keys_uri"}) {
			return "accumulator holder sequenced member"
		}
		if u, ok := h["uri"].(string); !ok || u == "" {
			return "accumulator holder uri"
		}
		if !isDigestV(h["root"]) {
			return "accumulator holder root"
		}
		ra, raP := h["root_alg"]
		if e := suiteCapability(ra, raP); e != "" {
			return "accumulator holder root_alg: " + e
		}
		if rp, has := h["root_pq_pk"]; has && !b64uOK(rp, -1) {
			return "accumulator holder root_pq_pk"
		}
		if ku, has := h["keys_uri"]; has {
			if s, ok := ku.(string); !ok || s == "" {
				return "accumulator holder keys_uri"
			}
		}
	default:
		return "accumulator holder kind"
	}
	wallet := h["kind"] == "wallet"
	if wallet != hasEv {
		return "accumulator wallet"
	}
	if !wallet {
		agg := a["agg"].(string)
		if agg != "count" && !hasVal && !hasAI {
			return "accumulator needs val"
		}
		if agg != "sum" && agg != "count" && !hasVal {
			return "accumulator needs val"
		}
		if agg == "count" && hasVal {
			return "count takes no val"
		}
	}
	return ""
}

// monitorDeclError: "" for a well-formed monitor declaration of S.
func monitorDeclError(mv any) string {
	m, ok := mv.(map[string]any)
	if !ok || !keysWithin(m, []string{"id", "kind", "p", "q", "status", "within"}) {
		return "monitor shape"
	}
	if id, ok := m["id"].(string); !ok || !matchIdent(id, 64, false) || forbiddenSegments[id] {
		return "monitor id must match [A-Za-z0-9_]{1,64} and not be __proto__ / constructor / prototype"
	}
	if !strIn(m["kind"], monitorKinds) {
		return "monitor kind"
	}
	if !predicateShapeOK(m["p"]) {
		return "monitor p"
	}
	kind := m["kind"].(string)
	needsQ := kind == "requires_prior" || kind == "precedes" || kind == "responds_within"
	q, hasQ := m["q"]
	if needsQ != hasQ || (hasQ && !predicateShapeOK(q)) {
		return "monitor q"
	}
	if st, has := m["status"]; has && st != "admitted" && st != "committed" {
		return "monitor status"
	}
	within, hasW := m["within"]
	if (kind == "responds_within") != hasW {
		return "monitor within"
	}
	if hasW && !(jsIsInt(within) && jsF(within) >= 1 && jsF(within) <= maxMonitorWithin) {
		return "monitor within range"
	}
	return ""
}

// monitorStates is the state set Q of a monitor.
func monitorStates(m map[string]any) []string {
	switch m["kind"] {
	case "requires_prior", "precedes":
		return []string{"unmet", "met"}
	case "never":
		return []string{"clean", "seen"}
	case "always":
		return []string{"ok", "broken"}
	case "responds_within":
		w := 0
		if jsIsInt(m["within"]) {
			w = int(jsF(m["within"]))
		}
		out := []string{"idle"}
		for i := 1; i <= w; i++ {
			out = append(out, "pending:"+itoa(i))
		}
		return append(out, "missed")
	}
	return nil
}

func itoa(i int) string { return jsNumberString(float64(i)) }

// accSelects: ω ∈ sel. throws reports a reference TypeError (an unusable entry of an unverified schema).
func accSelects(a map[string]any, verb string, schema any, haveSchema bool) (bool, bool) {
	sel := a["sel"].(map[string]any)
	if _, has := sel["event"]; has {
		return false, false
	}
	if vs, ok := sel["verbs"].([]any); ok && containsV(vs, verb) {
		return true, false
	}
	if ai, has := sel["accumulates_into"]; has && haveSchema {
		v, throws := schemaVerbOf(schema, verb)
		if throws {
			return false, true
		}
		if v == nil {
			return false, false
		}
		ps, throws := accumulationParams(v, ai.(string))
		return len(ps) > 0, throws
	}
	return false, false
}

// distinctKey: the strict canonical JSON text of a string or a safe integer (not -0).
func distinctKey(x any) (string, bool) {
	if _, ok := x.(string); !ok && !jsIsInt(x) {
		return "", false
	}
	s, err := Canonicalize(x)
	return s, err == nil
}

// accValue is val(ω) of a selected action (ok false: unreadable; throws: a reference TypeError).
type accValue struct {
	val float64
	key string
}

func accValueOf(a map[string]any, verb string, params map[string]any, schema any, haveSchema bool) (v accValue, ok bool, throws bool) {
	read := func(path string) (any, bool) {
		x, has := params[path[len("action.params."):]]
		return x, has
	}
	agg := a["agg"].(string)
	if agg == "count" {
		return accValue{val: 1}, true, false
	}
	if agg == "distinct" {
		x, _ := read(a["val"].(string))
		k, ok := distinctKey(x)
		return accValue{val: 1, key: k}, ok, false
	}
	if vp, has := a["val"]; has {
		x, _ := read(vp.(string))
		if !jsIsNonNeg(x) {
			return v, false, false
		}
		return accValue{val: jsF(x)}, true, false
	}
	if !haveSchema {
		return v, false, false
	}
	ve, th := schemaVerbOf(schema, verb)
	if th {
		return v, false, true
	}
	if ve == nil {
		return v, false, false
	}
	ps, th := accumulationParams(ve, a["sel"].(map[string]any)["accumulates_into"].(string))
	if th {
		return v, false, true
	}
	s := 0.0
	for _, p := range ps {
		x, has := read(p)
		if !has {
			continue
		}
		if !jsIsNonNeg(x) {
			return v, false, false
		}
		s += jsF(x)
		if !jsIsSafeInteger(jsNumber(s)) {
			return v, false, false
		}
	}
	return accValue{val: s}, true, false
}

func preWant(agg string) string {
	switch agg {
	case "sum":
		return "sum"
	case "count":
		return "count"
	case "max":
		return "max"
	}
	return "values"
}

// preStateOK is preStateError == null.
func preStateOK(agg string, s any) bool {
	m, ok := s.(map[string]any)
	if !ok {
		return false
	}
	want := preWant(agg)
	if len(m) != 1 || !hasKey(m, want) {
		return false
	}
	if want == "values" {
		vs, ok := m["values"].([]any)
		if !ok {
			return false
		}
		for _, x := range vs {
			if _, ok := x.(string); !ok {
				return false
			}
		}
		return distinctStrings(vs)
	}
	return jsIsNonNeg(m[want])
}

func preValue(agg string, pre map[string]any) float64 {
	if agg == "distinct" {
		return float64(len(pre["values"].([]any)))
	}
	return jsF(pre[preWant(agg)])
}

// combineAcc: the post-action value (ok false when it leaves the safe-integer range).
func combineAcc(agg string, pre map[string]any, v accValue) (float64, bool) {
	var post float64
	switch agg {
	case "sum":
		post = jsF(pre["sum"]) + v.val
	case "count":
		post = jsF(pre["count"]) + 1
	case "max":
		post = math.Max(jsF(pre["max"]), v.val)
	case "distinct":
		vs := pre["values"].([]any)
		post = float64(len(vs))
		if !containsV(vs, v.key) {
			post++
		}
	}
	return post, jsIsSafeInteger(jsNumber(post))
}

// pcactnReservationDigest = hashCanonical({d: "atlas-pca/acc-reserve/v1", b: PCActn without sig, pq_sig, threshold,
// intent_session}).
func pcactnReservationDigest(p map[string]any) (string, bool) {
	return hashCanonicalV(map[string]any{"d": accReserveDomain, "b": withoutKeys(p, "sig", "pq_sig", "threshold", "intent_session")})
}

var receiptKeys = []string{"v", "kind", "session", "acc", "seq", "pre", "delta", "post", "pcactn_digest", "aud", "issued_at", "expires_at",
	"kid", "ledger", "signer", "alg", "pq_pk", "sig", "pq_sig"}

func accReceiptShapeOK(rv any) bool {
	r, ok := rv.(map[string]any)
	if !ok || !keysWithin(r, receiptKeys) || !jsStrictEq(r["v"], jsNumber(1)) || r["kind"] != "pca-acc-receipt" {
		return false
	}
	if !isDigestV(r["session"]) {
		return false
	}
	if s, ok := r["acc"].(string); !ok || !matchIdent(s, 64, false) {
		return false
	}
	if !(jsIsInt(r["seq"]) && jsF(r["seq"]) >= 1) || !jsIsNonNeg(r["pre"]) || !jsIsNonNeg(r["delta"]) || !jsIsNonNeg(r["post"]) {
		return false
	}
	if !isDigestV(r["pcactn_digest"]) {
		return false
	}
	if s, ok := r["aud"].(string); !ok || s == "" {
		return false
	}
	if !jsIsNonNeg(r["issued_at"]) || !jsIsNonNeg(r["expires_at"]) {
		return false
	}
	if iss, exp := jsF(r["issued_at"]), jsF(r["expires_at"]); !(exp >= iss && exp-iss <= maxReceiptLifetimeMs) {
		return false
	}
	if s, ok := r["kid"].(string); !ok || !matchKid(s) {
		return false
	}
	l, ok := r["ledger"].(map[string]any)
	if !ok || sortedKeyList(l) != "head,index" || !jsIsNonNeg(l["index"]) || !isDigestV(l["head"]) {
		return false
	}
	if !isDigestV(r["signer"]) {
		return false
	}
	alg, algP := r["alg"]
	name := suiteAlgName(alg, algP)
	if name == "" {
		return false
	}
	_, hasPq := r["pq_pk"]
	_, hasPqSig := r["pq_sig"]
	if name == "ed25519" && (hasPq || hasPqSig) {
		return false
	}
	_, ok = r["sig"].(string)
	return ok
}

func receiptBody(r map[string]any) map[string]any {
	l := r["ledger"].(map[string]any)
	out := map[string]any{"ledger": map[string]any{"index": l["index"], "head": l["head"]}}
	for _, k := range []string{"v", "kind", "session", "acc", "seq", "pre", "delta", "post", "pcactn_digest", "aud", "issued_at", "expires_at", "kid", "signer"} {
		out[k] = r[k]
	}
	return out
}

func verifyAccReceiptSignature(r map[string]any, expectedSigner string, pins map[string]string) bool {
	if !accReceiptShapeOK(r) || r["signer"] != expectedSigner {
		return false
	}
	alg, algP := r["alg"]
	pq, pqP := r["pq_pk"]
	bound, ok := bindSuiteFields(receiptBody(r), alg, algP, pq, pqP)
	if !ok {
		return false
	}
	msg, ok := domainMessage(accReceiptDomain, bound)
	return ok && verifyPinnedSuite(alg, algP, expectedSigner, pq, msg, r["sig"], r["pq_sig"], pins)
}

// accReceiptDigest = hashCanonical({d: "atlas-pca/acc-receipt-ref/v1", r: receipt}).
func accReceiptDigest(r any) (string, bool) {
	return hashCanonicalV(map[string]any{"d": accReceiptRefDomain, "r": r})
}

func sequencerKeySetShapeOK(kv any) bool {
	k, ok := kv.(map[string]any)
	if !ok || !keysWithin(k, []string{"v", "kind", "sequencer", "version", "issued_at", "keys", "alg", "pq_pk", "sig", "pq_sig"}) {
		return false
	}
	if !jsStrictEq(k["v"], jsNumber(1)) || k["kind"] != "pca-sequencer-keys" || !isDigestV(k["sequencer"]) || !jsIsNonNeg(k["issued_at"]) {
		return false
	}
	if !(jsIsNonNeg(k["version"]) && jsF(k["version"]) >= 1) {
		return false
	}
	keys, ok := k["keys"].([]any)
	if !ok || len(keys) == 0 || len(keys) > 256 {
		return false
	}
	kids := map[string]bool{}
	for _, ev := range keys {
		e, ok := ev.(map[string]any)
		if !ok || !keysWithin(e, []string{"kid", "pk", "alg", "pq_pk", "not_before", "not_after"}) {
			return false
		}
		kid, ok := e["kid"].(string)
		if !ok || !matchKid(kid) || kids[kid] {
			return false
		}
		kids[kid] = true
		if !isDigestV(e["pk"]) {
			return false
		}
		if a, has := e["alg"]; has && suiteAlgName(a, true) == "" {
			return false
		}
		if q, has := e["pq_pk"]; has && !b64uOK(q, -1) {
			return false
		}
		if !jsIsNonNeg(e["not_before"]) {
			return false
		}
		if na, has := e["not_after"]; has && !(jsIsNonNeg(na) && jsF(na) >= jsF(e["not_before"])) {
			return false
		}
	}
	alg, algP := k["alg"]
	name := suiteAlgName(alg, algP)
	if name == "" {
		return false
	}
	_, hasPq := k["pq_pk"]
	_, hasPqSig := k["pq_sig"]
	if name == "ed25519" && (hasPq || hasPqSig) {
		return false
	}
	_, ok = k["sig"].(string)
	return ok
}

// verifySequencerKeySet: a key set signed by the session's pinned sequencer root (PQ pinned by root_pq_pk).
func verifySequencerKeySet(kv any, root any, rootPq any, rootPqPresent bool) bool {
	if !sequencerKeySetShapeOK(kv) {
		return false
	}
	k := kv.(map[string]any)
	rs, ok := root.(string)
	if !ok || k["sequencer"] != rs {
		return false
	}
	body := map[string]any{"v": k["v"], "kind": k["kind"], "sequencer": k["sequencer"], "version": k["version"], "issued_at": k["issued_at"], "keys": k["keys"]}
	alg, algP := k["alg"]
	pq, pqP := k["pq_pk"]
	bound, ok := bindSuiteFields(body, alg, algP, pq, pqP)
	if !ok {
		return false
	}
	msg, ok := domainMessage(sequencerKeysDomain, bound)
	return ok && verifyPinnedSuite(alg, algP, rs, pq, msg, k["sig"], k["pq_sig"], pinOf(rs, rootPq, rootPqPresent))
}

// receiptFreshness: the rule-15 bounds (policy acc, defaults 15 min / 1 h) and the tracked key-set version.
type receiptFreshness struct {
	maxReceiptAgeMs, maxKeySetAgeMs float64
	tracked                         map[string]any // acc.keyset_versions[root] (nil: not tracked)
}

const sequencerKeysRefDomain = "atlas-pca/sequencer-keys-ref/v1"

// sequencerKeySetDigest = base64url(sha256(strictCanonical({"d": "atlas-pca/sequencer-keys-ref/v1", "k": set}))).
func sequencerKeySetDigest(ks any) (string, bool) {
	return hashCanonicalV(map[string]any{"d": sequencerKeysRefDomain, "k": ks})
}

// trackedKeySetError: acc.keyset_versions[root] is exactly {version: safe integer >= 1, digest: 32-byte base64url}.
func trackedKeySetError(t any) string {
	m, ok := t.(map[string]any)
	if !ok {
		return "a tracked key set must be an object {version, digest}"
	}
	for k := range m {
		if k != "version" && k != "digest" {
			return "a tracked key set has the unknown member '" + k + "'"
		}
	}
	if !jsIsInt(m["version"]) || jsF(m["version"]) < 1 {
		return "a tracked key set version must be a safe integer >= 1"
	}
	if !isDigestV(m["digest"]) {
		return "a tracked key set digest must be canonical base64url (32 bytes)"
	}
	return ""
}

// verifyReceiptAgainstHolder (rule 15, sequenced): now a safe integer and the bounds non-negative safe integers; the
// receipt well-formed (lifetime <= 15 min), issued_at <= now + 60 s and now - issued_at <= the receipt age bound; SOME
// presented key set verifies under holder.root (PQ pinned by root_pq_pk), has version >= the tracked version, issued_at
// <= now + 60 s and now - issued_at <= the key-set age bound, and lists receipt.kid with pk == receipt.signer,
// not_before <= receipt.issued_at and, when not_after is set, receipt.issued_at <= not_after AND now - 60 s <= not_after
// (a retired key stops verifying), with the receipt's suite; the receipt verifies under that entry (PQ pinned by it).
func verifyReceiptAgainstHolder(r map[string]any, holder map[string]any, keySets []any, now float64, f receiptFreshness) bool {
	if !jsIsInt(jsNumber(now)) || !jsIsNonNeg(jsNumber(f.maxReceiptAgeMs)) || !jsIsNonNeg(jsNumber(f.maxKeySetAgeMs)) ||
		(f.tracked != nil && trackedKeySetError(f.tracked) != "") {
		return false
	}
	if !accReceiptShapeOK(r) {
		return false
	}
	issued := jsF(r["issued_at"])
	if !(issued <= now+receiptSkewMs) || !(now-issued <= f.maxReceiptAgeMs) {
		return false
	}
	rootPq, rootPqP := holder["root_pq_pk"]
	ralg, ralgP := r["alg"]
	rname := suiteAlgName(ralg, ralgP)
	if rname == "" {
		rname = "x"
	}
	for _, kv := range keySets {
		if !verifySequencerKeySet(kv, holder["root"], rootPq, rootPqP) {
			continue
		}
		ks := kv.(map[string]any)
		if f.tracked != nil {
			// rollback (an older version) or equivocation (the tracked version under another digest): skip the set
			tv := jsF(f.tracked["version"])
			if v := jsF(ks["version"]); v < tv {
				continue
			} else if v == tv {
				if d, ok := sequencerKeySetDigest(ks); !ok || d != f.tracked["digest"] {
					continue
				}
			}
		}
		ksIssued := jsF(ks["issued_at"])
		if !(ksIssued <= now+receiptSkewMs) || !(now-ksIssued <= f.maxKeySetAgeMs) {
			continue
		}
		var e map[string]any
		for _, x := range ks["keys"].([]any) {
			if m := x.(map[string]any); m["kid"] == r["kid"] {
				e = m
				break
			}
		}
		if e == nil || e["pk"] != r["signer"] || issued < jsF(e["not_before"]) {
			continue
		}
		if na, has := e["not_after"]; has && (issued > jsF(na) || jsF(na) < now-receiptSkewMs) {
			continue
		}
		ealg, ealgP := e["alg"]
		ename := suiteAlgName(ealg, ealgP)
		if ename == "" {
			ename = "ed25519"
		}
		if ename != rname {
			continue
		}
		pk := e["pk"].(string)
		pq, pqP := e["pq_pk"]
		if verifyAccReceiptSignature(r, pk, pinOf(pk, pq, pqP)) {
			return true
		}
	}
	return false
}

// receiptArithmeticOk (rule 15): sum delta == val, post == pre + delta; count delta == 1, post == pre + 1; max
// delta == val, post == max(pre, delta); distinct delta in {0, 1}, post == pre + delta.
func receiptArithmeticOk(agg string, r map[string]any, val float64) bool {
	pre, delta, post := jsF(r["pre"]), jsF(r["delta"]), jsF(r["post"])
	switch agg {
	case "sum":
		return delta == val && post == pre+delta
	case "count":
		return delta == 1 && post == pre+1
	case "max":
		return delta == val && post == math.Max(pre, delta)
	case "distinct":
		return (delta == 0 || delta == 1) && post == pre+delta
	}
	return false
}
