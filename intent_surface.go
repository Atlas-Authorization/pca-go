package pca

// The remaining public surface of the intent layer's core modules: signed statements, map attestations and runtime
// observations under any signature suite, the transparency-log anchor, v2 goal strings, the revocation vocabulary, the
// binding decision, the problem+json responses of lazy elicitation, and the closed vocabularies of the v2 artifacts.

import (
	"errors"
	"regexp"
	"strings"
)

// IntentMapDomain is the domain that content-addresses an Intent Map.
const IntentMapDomain = ixMkMapDomain

// IntentMapSigDomain is the domain of a signed map attestation.
const IntentMapSigDomain = "atlas-pca/intent-map-sig/v1\x00"

// IntentObsSigDomain is the domain of a signed runtime observation.
const IntentObsSigDomain = ixObsSigDomain

// IntentSourceKinds are the kinds of source an intent statement may cite.
var IntentSourceKinds = append([]string(nil), ixSourceKinds...)

// IntentObservationSources are the origins a runtime observation may claim.
var IntentObservationSources = append([]string(nil), ixObsSources...)

// IntentAnchorDomain is the domain of an anchored artifact's log leaf.
const IntentAnchorDomain = "atlas-pca/intent-anchor/v1"

// IntentAnchorLog names the per-instance intent transparency log (the tree head's principal).
const IntentAnchorLog = "pca-intent:v1"

// IntentAnchorKinds are the artifact kinds a log leaf may commit to.
var IntentAnchorKinds = []string{"statement", "map", "observation", "schema", "session", "delta", "receipt", "profile", "evidence"}

// IntentRevocationPrefix is the namespace of every intent revocation id.
const IntentRevocationPrefix = "pca-intent:"

// MapTagSalt is the tag of the per-leaf salt derivation of a committed map.
const MapTagSalt = ixMkTagSalt

// PublicClass is the data class that may flow to any audience.
const PublicClass = publicDataClass

// SignIntentStatement signs a statement as its principal under the suite (nil: Ed25519). The principal defaults to the key's own
// identity and must equal it when given.
func SignIntentStatement(s map[string]any, key *KeyPair, suite *SuiteOpts) (map[string]any, error) {
	if key == nil {
		return nil, errors.New("signIntentStatement: a key is required")
	}
	n, err := normObj(s)
	if err != nil {
		return nil, err
	}
	if p, has := n["principal"]; has && p != key.Public {
		return nil, errors.New("signIntentStatement: principal key mismatch")
	}
	n["principal"] = key.Public
	body := ixStatementBody(n)
	if bad := ixStatementShapeError(body); bad != "" {
		return nil, errors.New("signIntentStatement: " + bad)
	}
	return SignArtifact(IntentSigDomain, body, key, suite)
}

// VerifyIntentStatement verifies a signed statement: shape, signer and the suite signature (a post-quantum key must be pinned via
// opts["pqPins"]). The result is {ok: true} or {ok: false, reason}.
func VerifyIntentStatement(sv any, opts map[string]any) map[string]any {
	return IntentVerifyIntent(sv, opts)
}

// IntentMapShapeError is the structural check of an Intent Map ("" when well-formed); it does not replay the map.
func IntentMapShapeError(mv any) string {
	m, ok := mv.(map[string]any)
	if !ok || !jsStrictEq(m["v"], 1.0) || m["kind"] != "pca-intent-map" {
		return "not an intent map v1"
	}
	if r, has := m["intent_ref"]; !has || (r != nil && !ixIsB32(r)) {
		return "intent_ref must be null or canonical base64url (32 bytes)"
	}
	mt, ok := m["metrics"].(map[string]any)
	if !ok {
		return "metrics must be an object"
	}
	if !jsIsInt(mt["fidelity_est_ppm"]) || jsF(mt["fidelity_est_ppm"]) < 0 || jsF(mt["fidelity_est_ppm"]) > 1e6 {
		return "metrics.fidelity_est_ppm must be an integer in [0, 1e6]"
	}
	if !jsIsInt(mt["residual_risk_ppm"]) || jsF(mt["residual_risk_ppm"]) < 0 {
		return "metrics.residual_risk_ppm must be a non-negative integer"
	}
	return ""
}

// SignIntentMapAttestation signs a map's digest as signer (a detached vouching for the map), at signedAt epoch ms.
func SignIntentMapAttestation(m map[string]any, key *KeyPair, signedAt int64, suite *SuiteOpts) (map[string]any, error) {
	if key == nil {
		return nil, errors.New("signIntentMapAttestation: a key is required")
	}
	n, err := normObj(m)
	if err != nil {
		return nil, err
	}
	if bad := IntentMapShapeError(n); bad != "" {
		return nil, errors.New("signIntentMapAttestation: " + bad)
	}
	if signedAt < 0 {
		return nil, errors.New("signIntentMapAttestation: signedAt must be a non-negative safe integer")
	}
	digest, err := IntentMapDigest(n)
	if err != nil {
		return nil, err
	}
	body := map[string]any{"v": 1.0, "map_digest": digest, "intent_ref": n["intent_ref"], "signer": key.Public, "signed_at": float64(signedAt)}
	return SignArtifact(IntentMapSigDomain, body, key, suite)
}

// VerifyIntentMapAttestation verifies a map attestation: well-formed, the signature valid (a post-quantum key only when pinned via
// opts["pqPins"]) and, when a map is given, its digest and intent_ref matching. The result is {ok: true} or {ok: false, reason}.
func VerifyIntentMapAttestation(a any, opts map[string]any, m ...any) map[string]any {
	no := func(r string) map[string]any { return map[string]any{"ok": false, "reason": r} }
	at, ok := a.(map[string]any)
	if !ok || !jsStrictEq(at["v"], 1.0) {
		return no("not an intent map attestation v1")
	}
	if !ixIsB32(at["map_digest"]) {
		return no("map_digest is not canonical base64url (32 bytes)")
	}
	if r, has := at["intent_ref"]; !has || (r != nil && !ixIsB32(r)) {
		return no("intent_ref must be null or canonical base64url (32 bytes)")
	}
	if !ixIsB32(at["signer"]) {
		return no("signer is not canonical base64url (32 bytes)")
	}
	if !jsIsInt(at["signed_at"]) || jsF(at["signed_at"]) < 0 {
		return no("signed_at must be a non-negative safe integer")
	}
	if es := opts["expectedSigner"]; es != nil && at["signer"] != es {
		return no("signer mismatch")
	}
	alg, algP := at["alg"]
	pqPk, pqPkP := at["pq_pk"]
	_, pqSigP := at["pq_sig"]
	if algP && !suiteSupported(alg, true) {
		return no("unknown signature suite")
	}
	if (!algP || alg == "ed25519") && (pqPkP || pqSigP) {
		return no("an ed25519 artifact must not carry pq_pk / pq_sig")
	}
	if len(m) > 0 {
		if bad := IntentMapShapeError(m[0]); bad != "" {
			return no(bad)
		}
		digest, err := IntentMapDigest(m[0])
		if err != nil || digest != at["map_digest"] {
			return no("map digest mismatch")
		}
		if m[0].(map[string]any)["intent_ref"] != at["intent_ref"] {
			return no("intent_ref mismatch")
		}
	}
	body := map[string]any{}
	for _, k := range []string{"v", "map_digest", "intent_ref", "signer", "signed_at"} {
		body[k] = at[k]
	}
	bound, ok := bindSuiteFields(body, alg, algP, pqPk, pqPkP)
	if !ok {
		return no("malformed intent map attestation: canonicalize: unsupported type undefined")
	}
	msg, ok := domainMessage(IntentMapSigDomain, bound)
	if !ok {
		return no("malformed intent map attestation: the attestation is not canonicalizable")
	}
	if !verifyPinnedSuite(alg, algP, ixS(at["signer"]), pqPk, msg, at["sig"], at["pq_sig"], ixPqPins(opts)) {
		return no("bad signature")
	}
	return map[string]any{"ok": true}
}

// SignIntentObservation signs a runtime observation as its observer under the suite (nil: Ed25519); the signer is the key's identity.
func SignIntentObservation(o map[string]any, key *KeyPair, suite *SuiteOpts) (map[string]any, error) {
	if key == nil {
		return nil, errors.New("signIntentObservation: a key is required")
	}
	n, err := normObj(o)
	if err != nil {
		return nil, err
	}
	n["v"] = 1.0
	n["signer"] = key.Public
	body := ixObsBody(n)
	if bad := ixObsShapeError(body); bad != "" {
		return nil, errors.New("signIntentObservation: " + bad)
	}
	return SignArtifact(IntentObsSigDomain, body, key, suite)
}

// VerifyIntentObservation verifies a signed observation (shape, signer, suite signature; a post-quantum key must be pinned via
// opts["pqPins"]). The result is {ok: true} or {ok: false, reason}.
func VerifyIntentObservation(ov any, opts map[string]any) map[string]any {
	return IntentVerifyObservation(ov, opts)
}

// IntentAnchorCommit is the log leaf for an anchored artifact: H({d, kind, digest}).
func IntentAnchorCommit(kind, digest string) string {
	h, _ := hashCanonicalV(map[string]any{"d": IntentAnchorDomain, "kind": kind, "digest": digest})
	return h
}

// VerifyIntentAnchor verifies an anchoring receipt {kind, digest, index, proof, signed_tree_head}: the head is signed by
// guardianPublic for the intent log of instanceID and the artifact's leaf is included at index under the head's root and size.
// The result is {ok: true} or {ok: false, reason}; it never panics.
func VerifyIntentAnchor(r any, guardianPublic, instanceID string, pins ...map[string]string) (res map[string]any) {
	no := func(reason string) map[string]any { return map[string]any{"ok": false, "reason": reason} }
	defer func() {
		if p := recover(); p != nil {
			res = no("malformed anchor receipt")
		}
	}()
	m, ok := r.(map[string]any)
	if !ok {
		return no("malformed anchor receipt: not an object")
	}
	kind, _ := m["kind"].(string)
	if !contains(IntentAnchorKinds, kind) {
		return no("unknown anchor kind")
	}
	if !isDigestV(m["digest"]) {
		return no("digest is not canonical base64url (32 bytes)")
	}
	h, ok := m["signed_tree_head"].(map[string]any)
	if !ok {
		return no("malformed anchor receipt: no signed tree head")
	}
	if h["principal"] != IntentAnchorLog || h["instance_id"] != instanceID {
		return no("not a head of this instance intent log")
	}
	if !VerifyTreeHead(h, guardianPublic, nil, pins...) {
		return no("tree head signature invalid")
	}
	proof, ok := m["proof"].(map[string]any)
	if !ok || !jsStrictEq(proof["index"], m["index"]) || !jsStrictEq(proof["size"], h["size"]) {
		return no("proof does not match the head")
	}
	root, _ := h["root"].(string)
	if !VerifyLedgerInclusion(root, proof, IntentAnchorCommit(kind, ixS(m["digest"]))) {
		return no("artifact is not included under the signed head")
	}
	return map[string]any{"ok": true}
}

// IntentGoalV2 is the goal a session grant commits to: "pca-intent:v2:<session>:<map_digest>" ("pca-intent:v2c:" over a committed map).
func IntentGoalV2(session, mapDigest string, committed bool) string {
	prefix := intentGoalV2Prefix
	if committed {
		prefix = intentGoalV2cPrefix
	}
	return prefix + session + ":" + mapDigest
}

// ParseIntentGoalV2 splits a v2 session goal into its session and map digest; ok is false for anything else (the v2c form included).
func ParseIntentGoalV2(goal string) (session, mapDigest string, ok bool) {
	if !strings.HasPrefix(goal, intentGoalV2Prefix) {
		return "", "", false
	}
	parts := strings.Split(goal[len(intentGoalV2Prefix):], ":")
	if len(parts) != 2 || !b64uOK(parts[0], b32) || !b64uOK(parts[1], b32) {
		return "", "", false
	}
	return parts[0], parts[1], true
}

// SessionRootShapeError is the structural check of a signed session root ("" when well-formed, else the first problem).
func SessionRootShapeError(sv any) string { return sessionRootShape(sv) }

// RevocationEpochShapeError is the strict-type check of a revocation epoch ("" when well-formed, else the first problem).
func RevocationEpochShapeError(ep any) string { return revocationEpochShape(ep) }

// ProfileRevocationScope is the grant_ref of a profile's revocation epoch.
func ProfileRevocationScope(profileID string) string { return "pca-intent-profile:" + profileID }

// DefaultRevocationMaxAgeS is the default revocation epoch freshness bound by tier, in seconds: 60 for payment tiers, 300 otherwise.
var DefaultRevocationMaxAgeS = map[string]int{"payment": 60, "default": 300}

// RevocationExposureEnd is the end of the exposure window of a revocation: an action verified at now can rely on an epoch that
// predates a revocation at tRevoked only while now <= tRevoked + maxAgeMs + skewMs (skew defaults to 60 s when omitted).
func RevocationExposureEnd(tRevoked, maxAgeMs int64, skewMs ...int64) int64 {
	skew := int64(revocationSkewMs)
	if len(skewMs) > 0 {
		skew = skewMs[0]
	}
	return tRevoked + maxAgeMs + skew
}

// IsApprovedGoalRef reports whether v is the closed object {goal_digest, policy_digest} with both digests canonical base64url (32 bytes).
func IsApprovedGoalRef(v any) bool {
	r, ok := v.(map[string]any)
	return ok && len(r) == 2 && isDigestV(r["goal_digest"]) && isDigestV(r["policy_digest"])
}

// IntentPolicyActive reports whether the policy is active (the intent check then runs even for a PCActn without the slot).
func IntentPolicyActive(p *IntentPolicy) bool { return p.active() }

// DecideIntentBinding runs the intent check on a PCActn's `intent` slot (nil: absent) against the verifier's root grant: {status:
// "absent"} when nothing applies, {status: "pass"}, or {status: "fail", reason}. A non-empty session opens the v2 session goal
// (v2c when mapForm is "commit"). It never panics.
func DecideIntentBinding(intent map[string]any, grant map[string]any, policy *IntentPolicy, session, mapForm string) (res map[string]any) {
	defer func() {
		if p := recover(); p != nil {
			res = map[string]any{"status": "fail", "reason": "intent binding error (fail closed)"}
		}
	}()
	p := map[string]any{}
	if intent != nil {
		p["intent"] = intent
	}
	if session != "" {
		is := map[string]any{"session": session}
		if mapForm != "" {
			is["map_form"] = mapForm
		}
		p["intent_session"] = is
	}
	evaluated, reason := decideIntent(p, grant, policy)
	switch {
	case !evaluated:
		return map[string]any{"status": "absent"}
	case reason != "":
		return map[string]any{"status": "fail", "reason": reason}
	}
	return map[string]any{"status": "pass"}
}

// IsLayerPolicy reports whether v is a layer policy: the closed object {predicates: [...]}.
func IsLayerPolicy(v any) bool {
	l, ok := v.(map[string]any)
	if !ok || len(l) != 1 {
		return false
	}
	_, ok = l["predicates"].([]any)
	return ok
}

// IntentProblemBase is the type-URI prefix of the problem+json bodies of the intent layer.
const IntentProblemBase = "https://atlasauth.net/pca/problems/"

// ProblemBase is the type-URI prefix of the problem+json bodies of the intent layer.
const ProblemBase = IntentProblemBase

// IntentProblemKinds are the outcomes an intent-layer problem response reports.
var IntentProblemKinds = []string{"intent-required", "intent-denied", "schema-violation", "ceiling"}

// Frictions are the confirmation tiers of an intent_required question, mildest first.
var Frictions = []string{"tap", "hold", "typed", "device"}

// VerifyIntentRequired verifies a site-signed intent_required body against the site's discovery keys: shape, the signature under
// the pinned key suite and the expiry. The clock is required: a now that is not a safe integer is refused. The result is {ok: true}
// or {ok: false, reason}.
func VerifyIntentRequired(b any, keys any, now any) map[string]any {
	return WalletVerifyIntentRequired(b, keys, now)
}

// VerifyIntentRequiredAt is VerifyIntentRequired with the clock spelled out; a missing or non-integer now is a denial, so expiry can
// never be skipped.
func VerifyIntentRequiredAt(b any, keys any, now any) map[string]any {
	return WalletVerifyIntentRequired(b, keys, now)
}

// IntentProblem is the RFC 9457 response for an intent-layer outcome: status 403, the WWW-Authenticate challenge and the problem body
// (its `pca` member carries the signed body for intent-required, which needs it). detail nil is absent (an empty detail is kept).
// As the reference, a kind that is none of IntentProblemKinds is not refused: the challenge reads error="undefined" and the body has
// the type URI of the kind and no title.
func IntentProblem(kind string, detail *string, body map[string]any) (map[string]any, error) {
	titles := map[string]string{
		"intent-required":  "Principal confirmation required for this action",
		"intent-denied":    "The principal does not intend this action",
		"schema-violation": "The action does not conform to the site action schema",
		"ceiling":          "The action is outside a ceiling the principal cannot widen",
	}
	errs := map[string]string{"intent-required": "intent_required", "intent-denied": "intent_denied", "schema-violation": "schema_violation", "ceiling": "ceiling"}
	title, known := titles[kind]
	errName := "undefined"
	if known {
		errName = errs[kind]
	}
	params := []string{`error="` + errName + `"`}
	if kind == "intent-required" {
		if body == nil {
			return nil, errors.New("intentProblem: intent-required needs the signed body")
		}
		params = append(params, `session="`+jsMemberString(body, "session")+`"`, `question="`+jsMemberString(body, "question_id")+`"`)
	}
	pb := map[string]any{"type": IntentProblemBase + kind, "status": 403.0}
	if known {
		pb["title"] = title
	}
	if detail != nil {
		pb["detail"] = *detail
	}
	if body != nil {
		pb["pca"] = body
	}
	return map[string]any{
		"status":  403.0,
		"headers": map[string]any{"WWW-Authenticate": "PCA " + strings.Join(params, ", "), "Content-Type": "application/problem+json"},
		"body":    pb,
	}, nil
}

// Closed vocabularies and bounds of the v2 artifacts.
var (
	// AccScopes are the scopes an accumulator may count over.
	AccScopes = []string{"session", "principal", "org", "fleet"}
	// AccIDRe matches an accumulator or monitor id.
	AccIDRe = regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`)
	// KidRe matches a key id of a sequencer key set or receipt.
	KidRe = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,64}$`)
	// IntentNameRe matches an intent classifier or class name.
	IntentNameRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	// DataClassRe matches a data class ("pii.contact").
	DataClassRe = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z0-9_]+)*$`)
	// ParamSegmentRe matches one segment of an action.params path.
	ParamSegmentRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	// EventStatuses are the statuses of a session history event.
	EventStatuses = []string{"reserved", "committed", "released", "reverted"}
	// CountedStatuses are the statuses that count toward a cap.
	CountedStatuses = []string{"reserved", "committed"}
)

// IsLabelKey reports whether v is a label key {site, kid, pk, pq_pk?}: closed, bounded and a 32-byte pk.
func IsLabelKey(v any) bool {
	k, ok := v.(map[string]any)
	return ok && closedMembers(k, []string{"site", "kid", "pk"}, "pq_pk") && boundedStr(k["site"], 256) && boundedStr(k["kid"], 64) &&
		isDigestV(k["pk"]) && pinPqOK(k)
}

// LabelsRef is the content address of a label receipt.
func LabelsRef(l any) (string, bool) { return artifactRef(labelsRefDomain, "l", l) }

// OfferSetRef is the content address of an offer set.
func OfferSetRef(o any) (string, bool) { return artifactRef(offerSetRefDomain, "o", o) }

// QueryCovers reports whether every member of query is present in the filter query fq with an equal scalar.
func QueryCovers(query, fq map[string]any) bool {
	if query == nil || fq == nil {
		return false
	}
	for k, v := range query {
		x, has := fq[k]
		if !has || !jsStrictEq(x, v) {
			return false
		}
	}
	return true
}

// MapLeafSalt is the per-leaf salt of a committed map: H(MapTagSalt || secret || u64be(index)).
func MapLeafSalt(secret []byte, index int) []byte { return ixMkLeafSalt(secret, index) }

// MapTreeResult is a committed map's Merkle tree: its root and the audit path of any leaf.
type MapTreeResult struct {
	// Root is the tree root over the leaf hashes.
	Root   []byte
	hashes [][]byte
}

// Path is the audit path of leaf index as base64url hashes, nearest sibling first.
func (t MapTreeResult) Path(index int) []string {
	var out [][]byte
	ixMkAuditPath(t.hashes, index, &out)
	res := make([]string, len(out))
	for i, h := range out {
		res[i] = b64.EncodeToString(h)
	}
	return res
}

// MapTree builds the tree over the leaf hashes: the root and an audit-path builder. It errors on an empty list.
func MapTree(hashes [][]byte) (MapTreeResult, error) {
	if len(hashes) == 0 {
		return MapTreeResult{}, errors.New("mapTree: empty")
	}
	return MapTreeResult{Root: mapTreeRoot(hashes), hashes: hashes}, nil
}

// SignIntentProfile signs a profile version as its owner under the suite (nil: Ed25519); the owner is the key's identity and must
// equal the owner member when one is given.
func SignIntentProfile(body map[string]any, key *KeyPair, suite *SuiteOpts) (map[string]any, error) {
	if key == nil {
		return nil, errors.New("signIntentProfile: a key is required")
	}
	n, err := normObj(body)
	if err != nil {
		return nil, err
	}
	if o, has := n["owner"]; has && o != key.Public {
		return nil, errors.New("signIntentProfile: owner does not match the signing key")
	}
	n["owner"] = key.Public
	b := ixProfileBody(n)
	if bad := ixProfileShapeError(b, false); bad != "" {
		return nil, errors.New("signIntentProfile: " + bad)
	}
	return SignArtifact(ixProfileSigDomain, b, key, suite)
}

// IntentWBActive reports which W-B checks a verifier reports for {intent_session, policy: {world?, provenance?, classifiers?}}:
// {facts, provenance, classes}. A malformed member is never active or inactive by coercion.
func IntentWBActive(input any) map[string]any { return IntentWBActivePrimitive(input) }

// IntentV2Active reports whether any v2 check would be reported: the PCActn carries intent_session, a v2 policy is active, or a
// present context is malformed (the checks then fail closed).
func IntentV2Active(p map[string]any, ctx *IntentV2Context) bool {
	if _, has := p["intent_session"]; has || intentV2ContextError(ctx) != "" {
		return true
	}
	flag := func(ks ...string) bool { v, ok := ctx.get(ks...); return ok && v == true }
	return flag("policy", "schema", "closed_world") || flag("policy", "session", "require") || flag("policy", "map", "require")
}

// ReservedNames are the names the predicate language cannot address; they are refused as accumulator, monitor and parameter names.
var ReservedNames = []string{"__proto__", "constructor", "prototype"}

// IsSafeNonNeg reports whether v is a non-negative safe integer (not -0).
func IsSafeNonNeg(v any) bool { return jsIsNonNeg(v) }

// SuiteCapabilityError is the capability check of an artifact's alg: "" for an absent alg (Ed25519) or one this verifier implements,
// "alg must be a string" for a non-string, and "unsupported_suite: '<alg>'" for a string it does not implement.
func SuiteCapabilityError(alg any, present bool) string { return suiteCapability(alg, present) }
