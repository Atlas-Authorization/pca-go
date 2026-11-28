package pca

// Signing, shape checks with reasons and host-side admission for the v2 intent artifacts: accumulator receipts, sequencer key
// sets, classifier verdicts, judge verdicts and label receipts, plus the semantic-threshold verifier hook.

import (
	"errors"
	"fmt"
	"math"
	"sort"
)

// AccReceiptCoreDomain is the domain of the receipt's log-leaf content (the receipt without its ledger position and signatures).
const AccReceiptCoreDomain = "atlas-pca/acc-receipt-core/v1"

// AccReceiptCoreDigest is the digest of the receipt's log-leaf content: the receipt without its `ledger`, `kid`, `signer` and
// signature fields. Two receipts with the same (session, acc, seq) and different cores in one witnessed log are provable equivocation.
func AccReceiptCoreDigest(r map[string]any) (string, error) {
	core := map[string]any{}
	for _, k := range []string{"v", "kind", "session", "acc", "seq", "pre", "delta", "post", "pcactn_digest", "aud", "issued_at", "expires_at"} {
		if v, has := r[k]; has {
			core[k] = v
		}
	}
	return HashCanonical(map[string]any{"d": AccReceiptCoreDomain, "r": core})
}

// AccReceiptShapeError is the structural check of an accumulator receipt: "" when well-formed, else the first problem.
func AccReceiptShapeError(rv any) string {
	r, ok := rv.(map[string]any)
	if !ok {
		return "receipt is not an object"
	}
	if k, ok := firstUnknownKey(r, receiptKeys); !ok {
		return "receipt: unknown member '" + k + "'"
	}
	if !jsStrictEq(r["v"], 1.0) || r["kind"] != "pca-acc-receipt" {
		return "not a pca-acc-receipt v1"
	}
	if !isDigestV(r["session"]) {
		return "receipt.session is not canonical base64url (32 bytes)"
	}
	if s, ok := r["acc"].(string); !ok || !matchIdent(s, 64, false) {
		return "receipt.acc is not an accumulator id"
	}
	if !(jsIsInt(r["seq"]) && jsF(r["seq"]) >= 1) {
		return "receipt.seq must be a safe integer >= 1"
	}
	if !jsIsNonNeg(r["pre"]) || !jsIsNonNeg(r["delta"]) || !jsIsNonNeg(r["post"]) {
		return "receipt pre / delta / post must be non-negative safe integers"
	}
	if !isDigestV(r["pcactn_digest"]) {
		return "receipt.pcactn_digest is not canonical base64url (32 bytes)"
	}
	if s, ok := r["aud"].(string); !ok || s == "" {
		return "receipt.aud must be a non-empty string"
	}
	if !jsIsNonNeg(r["issued_at"]) || !jsIsNonNeg(r["expires_at"]) {
		return "receipt.issued_at / expires_at must be non-negative safe integers"
	}
	if iss, exp := jsF(r["issued_at"]), jsF(r["expires_at"]); !(exp >= iss && exp-iss <= maxReceiptLifetimeMs) {
		return fmt.Sprintf("receipt.expires_at must be within %d ms after issued_at", maxReceiptLifetimeMs)
	}
	if s, ok := r["kid"].(string); !ok || !matchKid(s) {
		return "receipt.kid must match [A-Za-z0-9_.:-]{1,64}"
	}
	if l, ok := r["ledger"].(map[string]any); !ok || sortedKeyList(l) != "head,index" || !jsIsNonNeg(l["index"]) || !isDigestV(l["head"]) {
		return "receipt.ledger must be {index, head}"
	}
	if !isDigestV(r["signer"]) {
		return "receipt.signer is not canonical base64url (32 bytes)"
	}
	return suiteFieldsShapeError(r, "receipt", "an ed25519 receipt must not carry pq_pk / pq_sig", "receipt.sig must be a string")
}

// suiteFieldsShapeError is the shared tail of the signed-artifact shape checks: alg, the ed25519 / PQ member rule, the sig string.
func suiteFieldsShapeError(a map[string]any, label, ed25519Msg, sigMsg string) string {
	alg, algP := a["alg"]
	if e := suiteCapability(alg, algP); e != "" {
		if label == "key set" {
			return "alg: " + e
		}
		return label + ".alg: " + e
	}
	_, hasPq := a["pq_pk"]
	_, hasPqSig := a["pq_sig"]
	if suiteAlgName(alg, algP) == "ed25519" && (hasPq || hasPqSig) {
		return ed25519Msg
	}
	if _, ok := a["sig"].(string); !ok {
		return sigMsg
	}
	return ""
}

// SequencerKeySetShapeError is the structural check of a sequencer key set: "" when well-formed, else the first problem.
func SequencerKeySetShapeError(kv any) string {
	k, ok := kv.(map[string]any)
	if !ok {
		return "key set is not an object"
	}
	if x, ok := firstUnknownKey(k, []string{"v", "kind", "sequencer", "version", "issued_at", "keys", "alg", "pq_pk", "sig", "pq_sig"}); !ok {
		return "key set: unknown member '" + x + "'"
	}
	if !jsStrictEq(k["v"], 1.0) || k["kind"] != "pca-sequencer-keys" {
		return "not a pca-sequencer-keys v1"
	}
	if !isDigestV(k["sequencer"]) {
		return "sequencer is not canonical base64url (32 bytes)"
	}
	if !(jsIsNonNeg(k["version"]) && jsF(k["version"]) >= 1) {
		return "version must be a safe integer >= 1"
	}
	if !jsIsNonNeg(k["issued_at"]) {
		return "issued_at must be a non-negative safe integer"
	}
	keys, ok := k["keys"].([]any)
	if !ok || len(keys) == 0 || len(keys) > 256 {
		return "keys must be 1..256 entries"
	}
	kids := map[string]bool{}
	for _, ev := range keys {
		e, ok := ev.(map[string]any)
		if !ok || !keysWithin(e, []string{"kid", "pk", "alg", "pq_pk", "not_before", "not_after"}) {
			return "keys entries are {kid, pk, alg?, pq_pk?, not_before, not_after?}"
		}
		kid, ok := e["kid"].(string)
		if !ok || !matchKid(kid) || kids[kid] {
			return "key kids must match [A-Za-z0-9_.:-]{1,64} and be distinct"
		}
		kids[kid] = true
		if !isDigestV(e["pk"]) {
			return "key pk is not canonical base64url (32 bytes)"
		}
		if a, has := e["alg"]; has {
			if se := suiteCapability(a, true); se != "" {
				return "key alg: " + se
			}
		}
		if q, has := e["pq_pk"]; has && !b64uOK(q, -1) {
			return "key pq_pk is not canonical base64url"
		}
		na, hasNa := e["not_after"]
		if !jsIsNonNeg(e["not_before"]) || (hasNa && !(jsIsNonNeg(na) && jsF(na) >= jsF(e["not_before"]))) {
			return "key validity must be 0 <= not_before <= not_after"
		}
	}
	return suiteFieldsShapeError(k, "key set", "an ed25519 key set must not carry pq_pk / pq_sig", "sig must be a string")
}

// SignAccReceipt signs an accumulator receipt as the sequencer (the signer is the key's identity) under the suite (nil: Ed25519).
func SignAccReceipt(body map[string]any, key *KeyPair, suite *SuiteOpts) (map[string]any, error) {
	if key == nil {
		return nil, errors.New("signAccReceipt: a key is required")
	}
	n, err := normObj(body)
	if err != nil {
		return nil, err
	}
	if _, ok := n["ledger"].(map[string]any); !ok {
		return nil, errors.New("signAccReceipt: receipt.ledger must be {index, head}")
	}
	n["signer"] = key.Public
	out, err := SignArtifact(accReceiptDomain, receiptBody(n), key, suite)
	if err != nil {
		return nil, err
	}
	if bad := AccReceiptShapeError(out); bad != "" {
		return nil, errors.New("signAccReceipt: " + bad)
	}
	return out, nil
}

// SignSequencerKeySet signs a sequencer key set as its root (the sequencer member is the key's identity) under the suite (nil: Ed25519).
func SignSequencerKeySet(body map[string]any, key *KeyPair, suite *SuiteOpts) (map[string]any, error) {
	if key == nil {
		return nil, errors.New("signSequencerKeySet: a key is required")
	}
	n, err := normObj(body)
	if err != nil {
		return nil, err
	}
	base := map[string]any{"v": n["v"], "kind": n["kind"], "sequencer": key.Public, "version": n["version"], "issued_at": n["issued_at"], "keys": n["keys"]}
	out, err := SignArtifact(sequencerKeysDomain, base, key, suite)
	if err != nil {
		return nil, err
	}
	if bad := SequencerKeySetShapeError(out); bad != "" {
		return nil, errors.New("signSequencerKeySet: " + bad)
	}
	return out, nil
}

// SortedDistinct is a set of distinct keys in canonical (UTF-8) order.
func SortedDistinct(keys []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, k := range keys {
		if !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	sortUtf8(out)
	return out
}

// ---- wire checks with reasons ---------------------------------------------------------------------------------------------

// IntentClassifierDomain is the domain of a signed classifier verdict.
const IntentClassifierDomain = "atlas-pca/intent-classifier/v1\x00"

// IntentClassifierRefDomain is the domain of a classifier verdict's content reference.
const IntentClassifierRefDomain = "atlas-pca/intent-classifier-ref/v1"

// classifierVerdictWireReason is the wire check of one classifier verdict: "" when well-formed, else the first problem.
func classifierVerdictWireReason(vv any) string {
	v, ok := vv.(map[string]any)
	if !ok {
		return "verdict must be an object"
	}
	if m := closedMembersMsg(v, "verdict", []string{"v", "kind", "classifier", "session", "content_digest", "label", "measurement", "judge", "sig"}, suiteMembers...); m != "" {
		return m
	}
	if !jsStrictEq(v["v"], 1.0) || v["kind"] != "pca-intent-classification" {
		return `verdict must be {v: 1, kind: "pca-intent-classification"}`
	}
	if c, ok := v["classifier"].(string); !ok || !matchName(c) {
		return "'verdict.classifier' must match ^[a-z][a-z0-9_]{0,63}$"
	}
	if !isDigestV(v["session"]) {
		return "'verdict.session' must be canonical base64url (32 bytes)"
	}
	if !isDigestV(v["content_digest"]) {
		return "'verdict.content_digest' must be canonical base64url (32 bytes)"
	}
	if !boundedStr(v["label"], 64) {
		return "'verdict.label' must be a non-empty string (<= 64 bytes)"
	}
	if _, ok := v["measurement"].(string); !ok || !boundedStr(v["measurement"], 256) {
		return "'verdict.measurement' must be a non-empty string (<= 256 bytes)"
	}
	if !isDigestV(v["judge"]) {
		return "'verdict.judge' must be canonical base64url (32 bytes)"
	}
	if _, ok := v["sig"].(string); !ok {
		return "'verdict.sig' must be a string"
	}
	return ""
}

// labelsWireReason is the wire check of a label receipt: "" when well-formed, else the first problem.
func labelsWireReason(lv any) string {
	l, ok := lv.(map[string]any)
	if !ok {
		return "label receipt must be an object"
	}
	if m := closedMembersMsg(l, "labels", []string{"v", "kind", "site", "session", "response_digest", "fields", "issued_at", "kid", "sig"}, suiteMembers...); m != "" {
		return m
	}
	if !jsStrictEq(l["v"], 1.0) || l["kind"] != "pca-labels" {
		return `label receipt must be {v: 1, kind: "pca-labels"}`
	}
	if !boundedStr(l["site"], 256) {
		return "'labels.site' must be a non-empty string (<= 256 bytes)"
	}
	if !isDigestV(l["session"]) {
		return "'labels.session' must be canonical base64url (32 bytes)"
	}
	if !isDigestV(l["response_digest"]) {
		return "'labels.response_digest' must be canonical base64url (32 bytes)"
	}
	fields, ok := l["fields"].(map[string]any)
	if !ok {
		return "'labels.fields' must be an object"
	}
	if len(fields) == 0 || len(fields) > maxLabelFields {
		return fmt.Sprintf("'labels.fields' must hold 1..%d fields", maxLabelFields)
	}
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if !boundedStr(k, 256) {
			return "label field paths must be non-empty strings (<= 256 bytes)"
		}
		f, ok := fields[k].(map[string]any)
		if !ok || closedMembersMsg(f, "object", []string{"class", "value_digest"}) != "" {
			return "label field '" + k + "' must be exactly {class, value_digest}"
		}
		if c, ok := f["class"].(string); !ok || jsLen(c) > 128 || !matchDataClass(c) {
			return "label field '" + k + "': invalid data class"
		}
		if !isDigestV(f["value_digest"]) {
			return "label field '" + k + "': value_digest must be canonical base64url (32 bytes)"
		}
	}
	if !jsIsInt(l["issued_at"]) || jsF(l["issued_at"]) < 0 {
		return "'labels.issued_at' must be a non-negative safe integer"
	}
	if !boundedStr(l["kid"], 64) {
		return "'labels.kid' must be a non-empty string (<= 64 bytes)"
	}
	if _, ok := l["sig"].(string); !ok {
		return "'labels.sig' must be a string"
	}
	return ""
}

// factWireReason is the wire check of an oracle fact: "" when well-formed, else the first problem.
func factWireReason(fv any) string {
	f, ok := fv.(map[string]any)
	if !ok {
		return "fact must be an object"
	}
	if m := closedMembersMsg(f, "fact", []string{"v", "kind", "name", "subject", "value", "t_obs", "oracle", "sig"}, suiteMembers...); m != "" {
		return m
	}
	if !jsStrictEq(f["v"], 1.0) || f["kind"] != "pca-fact" {
		return `fact must be {v: 1, kind: "pca-fact"}`
	}
	if n, ok := f["name"].(string); !ok || !matchName(n) {
		return "'fact.name' must match ^[a-z][a-z0-9_]{0,63}$"
	}
	if !boundedStr(f["subject"], 256) {
		return "'fact.subject' must be a non-empty string (<= 256 bytes)"
	}
	if !jsIsInt(f["value"]) && !boundedStr(f["value"], 256) {
		return "'fact.value' must be a safe integer or a non-empty string (<= 256 bytes)"
	}
	if !jsIsInt(f["t_obs"]) || jsF(f["t_obs"]) < 0 {
		return "'fact.t_obs' must be a non-negative safe integer"
	}
	if !boundedStr(f["oracle"], 64) {
		return "'fact.oracle' must be a non-empty string (<= 64 bytes)"
	}
	if _, ok := f["sig"].(string); !ok {
		return "'fact.sig' must be a string"
	}
	return ""
}

// ClassifierVerdictWireError is the wire check of a classifier verdict: "" when well-formed, else the first problem.
func ClassifierVerdictWireError(vv any) string { return classifierVerdictWireReason(vv) }

// LabelsWireError is the wire check of a label receipt: "" when well-formed, else the first problem.
func LabelsWireError(lv any) string { return labelsWireReason(lv) }

// FactWireError is the wire check of an oracle fact: "" when well-formed, else the first problem.
func FactWireError(fv any) string { return factWireReason(fv) }

// VerifyLabels checks a label receipt against the pinned label keys ({site, kid, pk, pq_pk?}): "" when it verifies, else the reason.
func VerifyLabels(lv any, keys []any) string {
	if w := labelsWireReason(lv); w != "" {
		return w
	}
	r := lv.(map[string]any)
	if se := artifactSuiteError(r); se != "" {
		return "signature suite: " + se
	}
	for _, kv := range keys {
		k, ok := kv.(map[string]any)
		if !ok || k["site"] != r["site"] || k["kid"] != r["kid"] {
			continue
		}
		if verifyArtifactSig(labelsDomain, r, k["pk"], k["pq_pk"]) {
			return ""
		}
		return "bad label receipt signature"
	}
	return fmt.Sprintf("no pinned label key for site '%s' kid '%s'", ixS(r["site"]), ixS(r["kid"]))
}

// DecideReadPurpose is the purpose-limitation decision of a read: fields [{path, class, optional?}] against coverage {purpose:
// [class pattern]}. The result is {outcome: allow | question | deny, minimise, uncovered}; onUncovered ("question" by default, or
// "deny") is the outcome when a required field's class is not covered. Malformed input is deny.
func DecideReadPurpose(fields []any, purpose string, coverage map[string]any, onUncovered string) map[string]any {
	in := map[string]any{"fields": fields, "purpose": purpose, "coverage": coverage}
	if onUncovered != "" {
		in["on_uncovered"] = onUncovered
	}
	return IntentReadPurposePrimitive(in)
}

// ---- classifier verdicts -----------------------------------------------------------------------------------------------

// ClassifierContentDigest is the digest of the content a classifier verdict is about.
func ClassifierContentDigest(content any) (string, error) { return HashCanonical(content) }

// SignClassifierVerdict signs a classifier verdict ({classifier, session, content_digest, label, measurement}) as its judge under the
// suite (nil: Ed25519); the judge is the key's identity.
func SignClassifierVerdict(body map[string]any, key *KeyPair, suite *SuiteOpts) (map[string]any, error) {
	if key == nil {
		return nil, errors.New("signClassifierVerdict: a key is required")
	}
	full := map[string]any{"v": 1.0, "kind": "pca-intent-classification"}
	for k, v := range body {
		full[k] = v
	}
	full["judge"] = key.Public
	return SignArtifact(IntentClassifierDomain, full, key, suite)
}

// ClassifierVerdictRef is the content reference of a classifier verdict (what a session commits).
func ClassifierVerdictRef(v any) (string, bool) {
	return artifactRef(IntentClassifierRefDomain, "c", v)
}

// VerifyClassifierAttestation binds a classifier verdict's signed measurement to a verified measured TEE (see VerifyJudgeAttestation).
func VerifyClassifierAttestation(v map[string]any, att *HardwareResult, approved map[string]any) map[string]any {
	if v == nil {
		return map[string]any{"ok": false, "reason": "verdict must be an object"}
	}
	m, _ := v["measurement"].(string)
	return VerifyJudgeAttestation(m, att, approved)
}

// ---- judge verdicts and the semantic verifier ------------------------------------------------------------------------------

// StatementOf is the canonical statement a judge verdict's signature covers (the suite fields are bound for a non-default suite).
func StatementOf(v map[string]any) (map[string]any, error) {
	base := map[string]any{"v": 1.0, "actionDigest": v["actionDigest"], "goalCommitment": v["goalCommitment"], "faithful": v["faithful"] == true,
		"score_ppm": IntentQuantizeScore(ixNumOrNaN(v["score"])), "judgeMeasurement": jsValueString(ixLrOpt(v, "judgeMeasurement", ""))}
	alg, algP := v["alg"]
	pqPk, pqP := v["pq_pk"]
	st, ok := bindSuiteFields(base, alg, algP, pqPk, pqP)
	if !ok { // the reference binds `alg` and an undefined pq_pk (no member): the statement then fails to verify, it is not refused here
		su, _ := resolveSigAlg(alg, algP)
		st = map[string]any{}
		for k, x := range base {
			st[k] = x
		}
		st["alg"] = su.alg
	}
	return st, nil
}

// SemanticJudgeMessage is the exact bytes a judge signs: the domain followed by the strict canonical statement.
func SemanticJudgeMessage(statement map[string]any) ([]byte, bool) {
	b, ok := ixStrictCanon(statement)
	if !ok {
		return nil, false
	}
	return append([]byte(ixSemanticJudgeDomain), b...), true
}

// ActionDigest is the canonical digest a judge binds to: the digest of the PCActn's action.
func ActionDigest(action any) (string, error) { return HashCanonical(action) }

// VerdictDigest is the digest of a verdict for ledger anchoring and challenge.
func VerdictDigest(v any) (string, error) { return HashCanonical(v) }

// SignJudgeVerdict signs a judge's verdict {actionDigest, goalCommitment, faithful, score, judgeMeasurement?} as its judge under the
// suite (nil: Ed25519). The judge member is the key's identity, so the result verifies as is.
func SignJudgeVerdict(key *KeyPair, v map[string]any, suite *SuiteOpts) (map[string]any, error) {
	if key == nil {
		return nil, errors.New("signJudgeVerdict: a key is required")
	}
	su, known := resolveSigAlg(suite.alg(), true)
	if !known {
		return nil, fmt.Errorf("signJudgeVerdict: unknown signature alg %q", suite.alg())
	}
	in := map[string]any{"actionDigest": v["actionDigest"], "goalCommitment": v["goalCommitment"], "faithful": v["faithful"] == true, "score": v["score"],
		"judgeMeasurement": jsValueString(ixLrOpt(v, "judgeMeasurement", ""))}
	if su.alg != "ed25519" {
		if suite == nil || suite.Pq == nil {
			return nil, fmt.Errorf("signJudgeVerdict: %s needs a post-quantum key pair", su.alg)
		}
		in["alg"] = su.alg
		in["pq_pk"] = suite.Pq.Public
	}
	st, err := StatementOf(in)
	if err != nil {
		return nil, err
	}
	msg, ok := SemanticJudgeMessage(st)
	if !ok {
		return nil, errors.New("signJudgeVerdict: the verdict is not canonicalizable")
	}
	sig, pqSig, err := signWithSuite(suite, key, msg)
	if err != nil {
		return nil, err
	}
	out := map[string]any{"judge": key.Public, "actionDigest": in["actionDigest"], "goalCommitment": in["goalCommitment"], "faithful": in["faithful"],
		"score": in["score"], "judgeMeasurement": in["judgeMeasurement"], "sig": sig}
	if su.alg != "ed25519" {
		out["alg"] = su.alg
		out["pq_pk"] = suite.Pq.Public
	}
	if pqSig != "" {
		out["pq_sig"] = pqSig
	}
	return out, nil
}

// VerifyJudgeAttestation binds a judge's signed measurement to a real measured TEE: the attestation must be verified and bound, carry a
// measured identity whose runtime measurement equals the signed one, and satisfy the approved agent binding (nil: any). The result is
// {ok: true, measured} or {ok: false, reason}; a missing attestation is a denial.
func VerifyJudgeAttestation(judgeMeasurement string, att *HardwareResult, approved map[string]any) map[string]any {
	no := func(r string) map[string]any { return map[string]any{"ok": false, "reason": r} }
	if att == nil || !att.OK {
		if att != nil && att.Reason != "" {
			return no(att.Reason)
		}
		return no("no verified attestation for this judge (fail-closed)")
	}
	if !att.Bound {
		return no("judge attestation not bound to a TEE report (report_data binding unconfirmed)")
	}
	if att.Measured == nil {
		return no("judge attestation carries no measured identity")
	}
	if judgeMeasurement == "" {
		return no("verdict carries no judgeMeasurement to bind to the attested identity")
	}
	if att.Measured["runtime_measurement"] != judgeMeasurement {
		return no("attested enclave measurement does not match the signed judgeMeasurement")
	}
	if r := MatchAgentBinding(MeasuredIdentityFromMap(att.Measured), approved); r != "" {
		return no(r)
	}
	return map[string]any{"ok": true, "measured": att.Measured}
}

// SemanticAttestation is the attested-judge gate of the semantic threshold: with Require set, only verdicts whose judge is bound to an
// approved measured TEE count (an off-allowlist key and an unattested judge are treated alike).
type SemanticAttestation struct {
	// Resolve returns the verified TEE attestation for a judge verdict (nil: the judge has none).
	Resolve func(verdict map[string]any) *HardwareResult
	// Approved is the agent binding the judge's measured identity must satisfy (nil: any).
	Approved map[string]any
	// Require makes the gate binding; without it unattested judges still count.
	Require bool
}

// VerifySemanticThreshold is IntentVerifySemanticThreshold with the attested-judge gate: att nil (or Require false) changes nothing.
func VerifySemanticThreshold(verdicts any, opts map[string]any, att *SemanticAttestation) map[string]any {
	if att == nil || !att.Require || att.Resolve == nil {
		return IntentVerifySemanticThreshold(verdicts, opts)
	}
	kept := []any{}
	for _, vv := range ixL(verdicts) {
		v, ok := vv.(map[string]any)
		if !ok {
			continue // not a verdict: the threshold would not count it either
		}
		m, _ := v["judgeMeasurement"].(string)
		if VerifyJudgeAttestation(m, att.Resolve(v), att.Approved)["ok"] == true {
			kept = append(kept, v)
		}
	}
	return IntentVerifySemanticThreshold(kept, opts)
}

// SemanticHookResult is what a semantic verifier hook reports: Enforced false means judgment does not apply to the action.
type SemanticHookResult struct {
	Enforced bool
	OK       bool
	Reason   string
}

// SemanticVerifierOpts configures CreateSemanticVerifier.
type SemanticVerifierOpts struct {
	// JudgeKeys is the allowlist of trusted judge public keys (base64url Ed25519).
	JudgeKeys []string
	// K is the quorum of distinct trusted judges that must agree.
	K int
	// Calibration is the optional conformal calibration gate.
	Calibration map[string]any
	// Verdicts finds the ensemble's verdicts for an action (ok false: none available).
	Verdicts func(ctx map[string]any) (verdicts []any, ok bool)
	// GoalCommitment recovers the principal's goal commitment for the action (ok false: none).
	GoalCommitment func(ctx map[string]any) (commitment string, ok bool)
	// ActionDigest overrides the digest the verdicts must bind to (default: the digest of the PCActn's action).
	ActionDigest func(ctx map[string]any) string
	// OptionalWhenAbsent reports a missing ensemble as not enforced; the default is fail closed.
	OptionalWhenAbsent bool
	// Attestation resolves the optional attested-judge gate per action.
	Attestation func(ctx map[string]any) *SemanticAttestation
}

// CreateSemanticVerifier builds a semantic-threshold hook over a verification context (ctx["pcactn"] is the PCActn). A missing ensemble
// or goal commitment denies unless OptionalWhenAbsent; otherwise the k-of-n threshold decides. The options are copied at creation.
func CreateSemanticVerifier(o SemanticVerifierOpts) func(ctx map[string]any) SemanticHookResult {
	keys := append([]any(nil), func() []any {
		out := make([]any, len(o.JudgeKeys))
		for i, k := range o.JudgeKeys {
			out[i] = k
		}
		return out
	}()...)
	var cal any // an absent calibration stays absent (an empty one is a gate whose cutoff is +Infinity)
	if o.Calibration != nil {
		cal = ixClone(o.Calibration)
	}
	k := o.K
	return func(ctx map[string]any) SemanticHookResult {
		var goal string
		var haveGoal bool
		if o.GoalCommitment != nil {
			goal, haveGoal = o.GoalCommitment(ctx)
		}
		var verdicts []any
		var haveVerdicts bool
		if o.Verdicts != nil {
			verdicts, haveVerdicts = o.Verdicts(ctx)
		}
		if !haveGoal || !haveVerdicts {
			if o.OptionalWhenAbsent {
				return SemanticHookResult{}
			}
			return SemanticHookResult{Enforced: true, Reason: "no semantic ensemble available for this action (fail-closed)"}
		}
		var digest string
		if o.ActionDigest != nil {
			digest = o.ActionDigest(ctx)
		} else {
			p, _ := ctx["pcactn"].(map[string]any)
			d, err := ActionDigest(p["action"])
			if err != nil {
				return SemanticHookResult{Enforced: true, Reason: "semantic threshold not met"}
			}
			digest = d
		}
		opts := map[string]any{"judgeKeys": keys, "k": float64(k), "goalCommitment": goal, "actionDigest": digest}
		if cal != nil {
			if c, ok := cal.(map[string]any); ok && c != nil {
				opts["calibration"] = c
			}
		}
		var att *SemanticAttestation
		if o.Attestation != nil {
			att = o.Attestation(ctx)
		}
		res := VerifySemanticThreshold(verdicts, opts, att)
		if res["ok"] == true {
			return SemanticHookResult{Enforced: true, OK: true}
		}
		reason, _ := res["reason"].(string)
		if reason == "" {
			reason = "semantic threshold not met"
		}
		return SemanticHookResult{Enforced: true, Reason: reason}
	}
}

// ixNumOrNaN is a JavaScript number argument: a value that is not a number is NaN (Number.isFinite does not coerce).
func ixNumOrNaN(v any) float64 {
	if f, ok := jsNum(v); ok {
		return f
	}
	return math.NaN()
}
