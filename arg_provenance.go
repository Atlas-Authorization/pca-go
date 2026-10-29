package pca

// PROVENANCE BY DEFAULT (argument provenance, check `provenance_flow`): an agent cannot be steered by injected content into
// choosing who, where or how much. Port of the TypeScript reference arg-provenance.ts (decideArgProvenance,
// createProvenanceRecorder, principalDirectProvenance) and of the gate its authorize() runs.
//
// A MEDIATOR (the agent harness, a gateway, an MCP client: whatever sees the bytes enter the model's context, holding a key the
// model cannot reach) appends one signed receipt per context segment to a per-session hash chain: the principal's own message
// (`principal`), a tool result (`tool`), a retrieved document (`retrieval`), a fetched page (`web`) and finally the action the
// model chose (`action`, bound to the exact operation digest). The verifier re-derives every label from that chain; nothing
// the agent writes can lower a label. An action is SENSITIVE unless its definition says it only reads; a sensitive action whose
// choice or any argument does not derive from the principal is `escalate` (the principal confirms it with a signed escalation
// answer); a forged or malformed chain is `deny`.
//
// Not to be confused with the K9 build-provenance gate (ProvenanceGate) or the Intent v2 rule 17 check `provenance`.
//
// Token matching (OccursAsToken) runs on UTF-16 code units, exactly as the reference (strings are converted first).
// Every function here is pure and total except the recorder (it signs and keeps the session's chain).

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
)

const (
	// ProvReceiptDomain is the signature domain of a provenance receipt (with its trailing NUL byte).
	ProvReceiptDomain = "atlas-pca/prov-receipt/v1\x00"
	// ProvReceiptRefDomain is the content-address domain of a receipt (the `prev` link).
	ProvReceiptRefDomain = "atlas-pca/prov-receipt-ref/v1"
	// ProvActionDomain is the domain of the operation digest an `action` receipt binds.
	ProvActionDomain = "atlas-pca/prov-action/v1"
	// ProvenanceHeader carries a bundle (strict base64url of its JSON); the JSON body member is `pca_provenance`.
	ProvenanceHeader = "PCA-Provenance"
	// MaxProvReceipts is the most receipts a bundle may carry.
	MaxProvReceipts = 256
	// MaxProvContentBytes is the largest principal message a bundle may carry (UTF-8 bytes).
	MaxProvContentBytes = 65536
	// MaxProvLeaves is the most leaves examined per parameter; a larger value keeps the context label.
	MaxProvLeaves = 4096
	maxProvDepth  = 32
)

var (
	provOrigins     = []string{"principal", "tool", "retrieval", "web", "action"}
	provRank        = map[string]int{"trusted": 0, "first_party": 1, "tool": 2, "web": 3, "agent": 4}
	provOriginLevel = map[string]string{"principal": "trusted", "tool": "tool", "retrieval": "tool", "web": "web"}
	provFloors      = []string{"first_party", "tool", "agent"}
	// traits a read-only action may carry and still be non-sensitive
	provReadSafeTraits = []string{"pca.financial_data_read", "pca.pii_access", "pca.regulated_data"}
	provContentKeyRe   = regexp.MustCompile(`^(0|[1-9][0-9]{0,8})$`)
)

func provJoin(a, b string) string {
	if provRank[a] >= provRank[b] {
		return a
	}
	return b
}

// ProvMediatorPin is a pinned mediator key: the verifier's own, or one the principal's grant envelope names.
// PQPK is the post-quantum key of a hybrid / PQ mediator ("" = none).
type ProvMediatorPin struct {
	Mediator string
	Kid      string
	PK       string
	PQPK     string
}

// JSON is the wire form {mediator, kid, pk, pq_pk?}.
func (p ProvMediatorPin) JSON() map[string]any {
	m := map[string]any{"mediator": p.Mediator, "kid": p.Kid, "pk": p.PK}
	if p.PQPK != "" {
		m["pq_pk"] = p.PQPK
	}
	return m
}

// ProvObservation is untrusted content THIS server saw reach the agent's context (raise only). Origin is tool, retrieval or web.
type ProvObservation struct {
	Origin string
	Source string
}

func isProvMediatorPin(k any) bool {
	m, ok := k.(map[string]any)
	return ok && closedMembers(m, []string{"mediator", "kid", "pk"}, "pq_pk") && boundedStr(m["mediator"], 256) &&
		boundedStr(m["kid"], 64) && isDigestV(m["pk"]) && pinPqOK(m)
}

// ProvReceiptWireError is the wire validation of one receipt: "" when well formed.
func ProvReceiptWireError(r any) string {
	m, ok := r.(map[string]any)
	if !ok {
		return "a receipt must be an object"
	}
	if e := closedMembersMsg(m, "receipt", []string{"v", "kind", "mediator", "kid", "session", "seq", "prev", "origin", "source",
		"content_digest", "issued_at", "sig"}, suiteMembers...); e != "" {
		return e
	}
	if v, isNum := jsNum(m["v"]); !isNum || v != 1 || m["kind"] != "pca-prov" {
		return `a receipt must be {v: 1, kind: "pca-prov"}`
	}
	if !boundedStr(m["mediator"], 256) {
		return "'mediator' must be a non-empty string (<= 256 bytes)"
	}
	if !boundedStr(m["kid"], 64) {
		return "'kid' must be a non-empty string (<= 64 bytes)"
	}
	if !isDigestV(m["session"]) {
		return "'session' must be canonical base64url (32 bytes)"
	}
	if !jsIsNonNeg(m["seq"]) {
		return "'seq' must be a non-negative safe integer"
	}
	if m["prev"] != nil && !isDigestV(m["prev"]) {
		return "'prev' must be null or canonical base64url (32 bytes)"
	}
	if o, _ := m["origin"].(string); !contains(provOrigins, o) {
		return "'origin' must be one of " + strings.Join(provOrigins, ", ")
	}
	if !boundedStr(m["source"], 256) {
		return "'source' must be a non-empty string (<= 256 bytes)"
	}
	if !isDigestV(m["content_digest"]) {
		return "'content_digest' must be canonical base64url (32 bytes)"
	}
	if !jsIsNonNeg(m["issued_at"]) {
		return "'issued_at' must be a non-negative safe integer"
	}
	if _, ok := m["sig"].(string); !ok {
		return "'sig' must be a string"
	}
	return artifactSuiteError(m)
}

// ProvActionInfoError validates action facts {effects?, traits?, params?}: "" when well formed.
func ProvActionInfoError(a any) string {
	m, ok := a.(map[string]any)
	if !ok {
		return "action info must be an object"
	}
	if e := closedMembersMsg(m, "action info", nil, "effects", "traits", "params"); e != "" {
		return e
	}
	for _, k := range []string{"effects", "traits"} {
		v, has := m[k]
		if !has {
			continue
		}
		l, isList := v.([]any)
		ok := isList && len(l) <= 64
		for _, x := range l {
			ok = ok && boundedStr(x, 128)
		}
		if !ok {
			return "action info '" + k + "' must be a list of strings"
		}
	}
	if pv, has := m["params"]; has {
		ps, isObj := pv.(map[string]any)
		if !isObj {
			return "action info 'params' must be an object"
		}
		for _, k := range sortedKeysUtf8(ps) {
			f, _ := ps[k].(string)
			if !boundedStr(k, 128) || !contains(provFloors, f) {
				return "action info param '" + k + "' must map to first_party | tool | agent"
			}
		}
	}
	return ""
}

// IsReadOnlyAction: is an action with these facts non-sensitive (effects non-empty and all `read`, traits within the read-safe
// set)? nil (unknown facts) and anything malformed are sensitive.
func IsReadOnlyAction(a any) bool {
	m, ok := a.(map[string]any)
	if !ok {
		return false
	}
	effects, ok := m["effects"].([]any)
	if !ok || len(effects) == 0 {
		return false
	}
	for _, e := range effects {
		if e != "read" {
			return false
		}
	}
	tv, has := m["traits"]
	if !has || tv == nil {
		return true
	}
	traits, ok := tv.([]any)
	if !ok {
		return false
	}
	for _, t := range traits {
		s, _ := t.(string)
		if !contains(provReadSafeTraits, s) {
			return false
		}
	}
	return true
}

// ---- tokens --------------------------------------------------------------------------------------------------------------

// word characters for token boundaries: ASCII letters, digits, `_`, and every non-ASCII code unit
func provWordUnit(c uint16) bool {
	return c >= '0' && c <= '9' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c == '_' || c >= 0x80
}

// OccursAsToken: does needle occur in text as a whole token? An occurrence counts when the code unit before it is not a word
// character (or the needle starts with a non-word character), and likewise after it. Exact, case-sensitive, on UTF-16 code
// units (both strings are converted first); an empty needle never occurs.
func OccursAsToken(text, needle string) bool {
	return occursUnits(utf16Units(text), utf16Units(needle))
}

func occursUnits(t, n []uint16) bool {
	if len(n) == 0 {
		return false
	}
	headWord, tailWord := provWordUnit(n[0]), provWordUnit(n[len(n)-1])
	for i := 0; i+len(n) <= len(t); i++ {
		if t[i] != n[0] || !unitsEqual(t[i:i+len(n)], n) {
			continue
		}
		okB := !headWord || i == 0 || !provWordUnit(t[i-1])
		end := i + len(n)
		okA := !tailWord || end == len(t) || !provWordUnit(t[end])
		if okB && okA {
			return true
		}
	}
	return false
}

func unitsEqual(a, b []uint16) bool {
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ProvLeaves is the text of every leaf of a JSON value: strings as is, object keys included (in the object's member order),
// other scalars in strict canonical form (true, null, 120, 1.5). ok is false (the reference's null) when the value is deeper
// than 32, has more than 4096 leaves, or holds a scalar that is not strict canonical.
func ProvLeaves(v any) (leaves []string, ok bool) {
	out := []string{}
	var walk func(x any, depth int) bool
	walk = func(x any, depth int) bool {
		if depth > maxProvDepth || len(out) > MaxProvLeaves {
			return false
		}
		switch t := x.(type) {
		case string:
			out = append(out, t)
		case []any:
			for _, y := range t {
				if !walk(y, depth+1) {
					return false
				}
			}
		case map[string]any:
			for _, k := range jsKeys(t) {
				out = append(out, k)
				if !walk(t[k], depth+1) {
					return false
				}
			}
		default:
			s, err := Canonicalize(normalizeJSON(x))
			if err != nil {
				return false
			}
			out = append(out, s)
		}
		return len(out) <= MaxProvLeaves
	}
	if !walk(v, 0) {
		return nil, false
	}
	return out, true
}

// ---- digests -------------------------------------------------------------------------------------------------------------

func provActionDigestJSON(verb, resource, params any) (string, error) {
	return HashCanonical(map[string]any{"d": ProvActionDomain, "verb": verb, "resource": resource, "params": params})
}

// ProvActionDigest is the digest an `action` receipt binds: hashCanonical({d, verb, resource, params}) of the exact operation.
func ProvActionDigest(op Operation) (string, error) {
	params, ok := jsonValue(op.Params, 1)
	if !ok {
		return "", errors.New("provenance: the operation params are not JSON")
	}
	return provActionDigestJSON(op.Verb, op.Resource, params)
}

// ProvReceiptRef is the content address of a receipt (signature included): the `prev` of the next receipt.
func ProvReceiptRef(r map[string]any) (string, bool) {
	return artifactRef(ProvReceiptRefDomain, "r", r)
}

// ---- the decision --------------------------------------------------------------------------------------------------------

// ArgProvenanceDecision is the provenance decision for one operation.
//
//   - Outcome: "pass", "escalate" (the principal must confirm) or "deny" (forged or malformed provenance).
//   - Code: the deny / escalate code ("" on pass); Reason: why (the escalate text is normative).
//   - Sensitive: the action is not read-only; Verified: a bundle verified under a pinned mediator.
//   - Control: the label of the action choice; Labels: the label of every top-level parameter.
//   - Tainted: sink parameters above their floor (UTF-8 order); Path: where untrusted content came from (`origin:source`,
//     plus `unlabelled` without a verified chain; UTF-8 order).
type ArgProvenanceDecision struct {
	Outcome   string
	Code      string
	Reason    string
	Sensitive bool
	Verified  bool
	Control   string
	Labels    map[string]string
	Tainted   []string
	Path      []string
}

type provChain struct {
	verified bool
	context  string
	path     []string
	texts    [][]uint16
}

func provSortU(xs []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, x := range xs {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	sortUtf8(out)
	return out
}

// provVerifyChain verifies a bundle against the pins and the operation; code != "" is a deny with its reason.
func provVerifyChain(bundle any, op map[string]any, pins []any) (ch provChain, code, reason string) {
	unverified := provChain{context: "agent", path: []string{"unlabelled"}}
	if bundle == nil {
		return unverified, "", ""
	}
	b, ok := bundle.(map[string]any)
	if !ok {
		return ch, "malformed_bundle", "the bundle must be an object"
	}
	if e := closedMembersMsg(b, "bundle", []string{"v", "kind", "receipts"}, "contents"); e != "" {
		return ch, "malformed_bundle", e
	}
	if v, isNum := jsNum(b["v"]); !isNum || v != 1 || b["kind"] != "pca-provenance" {
		return ch, "malformed_bundle", `the bundle must be {v: 1, kind: "pca-provenance"}`
	}
	rs, ok := b["receipts"].([]any)
	if !ok || len(rs) == 0 || len(rs) > MaxProvReceipts {
		return ch, "malformed_bundle", fmt.Sprintf("the bundle must hold 1..%d receipts", MaxProvReceipts)
	}
	receipts := make([]map[string]any, len(rs))
	for i, r := range rs {
		if e := ProvReceiptWireError(r); e != "" {
			return ch, "malformed_bundle", fmt.Sprintf("receipt %d: %s", i, e)
		}
		receipts[i] = r.(map[string]any)
	}
	contents := map[string]any{}
	if cv, has := b["contents"]; has {
		if contents, ok = cv.(map[string]any); !ok {
			return ch, "malformed_bundle", "'contents' must be an object"
		}
	}
	first := receipts[0]
	for i, r := range receipts {
		if seq, _ := jsNum(r["seq"]); seq != float64(i) {
			return ch, "broken_chain", fmt.Sprintf("receipt %d has seq %s", i, jsNumberString(seq))
		}
		if r["session"] != first["session"] || r["mediator"] != first["mediator"] || r["kid"] != first["kid"] {
			return ch, "broken_chain", fmt.Sprintf("receipt %d belongs to another session or mediator", i)
		}
		if i == 0 {
			if r["prev"] != nil {
				return ch, "broken_chain", "receipt 0 does not link to its predecessor"
			}
		} else if ref, ok := ProvReceiptRef(receipts[i-1]); !ok || r["prev"] != any(ref) {
			return ch, "broken_chain", fmt.Sprintf("receipt %d does not link to its predecessor", i)
		}
		if i > 0 && jsF(r["issued_at"]) < jsF(receipts[i-1]["issued_at"]) {
			return ch, "broken_chain", fmt.Sprintf("receipt %d is older than its predecessor", i)
		}
	}
	last := receipts[len(receipts)-1]
	want, err := provActionDigestJSON(op["verb"], op["resource"], op["params"])
	if err != nil {
		return ch, "malformed_config", "evaluation error (fail closed): " + err.Error()
	}
	if last["origin"] != "action" || last["source"] != op["verb"] || last["content_digest"] != any(want) {
		return ch, "unbound_action", "the last receipt is not the action receipt of this operation"
	}
	texts := [][]uint16{}
	for _, k := range jsKeys(contents) {
		var r map[string]any
		if provContentKeyRe.MatchString(k) {
			if n, _ := strconv.Atoi(k); n < len(receipts) {
				r = receipts[n]
			}
		}
		if r == nil || r["origin"] != "principal" {
			return ch, "malformed_bundle", "contents '" + k + "' does not name a principal receipt"
		}
		text, isStr := contents[k].(string)
		if !isStr || utf8Len(text) > MaxProvContentBytes {
			return ch, "malformed_bundle", fmt.Sprintf("contents '%s' must be a string of at most %d bytes", k, MaxProvContentBytes)
		}
		d, err := HashCanonical(text)
		if err != nil {
			return ch, "content_mismatch", "contents '" + k + "' is not canonical text"
		}
		if r["content_digest"] != any(d) {
			return ch, "content_mismatch", "contents '" + k + "' does not hash to its receipt"
		}
		texts = append(texts, utf16Units(text))
	}
	var pin map[string]any
	for _, p := range pins {
		if pm := p.(map[string]any); pm["mediator"] == first["mediator"] && pm["kid"] == first["kid"] {
			pin = pm
			break
		}
	}
	// a chain from a mediator this verifier does not pin vouches for nothing: every value stays at the top (escalate, never allow)
	if pin == nil {
		return unverified, "", ""
	}
	for i, r := range receipts {
		if !verifyArtifactSig(ProvReceiptDomain, r, pin["pk"], pin["pq_pk"]) {
			return ch, "bad_signature", fmt.Sprintf("receipt %d does not verify under the pinned mediator key", i)
		}
	}
	context := "trusted"
	path := []string{}
	before := 0
	for _, r := range receipts[:len(receipts)-1] {
		o, _ := r["origin"].(string)
		if o == "action" {
			continue
		}
		before++
		context = provJoin(context, provOriginLevel[o])
		if o != "principal" {
			path = append(path, o+":"+r["source"].(string))
		}
	}
	if before == 0 {
		context = "agent"
		path = append(path, "unlabelled")
	}
	return provChain{verified: true, context: context, path: provSortU(path), texts: texts}, "", ""
}

// DecideArgProvenance is the provenance decision for one operation. input is the reference's ArgProvenanceInput as JSON:
// {bundle?, operation: {verb, resource, params}, mediators: [pin], action?, principal_plan?, principal_control?, observed?}.
// Steps, first failure wins:
//  0. pins, operation, action facts and observations well formed, else deny (malformed_config / malformed_operation /
//     malformed_action);
//  1. the bundle (when present): wire, chain (contiguous seq, prev links, one session and mediator, non-decreasing issued_at),
//     the last receipt is the action receipt of this operation, every principal content hashes to its receipt, every
//     signature verifies under the pinned (mediator, kid); a failure is deny. A chain whose mediator is not pinned is ignored;
//  2. observations join into the context (raise only);
//  3. control = trusted under principal_plan or principal_control, else the context;
//  4. each top-level parameter: trusted under principal_plan, else the join over its leaves (a leaf is trusted when the
//     context is trusted or it occurs as a token in a verified principal content);
//  5. floors: the action's params[p], else first_party for a sensitive action and agent otherwise;
//  6. a sensitive action whose control is not trusted, or any tainted parameter, is escalate; otherwise pass.
//
// Never panics (an internal error is a malformed_config deny).
func DecideArgProvenance(input any) (d ArgProvenanceDecision) {
	d = ArgProvenanceDecision{Sensitive: true, Control: "agent", Labels: map[string]string{}, Tainted: []string{}, Path: []string{}}
	deny := func(code, reason string) ArgProvenanceDecision {
		d.Outcome, d.Code, d.Reason = "deny", code, reason
		return d
	}
	defer func() {
		if r := recover(); r != nil {
			d.Outcome, d.Code, d.Reason = "deny", "malformed_config", fmt.Sprintf("evaluation error (fail closed): %v", r)
		}
	}()
	in, ok := normalizeJSON(input).(map[string]any)
	if !ok {
		return deny("malformed_config", "input must be an object")
	}
	pins, ok := in["mediators"].([]any)
	for _, p := range pins {
		ok = ok && isProvMediatorPin(p)
	}
	if !ok {
		return deny("malformed_config", "mediator pins must be a list of {mediator, kid, pk, pq_pk?}")
	}
	op, ok := in["operation"].(map[string]any)
	if _, isStr := op["resource"].(string); !ok || !boundedStr(op["verb"], 256) || !isStr {
		return deny("malformed_operation", "the operation needs a verb, a resource and a params object")
	}
	params, ok := op["params"].(map[string]any)
	if !ok {
		return deny("malformed_operation", "the operation needs a verb, a resource and a params object")
	}
	action, hasAction := in["action"]
	if hasAction {
		if e := ProvActionInfoError(action); e != "" {
			return deny("malformed_action", e)
		}
	}
	var obs []any
	if ov, has := in["observed"]; has && ov != nil {
		if obs, ok = ov.([]any); !ok {
			return deny("malformed_config", "observations must be a list of {origin, source}")
		}
		for _, o := range obs {
			om, isObj := o.(map[string]any)
			if org := om["origin"]; !isObj || (org != "tool" && org != "retrieval" && org != "web") || !boundedStr(om["source"], 256) {
				return deny("malformed_config", "observations must be a list of {origin, source}")
			}
		}
	}
	sensitive := !IsReadOnlyAction(action)
	d.Sensitive = sensitive
	ch, code, reason := provVerifyChain(in["bundle"], op, pins)
	if code != "" {
		return deny(code, reason)
	}
	d.Verified = ch.verified
	context := ch.context
	path := append([]string{}, ch.path...)
	for _, o := range obs {
		om := o.(map[string]any)
		org := om["origin"].(string)
		context = provJoin(context, provOriginLevel[org])
		path = append(path, org+":"+om["source"].(string))
	}
	d.Path = provSortU(path)
	plan := in["principal_plan"] == true
	control := context
	if plan || in["principal_control"] == true {
		control = "trusted"
	}
	d.Control = control
	labels := map[string]string{}
	for _, p := range sortedKeysUtf8(params) {
		if plan {
			labels[p] = "trusted"
			continue
		}
		leaves, ok := ProvLeaves(params[p])
		if !ok {
			labels[p] = context
			continue
		}
		l := "trusted"
		for _, leaf := range leaves {
			// a leaf the principal typed verbatim is the principal's choice whatever else the context held
			level := context
			if context == "trusted" || provTyped(ch.texts, leaf) {
				level = "trusted"
			}
			l = provJoin(l, level)
		}
		labels[p] = l
	}
	d.Labels = labels
	facts, _ := action.(map[string]any)
	floors, _ := facts["params"].(map[string]any)
	tainted := []string{}
	for p, label := range labels {
		f, has := floors[p].(string)
		if !has {
			f = "agent"
			if sensitive {
				f = "first_party"
			}
		}
		if provRank[label] > provRank[f] {
			tainted = append(tainted, p)
		}
	}
	d.Tainted = provSortU(tainted)
	// no segment origin maps to first_party, so a control label is trusted or untrusted
	badControl := sensitive && control != "trusted"
	if !badControl && len(d.Tainted) == 0 {
		d.Outcome = "pass"
		return d
	}
	switch {
	case badControl && len(d.Tainted) > 0:
		d.Code = "untrusted_control_and_args"
	case badControl:
		d.Code = "untrusted_control"
	default:
		d.Code = "untrusted_args"
	}
	parts := []string{}
	if badControl {
		parts = append(parts, "the choice of "+op["verb"].(string)+" derives from untrusted content")
	}
	if len(d.Tainted) > 0 {
		verb := "derive"
		if len(d.Tainted) == 1 {
			verb = "derives"
		}
		parts = append(parts, strings.Join(d.Tainted, ", ")+" "+verb+" from untrusted content")
	}
	where := ""
	if len(d.Path) > 0 {
		where = " [" + strings.Join(d.Path, ", ") + "]"
	}
	d.Outcome = "escalate"
	d.Reason = strings.Join(parts, "; ") + where + ": the principal must confirm (prompt-injection path)"
	return d
}

func provTyped(texts [][]uint16, leaf string) bool {
	n := utf16Units(leaf)
	for _, t := range texts {
		if occursUnits(t, n) {
			return true
		}
	}
	return false
}

// ProvEnvelopeError validates the grant envelope member `provenance` {mode?: "enforce" | "insecure_off", mediators?: [pin]
// (<= 16)}: "" when well formed. mode "insecure_off" is the principal's signed, DOCUMENTED-DANGEROUS opt-out of the gate.
func ProvEnvelopeError(p any) string {
	m, ok := p.(map[string]any)
	if !ok {
		return "provenance must be an object"
	}
	if e := closedMembersMsg(m, "provenance", nil, "mode", "mediators"); e != "" {
		return e
	}
	if mode, has := m["mode"]; has && mode != "enforce" && mode != "insecure_off" {
		return "provenance.mode must be 'enforce' or 'insecure_off'"
	}
	if mv, has := m["mediators"]; has {
		l, isList := mv.([]any)
		ok := isList && len(l) <= 16
		for _, x := range l {
			ok = ok && isProvMediatorPin(x)
		}
		if !ok {
			return "provenance.mediators must be at most 16 {mediator, kid, pk, pq_pk?}"
		}
	}
	return ""
}

// ---- the gate (Authorize) --------------------------------------------------------------------------------------------------

// ArgProvenanceOptions configures the provenance gate Authorize always runs (check `provenance_flow`).
//
//   - Mediators: the mediator keys this verifier pins (the agent harness, gateway or MCP client that labels context segments);
//     the grant envelope's `provenance.mediators` are added to them.
//   - Actions: the facts of the action about to run, from YOUR action definitions ({effects, traits, params: {name: floor}}).
//     nil (or a nil map) = unknown action: every argument is a sink and the choice must derive from the principal.
//   - Observed: untrusted content THIS server saw reach the agent's context in this session (raise only); session is the
//     bundle's session id ("" when none).
//   - Bundle: where the bundle comes from when AuthorizeInput.ProvenanceBundle is nil (the middleware then does not read the
//     PCA-Provenance header / pca_provenance body member). An error or a panic is an unreadable bundle (denied).
type ArgProvenanceOptions struct {
	Mediators []ProvMediatorPin
	Actions   func(op Operation) map[string]any
	Observed  func(pcactn map[string]any, op Operation, session string) []ProvObservation
	Bundle    func(pcactn map[string]any, op Operation) (any, error)
}

// provUnreadable is the bundle the middleware passes for a PCA-Provenance header that does not decode or parse.
type provUnreadable struct{}

func provBundleSession(b any) string {
	m, _ := b.(map[string]any)
	rs, _ := m["receipts"].([]any)
	if len(rs) == 0 {
		return ""
	}
	r, _ := rs[0].(map[string]any)
	s, _ := r["session"].(string)
	return s
}

// argProvenanceGate runs the provenance gate for one request: status "pass", "not-enforced" (the grant's signed insecure_off)
// or "fail" with the reason (an escalate reason carries the `escalate:` prefix, so the ternary decision reads it as
// escalate-class; a deny code keeps it deny).
func argProvenanceGate(in AuthorizeInput, p, grant map[string]any, op Operation, principalPlan, principalControl bool) (status, reason string) {
	defer func() {
		if r := recover(); r != nil {
			status, reason = "fail", "evaluation error (fail closed)"
		}
	}()
	var penv map[string]any
	if env := ReadEnvelope(grant); env != nil {
		if pe, has := env["provenance"]; has {
			if e := ProvEnvelopeError(pe); e != "" {
				return "fail", "the grant's provenance member is malformed: " + e
			}
			penv = pe.(map[string]any)
		}
	}
	// the principal's signed, documented-dangerous opt-out
	if penv["mode"] == "insecure_off" {
		return "not-enforced", ""
	}
	o := in.ArgProvenance
	if o == nil {
		o = &ArgProvenanceOptions{}
	}
	bundle := in.ProvenanceBundle
	if bundle == nil && o.Bundle != nil {
		b, err := o.Bundle(p, op)
		if err != nil {
			return "fail", "the provenance bundle is unreadable (fail closed)"
		}
		bundle = b
	}
	if _, bad := bundle.(provUnreadable); bad {
		return "fail", "the provenance bundle is unreadable (fail closed)"
	}
	pins := []any{}
	for _, pin := range o.Mediators {
		pins = append(pins, pin.JSON())
	}
	if ms, ok := penv["mediators"].([]any); ok {
		pins = append(pins, ms...)
	}
	input := map[string]any{"bundle": bundle, "operation": map[string]any{"verb": op.Verb, "resource": op.Resource, "params": op.Params},
		"mediators": pins, "principal_plan": principalPlan, "principal_control": principalControl}
	if o.Actions != nil {
		if facts := o.Actions(op); facts != nil {
			input["action"] = facts
		}
	}
	if o.Observed != nil {
		obs := []any{}
		for _, x := range o.Observed(p, op, provBundleSession(bundle)) {
			obs = append(obs, map[string]any{"origin": x.Origin, "source": x.Source})
		}
		input["observed"] = obs
	}
	d := DecideArgProvenance(input)
	switch d.Outcome {
	case "pass":
		return "pass", ""
	case "escalate":
		return "fail", "escalate: " + d.Reason
	}
	return "fail", d.Code + ": " + d.Reason
}

// ---- the mediator side (the recorder) --------------------------------------------------------------------------------------

// ProvenanceRecorderOptions configures a recorder. Mediator (<= 256 bytes) and Kid (<= 64 bytes) are required. Key is the
// mediator's Ed25519 key (generated when nil; then pin Recorder.Pin): keep it out of the model's reach. Suite selects a
// post-quantum / hybrid artifact suite (nil = Ed25519). Session is the base64url 32-byte session id (random when ""). Now is
// the clock in epoch milliseconds (nil = the wall clock).
type ProvenanceRecorderOptions struct {
	Mediator string
	Kid      string
	Key      *KeyPair
	Suite    *SuiteOpts
	Session  string
	Now      func() int64
}

// ProvenanceRecorder is the mediator side: one recorder per agent session, run where the bytes enter the model's context
// (the harness that builds the prompt, a gateway, an MCP client). Safe for concurrent use.
type ProvenanceRecorder struct {
	// Session is the session id every receipt carries.
	Session string
	// Pin is what a verifier (ArgProvenanceOptions.Mediators) or the principal's grant envelope must carry for this recorder.
	Pin ProvMediatorPin

	o        ProvenanceRecorderOptions
	key      *KeyPair
	now      func() int64
	mu       sync.Mutex
	chain    []map[string]any
	contents map[string]any
}

// NewProvenanceRecorder creates the recorder of one agent session.
func NewProvenanceRecorder(o ProvenanceRecorderOptions) (*ProvenanceRecorder, error) {
	if !boundedStr(o.Mediator, 256) || !boundedStr(o.Kid, 64) {
		return nil, errors.New("NewProvenanceRecorder: mediator (<= 256 bytes) and kid (<= 64 bytes) are required")
	}
	key := o.Key
	if key == nil {
		k, err := NewKeyPair()
		if err != nil {
			return nil, err
		}
		key = k
	}
	session := o.Session
	if session == "" {
		s := make([]byte, 32)
		if _, err := rand.Read(s); err != nil {
			return nil, err
		}
		session = b64.EncodeToString(s)
	}
	if !isDigestV(session) {
		return nil, errors.New("NewProvenanceRecorder: session must be canonical base64url of 32 bytes")
	}
	pin := ProvMediatorPin{Mediator: o.Mediator, Kid: o.Kid, PK: key.Public}
	if o.Suite != nil && o.Suite.alg() != "ed25519" {
		if o.Suite.Pq == nil {
			return nil, fmt.Errorf("NewProvenanceRecorder: %s needs a post-quantum key pair", o.Suite.alg())
		}
		pin.PQPK = o.Suite.Pq.Public
	}
	now := o.Now
	if now == nil {
		now = func() int64 { return time.Now().UnixMilli() }
	}
	return &ProvenanceRecorder{Session: session, Pin: pin, o: o, key: key, now: now, contents: map[string]any{}}, nil
}

// provClip keeps a receipt source within 256 UTF-8 bytes (halving in UTF-16 code units, as the reference); empty is "-". A cut
// that splits a surrogate pair leaves a lone surrogate the reference's strict canonicalizer refuses: an error, never U+FFFD.
func provClip(s string) (string, error) {
	for utf8Len(s) > 256 {
		u := utf16Units(s)
		n := len(u) / 2
		if n < 1 {
			n = 1
		}
		if utf16.IsSurrogate(rune(u[n-1])) && u[n-1] < 0xDC00 {
			return "", errors.New("provenance: the source cannot be clipped without splitting a surrogate pair")
		}
		s = string(utf16.Decode(u[:n]))
	}
	if s == "" {
		return "-", nil
	}
	return s, nil
}

// provTextOf is the text a segment's digest covers: a string as is, anything else as its JSON text.
func provTextOf(c any) string {
	if s, ok := c.(string); ok {
		return s
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(c); err != nil {
		return fmt.Sprint(c)
	}
	return strings.TrimSuffix(buf.String(), "\n")
}

// appendLocked signs and appends one receipt (r.mu held).
func (r *ProvenanceRecorder) appendLocked(origin, source, digest string) (map[string]any, error) {
	issued := r.now()
	if issued < 0 {
		issued = 0
	}
	var prev any
	if n := len(r.chain); n > 0 {
		last := r.chain[n-1]
		ref, ok := ProvReceiptRef(last)
		if !ok {
			return nil, errors.New("provenance: the previous receipt is not canonical")
		}
		prev = ref
		if li := int64(jsF(last["issued_at"])); li > issued {
			issued = li
		}
	}
	src, err := provClip(source)
	if err != nil {
		return nil, err
	}
	body := map[string]any{"v": 1, "kind": "pca-prov", "mediator": r.o.Mediator, "kid": r.o.Kid, "session": r.Session,
		"seq": len(r.chain), "prev": prev, "origin": origin, "source": src, "content_digest": digest, "issued_at": issued}
	rc, err := SignArtifact(ProvReceiptDomain, body, r.key, r.o.Suite)
	if err != nil {
		return nil, err
	}
	r.chain = append(r.chain, rc)
	return copyMap(rc), nil
}

func (r *ProvenanceRecorder) segment(origin, source string, content any) (map[string]any, error) {
	text := provTextOf(content)
	digest, err := HashCanonical(text)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	rc, err := r.appendLocked(origin, source, digest)
	if err != nil {
		return nil, err
	}
	if origin == "principal" && utf8Len(text) <= MaxProvContentBytes {
		r.contents[strconv.Itoa(len(r.chain)-1)] = text
	}
	return rc, nil
}

// Principal records the principal's own message (TRUSTED).
func (r *ProvenanceRecorder) Principal(text string) (map[string]any, error) {
	return r.segment("principal", "user", text)
}

// Tool records a tool result (UNTRUSTED). Non-string output is recorded as its JSON text.
func (r *ProvenanceRecorder) Tool(name string, output any) (map[string]any, error) {
	return r.segment("tool", name, output)
}

// Retrieval records a retrieved document (UNTRUSTED).
func (r *ProvenanceRecorder) Retrieval(source string, content any) (map[string]any, error) {
	return r.segment("retrieval", source, content)
}

// Web records a fetched web page or HTTP response (UNTRUSTED).
func (r *ProvenanceRecorder) Web(url string, content any) (map[string]any, error) {
	return r.segment("web", url, content)
}

// ForAction records the chosen action and returns the bundle to present with it (AuthorizeInput.ProvenanceBundle, or the
// PCA-Provenance header: strict base64url of its JSON).
func (r *ProvenanceRecorder) ForAction(op Operation) (map[string]any, error) {
	digest, err := ProvActionDigest(op)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.chain) >= MaxProvReceipts {
		return nil, fmt.Errorf("provenance: the session holds %d receipts; start a new session with the principal's message", MaxProvReceipts)
	}
	if _, err := r.appendLocked("action", op.Verb, digest); err != nil {
		return nil, err
	}
	receipts := make([]any, len(r.chain))
	for i, x := range r.chain {
		receipts[i] = copyMap(x)
	}
	b := map[string]any{"v": 1, "kind": "pca-provenance", "receipts": receipts}
	if len(r.contents) > 0 {
		b["contents"] = copyMap(r.contents)
	}
	return b, nil
}

// Receipts returns every receipt so far.
func (r *ProvenanceRecorder) Receipts() []map[string]any {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]map[string]any, len(r.chain))
	for i, x := range r.chain {
		out[i] = copyMap(x)
	}
	return out
}

// PrincipalDirectProvenance is the bundle for an operation that came straight from the principal (the application's own UI
// acting on the user's explicit input, no model in between): one principal segment holding the operation's strict canonical
// JSON, then the action. Under a pinned recorder key the operation's choice and values are trusted.
func PrincipalDirectProvenance(r *ProvenanceRecorder, op Operation) (map[string]any, error) {
	params, ok := jsonValue(op.Params, 1)
	if !ok {
		return nil, errors.New("provenance: the operation params are not JSON")
	}
	text, err := Canonicalize(map[string]any{"verb": op.Verb, "resource": op.Resource, "params": params})
	if err != nil {
		return nil, err
	}
	if _, err := r.Principal(text); err != nil {
		return nil, err
	}
	return r.ForAction(op)
}
