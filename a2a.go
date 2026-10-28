package pca

// The A2A binding (verification side): typed needs (`pca_need`), per-hop chain extension, the pure gate of AUTH_REQUIRED
// resumption, push-token binding and signed task-update receipts. Total. Per-hop PCActn verification is the ordinary verifier's
// job; this is what surrounds it. Replays packages/pca/conformance/a2a-vectors.json.

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	a2aNeedMaxEncoded = 2048
	a2aNeedDomain     = "atlas-pca/need/v1"
	a2aReceiptDomain  = "atlas-pca/a2a-receipt/v1\x00"
	a2aReceiptRef     = "atlas-pca/a2a-receipt-ref/v1"
)

var a2aNeedMembers = map[string]bool{"v": true, "kind": true, "verb": true, "resource": true, "scopes": true, "grant_ref": true, "limits": true, "discharges": true, "tier": true, "policy_digest": true}
var a2aTerminal = map[string]bool{"TASK_STATE_COMPLETED": true, "TASK_STATE_FAILED": true, "TASK_STATE_CANCELED": true, "TASK_STATE_REJECTED": true}
var a2aStates = map[string]bool{"TASK_STATE_COMPLETED": true, "TASK_STATE_FAILED": true, "TASK_STATE_CANCELED": true, "TASK_STATE_REJECTED": true,
	"TASK_STATE_SUBMITTED": true, "TASK_STATE_WORKING": true, "TASK_STATE_INPUT_REQUIRED": true, "TASK_STATE_AUTH_REQUIRED": true}

// ValidateA2ANeed returns "" for a valid decoded need, else the refusal code.
func ValidateA2ANeed(x any) string {
	m, ok := x.(map[string]any)
	if !ok {
		return "bad_shape"
	}
	for k := range m {
		if !a2aNeedMembers[k] {
			return "unknown_member"
		}
	}
	if f, ok := jsNum(m["v"]); !ok || f != 1 {
		return "bad_version"
	}
	kind, _ := m["kind"].(string)
	if kind != "scope" && kind != "grant" && kind != "discharge" && kind != "escalate" {
		return "bad_kind"
	}
	if !k3Str(m["verb"], 128) || !k3Str(m["resource"], 512) {
		return "bad_field"
	}
	if v, has := m["scopes"]; has {
		l, ok := v.([]any)
		if !ok || len(l) > 16 {
			return "bad_field"
		}
		for _, e := range l {
			s, _ := e.(string)
			if !k3Str(e, 128) || strings.IndexFunc(s, unicode.IsSpace) >= 0 {
				return "bad_field"
			}
		}
	}
	for _, k := range []string{"grant_ref", "policy_digest"} {
		if v, has := m[k]; has && !k3Str(v, 128) {
			return "bad_field"
		}
	}
	if v, has := m["tier"]; has {
		if f, ok := jsNum(v); !ok || (f != 2 && f != 3) {
			return "bad_field"
		}
		if kind != "escalate" {
			return "bad_field"
		}
	}
	if v, has := m["limits"]; has {
		l, ok := v.(map[string]any)
		if !ok || len(l) > 16 {
			return "bad_field"
		}
		for k, e := range l {
			if f, ok := jsNum(e); !k3Str(k, 64) || !ok || f < 0 {
				return "bad_field"
			}
		}
	}
	if v, has := m["discharges"]; has {
		l, ok := v.([]any)
		if !ok || len(l) > 16 {
			return "bad_field"
		}
		for _, e := range l {
			d, ok := e.(map[string]any)
			if !ok || len(d) > 2 || !k3Str(d["issuer"], 512) || !k3Str(d["claim"], 256) {
				return "bad_field"
			}
			for k := range d {
				if k != "issuer" && k != "claim" {
					return "bad_field"
				}
			}
		}
	}
	if _, has := m["tier"]; !has && kind == "escalate" {
		return "bad_field"
	}
	return ""
}

// DecodeA2ANeed decodes a `pca_need` value: the need (nil on failure) and the refusal code ("" on success).
func DecodeA2ANeed(value any) (map[string]any, string) {
	s, ok := value.(string)
	if !ok || s == "" {
		return nil, "bad_base64"
	}
	if len(s) > a2aNeedMaxEncoded {
		return nil, "too_long"
	}
	raw, ok := DecodeB64uStrict(s, -1)
	if !ok {
		return nil, "bad_base64"
	}
	if !utf8.Valid(raw) {
		return nil, "bad_utf8"
	}
	parsed, err := StrictParse(string(raw))
	if err != nil {
		return nil, "bad_json"
	}
	if code := ValidateA2ANeed(parsed); code != "" {
		return nil, code
	}
	return parsed.(map[string]any), ""
}

// A2ANeedDigest is the content address an approval flow cites for a need.
func A2ANeedDigest(need map[string]any) (string, error) {
	return HashCanonical(map[string]any{"d": a2aNeedDomain, "need": need})
}

// CheckA2AChainExtension: every hop has a chain and each extends the one before it. Returns (failedHop, reason), ("" when ok).
func CheckA2AChainExtension(chains [][]string) (int, string) {
	for i, ids := range chains {
		if len(ids) == 0 {
			return i, "no_chain"
		}
		if i > 0 {
			prev := chains[i-1]
			if len(ids) < len(prev) {
				return i, "chain_does_not_extend_previous_hop"
			}
			for k := range prev {
				if ids[k] != prev[k] {
					return i, "chain_does_not_extend_previous_hop"
				}
			}
		}
	}
	return -1, ""
}

// A2AResumeGate is the pure part of AUTH_REQUIRED resumption; "" means the full verifier may now be asked.
func A2AResumeGate(state string, needEncoded any, answerDigest any, proofVerb, proofResource *string) string {
	if state != "TASK_STATE_AUTH_REQUIRED" && state != "auth-required" {
		return "task_not_auth_required"
	}
	var need map[string]any
	if needEncoded != nil {
		need, _ = DecodeA2ANeed(needEncoded)
	}
	if need == nil {
		return "no_valid_need"
	}
	d, err := A2ANeedDigest(need)
	if s, _ := answerDigest.(string); err != nil || s != d {
		return "answer_not_bound_to_need"
	}
	if proofVerb == nil || proofResource == nil {
		return "no_proof"
	}
	if *proofVerb != need["verb"] || *proofResource != need["resource"] {
		return "action_mismatch"
	}
	return ""
}

// A2APushToken binds a push-notification token to the task, the authorizing chain and a secret salt (>= 16 characters; else ok false).
func A2APushToken(taskID string, chainIDs []string, salt string) (string, bool) {
	if utf8.RuneCountInString(salt) < 16 {
		return "", false
	}
	cd, err := PcaGrantChainDigest(chainIDs)
	if err != nil {
		return "", false
	}
	t, err := HashCanonical(map[string]any{"d": "atlas-pca/a2a-push/v1", "task_id": taskID, "chain": cd, "salt": salt})
	return t, err == nil
}

// CheckA2APush checks a delivered notification; reason is "" when ok.
func CheckA2APush(taskID string, chainIDs []string, salt string, token any, payload any) string {
	t, _ := token.(string)
	if t == "" {
		return "no_token"
	}
	want, ok := A2APushToken(taskID, chainIDs, salt)
	if !ok || t != want {
		return "token_mismatch"
	}
	p, _ := payload.(map[string]any)
	for _, f := range [][2]string{{"task", "id"}, {"statusUpdate", "taskId"}, {"artifactUpdate", "taskId"}} {
		if c, ok := p[f[0]].(map[string]any); ok && c[f[1]] != nil {
			if id, _ := c[f[1]].(string); id == taskID {
				return ""
			}
			return "task_mismatch"
		}
	}
	return "task_mismatch"
}

// A2AReceiptDigest is the digest the next receipt cites as `prev`.
func A2AReceiptDigest(r any) (string, bool) {
	return hashCanonicalV(map[string]any{"d": a2aReceiptRef, "r": r})
}

// VerifyA2AReceipt: well formed and signed by `signer` over exactly its content.
func VerifyA2AReceipt(v any, signer string) bool {
	r, ok := v.(map[string]any)
	if !ok {
		return false
	}
	if f, ok := jsNum(r["v"]); !ok || f != 1 || r["signer"] != signer {
		return false
	}
	state, _ := r["state"].(string)
	if !k3Str(r["task_id"], 4096) || !a2aStates[state] || !k3Int(r["seq"]) || !k3Int(r["issued_at"]) {
		return false
	}
	if c, _ := r["chain"].(string); c == "" {
		return false
	} else if _, ok := DecodeB64uStrict(c, 32); !ok {
		return false
	}
	seq, _ := safeInt(r["seq"])
	prev := r["prev"]
	if prev != nil {
		p, isStr := prev.(string)
		if !isStr {
			return false
		}
		if _, ok := DecodeB64uStrict(p, 32); !ok {
			return false
		}
	}
	if (seq == 0) != (prev == nil) {
		return false
	}
	body, ok := extPick(r, "v", "task_id", "state", "seq", "prev", "chain", "issued_at", "signer")
	return ok && extSigned(signer, a2aReceiptDomain, body, r["sig"])
}

// A2AReceiptChainResult is the outcome of CheckA2AReceiptChain.
type A2AReceiptChainResult struct {
	OK        bool
	Code      string
	At        int
	Terminal  bool
	LastState string
}

// CheckA2AReceiptChain checks an ordered list of receipts for one task and one authorizing chain.
func CheckA2AReceiptChain(receipts []any, signer, taskID string, chainIDs []string) A2AReceiptChainResult {
	if len(receipts) == 0 {
		return A2AReceiptChainResult{Code: "empty", At: -1}
	}
	chain, err := PcaGrantChainDigest(chainIDs)
	if err != nil {
		return A2AReceiptChainResult{Code: "bad_receipt", At: 0}
	}
	var prev map[string]any
	for i, x := range receipts {
		if !VerifyA2AReceipt(x, signer) {
			return A2AReceiptChainResult{Code: "bad_receipt", At: i}
		}
		r := x.(map[string]any)
		if r["task_id"] != taskID {
			return A2AReceiptChainResult{Code: "wrong_task", At: i}
		}
		if r["chain"] != chain {
			return A2AReceiptChainResult{Code: "wrong_chain", At: i}
		}
		seq, _ := safeInt(r["seq"])
		if prev == nil {
			if seq != 0 {
				return A2AReceiptChainResult{Code: "bad_start", At: i}
			}
		} else {
			if ps, _ := prev["state"].(string); a2aTerminal[ps] {
				return A2AReceiptChainResult{Code: "after_terminal", At: i}
			}
			pseq, _ := safeInt(prev["seq"])
			d, _ := A2AReceiptDigest(prev)
			if seq != pseq+1 || r["prev"] != d {
				return A2AReceiptChainResult{Code: "broken_link", At: i}
			}
		}
		prev = r
	}
	st, _ := prev["state"].(string)
	return A2AReceiptChainResult{OK: true, At: -1, Terminal: a2aTerminal[st], LastState: st}
}

// A2AMayTriggerNext: only a verified, unbroken chain ending in COMPLETED may start the next workflow step.
func A2AMayTriggerNext(receipts []any, signer, taskID string, chainIDs []string) bool {
	r := CheckA2AReceiptChain(receipts, signer, taskID, chainIDs)
	return r.OK && r.LastState == "TASK_STATE_COMPLETED"
}
