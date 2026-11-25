package pca

import (
	"errors"
	"fmt"
	"math"
)

// ---- Merkle inclusion proofs --------------------------------------------------------------------------------------------

// MerkleProof builds the inclusion proof {index, size, path} of leaves[index] in the tree MerkleRoot builds (sha256 suite).
// VerifyInclusion checks it.
func MerkleProof(leaves []any, index int) (map[string]any, error) {
	if index < 0 || index >= len(leaves) {
		return nil, errors.New("merkleProof: index out of range")
	}
	hs := make([][]byte, len(leaves))
	for i, l := range leaves {
		h, err := leafHash(l)
		if err != nil {
			return nil, err
		}
		hs[i] = h
	}
	var prove func(hs [][]byte, idx int) []any
	prove = func(hs [][]byte, idx int) []any {
		if len(hs) == 1 {
			return nil
		}
		k := split(len(hs))
		if idx < k {
			return append(prove(hs[:k], idx), map[string]any{"side": "R", "hash": b64.EncodeToString(build(hs[k:]))})
		}
		return append(prove(hs[k:], idx-k), map[string]any{"side": "L", "hash": b64.EncodeToString(build(hs[:k]))})
	}
	path := prove(hs, index)
	if path == nil {
		path = []any{}
	}
	return map[string]any{"index": jsNumber(float64(index)), "size": jsNumber(float64(len(leaves))), "path": path}, nil // JSON numbers, as VerifyInclusion reads them
}

// ---- PCActn text ----------------------------------------------------------------------------------------------------------

// EncodePCActn is the server-side (lenient) canonical text of a PCActn.
func EncodePCActn(p map[string]any) (string, bool) { return canonicalLenient(p) }

// DecodePCActn decodes a PCActn from its JSON text under the strict profile (size cap first, no duplicate keys, canonical
// numbers). It errors on any deviation.
func DecodePCActn(s string) (map[string]any, error) { return ParsePCActn(s) }

// PCActnDigest is the content digest of a PCActn: base64url(sha256(strict canonical form)).
func PCActnDigest(p map[string]any) (string, error) { return HashCanonical(p) }

// ArtifactTooLarge reports whether s exceeds MaxArtifactBytes UTF-8 bytes.
func ArtifactTooLarge(s string) bool { return len(s) > MaxArtifactBytes }

// ---- pca_need ---------------------------------------------------------------------------------------------------------------

// ValidatePcaNeed is "" for a well-formed need, else its typed code (bad_shape, unknown_member, bad_version, bad_kind, bad_field).
func ValidatePcaNeed(x any) string { return ValidateA2ANeed(x) }

// DecodePcaNeed decodes a pca_need value: the need, or the typed failure code (too_long, bad_base64, bad_utf8, bad_json, ...).
func DecodePcaNeed(value any) (map[string]any, string) { return DecodeA2ANeed(value) }

// PcaNeedDigest is the content address an approval flow cites for a need.
func PcaNeedDigest(need map[string]any) (string, error) {
	return HashCanonical(map[string]any{"d": "atlas-pca/need/v1", "need": need})
}

// ---- conditions ---------------------------------------------------------------------------------------------------------------

// IsGroupCondition reports whether c is a boolean grouping (all_of, any_of or not) rather than a leaf comparison.
func IsGroupCondition(c map[string]any) bool { return isGroupCond(c) }

// IsLeafCondition reports whether c is a leaf comparison: not a grouping, with a string field.
func IsLeafCondition(c map[string]any) bool {
	_, hasField := c["field"].(string)
	return !isGroupCond(c) && hasField
}

// EvaluateCondition is true only when the condition decides true: a condition that cannot be cleanly decided never satisfies a
// not, never completes an all_of and never carries an any_of. b nil opens a fresh document budget.
func EvaluateCondition(c any, ctx map[string]any, b *RegexBudget) bool {
	if b == nil {
		b = &regexBudget{}
	}
	return evaluateConditionTri(c, ctx, b) == triTrue
}

// ---- action receipts ------------------------------------------------------------------------------------------------------

// ActionReceipt is one entry of the principal's own hash-chained record of what their agents did and how each action was
// verified. Each receipt commits to the previous one, so a dropped or altered entry is detectable.
type ActionReceipt struct {
	Seq          int    `json:"seq"`
	At           int64  `json:"at"`
	ActionDigest string `json:"actionDigest"`
	Verb         string `json:"verb"`
	Resource     string `json:"resource"`
	// Outcome is "allow" or "deny".
	Outcome string `json:"outcome"`
	// Checks is the verifier's per-check map at the time (optional, for drill-down).
	Checks any `json:"checks,omitempty"` // a JSON value (map[string]any)
	// Prev is the hash of the previous receipt ("" for the first) and Hash the hash of this receipt's body.
	Prev string `json:"prev"`
	Hash string `json:"hash"`
}

// ReceiptVerify is what a receipt records of a verification: the verdict and, optionally, its per-check map.
type ReceiptVerify struct {
	Allow  bool
	Checks any
}

func receiptBodyHash(r ActionReceipt) (string, error) {
	return HashCanonical(map[string]any{"d": "atlas-pca/receipt/v1", "seq": r.Seq, "at": int(r.At), "actionDigest": r.ActionDigest,
		"verb": r.Verb, "resource": r.Resource, "outcome": r.Outcome, "checks": r.Checks, "prev": r.Prev})
}

// ReceiptFor builds the next receipt in a chain for a verified action. at nil uses the PCActn's iat.
func ReceiptFor(prevHash string, seq int, p map[string]any, verify ReceiptVerify, at *int64) (ActionReceipt, error) {
	digest, err := PCActnDigest(p)
	if err != nil {
		return ActionReceipt{}, err
	}
	var t int64
	if at != nil {
		t = *at
	} else if iat, ok := jsNum(p["iat"]); ok {
		t = int64(iat)
	}
	action, _ := p["action"].(map[string]any)
	r := ActionReceipt{Seq: seq, At: t, ActionDigest: digest, Verb: receiptStr(action, "verb"), Resource: receiptStr(action, "resource"), Outcome: "deny", Checks: verify.Checks, Prev: prevHash}
	if verify.Allow {
		r.Outcome = "allow"
	}
	if r.Hash, err = receiptBodyHash(r); err != nil {
		return ActionReceipt{}, err
	}
	return r, nil
}

func receiptStr(m map[string]any, k string) string { s, _ := m[k].(string); return s }

// AppendReceipt appends a verified action to a receipt log, chaining to the last entry.
func AppendReceipt(log []ActionReceipt, p map[string]any, verify ReceiptVerify, at *int64) ([]ActionReceipt, error) {
	prev, seq := "", 0
	if n := len(log); n > 0 {
		prev, seq = log[n-1].Hash, log[n-1].Seq+1
	}
	r, err := ReceiptFor(prev, seq, p, verify, at)
	if err != nil {
		return nil, err
	}
	return append(append([]ActionReceipt(nil), log...), r), nil
}

// ActionReceiptChainCheck is the result of VerifyActionReceiptChain.
type ActionReceiptChainCheck struct {
	OK bool
	// BrokenAt is the seq of the first broken link, when OK is false.
	BrokenAt int
	Reason   string
}

// VerifyActionReceiptChain verifies a receipt log is an intact hash chain: sequential, correctly linked, each hash matching its body.
func VerifyActionReceiptChain(log []ActionReceipt) ActionReceiptChainCheck {
	prev := ""
	for i, r := range log {
		if r.Seq != i {
			return ActionReceiptChainCheck{BrokenAt: r.Seq, Reason: fmt.Sprintf("seq %d out of order (expected %d)", r.Seq, i)}
		}
		if r.Prev != prev {
			return ActionReceiptChainCheck{BrokenAt: r.Seq, Reason: fmt.Sprintf("prev link mismatch at seq %d", r.Seq)}
		}
		if h, err := receiptBodyHash(r); err != nil || h != r.Hash {
			return ActionReceiptChainCheck{BrokenAt: r.Seq, Reason: fmt.Sprintf("hash mismatch at seq %d (tampered body)", r.Seq)}
		}
		prev = r.Hash
	}
	return ActionReceiptChainCheck{OK: true}
}

// ReceiptHead is the head hash of a log: one value that commits to the entire history ("" for an empty log).
func ReceiptHead(log []ActionReceipt) string {
	if len(log) == 0 {
		return ""
	}
	return log[len(log)-1].Hash
}

// ---- multi-agent budget algebra -----------------------------------------------------------------------------------------

// SubBudget allocates a sub-agent budget B_sub = alloc, guarded by 0 <= alloc <= the parent's remaining budget.
func SubBudget(parent TrustBudget, alloc float64) (TrustBudget, error) {
	if math.IsNaN(alloc) || math.IsInf(alloc, 0) || alloc < 0 {
		return TrustBudget{}, errors.New("allocation must be finite and >= 0")
	}
	if !(finite(parent.B) && alloc <= parent.B) {
		return TrustBudget{}, errors.New("allocation exceeds parent remaining budget")
	}
	asOf := parent.Tau
	if parent.HasAsOf {
		asOf = parent.AsOf
	}
	return TrustBudget{B: alloc, Tau: parent.Tau, AsOf: asOf, HasAsOf: true}, nil
}

// DebitConsolidated debits a sub-agent's spend from both the sub-agent and the parent, so a swarm of sub-agents cannot
// collectively spend more than the parent's remaining budget. Nothing changes when either cannot cover c.
func DebitConsolidated(parent, sub TrustBudget, c float64) (newParent, newSub TrustBudget, err error) {
	x := riskNz(c)
	if !(finite(sub.B) && sub.B >= x) {
		return parent, sub, errors.New("sub-agent budget insufficient")
	}
	if !(finite(parent.B) && parent.B >= x) {
		return parent, sub, errors.New("parent budget insufficient")
	}
	return parent.Debit(x), sub.Debit(x), nil
}

// DebitConsolidatedPath debits c along a root-to-leaf budget path: every node must be able to cover c, else nothing is debited
// and the first offender is named.
func DebitConsolidatedPath(path []TrustBudget, c float64) ([]TrustBudget, error) {
	x := riskNz(c)
	for i, b := range path {
		if !(finite(b.B) && b.B >= x) {
			return nil, fmt.Errorf("budget node at depth %d insufficient (need %s, have %s)", i, jsNumberString(x), jsNumberString(b.B))
		}
	}
	out := make([]TrustBudget, len(path))
	for i, b := range path {
		out[i] = b.Debit(x)
	}
	return out, nil
}

// ---- plan leaves, budget-allocation caveats, template links -------------------------------------------------------------

// PlanNodeLeaf is the Merkle leaf of a plan node {id, verb, resource, params_digest?, reversibility_class?, pre?, post?}: the
// node's action with its pre and post conditions committed as one digest.
func PlanNodeLeaf(n map[string]any) (map[string]any, error) {
	cond, err := conditionsDigest(n["pre"], n["post"])
	if err != nil {
		return nil, err
	}
	return planLeaf(n["id"], n, cond)
}

// IsBudgetAllocCaveat reports whether cv is a well-formed budget_alloc caveat: its type and a finite limit of at least 0.
func IsBudgetAllocCaveat(cv any) bool {
	m, ok := cv.(map[string]any)
	if !ok || m["type"] != BudgetAllocCaveat {
		return false
	}
	limit, ok := jsNum(m["limit"])
	return ok && !math.IsNaN(limit) && !math.IsInf(limit, 0) && limit >= 0
}

// LinkDigest is the content digest of a template reference.
func LinkDigest(ref any) (string, error) { return HashCanonical(ref) }
