package pca

// Consistency tokens (`fresh_at`): a signed high-water mark of verifier-side state (revocation epoch, ledger size, budget
// version, policy revision). The verifier refuses to DECIDE against state older than the token it was handed
// (`stale_state` is an escalation, never an allow). Verification only: this SDK does not mint tokens.

import "strings"

const (
	freshAtDomain    = "atlas-pca/fresh-at/v1\x00"
	freshAtRefDomain = "atlas-pca/fresh-at-ref/v1"
	// freshAtSkewMs is how far in the future a token's issued_at may be.
	freshAtSkewMs = 60000
)

var freshAtCounters = []string{"revocation_epoch", "ledger_tree_size", "budget_version", "policy_revision"}

// k3Str is the reference isStr: a non-empty string of at most max UTF-16 units.
func k3Str(v any, max int) bool {
	s, ok := v.(string)
	return ok && s != "" && jsLen(s) <= max
}

// k3Int is the reference isSafeInt: a safe integer >= 0.
func k3Int(v any) bool {
	f, ok := jsNum(v)
	return ok && jsIsSafeInteger(v) && f >= 0
}

// VerifyFreshAt: the token is well formed and signed by `signer` over exactly its content. Never panics.
func VerifyFreshAt(t any, signer string) bool {
	m, ok := t.(map[string]any)
	if !ok {
		return false
	}
	if f, ok := jsNum(m["v"]); !ok || f != 1 {
		return false
	}
	if s, ok := m["signer"].(string); !ok || s != signer {
		return false
	}
	if !k3Str(m["scope"], 256) || !k3Str(m["policy_digest"], 128) || !k3Int(m["issued_at"]) {
		return false
	}
	for _, k := range freshAtCounters {
		if !k3Int(m[k]) {
			return false
		}
	}
	body, ok := extPick(m, "v", "scope", "revocation_epoch", "ledger_tree_size", "budget_version", "policy_revision", "policy_digest", "issued_at", "signer")
	return ok && extSigned(signer, freshAtDomain, body, m["sig"])
}

// FreshAtDigest is the content address a PCActn or request signs to bind the token it carried (ok false when the token
// is not canonicalizable).
func FreshAtDigest(token any) (string, bool) {
	return hashCanonicalV(map[string]any{"d": freshAtRefDomain, "t": token})
}

// FreshAtState is the verifier's own counters (or the ones a token commits to).
type FreshAtState struct {
	RevocationEpoch int64
	LedgerTreeSize  int64
	BudgetVersion   int64
	PolicyRevision  int64
	PolicyDigest    string
}

func (s FreshAtState) counter(k string) float64 {
	switch k {
	case "revocation_epoch":
		return float64(s.RevocationEpoch)
	case "ledger_tree_size":
		return float64(s.LedgerTreeSize)
	case "budget_version":
		return float64(s.BudgetVersion)
	}
	return float64(s.PolicyRevision)
}

// FreshAtStateFromJSON reads {revocation_epoch, ledger_tree_size, budget_version, policy_revision, policy_digest}; a
// missing or non-numeric counter is 0 and a missing digest "" (trusted configuration, not a wire object).
func FreshAtStateFromJSON(v any) FreshAtState {
	m, _ := v.(map[string]any)
	n := func(k string) int64 { f, _ := jsNum(m[k]); return int64(f) }
	d, _ := m["policy_digest"].(string)
	return FreshAtState{n("revocation_epoch"), n("ledger_tree_size"), n("budget_version"), n("policy_revision"), d}
}

// FreshAtOptions are the options of CheckFreshAt. MaxTokenAgeMs nil: only the state ordering applies.
type FreshAtOptions struct {
	Signer        string
	Scope         string
	Now           int64
	MaxTokenAgeMs *int64
}

// FreshAtVerdict: Decision "ok", "escalate" (Code "stale_state", Behind names the counters) or "deny" (Code bad_token,
// wrong_scope, token_from_the_future, token_too_old, policy_fork).
type FreshAtVerdict struct {
	Decision string
	Code     string
	Behind   []string
}

// CheckFreshAt: may the verifier decide against `local` for a request carrying `token`? Signature/shape, scope, issued in
// the future (> 60 s skew), token age, policy fork (same revision, different digest), then any counter behind the token
// is an escalation. Every step fails closed.
func CheckFreshAt(token any, local FreshAtState, o FreshAtOptions) FreshAtVerdict {
	deny := func(c string) FreshAtVerdict { return FreshAtVerdict{Decision: "deny", Code: c} }
	if !VerifyFreshAt(token, o.Signer) {
		return deny("bad_token")
	}
	m := token.(map[string]any)
	if m["scope"] != o.Scope {
		return deny("wrong_scope")
	}
	now := float64(o.Now)
	issued := jsF(m["issued_at"])
	if !(issued <= now+freshAtSkewMs) {
		return deny("token_from_the_future")
	}
	if o.MaxTokenAgeMs != nil && !(now-issued <= float64(*o.MaxTokenAgeMs)) {
		return deny("token_too_old")
	}
	if jsF(m["policy_revision"]) == local.counter("policy_revision") && m["policy_digest"] != local.PolicyDigest {
		return deny("policy_fork")
	}
	var behind []string
	for _, k := range freshAtCounters {
		if !(local.counter(k) >= jsF(m[k])) {
			behind = append(behind, k)
		}
	}
	if len(behind) == 0 {
		return FreshAtVerdict{Decision: "ok"}
	}
	return FreshAtVerdict{Decision: "escalate", Code: "stale_state", Behind: behind}
}

// ---- the PCActn member and the verifier check ----------------------------------------------------------------------------

var freshAtKeys = []string{"v", "scope", "revocation_epoch", "ledger_tree_size", "budget_version", "policy_revision", "policy_digest", "issued_at", "signer", "sig"}

// validateFreshAtWire is the wire shape of the `fresh_at` member: "" when well formed, else the problem. The signature is
// not checked here (that is the `fresh_at` check). The key set is closed: an unknown key inside a signed member is malleability.
func validateFreshAtWire(v any) string {
	m, ok := v.(map[string]any)
	if !ok {
		return "'fresh_at' must be an object"
	}
	for _, k := range jsKeys(m) {
		if !containsStr(freshAtKeys, k) {
			return "'fresh_at' has an unknown field '" + k + "'"
		}
	}
	if f, ok := jsNum(m["v"]); !ok || f != 1 {
		return "'fresh_at.v' must be 1"
	}
	if !k3Str(m["scope"], 256) || !k3Str(m["policy_digest"], 128) {
		return "'fresh_at' scope and policy_digest must be non-empty strings"
	}
	for _, k := range []string{"revocation_epoch", "ledger_tree_size", "budget_version", "policy_revision", "issued_at"} {
		if !k3Int(m[k]) {
			return "'fresh_at." + k + "' must be a non-negative safe integer"
		}
	}
	if !b64uOK(m["signer"], b32) {
		return "'fresh_at.signer' is not canonical base64url (32 bytes)"
	}
	if !b64uOK(m["sig"], sigLen) {
		return "'fresh_at.sig' is not canonical base64url (64 bytes)"
	}
	return ""
}

// FreshAtPolicy is the verifier-side configuration of the `fresh_at` check.
type FreshAtPolicy struct {
	// Signer is the pinned token signer (b64u Ed25519 public key).
	Signer string
	// Scope is the scope this verifier decides for; a token for another scope is refused.
	Scope string
	// Local is the verifier's OWN current state counters.
	Local         FreshAtState
	MaxTokenAgeMs *int64
	// Require: every PCActn must carry (or have side-carried) a token; none is `escalate: ...` (refresh and retry).
	Require bool
	// SideCarried is a token that travelled beside the PCActn (an HTTP header); HasSideCarried is true when one was presented
	// (even a null one). It is read only when the PCActn has no `fresh_at` member.
	SideCarried    any
	HasSideCarried bool
}

// FreshAtPolicyFromJSON reads {signer, scope, local, max_token_age_ms?, require?, side_carried?}; nil when v is not an object.
func FreshAtPolicyFromJSON(v any) *FreshAtPolicy {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	p := &FreshAtPolicy{Local: FreshAtStateFromJSON(m["local"])}
	p.Signer, _ = m["signer"].(string)
	p.Scope, _ = m["scope"].(string)
	p.Require = m["require"] == true
	if x, has := m["max_token_age_ms"]; has {
		f, _ := jsNum(x)
		n := int64(f)
		p.MaxTokenAgeMs = &n
	}
	p.SideCarried, p.HasSideCarried = m["side_carried"]
	return p
}

type freshAtCheck struct {
	status string // "none", "pass" or "fail"
	reason string
}

// decideFreshAt is the verifier's `fresh_at` check. Reported only when the PCActn carries the member, a side-carried token is
// read, or the policy requires one; otherwise "none" (the verdict is byte-identical to before). A stale verifier is an
// ESCALATE-class failure (DecisionOf reads the `escalate:` prefix), anything else is a hard failure.
func decideFreshAt(pcactn map[string]any, policy *FreshAtPolicy, now int64) freshAtCheck {
	member, hasMember := pcactn["fresh_at"]
	if policy == nil {
		if hasMember {
			return freshAtCheck{"fail", "the PCActn carries fresh_at but this verifier has no fresh_at policy (fail closed)"}
		}
		return freshAtCheck{status: "none"}
	}
	token, present := member, hasMember
	if !hasMember {
		token, present = policy.SideCarried, policy.HasSideCarried
	}
	if !present {
		if policy.Require {
			return freshAtCheck{"fail", "escalate: a consistency token is required (refresh and retry with the token of your latest write)"}
		}
		return freshAtCheck{status: "none"}
	}
	v := CheckFreshAt(token, policy.Local, FreshAtOptions{Signer: policy.Signer, Scope: policy.Scope, Now: now, MaxTokenAgeMs: policy.MaxTokenAgeMs})
	switch v.Decision {
	case "ok":
		return freshAtCheck{status: "pass"}
	case "escalate":
		return freshAtCheck{"fail", "escalate: stale_state (verifier state is behind the token on " + strings.Join(v.Behind, ", ") + ")"}
	}
	return freshAtCheck{"fail", v.Code}
}
