package pca

// Intent Layer M2: the signed `envelope.intent` slot of a PCActn and the `intent` check. Normative rules:
// packages/pca/src/intent-binding.ts and conformance/README.md "12. Intent binding".

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
)

const (
	intentGoalPrefix       = "pca-intent:v1:"
	intentGoalCommitDomain = "atlas-pca/goal/v1\x00"
	ppmOne                 = 1_000_000
	// MaxIntentGoalSaltLen is the UTF-8 byte cap of `intent.goal_salt`.
	MaxIntentGoalSaltLen = 128
)

// envelopeIntentFields is the closed (all-required) member set of `envelope.intent`.
var envelopeIntentFields = []string{"ref", "map_digest", "goal_salt", "fidelity_ppm", "residual_risk_ppm"}

// IntentPolicy is the verifier-side intent policy. Every field is optional. The policy is ACTIVE iff Require is
// true or either threshold is set (non-nil, even if invalid); an active policy runs the `intent` check even for a
// PCActn without the slot, and fails it closed. A set threshold that is not a non-negative safe integer is a
// misconfiguration and fails the check.
type IntentPolicy struct {
	// Require every PCActn to carry a bound `intent`.
	Require bool
	// MinFidelityPpm denies when the claimed `fidelity_ppm` is below it. Setting it implies Require.
	MinFidelityPpm *float64
	// MaxResidualRiskPpm denies when the claimed `residual_risk_ppm` is above it. Setting it implies Require.
	MaxResidualRiskPpm *float64
}

func (p *IntentPolicy) active() bool {
	return p != nil && (p.Require || p.MinFidelityPpm != nil || p.MaxResidualRiskPpm != nil)
}

// IntentGoalCommit = HashCanonical({d: "atlas-pca/goal/v1\x00", goal: "pca-intent:v1:"+ref+":"+mapDigest, salt}):
// the goal commitment a root grant minted for this IntentStatement and Intent Map carries.
func IntentGoalCommit(ref, mapDigest, goalSalt string) (string, error) {
	return HashCanonical(map[string]any{
		"d":    intentGoalCommitDomain,
		"goal": intentGoalPrefix + ref + ":" + mapDigest,
		"salt": goalSalt,
	})
}

// validateIntentWire returns "" when the `intent` slot is well-formed, else the wire reason.
func validateIntentWire(v any) string {
	m, ok := isObj(v)
	if !ok {
		return "'intent' must be an object"
	}
	if k, ok := closedKeys(m, envelopeIntentFields...); !ok {
		return "unknown field 'intent." + k + "'"
	}
	for _, k := range envelopeIntentFields {
		if _, has := m[k]; !has {
			return "missing field 'intent." + k + "'"
		}
	}
	if !b64uOK(m["ref"], b32) {
		return "'intent.ref' is not canonical base64url (32 bytes)"
	}
	if !b64uOK(m["map_digest"], b32) {
		return "'intent.map_digest' is not canonical base64url (32 bytes)"
	}
	if s, ok := m["goal_salt"].(string); !ok || len(s) == 0 || len(s) > MaxIntentGoalSaltLen {
		return "'intent.goal_salt' must be a non-empty string (<= 128 UTF-8 bytes)"
	}
	if f, ok := safeInt(m["fidelity_ppm"]); !ok || f < 0 || f > ppmOne {
		return "'intent.fidelity_ppm' must be a safe integer in [0, 1000000]"
	}
	if r, ok := safeInt(m["residual_risk_ppm"]); !ok || r < 0 {
		return "'intent.residual_risk_ppm' must be a non-negative safe integer"
	}
	return ""
}

// rootGoalCommit: the FIRST `envelope` caveat of the verifier's root grant, its string `goal_commit`.
func rootGoalCommit(grant map[string]any) (string, bool) {
	cav, _ := grant["caveats"].([]any) // not an array => no caveats
	for _, c := range cav {
		cm, _ := c.(map[string]any) // a non-object caveat reads as a nil map: no `type`, skipped
		if t, _ := cm["type"].(string); t == "envelope" {
			gc, ok := cm["goal_commit"].(string)
			return gc, ok
		}
	}
	return "", false
}

// okThreshold: unset, or a non-negative safe integer. NaN fails `f == Trunc(f)`, -Inf / -0 / negatives fail the sign
// test, +Inf fails the upper bound, so no separate finiteness test is needed.
func okThreshold(x *float64) bool {
	if x == nil {
		return true
	}
	f := *x
	return f == math.Trunc(f) && !math.Signbit(f) && f <= maxSafeInt
}

// decideIntent runs the `intent` check on a wire-valid PCActn. evaluated == false means the check is not reported
// (no slot, inactive policy). Panic-free on a wire-valid PCActn (VerifyPCActnCoreWith still recovers, fail closed).
func decideIntent(pcactn, grant map[string]any, policy *IntentPolicy) (evaluated bool, reason string) {
	slot, has := pcactn["intent"]
	active := policy.active()
	if !has && !active {
		return false, ""
	}
	if active && (!okThreshold(policy.MinFidelityPpm) || !okThreshold(policy.MaxResidualRiskPpm)) {
		return true, "intent policy misconfigured: thresholds must be non-negative safe integers (fail closed)"
	}
	if !has {
		return true, "this verifier requires an intent binding but the PCActn carries none"
	}
	m, _ := slot.(map[string]any)
	commit, ok := rootGoalCommit(grant)
	if !ok {
		return true, "the root grant carries no envelope goal commitment to bind the intent to"
	}
	ref, _ := m["ref"].(string)
	md, _ := m["map_digest"].(string)
	salt, _ := m["goal_salt"].(string)
	want, err := IntentGoalCommit(ref, md, salt)
	if is, ok := pcactn["intent_session"].(map[string]any); ok {
		session, _ := is["session"].(string)
		want, err = intentGoalCommitV2(session, md, salt, is["map_form"] == mapFormCommit)
	}
	if err != nil || want != commit {
		return true, "intent ref / map_digest / goal_salt do not open the root grant's goal commitment"
	}
	fid, _ := safeInt(m["fidelity_ppm"])
	res, _ := safeInt(m["residual_risk_ppm"])
	if policy != nil && policy.MinFidelityPpm != nil && !(float64(fid) >= *policy.MinFidelityPpm) {
		return true, fmt.Sprintf("intent fidelity %d ppm is below the policy minimum %v", fid, *policy.MinFidelityPpm)
	}
	if policy != nil && policy.MaxResidualRiskPpm != nil && !(float64(res) <= *policy.MaxResidualRiskPpm) {
		return true, fmt.Sprintf("intent residual risk %d ppm exceeds the policy maximum %v", res, *policy.MaxResidualRiskPpm)
	}
	return true, ""
}

// IntentPolicyFromJSON builds an IntentPolicy from a decoded JSON object ({require?, min_fidelity_ppm?,
// max_residual_risk_ppm?}; numbers as json.Number from ParseJSONLenient / StrictParse, or float64 / int / int64). A
// threshold keeps its NUMERIC VALUE whatever its lexical form (950000.0 and 1e6 are 950000 and 1000000; "-0" is -0),
// so the check accepts exactly the non-negative safe integers and fails closed on anything else. A present non-numeric
// threshold (null, bool, string, ...) or an unparseable number becomes NaN (misconfigured). nil when v is not an
// object.
func IntentPolicyFromJSON(v any) *IntentPolicy {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	p := &IntentPolicy{}
	p.Require, _ = m["require"].(bool)
	num := func(k string) *float64 {
		x, has := m[k]
		if !has {
			return nil
		}
		f := math.NaN()
		switch t := x.(type) {
		case float64:
			f = t
		case int:
			f = float64(t)
		case int64:
			f = float64(t)
		case json.Number:
			if g, err := strconv.ParseFloat(string(t), 64); err == nil {
				f = g
			}
		}
		return &f
	}
	p.MinFidelityPpm = num("min_fidelity_ppm")
	p.MaxResidualRiskPpm = num("max_residual_risk_ppm")
	return p
}

// IntentPolicyFromJSONText parses raw policy JSON text with the lenient loader (any JSON number form) and applies
// IntentPolicyFromJSON. An unparseable text or a non-object is an error.
func IntentPolicyFromJSONText(text string) (*IntentPolicy, error) {
	v, err := ParseJSONLenient([]byte(text))
	if err != nil {
		return nil, err
	}
	p := IntentPolicyFromJSON(v)
	if p == nil {
		return nil, fmt.Errorf("intent policy: not a JSON object")
	}
	return p, nil
}
