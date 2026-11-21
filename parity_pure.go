package pca

// Small pure helpers of the core surface: hash agility, the cheap PCActn claims, the agent caveat context, the reversibility
// class an action is bound to, the layer ceilings in their object form and the policy-side collection of obligations.

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"strings"
	"unicode/utf16"
)

// IsHashSuite reports whether s names a known hash suite ("sha256" or "sha384"); anything else must fail closed at the caller.
func IsHashSuite(s any) bool { return s == "sha256" || s == "sha384" }

// HashCanonicalSuite is the unpadded base64url digest of the strict canonical JSON of v under a hash suite: "sha256" (the
// default, equal to HashCanonical) or "sha384". An unknown suite is an error.
func HashCanonicalSuite(v any, suite string) (string, error) {
	if !IsHashSuite(suite) {
		return "", errors.New("hashCanonical: unknown hash suite")
	}
	c, err := Canonicalize(v)
	if err != nil {
		return "", err
	}
	if suite == "sha384" {
		return b64.EncodeToString(sha384Sum([]byte(c))), nil
	}
	h := sha256.Sum256([]byte(c))
	return b64.EncodeToString(h[:]), nil
}

// B64uLen is the length of the unpadded base64url text of n bytes.
func B64uLen(n int) int { return int(math.Ceil(float64(n) * 4 / 3)) }

// IsCanonicalB64u reports whether s is canonical unpadded base64url (alphabet only, no padding, zero trailing bits); wantLen >= 0
// also requires that exact decoded length.
func IsCanonicalB64u(s any, wantLen int) bool {
	str, ok := s.(string)
	if !ok {
		return false
	}
	_, good := DecodeB64uStrict(str, wantLen)
	return good
}

// PcactnCheapClaims checks the claims of a PCActn that need no signature and no store: the audience and the validity window. It
// returns ("", "") when they hold, else the failing check (audience or validity) and its reason. Run it before any expensive
// work; it replaces none of the verifier's checks.
func PcactnCheapClaims(p map[string]any, audience string, now float64) (check, reason string) {
	if aud, ok := p["aud"].(string); !ok || aud == "" || aud != audience {
		return "audience", "aud does not match this resource server / instance"
	}
	iat, ok1 := storeSafeInt(p["iat"])
	exp, ok2 := storeSafeInt(p["exp"])
	if !ok1 || !ok2 {
		return "validity", "iat and exp must be safe-integer epoch ms"
	}
	if now != math.Trunc(now) || math.IsInf(now, 0) || math.IsNaN(now) || math.Abs(now) > maxSafeInt {
		return "validity", "the verifier clock is not a safe integer epoch-ms"
	}
	n := int64(now)
	switch {
	case !(exp > iat):
		return "validity", "exp must be greater than iat"
	case exp-iat > MaxLifetimeMs:
		return "validity", fmt.Sprintf("lifetime exceeds %d ms", int64(MaxLifetimeMs))
	case iat > n+MaxSkewMs:
		return "validity", "iat is in the future (clock skew)"
	case n > exp:
		return "validity", "the PCActn has expired"
	}
	return "", ""
}

// ToolCallOf is the tool call an action context stands for: {tool: the verb ("" when it is not a string), args: the params object
// ({} for anything else), toolSignatureDigest: the context's toolBinding when it is a string}.
func ToolCallOf(action map[string]any) map[string]any {
	inner, _ := action["action"].(map[string]any)
	tool, _ := inner["verb"].(string)
	args, ok := inner["params"].(map[string]any)
	if !ok {
		args = map[string]any{}
	}
	out := map[string]any{"tool": tool, "args": args}
	if b, ok := action["toolBinding"].(string); ok {
		out["toolSignatureDigest"] = b
	}
	return out
}

// AgentCaveatContext is the caveat context of an agent action: base with `action` and `toolCall` set from the action context
// (whatever base carried under those names is replaced, so a caller cannot smuggle its own tool call in).
func AgentCaveatContext(base, action map[string]any) map[string]any {
	out := copyMap(base)
	if action == nil {
		action = map[string]any{}
	}
	out["action"], out["toolCall"] = action, ToolCallOf(action)
	return out
}

// ResolveReversibilityClass is the class an action is bound to: its own reversibility_class, else that of the plan node nodeID
// names (ok false when there is none: no node named, an unknown node, or a node without a class). There is never a guess from the
// verb or the resource.
func ResolveReversibilityClass(action map[string]any, plan []any, nodeID any) (class any, ok bool) {
	inner, _ := action["action"].(map[string]any)
	if own, has := inner["reversibility_class"]; has && own != nil {
		return own, true
	}
	id, isStr := nodeID.(string)
	if !isStr {
		return nil, false
	}
	for _, n := range plan {
		if node, isMap := n.(map[string]any); isMap && node["id"] == any(id) {
			c, has := node["reversibility_class"]
			return c, has && c != nil
		}
	}
	return nil, false
}

// DecideLayerCeilings checks an action against the org, site and std ceilings in that order: {status: "pass"} or {status:
// "fail", layer, reason}. A malformed layers object or ceiling fails (as the org ceiling when no ceiling is to blame): a ceiling
// is never a question.
func DecideLayerCeilings(layers any, actx map[string]any) map[string]any {
	reason := decideLayerCeilings(layers, actx)
	if reason == "" {
		return map[string]any{"status": "pass"}
	}
	layer := "org"
	for _, k := range []string{"site", "std"} {
		if strings.Contains(reason, "the "+k+" ceiling") {
			layer = k
		}
	}
	return map[string]any{"status": "fail", "layer": layer, "reason": strings.TrimSuffix(reason, ": fails as the org ceiling")}
}

// obligationsRuleError is the reference's wording for a malformed obligation list inside a rule ("" when well formed).
func obligationsRuleError(list any) string {
	l, ok := list.([]any)
	if !ok {
		return "obligations must be an array"
	}
	if len(l) > maxObligations {
		return fmt.Sprintf("more than %d obligations", maxObligations)
	}
	seen := map[string]bool{}
	for i, o := range l {
		if e := ObligationError(o); e != "" {
			if e == "unknown obligation kind" {
				m, _ := o.(map[string]any)
				e += " '" + oaString(oaGet(m, "kind")) + "'"
			}
			return fmt.Sprintf("obligations[%d]: %s", i, e)
		}
		key, ok := ObligationKey(o.(map[string]any))
		if !ok {
			return fmt.Sprintf("obligations[%d]: not canonicalizable", i)
		}
		if seen[key] {
			return fmt.Sprintf("obligations[%d] duplicates an earlier obligation", i)
		}
		seen[key] = true
	}
	return ""
}

// CollectObligations is the policy-side collection: the merged obligations of every rule {id, when, obligations} whose `when` is
// true OR cannot be decided over ctx ({action, subject, env}); a missing value adds the duties, the tightening direction. nil
// rules is no rules. The result is {ok: true, obligations} or {ok: false, reason}: a malformed rule list, rule or obligation
// list is a refusal, as is any evaluation fault.
func CollectObligations(rules any, ctx map[string]any) (res map[string]any) {
	no := func(reason string) map[string]any { return map[string]any{"ok": false, "reason": reason} }
	defer func() {
		if recover() != nil {
			res = no("evaluation error (fail closed)")
		}
	}()
	if rules == nil {
		return map[string]any{"ok": true, "obligations": []any{}}
	}
	list, ok := rules.([]any)
	if !ok {
		return no("obligation rules must be an array")
	}
	var lists []any
	ids := map[string]bool{}
	b := &regexBudget{}
	for i, rv := range list {
		r, isObj := rv.(map[string]any)
		id, isStr := r["id"].(string)
		_, whenObj := r["when"].(map[string]any)
		malformed := !isObj || !isStr || id == "" || len(utf16.Encode([]rune(id))) > 64 || !whenObj
		for k := range r {
			malformed = malformed || (k != "id" && k != "when" && k != "obligations")
		}
		if malformed {
			return no(fmt.Sprintf("obligation rule %d is malformed", i))
		}
		if ids[id] {
			return no("obligation rule id '" + id + "' is a duplicate")
		}
		ids[id] = true
		obs, has := r["obligations"]
		e := ""
		if has {
			e = obligationsRuleError(obs)
		}
		if l, _ := obs.([]any); e == "" && len(l) == 0 {
			e = "obligations must not be empty"
		}
		if e != "" {
			return no("obligation rule '" + id + "': " + e)
		}
		if evaluateConditionTri(r["when"], ctx, b) != triFalse {
			lists = append(lists, obs)
		}
	}
	merged, ok := MergeObligations(lists...)
	if !ok {
		return no(fmt.Sprintf("more than %d obligations after merging", maxObligations))
	}
	if merged == nil {
		merged = []any{}
	}
	return map[string]any{"ok": true, "obligations": merged}
}
