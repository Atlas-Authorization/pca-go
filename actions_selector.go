package pca

// Trait selectors and the signed confirmation message: a selector is a positive predicate over the trait closure of an action.
// Prohibit selectors float (they cover every present and future action that matches); allow selectors are pinned to a set of
// verbs and may not use negation (the absence of a trait is never a safety claim). An unconfirmed action is maximally dangerous:
// every prohibit selector matches it and no allow selector ever does. A selector is the JSON form {k, id | ids | s | a, b}; a
// malformed one matches nothing (and so cannot allow), except under prohibit, where every selector matches an unconfirmed action.

import (
	"errors"
	"sort"
)

// ActionSelectorMatches: does the selector match an action whose trait closure is `closure`? Monotone in `closure` unless the
// selector contains `not`.
func ActionSelectorMatches(s any, closure []string) bool {
	m, _ := s.(map[string]any)
	switch m["k"] {
	case "trait":
		id, ok := m["id"].(string)
		return ok && contains(closure, id)
	case "all_of":
		ids, ok := strsOf(m["ids"])
		if !ok {
			return false
		}
		for _, id := range ids {
			if !contains(closure, id) {
				return false
			}
		}
		return true
	case "any_of":
		ids, ok := strsOf(m["ids"])
		if !ok {
			return false
		}
		for _, id := range ids {
			if contains(closure, id) {
				return true
			}
		}
		return false
	case "not":
		return !ActionSelectorMatches(m["s"], closure)
	case "and":
		return ActionSelectorMatches(m["a"], closure) && ActionSelectorMatches(m["b"], closure)
	}
	return false
}

// ActionSelectorMatchesFor: does a selector of the given mode ("allow" | "prohibit") match an action? For a confirmed action it is
// ActionSelectorMatches over its closure; an unconfirmed one is matched by every prohibit selector and by no allow selector.
func ActionSelectorMatchesFor(s any, mode string, closure []string, confirmed bool) bool {
	if !confirmed {
		return mode == "prohibit"
	}
	return ActionSelectorMatches(s, closure)
}

// ActionSelectorHasNot: does the selector contain a negation (through `and`)?
func ActionSelectorHasNot(s any) bool {
	m, _ := s.(map[string]any)
	switch m["k"] {
	case "not":
		return true
	case "and":
		return ActionSelectorHasNot(m["a"]) || ActionSelectorHasNot(m["b"])
	}
	return false
}

func asAnyOf(s any) bool {
	m, _ := s.(map[string]any)
	switch m["k"] {
	case "any_of":
		return true
	case "and":
		return asAnyOf(m["a"]) || asAnyOf(m["b"])
	}
	return false
}

// ActionAllowSelectorError is the typing rule for an allow selector: no negation anywhere, and any_of only inside a pinned allow.
// "" = allowed.
func ActionAllowSelectorError(s any, pinned bool) string {
	if ActionSelectorHasNot(s) {
		return "an allow selector must not use negation: the absence of a trait is never a safety claim"
	}
	if !pinned && asAnyOf(s) {
		return "any_of in an allow selector requires the grant to be pinned to a pack digest"
	}
	return ""
}

func asAnyMatch(list any, mode string, closure []string, confirmed bool) bool {
	xs, _ := list.([]any)
	for _, s := range xs {
		if ActionSelectorMatchesFor(s, mode, closure, confirmed) {
			return true
		}
	}
	return false
}

// ActionPolicyDecision is the policy component of the decision for one action (its verb, trait closure, human-confirmed or not):
// a matching prohibit denies; an unpinned verb is deny (escalate under on_new_action); a pinned verb with a matching allow is
// allowed; a pinned verb with no allow is denied.
func ActionPolicyDecision(p map[string]any, verb string, closure []string, confirmed bool) string {
	if asAnyMatch(p["prohibit"], "prohibit", closure, confirmed) {
		return "deny"
	}
	pinned, _ := p["pinned"].([]any)
	if !containsV(pinned, verb) {
		if p["on_new_action"] == "escalate" {
			return "escalate"
		}
		return "deny"
	}
	if asAnyMatch(p["allow"], "allow", closure, confirmed) {
		return "allow"
	}
	return "deny"
}

// ActionReviewMessage is the domain-separated message the reviewer signs: REVIEW_DOMAIN \0 strictCanonical(body), with the
// final traits sorted and de-duplicated and the dismissals sorted by trait.
func ActionReviewMessage(b map[string]any) ([]byte, error) {
	final, ok := strsOf(b["final_traits"])
	if !ok {
		return nil, errors.New("final_traits is not a list of strings")
	}
	dis, ok := b["dismissed"].([]any)
	if !ok {
		return nil, errors.New("dismissed is not a list")
	}
	seen := map[string]bool{}
	fin := []string{}
	for _, t := range final {
		if !seen[t] {
			seen[t] = true
			fin = append(fin, t)
		}
	}
	adSortU16(fin)
	ds := make([]map[string]any, 0, len(dis))
	for _, x := range dis {
		m, ok := x.(map[string]any)
		if !ok {
			return nil, errors.New("a dismissal is not an object")
		}
		ds = append(ds, m)
	}
	sort.SliceStable(ds, func(i, j int) bool {
		a, _ := ds[i]["trait"].(string)
		c, _ := ds[j]["trait"].(string)
		return u16Less(a, c)
	})
	dl := make([]any, len(ds))
	for i, d := range ds {
		dl[i] = map[string]any{"trait": d["trait"], "reason": d["reason"]}
	}
	msg, ok := domainMessage(reviewDomain, map[string]any{"def_digest": b["def_digest"], "traits_digest": b["traits_digest"], "facts_digest": b["facts_digest"],
		"final_traits": anyStrs(fin), "dismissed": dl, "reviewer_kid": b["reviewer_kid"], "ts": b["ts"]})
	if !ok {
		return nil, errors.New("the review body is not canonical")
	}
	return msg, nil
}

// ActionSignReview signs a review body (an Ed25519 seed) and returns it with sorted final traits and dismissals and `sig`.
func ActionSignReview(b map[string]any, seed []byte) (map[string]any, error) {
	kp, err := KeyPairFromSeed(seed)
	if err != nil {
		return nil, err
	}
	msg, err := ActionReviewMessage(b)
	if err != nil {
		return nil, err
	}
	out := map[string]any{}
	for k, v := range b {
		out[k] = v
	}
	final, _ := strsOf(b["final_traits"])
	fin := []string{}
	seen := map[string]bool{}
	for _, t := range final {
		if !seen[t] {
			seen[t] = true
			fin = append(fin, t)
		}
	}
	adSortU16(fin)
	out["final_traits"] = anyStrs(fin)
	dis, _ := b["dismissed"].([]any)
	ds := append([]any{}, dis...)
	sort.SliceStable(ds, func(i, j int) bool {
		a, _ := ds[i].(map[string]any)["trait"].(string)
		c, _ := ds[j].(map[string]any)["trait"].(string)
		return u16Less(a, c)
	})
	out["dismissed"] = ds
	out["sig"] = b64.EncodeToString(kp.Sign(msg))
	return out, nil
}
