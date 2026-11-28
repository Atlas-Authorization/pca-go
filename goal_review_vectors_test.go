package pca

// Replay of the reference corpus for goal review: the policy card, semantic diff, signed goal approval and its loader, over an injected
// stub kernel (the proved compiler is not part of the untagged build).

import (
	"errors"
	"testing"
)

// goalReviewStub is the corpus's stub kernel; mode selects which entry points throw or are absent.
func goalReviewStub(mode string) *GoalReviewKernel {
	k := &GoalReviewKernel{
		Compile: func(g, _ any) map[string]any {
			if mode == "throwcompile" {
				panic(errors.New("boom"))
			}
			grants := anlReqList(goalReviewReq(g, "grants"))
			if len(grants) == 0 {
				return map[string]any{"ok": false, "reasons": []any{"empty"}}
			}
			gids := []any{}
			for _, x := range grants {
				gids = append(gids, goalReviewReq(x, "gid"))
			}
			return map[string]any{"ok": true, "policy": map[string]any{"gids": gids, "n": goalNum(int64(len(grants)))}}
		},
		PolicyDigest: func(p any) string {
			if mode == "throwdigest" {
				panic(errors.New("boom"))
			}
			return goalReviewHash(map[string]any{"d": "stub-policy", "p": p})
		},
		Analyze: func(p any) []any {
			if f, _ := jsNum(goalReviewReq(p, "n")); f >= 5 {
				return []any{"too many"}
			}
			return []any{}
		},
	}
	if mode != "nodecide" {
		k.Decide = func(g, _, act, _ any) string {
			for _, x := range anlReqList(goalReviewReq(g, "grants")) {
				if anlStrictEq(goalReviewReq(x, "verb"), goalReviewReq(act, "verb")) {
					return "allow"
				}
			}
			return "deny"
		}
	}
	if mode != "nonewly" {
		k.NewlyAllowed = func(prev, nxt, _ any, _ int) map[string]any {
			ws := []any{}
			for _, x := range anlReqList(goalReviewReq(nxt, "grants")) {
				seen := false
				for _, y := range anlReqList(goalReviewReq(prev, "grants")) {
					if anlStrictEq(goalReviewReq(y, "gid"), goalReviewReq(x, "gid")) {
						seen = true
					}
				}
				if !seen {
					ws = append(ws, map[string]any{"verb": goalReviewReq(x, "verb"), "res": "r", "params": map[string]any{}, "t": goalNum(0), "sess": "s",
						"prin": "p", "org": "o", "agent": "a", "depth": goalNum(0)})
				}
			}
			return map[string]any{"witnesses": ws, "complete": true}
		}
	}
	return k
}

func goalReviewSplit(opts any) (map[string]any, string) {
	o := map[string]any{}
	if m, ok := opts.(map[string]any); ok {
		o = anlCopy(m)
	}
	km := "full"
	if s, ok := o["kmode"].(string); ok {
		km = s
	}
	delete(o, "kmode")
	return o, km
}

// goalReviewCall runs f; a review refusal carries its code as the reference's does.
func goalReviewCall(f func() any) (any, error) {
	r, err := anlTry(f)
	var re *GoalReviewError
	if errors.As(err, &re) {
		return nil, &CodedError{Code: re.Code, Msg: re.Error()}
	}
	return r, err
}

func TestGoalReviewVectors(t *testing.T) {
	replayVectorsSeeded(t, "ref-goal-review.json.gz", map[string]vecFn{
		"effectiveLimits": func(a []any) (any, error) { return goalEffectiveLimits(vecArg(a, 0)), nil },
		"renderPolicyCard": func(a []any) (any, error) {
			return goalReviewCall(func() any { return goalRenderPolicyCard(vecArg(a, 0), vecArg(a, 1), vecArg(a, 2)) })
		},
		"cardDigest": func(a []any) (any, error) { return goalReviewCall(func() any { return goalCardDigest(vecArg(a, 0)) }) },
		"cardToText": func(a []any) (any, error) { return goalReviewCall(func() any { return goalCardToText(vecArg(a, 0)) }) },
		"diffGoals": func(a []any) (any, error) {
			o, km := goalReviewSplit(vecArg(a, 2))
			return goalReviewCall(func() any { return goalDiffGoals(vecArg(a, 0), vecArg(a, 1), goalReviewStub(km), o) })
		},
		"diffToText": func(a []any) (any, error) { return goalReviewCall(func() any { return goalDiffToText(vecArg(a, 0)) }) },
		"approveGoalSeed": func(a []any) (any, error) {
			o, km := goalReviewSplit(vecArg(a, 2))
			o["kernel"] = goalReviewStub(km)
			seed, ok := DecodeB64uStrict(vecArg(a, 1).(string), -1)
			if !ok {
				return nil, errors.New("bad seed")
			}
			return goalReviewCall(func() any { return goalApproveGoal(vecArg(a, 0), seed, o) })
		},
		"loadApprovedGoal": func(a []any) (any, error) {
			o, km := goalReviewSplit(vecArg(a, 2))
			o["kernel"] = goalReviewStub(km)
			return goalReviewCall(func() any { return goalLoadApprovedGoal(vecArg(a, 0), vecArg(a, 1), o) })
		},
	})
}
