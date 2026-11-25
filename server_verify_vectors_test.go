package pca

// The full verdict of the resource-server verifier against the reference corpus (ref-verify-verdict, 1022 cases, one function): allow,
// the risk score, the required threshold, every check with its status, the reasons (exact text, exact order), the budget and the
// assurance report.
//
// Counted deviations (asserted, never skipped):
//   - the strict-JSON parser words its refusal of an undecodable wire string in its own way (3 cases: the prefix up to the parser's
//     text is compared);
//   - the legacy allowUnboundPq option is never read (2 cases, Ed25519 artifacts, which the option does not touch: the verdicts are
//     compared in full and must be identical);
//   - a trust budget that is not a pair of finite numbers is refused by the Policy VM (fail closed) where the reference computes with
//     the missing numbers (2 cases: the verdict is either identical or a denial carrying the policy evaluation error).

import (
	"fmt"
	"math"
	"strings"
	"testing"
)

var vvState struct {
	budgetOdd  bool
	prefixOnly int
	unbound    int
	budgetDev  int
	allowed    int
}

// vvHook is a constant hook of the corpus: {enforced: false} | {enforced: true, ok, reason?, t?} | {throws} | {raw}.
func vvHook(h any) ServerHook {
	m, _ := h.(map[string]any)
	if th, has := m["throws"]; has {
		msg := fmt.Sprint(th)
		return func(map[string]any) ServerHookResult { panic(svThrow(msg)) }
	}
	raw := h
	if rv, has := m["raw"]; has {
		if rv == nil {
			return func(map[string]any) ServerHookResult {
				panic(svThrow("Cannot read properties of null (reading 'enforced')"))
			}
		}
		raw = rv
	}
	rm, _ := raw.(map[string]any)
	res := ServerHookResult{}
	if jsTruthy(rm["enforced"]) {
		res.Enforced, res.OK = true, jsTruthy(rm["ok"])
		if r, isStr := rm["reason"].(string); isStr {
			res.Reason, res.HasReason = r, true
		}
		if f, ok := jsNum(rm["t"]); ok {
			res.T = &f
		}
	}
	return func(map[string]any) ServerHookResult { return res }
}

func vvInput(opts map[string]any) ServerVerifyInput {
	o := map[string]any{}
	for k, v := range opts {
		if k != "hooks" && k != "enforce" {
			o[k] = v
		}
	}
	in := ServerVerifyInput{Opts: o}
	if hm, ok := opts["hooks"].(map[string]any); ok { // a `replay` entry is not a hook of the verifier: ignored
		if h, has := hm["attestation"]; has {
			in.Hooks.Attestation = vvHook(h)
		}
		if h, has := hm["threshold"]; has {
			in.Hooks.Threshold = vvHook(h)
		}
		if h, has := hm["revocation"]; has {
			in.Hooks.Revocation = vvHook(h)
		}
		if h, has := hm["zk"]; has {
			in.Hooks.Zk = vvHook(h)
		}
	}
	if em, ok := opts["enforce"].(map[string]any); ok {
		if f, ok := em["freshness"].(map[string]any); ok {
			g := &FreshnessGate{MaxAgeMs: jsF(f["maxAgeMs"])}
			if x, ok := jsNum(f["epochMs"]); ok {
				g.EpochMs = x
			}
			if x, ok := jsNum(f["clockSkewMs"]); ok {
				g.ClockSkewMs = x
			}
			if x, ok := jsNum(f["now"]); ok {
				n := int64(x)
				g.Now = &n
			}
			in.Enforce.Freshness = g
		}
		if a, ok := em["attestation"].(map[string]any); ok {
			in.Enforce.Attestation = &ServerAttestationGate{Verifier: vvHook(a["verifier"]), NotRequired: a["required"] == false}
		}
	}
	return in
}

func vvF(v any) float64 {
	f, _ := jsNum(v)
	return f
}

// vvDrop removes the members whose value is null (an absent member and a null one are the same here).
func vvDrop(m map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range m {
		if v != nil {
			out[k] = v
		}
	}
	return out
}

// vvDiff is "" when the two verdicts agree, else the first difference.
func vvDiff(want, got map[string]any) string {
	if want["allow"] != got["allow"] {
		return fmt.Sprintf("allow %v vs %v", want["allow"], got["allow"])
	}
	wr, gr := vvF(want["r"]), vvF(got["r"])
	if math.Abs(wr-gr) > 1e-12*math.Max(1, math.Abs(wr)) {
		return fmt.Sprintf("r %v vs %v", wr, gr)
	}
	wt, gt := svMap(want["requiredThreshold"]), svMap(got["requiredThreshold"])
	if vvF(wt["t"]) != vvF(gt["t"]) || wt["proof"] != gt["proof"] || wt["optimisticAllowed"] != gt["optimisticAllowed"] {
		return "requiredThreshold " + baseCanon(wt) + " vs " + baseCanon(gt)
	}
	if w, g := baseCanon(want["checks"]), baseCanon(got["checks"]); w != g {
		return "checks " + w + " vs " + g
	}
	wrs, _ := want["reasons"].([]any)
	grs, _ := got["reasons"].([]any)
	if len(wrs) == 1 && strings.HasPrefix(fmt.Sprint(wrs[0]), "undecodable PCActn: strict JSON:") {
		vvState.prefixOnly++
		if len(grs) != 1 || !strings.HasPrefix(fmt.Sprint(grs[0]), "undecodable PCActn: strict JSON:") {
			return "reasons " + baseCanon(wrs) + " vs " + baseCanon(grs)
		}
	} else if baseCanon(wrs) != baseCanon(grs) {
		return "reasons " + baseCanon(wrs) + " vs " + baseCanon(grs)
	}
	wb, gb := svMap(want["budget"]), svMap(got["budget"])
	if (want["budget"] != nil) != (got["budget"] != nil) {
		return "budget presence"
	}
	if wb != nil {
		wb, gb = vvDrop(wb), vvDrop(gb)
		for _, k := range []string{"B", "tau", "asOf"} {
			_, wp := wb[k]
			_, gp := gb[k]
			if wp != gp || (wp && vvF(wb[k]) != vvF(gb[k])) {
				return "budget " + baseCanon(wb) + " vs " + baseCanon(gb)
			}
		}
	}
	if (want["assurance"] != nil) != (got["assurance"] != nil) {
		return "assurance presence"
	}
	if want["assurance"] != nil {
		if w, g := baseCanon(want["assurance"]), baseCanon(got["assurance"]); w != g {
			return "assurance " + w + " vs " + g
		}
	}
	if (want["k1Bound"] != nil) != (got["k1Bound"] != nil) {
		return "k1Bound presence"
	}
	return ""
}

func TestServerVerifyMatchesTheReferenceVerdict(t *testing.T) {
	vvState.budgetOdd, vvState.prefixOnly, vvState.unbound, vvState.budgetDev, vvState.allowed = false, 0, 0, 0, 0
	replayVectorsCmp(t, "ref-verify-verdict.json.gz", map[string]vecFn{
		"verifyVerdict": func(a []any) (any, error) {
			opts, _ := a[1].(map[string]any)
			if v, has := opts["now"]; !has || v == nil { // `opts.now ?? Date.now()`: the generator's frozen clock is the default
				cl := make(map[string]any, len(opts)+1)
				for k, x := range opts {
					cl[k] = x
				}
				cl["now"] = jsNumber(vecOracleNow())
				opts = cl
			}
			if _, has := opts["allowUnboundPq"]; has {
				vvState.unbound++
			}
			vvState.budgetOdd = false
			if cm, ok := opts["context"].(map[string]any); ok {
				if b, has := cm["budget"]; has && b != nil {
					bm, isMap := b.(map[string]any)
					_, bNum := jsNum(bm["B"])
					vvState.budgetOdd = !isMap || !bNum
				}
			}
			return ServerVerify(a[0], vvInput(opts)), nil
		},
	}, map[string]func(want, got any) bool{
		"verifyVerdict": func(want, got any) bool {
			w, _ := want.(map[string]any)
			g, _ := got.(map[string]any)
			if w["allow"] == true {
				vvState.allowed++
			}
			d := vvDiff(w, g)
			if d == "" {
				return true
			}
			if vvState.budgetOdd {
				reasons := baseCanon(g["reasons"])
				if g["allow"] == false && strings.Contains(reasons, "policy evaluation error") {
					vvState.budgetDev++
					return true
				}
			}
			t.Logf("differs: %s", d)
			return false
		},
	})
	if vvState.prefixOnly != 3 {
		t.Errorf("strict-JSON wording cases: %d, want 3", vvState.prefixOnly)
	}
	if vvState.unbound != 2 {
		t.Errorf("allowUnboundPq cases (option not offered): %d, want 2", vvState.unbound)
	}
	if vvState.budgetDev > 2 {
		t.Errorf("malformed-budget deviations: %d, want at most 2", vvState.budgetDev)
	}
	if vvState.allowed < 100 {
		t.Errorf("the corpus allows a good share of its cases: %d", vvState.allowed)
	}
}

func TestServerVerifyDefaultDenyNamesTheRequiredCheckThatIsNotPass(t *testing.T) {
	ev := EnforceRequired(true, map[string]string{"counter_format": "pass", "bond": "unsupported"}, nil, []string{"counter", "bond", "revocation", "revocation"})
	if ev.Allow || ev.Checks["bond"] != "fail" || ev.Checks["revocation"] != "fail" {
		t.Fatalf("not denied: %+v", ev)
	}
	want := []string{"bond: required check is unsupported (default-deny: not enforced by this resource server)",
		"revocation: required check is absent (default-deny: not enforced by this resource server)"}
	if strings.Join(ev.Reasons, "|") != strings.Join(want, "|") {
		t.Fatalf("reasons %v", ev.Reasons)
	}
}
