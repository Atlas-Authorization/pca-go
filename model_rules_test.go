package pca

import (
	"os"
	"reflect"
	"regexp"
	"sort"
	"testing"
)

// Rules 20 (units) and 21 (tighten-only) END TO END through Authorize: the shared vectors
// packages/pca/conformance/model-rules-vectors.json (signed grants, decided by the TypeScript reference). A grant's tighten[]
// rules, unit tags and polarity are signed policy: ignoring them would let a model move a decision up, so every case must
// decide the same as the reference, reason text included.

var modelReasonRe = regexp.MustCompile(`^(units|tighten|schema|intent_session): `)

func modelRulesVectors(t *testing.T) map[string]any {
	t.Helper()
	b, err := os.ReadFile(dir + "model-rules-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	d, err := ParseJSONLenient(b)
	if err != nil {
		t.Fatal(err)
	}
	return d.(map[string]any)
}

func runModelCase(d, c map[string]any, extra func(*AuthorizeInput)) AuthorizeResult {
	grant := c["grant"].(map[string]any)
	in := AuthorizeInput{
		Audience:     d["audience"].(string),
		Now:          fixNum(d["now"]),
		Plan:         PlanSingleStep,
		StateStore:   NewMemoryStateStore(),
		Operation:    fixOp(c["operation"].(map[string]any)),
		ResolveGrant: func(ref string) (map[string]any, error) { return grant, nil },
		IsRevoked:    func(_, _ map[string]any) (bool, error) { return false, nil },
		// provenance by default: the TypeScript harness presents a principal-direct bundle under the harness pin
		ArgProvenance: harnessProv(),
	}
	if v2, has := c["intent_v2"]; has {
		in.IntentV2 = func(map[string]any) (*IntentV2Context, error) { return IntentV2ContextFromJSON(v2), nil }
	}
	if cx, has := c["context"].(map[string]any); has {
		in.Context = func(map[string]any) (*AuthorizeContext, error) { return &AuthorizeContext{Env: cx["env"]}, nil }
	}
	if extra != nil {
		extra(&in)
	}
	return Authorize(c["pcactn"], in)
}

func TestModelRulesVectors(t *testing.T) {
	d := modelRulesVectors(t)
	decisions := map[string]bool{}
	for _, x := range d["cases"].([]any) {
		c := x.(map[string]any)
		e := c["expect"].(map[string]any)
		decisions[e["decision"].(string)] = true
		t.Run(c["name"].(string), func(t *testing.T) {
			r := runModelCase(d, c, nil)
			if r.Allow != e["allow"].(bool) || r.Decision != e["decision"] || int64(r.Status) != fixNum(e["status"]) {
				t.Fatalf("got allow=%v decision=%s status=%d, want %v %v %v: %q", r.Allow, r.Decision, r.Status, e["allow"], e["decision"], e["status"], r.Reasons)
			}
			failed := []string{}
			for n, st := range r.Checks {
				if st == "fail" {
					failed = append(failed, n)
				}
			}
			sort.Strings(failed)
			wantFailed := []string{}
			for _, n := range e["failed"].([]any) {
				wantFailed = append(wantFailed, n.(string))
			}
			if !reflect.DeepEqual(failed, wantFailed) {
				t.Fatalf("failed checks %v, want %v (%q)", failed, wantFailed, r.Reasons)
			}
			got := []string{}
			for _, x := range r.Reasons {
				if modelReasonRe.MatchString(x) {
					got = append(got, x)
				}
			}
			want := []string{}
			for _, x := range e["reasons"].([]any) {
				want = append(want, x.(string))
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("model reasons %q, want %q", got, want)
			}
			for _, k := range []string{"units", "tighten"} {
				w, has := e[k].(string)
				if r.Checks[k] != w || (!has && r.Checks[k] != "") {
					t.Fatalf("check %s = %q, want %q", k, r.Checks[k], w)
				}
			}
			wantDeg := map[string]string{}
			if dg, has := e["degraded"].(map[string]any); has {
				for k, v := range dg {
					wantDeg[k] = v.(string)
				}
			}
			gotDeg := r.Degraded
			if gotDeg == nil {
				gotDeg = map[string]string{}
			}
			if !reflect.DeepEqual(gotDeg, wantDeg) {
				t.Fatalf("degraded %v, want %v", gotDeg, wantDeg)
			}
		})
	}
	for _, dec := range []string{"allow", "escalate", "deny"} {
		if !decisions[dec] {
			t.Errorf("no %s case in the vectors", dec)
		}
	}
}
