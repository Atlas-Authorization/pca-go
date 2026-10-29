package pca

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
)

// Replays packages/pca/conformance/authorize-workflow-fixtures.json through Authorize (C-308). A missing file fails (load calls t.Fatal).
func TestK5AuthorizeWorkflowFixtures(t *testing.T) {
	F := load(t, "authorize-workflow-fixtures.json")
	if F["format"] != "pca-authorize-workflow-fixtures/1" {
		t.Fatalf("format %v", F["format"])
	}
	cases := F["cases"].([]any)
	if len(cases) < 14 {
		t.Fatalf("only %d cases", len(cases))
	}
	var plan []map[string]any
	for _, n := range F["plan"].([]any) {
		plan = append(plan, n.(map[string]any))
	}
	grant := F["grant"].(map[string]any)
	for _, x := range cases {
		c := x.(map[string]any)
		t.Run(c["name"].(string), func(t *testing.T) {
			required, _ := c["required"].(bool)
			store := NewMemoryStateStore() // ONE replay store per case
			for i, y := range c["steps"].([]any) {
				s := y.(map[string]any)
				op := s["operation"].(map[string]any)
				in := AuthorizeInput{
					Operation: &Operation{Verb: op["verb"].(string), Resource: op["resource"].(string), Params: op["params"].(map[string]any)},
					Audience:  F["audience"].(string),
					ResolveGrant: func(ref string) (map[string]any, error) {
						if ref == grant["id"] {
							return grant, nil
						}
						return nil, nil
					},
					StateStore: store,
					IsRevoked:  func(_, _ map[string]any) (bool, error) { return false, nil },
					Now:        num(F["now"]),
					Context: func(map[string]any) (*AuthorizeContext, error) {
						return &AuthorizeContext{Plan: plan, PlanAuthorized: true}, nil
					},
					Workflow:      &WorkflowOption{Principal: F["principal"].(string), RsSigner: F["rs_signer"].(string), Required: required},
					ArgProvenance: harnessProv(), // the TypeScript harness presents a principal-direct bundle under the harness pin
				}
				if w, ok := s["workflow"].(map[string]any); ok {
					in.WorkflowStep = &WorkflowCall{Commitment: w["commitment"], Receipts: w["receipts"], Step: w["step"].(string), Units: w["units"], GoalDigest: w["goal_digest"]}
				}
				r := Authorize(s["pcactn"], in)
				failed := []string{}
				for k, v := range r.Checks {
					if v == "fail" {
						failed = append(failed, k)
					}
				}
				sort.Strings(failed)
				e := s["expect"].(map[string]any)
				wantFailed := []string{}
				for _, f := range e["failed"].([]any) {
					wantFailed = append(wantFailed, f.(string))
				}
				if r.Allow != e["allow"] || r.Decision != e["decision"] || int64(r.Status) != num(e["status"]) || strings.Join(failed, ",") != strings.Join(wantFailed, ",") {
					t.Errorf("step %d: allow=%v decision=%s status=%d failed=%v (%s); want %v", i, r.Allow, r.Decision, r.Status, failed, r.Reason, e)
				}
				if want, ok := e["reason"].(string); ok && (r.Allow || !strings.Contains(r.Reason, want)) {
					t.Errorf("step %d: reason %q lacks %q", i, r.Reason, want)
				}
			}
		})
	}
}

// RequirePCA (authorize mode) with AuthorizeOptions.Workflow: every fixture case with an object PCActn is replayed through the
// middleware, the step read from the body member `workflow` (or the WorkflowStep callback); same status and reason as Authorize.
func TestK5RequirePCAWorkflow(t *testing.T) {
	F := load(t, "authorize-workflow-fixtures.json")
	var plan []map[string]any
	for _, n := range F["plan"].([]any) {
		plan = append(plan, n.(map[string]any))
	}
	grant := F["grant"].(map[string]any)
	for _, viaCallback := range []bool{false, true} {
		for _, x := range F["cases"].([]any) {
			c := x.(map[string]any)
			t.Run(fmt.Sprintf("%v/%s", viaCallback, c["name"]), func(t *testing.T) {
				required, _ := c["required"].(bool)
				store := NewMemoryStateStore()
				var cur *http.Request
				var curOp *Operation
				az := &AuthorizeOptions{
					StateStore: store,
					IsRevoked:  func(_, _ map[string]any) (bool, error) { return false, nil },
					Context: func(*http.Request, map[string]any) (*AuthorizeContext, error) {
						return &AuthorizeContext{Plan: plan, PlanAuthorized: true}, nil
					},
					Operation:     func(*http.Request, []byte) (*Operation, error) { return curOp, nil },
					Workflow:      &WorkflowOption{Principal: F["principal"].(string), RsSigner: F["rs_signer"].(string), Required: required},
					ArgProvenance: harnessProv(),
				}
				var curCall *WorkflowCall
				if viaCallback {
					az.WorkflowStep = func(*http.Request, map[string]any) *WorkflowCall { return curCall }
				}
				h := RequirePCA(RequirePCAOptions{Audience: F["audience"].(string), Now: func() int64 { return num(F["now"]) }, Authorize: az,
					ResolveGrant: func(ref string) (map[string]any, error) {
						if ref == grant["id"] {
							return grant, nil
						}
						return nil, nil
					}})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
				for i, y := range c["steps"].([]any) {
					s := y.(map[string]any)
					if _, isObj := s["pcactn"].(map[string]any); !isObj {
						continue
					}
					op := s["operation"].(map[string]any)
					curOp = &Operation{Verb: op["verb"].(string), Resource: op["resource"].(string), Params: op["params"].(map[string]any)}
					body := map[string]any{"pcactn": s["pcactn"]}
					curCall = nil
					if w, ok := s["workflow"].(map[string]any); ok {
						if viaCallback {
							curCall = &WorkflowCall{Commitment: w["commitment"], Receipts: w["receipts"], Step: w["step"].(string), Units: w["units"], GoalDigest: w["goal_digest"]}
						} else {
							body["workflow"] = w
						}
					}
					b, _ := json.Marshal(body)
					cur = httptest.NewRequest("POST", "/x", bytes.NewReader(b))
					rec := httptest.NewRecorder()
					h.ServeHTTP(rec, cur)
					e := s["expect"].(map[string]any)
					if int64(rec.Code) != num(e["status"]) && !(e["allow"] == true && rec.Code == 200) {
						t.Errorf("step %d: status %d want %v (%s)", i, rec.Code, e["status"], rec.Body.String())
					}
					if want, ok := e["reason"].(string); ok && !strings.Contains(rec.Body.String(), want) {
						t.Errorf("step %d: body %s lacks %q", i, rec.Body.String(), want)
					}
				}
			})
		}
	}
}
