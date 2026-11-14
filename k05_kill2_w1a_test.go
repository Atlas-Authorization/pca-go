package pca

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// w1aFlipStore turns the staleness policy on at the replay-stage Last call: after the freshness step ran (off), before
// the required-check list is built.
type w1aFlipStore struct {
	*MemoryStateStore
	flip func()
}

func (s w1aFlipStore) Last(key string) (*int64, error) {
	s.flip()
	return s.MemoryStateStore.Last(key)
}

// authorize.go: the required list re-reads stalenessOn(); a policy switched on mid-call makes `freshness` required and absent.
func TestW1aStalenessRequiredReadsPolicyAgain(t *testing.T) {
	k := g01Keyset(t)
	g := g01Grant(t, k.principal, k.agent, nil)
	in := g01DynIn(g)
	pol := &RevocationStalenessPolicy{} // non-nil but off
	in.RevocationStaleness = pol
	age := 60_000.0
	in.StateStore = w1aFlipStore{NewMemoryStateStore(), func() { pol.MaxRevocationAgeMs = &age }}
	r := Authorize(g01Act(t, g, []map[string]any{g}, k.agent, "", g01Now, 1, nil), in)
	want := "freshness: required check is absent (default-deny: not enforced by this resource server)"
	if r.Allow || r.Checks["freshness"] != "fail" || !g01Has(r.Reasons, want) {
		t.Fatalf("got allow=%v checks=%v reasons=%q", r.Allow, r.Checks, r.Reasons)
	}
}

// w1aDoctorStore edits the record Get returns.
type w1aDoctorStore struct {
	OperationStore
	edit func(*OperationRecord)
}

func (s w1aDoctorStore) Get(id string) (*OperationRecord, error) {
	r, err := s.OperationStore.Get(id)
	if r == nil {
		return r, err
	}
	c := *r
	s.edit(&c)
	return &c, err
}

// executor.go: a replay is answered from the record only when verb, resource AND params digest all match.
func TestW1aExecutorReplayRecordMustMatch(t *testing.T) {
	fn := func(ExecutionHandle) (any, error) { return "ok", nil }
	for name, edit := range map[string]func(*OperationRecord){
		"none":     func(*OperationRecord) {},
		"digest":   func(r *OperationRecord) { r.ParamsDigest = "w1a" },
		"verb":     func(r *OperationRecord) { r.Verb = "w1a" },
		"resource": func(r *OperationRecord) { r.Resource = "w1a" },
	} {
		ex, pcactn, op, _ := executorFixture(t, -1)
		if o := ex.Run(pcactn, op, fn); o.Status != "committed" {
			t.Fatalf("%s: first: %+v", name, o)
		}
		ex.o.Operations = w1aDoctorStore{ex.o.Operations, edit}
		o := ex.Run(pcactn, op, fn)
		if name == "none" {
			if o.Status != "committed" || !o.Replayed {
				t.Fatalf("matching record: %+v", o)
			}
			continue
		}
		if o.Status != "denied" || o.Replayed || o.Authorization == nil || o.Authorization.Checks["replay"] != "fail" {
			t.Fatalf("%s mismatch: %+v", name, o)
		}
	}
}

// middleware.go: the buffered body is read with a limit of exactly MaxJSONChars+1 bytes, and that is what the
// request callbacks see.
func TestW1aMiddlewareBodyLimit(t *testing.T) {
	seen := -1
	az := &AuthorizeOptions{Risk: InsecureCalmRisk, Plan: PlanSingleStep, Workflow: &WorkflowOption{}, WorkflowStep: func(r *http.Request, _ map[string]any) *WorkflowCall {
		b, _ := io.ReadAll(r.Body)
		seen = len(b)
		return nil
	}}
	h := authorizeHandler(RequirePCAOptions{Authorize: az}, func() int64 { return 1 }, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("handler reached")
	}))
	req := httptest.NewRequest("POST", "/", strings.NewReader(strings.Repeat(" ", MaxJSONChars+5)))
	req.Header.Set(PCAHeader, base64.RawURLEncoding.EncodeToString([]byte("{}")))
	h.ServeHTTP(httptest.NewRecorder(), req)
	if seen != MaxJSONChars+1 {
		t.Fatalf("callback saw %d body bytes, want %d", seen, MaxJSONChars+1)
	}
}
