package pca

import (
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
)

func authorizeFixtures(t *testing.T) map[string]any {
	t.Helper()
	b, err := os.ReadFile("testdata/authorize-fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	d, err := ParseJSON(b)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func fixNum(v any) int64 {
	n, _ := v.(interface{ Int64() (int64, error) }).Int64()
	return n
}

func fixOp(m map[string]any) *Operation {
	return &Operation{Verb: m["verb"].(string), Resource: m["resource"].(string), Params: m["params"].(map[string]any)}
}

func fixInput(d, grant map[string]any, store StateStore, revoked *bool) AuthorizeInput {
	return AuthorizeInput{
		Audience:     d["audience"].(string),
		Now:          fixNum(d["now"]),
		Plan:         PlanSingleStep,
		StateStore:   store,
		ResolveGrant: func(ref string) (map[string]any, error) { return grant, nil },
		IsRevoked:    func(_, _ map[string]any) (bool, error) { return *revoked, nil },
	}
}

// Every shared fixture case, steps in order against one fresh store, must give exactly the recorded outcome.
func TestAuthorizeFixtures(t *testing.T) {
	d := authorizeFixtures(t)
	for _, c := range d["cases"].([]any) {
		c := c.(map[string]any)
		t.Run(c["name"].(string), func(t *testing.T) {
			var revoked bool
			grant := c["grant"].(map[string]any)
			store := NewMemoryStateStore()
			for i, s := range c["steps"].([]any) {
				s := s.(map[string]any)
				revoked = s["revoked"] == true
				in := fixInput(d, grant, store, &revoked)
				in.Operation = fixOp(s["operation"].(map[string]any))
				res := Authorize(s["pcactn"], in)
				exp := s["expect"].(map[string]any)
				var failed []string
				for k, v := range res.Checks {
					if v == "fail" {
						failed = append(failed, k)
					}
				}
				sort.Strings(failed)
				want := []string{}
				for _, f := range exp["failed"].([]any) {
					want = append(want, f.(string))
				}
				if failed == nil {
					failed = []string{}
				}
				if want, has := exp["reason"].(string); has && !strings.Contains(res.Reason, want) {
					t.Fatalf("step %d: reason %q does not contain %q", i, res.Reason, want)
				}
				if res.Allow != (exp["allow"] == true) || int64(res.Status) != fixNum(exp["status"]) || !reflect.DeepEqual(failed, want) {
					t.Fatalf("step %d: got allow=%v status=%d failed=%v, want %v", i, res.Allow, res.Status, failed, exp)
				}
			}
		})
	}
}

func TestAuthorizeFailsClosedOnMissingComponents(t *testing.T) {
	d := authorizeFixtures(t)
	c := d["cases"].([]any)[0].(map[string]any)
	s := c["steps"].([]any)[0].(map[string]any)
	revoked := false
	full := func() AuthorizeInput {
		in := fixInput(d, c["grant"].(map[string]any), NewMemoryStateStore(), &revoked)
		in.Operation = fixOp(s["operation"].(map[string]any))
		return in
	}
	if r := Authorize(s["pcactn"], full()); !r.Allow {
		t.Fatalf("baseline must allow: %+v", r)
	}
	for name, mut := range map[string]func(*AuthorizeInput){
		"StateStore":   func(in *AuthorizeInput) { in.StateStore = nil },
		"IsRevoked":    func(in *AuthorizeInput) { in.IsRevoked = nil },
		"ResolveGrant": func(in *AuthorizeInput) { in.ResolveGrant = nil },
		"Audience":     func(in *AuthorizeInput) { in.Audience = "" },
		"Operation":    func(in *AuthorizeInput) { in.Operation = nil },
	} {
		in := full()
		mut(&in)
		r := Authorize(s["pcactn"], in)
		if r.Allow || r.Status != 403 {
			t.Errorf("%s missing: allow=%v status=%d", name, r.Allow, r.Status)
		}
	}
	in := full()
	in.IsRevoked = func(_, _ map[string]any) (bool, error) { panic("boom") }
	if r := Authorize(s["pcactn"], in); r.Allow {
		t.Error("a panicking IsRevoked must deny")
	}
}

func TestMemoryStateStoreMonotoneAndConcurrent(t *testing.T) {
	st := NewMemoryStateStore()
	for _, step := range []struct {
		n  int64
		ok bool
	}{{5, true}, {5, false}, {4, false}, {6, true}} {
		r, err := st.Claim("k", step.n)
		if err != nil || r.OK != step.ok {
			t.Fatalf("claim %d: %+v %v", step.n, r, err)
		}
	}
	wins := 0
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if r, _ := st.Claim("c", 1); r.OK {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("exactly one concurrent claim must win, got %d", wins)
	}
}

// RequirePCA in authorize mode: the handler never runs for a refused request and runs once for a good one (replay refused).
func TestRequirePCAAuthorizeMode(t *testing.T) {
	d := authorizeFixtures(t)
	byName := map[string]map[string]any{}
	for _, c := range d["cases"].([]any) {
		cm := c.(map[string]any)
		byName[cm["name"].(string)] = cm
	}
	run := func(name string, replay bool) (codes []int, calls int) {
		c := byName[name]
		s := c["steps"].([]any)[0].(map[string]any)
		op := fixOp(s["operation"].(map[string]any))
		grant := c["grant"].(map[string]any)
		store := NewMemoryStateStore()
		h := RequirePCA(RequirePCAOptions{
			Audience:     d["audience"].(string),
			Now:          func() int64 { return fixNum(d["now"]) },
			ResolveGrant: func(string) (map[string]any, error) { return grant, nil },
			Authorize: &AuthorizeOptions{
				StateStore: store,
				IsRevoked:  func(_, _ map[string]any) (bool, error) { return false, nil },
				Operation:  func(*http.Request, []byte) (*Operation, error) { return op, nil },
			},
		})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls++
			if a, ok := AuthorizationFromContext(r.Context()); !ok || a.Operation == nil {
				t.Error("authorization missing from context")
			}
			w.WriteHeader(204)
		}))
		n := 1
		if replay {
			n = 2
		}
		for i := 0; i < n; i++ {
			req := httptest.NewRequest(http.MethodPost, "/pay", strings.NewReader(`{"amount":50}`))
			req.Header.Set(PCAHeader, headerFor(t, s["pcactn"].(map[string]any)))
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			codes = append(codes, rec.Code)
		}
		return
	}
	if codes, calls := run("envelope-predicate-within", true); calls != 1 || codes[0] != 204 || codes[1] != 403 {
		t.Fatalf("allow then replay: codes=%v calls=%d", codes, calls)
	}
	if codes, calls := run("envelope-predicate-400-refused", false); calls != 0 || codes[0] != 403 {
		t.Fatalf("over-limit: codes=%v calls=%d", codes, calls)
	}
}
