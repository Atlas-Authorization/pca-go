package pca

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type protectCase struct {
	grant, pcactn map[string]any
	op            *Operation
	aud           string
	now           int64
}

func protectFixture(t *testing.T) protectCase {
	t.Helper()
	d := authorizeFixtures(t)
	c := d["cases"].([]any)[0].(map[string]any)
	s := c["steps"].([]any)[0].(map[string]any)
	return protectCase{c["grant"].(map[string]any), s["pcactn"].(map[string]any), fixOp(s["operation"].(map[string]any)), d["audience"].(string), fixNum(d["now"])}
}

func (c protectCase) opts() ProtectOptions {
	return ProtectOptions{
		Audience:  c.aud,
		Grants:    []map[string]any{c.grant},
		Now:       func() int64 { return c.now },
		Operation: func(*http.Request, []byte) (*Operation, error) { return c.op, nil },
	}
}

func (c protectCase) send(t *testing.T, p *Protected) (int, map[string]any, bool) {
	t.Helper()
	called := false
	h := p.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
	req := httptest.NewRequest("POST", "/x", strings.NewReader("{}"))
	req.Header.Set(PCAHeader, headerFor(t, c.pcactn))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return rec.Code, body, called
}

func TestProtectAllowsOnceThenRefusesReplayWithDoc(t *testing.T) {
	c := protectFixture(t)
	p := Protect(c.opts())
	if code, body, called := c.send(t, p); code != 200 || !called {
		t.Fatalf("first: %d %v", code, body)
	}
	code, body, called := c.send(t, p) // same proof again: the default in-memory store refuses the replay
	if code != 403 || called || body["doc"] != refusalsDoc+"#replay" {
		t.Fatalf("replay: %d %v called=%v", code, body, called)
	}
}

func TestProtectRevoke(t *testing.T) {
	c := protectFixture(t)
	p := Protect(c.opts())
	p.Revoke(c.grant["id"].(string))
	code, body, called := c.send(t, p)
	if checks, _ := body["checks"].(map[string]any); code != 403 || called || checks["revocation"] != "fail" || body["doc"] != refusalsDoc+"#revocation" {
		t.Fatalf("%d %v called=%v", code, body, called)
	}
}

func TestProtectExtraRevocationSource(t *testing.T) {
	c := protectFixture(t)
	o := c.opts()
	o.IsRevoked = func(_, _ map[string]any) (bool, error) { return true, nil }
	if code, _, called := c.send(t, Protect(o)); code != 403 || called {
		t.Fatalf("extra source ignored: %d", code)
	}
	o.IsRevoked = func(_, _ map[string]any) (bool, error) { return false, errors.New("down") }
	if code, _, called := c.send(t, Protect(o)); code != 403 || called {
		t.Fatalf("a failing source must deny: %d", code)
	}
}

func TestProtectUnknownGrantAndNoGrants(t *testing.T) {
	c := protectFixture(t)
	o := c.opts()
	o.Grants = nil
	if code, body, called := c.send(t, Protect(o)); code == 200 || called || body == nil {
		t.Fatalf("no grants: %d %v", code, body)
	}
	o.Grants = []map[string]any{{"id": 7}, {"no": "id"}} // unusable grants are skipped, not a panic
	if code, _, called := c.send(t, Protect(o)); code == 200 || called {
		t.Fatalf("junk grants: %d", code)
	}
}

func TestProtectResolveGrantFuncAndWrongOperation(t *testing.T) {
	c := protectFixture(t)
	o := c.opts()
	o.Grants = nil
	o.ResolveGrant = func(ref string) (map[string]any, error) { return c.grant, nil }
	other := &Operation{Verb: c.op.Verb, Resource: c.op.Resource, Params: map[string]any{"amount": 99, "currency": "usd"}}
	o.Operation = func(*http.Request, []byte) (*Operation, error) { return other, nil }
	code, body, called := c.send(t, Protect(o))
	if doc, _ := body["doc"].(string); code != 403 || called || !strings.HasPrefix(doc, PCADocs+"/") {
		t.Fatalf("other op: %d %v", code, body)
	}
	o.Operation = func(*http.Request, []byte) (*Operation, error) { return c.op, nil }
	if code, _, called := c.send(t, Protect(o)); code != 200 || !called {
		t.Fatalf("resolver: %d", code)
	}
}

func TestProtectCallerOptionsWin(t *testing.T) {
	c := protectFixture(t)
	mine := NewMemoryStateStore()
	o := c.opts()
	o.Operation = nil
	o.Authorize = &AuthorizeOptions{
		StateStore: mine,
		IsRevoked:  func(_, _ map[string]any) (bool, error) { return true, nil }, // replaces the default source entirely
		Operation:  func(*http.Request, []byte) (*Operation, error) { return c.op, nil },
	}
	p := Protect(o)
	if p.Options.Authorize.StateStore != mine {
		t.Fatal("caller StateStore replaced")
	}
	if code, _, called := c.send(t, p); code != 403 || called {
		t.Fatalf("caller IsRevoked ignored: %d", code)
	}
	// the caller's struct is copied, not mutated
	if o.Authorize.Plan != "" {
		t.Fatal("caller AuthorizeOptions mutated")
	}
	if p.Options.Authorize.Plan != PlanSingleStep {
		t.Fatalf("plan %q", p.Options.Authorize.Plan)
	}
}

// Missing audience or operation fails closed (no panic), and the refusal names what is missing.
func TestProtectFailsClosedWithoutAudienceOrOperation(t *testing.T) {
	c := protectFixture(t)
	o := c.opts()
	o.Audience = ""
	if code, _, called := c.send(t, Protect(o)); code != 403 || called {
		t.Fatalf("no audience: %d", code)
	}
	o = c.opts()
	o.Operation = nil
	if code, _, called := c.send(t, Protect(o)); code != 403 || called {
		t.Fatalf("no operation: %d", code)
	}
}

func TestMiddlewareDocOnBadRequestTooNoReasonNoDoc(t *testing.T) {
	c := protectFixture(t)
	h := Protect(c.opts()).Middleware()(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/x", nil)) // no proof presented: 401 with a reason
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if rec.Code != 401 || body["doc"] != refusalsDoc {
		t.Fatalf("%d %v", rec.Code, body)
	}
	// reasons are unchanged
	if body["error_description"] != "no PCActn presented (missing PCA-Action header and request body)" {
		t.Fatalf("reason changed: %v", body)
	}
}
